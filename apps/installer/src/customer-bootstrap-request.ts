import * as v from 'valibot';

import {
  boundaryValueSchema,
  type BoundaryObject,
  type BoundaryValue,
} from './boundary';
import { canonicalJson } from './canonical-json';
import type { AuthorizedTarget } from './cloudflare-target';
import type { AccountWorkersSubdomain } from './cloudflare-management-surface';
import { base64UrlEncode } from './crypto';
import {
  buildStaticDeployPlan,
  deploySelectionFromStaticPlan,
  parseDeploySelection,
  parseStaticDeployPlan,
  verifyStaticDeployPlanIntegrity,
} from './schema';
import type { DeploySelection, GatewayResourceKind, StaticDeployPlan } from './schema';
import { parseReleaseManifest } from './release-manifest';
import type { VerifiedRelease } from './release';
import {
  parseReadyInstallationReceipt,
  type InstallationReceiptResourceExpectation,
  type ReadyInstallationReceipt,
  type ReadyInstallationReceiptExpectation,
} from './provider-neutral-installation-receipt';
import { isPlainDataTree } from './plain-data';

export type { AccountWorkersSubdomain } from './cloudflare-management-surface';

const BOOTSTRAP_PATH = '/__ankka/bootstrap';
const MAX_REQUEST_LIFETIME_SECONDS = 5 * 60;
const MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_ACCESS_TOKEN_BYTES = 16 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
// One signed bootstrap request is never replayed, so its deadline must cover a
// full first convergence of the seven gateway resources inside the customer
// Worker. 15s only ever covered a resumed no-op (live measurement 2026-08-23).
const MAX_TIMEOUT_MS = 120_000;
const REQUEST_ID_BYTES = 16;
const NONCE_BYTES = 32;
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const BARE_SHA256 = /^[0-9a-f]{64}$/u;
const PLAN_ID = /^plan-[0-9a-f]{24}$/u;
const INSTALLATION_ID = /^acg-[0-9a-f]{24}$/u;
const REQUEST_ID = /^[A-Za-z0-9_-]{22}$/u;
const NONCE = /^[A-Za-z0-9_-]{43}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const RELEASE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$/u;
const SOURCE_ID = 'company-context';
const PORTAL_CNAME_TARGET = 'gateway.agents.cloudflare.com';
const MANAGER = 'ankka-mcp-gateway';
const GATEWAY_RESOURCE_KINDS = Object.freeze([
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
] as const satisfies readonly GatewayResourceKind[]);
const PORTAL_RESOURCE_KINDS = Object.freeze([
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
] as const satisfies readonly GatewayResourceKind[]);

function unsafeTextCharacter(character: string): boolean {
  const codePoint = character.codePointAt(0);
  return codePoint === undefined || codePoint <= 0x1f || codePoint === 0x7f;
}

const safeNonnegativeIntegerSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const positiveTimeoutSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(1), v.maxValue(MAX_TIMEOUT_MS));
const accountWorkersSubdomainSchema = v.strictObject({
  accountId: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
  subdomain: v.pipe(v.string(), v.regex(HOST_LABEL)),
});
const authorizedTargetSchema = v.strictObject({
  actor: v.strictObject({
    id: v.pipe(v.string(), v.minLength(8), v.maxLength(128), v.regex(SAFE_ID)),
    email: v.string(),
  }),
  account: v.strictObject({
    id: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
    name: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
  }),
  zone: v.strictObject({
    id: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
    name: v.string(),
    status: v.literal('active'),
  }),
});
const verifiedReleaseInputSchema = v.strictObject({
  verification: v.literal('ed25519'),
  keyId: v.pipe(v.string(), v.regex(/^[a-z0-9][a-z0-9._-]{0,63}$/u)),
  manifest: boundaryValueSchema,
});
const releaseEvidenceInputSchema = v.strictObject({
  id: v.pipe(v.string(), v.regex(RELEASE)),
  artifactSha256: v.pipe(v.string(), v.regex(BARE_SHA256)),
});
const providerFailureDetailSchema = v.strictObject({
  kind: v.pipe(v.string(), v.regex(/^[a-z_]{1,40}$/u)),
  step: v.pipe(v.string(), v.regex(/^[a-z_]{1,32}$/u)),
  status: v.pipe(v.string(), v.regex(/^[a-z_]{1,24}$/u)),
  httpStatus: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(999))),
  code: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(999_999))),
});
const recoveryResponseSchema = v.strictObject({
  schemaVersion: v.literal(1),
  error: v.picklist([
    'bootstrap_recovery_required',
    'bootstrap_requires_repair',
    'bootstrap_request_mismatch',
    'management_publication_failed',
  ]),
  retryable: v.boolean(),
  /** Secret-free numbers and fixed words naming the provider outcome that stopped the payload. */
  provider: v.optional(providerFailureDetailSchema),
});

/** `payload_<kind>_<step>_<status>[_http_<n>][_code_<n>]`, from numbers and fixed words only. */
function providerFailureReason(detail: v.InferOutput<typeof providerFailureDetailSchema>): string {
  let reason = `payload_${detail.kind}_${detail.step}_${detail.status}`;
  if (detail.httpStatus !== undefined) reason += `_http_${detail.httpStatus}`;
  if (detail.code !== undefined) reason += `_code_${detail.code}`;
  return reason.slice(0, 160);
}
const readyResponseSchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: v.literal('ready'),
  installationId: v.pipe(v.string(), v.regex(INSTALLATION_ID)),
  approvedPlanId: v.pipe(v.string(), v.regex(PLAN_ID)),
  configurationHash: v.pipe(v.string(), v.regex(SHA256)),
  desiredHash: v.pipe(v.string(), v.regex(SHA256)),
  settingsRevision: v.literal(1),
  release: v.strictObject({
    id: v.pipe(v.string(), v.regex(RELEASE)),
    artifactSha256: v.pipe(v.string(), v.regex(SHA256)),
  }),
  gateway: v.strictObject({ hostname: v.string(), mcpUrl: v.string() }),
  receipt: v.strictObject({
    revision: safeNonnegativeIntegerSchema,
    resourceCount: v.union([v.literal(4), v.literal(7)]),
    evidence: boundaryValueSchema,
  }),
  applyInvoked: v.boolean(),
  resumed: v.boolean(),
});

export type CustomerBootstrapStage =
  | 'validate'
  | 'claim'
  | 'sign'
  | 'submit'
  | 'response';

export type CustomerBootstrapOutcome = 'not_sent' | 'rejected' | 'unknown';

export type CustomerBootstrapErrorCode =
  | 'invalid_input'
  | 'origin_invalid'
  | 'plan_mismatch'
  | 'request_expired'
  | 'sign_failed'
  | 'outcome_unknown'
  | 'bootstrap_rejected'
  | 'response_invalid';

/**
 * Value-free bootstrap failure. Arbitrary provider errors are deliberately not
 * attached as `cause`, and input values never become an error message.
 */
export class CustomerBootstrapRequestError extends Error {
  readonly code: CustomerBootstrapErrorCode;
  readonly stage: CustomerBootstrapStage;
  readonly outcome: CustomerBootstrapOutcome;
  readonly canRetry = false;

  constructor(
    code: CustomerBootstrapErrorCode,
    stage: CustomerBootstrapStage,
    outcome: CustomerBootstrapOutcome,
  ) {
    super(code);
    this.name = 'CustomerBootstrapRequestError';
    this.code = code;
    this.stage = stage;
    this.outcome = outcome;
  }
}

export interface CustomerGatewaySettings {
  readonly schemaVersion: 1;
  readonly connect: {
    readonly name: string;
    readonly hostname: string;
    readonly codeMode: 'default_on';
  };
  readonly access: {
    readonly adminEmails: readonly string[];
    readonly memberEmails: readonly string[];
  };
  readonly sources: readonly {
    readonly id: typeof SOURCE_ID;
    readonly label: string;
    readonly url: string;
    readonly authentication: {
      readonly mode: 'none';
      readonly onBehalfOfUser: false;
    };
    readonly enabledTools: readonly string[];
  }[];
}

export interface CustomerBootstrapTarget {
  readonly accountId: string;
  readonly zoneId: string;
  readonly zoneName: string;
}

export interface CustomerBootstrapReleaseEvidence {
  readonly id: string;
  readonly artifactSha256: string;
}

export interface CustomerBootstrapExpectedEvidence {
  readonly configurationHash: string;
  readonly installationId: string;
  readonly desiredHash: string;
}

/** The complete credential-free portion of the public bootstrap request. */
export interface PreparedCustomerBootstrapClaim {
  readonly schemaVersion: 1;
  readonly requestId: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly settingsRevision: 1;
  readonly settings: CustomerGatewaySettings;
  readonly target: CustomerBootstrapTarget;
  readonly release: CustomerBootstrapReleaseEvidence;
  readonly expected: CustomerBootstrapExpectedEvidence;
}

/**
 * Credential-free exact provider candidate projection derived from the same
 * reviewed planner as the signed customer bootstrap request.
 */
export interface CustomerGatewayDesiredProjection {
  readonly schemaVersion: 1;
  readonly target: CustomerBootstrapTarget;
  readonly plan: {
    readonly planId: string;
    readonly planHash: string;
    readonly expiresAt: number;
  };
  readonly release: {
    readonly id: string;
    /** Canonical aggregate release digest, without a `sha256:` prefix. */
    readonly artifactSha256: string;
  };
  readonly expected: CustomerBootstrapExpectedEvidence;
  readonly resourceKinds: readonly GatewayResourceKind[];
  readonly candidates: {
    readonly mcpServer: {
      readonly key: string;
      readonly desiredHash: string;
      readonly id: string;
      readonly endpoint: string;
      readonly ownershipMarker: string;
    } | null;
    readonly sourceAccessApplication: {
      readonly key: string;
      readonly desiredHash: string;
      readonly serverId: string;
      readonly ownershipMarker: string;
    } | null;
    readonly sourceAccessPolicy: {
      readonly key: string;
      readonly desiredHash: string;
      readonly parentApplicationKey: string;
    } | null;
    readonly portal: {
      readonly key: string;
      readonly desiredHash: string;
      readonly id: string;
      readonly hostname: string;
      readonly name: string;
      readonly ownershipMarker: string;
    };
    readonly portalAccessApplication: {
      readonly key: string;
      readonly desiredHash: string;
      readonly hostname: string;
      readonly name: string;
    };
    readonly portalAccessPolicy: {
      readonly key: string;
      readonly desiredHash: string;
      readonly parentApplicationKey: string;
    };
    readonly dnsRecord: {
      readonly key: string;
      readonly desiredHash: string;
      readonly hostname: string;
    };
  };
}

export interface DeriveCustomerGatewayExpectedProjectionInput {
  readonly selection: DeploySelection;
  readonly target: AuthorizedTarget;
  readonly plan: StaticDeployPlan;
  readonly release: {
    readonly id: string;
    /** Canonical aggregate release digest, without a `sha256:` prefix. */
    readonly artifactSha256: string;
  };
}

export interface CustomerBootstrapReadyResult {
  readonly schemaVersion: 1;
  readonly status: 'ready';
  readonly installationId: string;
  readonly approvedPlanId: string;
  readonly configurationHash: string;
  readonly desiredHash: string;
  readonly settingsRevision: 1;
  readonly release: CustomerBootstrapReleaseEvidence;
  readonly gateway: {
    readonly hostname: string;
    readonly mcpUrl: string;
  };
  readonly receipt: {
    readonly revision: number;
    readonly resourceCount: 4 | 7;
    readonly evidence: ReadyInstallationReceipt;
  };
  readonly applyInvoked: boolean;
  readonly resumed: boolean;
}

export type CustomerBootstrapRecoveryReason =
  | 'bootstrap_recovery_required'
  | 'bootstrap_requires_repair'
  | 'bootstrap_request_mismatch'
  /** The host could not publish the management status and control after a ready bootstrap. */
  | 'management_publication_failed';

export interface CustomerBootstrapRecoveryResult {
  readonly schemaVersion: 1;
  readonly status: 'recovery_required';
  readonly reason: CustomerBootstrapRecoveryReason;
  /** The payload's provider failure as a secret-free reason string, when it named one. */
  readonly detail: string | null;
  readonly canRetry: false;
}

export type CustomerBootstrapResult =
  | CustomerBootstrapReadyResult
  | CustomerBootstrapRecoveryResult;

export type CustomerBootstrapTransport = (request: Request) => Promise<Response>;

export interface PrepareCustomerBootstrapClaimInput {
  readonly selection: DeploySelection;
  readonly target: AuthorizedTarget;
  readonly release: VerifiedRelease;
  readonly plan: StaticDeployPlan;
  readonly nowMs?: number;
  readonly randomBytes?: (length: number) => Uint8Array;
}

export interface PrepareCustomerBootstrapClaimFromPlanInput {
  readonly plan: StaticDeployPlan;
  readonly target: CustomerBootstrapTarget;
  readonly nowMs?: number;
  readonly randomBytes?: (length: number) => Uint8Array;
}

export interface SubmitCustomerBootstrapInput extends PrepareCustomerBootstrapClaimInput {
  /** Pass the authorized provider result directly; do not reconstruct it. */
  readonly accountWorkersSubdomain: AccountWorkersSubdomain;
  /** Fresh 32-byte base64url secret already installed in the temporary Worker. */
  readonly bootstrapNonce: string;
  /** Cloudflare OAuth grant. It is used only while composing this one request. */
  readonly cloudflareAccessToken: string;
  readonly transport: CustomerBootstrapTransport;
  readonly timeoutMs?: number;
}

export interface SubmitCustomerBootstrapFromPlanInput extends PrepareCustomerBootstrapClaimFromPlanInput {
  readonly accountWorkersSubdomain: AccountWorkersSubdomain;
  readonly bootstrapNonce: string;
  readonly cloudflareAccessToken: string;
  readonly transport: CustomerBootstrapTransport;
  readonly timeoutMs?: number;
}

interface DesiredResource {
  readonly kind: GatewayResourceKind;
  readonly key: string;
  readonly desiredHash: string;
  readonly desired: BoundaryObject;
}

interface DesiredResourceSpecification {
  readonly kind: GatewayResourceKind;
  readonly key: string;
  readonly desired: BoundaryObject;
}

interface ValidatedContext {
  readonly selection: DeploySelection;
  readonly target: AuthorizedTarget;
  readonly release: VerifiedRelease;
  readonly plan: StaticDeployPlan;
  readonly nowMs: number;
}

interface PreparedBootstrap {
  readonly claim: PreparedCustomerBootstrapClaim;
  readonly workerName: string;
}

class BootstrapTimeout extends Error {}

function fail(
  code: CustomerBootstrapErrorCode,
  stage: CustomerBootstrapStage,
  outcome: CustomerBootstrapOutcome,
): never {
  throw new CustomerBootstrapRequestError(code, stage, outcome);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function requireFreshRandomBytes(
  generator: ((length: number) => Uint8Array) | undefined,
  length: number,
): Uint8Array {
  let value: Uint8Array;
  try {
    value = (generator ?? randomBytes)(length);
  } catch {
    fail('invalid_input', 'claim', 'not_sent');
  }
  if (!(value instanceof Uint8Array) || value.byteLength !== length) {
    fail('invalid_input', 'claim', 'not_sent');
  }
  const owned = new Uint8Array(length);
  owned.set(value);
  if (owned.every((byte) => byte === 0)) {
    owned.fill(0);
    fail('invalid_input', 'claim', 'not_sent');
  }
  return owned;
}

function requireNonce<Value>(value: Value): Uint8Array {
  const parsed = v.safeParse(v.pipe(v.string(), v.regex(NONCE)), value);
  if (!parsed.success) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  let bytes: Uint8Array;
  try {
    const base64 = parsed.output.replaceAll('-', '+').replaceAll('_', '/');
    const decoded = atob(`${base64}=`);
    bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  } catch {
    fail('invalid_input', 'validate', 'not_sent');
  }
  if (bytes.byteLength !== NONCE_BYTES || bytes.every((byte) => byte === 0)) {
    bytes.fill(0);
    fail('invalid_input', 'validate', 'not_sent');
  }
  return bytes;
}

function requireAccessToken<Value>(value: Value): string {
  const parsed = v.safeParse(v.string(), value);
  if (
    !parsed.success ||
    parsed.output.length === 0 ||
    new TextEncoder().encode(parsed.output).byteLength > MAX_ACCESS_TOKEN_BYTES ||
    parsed.output.trim() !== parsed.output ||
    [...parsed.output].some(unsafeTextCharacter)
  ) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  return parsed.output;
}

function requireTimeout<Value>(value: Value): number {
  const timeout = value === undefined ? DEFAULT_TIMEOUT_MS : value;
  const parsed = v.safeParse(positiveTimeoutSchema, timeout);
  if (!parsed.success) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  return parsed.output;
}

function managementWorkerName(plan: StaticDeployPlan): string {
  const workers = plan.managementResources.filter((resource) => resource.kind === 'management_worker');
  const worker = workers.length === 1 ? workers.at(0) : undefined;
  if (worker === undefined || !WORKER_NAME.test(worker.name)) {
    fail('plan_mismatch', 'validate', 'not_sent');
  }
  return worker.name;
}

function requireBootstrapUrl<AccountWorkersSubdomainCandidate>(
  accountWorkersSubdomain: AccountWorkersSubdomainCandidate,
  reviewedWorkerName: string,
  authorizedAccountId: string,
): URL {
  if (!isPlainDataTree(accountWorkersSubdomain)) {
    fail('origin_invalid', 'validate', 'not_sent');
  }
  const parsed = v.safeParse(accountWorkersSubdomainSchema, accountWorkersSubdomain);
  if (!parsed.success) fail('origin_invalid', 'validate', 'not_sent');
  // Read each provider-returned primitive exactly once. The captured values are
  // the only values validated and later interpolated into the secret-bearing URL.
  const { accountId, subdomain } = parsed.output;
  if (
    accountId !== authorizedAccountId ||
    !HOST_LABEL.test(subdomain)
  ) {
    fail('origin_invalid', 'validate', 'not_sent');
  }
  if (!WORKER_NAME.test(reviewedWorkerName)) {
    fail('plan_mismatch', 'validate', 'not_sent');
  }
  return new URL(
    `https://${reviewedWorkerName}.${subdomain}.workers.dev${BOOTSTRAP_PATH}`,
  );
}

function requireAuthorizedTarget<Value>(value: Value, selection: DeploySelection): AuthorizedTarget {
  if (!isPlainDataTree(value)) fail('invalid_input', 'validate', 'not_sent');
  const parsed = v.safeParse(authorizedTargetSchema, value);
  if (!parsed.success) fail('invalid_input', 'validate', 'not_sent');
  const { actor, account, zone } = parsed.output;
  if (
    actor.email !== selection.basics.adminEmail ||
    [...account.name].some(unsafeTextCharacter) ||
    zone.name !== selection.basics.zoneName
  ) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  return Object.freeze({
    actor: Object.freeze(actor),
    account: Object.freeze(account),
    zone: Object.freeze(zone),
  });
}

async function validateContext(input: PrepareCustomerBootstrapClaimInput): Promise<ValidatedContext> {
  try {
    const selection = parseDeploySelection(input.selection);
    const releaseInput = v.safeParse(verifiedReleaseInputSchema, input.release);
    if (!releaseInput.success) fail('plan_mismatch', 'validate', 'not_sent');
    const release = Object.freeze({
      verification: 'ed25519',
      keyId: releaseInput.output.keyId,
      manifest: parseReleaseManifest(releaseInput.output.manifest),
    });
    const parsedPlan = parseStaticDeployPlan(input.plan);
    const expiresAt = parsedPlan.expiresAt;
    if (!v.is(safeNonnegativeIntegerSchema, expiresAt) || expiresAt <= 0) {
      fail('plan_mismatch', 'validate', 'not_sent');
    }
    const target = requireAuthorizedTarget(input.target, selection);
    const expectedPlan = await buildStaticDeployPlan(selection, release.manifest, expiresAt);
    const reviewedPlanJson = canonicalJson(expectedPlan);
    const firstInputSnapshot = canonicalJson(input.plan);
    const secondInputSnapshot = canonicalJson(input.plan);
    if (canonicalJson(parsedPlan) !== reviewedPlanJson ||
        firstInputSnapshot !== reviewedPlanJson || secondInputSnapshot !== firstInputSnapshot) {
      fail('plan_mismatch', 'validate', 'not_sent');
    }
    const nowMs = input.nowMs ?? Date.now();
    if (!v.is(safeNonnegativeIntegerSchema, nowMs)) {
      fail('invalid_input', 'validate', 'not_sent');
    }
    if (expectedPlan.expiresAt <= nowMs) {
      fail('request_expired', 'validate', 'not_sent');
    }
    return { selection, target, release, plan: expectedPlan, nowMs };
  } catch (error) {
    if (error instanceof CustomerBootstrapRequestError) throw error;
    fail('plan_mismatch', 'validate', 'not_sent');
  }
}

function gatewaySettings(selection: DeploySelection): CustomerGatewaySettings {
  const audience = [...(selection.firstSource?.portalUserEmails ?? [
    selection.basics.adminEmail,
    ...selection.basics.additionalAdminEmails,
  ])].sort(compareText);
  return Object.freeze({
    schemaVersion: 1,
    connect: Object.freeze({
      name: selection.basics.gatewayName,
      hostname: selection.basics.portalHostname,
      codeMode: 'default_on' as const,
    }),
    access: Object.freeze({
      adminEmails: Object.freeze(audience.slice(0, 1)),
      memberEmails: Object.freeze(audience.slice(1)),
    }),
    sources: selection.firstSource === null
      ? Object.freeze([])
      : Object.freeze([Object.freeze({
        id: SOURCE_ID,
        label: selection.firstSource.name,
        url: selection.firstSource.url,
        authentication: Object.freeze({ mode: 'none' as const, onBehalfOfUser: false as const }),
        enabledTools: Object.freeze([...selection.firstSource.enabledTools]),
      })]),
  });
}

async function configurationEvidence(
  settings: CustomerGatewaySettings,
  target: CustomerBootstrapTarget,
  release: CustomerBootstrapReleaseEvidence,
  installationId: string,
): Promise<CustomerBootstrapExpectedEvidence> {
  if (!INSTALLATION_ID.test(installationId)) fail('plan_mismatch', 'claim', 'not_sent');
  const resources = await buildDesiredResources(settings, installationId);
  const desiredHash = await hashCanonical({ schemaVersion: 1, installationId, resources });
  const configurationHash = await hashCanonical({
    schemaVersion: 1,
    settingsRevision: 1,
    settings,
    target,
    release,
  });
  return Object.freeze({ configurationHash, installationId, desiredHash });
}

async function stableResourceKey(
  prefix: string,
  installationId: string,
  logicalId: string,
): Promise<string> {
  const digest = await hashHex({ installationId, prefix, logicalId });
  const hint = logicalId
    .toLowerCase()
    .replace(/[^a-z0-9-]+/gu, '-')
    .replace(/^-+|-+$/gu, '');
  const hintLength = Math.max(0, 32 - prefix.length - 10);
  if (hint && hintLength > 0) {
    return `${prefix}-${hint.slice(0, hintLength)}-${digest.slice(0, 8)}`;
  }
  return `${prefix}-${digest.slice(0, 32 - prefix.length - 1)}`;
}

async function buildDesiredResources(
  settings: CustomerGatewaySettings,
  installationId: string,
): Promise<readonly DesiredResource[]> {
  const source = settings.sources[0] ?? null;
  const allowedEmails = [
    ...settings.access.adminEmails,
    ...settings.access.memberEmails,
  ].sort(compareText);
  const identitiesHash = await hashCanonical({ emails: allowedEmails });
  const metadata = { manager: MANAGER, installationId };
  const emailAllowPolicy = {
    identitiesRef: 'access.allowedEmails',
    identityType: 'email',
    identityCount: allowedEmails.length,
    identitiesHash,
  };
  const mcpKey = source === null ? null : await stableResourceKey('mcp', installationId, source.id);
  const sourceApplicationKey = source === null
    ? null
    : await stableResourceKey('source-app', installationId, source.id);
  const sourceAccessKey = source === null
    ? null
    : await stableResourceKey('source-access', installationId, source.id);
  const portalKey = await stableResourceKey('portal', installationId, settings.connect.hostname);
  const portalApplicationKey = await stableResourceKey(
    'portal-app',
    installationId,
    settings.connect.hostname,
  );
  const portalAccessKey = await stableResourceKey(
    'portal-access',
    installationId,
    settings.connect.hostname,
  );
  const dnsKey = await stableResourceKey('dns', installationId, settings.connect.hostname);
  const sourceMappings = source === null ? [] : [{
    sourceResourceKey: mcpKey,
    defaultDisabled: true,
    allowedTools: [...source.enabledTools].sort(compareText),
    onBehalfOfUser: false,
  }];
  const sourceSpecifications: DesiredResourceSpecification[] =
    source === null || mcpKey === null || sourceApplicationKey === null || sourceAccessKey === null
      ? []
      : [
        {
          kind: 'mcp_server',
          key: mcpKey,
          desired: {
            metadata,
            sourceId: source.id,
            name: source.label,
            endpoint: source.url,
            capabilityMode: 'read_only',
            secureWebGateway: false,
            toolPolicy: {
              defaultDisabled: true,
              allowedTools: [...source.enabledTools].sort(compareText),
            },
            authentication: {
              mode: 'none',
              onBehalfOfUser: false,
              credentialCustody: 'customer',
            },
          },
        },
        {
          kind: 'source_access_application',
          key: sourceApplicationKey,
          desired: { metadata, sourceResourceKey: mcpKey, applicationType: 'mcp' },
        },
        {
          kind: 'source_access_policy',
          key: sourceAccessKey,
          desired: {
            metadata,
            sourceApplicationResourceKey: sourceApplicationKey,
            defaultAction: 'deny',
            allow: emailAllowPolicy,
          },
        },
      ];
  const specifications: DesiredResourceSpecification[] = [
    ...sourceSpecifications,
    {
      kind: 'portal',
      key: portalKey,
      desired: {
        metadata,
        name: settings.connect.name,
        hostname: settings.connect.hostname,
        capabilityMode: 'read_only',
        codeMode: settings.connect.codeMode,
        secureWebGateway: false,
        sourceMappings,
      },
    },
    {
      kind: 'portal_access_application',
      key: portalApplicationKey,
      desired: {
        metadata,
        portalResourceKey: portalKey,
        name: settings.connect.name,
        hostname: settings.connect.hostname,
        applicationType: 'mcp_portal',
        destination: { type: 'public', uri: settings.connect.hostname },
        authentication: {
          mode: 'managed_oauth',
          dynamicClientRegistration: {
            enabled: true,
            allowAnyOnLocalhost: true,
            allowAnyOnLoopback: true,
          },
          grant: { accessTokenLifetime: '15m', sessionDuration: '336h' },
        },
      },
    },
    {
      kind: 'portal_access_policy',
      key: portalAccessKey,
      desired: {
        metadata,
        portalApplicationResourceKey: portalApplicationKey,
        defaultAction: 'deny',
        allow: emailAllowPolicy,
      },
    },
    {
      kind: 'dns_record',
      key: dnsKey,
      desired: {
        metadata,
        recordType: 'CNAME',
        hostname: settings.connect.hostname,
        content: PORTAL_CNAME_TARGET,
        proxied: true,
        dependsOnResourceKey: portalKey,
      },
    },
  ];
  return Promise.all(specifications.map(async (resource) => Object.freeze({
    ...resource,
    desiredHash: await hashCanonical({
      schemaVersion: 1,
      kind: resource.kind,
      key: resource.key,
      desired: resource.desired,
    }),
  })));
}

async function installationReceiptExpectation(
  settings: CustomerGatewaySettings,
  target: CustomerBootstrapTarget,
  release: CustomerBootstrapReleaseEvidence,
  expected: CustomerBootstrapExpectedEvidence,
): Promise<ReadyInstallationReceiptExpectation> {
  const resources = await buildDesiredResources(settings, expected.installationId);
  const allowedEmails = [
    ...settings.access.adminEmails,
    ...settings.access.memberEmails,
  ].sort(compareText);
  const identitiesHash = await hashCanonical({ emails: allowedEmails });
  const receiptResources = resources.map((resource): InstallationReceiptResourceExpectation => {
    const common = {
      kind: resource.kind,
      key: resource.key,
      desiredHash: resource.desiredHash,
      marker: customerResourceOwnershipMarker(expected.installationId, resource.key),
    };
    return resource.kind === 'source_access_policy' || resource.kind === 'portal_access_policy'
      ? Object.freeze({ ...common, identityHash: identitiesHash })
      : Object.freeze(common);
  });
  return Object.freeze({
    installationId: expected.installationId,
    release: release.id,
    desiredHash: expected.desiredHash,
    target: Object.freeze({ ...target, hostname: settings.connect.hostname }),
    accessPolicy: Object.freeze({
      identityType: 'email',
      identityCount: allowedEmails.length,
      identitiesHash,
    }),
    resources: Object.freeze(receiptResources),
  });
}

/** Rebuild the exact public receipt contract without allocating a request ID. */
export async function deriveCustomerGatewayInstallationReceiptExpectation(
  input: DeriveCustomerGatewayExpectedProjectionInput,
): Promise<ReadyInstallationReceiptExpectation> {
  const projection = await deriveCustomerGatewayExpectedProjection(input);
  const selection = parseDeploySelection(input.selection);
  return installationReceiptExpectation(
    gatewaySettings(selection),
    projection.target,
    {
      id: projection.release.id,
      artifactSha256: `sha256:${projection.release.artifactSha256}`,
    },
    projection.expected,
  );
}

function exactDesiredResource(
  resources: readonly DesiredResource[],
  kind: GatewayResourceKind,
): DesiredResource {
  const matches = resources.filter((resource) => resource.kind === kind);
  const match = matches.length === 1 ? matches.at(0) : undefined;
  if (match === undefined) fail('plan_mismatch', 'claim', 'not_sent');
  return match;
}

function requiredDesiredString(resource: DesiredResource, field: string): string {
  const value = resource.desired[field];
  const parsed = v.safeParse(v.string(), value);
  if (!parsed.success) fail('plan_mismatch', 'claim', 'not_sent');
  return parsed.output;
}

function customerResourceOwnershipMarker(installationId: string, key: string): string {
  if (!INSTALLATION_ID.test(installationId) || !/^[a-z][a-z0-9-]{0,31}$/u.test(key)) {
    fail('plan_mismatch', 'claim', 'not_sent');
  }
  return `acg:v1:${installationId}:${key}`;
}

/**
 * Rebuild the exact credential-free desired projection used by the public
 * customer Worker. This performs no provider I/O and allocates no request ID.
 */
export async function deriveCustomerGatewayExpectedProjection(
  input: DeriveCustomerGatewayExpectedProjectionInput,
): Promise<CustomerGatewayDesiredProjection> {
  let selection: DeploySelection;
  let plan: StaticDeployPlan;
  let authorizedTarget: AuthorizedTarget;
  try {
    selection = parseDeploySelection(input.selection);
    plan = parseStaticDeployPlan(input.plan);
    authorizedTarget = requireAuthorizedTarget(input.target, selection);
  } catch {
    fail('plan_mismatch', 'claim', 'not_sent');
  }
  const releaseInput = v.safeParse(releaseEvidenceInputSchema, input.release);
  if (
    !releaseInput.success ||
    releaseInput.output.id !== plan.releaseId ||
    releaseInput.output.artifactSha256 !== plan.releaseArtifactSha256 ||
    plan.primaryAdminEmail !== selection.basics.adminEmail ||
    canonicalJson(plan.managementAdminEmails) !== canonicalJson([
      selection.basics.adminEmail,
      ...selection.basics.additionalAdminEmails,
    ].sort()) ||
    canonicalJson(plan.portalAudienceEmails) !== canonicalJson(selection.firstSource?.portalUserEmails ?? [
      selection.basics.adminEmail,
      ...selection.basics.additionalAdminEmails,
    ].sort()) ||
    plan.gatewayConfiguration.gatewayName !== selection.basics.gatewayName ||
    plan.gatewayConfiguration.zoneName !== selection.basics.zoneName ||
    plan.gatewayConfiguration.managementHostname !== selection.basics.managementHostname ||
    plan.gatewayConfiguration.portalHostname !== selection.basics.portalHostname ||
    (selection.firstSource === null
      ? plan.gatewayConfiguration.firstSource !== null
      : plan.gatewayConfiguration.firstSource === null ||
        plan.gatewayConfiguration.firstSource.name !== selection.firstSource.name ||
        plan.gatewayConfiguration.firstSource.url !== selection.firstSource.url ||
        canonicalJson(plan.gatewayConfiguration.firstSource.enabledTools) !== canonicalJson(selection.firstSource.enabledTools))
  ) fail('plan_mismatch', 'claim', 'not_sent');
  return buildCustomerGatewayDesiredProjection({
    selection,
    plan,
    target: {
      accountId: authorizedTarget.account.id,
      zoneId: authorizedTarget.zone.id,
      zoneName: authorizedTarget.zone.name,
    },
    release: releaseInput.output,
  });
}

async function buildCustomerGatewayDesiredProjection(input: {
  readonly selection: DeploySelection;
  readonly plan: StaticDeployPlan;
  readonly target: CustomerBootstrapTarget;
  readonly release: { readonly id: string; readonly artifactSha256: string };
}): Promise<CustomerGatewayDesiredProjection> {
  const { selection, plan } = input;
  const settings = gatewaySettings(selection);
  const target = Object.freeze({ ...input.target });
  const releaseEvidence = Object.freeze({
    id: input.release.id,
    artifactSha256: `sha256:${input.release.artifactSha256}`,
  });
  const expected = await configurationEvidence(
    settings,
    target,
    releaseEvidence,
    plan.managementOwnershipMarker,
  );
  const resources = await buildDesiredResources(settings, expected.installationId);
  const mcpServer = selection.firstSource === null ? null : exactDesiredResource(resources, 'mcp_server');
  const sourceApplication = selection.firstSource === null
    ? null
    : exactDesiredResource(resources, 'source_access_application');
  const sourcePolicy = selection.firstSource === null
    ? null
    : exactDesiredResource(resources, 'source_access_policy');
  const portal = exactDesiredResource(resources, 'portal');
  const portalApplication = exactDesiredResource(resources, 'portal_access_application');
  const portalPolicy = exactDesiredResource(resources, 'portal_access_policy');
  const dnsRecord = exactDesiredResource(resources, 'dns_record');

  const sourceServerId = sourceApplication === null
    ? null
    : requiredDesiredString(sourceApplication, 'sourceResourceKey');
  const sourcePolicyParent = sourcePolicy === null
    ? null
    : requiredDesiredString(sourcePolicy, 'sourceApplicationResourceKey');
  const portalPolicyParent = requiredDesiredString(portalPolicy, 'portalApplicationResourceKey');
  if (
    (mcpServer === null
      ? sourceApplication !== null || sourcePolicy !== null || sourceServerId !== null || sourcePolicyParent !== null
      : sourceApplication === null || sourcePolicy === null ||
        sourceServerId !== mcpServer.key || sourcePolicyParent !== sourceApplication.key) ||
    requiredDesiredString(portalApplication, 'portalResourceKey') !== portal.key ||
    portalPolicyParent !== portalApplication.key ||
    requiredDesiredString(dnsRecord, 'dependsOnResourceKey') !== portal.key
  ) fail('plan_mismatch', 'claim', 'not_sent');

  return Object.freeze({
    schemaVersion: 1,
    target,
    plan: Object.freeze({
      planId: plan.planId,
      planHash: plan.planHash,
      expiresAt: plan.expiresAt,
    }),
    release: Object.freeze({
      id: input.release.id,
      artifactSha256: input.release.artifactSha256,
    }),
    expected,
    resourceKinds: selection.firstSource === null ? PORTAL_RESOURCE_KINDS : GATEWAY_RESOURCE_KINDS,
    candidates: Object.freeze({
      mcpServer: mcpServer === null ? null : Object.freeze({
        key: mcpServer.key,
        desiredHash: mcpServer.desiredHash,
        id: mcpServer.key,
        endpoint: requiredDesiredString(mcpServer, 'endpoint'),
        ownershipMarker: customerResourceOwnershipMarker(expected.installationId, mcpServer.key),
      }),
      sourceAccessApplication: sourceApplication === null || sourceServerId === null ? null : Object.freeze({
        key: sourceApplication.key,
        desiredHash: sourceApplication.desiredHash,
        serverId: sourceServerId,
        ownershipMarker: customerResourceOwnershipMarker(
          expected.installationId,
          sourceApplication.key,
        ),
      }),
      sourceAccessPolicy: sourcePolicy === null || sourcePolicyParent === null ? null : Object.freeze({
        key: sourcePolicy.key,
        desiredHash: sourcePolicy.desiredHash,
        parentApplicationKey: sourcePolicyParent,
      }),
      portal: Object.freeze({
        key: portal.key,
        desiredHash: portal.desiredHash,
        id: portal.key,
        hostname: requiredDesiredString(portal, 'hostname'),
        name: requiredDesiredString(portal, 'name'),
        ownershipMarker: customerResourceOwnershipMarker(expected.installationId, portal.key),
      }),
      portalAccessApplication: Object.freeze({
        key: portalApplication.key,
        desiredHash: portalApplication.desiredHash,
        hostname: requiredDesiredString(portalApplication, 'hostname'),
        name: requiredDesiredString(portalApplication, 'name'),
      }),
      portalAccessPolicy: Object.freeze({
        key: portalPolicy.key,
        desiredHash: portalPolicy.desiredHash,
        parentApplicationKey: portalPolicyParent,
      }),
      dnsRecord: Object.freeze({
        key: dnsRecord.key,
        desiredHash: dnsRecord.desiredHash,
        hostname: requiredDesiredString(dnsRecord, 'hostname'),
      }),
    }),
  });
}

/** Build the exact desired projection from the deploy-signed plan in the customer Worker. */
export async function prepareCustomerGatewayDesiredProjectionFromPlan(input: {
  readonly plan: StaticDeployPlan;
  readonly target: CustomerBootstrapTarget;
}): Promise<CustomerGatewayDesiredProjection> {
  let plan: StaticDeployPlan;
  let selection: DeploySelection;
  try {
    plan = await verifyStaticDeployPlanIntegrity(input.plan);
    selection = deploySelectionFromStaticPlan(plan);
  } catch {
    fail('plan_mismatch', 'validate', 'not_sent');
  }
  const target = v.safeParse(v.strictObject({
    accountId: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
    zoneId: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
    zoneName: v.string(),
  }), input.target);
  if (!target.success || target.output.zoneName !== selection.basics.zoneName) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  return buildCustomerGatewayDesiredProjection({
    selection,
    plan,
    target: target.output,
    release: { id: plan.releaseId, artifactSha256: plan.releaseArtifactSha256 },
  });
}

/**
 * Rebuild the exact credential-free desired projection used by the public
 * customer Worker. This performs no provider I/O and allocates no request ID.
 */
export async function prepareCustomerGatewayDesiredProjection(
  input: PrepareCustomerBootstrapClaimInput,
): Promise<CustomerGatewayDesiredProjection> {
  const context = await validateContext(input);
  return deriveCustomerGatewayExpectedProjection({
    selection: context.selection,
    target: context.target,
    plan: context.plan,
    release: {
      id: context.release.manifest.release,
      artifactSha256: context.release.manifest.artifact.treeSha256,
    },
  });
}

/**
 * Validate the exact reviewed inputs and derive the public Worker's
 * credential-free claim. This function performs no I/O and returns no nonce.
 */
async function prepareBootstrap(
  input: PrepareCustomerBootstrapClaimInput,
): Promise<PreparedBootstrap> {
  const context = await validateContext(input);
  // Capture the exact worker name immediately after the complete reviewed plan
  // has been rebuilt and compared, before any later asynchronous hashing.
  const workerName = managementWorkerName(context.plan);
  const issuedAt = Math.floor(context.nowMs / 1000);
  const expiresAt = Math.min(
    issuedAt + MAX_REQUEST_LIFETIME_SECONDS,
    Math.floor(context.plan.expiresAt / 1000),
  );
  if (expiresAt <= issuedAt) fail('request_expired', 'claim', 'not_sent');
  const requestIdBytes = requireFreshRandomBytes(input.randomBytes, REQUEST_ID_BYTES);
  const requestId = base64UrlEncode(requestIdBytes);
  requestIdBytes.fill(0);
  if (!REQUEST_ID.test(requestId)) fail('invalid_input', 'claim', 'not_sent');
  const settings = gatewaySettings(context.selection);
  const target = Object.freeze({
    accountId: context.target.account.id,
    zoneId: context.target.zone.id,
    zoneName: context.target.zone.name,
  });
  const release = Object.freeze({
    id: context.release.manifest.release,
    artifactSha256: `sha256:${context.release.manifest.artifact.treeSha256}`,
  });
  const expected = await configurationEvidence(
    settings,
    target,
    release,
    context.plan.managementOwnershipMarker,
  );
  const claim = Object.freeze({
    schemaVersion: 1,
    requestId,
    issuedAt,
    expiresAt,
    settingsRevision: 1,
    settings,
    target,
    release,
    expected,
  });
  return Object.freeze({ claim, workerName });
}

export async function prepareCustomerBootstrapClaim(
  input: PrepareCustomerBootstrapClaimInput,
): Promise<PreparedCustomerBootstrapClaim> {
  return (await prepareBootstrap(input)).claim;
}

/**
 * Build the same canonical payload claim from the signed Stage 1 plan after
 * the customer Worker has resolved the authorized zone. No release bytes,
 * actor identity, or hosted credential are needed inside the Gateway.
 */
export async function prepareCustomerBootstrapClaimFromPlan(
  input: PrepareCustomerBootstrapClaimFromPlanInput,
): Promise<PreparedCustomerBootstrapClaim> {
  let plan: StaticDeployPlan;
  let selection: DeploySelection;
  try {
    plan = await verifyStaticDeployPlanIntegrity(input.plan);
    selection = deploySelectionFromStaticPlan(plan);
  } catch {
    fail('plan_mismatch', 'validate', 'not_sent');
  }
  const targetResult = v.safeParse(v.strictObject({
    accountId: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
    zoneId: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
    zoneName: v.string(),
  }), input.target);
  if (!targetResult.success || targetResult.output.zoneName !== selection.basics.zoneName) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  const nowMs = input.nowMs ?? Date.now();
  if (!v.is(safeNonnegativeIntegerSchema, nowMs) || plan.expiresAt <= nowMs) {
    fail('request_expired', 'claim', 'not_sent');
  }
  const issuedAt = Math.floor(nowMs / 1000);
  const expiresAt = Math.min(
    issuedAt + MAX_REQUEST_LIFETIME_SECONDS,
    Math.floor(plan.expiresAt / 1000),
  );
  if (expiresAt <= issuedAt) fail('request_expired', 'claim', 'not_sent');
  const requestIdBytes = requireFreshRandomBytes(input.randomBytes, REQUEST_ID_BYTES);
  const requestId = base64UrlEncode(requestIdBytes);
  requestIdBytes.fill(0);
  if (!REQUEST_ID.test(requestId)) fail('invalid_input', 'claim', 'not_sent');
  const settings = gatewaySettings(selection);
  const target = Object.freeze({ ...targetResult.output });
  const release = Object.freeze({
    id: plan.releaseId,
    artifactSha256: `sha256:${plan.releaseArtifactSha256}`,
  });
  const expected = await configurationEvidence(
    settings,
    target,
    release,
    plan.managementOwnershipMarker,
  );
  return Object.freeze({
    schemaVersion: 1,
    requestId,
    issuedAt,
    expiresAt,
    settingsRevision: 1,
    settings,
    target,
    release,
    expected,
  });
}

async function signRawBody(rawBody: string, nonceBytes: Uint8Array): Promise<string> {
  const ownedNonce = new Uint8Array(new ArrayBuffer(nonceBytes.byteLength));
  ownedNonce.set(nonceBytes);
  let signature: Uint8Array<ArrayBuffer> | null = null;
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      ownedNonce,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    signature = new Uint8Array(await crypto.subtle.sign(
      'HMAC',
      key,
      new TextEncoder().encode(rawBody),
    ));
    return `sha256=${bytesToHex(signature)}`;
  } catch {
    fail('sign_failed', 'sign', 'not_sent');
  } finally {
    signature?.fill(0);
    ownedNonce.fill(0);
  }
  fail('sign_failed', 'sign', 'not_sent');
}

function recoveryResult(
  value: BoundaryValue,
  status: number,
): CustomerBootstrapRecoveryResult | null {
  const result = v.safeParse(recoveryResponseSchema, value);
  if (
    status !== 409 ||
    !result.success
  ) return null;
  if (result.output.error === 'bootstrap_recovery_required' && result.output.retryable !== true) return null;
  if (result.output.error !== 'bootstrap_recovery_required' && result.output.retryable !== false) return null;
  return Object.freeze({
    schemaVersion: 1,
    status: 'recovery_required',
    reason: result.output.error,
    detail: result.output.provider === undefined ? null : providerFailureReason(result.output.provider),
    canRetry: false,
  });
}

async function parseReadyResult(
  value: BoundaryValue,
  claim: PreparedCustomerBootstrapClaim,
): Promise<CustomerBootstrapReadyResult> {
  const result = v.safeParse(readyResponseSchema, value);
  if (!result.success) fail('response_invalid', 'response', 'unknown');
  const ready = result.output;
  const expectedResourceCount = claim.settings.sources.length === 0 ? 4 : 7;
  if (
    ready.installationId !== claim.expected.installationId ||
    ready.configurationHash !== claim.expected.configurationHash ||
    ready.desiredHash !== claim.expected.desiredHash ||
    ready.release.id !== claim.release.id || ready.release.artifactSha256 !== claim.release.artifactSha256 ||
    ready.gateway.hostname !== claim.settings.connect.hostname ||
    ready.gateway.mcpUrl !== `https://${claim.settings.connect.hostname}/mcp` ||
    ready.receipt.resourceCount !== expectedResourceCount
  ) fail('response_invalid', 'response', 'unknown');
  const receiptExpectation = await installationReceiptExpectation(
    claim.settings,
    claim.target,
    claim.release,
    claim.expected,
  );
  const evidence = await parseReadyInstallationReceipt(ready.receipt.evidence, receiptExpectation);
  if (!evidence || evidence.revision !== ready.receipt.revision) {
    fail('response_invalid', 'response', 'unknown');
  }
  return Object.freeze({
    schemaVersion: 1,
    status: 'ready',
    installationId: ready.installationId,
    approvedPlanId: ready.approvedPlanId,
    configurationHash: ready.configurationHash,
    desiredHash: ready.desiredHash,
    settingsRevision: 1,
    release: Object.freeze({
      id: ready.release.id,
      artifactSha256: ready.release.artifactSha256,
    }),
    gateway: Object.freeze({
      hostname: ready.gateway.hostname,
      mcpUrl: ready.gateway.mcpUrl,
    }),
    receipt: Object.freeze({
      revision: ready.receipt.revision,
      resourceCount: expectedResourceCount,
      evidence,
    }),
    applyInvoked: ready.applyInvoked,
    resumed: ready.resumed,
  });
}

async function readBoundedJson(response: Response): Promise<BoundaryValue> {
  const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') fail('response_invalid', 'response', 'unknown');
  const declared = response.headers.get('content-length');
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0 || length > MAX_RESPONSE_BYTES) {
      fail('response_invalid', 'response', 'unknown');
    }
  }
  if (!response.body) fail('response_invalid', 'response', 'unknown');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      fail('response_invalid', 'response', 'unknown');
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const parsed = v.safeParse(boundaryValueSchema, JSON.parse(text));
    if (!parsed.success) fail('response_invalid', 'response', 'unknown');
    return parsed.output;
  } catch {
    fail('response_invalid', 'response', 'unknown');
  } finally {
    bytes.fill(0);
    for (const chunk of chunks) chunk.fill(0);
  }
}

async function parseBootstrapResponse(
  response: Response,
  requestUrl: URL,
  claim: PreparedCustomerBootstrapClaim,
): Promise<CustomerBootstrapResult> {
  if (
    response.type === 'opaqueredirect' ||
    response.redirected ||
    (response.url !== '' && response.url !== requestUrl.href) ||
    (response.status >= 300 && response.status < 400)
  ) {
    fail('outcome_unknown', 'response', 'unknown');
  }
  const value = await readBoundedJson(response);
  if (response.status === 200) return await parseReadyResult(value, claim);
  const recovery = recoveryResult(value, response.status);
  if (recovery) return recovery;
  if (response.status >= 500) fail('outcome_unknown', 'response', 'unknown');
  fail('bootstrap_rejected', 'response', 'rejected');
}

/**
 * Submit exactly one bootstrap request. There is intentionally no retry loop,
 * persistence hook, logger, runtime default transport, or recovery mutation.
 */
/**
 * The exact provider-bound bootstrap URL, for a side-effect-free readiness
 * probe before a signed request is armed. It applies the same validation the
 * submitter applies, so a probe can never widen the reachable origin set.
 */
export function customerBootstrapUrl(input: {
  readonly accountWorkersSubdomain: AccountWorkersSubdomain;
  readonly workerName: string;
  readonly accountId: string;
}): string {
  return requireBootstrapUrl(input.accountWorkersSubdomain, input.workerName, input.accountId).toString();
}

/** Optional call controls forwarded only when the caller supplied them. */
interface OptionalBootstrapControls {
  timeoutMs?: number;
}

async function submitPreparedCustomerBootstrap<AccountWorkersSubdomainCandidate>(input: {
  readonly claim: PreparedCustomerBootstrapClaim;
  readonly workerName: string;
  readonly accountWorkersSubdomain: AccountWorkersSubdomainCandidate;
  readonly bootstrapNonce: string;
  readonly cloudflareAccessToken: string;
  readonly transport: CustomerBootstrapTransport;
  readonly timeoutMs?: number;
}): Promise<CustomerBootstrapResult> {
  if (!v.is(v.function(), input.transport)) fail('invalid_input', 'validate', 'not_sent');
  const timeoutMs = requireTimeout(input.timeoutMs);
  const token = requireAccessToken(input.cloudflareAccessToken);
  const nonceBytes = requireNonce(input.bootstrapNonce);
  let rawBody = '';
  try {
    const claim = input.claim;
    const requestUrl = requireBootstrapUrl(
      input.accountWorkersSubdomain,
      input.workerName,
      claim.target.accountId,
    );
    rawBody = canonicalJson({ ...claim, cloudflareAccessToken: token });
    const signature = await signRawBody(rawBody, nonceBytes);
    const controller = new AbortController();
    const request = new Request(requestUrl, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        'x-ankka-bootstrap-signature': signature,
      },
      body: rawBody,
      redirect: 'manual',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      signal: controller.signal,
    });
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new BootstrapTimeout());
      }, timeoutMs);
    });
    try {
      const operation = (async () => {
        const response = await input.transport(request);
        if (!(response instanceof Response)) fail('outcome_unknown', 'submit', 'unknown');
        return parseBootstrapResponse(response, requestUrl, claim);
      })();
      return await Promise.race([operation, timeout]);
    } catch (error) {
      if (error instanceof CustomerBootstrapRequestError) throw error;
      if (error instanceof BootstrapTimeout) fail('outcome_unknown', 'submit', 'unknown');
      fail('outcome_unknown', 'submit', 'unknown');
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      controller.abort();
    }
  } finally {
    nonceBytes.fill(0);
    rawBody = '';
  }
  fail('outcome_unknown', 'submit', 'unknown');
}

export async function submitCustomerBootstrap<AccountWorkersSubdomainCandidate>(
  input: Omit<SubmitCustomerBootstrapInput, 'accountWorkersSubdomain'> & {
    readonly accountWorkersSubdomain: AccountWorkersSubdomainCandidate;
  },
): Promise<CustomerBootstrapResult> {
  const prepared = await prepareBootstrap(input);
  const controls: OptionalBootstrapControls = {};
  if (input.timeoutMs !== undefined) controls.timeoutMs = input.timeoutMs;
  return submitPreparedCustomerBootstrap({
    claim: prepared.claim,
    workerName: prepared.workerName,
    accountWorkersSubdomain: input.accountWorkersSubdomain,
    bootstrapNonce: input.bootstrapNonce,
    cloudflareAccessToken: input.cloudflareAccessToken,
    transport: input.transport,
    ...controls,
  });
}

/** Run the same signed payload bootstrap from the plan adopted by the customer Worker. */
export async function submitCustomerBootstrapFromPlan(
  input: SubmitCustomerBootstrapFromPlanInput,
): Promise<CustomerBootstrapResult> {
  const plan = await verifyStaticDeployPlanIntegrity(input.plan).catch(() =>
    fail('plan_mismatch', 'validate', 'not_sent'));
  const claim = await prepareCustomerBootstrapClaimFromPlan(input);
  const controls: OptionalBootstrapControls = {};
  if (input.timeoutMs !== undefined) controls.timeoutMs = input.timeoutMs;
  return submitPreparedCustomerBootstrap({
    claim,
    workerName: managementWorkerName(plan),
    accountWorkersSubdomain: input.accountWorkersSubdomain,
    bootstrapNonce: input.bootstrapNonce,
    cloudflareAccessToken: input.cloudflareAccessToken,
    transport: input.transport,
    ...controls,
  });
}

export function canonicalCustomerBootstrapJson<Value>(value: Value): string {
  return canonicalJson(value);
}

async function hashCanonical<Value>(value: Value): Promise<string> {
  return `sha256:${await hashHex(value)}`;
}

async function hashHex<Value>(value: Value): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonicalJson(value)),
  ));
  const result = bytesToHex(digest);
  digest.fill(0);
  return result;
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}
