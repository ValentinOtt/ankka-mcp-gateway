import type { AuthorizedTarget } from './cloudflare-target';
import type { AccountWorkersSubdomain } from './cloudflare-management-surface';
import { base64UrlEncode } from './crypto';
import {
  buildStaticDeployPlan,
  parseDeploySelection,
  parseStaticDeployPlan,
} from './schema';
import type { DeploySelection, GatewayResourceKind, StaticDeployPlan } from './schema';
import { parseReleaseManifest } from './release-manifest';
import type { VerifiedRelease } from './release';
import {
  parseReadyInstallationReceipt,
  type ReadyInstallationReceipt,
  type ReadyInstallationReceiptExpectation,
} from './provider-neutral-installation-receipt';

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
  | 'bootstrap_request_mismatch';

export interface CustomerBootstrapRecoveryResult {
  readonly schemaVersion: 1;
  readonly status: 'recovery_required';
  readonly reason: CustomerBootstrapRecoveryReason;
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

interface DesiredResource {
  readonly kind: string;
  readonly key: string;
  readonly desiredHash: string;
  readonly desired: Record<string, unknown>;
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort(compareText);
  const sortedExpected = [...expected].sort(compareText);
  return actual.length === sortedExpected.length &&
    actual.every((key, index) => key === sortedExpected[index]);
}

function exactDataKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  try {
    if (Object.getPrototypeOf(value) !== Object.prototype || !exactKeys(value, expected)) {
      return false;
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    return expected.every((key) => {
      const descriptor = descriptors[key];
      return descriptor !== undefined && descriptor.enumerable === true && 'value' in descriptor;
    });
  } catch {
    return false;
  }
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

function requireNonce(value: unknown): Uint8Array {
  if (typeof value !== 'string' || !NONCE.test(value)) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  let bytes: Uint8Array;
  try {
    const base64 = value.replaceAll('-', '+').replaceAll('_', '/');
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

function requireAccessToken(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    new TextEncoder().encode(value).byteLength > MAX_ACCESS_TOKEN_BYTES ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  return value;
}

function requireTimeout(value: unknown): number {
  const timeout = value === undefined ? DEFAULT_TIMEOUT_MS : value;
  if (!Number.isSafeInteger(timeout) || (timeout as number) < 1 || (timeout as number) > MAX_TIMEOUT_MS) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  return timeout as number;
}

function managementWorkerName(plan: StaticDeployPlan): string {
  const workers = plan.managementResources.filter((resource) => resource.kind === 'management_worker');
  if (workers.length !== 1 || !WORKER_NAME.test(workers[0].name)) {
    fail('plan_mismatch', 'validate', 'not_sent');
  }
  return workers[0].name;
}

function requireBootstrapUrl(
  accountWorkersSubdomain: unknown,
  reviewedWorkerName: string,
  authorizedAccountId: string,
): URL {
  if (
    !isRecord(accountWorkersSubdomain) ||
    !exactDataKeys(accountWorkersSubdomain, ['accountId', 'subdomain'])
  ) {
    fail('origin_invalid', 'validate', 'not_sent');
  }
  // Read each provider-returned primitive exactly once. The captured values are
  // the only values validated and later interpolated into the secret-bearing URL.
  const accountId = accountWorkersSubdomain.accountId;
  const subdomain = accountWorkersSubdomain.subdomain;
  if (
    accountId !== authorizedAccountId ||
    typeof subdomain !== 'string' ||
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

function requireAuthorizedTarget(value: unknown, selection: DeploySelection): AuthorizedTarget {
  if (!isRecord(value) || !exactDataKeys(value, ['actor', 'account', 'zone'])) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  const actor = value.actor;
  const account = value.account;
  const zone = value.zone;
  if (
    !isRecord(actor) || !exactDataKeys(actor, ['id', 'email']) ||
    !isRecord(account) || !exactDataKeys(account, ['id', 'name']) ||
    !isRecord(zone) || !exactDataKeys(zone, ['id', 'name', 'status'])
  ) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  const actorId = actor.id;
  const actorEmail = actor.email;
  const accountId = account.id;
  const accountName = account.name;
  const zoneId = zone.id;
  const zoneName = zone.name;
  const zoneStatus = zone.status;
  if (
    typeof actorId !== 'string' || actorId.length < 8 || actorId.length > 128 ||
    !SAFE_ID.test(actorId) || typeof actorEmail !== 'string' ||
    actorEmail !== selection.basics.adminEmail ||
    typeof accountId !== 'string' || !/^[a-f0-9]{32}$/u.test(accountId) ||
    typeof accountName !== 'string' || accountName.length < 1 || accountName.length > 256 ||
    /[\u0000-\u001f\u007f]/u.test(accountName) ||
    typeof zoneId !== 'string' || !/^[a-f0-9]{32}$/u.test(zoneId) ||
    typeof zoneName !== 'string' ||
    zoneName !== selection.basics.zoneName || zoneStatus !== 'active'
  ) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  return Object.freeze({
    actor: Object.freeze({ id: actorId, email: actorEmail }),
    account: Object.freeze({ id: accountId, name: accountName }),
    zone: Object.freeze({ id: zoneId, name: zoneName, status: 'active' as const }),
  });
}

async function validateContext(input: PrepareCustomerBootstrapClaimInput): Promise<ValidatedContext> {
  try {
    const selection = parseDeploySelection(input.selection);
    if (
      !isRecord(input.release) ||
      !exactKeys(input.release, ['verification', 'keyId', 'manifest']) ||
      input.release.verification !== 'ed25519' ||
      typeof input.release.keyId !== 'string' ||
      !/^[a-z0-9][a-z0-9._-]{0,63}$/u.test(input.release.keyId)
    ) fail('plan_mismatch', 'validate', 'not_sent');
    const release = Object.freeze({
      verification: 'ed25519' as const,
      keyId: input.release.keyId,
      manifest: parseReleaseManifest(input.release.manifest),
    });
    const parsedPlan = parseStaticDeployPlan(input.plan);
    const expiresAt = parsedPlan.expiresAt;
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0) {
      fail('plan_mismatch', 'validate', 'not_sent');
    }
    const target = requireAuthorizedTarget(input.target, selection);
    const expectedPlan = await buildStaticDeployPlan(selection, release.manifest, expiresAt);
    if (canonicalJson(parsedPlan) !== canonicalJson(expectedPlan)) {
      fail('plan_mismatch', 'validate', 'not_sent');
    }
    const nowMs = input.nowMs ?? Date.now();
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
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
): Promise<CustomerBootstrapExpectedEvidence> {
  const installationId = await stableInstallationId(settings.connect.hostname, target);
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

async function stableInstallationId(
  hostname: string,
  target: CustomerBootstrapTarget,
): Promise<string> {
  const digest = await hashHex({
    hostname,
    accountId: target.accountId,
    zoneId: target.zoneId,
  });
  return `acg-${digest.slice(0, 24)}`;
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
  const sourceSpecifications: Array<{ kind: string; key: string; desired: Record<string, unknown> }> =
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
  const specifications: Array<{ kind: string; key: string; desired: Record<string, unknown> }> = [
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
  return Object.freeze({
    installationId: expected.installationId,
    release: release.id,
    desiredHash: expected.desiredHash,
    target: Object.freeze({ ...target, hostname: settings.connect.hostname }),
    accessPolicy: Object.freeze({
      identityType: 'email' as const,
      identityCount: allowedEmails.length,
      identitiesHash,
    }),
    resources: Object.freeze(resources.map((resource) => Object.freeze({
      kind: resource.kind as GatewayResourceKind,
      key: resource.key,
      desiredHash: resource.desiredHash,
      marker: customerResourceOwnershipMarker(expected.installationId, resource.key),
      ...(
        resource.kind === 'source_access_policy' || resource.kind === 'portal_access_policy'
          ? { identityHash: identitiesHash }
          : {}
      ),
    }))),
  }) as ReadyInstallationReceiptExpectation;
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
  if (matches.length !== 1) fail('plan_mismatch', 'claim', 'not_sent');
  return matches[0];
}

function requiredDesiredString(resource: DesiredResource, field: string): string {
  const value = resource.desired[field];
  if (typeof value !== 'string') fail('plan_mismatch', 'claim', 'not_sent');
  return value;
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
  if (
    !isRecord(input.release) || !exactDataKeys(input.release, ['id', 'artifactSha256']) ||
    typeof input.release.id !== 'string' || !RELEASE.test(input.release.id) ||
    typeof input.release.artifactSha256 !== 'string' || !BARE_SHA256.test(input.release.artifactSha256) ||
    input.release.id !== plan.releaseId || input.release.artifactSha256 !== plan.releaseArtifactSha256 ||
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
  const settings = gatewaySettings(selection);
  const target = Object.freeze({
    accountId: authorizedTarget.account.id,
    zoneId: authorizedTarget.zone.id,
    zoneName: authorizedTarget.zone.name,
  });
  const releaseEvidence = Object.freeze({
    id: input.release.id,
    artifactSha256: `sha256:${input.release.artifactSha256}`,
  });
  const expected = await configurationEvidence(settings, target, releaseEvidence);
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
  const expected = await configurationEvidence(settings, target, release);
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
  value: Record<string, unknown>,
  status: number,
): CustomerBootstrapRecoveryResult | null {
  if (
    status !== 409 ||
    !exactKeys(value, ['schemaVersion', 'error', 'retryable']) ||
    value.schemaVersion !== 1 ||
    typeof value.error !== 'string' ||
    ![
      'bootstrap_recovery_required',
      'bootstrap_requires_repair',
      'bootstrap_request_mismatch',
    ].includes(value.error) ||
    typeof value.retryable !== 'boolean'
  ) return null;
  if (value.error === 'bootstrap_recovery_required' && value.retryable !== true) return null;
  if (value.error !== 'bootstrap_recovery_required' && value.retryable !== false) return null;
  return Object.freeze({
    schemaVersion: 1,
    status: 'recovery_required',
    reason: value.error as CustomerBootstrapRecoveryReason,
    canRetry: false,
  });
}

async function parseReadyResult(
  value: unknown,
  claim: PreparedCustomerBootstrapClaim,
): Promise<CustomerBootstrapReadyResult> {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion',
    'status',
    'installationId',
    'approvedPlanId',
    'configurationHash',
    'desiredHash',
    'settingsRevision',
    'release',
    'gateway',
    'receipt',
    'applyInvoked',
    'resumed',
  ])) fail('response_invalid', 'response', 'unknown');
  const expectedResourceCount = claim.settings.sources.length === 0 ? 4 : 7;
  if (
    value.schemaVersion !== 1 || value.status !== 'ready' ||
    value.installationId !== claim.expected.installationId ||
    typeof value.installationId !== 'string' || !INSTALLATION_ID.test(value.installationId) ||
    typeof value.approvedPlanId !== 'string' || !PLAN_ID.test(value.approvedPlanId) ||
    value.configurationHash !== claim.expected.configurationHash ||
    typeof value.configurationHash !== 'string' || !SHA256.test(value.configurationHash) ||
    value.desiredHash !== claim.expected.desiredHash ||
    typeof value.desiredHash !== 'string' || !SHA256.test(value.desiredHash) ||
    value.settingsRevision !== 1 ||
    !isRecord(value.release) || !exactKeys(value.release, ['id', 'artifactSha256']) ||
    value.release.id !== claim.release.id || value.release.artifactSha256 !== claim.release.artifactSha256 ||
    typeof value.release.id !== 'string' || !RELEASE.test(value.release.id) ||
    typeof value.release.artifactSha256 !== 'string' || !SHA256.test(value.release.artifactSha256) ||
    !isRecord(value.gateway) || !exactKeys(value.gateway, ['hostname', 'mcpUrl']) ||
    value.gateway.hostname !== claim.settings.connect.hostname ||
    value.gateway.mcpUrl !== `https://${claim.settings.connect.hostname}/mcp` ||
    !isRecord(value.receipt) || !exactKeys(value.receipt, ['revision', 'resourceCount', 'evidence']) ||
    !Number.isSafeInteger(value.receipt.revision) || (value.receipt.revision as number) < 0 ||
    value.receipt.resourceCount !== expectedResourceCount ||
    typeof value.applyInvoked !== 'boolean' || typeof value.resumed !== 'boolean'
  ) fail('response_invalid', 'response', 'unknown');
  const receiptExpectation = await installationReceiptExpectation(
    claim.settings,
    claim.target,
    claim.release,
    claim.expected,
  );
  const evidence = await parseReadyInstallationReceipt(value.receipt.evidence, receiptExpectation);
  if (!evidence || evidence.revision !== value.receipt.revision) {
    fail('response_invalid', 'response', 'unknown');
  }
  return Object.freeze({
    schemaVersion: 1,
    status: 'ready',
    installationId: value.installationId,
    approvedPlanId: value.approvedPlanId,
    configurationHash: value.configurationHash,
    desiredHash: value.desiredHash,
    settingsRevision: 1,
    release: Object.freeze({
      id: value.release.id,
      artifactSha256: value.release.artifactSha256,
    }),
    gateway: Object.freeze({
      hostname: value.gateway.hostname as string,
      mcpUrl: value.gateway.mcpUrl as string,
    }),
    receipt: Object.freeze({
      revision: value.receipt.revision as number,
      resourceCount: expectedResourceCount,
      evidence,
    }),
    applyInvoked: value.applyInvoked,
    resumed: value.resumed,
  });
}

async function readBoundedJson(response: Response): Promise<unknown> {
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
    return JSON.parse(text) as unknown;
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
  if (isRecord(value)) {
    const recovery = recoveryResult(value, response.status);
    if (recovery) return recovery;
  }
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

export async function submitCustomerBootstrap(
  input: SubmitCustomerBootstrapInput,
): Promise<CustomerBootstrapResult> {
  if (!input || typeof input !== 'object') fail('invalid_input', 'validate', 'not_sent');
  if (typeof input.transport !== 'function') fail('invalid_input', 'validate', 'not_sent');
  const timeoutMs = requireTimeout(input.timeoutMs);
  const token = requireAccessToken(input.cloudflareAccessToken);
  const nonceBytes = requireNonce(input.bootstrapNonce);
  let rawBody = '';
  try {
    const prepared = await prepareBootstrap(input);
    const claim = prepared.claim;
    const requestUrl = requireBootstrapUrl(
      input.accountWorkersSubdomain,
      prepared.workerName,
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

export function canonicalCustomerBootstrapJson(value: unknown): string {
  return canonicalJson(value);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('canonical_json_invalid');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort(compareText)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  throw new TypeError('canonical_json_invalid');
}

async function hashCanonical(value: unknown): Promise<string> {
  return `sha256:${await hashHex(value)}`;
}

async function hashHex(value: unknown): Promise<string> {
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
