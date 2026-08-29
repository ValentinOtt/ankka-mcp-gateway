import * as v from 'valibot';

import {
  boundaryObjectSchema,
  boundaryValueSchema,
  type BoundaryObject,
  type BoundaryValue,
} from './boundary';
import { CLOUDFLARE_API_ORIGIN } from './constants';
import {
  inspectAdminStateDurableObjectNamespace,
  prepareVerifiedWorkerRelease,
  prepareWorkerVersionRecoveryRecord,
  proveActiveWorkerVersionRecovery,
  type AdminStateDurableObjectNamespaceLocator,
  type CloudflareDirectUploadCall,
  type GatewayWorkerPlainTextBindings,
} from './cloudflare-worker-direct-upload';
import { getZeroTrustOrganization } from './cloudflare-management-surface';
import {
  inspectUninstallWorkerDeploymentRecovery,
  inspectUninstallWorkerVersionRecovery,
  parseAdminStateNamespaceRetirementProof,
  parseCloudflareUninstallWorkerLifecycleSubmission,
  parseWorkerDeleteMutationIntent,
  parseWorkerDeletionRecoveryProof,
  prepareRetirementWorkerVersionMutation,
  prepareUninstallWorkerDeploymentMutation,
  prepareWorkerDeleteMutation,
  proveAdminStateNamespaceRetired,
  provePersistedAdminStateNamespacePresent,
  recoverWorkerDeletionOutcome,
  submitUninstallWorkerDeploymentMutation,
  submitUninstallWorkerVersionMutation,
  submitWorkerDeleteMutation,
  verifyUninstallWorkerDeploymentIsActive,
  verifyUninstallWorkerDeploymentSubmission,
  verifyUninstallWorkerVersionSubmission,
  type ProveAdminStateNamespaceRetiredInput,
  type RetirementWorkerVersionRecoveryRecord,
  type AdminStateNamespaceRetirementProof,
  type UninstallWorkerDeploymentMutationIntent,
  type UninstallWorkerDeploymentSubmission,
  type UninstallWorkerVersionSubmission,
  type WorkerDeleteMutationIntent,
  type WorkerDeletionRecoveryProof,
} from './cloudflare-uninstall-worker-lifecycle';
import { sha256Hex } from './crypto';
import { DeployError } from './errors';
import {
  assertExactReleaseBundleIdentity,
  parseExactReleaseBundleIdentity,
  type ExactReleaseBundleIdentity,
} from './exact-release-bundle';
import { readBoundedText, withDeadline } from './http';
import {
  applyReturningUninstallAction,
  relayReturningUninstallAction,
  type ReturningUninstallActionRelayInput,
} from './returning-uninstall-action-relay';
import {
  returningUninstallAuthorityCanonicalJson as canonicalJson,
  type ReturningUninstallImportedAuthority,
} from './returning-uninstall-authority';
import type {
  ReturningUninstallExecutionInput,
  ReturningUninstallExecutionResult,
  ReturningUninstallExecutor,
  ReturningUninstallRecoveryExecutionInput,
} from './returning-uninstall-executor';
import { adaptVerifiedReleaseBundleForGatewayDeployments } from './release-direct-upload-adapter';
import type { VerifiedReleaseBundle } from './release';
import { assertSecretFree } from './schema';
import {
  MAX_RETURNING_UNINSTALL_LEASE_MS,
  type ReturningUninstallActionName,
  type ReturningUninstallJournal,
} from './returning-uninstall-journal';

const WORKER_ID = /^[a-f0-9]{32}$/u;
const DOMAIN_ID = /^[a-f0-9]{40}$/u;
const PROVIDER_ID = /^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const ACCESS_AUD = /^[A-Za-z0-9._~-]{16,512}$/u;
const MAX_RESPONSE_BYTES = 256 * 1024;
const PAGE_SIZE = 100;
const MAX_PAGES = 20;

type ProviderCall = CloudflareDirectUploadCall;

interface ProviderResponse {
  readonly status: number;
  readonly value: BoundaryValue;
}

interface ManagementLocator {
  readonly marker: string;
  readonly workerId: string;
  readonly namespace: AdminStateDurableObjectNamespaceLocator;
  readonly domain: { readonly id: string; readonly certificateId: string };
  readonly application: {
    readonly id: string;
    readonly aud: string;
    readonly allowedIdentityProviderIds: readonly string[];
  };
  readonly policy: { readonly id: string; readonly applicationId: string; readonly adminEmails: readonly string[] };
  readonly activeRelease: {
    readonly schemaVersion: 1;
    readonly versionId: string;
    readonly deploymentId: string;
    readonly versionRequestHash: string;
  };
}

type UnprovedManagementLocator = Omit<ManagementLocator, 'activeRelease'>;

const providerEnvelopeSchema = v.object({
  success: v.boolean(),
  result: v.optional(boundaryValueSchema),
  errors: v.union([v.array(boundaryValueSchema), v.null()]),
  messages: v.union([v.array(boundaryValueSchema), v.null()]),
  result_info: v.optional(v.object({
    page: v.number(),
    per_page: v.number(),
    count: v.number(),
    total_count: v.number(),
  })),
});
const providerItemSchema = v.pipe(
  boundaryObjectSchema,
  v.check((item) => v.is(v.string(), item.id)),
);
const domainCandidateSchema = v.looseObject({
  id: v.pipe(v.string(), v.regex(DOMAIN_ID)),
  cert_id: v.pipe(v.string(), v.regex(PROVIDER_ID)),
  hostname: v.string(),
  service: v.string(),
  zone_id: v.string(),
  zone_name: v.string(),
  environment: v.optional(v.literal('production')),
});
const applicationCandidateSchema = v.looseObject({
  id: v.pipe(v.string(), v.regex(PROVIDER_ID)),
  aud: v.pipe(v.string(), v.regex(ACCESS_AUD)),
  type: v.literal('self_hosted'),
  name: v.string(),
  domain: v.string(),
  session_duration: v.literal('24h'),
  app_launcher_visible: v.literal(false),
  auto_redirect_to_identity: v.literal(false),
  allow_authenticate_via_warp: v.literal(false),
  allowed_idps: v.pipe(
    v.array(v.pipe(v.string(), v.regex(PROVIDER_ID))),
    v.minLength(1),
    v.maxLength(64),
    v.check((ids) => new Set(ids).size === ids.length),
  ),
});
const policyCandidateSchema = v.looseObject({
  id: v.pipe(v.string(), v.regex(PROVIDER_ID)),
  name: v.string(),
  decision: v.literal('allow'),
  precedence: v.literal(1),
  approval_required: v.optional(v.literal(false)),
  isolation_required: v.optional(v.literal(false)),
  purpose_justification_required: v.optional(v.literal(false)),
  include: v.pipe(v.array(v.strictObject({
    email: v.strictObject({ email: v.string() }),
  })), v.minLength(1)),
  exclude: v.pipe(v.array(boundaryValueSchema), v.length(0)),
  require: v.pipe(v.array(boundaryValueSchema), v.length(0)),
});
const workerCandidateSchema = v.looseObject({
  id: v.pipe(v.string(), v.regex(WORKER_ID)),
  name: v.string(),
  logpush: v.literal(false),
  tags: v.tuple([v.literal('ankka-mcp-gateway'), v.pipe(v.string(), v.regex(/^ankka-worker-sha256:[a-f0-9]{64}$/u))]),
  tail_consumers: v.pipe(v.array(boundaryValueSchema), v.length(0)),
  subdomain: v.looseObject({ enabled: v.literal(false), previews_enabled: v.literal(false) }),
  references: v.looseObject({
    durable_objects: v.pipe(v.array(v.looseObject({
      worker_id: v.string(),
      worker_name: v.string(),
      namespace_id: v.string(),
      namespace_name: v.string(),
    })), v.length(1)),
    domains: v.array(v.looseObject({ id: v.string(), hostname: v.string(), zone_id: v.string() })),
    dispatch_namespace_outbounds: v.pipe(v.array(boundaryValueSchema), v.length(0)),
    queues: v.pipe(v.array(boundaryValueSchema), v.length(0)),
    workers: v.pipe(v.array(boundaryValueSchema), v.length(0)),
  }),
});
const listedWorkerSchema = v.object({
  id: v.pipe(v.string(), v.regex(WORKER_ID)),
  name: v.string(),
});
const disabledSubdomainSchema = v.strictObject({
  enabled: v.literal(false),
  previews_enabled: v.literal(false),
});
const managementLocatorSchema = v.strictObject({
  marker: v.string(),
  workerId: v.pipe(v.string(), v.regex(WORKER_ID)),
  namespace: v.strictObject({
    accountId: v.string(),
    className: v.literal('AdminState'),
    namespaceId: v.pipe(v.string(), v.regex(WORKER_ID)),
    namespaceName: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
    storage: v.literal('sqlite'),
    workerName: v.string(),
  }),
  domain: v.strictObject({
    id: v.pipe(v.string(), v.regex(DOMAIN_ID)),
    certificateId: v.pipe(v.string(), v.regex(PROVIDER_ID)),
  }),
  application: v.strictObject({
    id: v.pipe(v.string(), v.regex(PROVIDER_ID)),
    aud: v.pipe(v.string(), v.regex(ACCESS_AUD)),
    allowedIdentityProviderIds: v.pipe(
      v.array(v.pipe(v.string(), v.regex(PROVIDER_ID))),
      v.minLength(1),
      v.check((ids) => new Set(ids).size === ids.length),
    ),
  }),
  policy: v.strictObject({
    id: v.pipe(v.string(), v.regex(PROVIDER_ID)),
    applicationId: v.pipe(v.string(), v.regex(PROVIDER_ID)),
    adminEmails: v.pipe(v.array(v.string()), v.minLength(1)),
  }),
  activeRelease: v.strictObject({
    schemaVersion: v.literal(1),
    versionId: v.pipe(v.string(), v.regex(PROVIDER_ID)),
    deploymentId: v.pipe(v.string(), v.regex(PROVIDER_ID)),
    versionRequestHash: v.pipe(v.string(), v.regex(SHA256)),
  }),
});
const surfaceLocatorEvidenceSchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: v.literal('ready'),
  authorityHash: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  surface: managementLocatorSchema,
  surfaceHash: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
});
const gatewayRemovalEvidenceSchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: v.literal('gateway_removed'),
  actionId: v.pipe(v.string(), v.regex(/^action_[A-Za-z0-9_-]{32}$/u)),
  installationId: v.string(),
  removedResourceCount: v.pipe(v.number(), v.safeInteger(), v.minValue(4), v.maxValue(103)),
});
const routeListSchema = v.array(v.pipe(
  boundaryObjectSchema,
  v.check((route) => v.is(v.string(), route.pattern)),
));
const noResidueEvidenceSchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: v.literal('no_managed_residue'),
  authorityHash: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  workerDeletionHash: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  namespaceRetirementHash: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  namespaceSnapshotHash: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  routeSnapshotHash: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  evidenceHash: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
});
const finalConvergenceEvidenceSchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: v.literal('removed'),
  installationId: v.string(),
  convergenceHash: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
});

type ParsedProviderEnvelope = v.InferOutput<typeof providerEnvelopeSchema>;
type ParsedDomain = v.InferOutput<typeof domainCandidateSchema>;
type ParsedApplication = v.InferOutput<typeof applicationCandidateSchema>;
type ParsedPolicy = v.InferOutput<typeof policyCandidateSchema>;
type GatewayRemovalEvidence = v.InferOutput<typeof gatewayRemovalEvidenceSchema>;
type NoResidueEvidence = v.InferOutput<typeof noResidueEvidenceSchema>;
type FinalConvergenceEvidence = v.InferOutput<typeof finalConvergenceEvidenceSchema>;

interface SurfaceLocatorEvidence {
  readonly schemaVersion: 1;
  readonly status: 'ready';
  readonly authorityHash: string;
  readonly surface: ManagementLocator;
  readonly surfaceHash: string;
}

function record(value: BoundaryValue): value is BoundaryObject {
  return v.is(boundaryObjectSchema, value);
}

function same<Left, Right>(left: Left, right: Right): boolean {
  try { return canonicalJson(left) === canonicalJson(right); }
  catch { return false; }
}

function empty(value: BoundaryValue): boolean {
  return value === null || (Array.isArray(value) && value.length === 0);
}

function envelope<Input>(value: Input): ParsedProviderEnvelope | null {
  const result = v.safeParse(providerEnvelopeSchema, value);
  return result.success ? result.output : null;
}

async function providerRequest(call: ProviderCall, path: string, method: 'GET' | 'DELETE'): Promise<ProviderResponse> {
  return withDeadline(async (signal) => {
    const response = await call.transport(new Request(
      new URL(`/client/v4${path}`, CLOUDFLARE_API_ORIGIN),
      {
        method,
        headers: { accept: 'application/json', authorization: `Bearer ${call.accessToken}` },
        redirect: 'manual',
        signal,
      },
    ));
    if (response.redirected || (response.status >= 300 && response.status < 400)) {
      await response.body?.cancel().catch(() => undefined);
      throw new DeployError(409, 'session_conflict', 'returning_provider_redirect');
    }
    if (response.status === 204) {
      await response.body?.cancel().catch(() => undefined);
      return Object.freeze({ status: 204, value: null });
    }
    const serialized = await readBoundedText(response, 'session_conflict', MAX_RESPONSE_BYTES);
    let value: BoundaryValue;
    try { value = v.parse(boundaryValueSchema, JSON.parse(serialized)); }
    catch { throw new DeployError(409, 'session_conflict', 'returning_provider_response'); }
    return Object.freeze({ status: response.status, value });
  }, 'session_conflict', call.timeoutMs);
}

function successResult(response: ProviderResponse): BoundaryValue {
  const parsed = envelope(response.value);
  if (response.status !== 200 || !parsed || parsed.success !== true ||
    !Object.hasOwn(parsed, 'result') || !empty(parsed.errors) || !empty(parsed.messages)) {
    throw new DeployError(409, 'session_conflict', 'returning_provider_mismatch');
  }
  return parsed.result;
}

function exactAbsent(response: ProviderResponse): boolean {
  const parsed = envelope(response.value);
  return response.status === 404 && parsed?.success === false && parsed.result === null &&
    Array.isArray(parsed.errors) && parsed.errors.length > 0 && empty(parsed.messages);
}

async function getResult(call: ProviderCall, path: string): Promise<BoundaryValue | null> {
  const response = await providerRequest(call, path, 'GET');
  if (exactAbsent(response)) return null;
  return successResult(response);
}

function page<Input>(value: Input, requested: number): readonly BoundaryObject[] {
  const parsed = envelope(value);
  const info = parsed?.result_info;
  if (!parsed || parsed.success !== true || !empty(parsed.errors) || !empty(parsed.messages) ||
    !Array.isArray(parsed.result) || !record(info) || info.page !== requested || info.per_page !== PAGE_SIZE ||
    info.count !== parsed.result.length || !Number.isSafeInteger(info.count) ||
    !Number.isSafeInteger(info.total_count) || info.total_count < 0) {
    throw new DeployError(409, 'session_conflict', 'returning_provider_mismatch');
  }
  const items: BoundaryObject[] = [];
  for (const candidate of parsed.result) {
    const result = v.safeParse(providerItemSchema, candidate);
    if (!result.success) throw new DeployError(409, 'session_conflict', 'returning_provider_ambiguous');
    items.push(result.output);
  }
  return items;
}

async function paginated(call: ProviderCall, path: string, filter: URLSearchParams): Promise<readonly BoundaryObject[]> {
  const values: BoundaryObject[] = [];
  const ids = new Set<string>();
  for (let number = 1; number <= MAX_PAGES; number += 1) {
    const query = new URLSearchParams(filter);
    query.set('page', String(number));
    query.set('per_page', String(PAGE_SIZE));
    const response = await providerRequest(call, `${path}?${query}`, 'GET');
    const current = page(response.value, number);
    for (const item of current) {
      if (!v.is(v.string(), item.id) || ids.has(item.id)) {
        throw new DeployError(409, 'session_conflict', 'returning_provider_ambiguous');
      }
      ids.add(item.id);
      values.push(item);
    }
    if (current.length < PAGE_SIZE) return Object.freeze(values);
  }
  throw new DeployError(409, 'session_conflict', 'returning_provider_ambiguous');
}

async function customDomains(
  call: ProviderCall,
  accountId: string,
  hostname: string,
): Promise<readonly BoundaryValue[]> {
  const query = new URLSearchParams({ hostname });
  const response = await providerRequest(call, `/accounts/${accountId}/workers/domains?${query}`, 'GET');
  const result = successResult(response);
  if (!Array.isArray(result) || result.length > 2_000) {
    throw new DeployError(409, 'session_conflict', 'returning_provider_mismatch');
  }
  return Object.freeze([...result]);
}

function markerFromWorkerName(workerName: string): string {
  const match = workerName.match(/-(acg-[a-f0-9]{24})$/u);
  const marker = match?.at(1);
  if (marker === undefined) throw new DeployError(409, 'session_conflict');
  return marker;
}

function parseDomain(
  value: BoundaryValue,
  authority: ReturningUninstallImportedAuthority,
): ParsedDomain | null {
  const result = v.safeParse(domainCandidateSchema, value);
  if (!result.success || result.output.hostname !== authority.runtime.managementHostname ||
      result.output.service !== authority.runtime.workerName || result.output.zone_id !== authority.runtime.zoneId ||
      result.output.zone_name !== authority.runtime.zoneName) return null;
  return result.output;
}

function exactDomain(value: BoundaryValue, authority: ReturningUninstallImportedAuthority): boolean {
  return parseDomain(value, authority) !== null;
}

function parseApplication(
  value: BoundaryValue,
  authority: ReturningUninstallImportedAuthority,
  marker: string,
): ParsedApplication | null {
  const result = v.safeParse(applicationCandidateSchema, value);
  if (!result.success || result.output.name !== `${authority.control.portal.name} management [${marker}]` ||
      result.output.domain !== authority.runtime.managementHostname) return null;
  return result.output;
}

function exactApplication(
  value: BoundaryValue,
  authority: ReturningUninstallImportedAuthority,
  marker: string,
): boolean {
  return parseApplication(value, authority, marker) !== null;
}

function parsePolicy(
  value: BoundaryValue,
  authority: ReturningUninstallImportedAuthority,
  marker: string,
): ParsedPolicy | null {
  const result = v.safeParse(policyCandidateSchema, value);
  if (!result.success || result.output.name !== `${authority.control.portal.name} administrators [${marker}]`) {
    return null;
  }
  const emails = result.output.include.map((rule) => rule.email.email);
  if (emails.some((email) => email !== email.toLowerCase() ||
      !authority.control.audienceEmails.includes(email))) return null;
  emails.sort();
  return new Set(emails).size === emails.length && emails.includes(authority.actorEmail) ? result.output : null;
}

function exactPolicy(
  value: BoundaryValue,
  authority: ReturningUninstallImportedAuthority,
  marker: string,
): boolean {
  return parsePolicy(value, authority, marker) !== null;
}

function exactWorker(
  value: BoundaryValue,
  authority: ReturningUninstallImportedAuthority,
  workerId: string,
  namespace: AdminStateDurableObjectNamespaceLocator,
  domain: ManagementLocator['domain'],
): boolean {
  const result = v.safeParse(workerCandidateSchema, value);
  if (!result.success || result.output.id !== workerId || result.output.name !== authority.runtime.workerName) {
    return false;
  }
  const durable = result.output.references.durable_objects[0];
  if (!durable || durable.worker_id !== workerId || durable.worker_name !== authority.runtime.workerName ||
    durable.namespace_id !== namespace.namespaceId || durable.namespace_name !== namespace.namespaceName) return false;
  const domains = result.output.references.domains;
  return domains.length === 1 && domains[0]?.id === domain.id &&
    domains[0].hostname === authority.runtime.managementHostname && domains[0].zone_id === authority.runtime.zoneId;
}

function installedWorkerPlainTextBindings(
  authority: ReturningUninstallImportedAuthority,
  surface: UnprovedManagementLocator,
  accessIssuer: string,
): GatewayWorkerPlainTextBindings {
  return Object.freeze({
    ADMIN_EMAILS: authority.control.audienceEmails.join(','),
    ANKKA_GATEWAY_RELEASE: authority.runtime.release,
    ANKKA_GATEWAY_RELEASE_SHA256: authority.runtime.artifactSha256,
    ANKKA_MANAGEMENT_HOSTNAME: authority.runtime.managementHostname,
    ANKKA_UPDATE_CHANNEL: authority.runtime.updateChannel,
    ANKKA_UPDATE_KEY_ID: authority.runtime.updateKeyId,
    ANKKA_UPDATE_PUBLIC_KEY: authority.runtime.updatePublicKey,
    ANKKA_WORKERS_SUBDOMAIN: authority.runtime.workersSubdomain,
    ANKKA_WORKER_NAME: authority.runtime.workerName,
    CF_ACCESS_AUD: surface.application.aud,
    CF_ACCESS_ISSUER: accessIssuer,
    CLOUDFLARE_ACCOUNT_ID: authority.runtime.accountId,
    CLOUDFLARE_ZONE_ID: authority.runtime.zoneId,
    CLOUDFLARE_ZONE_NAME: authority.runtime.zoneName,
    ZERO_TRUST_READY: 'true',
  });
}

async function proveInstalledManagementWorkerRelease(
  authority: ReturningUninstallImportedAuthority,
  surface: UnprovedManagementLocator,
  releaseBundle: VerifiedReleaseBundle,
  call: ProviderCall,
): Promise<ManagementLocator['activeRelease']> {
  const organization = await getZeroTrustOrganization({
    ...call,
    accountId: authority.runtime.accountId,
  });
  const releaseSet = await adaptVerifiedReleaseBundleForGatewayDeployments(releaseBundle);
  const prepared = await prepareVerifiedWorkerRelease({
    accountId: authority.runtime.accountId,
    workerName: authority.runtime.workerName,
    release: releaseSet.primary,
    plainTextBindings: installedWorkerPlainTextBindings(authority, surface, organization.issuer),
    // Clean-version recovery never serializes or verifies a bootstrap secret;
    // the preparation primitive still requires a syntactically valid value.
    bootstrapNonce: 'returning-uninstall-readback-only-0001',
  });
  const recovery = await prepareWorkerVersionRecoveryRecord(prepared, Object.freeze({
    kind: 'worker' as const,
    accountId: authority.runtime.accountId,
    workerName: authority.runtime.workerName,
    workerId: surface.workerId,
  }), 'clean');
  const proof = await proveActiveWorkerVersionRecovery(
    recovery,
    call,
    surface.namespace.namespaceId,
  );
  return Object.freeze({
    schemaVersion: 1,
    versionId: proof.version.versionId,
    deploymentId: proof.deployment.deploymentId,
    versionRequestHash: recovery.requestHash,
  });
}

async function inspectManagement(
  authority: ReturningUninstallImportedAuthority,
  releaseBundle: VerifiedReleaseBundle,
  call: ProviderCall,
): Promise<ManagementLocator> {
  const marker = markerFromWorkerName(authority.runtime.workerName);
  const domainValues = await customDomains(
    call,
    authority.runtime.accountId,
    authority.runtime.managementHostname,
  );
  const domainMatches: ParsedDomain[] = [];
  for (const value of domainValues) {
    const parsed = parseDomain(value, authority);
    if (parsed) domainMatches.push(parsed);
  }
  if (domainValues.length !== domainMatches.length || domainMatches.length !== 1) {
    throw new DeployError(409, 'session_conflict', 'returning_management_domain_ambiguous');
  }
  const domain = domainMatches[0];
  if (!domain) throw new DeployError(409, 'session_conflict', 'returning_management_domain_ambiguous');
  const applications = await paginated(
    call,
    `/accounts/${authority.runtime.accountId}/access/apps`,
    new URLSearchParams({ domain: authority.runtime.managementHostname }),
  );
  const applicationMatches: ParsedApplication[] = [];
  for (const value of applications) {
    const parsed = parseApplication(value, authority, marker);
    if (parsed) applicationMatches.push(parsed);
  }
  if (applications.length !== applicationMatches.length || applicationMatches.length !== 1) {
    throw new DeployError(409, 'session_conflict', 'returning_management_application_ambiguous');
  }
  const application = applicationMatches[0];
  if (!application) {
    throw new DeployError(409, 'session_conflict', 'returning_management_application_ambiguous');
  }
  const policies = await paginated(
    call,
    `/accounts/${authority.runtime.accountId}/access/apps/${encodeURIComponent(application.id)}/policies`,
    new URLSearchParams(),
  );
  const policyMatches: ParsedPolicy[] = [];
  for (const value of policies) {
    const parsed = parsePolicy(value, authority, marker);
    if (parsed) policyMatches.push(parsed);
  }
  if (policies.length !== policyMatches.length || policyMatches.length !== 1) {
    throw new DeployError(409, 'session_conflict', 'returning_management_policy_ambiguous');
  }
  const policy = policyMatches[0];
  if (!policy) throw new DeployError(409, 'session_conflict', 'returning_management_policy_ambiguous');
  const workers = await paginated(
    call,
    `/accounts/${authority.runtime.accountId}/workers/workers`,
    new URLSearchParams(),
  );
  const workerMatches = workers.map((value) => v.safeParse(listedWorkerSchema, value))
    .filter((result) => result.success && result.output.name === authority.runtime.workerName);
  if (workerMatches.length !== 1 || !workerMatches[0]?.success) {
    throw new DeployError(409, 'session_conflict', 'returning_management_worker_ambiguous');
  }
  const workerId = workerMatches[0].output.id;
  const namespace = await inspectAdminStateDurableObjectNamespace({
    accountId: authority.runtime.accountId,
    workerName: authority.runtime.workerName,
    className: 'AdminState',
    storage: 'sqlite',
  }, call);
  const exactWorkerValue = await getResult(
    call,
    `/accounts/${authority.runtime.accountId}/workers/workers/${encodeURIComponent(workerId)}`,
  );
  const locator: UnprovedManagementLocator = Object.freeze({
    marker,
    workerId,
    namespace,
    domain: Object.freeze({ id: domain.id, certificateId: domain.cert_id }),
    application: Object.freeze({
      id: application.id,
      aud: application.aud,
      allowedIdentityProviderIds: Object.freeze([...application.allowed_idps].sort()),
    }),
    policy: Object.freeze({
      id: policy.id,
      applicationId: application.id,
      adminEmails: Object.freeze(policy.include.map((rule) => rule.email.email).sort()),
    }),
  });
  if (!exactWorker(exactWorkerValue, authority, workerId, namespace, locator.domain)) {
    throw new DeployError(409, 'session_conflict', 'returning_management_worker_mismatch');
  }
  const subdomain = await getResult(
    call,
    `/accounts/${authority.runtime.accountId}/workers/scripts/${encodeURIComponent(authority.runtime.workerName)}/subdomain`,
  );
  if (!v.safeParse(disabledSubdomainSchema, subdomain).success) {
    throw new DeployError(409, 'session_conflict', 'returning_workers_dev_enabled');
  }
  const activeRelease = await proveInstalledManagementWorkerRelease(
    authority,
    locator,
    releaseBundle,
    call,
  );
  return Object.freeze({ ...locator, activeRelease });
}

function exactDeleteSuccess(response: ProviderResponse, expectedId: string | null, domain: boolean): boolean {
  if (response.status === 204) return true;
  if (!record(response.value) || response.status !== 200 || response.value.success !== true ||
    !empty(response.value.errors) || !empty(response.value.messages)) return false;
  if (domain) return !Object.hasOwn(response.value, 'result');
  const result = response.value.result;
  return result === null || (record(result) && Object.keys(result).length === 1 && result.id === expectedId);
}

async function proveAbsent(
  call: ProviderCall,
  path: string,
  list: () => Promise<readonly BoundaryValue[]>,
): Promise<void> {
  for (let observation = 0; observation < 2; observation += 1) {
    const direct = await providerRequest(call, path, 'GET');
    if (!exactAbsent(direct)) throw new DeployError(409, 'session_conflict', 'returning_delete_not_converged');
    const values = await list();
    if (values.length !== 0) {
      throw new DeployError(409, 'session_conflict', 'returning_delete_not_converged');
    }
  }
}

async function deleteAndProve(
  call: ProviderCall,
  path: string,
  id: string,
  domain: boolean,
  matches: (value: BoundaryValue) => boolean,
  list: () => Promise<readonly BoundaryValue[]>,
): Promise<void> {
  const before = await providerRequest(call, path, 'GET');
  if (exactAbsent(before)) {
    await proveAbsent(call, path, list);
    return;
  }
  if (!matches(successResult(before))) {
    throw new DeployError(409, 'session_conflict', 'returning_replacement_detected');
  }
  try {
    const response = await providerRequest(call, path, 'DELETE');
    if (!exactDeleteSuccess(response, id, domain)) {
      throw new DeployError(409, 'session_conflict', 'returning_provider_mismatch');
    }
  } catch {
    // A transport failure may have applied. Only read-only convergence below
    // decides the outcome; this attempt never replays the DELETE.
  }
  await proveAbsent(call, path, list);
}

function relayInput(input: ReturningUninstallExecutionInput): ReturningUninstallActionRelayInput {
  return Object.freeze({
    actionId: input.action.actionId,
    actionKey: input.action.actionKey,
    actorEmail: input.action.actorEmail,
    accountId: input.action.accountId,
    installationId: input.action.installationId,
    workerName: input.action.workerName,
    workersSubdomain: input.action.workersSubdomain,
    managementOrigin: input.action.managementOrigin,
    portalHostname: input.plan.gateway.portalHostname,
    gatewayName: input.plan.gateway.name,
    expiresAt: input.action.expiresAt,
    accessToken: input.accessToken,
    transport: input.transport,
  });
}

type ManagementDeleteName =
  | 'management_custom_domain_delete'
  | 'management_admin_policy_delete'
  | 'management_access_application_delete';

interface ManagementDeleteSpec {
  readonly path: string;
  readonly id: string;
  readonly domain: boolean;
  readonly matches: (value: BoundaryValue) => boolean;
  readonly list: () => Promise<readonly BoundaryValue[]>;
}

interface ExecutionState {
  readonly input: ReturningUninstallExecutionInput | ReturningUninstallRecoveryExecutionInput;
  readonly releaseBundle: VerifiedReleaseBundle;
  readonly authority: ReturningUninstallImportedAuthority;
  readonly action: ReturningUninstallActionRelayInput | null;
  readonly call: ProviderCall;
  journal: ReturningUninstallJournal;
}

async function digest<Value>(value: Value): Promise<string> {
  return `sha256:${await sha256Hex(canonicalJson(value))}`;
}

function operationNow(state: ExecutionState): number {
  const now = Math.max(Date.now(), state.journal.updatedAt);
  if (!Number.isSafeInteger(now) || now >= state.input.recoverUntil) {
    throw new DeployError(409, 'session_conflict', 'returning_recovery_expired');
  }
  return now;
}

function journalAction(state: ExecutionState, name: ReturningUninstallActionName) {
  return state.journal.actions.find((candidate) => candidate.name === name) ?? null;
}

function freshHostedRecoveryMayResubmit(
  state: ExecutionState,
  action: NonNullable<ReturnType<typeof journalAction>>,
): boolean {
  const approval = state.journal.approvalHistory.at(-1);
  return approval?.authorization === 'hosted_recovery' &&
    approval.attemptId === state.input.attemptId && action.sendArmedAt !== null &&
    approval.approvedAt >= action.sendArmedAt + MAX_RETURNING_UNINSTALL_LEASE_MS;
}

async function refreshLease(state: ExecutionState): Promise<void> {
  const now = operationNow(state);
  if (state.journal.lease?.attemptId === state.input.attemptId &&
    state.journal.lease.expiresAt > now + 30_000) return;
  const expiresAt = Math.min(
    now + MAX_RETURNING_UNINSTALL_LEASE_MS,
    state.input.plan.expiresAt,
    state.input.recoverUntil,
  );
  if (expiresAt <= now) throw new DeployError(409, 'session_conflict', 'returning_recovery_expired');
  state.journal = await state.input.journal.acquireLease({
    expectedRevision: state.journal.revision,
    attemptId: state.input.attemptId,
    now,
    expiresAt,
  });
}

async function prepareAction<Value>(
  state: ExecutionState,
  name: ReturningUninstallActionName,
  value: Value,
): Promise<void> {
  const normalized = v.parse(boundaryValueSchema, value);
  await refreshLease(state);
  const current = journalAction(state, name);
  if (current) {
    if (!same(current.record, normalized)) throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
    return;
  }
  state.journal = await state.input.journal.prepare({
    expectedRevision: state.journal.revision,
    attemptId: state.input.attemptId,
    now: operationNow(state),
    name,
    record: normalized,
  });
}

async function armAction(state: ExecutionState, name: ReturningUninstallActionName): Promise<boolean> {
  await refreshLease(state);
  const current = journalAction(state, name);
  if (!current) throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
  if (current.phase !== 'prepared') return false;
  state.journal = await state.input.journal.arm({
    expectedRevision: state.journal.revision,
    attemptId: state.input.attemptId,
    now: operationNow(state),
    name,
  });
  return true;
}

async function submitAction<Locator>(
  state: ExecutionState,
  name: ReturningUninstallActionName,
  locator: Locator,
): Promise<void> {
  const normalized = v.parse(boundaryValueSchema, locator);
  state.journal = await state.input.journal.submit({
    expectedRevision: state.journal.revision,
    attemptId: state.input.attemptId,
    now: operationNow(state),
    name,
    locator: normalized,
  });
}

async function verifyAction<Locator>(
  state: ExecutionState,
  name: ReturningUninstallActionName,
  locator: Locator,
): Promise<void> {
  const normalized = v.parse(boundaryValueSchema, locator);
  state.journal = await state.input.journal.verify({
    expectedRevision: state.journal.revision,
    attemptId: state.input.attemptId,
    now: operationNow(state),
    name,
    locator: normalized,
  });
}

async function surfaceLocator(
  authority: ReturningUninstallImportedAuthority,
  surface: ManagementLocator,
): Promise<SurfaceLocatorEvidence> {
  const semantic = {
    schemaVersion: 1,
    status: 'ready',
    authorityHash: authority.authorityHash,
    surface,
  } satisfies Omit<SurfaceLocatorEvidence, 'surfaceHash'>;
  return Object.freeze({ ...semantic, surfaceHash: await digest(semantic) });
}

async function parseSurfaceLocator<Input>(
  authority: ReturningUninstallImportedAuthority,
  value: Input,
): Promise<ManagementLocator | null> {
  const result = v.safeParse(surfaceLocatorEvidenceSchema, value);
  if (!result.success || result.output.authorityHash !== authority.authorityHash) return null;
  const { surfaceHash, ...semantic } = result.output;
  if (surfaceHash !== await digest(semantic)) return null;
  const surface = result.output.surface;
  if (surface.marker !== markerFromWorkerName(authority.runtime.workerName) ||
    surface.namespace.accountId !== authority.runtime.accountId ||
    surface.policy.applicationId !== surface.application.id ||
    surface.namespace.workerName !== authority.runtime.workerName ||
    surface.policy.adminEmails.some((email) => !authority.control.audienceEmails.includes(email)) ||
    !surface.policy.adminEmails.includes(authority.actorEmail)) return null;
  return surface;
}

async function convergeSurface(state: ExecutionState): Promise<ManagementLocator> {
  const name = 'surface_preflight' as const;
  let current = journalAction(state, name);
  if (current?.phase === 'verified') {
    const parsed = await parseSurfaceLocator(state.authority, current.locator);
    if (!parsed) throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
    const retirementDeployment = journalAction(state, 'retirement_worker_deployment_create');
    // Until a retirement deployment may have been sent, the original clean
    // version must remain exactly active on every resumed attempt. This
    // catches binding/version drift even after earlier management resources
    // have already been removed.
    if (!retirementDeployment || retirementDeployment.phase === 'prepared') {
      const activeRelease = await proveInstalledManagementWorkerRelease(
        state.authority,
        parsed,
        state.releaseBundle,
        state.call,
      );
      if (!same(activeRelease, parsed.activeRelease)) {
        throw new DeployError(409, 'session_conflict', 'returning_active_release_changed');
      }
    }
    return parsed;
  }
  const surface = await inspectManagement(state.authority, state.releaseBundle, state.call);
  const locator = await surfaceLocator(state.authority, surface);
  const recordValue = Object.freeze({
    schemaVersion: 1,
    kind: 'returning_surface_preflight',
    authorityHash: state.authority.authorityHash,
    surfaceHash: locator.surfaceHash,
  });
  await prepareAction(state, name, recordValue);
  await armAction(state, name);
  current = journalAction(state, name);
  if (current?.phase === 'send_armed') await submitAction(state, name, locator);
  current = journalAction(state, name);
  if (current?.phase === 'submitted') await verifyAction(state, name, locator);
  current = journalAction(state, name);
  if (current?.phase !== 'verified' || !same(current.locator, locator)) {
    throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
  }
  return surface;
}

function parseGatewayRemovalEvidence<Input>(value: Input, installationId: string): GatewayRemovalEvidence | null {
  const result = v.safeParse(gatewayRemovalEvidenceSchema, value);
  return result.success && result.output.installationId === installationId ? result.output : null;
}

async function convergeGatewayRemoval(
  state: ExecutionState,
  surface: ManagementLocator,
): Promise<GatewayRemovalEvidence> {
  const name = 'customer_gateway_remove' as const;
  if (!state.action) throw new DeployError(409, 'session_conflict', 'returning_action_required');
  const recordValue = Object.freeze({
    schemaVersion: 1,
    kind: 'returning_customer_gateway_remove',
    authorityHash: state.authority.authorityHash,
    installationId: state.authority.installationId,
  });
  await prepareAction(state, name, recordValue);
  await armAction(state, name);
  let current = journalAction(state, name);
  if (current?.phase === 'send_armed') {
    const requestHash = await sha256Hex(`returning-remove:${state.journal.bindingHash}`);
    const removal = await applyReturningUninstallAction(
      state.action,
      requestHash.slice(0, 22),
      state.authority,
      async () => {
        const activeRelease = await proveInstalledManagementWorkerRelease(
          state.authority,
          surface,
          state.releaseBundle,
          state.call,
        );
        if (!same(activeRelease, surface.activeRelease)) {
          throw new DeployError(409, 'session_conflict', 'returning_active_release_changed');
        }
      },
    );
    await submitAction(state, name, removal);
  }
  current = journalAction(state, name);
  if (current?.phase === 'submitted') {
    const evidence = parseGatewayRemovalEvidence(current.locator, state.authority.installationId);
    if (!evidence) {
      throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
    }
    await verifyAction(state, name, evidence);
  }
  current = journalAction(state, name);
  const evidence = parseGatewayRemovalEvidence(current?.locator, state.authority.installationId);
  if (current?.phase !== 'verified' || !evidence) {
    throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
  }
  return evidence;
}

function managementDeleteSpec(
  authority: ReturningUninstallImportedAuthority,
  surface: ManagementLocator,
  call: ProviderCall,
  name: ManagementDeleteName,
): ManagementDeleteSpec {
  if (name === 'management_custom_domain_delete') return {
    path: `/accounts/${authority.runtime.accountId}/workers/domains/${encodeURIComponent(surface.domain.id)}`,
    id: surface.domain.id,
    domain: true,
    matches: (value) => exactDomain(value, authority),
    list: () => customDomains(call, authority.runtime.accountId, authority.runtime.managementHostname),
  };
  if (name === 'management_admin_policy_delete') return {
    path: `/accounts/${authority.runtime.accountId}/access/apps/${encodeURIComponent(surface.application.id)}` +
      `/policies/${encodeURIComponent(surface.policy.id)}`,
    id: surface.policy.id,
    domain: false,
    matches: (value) => exactPolicy(value, authority, surface.marker),
    list: () => paginated(call,
      `/accounts/${authority.runtime.accountId}/access/apps/${encodeURIComponent(surface.application.id)}/policies`,
      new URLSearchParams()),
  };
  return {
    path: `/accounts/${authority.runtime.accountId}/access/apps/${encodeURIComponent(surface.application.id)}`,
    id: surface.application.id,
    domain: false,
    matches: (value) => exactApplication(value, authority, surface.marker),
    list: () => paginated(call, `/accounts/${authority.runtime.accountId}/access/apps`,
      new URLSearchParams({ domain: authority.runtime.managementHostname })),
  };
}

async function convergeManagementDelete(
  state: ExecutionState,
  surface: ManagementLocator,
  name: ManagementDeleteName,
): Promise<BoundaryObject> {
  const spec = managementDeleteSpec(state.authority, surface, state.call, name);
  const recordValue = Object.freeze({
    schemaVersion: 1,
    kind: name,
    authorityHash: state.authority.authorityHash,
    resourceId: spec.id,
  });
  await prepareAction(state, name, recordValue);
  await armAction(state, name);
  let current = journalAction(state, name);
  const evidence = Object.freeze({
    schemaVersion: 1,
    status: 'absent',
    action: name,
    authorityHash: state.authority.authorityHash,
    resourceId: spec.id,
  });
  if (current?.phase === 'verified') {
    if (!same(current.locator, evidence)) {
      throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
    }
    return evidence;
  }
  if (current?.phase === 'send_armed') {
    // DELETE is safe to resume only after an exact read proves either the
    // receipt-owned resource or durable absence. This covers both sides of a
    // crash at send_armed without ever deleting a replacement.
    await deleteAndProve(state.call, spec.path, spec.id, spec.domain, spec.matches, spec.list);
    await submitAction(state, name, evidence);
  }
  current = journalAction(state, name);
  if (current?.phase === 'submitted') {
    await proveAbsent(state.call, spec.path, spec.list);
    if (!same(current.locator, evidence)) {
      throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
    }
    await verifyAction(state, name, evidence);
  }
  current = journalAction(state, name);
  if (current?.phase !== 'verified' || !same(current.locator, evidence)) {
    throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
  }
  return evidence;
}

async function inspectVersionTwice(
  recovery: RetirementWorkerVersionRecoveryRecord,
  call: ProviderCall,
): Promise<UninstallWorkerVersionSubmission | null> {
  const first = await inspectUninstallWorkerVersionRecovery(recovery, call);
  const second = await inspectUninstallWorkerVersionRecovery(recovery, call);
  if (!same(first, second)) throw new DeployError(409, 'session_conflict', 'returning_recovery_ambiguous');
  return second;
}

function parsedRetirementVersion<Input>(
  value: Input,
  recovery: RetirementWorkerVersionRecoveryRecord,
): UninstallWorkerVersionSubmission | null {
  const parsed = parseCloudflareUninstallWorkerLifecycleSubmission(value);
  return parsed?.kind === 'uninstall_worker_version' && parsed.stage === 'retirement' &&
    parsed.accountId === recovery.accountId && parsed.workerName === recovery.workerName &&
    parsed.workerId === recovery.workerId && parsed.uninstallCycleId === recovery.uninstallCycleId &&
    parsed.requestHash === recovery.requestHash ? parsed : null;
}

async function convergeRetirementVersion(
  state: ExecutionState,
  surface: ManagementLocator,
  uninstallCycleId: string,
): Promise<{ readonly recovery: RetirementWorkerVersionRecoveryRecord; readonly submission: UninstallWorkerVersionSubmission }> {
  const releaseSet = await adaptVerifiedReleaseBundleForGatewayDeployments(state.releaseBundle);
  const mutation = await prepareRetirementWorkerVersionMutation({
    accountId: state.authority.runtime.accountId,
    workerName: state.authority.runtime.workerName,
    workerId: surface.workerId,
    uninstallCycleId,
    releaseSet,
  });
  if (mutation.recovery.stage !== 'retirement') throw new DeployError(500, 'internal_error');
  const recovery = mutation.recovery;
  const name = 'retirement_worker_version_create' as const;
  await prepareAction(state, name, Object.freeze({
    schemaVersion: 1,
    kind: 'returning_retirement_worker_version_create',
    recovery,
  }));
  const armedHere = await armAction(state, name);
  let current = journalAction(state, name);
  if (current?.phase === 'send_armed') {
    let submission = armedHere ? null : await inspectVersionTwice(recovery, state.call);
    if (!armedHere && !submission && freshHostedRecoveryMayResubmit(state, current)) {
      try { submission = await submitUninstallWorkerVersionMutation(mutation.ephemeral, recovery, state.call); }
      catch (error) {
        submission = await inspectVersionTwice(recovery, state.call);
        if (!submission) throw error;
      }
    }
    if (armedHere) {
      try { submission = await submitUninstallWorkerVersionMutation(mutation.ephemeral, recovery, state.call); }
      catch (error) {
        submission = await inspectVersionTwice(recovery, state.call);
        if (!submission) throw error;
      }
    }
    if (!submission) throw new DeployError(409, 'session_conflict', 'returning_retirement_version_missing');
    await submitAction(state, name, submission);
  }
  current = journalAction(state, name);
  if (current?.phase === 'submitted') {
    const submission = parsedRetirementVersion(current.locator, recovery);
    if (!submission) throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
    await verifyUninstallWorkerVersionSubmission(recovery, submission, state.call);
    await verifyAction(state, name, submission);
  }
  current = journalAction(state, name);
  const submission = parsedRetirementVersion(current?.locator, recovery);
  if (current?.phase !== 'verified' || !submission) {
    throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
  }
  return Object.freeze({ recovery, submission });
}

async function inspectDeploymentTwice(
  intent: UninstallWorkerDeploymentMutationIntent,
  call: ProviderCall,
): Promise<UninstallWorkerDeploymentSubmission | null> {
  const first = await inspectUninstallWorkerDeploymentRecovery(intent, call);
  const second = await inspectUninstallWorkerDeploymentRecovery(intent, call);
  if (!same(first, second)) throw new DeployError(409, 'session_conflict', 'returning_recovery_ambiguous');
  return second;
}

function parsedRetirementDeployment<Input>(
  value: Input,
  intent: UninstallWorkerDeploymentMutationIntent,
): UninstallWorkerDeploymentSubmission | null {
  const parsed = parseCloudflareUninstallWorkerLifecycleSubmission(value);
  return parsed?.kind === 'uninstall_worker_deployment' && parsed.stage === 'retirement' &&
    parsed.accountId === intent.accountId && parsed.workerName === intent.workerName &&
    parsed.workerId === intent.workerId && parsed.uninstallCycleId === intent.uninstallCycleId &&
    parsed.versionId === intent.versionId && parsed.requestHash === intent.requestHash ? parsed : null;
}

async function convergeRetirementDeployment(
  state: ExecutionState,
  surface: ManagementLocator,
  uninstallCycleId: string,
  versionId: string,
): Promise<{ readonly intent: UninstallWorkerDeploymentMutationIntent; readonly submission: UninstallWorkerDeploymentSubmission }> {
  const intent = await prepareUninstallWorkerDeploymentMutation({
    stage: 'retirement',
    accountId: state.authority.runtime.accountId,
    workerName: state.authority.runtime.workerName,
    workerId: surface.workerId,
    uninstallCycleId,
    versionId,
  });
  const name = 'retirement_worker_deployment_create' as const;
  await prepareAction(state, name, Object.freeze({
    schemaVersion: 1,
    kind: 'returning_retirement_worker_deployment_create',
    intent,
  }));
  const armedHere = await armAction(state, name);
  let current = journalAction(state, name);
  if (current?.phase === 'send_armed') {
    let submission = armedHere ? null : await inspectDeploymentTwice(intent, state.call);
    if (!armedHere && !submission && freshHostedRecoveryMayResubmit(state, current)) {
      try { submission = await submitUninstallWorkerDeploymentMutation(intent, state.call); }
      catch (error) {
        submission = await inspectDeploymentTwice(intent, state.call);
        if (!submission) throw error;
      }
    }
    if (armedHere) {
      try { submission = await submitUninstallWorkerDeploymentMutation(intent, state.call); }
      catch (error) {
        submission = await inspectDeploymentTwice(intent, state.call);
        if (!submission) throw error;
      }
    }
    if (!submission) throw new DeployError(409, 'session_conflict', 'returning_retirement_deployment_missing');
    await submitAction(state, name, submission);
  }
  current = journalAction(state, name);
  if (current?.phase === 'submitted') {
    const submission = parsedRetirementDeployment(current.locator, intent);
    if (!submission) throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
    await verifyUninstallWorkerDeploymentSubmission(intent, submission, state.call);
    await verifyUninstallWorkerDeploymentIsActive(intent, submission, state.call);
    await verifyAction(state, name, submission);
  }
  current = journalAction(state, name);
  const submission = parsedRetirementDeployment(current?.locator, intent);
  if (current?.phase !== 'verified' || !submission) {
    throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
  }
  return Object.freeze({ intent, submission });
}

async function convergeNamespaceRetirement(
  state: ExecutionState,
  proofInput: ProveAdminStateNamespaceRetiredInput,
): Promise<AdminStateNamespaceRetirementProof> {
  const name = 'admin_state_namespace_retired' as const;
  const recordValue = Object.freeze({
    schemaVersion: 1,
    kind: 'returning_admin_state_namespace_retired',
    proofInputHash: await digest(proofInput),
  });
  await prepareAction(state, name, recordValue);
  await armAction(state, name);
  let current = journalAction(state, name);
  const matchesInput = (proof: AdminStateNamespaceRetirementProof): boolean =>
    proof.accountId === proofInput.namespace.accountId &&
    proof.workerName === proofInput.namespace.workerName && proof.workerId === proofInput.workerId &&
    proof.uninstallCycleId === proofInput.uninstallCycleId &&
    proof.namespaceId === proofInput.namespace.namespaceId &&
    proof.retirementVersionId === proofInput.retirementSubmission.versionId;
  if (current?.phase === 'verified') {
    const persisted = parseAdminStateNamespaceRetirementProof(current.locator);
    if (!persisted || !matchesInput(persisted)) {
      throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
    }
    return persisted;
  }
  if (current?.phase === 'send_armed') {
    const proof = parseAdminStateNamespaceRetirementProof(
      await proveAdminStateNamespaceRetired(proofInput, state.call),
    );
    if (!proof || !matchesInput(proof)) throw new DeployError(409, 'session_conflict');
    await submitAction(state, name, proof);
  }
  current = journalAction(state, name);
  if (current?.phase === 'submitted') {
    const persisted = parseAdminStateNamespaceRetirementProof(current.locator);
    const fresh = parseAdminStateNamespaceRetirementProof(
      await proveAdminStateNamespaceRetired(proofInput, state.call),
    );
    if (!persisted || !fresh || !matchesInput(persisted) || !matchesInput(fresh)) {
      throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
    }
    await verifyAction(state, name, persisted);
  }
  current = journalAction(state, name);
  const proof = parseAdminStateNamespaceRetirementProof(current?.locator);
  if (current?.phase !== 'verified' || !proof || !matchesInput(proof)) {
    throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
  }
  return proof;
}

async function exactRetiredWorkerPresent(
  state: ExecutionState,
  surface: ManagementLocator,
): Promise<void> {
  const value = await getResult(
    state.call,
    `/accounts/${state.authority.runtime.accountId}/workers/workers/${encodeURIComponent(surface.workerId)}`,
  );
  if (!record(value) || value.id !== surface.workerId || value.name !== state.authority.runtime.workerName ||
    !Array.isArray(value.tags) || value.tags[0] !== 'ankka-mcp-gateway') {
    throw new DeployError(409, 'session_conflict', 'returning_worker_replacement_detected');
  }
  const workers = await paginated(
    state.call,
    `/accounts/${state.authority.runtime.accountId}/workers/workers`,
    new URLSearchParams(),
  );
  const matches = workers.filter((item) => record(item) &&
    (item.id === surface.workerId || item.name === state.authority.runtime.workerName));
  if (matches.length !== 1 || !record(matches[0]) || matches[0].id !== surface.workerId ||
    matches[0].name !== state.authority.runtime.workerName) {
    throw new DeployError(409, 'session_conflict', 'returning_worker_replacement_detected');
  }
}

async function convergeWorkerDelete(
  state: ExecutionState,
  surface: ManagementLocator,
  proofInput: ProveAdminStateNamespaceRetiredInput,
): Promise<{ readonly intent: WorkerDeleteMutationIntent; readonly proof: WorkerDeletionRecoveryProof }> {
  const name = 'management_worker_delete' as const;
  let current = journalAction(state, name);
  let intent: WorkerDeleteMutationIntent | null = null;
  if (!current) {
    intent = await prepareWorkerDeleteMutation(proofInput, state.call);
    await prepareAction(state, name, Object.freeze({
      schemaVersion: 1,
      kind: 'returning_management_worker_delete',
      intent,
    }));
    current = journalAction(state, name);
  } else if (record(current.record) && current.record.schemaVersion === 1 &&
      current.record.kind === 'returning_management_worker_delete') {
    intent = await parseWorkerDeleteMutationIntent(current.record.intent);
  }
  if (!intent || intent.accountId !== proofInput.namespace.accountId ||
    intent.workerName !== proofInput.namespace.workerName || intent.workerId !== proofInput.workerId ||
    intent.uninstallCycleId !== proofInput.uninstallCycleId ||
    intent.namespaceId !== proofInput.namespace.namespaceId ||
    intent.retirementVersionId !== proofInput.retirementSubmission.versionId) {
    throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
  }
  const armedHere = await armAction(state, name);
  current = journalAction(state, name);
  if (current?.phase === 'verified') {
    const persisted = parseWorkerDeletionRecoveryProof(current.locator);
    if (!persisted || persisted.requestHash !== intent.requestHash) {
      throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
    }
    return Object.freeze({ intent, proof: persisted });
  }
  let proof: WorkerDeletionRecoveryProof | null = null;
  if (current?.phase === 'send_armed') {
    if (!armedHere) {
      try { proof = parseWorkerDeletionRecoveryProof(await recoverWorkerDeletionOutcome(intent, state.call)); }
      catch {
        await exactRetiredWorkerPresent(state, surface);
        try { await submitWorkerDeleteMutation(intent, proofInput, state.call); }
        catch { /* exact recovery below decides whether the resumed DELETE applied */ }
        proof = parseWorkerDeletionRecoveryProof(await recoverWorkerDeletionOutcome(intent, state.call));
      }
    }
    if (armedHere) {
      try { await submitWorkerDeleteMutation(intent, proofInput, state.call); }
      catch { /* exact two-read recovery below decides */ }
      proof = parseWorkerDeletionRecoveryProof(await recoverWorkerDeletionOutcome(intent, state.call));
    }
    if (!proof) throw new DeployError(409, 'session_conflict', 'returning_worker_delete_unknown');
    await submitAction(state, name, proof);
  }
  current = journalAction(state, name);
  if (current?.phase === 'submitted') {
    const persisted = parseWorkerDeletionRecoveryProof(current.locator);
    proof = parseWorkerDeletionRecoveryProof(await recoverWorkerDeletionOutcome(intent, state.call));
    if (!persisted || !proof || persisted.requestHash !== intent.requestHash ||
      proof.requestHash !== intent.requestHash) {
      throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
    }
    await verifyAction(state, name, persisted);
  }
  current = journalAction(state, name);
  const persisted = parseWorkerDeletionRecoveryProof(current?.locator);
  if (current?.phase !== 'verified' || !persisted || persisted.requestHash !== intent.requestHash) {
    throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
  }
  return Object.freeze({ intent, proof: persisted });
}

async function namespaceAbsenceSnapshot(
  state: ExecutionState,
  surface: ManagementLocator,
): Promise<readonly BoundaryObject[]> {
  const values = await paginated(
    state.call,
    `/accounts/${state.authority.runtime.accountId}/workers/durable_objects/namespaces`,
    new URLSearchParams(),
  );
  if (values.some((item) => record(item) && (item.id === surface.namespace.namespaceId ||
    (item.script === state.authority.runtime.workerName && item.class === 'AdminState')))) {
    throw new DeployError(409, 'session_conflict', 'returning_namespace_residue');
  }
  return values;
}

async function verifyNoResidue(
  state: ExecutionState,
  surface: ManagementLocator,
  worker: { readonly intent: WorkerDeleteMutationIntent; readonly proof: WorkerDeletionRecoveryProof },
  namespaceRetirement: AdminStateNamespaceRetirementProof,
): Promise<NoResidueEvidence> {
  const domainSpec = managementDeleteSpec(
    state.authority, surface, state.call, 'management_custom_domain_delete',
  );
  const applicationSpec = managementDeleteSpec(
    state.authority, surface, state.call, 'management_access_application_delete',
  );
  await proveAbsent(state.call, domainSpec.path, domainSpec.list);
  // Once the parent Access application is absent its policy collection is no
  // longer readable. The policy's own verified deletion journal entry remains
  // the durable evidence; parent absence prevents the policy from surviving.
  await proveAbsent(state.call, applicationSpec.path, applicationSpec.list);
  const deletion = parseWorkerDeletionRecoveryProof(
    await recoverWorkerDeletionOutcome(worker.intent, state.call),
  );
  if (!deletion || deletion.requestHash !== worker.proof.requestHash ||
    deletion.workerId !== worker.proof.workerId || deletion.namespaceId !== worker.proof.namespaceId) {
    throw new DeployError(409, 'session_conflict', 'returning_worker_residue');
  }
  const firstNamespaces = await namespaceAbsenceSnapshot(state, surface);
  const secondNamespaces = await namespaceAbsenceSnapshot(state, surface);
  if (!same(firstNamespaces, secondNamespaces)) {
    throw new DeployError(409, 'session_conflict', 'returning_namespace_residue');
  }
  const dns = await paginated(
    state.call,
    `/zones/${state.authority.runtime.zoneId}/dns_records`,
    new URLSearchParams({ 'name.exact': state.authority.runtime.managementHostname }),
  );
  if (dns.length !== 0) throw new DeployError(409, 'session_conflict', 'returning_dns_residue');
  const routesResult = await getResult(
    state.call,
    `/zones/${state.authority.runtime.zoneId}/workers/routes`,
  );
  const routes = v.safeParse(routeListSchema, routesResult);
  if (!routes.success) throw new DeployError(409, 'session_conflict', 'returning_route_residue');
  for (const route of routes.output) {
    if (!v.is(v.string(), route.pattern)) throw new DeployError(409, 'session_conflict', 'returning_route_residue');
    const pattern = route.pattern.replace(/^https?:\/\//u, '').split('/', 1).at(0);
    if (pattern === undefined) throw new DeployError(409, 'session_conflict', 'returning_route_residue');
    if (pattern === state.authority.runtime.managementHostname ||
      (pattern.startsWith('*.') && state.authority.runtime.managementHostname.endsWith(pattern.slice(1)))) {
      throw new DeployError(409, 'session_conflict', 'returning_route_residue');
    }
  }
  const semantic = Object.freeze({
    schemaVersion: 1,
    status: 'no_managed_residue',
    authorityHash: state.authority.authorityHash,
    workerDeletionHash: await digest(worker.proof),
    namespaceRetirementHash: await digest(namespaceRetirement),
    namespaceSnapshotHash: await digest(firstNamespaces),
    routeSnapshotHash: await digest(routes.output),
  });
  return Object.freeze({ ...semantic, evidenceHash: await digest(semantic) });
}

async function parseNoResidueEvidence<Input>(
  state: ExecutionState,
  value: Input,
): Promise<NoResidueEvidence | null> {
  const result = v.safeParse(noResidueEvidenceSchema, value);
  if (!result.success || result.output.authorityHash !== state.authority.authorityHash) return null;
  const { evidenceHash, ...semantic } = result.output;
  return evidenceHash === await digest(semantic) ? result.output : null;
}

async function convergeNoResidue(
  state: ExecutionState,
  surface: ManagementLocator,
  worker: { readonly intent: WorkerDeleteMutationIntent; readonly proof: WorkerDeletionRecoveryProof },
  namespaceRetirement: AdminStateNamespaceRetirementProof,
): Promise<NoResidueEvidence> {
  const name = 'no_managed_residue_verify' as const;
  let current = journalAction(state, name);
  if (current?.phase === 'verified') {
    const persisted = await parseNoResidueEvidence(state, current.locator);
    if (!persisted) throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
    return persisted;
  }
  await prepareAction(state, name, Object.freeze({
    schemaVersion: 1,
    kind: 'returning_no_managed_residue_verify',
    authorityHash: state.authority.authorityHash,
    installationId: state.authority.installationId,
    workerRequestHash: worker.intent.requestHash,
    namespaceId: surface.namespace.namespaceId,
  }));
  await armAction(state, name);
  current = journalAction(state, name);
  if (current?.phase === 'send_armed') {
    await submitAction(state, name, await verifyNoResidue(state, surface, worker, namespaceRetirement));
  }
  current = journalAction(state, name);
  if (current?.phase === 'submitted') {
    const persisted = await parseNoResidueEvidence(state, current.locator);
    if (!persisted) throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
    await verifyNoResidue(state, surface, worker, namespaceRetirement);
    await verifyAction(state, name, persisted);
  }
  current = journalAction(state, name);
  const persisted = await parseNoResidueEvidence(state, current?.locator);
  if (current?.phase !== 'verified' || !persisted) {
    throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
  }
  return persisted;
}

async function convergeFinal(
  state: ExecutionState,
  gatewayRemoval: GatewayRemovalEvidence,
  residue: NoResidueEvidence,
): Promise<FinalConvergenceEvidence> {
  const convergenceHash = await digest({
    schemaVersion: 1,
    authorityHash: state.authority.authorityHash,
    gatewayRemoval,
    residue,
  });
  const locator = Object.freeze({
    schemaVersion: 1,
    status: 'removed',
    installationId: state.authority.installationId,
    convergenceHash,
  });
  const name = 'final_convergence' as const;
  await prepareAction(state, name, Object.freeze({
    schemaVersion: 1,
    kind: 'returning_final_convergence',
    convergenceHash,
  }));
  await armAction(state, name);
  let current = journalAction(state, name);
  if (current?.phase === 'send_armed') await submitAction(state, name, locator);
  current = journalAction(state, name);
  if (current?.phase === 'submitted') await verifyAction(state, name, locator);
  current = journalAction(state, name);
  if (current?.phase !== 'verified' || !same(current.locator, locator)) {
    throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
  }
  return locator;
}

async function readJournalOrNull(
  input: ReturningUninstallExecutionInput | ReturningUninstallRecoveryExecutionInput,
): Promise<ReturningUninstallJournal | null> {
  try { return await input.journal.read(); }
  catch (error) {
    if (error instanceof DeployError && error.status === 404) return null;
    throw error;
  }
}

async function acquireJournal(
  input: ReturningUninstallExecutionInput,
  authority: ReturningUninstallImportedAuthority,
  existing: ReturningUninstallJournal | null,
): Promise<ReturningUninstallJournal> {
  let journal = existing;
  const now = Date.now();
  if (!Number.isSafeInteger(now) || now < input.approvedAt || now >= input.plan.expiresAt ||
    input.recoverUntil <= input.plan.expiresAt) {
    throw new DeployError(409, 'session_conflict', 'returning_recovery_expired');
  }
  if (!journal) {
    journal = await input.journal.initialize({
      now,
      plan: input.plan,
      authority,
      attemptId: input.attemptId,
      approvedAt: input.approvedAt,
      accountId: input.target.account.id,
      zoneId: input.target.zone.id,
      recoverUntil: input.recoverUntil,
    });
  } else if (!journal.approvalHistory.some((approval) => approval.attemptId === input.attemptId)) {
    journal = await input.journal.appendApproval({
      expectedRevision: journal.revision,
      attemptId: input.attemptId,
      approvedAt: input.approvedAt,
      now: Math.max(now, journal.updatedAt),
      plan: input.plan,
      authority,
    });
  }
  if (journal.authority.actionProofHash !== authority.actionProofHash ||
    journal.recoverUntil !== input.recoverUntil || !same(journal.plan, input.plan)) {
    throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
  }
  return input.journal.acquireLease({
    expectedRevision: journal.revision,
    attemptId: input.attemptId,
    now: Math.max(now, journal.updatedAt),
    expiresAt: Math.min(now + MAX_RETURNING_UNINSTALL_LEASE_MS, input.plan.expiresAt, input.recoverUntil),
  });
}

async function acquireRecoveryJournal(
  input: ReturningUninstallRecoveryExecutionInput,
  journal: ReturningUninstallJournal,
): Promise<ReturningUninstallJournal> {
  const now = Date.now();
  const gatewayRemoval = journal.actions.find((action) => action.name === 'customer_gateway_remove');
  if (!Number.isSafeInteger(now) || now < input.approvedAt || now >= input.plan.expiresAt ||
    input.recoverUntil !== journal.recoverUntil || now >= journal.recoverUntil ||
    input.plan.planId !== journal.plan.planId || input.plan.planHash !== journal.plan.planHash ||
    !same(input.plan.gateway, journal.plan.gateway) || gatewayRemoval?.phase !== 'verified') {
    throw new DeployError(409, 'session_conflict', 'returning_recovery_not_authorized');
  }
  let next = journal;
  if (!next.approvalHistory.some((approval) => approval.attemptId === input.attemptId)) {
    next = await input.journal.appendHostedRecoveryApproval({
      expectedRevision: next.revision,
      attemptId: input.attemptId,
      approvedAt: input.approvedAt,
      now: Math.max(now, next.updatedAt),
      plan: input.plan,
      actorEmail: input.target.actor.email,
      accountId: input.target.account.id,
      zoneId: input.target.zone.id,
    });
  }
  const approval = next.approvalHistory.find((candidate) => candidate.attemptId === input.attemptId);
  if (approval?.authorization !== 'hosted_recovery' || approval.actorEmail !== input.target.actor.email ||
    approval.accountId !== input.target.account.id || approval.zoneId !== input.target.zone.id ||
    !same(next.plan, input.plan)) {
    throw new DeployError(409, 'session_conflict', 'returning_journal_mismatch');
  }
  return input.journal.acquireLease({
    expectedRevision: next.revision,
    attemptId: input.attemptId,
    now: Math.max(now, next.updatedAt),
    expiresAt: Math.min(now + MAX_RETURNING_UNINSTALL_LEASE_MS, input.plan.expiresAt, input.recoverUntil),
  });
}

function persistedGatewayRemoval(state: ExecutionState): GatewayRemovalEvidence {
  const current = journalAction(state, 'customer_gateway_remove');
  const evidence = parseGatewayRemovalEvidence(current?.locator, state.authority.installationId);
  if (current?.phase !== 'verified' || !evidence) {
    throw new DeployError(409, 'session_conflict', 'returning_recovery_not_authorized');
  }
  return evidence;
}

async function convergeRemainingTeardown(
  state: ExecutionState,
  surface: ManagementLocator,
  gatewayRemoval: GatewayRemovalEvidence,
): Promise<FinalConvergenceEvidence> {
  await convergeManagementDelete(state, surface, 'management_custom_domain_delete');
  await convergeManagementDelete(state, surface, 'management_admin_policy_delete');
  await convergeManagementDelete(state, surface, 'management_access_application_delete');
  const cycleHash = await sha256Hex(`returning-uninstall:${state.journal.bindingHash}`);
  const uninstallCycleId = `uninstall-${cycleHash.slice(0, 24)}`;
  if (!journalAction(state, 'retirement_worker_version_create')) {
    const namespacePresence = await provePersistedAdminStateNamespacePresent({
      namespace: surface.namespace,
      workerId: surface.workerId,
      uninstallCycleId,
    }, state.call);
    if (namespacePresence.namespaceId !== surface.namespace.namespaceId) {
      throw new DeployError(409, 'session_conflict', 'returning_namespace_mismatch');
    }
  }
  const version = await convergeRetirementVersion(state, surface, uninstallCycleId);
  const deployment = await convergeRetirementDeployment(
    state,
    surface,
    uninstallCycleId,
    version.submission.versionId,
  );
  const proofInput: ProveAdminStateNamespaceRetiredInput = Object.freeze({
    namespace: surface.namespace,
    workerId: surface.workerId,
    uninstallCycleId,
    retirementRecovery: version.recovery,
    retirementSubmission: version.submission,
    retirementDeploymentIntent: deployment.intent,
    retirementDeploymentSubmission: deployment.submission,
  });
  const namespaceRetirement = await convergeNamespaceRetirement(state, proofInput);
  const worker = await convergeWorkerDelete(state, surface, proofInput);
  const residue = await convergeNoResidue(state, surface, worker, namespaceRetirement);
  return convergeFinal(state, gatewayRemoval, residue);
}

function returningResult(
  authority: ReturningUninstallImportedAuthority,
  final: FinalConvergenceEvidence | null,
): ReturningUninstallExecutionResult {
  if (!final) throw new DeployError(500, 'internal_error');
  const result = Object.freeze({
    status: 'removed' as const,
    installationId: authority.installationId,
    convergenceHash: final.convergenceHash,
  });
  assertSecretFree(result);
  return result;
}

function installedReleaseIdentity(
  authority: ReturningUninstallImportedAuthority,
): Readonly<ExactReleaseBundleIdentity> {
  return parseExactReleaseBundleIdentity({
    schemaVersion: 1,
    channel: authority.runtime.updateChannel,
    controlPlaneOrigin: authority.runtime.controlPlaneOrigin,
    release: authority.runtime.release,
    keyId: authority.runtime.updateKeyId,
    publicKey: authority.runtime.updatePublicKey,
    artifactSha256: authority.runtime.artifactSha256.slice('sha256:'.length),
  });
}

export async function loadInstalledReturningUninstallReleaseBundle(
  loadExactReleaseBundle: ReturningUninstallExecutionInput['loadExactReleaseBundle'],
  authority: ReturningUninstallImportedAuthority,
): Promise<VerifiedReleaseBundle> {
  const identity = installedReleaseIdentity(authority);
  const bundle = await loadExactReleaseBundle(identity);
  assertExactReleaseBundleIdentity(bundle, identity);
  return bundle;
}

export async function executeReviewedReturningUninstall(
  input: ReturningUninstallExecutionInput,
): Promise<ReturningUninstallExecutionResult> {
  if (input.target.account.id !== input.action.accountId || input.target.actor.email !== input.action.actorEmail ||
    input.action.installationId !== input.plan.gateway.installationId ||
    input.action.workerName !== input.plan.gateway.workerName || input.approvedAt < input.plan.createdAt ||
    input.approvedAt >= input.plan.expiresAt) throw new DeployError(409, 'session_conflict');
  const call: ProviderCall = Object.freeze({
    accessToken: input.accessToken,
    transport: (request: Request) => input.transport(request),
  });
  const action = relayInput(input);
  const existingJournal = await readJournalOrNull(input);
  // Once teardown has removed the management Custom Domain, the customer
  // action route cannot be opened again. A retry of the same one-time action
  // therefore reuses only the already-imported, secret-free receipt authority.
  const authority = existingJournal?.authority.actionId === input.action.actionId
    ? existingJournal.authority
    : await relayReturningUninstallAction(action);
  if (authority.runtime.zoneId !== input.target.zone.id || authority.actorEmail !== input.target.actor.email ||
    authority.runtime.zoneName !== input.target.zone.name || authority.runtime.accountId !== input.target.account.id) {
    throw new DeployError(409, 'session_conflict');
  }
  const releaseBundle = await loadInstalledReturningUninstallReleaseBundle(
    input.loadExactReleaseBundle,
    authority,
  );
  const state: ExecutionState = {
    input,
    releaseBundle,
    authority,
    action,
    call,
    journal: await acquireJournal(input, authority, existingJournal),
  };
  let final: FinalConvergenceEvidence | null = null;
  try {
    const surface = await convergeSurface(state);
    const gatewayRemoval = await convergeGatewayRemoval(state, surface);
    final = await convergeRemainingTeardown(state, surface, gatewayRemoval);
  } finally {
    if (state.journal.lease?.attemptId === input.attemptId) {
      state.journal = await input.journal.releaseLease({
        expectedRevision: state.journal.revision,
        attemptId: input.attemptId,
        now: operationNow(state),
      });
    }
  }
  return returningResult(authority, final);
}

export async function resumeReviewedReturningUninstall(
  input: ReturningUninstallRecoveryExecutionInput,
): Promise<ReturningUninstallExecutionResult> {
  const existing = await readJournalOrNull(input);
  if (!existing || input.approvedAt < input.plan.createdAt || input.approvedAt >= input.plan.expiresAt) {
    throw new DeployError(409, 'session_conflict', 'returning_recovery_not_authorized');
  }
  const authority = existing.authority;
  if (authority.actorEmail !== input.target.actor.email ||
    authority.runtime.accountId !== input.target.account.id || authority.runtime.zoneId !== input.target.zone.id ||
    authority.runtime.zoneName !== input.target.zone.name || authority.installationId !== input.plan.gateway.installationId) {
    throw new DeployError(409, 'session_conflict');
  }
  const releaseBundle = await loadInstalledReturningUninstallReleaseBundle(
    input.loadExactReleaseBundle,
    authority,
  );
  const call: ProviderCall = Object.freeze({
    accessToken: input.accessToken,
    transport: (request: Request) => input.transport(request),
  });
  const state: ExecutionState = {
    input,
    releaseBundle,
    authority,
    action: null,
    call,
    journal: await acquireRecoveryJournal(input, existing),
  };
  let final: FinalConvergenceEvidence | null = null;
  try {
    const surface = await convergeSurface(state);
    final = await convergeRemainingTeardown(state, surface, persistedGatewayRemoval(state));
  } finally {
    if (state.journal.lease?.attemptId === input.attemptId) {
      state.journal = await input.journal.releaseLease({
        expectedRevision: state.journal.revision,
        attemptId: input.attemptId,
        now: operationNow(state),
      });
    }
  }
  return returningResult(authority, final);
}

export class ReviewedReturningUninstallExecutor implements ReturningUninstallExecutor {
  execute(input: ReturningUninstallExecutionInput): Promise<ReturningUninstallExecutionResult> {
    return executeReviewedReturningUninstall(input);
  }

  resume(input: ReturningUninstallRecoveryExecutionInput): Promise<ReturningUninstallExecutionResult> {
    return resumeReviewedReturningUninstall(input);
  }
}
