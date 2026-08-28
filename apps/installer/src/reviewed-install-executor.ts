import { deriveBootstrapNonce } from './bootstrap-nonce';
import type {
  CustomerGatewayFreshPreflightAttestation,
} from './cloudflare-gateway-fresh-preflight';
import { preflightFreshCustomerGateway } from './cloudflare-gateway-fresh-preflight';
import type {
  AccessIdentityProvider,
  AccountWorkersSubdomain,
  ManagementAccessApplicationIntent,
  ManagementAccessApplicationLocator,
  ManagementAdminPolicyIntent,
  ManagementAdminPolicyLocator,
  ManagementCustomDomainIntent,
  ManagementCustomDomainLocator,
  WorkerSubdomainState,
  ZeroTrustOrganization,
} from './cloudflare-management-surface';
import {
  attachManagementCustomDomain,
  createManagementAccessApplication,
  createManagementAdminAllowPolicy,
  getAccountWorkersSubdomain,
  getZeroTrustOrganization,
  listAccessIdentityProviders,
  prepareManagementAccessApplicationIntent,
  prepareManagementAdminPolicyIntent,
  prepareManagementCustomDomainIntent,
  preflightFreshManagementAccessApplication,
  preflightFreshManagementCustomDomain,
  recoverManagementAccessApplication,
  recoverManagementAdminAllowPolicy,
  recoverManagementCustomDomain,
  setWorkerBootstrapSubdomain,
  verifyManagementAccessApplicationGet,
  verifyManagementAccessApplicationList,
  verifyManagementAdminAllowPolicyGet,
  verifyManagementAdminAllowPolicyList,
  verifyManagementCustomDomainGet,
  verifyManagementCustomDomainList,
  verifyWorkerBootstrapSubdomain,
} from './cloudflare-management-surface';
import type { AuthorizedTarget } from './cloudflare-target';
import {
  CloudflareDirectUploadError,
  inspectWorkerDeploymentRecovery,
  inspectAdminStateDurableObjectNamespace,
  inspectWorkerRecovery,
  inspectWorkerVersionRecovery,
  parseWorkerVersionRecoveryRecord,
  prepareAssetBucketMutation,
  prepareAssetUploadSessionMutation,
  prepareVerifiedWorkerRelease,
  prepareWorkerDeploymentMutation,
  prepareWorkerMutationForTarget,
  prepareWorkerVersionMutation,
  prepareWorkerVersionRecoveryRecord,
  proveActiveWorkerVersionRecovery,
  submitAssetBucketMutation,
  submitAssetUploadSessionMutation,
  submitWorkerDeploymentMutation,
  submitWorkerMutation,
  submitWorkerVersionMutation,
  verifyActiveWorkerDeployment,
  verifyWorkerDeploymentSubmission,
  verifyWorkerSubmission,
  type ConvergedWorkerExpectation,
  verifyWorkerVersionSubmission,
  type ActiveWorkerVersionProof,
  type DeploymentSubmission,
  type AdminStateDurableObjectNamespaceLocator,
  type InspectAdminStateDurableObjectNamespaceInput,
  type GatewayWorkerPlainTextBindings,
  type PreparedVerifiedWorkerRelease,
  type VerifiedWorkerDirectUploadRelease,
  type VersionSubmission,
  type WorkerDeploymentMutationIntent,
  type WorkerMutationIntent,
  type WorkerSubmission,
  type WorkerVersionMutationPlan,
  type WorkerVersionPhase,
  type WorkerVersionRecoveryRecord,
} from './cloudflare-worker-direct-upload';
import {
  canonicalCustomerBootstrapJson,
  deriveCustomerGatewayExpectedProjection,
  prepareCustomerBootstrapClaim,
  prepareCustomerGatewayDesiredProjection,
  customerBootstrapUrl,
  submitCustomerBootstrap,
  type CustomerBootstrapResult,
  type CustomerGatewayDesiredProjection,
  type PreparedCustomerBootstrapClaim,
} from './customer-bootstrap-request';
import { base64UrlDecode, sha256Hex } from './crypto';
import { DeployError } from './errors';
import type { InstallJournalPort } from './install-journal-port';
import {
  MAX_INSTALL_LEASE_MS,
  activeInstallJournalPlan,
  computeInstallJournalBindingHash,
  isRecoveryEquivalentInstallPlan,
  prepareFinalConvergenceRecordAndLocator,
  type BootstrapSubdomainRecord,
  type CustomerBootstrapLocator,
  type CustomerBootstrapRequestAttempt,
  type CustomerBootstrapSubmitRecord,
  type InstallActionLocator,
  type InstallActionName,
  type InstallJournal,
  type InstallJournalAction,
  type InstallReleasePin,
  type ManagementAccessApplicationCreateRecord,
  type ManagementAdminPolicyCreateRecord,
  type ManagementCustomDomainAttachRecord,
  type WorkerCreateRecord,
  type WorkerDeploymentCreateRecord,
  type WorkerVersionCreateRecord,
  type WorkerVersionLocator,
} from './install-journal';
import { adaptVerifiedReleaseBundleForWorkerDirectUpload } from './release-direct-upload-adapter';
import type { VerifiedRelease, VerifiedReleaseBundle } from './release';
import {
  parseDeploySelection,
  parseStaticDeployPlan,
  type DeploySelection,
  type StaticDeployPlan,
} from './schema';

const ATTEMPT_ID = /^att_[A-Za-z0-9_-]{32}$/u;
const ACCESS_TOKEN = /^[A-Za-z0-9._~-]{20,8192}$/u;
const SESSION_ID = /^[A-Za-z0-9_-]{43}$/u;
const BASE64_KEY = /^(?:[A-Za-z0-9_-]{43}|[A-Za-z0-9+/]{43}=)$/u;
const PROVIDER_ID = /^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$/u;
const NAMESPACE_ID = /^[a-f0-9]{32}$/u;
const MAX_BOOTSTRAP_CYCLES = 8;
// The customer Worker converges the portal resources and, for legacy plans,
// the initial source resources within this single request; a shorter deadline
// turns a healthy install into an unknown outcome.
const BOOTSTRAP_SUBMIT_TIMEOUT_MS = 90_000;
const BOOTSTRAP_READY_ATTEMPTS = 40;
const BOOTSTRAP_READY_INTERVAL_MS = 1_500;
const MAX_IDENTITY_PROVIDERS = 64;

export type ReviewedInstallFailureCode =
  | 'bootstrap_recovery_required'
  | 'fresh_preflight_expired'
  | 'journal_recovery_mismatch'
  | 'provider_recovery_missing'
  | 'reviewed_adapter_invalid';

/** Stable, value-free failure information for the unreferenced reviewed path. */
export class ReviewedInstallExecutionError extends Error {
  readonly canRetry = false;

  constructor(readonly code: ReviewedInstallFailureCode) {
    super(code);
    this.name = 'ReviewedInstallExecutionError';
  }
}

export type ReviewedInstallTransport = (request: Request) => Promise<Response>;

export interface ReviewedInstallProviderCall {
  /** The adapter must use and discard this value within the awaited call. */
  readonly accessToken: string;
  readonly transport: ReviewedInstallTransport;
  readonly timeoutMs?: number;
}

export interface ReviewedInstallProviderAdapter {
  getZeroTrustOrganization(
    input: ReviewedInstallProviderCall & { readonly accountId: string },
  ): Promise<ZeroTrustOrganization>;
  listAccessIdentityProviders(
    input: ReviewedInstallProviderCall & { readonly accountId: string },
  ): Promise<readonly AccessIdentityProvider[]>;
  getAccountWorkersSubdomain(
    input: ReviewedInstallProviderCall & { readonly accountId: string },
  ): Promise<AccountWorkersSubdomain>;
  preflightFreshManagementApplication(
    input: ReviewedInstallProviderCall & { readonly accountId: string; readonly plan: StaticDeployPlan },
  ): Promise<void>;
  preflightFreshManagementDomain(
    input: ReviewedInstallProviderCall & {
      readonly accountId: string;
      readonly zoneId: string;
      readonly plan: StaticDeployPlan;
    },
  ): Promise<void>;
  preflightFreshCustomerGateway(
    input: ReviewedInstallProviderCall & {
      readonly selection: DeploySelection;
      readonly target: AuthorizedTarget;
      readonly release: VerifiedRelease;
      readonly plan: StaticDeployPlan;
      readonly nowMs: number;
    },
  ): Promise<CustomerGatewayFreshPreflightAttestation>;

  inspectWorker(
    intent: WorkerMutationIntent,
    call: ReviewedInstallProviderCall,
  ): Promise<WorkerSubmission | null>;
  submitWorker(intent: WorkerMutationIntent, call: ReviewedInstallProviderCall): Promise<WorkerSubmission>;
  verifyWorker(
    intent: WorkerMutationIntent,
    locator: WorkerSubmission,
    call: ReviewedInstallProviderCall,
    /** Present only for the terminal re-proof of a deployed, domain-attached Worker. */
    converged?: ConvergedWorkerExpectation,
  ): Promise<WorkerSubmission>;

  submitManagementApplication(
    intent: ManagementAccessApplicationIntent,
    input: ReviewedInstallProviderCall & {
      readonly accountId: string;
      readonly plan: StaticDeployPlan;
      readonly allowedIdentityProviderIds: readonly string[];
    },
  ): Promise<ManagementAccessApplicationLocator>;
  recoverManagementApplication(
    intent: ManagementAccessApplicationIntent,
    input: ReviewedInstallProviderCall & {
      readonly accountId: string;
      readonly plan: StaticDeployPlan;
      readonly allowedIdentityProviderIds: readonly string[];
    },
  ): Promise<ManagementAccessApplicationLocator>;
  verifyManagementApplication(
    locator: ManagementAccessApplicationLocator,
    input: ReviewedInstallProviderCall & {
      readonly accountId: string;
      readonly plan: StaticDeployPlan;
      readonly allowedIdentityProviderIds: readonly string[];
    },
  ): Promise<ManagementAccessApplicationLocator>;

  submitManagementPolicy(
    intent: ManagementAdminPolicyIntent,
    input: ReviewedInstallProviderCall & {
      readonly accountId: string;
      readonly applicationId: string;
      readonly plan: StaticDeployPlan;
    },
  ): Promise<ManagementAdminPolicyLocator>;
  recoverManagementPolicy(
    intent: ManagementAdminPolicyIntent,
    input: ReviewedInstallProviderCall & {
      readonly accountId: string;
      readonly applicationId: string;
      readonly plan: StaticDeployPlan;
    },
  ): Promise<ManagementAdminPolicyLocator>;
  verifyManagementPolicy(
    locator: ManagementAdminPolicyLocator,
    input: ReviewedInstallProviderCall & {
      readonly accountId: string;
      readonly applicationId: string;
      readonly plan: StaticDeployPlan;
    },
  ): Promise<ManagementAdminPolicyLocator>;

  /**
   * Pure, credential-free version commitment. This must perform no provider
   * I/O and is intentionally a prerequisite that the current direct-upload
   * primitive does not yet expose.
   */
  prepareWorkerVersionRecovery(
    prepared: PreparedVerifiedWorkerRelease,
    worker: WorkerSubmission,
    phase: WorkerVersionPhase,
  ): Promise<WorkerVersionRecoveryRecord>;
  /**
   * Called only after the exact semantic recovery record is durably prepared;
   * the Version POST itself is armed only after this staging call completes.
   */
  stageWorkerVersionSubmission(
    prepared: PreparedVerifiedWorkerRelease,
    worker: WorkerSubmission,
    expectedRecovery: WorkerVersionRecoveryRecord,
    phase: WorkerVersionPhase,
    call: ReviewedInstallProviderCall,
  ): Promise<WorkerVersionMutationPlan>;
  inspectWorkerVersion(
    recovery: WorkerVersionRecoveryRecord,
    call: ReviewedInstallProviderCall,
  ): Promise<VersionSubmission | null>;
  submitWorkerVersion(
    plan: WorkerVersionMutationPlan,
    call: ReviewedInstallProviderCall,
  ): Promise<VersionSubmission>;
  verifyWorkerVersion(
    recovery: WorkerVersionRecoveryRecord,
    locator: VersionSubmission,
    call: ReviewedInstallProviderCall,
    expectedNamespaceId?: string,
  ): Promise<VersionSubmission>;
  inspectAdminStateNamespace(
    input: InspectAdminStateDurableObjectNamespaceInput,
    call: ReviewedInstallProviderCall,
  ): Promise<AdminStateDurableObjectNamespaceLocator>;

  inspectWorkerDeployment(
    intent: WorkerDeploymentMutationIntent,
    call: ReviewedInstallProviderCall,
  ): Promise<DeploymentSubmission | null>;
  submitWorkerDeployment(
    intent: WorkerDeploymentMutationIntent,
    call: ReviewedInstallProviderCall,
  ): Promise<DeploymentSubmission>;
  verifyWorkerDeployment(
    intent: WorkerDeploymentMutationIntent,
    locator: DeploymentSubmission,
    call: ReviewedInstallProviderCall,
  ): Promise<DeploymentSubmission>;
  /**
   * Discover and prove the exact actively serving bootstrap or clean version
   * from its signed-release recovery commitment. The provider primitive reads
   * active deployment, exact module bytes and bindings, then active deployment
   * again to close the read-back race as far as the Cloudflare API permits.
   */
  proveActiveWorkerVersion(
    recovery: WorkerVersionRecoveryRecord,
    call: ReviewedInstallProviderCall,
    expectedNamespaceId: string,
  ): Promise<ActiveWorkerVersionProof>;
  /**
   * Prove the persisted bootstrap or clean deployment is still item zero in
   * Cloudflare's current-deployments list, with exactly its one version serving
   * at 100%.
   */
  verifyActiveWorkerDeployment(
    intent: WorkerDeploymentMutationIntent,
    locator: DeploymentSubmission,
    call: ReviewedInstallProviderCall,
  ): Promise<DeploymentSubmission>;

  setWorkerSubdomain(
    enabled: boolean,
    input: ReviewedInstallProviderCall & { readonly accountId: string; readonly plan: StaticDeployPlan },
  ): Promise<WorkerSubdomainState>;
  verifyWorkerSubdomain(
    expectedEnabled: boolean,
    input: ReviewedInstallProviderCall & { readonly accountId: string; readonly plan: StaticDeployPlan },
  ): Promise<WorkerSubdomainState>;
  /**
   * Waits until the customer Worker's bootstrap route actually answers at the
   * edge. Enabling the workers.dev subdomain is verified through the API well
   * before the route serves (live 2026-08-23), and an unsigned probe is the
   * only safe way to observe it: the request is a GET the Worker answers with
   * its fixed method-not-allowed envelope.
   */
  awaitCustomerBootstrapReady(
    input: ReviewedInstallProviderCall & {
      readonly accountWorkersSubdomain: AccountWorkersSubdomain;
      readonly plan: StaticDeployPlan;
      readonly accountId: string;
    },
  ): Promise<void>;
  submitCustomerBootstrap(
    input: ReviewedInstallProviderCall & {
      readonly selection: DeploySelection;
      readonly target: AuthorizedTarget;
      readonly release: VerifiedRelease;
      readonly plan: StaticDeployPlan;
      readonly accountWorkersSubdomain: AccountWorkersSubdomain;
      readonly bootstrapNonce: string;
      readonly claim: PreparedCustomerBootstrapClaim;
    },
  ): Promise<CustomerBootstrapResult>;

  submitManagementDomain(
    intent: ManagementCustomDomainIntent,
    input: ReviewedInstallProviderCall & {
      readonly accountId: string;
      readonly zoneId: string;
      readonly plan: StaticDeployPlan;
    },
  ): Promise<ManagementCustomDomainLocator>;
  recoverManagementDomain(
    intent: ManagementCustomDomainIntent,
    input: ReviewedInstallProviderCall & {
      readonly accountId: string;
      readonly zoneId: string;
      readonly plan: StaticDeployPlan;
    },
  ): Promise<ManagementCustomDomainLocator>;
  verifyManagementDomain(
    locator: ManagementCustomDomainLocator,
    input: ReviewedInstallProviderCall & {
      readonly accountId: string;
      readonly zoneId: string;
      readonly plan: StaticDeployPlan;
    },
  ): Promise<ManagementCustomDomainLocator>;
}

/**
 * Stateless adapter over the reviewed provider primitives. The returned object
 * captures no grant; every credential is supplied to exactly one awaited call.
 */
export function createCloudflareReviewedInstallProviderAdapter(): ReviewedInstallProviderAdapter {
  const adapter: ReviewedInstallProviderAdapter = {
    getZeroTrustOrganization,
    listAccessIdentityProviders,
    getAccountWorkersSubdomain,
    preflightFreshManagementApplication: async (input) => {
      await preflightFreshManagementAccessApplication(input);
    },
    preflightFreshManagementDomain: async (input) => {
      await preflightFreshManagementCustomDomain(input);
    },
    preflightFreshCustomerGateway,
    inspectWorker: inspectWorkerRecovery,
    submitWorker: submitWorkerMutation,
    verifyWorker: verifyWorkerSubmission,
    submitManagementApplication: (intent, input) => createManagementAccessApplication({ ...input, intent }),
    recoverManagementApplication: async (intent, input) => {
      return (await recoverManagementAccessApplication({ ...input, intent })).locator;
    },
    verifyManagementApplication: async (locator, input) => {
      await verifyManagementAccessApplicationGet({ ...input, ...locator });
      return verifyManagementAccessApplicationList({ ...input, ...locator });
    },
    submitManagementPolicy: (intent, input) => createManagementAdminAllowPolicy({ ...input, intent }),
    recoverManagementPolicy: async (intent, input) => {
      return (await recoverManagementAdminAllowPolicy({ ...input, intent })).locator;
    },
    verifyManagementPolicy: async (locator, input) => {
      await verifyManagementAdminAllowPolicyGet({ ...input, ...locator });
      return verifyManagementAdminAllowPolicyList({ ...input, ...locator });
    },
    prepareWorkerVersionRecovery: prepareWorkerVersionRecoveryRecord,
    stageWorkerVersionSubmission: async (prepared, worker, expectedRecovery, phase, call) => {
      // The provision version carries no ASSETS binding, so no asset staging.
      if (phase === 'provision') {
        const plan = await prepareWorkerVersionMutation(prepared, worker, null, phase);
        if (!exact(plan.recovery, expectedRecovery)) fail('reviewed_adapter_invalid');
        return plan;
      }
      const sessionIntent = await prepareAssetUploadSessionMutation(prepared);
      const session = await submitAssetUploadSessionMutation(sessionIntent, call);
      let completionJwt: string | null = session.buckets.length === 0 ? session.uploadJwt : null;
      for (let index = 0; index < session.buckets.length; index += 1) {
        const bucketIntent = await prepareAssetBucketMutation(session, index);
        const result = await submitAssetBucketMutation(bucketIntent, session, prepared, call);
        if ('completionJwt' in result) completionJwt = result.completionJwt;
      }
      if (!completionJwt) fail('reviewed_adapter_invalid');
      const plan = await prepareWorkerVersionMutation(prepared, worker, completionJwt, phase);
      if (!exact(plan.recovery, expectedRecovery)) fail('reviewed_adapter_invalid');
      return plan;
    },
    inspectWorkerVersion: inspectWorkerVersionRecovery,
    submitWorkerVersion: (plan, call) => submitWorkerVersionMutation(plan.ephemeral, plan.recovery, call),
    verifyWorkerVersion: verifyWorkerVersionSubmission,
    inspectAdminStateNamespace: inspectAdminStateDurableObjectNamespace,
    inspectWorkerDeployment: inspectWorkerDeploymentRecovery,
    submitWorkerDeployment: submitWorkerDeploymentMutation,
    verifyWorkerDeployment: verifyWorkerDeploymentSubmission,
    proveActiveWorkerVersion: proveActiveWorkerVersionRecovery,
    verifyActiveWorkerDeployment,
    setWorkerSubdomain: (enabled, input) => setWorkerBootstrapSubdomain({ ...input, enabled }),
    verifyWorkerSubdomain: (expectedEnabled, input) => verifyWorkerBootstrapSubdomain({
      ...input,
      expectedEnabled,
    }),
    awaitCustomerBootstrapReady: async (input) => {
      const url = customerBootstrapUrl({
        accountWorkersSubdomain: input.accountWorkersSubdomain,
        workerName: requireWorkerName(input.plan),
        accountId: input.accountId,
      });
      for (let attempt = 0; attempt < BOOTSTRAP_READY_ATTEMPTS; attempt += 1) {
        try {
          const response = await input.transport(new Request(url, {
            method: 'GET',
            headers: { accept: 'application/json' },
            redirect: 'manual',
            credentials: 'omit',
          }));
          const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
          await response.body?.cancel().catch(() => undefined);
          // The Worker itself answers this route; the edge 404 page does not.
          if (response.status === 405 && contentType === 'application/json') return;
        } catch { /* the bounded retry below is the only outcome that matters */ }
        await new Promise((resolve) => setTimeout(resolve, BOOTSTRAP_READY_INTERVAL_MS));
      }
      fail('provider_recovery_missing');
    },
    submitCustomerBootstrap: async (input) => {
      const requestIdBytes = base64UrlDecode(input.claim.requestId);
      try {
        return await submitCustomerBootstrap({
          selection: input.selection,
          target: input.target,
          release: input.release,
          plan: input.plan,
          nowMs: input.claim.issuedAt * 1_000,
          randomBytes: (length) => {
            if (length !== requestIdBytes.byteLength) fail('reviewed_adapter_invalid');
            return new Uint8Array(requestIdBytes);
          },
          cloudflareAccessToken: input.accessToken,
          accountWorkersSubdomain: input.accountWorkersSubdomain,
          bootstrapNonce: input.bootstrapNonce,
          transport: input.transport,
          timeoutMs: input.timeoutMs,
        });
      } finally {
        requestIdBytes.fill(0);
      }
    },
    submitManagementDomain: (intent, input) => attachManagementCustomDomain({ ...input, intent }),
    recoverManagementDomain: async (intent, input) => {
      return (await recoverManagementCustomDomain({ ...input, intent })).locator;
    },
    verifyManagementDomain: async (locator, input) => {
      await verifyManagementCustomDomainGet({ ...input, ...locator });
      return verifyManagementCustomDomainList({ ...input, ...locator });
    },
  };
  return Object.freeze(adapter);
}

export interface ReviewedInstallExecutionInput {
  readonly selection: DeploySelection;
  readonly plan: StaticDeployPlan;
  readonly target: AuthorizedTarget;
  readonly releaseBundle: VerifiedReleaseBundle;
  readonly accessToken: string;
  readonly sessionId: string;
  readonly bootstrapNonceDerivationKey: string;
  readonly attemptId: string;
  readonly recoverUntil: number;
  readonly journal: InstallJournalPort;
  readonly provider: ReviewedInstallProviderAdapter;
  readonly transport: ReviewedInstallTransport;
  readonly timeoutMs?: number;
  readonly now?: () => number;
  readonly randomBytes?: (length: number) => Uint8Array;
}

export interface ReviewedInstallExecutionResult {
  readonly installationId: string;
}

interface ExecutionContext {
  readonly input: ReviewedInstallExecutionInput;
  readonly selection: DeploySelection;
  readonly plan: StaticDeployPlan;
  readonly target: AuthorizedTarget;
  readonly release: VerifiedRelease;
  readonly directRelease: VerifiedWorkerDirectUploadRelease;
  readonly projection: CustomerGatewayDesiredProjection;
  readonly workerName: string;
  readonly call: ReviewedInstallProviderCall;
  journal: InstallJournal;
}

function fail(code: ReviewedInstallFailureCode): never {
  throw new ReviewedInstallExecutionError(code);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError('canonical_json_invalid');
}

function exact(left: unknown, right: unknown): boolean {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

function executionNow(context: Pick<ExecutionContext, 'input' | 'journal'>): number {
  const candidate = context.input.now ? context.input.now() : Date.now();
  if (!Number.isSafeInteger(candidate) || candidate < 0) fail('reviewed_adapter_invalid');
  return Math.max(candidate, context.journal.updatedAt);
}

function action(journal: InstallJournal, name: InstallActionName): InstallJournalAction | null {
  return journal.actions.find((entry) => entry.name === name) ?? null;
}

function requireAction(journal: InstallJournal, name: InstallActionName): InstallJournalAction {
  return action(journal, name) ?? fail('journal_recovery_mismatch');
}

function requireWorkerName(plan: StaticDeployPlan): string {
  const matches = plan.managementResources.filter((resource) => resource.kind === 'management_worker');
  if (matches.length !== 1) fail('journal_recovery_mismatch');
  return matches[0].name;
}

function requireIdentityProviderIds(providers: readonly AccessIdentityProvider[]): readonly string[] {
  const ids = providers.map((provider) => provider.id);
  const sorted = [...ids].sort();
  if (
    ids.length < 1 || ids.length > MAX_IDENTITY_PROVIDERS ||
    ids.some((id) => !PROVIDER_ID.test(id)) ||
    ids.some((id, index) => id !== sorted[index]) ||
    sorted.some((id, index) => index > 0 && id === sorted[index - 1])
  ) fail('reviewed_adapter_invalid');
  return Object.freeze(sorted);
}

function releasePin(bundle: VerifiedReleaseBundle): InstallReleasePin {
  return Object.freeze({
    verification: 'ed25519',
    keyId: bundle.keyId,
    release: bundle.manifest.release,
    artifactSha256: bundle.manifest.artifact.treeSha256,
  });
}

function strippedRelease(bundle: VerifiedReleaseBundle): VerifiedRelease {
  return Object.freeze({
    verification: 'ed25519',
    keyId: bundle.keyId,
    manifest: bundle.manifest,
  });
}

function workerRecord(intent: WorkerMutationIntent): WorkerCreateRecord {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'worker_create',
    accountId: intent.accountId,
    workerName: intent.workerName,
    requestHash: intent.requestHash,
    correlationTag: intent.correlationTag,
  });
}

async function intentHash(intent: unknown): Promise<string> {
  return sha256Hex(canonicalJson(intent));
}

async function applicationRecord(
  intent: ManagementAccessApplicationIntent,
  identityProviderIds: readonly string[],
): Promise<ManagementAccessApplicationCreateRecord> {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'management_access_application_create',
    accountId: intent.accountId,
    planId: intent.planId,
    planHash: intent.planHash,
    ownershipMarker: intent.ownershipMarker,
    allowedIdentityProviderIds: Object.freeze([...identityProviderIds]),
    intentHash: await intentHash(intent),
  });
}

async function policyRecord(intent: ManagementAdminPolicyIntent): Promise<ManagementAdminPolicyCreateRecord> {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'management_admin_policy_create',
    accountId: intent.accountId,
    planId: intent.planId,
    planHash: intent.planHash,
    ownershipMarker: intent.ownershipMarker,
    applicationId: intent.applicationId,
    intentHash: await intentHash(intent),
  });
}

function versionRecord(recovery: WorkerVersionRecoveryRecord): WorkerVersionCreateRecord {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'worker_version_create',
    phase: recovery.phase,
    accountId: recovery.accountId,
    workerName: recovery.workerName,
    workerId: recovery.workerId,
    requestHash: recovery.requestHash,
    correlationTag: recovery.correlationTag,
    releaseContract: recovery.releaseContract,
    assets: recovery.assets,
    plainTextBindingHashes: recovery.plainTextBindingHashes,
    modules: recovery.modules,
  });
}

function recoveryFromVersionRecord(record: WorkerVersionCreateRecord): WorkerVersionRecoveryRecord {
  return {
    kind: 'version_recovery',
    phase: record.phase,
    accountId: record.accountId,
    workerName: record.workerName,
    workerId: record.workerId,
    requestHash: record.requestHash,
    correlationTag: record.correlationTag,
    releaseContract: record.releaseContract,
    assets: record.assets,
    plainTextBindingHashes: record.plainTextBindingHashes,
    modules: record.modules,
  };
}

function deploymentRecord(intent: WorkerDeploymentMutationIntent): WorkerDeploymentCreateRecord {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'worker_deployment_create',
    phase: intent.phase,
    accountId: intent.accountId,
    workerName: intent.workerName,
    workerId: intent.workerId,
    versionId: intent.versionId,
    requestHash: intent.requestHash,
    correlationTag: intent.correlationTag,
  });
}

async function subdomainRecord(
  accountId: string,
  workerName: string,
  enabled: boolean,
): Promise<BootstrapSubdomainRecord> {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'bootstrap_subdomain',
    accountId,
    workerName,
    enabled,
    requestHash: await sha256Hex(canonicalJson({ enabled, previews_enabled: false })),
  });
}

async function domainRecord(intent: ManagementCustomDomainIntent): Promise<ManagementCustomDomainAttachRecord> {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'management_custom_domain_attach',
    accountId: intent.accountId,
    zoneId: intent.zoneId,
    planId: intent.planId,
    planHash: intent.planHash,
    ownershipMarker: intent.ownershipMarker,
    intentHash: await intentHash(intent),
  });
}

function workerLocator(value: InstallActionLocator | null): WorkerSubmission {
  if (!value || !('kind' in value) || value.kind !== 'worker') fail('journal_recovery_mismatch');
  return value;
}

function versionLocator(value: InstallActionLocator | null): WorkerVersionLocator {
  if (!value || !('kind' in value) || value.kind !== 'version') fail('journal_recovery_mismatch');
  return value;
}

function namespaceProof(
  value: AdminStateDurableObjectNamespaceLocator,
  input: InspectAdminStateDurableObjectNamespaceInput,
): AdminStateDurableObjectNamespaceLocator {
  if (
    !isRecord(value) || !exact(Object.keys(value).sort(), [
      'accountId', 'className', 'namespaceId', 'namespaceName', 'storage', 'workerName',
    ]) || value.accountId !== input.accountId || value.workerName !== input.workerName ||
    value.className !== 'AdminState' || value.storage !== 'sqlite' ||
    !NAMESPACE_ID.test(value.namespaceId) ||
    (input.expectedNamespaceId !== undefined && value.namespaceId !== input.expectedNamespaceId) ||
    typeof value.namespaceName !== 'string' || value.namespaceName.length < 1 ||
    value.namespaceName.length > 256 || /[\u0000-\u001f\u007f]/u.test(value.namespaceName)
  ) fail('reviewed_adapter_invalid');
  return value;
}

function namespaceInspectionInput(
  context: ExecutionContext,
  phase: WorkerVersionPhase,
  expectedNamespaceId?: string,
): InspectAdminStateDurableObjectNamespaceInput {
  const bootstrap = action(context.journal, 'bootstrap_worker_version_create');
  const bootstrapNamespaceId = bootstrap?.locator && 'namespaceId' in bootstrap.locator
    ? bootstrap.locator.namespaceId
    : undefined;
  const expected = expectedNamespaceId ?? (phase === 'clean' ? bootstrapNamespaceId : undefined);
  return Object.freeze({
    accountId: context.target.account.id,
    workerName: context.workerName,
    className: 'AdminState' as const,
    storage: 'sqlite' as const,
    ...(expected === undefined ? {} : { expectedNamespaceId: expected }),
  });
}

function persistedVersionLocator(
  version: VersionSubmission,
  namespace: AdminStateDurableObjectNamespaceLocator,
): WorkerVersionLocator {
  return Object.freeze({ ...version, namespaceId: namespace.namespaceId });
}

function deploymentLocator(value: InstallActionLocator | null): DeploymentSubmission {
  if (!value || !('kind' in value) || value.kind !== 'deployment') fail('journal_recovery_mismatch');
  return value;
}

function applicationLocator(value: InstallActionLocator | null): ManagementAccessApplicationLocator {
  if (!value || !('applicationId' in value) || !('aud' in value)) fail('journal_recovery_mismatch');
  return value;
}

function policyLocator(value: InstallActionLocator | null): ManagementAdminPolicyLocator {
  if (!value || !('policyId' in value)) fail('journal_recovery_mismatch');
  return value;
}

function domainLocator(value: InstallActionLocator | null): ManagementCustomDomainLocator {
  if (!value || !('domainId' in value)) fail('journal_recovery_mismatch');
  return value;
}

function knownSubmission<T extends WorkerSubmission | VersionSubmission | DeploymentSubmission>(
  error: unknown,
  kind: T['kind'],
  predicate: (value: T) => boolean,
): T | null {
  if (!(error instanceof CloudflareDirectUploadError)) return null;
  const candidates = error.submissions.filter((submission) => submission.kind === kind) as T[];
  return candidates.length === 1 && predicate(candidates[0]) ? candidates[0] : null;
}

async function prepareAction(
  context: ExecutionContext,
  name: InstallActionName,
  record: unknown,
  preparedAt = executionNow(context),
): Promise<void> {
  context.journal = await context.input.journal.prepareAction({
    expectedRevision: context.journal.revision,
    attemptId: context.input.attemptId,
    now: preparedAt,
    action: name,
    record,
  });
}

async function armAction(context: ExecutionContext, name: InstallActionName): Promise<void> {
  context.journal = await context.input.journal.armAction({
    expectedRevision: context.journal.revision,
    attemptId: context.input.attemptId,
    now: executionNow(context),
    action: name,
  });
}

async function submittedAction(
  context: ExecutionContext,
  name: InstallActionName,
  locator: unknown,
): Promise<void> {
  context.journal = await context.input.journal.recordSubmitted({
    expectedRevision: context.journal.revision,
    attemptId: context.input.attemptId,
    now: executionNow(context),
    action: name,
    locator,
  });
}

async function verifiedAction(context: ExecutionContext, name: InstallActionName): Promise<void> {
  context.journal = await context.input.journal.verifyAction({
    expectedRevision: context.journal.revision,
    attemptId: context.input.attemptId,
    now: executionNow(context),
    action: name,
  });
}

async function convergeWorker(context: ExecutionContext, intent: WorkerMutationIntent): Promise<WorkerSubmission> {
  let current = action(context.journal, 'worker_create');
  if (!current) {
    await prepareAction(context, 'worker_create', workerRecord(intent));
    current = requireAction(context.journal, 'worker_create');
  }
  let armedHere = false;
  if (current.phase === 'prepared') {
    const preflight = requireAction(context.journal, 'gateway_fresh_preflight');
    if (
      preflight.record.kind !== 'customer_gateway_fresh_preflight' ||
      executionNow(context) >= preflight.record.expiresAt
    ) fail('fresh_preflight_expired');
    await armAction(context, 'worker_create');
    armedHere = true;
    current = requireAction(context.journal, 'worker_create');
  }
  if (current.phase === 'send_armed') {
    let locator: WorkerSubmission | null = null;
    if (armedHere) {
      try {
        locator = await context.input.provider.submitWorker(intent, context.call);
      } catch (error) {
        const known = knownSubmission<WorkerSubmission>(
          error,
          'worker',
          (candidate) => candidate.accountId === intent.accountId && candidate.workerName === intent.workerName,
        );
        if (!known) throw error;
        locator = known;
      }
    } else {
      locator = await context.input.provider.inspectWorker(intent, context.call);
      if (!locator) fail('provider_recovery_missing');
    }
    await submittedAction(context, 'worker_create', locator);
    current = requireAction(context.journal, 'worker_create');
  }
  if (current.phase === 'submitted') {
    const locator = workerLocator(current.locator);
    await context.input.provider.verifyWorker(intent, locator, context.call);
    await verifiedAction(context, 'worker_create');
    current = requireAction(context.journal, 'worker_create');
  }
  const locator = workerLocator(current.locator);
  await context.input.provider.verifyWorker(intent, locator, context.call);
  return locator;
}

async function convergeManagementApplication(
  context: ExecutionContext,
  identityProviderIds: readonly string[],
): Promise<ManagementAccessApplicationLocator> {
  let current = action(context.journal, 'management_access_application_create');
  const ids = current?.record.kind === 'management_access_application_create'
    ? current.record.allowedIdentityProviderIds
    : identityProviderIds;
  const intent = prepareManagementAccessApplicationIntent({
    accountId: context.target.account.id,
    plan: context.plan,
    allowedIdentityProviderIds: ids,
  });
  if (!current) {
    await prepareAction(context, 'management_access_application_create', await applicationRecord(intent, ids));
    current = requireAction(context.journal, 'management_access_application_create');
  }
  let armedHere = false;
  if (current.phase === 'prepared') {
    await armAction(context, 'management_access_application_create');
    current = requireAction(context.journal, 'management_access_application_create');
    armedHere = true;
  }
  const operationInput = {
    ...context.call,
    accountId: context.target.account.id,
    plan: context.plan,
    allowedIdentityProviderIds: ids,
  };
  if (current.phase === 'send_armed') {
    const locator = armedHere
      ? await context.input.provider.submitManagementApplication(intent, operationInput)
      : await context.input.provider.recoverManagementApplication(intent, operationInput);
    await submittedAction(context, 'management_access_application_create', locator);
    current = requireAction(context.journal, 'management_access_application_create');
  }
  if (current.phase === 'submitted') {
    const locator = applicationLocator(current.locator);
    await context.input.provider.verifyManagementApplication(locator, operationInput);
    await verifiedAction(context, 'management_access_application_create');
    current = requireAction(context.journal, 'management_access_application_create');
  }
  const locator = applicationLocator(current.locator);
  await context.input.provider.verifyManagementApplication(locator, operationInput);
  return locator;
}

async function convergeManagementPolicy(
  context: ExecutionContext,
  application: ManagementAccessApplicationLocator,
): Promise<ManagementAdminPolicyLocator> {
  const intent = prepareManagementAdminPolicyIntent({
    accountId: context.target.account.id,
    applicationId: application.applicationId,
    plan: context.plan,
  });
  let current = action(context.journal, 'management_admin_policy_create');
  if (!current) {
    await prepareAction(context, 'management_admin_policy_create', await policyRecord(intent));
    current = requireAction(context.journal, 'management_admin_policy_create');
  }
  let armedHere = false;
  if (current.phase === 'prepared') {
    await armAction(context, 'management_admin_policy_create');
    current = requireAction(context.journal, 'management_admin_policy_create');
    armedHere = true;
  }
  const operationInput = {
    ...context.call,
    accountId: context.target.account.id,
    applicationId: application.applicationId,
    plan: context.plan,
  };
  if (current.phase === 'send_armed') {
    const locator = armedHere
      ? await context.input.provider.submitManagementPolicy(intent, operationInput)
      : await context.input.provider.recoverManagementPolicy(intent, operationInput);
    await submittedAction(context, 'management_admin_policy_create', locator);
    current = requireAction(context.journal, 'management_admin_policy_create');
  }
  if (current.phase === 'submitted') {
    const locator = policyLocator(current.locator);
    await context.input.provider.verifyManagementPolicy(locator, operationInput);
    await verifiedAction(context, 'management_admin_policy_create');
    current = requireAction(context.journal, 'management_admin_policy_create');
  }
  const locator = policyLocator(current.locator);
  await context.input.provider.verifyManagementPolicy(locator, operationInput);
  return locator;
}

function workerPlainTextBindings(
  context: ExecutionContext,
  organization: ZeroTrustOrganization,
  application: ManagementAccessApplicationLocator,
  workersSubdomain: AccountWorkersSubdomain,
): GatewayWorkerPlainTextBindings {
  return Object.freeze({
    ADMIN_EMAILS: context.plan.managementAdminEmails.join(','),
    ANKKA_GATEWAY_RELEASE: context.journal.releasePin.release,
    ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${context.journal.releasePin.artifactSha256}`,
    ANKKA_UPDATE_CHANNEL: context.input.releaseBundle.channel,
    ANKKA_UPDATE_KEY_ID: context.journal.releasePin.keyId,
    ANKKA_UPDATE_PUBLIC_KEY: context.input.releaseBundle.publicKey,
    ANKKA_MANAGEMENT_HOSTNAME: context.selection.basics.managementHostname,
    ANKKA_WORKERS_SUBDOMAIN: workersSubdomain.subdomain,
    ANKKA_WORKER_NAME: context.workerName,
    CF_ACCESS_AUD: application.aud,
    CF_ACCESS_ISSUER: organization.issuer,
    CLOUDFLARE_ACCOUNT_ID: context.target.account.id,
    CLOUDFLARE_ZONE_ID: context.target.zone.id,
    CLOUDFLARE_ZONE_NAME: context.target.zone.name,
    ZERO_TRUST_READY: 'true',
  });
}

async function prepareDirectRelease(
  context: ExecutionContext,
  organization: ZeroTrustOrganization,
  application: ManagementAccessApplicationLocator,
  workersSubdomain: AccountWorkersSubdomain,
): Promise<PreparedVerifiedWorkerRelease> {
  const nonce = await deriveBootstrapNonce(context.input.bootstrapNonceDerivationKey, {
    sessionId: context.input.sessionId,
    journalBindingHash: context.journal.bindingHash,
    installationId: context.journal.installationId,
    releaseArtifactSha256: context.journal.releasePin.artifactSha256,
  });
  return prepareVerifiedWorkerRelease({
    accountId: context.target.account.id,
    workerName: context.workerName,
    release: context.directRelease,
    plainTextBindings: workerPlainTextBindings(context, organization, application, workersSubdomain),
    bootstrapNonce: nonce,
  });
}

function versionActionName(phase: WorkerVersionPhase): InstallActionName {
  if (phase === 'provision') return 'provision_worker_version_create';
  return phase === 'bootstrap' ? 'bootstrap_worker_version_create' : 'clean_worker_version_create';
}

async function convergeWorkerVersion(
  context: ExecutionContext,
  prepared: PreparedVerifiedWorkerRelease,
  worker: WorkerSubmission,
  phase: WorkerVersionPhase,
): Promise<WorkerVersionLocator> {
  const name = versionActionName(phase);
  let current = action(context.journal, name);
  const freshRecoveryInput = await context.input.provider.prepareWorkerVersionRecovery(prepared, worker, phase);
  const freshRecovery = await parseWorkerVersionRecoveryRecord(freshRecoveryInput);
  if (!freshRecovery || !exact(freshRecovery, freshRecoveryInput)) fail('reviewed_adapter_invalid');
  let recovery: WorkerVersionRecoveryRecord = freshRecovery;
  if (!current) {
    await prepareAction(context, name, versionRecord(recovery));
    current = requireAction(context.journal, name);
  } else {
    if (current.record.kind !== 'worker_version_create' || current.record.phase !== phase) {
      fail('journal_recovery_mismatch');
    }
    const parsed = await parseWorkerVersionRecoveryRecord(recoveryFromVersionRecord(current.record));
    if (!parsed) fail('journal_recovery_mismatch');
    if (!exact(parsed, freshRecovery)) fail('journal_recovery_mismatch');
    recovery = parsed;
  }
  let stagedPlan: WorkerVersionMutationPlan | null = null;
  let armedHere = false;
  if (current.phase === 'prepared') {
    // Asset-session and bucket writes are content-addressed staging, but still
    // provider mutations. The exact semantic version record is durable before
    // staging starts; the Version POST is not armed until staging completes.
    stagedPlan = await context.input.provider.stageWorkerVersionSubmission(
      prepared,
      worker,
      recovery,
      phase,
      context.call,
    );
    const stagedRecovery = await parseWorkerVersionRecoveryRecord(stagedPlan.recovery);
    if (!stagedRecovery || !exact(stagedRecovery, recovery)) fail('reviewed_adapter_invalid');
    await armAction(context, name);
    current = requireAction(context.journal, name);
    armedHere = true;
  }
  if (current.phase === 'send_armed') {
    let locator: VersionSubmission | null = null;
    if (armedHere) {
      if (!stagedPlan) fail('reviewed_adapter_invalid');
      try {
        locator = await context.input.provider.submitWorkerVersion(stagedPlan, context.call);
      } catch (error) {
        const known = knownSubmission<VersionSubmission>(
          error,
          'version',
          (candidate) => candidate.phase === phase && candidate.requestHash === recovery.requestHash,
        );
        if (!known) throw error;
        locator = known;
      }
    } else {
      const first = await context.input.provider.inspectWorkerVersion(recovery, context.call);
      const second = await context.input.provider.inspectWorkerVersion(recovery, context.call);
      if (!first || !second || !exact(first, second)) fail('provider_recovery_missing');
      locator = second;
    }
    // The Durable Object namespace exists only after a deployment has
    // reconciled the declarative exports; the provision version therefore has
    // no namespace to prove yet (live contract, 2026-08-23).
    if (phase === 'provision') {
      await submittedAction(context, name, Object.freeze({ ...locator }));
    } else {
      const inspectionInput = namespaceInspectionInput(context, phase);
      const namespace = namespaceProof(
        await context.input.provider.inspectAdminStateNamespace(inspectionInput, context.call),
        inspectionInput,
      );
      await submittedAction(context, name, persistedVersionLocator(locator, namespace));
    }
    current = requireAction(context.journal, name);
  }
  if (current.phase === 'submitted') {
    const locator = versionLocator(current.locator);
    await context.input.provider.verifyWorkerVersion(recovery, locator, context.call, locator.namespaceId);
    if (phase !== 'provision') {
      const inspectionInput = namespaceInspectionInput(context, phase, locator.namespaceId);
      namespaceProof(
        await context.input.provider.inspectAdminStateNamespace(inspectionInput, context.call),
        inspectionInput,
      );
    }
    await verifiedAction(context, name);
    current = requireAction(context.journal, name);
  }
  const locator = versionLocator(current.locator);
  await context.input.provider.verifyWorkerVersion(recovery, locator, context.call, locator.namespaceId);
  if (phase !== 'provision') {
    const inspectionInput = namespaceInspectionInput(context, phase, locator.namespaceId);
    namespaceProof(
      await context.input.provider.inspectAdminStateNamespace(inspectionInput, context.call),
      inspectionInput,
    );
  }
  return locator;
}

function deploymentActionName(phase: WorkerVersionPhase): InstallActionName {
  if (phase === 'provision') return 'provision_worker_deployment_create';
  return phase === 'bootstrap' ? 'bootstrap_worker_deployment_create' : 'clean_worker_deployment_create';
}

async function convergeWorkerDeployment(
  context: ExecutionContext,
  version: VersionSubmission,
): Promise<DeploymentSubmission> {
  const intent = await prepareWorkerDeploymentMutation(version);
  const name = deploymentActionName(version.phase);
  let current = action(context.journal, name);
  if (!current) {
    await prepareAction(context, name, deploymentRecord(intent));
    current = requireAction(context.journal, name);
  }
  let armedHere = false;
  if (current.phase === 'prepared') {
    await armAction(context, name);
    current = requireAction(context.journal, name);
    armedHere = true;
  }
  if (current.phase === 'send_armed') {
    let locator: DeploymentSubmission | null = null;
    if (armedHere) {
      try {
        locator = await context.input.provider.submitWorkerDeployment(intent, context.call);
      } catch (error) {
        const known = knownSubmission<DeploymentSubmission>(
          error,
          'deployment',
          (candidate) => candidate.phase === version.phase && candidate.requestHash === intent.requestHash,
        );
        if (!known) throw error;
        locator = known;
      }
    } else {
      locator = await context.input.provider.inspectWorkerDeployment(intent, context.call);
      if (!locator) fail('provider_recovery_missing');
    }
    await submittedAction(context, name, locator);
    current = requireAction(context.journal, name);
  }
  if (current.phase === 'submitted') {
    const locator = deploymentLocator(current.locator);
    await context.input.provider.verifyWorkerDeployment(intent, locator, context.call);
    await verifiedAction(context, name);
    current = requireAction(context.journal, name);
  }
  const locator = deploymentLocator(current.locator);
  await context.input.provider.verifyWorkerDeployment(intent, locator, context.call);
  return locator;
}

async function proveBootstrapVersionActive(context: ExecutionContext): Promise<void> {
  const versionAction = requireAction(context.journal, 'bootstrap_worker_version_create');
  if (versionAction.record.kind !== 'worker_version_create' || versionAction.record.phase !== 'bootstrap' ||
    versionAction.phase !== 'verified') fail('journal_recovery_mismatch');
  const recovery = await parseWorkerVersionRecoveryRecord(recoveryFromVersionRecord(versionAction.record));
  if (!recovery || recovery.phase !== 'bootstrap') fail('journal_recovery_mismatch');
  const persistedVersion = versionLocator(versionAction.locator);
  if (!persistedVersion.namespaceId) fail('journal_recovery_mismatch');
  const deploymentAction = requireAction(context.journal, 'bootstrap_worker_deployment_create');
  if (deploymentAction.record.kind !== 'worker_deployment_create' ||
    deploymentAction.record.phase !== 'bootstrap' || deploymentAction.phase !== 'verified') {
    fail('journal_recovery_mismatch');
  }
  const persistedDeployment = deploymentLocator(deploymentAction.locator);
  const { namespaceId: _namespaceId, ...expectedVersion } = persistedVersion;
  const proof = await context.input.provider.proveActiveWorkerVersion(
    recovery,
    context.call,
    persistedVersion.namespaceId,
  );
  if (!exact(proof.version, expectedVersion) || !exact(proof.deployment, persistedDeployment)) {
    fail('journal_recovery_mismatch');
  }
}

async function exactSubdomainState(
  context: ExecutionContext,
  desired: boolean,
): Promise<boolean> {
  const operationInput = {
    ...context.call,
    accountId: context.target.account.id,
    plan: context.plan,
  };
  try {
    await context.input.provider.verifyWorkerSubdomain(desired, operationInput);
    return desired;
  } catch (firstError) {
    try {
      await context.input.provider.verifyWorkerSubdomain(!desired, operationInput);
      return !desired;
    } catch {
      throw firstError;
    }
  }
}

function latestBootstrapAttempt(journal: InstallJournal): CustomerBootstrapRequestAttempt | null {
  const bootstrap = action(journal, 'customer_bootstrap_submit');
  if (!bootstrap || bootstrap.record.kind !== 'customer_bootstrap_submit') return null;
  return bootstrap.record.attempts[bootstrap.record.attempts.length - 1] ?? null;
}

function cycleMutation(
  journal: InstallJournal,
  enabled: boolean,
): { readonly phase: InstallJournalAction['phase']; readonly locator: InstallActionLocator | null } | null {
  const latest = latestBootstrapAttempt(journal);
  if (latest && latest.approvalAttemptId !== journal.approvalHistory[0]?.attemptId) {
    const nested = enabled ? latest.enable : latest.disable;
    return nested ? { phase: nested.phase, locator: nested.locator } : null;
  }
  const top = action(journal, enabled ? 'bootstrap_subdomain_enable' : 'bootstrap_subdomain_disable');
  return top ? { phase: top.phase, locator: top.locator } : null;
}

async function convergeSubdomainMutation(
  context: ExecutionContext,
  enabled: boolean,
  nested: boolean,
): Promise<void> {
  const name: InstallActionName = enabled ? 'bootstrap_subdomain_enable' : 'bootstrap_subdomain_disable';
  const record = await subdomainRecord(context.target.account.id, context.workerName, enabled);
  let state = nested ? cycleMutation(context.journal, enabled) : (() => {
    const top = action(context.journal, name);
    return top ? { phase: top.phase, locator: top.locator } : null;
  })();
  if (!state) {
    await prepareAction(context, name, record);
    state = nested ? cycleMutation(context.journal, enabled) : (() => {
      const top = action(context.journal, name);
      return top ? { phase: top.phase, locator: top.locator } : null;
    })();
  }
  if (!state) fail('journal_recovery_mismatch');
  let armedHere = false;
  if (state.phase === 'prepared') {
    await armAction(context, name);
    state = nested ? cycleMutation(context.journal, enabled) : (() => {
      const top = action(context.journal, name);
      return top ? { phase: top.phase, locator: top.locator } : null;
    })();
    armedHere = true;
  }
  if (!state) fail('journal_recovery_mismatch');
  const operationInput = {
    ...context.call,
    accountId: context.target.account.id,
    plan: context.plan,
  };
  if (state.phase === 'send_armed') {
    let locator: WorkerSubdomainState;
    if (armedHere) {
      locator = await context.input.provider.setWorkerSubdomain(enabled, operationInput);
    } else {
      const observed = await exactSubdomainState(context, enabled);
      locator = observed === enabled
        ? Object.freeze({ enabled, previewsEnabled: false })
        : await context.input.provider.setWorkerSubdomain(enabled, operationInput);
    }
    await submittedAction(context, name, locator);
    state = nested ? cycleMutation(context.journal, enabled) : (() => {
      const top = action(context.journal, name);
      return top ? { phase: top.phase, locator: top.locator } : null;
    })();
  }
  if (!state) fail('journal_recovery_mismatch');
  if (state.phase === 'submitted') {
    await context.input.provider.verifyWorkerSubdomain(enabled, operationInput);
    await verifiedAction(context, name);
  }
  await context.input.provider.verifyWorkerSubdomain(enabled, operationInput);
}

async function bootstrapClaimHash(
  record: Omit<CustomerBootstrapSubmitRecord, 'attempts'>,
  claim: PreparedCustomerBootstrapClaim,
): Promise<string> {
  return `sha256:${await sha256Hex(canonicalCustomerBootstrapJson({
    schemaVersion: 1,
    requestId: claim.requestId,
    issuedAt: claim.issuedAt,
    expiresAt: claim.expiresAt,
    accountId: record.accountId,
    zoneId: record.zoneId,
    zoneName: record.zoneName,
    accountWorkersSubdomain: record.accountWorkersSubdomain,
    installationId: record.installationId,
    configurationHash: record.configurationHash,
    desiredHash: record.desiredHash,
  }))}`;
}

async function freshClaim(
  context: ExecutionContext,
  workersSubdomain: AccountWorkersSubdomain,
): Promise<{ readonly claim: PreparedCustomerBootstrapClaim; readonly semantic: Omit<CustomerBootstrapSubmitRecord, 'attempts'> }> {
  const claim = await prepareCustomerBootstrapClaim({
    selection: context.selection,
    target: context.target,
    release: context.release,
    plan: context.plan,
    nowMs: executionNow(context),
    randomBytes: context.input.randomBytes,
  });
  const semantic = Object.freeze({
    schemaVersion: 1 as const,
    kind: 'customer_bootstrap_submit' as const,
    accountId: context.target.account.id,
    zoneId: context.target.zone.id,
    zoneName: context.target.zone.name,
    accountWorkersSubdomain: workersSubdomain.subdomain,
    installationId: claim.expected.installationId,
    configurationHash: claim.expected.configurationHash,
    desiredHash: claim.expected.desiredHash,
  });
  return Object.freeze({ claim, semantic });
}

async function firstBootstrapRecord(
  context: ExecutionContext,
  claim: PreparedCustomerBootstrapClaim,
  semantic: Omit<CustomerBootstrapSubmitRecord, 'attempts'>,
): Promise<{ readonly record: CustomerBootstrapSubmitRecord; readonly preparedAt: number }> {
  const topEnable = requireAction(context.journal, 'bootstrap_subdomain_enable');
  if (
    topEnable.phase !== 'verified' || topEnable.record.kind !== 'bootstrap_subdomain' ||
    !topEnable.locator || !('previewsEnabled' in topEnable.locator) || topEnable.locator.enabled !== true
  ) fail('journal_recovery_mismatch');
  const now = executionNow(context);
  const record = Object.freeze({
    ...semantic,
    attempts: Object.freeze([Object.freeze({
      schemaVersion: 1 as const,
      approvalAttemptId: context.input.attemptId,
      requestId: claim.requestId,
      issuedAt: claim.issuedAt,
      expiresAt: claim.expiresAt,
      claimHash: await bootstrapClaimHash(semantic, claim),
      enable: Object.freeze({
        schemaVersion: 1 as const,
        approvalAttemptId: context.input.attemptId,
        enabled: true,
        requestHash: topEnable.record.requestHash,
        phase: 'verified' as const,
        locator: topEnable.locator,
        preparedAt: topEnable.preparedAt,
        sendArmedAt: topEnable.sendArmedAt,
        submittedAt: topEnable.submittedAt,
        verifiedAt: topEnable.verifiedAt,
      }),
      disable: null,
      phase: 'prepared' as const,
      locator: null,
      preparedAt: now,
      sendArmedAt: null,
      submittedAt: null,
      verifiedAt: null,
    })]),
  });
  return Object.freeze({ record, preparedAt: now });
}

async function appendBootstrapCycle(
  context: ExecutionContext,
  workersSubdomain: AccountWorkersSubdomain,
): Promise<PreparedCustomerBootstrapClaim> {
  const { claim, semantic } = await freshClaim(context, workersSubdomain);
  const enable = await subdomainRecord(context.target.account.id, context.workerName, true);
  context.journal = await context.input.journal.appendCustomerBootstrapCycle({
    expectedRevision: context.journal.revision,
    attemptId: context.input.attemptId,
    now: executionNow(context),
    attempt: {
      requestId: claim.requestId,
      issuedAt: claim.issuedAt,
      expiresAt: claim.expiresAt,
      claimHash: await bootstrapClaimHash(semantic, claim),
      enableRequestHash: enable.requestHash,
    },
  });
  return claim;
}

function readyLocator(attempt: CustomerBootstrapRequestAttempt): CustomerBootstrapLocator | null {
  return attempt.locator?.status === 'ready' ? attempt.locator : null;
}

async function safetyDisableLatest(context: ExecutionContext): Promise<void> {
  let latest = latestBootstrapAttempt(context.journal);
  if (!latest) return;
  const first = requireAction(context.journal, 'customer_bootstrap_submit').record;
  if (first.kind !== 'customer_bootstrap_submit') fail('journal_recovery_mismatch');
  const nested = first.attempts.length > 1;
  // A newer approved lease may inherit an older cycle whose safe, idempotent
  // workers.dev enable was only partially journaled. Settle that exact nested
  // transition first; its original approval evidence remains on the enable.
  // No signed bootstrap request is reconstructed or replayed here.
  if (latest.enable.phase !== 'verified') {
    await convergeSubdomainMutation(context, true, nested);
    latest = latestBootstrapAttempt(context.journal);
    if (!latest || latest.enable.phase !== 'verified') fail('journal_recovery_mismatch');
  }
  if (latest.disable?.phase === 'verified') {
    await context.input.provider.verifyWorkerSubdomain(false, {
      ...context.call,
      accountId: context.target.account.id,
      plan: context.plan,
    });
    return;
  }
  await convergeSubdomainMutation(context, false, nested);
}

async function submitCurrentBootstrapAttempt(
  context: ExecutionContext,
  workersSubdomain: AccountWorkersSubdomain,
  claim: PreparedCustomerBootstrapClaim,
): Promise<void> {
  let latest = latestBootstrapAttempt(context.journal);
  if (!latest || latest.approvalAttemptId !== context.input.attemptId) fail('journal_recovery_mismatch');
  if (latest.phase === 'prepared') {
    await armAction(context, 'customer_bootstrap_submit');
    latest = latestBootstrapAttempt(context.journal);
  } else if (latest.phase === 'send_armed') {
    // The request may already have reached the customer Worker. Never replay it.
    await safetyDisableLatest(context);
    fail('provider_recovery_missing');
  }
  if (!latest || latest.phase !== 'send_armed') fail('journal_recovery_mismatch');

  const nonce = await deriveBootstrapNonce(context.input.bootstrapNonceDerivationKey, {
    sessionId: context.input.sessionId,
    journalBindingHash: context.journal.bindingHash,
    installationId: context.journal.installationId,
    releaseArtifactSha256: context.journal.releasePin.artifactSha256,
  });
  let result: CustomerBootstrapResult;
  try {
    result = await context.input.provider.submitCustomerBootstrap({
      ...context.call,
      timeoutMs: BOOTSTRAP_SUBMIT_TIMEOUT_MS,
      selection: context.selection,
      target: context.target,
      release: context.release,
      plan: context.plan,
      accountWorkersSubdomain: workersSubdomain,
      bootstrapNonce: nonce,
      claim,
    });
  } catch (error) {
    await safetyDisableLatest(context);
    throw error;
  }
  await submittedAction(context, 'customer_bootstrap_submit', result);
  await safetyDisableLatest(context);
  if (result.status !== 'ready') fail('bootstrap_recovery_required');
  await verifiedAction(context, 'customer_bootstrap_submit');
}

async function convergeCustomerBootstrap(
  context: ExecutionContext,
  workersSubdomain: AccountWorkersSubdomain,
): Promise<CustomerBootstrapLocator> {
  let bootstrap = action(context.journal, 'customer_bootstrap_submit');
  let claim: PreparedCustomerBootstrapClaim | null = null;

  if (!bootstrap) {
    await proveBootstrapVersionActive(context);
    await convergeSubdomainMutation(context, true, false);
    const prepared = await freshClaim(context, workersSubdomain);
    claim = prepared.claim;
    const initialRecord = await firstBootstrapRecord(context, prepared.claim, prepared.semantic);
    await prepareAction(
      context,
      'customer_bootstrap_submit',
      initialRecord.record,
      initialRecord.preparedAt,
    );
    bootstrap = requireAction(context.journal, 'customer_bootstrap_submit');
  }

  let latest = latestBootstrapAttempt(context.journal);
  if (!latest || bootstrap.record.kind !== 'customer_bootstrap_submit') fail('journal_recovery_mismatch');

  if (bootstrap.phase === 'verified') {
    await safetyDisableLatest(context);
    return readyLocator(latest) ?? fail('journal_recovery_mismatch');
  }

  if (latest.approvalAttemptId !== context.input.attemptId) {
    await safetyDisableLatest(context);
    if (
      latest.locator?.status === 'recovery_required' &&
      latest.locator.reason !== 'bootstrap_recovery_required'
    ) fail('bootstrap_recovery_required');
    if (latest.phase === 'verified') return readyLocator(latest) ?? fail('journal_recovery_mismatch');
    if (bootstrap.record.attempts.length >= MAX_BOOTSTRAP_CYCLES) fail('bootstrap_recovery_required');
    claim = await appendBootstrapCycle(context, workersSubdomain);
    await proveBootstrapVersionActive(context);
    await convergeSubdomainMutation(context, true, true);
    latest = latestBootstrapAttempt(context.journal);
  } else if (latest.locator?.status === 'recovery_required') {
    await safetyDisableLatest(context);
    // canRetry:false forbids replaying this signed request. A later approval may
    // append a new request only for the provider's recoverable receipt case.
    fail('bootstrap_recovery_required');
  }

  if (!latest || latest.approvalAttemptId !== context.input.attemptId) fail('journal_recovery_mismatch');
  if (latest.phase === 'submitted' && latest.locator?.status === 'ready') {
    await safetyDisableLatest(context);
    await verifiedAction(context, 'customer_bootstrap_submit');
  } else if (latest.phase === 'verified') {
    await safetyDisableLatest(context);
  } else {
    if (!claim) {
      // A prepared request is only valid in the same synchronous invocation in
      // which its random request ID was held in memory. A later entry cannot
      // reconstruct or replay it under the no-retry rule.
      await safetyDisableLatest(context);
      fail('provider_recovery_missing');
    }
    // Prove the route serves before the signed request is armed: an armed
    // request that never leaves is an unknown outcome that needs a fresh
    // approval, and the edge lags the verified subdomain setting.
    try {
      await context.input.provider.awaitCustomerBootstrapReady({
        ...context.call,
        accountWorkersSubdomain: workersSubdomain,
        plan: context.plan,
        accountId: context.target.account.id,
      });
      // The first strong proof ran before exposing workers.dev. Re-run the
      // deployment-read / module-read / deployment-read proof after the edge
      // reports ready and immediately before arming the one-shot grant-bearing
      // request. A drift here is compensated by closing workers.dev without
      // ever sending the token.
      await proveBootstrapVersionActive(context);
    } catch (error) {
      await safetyDisableLatest(context);
      throw error;
    }
    await submitCurrentBootstrapAttempt(context, workersSubdomain, claim);
  }
  bootstrap = requireAction(context.journal, 'customer_bootstrap_submit');
  latest = latestBootstrapAttempt(context.journal);
  if (bootstrap.phase !== 'verified' || !latest) fail('journal_recovery_mismatch');
  return readyLocator(latest) ?? fail('journal_recovery_mismatch');
}

async function convergeManagementDomain(context: ExecutionContext): Promise<ManagementCustomDomainLocator> {
  const intent = prepareManagementCustomDomainIntent({
    accountId: context.target.account.id,
    zoneId: context.target.zone.id,
    plan: context.plan,
  });
  let current = action(context.journal, 'management_custom_domain_attach');
  if (!current) {
    await prepareAction(context, 'management_custom_domain_attach', await domainRecord(intent));
    current = requireAction(context.journal, 'management_custom_domain_attach');
  }
  let armedHere = false;
  if (current.phase === 'prepared') {
    await armAction(context, 'management_custom_domain_attach');
    current = requireAction(context.journal, 'management_custom_domain_attach');
    armedHere = true;
  }
  const operationInput = {
    ...context.call,
    accountId: context.target.account.id,
    zoneId: context.target.zone.id,
    plan: context.plan,
  };
  if (current.phase === 'send_armed') {
    const locator = armedHere
      ? await context.input.provider.submitManagementDomain(intent, operationInput)
      : await context.input.provider.recoverManagementDomain(intent, operationInput);
    await submittedAction(context, 'management_custom_domain_attach', locator);
    current = requireAction(context.journal, 'management_custom_domain_attach');
  }
  if (current.phase === 'submitted') {
    const locator = domainLocator(current.locator);
    await context.input.provider.verifyManagementDomain(locator, operationInput);
    await verifiedAction(context, 'management_custom_domain_attach');
    current = requireAction(context.journal, 'management_custom_domain_attach');
  }
  const locator = domainLocator(current.locator);
  await context.input.provider.verifyManagementDomain(locator, operationInput);
  return locator;
}

async function proveCustomerReady(
  context: ExecutionContext,
  ready: CustomerBootstrapLocator,
  workersSubdomain: AccountWorkersSubdomain,
): Promise<void> {
  if (ready.status !== 'ready') fail('journal_recovery_mismatch');
  const projection = await deriveCustomerGatewayExpectedProjection({
    selection: context.selection,
    target: context.target,
    plan: context.plan,
    release: {
      id: context.journal.releasePin.release,
      artifactSha256: context.journal.releasePin.artifactSha256,
    },
  });
  const bootstrap = requireAction(context.journal, 'customer_bootstrap_submit');
  if (
    bootstrap.record.kind !== 'customer_bootstrap_submit' ||
    bootstrap.record.accountWorkersSubdomain !== workersSubdomain.subdomain ||
    workersSubdomain.accountId !== context.target.account.id ||
    ready.installationId !== projection.expected.installationId ||
    ready.configurationHash !== projection.expected.configurationHash ||
    ready.desiredHash !== projection.expected.desiredHash ||
    ready.release.id !== context.journal.releasePin.release ||
    ready.release.artifactSha256 !== `sha256:${context.journal.releasePin.artifactSha256}` ||
    ready.gateway.hostname !== context.selection.basics.portalHostname ||
    ready.gateway.mcpUrl !== `https://${context.selection.basics.portalHostname}/mcp` ||
    ready.receipt.resourceCount !== projection.resourceKinds.length
  ) fail('journal_recovery_mismatch');
}

async function convergeFinalAction(context: ExecutionContext): Promise<void> {
  // This action is a local durable convergence receipt, not a provider write.
  // Rebuild its exact deterministic record/locator after every full set of
  // live provider proofs so a crash at any journal transition can resume.
  const prepared = await prepareFinalConvergenceRecordAndLocator(context.journal);
  let current = action(context.journal, 'final_convergence');
  if (!current) {
    await prepareAction(context, 'final_convergence', prepared.record);
    current = requireAction(context.journal, 'final_convergence');
  }
  if (current.phase === 'prepared') {
    await armAction(context, 'final_convergence');
    current = requireAction(context.journal, 'final_convergence');
  }
  if (current.phase === 'send_armed') {
    await submittedAction(context, 'final_convergence', prepared.locator);
    current = requireAction(context.journal, 'final_convergence');
  }
  if (current.phase === 'submitted') {
    await verifiedAction(context, 'final_convergence');
    current = requireAction(context.journal, 'final_convergence');
  }
  if (current.phase !== 'verified') fail('journal_recovery_mismatch');
}

async function readJournalOrNull(port: InstallJournalPort): Promise<InstallJournal | null> {
  try {
    return await port.read();
  } catch (error) {
    if (error instanceof DeployError && error.status === 404) return null;
    throw error;
  }
}

function validateExecutionInput(input: ReviewedInstallExecutionInput): void {
  if (
    !ATTEMPT_ID.test(input.attemptId) || !ACCESS_TOKEN.test(input.accessToken) ||
    !SESSION_ID.test(input.sessionId) || !BASE64_KEY.test(input.bootstrapNonceDerivationKey) ||
    !Number.isSafeInteger(input.recoverUntil) || input.recoverUntil <= 0 ||
    typeof input.journal?.read !== 'function' || typeof input.provider?.inspectWorker !== 'function' ||
    typeof input.transport !== 'function'
  ) fail('reviewed_adapter_invalid');
}

async function initializeOrRecoverContext(
  input: ReviewedInstallExecutionInput,
): Promise<{ readonly base: Omit<ExecutionContext, 'journal'>; readonly identityProviders: readonly string[]; readonly organization: ZeroTrustOrganization; readonly workersSubdomain: AccountWorkersSubdomain; readonly journal: InstallJournal }> {
  validateExecutionInput(input);
  const selection = parseDeploySelection(input.selection);
  const plan = parseStaticDeployPlan(input.plan);
  const target = input.target;
  const release = strippedRelease(input.releaseBundle);
  const directRelease = await adaptVerifiedReleaseBundleForWorkerDirectUpload(input.releaseBundle);
  const validationNow = input.now ? input.now() : Date.now();
  const projection = await prepareCustomerGatewayDesiredProjection({
    selection,
    plan,
    target,
    release,
    nowMs: validationNow,
  });
  const workerName = requireWorkerName(plan);
  const call = Object.freeze({
    accessToken: input.accessToken,
    transport: input.transport,
    ...(input.timeoutMs === undefined ? {} : { timeoutMs: input.timeoutMs }),
  });
  const base = { input, selection, plan, target, release, directRelease, projection, workerName, call };
  let journal = await readJournalOrNull(input.journal);
  let organization: ZeroTrustOrganization;
  let workersSubdomain: AccountWorkersSubdomain;
  let identityProviders: readonly string[];

  if (!journal) {
    organization = await input.provider.getZeroTrustOrganization({ ...call, accountId: target.account.id });
    const idps = await input.provider.listAccessIdentityProviders({ ...call, accountId: target.account.id });
    identityProviders = requireIdentityProviderIds(idps);
    workersSubdomain = await input.provider.getAccountWorkersSubdomain({ ...call, accountId: target.account.id });
    const preflightNow = input.now ? input.now() : Date.now();
    const gatewayFreshPreflight = await input.provider.preflightFreshCustomerGateway({
      ...call,
      selection,
      target,
      release,
      plan,
      nowMs: preflightNow,
    });
    const workerIntent = await prepareWorkerMutationForTarget({ accountId: target.account.id, workerName });
    if (await input.provider.inspectWorker(workerIntent, call)) fail('journal_recovery_mismatch');
    await input.provider.preflightFreshManagementApplication({ ...call, accountId: target.account.id, plan });
    await input.provider.preflightFreshManagementDomain({
      ...call,
      accountId: target.account.id,
      zoneId: target.zone.id,
      plan,
    });
    const pin = releasePin(input.releaseBundle);
    const bindingHash = await computeInstallJournalBindingHash({
      selection,
      plan,
      releasePin: pin,
      target,
      installationId: projection.expected.installationId,
    });
    journal = await input.journal.initialize({
      schemaVersion: 1,
      now: preflightNow,
      recoverUntil: input.recoverUntil,
      selection,
      plan,
      releasePin: pin,
      target,
      installationId: projection.expected.installationId,
      bindingHash,
      gatewayFreshPreflight,
    });
  } else {
    if (
      !exact(journal.selection, selection) || !isRecoveryEquivalentInstallPlan(journal.plan, plan) ||
      !exact(journal.target, target) || journal.recoverUntil !== input.recoverUntil ||
      !exact(journal.releasePin, releasePin(input.releaseBundle)) ||
      journal.installationId !== projection.expected.installationId
    ) fail('journal_recovery_mismatch');
    const currentApproval = journal.approvalHistory.find((approval) => approval.attemptId === input.attemptId);
    if (!currentApproval) {
      journal = await input.journal.appendApproval({
        expectedRevision: journal.revision,
        attemptId: input.attemptId,
        now: Math.max(input.now ? input.now() : Date.now(), journal.updatedAt),
      });
    }
    organization = await input.provider.getZeroTrustOrganization({ ...call, accountId: target.account.id });
    const appAction = action(journal, 'management_access_application_create');
    if (appAction?.record.kind === 'management_access_application_create') {
      identityProviders = appAction.record.allowedIdentityProviderIds;
    } else {
      const idps = await input.provider.listAccessIdentityProviders({ ...call, accountId: target.account.id });
      identityProviders = requireIdentityProviderIds(idps);
    }
    workersSubdomain = await input.provider.getAccountWorkersSubdomain({ ...call, accountId: target.account.id });
  }
  const activePlan = activeInstallJournalPlan(journal);
  if (!exact(activePlan, plan)) fail('journal_recovery_mismatch');
  return {
    base: { ...base, plan: activePlan },
    identityProviders,
    organization,
    workersSubdomain,
    journal,
  };
}

/**
 * Execute the isolated reviewed install. This export is deliberately not
 * referenced by the Worker entrypoint; a caller must explicitly inject both a
 * journal port and a fully reviewed provider adapter.
 */
export async function executeReviewedInstall(
  input: ReviewedInstallExecutionInput,
): Promise<ReviewedInstallExecutionResult> {
  const initialized = await initializeOrRecoverContext(input);
  const context: ExecutionContext = { ...initialized.base, journal: initialized.journal };
  const now = executionNow(context);
  const leaseExpiresAt = Math.min(now + MAX_INSTALL_LEASE_MS, context.plan.expiresAt, context.journal.recoverUntil);
  if (leaseExpiresAt <= now) fail('journal_recovery_mismatch');
  context.journal = await input.journal.acquireLease({
    expectedRevision: context.journal.revision,
    attemptId: input.attemptId,
    now,
    leaseExpiresAt,
  });

  const workerIntent = await prepareWorkerMutationForTarget({
    accountId: context.target.account.id,
    workerName: context.workerName,
  });
  const worker = await convergeWorker(context, workerIntent);
  const application = await convergeManagementApplication(context, initialized.identityProviders);
  await convergeManagementPolicy(context, application);
  const prepared = await prepareDirectRelease(
    context,
    initialized.organization,
    application,
    initialized.workersSubdomain,
  );
  // A brand-new Worker cannot bind a Durable Object class that has never been
  // provisioned; the provision version (exports only, no ADMIN_STATE or ASSETS
  // binding) is deployed first so its reconciliation creates the namespace.
  const provisionVersion = await convergeWorkerVersion(context, prepared, worker, 'provision');
  await convergeWorkerDeployment(context, provisionVersion);
  const bootstrapVersion = await convergeWorkerVersion(context, prepared, worker, 'bootstrap');
  await convergeWorkerDeployment(context, bootstrapVersion);
  const ready = await convergeCustomerBootstrap(context, initialized.workersSubdomain);
  await proveCustomerReady(context, ready, initialized.workersSubdomain);
  const cleanVersion = await convergeWorkerVersion(context, prepared, worker, 'clean');
  await convergeWorkerDeployment(context, cleanVersion);
  await convergeManagementDomain(context);

  // Terminal provider re-proofs. No hash-only convergence is accepted.
  const attachedDomain = domainLocator(requireAction(context.journal, 'management_custom_domain_attach').locator);
  await context.input.provider.verifyWorker(workerIntent, worker, context.call, {
    domain: {
      id: attachedDomain.domainId,
      hostname: context.selection.basics.managementHostname,
      zoneId: context.target.zone.id,
      zoneName: context.target.zone.name,
    },
    namespaceId: cleanVersion.namespaceId as string,
  });
  const cleanAction = requireAction(context.journal, 'clean_worker_version_create');
  if (cleanAction.record.kind !== 'worker_version_create') fail('journal_recovery_mismatch');
  const cleanRecovery = await parseWorkerVersionRecoveryRecord(recoveryFromVersionRecord(cleanAction.record));
  if (!cleanRecovery) fail('journal_recovery_mismatch');
  await context.input.provider.verifyWorkerVersion(
    cleanRecovery,
    cleanVersion,
    context.call,
    cleanVersion.namespaceId,
  );
  const terminalNamespaceInput = namespaceInspectionInput(context, 'clean', cleanVersion.namespaceId);
  namespaceProof(
    await context.input.provider.inspectAdminStateNamespace(terminalNamespaceInput, context.call),
    terminalNamespaceInput,
  );
  const cleanDeploymentIntent = await prepareWorkerDeploymentMutation(cleanVersion);
  const cleanDeployment = deploymentLocator(
    requireAction(context.journal, 'clean_worker_deployment_create').locator,
  );
  await context.input.provider.verifyWorkerDeployment(
    cleanDeploymentIntent,
    cleanDeployment,
    context.call,
  );
  await context.input.provider.verifyActiveWorkerDeployment(
    cleanDeploymentIntent,
    cleanDeployment,
    context.call,
  );
  await context.input.provider.verifyWorkerSubdomain(false, {
    ...context.call,
    accountId: context.target.account.id,
    plan: context.plan,
  });
  await context.input.provider.verifyManagementApplication(application, {
    ...context.call,
    accountId: context.target.account.id,
    plan: context.plan,
    allowedIdentityProviderIds: initialized.identityProviders,
  });
  await context.input.provider.verifyManagementPolicy(
    policyLocator(requireAction(context.journal, 'management_admin_policy_create').locator),
    {
      ...context.call,
      accountId: context.target.account.id,
      applicationId: application.applicationId,
      plan: context.plan,
    },
  );
  await context.input.provider.verifyManagementDomain(
    domainLocator(requireAction(context.journal, 'management_custom_domain_attach').locator),
    {
      ...context.call,
      accountId: context.target.account.id,
      zoneId: context.target.zone.id,
      plan: context.plan,
    },
  );
  await proveCustomerReady(context, ready, initialized.workersSubdomain);
  await convergeFinalAction(context);
  context.journal = await input.journal.releaseLease({
    expectedRevision: context.journal.revision,
    attemptId: input.attemptId,
    now: executionNow(context),
  });
  return Object.freeze({ installationId: context.journal.installationId });
}
