import type { AuthorizedTarget } from './cloudflare-target';
import {
  parseWorkerVersionRecoveryRecord,
  type WorkerVersionRecoveryRecord,
} from './cloudflare-worker-direct-upload';
import {
  parseCustomerGatewayFreshPreflightAttestation,
  type CustomerGatewayFreshPreflightAttestation,
} from './cloudflare-gateway-fresh-preflight';
import {
  deriveCustomerGatewayExpectedProjection,
  deriveCustomerGatewayInstallationReceiptExpectation,
} from './customer-bootstrap-request';
import {
  parseReadyInstallationReceipt,
  type ReadyInstallationReceipt,
} from './provider-neutral-installation-receipt';
import {
  managementOwnershipMarker,
  prepareManagementAccessApplicationIntent,
  prepareManagementAdminPolicyIntent,
  prepareManagementCustomDomainIntent,
} from './cloudflare-management-surface';
import { sha256Hex } from './crypto';
import { DeployError } from './errors';
import {
  assertSecretFree,
  parseDeploySelection,
  parseStaticDeployPlan,
  type DeploySelection,
  type StaticDeployPlan,
} from './schema';

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const PROVIDER_ID = /^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$/u;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const RELEASE = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const KEY_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const PREFIXED_SHA256 = /^sha256:[a-f0-9]{64}$/u;
const ACCESS_AUD = /^[A-Za-z0-9._~-]{16,512}$/u;
const ATTEMPT_ID = /^att_[A-Za-z0-9_-]{32}$/u;
const REQUEST_ID = /^[A-Za-z0-9_-]{22}$/u;
const INSTALLATION_ID = /^acg-[a-f0-9]{24}$/u;
const CUSTOMER_PLAN_ID = /^plan-[a-f0-9]{24}$/u;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const SAFE_ACTOR_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$/u;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;
const MAX_IDENTITY_PROVIDERS = 64;
const MAX_LEASE_ATTEMPTS = 16;
const MAX_APPROVALS = 16;
const MAX_BOOTSTRAP_ATTEMPTS = 8;

export const MAX_INSTALL_RECOVERY_RETENTION_MS = 24 * 60 * 60 * 1_000;
export const MAX_INSTALL_LEASE_MS = 5 * 60 * 1_000;

export const INSTALL_ACTION_ORDER = Object.freeze([
  'gateway_fresh_preflight',
  'worker_create',
  'management_access_application_create',
  'management_admin_policy_create',
  'provision_worker_version_create',
  'provision_worker_deployment_create',
  'bootstrap_worker_version_create',
  'bootstrap_worker_deployment_create',
  'bootstrap_subdomain_enable',
  'customer_bootstrap_submit',
  'bootstrap_subdomain_disable',
  'clean_worker_version_create',
  'clean_worker_deployment_create',
  'management_custom_domain_attach',
  'final_convergence',
] as const);

export type InstallActionName = (typeof INSTALL_ACTION_ORDER)[number];
export type InstallActionPhase = 'prepared' | 'send_armed' | 'submitted' | 'verified';

export interface PublicInstallProgressAction {
  readonly name: InstallActionName;
  readonly phase: InstallActionPhase;
  readonly updatedAt: number;
}

export interface PublicInstallProgress {
  readonly schemaVersion: 1;
  readonly revision: number;
  readonly updatedAt: number;
  readonly actions: readonly PublicInstallProgressAction[];
}

export interface InstallReleasePin {
  readonly verification: 'ed25519';
  readonly keyId: string;
  readonly release: string;
  readonly artifactSha256: string;
}

export interface InstallJournalLease {
  readonly attemptId: string;
  readonly acquiredAt: number;
  readonly expiresAt: number;
}

export interface InstallJournalApproval {
  readonly schemaVersion: 1;
  readonly attemptId: string;
  readonly approvedAt: number;
  readonly recordedAt: number;
  readonly planId: string;
  readonly planHash: string;
  readonly planExpiresAt: number;
  readonly managementOwnershipMarker: string;
}

export interface WorkerCreateRecord {
  readonly schemaVersion: 1;
  readonly kind: 'worker_create';
  readonly accountId: string;
  readonly workerName: string;
  readonly requestHash: string;
  readonly correlationTag: string;
}

export type GatewayFreshPreflightRecord = CustomerGatewayFreshPreflightAttestation;

export interface ManagementAccessApplicationCreateRecord {
  readonly schemaVersion: 1;
  readonly kind: 'management_access_application_create';
  readonly accountId: string;
  readonly planId: string;
  readonly planHash: string;
  readonly ownershipMarker: string;
  readonly allowedIdentityProviderIds: readonly string[];
  readonly intentHash: string;
}

export interface ManagementAdminPolicyCreateRecord {
  readonly schemaVersion: 1;
  readonly kind: 'management_admin_policy_create';
  readonly accountId: string;
  readonly planId: string;
  readonly planHash: string;
  readonly ownershipMarker: string;
  readonly applicationId: string;
  readonly intentHash: string;
}

export interface WorkerVersionCreateRecord {
  readonly schemaVersion: 1;
  readonly kind: 'worker_version_create';
  readonly phase: 'provision' | 'bootstrap' | 'clean';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly requestHash: string;
  readonly correlationTag: string;
  readonly releaseContract: WorkerVersionRecoveryRecord['releaseContract'];
  readonly assets: WorkerVersionRecoveryRecord['assets'];
  readonly plainTextBindingHashes: readonly {
    readonly name: GatewayPlainTextBindingName;
    readonly valueSha256: string;
  }[];
  readonly modules: readonly {
    readonly name: string;
    readonly contentType: string;
    readonly contentSha256: string;
    readonly byteLength: number;
  }[];
}

export interface WorkerDeploymentCreateRecord {
  readonly schemaVersion: 1;
  readonly kind: 'worker_deployment_create';
  readonly phase: 'provision' | 'bootstrap' | 'clean';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly versionId: string;
  readonly requestHash: string;
  readonly correlationTag: string;
}

export interface BootstrapSubdomainRecord {
  readonly schemaVersion: 1;
  readonly kind: 'bootstrap_subdomain';
  readonly accountId: string;
  readonly workerName: string;
  readonly enabled: boolean;
  readonly requestHash: string;
}

export interface CustomerBootstrapSubmitRecord {
  readonly schemaVersion: 1;
  readonly kind: 'customer_bootstrap_submit';
  readonly accountId: string;
  readonly zoneId: string;
  readonly zoneName: string;
  readonly accountWorkersSubdomain: string;
  readonly installationId: string;
  readonly configurationHash: string;
  readonly desiredHash: string;
  readonly attempts: readonly CustomerBootstrapRequestAttempt[];
}

export interface CustomerBootstrapRequestAttempt {
  readonly schemaVersion: 1;
  readonly approvalAttemptId: string;
  readonly requestId: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly claimHash: string;
  readonly enable: CustomerBootstrapCycleSubdomainMutation;
  readonly disable: CustomerBootstrapCycleSubdomainMutation | null;
  readonly phase: InstallActionPhase;
  readonly locator: CustomerBootstrapLocator | null;
  readonly preparedAt: number;
  readonly sendArmedAt: number | null;
  readonly submittedAt: number | null;
  readonly verifiedAt: number | null;
}

export interface CustomerBootstrapCycleSubdomainMutation {
  readonly schemaVersion: 1;
  readonly approvalAttemptId: string;
  readonly enabled: boolean;
  readonly requestHash: string;
  readonly phase: InstallActionPhase;
  readonly locator: BootstrapSubdomainLocator | null;
  readonly preparedAt: number;
  readonly sendArmedAt: number | null;
  readonly submittedAt: number | null;
  readonly verifiedAt: number | null;
}

export interface ManagementCustomDomainAttachRecord {
  readonly schemaVersion: 1;
  readonly kind: 'management_custom_domain_attach';
  readonly accountId: string;
  readonly zoneId: string;
  readonly planId: string;
  readonly planHash: string;
  readonly ownershipMarker: string;
  readonly intentHash: string;
}

export interface FinalConvergenceRecord {
  readonly schemaVersion: 1;
  readonly kind: 'final_convergence';
  readonly convergenceHash: string;
}

export type InstallActionRecord =
  | GatewayFreshPreflightRecord
  | WorkerCreateRecord
  | ManagementAccessApplicationCreateRecord
  | ManagementAdminPolicyCreateRecord
  | WorkerVersionCreateRecord
  | WorkerDeploymentCreateRecord
  | BootstrapSubdomainRecord
  | CustomerBootstrapSubmitRecord
  | ManagementCustomDomainAttachRecord
  | FinalConvergenceRecord;

export interface WorkerLocator {
  readonly kind: 'worker';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
}

export interface GatewayFreshPreflightLocator {
  readonly attestationHash: string;
}

export interface ManagementAccessApplicationLocator {
  readonly applicationId: string;
  readonly aud: string;
}

export interface ManagementAdminPolicyLocator {
  readonly policyId: string;
}

export interface WorkerVersionLocator {
  readonly kind: 'version';
  readonly phase: 'provision' | 'bootstrap' | 'clean';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly versionId: string;
  readonly requestHash: string;
  readonly correlationTag: string;
  readonly namespaceId?: string;
}

export interface WorkerDeploymentLocator {
  readonly kind: 'deployment';
  readonly phase: 'provision' | 'bootstrap' | 'clean';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly versionId: string;
  readonly deploymentId: string;
  readonly requestHash: string;
  readonly correlationTag: string;
}

export interface BootstrapSubdomainLocator {
  readonly enabled: boolean;
  readonly previewsEnabled: false;
}

export type CustomerBootstrapLocator =
  | {
      readonly schemaVersion: 1;
      readonly status: 'ready';
      readonly installationId: string;
      readonly approvedPlanId: string;
      readonly configurationHash: string;
      readonly desiredHash: string;
      readonly settingsRevision: 1;
      readonly release: { readonly id: string; readonly artifactSha256: string };
      readonly gateway: { readonly hostname: string; readonly mcpUrl: string };
      readonly receipt: {
        readonly revision: number;
        readonly resourceCount: 4 | 7;
        readonly evidence: ReadyInstallationReceipt;
      };
      readonly applyInvoked: boolean;
      readonly resumed: boolean;
    }
  | {
      readonly schemaVersion: 1;
      readonly status: 'recovery_required';
      readonly reason:
        | 'bootstrap_recovery_required'
        | 'bootstrap_requires_repair'
        | 'bootstrap_request_mismatch';
      readonly canRetry: false;
    };

export interface ManagementCustomDomainLocator {
  readonly domainId: string;
}

export interface FinalConvergenceLocator {
  readonly schemaVersion: 1;
  readonly status: 'converged';
  readonly convergenceHash: string;
  readonly installationId: string;
  readonly bindingHash: string;
  readonly workerId: string;
  readonly managementApplicationId: string;
  readonly managementAccessAud: string;
  readonly managementPolicyId: string;
  readonly bootstrapVersionId: string;
  readonly bootstrapDeploymentId: string;
  readonly cleanVersionId: string;
  readonly cleanDeploymentId: string;
  readonly managementDomainId: string;
  readonly customerApprovedPlanId: string;
  readonly customerReceiptRevision: number;
  readonly customerReceiptEvidence: ReadyInstallationReceipt;
  readonly adminStateNamespaceId: string;
  readonly workersDevEnabled: false;
}

export type InstallActionLocator =
  | GatewayFreshPreflightLocator
  | WorkerLocator
  | ManagementAccessApplicationLocator
  | ManagementAdminPolicyLocator
  | WorkerVersionLocator
  | WorkerDeploymentLocator
  | BootstrapSubdomainLocator
  | CustomerBootstrapLocator
  | ManagementCustomDomainLocator
  | FinalConvergenceLocator;

export interface InstallJournalAction {
  readonly name: InstallActionName;
  readonly phase: InstallActionPhase;
  readonly record: InstallActionRecord;
  readonly locator: InstallActionLocator | null;
  readonly preparedAt: number;
  readonly sendArmedAt: number | null;
  readonly submittedAt: number | null;
  readonly verifiedAt: number | null;
}

export interface InstallJournal {
  readonly schemaVersion: 1;
  readonly revision: number;
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly sessionExpiresAt: number;
  readonly recoverUntil: number;
  readonly selection: DeploySelection;
  readonly plan: StaticDeployPlan;
  readonly releasePin: InstallReleasePin;
  readonly target: AuthorizedTarget;
  readonly installationId: string;
  readonly bindingHash: string;
  readonly approvalHistory: readonly InstallJournalApproval[];
  readonly lease: InstallJournalLease | null;
  readonly leaseAttemptIds: readonly string[];
  readonly actions: readonly InstallJournalAction[];
}

function publicActionUpdatedAt(action: InstallJournalAction): number {
  return action.verifiedAt ?? action.submittedAt ?? action.sendArmedAt ?? action.preparedAt;
}

/** Secret-free, provider-ID-free progress projection for the public UI. */
export function publicInstallProgress(journal: InstallJournal | null): PublicInstallProgress | null {
  if (!journal) return null;
  return Object.freeze({
    schemaVersion: 1 as const,
    revision: journal.revision,
    updatedAt: journal.updatedAt,
    actions: Object.freeze(journal.actions.map((action) => Object.freeze({
      name: action.name,
      phase: action.phase,
      updatedAt: publicActionUpdatedAt(action),
    }))),
  });
}

export function parsePublicInstallProgress(value: unknown): PublicInstallProgress | null {
  if (value === null) return null;
  if (!isRecord(value) || !exactKeys(value, ['schemaVersion', 'revision', 'updatedAt', 'actions']) ||
    value.schemaVersion !== 1 || !safeInteger(value.revision) || !safeInteger(value.updatedAt) ||
    !Array.isArray(value.actions) || value.actions.length > INSTALL_ACTION_ORDER.length) {
    invalid();
  }
  const actions: PublicInstallProgressAction[] = [];
  for (let index = 0; index < value.actions.length; index += 1) {
    const action = value.actions[index];
    if (!isRecord(action) || !exactKeys(action, ['name', 'phase', 'updatedAt']) ||
      action.name !== INSTALL_ACTION_ORDER[index] ||
      !['prepared', 'send_armed', 'submitted', 'verified'].includes(action.phase as string) ||
      !safeInteger(action.updatedAt) || action.updatedAt > value.updatedAt) {
      invalid();
    }
    actions.push(Object.freeze({
      name: action.name as InstallActionName,
      phase: action.phase as InstallActionPhase,
      updatedAt: action.updatedAt,
    }));
  }
  return Object.freeze({
    schemaVersion: 1,
    revision: value.revision,
    updatedAt: value.updatedAt,
    actions: Object.freeze(actions),
  });
}

export interface CreateInstallJournalInput {
  readonly schemaVersion: 1;
  readonly now: number;
  readonly recoverUntil: number;
  readonly selection: DeploySelection;
  readonly plan: StaticDeployPlan;
  readonly releasePin: InstallReleasePin;
  readonly target: AuthorizedTarget;
  readonly installationId: string;
  readonly bindingHash: string;
  readonly gatewayFreshPreflight: unknown;
}

export interface InstallJournalCasInput {
  readonly expectedRevision: number;
  readonly attemptId: string;
  readonly now: number;
}

export interface AcquireInstallJournalLeaseInput extends InstallJournalCasInput {
  readonly leaseExpiresAt: number;
}

export interface AppendInstallJournalApprovalInput extends InstallJournalCasInput {
  readonly approvedAt: number;
}

export interface PrepareInstallJournalActionInput extends InstallJournalCasInput {
  readonly action: InstallActionName;
  readonly record: unknown;
}

/**
 * Applies the Durable Object's authoritative transition time to a prepare
 * request. The initial customer bootstrap record carries its own preparedAt
 * because its action summary is nested inside the attempt. Leaving that one
 * timestamp on the caller's clock makes an otherwise valid request fail as
 * soon as transport latency separates it from the server clock.
 */
export function serverTimeInstallJournalPrepare(
  input: PrepareInstallJournalActionInput,
  serverNow: number,
): PrepareInstallJournalActionInput {
  if (input.action !== 'customer_bootstrap_submit' || !isRecord(input.record)) {
    return Object.freeze({ ...input, now: serverNow });
  }
  const attempts = input.record.attempts;
  const first = Array.isArray(attempts) && attempts.length === 1 && isRecord(attempts[0])
    ? attempts[0]
    : null;
  if (!first) return Object.freeze({ ...input, now: serverNow });
  return Object.freeze({
    ...input,
    now: serverNow,
    record: Object.freeze({
      ...input.record,
      attempts: Object.freeze([Object.freeze({ ...first, preparedAt: serverNow })]),
    }),
  });
}

export interface TransitionInstallJournalActionInput extends InstallJournalCasInput {
  readonly action: InstallActionName;
}

export interface SubmitInstallJournalActionInput extends TransitionInstallJournalActionInput {
  readonly locator: unknown;
}

export interface AppendCustomerBootstrapAttemptInput extends InstallJournalCasInput {
  readonly attempt: unknown;
}

const GATEWAY_BINDINGS = Object.freeze([
  'ADMIN_EMAILS',
  'ANKKA_GATEWAY_RELEASE',
  'ANKKA_GATEWAY_RELEASE_SHA256',
  'ANKKA_MANAGEMENT_HOSTNAME',
  'ANKKA_UPDATE_CHANNEL',
  'ANKKA_UPDATE_KEY_ID',
  'ANKKA_UPDATE_PUBLIC_KEY',
  'ANKKA_WORKERS_SUBDOMAIN',
  'ANKKA_WORKER_NAME',
  'CF_ACCESS_AUD',
  'CF_ACCESS_ISSUER',
  'CLOUDFLARE_ACCOUNT_ID',
  'CLOUDFLARE_ZONE_ID',
  'CLOUDFLARE_ZONE_NAME',
  'ZERO_TRUST_READY',
] as const);
type GatewayPlainTextBindingName = (typeof GATEWAY_BINDINGS)[number];


function invalid(status = 500): never {
  throw new DeployError(status, status === 400 ? 'bad_request' : 'session_invalid');
}

function conflict(): never {
  throw new DeployError(409, 'session_conflict');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value) && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError('canonical_json_invalid');
}

function exactJson(left: unknown, right: unknown): boolean {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

function planWithoutExpiry(plan: StaticDeployPlan): Omit<StaticDeployPlan, 'expiresAt'> {
  const { expiresAt: _expiresAt, ...stable } = plan;
  return stable;
}

export function isRecoveryEquivalentInstallPlan(
  baseline: StaticDeployPlan,
  candidate: StaticDeployPlan,
): boolean {
  try {
    const parsedBaseline = parseStaticDeployPlan(baseline);
    const parsedCandidate = parseStaticDeployPlan(candidate);
    return exactJson(planWithoutExpiry(parsedBaseline), planWithoutExpiry(parsedCandidate));
  } catch {
    return false;
  }
}

function activeApproval(journal: Pick<InstallJournal, 'approvalHistory'>): InstallJournalApproval {
  const approval = journal.approvalHistory[journal.approvalHistory.length - 1];
  if (!approval) invalid();
  return approval;
}

export function activeInstallJournalPlan(journal: InstallJournal): StaticDeployPlan {
  const approval = activeApproval(journal);
  return Object.freeze({ ...journal.plan, expiresAt: approval.planExpiresAt });
}

function safeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function safeText(value: unknown, maximum: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum && !CONTROL_CHARACTER.test(value);
}

function forbiddenJournalShape(value: unknown): boolean {
  if (value instanceof Uint8Array || value instanceof ArrayBuffer || value instanceof Blob) return true;
  if (Array.isArray(value)) return value.some(forbiddenJournalShape);
  if (!isRecord(value)) return false;
  for (const [key, child] of Object.entries(value)) {
    const normalized = key.toLowerCase().replaceAll('-', '').replaceAll('_', '');
    if (
      normalized === 'token' || normalized.endsWith('accesstoken') || normalized.endsWith('refreshtoken') ||
      normalized === 'code' || normalized.endsWith('authorizationcode') || normalized.endsWith('codeverifier') ||
      normalized === 'verifier' || (normalized.endsWith('nonce') && !normalized.endsWith('noncehash')) ||
      (normalized.endsWith('signature') && !normalized.endsWith('signaturehash')) || normalized.endsWith('jwt') ||
      normalized === 'bytes' || normalized.endsWith('releasebytes') || normalized === 'payload' ||
      normalized === 'body' || normalized === 'request' || normalized === 'response' ||
      normalized === 'providerbody' || normalized === 'privatekey'
    ) return true;
    if (forbiddenJournalShape(child)) return true;
  }
  return false;
}

function releasePin(value: unknown): InstallReleasePin | null {
  if (!isRecord(value) || !exactKeys(value, ['verification', 'keyId', 'release', 'artifactSha256'])) return null;
  if (
    value.verification !== 'ed25519' || typeof value.keyId !== 'string' || !KEY_ID.test(value.keyId) ||
    typeof value.release !== 'string' || !RELEASE.test(value.release) ||
    typeof value.artifactSha256 !== 'string' || !SHA256.test(value.artifactSha256)
  ) return null;
  return Object.freeze({
    verification: 'ed25519',
    keyId: value.keyId,
    release: value.release,
    artifactSha256: value.artifactSha256,
  });
}

function authorizedTarget(value: unknown, selection: DeploySelection): AuthorizedTarget | null {
  if (!isRecord(value) || !exactKeys(value, ['actor', 'account', 'zone'])) return null;
  const { actor, account, zone } = value;
  if (
    !isRecord(actor) || !exactKeys(actor, ['id', 'email']) ||
    typeof actor.id !== 'string' || !SAFE_ACTOR_ID.test(actor.id) || actor.email !== selection.basics.adminEmail ||
    !isRecord(account) || !exactKeys(account, ['id', 'name']) ||
    typeof account.id !== 'string' || !ACCOUNT_ID.test(account.id) || !safeText(account.name, 256) ||
    !isRecord(zone) || !exactKeys(zone, ['id', 'name', 'status']) ||
    typeof zone.id !== 'string' || !ACCOUNT_ID.test(zone.id) ||
    zone.name !== selection.basics.zoneName || zone.status !== 'active'
  ) return null;
  return Object.freeze({
    actor: Object.freeze({ id: actor.id, email: actor.email as string }),
    account: Object.freeze({ id: account.id, name: account.name }),
    zone: Object.freeze({ id: zone.id, name: zone.name as string, status: 'active' }),
  });
}

function managementWorkerName(plan: StaticDeployPlan): string | null {
  const values = plan.managementResources.filter((resource) => resource.kind === 'management_worker');
  return values.length === 1 && WORKER_NAME.test(values[0].name) ? values[0].name : null;
}

async function stableInstallationId(selection: DeploySelection, target: AuthorizedTarget): Promise<string> {
  const digest = await sha256Hex(canonicalJson({
    accountId: target.account.id,
    hostname: selection.basics.portalHostname,
    zoneId: target.zone.id,
  }));
  return `acg-${digest.slice(0, 24)}`;
}

export async function computeInstallJournalBindingHash(input: {
  readonly selection: DeploySelection;
  readonly plan: StaticDeployPlan;
  readonly releasePin: InstallReleasePin;
  readonly target: AuthorizedTarget;
  readonly installationId: string;
}): Promise<string> {
  return `sha256:${await sha256Hex(canonicalJson({
    schemaVersion: 1,
    installationId: input.installationId,
    plan: input.plan,
    releasePin: input.releasePin,
    selection: input.selection,
    target: input.target,
  }))}`;
}

function actionByName(journal: Pick<InstallJournal, 'actions'>, name: InstallActionName): InstallJournalAction | null {
  return journal.actions.find((action) => action.name === name) ?? null;
}

function verifiedLocator(journal: Pick<InstallJournal, 'actions'>, name: InstallActionName): InstallActionLocator | null {
  const action = actionByName(journal, name);
  return action?.phase === 'verified' ? action.locator : null;
}

function expectedPhase(name: InstallActionName): 'provision' | 'bootstrap' | 'clean' | null {
  if (name.startsWith('provision_worker_')) return 'provision';
  if (name.startsWith('bootstrap_worker_')) return 'bootstrap';
  if (name.startsWith('clean_worker_')) return 'clean';
  return null;
}

async function parseFreshPreflightRecord(
  value: unknown,
  journal: InstallJournal,
): Promise<GatewayFreshPreflightRecord | null> {
  const parsed = await parseCustomerGatewayFreshPreflightAttestation(value);
  let expected: Awaited<ReturnType<typeof deriveCustomerGatewayExpectedProjection>>;
  try {
    expected = await deriveCustomerGatewayExpectedProjection({
      selection: journal.selection,
      target: journal.target,
      plan: journal.plan,
      release: {
        id: journal.releasePin.release,
        artifactSha256: journal.releasePin.artifactSha256,
      },
    });
  } catch {
    return null;
  }
  if (
    !parsed || parsed.accountId !== journal.target.account.id || parsed.zoneId !== journal.target.zone.id ||
    parsed.planId !== journal.plan.planId || parsed.planHash !== journal.plan.planHash ||
    parsed.installationId !== journal.installationId || parsed.releaseId !== journal.releasePin.release ||
    parsed.releaseArtifactSha256 !== journal.releasePin.artifactSha256 ||
    parsed.installationId !== expected.expected.installationId ||
    parsed.configurationHash !== expected.expected.configurationHash ||
    parsed.desiredHash !== expected.expected.desiredHash ||
    parsed.zeroCandidateKinds.length !== expected.resourceKinds.length ||
    parsed.zeroCandidateKinds.some((kind, index) => kind !== expected.resourceKinds[index]) ||
    parsed.checkedAt > journal.createdAt || parsed.expiresAt <= journal.createdAt ||
    parsed.expiresAt > journal.plan.expiresAt
  ) return null;
  return parsed;
}

async function parseWorkerRecord(value: unknown, journal: InstallJournal): Promise<WorkerCreateRecord | null> {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'kind', 'accountId', 'workerName', 'requestHash', 'correlationTag',
  ])) return null;
  const workerName = managementWorkerName(journal.plan);
  if (
    value.schemaVersion !== 1 || value.kind !== 'worker_create' || value.accountId !== journal.target.account.id ||
    value.workerName !== workerName || typeof value.requestHash !== 'string' || !SHA256.test(value.requestHash) ||
    value.correlationTag !== `ankka-worker-sha256:${value.requestHash}`
  ) return null;
  const core = {
    logpush: false,
    name: workerName,
    observability: { enabled: false },
    subdomain: { enabled: false, previews_enabled: false },
    tags: ['ankka-mcp-gateway'],
    tail_consumers: [],
  };
  if (await sha256Hex(canonicalJson(core)) !== value.requestHash) return null;
  return Object.freeze({
    schemaVersion: 1,
    kind: 'worker_create',
    accountId: value.accountId,
    workerName: value.workerName as string,
    requestHash: value.requestHash,
    correlationTag: value.correlationTag as string,
  });
}

function canonicalProviderIds(value: unknown): readonly string[] | null {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_IDENTITY_PROVIDERS) return null;
  const ids = value.map((id) => typeof id === 'string' && PROVIDER_ID.test(id) ? id : '');
  if (ids.some((id) => id === '')) return null;
  const sorted = [...ids].sort();
  if (sorted.some((id, index) => index > 0 && id === sorted[index - 1])) return null;
  if (!ids.every((id, index) => id === sorted[index])) return null;
  return Object.freeze(sorted);
}

async function parseApplicationRecord(
  value: unknown,
  journal: InstallJournal,
): Promise<ManagementAccessApplicationCreateRecord | null> {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'kind', 'accountId', 'planId', 'planHash', 'ownershipMarker',
    'allowedIdentityProviderIds', 'intentHash',
  ])) return null;
  const ids = canonicalProviderIds(value.allowedIdentityProviderIds);
  if (
    value.schemaVersion !== 1 || value.kind !== 'management_access_application_create' ||
    value.accountId !== journal.target.account.id || value.planId !== journal.plan.planId ||
    value.planHash !== journal.plan.planHash || value.ownershipMarker !== managementOwnershipMarker(journal.plan) ||
    !ids || typeof value.intentHash !== 'string' || !SHA256.test(value.intentHash)
  ) return null;
  try {
    const intent = prepareManagementAccessApplicationIntent({
      accountId: journal.target.account.id,
      plan: journal.plan,
      allowedIdentityProviderIds: ids,
    });
    if (await sha256Hex(canonicalJson(intent)) !== value.intentHash) return null;
  } catch {
    return null;
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: 'management_access_application_create',
    accountId: value.accountId,
    planId: value.planId as string,
    planHash: value.planHash as string,
    ownershipMarker: value.ownershipMarker as string,
    allowedIdentityProviderIds: ids,
    intentHash: value.intentHash,
  });
}

async function parsePolicyRecord(
  value: unknown,
  journal: InstallJournal,
): Promise<ManagementAdminPolicyCreateRecord | null> {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'kind', 'accountId', 'planId', 'planHash', 'ownershipMarker', 'applicationId', 'intentHash',
  ])) return null;
  const application = verifiedLocator(journal, 'management_access_application_create');
  const applicationId = application && 'applicationId' in application ? application.applicationId : null;
  if (applicationId === null) return null;
  if (
    value.schemaVersion !== 1 || value.kind !== 'management_admin_policy_create' ||
    value.accountId !== journal.target.account.id || value.planId !== journal.plan.planId ||
    value.planHash !== journal.plan.planHash || value.ownershipMarker !== managementOwnershipMarker(journal.plan) ||
    value.applicationId !== applicationId || typeof value.intentHash !== 'string' || !SHA256.test(value.intentHash)
  ) return null;
  try {
    const intent = prepareManagementAdminPolicyIntent({
      accountId: journal.target.account.id,
      applicationId,
      plan: journal.plan,
    });
    if (await sha256Hex(canonicalJson(intent)) !== value.intentHash) return null;
  } catch {
    return null;
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: 'management_admin_policy_create',
    accountId: value.accountId,
    planId: value.planId as string,
    planHash: value.planHash as string,
    ownershipMarker: value.ownershipMarker as string,
    applicationId,
    intentHash: value.intentHash,
  });
}

function workerLocator(journal: InstallJournal): WorkerLocator | null {
  const locator = verifiedLocator(journal, 'worker_create');
  return locator && 'kind' in locator && locator.kind === 'worker' ? locator : null;
}

async function parseVersionRecord(
  name: InstallActionName,
  value: unknown,
  journal: InstallJournal,
): Promise<WorkerVersionCreateRecord | null> {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'kind', 'phase', 'accountId', 'workerName', 'workerId', 'requestHash',
    'correlationTag', 'releaseContract', 'assets', 'plainTextBindingHashes', 'modules',
  ])) return null;
  const phase = expectedPhase(name);
  const worker = workerLocator(journal);
  if (
    !phase || value.schemaVersion !== 1 || value.kind !== 'worker_version_create' || value.phase !== phase ||
    value.accountId !== journal.target.account.id || value.workerName !== managementWorkerName(journal.plan) ||
    value.workerId !== worker?.workerId
  ) return null;
  const parsed = await parseWorkerVersionRecoveryRecord({
    kind: 'version_recovery',
    phase: value.phase,
    accountId: value.accountId,
    workerName: value.workerName,
    workerId: value.workerId,
    requestHash: value.requestHash,
    correlationTag: value.correlationTag,
    releaseContract: value.releaseContract,
    assets: value.assets,
    plainTextBindingHashes: value.plainTextBindingHashes,
    modules: value.modules,
  });
  if (!parsed) return null;
  return Object.freeze({
    schemaVersion: 1,
    kind: 'worker_version_create',
    phase,
    accountId: parsed.accountId,
    workerName: parsed.workerName,
    workerId: parsed.workerId,
    requestHash: parsed.requestHash,
    correlationTag: parsed.correlationTag,
    releaseContract: parsed.releaseContract,
    assets: parsed.assets,
    plainTextBindingHashes: parsed.plainTextBindingHashes,
    modules: parsed.modules,
  });
}

function versionLocator(
  journal: InstallJournal,
  phase: 'provision' | 'bootstrap' | 'clean',
): WorkerVersionLocator | null {
  const name = phase === 'provision'
    ? 'provision_worker_version_create'
    : phase === 'bootstrap'
      ? 'bootstrap_worker_version_create'
      : 'clean_worker_version_create';
  const locator = verifiedLocator(journal, name);
  return locator && 'kind' in locator && locator.kind === 'version' ? locator : null;
}

async function parseDeploymentRecord(
  name: InstallActionName,
  value: unknown,
  journal: InstallJournal,
): Promise<WorkerDeploymentCreateRecord | null> {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'kind', 'phase', 'accountId', 'workerName', 'workerId', 'versionId', 'requestHash', 'correlationTag',
  ])) return null;
  const phase = expectedPhase(name);
  const version = phase ? versionLocator(journal, phase) : null;
  if (
    !phase || value.schemaVersion !== 1 || value.kind !== 'worker_deployment_create' || value.phase !== phase ||
    value.accountId !== journal.target.account.id || value.workerName !== version?.workerName ||
    value.workerId !== version?.workerId || value.versionId !== version?.versionId ||
    typeof value.requestHash !== 'string' || !SHA256.test(value.requestHash) ||
    value.correlationTag !== `ankka-deploy-${phase}-sha256:${value.requestHash}`
  ) return null;
  const core = { strategy: 'percentage', versions: [{ percentage: 100, version_id: value.versionId }] };
  if (await sha256Hex(canonicalJson(core)) !== value.requestHash) return null;
  return Object.freeze({
    schemaVersion: 1,
    kind: 'worker_deployment_create',
    phase,
    accountId: value.accountId,
    workerName: value.workerName as string,
    workerId: value.workerId as string,
    versionId: value.versionId as string,
    requestHash: value.requestHash,
    correlationTag: value.correlationTag as string,
  });
}

async function parseSubdomainRecord(
  name: InstallActionName,
  value: unknown,
  journal: InstallJournal,
): Promise<BootstrapSubdomainRecord | null> {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'kind', 'accountId', 'workerName', 'enabled', 'requestHash',
  ])) return null;
  const enabled = name === 'bootstrap_subdomain_enable' ? true : name === 'bootstrap_subdomain_disable' ? false : null;
  if (
    enabled === null || value.schemaVersion !== 1 || value.kind !== 'bootstrap_subdomain' ||
    value.accountId !== journal.target.account.id || value.workerName !== managementWorkerName(journal.plan) ||
    value.enabled !== enabled || typeof value.requestHash !== 'string' || !SHA256.test(value.requestHash) ||
    await sha256Hex(canonicalJson({ enabled, previews_enabled: false })) !== value.requestHash
  ) return null;
  return Object.freeze({
    schemaVersion: 1,
    kind: 'bootstrap_subdomain',
    accountId: value.accountId,
    workerName: value.workerName as string,
    enabled,
    requestHash: value.requestHash,
  });
}

async function bootstrapClaimHash(
  record: Omit<CustomerBootstrapSubmitRecord, 'attempts'>,
  attempt: Pick<CustomerBootstrapRequestAttempt, 'requestId' | 'issuedAt' | 'expiresAt'>,
): Promise<string> {
  return `sha256:${await sha256Hex(canonicalJson({
    schemaVersion: 1,
    requestId: attempt.requestId,
    issuedAt: attempt.issuedAt,
    expiresAt: attempt.expiresAt,
    accountId: record.accountId,
    zoneId: record.zoneId,
    zoneName: record.zoneName,
    accountWorkersSubdomain: record.accountWorkersSubdomain,
    installationId: record.installationId,
    configurationHash: record.configurationHash,
    desiredHash: record.desiredHash,
  }))}`;
}

async function parseCycleSubdomainMutation(
  value: unknown,
  enabled: boolean,
  journal: InstallJournal,
): Promise<CustomerBootstrapCycleSubdomainMutation | null> {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'approvalAttemptId', 'enabled', 'requestHash', 'phase', 'locator', 'preparedAt',
    'sendArmedAt', 'submittedAt', 'verifiedAt',
  ])) return null;
  const phase = value.phase as InstallActionPhase;
  const approval = typeof value.approvalAttemptId === 'string'
    ? journal.approvalHistory.find((entry) => entry.attemptId === value.approvalAttemptId)
    : null;
  const armed = phase !== 'prepared';
  const submitted = phase === 'submitted' || phase === 'verified';
  const verified = phase === 'verified';
  if (
    value.schemaVersion !== 1 || !approval || value.enabled !== enabled ||
    typeof value.requestHash !== 'string' || !SHA256.test(value.requestHash) ||
    await sha256Hex(canonicalJson({ enabled, previews_enabled: false })) !== value.requestHash ||
    !['prepared', 'send_armed', 'submitted', 'verified'].includes(String(value.phase)) ||
    !safeInteger(value.preparedAt) || value.preparedAt < approval.approvedAt || value.preparedAt > journal.updatedAt ||
    (armed !== safeInteger(value.sendArmedAt)) ||
    (submitted !== safeInteger(value.submittedAt)) ||
    (verified !== safeInteger(value.verifiedAt)) ||
    (armed && (value.sendArmedAt as number) < value.preparedAt) ||
    (submitted && (value.submittedAt as number) < (value.sendArmedAt as number)) ||
    (verified && (value.verifiedAt as number) < (value.submittedAt as number)) ||
    [value.sendArmedAt, value.submittedAt, value.verifiedAt].some(
      (time) => typeof time === 'number' && time > journal.updatedAt,
    )
  ) return null;
  let locator: BootstrapSubdomainLocator | null = null;
  if (submitted) {
    if (!isRecord(value.locator) || !exactKeys(value.locator, ['enabled', 'previewsEnabled']) ||
      value.locator.enabled !== enabled || value.locator.previewsEnabled !== false) return null;
    locator = Object.freeze({ enabled, previewsEnabled: false });
  } else if (value.locator !== null) return null;
  return Object.freeze({
    schemaVersion: 1,
    approvalAttemptId: approval.attemptId,
    enabled,
    requestHash: value.requestHash,
    phase,
    locator,
    preparedAt: value.preparedAt,
    sendArmedAt: armed ? value.sendArmedAt as number : null,
    submittedAt: submitted ? value.submittedAt as number : null,
    verifiedAt: verified ? value.verifiedAt as number : null,
  });
}

async function parseBootstrapRecord(value: unknown, journal: InstallJournal): Promise<CustomerBootstrapSubmitRecord | null> {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'kind', 'accountId', 'zoneId', 'zoneName', 'accountWorkersSubdomain',
    'installationId', 'configurationHash', 'desiredHash', 'attempts',
  ])) return null;
  const preflight = actionByName(journal, 'gateway_fresh_preflight');
  if (
    value.schemaVersion !== 1 || value.kind !== 'customer_bootstrap_submit' ||
    value.accountId !== journal.target.account.id || value.zoneId !== journal.target.zone.id ||
    value.zoneName !== journal.target.zone.name || typeof value.accountWorkersSubdomain !== 'string' ||
    !HOST_LABEL.test(value.accountWorkersSubdomain) || value.installationId !== journal.installationId ||
    typeof value.configurationHash !== 'string' || !PREFIXED_SHA256.test(value.configurationHash) ||
    typeof value.desiredHash !== 'string' || !PREFIXED_SHA256.test(value.desiredHash) ||
    preflight?.phase !== 'verified' || preflight.record.kind !== 'customer_gateway_fresh_preflight' ||
    value.configurationHash !== preflight.record.configurationHash || value.desiredHash !== preflight.record.desiredHash ||
    !Array.isArray(value.attempts) || value.attempts.length < 1 || value.attempts.length > MAX_BOOTSTRAP_ATTEMPTS
  ) return null;
  const semantic = Object.freeze({
    schemaVersion: 1,
    kind: 'customer_bootstrap_submit' as const,
    accountId: value.accountId,
    zoneId: value.zoneId as string,
    zoneName: value.zoneName as string,
    accountWorkersSubdomain: value.accountWorkersSubdomain,
    installationId: value.installationId as string,
    configurationHash: value.configurationHash,
    desiredHash: value.desiredHash,
  });
  const attempts: CustomerBootstrapRequestAttempt[] = [];
  for (let index = 0; index < value.attempts.length; index += 1) {
    const input = value.attempts[index];
    if (!isRecord(input) || !exactKeys(input, [
      'schemaVersion', 'approvalAttemptId', 'requestId', 'issuedAt', 'expiresAt', 'claimHash',
      'enable', 'disable', 'phase', 'locator', 'preparedAt', 'sendArmedAt', 'submittedAt', 'verifiedAt',
    ])) return null;
    const approval = journal.approvalHistory.find((entry) => entry.attemptId === input.approvalAttemptId);
    const prior = attempts[index - 1];
    const enable = await parseCycleSubdomainMutation(input.enable, true, journal);
    const disable = input.disable === null ? null : await parseCycleSubdomainMutation(input.disable, false, journal);
    if (
      input.schemaVersion !== 1 || typeof input.approvalAttemptId !== 'string' || !approval || !enable ||
      enable.approvalAttemptId !== input.approvalAttemptId ||
      attempts.some((attempt) => attempt.approvalAttemptId === input.approvalAttemptId) ||
      typeof input.requestId !== 'string' || !REQUEST_ID.test(input.requestId) ||
      attempts.some((attempt) => attempt.requestId === input.requestId) ||
      !safeInteger(input.issuedAt) || !safeInteger(input.expiresAt) || input.expiresAt <= input.issuedAt ||
      input.expiresAt - input.issuedAt > 5 * 60 || input.expiresAt > Math.floor(approval.planExpiresAt / 1_000) ||
      typeof input.claimHash !== 'string' || !PREFIXED_SHA256.test(input.claimHash) ||
      !['prepared', 'send_armed', 'submitted', 'verified'].includes(String(input.phase)) ||
      !safeInteger(input.preparedAt) || input.preparedAt < approval.approvedAt || input.preparedAt > journal.updatedAt ||
      (prior && input.preparedAt < Math.max(
        prior.preparedAt,
        prior.sendArmedAt ?? 0,
        prior.submittedAt ?? 0,
        prior.verifiedAt ?? 0,
      )) ||
      (prior && (prior.phase === 'verified' || prior.disable?.phase !== 'verified')) ||
      (input.phase !== 'prepared' && enable.phase !== 'verified') ||
      (input.disable !== null && (
        !disable || enable.phase !== 'verified' ||
        disable.preparedAt < (enable.verifiedAt as number)
      ))
    ) return null;
    if (index === 0) {
      const topEnable = actionByName(journal, 'bootstrap_subdomain_enable');
      if (
        !topEnable || topEnable.phase !== 'verified' || topEnable.record.kind !== 'bootstrap_subdomain' ||
        topEnable.record.enabled !== true || enable.phase !== 'verified' ||
        enable.requestHash !== topEnable.record.requestHash || !exactJson(enable.locator, topEnable.locator) ||
        enable.preparedAt !== topEnable.preparedAt || enable.sendArmedAt !== topEnable.sendArmedAt ||
        enable.submittedAt !== topEnable.submittedAt || enable.verifiedAt !== topEnable.verifiedAt
      ) return null;
    }
    const phase = input.phase as InstallActionPhase;
    const armed = phase !== 'prepared';
    const submitted = phase === 'submitted' || phase === 'verified';
    const verified = phase === 'verified';
    if (
      (armed !== safeInteger(input.sendArmedAt)) ||
      (submitted !== safeInteger(input.submittedAt)) ||
      (verified !== safeInteger(input.verifiedAt)) ||
      (armed && (input.sendArmedAt as number) < input.preparedAt) ||
      (submitted && (input.submittedAt as number) < (input.sendArmedAt as number)) ||
      (verified && (input.verifiedAt as number) < (input.submittedAt as number)) ||
      [input.sendArmedAt, input.submittedAt, input.verifiedAt].some(
        (time) => typeof time === 'number' && time > journal.updatedAt,
      ) ||
      await bootstrapClaimHash(semantic, input as unknown as CustomerBootstrapRequestAttempt) !== input.claimHash
    ) return null;
    let locator: CustomerBootstrapLocator | null = null;
    if (submitted) {
      locator = await parseBootstrapLocator(input.locator, semantic, journal);
      if (!locator || (verified && locator.status !== 'ready')) return null;
    } else if (input.locator !== null) return null;
    attempts.push(Object.freeze({
      schemaVersion: 1,
      approvalAttemptId: input.approvalAttemptId,
      requestId: input.requestId,
      issuedAt: input.issuedAt,
      expiresAt: input.expiresAt,
      claimHash: input.claimHash,
      enable,
      disable,
      phase,
      locator,
      preparedAt: input.preparedAt,
      sendArmedAt: armed ? input.sendArmedAt as number : null,
      submittedAt: submitted ? input.submittedAt as number : null,
      verifiedAt: verified ? input.verifiedAt as number : null,
    }));
  }
  return Object.freeze({
    ...semantic,
    attempts: Object.freeze(attempts),
  });
}

async function parseDomainRecord(
  value: unknown,
  journal: InstallJournal,
): Promise<ManagementCustomDomainAttachRecord | null> {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'kind', 'accountId', 'zoneId', 'planId', 'planHash', 'ownershipMarker', 'intentHash',
  ])) return null;
  if (
    value.schemaVersion !== 1 || value.kind !== 'management_custom_domain_attach' ||
    value.accountId !== journal.target.account.id || value.zoneId !== journal.target.zone.id ||
    value.planId !== journal.plan.planId || value.planHash !== journal.plan.planHash ||
    value.ownershipMarker !== managementOwnershipMarker(journal.plan) ||
    typeof value.intentHash !== 'string' || !SHA256.test(value.intentHash)
  ) return null;
  try {
    const intent = prepareManagementCustomDomainIntent({
      accountId: journal.target.account.id,
      zoneId: journal.target.zone.id,
      plan: journal.plan,
    });
    if (await sha256Hex(canonicalJson(intent)) !== value.intentHash) return null;
  } catch {
    return null;
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: 'management_custom_domain_attach',
    accountId: value.accountId,
    zoneId: value.zoneId as string,
    planId: value.planId as string,
    planHash: value.planHash as string,
    ownershipMarker: value.ownershipMarker as string,
    intentHash: value.intentHash,
  });
}

function finalProjection(journal: InstallJournal): Record<string, unknown> | null {
  const worker = verifiedLocator(journal, 'worker_create');
  const application = verifiedLocator(journal, 'management_access_application_create');
  const policy = verifiedLocator(journal, 'management_admin_policy_create');
  const bootstrapVersion = verifiedLocator(journal, 'bootstrap_worker_version_create');
  const bootstrapDeployment = verifiedLocator(journal, 'bootstrap_worker_deployment_create');
  const bootstrap = verifiedLocator(journal, 'customer_bootstrap_submit');
  const disabled = verifiedLocator(journal, 'bootstrap_subdomain_disable');
  const cleanVersion = verifiedLocator(journal, 'clean_worker_version_create');
  const cleanDeployment = verifiedLocator(journal, 'clean_worker_deployment_create');
  const domain = verifiedLocator(journal, 'management_custom_domain_attach');
  if (
    !worker || !('kind' in worker) || worker.kind !== 'worker' ||
    !application || !('applicationId' in application) ||
    !policy || !('policyId' in policy) ||
    !bootstrapVersion || !('kind' in bootstrapVersion) || bootstrapVersion.kind !== 'version' ||
    !bootstrapDeployment || !('kind' in bootstrapDeployment) || bootstrapDeployment.kind !== 'deployment' ||
    !bootstrap || !('status' in bootstrap) || bootstrap.status !== 'ready' ||
    !disabled || !('enabled' in disabled) || disabled.enabled !== false ||
    !cleanVersion || !('kind' in cleanVersion) || cleanVersion.kind !== 'version' ||
    !cleanDeployment || !('kind' in cleanDeployment) || cleanDeployment.kind !== 'deployment' ||
    !domain || !('domainId' in domain)
  ) return null;
  if (bootstrapVersion.namespaceId !== cleanVersion.namespaceId) return null;
  return {
    adminStateNamespaceId: bootstrapVersion.namespaceId,
    bindingHash: journal.bindingHash,
    bootstrapDeploymentId: bootstrapDeployment.deploymentId,
    bootstrapVersionId: bootstrapVersion.versionId,
    cleanDeploymentId: cleanDeployment.deploymentId,
    cleanVersionId: cleanVersion.versionId,
    customerApprovedPlanId: bootstrap.approvedPlanId,
    customerReceiptEvidence: bootstrap.receipt.evidence,
    customerReceiptRevision: bootstrap.receipt.revision,
    installationId: journal.installationId,
    managementAccessAud: application.aud,
    managementApplicationId: application.applicationId,
    managementDomainId: domain.domainId,
    managementPolicyId: policy.policyId,
    workerId: worker.workerId,
    workersDevEnabled: false,
  };
}

async function expectedConvergenceHash(journal: InstallJournal): Promise<string | null> {
  const projection = finalProjection(journal);
  return projection ? `sha256:${await sha256Hex(canonicalJson({ schemaVersion: 1, ...projection }))}` : null;
}

export async function prepareFinalConvergenceRecordAndLocator(journal: InstallJournal): Promise<{
  readonly record: FinalConvergenceRecord;
  readonly locator: FinalConvergenceLocator;
}> {
  const finalIndex = INSTALL_ACTION_ORDER.indexOf('final_convergence');
  const bootstrap = actionByName(journal, 'customer_bootstrap_submit');
  const latest = bootstrap?.record.kind === 'customer_bootstrap_submit'
    ? bootstrap.record.attempts[bootstrap.record.attempts.length - 1]
    : null;
  const projection = finalProjection(journal);
  const convergenceHash = await expectedConvergenceHash(journal);
  if (
    !projection || !convergenceHash || bootstrap?.phase !== 'verified' ||
    latest?.locator?.status !== 'ready' || latest.disable?.phase !== 'verified' ||
    latest.disable.locator?.enabled !== false ||
    (journal.actions.length !== finalIndex && journal.actions.length !== finalIndex + 1) ||
    !journal.actions.slice(0, finalIndex).every((action) => action.phase === 'verified')
  ) conflict();
  const record: FinalConvergenceRecord = Object.freeze({
    schemaVersion: 1,
    kind: 'final_convergence',
    convergenceHash,
  });
  const locator = Object.freeze({
    schemaVersion: 1,
    status: 'converged',
    convergenceHash,
    ...projection,
  }) as FinalConvergenceLocator;
  const existing = journal.actions[finalIndex];
  if (existing && (
    existing.name !== 'final_convergence' || !exactJson(existing.record, record) ||
    ((existing.phase === 'submitted' || existing.phase === 'verified')
      ? !exactJson(existing.locator, locator)
      : existing.locator !== null)
  )) conflict();
  return Object.freeze({ record, locator });
}

async function parseFinalRecord(value: unknown, journal: InstallJournal): Promise<FinalConvergenceRecord | null> {
  if (!isRecord(value) || !exactKeys(value, ['schemaVersion', 'kind', 'convergenceHash'])) return null;
  const expected = await expectedConvergenceHash(journal);
  if (
    value.schemaVersion !== 1 || value.kind !== 'final_convergence' ||
    typeof value.convergenceHash !== 'string' || value.convergenceHash !== expected
  ) return null;
  return Object.freeze({ schemaVersion: 1, kind: 'final_convergence', convergenceHash: value.convergenceHash });
}

async function parseActionRecord(
  name: InstallActionName,
  value: unknown,
  journal: InstallJournal,
): Promise<InstallActionRecord | null> {
  if (forbiddenJournalShape(value)) return null;
  if (name === 'gateway_fresh_preflight') return parseFreshPreflightRecord(value, journal);
  if (name === 'worker_create') return parseWorkerRecord(value, journal);
  if (name === 'management_access_application_create') return parseApplicationRecord(value, journal);
  if (name === 'management_admin_policy_create') return parsePolicyRecord(value, journal);
  if (
    name === 'provision_worker_version_create' || name === 'bootstrap_worker_version_create' ||
    name === 'clean_worker_version_create'
  ) {
    return parseVersionRecord(name, value, journal);
  }
  if (
    name === 'provision_worker_deployment_create' || name === 'bootstrap_worker_deployment_create' ||
    name === 'clean_worker_deployment_create'
  ) {
    return parseDeploymentRecord(name, value, journal);
  }
  if (name === 'bootstrap_subdomain_enable' || name === 'bootstrap_subdomain_disable') {
    return parseSubdomainRecord(name, value, journal);
  }
  if (name === 'customer_bootstrap_submit') return parseBootstrapRecord(value, journal);
  if (name === 'management_custom_domain_attach') return parseDomainRecord(value, journal);
  if (name === 'final_convergence') return parseFinalRecord(value, journal);
  return null;
}

function parseWorkerLocator(value: unknown, record: WorkerCreateRecord): WorkerLocator | null {
  if (!isRecord(value) || !exactKeys(value, ['kind', 'accountId', 'workerName', 'workerId'])) return null;
  if (
    value.kind !== 'worker' || value.accountId !== record.accountId || value.workerName !== record.workerName ||
    typeof value.workerId !== 'string' || !ACCOUNT_ID.test(value.workerId)
  ) return null;
  return Object.freeze({ kind: 'worker', accountId: record.accountId, workerName: record.workerName, workerId: value.workerId });
}

function parseFreshPreflightLocator(
  value: unknown,
  record: GatewayFreshPreflightRecord,
): GatewayFreshPreflightLocator | null {
  if (
    !isRecord(value) || !exactKeys(value, ['attestationHash']) ||
    value.attestationHash !== record.attestationHash
  ) return null;
  return Object.freeze({ attestationHash: record.attestationHash });
}

function parseApplicationLocator(value: unknown): ManagementAccessApplicationLocator | null {
  if (!isRecord(value) || !exactKeys(value, ['applicationId', 'aud'])) return null;
  if (
    typeof value.applicationId !== 'string' || !PROVIDER_ID.test(value.applicationId) ||
    typeof value.aud !== 'string' || !ACCESS_AUD.test(value.aud)
  ) return null;
  return Object.freeze({ applicationId: value.applicationId, aud: value.aud });
}

function parsePolicyLocator(value: unknown): ManagementAdminPolicyLocator | null {
  if (!isRecord(value) || !exactKeys(value, ['policyId']) || typeof value.policyId !== 'string' || !PROVIDER_ID.test(value.policyId)) {
    return null;
  }
  return Object.freeze({ policyId: value.policyId });
}

function parseVersionLocator(value: unknown, record: WorkerVersionCreateRecord): WorkerVersionLocator | null {
  // The provision version precedes the deployment that provisions the
  // Durable Object namespace, so its locator carries no namespaceId.
  const expectedKeys = record.phase === 'provision'
    ? ['kind', 'phase', 'accountId', 'workerName', 'workerId', 'versionId', 'requestHash', 'correlationTag']
    : ['kind', 'phase', 'accountId', 'workerName', 'workerId', 'versionId', 'requestHash', 'correlationTag', 'namespaceId'];
  if (!isRecord(value) || !exactKeys(value, expectedKeys)) return null;
  if (
    value.kind !== 'version' || value.phase !== record.phase || value.accountId !== record.accountId ||
    value.workerName !== record.workerName || value.workerId !== record.workerId ||
    typeof value.versionId !== 'string' || !UUID.test(value.versionId) ||
    (record.phase !== 'provision' &&
      (typeof value.namespaceId !== 'string' || !ACCOUNT_ID.test(value.namespaceId))) ||
    value.requestHash !== record.requestHash || value.correlationTag !== record.correlationTag
  ) return null;
  return Object.freeze({
    kind: 'version', phase: record.phase, accountId: record.accountId, workerName: record.workerName,
    workerId: record.workerId, versionId: value.versionId, requestHash: record.requestHash,
    correlationTag: record.correlationTag,
    ...(record.phase === 'provision' ? {} : { namespaceId: value.namespaceId as string }),
  });
}

function parseDeploymentLocator(value: unknown, record: WorkerDeploymentCreateRecord): WorkerDeploymentLocator | null {
  if (!isRecord(value) || !exactKeys(value, [
    'kind', 'phase', 'accountId', 'workerName', 'workerId', 'versionId', 'deploymentId', 'requestHash', 'correlationTag',
  ])) return null;
  if (
    value.kind !== 'deployment' || value.phase !== record.phase || value.accountId !== record.accountId ||
    value.workerName !== record.workerName || value.workerId !== record.workerId || value.versionId !== record.versionId ||
    typeof value.deploymentId !== 'string' || !UUID.test(value.deploymentId) ||
    value.requestHash !== record.requestHash || value.correlationTag !== record.correlationTag
  ) return null;
  return Object.freeze({
    kind: 'deployment', phase: record.phase, accountId: record.accountId, workerName: record.workerName,
    workerId: record.workerId, versionId: record.versionId, deploymentId: value.deploymentId,
    requestHash: record.requestHash, correlationTag: record.correlationTag,
  });
}

function parseSubdomainLocator(value: unknown, record: BootstrapSubdomainRecord): BootstrapSubdomainLocator | null {
  if (!isRecord(value) || !exactKeys(value, ['enabled', 'previewsEnabled'])) return null;
  if (value.enabled !== record.enabled || value.previewsEnabled !== false) return null;
  return Object.freeze({ enabled: record.enabled, previewsEnabled: false });
}

async function parseBootstrapLocator(
  value: unknown,
  record: Omit<CustomerBootstrapSubmitRecord, 'attempts'>,
  journal: InstallJournal,
): Promise<CustomerBootstrapLocator | null> {
  if (!isRecord(value)) return null;
  if (value.status === 'recovery_required') {
    if (
      !exactKeys(value, ['schemaVersion', 'status', 'reason', 'canRetry']) || value.schemaVersion !== 1 ||
      !['bootstrap_recovery_required', 'bootstrap_requires_repair', 'bootstrap_request_mismatch'].includes(String(value.reason)) ||
      value.canRetry !== false
    ) return null;
    const reason = value.reason as
      | 'bootstrap_recovery_required'
      | 'bootstrap_requires_repair'
      | 'bootstrap_request_mismatch';
    return Object.freeze({
      schemaVersion: 1,
      status: 'recovery_required',
      reason,
      canRetry: false,
    });
  }
  if (!exactKeys(value, [
    'schemaVersion', 'status', 'installationId', 'approvedPlanId', 'configurationHash', 'desiredHash',
    'settingsRevision', 'release', 'gateway', 'receipt', 'applyInvoked', 'resumed',
  ])) return null;
  if (
    value.schemaVersion !== 1 || value.status !== 'ready' || value.installationId !== journal.installationId ||
    typeof value.approvedPlanId !== 'string' || !CUSTOMER_PLAN_ID.test(value.approvedPlanId) ||
    value.configurationHash !== record.configurationHash || value.desiredHash !== record.desiredHash ||
    value.settingsRevision !== 1 || !isRecord(value.release) || !exactKeys(value.release, ['id', 'artifactSha256']) ||
    value.release.id !== journal.releasePin.release ||
    value.release.artifactSha256 !== `sha256:${journal.releasePin.artifactSha256}` ||
    !isRecord(value.gateway) || !exactKeys(value.gateway, ['hostname', 'mcpUrl']) ||
    value.gateway.hostname !== journal.selection.basics.portalHostname ||
    value.gateway.mcpUrl !== `https://${journal.selection.basics.portalHostname}/mcp` ||
    !isRecord(value.receipt) || !exactKeys(value.receipt, ['revision', 'resourceCount', 'evidence']) ||
    !safeInteger(value.receipt.revision) ||
    value.receipt.resourceCount !== journal.plan.gatewayResources.length ||
    typeof value.applyInvoked !== 'boolean' || typeof value.resumed !== 'boolean'
  ) return null;
  let expectation: Awaited<ReturnType<typeof deriveCustomerGatewayInstallationReceiptExpectation>>;
  try {
    expectation = await deriveCustomerGatewayInstallationReceiptExpectation({
      selection: journal.selection,
      target: journal.target,
      plan: journal.plan,
      release: {
        id: journal.releasePin.release,
        artifactSha256: journal.releasePin.artifactSha256,
      },
    });
  } catch {
    return null;
  }
  const evidence = await parseReadyInstallationReceipt(value.receipt.evidence, expectation);
  if (!evidence || evidence.revision !== value.receipt.revision) return null;
  return Object.freeze({
    schemaVersion: 1,
    status: 'ready',
    installationId: journal.installationId,
    approvedPlanId: value.approvedPlanId,
    configurationHash: record.configurationHash,
    desiredHash: record.desiredHash,
    settingsRevision: 1,
    release: Object.freeze({
      id: journal.releasePin.release,
      artifactSha256: `sha256:${journal.releasePin.artifactSha256}`,
    }),
    gateway: Object.freeze({ hostname: value.gateway.hostname as string, mcpUrl: value.gateway.mcpUrl as string }),
    receipt: Object.freeze({
      revision: value.receipt.revision,
      resourceCount: journal.plan.gatewayResources.length as 4 | 7,
      evidence,
    }),
    applyInvoked: value.applyInvoked,
    resumed: value.resumed,
  });
}

function parseDomainLocator(value: unknown): ManagementCustomDomainLocator | null {
  // Worker custom-domain ids are 40 lowercase hex characters (live 2026-08-23).
  const CUSTOM_DOMAIN_ID = /^[a-f0-9]{40}$/u;
  if (
    !isRecord(value) || !exactKeys(value, ['domainId']) || typeof value.domainId !== 'string' ||
    !(PROVIDER_ID.test(value.domainId) || CUSTOM_DOMAIN_ID.test(value.domainId))
  ) return null;
  return Object.freeze({ domainId: value.domainId });
}

async function parseFinalLocator(value: unknown, record: FinalConvergenceRecord, journal: InstallJournal): Promise<FinalConvergenceLocator | null> {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'status', 'convergenceHash', 'installationId', 'bindingHash', 'workerId',
    'managementApplicationId', 'managementAccessAud', 'managementPolicyId', 'bootstrapVersionId',
    'bootstrapDeploymentId', 'cleanVersionId', 'cleanDeploymentId', 'managementDomainId',
    'customerApprovedPlanId', 'customerReceiptRevision', 'customerReceiptEvidence',
    'adminStateNamespaceId', 'workersDevEnabled',
  ])) return null;
  const projection = finalProjection(journal);
  const expectedHash = await expectedConvergenceHash(journal);
  if (
    !projection || value.schemaVersion !== 1 || value.status !== 'converged' ||
    value.convergenceHash !== record.convergenceHash || value.convergenceHash !== expectedHash
  ) return null;
  const expected = projection ? {
    schemaVersion: 1,
    status: 'converged',
    convergenceHash: expectedHash,
    ...projection,
  } : null;
  if (!expected || !exactJson(value, expected)) return null;
  return Object.freeze(expected) as FinalConvergenceLocator;
}

async function parseActionLocator(
  name: InstallActionName,
  value: unknown,
  record: InstallActionRecord,
  journal: InstallJournal,
): Promise<InstallActionLocator | null> {
  if (forbiddenJournalShape(value)) return null;
  if (name === 'gateway_fresh_preflight' && record.kind === 'customer_gateway_fresh_preflight') {
    return parseFreshPreflightLocator(value, record);
  }
  if (name === 'worker_create' && record.kind === 'worker_create') return parseWorkerLocator(value, record);
  if (name === 'management_access_application_create') return parseApplicationLocator(value);
  if (name === 'management_admin_policy_create') return parsePolicyLocator(value);
  if ((
    name === 'provision_worker_version_create' || name === 'bootstrap_worker_version_create' ||
    name === 'clean_worker_version_create'
  ) && record.kind === 'worker_version_create') {
    return parseVersionLocator(value, record);
  }
  if ((
    name === 'provision_worker_deployment_create' || name === 'bootstrap_worker_deployment_create' ||
    name === 'clean_worker_deployment_create'
  ) && record.kind === 'worker_deployment_create') {
    return parseDeploymentLocator(value, record);
  }
  if ((name === 'bootstrap_subdomain_enable' || name === 'bootstrap_subdomain_disable') && record.kind === 'bootstrap_subdomain') {
    return parseSubdomainLocator(value, record);
  }
  if (name === 'customer_bootstrap_submit' && record.kind === 'customer_bootstrap_submit') return null;
  if (name === 'management_custom_domain_attach') return parseDomainLocator(value);
  if (name === 'final_convergence' && record.kind === 'final_convergence') return parseFinalLocator(value, record, journal);
  return null;
}

function actionPrerequisites(journal: Pick<InstallJournal, 'actions'>, name: InstallActionName): boolean {
  const index = INSTALL_ACTION_ORDER.indexOf(name);
  if (index < 0 || journal.actions.length !== index) return false;
  if (name === 'gateway_fresh_preflight') return true;
  if (name === 'worker_create') return actionByName(journal, 'gateway_fresh_preflight')?.phase === 'verified';
  if (name === 'bootstrap_subdomain_disable') {
    const enabled = actionByName(journal, 'bootstrap_subdomain_enable');
    const bootstrap = actionByName(journal, 'customer_bootstrap_submit');
    const first = bootstrap?.record.kind === 'customer_bootstrap_submit'
      ? bootstrap.record.attempts[0]
      : null;
    return enabled?.phase === 'verified' && first?.enable.phase === 'verified';
  }
  if (name === 'clean_worker_version_create') {
    const bootstrap = actionByName(journal, 'customer_bootstrap_submit');
    const latest = bootstrap?.record.kind === 'customer_bootstrap_submit'
      ? bootstrap.record.attempts[bootstrap.record.attempts.length - 1]
      : null;
    return bootstrap?.phase === 'verified' && latest?.disable?.phase === 'verified' &&
      actionByName(journal, 'bootstrap_subdomain_disable')?.phase === 'verified';
  }
  return journal.actions.slice(0, index).every((action) => action.phase === 'verified');
}

function transitionPrerequisites(journal: InstallJournal, name: InstallActionName): boolean {
  const index = INSTALL_ACTION_ORDER.indexOf(name);
  if (index < 0 || journal.actions[index]?.name !== name) return false;
  if (name === 'bootstrap_subdomain_disable') {
    const enabled = actionByName(journal, 'bootstrap_subdomain_enable');
    const bootstrap = actionByName(journal, 'customer_bootstrap_submit');
    const latest = bootstrap?.record.kind === 'customer_bootstrap_submit'
      ? bootstrap.record.attempts[bootstrap.record.attempts.length - 1]
      : null;
    return enabled?.phase === 'verified' && latest?.enable.phase === 'verified' && latest.disable !== null;
  }
  if (name === 'clean_worker_version_create') {
    const bootstrap = actionByName(journal, 'customer_bootstrap_submit');
    const latest = bootstrap?.record.kind === 'customer_bootstrap_submit'
      ? bootstrap.record.attempts[bootstrap.record.attempts.length - 1]
      : null;
    return bootstrap?.phase === 'verified' && latest?.disable?.phase === 'verified' &&
      actionByName(journal, 'bootstrap_subdomain_disable')?.phase === 'verified';
  }
  return journal.actions.slice(0, index).every((action) => action.phase === 'verified');
}

function bootstrapActionSummary(record: CustomerBootstrapSubmitRecord): {
  readonly phase: InstallActionPhase;
  readonly locator: CustomerBootstrapLocator | null;
  readonly preparedAt: number;
  readonly sendArmedAt: number | null;
  readonly submittedAt: number | null;
  readonly verifiedAt: number | null;
} {
  const first = record.attempts[0];
  const last = record.attempts[record.attempts.length - 1];
  if (!first || !last) invalid();
  const anyArmed = record.attempts.some((attempt) => attempt.phase !== 'prepared');
  const phase: InstallActionPhase = last.phase === 'verified'
    ? 'verified'
    : last.phase === 'submitted'
      ? 'submitted'
      : anyArmed
        ? 'send_armed'
        : 'prepared';
  return Object.freeze({
    phase,
    locator: phase === 'submitted' || phase === 'verified' ? last.locator : null,
    preparedAt: first.preparedAt,
    sendArmedAt: anyArmed
      ? record.attempts.find((attempt) => attempt.sendArmedAt !== null)?.sendArmedAt ?? null
      : null,
    submittedAt: phase === 'submitted' || phase === 'verified' ? last.submittedAt : null,
    verifiedAt: phase === 'verified' ? last.verifiedAt : null,
  });
}

function parseLease(value: unknown, recoverUntil: number): InstallJournalLease | null | undefined {
  if (value === null) return null;
  if (!isRecord(value) || !exactKeys(value, ['attemptId', 'acquiredAt', 'expiresAt'])) return undefined;
  if (
    typeof value.attemptId !== 'string' || !ATTEMPT_ID.test(value.attemptId) ||
    !safeInteger(value.acquiredAt) || !safeInteger(value.expiresAt) || value.expiresAt <= value.acquiredAt ||
    value.expiresAt - value.acquiredAt > MAX_INSTALL_LEASE_MS || value.expiresAt > recoverUntil
  ) return undefined;
  return Object.freeze({ attemptId: value.attemptId, acquiredAt: value.acquiredAt, expiresAt: value.expiresAt });
}

function parseApprovalHistory(
  value: unknown,
  plan: StaticDeployPlan,
  createdAt: number,
  updatedAt: number,
  recoverUntil: number,
): readonly InstallJournalApproval[] | null {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_APPROVALS) return null;
  const approvals: InstallJournalApproval[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const entry = value[index];
    if (!isRecord(entry) || !exactKeys(entry, [
      'schemaVersion', 'attemptId', 'approvedAt', 'recordedAt', 'planId', 'planHash',
      'planExpiresAt', 'managementOwnershipMarker',
    ])) return null;
    const previous = approvals[index - 1];
    if (
      entry.schemaVersion !== 1 || typeof entry.attemptId !== 'string' || !ATTEMPT_ID.test(entry.attemptId) ||
      approvals.some((approval) => approval.attemptId === entry.attemptId) ||
      !safeInteger(entry.approvedAt) || !safeInteger(entry.recordedAt) || entry.approvedAt > entry.recordedAt ||
      entry.recordedAt > updatedAt || (index === 0 ? entry.recordedAt !== createdAt : entry.recordedAt < previous.recordedAt) ||
      entry.planId !== plan.planId || entry.planHash !== plan.planHash ||
      entry.managementOwnershipMarker !== plan.managementOwnershipMarker ||
      !safeInteger(entry.planExpiresAt) || entry.planExpiresAt <= entry.approvedAt || entry.planExpiresAt > recoverUntil ||
      (index === 0 ? entry.planExpiresAt !== plan.expiresAt : entry.planExpiresAt <= previous.planExpiresAt)
    ) return null;
    approvals.push(Object.freeze({
      schemaVersion: 1,
      attemptId: entry.attemptId,
      approvedAt: entry.approvedAt,
      recordedAt: entry.recordedAt,
      planId: plan.planId,
      planHash: plan.planHash,
      planExpiresAt: entry.planExpiresAt,
      managementOwnershipMarker: plan.managementOwnershipMarker,
    }));
  }
  return Object.freeze(approvals);
}

async function parseJournal(value: unknown): Promise<InstallJournal | null> {
  if (forbiddenJournalShape(value)) return null;
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'revision', 'createdAt', 'updatedAt', 'sessionExpiresAt', 'recoverUntil', 'selection', 'plan',
    'releasePin', 'target', 'installationId', 'bindingHash', 'approvalHistory', 'lease', 'leaseAttemptIds', 'actions',
  ])) return null;
  if (
    value.schemaVersion !== 1 || !safeInteger(value.revision) || !safeInteger(value.createdAt) ||
    !safeInteger(value.updatedAt) || !safeInteger(value.sessionExpiresAt) || !safeInteger(value.recoverUntil) ||
    value.updatedAt < value.createdAt || value.updatedAt > value.recoverUntil ||
    value.sessionExpiresAt <= value.createdAt || value.recoverUntil <= value.sessionExpiresAt ||
    value.recoverUntil > value.sessionExpiresAt + MAX_INSTALL_RECOVERY_RETENTION_MS
  ) return null;
  let selection: DeploySelection;
  let plan: StaticDeployPlan;
  try {
    selection = parseDeploySelection(value.selection);
    plan = parseStaticDeployPlan(value.plan);
  } catch {
    return null;
  }
  const pin = releasePin(value.releasePin);
  const target = authorizedTarget(value.target, selection);
  if (
    !pin || !target || pin.release !== plan.releaseId || pin.artifactSha256 !== plan.releaseArtifactSha256 ||
    typeof value.installationId !== 'string' || !INSTALLATION_ID.test(value.installationId) ||
    value.installationId !== await stableInstallationId(selection, target) ||
    typeof value.bindingHash !== 'string' || !PREFIXED_SHA256.test(value.bindingHash)
  ) return null;
  const expectedBinding = await computeInstallJournalBindingHash({
    selection, plan, releasePin: pin, target, installationId: value.installationId,
  });
  if (value.bindingHash !== expectedBinding) return null;
  const approvals = parseApprovalHistory(
    value.approvalHistory,
    plan,
    value.createdAt,
    value.updatedAt,
    value.recoverUntil,
  );
  if (!approvals) return null;
  const lease = parseLease(value.lease, value.recoverUntil);
  if (lease === undefined || !Array.isArray(value.leaseAttemptIds) || value.leaseAttemptIds.length > MAX_LEASE_ATTEMPTS) return null;
  const attempts: string[] = [];
  for (const attempt of value.leaseAttemptIds) {
    if (typeof attempt !== 'string' || !ATTEMPT_ID.test(attempt) || attempts.includes(attempt)) return null;
    attempts.push(attempt);
  }
  if (lease && !attempts.includes(lease.attemptId)) return null;
  if (!Array.isArray(value.actions) || value.actions.length > INSTALL_ACTION_ORDER.length) return null;
  const partial: InstallJournal = {
    schemaVersion: 1,
    revision: value.revision,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
    sessionExpiresAt: value.sessionExpiresAt,
    recoverUntil: value.recoverUntil,
    selection,
    plan,
    releasePin: pin,
    target,
    installationId: value.installationId,
    bindingHash: value.bindingHash,
    approvalHistory: approvals,
    lease,
    leaseAttemptIds: Object.freeze(attempts),
    actions: Object.freeze([]),
  };
  const actions: InstallJournalAction[] = [];
  let lastPreparedAt = value.createdAt;
  for (let index = 0; index < value.actions.length; index += 1) {
    const input = value.actions[index];
    if (!isRecord(input) || !exactKeys(input, [
      'name', 'phase', 'record', 'locator', 'preparedAt', 'sendArmedAt', 'submittedAt', 'verifiedAt',
    ])) return null;
    const name = INSTALL_ACTION_ORDER[index];
    if (input.name !== name || !['prepared', 'send_armed', 'submitted', 'verified'].includes(String(input.phase))) return null;
    const context = { ...partial, actions: Object.freeze([...actions]) } as InstallJournal;
    if (!actionPrerequisites(context, name)) return null;
    const record = await parseActionRecord(name, input.record, context);
    if (!record || !safeInteger(input.preparedAt) || input.preparedAt < lastPreparedAt || input.preparedAt > value.updatedAt) return null;
    if (
      name === 'gateway_fresh_preflight' && (
        record.kind !== 'customer_gateway_fresh_preflight' || input.phase !== 'verified' ||
        input.preparedAt !== value.createdAt || input.sendArmedAt !== value.createdAt ||
        input.submittedAt !== value.createdAt || input.verifiedAt !== value.createdAt
      )
    ) return null;
    if (name === 'customer_bootstrap_submit' && record.kind === 'customer_bootstrap_submit') {
      const summary = bootstrapActionSummary(record);
      if (
        input.phase !== summary.phase || input.preparedAt !== summary.preparedAt ||
        input.sendArmedAt !== summary.sendArmedAt || input.submittedAt !== summary.submittedAt ||
        input.verifiedAt !== summary.verifiedAt || !exactJson(input.locator, summary.locator)
      ) return null;
      actions.push(Object.freeze({ name, record, ...summary }));
      lastPreparedAt = input.preparedAt;
      continue;
    }
    const phase = input.phase as InstallActionPhase;
    const armedRequired = phase !== 'prepared';
    const submittedRequired = phase === 'submitted' || phase === 'verified';
    const verifiedRequired = phase === 'verified';
    if (
      (armedRequired !== safeInteger(input.sendArmedAt)) ||
      (submittedRequired !== safeInteger(input.submittedAt)) ||
      (verifiedRequired !== safeInteger(input.verifiedAt)) ||
      (armedRequired && (input.sendArmedAt as number) < input.preparedAt) ||
      (submittedRequired && (input.submittedAt as number) < (input.sendArmedAt as number)) ||
      (verifiedRequired && (input.verifiedAt as number) < (input.submittedAt as number)) ||
      [input.sendArmedAt, input.submittedAt, input.verifiedAt].some(
        (time) => typeof time === 'number' && time > (value.updatedAt as number),
      )
    ) return null;
    let locator: InstallActionLocator | null = null;
    if (submittedRequired) {
      locator = await parseActionLocator(name, input.locator, record, context);
      if (!locator || (verifiedRequired && name === 'customer_bootstrap_submit' && 'status' in locator && locator.status !== 'ready')) {
        return null;
      }
    } else if (input.locator !== null) return null;
    const action = Object.freeze({
      name,
      phase,
      record,
      locator,
      preparedAt: input.preparedAt,
      sendArmedAt: armedRequired ? input.sendArmedAt as number : null,
      submittedAt: submittedRequired ? input.submittedAt as number : null,
      verifiedAt: verifiedRequired ? input.verifiedAt as number : null,
    });
    actions.push(action);
    lastPreparedAt = input.preparedAt;
  }
  const bootstrap = actions[INSTALL_ACTION_ORDER.indexOf('customer_bootstrap_submit')];
  const topDisable = actions[INSTALL_ACTION_ORDER.indexOf('bootstrap_subdomain_disable')];
  if (bootstrap?.record.kind === 'customer_bootstrap_submit') {
    const firstDisable = bootstrap.record.attempts[0]?.disable ?? null;
    if (!topDisable) {
      if (firstDisable !== null) return null;
    } else {
      if (topDisable.record.kind !== 'bootstrap_subdomain' || topDisable.record.enabled !== false || !firstDisable) {
        return null;
      }
      const mirrored: CustomerBootstrapCycleSubdomainMutation = {
        schemaVersion: 1,
        approvalAttemptId: firstDisable.approvalAttemptId,
        enabled: false,
        requestHash: topDisable.record.requestHash,
        phase: topDisable.phase,
        locator: topDisable.locator && 'previewsEnabled' in topDisable.locator
          ? topDisable.locator
          : null,
        preparedAt: topDisable.preparedAt,
        sendArmedAt: topDisable.sendArmedAt,
        submittedAt: topDisable.submittedAt,
        verifiedAt: topDisable.verifiedAt,
      };
      if (!exactJson(firstDisable, mirrored)) return null;
    }
  } else if (topDisable) return null;
  const parsed = Object.freeze({ ...partial, actions: Object.freeze(actions) });
  try {
    assertSecretFree(parsed);
  } catch {
    return null;
  }
  return parsed;
}

export async function requireInstallJournal(value: unknown): Promise<InstallJournal> {
  const parsed = await parseJournal(value);
  if (!parsed) invalid();
  return parsed;
}

export async function createInstallJournal(
  value: unknown,
  sessionSelection: DeploySelection,
  sessionPlan: StaticDeployPlan,
  sessionExpiresAt: number,
  approval: { readonly attemptId: string; readonly approvedAt: number },
): Promise<InstallJournal> {
  if (forbiddenJournalShape(value) || !isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'now', 'recoverUntil', 'selection', 'plan', 'releasePin', 'target', 'installationId', 'bindingHash',
    'gatewayFreshPreflight',
  ])) invalid(400);
  let selection: DeploySelection;
  let plan: StaticDeployPlan;
  try {
    selection = parseDeploySelection(value.selection);
    plan = parseStaticDeployPlan(value.plan);
  } catch {
    invalid(400);
  }
  const pin = releasePin(value.releasePin);
  const target = authorizedTarget(value.target, selection);
  if (
    value.schemaVersion !== 1 || !safeInteger(value.now) || value.now >= sessionExpiresAt || value.now >= plan.expiresAt ||
    typeof approval.attemptId !== 'string' || !ATTEMPT_ID.test(approval.attemptId) ||
    !safeInteger(approval.approvedAt) || approval.approvedAt > value.now || approval.approvedAt >= plan.expiresAt ||
    !safeInteger(value.recoverUntil) || value.recoverUntil <= sessionExpiresAt ||
    value.recoverUntil > sessionExpiresAt + MAX_INSTALL_RECOVERY_RETENTION_MS ||
    !exactJson(selection, sessionSelection) || !exactJson(plan, sessionPlan) || !pin || !target ||
    pin.release !== plan.releaseId || pin.artifactSha256 !== plan.releaseArtifactSha256 ||
    typeof value.installationId !== 'string' || !INSTALLATION_ID.test(value.installationId) ||
    value.installationId !== await stableInstallationId(selection, target) ||
    typeof value.bindingHash !== 'string' || !PREFIXED_SHA256.test(value.bindingHash)
  ) invalid(400);
  const expectedBinding = await computeInstallJournalBindingHash({
    selection, plan, releasePin: pin, target, installationId: value.installationId,
  });
  if (value.bindingHash !== expectedBinding) invalid(400);
  const base: InstallJournal = {
    schemaVersion: 1,
    revision: 0,
    createdAt: value.now,
    updatedAt: value.now,
    sessionExpiresAt,
    recoverUntil: value.recoverUntil,
    selection,
    plan,
    releasePin: pin,
    target,
    installationId: value.installationId,
    bindingHash: value.bindingHash,
    approvalHistory: Object.freeze([Object.freeze({
      schemaVersion: 1,
      attemptId: approval.attemptId,
      approvedAt: approval.approvedAt,
      recordedAt: value.now,
      planId: plan.planId,
      planHash: plan.planHash,
      planExpiresAt: plan.expiresAt,
      managementOwnershipMarker: plan.managementOwnershipMarker,
    })]),
    lease: null,
    leaseAttemptIds: Object.freeze([]),
    actions: Object.freeze([]),
  };
  const preflight = await parseFreshPreflightRecord(value.gatewayFreshPreflight, base);
  if (!preflight) invalid(400);
  const action: InstallJournalAction = Object.freeze({
    name: 'gateway_fresh_preflight',
    phase: 'verified',
    record: preflight,
    locator: Object.freeze({ attestationHash: preflight.attestationHash }),
    preparedAt: value.now,
    sendArmedAt: value.now,
    submittedAt: value.now,
    verifiedAt: value.now,
  });
  const journal = Object.freeze({ ...base, actions: Object.freeze([action]) });
  try {
    assertSecretFree(journal);
  } catch {
    invalid(400);
  }
  return journal;
}

function revisionCas(journal: InstallJournal, input: InstallJournalCasInput): void {
  if (
    !safeInteger(input.expectedRevision) || input.expectedRevision !== journal.revision ||
    typeof input.attemptId !== 'string' || !ATTEMPT_ID.test(input.attemptId) ||
    !safeInteger(input.now) || input.now < journal.updatedAt || input.now >= journal.recoverUntil
  ) conflict();
}

function cas(journal: InstallJournal, input: InstallJournalCasInput, requireLease: boolean): void {
  revisionCas(journal, input);
  const approval = journal.approvalHistory.find((entry) => entry.attemptId === input.attemptId);
  if (!approval || input.now < approval.approvedAt || input.now >= approval.planExpiresAt) conflict();
  if (
    requireLease &&
    (!journal.lease || journal.lease.attemptId !== input.attemptId || input.now >= journal.lease.expiresAt)
  ) conflict();
}

export function appendInstallJournalApproval(
  journal: InstallJournal,
  plan: StaticDeployPlan,
  input: AppendInstallJournalApprovalInput,
): InstallJournal {
  revisionCas(journal, input);
  let parsedPlan: StaticDeployPlan;
  try {
    parsedPlan = parseStaticDeployPlan(plan);
  } catch {
    conflict();
  }
  const previous = activeApproval(journal);
  if (
    !isRecoveryEquivalentInstallPlan(journal.plan, parsedPlan) ||
    journal.lease !== null ||
    journal.approvalHistory.length >= MAX_APPROVALS ||
    journal.approvalHistory.some((entry) => entry.attemptId === input.attemptId) ||
    journal.leaseAttemptIds.includes(input.attemptId) ||
    !safeInteger(input.approvedAt) || input.approvedAt > input.now || input.approvedAt < previous.recordedAt ||
    parsedPlan.expiresAt <= input.now || parsedPlan.expiresAt <= previous.planExpiresAt ||
    parsedPlan.expiresAt > journal.recoverUntil
  ) conflict();
  const nextApproval: InstallJournalApproval = Object.freeze({
    schemaVersion: 1,
    attemptId: input.attemptId,
    approvedAt: input.approvedAt,
    recordedAt: input.now,
    planId: journal.plan.planId,
    planHash: journal.plan.planHash,
    planExpiresAt: parsedPlan.expiresAt,
    managementOwnershipMarker: journal.plan.managementOwnershipMarker,
  });
  return Object.freeze({
    ...journal,
    revision: journal.revision + 1,
    updatedAt: input.now,
    approvalHistory: Object.freeze([...journal.approvalHistory, nextApproval]),
  });
}

export function acquireInstallJournalLease(
  journal: InstallJournal,
  input: AcquireInstallJournalLeaseInput,
): InstallJournal {
  cas(journal, input, false);
  const approval = journal.approvalHistory.find((entry) => entry.attemptId === input.attemptId);
  if (
    !approval || !safeInteger(input.leaseExpiresAt) || input.leaseExpiresAt <= input.now ||
    input.leaseExpiresAt > input.now + MAX_INSTALL_LEASE_MS || input.leaseExpiresAt > journal.recoverUntil ||
    input.leaseExpiresAt > approval.planExpiresAt ||
    journal.leaseAttemptIds.includes(input.attemptId) ||
    journal.leaseAttemptIds.length >= MAX_LEASE_ATTEMPTS ||
    (journal.lease !== null && input.now < journal.lease.expiresAt)
  ) conflict();
  return Object.freeze({
    ...journal,
    revision: journal.revision + 1,
    updatedAt: input.now,
    lease: Object.freeze({ attemptId: input.attemptId, acquiredAt: input.now, expiresAt: input.leaseExpiresAt }),
    leaseAttemptIds: Object.freeze([...journal.leaseAttemptIds, input.attemptId]),
  });
}

export function releaseInstallJournalLease(
  journal: InstallJournal,
  input: InstallJournalCasInput,
): InstallJournal {
  cas(journal, input, true);
  return Object.freeze({
    ...journal,
    revision: journal.revision + 1,
    updatedAt: input.now,
    lease: null,
  });
}

export function expireInstallJournalLease(journal: InstallJournal, now: number): InstallJournal {
  if (!safeInteger(now) || !journal.lease || now < journal.lease.expiresAt) return journal;
  return Object.freeze({
    ...journal,
    revision: journal.revision + 1,
    updatedAt: Math.min(Math.max(journal.updatedAt, now), journal.recoverUntil),
    lease: null,
  });
}

export async function prepareInstallJournalAction(
  journal: InstallJournal,
  input: PrepareInstallJournalActionInput,
): Promise<InstallJournal> {
  cas(journal, input, true);
  if (input.action === 'bootstrap_subdomain_disable') {
    const existingDisable = actionByName(journal, 'bootstrap_subdomain_disable');
    const bootstrapIndex = INSTALL_ACTION_ORDER.indexOf('customer_bootstrap_submit');
    const bootstrap = journal.actions[bootstrapIndex];
    const bootstrapRecord = bootstrap?.record.kind === 'customer_bootstrap_submit' ? bootstrap.record : null;
    const attempts = bootstrapRecord
      ? [...bootstrapRecord.attempts]
      : [];
    const attempt = attempts[attempts.length - 1];
    if (
      bootstrapRecord && existingDisable?.phase === 'verified' && attempts.length > 1 && attempt &&
      attempt.enable.phase === 'verified' && attempt.disable === null
    ) {
      const parsed = await parseActionRecord(input.action, input.record, journal);
      if (parsed?.kind !== 'bootstrap_subdomain' || parsed.enabled !== false) invalid(400);
      attempts[attempts.length - 1] = Object.freeze({
        ...attempt,
        disable: Object.freeze({
          schemaVersion: 1,
          approvalAttemptId: input.attemptId,
          enabled: false,
          requestHash: parsed.requestHash,
          phase: 'prepared',
          locator: null,
          preparedAt: input.now,
          sendArmedAt: null,
          submittedAt: null,
          verifiedAt: null,
        }),
      });
      const record = Object.freeze({ ...bootstrapRecord, attempts: Object.freeze(attempts) });
      return replaceAction(journal, bootstrapIndex, {
        name: bootstrap.name,
        record,
        ...bootstrapActionSummary(record),
      }, input.now);
    }
  }
  if (!INSTALL_ACTION_ORDER.includes(input.action) || !actionPrerequisites(journal, input.action)) conflict();
  const recordContext = input.action === 'customer_bootstrap_submit'
    ? { ...journal, updatedAt: input.now } as InstallJournal
    : journal;
  const record = await parseActionRecord(input.action, input.record, recordContext);
  if (!record) invalid(400);
  if (input.action === 'customer_bootstrap_submit' && record.kind === 'customer_bootstrap_submit') {
    const summary = bootstrapActionSummary(record);
    if (
      record.attempts.length !== 1 || summary.phase !== 'prepared' || summary.preparedAt !== input.now ||
      record.attempts[0].approvalAttemptId !== input.attemptId
    ) invalid(400);
    return Object.freeze({
      ...journal,
      revision: journal.revision + 1,
      updatedAt: input.now,
      actions: Object.freeze([...journal.actions, Object.freeze({ name: input.action, record, ...summary })]),
    });
  }
  const action: InstallJournalAction = Object.freeze({
    name: input.action,
    phase: 'prepared',
    record,
    locator: null,
    preparedAt: input.now,
    sendArmedAt: null,
    submittedAt: null,
    verifiedAt: null,
  });
  if (input.action === 'bootstrap_subdomain_disable' && record.kind === 'bootstrap_subdomain') {
    const bootstrapIndex = INSTALL_ACTION_ORDER.indexOf('customer_bootstrap_submit');
    const bootstrap = journal.actions[bootstrapIndex];
    if (bootstrap?.record.kind !== 'customer_bootstrap_submit') conflict();
    const attempts = [...bootstrap.record.attempts];
    const attempt = attempts[attempts.length - 1];
    if (!attempt || attempt.disable !== null || attempt.enable.phase !== 'verified') conflict();
    attempts[attempts.length - 1] = Object.freeze({
      ...attempt,
      disable: Object.freeze({
        schemaVersion: 1,
        approvalAttemptId: input.attemptId,
        enabled: false,
        requestHash: record.requestHash,
        phase: 'prepared',
        locator: null,
        preparedAt: input.now,
        sendArmedAt: null,
        submittedAt: null,
        verifiedAt: null,
      }),
    });
    const bootstrapRecord = Object.freeze({ ...bootstrap.record, attempts: Object.freeze(attempts) });
    const actions = [...journal.actions];
    actions[bootstrapIndex] = Object.freeze({
      name: bootstrap.name,
      record: bootstrapRecord,
      ...bootstrapActionSummary(bootstrapRecord),
    });
    actions.push(action);
    return Object.freeze({
      ...journal,
      revision: journal.revision + 1,
      updatedAt: input.now,
      actions: Object.freeze(actions),
    });
  }
  return Object.freeze({
    ...journal,
    revision: journal.revision + 1,
    updatedAt: input.now,
    actions: Object.freeze([...journal.actions, action]),
  });
}

function replaceAction(journal: InstallJournal, index: number, action: InstallJournalAction, now: number): InstallJournal {
  const actions = [...journal.actions];
  actions[index] = Object.freeze(action);
  return Object.freeze({
    ...journal,
    revision: journal.revision + 1,
    updatedAt: now,
    actions: Object.freeze(actions),
  });
}

export function armInstallJournalAction(
  journal: InstallJournal,
  input: TransitionInstallJournalActionInput,
): InstallJournal {
  cas(journal, input, true);
  const index = INSTALL_ACTION_ORDER.indexOf(input.action);
  const action = journal.actions[index];
  if (input.action === 'worker_create') {
    const preflight = actionByName(journal, 'gateway_fresh_preflight');
    if (
      preflight?.phase !== 'verified' || preflight.record.kind !== 'customer_gateway_fresh_preflight' ||
      input.now >= preflight.record.expiresAt
    ) conflict();
  }
  if (input.action === 'bootstrap_subdomain_enable') {
    const bootstrapIndex = INSTALL_ACTION_ORDER.indexOf('customer_bootstrap_submit');
    const bootstrap = journal.actions[bootstrapIndex];
    const bootstrapRecord = bootstrap?.record.kind === 'customer_bootstrap_submit' ? bootstrap.record : null;
    const attempts = bootstrapRecord
      ? [...bootstrapRecord.attempts]
      : [];
    const attempt = attempts[attempts.length - 1];
    // CAS authorizes the current recovery lease. The nested mutation remains pinned
    // to the approval that created it while that lease settles its journal phases.
    if (
      bootstrapRecord && attempts.length > 1 && attempt?.enable.phase === 'prepared'
    ) {
      attempts[attempts.length - 1] = Object.freeze({
        ...attempt,
        enable: Object.freeze({ ...attempt.enable, phase: 'send_armed', sendArmedAt: input.now }),
      });
      const record = Object.freeze({ ...bootstrapRecord, attempts: Object.freeze(attempts) });
      return replaceAction(journal, bootstrapIndex, {
        name: bootstrap.name,
        record,
        ...bootstrapActionSummary(record),
      }, input.now);
    }
  }
  if (input.action === 'bootstrap_subdomain_disable') {
    const bootstrapIndex = INSTALL_ACTION_ORDER.indexOf('customer_bootstrap_submit');
    const bootstrap = journal.actions[bootstrapIndex];
    const bootstrapRecord = bootstrap?.record.kind === 'customer_bootstrap_submit' ? bootstrap.record : null;
    const attempts = bootstrapRecord
      ? [...bootstrapRecord.attempts]
      : [];
    const attempt = attempts[attempts.length - 1];
    if (
      bootstrapRecord && attempt?.disable?.phase === 'prepared' &&
      attempt.disable.approvalAttemptId === input.attemptId
    ) {
      attempts[attempts.length - 1] = Object.freeze({
        ...attempt,
        disable: Object.freeze({ ...attempt.disable, phase: 'send_armed', sendArmedAt: input.now }),
      });
      const record = Object.freeze({ ...bootstrapRecord, attempts: Object.freeze(attempts) });
      const nextBootstrap = Object.freeze({
        name: bootstrap.name,
        record,
        ...bootstrapActionSummary(record),
      });
      if (attempts.length > 1) return replaceAction(journal, bootstrapIndex, nextBootstrap, input.now);
      if (!action || action.phase !== 'prepared') conflict();
      const actions = [...journal.actions];
      actions[bootstrapIndex] = nextBootstrap;
      actions[index] = Object.freeze({ ...action, phase: 'send_armed', sendArmedAt: input.now });
      return Object.freeze({
        ...journal,
        revision: journal.revision + 1,
        updatedAt: input.now,
        actions: Object.freeze(actions),
      });
    }
  }
  if (input.action === 'customer_bootstrap_submit' && action?.record.kind === 'customer_bootstrap_submit') {
    const attempts = [...action.record.attempts];
    const attempt = attempts[attempts.length - 1];
    if (
      !attempt || attempt.phase !== 'prepared' || attempt.enable.phase !== 'verified' ||
      attempt.approvalAttemptId !== input.attemptId ||
      !transitionPrerequisites(journal, input.action)
    ) conflict();
    attempts[attempts.length - 1] = Object.freeze({
      ...attempt,
      phase: 'send_armed',
      sendArmedAt: input.now,
    });
    const record = Object.freeze({ ...action.record, attempts: Object.freeze(attempts) });
    return replaceAction(journal, index, {
      name: action.name,
      record,
      ...bootstrapActionSummary(record),
    }, input.now);
  }
  if (!action || action.name !== input.action || action.phase !== 'prepared' || !transitionPrerequisites(journal, input.action)) {
    conflict();
  }
  return replaceAction(journal, index, {
    ...action,
    phase: 'send_armed',
    sendArmedAt: input.now,
  }, input.now);
}

export async function submitInstallJournalAction(
  journal: InstallJournal,
  input: SubmitInstallJournalActionInput,
): Promise<InstallJournal> {
  cas(journal, input, true);
  const index = INSTALL_ACTION_ORDER.indexOf(input.action);
  const action = journal.actions[index];
  if (input.action === 'bootstrap_subdomain_enable') {
    const bootstrapIndex = INSTALL_ACTION_ORDER.indexOf('customer_bootstrap_submit');
    const bootstrap = journal.actions[bootstrapIndex];
    const bootstrapRecord = bootstrap?.record.kind === 'customer_bootstrap_submit' ? bootstrap.record : null;
    const attempts = bootstrapRecord
      ? [...bootstrapRecord.attempts]
      : [];
    const attempt = attempts[attempts.length - 1];
    if (
      bootstrapRecord && attempts.length > 1 && attempt?.enable.phase === 'send_armed'
    ) {
      const locator = parseSubdomainLocator(input.locator, {
        schemaVersion: 1,
        kind: 'bootstrap_subdomain',
        accountId: journal.target.account.id,
        workerName: managementWorkerName(journal.plan) as string,
        enabled: true,
        requestHash: attempt.enable.requestHash,
      });
      if (!locator) invalid(400);
      attempts[attempts.length - 1] = Object.freeze({
        ...attempt,
        enable: Object.freeze({ ...attempt.enable, phase: 'submitted', locator, submittedAt: input.now }),
      });
      const record = Object.freeze({ ...bootstrapRecord, attempts: Object.freeze(attempts) });
      return replaceAction(journal, bootstrapIndex, {
        name: bootstrap.name,
        record,
        ...bootstrapActionSummary(record),
      }, input.now);
    }
  }
  if (input.action === 'bootstrap_subdomain_disable') {
    const bootstrapIndex = INSTALL_ACTION_ORDER.indexOf('customer_bootstrap_submit');
    const bootstrap = journal.actions[bootstrapIndex];
    const bootstrapRecord = bootstrap?.record.kind === 'customer_bootstrap_submit' ? bootstrap.record : null;
    const attempts = bootstrapRecord
      ? [...bootstrapRecord.attempts]
      : [];
    const attempt = attempts[attempts.length - 1];
    if (
      bootstrapRecord && attempt?.disable?.phase === 'send_armed' &&
      attempt.disable.approvalAttemptId === input.attemptId
    ) {
      const locator = parseSubdomainLocator(input.locator, {
        schemaVersion: 1,
        kind: 'bootstrap_subdomain',
        accountId: journal.target.account.id,
        workerName: managementWorkerName(journal.plan) as string,
        enabled: false,
        requestHash: attempt.disable.requestHash,
      });
      if (!locator) invalid(400);
      attempts[attempts.length - 1] = Object.freeze({
        ...attempt,
        disable: Object.freeze({ ...attempt.disable, phase: 'submitted', locator, submittedAt: input.now }),
      });
      const record = Object.freeze({ ...bootstrapRecord, attempts: Object.freeze(attempts) });
      const nextBootstrap = Object.freeze({
        name: bootstrap.name,
        record,
        ...bootstrapActionSummary(record),
      });
      if (attempts.length > 1) return replaceAction(journal, bootstrapIndex, nextBootstrap, input.now);
      if (!action || action.phase !== 'send_armed') conflict();
      const actions = [...journal.actions];
      actions[bootstrapIndex] = nextBootstrap;
      actions[index] = Object.freeze({ ...action, phase: 'submitted', locator, submittedAt: input.now });
      return Object.freeze({
        ...journal,
        revision: journal.revision + 1,
        updatedAt: input.now,
        actions: Object.freeze(actions),
      });
    }
  }
  if (input.action === 'customer_bootstrap_submit' && action?.record.kind === 'customer_bootstrap_submit') {
    const attempts = [...action.record.attempts];
    const attempt = attempts[attempts.length - 1];
    if (!attempt || attempt.phase !== 'send_armed' || attempt.approvalAttemptId !== input.attemptId) conflict();
    const { attempts: _attempts, ...semantic } = action.record;
    const locator = await parseBootstrapLocator(input.locator, semantic, journal);
    if (!locator) invalid(400);
    attempts[attempts.length - 1] = Object.freeze({
      ...attempt,
      phase: 'submitted',
      locator,
      submittedAt: input.now,
    });
    const record = Object.freeze({ ...action.record, attempts: Object.freeze(attempts) });
    return replaceAction(journal, index, {
      name: action.name,
      record,
      ...bootstrapActionSummary(record),
    }, input.now);
  }
  if (!action || action.name !== input.action || action.phase !== 'send_armed') conflict();
  const locator = await parseActionLocator(input.action, input.locator, action.record, journal);
  if (!locator) invalid(400);
  return replaceAction(journal, index, {
    ...action,
    phase: 'submitted',
    locator,
    submittedAt: input.now,
  }, input.now);
}

export function verifyInstallJournalAction(
  journal: InstallJournal,
  input: TransitionInstallJournalActionInput,
): InstallJournal {
  cas(journal, input, true);
  const index = INSTALL_ACTION_ORDER.indexOf(input.action);
  const action = journal.actions[index];
  if (input.action === 'bootstrap_subdomain_enable') {
    const bootstrapIndex = INSTALL_ACTION_ORDER.indexOf('customer_bootstrap_submit');
    const bootstrap = journal.actions[bootstrapIndex];
    const bootstrapRecord = bootstrap?.record.kind === 'customer_bootstrap_submit' ? bootstrap.record : null;
    const attempts = bootstrapRecord
      ? [...bootstrapRecord.attempts]
      : [];
    const attempt = attempts[attempts.length - 1];
    if (
      bootstrapRecord && attempts.length > 1 && attempt?.enable.phase === 'submitted' &&
      attempt.enable.locator?.enabled === true
    ) {
      attempts[attempts.length - 1] = Object.freeze({
        ...attempt,
        enable: Object.freeze({ ...attempt.enable, phase: 'verified', verifiedAt: input.now }),
      });
      const record = Object.freeze({ ...bootstrapRecord, attempts: Object.freeze(attempts) });
      return replaceAction(journal, bootstrapIndex, {
        name: bootstrap.name,
        record,
        ...bootstrapActionSummary(record),
      }, input.now);
    }
  }
  if (input.action === 'bootstrap_subdomain_disable') {
    const bootstrapIndex = INSTALL_ACTION_ORDER.indexOf('customer_bootstrap_submit');
    const bootstrap = journal.actions[bootstrapIndex];
    const bootstrapRecord = bootstrap?.record.kind === 'customer_bootstrap_submit' ? bootstrap.record : null;
    const attempts = bootstrapRecord
      ? [...bootstrapRecord.attempts]
      : [];
    const attempt = attempts[attempts.length - 1];
    if (
      bootstrapRecord && attempt?.disable?.phase === 'submitted' && attempt.disable.locator?.enabled === false &&
      attempt.disable.approvalAttemptId === input.attemptId
    ) {
      attempts[attempts.length - 1] = Object.freeze({
        ...attempt,
        disable: Object.freeze({ ...attempt.disable, phase: 'verified', verifiedAt: input.now }),
      });
      const record = Object.freeze({ ...bootstrapRecord, attempts: Object.freeze(attempts) });
      const nextBootstrap = Object.freeze({
        name: bootstrap.name,
        record,
        ...bootstrapActionSummary(record),
      });
      if (attempts.length > 1) return replaceAction(journal, bootstrapIndex, nextBootstrap, input.now);
      if (!action || action.phase !== 'submitted' || !action.locator) conflict();
      const actions = [...journal.actions];
      actions[bootstrapIndex] = nextBootstrap;
      actions[index] = Object.freeze({ ...action, phase: 'verified', verifiedAt: input.now });
      return Object.freeze({
        ...journal,
        revision: journal.revision + 1,
        updatedAt: input.now,
        actions: Object.freeze(actions),
      });
    }
  }
  if (input.action === 'customer_bootstrap_submit' && action?.record.kind === 'customer_bootstrap_submit') {
    const attempts = [...action.record.attempts];
    const attempt = attempts[attempts.length - 1];
    if (
      !attempt || attempt.phase !== 'submitted' || attempt.approvalAttemptId !== input.attemptId ||
      attempt.locator?.status !== 'ready'
    ) conflict();
    attempts[attempts.length - 1] = Object.freeze({
      ...attempt,
      phase: 'verified',
      verifiedAt: input.now,
    });
    const record = Object.freeze({ ...action.record, attempts: Object.freeze(attempts) });
    return replaceAction(journal, index, {
      name: action.name,
      record,
      ...bootstrapActionSummary(record),
    }, input.now);
  }
  if (
    !action || action.name !== input.action || action.phase !== 'submitted' || !action.locator ||
    (input.action === 'customer_bootstrap_submit' && 'status' in action.locator && action.locator.status !== 'ready')
  ) conflict();
  return replaceAction(journal, index, {
    ...action,
    phase: 'verified',
    verifiedAt: input.now,
  }, input.now);
}

export async function appendCustomerBootstrapAttempt(
  journal: InstallJournal,
  input: AppendCustomerBootstrapAttemptInput,
): Promise<InstallJournal> {
  cas(journal, input, true);
  const index = INSTALL_ACTION_ORDER.indexOf('customer_bootstrap_submit');
  const action = journal.actions[index];
  if (
    !action || action.record.kind !== 'customer_bootstrap_submit' || action.phase === 'verified' ||
    action.record.attempts.length >= MAX_BOOTSTRAP_ATTEMPTS ||
    !isRecord(input.attempt) || !exactKeys(input.attempt, [
      'requestId', 'issuedAt', 'expiresAt', 'claimHash', 'enableRequestHash',
    ])
  ) conflict();
  const attemptInput = input.attempt as Record<string, unknown>;
  if (
    action.record.attempts.some((attempt) => attempt.approvalAttemptId === input.attemptId) ||
    action.record.attempts.some((attempt) => attempt.requestId === attemptInput.requestId)
  ) conflict();
  const nextAttempt = {
    schemaVersion: 1 as const,
    approvalAttemptId: input.attemptId,
    requestId: attemptInput.requestId,
    issuedAt: attemptInput.issuedAt,
    expiresAt: attemptInput.expiresAt,
    claimHash: attemptInput.claimHash,
    enable: {
      schemaVersion: 1 as const,
      approvalAttemptId: input.attemptId,
      enabled: true,
      requestHash: attemptInput.enableRequestHash,
      phase: 'prepared' as const,
      locator: null,
      preparedAt: input.now,
      sendArmedAt: null,
      submittedAt: null,
      verifiedAt: null,
    },
    disable: null,
    phase: 'prepared' as const,
    locator: null,
    preparedAt: input.now,
    sendArmedAt: null,
    submittedAt: null,
    verifiedAt: null,
  };
  const candidate = {
    ...action.record,
    attempts: [...action.record.attempts, nextAttempt],
  };
  const context = { ...journal, updatedAt: input.now } as InstallJournal;
  const record = await parseBootstrapRecord(candidate, context);
  if (!record) invalid(400);
  return replaceAction(journal, index, {
    name: action.name,
    record,
    ...bootstrapActionSummary(record),
  }, input.now);
}

export function hasArmedInstallJournalAction(journal: InstallJournal): boolean {
  return journal.actions.some(
    (action) => action.name !== 'gateway_fresh_preflight' && action.phase !== 'prepared',
  );
}

export function isCompleteInstallJournal(journal: InstallJournal): boolean {
  return journal.actions.length === INSTALL_ACTION_ORDER.length &&
    journal.actions.every((action) => action.phase === 'verified');
}

export function isPartialInstallJournal(journal: InstallJournal): boolean {
  return hasArmedInstallJournalAction(journal) && !isCompleteInstallJournal(journal);
}
