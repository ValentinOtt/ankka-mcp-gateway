import type { AuthorizedTarget } from './cloudflare-target';
import {
  parseHostedUninstallManagementAbsenceEvidence,
  parseHostedUninstallManagementDeleteArm,
  parseHostedUninstallManagementDeleteIntent,
  parseHostedUninstallManagementDeleteRecoveryEvidence,
  parseHostedUninstallManagementDeleteSubmission,
  parseHostedUninstallManagementNoManagedResidueResult,
  parseHostedUninstallManagementPreflightResult,
  type HostedUninstallManagementAbsenceEvidence,
  type HostedUninstallManagementContext,
  type HostedUninstallManagementDeleteArm,
  type HostedUninstallManagementDeleteIntent,
  type HostedUninstallManagementDeletePrerequisites,
  type HostedUninstallManagementDeleteRecoveryEvidence,
  type HostedUninstallManagementDeleteSubmission,
  type HostedUninstallManagementNoManagedResidueResult,
  type HostedUninstallManagementPreflightResult,
  type HostedUninstallManagementStillPresentEvidence,
} from './cloudflare-uninstall-management';
import {
  parseAdminStateNamespacePresenceProof,
  parseAdminStateNamespaceRetirementProof,
  parseCloudflareUninstallWorkerLifecycleSubmission,
  parseUninstallWorkerDeploymentMutationIntent,
  parseUninstallWorkerVersionRecoveryRecord,
  parseWorkerDeleteMutationIntent,
  parseWorkerDeletionRecoveryProof,
  type CloudflareUninstallWorkerLifecycleSubmission,
  AdminStateNamespacePresenceProof,
  type AdminStateNamespaceRetirementProof,
  UninstallWorkerDeploymentMutationIntent,
  type UninstallWorkerDeploymentSubmission,
  type UninstallWorkerVersionRecoveryRecord,
  type UninstallWorkerVersionSubmission,
  type WorkerDeleteMutationIntent,
  type WorkerDeleteSubmission,
  type WorkerDeletionRecoveryProof,
} from './cloudflare-uninstall-worker-lifecycle';
import {
  parseCustomerUninstallLocator,
  parseCustomerUninstallSemanticRecord,
  CustomerUninstallLocator,
  type CustomerUninstallSemanticRecord,
} from './customer-uninstall-request';
import { sha256Hex } from './crypto';
import { DeployError } from './errors';
import {
  isCompleteInstallJournal,
  prepareFinalConvergenceRecordAndLocator,
  requireInstallJournal,
  type FinalConvergenceLocator as InstallFinalConvergenceLocator,
  type InstallJournal,
} from './install-journal';
import { assertSecretFree } from './schema';
import {
  buildStaticUninstallPlan,
  isRecoveryEquivalentUninstallPlan,
  parseStaticUninstallPlan,
  STATIC_UNINSTALL_PROVIDER_NOTICE,
  type StaticUninstallPlan,
} from './uninstall-plan';

const ATTEMPT_ID = /^att_[A-Za-z0-9_-]{32}$/u;
const UNINSTALL_CYCLE_ID = /^uninstall-[a-f0-9]{24}$/u;
const PREFIXED_SHA256 = /^sha256:[a-f0-9]{64}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const MAX_APPROVALS = 16;
const MAX_LEASE_ATTEMPTS = 16;
const MAX_CUSTOMER_REMOVE_CYCLES = 8;
const MAX_WORKERS_DEV_DISABLE_ATTEMPTS = 8;
const MAX_MANAGEMENT_DELETE_ATTEMPTS = 8;
const MAX_MANAGEMENT_PREFLIGHTS = 32;
const FRESH_PREFLIGHT_TTL_MS = 60_000;

export const MAX_UNINSTALL_LEASE_MS = 5 * 60 * 1_000;

export const UNINSTALL_ACTION_ORDER = Object.freeze([
  'uninstall_fresh_preflight',
  'cleanup_worker_version_create',
  'cleanup_worker_deployment_create',
  'customer_gateway_remove',
  'restore_clean_worker_deployment',
  'management_custom_domain_delete',
  'management_admin_policy_delete',
  'management_access_application_delete',
  'retirement_worker_version_create',
  'retirement_worker_deployment_create',
  'admin_state_namespace_retired',
  'management_worker_delete',
  'management_no_managed_residue',
  'uninstall_final_convergence',
] as const);

export type UninstallActionName = (typeof UNINSTALL_ACTION_ORDER)[number];
export type UninstallActionPhase = 'prepared' | 'send_armed' | 'submitted' | 'verified';
export type UninstallWorkersDevPhase = UninstallActionPhase | 'not_applied';
export type UninstallManagementDeletePhase = UninstallActionPhase | 'not_applied';

export interface UninstallJournalApproval {
  readonly schemaVersion: 1;
  readonly attemptId: string;
  readonly approvedAt: number;
  readonly recordedAt: number;
  readonly plan: StaticUninstallPlan;
  readonly authorizedTarget: AuthorizedTarget;
}

export interface UninstallJournalLease {
  readonly attemptId: string;
  readonly acquiredAt: number;
  readonly expiresAt: number;
}

export interface UninstallWorkerVersionActionRecord {
  readonly schemaVersion: 1;
  readonly kind: 'uninstall_worker_version_create';
  readonly stage: 'cleanup' | 'retirement';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly namespacePresence: AdminStateNamespacePresenceProof | null;
  readonly release: string;
  readonly artifactSha256: string;
  readonly componentSha256: string;
  readonly recovery: UninstallWorkerVersionRecoveryRecord | null;
}

export interface UninstallWorkerDeploymentActionRecord {
  readonly schemaVersion: 1;
  readonly kind: 'uninstall_worker_deployment_create';
  readonly stage: 'cleanup' | 'retirement' | 'restore_clean';
  readonly intent: UninstallWorkerDeploymentMutationIntent;
}

export interface UninstallWorkersDevMutation {
  readonly schemaVersion: 1;
  readonly kind: 'uninstall_workers_dev';
  readonly approvalAttemptId: string;
  readonly accountId: string;
  readonly workerName: string;
  readonly uninstallCycleId: string;
  readonly enabled: boolean;
  readonly previewsEnabled: false;
  readonly requestHash: string;
  readonly phase: UninstallWorkersDevPhase;
  readonly locator: { readonly enabled: boolean; readonly previewsEnabled: false } | null;
  readonly preparedAt: number;
  readonly sendArmedAt: number | null;
  readonly submittedAt: number | null;
  readonly submittedByAttemptId: string | null;
  readonly verifiedAt: number | null;
  readonly verifiedByAttemptId: string | null;
}

export interface CustomerGatewayRemoveRequestAttempt {
  readonly schemaVersion: 1;
  readonly approvalAttemptId: string;
  readonly semantic: CustomerUninstallSemanticRecord;
  readonly enable: UninstallWorkersDevMutation;
  readonly requestPhase: UninstallActionPhase;
  readonly locator: CustomerUninstallLocator | null;
  readonly disableAttempts: readonly UninstallWorkersDevMutation[];
  readonly preparedAt: number;
  readonly sendArmedAt: number | null;
  readonly submittedAt: number | null;
  readonly submittedByAttemptId: string | null;
  readonly verifiedAt: number | null;
  readonly verifiedByAttemptId: string | null;
}

export interface CustomerGatewayRemoveActionRecord {
  readonly schemaVersion: 1;
  readonly kind: 'customer_gateway_remove';
  readonly accountId: string;
  readonly zoneId: string;
  readonly zoneName: string;
  readonly workerName: string;
  readonly installationId: string;
  readonly uninstallCycleId: string;
  readonly attempts: readonly CustomerGatewayRemoveRequestAttempt[];
}

export interface ManagementDeleteAttempt {
  readonly schemaVersion: 1;
  readonly prerequisites: HostedUninstallManagementDeletePrerequisites;
  readonly intent: HostedUninstallManagementDeleteIntent;
  readonly phase: UninstallManagementDeletePhase;
  readonly arm: HostedUninstallManagementDeleteArm | null;
  readonly submission: HostedUninstallManagementDeleteSubmission | null;
  readonly recovery: HostedUninstallManagementStillPresentEvidence | null;
  readonly locator: HostedUninstallManagementAbsenceEvidence | null;
  readonly preparedAt: number;
  readonly sendArmedAt: number | null;
  readonly submittedAt: number | null;
  readonly submittedByAttemptId: string | null;
  readonly verifiedAt: number | null;
  readonly verifiedByAttemptId: string | null;
}

export interface ManagementDeleteActionRecord {
  readonly schemaVersion: 1;
  readonly kind: 'uninstall_management_delete';
  readonly action: 'management_custom_domain_delete' | 'management_admin_policy_delete' |
    'management_access_application_delete';
  readonly attempts: readonly ManagementDeleteAttempt[];
}

export interface ManagementDeleteActionDraft {
  readonly schemaVersion: 1;
  readonly kind: 'uninstall_management_delete';
  readonly prerequisites: HostedUninstallManagementDeletePrerequisites;
  readonly intent: HostedUninstallManagementDeleteIntent;
}

export interface NamespaceRetirementActionRecord {
  readonly schemaVersion: 1;
  readonly kind: 'admin_state_namespace_retired';
  readonly proof: AdminStateNamespaceRetirementProof;
}

export interface WorkerDeleteActionRecord {
  readonly schemaVersion: 1;
  readonly kind: 'management_worker_delete';
  readonly intent: WorkerDeleteMutationIntent;
  readonly submission: WorkerDeleteSubmission | null;
}

export interface NoManagedResidueActionRecord {
  readonly schemaVersion: 1;
  readonly kind: 'management_no_managed_residue';
  readonly result: HostedUninstallManagementNoManagedResidueResult;
  readonly preparedByAttemptId: string;
  readonly armedByAttemptId: string | null;
  readonly submittedByAttemptId: string | null;
  readonly verifiedByAttemptId: string | null;
}

export interface NoManagedResidueActionDraft {
  readonly schemaVersion: 1;
  readonly kind: 'management_no_managed_residue';
  readonly result: HostedUninstallManagementNoManagedResidueResult;
}

export interface UninstallFinalConvergenceRecord {
  readonly schemaVersion: 1;
  readonly kind: 'uninstall_final_convergence';
  readonly convergenceHash: string;
}

export interface UninstallRemovedTombstone {
  readonly schemaVersion: 1;
  readonly status: 'removed';
  readonly convergenceHash: string;
  readonly bindingHash: string;
  readonly uninstallCycleId: string;
  readonly installationId: string;
  readonly target: {
    readonly accountId: string;
    readonly zoneId: string;
    readonly zoneName: string;
  };
  readonly release: { readonly id: string; readonly artifactSha256: string };
  readonly customer: Extract<CustomerUninstallLocator, { readonly status: 'removed' }>;
  readonly lifecycle: {
    readonly cleanupVersion: UninstallWorkerVersionSubmission;
    readonly cleanupDeployment: UninstallWorkerDeploymentSubmission;
    readonly restoredCleanDeployment: UninstallWorkerDeploymentSubmission;
    readonly retirementVersion: UninstallWorkerVersionSubmission;
    readonly retirementDeployment: UninstallWorkerDeploymentSubmission;
    readonly namespaceRetirement: AdminStateNamespaceRetirementProof;
    readonly workerDeletion: WorkerDeletionRecoveryProof;
  };
  readonly management: {
    readonly customDomainAbsence: HostedUninstallManagementAbsenceEvidence;
    readonly adminPolicyAbsence: HostedUninstallManagementAbsenceEvidence;
    readonly accessApplicationAbsence: HostedUninstallManagementAbsenceEvidence;
    readonly noManagedResidue: HostedUninstallManagementNoManagedResidueResult;
  };
  readonly workersDevEnabled: false;
  readonly providerNotice: typeof STATIC_UNINSTALL_PROVIDER_NOTICE;
}

export type UninstallActionRecord =
  | HostedUninstallManagementPreflightResult
  | UninstallWorkerVersionActionRecord
  | UninstallWorkerDeploymentActionRecord
  | CustomerGatewayRemoveActionRecord
  | ManagementDeleteActionRecord
  | NamespaceRetirementActionRecord
  | WorkerDeleteActionRecord
  | NoManagedResidueActionRecord
  | UninstallFinalConvergenceRecord;

export type UninstallActionLocator =
  | { readonly attestationSha256: string }
  | UninstallWorkerVersionSubmission
  | UninstallWorkerDeploymentSubmission
  | CustomerUninstallLocator
  | HostedUninstallManagementAbsenceEvidence
  | AdminStateNamespaceRetirementProof
  | WorkerDeletionRecoveryProof
  | HostedUninstallManagementNoManagedResidueResult
  | UninstallRemovedTombstone;

export interface UninstallJournalAction {
  readonly name: UninstallActionName;
  readonly phase: UninstallActionPhase;
  readonly record: UninstallActionRecord;
  readonly locator: UninstallActionLocator | null;
  readonly preparedAt: number;
  readonly sendArmedAt: number | null;
  readonly submittedAt: number | null;
  readonly verifiedAt: number | null;
}

export interface UninstallJournal {
  readonly schemaVersion: 1;
  readonly revision: number;
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly recoverUntil: number;
  readonly installJournal: InstallJournal;
  readonly uninstallPlan: StaticUninstallPlan;
  readonly uninstallCycleId: string;
  readonly bindingHash: string;
  readonly approvalHistory: readonly UninstallJournalApproval[];
  readonly managementPreflightHistory: readonly HostedUninstallManagementPreflightResult[];
  readonly lease: UninstallJournalLease | null;
  readonly leaseAttemptIds: readonly string[];
  readonly actions: readonly UninstallJournalAction[];
}

export interface UninstallJournalCasInput {
  readonly expectedRevision: number;
  readonly attemptId: string;
  readonly now: number;
}

export interface CreateUninstallJournalInput {
  readonly schemaVersion: 1;
  readonly now: number;
  readonly recoverUntil: number;
  readonly installJournal: unknown;
  readonly uninstallPlan: unknown;
  readonly uninstallCycleId: string;
  readonly bindingHash: string;
  readonly freshPreflight: unknown;
}

export interface CreateUninstallJournalApprovalInput {
  readonly attemptId: string;
  readonly approvedAt: number;
  readonly authorizedTarget: unknown;
}

export interface AcquireUninstallJournalLeaseInput extends UninstallJournalCasInput {
  readonly leaseExpiresAt: number;
}

export interface AppendUninstallJournalApprovalInput extends UninstallJournalCasInput {
  readonly approvedAt: number;
  readonly authorizedTarget: unknown;
}

export interface AppendUninstallManagementPreflightInput extends UninstallJournalCasInput {
  readonly preflight: unknown;
}

function invalid(status = 500): never {
  throw new DeployError(status, status === 400 ? 'bad_request' : 'session_invalid');
}

function conflict(): never {
  throw new DeployError(409, 'session_conflict');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

function safeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isPlainDataTree(
  value: unknown,
  budget = { nodes: 250_000, characters: 16 * 1024 * 1024 },
  depth = 0,
): boolean {
  if (budget.nodes-- <= 0 || depth > 64) return false;
  if (value === null || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value === 'string') {
    budget.characters -= value.length;
    return budget.characters >= 0;
  }
  if (typeof value !== 'object') return false;
  let prototype: object | null;
  let descriptors: Record<PropertyKey, PropertyDescriptor>;
  let keys: readonly PropertyKey[];
  try {
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
    keys = Reflect.ownKeys(value);
  } catch {
    return false;
  }
  if (keys.some((key) => typeof key !== 'string')) return false;
  if (Array.isArray(value)) {
    if (prototype !== Array.prototype || keys.length !== value.length + 1) return false;
    const length = descriptors.length;
    if (!length || !('value' in length) || length.value !== value.length) return false;
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || descriptor.enumerable !== true || !('value' in descriptor) ||
        !isPlainDataTree(descriptor.value, budget, depth + 1)) return false;
    }
    return true;
  }
  if (prototype !== Object.prototype) return false;
  return keys.every((key) => {
    const descriptor = descriptors[key];
    return Boolean(descriptor && descriptor.enumerable === true && 'value' in descriptor &&
      isPlainDataTree(descriptor.value, budget, depth + 1));
  });
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError('canonical_json_invalid');
}

function canonicalEqual(left: unknown, right: unknown): boolean {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function assertDurable(value: unknown, status = 400): void {
  try {
    if (!isPlainDataTree(value)) invalid(status);
    assertSecretFree(value);
    canonicalJson(value);
  } catch {
    invalid(status);
  }
}

function installFinalLocator(journal: InstallJournal): InstallFinalConvergenceLocator | null {
  const action = journal.actions[journal.actions.length - 1];
  if (action?.name !== 'final_convergence' || action.phase !== 'verified' || !action.locator ||
    !('status' in action.locator) || action.locator.status !== 'converged') return null;
  return action.locator as InstallFinalConvergenceLocator;
}

async function requireCompleteInstallAuthority(value: unknown): Promise<{
  readonly journal: InstallJournal;
  readonly final: InstallFinalConvergenceLocator;
}> {
  const journal = await requireInstallJournal(value);
  if (!isCompleteInstallJournal(journal)) conflict();
  const rebuilt = await prepareFinalConvergenceRecordAndLocator(journal);
  const final = installFinalLocator(journal);
  if (!final || !canonicalEqual(rebuilt.locator, final)) conflict();
  return deepFreeze({ journal, final });
}

function targetMatches(left: unknown, right: AuthorizedTarget): left is AuthorizedTarget {
  return canonicalEqual(left, right);
}

function installAttemptWasUsed(journal: InstallJournal, attemptId: string): boolean {
  return journal.approvalHistory.some((approval) => approval.attemptId === attemptId) ||
    journal.leaseAttemptIds.includes(attemptId);
}

function approvalContext(
  journal: Pick<UninstallJournal, 'installJournal' | 'approvalHistory'>,
  approval: UninstallJournalApproval,
): HostedUninstallManagementContext {
  const activeIndex = journal.approvalHistory.findIndex(
    (entry) => entry.attemptId === approval.attemptId,
  );
  if (activeIndex < 0) invalid();
  return deepFreeze({
    schemaVersion: 1 as const,
    installJournal: journal.installJournal,
    approvalHistory: journal.approvalHistory.slice(0, activeIndex + 1).map((entry) => ({
      attemptId: entry.attemptId,
      uninstallPlan: entry.plan,
      authorizedTarget: entry.authorizedTarget,
    })),
    activeAttemptId: approval.attemptId,
  });
}

function activeApproval(journal: Pick<UninstallJournal, 'approvalHistory'>): UninstallJournalApproval {
  const approval = journal.approvalHistory[journal.approvalHistory.length - 1];
  if (!approval) invalid();
  return approval;
}

export function activeUninstallJournalPlan(journal: UninstallJournal): StaticUninstallPlan {
  return activeApproval(journal).plan;
}

async function exactReviewedPlan(
  installJournal: InstallJournal,
  value: unknown,
): Promise<StaticUninstallPlan> {
  const parsed = await parseStaticUninstallPlan(value);
  const rebuilt = await buildStaticUninstallPlan(installJournal, parsed.createdAt, parsed.expiresAt);
  if (!canonicalEqual(parsed, rebuilt)) invalid(400);
  return parsed;
}

export async function computeUninstallJournalBindingHash(input: {
  readonly installJournal: unknown;
  readonly uninstallPlan: unknown;
  readonly uninstallCycleId: string;
}): Promise<string> {
  if (!isRecord(input) || !exactKeys(input, ['installJournal', 'uninstallPlan', 'uninstallCycleId']) ||
    typeof input.uninstallCycleId !== 'string' || !UNINSTALL_CYCLE_ID.test(input.uninstallCycleId)) invalid(400);
  const authority = await requireCompleteInstallAuthority(input.installJournal);
  const plan = await exactReviewedPlan(authority.journal, input.uninstallPlan);
  return `sha256:${await sha256Hex(canonicalJson({
    schemaVersion: 1,
    install: {
      installationId: authority.journal.installationId,
      bindingHash: authority.journal.bindingHash,
      convergenceHash: authority.final.convergenceHash,
      readyReceiptChecksum: authority.final.customerReceiptEvidence.checksum,
      adminStateNamespaceId: authority.final.adminStateNamespaceId,
    },
    uninstall: {
      planId: plan.planId,
      planHash: plan.planHash,
      authorityHash: plan.authorityHash,
      cycleId: input.uninstallCycleId,
    },
    target: authority.journal.target,
    release: {
      id: authority.journal.releasePin.release,
      artifactSha256: authority.journal.releasePin.artifactSha256,
    },
  }))}`;
}

function revisionCas(journal: UninstallJournal, input: UninstallJournalCasInput): void {
  if (!safeInteger(input.expectedRevision) || input.expectedRevision !== journal.revision ||
    typeof input.attemptId !== 'string' || !ATTEMPT_ID.test(input.attemptId) ||
    !safeInteger(input.now) || input.now < journal.updatedAt || input.now >= journal.recoverUntil) conflict();
}

function cas(journal: UninstallJournal, input: UninstallJournalCasInput, requireLease: boolean): void {
  revisionCas(journal, input);
  const approval = journal.approvalHistory.find((entry) => entry.attemptId === input.attemptId);
  if (!approval || input.now < approval.approvedAt || input.now >= approval.plan.expiresAt) conflict();
  if (requireLease && (!journal.lease || journal.lease.attemptId !== input.attemptId ||
    input.now >= journal.lease.expiresAt)) conflict();
}

function replaceJournal(
  journal: UninstallJournal,
  now: number,
  fields: Partial<Pick<
    UninstallJournal,
    'approvalHistory' | 'managementPreflightHistory' | 'lease' | 'leaseAttemptIds' | 'actions'
  >>,
): UninstallJournal {
  const next = deepFreeze({
    ...journal,
    ...fields,
    revision: journal.revision + 1,
    updatedAt: now,
  });
  assertDurable(next);
  return next;
}

export async function createUninstallJournal(
  value: unknown,
  approvalInput: CreateUninstallJournalApprovalInput,
): Promise<UninstallJournal> {
  assertDurable(value, 400);
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'now', 'recoverUntil', 'installJournal', 'uninstallPlan',
    'uninstallCycleId', 'bindingHash', 'freshPreflight',
  ]) || !isRecord(approvalInput) || !exactKeys(approvalInput, [
    'attemptId', 'approvedAt', 'authorizedTarget',
  ])) invalid(400);
  const authority = await requireCompleteInstallAuthority(value.installJournal);
  const plan = await exactReviewedPlan(authority.journal, value.uninstallPlan);
  if (
    value.schemaVersion !== 1 || !safeInteger(value.now) || !safeInteger(value.recoverUntil) ||
    value.recoverUntil <= value.now || value.recoverUntil > authority.journal.recoverUntil ||
    value.now < authority.journal.updatedAt || value.now >= plan.expiresAt || plan.expiresAt > value.recoverUntil ||
    typeof value.uninstallCycleId !== 'string' || !UNINSTALL_CYCLE_ID.test(value.uninstallCycleId) ||
    typeof value.bindingHash !== 'string' || !PREFIXED_SHA256.test(value.bindingHash) ||
    typeof approvalInput.attemptId !== 'string' || !ATTEMPT_ID.test(approvalInput.attemptId) ||
    installAttemptWasUsed(authority.journal, approvalInput.attemptId) ||
    !safeInteger(approvalInput.approvedAt) || approvalInput.approvedAt > value.now ||
    approvalInput.approvedAt < plan.createdAt || approvalInput.approvedAt >= plan.expiresAt ||
    !targetMatches(approvalInput.authorizedTarget, authority.journal.target)
  ) invalid(400);
  const bindingHash = await computeUninstallJournalBindingHash({
    installJournal: authority.journal,
    uninstallPlan: plan,
    uninstallCycleId: value.uninstallCycleId,
  });
  if (bindingHash !== value.bindingHash) invalid(400);
  const approval = deepFreeze({
    schemaVersion: 1 as const,
    attemptId: approvalInput.attemptId,
    approvedAt: approvalInput.approvedAt,
    recordedAt: value.now,
    plan,
    authorizedTarget: authority.journal.target,
  });
  const base: UninstallJournal = {
    schemaVersion: 1,
    revision: 0,
    createdAt: value.now,
    updatedAt: value.now,
    recoverUntil: value.recoverUntil,
    installJournal: authority.journal,
    uninstallPlan: plan,
    uninstallCycleId: value.uninstallCycleId,
    bindingHash,
    approvalHistory: Object.freeze([approval]),
    managementPreflightHistory: Object.freeze([]),
    lease: null,
    leaseAttemptIds: Object.freeze([]),
    actions: Object.freeze([]),
  };
  const preflight = await parseHostedUninstallManagementPreflightResult(
    approvalContext(base, approval),
    value.freshPreflight,
  );
  if (!preflight || preflight.attemptId !== approval.attemptId ||
    preflight.checkedAt < approval.approvedAt || preflight.checkedAt > value.now ||
    value.now >= preflight.expiresAt || value.now - preflight.checkedAt > FRESH_PREFLIGHT_TTL_MS) invalid(400);
  const preflightAction = deepFreeze({
    name: 'uninstall_fresh_preflight' as const,
    phase: 'verified' as const,
    record: preflight,
    locator: { attestationSha256: preflight.attestationSha256 },
    preparedAt: value.now,
    sendArmedAt: value.now,
    submittedAt: value.now,
    verifiedAt: value.now,
  });
  const journal = deepFreeze({ ...base, actions: [preflightAction] });
  assertDurable(journal);
  return journal;
}

export async function appendUninstallJournalApproval(
  journal: UninstallJournal,
  candidatePlan: unknown,
  input: AppendUninstallJournalApprovalInput,
): Promise<UninstallJournal> {
  revisionCas(journal, { expectedRevision: input.expectedRevision, attemptId: input.attemptId, now: input.now });
  const plan = await exactReviewedPlan(journal.installJournal, candidatePlan);
  const previous = activeApproval(journal);
  if (!targetMatches(input.authorizedTarget, journal.installJournal.target) ||
    journal.lease !== null || journal.approvalHistory.length >= MAX_APPROVALS ||
    journal.approvalHistory.some((entry) => entry.attemptId === input.attemptId) ||
    installAttemptWasUsed(journal.installJournal, input.attemptId) ||
    journal.leaseAttemptIds.includes(input.attemptId) || !safeInteger(input.approvedAt) ||
    input.approvedAt > input.now || input.approvedAt < previous.recordedAt ||
    input.approvedAt < plan.createdAt || input.approvedAt >= plan.expiresAt ||
    plan.createdAt < previous.plan.createdAt || plan.createdAt > input.now ||
    plan.expiresAt <= input.now || plan.expiresAt < previous.plan.expiresAt ||
    plan.expiresAt > journal.recoverUntil ||
    !await isRecoveryEquivalentUninstallPlan(journal.uninstallPlan, plan)) conflict();
  const approval = deepFreeze({
    schemaVersion: 1 as const,
    attemptId: input.attemptId,
    approvedAt: input.approvedAt,
    recordedAt: input.now,
    plan,
    authorizedTarget: journal.installJournal.target,
  });
  return replaceJournal(journal, input.now, {
    approvalHistory: Object.freeze([...journal.approvalHistory, approval]),
  });
}

export function acquireUninstallJournalLease(
  journal: UninstallJournal,
  input: AcquireUninstallJournalLeaseInput,
): UninstallJournal {
  cas(journal, { expectedRevision: input.expectedRevision, attemptId: input.attemptId, now: input.now }, false);
  const current = activeApproval(journal);
  if (current.attemptId !== input.attemptId || !safeInteger(input.leaseExpiresAt) ||
    input.leaseExpiresAt <= input.now || input.leaseExpiresAt > input.now + MAX_UNINSTALL_LEASE_MS ||
    input.leaseExpiresAt > current.plan.expiresAt || input.leaseExpiresAt > journal.recoverUntil ||
    journal.leaseAttemptIds.includes(input.attemptId) || journal.leaseAttemptIds.length >= MAX_LEASE_ATTEMPTS ||
    (journal.lease !== null && input.now < journal.lease.expiresAt)) conflict();
  return replaceJournal(journal, input.now, {
    lease: deepFreeze({ attemptId: input.attemptId, acquiredAt: input.now, expiresAt: input.leaseExpiresAt }),
    leaseAttemptIds: Object.freeze([...journal.leaseAttemptIds, input.attemptId]),
  });
}

export function releaseUninstallJournalLease(
  journal: UninstallJournal,
  input: UninstallJournalCasInput,
): UninstallJournal {
  cas(journal, input, true);
  return replaceJournal(journal, input.now, { lease: null });
}

export function expireUninstallJournalLease(journal: UninstallJournal, now: number): UninstallJournal {
  if (!safeInteger(now) || !journal.lease || now < journal.lease.expiresAt) return journal;
  return replaceJournal(journal, Math.min(Math.max(journal.updatedAt, now), journal.recoverUntil - 1), { lease: null });
}

export async function refreshUninstallJournalPreflight(
  journal: UninstallJournal,
  value: unknown,
  input: UninstallJournalCasInput,
): Promise<UninstallJournal> {
  cas(journal, input, true);
  if (journal.actions.length !== 1 || journal.actions[0]?.name !== 'uninstall_fresh_preflight') conflict();
  const approval = activeApproval(journal);
  if (approval.attemptId !== input.attemptId) conflict();
  const preflight = await parseHostedUninstallManagementPreflightResult(
    approvalContext(journal, approval),
    value,
  );
  if (!preflight || preflight.checkedAt < approval.approvedAt || preflight.checkedAt > input.now ||
    input.now >= preflight.expiresAt || input.now - preflight.checkedAt > FRESH_PREFLIGHT_TTL_MS) invalid(400);
  const action = deepFreeze({
    name: 'uninstall_fresh_preflight' as const,
    phase: 'verified' as const,
    record: preflight,
    locator: { attestationSha256: preflight.attestationSha256 },
    preparedAt: input.now,
    sendArmedAt: input.now,
    submittedAt: input.now,
    verifiedAt: input.now,
  });
  return replaceJournal(journal, input.now, { actions: Object.freeze([action]) });
}

export function discardPreflightOnlyUninstallJournal(
  journal: UninstallJournal,
  input: UninstallJournalCasInput,
): null {
  cas(journal, input, true);
  if (journal.actions.length !== 1 || journal.actions[0]?.name !== 'uninstall_fresh_preflight') conflict();
  return null;
}

/**
 * Append a fresh, approval-bound management attestation after the customer
 * gateway is removed and the clean Worker is restored. The immutable initial
 * preflight remains action zero; these bounded observations make OAuth-grant
 * rotation recoverable without rewriting earlier authority.
 */
export async function appendUninstallManagementPreflight(
  journal: UninstallJournal,
  input: AppendUninstallManagementPreflightInput,
): Promise<UninstallJournal> {
  cas(journal, input, true);
  const domainAction = actionByName(journal, 'management_custom_domain_delete');
  const domainAttempt = domainAction && 'kind' in domainAction.record &&
    domainAction.record.kind === 'uninstall_management_delete'
    ? domainAction.record.attempts[domainAction.record.attempts.length - 1]
    : null;
  if (
    journal.managementPreflightHistory.length >= MAX_MANAGEMENT_PREFLIGHTS ||
    verifiedAction(journal, 'customer_gateway_remove') === null ||
    verifiedAction(journal, 'restore_clean_worker_deployment') === null ||
    (domainAction !== null && (!domainAttempt || !['prepared', 'not_applied'].includes(domainAttempt.phase)))
  ) conflict();
  const approval = activeApproval(journal);
  if (approval.attemptId !== input.attemptId) conflict();
  const preflight = await parseHostedUninstallManagementPreflightResult(
    approvalContext(journal, approval),
    input.preflight,
  );
  const previous = journal.managementPreflightHistory[journal.managementPreflightHistory.length - 1];
  if (
    !preflight || preflight.attemptId !== input.attemptId ||
    preflight.checkedAt < approval.approvedAt || preflight.checkedAt < approval.recordedAt ||
    preflight.checkedAt > input.now || input.now >= preflight.expiresAt ||
    input.now - preflight.checkedAt > FRESH_PREFLIGHT_TTL_MS ||
    journal.managementPreflightHistory.some(
      (entry) => entry.attestationSha256 === preflight.attestationSha256,
    ) ||
    (previous && preflight.checkedAt < previous.checkedAt) ||
    (previous?.attemptId === input.attemptId &&
      (input.now < previous.expiresAt || preflight.checkedAt < previous.expiresAt))
  ) invalid(400);
  return replaceJournal(journal, input.now, {
    managementPreflightHistory: Object.freeze([
      ...journal.managementPreflightHistory,
      preflight,
    ]),
  });
}

function actionByName(
  journal: Pick<UninstallJournal, 'actions'>,
  name: UninstallActionName,
): UninstallJournalAction | null {
  return journal.actions.find((action) => action.name === name) ?? null;
}

function verifiedAction(
  journal: Pick<UninstallJournal, 'actions'>,
  name: UninstallActionName,
): UninstallJournalAction | null {
  const action = actionByName(journal, name);
  return action?.phase === 'verified' ? action : null;
}

function approvalByAttempt(
  journal: Pick<UninstallJournal, 'approvalHistory'>,
  attemptId: string,
): UninstallJournalApproval | null {
  return journal.approvalHistory.find((approval) => approval.attemptId === attemptId) ?? null;
}

function approvalIndexByAttempt(
  journal: Pick<UninstallJournal, 'approvalHistory'>,
  attemptId: string,
): number {
  return journal.approvalHistory.findIndex((approval) => approval.attemptId === attemptId);
}

function approvalWasActiveAt(
  journal: Pick<UninstallJournal, 'approvalHistory'>,
  attemptId: string,
  time: number,
): boolean {
  const index = approvalIndexByAttempt(journal, attemptId);
  if (index < 0) return false;
  const approval = journal.approvalHistory[index];
  const next = journal.approvalHistory[index + 1];
  return Boolean(approval && time >= approval.recordedAt && (!next || time <= next.recordedAt));
}

function contextForAttempt(journal: UninstallJournal, attemptId: string): HostedUninstallManagementContext | null {
  const approval = approvalByAttempt(journal, attemptId);
  return approval ? approvalContext(journal, approval) : null;
}

function activeManagementContext(journal: UninstallJournal): HostedUninstallManagementContext {
  return approvalContext(journal, activeApproval(journal));
}

function installFinal(journal: UninstallJournal): InstallFinalConvergenceLocator {
  const final = installFinalLocator(journal.installJournal);
  if (!final) invalid();
  return final;
}

function workerIdentity(journal: UninstallJournal): {
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly namespaceId: string;
} {
  const final = installFinal(journal);
  return {
    accountId: journal.installJournal.target.account.id,
    workerName: journal.uninstallPlan.gateway.workerName,
    workerId: final.workerId,
    namespaceId: final.adminStateNamespaceId,
  };
}

function installedAccountWorkersSubdomain(journal: UninstallJournal): string | null {
  const action = journal.installJournal.actions.find(
    (entry) => entry.name === 'customer_bootstrap_submit',
  );
  return action?.phase === 'verified' && 'kind' in action.record &&
    action.record.kind === 'customer_bootstrap_submit'
    ? action.record.accountWorkersSubdomain
    : null;
}

async function customerSemanticMatchesAuthority(
  semantic: CustomerUninstallSemanticRecord,
  journal: UninstallJournal,
): Promise<boolean> {
  const recoveryProbe = {
    schemaVersion: 1 as const,
    status: 'recovery_required' as const,
    requestId: semantic.requestId,
    accountId: semantic.accountId,
    zoneId: semantic.zoneId,
    zoneName: semantic.zoneName,
    accountWorkersSubdomain: semantic.accountWorkersSubdomain,
    workerName: semantic.workerName,
    installationId: semantic.installationId,
    configurationHash: semantic.configurationHash,
    desiredHash: semantic.desiredHash,
    release: semantic.release,
    installBindingHash: semantic.installBindingHash,
    installConvergenceHash: semantic.installConvergenceHash,
    adminStateNamespaceId: semantic.adminStateNamespaceId,
    uninstallPlanId: semantic.uninstallPlanId,
    uninstallPlanHash: semantic.uninstallPlanHash,
    authorityHash: semantic.authorityHash,
    approvalAttemptId: semantic.approvalAttemptId,
    reason: 'uninstall_blocked' as const,
    freshGrantRequired: true as const,
  };
  const parsed = await parseCustomerUninstallLocator(
    recoveryProbe,
    semantic,
    journal.installJournal,
  );
  return parsed?.status === 'recovery_required' && canonicalEqual(parsed, recoveryProbe);
}

function lifecycleIdentityMatches(
  value: {
    readonly accountId: string;
    readonly workerName: string;
    readonly workerId: string;
    readonly uninstallCycleId: string;
  },
  journal: UninstallJournal,
): boolean {
  const expected = workerIdentity(journal);
  return value.accountId === expected.accountId && value.workerName === expected.workerName &&
    value.workerId === expected.workerId && value.uninstallCycleId === journal.uninstallCycleId;
}

function parseLifecycleSubmission<T extends CloudflareUninstallWorkerLifecycleSubmission['kind']>(
  value: unknown,
  kind: T,
  journal: UninstallJournal,
): Extract<CloudflareUninstallWorkerLifecycleSubmission, { readonly kind: T }> | null {
  const parsed = parseCloudflareUninstallWorkerLifecycleSubmission(value);
  return parsed && parsed.kind === kind && lifecycleIdentityMatches(parsed, journal)
    ? parsed as Extract<CloudflareUninstallWorkerLifecycleSubmission, { readonly kind: T }>
    : null;
}

async function parseVersionActionRecord(
  value: unknown,
  stage: 'cleanup' | 'retirement',
  journal: UninstallJournal,
): Promise<UninstallWorkerVersionActionRecord | null> {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'kind', 'stage', 'accountId', 'workerName', 'workerId', 'uninstallCycleId',
    'namespacePresence', 'release', 'artifactSha256', 'componentSha256', 'recovery',
  ]) || value.schemaVersion !== 1 || value.kind !== 'uninstall_worker_version_create' || value.stage !== stage ||
    typeof value.accountId !== 'string' || typeof value.workerName !== 'string' || typeof value.workerId !== 'string' ||
    typeof value.uninstallCycleId !== 'string' || !lifecycleIdentityMatches(value as never, journal) ||
    value.release !== journal.uninstallPlan.release.id ||
    value.artifactSha256 !== journal.uninstallPlan.release.aggregateSha256 ||
    typeof value.componentSha256 !== 'string' || !SHA256.test(value.componentSha256)) return null;
  const identity = workerIdentity(journal);
  let namespacePresence: AdminStateNamespacePresenceProof | null = null;
  if (stage === 'cleanup') {
    namespacePresence = parseAdminStateNamespacePresenceProof(value.namespacePresence);
    if (!namespacePresence || !lifecycleIdentityMatches(namespacePresence, journal) ||
      namespacePresence.namespaceId !== identity.namespaceId) return null;
  } else if (value.namespacePresence !== null) return null;
  let recovery: UninstallWorkerVersionRecoveryRecord | null = null;
  if (value.recovery !== null) {
    recovery = await parseUninstallWorkerVersionRecoveryRecord(value.recovery);
    if (!recovery || recovery.stage !== stage || !lifecycleIdentityMatches(recovery, journal) ||
      recovery.release !== value.release || recovery.artifactSha256 !== value.artifactSha256 ||
      recovery.componentSha256 !== value.componentSha256 ||
      (stage === 'cleanup' && (recovery.stage !== 'cleanup' || recovery.namespaceId !== identity.namespaceId))) return null;
  }
  return deepFreeze({
    schemaVersion: 1,
    kind: 'uninstall_worker_version_create',
    stage,
    accountId: identity.accountId,
    workerName: identity.workerName,
    workerId: identity.workerId,
    uninstallCycleId: journal.uninstallCycleId,
    namespacePresence,
    release: value.release,
    artifactSha256: value.artifactSha256,
    componentSha256: value.componentSha256,
    recovery,
  });
}

function expectedVersionIdForDeployment(
  journal: UninstallJournal,
  stage: 'cleanup' | 'retirement' | 'restore_clean',
): string | null {
  if (stage === 'restore_clean') return installFinal(journal).cleanVersionId;
  const action = verifiedAction(
    journal,
    stage === 'cleanup' ? 'cleanup_worker_version_create' : 'retirement_worker_version_create',
  );
  return action?.locator && 'kind' in action.locator && action.locator.kind === 'uninstall_worker_version'
    ? action.locator.versionId
    : null;
}

async function parseDeploymentActionRecord(
  value: unknown,
  stage: 'cleanup' | 'retirement' | 'restore_clean',
  journal: UninstallJournal,
): Promise<UninstallWorkerDeploymentActionRecord | null> {
  if (!isRecord(value) || !exactKeys(value, ['schemaVersion', 'kind', 'stage', 'intent']) ||
    value.schemaVersion !== 1 || value.kind !== 'uninstall_worker_deployment_create' || value.stage !== stage) return null;
  const intent = await parseUninstallWorkerDeploymentMutationIntent(value.intent);
  const versionId = expectedVersionIdForDeployment(journal, stage);
  if (!intent || intent.stage !== stage || !lifecycleIdentityMatches(intent, journal) ||
    !versionId || intent.versionId !== versionId) return null;
  return deepFreeze({ schemaVersion: 1, kind: 'uninstall_worker_deployment_create', stage, intent });
}

function expectedManagementPrerequisites(
  journal: UninstallJournal,
  action: 'management_custom_domain_delete' | 'management_admin_policy_delete' |
    'management_access_application_delete',
): HostedUninstallManagementDeletePrerequisites | null {
  if (action === 'management_custom_domain_delete') {
    const preflight = journal.managementPreflightHistory[
      journal.managementPreflightHistory.length - 1
    ];
    if (!preflight) return null;
    return deepFreeze({ schemaVersion: 1, action, preflight });
  }
  const domain = verifiedAction(journal, 'management_custom_domain_delete')?.locator;
  if (!domain || !('action' in domain) || domain.action !== 'management_custom_domain_delete') return null;
  if (action === 'management_admin_policy_delete') {
    return deepFreeze({ schemaVersion: 1, action, domainAbsence: domain });
  }
  const policy = verifiedAction(journal, 'management_admin_policy_delete')?.locator;
  if (!policy || !('action' in policy) || policy.action !== 'management_admin_policy_delete') return null;
  return deepFreeze({ schemaVersion: 1, action, domainAbsence: domain, policyAbsence: policy });
}

async function parseManagementDeleteActionRecord(
  value: unknown,
  action: 'management_custom_domain_delete' | 'management_admin_policy_delete' |
    'management_access_application_delete',
  journal: UninstallJournal,
): Promise<ManagementDeleteActionRecord | null> {
  if (!isRecord(value) || !exactKeys(value, ['schemaVersion', 'kind', 'action', 'attempts']) ||
    value.schemaVersion !== 1 || value.kind !== 'uninstall_management_delete' ||
    value.action !== action || !Array.isArray(value.attempts) || value.attempts.length < 1 ||
    value.attempts.length > MAX_MANAGEMENT_DELETE_ATTEMPTS) return null;
  const expectedPrerequisites = expectedManagementPrerequisites(journal, action);
  if (!expectedPrerequisites) return null;
  const attempts: ManagementDeleteAttempt[] = [];
  let previousDomainPreflightIndex = -1;
  for (const raw of value.attempts) {
    if (!isRecord(raw) || !exactKeys(raw, [
      'schemaVersion', 'prerequisites', 'intent', 'phase', 'arm', 'submission', 'recovery',
      'locator', 'preparedAt', 'sendArmedAt', 'submittedAt', 'submittedByAttemptId',
      'verifiedAt', 'verifiedByAttemptId',
    ]) || raw.schemaVersion !== 1 || !isRecord(raw.intent) ||
      typeof raw.intent.attemptId !== 'string' || ![
        'prepared', 'send_armed', 'submitted', 'verified', 'not_applied',
      ].includes(String(raw.phase))) return null;
    const originApproval = approvalByAttempt(journal, raw.intent.attemptId);
    const originContext = originApproval ? contextForAttempt(journal, originApproval.attemptId) : null;
    if (!originApproval || !originContext || !safeInteger(raw.preparedAt) ||
      raw.preparedAt < originApproval.recordedAt || raw.preparedAt >= originApproval.plan.expiresAt ||
      raw.preparedAt > journal.updatedAt) return null;
    const prerequisites = raw.prerequisites as HostedUninstallManagementDeletePrerequisites;
    if (action === 'management_custom_domain_delete') {
      if (!isRecord(prerequisites) || !('preflight' in prerequisites)) return null;
      const preflightIndex = journal.managementPreflightHistory.findIndex(
        (entry) => canonicalEqual(entry, prerequisites.preflight),
      );
      if (preflightIndex < 0 || preflightIndex <= previousDomainPreflightIndex ||
        !isRecord(prerequisites.preflight) || prerequisites.preflight.attemptId !== raw.intent.attemptId ||
        !safeInteger(prerequisites.preflight.checkedAt) || !safeInteger(prerequisites.preflight.expiresAt) ||
        raw.preparedAt < prerequisites.preflight.checkedAt || raw.preparedAt >= prerequisites.preflight.expiresAt ||
        raw.preparedAt - prerequisites.preflight.checkedAt > FRESH_PREFLIGHT_TTL_MS) return null;
      previousDomainPreflightIndex = preflightIndex;
    } else if (!canonicalEqual(prerequisites, expectedPrerequisites)) return null;
    const intent = await parseHostedUninstallManagementDeleteIntent(originContext, prerequisites, raw.intent);
    if (!intent || intent.kind !== action || attempts.some(
      (attempt) => attempt.intent.attemptId === intent.attemptId,
    )) return null;
    const arm = raw.arm === null ? null : await parseHostedUninstallManagementDeleteArm(
      originContext,
      intent,
      prerequisites,
      raw.arm,
    );
    if (raw.arm !== null && !arm) return null;
    const submission = raw.submission === null ? null : arm
      ? await parseHostedUninstallManagementDeleteSubmission(
        originContext,
        intent,
        prerequisites,
        arm,
        raw.submission,
      )
      : null;
    if (raw.submission !== null && !submission) return null;
    const phase = raw.phase as UninstallManagementDeletePhase;
    const armed = phase !== 'prepared';
    const submitted = phase === 'submitted' ||
      ((phase === 'verified' || phase === 'not_applied') && submission !== null);
    const terminal = phase === 'verified' || phase === 'not_applied';
    const submittedApproval = typeof raw.submittedByAttemptId === 'string'
      ? approvalByAttempt(journal, raw.submittedByAttemptId)
      : null;
    const verifiedApproval = typeof raw.verifiedByAttemptId === 'string'
      ? approvalByAttempt(journal, raw.verifiedByAttemptId)
      : null;
    const originApprovalIndex = approvalIndexByAttempt(journal, intent.attemptId);
    const submittedApprovalIndex = typeof raw.submittedByAttemptId === 'string'
      ? approvalIndexByAttempt(journal, raw.submittedByAttemptId)
      : -1;
    const verifiedApprovalIndex = typeof raw.verifiedByAttemptId === 'string'
      ? approvalIndexByAttempt(journal, raw.verifiedByAttemptId)
      : -1;
    if (armed !== Boolean(arm) || submitted !== Boolean(submission) ||
      safeInteger(raw.sendArmedAt) !== armed || safeInteger(raw.submittedAt) !== submitted ||
      safeInteger(raw.verifiedAt) !== terminal ||
      submitted !== Boolean(submittedApproval) || terminal !== Boolean(verifiedApproval) ||
      (!submitted && raw.submittedByAttemptId !== null) ||
      (submitted && raw.submittedByAttemptId !== intent.attemptId) ||
      (!terminal && raw.verifiedByAttemptId !== null) ||
      (submitted && submittedApprovalIndex < originApprovalIndex) ||
      (terminal && verifiedApprovalIndex < (submitted ? submittedApprovalIndex : originApprovalIndex)) ||
      (armed && (raw.sendArmedAt !== arm?.armedAt || (raw.sendArmedAt as number) < raw.preparedAt)) ||
      (submitted && (raw.submittedAt as number) < (raw.sendArmedAt as number)) ||
      (terminal && (raw.verifiedAt as number) <
        ((raw.submittedAt ?? raw.sendArmedAt) as number)) ||
      (submitted && ((raw.submittedAt as number) <
        (submittedApproval as UninstallJournalApproval).recordedAt ||
        (raw.submittedAt as number) >= (submittedApproval as UninstallJournalApproval).plan.expiresAt)) ||
      (terminal && ((raw.verifiedAt as number) <
        (verifiedApproval as UninstallJournalApproval).recordedAt ||
        (raw.verifiedAt as number) >= (verifiedApproval as UninstallJournalApproval).plan.expiresAt)) ||
      [raw.sendArmedAt, raw.submittedAt, raw.verifiedAt].some(
        (time) => typeof time === 'number' && time > journal.updatedAt,
      ) || (arm && action === 'management_custom_domain_delete' &&
        (arm.armedAt >= (prerequisites as Extract<HostedUninstallManagementDeletePrerequisites, {
          readonly action: 'management_custom_domain_delete';
        }>).preflight.expiresAt ||
        arm.armedAt - (prerequisites as Extract<HostedUninstallManagementDeletePrerequisites, {
          readonly action: 'management_custom_domain_delete';
        }>).preflight.checkedAt > FRESH_PREFLIGHT_TTL_MS))) return null;
    let recovery: HostedUninstallManagementStillPresentEvidence | null = null;
    let locator: HostedUninstallManagementAbsenceEvidence | null = null;
    if (phase === 'not_applied') {
      if (!arm || raw.locator !== null || !isRecord(raw.recovery) ||
        typeof raw.recovery.attemptId !== 'string') return null;
      const recoveryContext = contextForAttempt(journal, raw.recovery.attemptId);
      const parsed = recoveryContext
        ? await parseHostedUninstallManagementDeleteRecoveryEvidence(
          recoveryContext,
          intent,
          arm,
          prerequisites,
          raw.recovery,
        )
        : null;
      if (!parsed || parsed.status !== 'still_present' ||
        parsed.attemptId !== raw.verifiedByAttemptId) return null;
      recovery = parsed;
    } else if (phase === 'verified') {
      if (!arm || raw.recovery !== null || !isRecord(raw.locator) ||
        typeof raw.locator.attemptId !== 'string') return null;
      const evidenceContext = contextForAttempt(journal, raw.locator.attemptId);
      locator = evidenceContext ? await parseHostedUninstallManagementAbsenceEvidence(
        evidenceContext,
        intent,
        prerequisites,
        raw.locator,
      ) : null;
      if (!locator || locator.attemptId !== raw.verifiedByAttemptId) return null;
    } else if (raw.recovery !== null || raw.locator !== null) return null;
    const previous = attempts[attempts.length - 1];
    if (previous && (previous.phase !== 'not_applied' ||
      raw.preparedAt < (previous.verifiedAt as number) ||
      originApprovalIndex < approvalIndexByAttempt(
        journal,
        previous.verifiedByAttemptId as string,
      ))) return null;
    attempts.push(deepFreeze({
      schemaVersion: 1,
      prerequisites,
      intent,
      phase,
      arm,
      submission,
      recovery,
      locator,
      preparedAt: raw.preparedAt as number,
      sendArmedAt: armed ? raw.sendArmedAt as number : null,
      submittedAt: submitted ? raw.submittedAt as number : null,
      submittedByAttemptId: submitted ? raw.submittedByAttemptId as string : null,
      verifiedAt: terminal ? raw.verifiedAt as number : null,
      verifiedByAttemptId: terminal ? raw.verifiedByAttemptId as string : null,
    }));
  }
  return deepFreeze({ schemaVersion: 1, kind: 'uninstall_management_delete', action, attempts });
}

async function parseManagementDeleteDraft(
  value: unknown,
  action: 'management_custom_domain_delete' | 'management_admin_policy_delete' |
    'management_access_application_delete',
  journal: UninstallJournal,
): Promise<ManagementDeleteActionDraft | null> {
  if (!isRecord(value) || !exactKeys(value, ['schemaVersion', 'kind', 'prerequisites', 'intent']) ||
    value.schemaVersion !== 1 || value.kind !== 'uninstall_management_delete' ||
    !isRecord(value.intent) || typeof value.intent.attemptId !== 'string') return null;
  const approval = activeApproval(journal);
  const prerequisites = expectedManagementPrerequisites(journal, action);
  if (!prerequisites || value.intent.attemptId !== approval.attemptId ||
    !canonicalEqual(value.prerequisites, prerequisites)) return null;
  const intent = await parseHostedUninstallManagementDeleteIntent(
    activeManagementContext(journal),
    prerequisites,
    value.intent,
  );
  return intent?.kind === action
    ? deepFreeze({ schemaVersion: 1, kind: 'uninstall_management_delete', prerequisites, intent })
    : null;
}

function managementDeleteActionSummary(record: ManagementDeleteActionRecord): Omit<
  UninstallJournalAction,
  'name' | 'record'
> {
  const attempt = record.attempts[record.attempts.length - 1];
  if (!attempt) invalid();
  if (attempt.phase === 'not_applied') {
    return {
      phase: attempt.submission ? 'submitted' : 'send_armed',
      locator: null,
      preparedAt: attempt.preparedAt,
      sendArmedAt: attempt.sendArmedAt,
      submittedAt: attempt.submittedAt,
      verifiedAt: null,
    };
  }
  return {
    phase: attempt.phase,
    locator: attempt.locator,
    preparedAt: attempt.preparedAt,
    sendArmedAt: attempt.sendArmedAt,
    submittedAt: attempt.submittedAt,
    verifiedAt: attempt.verifiedAt,
  };
}

function noManagedResidueMatchesVerifiedPrerequisites(
  journal: UninstallJournal,
  result: HostedUninstallManagementNoManagedResidueResult,
): boolean {
  const deletionEvidence = [
    verifiedAction(journal, 'management_custom_domain_delete')?.locator,
    verifiedAction(journal, 'management_admin_policy_delete')?.locator,
    verifiedAction(journal, 'management_access_application_delete')?.locator,
  ];
  const namespaceRetirement = verifiedAction(journal, 'admin_state_namespace_retired')?.locator;
  const workerDeletion = verifiedAction(journal, 'management_worker_delete')?.locator;
  return deletionEvidence.every((entry) => entry !== null && entry !== undefined) &&
    namespaceRetirement !== null && namespaceRetirement !== undefined &&
    workerDeletion !== null && workerDeletion !== undefined &&
    canonicalEqual(result.evidence.deletionEvidence, deletionEvidence) &&
    canonicalEqual(result.evidence.namespaceRetirement, namespaceRetirement) &&
    canonicalEqual(result.evidence.workerDeletion, workerDeletion);
}

async function parseNoManagedResidueDraft(
  value: unknown,
  journal: UninstallJournal,
): Promise<NoManagedResidueActionDraft | null> {
  if (!isRecord(value) || !exactKeys(value, ['schemaVersion', 'kind', 'result']) ||
    value.schemaVersion !== 1 || value.kind !== 'management_no_managed_residue' ||
    !isRecord(value.result) || typeof value.result.attemptId !== 'string' ||
    value.result.attemptId !== activeApproval(journal).attemptId) return null;
  const result = await parseHostedUninstallManagementNoManagedResidueResult(
    activeManagementContext(journal),
    value.result,
  );
  return result?.uninstallCycleId === journal.uninstallCycleId &&
    noManagedResidueMatchesVerifiedPrerequisites(journal, result)
    ? deepFreeze({ schemaVersion: 1, kind: 'management_no_managed_residue', result })
    : null;
}

function validPhaseTimes(value: {
  readonly phase: unknown;
  readonly preparedAt: unknown;
  readonly sendArmedAt: unknown;
  readonly submittedAt: unknown;
  readonly verifiedAt: unknown;
}, minimum: number, maximum: number): boolean {
  if (!['prepared', 'send_armed', 'submitted', 'verified'].includes(String(value.phase)) ||
    !safeInteger(value.preparedAt) || value.preparedAt < minimum || value.preparedAt > maximum) return false;
  const phase = value.phase as UninstallActionPhase;
  const armed = phase !== 'prepared';
  const submitted = phase === 'submitted' || phase === 'verified';
  const verified = phase === 'verified';
  return armed === safeInteger(value.sendArmedAt) && submitted === safeInteger(value.submittedAt) &&
    verified === safeInteger(value.verifiedAt) &&
    (!armed || (value.sendArmedAt as number) >= value.preparedAt) &&
    (!submitted || (value.submittedAt as number) >= (value.sendArmedAt as number)) &&
    (!verified || (value.verifiedAt as number) >= (value.submittedAt as number)) &&
    [value.sendArmedAt, value.submittedAt, value.verifiedAt].every(
      (time) => time === null || (safeInteger(time) && time <= maximum),
    );
}

async function workersDevRequestHash(enabled: boolean): Promise<string> {
  return sha256Hex(canonicalJson({ enabled, previews_enabled: false }));
}

async function parseWorkersDevMutation(
  value: unknown,
  enabled: boolean,
  journal: UninstallJournal,
): Promise<UninstallWorkersDevMutation | null> {
  const approvalAttemptId = isRecord(value) && typeof value.approvalAttemptId === 'string'
    ? value.approvalAttemptId
    : null;
  const approval = approvalAttemptId ? approvalByAttempt(journal, approvalAttemptId) : null;
  const phase = isRecord(value) && typeof value.phase === 'string'
    ? value.phase as UninstallWorkersDevPhase
    : null;
  const submittedByAttemptId = isRecord(value) && typeof value.submittedByAttemptId === 'string'
    ? value.submittedByAttemptId
    : null;
  const verifiedByAttemptId = isRecord(value) && typeof value.verifiedByAttemptId === 'string'
    ? value.verifiedByAttemptId
    : null;
  const submittedApproval = submittedByAttemptId
    ? approvalByAttempt(journal, submittedByAttemptId)
    : null;
  const verifiedApproval = verifiedByAttemptId
    ? approvalByAttempt(journal, verifiedByAttemptId)
    : null;
  const basePhaseValid = isRecord(value) && phase !== 'not_applied' && validPhaseTimes(
    value as Record<string, unknown> & {
      phase: unknown; preparedAt: unknown; sendArmedAt: unknown; submittedAt: unknown; verifiedAt: unknown;
    },
    journal.createdAt,
    journal.updatedAt,
  );
  const notAppliedPhaseValid = phase === 'not_applied' && isRecord(value) &&
    safeInteger(value.preparedAt) && safeInteger(value.sendArmedAt) &&
    value.submittedAt === null && safeInteger(value.verifiedAt) &&
    value.preparedAt >= journal.createdAt && value.sendArmedAt >= value.preparedAt &&
    value.verifiedAt >= value.sendArmedAt && value.verifiedAt <= journal.updatedAt;
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'kind', 'approvalAttemptId', 'accountId', 'workerName', 'uninstallCycleId',
    'enabled', 'previewsEnabled', 'requestHash', 'phase', 'locator', 'preparedAt',
    'sendArmedAt', 'submittedAt', 'submittedByAttemptId', 'verifiedAt', 'verifiedByAttemptId',
  ]) || value.schemaVersion !== 1 || value.kind !== 'uninstall_workers_dev' || value.enabled !== enabled ||
    value.previewsEnabled !== false || typeof value.approvalAttemptId !== 'string' ||
    !approval ||
    typeof value.accountId !== 'string' || typeof value.workerName !== 'string' ||
    typeof value.uninstallCycleId !== 'string' ||
    !lifecycleIdentityMatches({ ...value, workerId: workerIdentity(journal).workerId } as never, journal) ||
    typeof value.requestHash !== 'string' || value.requestHash !== await workersDevRequestHash(enabled) ||
    (!basePhaseValid && !notAppliedPhaseValid) ||
    (value.preparedAt as number) < approval.recordedAt ||
    !approvalWasActiveAt(journal, approval.attemptId, value.preparedAt as number) ||
    [value.preparedAt, value.sendArmedAt].some(
      (time) => typeof time === 'number' && time >= approval.plan.expiresAt,
    )) return null;
  const parsedPhase = phase as UninstallWorkersDevPhase;
  const submitted = parsedPhase === 'submitted' || parsedPhase === 'verified';
  const notApplied = parsedPhase === 'not_applied';
  const verified = parsedPhase === 'verified' || notApplied;
  const originApprovalIndex = approvalIndexByAttempt(journal, approval.attemptId);
  const submittedApprovalIndex = submittedByAttemptId
    ? approvalIndexByAttempt(journal, submittedByAttemptId)
    : -1;
  const verifiedApprovalIndex = verifiedByAttemptId
    ? approvalIndexByAttempt(journal, verifiedByAttemptId)
    : -1;
  if (submitted !== Boolean(submittedApproval) || verified !== Boolean(verifiedApproval) ||
    (!submitted && value.submittedByAttemptId !== null) ||
    (!verified && value.verifiedByAttemptId !== null) ||
    (submitted && submittedApprovalIndex < originApprovalIndex) ||
    (verified && verifiedApprovalIndex < (submitted ? submittedApprovalIndex : originApprovalIndex)) ||
    (submitted && ((value.submittedAt as number) < (submittedApproval as UninstallJournalApproval).recordedAt ||
      (value.submittedAt as number) >= (submittedApproval as UninstallJournalApproval).plan.expiresAt ||
      !approvalWasActiveAt(journal, submittedByAttemptId as string, value.submittedAt as number))) ||
    (verified && ((value.verifiedAt as number) < (verifiedApproval as UninstallJournalApproval).recordedAt ||
      (value.verifiedAt as number) >= (verifiedApproval as UninstallJournalApproval).plan.expiresAt ||
      !approvalWasActiveAt(journal, verifiedByAttemptId as string, value.verifiedAt as number)))) return null;
  let locator: { readonly enabled: boolean; readonly previewsEnabled: false } | null = null;
  if (submitted || notApplied) {
    if (!isRecord(value.locator) || !exactKeys(value.locator, ['enabled', 'previewsEnabled']) ||
      value.locator.enabled !== (notApplied ? !enabled : enabled) ||
      value.locator.previewsEnabled !== false) return null;
    locator = deepFreeze({ enabled: notApplied ? !enabled : enabled, previewsEnabled: false });
  } else if (value.locator !== null) return null;
  return deepFreeze({
    schemaVersion: 1,
    kind: 'uninstall_workers_dev',
    approvalAttemptId: value.approvalAttemptId,
    accountId: value.accountId,
    workerName: value.workerName,
    uninstallCycleId: value.uninstallCycleId,
    enabled,
    previewsEnabled: false,
    requestHash: value.requestHash,
    phase: parsedPhase,
    locator,
    preparedAt: value.preparedAt as number,
    sendArmedAt: parsedPhase === 'prepared' ? null : value.sendArmedAt as number,
    submittedAt: submitted ? value.submittedAt as number : null,
    submittedByAttemptId: submitted ? submittedByAttemptId : null,
    verifiedAt: verified ? value.verifiedAt as number : null,
    verifiedByAttemptId: verified ? verifiedByAttemptId : null,
  });
}

function latestDisableAttempt(
  attempt: Pick<CustomerGatewayRemoveRequestAttempt, 'disableAttempts'>,
): UninstallWorkersDevMutation | null {
  return attempt.disableAttempts[attempt.disableAttempts.length - 1] ?? null;
}

function customerAttemptCanBeFollowedByFreshCycle(
  attempt: CustomerGatewayRemoveRequestAttempt,
): boolean {
  if (
    attempt.enable.phase === 'not_applied' && attempt.enable.locator?.enabled === false &&
    attempt.requestPhase === 'prepared' && attempt.locator === null &&
    attempt.disableAttempts.length === 0
  ) return true;
  const disable = latestDisableAttempt(attempt);
  const requestCanBeRetried = (
    attempt.requestPhase === 'prepared' && attempt.locator === null
  ) || (
    attempt.requestPhase === 'submitted' && attempt.locator?.status === 'recovery_required' &&
    attempt.locator.freshGrantRequired === true
  );
  return disable?.phase === 'verified' && disable.locator?.enabled === false && requestCanBeRetried;
}

async function parseCustomerGatewayRemoveRecord(
  value: unknown,
  journal: UninstallJournal,
): Promise<CustomerGatewayRemoveActionRecord | null> {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'kind', 'accountId', 'zoneId', 'zoneName', 'workerName', 'installationId',
    'uninstallCycleId', 'attempts',
  ]) || value.schemaVersion !== 1 || value.kind !== 'customer_gateway_remove' ||
    value.accountId !== journal.installJournal.target.account.id ||
    value.zoneId !== journal.installJournal.target.zone.id || value.zoneName !== journal.installJournal.target.zone.name ||
    value.workerName !== journal.uninstallPlan.gateway.workerName ||
    value.installationId !== journal.installJournal.installationId || value.uninstallCycleId !== journal.uninstallCycleId ||
    !Array.isArray(value.attempts) || value.attempts.length < 1 ||
    value.attempts.length > MAX_CUSTOMER_REMOVE_CYCLES) return null;
  const attempts: CustomerGatewayRemoveRequestAttempt[] = [];
  for (const raw of value.attempts) {
    if (!isRecord(raw) || !exactKeys(raw, [
      'schemaVersion', 'approvalAttemptId', 'semantic', 'enable', 'requestPhase', 'locator', 'disableAttempts',
      'preparedAt', 'sendArmedAt', 'submittedAt', 'submittedByAttemptId', 'verifiedAt',
      'verifiedByAttemptId',
    ]) || raw.schemaVersion !== 1 || typeof raw.approvalAttemptId !== 'string') return null;
    const approval = approvalByAttempt(journal, raw.approvalAttemptId);
    const semantic = parseCustomerUninstallSemanticRecord(raw.semantic);
    const enable = await parseWorkersDevMutation(raw.enable, true, journal);
    const prior = attempts[attempts.length - 1];
    const priorTerminalAttemptId = prior?.enable.phase === 'not_applied'
      ? prior.enable.verifiedByAttemptId
      : prior ? latestDisableAttempt(prior)?.verifiedByAttemptId : null;
    const priorTerminalAt = prior?.enable.phase === 'not_applied'
      ? prior.enable.verifiedAt
      : prior ? latestDisableAttempt(prior)?.verifiedAt : null;
    if (!approval || !semantic || !enable || !await customerSemanticMatchesAuthority(semantic, journal) ||
      semantic.approvalAttemptId !== approval.attemptId ||
      enable.approvalAttemptId !== approval.attemptId || semantic.accountId !== value.accountId ||
      semantic.zoneId !== value.zoneId || semantic.zoneName !== value.zoneName ||
      semantic.workerName !== value.workerName || semantic.installationId !== value.installationId ||
      semantic.uninstallPlanId !== approval.plan.planId || semantic.uninstallPlanHash !== approval.plan.planHash ||
      semantic.authorityHash !== approval.plan.authorityHash || semantic.installBindingHash !== journal.installJournal.bindingHash ||
      semantic.installConvergenceHash !== installFinal(journal).convergenceHash ||
      semantic.rootReceiptChecksum !== installFinal(journal).customerReceiptEvidence.checksum ||
      semantic.adminStateNamespaceId !== installFinal(journal).adminStateNamespaceId ||
      semantic.accountWorkersSubdomain !== installedAccountWorkersSubdomain(journal) ||
      semantic.release.id !== journal.installJournal.releasePin.release ||
      semantic.release.artifactSha256 !== `sha256:${journal.installJournal.releasePin.artifactSha256}` ||
      semantic.expiresAt * 1_000 > approval.plan.expiresAt ||
      semantic.expiresAt * 1_000 > journal.recoverUntil ||
      semantic.issuedAt * 1_000 > (raw.preparedAt as number) ||
      semantic.expiresAt * 1_000 <= (raw.preparedAt as number) ||
      attempts.some((attempt) => attempt.approvalAttemptId === approval.attemptId ||
        attempt.semantic.requestId === semantic.requestId) ||
      (prior && !customerAttemptCanBeFollowedByFreshCycle(prior)) ||
      (priorTerminalAttemptId && approvalIndexByAttempt(journal, approval.attemptId) <
        approvalIndexByAttempt(journal, priorTerminalAttemptId)) ||
      (priorTerminalAt !== null && priorTerminalAt !== undefined &&
        (raw.preparedAt as number) < priorTerminalAt) ||
      raw.preparedAt !== enable.preparedAt ||
      !validPhaseTimes({
        phase: raw.requestPhase,
        preparedAt: raw.preparedAt,
        sendArmedAt: raw.sendArmedAt,
        submittedAt: raw.submittedAt,
        verifiedAt: raw.verifiedAt,
      }, approval.approvedAt, journal.updatedAt)) return null;
    const requestPhase = raw.requestPhase as UninstallActionPhase;
    const requestSubmitted = requestPhase === 'submitted' || requestPhase === 'verified';
    const requestVerified = requestPhase === 'verified';
    const submittedApproval = typeof raw.submittedByAttemptId === 'string'
      ? approvalByAttempt(journal, raw.submittedByAttemptId)
      : null;
    const verifiedApproval = typeof raw.verifiedByAttemptId === 'string'
      ? approvalByAttempt(journal, raw.verifiedByAttemptId)
      : null;
    const originApprovalIndex = approvalIndexByAttempt(journal, approval.attemptId);
    const submittedApprovalIndex = submittedApproval
      ? approvalIndexByAttempt(journal, submittedApproval.attemptId)
      : -1;
    const verifiedApprovalIndex = verifiedApproval
      ? approvalIndexByAttempt(journal, verifiedApproval.attemptId)
      : -1;
    if (requestPhase !== 'prepared' && (
      enable.phase !== 'verified' || (raw.sendArmedAt as number) < (enable.verifiedAt as number) ||
      (raw.sendArmedAt as number) >= semantic.expiresAt * 1_000
    )) return null;
    if (requestSubmitted !== Boolean(submittedApproval) || requestVerified !== Boolean(verifiedApproval) ||
      (!requestSubmitted && raw.submittedByAttemptId !== null) ||
      (!requestVerified && raw.verifiedByAttemptId !== null) ||
      (requestSubmitted && submittedApprovalIndex < originApprovalIndex) ||
      (requestVerified && verifiedApprovalIndex < submittedApprovalIndex) ||
      (requestSubmitted && ((raw.submittedAt as number) <
        (submittedApproval as UninstallJournalApproval).recordedAt ||
        (raw.submittedAt as number) >= (submittedApproval as UninstallJournalApproval).plan.expiresAt ||
        !approvalWasActiveAt(journal, raw.submittedByAttemptId as string, raw.submittedAt as number))) ||
      (requestVerified && ((raw.verifiedAt as number) <
        (verifiedApproval as UninstallJournalApproval).recordedAt ||
        (raw.verifiedAt as number) >= (verifiedApproval as UninstallJournalApproval).plan.expiresAt ||
        !approvalWasActiveAt(journal, raw.verifiedByAttemptId as string, raw.verifiedAt as number)))) return null;
    let locator: CustomerUninstallLocator | null = null;
    if (requestSubmitted) {
      locator = await parseCustomerUninstallLocator(raw.locator, semantic, journal.installJournal);
      if (!locator || (requestPhase === 'verified' && locator.status !== 'removed')) return null;
    } else if (raw.locator !== null) return null;
    if (!Array.isArray(raw.disableAttempts) ||
      raw.disableAttempts.length > MAX_WORKERS_DEV_DISABLE_ATTEMPTS) return null;
    const disableAttempts: UninstallWorkersDevMutation[] = [];
    const latestRequestActorIndex = requestVerified
      ? verifiedApprovalIndex
      : requestSubmitted
        ? submittedApprovalIndex
        : requestPhase === 'send_armed'
          ? originApprovalIndex
          : -1;
    for (const candidate of raw.disableAttempts) {
      const disable = await parseWorkersDevMutation(candidate, false, journal);
      const previousDisable = disableAttempts[disableAttempts.length - 1];
      const disableApproval = disable ? approvalByAttempt(journal, disable.approvalAttemptId) : null;
      if (!disable || !disableApproval || enable.phase !== 'verified' ||
        approvalIndexByAttempt(journal, disable.approvalAttemptId) < approvalIndexByAttempt(
          journal,
          enable.verifiedByAttemptId as string,
        ) ||
        approvalIndexByAttempt(journal, disable.approvalAttemptId) < latestRequestActorIndex ||
        disable.preparedAt < (enable.verifiedAt as number) ||
        (requestPhase !== 'prepared' && disableAttempts.length === 0 &&
          disable.preparedAt < (raw.sendArmedAt as number)) ||
        (requestPhase === 'prepared' && disableAttempts.length === 0 &&
          disable.approvalAttemptId === approval.attemptId &&
          disable.preparedAt < semantic.expiresAt * 1_000) ||
        disable.preparedAt < disableApproval.recordedAt ||
        disableAttempts.some((entry) => entry.approvalAttemptId === disable.approvalAttemptId) ||
        (previousDisable && (previousDisable.phase !== 'not_applied' ||
          previousDisable.locator?.enabled !== true ||
          disable.approvalAttemptId === previousDisable.approvalAttemptId ||
          approvalIndexByAttempt(journal, disable.approvalAttemptId) < approvalIndexByAttempt(
            journal,
            previousDisable.verifiedByAttemptId as string,
          ) ||
          disable.preparedAt < (previousDisable.verifiedAt as number)))) return null;
      disableAttempts.push(disable);
    }
    if (enable.phase === 'not_applied' && (
      requestPhase !== 'prepared' || raw.locator !== null || disableAttempts.length !== 0
    )) return null;
    attempts.push(deepFreeze({
      schemaVersion: 1,
      approvalAttemptId: approval.attemptId,
      semantic,
      enable,
      requestPhase,
      locator,
      disableAttempts,
      preparedAt: raw.preparedAt as number,
      sendArmedAt: requestPhase === 'prepared' ? null : raw.sendArmedAt as number,
      submittedAt: requestSubmitted ? raw.submittedAt as number : null,
      submittedByAttemptId: requestSubmitted ? raw.submittedByAttemptId as string : null,
      verifiedAt: requestPhase === 'verified' ? raw.verifiedAt as number : null,
      verifiedByAttemptId: requestVerified ? raw.verifiedByAttemptId as string : null,
    }));
  }
  return deepFreeze({
    schemaVersion: 1,
    kind: 'customer_gateway_remove',
    accountId: value.accountId,
    zoneId: value.zoneId,
    zoneName: value.zoneName,
    workerName: value.workerName,
    installationId: value.installationId,
    uninstallCycleId: value.uninstallCycleId,
    attempts,
  });
}

function customerActionSummary(record: CustomerGatewayRemoveActionRecord): Omit<
  UninstallJournalAction,
  'name' | 'record'
> {
  const attempt = record.attempts[record.attempts.length - 1];
  if (!attempt) invalid();
  const disable = latestDisableAttempt(attempt);
  const removed = attempt.requestPhase === 'verified' && attempt.locator?.status === 'removed';
  const disabled = disable?.phase === 'verified' && disable.locator?.enabled === false;
  if (removed && disabled) {
    return {
      phase: 'verified',
      locator: attempt.locator,
      preparedAt: attempt.preparedAt,
      sendArmedAt: attempt.sendArmedAt,
      submittedAt: attempt.submittedAt,
      verifiedAt: Math.max(attempt.verifiedAt as number, disable?.verifiedAt as number),
    };
  }
  const eventTimes = [
    attempt.enable.sendArmedAt, attempt.enable.submittedAt, attempt.enable.verifiedAt,
    attempt.sendArmedAt, attempt.submittedAt, attempt.verifiedAt,
    ...attempt.disableAttempts.flatMap((entry) => [
      entry.sendArmedAt, entry.submittedAt, entry.verifiedAt,
    ]),
  ].filter((time): time is number => typeof time === 'number');
  const phase: UninstallActionPhase = attempt.requestPhase === 'submitted' || attempt.requestPhase === 'verified'
    ? 'submitted'
    : attempt.requestPhase === 'send_armed' || attempt.enable.phase !== 'prepared' ||
        attempt.disableAttempts.length > 0
      ? 'send_armed'
      : 'prepared';
  return {
    phase,
    locator: attempt.locator,
    preparedAt: attempt.preparedAt,
    sendArmedAt: phase === 'prepared' ? null : Math.min(...eventTimes),
    submittedAt: phase === 'submitted' ? attempt.submittedAt : null,
    verifiedAt: null,
  };
}

async function parseActionRecord(
  name: UninstallActionName,
  value: unknown,
  journal: UninstallJournal,
): Promise<UninstallActionRecord | null> {
  if (name === 'cleanup_worker_version_create') return parseVersionActionRecord(value, 'cleanup', journal);
  if (name === 'retirement_worker_version_create') return parseVersionActionRecord(value, 'retirement', journal);
  if (name === 'cleanup_worker_deployment_create') return parseDeploymentActionRecord(value, 'cleanup', journal);
  if (name === 'restore_clean_worker_deployment') return parseDeploymentActionRecord(value, 'restore_clean', journal);
  if (name === 'retirement_worker_deployment_create') return parseDeploymentActionRecord(value, 'retirement', journal);
  if (name === 'customer_gateway_remove') return parseCustomerGatewayRemoveRecord(value, journal);
  if (name === 'management_custom_domain_delete' || name === 'management_admin_policy_delete' ||
    name === 'management_access_application_delete') {
    return parseManagementDeleteActionRecord(value, name, journal);
  }
  if (name === 'admin_state_namespace_retired') {
    if (!isRecord(value) || !exactKeys(value, ['schemaVersion', 'kind', 'proof']) ||
      value.schemaVersion !== 1 || value.kind !== name) return null;
    const proof = parseAdminStateNamespaceRetirementProof(value.proof);
    const retirement = verifiedAction(journal, 'retirement_worker_version_create')?.locator;
    if (!proof || !lifecycleIdentityMatches(proof, journal) || proof.namespaceId !== workerIdentity(journal).namespaceId ||
      !retirement || !('kind' in retirement) || retirement.kind !== 'uninstall_worker_version' ||
      proof.retirementVersionId !== retirement.versionId) return null;
    return deepFreeze({ schemaVersion: 1, kind: name, proof });
  }
  if (name === 'management_worker_delete') {
    if (!isRecord(value) || !exactKeys(value, ['schemaVersion', 'kind', 'intent', 'submission']) ||
      value.schemaVersion !== 1 || value.kind !== name) return null;
    const intent = await parseWorkerDeleteMutationIntent(value.intent);
    const namespace = verifiedAction(journal, 'admin_state_namespace_retired')?.locator;
    if (!intent || !lifecycleIdentityMatches(intent, journal) ||
      !namespace || !('kind' in namespace) || namespace.kind !== 'admin_state_namespace_retirement' ||
      !canonicalEqual(intent.retirementProof, namespace)) return null;
    const submission = value.submission === null ? null :
      parseLifecycleSubmission(value.submission, 'uninstall_worker_delete', journal);
    if (value.submission !== null && (!submission || submission.requestHash !== intent.requestHash ||
      submission.retirementProofCommitment !== intent.retirementProofCommitment)) return null;
    return deepFreeze({ schemaVersion: 1, kind: name, intent, submission });
  }
  if (name === 'management_no_managed_residue') {
    if (!isRecord(value) || !exactKeys(value, [
      'schemaVersion', 'kind', 'result', 'preparedByAttemptId', 'armedByAttemptId',
      'submittedByAttemptId', 'verifiedByAttemptId',
    ]) ||
      value.schemaVersion !== 1 || value.kind !== name || !isRecord(value.result) ||
      typeof value.result.attemptId !== 'string' || typeof value.preparedByAttemptId !== 'string' ||
      value.preparedByAttemptId !== value.result.attemptId ||
      ![value.armedByAttemptId, value.submittedByAttemptId, value.verifiedByAttemptId].every(
        (attemptId) => attemptId === null ||
          (typeof attemptId === 'string' && approvalByAttempt(journal, attemptId) !== null),
      )) return null;
    const context = contextForAttempt(journal, value.result.attemptId);
    const result = context ? await parseHostedUninstallManagementNoManagedResidueResult(context, value.result) : null;
    if (!result || result.uninstallCycleId !== journal.uninstallCycleId ||
      !noManagedResidueMatchesVerifiedPrerequisites(journal, result)) return null;
    return deepFreeze({
      schemaVersion: 1,
      kind: name,
      result,
      preparedByAttemptId: value.preparedByAttemptId,
      armedByAttemptId: value.armedByAttemptId as string | null,
      submittedByAttemptId: value.submittedByAttemptId as string | null,
      verifiedByAttemptId: value.verifiedByAttemptId as string | null,
    });
  }
  if (name === 'uninstall_final_convergence') {
    if (!isRecord(value) || !exactKeys(value, ['schemaVersion', 'kind', 'convergenceHash']) ||
      value.schemaVersion !== 1 || value.kind !== name || typeof value.convergenceHash !== 'string' ||
      !PREFIXED_SHA256.test(value.convergenceHash)) return null;
    const expected = await finalConvergenceProjection(journal);
    return value.convergenceHash === expected.record.convergenceHash ? expected.record : null;
  }
  return null;
}

function actionPrerequisites(journal: UninstallJournal, name: UninstallActionName): boolean {
  const index = UNINSTALL_ACTION_ORDER.indexOf(name);
  if (index <= 0 || journal.actions.length !== index) return false;
  return journal.actions.slice(0, index).every((action) => action.phase === 'verified');
}

export interface PrepareUninstallJournalActionInput extends UninstallJournalCasInput {
  readonly action: Exclude<UninstallActionName, 'uninstall_fresh_preflight' | 'customer_gateway_remove'>;
  readonly record: unknown;
}

export interface TransitionUninstallJournalActionInput extends UninstallJournalCasInput {
  readonly action: Exclude<UninstallActionName, 'uninstall_fresh_preflight' | 'customer_gateway_remove'>;
  readonly value?: unknown;
}

export interface AppendUninstallManagementDeleteAttemptInput extends UninstallJournalCasInput {
  readonly action: ManagementDeleteActionName;
  readonly prerequisites: unknown;
  readonly intent: unknown;
}

function replaceAction(
  journal: UninstallJournal,
  index: number,
  action: UninstallJournalAction,
  now: number,
): UninstallJournal {
  const actions = [...journal.actions];
  actions[index] = deepFreeze(action);
  return replaceJournal(journal, now, { actions: Object.freeze(actions) });
}

export type ManagementDeleteActionName = Extract<UninstallActionName,
  'management_custom_domain_delete' | 'management_admin_policy_delete' |
  'management_access_application_delete'>;

function isManagementDeleteActionName(value: UninstallActionName): value is ManagementDeleteActionName {
  return value === 'management_custom_domain_delete' || value === 'management_admin_policy_delete' ||
    value === 'management_access_application_delete';
}

function preparedManagementDeleteAttempt(
  draft: ManagementDeleteActionDraft,
  now: number,
): ManagementDeleteAttempt {
  return deepFreeze({
    schemaVersion: 1,
    prerequisites: draft.prerequisites,
    intent: draft.intent,
    phase: 'prepared',
    arm: null,
    submission: null,
    recovery: null,
    locator: null,
    preparedAt: now,
    sendArmedAt: null,
    submittedAt: null,
    submittedByAttemptId: null,
    verifiedAt: null,
    verifiedByAttemptId: null,
  });
}

function requireFreshDomainDeleteDraft(
  journal: UninstallJournal,
  draft: ManagementDeleteActionDraft,
  attemptId: string,
  now: number,
): void {
  if (draft.intent.kind !== 'management_custom_domain_delete') return;
  const latest = journal.managementPreflightHistory[journal.managementPreflightHistory.length - 1];
  if (!latest || draft.intent.attemptId !== attemptId || latest.attemptId !== attemptId ||
    !canonicalEqual(draft.prerequisites, {
      schemaVersion: 1,
      action: 'management_custom_domain_delete',
      preflight: latest,
    }) || now < latest.checkedAt || now >= latest.expiresAt ||
    now - latest.checkedAt > FRESH_PREFLIGHT_TTL_MS) conflict();
}

export async function prepareUninstallJournalAction(
  journal: UninstallJournal,
  input: PrepareUninstallJournalActionInput,
): Promise<UninstallJournal> {
  cas(journal, input, true);
  if (!actionPrerequisites(journal, input.action)) conflict();
  const context = { ...journal, updatedAt: input.now } as UninstallJournal;
  let record: UninstallActionRecord;
  if (isManagementDeleteActionName(input.action)) {
    const draft = await parseManagementDeleteDraft(input.record, input.action, context);
    if (!draft) invalid(400);
    requireFreshDomainDeleteDraft(journal, draft, input.attemptId, input.now);
    record = deepFreeze({
      schemaVersion: 1,
      kind: 'uninstall_management_delete',
      action: input.action,
      attempts: [preparedManagementDeleteAttempt(draft, input.now)],
    });
  } else if (input.action === 'management_no_managed_residue') {
    const draft = await parseNoManagedResidueDraft(input.record, context);
    if (!draft) invalid(400);
    record = deepFreeze({
      ...draft,
      preparedByAttemptId: input.attemptId,
      armedByAttemptId: null,
      submittedByAttemptId: null,
      verifiedByAttemptId: null,
    });
  } else {
    const parsed = await parseActionRecord(input.action, input.record, context);
    if (!parsed) invalid(400);
    record = parsed;
  }
  const action = deepFreeze({
    name: input.action,
    phase: 'prepared' as const,
    record,
    locator: null,
    preparedAt: input.now,
    sendArmedAt: null,
    submittedAt: null,
    verifiedAt: null,
  });
  return replaceJournal(journal, input.now, { actions: Object.freeze([...journal.actions, action]) });
}

export async function replacePreparedUninstallJournalAction(
  journal: UninstallJournal,
  input: PrepareUninstallJournalActionInput,
): Promise<UninstallJournal> {
  cas(journal, input, true);
  const index = UNINSTALL_ACTION_ORDER.indexOf(input.action);
  const existing = journal.actions[index];
  if (!existing || existing.phase !== 'prepared' || index !== journal.actions.length - 1) conflict();
  const context = { ...journal, updatedAt: input.now } as UninstallJournal;
  let record: UninstallActionRecord;
  if (isManagementDeleteActionName(input.action)) {
    if (!('kind' in existing.record) || existing.record.kind !== 'uninstall_management_delete' ||
      existing.record.action !== input.action ||
      existing.record.attempts[existing.record.attempts.length - 1]?.phase !== 'prepared') conflict();
    const draft = await parseManagementDeleteDraft(input.record, input.action, context);
    if (!draft) invalid(400);
    requireFreshDomainDeleteDraft(journal, draft, input.attemptId, input.now);
    record = deepFreeze({
      ...existing.record,
      attempts: Object.freeze([
        ...existing.record.attempts.slice(0, -1),
        preparedManagementDeleteAttempt(draft, input.now),
      ]),
    });
  } else if (input.action === 'management_no_managed_residue') {
    const draft = await parseNoManagedResidueDraft(input.record, context);
    if (!draft) invalid(400);
    record = deepFreeze({
      ...draft,
      preparedByAttemptId: input.attemptId,
      armedByAttemptId: null,
      submittedByAttemptId: null,
      verifiedByAttemptId: null,
    });
  } else {
    const parsed = await parseActionRecord(input.action, input.record, context);
    if (!parsed) invalid(400);
    record = parsed;
  }
  return replaceAction(journal, index, {
    name: input.action,
    phase: 'prepared',
    record,
    locator: null,
    preparedAt: input.now,
    sendArmedAt: null,
    submittedAt: null,
    verifiedAt: null,
  }, input.now);
}

export async function appendUninstallManagementDeleteAttempt(
  journal: UninstallJournal,
  input: AppendUninstallManagementDeleteAttemptInput,
): Promise<UninstallJournal> {
  cas(journal, input, true);
  const index = UNINSTALL_ACTION_ORDER.indexOf(input.action);
  const action = journal.actions[index];
  if (!action || index !== journal.actions.length - 1 || !('kind' in action.record) ||
    action.record.kind !== 'uninstall_management_delete' || action.record.action !== input.action ||
    action.record.attempts.length >= MAX_MANAGEMENT_DELETE_ATTEMPTS) conflict();
  const previous = action.record.attempts[action.record.attempts.length - 1];
  if (!previous || previous.phase !== 'not_applied') conflict();
  const draft = await parseManagementDeleteDraft({
    schemaVersion: 1,
    kind: 'uninstall_management_delete',
    prerequisites: input.prerequisites,
    intent: input.intent,
  }, input.action, { ...journal, updatedAt: input.now } as UninstallJournal);
  if (!draft || draft.intent.attemptId === previous.intent.attemptId) invalid(400);
  requireFreshDomainDeleteDraft(journal, draft, input.attemptId, input.now);
  const record = deepFreeze({
    ...action.record,
    attempts: Object.freeze([
      ...action.record.attempts,
      preparedManagementDeleteAttempt(draft, input.now),
    ]),
  });
  return replaceAction(journal, index, {
    name: input.action,
    record,
    ...managementDeleteActionSummary(record),
  }, input.now);
}

export async function attachUninstallWorkerVersionRecovery(
  journal: UninstallJournal,
  input: UninstallJournalCasInput & {
    readonly action: 'cleanup_worker_version_create' | 'retirement_worker_version_create';
    readonly recovery: unknown;
  },
): Promise<UninstallJournal> {
  cas(journal, input, true);
  const index = UNINSTALL_ACTION_ORDER.indexOf(input.action);
  const action = journal.actions[index];
  if (!action || action.phase !== 'prepared' || !('kind' in action.record) ||
    action.record.kind !== 'uninstall_worker_version_create' || action.record.recovery !== null) conflict();
  const candidate = { ...action.record, recovery: input.recovery };
  const parsed = await parseVersionActionRecord(
    candidate,
    input.action === 'cleanup_worker_version_create' ? 'cleanup' : 'retirement',
    journal,
  );
  if (!parsed?.recovery) invalid(400);
  return replaceAction(journal, index, { ...action, record: parsed }, input.now);
}

export async function armUninstallJournalAction(
  journal: UninstallJournal,
  input: TransitionUninstallJournalActionInput,
): Promise<UninstallJournal> {
  cas(journal, input, true);
  const index = UNINSTALL_ACTION_ORDER.indexOf(input.action);
  const action = journal.actions[index];
  if (!action || action.phase !== 'prepared' ||
    !journal.actions.slice(0, index).every((entry) => entry.phase === 'verified')) conflict();
  if (input.action === 'cleanup_worker_version_create') {
    const preflight = journal.actions[0]?.record;
    if (!preflight || !('expiresAt' in preflight) || input.now >= preflight.expiresAt ||
      input.now - preflight.checkedAt > FRESH_PREFLIGHT_TTL_MS) conflict();
  }
  let record = action.record;
  if ('kind' in record && record.kind === 'uninstall_worker_version_create' && !record.recovery) conflict();
  if ('kind' in record && record.kind === 'uninstall_management_delete') {
    const attempt = record.attempts[record.attempts.length - 1];
    if (!attempt || attempt.phase !== 'prepared' || attempt.intent.attemptId !== input.attemptId ||
      input.value === undefined) conflict();
    if (attempt.intent.kind === 'management_custom_domain_delete') {
      const latest = journal.managementPreflightHistory[
        journal.managementPreflightHistory.length - 1
      ];
      if (
        !latest || latest.attemptId !== input.attemptId ||
        !canonicalEqual(attempt.prerequisites, {
          schemaVersion: 1,
          action: 'management_custom_domain_delete',
          preflight: latest,
        }) || input.now < latest.checkedAt || input.now >= latest.expiresAt ||
        input.now - latest.checkedAt > FRESH_PREFLIGHT_TTL_MS
      ) conflict();
    }
    const arm = await parseHostedUninstallManagementDeleteArm(
      activeManagementContext(journal),
      attempt.intent,
      attempt.prerequisites,
      input.value,
    );
    if (!arm || arm.armedAt !== input.now) invalid(400);
    const armedAttempt = deepFreeze({
      ...attempt,
      phase: 'send_armed' as const,
      arm,
      sendArmedAt: input.now,
    });
    record = deepFreeze({
      ...record,
      attempts: Object.freeze([...record.attempts.slice(0, -1), armedAttempt]),
    });
  } else if ('kind' in record && record.kind === 'management_no_managed_residue') {
    if (input.value !== undefined || record.armedByAttemptId !== null) conflict();
    record = deepFreeze({ ...record, armedByAttemptId: input.attemptId });
  } else if (input.value !== undefined) invalid(400);
  return replaceAction(journal, index, {
    ...action,
    record,
    phase: 'send_armed',
    sendArmedAt: input.now,
  }, input.now);
}

async function parseActionSubmission(
  journal: UninstallJournal,
  action: UninstallJournalAction,
  value: unknown,
  now: number,
  attemptId: string,
): Promise<{ readonly record: UninstallActionRecord; readonly locator: UninstallActionLocator | null } | null> {
  if (!('kind' in action.record)) return null;
  if (action.record.kind === 'uninstall_worker_version_create') {
    const submission = parseLifecycleSubmission(value, 'uninstall_worker_version', journal);
    return submission && submission.stage === action.record.stage && action.record.recovery &&
      submission.requestHash === action.record.recovery.requestHash
      ? { record: action.record, locator: submission }
      : null;
  }
  if (action.record.kind === 'uninstall_worker_deployment_create') {
    const submission = parseLifecycleSubmission(value, 'uninstall_worker_deployment', journal);
    return submission && submission.stage === action.record.stage &&
      submission.versionId === action.record.intent.versionId &&
      submission.requestHash === action.record.intent.requestHash
      ? { record: action.record, locator: submission }
      : null;
  }
  if (action.record.kind === 'uninstall_management_delete') {
    const attempt = action.record.attempts[action.record.attempts.length - 1];
    const submission = attempt?.phase === 'send_armed' && attempt.arm &&
      attempt.intent.attemptId === attemptId
      ? await parseHostedUninstallManagementDeleteSubmission(
      activeManagementContext(journal),
      attempt.intent,
      attempt.prerequisites,
      attempt.arm,
      value,
    ) : null;
    if (!attempt || !submission) return null;
    const submittedAttempt = deepFreeze({
      ...attempt,
      phase: 'submitted' as const,
      submission,
      submittedAt: now,
      submittedByAttemptId: attemptId,
    });
    return {
      record: deepFreeze({
        ...action.record,
        attempts: Object.freeze([...action.record.attempts.slice(0, -1), submittedAttempt]),
      }),
      locator: null,
    };
  }
  if (action.record.kind === 'admin_state_namespace_retired') {
    const proof = parseAdminStateNamespaceRetirementProof(value);
    return proof && canonicalEqual(proof, action.record.proof) ? { record: action.record, locator: proof } : null;
  }
  if (action.record.kind === 'management_worker_delete') {
    const submission = parseLifecycleSubmission(value, 'uninstall_worker_delete', journal);
    return submission && submission.requestHash === action.record.intent.requestHash &&
      submission.retirementProofCommitment === action.record.intent.retirementProofCommitment
      ? { record: deepFreeze({ ...action.record, submission }), locator: null }
      : null;
  }
  if (action.record.kind === 'management_no_managed_residue') {
    return canonicalEqual(value, action.record.result)
      ? { record: deepFreeze({ ...action.record, submittedByAttemptId: attemptId }),
        locator: action.record.result }
      : null;
  }
  if (action.record.kind === 'uninstall_final_convergence') {
    const prepared = await prepareUninstallFinalConvergenceRecordAndLocator(journal);
    return canonicalEqual(action.record, prepared.record) && canonicalEqual(value, prepared.locator)
      ? { record: prepared.record, locator: prepared.locator }
      : null;
  }
  return null;
}

export async function submitUninstallJournalAction(
  journal: UninstallJournal,
  input: TransitionUninstallJournalActionInput & { readonly value: unknown },
): Promise<UninstallJournal> {
  cas(journal, input, true);
  const index = UNINSTALL_ACTION_ORDER.indexOf(input.action);
  const action = journal.actions[index];
  if (!action || action.phase !== 'send_armed') conflict();
  const parsed = await parseActionSubmission(journal, action, input.value, input.now, input.attemptId);
  if (!parsed) invalid(400);
  return replaceAction(journal, index, {
    ...action,
    record: parsed.record,
    locator: parsed.locator,
    phase: 'submitted',
    submittedAt: input.now,
  }, input.now);
}

async function parseActionVerification(
  journal: UninstallJournal,
  action: UninstallJournalAction,
  value: unknown,
): Promise<UninstallActionLocator | null> {
  if (!('kind' in action.record)) return null;
  if (action.record.kind === 'uninstall_worker_version_create') {
    const parsed = parseLifecycleSubmission(value, 'uninstall_worker_version', journal);
    return parsed && canonicalEqual(parsed, action.locator) ? parsed : null;
  }
  if (action.record.kind === 'uninstall_worker_deployment_create') {
    const parsed = parseLifecycleSubmission(value, 'uninstall_worker_deployment', journal);
    return parsed && canonicalEqual(parsed, action.locator) ? parsed : null;
  }
  if (action.record.kind === 'uninstall_management_delete') {
    const attempt = action.record.attempts[action.record.attempts.length - 1];
    return attempt?.phase === 'submitted' ? await parseHostedUninstallManagementAbsenceEvidence(
      activeManagementContext(journal),
      attempt.intent,
      attempt.prerequisites,
      value,
    ) : null;
  }
  if (action.record.kind === 'admin_state_namespace_retired') {
    const proof = parseAdminStateNamespaceRetirementProof(value);
    return proof && canonicalEqual(proof, action.locator) ? proof : null;
  }
  if (action.record.kind === 'management_worker_delete') {
    const proof = parseWorkerDeletionRecoveryProof(value);
    return proof && lifecycleIdentityMatches(proof, journal) &&
      proof.requestHash === action.record.intent.requestHash &&
      proof.retirementProofCommitment === action.record.intent.retirementProofCommitment
      ? proof
      : null;
  }
  if (action.record.kind === 'management_no_managed_residue') {
    const context = contextForAttempt(journal, action.record.result.attemptId);
    const parsed = context ? await parseHostedUninstallManagementNoManagedResidueResult(context, value) : null;
    return parsed && canonicalEqual(parsed, action.record.result) ? parsed : null;
  }
  if (action.record.kind === 'uninstall_final_convergence') {
    const prepared = await prepareUninstallFinalConvergenceRecordAndLocator(journal);
    return canonicalEqual(value, prepared.locator) ? prepared.locator : null;
  }
  return null;
}

export async function verifyUninstallJournalAction(
  journal: UninstallJournal,
  input: TransitionUninstallJournalActionInput & { readonly value: unknown },
): Promise<UninstallJournal> {
  cas(journal, input, true);
  const index = UNINSTALL_ACTION_ORDER.indexOf(input.action);
  const action = journal.actions[index];
  if (!action || action.phase !== 'submitted') conflict();
  const locator = await parseActionVerification(journal, action, input.value);
  if (!locator) invalid(400);
  let record = action.record;
  if ('kind' in record && record.kind === 'uninstall_management_delete') {
    const attempt = record.attempts[record.attempts.length - 1];
    if (!attempt || attempt.phase !== 'submitted' || !('status' in locator) || locator.status !== 'absent') {
      conflict();
    }
    const verifiedAttempt = deepFreeze({
      ...attempt,
      phase: 'verified' as const,
      locator: locator as HostedUninstallManagementAbsenceEvidence,
      verifiedAt: input.now,
      verifiedByAttemptId: input.attemptId,
    });
    record = deepFreeze({
      ...record,
      attempts: Object.freeze([...record.attempts.slice(0, -1), verifiedAttempt]),
    });
  } else if ('kind' in record && record.kind === 'management_no_managed_residue') {
    record = deepFreeze({ ...record, verifiedByAttemptId: input.attemptId });
  }
  return replaceAction(journal, index, {
    ...action,
    record,
    locator,
    phase: 'verified',
    verifiedAt: input.now,
  }, input.now);
}

export interface RecordUninstallManagementDeleteRecoveryInput extends UninstallJournalCasInput {
  readonly action: ManagementDeleteActionName;
  readonly evidence: unknown;
}

/**
 * Terminally records the exact read-only recovery of a durably armed DELETE.
 * Absence closes the top-level action without inventing a submission; exact
 * continued presence abandons that arm and permits one fresh approved attempt.
 */
export async function recordUninstallManagementDeleteRecovery(
  journal: UninstallJournal,
  input: RecordUninstallManagementDeleteRecoveryInput,
): Promise<UninstallJournal> {
  cas(journal, input, true);
  const index = UNINSTALL_ACTION_ORDER.indexOf(input.action);
  const action = journal.actions[index];
  if (!action || index !== journal.actions.length - 1 ||
    !['send_armed', 'submitted'].includes(action.phase) ||
    !('kind' in action.record) || action.record.kind !== 'uninstall_management_delete' ||
    action.record.action !== input.action) conflict();
  const attempt = action.record.attempts[action.record.attempts.length - 1];
  if (!attempt || !['send_armed', 'submitted'].includes(attempt.phase) || !attempt.arm) conflict();
  const evidence: HostedUninstallManagementDeleteRecoveryEvidence | null =
    await parseHostedUninstallManagementDeleteRecoveryEvidence(
      activeManagementContext(journal),
      attempt.intent,
      attempt.arm,
      attempt.prerequisites,
      input.evidence,
    );
  if (!evidence || evidence.attemptId !== input.attemptId) invalid(400);
  const recoveredAttempt: ManagementDeleteAttempt = evidence.status === 'absent'
    ? deepFreeze({
      ...attempt,
      phase: 'verified',
      recovery: null,
      locator: evidence,
      verifiedAt: input.now,
      verifiedByAttemptId: input.attemptId,
    })
    : deepFreeze({
      ...attempt,
      phase: 'not_applied',
      recovery: evidence,
      locator: null,
      verifiedAt: input.now,
      verifiedByAttemptId: input.attemptId,
    });
  const record = deepFreeze({
    ...action.record,
    attempts: Object.freeze([...action.record.attempts.slice(0, -1), recoveredAttempt]),
  });
  return replaceAction(journal, index, {
    name: input.action,
    record,
    ...managementDeleteActionSummary(record),
  }, input.now);
}

export interface AppendCustomerGatewayRemoveAttemptInput extends UninstallJournalCasInput {
  readonly semantic: unknown;
}

function customerActionIndex(): number {
  return UNINSTALL_ACTION_ORDER.indexOf('customer_gateway_remove');
}

function customerActionAndRecord(journal: UninstallJournal): {
  readonly index: number;
  readonly action: UninstallJournalAction;
  readonly record: CustomerGatewayRemoveActionRecord;
} {
  const index = customerActionIndex();
  const action = journal.actions[index];
  if (!action || !('kind' in action.record) || action.record.kind !== 'customer_gateway_remove') conflict();
  return { index, action, record: action.record };
}

function replaceCustomerAction(
  journal: UninstallJournal,
  record: CustomerGatewayRemoveActionRecord,
  now: number,
): UninstallJournal {
  const current = customerActionAndRecord(journal);
  return replaceAction(journal, current.index, {
    name: 'customer_gateway_remove',
    record,
    ...customerActionSummary(record),
  }, now);
}

export async function appendCustomerGatewayRemoveAttempt(
  journal: UninstallJournal,
  input: AppendCustomerGatewayRemoveAttemptInput,
): Promise<UninstallJournal> {
  cas(journal, input, true);
  const index = customerActionIndex();
  const existing = journal.actions[index];
  if ((!existing && !actionPrerequisites(journal, 'customer_gateway_remove')) ||
    (existing && (!('kind' in existing.record) || existing.record.kind !== 'customer_gateway_remove')) ||
    journal.actions.length > index + 1) conflict();
  const attempts = existing && 'kind' in existing.record && existing.record.kind === 'customer_gateway_remove'
    ? [...existing.record.attempts]
    : [];
  const prior = attempts[attempts.length - 1];
  if (attempts.length >= MAX_CUSTOMER_REMOVE_CYCLES ||
    (prior && !customerAttemptCanBeFollowedByFreshCycle(prior))) conflict();
  const semantic = parseCustomerUninstallSemanticRecord(input.semantic);
  const approval = activeApproval(journal);
  if (!semantic || semantic.approvalAttemptId !== input.attemptId || approval.attemptId !== input.attemptId ||
    semantic.issuedAt * 1_000 > input.now || semantic.expiresAt * 1_000 <= input.now) invalid(400);
  const identity = workerIdentity(journal);
  const enable: UninstallWorkersDevMutation = deepFreeze({
    schemaVersion: 1,
    kind: 'uninstall_workers_dev',
    approvalAttemptId: input.attemptId,
    accountId: identity.accountId,
    workerName: identity.workerName,
    uninstallCycleId: journal.uninstallCycleId,
    enabled: true,
    previewsEnabled: false,
    requestHash: await workersDevRequestHash(true),
    phase: 'prepared',
    locator: null,
    preparedAt: input.now,
    sendArmedAt: null,
    submittedAt: null,
    submittedByAttemptId: null,
    verifiedAt: null,
    verifiedByAttemptId: null,
  });
  const attempt: CustomerGatewayRemoveRequestAttempt = deepFreeze({
    schemaVersion: 1,
    approvalAttemptId: input.attemptId,
    semantic,
    enable,
    requestPhase: 'prepared',
    locator: null,
    disableAttempts: Object.freeze([]),
    preparedAt: input.now,
    sendArmedAt: null,
    submittedAt: null,
    submittedByAttemptId: null,
    verifiedAt: null,
    verifiedByAttemptId: null,
  });
  const candidate = {
    schemaVersion: 1 as const,
    kind: 'customer_gateway_remove' as const,
    accountId: identity.accountId,
    zoneId: journal.installJournal.target.zone.id,
    zoneName: journal.installJournal.target.zone.name,
    workerName: identity.workerName,
    installationId: journal.installJournal.installationId,
    uninstallCycleId: journal.uninstallCycleId,
    attempts: [...attempts, attempt],
  };
  const context = { ...journal, updatedAt: input.now } as UninstallJournal;
  const record = await parseCustomerGatewayRemoveRecord(candidate, context);
  if (!record) invalid(400);
  if (!existing) {
    const action = deepFreeze({
      name: 'customer_gateway_remove' as const,
      record,
      ...customerActionSummary(record),
    });
    return replaceJournal(journal, input.now, { actions: Object.freeze([...journal.actions, action]) });
  }
  return replaceCustomerAction(journal, record, input.now);
}

/** Replace a customer cycle whose workers.dev enable was durably prepared but never armed. */
export async function replacePreparedCustomerGatewayRemoveAttempt(
  journal: UninstallJournal,
  input: AppendCustomerGatewayRemoveAttemptInput,
): Promise<UninstallJournal> {
  cas(journal, input, true);
  const current = customerActionAndRecord(journal);
  const latest = current.record.attempts[current.record.attempts.length - 1];
  if (current.index !== journal.actions.length - 1 || current.action.phase !== 'prepared' ||
    !latest || latest.approvalAttemptId === input.attemptId || latest.enable.phase !== 'prepared' ||
    latest.requestPhase !== 'prepared' || latest.locator !== null || latest.disableAttempts.length !== 0) conflict();
  const semantic = parseCustomerUninstallSemanticRecord(input.semantic);
  const approval = activeApproval(journal);
  if (!semantic || approval.attemptId !== input.attemptId ||
    semantic.approvalAttemptId !== input.attemptId || semantic.issuedAt * 1_000 > input.now ||
    semantic.expiresAt * 1_000 <= input.now) invalid(400);
  const identity = workerIdentity(journal);
  const enable: UninstallWorkersDevMutation = deepFreeze({
    schemaVersion: 1,
    kind: 'uninstall_workers_dev',
    approvalAttemptId: input.attemptId,
    accountId: identity.accountId,
    workerName: identity.workerName,
    uninstallCycleId: journal.uninstallCycleId,
    enabled: true,
    previewsEnabled: false,
    requestHash: await workersDevRequestHash(true),
    phase: 'prepared',
    locator: null,
    preparedAt: input.now,
    sendArmedAt: null,
    submittedAt: null,
    submittedByAttemptId: null,
    verifiedAt: null,
    verifiedByAttemptId: null,
  });
  const replacement: CustomerGatewayRemoveRequestAttempt = deepFreeze({
    schemaVersion: 1,
    approvalAttemptId: input.attemptId,
    semantic,
    enable,
    requestPhase: 'prepared',
    locator: null,
    disableAttempts: Object.freeze([]),
    preparedAt: input.now,
    sendArmedAt: null,
    submittedAt: null,
    submittedByAttemptId: null,
    verifiedAt: null,
    verifiedByAttemptId: null,
  });
  const candidate = {
    ...current.record,
    attempts: [...current.record.attempts.slice(0, -1), replacement],
  };
  const parsed = await parseCustomerGatewayRemoveRecord(
    candidate,
    { ...journal, updatedAt: input.now } as UninstallJournal,
  );
  if (!parsed) invalid(400);
  return replaceCustomerAction(journal, parsed, input.now);
}

function replaceLatestCustomerAttempt(
  journal: UninstallJournal,
  transform: (attempt: CustomerGatewayRemoveRequestAttempt) => CustomerGatewayRemoveRequestAttempt,
  now: number,
): UninstallJournal {
  const { record } = customerActionAndRecord(journal);
  const attempts = [...record.attempts];
  const latest = attempts[attempts.length - 1];
  if (!latest) conflict();
  attempts[attempts.length - 1] = deepFreeze(transform(latest));
  return replaceCustomerAction(journal, deepFreeze({ ...record, attempts }), now);
}

export async function prepareCustomerGatewayWorkersDevDisable(
  journal: UninstallJournal,
  input: UninstallJournalCasInput,
): Promise<UninstallJournal> {
  cas(journal, input, true);
  const current = customerActionAndRecord(journal);
  const attempt = current.record.attempts[current.record.attempts.length - 1];
  const previousDisable = attempt ? latestDisableAttempt(attempt) : null;
  if (!attempt || attempt.enable.phase !== 'verified' ||
    attempt.disableAttempts.length >= MAX_WORKERS_DEV_DISABLE_ATTEMPTS ||
    (previousDisable && (previousDisable.phase !== 'not_applied' ||
      previousDisable.locator?.enabled !== true ||
      previousDisable.approvalAttemptId === input.attemptId)) ||
    (attempt.requestPhase === 'prepared' && input.attemptId === attempt.approvalAttemptId &&
      input.now < attempt.semantic.expiresAt * 1_000)) conflict();
  const identity = workerIdentity(journal);
  const requestHash = await workersDevRequestHash(false);
  const disable: UninstallWorkersDevMutation = deepFreeze({
    schemaVersion: 1,
    kind: 'uninstall_workers_dev',
    approvalAttemptId: input.attemptId,
    accountId: identity.accountId,
    workerName: identity.workerName,
    uninstallCycleId: journal.uninstallCycleId,
    enabled: false,
    previewsEnabled: false,
    requestHash,
    phase: 'prepared',
    locator: null,
    preparedAt: input.now,
    sendArmedAt: null,
    submittedAt: null,
    submittedByAttemptId: null,
    verifiedAt: null,
    verifiedByAttemptId: null,
  });
  return replaceLatestCustomerAttempt(journal, (entry) => ({
    ...entry,
    disableAttempts: Object.freeze([...entry.disableAttempts, disable]),
  }), input.now);
}

/** Replace a workers.dev disable that was durably prepared but never armed. */
export async function replacePreparedCustomerGatewayWorkersDevDisable(
  journal: UninstallJournal,
  input: UninstallJournalCasInput,
): Promise<UninstallJournal> {
  cas(journal, input, true);
  const current = customerActionAndRecord(journal);
  const attempt = current.record.attempts[current.record.attempts.length - 1];
  const previous = attempt ? latestDisableAttempt(attempt) : null;
  if (current.index !== journal.actions.length - 1 || !attempt || !previous ||
    previous.phase !== 'prepared' || previous.approvalAttemptId === input.attemptId) conflict();
  const identity = workerIdentity(journal);
  const replacement: UninstallWorkersDevMutation = deepFreeze({
    schemaVersion: 1,
    kind: 'uninstall_workers_dev',
    approvalAttemptId: input.attemptId,
    accountId: identity.accountId,
    workerName: identity.workerName,
    uninstallCycleId: journal.uninstallCycleId,
    enabled: false,
    previewsEnabled: false,
    requestHash: await workersDevRequestHash(false),
    phase: 'prepared',
    locator: null,
    preparedAt: input.now,
    sendArmedAt: null,
    submittedAt: null,
    submittedByAttemptId: null,
    verifiedAt: null,
    verifiedByAttemptId: null,
  });
  const attempts = [...current.record.attempts];
  attempts[attempts.length - 1] = deepFreeze({
    ...attempt,
    disableAttempts: Object.freeze([
      ...attempt.disableAttempts.slice(0, -1),
      replacement,
    ]),
  });
  const parsed = await parseCustomerGatewayRemoveRecord(
    { ...current.record, attempts },
    { ...journal, updatedAt: input.now } as UninstallJournal,
  );
  if (!parsed) invalid(400);
  return replaceCustomerAction(journal, parsed, input.now);
}

export async function armCustomerGatewayWorkersDev(
  journal: UninstallJournal,
  input: UninstallJournalCasInput & { readonly enabled: boolean },
): Promise<UninstallJournal> {
  cas(journal, input, true);
  const current = customerActionAndRecord(journal);
  const latest = current.record.attempts[current.record.attempts.length - 1];
  const mutation = input.enabled ? latest?.enable : latest ? latestDisableAttempt(latest) : null;
  if (!latest || !mutation || mutation.phase !== 'prepared' ||
    mutation.approvalAttemptId !== input.attemptId) conflict();
  return replaceLatestCustomerAttempt(journal, (attempt) => ({
    ...attempt,
    ...(input.enabled
      ? { enable: deepFreeze({ ...attempt.enable, phase: 'send_armed' as const, sendArmedAt: input.now }) }
      : { disableAttempts: Object.freeze(attempt.disableAttempts.map((entry, index) =>
          index === attempt.disableAttempts.length - 1
            ? deepFreeze({ ...entry, phase: 'send_armed' as const, sendArmedAt: input.now })
            : entry)) }),
  }), input.now);
}

export function submitCustomerGatewayWorkersDev(
  journal: UninstallJournal,
  input: UninstallJournalCasInput & {
    readonly enabled: boolean;
    readonly locator: unknown;
  },
): UninstallJournal {
  cas(journal, { expectedRevision: input.expectedRevision, attemptId: input.attemptId, now: input.now }, true);
  if (!isRecord(input.locator) || !exactKeys(input.locator, ['enabled', 'previewsEnabled']) ||
    input.locator.enabled !== input.enabled || input.locator.previewsEnabled !== false) invalid(400);
  const current = customerActionAndRecord(journal);
  const latest = current.record.attempts[current.record.attempts.length - 1];
  const mutation = input.enabled ? latest?.enable : latest ? latestDisableAttempt(latest) : null;
  if (!latest || !mutation || mutation.phase !== 'send_armed') conflict();
  const locator = deepFreeze({ enabled: input.enabled, previewsEnabled: false as const });
  return replaceLatestCustomerAttempt(journal, (attempt) => ({
    ...attempt,
    ...(input.enabled
      ? { enable: deepFreeze({ ...attempt.enable, phase: 'submitted' as const,
          locator, submittedAt: input.now, submittedByAttemptId: input.attemptId }) }
      : { disableAttempts: Object.freeze(attempt.disableAttempts.map((entry, index) =>
          index === attempt.disableAttempts.length - 1
            ? deepFreeze({ ...entry, phase: 'submitted' as const, locator, submittedAt: input.now,
              submittedByAttemptId: input.attemptId })
            : entry)) }),
  }), input.now);
}

export function verifyCustomerGatewayWorkersDev(
  journal: UninstallJournal,
  input: UninstallJournalCasInput & { readonly enabled: boolean },
): UninstallJournal {
  cas(journal, input, true);
  const current = customerActionAndRecord(journal);
  const latest = current.record.attempts[current.record.attempts.length - 1];
  const mutation = input.enabled ? latest?.enable : latest ? latestDisableAttempt(latest) : null;
  if (!latest || !mutation || mutation.phase !== 'submitted' || mutation.locator?.enabled !== input.enabled) conflict();
  return replaceLatestCustomerAttempt(journal, (attempt) => ({
    ...attempt,
    ...(input.enabled
      ? { enable: deepFreeze({ ...attempt.enable, phase: 'verified' as const, verifiedAt: input.now,
          verifiedByAttemptId: input.attemptId }) }
      : { disableAttempts: Object.freeze(attempt.disableAttempts.map((entry, index) =>
          index === attempt.disableAttempts.length - 1
            ? deepFreeze({ ...entry, phase: 'verified' as const, verifiedAt: input.now,
              verifiedByAttemptId: input.attemptId })
            : entry)) }),
  }), input.now);
}

/**
 * Settle an armed workers.dev mutation after a read proves the requested value
 * was not applied. The armed mutation is terminal and can never be replayed;
 * a fresh approval must append a new customer cycle or disable attempt.
 */
export function recordCustomerGatewayWorkersDevNotApplied(
  journal: UninstallJournal,
  input: UninstallJournalCasInput & {
    readonly enabled: boolean;
    readonly locator: unknown;
  },
): UninstallJournal {
  cas(journal, input, true);
  if (!isRecord(input.locator) || !exactKeys(input.locator, ['enabled', 'previewsEnabled']) ||
    input.locator.enabled !== !input.enabled || input.locator.previewsEnabled !== false) invalid(400);
  const current = customerActionAndRecord(journal);
  const latest = current.record.attempts[current.record.attempts.length - 1];
  const mutation = input.enabled ? latest?.enable : latest ? latestDisableAttempt(latest) : null;
  if (!latest || !mutation || mutation.phase !== 'send_armed' ||
    (input.enabled && (latest.requestPhase !== 'prepared' || latest.disableAttempts.length !== 0))) conflict();
  const locator = deepFreeze({ enabled: !input.enabled, previewsEnabled: false as const });
  return replaceLatestCustomerAttempt(journal, (attempt) => ({
    ...attempt,
    ...(input.enabled
      ? { enable: deepFreeze({ ...attempt.enable, phase: 'not_applied' as const,
          locator, verifiedAt: input.now, verifiedByAttemptId: input.attemptId }) }
      : { disableAttempts: Object.freeze(attempt.disableAttempts.map((entry, index) =>
          index === attempt.disableAttempts.length - 1
            ? deepFreeze({ ...entry, phase: 'not_applied' as const, locator, verifiedAt: input.now,
              verifiedByAttemptId: input.attemptId })
            : entry)) }),
  }), input.now);
}

export function armCustomerGatewayRemoveRequest(
  journal: UninstallJournal,
  input: UninstallJournalCasInput,
): UninstallJournal {
  cas(journal, input, true);
  const current = customerActionAndRecord(journal);
  const latest = current.record.attempts[current.record.attempts.length - 1];
  if (!latest || latest.enable.phase !== 'verified' || latest.requestPhase !== 'prepared' ||
    latest.approvalAttemptId !== input.attemptId || input.now >= latest.semantic.expiresAt * 1_000) conflict();
  return replaceLatestCustomerAttempt(journal, (attempt) => ({
    ...attempt,
    requestPhase: 'send_armed',
    sendArmedAt: input.now,
  }), input.now);
}

export async function submitCustomerGatewayRemoveRequest(
  journal: UninstallJournal,
  input: UninstallJournalCasInput & { readonly locator: unknown },
): Promise<UninstallJournal> {
  cas(journal, input, true);
  const current = customerActionAndRecord(journal);
  const latest = current.record.attempts[current.record.attempts.length - 1];
  if (!latest || latest.requestPhase !== 'send_armed') conflict();
  const locator = await parseCustomerUninstallLocator(
    input.locator,
    latest.semantic,
    journal.installJournal,
  );
  if (!locator) invalid(400);
  return replaceLatestCustomerAttempt(journal, (attempt) => ({
    ...attempt,
    requestPhase: 'submitted',
    locator,
    submittedAt: input.now,
    submittedByAttemptId: input.attemptId,
  }), input.now);
}

export function verifyCustomerGatewayRemoveRequest(
  journal: UninstallJournal,
  input: UninstallJournalCasInput,
): UninstallJournal {
  cas(journal, input, true);
  const current = customerActionAndRecord(journal);
  const latest = current.record.attempts[current.record.attempts.length - 1];
  if (!latest || latest.requestPhase !== 'submitted' || latest.locator?.status !== 'removed') conflict();
  return replaceLatestCustomerAttempt(journal, (attempt) => ({
    ...attempt,
    requestPhase: 'verified',
    verifiedAt: input.now,
    verifiedByAttemptId: input.attemptId,
  }), input.now);
}

function requiredVerifiedLocator(
  journal: UninstallJournal,
  name: UninstallActionName,
): UninstallActionLocator {
  const action = verifiedAction(journal, name);
  if (!action?.locator) conflict();
  return action.locator;
}

async function finalConvergenceProjection(journal: UninstallJournal): Promise<{
  readonly record: UninstallFinalConvergenceRecord;
  readonly locator: UninstallRemovedTombstone;
}> {
  const finalIndex = UNINSTALL_ACTION_ORDER.indexOf('uninstall_final_convergence');
  if ((journal.actions.length !== finalIndex && journal.actions.length !== finalIndex + 1) ||
    !journal.actions.slice(0, finalIndex).every((action) => action.phase === 'verified')) conflict();
  const customer = requiredVerifiedLocator(journal, 'customer_gateway_remove');
  const cleanupVersion = requiredVerifiedLocator(journal, 'cleanup_worker_version_create');
  const cleanupDeployment = requiredVerifiedLocator(journal, 'cleanup_worker_deployment_create');
  const restored = requiredVerifiedLocator(journal, 'restore_clean_worker_deployment');
  const domain = requiredVerifiedLocator(journal, 'management_custom_domain_delete');
  const policy = requiredVerifiedLocator(journal, 'management_admin_policy_delete');
  const application = requiredVerifiedLocator(journal, 'management_access_application_delete');
  const retirementVersion = requiredVerifiedLocator(journal, 'retirement_worker_version_create');
  const retirementDeployment = requiredVerifiedLocator(journal, 'retirement_worker_deployment_create');
  const namespace = requiredVerifiedLocator(journal, 'admin_state_namespace_retired');
  const workerDeletion = requiredVerifiedLocator(journal, 'management_worker_delete');
  const noResidue = requiredVerifiedLocator(journal, 'management_no_managed_residue');
  if (!('status' in customer) || customer.status !== 'removed' || !('receipt' in customer) ||
    !('kind' in cleanupVersion) || cleanupVersion.kind !== 'uninstall_worker_version' ||
    cleanupVersion.stage !== 'cleanup' ||
    !('kind' in cleanupDeployment) || cleanupDeployment.kind !== 'uninstall_worker_deployment' ||
    cleanupDeployment.stage !== 'cleanup' ||
    !('kind' in restored) || restored.kind !== 'uninstall_worker_deployment' ||
    restored.stage !== 'restore_clean' ||
    !('action' in domain) || domain.action !== 'management_custom_domain_delete' ||
    !('action' in policy) || policy.action !== 'management_admin_policy_delete' ||
    !('action' in application) || application.action !== 'management_access_application_delete' ||
    !('kind' in retirementVersion) || retirementVersion.kind !== 'uninstall_worker_version' ||
    retirementVersion.stage !== 'retirement' ||
    !('kind' in retirementDeployment) || retirementDeployment.kind !== 'uninstall_worker_deployment' ||
    retirementDeployment.stage !== 'retirement' ||
    !('kind' in namespace) || namespace.kind !== 'admin_state_namespace_retirement' ||
    !('kind' in workerDeletion) || workerDeletion.kind !== 'uninstall_worker_deletion_proof' ||
    !('status' in noResidue) || noResidue.status !== 'no_ankka_managed_residue') conflict();
  const final = installFinal(journal);
  if (restored.versionId !== final.cleanVersionId || namespace.namespaceId !== final.adminStateNamespaceId ||
    namespace.retirementVersionId !== retirementVersion.versionId ||
    workerDeletion.namespaceId !== namespace.namespaceId ||
    workerDeletion.retirementVersionId !== retirementVersion.versionId ||
    noResidue.uninstallCycleId !== journal.uninstallCycleId ||
    !canonicalEqual(noResidue.evidence.deletionEvidence, [domain, policy, application]) ||
    !canonicalEqual(noResidue.evidence.workerDeletion, workerDeletion) ||
    !canonicalEqual(noResidue.evidence.namespaceRetirement, namespace) ||
    noResidue.deletionEvidenceSha256 !== await sha256Hex(canonicalJson([domain, policy, application])) ||
    noResidue.workerDeletionProofSha256 !== await sha256Hex(canonicalJson(workerDeletion)) ||
    noResidue.namespaceRetirementProofSha256 !== await sha256Hex(canonicalJson(namespace))) conflict();
  const semantic = deepFreeze({
    schemaVersion: 1 as const,
    status: 'removed' as const,
    bindingHash: journal.bindingHash,
    uninstallCycleId: journal.uninstallCycleId,
    installationId: journal.installJournal.installationId,
    target: {
      accountId: journal.installJournal.target.account.id,
      zoneId: journal.installJournal.target.zone.id,
      zoneName: journal.installJournal.target.zone.name,
    },
    release: {
      id: journal.installJournal.releasePin.release,
      artifactSha256: journal.installJournal.releasePin.artifactSha256,
    },
    customer,
    lifecycle: {
      cleanupVersion,
      cleanupDeployment,
      restoredCleanDeployment: restored,
      retirementVersion,
      retirementDeployment,
      namespaceRetirement: namespace,
      workerDeletion,
    },
    management: {
      customDomainAbsence: domain,
      adminPolicyAbsence: policy,
      accessApplicationAbsence: application,
      noManagedResidue: noResidue,
    },
    workersDevEnabled: false as const,
    providerNotice: STATIC_UNINSTALL_PROVIDER_NOTICE,
  });
  const convergenceHash = `sha256:${await sha256Hex(canonicalJson(semantic))}`;
  return deepFreeze({
    record: {
      schemaVersion: 1,
      kind: 'uninstall_final_convergence',
      convergenceHash,
    },
    locator: { ...semantic, convergenceHash },
  });
}

export async function prepareUninstallFinalConvergenceRecordAndLocator(
  journal: UninstallJournal,
): Promise<{
  readonly record: UninstallFinalConvergenceRecord;
  readonly locator: UninstallRemovedTombstone;
}> {
  const prepared = await finalConvergenceProjection(journal);
  const existing = actionByName(journal, 'uninstall_final_convergence');
  if (existing && (!canonicalEqual(existing.record, prepared.record) ||
    ((existing.phase === 'submitted' || existing.phase === 'verified')
      ? !canonicalEqual(existing.locator, prepared.locator)
      : existing.locator !== null))) conflict();
  return prepared;
}

async function parseApproval(
  value: unknown,
  installJournal: InstallJournal,
  baseline: StaticUninstallPlan,
  recoverUntil: number,
): Promise<UninstallJournalApproval | null> {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'attemptId', 'approvedAt', 'recordedAt', 'plan', 'authorizedTarget',
  ]) || value.schemaVersion !== 1 || typeof value.attemptId !== 'string' || !ATTEMPT_ID.test(value.attemptId) ||
    installAttemptWasUsed(installJournal, value.attemptId) ||
    !safeInteger(value.approvedAt) || !safeInteger(value.recordedAt) || value.approvedAt > value.recordedAt ||
    !targetMatches(value.authorizedTarget, installJournal.target)) return null;
  let plan: StaticUninstallPlan;
  try {
    plan = await exactReviewedPlan(installJournal, value.plan);
  } catch {
    return null;
  }
  if (value.approvedAt < plan.createdAt || value.approvedAt >= plan.expiresAt ||
    value.recordedAt < plan.createdAt || value.recordedAt >= plan.expiresAt ||
    plan.expiresAt > recoverUntil || !await isRecoveryEquivalentUninstallPlan(baseline, plan)) return null;
  return deepFreeze({
    schemaVersion: 1,
    attemptId: value.attemptId,
    approvedAt: value.approvedAt,
    recordedAt: value.recordedAt,
    plan,
    authorizedTarget: installJournal.target,
  });
}

function actionPhaseShape(record: UninstallActionRecord, phase: UninstallActionPhase): boolean {
  if (!('kind' in record)) return false;
  if (record.kind === 'uninstall_worker_version_create') {
    return phase === 'prepared' || record.recovery !== null;
  }
  if (record.kind === 'uninstall_management_delete') {
    return phase === managementDeleteActionSummary(record).phase;
  }
  if (record.kind === 'management_worker_delete') {
    return phase === 'prepared' || phase === 'send_armed'
      ? record.submission === null
      : record.submission !== null;
  }
  if (record.kind === 'management_no_managed_residue') {
    return phase === 'prepared'
      ? record.armedByAttemptId === null && record.submittedByAttemptId === null &&
          record.verifiedByAttemptId === null
      : phase === 'send_armed'
        ? record.armedByAttemptId !== null && record.submittedByAttemptId === null &&
            record.verifiedByAttemptId === null
        : phase === 'submitted'
          ? record.armedByAttemptId !== null && record.submittedByAttemptId !== null &&
              record.verifiedByAttemptId === null
          : record.armedByAttemptId !== null && record.submittedByAttemptId !== null &&
              record.verifiedByAttemptId !== null;
  }
  return true;
}

async function parsePersistedActionLocator(
  journal: UninstallJournal,
  action: UninstallJournalAction,
  value: unknown,
): Promise<UninstallActionLocator | null> {
  if (action.phase === 'prepared' || action.phase === 'send_armed') return value === null ? null : null;
  if (!('kind' in action.record)) return null;
  if (action.record.kind === 'uninstall_worker_version_create') {
    const submission = parseLifecycleSubmission(value, 'uninstall_worker_version', journal);
    return submission && submission.stage === action.record.stage && action.record.recovery &&
      submission.requestHash === action.record.recovery.requestHash ? submission : null;
  }
  if (action.record.kind === 'uninstall_worker_deployment_create') {
    const submission = parseLifecycleSubmission(value, 'uninstall_worker_deployment', journal);
    return submission && submission.stage === action.record.stage &&
      submission.requestHash === action.record.intent.requestHash &&
      submission.versionId === action.record.intent.versionId ? submission : null;
  }
  if (action.record.kind === 'uninstall_management_delete') {
    return null;
  }
  if (action.record.kind === 'admin_state_namespace_retired') {
    const proof = parseAdminStateNamespaceRetirementProof(value);
    return proof && canonicalEqual(proof, action.record.proof) ? proof : null;
  }
  if (action.record.kind === 'management_worker_delete') {
    if (action.phase === 'submitted') return value === null ? null : null;
    const proof = parseWorkerDeletionRecoveryProof(value);
    return proof && proof.requestHash === action.record.intent.requestHash &&
      proof.retirementProofCommitment === action.record.intent.retirementProofCommitment &&
      lifecycleIdentityMatches(proof, journal) ? proof : null;
  }
  if (action.record.kind === 'management_no_managed_residue') {
    const context = contextForAttempt(journal, action.record.result.attemptId);
    const parsed = context ? await parseHostedUninstallManagementNoManagedResidueResult(context, value) : null;
    return parsed && canonicalEqual(parsed, action.record.result) ? parsed : null;
  }
  if (action.record.kind === 'uninstall_final_convergence') {
    const expected = await prepareUninstallFinalConvergenceRecordAndLocator(journal);
    return canonicalEqual(value, expected.locator) ? expected.locator : null;
  }
  return null;
}

async function parsePersistedAction(
  value: unknown,
  expectedName: UninstallActionName,
  partial: UninstallJournal,
): Promise<UninstallJournalAction | null> {
  if (!isRecord(value) || !exactKeys(value, [
    'name', 'phase', 'record', 'locator', 'preparedAt', 'sendArmedAt', 'submittedAt', 'verifiedAt',
  ]) || value.name !== expectedName) return null;
  const managementDelete = isManagementDeleteActionName(expectedName);
  if (!managementDelete && !validPhaseTimes({
      phase: value.phase,
      preparedAt: value.preparedAt,
      sendArmedAt: value.sendArmedAt,
      submittedAt: value.submittedAt,
      verifiedAt: value.verifiedAt,
    }, partial.createdAt, partial.updatedAt)) return null;
  if (managementDelete && !['prepared', 'send_armed', 'submitted', 'verified'].includes(
    String(value.phase),
  )) return null;
  const phase = value.phase as UninstallActionPhase;
  if (expectedName === 'uninstall_fresh_preflight') {
    if (phase !== 'verified' || !isRecord(value.record) || typeof value.record.attemptId !== 'string') return null;
    const approval = approvalByAttempt(partial, value.record.attemptId);
    const context = approval ? approvalContext(partial, approval) : null;
    const record = context ? await parseHostedUninstallManagementPreflightResult(context, value.record) : null;
    if (!record || !isRecord(value.locator) || !exactKeys(value.locator, ['attestationSha256']) ||
      value.locator.attestationSha256 !== record.attestationSha256 ||
      !approval || record.checkedAt < approval.approvedAt ||
      (value.preparedAt as number) < approval.recordedAt ||
      value.preparedAt !== value.sendArmedAt || value.preparedAt !== value.submittedAt ||
      value.preparedAt !== value.verifiedAt || (value.preparedAt as number) < record.checkedAt ||
      (value.preparedAt as number) >= record.expiresAt ||
      (value.preparedAt as number) - record.checkedAt > FRESH_PREFLIGHT_TTL_MS) return null;
    return deepFreeze({
      name: expectedName,
      phase,
      record,
      locator: { attestationSha256: record.attestationSha256 },
      preparedAt: value.preparedAt as number,
      sendArmedAt: value.sendArmedAt as number,
      submittedAt: value.submittedAt as number,
      verifiedAt: value.verifiedAt as number,
    });
  }
  const record = await parseActionRecord(expectedName, value.record, partial);
  if (!record || !actionPhaseShape(record, phase)) return null;
  if (expectedName === 'cleanup_worker_version_create' && phase !== 'prepared') {
    const preflight = partial.actions[0]?.record;
    if (!preflight || !('checkedAt' in preflight) || !('expiresAt' in preflight) ||
      (value.sendArmedAt as number) < preflight.checkedAt ||
      (value.sendArmedAt as number) >= preflight.expiresAt ||
      (value.sendArmedAt as number) - preflight.checkedAt > FRESH_PREFLIGHT_TTL_MS) return null;
  }
  if ('kind' in record && record.kind === 'uninstall_management_delete') {
    const expected = managementDeleteActionSummary(record);
    return canonicalEqual({
      phase: value.phase,
      locator: value.locator,
      preparedAt: value.preparedAt,
      sendArmedAt: value.sendArmedAt,
      submittedAt: value.submittedAt,
      verifiedAt: value.verifiedAt,
    }, expected) ? deepFreeze({ name: expectedName, record, ...expected }) : null;
  }
  if ('kind' in record && record.kind === 'management_no_managed_residue') {
    const transitions: readonly [unknown, string | null][] = [
      [value.preparedAt, record.preparedByAttemptId],
      [value.sendArmedAt, record.armedByAttemptId],
      [value.submittedAt, record.submittedByAttemptId],
      [value.verifiedAt, record.verifiedByAttemptId],
    ];
    let previousApprovalIndex = -1;
    if (transitions.some(([time, attemptId]) => {
      if (time === null && attemptId === null) return false;
      if (!safeInteger(time) || !attemptId) return true;
      const approval = approvalByAttempt(partial, attemptId);
      const approvalIndex = approvalIndexByAttempt(partial, attemptId);
      if (!approval || approvalIndex < previousApprovalIndex ||
        time < approval.recordedAt || time >= approval.plan.expiresAt) return true;
      previousApprovalIndex = approvalIndex;
      return false;
    })) return null;
  }
  const provisional: UninstallJournalAction = deepFreeze({
    name: expectedName,
    phase,
    record,
    locator: null,
    preparedAt: value.preparedAt as number,
    sendArmedAt: phase === 'prepared' ? null : value.sendArmedAt as number,
    submittedAt: phase === 'submitted' || phase === 'verified' ? value.submittedAt as number : null,
    verifiedAt: phase === 'verified' ? value.verifiedAt as number : null,
  });
  if (expectedName === 'customer_gateway_remove') {
    if (!('kind' in record) || record.kind !== 'customer_gateway_remove') return null;
    const expected = customerActionSummary(record);
    return canonicalEqual({
      phase,
      locator: value.locator,
      preparedAt: value.preparedAt,
      sendArmedAt: value.sendArmedAt,
      submittedAt: value.submittedAt,
      verifiedAt: value.verifiedAt,
    }, expected) ? deepFreeze({ name: expectedName, record, ...expected }) : null;
  }
  const locator = await parsePersistedActionLocator(partial, provisional, value.locator);
  const mustHaveLocator = phase === 'verified' || (
    phase === 'submitted' && !(
      'kind' in record && record.kind === 'management_worker_delete'
    )
  );
  if ((mustHaveLocator && !locator) || (!mustHaveLocator && value.locator !== null)) return null;
  return deepFreeze({ ...provisional, locator });
}

async function parseUninstallJournal(value: unknown): Promise<UninstallJournal | null> {
  try {
    assertDurable(value);
    if (!isRecord(value) || !exactKeys(value, [
      'schemaVersion', 'revision', 'createdAt', 'updatedAt', 'recoverUntil', 'installJournal',
      'uninstallPlan', 'uninstallCycleId', 'bindingHash', 'approvalHistory',
      'managementPreflightHistory', 'lease', 'leaseAttemptIds', 'actions',
    ]) || value.schemaVersion !== 1 || !safeInteger(value.revision) || !safeInteger(value.createdAt) ||
      !safeInteger(value.updatedAt) || value.updatedAt < value.createdAt || !safeInteger(value.recoverUntil) ||
      value.updatedAt >= value.recoverUntil || typeof value.uninstallCycleId !== 'string' ||
      !UNINSTALL_CYCLE_ID.test(value.uninstallCycleId) || typeof value.bindingHash !== 'string' ||
      !PREFIXED_SHA256.test(value.bindingHash) || !Array.isArray(value.approvalHistory) ||
      value.approvalHistory.length < 1 || value.approvalHistory.length > MAX_APPROVALS ||
      !Array.isArray(value.managementPreflightHistory) ||
      value.managementPreflightHistory.length > MAX_MANAGEMENT_PREFLIGHTS ||
      !Array.isArray(value.leaseAttemptIds) || value.leaseAttemptIds.length > MAX_LEASE_ATTEMPTS ||
      !Array.isArray(value.actions) || value.actions.length < 1 ||
      value.actions.length > UNINSTALL_ACTION_ORDER.length) return null;
    const authority = await requireCompleteInstallAuthority(value.installJournal);
    if (value.createdAt < authority.journal.updatedAt || value.recoverUntil > authority.journal.recoverUntil) return null;
    const baseline = await exactReviewedPlan(authority.journal, value.uninstallPlan);
    if (baseline.createdAt > value.createdAt || baseline.expiresAt <= value.createdAt ||
      baseline.expiresAt > value.recoverUntil) return null;
    const expectedBinding = await computeUninstallJournalBindingHash({
      installJournal: authority.journal,
      uninstallPlan: baseline,
      uninstallCycleId: value.uninstallCycleId,
    });
    if (value.bindingHash !== expectedBinding) return null;
    const approvals: UninstallJournalApproval[] = [];
    for (const raw of value.approvalHistory) {
      const approval = await parseApproval(raw, authority.journal, baseline, value.recoverUntil);
      const previous = approvals[approvals.length - 1];
      if (!approval || approvals.some((entry) => entry.attemptId === approval.attemptId) ||
        approval.recordedAt < value.createdAt || approval.recordedAt > value.updatedAt ||
        (previous && (approval.approvedAt < previous.recordedAt ||
          approval.recordedAt < previous.recordedAt ||
          approval.plan.createdAt < previous.plan.createdAt || approval.plan.expiresAt < previous.plan.expiresAt))) return null;
      approvals.push(approval);
    }
    if (!canonicalEqual(approvals[0]?.plan, baseline) || approvals[0]?.recordedAt !== value.createdAt) return null;
    const leaseAttemptIds: string[] = [];
    let previousLeaseApprovalIndex = -1;
    for (const attemptId of value.leaseAttemptIds) {
      const approvalIndex = typeof attemptId === 'string'
        ? approvals.findIndex((approval) => approval.attemptId === attemptId)
        : -1;
      if (typeof attemptId !== 'string' || !ATTEMPT_ID.test(attemptId) ||
        leaseAttemptIds.includes(attemptId) || approvalIndex < 0 ||
        approvalIndex <= previousLeaseApprovalIndex) return null;
      leaseAttemptIds.push(attemptId);
      previousLeaseApprovalIndex = approvalIndex;
    }
    let lease: UninstallJournalLease | null = null;
    if (value.lease !== null) {
      const leaseValue = value.lease;
      const leaseApproval = isRecord(leaseValue) && typeof leaseValue.attemptId === 'string'
        ? approvals.find((entry) => entry.attemptId === leaseValue.attemptId)
        : undefined;
      if (!isRecord(leaseValue) || !exactKeys(leaseValue, ['attemptId', 'acquiredAt', 'expiresAt']) ||
        typeof leaseValue.attemptId !== 'string' || !leaseAttemptIds.includes(leaseValue.attemptId) ||
        leaseValue.attemptId !== approvals[approvals.length - 1]?.attemptId ||
        !leaseApproval ||
        !safeInteger(leaseValue.acquiredAt) || !safeInteger(leaseValue.expiresAt) ||
        leaseValue.acquiredAt < leaseApproval.approvedAt ||
        leaseValue.acquiredAt < leaseApproval.recordedAt ||
        leaseValue.acquiredAt > value.updatedAt || leaseValue.expiresAt <= leaseValue.acquiredAt ||
        leaseValue.expiresAt > leaseValue.acquiredAt + MAX_UNINSTALL_LEASE_MS ||
        leaseValue.expiresAt > (leaseApproval as UninstallJournalApproval).plan.expiresAt ||
        leaseValue.expiresAt > value.recoverUntil) return null;
      lease = deepFreeze({
        attemptId: leaseValue.attemptId,
        acquiredAt: leaseValue.acquiredAt,
        expiresAt: leaseValue.expiresAt,
      });
    }
    const managementPreflightHistory: HostedUninstallManagementPreflightResult[] = [];
    for (const raw of value.managementPreflightHistory) {
      if (!isRecord(raw) || typeof raw.attemptId !== 'string') return null;
      const approval = approvals.find((entry) => entry.attemptId === raw.attemptId);
      const context = approval ? approvalContext({
        installJournal: authority.journal,
        approvalHistory: approvals,
      }, approval) : null;
      const preflight = context
        ? await parseHostedUninstallManagementPreflightResult(context, raw)
        : null;
      const previous = managementPreflightHistory[managementPreflightHistory.length - 1];
      const approvalIndex = approval
        ? approvals.findIndex((entry) => entry.attemptId === approval.attemptId)
        : -1;
      const previousApprovalIndex = previous
        ? approvals.findIndex((entry) => entry.attemptId === previous.attemptId)
        : -1;
      if (
        !approval || !preflight || preflight.checkedAt < approval.approvedAt ||
        preflight.checkedAt < approval.recordedAt || preflight.checkedAt > value.updatedAt ||
        managementPreflightHistory.some(
          (entry) => entry.attestationSha256 === preflight.attestationSha256,
        ) || (previous && preflight.checkedAt < previous.checkedAt) ||
        (previous?.attemptId === preflight.attemptId && preflight.checkedAt < previous.expiresAt) ||
        approvalIndex < previousApprovalIndex
      ) return null;
      managementPreflightHistory.push(preflight);
    }
    let partial: UninstallJournal = deepFreeze({
      schemaVersion: 1,
      revision: value.revision,
      createdAt: value.createdAt,
      updatedAt: value.updatedAt,
      recoverUntil: value.recoverUntil,
      installJournal: authority.journal,
      uninstallPlan: baseline,
      uninstallCycleId: value.uninstallCycleId,
      bindingHash: value.bindingHash,
      approvalHistory: approvals,
      managementPreflightHistory,
      lease,
      leaseAttemptIds,
      actions: [],
    });
    const actions: UninstallJournalAction[] = [];
    for (let index = 0; index < value.actions.length; index += 1) {
      if (index > 0 && actions.slice(0, index).some((action) => action.phase !== 'verified')) return null;
      partial = deepFreeze({ ...partial, actions: [...actions] });
      const parsed = await parsePersistedAction(value.actions[index], UNINSTALL_ACTION_ORDER[index], partial);
      if (!parsed || (index > 0 && parsed.preparedAt < (actions[index - 1].verifiedAt as number))) return null;
      actions.push(parsed);
    }
    if (managementPreflightHistory.length > 0) {
      const customer = actions[UNINSTALL_ACTION_ORDER.indexOf('customer_gateway_remove')];
      const restored = actions[UNINSTALL_ACTION_ORDER.indexOf('restore_clean_worker_deployment')];
      if (customer?.phase !== 'verified' || restored?.phase !== 'verified') return null;
      const domain = actions[UNINSTALL_ACTION_ORDER.indexOf('management_custom_domain_delete')];
      if (domain && 'kind' in domain.record && domain.record.kind === 'uninstall_management_delete') {
        const latestAttempt = domain.record.attempts[domain.record.attempts.length - 1];
        const usedPreflight = latestAttempt && latestAttempt.prerequisites.action ===
          'management_custom_domain_delete'
          ? latestAttempt.prerequisites.preflight
          : null;
        const usedIndex = usedPreflight
          ? managementPreflightHistory.findIndex((entry) => canonicalEqual(entry, usedPreflight))
          : -1;
        if (!latestAttempt || usedIndex < 0 ||
          (usedIndex !== managementPreflightHistory.length - 1 &&
            !['prepared', 'not_applied'].includes(latestAttempt.phase))) return null;
      }
    }
    const journal = deepFreeze({ ...partial, actions });
    assertDurable(journal);
    return journal;
  } catch {
    return null;
  }
}

export async function requireUninstallJournal(value: unknown): Promise<UninstallJournal> {
  const parsed = await parseUninstallJournal(value);
  if (!parsed) invalid();
  return parsed;
}

export function hasArmedUninstallJournalAction(journal: UninstallJournal): boolean {
  const customer = journal.actions.find((action) => action.name === 'customer_gateway_remove');
  const customerArmed = customer && 'kind' in customer.record &&
    customer.record.kind === 'customer_gateway_remove' && customer.record.attempts.some(
    (attempt) => attempt.enable.phase !== 'prepared' || attempt.requestPhase !== 'prepared' ||
      attempt.disableAttempts.some((entry) => entry.phase !== 'prepared'),
  );
  const managementArmed = journal.actions.some((action) => 'kind' in action.record &&
    action.record.kind === 'uninstall_management_delete' && action.record.attempts.some(
      (attempt) => attempt.phase !== 'prepared',
    ));
  return Boolean(customerArmed || managementArmed || journal.actions.some(
    (action) => action.name !== 'uninstall_fresh_preflight' && action.phase !== 'prepared',
  ));
}

export function isCompleteUninstallJournal(journal: UninstallJournal): boolean {
  return journal.actions.length === UNINSTALL_ACTION_ORDER.length &&
    journal.actions.every((action) => action.phase === 'verified');
}

export function isPartialUninstallJournal(journal: UninstallJournal): boolean {
  return hasArmedUninstallJournalAction(journal) && !isCompleteUninstallJournal(journal);
}

// Kept here, rather than in the executor, so every future customer-cycle parser
// uses the same hard cap at the durable boundary.
export const MAX_CUSTOMER_GATEWAY_REMOVE_CYCLES = MAX_CUSTOMER_REMOVE_CYCLES;
export const MAX_UNINSTALL_MANAGEMENT_DELETE_ATTEMPTS = MAX_MANAGEMENT_DELETE_ATTEMPTS;
