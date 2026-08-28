import type {
  AccountWorkersSubdomain,
  WorkerSubdomainState,
} from './cloudflare-management-surface';
import {
  getAccountWorkersSubdomain,
  setWorkerBootstrapSubdomain,
  verifyWorkerBootstrapSubdomain,
} from './cloudflare-management-surface';
import type { AuthorizedTarget } from './cloudflare-target';
import {
  recoverHostedUninstallManagementDeleteOutcome,
  prepareHostedUninstallManagementDeleteArm,
  prepareHostedUninstallManagementDeleteIntent,
  preflightHostedUninstallManagement,
  submitHostedUninstallManagementDeleteOnce,
  verifyHostedUninstallManagementDeleteAbsence,
  verifyHostedUninstallManagementNoManagedResidue,
  type HostedUninstallManagementAbsenceEvidence,
  type HostedUninstallManagementContext,
  type HostedUninstallManagementDeleteAction,
  type HostedUninstallManagementDeleteArm,
  type HostedUninstallManagementDeleteIntent,
  type HostedUninstallManagementDeletePrerequisites,
  type HostedUninstallManagementDeleteRecoveryEvidence,
  type HostedUninstallManagementDeleteSubmission,
  type HostedUninstallManagementLifecycleEvidence,
  type HostedUninstallManagementNoManagedResidueResult,
  type HostedUninstallManagementPreflightResult,
} from './cloudflare-uninstall-management';
import {
  CloudflareUninstallWorkerLifecycleError,
  inspectUninstallWorkerDeploymentRecovery,
  inspectUninstallWorkerVersionRecovery,
  prepareCleanupWorkerVersionMutation,
  prepareRetirementWorkerVersionMutation,
  prepareUninstallWorkerDeploymentMutation,
  prepareWorkerDeleteMutation,
  proveActiveCleanupWorkerVersion,
  proveAdminStateNamespaceRetired,
  provePersistedAdminStateNamespacePresent,
  recoverWorkerDeletionOutcome,
  submitUninstallWorkerDeploymentMutation,
  submitUninstallWorkerVersionMutation,
  submitWorkerDeleteMutation,
  verifyUninstallWorkerDeploymentIsActive,
  verifyUninstallWorkerDeploymentSubmission,
  verifyUninstallWorkerVersionSubmission,
  type AdminStateNamespacePresenceProof,
  type AdminStateNamespaceRetirementProof,
  type ActiveCleanupWorkerVersionProof,
  type PrepareCleanupWorkerVersionInput,
  type PrepareRetirementWorkerVersionInput,
  type PrepareUninstallWorkerDeploymentInput,
  type ProveAdminStateNamespacePresentInput,
  type ProveAdminStateNamespaceRetiredInput,
  type UninstallCleanupVariables,
  type UninstallWorkerDeploymentMutationIntent,
  type UninstallWorkerDeploymentSubmission,
  type UninstallWorkerVersionMutationPlan,
  type UninstallWorkerVersionRecoveryRecord,
  type UninstallWorkerVersionSubmission,
  type WorkerDeleteMutationIntent,
  type WorkerDeleteSubmission,
  type WorkerDeletionRecoveryProof,
} from './cloudflare-uninstall-worker-lifecycle';
import type {
  AdminStateDurableObjectNamespaceLocator,
  InspectAdminStateDurableObjectNamespaceInput,
} from './cloudflare-worker-direct-upload';
import { inspectAdminStateDurableObjectNamespace } from './cloudflare-worker-direct-upload';
import {
  customerUninstallUrl,
  deriveCustomerUninstallNonce,
  prepareCustomerUninstallRequest,
  submitCustomerUninstallRequest,
  type CustomerUninstallLocator,
  type CustomerUninstallMutationPlan,
  type CustomerUninstallSemanticRecord,
  type PrepareCustomerUninstallRequestInput,
  type SubmitCustomerUninstallRequestInput,
} from './customer-uninstall-request';
import { DeployError } from './errors';
import {
  isCompleteInstallJournal,
  prepareFinalConvergenceRecordAndLocator,
  type FinalConvergenceLocator,
  type InstallJournal,
} from './install-journal';
import {
  adaptVerifiedReleaseBundleForGatewayDeployments,
  type VerifiedGatewayWorkerReleaseSet,
} from './release-direct-upload-adapter';
import { canonicalJson } from './release-manifest';
import type { StaticDeployPlan } from './schema';
import type { UninstallExecutionInput, UninstallExecutionResult } from './uninstall-executor';
import {
  MAX_UNINSTALL_LEASE_MS,
  activeUninstallJournalPlan,
  computeUninstallJournalBindingHash,
  prepareUninstallFinalConvergenceRecordAndLocator,
  type CustomerGatewayRemoveRequestAttempt,
  type ManagementDeleteActionName,
  type ManagementDeleteActionDraft,
  type NamespaceRetirementActionRecord,
  type NoManagedResidueActionDraft,
  type ManagementDeleteAttempt,
  type UninstallActionName,
  type UninstallFinalConvergenceRecord,
  type UninstallJournal,
  type UninstallJournalAction,
  type UninstallJournalCasInput,
  type UninstallWorkerDeploymentActionRecord,
  type UninstallWorkerVersionActionRecord,
  type UninstallWorkersDevMutation,
  type WorkerDeleteActionRecord,
} from './uninstall-journal';
import {
  isRecoveryEquivalentUninstallPlan,
  parseStaticUninstallPlan,
  type StaticUninstallPlan,
} from './uninstall-plan';

const ATTEMPT_ID = /^att_[A-Za-z0-9_-]{32}$/u;
const ACCESS_TOKEN = /^[A-Za-z0-9._~-]{20,8192}$/u;
const BASE64_KEY = /^(?:[A-Za-z0-9_-]{43}|[A-Za-z0-9+/]{43}=)$/u;
const UNINSTALL_CYCLE_ID = /^uninstall-[a-f0-9]{24}$/u;
const MAX_CUSTOMER_DISABLE_CYCLES = 8;
const FRESH_PREFLIGHT_TTL_MS = 60_000;
const REMOVE_READY_ATTEMPTS = 40;
const REMOVE_READY_INTERVAL_MS = 1_500;
const executionCapabilitiesSchema = v.object({
  journal: v.object({ read: v.function() }),
  provider: v.object({ preflightManagement: v.function() }),
  transport: v.function(),
});

export type ReviewedUninstallFailureCode =
  | 'customer_recovery_unavailable'
  | 'fresh_grant_required'
  | 'fresh_preflight_expired'
  | 'journal_recovery_mismatch'
  | 'provider_recovery_missing'
  | 'reviewed_adapter_invalid';

/** Stable, value-free failure information for the explicitly injected path. */
export class ReviewedUninstallExecutionError extends Error {
  readonly canRetry = false;

  constructor(readonly code: ReviewedUninstallFailureCode) {
    super(code);
    this.name = 'ReviewedUninstallExecutionError';
  }
}

export type ReviewedUninstallTransport = (request: Request) => Promise<Response>;

export interface ReviewedUninstallProviderCall {
  /** Used and discarded by exactly one awaited provider call. */
  readonly accessToken: string;
  readonly transport: ReviewedUninstallTransport;
  readonly timeoutMs?: number;
}

export interface ReviewedUninstallProviderAdapter {
  getAccountWorkersSubdomain(
    input: ReviewedUninstallProviderCall & { readonly accountId: string },
  ): Promise<AccountWorkersSubdomain>;
  inspectAdminStateNamespace(
    input: InspectAdminStateDurableObjectNamespaceInput,
    call: ReviewedUninstallProviderCall,
  ): Promise<AdminStateDurableObjectNamespaceLocator>;
  preflightManagement(
    context: HostedUninstallManagementContext,
    call: ReviewedUninstallProviderCall,
    nowMs: number,
  ): Promise<HostedUninstallManagementPreflightResult>;

  prepareCleanupVersion(input: PrepareCleanupWorkerVersionInput): Promise<UninstallWorkerVersionMutationPlan>;
  prepareRetirementVersion(input: PrepareRetirementWorkerVersionInput): Promise<UninstallWorkerVersionMutationPlan>;
  inspectVersion(
    recovery: UninstallWorkerVersionRecoveryRecord,
    call: ReviewedUninstallProviderCall,
  ): Promise<UninstallWorkerVersionSubmission | null>;
  submitVersion(
    plan: UninstallWorkerVersionMutationPlan,
    call: ReviewedUninstallProviderCall,
  ): Promise<UninstallWorkerVersionSubmission>;
  verifyVersion(
    recovery: UninstallWorkerVersionRecoveryRecord,
    submission: UninstallWorkerVersionSubmission,
    call: ReviewedUninstallProviderCall,
  ): Promise<UninstallWorkerVersionSubmission>;

  prepareDeployment(
    input: PrepareUninstallWorkerDeploymentInput,
  ): Promise<UninstallWorkerDeploymentMutationIntent>;
  inspectDeployment(
    intent: UninstallWorkerDeploymentMutationIntent,
    call: ReviewedUninstallProviderCall,
  ): Promise<UninstallWorkerDeploymentSubmission | null>;
  submitDeployment(
    intent: UninstallWorkerDeploymentMutationIntent,
    call: ReviewedUninstallProviderCall,
  ): Promise<UninstallWorkerDeploymentSubmission>;
  verifyDeployment(
    intent: UninstallWorkerDeploymentMutationIntent,
    submission: UninstallWorkerDeploymentSubmission,
    call: ReviewedUninstallProviderCall,
  ): Promise<UninstallWorkerDeploymentSubmission>;
  verifyActiveDeployment(
    intent: UninstallWorkerDeploymentMutationIntent,
    submission: UninstallWorkerDeploymentSubmission,
    call: ReviewedUninstallProviderCall,
  ): Promise<UninstallWorkerDeploymentSubmission>;
  proveActiveCleanupWorker(
    recovery: Extract<UninstallWorkerVersionRecoveryRecord, { readonly stage: 'cleanup' }>,
    version: UninstallWorkerVersionSubmission,
    deploymentIntent: UninstallWorkerDeploymentMutationIntent,
    deployment: UninstallWorkerDeploymentSubmission,
    call: ReviewedUninstallProviderCall,
  ): Promise<ActiveCleanupWorkerVersionProof>;

  setWorkersDev(
    enabled: boolean,
    input: ReviewedUninstallProviderCall & { readonly accountId: string; readonly plan: StaticDeployPlan },
  ): Promise<WorkerSubdomainState>;
  verifyWorkersDev(
    expectedEnabled: boolean,
    input: ReviewedUninstallProviderCall & { readonly accountId: string; readonly plan: StaticDeployPlan },
  ): Promise<WorkerSubdomainState>;

  prepareCustomerRequest(input: PrepareCustomerUninstallRequestInput): Promise<CustomerUninstallMutationPlan>;
  /**
   * The removal request is one-shot: the public cleanup contract exposes no
   * retry, so an unknown outcome ends the attempt. Enabling the workers.dev
   * subdomain is verified through the API well before the route serves (live
   * 2026-08-23), so the route is proven to answer before the request is armed.
   * The probe is an unsigned GET the cleanup Worker answers with its fixed
   * method-not-allowed envelope; the edge 404 page does not.
   */
  awaitCustomerRemoveReady(
    input: ReviewedUninstallProviderCall & {
      readonly accountWorkersSubdomain: AccountWorkersSubdomain;
      readonly workerName: string;
    },
  ): Promise<void>;
  submitCustomerRequest(input: SubmitCustomerUninstallRequestInput): Promise<CustomerUninstallLocator>;

  prepareManagementDeleteIntent(
    context: HostedUninstallManagementContext,
    action: HostedUninstallManagementDeleteAction,
    prerequisites: HostedUninstallManagementDeletePrerequisites,
  ): Promise<HostedUninstallManagementDeleteIntent>;
  prepareManagementDeleteArm(
    context: HostedUninstallManagementContext,
    intent: HostedUninstallManagementDeleteIntent,
    prerequisites: HostedUninstallManagementDeletePrerequisites,
    armedAt: number,
  ): Promise<HostedUninstallManagementDeleteArm>;
  submitManagementDelete(
    context: HostedUninstallManagementContext,
    intent: HostedUninstallManagementDeleteIntent,
    arm: HostedUninstallManagementDeleteArm,
    prerequisites: HostedUninstallManagementDeletePrerequisites,
    call: ReviewedUninstallProviderCall,
    nowMs: number,
  ): Promise<HostedUninstallManagementDeleteSubmission>;
  verifyManagementDelete(
    context: HostedUninstallManagementContext,
    intent: HostedUninstallManagementDeleteIntent,
    prerequisites: HostedUninstallManagementDeletePrerequisites,
    call: ReviewedUninstallProviderCall,
  ): Promise<HostedUninstallManagementAbsenceEvidence>;
  recoverManagementDelete(
    context: HostedUninstallManagementContext,
    intent: HostedUninstallManagementDeleteIntent,
    arm: HostedUninstallManagementDeleteArm,
    prerequisites: HostedUninstallManagementDeletePrerequisites,
    call: ReviewedUninstallProviderCall,
  ): Promise<HostedUninstallManagementDeleteRecoveryEvidence>;

  proveNamespacePresent(
    input: ProveAdminStateNamespacePresentInput,
    call: ReviewedUninstallProviderCall,
  ): Promise<AdminStateNamespacePresenceProof>;
  proveNamespaceRetired(
    input: ProveAdminStateNamespaceRetiredInput,
    call: ReviewedUninstallProviderCall,
  ): Promise<AdminStateNamespaceRetirementProof>;
  prepareWorkerDelete(
    input: ProveAdminStateNamespaceRetiredInput,
    call: ReviewedUninstallProviderCall,
  ): Promise<WorkerDeleteMutationIntent>;
  submitWorkerDelete(
    intent: WorkerDeleteMutationIntent,
    input: ProveAdminStateNamespaceRetiredInput,
    call: ReviewedUninstallProviderCall,
  ): Promise<WorkerDeleteSubmission>;
  recoverWorkerDelete(
    intent: WorkerDeleteMutationIntent,
    call: ReviewedUninstallProviderCall,
  ): Promise<WorkerDeletionRecoveryProof>;
  verifyNoManagedResidue(
    context: HostedUninstallManagementContext,
    deletionEvidence: readonly HostedUninstallManagementAbsenceEvidence[],
    lifecycle: HostedUninstallManagementLifecycleEvidence,
    call: ReviewedUninstallProviderCall,
  ): Promise<HostedUninstallManagementNoManagedResidueResult>;
}

/** Stateless adapter over the reviewed uninstall primitives. */
export function createCloudflareReviewedUninstallProviderAdapter(): ReviewedUninstallProviderAdapter {
  return Object.freeze({
    getAccountWorkersSubdomain,
    inspectAdminStateNamespace: inspectAdminStateDurableObjectNamespace,
    preflightManagement: preflightHostedUninstallManagement,
    prepareCleanupVersion: prepareCleanupWorkerVersionMutation,
    prepareRetirementVersion: prepareRetirementWorkerVersionMutation,
    inspectVersion: inspectUninstallWorkerVersionRecovery,
    submitVersion: (
      plan: UninstallWorkerVersionMutationPlan,
      call: ReviewedUninstallProviderCall,
    ) => submitUninstallWorkerVersionMutation(plan.ephemeral, plan.recovery, call),
    verifyVersion: verifyUninstallWorkerVersionSubmission,
    prepareDeployment: prepareUninstallWorkerDeploymentMutation,
    inspectDeployment: inspectUninstallWorkerDeploymentRecovery,
    submitDeployment: submitUninstallWorkerDeploymentMutation,
    verifyDeployment: verifyUninstallWorkerDeploymentSubmission,
    verifyActiveDeployment: verifyUninstallWorkerDeploymentIsActive,
    proveActiveCleanupWorker: proveActiveCleanupWorkerVersion,
    setWorkersDev: (
      enabled: boolean,
      input: ReviewedUninstallProviderCall & { readonly accountId: string; readonly plan: StaticDeployPlan },
    ) => setWorkerBootstrapSubdomain({ ...input, enabled }),
    verifyWorkersDev: (
      expectedEnabled: boolean,
      input: ReviewedUninstallProviderCall & { readonly accountId: string; readonly plan: StaticDeployPlan },
    ) => verifyWorkerBootstrapSubdomain({
      ...input,
      expectedEnabled,
    }),
    prepareCustomerRequest: prepareCustomerUninstallRequest,
    awaitCustomerRemoveReady: async (input: ReviewedUninstallProviderCall & {
      readonly accountWorkersSubdomain: AccountWorkersSubdomain;
      readonly workerName: string;
    }) => {
      const url = customerUninstallUrl({
        workerName: input.workerName,
        accountWorkersSubdomain: input.accountWorkersSubdomain,
      });
      for (let attempt = 0; attempt < REMOVE_READY_ATTEMPTS; attempt += 1) {
        try {
          const response = await input.transport(new Request(url, {
            method: 'GET',
            headers: { accept: 'application/json' },
            redirect: 'manual',
            credentials: 'omit',
          }));
          const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
          await response.body?.cancel().catch(() => undefined);
          if (response.status === 405 && contentType === 'application/json') return;
        } catch { /* the bounded retry below is the only outcome that matters */ }
        await new Promise((resolve) => setTimeout(resolve, REMOVE_READY_INTERVAL_MS));
      }
      fail('customer_recovery_unavailable');
    },
    submitCustomerRequest: submitCustomerUninstallRequest,
    prepareManagementDeleteIntent: prepareHostedUninstallManagementDeleteIntent,
    prepareManagementDeleteArm: prepareHostedUninstallManagementDeleteArm,
    submitManagementDelete: submitHostedUninstallManagementDeleteOnce,
    verifyManagementDelete: verifyHostedUninstallManagementDeleteAbsence,
    recoverManagementDelete: recoverHostedUninstallManagementDeleteOutcome,
    proveNamespacePresent: provePersistedAdminStateNamespacePresent,
    proveNamespaceRetired: proveAdminStateNamespaceRetired,
    prepareWorkerDelete: prepareWorkerDeleteMutation,
    submitWorkerDelete: submitWorkerDeleteMutation,
    recoverWorkerDelete: recoverWorkerDeletionOutcome,
    verifyNoManagedResidue: verifyHostedUninstallManagementNoManagedResidue,
  });
}

interface ReviewedInitializeJournalInput {
  readonly initialization: {
    readonly schemaVersion: 1;
    readonly now: number;
    readonly recoverUntil: number;
    readonly installJournal: InstallJournal;
    readonly uninstallPlan: StaticUninstallPlan;
    readonly uninstallCycleId: string;
    readonly bindingHash: string;
    readonly freshPreflight: HostedUninstallManagementPreflightResult;
  };
  readonly approval: {
    readonly attemptId: string;
    readonly approvedAt: number;
    readonly authorizedTarget: AuthorizedTarget;
  };
}

export interface ReviewedPreparedActionRecords {
  readonly cleanup_worker_version_create: UninstallWorkerVersionActionRecord;
  readonly retirement_worker_version_create: UninstallWorkerVersionActionRecord;
  readonly cleanup_worker_deployment_create: UninstallWorkerDeploymentActionRecord;
  readonly restore_clean_worker_deployment: UninstallWorkerDeploymentActionRecord;
  readonly retirement_worker_deployment_create: UninstallWorkerDeploymentActionRecord;
  readonly management_custom_domain_delete: ManagementDeleteActionDraft;
  readonly management_admin_policy_delete: ManagementDeleteActionDraft;
  readonly management_access_application_delete: ManagementDeleteActionDraft;
  readonly admin_state_namespace_retired: NamespaceRetirementActionRecord;
  readonly management_worker_delete: WorkerDeleteActionRecord;
  readonly management_no_managed_residue: NoManagedResidueActionDraft;
  readonly uninstall_final_convergence: UninstallFinalConvergenceRecord;
}

export interface ReviewedSubmittedActionValues {
  readonly cleanup_worker_version_create: UninstallWorkerVersionSubmission;
  readonly retirement_worker_version_create: UninstallWorkerVersionSubmission;
  readonly cleanup_worker_deployment_create: UninstallWorkerDeploymentSubmission;
  readonly restore_clean_worker_deployment: UninstallWorkerDeploymentSubmission;
  readonly retirement_worker_deployment_create: UninstallWorkerDeploymentSubmission;
  readonly management_custom_domain_delete: HostedUninstallManagementDeleteSubmission;
  readonly management_admin_policy_delete: HostedUninstallManagementDeleteSubmission;
  readonly management_access_application_delete: HostedUninstallManagementDeleteSubmission;
  readonly admin_state_namespace_retired: AdminStateNamespaceRetirementProof;
  readonly management_worker_delete: WorkerDeleteSubmission;
  readonly management_no_managed_residue: HostedUninstallManagementNoManagedResidueResult;
  readonly uninstall_final_convergence: ReviewedUninstallFinalProjection['locator'];
}

export interface ReviewedVerifiedActionValues extends Omit<
  ReviewedSubmittedActionValues,
  ManagementDeleteActionName | 'management_worker_delete'
> {
  readonly management_custom_domain_delete: HostedUninstallManagementAbsenceEvidence;
  readonly management_admin_policy_delete: HostedUninstallManagementAbsenceEvidence;
  readonly management_access_application_delete: HostedUninstallManagementAbsenceEvidence;
  readonly management_worker_delete: WorkerDeletionRecoveryProof;
}

/** Exact in-process journal contract consumed by the reviewed orchestrator. */
export interface ReviewedUninstallJournalPort {
  initialize(input: ReviewedInitializeJournalInput): Promise<UninstallJournal>;
  read(): Promise<UninstallJournal>;
  appendApproval(input: UninstallJournalCasInput & {
    readonly approvedAt: number;
    readonly authorizedTarget: AuthorizedTarget;
    readonly candidatePlan: StaticUninstallPlan;
  }): Promise<UninstallJournal>;
  acquireLease(input: UninstallJournalCasInput & { readonly leaseExpiresAt: number }): Promise<UninstallJournal>;
  releaseLease(input: UninstallJournalCasInput): Promise<UninstallJournal>;
  refreshPreflight(input: UninstallJournalCasInput & {
    readonly preflight: HostedUninstallManagementPreflightResult;
  }): Promise<UninstallJournal>;
  discardPreflight(input: UninstallJournalCasInput): Promise<{ readonly discarded: true }>;
  appendManagementPreflight(input: UninstallJournalCasInput & {
    readonly preflight: HostedUninstallManagementPreflightResult;
  }): Promise<UninstallJournal>;
  appendManagementDeleteAttempt(input: UninstallJournalCasInput & {
    readonly action: ManagementDeleteActionName;
    readonly prerequisites: HostedUninstallManagementDeletePrerequisites;
    readonly intent: HostedUninstallManagementDeleteIntent;
  }): Promise<UninstallJournal>;
  recordManagementDeleteRecovery(input: UninstallJournalCasInput & {
    readonly action: ManagementDeleteActionName;
    readonly evidence: HostedUninstallManagementDeleteRecoveryEvidence;
  }): Promise<UninstallJournal>;
  prepareAction<Action extends keyof ReviewedPreparedActionRecords>(
    input: UninstallJournalCasInput & {
      readonly action: Action;
      readonly record: ReviewedPreparedActionRecords[Action];
    },
  ): Promise<UninstallJournal>;
  replacePreparedAction<Action extends keyof ReviewedPreparedActionRecords>(
    input: UninstallJournalCasInput & {
      readonly action: Action;
      readonly record: ReviewedPreparedActionRecords[Action];
    },
  ): Promise<UninstallJournal>;
  attachWorkerVersionRecovery(input: UninstallJournalCasInput & {
    readonly action: 'cleanup_worker_version_create' | 'retirement_worker_version_create';
    readonly recovery: UninstallWorkerVersionRecoveryRecord;
  }): Promise<UninstallJournal>;
  armAction<Action extends keyof ReviewedPreparedActionRecords>(input: UninstallJournalCasInput & {
    readonly action: Action;
    readonly value?: Action extends ManagementDeleteActionName
      ? HostedUninstallManagementDeleteArm
      : never;
  }): Promise<UninstallJournal>;
  recordActionSubmitted<Action extends keyof ReviewedSubmittedActionValues>(
    input: UninstallJournalCasInput & {
      readonly action: Action;
      readonly value: ReviewedSubmittedActionValues[Action];
    },
  ): Promise<UninstallJournal>;
  verifyAction<Action extends keyof ReviewedVerifiedActionValues>(
    input: UninstallJournalCasInput & {
      readonly action: Action;
      readonly value: ReviewedVerifiedActionValues[Action];
    },
  ): Promise<UninstallJournal>;
  appendCustomerRemoveCycle(input: UninstallJournalCasInput & {
    readonly semantic: CustomerUninstallSemanticRecord;
  }): Promise<UninstallJournal>;
  replacePreparedCustomerRemoveCycle(input: UninstallJournalCasInput & {
    readonly semantic: CustomerUninstallSemanticRecord;
  }): Promise<UninstallJournal>;
  prepareCustomerWorkersDevDisable(input: UninstallJournalCasInput): Promise<UninstallJournal>;
  replacePreparedCustomerWorkersDevDisable(input: UninstallJournalCasInput): Promise<UninstallJournal>;
  armCustomerWorkersDev(input: UninstallJournalCasInput & { readonly enabled: boolean }): Promise<UninstallJournal>;
  recordCustomerWorkersDevSubmitted(input: UninstallJournalCasInput & {
    readonly enabled: boolean;
    readonly locator: WorkerSubdomainState;
  }): Promise<UninstallJournal>;
  verifyCustomerWorkersDev(input: UninstallJournalCasInput & { readonly enabled: boolean }): Promise<UninstallJournal>;
  recordCustomerWorkersDevNotApplied(input: UninstallJournalCasInput & {
    readonly enabled: boolean;
    readonly locator: WorkerSubdomainState;
  }): Promise<UninstallJournal>;
  armCustomerRemoveRequest(input: UninstallJournalCasInput): Promise<UninstallJournal>;
  recordCustomerRemoveRequestSubmitted(input: UninstallJournalCasInput & {
    readonly locator: CustomerUninstallLocator;
  }): Promise<UninstallJournal>;
  verifyCustomerRemoveRequest(input: UninstallJournalCasInput): Promise<UninstallJournal>;
}

export interface ReviewedUninstallExecutionInput extends Omit<UninstallExecutionInput, 'journal'> {
  readonly journal: ReviewedUninstallJournalPort;
  readonly provider: ReviewedUninstallProviderAdapter;
  readonly transport: ReviewedUninstallTransport;
  readonly timeoutMs?: number;
  readonly now?: () => number;
  readonly randomBytes?: (length: number) => Uint8Array;
}

/** Pure domain primitives used by the reviewed orchestration. */
export interface ReviewedUninstallExecutionDependencies {
  readonly isCompleteInstallJournal: typeof isCompleteInstallJournal;
  readonly prepareFinalConvergenceRecordAndLocator: typeof prepareFinalConvergenceRecordAndLocator;
  readonly parseStaticUninstallPlan: typeof parseStaticUninstallPlan;
  readonly isRecoveryEquivalentUninstallPlan: typeof isRecoveryEquivalentUninstallPlan;
  readonly adaptVerifiedReleaseBundleForGatewayDeployments:
    typeof adaptVerifiedReleaseBundleForGatewayDeployments;
  readonly deriveCustomerUninstallNonce: typeof deriveCustomerUninstallNonce;
  readonly computeUninstallJournalBindingHash: typeof computeUninstallJournalBindingHash;
  readonly prepareUninstallFinalConvergenceRecordAndLocator: (
    journal: UninstallJournal,
  ) => Promise<ReviewedUninstallFinalProjection>;
}

export interface ReviewedUninstallFinalProjection {
  readonly record: {
    readonly schemaVersion: 1;
    readonly kind: 'uninstall_final_convergence';
    readonly convergenceHash: string;
  };
  readonly locator: {
    readonly schemaVersion: 1;
    readonly status: 'removed';
    readonly installationId: string;
    readonly convergenceHash: string;
  };
}

const defaultExecutionDependencies: ReviewedUninstallExecutionDependencies = Object.freeze({
  isCompleteInstallJournal,
  prepareFinalConvergenceRecordAndLocator,
  parseStaticUninstallPlan,
  isRecoveryEquivalentUninstallPlan,
  adaptVerifiedReleaseBundleForGatewayDeployments,
  deriveCustomerUninstallNonce,
  computeUninstallJournalBindingHash,
  prepareUninstallFinalConvergenceRecordAndLocator,
});

interface ExecutionContext {
  readonly input: ReviewedUninstallExecutionInput;
  readonly dependencies: ReviewedUninstallExecutionDependencies;
  readonly installJournal: InstallJournal;
  readonly plan: StaticUninstallPlan;
  readonly releaseSet: VerifiedGatewayWorkerReleaseSet;
  readonly finalInstall: FinalConvergenceLocator;
  readonly call: ReviewedUninstallProviderCall;
  readonly workerName: string;
  readonly workerId: string;
  readonly namespaceId: string;
  journal: UninstallJournal;
}

interface UninstallWorkerVersionJournalRecord {
  readonly accountId: string;
  readonly artifactSha256: string;
  readonly componentSha256: string;
  readonly kind: 'uninstall_worker_version_create';
  readonly namespacePresence: AdminStateNamespacePresenceProof | null;
  readonly recovery: null;
  readonly release: string;
  readonly schemaVersion: 1;
  readonly stage: 'cleanup' | 'retirement';
  readonly uninstallCycleId: string;
  readonly workerId: string;
  readonly workerName: string;
}

interface ManagementDeleteJournalRecord {
  readonly intent: HostedUninstallManagementDeleteIntent;
  readonly kind: 'uninstall_management_delete';
  readonly prerequisites: HostedUninstallManagementDeletePrerequisites;
  readonly schemaVersion: 1;
}

interface FreshManagementDeleteDraft {
  readonly prerequisites: HostedUninstallManagementDeletePrerequisites;
  readonly intent: HostedUninstallManagementDeleteIntent;
  readonly record: ManagementDeleteJournalRecord;
}

function fail(code: ReviewedUninstallFailureCode): never {
  throw new ReviewedUninstallExecutionError(code);
}

function exact<Left, Right>(left: Left, right: Right): boolean {
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

function action(journal: UninstallJournal, name: UninstallActionName): UninstallJournalAction | null {
  return journal.actions.find((entry) => entry.name === name) ?? null;
}

function requireAction(journal: UninstallJournal, name: UninstallActionName): UninstallJournalAction {
  return action(journal, name) ?? fail('journal_recovery_mismatch');
}

function finalInstallLocator(journal: InstallJournal): FinalConvergenceLocator {
  const current = journal.actions[journal.actions.length - 1];
  if (!current || current.name !== 'final_convergence' || current.phase !== 'verified' ||
    !current.locator || !('status' in current.locator) || current.locator.status !== 'converged') {
    fail('journal_recovery_mismatch');
  }
  return current.locator;
}

function activeApprovalContext(journal: UninstallJournal): HostedUninstallManagementContext {
  const active = journal.approvalHistory[journal.approvalHistory.length - 1];
  if (!active) fail('journal_recovery_mismatch');
  return Object.freeze({
    schemaVersion: 1,
    installJournal: journal.installJournal,
    approvalHistory: Object.freeze(journal.approvalHistory.map((approval) => Object.freeze({
      attemptId: approval.attemptId,
      uninstallPlan: approval.plan,
      authorizedTarget: approval.authorizedTarget,
    }))),
    activeAttemptId: active.attemptId,
  });
}

function approvalContextForAttempt(
  journal: UninstallJournal,
  attemptId: string,
): HostedUninstallManagementContext {
  const index = journal.approvalHistory.findIndex((approval) => approval.attemptId === attemptId);
  if (index < 0) fail('journal_recovery_mismatch');
  return Object.freeze({
    schemaVersion: 1,
    installJournal: journal.installJournal,
    approvalHistory: Object.freeze(journal.approvalHistory.slice(0, index + 1).map((approval) => Object.freeze({
      attemptId: approval.attemptId,
      uninstallPlan: approval.plan,
      authorizedTarget: approval.authorizedTarget,
    }))),
    activeAttemptId: attemptId,
  });
}

function approvalInput(context: ExecutionContext): {
  readonly attemptId: string;
  readonly authorizedTarget: AuthorizedTarget;
} {
  return Object.freeze({
    attemptId: context.input.attemptId,
    authorizedTarget: context.input.target,
  });
}

async function readJournalOrNull(port: ReviewedUninstallJournalPort): Promise<UninstallJournal | null> {
  try {
    return await port.read();
  } catch (error) {
    if (error instanceof DeployError && error.status === 404) return null;
    throw error;
  }
}

async function prepareAction<Action extends keyof ReviewedPreparedActionRecords>(
  context: ExecutionContext,
  name: Action,
  record: ReviewedPreparedActionRecords[Action],
): Promise<void> {
  context.journal = await context.input.journal.prepareAction({
    expectedRevision: context.journal.revision,
    attemptId: context.input.attemptId,
    now: executionNow(context),
    action: name,
    record,
  });
}

async function replacePreparedAction<Action extends keyof ReviewedPreparedActionRecords>(
  context: ExecutionContext,
  name: Action,
  record: ReviewedPreparedActionRecords[Action],
): Promise<void> {
  context.journal = await context.input.journal.replacePreparedAction({
    expectedRevision: context.journal.revision,
    attemptId: context.input.attemptId,
    now: executionNow(context),
    action: name,
    record,
  });
}

/**
 * `armedAt` is threaded rather than read again: the journal requires the armed
 * value's own timestamp to equal the transition's `now`, and the wall clock
 * advances while the provider prepares the arm.
 */
async function armAction<Action extends keyof ReviewedPreparedActionRecords>(
  context: ExecutionContext,
  name: Action,
  value?: Action extends ManagementDeleteActionName ? HostedUninstallManagementDeleteArm : never,
  armedAt?: number,
): Promise<void> {
  const transition = {
    expectedRevision: context.journal.revision,
    attemptId: context.input.attemptId,
    now: armedAt ?? executionNow(context),
    action: name,
  };
  context.journal = value === undefined
    ? await context.input.journal.armAction(transition)
    : await context.input.journal.armAction({ ...transition, value });
}

async function submittedAction<Action extends keyof ReviewedSubmittedActionValues>(
  context: ExecutionContext,
  name: Action,
  value: ReviewedSubmittedActionValues[Action],
): Promise<void> {
  context.journal = await context.input.journal.recordActionSubmitted({
    expectedRevision: context.journal.revision,
    attemptId: context.input.attemptId,
    now: executionNow(context),
    action: name,
    value,
  });
}

async function verifiedAction<Action extends keyof ReviewedVerifiedActionValues>(
  context: ExecutionContext,
  name: Action,
  value: ReviewedVerifiedActionValues[Action],
): Promise<void> {
  context.journal = await context.input.journal.verifyAction({
    expectedRevision: context.journal.revision,
    attemptId: context.input.attemptId,
    now: executionNow(context),
    action: name,
    value,
  });
}

function lifecycleSubmissions<ErrorValue>(
  error: ErrorValue,
): readonly (UninstallWorkerVersionSubmission | UninstallWorkerDeploymentSubmission | WorkerDeleteSubmission)[] {
  return error instanceof CloudflareUninstallWorkerLifecycleError
    ? error.submissions
    : Object.freeze([]);
}

function knownVersionSubmission<ErrorValue>(
  error: ErrorValue,
  predicate: (value: UninstallWorkerVersionSubmission) => boolean,
): UninstallWorkerVersionSubmission | null {
  const candidates = lifecycleSubmissions(error).filter(
    (submission): submission is UninstallWorkerVersionSubmission =>
      submission.kind === 'uninstall_worker_version',
  );
  const candidate = candidates.length === 1 ? candidates.at(0) : undefined;
  return candidate !== undefined && predicate(candidate) ? candidate : null;
}

function knownDeploymentSubmission<ErrorValue>(
  error: ErrorValue,
  predicate: (value: UninstallWorkerDeploymentSubmission) => boolean,
): UninstallWorkerDeploymentSubmission | null {
  const candidates = lifecycleSubmissions(error).filter(
    (submission): submission is UninstallWorkerDeploymentSubmission =>
      submission.kind === 'uninstall_worker_deployment',
  );
  const candidate = candidates.length === 1 ? candidates.at(0) : undefined;
  return candidate !== undefined && predicate(candidate) ? candidate : null;
}

function knownWorkerDeleteSubmission<ErrorValue>(
  error: ErrorValue,
  predicate: (value: WorkerDeleteSubmission) => boolean,
): WorkerDeleteSubmission | null {
  const candidates = lifecycleSubmissions(error).filter(
    (submission): submission is WorkerDeleteSubmission => submission.kind === 'uninstall_worker_delete',
  );
  const candidate = candidates.length === 1 ? candidates.at(0) : undefined;
  return candidate !== undefined && predicate(candidate) ? candidate : null;
}

function cleanupVariables(context: ExecutionContext): UninstallCleanupVariables {
  return Object.freeze({
    ANKKA_GATEWAY_RELEASE: context.installJournal.releasePin.release,
    ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${context.installJournal.releasePin.artifactSha256}`,
    CLOUDFLARE_ACCOUNT_ID: context.installJournal.target.account.id,
    CLOUDFLARE_ZONE_ID: context.installJournal.target.zone.id,
    CLOUDFLARE_ZONE_NAME: context.installJournal.target.zone.name,
    ZERO_TRUST_READY: 'true',
  });
}

function namespaceInspectionInput(context: ExecutionContext): InspectAdminStateDurableObjectNamespaceInput {
  return Object.freeze({
    accountId: context.installJournal.target.account.id,
    workerName: context.workerName,
    className: 'AdminState',
    storage: 'sqlite',
    expectedNamespaceId: context.namespaceId,
  });
}

function exactNamespace(
  input: InspectAdminStateDurableObjectNamespaceInput,
  value: AdminStateDurableObjectNamespaceLocator,
): AdminStateDurableObjectNamespaceLocator {
  if (value.accountId !== input.accountId || value.workerName !== input.workerName ||
    value.namespaceId !== input.expectedNamespaceId || value.className !== 'AdminState' ||
    value.storage !== 'sqlite') fail('reviewed_adapter_invalid');
  return value;
}

async function prepareVersionPlan(
  context: ExecutionContext,
  stage: 'cleanup' | 'retirement',
  namespace: AdminStateDurableObjectNamespaceLocator,
  uninstallNonce: string,
): Promise<UninstallWorkerVersionMutationPlan> {
  const common = {
    accountId: context.installJournal.target.account.id,
    workerName: context.workerName,
    workerId: context.workerId,
    uninstallCycleId: context.journal.uninstallCycleId,
    releaseSet: context.releaseSet,
  };
  return stage === 'cleanup'
    ? context.input.provider.prepareCleanupVersion({
      ...common,
      namespaceId: namespace.namespaceId,
      variables: cleanupVariables(context),
      uninstallNonce,
    })
    : context.input.provider.prepareRetirementVersion(common);
}

function versionRecord(
  context: ExecutionContext,
  stage: 'cleanup' | 'retirement',
  namespacePresence: AdminStateNamespacePresenceProof | null,
): UninstallWorkerVersionJournalRecord {
  const release = stage === 'cleanup' ? context.releaseSet.cleanup : context.releaseSet.retirement;
  return Object.freeze({
    schemaVersion: 1,
    kind: 'uninstall_worker_version_create',
    stage,
    accountId: context.installJournal.target.account.id,
    workerName: context.workerName,
    workerId: context.workerId,
    uninstallCycleId: context.journal.uninstallCycleId,
    namespacePresence,
    release: release.release,
    artifactSha256: release.artifactSha256,
    componentSha256: release.componentSha256,
    recovery: null,
  });
}

async function inspectVersionTwice(
  context: ExecutionContext,
  recovery: UninstallWorkerVersionRecoveryRecord,
): Promise<UninstallWorkerVersionSubmission | null> {
  const first = await context.input.provider.inspectVersion(recovery, context.call);
  const second = await context.input.provider.inspectVersion(recovery, context.call);
  if (!exact(first, second)) fail('provider_recovery_missing');
  return second;
}

async function convergeWorkerVersion(
  context: ExecutionContext,
  stage: 'cleanup' | 'retirement',
  namespace: AdminStateDurableObjectNamespaceLocator,
  namespacePresence: AdminStateNamespacePresenceProof | null,
  uninstallNonce: string,
): Promise<UninstallWorkerVersionSubmission> {
  const name = stage === 'cleanup'
    ? 'cleanup_worker_version_create' as const
    : 'retirement_worker_version_create' as const;
  let current = action(context.journal, name);
  if (!current) {
    await prepareAction(context, name, versionRecord(context, stage, namespacePresence));
    current = requireAction(context.journal, name);
  }
  const mutation = await prepareVersionPlan(context, stage, namespace, uninstallNonce);
  if (mutation.recovery.stage !== stage) fail('reviewed_adapter_invalid');
  if (!('kind' in current.record) || current.record.kind !== 'uninstall_worker_version_create' ||
    current.record.stage !== stage) {
    fail('journal_recovery_mismatch');
  }
  if (current.record.recovery === null) {
    context.journal = await context.input.journal.attachWorkerVersionRecovery({
      expectedRevision: context.journal.revision,
      attemptId: context.input.attemptId,
      now: executionNow(context),
      action: name,
      recovery: mutation.recovery,
    });
    current = requireAction(context.journal, name);
  } else if (!exact(current.record.recovery, mutation.recovery)) {
    fail('journal_recovery_mismatch');
  }
  let armedHere = false;
  if (current.phase === 'prepared') {
    if (stage === 'cleanup') {
      const preflight = context.journal.actions[0]?.record;
      if (!preflight || !('expiresAt' in preflight) || executionNow(context) >= preflight.expiresAt) {
        fail('fresh_preflight_expired');
      }
    }
    await armAction(context, name);
    current = requireAction(context.journal, name);
    armedHere = true;
  }
  if (current.phase === 'send_armed') {
    let submission: UninstallWorkerVersionSubmission | null = null;
    if (armedHere) {
      try {
        submission = await context.input.provider.submitVersion(mutation, context.call);
      } catch (error) {
        submission = knownVersionSubmission(
          error,
          (candidate) => candidate.stage === stage &&
            candidate.requestHash === mutation.recovery.requestHash,
        );
        if (!submission) submission = await inspectVersionTwice(context, mutation.recovery);
        if (!submission) throw error;
      }
    } else {
      submission = await inspectVersionTwice(context, mutation.recovery);
      if (!submission) fail('provider_recovery_missing');
    }
    await submittedAction(context, name, submission);
    current = requireAction(context.journal, name);
  }
  const persisted = 'kind' in current.record && current.record.kind === 'uninstall_worker_version_create'
    ? current.record.recovery
    : null;
  if (!persisted) fail('journal_recovery_mismatch');
  if (current.phase === 'submitted') {
    const submission = current.locator;
    if (!submission || !('kind' in submission) || submission.kind !== 'uninstall_worker_version') {
      fail('journal_recovery_mismatch');
    }
    await context.input.provider.verifyVersion(persisted, submission, context.call);
    await verifiedAction(context, name, submission);
    current = requireAction(context.journal, name);
  }
  const submission = current.locator;
  if (current.phase !== 'verified' || !submission || !('kind' in submission) ||
    submission.kind !== 'uninstall_worker_version') fail('journal_recovery_mismatch');
  await context.input.provider.verifyVersion(persisted, submission, context.call);
  return submission;
}

async function inspectDeploymentTwice(
  context: ExecutionContext,
  intent: UninstallWorkerDeploymentMutationIntent,
): Promise<UninstallWorkerDeploymentSubmission | null> {
  const first = await context.input.provider.inspectDeployment(intent, context.call);
  const second = await context.input.provider.inspectDeployment(intent, context.call);
  if (!exact(first, second)) fail('provider_recovery_missing');
  return second;
}

async function convergeWorkerDeployment(
  context: ExecutionContext,
  stage: 'cleanup' | 'retirement' | 'restore_clean',
  versionId: string,
): Promise<UninstallWorkerDeploymentSubmission> {
  const name = stage === 'cleanup'
    ? 'cleanup_worker_deployment_create' as const
    : stage === 'retirement'
      ? 'retirement_worker_deployment_create' as const
      : 'restore_clean_worker_deployment' as const;
  const intent = await context.input.provider.prepareDeployment({
    stage,
    accountId: context.installJournal.target.account.id,
    workerName: context.workerName,
    workerId: context.workerId,
    uninstallCycleId: context.journal.uninstallCycleId,
    versionId,
  });
  let current = action(context.journal, name);
  const record = Object.freeze({
    schemaVersion: 1,
    kind: 'uninstall_worker_deployment_create',
    stage,
    intent,
  });
  if (!current) {
    await prepareAction(context, name, record);
    current = requireAction(context.journal, name);
  } else if (!('kind' in current.record) || current.record.kind !== 'uninstall_worker_deployment_create' ||
    !exact(current.record.intent, intent)) {
    fail('journal_recovery_mismatch');
  }
  let armedHere = false;
  if (current.phase === 'prepared') {
    await armAction(context, name);
    current = requireAction(context.journal, name);
    armedHere = true;
  }
  if (current.phase === 'send_armed') {
    let submission: UninstallWorkerDeploymentSubmission | null = null;
    if (armedHere) {
      try {
        submission = await context.input.provider.submitDeployment(intent, context.call);
      } catch (error) {
        submission = knownDeploymentSubmission(
          error,
          (candidate) => candidate.stage === stage && candidate.requestHash === intent.requestHash,
        );
        if (!submission) submission = await inspectDeploymentTwice(context, intent);
        if (!submission) throw error;
      }
    } else {
      submission = await inspectDeploymentTwice(context, intent);
      if (!submission) fail('provider_recovery_missing');
    }
    await submittedAction(context, name, submission);
    current = requireAction(context.journal, name);
  }
  if (current.phase === 'submitted') {
    const submission = current.locator;
    if (!submission || !('kind' in submission) || submission.kind !== 'uninstall_worker_deployment') {
      fail('journal_recovery_mismatch');
    }
    await context.input.provider.verifyDeployment(intent, submission, context.call);
    await verifiedAction(context, name, submission);
    current = requireAction(context.journal, name);
  }
  const submission = current.locator;
  if (current.phase !== 'verified' || !submission || !('kind' in submission) ||
    submission.kind !== 'uninstall_worker_deployment') fail('journal_recovery_mismatch');
  await context.input.provider.verifyDeployment(intent, submission, context.call);
  // The deployment record stays true forever, but "still the active
  // deployment" is only true until the next stage replaces it. A resumed run
  // re-enters every earlier stage, so re-asserting activeness after the journal
  // itself records the successor would contradict the journal.
  if (!supersededDeployment(context.journal, stage)) {
    await context.input.provider.verifyActiveDeployment(intent, submission, context.call);
  }
  return submission;
}

async function proveCurrentCleanupWorker(context: ExecutionContext): Promise<void> {
  const versionAction = requireAction(context.journal, 'cleanup_worker_version_create');
  if (versionAction.phase !== 'verified' ||
    !('kind' in versionAction.record) || versionAction.record.kind !== 'uninstall_worker_version_create' ||
    versionAction.record.stage !== 'cleanup' || versionAction.record.recovery?.stage !== 'cleanup' ||
    !versionAction.locator || !('kind' in versionAction.locator) ||
    versionAction.locator.kind !== 'uninstall_worker_version' || versionAction.locator.stage !== 'cleanup') {
    fail('journal_recovery_mismatch');
  }
  const deploymentAction = requireAction(context.journal, 'cleanup_worker_deployment_create');
  if (deploymentAction.phase !== 'verified' ||
    !('kind' in deploymentAction.record) ||
    deploymentAction.record.kind !== 'uninstall_worker_deployment_create' ||
    deploymentAction.record.stage !== 'cleanup' || deploymentAction.record.intent.stage !== 'cleanup' ||
    !deploymentAction.locator || !('kind' in deploymentAction.locator) ||
    deploymentAction.locator.kind !== 'uninstall_worker_deployment' ||
    deploymentAction.locator.stage !== 'cleanup') fail('journal_recovery_mismatch');
  const proof = await context.input.provider.proveActiveCleanupWorker(
    versionAction.record.recovery,
    versionAction.locator,
    deploymentAction.record.intent,
    deploymentAction.locator,
    context.call,
  );
  if (!exact(proof.version, versionAction.locator) ||
    !exact(proof.deployment, deploymentAction.locator)) fail('reviewed_adapter_invalid');
}

/** The verified action whose deployment replaced this stage's, if it exists. */
function supersededDeployment(
  journal: UninstallJournal,
  stage: 'cleanup' | 'retirement' | 'restore_clean',
): boolean {
  const successor = stage === 'cleanup'
    ? 'restore_clean_worker_deployment' as const
    : stage === 'restore_clean'
      ? 'retirement_worker_deployment_create' as const
      : null;
  if (!successor) return false;
  return action(journal, successor)?.phase === 'verified';
}

/** The terminal state of the customer removal step: removed and closed again. */
function completedCustomerRemoval(
  attempt: CustomerGatewayRemoveRequestAttempt | null,
): attempt is CustomerGatewayRemoveRequestAttempt & {
  readonly locator: Extract<CustomerUninstallLocator, { readonly status: 'removed' }>;
} {
  return attempt?.requestPhase === 'verified' && attempt.locator?.status === 'removed' &&
    latestDisable(attempt)?.phase === 'verified';
}

function latestCustomerAttempt(journal: UninstallJournal): CustomerGatewayRemoveRequestAttempt | null {
  const current = action(journal, 'customer_gateway_remove');
  if (!current || !('kind' in current.record) || current.record.kind !== 'customer_gateway_remove') return null;
  return current.record.attempts[current.record.attempts.length - 1] ?? null;
}

function latestDisable(attempt: CustomerGatewayRemoveRequestAttempt): UninstallWorkersDevMutation | null {
  return attempt.disableAttempts[attempt.disableAttempts.length - 1] ?? null;
}

function mutationFromSemantic(
  context: ExecutionContext,
  semantic: CustomerUninstallSemanticRecord,
): CustomerUninstallMutationPlan {
  return Object.freeze({
    ephemeral: Object.freeze({
      claim: Object.freeze({
        schemaVersion: 1,
        requestId: semantic.requestId,
        issuedAt: semantic.issuedAt,
        expiresAt: semantic.expiresAt,
        target: Object.freeze({
          accountId: semantic.accountId,
          zoneId: semantic.zoneId,
          zoneName: semantic.zoneName,
        }),
        release: semantic.release,
        expected: Object.freeze({
          configurationHash: semantic.configurationHash,
          installationId: semantic.installationId,
          desiredHash: semantic.desiredHash,
          readyReceipt: context.finalInstall.customerReceiptEvidence,
        }),
      }),
    }),
    semantic,
  });
}

async function freshCustomerMutation(
  context: ExecutionContext,
  workersSubdomain: AccountWorkersSubdomain,
): Promise<CustomerUninstallMutationPlan> {
  const base = {
    installJournal: context.installJournal,
    uninstallPlan: context.plan,
    approval: approvalInput(context),
    accountWorkersSubdomain: workersSubdomain,
    nowMs: executionNow(context),
  };
  return context.input.randomBytes === undefined
    ? context.input.provider.prepareCustomerRequest(base)
    : context.input.provider.prepareCustomerRequest({
      ...base,
      randomBytes: context.input.randomBytes,
    });
}

async function appendOrReplaceCustomerCycle(
  context: ExecutionContext,
  workersSubdomain: AccountWorkersSubdomain,
  replace: boolean,
): Promise<CustomerUninstallMutationPlan> {
  const mutation = await freshCustomerMutation(context, workersSubdomain);
  const transition = {
    expectedRevision: context.journal.revision,
    attemptId: context.input.attemptId,
    now: executionNow(context),
    semantic: mutation.semantic,
  };
  context.journal = replace
    ? await context.input.journal.replacePreparedCustomerRemoveCycle(transition)
    : await context.input.journal.appendCustomerRemoveCycle(transition);
  return mutation;
}

async function observeWorkersDev(
  context: ExecutionContext,
  desired: boolean,
): Promise<WorkerSubdomainState> {
  const input = {
    ...context.call,
    accountId: context.installJournal.target.account.id,
    plan: context.installJournal.plan,
  };
  try {
    return await context.input.provider.verifyWorkersDev(desired, input);
  } catch (firstError) {
    try {
      return await context.input.provider.verifyWorkersDev(!desired, input);
    } catch {
      throw firstError;
    }
  }
}

async function convergeWorkersDevMutation(
  context: ExecutionContext,
  enabled: boolean,
): Promise<'verified' | 'not_applied'> {
  let attempt = latestCustomerAttempt(context.journal);
  if (!attempt) fail('journal_recovery_mismatch');
  let mutation = enabled ? attempt.enable : latestDisable(attempt);
  if (!mutation) fail('journal_recovery_mismatch');
  let armedHere = false;
  if (mutation.phase === 'prepared') {
    if (mutation.approvalAttemptId !== context.input.attemptId) fail('fresh_grant_required');
    context.journal = await context.input.journal.armCustomerWorkersDev({
      expectedRevision: context.journal.revision,
      attemptId: context.input.attemptId,
      now: executionNow(context),
      enabled,
    });
    attempt = latestCustomerAttempt(context.journal);
    mutation = attempt ? (enabled ? attempt.enable : latestDisable(attempt)) : null;
    if (!mutation) fail('journal_recovery_mismatch');
    armedHere = true;
  }
  if (mutation.phase === 'send_armed') {
    let observed: WorkerSubdomainState;
    if (armedHere) {
      try {
        observed = await context.input.provider.setWorkersDev(enabled, {
          ...context.call,
          accountId: context.installJournal.target.account.id,
          plan: context.installJournal.plan,
        });
      } catch (error) {
        try {
          observed = await observeWorkersDev(context, enabled);
        } catch {
          throw error;
        }
      }
    } else {
      // A durably armed mutation is never submitted twice. Exact reads either
      // adopt the desired state or terminally record that it was not applied.
      observed = await observeWorkersDev(context, enabled);
    }
    if (observed.enabled === enabled && observed.previewsEnabled === false) {
      context.journal = await context.input.journal.recordCustomerWorkersDevSubmitted({
        expectedRevision: context.journal.revision,
        attemptId: context.input.attemptId,
        now: executionNow(context),
        enabled,
        locator: observed,
      });
    } else if (observed.enabled === !enabled && observed.previewsEnabled === false) {
      context.journal = await context.input.journal.recordCustomerWorkersDevNotApplied({
        expectedRevision: context.journal.revision,
        attemptId: context.input.attemptId,
        now: executionNow(context),
        enabled,
        locator: observed,
      });
      return 'not_applied';
    } else {
      fail('reviewed_adapter_invalid');
    }
    attempt = latestCustomerAttempt(context.journal);
    mutation = attempt ? (enabled ? attempt.enable : latestDisable(attempt)) : null;
    if (!mutation) fail('journal_recovery_mismatch');
  }
  if (mutation.phase === 'submitted') {
    await context.input.provider.verifyWorkersDev(enabled, {
      ...context.call,
      accountId: context.installJournal.target.account.id,
      plan: context.installJournal.plan,
    });
    context.journal = await context.input.journal.verifyCustomerWorkersDev({
      expectedRevision: context.journal.revision,
      attemptId: context.input.attemptId,
      now: executionNow(context),
      enabled,
    });
    attempt = latestCustomerAttempt(context.journal);
    mutation = attempt ? (enabled ? attempt.enable : latestDisable(attempt)) : null;
  }
  if (!mutation) fail('journal_recovery_mismatch');
  if (mutation.phase === 'not_applied') return 'not_applied';
  if (mutation.phase !== 'verified') fail('journal_recovery_mismatch');
  await context.input.provider.verifyWorkersDev(enabled, {
    ...context.call,
    accountId: context.installJournal.target.account.id,
    plan: context.installJournal.plan,
  });
  return 'verified';
}

async function convergeWorkersDevDisabled(context: ExecutionContext): Promise<void> {
  for (let cycle = 0; cycle < MAX_CUSTOMER_DISABLE_CYCLES; cycle += 1) {
    let attempt = latestCustomerAttempt(context.journal);
    if (!attempt || attempt.enable.phase !== 'verified') fail('journal_recovery_mismatch');
    let disable = latestDisable(attempt);
    if (!disable) {
      context.journal = await context.input.journal.prepareCustomerWorkersDevDisable({
        expectedRevision: context.journal.revision,
        attemptId: context.input.attemptId,
        now: executionNow(context),
      });
    } else if (disable.phase === 'prepared' && disable.approvalAttemptId !== context.input.attemptId) {
      context.journal = await context.input.journal.replacePreparedCustomerWorkersDevDisable({
        expectedRevision: context.journal.revision,
        attemptId: context.input.attemptId,
        now: executionNow(context),
      });
    } else if (disable.phase === 'not_applied') {
      if (disable.approvalAttemptId === context.input.attemptId) fail('fresh_grant_required');
      context.journal = await context.input.journal.prepareCustomerWorkersDevDisable({
        expectedRevision: context.journal.revision,
        attemptId: context.input.attemptId,
        now: executionNow(context),
      });
    }
    const result = await convergeWorkersDevMutation(context, false);
    if (result === 'verified') return;
    attempt = latestCustomerAttempt(context.journal);
    disable = attempt ? latestDisable(attempt) : null;
    if (!disable || disable.approvalAttemptId === context.input.attemptId) fail('fresh_grant_required');
  }
  fail('journal_recovery_mismatch');
}

async function convergeCustomerGatewayRemoval(
  context: ExecutionContext,
  workersSubdomain: AccountWorkersSubdomain,
  uninstallNonce: string,
): Promise<Extract<CustomerUninstallLocator, { readonly status: 'removed' }>> {
  let preparedMutation: CustomerUninstallMutationPlan | null = null;
  for (let cycle = 0; cycle < 8; cycle += 1) {
    let attempt = latestCustomerAttempt(context.journal);
    // A resumed run re-enters this step. Once the journal proves the removal
    // ran and the subdomain was closed again, there is nothing to converge:
    // re-enabling workers.dev would contradict the disable it already recorded.
    if (completedCustomerRemoval(attempt)) return attempt.locator;
    if (!attempt) {
      preparedMutation = await appendOrReplaceCustomerCycle(context, workersSubdomain, false);
      attempt = latestCustomerAttempt(context.journal);
    } else if (attempt.enable.phase === 'prepared' &&
      attempt.approvalAttemptId !== context.input.attemptId) {
      preparedMutation = await appendOrReplaceCustomerCycle(context, workersSubdomain, true);
      attempt = latestCustomerAttempt(context.journal);
    } else if (attempt.enable.phase === 'not_applied') {
      if (attempt.approvalAttemptId === context.input.attemptId) fail('fresh_grant_required');
      preparedMutation = await appendOrReplaceCustomerCycle(context, workersSubdomain, false);
      attempt = latestCustomerAttempt(context.journal);
    } else if (
      latestDisable(attempt)?.phase === 'verified' &&
      attempt.locator?.status === 'recovery_required' &&
      attempt.locator.freshGrantRequired
    ) {
      if (attempt.approvalAttemptId === context.input.attemptId) fail('fresh_grant_required');
      preparedMutation = await appendOrReplaceCustomerCycle(context, workersSubdomain, false);
      attempt = latestCustomerAttempt(context.journal);
    }
    if (!attempt) fail('journal_recovery_mismatch');

    const enabled = await convergeWorkersDevMutation(context, true);
    if (enabled === 'not_applied') {
      attempt = latestCustomerAttempt(context.journal);
      if (!attempt || attempt.approvalAttemptId === context.input.attemptId) fail('fresh_grant_required');
      continue;
    }
    attempt = latestCustomerAttempt(context.journal);
    if (!attempt) fail('journal_recovery_mismatch');
    let armedHere = false;
    if (attempt.requestPhase === 'prepared') {
      if (attempt.approvalAttemptId !== context.input.attemptId) fail('fresh_grant_required');
      try {
        // The one-shot request is armed only once the route is proven to answer
        // and the exact signed cleanup module/bindings remain the sole active
        // deployment after that edge-readiness race window.
        await context.input.provider.awaitCustomerRemoveReady({
          ...context.call,
          accountWorkersSubdomain: workersSubdomain,
          workerName: context.workerName,
        });
        await proveCurrentCleanupWorker(context);
      } catch (error) {
        await convergeWorkersDevDisabled(context);
        throw error;
      }
      context.journal = await context.input.journal.armCustomerRemoveRequest({
        expectedRevision: context.journal.revision,
        attemptId: context.input.attemptId,
        now: executionNow(context),
      });
      attempt = latestCustomerAttempt(context.journal);
      if (!attempt) fail('journal_recovery_mismatch');
      armedHere = true;
    }
    if (attempt.requestPhase === 'send_armed') {
      if (!armedHere) {
        // The public cleanup contract intentionally has no retry. Until it
        // exposes an authenticated read-only request-status proof, an unknown
        // persisted POST cannot be recovered or replayed.
        await convergeWorkersDevDisabled(context);
        fail('customer_recovery_unavailable');
      }
      const mutation = preparedMutation ?? mutationFromSemantic(context, attempt.semantic);
      let locator: CustomerUninstallLocator;
      try {
        locator = await context.input.provider.submitCustomerRequest({
          installJournal: context.installJournal,
          uninstallPlan: context.plan,
          approval: approvalInput(context),
          mutation,
          accountWorkersSubdomain: workersSubdomain,
          uninstallNonce,
          cloudflareAccessToken: context.input.accessToken,
          transport: context.input.transport,
          nowMs: executionNow(context),
        });
      } catch (error) {
        await convergeWorkersDevDisabled(context);
        throw error;
      }
      context.journal = await context.input.journal.recordCustomerRemoveRequestSubmitted({
        expectedRevision: context.journal.revision,
        attemptId: context.input.attemptId,
        now: executionNow(context),
        locator,
      });
      attempt = latestCustomerAttempt(context.journal);
      if (!attempt) fail('journal_recovery_mismatch');
    }
    if (attempt.requestPhase === 'submitted' && attempt.locator?.status === 'removed') {
      context.journal = await context.input.journal.verifyCustomerRemoveRequest({
        expectedRevision: context.journal.revision,
        attemptId: context.input.attemptId,
        now: executionNow(context),
      });
      attempt = latestCustomerAttempt(context.journal);
      if (!attempt) fail('journal_recovery_mismatch');
    }
    await convergeWorkersDevDisabled(context);
    attempt = latestCustomerAttempt(context.journal);
    if (attempt?.requestPhase === 'verified' && attempt.locator?.status === 'removed' &&
      latestDisable(attempt)?.phase === 'verified') return attempt.locator;
    if (attempt?.locator?.status === 'recovery_required' && attempt.locator.freshGrantRequired) {
      fail('fresh_grant_required');
    }
    fail('customer_recovery_unavailable');
  }
  fail('journal_recovery_mismatch');
}

function verifiedManagementAbsence(
  context: ExecutionContext,
  name: ManagementDeleteActionName,
): HostedUninstallManagementAbsenceEvidence {
  const current = requireAction(context.journal, name);
  if (current.phase !== 'verified' || !current.locator || !('status' in current.locator) ||
    current.locator.status !== 'absent') fail('journal_recovery_mismatch');
  return current.locator;
}

function managementPrerequisites(
  context: ExecutionContext,
  name: ManagementDeleteActionName,
): HostedUninstallManagementDeletePrerequisites {
  if (name === 'management_custom_domain_delete') {
    const preflight = context.journal.managementPreflightHistory[
      context.journal.managementPreflightHistory.length - 1
    ];
    if (!preflight) fail('journal_recovery_mismatch');
    return Object.freeze({ schemaVersion: 1, action: name, preflight });
  }
  const domainAbsence = verifiedManagementAbsence(context, 'management_custom_domain_delete');
  if (name === 'management_admin_policy_delete') {
    return Object.freeze({ schemaVersion: 1, action: name, domainAbsence });
  }
  return Object.freeze({
    schemaVersion: 1,
    action: name,
    domainAbsence,
    policyAbsence: verifiedManagementAbsence(context, 'management_admin_policy_delete'),
  });
}

function latestManagementAttempt(
  journal: UninstallJournal,
  name: ManagementDeleteActionName,
): ManagementDeleteAttempt | null {
  const current = action(journal, name);
  if (!current || !('kind' in current.record) || current.record.kind !== 'uninstall_management_delete' ||
    current.record.action !== name) return null;
  return current.record.attempts[current.record.attempts.length - 1] ?? null;
}

async function appendFreshManagementPreflight(context: ExecutionContext): Promise<void> {
  const now = executionNow(context);
  const preflight = await context.input.provider.preflightManagement(
    activeApprovalContext(context.journal),
    context.call,
    now,
  );
  context.journal = await context.input.journal.appendManagementPreflight({
    expectedRevision: context.journal.revision,
    attemptId: context.input.attemptId,
    now: executionNow(context),
    preflight,
  });
}

async function freshManagementDeleteDraft(
  context: ExecutionContext,
  name: ManagementDeleteActionName,
): Promise<FreshManagementDeleteDraft> {
  const prerequisites = managementPrerequisites(context, name);
  const intent = await context.input.provider.prepareManagementDeleteIntent(
    activeApprovalContext(context.journal),
    name,
    prerequisites,
  );
  return Object.freeze({
    prerequisites,
    intent,
    record: Object.freeze({
      schemaVersion: 1,
      kind: 'uninstall_management_delete',
      prerequisites,
      intent,
    }),
  });
}

async function recordManagementRecovery(
  context: ExecutionContext,
  name: ManagementDeleteActionName,
  attempt: ManagementDeleteAttempt,
): Promise<'absent' | 'still_present'> {
  if (!attempt.arm) fail('journal_recovery_mismatch');
  const evidence = await context.input.provider.recoverManagementDelete(
    activeApprovalContext(context.journal),
    attempt.intent,
    attempt.arm,
    attempt.prerequisites,
    context.call,
  );
  context.journal = await context.input.journal.recordManagementDeleteRecovery({
    expectedRevision: context.journal.revision,
    attemptId: context.input.attemptId,
    now: executionNow(context),
    action: name,
    evidence,
  });
  return evidence.status;
}

async function convergeManagementDelete(
  context: ExecutionContext,
  name: ManagementDeleteActionName,
): Promise<HostedUninstallManagementAbsenceEvidence> {
  for (let cycle = 0; cycle < 8; cycle += 1) {
    let current = action(context.journal, name);
    let latest = latestManagementAttempt(context.journal, name);
    if (!current) {
      if (name === 'management_custom_domain_delete') await appendFreshManagementPreflight(context);
      const draft = await freshManagementDeleteDraft(context, name);
      await prepareAction(context, name, draft.record);
      current = requireAction(context.journal, name);
      latest = latestManagementAttempt(context.journal, name);
    } else if (latest?.phase === 'prepared' && latest.intent.attemptId !== context.input.attemptId) {
      if (name === 'management_custom_domain_delete') await appendFreshManagementPreflight(context);
      const draft = await freshManagementDeleteDraft(context, name);
      await replacePreparedAction(context, name, draft.record);
      current = requireAction(context.journal, name);
      latest = latestManagementAttempt(context.journal, name);
    }
    if (!current || !latest) fail('journal_recovery_mismatch');

    if (name === 'management_custom_domain_delete' && latest.phase === 'prepared') {
      const preflight = latest.prerequisites.action === 'management_custom_domain_delete'
        ? latest.prerequisites.preflight
        : null;
      const now = executionNow(context);
      if (!preflight || now >= preflight.expiresAt || now - preflight.checkedAt > FRESH_PREFLIGHT_TTL_MS) {
        await appendFreshManagementPreflight(context);
        const draft = await freshManagementDeleteDraft(context, name);
        await replacePreparedAction(context, name, draft.record);
        current = requireAction(context.journal, name);
        latest = latestManagementAttempt(context.journal, name);
        if (!latest) fail('journal_recovery_mismatch');
      }
    }

    if (latest.phase === 'send_armed' || latest.phase === 'submitted') {
      const recovered = await recordManagementRecovery(context, name, latest);
      if (recovered === 'absent') return verifiedManagementAbsence(context, name);
      latest = latestManagementAttempt(context.journal, name);
      if (!latest || latest.phase !== 'not_applied') fail('journal_recovery_mismatch');
    }
    if (latest.phase === 'not_applied') {
      if (latest.intent.attemptId === context.input.attemptId) fail('fresh_grant_required');
      if (name === 'management_custom_domain_delete') await appendFreshManagementPreflight(context);
      const draft = await freshManagementDeleteDraft(context, name);
      context.journal = await context.input.journal.appendManagementDeleteAttempt({
        expectedRevision: context.journal.revision,
        attemptId: context.input.attemptId,
        now: executionNow(context),
        action: name,
        prerequisites: draft.prerequisites,
        intent: draft.intent,
      });
      current = requireAction(context.journal, name);
      latest = latestManagementAttempt(context.journal, name);
      if (!latest) fail('journal_recovery_mismatch');
    }
    if (latest.phase === 'verified') return verifiedManagementAbsence(context, name);
    if (latest.phase !== 'prepared') fail('journal_recovery_mismatch');

    const armedAt = executionNow(context);
    const arm = await context.input.provider.prepareManagementDeleteArm(
      activeApprovalContext(context.journal),
      latest.intent,
      latest.prerequisites,
      armedAt,
    );
    await armAction(context, name, arm, armedAt);
    latest = latestManagementAttempt(context.journal, name);
    if (!latest?.arm) fail('journal_recovery_mismatch');
    try {
      const submission = await context.input.provider.submitManagementDelete(
        activeApprovalContext(context.journal),
        latest.intent,
        latest.arm,
        latest.prerequisites,
        context.call,
        executionNow(context),
      );
      await submittedAction(context, name, submission);
      latest = latestManagementAttempt(context.journal, name);
      if (!latest) fail('journal_recovery_mismatch');
      try {
        const absence = await context.input.provider.verifyManagementDelete(
          activeApprovalContext(context.journal),
          latest.intent,
          latest.prerequisites,
          context.call,
        );
        await verifiedAction(context, name, absence);
        return verifiedManagementAbsence(context, name);
      } catch {
        // A submitted DELETE is never replayed. Resolve only through exact GET
        // and complete-list recovery below.
      }
    } catch {
      // A durably armed DELETE is likewise recovered read-only below.
    }
    latest = latestManagementAttempt(context.journal, name);
    if (!latest || !latest.arm) fail('journal_recovery_mismatch');
    const recovered = await recordManagementRecovery(context, name, latest);
    if (recovered === 'absent') return verifiedManagementAbsence(context, name);
    fail('fresh_grant_required');
  }
  fail('journal_recovery_mismatch');
}

function retirementProofInput(
  context: ExecutionContext,
  namespace: AdminStateDurableObjectNamespaceLocator,
  retirementRecovery: UninstallWorkerVersionRecoveryRecord,
  retirementSubmission: UninstallWorkerVersionSubmission,
  retirementDeploymentIntent: UninstallWorkerDeploymentMutationIntent,
  retirementDeploymentSubmission: UninstallWorkerDeploymentSubmission,
): ProveAdminStateNamespaceRetiredInput {
  if (retirementRecovery.stage !== 'retirement' || retirementSubmission.stage !== 'retirement' ||
    retirementDeploymentIntent.stage !== 'retirement' || retirementDeploymentSubmission.stage !== 'retirement') {
    fail('journal_recovery_mismatch');
  }
  return Object.freeze({
    namespace,
    workerId: context.workerId,
    uninstallCycleId: context.journal.uninstallCycleId,
    retirementRecovery,
    retirementSubmission,
    retirementDeploymentIntent,
    retirementDeploymentSubmission,
  });
}

async function convergeNamespaceRetirement(
  context: ExecutionContext,
  input: ProveAdminStateNamespaceRetiredInput,
): Promise<AdminStateNamespaceRetirementProof> {
  const name = 'admin_state_namespace_retired' as const;
  let current = action(context.journal, name);
  if (!current) {
    const proof = await context.input.provider.proveNamespaceRetired(input, context.call);
    await prepareAction(context, name, Object.freeze({ schemaVersion: 1, kind: name, proof }));
    current = requireAction(context.journal, name);
  }
  if (!('kind' in current.record) || current.record.kind !== 'admin_state_namespace_retired') {
    fail('journal_recovery_mismatch');
  }
  const proof = current.record.proof;
  if (current.phase === 'prepared') {
    await armAction(context, name);
    current = requireAction(context.journal, name);
  }
  if (current.phase === 'send_armed') {
    await submittedAction(context, name, proof);
    current = requireAction(context.journal, name);
  }
  if (current.phase === 'submitted') {
    const fresh = await context.input.provider.proveNamespaceRetired(input, context.call);
    if (!exact(fresh, proof)) fail('provider_recovery_missing');
    await verifiedAction(context, name, fresh);
    current = requireAction(context.journal, name);
  }
  if (current.phase !== 'verified' || !current.locator || !('kind' in current.locator) ||
    current.locator.kind !== 'admin_state_namespace_retirement') fail('journal_recovery_mismatch');
  const fresh = await context.input.provider.proveNamespaceRetired(input, context.call);
  if (!exact(fresh, current.locator)) fail('provider_recovery_missing');
  return current.locator;
}

function deterministicWorkerDeleteSubmission(intent: WorkerDeleteMutationIntent): WorkerDeleteSubmission {
  return Object.freeze({
    kind: 'uninstall_worker_delete',
    accountId: intent.accountId,
    workerName: intent.workerName,
    workerId: intent.workerId,
    uninstallCycleId: intent.uninstallCycleId,
    namespaceId: intent.namespaceId,
    retirementVersionId: intent.retirementVersionId,
    retirementProofCommitment: intent.retirementProofCommitment,
    requestHash: intent.requestHash,
    correlationTag: intent.correlationTag,
  });
}

async function convergeWorkerDelete(
  context: ExecutionContext,
  proofInput: ProveAdminStateNamespaceRetiredInput,
): Promise<{ readonly intent: WorkerDeleteMutationIntent; readonly proof: WorkerDeletionRecoveryProof }> {
  const name = 'management_worker_delete' as const;
  let current = action(context.journal, name);
  let intent: WorkerDeleteMutationIntent;
  if (!current) {
    intent = await context.input.provider.prepareWorkerDelete(proofInput, context.call);
    await prepareAction(context, name, Object.freeze({
      schemaVersion: 1,
      kind: name,
      intent,
      submission: null,
    }));
    current = requireAction(context.journal, name);
  }
  if (!('kind' in current.record) || current.record.kind !== 'management_worker_delete') {
    fail('journal_recovery_mismatch');
  }
  intent = current.record.intent;
  let armedHere = false;
  if (current.phase === 'prepared') {
    await armAction(context, name);
    current = requireAction(context.journal, name);
    armedHere = true;
  }
  if (current.phase === 'send_armed') {
    let submission: WorkerDeleteSubmission | null = null;
    if (armedHere) {
      try {
        submission = await context.input.provider.submitWorkerDelete(intent, proofInput, context.call);
      } catch (error) {
        submission = knownWorkerDeleteSubmission(
          error,
          (candidate) => candidate.requestHash === intent.requestHash,
        );
        if (!submission) {
          // Worker DELETE has no provider locator; once exact absence is proved,
          // its deterministic semantic submission can safely advance the
          // journal without issuing another DELETE.
          await context.input.provider.recoverWorkerDelete(intent, context.call);
          submission = deterministicWorkerDeleteSubmission(intent);
        }
      }
    } else {
      await context.input.provider.recoverWorkerDelete(intent, context.call);
      submission = deterministicWorkerDeleteSubmission(intent);
    }
    await submittedAction(context, name, submission);
    current = requireAction(context.journal, name);
  }
  const proof = await context.input.provider.recoverWorkerDelete(intent, context.call);
  if (current.phase === 'submitted') {
    await verifiedAction(context, name, proof);
    current = requireAction(context.journal, name);
  }
  if (current.phase !== 'verified' || !current.locator || !('kind' in current.locator) ||
    current.locator.kind !== 'uninstall_worker_deletion_proof' || !exact(current.locator, proof)) {
    fail('journal_recovery_mismatch');
  }
  return Object.freeze({ intent, proof });
}

async function convergeNoManagedResidue(
  context: ExecutionContext,
  deletionEvidence: readonly HostedUninstallManagementAbsenceEvidence[],
  lifecycle: HostedUninstallManagementLifecycleEvidence,
): Promise<HostedUninstallManagementNoManagedResidueResult> {
  const name = 'management_no_managed_residue' as const;
  let current = action(context.journal, name);
  let proofContext = activeApprovalContext(context.journal);
  if (current && 'kind' in current.record && current.record.kind === 'management_no_managed_residue' &&
    current.phase !== 'prepared') {
    proofContext = approvalContextForAttempt(context.journal, current.record.result.attemptId);
  }
  const result = await context.input.provider.verifyNoManagedResidue(
    proofContext,
    deletionEvidence,
    lifecycle,
    context.call,
  );
  const record = Object.freeze({ schemaVersion: 1, kind: name, result });
  if (!current) {
    await prepareAction(context, name, record);
    current = requireAction(context.journal, name);
  } else if (current.phase === 'prepared' && !exact(current.record, {
    ...record,
    preparedByAttemptId: context.input.attemptId,
    armedByAttemptId: null,
    submittedByAttemptId: null,
    verifiedByAttemptId: null,
  })) {
    await replacePreparedAction(context, name, record);
    current = requireAction(context.journal, name);
  }
  if (!('kind' in current.record) || current.record.kind !== 'management_no_managed_residue' ||
    !exact(current.record.result, result)) fail('journal_recovery_mismatch');
  if (current.phase === 'prepared') {
    await armAction(context, name);
    current = requireAction(context.journal, name);
  }
  if (current.phase === 'send_armed') {
    await submittedAction(context, name, result);
    current = requireAction(context.journal, name);
  }
  if (current.phase === 'submitted') {
    await verifiedAction(context, name, result);
    current = requireAction(context.journal, name);
  }
  if (current.phase !== 'verified' || !current.locator || !('status' in current.locator) ||
    current.locator.status !== 'no_ankka_managed_residue') fail('journal_recovery_mismatch');
  return current.locator;
}

async function convergeFinalAction(
  context: ExecutionContext,
): Promise<ReviewedUninstallFinalProjection['locator']> {
  const name = 'uninstall_final_convergence' as const;
  const prepared = await context.dependencies.prepareUninstallFinalConvergenceRecordAndLocator(
    context.journal,
  );
  let current = action(context.journal, name);
  if (!current) {
    await prepareAction(context, name, prepared.record);
    current = requireAction(context.journal, name);
  }
  if (!exact(current.record, prepared.record)) fail('journal_recovery_mismatch');
  if (current.phase === 'prepared') {
    await armAction(context, name);
    current = requireAction(context.journal, name);
  }
  if (current.phase === 'send_armed') {
    await submittedAction(context, name, prepared.locator);
    current = requireAction(context.journal, name);
  }
  if (current.phase === 'submitted') {
    await verifiedAction(context, name, prepared.locator);
    current = requireAction(context.journal, name);
  }
  if (current.phase !== 'verified' || !current.locator || !('status' in current.locator) ||
    current.locator.status !== 'removed' || !('convergenceHash' in current.locator)) {
    fail('journal_recovery_mismatch');
  }
  return current.locator;
}

function validateExecutionInput(input: ReviewedUninstallExecutionInput): void {
  if (!ATTEMPT_ID.test(input.attemptId) || !ACCESS_TOKEN.test(input.accessToken) ||
    !BASE64_KEY.test(input.uninstallNonceDerivationKey) ||
    !UNINSTALL_CYCLE_ID.test(input.uninstallCycleId) ||
    !Number.isSafeInteger(input.approvedAt) || input.approvedAt < 0 ||
    !Number.isSafeInteger(input.recoverUntil) || input.recoverUntil <= 0 ||
    !v.safeParse(executionCapabilitiesSchema, input).success) fail('reviewed_adapter_invalid');
}

async function initializeOrRecoverContext(
  input: ReviewedUninstallExecutionInput,
  dependencies: ReviewedUninstallExecutionDependencies,
): Promise<ExecutionContext> {
  validateExecutionInput(input);
  const plan = await dependencies.parseStaticUninstallPlan(input.uninstallPlan);
  const installJournal = input.installJournal;
  if (!dependencies.isCompleteInstallJournal(installJournal)) fail('journal_recovery_mismatch');
  const rebuiltInstall = await dependencies.prepareFinalConvergenceRecordAndLocator(installJournal);
  const finalInstall = finalInstallLocator(installJournal);
  if (!exact(rebuiltInstall.locator, finalInstall) ||
    !exact(installJournal.target, input.target) ||
    plan.installationId !== installJournal.installationId ||
    plan.release.id !== installJournal.releasePin.release ||
    plan.release.aggregateSha256 !== installJournal.releasePin.artifactSha256 ||
    input.recoverUntil !== installJournal.recoverUntil) fail('journal_recovery_mismatch');
  const releaseSet = await dependencies.adaptVerifiedReleaseBundleForGatewayDeployments(
    input.releaseBundle,
  );
  // The root installation receipt remains pinned to the originally installed
  // release. Cleanup and retirement code may come from a newer, independently
  // verified release after normal runtime updates; their plain-text ownership
  // bindings below deliberately continue to carry the root receipt release.
  const callBase: ReviewedUninstallProviderCall = {
    accessToken: input.accessToken,
    transport: input.transport,
  };
  const call = input.timeoutMs === undefined
    ? Object.freeze(callBase)
    : Object.freeze({ ...callBase, timeoutMs: input.timeoutMs });
  const workerName = plan.gateway.workerName;
  const base = {
    input,
    dependencies,
    installJournal,
    plan,
    releaseSet,
    finalInstall,
    call,
    workerName,
    workerId: finalInstall.workerId,
    namespaceId: finalInstall.adminStateNamespaceId,
  };
  let journal = await readJournalOrNull(input.journal);
  const wallNow = input.now ? input.now() : Date.now();
  if (!Number.isSafeInteger(wallNow) || wallNow < 0 || wallNow >= plan.expiresAt ||
    wallNow >= input.recoverUntil || input.approvedAt > wallNow || input.approvedAt < plan.createdAt) {
    fail('reviewed_adapter_invalid');
  }
  if (!journal) {
    const approval = Object.freeze({
      attemptId: input.attemptId,
      uninstallPlan: plan,
      authorizedTarget: input.target,
    });
    const managementContext: HostedUninstallManagementContext = Object.freeze({
      schemaVersion: 1,
      installJournal,
      approvalHistory: Object.freeze([approval]),
      activeAttemptId: input.attemptId,
    });
    const freshPreflight = await input.provider.preflightManagement(managementContext, call, wallNow);
    const bindingHash = await dependencies.computeUninstallJournalBindingHash({
      installJournal,
      uninstallPlan: plan,
      uninstallCycleId: input.uninstallCycleId,
    });
    journal = await input.journal.initialize({
      initialization: {
        schemaVersion: 1,
        now: wallNow,
        recoverUntil: input.recoverUntil,
        installJournal,
        uninstallPlan: plan,
        uninstallCycleId: input.uninstallCycleId,
        bindingHash,
        freshPreflight,
      },
      approval: {
        attemptId: input.attemptId,
        approvedAt: input.approvedAt,
        authorizedTarget: input.target,
      },
    });
  } else {
    if (!exact(journal.installJournal, installJournal) ||
      !await dependencies.isRecoveryEquivalentUninstallPlan(journal.uninstallPlan, plan) ||
      journal.uninstallCycleId !== input.uninstallCycleId ||
      journal.recoverUntil !== input.recoverUntil) fail('journal_recovery_mismatch');
    const approval = journal.approvalHistory.find((entry) => entry.attemptId === input.attemptId);
    if (!approval) {
      journal = await input.journal.appendApproval({
        expectedRevision: journal.revision,
        attemptId: input.attemptId,
        now: Math.max(wallNow, journal.updatedAt),
        approvedAt: input.approvedAt,
        authorizedTarget: input.target,
        candidatePlan: plan,
      });
    } else if (!exact(approval.plan, plan) || !exact(approval.authorizedTarget, input.target) ||
      approval.approvedAt !== input.approvedAt) {
      fail('journal_recovery_mismatch');
    }
  }
  const activePlan = activeUninstallJournalPlan(journal);
  if (!exact(activePlan, plan)) fail('journal_recovery_mismatch');
  const context: ExecutionContext = { ...base, plan: activePlan, journal };
  const now = executionNow(context);
  const leaseExpiresAt = Math.min(
    now + MAX_UNINSTALL_LEASE_MS,
    activePlan.expiresAt,
    journal.recoverUntil,
  );
  if (leaseExpiresAt <= now) fail('journal_recovery_mismatch');
  context.journal = await input.journal.acquireLease({
    expectedRevision: context.journal.revision,
    attemptId: input.attemptId,
    now,
    leaseExpiresAt,
  });

  const preflightAction = context.journal.actions[0];
  if (context.journal.actions.length === 1 && preflightAction &&
    !('kind' in preflightAction.record) &&
    ('attemptId' in preflightAction.record) &&
    (preflightAction.record.attemptId !== input.attemptId ||
      executionNow(context) >= preflightAction.record.expiresAt)) {
    const refreshed = await input.provider.preflightManagement(
      activeApprovalContext(context.journal),
      call,
      executionNow(context),
    );
    context.journal = await input.journal.refreshPreflight({
      expectedRevision: context.journal.revision,
      attemptId: input.attemptId,
      now: executionNow(context),
      preflight: refreshed,
    });
  }
  return context;
}

/**
 * Execute the canary-only reviewed uninstall. This module is not a default
 * runtime dependency: callers must inject the adapter, transport, same-DO
 * journal port, fresh OAuth grant, and namespace-bound nonce derivation key.
 */
async function executeReviewedUninstallWithDependencies(
  input: ReviewedUninstallExecutionInput,
  dependencies: ReviewedUninstallExecutionDependencies,
): Promise<UninstallExecutionResult> {
  const context = await initializeOrRecoverContext(input, dependencies);
  try {
  const workersSubdomain = await input.provider.getAccountWorkersSubdomain({
    ...context.call,
    accountId: context.installJournal.target.account.id,
  });
  const namespace = exactNamespace(
    namespaceInspectionInput(context),
    await input.provider.inspectAdminStateNamespace(namespaceInspectionInput(context), context.call),
  );
  const uninstallNonce = await dependencies.deriveCustomerUninstallNonce(
    input.uninstallNonceDerivationKey,
    context.installJournal,
  );

  const namespacePresence = await input.provider.proveNamespacePresent({
    namespace,
    workerId: context.workerId,
    uninstallCycleId: context.journal.uninstallCycleId,
  }, context.call);
  const cleanupVersion = await convergeWorkerVersion(
    context,
    'cleanup',
    namespace,
    namespacePresence,
    uninstallNonce,
  );
  await convergeWorkerDeployment(context, 'cleanup', cleanupVersion.versionId);
  await convergeCustomerGatewayRemoval(context, workersSubdomain, uninstallNonce);
  await convergeWorkerDeployment(context, 'restore_clean', context.finalInstall.cleanVersionId);

  const customDomain = await convergeManagementDelete(context, 'management_custom_domain_delete');
  const adminPolicy = await convergeManagementDelete(context, 'management_admin_policy_delete');
  const accessApplication = await convergeManagementDelete(
    context,
    'management_access_application_delete',
  );

  const retirementVersion = await convergeWorkerVersion(
    context,
    'retirement',
    namespace,
    null,
    uninstallNonce,
  );
  const retirementDeployment = await convergeWorkerDeployment(
    context,
    'retirement',
    retirementVersion.versionId,
  );
  const retirementAction = requireAction(context.journal, 'retirement_worker_version_create');
  if (!('kind' in retirementAction.record) ||
    retirementAction.record.kind !== 'uninstall_worker_version_create' ||
    retirementAction.record.recovery?.stage !== 'retirement') fail('journal_recovery_mismatch');
  const deploymentAction = requireAction(context.journal, 'retirement_worker_deployment_create');
  if (!('kind' in deploymentAction.record) ||
    deploymentAction.record.kind !== 'uninstall_worker_deployment_create' ||
    deploymentAction.record.intent.stage !== 'retirement') fail('journal_recovery_mismatch');
  const proofInput = retirementProofInput(
    context,
    namespace,
    retirementAction.record.recovery,
    retirementVersion,
    deploymentAction.record.intent,
    retirementDeployment,
  );
  const namespaceRetirement = await convergeNamespaceRetirement(context, proofInput);
  const workerDeletion = await convergeWorkerDelete(context, proofInput);
  await convergeNoManagedResidue(
    context,
    Object.freeze([customDomain, adminPolicy, accessApplication]),
    Object.freeze({
      workerDeleteIntent: workerDeletion.intent,
      namespaceRetirement,
    }),
  );
  const tombstone = await convergeFinalAction(context);
  context.journal = await input.journal.releaseLease({
    expectedRevision: context.journal.revision,
    attemptId: input.attemptId,
    now: executionNow(context),
  });
  return Object.freeze({
    status: 'removed',
    installationId: tombstone.installationId,
    convergenceHash: tombstone.convergenceHash,
  });
  } catch (error) {
    if (error instanceof ReviewedUninstallExecutionError &&
      (error.code === 'fresh_grant_required' || error.code === 'customer_recovery_unavailable') &&
      context.journal.lease?.attemptId === input.attemptId) {
      context.journal = await input.journal.releaseLease({
        expectedRevision: context.journal.revision,
        attemptId: input.attemptId,
        now: executionNow(context),
      });
    }
    throw error;
  }
}

export function createReviewedUninstallExecutor(
  dependencies: ReviewedUninstallExecutionDependencies,
): (input: ReviewedUninstallExecutionInput) => Promise<UninstallExecutionResult> {
  return (input) => executeReviewedUninstallWithDependencies(input, dependencies);
}

export async function executeReviewedUninstall(
  input: ReviewedUninstallExecutionInput,
): Promise<UninstallExecutionResult> {
  return executeReviewedUninstallWithDependencies(input, defaultExecutionDependencies);
}
import * as v from 'valibot';
