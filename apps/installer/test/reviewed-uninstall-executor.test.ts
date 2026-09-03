import { describe, expect, it } from 'vitest';
import * as v from 'valibot';

import type {
  HostedUninstallManagementAbsenceEvidence,
  HostedUninstallManagementDeleteArm,
  HostedUninstallManagementDeleteAction,
  HostedUninstallManagementDeleteIntent,
  HostedUninstallManagementDeleteSubmission,
  HostedUninstallManagementNoManagedResidueResult,
  HostedUninstallManagementPreflightResult,
} from '../src/cloudflare-uninstall-management';
import type { AuthorizedTarget } from '../src/cloudflare-target';
import type {
  AdminStateNamespacePresenceProof,
  AdminStateNamespaceRetirementProof,
  UninstallWorkerDeploymentMutationIntent,
  UninstallWorkerDeploymentSubmission,
  UninstallWorkerVersionMutationPlan,
  UninstallWorkerVersionSubmission,
  WorkerDeleteMutationIntent,
  WorkerDeletionRecoveryProof,
} from '../src/cloudflare-uninstall-worker-lifecycle';
import type {
  CustomerUninstallMutationPlan,
  CustomerUninstallRemovedLocator,
} from '../src/customer-uninstall-request';
import { DeployError } from '../src/errors';
import type { FinalConvergenceLocator, InstallJournal } from '../src/install-journal';
import type { ReadyInstallationReceipt } from '../src/provider-neutral-installation-receipt';
import {
  createReviewedUninstallExecutor,
  type ReviewedUninstallExecutionDependencies,
  type ReviewedUninstallExecutionInput,
  type ReviewedUninstallJournalPort,
  type ReviewedPreparedActionRecords,
  type ReviewedSubmittedActionValues,
  type ReviewedVerifiedActionValues,
  type ReviewedUninstallProviderAdapter,
} from '../src/reviewed-uninstall-executor';
import { APPROVED_CLOUDFLARE_RELEASE_CONTRACT } from '../src/release-manifest';
import type { VerifiedGatewayWorkerReleaseSet } from '../src/release-direct-upload-adapter';
import type { DeploySelection, StaticDeployPlan } from '../src/schema';
import { DisabledUninstallExecutor } from '../src/uninstall-executor';
import type {
  CustomerGatewayRemoveActionRecord,
  CustomerGatewayRemoveRequestAttempt,
  ManagementDeleteActionRecord,
  ManagementDeleteActionDraft,
  ManagementDeleteAttempt,
  UninstallActionName,
  UninstallJournal,
  UninstallJournalAction,
  UninstallJournalCasInput,
  UninstallRemovedTombstone,
  UninstallWorkersDevMutation,
} from '../src/uninstall-journal';
import { STATIC_UNINSTALL_PROVIDER_NOTICE, type StaticUninstallPlan } from '../src/uninstall-plan';
import { verifiedReleaseBundle } from './fixtures';

const fixture = Object.freeze({
  now: 1_787_444_500_000,
  finalInstall: Object.freeze({
    schemaVersion: 1,
    status: 'converged',
    convergenceHash: `sha256:${'1'.repeat(64)}`,
    installationId: `acg-${'2'.repeat(24)}`,
    bindingHash: `sha256:${'3'.repeat(64)}`,
    workerId: '4'.repeat(32),
    managementApplicationId: '5'.repeat(32),
    managementAccessAud: 'audience-abcdefghijklmnop',
    managementPolicyId: '6'.repeat(32),
    bootstrapVersionId: '11111111-1111-4111-8111-111111111111',
    bootstrapDeploymentId: '22222222-2222-4222-8222-222222222222',
    cleanVersionId: '33333333-3333-4333-8333-333333333333',
    cleanDeploymentId: '44444444-4444-4444-8444-444444444444',
    managementDomainId: '7'.repeat(32),
    customerApprovedPlanId: `plan-${'8'.repeat(24)}`,
    customerReceiptRevision: 9,
    customerReceiptEvidence: Object.freeze({
      schemaVersion: 1,
      manager: 'ankka-mcp-gateway',
      installationId: `acg-${'2'.repeat(24)}`,
      state: 'ready',
      revision: 9,
      release: 'gateway-v1.2.3',
      target: Object.freeze({
        accountId: '1'.repeat(32),
        zoneId: '2'.repeat(32),
        zoneName: 'example.com',
        hostname: 'mcp.example.com',
      }),
      accessPolicy: Object.freeze({
        identityType: 'email',
        identityCount: 1,
        identitiesHash: `sha256:${'8'.repeat(64)}`,
      }),
      desiredHash: `sha256:${'7'.repeat(64)}`,
      resources: Object.freeze([]),
      pending: null,
      checksum: `sha256:${'9'.repeat(64)}`,
    } satisfies ReadyInstallationReceipt),
    adminStateNamespaceId: 'a'.repeat(32),
    workersDevEnabled: false,
  } satisfies FinalConvergenceLocator),
  releaseSet: Object.freeze({
    bootstrap: Object.freeze({
      verification: 'ed25519',
      release: 'gateway-v1.2.3',
      artifactSha256: 'b'.repeat(64),
      componentSha256: 'f'.repeat(64),
      worker: Object.freeze({
        mainModule: 'index.js',
        compatibilityDate: '2026-08-08',
        compatibilityFlags: Object.freeze([] as const),
        modules: Object.freeze([]),
        assets: Object.freeze({
          binding: 'ASSETS',
          notFoundHandling: 'single-page-application',
          runWorkerFirst: Object.freeze(['/__ankka/*', '/api/*'] as const),
          files: Object.freeze([]),
        }),
        durableObject: Object.freeze({
          binding: 'ADMIN_STATE',
          className: 'AdminState',
          storage: 'sqlite',
        }),
      }),
    }),
    primary: Object.freeze({
      verification: 'ed25519',
      release: 'gateway-v1.2.3',
      artifactSha256: 'b'.repeat(64),
      worker: Object.freeze({
        mainModule: 'index.js',
        compatibilityDate: '2026-08-08',
        compatibilityFlags: Object.freeze([] as const),
        modules: Object.freeze([]),
        assets: Object.freeze({
          binding: 'ASSETS',
          notFoundHandling: 'single-page-application',
          runWorkerFirst: Object.freeze(['/__ankka/*', '/api/*'] as const),
          files: Object.freeze([]),
        }),
        durableObject: Object.freeze({
          binding: 'ADMIN_STATE',
          className: 'AdminState',
          storage: 'sqlite',
        }),
      }),
    }),
    cleanup: Object.freeze({
      verification: 'ed25519', release: 'gateway-v1.2.3', artifactSha256: 'b'.repeat(64),
      componentSha256: 'c'.repeat(64), variant: 'cleanup',
      worker: Object.freeze({
        contract: APPROVED_CLOUDFLARE_RELEASE_CONTRACT.workerVariants.cleanup,
        modules: Object.freeze([]),
      }),
    }),
    retirement: Object.freeze({
      verification: 'ed25519', release: 'gateway-v1.2.3', artifactSha256: 'b'.repeat(64),
      componentSha256: 'd'.repeat(64), variant: 'retirement',
      worker: Object.freeze({
        contract: APPROVED_CLOUDFLARE_RELEASE_CONTRACT.workerVariants.retirement,
        modules: Object.freeze([]),
      }),
    }),
  } satisfies VerifiedGatewayWorkerReleaseSet),
  tombstone: Object.freeze({
    schemaVersion: 1,
    status: 'removed',
    convergenceHash: `sha256:${'e'.repeat(64)}`,
    installationId: `acg-${'2'.repeat(24)}`,
  }),
});

const ATTEMPT_ONE = `att_${'a'.repeat(32)}`;
const ATTEMPT_TWO = `att_${'b'.repeat(32)}`;
const ACCESS_TOKEN = `grant-${'a'.repeat(32)}`;
const NONCE_KEY = 'CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg';
const ACCOUNT_ID = '1'.repeat(32);
const ZONE_ID = '2'.repeat(32);
const WORKER_NAME = 'ankka-example-gateway';
const UNINSTALL_CYCLE_ID = `uninstall-${'1'.repeat(24)}`;

const target = Object.freeze({
  actor: Object.freeze({ id: 'actor-test', email: 'owner@example.com' }),
  account: Object.freeze({ id: ACCOUNT_ID, name: 'Example account' }),
  zone: Object.freeze({ id: ZONE_ID, name: 'example.com', status: 'active' as const }),
} satisfies AuthorizedTarget);

const plan = Object.freeze({
  schemaVersion: 1,
  planId: `uninstall-plan-${'1'.repeat(24)}`,
  planHash: `sha256:${'2'.repeat(64)}`,
  createdAt: fixture.now,
  expiresAt: fixture.now + 10 * 60_000,
  writesPerformed: false,
  installationId: fixture.finalInstall.installationId,
  authorityHash: `sha256:${'3'.repeat(64)}`,
  requiredScopes: [],
  gateway: {
    name: 'Example Gateway', zoneName: 'example.com', managementHostname: 'manage.example.com',
    portalHostname: 'mcp.example.com', workerName: WORKER_NAME,
  },
  source: { name: 'Company context', hostname: 'source.example.com', enabledTools: ['search'] },
  release: { id: 'gateway-v1.2.3', aggregateSha256: 'b'.repeat(64) },
  steps: [],
  providerNotice: STATIC_UNINSTALL_PROVIDER_NOTICE,
} satisfies StaticUninstallPlan);

const installSelection = Object.freeze({
  schemaVersion: 1,
  basics: Object.freeze({
    gatewayName: 'Example Gateway',
    zoneName: 'example.com',
    adminEmail: 'owner@example.com',
    additionalAdminEmails: Object.freeze([]),
    managementHostname: 'manage.example.com',
    portalHostname: 'mcp.example.com',
  }),
  firstSource: Object.freeze({
    name: 'Company context',
    url: 'https://source.example.com/mcp',
    enabledTools: Object.freeze(['search']),
    portalUserEmails: Object.freeze(['owner@example.com']),
  }),
} satisfies DeploySelection);

const installDeployPlan = Object.freeze({
  schemaVersion: 1,
  planId: `plan-${'1'.repeat(24)}`,
  planHash: `sha256:${'2'.repeat(64)}`,
  expiresAt: fixture.now + 600_000,
  releaseId: 'gateway-v1.2.3',
  releaseArtifactSha256: 'b'.repeat(64),
  sourceCommit: 'c'.repeat(40),
  bootstrapWorkerSourceSha256: 'f'.repeat(64),
  workerBundleSha256: 'd'.repeat(64),
  dashboardAssetsSha256: 'e'.repeat(64),
  managementOwnershipMarker: 'ankka:management:test',
  actorRole: 'deployment_authorizer',
  primaryAdminEmail: 'owner@example.com',
  managementAdminEmails: Object.freeze(['owner@example.com']),
  portalAudienceEmails: Object.freeze(['owner@example.com']),
  gatewayConfiguration: Object.freeze({
    gatewayName: 'Example Gateway',
    zoneName: 'example.com',
    managementHostname: 'manage.example.com',
    portalHostname: 'mcp.example.com',
    capabilityMode: 'read_only',
    codeMode: 'default_on',
    firstSource: Object.freeze({
      name: 'Company context',
      url: 'https://source.example.com/mcp',
      enabledTools: Object.freeze(['search']),
    }),
  }),
  managementResources: Object.freeze([]),
  gatewayResources: Object.freeze([]),
  requiredScopes: Object.freeze([]),
} satisfies StaticDeployPlan);

const installJournal = Object.freeze({
  schemaVersion: 1,
  revision: 40,
  createdAt: fixture.now - 1_000,
  updatedAt: fixture.now,
  sessionExpiresAt: fixture.now + 60_000,
  recoverUntil: fixture.now + 24 * 60 * 60_000,
  selection: installSelection,
  plan: installDeployPlan,
  releasePin: {
    verification: 'ed25519', keyId: 'key-1', release: 'gateway-v1.2.3', artifactSha256: 'b'.repeat(64),
  },
  target,
  installationId: fixture.finalInstall.installationId,
  bindingHash: fixture.finalInstall.bindingHash,
  approvalHistory: [],
  lease: null,
  leaseAttemptIds: [],
  actions: Object.freeze([Object.freeze({
    name: 'final_convergence',
    phase: 'verified',
    record: Object.freeze({
      schemaVersion: 1,
      kind: 'final_convergence',
      convergenceHash: fixture.finalInstall.convergenceHash,
    }),
    locator: fixture.finalInstall,
    preparedAt: fixture.now,
    sendArmedAt: fixture.now,
    submittedAt: fixture.now,
    verifiedAt: fixture.now,
  })]),
} satisfies InstallJournal);

function versionSubmission(stage: 'cleanup' | 'retirement'): UninstallWorkerVersionSubmission {
  return {
    kind: 'uninstall_worker_version',
    stage,
    accountId: ACCOUNT_ID,
    workerName: WORKER_NAME,
    workerId: fixture.finalInstall.workerId,
    uninstallCycleId: UNINSTALL_CYCLE_ID,
    versionId: stage === 'cleanup'
      ? '55555555-5555-4555-8555-555555555555'
      : '66666666-6666-4666-8666-666666666666',
    requestHash: stage === 'cleanup' ? '1'.repeat(64) : '2'.repeat(64),
    correlationTag: `version-${stage}`,
  };
}

function versionMutationPlan(stage: 'cleanup' | 'retirement'): UninstallWorkerVersionMutationPlan {
  const requestHash = stage === 'cleanup' ? '1'.repeat(64) : '2'.repeat(64);
  const ephemeral = {
    kind: 'uninstall_version_submit' as const,
    stage,
    accountId: ACCOUNT_ID,
    workerName: WORKER_NAME,
    workerId: fixture.finalInstall.workerId,
    uninstallCycleId: UNINSTALL_CYCLE_ID,
    requestHash,
    correlationTag: `version-${stage}`,
    semanticCommitment: { stage },
    body: { modules: [] },
  };
  if (stage === 'cleanup') {
    return {
      ephemeral,
      recovery: {
        kind: 'uninstall_version_recovery',
        stage,
        accountId: ACCOUNT_ID,
        workerName: WORKER_NAME,
        workerId: fixture.finalInstall.workerId,
        namespaceId: fixture.finalInstall.adminStateNamespaceId,
        uninstallCycleId: UNINSTALL_CYCLE_ID,
        release: fixture.releaseSet.cleanup.release,
        artifactSha256: fixture.releaseSet.cleanup.artifactSha256,
        componentSha256: fixture.releaseSet.cleanup.componentSha256,
        requestHash,
        correlationTag: `version-${stage}`,
        compatibilityDate: '2026-08-08',
        compatibilityFlags: [],
        mainModule: 'index.js',
        contract: {
          assets: 'absent',
          defaultApplication: 'absent',
          durableObject: {
            binding: 'ADMIN_STATE',
            className: 'AdminState',
            namespaceId: fixture.finalInstall.adminStateNamespaceId,
            storage: 'sqlite',
          },
          exports: { AdminState: { type: 'durable-object', storage: 'sqlite' } },
          uninstallNonceBinding: 'present',
          variableValueHashes: [],
        },
        modules: [],
      },
    };
  }
  return {
    ephemeral,
    recovery: {
      kind: 'uninstall_version_recovery',
      stage,
      accountId: ACCOUNT_ID,
      workerName: WORKER_NAME,
      workerId: fixture.finalInstall.workerId,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      release: fixture.releaseSet.retirement.release,
      artifactSha256: fixture.releaseSet.retirement.artifactSha256,
      componentSha256: fixture.releaseSet.retirement.componentSha256,
      requestHash,
      correlationTag: `version-${stage}`,
      compatibilityDate: '2026-08-08',
      compatibilityFlags: [],
      mainModule: 'index.js',
      contract: {
        assets: 'absent',
        bindings: [],
        defaultApplication: 'absent',
        exports: { AdminState: { type: 'durable-object', state: 'deleted' } },
      },
      modules: [],
    },
  };
}

function deploymentIntent(
  stage: UninstallWorkerDeploymentMutationIntent['stage'],
  versionId: string,
): UninstallWorkerDeploymentMutationIntent {
  return {
    kind: 'uninstall_deployment',
    stage,
    accountId: ACCOUNT_ID,
    workerName: WORKER_NAME,
    workerId: fixture.finalInstall.workerId,
    uninstallCycleId: UNINSTALL_CYCLE_ID,
    versionId,
    requestHash: stage === 'cleanup' ? '5'.repeat(64)
      : stage === 'restore_clean' ? '6'.repeat(64) : '7'.repeat(64),
    correlationTag: `deployment-${stage}`,
    body: {
      annotations: { 'workers/message': `Ankka reviewed uninstall ${stage}` },
      strategy: 'percentage',
      versions: [{ percentage: 100, version_id: versionId }],
    },
  };
}

function deploymentSubmission(
  intent: UninstallWorkerDeploymentMutationIntent,
): UninstallWorkerDeploymentSubmission {
  return {
    kind: 'uninstall_worker_deployment',
    stage: intent.stage,
    accountId: intent.accountId,
    workerName: intent.workerName,
    workerId: intent.workerId,
    uninstallCycleId: intent.uninstallCycleId,
    versionId: intent.versionId,
    deploymentId: intent.stage === 'cleanup' ? '77777777-7777-4777-8777-777777777777'
      : intent.stage === 'restore_clean' ? '88888888-8888-4888-8888-888888888888'
        : '99999999-9999-4999-8999-999999999999',
    requestHash: intent.requestHash,
    correlationTag: intent.correlationTag,
  };
}

function namespacePresence(): AdminStateNamespacePresenceProof {
  return {
    kind: 'admin_state_namespace_presence',
    accountId: ACCOUNT_ID,
    workerName: WORKER_NAME,
    workerId: fixture.finalInstall.workerId,
    uninstallCycleId: UNINSTALL_CYCLE_ID,
    namespaceId: fixture.finalInstall.adminStateNamespaceId,
    namespaceName: 'ankka-admin-state',
    className: 'AdminState',
    storage: 'sqlite',
    accountNamespaceCount: 1,
    snapshotSha256: 'a'.repeat(64),
  };
}

function namespaceRetirement(): AdminStateNamespaceRetirementProof {
  return {
    kind: 'admin_state_namespace_retirement',
    accountId: ACCOUNT_ID,
    workerName: WORKER_NAME,
    workerId: fixture.finalInstall.workerId,
    uninstallCycleId: UNINSTALL_CYCLE_ID,
    namespaceId: fixture.finalInstall.adminStateNamespaceId,
    retirementVersionId: versionSubmission('retirement').versionId,
    accountNamespaceCount: 0,
    firstSnapshotSha256: 'b'.repeat(64),
    secondSnapshotSha256: 'b'.repeat(64),
  };
}

function workerDeleteIntent(): WorkerDeleteMutationIntent {
  return {
    kind: 'uninstall_worker_delete_intent',
    accountId: ACCOUNT_ID,
    workerName: WORKER_NAME,
    workerId: fixture.finalInstall.workerId,
    uninstallCycleId: UNINSTALL_CYCLE_ID,
    namespaceId: fixture.finalInstall.adminStateNamespaceId,
    retirementVersionId: versionSubmission('retirement').versionId,
    retirementProofCommitment: '9'.repeat(64),
    retirementProof: namespaceRetirement(),
    requestHash: 'a'.repeat(64),
    correlationTag: 'worker-delete',
    method: 'DELETE',
    force: 'omitted',
  };
}

function workerDeletionProof(): WorkerDeletionRecoveryProof {
  const intent = workerDeleteIntent();
  return {
    kind: 'uninstall_worker_deletion_proof',
    accountId: intent.accountId,
    workerName: intent.workerName,
    workerId: intent.workerId,
    uninstallCycleId: intent.uninstallCycleId,
    namespaceId: intent.namespaceId,
    retirementVersionId: intent.retirementVersionId,
    retirementProofCommitment: intent.retirementProofCommitment,
    requestHash: intent.requestHash,
    firstScriptListSha256: 'c'.repeat(64),
    secondScriptListSha256: 'c'.repeat(64),
    scriptCount: 0,
  };
}

function managementPreflight(attemptId: string, now: number): HostedUninstallManagementPreflightResult {
  return {
    schemaVersion: 1,
    status: 'ready',
    uninstallPlanId: plan.planId,
    uninstallPlanHash: plan.planHash,
    uninstallAuthorityHash: plan.authorityHash,
    installBindingHash: fixture.finalInstall.bindingHash,
    installConvergenceHash: fixture.finalInstall.convergenceHash,
    attemptId,
    ownershipMarker: installDeployPlan.managementOwnershipMarker,
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
    workerId: fixture.finalInstall.workerId,
    namespaceId: fixture.finalInstall.adminStateNamespaceId,
    domainId: fixture.finalInstall.managementDomainId,
    domainCertificateId: 'd'.repeat(32),
    applicationId: fixture.finalInstall.managementApplicationId,
    policyId: fixture.finalInstall.managementPolicyId,
    checkedAt: now,
    expiresAt: now + 60_000,
    attestationSha256: '4'.repeat(64),
  };
}

function managementDeleteIntent(
  action: HostedUninstallManagementDeleteAction,
  attemptId: string,
): HostedUninstallManagementDeleteIntent {
  const common = {
    schemaVersion: 1 as const,
    uninstallPlanId: plan.planId,
    uninstallPlanHash: plan.planHash,
    uninstallAuthorityHash: plan.authorityHash,
    installBindingHash: fixture.finalInstall.bindingHash,
    installConvergenceHash: fixture.finalInstall.convergenceHash,
    attemptId,
    ownershipMarker: installDeployPlan.managementOwnershipMarker,
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
    managementHostname: plan.gateway.managementHostname,
    workerName: WORKER_NAME,
    prerequisiteCommitments: [],
  };
  if (action === 'management_custom_domain_delete') {
    return { ...common, kind: action, ordinal: 0, locator: { domainId: fixture.finalInstall.managementDomainId } };
  }
  if (action === 'management_admin_policy_delete') {
    return {
      ...common,
      kind: action,
      ordinal: 1,
      locator: {
        applicationId: fixture.finalInstall.managementApplicationId,
        policyId: fixture.finalInstall.managementPolicyId,
      },
    };
  }
  return {
    ...common,
    kind: action,
    ordinal: 2,
    locator: {
      applicationId: fixture.finalInstall.managementApplicationId,
      aud: fixture.finalInstall.managementAccessAud,
    },
  };
}

function managementSubmission(
  intent: HostedUninstallManagementDeleteIntent,
): HostedUninstallManagementDeleteSubmission {
  return {
    schemaVersion: 1,
    status: 'submitted',
    action: intent.kind,
    attemptId: intent.attemptId,
    intentSha256: '8'.repeat(64),
    locator: intent.locator,
  };
}

function managementAbsence(
  intent: HostedUninstallManagementDeleteIntent,
): HostedUninstallManagementAbsenceEvidence {
  return {
    schemaVersion: 1,
    status: 'absent',
    action: intent.kind,
    uninstallPlanId: intent.uninstallPlanId,
    uninstallPlanHash: intent.uninstallPlanHash,
    uninstallAuthorityHash: intent.uninstallAuthorityHash,
    installBindingHash: intent.installBindingHash,
    installConvergenceHash: intent.installConvergenceHash,
    attemptId: intent.attemptId,
    ownershipMarker: intent.ownershipMarker,
    accountId: intent.accountId,
    locator: intent.locator,
    proof: 'id_get_404_and_complete_list_absence',
    evidenceSha256: '3'.repeat(64),
  };
}

function customerMutationPlan(attemptId: string): CustomerUninstallMutationPlan {
  const requestId = `request-${'1'.repeat(24)}`;
  const issuedAt = Math.floor(fixture.now / 1_000);
  const expiresAt = Math.floor((fixture.now + 60_000) / 1_000);
  const targetEvidence = { accountId: ACCOUNT_ID, zoneId: ZONE_ID, zoneName: 'example.com' };
  const release = { id: 'gateway-v1.2.3', artifactSha256: `sha256:${'b'.repeat(64)}` };
  const configurationHash = `sha256:${'5'.repeat(64)}`;
  const desiredHash = fixture.finalInstall.customerReceiptEvidence.desiredHash;
  return {
    ephemeral: {
      claim: {
        schemaVersion: 1,
        requestId,
        issuedAt,
        expiresAt,
        target: targetEvidence,
        release,
        expected: {
          configurationHash,
          installationId: fixture.finalInstall.installationId,
          desiredHash,
          readyReceipt: fixture.finalInstall.customerReceiptEvidence,
        },
      },
    },
    semantic: {
      schemaVersion: 1,
      kind: 'customer_uninstall_submit',
      accountId: ACCOUNT_ID,
      zoneId: ZONE_ID,
      zoneName: 'example.com',
      accountWorkersSubdomain: 'example-account',
      workerName: WORKER_NAME,
      requestId,
      issuedAt,
      expiresAt,
      installationId: fixture.finalInstall.installationId,
      configurationHash,
      desiredHash,
      release,
      rootReceiptRevision: fixture.finalInstall.customerReceiptRevision,
      rootReceiptChecksum: fixture.finalInstall.customerReceiptEvidence.checksum,
      installBindingHash: fixture.finalInstall.bindingHash,
      installConvergenceHash: fixture.finalInstall.convergenceHash,
      adminStateNamespaceId: fixture.finalInstall.adminStateNamespaceId,
      uninstallPlanId: plan.planId,
      uninstallPlanHash: plan.planHash,
      authorityHash: plan.authorityHash,
      approvalAttemptId: attemptId,
      claimHash: `sha256:${'6'.repeat(64)}`,
    },
  };
}

function customerRemovedLocator(attemptId: string): CustomerUninstallRemovedLocator {
  const semantic = customerMutationPlan(attemptId).semantic;
  return {
    schemaVersion: 1,
    status: 'removed',
    requestId: semantic.requestId,
    uninstallId: `uninstall-${'2'.repeat(24)}`,
    uninstallInvoked: true,
    resumed: false,
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
    receipt: {
      revision: fixture.finalInstall.customerReceiptRevision + 1,
      resourceCount: 0,
      evidence: {
        schemaVersion: 1,
        manager: 'ankka-mcp-gateway',
        installationId: fixture.finalInstall.installationId,
        state: 'removed',
        revision: fixture.finalInstall.customerReceiptRevision + 1,
        release: fixture.finalInstall.customerReceiptEvidence.release,
        target: fixture.finalInstall.customerReceiptEvidence.target,
        accessPolicy: fixture.finalInstall.customerReceiptEvidence.accessPolicy,
        desiredHash: fixture.finalInstall.customerReceiptEvidence.desiredHash,
        resources: [],
        pending: null,
        checksum: `sha256:${'7'.repeat(64)}`,
      },
    },
  };
}

function noManagedResidue(
  attemptId: string,
  deletionEvidence: readonly [
    HostedUninstallManagementAbsenceEvidence,
    HostedUninstallManagementAbsenceEvidence,
    HostedUninstallManagementAbsenceEvidence,
  ],
): HostedUninstallManagementNoManagedResidueResult {
  const namespaceProof = namespaceRetirement();
  const deletionProof = workerDeletionProof();
  return {
    schemaVersion: 1,
    status: 'no_ankka_managed_residue',
    uninstallPlanId: plan.planId,
    uninstallPlanHash: plan.planHash,
    uninstallAuthorityHash: plan.authorityHash,
    installBindingHash: fixture.finalInstall.bindingHash,
    installConvergenceHash: fixture.finalInstall.convergenceHash,
    attemptId,
    ownershipMarker: installDeployPlan.managementOwnershipMarker,
    managementHostname: plan.gateway.managementHostname,
    dnsAbsenceObservations: 2,
    advancedCertificate: 'provider_retained_out_of_scope_not_observable_or_deleted',
    uninstallCycleId: UNINSTALL_CYCLE_ID,
    deletionEvidenceSha256: 'd'.repeat(64),
    workerDeletionProofSha256: 'e'.repeat(64),
    namespaceRetirementProofSha256: 'f'.repeat(64),
    namespaceSnapshotSha256: '0'.repeat(64),
    evidence: {
      schemaVersion: 1,
      kind: 'hosted_uninstall_no_managed_residue_evidence',
      deletionEvidence,
      workerDeletion: deletionProof,
      namespaceRetirement: namespaceProof,
      namespaceSnapshots: [
        {
          schemaVersion: 1,
          kind: 'admin_state_namespace_absence_snapshot',
          observation: 1,
          accountId: ACCOUNT_ID,
          workerName: WORKER_NAME,
          namespaceId: fixture.finalInstall.adminStateNamespaceId,
          uninstallCycleId: UNINSTALL_CYCLE_ID,
          accountNamespaceCount: 0,
          snapshotSha256: namespaceProof.firstSnapshotSha256,
        },
        {
          schemaVersion: 1,
          kind: 'admin_state_namespace_absence_snapshot',
          observation: 2,
          accountId: ACCOUNT_ID,
          workerName: WORKER_NAME,
          namespaceId: fixture.finalInstall.adminStateNamespaceId,
          uninstallCycleId: UNINSTALL_CYCLE_ID,
          accountNamespaceCount: 0,
          snapshotSha256: namespaceProof.secondSnapshotSha256,
        },
      ],
      evidenceSha256: '1'.repeat(64),
    },
    proofSha256: '2'.repeat(64),
  };
}

function fullUninstallTombstone(): UninstallRemovedTombstone {
  const customDomainAbsence = managementAbsence(
    managementDeleteIntent('management_custom_domain_delete', ATTEMPT_ONE),
  );
  const adminPolicyAbsence = managementAbsence(
    managementDeleteIntent('management_admin_policy_delete', ATTEMPT_ONE),
  );
  const accessApplicationAbsence = managementAbsence(
    managementDeleteIntent('management_access_application_delete', ATTEMPT_ONE),
  );
  return {
    schemaVersion: 1,
    status: 'removed',
    convergenceHash: fixture.tombstone.convergenceHash,
    bindingHash: `sha256:${'f'.repeat(64)}`,
    uninstallCycleId: UNINSTALL_CYCLE_ID,
    installationId: fixture.finalInstall.installationId,
    target: { accountId: ACCOUNT_ID, zoneId: ZONE_ID, zoneName: 'example.com' },
    release: { id: 'gateway-v1.2.3', artifactSha256: 'b'.repeat(64) },
    customer: customerRemovedLocator(ATTEMPT_ONE),
    lifecycle: {
      cleanupVersion: versionSubmission('cleanup'),
      cleanupDeployment: deploymentSubmission(
        deploymentIntent('cleanup', versionSubmission('cleanup').versionId),
      ),
      restoredCleanDeployment: deploymentSubmission(
        deploymentIntent('restore_clean', fixture.finalInstall.cleanVersionId),
      ),
      retirementVersion: versionSubmission('retirement'),
      retirementDeployment: deploymentSubmission(
        deploymentIntent('retirement', versionSubmission('retirement').versionId),
      ),
      namespaceRetirement: namespaceRetirement(),
      workerDeletion: workerDeletionProof(),
    },
    management: {
      customDomainAbsence,
      adminPolicyAbsence,
      accessApplicationAbsence,
      noManagedResidue: noManagedResidue(ATTEMPT_ONE, [
        customDomainAbsence,
        adminPolicyAbsence,
        accessApplicationAbsence,
      ]),
    },
    workersDevEnabled: false,
    providerNotice: STATIC_UNINSTALL_PROVIDER_NOTICE,
  };
}

const executionDependencies: ReviewedUninstallExecutionDependencies = Object.freeze({
  isCompleteInstallJournal: () => true,
  prepareFinalConvergenceRecordAndLocator: async () => Object.freeze({
    record: Object.freeze({
      schemaVersion: 1,
      kind: 'final_convergence',
      convergenceHash: fixture.finalInstall.convergenceHash,
    }),
    locator: fixture.finalInstall,
  }),
  parseStaticUninstallPlan: async () => plan,
  isRecoveryEquivalentUninstallPlan: async () => true,
  adaptVerifiedReleaseBundleForGatewayDeployments: async () => fixture.releaseSet,
  deriveCustomerUninstallNonce: async () => 'n'.repeat(43),
  computeUninstallJournalBindingHash: async () => `sha256:${'f'.repeat(64)}`,
  prepareUninstallFinalConvergenceRecordAndLocator: async () => Object.freeze({
    record: Object.freeze({
      schemaVersion: 1,
      kind: 'uninstall_final_convergence',
      convergenceHash: fixture.tombstone.convergenceHash,
    }),
    locator: fullUninstallTombstone(),
  }),
});
const executeReviewedUninstall = createReviewedUninstallExecutor(executionDependencies);

function replaceAction(
  journal: UninstallJournal,
  name: UninstallActionName,
  transform: (action: UninstallJournalAction) => UninstallJournalAction,
): UninstallJournal {
  return {
    ...journal,
    revision: journal.revision + 1,
    actions: journal.actions.map((entry) => entry.name === name ? transform(entry) : entry),
  };
}

const versionSubmissionSchema = v.looseObject({ kind: v.literal('uninstall_worker_version') });
const deploymentSubmissionSchema = v.looseObject({ kind: v.literal('uninstall_worker_deployment') });
const managementSubmissionSchema = v.looseObject({
  status: v.literal('submitted'),
  action: v.picklist([
    'management_custom_domain_delete',
    'management_admin_policy_delete',
    'management_access_application_delete',
  ]),
});
const namespaceRetirementSchema = v.looseObject({
  kind: v.literal('admin_state_namespace_retirement'),
});
const workerDeleteSubmissionSchema = v.looseObject({ kind: v.literal('uninstall_worker_delete') });
const noResidueSchema = v.looseObject({ status: v.literal('no_ankka_managed_residue') });
const managementAbsenceSchema = v.looseObject({ status: v.literal('absent') });
const workerDeletionProofSchema = v.looseObject({ kind: v.literal('uninstall_worker_deletion_proof') });
const removedProjectionSchema = v.looseObject({ status: v.literal('removed') });

function isVersionSubmission<Value>(value: Value): value is Value & UninstallWorkerVersionSubmission {
  return v.is(versionSubmissionSchema, value);
}

function isDeploymentSubmission<Value>(
  value: Value,
): value is Value & UninstallWorkerDeploymentSubmission {
  return v.is(deploymentSubmissionSchema, value);
}

function isManagementSubmission<Value>(
  value: Value,
): value is Value & ReviewedSubmittedActionValues['management_custom_domain_delete'] {
  return v.is(managementSubmissionSchema, value);
}

function isNamespaceRetirement<Value>(
  value: Value,
): value is Value & ReviewedSubmittedActionValues['admin_state_namespace_retired'] {
  return v.is(namespaceRetirementSchema, value);
}

function isWorkerDeleteSubmission<Value>(
  value: Value,
): value is Value & ReviewedSubmittedActionValues['management_worker_delete'] {
  return v.is(workerDeleteSubmissionSchema, value);
}

function isNoResidue<Value>(
  value: Value,
): value is Value & ReviewedSubmittedActionValues['management_no_managed_residue'] {
  return v.is(noResidueSchema, value);
}

function isManagementAbsence<Value>(
  value: Value,
): value is Value & ReviewedVerifiedActionValues['management_custom_domain_delete'] {
  return v.is(managementAbsenceSchema, value);
}

function isWorkerDeletionProof<Value>(
  value: Value,
): value is Value & ReviewedVerifiedActionValues['management_worker_delete'] {
  return v.is(workerDeletionProofSchema, value);
}

function isRemovedProjection<Value>(
  value: Value,
): value is Value & ReviewedSubmittedActionValues['uninstall_final_convergence'] {
  return v.is(removedProjectionSchema, value);
}

class MemoryUninstallJournalPort implements ReviewedUninstallJournalPort {
  journal: UninstallJournal | null = null;
  readonly prepared: string[] = [];

  async initialize(input: Parameters<ReviewedUninstallJournalPort['initialize']>[0]): Promise<UninstallJournal> {
    const approval = input.approval;
    this.journal = {
      schemaVersion: 1,
      revision: 0,
      createdAt: input.initialization.now,
      updatedAt: input.initialization.now,
      recoverUntil: input.initialization.recoverUntil,
      installJournal: input.initialization.installJournal,
      uninstallPlan: input.initialization.uninstallPlan,
      uninstallCycleId: input.initialization.uninstallCycleId,
      bindingHash: input.initialization.bindingHash,
      approvalHistory: [{
        schemaVersion: 1,
        attemptId: approval.attemptId,
        approvedAt: approval.approvedAt,
        recordedAt: input.initialization.now,
        plan: input.initialization.uninstallPlan,
        authorizedTarget: approval.authorizedTarget,
      }],
      managementPreflightHistory: [],
      lease: null,
      leaseAttemptIds: [],
      actions: [{
        name: 'uninstall_fresh_preflight',
        phase: 'verified',
        record: input.initialization.freshPreflight,
        locator: { attestationSha256: input.initialization.freshPreflight.attestationSha256 },
        preparedAt: input.initialization.now,
        sendArmedAt: input.initialization.now,
        submittedAt: input.initialization.now,
        verifiedAt: input.initialization.now,
      }],
    };
    return this.journal;
  }

  async read(): Promise<UninstallJournal> {
    if (!this.journal) throw new DeployError(404, 'session_invalid');
    return this.journal;
  }

  async appendApproval(input: Parameters<ReviewedUninstallJournalPort['appendApproval']>[0]): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = {
      ...journal,
      revision: journal.revision + 1,
      approvalHistory: [...journal.approvalHistory, {
        schemaVersion: 1,
        attemptId: input.attemptId,
        approvedAt: input.approvedAt,
        recordedAt: input.now,
        plan: input.candidatePlan,
        authorizedTarget: input.authorizedTarget,
      }],
      lease: null,
    };
    return this.journal;
  }

  async acquireLease(input: Parameters<ReviewedUninstallJournalPort['acquireLease']>[0]): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = { ...journal, revision: journal.revision + 1,
      lease: { attemptId: input.attemptId, acquiredAt: input.now, expiresAt: input.leaseExpiresAt },
      leaseAttemptIds: [...journal.leaseAttemptIds, input.attemptId] };
    return this.journal;
  }

  async releaseLease(): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = { ...journal, revision: journal.revision + 1, lease: null };
    return this.journal;
  }

  async refreshPreflight(input: Parameters<ReviewedUninstallJournalPort['refreshPreflight']>[0]): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = replaceAction(journal, 'uninstall_fresh_preflight', (entry) => ({
      ...entry, record: input.preflight,
    }));
    return this.journal;
  }

  async appendManagementPreflight(
    input: Parameters<ReviewedUninstallJournalPort['appendManagementPreflight']>[0],
  ): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = { ...journal, revision: journal.revision + 1,
      managementPreflightHistory: [...journal.managementPreflightHistory, input.preflight] };
    return this.journal;
  }

  async prepareAction<Action extends keyof ReviewedPreparedActionRecords>(input: UninstallJournalCasInput & {
    readonly action: Action;
    readonly record: ReviewedPreparedActionRecords[Action];
  }): Promise<UninstallJournal> {
    const journal = this.must();
    this.prepared.push(input.action);
    const record = this.persistedRecord(input.action, input.record, input.attemptId, input.now);
    const prepared: UninstallJournalAction = {
      name: input.action,
      phase: 'prepared',
      record,
      locator: null,
      preparedAt: input.now,
      sendArmedAt: null,
      submittedAt: null,
      verifiedAt: null,
    };
    this.journal = {
      ...journal,
      revision: journal.revision + 1,
      actions: [...journal.actions, prepared],
    };
    return this.journal;
  }

  async replacePreparedAction<Action extends keyof ReviewedPreparedActionRecords>(
    input: UninstallJournalCasInput & {
      readonly action: Action;
      readonly record: ReviewedPreparedActionRecords[Action];
    },
  ): Promise<UninstallJournal> {
    const journal = this.must();
    const record = this.persistedRecord(input.action, input.record, input.attemptId, input.now);
    this.journal = replaceAction(journal, input.action, (entry) => ({ ...entry, record }));
    return this.journal;
  }

  async attachWorkerVersionRecovery(
    input: Parameters<ReviewedUninstallJournalPort['attachWorkerVersionRecovery']>[0],
  ): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = replaceAction(journal, input.action, (entry) => {
      if (!('kind' in entry.record) || entry.record.kind !== 'uninstall_worker_version_create') {
        throw new TypeError('worker version action fixture mismatch');
      }
      return { ...entry, record: { ...entry.record, recovery: input.recovery } };
    });
    return this.journal;
  }

  async armAction<Action extends keyof ReviewedPreparedActionRecords>(input: UninstallJournalCasInput & {
    readonly action: Action;
    readonly value?: Action extends 'management_custom_domain_delete' |
      'management_admin_policy_delete' | 'management_access_application_delete'
      ? HostedUninstallManagementDeleteArm
      : never;
  }): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = replaceAction(journal, input.action, (entry) => {
      if ('kind' in entry.record && entry.record.kind === 'uninstall_management_delete') {
        if (!input.value) throw new TypeError('management arm fixture missing');
        const latest = entry.record.attempts.at(-1);
        if (!latest) throw new TypeError('management attempt fixture missing');
        const updatedAttempt: ManagementDeleteAttempt = {
          ...latest,
          phase: 'send_armed',
          arm: input.value,
          sendArmedAt: input.now,
        };
        const record: ManagementDeleteActionRecord = {
          ...entry.record,
          attempts: [...entry.record.attempts.slice(0, -1), updatedAttempt],
        };
        return { ...entry, phase: 'send_armed', record, sendArmedAt: input.now };
      }
      return { ...entry, phase: 'send_armed', sendArmedAt: input.now };
    });
    return this.journal;
  }

  async recordActionSubmitted<Action extends keyof ReviewedSubmittedActionValues>(
    input: UninstallJournalCasInput & {
      readonly action: Action;
      readonly value: ReviewedSubmittedActionValues[Action];
    },
  ): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = replaceAction(journal, input.action, (entry) => {
      if (input.action === 'management_custom_domain_delete' ||
        input.action === 'management_admin_policy_delete' ||
        input.action === 'management_access_application_delete') {
        if (!('kind' in entry.record) || entry.record.kind !== 'uninstall_management_delete') {
          throw new TypeError('management action fixture mismatch');
        }
        if (!isManagementSubmission(input.value)) {
          throw new TypeError('management submission fixture mismatch');
        }
        const latest = entry.record.attempts.at(-1);
        if (!latest) throw new TypeError('management attempt fixture missing');
        const updatedAttempt: ManagementDeleteAttempt = {
          ...latest,
          phase: 'submitted',
          submission: input.value,
          submittedAt: input.now,
          submittedByAttemptId: input.attemptId,
        };
        const record: ManagementDeleteActionRecord = {
          ...entry.record,
          attempts: [...entry.record.attempts.slice(0, -1), updatedAttempt],
        };
        return { ...entry, phase: 'submitted', record, locator: null, submittedAt: input.now };
      }
      if (input.action === 'management_worker_delete') {
        if (!('kind' in entry.record) || entry.record.kind !== 'management_worker_delete') {
          throw new TypeError('worker delete action fixture mismatch');
        }
        if (!isWorkerDeleteSubmission(input.value)) {
          throw new TypeError('worker delete submission fixture mismatch');
        }
        return {
          ...entry,
          phase: 'submitted',
          record: { ...entry.record, submission: input.value },
          locator: null,
          submittedAt: input.now,
        };
      }
      if ('kind' in entry.record && entry.record.kind === 'uninstall_worker_version_create') {
        if (!isVersionSubmission(input.value)) throw new TypeError('version submission fixture mismatch');
        return { ...entry, phase: 'submitted', locator: input.value, submittedAt: input.now };
      }
      if ('kind' in entry.record && entry.record.kind === 'uninstall_worker_deployment_create') {
        if (!isDeploymentSubmission(input.value)) {
          throw new TypeError('deployment submission fixture mismatch');
        }
        return { ...entry, phase: 'submitted', locator: input.value, submittedAt: input.now };
      }
      if ('kind' in entry.record && entry.record.kind === 'admin_state_namespace_retired') {
        if (!isNamespaceRetirement(input.value)) {
          throw new TypeError('namespace retirement fixture mismatch');
        }
        return { ...entry, phase: 'submitted', locator: input.value, submittedAt: input.now };
      }
      if ('kind' in entry.record && entry.record.kind === 'management_no_managed_residue') {
        if (!isNoResidue(input.value)) throw new TypeError('residue proof fixture mismatch');
        return { ...entry, phase: 'submitted', locator: input.value, submittedAt: input.now };
      }
      if ('kind' in entry.record && entry.record.kind === 'uninstall_final_convergence') {
        if (!isRemovedProjection(input.value)) throw new TypeError('final projection fixture mismatch');
        return { ...entry, phase: 'submitted', locator: fullUninstallTombstone(), submittedAt: input.now };
      }
      throw new TypeError('submitted action fixture mismatch');
    });
    return this.journal;
  }

  async verifyAction<Action extends keyof ReviewedVerifiedActionValues>(input: UninstallJournalCasInput & {
    readonly action: Action;
    readonly value: ReviewedVerifiedActionValues[Action];
  }): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = replaceAction(journal, input.action, (entry) => {
      if (input.action === 'management_custom_domain_delete' ||
        input.action === 'management_admin_policy_delete' ||
        input.action === 'management_access_application_delete') {
        if (!('kind' in entry.record) || entry.record.kind !== 'uninstall_management_delete') {
          throw new TypeError('management action fixture mismatch');
        }
        if (!isManagementAbsence(input.value)) {
          throw new TypeError('management absence fixture mismatch');
        }
        const latest = entry.record.attempts.at(-1);
        if (!latest) throw new TypeError('management attempt fixture missing');
        const updatedAttempt: ManagementDeleteAttempt = {
          ...latest,
          phase: 'verified',
          locator: input.value,
          verifiedAt: input.now,
          verifiedByAttemptId: input.attemptId,
        };
        const record: ManagementDeleteActionRecord = {
          ...entry.record,
          attempts: [...entry.record.attempts.slice(0, -1), updatedAttempt],
        };
        return {
          ...entry,
          phase: 'verified',
          record,
          locator: input.value,
          verifiedAt: input.now,
        };
      }
      if ('kind' in entry.record && entry.record.kind === 'uninstall_worker_version_create') {
        if (!isVersionSubmission(input.value)) throw new TypeError('version proof fixture mismatch');
        return { ...entry, phase: 'verified', locator: input.value, verifiedAt: input.now };
      }
      if ('kind' in entry.record && entry.record.kind === 'uninstall_worker_deployment_create') {
        if (!isDeploymentSubmission(input.value)) throw new TypeError('deployment proof fixture mismatch');
        return { ...entry, phase: 'verified', locator: input.value, verifiedAt: input.now };
      }
      if ('kind' in entry.record && entry.record.kind === 'admin_state_namespace_retired') {
        if (!isNamespaceRetirement(input.value)) throw new TypeError('namespace proof fixture mismatch');
        return { ...entry, phase: 'verified', locator: input.value, verifiedAt: input.now };
      }
      if ('kind' in entry.record && entry.record.kind === 'management_worker_delete') {
        if (!isWorkerDeletionProof(input.value)) throw new TypeError('worker deletion proof mismatch');
        return { ...entry, phase: 'verified', locator: input.value, verifiedAt: input.now };
      }
      if ('kind' in entry.record && entry.record.kind === 'management_no_managed_residue') {
        if (!isNoResidue(input.value)) throw new TypeError('residue proof fixture mismatch');
        return { ...entry, phase: 'verified', locator: input.value, verifiedAt: input.now };
      }
      if ('kind' in entry.record && entry.record.kind === 'uninstall_final_convergence') {
        if (!isRemovedProjection(input.value)) throw new TypeError('final projection fixture mismatch');
        return { ...entry, phase: 'verified', locator: fullUninstallTombstone(), verifiedAt: input.now };
      }
      throw new TypeError('verified action fixture mismatch');
    });
    return this.journal;
  }

  async appendCustomerRemoveCycle(
    input: Parameters<ReviewedUninstallJournalPort['appendCustomerRemoveCycle']>[0],
  ): Promise<UninstallJournal> {
    const journal = this.must();
    const attempt = this.customerAttempt(input.attemptId, input.semantic, input.now);
    this.prepared.push('customer_gateway_remove');
    const record: CustomerGatewayRemoveActionRecord = {
      schemaVersion: 1,
      kind: 'customer_gateway_remove',
      accountId: ACCOUNT_ID,
      zoneId: ZONE_ID,
      zoneName: 'example.com',
      workerName: WORKER_NAME,
      installationId: fixture.finalInstall.installationId,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      attempts: [attempt],
    };
    const action: UninstallJournalAction = {
      name: 'customer_gateway_remove', phase: 'prepared', locator: null,
      record,
      preparedAt: input.now, sendArmedAt: null, submittedAt: null, verifiedAt: null,
    };
    this.journal = {
      ...journal,
      revision: journal.revision + 1,
      actions: [...journal.actions, action],
    };
    return this.journal;
  }

  async replacePreparedCustomerRemoveCycle(
    input: Parameters<ReviewedUninstallJournalPort['replacePreparedCustomerRemoveCycle']>[0],
  ): Promise<UninstallJournal> {
    const journal = this.must();
    const replacement = this.customerAttempt(input.attemptId, input.semantic, input.now);
    this.journal = this.mapCustomer(journal, (record) => ({
      ...record, attempts: [...record.attempts.slice(0, -1), replacement],
    }));
    return this.journal;
  }

  async armCustomerWorkersDev(
    input: Parameters<ReviewedUninstallJournalPort['armCustomerWorkersDev']>[0],
  ): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => input.enabled
      ? { ...attempt, enable: { ...attempt.enable, phase: 'send_armed', sendArmedAt: input.now } }
      : { ...attempt, disableAttempts: attempt.disableAttempts.map((entry, index) =>
        index === attempt.disableAttempts.length - 1
          ? { ...entry, phase: 'send_armed', sendArmedAt: input.now }
          : entry) }));
    return this.journal;
  }

  async recordCustomerWorkersDevSubmitted(
    input: Parameters<ReviewedUninstallJournalPort['recordCustomerWorkersDevSubmitted']>[0],
  ): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => input.enabled
      ? { ...attempt, enable: { ...attempt.enable, phase: 'submitted', locator: input.locator,
        submittedAt: input.now, submittedByAttemptId: input.attemptId } }
      : { ...attempt, disableAttempts: attempt.disableAttempts.map((entry, index) =>
        index === attempt.disableAttempts.length - 1
          ? { ...entry, phase: 'submitted', locator: input.locator, submittedAt: input.now,
            submittedByAttemptId: input.attemptId }
          : entry) }));
    return this.journal;
  }

  async verifyCustomerWorkersDev(
    input: Parameters<ReviewedUninstallJournalPort['verifyCustomerWorkersDev']>[0],
  ): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => input.enabled
      ? { ...attempt, enable: { ...attempt.enable, phase: 'verified', verifiedAt: input.now,
        verifiedByAttemptId: input.attemptId } }
      : { ...attempt, disableAttempts: attempt.disableAttempts.map((entry, index) =>
        index === attempt.disableAttempts.length - 1
          ? { ...entry, phase: 'verified', verifiedAt: input.now, verifiedByAttemptId: input.attemptId }
          : entry) }));
    return this.journal;
  }

  async recordCustomerWorkersDevNotApplied(
    input: Parameters<ReviewedUninstallJournalPort['recordCustomerWorkersDevNotApplied']>[0],
  ): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => input.enabled
      ? { ...attempt, enable: { ...attempt.enable, phase: 'not_applied', locator: input.locator,
        verifiedAt: input.now, verifiedByAttemptId: input.attemptId } }
      : { ...attempt, disableAttempts: attempt.disableAttempts.map((entry, index) =>
        index === attempt.disableAttempts.length - 1
          ? { ...entry, phase: 'not_applied', locator: input.locator, verifiedAt: input.now,
            verifiedByAttemptId: input.attemptId }
          : entry) }));
    return this.journal;
  }

  async armCustomerRemoveRequest(
    input: Parameters<ReviewedUninstallJournalPort['armCustomerRemoveRequest']>[0],
  ): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => ({
      ...attempt, requestPhase: 'send_armed', sendArmedAt: input.now,
    })));
    return this.journal;
  }

  async recordCustomerRemoveRequestSubmitted(
    input: Parameters<ReviewedUninstallJournalPort['recordCustomerRemoveRequestSubmitted']>[0],
  ): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => ({
      ...attempt, requestPhase: 'submitted', locator: input.locator, submittedAt: input.now,
      submittedByAttemptId: input.attemptId,
    })));
    return this.journal;
  }

  async verifyCustomerRemoveRequest(
    input: Parameters<ReviewedUninstallJournalPort['verifyCustomerRemoveRequest']>[0],
  ): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => ({
      ...attempt, requestPhase: 'verified', verifiedAt: input.now, verifiedByAttemptId: input.attemptId,
    })));
    return this.journal;
  }

  async prepareCustomerWorkersDevDisable(
    input: Parameters<ReviewedUninstallJournalPort['prepareCustomerWorkersDevDisable']>[0],
  ): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => ({
      ...attempt,
      disableAttempts: [...attempt.disableAttempts, this.workersDev(input.attemptId, false, input.now)],
    })));
    return this.journal;
  }

  async replacePreparedCustomerWorkersDevDisable(
    input: Parameters<ReviewedUninstallJournalPort['replacePreparedCustomerWorkersDevDisable']>[0],
  ): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => ({
      ...attempt,
      disableAttempts: [...attempt.disableAttempts.slice(0, -1), this.workersDev(input.attemptId, false, input.now)],
    })));
    return this.journal;
  }

  async appendManagementDeleteAttempt(
    input: Parameters<ReviewedUninstallJournalPort['appendManagementDeleteAttempt']>[0],
  ): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = replaceAction(journal, input.action, (entry) => {
      if (!('kind' in entry.record) || entry.record.kind !== 'uninstall_management_delete') {
        throw new TypeError('management action fixture mismatch');
      }
      const draft: ManagementDeleteActionDraft = {
        schemaVersion: 1,
        kind: 'uninstall_management_delete',
        prerequisites: input.prerequisites,
        intent: input.intent,
      };
      return {
        ...entry,
        record: {
          ...entry.record,
          attempts: [...entry.record.attempts, this.managementAttempt(draft, input.now)],
        },
      };
    });
    return this.journal;
  }

  async recordManagementDeleteRecovery(
    input: Parameters<ReviewedUninstallJournalPort['recordManagementDeleteRecovery']>[0],
  ): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = replaceAction(journal, input.action, (entry) => {
      if (!('kind' in entry.record) || entry.record.kind !== 'uninstall_management_delete') {
        throw new TypeError('management action fixture mismatch');
      }
      const latest = entry.record.attempts.at(-1);
      if (!latest) throw new TypeError('management attempt fixture missing');
      const absent = input.evidence.status === 'absent';
      const recovered: ManagementDeleteAttempt = absent
        ? {
            ...latest,
            phase: 'verified',
            locator: input.evidence,
            recovery: null,
            verifiedAt: input.now,
            verifiedByAttemptId: input.attemptId,
          }
        : {
            ...latest,
            phase: 'not_applied',
            locator: null,
            recovery: input.evidence,
            verifiedAt: input.now,
            verifiedByAttemptId: input.attemptId,
          };
      const record: ManagementDeleteActionRecord = {
        ...entry.record,
        attempts: [...entry.record.attempts.slice(0, -1), recovered],
      };
      return {
        ...entry,
        phase: absent ? 'verified' : entry.phase,
        locator: absent ? input.evidence : null,
        record,
        verifiedAt: absent ? input.now : null,
      };
    });
    return this.journal;
  }

  discardPreflight = async () => ({ discarded: true as const });

  private must(): UninstallJournal {
    if (!this.journal) throw new TypeError('missing journal fixture');
    return this.journal;
  }

  clearLeaseForRecovery(): void {
    const journal = this.must();
    this.journal = { ...journal, lease: null };
  }

  private workersDev(attemptId: string, enabled: boolean, now: number): UninstallWorkersDevMutation {
    return { schemaVersion: 1, kind: 'uninstall_workers_dev', approvalAttemptId: attemptId,
      accountId: ACCOUNT_ID, workerName: WORKER_NAME, uninstallCycleId: UNINSTALL_CYCLE_ID,
      enabled, previewsEnabled: false, requestHash: '0'.repeat(64), phase: 'prepared', locator: null,
      preparedAt: now, sendArmedAt: null, submittedAt: null, submittedByAttemptId: null,
      verifiedAt: null, verifiedByAttemptId: null };
  }

  private customerAttempt(
    attemptId: string,
    semantic: CustomerGatewayRemoveRequestAttempt['semantic'],
    now: number,
  ): CustomerGatewayRemoveRequestAttempt {
    return { schemaVersion: 1, approvalAttemptId: attemptId, semantic, enable: this.workersDev(attemptId, true, now),
      requestPhase: 'prepared', locator: null, disableAttempts: [], preparedAt: now, sendArmedAt: null,
      submittedAt: null, submittedByAttemptId: null, verifiedAt: null, verifiedByAttemptId: null };
  }

  private managementAttempt(record: ManagementDeleteActionDraft, now: number): ManagementDeleteAttempt {
    return { schemaVersion: 1, prerequisites: record.prerequisites, intent: record.intent, phase: 'prepared',
      arm: null, submission: null, recovery: null, locator: null, preparedAt: now, sendArmedAt: null,
      submittedAt: null, submittedByAttemptId: null, verifiedAt: null,
      verifiedByAttemptId: null };
  }

  private persistedRecord<Action extends keyof ReviewedPreparedActionRecords>(
    _action: Action,
    record: ReviewedPreparedActionRecords[Action],
    attemptId: string,
    now: number,
  ): UninstallJournalAction['record'] {
    if (record.kind === 'uninstall_management_delete') {
      return {
        schemaVersion: 1,
        kind: 'uninstall_management_delete',
        action: record.intent.kind,
        attempts: [this.managementAttempt(record, now)],
      };
    }
    if (record.kind === 'management_no_managed_residue') {
      return {
        ...record,
        preparedByAttemptId: attemptId,
        armedByAttemptId: null,
        submittedByAttemptId: null,
        verifiedByAttemptId: null,
      };
    }
    return record;
  }

  private mapCustomer(
    journal: UninstallJournal,
    transform: (record: CustomerGatewayRemoveActionRecord) => CustomerGatewayRemoveActionRecord,
  ): UninstallJournal {
    return replaceAction(journal, 'customer_gateway_remove', (entry) => {
      if (!('kind' in entry.record) || entry.record.kind !== 'customer_gateway_remove') {
        throw new TypeError('customer action fixture mismatch');
      }
      const record = transform(entry.record);
      const attempt = record.attempts.at(-1);
      const disable = attempt?.disableAttempts.at(-1);
      const complete = attempt?.requestPhase === 'verified' && disable?.phase === 'verified';
      const verifiedAt = complete && attempt && disable &&
        attempt.verifiedAt !== null && disable.verifiedAt !== null
        ? Math.max(attempt.verifiedAt, disable.verifiedAt)
        : entry.verifiedAt;
      return {
        ...entry,
        record,
        phase: complete ? 'verified' : entry.phase,
        locator: complete && attempt ? attempt.locator : entry.locator,
        verifiedAt,
      };
    });
  }

  private mapLatestCustomer(
    record: CustomerGatewayRemoveActionRecord,
    transform: (attempt: CustomerGatewayRemoveRequestAttempt) => CustomerGatewayRemoveRequestAttempt,
  ): CustomerGatewayRemoveActionRecord {
    const latest = record.attempts.at(-1);
    if (!latest) throw new TypeError('customer attempt fixture missing');
    return { ...record, attempts: [...record.attempts.slice(0, -1), transform(latest)] };
  }
}

interface ProviderOptions {
  readonly failFirstCleanupSubmit?: boolean;
  readonly failPostReadyCleanupProof?: boolean;
}

interface ProviderHarness {
  readonly provider: ReviewedUninstallProviderAdapter;
  readonly mutations: string[];
  readonly inspections: string[];
  allowCleanupRecovery(): void;
}

function providerHarness(options: ProviderOptions = {}): ProviderHarness {
  const mutations: string[] = [];
  const inspections: string[] = [];
  let cleanupFailed = false;
  let cleanupRecoverable = !options.failFirstCleanupSubmit;

  const provider: ReviewedUninstallProviderAdapter = {
    getAccountWorkersSubdomain: async () => ({ accountId: ACCOUNT_ID, subdomain: 'example-account' }),
    inspectAdminStateNamespace: async () => ({ accountId: ACCOUNT_ID,
      namespaceId: fixture.finalInstall.adminStateNamespaceId, namespaceName: 'ankka-admin-state',
      workerName: WORKER_NAME, className: 'AdminState', storage: 'sqlite' }),
    preflightManagement: async (context, _call, now) => managementPreflight(context.activeAttemptId, now),
    prepareCleanupVersion: async () => versionMutationPlan('cleanup'),
    prepareRetirementVersion: async () => versionMutationPlan('retirement'),
    inspectVersion: async (recovery) => {
      inspections.push(`version:${recovery.stage}`);
      return recovery.stage === 'cleanup' && !cleanupRecoverable ? null : versionSubmission(recovery.stage);
    },
    submitVersion: async (mutation) => {
      mutations.push(`version:${mutation.recovery.stage}`);
      if (mutation.recovery.stage === 'cleanup' && options.failFirstCleanupSubmit && !cleanupFailed) {
        cleanupFailed = true;
        throw new Error('unknown');
      }
      return versionSubmission(mutation.recovery.stage);
    },
    verifyVersion: async (_recovery, submission) => submission,
    prepareDeployment: async (input) => deploymentIntent(input.stage, input.versionId),
    inspectDeployment: async () => null,
    submitDeployment: async (intent) => {
      mutations.push(`deployment:${intent.stage}`);
      return deploymentSubmission(intent);
    },
    verifyDeployment: async (_intent, submission) => submission,
    verifyActiveDeployment: async (_intent, submission) => submission,
    proveActiveCleanupWorker: async (
      _recovery,
      versionSubmission,
      _deploymentIntent,
      deploymentSubmission,
    ) => {
      inspections.push('cleanup-active-proof');
      if (options.failPostReadyCleanupProof) throw new Error('cleanup deployment drift');
      return { version: versionSubmission, deployment: deploymentSubmission };
    },
    setWorkersDev: async (enabled: boolean) => {
      mutations.push(`workers-dev:${String(enabled)}`);
      return { enabled, previewsEnabled: false };
    },
    verifyWorkersDev: async (enabled: boolean) => ({ enabled, previewsEnabled: false }),
    prepareCustomerRequest: async (input) => customerMutationPlan(input.approval.attemptId),
    awaitCustomerRemoveReady: async () => {
      mutations.push('customer-remove-ready');
    },
    submitCustomerRequest: async (input) => {
      mutations.push('customer-remove');
      return customerRemovedLocator(input.mutation.semantic.approvalAttemptId);
    },
    prepareManagementDeleteIntent: async (context, action) =>
      managementDeleteIntent(action, context.activeAttemptId),
    prepareManagementDeleteArm: async (_context, intent, _prerequisites, armedAt) => ({
      schemaVersion: 1, kind: 'management_delete_arm', action: intent.kind,
      attemptId: intent.attemptId, armedAt, intentSha256: '8'.repeat(64),
    }),
    submitManagementDelete: async (_context, intent) => {
      mutations.push(intent.kind);
      return managementSubmission(intent);
    },
    verifyManagementDelete: async (_context, intent) => managementAbsence(intent),
    recoverManagementDelete: async (_context, intent) => managementAbsence(intent),
    proveNamespacePresent: async () => namespacePresence(),
    proveNamespaceRetired: async () => {
      inspections.push('namespace-retired');
      return namespaceRetirement();
    },
    prepareWorkerDelete: async () => workerDeleteIntent(),
    submitWorkerDelete: async (intent) => {
      mutations.push('worker-delete');
      return {
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
      };
    },
    recoverWorkerDelete: async () => workerDeletionProof(),
    verifyNoManagedResidue: async (context, deletionEvidence) => {
      inspections.push('no-residue');
      const [customDomain, adminPolicy, accessApplication] = deletionEvidence;
      if (!customDomain || !adminPolicy || !accessApplication || deletionEvidence.length !== 3) {
        throw new TypeError('management deletion evidence fixture mismatch');
      }
      return noManagedResidue(context.activeAttemptId, [customDomain, adminPolicy, accessApplication]);
    },
  };
  return {
    provider,
    mutations,
    inspections,
    allowCleanupRecovery: () => { cleanupRecoverable = true; },
  };
}

function executionInput(
  port: MemoryUninstallJournalPort,
  provider: ReviewedUninstallProviderAdapter,
  attemptId = ATTEMPT_ONE,
): ReviewedUninstallExecutionInput {
  return {
    installJournal,
    uninstallPlan: plan,
    target,
    releaseBundle: verifiedReleaseBundle,
    accessToken: ACCESS_TOKEN,
    uninstallNonceDerivationKey: NONCE_KEY,
    attemptId,
    approvedAt: fixture.now,
    recoverUntil: installJournal.recoverUntil,
    uninstallCycleId: UNINSTALL_CYCLE_ID,
    journal: port,
    provider,
    transport: async () => new Response(null, { status: 500 }),
    now: () => fixture.now,
  };
}

describe('reviewed uninstall executor', () => {
  it('keeps the default executor disabled without inspecting dependencies', async () => {
    const inertInput = executionInput(new MemoryUninstallJournalPort(), providerHarness().provider);
    await expect(new DisabledUninstallExecutor().execute(inertInput)).rejects.toMatchObject({
      status: 503,
      code: 'uninstall_mutations_disabled',
    });
  });

  it('durably converges the exact 14-action canary uninstall order', async () => {
    const port = new MemoryUninstallJournalPort();
    const harness = providerHarness();
    await expect(executeReviewedUninstall(executionInput(port, harness.provider))).resolves.toEqual({
      status: 'removed',
      installationId: fixture.finalInstall.installationId,
      convergenceHash: fixture.tombstone.convergenceHash,
    });
    expect(port.journal?.actions.map((entry) => entry.name)).toEqual([
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
    ]);
    expect(port.journal?.actions.every((entry) => entry.phase === 'verified')).toBe(true);
    expect(harness.mutations).toEqual([
      'version:cleanup',
      'deployment:cleanup',
      'workers-dev:true',
      'customer-remove-ready',
      'customer-remove',
      'workers-dev:false',
      'deployment:restore_clean',
      'management_custom_domain_delete',
      'management_admin_policy_delete',
      'management_access_application_delete',
      'version:retirement',
      'deployment:retirement',
      'worker-delete',
    ]);
  });

  it('never replays an armed version mutation and resumes only from two equal inspections', async () => {
    const port = new MemoryUninstallJournalPort();
    const harness = providerHarness({ failFirstCleanupSubmit: true });
    await expect(executeReviewedUninstall(executionInput(port, harness.provider))).rejects.toThrow('unknown');
    expect(harness.mutations).toEqual(['version:cleanup']);
    expect(port.journal?.actions.at(-1)).toMatchObject({
      name: 'cleanup_worker_version_create',
      phase: 'send_armed',
    });
    expect(harness.inspections).toEqual(['version:cleanup', 'version:cleanup']);

    port.clearLeaseForRecovery();
    harness.allowCleanupRecovery();
    await expect(executeReviewedUninstall(
      executionInput(port, harness.provider, ATTEMPT_TWO),
    )).resolves.toMatchObject({ status: 'removed' });
    expect(harness.mutations.filter((entry) => entry === 'version:cleanup')).toHaveLength(1);
    expect(harness.inspections.slice(2, 4)).toEqual(['version:cleanup', 'version:cleanup']);
  });

  it('closes workers.dev and sends no grant when cleanup drifts after route readiness', async () => {
    const port = new MemoryUninstallJournalPort();
    const harness = providerHarness({ failPostReadyCleanupProof: true });
    await expect(executeReviewedUninstall(executionInput(port, harness.provider)))
      .rejects.toThrow('cleanup deployment drift');
    expect(harness.mutations).toEqual([
      'version:cleanup',
      'deployment:cleanup',
      'workers-dev:true',
      'customer-remove-ready',
      'workers-dev:false',
    ]);
    expect(harness.mutations).not.toContain('customer-remove');
    expect(harness.inspections).toContain('cleanup-active-proof');
  });
});
