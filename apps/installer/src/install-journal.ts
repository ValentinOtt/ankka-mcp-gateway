import * as v from 'valibot';

import {
  boundaryObjectSchema,
  boundaryValueSchema,
  type BoundaryObject,
  type BoundaryValue,
} from './boundary';
import { canonicalJson } from './canonical-json';
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
const MAX_IDENTITY_PROVIDERS = 64;
const MAX_LEASE_ATTEMPTS = 16;
const MAX_APPROVALS = 16;
const MAX_BOOTSTRAP_ATTEMPTS = 8;

const safeIntegerSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const sha256Schema = v.pipe(v.string(), v.regex(SHA256));
const prefixedSha256Schema = v.pipe(v.string(), v.regex(PREFIXED_SHA256));
const providerIdSchema = v.pipe(v.string(), v.regex(PROVIDER_ID));
const attemptIdSchema = v.pipe(v.string(), v.regex(ATTEMPT_ID));
const installationIdSchema = v.pipe(v.string(), v.regex(INSTALLATION_ID));
const installActionPhaseSchema = v.picklist(['prepared', 'send_armed', 'submitted', 'verified']);
const releasePinSchema = v.strictObject({
  verification: v.literal('ed25519'),
  keyId: v.pipe(v.string(), v.regex(KEY_ID)),
  release: v.pipe(v.string(), v.regex(RELEASE)),
  artifactSha256: sha256Schema,
});
const authorizedTargetSchema = v.strictObject({
  actor: v.strictObject({
    id: v.pipe(v.string(), v.regex(SAFE_ACTOR_ID)),
    email: v.string(),
  }),
  account: v.strictObject({
    id: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
    name: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
  }),
  zone: v.strictObject({
    id: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
    name: v.string(),
    status: v.literal('active'),
  }),
});
const workerCreateRecordSchema = v.strictObject({
  schemaVersion: v.literal(1),
  kind: v.literal('worker_create'),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  workerName: v.pipe(v.string(), v.regex(WORKER_NAME)),
  requestHash: sha256Schema,
  correlationTag: v.pipe(v.string(), v.regex(/^ankka-worker-sha256:[a-f0-9]{64}$/u)),
});
const applicationCreateRecordSchema = v.strictObject({
  schemaVersion: v.literal(1),
  kind: v.literal('management_access_application_create'),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  planId: v.string(),
  planHash: v.string(),
  ownershipMarker: v.string(),
  allowedIdentityProviderIds: v.pipe(v.array(providerIdSchema), v.minLength(1), v.maxLength(MAX_IDENTITY_PROVIDERS)),
  intentHash: sha256Schema,
});
const policyCreateRecordSchema = v.strictObject({
  schemaVersion: v.literal(1),
  kind: v.literal('management_admin_policy_create'),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  planId: v.string(),
  planHash: v.string(),
  ownershipMarker: v.string(),
  applicationId: providerIdSchema,
  intentHash: sha256Schema,
});
const workerVersionCreateRecordShellSchema = v.strictObject({
  schemaVersion: v.literal(1),
  kind: v.literal('worker_version_create'),
  phase: v.picklist(['provision', 'bootstrap', 'clean']),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  workerName: v.pipe(v.string(), v.regex(WORKER_NAME)),
  workerId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  requestHash: sha256Schema,
  correlationTag: v.string(),
  releaseContract: boundaryValueSchema,
  assets: boundaryValueSchema,
  plainTextBindingHashes: boundaryValueSchema,
  modules: boundaryValueSchema,
});
const workerDeploymentCreateRecordSchema = v.strictObject({
  schemaVersion: v.literal(1),
  kind: v.literal('worker_deployment_create'),
  phase: v.picklist(['provision', 'bootstrap', 'clean']),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  workerName: v.pipe(v.string(), v.regex(WORKER_NAME)),
  workerId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  versionId: v.pipe(v.string(), v.regex(UUID)),
  requestHash: sha256Schema,
  correlationTag: v.string(),
});
const bootstrapSubdomainRecordSchema = v.strictObject({
  schemaVersion: v.literal(1),
  kind: v.literal('bootstrap_subdomain'),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  workerName: v.pipe(v.string(), v.regex(WORKER_NAME)),
  enabled: v.boolean(),
  requestHash: sha256Schema,
});
const cycleSubdomainMutationSchema = v.strictObject({
  schemaVersion: v.literal(1),
  approvalAttemptId: v.pipe(v.string(), v.regex(ATTEMPT_ID)),
  enabled: v.boolean(),
  requestHash: sha256Schema,
  phase: installActionPhaseSchema,
  locator: v.nullable(v.strictObject({ enabled: v.boolean(), previewsEnabled: v.literal(false) })),
  preparedAt: safeIntegerSchema,
  sendArmedAt: v.nullable(safeIntegerSchema),
  submittedAt: v.nullable(safeIntegerSchema),
  verifiedAt: v.nullable(safeIntegerSchema),
});
const bootstrapAttemptSchema = v.strictObject({
  schemaVersion: v.literal(1),
  approvalAttemptId: v.pipe(v.string(), v.regex(ATTEMPT_ID)),
  requestId: v.pipe(v.string(), v.regex(REQUEST_ID)),
  issuedAt: safeIntegerSchema,
  expiresAt: safeIntegerSchema,
  claimHash: v.pipe(v.string(), v.regex(PREFIXED_SHA256)),
  enable: cycleSubdomainMutationSchema,
  disable: v.nullable(cycleSubdomainMutationSchema),
  phase: installActionPhaseSchema,
  locator: v.nullable(boundaryValueSchema),
  preparedAt: safeIntegerSchema,
  sendArmedAt: v.nullable(safeIntegerSchema),
  submittedAt: v.nullable(safeIntegerSchema),
  verifiedAt: v.nullable(safeIntegerSchema),
});
const bootstrapSubmitRecordSchema = v.strictObject({
  schemaVersion: v.literal(1),
  kind: v.literal('customer_bootstrap_submit'),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  zoneId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  zoneName: v.string(),
  accountWorkersSubdomain: v.pipe(v.string(), v.regex(HOST_LABEL)),
  installationId: v.pipe(v.string(), v.regex(INSTALLATION_ID)),
  configurationHash: v.pipe(v.string(), v.regex(PREFIXED_SHA256)),
  desiredHash: v.pipe(v.string(), v.regex(PREFIXED_SHA256)),
  attempts: v.pipe(v.array(bootstrapAttemptSchema), v.minLength(1), v.maxLength(MAX_BOOTSTRAP_ATTEMPTS)),
});
const managementCustomDomainRecordSchema = v.strictObject({
  schemaVersion: v.literal(1),
  kind: v.literal('management_custom_domain_attach'),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  zoneId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  planId: v.string(),
  planHash: v.string(),
  ownershipMarker: v.string(),
  intentHash: sha256Schema,
});
const finalConvergenceRecordSchema = v.strictObject({
  schemaVersion: v.literal(1),
  kind: v.literal('final_convergence'),
  convergenceHash: v.pipe(v.string(), v.regex(PREFIXED_SHA256)),
});
const workerLocatorSchema = v.strictObject({
  kind: v.literal('worker'),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  workerName: v.pipe(v.string(), v.regex(WORKER_NAME)),
  workerId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
});
const freshPreflightLocatorSchema = v.strictObject({ attestationHash: prefixedSha256Schema });
const applicationLocatorSchema = v.strictObject({
  applicationId: providerIdSchema,
  aud: v.pipe(v.string(), v.regex(ACCESS_AUD)),
});
const policyLocatorSchema = v.strictObject({ policyId: providerIdSchema });
const versionLocatorSchema = v.strictObject({
  kind: v.literal('version'),
  phase: v.picklist(['provision', 'bootstrap', 'clean']),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  workerName: v.pipe(v.string(), v.regex(WORKER_NAME)),
  workerId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  versionId: v.pipe(v.string(), v.regex(UUID)),
  requestHash: sha256Schema,
  correlationTag: v.string(),
  namespaceId: v.optional(v.pipe(v.string(), v.regex(ACCOUNT_ID))),
});
const deploymentLocatorSchema = v.strictObject({
  kind: v.literal('deployment'),
  phase: v.picklist(['provision', 'bootstrap', 'clean']),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  workerName: v.pipe(v.string(), v.regex(WORKER_NAME)),
  workerId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  versionId: v.pipe(v.string(), v.regex(UUID)),
  deploymentId: v.pipe(v.string(), v.regex(UUID)),
  requestHash: sha256Schema,
  correlationTag: v.string(),
});
const subdomainLocatorSchema = v.strictObject({ enabled: v.boolean(), previewsEnabled: v.literal(false) });
const bootstrapRecoveryLocatorSchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: v.literal('recovery_required'),
  reason: v.picklist([
    'bootstrap_recovery_required',
    'bootstrap_requires_repair',
    'bootstrap_request_mismatch',
  ]),
  canRetry: v.literal(false),
});
const bootstrapReadyLocatorSchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: v.literal('ready'),
  installationId: v.pipe(v.string(), v.regex(INSTALLATION_ID)),
  approvedPlanId: v.pipe(v.string(), v.regex(CUSTOMER_PLAN_ID)),
  configurationHash: v.pipe(v.string(), v.regex(PREFIXED_SHA256)),
  desiredHash: v.pipe(v.string(), v.regex(PREFIXED_SHA256)),
  settingsRevision: v.literal(1),
  release: v.strictObject({ id: v.string(), artifactSha256: v.pipe(v.string(), v.regex(PREFIXED_SHA256)) }),
  gateway: v.strictObject({ hostname: v.string(), mcpUrl: v.string() }),
  receipt: v.strictObject({
    revision: safeIntegerSchema,
    resourceCount: v.union([v.literal(4), v.literal(7)]),
    evidence: boundaryValueSchema,
  }),
  applyInvoked: v.boolean(),
  resumed: v.boolean(),
});
const domainLocatorSchema = v.strictObject({
  domainId: v.pipe(v.string(), v.regex(/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$/u)),
});
const installJournalLeaseSchema = v.strictObject({
  attemptId: attemptIdSchema,
  acquiredAt: safeIntegerSchema,
  expiresAt: safeIntegerSchema,
});
const installJournalApprovalSchema = v.strictObject({
  schemaVersion: v.literal(1),
  attemptId: attemptIdSchema,
  approvedAt: safeIntegerSchema,
  recordedAt: safeIntegerSchema,
  planId: v.string(),
  planHash: v.string(),
  planExpiresAt: safeIntegerSchema,
  managementOwnershipMarker: v.string(),
});
const installJournalActionSchema = v.strictObject({
  name: v.lazy(() => installActionNameSchema),
  phase: installActionPhaseSchema,
  record: boundaryValueSchema,
  locator: boundaryValueSchema,
  preparedAt: safeIntegerSchema,
  sendArmedAt: v.nullable(safeIntegerSchema),
  submittedAt: v.nullable(safeIntegerSchema),
  verifiedAt: v.nullable(safeIntegerSchema),
});
const installJournalSchema = v.strictObject({
  schemaVersion: v.literal(1),
  revision: safeIntegerSchema,
  createdAt: safeIntegerSchema,
  updatedAt: safeIntegerSchema,
  sessionExpiresAt: safeIntegerSchema,
  recoverUntil: safeIntegerSchema,
  selection: boundaryValueSchema,
  plan: boundaryValueSchema,
  releasePin: boundaryValueSchema,
  target: boundaryValueSchema,
  installationId: installationIdSchema,
  bindingHash: prefixedSha256Schema,
  approvalHistory: v.pipe(v.array(installJournalApprovalSchema), v.minLength(1), v.maxLength(MAX_APPROVALS)),
  lease: v.nullable(installJournalLeaseSchema),
  leaseAttemptIds: v.pipe(v.array(attemptIdSchema), v.maxLength(MAX_LEASE_ATTEMPTS)),
  actions: v.pipe(v.array(installJournalActionSchema), v.maxLength(15)),
});
const createInstallJournalSchema = v.strictObject({
  schemaVersion: v.literal(1),
  now: safeIntegerSchema,
  recoverUntil: safeIntegerSchema,
  selection: boundaryValueSchema,
  plan: boundaryValueSchema,
  releasePin: boundaryValueSchema,
  target: boundaryValueSchema,
  installationId: installationIdSchema,
  bindingHash: prefixedSha256Schema,
  gatewayFreshPreflight: boundaryValueSchema,
});
const appendCustomerBootstrapAttemptSchema = v.strictObject({
  requestId: v.pipe(v.string(), v.regex(REQUEST_ID)),
  issuedAt: safeIntegerSchema,
  expiresAt: safeIntegerSchema,
  claimHash: prefixedSha256Schema,
  enableRequestHash: sha256Schema,
});

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

const installActionNameSchema = v.picklist(INSTALL_ACTION_ORDER);
const publicInstallProgressSchema = v.strictObject({
  schemaVersion: v.literal(1),
  revision: safeIntegerSchema,
  updatedAt: safeIntegerSchema,
  actions: v.pipe(v.array(v.strictObject({
    name: installActionNameSchema,
    phase: installActionPhaseSchema,
    updatedAt: safeIntegerSchema,
  })), v.maxLength(INSTALL_ACTION_ORDER.length)),
});

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

export function parsePublicInstallProgress<Input>(value: Input): PublicInstallProgress | null {
  if (value === null) return null;
  const candidate = v.safeParse(publicInstallProgressSchema, value);
  if (!candidate.success) invalid();
  const actions: PublicInstallProgressAction[] = [];
  for (let index = 0; index < candidate.output.actions.length; index += 1) {
    const action = candidate.output.actions[index];
    if (!action || action.name !== INSTALL_ACTION_ORDER[index] ||
      action.updatedAt > candidate.output.updatedAt) {
      invalid();
    }
    actions.push(Object.freeze({
      name: action.name,
      phase: action.phase,
      updatedAt: action.updatedAt,
    }));
  }
  return Object.freeze({
    schemaVersion: 1,
    revision: candidate.output.revision,
    updatedAt: candidate.output.updatedAt,
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
  'ANKKA_INSTALL_ID',
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

function isRecord<Value>(value: Value): value is Value & BoundaryObject {
  return v.is(boundaryObjectSchema, value);
}

function exactKeys<Value extends object>(value: Value, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

function exactJson<Left, Right>(left: Left, right: Right): boolean {
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

function safeInteger<Value>(value: Value): value is Value & number {
  return v.is(safeIntegerSchema, value);
}

function containsForbiddenJournalData<Value>(value: Value): boolean {
  if (value instanceof Uint8Array || value instanceof ArrayBuffer || value instanceof Blob) return true;
  if (Array.isArray(value)) return value.some(containsForbiddenJournalData);
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
    if (containsForbiddenJournalData(child)) return true;
  }
  return false;
}

function releasePin<Value>(value: Value): InstallReleasePin | null {
  const candidate = v.safeParse(releasePinSchema, value);
  if (!candidate.success) return null;
  return Object.freeze({
    verification: 'ed25519',
    keyId: candidate.output.keyId,
    release: candidate.output.release,
    artifactSha256: candidate.output.artifactSha256,
  });
}

function authorizedTarget<Value>(value: Value, selection: DeploySelection): AuthorizedTarget | null {
  const candidate = v.safeParse(authorizedTargetSchema, value);
  if (!candidate.success || candidate.output.actor.email !== selection.basics.adminEmail ||
    candidate.output.zone.name !== selection.basics.zoneName) return null;
  return Object.freeze({
    actor: Object.freeze({ id: candidate.output.actor.id, email: candidate.output.actor.email }),
    account: Object.freeze({ id: candidate.output.account.id, name: candidate.output.account.name }),
    zone: Object.freeze({ id: candidate.output.zone.id, name: candidate.output.zone.name, status: 'active' }),
  });
}

function managementWorkerName(plan: StaticDeployPlan): string | null {
  const values = plan.managementResources.filter((resource) => resource.kind === 'management_worker');
  const worker = values.at(0);
  return values.length === 1 && worker !== undefined && WORKER_NAME.test(worker.name) ? worker.name : null;
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

async function parseFreshPreflightRecord<Input>(
  value: Input,
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

async function parseWorkerRecord<Input>(value: Input, journal: InstallJournal): Promise<WorkerCreateRecord | null> {
  const candidate = v.safeParse(workerCreateRecordSchema, value);
  if (!candidate.success) return null;
  const record = candidate.output;
  const workerName = managementWorkerName(journal.plan);
  if (
    record.accountId !== journal.target.account.id || record.workerName !== workerName ||
    record.correlationTag !== `ankka-worker-sha256:${record.requestHash}`
  ) return null;
  const core = {
    logpush: false,
    name: workerName,
    observability: { enabled: false },
    subdomain: { enabled: false, previews_enabled: false },
    tags: ['ankka-mcp-gateway'],
    tail_consumers: [],
  };
  if (await sha256Hex(canonicalJson(core)) !== record.requestHash) return null;
  return Object.freeze({
    schemaVersion: 1,
    kind: 'worker_create',
    accountId: record.accountId,
    workerName: record.workerName,
    requestHash: record.requestHash,
    correlationTag: record.correlationTag,
  });
}

function canonicalProviderIds<Value>(value: Value): readonly string[] | null {
  const candidate = v.safeParse(
    v.pipe(v.array(providerIdSchema), v.minLength(1), v.maxLength(MAX_IDENTITY_PROVIDERS)),
    value,
  );
  if (!candidate.success) return null;
  const sorted = [...candidate.output].sort();
  if (sorted.some((id, index) => index > 0 && id === sorted[index - 1])) return null;
  if (!candidate.output.every((id, index) => id === sorted[index])) return null;
  return Object.freeze(sorted);
}

async function parseApplicationRecord<Input>(
  value: Input,
  journal: InstallJournal,
): Promise<ManagementAccessApplicationCreateRecord | null> {
  const candidate = v.safeParse(applicationCreateRecordSchema, value);
  if (!candidate.success) return null;
  const record = candidate.output;
  const ids = canonicalProviderIds(record.allowedIdentityProviderIds);
  if (
    record.accountId !== journal.target.account.id || record.planId !== journal.plan.planId ||
    record.planHash !== journal.plan.planHash || record.ownershipMarker !== managementOwnershipMarker(journal.plan) ||
    !ids
  ) return null;
  try {
    const intent = prepareManagementAccessApplicationIntent({
      accountId: journal.target.account.id,
      zoneId: journal.target.zone.id,
      plan: journal.plan,
      allowedIdentityProviderIds: ids,
    });
    if (await sha256Hex(canonicalJson(intent)) !== record.intentHash) return null;
  } catch {
    return null;
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: 'management_access_application_create',
    accountId: record.accountId,
    planId: record.planId,
    planHash: record.planHash,
    ownershipMarker: record.ownershipMarker,
    allowedIdentityProviderIds: ids,
    intentHash: record.intentHash,
  });
}

async function parsePolicyRecord<Input>(
  value: Input,
  journal: InstallJournal,
): Promise<ManagementAdminPolicyCreateRecord | null> {
  const candidate = v.safeParse(policyCreateRecordSchema, value);
  if (!candidate.success) return null;
  const record = candidate.output;
  const application = verifiedLocator(journal, 'management_access_application_create');
  const applicationId = application && 'applicationId' in application ? application.applicationId : null;
  if (applicationId === null) return null;
  if (
    record.accountId !== journal.target.account.id || record.planId !== journal.plan.planId ||
    record.planHash !== journal.plan.planHash || record.ownershipMarker !== managementOwnershipMarker(journal.plan) ||
    record.applicationId !== applicationId
  ) return null;
  try {
    const intent = prepareManagementAdminPolicyIntent({
      accountId: journal.target.account.id,
      zoneId: journal.target.zone.id,
      applicationId,
      plan: journal.plan,
    });
    if (await sha256Hex(canonicalJson(intent)) !== record.intentHash) return null;
  } catch {
    return null;
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: 'management_admin_policy_create',
    accountId: record.accountId,
    planId: record.planId,
    planHash: record.planHash,
    ownershipMarker: record.ownershipMarker,
    applicationId,
    intentHash: record.intentHash,
  });
}

function workerLocator(journal: InstallJournal): WorkerLocator | null {
  const locator = verifiedLocator(journal, 'worker_create');
  return locator && 'kind' in locator && locator.kind === 'worker' ? locator : null;
}

async function parseVersionRecord(
  name: InstallActionName,
  value: BoundaryValue,
  journal: InstallJournal,
): Promise<WorkerVersionCreateRecord | null> {
  const candidate = v.safeParse(workerVersionCreateRecordShellSchema, value);
  if (!candidate.success) return null;
  const record = candidate.output;
  const phase = expectedPhase(name);
  const worker = workerLocator(journal);
  if (
    !phase || record.phase !== phase || record.accountId !== journal.target.account.id ||
    record.workerName !== managementWorkerName(journal.plan) || record.workerId !== worker?.workerId
  ) return null;
  const parsed = await parseWorkerVersionRecoveryRecord({
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
  value: BoundaryValue,
  journal: InstallJournal,
): Promise<WorkerDeploymentCreateRecord | null> {
  const candidate = v.safeParse(workerDeploymentCreateRecordSchema, value);
  if (!candidate.success) return null;
  const record = candidate.output;
  const phase = expectedPhase(name);
  const version = phase ? versionLocator(journal, phase) : null;
  if (
    !phase || record.phase !== phase || record.accountId !== journal.target.account.id ||
    record.workerName !== version?.workerName || record.workerId !== version?.workerId ||
    record.versionId !== version?.versionId ||
    record.correlationTag !== `ankka-deploy-${phase}-sha256:${record.requestHash}`
  ) return null;
  const core = { strategy: 'percentage', versions: [{ percentage: 100, version_id: record.versionId }] };
  if (await sha256Hex(canonicalJson(core)) !== record.requestHash) return null;
  return Object.freeze({
    schemaVersion: 1,
    kind: 'worker_deployment_create',
    phase,
    accountId: record.accountId,
    workerName: record.workerName,
    workerId: record.workerId,
    versionId: record.versionId,
    requestHash: record.requestHash,
    correlationTag: record.correlationTag,
  });
}

async function parseSubdomainRecord(
  name: InstallActionName,
  value: BoundaryValue,
  journal: InstallJournal,
): Promise<BootstrapSubdomainRecord | null> {
  const candidate = v.safeParse(bootstrapSubdomainRecordSchema, value);
  if (!candidate.success) return null;
  const record = candidate.output;
  const enabled = name === 'bootstrap_subdomain_enable' ? true : name === 'bootstrap_subdomain_disable' ? false : null;
  if (
    enabled === null || record.accountId !== journal.target.account.id ||
    record.workerName !== managementWorkerName(journal.plan) || record.enabled !== enabled ||
    await sha256Hex(canonicalJson({ enabled, previews_enabled: false })) !== record.requestHash
  ) return null;
  return Object.freeze({
    schemaVersion: 1,
    kind: 'bootstrap_subdomain',
    accountId: record.accountId,
    workerName: record.workerName,
    enabled,
    requestHash: record.requestHash,
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
  value: BoundaryValue,
  enabled: boolean,
  journal: InstallJournal,
): Promise<CustomerBootstrapCycleSubdomainMutation | null> {
  const candidate = v.safeParse(cycleSubdomainMutationSchema, value);
  if (!candidate.success) return null;
  const mutation = candidate.output;
  const phase = mutation.phase;
  const approval = journal.approvalHistory.find((entry) => entry.attemptId === mutation.approvalAttemptId);
  const armed = phase !== 'prepared';
  const submitted = phase === 'submitted' || phase === 'verified';
  const verified = phase === 'verified';
  if (
    !approval || mutation.enabled !== enabled ||
    await sha256Hex(canonicalJson({ enabled, previews_enabled: false })) !== mutation.requestHash ||
    mutation.preparedAt < approval.approvedAt || mutation.preparedAt > journal.updatedAt ||
    (armed !== (mutation.sendArmedAt !== null)) ||
    (submitted !== (mutation.submittedAt !== null)) ||
    (verified !== (mutation.verifiedAt !== null)) ||
    (mutation.sendArmedAt !== null && mutation.sendArmedAt < mutation.preparedAt) ||
    (mutation.submittedAt !== null && mutation.sendArmedAt !== null &&
      mutation.submittedAt < mutation.sendArmedAt) ||
    (mutation.verifiedAt !== null && mutation.submittedAt !== null &&
      mutation.verifiedAt < mutation.submittedAt) ||
    [mutation.sendArmedAt, mutation.submittedAt, mutation.verifiedAt].some(
      (time) => time !== null && time > journal.updatedAt,
    )
  ) return null;
  let locator: BootstrapSubdomainLocator | null = null;
  if (submitted) {
    if (!mutation.locator || mutation.locator.enabled !== enabled) return null;
    locator = Object.freeze({ enabled, previewsEnabled: false });
  } else if (mutation.locator !== null) return null;
  return Object.freeze({
    schemaVersion: 1,
    approvalAttemptId: approval.attemptId,
    enabled,
    requestHash: mutation.requestHash,
    phase,
    locator,
    preparedAt: mutation.preparedAt,
    sendArmedAt: mutation.sendArmedAt,
    submittedAt: mutation.submittedAt,
    verifiedAt: mutation.verifiedAt,
  });
}

async function parseBootstrapRecord<Input>(
  value: Input,
  journal: InstallJournal,
): Promise<CustomerBootstrapSubmitRecord | null> {
  const candidate = v.safeParse(bootstrapSubmitRecordSchema, value);
  if (!candidate.success) return null;
  const record = candidate.output;
  const preflight = actionByName(journal, 'gateway_fresh_preflight');
  if (
    record.accountId !== journal.target.account.id || record.zoneId !== journal.target.zone.id ||
    record.zoneName !== journal.target.zone.name || record.installationId !== journal.installationId ||
    preflight?.phase !== 'verified' || preflight.record.kind !== 'customer_gateway_fresh_preflight' ||
    record.configurationHash !== preflight.record.configurationHash || record.desiredHash !== preflight.record.desiredHash
  ) return null;
  const semantic = Object.freeze({
    schemaVersion: 1,
    kind: 'customer_bootstrap_submit' as const,
    accountId: record.accountId,
    zoneId: record.zoneId,
    zoneName: record.zoneName,
    accountWorkersSubdomain: record.accountWorkersSubdomain,
    installationId: record.installationId,
    configurationHash: record.configurationHash,
    desiredHash: record.desiredHash,
  });
  const attempts: CustomerBootstrapRequestAttempt[] = [];
  for (let index = 0; index < record.attempts.length; index += 1) {
    const input = record.attempts[index];
    if (!input) return null;
    const approval = journal.approvalHistory.find((entry) => entry.attemptId === input.approvalAttemptId);
    const prior = attempts[index - 1];
    const enable = await parseCycleSubdomainMutation(input.enable, true, journal);
    const disable = input.disable === null ? null : await parseCycleSubdomainMutation(input.disable, false, journal);
    if (
      !approval || !enable ||
      enable.approvalAttemptId !== input.approvalAttemptId ||
      attempts.some((attempt) => attempt.approvalAttemptId === input.approvalAttemptId) ||
      attempts.some((attempt) => attempt.requestId === input.requestId) ||
      input.expiresAt <= input.issuedAt ||
      input.expiresAt - input.issuedAt > 5 * 60 || input.expiresAt > Math.floor(approval.planExpiresAt / 1_000) ||
      input.preparedAt < approval.approvedAt || input.preparedAt > journal.updatedAt ||
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
        enable.verifiedAt === null || disable.preparedAt < enable.verifiedAt
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
    const phase = input.phase;
    const armed = phase !== 'prepared';
    const submitted = phase === 'submitted' || phase === 'verified';
    const verified = phase === 'verified';
    if (
      (armed !== (input.sendArmedAt !== null)) ||
      (submitted !== (input.submittedAt !== null)) ||
      (verified !== (input.verifiedAt !== null)) ||
      (input.sendArmedAt !== null && input.sendArmedAt < input.preparedAt) ||
      (input.submittedAt !== null && input.sendArmedAt !== null && input.submittedAt < input.sendArmedAt) ||
      (input.verifiedAt !== null && input.submittedAt !== null && input.verifiedAt < input.submittedAt) ||
      [input.sendArmedAt, input.submittedAt, input.verifiedAt].some(
        (time) => time !== null && time > journal.updatedAt,
      ) ||
      await bootstrapClaimHash(semantic, input) !== input.claimHash
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
      sendArmedAt: input.sendArmedAt,
      submittedAt: input.submittedAt,
      verifiedAt: input.verifiedAt,
    }));
  }
  return Object.freeze({
    ...semantic,
    attempts: Object.freeze(attempts),
  });
}

async function parseDomainRecord(
  value: BoundaryValue,
  journal: InstallJournal,
): Promise<ManagementCustomDomainAttachRecord | null> {
  const candidate = v.safeParse(managementCustomDomainRecordSchema, value);
  if (!candidate.success) return null;
  const record = candidate.output;
  if (
    record.accountId !== journal.target.account.id || record.zoneId !== journal.target.zone.id ||
    record.planId !== journal.plan.planId || record.planHash !== journal.plan.planHash ||
    record.ownershipMarker !== managementOwnershipMarker(journal.plan)
  ) return null;
  try {
    const intent = prepareManagementCustomDomainIntent({
      accountId: journal.target.account.id,
      zoneId: journal.target.zone.id,
      plan: journal.plan,
    });
    if (await sha256Hex(canonicalJson(intent)) !== record.intentHash) return null;
  } catch {
    return null;
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: 'management_custom_domain_attach',
    accountId: record.accountId,
    zoneId: record.zoneId,
    planId: record.planId,
    planHash: record.planHash,
    ownershipMarker: record.ownershipMarker,
    intentHash: record.intentHash,
  });
}

type FinalConvergenceProjection = Omit<FinalConvergenceLocator, 'schemaVersion' | 'status' | 'convergenceHash'>;

function finalProjection(journal: InstallJournal): FinalConvergenceProjection | null {
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
  if (!bootstrapVersion.namespaceId || bootstrapVersion.namespaceId !== cleanVersion.namespaceId) return null;
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
  const locator: FinalConvergenceLocator = Object.freeze({
    schemaVersion: 1,
    status: 'converged',
    convergenceHash,
    ...projection,
  });
  const existing = journal.actions[finalIndex];
  if (existing && (
    existing.name !== 'final_convergence' || !exactJson(existing.record, record) ||
    ((existing.phase === 'submitted' || existing.phase === 'verified')
      ? !exactJson(existing.locator, locator)
      : existing.locator !== null)
  )) conflict();
  return Object.freeze({ record, locator });
}

async function parseFinalRecord(value: BoundaryValue, journal: InstallJournal): Promise<FinalConvergenceRecord | null> {
  const candidate = v.safeParse(finalConvergenceRecordSchema, value);
  if (!candidate.success) return null;
  const expected = await expectedConvergenceHash(journal);
  if (candidate.output.convergenceHash !== expected) return null;
  return Object.freeze({
    schemaVersion: 1,
    kind: 'final_convergence',
    convergenceHash: candidate.output.convergenceHash,
  });
}

async function parseActionRecord<Input>(
  name: InstallActionName,
  value: Input,
  journal: InstallJournal,
): Promise<InstallActionRecord | null> {
  if (containsForbiddenJournalData(value)) return null;
  const candidate = v.safeParse(boundaryValueSchema, value);
  if (!candidate.success) return null;
  const record = candidate.output;
  if (name === 'gateway_fresh_preflight') return parseFreshPreflightRecord(record, journal);
  if (name === 'worker_create') return parseWorkerRecord(record, journal);
  if (name === 'management_access_application_create') return parseApplicationRecord(record, journal);
  if (name === 'management_admin_policy_create') return parsePolicyRecord(record, journal);
  if (
    name === 'provision_worker_version_create' || name === 'bootstrap_worker_version_create' ||
    name === 'clean_worker_version_create'
  ) {
    return parseVersionRecord(name, record, journal);
  }
  if (
    name === 'provision_worker_deployment_create' || name === 'bootstrap_worker_deployment_create' ||
    name === 'clean_worker_deployment_create'
  ) {
    return parseDeploymentRecord(name, record, journal);
  }
  if (name === 'bootstrap_subdomain_enable' || name === 'bootstrap_subdomain_disable') {
    return parseSubdomainRecord(name, record, journal);
  }
  if (name === 'customer_bootstrap_submit') return parseBootstrapRecord(record, journal);
  if (name === 'management_custom_domain_attach') return parseDomainRecord(record, journal);
  if (name === 'final_convergence') return parseFinalRecord(record, journal);
  return null;
}

function parseWorkerLocator<Input>(value: Input, record: WorkerCreateRecord): WorkerLocator | null {
  const candidate = v.safeParse(workerLocatorSchema, value);
  if (!candidate.success) return null;
  if (
    candidate.output.accountId !== record.accountId || candidate.output.workerName !== record.workerName
  ) return null;
  return Object.freeze({
    kind: 'worker',
    accountId: record.accountId,
    workerName: record.workerName,
    workerId: candidate.output.workerId,
  });
}

function parseFreshPreflightLocator<Input>(
  value: Input,
  record: GatewayFreshPreflightRecord,
): GatewayFreshPreflightLocator | null {
  if (
    !v.is(freshPreflightLocatorSchema, value) || value.attestationHash !== record.attestationHash
  ) return null;
  return Object.freeze({ attestationHash: record.attestationHash });
}

function parseApplicationLocator<Input>(value: Input): ManagementAccessApplicationLocator | null {
  const candidate = v.safeParse(applicationLocatorSchema, value);
  return candidate.success ? Object.freeze(candidate.output) : null;
}

function parsePolicyLocator<Input>(value: Input): ManagementAdminPolicyLocator | null {
  const candidate = v.safeParse(policyLocatorSchema, value);
  return candidate.success ? Object.freeze(candidate.output) : null;
}

function parseVersionLocator<Input>(value: Input, record: WorkerVersionCreateRecord): WorkerVersionLocator | null {
  const candidate = v.safeParse(versionLocatorSchema, value);
  if (!candidate.success) return null;
  const locator = candidate.output;
  if (
    locator.phase !== record.phase || locator.accountId !== record.accountId ||
    locator.workerName !== record.workerName || locator.workerId !== record.workerId ||
    (record.phase === 'provision' ? locator.namespaceId !== undefined : locator.namespaceId === undefined) ||
    locator.requestHash !== record.requestHash || locator.correlationTag !== record.correlationTag
  ) return null;
  if (record.phase === 'provision') {
    return Object.freeze({
      kind: 'version', phase: record.phase, accountId: record.accountId, workerName: record.workerName,
      workerId: record.workerId, versionId: locator.versionId, requestHash: record.requestHash,
      correlationTag: record.correlationTag,
    });
  }
  if (!locator.namespaceId) return null;
  return Object.freeze({
    kind: 'version', phase: record.phase, accountId: record.accountId, workerName: record.workerName,
    workerId: record.workerId, versionId: locator.versionId, requestHash: record.requestHash,
    correlationTag: record.correlationTag,
    namespaceId: locator.namespaceId,
  });
}

function parseDeploymentLocator<Input>(value: Input, record: WorkerDeploymentCreateRecord): WorkerDeploymentLocator | null {
  const candidate = v.safeParse(deploymentLocatorSchema, value);
  if (!candidate.success) return null;
  const locator = candidate.output;
  if (
    locator.phase !== record.phase || locator.accountId !== record.accountId ||
    locator.workerName !== record.workerName || locator.workerId !== record.workerId ||
    locator.versionId !== record.versionId || locator.requestHash !== record.requestHash ||
    locator.correlationTag !== record.correlationTag
  ) return null;
  return Object.freeze({
    kind: 'deployment', phase: record.phase, accountId: record.accountId, workerName: record.workerName,
    workerId: record.workerId, versionId: record.versionId, deploymentId: locator.deploymentId,
    requestHash: record.requestHash, correlationTag: record.correlationTag,
  });
}

function parseSubdomainLocator<Input>(value: Input, record: BootstrapSubdomainRecord): BootstrapSubdomainLocator | null {
  const candidate = v.safeParse(subdomainLocatorSchema, value);
  if (!candidate.success || candidate.output.enabled !== record.enabled) return null;
  return Object.freeze({ enabled: record.enabled, previewsEnabled: false });
}

async function parseBootstrapLocator<Input>(
  value: Input,
  record: Omit<CustomerBootstrapSubmitRecord, 'attempts'>,
  journal: InstallJournal,
): Promise<CustomerBootstrapLocator | null> {
  const recovery = v.safeParse(bootstrapRecoveryLocatorSchema, value);
  if (recovery.success) {
    return Object.freeze({
      schemaVersion: 1,
      status: 'recovery_required',
      reason: recovery.output.reason,
      canRetry: false,
    });
  }
  const candidate = v.safeParse(bootstrapReadyLocatorSchema, value);
  if (!candidate.success) return null;
  const locator = candidate.output;
  if (
    locator.installationId !== journal.installationId || locator.configurationHash !== record.configurationHash ||
    locator.desiredHash !== record.desiredHash || locator.release.id !== journal.releasePin.release ||
    locator.release.artifactSha256 !== `sha256:${journal.releasePin.artifactSha256}` ||
    locator.gateway.hostname !== journal.selection.basics.portalHostname ||
    locator.gateway.mcpUrl !== `https://${journal.selection.basics.portalHostname}/mcp` ||
    locator.receipt.resourceCount !== journal.plan.gatewayResources.length
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
  const evidence = await parseReadyInstallationReceipt(locator.receipt.evidence, expectation);
  if (!evidence || evidence.revision !== locator.receipt.revision) return null;
  return Object.freeze({
    schemaVersion: 1,
    status: 'ready',
    installationId: journal.installationId,
    approvedPlanId: locator.approvedPlanId,
    configurationHash: record.configurationHash,
    desiredHash: record.desiredHash,
    settingsRevision: 1,
    release: Object.freeze({
      id: journal.releasePin.release,
      artifactSha256: `sha256:${journal.releasePin.artifactSha256}`,
    }),
    gateway: Object.freeze({ hostname: locator.gateway.hostname, mcpUrl: locator.gateway.mcpUrl }),
    receipt: Object.freeze({
      revision: locator.receipt.revision,
      resourceCount: locator.receipt.resourceCount,
      evidence,
    }),
    applyInvoked: locator.applyInvoked,
    resumed: locator.resumed,
  });
}

function parseDomainLocator<Input>(value: Input): ManagementCustomDomainLocator | null {
  const candidate = v.safeParse(domainLocatorSchema, value);
  return candidate.success ? Object.freeze(candidate.output) : null;
}

async function parseFinalLocator<Input>(value: Input, record: FinalConvergenceRecord, journal: InstallJournal): Promise<FinalConvergenceLocator | null> {
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
  const expected: FinalConvergenceLocator | null = projection ? {
    schemaVersion: 1,
    status: 'converged',
    convergenceHash: expectedHash,
    ...projection,
  } : null;
  if (!expected || !exactJson(value, expected)) return null;
  return Object.freeze(expected);
}

async function parseActionLocator<Input>(
  name: InstallActionName,
  value: Input,
  record: InstallActionRecord,
  journal: InstallJournal,
): Promise<InstallActionLocator | null> {
  if (containsForbiddenJournalData(value)) return null;
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

function parseLease<Input>(value: Input, recoverUntil: number): InstallJournalLease | null | undefined {
  if (value === null) return null;
  const candidate = v.safeParse(installJournalLeaseSchema, value);
  if (!candidate.success) return undefined;
  const lease = candidate.output;
  if (
    lease.expiresAt <= lease.acquiredAt || lease.expiresAt - lease.acquiredAt > MAX_INSTALL_LEASE_MS ||
    lease.expiresAt > recoverUntil
  ) return undefined;
  return Object.freeze({ attemptId: lease.attemptId, acquiredAt: lease.acquiredAt, expiresAt: lease.expiresAt });
}

function parseApprovalHistory<Input>(
  value: Input,
  plan: StaticDeployPlan,
  createdAt: number,
  updatedAt: number,
  recoverUntil: number,
): readonly InstallJournalApproval[] | null {
  const candidate = v.safeParse(
    v.pipe(v.array(installJournalApprovalSchema), v.minLength(1), v.maxLength(MAX_APPROVALS)),
    value,
  );
  if (!candidate.success) return null;
  const approvals: InstallJournalApproval[] = [];
  for (let index = 0; index < candidate.output.length; index += 1) {
    const entry = candidate.output[index];
    if (!entry) return null;
    const previous = approvals[index - 1];
    let invalidRecordedAt: boolean;
    let invalidPlanExpiry: boolean;
    if (index === 0) {
      invalidRecordedAt = entry.recordedAt !== createdAt;
      invalidPlanExpiry = entry.planExpiresAt !== plan.expiresAt;
    } else {
      if (previous === undefined) return null;
      invalidRecordedAt = entry.recordedAt < previous.recordedAt;
      invalidPlanExpiry = entry.planExpiresAt <= previous.planExpiresAt;
    }
    if (
      approvals.some((approval) => approval.attemptId === entry.attemptId) ||
      entry.approvedAt > entry.recordedAt ||
      entry.recordedAt > updatedAt || invalidRecordedAt ||
      entry.planId !== plan.planId || entry.planHash !== plan.planHash ||
      entry.managementOwnershipMarker !== plan.managementOwnershipMarker ||
      entry.planExpiresAt <= entry.approvedAt || entry.planExpiresAt > recoverUntil ||
      invalidPlanExpiry
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

async function parseJournal<Input>(value: Input): Promise<InstallJournal | null> {
  if (containsForbiddenJournalData(value)) return null;
  const candidate = v.safeParse(installJournalSchema, value);
  if (!candidate.success) return null;
  const journalInput = candidate.output;
  if (
    journalInput.updatedAt < journalInput.createdAt || journalInput.updatedAt > journalInput.recoverUntil ||
    journalInput.sessionExpiresAt <= journalInput.createdAt || journalInput.recoverUntil <= journalInput.sessionExpiresAt ||
    journalInput.recoverUntil > journalInput.sessionExpiresAt + MAX_INSTALL_RECOVERY_RETENTION_MS
  ) return null;
  let selection: DeploySelection;
  let plan: StaticDeployPlan;
  try {
    selection = parseDeploySelection(journalInput.selection);
    plan = parseStaticDeployPlan(journalInput.plan);
  } catch {
    return null;
  }
  const pin = releasePin(journalInput.releasePin);
  const target = authorizedTarget(journalInput.target, selection);
  if (
    !pin || !target || pin.release !== plan.releaseId || pin.artifactSha256 !== plan.releaseArtifactSha256 ||
    journalInput.installationId !== plan.managementOwnershipMarker
  ) return null;
  const expectedBinding = await computeInstallJournalBindingHash({
    selection, plan, releasePin: pin, target, installationId: journalInput.installationId,
  });
  if (journalInput.bindingHash !== expectedBinding) return null;
  const approvals = parseApprovalHistory(
    journalInput.approvalHistory,
    plan,
    journalInput.createdAt,
    journalInput.updatedAt,
    journalInput.recoverUntil,
  );
  if (!approvals) return null;
  const lease = parseLease(journalInput.lease, journalInput.recoverUntil);
  if (lease === undefined) return null;
  const attempts: string[] = [];
  for (const attempt of journalInput.leaseAttemptIds) {
    if (attempts.includes(attempt)) return null;
    attempts.push(attempt);
  }
  if (lease && !attempts.includes(lease.attemptId)) return null;
  if (journalInput.actions.length > INSTALL_ACTION_ORDER.length) return null;
  const partial: InstallJournal = {
    schemaVersion: 1,
    revision: journalInput.revision,
    createdAt: journalInput.createdAt,
    updatedAt: journalInput.updatedAt,
    sessionExpiresAt: journalInput.sessionExpiresAt,
    recoverUntil: journalInput.recoverUntil,
    selection,
    plan,
    releasePin: pin,
    target,
    installationId: journalInput.installationId,
    bindingHash: journalInput.bindingHash,
    approvalHistory: approvals,
    lease,
    leaseAttemptIds: Object.freeze(attempts),
    actions: Object.freeze([]),
  };
  const actions: InstallJournalAction[] = [];
  let lastPreparedAt = journalInput.createdAt;
  for (let index = 0; index < journalInput.actions.length; index += 1) {
    const input = journalInput.actions[index];
    if (!input) return null;
    const name = INSTALL_ACTION_ORDER[index];
    if (input.name !== name) return null;
    const context: InstallJournal = { ...partial, actions: Object.freeze([...actions]) };
    if (!actionPrerequisites(context, name)) return null;
    const record = await parseActionRecord(name, input.record, context);
    if (!record || input.preparedAt < lastPreparedAt || input.preparedAt > journalInput.updatedAt) return null;
    if (
      name === 'gateway_fresh_preflight' && (
        record.kind !== 'customer_gateway_fresh_preflight' || input.phase !== 'verified' ||
        input.preparedAt !== journalInput.createdAt || input.sendArmedAt !== journalInput.createdAt ||
        input.submittedAt !== journalInput.createdAt || input.verifiedAt !== journalInput.createdAt
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
    const phase = input.phase;
    const armedRequired = phase !== 'prepared';
    const submittedRequired = phase === 'submitted' || phase === 'verified';
    const verifiedRequired = phase === 'verified';
    if (
      (armedRequired !== (input.sendArmedAt !== null)) ||
      (submittedRequired !== (input.submittedAt !== null)) ||
      (verifiedRequired !== (input.verifiedAt !== null)) ||
      (input.sendArmedAt !== null && input.sendArmedAt < input.preparedAt) ||
      (input.submittedAt !== null && input.sendArmedAt !== null && input.submittedAt < input.sendArmedAt) ||
      (input.verifiedAt !== null && input.submittedAt !== null && input.verifiedAt < input.submittedAt) ||
      [input.sendArmedAt, input.submittedAt, input.verifiedAt].some(
        (time) => time !== null && time > journalInput.updatedAt,
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
      sendArmedAt: input.sendArmedAt,
      submittedAt: input.submittedAt,
      verifiedAt: input.verifiedAt,
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

export async function requireInstallJournal<Input>(value: Input): Promise<InstallJournal> {
  const parsed = await parseJournal(value);
  if (!parsed) invalid();
  return parsed;
}

export async function createInstallJournal<Input>(
  value: Input,
  sessionSelection: DeploySelection,
  sessionPlan: StaticDeployPlan,
  sessionExpiresAt: number,
  approval: { readonly attemptId: string; readonly approvedAt: number },
): Promise<InstallJournal> {
  if (containsForbiddenJournalData(value)) invalid(400);
  const candidate = v.safeParse(createInstallJournalSchema, value);
  if (!candidate.success) invalid(400);
  const journalInput = candidate.output;
  let selection: DeploySelection;
  let plan: StaticDeployPlan;
  try {
    selection = parseDeploySelection(journalInput.selection);
    plan = parseStaticDeployPlan(journalInput.plan);
  } catch {
    invalid(400);
  }
  const pin = releasePin(journalInput.releasePin);
  const target = authorizedTarget(journalInput.target, selection);
  if (
    journalInput.now >= sessionExpiresAt || journalInput.now >= plan.expiresAt ||
    !ATTEMPT_ID.test(approval.attemptId) ||
    !safeInteger(approval.approvedAt) || approval.approvedAt > journalInput.now || approval.approvedAt >= plan.expiresAt ||
    journalInput.recoverUntil <= sessionExpiresAt ||
    journalInput.recoverUntil > sessionExpiresAt + MAX_INSTALL_RECOVERY_RETENTION_MS ||
    !exactJson(selection, sessionSelection) || !exactJson(plan, sessionPlan) || !pin || !target ||
    pin.release !== plan.releaseId || pin.artifactSha256 !== plan.releaseArtifactSha256 ||
    journalInput.installationId !== plan.managementOwnershipMarker
  ) invalid(400);
  const expectedBinding = await computeInstallJournalBindingHash({
    selection, plan, releasePin: pin, target, installationId: journalInput.installationId,
  });
  if (journalInput.bindingHash !== expectedBinding) invalid(400);
  const base: InstallJournal = {
    schemaVersion: 1,
    revision: 0,
    createdAt: journalInput.now,
    updatedAt: journalInput.now,
    sessionExpiresAt,
    recoverUntil: journalInput.recoverUntil,
    selection,
    plan,
    releasePin: pin,
    target,
    installationId: journalInput.installationId,
    bindingHash: journalInput.bindingHash,
    approvalHistory: Object.freeze([Object.freeze({
      schemaVersion: 1,
      attemptId: approval.attemptId,
      approvedAt: approval.approvedAt,
      recordedAt: journalInput.now,
      planId: plan.planId,
      planHash: plan.planHash,
      planExpiresAt: plan.expiresAt,
      managementOwnershipMarker: plan.managementOwnershipMarker,
    })]),
    lease: null,
    leaseAttemptIds: Object.freeze([]),
    actions: Object.freeze([]),
  };
  const preflight = await parseFreshPreflightRecord(journalInput.gatewayFreshPreflight, base);
  if (!preflight) invalid(400);
  const action: InstallJournalAction = Object.freeze({
    name: 'gateway_fresh_preflight',
    phase: 'verified',
    record: preflight,
    locator: Object.freeze({ attestationHash: preflight.attestationHash }),
    preparedAt: journalInput.now,
    sendArmedAt: journalInput.now,
    submittedAt: journalInput.now,
    verifiedAt: journalInput.now,
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
    !ATTEMPT_ID.test(input.attemptId) ||
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
      bootstrap !== undefined && bootstrapRecord && existingDisable?.phase === 'verified' && attempts.length > 1 && attempt &&
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
  const recordContext: InstallJournal = input.action === 'customer_bootstrap_submit'
    ? { ...journal, updatedAt: input.now }
    : journal;
  const record = await parseActionRecord(input.action, input.record, recordContext);
  if (!record) invalid(400);
  if (input.action === 'customer_bootstrap_submit' && record.kind === 'customer_bootstrap_submit') {
    const summary = bootstrapActionSummary(record);
    const firstAttempt = record.attempts.at(0);
    if (
      record.attempts.length !== 1 || summary.phase !== 'prepared' || summary.preparedAt !== input.now ||
      firstAttempt === undefined || firstAttempt.approvalAttemptId !== input.attemptId
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
      bootstrap !== undefined && bootstrapRecord && attempts.length > 1 && attempt?.enable.phase === 'prepared'
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
      bootstrap !== undefined && bootstrapRecord && attempt?.disable?.phase === 'prepared' &&
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
      bootstrap !== undefined && bootstrapRecord && attempts.length > 1 && attempt?.enable.phase === 'send_armed'
    ) {
      const workerName = managementWorkerName(journal.plan);
      if (!workerName) invalid(400);
      const locator = parseSubdomainLocator(input.locator, {
        schemaVersion: 1,
        kind: 'bootstrap_subdomain',
        accountId: journal.target.account.id,
        workerName,
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
      bootstrap !== undefined && bootstrapRecord && attempt?.disable?.phase === 'send_armed' &&
      attempt.disable.approvalAttemptId === input.attemptId
    ) {
      const workerName = managementWorkerName(journal.plan);
      if (!workerName) invalid(400);
      const locator = parseSubdomainLocator(input.locator, {
        schemaVersion: 1,
        kind: 'bootstrap_subdomain',
        accountId: journal.target.account.id,
        workerName,
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
      bootstrap !== undefined && bootstrapRecord && attempts.length > 1 && attempt?.enable.phase === 'submitted' &&
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
      bootstrap !== undefined && bootstrapRecord && attempt?.disable?.phase === 'submitted' && attempt.disable.locator?.enabled === false &&
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
    action.record.attempts.length >= MAX_BOOTSTRAP_ATTEMPTS
  ) conflict();
  const attemptCandidate = v.safeParse(appendCustomerBootstrapAttemptSchema, input.attempt);
  if (!attemptCandidate.success) conflict();
  const attemptInput = attemptCandidate.output;
  if (
    action.record.attempts.some((attempt) => attempt.approvalAttemptId === input.attemptId) ||
    action.record.attempts.some((attempt) => attempt.requestId === attemptInput.requestId)
  ) conflict();
  const nextAttempt: CustomerBootstrapRequestAttempt = {
    schemaVersion: 1,
    approvalAttemptId: input.attemptId,
    requestId: attemptInput.requestId,
    issuedAt: attemptInput.issuedAt,
    expiresAt: attemptInput.expiresAt,
    claimHash: attemptInput.claimHash,
    enable: {
      schemaVersion: 1,
      approvalAttemptId: input.attemptId,
      enabled: true,
      requestHash: attemptInput.enableRequestHash,
      phase: 'prepared',
      locator: null,
      preparedAt: input.now,
      sendArmedAt: null,
      submittedAt: null,
      verifiedAt: null,
    },
    disable: null,
    phase: 'prepared',
    locator: null,
    preparedAt: input.now,
    sendArmedAt: null,
    submittedAt: null,
    verifiedAt: null,
  };
  const candidate: CustomerBootstrapSubmitRecord = {
    ...action.record,
    attempts: [...action.record.attempts, nextAttempt],
  };
  const context: InstallJournal = { ...journal, updatedAt: input.now };
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
