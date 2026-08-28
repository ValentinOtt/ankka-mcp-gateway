import * as v from 'valibot';

import {
  boundaryObjectSchema,
  boundaryValueSchema,
  type BoundaryObject,
  type BoundaryValue,
} from './boundary';
import { canonicalJson } from './canonical-json';
import { CLOUDFLARE_API_ORIGIN } from './constants';
import {
  managementAccessApplicationName,
  managementAdminPolicyName,
  managementOwnershipMarker,
} from './cloudflare-management-surface';
import {
  type StaticDeployPlan,
} from './schema';
import {
  isCompleteInstallJournal,
  prepareFinalConvergenceRecordAndLocator,
  requireInstallJournal,
  type InstallJournal,
} from './install-journal';
import {
  buildStaticUninstallPlan,
  isRecoveryEquivalentUninstallPlan,
  parseStaticUninstallPlan,
  type StaticUninstallPlan,
} from './uninstall-plan';
import {
  parseAdminStateNamespaceRetirementProof,
  parseWorkerDeleteMutationIntent,
  parseWorkerDeletionRecoveryProof,
  recoverWorkerDeletionOutcome,
  type AdminStateNamespaceRetirementProof,
  type WorkerDeleteMutationIntent,
  type WorkerDeletionRecoveryProof,
} from './cloudflare-uninstall-worker-lifecycle';
import type { AuthorizedTarget } from './cloudflare-target';
import { sha256Hex as sha256 } from './crypto';
import { deepFreezePlainData as deepFreeze } from './plain-data';

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const PROVIDER_ID = /^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$/u;
const ACCESS_AUD = /^[A-Za-z0-9._~-]{16,512}$/u;
const TOKEN = /^[A-Za-z0-9._~-]{20,8192}$/u;
const ATTEMPT_ID = /^att_[A-Za-z0-9_-]{32}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const WORKER_CORRELATION = /^ankka-worker-sha256:[a-f0-9]{64}$/u;
const PLAN_HASH = /^sha256:[a-f0-9]{64}$/u;
const EMAIL = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/u;
const DNS_LABEL = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$/u;
const MAX_RESPONSE_BYTES = 128 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const PAGE_SIZE = 100;
const MAX_PAGES = 20;
const MAX_ITEMS = PAGE_SIZE * MAX_PAGES;
const MAX_UNINSTALL_APPROVALS = 16;
const PREFLIGHT_ATTESTATION_TTL_MS = 60_000;
const ACCESS_SESSION_DURATION = '24h';
const MANAGED_WORKER_TAG = 'ankka-mcp-gateway';
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;

const providerIdentifierSchema = v.pipe(v.string(), v.regex(PROVIDER_ID));
const workerCustomDomainIdSchema = v.pipe(v.string(), v.regex(
  /^(?:(?:[a-f0-9]{32})|(?:[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})|(?:[a-f0-9]{40}))$/u,
));
const rfc3339Schema = v.pipe(
  v.string(),
  v.minLength(20),
  v.maxLength(40),
  v.regex(RFC3339),
  v.check((value) => Number.isFinite(Date.parse(value))),
);
const emptyBoundaryArraySchema = v.pipe(v.array(boundaryValueSchema), v.length(0));
const optionalFalseSchema = v.optional(v.literal(false));
const accessApplicationObservationSchema = v.looseObject({
  id: providerIdentifierSchema,
  aud: v.pipe(v.string(), v.regex(ACCESS_AUD)),
  name: v.string(),
  type: v.literal('self_hosted'),
  domain: v.string(),
  session_duration: v.literal(ACCESS_SESSION_DURATION),
  app_launcher_visible: v.literal(false),
  auto_redirect_to_identity: v.literal(false),
  allow_authenticate_via_warp: v.literal(false),
  allowed_idps: v.array(providerIdentifierSchema),
});
const accessPolicyObservationSchema = v.looseObject({
  id: providerIdentifierSchema,
  name: v.string(),
  decision: v.literal('allow'),
  precedence: v.literal(1),
  approval_required: optionalFalseSchema,
  isolation_required: optionalFalseSchema,
  purpose_justification_required: optionalFalseSchema,
  include: v.array(v.strictObject({ email: v.strictObject({ email: v.string() }) })),
  exclude: emptyBoundaryArraySchema,
  require: emptyBoundaryArraySchema,
});
const customDomainObservationSchema = v.looseObject({
  id: workerCustomDomainIdSchema,
  cert_id: providerIdentifierSchema,
  hostname: v.string(),
  service: v.string(),
  zone_id: v.string(),
  zone_name: v.string(),
  environment: v.optional(v.literal('production')),
});
const disabledObservabilityDetailSchema = v.looseObject({
  enabled: optionalFalseSchema,
  destinations: v.optional(emptyBoundaryArraySchema),
});
const disabledWorkerObservabilitySchema = v.strictObject({
  enabled: v.literal(false),
  head_sampling_rate: v.optional(boundaryValueSchema),
  redact_query_string: optionalFalseSchema,
  logs: v.optional(disabledObservabilityDetailSchema),
  traces: v.optional(disabledObservabilityDetailSchema),
});
const workerReferenceSchema = v.strictObject({
  dispatch_namespace_outbounds: emptyBoundaryArraySchema,
  domains: v.pipe(v.array(v.strictObject({
    hostname: v.string(),
    id: workerCustomDomainIdSchema,
    zone_id: v.string(),
    zone_name: v.string(),
  })), v.length(1)),
  durable_objects: v.pipe(v.array(v.strictObject({
    worker_id: providerIdentifierSchema,
    worker_name: v.string(),
    namespace_id: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
    namespace_name: v.string(),
  })), v.length(1)),
  queues: emptyBoundaryArraySchema,
  workers: emptyBoundaryArraySchema,
});
const workerObservationSchema = v.strictObject({
  created_on: rfc3339Schema,
  deployed_on: rfc3339Schema,
  id: providerIdentifierSchema,
  logpush: v.literal(false),
  name: v.string(),
  observability: disabledWorkerObservabilitySchema,
  references: workerReferenceSchema,
  subdomain: v.strictObject({ enabled: v.literal(false), previews_enabled: v.literal(false) }),
  tags: v.array(v.string()),
  tail_consumers: emptyBoundaryArraySchema,
  updated_on: rfc3339Schema,
});
const routeObservationSchema = v.looseObject({
  id: providerIdentifierSchema,
  pattern: v.string(),
  script: v.optional(v.nullable(v.string())),
});
const singlePageInfoSchema = v.strictObject({
  count: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(0))),
  page: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(0))),
  per_page: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(0))),
  total_count: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(0))),
  total_pages: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(0))),
});

export const HOSTED_UNINSTALL_MANAGEMENT_DELETE_ORDER = Object.freeze([
  'management_custom_domain_delete',
  'management_admin_policy_delete',
  'management_access_application_delete',
] as const);

export type HostedUninstallManagementDeleteAction =
  (typeof HOSTED_UNINSTALL_MANAGEMENT_DELETE_ORDER)[number];

/**
 * Only these fields are safe to persist in the uninstall journal. In
 * particular, no bearer token, provider response, request body, or exception
 * text belongs in an intent or arm.
 */
export const HOSTED_UNINSTALL_MANAGEMENT_JOURNAL_ALLOWLIST = Object.freeze({
  intent: Object.freeze([
    'schemaVersion',
    'kind',
    'ordinal',
    'uninstallPlanId',
    'uninstallPlanHash',
    'uninstallAuthorityHash',
    'installBindingHash',
    'installConvergenceHash',
    'attemptId',
    'ownershipMarker',
    'accountId',
    'zoneId',
    'managementHostname',
    'workerName',
    'prerequisiteCommitments',
    'locator',
  ] as const),
  arm: Object.freeze([
    'schemaVersion',
    'kind',
    'action',
    'attemptId',
    'armedAt',
    'intentSha256',
  ] as const),
  locators: Object.freeze({
    management_custom_domain_delete: Object.freeze(['domainId'] as const),
    management_admin_policy_delete: Object.freeze(['applicationId', 'policyId'] as const),
    management_access_application_delete: Object.freeze(['applicationId', 'aud'] as const),
  }),
});

export type CloudflareUninstallManagementStage =
  | 'validate'
  | 'fresh_custom_domain_get'
  | 'fresh_custom_domain_list'
  | 'fresh_admin_policy_get'
  | 'fresh_admin_policy_list'
  | 'fresh_access_application_get'
  | 'fresh_access_application_list'
  | 'fresh_worker_get'
  | 'fresh_worker_list'
  | 'fresh_workers_dev_get'
  | 'fresh_dns_collision_list'
  | 'fresh_worker_route_list'
  | 'management_custom_domain_delete'
  | 'management_admin_policy_delete'
  | 'management_access_application_delete'
  | 'management_custom_domain_absence_get'
  | 'management_custom_domain_absence_list'
  | 'management_admin_policy_absence_get'
  | 'management_admin_policy_absence_list'
  | 'management_access_application_absence_get'
  | 'management_access_application_absence_list'
  | 'management_custom_domain_recovery_get'
  | 'management_custom_domain_recovery_list'
  | 'management_admin_policy_recovery_get'
  | 'management_admin_policy_recovery_list'
  | 'management_access_application_recovery_get'
  | 'management_access_application_recovery_list'
  | 'final_custom_domain_get'
  | 'final_custom_domain_list'
  | 'final_access_application_get'
  | 'final_access_application_list'
  | 'final_dns_list'
  | 'final_worker_route_list'
  | 'final_worker_delete_recovery'
  | 'final_namespace_list';

export type CloudflareUninstallManagementOutcome = 'not_sent' | 'rejected' | 'unknown';

export type CloudflareUninstallManagementErrorCode =
  | 'invalid_input'
  | 'provider_rejected'
  | 'provider_unknown'
  | 'provider_mismatch'
  | 'provider_ambiguous'
  | 'delete_not_converged'
  | 'replacement_detected'
  | 'management_residue';

export class CloudflareUninstallManagementError extends Error {
  readonly code: CloudflareUninstallManagementErrorCode;
  readonly stage: CloudflareUninstallManagementStage;
  readonly outcome: CloudflareUninstallManagementOutcome;
  readonly canRetry: false;

  constructor(
    code: CloudflareUninstallManagementErrorCode,
    stage: CloudflareUninstallManagementStage,
    outcome: CloudflareUninstallManagementOutcome,
  ) {
    super(code);
    this.name = 'CloudflareUninstallManagementError';
    this.code = code;
    this.stage = stage;
    this.outcome = outcome;
    this.canRetry = false;
  }
}

export type CloudflareUninstallManagementTransport = (request: Request) => Promise<Response>;

export interface CloudflareUninstallManagementCall {
  readonly accessToken: string;
  readonly transport: CloudflareUninstallManagementTransport;
  readonly timeoutMs?: number;
}

export interface HostedUninstallManagementContext {
  readonly schemaVersion: 1;
  readonly installJournal: InstallJournal;
  readonly approvalHistory: readonly {
    readonly attemptId: string;
    readonly uninstallPlan: StaticUninstallPlan;
    readonly authorizedTarget: AuthorizedTarget;
  }[];
  readonly activeAttemptId: string;
}

interface BaseDeleteIntent {
  readonly schemaVersion: 1;
  readonly ordinal: 0 | 1 | 2;
  readonly uninstallPlanId: string;
  readonly uninstallPlanHash: string;
  readonly uninstallAuthorityHash: string;
  readonly installBindingHash: string;
  readonly installConvergenceHash: string;
  readonly attemptId: string;
  readonly ownershipMarker: string;
  readonly accountId: string;
  readonly zoneId: string;
  readonly managementHostname: string;
  readonly workerName: string;
  readonly prerequisiteCommitments: readonly string[];
}

export type HostedUninstallManagementDeleteIntent =
  | (BaseDeleteIntent & {
      readonly kind: 'management_custom_domain_delete';
      readonly ordinal: 0;
      readonly locator: { readonly domainId: string };
    })
  | (BaseDeleteIntent & {
      readonly kind: 'management_admin_policy_delete';
      readonly ordinal: 1;
      readonly locator: { readonly applicationId: string; readonly policyId: string };
    })
  | (BaseDeleteIntent & {
      readonly kind: 'management_access_application_delete';
      readonly ordinal: 2;
      readonly locator: { readonly applicationId: string; readonly aud: string };
    });

export interface HostedUninstallManagementDeleteArm {
  readonly schemaVersion: 1;
  readonly kind: 'management_delete_arm';
  readonly action: HostedUninstallManagementDeleteAction;
  readonly attemptId: string;
  readonly armedAt: number;
  readonly intentSha256: string;
}

export interface HostedUninstallManagementDeleteSubmission {
  readonly schemaVersion: 1;
  readonly status: 'submitted';
  readonly action: HostedUninstallManagementDeleteAction;
  readonly attemptId: string;
  readonly intentSha256: string;
  readonly locator: HostedUninstallManagementDeleteIntent['locator'];
}

export interface HostedUninstallManagementAbsenceEvidence {
  readonly schemaVersion: 1;
  readonly status: 'absent';
  readonly action: HostedUninstallManagementDeleteAction;
  readonly uninstallPlanId: string;
  readonly uninstallPlanHash: string;
  readonly uninstallAuthorityHash: string;
  readonly installBindingHash: string;
  readonly installConvergenceHash: string;
  readonly attemptId: string;
  readonly ownershipMarker: string;
  readonly accountId: string;
  readonly locator: HostedUninstallManagementDeleteIntent['locator'];
  readonly proof: 'id_get_404_and_complete_list_absence';
  readonly evidenceSha256: string;
}

export type HostedUninstallManagementProviderOwnership =
  | {
      readonly kind: 'management_custom_domain';
      readonly domainId: string;
      readonly certificateId: string;
      readonly hostname: string;
      readonly workerName: string;
      readonly zoneId: string;
      readonly zoneName: string;
    }
  | {
      readonly kind: 'management_admin_policy';
      readonly applicationId: string;
      readonly policyId: string;
      readonly name: string;
      readonly adminEmails: readonly string[];
    }
  | {
      readonly kind: 'management_access_application';
      readonly applicationId: string;
      readonly aud: string;
      readonly name: string;
      readonly hostname: string;
      readonly allowedIdentityProviderIds: readonly string[];
    };

export interface HostedUninstallManagementStillPresentEvidence {
  readonly schemaVersion: 1;
  readonly status: 'still_present';
  readonly outcome: 'not_applied';
  readonly action: HostedUninstallManagementDeleteAction;
  readonly uninstallPlanId: string;
  readonly uninstallPlanHash: string;
  readonly uninstallAuthorityHash: string;
  readonly installBindingHash: string;
  readonly installConvergenceHash: string;
  readonly attemptId: string;
  readonly deleteAttemptId: string;
  readonly ownershipMarker: string;
  readonly accountId: string;
  readonly zoneId: string;
  readonly intentSha256: string;
  readonly locator: HostedUninstallManagementDeleteIntent['locator'];
  readonly providerOwnership: HostedUninstallManagementProviderOwnership;
  readonly providerOwnershipSha256: string;
  readonly proof: 'id_get_200_and_complete_list_exact_match';
  readonly evidenceSha256: string;
}

export type HostedUninstallManagementDeleteRecoveryEvidence =
  | HostedUninstallManagementAbsenceEvidence
  | HostedUninstallManagementStillPresentEvidence;

/** Exact read-only proof emitted by the isolated Worker lifecycle boundary. */
export type HostedUninstallExternalWorkerAbsenceEvidence = WorkerDeletionRecoveryProof;

/** Exact read-only proof emitted by the isolated Worker lifecycle boundary. */
export type HostedUninstallExternalNamespaceAbsenceEvidence = AdminStateNamespaceRetirementProof;

export interface HostedUninstallManagementPreflightResult {
  readonly schemaVersion: 1;
  readonly status: 'ready';
  readonly uninstallPlanId: string;
  readonly uninstallPlanHash: string;
  readonly uninstallAuthorityHash: string;
  readonly installBindingHash: string;
  readonly installConvergenceHash: string;
  readonly attemptId: string;
  readonly ownershipMarker: string;
  readonly accountId: string;
  readonly zoneId: string;
  readonly workerId: string;
  readonly namespaceId: string;
  readonly domainId: string;
  readonly domainCertificateId: string;
  readonly applicationId: string;
  readonly policyId: string;
  readonly checkedAt: number;
  readonly expiresAt: number;
  readonly attestationSha256: string;
}

export interface HostedUninstallManagementNamespaceAbsenceSnapshot {
  readonly schemaVersion: 1;
  readonly kind: 'admin_state_namespace_absence_snapshot';
  readonly observation: 1 | 2;
  readonly accountId: string;
  readonly workerName: string;
  readonly namespaceId: string;
  readonly uninstallCycleId: string;
  readonly accountNamespaceCount: number;
  readonly snapshotSha256: string;
}

export interface HostedUninstallManagementNoManagedResidueEvidence {
  readonly schemaVersion: 1;
  readonly kind: 'hosted_uninstall_no_managed_residue_evidence';
  readonly deletionEvidence: readonly [
    HostedUninstallManagementAbsenceEvidence,
    HostedUninstallManagementAbsenceEvidence,
    HostedUninstallManagementAbsenceEvidence,
  ];
  readonly workerDeletion: WorkerDeletionRecoveryProof;
  readonly namespaceRetirement: AdminStateNamespaceRetirementProof;
  readonly namespaceSnapshots: readonly [
    HostedUninstallManagementNamespaceAbsenceSnapshot,
    HostedUninstallManagementNamespaceAbsenceSnapshot,
  ];
  readonly evidenceSha256: string;
}

export interface HostedUninstallManagementNoManagedResidueResult {
  readonly schemaVersion: 1;
  readonly status: 'no_ankka_managed_residue';
  readonly uninstallPlanId: string;
  readonly uninstallPlanHash: string;
  readonly uninstallAuthorityHash: string;
  readonly installBindingHash: string;
  readonly installConvergenceHash: string;
  readonly attemptId: string;
  readonly ownershipMarker: string;
  readonly managementHostname: string;
  readonly dnsAbsenceObservations: 2;
  readonly advancedCertificate: 'provider_retained_out_of_scope_not_observable_or_deleted';
  readonly uninstallCycleId: string;
  readonly deletionEvidenceSha256: string;
  readonly workerDeletionProofSha256: string;
  readonly namespaceRetirementProofSha256: string;
  readonly namespaceSnapshotSha256: string;
  readonly evidence: HostedUninstallManagementNoManagedResidueEvidence;
  readonly proofSha256: string;
}

interface Projection {
  readonly uninstallPlanId: string;
  readonly uninstallPlanHash: string;
  readonly uninstallAuthorityHash: string;
  readonly uninstallPlanCreatedAt: number;
  readonly uninstallPlanExpiresAt: number;
  readonly installBindingHash: string;
  readonly installConvergenceHash: string;
  readonly attemptId: string;
  readonly ownershipMarker: string;
  readonly accountId: string;
  readonly zoneId: string;
  readonly zoneName: string;
  readonly managementHostname: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly correlationTag: string;
  readonly namespaceId: string;
  readonly applicationId: string;
  readonly applicationAud: string;
  readonly allowedIdentityProviderIds: readonly string[];
  readonly applicationName: string;
  readonly policyId: string;
  readonly policyName: string;
  readonly adminEmails: readonly string[];
  readonly domainId: string;
  readonly approvedAuthorities: readonly ApprovedUninstallAuthority[];
}

interface ApprovedUninstallAuthority {
  readonly attemptId: string;
  readonly uninstallPlanId: string;
  readonly uninstallPlanHash: string;
  readonly uninstallAuthorityHash: string;
  readonly uninstallPlanCreatedAt: number;
  readonly uninstallPlanExpiresAt: number;
}

export type HostedUninstallManagementDeletePrerequisites =
  | {
      readonly schemaVersion: 1;
      readonly action: 'management_custom_domain_delete';
      readonly preflight: HostedUninstallManagementPreflightResult;
    }
  | {
      readonly schemaVersion: 1;
      readonly action: 'management_admin_policy_delete';
      readonly domainAbsence: HostedUninstallManagementAbsenceEvidence;
    }
  | {
      readonly schemaVersion: 1;
      readonly action: 'management_access_application_delete';
      readonly domainAbsence: HostedUninstallManagementAbsenceEvidence;
      readonly policyAbsence: HostedUninstallManagementAbsenceEvidence;
    };

export interface HostedUninstallManagementLifecycleEvidence {
  readonly workerDeleteIntent: WorkerDeleteMutationIntent;
  readonly namespaceRetirement: AdminStateNamespaceRetirementProof;
}

interface ProviderResponse {
  readonly status: number;
  readonly value: BoundaryValue;
}

interface ProviderEnvelope {
  readonly errors: null | readonly BoundaryValue[];
  readonly messages: null | readonly BoundaryValue[];
  readonly result: BoundaryValue;
  readonly success: boolean;
  readonly resultInfo?: BoundaryValue;
}

interface ExactManagementDomainObservation {
  readonly id: string;
  readonly certificateId: string;
  readonly hostname: string;
  readonly service: string;
  readonly zoneId: string;
  readonly zoneName: string;
  readonly environment: 'production';
}

type ListPaginationMode = 'filtered' | 'unfiltered';

interface PreparedCall {
  readonly accessToken: string;
  readonly transport: CloudflareUninstallManagementTransport;
  readonly timeoutMs: number;
}

function fail(
  code: CloudflareUninstallManagementErrorCode,
  stage: CloudflareUninstallManagementStage,
  outcome: CloudflareUninstallManagementOutcome,
): never {
  throw new CloudflareUninstallManagementError(code, stage, outcome);
}

function isRecord<Value>(value: Value): value is Value & BoundaryObject {
  return v.is(boundaryObjectSchema, value);
}

function exactKeys(value: BoundaryObject, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function canonicalEqual<Left, Right>(left: Left, right: Right): boolean {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

const providerIdSchema = v.pipe(v.string(), v.regex(PROVIDER_ID));
const customDomainIdSchema = v.pipe(v.string(), v.regex(/^(?:(?:[a-f0-9]{32})|(?:[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})|(?:[a-f0-9]{40}))$/u));
const providerEnvelopeSchema = v.strictObject({
  errors: v.union([v.array(boundaryValueSchema), v.null()]),
  messages: v.union([v.array(boundaryValueSchema), v.null()]),
  result: boundaryValueSchema,
  success: v.boolean(),
  result_info: v.optional(boundaryValueSchema),
});
const providerErrorListSchema = v.pipe(v.array(v.object({
  code: v.pipe(v.number(), v.safeInteger()),
  message: v.pipe(v.string(), v.minLength(1), v.maxLength(2_048)),
})), v.minLength(1), v.maxLength(16));
const listPageInfoSchema = v.strictObject({
  count: v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(PAGE_SIZE)),
  page: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
  per_page: v.pipe(v.number(), v.safeInteger()),
  total_count: v.pipe(v.number(), v.safeInteger(), v.minValue(0)),
  total_pages: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(0))),
});
const providerListItemSchema = v.pipe(
  boundaryObjectSchema,
  v.check((item) => providerId(item.id)),
);
const hostedUninstallContextSchema = v.strictObject({
  schemaVersion: v.literal(1),
  installJournal: boundaryValueSchema,
  approvalHistory: v.pipe(v.array(v.strictObject({
    attemptId: v.pipe(v.string(), v.regex(ATTEMPT_ID)),
    uninstallPlan: boundaryValueSchema,
    authorizedTarget: boundaryValueSchema,
  })), v.minLength(1), v.maxLength(MAX_UNINSTALL_APPROVALS)),
  activeAttemptId: v.pipe(v.string(), v.regex(ATTEMPT_ID)),
});
const uninstallManagementCallSchema = v.strictObject({
  accessToken: v.pipe(v.string(), v.regex(TOKEN)),
  transport: v.function(),
  timeoutMs: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(100), v.maxValue(60_000))),
});
const evidenceHashSchema = v.pipe(v.string(), v.regex(/^[a-f0-9]{64}$/u));
const deleteActionSchema = v.picklist(HOSTED_UNINSTALL_MANAGEMENT_DELETE_ORDER);
const workerListObservationSchema = v.looseObject({
  id: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  name: v.pipe(v.string(), v.regex(WORKER_NAME)),
});
const workersDevObservationSchema = v.strictObject({
  enabled: v.literal(false),
  previews_enabled: v.literal(false),
});
const preflightResultSchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: v.literal('ready'),
  uninstallPlanId: v.string(),
  uninstallPlanHash: v.string(),
  uninstallAuthorityHash: v.string(),
  installBindingHash: v.string(),
  installConvergenceHash: v.string(),
  attemptId: v.pipe(v.string(), v.regex(ATTEMPT_ID)),
  ownershipMarker: v.string(),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  zoneId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  workerId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  namespaceId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  domainId: customDomainIdSchema,
  domainCertificateId: providerIdSchema,
  applicationId: providerIdSchema,
  policyId: providerIdSchema,
  checkedAt: v.pipe(v.number(), v.safeInteger()),
  expiresAt: v.pipe(v.number(), v.safeInteger()),
  attestationSha256: evidenceHashSchema,
});
const deleteLocatorSchema = v.union([
  v.strictObject({ domainId: customDomainIdSchema }),
  v.strictObject({ applicationId: providerIdSchema, policyId: providerIdSchema }),
  v.strictObject({ applicationId: providerIdSchema, aud: v.pipe(v.string(), v.regex(ACCESS_AUD)) }),
]);
const absenceEvidenceSchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: v.literal('absent'),
  action: deleteActionSchema,
  uninstallPlanId: v.string(),
  uninstallPlanHash: v.string(),
  uninstallAuthorityHash: v.string(),
  installBindingHash: v.string(),
  installConvergenceHash: v.string(),
  attemptId: v.pipe(v.string(), v.regex(ATTEMPT_ID)),
  ownershipMarker: v.string(),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  locator: deleteLocatorSchema,
  proof: v.literal('id_get_404_and_complete_list_absence'),
  evidenceSha256: evidenceHashSchema,
});
const providerOwnershipSchema = v.variant('kind', [
  v.strictObject({
    kind: v.literal('management_custom_domain'),
    domainId: customDomainIdSchema,
    certificateId: providerIdSchema,
    hostname: v.string(),
    workerName: v.string(),
    zoneId: v.string(),
    zoneName: v.string(),
  }),
  v.strictObject({
    kind: v.literal('management_admin_policy'),
    applicationId: providerIdSchema,
    policyId: providerIdSchema,
    name: v.string(),
    adminEmails: v.array(v.string()),
  }),
  v.strictObject({
    kind: v.literal('management_access_application'),
    applicationId: providerIdSchema,
    aud: v.pipe(v.string(), v.regex(ACCESS_AUD)),
    name: v.string(),
    hostname: v.string(),
    allowedIdentityProviderIds: v.array(providerIdSchema),
  }),
]);
const deletePrerequisitesSchema = v.variant('action', [
  v.strictObject({
    schemaVersion: v.literal(1),
    action: v.literal('management_custom_domain_delete'),
    preflight: preflightResultSchema,
  }),
  v.strictObject({
    schemaVersion: v.literal(1),
    action: v.literal('management_admin_policy_delete'),
    domainAbsence: absenceEvidenceSchema,
  }),
  v.strictObject({
    schemaVersion: v.literal(1),
    action: v.literal('management_access_application_delete'),
    domainAbsence: absenceEvidenceSchema,
    policyAbsence: absenceEvidenceSchema,
  }),
]);
const deleteIntentBaseEntries = {
  schemaVersion: v.literal(1),
  uninstallPlanId: v.string(),
  uninstallPlanHash: v.string(),
  uninstallAuthorityHash: v.string(),
  installBindingHash: v.string(),
  installConvergenceHash: v.string(),
  attemptId: v.pipe(v.string(), v.regex(ATTEMPT_ID)),
  ownershipMarker: v.string(),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  zoneId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  managementHostname: v.string(),
  workerName: v.pipe(v.string(), v.regex(WORKER_NAME)),
  prerequisiteCommitments: v.array(evidenceHashSchema),
};
const deleteIntentSchema = v.variant('kind', [
  v.strictObject({
    ...deleteIntentBaseEntries,
    kind: v.literal('management_custom_domain_delete'),
    ordinal: v.literal(0),
    locator: v.strictObject({ domainId: customDomainIdSchema }),
  }),
  v.strictObject({
    ...deleteIntentBaseEntries,
    kind: v.literal('management_admin_policy_delete'),
    ordinal: v.literal(1),
    locator: v.strictObject({ applicationId: providerIdSchema, policyId: providerIdSchema }),
  }),
  v.strictObject({
    ...deleteIntentBaseEntries,
    kind: v.literal('management_access_application_delete'),
    ordinal: v.literal(2),
    locator: v.strictObject({ applicationId: providerIdSchema, aud: v.pipe(v.string(), v.regex(ACCESS_AUD)) }),
  }),
]);
const deleteArmSchema = v.strictObject({
  schemaVersion: v.literal(1),
  kind: v.literal('management_delete_arm'),
  action: deleteActionSchema,
  attemptId: v.pipe(v.string(), v.regex(ATTEMPT_ID)),
  armedAt: v.pipe(v.number(), v.safeInteger()),
  intentSha256: evidenceHashSchema,
});
const deleteSubmissionSchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: v.literal('submitted'),
  action: deleteActionSchema,
  attemptId: v.pipe(v.string(), v.regex(ATTEMPT_ID)),
  intentSha256: evidenceHashSchema,
  locator: deleteLocatorSchema,
});
const stillPresentEvidenceSchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: v.literal('still_present'),
  outcome: v.literal('not_applied'),
  action: deleteActionSchema,
  uninstallPlanId: v.string(),
  uninstallPlanHash: v.string(),
  uninstallAuthorityHash: v.string(),
  installBindingHash: v.string(),
  installConvergenceHash: v.string(),
  attemptId: v.pipe(v.string(), v.regex(ATTEMPT_ID)),
  deleteAttemptId: v.pipe(v.string(), v.regex(ATTEMPT_ID)),
  ownershipMarker: v.string(),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  zoneId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  intentSha256: evidenceHashSchema,
  locator: deleteLocatorSchema,
  providerOwnership: providerOwnershipSchema,
  providerOwnershipSha256: evidenceHashSchema,
  proof: v.literal('id_get_200_and_complete_list_exact_match'),
  evidenceSha256: evidenceHashSchema,
});
const finalNamespaceItemSchema = v.strictObject({
  id: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  class: v.pipe(v.string(), v.minLength(1), v.maxLength(128)),
  name: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
  script: v.pipe(v.string(), v.minLength(1), v.maxLength(128)),
  use_sqlite: v.boolean(),
});
const namespaceSnapshotSchema = v.strictObject({
  schemaVersion: v.literal(1),
  kind: v.literal('admin_state_namespace_absence_snapshot'),
  observation: v.union([v.literal(1), v.literal(2)]),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  workerName: v.string(),
  namespaceId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  uninstallCycleId: v.pipe(v.string(), v.regex(/^uninstall-[a-f0-9]{24}$/u)),
  accountNamespaceCount: v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(MAX_ITEMS)),
  snapshotSha256: evidenceHashSchema,
});
const noManagedResidueEvidenceShellSchema = v.strictObject({
  schemaVersion: v.literal(1),
  kind: v.literal('hosted_uninstall_no_managed_residue_evidence'),
  deletionEvidence: v.pipe(v.array(absenceEvidenceSchema), v.length(3)),
  workerDeletion: boundaryValueSchema,
  namespaceRetirement: boundaryValueSchema,
  namespaceSnapshots: v.pipe(v.array(namespaceSnapshotSchema), v.length(2)),
  evidenceSha256: evidenceHashSchema,
});
const noManagedResidueResultShellSchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: v.literal('no_ankka_managed_residue'),
  uninstallPlanId: v.string(),
  uninstallPlanHash: v.string(),
  uninstallAuthorityHash: v.string(),
  installBindingHash: v.string(),
  installConvergenceHash: v.string(),
  attemptId: v.pipe(v.string(), v.regex(ATTEMPT_ID)),
  ownershipMarker: v.string(),
  managementHostname: v.string(),
  dnsAbsenceObservations: v.literal(2),
  advancedCertificate: v.literal('provider_retained_out_of_scope_not_observable_or_deleted'),
  uninstallCycleId: v.pipe(v.string(), v.regex(/^uninstall-[a-f0-9]{24}$/u)),
  deletionEvidenceSha256: evidenceHashSchema,
  workerDeletionProofSha256: evidenceHashSchema,
  namespaceRetirementProofSha256: evidenceHashSchema,
  namespaceSnapshotSha256: evidenceHashSchema,
  evidence: noManagedResidueEvidenceShellSchema,
  proofSha256: evidenceHashSchema,
});

function providerId<Input>(value: Input): value is Input & string {
  return v.is(providerIdSchema, value);
}

/** Worker custom-domain ids are 40 lowercase hex characters (live 2026-08-23). */
function customDomainId<Input>(value: Input): value is Input & string {
  return v.is(customDomainIdSchema, value);
}

function validHostname<Input>(value: Input): value is Input & string {
  if (!v.is(v.string(), value) || value.length < 3 || value.length > 253 || value !== value.toLowerCase()) return false;
  const labels = value.split('.');
  return labels.length >= 2 && labels.every((label) => DNS_LABEL.test(label));
}

function canonicalProviderIds<Input>(value: Input): readonly string[] | null {
  const result = v.safeParse(v.pipe(v.array(providerIdSchema), v.minLength(1), v.maxLength(64)), value);
  if (!result.success) return null;
  const sorted = [...result.output];
  sorted.sort();
  if (sorted.some((id, index) => index > 0 && id === sorted[index - 1])) return null;
  return Object.freeze(sorted);
}

function canonicalEmails<Input>(value: Input): readonly string[] | null {
  const result = v.safeParse(v.pipe(v.array(v.string()), v.minLength(1), v.maxLength(64)), value);
  if (!result.success) return null;
  const sorted = result.output.map((entry) => entry.trim().toLowerCase());
  if (sorted.some((email) => email.length > 254 || !EMAIL.test(email))) return null;
  sorted.sort();
  if (sorted.some((email, index) => index > 0 && email === sorted[index - 1])) return null;
  return Object.freeze(sorted);
}

function managementWorkerName(plan: StaticDeployPlan): string | null {
  const resource = plan.managementResources.find((candidate) => candidate.kind === 'management_worker');
  return resource?.key === 'management-worker' && WORKER_NAME.test(resource.name) ? resource.name : null;
}

async function validateContext(
  input: HostedUninstallManagementContext,
  stage: CloudflareUninstallManagementStage,
): Promise<Projection> {
  const contextResult = v.safeParse(hostedUninstallContextSchema, input);
  if (!contextResult.success) fail('invalid_input', stage, 'not_sent');
  const validated = contextResult.output;

  let journal: InstallJournal;
  let final: Awaited<ReturnType<typeof prepareFinalConvergenceRecordAndLocator>>;
  try {
    journal = await requireInstallJournal(validated.installJournal);
    final = await prepareFinalConvergenceRecordAndLocator(journal);
  } catch {
    return fail('invalid_input', stage, 'not_sent');
  }
  const finalAction = journal.actions[journal.actions.length - 1];
  if (!canonicalEqual(journal, validated.installJournal) || !isCompleteInstallJournal(journal) ||
    finalAction?.name !== 'final_convergence' ||
    finalAction.phase !== 'verified' || !canonicalEqual(finalAction.record, final.record) ||
    !canonicalEqual(finalAction.locator, final.locator)) {
    fail('invalid_input', stage, 'not_sent');
  }

  const approvedAuthorities: ApprovedUninstallAuthority[] = [];
  const seenAttemptIds = new Set<string>();
  let baselinePlan: StaticUninstallPlan | null = null;
  let previousPlan: StaticUninstallPlan | null = null;
  for (const raw of validated.approvalHistory) {
    if (seenAttemptIds.has(raw.attemptId) ||
      journal.approvalHistory.some((entry) => entry.attemptId === raw.attemptId) ||
      journal.leaseAttemptIds.includes(raw.attemptId) ||
      !canonicalEqual(raw.authorizedTarget, journal.target)) fail('invalid_input', stage, 'not_sent');
    let plan: StaticUninstallPlan;
    let rebuilt: StaticUninstallPlan;
    try {
      plan = await parseStaticUninstallPlan(raw.uninstallPlan);
      rebuilt = await buildStaticUninstallPlan(journal, plan.createdAt, plan.expiresAt);
    } catch {
      return fail('invalid_input', stage, 'not_sent');
    }
    if (!canonicalEqual(plan, raw.uninstallPlan) || !canonicalEqual(plan, rebuilt) ||
      !await isRecoveryEquivalentUninstallPlan(plan, rebuilt) ||
      (baselinePlan !== null && (!await isRecoveryEquivalentUninstallPlan(baselinePlan, plan) ||
        baselinePlan.authorityHash !== plan.authorityHash)) ||
      (previousPlan !== null && (plan.createdAt < previousPlan.createdAt ||
        plan.expiresAt < previousPlan.expiresAt))) fail('invalid_input', stage, 'not_sent');
    seenAttemptIds.add(raw.attemptId);
    baselinePlan ??= plan;
    previousPlan = plan;
    approvedAuthorities.push(Object.freeze({
      attemptId: raw.attemptId,
      uninstallPlanId: plan.planId,
      uninstallPlanHash: plan.planHash,
      uninstallAuthorityHash: plan.authorityHash,
      uninstallPlanCreatedAt: plan.createdAt,
      uninstallPlanExpiresAt: plan.expiresAt,
    }));
  }
  const activeAuthority = approvedAuthorities[approvedAuthorities.length - 1];
  const activePlan = previousPlan;
  if (!activeAuthority || !activePlan || validated.activeAttemptId !== activeAuthority.attemptId) {
    fail('invalid_input', stage, 'not_sent');
  }

  let expectedOwnershipMarker: string;
  let applicationName: string;
  let policyName: string;
  try {
    expectedOwnershipMarker = managementOwnershipMarker(journal.plan);
    applicationName = managementAccessApplicationName(journal.plan);
    policyName = managementAdminPolicyName(journal.plan);
  } catch {
    return fail('invalid_input', stage, 'not_sent');
  }
  const workerName = managementWorkerName(journal.plan);
  const workerAction = journal.actions.find((action) => action.name === 'worker_create');
  const applicationAction = journal.actions.find((action) => action.name === 'management_access_application_create');
  if (workerName === null || workerAction?.phase !== 'verified' || workerAction.record.kind !== 'worker_create' ||
    workerAction.record.workerName !== workerName || !WORKER_CORRELATION.test(workerAction.record.correlationTag) ||
    applicationAction?.phase !== 'verified' ||
    applicationAction.record.kind !== 'management_access_application_create') {
    fail('invalid_input', stage, 'not_sent');
  }
  const allowedIdentityProviderIds = canonicalProviderIds(applicationAction.record.allowedIdentityProviderIds);
  const adminEmails = canonicalEmails(journal.plan.managementAdminEmails);
  if (!allowedIdentityProviderIds ||
    !canonicalEqual(allowedIdentityProviderIds, applicationAction.record.allowedIdentityProviderIds) ||
    !adminEmails || !canonicalEqual(adminEmails, journal.plan.managementAdminEmails) ||
    !validHostname(journal.selection.basics.managementHostname) ||
    !PLAN_HASH.test(activePlan.planHash) || !PLAN_HASH.test(activePlan.authorityHash) ||
    activePlan.installationId !== journal.installationId ||
    activePlan.gateway.workerName !== workerName ||
    activePlan.gateway.managementHostname !== journal.selection.basics.managementHostname ||
    final.locator.bindingHash !== journal.bindingHash ||
    !ACCOUNT_ID.test(final.locator.workerId) || !ACCOUNT_ID.test(final.locator.adminStateNamespaceId) ||
    !customDomainId(final.locator.managementDomainId) || !providerId(final.locator.managementApplicationId) ||
    !ACCESS_AUD.test(final.locator.managementAccessAud) || !providerId(final.locator.managementPolicyId)) {
    fail('invalid_input', stage, 'not_sent');
  }

  return Object.freeze({
    uninstallPlanId: activeAuthority.uninstallPlanId,
    uninstallPlanHash: activeAuthority.uninstallPlanHash,
    uninstallAuthorityHash: activeAuthority.uninstallAuthorityHash,
    uninstallPlanCreatedAt: activeAuthority.uninstallPlanCreatedAt,
    uninstallPlanExpiresAt: activeAuthority.uninstallPlanExpiresAt,
    installBindingHash: journal.bindingHash,
    installConvergenceHash: final.locator.convergenceHash,
    attemptId: activeAuthority.attemptId,
    ownershipMarker: expectedOwnershipMarker,
    accountId: journal.target.account.id,
    zoneId: journal.target.zone.id,
    zoneName: journal.target.zone.name,
    managementHostname: journal.selection.basics.managementHostname,
    workerName,
    workerId: final.locator.workerId,
    correlationTag: workerAction.record.correlationTag,
    namespaceId: final.locator.adminStateNamespaceId,
    applicationId: final.locator.managementApplicationId,
    applicationAud: final.locator.managementAccessAud,
    allowedIdentityProviderIds,
    applicationName,
    policyId: final.locator.managementPolicyId,
    policyName,
    adminEmails,
    domainId: final.locator.managementDomainId,
    approvedAuthorities: Object.freeze(approvedAuthorities),
  });
}

function projectionForApprovedAttempt(expected: Projection, attemptId: string): Projection | null {
  const authority = expected.approvedAuthorities.find((candidate) => candidate.attemptId === attemptId);
  if (!authority) return null;
  return Object.freeze({
    ...expected,
    uninstallPlanId: authority.uninstallPlanId,
    uninstallPlanHash: authority.uninstallPlanHash,
    uninstallAuthorityHash: authority.uninstallAuthorityHash,
    uninstallPlanCreatedAt: authority.uninstallPlanCreatedAt,
    uninstallPlanExpiresAt: authority.uninstallPlanExpiresAt,
    attemptId: authority.attemptId,
  });
}

function stableAuthorityMatches(left: Projection, right: Projection): boolean {
  return left.uninstallPlanId === right.uninstallPlanId &&
    left.uninstallPlanHash === right.uninstallPlanHash &&
    left.uninstallAuthorityHash === right.uninstallAuthorityHash &&
    left.installBindingHash === right.installBindingHash &&
    left.installConvergenceHash === right.installConvergenceHash &&
    left.ownershipMarker === right.ownershipMarker && left.accountId === right.accountId &&
    left.zoneId === right.zoneId && left.zoneName === right.zoneName &&
    left.managementHostname === right.managementHostname && left.workerName === right.workerName &&
    left.workerId === right.workerId && left.namespaceId === right.namespaceId &&
    left.applicationId === right.applicationId && left.applicationAud === right.applicationAud &&
    left.policyId === right.policyId && left.domainId === right.domainId;
}

function prepareCall(
  input: CloudflareUninstallManagementCall,
  stage: CloudflareUninstallManagementStage,
): PreparedCall {
  const result = v.safeParse(uninstallManagementCallSchema, input);
  if (!result.success) fail('invalid_input', stage, 'not_sent');
  return {
    accessToken: result.output.accessToken,
    transport: input.transport,
    timeoutMs: result.output.timeoutMs ?? DEFAULT_TIMEOUT_MS,
  };
}

function authHeaders(token: string): Headers {
  return new Headers({ accept: 'application/json', authorization: `Bearer ${token}` });
}

function accountUrl(accountId: string, path: string): URL {
  return new URL(`/client/v4/accounts/${accountId}${path}`, CLOUDFLARE_API_ORIGIN);
}

function zoneUrl(zoneId: string, path: string): URL {
  return new URL(`/client/v4/zones/${zoneId}${path}`, CLOUDFLARE_API_ORIGIN);
}

async function readBoundedJson(response: Response): Promise<BoundaryValue> {
  const length = response.headers.get('content-length');
  if (length !== null) {
    const parsed = Number(length);
    if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > MAX_RESPONSE_BYTES) {
      throw new TypeError('provider_response');
    }
  }
  const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
  if (!contentType.startsWith('application/json') || !response.body) throw new TypeError('provider_response');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new TypeError('provider_response');
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
    return v.parse(boundaryValueSchema, JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
  } catch {
    throw new TypeError('provider_response');
  }
}

async function request(
  call: PreparedCall,
  stage: CloudflareUninstallManagementStage,
  url: URL,
  method: 'GET' | 'DELETE',
): Promise<ProviderResponse> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const providerRequest = new Request(url, {
      method,
      headers: authHeaders(call.accessToken),
      // workerd rejects `redirect: 'error'` at construction; redirects are
      // rejected explicitly by status instead.
      redirect: 'manual',
      signal: controller.signal,
    });
    const operation = (async () => {
      const response = await call.transport(providerRequest);
      if (response.redirected || response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
        throw new TypeError('redirect');
      }
      return Object.freeze({ status: response.status, value: await readBoundedJson(response) });
    })();
    const deadline = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new TypeError('timeout'));
      }, call.timeoutMs);
    });
    return await Promise.race([operation, deadline]);
  } catch (error) {
    if (error instanceof CloudflareUninstallManagementError) throw error;
    return fail('provider_unknown', stage, 'unknown');
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    controller.abort();
  }
}

function isEmpty(value: BoundaryValue): value is null | readonly [] {
  return value === null || (Array.isArray(value) && value.length === 0);
}

function providerErrors(value: BoundaryValue): boolean {
  return v.safeParse(providerErrorListSchema, value).success;
}

function parseEnvelope<Input>(value: Input): ProviderEnvelope | null {
  const result = v.safeParse(providerEnvelopeSchema, value);
  if (!result.success) return null;
  const base = {
    errors: result.output.errors,
    messages: result.output.messages,
    result: result.output.result,
    success: result.output.success,
  };
  return result.output.result_info === undefined
    ? base
    : { ...base, resultInfo: result.output.result_info };
}

function success(response: ProviderResponse, stage: CloudflareUninstallManagementStage): ProviderEnvelope {
  const envelope = parseEnvelope(response.value);
  if (response.status === 200 && envelope?.success === true && isEmpty(envelope.errors) && isEmpty(envelope.messages)) {
    return envelope;
  }
  if (response.status >= 400 && response.status < 500 && envelope?.success === false &&
    providerErrors(envelope.errors) && isEmpty(envelope.messages) && envelope.result === null) {
    fail('provider_rejected', stage, 'rejected');
  }
  return fail('provider_unknown', stage, 'unknown');
}

function exactAbsent(response: ProviderResponse): boolean {
  const envelope = parseEnvelope(response.value);
  return response.status === 404 && envelope?.success === false && providerErrors(envelope.errors) &&
    isEmpty(envelope.messages) && envelope.result === null && envelope.resultInfo === undefined;
}

interface ListPage {
  readonly values: readonly BoundaryObject[];
  readonly page: number;
  readonly perPage: number;
  readonly totalCount: number;
  readonly totalPages: number;
}

function parseListPage(envelope: ProviderEnvelope, requestedPage: number): ListPage | null {
  const result = v.safeParse(v.array(providerListItemSchema), envelope.result);
  const infoResult = v.safeParse(listPageInfoSchema, envelope.resultInfo);
  if (!result.success || !infoResult.success) return null;
  const info = infoResult.output;
  if (
    info.page !== requestedPage || info.per_page !== PAGE_SIZE ||
    info.count !== result.output.length
  ) return null;
  return {
    values: result.output,
    page: info.page,
    perPage: info.per_page,
    totalCount: info.total_count,
    totalPages: info.total_pages === undefined
      ? (info.total_count === 0 ? 0 : Math.ceil(info.total_count / PAGE_SIZE))
      : info.total_pages,
  };
}

async function collectList(
  call: PreparedCall,
  stage: CloudflareUninstallManagementStage,
  urlForPage: (page: number) => URL,
  mode: ListPaginationMode,
): Promise<readonly BoundaryObject[]> {
  const values: BoundaryObject[] = [];
  const seenIds = new Set<string>();
  let totalCount: number | null = null;
  let totalPages: number | null = null;
  for (let pageNumber = 1; pageNumber <= MAX_PAGES; pageNumber += 1) {
    const envelope = success(await request(call, stage, urlForPage(pageNumber), 'GET'), stage);
    const page = parseListPage(envelope, pageNumber);
    if (!page) fail('provider_unknown', stage, 'unknown');
    if (mode === 'unfiltered') {
      const calculatedPages = page.totalCount === 0 ? 0 : Math.ceil(page.totalCount / PAGE_SIZE);
      const totalPagesValid = page.totalCount === 0
        ? page.totalPages === 0 || page.totalPages === 1
        : page.totalPages === calculatedPages;
      if (
        page.totalCount > MAX_ITEMS || page.totalPages > MAX_PAGES ||
        !totalPagesValid ||
        (totalCount !== null && totalCount !== page.totalCount) ||
        (totalPages !== null && totalPages !== page.totalPages)
      ) {
        fail('provider_unknown', stage, 'unknown');
      }
      totalCount = page.totalCount;
      totalPages = page.totalPages;
    }

    if (mode === 'unfiltered') {
      if (totalCount === null) fail('provider_unknown', stage, 'unknown');
      const remaining = totalCount - values.length;
      const expectedCount = Math.max(0, Math.min(PAGE_SIZE, remaining));
      if (page.values.length !== expectedCount) fail('provider_unknown', stage, 'unknown');
    }
    for (const value of page.values) {
      if (!providerId(value.id) || seenIds.has(value.id)) {
        fail('provider_ambiguous', stage, 'unknown');
      }
      seenIds.add(value.id);
      values.push(value);
    }
    if (values.length > MAX_ITEMS || (totalCount !== null && values.length > totalCount)) {
      fail('provider_unknown', stage, 'unknown');
    }
    if (mode === 'filtered') {
      if (page.values.length < PAGE_SIZE) return Object.freeze(values);
      continue;
    }
    if (totalPages === null) fail('provider_unknown', stage, 'unknown');
    const lastPage = totalPages === 0 ? 1 : totalPages;
    if (pageNumber === lastPage) {
      if (values.length !== totalCount) fail('provider_unknown', stage, 'unknown');
      return Object.freeze(values);
    }
  }
  return fail('provider_unknown', stage, 'unknown');
}

function filteredListUrl(base: URL, filter: string, value: string, page: number): URL {
  base.searchParams.set(filter, value);
  base.searchParams.set('page', String(page));
  base.searchParams.set('per_page', String(PAGE_SIZE));
  return base;
}

function exactApplication(value: BoundaryValue, expected: Projection): boolean {
  const observation = v.safeParse(accessApplicationObservationSchema, value);
  if (!observation.success || observation.output.id !== expected.applicationId ||
    observation.output.aud !== expected.applicationAud || observation.output.name !== expected.applicationName ||
    observation.output.domain !== expected.managementHostname) return false;
  const ids = canonicalProviderIds(observation.output.allowed_idps);
  return Boolean(ids && canonicalEqual(ids, expected.allowedIdentityProviderIds));
}

function exactPolicy(value: BoundaryValue, expected: Projection): boolean {
  const observation = v.safeParse(accessPolicyObservationSchema, value);
  if (!observation.success || observation.output.id !== expected.policyId ||
    observation.output.name !== expected.policyName ||
    observation.output.include.length !== expected.adminEmails.length) return false;
  const emails = observation.output.include.map((rule) => rule.email.email);
  emails.sort();
  return canonicalEqual(emails, expected.adminEmails);
}

function exactDomain(
  value: BoundaryValue,
  expected: Projection,
): ExactManagementDomainObservation | null {
  const observation = v.safeParse(customDomainObservationSchema, value);
  if (!observation.success || observation.output.id !== expected.domainId ||
    observation.output.hostname !== expected.managementHostname ||
    observation.output.service !== expected.workerName || observation.output.zone_id !== expected.zoneId ||
    observation.output.zone_name !== expected.zoneName) return null;
  return Object.freeze({
    id: observation.output.id,
    certificateId: observation.output.cert_id,
    hostname: observation.output.hostname,
    service: observation.output.service,
    zoneId: observation.output.zone_id,
    zoneName: observation.output.zone_name,
    environment: 'production',
  });
}

/**
 * The installed gateway Worker references exactly its management custom domain
 * and its own AdminState Durable Object namespace, and nothing else. Live
 * (2026-08-23): the domain reference carries no certificate_id, and the
 * durable_objects list is populated once the namespace exists — the same shape
 * the install-side converged expectation asserts.
 */
function exactWorkerReferences(
  value: BoundaryValue,
  expected: Projection,
  domain: ExactManagementDomainObservation,
): boolean {
  const observation = v.safeParse(workerReferenceSchema, value);
  if (!observation.success) return false;
  const reference = observation.output.domains.at(0);
  const namespace = observation.output.durable_objects.at(0);
  if (reference === undefined || namespace === undefined) return false;
  if (
    reference.id !== domain.id || reference.hostname !== domain.hostname ||
    reference.zone_id !== domain.zoneId || reference.zone_name !== domain.zoneName) return false;
  return namespace.worker_id === expected.workerId &&
    namespace.worker_name === expected.workerName &&
    namespace.namespace_id === expected.namespaceId &&
    namespace.namespace_name === `${expected.workerName}_AdminState`;
}

function exactWorker(
  value: BoundaryValue,
  expected: Projection,
  domain: ExactManagementDomainObservation,
): boolean {
  const observation = v.safeParse(workerObservationSchema, value);
  return observation.success && observation.output.id === expected.workerId &&
    observation.output.name === expected.workerName &&
    canonicalEqual(observation.output.tags, [MANAGED_WORKER_TAG, expected.correlationTag]) &&
    exactWorkerReferences(observation.output.references, expected, domain);
}

function routeOverlapsHostname(pattern: string, hostname: string): boolean | null {
  if (pattern.length < 3 || pattern.length > 512 || pattern !== pattern.toLowerCase() ||
    [...pattern].some((character) => {
      const codePoint = character.codePointAt(0);
      return codePoint === undefined || codePoint <= 32 || codePoint === 127;
    })) return null;
  const withoutScheme = pattern.replace(/^https?:\/\//u, '');
  const slash = withoutScheme.indexOf('/');
  if (slash <= 0 || slash === withoutScheme.length - 1) return null;
  const hostPattern = withoutScheme.slice(0, slash);
  if ([...hostPattern].some((character) => '[]@:?#'.includes(character))) return null;
  if (!hostPattern.includes('*')) return validHostname(hostPattern) ? hostPattern === hostname : null;
  if (!hostPattern.startsWith('*') || hostPattern.slice(1).includes('*')) return null;
  const suffix = hostPattern.slice(1).replace(/^\./u, '');
  if (!validHostname(suffix)) return null;
  return hostname === suffix || hostname.endsWith(`.${suffix}`) || hostname.endsWith(suffix);
}

function domainListUrl(expected: Projection): URL {
  const url = accountUrl(expected.accountId, '/workers/domains');
  url.searchParams.set('hostname', expected.managementHostname);
  return url;
}

function applicationListUrl(expected: Projection, page: number): URL {
  return filteredListUrl(
    accountUrl(expected.accountId, '/access/apps'),
    'domain',
    expected.managementHostname,
    page,
  );
}

function policyListUrl(expected: Projection, page: number): URL {
  const url = accountUrl(expected.accountId, `/access/apps/${encodeURIComponent(expected.applicationId)}/policies`);
  url.searchParams.set('page', String(page));
  url.searchParams.set('per_page', String(PAGE_SIZE));
  return url;
}

function workerListUrl(expected: Projection, page: number): URL {
  const url = accountUrl(expected.accountId, '/workers/workers');
  url.searchParams.set('page', String(page));
  url.searchParams.set('per_page', String(PAGE_SIZE));
  return url;
}

function dnsListUrl(expected: Projection, page: number): URL {
  return filteredListUrl(
    zoneUrl(expected.zoneId, '/dns_records'),
    'name.exact',
    expected.managementHostname,
    page,
  );
}

function routeListUrl(expected: Projection): URL {
  return zoneUrl(expected.zoneId, '/workers/routes');
}

/**
 * Workers Custom Domains is a Cloudflare SinglePage API. Its success envelope
 * may carry optional `result_info`, but those totals are global and explicitly
 * non-authoritative for a filtered query. The endpoint defines no page/per_page
 * traversal parameters, so one bounded exact result is the complete response.
 */
async function collectCustomDomainsSinglePage(
  call: PreparedCall,
  stage: CloudflareUninstallManagementStage,
  expected: Projection,
): Promise<readonly BoundaryObject[]> {
  const envelope = success(await request(call, stage, domainListUrl(expected), 'GET'), stage);
  if (!Array.isArray(envelope.result) || envelope.result.length > MAX_ITEMS) {
    fail('provider_unknown', stage, 'unknown');
  }
  if (envelope.resultInfo !== undefined) {
    const parsedInfo = v.safeParse(singlePageInfoSchema, envelope.resultInfo);
    if (!parsedInfo.success ||
      (parsedInfo.output.count !== undefined && parsedInfo.output.count !== envelope.result.length) ||
      (parsedInfo.output.page !== undefined && parsedInfo.output.page !== 1) ||
      // Live (2026-08-23): an empty Custom Domains list reports per_page 0.
      (parsedInfo.output.per_page !== undefined &&
        (parsedInfo.output.per_page === 0 ? envelope.result.length !== 0 :
          envelope.result.length > parsedInfo.output.per_page)) ||
      (parsedInfo.output.total_count !== undefined && parsedInfo.output.total_count < envelope.result.length) ||
      (parsedInfo.output.total_count !== undefined && parsedInfo.output.total_pages !== undefined &&
        ((parsedInfo.output.total_count === 0 && parsedInfo.output.total_pages !== 0) ||
          (parsedInfo.output.total_count > 0 && parsedInfo.output.total_pages < 1))) ||
      (parsedInfo.output.total_count !== undefined && parsedInfo.output.total_pages !== undefined &&
        parsedInfo.output.per_page !== undefined && parsedInfo.output.per_page > 0 &&
        parsedInfo.output.total_pages !== Math.ceil(parsedInfo.output.total_count / parsedInfo.output.per_page))) {
      fail('provider_unknown', stage, 'unknown');
    }
  }
  const seenIds = new Set<string>();
  const values: BoundaryObject[] = [];
  for (const value of envelope.result) {
    // Worker custom domains carry 40-hex ids, not the 32-hex provider id.
    if (!isRecord(value) || !customDomainId(value.id)) fail('provider_mismatch', stage, 'rejected');
    if (seenIds.has(value.id)) fail('provider_ambiguous', stage, 'unknown');
    seenIds.add(value.id);
    values.push(value);
  }
  return Object.freeze(values);
}

/** Workers Routes is also a Cloudflare SinglePage API. */
async function collectWorkerRoutesSinglePage(
  call: PreparedCall,
  stage: CloudflareUninstallManagementStage,
  expected: Projection,
): Promise<readonly BoundaryObject[]> {
  const envelope = success(await request(call, stage, routeListUrl(expected), 'GET'), stage);
  if (envelope.resultInfo !== undefined || !Array.isArray(envelope.result) ||
    envelope.result.length > MAX_ITEMS) fail('provider_unknown', stage, 'unknown');
  const seenIds = new Set<string>();
  const values: BoundaryObject[] = [];
  for (const value of envelope.result) {
    if (!isRecord(value) || !providerId(value.id)) fail('provider_mismatch', stage, 'rejected');
    if (seenIds.has(value.id)) fail('provider_ambiguous', stage, 'unknown');
    seenIds.add(value.id);
    values.push(value);
  }
  return Object.freeze(values);
}

async function requireExactGet(
  call: PreparedCall,
  stage: CloudflareUninstallManagementStage,
  url: URL,
  matches: (value: BoundaryValue) => boolean,
): Promise<BoundaryValue> {
  const envelope = success(await request(call, stage, url, 'GET'), stage);
  if (envelope.resultInfo !== undefined) fail('provider_unknown', stage, 'unknown');
  const result = envelope.result;
  if (!matches(result)) fail('provider_mismatch', stage, 'rejected');
  return result;
}

async function requireExactSingletonList(
  call: PreparedCall,
  stage: CloudflareUninstallManagementStage,
  urlForPage: (page: number) => URL,
  matches: (value: BoundaryObject) => boolean,
  mode: ListPaginationMode,
): Promise<BoundaryObject> {
  const values = await collectList(call, stage, urlForPage, mode);
  if (values.length > 1) fail('provider_ambiguous', stage, 'rejected');
  const value = values.length === 1 ? values.at(0) : undefined;
  if (value === undefined || !matches(value)) fail('provider_mismatch', stage, 'rejected');
  return value;
}

async function requireExactSingletonCustomDomainList(
  call: PreparedCall,
  stage: CloudflareUninstallManagementStage,
  expected: Projection,
  matches: (value: BoundaryObject) => boolean,
): Promise<BoundaryObject> {
  const values = await collectCustomDomainsSinglePage(call, stage, expected);
  if (values.length > 1) fail('provider_ambiguous', stage, 'rejected');
  const value = values.length === 1 ? values.at(0) : undefined;
  if (value === undefined || !matches(value)) fail('provider_mismatch', stage, 'rejected');
  return value;
}

async function requireNoDnsOrRouteCollision(
  call: PreparedCall,
  expected: Projection,
  dnsStage: CloudflareUninstallManagementStage,
  routeStage: CloudflareUninstallManagementStage,
  residueCode: CloudflareUninstallManagementErrorCode,
  dnsMode: 'installed_custom_domain' | 'absent',
): Promise<void> {
  const dns = await collectList(call, dnsStage, (page) => dnsListUrl(expected, page), 'filtered');
  for (const value of dns) {
    if (!isRecord(value) || !providerId(value.id) || value.name !== expected.managementHostname) {
      fail('provider_mismatch', dnsStage, 'rejected');
    }
  }
  if (dnsMode === 'absent') {
    if (dns.length > 0) fail(residueCode, dnsStage, 'rejected');
  } else {
    // The exact Custom Domain GET + singleton list above is the authoritative
    // ownership proof. Cloudflare auto-creates a same-name DNS companion, but
    // the current DNS API no longer exposes `auto_added`/`managed_by_apps`, so
    // one companion is compatible and cannot be classified by metadata. More
    // than one record is ambiguous and fails closed.
    if (dns.length > 1) fail(residueCode, dnsStage, 'rejected');
  }

  if (dnsMode === 'absent') {
    // A second complete observation avoids certifying a one-read transient as
    // post-delete convergence. Both observations must independently be empty.
    const secondDns = await collectList(call, dnsStage, (page) => dnsListUrl(expected, page), 'filtered');
    if (secondDns.length > 0 || !canonicalEqual(dns, secondDns)) {
      fail(residueCode, dnsStage, 'rejected');
    }
  }

  const routes = await collectWorkerRoutesSinglePage(call, routeStage, expected);
  for (const value of routes) {
    const route = v.safeParse(routeObservationSchema, value);
    if (!route.success) {
      fail('provider_mismatch', routeStage, 'rejected');
    }
    const overlaps = routeOverlapsHostname(route.output.pattern, expected.managementHostname);
    if (overlaps === null) fail('provider_mismatch', routeStage, 'rejected');
    if (overlaps) fail(residueCode, routeStage, 'rejected');
  }
}

export async function preflightHostedUninstallManagement(
  context: HostedUninstallManagementContext,
  callInput: CloudflareUninstallManagementCall,
  nowMs = Date.now(),
): Promise<HostedUninstallManagementPreflightResult> {
  const expected = await validateContext(context, 'validate');
  const call = prepareCall(callInput, 'validate');
  if (!Number.isSafeInteger(nowMs) || nowMs < expected.uninstallPlanCreatedAt ||
    nowMs >= expected.uninstallPlanExpiresAt ||
    nowMs > Number.MAX_SAFE_INTEGER - PREFLIGHT_ATTESTATION_TTL_MS) {
    fail('invalid_input', 'validate', 'not_sent');
  }

  const domainGetValue = await requireExactGet(
    call,
    'fresh_custom_domain_get',
    accountUrl(expected.accountId, `/workers/domains/${encodeURIComponent(expected.domainId)}`),
    (value) => exactDomain(value, expected) !== null,
  );
  const domain = exactDomain(domainGetValue, expected);
  if (!domain) fail('provider_mismatch', 'fresh_custom_domain_get', 'rejected');
  await requireExactSingletonCustomDomainList(
    call,
    'fresh_custom_domain_list',
    expected,
    (value) => canonicalEqual(exactDomain(value, expected), domain),
  );
  await requireExactGet(
    call,
    'fresh_admin_policy_get',
    accountUrl(expected.accountId, `/access/apps/${encodeURIComponent(expected.applicationId)}/policies/${encodeURIComponent(expected.policyId)}`),
    (value) => exactPolicy(value, expected),
  );
  await requireExactSingletonList(
    call,
    'fresh_admin_policy_list',
    (page) => policyListUrl(expected, page),
    (value) => exactPolicy(value, expected),
    'unfiltered',
  );
  await requireExactGet(
    call,
    'fresh_access_application_get',
    accountUrl(expected.accountId, `/access/apps/${encodeURIComponent(expected.applicationId)}`),
    (value) => exactApplication(value, expected),
  );
  await requireExactSingletonList(
    call,
    'fresh_access_application_list',
    (page) => applicationListUrl(expected, page),
    (value) => exactApplication(value, expected),
    'filtered',
  );
  await requireExactGet(
    call,
    'fresh_worker_get',
    accountUrl(expected.accountId, `/workers/workers/${encodeURIComponent(expected.workerId)}`),
    (value) => exactWorker(value, expected, domain),
  );
  const workers = await collectList(
    call,
    'fresh_worker_list',
    (page) => workerListUrl(expected, page),
    'unfiltered',
  );
  let workerMatches = 0;
  for (const value of workers) {
    const observation = v.safeParse(workerListObservationSchema, value);
    if (!observation.success) {
      fail('provider_mismatch', 'fresh_worker_list', 'rejected');
    }
    if (observation.output.id === expected.workerId || observation.output.name === expected.workerName) {
      if (observation.output.id !== expected.workerId || observation.output.name !== expected.workerName) {
        fail('provider_mismatch', 'fresh_worker_list', 'rejected');
      }
      workerMatches += 1;
    }
  }
  if (workerMatches !== 1) fail(workerMatches > 1 ? 'provider_ambiguous' : 'provider_mismatch', 'fresh_worker_list', 'rejected');

  await requireExactGet(
    call,
    'fresh_workers_dev_get',
    accountUrl(expected.accountId, `/workers/scripts/${encodeURIComponent(expected.workerName)}/subdomain`),
    (value) => v.is(workersDevObservationSchema, value),
  );
  await requireNoDnsOrRouteCollision(
    call,
    expected,
    'fresh_dns_collision_list',
    'fresh_worker_route_list',
    'management_residue',
    'installed_custom_domain',
  );
  const checkedAt = nowMs;
  const expiresAt = Math.min(nowMs + PREFLIGHT_ATTESTATION_TTL_MS, expected.uninstallPlanExpiresAt);
  const semantic = {
    schemaVersion: 1,
    status: 'ready',
    uninstallPlanId: expected.uninstallPlanId,
    uninstallPlanHash: expected.uninstallPlanHash,
    uninstallAuthorityHash: expected.uninstallAuthorityHash,
    installBindingHash: expected.installBindingHash,
    installConvergenceHash: expected.installConvergenceHash,
    attemptId: expected.attemptId,
    ownershipMarker: expected.ownershipMarker,
    accountId: expected.accountId,
    zoneId: expected.zoneId,
    workerId: expected.workerId,
    namespaceId: expected.namespaceId,
    domainId: expected.domainId,
    domainCertificateId: domain.certificateId,
    applicationId: expected.applicationId,
    policyId: expected.policyId,
    checkedAt,
    expiresAt,
  } as const;
  return deepFreeze({
    ...semantic,
    attestationSha256: await sha256(canonicalJson(semantic)),
  });
}

export async function parseHostedUninstallManagementPreflightResult<Input>(
  context: HostedUninstallManagementContext,
  value: Input,
): Promise<HostedUninstallManagementPreflightResult | null> {
  let expected: Projection;
  try {
    expected = await validateContext(context, 'validate');
  } catch {
    return null;
  }
  return parsePreflightForExpected(expected, value);
}

async function parsePreflightForExpected<Input>(
  expected: Projection,
  value: Input,
): Promise<HostedUninstallManagementPreflightResult | null> {
  const candidate = v.safeParse(preflightResultSchema, value);
  if (!candidate.success || candidate.output.checkedAt < expected.uninstallPlanCreatedAt ||
    candidate.output.expiresAt !== Math.min(
      candidate.output.checkedAt + PREFLIGHT_ATTESTATION_TTL_MS,
      expected.uninstallPlanExpiresAt,
    ) || candidate.output.expiresAt <= candidate.output.checkedAt) return null;
  const semantic = {
    schemaVersion: 1 as const,
    status: 'ready' as const,
    uninstallPlanId: expected.uninstallPlanId,
    uninstallPlanHash: expected.uninstallPlanHash,
    uninstallAuthorityHash: expected.uninstallAuthorityHash,
    installBindingHash: expected.installBindingHash,
    installConvergenceHash: expected.installConvergenceHash,
    attemptId: expected.attemptId,
    ownershipMarker: expected.ownershipMarker,
    accountId: expected.accountId,
    zoneId: expected.zoneId,
    workerId: expected.workerId,
    namespaceId: expected.namespaceId,
    domainId: expected.domainId,
    domainCertificateId: candidate.output.domainCertificateId,
    applicationId: expected.applicationId,
    policyId: expected.policyId,
    checkedAt: candidate.output.checkedAt,
    expiresAt: candidate.output.expiresAt,
  };
  const parsed = deepFreeze({
    ...semantic,
    attestationSha256: candidate.output.attestationSha256,
  });
  return canonicalEqual(candidate.output, parsed) &&
    candidate.output.attestationSha256 === await sha256(canonicalJson(semantic)) ? parsed : null;
}

function canonicalLocator(
  expected: Projection,
  action: HostedUninstallManagementDeleteAction,
): HostedUninstallManagementDeleteIntent['locator'] {
  if (action === 'management_custom_domain_delete') return deepFreeze({ domainId: expected.domainId });
  if (action === 'management_admin_policy_delete') {
    return deepFreeze({ applicationId: expected.applicationId, policyId: expected.policyId });
  }
  return deepFreeze({ applicationId: expected.applicationId, aud: expected.applicationAud });
}

async function parseAbsenceForAction<Input>(
  expected: Projection,
  action: HostedUninstallManagementDeleteAction,
  value: Input,
): Promise<HostedUninstallManagementAbsenceEvidence | null> {
  const candidate = v.safeParse(absenceEvidenceSchema, value);
  if (!candidate.success || candidate.output.action !== action) return null;
  const semantic = {
    schemaVersion: 1 as const,
    status: 'absent' as const,
    action,
    uninstallPlanId: expected.uninstallPlanId,
    uninstallPlanHash: expected.uninstallPlanHash,
    uninstallAuthorityHash: expected.uninstallAuthorityHash,
    installBindingHash: expected.installBindingHash,
    installConvergenceHash: expected.installConvergenceHash,
    attemptId: expected.attemptId,
    ownershipMarker: expected.ownershipMarker,
    accountId: expected.accountId,
    locator: canonicalLocator(expected, action),
    proof: 'id_get_404_and_complete_list_absence' as const,
  };
  const parsed = deepFreeze({ ...semantic, evidenceSha256: candidate.output.evidenceSha256 });
  return canonicalEqual(candidate.output, parsed) &&
    candidate.output.evidenceSha256 === await sha256(canonicalJson(semantic)) ? parsed : null;
}

async function parseApprovedAbsenceForAction<Input>(
  active: Projection,
  action: HostedUninstallManagementDeleteAction,
  value: Input,
): Promise<HostedUninstallManagementAbsenceEvidence | null> {
  const candidate = v.safeParse(absenceEvidenceSchema, value);
  if (!candidate.success) return null;
  const origin = projectionForApprovedAttempt(active, candidate.output.attemptId);
  if (!origin || !stableAuthorityMatches(origin, active)) return null;
  const parsed = await parseAbsenceForAction(origin, action, candidate.output);
  if (!parsed || !canonicalEqual(parsed.locator, canonicalLocator(active, action)) ||
    parsed.accountId !== active.accountId || parsed.ownershipMarker !== active.ownershipMarker ||
    parsed.installBindingHash !== active.installBindingHash ||
    parsed.installConvergenceHash !== active.installConvergenceHash ||
    parsed.uninstallPlanId !== active.uninstallPlanId ||
    parsed.uninstallPlanHash !== active.uninstallPlanHash ||
    parsed.uninstallAuthorityHash !== active.uninstallAuthorityHash) return null;
  return parsed;
}

function providerOwnershipObservation(
  expected: Projection,
  action: HostedUninstallManagementDeleteAction,
  domain?: ExactManagementDomainObservation,
): HostedUninstallManagementProviderOwnership {
  if (action === 'management_custom_domain_delete') {
    if (!domain) fail('provider_mismatch', 'management_custom_domain_recovery_get', 'rejected');
    return deepFreeze({
      kind: 'management_custom_domain',
      domainId: domain.id,
      certificateId: domain.certificateId,
      hostname: domain.hostname,
      workerName: domain.service,
      zoneId: domain.zoneId,
      zoneName: domain.zoneName,
    });
  }
  if (action === 'management_admin_policy_delete') {
    return deepFreeze({
      kind: 'management_admin_policy',
      applicationId: expected.applicationId,
      policyId: expected.policyId,
      name: expected.policyName,
      adminEmails: Object.freeze([...expected.adminEmails]),
    });
  }
  return deepFreeze({
    kind: 'management_access_application',
    applicationId: expected.applicationId,
    aud: expected.applicationAud,
    name: expected.applicationName,
    hostname: expected.managementHostname,
    allowedIdentityProviderIds: Object.freeze([...expected.allowedIdentityProviderIds]),
  });
}

function parseProviderOwnershipObservation<Input>(
  expected: Projection,
  action: HostedUninstallManagementDeleteAction,
  value: Input,
): HostedUninstallManagementProviderOwnership | null {
  const candidate = v.safeParse(providerOwnershipSchema, value);
  if (!candidate.success) return null;
  if (action === 'management_custom_domain_delete') {
    if (candidate.output.kind !== 'management_custom_domain' ||
      candidate.output.domainId !== expected.domainId ||
      candidate.output.hostname !== expected.managementHostname ||
      candidate.output.workerName !== expected.workerName || candidate.output.zoneId !== expected.zoneId ||
      candidate.output.zoneName !== expected.zoneName) return null;
    return deepFreeze({
      kind: 'management_custom_domain',
      domainId: candidate.output.domainId,
      certificateId: candidate.output.certificateId,
      hostname: candidate.output.hostname,
      workerName: candidate.output.workerName,
      zoneId: candidate.output.zoneId,
      zoneName: candidate.output.zoneName,
    });
  }
  if (action === 'management_admin_policy_delete') {
    if (candidate.output.kind !== 'management_admin_policy') return null;
    const canonical = providerOwnershipObservation(expected, action);
    return canonicalEqual(candidate.output, canonical) ? canonical : null;
  }
  if (candidate.output.kind !== 'management_access_application') return null;
  const canonical = providerOwnershipObservation(expected, action);
  return canonicalEqual(candidate.output, canonical) ? canonical : null;
}

async function buildStillPresentEvidence(
  active: Projection,
  intent: HostedUninstallManagementDeleteIntent,
  arm: HostedUninstallManagementDeleteArm,
  providerOwnership: HostedUninstallManagementProviderOwnership,
): Promise<HostedUninstallManagementStillPresentEvidence> {
  const providerOwnershipSha256 = await sha256(canonicalJson(providerOwnership));
  const semantic = deepFreeze({
    schemaVersion: 1 as const,
    status: 'still_present' as const,
    outcome: 'not_applied' as const,
    action: intent.kind,
    uninstallPlanId: active.uninstallPlanId,
    uninstallPlanHash: active.uninstallPlanHash,
    uninstallAuthorityHash: active.uninstallAuthorityHash,
    installBindingHash: active.installBindingHash,
    installConvergenceHash: active.installConvergenceHash,
    attemptId: active.attemptId,
    deleteAttemptId: intent.attemptId,
    ownershipMarker: active.ownershipMarker,
    accountId: active.accountId,
    zoneId: active.zoneId,
    intentSha256: arm.intentSha256,
    locator: canonicalLocator(active, intent.kind),
    providerOwnership,
    providerOwnershipSha256,
    proof: 'id_get_200_and_complete_list_exact_match' as const,
  });
  return deepFreeze({ ...semantic, evidenceSha256: await sha256(canonicalJson(semantic)) });
}

async function requirePrerequisites(
  _context: HostedUninstallManagementContext,
  expected: Projection,
  action: HostedUninstallManagementDeleteAction,
  value: HostedUninstallManagementDeletePrerequisites,
): Promise<{
  readonly value: HostedUninstallManagementDeletePrerequisites;
  readonly commitments: readonly string[];
}> {
  const parsedValue = v.safeParse(deletePrerequisitesSchema, value);
  if (!parsedValue.success || parsedValue.output.action !== action) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  if (parsedValue.output.action === 'management_custom_domain_delete') {
    const preflight = await parsePreflightForExpected(expected, parsedValue.output.preflight);
    if (!preflight) fail('invalid_input', 'validate', 'not_sent');
    return deepFreeze({
      value: { schemaVersion: 1, action: 'management_custom_domain_delete', preflight },
      commitments: [preflight.attestationSha256],
    });
  }
  const domainAbsence = await parseApprovedAbsenceForAction(
    expected,
    'management_custom_domain_delete',
    parsedValue.output.domainAbsence,
  );
  if (!domainAbsence) fail('invalid_input', 'validate', 'not_sent');
  if (parsedValue.output.action === 'management_admin_policy_delete') {
    return deepFreeze({
      value: { schemaVersion: 1, action: 'management_admin_policy_delete', domainAbsence },
      commitments: [domainAbsence.evidenceSha256],
    });
  }
  const policyAbsence = await parseApprovedAbsenceForAction(
    expected,
    'management_admin_policy_delete',
    parsedValue.output.policyAbsence,
  );
  if (!policyAbsence) fail('invalid_input', 'validate', 'not_sent');
  return deepFreeze({
    value: { schemaVersion: 1, action: 'management_access_application_delete', domainAbsence, policyAbsence },
    commitments: [domainAbsence.evidenceSha256, policyAbsence.evidenceSha256],
  });
}

function canonicalIntent(
  expected: Projection,
  action: HostedUninstallManagementDeleteAction,
  prerequisiteCommitments: readonly string[],
): HostedUninstallManagementDeleteIntent {
  const base = {
    schemaVersion: 1 as const,
    uninstallPlanId: expected.uninstallPlanId,
    uninstallPlanHash: expected.uninstallPlanHash,
    uninstallAuthorityHash: expected.uninstallAuthorityHash,
    installBindingHash: expected.installBindingHash,
    installConvergenceHash: expected.installConvergenceHash,
    attemptId: expected.attemptId,
    ownershipMarker: expected.ownershipMarker,
    accountId: expected.accountId,
    zoneId: expected.zoneId,
    managementHostname: expected.managementHostname,
    workerName: expected.workerName,
    prerequisiteCommitments: Object.freeze([...prerequisiteCommitments]),
  };
  if (action === 'management_custom_domain_delete') {
    return deepFreeze({
      ...base,
      kind: action,
      ordinal: 0,
      locator: { domainId: expected.domainId },
    });
  }
  if (action === 'management_admin_policy_delete') {
    return deepFreeze({
      ...base,
      kind: action,
      ordinal: 1,
      locator: { applicationId: expected.applicationId, policyId: expected.policyId },
    });
  }
  return deepFreeze({
    ...base,
    kind: action,
    ordinal: 2,
    locator: { applicationId: expected.applicationId, aud: expected.applicationAud },
  });
}

export async function prepareHostedUninstallManagementDeleteIntent(
  context: HostedUninstallManagementContext,
  action: HostedUninstallManagementDeleteAction,
  prerequisites: HostedUninstallManagementDeletePrerequisites,
): Promise<HostedUninstallManagementDeleteIntent> {
  const expected = await validateContext(context, 'validate');
  if (!HOSTED_UNINSTALL_MANAGEMENT_DELETE_ORDER.includes(action)) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  const parsed = await requirePrerequisites(context, expected, action, prerequisites);
  return canonicalIntent(expected, action, parsed.commitments);
}

async function requireIntent(
  context: HostedUninstallManagementContext,
  intent: HostedUninstallManagementDeleteIntent,
  prerequisites: HostedUninstallManagementDeletePrerequisites,
  mode: 'active' | 'approved',
): Promise<{ readonly expected: Projection; readonly intent: HostedUninstallManagementDeleteIntent }> {
  const active = await validateContext(context, 'validate');
  const parsedIntent = v.safeParse(deleteIntentSchema, intent);
  if (!parsedIntent.success) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  const expected = mode === 'active'
    ? active
    : projectionForApprovedAttempt(active, parsedIntent.output.attemptId);
  if (!expected || (mode === 'active' && parsedIntent.output.attemptId !== active.attemptId) ||
    !stableAuthorityMatches(expected, active)) fail('invalid_input', 'validate', 'not_sent');
  const parsed = await requirePrerequisites(
    context,
    expected,
    parsedIntent.output.kind,
    prerequisites,
  );
  const canonical = canonicalIntent(
    expected,
    parsedIntent.output.kind,
    parsed.commitments,
  );
  if (!canonicalEqual(parsedIntent.output, canonical)) fail('invalid_input', 'validate', 'not_sent');
  return Object.freeze({ expected, intent: canonical });
}

export async function parseHostedUninstallManagementDeleteIntent<Input>(
  context: HostedUninstallManagementContext,
  prerequisites: HostedUninstallManagementDeletePrerequisites,
  value: Input,
): Promise<HostedUninstallManagementDeleteIntent | null> {
  try {
    const candidate = v.safeParse(deleteIntentSchema, value);
    if (!candidate.success) return null;
    return (await requireIntent(
      context,
      candidate.output,
      prerequisites,
      'approved',
    )).intent;
  } catch {
    return null;
  }
}

export async function prepareHostedUninstallManagementDeleteArm(
  context: HostedUninstallManagementContext,
  intent: HostedUninstallManagementDeleteIntent,
  prerequisites: HostedUninstallManagementDeletePrerequisites,
  armedAt: number,
): Promise<HostedUninstallManagementDeleteArm> {
  const { expected, intent: canonical } = await requireIntent(context, intent, prerequisites, 'active');
  if (!Number.isSafeInteger(armedAt) || armedAt < expected.uninstallPlanCreatedAt ||
    armedAt >= expected.uninstallPlanExpiresAt) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  return deepFreeze({
    schemaVersion: 1,
    kind: 'management_delete_arm',
    action: canonical.kind,
    attemptId: expected.attemptId,
    armedAt,
    intentSha256: await sha256(canonicalJson(canonical)),
  });
}

export async function parseHostedUninstallManagementDeleteArm<Input>(
  context: HostedUninstallManagementContext,
  intent: HostedUninstallManagementDeleteIntent,
  prerequisites: HostedUninstallManagementDeletePrerequisites,
  value: Input,
): Promise<HostedUninstallManagementDeleteArm | null> {
  let expected: Projection;
  let parsedIntent: HostedUninstallManagementDeleteIntent;
  try {
    const parsed = await requireIntent(context, intent, prerequisites, 'approved');
    expected = parsed.expected;
    parsedIntent = parsed.intent;
  } catch {
    return null;
  }
  const candidate = v.safeParse(deleteArmSchema, value);
  if (!candidate.success || candidate.output.action !== parsedIntent.kind ||
    candidate.output.attemptId !== parsedIntent.attemptId ||
    candidate.output.armedAt < expected.uninstallPlanCreatedAt ||
    candidate.output.armedAt >= expected.uninstallPlanExpiresAt ||
    candidate.output.intentSha256 !== await sha256(canonicalJson(parsedIntent))) return null;
  return deepFreeze({
    schemaVersion: 1,
    kind: 'management_delete_arm',
    action: parsedIntent.kind,
    attemptId: candidate.output.attemptId,
    armedAt: candidate.output.armedAt,
    intentSha256: candidate.output.intentSha256,
  });
}

function deleteUrl(expected: Projection, action: HostedUninstallManagementDeleteAction): URL {
  if (action === 'management_custom_domain_delete') {
    return accountUrl(expected.accountId, `/workers/domains/${encodeURIComponent(expected.domainId)}`);
  }
  if (action === 'management_admin_policy_delete') {
    return accountUrl(
      expected.accountId,
      `/access/apps/${encodeURIComponent(expected.applicationId)}/policies/${encodeURIComponent(expected.policyId)}`,
    );
  }
  return accountUrl(expected.accountId, `/access/apps/${encodeURIComponent(expected.applicationId)}`);
}

function exactDeleteResult(result: BoundaryValue, intent: HostedUninstallManagementDeleteIntent): boolean {
  if (result === null) return true;
  if (!isRecord(result) || !exactKeys(result, ['id'])) return false;
  if (intent.kind === 'management_custom_domain_delete') return false;
  if (intent.kind === 'management_admin_policy_delete') return result.id === intent.locator.policyId;
  return result.id === intent.locator.applicationId;
}

function exactCustomDomainDeleteSuccess(response: ProviderResponse): boolean {
  if (response.status !== 200 || !isRecord(response.value) ||
    !exactKeys(response.value, ['errors', 'messages', 'success'])) return false;
  return response.value.success === true && isEmpty(response.value.errors) && isEmpty(response.value.messages);
}

async function requireFreshDeletePrerequisites(
  call: PreparedCall,
  expected: Projection,
  action: HostedUninstallManagementDeleteAction,
  prerequisites: HostedUninstallManagementDeletePrerequisites,
  nowMs: number,
): Promise<void> {
  if (action === 'management_custom_domain_delete') {
    if (prerequisites.action !== action) fail('invalid_input', 'validate', 'not_sent');
    const preflight = prerequisites.preflight;
    if (nowMs < preflight.checkedAt || nowMs >= preflight.expiresAt) {
      fail('invalid_input', 'validate', 'not_sent');
    }
    const observed = await requireExactGet(
      call,
      'fresh_custom_domain_get',
      accountUrl(expected.accountId, `/workers/domains/${encodeURIComponent(expected.domainId)}`),
      (value) => exactDomain(value, expected)?.certificateId === preflight.domainCertificateId,
    );
    const domain = exactDomain(observed, expected);
    if (!domain || domain.certificateId !== preflight.domainCertificateId) {
      fail('provider_mismatch', 'fresh_custom_domain_get', 'rejected');
    }
    await requireExactSingletonCustomDomainList(
      call,
      'fresh_custom_domain_list',
      expected,
      (value) => canonicalEqual(exactDomain(value, expected), domain),
    );
    return;
  }

  await requireExactGet(
    call,
    'fresh_access_application_get',
    accountUrl(expected.accountId, `/access/apps/${encodeURIComponent(expected.applicationId)}`),
    (value) => exactApplication(value, expected),
  );
  await requireExactSingletonList(
    call,
    'fresh_access_application_list',
    (page) => applicationListUrl(expected, page),
    (value) => exactApplication(value, expected),
    'filtered',
  );
  await requireId404AndListAbsence(call, expected, 'management_custom_domain_delete');
  if (action === 'management_admin_policy_delete') {
    await requireExactGet(
      call,
      'fresh_admin_policy_get',
      accountUrl(expected.accountId, `/access/apps/${encodeURIComponent(expected.applicationId)}/policies/${encodeURIComponent(expected.policyId)}`),
      (value) => exactPolicy(value, expected),
    );
    await requireExactSingletonList(
      call,
      'fresh_admin_policy_list',
      (page) => policyListUrl(expected, page),
      (value) => exactPolicy(value, expected),
      'unfiltered',
    );
    return;
  }
  await requireId404AndListAbsence(call, expected, 'management_admin_policy_delete');
}

/**
 * The caller must durably CAS the exact arm from `armed` to `submitted` in the
 * same Durable Object journal before invoking this function. This primitive
 * intentionally keeps no isolate-local replay state: an unknown outcome must
 * enter read-only convergence and the same arm must never be invoked again.
 */
export async function submitHostedUninstallManagementDeleteOnce(
  context: HostedUninstallManagementContext,
  intentInput: HostedUninstallManagementDeleteIntent,
  arm: HostedUninstallManagementDeleteArm,
  prerequisites: HostedUninstallManagementDeletePrerequisites,
  callInput: CloudflareUninstallManagementCall,
  nowMs = Date.now(),
): Promise<HostedUninstallManagementDeleteSubmission> {
  const { expected, intent } = await requireIntent(context, intentInput, prerequisites, 'active');
  const call = prepareCall(callInput, 'validate');
  const parsedArm = await parseHostedUninstallManagementDeleteArm(context, intent, prerequisites, arm);
  if (!parsedArm || !Number.isSafeInteger(nowMs) || nowMs < parsedArm.armedAt ||
    nowMs >= expected.uninstallPlanExpiresAt) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  const parsedPrerequisites = await requirePrerequisites(context, expected, intent.kind, prerequisites);
  await requireFreshDeletePrerequisites(call, expected, intent.kind, parsedPrerequisites.value, nowMs);
  const response = await request(call, intent.kind, deleteUrl(expected, intent.kind), 'DELETE');
  if (intent.kind === 'management_custom_domain_delete' && exactCustomDomainDeleteSuccess(response)) {
    return deepFreeze({
      schemaVersion: 1,
      status: 'submitted',
      action: intent.kind,
      attemptId: parsedArm.attemptId,
      intentSha256: parsedArm.intentSha256,
      locator: intent.locator,
    });
  }
  const envelope = parseEnvelope(response.value);
  // Live Cloudflare contract (2026-08-23): Access application and policy
  // deletes answer 202 with the deleted id as result.
  if (intent.kind !== 'management_custom_domain_delete' &&
    (response.status === 200 || response.status === 202) && envelope?.success === true &&
    isEmpty(envelope.errors) && isEmpty(envelope.messages) && envelope.resultInfo === undefined) {
    if (!exactDeleteResult(envelope.result, intent)) {
      fail('provider_mismatch', intent.kind, 'unknown');
    }
    return deepFreeze({
      schemaVersion: 1,
      status: 'submitted',
      action: intent.kind,
      attemptId: parsedArm.attemptId,
      intentSha256: parsedArm.intentSha256,
      locator: intent.locator,
    });
  }
  if (response.status >= 400 && response.status < 500 && envelope?.success === false &&
    providerErrors(envelope.errors) && isEmpty(envelope.messages) && envelope.result === null &&
    envelope.resultInfo === undefined) {
    fail('provider_rejected', intent.kind, 'rejected');
  }
  return fail('provider_unknown', intent.kind, 'unknown');
}

export async function parseHostedUninstallManagementDeleteSubmission<Input>(
  context: HostedUninstallManagementContext,
  intent: HostedUninstallManagementDeleteIntent,
  prerequisites: HostedUninstallManagementDeletePrerequisites,
  arm: HostedUninstallManagementDeleteArm,
  value: Input,
): Promise<HostedUninstallManagementDeleteSubmission | null> {
  const parsedArm = await parseHostedUninstallManagementDeleteArm(context, intent, prerequisites, arm);
  const candidate = v.safeParse(deleteSubmissionSchema, value);
  if (!parsedArm || !candidate.success || candidate.output.action !== intent.kind ||
    candidate.output.attemptId !== parsedArm.attemptId ||
    candidate.output.intentSha256 !== parsedArm.intentSha256 ||
    !canonicalEqual(candidate.output.locator, intent.locator)) return null;
  return deepFreeze({
    schemaVersion: 1,
    status: 'submitted',
    action: intent.kind,
    attemptId: parsedArm.attemptId,
    intentSha256: parsedArm.intentSha256,
    locator: intent.locator,
  });
}

function absenceStages(
  action: HostedUninstallManagementDeleteAction,
): readonly [CloudflareUninstallManagementStage, CloudflareUninstallManagementStage] {
  if (action === 'management_custom_domain_delete') {
    return ['management_custom_domain_absence_get', 'management_custom_domain_absence_list'];
  }
  if (action === 'management_admin_policy_delete') {
    return ['management_admin_policy_absence_get', 'management_admin_policy_absence_list'];
  }
  return ['management_access_application_absence_get', 'management_access_application_absence_list'];
}

async function requireId404AndListAbsence(
  call: PreparedCall,
  expected: Projection,
  action: HostedUninstallManagementDeleteAction,
  getStageOverride?: CloudflareUninstallManagementStage,
  listStageOverride?: CloudflareUninstallManagementStage,
): Promise<void> {
  const [defaultGetStage, defaultListStage] = absenceStages(action);
  const getStage = getStageOverride ?? defaultGetStage;
  const listStage = listStageOverride ?? defaultListStage;
  let getUrl: URL;
  if (action === 'management_custom_domain_delete') {
    getUrl = accountUrl(expected.accountId, `/workers/domains/${encodeURIComponent(expected.domainId)}`);
  } else if (action === 'management_admin_policy_delete') {
    getUrl = accountUrl(
      expected.accountId,
      `/access/apps/${encodeURIComponent(expected.applicationId)}/policies/${encodeURIComponent(expected.policyId)}`,
    );
  } else {
    getUrl = accountUrl(expected.accountId, `/access/apps/${encodeURIComponent(expected.applicationId)}`);
  }

  const getResponse = await request(call, getStage, getUrl, 'GET');
  if (!exactAbsent(getResponse)) {
    const envelope = parseEnvelope(getResponse.value);
    if (getResponse.status === 200 && envelope?.success === true && isEmpty(envelope.errors) && isEmpty(envelope.messages)) {
      if (envelope.resultInfo !== undefined) fail('provider_unknown', getStage, 'unknown');
      fail('delete_not_converged', getStage, 'rejected');
    }
    if (getResponse.status >= 400 && getResponse.status < 500 && envelope?.success === false &&
      providerErrors(envelope.errors) && isEmpty(envelope.messages) && envelope.result === null &&
      envelope.resultInfo === undefined) {
      fail('provider_rejected', getStage, 'rejected');
    }
    fail('provider_unknown', getStage, 'unknown');
  }
  const values = action === 'management_custom_domain_delete'
    ? await collectCustomDomainsSinglePage(call, listStage, expected)
    : action === 'management_admin_policy_delete'
      ? await collectList(call, listStage, (page) => policyListUrl(expected, page), 'unfiltered')
      : await collectList(call, listStage, (page) => applicationListUrl(expected, page), 'filtered');
  if (values.length > 0) fail('replacement_detected', listStage, 'rejected');
}

function recoveryStages(
  action: HostedUninstallManagementDeleteAction,
): readonly [CloudflareUninstallManagementStage, CloudflareUninstallManagementStage] {
  if (action === 'management_custom_domain_delete') {
    return ['management_custom_domain_recovery_get', 'management_custom_domain_recovery_list'];
  }
  if (action === 'management_admin_policy_delete') {
    return ['management_admin_policy_recovery_get', 'management_admin_policy_recovery_list'];
  }
  return ['management_access_application_recovery_get', 'management_access_application_recovery_list'];
}

async function collectRecoveryList(
  call: PreparedCall,
  expected: Projection,
  action: HostedUninstallManagementDeleteAction,
  stage: CloudflareUninstallManagementStage,
): Promise<readonly BoundaryObject[]> {
  if (action === 'management_custom_domain_delete') {
    return collectCustomDomainsSinglePage(call, stage, expected);
  }
  if (action === 'management_admin_policy_delete') {
    return collectList(call, stage, (page) => policyListUrl(expected, page), 'unfiltered');
  }
  return collectList(call, stage, (page) => applicationListUrl(expected, page), 'filtered');
}

function recoveryGetUrl(expected: Projection, action: HostedUninstallManagementDeleteAction): URL {
  if (action === 'management_custom_domain_delete') {
    return accountUrl(expected.accountId, `/workers/domains/${encodeURIComponent(expected.domainId)}`);
  }
  if (action === 'management_admin_policy_delete') {
    return accountUrl(
      expected.accountId,
      `/access/apps/${encodeURIComponent(expected.applicationId)}/policies/${encodeURIComponent(expected.policyId)}`,
    );
  }
  return accountUrl(expected.accountId, `/access/apps/${encodeURIComponent(expected.applicationId)}`);
}

function exactRecoveryOwnership(
  value: BoundaryValue,
  expected: Projection,
  action: HostedUninstallManagementDeleteAction,
): HostedUninstallManagementProviderOwnership | null {
  if (action === 'management_custom_domain_delete') {
    const domain = exactDomain(value, expected);
    return domain ? providerOwnershipObservation(expected, action, domain) : null;
  }
  if (action === 'management_admin_policy_delete') {
    return exactPolicy(value, expected) ? providerOwnershipObservation(expected, action) : null;
  }
  return exactApplication(value, expected) ? providerOwnershipObservation(expected, action) : null;
}

async function readDeleteRecoveryState(
  call: PreparedCall,
  expected: Projection,
  action: HostedUninstallManagementDeleteAction,
): Promise<{ readonly status: 'absent' } | {
  readonly status: 'still_present';
  readonly providerOwnership: HostedUninstallManagementProviderOwnership;
}> {
  const [getStage, listStage] = recoveryStages(action);
  const response = await request(call, getStage, recoveryGetUrl(expected, action), 'GET');
  if (exactAbsent(response)) {
    const values = await collectRecoveryList(call, expected, action, listStage);
    if (values.length > 0) fail('replacement_detected', listStage, 'rejected');
    return Object.freeze({ status: 'absent' });
  }
  const envelope = parseEnvelope(response.value);
  if (response.status === 200 && envelope?.success === true && isEmpty(envelope.errors) &&
    isEmpty(envelope.messages) && envelope.resultInfo === undefined) {
    const providerOwnership = exactRecoveryOwnership(envelope.result, expected, action);
    if (!providerOwnership) fail('provider_mismatch', getStage, 'rejected');
    const values = await collectRecoveryList(call, expected, action, listStage);
    if (values.length > 1) fail('provider_ambiguous', listStage, 'rejected');
    if (values.length !== 1) fail('replacement_detected', listStage, 'rejected');
    const listedOwnership = exactRecoveryOwnership(values[0], expected, action);
    if (!listedOwnership || !canonicalEqual(providerOwnership, listedOwnership)) {
      fail('provider_mismatch', listStage, 'rejected');
    }
    return deepFreeze({ status: 'still_present', providerOwnership });
  }
  if (response.status >= 400 && response.status < 500 && envelope?.success === false &&
    providerErrors(envelope.errors) && isEmpty(envelope.messages) && envelope.result === null &&
    envelope.resultInfo === undefined) fail('provider_rejected', getStage, 'rejected');
  return fail('provider_unknown', getStage, 'unknown');
}

async function buildAbsenceEvidence(
  active: Projection,
  action: HostedUninstallManagementDeleteAction,
): Promise<HostedUninstallManagementAbsenceEvidence> {
  const semantic = {
    schemaVersion: 1,
    status: 'absent',
    action,
    uninstallPlanId: active.uninstallPlanId,
    uninstallPlanHash: active.uninstallPlanHash,
    uninstallAuthorityHash: active.uninstallAuthorityHash,
    installBindingHash: active.installBindingHash,
    installConvergenceHash: active.installConvergenceHash,
    attemptId: active.attemptId,
    ownershipMarker: active.ownershipMarker,
    accountId: active.accountId,
    locator: canonicalLocator(active, action),
    proof: 'id_get_404_and_complete_list_absence',
  } as const;
  return deepFreeze({ ...semantic, evidenceSha256: await sha256(canonicalJson(semantic)) });
}

export async function verifyHostedUninstallManagementDeleteAbsence(
  context: HostedUninstallManagementContext,
  intentInput: HostedUninstallManagementDeleteIntent,
  prerequisites: HostedUninstallManagementDeletePrerequisites,
  callInput: CloudflareUninstallManagementCall,
): Promise<HostedUninstallManagementAbsenceEvidence> {
  const active = await validateContext(context, 'validate');
  const { intent } = await requireIntent(context, intentInput, prerequisites, 'approved');
  const call = prepareCall(callInput, 'validate');
  await requireId404AndListAbsence(call, active, intent.kind);
  return buildAbsenceEvidence(active, intent.kind);
}

export async function parseHostedUninstallManagementAbsenceEvidence<Input>(
  context: HostedUninstallManagementContext,
  intent: HostedUninstallManagementDeleteIntent,
  prerequisites: HostedUninstallManagementDeletePrerequisites,
  value: Input,
): Promise<HostedUninstallManagementAbsenceEvidence | null> {
  try {
    const active = await validateContext(context, 'validate');
    const parsedIntent = await requireIntent(context, intent, prerequisites, 'approved');
    if (!stableAuthorityMatches(parsedIntent.expected, active)) return null;
    return await parseApprovedAbsenceForAction(active, parsedIntent.intent.kind, value);
  } catch {
    return null;
  }
}

/**
 * Read-only recovery for a durably send-armed historical delete. The caller
 * must terminally record `still_present/not_applied` before preparing a new
 * current-attempt mutation; the historical DELETE must never be replayed.
 */
export async function recoverHostedUninstallManagementDeleteOutcome(
  context: HostedUninstallManagementContext,
  intentInput: HostedUninstallManagementDeleteIntent,
  armInput: HostedUninstallManagementDeleteArm,
  prerequisites: HostedUninstallManagementDeletePrerequisites,
  callInput: CloudflareUninstallManagementCall,
): Promise<HostedUninstallManagementDeleteRecoveryEvidence> {
  const active = await validateContext(context, 'validate');
  const { intent } = await requireIntent(context, intentInput, prerequisites, 'approved');
  const arm = await parseHostedUninstallManagementDeleteArm(context, intent, prerequisites, armInput);
  if (!arm) fail('invalid_input', 'validate', 'not_sent');
  const call = prepareCall(callInput, 'validate');
  const state = await readDeleteRecoveryState(call, active, intent.kind);
  if (state.status === 'absent') return buildAbsenceEvidence(active, intent.kind);
  return buildStillPresentEvidence(active, intent, arm, state.providerOwnership);
}

export async function parseHostedUninstallManagementDeleteRecoveryEvidence<Input>(
  context: HostedUninstallManagementContext,
  intentInput: HostedUninstallManagementDeleteIntent,
  armInput: HostedUninstallManagementDeleteArm,
  prerequisites: HostedUninstallManagementDeletePrerequisites,
  value: Input,
): Promise<HostedUninstallManagementDeleteRecoveryEvidence | null> {
  try {
    const active = await validateContext(context, 'validate');
    const { intent } = await requireIntent(context, intentInput, prerequisites, 'approved');
    const arm = await parseHostedUninstallManagementDeleteArm(context, intent, prerequisites, armInput);
    if (!arm) return null;
    const absence = v.safeParse(absenceEvidenceSchema, value);
    if (absence.success) {
      return parseApprovedAbsenceForAction(active, intent.kind, absence.output);
    }
    const candidate = v.safeParse(stillPresentEvidenceSchema, value);
    if (!candidate.success) return null;
    const providerOwnership = parseProviderOwnershipObservation(
      active,
      intent.kind,
      candidate.output.providerOwnership,
    );
    if (!providerOwnership) return null;
    const canonical = await buildStillPresentEvidence(active, intent, arm, providerOwnership);
    return canonicalEqual(candidate.output, canonical) ? canonical : null;
  } catch {
    return null;
  }
}

interface FinalNamespaceItem {
  readonly id: string;
  readonly className: string;
  readonly name: string;
  readonly script: string;
  readonly useSqlite: boolean;
}

function exactFinalNamespaceItem(value: BoundaryValue): FinalNamespaceItem | null {
  const candidate = v.safeParse(finalNamespaceItemSchema, value);
  if (!candidate.success) return null;
  return Object.freeze({
    id: candidate.output.id,
    className: candidate.output.class,
    name: candidate.output.name,
    script: candidate.output.script,
    useSqlite: candidate.output.use_sqlite,
  });
}

async function readFinalNamespaceSnapshot(call: PreparedCall, expected: Projection): Promise<{
  readonly items: readonly FinalNamespaceItem[];
  readonly count: number;
  readonly sha256: string;
}> {
  const values = await collectList(
    call,
    'final_namespace_list',
    (page) => {
      const url = accountUrl(expected.accountId, '/workers/durable_objects/namespaces');
      url.searchParams.set('page', String(page));
      url.searchParams.set('per_page', String(PAGE_SIZE));
      return url;
    },
    'unfiltered',
  );
  const items: FinalNamespaceItem[] = [];
  for (const value of values) {
    const item = exactFinalNamespaceItem(value);
    if (!item) fail('provider_mismatch', 'final_namespace_list', 'rejected');
    if (item.id === expected.namespaceId ||
      (item.script === expected.workerName && item.className === 'AdminState')) {
      fail('management_residue', 'final_namespace_list', 'rejected');
    }
    items.push(item);
  }
  items.sort((left, right) => left.id.localeCompare(right.id));
  const frozen = Object.freeze(items);
  return Object.freeze({ items: frozen, count: frozen.length, sha256: await sha256(canonicalJson(frozen)) });
}

function namespaceSnapshotEvidence(
  expected: Projection,
  uninstallCycleId: string,
  observation: 1 | 2,
  accountNamespaceCount: number,
  snapshotSha256: string,
): HostedUninstallManagementNamespaceAbsenceSnapshot {
  return deepFreeze({
    schemaVersion: 1,
    kind: 'admin_state_namespace_absence_snapshot',
    observation,
    accountId: expected.accountId,
    workerName: expected.workerName,
    namespaceId: expected.namespaceId,
    uninstallCycleId,
    accountNamespaceCount,
    snapshotSha256,
  });
}

function parseNamespaceSnapshotEvidence<Input>(
  expected: Projection,
  uninstallCycleId: string,
  observation: 1 | 2,
  value: Input,
): HostedUninstallManagementNamespaceAbsenceSnapshot | null {
  const candidate = v.safeParse(namespaceSnapshotSchema, value);
  if (!candidate.success || candidate.output.observation !== observation ||
    candidate.output.accountId !== expected.accountId || candidate.output.workerName !== expected.workerName ||
    candidate.output.namespaceId !== expected.namespaceId ||
    candidate.output.uninstallCycleId !== uninstallCycleId) return null;
  return namespaceSnapshotEvidence(
    expected,
    uninstallCycleId,
    observation,
    candidate.output.accountNamespaceCount,
    candidate.output.snapshotSha256,
  );
}

async function buildNoManagedResidueEvidence(
  expected: Projection,
  deletionEvidence: HostedUninstallManagementNoManagedResidueEvidence['deletionEvidence'],
  workerDeletion: WorkerDeletionRecoveryProof,
  namespaceRetirement: AdminStateNamespaceRetirementProof,
  namespaceSnapshots: readonly [
    HostedUninstallManagementNamespaceAbsenceSnapshot,
    HostedUninstallManagementNamespaceAbsenceSnapshot,
  ],
): Promise<HostedUninstallManagementNoManagedResidueEvidence> {
  const semantic = deepFreeze({
    schemaVersion: 1 as const,
    kind: 'hosted_uninstall_no_managed_residue_evidence' as const,
    deletionEvidence,
    workerDeletion,
    namespaceRetirement,
    namespaceSnapshots,
  });
  if (workerDeletion.accountId !== expected.accountId || workerDeletion.workerName !== expected.workerName ||
    workerDeletion.workerId !== expected.workerId || workerDeletion.namespaceId !== expected.namespaceId ||
    namespaceRetirement.accountId !== expected.accountId || namespaceRetirement.workerName !== expected.workerName ||
    namespaceRetirement.workerId !== expected.workerId || namespaceRetirement.namespaceId !== expected.namespaceId ||
    workerDeletion.uninstallCycleId !== namespaceRetirement.uninstallCycleId ||
    workerDeletion.retirementVersionId !== namespaceRetirement.retirementVersionId ||
    namespaceSnapshots[0].uninstallCycleId !== workerDeletion.uninstallCycleId ||
    namespaceSnapshots[1].uninstallCycleId !== workerDeletion.uninstallCycleId ||
    namespaceSnapshots[0].accountNamespaceCount !== namespaceSnapshots[1].accountNamespaceCount ||
    namespaceSnapshots[0].snapshotSha256 !== namespaceSnapshots[1].snapshotSha256) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  return deepFreeze({ ...semantic, evidenceSha256: await sha256(canonicalJson(semantic)) });
}

export async function parseHostedUninstallManagementNoManagedResidueEvidence<Input>(
  context: HostedUninstallManagementContext,
  value: Input,
): Promise<HostedUninstallManagementNoManagedResidueEvidence | null> {
  let expected: Projection;
  try {
    expected = await validateContext(context, 'validate');
  } catch {
    return null;
  }
  const candidate = v.safeParse(noManagedResidueEvidenceShellSchema, value);
  if (!candidate.success) return null;
  const deletionEvidence: HostedUninstallManagementAbsenceEvidence[] = [];
  for (const [index, action] of HOSTED_UNINSTALL_MANAGEMENT_DELETE_ORDER.entries()) {
    const parsed = await parseApprovedAbsenceForAction(expected, action, candidate.output.deletionEvidence[index]);
    if (!parsed) return null;
    deletionEvidence.push(parsed);
  }
  const workerDeletion = parseWorkerDeletionRecoveryProof(candidate.output.workerDeletion);
  const namespaceRetirement = parseAdminStateNamespaceRetirementProof(candidate.output.namespaceRetirement);
  if (!workerDeletion || !namespaceRetirement) return null;
  const first = parseNamespaceSnapshotEvidence(
    expected,
    workerDeletion.uninstallCycleId,
    1,
    candidate.output.namespaceSnapshots[0],
  );
  const second = parseNamespaceSnapshotEvidence(
    expected,
    workerDeletion.uninstallCycleId,
    2,
    candidate.output.namespaceSnapshots[1],
  );
  if (!first || !second) return null;
  const [firstDeletion, secondDeletion, thirdDeletion] = deletionEvidence;
  if (!firstDeletion || !secondDeletion || !thirdDeletion) return null;
  const deletionEvidenceTuple: HostedUninstallManagementNoManagedResidueEvidence['deletionEvidence'] =
    Object.freeze([firstDeletion, secondDeletion, thirdDeletion]);
  try {
    const parsed = await buildNoManagedResidueEvidence(
      expected,
      deletionEvidenceTuple,
      workerDeletion,
      namespaceRetirement,
      Object.freeze([first, second]),
    );
    return canonicalEqual(candidate.output, parsed) &&
      candidate.output.evidenceSha256 === parsed.evidenceSha256 ? parsed : null;
  } catch {
    return null;
  }
}

function noManagedResidueSemantic(
  expected: Projection,
  uninstallCycleId: string,
  deletionEvidenceSha256: string,
  workerDeletionProofSha256: string,
  namespaceRetirementProofSha256: string,
  namespaceSnapshotSha256: string,
  evidence: HostedUninstallManagementNoManagedResidueEvidence,
): Omit<HostedUninstallManagementNoManagedResidueResult, 'proofSha256'> {
  return deepFreeze({
    schemaVersion: 1,
    status: 'no_ankka_managed_residue',
    uninstallPlanId: expected.uninstallPlanId,
    uninstallPlanHash: expected.uninstallPlanHash,
    uninstallAuthorityHash: expected.uninstallAuthorityHash,
    installBindingHash: expected.installBindingHash,
    installConvergenceHash: expected.installConvergenceHash,
    attemptId: expected.attemptId,
    ownershipMarker: expected.ownershipMarker,
    managementHostname: expected.managementHostname,
    dnsAbsenceObservations: 2,
    advancedCertificate: 'provider_retained_out_of_scope_not_observable_or_deleted',
    uninstallCycleId,
    deletionEvidenceSha256,
    workerDeletionProofSha256,
    namespaceRetirementProofSha256,
    namespaceSnapshotSha256,
    evidence,
  });
}

export async function verifyHostedUninstallManagementNoManagedResidue(
  context: HostedUninstallManagementContext,
  deletionEvidence: readonly HostedUninstallManagementAbsenceEvidence[],
  lifecycleEvidence: HostedUninstallManagementLifecycleEvidence,
  callInput: CloudflareUninstallManagementCall,
): Promise<HostedUninstallManagementNoManagedResidueResult> {
  const expected = await validateContext(context, 'validate');
  if (!Array.isArray(deletionEvidence) || deletionEvidence.length !== 3) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  const parsedDeletionEvidence: HostedUninstallManagementAbsenceEvidence[] = [];
  for (const [index, action] of HOSTED_UNINSTALL_MANAGEMENT_DELETE_ORDER.entries()) {
    const parsed = await parseApprovedAbsenceForAction(expected, action, deletionEvidence[index]);
    if (!parsed) fail('invalid_input', 'validate', 'not_sent');
    parsedDeletionEvidence.push(parsed);
  }
  const [firstDeletion, secondDeletion, thirdDeletion] = parsedDeletionEvidence;
  if (!firstDeletion || !secondDeletion || !thirdDeletion) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  const deletionEvidenceTuple: HostedUninstallManagementNoManagedResidueEvidence['deletionEvidence'] =
    Object.freeze([firstDeletion, secondDeletion, thirdDeletion]);
  if (!isRecord(lifecycleEvidence) || !exactKeys(lifecycleEvidence, [
    'namespaceRetirement', 'workerDeleteIntent',
  ])) fail('invalid_input', 'validate', 'not_sent');
  const workerDeleteIntent = await parseWorkerDeleteMutationIntent(lifecycleEvidence.workerDeleteIntent);
  const namespaceRetirement = parseAdminStateNamespaceRetirementProof(lifecycleEvidence.namespaceRetirement);
  if (!workerDeleteIntent || !namespaceRetirement ||
    workerDeleteIntent.accountId !== expected.accountId || workerDeleteIntent.workerName !== expected.workerName ||
    workerDeleteIntent.workerId !== expected.workerId || workerDeleteIntent.namespaceId !== expected.namespaceId ||
    !canonicalEqual(workerDeleteIntent.retirementProof, namespaceRetirement)) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  const call = prepareCall(callInput, 'validate');
  // The policy evidence was obtained while its exact parent application still
  // existed. Once the application is absent, Cloudflare has no independent
  // nested policy list surface; the exact earlier proof is therefore retained.
  await requireId404AndListAbsence(
    call,
    expected,
    'management_custom_domain_delete',
    'final_custom_domain_get',
    'final_custom_domain_list',
  );
  await requireId404AndListAbsence(
    call,
    expected,
    'management_access_application_delete',
    'final_access_application_get',
    'final_access_application_list',
  );
  await requireNoDnsOrRouteCollision(
    call,
    expected,
    'final_dns_list',
    'final_worker_route_list',
    'management_residue',
    'absent',
  );
  let workerAbsence: WorkerDeletionRecoveryProof;
  try {
    workerAbsence = await recoverWorkerDeletionOutcome(workerDeleteIntent, callInput);
  } catch {
    return fail('provider_unknown', 'final_worker_delete_recovery', 'unknown');
  }
  const firstNamespace = await readFinalNamespaceSnapshot(call, expected);
  const secondNamespace = await readFinalNamespaceSnapshot(call, expected);
  if (firstNamespace.sha256 !== secondNamespace.sha256 ||
    !canonicalEqual(firstNamespace.items, secondNamespace.items)) {
    fail('provider_unknown', 'final_namespace_list', 'unknown');
  }
  const namespaceSnapshots: HostedUninstallManagementNoManagedResidueEvidence['namespaceSnapshots'] = Object.freeze([
    namespaceSnapshotEvidence(
      expected,
      workerDeleteIntent.uninstallCycleId,
      1,
      firstNamespace.count,
      firstNamespace.sha256,
    ),
    namespaceSnapshotEvidence(
      expected,
      workerDeleteIntent.uninstallCycleId,
      2,
      secondNamespace.count,
      secondNamespace.sha256,
    ),
  ]);
  const evidence = await buildNoManagedResidueEvidence(
    expected,
    deletionEvidenceTuple,
    workerAbsence,
    namespaceRetirement,
    namespaceSnapshots,
  );
  const semantic = noManagedResidueSemantic(
    expected,
    workerDeleteIntent.uninstallCycleId,
    await sha256(canonicalJson(evidence.deletionEvidence)),
    await sha256(canonicalJson(evidence.workerDeletion)),
    await sha256(canonicalJson(evidence.namespaceRetirement)),
    await sha256(canonicalJson(evidence.namespaceSnapshots)),
    evidence,
  );
  return deepFreeze({ ...semantic, proofSha256: await sha256(canonicalJson(semantic)) });
}

export async function parseHostedUninstallManagementNoManagedResidueResult<Input>(
  context: HostedUninstallManagementContext,
  value: Input,
): Promise<HostedUninstallManagementNoManagedResidueResult | null> {
  let expected: Projection;
  try {
    expected = await validateContext(context, 'validate');
  } catch {
    return null;
  }
  const candidate = v.safeParse(noManagedResidueResultShellSchema, value);
  if (!candidate.success) return null;
  const evidence = await parseHostedUninstallManagementNoManagedResidueEvidence(context, candidate.output.evidence);
  if (!evidence) return null;
  const semantic = noManagedResidueSemantic(
    expected,
    evidence.workerDeletion.uninstallCycleId,
    await sha256(canonicalJson(evidence.deletionEvidence)),
    await sha256(canonicalJson(evidence.workerDeletion)),
    await sha256(canonicalJson(evidence.namespaceRetirement)),
    await sha256(canonicalJson(evidence.namespaceSnapshots)),
    evidence,
  );
  const parsed = deepFreeze({ ...semantic, proofSha256: candidate.output.proofSha256 });
  return canonicalEqual(candidate.output, parsed) && parsed.proofSha256 === await sha256(canonicalJson(semantic))
    ? parsed
    : null;
}
