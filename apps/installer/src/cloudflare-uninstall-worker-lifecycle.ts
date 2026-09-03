import * as v from 'valibot';

import {
  boundaryObjectSchema,
  boundaryValueSchema,
  type BoundaryObject,
  type BoundaryValue,
} from './boundary';
import { canonicalJson } from './canonical-json';
import { CLOUDFLARE_API_ORIGIN } from './constants';
import type {
  AdminStateDurableObjectNamespaceLocator,
  CloudflareDirectUploadCall,
} from './cloudflare-worker-direct-upload';
import type {
  VerifiedGatewayWorkerReleaseSet,
} from './release-direct-upload-adapter';
import { APPROVED_CLOUDFLARE_RELEASE_CONTRACT } from './release-manifest';

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const WORKER_ID = /^[a-f0-9]{32}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const RELEASE = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const UNINSTALL_CYCLE_ID = /^uninstall-[a-f0-9]{24}$/u;
const SAFE_TOKEN = /^[A-Za-z0-9._~-]+$/u;
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;

const EXACT_COMPATIBILITY_DATE = '2026-08-08' as const;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_RELEASE_BYTES = 32 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_VERSION_RESPONSE_BYTES = 64 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const VERSION_PAGE_SIZE = 100;
const MAX_VERSION_PAGES = 100;

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 31 || code === 127) return true;
  }
  return false;
}
const NAMESPACE_PAGE_SIZE = 1_000;
const MAX_NAMESPACE_PAGES = 100;
const MAX_NAMESPACE_COUNT = NAMESPACE_PAGE_SIZE * MAX_NAMESPACE_PAGES;
const MAX_NAMESPACE_RESPONSE_BYTES = 512 * 1024;
const MAX_DEPLOYMENTS = 1_000;
const MAX_SCRIPTS = 10_000;
const SCRIPT_PAGE_SIZE = 100;
const MAX_SCRIPT_PAGES = MAX_SCRIPTS / SCRIPT_PAGE_SIZE;

export const UNINSTALL_CLEANUP_VARIABLE_NAMES = Object.freeze([
  'ANKKA_GATEWAY_RELEASE',
  'ANKKA_GATEWAY_RELEASE_SHA256',
  'CLOUDFLARE_ACCOUNT_ID',
  'CLOUDFLARE_ZONE_ID',
  'CLOUDFLARE_ZONE_NAME',
  'ZERO_TRUST_READY',
] as const);

const accountIdSchema = v.pipe(v.string(), v.regex(ACCOUNT_ID));
const workerIdSchema = v.pipe(v.string(), v.regex(WORKER_ID));
const workerNameSchema = v.pipe(v.string(), v.regex(WORKER_NAME));
const uuidSchema = v.pipe(v.string(), v.regex(UUID));
const sha256Schema = v.pipe(v.string(), v.regex(SHA256));
const uninstallCycleIdSchema = v.pipe(v.string(), v.regex(UNINSTALL_CYCLE_ID));
const versionSubmissionSchema = v.strictObject({
  kind: v.literal('uninstall_worker_version'),
  stage: v.picklist(['cleanup', 'retirement']),
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workerId: workerIdSchema,
  uninstallCycleId: uninstallCycleIdSchema,
  versionId: uuidSchema,
  requestHash: sha256Schema,
  correlationTag: v.string(),
});
const deploymentSubmissionSchema = v.strictObject({
  kind: v.literal('uninstall_worker_deployment'),
  stage: v.picklist(['cleanup', 'retirement', 'restore_clean']),
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workerId: workerIdSchema,
  uninstallCycleId: uninstallCycleIdSchema,
  versionId: uuidSchema,
  deploymentId: uuidSchema,
  requestHash: sha256Schema,
  correlationTag: v.string(),
});
const workerDeleteSubmissionSchema = v.strictObject({
  kind: v.literal('uninstall_worker_delete'),
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workerId: workerIdSchema,
  uninstallCycleId: uninstallCycleIdSchema,
  namespaceId: accountIdSchema,
  retirementVersionId: uuidSchema,
  retirementProofCommitment: sha256Schema,
  requestHash: sha256Schema,
  correlationTag: v.string(),
});
const directUploadTransportSchema = v.custom<CloudflareDirectUploadCall['transport']>(
  (value) => v.is(v.function(), value),
);
const directUploadCallSchema = v.object({
  accessToken: v.pipe(v.string(), v.minLength(20), v.maxLength(8_192), v.regex(SAFE_TOKEN)),
  transport: directUploadTransportSchema,
  timeoutMs: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(100), v.maxValue(60_000))),
});
const providerEnvelopeSchema = v.strictObject({
  errors: v.nullable(v.array(boundaryValueSchema)),
  messages: v.nullable(v.array(boundaryValueSchema)),
  result: boundaryValueSchema,
  success: v.boolean(),
});
const providerErrorListSchema = v.pipe(v.array(v.looseObject({
  code: v.pipe(v.number(), v.safeInteger()),
  message: v.pipe(v.string(), v.minLength(1), v.maxLength(2_048)),
})), v.minLength(1), v.maxLength(16));
const emptyProviderListSchema = v.union([
  v.null(),
  v.pipe(v.array(boundaryValueSchema), v.length(0)),
]);
const rawResultSchema = v.object({ result: v.object({ id: v.string() }) });
const moduleCommitmentSchema = v.strictObject({
  name: v.string(),
  contentType: v.string(),
  contentSha256: sha256Schema,
  byteLength: v.pipe(v.number(), v.safeInteger(), v.minValue(1), v.maxValue(MAX_FILE_BYTES)),
});
const cleanupVariableHashSchema = v.strictObject({
  name: v.picklist(UNINSTALL_CLEANUP_VARIABLE_NAMES),
  valueSha256: sha256Schema,
});
const cleanupContractSchema = v.strictObject({
  assets: v.literal('absent'),
  defaultApplication: v.literal('absent'),
  durableObject: v.strictObject({
    binding: v.literal('ADMIN_STATE'),
    className: v.literal('AdminState'),
    namespaceId: accountIdSchema,
    storage: v.literal('sqlite'),
  }),
  exports: v.strictObject({
    AdminState: v.strictObject({ type: v.literal('durable-object'), storage: v.literal('sqlite') }),
  }),
  uninstallNonceBinding: v.literal('present'),
  variableValueHashes: v.pipe(
    v.array(cleanupVariableHashSchema),
    v.length(UNINSTALL_CLEANUP_VARIABLE_NAMES.length),
  ),
});
const retirementContractSchema = v.strictObject({
  assets: v.literal('absent'),
  bindings: v.tuple([]),
  defaultApplication: v.literal('absent'),
  exports: v.strictObject({
    AdminState: v.strictObject({ type: v.literal('durable-object'), state: v.literal('deleted') }),
  }),
});
const recoveryBaseSchemas = {
  kind: v.literal('uninstall_version_recovery'),
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workerId: workerIdSchema,
  uninstallCycleId: uninstallCycleIdSchema,
  release: v.pipe(v.string(), v.regex(RELEASE)),
  artifactSha256: sha256Schema,
  componentSha256: sha256Schema,
  requestHash: sha256Schema,
  correlationTag: v.string(),
  compatibilityDate: v.literal(EXACT_COMPATIBILITY_DATE),
  compatibilityFlags: v.tuple([]),
  mainModule: v.literal('index.js'),
  modules: v.pipe(v.array(moduleCommitmentSchema), v.minLength(1), v.maxLength(1_000)),
};
const cleanupRecoverySchema = v.strictObject({
  ...recoveryBaseSchemas,
  stage: v.literal('cleanup'),
  namespaceId: accountIdSchema,
  contract: cleanupContractSchema,
});
const retirementRecoverySchema = v.strictObject({
  ...recoveryBaseSchemas,
  stage: v.literal('retirement'),
  contract: retirementContractSchema,
});
const versionRecoverySchema = v.union([cleanupRecoverySchema, retirementRecoverySchema]);
const deploymentBodySchema = v.strictObject({
  annotations: v.strictObject({ 'workers/message': v.string() }),
  strategy: v.literal('percentage'),
  versions: v.tuple([v.strictObject({ percentage: v.literal(100), version_id: uuidSchema })]),
});
const deploymentIntentSchema = v.strictObject({
  kind: v.literal('uninstall_deployment'),
  stage: v.picklist(['cleanup', 'retirement', 'restore_clean']),
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workerId: workerIdSchema,
  uninstallCycleId: uninstallCycleIdSchema,
  versionId: uuidSchema,
  requestHash: sha256Schema,
  correlationTag: v.string(),
  body: deploymentBodySchema,
});
const prepareDeploymentInputSchema = v.strictObject({
  stage: v.picklist(['cleanup', 'retirement', 'restore_clean']),
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workerId: workerIdSchema,
  uninstallCycleId: uninstallCycleIdSchema,
  versionId: uuidSchema,
});
const deploymentAnnotationsSchema = v.strictObject({
  'workers/message': v.optional(v.pipe(v.string(), v.minLength(1), v.maxLength(256))),
  'workers/triggered_by': v.optional(v.pipe(v.string(), v.minLength(1), v.maxLength(256))),
});
const deploymentObservationSchema = v.strictObject({
  annotations: v.optional(deploymentAnnotationsSchema),
  author_email: v.optional(v.pipe(v.string(), v.minLength(1), v.maxLength(320))),
  created_on: v.string(),
  id: uuidSchema,
  source: v.literal('api'),
  strategy: v.literal('percentage'),
  versions: v.pipe(v.array(v.strictObject({
    percentage: v.pipe(v.number(), v.minValue(0), v.maxValue(100)),
    version_id: uuidSchema,
  })), v.minLength(1), v.maxLength(100)),
});
const deploymentListResultSchema = v.strictObject({
  deployments: v.pipe(v.array(deploymentObservationSchema), v.maxLength(MAX_DEPLOYMENTS)),
});
const boundedNamespaceTextSchema = (maximum: number) => v.pipe(
  v.string(),
  v.minLength(1),
  v.maxLength(maximum),
  v.check((value) => !hasControlCharacter(value)),
);
const namespaceLocatorSchema = v.strictObject({
  accountId: accountIdSchema,
  namespaceId: accountIdSchema,
  namespaceName: boundedNamespaceTextSchema(256),
  workerName: workerNameSchema,
  className: v.literal('AdminState'),
  storage: v.literal('sqlite'),
});
const namespacePresenceProofSchema = v.strictObject({
  kind: v.literal('admin_state_namespace_presence'),
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workerId: workerIdSchema,
  uninstallCycleId: uninstallCycleIdSchema,
  namespaceId: accountIdSchema,
  namespaceName: boundedNamespaceTextSchema(256),
  className: v.literal('AdminState'),
  storage: v.literal('sqlite'),
  accountNamespaceCount: v.pipe(v.number(), v.safeInteger(), v.minValue(1), v.maxValue(MAX_NAMESPACE_COUNT)),
  snapshotSha256: sha256Schema,
});
const namespaceRetirementProofSchema = v.strictObject({
  kind: v.literal('admin_state_namespace_retirement'),
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workerId: workerIdSchema,
  uninstallCycleId: uninstallCycleIdSchema,
  namespaceId: accountIdSchema,
  retirementVersionId: uuidSchema,
  accountNamespaceCount: v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(MAX_NAMESPACE_COUNT)),
  firstSnapshotSha256: sha256Schema,
  secondSnapshotSha256: sha256Schema,
});
const namespaceRetiredInputSchema = v.strictObject({
  namespace: namespaceLocatorSchema,
  workerId: workerIdSchema,
  uninstallCycleId: uninstallCycleIdSchema,
  retirementRecovery: retirementRecoverySchema,
  retirementSubmission: versionSubmissionSchema,
  retirementDeploymentIntent: deploymentIntentSchema,
  retirementDeploymentSubmission: deploymentSubmissionSchema,
});
const namespacePresentInputSchema = v.strictObject({
  namespace: namespaceLocatorSchema,
  workerId: workerIdSchema,
  uninstallCycleId: uninstallCycleIdSchema,
});
const namespaceListItemSchema = v.strictObject({
  id: accountIdSchema,
  class: boundedNamespaceTextSchema(128),
  name: boundedNamespaceTextSchema(256),
  script: boundedNamespaceTextSchema(128),
  use_sqlite: v.boolean(),
});
const namespaceListPageSchema = v.strictObject({
  errors: v.nullable(v.array(boundaryValueSchema)),
  messages: v.nullable(v.array(boundaryValueSchema)),
  result: v.pipe(v.array(namespaceListItemSchema), v.maxLength(NAMESPACE_PAGE_SIZE)),
  result_info: v.strictObject({
    count: v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(NAMESPACE_PAGE_SIZE)),
    page: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
    per_page: v.literal(NAMESPACE_PAGE_SIZE),
    total_count: v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(MAX_NAMESPACE_COUNT)),
    total_pages: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(MAX_NAMESPACE_PAGES))),
  }),
  success: v.literal(true),
});
const verifiedReleaseModuleSchema = v.strictObject({
  bytes: v.custom<Uint8Array>((value) => value instanceof Uint8Array),
  contentType: v.string(),
  name: v.string(),
  sha256: sha256Schema,
});
const releaseSetIdentitySchema = v.strictObject({
  bootstrap: v.object({
    verification: v.literal('ed25519'),
    release: v.pipe(v.string(), v.regex(RELEASE)),
    artifactSha256: sha256Schema,
    componentSha256: sha256Schema,
  }),
  primary: v.object({
    verification: v.literal('ed25519'),
    release: v.pipe(v.string(), v.regex(RELEASE)),
    artifactSha256: sha256Schema,
  }),
  cleanup: v.object({
    verification: v.literal('ed25519'),
    release: v.pipe(v.string(), v.regex(RELEASE)),
    artifactSha256: sha256Schema,
    componentSha256: sha256Schema,
    variant: v.literal('cleanup'),
    worker: v.object({
      contract: boundaryObjectSchema,
      modules: v.pipe(v.array(verifiedReleaseModuleSchema), v.minLength(1), v.maxLength(1_000)),
    }),
  }),
  retirement: v.object({
    verification: v.literal('ed25519'),
    release: v.pipe(v.string(), v.regex(RELEASE)),
    artifactSha256: sha256Schema,
    componentSha256: sha256Schema,
    variant: v.literal('retirement'),
    worker: v.object({
      contract: boundaryObjectSchema,
      modules: v.pipe(v.array(verifiedReleaseModuleSchema), v.minLength(1), v.maxLength(1_000)),
    }),
  }),
});
const verifiedReleaseSetSchema = v.custom<VerifiedGatewayWorkerReleaseSet>(
  (value) => v.is(releaseSetIdentitySchema, value),
);
const cleanupVariablesSchema = v.strictObject({
  ANKKA_GATEWAY_RELEASE: boundedNamespaceTextSchema(4_096),
  ANKKA_GATEWAY_RELEASE_SHA256: boundedNamespaceTextSchema(4_096),
  CLOUDFLARE_ACCOUNT_ID: accountIdSchema,
  CLOUDFLARE_ZONE_ID: accountIdSchema,
  CLOUDFLARE_ZONE_NAME: v.pipe(boundedNamespaceTextSchema(4_096), v.regex(HOSTNAME)),
  ZERO_TRUST_READY: v.literal('true'),
});
const prepareCleanupVersionInputSchema = v.strictObject({
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workerId: workerIdSchema,
  namespaceId: accountIdSchema,
  uninstallCycleId: uninstallCycleIdSchema,
  releaseSet: verifiedReleaseSetSchema,
  variables: cleanupVariablesSchema,
  uninstallNonce: v.pipe(v.string(), v.minLength(32), v.maxLength(8_192), v.regex(SAFE_TOKEN)),
});
const prepareRetirementVersionInputSchema = v.strictObject({
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workerId: workerIdSchema,
  uninstallCycleId: uninstallCycleIdSchema,
  releaseSet: verifiedReleaseSetSchema,
});
const isoDateSchema = v.pipe(
  v.string(),
  v.minLength(20),
  v.maxLength(40),
  v.check((date) => Number.isFinite(Date.parse(date))),
);
const versionAnnotationsSchema = v.strictObject({
  'workers/message': v.optional(v.pipe(v.string(), v.minLength(1), v.maxLength(256))),
  'workers/tag': v.string(),
  'workers/triggered_by': v.optional(v.pipe(v.string(), v.minLength(1), v.maxLength(256))),
});
const versionSubmitBindingSchema = v.union([
  v.strictObject({
    name: v.literal('ADMIN_STATE'),
    type: v.literal('durable_object_namespace'),
    class_name: v.literal('AdminState'),
    namespace_id: accountIdSchema,
  }),
  v.strictObject({
    name: v.picklist(UNINSTALL_CLEANUP_VARIABLE_NAMES),
    type: v.literal('plain_text'),
    text: v.string(),
  }),
  v.strictObject({
    name: v.literal('ANKKA_UNINSTALL_NONCE'),
    type: v.literal('secret_text'),
    text: v.pipe(v.string(), v.minLength(32), v.maxLength(8_192), v.regex(SAFE_TOKEN)),
  }),
]);
const versionSubmitIntentSchema = v.strictObject({
  kind: v.literal('uninstall_version_submit'),
  stage: v.picklist(['cleanup', 'retirement']),
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workerId: workerIdSchema,
  uninstallCycleId: uninstallCycleIdSchema,
  requestHash: sha256Schema,
  correlationTag: v.string(),
  semanticCommitment: boundaryObjectSchema,
  body: v.strictObject({
    annotations: v.strictObject({ 'workers/tag': v.string() }),
    bindings: v.array(versionSubmitBindingSchema),
    compatibility_date: v.literal(EXACT_COMPATIBILITY_DATE),
    compatibility_flags: v.tuple([]),
    exports: boundaryObjectSchema,
    main_module: v.literal('index.js'),
    modules: v.array(v.strictObject({
      name: v.string(),
      content_type: v.string(),
      content_base64: v.string(),
    })),
  }),
});
const defaultWorkerExportSchema = v.strictObject({
  type: v.literal('worker'),
  state: v.optional(v.literal('created')),
  cache: v.optional(v.strictObject({ enabled: v.literal(false) })),
});
const activeExportsSchema = v.strictObject({
  AdminState: v.strictObject({
    type: v.literal('durable-object'),
    storage: v.literal('sqlite'),
    state: v.optional(v.literal('created')),
  }),
  default: v.optional(defaultWorkerExportSchema),
});
const retiredExportsSchema = v.strictObject({
  AdminState: v.optional(v.strictObject({
    type: v.literal('durable-object'),
    state: v.literal('deleted'),
  })),
  default: v.optional(defaultWorkerExportSchema),
});
const exportReconciliationSchema = v.strictObject({
  created: v.array(boundaryValueSchema),
  deleted: v.array(boundaryValueSchema),
  info: v.array(boundaryValueSchema),
  removable_entries: v.array(boundaryValueSchema),
  renamed: v.array(boundaryValueSchema),
  transfer_pending: v.array(boundaryValueSchema),
  transferred: v.array(boundaryValueSchema),
  updated: v.array(boundaryValueSchema),
  warnings: v.array(boundaryValueSchema),
});
const providerVersionBindingSchema = v.union([
  v.strictObject({
    name: v.literal('ADMIN_STATE'),
    type: v.literal('durable_object_namespace'),
    class_name: v.literal('AdminState'),
    namespace_id: v.optional(accountIdSchema),
  }),
  v.strictObject({
    name: v.picklist(UNINSTALL_CLEANUP_VARIABLE_NAMES),
    type: v.literal('plain_text'),
    text: v.string(),
  }),
  v.strictObject({ name: v.literal('ANKKA_UNINSTALL_NONCE'), type: v.literal('secret_text') }),
]);
const providerVersionModuleSchema = v.strictObject({
  name: v.string(),
  content_type: v.string(),
  content_base64: v.optional(v.string()),
});
const versionResultSchema = v.strictObject({
  annotations: versionAnnotationsSchema,
  bindings: v.optional(v.array(providerVersionBindingSchema)),
  compatibility_date: v.literal(EXACT_COMPATIBILITY_DATE),
  compatibility_flags: v.optional(v.tuple([])),
  created_on: isoDateSchema,
  env: v.optional(boundaryObjectSchema),
  exports: boundaryObjectSchema,
  exports_reconciliation: v.optional(exportReconciliationSchema),
  id: uuidSchema,
  limits: v.optional(v.strictObject({
    cpu_ms: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(0))),
  })),
  main_module: v.literal('index.js'),
  modules: v.array(providerVersionModuleSchema),
  number: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
  placement: v.optional(v.strictObject({
    hint: v.optional(v.string()),
    mode: v.optional(v.string()),
  })),
  source: v.optional(v.literal('api')),
  startup_time_ms: v.optional(v.pipe(v.number(), v.finite(), v.minValue(0))),
  urls: v.optional(v.array(boundaryValueSchema)),
  usage_model: v.optional(v.pipe(v.string(), v.minLength(1), v.maxLength(128))),
});
const versionListItemSchema = v.strictObject({
  annotations: v.optional(v.strictObject({
    'workers/message': v.optional(v.string()),
    'workers/tag': v.optional(v.string()),
    'workers/triggered_by': v.optional(v.string()),
  })),
  assets: v.optional(boundaryValueSchema),
  bindings: v.optional(boundaryValueSchema),
  compatibility_date: v.optional(boundaryValueSchema),
  compatibility_flags: v.optional(boundaryValueSchema),
  created_on: v.optional(boundaryValueSchema),
  exports: v.optional(boundaryValueSchema),
  exports_reconciliation: v.optional(boundaryValueSchema),
  id: uuidSchema,
  limits: v.optional(boundaryValueSchema),
  main_module: v.optional(boundaryValueSchema),
  modules: v.optional(boundaryValueSchema),
  number: v.optional(boundaryValueSchema),
  placement: v.optional(boundaryValueSchema),
  startup_time_ms: v.optional(boundaryValueSchema),
  usage_model: v.optional(boundaryValueSchema),
});
const versionListPageSchema = v.strictObject({
  errors: v.nullable(v.array(boundaryValueSchema)),
  messages: v.nullable(v.array(boundaryValueSchema)),
  result: v.pipe(v.array(versionListItemSchema), v.maxLength(VERSION_PAGE_SIZE)),
  result_info: v.strictObject({
    count: v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(VERSION_PAGE_SIZE)),
    page: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
    per_page: v.literal(VERSION_PAGE_SIZE),
    total_count: v.pipe(
      v.number(),
      v.safeInteger(),
      v.minValue(0),
      v.maxValue(VERSION_PAGE_SIZE * MAX_VERSION_PAGES),
    ),
    total_pages: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(MAX_VERSION_PAGES))),
  }),
  success: v.literal(true),
});
const workerDeleteIntentSchema = v.strictObject({
  kind: v.literal('uninstall_worker_delete_intent'),
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workerId: workerIdSchema,
  uninstallCycleId: uninstallCycleIdSchema,
  namespaceId: accountIdSchema,
  retirementVersionId: uuidSchema,
  retirementProofCommitment: sha256Schema,
  retirementProof: namespaceRetirementProofSchema,
  requestHash: sha256Schema,
  correlationTag: v.string(),
  method: v.literal('DELETE'),
  force: v.literal('omitted'),
});
const workerDeletionRecoveryProofSchema = v.strictObject({
  kind: v.literal('uninstall_worker_deletion_proof'),
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workerId: workerIdSchema,
  uninstallCycleId: uninstallCycleIdSchema,
  namespaceId: accountIdSchema,
  retirementVersionId: uuidSchema,
  retirementProofCommitment: sha256Schema,
  requestHash: sha256Schema,
  firstScriptListSha256: sha256Schema,
  secondScriptListSha256: sha256Schema,
  scriptCount: v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(MAX_SCRIPTS)),
});
const workerDeleteResultSchema = v.union([
  v.null(),
  v.strictObject({}),
  v.strictObject({ id: workerIdSchema }),
]);
const scriptListInfoSchema = v.strictObject({
  count: v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(SCRIPT_PAGE_SIZE)),
  page: v.pipe(v.number(), v.safeInteger(), v.minValue(1), v.maxValue(MAX_SCRIPT_PAGES)),
  per_page: v.literal(SCRIPT_PAGE_SIZE),
  total_count: v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(MAX_SCRIPTS)),
  total_pages: v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(MAX_SCRIPT_PAGES)),
});
const scriptListPageSchema = v.strictObject({
  errors: v.nullable(v.array(boundaryValueSchema)),
  messages: v.nullable(v.array(boundaryValueSchema)),
  result: v.pipe(v.array(v.looseObject({ id: workerNameSchema })), v.maxLength(SCRIPT_PAGE_SIZE)),
  result_info: v.optional(v.nullable(scriptListInfoSchema)),
  success: v.literal(true),
});

const MODULE_CONTENT_TYPES: Readonly<Record<string, string>> = Object.freeze({
  '.js': 'application/javascript+module',
  '.mjs': 'application/javascript+module',
  '.wasm': 'application/wasm',
});

export type UninstallCleanupVariableName = (typeof UNINSTALL_CLEANUP_VARIABLE_NAMES)[number];
export type UninstallCleanupVariables = Readonly<Record<UninstallCleanupVariableName, string>>;
export type UninstallWorkerVersionStage = 'cleanup' | 'retirement';
export type UninstallWorkerDeploymentStage = 'cleanup' | 'retirement' | 'restore_clean';

export type CloudflareUninstallWorkerLifecycleStage =
  | 'validate'
  | 'version_submit'
  | 'version_verify'
  | 'version_recovery'
  | 'deployment_submit'
  | 'deployment_verify'
  | 'deployment_active_verify'
  | 'deployment_recovery'
  | 'namespace_present'
  | 'namespace_absent'
  | 'worker_delete'
  | 'worker_delete_recovery';

export type CloudflareUninstallWorkerLifecycleOutcome =
  | 'not_sent'
  | 'rejected'
  | 'unknown'
  | 'submitted';

export type CloudflareUninstallWorkerLifecycleErrorCode =
  | 'invalid_input'
  | 'provider_rejected'
  | 'provider_unknown'
  | 'provider_mismatch'
  | 'recovery_ambiguous'
  | 'deletion_not_proven';

export interface UninstallWorkerVersionSubmission {
  readonly kind: 'uninstall_worker_version';
  readonly stage: UninstallWorkerVersionStage;
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly versionId: string;
  readonly requestHash: string;
  readonly correlationTag: string;
}

export interface UninstallWorkerDeploymentSubmission {
  readonly kind: 'uninstall_worker_deployment';
  readonly stage: UninstallWorkerDeploymentStage;
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly versionId: string;
  readonly deploymentId: string;
  readonly requestHash: string;
  readonly correlationTag: string;
}

export interface WorkerDeleteSubmission {
  readonly kind: 'uninstall_worker_delete';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly namespaceId: string;
  readonly retirementVersionId: string;
  readonly retirementProofCommitment: string;
  readonly requestHash: string;
  readonly correlationTag: string;
}

export type CloudflareUninstallWorkerLifecycleSubmission =
  | UninstallWorkerVersionSubmission
  | UninstallWorkerDeploymentSubmission
  | WorkerDeleteSubmission;

/**
 * Safe error surface. Provider bodies, access tokens, nonces, and module bytes
 * are deliberately never attached. A mutation-stage `unknown` outcome must be
 * resolved by the corresponding recovery API; callers must not replay it.
 */
export class CloudflareUninstallWorkerLifecycleError extends Error {
  readonly code: CloudflareUninstallWorkerLifecycleErrorCode;
  readonly stage: CloudflareUninstallWorkerLifecycleStage;
  readonly outcome: CloudflareUninstallWorkerLifecycleOutcome;
  readonly submissions: readonly CloudflareUninstallWorkerLifecycleSubmission[];
  readonly canRetry: false;

  constructor(
    code: CloudflareUninstallWorkerLifecycleErrorCode,
    stage: CloudflareUninstallWorkerLifecycleStage,
    outcome: CloudflareUninstallWorkerLifecycleOutcome,
    submissions: readonly unknown[] = [],
  ) {
    const validCode = (['invalid_input', 'provider_rejected', 'provider_unknown', 'provider_mismatch',
      'recovery_ambiguous', 'deletion_not_proven'] as const).includes(code);
    const validStage = (['validate', 'version_submit', 'version_verify', 'version_recovery',
      'deployment_submit', 'deployment_verify', 'deployment_active_verify', 'deployment_recovery',
      'namespace_present', 'namespace_absent', 'worker_delete', 'worker_delete_recovery'] as const).includes(stage);
    const validOutcome = (['not_sent', 'rejected', 'unknown', 'submitted'] as const).includes(outcome);
    const safeCode: CloudflareUninstallWorkerLifecycleErrorCode =
      validCode && validStage && validOutcome ? code : 'invalid_input';
    const safeStage: CloudflareUninstallWorkerLifecycleStage = safeCode === 'invalid_input' ? 'validate' : stage;
    const safeOutcome: CloudflareUninstallWorkerLifecycleOutcome =
      safeCode === 'invalid_input' ? 'not_sent' : outcome;
    super(safeCode);
    this.name = 'CloudflareUninstallWorkerLifecycleError';
    this.code = safeCode;
    this.stage = safeStage;
    this.outcome = safeOutcome;
    const projected: CloudflareUninstallWorkerLifecycleSubmission[] = [];
    if (safeCode !== 'invalid_input' && Array.isArray(submissions)) {
      try {
        const count = Math.min(submissions.length, 16);
        for (let index = 0; index < count; index += 1) {
          const parsed = parseCloudflareUninstallWorkerLifecycleSubmission(submissions[index]);
          if (parsed !== null) projected.push(parsed);
        }
      } catch {
        projected.length = 0;
      }
    }
    this.submissions = Object.freeze(projected);
    this.canRetry = false;
  }
}

export interface UninstallWorkerModuleCommitment {
  readonly name: string;
  readonly contentType: string;
  readonly contentSha256: string;
  readonly byteLength: number;
}

export interface CleanupWorkerVersionRecoveryRecord {
  readonly kind: 'uninstall_version_recovery';
  readonly stage: 'cleanup';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly namespaceId: string;
  readonly uninstallCycleId: string;
  readonly release: string;
  readonly artifactSha256: string;
  readonly componentSha256: string;
  readonly requestHash: string;
  readonly correlationTag: string;
  readonly compatibilityDate: '2026-08-08';
  readonly compatibilityFlags: readonly [];
  readonly mainModule: 'index.js';
  readonly contract: {
    readonly assets: 'absent';
    readonly defaultApplication: 'absent';
    readonly durableObject: {
      readonly binding: 'ADMIN_STATE';
      readonly className: 'AdminState';
      readonly namespaceId: string;
      readonly storage: 'sqlite';
    };
    readonly exports: {
      readonly AdminState: { readonly type: 'durable-object'; readonly storage: 'sqlite' };
    };
    readonly uninstallNonceBinding: 'present';
    readonly variableValueHashes: readonly {
      readonly name: UninstallCleanupVariableName;
      readonly valueSha256: string;
    }[];
  };
  readonly modules: readonly UninstallWorkerModuleCommitment[];
}

export interface RetirementWorkerVersionRecoveryRecord {
  readonly kind: 'uninstall_version_recovery';
  readonly stage: 'retirement';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly release: string;
  readonly artifactSha256: string;
  readonly componentSha256: string;
  readonly requestHash: string;
  readonly correlationTag: string;
  readonly compatibilityDate: '2026-08-08';
  readonly compatibilityFlags: readonly [];
  readonly mainModule: 'index.js';
  readonly contract: {
    readonly assets: 'absent';
    readonly bindings: readonly [];
    readonly defaultApplication: 'absent';
    readonly exports: {
      readonly AdminState: { readonly type: 'durable-object'; readonly state: 'deleted' };
    };
  };
  readonly modules: readonly UninstallWorkerModuleCommitment[];
}

export type UninstallWorkerVersionRecoveryRecord =
  | CleanupWorkerVersionRecoveryRecord
  | RetirementWorkerVersionRecoveryRecord;

/** Contains nonce/module bytes and is never journal-safe or a replay-control record. */
export interface UninstallWorkerVersionSubmitIntent {
  readonly kind: 'uninstall_version_submit';
  readonly stage: UninstallWorkerVersionStage;
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly requestHash: string;
  readonly correlationTag: string;
  readonly semanticCommitment: BoundaryObject;
  readonly body: BoundaryObject;
}

export interface UninstallWorkerVersionMutationPlan {
  /** Ephemeral payload. The outer durable journal must CAS before submission, then discard it. */
  readonly ephemeral: UninstallWorkerVersionSubmitIntent;
  /** Persist before POST. Exact, semantic, credential-free recovery input. */
  readonly recovery: UninstallWorkerVersionRecoveryRecord;
}

/**
 * Ephemeral proof used immediately before forwarding a Cloudflare grant to the
 * customer cleanup Worker. It is deliberately not a journal record: the
 * caller must consume it in the same request that performs the relay.
 */
export interface ActiveCleanupWorkerVersionProof {
  readonly version: UninstallWorkerVersionSubmission;
  readonly deployment: UninstallWorkerDeploymentSubmission;
}

export interface PrepareCleanupWorkerVersionInput {
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly namespaceId: string;
  readonly uninstallCycleId: string;
  readonly releaseSet: VerifiedGatewayWorkerReleaseSet;
  readonly variables: UninstallCleanupVariables;
  readonly uninstallNonce: string;
}

export interface PrepareRetirementWorkerVersionInput {
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly releaseSet: VerifiedGatewayWorkerReleaseSet;
}

export interface UninstallWorkerDeploymentMutationIntent {
  readonly kind: 'uninstall_deployment';
  readonly stage: UninstallWorkerDeploymentStage;
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly versionId: string;
  readonly requestHash: string;
  readonly correlationTag: string;
  readonly body: {
    readonly annotations: { readonly 'workers/message': string };
    readonly strategy: 'percentage';
    readonly versions: readonly [{ readonly percentage: 100; readonly version_id: string }];
  };
}

export interface PrepareUninstallWorkerDeploymentInput {
  readonly stage: UninstallWorkerDeploymentStage;
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly versionId: string;
}

export interface AdminStateNamespacePresenceProof {
  readonly kind: 'admin_state_namespace_presence';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly namespaceId: string;
  readonly namespaceName: string;
  readonly className: 'AdminState';
  readonly storage: 'sqlite';
  readonly accountNamespaceCount: number;
  readonly snapshotSha256: string;
}

export interface AdminStateNamespaceRetirementProof {
  readonly kind: 'admin_state_namespace_retirement';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly namespaceId: string;
  readonly retirementVersionId: string;
  readonly accountNamespaceCount: number;
  readonly firstSnapshotSha256: string;
  readonly secondSnapshotSha256: string;
}

export type PrepareWorkerDeleteInput = ProveAdminStateNamespaceRetiredInput;

export interface WorkerDeleteMutationIntent {
  readonly kind: 'uninstall_worker_delete_intent';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly namespaceId: string;
  readonly retirementVersionId: string;
  /** SHA-256 of the canonical, exact ProveAdminStateNamespaceRetiredInput. */
  readonly retirementProofCommitment: string;
  /** First complete proof; submit must reproduce it exactly before DELETE. */
  readonly retirementProof: AdminStateNamespaceRetirementProof;
  readonly requestHash: string;
  readonly correlationTag: string;
  readonly method: 'DELETE';
  /** Auditable proof that the optional destructive query flag is not sent. */
  readonly force: 'omitted';
}

export interface WorkerDeletionProof {
  readonly kind: 'uninstall_worker_deletion_proof';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly requestHash: string;
  readonly firstScriptListSha256: string;
  readonly secondScriptListSha256: string;
  readonly scriptCount: number;
}

/** Exact proof returned by this lifecycle's namespace-bound recovery API. */
export interface WorkerDeletionRecoveryProof extends WorkerDeletionProof {
  readonly namespaceId: string;
  readonly retirementVersionId: string;
  readonly retirementProofCommitment: string;
}

/**
 * The complete persistence allowlist for this module. Submit intents for
 * versions are intentionally excluded because they carry module bytes and, for
 * cleanup, ANKKA_UNINSTALL_NONCE. Cloudflare access tokens live only in calls.
 */
export type CloudflareUninstallWorkerLifecycleJournalRecord =
  | UninstallWorkerVersionRecoveryRecord
  | UninstallWorkerVersionSubmission
  | UninstallWorkerDeploymentMutationIntent
  | UninstallWorkerDeploymentSubmission
  | AdminStateNamespacePresenceProof
  | AdminStateNamespaceRetirementProof
  | WorkerDeleteMutationIntent
  | WorkerDeleteSubmission
  | WorkerDeletionRecoveryProof;

interface PreparedCall {
  readonly accessToken: string;
  readonly transport: (request: Request) => Promise<Response>;
  readonly timeoutMs: number;
}

interface CloudflareEnvelope {
  readonly errors: null | readonly BoundaryValue[];
  readonly messages: null | readonly BoundaryValue[];
  readonly result: BoundaryValue;
  readonly success: boolean;
}

interface VersionModuleBytes extends UninstallWorkerModuleCommitment {
  readonly bytes: Uint8Array;
}

interface DurableObjectNamespaceItem {
  readonly id: string;
  readonly className: string;
  readonly name: string;
  readonly script: string;
  readonly useSqlite: boolean;
}

interface DurableObjectNamespaceSnapshot {
  readonly items: readonly DurableObjectNamespaceItem[];
  readonly sha256: string;
}

function fail(
  code: CloudflareUninstallWorkerLifecycleErrorCode,
  stage: CloudflareUninstallWorkerLifecycleStage,
  outcome: CloudflareUninstallWorkerLifecycleOutcome,
  submissions: readonly CloudflareUninstallWorkerLifecycleSubmission[] = [],
): never {
  throw new CloudflareUninstallWorkerLifecycleError(code, stage, outcome, submissions);
}

function isRecord<Value>(value: Value): value is Value & BoundaryObject {
  return v.is(boundaryObjectSchema, value);
}

function isJournalObject<Value>(value: Value): value is Value & BoundaryObject {
  if (!isRecord(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys<Value extends object>(value: Value, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length && actual.every((key, index) => key === sortedExpected[index]);
}

/**
 * Pure journal/error-boundary parser. It accepts only an exact known kind and
 * returns a fresh allowlisted locator; extra provider or credential fields
 * reject the whole value instead of being copied into an error.
 */
export function parseCloudflareUninstallWorkerLifecycleSubmission<Input>(
  value: Input,
): CloudflareUninstallWorkerLifecycleSubmission | null {
  try {
    const versionCandidate = v.safeParse(versionSubmissionSchema, value);
    if (versionCandidate.success && versionCandidate.output.correlationTag ===
      versionCorrelationTag(versionCandidate.output.stage, versionCandidate.output.requestHash)) {
      const submission = versionCandidate.output;
      return Object.freeze({
        kind: 'uninstall_worker_version',
        stage: submission.stage,
        accountId: submission.accountId,
        workerName: submission.workerName,
        workerId: submission.workerId,
        uninstallCycleId: submission.uninstallCycleId,
        versionId: submission.versionId,
        requestHash: submission.requestHash,
        correlationTag: submission.correlationTag,
      });
    }
    const deploymentCandidate = v.safeParse(deploymentSubmissionSchema, value);
    if (deploymentCandidate.success && deploymentCandidate.output.correlationTag ===
      deploymentCorrelationTag(deploymentCandidate.output.stage, deploymentCandidate.output.requestHash)) {
      const submission = deploymentCandidate.output;
      return Object.freeze({
        kind: 'uninstall_worker_deployment',
        stage: submission.stage,
        accountId: submission.accountId,
        workerName: submission.workerName,
        workerId: submission.workerId,
        uninstallCycleId: submission.uninstallCycleId,
        versionId: submission.versionId,
        deploymentId: submission.deploymentId,
        requestHash: submission.requestHash,
        correlationTag: submission.correlationTag,
      });
    }
    const deleteCandidate = v.safeParse(workerDeleteSubmissionSchema, value);
    if (deleteCandidate.success && deleteCandidate.output.correlationTag ===
      `ankka-un-w-delete-sha256:${deleteCandidate.output.requestHash}`) {
      const submission = deleteCandidate.output;
      return Object.freeze({
        kind: 'uninstall_worker_delete',
        accountId: submission.accountId,
        workerName: submission.workerName,
        workerId: submission.workerId,
        uninstallCycleId: submission.uninstallCycleId,
        namespaceId: submission.namespaceId,
        retirementVersionId: submission.retirementVersionId,
        retirementProofCommitment: submission.retirementProofCommitment,
        requestHash: submission.requestHash,
        correlationTag: submission.correlationTag,
      });
    }
    return null;
  } catch {
    return null;
  }
}

function canonicalEqual<Left, Right>(left: Left, right: Right): boolean {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

function lexicalCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(value: Uint8Array | string): Promise<string> {
  const source = value instanceof Uint8Array ? value : new TextEncoder().encode(value);
  const owned = new Uint8Array(source.byteLength);
  owned.set(source);
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', owned)));
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let offset = 0; offset < bytes.byteLength; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, Math.min(offset + 0x8000, bytes.byteLength)));
  }
  return btoa(binary);
}

function strictBase64Bytes<Input>(value: Input, byteLength: number): Uint8Array | null {
  if (
    !v.is(v.string(), value) ||
    value.length !== 4 * Math.ceil(byteLength / 3) ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
  ) return null;
  try {
    const decoded = atob(value);
    if (decoded.length !== byteLength) return null;
    const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
    return bytesToBase64(bytes) === value ? bytes : null;
  } catch {
    return null;
  }
}

function extension(path: string): string {
  const slash = path.lastIndexOf('/');
  const dot = path.lastIndexOf('.');
  return dot > slash ? path.slice(dot).toLowerCase() : '';
}

function safeModuleName<Input>(value: Input): value is Input & string {
  return v.is(v.string(), value) && value.length > 0 && value.length <= 256 &&
    !value.startsWith('/') && !value.includes('\\') && !hasControlCharacter(value) &&
    value.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..');
}

function validCleanupVariables(
  value: v.InferOutput<typeof cleanupVariablesSchema>,
  accountId: string,
  release: string,
  artifactSha256: string,
): boolean {
  return value.ANKKA_GATEWAY_RELEASE === release &&
    value.ANKKA_GATEWAY_RELEASE_SHA256 === `sha256:${artifactSha256}` &&
    value.CLOUDFLARE_ACCOUNT_ID === accountId &&
    value.ZERO_TRUST_READY === 'true';
}

async function verifiedModules(
  modules: VerifiedGatewayWorkerReleaseSet['cleanup']['worker']['modules'],
): Promise<readonly VersionModuleBytes[]> {
  const candidate = v.safeParse(
    v.pipe(v.array(verifiedReleaseModuleSchema), v.minLength(1), v.maxLength(1_000)),
    modules,
  );
  if (!candidate.success) fail('invalid_input', 'validate', 'not_sent');
  const result: VersionModuleBytes[] = [];
  const names = new Set<string>();
  let totalBytes = 0;
  for (const module of candidate.output) {
    if (
      !safeModuleName(module.name) || names.has(module.name) ||
      module.contentType !== MODULE_CONTENT_TYPES[extension(module.name)] ||
      module.bytes.byteLength === 0 ||
      module.bytes.byteLength > MAX_FILE_BYTES
    ) fail('invalid_input', 'validate', 'not_sent');
    const bytes = new Uint8Array(module.bytes);
    if (await sha256(bytes) !== module.sha256) fail('invalid_input', 'validate', 'not_sent');
    names.add(module.name);
    totalBytes += bytes.byteLength;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_RELEASE_BYTES) {
      fail('invalid_input', 'validate', 'not_sent');
    }
    result.push(Object.freeze({
      name: module.name,
      contentType: module.contentType,
      contentSha256: module.sha256,
      byteLength: bytes.byteLength,
      bytes,
    }));
  }
  if (!names.has('index.js')) fail('invalid_input', 'validate', 'not_sent');
  result.sort((left, right) => lexicalCompare(left.name, right.name));
  return Object.freeze(result);
}

function releaseSetIdentityValid(releaseSet: VerifiedGatewayWorkerReleaseSet): boolean {
  if (!v.is(releaseSetIdentitySchema, releaseSet)) return false;
  const { bootstrap, primary, cleanup, retirement } = releaseSet;
  if (
    bootstrap.release !== primary.release || cleanup.release !== primary.release ||
    retirement.release !== primary.release ||
    bootstrap.artifactSha256 !== primary.artifactSha256 ||
    cleanup.artifactSha256 !== primary.artifactSha256 ||
    retirement.artifactSha256 !== primary.artifactSha256 ||
    cleanup.variant !== 'cleanup' || retirement.variant !== 'retirement'
  ) return false;
  return canonicalEqual(
    cleanup.worker.contract,
    APPROVED_CLOUDFLARE_RELEASE_CONTRACT.workerVariants.cleanup,
  ) && canonicalEqual(
    retirement.worker.contract,
    APPROVED_CLOUDFLARE_RELEASE_CONTRACT.workerVariants.retirement,
  );
}

function moduleCommitments(modules: readonly VersionModuleBytes[]): readonly UninstallWorkerModuleCommitment[] {
  return Object.freeze(modules.map((module) => Object.freeze({
    name: module.name,
    contentType: module.contentType,
    contentSha256: module.contentSha256,
    byteLength: module.byteLength,
  })));
}

function versionSemanticCommitment(recovery: UninstallWorkerVersionRecoveryRecord): BoundaryObject {
  return {
    accountId: recovery.accountId,
    artifactSha256: recovery.artifactSha256,
    compatibilityDate: recovery.compatibilityDate,
    compatibilityFlags: [...recovery.compatibilityFlags],
    componentSha256: recovery.componentSha256,
    contract: recovery.contract,
    mainModule: recovery.mainModule,
    modules: recovery.modules.map((module) => ({ ...module })),
    release: recovery.release,
    stage: recovery.stage,
    uninstallCycleId: recovery.uninstallCycleId,
    workerId: recovery.workerId,
    workerName: recovery.workerName,
  };
}

/**
 * Version annotations are bounded: Cloudflare rejects a `workers/tag` longer
 * than 100 characters (live 2026-08-23), and stage plus a 64-character digest
 * already spends most of that, so the fixed prefix stays short.
 */
function versionCorrelationTag(stage: UninstallWorkerVersionStage, requestHash: string): string {
  return `ankka-un-v-${stage}-sha256:${requestHash}`;
}

async function createCleanupRecovery(
  input: Omit<PrepareCleanupWorkerVersionInput, 'uninstallNonce'>,
  modules: readonly VersionModuleBytes[],
): Promise<CleanupWorkerVersionRecoveryRecord> {
  const hashes = await Promise.all(UNINSTALL_CLEANUP_VARIABLE_NAMES.map(async (name) => Object.freeze({
    name,
    valueSha256: await sha256(input.variables[name]),
  })));
  const emptyTuple: readonly [] = Object.freeze([]);
  const base: Omit<CleanupWorkerVersionRecoveryRecord, 'correlationTag' | 'requestHash'> = {
    kind: 'uninstall_version_recovery',
    stage: 'cleanup',
    accountId: input.accountId,
    workerName: input.workerName,
    workerId: input.workerId,
    namespaceId: input.namespaceId,
    uninstallCycleId: input.uninstallCycleId,
    release: input.releaseSet.cleanup.release,
    artifactSha256: input.releaseSet.cleanup.artifactSha256,
    componentSha256: input.releaseSet.cleanup.componentSha256,
    compatibilityDate: EXACT_COMPATIBILITY_DATE,
    compatibilityFlags: emptyTuple,
    mainModule: 'index.js',
    contract: Object.freeze({
      assets: 'absent',
      defaultApplication: 'absent',
      durableObject: Object.freeze({
        binding: 'ADMIN_STATE',
        className: 'AdminState',
        namespaceId: input.namespaceId,
        storage: 'sqlite',
      }),
      exports: Object.freeze({
        AdminState: Object.freeze({ type: 'durable-object', storage: 'sqlite' }),
      }),
      uninstallNonceBinding: 'present',
      variableValueHashes: Object.freeze(hashes),
    }),
    modules: moduleCommitments(modules),
  };
  const requestHash = await sha256(canonicalJson(versionSemanticCommitment({
    ...base,
    requestHash: '0'.repeat(64),
    correlationTag: '',
  })));
  return Object.freeze({
    ...base,
    requestHash,
    correlationTag: versionCorrelationTag('cleanup', requestHash),
  });
}

async function createRetirementRecovery(
  input: PrepareRetirementWorkerVersionInput,
  modules: readonly VersionModuleBytes[],
): Promise<RetirementWorkerVersionRecoveryRecord> {
  const emptyTuple: readonly [] = Object.freeze([]);
  const base: Omit<RetirementWorkerVersionRecoveryRecord, 'correlationTag' | 'requestHash'> = {
    kind: 'uninstall_version_recovery',
    stage: 'retirement',
    accountId: input.accountId,
    workerName: input.workerName,
    workerId: input.workerId,
    uninstallCycleId: input.uninstallCycleId,
    release: input.releaseSet.retirement.release,
    artifactSha256: input.releaseSet.retirement.artifactSha256,
    componentSha256: input.releaseSet.retirement.componentSha256,
    compatibilityDate: EXACT_COMPATIBILITY_DATE,
    compatibilityFlags: emptyTuple,
    mainModule: 'index.js',
    contract: Object.freeze({
      assets: 'absent',
      bindings: emptyTuple,
      defaultApplication: 'absent',
      exports: Object.freeze({
        AdminState: Object.freeze({ type: 'durable-object', state: 'deleted' }),
      }),
    }),
    modules: moduleCommitments(modules),
  };
  const requestHash = await sha256(canonicalJson(versionSemanticCommitment({
    ...base,
    requestHash: '0'.repeat(64),
    correlationTag: '',
  })));
  return Object.freeze({
    ...base,
    requestHash,
    correlationTag: versionCorrelationTag('retirement', requestHash),
  });
}

function versionBody(
  recovery: UninstallWorkerVersionRecoveryRecord,
  modules: readonly VersionModuleBytes[],
  variables?: UninstallCleanupVariables,
  uninstallNonce?: string,
): BoundaryObject {
  const bindings: BoundaryObject[] = [];
  if (recovery.stage === 'cleanup') {
    if (!variables || !uninstallNonce) fail('invalid_input', 'validate', 'not_sent');
    bindings.push({
      name: 'ADMIN_STATE',
      type: 'durable_object_namespace',
      class_name: 'AdminState',
      namespace_id: recovery.namespaceId,
    });
    for (const name of UNINSTALL_CLEANUP_VARIABLE_NAMES) {
      bindings.push({ name, type: 'plain_text', text: variables[name] });
    }
    bindings.push({ name: 'ANKKA_UNINSTALL_NONCE', type: 'secret_text', text: uninstallNonce });
  }
  bindings.sort((left, right) => lexicalCompare(String(left.name), String(right.name)));
  return Object.freeze({
    annotations: Object.freeze({ 'workers/tag': recovery.correlationTag }),
    bindings: Object.freeze(bindings.map((binding) => Object.freeze(binding))),
    compatibility_date: recovery.compatibilityDate,
    compatibility_flags: Object.freeze([]),
    exports: recovery.contract.exports,
    main_module: recovery.mainModule,
    modules: Object.freeze(modules.map((module) => Object.freeze({
      name: module.name,
      content_type: module.contentType,
      content_base64: bytesToBase64(module.bytes),
    }))),
  });
}

export async function prepareCleanupWorkerVersionMutation(
  input: PrepareCleanupWorkerVersionInput,
): Promise<UninstallWorkerVersionMutationPlan> {
  const candidate = v.safeParse(prepareCleanupVersionInputSchema, input);
  if (!candidate.success || !releaseSetIdentityValid(candidate.output.releaseSet) ||
    !validCleanupVariables(
      candidate.output.variables,
      candidate.output.accountId,
      candidate.output.releaseSet.cleanup.release,
      candidate.output.releaseSet.cleanup.artifactSha256,
    )
  ) fail('invalid_input', 'validate', 'not_sent');
  const parsedInput: PrepareCleanupWorkerVersionInput = candidate.output;
  const modules = await verifiedModules(parsedInput.releaseSet.cleanup.worker.modules);
  const recovery = await createCleanupRecovery(parsedInput, modules);
  const body = versionBody(recovery, modules, parsedInput.variables, parsedInput.uninstallNonce);
  return Object.freeze({
    recovery,
    ephemeral: Object.freeze({
      kind: 'uninstall_version_submit',
      stage: 'cleanup',
      accountId: parsedInput.accountId,
      workerName: parsedInput.workerName,
      workerId: parsedInput.workerId,
      uninstallCycleId: parsedInput.uninstallCycleId,
      requestHash: recovery.requestHash,
      correlationTag: recovery.correlationTag,
      semanticCommitment: Object.freeze(versionSemanticCommitment(recovery)),
      body,
    }),
  });
}

export async function prepareRetirementWorkerVersionMutation(
  input: PrepareRetirementWorkerVersionInput,
): Promise<UninstallWorkerVersionMutationPlan> {
  const candidate = v.safeParse(prepareRetirementVersionInputSchema, input);
  if (!candidate.success || !releaseSetIdentityValid(candidate.output.releaseSet)) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  const parsedInput: PrepareRetirementWorkerVersionInput = candidate.output;
  const modules = await verifiedModules(parsedInput.releaseSet.retirement.worker.modules);
  const recovery = await createRetirementRecovery(parsedInput, modules);
  const body = versionBody(recovery, modules);
  return Object.freeze({
    recovery,
    ephemeral: Object.freeze({
      kind: 'uninstall_version_submit',
      stage: 'retirement',
      accountId: parsedInput.accountId,
      workerName: parsedInput.workerName,
      workerId: parsedInput.workerId,
      uninstallCycleId: parsedInput.uninstallCycleId,
      requestHash: recovery.requestHash,
      correlationTag: recovery.correlationTag,
      semanticCommitment: Object.freeze(versionSemanticCommitment(recovery)),
      body,
    }),
  });
}

function validModuleCommitments(value: readonly UninstallWorkerModuleCommitment[]): boolean {
  const names = new Set<string>();
  let previous = '';
  let total = 0;
  for (const module of value) {
    if (
      !safeModuleName(module.name) || names.has(module.name) || (previous !== '' && previous >= module.name) ||
      module.contentType !== MODULE_CONTENT_TYPES[extension(module.name)] ||
      module.byteLength <= 0 || module.byteLength > MAX_FILE_BYTES
    ) return false;
    names.add(module.name);
    previous = module.name;
    total += module.byteLength;
    if (!Number.isSafeInteger(total) || total > MAX_RELEASE_BYTES) return false;
  }
  return names.has('index.js');
}

async function validVersionRecoveryRecord(value: UninstallWorkerVersionRecoveryRecord): Promise<boolean> {
  const candidate = v.safeParse(versionRecoverySchema, value);
  if (!candidate.success || value.correlationTag !== versionCorrelationTag(value.stage, value.requestHash) ||
    !validModuleCommitments(value.modules)) return false;
  if (value.stage === 'cleanup' && (
    value.contract.durableObject.namespaceId !== value.namespaceId ||
    value.contract.variableValueHashes.some(
      (binding, index) => binding.name !== UNINSTALL_CLEANUP_VARIABLE_NAMES[index],
    )
  )) return false;
  try {
    const expectedHash = await sha256(canonicalJson(versionSemanticCommitment(value)));
    return expectedHash === value.requestHash;
  } catch {
    return false;
  }
}

/** Parse an exact, credential-free record at the uninstall journal boundary. */
export async function parseUninstallWorkerVersionRecoveryRecord<Input>(
  value: Input,
): Promise<UninstallWorkerVersionRecoveryRecord | null> {
  try {
    const candidate = v.safeParse(versionRecoverySchema, value);
    if (!candidate.success) return null;
    const input = candidate.output;
    const modules = Object.freeze(input.modules.map((module) => Object.freeze({
        name: module.name,
        contentType: module.contentType,
        contentSha256: module.contentSha256,
        byteLength: module.byteLength,
      })));
    const emptyTuple: readonly [] = Object.freeze([]);
    const recoveryKind = 'uninstall_version_recovery' as const;
    const mainModule = 'index.js' as const;
    const common = {
      kind: recoveryKind,
      accountId: input.accountId,
      workerName: input.workerName,
      workerId: input.workerId,
      uninstallCycleId: input.uninstallCycleId,
      release: input.release,
      artifactSha256: input.artifactSha256,
      componentSha256: input.componentSha256,
      requestHash: input.requestHash,
      correlationTag: input.correlationTag,
      compatibilityDate: EXACT_COMPATIBILITY_DATE,
      compatibilityFlags: emptyTuple,
      mainModule,
      modules,
    };
    if (input.stage === 'cleanup') {
      const variableValueHashes = Object.freeze(input.contract.variableValueHashes.map((binding) => Object.freeze({
          name: binding.name,
          valueSha256: binding.valueSha256,
        })));
      const parsed: CleanupWorkerVersionRecoveryRecord = Object.freeze({
        ...common,
        stage: 'cleanup',
        namespaceId: input.namespaceId,
        contract: Object.freeze({
          assets: 'absent',
          defaultApplication: 'absent',
          durableObject: Object.freeze({
            binding: 'ADMIN_STATE',
            className: 'AdminState',
            namespaceId: input.namespaceId,
            storage: 'sqlite',
          }),
          exports: Object.freeze({
            AdminState: Object.freeze({ type: 'durable-object', storage: 'sqlite' }),
          }),
          uninstallNonceBinding: 'present',
          variableValueHashes,
        }),
      });
      return await validVersionRecoveryRecord(parsed) ? parsed : null;
    }
    const parsed: RetirementWorkerVersionRecoveryRecord = Object.freeze({
      ...common,
      stage: 'retirement',
      contract: Object.freeze({
        assets: 'absent',
        bindings: emptyTuple,
        defaultApplication: 'absent',
        exports: Object.freeze({
          AdminState: Object.freeze({ type: 'durable-object', state: 'deleted' }),
        }),
      }),
    });
    return await validVersionRecoveryRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

async function validVersionSubmitIntent(
  intent: UninstallWorkerVersionSubmitIntent,
  recovery: UninstallWorkerVersionRecoveryRecord,
): Promise<boolean> {
  const candidate = v.safeParse(versionSubmitIntentSchema, intent);
  if (
    !candidate.success || !await validVersionRecoveryRecord(recovery) ||
    candidate.output.stage !== recovery.stage ||
    candidate.output.accountId !== recovery.accountId || candidate.output.workerName !== recovery.workerName ||
    candidate.output.workerId !== recovery.workerId ||
    candidate.output.uninstallCycleId !== recovery.uninstallCycleId ||
    candidate.output.requestHash !== recovery.requestHash ||
    candidate.output.correlationTag !== recovery.correlationTag ||
    !canonicalEqual(candidate.output.semanticCommitment, versionSemanticCommitment(recovery)) ||
    candidate.output.body.annotations['workers/tag'] !== recovery.correlationTag ||
    !canonicalEqual(candidate.output.body.exports, recovery.contract.exports) ||
    candidate.output.body.modules.length !== recovery.modules.length
  ) return false;
  const parsedIntent = candidate.output;

  const bindingMap = new Map<string, v.InferOutput<typeof versionSubmitBindingSchema>>();
  for (const binding of parsedIntent.body.bindings) {
    if (bindingMap.has(binding.name)) return false;
    bindingMap.set(binding.name, binding);
  }
  if (recovery.stage === 'cleanup') {
    if (bindingMap.size !== UNINSTALL_CLEANUP_VARIABLE_NAMES.length + 2) return false;
    if (!canonicalEqual(bindingMap.get('ADMIN_STATE'), {
      name: 'ADMIN_STATE', type: 'durable_object_namespace', class_name: 'AdminState',
      namespace_id: recovery.namespaceId,
    })) return false;
    for (const expected of recovery.contract.variableValueHashes) {
      const binding = bindingMap.get(expected.name);
      if (
        binding?.name !== expected.name || binding.type !== 'plain_text' ||
        await sha256(binding.text) !== expected.valueSha256
      ) return false;
    }
    const nonce = bindingMap.get('ANKKA_UNINSTALL_NONCE');
    if (
      nonce?.name !== 'ANKKA_UNINSTALL_NONCE' || nonce.type !== 'secret_text'
    ) return false;
  } else if (bindingMap.size !== 0) return false;

  for (let index = 0; index < recovery.modules.length; index += 1) {
    const expected = recovery.modules.at(index);
    const module = parsedIntent.body.modules.at(index);
    if (expected === undefined || module === undefined) return false;
    if (
      module.name !== expected.name || module.content_type !== expected.contentType
    ) return false;
    const bytes = strictBase64Bytes(module.content_base64, expected.byteLength);
    if (!bytes || await sha256(bytes) !== expected.contentSha256) return false;
  }
  return await sha256(canonicalJson(parsedIntent.semanticCommitment)) === recovery.requestHash;
}

function prepareCall(value: CloudflareDirectUploadCall): PreparedCall {
  const candidate = v.safeParse(directUploadCallSchema, value);
  if (!candidate.success) fail('invalid_input', 'validate', 'not_sent');
  return {
    accessToken: candidate.output.accessToken,
    transport: candidate.output.transport,
    timeoutMs: candidate.output.timeoutMs ?? DEFAULT_TIMEOUT_MS,
  };
}

function authHeaders(accessToken: string): Headers {
  const headers = new Headers();
  headers.set('accept', 'application/json');
  headers.set('authorization', `Bearer ${accessToken}`);
  return headers;
}

function jsonHeaders(accessToken: string): Headers {
  const headers = authHeaders(accessToken);
  headers.set('content-type', 'application/json');
  return headers;
}

async function readBoundedJson(response: Response, maximum = MAX_RESPONSE_BYTES): Promise<BoundaryValue> {
  const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
  if (!contentType.startsWith('application/json') || !response.body) throw new TypeError('response');
  const declared = response.headers.get('content-length');
  if (declared !== null) {
    const parsed = Number(declared);
    if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maximum) throw new TypeError('response');
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximum) {
      await reader.cancel();
      throw new TypeError('response');
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
    const parsed: BoundaryValue = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!v.is(boundaryValueSchema, parsed)) throw new TypeError('response');
    return parsed;
  } catch {
    throw new TypeError('response');
  }
}

async function requestJson(
  call: PreparedCall,
  stage: CloudflareUninstallWorkerLifecycleStage,
  url: string,
  init: RequestInit,
  maximum = MAX_RESPONSE_BYTES,
  submissions: readonly CloudflareUninstallWorkerLifecycleSubmission[] = [],
): Promise<{ readonly status: number; readonly value: BoundaryValue }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), call.timeoutMs);
  const mutation = init.method === 'POST' || init.method === 'DELETE';
  try {
    const response = await call.transport(new Request(url, { ...init, signal: controller.signal }));
    const value = await readBoundedJson(response, maximum);
    return { status: response.status, value };
  } catch {
    fail('provider_unknown', stage, mutation ? 'unknown' : 'unknown', submissions);
  } finally {
    clearTimeout(timeout);
  }
}

function isEmptyProviderList<Value>(value: Value): boolean {
  return v.is(emptyProviderListSchema, value);
}

function providerErrors<Value>(value: Value): boolean {
  return v.is(providerErrorListSchema, value);
}

function parseEnvelope<Value>(value: Value): CloudflareEnvelope | null {
  const candidate = v.safeParse(providerEnvelopeSchema, value);
  if (!candidate.success) return null;
  return {
    errors: candidate.output.errors,
    messages: candidate.output.messages,
    result: candidate.output.result,
    success: candidate.output.success,
  };
}

function successResult<Value>(value: Value): BoundaryValue | null {
  const envelope = parseEnvelope(value);
  return envelope && envelope.success && isEmptyProviderList(envelope.errors) &&
    isEmptyProviderList(envelope.messages) ? envelope.result : null;
}

function absentEnvelope<Value>(value: Value): boolean {
  const envelope = parseEnvelope(value);
  return Boolean(envelope && !envelope.success && providerErrors(envelope.errors) &&
    isEmptyProviderList(envelope.messages) && envelope.result === null);
}

function rejectStatus<Value>(
  status: number,
  value: Value,
  stage: CloudflareUninstallWorkerLifecycleStage,
  submissions: readonly CloudflareUninstallWorkerLifecycleSubmission[] = [],
): never {
  const envelope = parseEnvelope(value);
  if (status >= 400 && status < 500 && envelope && !envelope.success && providerErrors(envelope.errors)) {
    fail('provider_rejected', stage, 'rejected', submissions);
  }
  fail('provider_unknown', stage, 'unknown', submissions);
}

function rawResultId<Value>(value: Value, pattern: RegExp): string | null {
  const candidate = v.safeParse(rawResultSchema, value);
  return candidate.success && pattern.test(candidate.output.result.id) ? candidate.output.result.id : null;
}

function versionResponseMaximum(recovery: UninstallWorkerVersionRecoveryRecord): number {
  const moduleBytes = recovery.modules.reduce(
    (total, module) => total + 4 * Math.ceil(module.byteLength / 3),
    0,
  );
  return Math.min(MAX_VERSION_RESPONSE_BYTES, Math.max(MAX_RESPONSE_BYTES, moduleBytes + 1024 * 1024));
}

function versionSubmission(
  recovery: UninstallWorkerVersionRecoveryRecord,
  versionId: string,
): UninstallWorkerVersionSubmission {
  return Object.freeze({
    kind: 'uninstall_worker_version',
    stage: recovery.stage,
    accountId: recovery.accountId,
    workerName: recovery.workerName,
    workerId: recovery.workerId,
    uninstallCycleId: recovery.uninstallCycleId,
    versionId,
    requestHash: recovery.requestHash,
    correlationTag: recovery.correlationTag,
  });
}

function validVersionSubmission(
  recovery: UninstallWorkerVersionRecoveryRecord,
  submission: UninstallWorkerVersionSubmission,
): boolean {
  return isRecord(submission) && exactKeys(submission, [
    'accountId', 'correlationTag', 'kind', 'requestHash', 'stage', 'uninstallCycleId', 'versionId',
    'workerId', 'workerName',
  ]) && submission.kind === 'uninstall_worker_version' && submission.stage === recovery.stage &&
    submission.accountId === recovery.accountId && submission.workerName === recovery.workerName &&
    submission.workerId === recovery.workerId && submission.uninstallCycleId === recovery.uninstallCycleId &&
    submission.requestHash === recovery.requestHash && submission.correlationTag === recovery.correlationTag &&
    UUID.test(submission.versionId);
}

/**
 * The outer durable journal owns one-shot CAS/replay control. This module has
 * no process-local replay lock. A returned ID is not a validation proof.
 */
export async function submitUninstallWorkerVersionMutation(
  intent: UninstallWorkerVersionSubmitIntent,
  recovery: UninstallWorkerVersionRecoveryRecord,
  callInput: CloudflareDirectUploadCall,
): Promise<UninstallWorkerVersionSubmission> {
  if (!await validVersionSubmitIntent(intent, recovery)) fail('invalid_input', 'validate', 'not_sent');
  const call = prepareCall(callInput);
  const response = await requestJson(
    call,
    'version_submit',
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/workers/${intent.workerId}/versions`,
    { method: 'POST', headers: jsonHeaders(call.accessToken), body: JSON.stringify(intent.body) },
    versionResponseMaximum(recovery),
  );
  const versionId = rawResultId(response.value, UUID);
  const surfaced = versionId === null ? [] : [versionSubmission(recovery, versionId)];
  if (![200, 201].includes(response.status)) rejectStatus(response.status, response.value, 'version_submit', surfaced);
  if (versionId === null) fail('provider_mismatch', 'version_submit', 'unknown');
  const submission = versionSubmission(recovery, versionId);
  const result = successResult(response.value);
  if (!isRecord(result) || result.id !== versionId) {
    fail('provider_mismatch', 'version_submit', 'submitted', [submission]);
  }
  return submission;
}

function safeIsoDate<Value>(value: Value): value is Value & string {
  return v.is(isoDateSchema, value);
}

function exactVersionAnnotations<Value>(value: Value, correlationTag: string): boolean {
  const candidate = v.safeParse(versionAnnotationsSchema, value);
  return candidate.success && candidate.output['workers/tag'] === correlationTag;
}

function exactActiveExports<Value>(value: Value): boolean {
  return v.is(activeExportsSchema, value);
}

/**
 * Live (2026-08-23): a retired Durable Object export is not dropped from the
 * version's export map — it stays and is marked `state: 'deleted'`, which is a
 * stronger retirement proof than absence. Either shape is accepted; a live
 * `AdminState` export is not.
 */
function exactRetiredExports<Value>(value: Value): boolean {
  return v.is(retiredExportsSchema, value);
}

const EXPORT_RECONCILIATION_KEYS = Object.freeze([
  'created',
  'deleted',
  'info',
  'removable_entries',
  'renamed',
  'transfer_pending',
  'transferred',
  'updated',
  'warnings',
] as const);

function validExportReconciliation(
  value: v.InferOutput<typeof exportReconciliationSchema>,
  stage: UninstallWorkerVersionStage,
): boolean {
  if (stage === 'retirement') {
    return canonicalEqual(value.deleted, ['AdminState']) &&
      EXPORT_RECONCILIATION_KEYS.filter((key) => key !== 'deleted').every(
        (key) => value[key].length === 0,
      );
  }
  if (value.deleted.length !== 0) return false;
  const allowedAdminState = (entry: BoundaryValue): boolean => entry === 'AdminState';
  return ['created', 'updated'].every((key) => (
    value[key === 'created' ? 'created' : 'updated'].length <= 1 &&
    value[key === 'created' ? 'created' : 'updated'].every(allowedAdminState)
  )) && EXPORT_RECONCILIATION_KEYS.filter(
    (key) => !['created', 'deleted', 'updated'].includes(key),
  ).every((key) => value[key].length === 0);
}

async function exactVersionResult<Input>(
  result: Input,
  recovery: UninstallWorkerVersionRecoveryRecord,
  versionId: string,
  requireModuleContent = false,
): Promise<boolean> {
  // Live version read-back (2026-08-23) also carries env, source, and urls, and
  // omits compatibility_flags and exports_reconciliation when they are empty or
  // not yet reconciled. The uninstall Workers carry no assets at any stage.
  const candidate = v.safeParse(versionResultSchema, result);
  if (!candidate.success) return false;
  const parsedResult = candidate.output;
  if (
    parsedResult.id !== versionId || parsedResult.compatibility_date !== recovery.compatibilityDate ||
    parsedResult.main_module !== recovery.mainModule ||
    !exactVersionAnnotations(parsedResult.annotations, recovery.correlationTag) ||
    // Declarative exports are reconciled by the deployment, so the field is
    // absent on a version that has not been deployed yet. The exact `exports`
    // assertion below carries the same evidence and is always present.
    !(parsedResult.exports_reconciliation === undefined ||
      validExportReconciliation(parsedResult.exports_reconciliation, recovery.stage)) ||
    parsedResult.modules.length !== recovery.modules.length
  ) return false;
  if (recovery.stage === 'cleanup'
    ? !exactActiveExports(parsedResult.exports)
    : !exactRetiredExports(parsedResult.exports)) {
    return false;
  }

  const bindings = new Map<string, v.InferOutput<typeof providerVersionBindingSchema>>();
  for (const binding of parsedResult.bindings ?? []) {
    if (bindings.has(binding.name)) return false;
    bindings.set(binding.name, binding);
  }
  if (recovery.stage === 'retirement') {
    if (bindings.size !== 0) return false;
  } else {
    if (bindings.size !== UNINSTALL_CLEANUP_VARIABLE_NAMES.length + 2) return false;
    const adminState = bindings.get('ADMIN_STATE');
    if (
      !adminState || adminState.type !== 'durable_object_namespace' || adminState.class_name !== 'AdminState' ||
      Object.keys(adminState).some((key) => !['class_name', 'name', 'namespace_id', 'type'].includes(key)) ||
      (adminState.namespace_id !== undefined && adminState.namespace_id !== recovery.namespaceId)
    ) return false;
    const nonce = bindings.get('ANKKA_UNINSTALL_NONCE');
    if (nonce?.name !== 'ANKKA_UNINSTALL_NONCE' || nonce.type !== 'secret_text') return false;
    for (const expected of recovery.contract.variableValueHashes) {
      const binding = bindings.get(expected.name);
      if (
        binding?.name !== expected.name || binding.type !== 'plain_text' ||
        await sha256(binding.text) !== expected.valueSha256
      ) return false;
    }
  }

  const returnedModules = new Map<string, v.InferOutput<typeof providerVersionModuleSchema>>();
  for (const module of parsedResult.modules) {
    if (returnedModules.has(module.name)) return false;
    returnedModules.set(module.name, module);
  }
  if (returnedModules.size !== recovery.modules.length) return false;
  for (const expected of recovery.modules) {
    const module = returnedModules.get(expected.name);
    if (
      !module || module.content_type !== expected.contentType ||
      (requireModuleContent && module.content_base64 === undefined)
    ) return false;
    if (module.content_base64 !== undefined) {
      const bytes = strictBase64Bytes(module.content_base64, expected.byteLength);
      if (!bytes || await sha256(bytes) !== expected.contentSha256) return false;
    }
  }
  return true;
}

async function verifyUninstallWorkerVersionSubmissionWithMode(
  recovery: UninstallWorkerVersionRecoveryRecord,
  submission: UninstallWorkerVersionSubmission,
  callInput: CloudflareDirectUploadCall,
  requireModuleContent: boolean,
): Promise<UninstallWorkerVersionSubmission> {
  if (!await validVersionRecoveryRecord(recovery) || !validVersionSubmission(recovery, submission)) {
    fail('invalid_input', 'validate', 'not_sent', [submission]);
  }
  const call = prepareCall(callInput);
  const response = await requestJson(
    call,
    'version_verify',
    // Modules are returned only when explicitly included (live 2026-08-23).
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${recovery.accountId}/workers/workers/${recovery.workerId}/versions/${submission.versionId}?include=modules`,
    { method: 'GET', headers: authHeaders(call.accessToken) },
    versionResponseMaximum(recovery),
    [submission],
  );
  if (response.status !== 200) rejectStatus(response.status, response.value, 'version_verify', [submission]);
  const result = successResult(response.value);
  if (!await exactVersionResult(result, recovery, submission.versionId, requireModuleContent)) {
    fail('provider_mismatch', 'version_verify', 'submitted', [submission]);
  }
  return submission;
}

/** Validate the exact provider version. Returned module bytes are optional, but exact when present. */
export async function verifyUninstallWorkerVersionSubmission<RecoveryInput, SubmissionInput>(
  recoveryInput: RecoveryInput,
  submissionInput: SubmissionInput,
  callInput: CloudflareDirectUploadCall,
): Promise<UninstallWorkerVersionSubmission> {
  const recovery = await parseUninstallWorkerVersionRecoveryRecord(recoveryInput);
  const submission = parseCloudflareUninstallWorkerLifecycleSubmission(submissionInput);
  if (!recovery || !submission || submission.kind !== 'uninstall_worker_version') {
    fail('invalid_input', 'validate', 'not_sent');
  }
  return verifyUninstallWorkerVersionSubmissionWithMode(recovery, submission, callInput, false);
}

type VersionListItem = v.InferOutput<typeof versionListItemSchema>;

function parseVersionListPage<Value>(
  value: Value,
  expectedPage: number,
): { readonly items: readonly VersionListItem[]; readonly totalCount: number; readonly totalPages: number } | null {
  const candidate = v.safeParse(versionListPageSchema, value);
  if (!candidate.success || !isEmptyProviderList(candidate.output.errors) ||
    !isEmptyProviderList(candidate.output.messages)) return null;
  const info = candidate.output.result_info;
  if (
    info.page !== expectedPage || info.count !== candidate.output.result.length
  ) return null;
  const calculated = info.total_count === 0 ? 0 : Math.ceil(info.total_count / VERSION_PAGE_SIZE);
  const totalPages = info.total_pages ?? calculated;
  if (!(
    (info.total_count === 0 && (totalPages === 0 || totalPages === 1) && expectedPage === 1) ||
    (info.total_count > 0 && totalPages === calculated)
  )) return null;
  return { items: candidate.output.result, totalCount: info.total_count, totalPages };
}

function versionListItem(value: VersionListItem) {
  if (value.annotations === undefined) return { id: value.id, tag: null };
  const tag = value.annotations['workers/tag'];
  return { id: value.id, tag: tag ?? null };
}

/** Fully paginate versions and recover only one exact correlation match. */
export async function inspectUninstallWorkerVersionRecovery(
  recovery: UninstallWorkerVersionRecoveryRecord,
  callInput: CloudflareDirectUploadCall,
): Promise<UninstallWorkerVersionSubmission | null> {
  if (!await validVersionRecoveryRecord(recovery)) fail('invalid_input', 'validate', 'not_sent');
  const call = prepareCall(callInput);
  const seenIds = new Set<string>();
  const matches: string[] = [];
  let totalCount: number | null = null;
  let totalPages: number | null = null;
  let observed = 0;
  for (let page = 1; page <= MAX_VERSION_PAGES; page += 1) {
    const response = await requestJson(
      call,
      'version_recovery',
      `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${recovery.accountId}/workers/workers/${recovery.workerId}/versions?page=${page}&per_page=${VERSION_PAGE_SIZE}`,
      { method: 'GET', headers: authHeaders(call.accessToken) },
      versionResponseMaximum(recovery),
    );
    if (response.status !== 200) rejectStatus(response.status, response.value, 'version_recovery');
    const parsed = parseVersionListPage(response.value, page);
    if (!parsed) fail('provider_mismatch', 'version_recovery', 'unknown');
    if (page === 1) {
      totalCount = parsed.totalCount;
      totalPages = parsed.totalPages;
    } else if (parsed.totalCount !== totalCount || parsed.totalPages !== totalPages) {
      fail('provider_mismatch', 'version_recovery', 'unknown');
    }
    for (const raw of parsed.items) {
      const item = versionListItem(raw);
      if (seenIds.has(item.id)) fail('recovery_ambiguous', 'version_recovery', 'unknown');
      seenIds.add(item.id);
      if (item.tag === recovery.correlationTag) matches.push(item.id);
    }
    observed += parsed.items.length;
    const last = (totalPages ?? 0) === 0 ? 1 : totalPages ?? 1;
    if (page === last) break;
  }
  if (totalCount === null || observed !== totalCount) fail('provider_mismatch', 'version_recovery', 'unknown');
  if (matches.length === 0) return null;
  if (matches.length !== 1) fail('recovery_ambiguous', 'version_recovery', 'unknown');
  const versionId = matches.at(0);
  if (versionId === undefined) fail('provider_mismatch', 'version_recovery', 'unknown');
  const submission = versionSubmission(recovery, versionId);
  return await verifyUninstallWorkerVersionSubmission(recovery, submission, callInput);
}

function deploymentSemanticCommitment(input: PrepareUninstallWorkerDeploymentInput): BoundaryObject {
  return {
    accountId: input.accountId,
    stage: input.stage,
    uninstallCycleId: input.uninstallCycleId,
    versionId: input.versionId,
    workerId: input.workerId,
    workerName: input.workerName,
  };
}

function deploymentCorrelationTag(stage: UninstallWorkerDeploymentStage, requestHash: string): string {
  return `ankka-un-d-${stage}-sha256:${requestHash}`;
}

function deploymentBody(
  correlationTag: string,
  versionId: string,
): UninstallWorkerDeploymentMutationIntent['body'] {
  const version: { readonly percentage: 100; readonly version_id: string } = Object.freeze({
    percentage: 100,
    version_id: versionId,
  });
  const versions: readonly [{ readonly percentage: 100; readonly version_id: string }] = Object.freeze([version]);
  return Object.freeze({
    annotations: Object.freeze({ 'workers/message': correlationTag }),
    strategy: 'percentage',
    versions,
  });
}

/**
 * Prepare a journal-safe deployment intent. `restore_clean` uses the persisted
 * pre-uninstall clean version ID, but its correlation is unique to this exact
 * uninstall cycle rather than adopting the original installation deployment.
 */
export async function prepareUninstallWorkerDeploymentMutation(
  input: PrepareUninstallWorkerDeploymentInput,
): Promise<UninstallWorkerDeploymentMutationIntent> {
  const candidate = v.safeParse(prepareDeploymentInputSchema, input);
  if (!candidate.success) fail('invalid_input', 'validate', 'not_sent');
  const parsedInput = candidate.output;
  const requestHash = await sha256(canonicalJson(deploymentSemanticCommitment(parsedInput)));
  const correlationTag = deploymentCorrelationTag(parsedInput.stage, requestHash);
  const body = deploymentBody(correlationTag, parsedInput.versionId);
  return Object.freeze({
    kind: 'uninstall_deployment',
    stage: parsedInput.stage,
    accountId: parsedInput.accountId,
    workerName: parsedInput.workerName,
    workerId: parsedInput.workerId,
    uninstallCycleId: parsedInput.uninstallCycleId,
    versionId: parsedInput.versionId,
    requestHash,
    correlationTag,
    body,
  });
}

async function validDeploymentIntent(intent: UninstallWorkerDeploymentMutationIntent): Promise<boolean> {
  if (!v.is(deploymentIntentSchema, intent) ||
    intent.correlationTag !== deploymentCorrelationTag(intent.stage, intent.requestHash) ||
    intent.body.annotations['workers/message'] !== intent.correlationTag ||
    intent.body.versions[0].version_id !== intent.versionId
  ) return false;
  return await sha256(canonicalJson(deploymentSemanticCommitment(intent))) === intent.requestHash;
}

/** Pure, exact journal parser for a semantic deployment mutation intent. */
export async function parseUninstallWorkerDeploymentMutationIntent<Input>(
  value: Input,
): Promise<UninstallWorkerDeploymentMutationIntent | null> {
  try {
    const candidate = v.safeParse(deploymentIntentSchema, value);
    if (!candidate.success) return null;
    const input = candidate.output;
    const body = deploymentBody(input.correlationTag, input.versionId);
    const parsed: UninstallWorkerDeploymentMutationIntent = Object.freeze({
      kind: 'uninstall_deployment',
      stage: input.stage,
      accountId: input.accountId,
      workerName: input.workerName,
      workerId: input.workerId,
      uninstallCycleId: input.uninstallCycleId,
      versionId: input.versionId,
      requestHash: input.requestHash,
      correlationTag: input.correlationTag,
      body,
    });
    return await validDeploymentIntent(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function deploymentSubmission(
  intent: UninstallWorkerDeploymentMutationIntent,
  deploymentId: string,
): UninstallWorkerDeploymentSubmission {
  return Object.freeze({
    kind: 'uninstall_worker_deployment',
    stage: intent.stage,
    accountId: intent.accountId,
    workerName: intent.workerName,
    workerId: intent.workerId,
    uninstallCycleId: intent.uninstallCycleId,
    versionId: intent.versionId,
    deploymentId,
    requestHash: intent.requestHash,
    correlationTag: intent.correlationTag,
  });
}

function validDeploymentSubmission(
  intent: UninstallWorkerDeploymentMutationIntent,
  submission: UninstallWorkerDeploymentSubmission,
): boolean {
  return v.is(deploymentSubmissionSchema, submission) && submission.stage === intent.stage &&
    submission.accountId === intent.accountId && submission.workerName === intent.workerName &&
    submission.workerId === intent.workerId && submission.uninstallCycleId === intent.uninstallCycleId &&
    submission.versionId === intent.versionId && submission.requestHash === intent.requestHash &&
    submission.correlationTag === intent.correlationTag && UUID.test(submission.deploymentId);
}

export async function submitUninstallWorkerDeploymentMutation(
  intent: UninstallWorkerDeploymentMutationIntent,
  callInput: CloudflareDirectUploadCall,
): Promise<UninstallWorkerDeploymentSubmission> {
  if (!await validDeploymentIntent(intent)) fail('invalid_input', 'validate', 'not_sent');
  const call = prepareCall(callInput);
  const response = await requestJson(
    call,
    'deployment_submit',
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/scripts/${encodeURIComponent(intent.workerName)}/deployments`,
    { method: 'POST', headers: jsonHeaders(call.accessToken), body: JSON.stringify(intent.body) },
  );
  const deploymentId = rawResultId(response.value, UUID);
  const surfaced = deploymentId === null ? [] : [deploymentSubmission(intent, deploymentId)];
  if (![200, 201].includes(response.status)) {
    rejectStatus(response.status, response.value, 'deployment_submit', surfaced);
  }
  if (deploymentId === null) fail('provider_mismatch', 'deployment_submit', 'unknown');
  const submission = deploymentSubmission(intent, deploymentId);
  const result = successResult(response.value);
  if (!isRecord(result) || result.id !== deploymentId) {
    fail('provider_mismatch', 'deployment_submit', 'submitted', [submission]);
  }
  return submission;
}

type DeploymentObservation = v.InferOutput<typeof deploymentObservationSchema>;

function deploymentAnnotations<Value>(
  value: Value,
): v.InferOutput<typeof deploymentAnnotationsSchema> | null {
  const candidate = v.safeParse(deploymentAnnotationsSchema, value);
  return candidate.success ? candidate.output : null;
}

function parseDeploymentObservation<Value>(value: Value): DeploymentObservation | null {
  const candidate = v.safeParse(deploymentObservationSchema, value);
  if (!candidate.success || !safeIsoDate(candidate.output.created_on)) return null;
  let percentage = 0;
  const versions = new Set<string>();
  for (const version of candidate.output.versions) {
    if (versions.has(version.version_id) || version.percentage <= 0) return null;
    versions.add(version.version_id);
    percentage += version.percentage;
  }
  return percentage === 100 ? candidate.output : null;
}

function exactDeployment<Value>(
  value: Value,
  intent: UninstallWorkerDeploymentMutationIntent,
  deploymentId: string,
): boolean {
  const deployment = parseDeploymentObservation(value);
  if (!deployment || deployment.id !== deploymentId) return false;
  const annotations = deploymentAnnotations(deployment.annotations);
  if (!annotations || annotations['workers/message'] !== intent.correlationTag) return false;
  return canonicalEqual(deployment.versions, [{ percentage: 100, version_id: intent.versionId }]);
}

export async function verifyUninstallWorkerDeploymentSubmission(
  intent: UninstallWorkerDeploymentMutationIntent,
  submission: UninstallWorkerDeploymentSubmission,
  callInput: CloudflareDirectUploadCall,
): Promise<UninstallWorkerDeploymentSubmission> {
  if (!await validDeploymentIntent(intent) || !validDeploymentSubmission(intent, submission)) {
    fail('invalid_input', 'validate', 'not_sent', [submission]);
  }
  const call = prepareCall(callInput);
  const response = await requestJson(
    call,
    'deployment_verify',
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/scripts/${encodeURIComponent(intent.workerName)}/deployments/${submission.deploymentId}`,
    { method: 'GET', headers: authHeaders(call.accessToken) },
    MAX_RESPONSE_BYTES,
    [submission],
  );
  if (response.status !== 200) rejectStatus(response.status, response.value, 'deployment_verify', [submission]);
  if (!exactDeployment(successResult(response.value), intent, submission.deploymentId)) {
    fail('provider_mismatch', 'deployment_verify', 'submitted', [submission]);
  }
  return submission;
}

function deploymentList<Value>(value: Value): readonly DeploymentObservation[] | null {
  const result = successResult(value);
  const candidate = v.safeParse(deploymentListResultSchema, result);
  if (!candidate.success) return null;
  const deployments: DeploymentObservation[] = [];
  for (const raw of candidate.output.deployments) {
    const parsed = parseDeploymentObservation(raw);
    if (!parsed) return null;
    deployments.push(parsed);
  }
  return Object.freeze(deployments);
}

async function readDeploymentList(
  intent: UninstallWorkerDeploymentMutationIntent,
  call: PreparedCall,
  stage: 'deployment_recovery' | 'deployment_active_verify',
  submissions: readonly CloudflareUninstallWorkerLifecycleSubmission[] = [],
): Promise<readonly DeploymentObservation[]> {
  const response = await requestJson(
    call,
    stage,
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/scripts/${encodeURIComponent(intent.workerName)}/deployments`,
    { method: 'GET', headers: authHeaders(call.accessToken) },
    2 * 1024 * 1024,
    submissions,
  );
  if (response.status !== 200) rejectStatus(response.status, response.value, stage, submissions);
  const deployments = deploymentList(response.value);
  if (!deployments) fail('provider_mismatch', stage, 'unknown', submissions);
  const seen = new Set<string>();
  for (const deployment of deployments) {
    const id = deployment.id;
    if (seen.has(id)) fail('recovery_ambiguous', stage, 'unknown', submissions);
    seen.add(id);
  }
  return deployments;
}

export async function inspectUninstallWorkerDeploymentRecovery(
  intent: UninstallWorkerDeploymentMutationIntent,
  callInput: CloudflareDirectUploadCall,
): Promise<UninstallWorkerDeploymentSubmission | null> {
  if (!await validDeploymentIntent(intent)) fail('invalid_input', 'validate', 'not_sent');
  const call = prepareCall(callInput);
  const deployments = await readDeploymentList(intent, call, 'deployment_recovery');
  const matches = deployments.filter((deployment) => (
    deploymentAnnotations(deployment.annotations)?.['workers/message'] ===
      intent.correlationTag
  ));
  if (matches.length === 0) return null;
  if (matches.length !== 1) fail('recovery_ambiguous', 'deployment_recovery', 'unknown');
  const match = matches[0];
  if (!match) fail('provider_mismatch', 'deployment_recovery', 'unknown');
  const submission = deploymentSubmission(intent, match.id);
  return await verifyUninstallWorkerDeploymentSubmission(intent, submission, callInput);
}

/**
 * Exact latest-active proof for every uninstall lifecycle deployment. Cleanup
 * must be current before workers.dev is enabled; retirement must be current
 * before namespace retirement is accepted; restore_clean must be current
 * before the attempt can exit. A foreign/newer item fails closed.
 */
export async function verifyUninstallWorkerDeploymentIsActive(
  intent: UninstallWorkerDeploymentMutationIntent,
  submission: UninstallWorkerDeploymentSubmission,
  callInput: CloudflareDirectUploadCall,
): Promise<UninstallWorkerDeploymentSubmission> {
  if (
    !await validDeploymentIntent(intent) || !validDeploymentSubmission(intent, submission)
  ) fail('invalid_input', 'validate', 'not_sent', [submission]);
  const call = prepareCall(callInput);
  const deployments = await readDeploymentList(
    intent,
    call,
    'deployment_active_verify',
    [submission],
  );
  if (deployments.length === 0) {
    fail('provider_mismatch', 'deployment_active_verify', 'submitted', [submission]);
  }
  const matches = deployments.filter((deployment) => (
    deploymentAnnotations(deployment.annotations)?.['workers/message'] ===
      intent.correlationTag
  ));
  if (matches.length !== 1) {
    fail(
      matches.length > 1 ? 'recovery_ambiguous' : 'provider_mismatch',
      'deployment_active_verify',
      'submitted',
      [submission],
    );
  }
  if (!exactDeployment(deployments[0], intent, submission.deploymentId)) {
    fail('provider_mismatch', 'deployment_active_verify', 'submitted', [submission]);
  }
  return submission;
}

/**
 * Prove that the exact signed cleanup module and binding set are still the
 * sole actively serving deployment. The deployment/version/deployment read
 * sequence closes the edge-readiness race as far as Cloudflare's API permits;
 * callers must run it immediately before arming the credential-bearing POST.
 */
export async function proveActiveCleanupWorkerVersion(
  recovery: CleanupWorkerVersionRecoveryRecord,
  version: UninstallWorkerVersionSubmission,
  deploymentIntent: UninstallWorkerDeploymentMutationIntent,
  deployment: UninstallWorkerDeploymentSubmission,
  callInput: CloudflareDirectUploadCall,
): Promise<ActiveCleanupWorkerVersionProof> {
  if (
    recovery.stage !== 'cleanup' ||
    version.stage !== 'cleanup' ||
    deploymentIntent.stage !== 'cleanup' ||
    deployment.stage !== 'cleanup' ||
    version.versionId !== deploymentIntent.versionId ||
    version.versionId !== deployment.versionId ||
    version.accountId !== deploymentIntent.accountId ||
    version.workerName !== deploymentIntent.workerName ||
    version.workerId !== deploymentIntent.workerId ||
    version.uninstallCycleId !== deploymentIntent.uninstallCycleId
  ) fail('invalid_input', 'validate', 'not_sent', [version, deployment]);
  await verifyUninstallWorkerDeploymentIsActive(deploymentIntent, deployment, callInput);
  await verifyUninstallWorkerVersionSubmissionWithMode(recovery, version, callInput, true);
  await verifyUninstallWorkerDeploymentIsActive(deploymentIntent, deployment, callInput);
  return Object.freeze({ version, deployment });
}

/** Backward-compatible, stage-restricted name for the restore-specific call site. */
export async function verifyRestoredCleanWorkerDeploymentIsActive(
  intent: UninstallWorkerDeploymentMutationIntent,
  submission: UninstallWorkerDeploymentSubmission,
  callInput: CloudflareDirectUploadCall,
): Promise<UninstallWorkerDeploymentSubmission> {
  if (intent.stage !== 'restore_clean') fail('invalid_input', 'validate', 'not_sent', [submission]);
  return await verifyUninstallWorkerDeploymentIsActive(intent, submission, callInput);
}

export interface ProveAdminStateNamespacePresentInput {
  readonly namespace: AdminStateDurableObjectNamespaceLocator;
  readonly workerId: string;
  readonly uninstallCycleId: string;
}

export interface ProveAdminStateNamespaceRetiredInput {
  readonly namespace: AdminStateDurableObjectNamespaceLocator;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly retirementRecovery: RetirementWorkerVersionRecoveryRecord;
  readonly retirementSubmission: UninstallWorkerVersionSubmission;
  readonly retirementDeploymentIntent: UninstallWorkerDeploymentMutationIntent;
  readonly retirementDeploymentSubmission: UninstallWorkerDeploymentSubmission;
}

/** Pure, exact journal parser for the pre-retirement namespace presence proof. */
export function parseAdminStateNamespacePresenceProof<Input>(
  value: Input,
): AdminStateNamespacePresenceProof | null {
  try {
    const candidate = v.safeParse(namespacePresenceProofSchema, value);
    if (!candidate.success) return null;
    const proof = candidate.output;
    return Object.freeze({
      kind: 'admin_state_namespace_presence',
      accountId: proof.accountId,
      workerName: proof.workerName,
      workerId: proof.workerId,
      uninstallCycleId: proof.uninstallCycleId,
      namespaceId: proof.namespaceId,
      namespaceName: proof.namespaceName,
      className: 'AdminState',
      storage: 'sqlite',
      accountNamespaceCount: proof.accountNamespaceCount,
      snapshotSha256: proof.snapshotSha256,
    });
  } catch {
    return null;
  }
}

export function parseAdminStateNamespaceRetirementProof<Input>(
  value: Input,
): AdminStateNamespaceRetirementProof | null {
  try {
    const candidate = v.safeParse(namespaceRetirementProofSchema, value);
    if (!candidate.success || candidate.output.firstSnapshotSha256 !== candidate.output.secondSnapshotSha256) {
      return null;
    }
    const proof = candidate.output;
    return Object.freeze({
      kind: 'admin_state_namespace_retirement',
      accountId: proof.accountId,
      workerName: proof.workerName,
      workerId: proof.workerId,
      uninstallCycleId: proof.uninstallCycleId,
      namespaceId: proof.namespaceId,
      retirementVersionId: proof.retirementVersionId,
      accountNamespaceCount: proof.accountNamespaceCount,
      firstSnapshotSha256: proof.firstSnapshotSha256,
      secondSnapshotSha256: proof.secondSnapshotSha256,
    });
  } catch {
    return null;
  }
}

async function validAdminStateNamespaceRetiredInput(
  input: ProveAdminStateNamespaceRetiredInput,
): Promise<boolean> {
  if (
    !v.is(namespaceRetiredInputSchema, input) ||
    input.retirementRecovery.stage !== 'retirement' ||
    input.retirementRecovery.accountId !== input.namespace.accountId ||
    input.retirementRecovery.workerName !== input.namespace.workerName ||
    input.retirementRecovery.workerId !== input.workerId ||
    input.retirementRecovery.uninstallCycleId !== input.uninstallCycleId ||
    input.retirementDeploymentIntent.stage !== 'retirement' ||
    input.retirementDeploymentIntent.accountId !== input.namespace.accountId ||
    input.retirementDeploymentIntent.workerName !== input.namespace.workerName ||
    input.retirementDeploymentIntent.workerId !== input.workerId ||
    input.retirementDeploymentIntent.uninstallCycleId !== input.uninstallCycleId ||
    input.retirementDeploymentIntent.versionId !== input.retirementSubmission.versionId
  ) return false;
  return await validVersionRecoveryRecord(input.retirementRecovery) &&
    validVersionSubmission(input.retirementRecovery, input.retirementSubmission) &&
    await validDeploymentIntent(input.retirementDeploymentIntent) &&
    validDeploymentSubmission(input.retirementDeploymentIntent, input.retirementDeploymentSubmission);
}

async function parseAdminStateNamespaceRetiredInput<Input>(
  value: Input,
): Promise<ProveAdminStateNamespaceRetiredInput | null> {
  try {
    const candidate = v.safeParse(namespaceRetiredInputSchema, value);
    if (!candidate.success) return null;
    const input = candidate.output;
    const retirementRecovery = await parseUninstallWorkerVersionRecoveryRecord(input.retirementRecovery);
    const retirementSubmission = parseCloudflareUninstallWorkerLifecycleSubmission(input.retirementSubmission);
    const retirementDeploymentIntent = await parseUninstallWorkerDeploymentMutationIntent(
      input.retirementDeploymentIntent,
    );
    const retirementDeploymentSubmission = parseCloudflareUninstallWorkerLifecycleSubmission(
      input.retirementDeploymentSubmission,
    );
    if (retirementRecovery?.stage !== 'retirement' ||
      retirementSubmission?.kind !== 'uninstall_worker_version' || retirementSubmission.stage !== 'retirement' ||
      retirementDeploymentIntent?.stage !== 'retirement' ||
      retirementDeploymentSubmission?.kind !== 'uninstall_worker_deployment' ||
      retirementDeploymentSubmission.stage !== 'retirement') return null;
    const parsed: ProveAdminStateNamespaceRetiredInput = Object.freeze({
      namespace: Object.freeze({
        accountId: input.namespace.accountId,
        namespaceId: input.namespace.namespaceId,
        namespaceName: input.namespace.namespaceName,
        workerName: input.namespace.workerName,
        className: 'AdminState',
        storage: 'sqlite',
      }),
      workerId: input.workerId,
      uninstallCycleId: input.uninstallCycleId,
      retirementRecovery,
      retirementSubmission,
      retirementDeploymentIntent,
      retirementDeploymentSubmission,
    });
    return await validAdminStateNamespaceRetiredInput(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

async function adminStateNamespaceRetirementProofCommitment(
  input: ProveAdminStateNamespaceRetiredInput,
): Promise<string> {
  return await sha256(canonicalJson(input));
}

function retirementProofMatchesInput(
  proof: AdminStateNamespaceRetirementProof,
  input: ProveAdminStateNamespaceRetiredInput,
): boolean {
  return proof.accountId === input.namespace.accountId && proof.workerName === input.namespace.workerName &&
    proof.workerId === input.workerId && proof.uninstallCycleId === input.uninstallCycleId &&
    proof.namespaceId === input.namespace.namespaceId &&
    proof.retirementVersionId === input.retirementSubmission.versionId;
}

function parseNamespacePage<Input>(
  value: Input,
  expectedPage: number,
): {
  readonly items: readonly DurableObjectNamespaceItem[];
  readonly totalCount: number;
  readonly totalPages: number;
} | null {
  const candidate = v.safeParse(namespaceListPageSchema, value);
  if (!candidate.success || !isEmptyProviderList(candidate.output.errors) ||
    !isEmptyProviderList(candidate.output.messages)) return null;
  const info = candidate.output.result_info;
  if (
    info.page !== expectedPage || info.count !== candidate.output.result.length
  ) return null;
  const calculated = info.total_count === 0 ? 0 : Math.ceil(info.total_count / NAMESPACE_PAGE_SIZE);
  const totalPages = info.total_pages ?? calculated;
  if (!(
    (info.total_count === 0 && (totalPages === 0 || totalPages === 1) && expectedPage === 1) ||
    (info.total_count > 0 && totalPages === calculated)
  )) return null;
  const items: DurableObjectNamespaceItem[] = [];
  for (const item of candidate.output.result) {
    items.push(Object.freeze({
      id: item.id,
      className: item.class,
      name: item.name,
      script: item.script,
      useSqlite: item.use_sqlite,
    }));
  }
  return { items: Object.freeze(items), totalCount: info.total_count, totalPages };
}

async function readNamespaceSnapshot(
  accountId: string,
  call: PreparedCall,
  stage: 'namespace_present' | 'namespace_absent',
): Promise<DurableObjectNamespaceSnapshot> {
  const seenIds = new Set<string>();
  const items: DurableObjectNamespaceItem[] = [];
  let totalCount: number | null = null;
  let totalPages: number | null = null;
  for (let page = 1; page <= MAX_NAMESPACE_PAGES; page += 1) {
    const response = await requestJson(
      call,
      stage,
      `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${accountId}/workers/durable_objects/namespaces?page=${page}&per_page=${NAMESPACE_PAGE_SIZE}`,
      { method: 'GET', headers: authHeaders(call.accessToken) },
      MAX_NAMESPACE_RESPONSE_BYTES,
    );
    if (response.status !== 200) rejectStatus(response.status, response.value, stage);
    const parsed = parseNamespacePage(response.value, page);
    if (!parsed) fail('provider_mismatch', stage, 'unknown');
    if (page === 1) {
      totalCount = parsed.totalCount;
      totalPages = parsed.totalPages;
    } else if (parsed.totalCount !== totalCount || parsed.totalPages !== totalPages) {
      fail('provider_mismatch', stage, 'unknown');
    }
    for (const item of parsed.items) {
      if (seenIds.has(item.id)) fail('recovery_ambiguous', stage, 'unknown');
      seenIds.add(item.id);
      items.push(item);
    }
    const lastPage = totalPages === null || totalPages === 0 ? 1 : totalPages;
    if (page === lastPage) break;
  }
  if (totalCount === null || items.length !== totalCount) fail('provider_mismatch', stage, 'unknown');
  items.sort((left, right) => lexicalCompare(left.id, right.id));
  const frozenItems = Object.freeze(items.map((item) => Object.freeze({ ...item })));
  return Object.freeze({ items: frozenItems, sha256: await sha256(canonicalJson(frozenItems)) });
}

/** Full-account, exact ownership proof required before creating retirement. */
export async function provePersistedAdminStateNamespacePresent(
  input: ProveAdminStateNamespacePresentInput,
  callInput: CloudflareDirectUploadCall,
): Promise<AdminStateNamespacePresenceProof> {
  if (!v.is(namespacePresentInputSchema, input)) fail('invalid_input', 'validate', 'not_sent');
  const call = prepareCall(callInput);
  const snapshot = await readNamespaceSnapshot(input.namespace.accountId, call, 'namespace_present');
  const identityMatches = snapshot.items.filter((item) => (
    item.script === input.namespace.workerName && item.className === 'AdminState'
  ));
  if (identityMatches.length !== 1) {
    fail(identityMatches.length > 1 ? 'recovery_ambiguous' : 'provider_mismatch', 'namespace_present', 'unknown');
  }
  const match = identityMatches.at(0);
  if (match === undefined) fail('provider_mismatch', 'namespace_present', 'unknown');
  if (
    match.id !== input.namespace.namespaceId || match.name !== input.namespace.namespaceName || !match.useSqlite
  ) fail('provider_mismatch', 'namespace_present', 'unknown');
  return Object.freeze({
    kind: 'admin_state_namespace_presence',
    accountId: input.namespace.accountId,
    workerName: input.namespace.workerName,
    workerId: input.workerId,
    uninstallCycleId: input.uninstallCycleId,
    namespaceId: input.namespace.namespaceId,
    namespaceName: input.namespace.namespaceName,
    className: 'AdminState',
    storage: 'sqlite',
    accountNamespaceCount: snapshot.items.length,
    snapshotSha256: snapshot.sha256,
  });
}

/**
 * Prove the first retirement version deleted the declarative class, then prove
 * two complete, byte-stable account namespace catalogues contain neither the
 * persisted namespace ID nor another AdminState namespace for this script.
 */
export async function proveAdminStateNamespaceRetired(
  input: ProveAdminStateNamespaceRetiredInput,
  callInput: CloudflareDirectUploadCall,
): Promise<AdminStateNamespaceRetirementProof> {
  const parsedInput = await parseAdminStateNamespaceRetiredInput(input);
  if (!parsedInput) fail('invalid_input', 'validate', 'not_sent');
  input = parsedInput;
  const call = prepareCall(callInput);
  await verifyUninstallWorkerDeploymentIsActive(
    input.retirementDeploymentIntent,
    input.retirementDeploymentSubmission,
    call,
  );
  await verifyUninstallWorkerVersionSubmission(
    input.retirementRecovery,
    input.retirementSubmission,
    call,
  );
  const first = await readNamespaceSnapshot(input.namespace.accountId, call, 'namespace_absent');
  const second = await readNamespaceSnapshot(input.namespace.accountId, call, 'namespace_absent');
  const hasResidue = (snapshot: DurableObjectNamespaceSnapshot): boolean => snapshot.items.some((item) => (
    item.id === input.namespace.namespaceId ||
    (item.script === input.namespace.workerName && item.className === 'AdminState')
  ));
  if (hasResidue(first) || hasResidue(second) || first.sha256 !== second.sha256 ||
    !canonicalEqual(first.items, second.items)) {
    fail('provider_mismatch', 'namespace_absent', 'unknown', [input.retirementSubmission]);
  }
  return Object.freeze({
    kind: 'admin_state_namespace_retirement',
    accountId: input.namespace.accountId,
    workerName: input.namespace.workerName,
    workerId: input.workerId,
    uninstallCycleId: input.uninstallCycleId,
    namespaceId: input.namespace.namespaceId,
    retirementVersionId: input.retirementSubmission.versionId,
    accountNamespaceCount: first.items.length,
    firstSnapshotSha256: first.sha256,
    secondSnapshotSha256: second.sha256,
  });
}

function workerDeleteSemanticCommitment(input: WorkerDeleteMutationIntent): BoundaryObject {
  return {
    accountId: input.accountId,
    force: 'omitted',
    method: 'DELETE',
    namespaceId: input.namespaceId,
    retirementProof: { ...input.retirementProof },
    retirementProofCommitment: input.retirementProofCommitment,
    retirementVersionId: input.retirementVersionId,
    uninstallCycleId: input.uninstallCycleId,
    workerId: input.workerId,
    workerName: input.workerName,
  };
}

export async function prepareWorkerDeleteMutation(
  input: PrepareWorkerDeleteInput,
  callInput: CloudflareDirectUploadCall,
): Promise<WorkerDeleteMutationIntent> {
  const parsedInput = await parseAdminStateNamespaceRetiredInput(input);
  if (!parsedInput) fail('invalid_input', 'validate', 'not_sent');
  input = parsedInput;
  const proved = parseAdminStateNamespaceRetirementProof(
    await proveAdminStateNamespaceRetired(input, callInput),
  );
  if (!proved || !retirementProofMatchesInput(proved, input)) {
    fail('provider_mismatch', 'namespace_absent', 'unknown', [input.retirementSubmission]);
  }
  const retirementProofCommitment = await adminStateNamespaceRetirementProofCommitment(input);
  const base: WorkerDeleteMutationIntent = {
    kind: 'uninstall_worker_delete_intent',
    accountId: input.namespace.accountId,
    workerName: input.namespace.workerName,
    workerId: input.workerId,
    uninstallCycleId: input.uninstallCycleId,
    namespaceId: input.namespace.namespaceId,
    retirementVersionId: input.retirementSubmission.versionId,
    retirementProofCommitment,
    retirementProof: proved,
    requestHash: '0'.repeat(64),
    correlationTag: '',
    method: 'DELETE',
    force: 'omitted',
  };
  const requestHash = await sha256(canonicalJson(workerDeleteSemanticCommitment(base)));
  return Object.freeze({
    ...base,
    requestHash,
    correlationTag: `ankka-un-w-delete-sha256:${requestHash}`,
  });
}

export async function parseWorkerDeleteMutationIntent<Input>(
  value: Input,
): Promise<WorkerDeleteMutationIntent | null> {
  try {
    const candidate = v.safeParse(workerDeleteIntentSchema, value);
    if (!candidate.success || candidate.output.correlationTag !==
      `ankka-un-w-delete-sha256:${candidate.output.requestHash}`) return null;
    const input = candidate.output;
    const retirementProof = parseAdminStateNamespaceRetirementProof(input.retirementProof);
    if (!retirementProof || retirementProof.accountId !== input.accountId ||
      retirementProof.workerName !== input.workerName || retirementProof.workerId !== input.workerId ||
      retirementProof.uninstallCycleId !== input.uninstallCycleId ||
      retirementProof.namespaceId !== input.namespaceId ||
      retirementProof.retirementVersionId !== input.retirementVersionId) return null;
    const parsed: WorkerDeleteMutationIntent = Object.freeze({
      kind: 'uninstall_worker_delete_intent',
      accountId: input.accountId,
      workerName: input.workerName,
      workerId: input.workerId,
      uninstallCycleId: input.uninstallCycleId,
      namespaceId: input.namespaceId,
      retirementVersionId: input.retirementVersionId,
      retirementProofCommitment: input.retirementProofCommitment,
      retirementProof,
      requestHash: input.requestHash,
      correlationTag: input.correlationTag,
      method: 'DELETE',
      force: 'omitted',
    });
    return await sha256(canonicalJson(workerDeleteSemanticCommitment(parsed))) === parsed.requestHash
      ? parsed
      : null;
  } catch {
    return null;
  }
}

function workerDeleteSubmission(intent: WorkerDeleteMutationIntent): WorkerDeleteSubmission {
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

async function requestDelete(
  call: PreparedCall,
  intent: WorkerDeleteMutationIntent,
): Promise<{ readonly status: number; readonly value: BoundaryValue | undefined }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), call.timeoutMs);
  try {
    const url = `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/workers/${intent.workerId}`;
    const request = new Request(url, {
      method: 'DELETE',
      headers: authHeaders(call.accessToken),
      signal: controller.signal,
    });
    // `force` is intentionally absent from both the URL and RequestInit.
    if (new URL(request.url).search !== '' || request.body !== null) {
      fail('invalid_input', 'validate', 'not_sent');
    }
    const response = await call.transport(request);
    if (response.status === 204) {
      if (response.body) await response.body.cancel();
      return { status: 204, value: undefined };
    }
    return { status: response.status, value: await readBoundedJson(response) };
  } catch (error) {
    if (error instanceof CloudflareUninstallWorkerLifecycleError) throw error;
    fail('provider_unknown', 'worker_delete', 'unknown');
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * The outer durable journal must CAS this mutation to its submitting state.
 * This module has no process-local replay lock. After an unknown outcome,
 * recoverWorkerDeletionOutcome is read-only and must replace any replay.
 */
export async function submitWorkerDeleteMutation<IntentInput, ProofInput>(
  intentInput: IntentInput,
  proofInput: ProofInput,
  callInput: CloudflareDirectUploadCall,
): Promise<WorkerDeleteSubmission> {
  const parsedIntent = await parseWorkerDeleteMutationIntent(intentInput);
  const parsedProofInput = await parseAdminStateNamespaceRetiredInput(proofInput);
  if (!parsedIntent || !parsedProofInput) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  const retirementProofInput = parsedProofInput;
  const commitment = await adminStateNamespaceRetirementProofCommitment(retirementProofInput);
  if (commitment !== parsedIntent.retirementProofCommitment ||
    !retirementProofMatchesInput(parsedIntent.retirementProof, retirementProofInput)) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  const call = prepareCall(callInput);
  const freshProof = parseAdminStateNamespaceRetirementProof(
    await proveAdminStateNamespaceRetired(retirementProofInput, call),
  );
  if (!freshProof || !canonicalEqual(freshProof, parsedIntent.retirementProof)) {
    fail('provider_mismatch', 'namespace_absent', 'unknown', [retirementProofInput.retirementSubmission]);
  }
  const response = await requestDelete(call, parsedIntent);
  const submission = workerDeleteSubmission(parsedIntent);
  if (![200, 202, 204].includes(response.status)) {
    if (response.value === undefined) fail('provider_unknown', 'worker_delete', 'unknown');
    rejectStatus(response.status, response.value, 'worker_delete');
  }
  if (response.status !== 204) {
    const envelope = parseEnvelope(response.value);
    if (!envelope || !envelope.success || !isEmptyProviderList(envelope.errors) ||
      !isEmptyProviderList(envelope.messages)) {
      fail('provider_mismatch', 'worker_delete', 'submitted', [submission]);
    }
    const result = envelope.result;
    const parsedResult = v.safeParse(workerDeleteResultSchema, result);
    if (!parsedResult.success || (
      parsedResult.output !== null && 'id' in parsedResult.output &&
      parsedResult.output.id !== parsedIntent.workerId
    )) {
      fail('provider_mismatch', 'worker_delete', 'submitted', [submission]);
    }
  }
  return submission;
}

async function requestAbsenceStatus(
  call: PreparedCall,
  url: string,
): Promise<{ readonly status: number; readonly value?: BoundaryValue }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), call.timeoutMs);
  try {
    const response = await call.transport(new Request(url, {
      method: 'GET',
      headers: authHeaders(call.accessToken),
      signal: controller.signal,
    }));
    if (response.status >= 200 && response.status < 300) {
      if (response.body) await response.body.cancel();
      return { status: response.status };
    }
    return { status: response.status, value: await readBoundedJson(response) };
  } catch {
    fail('provider_unknown', 'worker_delete_recovery', 'unknown');
  } finally {
    clearTimeout(timeout);
  }
}

interface ScriptListPage {
  readonly ids: readonly string[];
  readonly pagination: null | {
    readonly totalCount: number;
    readonly totalPages: number;
  };
}

function parseScriptListPage<Value>(value: Value, expectedPage: number): ScriptListPage | null {
  const candidate = v.safeParse(scriptListPageSchema, value);
  if (!candidate.success || !isEmptyProviderList(candidate.output.errors) ||
    !isEmptyProviderList(candidate.output.messages)) return null;
  const parsedPage = candidate.output;
  const ids: string[] = [];
  const seen = new Set<string>();
  for (const script of parsedPage.result) {
    if (seen.has(script.id)) return null;
    seen.add(script.id);
    ids.push(script.id);
  }
  ids.sort(lexicalCompare);
  if (parsedPage.result_info === undefined || parsedPage.result_info === null) {
    return expectedPage === 1 ? Object.freeze({ ids: Object.freeze(ids), pagination: null }) : null;
  }
  const info = parsedPage.result_info;
  if (
    info.page !== expectedPage || info.count !== ids.length
  ) return null;
  const calculated = info.total_count === 0 ? 0 : Math.ceil(info.total_count / SCRIPT_PAGE_SIZE);
  if (!(
    (info.total_count === 0 && (info.total_pages === 0 || info.total_pages === 1) && expectedPage === 1) ||
    (info.total_count > 0 && info.total_pages === calculated)
  )) return null;
  return Object.freeze({
    ids: Object.freeze(ids),
    pagination: Object.freeze({ totalCount: info.total_count, totalPages: info.total_pages }),
  });
}

async function readFullScriptList(
  intent: WorkerDeleteMutationIntent,
  call: PreparedCall,
): Promise<readonly string[]> {
  const ids: string[] = [];
  const seen = new Set<string>();
  let totalCount: number | null = null;
  let totalPages: number | null = null;
  for (let page = 1; page <= MAX_SCRIPT_PAGES; page += 1) {
    const list = await requestJson(
      call,
      'worker_delete_recovery',
      `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/scripts?page=${page}&per_page=${SCRIPT_PAGE_SIZE}`,
      { method: 'GET', headers: authHeaders(call.accessToken) },
      4 * 1024 * 1024,
    );
    if (list.status !== 200) rejectStatus(list.status, list.value, 'worker_delete_recovery');
    const parsed = parseScriptListPage(list.value, page);
    if (!parsed) fail('provider_mismatch', 'worker_delete_recovery', 'unknown');
    if (parsed.pagination === null) {
      if (page !== 1) fail('provider_mismatch', 'worker_delete_recovery', 'unknown');
      for (const id of parsed.ids) {
        if (seen.has(id)) fail('recovery_ambiguous', 'worker_delete_recovery', 'unknown');
        seen.add(id);
        ids.push(id);
      }
      totalCount = ids.length;
      totalPages = 1;
      break;
    }
    if (page === 1) {
      totalCount = parsed.pagination.totalCount;
      totalPages = parsed.pagination.totalPages;
    } else if (
      parsed.pagination.totalCount !== totalCount || parsed.pagination.totalPages !== totalPages
    ) fail('provider_mismatch', 'worker_delete_recovery', 'unknown');
    const remaining = (totalCount ?? 0) - ids.length;
    const expectedCount = Math.max(0, Math.min(SCRIPT_PAGE_SIZE, remaining));
    if (parsed.ids.length !== expectedCount) fail('provider_mismatch', 'worker_delete_recovery', 'unknown');
    for (const id of parsed.ids) {
      if (seen.has(id)) fail('recovery_ambiguous', 'worker_delete_recovery', 'unknown');
      seen.add(id);
      ids.push(id);
    }
    const lastPage = (totalPages ?? 0) === 0 ? 1 : totalPages ?? 1;
    if (page === lastPage) break;
  }
  if (totalCount === null || totalPages === null || ids.length !== totalCount) {
    fail('provider_mismatch', 'worker_delete_recovery', 'unknown');
  }
  ids.sort(lexicalCompare);
  return Object.freeze(ids);
}

async function proveOneWorkerAbsenceObservation(
  intent: WorkerDeleteMutationIntent,
  call: PreparedCall,
): Promise<{ readonly scriptIds: readonly string[]; readonly sha256: string }> {
  const beta = await requestAbsenceStatus(
    call,
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/workers/${intent.workerId}`,
  );
  if (beta.status !== 404) {
    if (beta.status >= 200 && beta.status < 300) {
      fail('deletion_not_proven', 'worker_delete_recovery', 'unknown');
    }
    rejectStatus(beta.status, beta.value, 'worker_delete_recovery');
  }
  if (!absentEnvelope(beta.value)) fail('provider_mismatch', 'worker_delete_recovery', 'unknown');

  const script = await requestAbsenceStatus(
    call,
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/scripts/${encodeURIComponent(intent.workerName)}`,
  );
  if (script.status !== 404) {
    if (script.status >= 200 && script.status < 300) {
      fail('deletion_not_proven', 'worker_delete_recovery', 'unknown');
    }
    rejectStatus(script.status, script.value, 'worker_delete_recovery');
  }
  if (!absentEnvelope(script.value)) fail('provider_mismatch', 'worker_delete_recovery', 'unknown');

  const scriptIds = await readFullScriptList(intent, call);
  if (scriptIds.includes(intent.workerName)) fail('deletion_not_proven', 'worker_delete_recovery', 'unknown');
  return Object.freeze({ scriptIds, sha256: await sha256(canonicalJson(scriptIds)) });
}

/** Pure, exact journal parser for the namespace-bound Worker absence proof. */
export function parseWorkerDeletionRecoveryProof<Input>(
  value: Input,
): WorkerDeletionRecoveryProof | null {
  try {
    const candidate = v.safeParse(workerDeletionRecoveryProofSchema, value);
    if (!candidate.success || candidate.output.firstScriptListSha256 !==
      candidate.output.secondScriptListSha256) return null;
    const input = candidate.output;
    return Object.freeze({
      kind: 'uninstall_worker_deletion_proof',
      accountId: input.accountId,
      workerName: input.workerName,
      workerId: input.workerId,
      uninstallCycleId: input.uninstallCycleId,
      namespaceId: input.namespaceId,
      retirementVersionId: input.retirementVersionId,
      retirementProofCommitment: input.retirementProofCommitment,
      requestHash: input.requestHash,
      firstScriptListSha256: input.firstScriptListSha256,
      secondScriptListSha256: input.secondScriptListSha256,
      scriptCount: input.scriptCount,
    });
  } catch {
    return null;
  }
}

/** Pure aggregate parser for every credential-free lifecycle journal kind. */
export async function parseCloudflareUninstallWorkerLifecycleJournalRecord<Input>(
  value: Input,
): Promise<CloudflareUninstallWorkerLifecycleJournalRecord | null> {
  try {
    if (!isJournalObject(value)) return null;
    const candidate = v.safeParse(boundaryObjectSchema, value);
    if (!candidate.success || !v.is(v.string(), candidate.output.kind)) return null;
    const input = candidate.output;
    switch (input.kind) {
      case 'uninstall_version_recovery':
        return await parseUninstallWorkerVersionRecoveryRecord(input);
      case 'uninstall_worker_version':
      case 'uninstall_worker_deployment':
      case 'uninstall_worker_delete':
        return parseCloudflareUninstallWorkerLifecycleSubmission(input);
      case 'uninstall_deployment':
        return await parseUninstallWorkerDeploymentMutationIntent(input);
      case 'admin_state_namespace_presence':
        return parseAdminStateNamespacePresenceProof(input);
      case 'admin_state_namespace_retirement':
        return parseAdminStateNamespaceRetirementProof(input);
      case 'uninstall_worker_delete_intent':
        return await parseWorkerDeleteMutationIntent(input);
      case 'uninstall_worker_deletion_proof':
        return parseWorkerDeletionRecoveryProof(input);
      default:
        return null;
    }
  } catch {
    return null;
  }
}

/**
 * Outcome-unknown recovery. This never replays DELETE and never adopts a
 * same-named Worker: exact beta-ID absence and same-name Script GET/list
 * absence must hold across two identical full list observations.
 */
export async function recoverWorkerDeletionOutcome(
  intent: WorkerDeleteMutationIntent,
  callInput: CloudflareDirectUploadCall,
): Promise<WorkerDeletionRecoveryProof> {
  const parsedIntent = await parseWorkerDeleteMutationIntent(intent);
  if (!parsedIntent) fail('invalid_input', 'validate', 'not_sent');
  const call = prepareCall(callInput);
  const first = await proveOneWorkerAbsenceObservation(parsedIntent, call);
  const second = await proveOneWorkerAbsenceObservation(parsedIntent, call);
  if (first.sha256 !== second.sha256 || !canonicalEqual(first.scriptIds, second.scriptIds)) {
    fail('deletion_not_proven', 'worker_delete_recovery', 'unknown');
  }
  return Object.freeze({
    kind: 'uninstall_worker_deletion_proof',
    accountId: parsedIntent.accountId,
    workerName: parsedIntent.workerName,
    workerId: parsedIntent.workerId,
    uninstallCycleId: parsedIntent.uninstallCycleId,
    namespaceId: parsedIntent.namespaceId,
    retirementVersionId: parsedIntent.retirementVersionId,
    retirementProofCommitment: parsedIntent.retirementProofCommitment,
    requestHash: parsedIntent.requestHash,
    firstScriptListSha256: first.sha256,
    secondScriptListSha256: second.sha256,
    scriptCount: first.scriptIds.length,
  });
}
