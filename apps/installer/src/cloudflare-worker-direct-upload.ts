import * as v from 'valibot';

import {
  boundaryObjectSchema,
  boundaryValueSchema,
  type BoundaryObject,
  type BoundaryValue,
} from './boundary';
import { canonicalJson } from './canonical-json';
import { CLOUDFLARE_API_ORIGIN } from './constants';

const ACCOUNT_ID_PATTERN = /^[a-f0-9]{32}$/u;
const WORKER_ID_PATTERN = /^[a-f0-9]{32}$/u;
const WORKER_NAME_PATTERN = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const ASSET_HASH_PATTERN = /^[a-f0-9]{32}$/u;
const UUID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const RELEASE_PATTERN = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const TOKEN_PATTERN = /^[A-Za-z0-9._~-]+$/u;
const DNS_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;

const MAX_RESPONSE_BYTES = 128 * 1024;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_RELEASE_BYTES = 32 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const MANAGED_WORKER_TAG = 'ankka-mcp-gateway';
const NAMESPACE_PAGE_SIZE = 1_000;
const MAX_NAMESPACE_PAGES = 100;
const MAX_NAMESPACE_COUNT = NAMESPACE_PAGE_SIZE * MAX_NAMESPACE_PAGES;
const MAX_NAMESPACE_RESPONSE_BYTES = 512 * 1024;

const EXACT_COMPATIBILITY_DATE = '2026-08-08';
const EXACT_RUN_WORKER_FIRST = Object.freeze(['/__ankka/*', '/api/*'] as const);
const EXACT_PLAIN_TEXT_BINDINGS = Object.freeze([
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

const MODULE_CONTENT_TYPES: Readonly<Record<string, string>> = Object.freeze({
  '.js': 'application/javascript+module',
  '.mjs': 'application/javascript+module',
  '.wasm': 'application/wasm',
});

const ASSET_CONTENT_TYPES: Readonly<Record<string, string>> = Object.freeze({
  '.avif': 'image/avif',
  '.css': 'text/css; charset=utf-8',
  '.gif': 'image/gif',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.jpeg': 'image/jpeg',
  '.jpg': 'image/jpeg',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.otf': 'font/otf',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.ttf': 'font/ttf',
  '.wasm': 'application/wasm',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
});

const accountIdSchema = v.pipe(v.string(), v.regex(ACCOUNT_ID_PATTERN));
const workerNameSchema = v.pipe(v.string(), v.regex(WORKER_NAME_PATTERN));
const sha256Schema = v.pipe(v.string(), v.regex(SHA256_PATTERN));
const safeTokenSchema = v.pipe(v.string(), v.minLength(20), v.maxLength(8_192), v.regex(TOKEN_PATTERN));
const safeBootstrapNonceSchema = v.pipe(safeTokenSchema, v.minLength(32));
const safeBindingValueSchema = v.pipe(
  v.string(),
  v.minLength(1),
  v.maxLength(4_096),
  v.check((value) => ![...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  })),
);
const uploadFileSchema = v.strictObject({
  name: v.string(),
  contentType: v.string(),
  sha256: sha256Schema,
  bytes: v.instance(Uint8Array),
});
const assetFileSchema = v.strictObject({
  path: v.string(),
  contentType: v.string(),
  sha256: sha256Schema,
  bytes: v.instance(Uint8Array),
});
const plainTextBindingsSchema = v.strictObject({
  ADMIN_EMAILS: safeBindingValueSchema,
  ANKKA_GATEWAY_RELEASE: safeBindingValueSchema,
  ANKKA_GATEWAY_RELEASE_SHA256: safeBindingValueSchema,
  ANKKA_MANAGEMENT_HOSTNAME: safeBindingValueSchema,
  ANKKA_UPDATE_CHANNEL: safeBindingValueSchema,
  ANKKA_UPDATE_KEY_ID: safeBindingValueSchema,
  ANKKA_UPDATE_PUBLIC_KEY: safeBindingValueSchema,
  ANKKA_WORKERS_SUBDOMAIN: safeBindingValueSchema,
  ANKKA_WORKER_NAME: safeBindingValueSchema,
  CF_ACCESS_AUD: safeBindingValueSchema,
  CF_ACCESS_ISSUER: safeBindingValueSchema,
  CLOUDFLARE_ACCOUNT_ID: safeBindingValueSchema,
  CLOUDFLARE_ZONE_ID: safeBindingValueSchema,
  CLOUDFLARE_ZONE_NAME: safeBindingValueSchema,
  ZERO_TRUST_READY: safeBindingValueSchema,
});
const prepareReleaseInputSchema = v.object({
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  release: v.strictObject({
    verification: v.literal('ed25519'),
    release: v.pipe(v.string(), v.regex(RELEASE_PATTERN)),
    artifactSha256: sha256Schema,
    worker: v.strictObject({
      mainModule: v.literal('index.js'),
      compatibilityDate: v.literal(EXACT_COMPATIBILITY_DATE),
      compatibilityFlags: v.tuple([]),
      modules: v.pipe(v.array(uploadFileSchema), v.minLength(1)),
      assets: v.strictObject({
        binding: v.literal('ASSETS'),
        notFoundHandling: v.literal('single-page-application'),
        runWorkerFirst: v.tuple([v.literal('/__ankka/*'), v.literal('/api/*')]),
        files: v.pipe(v.array(assetFileSchema), v.minLength(1)),
      }),
      durableObject: v.strictObject({
        binding: v.literal('ADMIN_STATE'),
        className: v.literal('AdminState'),
        storage: v.literal('sqlite'),
      }),
    }),
  }),
  plainTextBindings: plainTextBindingsSchema,
  bootstrapNonce: safeBootstrapNonceSchema,
});
const directUploadTransportSchema = v.custom<CloudflareDirectUploadTransport>(
  (value) => v.is(v.function(), value),
);
const directUploadCallSchema = v.object({
  accessToken: safeTokenSchema,
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
const emptyBoundaryArraySchema = v.pipe(v.array(boundaryValueSchema), v.length(0));
const disabledObservabilityDetailSchema = v.looseObject({
  enabled: v.optional(v.literal(false)),
  destinations: v.optional(emptyBoundaryArraySchema),
});
const disabledObservabilitySchema = v.strictObject({
  enabled: v.literal(false),
  head_sampling_rate: v.optional(boundaryValueSchema),
  redact_query_string: v.optional(v.literal(false)),
  logs: v.optional(disabledObservabilityDetailSchema),
  traces: v.optional(disabledObservabilityDetailSchema),
});
const emptyWorkerReferencesSchema = v.strictObject({
  dispatch_namespace_outbounds: emptyBoundaryArraySchema,
  domains: emptyBoundaryArraySchema,
  durable_objects: emptyBoundaryArraySchema,
  queues: emptyBoundaryArraySchema,
  workers: emptyBoundaryArraySchema,
});
const convergedWorkerReferencesSchema = v.strictObject({
  dispatch_namespace_outbounds: emptyBoundaryArraySchema,
  domains: v.pipe(v.array(v.strictObject({
    id: v.string(),
    hostname: v.string(),
    zone_id: v.string(),
    zone_name: v.string(),
  })), v.length(1)),
  durable_objects: v.pipe(v.array(v.strictObject({
    worker_id: v.string(),
    worker_name: v.string(),
    namespace_id: v.string(),
    namespace_name: v.string(),
  })), v.length(1)),
  queues: emptyBoundaryArraySchema,
  workers: emptyBoundaryArraySchema,
});
const workerStateSchema = v.strictObject({
  created_on: v.string(),
  deployed_on: v.optional(v.nullable(v.string())),
  id: v.pipe(v.string(), v.regex(WORKER_ID_PATTERN)),
  logpush: v.literal(false),
  name: v.string(),
  observability: disabledObservabilitySchema,
  references: boundaryValueSchema,
  subdomain: v.strictObject({ enabled: v.literal(false), previews_enabled: v.literal(false) }),
  tags: v.array(v.string()),
  tail_consumers: emptyBoundaryArraySchema,
  updated_on: v.string(),
});
const workerTargetInputSchema = v.strictObject({ accountId: accountIdSchema, workerName: workerNameSchema });
const workerIntentSchema = v.strictObject({
  kind: v.literal('worker'),
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  requestHash: sha256Schema,
  correlationTag: v.pipe(v.string(), v.regex(/^ankka-worker-sha256:[a-f0-9]{64}$/u)),
  body: v.strictObject({
    logpush: v.literal(false),
    name: workerNameSchema,
    observability: v.strictObject({ enabled: v.literal(false) }),
    subdomain: v.strictObject({ enabled: v.literal(false), previews_enabled: v.literal(false) }),
    tags: v.array(v.string()),
    tail_consumers: emptyBoundaryArraySchema,
  }),
});
const namespaceTextSchema = (maximum: number) => v.pipe(
  v.string(),
  v.minLength(1),
  v.maxLength(maximum),
  v.check((value) => ![...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  })),
);
const durableObjectNamespaceItemSchema = v.strictObject({
  id: accountIdSchema,
  class: namespaceTextSchema(128),
  name: namespaceTextSchema(256),
  script: namespaceTextSchema(128),
  use_sqlite: v.boolean(),
});
const durableObjectNamespacePageSchema = v.strictObject({
  errors: v.nullable(v.array(boundaryValueSchema)),
  messages: v.nullable(v.array(boundaryValueSchema)),
  result: v.array(durableObjectNamespaceItemSchema),
  result_info: v.strictObject({
    count: v.pipe(v.number(), v.safeInteger(), v.minValue(0)),
    page: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
    per_page: v.literal(NAMESPACE_PAGE_SIZE),
    total_count: v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(MAX_NAMESPACE_COUNT)),
    total_pages: v.optional(v.pipe(
      v.number(),
      v.safeInteger(),
      v.minValue(0),
      v.maxValue(MAX_NAMESPACE_PAGES),
    )),
  }),
  success: v.literal(true),
});
const inspectNamespaceInputSchema = v.strictObject({
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  className: v.literal('AdminState'),
  storage: v.literal('sqlite'),
  expectedNamespaceId: v.optional(accountIdSchema),
});
const assetHashSchema = v.pipe(v.string(), v.regex(ASSET_HASH_PATTERN));
const assetManifestEntrySchema = v.strictObject({
  hash: assetHashSchema,
  size: v.pipe(v.number(), v.safeInteger(), v.minValue(1), v.maxValue(MAX_FILE_BYTES)),
});
const assetManifestSchema = v.pipe(
  v.record(v.string(), assetManifestEntrySchema),
  v.check((manifest) => Object.keys(manifest).length > 0),
);
const assetSessionResponseSchema = v.strictObject({
  jwt: safeTokenSchema,
  buckets: v.array(v.pipe(v.array(assetHashSchema), v.minLength(1))),
});
const assetSessionIntentSchema = v.strictObject({
  kind: v.literal('asset_session'),
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  requestHash: sha256Schema,
  body: v.strictObject({ manifest: assetManifestSchema }),
});
const assetSessionSubmissionSchema = v.strictObject({
  kind: v.literal('asset_session'),
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  requestHash: sha256Schema,
  uploadJwt: safeTokenSchema,
  buckets: v.pipe(
    v.array(v.pipe(v.array(assetHashSchema), v.minLength(1), v.maxLength(10_000))),
    v.minLength(1),
    v.maxLength(10_000),
  ),
});
const assetBucketIntentSchema = v.strictObject({
  kind: v.literal('asset_bucket'),
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  sessionRequestHash: sha256Schema,
  bucketIndex: v.pipe(v.number(), v.safeInteger(), v.minValue(0)),
  bucketCount: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
  hashes: v.pipe(v.array(assetHashSchema), v.minLength(1)),
  isFinal: v.boolean(),
  requestHash: sha256Schema,
});
const workerVersionPhaseSchema = v.picklist(['provision', 'bootstrap', 'clean']);
const exactRunWorkerFirstSchema = v.tuple([v.literal('/__ankka/*'), v.literal('/api/*')]);
const releaseExportsSchema = v.strictObject({
  AdminState: v.strictObject({
    type: v.literal('durable-object'),
    storage: v.literal('sqlite'),
    state: v.optional(v.literal('created')),
  }),
  default: v.optional(v.strictObject({
    type: v.literal('worker'),
    state: v.optional(v.literal('created')),
    cache: v.optional(v.strictObject({ enabled: v.literal(false) })),
  })),
});
const exportsReconciliationSchema = v.strictObject({
  created: v.pipe(v.array(v.string()), v.maxLength(1)),
  deleted: emptyBoundaryArraySchema,
  info: emptyBoundaryArraySchema,
  removable_entries: emptyBoundaryArraySchema,
  renamed: emptyBoundaryArraySchema,
  transfer_pending: emptyBoundaryArraySchema,
  transferred: emptyBoundaryArraySchema,
  updated: emptyBoundaryArraySchema,
  warnings: emptyBoundaryArraySchema,
});
const versionAnnotationsSchema = v.strictObject({
  'workers/tag': v.string(),
  'workers/message': v.optional(v.pipe(v.string(), v.minLength(1), v.maxLength(256))),
  'workers/triggered_by': v.optional(v.pipe(v.string(), v.minLength(1), v.maxLength(256))),
});
const workerVersionAssetConfigSchema = v.strictObject({
  html_handling: v.optional(v.literal('auto-trailing-slash')),
  not_found_handling: v.literal('single-page-application'),
  run_worker_first: exactRunWorkerFirstSchema,
});
const returnedVersionBindingSchema = v.union([
  v.strictObject({
    name: v.literal('ADMIN_STATE'),
    type: v.literal('durable_object_namespace'),
    class_name: v.literal('AdminState'),
    namespace_id: v.optional(accountIdSchema),
  }),
  v.strictObject({ name: v.literal('ASSETS'), type: v.literal('assets') }),
  v.strictObject({ name: v.literal('ANKKA_BOOTSTRAP_NONCE'), type: v.literal('secret_text') }),
  v.strictObject({
    name: v.picklist(EXACT_PLAIN_TEXT_BINDINGS),
    type: v.literal('plain_text'),
    text: v.string(),
  }),
]);
const returnedVersionModuleSchema = v.strictObject({
  name: v.string(),
  content_type: v.string(),
  content_base64: v.optional(v.string()),
});
const versionResultSchema = v.strictObject({
  annotations: versionAnnotationsSchema,
  assets: v.optional(v.strictObject({ config: workerVersionAssetConfigSchema })),
  bindings: v.array(returnedVersionBindingSchema),
  compatibility_date: v.literal(EXACT_COMPATIBILITY_DATE),
  compatibility_flags: v.optional(v.tuple([])),
  created_on: v.string(),
  env: v.optional(boundaryObjectSchema),
  exports: releaseExportsSchema,
  exports_reconciliation: v.optional(exportsReconciliationSchema),
  id: v.string(),
  limits: v.optional(v.strictObject({
    cpu_ms: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(0))),
  })),
  main_module: v.literal('index.js'),
  modules: v.array(returnedVersionModuleSchema),
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
const versionReleaseContractSchema = v.strictObject({
  assetBinding: v.literal('ASSETS'),
  assetConfig: v.strictObject({
    notFoundHandling: v.literal('single-page-application'),
    runWorkerFirst: exactRunWorkerFirstSchema,
  }),
  bootstrapBinding: v.picklist(['present', 'absent']),
  compatibilityDate: v.literal(EXACT_COMPATIBILITY_DATE),
  compatibilityFlags: v.tuple([]),
  durableObject: v.strictObject({
    binding: v.literal('ADMIN_STATE'),
    className: v.literal('AdminState'),
    storage: v.literal('sqlite'),
  }),
  exports: v.strictObject({
    AdminState: v.strictObject({ type: v.literal('durable-object'), storage: v.literal('sqlite') }),
  }),
  mainModule: v.literal('index.js'),
});
const versionRecoveryRecordSchema = v.strictObject({
  kind: v.literal('version_recovery'),
  phase: workerVersionPhaseSchema,
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workerId: v.pipe(v.string(), v.regex(WORKER_ID_PATTERN)),
  requestHash: sha256Schema,
  correlationTag: v.string(),
  releaseContract: versionReleaseContractSchema,
  assets: v.pipe(v.array(v.strictObject({
    path: v.string(),
    uploadHash: assetHashSchema,
    contentType: v.string(),
    byteLength: v.pipe(v.number(), v.safeInteger(), v.minValue(1), v.maxValue(MAX_FILE_BYTES)),
  })), v.minLength(1), v.maxLength(10_000)),
  plainTextBindingHashes: v.pipe(v.array(v.strictObject({
    name: v.picklist(EXACT_PLAIN_TEXT_BINDINGS),
    valueSha256: sha256Schema,
  })), v.length(EXACT_PLAIN_TEXT_BINDINGS.length)),
  modules: v.pipe(v.array(v.strictObject({
    name: v.string(),
    contentType: v.string(),
    contentSha256: sha256Schema,
    byteLength: v.pipe(v.number(), v.safeInteger(), v.minValue(1), v.maxValue(MAX_FILE_BYTES)),
  })), v.minLength(1)),
});
const submitVersionBindingSchema = v.union([
  v.strictObject({
    name: v.literal('ADMIN_STATE'),
    type: v.literal('durable_object_namespace'),
    class_name: v.literal('AdminState'),
  }),
  v.strictObject({ name: v.literal('ASSETS'), type: v.literal('assets') }),
  v.strictObject({
    name: v.literal('ANKKA_BOOTSTRAP_NONCE'),
    type: v.literal('secret_text'),
    text: safeBootstrapNonceSchema,
  }),
  v.strictObject({
    name: v.picklist(EXACT_PLAIN_TEXT_BINDINGS),
    type: v.literal('plain_text'),
    text: v.string(),
  }),
]);
const versionSubmitIntentSchema = v.strictObject({
  kind: v.literal('version_submit'),
  phase: workerVersionPhaseSchema,
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workerId: v.pipe(v.string(), v.regex(WORKER_ID_PATTERN)),
  requestHash: sha256Schema,
  correlationTag: v.string(),
  semanticCommitment: boundaryObjectSchema,
  body: v.strictObject({
    annotations: v.strictObject({ 'workers/tag': v.string() }),
    assets: v.optional(v.strictObject({ config: v.strictObject({
      not_found_handling: v.literal('single-page-application'),
      run_worker_first: exactRunWorkerFirstSchema,
    }), jwt: safeTokenSchema })),
    bindings: v.array(submitVersionBindingSchema),
    compatibility_date: v.literal(EXACT_COMPATIBILITY_DATE),
    compatibility_flags: v.tuple([]),
    exports: v.strictObject({
      AdminState: v.strictObject({ type: v.literal('durable-object'), storage: v.literal('sqlite') }),
    }),
    main_module: v.literal('index.js'),
    modules: v.array(v.strictObject({
      name: v.string(),
      content_type: v.string(),
      content_base64: v.string(),
    })),
  }),
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
  id: v.pipe(v.string(), v.regex(UUID_PATTERN)),
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
  result: v.pipe(v.array(versionListItemSchema), v.maxLength(1)),
  result_info: v.strictObject({
    count: v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(1)),
    page: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
    per_page: v.literal(1),
    total_count: v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(100)),
    total_pages: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(100))),
  }),
  success: v.literal(true),
});
const deploymentAnnotationsSchema = v.strictObject({
  'workers/message': v.optional(v.pipe(v.string(), v.minLength(1), v.maxLength(256))),
  'workers/triggered_by': v.optional(v.pipe(v.string(), v.minLength(1), v.maxLength(256))),
});
const deploymentVersionSchema = v.strictObject({
  version_id: v.pipe(v.string(), v.regex(UUID_PATTERN)),
  percentage: v.pipe(v.number(), v.finite(), v.minValue(Number.MIN_VALUE), v.maxValue(100)),
});
const deploymentObservationSchema = v.strictObject({
  annotations: v.optional(deploymentAnnotationsSchema),
  author_email: v.optional(v.pipe(v.string(), v.minLength(1), v.maxLength(320))),
  created_on: v.string(),
  id: v.pipe(v.string(), v.regex(UUID_PATTERN)),
  source: v.literal('api'),
  strategy: v.literal('percentage'),
  versions: v.pipe(v.array(deploymentVersionSchema), v.minLength(1), v.maxLength(100)),
});
const deploymentListResultSchema = v.strictObject({
  deployments: v.pipe(v.array(deploymentObservationSchema), v.maxLength(1_000)),
});

export type CloudflareDirectUploadStage =
  | 'validate'
  | 'worker_lookup'
  | 'worker_create'
  | 'worker_verify'
  | 'worker_recovery'
  | 'namespace_verify'
  | 'asset_session'
  | 'asset_bucket'
  | 'worker_version'
  | 'version_verify'
  | 'version_recovery'
  | 'deployment'
  | 'deployment_verify'
  | 'deployment_active_verify'
  | 'deployment_recovery';

export type CloudflareDirectUploadOutcome = 'not_sent' | 'rejected' | 'unknown' | 'submitted';

// 'provision' is the first version of a brand-new Worker: it declares the
// Durable Object class via `exports` but carries no ADMIN_STATE or ASSETS
// binding, because the live Versions API rejects a binding whose class has
// not been provisioned by a deployment yet (observed 2026-08-23). Its
// deployment provisions the namespace; the bootstrap version then binds it.
export type WorkerVersionPhase = 'provision' | 'bootstrap' | 'clean';

export type CloudflareDirectUploadErrorCode =
  | 'invalid_input'
  | 'worker_name_collision'
  | 'provider_rejected'
  | 'provider_unknown'
  | 'provider_mismatch'
  | 'recovery_ambiguous';

export type CloudflareDirectUploadSubmission =
  | {
      readonly kind: 'worker';
      readonly accountId: string;
      readonly workerName: string;
      readonly workerId: string;
    }
  | {
      readonly kind: 'version';
      readonly phase: WorkerVersionPhase;
      readonly accountId: string;
      readonly workerName: string;
      readonly workerId: string;
      readonly versionId: string;
      readonly requestHash: string;
      readonly correlationTag: string;
    }
  | {
      readonly kind: 'deployment';
      readonly phase: WorkerVersionPhase;
      readonly accountId: string;
      readonly workerName: string;
      readonly workerId: string;
      readonly versionId: string;
      readonly deploymentId: string;
      readonly requestHash: string;
      readonly correlationTag: string;
    };

export interface CloudflareDirectUploadProgress {
  readonly workerCreated: boolean;
  readonly workerVerified: boolean;
  readonly assetSessionCreated: boolean;
  readonly assetBucketsCompleted: number;
  readonly assetBucketCount: number;
  readonly versionCreated: boolean;
  readonly deploymentVerified: boolean;
}

/**
 * Safe, body-free failure information. A caller must start a separate recovery
 * workflow after any mutation-stage failure; this module deliberately exposes
 * no replay token and never retries a request.
 */
export class CloudflareDirectUploadError extends Error {
  readonly code: CloudflareDirectUploadErrorCode;
  readonly stage: CloudflareDirectUploadStage;
  readonly outcome: CloudflareDirectUploadOutcome;
  readonly progress: CloudflareDirectUploadProgress;
  readonly submissions: readonly CloudflareDirectUploadSubmission[];
  readonly canRetry: false;

  constructor(
    code: CloudflareDirectUploadErrorCode,
    stage: CloudflareDirectUploadStage,
    outcome: CloudflareDirectUploadOutcome,
    progress: CloudflareDirectUploadProgress,
    submissions: readonly CloudflareDirectUploadSubmission[] = [],
  ) {
    super(code);
    this.name = 'CloudflareDirectUploadError';
    this.code = code;
    this.stage = stage;
    this.outcome = outcome;
    this.progress = Object.freeze({ ...progress });
    this.submissions = Object.freeze(submissions.map((submission) => Object.freeze({ ...submission })));
    this.canRetry = false;
  }
}

export interface VerifiedWorkerUploadFile {
  readonly name: string;
  readonly contentType: string;
  readonly sha256: string;
  readonly bytes: Uint8Array;
}

export interface VerifiedWorkerAssetFile {
  readonly path: string;
  readonly contentType: string;
  readonly sha256: string;
  readonly bytes: Uint8Array;
}

/**
 * This is the narrow handoff expected from the separate signed-release
 * verifier. Raw bytes are re-hashed here before any provider request.
 */
export interface VerifiedWorkerDirectUploadRelease {
  readonly verification: 'ed25519';
  readonly release: string;
  /** Aggregate `manifest.artifact.treeSha256`, never a component tree digest. */
  readonly artifactSha256: string;
  readonly worker: {
    readonly mainModule: 'index.js';
    readonly compatibilityDate: '2026-08-08';
    readonly compatibilityFlags: readonly [];
    readonly modules: readonly VerifiedWorkerUploadFile[];
    readonly assets: {
      readonly binding: 'ASSETS';
      readonly notFoundHandling: 'single-page-application';
      readonly runWorkerFirst: readonly ['/__ankka/*', '/api/*'];
      readonly files: readonly VerifiedWorkerAssetFile[];
    };
    readonly durableObject: {
      readonly binding: 'ADMIN_STATE';
      readonly className: 'AdminState';
      readonly storage: 'sqlite';
    };
  };
}

export type GatewayWorkerPlainTextBindingName = (typeof EXACT_PLAIN_TEXT_BINDINGS)[number];
export type GatewayWorkerPlainTextBindings = Readonly<Record<GatewayWorkerPlainTextBindingName, string>>;

export type CloudflareDirectUploadTransport = (request: Request) => Promise<Response>;

export interface PrepareVerifiedWorkerReleaseInput {
  readonly accountId: string;
  readonly workerName: string;
  readonly release: VerifiedWorkerDirectUploadRelease;
  readonly plainTextBindings: GatewayWorkerPlainTextBindings;
  readonly bootstrapNonce: string;
}

export interface CloudflareDirectUploadCall {
  readonly accessToken: string;
  readonly transport: CloudflareDirectUploadTransport;
  readonly timeoutMs?: number;
}

export interface AdminStateDurableObjectNamespaceLocator {
  readonly accountId: string;
  readonly namespaceId: string;
  readonly namespaceName: string;
  readonly workerName: string;
  readonly className: 'AdminState';
  readonly storage: 'sqlite';
}

export interface InspectAdminStateDurableObjectNamespaceInput {
  readonly accountId: string;
  readonly workerName: string;
  readonly className: 'AdminState';
  readonly storage: 'sqlite';
  readonly expectedNamespaceId?: string;
}

export interface DeployVerifiedWorkerReleaseInput
  extends PrepareVerifiedWorkerReleaseInput, CloudflareDirectUploadCall {}

export interface DeployVerifiedWorkerReleaseResult {
  readonly workerId: string;
  readonly workerName: string;
  readonly versionId: string;
  readonly deploymentId: string;
  readonly percentage: 100;
}

export interface PreparedModule {
  readonly name: string;
  readonly contentType: string;
  readonly bytes: Uint8Array;
}

export interface PreparedAsset {
  readonly path: string;
  readonly contentType: string;
  readonly bytes: Uint8Array;
  readonly uploadHash: string;
}

export interface PreparedVerifiedWorkerRelease {
  readonly accountId: string;
  readonly workerName: string;
  readonly release: string;
  readonly modules: readonly PreparedModule[];
  readonly assets: readonly PreparedAsset[];
  readonly plainTextBindings: GatewayWorkerPlainTextBindings;
  readonly bootstrapNonce: string;
}

interface PreparedCall {
  readonly accessToken: string;
  readonly transport: CloudflareDirectUploadTransport;
  readonly timeoutMs: number;
}

interface MutableProgress {
  workerCreated: boolean;
  workerVerified: boolean;
  assetSessionCreated: boolean;
  assetBucketsCompleted: number;
  assetBucketCount: number;
  versionCreated: boolean;
  deploymentVerified: boolean;
}

interface CloudflareEnvelope {
  readonly errors: null | readonly BoundaryValue[];
  readonly messages: null | readonly BoundaryValue[];
  readonly result: BoundaryValue;
  readonly success: boolean;
}

function initialProgress(): MutableProgress {
  return {
    workerCreated: false,
    workerVerified: false,
    assetSessionCreated: false,
    assetBucketsCompleted: 0,
    assetBucketCount: 0,
    versionCreated: false,
    deploymentVerified: false,
  };
}

function fail(
  code: CloudflareDirectUploadErrorCode,
  stage: CloudflareDirectUploadStage,
  outcome: CloudflareDirectUploadOutcome,
  progress: MutableProgress,
  submissions: readonly CloudflareDirectUploadSubmission[] = [],
): never {
  throw new CloudflareDirectUploadError(code, stage, outcome, progress, submissions);
}

function submissionKey(submission: CloudflareDirectUploadSubmission): string {
  if (submission.kind === 'worker') return `worker:${submission.workerId}`;
  if (submission.kind === 'version') return `version:${submission.versionId}`;
  return `deployment:${submission.deploymentId}`;
}

function rethrowWithSubmissions<Thrown>(
  error: Thrown,
  submissions: readonly CloudflareDirectUploadSubmission[],
  outcome?: CloudflareDirectUploadOutcome,
): never {
  if (!(error instanceof CloudflareDirectUploadError)) throw error;
  const merged = new Map<string, CloudflareDirectUploadSubmission>();
  for (const submission of [...error.submissions, ...submissions]) {
    merged.set(submissionKey(submission), submission);
  }
  throw new CloudflareDirectUploadError(
    error.code,
    error.stage,
    outcome ?? error.outcome,
    error.progress,
    [...merged.values()],
  );
}

function isRecord<Value>(value: Value): value is Value & BoundaryObject {
  return v.is(boundaryObjectSchema, value);
}

function exactKeys<Value extends object>(value: Value, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function lexicalCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isEmptyProviderList<Value>(value: Value): boolean {
  return v.is(v.union([v.null(), v.pipe(v.array(boundaryValueSchema), v.length(0))]), value);
}

function validProviderErrorList<Value>(value: Value): boolean {
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

function parseSuccessEnvelope<Value>(value: Value): BoundaryValue | null {
  const envelope = parseEnvelope(value);
  if (
    !envelope ||
    envelope.success !== true ||
    !isEmptyProviderList(envelope.errors) ||
    !isEmptyProviderList(envelope.messages)
  ) return null;
  return envelope.result;
}

function parseAbsentEnvelope<Value>(value: Value): boolean {
  const envelope = parseEnvelope(value);
  return Boolean(
    envelope &&
    envelope.success === false &&
    validProviderErrorList(envelope.errors) &&
    isEmptyProviderList(envelope.messages) &&
    envelope.result === null,
  );
}

function safeToken<Value>(value: Value, minimum = 20): value is Value & string {
  return v.is(v.pipe(safeTokenSchema, v.minLength(minimum)), value);
}

function extension(path: string): string {
  const slash = path.lastIndexOf('/');
  const dot = path.lastIndexOf('.');
  return dot > slash ? path.slice(dot).toLowerCase() : '';
}

function hasControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  });
}

function safeModuleName<Value>(value: Value): value is Value & string {
  if (!v.is(v.pipe(v.string(), v.minLength(1), v.maxLength(256)), value)) return false;
  if (value.startsWith('/') || value.includes('\\') || hasControlCharacter(value)) return false;
  return value.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..');
}

function safeAssetPath<Value>(value: Value): value is Value & string {
  if (!v.is(v.pipe(v.string(), v.minLength(2), v.maxLength(1_024)), value)) return false;
  if (!value.startsWith('/') || value.includes('\\') || hasControlCharacter(value)) return false;
  return value.slice(1).split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..');
}

function safeBindingValue<Value>(value: Value): value is Value & string {
  return v.is(safeBindingValueSchema, value);
}

function safeHostname<Value>(value: Value): value is Value & string {
  if (!v.is(v.pipe(v.string(), v.minLength(3), v.maxLength(253)), value) || value !== value.toLowerCase() ||
      value.includes(':') || /^(?:\d+\.)+\d+$/u.test(value)) return false;
  const labels = value.split('.');
  return labels.length >= 2 && labels.every((label) => DNS_LABEL_PATTERN.test(label));
}

function safeIsoDate<Value>(value: Value): value is Value & string {
  return v.is(v.pipe(
    v.string(),
    v.minLength(20),
    v.maxLength(40),
    v.check((date) => Number.isFinite(Date.parse(date))),
  ), value);
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.byteLength; offset += chunkSize) {
    const chunk = bytes.subarray(offset, Math.min(offset + chunkSize, bytes.byteLength));
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function strictBase64Bytes<Value>(value: Value, expectedByteLength: number): Uint8Array | null {
  const candidate = v.safeParse(v.pipe(
    v.string(),
    v.length(4 * Math.ceil(expectedByteLength / 3)),
    v.regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u),
  ), value);
  if (!candidate.success) return null;
  let binary: string;
  try {
    binary = atob(candidate.output);
  } catch {
    return null;
  }
  if (binary.length !== expectedByteLength) return null;
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return bytesToBase64(bytes) === candidate.output ? bytes : null;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(value: Uint8Array | string): Promise<string> {
  const bytes = v.is(v.string(), value) ? new TextEncoder().encode(value) : value;
  const digestInput = new Uint8Array(bytes).buffer;
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', digestInput)));
}

async function prepareInput(
  input: PrepareVerifiedWorkerReleaseInput,
  progress: MutableProgress,
): Promise<PreparedVerifiedWorkerRelease> {
  const candidate = v.safeParse(prepareReleaseInputSchema, input);
  if (!candidate.success) fail('invalid_input', 'validate', 'not_sent', progress);
  const parsedInput = candidate.output;

  for (const name of EXACT_PLAIN_TEXT_BINDINGS) {
    if (!safeBindingValue(parsedInput.plainTextBindings[name])) {
      fail('invalid_input', 'validate', 'not_sent', progress);
    }
  }
  if (
    parsedInput.plainTextBindings.ANKKA_GATEWAY_RELEASE !== parsedInput.release.release ||
    parsedInput.plainTextBindings.ANKKA_GATEWAY_RELEASE_SHA256 !== `sha256:${parsedInput.release.artifactSha256}` ||
    parsedInput.plainTextBindings.ANKKA_WORKER_NAME !== parsedInput.workerName ||
    !WORKER_NAME_PATTERN.test(parsedInput.plainTextBindings.ANKKA_WORKER_NAME) ||
    !DNS_LABEL_PATTERN.test(parsedInput.plainTextBindings.ANKKA_WORKERS_SUBDOMAIN) ||
    !safeHostname(parsedInput.plainTextBindings.ANKKA_MANAGEMENT_HOSTNAME) ||
    parsedInput.plainTextBindings.CLOUDFLARE_ACCOUNT_ID !== parsedInput.accountId ||
    !ACCOUNT_ID_PATTERN.test(parsedInput.plainTextBindings.CLOUDFLARE_ZONE_ID) ||
    parsedInput.plainTextBindings.ZERO_TRUST_READY !== 'true'
  ) fail('invalid_input', 'validate', 'not_sent', progress);

  const modules: PreparedModule[] = [];
  const moduleNames = new Set<string>();
  let totalBytes = 0;
  for (const module of parsedInput.release.worker.modules) {
    if (
      !safeModuleName(module.name) ||
      moduleNames.has(module.name) ||
      module.contentType !== MODULE_CONTENT_TYPES[extension(module.name)] ||
      module.bytes.byteLength === 0 ||
      module.bytes.byteLength > MAX_FILE_BYTES
    ) fail('invalid_input', 'validate', 'not_sent', progress);
    const bytes = new Uint8Array(module.bytes);
    if (await sha256(bytes) !== module.sha256) {
      fail('invalid_input', 'validate', 'not_sent', progress);
    }
    moduleNames.add(module.name);
    totalBytes += bytes.byteLength;
    modules.push(Object.freeze({ name: module.name, contentType: module.contentType, bytes }));
  }
  if (!moduleNames.has('index.js')) fail('invalid_input', 'validate', 'not_sent', progress);

  const assets: PreparedAsset[] = [];
  const assetPaths = new Set<string>();
  const hashContentTypes = new Map<string, string>();
  for (const asset of parsedInput.release.worker.assets.files) {
    if (
      !safeAssetPath(asset.path) ||
      assetPaths.has(asset.path) ||
      asset.contentType !== ASSET_CONTENT_TYPES[extension(asset.path)] ||
      asset.bytes.byteLength === 0 ||
      asset.bytes.byteLength > MAX_FILE_BYTES
    ) fail('invalid_input', 'validate', 'not_sent', progress);
    const bytes = new Uint8Array(asset.bytes);
    if (await sha256(bytes) !== asset.sha256) {
      fail('invalid_input', 'validate', 'not_sent', progress);
    }
    const uploadHash = (await sha256(`${bytesToBase64(bytes)}${extension(asset.path).slice(1)}`)).slice(0, 32);
    const priorContentType = hashContentTypes.get(uploadHash);
    if (priorContentType !== undefined && priorContentType !== asset.contentType) {
      fail('invalid_input', 'validate', 'not_sent', progress);
    }
    hashContentTypes.set(uploadHash, asset.contentType);
    assetPaths.add(asset.path);
    totalBytes += bytes.byteLength;
    assets.push(Object.freeze({
      path: asset.path,
      contentType: asset.contentType,
      bytes,
      uploadHash,
    }));
  }
  if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_RELEASE_BYTES) {
    fail('invalid_input', 'validate', 'not_sent', progress);
  }

  modules.sort((left, right) => lexicalCompare(left.name, right.name));
  assets.sort((left, right) => lexicalCompare(left.path, right.path));
  return {
    accountId: parsedInput.accountId,
    workerName: parsedInput.workerName,
    release: parsedInput.release.release,
    modules: Object.freeze(modules),
    assets: Object.freeze(assets),
    plainTextBindings: Object.freeze({ ...parsedInput.plainTextBindings }),
    bootstrapNonce: parsedInput.bootstrapNonce,
  };
}

export async function prepareVerifiedWorkerRelease(
  input: PrepareVerifiedWorkerReleaseInput,
): Promise<PreparedVerifiedWorkerRelease> {
  return await prepareInput(input, initialProgress());
}

function prepareCall(call: CloudflareDirectUploadCall, progress: MutableProgress): PreparedCall {
  const candidate = v.safeParse(directUploadCallSchema, call);
  if (!candidate.success) fail('invalid_input', 'validate', 'not_sent', progress);
  return {
    accessToken: candidate.output.accessToken,
    transport: candidate.output.transport,
    timeoutMs: candidate.output.timeoutMs ?? DEFAULT_TIMEOUT_MS,
  };
}

async function readBoundedJson(response: Response, maxBytes = MAX_RESPONSE_BYTES): Promise<BoundaryValue> {
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null) {
    const declared = Number(declaredLength);
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > maxBytes) {
      throw new TypeError('response');
    }
  }
  const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
  if (!contentType.startsWith('application/json')) throw new TypeError('response');
  if (!response.body) throw new TypeError('response');

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
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
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new TypeError('response');
  }
  try {
    return v.parse(boundaryValueSchema, JSON.parse(text));
  } catch {
    throw new TypeError('response');
  }
}

async function performRequest(
  call: PreparedCall,
  progress: MutableProgress,
  stage: CloudflareDirectUploadStage,
  url: string,
  init: RequestInit,
  maxResponseBytes = MAX_RESPONSE_BYTES,
): Promise<{ readonly status: number; readonly value: BoundaryValue }> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const request = new Request(url, {
      ...init,
      // workerd rejects `redirect: 'error'` at construction; redirects are
      // rejected explicitly by status instead.
      redirect: 'manual',
      signal: controller.signal,
    });
    const operation = (async () => {
      const response = await call.transport(request);
      if (response.redirected || response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
        throw new TypeError('redirect');
      }
      const value = await readBoundedJson(response, maxResponseBytes);
      return { status: response.status, value };
    })();
    const deadline = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new TypeError('timeout'));
      }, call.timeoutMs);
    });
    return await Promise.race([operation, deadline]);
  } catch (error) {
    if (error instanceof CloudflareDirectUploadError) throw error;
    return fail('provider_unknown', stage, 'unknown', progress);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    controller.abort();
  }
}

function authHeaders(accessToken: string): Headers {
  return new Headers({
    accept: 'application/json',
    authorization: `Bearer ${accessToken}`,
  });
}

function jsonHeaders(accessToken: string): Headers {
  const headers = authHeaders(accessToken);
  headers.set('content-type', 'application/json');
  return headers;
}

function rejectForStatus(
  status: number,
  value: BoundaryValue,
  stage: CloudflareDirectUploadStage,
  progress: MutableProgress,
): never {
  const envelope = parseEnvelope(value);
  const explicitFailure = envelope &&
    envelope.success === false &&
    validProviderErrorList(envelope.errors) &&
    isEmptyProviderList(envelope.messages) &&
    envelope.result === null;
  if (status >= 400 && status < 500 && explicitFailure) {
    fail('provider_rejected', stage, 'rejected', progress);
  }
  fail('provider_unknown', stage, 'unknown', progress);
}

function requireSuccess(
  response: { readonly status: number; readonly value: BoundaryValue },
  expectedStatuses: readonly number[],
  stage: CloudflareDirectUploadStage,
  progress: MutableProgress,
): BoundaryValue {
  if (!expectedStatuses.includes(response.status)) {
    rejectForStatus(response.status, response.value, stage, progress);
  }
  const result = parseSuccessEnvelope(response.value);
  if (result === null) fail('provider_unknown', stage, 'unknown', progress);
  return result;
}

function disabledObservability<Value>(value: Value): boolean {
  return v.is(disabledObservabilitySchema, value);
}

function emptyReferences(value: BoundaryValue): boolean {
  return v.is(emptyWorkerReferencesSchema, value);
}

/**
 * Terminal expectation for a Worker that has been deployed and had the
 * management custom domain attached. A converged Worker legitimately reports
 * `deployed_on` and exactly one domain and Durable Object reference, so the
 * fresh-state proof cannot be reused verbatim (live 2026-08-23).
 */
export interface ConvergedWorkerExpectation {
  readonly domain: {
    readonly id: string;
    readonly hostname: string;
    readonly zoneId: string;
    readonly zoneName: string;
  };
  readonly namespaceId: string;
}

function exactConvergedReferences(
  value: BoundaryValue,
  expectedName: string,
  converged: ConvergedWorkerExpectation,
): boolean {
  const candidate = v.safeParse(convergedWorkerReferencesSchema, value);
  if (!candidate.success) return false;
  const domain = candidate.output.domains.at(0);
  if (domain === undefined) return false;
  if (
    domain.id !== converged.domain.id || domain.hostname !== converged.domain.hostname ||
    domain.zone_id !== converged.domain.zoneId || domain.zone_name !== converged.domain.zoneName
  ) return false;
  const namespace = candidate.output.durable_objects.at(0);
  if (namespace === undefined) return false;
  return namespace.namespace_id === converged.namespaceId &&
    namespace.worker_name === expectedName &&
    namespace.namespace_name === `${expectedName}_AdminState`;
}

function exactWorkerState(
  value: BoundaryValue,
  expectedName: string,
  expectedTags: readonly string[],
  expectedId?: string,
  converged?: ConvergedWorkerExpectation,
): value is BoundaryObject & { readonly id: string } {
  const candidate = v.safeParse(workerStateSchema, value);
  if (!candidate.success) return false;
  const observation = candidate.output;
  if (
    (expectedId !== undefined && observation.id !== expectedId) ||
    observation.name !== expectedName ||
    !disabledObservability(observation.observability) ||
    observation.tags.length !== expectedTags.length ||
    !observation.tags.every((tag, index) => tag === expectedTags[index]) ||
    !safeIsoDate(observation.created_on) ||
    !safeIsoDate(observation.updated_on) ||
    (converged
      ? !safeIsoDate(observation.deployed_on) ||
        !exactConvergedReferences(observation.references, expectedName, converged)
      : !(observation.deployed_on === undefined || observation.deployed_on === null) ||
        !emptyReferences(observation.references))
  ) return false;
  return true;
}

function canonicalEqual<Left, Right>(left: Left, right: Right): boolean {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

export interface WorkerMutationIntent {
  readonly kind: 'worker';
  readonly accountId: string;
  readonly workerName: string;
  readonly requestHash: string;
  readonly correlationTag: string;
  readonly body: {
    readonly logpush: false;
    readonly name: string;
    readonly observability: { readonly enabled: false };
    readonly subdomain: { readonly enabled: false; readonly previews_enabled: false };
    readonly tags: readonly string[];
    readonly tail_consumers: readonly [];
  };
}

export interface PrepareWorkerMutationForTargetInput {
  readonly accountId: string;
  readonly workerName: string;
}

export type WorkerSubmission = Extract<CloudflareDirectUploadSubmission, { readonly kind: 'worker' }>;

function workerCoreBody(workerName: string) {
  return {
    logpush: false as const,
    name: workerName,
    observability: { enabled: false as const },
    subdomain: { enabled: false as const, previews_enabled: false as const },
    tags: [MANAGED_WORKER_TAG],
    tail_consumers: [] as const,
  };
}

/**
 * Prepare the deterministic Worker container before release bindings exist.
 * Access application state (including CF_ACCESS_AUD) is intentionally absent.
 */
export async function prepareWorkerMutationForTarget<Input>(
  input: Input,
): Promise<WorkerMutationIntent> {
  const progress = initialProgress();
  const candidate = v.safeParse(workerTargetInputSchema, input);
  if (!candidate.success) fail('invalid_input', 'validate', 'not_sent', progress);
  const { accountId, workerName } = candidate.output;
  const core = workerCoreBody(workerName);
  const requestHash = await sha256(canonicalJson(core));
  const correlationTag = `ankka-worker-sha256:${requestHash}`;
  return Object.freeze({
    kind: 'worker',
    accountId,
    workerName,
    requestHash,
    correlationTag,
    body: Object.freeze({ ...core, tags: Object.freeze([MANAGED_WORKER_TAG, correlationTag]) }),
  });
}

export async function prepareWorkerMutation(
  prepared: PreparedVerifiedWorkerRelease,
): Promise<WorkerMutationIntent> {
  const progress = initialProgress();
  if (!isRecord(prepared)) fail('invalid_input', 'validate', 'not_sent', progress);
  return prepareWorkerMutationForTarget({
    accountId: prepared.accountId,
    workerName: prepared.workerName,
  });
}

async function validWorkerIntent(intent: WorkerMutationIntent): Promise<boolean> {
  const candidate = v.safeParse(workerIntentSchema, intent);
  if (!candidate.success ||
    candidate.output.correlationTag !== `ankka-worker-sha256:${candidate.output.requestHash}` ||
    !canonicalEqual(candidate.output.body, {
      ...workerCoreBody(candidate.output.workerName),
      tags: [MANAGED_WORKER_TAG, candidate.output.correlationTag],
    })
  ) return false;
  return await sha256(canonicalJson(workerCoreBody(candidate.output.workerName))) === candidate.output.requestHash;
}

function rawResultId(value: BoundaryValue, pattern: RegExp): string | null {
  const envelope = parseEnvelope(value);
  if (!envelope) return null;
  const result = v.safeParse(v.looseObject({ id: v.pipe(v.string(), v.regex(pattern)) }), envelope.result);
  return result.success ? result.output.id : null;
}

function workerSubmission(intent: WorkerMutationIntent, workerId: string): WorkerSubmission {
  return Object.freeze({
    kind: 'worker',
    accountId: intent.accountId,
    workerName: intent.workerName,
    workerId,
  });
}

export async function inspectWorkerRecovery(
  intent: WorkerMutationIntent,
  callInput: CloudflareDirectUploadCall,
): Promise<WorkerSubmission | null> {
  const progress = initialProgress();
  if (!await validWorkerIntent(intent)) fail('invalid_input', 'validate', 'not_sent', progress);
  const call = prepareCall(callInput, progress);
  const response = await performRequest(
    call,
    progress,
    'worker_recovery',
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/workers/${encodeURIComponent(intent.workerName)}`,
    { method: 'GET', headers: authHeaders(call.accessToken) },
  );
  if (response.status === 404 && parseAbsentEnvelope(response.value)) return null;
  const result = requireSuccess(response, [200], 'worker_recovery', progress);
  if (!exactWorkerState(result, intent.workerName, intent.body.tags)) {
    fail('worker_name_collision', 'worker_recovery', 'rejected', progress);
  }
  return workerSubmission(intent, String(result.id));
}

export async function submitWorkerMutation(
  intent: WorkerMutationIntent,
  callInput: CloudflareDirectUploadCall,
): Promise<WorkerSubmission> {
  const progress = initialProgress();
  if (!await validWorkerIntent(intent)) fail('invalid_input', 'validate', 'not_sent', progress);
  const call = prepareCall(callInput, progress);
  const response = await performRequest(
    call,
    progress,
    'worker_create',
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/workers`,
    {
      method: 'POST',
      headers: jsonHeaders(call.accessToken),
      body: JSON.stringify(intent.body),
    },
  );
  const workerId = rawResultId(response.value, WORKER_ID_PATTERN);
  if (![200, 201].includes(response.status)) {
    if (response.status >= 200 && response.status < 300 && workerId !== null) {
      fail(
        'provider_mismatch',
        'worker_create',
        'submitted',
        progress,
        [workerSubmission(intent, workerId)],
      );
    }
    rejectForStatus(response.status, response.value, 'worker_create', progress);
  }
  if (workerId === null) {
    requireSuccess(response, [200, 201], 'worker_create', progress);
    fail('provider_mismatch', 'worker_create', 'unknown', progress);
  }
  const submission = workerSubmission(intent, workerId);
  const result = parseSuccessEnvelope(response.value);
  if (result === null || !isRecord(result) || result.id !== workerId) {
    fail('provider_mismatch', 'worker_create', 'submitted', progress, [submission]);
  }
  return submission;
}

export async function verifyWorkerSubmission(
  intent: WorkerMutationIntent,
  submission: WorkerSubmission,
  callInput: CloudflareDirectUploadCall,
  converged?: ConvergedWorkerExpectation,
): Promise<WorkerSubmission> {
  const progress = initialProgress();
  progress.workerCreated = true;
  if (
    !await validWorkerIntent(intent) ||
    submission.kind !== 'worker' ||
    submission.accountId !== intent.accountId ||
    submission.workerName !== intent.workerName ||
    !WORKER_ID_PATTERN.test(submission.workerId)
  ) fail('invalid_input', 'validate', 'not_sent', progress, [submission]);
  const call = prepareCall(callInput, progress);
  try {
    const response = await performRequest(
      call,
      progress,
      'worker_verify',
      `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/workers/${submission.workerId}`,
      { method: 'GET', headers: authHeaders(call.accessToken) },
    );
    const result = requireSuccess(response, [200], 'worker_verify', progress);
    if (!exactWorkerState(result, intent.workerName, intent.body.tags, submission.workerId, converged)) {
      fail('provider_mismatch', 'worker_verify', 'submitted', progress, [submission]);
    }
    progress.workerVerified = true;
    return submission;
  } catch (error) {
    rethrowWithSubmissions(error, [submission], 'submitted');
  }
}

interface DurableObjectNamespaceItem {
  readonly id: string;
  readonly className: string;
  readonly name: string;
  readonly script: string;
  readonly useSqlite: boolean;
}

interface DurableObjectNamespacePage {
  readonly items: readonly DurableObjectNamespaceItem[];
  readonly page: number;
  readonly perPage: number;
  readonly count: number;
  readonly totalCount: number;
  readonly totalPages: number | null;
}

function parseDurableObjectNamespacePage(value: BoundaryValue): DurableObjectNamespacePage | null {
  const candidate = v.safeParse(durableObjectNamespacePageSchema, value);
  if (!candidate.success || !isEmptyProviderList(candidate.output.errors) ||
    !isEmptyProviderList(candidate.output.messages) ||
    candidate.output.result_info.count !== candidate.output.result.length) return null;
  const info = candidate.output.result_info;
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
  return Object.freeze({
    items: Object.freeze(items),
    page: info.page,
    perPage: NAMESPACE_PAGE_SIZE,
    count: info.count,
    totalCount: info.total_count,
    totalPages: info.total_pages ?? null,
  });
}

/**
 * Fully paginate the account namespace catalogue and prove that exactly one
 * sqlite namespace belongs to this Worker/AdminState pair. The version binding
 * may omit namespace_id, so it is not accepted as the sole ownership proof.
 */
export async function inspectAdminStateDurableObjectNamespace(
  input: InspectAdminStateDurableObjectNamespaceInput,
  callInput: CloudflareDirectUploadCall,
): Promise<AdminStateDurableObjectNamespaceLocator> {
  const progress = initialProgress();
  const candidate = v.safeParse(inspectNamespaceInputSchema, input);
  if (!candidate.success) fail('invalid_input', 'validate', 'not_sent', progress);
  const parsedInput = candidate.output;
  const call = prepareCall(callInput, progress);
  const seenIds = new Set<string>();
  const identityMatches: DurableObjectNamespaceItem[] = [];
  let expectedTotalCount: number | null = null;
  let expectedTotalPages: number | null = null;
  let observedCount = 0;

  for (let page = 1; page <= MAX_NAMESPACE_PAGES; page += 1) {
    const response = await performRequest(
      call,
      progress,
      'namespace_verify',
      `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${parsedInput.accountId}/workers/durable_objects/namespaces?page=${page}&per_page=${NAMESPACE_PAGE_SIZE}`,
      { method: 'GET', headers: authHeaders(call.accessToken) },
      MAX_NAMESPACE_RESPONSE_BYTES,
    );
    if (response.status !== 200) rejectForStatus(response.status, response.value, 'namespace_verify', progress);
    const parsed = parseDurableObjectNamespacePage(response.value);
    if (!parsed || parsed.page !== page) fail('provider_mismatch', 'namespace_verify', 'unknown', progress);
    if (page === 1) {
      expectedTotalCount = parsed.totalCount;
      const calculatedPages = parsed.totalCount === 0 ? 0 : Math.ceil(parsed.totalCount / NAMESPACE_PAGE_SIZE);
      // Live (2026-08-23): the namespace list omits total_pages, so the page
      // count is derived from the exact total_count instead.
      expectedTotalPages = parsed.totalPages ?? calculatedPages;
      if (
        parsed.totalPages !== null &&
        !(
          (parsed.totalCount === 0 && (parsed.totalPages === 0 || parsed.totalPages === 1)) ||
          (parsed.totalCount > 0 && parsed.totalPages === calculatedPages)
        )
      ) fail('provider_mismatch', 'namespace_verify', 'unknown', progress);
    } else if (
      parsed.totalCount !== expectedTotalCount ||
      (parsed.totalPages !== null && parsed.totalPages !== expectedTotalPages)
    ) fail('provider_mismatch', 'namespace_verify', 'unknown', progress);

    if (expectedTotalCount === null) fail('provider_mismatch', 'namespace_verify', 'unknown', progress);
    const remaining = expectedTotalCount - observedCount;
    const expectedPageCount = Math.max(0, Math.min(NAMESPACE_PAGE_SIZE, remaining));
    if (parsed.count !== expectedPageCount) fail('provider_mismatch', 'namespace_verify', 'unknown', progress);
    for (const item of parsed.items) {
      if (seenIds.has(item.id)) fail('recovery_ambiguous', 'namespace_verify', 'unknown', progress);
      seenIds.add(item.id);
      if (item.script === parsedInput.workerName && item.className === parsedInput.className) identityMatches.push(item);
    }
    observedCount += parsed.count;
    if (expectedTotalPages === null) fail('provider_mismatch', 'namespace_verify', 'unknown', progress);
    const lastPage = expectedTotalPages === 0 ? 1 : expectedTotalPages;
    if (page === lastPage) break;
    if (page >= expectedTotalPages) fail('provider_mismatch', 'namespace_verify', 'unknown', progress);
  }

  if (expectedTotalCount === null || observedCount !== expectedTotalCount) {
    fail('provider_mismatch', 'namespace_verify', 'unknown', progress);
  }
  if (identityMatches.length === 0) fail('provider_mismatch', 'namespace_verify', 'unknown', progress);
  if (identityMatches.length > 1) fail('recovery_ambiguous', 'namespace_verify', 'unknown', progress);
  const match = identityMatches.at(0);
  if (match === undefined) fail('provider_mismatch', 'namespace_verify', 'unknown', progress);
  if (!match.useSqlite ||
    (parsedInput.expectedNamespaceId !== undefined && match.id !== parsedInput.expectedNamespaceId)) {
    fail('provider_mismatch', 'namespace_verify', 'unknown', progress);
  }
  return Object.freeze({
    accountId: parsedInput.accountId,
    namespaceId: match.id,
    namespaceName: match.name,
    workerName: parsedInput.workerName,
    className: 'AdminState',
    storage: 'sqlite',
  });
}

function parseAssetSession(
  value: BoundaryValue,
  knownHashes: ReadonlySet<string>,
): { readonly jwt: string; readonly buckets: readonly (readonly string[])[] } | null {
  const candidate = v.safeParse(assetSessionResponseSchema, value);
  if (!candidate.success) return null;
  const seen = new Set<string>();
  const buckets: string[][] = [];
  for (const bucket of candidate.output.buckets) {
    const parsed: string[] = [];
    for (const hash of bucket) {
      if (!knownHashes.has(hash) || seen.has(hash)) {
        return null;
      }
      seen.add(hash);
      parsed.push(hash);
    }
    buckets.push(parsed);
  }
  return { jwt: candidate.output.jwt, buckets };
}

export interface AssetUploadSessionMutationIntent {
  readonly kind: 'asset_session';
  readonly accountId: string;
  readonly workerName: string;
  readonly requestHash: string;
  readonly body: {
    readonly manifest: Readonly<Record<string, { readonly hash: string; readonly size: number }>>;
  };
}

export interface AssetUploadSessionSubmission {
  readonly kind: 'asset_session';
  readonly accountId: string;
  readonly workerName: string;
  readonly requestHash: string;
  /** Provider-scoped upload credential. Keep in memory only; NEVER journal this submission. */
  readonly uploadJwt: string;
  readonly buckets: readonly (readonly string[])[];
}

export interface AssetBucketMutationIntent {
  readonly kind: 'asset_bucket';
  readonly accountId: string;
  readonly workerName: string;
  readonly sessionRequestHash: string;
  readonly bucketIndex: number;
  readonly bucketCount: number;
  readonly hashes: readonly string[];
  readonly isFinal: boolean;
  readonly requestHash: string;
}

export type AssetBucketSubmission =
  | {
      readonly kind: 'asset_bucket';
      readonly requestHash: string;
      readonly bucketIndex: number;
      readonly isFinal: false;
    }
  | {
      readonly kind: 'asset_bucket';
      readonly requestHash: string;
      readonly bucketIndex: number;
      readonly isFinal: true;
      /** Provider-scoped credential. Keep in memory only; NEVER journal this submission. */
      readonly completionJwt: string;
    };

interface PreparedAssetManifest {
  readonly manifest: Record<string, { readonly hash: string; readonly size: number }>;
  readonly assetsByHash: Map<string, PreparedAsset>;
}

function assetManifest(prepared: PreparedVerifiedWorkerRelease): PreparedAssetManifest {
  const manifest: Record<string, { readonly hash: string; readonly size: number }> = {};
  const assetsByHash = new Map<string, PreparedAsset>();
  for (const asset of prepared.assets) {
    manifest[asset.path] = { hash: asset.uploadHash, size: asset.bytes.byteLength };
    if (!assetsByHash.has(asset.uploadHash)) assetsByHash.set(asset.uploadHash, asset);
  }
  return { manifest, assetsByHash };
}

export async function prepareAssetUploadSessionMutation(
  prepared: PreparedVerifiedWorkerRelease,
): Promise<AssetUploadSessionMutationIntent> {
  const { manifest } = assetManifest(prepared);
  const body = Object.freeze({ manifest: Object.freeze(manifest) });
  const requestHash = await sha256(canonicalJson(body));
  return Object.freeze({
    kind: 'asset_session',
    accountId: prepared.accountId,
    workerName: prepared.workerName,
    requestHash,
    body,
  });
}

async function validAssetSessionIntent(intent: AssetUploadSessionMutationIntent): Promise<boolean> {
  const candidate = v.safeParse(assetSessionIntentSchema, intent);
  if (!candidate.success) return false;
  for (const path of Object.keys(candidate.output.body.manifest)) {
    if (!safeAssetPath(path)) return false;
  }
  try {
    return await sha256(canonicalJson(candidate.output.body)) === candidate.output.requestHash;
  } catch {
    return false;
  }
}

export async function submitAssetUploadSessionMutation(
  intent: AssetUploadSessionMutationIntent,
  callInput: CloudflareDirectUploadCall,
): Promise<AssetUploadSessionSubmission> {
  const progress = initialProgress();
  if (!await validAssetSessionIntent(intent)) fail('invalid_input', 'validate', 'not_sent', progress);
  const call = prepareCall(callInput, progress);
  const response = await performRequest(
    call,
    progress,
    'asset_session',
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/scripts/${encodeURIComponent(intent.workerName)}/assets-upload-session`,
    {
      method: 'POST',
      headers: jsonHeaders(call.accessToken),
      body: JSON.stringify(intent.body),
    },
  );
  const result = requireSuccess(response, [200, 201], 'asset_session', progress);
  const hashes = new Set(Object.values(intent.body.manifest).map((entry) => entry.hash));
  const parsed = parseAssetSession(result, hashes);
  if (!parsed) fail('provider_mismatch', 'asset_session', 'unknown', progress);
  return Object.freeze({
    kind: 'asset_session',
    accountId: intent.accountId,
    workerName: intent.workerName,
    requestHash: intent.requestHash,
    uploadJwt: parsed.jwt,
    buckets: Object.freeze(parsed.buckets.map((bucket) => Object.freeze([...bucket]))),
  });
}

function assetBucketCore(
  session: AssetUploadSessionSubmission,
  bucketIndex: number,
): Omit<AssetBucketMutationIntent, 'kind' | 'requestHash'> | null {
  const hashes = session.buckets.at(bucketIndex);
  if (hashes === undefined) return null;
  return {
    accountId: session.accountId,
    workerName: session.workerName,
    sessionRequestHash: session.requestHash,
    bucketIndex,
    bucketCount: session.buckets.length,
    hashes: [...hashes],
    isFinal: bucketIndex === session.buckets.length - 1,
  };
}

function validAssetSessionSubmission(session: AssetUploadSessionSubmission): boolean {
  const candidate = v.safeParse(assetSessionSubmissionSchema, session);
  if (!candidate.success) return false;
  const seen = new Set<string>();
  for (const bucket of candidate.output.buckets) {
    for (const hash of bucket) {
      if (seen.has(hash)) return false;
      seen.add(hash);
    }
  }
  return true;
}

export async function prepareAssetBucketMutation(
  session: AssetUploadSessionSubmission,
  bucketIndex: number,
): Promise<AssetBucketMutationIntent> {
  const progress = initialProgress();
  if (
    !validAssetSessionSubmission(session) ||
    !Number.isSafeInteger(bucketIndex) ||
    bucketIndex < 0 ||
    bucketIndex >= session.buckets.length
  ) fail('invalid_input', 'validate', 'not_sent', progress);
  const core = assetBucketCore(session, bucketIndex);
  if (core === null) fail('invalid_input', 'validate', 'not_sent', progress);
  if (
    core.hashes.length === 0 ||
    core.hashes.some((hash) => !ASSET_HASH_PATTERN.test(hash)) ||
    new Set(core.hashes).size !== core.hashes.length
  ) fail('invalid_input', 'validate', 'not_sent', progress);
  const requestHash = await sha256(canonicalJson(core));
  return Object.freeze({
    kind: 'asset_bucket',
    ...core,
    hashes: Object.freeze([...core.hashes]),
    requestHash,
  });
}

async function validAssetBucketIntent(
  intent: AssetBucketMutationIntent,
  session: AssetUploadSessionSubmission,
): Promise<boolean> {
  const candidate = v.safeParse(assetBucketIntentSchema, intent);
  if (!candidate.success ||
    candidate.output.accountId !== session.accountId ||
    candidate.output.workerName !== session.workerName ||
    candidate.output.sessionRequestHash !== session.requestHash ||
    candidate.output.bucketIndex >= session.buckets.length ||
    candidate.output.bucketCount !== session.buckets.length ||
    candidate.output.isFinal !== (candidate.output.bucketIndex === session.buckets.length - 1) ||
    !canonicalEqual(candidate.output.hashes, session.buckets.at(candidate.output.bucketIndex))
  ) return false;
  try {
    const core = assetBucketCore(session, candidate.output.bucketIndex);
    return core !== null && await sha256(canonicalJson(core)) ===
      candidate.output.requestHash;
  } catch {
    return false;
  }
}

export async function submitAssetBucketMutation(
  intent: AssetBucketMutationIntent,
  session: AssetUploadSessionSubmission,
  prepared: PreparedVerifiedWorkerRelease,
  callInput: CloudflareDirectUploadCall,
): Promise<AssetBucketSubmission> {
  const progress = initialProgress();
  progress.assetSessionCreated = true;
  progress.assetBucketCount = intent.bucketCount;
  const expectedSessionIntent = await prepareAssetUploadSessionMutation(prepared);
  if (
    !await validAssetBucketIntent(intent, session) ||
    !validAssetSessionSubmission(session) ||
    prepared.accountId !== intent.accountId ||
    prepared.workerName !== intent.workerName ||
    session.requestHash !== expectedSessionIntent.requestHash ||
    !safeToken(session.uploadJwt)
  ) fail('invalid_input', 'validate', 'not_sent', progress);
  const { assetsByHash } = assetManifest(prepared);
  const form = new FormData();
  for (const hash of intent.hashes) {
    const asset = assetsByHash.get(hash);
    if (!asset) fail('invalid_input', 'validate', 'not_sent', progress);
    form.append(hash, new Blob([bytesToBase64(asset.bytes)], { type: asset.contentType }), hash);
  }
  const call = prepareCall(callInput, progress);
  const response = await performRequest(
    call,
    progress,
    'asset_bucket',
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/assets/upload?base64=true`,
    {
      method: 'POST',
      headers: new Headers({ accept: 'application/json', authorization: `Bearer ${session.uploadJwt}` }),
      body: form,
    },
  );
  if (intent.isFinal) {
    const result = requireSuccess(response, [201], 'asset_bucket', progress);
    if (!isRecord(result) || !exactKeys(result, ['jwt']) || !safeToken(result.jwt)) {
      fail('provider_mismatch', 'asset_bucket', 'unknown', progress);
    }
    return Object.freeze({
      kind: 'asset_bucket',
      requestHash: intent.requestHash,
      bucketIndex: intent.bucketIndex,
      isFinal: true,
      completionJwt: result.jwt,
    });
  }
  if (response.status !== 202) rejectForStatus(response.status, response.value, 'asset_bucket', progress);
  const envelope = parseEnvelope(response.value);
  if (
    !envelope ||
    envelope.success !== true ||
    !isEmptyProviderList(envelope.errors) ||
    !isEmptyProviderList(envelope.messages) ||
    !(envelope.result === null || (isRecord(envelope.result) && exactKeys(envelope.result, [])))
  ) fail('provider_mismatch', 'asset_bucket', 'unknown', progress);
  return Object.freeze({
    kind: 'asset_bucket',
    requestHash: intent.requestHash,
    bucketIndex: intent.bucketIndex,
    isFinal: false,
  });
}

async function uploadAssets(
  prepared: PreparedVerifiedWorkerRelease,
  call: PreparedCall,
  progress: MutableProgress,
): Promise<string> {
  const manifest: Record<string, { readonly hash: string; readonly size: number }> = {};
  const assetsByHash = new Map<string, PreparedAsset>();
  for (const asset of prepared.assets) {
    manifest[asset.path] = { hash: asset.uploadHash, size: asset.bytes.byteLength };
    if (!assetsByHash.has(asset.uploadHash)) assetsByHash.set(asset.uploadHash, asset);
  }
  const sessionResponse = await performRequest(
    call,
    progress,
    'asset_session',
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${prepared.accountId}/workers/scripts/${encodeURIComponent(prepared.workerName)}/assets-upload-session`,
    {
      method: 'POST',
      headers: jsonHeaders(call.accessToken),
      body: JSON.stringify({ manifest }),
    },
  );
  const sessionResult = requireSuccess(sessionResponse, [200, 201], 'asset_session', progress);
  const session = parseAssetSession(sessionResult, new Set(assetsByHash.keys()));
  if (!session) fail('provider_mismatch', 'asset_session', 'unknown', progress);
  progress.assetSessionCreated = true;
  progress.assetBucketCount = session.buckets.length;
  if (session.buckets.length === 0) return session.jwt;

  let completionJwt: string | null = null;
  for (let index = 0; index < session.buckets.length; index += 1) {
    const bucket = session.buckets.at(index);
    if (bucket === undefined) fail('provider_mismatch', 'asset_bucket', 'unknown', progress);
    const form = new FormData();
    for (const hash of bucket) {
      const asset = assetsByHash.get(hash);
      if (!asset) fail('provider_mismatch', 'asset_bucket', 'unknown', progress);
      form.append(hash, new Blob([bytesToBase64(asset.bytes)], { type: asset.contentType }), hash);
    }
    const headers = new Headers({
      accept: 'application/json',
      authorization: `Bearer ${session.jwt}`,
    });
    const response = await performRequest(
      call,
      progress,
      'asset_bucket',
      `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${prepared.accountId}/workers/assets/upload?base64=true`,
      { method: 'POST', headers, body: form },
    );
    const isFinal = index === session.buckets.length - 1;
    if (isFinal) {
      const result = requireSuccess(response, [201], 'asset_bucket', progress);
      if (!isRecord(result) || !exactKeys(result, ['jwt']) || !safeToken(result.jwt)) {
        fail('provider_mismatch', 'asset_bucket', 'unknown', progress);
      }
      completionJwt = result.jwt;
    } else {
      if (response.status !== 202) {
        rejectForStatus(response.status, response.value, 'asset_bucket', progress);
      }
      const envelope = parseEnvelope(response.value);
      if (
        !envelope ||
        envelope.success !== true ||
        !isEmptyProviderList(envelope.errors) ||
        !isEmptyProviderList(envelope.messages) ||
        !(envelope.result === null || (isRecord(envelope.result) && exactKeys(envelope.result, [])))
      ) {
        fail('provider_mismatch', 'asset_bucket', 'unknown', progress);
      }
    }
    progress.assetBucketsCompleted += 1;
  }
  if (completionJwt === null) fail('provider_mismatch', 'asset_bucket', 'unknown', progress);
  return completionJwt;
}

export type WorkerVersionBinding =
  | { readonly name: 'ADMIN_STATE'; readonly type: 'durable_object_namespace'; readonly class_name: 'AdminState' }
  | { readonly name: 'ASSETS'; readonly type: 'assets' }
  | { readonly name: GatewayWorkerPlainTextBindingName; readonly type: 'plain_text'; readonly text: string }
  | { readonly name: 'ANKKA_BOOTSTRAP_NONCE'; readonly type: 'secret_text'; readonly text: string };

function versionBindings(
  prepared: PreparedVerifiedWorkerRelease,
  phase: WorkerVersionPhase,
): readonly WorkerVersionBinding[] {
  const bindings: WorkerVersionBinding[] = phase === 'provision'
    ? []
    : [
      { name: 'ADMIN_STATE', type: 'durable_object_namespace', class_name: 'AdminState' },
      { name: 'ASSETS', type: 'assets' },
    ];
  for (const name of EXACT_PLAIN_TEXT_BINDINGS) {
    bindings.push({ name, type: 'plain_text', text: prepared.plainTextBindings[name] });
  }
  if (phase === 'bootstrap') {
    bindings.push({ name: 'ANKKA_BOOTSTRAP_NONCE', type: 'secret_text', text: prepared.bootstrapNonce });
  }
  return bindings.sort((left, right) => lexicalCompare(left.name, right.name));
}

export interface WorkerVersionRecoveryRecord {
  readonly kind: 'version_recovery';
  readonly phase: WorkerVersionPhase;
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly requestHash: string;
  readonly correlationTag: string;
  readonly releaseContract: {
    readonly assetBinding: 'ASSETS';
    readonly assetConfig: {
      readonly notFoundHandling: 'single-page-application';
      readonly runWorkerFirst: readonly ['/__ankka/*', '/api/*'];
    };
    /** `phase` determines which value is valid; no credential value is persisted. */
    readonly bootstrapBinding: 'present' | 'absent';
    readonly compatibilityDate: '2026-08-08';
    readonly compatibilityFlags: readonly [];
    readonly durableObject: {
      readonly binding: 'ADMIN_STATE';
      readonly className: 'AdminState';
      readonly storage: 'sqlite';
    };
    readonly exports: {
      readonly AdminState: { readonly type: 'durable-object'; readonly storage: 'sqlite' };
    };
    readonly mainModule: 'index.js';
  };
  readonly assets: readonly {
    readonly path: string;
    readonly uploadHash: string;
    readonly contentType: string;
    readonly byteLength: number;
  }[];
  readonly plainTextBindingHashes: readonly {
    readonly name: GatewayWorkerPlainTextBindingName;
    readonly valueSha256: string;
  }[];
  readonly modules: readonly {
    readonly name: string;
    readonly contentType: string;
    readonly contentSha256: string;
    readonly byteLength: number;
  }[];
}

export interface WorkerVersionSubmitIntent {
  readonly kind: 'version_submit';
  readonly phase: WorkerVersionPhase;
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly requestHash: string;
  readonly correlationTag: string;
  /** Nonsecret exact release semantics used to validate a freshly rebuilt submit body. */
  readonly semanticCommitment: BoundaryObject;
  /** Ephemeral only: contains provider credentials and must NEVER be journaled. */
  readonly body: BoundaryObject;
}

export interface WorkerVersionMutationPlan {
  /** Submit directly, then discard. This value is intentionally not journal-safe. */
  readonly ephemeral: WorkerVersionSubmitIntent;
  /** Persist this record before POST; it is the only restart input for version recovery. */
  readonly recovery: WorkerVersionRecoveryRecord;
}

function exactExports(value: BoundaryValue): boolean {
  return v.is(releaseExportsSchema, value);
}

function exactExportsReconciliation(value: BoundaryValue): boolean {
  const candidate = v.safeParse(exportsReconciliationSchema, value);
  return candidate.success &&
    (candidate.output.created.length === 0 || candidate.output.created[0] === 'AdminState');
}

function exactVersionAnnotations(value: BoundaryValue, correlationTag: string): boolean {
  const candidate = v.safeParse(versionAnnotationsSchema, value);
  return candidate.success && candidate.output['workers/tag'] === correlationTag;
}

async function exactVersionResult(
  value: BoundaryValue,
  recovery: WorkerVersionRecoveryRecord,
  expectedVersionId: string,
  expectedNamespaceId?: string,
  requireModuleContent = false,
): Promise<boolean> {
  const candidate = v.safeParse(versionResultSchema, value);
  if (!candidate.success) return false;
  const result = candidate.output;
  if (
    result.id !== expectedVersionId || !safeIsoDate(result.created_on) ||
    (recovery.phase === 'provision'
      ? result.assets !== undefined
      : result.assets === undefined) ||
    result.bindings.length !== recovery.plainTextBindingHashes.length +
      (recovery.phase === 'bootstrap' ? 3 : recovery.phase === 'clean' ? 2 : 0) ||
    result.modules.length !== recovery.modules.length ||
    !exactVersionAnnotations(result.annotations, recovery.correlationTag) ||
    !exactExports(result.exports) ||
    // Declarative exports are reconciled by the deployment, so the field is
    // absent on a version that has not been deployed yet.
    !(result.exports_reconciliation === undefined || exactExportsReconciliation(result.exports_reconciliation))
  ) return false;
  const returnedBindings = new Map<string, v.InferOutput<typeof returnedVersionBindingSchema>>();
  for (const binding of result.bindings) {
    if (returnedBindings.has(binding.name)) return false;
    returnedBindings.set(binding.name, binding);
  }
  if (recovery.phase === 'provision') {
    if (returnedBindings.has('ADMIN_STATE') || returnedBindings.has('ASSETS')) return false;
  } else {
    const adminBinding = returnedBindings.get('ADMIN_STATE');
    if (
      adminBinding?.name !== 'ADMIN_STATE' ||
      (expectedNamespaceId !== undefined && adminBinding.namespace_id !== undefined &&
        adminBinding.namespace_id !== expectedNamespaceId)
    ) return false;
    const assetsBinding = returnedBindings.get('ASSETS');
    if (assetsBinding?.name !== 'ASSETS') {
      return false;
    }
  }
  const redactedBinding = returnedBindings.get('ANKKA_BOOTSTRAP_NONCE');
  if (recovery.phase === 'bootstrap') {
    if (redactedBinding?.name !== 'ANKKA_BOOTSTRAP_NONCE') return false;
  } else if (redactedBinding !== undefined) return false;
  for (const expected of recovery.plainTextBindingHashes) {
    const binding = returnedBindings.get(expected.name);
    if (
      binding?.name !== expected.name || binding.type !== 'plain_text' ||
      await sha256(binding.text) !== expected.valueSha256
    ) return false;
  }

  const returnedModules = new Map<string, v.InferOutput<typeof returnedVersionModuleSchema>>();
  for (const module of result.modules) {
    if (returnedModules.has(module.name)) return false;
    returnedModules.set(module.name, module);
  }
  for (const module of recovery.modules) {
    const returned = returnedModules.get(module.name);
    if (!returned) return false;
    const keys = Object.keys(returned);
    if (
      !keys.every((key) => ['content_base64', 'content_type', 'name'].includes(key)) ||
      !keys.includes('content_type') ||
      !keys.includes('name') ||
      (requireModuleContent && !keys.includes('content_base64')) ||
      returned.content_type !== module.contentType
    ) return false;
    if (returned.content_base64 !== undefined) {
      const bytes = strictBase64Bytes(returned.content_base64, module.byteLength);
      if (!bytes || await sha256(bytes) !== module.contentSha256) return false;
    }
  }
  return true;
}

export type VersionSubmission = Extract<CloudflareDirectUploadSubmission, { readonly kind: 'version' }>;

function versionCorrelationTag(phase: WorkerVersionPhase, requestHash: string): string {
  return `ankka-version-${phase}-sha256:${requestHash}`;
}

type WorkerVersionSemanticInput = Pick<
  WorkerVersionRecoveryRecord,
  | 'accountId'
  | 'assets'
  | 'modules'
  | 'phase'
  | 'plainTextBindingHashes'
  | 'releaseContract'
  | 'workerId'
  | 'workerName'
>;

function versionSemanticCommitment(input: WorkerVersionSemanticInput) {
  return {
    accountId: input.accountId,
    assets: {
      binding: input.releaseContract.assetBinding,
      config: {
        notFoundHandling: input.releaseContract.assetConfig.notFoundHandling,
        runWorkerFirst: [...input.releaseContract.assetConfig.runWorkerFirst],
      },
      files: input.assets.map((asset) => ({
        path: asset.path,
        uploadHash: asset.uploadHash,
        contentType: asset.contentType,
        byteLength: asset.byteLength,
      })),
    },
    bindings: {
      bootstrap: input.releaseContract.bootstrapBinding,
      durableObject: input.releaseContract.durableObject,
      plainText: input.plainTextBindingHashes.map((binding) => ({ ...binding })),
    },
    compatibilityDate: input.releaseContract.compatibilityDate,
    compatibilityFlags: [...input.releaseContract.compatibilityFlags],
    exports: input.releaseContract.exports,
    mainModule: input.releaseContract.mainModule,
    modules: input.modules.map((module) => ({ ...module })),
    phase: input.phase,
    workerId: input.workerId,
    workerName: input.workerName,
  };
}

async function versionSemanticHash(input: WorkerVersionSemanticInput): Promise<string> {
  return sha256(canonicalJson(versionSemanticCommitment(input)));
}

/**
 * Derive the complete journal-safe version recovery record before creating an
 * asset session. No provider credential, completion JWT, or nonce value is
 * accepted by or included in this helper.
 */
export async function prepareWorkerVersionRecoveryRecord(
  prepared: PreparedVerifiedWorkerRelease,
  worker: WorkerSubmission,
  phase: WorkerVersionPhase,
): Promise<WorkerVersionRecoveryRecord> {
  const progress = initialProgress();
  if (
    !isRecord(prepared) ||
    !isRecord(worker) ||
    !exactKeys(worker, ['accountId', 'kind', 'workerId', 'workerName']) ||
    worker.kind !== 'worker' ||
    worker.accountId !== prepared.accountId ||
    worker.workerName !== prepared.workerName ||
    !ACCOUNT_ID_PATTERN.test(worker.accountId) ||
    !WORKER_NAME_PATTERN.test(worker.workerName) ||
    !WORKER_ID_PATTERN.test(worker.workerId) ||
    (phase !== 'provision' && phase !== 'bootstrap' && phase !== 'clean') ||
    !Array.isArray(prepared.assets) ||
    !Array.isArray(prepared.modules) ||
    !isRecord(prepared.plainTextBindings)
  ) fail('invalid_input', 'validate', 'not_sent', progress);
  const plainTextBindingHashes = await Promise.all(EXACT_PLAIN_TEXT_BINDINGS.map(async (name) => Object.freeze({
    name,
    valueSha256: await sha256(prepared.plainTextBindings[name]),
  })));
  const modules = await Promise.all(prepared.modules.map(async (module) => Object.freeze({
    name: module.name,
    contentType: module.contentType,
    contentSha256: await sha256(module.bytes),
    byteLength: module.bytes.byteLength,
  })));
  const assets = Object.freeze(prepared.assets.map((asset) => Object.freeze({
    path: asset.path,
    uploadHash: asset.uploadHash,
    contentType: asset.contentType,
    byteLength: asset.bytes.byteLength,
  })));
  const compatibilityFlags: readonly [] = Object.freeze([]);
  const releaseContract = Object.freeze({
    assetBinding: 'ASSETS' as const,
    assetConfig: Object.freeze({
      notFoundHandling: 'single-page-application' as const,
      runWorkerFirst: EXACT_RUN_WORKER_FIRST,
    }),
    bootstrapBinding: phase === 'bootstrap' ? 'present' as const : 'absent' as const,
    compatibilityDate: EXACT_COMPATIBILITY_DATE,
    compatibilityFlags,
    durableObject: Object.freeze({
      binding: 'ADMIN_STATE' as const,
      className: 'AdminState' as const,
      storage: 'sqlite' as const,
    }),
    exports: Object.freeze({
      AdminState: Object.freeze({ type: 'durable-object' as const, storage: 'sqlite' as const }),
    }),
    mainModule: 'index.js' as const,
  });
  const semanticInput: WorkerVersionSemanticInput = {
    phase,
    accountId: prepared.accountId,
    workerName: prepared.workerName,
    workerId: worker.workerId,
    releaseContract,
    assets,
    plainTextBindingHashes,
    modules,
  };
  const requestHash = await versionSemanticHash(semanticInput);
  const correlationTag = versionCorrelationTag(phase, requestHash);
  const recovery: WorkerVersionRecoveryRecord = Object.freeze({
    kind: 'version_recovery',
    phase,
    accountId: prepared.accountId,
    workerName: prepared.workerName,
    workerId: worker.workerId,
    requestHash,
    correlationTag,
    releaseContract,
    assets,
    plainTextBindingHashes: Object.freeze(plainTextBindingHashes),
    modules: Object.freeze(modules),
  });
  if (!await validVersionRecoveryRecord(recovery)) {
    fail('invalid_input', 'validate', 'not_sent', progress);
  }
  return recovery;
}

export async function prepareWorkerVersionMutation(
  prepared: PreparedVerifiedWorkerRelease,
  worker: WorkerSubmission,
  completionJwt: string | null,
  phase: WorkerVersionPhase,
): Promise<WorkerVersionMutationPlan> {
  const progress = initialProgress();
  // The provision version carries no ASSETS binding and therefore no asset
  // completion token; every other phase requires one.
  if (phase === 'provision' ? completionJwt !== null : !safeToken(completionJwt)) {
    fail('invalid_input', 'validate', 'not_sent', progress);
  }
  const recovery = await prepareWorkerVersionRecoveryRecord(prepared, worker, phase);
  const bindings = versionBindings(prepared, phase);
  const semanticCommitment = Object.freeze(versionSemanticCommitment(recovery));
  const versionBodyCore = {
    bindings,
    compatibility_date: recovery.releaseContract.compatibilityDate,
    compatibility_flags: [...recovery.releaseContract.compatibilityFlags],
    exports: recovery.releaseContract.exports,
    main_module: recovery.releaseContract.mainModule,
    modules: prepared.modules.map((module) => ({
      name: module.name,
      content_type: module.contentType,
      content_base64: bytesToBase64(module.bytes),
    })),
  };
  let coreBody: BoundaryObject;
  if (phase === 'provision') {
    coreBody = versionBodyCore;
  } else {
    if (!safeToken(completionJwt)) fail('invalid_input', 'validate', 'not_sent', progress);
    coreBody = {
      ...versionBodyCore,
      assets: {
        config: {
          not_found_handling: 'single-page-application',
          run_worker_first: [...EXACT_RUN_WORKER_FIRST],
        },
        jwt: completionJwt,
      },
    };
  }
  const body = Object.freeze({
    ...coreBody,
    annotations: Object.freeze({ 'workers/tag': recovery.correlationTag }),
  });
  const ephemeral: WorkerVersionSubmitIntent = Object.freeze({
    kind: 'version_submit',
    phase,
    accountId: prepared.accountId,
    workerName: prepared.workerName,
    workerId: worker.workerId,
    requestHash: recovery.requestHash,
    correlationTag: recovery.correlationTag,
    semanticCommitment,
    body,
  });
  return Object.freeze({
    ephemeral,
    recovery,
  });
}

function hasSecretRecoverySerialization(recovery: WorkerVersionRecoveryRecord): boolean {
  try {
    return /jwt|nonce|token|secret/iu.test(JSON.stringify(recovery));
  } catch {
    return true;
  }
}

function validVersionReleaseContract(
  value: BoundaryValue,
  phase: WorkerVersionPhase,
): value is WorkerVersionRecoveryRecord['releaseContract'] {
  const candidate = v.safeParse(versionReleaseContractSchema, value);
  return candidate.success &&
    candidate.output.bootstrapBinding === (phase === 'bootstrap' ? 'present' : 'absent');
}

async function validVersionRecoveryRecord(recovery: WorkerVersionRecoveryRecord): Promise<boolean> {
  const candidate = v.safeParse(versionRecoveryRecordSchema, recovery);
  if (!candidate.success) return false;
  const record = candidate.output;
  if (record.correlationTag !== versionCorrelationTag(record.phase, record.requestHash) ||
    !validVersionReleaseContract(record.releaseContract, record.phase) ||
    hasSecretRecoverySerialization(recovery)) return false;
  let totalBytes = 0;
  let previousAssetPath = '';
  const contentTypesByHash = new Map<string, string>();
  for (const asset of record.assets) {
    if (
      !safeAssetPath(asset.path) ||
      (previousAssetPath !== '' && previousAssetPath >= asset.path) ||
      asset.contentType !== ASSET_CONTENT_TYPES[extension(asset.path)] ||
      !ASSET_HASH_PATTERN.test(asset.uploadHash)
    ) return false;
    const priorContentType = contentTypesByHash.get(asset.uploadHash);
    if (priorContentType !== undefined && priorContentType !== asset.contentType) return false;
    contentTypesByHash.set(asset.uploadHash, asset.contentType);
    totalBytes += asset.byteLength;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_RELEASE_BYTES) return false;
    previousAssetPath = asset.path;
  }
  for (let index = 0; index < record.plainTextBindingHashes.length; index += 1) {
    const binding = record.plainTextBindingHashes.at(index);
    const expectedName = EXACT_PLAIN_TEXT_BINDINGS.at(index);
    if (
      binding === undefined || expectedName === undefined || binding.name !== expectedName
    ) return false;
  }
  const names = new Set<string>();
  let previousModuleName = '';
  for (const module of record.modules) {
    if (
      !safeModuleName(module.name) ||
      names.has(module.name) ||
      (previousModuleName !== '' && previousModuleName >= module.name) ||
      module.contentType !== MODULE_CONTENT_TYPES[extension(module.name)] ||
      !SHA256_PATTERN.test(module.contentSha256)
    ) return false;
    totalBytes += module.byteLength;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_RELEASE_BYTES) return false;
    names.add(module.name);
    previousModuleName = module.name;
  }
  if (!names.has('index.js')) return false;
  try {
    return await versionSemanticHash(record) === record.requestHash;
  } catch {
    return false;
  }
}

/**
 * Pure journal-boundary parser. Performs no provider I/O and returns a new,
 * deeply immutable, credential-free record only after the exact semantic hash
 * has been recomputed. Callers should persist this result, never the submit
 * intent or its body.
 */
export async function parseWorkerVersionRecoveryRecord<Input>(
  value: Input,
): Promise<WorkerVersionRecoveryRecord | null> {
  try {
    const candidate = v.safeParse(versionRecoveryRecordSchema, value);
    if (!candidate.success || !await validVersionRecoveryRecord(candidate.output)) return null;
    const input = candidate.output;
    const phase = input.phase;
    const compatibilityFlags: readonly [] = Object.freeze([]);
    const parsed: WorkerVersionRecoveryRecord = Object.freeze({
      kind: 'version_recovery',
      phase,
      accountId: input.accountId,
      workerName: input.workerName,
      workerId: input.workerId,
      requestHash: input.requestHash,
      correlationTag: input.correlationTag,
      releaseContract: Object.freeze({
        assetBinding: 'ASSETS',
        assetConfig: Object.freeze({
          notFoundHandling: 'single-page-application',
          runWorkerFirst: EXACT_RUN_WORKER_FIRST,
        }),
        bootstrapBinding: phase === 'bootstrap' ? 'present' : 'absent',
        compatibilityDate: EXACT_COMPATIBILITY_DATE,
        compatibilityFlags,
        durableObject: Object.freeze({
          binding: 'ADMIN_STATE',
          className: 'AdminState',
          storage: 'sqlite',
        }),
        exports: Object.freeze({
          AdminState: Object.freeze({ type: 'durable-object', storage: 'sqlite' }),
        }),
        mainModule: 'index.js',
      }),
      assets: Object.freeze(input.assets.map((asset) => Object.freeze({
        path: asset.path,
        uploadHash: asset.uploadHash,
        contentType: asset.contentType,
        byteLength: asset.byteLength,
      }))),
      plainTextBindingHashes: Object.freeze(input.plainTextBindingHashes.map((binding) => Object.freeze({
        name: binding.name,
        valueSha256: binding.valueSha256,
      }))),
      modules: Object.freeze(input.modules.map((module) => Object.freeze({
        name: module.name,
        contentType: module.contentType,
        contentSha256: module.contentSha256,
        byteLength: module.byteLength,
      }))),
    });
    return await validVersionRecoveryRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

async function validVersionSubmitIntent(
  intent: WorkerVersionSubmitIntent,
  recovery: WorkerVersionRecoveryRecord,
): Promise<boolean> {
  const candidate = v.safeParse(versionSubmitIntentSchema, intent);
  if (!candidate.success || !await validVersionRecoveryRecord(recovery)) return false;
  const parsedIntent = candidate.output;
  if (
    parsedIntent.phase !== recovery.phase || parsedIntent.accountId !== recovery.accountId ||
    parsedIntent.workerName !== recovery.workerName || parsedIntent.workerId !== recovery.workerId ||
    parsedIntent.requestHash !== recovery.requestHash || parsedIntent.correlationTag !== recovery.correlationTag ||
    !canonicalEqual(parsedIntent.semanticCommitment, versionSemanticCommitment(recovery)) ||
    parsedIntent.body.annotations['workers/tag'] !== parsedIntent.correlationTag ||
    parsedIntent.body.bindings.length !== recovery.plainTextBindingHashes.length +
      (recovery.phase === 'bootstrap' ? 3 : recovery.phase === 'clean' ? 2 : 0) ||
    parsedIntent.body.modules.length !== recovery.modules.length ||
    !canonicalEqual(parsedIntent.body.exports, recovery.releaseContract.exports) ||
    // The provision version carries no ASSETS binding and no asset session.
    (recovery.phase === 'provision'
      ? parsedIntent.body.assets !== undefined
      : parsedIntent.body.assets === undefined)
  ) return false;
  const bindings = new Map<string, v.InferOutput<typeof submitVersionBindingSchema>>();
  for (const binding of parsedIntent.body.bindings) {
    if (bindings.has(binding.name)) return false;
    bindings.set(binding.name, binding);
  }
  if (recovery.phase === 'provision') {
    if (bindings.has('ADMIN_STATE') || bindings.has('ASSETS')) return false;
  } else {
    if (!canonicalEqual(bindings.get('ADMIN_STATE'), {
      name: 'ADMIN_STATE', type: 'durable_object_namespace', class_name: 'AdminState',
    })) return false;
    if (!canonicalEqual(bindings.get('ASSETS'), { name: 'ASSETS', type: 'assets' })) return false;
  }
  const redactedBinding = bindings.get('ANKKA_BOOTSTRAP_NONCE');
  if (recovery.phase === 'bootstrap') {
    if (redactedBinding?.name !== 'ANKKA_BOOTSTRAP_NONCE') return false;
  } else if (redactedBinding !== undefined) return false;
  for (const expected of recovery.plainTextBindingHashes) {
    const binding = bindings.get(expected.name);
    if (
      binding?.name !== expected.name || binding.type !== 'plain_text' ||
      await sha256(binding.text) !== expected.valueSha256
    ) return false;
  }
  for (let index = 0; index < parsedIntent.body.modules.length; index += 1) {
    const module = parsedIntent.body.modules.at(index);
    const metadata = recovery.modules.at(index);
    if (
      module === undefined || metadata === undefined ||
      module.name !== metadata.name ||
      module.content_type !== metadata.contentType ||
      strictBase64Bytes(module.content_base64, metadata.byteLength) === null
    ) return false;
    const bytes = strictBase64Bytes(module.content_base64, metadata.byteLength);
    if (!bytes || await sha256(bytes) !== metadata.contentSha256) return false;
  }
  try {
    return await sha256(canonicalJson(parsedIntent.semanticCommitment)) === parsedIntent.requestHash;
  } catch {
    return false;
  }
}

function versionResponseLimit(recovery: WorkerVersionRecoveryRecord): number {
  const expectedContentBytes = recovery.modules.reduce(
    (sum, module) => sum + 4 * Math.ceil(module.byteLength / 3),
    0,
  );
  return Math.min(64 * 1024 * 1024, Math.max(MAX_RESPONSE_BYTES, expectedContentBytes + 1024 * 1024));
}

function versionSubmission(recovery: WorkerVersionRecoveryRecord, versionId: string): VersionSubmission {
  return Object.freeze({
    kind: 'version',
    phase: recovery.phase,
    accountId: recovery.accountId,
    workerName: recovery.workerName,
    workerId: recovery.workerId,
    versionId,
    requestHash: recovery.requestHash,
    correlationTag: recovery.correlationTag,
  });
}

export async function submitWorkerVersionMutation(
  intent: WorkerVersionSubmitIntent,
  recovery: WorkerVersionRecoveryRecord,
  callInput: CloudflareDirectUploadCall,
): Promise<VersionSubmission> {
  const progress = initialProgress();
  if (!await validVersionSubmitIntent(intent, recovery)) {
    fail('invalid_input', 'validate', 'not_sent', progress);
  }
  const call = prepareCall(callInput, progress);
  const response = await performRequest(
    call,
    progress,
    'worker_version',
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/workers/${intent.workerId}/versions`,
    {
      method: 'POST',
      headers: jsonHeaders(call.accessToken),
      body: JSON.stringify(intent.body),
    },
    versionResponseLimit(recovery),
  );
  const versionId = rawResultId(response.value, UUID_PATTERN);
  if (![200, 201].includes(response.status)) {
    if (response.status >= 200 && response.status < 300 && versionId !== null) {
      fail(
        'provider_mismatch',
        'worker_version',
        'submitted',
        progress,
        [versionSubmission(recovery, versionId)],
      );
    }
    rejectForStatus(response.status, response.value, 'worker_version', progress);
  }
  if (versionId === null) {
    requireSuccess(response, [200, 201], 'worker_version', progress);
    fail('provider_mismatch', 'worker_version', 'unknown', progress);
  }
  const submission = versionSubmission(recovery, versionId);
  const result = parseSuccessEnvelope(response.value);
  if (result === null || !isRecord(result) || result.id !== versionId) {
    fail('provider_mismatch', 'worker_version', 'submitted', progress, [submission]);
  }
  progress.versionCreated = true;
  return submission;
}

async function verifyWorkerVersionSubmissionWithMode(
  recovery: WorkerVersionRecoveryRecord,
  submission: VersionSubmission,
  callInput: CloudflareDirectUploadCall,
  expectedNamespaceId?: string,
  requireModuleContent = false,
): Promise<VersionSubmission> {
  const progress = initialProgress();
  progress.versionCreated = true;
  if (
    !await validVersionRecoveryRecord(recovery) ||
    submission.phase !== recovery.phase ||
    submission.accountId !== recovery.accountId ||
    submission.workerName !== recovery.workerName ||
    submission.workerId !== recovery.workerId ||
    submission.requestHash !== recovery.requestHash ||
    submission.correlationTag !== recovery.correlationTag ||
    !UUID_PATTERN.test(submission.versionId) ||
    (expectedNamespaceId !== undefined && !ACCOUNT_ID_PATTERN.test(expectedNamespaceId))
  ) fail('invalid_input', 'validate', 'not_sent', progress, [submission]);
  const call = prepareCall(callInput, progress);
  try {
    const response = await performRequest(
      call,
      progress,
      'version_verify',
      // Module content is returned only when explicitly included, so the exact
      // uploaded bytes stay verifiable on read-back (live contract 2026-08-23).
      `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${recovery.accountId}/workers/workers/${recovery.workerId}/versions/${submission.versionId}?include=modules`,
      { method: 'GET', headers: authHeaders(call.accessToken) },
      versionResponseLimit(recovery),
    );
    const result = requireSuccess(response, [200], 'version_verify', progress);
    if (!await exactVersionResult(
      result,
      recovery,
      submission.versionId,
      expectedNamespaceId,
      requireModuleContent,
    )) {
      fail('provider_mismatch', 'version_verify', 'submitted', progress, [submission]);
    }
    return submission;
  } catch (error) {
    rethrowWithSubmissions(error, [submission], 'submitted');
  }
}

export async function verifyWorkerVersionSubmission(
  recovery: WorkerVersionRecoveryRecord,
  submission: VersionSubmission,
  callInput: CloudflareDirectUploadCall,
  expectedNamespaceId?: string,
): Promise<VersionSubmission> {
  return verifyWorkerVersionSubmissionWithMode(
    recovery,
    submission,
    callInput,
    expectedNamespaceId,
    false,
  );
}

type VersionListItem = v.InferOutput<typeof versionListItemSchema>;

function parseVersionListPage(
  value: BoundaryValue,
  expectedPage: number,
): { readonly items: readonly VersionListItem[]; readonly totalCount: number; readonly totalPages: number } | null {
  const candidate = v.safeParse(versionListPageSchema, value);
  if (!candidate.success || !isEmptyProviderList(candidate.output.errors) ||
    !isEmptyProviderList(candidate.output.messages)) return null;
  const info = candidate.output.result_info;
  // Live (2026-08-23): the version list omits total_pages entirely. When it is
  // absent the page count is derived from the totals actually reported.
  const totalPages = info.total_pages === undefined
    ? (info.total_count === 0 ? 0 : Math.ceil(info.total_count))
    : info.total_pages;
  if (
    info.page !== expectedPage ||
    info.per_page !== 1 ||
    info.count !== candidate.output.result.length ||
    totalPages !== (info.total_count === 0 ? 0 : Math.ceil(info.total_count)) ||
    (totalPages === 0 && (expectedPage !== 1 || candidate.output.result.length !== 0))
  ) return null;
  return { items: candidate.output.result, totalCount: info.total_count, totalPages };
}

function versionItemTag(value: VersionListItem): { readonly id: string; readonly tag: string | null } | null {
  if (value.annotations === undefined) return { id: value.id, tag: null };
  const tag = value.annotations['workers/tag'];
  return { id: value.id, tag: tag ?? null };
}

export async function inspectWorkerVersionRecovery(
  recovery: WorkerVersionRecoveryRecord,
  callInput: CloudflareDirectUploadCall,
): Promise<VersionSubmission | null> {
  const progress = initialProgress();
  if (!await validVersionRecoveryRecord(recovery)) fail('invalid_input', 'validate', 'not_sent', progress);
  const call = prepareCall(callInput, progress);
  const matches: string[] = [];
  const seenIds = new Set<string>();
  let page = 1;
  let totalPages = 1;
  let totalCount: number | undefined;
  while (page <= totalPages) {
    const response = await performRequest(
      call,
      progress,
      'version_recovery',
      `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${recovery.accountId}/workers/workers/${recovery.workerId}/versions?page=${page}&per_page=1`,
      { method: 'GET', headers: authHeaders(call.accessToken) },
      versionResponseLimit(recovery),
    );
    if (response.status !== 200) rejectForStatus(response.status, response.value, 'version_recovery', progress);
    const parsed = parseVersionListPage(response.value, page);
    if (!parsed) fail('provider_mismatch', 'version_recovery', 'unknown', progress);
    if (totalCount !== undefined && (
      parsed.totalCount !== totalCount || parsed.totalPages !== totalPages
    )) fail('provider_mismatch', 'version_recovery', 'unknown', progress);
    totalCount = parsed.totalCount;
    totalPages = parsed.totalPages;
    for (const item of parsed.items) {
      const parsedItem = versionItemTag(item);
      if (!parsedItem) fail('provider_mismatch', 'version_recovery', 'unknown', progress);
      if (seenIds.has(parsedItem.id)) {
        fail('provider_mismatch', 'version_recovery', 'unknown', progress);
      }
      seenIds.add(parsedItem.id);
      if (parsedItem.tag === recovery.correlationTag) matches.push(parsedItem.id);
    }
    page += 1;
  }
  if (matches.length === 0) return null;
  if (matches.length !== 1) fail('recovery_ambiguous', 'version_recovery', 'unknown', progress);
  const versionId = matches.at(0);
  if (versionId === undefined) fail('provider_mismatch', 'version_recovery', 'unknown', progress);
  const submission = versionSubmission(recovery, versionId);
  return await verifyWorkerVersionSubmission(recovery, submission, callInput);
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
  let total = 0;
  const versionIds = new Set<string>();
  for (const version of candidate.output.versions) {
    if (versionIds.has(version.version_id)) return null;
    versionIds.add(version.version_id);
    total += version.percentage;
  }
  return total === 100 ? candidate.output : null;
}

export interface WorkerDeploymentMutationIntent {
  readonly kind: 'deployment';
  readonly phase: WorkerVersionPhase;
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly versionId: string;
  readonly requestHash: string;
  readonly correlationTag: string;
  readonly body: {
    readonly annotations: { readonly 'workers/message': string };
    readonly strategy: 'percentage';
    readonly versions: readonly [{ readonly percentage: 100; readonly version_id: string }];
  };
}

export type DeploymentSubmission = Extract<CloudflareDirectUploadSubmission, { readonly kind: 'deployment' }>;

function deploymentCorrelationTag(phase: WorkerVersionPhase, requestHash: string): string {
  return `ankka-deploy-${phase}-sha256:${requestHash}`;
}

export async function prepareWorkerDeploymentMutation(
  version: VersionSubmission,
): Promise<WorkerDeploymentMutationIntent> {
  const progress = initialProgress();
  if (
    version.kind !== 'version' ||
    !ACCOUNT_ID_PATTERN.test(version.accountId) ||
    !WORKER_NAME_PATTERN.test(version.workerName) ||
    !WORKER_ID_PATTERN.test(version.workerId) ||
    !UUID_PATTERN.test(version.versionId) ||
    !SHA256_PATTERN.test(version.requestHash) ||
    (version.phase !== 'provision' && version.phase !== 'bootstrap' && version.phase !== 'clean') ||
    version.correlationTag !== versionCorrelationTag(version.phase, version.requestHash)
  ) fail('invalid_input', 'validate', 'not_sent', progress, [version]);
  const core = {
    strategy: 'percentage' as const,
    versions: [{ percentage: 100 as const, version_id: version.versionId }] as const,
  };
  const requestHash = await sha256(canonicalJson(core));
  const correlationTag = deploymentCorrelationTag(version.phase, requestHash);
  return Object.freeze({
    kind: 'deployment',
    phase: version.phase,
    accountId: version.accountId,
    workerName: version.workerName,
    workerId: version.workerId,
    versionId: version.versionId,
    requestHash,
    correlationTag,
    body: Object.freeze({
      annotations: Object.freeze({ 'workers/message': correlationTag }),
      ...core,
    }),
  });
}

async function validDeploymentIntent(intent: WorkerDeploymentMutationIntent): Promise<boolean> {
  if (
    !isRecord(intent) ||
    intent.kind !== 'deployment' ||
    (intent.phase !== 'provision' && intent.phase !== 'bootstrap' && intent.phase !== 'clean') ||
    !ACCOUNT_ID_PATTERN.test(intent.accountId) ||
    !WORKER_NAME_PATTERN.test(intent.workerName) ||
    !WORKER_ID_PATTERN.test(intent.workerId) ||
    !UUID_PATTERN.test(intent.versionId) ||
    !SHA256_PATTERN.test(intent.requestHash) ||
    intent.correlationTag !== deploymentCorrelationTag(intent.phase, intent.requestHash) ||
    !isRecord(intent.body) ||
    !canonicalEqual(intent.body, {
      annotations: { 'workers/message': intent.correlationTag },
      strategy: 'percentage',
      versions: [{ percentage: 100, version_id: intent.versionId }],
    })
  ) return false;
  return await sha256(canonicalJson({
    strategy: 'percentage',
    versions: [{ percentage: 100, version_id: intent.versionId }],
  })) === intent.requestHash;
}

function deploymentSubmission(
  intent: WorkerDeploymentMutationIntent,
  deploymentId: string,
): DeploymentSubmission {
  return Object.freeze({
    kind: 'deployment',
    phase: intent.phase,
    accountId: intent.accountId,
    workerName: intent.workerName,
    workerId: intent.workerId,
    versionId: intent.versionId,
    deploymentId,
    requestHash: intent.requestHash,
    correlationTag: intent.correlationTag,
  });
}

function exactDeployment(
  value: BoundaryValue,
  intent: WorkerDeploymentMutationIntent,
  expectedDeploymentId: string,
): boolean {
  const observation = parseDeploymentObservation(value);
  return observation !== null && observation.id === expectedDeploymentId &&
    observation.annotations?.['workers/message'] === intent.correlationTag &&
    observation.versions.length === 1 && observation.versions[0]?.percentage === 100 &&
    observation.versions[0]?.version_id === intent.versionId;
}

export async function submitWorkerDeploymentMutation(
  intent: WorkerDeploymentMutationIntent,
  callInput: CloudflareDirectUploadCall,
): Promise<DeploymentSubmission> {
  const progress = initialProgress();
  if (!await validDeploymentIntent(intent)) fail('invalid_input', 'validate', 'not_sent', progress);
  const call = prepareCall(callInput, progress);
  const response = await performRequest(
    call,
    progress,
    'deployment',
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/scripts/${encodeURIComponent(intent.workerName)}/deployments`,
    {
      method: 'POST',
      headers: jsonHeaders(call.accessToken),
      body: JSON.stringify(intent.body),
    },
  );
  const deploymentId = rawResultId(response.value, UUID_PATTERN);
  if (![200, 201].includes(response.status)) {
    if (response.status >= 200 && response.status < 300 && deploymentId !== null) {
      fail(
        'provider_mismatch',
        'deployment',
        'submitted',
        progress,
        [deploymentSubmission(intent, deploymentId)],
      );
    }
    rejectForStatus(response.status, response.value, 'deployment', progress);
  }
  if (deploymentId === null) {
    requireSuccess(response, [200, 201], 'deployment', progress);
    fail('provider_mismatch', 'deployment', 'unknown', progress);
  }
  const submission = deploymentSubmission(intent, deploymentId);
  const result = parseSuccessEnvelope(response.value);
  if (result === null || !isRecord(result) || result.id !== deploymentId) {
    fail('provider_mismatch', 'deployment', 'submitted', progress, [submission]);
  }
  return submission;
}

export async function verifyWorkerDeploymentSubmission(
  intent: WorkerDeploymentMutationIntent,
  submission: DeploymentSubmission,
  callInput: CloudflareDirectUploadCall,
): Promise<DeploymentSubmission> {
  const progress = initialProgress();
  if (
    !await validDeploymentIntent(intent) ||
    submission.phase !== intent.phase ||
    submission.accountId !== intent.accountId ||
    submission.workerName !== intent.workerName ||
    submission.workerId !== intent.workerId ||
    submission.versionId !== intent.versionId ||
    submission.requestHash !== intent.requestHash ||
    submission.correlationTag !== intent.correlationTag ||
    !UUID_PATTERN.test(submission.deploymentId)
  ) fail('invalid_input', 'validate', 'not_sent', progress, [submission]);
  const call = prepareCall(callInput, progress);
  try {
    const response = await performRequest(
      call,
      progress,
      'deployment_verify',
      `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/scripts/${encodeURIComponent(intent.workerName)}/deployments/${submission.deploymentId}`,
      { method: 'GET', headers: authHeaders(call.accessToken) },
    );
    const result = requireSuccess(response, [200], 'deployment_verify', progress);
    if (!exactDeployment(result, intent, submission.deploymentId)) {
      fail('provider_mismatch', 'deployment_verify', 'submitted', progress, [submission]);
    }
    progress.deploymentVerified = true;
    return submission;
  } catch (error) {
    rethrowWithSubmissions(error, [submission], 'submitted');
  }
}

/**
 * Prove that the latest actively serving deployment is the exact persisted
 * bootstrap or clean deployment. Cloudflare documents item zero of this
 * non-paginated list as the currently active deployment; any pagination
 * metadata is rejected by the exact envelope parser rather than followed or
 * inferred. Provision exports are never accepted because they must not receive
 * a bootstrap request or become terminal runtime authority.
 */
export async function verifyActiveWorkerDeployment(
  intent: WorkerDeploymentMutationIntent,
  submission: DeploymentSubmission,
  callInput: CloudflareDirectUploadCall,
): Promise<DeploymentSubmission> {
  const progress = initialProgress();
  if (
    !await validDeploymentIntent(intent) ||
    (intent.phase !== 'bootstrap' && intent.phase !== 'clean') ||
    submission.kind !== 'deployment' ||
    submission.phase !== intent.phase ||
    submission.accountId !== intent.accountId ||
    submission.workerName !== intent.workerName ||
    submission.workerId !== intent.workerId ||
    submission.versionId !== intent.versionId ||
    submission.requestHash !== intent.requestHash ||
    submission.correlationTag !== intent.correlationTag ||
    !UUID_PATTERN.test(submission.deploymentId)
  ) fail('invalid_input', 'validate', 'not_sent', progress, [submission]);
  const call = prepareCall(callInput, progress);
  try {
    const response = await performRequest(
      call,
      progress,
      'deployment_active_verify',
      `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/scripts/${encodeURIComponent(intent.workerName)}/deployments`,
      { method: 'GET', headers: authHeaders(call.accessToken) },
      2 * 1024 * 1024,
    );
    if (response.status !== 200) {
      rejectForStatus(response.status, response.value, 'deployment_active_verify', progress);
    }
    const deployments = parseDeploymentList(response.value);
    if (!deployments || deployments.length === 0) {
      fail('provider_mismatch', 'deployment_active_verify', 'submitted', progress, [submission]);
    }
    const seenIds = new Set<string>();
    let correlationMatches = 0;
    for (const deployment of deployments) {
      const observation = parseDeploymentObservation(deployment);
      if (!observation) {
        fail('provider_mismatch', 'deployment_active_verify', 'submitted', progress, [submission]);
      }
      const deploymentId = observation.id;
      if (seenIds.has(deploymentId)) {
        fail('provider_mismatch', 'deployment_active_verify', 'submitted', progress, [submission]);
      }
      seenIds.add(deploymentId);
      const annotations = deploymentAnnotations(observation.annotations);
      if (annotations?.['workers/message'] === intent.correlationTag) correlationMatches += 1;
    }
    if (correlationMatches !== 1) {
      fail(
        correlationMatches > 1 ? 'recovery_ambiguous' : 'provider_mismatch',
        'deployment_active_verify',
        'submitted',
        progress,
        [submission],
      );
    }
    if (!exactDeployment(deployments[0], intent, submission.deploymentId)) {
      fail('provider_mismatch', 'deployment_active_verify', 'submitted', progress, [submission]);
    }
    progress.deploymentVerified = true;
    return submission;
  } catch (error) {
    rethrowWithSubmissions(error, [submission], 'submitted');
  }
}

export interface ActiveWorkerVersionProof {
  readonly version: VersionSubmission;
  readonly deployment: DeploymentSubmission;
}

/**
 * Prove the exact bootstrap or clean version that is actively serving without
 * trusting a caller-supplied version or deployment locator. The first
 * deployment read discovers only Cloudflare's active IDs. The version read
 * then verifies the exact returned module bytes and every plaintext binding. A
 * second deployment read closes the read-back race by proving that exact
 * verified version is still the sole 100% active deployment. Asset
 * configuration is checked, but asset content is deliberately not release
 * authority because this API does not return an immutable asset manifest or
 * content digest.
 */
export async function proveActiveWorkerVersionRecovery(
  recovery: WorkerVersionRecoveryRecord,
  callInput: CloudflareDirectUploadCall,
  expectedNamespaceId?: string,
): Promise<ActiveWorkerVersionProof> {
  const progress = initialProgress();
  if (
    !await validVersionRecoveryRecord(recovery) ||
    (recovery.phase !== 'bootstrap' && recovery.phase !== 'clean') ||
    (expectedNamespaceId !== undefined && !ACCOUNT_ID_PATTERN.test(expectedNamespaceId))
  ) fail('invalid_input', 'validate', 'not_sent', progress);
  const call = prepareCall(callInput, progress);
  const response = await performRequest(
    call,
    progress,
    'deployment_active_verify',
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${recovery.accountId}/workers/scripts/${encodeURIComponent(recovery.workerName)}/deployments`,
    { method: 'GET', headers: authHeaders(call.accessToken) },
    2 * 1024 * 1024,
  );
  if (response.status !== 200) {
    rejectForStatus(response.status, response.value, 'deployment_active_verify', progress);
  }
  const deployments = parseDeploymentList(response.value);
  const active = deployments?.[0];
  if (!deployments || !active || active.versions.length !== 1) {
    fail('provider_mismatch', 'deployment_active_verify', 'unknown', progress);
  }
  const activeVersion = active.versions[0];
  if (!activeVersion || activeVersion.percentage !== 100) {
    fail('provider_mismatch', 'deployment_active_verify', 'unknown', progress);
  }
  const version = versionSubmission(recovery, String(activeVersion.version_id));
  // Credential-bearing relay preflights use this stronger mode: the beta
  // Versions API is queried with `include=modules`, so omission of any
  // content_base64 is a mismatch rather than something a caller-controlled
  // annotation can cover.
  await verifyWorkerVersionSubmissionWithMode(
    recovery,
    version,
    callInput,
    expectedNamespaceId,
    true,
  );
  const intent = await prepareWorkerDeploymentMutation(version);
  const deployment = deploymentSubmission(intent, String(active.id));
  await verifyActiveWorkerDeployment(intent, deployment, callInput);
  return Object.freeze({ version, deployment });
}

function parseDeploymentList(value: BoundaryValue): readonly DeploymentObservation[] | null {
  const result = parseSuccessEnvelope(value);
  const candidate = v.safeParse(deploymentListResultSchema, result);
  return candidate.success ? candidate.output.deployments : null;
}

export async function inspectWorkerDeploymentRecovery(
  intent: WorkerDeploymentMutationIntent,
  callInput: CloudflareDirectUploadCall,
): Promise<DeploymentSubmission | null> {
  const progress = initialProgress();
  if (!await validDeploymentIntent(intent)) fail('invalid_input', 'validate', 'not_sent', progress);
  const call = prepareCall(callInput, progress);
  const response = await performRequest(
    call,
    progress,
    'deployment_recovery',
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/scripts/${encodeURIComponent(intent.workerName)}/deployments`,
    { method: 'GET', headers: authHeaders(call.accessToken) },
    2 * 1024 * 1024,
  );
  if (response.status !== 200) rejectForStatus(response.status, response.value, 'deployment_recovery', progress);
  const deployments = parseDeploymentList(response.value);
  if (!deployments) fail('provider_mismatch', 'deployment_recovery', 'unknown', progress);
  const matches: string[] = [];
  for (const deployment of deployments) {
    const observation = parseDeploymentObservation(deployment);
    if (!observation) {
      fail('provider_mismatch', 'deployment_recovery', 'unknown', progress);
    }
    const annotations = deploymentAnnotations(observation.annotations);
    if (annotations?.['workers/message'] === intent.correlationTag) matches.push(observation.id);
  }
  if (matches.length === 0) return null;
  if (matches.length !== 1) fail('recovery_ambiguous', 'deployment_recovery', 'unknown', progress);
  const deploymentId = matches.at(0);
  if (deploymentId === undefined) fail('provider_mismatch', 'deployment_recovery', 'unknown', progress);
  return await verifyWorkerDeploymentSubmission(intent, deploymentSubmission(intent, deploymentId), callInput);
}

/**
 * The complete persistence allowlist for a production journal. Deliberately
 * excludes WorkerVersionSubmitIntent, AssetUploadSessionSubmission, and
 * AssetBucketSubmission because those values may contain provider credentials.
 */
export type CloudflareDirectUploadJournalRecord =
  | WorkerMutationIntent
  | AssetUploadSessionMutationIntent
  | AssetBucketMutationIntent
  | WorkerVersionRecoveryRecord
  | WorkerDeploymentMutationIntent
  | CloudflareDirectUploadSubmission;

/**
 * Test-only convenience orchestration. Production callers may journal only
 * CloudflareDirectUploadJournalRecord values: the safe request intent before
 * each POST, `versionPlan.recovery` (never `versionPlan.ephemeral`), and each
 * safe Worker/version/deployment submission immediately after return. NEVER
 * journal AssetUploadSessionSubmission or AssetBucketSubmission; their upload
 * credentials live only in the active invocation. This helper is intentionally
 * unreferenced by runtime entry points and performs no retries or recovery
 * inference.
 */
export async function __testOnlyDeployVerifiedWorkerRelease(
  input: DeployVerifiedWorkerReleaseInput,
): Promise<DeployVerifiedWorkerReleaseResult> {
  const progress = initialProgress();
  const submissions: CloudflareDirectUploadSubmission[] = [];
  try {
    const prepared = await prepareInput(input, progress);
    const call = prepareCall(input, progress);
    const workerIntent = await prepareWorkerMutation(prepared);
    const existingWorker = await inspectWorkerRecovery(workerIntent, input);
    if (existingWorker !== null) fail('worker_name_collision', 'worker_lookup', 'rejected', progress);
    const worker = await submitWorkerMutation(workerIntent, input);
    submissions.push(worker);
    await verifyWorkerSubmission(workerIntent, worker, input);
    progress.workerCreated = true;
    progress.workerVerified = true;
    const completionJwt = await uploadAssets(prepared, call, progress);
    const versionPlan = await prepareWorkerVersionMutation(prepared, worker, completionJwt, 'bootstrap');
    const version = await submitWorkerVersionMutation(versionPlan.ephemeral, versionPlan.recovery, input);
    submissions.push(version);
    await verifyWorkerVersionSubmission(versionPlan.recovery, version, input);
    progress.versionCreated = true;
    const deploymentIntent = await prepareWorkerDeploymentMutation(version);
    const deployment = await submitWorkerDeploymentMutation(deploymentIntent, input);
    submissions.push(deployment);
    await verifyWorkerDeploymentSubmission(deploymentIntent, deployment, input);
    progress.deploymentVerified = true;
    return Object.freeze({
      workerId: worker.workerId,
      workerName: prepared.workerName,
      versionId: version.versionId,
      deploymentId: deployment.deploymentId,
      percentage: 100,
    });
  } catch (error) {
    rethrowWithSubmissions(error, submissions);
  }
}
