import * as v from 'valibot';

import {
  __testOnlyDeployVerifiedWorkerRelease,
  CloudflareDirectUploadError,
  inspectAdminStateDurableObjectNamespace,
  inspectWorkerDeploymentRecovery,
  inspectWorkerRecovery,
  inspectWorkerVersionRecovery,
  parseWorkerVersionRecoveryRecord,
  prepareAssetBucketMutation,
  prepareAssetUploadSessionMutation,
  prepareVerifiedWorkerRelease,
  prepareWorkerDeploymentMutation,
  prepareWorkerMutation,
  prepareWorkerMutationForTarget,
  prepareWorkerVersionRecoveryRecord,
  prepareWorkerVersionMutation,
  proveActiveWorkerVersionRecovery,
  submitWorkerDeploymentMutation,
  submitWorkerMutation,
  submitWorkerScriptMutation,
  submitWorkerVersionMutation,
  verifyActiveWorkerDeployment,
  verifyWorkerSubmission,
  verifyWorkerVersionSubmission,
  submitAssetBucketMutation,
  submitAssetUploadSessionMutation,
  type CloudflareDirectUploadCall,
  type CloudflareDirectUploadJournalRecord,
  type CloudflareDirectUploadTransport,
  type DeployVerifiedWorkerReleaseInput,
  type GatewayWorkerPlainTextBindings,
  type VersionSubmission,
  type WorkerVersionRecoveryRecord,
  type VerifiedWorkerDirectUploadRelease,
  type WorkerSubmission,
} from '../src/cloudflare-worker-direct-upload';
import { boundaryObjectSchema, type BoundaryObject } from '../src/boundary';
import { requestJson } from './boundary';

const ACCOUNT_ID = 'a'.repeat(32);
const WORKER_ID = 'b'.repeat(32);
const WORKER_NAME = 'ankka-gateway-test';
const ACCESS_TOKEN = 'oauth_access_token_for_direct_upload_test';
const UPLOAD_JWT = 'upload.jwt.token_for_direct_upload_test';
const COMPLETION_JWT = 'completion.jwt.token_for_direct_upload_test';
const REFRESHED_COMPLETION_JWT = 'refreshed.completion.jwt_for_direct_upload_test';
const VERSION_ID = '182bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e';
const OTHER_VERSION_ID = '382bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e';
const DEPLOYMENT_ID = '282bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e';
const OTHER_DEPLOYMENT_ID = '482bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e';
const CREATED_ON = '2026-08-23T01:00:00.000Z';
const NAMESPACE_ID = 'e'.repeat(32);
const WORKER_SUBDOMAIN_HOSTNAME = `${WORKER_NAME}.example-account.workers.dev`;

interface ReleaseFixture {
  readonly release: VerifiedWorkerDirectUploadRelease;
  readonly moduleBase64: string;
  readonly assetHashes: Readonly<Record<string, string>>;
  readonly assetBase64: Readonly<Record<string, string>>;
}

type UploadRequest = Parameters<CloudflareDirectUploadTransport>[0];
type RecordedRequest = ReturnType<UploadRequest['clone']>;
type ResponseFactory = (request: UploadRequest) => Response | Promise<Response>;

const workerMutationBodySchema = v.object({ tags: v.array(v.string()) });
const versionBindingSchema = v.object({
  name: v.string(),
  type: v.string(),
  text: v.optional(v.string()),
  class_name: v.optional(v.string()),
});
const versionSubmitBodySchema = v.object({
  annotations: v.record(v.string(), v.string()),
  assets: v.object({
    config: boundaryObjectSchema,
    jwt: v.string(),
  }),
  bindings: v.array(versionBindingSchema),
  compatibility_date: v.string(),
  compatibility_flags: v.array(v.string()),
  exports: boundaryObjectSchema,
  main_module: v.string(),
  modules: v.array(v.object({
    name: v.string(),
    content_type: v.string(),
    content_base64: v.string(),
  })),
});
type VersionSubmitBody = v.InferOutput<typeof versionSubmitBodySchema>;
const deploymentSubmitBodySchema = v.object({
  annotations: v.record(v.string(), v.string()),
  strategy: v.literal('percentage'),
  versions: v.array(v.object({ percentage: v.number(), version_id: v.string() })),
});
type DeploymentSubmitBody = v.InferOutput<typeof deploymentSubmitBodySchema>;
const versionSubmissionSchema = v.object({
  kind: v.literal('version'),
  phase: v.picklist(['provision', 'bootstrap', 'clean']),
  accountId: v.string(),
  workerName: v.string(),
  workerId: v.string(),
  versionId: v.string(),
  requestHash: v.string(),
  correlationTag: v.string(),
});

async function directUploadError<Output>(operation: PromiseLike<Output>): Promise<CloudflareDirectUploadError> {
  try {
    await operation;
  } catch (error) {
    if (error instanceof CloudflareDirectUploadError) return error;
    throw error;
  }
  throw new Error('expected CloudflareDirectUploadError');
}

async function recoveryClone(
  recovery: WorkerVersionRecoveryRecord,
): Promise<WorkerVersionRecoveryRecord> {
  const parsed = await parseWorkerVersionRecoveryRecord(JSON.parse(JSON.stringify(recovery)));
  if (!parsed) throw new Error('serialized recovery did not parse');
  return parsed;
}

function required<Value>(value: Value | undefined, name: string): Value {
  if (value === undefined) throw new Error(`missing ${name}`);
  return value;
}

function base64(bytes: Uint8Array): string {
  let binary = '';
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.byteLength; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, Math.min(bytes.byteLength, offset + chunkSize)));
  }
  return btoa(binary);
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(value: Uint8Array | string): Promise<string> {
  const bytes = v.is(v.string(), value) ? new TextEncoder().encode(value) : value;
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes).buffer)));
}

async function releaseFixture(moduleBytes?: Uint8Array): Promise<ReleaseFixture> {
  const workerBytes = moduleBytes ?? new TextEncoder().encode(
    'export class AdminState {}; export default { async fetch() { return new Response("ok") } };',
  );
  const indexBytes = new TextEncoder().encode('<!doctype html><title>Ankka MCP Gateway</title>');
  const appBytes = new TextEncoder().encode('globalThis.__ankka = true;');
  const indexBase64 = base64(indexBytes);
  const appBase64 = base64(appBytes);
  const indexHash = (await sha256(`${indexBase64}html`)).slice(0, 32);
  const appHash = (await sha256(`${appBase64}js`)).slice(0, 32);
  const artifactSha256 = 'c'.repeat(64);
  return {
    release: {
      verification: 'ed25519',
      release: 'gateway-v1.2.3',
      artifactSha256,
      worker: {
        mainModule: 'index.js',
        compatibilityDate: '2026-08-08',
        compatibilityFlags: [],
        modules: [{
          name: 'index.js',
          contentType: 'application/javascript+module',
          sha256: await sha256(workerBytes),
          bytes: workerBytes,
        }],
        assets: {
          binding: 'ASSETS',
          notFoundHandling: 'single-page-application',
          runWorkerFirst: ['/__ankka/*', '/api/*'],
          files: [
            {
              path: '/index.html',
              contentType: 'text/html; charset=utf-8',
              sha256: await sha256(indexBytes),
              bytes: indexBytes,
            },
            {
              path: '/app.js',
              contentType: 'text/javascript; charset=utf-8',
              sha256: await sha256(appBytes),
              bytes: appBytes,
            },
          ],
        },
        durableObject: { binding: 'ADMIN_STATE', className: 'AdminState', storage: 'sqlite' },
      },
    },
    moduleBase64: base64(workerBytes),
    assetHashes: { '/app.js': appHash, '/index.html': indexHash },
    assetBase64: { '/app.js': appBase64, '/index.html': indexBase64 },
  };
}

function plainTextBindings(release: VerifiedWorkerDirectUploadRelease): GatewayWorkerPlainTextBindings {
  return {
    ADMIN_EMAILS: 'admin@example.com',
    ANKKA_INSTALL_ID: `acg-${'e'.repeat(24)}`,
    ANKKA_GATEWAY_RELEASE: release.release,
    ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${release.artifactSha256}`,
    ANKKA_MANAGEMENT_HOSTNAME: 'manage.example.com',
    ANKKA_UPDATE_CHANNEL: 'stable',
    ANKKA_UPDATE_KEY_ID: 'release-key-1',
    ANKKA_UPDATE_PUBLIC_KEY: 'A'.repeat(43),
    ANKKA_WORKERS_SUBDOMAIN: 'customer-workers',
    ANKKA_WORKER_NAME: WORKER_NAME,
    CF_ACCESS_AUD: 'access-audience-tag',
    CF_ACCESS_ISSUER: 'https://example.cloudflareaccess.com',
    CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID,
    CLOUDFLARE_ZONE_ID: 'd'.repeat(32),
    CLOUDFLARE_ZONE_NAME: 'example.com',
    ZERO_TRUST_READY: 'true',
  };
}

function prepareInput(release: VerifiedWorkerDirectUploadRelease) {
  return {
    accountId: ACCOUNT_ID,
    workerName: WORKER_NAME,
    release,
    plainTextBindings: plainTextBindings(release),
    bootstrapNonce: 'bootstrap_nonce_value_that_is_never_returned',
  } as const;
}

function call(transport: CloudflareDirectUploadTransport, timeoutMs?: number): CloudflareDirectUploadCall {
  const base = { accessToken: ACCESS_TOKEN, transport };
  return timeoutMs === undefined ? base : { ...base, timeoutMs };
}

function input(
  release: VerifiedWorkerDirectUploadRelease,
  transport: CloudflareDirectUploadTransport,
  timeoutMs?: number,
): DeployVerifiedWorkerReleaseInput {
  return { ...prepareInput(release), ...call(transport, timeoutMs) };
}

function success<Result>(result: Result, status = 200): Response {
  return Response.json({ errors: [], messages: [], result, success: true }, { status });
}

function failure(status: number, message = 'provider rejected request'): Response {
  return Response.json({
    errors: [{ code: 1000, message }], messages: [], result: null, success: false,
  }, { status });
}

function workerState(tags: readonly string[], workerId = WORKER_ID) {
  return {
    id: workerId,
    created_on: CREATED_ON,
    updated_on: CREATED_ON,
    deployed_on: null,
    logpush: false,
    name: WORKER_NAME,
    observability: {
      enabled: false,
      head_sampling_rate: 1,
      redact_query_string: false,
      logs: { enabled: false, head_sampling_rate: 1, invocation_logs: true, persist: true, destinations: [] },
      traces: { enabled: false, head_sampling_rate: 1, persist: true, destinations: [] },
    },
    references: {
      dispatch_namespace_outbounds: [], domains: [], durable_objects: [], queues: [], workers: [],
    },
    subdomain: {
      enabled: false,
      preview_url_suffix: `-${WORKER_SUBDOMAIN_HOSTNAME}`,
      previews_enabled: false,
      url: `https://${WORKER_SUBDOMAIN_HOSTNAME}`,
    },
    tags,
    tail_consumers: [],
  };
}

function versionResultFromBody<Input>(
  input: Input,
  options: { readonly echoModuleContent?: boolean; readonly versionId?: string } = {},
 ) {
  const body = v.parse(versionSubmitBodySchema, input);
  const modules = body.modules;
  const bindings = body.bindings;
  const assets = body.assets;
  return {
    id: options.versionId ?? VERSION_ID,
    created_on: CREATED_ON,
    number: 1,
    annotations: body.annotations,
    assets: { config: assets.config },
    bindings: bindings.map((binding) => binding.type === 'secret_text' || binding.type === 'inherit'
      ? { name: binding.name, type: 'secret_text' }
      : binding),
    compatibility_date: body.compatibility_date,
    compatibility_flags: body.compatibility_flags,
    main_module: body.main_module,
    modules: modules.map((module) => {
      const identity = { name: module.name, content_type: module.content_type };
      return options.echoModuleContent
        ? { ...identity, content_base64: module.content_base64 }
        : identity;
    }),
    exports: {
      AdminState: { type: 'durable-object', storage: 'sqlite', state: 'created' },
      default: { type: 'worker', state: 'created', cache: { enabled: false } },
    },
    exports_reconciliation: {
      created: ['AdminState'], deleted: [], info: [], removable_entries: [], renamed: [],
      transfer_pending: [], transferred: [], updated: [], warnings: [],
    },
    limits: { cpu_ms: 30_000 },
    placement: { mode: 'smart' },
    startup_time_ms: 2,
    usage_model: 'standard',
  };
}

function deploymentResultFromBody<Input>(
  input: Input,
  deploymentId = DEPLOYMENT_ID,
 ) {
  const body = v.parse(deploymentSubmitBodySchema, input);
  return {
    id: deploymentId,
    annotations: body.annotations,
    author_email: 'admin@example.com',
    created_on: CREATED_ON,
    source: 'api',
    strategy: body.strategy,
    versions: body.versions,
  };
}

interface SequencedTransport {
  readonly transport: CloudflareDirectUploadTransport;
  readonly requests: RecordedRequest[];
  readonly callCount: () => number;
}

function sequencedTransport(steps: readonly ResponseFactory[]): SequencedTransport {
  const requests: RecordedRequest[] = [];
  let index = 0;
  return {
    requests,
    callCount: () => index,
    transport: async (request) => {
      requests.push(request.clone());
      const step = steps[index];
      index += 1;
      if (!step) throw new Error('unexpected provider call');
      return await step(request);
    },
  };
}

function listPage<Item>(items: readonly Item[], page: number, totalCount: number): Response {
  return Response.json({
    errors: [],
    messages: [],
    result: items,
    result_info: {
      count: items.length, page, per_page: 1, total_count: totalCount, total_pages: totalCount,
    },
    success: true,
  });
}

function namespacePage<Item>(items: readonly Item[], page: number, totalCount: number): Response {
  return Response.json({
    errors: [], messages: [], result: items,
    result_info: {
      count: items.length,
      page,
      per_page: 1_000,
      total_count: totalCount,
      total_pages: totalCount === 0 ? 0 : Math.ceil(totalCount / 1_000),
    },
    success: true,
  });
}

interface NamespaceItem {
  readonly id: string;
  readonly class: string;
  readonly name: string;
  readonly script: string;
  readonly use_sqlite: boolean;
}

function namespaceItem(
  id: string,
  overrides: Partial<Omit<NamespaceItem, 'id'>> = {},
): NamespaceItem {
  return {
    id,
    class: 'OtherState',
    name: `namespace-${id}`,
    script: 'unrelated-worker',
    use_sqlite: true,
    ...overrides,
  };
}

describe('Cloudflare Worker direct upload prerequisite', () => {
  it('prepares the exact same telemetry-off Worker create intent before release bindings or Access AUD exist', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const fromTarget = await prepareWorkerMutationForTarget({
      accountId: ACCOUNT_ID,
      workerName: WORKER_NAME,
    });
    const fromRelease = await prepareWorkerMutation(prepared);

    expect(fromTarget).toEqual(fromRelease);
    expect(fromTarget.body).toEqual({
      logpush: false,
      name: WORKER_NAME,
      observability: { enabled: false },
      subdomain: { enabled: false, previews_enabled: false },
      tags: [
        'ankka-mcp-gateway',
        `ankka-worker-sha256:${fromTarget.requestHash}`,
      ],
      tail_consumers: [],
    });
    expect(JSON.stringify(fromTarget)).not.toMatch(/CF_ACCESS_AUD|access-audience-tag|binding/iu);
    expect(Object.isFrozen(fromTarget)).toBe(true);
    expect(Object.isFrozen(fromTarget.body)).toBe(true);
    expect(Object.isFrozen(fromTarget.body.tags)).toBe(true);
  });

  it.each([
    [{ accountId: 'a'.repeat(31), workerName: WORKER_NAME }],
    [{ accountId: ACCOUNT_ID, workerName: 'Uppercase-Worker' }],
    [{ accountId: ACCOUNT_ID, workerName: WORKER_NAME, extra: true }],
    [null],
  ])('rejects an inexact Worker-create target without deriving an intent', async (invalid) => {
    const error = await directUploadError(prepareWorkerMutationForTarget(invalid));
    expect(error).toBeInstanceOf(CloudflareDirectUploadError);
    expect(error).toMatchObject({
      code: 'invalid_input', stage: 'validate', outcome: 'not_sent', canRetry: false,
    });
    expect(error.message).toBe('invalid_input');
  });

  it('uses exact Worker, asset multipart, JSON Version, SQLite export, and 100% deployment contracts', async () => {
    const fixture = await releaseFixture();
    const appHash = required(fixture.assetHashes['/app.js'], 'app asset hash');
    const indexHash = required(fixture.assetHashes['/index.html'], 'index asset hash');
    let workerTags: readonly string[] = [];
    let versionBody: VersionSubmitBody | undefined;
    let deploymentBody: DeploymentSubmitBody | undefined;
    const sequence = sequencedTransport([
      () => failure(404, 'worker not found'),
      async (request) => {
        const body = await requestJson(request, workerMutationBodySchema);
        workerTags = body.tags;
        return success({ id: WORKER_ID }, 201);
      },
      () => success(workerState(workerTags)),
      () => success({ jwt: UPLOAD_JWT, buckets: [[appHash], [indexHash]] }),
      () => success(null, 202),
      () => success({ jwt: COMPLETION_JWT }, 201),
      async (request) => {
        versionBody = await requestJson(request, versionSubmitBodySchema);
        return success({ id: VERSION_ID }, 201);
      },
      () => success(versionResultFromBody(required(versionBody, 'version request body'))),
      async (request) => {
        deploymentBody = await requestJson(request, deploymentSubmitBodySchema);
        return success({ id: DEPLOYMENT_ID }, 201);
      },
      () => success(deploymentResultFromBody(required(deploymentBody, 'deployment request body'))),
    ]);

    await expect(__testOnlyDeployVerifiedWorkerRelease(input(fixture.release, sequence.transport))).resolves.toEqual({
      workerId: WORKER_ID,
      workerName: WORKER_NAME,
      versionId: VERSION_ID,
      deploymentId: DEPLOYMENT_ID,
      percentage: 100,
    });

    expect(sequence.callCount()).toBe(10);
    expect(sequence.requests.map((request) => `${request.method} ${new URL(request.url).pathname}`)).toEqual([
      `GET /client/v4/accounts/${ACCOUNT_ID}/workers/workers/${WORKER_NAME}`,
      `POST /client/v4/accounts/${ACCOUNT_ID}/workers/workers`,
      `GET /client/v4/accounts/${ACCOUNT_ID}/workers/workers/${WORKER_ID}`,
      `POST /client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${WORKER_NAME}/assets-upload-session`,
      `POST /client/v4/accounts/${ACCOUNT_ID}/workers/assets/upload`,
      `POST /client/v4/accounts/${ACCOUNT_ID}/workers/assets/upload`,
      `POST /client/v4/accounts/${ACCOUNT_ID}/workers/workers/${WORKER_ID}/versions`,
      `GET /client/v4/accounts/${ACCOUNT_ID}/workers/workers/${WORKER_ID}/versions/${VERSION_ID}`,
      `POST /client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${WORKER_NAME}/deployments`,
      `GET /client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${WORKER_NAME}/deployments/${DEPLOYMENT_ID}`,
    ]);

    const workerBody = await requestJson(required(sequence.requests.at(1), 'worker create request').clone(), boundaryObjectSchema);
    expect(workerBody).toMatchObject({
      logpush: false,
      name: WORKER_NAME,
      observability: { enabled: false },
      subdomain: { enabled: false, previews_enabled: false },
      tail_consumers: [],
    });
    expect(workerTags).toHaveLength(2);
    expect(workerTags[0]).toBe('ankka-mcp-gateway');
    expect(workerTags[1]).toMatch(/^ankka-worker-sha256:[a-f0-9]{64}$/u);
    expect(await required(sequence.requests.at(3), 'asset session request').clone().json()).toEqual({
      manifest: {
        '/app.js': { hash: appHash, size: required(fixture.release.worker.assets.files.at(1), 'app asset').bytes.byteLength },
        '/index.html': { hash: indexHash, size: required(fixture.release.worker.assets.files.at(0), 'index asset').bytes.byteLength },
      },
    });

    for (const [offset, hash, path] of [
      [4, appHash, '/app.js'],
      [5, indexHash, '/index.html'],
    ] as const) {
      const request = required(sequence.requests.at(offset), `asset upload request ${offset}`);
      expect(new URL(request.url).search).toBe('?base64=true');
      expect(request.headers.get('authorization')).toBe(`Bearer ${UPLOAD_JWT}`);
      expect(request.headers.get('content-type')).toMatch(/^multipart\/form-data; boundary=/u);
      const form = await request.clone().formData();
      expect([...form.keys()]).toEqual([hash]);
      const part = form.get(hash);
      expect(part).toBeInstanceOf(File);
      if (!(part instanceof File)) throw new TypeError('expected multipart file');
      expect(part.name).toBe(hash);
      expect(part.type).toBe(fixture.release.worker.assets.files.find((asset) => asset.path === path)?.contentType);
      expect(await part.text()).toBe(fixture.assetBase64[path]);
    }

    const submittedVersion = required(versionBody, 'version request body');
    expect(Object.keys(submittedVersion).sort()).toEqual([
      'annotations', 'assets', 'bindings', 'compatibility_date', 'compatibility_flags',
      'exports', 'main_module', 'modules',
    ]);
    expect(submittedVersion).toMatchObject({
      annotations: { 'workers/tag': expect.stringMatching(/^ankka-version-bootstrap-sha256:[a-f0-9]{64}$/u) },
      assets: {
        config: {
          not_found_handling: 'single-page-application',
          run_worker_first: ['/__ankka/*', '/api/*'],
        },
        jwt: COMPLETION_JWT,
      },
      compatibility_date: '2026-08-08',
      compatibility_flags: [],
      exports: { AdminState: { type: 'durable-object', storage: 'sqlite' } },
      main_module: 'index.js',
      modules: [{
        name: 'index.js', content_type: 'application/javascript+module', content_base64: fixture.moduleBase64,
      }],
    });
    expect(Object.hasOwn(submittedVersion, 'migrations')).toBe(false);
    const versionBindings = submittedVersion.bindings;
    expect(versionBindings.find((binding) => binding.name === 'ADMIN_STATE')).toEqual({
      class_name: 'AdminState', name: 'ADMIN_STATE', type: 'durable_object_namespace',
    });
    expect(versionBindings.find((binding) => binding.name === 'ANKKA_GATEWAY_RELEASE_SHA256')).toEqual({
      name: 'ANKKA_GATEWAY_RELEASE_SHA256',
      type: 'plain_text',
      text: `sha256:${fixture.release.artifactSha256}`,
    });
    expect(versionBindings.find((binding) => binding.name === 'ZERO_TRUST_READY')).toEqual({
      name: 'ZERO_TRUST_READY', type: 'plain_text', text: 'true',
    });
    expect(deploymentBody).toEqual({
      annotations: { 'workers/message': expect.stringMatching(/^ankka-deploy-bootstrap-sha256:[a-f0-9]{64}$/u) },
      strategy: 'percentage',
      versions: [{ percentage: 100, version_id: VERSION_ID }],
    });
    for (const index of [0, 1, 2, 3, 6, 7, 8, 9]) {
      expect(required(sequence.requests.at(index), `authenticated request ${index}`).headers.get('authorization'))
        .toBe(`Bearer ${ACCESS_TOKEN}`);
    }
  });

  it('requires exact 202 for every nonfinal asset bucket and exact 201 plus JWT for final', async () => {
    const fixture = await releaseFixture();
    const hashes = [
      required(fixture.assetHashes['/app.js'], 'app asset hash'),
      required(fixture.assetHashes['/index.html'], 'index asset hash'),
    ];
    let tags: readonly string[] = [];
    const sequence = sequencedTransport([
      () => failure(404),
      async (request) => {
        tags = (await requestJson(request, workerMutationBodySchema)).tags;
        return success({ id: WORKER_ID }, 201);
      },
      () => success(workerState(tags)),
      () => success({
        jwt: UPLOAD_JWT,
        buckets: [[required(hashes.at(0), 'app asset hash')], [required(hashes.at(1), 'index asset hash')]],
      }),
      () => success(null, 200),
    ]);
    const error = await directUploadError(__testOnlyDeployVerifiedWorkerRelease(
      input(fixture.release, sequence.transport),
    ));
    expect(error).toMatchObject({ code: 'provider_unknown', stage: 'asset_bucket', outcome: 'unknown' });
    expect(sequence.callCount()).toBe(5);
  });

  it('builds distinct ready=true bootstrap and clean version contracts', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const bootstrap = await prepareWorkerVersionMutation(
      prepared,
      worker,
      COMPLETION_JWT,
      'bootstrap',
    );
    const clean = await prepareWorkerVersionMutation(prepared, worker, COMPLETION_JWT, 'clean');
    const bootstrapBindings = v.parse(versionSubmitBodySchema, bootstrap.ephemeral.body).bindings;
    const cleanBindings = v.parse(versionSubmitBodySchema, clean.ephemeral.body).bindings;
    for (const bindings of [bootstrapBindings, cleanBindings]) {
      expect(bindings.find((binding) => binding.name === 'ZERO_TRUST_READY')).toEqual({
        name: 'ZERO_TRUST_READY', type: 'plain_text', text: 'true',
      });
    }
    expect(bootstrapBindings.find((binding) => binding.name === 'ANKKA_BOOTSTRAP_NONCE')).toEqual({
      name: 'ANKKA_BOOTSTRAP_NONCE',
      type: 'secret_text',
      text: 'bootstrap_nonce_value_that_is_never_returned',
    });
    expect(cleanBindings.some((binding) => binding.name === 'ANKKA_BOOTSTRAP_NONCE')).toBe(false);
    expect(JSON.stringify(clean.ephemeral)).not.toContain('bootstrap_nonce_value_that_is_never_returned');
    expect(bootstrap.recovery.phase).toBe('bootstrap');
    expect(clean.recovery.phase).toBe('clean');
    expect(bootstrap.recovery.correlationTag).toMatch(/^ankka-version-bootstrap-sha256:[a-f0-9]{64}$/u);
    expect(clean.recovery.correlationTag).toMatch(/^ankka-version-clean-sha256:[a-f0-9]{64}$/u);
    expect(bootstrap.recovery.correlationTag).not.toBe(clean.recovery.correlationTag);
    for (const recovery of [bootstrap.recovery, clean.recovery]) {
      expect(JSON.stringify(recovery)).not.toMatch(/jwt|nonce|token|secret/iu);
    }
    const notReadyInput = prepareInput(fixture.release);
    await expect(prepareVerifiedWorkerRelease({
      ...notReadyInput,
      plainTextBindings: { ...notReadyInput.plainTextBindings, ZERO_TRUST_READY: 'false' },
    })).rejects.toMatchObject({ code: 'invalid_input', stage: 'validate', outcome: 'not_sent' });
  });

  it('publishes through the stable direct script endpoint with exact multipart metadata', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const plan = await prepareWorkerVersionMutation(
      prepared,
      worker,
      COMPLETION_JWT,
      'bootstrap',
    );
    let metadata: BoundaryObject | null = null;
    let moduleText = '';
    const sequence = sequencedTransport([async (request) => {
      const form = await request.formData();
      const metadataPart = form.get('metadata');
      const modulePart = form.get('index.js');
      expect(metadataPart).toBeInstanceOf(File);
      expect(modulePart).toBeInstanceOf(File);
      if (!(metadataPart instanceof File) || !(modulePart instanceof File)) {
        throw new Error('direct script upload must carry File multipart parts');
      }
      metadata = v.parse(boundaryObjectSchema, JSON.parse(await metadataPart.text()));
      moduleText = await modulePart.text();
      return success({ id: VERSION_ID });
    }]);

    await expect(submitWorkerScriptMutation(
      plan.ephemeral,
      plan.recovery,
      call(sequence.transport),
    )).resolves.toEqual({
      kind: 'worker_script',
      phase: 'bootstrap',
      accountId: ACCOUNT_ID,
      workerName: WORKER_NAME,
      workerId: WORKER_ID,
      requestHash: plan.recovery.requestHash,
      correlationTag: plan.recovery.correlationTag,
    });

    const request = required(sequence.requests.at(0), 'direct script request');
    const url = new URL(request.url);
    expect(request.method).toBe('PUT');
    expect(url.pathname).toBe(`/client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${WORKER_NAME}`);
    expect(url.search).toBe('');
    expect(request.headers.get('authorization')).toBe(`Bearer ${ACCESS_TOKEN}`);
    expect(request.headers.get('content-type')).toMatch(/^multipart\/form-data; boundary=/u);
    expect(metadata).toMatchObject({
      annotations: {
        'workers/message': plan.recovery.correlationTag,
        'workers/tag': plan.recovery.correlationTag,
      },
      main_module: 'index.js',
      compatibility_date: '2026-08-08',
    });
    expect(metadata).not.toHaveProperty('modules');
    expect(moduleText).toContain('export class AdminState');
    expect(sequence.callCount()).toBe(1);
  });

  it('keeps recovery correlation stable across fresh asset credentials and bootstrap values', async () => {
    const fixture = await releaseFixture();
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const firstPrepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const earlyRecovery = await prepareWorkerVersionRecoveryRecord(
      firstPrepared,
      worker,
      'bootstrap',
    );
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
    const first = await prepareWorkerVersionMutation(firstPrepared, worker, COMPLETION_JWT, 'bootstrap');
    const refreshedBootstrapValue = 'refreshed_bootstrap_value_for_resumed_prepared_action';
    const refreshedPrepared = await prepareVerifiedWorkerRelease({
      ...prepareInput(fixture.release),
      bootstrapNonce: refreshedBootstrapValue,
    });
    const refreshedEarlyRecovery = await prepareWorkerVersionRecoveryRecord(
      refreshedPrepared,
      worker,
      'bootstrap',
    );
    const refreshed = await prepareWorkerVersionMutation(
      refreshedPrepared,
      worker,
      REFRESHED_COMPLETION_JWT,
      'bootstrap',
    );

    expect(earlyRecovery).toEqual(first.recovery);
    expect(refreshedEarlyRecovery).toEqual(refreshed.recovery);
    expect(refreshedEarlyRecovery).toEqual(earlyRecovery);
    expect(refreshed.recovery).toEqual(first.recovery);
    expect(refreshed.recovery.requestHash).toBe(first.recovery.requestHash);
    expect(refreshed.recovery.correlationTag).toBe(first.recovery.correlationTag);
    const firstBody = v.parse(versionSubmitBodySchema, first.ephemeral.body);
    const refreshedBody = v.parse(versionSubmitBodySchema, refreshed.ephemeral.body);
    expect(firstBody.assets.jwt).toBe(COMPLETION_JWT);
    expect(refreshedBody.assets.jwt).toBe(REFRESHED_COMPLETION_JWT);
    const refreshedBindings = refreshedBody.bindings;
    expect(refreshedBindings.find((binding) => binding.name === 'ANKKA_BOOTSTRAP_NONCE')?.text)
      .toBe(refreshedBootstrapValue);

    const sequence = sequencedTransport([() => success({ id: VERSION_ID }, 201)]);
    await expect(submitWorkerVersionMutation(
      refreshed.ephemeral,
      first.recovery,
      call(sequence.transport),
    )).resolves.toMatchObject({ kind: 'version', versionId: VERSION_ID });
    expect((await requestJson(required(sequence.requests.at(0), 'version submit request'), versionSubmitBodySchema)).assets).toMatchObject({
      jwt: REFRESHED_COMPLETION_JWT,
    });
    const serialized = JSON.stringify(first.recovery);
    expect(serialized).not.toMatch(/jwt|nonce|token|secret/iu);
    expect(serialized).not.toContain(COMPLETION_JWT);
    expect(serialized).not.toContain(REFRESHED_COMPLETION_JWT);
    expect(serialized).not.toContain(refreshedBootstrapValue);
    expect(JSON.stringify(first.ephemeral.semanticCommitment)).not.toMatch(/jwt|nonce|token|secret/iu);
    const parsedRecovery = await parseWorkerVersionRecoveryRecord(JSON.parse(serialized));
    if (!parsedRecovery) throw new Error('serialized recovery did not parse');
    expect(parsedRecovery).toEqual(first.recovery);
    expect(parsedRecovery).not.toBe(first.recovery);
    expect(Object.isFrozen(parsedRecovery)).toBe(true);
    expect(Object.isFrozen(parsedRecovery?.releaseContract.assetConfig)).toBe(true);
    expect(Object.isFrozen(parsedRecovery?.assets[0])).toBe(true);
    await expect(prepareWorkerVersionRecoveryRecord(
      firstPrepared,
      { ...worker, workerName: 'different-worker' },
      'bootstrap',
    )).rejects.toMatchObject({ code: 'invalid_input', stage: 'validate', outcome: 'not_sent' });
    expect(await parseWorkerVersionRecoveryRecord({
      ...parsedRecovery,
      requestHash: 'f'.repeat(64),
    })).toBeNull();
  });

  it('binds asset, module, binding, and phase semantics and rejects cross-plan submission', async () => {
    const fixture = await releaseFixture();
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const baselinePrepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const storedRecovery = await prepareWorkerVersionRecoveryRecord(
      baselinePrepared,
      worker,
      'bootstrap',
    );
    const baseline = await prepareWorkerVersionMutation(baselinePrepared, worker, COMPLETION_JWT, 'bootstrap');
    expect(baseline.recovery).toEqual(storedRecovery);

    const originalAsset = required(fixture.release.worker.assets.files.at(0), 'original asset');
    const changedAssetBytes = new TextEncoder().encode('<!doctype html><title>Changed gateway</title>');
    const assetDriftRelease: VerifiedWorkerDirectUploadRelease = {
      ...fixture.release,
      worker: {
        ...fixture.release.worker,
        assets: {
          ...fixture.release.worker.assets,
          files: [{
            ...originalAsset,
            sha256: await sha256(changedAssetBytes),
            bytes: changedAssetBytes,
          }, ...fixture.release.worker.assets.files.slice(1)],
        },
      },
    };
    const assetDrift = await prepareWorkerVersionMutation(
      await prepareVerifiedWorkerRelease(prepareInput(assetDriftRelease)),
      worker,
      COMPLETION_JWT,
      'bootstrap',
    );
    const moduleFixture = await releaseFixture(new TextEncoder().encode(
      'export class AdminState {}; export default { fetch() { return new Response("changed") } };',
    ));
    const moduleDrift = await prepareWorkerVersionMutation(
      await prepareVerifiedWorkerRelease(prepareInput(moduleFixture.release)),
      worker,
      COMPLETION_JWT,
      'bootstrap',
    );
    const bindingInput = prepareInput(fixture.release);
    const bindingDrift = await prepareWorkerVersionMutation(
      await prepareVerifiedWorkerRelease({
        ...bindingInput,
        plainTextBindings: { ...bindingInput.plainTextBindings, ADMIN_EMAILS: 'other@example.com' },
      }),
      worker,
      COMPLETION_JWT,
      'bootstrap',
    );
    const phaseDrift = await prepareWorkerVersionMutation(
      baselinePrepared,
      worker,
      COMPLETION_JWT,
      'clean',
    );

    for (const drift of [assetDrift, moduleDrift, bindingDrift, phaseDrift]) {
      expect(drift.recovery.requestHash).not.toBe(baseline.recovery.requestHash);
      expect(drift.recovery.correlationTag).not.toBe(baseline.recovery.correlationTag);
      const sequence = sequencedTransport([]);
      await expect(submitWorkerVersionMutation(
        drift.ephemeral,
        storedRecovery,
        call(sequence.transport),
      )).rejects.toMatchObject({ code: 'invalid_input', stage: 'validate', outcome: 'not_sent' });
      expect(sequence.callCount()).toBe(0);
    }

    const maskedAssetDrift = {
      ...assetDrift.ephemeral,
      requestHash: storedRecovery.requestHash,
      correlationTag: storedRecovery.correlationTag,
      body: {
        ...assetDrift.ephemeral.body,
        annotations: { 'workers/tag': storedRecovery.correlationTag },
      },
    };
    const maskedNoCall = sequencedTransport([]);
    await expect(submitWorkerVersionMutation(
      maskedAssetDrift,
      storedRecovery,
      call(maskedNoCall.transport),
    )).rejects.toMatchObject({ code: 'invalid_input', stage: 'validate', outcome: 'not_sent' });
    expect(maskedNoCall.callCount()).toBe(0);

    const contradictory: WorkerVersionRecoveryRecord = {
      ...baseline.recovery,
      assets: baseline.recovery.assets.map((asset, index) => (
        index === 0 ? { ...asset, byteLength: asset.byteLength + 1 } : asset
      )),
    };
    const noCall = sequencedTransport([]);
    await expect(submitWorkerVersionMutation(
      baseline.ephemeral,
      contradictory,
      call(noCall.transport),
    )).rejects.toMatchObject({ code: 'invalid_input', stage: 'validate', outcome: 'not_sent' });
    expect(noCall.callCount()).toBe(0);
  });

  it('exposes deterministic journalable intents before each asset POST', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const appHash = fixture.assetHashes['/app.js'];
    const indexHash = fixture.assetHashes['/index.html'];
    const sessionIntent = await prepareAssetUploadSessionMutation(prepared);
    const sessionTransport = sequencedTransport([
      () => success({ jwt: UPLOAD_JWT, buckets: [[appHash], [indexHash]] }),
    ]);
    const session = await submitAssetUploadSessionMutation(sessionIntent, call(sessionTransport.transport));
    expect(sessionIntent.requestHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(JSON.stringify(sessionIntent)).not.toContain(ACCESS_TOKEN);
    expect(JSON.stringify(sessionIntent)).not.toContain(UPLOAD_JWT);

    const firstIntent = await prepareAssetBucketMutation(session, 0);
    const firstTransport = sequencedTransport([() => success(null, 202)]);
    await expect(submitAssetBucketMutation(
      firstIntent,
      session,
      prepared,
      call(firstTransport.transport),
    )).resolves.toEqual({
      kind: 'asset_bucket', requestHash: firstIntent.requestHash, bucketIndex: 0, isFinal: false,
    });
    expect(JSON.stringify(firstIntent)).not.toContain(UPLOAD_JWT);

    const finalIntent = await prepareAssetBucketMutation(session, 1);
    const finalTransport = sequencedTransport([() => success({ jwt: COMPLETION_JWT }, 201)]);
    await expect(submitAssetBucketMutation(
      finalIntent,
      session,
      prepared,
      call(finalTransport.transport),
    )).resolves.toEqual({
      kind: 'asset_bucket',
      requestHash: finalIntent.requestHash,
      bucketIndex: 1,
      isFinal: true,
      completionJwt: COMPLETION_JWT,
    });
  });

  it('rejects a final asset bucket unless it is exact 201 with a completion JWT', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const sessionIntent = await prepareAssetUploadSessionMutation(prepared);
    const sessionTransport = sequencedTransport([
      () => success({ jwt: UPLOAD_JWT, buckets: [[fixture.assetHashes['/app.js']]] }),
    ]);
    const session = await submitAssetUploadSessionMutation(sessionIntent, call(sessionTransport.transport));
    const finalIntent = await prepareAssetBucketMutation(session, 0);

    for (const response of [success({ jwt: COMPLETION_JWT }, 202), success({}, 201)]) {
      const sequence = sequencedTransport([() => response]);
      const error = await directUploadError(submitAssetBucketMutation(
        finalIntent,
        session,
        prepared,
        call(sequence.transport),
      ));
      expect(error).toMatchObject({ stage: 'asset_bucket', outcome: 'unknown' });
      expect(sequence.callCount()).toBe(1);
    }
  });

  it.each([349 * 1024, 4 * 1024 * 1024])('accepts a %i-byte module without requiring POST or GET to echo module content', async (size) => {
    const moduleBytes = new Uint8Array(size);
    moduleBytes.fill(97);
    const fixture = await releaseFixture(moduleBytes);
    let tags: readonly string[] = [];
    let versionBody: VersionSubmitBody | undefined;
    let deploymentBody: DeploymentSubmitBody | undefined;
    const sequence = sequencedTransport([
      () => failure(404),
      async (request) => {
        tags = (await requestJson(request, workerMutationBodySchema)).tags;
        return success({ id: WORKER_ID }, 201);
      },
      () => success(workerState(tags)),
      () => success({ jwt: COMPLETION_JWT, buckets: [] }),
      async (request) => {
        versionBody = await requestJson(request, versionSubmitBodySchema);
        return success(versionResultFromBody(versionBody, { echoModuleContent: true }), 201);
      },
      () => success(versionResultFromBody(required(versionBody, 'version request body'))),
      async (request) => {
        deploymentBody = await requestJson(request, deploymentSubmitBodySchema);
        return success({ id: DEPLOYMENT_ID }, 201);
      },
      () => success(deploymentResultFromBody(required(deploymentBody, 'deployment request body'))),
    ]);

    await expect(__testOnlyDeployVerifiedWorkerRelease(input(fixture.release, sequence.transport))).resolves.toMatchObject({
      versionId: VERSION_ID, percentage: 100,
    });
    const submittedVersion = required(versionBody, 'version request body');
    expect(JSON.stringify(versionResultFromBody(submittedVersion, { echoModuleContent: true })).length)
      .toBeGreaterThan(128 * 1024);
    expect(versionResultFromBody(submittedVersion).modules[0])
      .not.toHaveProperty('content_base64');
  });

  it('preserves every provider ID before optional response validation and marks it submitted', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const workerIntent = await prepareWorkerMutation(prepared);
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const versionPlan = await prepareWorkerVersionMutation(prepared, worker, COMPLETION_JWT, 'bootstrap');
    const version: VersionSubmission = {
      kind: 'version', phase: 'bootstrap', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
      versionId: VERSION_ID,
      requestHash: versionPlan.recovery.requestHash,
      correlationTag: versionPlan.recovery.correlationTag,
    };
    const deploymentIntent = await prepareWorkerDeploymentMutation(version);

    interface SubmissionFailureCase {
      readonly kind: 'worker' | 'version' | 'deployment';
      readonly id: string;
      readonly status: number;
      invoke(transport: CloudflareDirectUploadTransport): Promise<object>;
    }
    const cases: readonly SubmissionFailureCase[] = [
      {
        kind: 'worker', id: WORKER_ID, status: 202,
        invoke: (transport: CloudflareDirectUploadTransport) => submitWorkerMutation(workerIntent, call(transport)),
      },
      {
        kind: 'version', id: VERSION_ID, status: 201,
        invoke: (transport: CloudflareDirectUploadTransport) => submitWorkerVersionMutation(
          versionPlan.ephemeral,
          versionPlan.recovery,
          call(transport),
        ),
      },
      {
        kind: 'deployment', id: DEPLOYMENT_ID, status: 201,
        invoke: (transport: CloudflareDirectUploadTransport) => submitWorkerDeploymentMutation(deploymentIntent, call(transport)),
      },
    ];
    for (const testCase of cases) {
      const sequence = sequencedTransport([() => Response.json({
        errors: [], messages: [], result: { id: testCase.id }, success: false,
      }, { status: testCase.status })]);
      const error = await directUploadError(testCase.invoke(sequence.transport));
      expect(error).toBeInstanceOf(CloudflareDirectUploadError);
      expect(error).toMatchObject({ outcome: 'submitted', canRetry: false });
      expect(error.submissions).toEqual([
        expect.objectContaining({ kind: testCase.kind, [`${testCase.kind}Id`]: testCase.id }),
      ]);
      expect(sequence.callCount()).toBe(1);
      expect(JSON.stringify(error)).not.toContain(ACCESS_TOKEN);
      expect(JSON.stringify(error)).not.toContain(COMPLETION_JWT);
      expect(JSON.stringify(error)).not.toContain('bootstrap_nonce_value_that_is_never_returned');
    }
  });

  it('recovers a Worker only from deterministic name plus exact full marker/state', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const intent = await prepareWorkerMutation(prepared);
    const exact = sequencedTransport([() => success(workerState(intent.body.tags))]);
    await expect(inspectWorkerRecovery(intent, call(exact.transport))).resolves.toEqual({
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    });
    const wrong = sequencedTransport([() => success(workerState(['ankka-mcp-gateway', 'wrong-marker']))]);
    const error = await directUploadError(inspectWorkerRecovery(intent, call(wrong.transport)));
    expect(error).toMatchObject({ code: 'worker_name_collision', stage: 'worker_recovery' });
    const unsafeObservability = sequencedTransport([() => success({
      ...workerState(intent.body.tags),
      observability: { enabled: false, redact_query_string: true },
    })]);
    await expect(inspectWorkerRecovery(intent, call(unsafeObservability.transport)))
      .rejects.toMatchObject({ code: 'worker_name_collision', stage: 'worker_recovery' });
  });

  it('accepts the documented beta Worker subdomain metadata and rejects unsafe variants', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const intent = await prepareWorkerMutation(prepared);
    const submission: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const current = workerState(intent.body.tags);
    const currentProvider = sequencedTransport([() => success(current)]);
    await expect(verifyWorkerSubmission(intent, submission, call(currentProvider.transport)))
      .resolves.toEqual(submission);

    const legacyProvider = sequencedTransport([() => success({
      ...current,
      subdomain: { enabled: false, previews_enabled: false },
    })]);
    await expect(verifyWorkerSubmission(intent, submission, call(legacyProvider.transport)))
      .resolves.toEqual(submission);

    const invalidSubdomains: readonly object[] = [
      { ...current.subdomain, enabled: true },
      { ...current.subdomain, previews_enabled: true },
      { enabled: false, previews_enabled: false, url: current.subdomain.url },
      { ...current.subdomain, url: `http://${WORKER_SUBDOMAIN_HOSTNAME}` },
      { ...current.subdomain, url: `https://user@${WORKER_SUBDOMAIN_HOSTNAME}` },
      { ...current.subdomain, url: `https://${WORKER_SUBDOMAIN_HOSTNAME}?next=1` },
      { ...current.subdomain, preview_url_suffix: '-different-worker.example-account.workers.dev' },
      { ...current.subdomain, unexpected: true },
      { ...current.subdomain, url: 42 },
    ];
    for (const subdomain of invalidSubdomains) {
      const provider = sequencedTransport([() => success({ ...current, subdomain })]);
      await expect(verifyWorkerSubmission(intent, submission, call(provider.transport))).rejects.toMatchObject({
        code: 'provider_mismatch', stage: 'worker_verify', outcome: 'submitted',
      });
    }
  });

  it('accepts only a provider identifier as optional converged Custom Domain certificate metadata', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const intent = await prepareWorkerMutation(prepared);
    const submission: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const converged = {
      domain: {
        id: 'd'.repeat(32),
        hostname: 'gateway.example.com',
        zoneId: 'c'.repeat(32),
        zoneName: 'example.com',
      },
      namespaceId: NAMESPACE_ID,
    };
    const convergedState = (certificateId?: string) => {
      const baseDomain = {
        id: converged.domain.id,
        hostname: converged.domain.hostname,
        zone_id: converged.domain.zoneId,
        zone_name: converged.domain.zoneName,
      };
      const domain = certificateId === undefined
        ? baseDomain
        : { ...baseDomain, certificate_id: certificateId };
      return {
        ...workerState(intent.body.tags),
        deployed_on: CREATED_ON,
        references: {
          dispatch_namespace_outbounds: [],
          domains: [domain],
          durable_objects: [{
            worker_id: WORKER_ID,
            worker_name: WORKER_NAME,
            namespace_id: NAMESPACE_ID,
            namespace_name: `${WORKER_NAME}_AdminState`,
          }],
          queues: [],
          workers: [],
        },
      };
    };
    for (const certificateId of [undefined, 'f'.repeat(32), VERSION_ID]) {
      const provider = sequencedTransport([() => success(convergedState(certificateId))]);
      await expect(verifyWorkerSubmission(intent, submission, call(provider.transport), converged))
        .resolves.toEqual(submission);
    }
    for (const certificateId of ['', 'not-a-provider-id', 'f'.repeat(40)]) {
      const provider = sequencedTransport([() => success(convergedState(certificateId))]);
      await expect(verifyWorkerSubmission(intent, submission, call(provider.transport), converged))
        .rejects.toMatchObject({ code: 'provider_mismatch', stage: 'worker_verify' });
    }
  });

  it('fully paginates and binds exactly one complete sqlite AdminState namespace', async () => {
    const firstPage = Array.from({ length: 1_000 }, (_value, index) => (
      namespaceItem(index.toString(16).padStart(32, '0'))
    ));
    const sequence = sequencedTransport([
      () => namespacePage(firstPage, 1, 1_001),
      () => namespacePage([namespaceItem(NAMESPACE_ID, {
        class: 'AdminState', name: 'admin-state-namespace', script: WORKER_NAME, use_sqlite: true,
      })], 2, 1_001),
    ]);
    await expect(inspectAdminStateDurableObjectNamespace({
      accountId: ACCOUNT_ID,
      workerName: WORKER_NAME,
      className: 'AdminState',
      storage: 'sqlite',
      expectedNamespaceId: NAMESPACE_ID,
    }, call(sequence.transport))).resolves.toEqual({
      accountId: ACCOUNT_ID,
      namespaceId: NAMESPACE_ID,
      namespaceName: 'admin-state-namespace',
      workerName: WORKER_NAME,
      className: 'AdminState',
      storage: 'sqlite',
    });
    expect(sequence.requests.map((request) => new URL(request.url).search)).toEqual([
      '?page=1&per_page=1000', '?page=2&per_page=1000',
    ]);
  });

  it('rejects partial, duplicate, ambiguous, legacy, and mismatched namespace evidence', async () => {
    const exact = namespaceItem(NAMESPACE_ID, {
      class: 'AdminState', name: 'admin-state-namespace', script: WORKER_NAME, use_sqlite: true,
    });
    const cases: Array<{ value: readonly object[]; code: string; expected?: string }> = [
      { value: [{ id: NAMESPACE_ID, class: 'AdminState', name: 'partial', script: WORKER_NAME }], code: 'provider_mismatch' },
      { value: [exact, exact], code: 'recovery_ambiguous' },
      { value: [exact, namespaceItem('f'.repeat(32), { class: 'AdminState', name: 'second', script: WORKER_NAME })], code: 'recovery_ambiguous' },
      { value: [namespaceItem(NAMESPACE_ID, { class: 'AdminState', name: 'legacy', script: WORKER_NAME, use_sqlite: false })], code: 'provider_mismatch' },
      { value: [exact], code: 'provider_mismatch', expected: 'f'.repeat(32) },
    ];
    for (const testCase of cases) {
      const transport = sequencedTransport([() => namespacePage(testCase.value, 1, testCase.value.length)]);
      const error = await directUploadError(inspectAdminStateDurableObjectNamespace({
        accountId: ACCOUNT_ID,
        workerName: WORKER_NAME,
        className: 'AdminState',
        storage: 'sqlite',
        expectedNamespaceId: testCase.expected ?? NAMESPACE_ID,
      }, call(transport.transport)));
      expect(error).toMatchObject({ code: testCase.code, stage: 'namespace_verify', outcome: 'unknown' });
    }
  });

  it('fully paginates version recovery and accepts exactly one full immutable match', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const plan = await prepareWorkerVersionMutation(prepared, worker, COMPLETION_JWT, 'bootstrap');
    const serializedRecovery = JSON.stringify(plan.recovery);
    expect(serializedRecovery).not.toMatch(/jwt|nonce|token|secret/iu);
    expect(serializedRecovery).not.toContain(COMPLETION_JWT);
    expect(serializedRecovery).not.toContain('bootstrap_nonce_value_that_is_never_returned');
    const recovery = await recoveryClone(plan.recovery);
    const sequence = sequencedTransport([
      () => listPage([{ id: OTHER_VERSION_ID, annotations: { 'workers/tag': 'unrelated' } }], 1, 2),
      () => listPage([{ id: VERSION_ID, annotations: { 'workers/tag': recovery.correlationTag } }], 2, 2),
      () => success(versionResultFromBody(plan.ephemeral.body, { versionId: VERSION_ID })),
    ]);
    await expect(inspectWorkerVersionRecovery(recovery, call(sequence.transport))).resolves.toMatchObject({
      kind: 'version', versionId: VERSION_ID, requestHash: recovery.requestHash,
    });
    expect(sequence.requests.slice(0, 2).map((request) => new URL(request.url).search)).toEqual([
      '?page=1&per_page=1', '?page=2&per_page=1',
    ]);
  });

  it('verifies after a crash using only the journal-safe record and safe submission', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const plan = await prepareWorkerVersionMutation(prepared, worker, COMPLETION_JWT, 'bootstrap');
    const providerVersion = versionResultFromBody(plan.ephemeral.body, { echoModuleContent: true });
    const submitTransport = sequencedTransport([() => success({ id: VERSION_ID }, 201)]);
    const submission = await submitWorkerVersionMutation(
      plan.ephemeral,
      plan.recovery,
      call(submitTransport.transport),
    );

    const journalRecord: CloudflareDirectUploadJournalRecord = plan.recovery;
    const journalSubmission: CloudflareDirectUploadJournalRecord = submission;
    const persistedRecord = JSON.stringify(journalRecord);
    const persistedSubmission = JSON.stringify(journalSubmission);
    for (const serialized of [persistedRecord, persistedSubmission]) {
      expect(serialized).not.toMatch(/jwt|nonce|token|secret/iu);
      expect(serialized).not.toContain(COMPLETION_JWT);
      expect(serialized).not.toContain('bootstrap_nonce_value_that_is_never_returned');
    }
    const restartedRecord = await recoveryClone(plan.recovery);
    const restartedSubmission = v.parse(versionSubmissionSchema, JSON.parse(persistedSubmission));
    const verifyTransport = sequencedTransport([() => success(providerVersion)]);
    await expect(verifyWorkerVersionSubmission(
      restartedRecord,
      restartedSubmission,
      call(verifyTransport.transport),
    )).resolves.toEqual(restartedSubmission);
  });

  it('rejects the retired management binding from clean versions and recovery records', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const plan = await prepareWorkerVersionMutation(prepared, worker, COMPLETION_JWT, 'clean');
    expect(plan.ephemeral.body.bindings).not.toContainEqual(expect.objectContaining({
      name: 'ANKKA_TEAM_MANAGEMENT_TOKEN',
    }));
    expect(JSON.stringify(plan.recovery)).not.toMatch(/jwt|nonce|token|secret/iu);
    expect(await recoveryClone(plan.recovery)).toEqual(plan.recovery);
    expect(await parseWorkerVersionRecoveryRecord({
      ...plan.recovery,
      releaseContract: { ...plan.recovery.releaseContract, teamManagementBinding: { fromVersionId: VERSION_ID } },
    })).toBeNull();
    const wrongBindingTransport = sequencedTransport([]);
    const body = v.parse(versionSubmitBodySchema, plan.ephemeral.body);
    const credentialWrite = {
      ...plan.ephemeral,
      body: { ...body, bindings: [...body.bindings, {
        name: 'ANKKA_TEAM_MANAGEMENT_TOKEN', type: 'inherit', version_id: OTHER_VERSION_ID,
      }] },
    };
    await expect(submitWorkerVersionMutation(credentialWrite, plan.recovery, call(wrongBindingTransport.transport))).rejects.toThrow();
    expect(wrongBindingTransport.requests).toHaveLength(0);
  });

  it('rejects a contradictory optional version namespace_id against the list-bound ID', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const plan = await prepareWorkerVersionMutation(prepared, worker, COMPLETION_JWT, 'bootstrap');
    const returnedVersion = versionResultFromBody(plan.ephemeral.body);
    const returned = {
      ...returnedVersion,
      bindings: returnedVersion.bindings.map((binding) => binding.name === 'ADMIN_STATE'
        ? { ...binding, namespace_id: 'f'.repeat(32) }
        : binding),
    };
    const submission: VersionSubmission = {
      kind: 'version', phase: 'bootstrap', accountId: ACCOUNT_ID, workerName: WORKER_NAME,
      workerId: WORKER_ID, versionId: VERSION_ID, requestHash: plan.recovery.requestHash,
      correlationTag: plan.recovery.correlationTag,
    };
    const sequence = sequencedTransport([() => success(returned)]);
    await expect(verifyWorkerVersionSubmission(
      plan.recovery,
      submission,
      call(sequence.transport),
      NAMESPACE_ID,
    )).rejects.toMatchObject({ code: 'provider_mismatch', stage: 'version_verify', outcome: 'submitted' });
  });

  it('recovers a lost clean-version response using only its phase-bound safe record', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const plan = await prepareWorkerVersionMutation(prepared, worker, COMPLETION_JWT, 'clean');
    const recovery = await recoveryClone(plan.recovery);
    const providerVersion = versionResultFromBody(plan.ephemeral.body);
    const sequence = sequencedTransport([
      () => listPage([{ id: VERSION_ID, annotations: { 'workers/tag': recovery.correlationTag } }], 1, 1),
      () => success(providerVersion),
    ]);
    await expect(inspectWorkerVersionRecovery(recovery, call(sequence.transport))).resolves.toMatchObject({
      kind: 'version', phase: 'clean', versionId: VERSION_ID, requestHash: recovery.requestHash,
    });
    expect(JSON.stringify(recovery)).not.toMatch(/jwt|nonce|token|secret/iu);
  });

  it('never accepts a nonce binding in a clean version verification', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const plan = await prepareWorkerVersionMutation(prepared, worker, COMPLETION_JWT, 'clean');
    const returnedVersion = versionResultFromBody(plan.ephemeral.body);
    const returned = {
      ...returnedVersion,
      bindings: [
        ...returnedVersion.bindings,
        { name: 'ANKKA_BOOTSTRAP_NONCE', type: 'secret_text' },
      ],
    };
    const submission: VersionSubmission = {
      kind: 'version',
      phase: 'clean',
      accountId: ACCOUNT_ID,
      workerName: WORKER_NAME,
      workerId: WORKER_ID,
      versionId: VERSION_ID,
      requestHash: plan.recovery.requestHash,
      correlationTag: plan.recovery.correlationTag,
    };
    const recovery = await recoveryClone(plan.recovery);
    const sequence = sequencedTransport([() => success(returned)]);
    const error = await directUploadError(
      verifyWorkerVersionSubmission(recovery, submission, call(sequence.transport)),
    );
    expect(error).toMatchObject({ code: 'provider_mismatch', stage: 'version_verify', outcome: 'submitted' });
    expect(error.submissions).toEqual([submission]);
  });

  it('rejects contradictory returned module content even when metadata and tag match', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const plan = await prepareWorkerVersionMutation(prepared, worker, COMPLETION_JWT, 'bootstrap');
    const returnedVersion = versionResultFromBody(plan.ephemeral.body, { echoModuleContent: true });
    const contradictoryBytes = Uint8Array.from(atob(fixture.moduleBase64), (character) => character.charCodeAt(0));
    const firstByte = required(contradictoryBytes.at(0), 'contradictory module byte');
    contradictoryBytes[0] = firstByte ^ 1;
    const returned = {
      ...returnedVersion,
      modules: returnedVersion.modules.map((module, index) => index === 0
        ? { ...module, content_base64: base64(contradictoryBytes) }
        : module),
    };
    const submission: VersionSubmission = {
      kind: 'version',
      phase: 'bootstrap',
      accountId: ACCOUNT_ID,
      workerName: WORKER_NAME,
      workerId: WORKER_ID,
      versionId: VERSION_ID,
      requestHash: plan.recovery.requestHash,
      correlationTag: plan.recovery.correlationTag,
    };
    const recovery = await recoveryClone(plan.recovery);
    const sequence = sequencedTransport([() => success(returned)]);
    const error = await directUploadError(
      verifyWorkerVersionSubmission(recovery, submission, call(sequence.transport)),
    );
    expect(error).toMatchObject({ code: 'provider_mismatch', stage: 'version_verify', outcome: 'submitted' });
    expect(error.submissions).toEqual([submission]);
    expect(JSON.stringify(error)).not.toContain(COMPLETION_JWT);
    expect(JSON.stringify(error)).not.toContain('bootstrap_nonce_value_that_is_never_returned');
  });

  it('rejects ambiguous version recovery without guessing or replaying', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const plan = await prepareWorkerVersionMutation(prepared, worker, COMPLETION_JWT, 'bootstrap');
    const recovery = await recoveryClone(plan.recovery);
    const sequence = sequencedTransport([
      () => listPage([{ id: VERSION_ID, annotations: { 'workers/tag': recovery.correlationTag } }], 1, 2),
      () => listPage([{ id: OTHER_VERSION_ID, annotations: { 'workers/tag': recovery.correlationTag } }], 2, 2),
    ]);
    const error = await directUploadError(inspectWorkerVersionRecovery(recovery, call(sequence.transport)));
    expect(error).toMatchObject({ code: 'recovery_ambiguous', stage: 'version_recovery', outcome: 'unknown' });
    expect(sequence.callCount()).toBe(2);
  });

  it('rejects duplicate version IDs across recovery pages even when the duplicate is unrelated', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const plan = await prepareWorkerVersionMutation(prepared, worker, COMPLETION_JWT, 'bootstrap');
    const recovery = await recoveryClone(plan.recovery);
    const sequence = sequencedTransport([
      () => listPage([{ id: OTHER_VERSION_ID, annotations: { 'workers/tag': 'unrelated' } }], 1, 2),
      () => listPage([{ id: OTHER_VERSION_ID, annotations: { 'workers/tag': 'still-unrelated' } }], 2, 2),
    ]);
    const error = await directUploadError(inspectWorkerVersionRecovery(recovery, call(sequence.transport)));
    expect(error).toMatchObject({ code: 'provider_mismatch', stage: 'version_recovery', outcome: 'unknown' });
    expect(sequence.callCount()).toBe(2);
  });

  it('recovers exactly one deployment matching correlation, version, and 100% distribution', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const versionPlan = await prepareWorkerVersionMutation(prepared, worker, COMPLETION_JWT, 'bootstrap');
    const version: VersionSubmission = {
      kind: 'version', phase: 'bootstrap', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
      versionId: VERSION_ID,
      requestHash: versionPlan.recovery.requestHash,
      correlationTag: versionPlan.recovery.correlationTag,
    };
    const intent = await prepareWorkerDeploymentMutation(version);
    const matching = deploymentResultFromBody(intent.body);
    const sequence = sequencedTransport([
      () => success({ deployments: [
        deploymentResultFromBody({
          annotations: { 'workers/message': 'unrelated' },
          strategy: 'percentage',
          versions: [{ percentage: 100, version_id: OTHER_VERSION_ID }],
        }, OTHER_DEPLOYMENT_ID),
        matching,
      ] }),
      () => success(matching),
    ]);
    await expect(inspectWorkerDeploymentRecovery(intent, call(sequence.transport))).resolves.toMatchObject({
      kind: 'deployment', deploymentId: DEPLOYMENT_ID, versionId: VERSION_ID,
    });
    const ambiguous = sequencedTransport([() => success({ deployments: [
      matching, deploymentResultFromBody(intent.body, OTHER_DEPLOYMENT_ID),
    ] })]);
    const error = await directUploadError(inspectWorkerDeploymentRecovery(intent, call(ambiguous.transport)));
    expect(error).toMatchObject({ code: 'recovery_ambiguous', stage: 'deployment_recovery' });
    expect(ambiguous.callCount()).toBe(1);
  });

  it('proves item zero is the exact actively serving clean deployment', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const versionPlan = await prepareWorkerVersionMutation(prepared, worker, COMPLETION_JWT, 'clean');
    const version: VersionSubmission = {
      kind: 'version', phase: 'clean', accountId: ACCOUNT_ID, workerName: WORKER_NAME,
      workerId: WORKER_ID, versionId: VERSION_ID,
      requestHash: versionPlan.recovery.requestHash,
      correlationTag: versionPlan.recovery.correlationTag,
    };
    const intent = await prepareWorkerDeploymentMutation(version);
    const submission = {
      kind: 'deployment' as const,
      phase: 'clean' as const,
      accountId: ACCOUNT_ID,
      workerName: WORKER_NAME,
      workerId: WORKER_ID,
      versionId: VERSION_ID,
      deploymentId: DEPLOYMENT_ID,
      requestHash: intent.requestHash,
      correlationTag: intent.correlationTag,
    };
    const current = deploymentResultFromBody(intent.body, DEPLOYMENT_ID);
    const foreign = deploymentResultFromBody({
      annotations: { 'workers/message': 'unrelated' },
      strategy: 'percentage',
      versions: [{ percentage: 100, version_id: OTHER_VERSION_ID }],
    }, OTHER_DEPLOYMENT_ID);
    const sequence = sequencedTransport([() => success({ deployments: [current, foreign] })]);

    await expect(verifyActiveWorkerDeployment(intent, submission, call(sequence.transport)))
      .resolves.toEqual(submission);
    expect(sequence.callCount()).toBe(1);
    const deploymentRequest = required(sequence.requests.at(0), 'deployment request');
    expect(deploymentRequest.method).toBe('GET');
    const requestUrl = new URL(deploymentRequest.url);
    expect(requestUrl.pathname).toBe(
      `/client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${WORKER_NAME}/deployments`,
    );
    expect(requestUrl.search).toBe('');
  });

  it.each(['bootstrap', 'clean'] as const)(
    'discovers and proves the exact active %s version from its release-and-binding commitment',
    async (phase) => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const versionPlan = await prepareWorkerVersionMutation(prepared, worker, COMPLETION_JWT, phase);
    const version: VersionSubmission = {
      kind: 'version', phase, accountId: ACCOUNT_ID, workerName: WORKER_NAME,
      workerId: WORKER_ID, versionId: VERSION_ID,
      requestHash: versionPlan.recovery.requestHash,
      correlationTag: versionPlan.recovery.correlationTag,
    };
    const deploymentIntent = await prepareWorkerDeploymentMutation(version);
    const active = deploymentResultFromBody(deploymentIntent.body);
    const sequence = sequencedTransport([
      () => success({ deployments: [active] }),
      () => success(versionResultFromBody(versionPlan.ephemeral.body, { echoModuleContent: true })),
      () => success({ deployments: [active] }),
    ]);

    await expect(proveActiveWorkerVersionRecovery(
      versionPlan.recovery,
      call(sequence.transport),
      NAMESPACE_ID,
    )).resolves.toEqual({
      version,
      deployment: {
        kind: 'deployment', phase, accountId: ACCOUNT_ID, workerName: WORKER_NAME,
        workerId: WORKER_ID, versionId: VERSION_ID, deploymentId: DEPLOYMENT_ID,
        requestHash: deploymentIntent.requestHash,
        correlationTag: deploymentIntent.correlationTag,
      },
    });
    expect(sequence.requests.map((request) => new URL(request.url).pathname)).toEqual([
      `/client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${WORKER_NAME}/deployments`,
      `/client/v4/accounts/${ACCOUNT_ID}/workers/workers/${WORKER_ID}/versions/${VERSION_ID}`,
      `/client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${WORKER_NAME}/deployments`,
    ]);
    },
  );

  it('rejects changed release bindings even when the active module bytes and expected tag are unchanged', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const versionPlan = await prepareWorkerVersionMutation(prepared, worker, COMPLETION_JWT, 'clean');
    const version: VersionSubmission = {
      kind: 'version', phase: 'clean', accountId: ACCOUNT_ID, workerName: WORKER_NAME,
      workerId: WORKER_ID, versionId: VERSION_ID,
      requestHash: versionPlan.recovery.requestHash,
      correlationTag: versionPlan.recovery.correlationTag,
    };
    const deploymentIntent = await prepareWorkerDeploymentMutation(version);
    const active = deploymentResultFromBody(deploymentIntent.body);
    const providerVersion = versionResultFromBody(versionPlan.ephemeral.body, { echoModuleContent: true });
    const changed = {
      ...providerVersion,
      bindings: providerVersion.bindings.map((binding) => binding.name === 'ANKKA_GATEWAY_RELEASE'
        ? { ...binding, text: 'gateway-v1.2.4' }
        : binding),
    };
    const sequence = sequencedTransport([
      () => success({ deployments: [active] }),
      () => success(changed),
    ]);

    await expect(proveActiveWorkerVersionRecovery(
      versionPlan.recovery,
      call(sequence.transport),
      NAMESPACE_ID,
    )).rejects.toMatchObject({
      code: 'provider_mismatch', stage: 'version_verify', outcome: 'submitted',
    });
    expect(sequence.callCount()).toBe(2);
    expect(JSON.stringify(sequence.requests)).not.toContain(ACCESS_TOKEN);
  });

  it('rejects an active version that omits module bytes despite matching tags, bindings, and metadata', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const versionPlan = await prepareWorkerVersionMutation(prepared, worker, COMPLETION_JWT, 'clean');
    const version: VersionSubmission = {
      kind: 'version', phase: 'clean', accountId: ACCOUNT_ID, workerName: WORKER_NAME,
      workerId: WORKER_ID, versionId: VERSION_ID,
      requestHash: versionPlan.recovery.requestHash,
      correlationTag: versionPlan.recovery.correlationTag,
    };
    const deploymentIntent = await prepareWorkerDeploymentMutation(version);
    const active = deploymentResultFromBody(deploymentIntent.body);
    const sequence = sequencedTransport([
      () => success({ deployments: [active] }),
      // The ordinary install verifier tolerates this observed provider shape;
      // returning uninstall's authority proof deliberately does not.
      () => success(versionResultFromBody(versionPlan.ephemeral.body)),
    ]);

    await expect(proveActiveWorkerVersionRecovery(
      versionPlan.recovery,
      call(sequence.transport),
      NAMESPACE_ID,
    )).rejects.toMatchObject({
      code: 'provider_mismatch', stage: 'version_verify', outcome: 'submitted',
    });
    expect(sequence.callCount()).toBe(2);
  });

  it('rejects missing, duplicate, ambiguous, paginated, and foreign-current deployment lists', async () => {
    const fixture = await releaseFixture();
    const prepared = await prepareVerifiedWorkerRelease(prepareInput(fixture.release));
    const worker: WorkerSubmission = {
      kind: 'worker', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    };
    const versionPlan = await prepareWorkerVersionMutation(prepared, worker, COMPLETION_JWT, 'clean');
    const version: VersionSubmission = {
      kind: 'version', phase: 'clean', accountId: ACCOUNT_ID, workerName: WORKER_NAME,
      workerId: WORKER_ID, versionId: VERSION_ID,
      requestHash: versionPlan.recovery.requestHash,
      correlationTag: versionPlan.recovery.correlationTag,
    };
    const intent = await prepareWorkerDeploymentMutation(version);
    const submission = {
      kind: 'deployment' as const,
      phase: 'clean' as const,
      accountId: ACCOUNT_ID,
      workerName: WORKER_NAME,
      workerId: WORKER_ID,
      versionId: VERSION_ID,
      deploymentId: DEPLOYMENT_ID,
      requestHash: intent.requestHash,
      correlationTag: intent.correlationTag,
    };
    const current = deploymentResultFromBody(intent.body, DEPLOYMENT_ID);
    const sameTagOtherId = deploymentResultFromBody(intent.body, OTHER_DEPLOYMENT_ID);
    const foreign = deploymentResultFromBody({
      annotations: { 'workers/message': 'unrelated' },
      strategy: 'percentage',
      versions: [{ percentage: 100, version_id: OTHER_VERSION_ID }],
    }, OTHER_DEPLOYMENT_ID);
    const wrongVersionCurrent = deploymentResultFromBody({
      ...intent.body,
      versions: [{ percentage: 100, version_id: OTHER_VERSION_ID }],
    }, DEPLOYMENT_ID);
    const paginated = Response.json({
      errors: [],
      messages: [],
      result: { deployments: [current] },
      result_info: { count: 1, page: 1, per_page: 1, total_count: 2, total_pages: 2 },
      success: true,
    });
    const cases = [
      { label: 'missing', response: success({ deployments: [] }), code: 'provider_mismatch' },
      { label: 'duplicate', response: success({ deployments: [current, current] }), code: 'provider_mismatch' },
      { label: 'ambiguous', response: success({ deployments: [current, sameTagOtherId] }), code: 'recovery_ambiguous' },
      { label: 'paginated', response: paginated, code: 'provider_mismatch' },
      { label: 'foreign-current', response: success({ deployments: [foreign, current] }), code: 'provider_mismatch' },
      { label: 'wrong-version', response: success({ deployments: [wrongVersionCurrent] }), code: 'provider_mismatch' },
    ] as const;
    for (const testCase of cases) {
      const sequence = sequencedTransport([() => testCase.response.clone()]);
      const error = await directUploadError(verifyActiveWorkerDeployment(
        intent,
        submission,
        call(sequence.transport),
      ));
      expect(error, testCase.label).toBeInstanceOf(CloudflareDirectUploadError);
      expect(error, testCase.label).toMatchObject({
        code: testCase.code,
        stage: 'deployment_active_verify',
        outcome: 'submitted',
        submissions: [submission],
      });
      expect(sequence.callCount(), testCase.label).toBe(1);
      expect(JSON.stringify(error)).not.toContain(ACCESS_TOKEN);
    }

    const provisionPlan = await prepareWorkerVersionMutation(
      prepared,
      worker,
      null,
      'provision',
    );
    const provisionVersion: VersionSubmission = {
      ...version,
      phase: 'provision',
      requestHash: provisionPlan.recovery.requestHash,
      correlationTag: provisionPlan.recovery.correlationTag,
    };
    const provisionIntent = await prepareWorkerDeploymentMutation(provisionVersion);
    const noCall = sequencedTransport([]);
    await expect(verifyActiveWorkerDeployment(
      provisionIntent,
      { ...submission, phase: 'provision', requestHash: provisionIntent.requestHash,
        correlationTag: provisionIntent.correlationTag },
      call(noCall.transport),
    )).rejects.toMatchObject({ code: 'invalid_input', stage: 'validate', outcome: 'not_sent' });
    expect(noCall.callCount()).toBe(0);
  });

  it.each([
    ['unknown hash', (known: string) => [['f'.repeat(32), known]]],
    ['duplicate hash', (known: string) => [[known], [known]]],
  ])('rejects %s assets without uploading or assuming replay safety', async (_label, buckets) => {
    const fixture = await releaseFixture();
    let tags: readonly string[] = [];
    const known = required(fixture.assetHashes['/app.js'], 'app asset hash');
    const sequence = sequencedTransport([
      () => failure(404),
      async (request) => {
        tags = (await requestJson(request, workerMutationBodySchema)).tags;
        return success({ id: WORKER_ID }, 201);
      },
      () => success(workerState(tags)),
      () => success({ jwt: UPLOAD_JWT, buckets: buckets(known) }),
    ]);
    const error = await directUploadError(
      __testOnlyDeployVerifiedWorkerRelease(input(fixture.release, sequence.transport)),
    );
    expect(error).toMatchObject({
      code: 'provider_mismatch', stage: 'asset_session', outcome: 'unknown', canRetry: false,
    });
    expect(sequence.callCount()).toBe(4);
  });

  it('preserves a partial-bucket unknown outcome and safe locators, with no replay', async () => {
    const fixture = await releaseFixture();
    const hashes = [fixture.assetHashes['/app.js'], fixture.assetHashes['/index.html']];
    let tags: readonly string[] = [];
    const sequence = sequencedTransport([
      () => failure(404),
      async (request) => {
        tags = (await requestJson(request, workerMutationBodySchema)).tags;
        return success({ id: WORKER_ID }, 201);
      },
      () => success(workerState(tags)),
      () => success({ jwt: UPLOAD_JWT, buckets: [[hashes[0]], [hashes[1]]] }),
      () => success(null, 202),
      () => { throw new Error('sensitive provider body must not escape'); },
    ]);
    const error = await directUploadError(
      __testOnlyDeployVerifiedWorkerRelease(input(fixture.release, sequence.transport)),
    );
    expect(error).toBeInstanceOf(CloudflareDirectUploadError);
    expect(error).toMatchObject({
      code: 'provider_unknown', stage: 'asset_bucket', outcome: 'unknown',
      progress: { assetBucketsCompleted: 1, assetBucketCount: 2 },
    });
    expect(error.submissions).toEqual([
      expect.objectContaining({ kind: 'worker', workerId: WORKER_ID }),
    ]);
    expect(sequence.callCount()).toBe(6);
    expect(String(error)).not.toContain('sensitive provider body');
    expect(JSON.stringify(error)).not.toContain(UPLOAD_JWT);
    expect(JSON.stringify(error)).not.toContain(ACCESS_TOKEN);
  });

  it('rejects mismatched version/deployment reads while preserving submitted locators', async () => {
    const fixture = await releaseFixture();
    let tags: readonly string[] = [];
    let versionBody: VersionSubmitBody | undefined;
    const versionMismatch = sequencedTransport([
      () => failure(404),
      async (request) => {
        tags = (await requestJson(request, workerMutationBodySchema)).tags;
        return success({ id: WORKER_ID }, 201);
      },
      () => success(workerState(tags)),
      () => success({ jwt: COMPLETION_JWT, buckets: [] }),
      async (request) => {
        versionBody = await requestJson(request, versionSubmitBodySchema);
        return success({ id: VERSION_ID }, 201);
      },
      () => success({
        ...versionResultFromBody(required(versionBody, 'version request body')),
        main_module: 'other.js',
      }),
    ]);
    const versionError = await directUploadError(__testOnlyDeployVerifiedWorkerRelease(
      input(fixture.release, versionMismatch.transport),
    ));
    expect(versionError).toMatchObject({ code: 'provider_mismatch', stage: 'version_verify', outcome: 'submitted' });
    expect(versionError.submissions).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: 'version', versionId: VERSION_ID }),
    ]));

    let deploymentBody: DeploymentSubmitBody | undefined;
    const deploymentMismatch = sequencedTransport([
      () => failure(404),
      async (request) => {
        tags = (await requestJson(request, workerMutationBodySchema)).tags;
        return success({ id: WORKER_ID }, 201);
      },
      () => success(workerState(tags)),
      () => success({ jwt: COMPLETION_JWT, buckets: [] }),
      async (request) => {
        versionBody = await requestJson(request, versionSubmitBodySchema);
        return success({ id: VERSION_ID }, 201);
      },
      () => success(versionResultFromBody(required(versionBody, 'version request body'))),
      async (request) => {
        deploymentBody = await requestJson(request, deploymentSubmitBodySchema);
        return success({ id: DEPLOYMENT_ID }, 201);
      },
      () => success({
        ...deploymentResultFromBody(required(deploymentBody, 'deployment request body')),
        versions: [{ percentage: 50, version_id: OTHER_VERSION_ID }],
      }),
    ]);
    const deploymentError = await directUploadError(__testOnlyDeployVerifiedWorkerRelease(
      input(fixture.release, deploymentMismatch.transport),
    ));
    expect(deploymentError).toMatchObject({
      code: 'provider_mismatch', stage: 'deployment_verify', outcome: 'submitted',
    });
    expect(deploymentError.submissions).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: 'deployment', deploymentId: DEPLOYMENT_ID }),
    ]));
  });

  it('bounds responses and times out once without exposing token or provider body', async () => {
    const fixture = await releaseFixture();
    const oversized = sequencedTransport([() => new Response('{}', {
      status: 404,
      headers: { 'content-type': 'application/json', 'content-length': String(128 * 1024 + 1) },
    })]);
    const oversizedError = await directUploadError(__testOnlyDeployVerifiedWorkerRelease(
      input(fixture.release, oversized.transport),
    ));
    expect(oversizedError).toMatchObject({ code: 'provider_unknown', stage: 'worker_recovery', outcome: 'unknown' });
    expect(oversized.callCount()).toBe(1);

    let pendingRequest: UploadRequest | undefined;
    const timeout = sequencedTransport([
      () => failure(404),
      (request) => {
        pendingRequest = request;
        return new Promise<Response>(() => undefined);
      },
    ]);
    const timeoutError = await directUploadError(__testOnlyDeployVerifiedWorkerRelease(
      input(fixture.release, timeout.transport, 100),
    ));
    expect(timeoutError).toMatchObject({ code: 'provider_unknown', stage: 'worker_create', outcome: 'unknown' });
    expect(timeout.callCount()).toBe(2);
    expect(pendingRequest?.signal.aborted).toBe(true);
    expect(JSON.stringify(timeoutError)).not.toContain(ACCESS_TOKEN);
  });

  it('re-hashes bytes and rejects prefixed, double-prefixed, or component digest evidence', async () => {
    const fixture = await releaseFixture();
    const module = required(fixture.release.worker.modules.at(0), 'worker module');
    const firstByte = required(module.bytes.at(0), 'worker module byte');
    module.bytes[0] = firstByte ^ 1;
    const untouched = sequencedTransport([]);
    const hashError = await directUploadError(
      __testOnlyDeployVerifiedWorkerRelease(input(fixture.release, untouched.transport)),
    );
    expect(hashError).toMatchObject({ code: 'invalid_input', stage: 'validate', outcome: 'not_sent' });
    expect(untouched.callCount()).toBe(0);

    const clean = await releaseFixture();
    const prefixed: VerifiedWorkerDirectUploadRelease = {
      ...clean.release, artifactSha256: `sha256:${clean.release.artifactSha256}`,
    };
    const cases: Array<{ readonly release: VerifiedWorkerDirectUploadRelease; readonly binding?: string }> = [
      { release: prefixed },
      { release: clean.release, binding: `sha256:sha256:${clean.release.artifactSha256}` },
      {
        release: clean.release,
        binding: `sha256:${required(clean.release.worker.modules.at(0), 'worker module').sha256}`,
      },
    ];
    for (const testCase of cases) {
      const sequence = sequencedTransport([]);
      const valid = input(testCase.release, sequence.transport);
      const invalid: DeployVerifiedWorkerReleaseInput = testCase.binding === undefined
        ? valid
        : {
            ...valid,
            plainTextBindings: {
              ...valid.plainTextBindings,
              ANKKA_GATEWAY_RELEASE_SHA256: testCase.binding,
            },
          };
      const error = await directUploadError(__testOnlyDeployVerifiedWorkerRelease(invalid));
      expect(error).toMatchObject({ code: 'invalid_input', stage: 'validate', outcome: 'not_sent' });
      expect(sequence.callCount()).toBe(0);
    }
  });
});
