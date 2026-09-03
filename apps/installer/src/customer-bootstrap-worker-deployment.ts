import * as v from 'valibot';

import {
  boundaryObjectSchema,
  boundaryValueSchema,
  type BoundaryObject,
  type BoundaryValue,
} from './boundary';
import { canonicalJson } from './canonical-json';
import {
  inspectAdminStateDurableObjectNamespace,
  prepareAssetBucketMutation,
  prepareAssetUploadSessionMutation,
  submitAssetBucketMutation,
  submitAssetUploadSessionMutation,
  type CloudflareDirectUploadCall,
  type PreparedAsset,
  type PreparedModule,
  type PreparedWorkerAssets,
  type VerifiedWorkerAssetFile,
  type VerifiedWorkerUploadFile,
} from './cloudflare-worker-direct-upload';
import { CLOUDFLARE_API_ORIGIN } from './constants';
import { CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS } from './customer-bootstrap-worker-readback';
import type { CustomerCloudflareTransport } from './customer-cloudflare-grant';
import { readBoundedText, withDeadline } from './http';

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const WORKER_ID = /^[a-f0-9]{32}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const VERSION_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const RELEASE_ID = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const BOOTSTRAP_ID = /^boot_[A-Za-z0-9_-]{24}$/u;
const SECRET = /^[A-Za-z0-9_-]{43}$/u;
const COMPATIBILITY_DATE = '2026-08-08';
const MAIN_MODULE = 'index.js';
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 32 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const WORKER_TAGS = Object.freeze(['ankka-mcp-gateway', 'ankka-stage1-bootstrap'] as const);
const RUN_WORKER_FIRST = Object.freeze(['/__ankka/*', '/api/*'] as const);

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

const envelopeSchema = v.looseObject({
  success: v.boolean(),
  errors: v.nullable(v.array(boundaryValueSchema)),
  messages: v.nullable(v.array(boundaryValueSchema)),
  result: boundaryValueSchema,
});
const workerSchema = v.looseObject({
  id: v.pipe(v.string(), v.regex(WORKER_ID)),
  name: v.pipe(v.string(), v.regex(WORKER_NAME)),
  logpush: v.literal(false),
  observability: v.looseObject({ enabled: v.literal(false) }),
  subdomain: v.looseObject({
    enabled: v.boolean(),
    previews_enabled: v.literal(false),
  }),
  tags: v.array(v.string()),
  tail_consumers: v.array(boundaryValueSchema),
});
const deploymentSchema = v.looseObject({
  id: v.pipe(v.string(), v.regex(VERSION_ID)),
  versions: v.array(v.looseObject({
    version_id: v.pipe(v.string(), v.regex(VERSION_ID)),
    percentage: v.number(),
  })),
});
const deploymentsSchema = v.looseObject({ deployments: v.array(deploymentSchema) });
const namedBindingSchema = v.looseObject({ name: v.string(), type: v.string() });
const moduleSchema = v.looseObject({
  name: v.string(),
  content_type: v.string(),
  content_base64: v.string(),
});
const versionSchema = v.looseObject({
  id: v.pipe(v.string(), v.regex(VERSION_ID)),
  annotations: v.looseObject({ 'workers/tag': v.string() }),
  assets: v.looseObject({
    config: v.looseObject({
      not_found_handling: v.literal('single-page-application'),
      run_worker_first: v.array(v.string()),
    }),
  }),
  bindings: v.array(boundaryValueSchema),
  compatibility_date: v.literal(COMPATIBILITY_DATE),
  compatibility_flags: v.optional(v.array(v.string())),
  exports: v.looseObject({
    AdminState: v.looseObject({
      type: v.literal('durable-object'),
      storage: v.literal('sqlite'),
    }),
  }),
  main_module: v.literal(MAIN_MODULE),
  modules: v.array(moduleSchema),
});

export type CustomerBootstrapPlainBindings = Readonly<Record<
  (typeof CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS)[number],
  string
>>;

export interface VerifiedCustomerBootstrapWorkerRelease {
  readonly verification: 'ed25519';
  readonly release: string;
  readonly artifactSha256: string;
  readonly componentSha256: string;
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

export type CustomerBootstrapWorkerDeploymentStage =
  | 'validate'
  | 'worker_read'
  | 'worker_create'
  | 'asset_upload'
  | 'script_upload'
  | 'deployment_read'
  | 'version_read'
  | 'namespace_read';

export class CustomerBootstrapWorkerDeploymentError extends Error {
  readonly canRetry = false;

  constructor(
    readonly code: 'invalid' | 'worker_name_collision' | 'provider_rejected' |
      'provider_unknown' | 'provider_mismatch',
    readonly stage: CustomerBootstrapWorkerDeploymentStage,
    readonly outcome: 'not_sent' | 'rejected' | 'unknown' | 'submitted',
  ) {
    super(code);
    this.name = 'CustomerBootstrapWorkerDeploymentError';
  }
}

export interface DeployCustomerBootstrapWorkerInput {
  readonly accessToken: string;
  readonly accountId: string;
  readonly workerName: string;
  readonly bootstrapId: string;
  readonly release: VerifiedCustomerBootstrapWorkerRelease;
  readonly plainTextBindings: CustomerBootstrapPlainBindings;
  readonly bootstrapNonce: string;
  readonly ownershipWrapKey: string;
  readonly transport: CustomerCloudflareTransport;
  readonly wait?: (milliseconds: number) => Promise<void>;
}

export interface CustomerBootstrapWorkerDeployment {
  readonly workerId: string;
  readonly workerName: string;
  readonly namespaceId: string;
  readonly namespaceName: string;
  readonly deploymentId: string;
  readonly versionId: string;
  readonly release: string;
  readonly artifactSha256: string;
  readonly bootstrapComponentSha256: string;
  readonly sourceSha256: string;
  readonly recovery: 'created' | 'recovered';
}

interface PreparedBootstrapWorker {
  readonly accountId: string;
  readonly workerName: string;
  readonly bootstrapId: string;
  readonly workerTags: readonly string[];
  readonly release: string;
  readonly artifactSha256: string;
  readonly componentSha256: string;
  readonly modules: readonly PreparedModule[];
  readonly assets: readonly PreparedAsset[];
  readonly plainTextBindings: CustomerBootstrapPlainBindings;
  readonly bootstrapNonce: string;
  readonly ownershipWrapKey: string;
  readonly correlationTag: string;
}

interface ProviderResponse {
  readonly status: number;
  readonly envelope: v.InferOutput<typeof envelopeSchema> | null;
}

function fail(
  code: CustomerBootstrapWorkerDeploymentError['code'],
  stage: CustomerBootstrapWorkerDeploymentStage,
  outcome: CustomerBootstrapWorkerDeploymentError['outcome'],
): never {
  throw new CustomerBootstrapWorkerDeploymentError(code, stage, outcome);
}

function extension(path: string): string {
  const index = path.lastIndexOf('.');
  return index < 0 ? '' : path.slice(index).toLowerCase();
}

function safePath(path: string, leadingSlash: boolean): boolean {
  if (path.length < (leadingSlash ? 2 : 1) || path.length > 512 || path.includes('\\') ||
      path !== path.normalize('NFC') || [...path].some((character) => {
        const point = character.codePointAt(0) ?? 0;
        return point <= 31 || point === 127;
      })) return false;
  const value = leadingSlash ? path.slice(1) : path;
  return (leadingSlash ? path.startsWith('/') : !path.startsWith('/')) &&
    value.split('/').every((part) => part !== '' && part !== '.' && part !== '..');
}

function safeToken(value: string): boolean {
  return value.length >= 16 && value.length <= 8192 &&
    ![...value].some((character) => {
      const point = character.codePointAt(0) ?? 0;
      return point <= 31 || point === 127;
    });
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let offset = 0; offset < bytes.byteLength; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, Math.min(offset + 0x8000, bytes.byteLength)));
  }
  return btoa(binary);
}

function base64ToBytes(value: string, maximum = MAX_FILE_BYTES): Uint8Array | null {
  if (value.length < 4 || value.length > 4 * Math.ceil(maximum / 3) + 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) return null;
  try {
    const binary = atob(value);
    if (binary.length < 1 || binary.length > maximum) return null;
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (bytesToBase64(bytes) !== value) {
      bytes.fill(0);
      return null;
    }
    return bytes;
  } catch {
    return null;
  }
}

async function sha256BytesHex(value: Uint8Array): Promise<string> {
  const owned = new Uint8Array(value.byteLength);
  owned.set(value);
  try {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', owned));
    return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  } finally {
    owned.fill(0);
  }
}

async function sha256TextHex(value: string): Promise<string> {
  return sha256BytesHex(new TextEncoder().encode(value));
}

async function prepare(input: DeployCustomerBootstrapWorkerInput): Promise<PreparedBootstrapWorker> {
  if (!safeToken(input.accessToken) || !ACCOUNT_ID.test(input.accountId) ||
      !WORKER_NAME.test(input.workerName) || !BOOTSTRAP_ID.test(input.bootstrapId) ||
      !SECRET.test(input.bootstrapNonce) || !SECRET.test(input.ownershipWrapKey) ||
      !v.is(v.function(), input.transport)) fail('invalid', 'validate', 'not_sent');
  const release = input.release;
  if (release.verification !== 'ed25519' || !RELEASE_ID.test(release.release) ||
      !SHA256.test(release.artifactSha256) || !SHA256.test(release.componentSha256) ||
      release.worker.mainModule !== MAIN_MODULE ||
      release.worker.compatibilityDate !== COMPATIBILITY_DATE ||
      release.worker.compatibilityFlags.length !== 0 ||
      release.worker.assets.binding !== 'ASSETS' ||
      release.worker.assets.notFoundHandling !== 'single-page-application' ||
      JSON.stringify(release.worker.assets.runWorkerFirst) !== JSON.stringify(RUN_WORKER_FIRST) ||
      release.worker.durableObject.binding !== 'ADMIN_STATE' ||
      release.worker.durableObject.className !== 'AdminState' ||
      release.worker.durableObject.storage !== 'sqlite') fail('invalid', 'validate', 'not_sent');
  const actualBindingNames = Object.keys(input.plainTextBindings).sort();
  const expectedBindingNames = [...CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS].sort();
  if (actualBindingNames.length !== expectedBindingNames.length ||
      !actualBindingNames.every((name, index) => name === expectedBindingNames[index]) ||
      CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS.some((name) => {
        const value = input.plainTextBindings[name];
        return value.length < 1 || value.length > 4096 ||
          [...value].some((character) => {
            const point = character.codePointAt(0) ?? 0;
            return point <= 31 || point === 127;
          });
      }) ||
      input.plainTextBindings.CLOUDFLARE_ACCOUNT_ID !== input.accountId ||
      input.plainTextBindings.ANKKA_WORKER_NAME !== input.workerName ||
      input.plainTextBindings.ANKKA_BOOTSTRAP_ID !== input.bootstrapId ||
      input.plainTextBindings.ANKKA_GATEWAY_RELEASE !== release.release ||
      input.plainTextBindings.ANKKA_GATEWAY_RELEASE_SHA256 !== `sha256:${release.artifactSha256}`) {
    fail('invalid', 'validate', 'not_sent');
  }

  let totalBytes = 0;
  const modules: PreparedModule[] = [];
  const moduleNames = new Set<string>();
  for (const module of release.worker.modules) {
    if (!safePath(module.name, false) || moduleNames.has(module.name) ||
        module.contentType !== MODULE_CONTENT_TYPES[extension(module.name)] ||
        module.bytes.byteLength < 1 || module.bytes.byteLength > MAX_FILE_BYTES) {
      fail('invalid', 'validate', 'not_sent');
    }
    const bytes = new Uint8Array(module.bytes);
    if (await sha256BytesHex(bytes) !== module.sha256) fail('invalid', 'validate', 'not_sent');
    moduleNames.add(module.name);
    modules.push(Object.freeze({ name: module.name, contentType: module.contentType, bytes }));
    totalBytes += bytes.byteLength;
  }
  if (modules.length !== 1 || !moduleNames.has(MAIN_MODULE)) fail('invalid', 'validate', 'not_sent');

  const assets: PreparedAsset[] = [];
  const assetPaths = new Set<string>();
  const hashContentTypes = new Map<string, string>();
  for (const asset of release.worker.assets.files) {
    if (!safePath(asset.path, true) || assetPaths.has(asset.path) ||
        asset.contentType !== ASSET_CONTENT_TYPES[extension(asset.path)] ||
        asset.bytes.byteLength < 1 || asset.bytes.byteLength > MAX_FILE_BYTES) {
      fail('invalid', 'validate', 'not_sent');
    }
    const bytes = new Uint8Array(asset.bytes);
    if (await sha256BytesHex(bytes) !== asset.sha256) fail('invalid', 'validate', 'not_sent');
    const uploadHash = (await sha256TextHex(
      `${bytesToBase64(bytes)}${extension(asset.path).slice(1)}`,
    )).slice(0, 32);
    const prior = hashContentTypes.get(uploadHash);
    if (prior !== undefined && prior !== asset.contentType) fail('invalid', 'validate', 'not_sent');
    hashContentTypes.set(uploadHash, asset.contentType);
    assetPaths.add(asset.path);
    assets.push(Object.freeze({ path: asset.path, contentType: asset.contentType, bytes, uploadHash }));
    totalBytes += bytes.byteLength;
  }
  if (!assetPaths.has('/index.html') || !Number.isSafeInteger(totalBytes) ||
      totalBytes > MAX_PAYLOAD_BYTES) fail('invalid', 'validate', 'not_sent');
  modules.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  assets.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);

  const sourceSha256 = await sha256BytesHex(modules[0]?.bytes ?? new Uint8Array());
  const correlationHash = await sha256TextHex(canonicalJson({
    accountId: input.accountId,
    workerName: input.workerName,
    bootstrapId: input.bootstrapId,
    release: release.release,
    artifactSha256: release.artifactSha256,
    componentSha256: release.componentSha256,
    sourceSha256,
    assets: assets.map((asset) => ({
      path: asset.path,
      uploadHash: asset.uploadHash,
      contentType: asset.contentType,
      byteLength: asset.bytes.byteLength,
    })),
    plainTextBindings: input.plainTextBindings,
    bootstrapNonceSha256: await sha256TextHex(input.bootstrapNonce),
    ownershipWrapKeySha256: await sha256TextHex(input.ownershipWrapKey),
  }));
  return Object.freeze({
    accountId: input.accountId,
    workerName: input.workerName,
    bootstrapId: input.bootstrapId,
    workerTags: Object.freeze([...WORKER_TAGS, `ankka-bootstrap-id:${input.bootstrapId}`].sort()),
    release: release.release,
    artifactSha256: release.artifactSha256,
    componentSha256: release.componentSha256,
    modules: Object.freeze(modules),
    assets: Object.freeze(assets),
    plainTextBindings: Object.freeze({ ...input.plainTextBindings }),
    bootstrapNonce: input.bootstrapNonce,
    ownershipWrapKey: input.ownershipWrapKey,
    correlationTag: `ankka-bootstrap-sha256:${correlationHash}`,
  });
}

function accountUrl(accountId: string, path: string): URL {
  return new URL(`/client/v4/accounts/${accountId}${path}`, CLOUDFLARE_API_ORIGIN);
}

async function providerRequest(
  input: DeployCustomerBootstrapWorkerInput,
  stage: CustomerBootstrapWorkerDeploymentStage,
  url: URL,
  init: RequestInit,
  maximum = MAX_RESPONSE_BYTES,
): Promise<ProviderResponse> {
  try {
    return await withDeadline(async (signal) => {
      const response = await input.transport(url, { ...init, redirect: 'manual', signal });
      const serialized = await readBoundedText(response, 'internal_error', maximum);
      let decoded: unknown;
      try {
        decoded = JSON.parse(serialized);
      } catch {
        return { status: response.status, envelope: null };
      }
      const parsed = v.safeParse(envelopeSchema, decoded);
      return { status: response.status, envelope: parsed.success ? parsed.output : null };
    }, 'internal_error');
  } catch (error) {
    if (error instanceof CustomerBootstrapWorkerDeploymentError) throw error;
    fail('provider_unknown', stage, 'unknown');
  }
}

function successful(response: ProviderResponse): BoundaryValue | null {
  const envelope = response.envelope;
  return response.status >= 200 && response.status < 300 && envelope?.success === true &&
    (envelope.errors?.length ?? 0) === 0 && (envelope.messages?.length ?? 0) === 0
    ? envelope.result
    : null;
}

function exactStringSet(actual: readonly string[], expected: readonly string[]): boolean {
  const left = [...actual].sort();
  const right = [...expected].sort();
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

async function readWorker(
  input: DeployCustomerBootstrapWorkerInput,
  prepared: PreparedBootstrapWorker,
): Promise<string | null> {
  const response = await providerRequest(input, 'worker_read', accountUrl(
    prepared.accountId,
    `/workers/workers/${encodeURIComponent(prepared.workerName)}`,
  ), { method: 'GET', headers: { accept: 'application/json', authorization: `Bearer ${input.accessToken}` } });
  if (response.status === 404 && response.envelope?.success === false) return null;
  const result = successful(response);
  const worker = v.safeParse(workerSchema, result);
  if (!worker.success || worker.output.name !== prepared.workerName ||
      worker.output.tail_consumers.length !== 0 ||
      !exactStringSet(worker.output.tags, prepared.workerTags)) {
    fail('worker_name_collision', 'worker_read', 'rejected');
  }
  return worker.output.id;
}

async function ensureWorker(
  input: DeployCustomerBootstrapWorkerInput,
  prepared: PreparedBootstrapWorker,
): Promise<{ readonly workerId: string; readonly created: boolean }> {
  const existing = await readWorker(input, prepared);
  if (existing !== null) return Object.freeze({ workerId: existing, created: false });
  const body = Object.freeze({
    logpush: false,
    name: prepared.workerName,
    observability: Object.freeze({ enabled: false }),
    subdomain: Object.freeze({ enabled: false, previews_enabled: false }),
    tags: prepared.workerTags,
    tail_consumers: Object.freeze([]),
  });
  let response: ProviderResponse | null = null;
  try {
    response = await providerRequest(input, 'worker_create', accountUrl(
      prepared.accountId,
      '/workers/workers',
    ), {
      method: 'POST',
      headers: { accept: 'application/json', authorization: `Bearer ${input.accessToken}`, 'content-type': 'application/json' },
      body: canonicalJson(body),
    });
  } catch {
    // A timed-out create is reconciled by the exact name/tag read below.
  }
  const wait = input.wait ?? ((milliseconds: number) =>
    new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      const workerId = await readWorker(input, prepared);
      if (workerId !== null) return Object.freeze({ workerId, created: true });
    } catch (error) {
      if (error instanceof CustomerBootstrapWorkerDeploymentError &&
          error.code === 'worker_name_collision') throw error;
    }
    await wait(100 * (attempt + 1));
  }
  if (response !== null && response.status < 500) {
    fail('provider_rejected', 'worker_create', 'rejected');
  }
  fail('provider_unknown', 'worker_create', 'unknown');
}

function exactBindings(
  values: readonly BoundaryValue[],
  prepared: PreparedBootstrapWorker,
  namespaceId?: string,
): boolean {
  const bindings = new Map<string, BoundaryObject>();
  for (const value of values) {
    const named = v.safeParse(namedBindingSchema, value);
    const objectValue = v.safeParse(boundaryObjectSchema, value);
    if (!named.success || !objectValue.success || bindings.has(named.output.name)) return false;
    bindings.set(named.output.name, objectValue.output);
  }
  if (bindings.size !== CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS.length + 4) return false;
  const admin = bindings.get('ADMIN_STATE');
  const assets = bindings.get('ASSETS');
  if (admin?.name !== 'ADMIN_STATE' || admin.type !== 'durable_object_namespace' ||
      admin.class_name !== 'AdminState' ||
      (namespaceId !== undefined && admin.namespace_id !== undefined && admin.namespace_id !== namespaceId) ||
      assets?.name !== 'ASSETS' || assets.type !== 'assets') return false;
  for (const secret of ['ANKKA_BOOTSTRAP_NONCE', 'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY']) {
    const binding = bindings.get(secret);
    if (binding?.name !== secret || binding.type !== 'secret_text' || Object.hasOwn(binding, 'text')) return false;
  }
  for (const name of CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS) {
    const binding = bindings.get(name);
    if (binding?.name !== name || binding.type !== 'plain_text' ||
        binding.text !== prepared.plainTextBindings[name]) return false;
  }
  return true;
}

async function exactModules(
  values: readonly v.InferOutput<typeof moduleSchema>[],
  expected: readonly PreparedModule[],
): Promise<boolean> {
  if (values.length !== expected.length) return false;
  const byName = new Map(values.map((module) => [module.name, module]));
  if (byName.size !== values.length) return false;
  for (const module of expected) {
    const returned = byName.get(module.name);
    if (!returned || returned.content_type !== module.contentType) return false;
    const bytes = base64ToBytes(returned.content_base64);
    if (bytes === null) return false;
    try {
      if (await sha256BytesHex(bytes) !== await sha256BytesHex(module.bytes)) return false;
    } finally {
      bytes.fill(0);
    }
  }
  return true;
}

async function readActiveDeployment(
  input: DeployCustomerBootstrapWorkerInput,
  prepared: PreparedBootstrapWorker,
): Promise<{ readonly deploymentId: string; readonly versionId: string } | null> {
  const response = await providerRequest(input, 'deployment_read', accountUrl(
    prepared.accountId,
    `/workers/scripts/${encodeURIComponent(prepared.workerName)}/deployments`,
  ), { method: 'GET', headers: { accept: 'application/json', authorization: `Bearer ${input.accessToken}` } });
  const result = successful(response);
  if (result === null) {
    if (response.status === 404) return null;
    fail(response.status >= 500 ? 'provider_unknown' : 'provider_rejected', 'deployment_read', 'unknown');
  }
  const parsed = v.safeParse(deploymentsSchema, result);
  if (!parsed.success) fail('provider_mismatch', 'deployment_read', 'unknown');
  if (parsed.output.deployments.length === 0) return null;
  const active = parsed.output.deployments[0];
  const version = active?.versions[0];
  if (!active || active.versions.length !== 1 || !version || version.percentage !== 100) {
    fail('provider_mismatch', 'deployment_read', 'unknown');
  }
  return Object.freeze({ deploymentId: active.id, versionId: version.version_id });
}

async function exactVersion(
  input: DeployCustomerBootstrapWorkerInput,
  prepared: PreparedBootstrapWorker,
  workerId: string,
  versionId: string,
  namespaceId?: string,
): Promise<boolean> {
  const response = await providerRequest(input, 'version_read', accountUrl(
    prepared.accountId,
    `/workers/workers/${workerId}/versions/${versionId}?include=modules`,
  ), { method: 'GET', headers: { accept: 'application/json', authorization: `Bearer ${input.accessToken}` } });
  const parsed = v.safeParse(versionSchema, successful(response));
  return parsed.success && parsed.output.id === versionId &&
    parsed.output.annotations['workers/tag'] === prepared.correlationTag &&
    (parsed.output.compatibility_flags ?? []).length === 0 &&
    JSON.stringify(parsed.output.assets.config.run_worker_first) === JSON.stringify(RUN_WORKER_FIRST) &&
    exactBindings(parsed.output.bindings, prepared, namespaceId) &&
    await exactModules(parsed.output.modules, prepared.modules);
}

async function inspectExactActive(
  input: DeployCustomerBootstrapWorkerInput,
  prepared: PreparedBootstrapWorker,
  workerId: string,
  namespaceId?: string,
): Promise<{ readonly deploymentId: string; readonly versionId: string } | null> {
  const first = await readActiveDeployment(input, prepared);
  if (first === null || !await exactVersion(input, prepared, workerId, first.versionId, namespaceId)) return null;
  const second = await readActiveDeployment(input, prepared);
  if (second === null || second.deploymentId !== first.deploymentId || second.versionId !== first.versionId) {
    fail('provider_mismatch', 'deployment_read', 'unknown');
  }
  return first;
}

async function stageAssets(
  input: DeployCustomerBootstrapWorkerInput,
  prepared: PreparedBootstrapWorker,
): Promise<string> {
  const assets: PreparedWorkerAssets = Object.freeze({
    accountId: prepared.accountId,
    workerName: prepared.workerName,
    assets: prepared.assets,
  });
  const call: CloudflareDirectUploadCall = {
    accessToken: input.accessToken,
    transport: input.transport,
  };
  try {
    const intent = await prepareAssetUploadSessionMutation(assets);
    const session = await submitAssetUploadSessionMutation(intent, call);
    if (session.buckets.length === 0) return session.uploadJwt;
    let completionJwt: string | null = null;
    for (let index = 0; index < session.buckets.length; index += 1) {
      const bucket = await prepareAssetBucketMutation(session, index);
      const submitted = await submitAssetBucketMutation(bucket, session, assets, call);
      if (submitted.isFinal) completionJwt = submitted.completionJwt;
    }
    if (completionJwt === null) fail('provider_mismatch', 'asset_upload', 'unknown');
    return completionJwt;
  } catch (error) {
    if (error instanceof CustomerBootstrapWorkerDeploymentError) throw error;
    fail('provider_unknown', 'asset_upload', 'unknown');
  }
}

function uploadMetadata(prepared: PreparedBootstrapWorker, completionJwt: string): BoundaryObject {
  const bindings: BoundaryObject[] = [
    { name: 'ADMIN_STATE', type: 'durable_object_namespace', class_name: 'AdminState' },
    { name: 'ASSETS', type: 'assets' },
    { name: 'ANKKA_BOOTSTRAP_NONCE', type: 'secret_text', text: prepared.bootstrapNonce },
    { name: 'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY', type: 'secret_text', text: prepared.ownershipWrapKey },
    ...CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS.map((name) => ({
      name,
      type: 'plain_text',
      text: prepared.plainTextBindings[name],
    })),
  ];
  bindings.sort((left, right) => String(left.name) < String(right.name) ? -1 : String(left.name) > String(right.name) ? 1 : 0);
  return {
    annotations: {
      'workers/message': prepared.correlationTag,
      'workers/tag': prepared.correlationTag,
    },
    assets: {
      config: {
        not_found_handling: 'single-page-application',
        run_worker_first: [...RUN_WORKER_FIRST],
      },
      jwt: completionJwt,
    },
    bindings,
    compatibility_date: COMPATIBILITY_DATE,
    compatibility_flags: [],
    exports: { AdminState: { type: 'durable-object', storage: 'sqlite' } },
    main_module: MAIN_MODULE,
  };
}

async function submitScript(
  input: DeployCustomerBootstrapWorkerInput,
  prepared: PreparedBootstrapWorker,
  completionJwt: string,
): Promise<ProviderResponse | null> {
  const metadata = uploadMetadata(prepared, completionJwt);
  const form = new FormData();
  form.append('metadata', new Blob([canonicalJson(metadata)], { type: 'application/json' }), 'metadata.json');
  for (const module of prepared.modules) {
    form.append(
      module.name,
      new Blob([new Uint8Array(module.bytes)], { type: module.contentType }),
      module.name,
    );
  }
  try {
    return await providerRequest(input, 'script_upload', accountUrl(
      prepared.accountId,
      `/workers/scripts/${encodeURIComponent(prepared.workerName)}`,
    ), {
      method: 'PUT',
      headers: { accept: 'application/json', authorization: `Bearer ${input.accessToken}` },
      body: form,
    });
  } catch {
    return null;
  }
}

async function waitForNamespace(
  input: DeployCustomerBootstrapWorkerInput,
  prepared: PreparedBootstrapWorker,
) {
  const wait = input.wait ?? ((milliseconds: number) =>
    new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      return await inspectAdminStateDurableObjectNamespace({
        accountId: prepared.accountId,
        workerName: prepared.workerName,
        className: 'AdminState',
        storage: 'sqlite',
      }, { accessToken: input.accessToken, transport: input.transport });
    } catch {
      await wait(100 * (attempt + 1));
    }
  }
  fail('provider_unknown', 'namespace_read', 'unknown');
}

/**
 * Create or recover the one exact restricted Stage 1 Worker. The only write
 * authority accepted by this primitive is a request-local Cloudflare access
 * token; no token, asset JWT, or secret-bearing request body is returned.
 */
export async function deployCustomerBootstrapWorker(
  input: DeployCustomerBootstrapWorkerInput,
): Promise<CustomerBootstrapWorkerDeployment> {
  const prepared = await prepare(input);
  const worker = await ensureWorker(input, prepared);
  let active = await inspectExactActive(input, prepared, worker.workerId);
  let recovery: CustomerBootstrapWorkerDeployment['recovery'] = 'recovered';
  if (active === null) {
    if (!worker.created) {
      const prior = await readActiveDeployment(input, prepared);
      if (prior !== null) fail('worker_name_collision', 'version_read', 'rejected');
    }
    const completionJwt = await stageAssets(input, prepared);
    const response = await submitScript(input, prepared, completionJwt);
    if (response !== null && successful(response) === null && response.status < 500) {
      fail('provider_rejected', 'script_upload', 'rejected');
    }
    const wait = input.wait ?? ((milliseconds: number) =>
      new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
    for (let attempt = 0; attempt < 8; attempt += 1) {
      active = await inspectExactActive(input, prepared, worker.workerId);
      if (active !== null) break;
      await wait(100 * (attempt + 1));
    }
    if (active === null) fail('provider_unknown', 'version_read', 'submitted');
    recovery = 'created';
  }
  const namespace = await waitForNamespace(input, prepared);
  if (!await exactVersion(input, prepared, worker.workerId, active.versionId, namespace.namespaceId)) {
    fail('provider_mismatch', 'version_read', 'submitted');
  }
  const source = prepared.modules[0];
  if (source === undefined) fail('invalid', 'validate', 'not_sent');
  return Object.freeze({
    workerId: worker.workerId,
    workerName: prepared.workerName,
    namespaceId: namespace.namespaceId,
    namespaceName: namespace.namespaceName,
    deploymentId: active.deploymentId,
    versionId: active.versionId,
    release: prepared.release,
    artifactSha256: prepared.artifactSha256,
    bootstrapComponentSha256: prepared.componentSha256,
    sourceSha256: await sha256BytesHex(source.bytes),
    recovery,
  });
}
