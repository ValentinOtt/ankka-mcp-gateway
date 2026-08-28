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
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;

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
  readonly errors: null | readonly unknown[];
  readonly messages: null | readonly unknown[];
  readonly result: unknown;
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

function rethrowWithSubmissions(
  error: unknown,
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function lexicalCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isEmptyProviderList(value: unknown): value is null | readonly [] {
  return value === null || (Array.isArray(value) && value.length === 0);
}

function validProviderErrorList(value: unknown): boolean {
  if (!Array.isArray(value) || value.length === 0 || value.length > 16) return false;
  return value.every((entry) => {
    if (!isRecord(entry)) return false;
    const allowed = new Set(['code', 'documentation_url', 'message', 'source']);
    if (Object.keys(entry).some((key) => !allowed.has(key))) return false;
    return typeof entry.code === 'number' && Number.isSafeInteger(entry.code) &&
      typeof entry.message === 'string' && entry.message.length > 0 && entry.message.length <= 2048;
  });
}

function parseEnvelope(value: unknown): CloudflareEnvelope | null {
  if (!isRecord(value) || !exactKeys(value, ['errors', 'messages', 'result', 'success'])) return null;
  if (typeof value.success !== 'boolean') return null;
  if (!(value.errors === null || Array.isArray(value.errors))) return null;
  if (!(value.messages === null || Array.isArray(value.messages))) return null;
  return {
    errors: value.errors,
    messages: value.messages,
    result: value.result,
    success: value.success,
  };
}

function parseSuccessEnvelope(value: unknown): unknown | null {
  const envelope = parseEnvelope(value);
  if (
    !envelope ||
    envelope.success !== true ||
    !isEmptyProviderList(envelope.errors) ||
    !isEmptyProviderList(envelope.messages)
  ) return null;
  return envelope.result;
}

function parseAbsentEnvelope(value: unknown): boolean {
  const envelope = parseEnvelope(value);
  return Boolean(
    envelope &&
    envelope.success === false &&
    validProviderErrorList(envelope.errors) &&
    isEmptyProviderList(envelope.messages) &&
    envelope.result === null,
  );
}

function safeToken(value: unknown, minimum = 20): value is string {
  return typeof value === 'string' &&
    value.length >= minimum &&
    value.length <= 8192 &&
    TOKEN_PATTERN.test(value);
}

function extension(path: string): string {
  const slash = path.lastIndexOf('/');
  const dot = path.lastIndexOf('.');
  return dot > slash ? path.slice(dot).toLowerCase() : '';
}

function safeModuleName(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256) return false;
  if (value.startsWith('/') || value.includes('\\') || CONTROL_CHARACTER.test(value)) return false;
  return value.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..');
}

function safeAssetPath(value: unknown): value is string {
  if (typeof value !== 'string' || value.length < 2 || value.length > 1024) return false;
  if (!value.startsWith('/') || value.includes('\\') || CONTROL_CHARACTER.test(value)) return false;
  return value.slice(1).split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..');
}

function safeBindingValue(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 4096 && !CONTROL_CHARACTER.test(value);
}

function safeHostname(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 253 || value !== value.toLowerCase() ||
      value.includes(':') || /^(?:\d+\.)+\d+$/u.test(value)) return false;
  const labels = value.split('.');
  return labels.length >= 2 && labels.every((label) => DNS_LABEL_PATTERN.test(label));
}

function safeIsoDate(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 20 && value.length <= 40 && Number.isFinite(Date.parse(value));
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

function strictBase64Bytes(value: unknown, expectedByteLength: number): Uint8Array | null {
  if (
    typeof value !== 'string' ||
    value.length !== 4 * Math.ceil(expectedByteLength / 3) ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
  ) return null;
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    return null;
  }
  if (binary.length !== expectedByteLength) return null;
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return bytesToBase64(bytes) === value ? bytes : null;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(value: Uint8Array | string): Promise<string> {
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  const digestInput = new Uint8Array(bytes).buffer;
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', digestInput)));
}

async function prepareInput(
  input: PrepareVerifiedWorkerReleaseInput,
  progress: MutableProgress,
): Promise<PreparedVerifiedWorkerRelease> {
  if (
    !isRecord(input) ||
    !ACCOUNT_ID_PATTERN.test(input.accountId) ||
    !WORKER_NAME_PATTERN.test(input.workerName) ||
    !isRecord(input.release) ||
    input.release.verification !== 'ed25519' ||
    !RELEASE_PATTERN.test(input.release.release) ||
    !SHA256_PATTERN.test(input.release.artifactSha256) ||
    !isRecord(input.release.worker) ||
    input.release.worker.mainModule !== 'index.js' ||
    input.release.worker.compatibilityDate !== EXACT_COMPATIBILITY_DATE ||
    !Array.isArray(input.release.worker.compatibilityFlags) ||
    input.release.worker.compatibilityFlags.length !== 0 ||
    !Array.isArray(input.release.worker.modules) ||
    input.release.worker.modules.length === 0 ||
    !isRecord(input.release.worker.assets) ||
    input.release.worker.assets.binding !== 'ASSETS' ||
    input.release.worker.assets.notFoundHandling !== 'single-page-application' ||
    !Array.isArray(input.release.worker.assets.runWorkerFirst) ||
    input.release.worker.assets.runWorkerFirst.length !== EXACT_RUN_WORKER_FIRST.length ||
    !input.release.worker.assets.runWorkerFirst.every(
      (route, index) => route === EXACT_RUN_WORKER_FIRST[index],
    ) ||
    !Array.isArray(input.release.worker.assets.files) ||
    input.release.worker.assets.files.length === 0 ||
    !isRecord(input.release.worker.durableObject) ||
    input.release.worker.durableObject.binding !== 'ADMIN_STATE' ||
    input.release.worker.durableObject.className !== 'AdminState' ||
    input.release.worker.durableObject.storage !== 'sqlite' ||
    !isRecord(input.plainTextBindings) ||
    !exactKeys(input.plainTextBindings, EXACT_PLAIN_TEXT_BINDINGS) ||
    !safeToken(input.bootstrapNonce, 32)
  ) fail('invalid_input', 'validate', 'not_sent', progress);

  for (const name of EXACT_PLAIN_TEXT_BINDINGS) {
    if (!safeBindingValue(input.plainTextBindings[name])) {
      fail('invalid_input', 'validate', 'not_sent', progress);
    }
  }
  if (
    input.plainTextBindings.ANKKA_GATEWAY_RELEASE !== input.release.release ||
    input.plainTextBindings.ANKKA_GATEWAY_RELEASE_SHA256 !== `sha256:${input.release.artifactSha256}` ||
    input.plainTextBindings.ANKKA_WORKER_NAME !== input.workerName ||
    !WORKER_NAME_PATTERN.test(input.plainTextBindings.ANKKA_WORKER_NAME) ||
    !DNS_LABEL_PATTERN.test(input.plainTextBindings.ANKKA_WORKERS_SUBDOMAIN) ||
    !safeHostname(input.plainTextBindings.ANKKA_MANAGEMENT_HOSTNAME) ||
    input.plainTextBindings.CLOUDFLARE_ACCOUNT_ID !== input.accountId ||
    !ACCOUNT_ID_PATTERN.test(input.plainTextBindings.CLOUDFLARE_ZONE_ID) ||
    input.plainTextBindings.ZERO_TRUST_READY !== 'true'
  ) fail('invalid_input', 'validate', 'not_sent', progress);

  const modules: PreparedModule[] = [];
  const moduleNames = new Set<string>();
  let totalBytes = 0;
  for (const module of input.release.worker.modules) {
    if (
      !isRecord(module) ||
      !safeModuleName(module.name) ||
      moduleNames.has(module.name) ||
      typeof module.contentType !== 'string' ||
      module.contentType !== MODULE_CONTENT_TYPES[extension(module.name)] ||
      typeof module.sha256 !== 'string' ||
      !SHA256_PATTERN.test(module.sha256) ||
      !(module.bytes instanceof Uint8Array) ||
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
  for (const asset of input.release.worker.assets.files) {
    if (
      !isRecord(asset) ||
      !safeAssetPath(asset.path) ||
      assetPaths.has(asset.path) ||
      typeof asset.contentType !== 'string' ||
      asset.contentType !== ASSET_CONTENT_TYPES[extension(asset.path)] ||
      typeof asset.sha256 !== 'string' ||
      !SHA256_PATTERN.test(asset.sha256) ||
      !(asset.bytes instanceof Uint8Array) ||
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
    accountId: input.accountId,
    workerName: input.workerName,
    release: input.release.release,
    modules: Object.freeze(modules),
    assets: Object.freeze(assets),
    plainTextBindings: Object.freeze({ ...input.plainTextBindings }),
    bootstrapNonce: input.bootstrapNonce,
  };
}

export async function prepareVerifiedWorkerRelease(
  input: PrepareVerifiedWorkerReleaseInput,
): Promise<PreparedVerifiedWorkerRelease> {
  return await prepareInput(input, initialProgress());
}

function prepareCall(call: CloudflareDirectUploadCall, progress: MutableProgress): PreparedCall {
  if (!isRecord(call)) fail('invalid_input', 'validate', 'not_sent', progress);
  const timeoutMs = call.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (
    !safeToken(call.accessToken) ||
    typeof call.transport !== 'function' ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 100 ||
    timeoutMs > 60_000
  ) fail('invalid_input', 'validate', 'not_sent', progress);
  return { accessToken: call.accessToken, transport: call.transport, timeoutMs };
}

async function readBoundedJson(response: Response, maxBytes = MAX_RESPONSE_BYTES): Promise<unknown> {
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
    return JSON.parse(text) as unknown;
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
): Promise<{ readonly status: number; readonly value: unknown }> {
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
  value: unknown,
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
  response: { readonly status: number; readonly value: unknown },
  expectedStatuses: readonly number[],
  stage: CloudflareDirectUploadStage,
  progress: MutableProgress,
): unknown {
  if (!expectedStatuses.includes(response.status)) {
    rejectForStatus(response.status, response.value, stage, progress);
  }
  const result = parseSuccessEnvelope(response.value);
  if (result === null) fail('provider_unknown', stage, 'unknown', progress);
  return result;
}

function disabledObservability(value: unknown): boolean {
  if (!isRecord(value) || value.enabled !== false) return false;
  const allowed = new Set(['enabled', 'head_sampling_rate', 'redact_query_string', 'logs', 'traces']);
  if (Object.keys(value).some((key) => !allowed.has(key))) return false;
  if (value.redact_query_string !== undefined && value.redact_query_string !== false) return false;
  for (const key of ['logs', 'traces'] as const) {
    const nested = value[key];
    if (nested === undefined) continue;
    if (!isRecord(nested)) return false;
    if (nested.enabled !== undefined && nested.enabled !== false) return false;
    if (nested.destinations !== undefined && (!Array.isArray(nested.destinations) || nested.destinations.length !== 0)) {
      return false;
    }
  }
  return true;
}

function emptyReferences(value: unknown): boolean {
  if (!isRecord(value)) return false;
  const expected = ['dispatch_namespace_outbounds', 'domains', 'durable_objects', 'queues', 'workers'];
  if (!exactKeys(value, expected)) return false;
  return expected.every((key) => Array.isArray(value[key]) && (value[key] as unknown[]).length === 0);
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
  value: unknown,
  expectedName: string,
  converged: ConvergedWorkerExpectation,
): boolean {
  if (!isRecord(value)) return false;
  if (!exactKeys(value, ['dispatch_namespace_outbounds', 'domains', 'durable_objects', 'queues', 'workers'])) {
    return false;
  }
  for (const key of ['dispatch_namespace_outbounds', 'queues', 'workers'] as const) {
    if (!Array.isArray(value[key]) || (value[key] as unknown[]).length !== 0) return false;
  }
  if (!Array.isArray(value.domains) || value.domains.length !== 1) return false;
  const domain = value.domains[0];
  if (
    !isRecord(domain) || !exactKeys(domain, ['id', 'hostname', 'zone_id', 'zone_name']) ||
    domain.id !== converged.domain.id || domain.hostname !== converged.domain.hostname ||
    domain.zone_id !== converged.domain.zoneId || domain.zone_name !== converged.domain.zoneName
  ) return false;
  if (!Array.isArray(value.durable_objects) || value.durable_objects.length !== 1) return false;
  const namespace = value.durable_objects[0];
  return isRecord(namespace) &&
    exactKeys(namespace, ['worker_id', 'worker_name', 'namespace_id', 'namespace_name']) &&
    namespace.namespace_id === converged.namespaceId &&
    namespace.worker_name === expectedName &&
    namespace.namespace_name === `${expectedName}_AdminState`;
}

function exactWorkerState(
  value: unknown,
  expectedName: string,
  expectedTags: readonly string[],
  expectedId?: string,
  converged?: ConvergedWorkerExpectation,
): value is Record<string, unknown> {
  if (!isRecord(value)) return false;
  const allowed = new Set([
    'created_on',
    'deployed_on',
    'id',
    'logpush',
    'name',
    'observability',
    'references',
    'subdomain',
    'tags',
    'tail_consumers',
    'updated_on',
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key))) return false;
  if (
    !WORKER_ID_PATTERN.test(String(value.id)) ||
    (expectedId !== undefined && value.id !== expectedId) ||
    value.name !== expectedName ||
    value.logpush !== false ||
    !disabledObservability(value.observability) ||
    !isRecord(value.subdomain) ||
    value.subdomain.enabled !== false ||
    value.subdomain.previews_enabled !== false ||
    !Array.isArray(value.tags) ||
    value.tags.length !== expectedTags.length ||
    !value.tags.every((tag, index) => tag === expectedTags[index]) ||
    !Array.isArray(value.tail_consumers) ||
    value.tail_consumers.length !== 0 ||
    !safeIsoDate(value.created_on) ||
    !safeIsoDate(value.updated_on) ||
    (converged
      ? !safeIsoDate(value.deployed_on) || !exactConvergedReferences(value.references, expectedName, converged)
      : !(value.deployed_on === undefined || value.deployed_on === null) || !emptyReferences(value.references))
  ) return false;
  return true;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError('canonical');
}

function canonicalEqual(left: unknown, right: unknown): boolean {
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
export async function prepareWorkerMutationForTarget(
  input: PrepareWorkerMutationForTargetInput,
): Promise<WorkerMutationIntent> {
  const progress = initialProgress();
  if (!isRecord(input) || !exactKeys(input, ['accountId', 'workerName'])) {
    fail('invalid_input', 'validate', 'not_sent', progress);
  }
  const accountId = input.accountId;
  const workerName = input.workerName;
  if (!ACCOUNT_ID_PATTERN.test(accountId) || !WORKER_NAME_PATTERN.test(workerName)) {
    fail('invalid_input', 'validate', 'not_sent', progress);
  }
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
  if (
    !isRecord(intent) ||
    intent.kind !== 'worker' ||
    !ACCOUNT_ID_PATTERN.test(intent.accountId) ||
    !WORKER_NAME_PATTERN.test(intent.workerName) ||
    !SHA256_PATTERN.test(intent.requestHash) ||
    intent.correlationTag !== `ankka-worker-sha256:${intent.requestHash}` ||
    !isRecord(intent.body) ||
    !canonicalEqual(intent.body, {
      ...workerCoreBody(intent.workerName),
      tags: [MANAGED_WORKER_TAG, intent.correlationTag],
    })
  ) return false;
  return await sha256(canonicalJson(workerCoreBody(intent.workerName))) === intent.requestHash;
}

function rawResultId(value: unknown, pattern: RegExp): string | null {
  if (!isRecord(value) || !isRecord(value.result) || typeof value.result.id !== 'string') return null;
  return pattern.test(value.result.id) ? value.result.id : null;
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

function boundedNamespaceText(value: unknown, maximum: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum && !CONTROL_CHARACTER.test(value);
}

function parseDurableObjectNamespacePage(value: unknown): DurableObjectNamespacePage | null {
  if (!isRecord(value) || !exactKeys(value, ['errors', 'messages', 'result', 'result_info', 'success'])) return null;
  if (
    value.success !== true || !isEmptyProviderList(value.errors) || !isEmptyProviderList(value.messages) ||
    !Array.isArray(value.result) || !isRecord(value.result_info) ||
    // Live (2026-08-23): this endpoint omits total_pages entirely.
    !exactKeys(value.result_info, Object.hasOwn(value.result_info, 'total_pages')
      ? ['count', 'page', 'per_page', 'total_count', 'total_pages']
      : ['count', 'page', 'per_page', 'total_count'])
  ) return null;
  const info = value.result_info;
  if (
    !Number.isSafeInteger(info.count) || (info.count as number) < 0 ||
    !Number.isSafeInteger(info.page) || (info.page as number) < 1 ||
    info.per_page !== NAMESPACE_PAGE_SIZE ||
    !Number.isSafeInteger(info.total_count) || (info.total_count as number) < 0 ||
    (info.total_count as number) > MAX_NAMESPACE_COUNT ||
    (info.total_pages !== undefined && (
      !Number.isSafeInteger(info.total_pages) || (info.total_pages as number) < 0 ||
      (info.total_pages as number) > MAX_NAMESPACE_PAGES
    )) ||
    info.count !== value.result.length
  ) return null;
  const items: DurableObjectNamespaceItem[] = [];
  for (const item of value.result) {
    if (!isRecord(item) || !exactKeys(item, ['id', 'class', 'name', 'script', 'use_sqlite'])) return null;
    if (
      typeof item.id !== 'string' || !ACCOUNT_ID_PATTERN.test(item.id) ||
      !boundedNamespaceText(item.class, 128) || !boundedNamespaceText(item.name, 256) ||
      !boundedNamespaceText(item.script, 128) || typeof item.use_sqlite !== 'boolean'
    ) return null;
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
    page: info.page as number,
    perPage: NAMESPACE_PAGE_SIZE,
    count: info.count as number,
    totalCount: info.total_count as number,
    totalPages: info.total_pages === undefined ? null : info.total_pages as number,
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
  if (
    !isRecord(input) ||
    !exactKeys(input, input.expectedNamespaceId === undefined
      ? ['accountId', 'workerName', 'className', 'storage']
      : ['accountId', 'workerName', 'className', 'storage', 'expectedNamespaceId']) ||
    !ACCOUNT_ID_PATTERN.test(input.accountId) || !WORKER_NAME_PATTERN.test(input.workerName) ||
    input.className !== 'AdminState' || input.storage !== 'sqlite' ||
    (input.expectedNamespaceId !== undefined && !ACCOUNT_ID_PATTERN.test(input.expectedNamespaceId))
  ) fail('invalid_input', 'validate', 'not_sent', progress);
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
      `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${input.accountId}/workers/durable_objects/namespaces?page=${page}&per_page=${NAMESPACE_PAGE_SIZE}`,
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

    const remaining = (expectedTotalCount as number) - observedCount;
    const expectedPageCount = Math.max(0, Math.min(NAMESPACE_PAGE_SIZE, remaining));
    if (parsed.count !== expectedPageCount) fail('provider_mismatch', 'namespace_verify', 'unknown', progress);
    for (const item of parsed.items) {
      if (seenIds.has(item.id)) fail('recovery_ambiguous', 'namespace_verify', 'unknown', progress);
      seenIds.add(item.id);
      if (item.script === input.workerName && item.className === input.className) identityMatches.push(item);
    }
    observedCount += parsed.count;
    const lastPage = expectedTotalPages === 0 ? 1 : expectedTotalPages as number;
    if (page === lastPage) break;
    if (page >= (expectedTotalPages as number)) fail('provider_mismatch', 'namespace_verify', 'unknown', progress);
  }

  if (expectedTotalCount === null || observedCount !== expectedTotalCount) {
    fail('provider_mismatch', 'namespace_verify', 'unknown', progress);
  }
  if (identityMatches.length === 0) fail('provider_mismatch', 'namespace_verify', 'unknown', progress);
  if (identityMatches.length > 1) fail('recovery_ambiguous', 'namespace_verify', 'unknown', progress);
  const match = identityMatches[0];
  if (!match.useSqlite || (input.expectedNamespaceId !== undefined && match.id !== input.expectedNamespaceId)) {
    fail('provider_mismatch', 'namespace_verify', 'unknown', progress);
  }
  return Object.freeze({
    accountId: input.accountId,
    namespaceId: match.id,
    namespaceName: match.name,
    workerName: input.workerName,
    className: 'AdminState',
    storage: 'sqlite',
  });
}

function parseAssetSession(
  value: unknown,
  knownHashes: ReadonlySet<string>,
): { readonly jwt: string; readonly buckets: readonly (readonly string[])[] } | null {
  if (!isRecord(value) || !exactKeys(value, ['buckets', 'jwt']) || !safeToken(value.jwt) || !Array.isArray(value.buckets)) {
    return null;
  }
  const seen = new Set<string>();
  const buckets: string[][] = [];
  for (const bucket of value.buckets) {
    if (!Array.isArray(bucket) || bucket.length === 0) return null;
    const parsed: string[] = [];
    for (const hash of bucket) {
      if (typeof hash !== 'string' || !ASSET_HASH_PATTERN.test(hash) || !knownHashes.has(hash) || seen.has(hash)) {
        return null;
      }
      seen.add(hash);
      parsed.push(hash);
    }
    buckets.push(parsed);
  }
  return { jwt: value.jwt, buckets };
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

function assetManifest(prepared: PreparedVerifiedWorkerRelease): {
  readonly manifest: Record<string, { readonly hash: string; readonly size: number }>;
  readonly assetsByHash: Map<string, PreparedAsset>;
} {
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
  if (
    !isRecord(intent) ||
    intent.kind !== 'asset_session' ||
    !ACCOUNT_ID_PATTERN.test(intent.accountId) ||
    !WORKER_NAME_PATTERN.test(intent.workerName) ||
    !SHA256_PATTERN.test(intent.requestHash) ||
    !isRecord(intent.body) ||
    !exactKeys(intent.body, ['manifest']) ||
    !isRecord(intent.body.manifest) ||
    Object.keys(intent.body.manifest).length === 0
  ) return false;
  for (const [path, entry] of Object.entries(intent.body.manifest)) {
    if (
      !safeAssetPath(path) ||
      !isRecord(entry) ||
      !exactKeys(entry, ['hash', 'size']) ||
      typeof entry.hash !== 'string' ||
      !ASSET_HASH_PATTERN.test(entry.hash) ||
      typeof entry.size !== 'number' ||
      !Number.isSafeInteger(entry.size) ||
      entry.size <= 0 ||
      entry.size > MAX_FILE_BYTES
    ) return false;
  }
  try {
    return await sha256(canonicalJson(intent.body)) === intent.requestHash;
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
): Omit<AssetBucketMutationIntent, 'kind' | 'requestHash'> {
  return {
    accountId: session.accountId,
    workerName: session.workerName,
    sessionRequestHash: session.requestHash,
    bucketIndex,
    bucketCount: session.buckets.length,
    hashes: [...session.buckets[bucketIndex]],
    isFinal: bucketIndex === session.buckets.length - 1,
  };
}

function validAssetSessionSubmission(session: AssetUploadSessionSubmission): boolean {
  if (
    !isRecord(session) ||
    session.kind !== 'asset_session' ||
    !ACCOUNT_ID_PATTERN.test(session.accountId) ||
    !WORKER_NAME_PATTERN.test(session.workerName) ||
    !SHA256_PATTERN.test(session.requestHash) ||
    !safeToken(session.uploadJwt) ||
    !Array.isArray(session.buckets) ||
    session.buckets.length === 0 ||
    session.buckets.length > 10_000
  ) return false;
  const seen = new Set<string>();
  for (const bucket of session.buckets) {
    if (!Array.isArray(bucket) || bucket.length === 0 || bucket.length > 10_000) return false;
    for (const hash of bucket) {
      if (
        typeof hash !== 'string' ||
        !ASSET_HASH_PATTERN.test(hash) ||
        seen.has(hash)
      ) return false;
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
  if (
    core.hashes.length === 0 ||
    core.hashes.some((hash) => typeof hash !== 'string' || !ASSET_HASH_PATTERN.test(hash)) ||
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
  if (
    !isRecord(intent) ||
    intent.kind !== 'asset_bucket' ||
    !ACCOUNT_ID_PATTERN.test(intent.accountId) ||
    !WORKER_NAME_PATTERN.test(intent.workerName) ||
    !SHA256_PATTERN.test(intent.sessionRequestHash) ||
    !SHA256_PATTERN.test(intent.requestHash) ||
    intent.accountId !== session.accountId ||
    intent.workerName !== session.workerName ||
    intent.sessionRequestHash !== session.requestHash ||
    !Number.isSafeInteger(intent.bucketIndex) ||
    intent.bucketIndex < 0 ||
    intent.bucketIndex >= session.buckets.length ||
    intent.bucketCount !== session.buckets.length ||
    intent.isFinal !== (intent.bucketIndex === session.buckets.length - 1) ||
    !canonicalEqual(intent.hashes, session.buckets[intent.bucketIndex])
  ) return false;
  try {
    return await sha256(canonicalJson(assetBucketCore(session, intent.bucketIndex))) === intent.requestHash;
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
    const bucket = session.buckets[index];
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
  readonly semanticCommitment: Readonly<Record<string, unknown>>;
  /** Ephemeral only: contains provider credentials and must NEVER be journaled. */
  readonly body: Record<string, unknown>;
}

export interface WorkerVersionMutationPlan {
  /** Submit directly, then discard. This value is intentionally not journal-safe. */
  readonly ephemeral: WorkerVersionSubmitIntent;
  /** Persist this record before POST; it is the only restart input for version recovery. */
  readonly recovery: WorkerVersionRecoveryRecord;
}

function exactExports(value: unknown): boolean {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value).sort();
  if (!(keys.length === 1 || (keys.length === 2 && keys[0] === 'AdminState' && keys[1] === 'default'))) {
    return false;
  }
  const admin = value.AdminState;
  if (
    !isRecord(admin) ||
    !(
      exactKeys(admin, ['storage', 'type']) ||
      exactKeys(admin, ['state', 'storage', 'type'])
    ) ||
    admin.type !== 'durable-object' ||
    admin.storage !== 'sqlite' ||
    !(admin.state === undefined || admin.state === 'created')
  ) return false;
  if (value.default !== undefined) {
    const defaultExport = value.default;
    if (!isRecord(defaultExport)) return false;
    const allowed = new Set(['cache', 'state', 'type']);
    if (Object.keys(defaultExport).some((key) => !allowed.has(key))) return false;
    if (
      defaultExport.type !== 'worker' ||
      !(defaultExport.state === undefined || defaultExport.state === 'created')
    ) return false;
    if (defaultExport.cache !== undefined) {
      if (!isRecord(defaultExport.cache) || !exactKeys(defaultExport.cache, ['enabled']) || defaultExport.cache.enabled !== false) {
        return false;
      }
    }
  }
  return true;
}

function exactExportsReconciliation(value: unknown): boolean {
  if (!isRecord(value)) return false;
  const expected = [
    'created',
    'deleted',
    'info',
    'removable_entries',
    'renamed',
    'transfer_pending',
    'transferred',
    'updated',
    'warnings',
  ];
  if (!exactKeys(value, expected)) return false;
  return Array.isArray(value.created) &&
    value.created.length <= 1 &&
    (value.created.length === 0 || value.created[0] === 'AdminState') &&
    expected.slice(1).every((key) => Array.isArray(value[key]) && (value[key] as unknown[]).length === 0);
}

function exactVersionAnnotations(value: unknown, correlationTag: string): boolean {
  if (!isRecord(value)) return false;
  const allowed = new Set(['workers/message', 'workers/tag', 'workers/triggered_by']);
  if (Object.keys(value).some((key) => !allowed.has(key))) return false;
  if (value['workers/tag'] !== correlationTag) return false;
  return ['workers/message', 'workers/triggered_by'].every((key) => (
    value[key] === undefined || (
      typeof value[key] === 'string' && value[key].length > 0 && value[key].length <= 256
    )
  ));
}

async function exactVersionResult(
  value: unknown,
  recovery: WorkerVersionRecoveryRecord,
  expectedVersionId: string,
  expectedNamespaceId?: string,
  requireModuleContent = false,
): Promise<boolean> {
  if (
    !isRecord(value) ||
    // Live version read-back (2026-08-23) also carries env, source, and urls,
    // and omits compatibility_flags, assets, exports_reconciliation, and
    // modules when they are empty or not yet reconciled.
    Object.keys(value).some((key) => ![
      'annotations',
      'assets',
      'bindings',
      'compatibility_date',
      'compatibility_flags',
      'created_on',
      'env',
      'exports',
      'exports_reconciliation',
      'id',
      'limits',
      'main_module',
      'modules',
      'number',
      'placement',
      'source',
      'startup_time_ms',
      'urls',
      'usage_model',
    ].includes(key)) ||
    value.id !== expectedVersionId ||
    !safeIsoDate(value.created_on) ||
    typeof value.number !== 'number' ||
    !Number.isSafeInteger(value.number) ||
    value.number < 1
  ) return false;
  if (
    value.compatibility_date !== EXACT_COMPATIBILITY_DATE ||
    !(value.compatibility_flags === undefined ||
      (Array.isArray(value.compatibility_flags) && value.compatibility_flags.length === 0)) ||
    value.main_module !== 'index.js' ||
    Object.hasOwn(value, 'migrations') ||
    Object.hasOwn(value, 'migration_tag') ||
    (recovery.phase === 'provision'
      ? Object.hasOwn(value, 'assets')
      : !isRecord(value.assets) ||
        !exactKeys(value.assets, ['config']) ||
        !isRecord((value.assets as { config?: unknown }).config) ||
        Object.keys((value.assets as { config: Record<string, unknown> }).config).some(
          (key) => !['html_handling', 'not_found_handling', 'run_worker_first'].includes(key),
        ) ||
        ((value.assets as { config: Record<string, unknown> }).config.html_handling !== undefined && (value.assets as { config: Record<string, unknown> }).config.html_handling !== 'auto-trailing-slash') ||
        (value.assets as { config: Record<string, unknown> }).config.not_found_handling !== 'single-page-application' ||
        !Array.isArray((value.assets as { config: Record<string, unknown> }).config.run_worker_first) ||
        ((value.assets as { config: { run_worker_first: unknown[] } }).config.run_worker_first).length !== EXACT_RUN_WORKER_FIRST.length ||
        !((value.assets as { config: { run_worker_first: unknown[] } }).config.run_worker_first).every((route, index) => route === EXACT_RUN_WORKER_FIRST[index])) ||
    !Array.isArray(value.bindings) ||
    value.bindings.length !== recovery.plainTextBindingHashes.length + (recovery.phase === 'bootstrap' ? 3 : recovery.phase === 'clean' ? 2 : 0) ||
    !Array.isArray(value.modules) ||
    value.modules.length !== recovery.modules.length ||
    !exactVersionAnnotations(value.annotations, recovery.correlationTag) ||
    !exactExports(value.exports) ||
    // Declarative exports are reconciled by the deployment, so the field is
    // absent on a version that has not been deployed yet.
    !(value.exports_reconciliation === undefined || exactExportsReconciliation(value.exports_reconciliation))
  ) return false;
  if (value.source !== undefined && value.source !== 'api') return false;
  if (value.urls !== undefined && !Array.isArray(value.urls)) return false;
  if (value.env !== undefined && !isRecord(value.env)) return false;

  if (
    value.usage_model !== undefined &&
    !(typeof value.usage_model === 'string' && value.usage_model.length > 0 && value.usage_model.length <= 128)
  ) return false;
  if (
    value.startup_time_ms !== undefined &&
    !(typeof value.startup_time_ms === 'number' && Number.isFinite(value.startup_time_ms) && value.startup_time_ms >= 0)
  ) return false;
  if (value.limits !== undefined) {
    if (
      !isRecord(value.limits) ||
      Object.keys(value.limits).some((key) => key !== 'cpu_ms') ||
      (value.limits.cpu_ms !== undefined && (
        typeof value.limits.cpu_ms !== 'number' ||
        !Number.isSafeInteger(value.limits.cpu_ms) ||
        value.limits.cpu_ms < 0
      ))
    ) return false;
  }
  if (value.placement !== undefined) {
    if (
      !isRecord(value.placement) ||
      Object.keys(value.placement).some((key) => !['hint', 'mode'].includes(key)) ||
      (value.placement.mode !== undefined && typeof value.placement.mode !== 'string') ||
      (value.placement.hint !== undefined && typeof value.placement.hint !== 'string')
    ) return false;
  }

  const returnedBindings = new Map<string, unknown>();
  for (const binding of value.bindings) {
    if (!isRecord(binding) || typeof binding.name !== 'string' || returnedBindings.has(binding.name)) return false;
    returnedBindings.set(binding.name, binding);
  }
  if (recovery.phase === 'provision') {
    if (returnedBindings.has('ADMIN_STATE') || returnedBindings.has('ASSETS')) return false;
  } else {
    const adminBinding = returnedBindings.get('ADMIN_STATE');
    if (
      !isRecord(adminBinding) ||
      adminBinding.type !== 'durable_object_namespace' ||
      adminBinding.class_name !== 'AdminState' ||
      Object.keys(adminBinding).some((key) => !['class_name', 'name', 'namespace_id', 'type'].includes(key)) ||
      (adminBinding.namespace_id !== undefined && !(
        typeof adminBinding.namespace_id === 'string' && ACCOUNT_ID_PATTERN.test(adminBinding.namespace_id)
      )) ||
      (expectedNamespaceId !== undefined && adminBinding.namespace_id !== undefined &&
        adminBinding.namespace_id !== expectedNamespaceId)
    ) return false;
    const assetsBinding = returnedBindings.get('ASSETS');
    if (!isRecord(assetsBinding) || !exactKeys(assetsBinding, ['name', 'type']) || assetsBinding.type !== 'assets') {
      return false;
    }
  }
  const redactedBinding = returnedBindings.get('ANKKA_BOOTSTRAP_NONCE');
  if (recovery.phase === 'bootstrap') {
    if (
      !isRecord(redactedBinding) ||
      !exactKeys(redactedBinding, ['name', 'type']) ||
      redactedBinding.type !== 'secret_text'
    ) return false;
  } else if (redactedBinding !== undefined) return false;
  for (const expected of recovery.plainTextBindingHashes) {
    const binding = returnedBindings.get(expected.name);
    if (
      !isRecord(binding) ||
      !exactKeys(binding, ['name', 'text', 'type']) ||
      binding.type !== 'plain_text' ||
      typeof binding.text !== 'string' ||
      await sha256(binding.text) !== expected.valueSha256
    ) return false;
  }

  const returnedModules = new Map<string, unknown>();
  for (const module of value.modules) {
    if (!isRecord(module) || typeof module.name !== 'string' || returnedModules.has(module.name)) return false;
    returnedModules.set(module.name, module);
  }
  for (const module of recovery.modules) {
    const returned = returnedModules.get(module.name);
    if (!isRecord(returned)) return false;
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

function versionSemanticCommitment(input: WorkerVersionSemanticInput): Record<string, unknown> {
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
  const releaseContract = Object.freeze({
    assetBinding: 'ASSETS' as const,
    assetConfig: Object.freeze({
      notFoundHandling: 'single-page-application' as const,
      runWorkerFirst: EXACT_RUN_WORKER_FIRST,
    }),
    bootstrapBinding: phase === 'bootstrap' ? 'present' as const : 'absent' as const,
    compatibilityDate: EXACT_COMPATIBILITY_DATE,
    compatibilityFlags: Object.freeze([]) as readonly [],
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
  const coreBody = {
    ...(phase === 'provision' ? {} : {
      assets: {
        config: {
          not_found_handling: 'single-page-application',
          run_worker_first: [...EXACT_RUN_WORKER_FIRST],
        },
        jwt: completionJwt as string,
      },
    }),
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
  value: unknown,
  phase: WorkerVersionPhase,
): value is WorkerVersionRecoveryRecord['releaseContract'] {
  if (!isRecord(value) || !exactKeys(value, [
    'assetBinding',
    'assetConfig',
    'bootstrapBinding',
    'compatibilityDate',
    'compatibilityFlags',
    'durableObject',
    'exports',
    'mainModule',
  ])) return false;
  if (
    value.assetBinding !== 'ASSETS' ||
    !isRecord(value.assetConfig) ||
    !exactKeys(value.assetConfig, ['notFoundHandling', 'runWorkerFirst']) ||
    value.assetConfig.notFoundHandling !== 'single-page-application' ||
    !Array.isArray(value.assetConfig.runWorkerFirst) ||
    value.assetConfig.runWorkerFirst.length !== EXACT_RUN_WORKER_FIRST.length ||
    !value.assetConfig.runWorkerFirst.every((route, index) => route === EXACT_RUN_WORKER_FIRST[index]) ||
    value.bootstrapBinding !== (phase === 'bootstrap' ? 'present' : 'absent') ||
    value.compatibilityDate !== EXACT_COMPATIBILITY_DATE ||
    !Array.isArray(value.compatibilityFlags) ||
    value.compatibilityFlags.length !== 0 ||
    !canonicalEqual(value.durableObject, {
      binding: 'ADMIN_STATE', className: 'AdminState', storage: 'sqlite',
    }) ||
    !canonicalEqual(value.exports, {
      AdminState: { type: 'durable-object', storage: 'sqlite' },
    }) ||
    value.mainModule !== 'index.js'
  ) return false;
  return true;
}

async function validVersionRecoveryRecord(recovery: WorkerVersionRecoveryRecord): Promise<boolean> {
  if (
    !isRecord(recovery) ||
    !exactKeys(recovery, [
      'accountId',
      'assets',
      'correlationTag',
      'kind',
      'modules',
      'phase',
      'plainTextBindingHashes',
      'releaseContract',
      'requestHash',
      'workerId',
      'workerName',
    ]) ||
    recovery.kind !== 'version_recovery' ||
    (recovery.phase !== 'provision' && recovery.phase !== 'bootstrap' && recovery.phase !== 'clean') ||
    !ACCOUNT_ID_PATTERN.test(recovery.accountId) ||
    !WORKER_NAME_PATTERN.test(recovery.workerName) ||
    !WORKER_ID_PATTERN.test(recovery.workerId) ||
    !SHA256_PATTERN.test(recovery.requestHash) ||
    recovery.correlationTag !== versionCorrelationTag(recovery.phase, recovery.requestHash) ||
    !validVersionReleaseContract(recovery.releaseContract, recovery.phase) ||
    !Array.isArray(recovery.assets) ||
    recovery.assets.length === 0 ||
    recovery.assets.length > 10_000 ||
    !Array.isArray(recovery.plainTextBindingHashes) ||
    recovery.plainTextBindingHashes.length !== EXACT_PLAIN_TEXT_BINDINGS.length ||
    !Array.isArray(recovery.modules) ||
    recovery.modules.length === 0 ||
    hasSecretRecoverySerialization(recovery)
  ) return false;
  let totalBytes = 0;
  let previousAssetPath = '';
  const contentTypesByHash = new Map<string, string>();
  for (const asset of recovery.assets) {
    if (
      !isRecord(asset) ||
      !exactKeys(asset, ['byteLength', 'contentType', 'path', 'uploadHash']) ||
      !safeAssetPath(asset.path) ||
      (previousAssetPath !== '' && previousAssetPath >= asset.path) ||
      asset.contentType !== ASSET_CONTENT_TYPES[extension(asset.path)] ||
      typeof asset.uploadHash !== 'string' ||
      !ASSET_HASH_PATTERN.test(asset.uploadHash) ||
      typeof asset.byteLength !== 'number' ||
      !Number.isSafeInteger(asset.byteLength) ||
      asset.byteLength <= 0 ||
      asset.byteLength > MAX_FILE_BYTES
    ) return false;
    const priorContentType = contentTypesByHash.get(asset.uploadHash);
    if (priorContentType !== undefined && priorContentType !== asset.contentType) return false;
    contentTypesByHash.set(asset.uploadHash, asset.contentType);
    totalBytes += asset.byteLength;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_RELEASE_BYTES) return false;
    previousAssetPath = asset.path;
  }
  for (let index = 0; index < recovery.plainTextBindingHashes.length; index += 1) {
    const binding = recovery.plainTextBindingHashes[index];
    if (
      !isRecord(binding) ||
      !exactKeys(binding, ['name', 'valueSha256']) ||
      binding.name !== EXACT_PLAIN_TEXT_BINDINGS[index] ||
      typeof binding.valueSha256 !== 'string' ||
      !SHA256_PATTERN.test(binding.valueSha256)
    ) return false;
  }
  const names = new Set<string>();
  let previousModuleName = '';
  for (const module of recovery.modules) {
    if (
      !isRecord(module) ||
      !exactKeys(module, ['byteLength', 'contentSha256', 'contentType', 'name']) ||
      !safeModuleName(module.name) ||
      names.has(module.name) ||
      (previousModuleName !== '' && previousModuleName >= module.name) ||
      module.contentType !== MODULE_CONTENT_TYPES[extension(module.name)] ||
      typeof module.contentSha256 !== 'string' ||
      !SHA256_PATTERN.test(module.contentSha256) ||
      typeof module.byteLength !== 'number' ||
      !Number.isSafeInteger(module.byteLength) ||
      module.byteLength <= 0 ||
      module.byteLength > MAX_FILE_BYTES
    ) return false;
    totalBytes += module.byteLength;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_RELEASE_BYTES) return false;
    names.add(module.name);
    previousModuleName = module.name;
  }
  if (!names.has('index.js')) return false;
  try {
    return await versionSemanticHash(recovery) === recovery.requestHash;
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
export async function parseWorkerVersionRecoveryRecord(
  value: unknown,
): Promise<WorkerVersionRecoveryRecord | null> {
  try {
    if (!await validVersionRecoveryRecord(value as WorkerVersionRecoveryRecord)) return null;
    const input = value as WorkerVersionRecoveryRecord;
    const phase = input.phase;
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
        compatibilityFlags: Object.freeze([]) as readonly [],
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
  if (
    !await validVersionRecoveryRecord(recovery) ||
    !isRecord(intent) ||
    !exactKeys(intent, [
      'accountId', 'body', 'correlationTag', 'kind', 'phase', 'requestHash', 'semanticCommitment',
      'workerId', 'workerName',
    ]) ||
    intent.kind !== 'version_submit' ||
    intent.phase !== recovery.phase ||
    intent.accountId !== recovery.accountId ||
    intent.workerName !== recovery.workerName ||
    intent.workerId !== recovery.workerId ||
    intent.requestHash !== recovery.requestHash ||
    intent.correlationTag !== recovery.correlationTag ||
    !canonicalEqual(intent.semanticCommitment, versionSemanticCommitment(recovery)) ||
    !isRecord(intent.body) ||
    !isRecord(intent.body.annotations) ||
    !exactKeys(intent.body.annotations, ['workers/tag']) ||
    intent.body.annotations['workers/tag'] !== intent.correlationTag ||
    !exactKeys(intent.body, recovery.phase === 'provision'
      ? ['annotations', 'bindings', 'compatibility_date', 'compatibility_flags', 'exports', 'main_module', 'modules']
      : ['annotations', 'assets', 'bindings', 'compatibility_date', 'compatibility_flags', 'exports', 'main_module', 'modules']) ||
    !Array.isArray(intent.body.bindings) ||
    intent.body.bindings.length !== recovery.plainTextBindingHashes.length + (recovery.phase === 'bootstrap' ? 3 : recovery.phase === 'clean' ? 2 : 0) ||
    !Array.isArray(intent.body.modules) ||
    intent.body.modules.length !== recovery.modules.length ||
    intent.body.compatibility_date !== recovery.releaseContract.compatibilityDate ||
    !Array.isArray(intent.body.compatibility_flags) ||
    intent.body.compatibility_flags.length !== 0 ||
    intent.body.main_module !== 'index.js' ||
    !canonicalEqual(intent.body.exports, recovery.releaseContract.exports) ||
    // The provision version carries no ASSETS binding and no asset session.
    (recovery.phase === 'provision'
      ? Object.hasOwn(intent.body, 'assets')
      : !isRecord(intent.body.assets) ||
        !exactKeys(intent.body.assets, ['config', 'jwt']) ||
        !safeToken((intent.body.assets as { jwt?: unknown }).jwt) ||
        !isRecord((intent.body.assets as { config?: unknown }).config) ||
        !exactKeys((intent.body.assets as { config: Record<string, unknown> }).config, ['not_found_handling', 'run_worker_first']) ||
        (intent.body.assets as { config: Record<string, unknown> }).config.not_found_handling !== recovery.releaseContract.assetConfig.notFoundHandling ||
        !Array.isArray((intent.body.assets as { config: Record<string, unknown> }).config.run_worker_first) ||
        ((intent.body.assets as { config: { run_worker_first: unknown[] } }).config.run_worker_first).length !== recovery.releaseContract.assetConfig.runWorkerFirst.length ||
        !((intent.body.assets as { config: { run_worker_first: unknown[] } }).config.run_worker_first).every(
          (route, index) => route === recovery.releaseContract.assetConfig.runWorkerFirst[index],
        ))
  ) return false;
  const bindings = new Map<string, unknown>();
  for (const binding of intent.body.bindings) {
    if (!isRecord(binding) || typeof binding.name !== 'string' || bindings.has(binding.name)) return false;
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
    if (
      !isRecord(redactedBinding) ||
      !exactKeys(redactedBinding, ['name', 'text', 'type']) ||
      redactedBinding.type !== 'secret_text' ||
      !safeToken(redactedBinding.text, 32)
    ) return false;
  } else if (redactedBinding !== undefined) return false;
  for (const expected of recovery.plainTextBindingHashes) {
    const binding = bindings.get(expected.name);
    if (
      !isRecord(binding) ||
      !exactKeys(binding, ['name', 'text', 'type']) ||
      binding.type !== 'plain_text' ||
      typeof binding.text !== 'string' ||
      await sha256(binding.text) !== expected.valueSha256
    ) return false;
  }
  for (let index = 0; index < intent.body.modules.length; index += 1) {
    const module = intent.body.modules[index];
    const metadata = recovery.modules[index];
    if (
      !isRecord(module) ||
      !exactKeys(module, ['content_base64', 'content_type', 'name']) ||
      !isRecord(metadata) ||
      module.name !== metadata.name ||
      module.content_type !== metadata.contentType ||
      strictBase64Bytes(module.content_base64, metadata.byteLength) === null
    ) return false;
    const bytes = strictBase64Bytes(module.content_base64, metadata.byteLength);
    if (!bytes || await sha256(bytes) !== metadata.contentSha256) return false;
  }
  try {
    return await sha256(canonicalJson(intent.semanticCommitment)) === intent.requestHash;
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

function parseVersionListPage(
  value: unknown,
  expectedPage: number,
): { readonly items: readonly unknown[]; readonly totalCount: number; readonly totalPages: number } | null {
  if (!isRecord(value) || !exactKeys(value, ['errors', 'messages', 'result', 'result_info', 'success'])) return null;
  if (value.success !== true || !isEmptyProviderList(value.errors) || !isEmptyProviderList(value.messages)) return null;
  if (!Array.isArray(value.result) || !isRecord(value.result_info)) return null;
  const info = value.result_info;
  const allowed = new Set(['count', 'page', 'per_page', 'total_count', 'total_pages']);
  if (Object.keys(info).some((key) => !allowed.has(key))) return null;
  // Live (2026-08-23): the version list omits total_pages entirely. When it is
  // absent the page count is derived from the totals actually reported.
  const totalPages = info.total_pages === undefined
    ? (info.total_count === 0 ? 0 : Math.ceil(info.total_count as number))
    : info.total_pages;
  if (
    info.page !== expectedPage ||
    info.per_page !== 1 ||
    info.count !== value.result.length ||
    typeof info.count !== 'number' ||
    !Number.isSafeInteger(info.count) ||
    typeof info.total_count !== 'number' ||
    !Number.isSafeInteger(info.total_count) ||
    info.total_count < 0 ||
    typeof totalPages !== 'number' ||
    !Number.isSafeInteger(totalPages) ||
    totalPages < 0 ||
    totalPages > 100 ||
    totalPages !== (info.total_count === 0 ? 0 : Math.ceil(info.total_count)) ||
    (totalPages === 0 && (expectedPage !== 1 || value.result.length !== 0)) ||
    value.result.length > 1
  ) return null;
  return { items: value.result, totalCount: info.total_count, totalPages };
}

function versionItemTag(value: unknown): { readonly id: string; readonly tag: string | null } | null {
  if (!isRecord(value) || typeof value.id !== 'string' || !UUID_PATTERN.test(value.id)) return null;
  const allowed = new Set([
    'annotations',
    'assets',
    'bindings',
    'compatibility_date',
    'compatibility_flags',
    'created_on',
    'exports',
    'exports_reconciliation',
    'id',
    'limits',
    'main_module',
    'modules',
    'number',
    'placement',
    'startup_time_ms',
    'usage_model',
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key))) return null;
  if (value.annotations === undefined) return { id: value.id, tag: null };
  if (!isRecord(value.annotations)) return null;
  if (Object.keys(value.annotations).some(
    (key) => !['workers/message', 'workers/tag', 'workers/triggered_by'].includes(key),
  )) return null;
  const tag = value.annotations['workers/tag'];
  if (!(tag === undefined || typeof tag === 'string')) return null;
  return { id: value.id, tag: typeof tag === 'string' ? tag : null };
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
  const submission = versionSubmission(recovery, matches[0]);
  return await verifyWorkerVersionSubmission(recovery, submission, callInput);
}

function deploymentAnnotations(value: unknown): Record<string, unknown> | null {
  if (!isRecord(value)) return null;
  const allowed = new Set(['workers/message', 'workers/triggered_by']);
  if (Object.keys(value).some((key) => !allowed.has(key))) return null;
  for (const key of allowed) {
    const entry = value[key];
    if (entry !== undefined && !(
      typeof entry === 'string' && entry.length > 0 && entry.length <= 256
    )) return null;
  }
  return value;
}

function validDeploymentShape(value: unknown): value is Record<string, unknown> {
  if (!isRecord(value)) return false;
  const allowed = new Set(['annotations', 'author_email', 'created_on', 'id', 'source', 'strategy', 'versions']);
  if (Object.keys(value).some((key) => !allowed.has(key))) return false;
  if (
    !UUID_PATTERN.test(String(value.id)) ||
    !safeIsoDate(value.created_on) ||
    value.source !== 'api' ||
    value.strategy !== 'percentage' ||
    (value.author_email !== undefined && !(
      typeof value.author_email === 'string' &&
      value.author_email.length > 0 &&
      value.author_email.length <= 320
    )) ||
    (value.annotations !== undefined && deploymentAnnotations(value.annotations) === null) ||
    !Array.isArray(value.versions) ||
    value.versions.length === 0 ||
    value.versions.length > 100
  ) return false;
  let total = 0;
  const versionIds = new Set<string>();
  for (const version of value.versions) {
    if (
      !isRecord(version) ||
      !exactKeys(version, ['percentage', 'version_id']) ||
      typeof version.version_id !== 'string' ||
      !UUID_PATTERN.test(version.version_id) ||
      versionIds.has(version.version_id) ||
      typeof version.percentage !== 'number' ||
      !Number.isFinite(version.percentage) ||
      version.percentage <= 0 ||
      version.percentage > 100
    ) return false;
    versionIds.add(version.version_id);
    total += version.percentage;
  }
  return total === 100;
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
  value: unknown,
  intent: WorkerDeploymentMutationIntent,
  expectedDeploymentId: string,
): value is Record<string, unknown> {
  if (!validDeploymentShape(value) || value.id !== expectedDeploymentId) return false;
  if (!isRecord(value.annotations) || value.annotations['workers/message'] !== intent.correlationTag) return false;
  const versions = value.versions as readonly unknown[];
  return versions.length === 1 &&
    isRecord(versions[0]) &&
    versions[0].percentage === 100 &&
    versions[0].version_id === intent.versionId;
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
      if (!validDeploymentShape(deployment)) {
        fail('provider_mismatch', 'deployment_active_verify', 'submitted', progress, [submission]);
      }
      const deploymentId = String(deployment.id);
      if (seenIds.has(deploymentId)) {
        fail('provider_mismatch', 'deployment_active_verify', 'submitted', progress, [submission]);
      }
      seenIds.add(deploymentId);
      const annotations = deploymentAnnotations(deployment.annotations);
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
  if (!deployments || !validDeploymentShape(active) || !Array.isArray(active.versions) ||
    active.versions.length !== 1) {
    fail('provider_mismatch', 'deployment_active_verify', 'unknown', progress);
  }
  const activeVersion = (active.versions as readonly unknown[])[0];
  if (!isRecord(activeVersion) || activeVersion.percentage !== 100) {
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

function parseDeploymentList(value: unknown): readonly unknown[] | null {
  const result = parseSuccessEnvelope(value);
  if (!isRecord(result) || !exactKeys(result, ['deployments']) || !Array.isArray(result.deployments)) return null;
  if (result.deployments.length > 1_000) return null;
  return result.deployments;
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
    if (!validDeploymentShape(deployment)) {
      fail('provider_mismatch', 'deployment_recovery', 'unknown', progress);
    }
    const annotations = deploymentAnnotations(deployment.annotations);
    if (annotations?.['workers/message'] === intent.correlationTag) matches.push(String(deployment.id));
  }
  if (matches.length === 0) return null;
  if (matches.length !== 1) fail('recovery_ambiguous', 'deployment_recovery', 'unknown', progress);
  return await verifyWorkerDeploymentSubmission(intent, deploymentSubmission(intent, matches[0]), callInput);
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
