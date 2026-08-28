import { REQUIRED_OAUTH_SCOPES } from './constants';
import { DeployError } from './errors';

const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const RELEASE_PATTERN = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const COMMIT_PATTERN = /^[a-f0-9]{40}$/u;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;

export const MAX_RELEASE_FILE_BYTES = 8 * 1024 * 1024;
export const MAX_RELEASE_PAYLOAD_BYTES = 32 * 1024 * 1024;
export const MAX_CANONICAL_MANIFEST_BYTES = 8 * 1024 * 1024;

const WORKER_CONTENT_TYPES: Readonly<Record<string, string>> = Object.freeze({
  '.js': 'application/javascript+module',
  '.mjs': 'application/javascript+module',
  '.wasm': 'application/wasm',
});

const WEB_ASSET_CONTENT_TYPES: Readonly<Record<string, string>> = Object.freeze({
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

export const APPROVED_CLOUDFLARE_RELEASE_CONTRACT = Object.freeze({
  assets: Object.freeze({
    binding: 'ASSETS',
    notFoundHandling: 'single-page-application',
    payloadDirectory: 'payload/admin',
    runWorkerFirst: Object.freeze(['/__ankka/*', '/api/*']),
  }),
  compatibilityDate: '2026-08-08',
  compatibilityFlags: Object.freeze([]),
  dependenciesInstrumentation: Object.freeze({ enabled: false }),
  durableObjects: Object.freeze({
    bindings: Object.freeze([
      Object.freeze({ binding: 'ADMIN_STATE', className: 'AdminState' }),
    ]),
    exports: Object.freeze({
      AdminState: Object.freeze({ storage: 'sqlite', type: 'durable-object' }),
    }),
  }),
  mainModule: 'index.js',
  observability: Object.freeze({ enabled: false }),
  previewUrls: false,
  publicBindings: Object.freeze({
    secrets: Object.freeze([
      Object.freeze({ lifecycle: 'bootstrap-only', name: 'ANKKA_BOOTSTRAP_NONCE' }),
    ]),
    variables: Object.freeze([
      'ADMIN_EMAILS',
      'ANKKA_GATEWAY_RELEASE',
      'ANKKA_GATEWAY_RELEASE_SHA256',
      'CF_ACCESS_AUD',
      'CF_ACCESS_ISSUER',
      'CLOUDFLARE_ACCOUNT_ID',
      'CLOUDFLARE_ZONE_ID',
      'CLOUDFLARE_ZONE_NAME',
      'ANKKA_UPDATE_CHANNEL',
      'ANKKA_UPDATE_KEY_ID',
      'ANKKA_UPDATE_PUBLIC_KEY',
      'ZERO_TRUST_READY',
    ]),
  }),
  sendMetrics: false,
  workersDev: false,
  workerVariants: Object.freeze({
    cleanup: Object.freeze({
      component: 'workerCleanup',
      compatibilityDate: '2026-08-08',
      compatibilityFlags: Object.freeze([]),
      dependenciesInstrumentation: Object.freeze({ enabled: false }),
      durableObjects: Object.freeze({
        bindings: Object.freeze([
          Object.freeze({ binding: 'ADMIN_STATE', className: 'AdminState' }),
        ]),
        exports: Object.freeze({
          AdminState: Object.freeze({ storage: 'sqlite', type: 'durable-object' }),
        }),
      }),
      mainModule: 'index.js',
      observability: Object.freeze({ enabled: false }),
      payloadDirectory: 'payload/worker-cleanup',
      previewUrls: false,
      publicBindings: Object.freeze({
        secrets: Object.freeze([
          Object.freeze({ lifecycle: 'uninstall-attempt', name: 'ANKKA_UNINSTALL_NONCE' }),
        ]),
        variables: Object.freeze([
          'ANKKA_GATEWAY_RELEASE',
          'ANKKA_GATEWAY_RELEASE_SHA256',
          'CLOUDFLARE_ACCOUNT_ID',
          'CLOUDFLARE_ZONE_ID',
          'CLOUDFLARE_ZONE_NAME',
          'ZERO_TRUST_READY',
        ]),
      }),
      publicPath: '/__ankka/uninstall',
      sendMetrics: false,
      workersDev: false,
    }),
    retirement: Object.freeze({
      component: 'workerRetirement',
      compatibilityDate: '2026-08-08',
      compatibilityFlags: Object.freeze([]),
      dependenciesInstrumentation: Object.freeze({ enabled: false }),
      durableObjects: Object.freeze({
        bindings: Object.freeze([]),
        exports: Object.freeze({
          AdminState: Object.freeze({ state: 'deleted', type: 'durable-object' }),
        }),
      }),
      mainModule: 'index.js',
      observability: Object.freeze({ enabled: false }),
      payloadDirectory: 'payload/worker-retirement',
      previewUrls: false,
      publicBindings: Object.freeze({
        secrets: Object.freeze([]),
        variables: Object.freeze([]),
      }),
      sendMetrics: false,
      workersDev: false,
    }),
  }),
} as const);

export type ReleaseComponentName =
  | 'admin'
  | 'installer'
  | 'worker'
  | 'workerCleanup'
  | 'workerRetirement';

export interface ReleaseFileRecord {
  readonly byteSize: number;
  readonly contentType: string;
  readonly path: string;
  readonly sha256: string;
}

export interface ReleaseComponent {
  readonly byteSize: number;
  readonly fileCount: number;
  readonly files: readonly ReleaseFileRecord[];
  readonly treeSha256: string;
}

export interface ReleaseManifest {
  readonly artifact: {
    readonly byteSize: number;
    readonly fileCount: number;
    readonly treeSha256: string;
  };
  readonly cloudflare: typeof APPROVED_CLOUDFLARE_RELEASE_CONTRACT;
  readonly components: Readonly<Record<ReleaseComponentName, ReleaseComponent>>;
  readonly oauthScopeIds: typeof REQUIRED_OAUTH_SCOPES;
  readonly release: string;
  readonly schemaVersion: 1;
  readonly sourceCommit: string;
}

function invalid(): never {
  throw new DeployError(503, 'release_invalid');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isSafeNonnegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function extension(path: string): string {
  const filename = path.slice(path.lastIndexOf('/') + 1);
  const dot = filename.lastIndexOf('.');
  return dot < 0 ? '' : filename.slice(dot).toLowerCase();
}

function componentPayloadDirectory(component: ReleaseComponentName): string {
  if (component === 'workerCleanup') return 'worker-cleanup';
  if (component === 'workerRetirement') return 'worker-retirement';
  return component;
}

function safePayloadPath(path: unknown, component: ReleaseComponentName): path is string {
  const payloadDirectory = componentPayloadDirectory(component);
  if (
    typeof path !== 'string' ||
    !path.startsWith(`payload/${payloadDirectory}/`) ||
    path.includes('\\') ||
    CONTROL_CHARACTER.test(path)
  ) return false;
  const segments = path.split('/');
  return segments.length >= 3 && segments.every(
    (segment) => segment !== '' && segment !== '.' && segment !== '..',
  );
}

function expectedContentType(component: ReleaseComponentName, path: string): string | undefined {
  const contentTypes = component === 'admin' || component === 'installer'
    ? WEB_ASSET_CONTENT_TYPES
    : WORKER_CONTENT_TYPES;
  return contentTypes[extension(path)];
}

function parseFileRecord(input: unknown, component: ReleaseComponentName): ReleaseFileRecord {
  if (!isRecord(input) || !exactKeys(input, ['byteSize', 'contentType', 'path', 'sha256'])) invalid();
  if (
    !isSafeNonnegativeInteger(input.byteSize) ||
    input.byteSize > MAX_RELEASE_FILE_BYTES ||
    !safePayloadPath(input.path, component) ||
    typeof input.contentType !== 'string' ||
    input.contentType !== expectedContentType(component, input.path) ||
    typeof input.sha256 !== 'string' ||
    !SHA256_PATTERN.test(input.sha256)
  ) invalid();
  return Object.freeze({
    byteSize: input.byteSize,
    contentType: input.contentType,
    path: input.path,
    sha256: input.sha256,
  });
}

function parseComponent(input: unknown, component: ReleaseComponentName): ReleaseComponent {
  if (!isRecord(input) || !exactKeys(input, ['byteSize', 'fileCount', 'files', 'treeSha256'])) invalid();
  if (
    !isSafeNonnegativeInteger(input.byteSize) ||
    input.byteSize > MAX_RELEASE_PAYLOAD_BYTES ||
    !isSafeNonnegativeInteger(input.fileCount) ||
    !Array.isArray(input.files) ||
    typeof input.treeSha256 !== 'string' ||
    !SHA256_PATTERN.test(input.treeSha256)
  ) invalid();
  const files = input.files.map((file) => parseFileRecord(file, component));
  if (files.length !== input.fileCount || files.length === 0) invalid();
  for (let index = 1; index < files.length; index += 1) {
    if (files[index - 1].path >= files[index].path) invalid();
  }
  const byteSize = files.reduce((total, file) => total + file.byteSize, 0);
  if (!Number.isSafeInteger(byteSize) || byteSize !== input.byteSize) invalid();
  const requiredPath = component === 'admin' || component === 'installer'
    ? `payload/${component}/index.html`
    : `payload/${componentPayloadDirectory(component)}/index.js`;
  if (!files.some((file) => file.path === requiredPath)) invalid();
  return Object.freeze({
    byteSize: input.byteSize,
    fileCount: input.fileCount,
    files: Object.freeze(files),
    treeSha256: input.treeSha256,
  });
}

function scopesAreExact(input: unknown): input is typeof REQUIRED_OAUTH_SCOPES {
  return Array.isArray(input) &&
    input.length === REQUIRED_OAUTH_SCOPES.length &&
    input.every((scope, index) => scope === REQUIRED_OAUTH_SCOPES[index]);
}

function cloudflareContractIsExact(input: unknown): input is typeof APPROVED_CLOUDFLARE_RELEASE_CONTRACT {
  try {
    return canonicalJson(input) === canonicalJson(APPROVED_CLOUDFLARE_RELEASE_CONTRACT);
  } catch {
    return false;
  }
}

export function parseReleaseManifest(input: unknown): ReleaseManifest {
  if (!isRecord(input) || !exactKeys(input, [
    'artifact',
    'cloudflare',
    'components',
    'oauthScopeIds',
    'release',
    'schemaVersion',
    'sourceCommit',
  ])) invalid();
  if (
    input.schemaVersion !== 1 ||
    typeof input.release !== 'string' ||
    !RELEASE_PATTERN.test(input.release) ||
    typeof input.sourceCommit !== 'string' ||
    !COMMIT_PATTERN.test(input.sourceCommit) ||
    !scopesAreExact(input.oauthScopeIds) ||
    !cloudflareContractIsExact(input.cloudflare) ||
    !isRecord(input.artifact) ||
    !exactKeys(input.artifact, ['byteSize', 'fileCount', 'treeSha256']) ||
    !isSafeNonnegativeInteger(input.artifact.byteSize) ||
    input.artifact.byteSize > MAX_RELEASE_PAYLOAD_BYTES ||
    !isSafeNonnegativeInteger(input.artifact.fileCount) ||
    typeof input.artifact.treeSha256 !== 'string' ||
    !SHA256_PATTERN.test(input.artifact.treeSha256) ||
    !isRecord(input.components) ||
    !exactKeys(input.components, [
      'admin',
      'installer',
      'worker',
      'workerCleanup',
      'workerRetirement',
    ])
  ) invalid();

  const components = Object.freeze({
    admin: parseComponent(input.components.admin, 'admin'),
    installer: parseComponent(input.components.installer, 'installer'),
    worker: parseComponent(input.components.worker, 'worker'),
    workerCleanup: parseComponent(input.components.workerCleanup, 'workerCleanup'),
    workerRetirement: parseComponent(input.components.workerRetirement, 'workerRetirement'),
  });
  const allFiles = [
    ...components.admin.files,
    ...components.installer.files,
    ...components.worker.files,
    ...components.workerCleanup.files,
    ...components.workerRetirement.files,
  ].sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  const byteSize = allFiles.reduce((total, file) => total + file.byteSize, 0);
  if (
    allFiles.length !== input.artifact.fileCount ||
    byteSize !== input.artifact.byteSize ||
    !Number.isSafeInteger(byteSize)
  ) invalid();
  for (let index = 1; index < allFiles.length; index += 1) {
    if (allFiles[index - 1].path >= allFiles[index].path) invalid();
  }

  return Object.freeze({
    artifact: Object.freeze({
      byteSize: input.artifact.byteSize,
      fileCount: input.artifact.fileCount,
      treeSha256: input.artifact.treeSha256,
    }),
    cloudflare: APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
    components,
    oauthScopeIds: REQUIRED_OAUTH_SCOPES,
    release: input.release,
    schemaVersion: 1,
    sourceCommit: input.sourceCommit,
  });
}

export function parseCanonicalReleaseManifest(serialized: string): ReleaseManifest {
  if (typeof serialized !== 'string') invalid();
  const bytes = new TextEncoder().encode(serialized);
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_CANONICAL_MANIFEST_BYTES) invalid();
  let input: unknown;
  try {
    input = JSON.parse(serialized);
  } catch {
    invalid();
  }
  try {
    if (canonicalJson(input) !== serialized) invalid();
  } catch {
    invalid();
  }
  return parseReleaseManifest(input);
}

export function canonicalJson(value: unknown): string {
  return serializeCanonical(value, new Set<object>());
}

function serializeCanonical(value: unknown, seen: Set<object>): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Canonical JSON requires finite numbers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new TypeError('Canonical JSON does not support cycles');
    seen.add(value);
    const serialized = `[${value.map((entry) => serializeCanonical(entry, seen)).join(',')}]`;
    seen.delete(value);
    return serialized;
  }
  if (isRecord(value) && Object.getPrototypeOf(value) === Object.prototype) {
    if (seen.has(value)) throw new TypeError('Canonical JSON does not support cycles');
    seen.add(value);
    const entries = Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${serializeCanonical(value[key], seen)}`);
    seen.delete(value);
    return `{${entries.join(',')}}`;
  }
  throw new TypeError('Canonical JSON supports only JSON values');
}
