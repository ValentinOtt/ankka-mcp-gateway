import * as v from 'valibot';

import { boundaryObjectSchema } from './boundary';
export { canonicalJson } from './canonical-json';
import { canonicalJson } from './canonical-json';
import { REQUIRED_OAUTH_SCOPES } from './constants';
import { DeployError } from './errors';

const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const RELEASE_PATTERN = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const COMMIT_PATTERN = /^[a-f0-9]{40}$/u;

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

const safeNonnegativeIntegerSchema = v.pipe(
  v.number(),
  v.safeInteger(),
  v.minValue(0),
);
const releaseFileRecordSchema = v.strictObject({
  byteSize: safeNonnegativeIntegerSchema,
  contentType: v.string(),
  path: v.string(),
  sha256: v.string(),
});
const releaseComponentSchema = v.strictObject({
  byteSize: safeNonnegativeIntegerSchema,
  fileCount: safeNonnegativeIntegerSchema,
  files: v.array(releaseFileRecordSchema),
  treeSha256: v.string(),
});
const releaseManifestSchema = v.strictObject({
  artifact: v.strictObject({
    byteSize: safeNonnegativeIntegerSchema,
    fileCount: safeNonnegativeIntegerSchema,
    treeSha256: v.string(),
  }),
  cloudflare: boundaryObjectSchema,
  components: v.strictObject({
    admin: releaseComponentSchema,
    installer: releaseComponentSchema,
    worker: releaseComponentSchema,
    workerCleanup: releaseComponentSchema,
    workerRetirement: releaseComponentSchema,
  }),
  oauthScopeIds: v.array(v.string()),
  release: v.string(),
  schemaVersion: v.literal(1),
  sourceCommit: v.string(),
});
function invalid(): never {
  throw new DeployError(503, 'release_invalid');
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

function safePayloadPath(path: string, component: ReleaseComponentName): boolean {
  const payloadDirectory = componentPayloadDirectory(component);
  if (
    !path.startsWith(`payload/${payloadDirectory}/`) ||
    path.includes('\\') ||
    Array.from(path).some((character) => {
      const code = character.charCodeAt(0);
      return code <= 31 || code === 127;
    })
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

function parseFileRecord(
  input: v.InferOutput<typeof releaseFileRecordSchema>,
  component: ReleaseComponentName,
): ReleaseFileRecord {
  if (
    input.byteSize > MAX_RELEASE_FILE_BYTES ||
    !safePayloadPath(input.path, component) ||
    input.contentType !== expectedContentType(component, input.path) ||
    !SHA256_PATTERN.test(input.sha256)
  ) invalid();
  return Object.freeze({
    byteSize: input.byteSize,
    contentType: input.contentType,
    path: input.path,
    sha256: input.sha256,
  });
}

function parseComponent(
  input: v.InferOutput<typeof releaseComponentSchema>,
  component: ReleaseComponentName,
): ReleaseComponent {
  if (
    input.byteSize > MAX_RELEASE_PAYLOAD_BYTES ||
    !SHA256_PATTERN.test(input.treeSha256)
  ) invalid();
  const files = input.files.map((file) => parseFileRecord(file, component));
  if (files.length !== input.fileCount || files.length === 0) invalid();
  for (let index = 1; index < files.length; index += 1) {
    const previous = files.at(index - 1);
    const current = files.at(index);
    if (previous === undefined || current === undefined || previous.path >= current.path) invalid();
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

function scopesAreExact(input: readonly string[]): boolean {
  return input.length === REQUIRED_OAUTH_SCOPES.length &&
    input.every((scope, index) => scope === REQUIRED_OAUTH_SCOPES[index]);
}

function cloudflareContractIsExact(input: v.InferOutput<typeof boundaryObjectSchema>): boolean {
  try {
    return canonicalJson(input) === canonicalJson(APPROVED_CLOUDFLARE_RELEASE_CONTRACT);
  } catch {
    return false;
  }
}

export function parseReleaseManifest<Input>(input: Input): ReleaseManifest {
  const result = v.safeParse(releaseManifestSchema, input);
  if (!result.success) invalid();
  const value = result.output;
  if (
    !RELEASE_PATTERN.test(value.release) ||
    !COMMIT_PATTERN.test(value.sourceCommit) ||
    !scopesAreExact(value.oauthScopeIds) ||
    !cloudflareContractIsExact(value.cloudflare) ||
    value.artifact.byteSize > MAX_RELEASE_PAYLOAD_BYTES ||
    !SHA256_PATTERN.test(value.artifact.treeSha256)
  ) invalid();

  const components = Object.freeze({
    admin: parseComponent(value.components.admin, 'admin'),
    installer: parseComponent(value.components.installer, 'installer'),
    worker: parseComponent(value.components.worker, 'worker'),
    workerCleanup: parseComponent(value.components.workerCleanup, 'workerCleanup'),
    workerRetirement: parseComponent(value.components.workerRetirement, 'workerRetirement'),
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
    allFiles.length !== value.artifact.fileCount ||
    byteSize !== value.artifact.byteSize ||
    !Number.isSafeInteger(byteSize)
  ) invalid();
  for (let index = 1; index < allFiles.length; index += 1) {
    const previous = allFiles.at(index - 1);
    const current = allFiles.at(index);
    if (previous === undefined || current === undefined || previous.path >= current.path) invalid();
  }

  return Object.freeze({
    artifact: Object.freeze({
      byteSize: value.artifact.byteSize,
      fileCount: value.artifact.fileCount,
      treeSha256: value.artifact.treeSha256,
    }),
    cloudflare: APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
    components,
    oauthScopeIds: REQUIRED_OAUTH_SCOPES,
    release: value.release,
    schemaVersion: 1,
    sourceCommit: value.sourceCommit,
  });
}

export function parseCanonicalReleaseManifest(serialized: string): ReleaseManifest {
  const bytes = new TextEncoder().encode(serialized);
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_CANONICAL_MANIFEST_BYTES) invalid();
  let input: v.InferOutput<typeof releaseManifestSchema>;
  try {
    const result = v.safeParse(releaseManifestSchema, JSON.parse(serialized));
    if (!result.success) invalid();
    input = result.output;
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
