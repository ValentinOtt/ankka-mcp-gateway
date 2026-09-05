import * as v from 'valibot';

import { DeployError } from './errors';
import {
  verifyReleaseManifestDigests,
} from './release';
import {
  MAX_RELEASE_FILE_BYTES,
  MAX_RELEASE_PAYLOAD_BYTES,
  type ReleaseComponentName,
  type ReleaseFileRecord,
  type ReleaseManifest,
} from './release-manifest';
import {
  parseVerifiedReleaseBundle,
  type ParsedVerifiedPayloadBlob,
} from './verified-release-bundle';

const INSTALLER_PREFIX = 'payload/installer/';
const INSTALLER_INDEX = `${INSTALLER_PREFIX}index.html`;
const PUBLIC_ASSET_PATH = /^[A-Za-z0-9._/-]+$/u;
const HASHED_ASSET_BASENAME = /-[A-Za-z0-9_][A-Za-z0-9_-]{7,}\.[a-z0-9]+$/u;
const SOURCE_MAP_NAME = /\.map(?:[-.]|$)/iu;
const SOURCE_MAP_DIRECTIVE = /sourceMappingURL\s*=/iu;
const RELEASE_INTERNAL_NAME = /(?:^|[-_.])(?:manifest|release[-_.]?envelope)(?:[-_.]|$)/iu;
const SENSITIVE_NAME = /(?:^|[-_.])(?:api[-_.]?key|credential|password|private[-_.]?key|provider[-_.]?data|r2[-_.]?key|secret|token)(?:[-_.]|$)/iu;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const indexHandleSchema = v.object({});

/**
 * The public installer router has the wizard locations plus two OAuth-only
 * routes. `/oauth/handoff` exchanges an encrypted fragment in the user's
 * chosen browser; `/result` is the callback's fixed, query-free return. There
 * is no catch-all: adding a route requires a code review in this service.
 */
export const APPROVED_INSTALLER_HTML_ROUTES = Object.freeze([
  '/',
  '/gateway',
  '/review',
  '/deploy',
  '/oauth/handoff',
  '/manage',
  '/result',
] as const);

const APPROVED_ROUTE_SET = new Set<string>(APPROVED_INSTALLER_HTML_ROUTES);

const CSP = [
  "default-src 'none'",
  "base-uri 'none'",
  "connect-src 'self' https://*.workers.dev/__ankka/install/status",
  "font-src 'self'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "frame-src 'none'",
  "img-src 'self'",
  "manifest-src 'self'",
  "media-src 'none'",
  "object-src 'none'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "worker-src 'none'",
].join('; ');

const COMMON_SECURITY_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  'content-security-policy': CSP,
  'cross-origin-embedder-policy': 'require-corp',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy': 'camera=(), geolocation=(), microphone=(), payment=(), tools=(self), usb=()',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
});

export interface SignedInstallerAssetMetadata {
  /** Exact public URL path. It is never an R2 key or a release payload path. */
  readonly path: string;
  readonly byteSize: number;
  readonly contentType: string;
  readonly sha256: string;
}

/**
 * Public, secret-free view of an installer asset index. Payload blobs and the
 * release envelope remain in private module state and cannot be enumerated by
 * callers. Object identity is checked before a response is built.
 */
export interface SignedInstallerAssetIndex {
  readonly schemaVersion: 1;
  readonly release: string;
  readonly artifactSha256: string;
  readonly htmlRoutes: typeof APPROVED_INSTALLER_HTML_ROUTES;
  readonly assets: readonly SignedInstallerAssetMetadata[];
}

interface ExpectedPayloadRecord {
  readonly component: ReleaseComponentName;
  readonly record: ReleaseFileRecord;
}

interface PayloadSnapshot extends ExpectedPayloadRecord {
  readonly blob: Blob;
}

interface InternalAsset {
  readonly metadata: SignedInstallerAssetMetadata;
  readonly body: Blob;
}

interface InternalIndex {
  readonly html: InternalAsset;
  readonly assets: ReadonlyMap<string, InternalAsset>;
}

const INDEX_STATE = new WeakMap<object, InternalIndex>();

function invalid(): never {
  throw new DeployError(503, 'release_invalid');
}

function lexicalCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function expectedPayload(manifest: ReleaseManifest): readonly ExpectedPayloadRecord[] {
  const expected: ExpectedPayloadRecord[] = [];
  for (const component of [
    'admin',
    'installer',
    'worker',
    'workerBootstrap',
    'workerCleanup',
    'workerRetirement',
  ] as const) {
    for (const record of manifest.components[component].files) {
      expected.push(Object.freeze({ component, record }));
    }
  }
  expected.sort((left, right) => lexicalCompare(left.record.path, right.record.path));
  return Object.freeze(expected);
}

function snapshotPayload(
  input: readonly ParsedVerifiedPayloadBlob[],
  expected: readonly ExpectedPayloadRecord[],
  manifest: ReleaseManifest,
): ReadonlyMap<string, PayloadSnapshot> {
  if (input.length !== expected.length || input.length !== manifest.artifact.fileCount) invalid();
  const expectedByPath = new Map(expected.map((entry) => [entry.record.path, entry]));
  const snapshots = new Map<string, PayloadSnapshot>();
  let declaredBytes = 0;

  for (const entry of input) {
    if (snapshots.has(entry.path)) invalid();
    const expectedEntry = expectedByPath.get(entry.path);
    if (!expectedEntry) invalid();
    const { record } = expectedEntry;
    if (
      entry.byteSize > MAX_RELEASE_FILE_BYTES ||
      entry.byteSize !== record.byteSize ||
      entry.contentType !== record.contentType ||
      !SHA256_PATTERN.test(entry.sha256) ||
      entry.sha256 !== record.sha256 ||
      entry.bytes.size !== record.byteSize ||
      entry.bytes.type !== record.contentType
    ) invalid();
    declaredBytes += entry.byteSize;
    if (!Number.isSafeInteger(declaredBytes) || declaredBytes > MAX_RELEASE_PAYLOAD_BYTES) invalid();
    snapshots.set(entry.path, Object.freeze({
      component: expectedEntry.component,
      record,
      blob: entry.bytes,
    }));
  }
  if (snapshots.size !== expected.length || declaredBytes !== manifest.artifact.byteSize) invalid();
  return snapshots;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(bytes: Uint8Array): Promise<string> {
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  try {
    return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', owned)));
  } catch {
    invalid();
  } finally {
    owned.fill(0);
  }
}

async function readVerifiedInstallerBlob(snapshot: PayloadSnapshot): Promise<Blob> {
  if (snapshot.component !== 'installer') invalid();
  let buffer: ArrayBuffer;
  try {
    buffer = await snapshot.blob.arrayBuffer();
  } catch {
    invalid();
  }
  if (
    !(buffer instanceof ArrayBuffer) ||
    buffer.byteLength === 0 ||
    buffer.byteLength > MAX_RELEASE_FILE_BYTES ||
    buffer.byteLength !== snapshot.record.byteSize
  ) invalid();
  const bytes = new Uint8Array(buffer);
  try {
    if (await sha256(bytes) !== snapshot.record.sha256) invalid();
    if (
      snapshot.record.contentType.includes('javascript') ||
      snapshot.record.contentType.startsWith('text/css') ||
      snapshot.record.contentType.startsWith('text/html')
    ) {
      let text: string;
      try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      } catch {
        invalid();
      }
      if (SOURCE_MAP_DIRECTIVE.test(text)) invalid();
    }
    return new Blob([bytes], { type: snapshot.record.contentType });
  } finally {
    bytes.fill(0);
  }
}

function installerPublicPath(record: ReleaseFileRecord): string {
  if (!record.path.startsWith(INSTALLER_PREFIX)) invalid();
  const relative = record.path.slice(INSTALLER_PREFIX.length);
  if (
    relative.length === 0 ||
    !PUBLIC_ASSET_PATH.test(relative) ||
    relative.startsWith('/') ||
    relative.includes('//') ||
    relative.split('/').some((segment) => segment === '' || segment === '.' || segment === '..')
  ) invalid();
  return `/${relative}`;
}

function assertApprovedImmutableAsset(record: ReleaseFileRecord, publicPath: string): void {
  if (record.contentType === 'text/html; charset=utf-8') invalid();
  const basename = publicPath.slice(publicPath.lastIndexOf('/') + 1);
  if (
    !HASHED_ASSET_BASENAME.test(basename) ||
    SOURCE_MAP_NAME.test(basename) ||
    RELEASE_INTERNAL_NAME.test(basename) ||
    SENSITIVE_NAME.test(basename)
  ) invalid();
}

function metadata(record: ReleaseFileRecord, path: string): SignedInstallerAssetMetadata {
  return Object.freeze({
    path,
    byteSize: record.byteSize,
    contentType: record.contentType,
    sha256: record.sha256,
  });
}

function responseHeaders(asset: InternalAsset, html: boolean): Headers {
  const headers = new Headers(COMMON_SECURITY_HEADERS);
  headers.set('cache-control', html ? 'no-store' : 'public, max-age=31536000, immutable');
  headers.set('content-length', String(asset.metadata.byteSize));
  headers.set('content-type', asset.metadata.contentType);
  headers.set('etag', `"sha256-${asset.metadata.sha256}"`);
  return headers;
}

function emptyResponse(status: 404 | 405): Response {
  const headers = new Headers(COMMON_SECURITY_HEADERS);
  headers.set('cache-control', 'no-store');
  headers.set('content-length', '0');
  if (status === 405) headers.set('allow', 'GET, HEAD');
  return new Response(null, { status, headers });
}

/**
 * Builds an opaque, in-memory serving index from a previously signature- and
 * payload-verified release. This boundary nevertheless re-parses the exact
 * canonical manifest relation and re-hashes every installer byte it may serve.
 * Admin and all three Worker-variant payload bytes are metadata-checked but
 * never read or placed in the returned index.
 *
 * This function has no R2 or environment input and is intentionally not
 * imported by the default Worker entrypoint.
 */
export async function createSignedInstallerAssetIndex<Input>(
  bundle: Input,
): Promise<SignedInstallerAssetIndex> {
  try {
    const input = parseVerifiedReleaseBundle(bundle);
    const { manifest } = input;
    await verifyReleaseManifestDigests(manifest);
    const expected = expectedPayload(manifest);
    const snapshots = snapshotPayload(input.payload, expected, manifest);
    const privateAssets = new Map<string, InternalAsset>();
    const publicAssets: SignedInstallerAssetMetadata[] = [];
    let html: InternalAsset | null = null;
    let readBytes = 0;

    for (const record of manifest.components.installer.files) {
      const snapshot = snapshots.get(record.path);
      if (!snapshot || snapshot.component !== 'installer' || snapshot.record !== record) invalid();
      const path = installerPublicPath(record);
      const body = await readVerifiedInstallerBlob(snapshot);
      readBytes += body.size;
      if (!Number.isSafeInteger(readBytes) || readBytes > MAX_RELEASE_PAYLOAD_BYTES) invalid();
      const asset: InternalAsset = Object.freeze({ metadata: metadata(record, path), body });

      if (record.path === INSTALLER_INDEX) {
        if (html || path !== '/index.html' || record.contentType !== 'text/html; charset=utf-8') invalid();
        html = asset;
        continue;
      }
      assertApprovedImmutableAsset(record, path);
      if (privateAssets.has(path)) invalid();
      privateAssets.set(path, asset);
      publicAssets.push(asset.metadata);
    }
    if (
      !html ||
      readBytes !== manifest.components.installer.byteSize ||
      publicAssets.length + 1 !== manifest.components.installer.fileCount
    ) invalid();

    publicAssets.sort((left, right) => lexicalCompare(left.path, right.path));
    const index = Object.freeze({
      schemaVersion: 1 as const,
      release: manifest.release,
      artifactSha256: manifest.artifact.treeSha256,
      htmlRoutes: APPROVED_INSTALLER_HTML_ROUTES,
      assets: Object.freeze(publicAssets),
    });
    INDEX_STATE.set(index, Object.freeze({ html, assets: privateAssets }));
    return index;
  } catch (error) {
    if (error instanceof DeployError && error.code === 'release_invalid') throw error;
    invalid();
  }
}

/**
 * Pure request-to-Response mapper for an opaque installer index. It never
 * redirects and never applies a generic SPA fallback. Query strings, encoded
 * path aliases, fragments, credentials, non-GET methods, and unknown paths are
 * rejected before a body is selected.
 */
export function buildSignedInstallerAssetResponse<Index>(
  index: Index,
  request: Request,
): Response {
  if (!v.is(indexHandleSchema, index)) invalid();
  const internal = INDEX_STATE.get(index);
  if (!internal) invalid();
  if (request.method !== 'GET' && request.method !== 'HEAD') return emptyResponse(405);

  let url: URL;
  try {
    url = new URL(request.url);
  } catch {
    return emptyResponse(404);
  }
  if (
    url.search !== '' ||
    url.hash !== '' ||
    url.username !== '' ||
    url.password !== '' ||
    url.pathname.includes('%')
  ) return emptyResponse(404);

  const isHtmlRoute = APPROVED_ROUTE_SET.has(url.pathname);
  const asset = isHtmlRoute ? internal.html : internal.assets.get(url.pathname);
  if (!asset) return emptyResponse(404);
  const headers = responseHeaders(asset, isHtmlRoute);
  return new Response(request.method === 'HEAD' ? null : asset.body, { status: 200, headers });
}
