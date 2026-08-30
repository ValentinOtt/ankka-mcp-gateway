#!/usr/bin/env node

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as ed25519Sign,
  timingSafeEqual,
  verify as ed25519Verify,
} from 'node:crypto';
import { constants as FS_CONSTANTS } from 'node:fs';
import {
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  stat,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import * as v from 'valibot';

const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 32 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 8 * 1024 * 1024;
const MAX_OBJECT_PLAN_BYTES = 8 * 1024 * 1024;
const MAX_FILES = 10_000;
const MAX_PAYLOAD_PATH_BYTES = 900;
const MAX_R2_KEY_BYTES = 1_024;
const R2_ROOT = 'ankka-mcp-gateway/releases';
const ENVELOPE_CONTENT_TYPE = 'application/json; charset=utf-8';
const PLAN_FILENAME = 'r2-object-plan.json';
const OBJECTS_DIRECTORY = 'objects';
const CHANNEL_PATTERN = /^(?:canary|stable)$/u;
const RELEASE_PATTERN = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const PUBLIC_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const COMMIT_PATTERN = /^[a-f0-9]{40}$/u;
const MAX_CONTROL_PLANE_ORIGIN_LENGTH = 2_048;
const WORKER_CONTROL_PLANE_ORIGIN_DECLARATION =
  /^const CONTROL_PLANE_ORIGIN = '(https:\/\/[^'\r\n]+)';$/gmu;
const SAFE_SEGMENT = /^[A-Za-z0-9._-]+$/u;
const CREDENTIAL_NAME = /(?:^|[-_.])(?:api[-_.]?key|client[-_.]?secret|credential|credentials|password|passwd|private[-_.]?key|secret|secrets|token|tokens)(?:[-_.]|$)/iu;
const DISALLOWED_CREDENTIAL_SEGMENT = new Set([
  'APIKEY',
  'CREDENTIAL',
  'CREDENTIALS',
  'KEY',
  'PASSWORD',
  'PASSWD',
  'PRIVATEKEY',
  'SECRET',
  'TOKEN',
]);

function hasControlCharacter(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 31 || code === 127) return true;
  }
  return false;
}
const PKCS8_SEED_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PUBLIC_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const BOOLEAN_SCHEMA = v.boolean();
const NUMBER_SCHEMA = v.number();
const OBJECT_SCHEMA = v.object({});
const STRING_SCHEMA = v.string();

export const REVIEWED_FAULT_INJECTION = 'exact-version-health-probe-v1';
export const REVIEWED_FAULT_INJECTION_MARKER =
  `/* ANKKA_REVIEWED_FAULT_INJECTION:${REVIEWED_FAULT_INJECTION} */`;
export const REVIEWED_FAULT_INJECTION_SENTINEL = 'reviewed_fault_injected';
export const RELEASE_ENVELOPE_SCHEMA_VERSION = 2;
export const RELEASE_SIGNATURE_CONTEXT = 'ankka-mcp-gateway-release-envelope-v2';

export const REQUIRED_OAUTH_SCOPES = Object.freeze([
  'access-acct.write',
  'access.write',
  'account-settings.read',
  'dns.write',
  'mcp-portals.write',
  'memberships.read',
  'user-details.read',
  'workers-routes.read',
  'workers-scripts.write',
  'zone.read',
]);

export const APPROVED_CLOUDFLARE_CONTRACT = Object.freeze({
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
    bindings: Object.freeze([Object.freeze({ binding: 'ADMIN_STATE', className: 'AdminState' })]),
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
      Object.freeze({ lifecycle: 'customer-managed-optional', name: 'ANKKA_TEAM_MANAGEMENT_TOKEN' }),
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
});

const WORKER_CONTENT_TYPES = Object.freeze({
  '.js': 'application/javascript+module',
  '.mjs': 'application/javascript+module',
  '.wasm': 'application/wasm',
});

const WEB_CONTENT_TYPES = Object.freeze({
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

const PREPARED_STATE = new WeakMap();

export class ReleaseSigningError extends Error {
  constructor() {
    super('Release signing failed');
    this.name = 'ReleaseSigningError';
    this.code = 'release_signing_failed';
  }
}

function fail() {
  throw new ReleaseSigningError();
}

function isRecord(value) {
  return v.is(OBJECT_SCHEMA, value) && !Array.isArray(value);
}

function exactKeys(value, keys) {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function parseControlPlaneOrigin(value) {
  if (!v.is(STRING_SCHEMA, value) || value.length === 0 || value.length > MAX_CONTROL_PLANE_ORIGIN_LENGTH) fail();
  try {
    const parsed = new URL(value);
    if (
      parsed.protocol !== 'https:' ||
      parsed.username !== '' ||
      parsed.password !== '' ||
      parsed.port !== '' ||
      parsed.pathname !== '/' ||
      parsed.search !== '' ||
      parsed.hash !== '' ||
      parsed.origin !== value ||
      value.includes("'")
    ) fail();
  } catch (error) {
    if (error instanceof ReleaseSigningError) throw error;
    fail();
  }
  return value;
}

function assertWorkerControlPlaneOrigin(payload, expectedOrigin) {
  const worker = payload.find((entry) => entry.record.path === 'payload/worker/index.js');
  if (!worker) fail();
  let source;
  try {
    source = new TextDecoder('utf-8', { fatal: true }).decode(worker.bytes);
  } catch {
    fail();
  }
  const matches = [...source.matchAll(WORKER_CONTROL_PLANE_ORIGIN_DECLARATION)];
  if (matches.length !== 1 || parseControlPlaneOrigin(matches[0]?.[1]) !== expectedOrigin) fail();
}

function safeInteger(value, maximum = Number.MAX_SAFE_INTEGER) {
  return Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function lexicalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function canonicalJson(value) {
  return canonicalValue(value, new Set());
}

export function releaseSignatureCanonicalJson(channel, keyId, manifest) {
  if (
    !v.is(STRING_SCHEMA, channel) || !CHANNEL_PATTERN.test(channel) ||
    !v.is(STRING_SCHEMA, keyId) || !KEY_ID_PATTERN.test(keyId) ||
    !v.is(STRING_SCHEMA, manifest) || manifest.length === 0
  ) fail();
  return canonicalJson({
    channel,
    keyId,
    manifest,
    schemaVersion: RELEASE_ENVELOPE_SCHEMA_VERSION,
    signatureContext: RELEASE_SIGNATURE_CONTEXT,
  });
}

function canonicalValue(value, seen) {
  if (value === null || v.is(STRING_SCHEMA, value) || v.is(BOOLEAN_SCHEMA, value)) {
    return JSON.stringify(value);
  }
  if (v.is(NUMBER_SCHEMA, value)) {
    if (!Number.isFinite(value)) fail();
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) fail();
    seen.add(value);
    const output = `[${value.map((entry) => canonicalValue(entry, seen)).join(',')}]`;
    seen.delete(value);
    return output;
  }
  if (isRecord(value) && Object.getPrototypeOf(value) === Object.prototype) {
    if (seen.has(value)) fail();
    seen.add(value);
    const output = `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${canonicalValue(value[key], seen)}`,
    ).join(',')}}`;
    seen.delete(value);
    return output;
  }
  fail();
}

function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest();
}

function sha256Hex(bytes) {
  const digest = sha256Bytes(bytes);
  try {
    return digest.toString('hex');
  } finally {
    digest.fill(0);
  }
}

function extension(filePath) {
  const filename = filePath.slice(filePath.lastIndexOf('/') + 1);
  const dot = filename.lastIndexOf('.');
  return dot < 0 ? '' : filename.slice(dot).toLowerCase();
}

function byteOccurrences(bytes, needle) {
  let count = 0;
  let offset = 0;
  while (true) {
    const found = bytes.indexOf(needle, offset);
    if (found < 0) return count;
    count += 1;
    offset = found + needle.byteLength;
  }
}

export function classifyReviewedFaultWorker(bytes) {
  if (!(bytes instanceof Uint8Array)) fail();
  const view = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const marker = Buffer.from(REVIEWED_FAULT_INJECTION_MARKER, 'utf8');
  const sentinel = Buffer.from(REVIEWED_FAULT_INJECTION_SENTINEL, 'utf8');
  try {
    const markerCount = byteOccurrences(view, marker);
    const sentinelCount = byteOccurrences(view, sentinel);
    if (markerCount === 0 && sentinelCount === 0) return 'ordinary';
    if (markerCount !== 1 || sentinelCount !== 1) fail();
    return 'reviewed-fault';
  } finally {
    marker.fill(0);
    sentinel.fill(0);
  }
}

function componentPayloadDirectory(component) {
  if (component === 'workerCleanup') return 'worker-cleanup';
  if (component === 'workerRetirement') return 'worker-retirement';
  return component;
}

function safePayloadPath(value, component) {
  const payloadDirectory = componentPayloadDirectory(component);
  if (
    !v.is(STRING_SCHEMA, value) ||
    !value.startsWith(`payload/${payloadDirectory}/`) ||
    value.includes('\\') ||
    value.includes('%') ||
    hasControlCharacter(value) ||
    Buffer.byteLength(value, 'utf8') > MAX_PAYLOAD_PATH_BYTES
  ) return false;
  const segments = value.split('/');
  return segments.length >= 3 && segments.every(
    (segment) => SAFE_SEGMENT.test(segment) &&
      segment !== '.' &&
      segment !== '..' &&
      !CREDENTIAL_NAME.test(segment),
  );
}

function identifierSegments(identifier) {
  if (!v.is(STRING_SCHEMA, identifier) || identifier === '') return [];
  return identifier
    .replace(/([a-z0-9])([A-Z])/gu, '$1_$2')
    .replace(/[^A-Za-z0-9]+/gu, '_')
    .toUpperCase()
    .split('_')
    .filter(Boolean);
}

function credentialEnvironmentName(identifier) {
  const segments = identifierSegments(identifier);
  if (segments.length === 0) return false;
  if (segments.some((segment) => DISALLOWED_CREDENTIAL_SEGMENT.has(segment))) return true;
  const compact = segments.join('');
  return compact.includes('APIKEY') ||
    compact.includes('CLIENTSECRET') ||
    compact.includes('PRIVATEKEY') ||
    compact.includes('SECRETKEY');
}

function credentialLiteralIdentifier(identifier) {
  const segments = identifierSegments(identifier);
  if (segments.length === 0) return false;
  const credentialWords = new Set(['CREDENTIAL', 'CREDENTIALS', 'PASSWORD', 'PASSWD', 'SECRET', 'TOKEN']);
  if (
    segments[0] === 'VITE' &&
    segments.some((segment) => credentialWords.has(segment) || segment === 'KEY')
  ) return true;
  if (segments.some((segment) => credentialWords.has(segment))) return true;
  const compact = segments.join('');
  return compact.includes('APIKEY') ||
    compact.includes('CLIENTSECRET') ||
    compact.includes('PRIVATEKEY') ||
    compact.includes('SECRETKEY');
}

function containsCredentialLiteralAssignment(text) {
  const quoted = /\b([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:=|:)\s*(["'`])([^"'`\r\n]{16,})\2/gu;
  for (const match of text.matchAll(quoted)) {
    if (credentialLiteralIdentifier(match[1])) return true;
  }
  const environment = /(?:^|[\r\n])([A-Z][A-Z0-9_]*)\s*=\s*([^\s#]{16,})(?:\s|$)/gu;
  for (const match of text.matchAll(environment)) {
    if (credentialEnvironmentName(match[1])) return true;
  }
  return false;
}

function assertSecretFreePayload(bytes) {
  const text = bytes.toString('utf8');
  const patterns = [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{32,}?-----END [A-Z ]*PRIVATE KEY-----/u,
    /\bAKIA[A-Z0-9]{16}\b/u,
    /\bgh[pousr]_[A-Za-z0-9]{20,}\b/u,
    /\bAIza[0-9A-Za-z_-]{35}\b/u,
    /\bxox[baprs]-[0-9A-Za-z-]{20,}\b/u,
    /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/u,
    /(?:^|[\r\n])[A-Z][A-Z0-9_]*(?:API_KEY|PASSWORD|SECRET|TOKEN)[A-Z0-9_]*\s*=\s*[^\s#]{16,}/mu,
    /["'](?:api[-_]?key|client[-_]?secret|password|token)["']\s*:\s*["'][^"'\s]{16,}["']/iu,
  ];
  if (patterns.some((pattern) => pattern.test(text)) || containsCredentialLiteralAssignment(text)) fail();
}

function assertNormalizedTextPayload(bytes, contentType) {
  if (!(contentType.includes('; charset=utf-8') ||
      contentType === 'application/javascript+module' ||
      contentType === 'image/svg+xml')) return;
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail();
  }
  if (text.includes('\r') || text.includes('\0')) fail();
}

function expectedContentType(component, filePath) {
  const mapping = component === 'admin' || component === 'installer'
    ? WEB_CONTENT_TYPES
    : WORKER_CONTENT_TYPES;
  return mapping[extension(filePath)];
}

function parseFileRecord(input, component) {
  if (!exactKeys(input, ['byteSize', 'contentType', 'path', 'sha256'])) fail();
  if (
    !safeInteger(input.byteSize, MAX_FILE_BYTES) ||
    !safePayloadPath(input.path, component) ||
    !v.is(STRING_SCHEMA, input.contentType) ||
    input.contentType !== expectedContentType(component, input.path) ||
    !v.is(STRING_SCHEMA, input.sha256) ||
    !SHA256_PATTERN.test(input.sha256)
  ) fail();
  return Object.freeze({
    byteSize: input.byteSize,
    contentType: input.contentType,
    path: input.path,
    sha256: input.sha256,
  });
}

function parseComponent(input, component) {
  if (!exactKeys(input, ['byteSize', 'fileCount', 'files', 'treeSha256'])) fail();
  if (
    !safeInteger(input.byteSize, MAX_PAYLOAD_BYTES) ||
    !safeInteger(input.fileCount, MAX_FILES) ||
    !Array.isArray(input.files) ||
    !v.is(STRING_SCHEMA, input.treeSha256) ||
    !SHA256_PATTERN.test(input.treeSha256)
  ) fail();
  const files = input.files.map((record) => parseFileRecord(record, component));
  if (files.length === 0 || files.length !== input.fileCount) fail();
  for (let index = 1; index < files.length; index += 1) {
    if (files[index - 1].path >= files[index].path) fail();
  }
  const byteSize = files.reduce((total, file) => total + file.byteSize, 0);
  if (!safeInteger(byteSize, MAX_PAYLOAD_BYTES) || byteSize !== input.byteSize) fail();
  const requiredPath = component === 'admin' || component === 'installer'
    ? `payload/${component}/index.html`
    : `payload/${componentPayloadDirectory(component)}/index.js`;
  if (!files.some((file) => file.path === requiredPath)) fail();
  return Object.freeze({
    byteSize,
    fileCount: files.length,
    files: Object.freeze(files),
    treeSha256: input.treeSha256,
  });
}

function parseCanonicalManifest(bytes, expectedRelease) {
  if (!Buffer.isBuffer(bytes) || bytes.byteLength === 0 || bytes.byteLength > MAX_MANIFEST_BYTES) fail();
  let serialized;
  let raw;
  try {
    serialized = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    raw = JSON.parse(serialized);
  } catch {
    fail();
  }
  if (canonicalJson(raw) !== serialized) fail();
  if (!exactKeys(raw, [
    'artifact',
    'cloudflare',
    'components',
    'controlPlaneOrigin',
    'oauthScopeIds',
    'release',
    'schemaVersion',
    'sourceCommit',
  ])) fail();
  if (
    raw.schemaVersion !== 1 ||
    parseControlPlaneOrigin(raw.controlPlaneOrigin) !== raw.controlPlaneOrigin ||
    !v.is(STRING_SCHEMA, raw.release) ||
    !RELEASE_PATTERN.test(raw.release) ||
    raw.release !== expectedRelease ||
    !v.is(STRING_SCHEMA, raw.sourceCommit) ||
    !COMMIT_PATTERN.test(raw.sourceCommit) ||
    canonicalJson(raw.cloudflare) !== canonicalJson(APPROVED_CLOUDFLARE_CONTRACT) ||
    !Array.isArray(raw.oauthScopeIds) ||
    raw.oauthScopeIds.length !== REQUIRED_OAUTH_SCOPES.length ||
    !raw.oauthScopeIds.every((scope, index) => scope === REQUIRED_OAUTH_SCOPES[index]) ||
    !exactKeys(raw.artifact, ['byteSize', 'fileCount', 'treeSha256']) ||
    !safeInteger(raw.artifact.byteSize, MAX_PAYLOAD_BYTES) ||
    !safeInteger(raw.artifact.fileCount, MAX_FILES) ||
    !v.is(STRING_SCHEMA, raw.artifact.treeSha256) ||
    !SHA256_PATTERN.test(raw.artifact.treeSha256) ||
    !exactKeys(raw.components, [
      'admin',
      'installer',
      'worker',
      'workerCleanup',
      'workerRetirement',
    ])
  ) fail();

  const components = Object.freeze({
    admin: parseComponent(raw.components.admin, 'admin'),
    installer: parseComponent(raw.components.installer, 'installer'),
    worker: parseComponent(raw.components.worker, 'worker'),
    workerCleanup: parseComponent(raw.components.workerCleanup, 'workerCleanup'),
    workerRetirement: parseComponent(raw.components.workerRetirement, 'workerRetirement'),
  });
  const records = Object.freeze([
    ...components.admin.files,
    ...components.installer.files,
    ...components.worker.files,
    ...components.workerCleanup.files,
    ...components.workerRetirement.files,
  ].sort((left, right) => lexicalCompare(left.path, right.path)));
  if (records.length !== raw.artifact.fileCount) fail();
  for (let index = 1; index < records.length; index += 1) {
    if (records[index - 1].path >= records[index].path) fail();
  }
  const totalBytes = records.reduce((total, record) => total + record.byteSize, 0);
  if (!safeInteger(totalBytes, MAX_PAYLOAD_BYTES) || totalBytes !== raw.artifact.byteSize) fail();
  for (const component of [
    'admin',
    'installer',
    'worker',
    'workerCleanup',
    'workerRetirement',
  ]) {
    const tree = sha256Hex(Buffer.from(canonicalJson(components[component].files), 'utf8'));
    if (tree !== components[component].treeSha256) fail();
  }
  const artifactTree = sha256Hex(Buffer.from(canonicalJson(records), 'utf8'));
  if (artifactTree !== raw.artifact.treeSha256) fail();
  return Object.freeze({
    serialized,
    manifest: Object.freeze({
      artifact: Object.freeze({ ...raw.artifact }),
      cloudflare: APPROVED_CLOUDFLARE_CONTRACT,
      components,
      controlPlaneOrigin: raw.controlPlaneOrigin,
      oauthScopeIds: REQUIRED_OAUTH_SCOPES,
      release: raw.release,
      schemaVersion: 1,
      sourceCommit: raw.sourceCommit,
    }),
    records,
  });
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs;
}

async function readRegularFile(root, relativePath, maximumBytes, expectedBytes) {
  const absolutePath = path.join(root, ...relativePath.split('/'));
  let before;
  let handle;
  let fileBuffer;
  try {
    before = await lstat(absolutePath);
    if (
      !before.isFile() ||
      before.isSymbolicLink() ||
      before.nlink !== 1 ||
      !safeInteger(before.size, maximumBytes) ||
      (expectedBytes !== undefined && before.size !== expectedBytes)
    ) fail();
    handle = await open(absolutePath, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!sameFileIdentity(before, opened)) fail();
    fileBuffer = await handle.readFile();
    const after = await handle.stat();
    if (
      !sameFileIdentity(opened, after) ||
      fileBuffer.byteLength !== after.size ||
      fileBuffer.byteLength > maximumBytes ||
      (expectedBytes !== undefined && fileBuffer.byteLength !== expectedBytes)
    ) fail();
    const owned = Buffer.alloc(fileBuffer.byteLength);
    fileBuffer.copy(owned);
    return owned;
  } catch (error) {
    if (error instanceof ReleaseSigningError) throw error;
    fail();
  } finally {
    if (fileBuffer) fileBuffer.fill(0);
    if (handle) {
      try {
        await handle.close();
      } catch {
        // The caller receives only the fixed failure below when close is the
        // primary error; an earlier fixed error remains fixed.
      }
    }
  }
}

function expectedDirectories(records) {
  const directories = new Set([
    'payload',
    'payload/admin',
    'payload/installer',
    'payload/worker',
    'payload/worker-cleanup',
    'payload/worker-retirement',
  ]);
  for (const record of records) {
    const segments = record.path.split('/');
    for (let index = 1; index < segments.length; index += 1) {
      directories.add(segments.slice(0, index).join('/'));
    }
  }
  return directories;
}

async function enumeratePayloadTree(root) {
  const files = new Set();
  const directories = new Set(['payload']);
  const queue = ['payload'];
  let entries = 0;
  while (queue.length > 0) {
    const relativeDirectory = queue.shift();
    let children;
    try {
      children = await readdir(path.join(root, ...relativeDirectory.split('/')), { withFileTypes: true });
    } catch {
      fail();
    }
    children.sort((left, right) => lexicalCompare(left.name, right.name));
    for (const child of children) {
      entries += 1;
      if (entries > (MAX_FILES * 4) || !SAFE_SEGMENT.test(child.name) || child.name === '.' || child.name === '..') fail();
      const relativePath = `${relativeDirectory}/${child.name}`;
      if (child.isSymbolicLink()) fail();
      if (child.isDirectory()) {
        directories.add(relativePath);
        queue.push(relativePath);
      } else if (child.isFile()) {
        files.add(relativePath);
      } else {
        fail();
      }
    }
  }
  return { files, directories };
}

function setsEqual(left, right) {
  return left.size === right.size && [...left].every((entry) => right.has(entry));
}

export async function loadVerifiedPublicRelease(releaseDirectory, expectedRelease) {
  if (!v.is(STRING_SCHEMA, releaseDirectory) || releaseDirectory.length === 0 || releaseDirectory.includes('\0')) fail();
  let root;
  try {
    const requestedRoot = path.resolve(releaseDirectory);
    const requestedStat = await lstat(requestedRoot);
    if (!requestedStat.isDirectory() || requestedStat.isSymbolicLink()) fail();
    root = await realpath(requestedRoot);
    const rootStat = await stat(root);
    if (!rootStat.isDirectory()) fail();
    const rootEntries = await readdir(root, { withFileTypes: true });
    rootEntries.sort((left, right) => lexicalCompare(left.name, right.name));
    if (
      rootEntries.length !== 2 ||
      rootEntries[0].name !== 'manifest.json' ||
      !rootEntries[0].isFile() ||
      rootEntries[0].isSymbolicLink() ||
      rootEntries[1].name !== 'payload' ||
      !rootEntries[1].isDirectory() ||
      rootEntries[1].isSymbolicLink()
    ) fail();
    const payloadStat = await lstat(path.join(root, 'payload'));
    if (!payloadStat.isDirectory() || payloadStat.isSymbolicLink()) fail();
  } catch (error) {
    if (error instanceof ReleaseSigningError) throw error;
    fail();
  }
  const manifestBytes = await readRegularFile(root, 'manifest.json', MAX_MANIFEST_BYTES);
  let parsed;
  try {
    parsed = parseCanonicalManifest(manifestBytes, expectedRelease);
    const expectedFiles = new Set(parsed.records.map((record) => record.path));
    const expectedDirs = expectedDirectories(parsed.records);
    const beforeTree = await enumeratePayloadTree(root);
    if (!setsEqual(beforeTree.files, expectedFiles) || !setsEqual(beforeTree.directories, expectedDirs)) fail();

    const payload = [];
    let totalBytes = 0;
    try {
      for (const record of parsed.records) {
        const bytes = await readRegularFile(root, record.path, MAX_FILE_BYTES, record.byteSize);
        totalBytes += bytes.byteLength;
        if (!safeInteger(totalBytes, MAX_PAYLOAD_BYTES) || sha256Hex(bytes) !== record.sha256) {
          bytes.fill(0);
          fail();
        }
        assertNormalizedTextPayload(bytes, record.contentType);
        assertSecretFreePayload(bytes);
        payload.push(Object.freeze({ record, bytes }));
      }
      if (totalBytes !== parsed.manifest.artifact.byteSize) fail();
      assertWorkerControlPlaneOrigin(payload, parsed.manifest.controlPlaneOrigin);
      const afterTree = await enumeratePayloadTree(root);
      if (!setsEqual(afterTree.files, expectedFiles) || !setsEqual(afterTree.directories, expectedDirs)) fail();
      return Object.freeze({ root, manifestBytes, ...parsed, payload: Object.freeze(payload) });
    } catch (error) {
      for (const entry of payload) entry.bytes.fill(0);
      throw error;
    }
  } catch (error) {
    manifestBytes.fill(0);
    if (error instanceof ReleaseSigningError) throw error;
    fail();
  }
}

function decodePublicKey(encoded) {
  if (!v.is(STRING_SCHEMA, encoded) || !PUBLIC_KEY_PATTERN.test(encoded)) fail();
  let bytes;
  try {
    bytes = Buffer.from(encoded, 'base64url');
  } catch {
    fail();
  }
  if (bytes.byteLength !== 32 || bytes.toString('base64url') !== encoded) {
    bytes.fill(0);
    fail();
  }
  return bytes;
}

function signReleaseStatement(statementBytes, seed, encodedPublicKey) {
  if (!(seed instanceof Uint8Array) || seed.byteLength !== 32) fail();
  const seedCopy = Buffer.alloc(32);
  seedCopy.set(seed);
  const pkcs8 = Buffer.concat([PKCS8_SEED_PREFIX, seedCopy]);
  const expectedPublic = decodePublicKey(encodedPublicKey);
  const expectedSpki = Buffer.concat([SPKI_PUBLIC_PREFIX, expectedPublic]);
  let derivedSpki;
  let signature;
  try {
    const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
    derivedSpki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
    if (
      !Buffer.isBuffer(derivedSpki) ||
      derivedSpki.byteLength !== expectedSpki.byteLength ||
      !timingSafeEqual(derivedSpki, expectedSpki)
    ) fail();
    signature = ed25519Sign(null, statementBytes, privateKey);
    if (
      signature.byteLength !== 64 ||
      !ed25519Verify(null, statementBytes, { key: expectedSpki, format: 'der', type: 'spki' }, signature)
    ) fail();
    return signature.toString('base64url');
  } catch (error) {
    if (error instanceof ReleaseSigningError) throw error;
    fail();
  } finally {
    seedCopy.fill(0);
    pkcs8.fill(0);
    expectedPublic.fill(0);
    expectedSpki.fill(0);
    if (Buffer.isBuffer(derivedSpki)) derivedSpki.fill(0);
    if (Buffer.isBuffer(signature)) signature.fill(0);
  }
}

function immutablePlan(plan) {
  for (const object of plan.objects) Object.freeze(object);
  Object.freeze(plan.objects);
  Object.freeze(plan.immutability);
  return Object.freeze(plan);
}

/**
 * Independently validates and signs one complete public gateway release.
 * `privateKeySeed` is consumed: the exact caller-provided 32-byte view and all
 * internal secret-bearing buffers are zeroed before this function settles.
 * No environment, Keychain, network, R2, Wrangler, or Worker API is consulted.
 */
export async function prepareSignedReleasePublishPlan(input) {
  const seed = isRecord(input) ? input.privateKeySeed : undefined;
  let loaded;
  try {
    const ordinaryKeys = [
      'channel',
      'keyId',
      'privateKeySeed',
      'publicKey',
      'release',
      'releaseDirectory',
    ];
    const acknowledgedFault = isRecord(input) && Object.hasOwn(input, 'reviewedFaultInjection')
      ? input.reviewedFaultInjection
      : null;
    if (
      !exactKeys(input, ordinaryKeys) &&
      !exactKeys(input, [...ordinaryKeys, 'reviewedFaultInjection'])
    ) fail();
    if (
      !v.is(STRING_SCHEMA, input.channel) || !CHANNEL_PATTERN.test(input.channel) ||
      !v.is(STRING_SCHEMA, input.release) || !RELEASE_PATTERN.test(input.release) ||
      !v.is(STRING_SCHEMA, input.keyId) || !KEY_ID_PATTERN.test(input.keyId) ||
      !v.is(STRING_SCHEMA, input.publicKey) || !PUBLIC_KEY_PATTERN.test(input.publicKey) ||
      !(seed instanceof Uint8Array) || seed.byteLength !== 32
    ) fail();

    loaded = await loadVerifiedPublicRelease(input.releaseDirectory, input.release);
    const worker = loaded.payload.find((entry) => entry.record.path === 'payload/worker/index.js');
    if (!worker) fail();
    const hasReviewedFault = classifyReviewedFaultWorker(worker.bytes) === 'reviewed-fault';
    if (
      (hasReviewedFault && (
        input.channel !== 'canary' || acknowledgedFault !== REVIEWED_FAULT_INJECTION
      )) ||
      (!hasReviewedFault && acknowledgedFault !== null)
    ) fail();
    const signatureStatement = Buffer.from(releaseSignatureCanonicalJson(
      input.channel,
      input.keyId,
      loaded.serialized,
    ), 'utf8');
    let signature;
    try {
      signature = signReleaseStatement(signatureStatement, seed, input.publicKey);
    } finally {
      signatureStatement.fill(0);
    }
    const envelopeObject = Object.freeze({
      channel: input.channel,
      keyId: input.keyId,
      manifest: loaded.serialized,
      schemaVersion: RELEASE_ENVELOPE_SCHEMA_VERSION,
      signature,
      signatureContext: RELEASE_SIGNATURE_CONTEXT,
    });
    const envelopeCanonicalJson = canonicalJson(envelopeObject);
    const envelopeBytes = Buffer.from(envelopeCanonicalJson, 'utf8');
    const prefix = `${R2_ROOT}/${input.channel}/${input.release}`;
    const objects = [
      Object.freeze({
        byteSize: envelopeBytes.byteLength,
        contentType: ENVELOPE_CONTENT_TYPE,
        key: `${prefix}/release-envelope.json`,
        sha256: sha256Hex(envelopeBytes),
        sourcePath: `${OBJECTS_DIRECTORY}/${prefix}/release-envelope.json`,
      }),
      ...loaded.payload.map(({ record }) => Object.freeze({
        byteSize: record.byteSize,
        contentType: record.contentType,
        key: `${prefix}/${record.path}`,
        sha256: record.sha256,
        sourcePath: `${OBJECTS_DIRECTORY}/${prefix}/${record.path}`,
      })),
    ].sort((left, right) => lexicalCompare(left.key, right.key));
    if (objects.some((object) => Buffer.byteLength(object.key, 'utf8') > MAX_R2_KEY_BYTES)) fail();
    const totalByteSize = objects.reduce((total, object) => total + object.byteSize, 0);
    if (!safeInteger(totalByteSize, MAX_PAYLOAD_BYTES + (2 * MAX_MANIFEST_BYTES) + 4_096)) fail();
    const objectPlan = immutablePlan({
      artifactSha256: loaded.manifest.artifact.treeSha256,
      channel: input.channel,
      controlPlaneOrigin: loaded.manifest.controlPlaneOrigin,
      immutability: {
        externalAtomicCreateOnlyRequired: true,
        overwriteAllowed: false,
      },
      keyId: input.keyId,
      objectCount: objects.length,
      objects,
      prefix: `${prefix}/`,
      release: input.release,
      schemaVersion: 1,
      totalByteSize,
    });
    const objectPlanCanonicalJson = canonicalJson(objectPlan);
    if (Buffer.byteLength(objectPlanCanonicalJson, 'utf8') > MAX_OBJECT_PLAN_BYTES) fail();
    const prepared = Object.freeze({
      schemaVersion: 1,
      release: input.release,
      channel: input.channel,
      keyId: input.keyId,
      artifactSha256: loaded.manifest.artifact.treeSha256,
      controlPlaneOrigin: loaded.manifest.controlPlaneOrigin,
      releaseEnvelopeCanonicalJson: envelopeCanonicalJson,
      releaseEnvelopeSha256: sha256Hex(envelopeBytes),
      objectPlan,
      objectPlanCanonicalJson,
      objectPlanSha256: sha256Hex(Buffer.from(objectPlanCanonicalJson, 'utf8')),
    });
    const payloadByPath = new Map(loaded.payload.map((entry) => [entry.record.path, entry.bytes]));
    PREPARED_STATE.set(prepared, Object.freeze({
      sourceRoot: loaded.root,
      envelopeBytes,
      payloadByPath,
    }));
    loaded.manifestBytes.fill(0);
    return prepared;
  } catch (error) {
    if (loaded) {
      loaded.manifestBytes.fill(0);
      for (const entry of loaded.payload) entry.bytes.fill(0);
    }
    if (error instanceof ReleaseSigningError) throw error;
    fail();
  } finally {
    if (seed instanceof Uint8Array) {
      try {
        seed.fill(0);
      } catch {
        // A detached hostile view still results in the fixed failure above;
        // ordinary caller-owned seed views are always consumed and zeroed.
      }
    }
  }
}

function outputRelativeForObject(object, release) {
  const expectedPrefix = `${OBJECTS_DIRECTORY}/${R2_ROOT}/`;
  if (
    !v.is(STRING_SCHEMA, object.sourcePath) ||
    !object.sourcePath.startsWith(expectedPrefix) ||
    object.sourcePath.includes('\\') ||
    object.sourcePath.includes('%') ||
    object.sourcePath.split('/').some((segment) => !SAFE_SEGMENT.test(segment) || segment === '.' || segment === '..')
  ) fail();
  if (!object.key.endsWith('/release-envelope.json')) {
    const marker = `/${release}/`;
    const markerIndex = object.key.indexOf(marker);
    if (markerIndex < 0) fail();
    return { relative: object.sourcePath, payloadPath: object.key.slice(markerIndex + marker.length) };
  }
  return { relative: object.sourcePath, payloadPath: null };
}

async function ensureDirectory(root, relativeDirectory) {
  if (relativeDirectory === '.') return;
  const segments = relativeDirectory.split('/');
  let current = root;
  for (const segment of segments) {
    if (!SAFE_SEGMENT.test(segment) || segment === '.' || segment === '..') fail();
    current = path.join(current, segment);
    try {
      await mkdir(current, { recursive: false, mode: 0o700 });
    } catch (error) {
      if (error?.code !== 'EEXIST') fail();
    }
    try {
      const currentStat = await lstat(current);
      if (!currentStat.isDirectory() || currentStat.isSymbolicLink()) fail();
    } catch (error) {
      if (error instanceof ReleaseSigningError) throw error;
      fail();
    }
  }
}

async function writeExclusiveAndVerify(root, relativePath, bytes, expectedSha256) {
  const absolutePath = path.join(root, ...relativePath.split('/'));
  await ensureDirectory(root, path.posix.dirname(relativePath));
  try {
    await writeFile(absolutePath, bytes, { flag: 'wx', mode: 0o600 });
  } catch {
    fail();
  }
  const verified = await readRegularFile(root, relativePath, bytes.byteLength, bytes.byteLength);
  try {
    if (sha256Hex(verified) !== expectedSha256) fail();
  } finally {
    verified.fill(0);
  }
}

/**
 * Materializes a fresh, local publish directory. It never uploads. The output
 * root must not exist, every file is opened create-only, and the canonical
 * object plan is written last as the completion marker. A failed partial
 * directory is deliberately not reused or overwritten.
 */
export async function writeSignedReleasePublishDirectory(prepared, outputDirectory) {
  const state = PREPARED_STATE.get(prepared);
  if (!state || !v.is(STRING_SCHEMA, outputDirectory) || outputDirectory.length === 0 || outputDirectory.includes('\0')) fail();
  const resolved = path.resolve(outputDirectory);
  if (resolved === state.sourceRoot || resolved.startsWith(`${state.sourceRoot}${path.sep}`)) fail();
  const basename = path.basename(resolved);
  if (!SAFE_SEGMENT.test(basename) || basename === '.' || basename === '..') fail();
  let parent;
  try {
    parent = await realpath(path.dirname(resolved));
  } catch {
    fail();
  }
  const root = path.join(parent, basename);
  try {
    await mkdir(root, { recursive: false, mode: 0o700 });
  } catch {
    fail();
  }

  for (const object of prepared.objectPlan.objects) {
    const mapped = outputRelativeForObject(object, prepared.release);
    const bytes = mapped.payloadPath === null
      ? state.envelopeBytes
      : state.payloadByPath.get(mapped.payloadPath);
    if (!bytes || bytes.byteLength !== object.byteSize || sha256Hex(bytes) !== object.sha256) fail();
    await writeExclusiveAndVerify(root, mapped.relative, bytes, object.sha256);
  }
  const planBytes = Buffer.from(prepared.objectPlanCanonicalJson, 'utf8');
  try {
    await writeExclusiveAndVerify(root, PLAN_FILENAME, planBytes, prepared.objectPlanSha256);
  } finally {
    planBytes.fill(0);
  }
  return Object.freeze({
    schemaVersion: 1,
    outputDirectory: root,
    objectPlanPath: path.join(root, PLAN_FILENAME),
    objectCount: prepared.objectPlan.objectCount,
    objectPlanSha256: prepared.objectPlanSha256,
  });
}

const HELP = `Usage: node scripts/sign-gateway-release.mjs \\
  --release-dir <public-release-dir> \\
  --release <gateway-vX.Y.Z> --channel <channel> \\
  --key-id <id> --public-key <raw-ed25519-base64url> \\
  --private-key-stdin [--write-publish-directory --out <new-dir>] \\
  [--reviewed-fault-injection exact-version-health-probe-v1]

The private key seed must be exactly 32 raw bytes on stdin. It is never read
from argv, environment, or a file. Without --write-publish-directory the CLI
is an offline dry run and prints only the canonical, secret-free R2 object plan.
There is intentionally no live uploader: every external upload must guarantee
atomic create-only writes and reject an existing release prefix.

A candidate containing the reviewed exact-version probe fault marker is
signable only on channel canary and only with the exact explicit
--reviewed-fault-injection acknowledgement shown above. The acknowledgement is
rejected for every ordinary candidate.
`;

function parseCliArguments(argv) {
  if (!Array.isArray(argv)) fail();
  if (argv.length === 1 && argv[0] === '--help') return { help: true };
  const values = {};
  let write = false;
  let stdinKey = false;
  const valueFlags = new Set([
    '--release-dir', '--release', '--channel', '--key-id', '--public-key', '--out',
    '--reviewed-fault-injection',
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === '--private-key-stdin') {
      if (stdinKey) fail();
      stdinKey = true;
      continue;
    }
    if (flag === '--write-publish-directory') {
      if (write) fail();
      write = true;
      continue;
    }
    if (!valueFlags.has(flag) || index + 1 >= argv.length || argv[index + 1].startsWith('--')) fail();
    if (Object.hasOwn(values, flag)) fail();
    values[flag] = argv[index + 1];
    index += 1;
  }
  if (
    !stdinKey ||
    !v.is(STRING_SCHEMA, values['--release-dir']) ||
    !v.is(STRING_SCHEMA, values['--release']) ||
    !v.is(STRING_SCHEMA, values['--channel']) ||
    !v.is(STRING_SCHEMA, values['--key-id']) ||
    !v.is(STRING_SCHEMA, values['--public-key']) ||
    (write !== v.is(STRING_SCHEMA, values['--out']))
  ) fail();
  return {
    help: false,
    write,
    releaseDirectory: values['--release-dir'],
    release: values['--release'],
    channel: values['--channel'],
    keyId: values['--key-id'],
    publicKey: values['--public-key'],
    outputDirectory: values['--out'],
    reviewedFaultInjection: values['--reviewed-fault-injection'],
  };
}

async function readRawSeed(readable) {
  const chunks = [];
  let total = 0;
  try {
    for await (const chunk of readable) {
      if (!(chunk instanceof Uint8Array)) fail();
      total += chunk.byteLength;
      if (total > 32) {
        chunk.fill(0);
        fail();
      }
      const owned = Buffer.alloc(chunk.byteLength);
      owned.set(chunk);
      chunk.fill(0);
      chunks.push(owned);
    }
    if (total !== 32) fail();
    const seed = Buffer.concat(chunks, 32);
    for (const chunk of chunks) chunk.fill(0);
    return seed;
  } catch (error) {
    for (const chunk of chunks) chunk.fill(0);
    if (error instanceof ReleaseSigningError) throw error;
    fail();
  }
}

export async function runReleaseSigningCli({ argv, stdin, stdout, stderr }) {
  let seed;
  try {
    const options = parseCliArguments(argv);
    if (options.help) {
      stdout.write(HELP);
      return 0;
    }
    seed = await readRawSeed(stdin);
    const signingInput = {
      channel: options.channel,
      keyId: options.keyId,
      privateKeySeed: seed,
      publicKey: options.publicKey,
      release: options.release,
      releaseDirectory: options.releaseDirectory,
    };
    if (options.reviewedFaultInjection !== undefined) {
      signingInput.reviewedFaultInjection = options.reviewedFaultInjection;
    }
    const prepared = await prepareSignedReleasePublishPlan(signingInput);
    if (options.write) {
      await writeSignedReleasePublishDirectory(prepared, options.outputDirectory);
    }
    stdout.write(`${prepared.objectPlanCanonicalJson}\n`);
    return 0;
  } catch {
    stderr.write('Release signing failed. No live upload was attempted.\n');
    return 1;
  } finally {
    if (seed) seed.fill(0);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = await runReleaseSigningCli({
    argv: process.argv.slice(2),
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
  });
}
