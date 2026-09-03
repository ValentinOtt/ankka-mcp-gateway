#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { constants as FS_CONSTANTS } from 'node:fs';
import {
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
  realpath,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build as esbuildBuild, version as esbuildRuntimeVersion } from 'esbuild';
import * as v from 'valibot';

import {
  LIVE_INSTALLER_HOSTNAME,
  LIVE_INSTALLER_OAUTH_CLIENT_ID,
  LIVE_INSTALLER_WORKER_NAME,
  parseIsolatedCanaryTarget,
  readIsolatedCanaryTargetFile,
} from './isolated-canary-target.mjs';

const APP_ROOT = fileURLToPath(new URL('../', import.meta.url));
const REPOSITORY_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const COMPATIBILITY_DATE = '2026-08-14';
const WORKER_NAME = LIVE_INSTALLER_WORKER_NAME;
const PUBLIC_HOSTNAME = LIVE_INSTALLER_HOSTNAME;
const OAUTH_CLIENT_ID = LIVE_INSTALLER_OAUTH_CLIENT_ID;
const EXPECTED_ESBUILD_VERSION = '0.28.1';
const EXPECTED_VALIBOT_VERSION = '1.4.2';
const EXPECTED_WRANGLER_VERSION = '4.127.0';
const RELEASE_BUCKET_BINDING = 'GATEWAY_RELEASE_BUCKET';
const SESSION_BINDING = 'TWO_STAGE_DEPLOY_SESSION';
const SESSION_CLASS = 'TwoStageDeploySession';
const SESSION_MIGRATION_TAG = 'v1';
const ANONYMOUS_SESSION_RATE_LIMIT_BINDING = 'ANONYMOUS_SESSION_RATE_LIMIT';
const ANONYMOUS_SESSION_RATE_LIMIT_NAMESPACE_ID = '588230349';
const SESSION_READ_RATE_LIMIT_BINDING = 'SESSION_READ_RATE_LIMIT';
const SESSION_READ_RATE_LIMIT_NAMESPACE_ID = '913742685';
const SESSION_MUTATION_RATE_LIMIT_BINDING = 'SESSION_MUTATION_RATE_LIMIT';
const SESSION_MUTATION_RATE_LIMIT_NAMESPACE_ID = '74228090';
const RELEASE_ROOT = 'ankka-mcp-gateway/releases';
const MAX_INPUT_BYTES = 16 * 1024;
const MAX_GENERATED_FILE_BYTES = 2_500_000;
const MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024;
const MAX_TOOL_FILE_BYTES = 24 * 1024 * 1024;
const RELEASE_PATTERN = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const ACCOUNT_ID_PATTERN = /^[a-f0-9]{32}$/u;
const CHANNEL_PATTERN = /^(?:canary|stable)$/u;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const PUBLIC_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const BUCKET_PATTERN = /^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$/u;
const SAFE_SEGMENT = /^[A-Za-z0-9._-]+$/u;
const EVIDENCE_SEGMENT = /^[A-Za-z0-9@._-]+$/u;
// Bindings the two-stage runtime reads at request time that are provisioned
// outside the repository (`wrangler secret put`), never written into a
// generated file. The customer client id, issuer public key, and key id are
// not secrets, but they are provisioned the same way so the artifact stays
// bound to the pin alone and a deploy never removes them.
const PROVISIONED_BINDINGS = Object.freeze([
  'CLOUDFLARE_OAUTH_CLIENT_SECRET',
  'DEPLOY_SESSION_ENCRYPTION_KEY',
  'CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID',
  'CLOUDFLARE_OWNERSHIP_ISSUER_PRIVATE_KEY',
  'CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY',
  'CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID',
]);
const SECRET_ASSIGNMENT = new RegExp(`^(?:${PROVISIONED_BINDINGS.join('|')}|BOOTSTRAP_NONCE_DERIVATION_KEY)\\s*=`, 'mu');
const LEGACY_RUNTIME_SOURCES = Object.freeze([
  'src/durable/gateway-deploy-session.ts',
  'src/hosted-installer-analytics.ts',
  'src/index.ts',
  'src/reviewed-runtime.ts',
]);
const REQUIRED_RUNTIME_SOURCES = Object.freeze([
  'src/two-stage-deploy-session.ts',
  'src/two-stage-runtime.ts',
]);
const VALIBOT_RUNTIME_LOGICAL_PATH = '/node_modules/valibot/dist/index.mjs';
const BOOLEAN_SCHEMA = v.boolean();
const NUMBER_SCHEMA = v.number();
const PLAIN_OBJECT_SCHEMA = v.object({});
const STRING_SCHEMA = v.string();
const GENERATED_FILES = Object.freeze([
  'reviewed-canary-worker.mjs',
  'reviewed-rollback-worker.mjs',
  'wrangler.canary.toml',
  'wrangler.rollback.toml',
]);
const RECORD_FILENAME = 'reviewed-canary-record.json';
const EXACT_OUTPUT_FILES = Object.freeze([...GENERATED_FILES, RECORD_FILENAME].sort());
const PUBLIC_ORIGIN_DECLARATION = "export const PUBLIC_ORIGIN = 'https://deploy.ankka.ai';";
const MAX_CONTROL_PLANE_ORIGIN_LENGTH = 2_048;
const LIVE_DEPLOYMENT_TARGET = Object.freeze({
  hostname: PUBLIC_HOSTNAME,
  oauthClientId: OAUTH_CLIENT_ID,
  workerName: WORKER_NAME,
});

export class ReviewedCanaryGenerationError extends Error {
  constructor() {
    super('Reviewed canary generation failed');
    this.name = 'ReviewedCanaryGenerationError';
    this.code = 'reviewed_canary_generation_failed';
  }
}

function fail() {
  throw new ReviewedCanaryGenerationError();
}

function parseControlPlaneOrigin(value) {
  if (!v.is(STRING_SCHEMA, value) || value.length === 0 || value.length > MAX_CONTROL_PLANE_ORIGIN_LENGTH) fail();
  try {
    const parsed = new URL(value);
    if (
      parsed.protocol !== 'https:' || parsed.username !== '' || parsed.password !== '' ||
      parsed.port !== '' || parsed.pathname !== '/' || parsed.search !== '' ||
      parsed.hash !== '' || parsed.origin !== value || value.includes("'")
    ) fail();
  } catch (error) {
    if (error instanceof ReviewedCanaryGenerationError) throw error;
    fail();
  }
  return value;
}

function isPlainRecord(value) {
  return v.is(PLAIN_OBJECT_SCHEMA, value) &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, keys) {
  if (!isPlainRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function safeInteger(value, maximum = Number.MAX_SAFE_INTEGER) {
  return v.is(NUMBER_SCHEMA, value) && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function isWithinRepository(filename) {
  const relative = path.relative(path.resolve(REPOSITORY_ROOT), filename);
  return relative === '' || (
    relative !== '..' &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

function canonicalJson(value) {
  return canonicalValue(value, new Set());
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
  if (isPlainRecord(value)) {
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

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function parsePin(input) {
  if (!exactKeys(input, [
    'artifactSha256',
    'channel',
    'controlPlaneOrigin',
    'keyId',
    'publicKey',
    'release',
    'schemaVersion',
  ])) fail();
  if (
    input.schemaVersion !== 1 ||
    !v.is(STRING_SCHEMA, input.channel) || !CHANNEL_PATTERN.test(input.channel) ||
    parseControlPlaneOrigin(input.controlPlaneOrigin) !== input.controlPlaneOrigin ||
    !v.is(STRING_SCHEMA, input.release) || !RELEASE_PATTERN.test(input.release) ||
    !v.is(STRING_SCHEMA, input.keyId) || !KEY_ID_PATTERN.test(input.keyId) ||
    !v.is(STRING_SCHEMA, input.publicKey) || !PUBLIC_KEY_PATTERN.test(input.publicKey) ||
    !v.is(STRING_SCHEMA, input.artifactSha256) || !SHA256_PATTERN.test(input.artifactSha256)
  ) fail();
  let decoded;
  try {
    decoded = Buffer.from(input.publicKey, 'base64url');
    if (decoded.byteLength !== 32 || decoded.toString('base64url') !== input.publicKey) fail();
  } finally {
    decoded?.fill(0);
  }
  return Object.freeze({
    schemaVersion: 1,
    channel: input.channel,
    controlPlaneOrigin: input.controlPlaneOrigin,
    release: input.release,
    keyId: input.keyId,
    publicKey: input.publicKey,
    artifactSha256: input.artifactSha256,
  });
}

function parsePublicationResult(input) {
  if (!exactKeys(input, [
    'accountId',
    'artifactSha256',
    'bucketName',
    'channel',
    'controlPlaneOrigin',
    'keyId',
    'objectPlanSha256',
    'prefix',
    'publicKey',
    'release',
    'releaseEnvelopeSha256',
    'schemaVersion',
    'status',
  ])) fail();
  if (
    input.schemaVersion !== 1 ||
    input.status !== 'published' ||
    !v.is(STRING_SCHEMA, input.accountId) || !ACCOUNT_ID_PATTERN.test(input.accountId) ||
    !v.is(STRING_SCHEMA, input.bucketName) || !BUCKET_PATTERN.test(input.bucketName) ||
    !v.is(STRING_SCHEMA, input.channel) || !CHANNEL_PATTERN.test(input.channel) ||
    parseControlPlaneOrigin(input.controlPlaneOrigin) !== input.controlPlaneOrigin ||
    !v.is(STRING_SCHEMA, input.release) || !RELEASE_PATTERN.test(input.release) ||
    !v.is(STRING_SCHEMA, input.keyId) || !KEY_ID_PATTERN.test(input.keyId) ||
    !v.is(STRING_SCHEMA, input.publicKey) || !PUBLIC_KEY_PATTERN.test(input.publicKey) ||
    !v.is(STRING_SCHEMA, input.artifactSha256) || !SHA256_PATTERN.test(input.artifactSha256) ||
    !v.is(STRING_SCHEMA, input.releaseEnvelopeSha256) || !SHA256_PATTERN.test(input.releaseEnvelopeSha256) ||
    !v.is(STRING_SCHEMA, input.objectPlanSha256) || !SHA256_PATTERN.test(input.objectPlanSha256)
  ) fail();
  const prefix = `${RELEASE_ROOT}/${input.channel}/${input.release}/`;
  if (input.prefix !== prefix) fail();
  return Object.freeze({
    schemaVersion: 1,
    status: 'published',
    accountId: input.accountId,
    bucketName: input.bucketName,
    channel: input.channel,
    controlPlaneOrigin: input.controlPlaneOrigin,
    release: input.release,
    prefix,
    keyId: input.keyId,
    publicKey: input.publicKey,
    artifactSha256: input.artifactSha256,
    releaseEnvelopeSha256: input.releaseEnvelopeSha256,
    objectPlanSha256: input.objectPlanSha256,
  });
}

function verifiedInputs(pinInput, publicationInput) {
  const pin = parsePin(pinInput);
  const publication = parsePublicationResult(publicationInput);
  if (
    pin.channel !== publication.channel ||
    pin.release !== publication.release ||
    pin.keyId !== publication.keyId ||
    pin.publicKey !== publication.publicKey ||
    pin.controlPlaneOrigin !== publication.controlPlaneOrigin ||
    pin.artifactSha256 !== publication.artifactSha256
  ) fail();
  return Object.freeze({ pin, publication });
}

function verifiedIsolatedTarget(input, accountId) {
  let target;
  try {
    target = parseIsolatedCanaryTarget(input);
  } catch {
    fail();
  }
  if (target.accountId !== accountId) fail();
  return target;
}

async function readRegularJson(filename) {
  if (!v.is(STRING_SCHEMA, filename) || filename.length === 0 || filename.includes('\0')) fail();
  const resolved = path.resolve(filename);
  let handle;
  try {
    const before = await lstat(resolved);
    if (!before.isFile() || before.isSymbolicLink() || !safeInteger(before.size, MAX_INPUT_BYTES)) fail();
    handle = await open(resolved, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (
      !opened.isFile() ||
      opened.size !== before.size ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino
    ) fail();
    const bytes = await handle.readFile();
    if (bytes.byteLength !== opened.size) fail();
    let serialized;
    try {
      serialized = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      return JSON.parse(serialized);
    } finally {
      bytes.fill(0);
    }
  } catch (error) {
    if (error instanceof ReviewedCanaryGenerationError) throw error;
    fail();
  } finally {
    await handle?.close().catch(() => {});
  }
}

function activeEntrypointSource(pin) {
  return `import { TwoStageDeploySession } from './src/two-stage-deploy-session';\n` +
    `import { createTwoStageDeployRuntime } from './src/two-stage-runtime';\n\n` +
    `const REVIEWED_CANARY_PIN = Object.freeze({\n` +
    `  schemaVersion: 1,\n` +
    `  channel: ${JSON.stringify(pin.channel)},\n` +
    `  controlPlaneOrigin: ${JSON.stringify(pin.controlPlaneOrigin)},\n` +
    `  release: ${JSON.stringify(pin.release)},\n` +
    `  keyId: ${JSON.stringify(pin.keyId)},\n` +
    `  publicKey: ${JSON.stringify(pin.publicKey)},\n` +
    `  artifactSha256: ${JSON.stringify(pin.artifactSha256)},\n` +
    `} as const);\n\n` +
    `export { TwoStageDeploySession };\n` +
    `export default createTwoStageDeployRuntime(REVIEWED_CANARY_PIN);\n`;
}

function rollbackEntrypointSource() {
  return `import { TwoStageDeploySession } from './src/two-stage-deploy-session';\n` +
    `import { createTwoStageDeployEntrypoint } from './src/two-stage-runtime';\n\n` +
    `const ROLLBACK_ACTIVATION = Object.freeze({ enabled: false, pin: null } as const);\n\n` +
    `export { TwoStageDeploySession };\n` +
    `export default createTwoStageDeployEntrypoint(ROLLBACK_ACTIVATION);\n`;
}

async function readRegularBytes(absolutePath, maximumBytes) {
  let handle;
  try {
    const before = await lstat(absolutePath);
    if (
      !before.isFile() ||
      before.isSymbolicLink() ||
      !safeInteger(before.size, maximumBytes)
    ) fail();
    handle = await open(absolutePath, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (
      !opened.isFile() ||
      opened.size !== before.size ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino
    ) fail();
    const bytes = await handle.readFile();
    if (bytes.byteLength !== opened.size) fail();
    return bytes;
  } catch (error) {
    if (error instanceof ReviewedCanaryGenerationError) throw error;
    fail();
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function loadSourceSnapshot() {
  const sourceRoot = path.join(APP_ROOT, 'src');
  const snapshot = new Map();
  const visit = async (absoluteDirectory, relativeDirectory) => {
    let entries;
    try {
      entries = await readdir(absoluteDirectory, { withFileTypes: true });
    } catch {
      fail();
    }
    entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
    for (const entry of entries) {
      if (!SAFE_SEGMENT.test(entry.name) || entry.name === '.' || entry.name === '..') fail();
      const absolute = path.join(absoluteDirectory, entry.name);
      const relative = relativeDirectory.length === 0
        ? entry.name
        : `${relativeDirectory}/${entry.name}`;
      const metadata = await lstat(absolute).catch(() => fail());
      if (metadata.isSymbolicLink()) fail();
      if (metadata.isDirectory()) {
        await visit(absolute, relative);
        continue;
      }
      if (!metadata.isFile() || path.posix.extname(relative) !== '.ts') fail();
      const bytes = await readRegularBytes(absolute, MAX_SOURCE_FILE_BYTES);
      let contents;
      try {
        contents = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      } catch {
        bytes.fill(0);
        fail();
      }
      const logicalPath = `/src/${relative}`;
      snapshot.set(logicalPath, Object.freeze({
        byteSize: bytes.byteLength,
        contents,
        path: logicalPath.slice(1),
        sha256: sha256Hex(bytes),
      }));
      bytes.fill(0);
    }
  };
  await visit(sourceRoot, '');
  const valibotBytes = await readRegularBytes(
    path.join(REPOSITORY_ROOT, VALIBOT_RUNTIME_LOGICAL_PATH.slice(1)),
    MAX_SOURCE_FILE_BYTES,
  );
  let valibotContents;
  try {
    valibotContents = new TextDecoder('utf-8', { fatal: true }).decode(valibotBytes);
    snapshot.set(VALIBOT_RUNTIME_LOGICAL_PATH, Object.freeze({
      byteSize: valibotBytes.byteLength,
      contents: valibotContents,
      path: VALIBOT_RUNTIME_LOGICAL_PATH.slice(1),
      sha256: sha256Hex(valibotBytes),
    }));
  } finally {
    valibotBytes.fill(0);
  }
  if (snapshot.size === 0) fail();
  return snapshot;
}

function resolveSnapshotPath(snapshot, importer, requestPath) {
  if (!v.is(STRING_SCHEMA, requestPath) || requestPath.includes('\\')) fail();
  if (requestPath === 'valibot') {
    if (!snapshot.has(VALIBOT_RUNTIME_LOGICAL_PATH)) fail();
    return VALIBOT_RUNTIME_LOGICAL_PATH;
  }
  if (!requestPath.startsWith('.')) fail();
  const normalizedImporter = importer.startsWith('/') ? importer : `/${importer}`;
  const base = path.posix.resolve(path.posix.dirname(normalizedImporter), requestPath);
  const candidates = [base, `${base}.ts`, `${base}/index.ts`];
  const matches = candidates.filter((candidate) => snapshot.has(candidate));
  if (matches.length !== 1) fail();
  return matches[0];
}

function sourceInputRecords(snapshot, used) {
  return Object.freeze([...used].sort().map((logicalPath) => {
    const source = snapshot.get(logicalPath);
    if (!source) fail();
    return Object.freeze({
      byteSize: source.byteSize,
      path: source.path,
      sha256: source.sha256,
    });
  }));
}

function compiledSourceContents(logicalPath, source, publicOrigin) {
  if (logicalPath !== '/src/constants.ts') return source.contents;
  const first = source.contents.indexOf(PUBLIC_ORIGIN_DECLARATION);
  if (
    first < 0 ||
    source.contents.indexOf(PUBLIC_ORIGIN_DECLARATION, first + PUBLIC_ORIGIN_DECLARATION.length) !== -1
  ) fail();
  return source.contents.replace(
    PUBLIC_ORIGIN_DECLARATION,
    `export const PUBLIC_ORIGIN = ${JSON.stringify(publicOrigin)};`,
  );
}

async function bundleWorkerModule(kind, entrySource, snapshot, publicOrigin) {
  if (
    !['active', 'rollback'].includes(kind) ||
    !v.is(STRING_SCHEMA, entrySource) ||
    !v.is(STRING_SCHEMA, publicOrigin) ||
    !/^https:\/\/[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])$/u.test(publicOrigin)
  ) fail();
  const used = new Set();
  let result;
  try {
    result = await esbuildBuild({
      absWorkingDir: APP_ROOT,
      bundle: true,
      charset: 'utf8',
      format: 'esm',
      legalComments: 'none',
      logLevel: 'silent',
      metafile: true,
      minify: false,
      platform: 'browser',
      plugins: [{
        name: 'ankka-reviewed-canary-source-snapshot',
        setup(build) {
          build.onResolve({ filter: /.*/ }, (args) => {
            try {
              return {
                namespace: 'snapshot',
                path: resolveSnapshotPath(snapshot, args.importer, args.path),
              };
            } catch {
              return { errors: [{ text: 'reviewed_canary_source_resolution_failed' }] };
            }
          });
          build.onLoad({ filter: /.*/, namespace: 'snapshot' }, (args) => {
            const source = snapshot.get(args.path);
            if (!source) return { errors: [{ text: 'reviewed_canary_source_load_failed' }] };
            used.add(args.path);
            return {
              contents: compiledSourceContents(args.path, source, publicOrigin),
              loader: args.path.endsWith('.ts') ? 'ts' : 'js',
              resolveDir: path.posix.dirname(args.path),
            };
          });
        },
      }],
      sourcemap: false,
      stdin: {
        contents: entrySource,
        loader: 'ts',
        resolveDir: '/',
        sourcefile: `generated-${kind}-entrypoint.ts`,
      },
      target: 'es2022',
      treeShaking: true,
      write: false,
    });
  } catch {
    fail();
  }
  if (
    !result ||
    !Array.isArray(result.outputFiles) ||
    result.outputFiles.length !== 1 ||
    !isPlainRecord(result.metafile) ||
    !isPlainRecord(result.metafile.outputs)
  ) fail();
  const outputMetadata = Object.values(result.metafile.outputs);
  if (
    outputMetadata.length !== 1 ||
    !isPlainRecord(outputMetadata[0]) ||
    !Array.isArray(outputMetadata[0].imports) ||
    outputMetadata[0].imports.length !== 0
  ) fail();
  const contents = result.outputFiles[0].text;
  if (
    !v.is(STRING_SCHEMA, contents) ||
    Buffer.byteLength(contents, 'utf8') === 0 ||
    Buffer.byteLength(contents, 'utf8') > MAX_GENERATED_FILE_BYTES ||
    /sourceMappingURL\s*=/u.test(contents) ||
    /\bimport\s*(?:\(|[^;]*?\bfrom\s*)["']\.{1,2}\//u.test(contents)
  ) fail();
  const entryBytes = Buffer.from(entrySource, 'utf8');
  const outputBytes = Buffer.from(contents, 'utf8');
  try {
    return Object.freeze({
      contents,
      provenance: Object.freeze({
        entryByteSize: entryBytes.byteLength,
        entrySha256: sha256Hex(entryBytes),
        kind,
        outputByteSize: outputBytes.byteLength,
        outputSha256: sha256Hex(outputBytes),
        publicOrigin,
        sourceInputs: sourceInputRecords(snapshot, used),
      }),
    });
  } finally {
    entryBytes.fill(0);
    outputBytes.fill(0);
  }
}

async function fileEvidence(relativePath, maximumBytes = MAX_TOOL_FILE_BYTES, root = APP_ROOT) {
  if (
    !v.is(STRING_SCHEMA, relativePath) ||
    relativePath.startsWith('/') ||
    relativePath.includes('\\') ||
    relativePath.split('/').some((segment) => !EVIDENCE_SEGMENT.test(segment) || segment === '.' || segment === '..')
  ) fail();
  const absolute = path.resolve(root, ...relativePath.split('/'));
  const containment = path.relative(root, absolute);
  if (containment.length === 0 || containment.startsWith(`..${path.sep}`) || path.isAbsolute(containment)) fail();
  const bytes = await readRegularBytes(absolute, maximumBytes);
  try {
    return Object.freeze({
      byteSize: bytes.byteLength,
      path: relativePath,
      sha256: sha256Hex(bytes),
    });
  } finally {
    bytes.fill(0);
  }
}

async function readToolJson(relativePath, root = APP_ROOT) {
  const absolute = path.resolve(root, ...relativePath.split('/'));
  const bytes = await readRegularBytes(absolute, MAX_TOOL_FILE_BYTES);
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    fail();
  } finally {
    bytes.fill(0);
  }
}

async function loadToolchainProvenance() {
  const esbuildPlatformPackageName = `@esbuild/${process.platform}-${process.arch}`;
  const esbuildPlatformRoot = `node_modules/${esbuildPlatformPackageName}`;
  const [lock, esbuildPackage, esbuildPlatformPackage, valibotPackage, wranglerPackage] = await Promise.all([
    readToolJson('package-lock.json', REPOSITORY_ROOT),
    readToolJson('node_modules/esbuild/package.json', REPOSITORY_ROOT),
    readToolJson(`${esbuildPlatformRoot}/package.json`, REPOSITORY_ROOT),
    readToolJson('node_modules/valibot/package.json', REPOSITORY_ROOT),
    readToolJson('node_modules/wrangler/package.json', REPOSITORY_ROOT),
  ]);
  if (
    esbuildRuntimeVersion !== EXPECTED_ESBUILD_VERSION ||
    !isPlainRecord(esbuildPackage) ||
    esbuildPackage.name !== 'esbuild' ||
    esbuildPackage.version !== EXPECTED_ESBUILD_VERSION ||
    esbuildPackage.main !== 'lib/main.js' ||
    !isPlainRecord(esbuildPlatformPackage) ||
    esbuildPlatformPackage.name !== esbuildPlatformPackageName ||
    esbuildPlatformPackage.version !== EXPECTED_ESBUILD_VERSION ||
    !isPlainRecord(valibotPackage) ||
    valibotPackage.name !== 'valibot' ||
    valibotPackage.version !== EXPECTED_VALIBOT_VERSION ||
    valibotPackage.main !== './dist/index.mjs' ||
    !isPlainRecord(wranglerPackage) ||
    wranglerPackage.name !== 'wrangler' ||
    wranglerPackage.version !== EXPECTED_WRANGLER_VERSION ||
    !isPlainRecord(wranglerPackage.bin) ||
    wranglerPackage.bin.wrangler !== './bin/wrangler.js' ||
    !isPlainRecord(lock) ||
    !isPlainRecord(lock.packages) ||
    lock.packages['node_modules/esbuild']?.version !== EXPECTED_ESBUILD_VERSION ||
    lock.packages[esbuildPlatformRoot]?.version !== EXPECTED_ESBUILD_VERSION ||
    lock.packages['node_modules/valibot']?.version !== EXPECTED_VALIBOT_VERSION ||
    lock.packages['node_modules/wrangler']?.version !== EXPECTED_WRANGLER_VERSION
  ) fail();
  const [
    packageLock,
    esbuildPackageFile,
    esbuildRuntime,
    esbuildLauncher,
    esbuildNativeBinary,
    esbuildPlatformPackageFile,
    valibotPackageFile,
    valibotRuntime,
    wranglerPackageFile,
    wranglerCli,
    wranglerRuntime,
    wranglerSchema,
  ] =
    await Promise.all([
      fileEvidence('package-lock.json', MAX_TOOL_FILE_BYTES, REPOSITORY_ROOT),
      fileEvidence('node_modules/esbuild/package.json', MAX_TOOL_FILE_BYTES, REPOSITORY_ROOT),
      fileEvidence('node_modules/esbuild/lib/main.js', MAX_TOOL_FILE_BYTES, REPOSITORY_ROOT),
      fileEvidence('node_modules/esbuild/bin/esbuild', MAX_TOOL_FILE_BYTES, REPOSITORY_ROOT),
      fileEvidence(`${esbuildPlatformRoot}/bin/esbuild`, MAX_TOOL_FILE_BYTES, REPOSITORY_ROOT),
      fileEvidence(`${esbuildPlatformRoot}/package.json`, MAX_TOOL_FILE_BYTES, REPOSITORY_ROOT),
      fileEvidence('node_modules/valibot/package.json', MAX_TOOL_FILE_BYTES, REPOSITORY_ROOT),
      fileEvidence('node_modules/valibot/dist/index.mjs', MAX_TOOL_FILE_BYTES, REPOSITORY_ROOT),
      fileEvidence('node_modules/wrangler/package.json', MAX_TOOL_FILE_BYTES, REPOSITORY_ROOT),
      fileEvidence('node_modules/wrangler/bin/wrangler.js', MAX_TOOL_FILE_BYTES, REPOSITORY_ROOT),
      fileEvidence('node_modules/wrangler/wrangler-dist/cli.js', MAX_TOOL_FILE_BYTES, REPOSITORY_ROOT),
      fileEvidence('node_modules/wrangler/config-schema.json', MAX_TOOL_FILE_BYTES, REPOSITORY_ROOT),
    ]);
  return Object.freeze({
    bundler: Object.freeze({
      name: 'esbuild',
      launcherFile: esbuildLauncher,
      nativeBinaryFile: esbuildNativeBinary,
      packageFile: esbuildPackageFile,
      platform: `${process.platform}-${process.arch}`,
      platformPackageFile: esbuildPlatformPackageFile,
      runtimeFile: esbuildRuntime,
      version: EXPECTED_ESBUILD_VERSION,
    }),
    packageLock,
    runtimeDependencies: Object.freeze({
      valibot: Object.freeze({
        name: 'valibot',
        packageFile: valibotPackageFile,
        runtimeFile: valibotRuntime,
        version: EXPECTED_VALIBOT_VERSION,
      }),
    }),
    schemaVersion: 1,
    wrangler: Object.freeze({
      cliFile: wranglerCli,
      name: 'wrangler',
      packageFile: wranglerPackageFile,
      runtimeFile: wranglerRuntime,
      schemaFile: wranglerSchema,
      version: EXPECTED_WRANGLER_VERSION,
    }),
  });
}

async function materializeWorkerModules(pin, deploymentTarget) {
  const toolchain = await loadToolchainProvenance();
  const snapshot = await loadSourceSnapshot();
  const publicOrigin = `https://${deploymentTarget.hostname}`;
  const active = await bundleWorkerModule('active', activeEntrypointSource(pin), snapshot, publicOrigin);
  const rollback = await bundleWorkerModule('rollback', rollbackEntrypointSource(), snapshot, publicOrigin);
  const toolchainAfterBuild = await loadToolchainProvenance();
  if (canonicalJson(toolchainAfterBuild) !== canonicalJson(toolchain)) fail();
  return Object.freeze({
    buildProvenance: Object.freeze({
      bundles: Object.freeze([active.provenance, rollback.provenance]),
      schemaVersion: 1,
      toolchain,
    }),
    modules: Object.freeze({
      'reviewed-canary-worker.mjs': active.contents,
      'reviewed-rollback-worker.mjs': rollback.contents,
    }),
  });
}

function observabilityConfig() {
  return `[observability]\n` +
    `enabled = false\n` +
    `head_sampling_rate = 0\n\n` +
    `[observability.logs]\n` +
    `enabled = false\n` +
    `head_sampling_rate = 0\n` +
    `invocation_logs = false\n` +
    `persist = false\n\n` +
    `[observability.traces]\n` +
    `enabled = false\n` +
    `head_sampling_rate = 0\n` +
    `persist = false\n`;
}

function baseWrangler(accountId, main, deploymentTarget) {
  return `name = ${JSON.stringify(deploymentTarget.workerName)}\n` +
    `account_id = ${JSON.stringify(accountId)}\n` +
    `main = ${JSON.stringify(main)}\n` +
    `compatibility_date = ${JSON.stringify(COMPATIBILITY_DATE)}\n` +
    `no_bundle = true\n` +
    `find_additional_modules = false\n` +
    `workers_dev = false\n` +
    `preview_urls = false\n` +
    `send_metrics = false\n\n` +
    `[[durable_objects.bindings]]\n` +
    `name = ${JSON.stringify(SESSION_BINDING)}\n` +
    `class_name = ${JSON.stringify(SESSION_CLASS)}\n\n` +
    `[[migrations]]\n` +
    `tag = ${JSON.stringify(SESSION_MIGRATION_TAG)}\n` +
    `new_sqlite_classes = [${JSON.stringify(SESSION_CLASS)}]\n\n` +
    `[[routes]]\n` +
    `pattern = ${JSON.stringify(deploymentTarget.hostname)}\n` +
    `custom_domain = true\n\n` +
    observabilityConfig();
}

function canaryWrangler(publication, deploymentTarget) {
  return baseWrangler(publication.accountId, 'reviewed-canary-worker.mjs', deploymentTarget) +
    `\n[vars]\n` +
    `CLOUDFLARE_OAUTH_CLIENT_ID = ${JSON.stringify(deploymentTarget.oauthClientId)}\n\n` +
    `# Provision these bindings outside the repository with \`wrangler secret put\`\n` +
    `# before deploying; the runtime fails closed (500 runtime_config_invalid)\n` +
    `# while any is missing. The issuer public key and key id must match the\n` +
    `# values provisioned on the auth.ankka.ai relay:\n` +
    PROVISIONED_BINDINGS.map((binding) => `# ${binding}\n`).join('') +
    `\n[[ratelimits]]\n` +
    `name = ${JSON.stringify(ANONYMOUS_SESSION_RATE_LIMIT_BINDING)}\n` +
    `namespace_id = ${JSON.stringify(ANONYMOUS_SESSION_RATE_LIMIT_NAMESPACE_ID)}\n` +
    `simple = { limit = 6, period = 60 }\n\n` +
    `[[ratelimits]]\n` +
    `name = ${JSON.stringify(SESSION_READ_RATE_LIMIT_BINDING)}\n` +
    `namespace_id = ${JSON.stringify(SESSION_READ_RATE_LIMIT_NAMESPACE_ID)}\n` +
    `simple = { limit = 120, period = 60 }\n\n` +
    `[[ratelimits]]\n` +
    `name = ${JSON.stringify(SESSION_MUTATION_RATE_LIMIT_BINDING)}\n` +
    `namespace_id = ${JSON.stringify(SESSION_MUTATION_RATE_LIMIT_NAMESPACE_ID)}\n` +
    `simple = { limit = 30, period = 60 }\n\n` +
    `[[r2_buckets]]\n` +
    `binding = ${JSON.stringify(RELEASE_BUCKET_BINDING)}\n` +
    `bucket_name = ${JSON.stringify(publication.bucketName)}\n`;
}

function rollbackWrangler(accountId, deploymentTarget) {
  return baseWrangler(accountId, 'reviewed-rollback-worker.mjs', deploymentTarget);
}

function assertSelfContainedModule(contents, kind, pin, deploymentTarget) {
  const publicOrigin = `https://${deploymentTarget.hostname}`;
  if (
    !v.is(STRING_SCHEMA, contents) ||
    !['active', 'rollback'].includes(kind) ||
    Buffer.byteLength(contents, 'utf8') === 0 ||
    Buffer.byteLength(contents, 'utf8') > MAX_GENERATED_FILE_BYTES ||
    /sourceMappingURL\s*=/u.test(contents) ||
    /(?:^|\n)\s*import(?:\s|\()/mu.test(contents) ||
    /(?:^|\n)\s*export[^;\n]*\sfrom\s*["']/mu.test(contents) ||
    !/export\s*\{[^}]*TwoStageDeploySession[^}]*\}/su.test(contents) ||
    contents.includes('GatewayDeploySession') ||
    contents.includes('HOSTED_INSTALLER_ANALYTICS') ||
    !contents.includes(publicOrigin) ||
    (deploymentTarget.hostname !== PUBLIC_HOSTNAME && contents.includes(`https://${PUBLIC_HOSTNAME}`))
  ) fail();
  if (kind === 'active') {
    if (
      !contents.includes(pin.channel) ||
      !contents.includes(pin.release) ||
      !contents.includes(pin.keyId) ||
      !contents.includes(pin.publicKey) ||
      !contents.includes(pin.artifactSha256)
    ) fail();
    return;
  }
  if (!contents.includes('enabled: false') || !contents.includes('pin: null')) fail();
}

async function materializeGeneratedArtifacts(pin, publication, deploymentTarget) {
  const built = await materializeWorkerModules(pin, deploymentTarget);
  const files = Object.freeze({
    ...built.modules,
    'wrangler.canary.toml': canaryWrangler(publication, deploymentTarget),
    'wrangler.rollback.toml': rollbackWrangler(publication.accountId, deploymentTarget),
  });
  if (!exactKeys(files, GENERATED_FILES)) fail();
  assertSelfContainedModule(files['reviewed-canary-worker.mjs'], 'active', pin, deploymentTarget);
  assertSelfContainedModule(files['reviewed-rollback-worker.mjs'], 'rollback', pin, deploymentTarget);
  for (const [filename, contents] of Object.entries(files)) {
    if (
      !GENERATED_FILES.includes(filename) ||
      !v.is(STRING_SCHEMA, contents) ||
      Buffer.byteLength(contents, 'utf8') === 0 ||
      Buffer.byteLength(contents, 'utf8') > MAX_GENERATED_FILE_BYTES ||
      SECRET_ASSIGNMENT.test(contents)
    ) fail();
  }
  return Object.freeze({ buildProvenance: built.buildProvenance, files });
}

function generatedRecord(pin, publication, files, buildProvenance, isolatedTarget = null) {
  const outputFiles = Object.entries(files).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([filename, contents]) => Object.freeze({
      byteSize: Buffer.byteLength(contents, 'utf8'),
      path: filename,
      sha256: sha256Hex(Buffer.from(contents, 'utf8')),
    }));
  const common = {
    buildProvenance,
    objectPlanSha256: publication.objectPlanSha256,
    outputFiles: Object.freeze(outputFiles),
    pin,
    publication,
  };
  if (isolatedTarget === null) {
    return Object.freeze({
      ...common,
      kind: 'ankka-gateway-deploy-reviewed-canary',
      schemaVersion: 1,
    });
  }
  return Object.freeze({
    ...common,
    deploymentTarget: isolatedTarget,
    kind: 'ankka-gateway-deploy-reviewed-isolated-canary',
    schemaVersion: 2,
  });
}

async function assertWranglerSchemaContract() {
  const schema = await readToolJson('node_modules/wrangler/config-schema.json', REPOSITORY_ROOT);
  const raw = schema?.definitions?.RawConfig?.properties;
  const r2 = raw?.r2_buckets?.items;
  const rateLimit = raw?.ratelimits?.items;
  const observability = schema?.definitions?.Observability?.properties;
  const customDomain = schema?.definitions?.CustomDomainRoute;
  const migration = schema?.definitions?.DurableObjectMigration;
  if (
    !isPlainRecord(raw) ||
    !isPlainRecord(r2) ||
    !isPlainRecord(r2.properties) ||
    !Object.hasOwn(r2.properties, 'binding') ||
    !Object.hasOwn(r2.properties, 'bucket_name') ||
    Object.hasOwn(r2.properties, 'read_only') ||
    !isPlainRecord(rateLimit) ||
    !isPlainRecord(rateLimit.properties) ||
    !Object.hasOwn(rateLimit.properties, 'name') ||
    !Object.hasOwn(rateLimit.properties, 'namespace_id') ||
    !isPlainRecord(rateLimit.properties.simple) ||
    !isPlainRecord(rateLimit.properties.simple.properties) ||
    !Object.hasOwn(rateLimit.properties.simple.properties, 'limit') ||
    !Object.hasOwn(rateLimit.properties.simple.properties, 'period') ||
    !Array.isArray(rateLimit.required) ||
    !['name', 'namespace_id', 'simple'].every((field) => rateLimit.required.includes(field)) ||
    !isPlainRecord(observability) ||
    !isPlainRecord(observability.logs?.properties) ||
    !Object.hasOwn(observability.logs.properties, 'invocation_logs') ||
    !isPlainRecord(observability.traces?.properties) ||
    !isPlainRecord(customDomain) ||
    !Array.isArray(customDomain.required) ||
    !customDomain.required.includes('pattern') ||
    !customDomain.required.includes('custom_domain') ||
    !isPlainRecord(migration) ||
    !isPlainRecord(migration.properties) ||
    !Object.hasOwn(migration.properties, 'new_sqlite_classes')
  ) fail();
  for (const field of [
    'account_id',
    'durable_objects',
    'find_additional_modules',
    'main',
    'migrations',
    'name',
    'no_bundle',
    'observability',
    'preview_urls',
    'ratelimits',
    'r2_buckets',
    'routes',
    'send_metrics',
    'vars',
    'workers_dev',
  ]) {
    if (!Object.hasOwn(raw, field)) fail();
  }
}

async function freshOutputRoot(outputDirectory, requireOutsideRepository) {
  if (
    !v.is(STRING_SCHEMA, outputDirectory) ||
    outputDirectory.length === 0 ||
    outputDirectory.includes('\0')
  ) fail();
  const requested = path.resolve(outputDirectory);
  if (
    requested === path.parse(requested).root ||
    requested === APP_ROOT ||
    requested.startsWith(`${APP_ROOT}${path.sep}`)
  ) fail();
  const basename = path.basename(requested);
  if (!SAFE_SEGMENT.test(basename) || basename === '.' || basename === '..') fail();
  let parent;
  try {
    parent = await realpath(path.dirname(requested));
    const parentMetadata = await lstat(parent);
    if (!parentMetadata.isDirectory() || parentMetadata.isSymbolicLink()) fail();
  } catch (error) {
    if (error instanceof ReviewedCanaryGenerationError) throw error;
    fail();
  }
  const outputRoot = path.join(parent, basename);
  if (requireOutsideRepository && isWithinRepository(outputRoot)) fail();
  try {
    await mkdir(outputRoot, { recursive: false, mode: 0o700 });
  } catch {
    fail();
  }
  return outputRoot;
}

async function writeExclusiveAndVerify(outputRoot, filename, contents) {
  if (!SAFE_SEGMENT.test(filename) || filename === '.' || filename === '..') fail();
  const bytes = Buffer.from(contents, 'utf8');
  const target = path.join(outputRoot, filename);
  try {
    await writeFile(target, bytes, { flag: 'wx', mode: 0o600 });
    const observed = await readFile(target);
    if (observed.byteLength !== bytes.byteLength || sha256Hex(observed) !== sha256Hex(bytes)) fail();
    observed.fill(0);
  } catch (error) {
    if (error instanceof ReviewedCanaryGenerationError) throw error;
    fail();
  } finally {
    bytes.fill(0);
  }
}

async function readGeneratedFile(outputRoot, filename) {
  const target = path.join(outputRoot, filename);
  let handle;
  try {
    const before = await lstat(target);
    if (!before.isFile() || before.isSymbolicLink() || !safeInteger(before.size, MAX_GENERATED_FILE_BYTES)) fail();
    handle = await open(target, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (opened.size !== before.size || opened.dev !== before.dev || opened.ino !== before.ino) fail();
    const bytes = await handle.readFile();
    if (bytes.byteLength !== opened.size) fail();
    return bytes;
  } catch (error) {
    if (error instanceof ReviewedCanaryGenerationError) throw error;
    fail();
  } finally {
    await handle?.close().catch(() => {});
  }
}

function parseEvidenceFile(input, options = {}) {
  if (!exactKeys(input, ['byteSize', 'path', 'sha256'])) fail();
  const maximumBytes = options.maximumBytes ?? MAX_TOOL_FILE_BYTES;
  if (
    !safeInteger(input.byteSize, maximumBytes) ||
    input.byteSize === 0 ||
    !v.is(STRING_SCHEMA, input.path) ||
    input.path.length === 0 ||
    input.path.startsWith('/') ||
    input.path.includes('\\') ||
    input.path.split('/').some(
      (segment) => !EVIDENCE_SEGMENT.test(segment) || segment === '.' || segment === '..',
    ) ||
    (options.expectedPath !== undefined && input.path !== options.expectedPath) ||
    !v.is(STRING_SCHEMA, input.sha256) ||
    !SHA256_PATTERN.test(input.sha256)
  ) fail();
  return Object.freeze({
    byteSize: input.byteSize,
    path: input.path,
    sha256: input.sha256,
  });
}

function parseBundleProvenance(input, expectedKind, pin, outputFile) {
  if (!exactKeys(input, [
    'entryByteSize',
    'entrySha256',
    'kind',
    'outputByteSize',
    'outputSha256',
    'publicOrigin',
    'sourceInputs',
  ])) fail();
  if (
    input.kind !== expectedKind ||
    !safeInteger(input.entryByteSize, MAX_GENERATED_FILE_BYTES) ||
    input.entryByteSize === 0 ||
    !v.is(STRING_SCHEMA, input.entrySha256) || !SHA256_PATTERN.test(input.entrySha256) ||
    !safeInteger(input.outputByteSize, MAX_GENERATED_FILE_BYTES) ||
    input.outputByteSize === 0 ||
    !v.is(STRING_SCHEMA, input.outputSha256) || !SHA256_PATTERN.test(input.outputSha256) ||
    !v.is(STRING_SCHEMA, input.publicOrigin) ||
    !Array.isArray(input.sourceInputs) ||
    input.sourceInputs.length === 0 ||
    input.sourceInputs.length > 256 ||
    input.outputByteSize !== outputFile.byteSize ||
    input.outputSha256 !== outputFile.sha256
  ) fail();
  const sourceInputs = input.sourceInputs.map((entry) => {
    const parsed = parseEvidenceFile(entry, { maximumBytes: MAX_SOURCE_FILE_BYTES });
    const installerSource = parsed.path.startsWith('src/') && parsed.path.endsWith('.ts');
    const reviewedDependency = parsed.path === VALIBOT_RUNTIME_LOGICAL_PATH.slice(1);
    if (
      (!installerSource && !reviewedDependency) ||
      parsed.path === 'src/r2-publication-operator.ts' ||
      parsed.path === 'src/r2-release-publisher.ts' ||
      LEGACY_RUNTIME_SOURCES.includes(parsed.path)
    ) fail();
    return parsed;
  });
  const sourcePaths = sourceInputs.map((entry) => entry.path);
  if (
    new Set(sourcePaths).size !== sourcePaths.length ||
    sourcePaths.some((entry, index) => index > 0 && sourcePaths[index - 1] >= entry) ||
    !sourcePaths.includes(VALIBOT_RUNTIME_LOGICAL_PATH.slice(1)) ||
    !REQUIRED_RUNTIME_SOURCES.every((source) => sourcePaths.includes(source))
  ) fail();
  const expectedEntry = expectedKind === 'active'
    ? activeEntrypointSource(pin)
    : rollbackEntrypointSource();
  const expectedEntryBytes = Buffer.from(expectedEntry, 'utf8');
  try {
    if (
      input.entryByteSize !== expectedEntryBytes.byteLength ||
      input.entrySha256 !== sha256Hex(expectedEntryBytes)
    ) fail();
  } finally {
    expectedEntryBytes.fill(0);
  }
  return Object.freeze({
    entryByteSize: input.entryByteSize,
    entrySha256: input.entrySha256,
    kind: input.kind,
    outputByteSize: input.outputByteSize,
    outputSha256: input.outputSha256,
    publicOrigin: input.publicOrigin,
    sourceInputs: Object.freeze(sourceInputs),
  });
}

async function parseBuildProvenance(input, pin, outputFiles, deploymentTarget) {
  if (!exactKeys(input, ['bundles', 'schemaVersion', 'toolchain'])) fail();
  if (input.schemaVersion !== 1 || !Array.isArray(input.bundles) || input.bundles.length !== 2) fail();
  const currentToolchain = await loadToolchainProvenance();
  if (canonicalJson(input.toolchain) !== canonicalJson(currentToolchain)) fail();
  const outputByPath = new Map(outputFiles.map((entry) => [entry.path, entry]));
  const activeOutput = outputByPath.get('reviewed-canary-worker.mjs');
  const rollbackOutput = outputByPath.get('reviewed-rollback-worker.mjs');
  if (!activeOutput || !rollbackOutput) fail();
  const publicOrigin = `https://${deploymentTarget.hostname}`;
  const bundles = Object.freeze([
    parseBundleProvenance(input.bundles[0], 'active', pin, activeOutput),
    parseBundleProvenance(input.bundles[1], 'rollback', pin, rollbackOutput),
  ]);
  if (bundles.some((bundle) => bundle.publicOrigin !== publicOrigin)) fail();
  return Object.freeze({ bundles, schemaVersion: 1, toolchain: currentToolchain });
}

async function parseRecord(input) {
  const liveKeys = [
    'buildProvenance',
    'kind',
    'objectPlanSha256',
    'outputFiles',
    'pin',
    'publication',
    'schemaVersion',
  ];
  const isolatedKeys = [...liveKeys, 'deploymentTarget'];
  const live = exactKeys(input, liveKeys) && input.schemaVersion === 1 &&
    input.kind === 'ankka-gateway-deploy-reviewed-canary';
  const isolated = exactKeys(input, isolatedKeys) && input.schemaVersion === 2 &&
    input.kind === 'ankka-gateway-deploy-reviewed-isolated-canary';
  if (
    (!live && !isolated) ||
    !v.is(STRING_SCHEMA, input.objectPlanSha256) || !SHA256_PATTERN.test(input.objectPlanSha256) ||
    !Array.isArray(input.outputFiles) ||
    input.outputFiles.length !== GENERATED_FILES.length
  ) fail();
  const verified = verifiedInputs(input.pin, input.publication);
  if (input.objectPlanSha256 !== verified.publication.objectPlanSha256) fail();
  const deploymentTarget = isolated
    ? verifiedIsolatedTarget(input.deploymentTarget, verified.publication.accountId)
    : LIVE_DEPLOYMENT_TARGET;
  if (verified.pin.controlPlaneOrigin !== `https://${deploymentTarget.hostname}`) fail();
  const outputFiles = input.outputFiles.map((entry) => {
    const parsed = parseEvidenceFile(entry, { maximumBytes: MAX_GENERATED_FILE_BYTES });
    if (!GENERATED_FILES.includes(parsed.path)) fail();
    return parsed;
  });
  const paths = outputFiles.map((entry) => entry.path);
  if (
    new Set(paths).size !== GENERATED_FILES.length ||
    paths.some((entry, index) => index > 0 && paths[index - 1] >= entry)
  ) fail();
  const buildProvenance = await parseBuildProvenance(
    input.buildProvenance,
    verified.pin,
    outputFiles,
    deploymentTarget,
  );
  const record = {
    buildProvenance,
    kind: input.kind,
    objectPlanSha256: input.objectPlanSha256,
    outputFiles: Object.freeze(outputFiles),
    pin: verified.pin,
    publication: verified.publication,
    schemaVersion: input.schemaVersion,
  };
  if (isolated) record.deploymentTarget = deploymentTarget;
  return Object.freeze({
    deploymentTarget,
    record: Object.freeze(record),
  });
}

async function generateArtifacts(input, isolatedTargetInput) {
  const {
    outputDirectory,
    pin: pinInput,
    publicationResult,
  } = input;
  await assertWranglerSchemaContract();
  const { pin, publication } = verifiedInputs(pinInput, publicationResult);
  const deploymentTarget = isolatedTargetInput === null
    ? LIVE_DEPLOYMENT_TARGET
    : verifiedIsolatedTarget(isolatedTargetInput, publication.accountId);
  if (pin.controlPlaneOrigin !== `https://${deploymentTarget.hostname}`) fail();
  const { buildProvenance, files } = await materializeGeneratedArtifacts(
    pin,
    publication,
    deploymentTarget,
  );
  const record = generatedRecord(
    pin,
    publication,
    files,
    buildProvenance,
    isolatedTargetInput === null ? null : deploymentTarget,
  );
  const outputRoot = await freshOutputRoot(outputDirectory, isolatedTargetInput !== null);
  for (const filename of GENERATED_FILES) {
    await writeExclusiveAndVerify(outputRoot, filename, files[filename]);
  }
  await writeExclusiveAndVerify(outputRoot, RECORD_FILENAME, `${canonicalJson(record)}\n`);
  await validateGeneratedReviewedCanaryDirectory(outputRoot);
  return Object.freeze({
    schemaVersion: record.schemaVersion,
    accountId: publication.accountId,
    outputDirectory: outputRoot,
    objectPlanSha256: publication.objectPlanSha256,
    release: pin.release,
  });
}

export async function generateReviewedCanaryArtifacts(input) {
  if (!exactKeys(input, [
    'outputDirectory',
    'pin',
    'publicationResult',
  ])) fail();
  return generateArtifacts(input, null);
}

export async function generateReviewedIsolatedCanaryArtifacts(input) {
  if (!exactKeys(input, [
    'isolatedTarget',
    'outputDirectory',
    'pin',
    'publicationResult',
  ])) fail();
  return generateArtifacts(input, input.isolatedTarget);
}

export async function validateGeneratedReviewedCanaryDirectory(outputDirectory) {
  await assertWranglerSchemaContract();
  if (!v.is(STRING_SCHEMA, outputDirectory) || outputDirectory.length === 0 || outputDirectory.includes('\0')) fail();
  let outputRoot;
  try {
    outputRoot = await realpath(path.resolve(outputDirectory));
    const metadata = await lstat(outputRoot);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) fail();
  } catch (error) {
    if (error instanceof ReviewedCanaryGenerationError) throw error;
    fail();
  }
  const entries = await readdir(outputRoot, { withFileTypes: true }).catch(() => fail());
  const wranglerCache = entries.find((entry) => entry.name === '.wrangler');
  if (wranglerCache && (!wranglerCache.isDirectory() || wranglerCache.isSymbolicLink())) fail();
  const artifactEntries = entries.filter((entry) => entry.name !== '.wrangler');
  const names = artifactEntries.map((entry) => entry.name).sort();
  if (
    names.length !== EXACT_OUTPUT_FILES.length ||
    names.some((name, index) => name !== EXACT_OUTPUT_FILES[index]) ||
    artifactEntries.some((entry) => !entry.isFile() || entry.isSymbolicLink())
  ) fail();

  const recordBytes = await readGeneratedFile(outputRoot, RECORD_FILENAME);
  let parsedRecord;
  try {
    const serialized = new TextDecoder('utf-8', { fatal: true }).decode(recordBytes);
    if (!serialized.endsWith('\n')) fail();
    parsedRecord = await parseRecord(JSON.parse(serialized));
    if (`${canonicalJson(parsedRecord.record)}\n` !== serialized) fail();
  } catch (error) {
    if (error instanceof ReviewedCanaryGenerationError) throw error;
    fail();
  } finally {
    recordBytes.fill(0);
  }
  const { deploymentTarget, record } = parsedRecord;

  const expectedTextFiles = Object.freeze({
    'wrangler.canary.toml': canaryWrangler(record.publication, deploymentTarget),
    'wrangler.rollback.toml': rollbackWrangler(record.publication.accountId, deploymentTarget),
  });
  for (const fileRecord of record.outputFiles) {
    const bytes = await readGeneratedFile(outputRoot, fileRecord.path);
    try {
      if (
        bytes.byteLength !== fileRecord.byteSize ||
        sha256Hex(bytes) !== fileRecord.sha256
      ) fail();
      let contents;
      try {
        contents = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      } catch {
        fail();
      }
      if (fileRecord.path === 'reviewed-canary-worker.mjs') {
        assertSelfContainedModule(contents, 'active', record.pin, deploymentTarget);
      } else if (fileRecord.path === 'reviewed-rollback-worker.mjs') {
        assertSelfContainedModule(contents, 'rollback', record.pin, deploymentTarget);
      } else if (
        !Object.hasOwn(expectedTextFiles, fileRecord.path) ||
        contents !== expectedTextFiles[fileRecord.path]
      ) fail();
      if (SECRET_ASSIGNMENT.test(contents)) fail();
    } finally {
      bytes.fill(0);
    }
  }
  return Object.freeze({
    schemaVersion: record.schemaVersion,
    accountId: record.publication.accountId,
    outputDirectory: outputRoot,
    objectPlanSha256: record.objectPlanSha256,
    release: record.pin.release,
  });
}

export async function validateGeneratedReviewedIsolatedCanaryDirectory(outputDirectory) {
  const result = await validateGeneratedReviewedCanaryDirectory(outputDirectory);
  if (result.schemaVersion !== 2) fail();
  return result;
}

const HELP = `Usage:\n` +
  `  node scripts/generate-reviewed-canary.mjs \\\n` +
  `    --pin <exact-secret-free-pin.json> \\\n` +
  `    --publication-result <exact-publication-receipt.json> \\\n` +
  `    --output-dir <new-directory> \\\n` +
  `    [--isolated-target <exact-outside-repository-target.json>]\n` +
  `  node scripts/generate-reviewed-canary.mjs --validate-output-dir <directory>\n\n` +
  `Without --isolated-target the existing live deploy.ankka.ai artifact is generated.\n` +
  `An isolated target must use a different hostname and an ankka-gateway-deploy-isolated-* Worker.\n` +
  `This command is offline. It performs no deploy, network, environment, or Keychain access.\n`;

function parseArguments(argv) {
  if (!Array.isArray(argv)) fail();
  if (argv.length === 1 && argv[0] === '--help') return Object.freeze({ mode: 'help' });
  if (argv.length === 2 && argv[0] === '--validate-output-dir' && !argv[1].startsWith('--')) {
    return Object.freeze({ mode: 'validate', outputDirectory: argv[1] });
  }
  const required = new Set(['--pin', '--publication-result', '--output-dir']);
  const allowed = new Set([...required, '--isolated-target']);
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (!allowed.has(flag) || index + 1 >= argv.length || argv[index + 1].startsWith('--')) fail();
    if (Object.hasOwn(values, flag)) fail();
    values[flag] = argv[index + 1];
    index += 1;
  }
  if (![...required].every((flag) => Object.hasOwn(values, flag))) fail();
  return Object.freeze({
    isolatedTargetFilename: values['--isolated-target'] ?? null,
    mode: 'generate',
    outputDirectory: values['--output-dir'],
    pinFilename: values['--pin'],
    publicationFilename: values['--publication-result'],
  });
}

export async function runReviewedCanaryGeneratorCli({ argv, stderr, stdout }) {
  try {
    const options = parseArguments(argv);
    if (options.mode === 'help') {
      stdout.write(HELP);
      return 0;
    }
    if (options.mode === 'validate') {
      await validateGeneratedReviewedCanaryDirectory(options.outputDirectory);
      stdout.write('Reviewed canary artifacts are exact and secret-free.\n');
      return 0;
    }
    const [pin, publicationResult, isolatedTarget] = await Promise.all([
      readRegularJson(options.pinFilename),
      readRegularJson(options.publicationFilename),
      options.isolatedTargetFilename === null
        ? Promise.resolve(null)
        : readIsolatedCanaryTargetFile(options.isolatedTargetFilename),
    ]);
    if (isolatedTarget === null) {
      await generateReviewedCanaryArtifacts({
        outputDirectory: options.outputDirectory,
        pin,
        publicationResult,
      });
    } else {
      await generateReviewedIsolatedCanaryArtifacts({
        isolatedTarget,
        outputDirectory: options.outputDirectory,
        pin,
        publicationResult,
      });
    }
    stdout.write('Reviewed canary artifacts generated and validated. No live call was attempted.\n');
    return 0;
  } catch {
    stderr.write('Reviewed canary artifact operation failed. No deploy or live call was attempted.\n');
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = await runReviewedCanaryGeneratorCli({
    argv: process.argv.slice(2),
    stderr: process.stderr,
    stdout: process.stdout,
  });
}
