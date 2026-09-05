#!/usr/bin/env node

import {
  createHash,
  createPublicKey,
  verify as ed25519Verify,
} from 'node:crypto';
import { constants as FS_CONSTANTS } from 'node:fs';
import {
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as v from 'valibot';

const PLAN_FILENAME = 'r2-object-plan.json';
const RELEASE_ROOT = 'ankka-mcp-gateway/releases';
const ENVELOPE_FILENAME = 'release-envelope.json';
const OPERATOR_BINDING = 'RELEASE_BUCKET';
const OPERATOR_PORT = 5732;
const COMPATIBILITY_DATE = '2026-08-14';
const MAX_PLAN_BYTES = 1 * 1024 * 1024;
// Raw signed object bytes one local publisher may carry. The two customer
// The gateway embeds its BigQuery bridge and bootstrap runtime. Current signed
// releases total about 8.2 MB; bound the local publication bundle to 10 MB.
const MAX_OPERATOR_RELEASE_BYTES = 10_000_000;
const MAX_OPERATOR_OBJECTS = 512;
// Base64 expansion of the raw cap plus a fixed allowance for keys, content
// types, the canonical plan, identity, and decoder code.
const MAX_GENERATED_DATA_MODULE_BYTES = Math.ceil(MAX_OPERATOR_RELEASE_BYTES * 4 / 3) + 333_332;
const MAX_R2_KEY_BYTES = 1_024;
const MAX_SOURCE_PATH_BYTES = 1_040;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const ACCOUNT_ID_PATTERN = /^[a-f0-9]{32}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/u;
const PUBLIC_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const RELEASE_PATTERN = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const CHANNEL_PATTERN = /^(?:canary|stable)$/u;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const MAX_CONTROL_PLANE_ORIGIN_LENGTH = 2_048;
const BUCKET_PATTERN = /^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$/u;
const SAFE_SEGMENT = /^[A-Za-z0-9._-]+$/u;
const CREDENTIAL_NAME = /(?:^|[-_.])(?:api[-_.]?key|client[-_.]?secret|credential|credentials|password|passwd|private[-_.]?key|secret|secrets|token|tokens)(?:[-_.]|$)/iu;
const MUTABLE_CHANNELS = new Set(['current', 'latest', 'mutable']);
const RELEASE_ENVELOPE_SCHEMA_VERSION = 2;
const RELEASE_SIGNATURE_CONTEXT = 'ankka-mcp-gateway-release-envelope-v2';
const SPKI_PUBLIC_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const GENERATED_SOURCE_FILES = Object.freeze([
  'boundary.ts',
  'canonical-json.ts',
  'constants.ts',
  'errors.ts',
  'r2-publication-operator.ts',
  'r2-release-publisher.ts',
  'release-manifest.ts',
]);

function hasControlCharacter(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 31 || code === 127) return true;
  }
  return false;
}
const GENERATED_DEPENDENCY_FILES = Object.freeze([
  'node_modules/valibot/LICENSE.md',
  'node_modules/valibot/dist/index.mjs',
  'node_modules/valibot/package.json',
]);
const BOOLEAN_SCHEMA = v.boolean();
const NUMBER_SCHEMA = v.number();
const OBJECT_SCHEMA = v.object({});
const STRING_SCHEMA = v.string();

export class R2PublicationWorkerGenerationError extends Error {
  constructor() {
    super('R2 publication Worker generation failed');
    this.name = 'R2PublicationWorkerGenerationError';
    this.code = 'r2_publication_worker_generation_failed';
  }
}

function fail() {
  throw new R2PublicationWorkerGenerationError();
}

function isPlainRecord(value) {
  return v.is(OBJECT_SCHEMA, value) &&
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
  return Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function lexicalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
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
    if (error instanceof R2PublicationWorkerGenerationError) throw error;
    fail();
  }
  return value;
}

function canonicalJson(value) {
  return canonicalValue(value, new Set());
}

function releaseSignatureCanonicalJson(channel, keyId, manifest) {
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

function safePath(value) {
  if (
    !v.is(STRING_SCHEMA, value) ||
    value.length === 0 ||
    value.startsWith('/') ||
    value.endsWith('/') ||
    value.includes('\\') ||
    value.includes('%') ||
    hasControlCharacter(value)
  ) return false;
  return value.split('/').every((segment) =>
    SAFE_SEGMENT.test(segment) &&
    segment !== '.' &&
    segment !== '..' &&
    !CREDENTIAL_NAME.test(segment));
}

function parseObjectEntry(input) {
  if (!exactKeys(input, ['byteSize', 'contentType', 'key', 'sha256', 'sourcePath'])) fail();
  if (
    !safeInteger(input.byteSize, MAX_OPERATOR_RELEASE_BYTES) ||
    !v.is(STRING_SCHEMA, input.contentType) ||
    input.contentType.length === 0 ||
    input.contentType.length > 128 ||
    hasControlCharacter(input.contentType) ||
    !safePath(input.key) ||
    Buffer.byteLength(input.key, 'utf8') > MAX_R2_KEY_BYTES ||
    !v.is(STRING_SCHEMA, input.sha256) ||
    !SHA256_PATTERN.test(input.sha256) ||
    !safePath(input.sourcePath) ||
    Buffer.byteLength(input.sourcePath, 'utf8') > MAX_SOURCE_PATH_BYTES
  ) fail();
  return Object.freeze({
    byteSize: input.byteSize,
    contentType: input.contentType,
    key: input.key,
    sha256: input.sha256,
    sourcePath: input.sourcePath,
  });
}

function parseObjectPlan(input) {
  if (!exactKeys(input, [
    'artifactSha256',
    'channel',
    'controlPlaneOrigin',
    'immutability',
    'keyId',
    'objectCount',
    'objects',
    'prefix',
    'release',
    'schemaVersion',
    'totalByteSize',
  ])) fail();
  if (
    input.schemaVersion !== 1 ||
    !v.is(STRING_SCHEMA, input.artifactSha256) ||
    !SHA256_PATTERN.test(input.artifactSha256) ||
    !v.is(STRING_SCHEMA, input.channel) ||
    !CHANNEL_PATTERN.test(input.channel) ||
    parseControlPlaneOrigin(input.controlPlaneOrigin) !== input.controlPlaneOrigin ||
    MUTABLE_CHANNELS.has(input.channel) ||
    !v.is(STRING_SCHEMA, input.keyId) ||
    !KEY_ID_PATTERN.test(input.keyId) ||
    !v.is(STRING_SCHEMA, input.release) ||
    !RELEASE_PATTERN.test(input.release) ||
    !safeInteger(input.objectCount, MAX_OPERATOR_OBJECTS) ||
    input.objectCount < 2 ||
    !safeInteger(input.totalByteSize, MAX_OPERATOR_RELEASE_BYTES) ||
    !Array.isArray(input.objects) ||
    !exactKeys(input.immutability, ['externalAtomicCreateOnlyRequired', 'overwriteAllowed']) ||
    input.immutability.externalAtomicCreateOnlyRequired !== true ||
    input.immutability.overwriteAllowed !== false
  ) fail();
  const prefix = `${RELEASE_ROOT}/${input.channel}/${input.release}/`;
  if (input.prefix !== prefix) fail();
  const objects = input.objects.map(parseObjectEntry);
  if (objects.length !== input.objectCount) fail();
  let totalByteSize = 0;
  let envelopeCount = 0;
  const keys = new Set();
  const sources = new Set();
  for (let index = 0; index < objects.length; index += 1) {
    const object = objects[index];
    if (
      !object.key.startsWith(prefix) ||
      object.key === prefix ||
      object.sourcePath !== `objects/${object.key}` ||
      keys.has(object.key) ||
      sources.has(object.sourcePath) ||
      (index > 0 && lexicalCompare(objects[index - 1].key, object.key) >= 0)
    ) fail();
    if (object.key === `${prefix}${ENVELOPE_FILENAME}`) {
      envelopeCount += 1;
      if (object.contentType !== 'application/json; charset=utf-8') fail();
    }
    keys.add(object.key);
    sources.add(object.sourcePath);
    totalByteSize += object.byteSize;
    if (!safeInteger(totalByteSize, MAX_OPERATOR_RELEASE_BYTES)) fail();
  }
  if (totalByteSize !== input.totalByteSize || envelopeCount !== 1) fail();
  return Object.freeze({
    artifactSha256: input.artifactSha256,
    channel: input.channel,
    controlPlaneOrigin: input.controlPlaneOrigin,
    immutability: Object.freeze({
      externalAtomicCreateOnlyRequired: true,
      overwriteAllowed: false,
    }),
    keyId: input.keyId,
    objectCount: input.objectCount,
    objects: Object.freeze(objects),
    prefix,
    release: input.release,
    schemaVersion: 1,
    totalByteSize,
  });
}

async function readRegularFile(root, relativePath, maximumBytes) {
  if (!safePath(relativePath)) fail();
  const absolute = path.join(root, ...relativePath.split('/'));
  let handle;
  try {
    const before = await lstat(absolute);
    if (!before.isFile() || before.isSymbolicLink() || !safeInteger(before.size, maximumBytes)) fail();
    handle = await open(
      absolute,
      FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0),
    );
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size !== before.size || opened.dev !== before.dev || opened.ino !== before.ino) fail();
    const bytes = await handle.readFile();
    if (bytes.byteLength !== opened.size) fail();
    return bytes;
  } catch (error) {
    if (error instanceof R2PublicationWorkerGenerationError) throw error;
    fail();
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function walkExactTree(root) {
  const files = new Set();
  const directories = new Set(['.']);
  const visit = async (relativeDirectory) => {
    const absolute = relativeDirectory === '.'
      ? root
      : path.join(root, ...relativeDirectory.split('/'));
    let entries;
    try {
      entries = await readdir(absolute, { withFileTypes: true });
    } catch {
      fail();
    }
    for (const entry of entries) {
      if (!SAFE_SEGMENT.test(entry.name) || entry.name === '.' || entry.name === '..') fail();
      const relative = relativeDirectory === '.' ? entry.name : `${relativeDirectory}/${entry.name}`;
      const absoluteEntry = path.join(root, ...relative.split('/'));
      let metadata;
      try {
        metadata = await lstat(absoluteEntry);
      } catch {
        fail();
      }
      if (metadata.isSymbolicLink()) fail();
      if (metadata.isDirectory()) {
        directories.add(relative);
        await visit(relative);
      } else if (metadata.isFile()) {
        files.add(relative);
      } else {
        fail();
      }
    }
  };
  await visit('.');
  return Object.freeze({ files, directories });
}

function expectedDirectories(files) {
  const directories = new Set(['.']);
  for (const file of files) {
    let current = path.posix.dirname(file);
    while (current !== '.') {
      directories.add(current);
      current = path.posix.dirname(current);
    }
  }
  return directories;
}

function equalSets(left, right) {
  return left.size === right.size && [...left].every((entry) => right.has(entry));
}

export async function loadVerifiedR2PublicationDirectory(inputDirectory) {
  if (!v.is(STRING_SCHEMA, inputDirectory) || inputDirectory.length === 0 || inputDirectory.includes('\0')) fail();
  let root;
  try {
    root = await realpath(path.resolve(inputDirectory));
    const metadata = await lstat(root);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) fail();
  } catch (error) {
    if (error instanceof R2PublicationWorkerGenerationError) throw error;
    fail();
  }
  const planBytes = await readRegularFile(root, PLAN_FILENAME, MAX_PLAN_BYTES);
  let serialized;
  let parsed;
  try {
    serialized = new TextDecoder('utf-8', { fatal: true }).decode(planBytes);
    parsed = JSON.parse(serialized);
    if (canonicalJson(parsed) !== serialized) fail();
  } catch (error) {
    if (error instanceof R2PublicationWorkerGenerationError) throw error;
    fail();
  }
  const plan = parseObjectPlan(parsed);
  const canonicalPlan = canonicalJson(plan);
  if (canonicalPlan !== serialized) fail();
  const objectPlanSha256 = sha256Hex(planBytes);
  const expectedFiles = new Set([PLAN_FILENAME, ...plan.objects.map((object) => object.sourcePath)]);
  const tree = await walkExactTree(root);
  if (!equalSets(tree.files, expectedFiles) || !equalSets(tree.directories, expectedDirectories(expectedFiles))) fail();

  const objects = [];
  let totalByteSize = 0;
  for (const object of plan.objects) {
    const bytes = await readRegularFile(root, object.sourcePath, object.byteSize);
    if (bytes.byteLength !== object.byteSize || sha256Hex(bytes) !== object.sha256) fail();
    totalByteSize += bytes.byteLength;
    if (!safeInteger(totalByteSize, MAX_OPERATOR_RELEASE_BYTES)) fail();
    objects.push(Object.freeze({ ...object, bytes }));
  }
  if (totalByteSize !== plan.totalByteSize) fail();
  return Object.freeze({
    root,
    plan,
    canonicalPlan,
    objectPlanSha256,
    objects: Object.freeze(objects),
  });
}

function decodeCanonicalBase64Url(value, expectedBytes, pattern) {
  if (!v.is(STRING_SCHEMA, value) || !pattern.test(value)) fail();
  let bytes;
  try {
    bytes = Buffer.from(value, 'base64url');
  } catch {
    fail();
  }
  if (bytes.byteLength !== expectedBytes || bytes.toString('base64url') !== value) fail();
  return bytes;
}

function verifyEnvelopeSignature(verified, publicKey) {
  const envelope = verified.objects.find(
    (object) => object.key === `${verified.plan.prefix}${ENVELOPE_FILENAME}`,
  );
  if (!envelope) fail();
  let serialized;
  let parsed;
  try {
    serialized = new TextDecoder('utf-8', { fatal: true }).decode(envelope.bytes);
    parsed = JSON.parse(serialized);
    if (canonicalJson(parsed) !== serialized) fail();
  } catch (error) {
    if (error instanceof R2PublicationWorkerGenerationError) throw error;
    fail();
  }
  if (!exactKeys(parsed, [
    'channel', 'keyId', 'manifest', 'schemaVersion', 'signature', 'signatureContext',
  ])) fail();
  if (
    parsed.schemaVersion !== RELEASE_ENVELOPE_SCHEMA_VERSION ||
    parsed.channel !== verified.plan.channel ||
    parsed.keyId !== verified.plan.keyId ||
    !v.is(STRING_SCHEMA, parsed.manifest) ||
    !v.is(STRING_SCHEMA, parsed.signature) ||
    !SIGNATURE_PATTERN.test(parsed.signature) ||
    parsed.signatureContext !== RELEASE_SIGNATURE_CONTEXT
  ) fail();
  let manifest;
  try {
    manifest = JSON.parse(parsed.manifest);
    if (canonicalJson(manifest) !== parsed.manifest) fail();
  } catch (error) {
    if (error instanceof R2PublicationWorkerGenerationError) throw error;
    fail();
  }
  if (
    !isPlainRecord(manifest) ||
    manifest.release !== verified.plan.release ||
    manifest.controlPlaneOrigin !== verified.plan.controlPlaneOrigin ||
    !isPlainRecord(manifest.artifact) ||
    manifest.artifact.treeSha256 !== verified.plan.artifactSha256
  ) fail();

  const rawPublic = decodeCanonicalBase64Url(publicKey, 32, PUBLIC_KEY_PATTERN);
  const signature = decodeCanonicalBase64Url(parsed.signature, 64, SIGNATURE_PATTERN);
  const spki = Buffer.concat([SPKI_PUBLIC_PREFIX, rawPublic]);
  try {
    const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    if (!ed25519Verify(
      null,
      Buffer.from(releaseSignatureCanonicalJson(parsed.channel, parsed.keyId, parsed.manifest), 'utf8'),
      key,
      signature,
    )) fail();
  } catch (error) {
    if (error instanceof R2PublicationWorkerGenerationError) throw error;
    fail();
  } finally {
    rawPublic.fill(0);
    signature.fill(0);
    spki.fill(0);
  }
  return Object.freeze({
    publicKey,
    releaseEnvelopeSha256: envelope.sha256,
  });
}

function publicationIdentity(verified, accountId, bucketName, signatureIdentity) {
  return Object.freeze({
    accountId,
    artifactSha256: verified.plan.artifactSha256,
    bucketName,
    channel: verified.plan.channel,
    controlPlaneOrigin: verified.plan.controlPlaneOrigin,
    keyId: verified.plan.keyId,
    objectPlanSha256: verified.objectPlanSha256,
    prefix: verified.plan.prefix,
    publicKey: signatureIdentity.publicKey,
    release: verified.plan.release,
    releaseEnvelopeSha256: signatureIdentity.releaseEnvelopeSha256,
    schemaVersion: 1,
  });
}

function generatedDataModule(verified, identity) {
  const encoded = verified.objects.map((object) => Object.freeze({
    base64: object.bytes.toString('base64'),
    contentType: object.contentType,
    key: object.key,
  }));
  const source = `// Generated from one independently revalidated signed release. Do not edit.\n` +
    `export const OBJECT_PLAN_SHA256 = ${JSON.stringify(verified.objectPlanSha256)};\n` +
    `export const OBJECT_PLAN: unknown = ${verified.canonicalPlan};\n` +
    `export const PUBLICATION_IDENTITY = Object.freeze(${canonicalJson(identity)});\n` +
    `const ENCODED = ${JSON.stringify(encoded)} as const;\n` +
    `function decode(base64: string): Uint8Array<ArrayBuffer> {\n` +
    `  const raw = atob(base64);\n` +
    `  const bytes = new Uint8Array(raw.length);\n` +
    `  for (let index = 0; index < raw.length; index += 1) bytes[index] = raw.charCodeAt(index);\n` +
    `  return bytes;\n` +
    `}\n` +
    `export const RELEASE_BLOBS = Object.freeze(ENCODED.map((entry) => Object.freeze({\n` +
    `  key: entry.key,\n` +
    `  bytes: new Blob([decode(entry.base64)], { type: entry.contentType }),\n` +
    `})));\n`;
  if (Buffer.byteLength(source, 'utf8') > MAX_GENERATED_DATA_MODULE_BYTES) fail();
  return source;
}

function generatedIndexModule() {
  return `import { createR2PublicationOperator } from './r2-publication-operator';\n` +
    `import { publishCreateOnlyR2Release } from './r2-release-publisher';\n` +
    `import { OBJECT_PLAN, OBJECT_PLAN_SHA256, PUBLICATION_IDENTITY, RELEASE_BLOBS } from './release-data';\n\n` +
    `export default createR2PublicationOperator({\n` +
    `  blobs: RELEASE_BLOBS,\n` +
    `  objectPlan: OBJECT_PLAN,\n` +
    `  objectPlanSha256: OBJECT_PLAN_SHA256,\n` +
    `  publicationIdentity: PUBLICATION_IDENTITY,\n` +
    `  publish: publishCreateOnlyR2Release,\n` +
    `});\n`;
}

function tomlString(value) {
  return JSON.stringify(value);
}

function generatedWranglerConfig(accountId, bucketName, objectPlanSha256) {
  const name = `ankka-r2-publish-${objectPlanSha256.slice(0, 16)}`;
  return `name = ${tomlString(name)}\n` +
    `main = "src/index.ts"\n` +
    `account_id = ${tomlString(accountId)}\n` +
    `compatibility_date = "${COMPATIBILITY_DATE}"\n` +
    `workers_dev = false\n` +
    `preview_urls = false\n` +
    `send_metrics = false\n\n` +
    `[dev]\n` +
    `ip = "127.0.0.1"\n` +
    `port = ${OPERATOR_PORT}\n` +
    `local_protocol = "http"\n\n` +
    `[[r2_buckets]]\n` +
    `binding = "${OPERATOR_BINDING}"\n` +
    `bucket_name = ${tomlString(bucketName)}\n` +
    `remote = true\n\n` +
    `[observability.logs]\n` +
    `enabled = false\n` +
    `invocation_logs = false\n\n` +
    `[observability.traces]\n` +
    `enabled = false\n` +
    `head_sampling_rate = 0\n`;
}

async function writeExclusive(root, relativePath, contents) {
  const absolute = path.join(root, ...relativePath.split('/'));
  try {
    await mkdir(path.dirname(absolute), { recursive: true, mode: 0o700 });
    await writeFile(absolute, contents, { flag: 'wx', mode: 0o600 });
  } catch {
    fail();
  }
}

async function copyReviewedSources(outputRoot) {
  const sourceRoot = fileURLToPath(new URL('../src/', import.meta.url));
  for (const filename of GENERATED_SOURCE_FILES) {
    const source = await readRegularFile(sourceRoot, filename, MAX_OPERATOR_RELEASE_BYTES);
    await writeExclusive(outputRoot, `src/${filename}`, source);
  }
  const repositoryRoot = fileURLToPath(new URL('../../../', import.meta.url));
  for (const filename of GENERATED_DEPENDENCY_FILES) {
    const source = await readRegularFile(
      repositoryRoot,
      filename,
      MAX_OPERATOR_RELEASE_BYTES,
    );
    await writeExclusive(outputRoot, filename, source);
  }
}

async function reviewedWranglerExecutable() {
  // npm places the workspace's wrangler bin beside the workspace or hoisted at
  // the repository root depending on the dependency graph; both directories
  // are written only by the lockfile-driven install.
  const candidates = [
    '../node_modules/.bin/wrangler',
    '../../../node_modules/.bin/wrangler',
  ];
  for (const candidate of candidates) {
    try {
      const executable = await realpath(fileURLToPath(new URL(candidate, import.meta.url)));
      const metadata = await lstat(executable);
      if (metadata.isFile()) return executable;
    } catch {
      // Try the next lockfile-managed location.
    }
  }
  fail();
}

function shellQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

export async function generateR2PublicationWorker(input) {
  if (!exactKeys(input, ['accountId', 'bucketName', 'inputDirectory', 'outputDirectory', 'publicKey'])) fail();
  const { accountId, bucketName, inputDirectory, outputDirectory, publicKey } = input;
  if (!v.is(STRING_SCHEMA, accountId) || !ACCOUNT_ID_PATTERN.test(accountId)) fail();
  if (!v.is(STRING_SCHEMA, bucketName) || !BUCKET_PATTERN.test(bucketName)) fail();
  if (!v.is(STRING_SCHEMA, publicKey) || !PUBLIC_KEY_PATTERN.test(publicKey)) fail();
  if (!v.is(STRING_SCHEMA, outputDirectory) || outputDirectory.length === 0 || outputDirectory.includes('\0')) fail();
  const verified = await loadVerifiedR2PublicationDirectory(inputDirectory);
  const resolvedOutput = path.resolve(outputDirectory);
  if (resolvedOutput === verified.root || resolvedOutput.startsWith(`${verified.root}${path.sep}`)) fail();
  const basename = path.basename(resolvedOutput);
  if (!SAFE_SEGMENT.test(basename) || basename === '.' || basename === '..') fail();
  let parent;
  try {
    parent = await realpath(path.dirname(resolvedOutput));
  } catch {
    fail();
  }
  const outputRoot = path.join(parent, basename);
  try {
    await mkdir(outputRoot, { recursive: false, mode: 0o700 });
  } catch {
    fail();
  }

  const signatureIdentity = verifyEnvelopeSignature(verified, publicKey);
  const identity = publicationIdentity(verified, accountId, bucketName, signatureIdentity);
  const dataModule = generatedDataModule(verified, identity);
  const wranglerExecutable = await reviewedWranglerExecutable();
  await copyReviewedSources(outputRoot);
  await writeExclusive(outputRoot, 'src/release-data.ts', dataModule);
  await writeExclusive(outputRoot, 'src/index.ts', generatedIndexModule());
  await writeExclusive(
    outputRoot,
    'wrangler.toml',
    generatedWranglerConfig(accountId, bucketName, verified.objectPlanSha256),
  );
  await writeExclusive(
    outputRoot,
    'INVOCATION.txt',
    `Run only from this generated directory:\n` +
      `${shellQuote(wranglerExecutable)} dev --config wrangler.toml --ip 127.0.0.1 --port ${OPERATOR_PORT}\n` +
      `Then, once only and with no request body:\n` +
      `curl --fail-with-body -X POST http://127.0.0.1:${OPERATOR_PORT}/__ankka/publish/${verified.objectPlanSha256}\n` +
      `Stop Wrangler immediately after the response and remove this temporary directory.\n`,
  );
  return Object.freeze({
    schemaVersion: 1,
    outputDirectory: outputRoot,
    objectPlanSha256: verified.objectPlanSha256,
    publicationPath: `/__ankka/publish/${verified.objectPlanSha256}`,
    port: OPERATOR_PORT,
    bucketBinding: OPERATOR_BINDING,
    publicationIdentity: identity,
    wranglerExecutable,
  });
}

const HELP = `Usage: node scripts/generate-r2-publication-worker.mjs \\\n  --publish-dir <signed-publish-directory> \\\n  --account-id <32-lowerhex-cloudflare-account-id> \\\n  --bucket <exact-r2-bucket-name> \\\n  --public-key <raw-ed25519-base64url> \\\n  --out <new-temporary-directory>\n\n` +
  `This command performs no network call. It revalidates the exact signed object\n` +
  `plan and object tree, then writes a fresh release-specific local Worker whose\n` +
  `single R2 binding is explicitly remote. The output path must not exist.\n`;

function parseArguments(argv) {
  if (!Array.isArray(argv)) fail();
  if (argv.length === 1 && argv[0] === '--help') return { help: true };
  const flags = new Set(['--publish-dir', '--account-id', '--bucket', '--public-key', '--out']);
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (!flags.has(flag) || index + 1 >= argv.length || argv[index + 1].startsWith('--')) fail();
    if (Object.hasOwn(values, flag)) fail();
    values[flag] = argv[index + 1];
    index += 1;
  }
  if (Object.keys(values).length !== flags.size) fail();
  return {
    help: false,
    accountId: values['--account-id'],
    bucketName: values['--bucket'],
    inputDirectory: values['--publish-dir'],
    outputDirectory: values['--out'],
    publicKey: values['--public-key'],
  };
}

export async function runR2PublicationWorkerGeneratorCli({ argv, stdout, stderr }) {
  try {
    const options = parseArguments(argv);
    if (options.help) {
      stdout.write(HELP);
      return 0;
    }
    const generated = await generateR2PublicationWorker({
      accountId: options.accountId,
      bucketName: options.bucketName,
      inputDirectory: options.inputDirectory,
      outputDirectory: options.outputDirectory,
      publicKey: options.publicKey,
    });
    stdout.write(`Generated one release-specific local publisher with a remote R2 binding at ${generated.outputDirectory}\n`);
    stdout.write(`Object-plan SHA-256: ${generated.objectPlanSha256}\n`);
    return 0;
  } catch {
    stderr.write('R2 publication Worker generation failed. No live call was attempted.\n');
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = await runR2PublicationWorkerGeneratorCli({
    argv: process.argv.slice(2),
    stdout: process.stdout,
    stderr: process.stderr,
  });
}
