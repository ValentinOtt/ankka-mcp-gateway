#!/usr/bin/env node

/**
 * Read-only public-self-service gate for deploy.ankka.ai.
 *
 * This verifier deliberately does not create a session or mutate Cloudflare.
 * It proves that the complete account Access-app listing contains no app that
 * could cover the installer host, then makes cookie-free, manual-redirect
 * observations of the active reviewed runtime. The active signed release is
 * bound to the operator-reviewed channel, release, source commit, artifact
 * digest, key ID, and raw Ed25519 public key.
 *
 * The Cloudflare read token is accepted only through bounded stdin. Provider
 * response bodies, account IDs, application IDs, and identities are never
 * printed.
 */
import {
  createHash,
  createPublicKey,
  verify as verifyEd25519,
} from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import * as v from 'valibot';

import {
  ACCESS_HOST,
  OAUTH_CALLBACK_PATH,
  RELEASE_CHANNEL_PATHS,
  classifyAccessApplicationForInstaller,
  isCloudflareAccessLoginUrl,
} from './access-contract.mjs';
import {
  RELEASE_ENVELOPE_SCHEMA_VERSION,
  RELEASE_SIGNATURE_CONTEXT,
  canonicalJson,
  releaseSignatureCanonicalJson,
} from '../sign-gateway-release.mjs';

const API = 'https://api.cloudflare.com/client/v4';
const ZONE = 'ankka.ai';
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{20,256}$/u;
const CHANNEL_PATTERN = /^(?:canary|stable)$/u;
const RELEASE_PATTERN = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const PUBLIC_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const COMMIT_PATTERN = /^[a-f0-9]{40}$/u;
const MAX_TOKEN_BYTES = 512;
const MAX_API_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_PUBLIC_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_ACCESS_PAGES = 10;
const ACCESS_PAGE_SIZE = 100;
const TIMEOUT_MS = 10_000;
const SPKI_PUBLIC_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const FUNCTION_SCHEMA = v.function();
const OBJECT_SCHEMA = v.object({});
const STRING_SCHEMA = v.string();

const NORMAL_UPDATE_CHANGES = Object.freeze([
  'customer_worker_code',
  'management_assets',
]);
const NORMAL_UPDATE_EXCLUSIONS = Object.freeze([
  'access_policies',
  'credentials',
  'dns',
  'durable_object_migrations',
  'mcp_portal_configuration',
  'sources',
  'tool_allowlists',
]);

export class PublicAccessVerificationError extends Error {
  constructor(code) {
    super(code);
    this.name = 'PublicAccessVerificationError';
    this.code = code;
  }
}

function fail(code = 'public_access_verification_failed') {
  throw new PublicAccessVerificationError(code);
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

function exactStrings(value, expected) {
  return Array.isArray(value) && value.length === expected.length &&
    value.every((entry, index) => entry === expected[index]);
}

function validExpectedRelease(expected) {
  return isRecord(expected) && CHANNEL_PATTERN.test(expected.channel) &&
    RELEASE_PATTERN.test(expected.release) && KEY_ID_PATTERN.test(expected.keyId) &&
    PUBLIC_KEY_PATTERN.test(expected.publicKey) && SHA256_PATTERN.test(expected.artifactSha256) &&
    COMMIT_PATTERN.test(expected.sourceCommit);
}

async function boundedBytes(response, maximumBytes) {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && (declared < 0 || declared > maximumBytes)) {
    fail('response_invalid');
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > maximumBytes) {
    bytes.fill(0);
    fail('response_invalid');
  }
  return bytes;
}

async function boundedJson(response, maximumBytes) {
  const bytes = await boundedBytes(response, maximumBytes);
  try {
    const serialized = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return JSON.parse(serialized);
  } catch {
    fail('response_invalid');
  } finally {
    bytes.fill(0);
  }
}

async function fetchWithTimeout(fetchImpl, url, init) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    return await fetchImpl(url, { ...init, signal: controller.signal });
  } catch {
    fail('endpoint_unavailable');
  } finally {
    clearTimeout(timeout);
  }
}

async function cloudflareGet(fetchImpl, pathname, token) {
  const response = await fetchWithTimeout(fetchImpl, `${API}${pathname}`, {
    method: 'GET',
    redirect: 'error',
    headers: {
      accept: 'application/json',
      authorization: `Bearer ${token}`,
    },
  });
  if (!(response instanceof Response) || response.status !== 200) {
    fail('access_configuration_unavailable');
  }
  const body = await boundedJson(response, MAX_API_RESPONSE_BYTES);
  if (!isRecord(body) || body.success !== true || !Object.hasOwn(body, 'result')) {
    fail('access_configuration_unavailable');
  }
  return body;
}

async function readAllAccessApplications(fetchImpl, token) {
  const zones = await cloudflareGet(fetchImpl, `/zones?name=${encodeURIComponent(ZONE)}`, token);
  if (!Array.isArray(zones.result)) fail('access_configuration_unavailable');
  const matchingZones = zones.result.filter((zone) => (
    isRecord(zone) && zone.name === ZONE &&
    v.is(STRING_SCHEMA, zone.id) && /^[A-Za-z0-9_-]{1,128}$/u.test(zone.id) &&
    isRecord(zone.account) &&
    v.is(STRING_SCHEMA, zone.account.id) && /^[A-Za-z0-9_-]{1,128}$/u.test(zone.account.id)
  ));
  if (matchingZones.length !== 1) fail('access_configuration_unavailable');
  const zoneId = matchingZones[0].id;

  const applications = [];
  const seenIds = new Set();
  let totalPages = null;
  for (let page = 1; page <= (totalPages ?? 1); page += 1) {
    const body = await cloudflareGet(
      fetchImpl,
      `/zones/${encodeURIComponent(zoneId)}/access/apps?per_page=${ACCESS_PAGE_SIZE}&page=${page}`,
      token,
    );
    if (!Array.isArray(body.result) || !isRecord(body.result_info)) {
      fail('access_configuration_unavailable');
    }
    const reportedPage = body.result_info.page;
    const reportedTotalPages = body.result_info.total_pages;
    // Cloudflare's live empty-list envelope reports page 1 with zero total
    // pages. Accept only that exact complete-empty shape; a non-empty zero-page
    // response remains unverifiable and fails closed.
    const completeEmptyInventory = reportedPage === 1 && reportedTotalPages === 0 &&
      body.result.length === 0 && body.result_info.count === 0 &&
      body.result_info.total_count === 0;
    if (
      reportedPage !== page || !Number.isSafeInteger(reportedTotalPages) ||
      reportedTotalPages < 0 || reportedTotalPages > MAX_ACCESS_PAGES ||
      (reportedTotalPages === 0 && !completeEmptyInventory) ||
      (totalPages !== null && reportedTotalPages !== totalPages)
    ) fail('access_configuration_unavailable');
    totalPages = reportedTotalPages;
    for (const application of body.result) {
      if (!isRecord(application) || !v.is(STRING_SCHEMA, application.id) ||
          application.id.length === 0 || application.id.length > 256 || seenIds.has(application.id)) {
        fail('access_configuration_unavailable');
      }
      seenIds.add(application.id);
      applications.push(application);
    }
  }
  return applications;
}

function exactPublicReleaseManifest(serialized, expected) {
  if (!v.is(STRING_SCHEMA, serialized) || serialized.length === 0 ||
      Buffer.byteLength(serialized, 'utf8') > MAX_PUBLIC_RESPONSE_BYTES) fail('public_release_invalid');
  let manifest;
  try {
    manifest = JSON.parse(serialized);
    if (canonicalJson(manifest) !== serialized) fail('public_release_invalid');
  } catch (error) {
    if (error instanceof PublicAccessVerificationError) throw error;
    fail('public_release_invalid');
  }
  if (
    !exactKeys(manifest, [
      'artifact', 'cloudflare', 'components', 'oauthScopeIds', 'release', 'schemaVersion', 'sourceCommit',
    ]) ||
    manifest.schemaVersion !== 1 || manifest.release !== expected.release ||
    manifest.sourceCommit !== expected.sourceCommit ||
    !exactKeys(manifest.artifact, ['byteSize', 'fileCount', 'treeSha256']) ||
    manifest.artifact.treeSha256 !== expected.artifactSha256 ||
    !Number.isSafeInteger(manifest.artifact.byteSize) || manifest.artifact.byteSize < 1 ||
    !Number.isSafeInteger(manifest.artifact.fileCount) || manifest.artifact.fileCount < 1 ||
    !isRecord(manifest.cloudflare) ||
    !exactKeys(manifest.components, [
      'admin', 'installer', 'worker', 'workerBootstrap', 'workerCleanup', 'workerRetirement',
    ]) ||
    !Array.isArray(manifest.oauthScopeIds)
  ) fail('public_release_invalid');
  const installer = manifest.components.installer;
  if (!exactKeys(installer, ['byteSize', 'fileCount', 'files', 'treeSha256']) ||
      !Array.isArray(installer.files)) fail('public_release_invalid');
  const rootFiles = installer.files.filter((file) => (
    exactKeys(file, ['byteSize', 'contentType', 'path', 'sha256']) &&
    file.path === 'payload/installer/index.html' &&
    file.contentType === 'text/html; charset=utf-8' &&
    Number.isSafeInteger(file.byteSize) && file.byteSize > 0 &&
    v.is(STRING_SCHEMA, file.sha256) && SHA256_PATTERN.test(file.sha256)
  ));
  if (rootFiles.length !== 1) fail('public_release_invalid');
  return Object.freeze({
    byteSize: rootFiles[0].byteSize,
    sha256: rootFiles[0].sha256,
  });
}

/** Verify the exact signed descriptor served to customer-owned gateway updaters. */
export function verifyPublicReleaseDescriptor(input, expected) {
  if (!validExpectedRelease(expected)) fail('input_invalid');
  if (
    !exactKeys(input, ['channel', 'classification', 'notes', 'release', 'schemaVersion', 'verification']) ||
    input.schemaVersion !== 1 || input.channel !== expected.channel ||
    !exactKeys(input.release, ['artifactSha256', 'id', 'sourceCommit']) ||
    input.release.id !== expected.release ||
    input.release.artifactSha256 !== `sha256:${expected.artifactSha256}` ||
    input.release.sourceCommit !== expected.sourceCommit ||
    !exactKeys(input.classification, ['changes', 'excludes', 'kind', 'updaterProtocol']) ||
    input.classification.kind !== 'normal' || input.classification.updaterProtocol !== 2 ||
    !exactStrings(input.classification.changes, NORMAL_UPDATE_CHANGES) ||
    !exactStrings(input.classification.excludes, NORMAL_UPDATE_EXCLUSIONS) ||
    !Array.isArray(input.notes) || input.notes.length < 1 || input.notes.length > 8 ||
    input.notes.some((note) => !v.is(STRING_SCHEMA, note) || note.length < 1 || note.length > 512) ||
    !exactKeys(input.verification, [
      'algorithm', 'channel', 'keyId', 'manifest', 'schemaVersion', 'signature', 'signatureContext',
    ]) ||
    input.verification.algorithm !== 'ed25519' || input.verification.channel !== expected.channel ||
    input.verification.keyId !== expected.keyId ||
    input.verification.schemaVersion !== RELEASE_ENVELOPE_SCHEMA_VERSION ||
    input.verification.signatureContext !== RELEASE_SIGNATURE_CONTEXT ||
    !v.is(STRING_SCHEMA, input.verification.signature) ||
    !SIGNATURE_PATTERN.test(input.verification.signature)
  ) fail('public_release_invalid');

  const installerIndex = exactPublicReleaseManifest(input.verification.manifest, expected);
  let rawPublic;
  let signature;
  let publicKey;
  try {
    rawPublic = Buffer.from(expected.publicKey, 'base64url');
    signature = Buffer.from(input.verification.signature, 'base64url');
    if (
      rawPublic.byteLength !== 32 || rawPublic.toString('base64url') !== expected.publicKey ||
      signature.byteLength !== 64 || signature.toString('base64url') !== input.verification.signature
    ) fail('public_release_invalid');
    publicKey = createPublicKey({
      key: Buffer.concat([SPKI_PUBLIC_PREFIX, rawPublic]),
      format: 'der',
      type: 'spki',
    });
    const statement = Buffer.from(releaseSignatureCanonicalJson(
      expected.channel,
      expected.keyId,
      input.verification.manifest,
    ), 'utf8');
    try {
      if (!verifyEd25519(null, statement, publicKey, signature)) fail('public_release_invalid');
    } finally {
      statement.fill(0);
    }
  } catch (error) {
    if (error instanceof PublicAccessVerificationError) throw error;
    fail('public_release_invalid');
  } finally {
    rawPublic?.fill(0);
    signature?.fill(0);
  }
  return Object.freeze({
    channel: expected.channel,
    installerIndex,
    release: expected.release,
    schemaVersion: 1,
    status: 'verified',
  });
}

function isAccessRedirect(response) {
  const location = response.headers.get('location') ?? '';
  return response.status >= 300 && response.status < 400 &&
    isCloudflareAccessLoginUrl(location);
}

async function anonymousProbe(fetchImpl, pathname, { accept, method = 'GET' }) {
  const response = await fetchWithTimeout(fetchImpl, `https://${ACCESS_HOST}${pathname}`, {
    method,
    redirect: 'manual',
    credentials: 'omit',
    headers: {
      accept,
      'cache-control': 'no-store',
    },
  });
  if (!(response instanceof Response)) fail('public_behavior_invalid');
  if (isAccessRedirect(response)) fail('access_redirect_present');
  // Cloudflare may inject NEL/Report-To for the Ankka-owned hosted zone. That
  // platform metadata is an explicit hosted-service policy, not an Access
  // redirect or customer-gateway telemetry, so it is not a readiness failure.
  return response;
}

function requireContentType(response, mediaType) {
  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.toLowerCase().startsWith(mediaType)) fail('public_behavior_invalid');
}

/**
 * Verify public configuration and anonymous behavior. No request below uses a
 * cookie, follows a redirect, or sends a state-minting GET to /api/session.
 */
export async function verifyPublicSelfService({ fetchImpl = fetch, readToken, expected }) {
  if (!v.is(FUNCTION_SCHEMA, fetchImpl) || !v.is(FUNCTION_SCHEMA, readToken) ||
      !validExpectedRelease(expected)) fail('input_invalid');
  let token;
  try {
    token = await readToken();
    if (!v.is(STRING_SCHEMA, token) || !TOKEN_PATTERN.test(token)) fail('input_invalid');
    const applications = await readAllAccessApplications(fetchImpl, token);
    for (const application of applications) {
      const classification = classifyAccessApplicationForInstaller(application);
      if (classification === 'unverifiable') fail('access_configuration_unverifiable');
      if (classification === 'covering') fail('access_application_present');
    }
  } finally {
    token = undefined;
  }

  const health = await anonymousProbe(fetchImpl, '/health', { accept: 'application/json' });
  if (health.status !== 200) fail('active_installer_not_verified');
  requireContentType(health, 'application/json');
  const healthBody = await boundedJson(health, MAX_PUBLIC_RESPONSE_BYTES);
  if (!exactKeys(healthBody, ['mutationsEnabled', 'ok']) ||
      healthBody.ok !== true || healthBody.mutationsEnabled !== true) {
    fail('active_installer_not_verified');
  }

  const root = await anonymousProbe(fetchImpl, '/', { accept: 'text/html' });
  if (root.status !== 200) fail('active_installer_not_verified');
  requireContentType(root, 'text/html');
  const rootBytes = await boundedBytes(root, MAX_PUBLIC_RESPONSE_BYTES);
  let rootBody;
  try {
    rootBody = new TextDecoder('utf-8', { fatal: true }).decode(rootBytes);
  } catch {
    rootBytes.fill(0);
    fail('active_installer_not_verified');
  }
  if (!/<(?:!doctype\s+html|html)\b/iu.test(rootBody)) {
    rootBytes.fill(0);
    fail('active_installer_not_verified');
  }

  const sessionHead = await anonymousProbe(fetchImpl, '/api/session', {
    accept: 'application/json',
    method: 'HEAD',
  });
  if (sessionHead.status !== 404) fail('public_behavior_invalid');
  requireContentType(sessionHead, 'application/json');

  const callback = await anonymousProbe(fetchImpl, OAUTH_CALLBACK_PATH, { accept: 'application/json' });
  if (callback.status !== 400) fail('public_behavior_invalid');
  requireContentType(callback, 'application/json');
  const callbackBody = await boundedJson(callback, MAX_PUBLIC_RESPONSE_BYTES);
  if (!exactKeys(callbackBody, ['code']) || callbackBody.code !== 'session_invalid') {
    fail('public_behavior_invalid');
  }

  let activeRelease = null;
  for (const pathname of RELEASE_CHANNEL_PATHS) {
    const channel = pathname.slice('/api/releases/'.length);
    const release = await anonymousProbe(fetchImpl, pathname, { accept: 'application/json' });
    requireContentType(release, 'application/json');
    const body = await boundedJson(release, MAX_PUBLIC_RESPONSE_BYTES);
    if (channel === expected.channel) {
      if (release.status !== 200) fail('public_release_invalid');
      activeRelease = verifyPublicReleaseDescriptor(body, expected);
    } else if (
      release.status !== 404 || !exactKeys(body, ['code']) || body.code !== 'release_unavailable'
    ) {
      fail('public_release_invalid');
    }
  }
  if (!activeRelease) {
    rootBytes.fill(0);
    fail('public_release_invalid');
  }
  try {
    const digest = createHash('sha256').update(rootBytes).digest('hex');
    if (rootBytes.byteLength !== activeRelease.installerIndex.byteSize ||
        digest !== activeRelease.installerIndex.sha256) fail('active_installer_not_verified');
  } finally {
    rootBytes.fill(0);
  }

  return Object.freeze({
    accessApplicationsCoveringInstaller: 0,
    activeChannel: expected.channel,
    anonymousBehaviorChecks: 6,
    schemaVersion: 1,
    status: 'verified',
  });
}

async function readTokenFromStdin(readable) {
  const chunks = [];
  let total = 0;
  try {
    for await (const chunk of readable) {
      const owned = Buffer.from(chunk);
      total += owned.byteLength;
      if (total > MAX_TOKEN_BYTES) {
        owned.fill(0);
        fail('input_invalid');
      }
      chunks.push(owned);
    }
    const bytes = Buffer.concat(chunks, total);
    try {
      return bytes.toString('utf8').trim();
    } finally {
      bytes.fill(0);
    }
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

const HELP = `Usage: <read-token-source> | node scripts/edge-gate/verify-public.mjs \\
  --api-token-stdin --channel <canary|stable> --release <gateway-vX.Y.Z> \\
  --source-commit <40-lowerhex> --artifact-sha256 <64-lowerhex> \\
  --key-id <id> --public-key <raw-ed25519-base64url>\n`;

function parseArguments(argv) {
  if (argv.length === 1 && argv[0] === '--help') return { help: true };
  const values = {};
  let stdinToken = false;
  const valueFlags = new Set([
    '--artifact-sha256', '--channel', '--key-id', '--public-key', '--release', '--source-commit',
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === '--api-token-stdin') {
      if (stdinToken) fail('input_invalid');
      stdinToken = true;
      continue;
    }
    if (!valueFlags.has(flag) || index + 1 >= argv.length || argv[index + 1].startsWith('--') ||
        Object.hasOwn(values, flag)) fail('input_invalid');
    values[flag] = argv[index + 1];
    index += 1;
  }
  if (!stdinToken || Object.keys(values).length !== valueFlags.size) fail('input_invalid');
  const expected = Object.freeze({
    artifactSha256: values['--artifact-sha256'],
    channel: values['--channel'],
    keyId: values['--key-id'],
    publicKey: values['--public-key'],
    release: values['--release'],
    sourceCommit: values['--source-commit'],
  });
  if (!validExpectedRelease(expected)) fail('input_invalid');
  return { help: false, expected };
}

export async function runPublicAccessVerifierCli({
  argv,
  stdin,
  stdout,
  stderr,
  fetchImpl = fetch,
}) {
  try {
    const options = parseArguments(argv);
    if (options.help) {
      stdout.write(HELP);
      return 0;
    }
    const result = await verifyPublicSelfService({
      expected: options.expected,
      fetchImpl,
      readToken: () => readTokenFromStdin(stdin),
    });
    stdout.write(`${JSON.stringify(result)}\n`);
    return 0;
  } catch (error) {
    const code = error instanceof PublicAccessVerificationError ? error.code : 'internal_error';
    stderr.write(`Public self-service verification failed: ${code}.\n`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = await runPublicAccessVerifierCli({
    argv: process.argv.slice(2),
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
  });
}
