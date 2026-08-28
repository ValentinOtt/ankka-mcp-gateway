#!/usr/bin/env node

/** Read-only configuration and behavior proof for one non-live Access canary. */

import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

import {
  classifyAccessApplicationForHostname,
  createIsolatedPrivateAccessContract,
  isCloudflareAccessLoginUrl,
} from './access-contract.mjs';
import {
  parseIsolatedCanaryTarget,
  readIsolatedCanaryTargetFile,
} from '../isolated-canary-target.mjs';

const API = 'https://api.cloudflare.com/client/v4';
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{20,256}$/u;
const MAX_TOKEN_BYTES = 512;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_PAGES = 10;
const PAGE_SIZE = 100;
const TIMEOUT_MS = 10_000;
const RUNTIME_MODES = Object.freeze(['active', 'disabled']);

export class IsolatedAccessVerificationError extends Error {
  constructor(code = 'isolated_access_verification_failed') {
    super(code);
    this.name = 'IsolatedAccessVerificationError';
    this.code = code;
  }
}

function fail(code = 'isolated_access_verification_failed') {
  throw new IsolatedAccessVerificationError(code);
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, keys) {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length &&
    actual.every((key, index) => key === expected[index]);
}

async function boundedJson(response, errorCode = 'provider_response_invalid') {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && (declared < 0 || declared > MAX_RESPONSE_BYTES)) {
    fail(errorCode);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > MAX_RESPONSE_BYTES) {
    bytes.fill(0);
    fail(errorCode);
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    fail(errorCode);
  } finally {
    bytes.fill(0);
  }
}

async function fetchWithTimeout(fetchImpl, url, init) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    try {
      return await fetchImpl(url, { ...init, signal: controller.signal });
    } catch {
      fail('endpoint_unavailable');
    }
  } finally {
    clearTimeout(timeout);
  }
}

async function providerGet(fetchImpl, token, pathname) {
  const response = await fetchWithTimeout(fetchImpl, `${API}${pathname}`, {
    method: 'GET',
    redirect: 'error',
    headers: { accept: 'application/json', authorization: `Bearer ${token}` },
  });
  if (!(response instanceof Response) || response.status !== 200) {
    fail('provider_request_failed');
  }
  const body = await boundedJson(response);
  if (!isRecord(body) || body.success !== true || !Object.hasOwn(body, 'result')) {
    fail('provider_response_invalid');
  }
  return body;
}

async function readAllApplications(fetchImpl, token, accountId) {
  const applications = [];
  const ids = new Set();
  let totalPages = null;
  for (let page = 1; page <= (totalPages ?? 1); page += 1) {
    const body = await providerGet(
      fetchImpl,
      token,
      `/accounts/${encodeURIComponent(accountId)}/access/apps?per_page=${PAGE_SIZE}&page=${page}`,
    );
    if (!Array.isArray(body.result) || !isRecord(body.result_info)) fail('provider_response_invalid');
    const completeEmptyInventory = body.result_info.page === 1 &&
      body.result_info.total_pages === 0 && body.result.length === 0 &&
      body.result_info.count === 0 && body.result_info.total_count === 0;
    if (
      body.result_info.page !== page ||
      !Number.isSafeInteger(body.result_info.total_pages) ||
      body.result_info.total_pages < 0 ||
      body.result_info.total_pages > MAX_PAGES ||
      (body.result_info.total_pages === 0 && !completeEmptyInventory) ||
      (totalPages !== null && body.result_info.total_pages !== totalPages)
    ) fail('provider_response_invalid');
    totalPages = body.result_info.total_pages;
    for (const application of body.result) {
      if (
        !isRecord(application) ||
        typeof application.id !== 'string' || application.id.length < 1 || application.id.length > 256 ||
        ids.has(application.id)
      ) fail('provider_response_invalid');
      ids.add(application.id);
      applications.push(application);
    }
  }
  return applications;
}

function verifyConfiguration(applications, contract) {
  const specifications = [
    contract.privateInstallerApplication,
    ...contract.bypassApplications,
  ];
  const exactDomains = new Set(specifications.map((entry) => entry.domain));
  for (const application of applications) {
    const classification = classifyAccessApplicationForHostname(application, contract.accessHost);
    if (classification === 'unverifiable') fail('access_inventory_unverifiable');
    if (classification === 'covering' && !exactDomains.has(application.domain)) {
      fail('access_selector_conflict');
    }
  }
  for (const specification of contract.bypassApplications) {
    const matches = applications.filter((application) => application.domain === specification.domain);
    if (matches.length !== 1 || !contract.assessBypassApplication(matches[0], specification).ok) {
      fail('access_application_invalid');
    }
  }
  const installers = applications.filter(
    (application) => application.domain === contract.privateInstallerApplication.domain,
  );
  if (installers.length !== 1 || !contract.assessInstallerApplication(installers[0]).ok) {
    fail('access_application_invalid');
  }
  return Object.freeze({
    applicationCount: 4,
    identityProviderCount: contract.assessInstallerApplication(installers[0]).identityProviderCount,
    operatorIdentityCount: contract.assessInstallerApplication(installers[0]).operatorIdentityCount,
  });
}

function isAccessRedirect(response) {
  const location = response.headers.get('location') ?? '';
  return response.status >= 300 && response.status < 400 &&
    isCloudflareAccessLoginUrl(location);
}

function requireApplicationJson(response) {
  const contentType = response.headers.get('content-type') ?? '';
  if (!/^application\/json(?:\s*;|$)/iu.test(contentType)) fail('behavior_invalid');
}

function exactErrorBody(value, code) {
  return exactKeys(value, ['code']) && value.code === code;
}

function applicationReleaseDescriptor(value, channel) {
  return exactKeys(value, [
    'channel',
    'classification',
    'notes',
    'release',
    'schemaVersion',
    'verification',
  ]) &&
    value.schemaVersion === 1 && value.channel === channel &&
    exactKeys(value.release, ['artifactSha256', 'id', 'sourceCommit']) &&
    isRecord(value.classification) && Array.isArray(value.notes) &&
    isRecord(value.verification);
}

async function anonymousProbe(fetchImpl, hostname, pathname, method = 'GET') {
  const response = await fetchWithTimeout(fetchImpl, `https://${hostname}${pathname}`, {
    method,
    redirect: 'manual',
    credentials: 'omit',
    headers: {
      accept: pathname.startsWith('/api/') || pathname === '/oauth/callback'
        ? 'application/json'
        : 'text/html',
    },
  });
  if (!(response instanceof Response)) fail('behavior_invalid');
  return response;
}

async function verifyBehavior(fetchImpl, contract, runtimeMode) {
  const [root, session, callback, ...releases] = await Promise.all([
    anonymousProbe(fetchImpl, contract.accessHost, '/'),
    anonymousProbe(fetchImpl, contract.accessHost, '/api/session', 'HEAD'),
    anonymousProbe(fetchImpl, contract.accessHost, '/oauth/callback'),
    ...contract.bypassApplications.slice(1).map((specification) => {
      const pathname = specification.domain.slice(contract.accessHost.length);
      return anonymousProbe(fetchImpl, contract.accessHost, pathname);
    }),
  ]);
  if (!isAccessRedirect(root) || !isAccessRedirect(session)) fail('operator_gate_not_enforced');
  if (isAccessRedirect(callback) || releases.some(isAccessRedirect)) fail('required_bypass_not_enforced');
  for (const response of [callback, ...releases]) requireApplicationJson(response);
  const callbackBody = await boundedJson(callback, 'behavior_invalid');
  const releaseBodies = await Promise.all(
    releases.map((response) => boundedJson(response, 'behavior_invalid')),
  );
  if (runtimeMode === 'disabled') {
    if (
      callback.status !== 503 || !exactErrorBody(callbackBody, 'release_unavailable') ||
      releases.some((response) => response.status !== 503) ||
      releaseBodies.some((body) => !exactErrorBody(body, 'release_unavailable'))
    ) fail('disabled_shell_not_verified');
    return 5;
  }
  if (callback.status !== 400 || !exactErrorBody(callbackBody, 'session_invalid')) {
    fail('callback_boundary_not_verified');
  }
  let availableReleaseCount = 0;
  for (let index = 0; index < releases.length; index += 1) {
    const response = releases[index];
    const body = releaseBodies[index];
    const channel = contract.bypassApplications[index + 1].domain.slice(
      `${contract.accessHost}/api/releases/`.length,
    );
    if (response.status === 200 && applicationReleaseDescriptor(body, channel)) {
      availableReleaseCount += 1;
      continue;
    }
    if (response.status === 404 && exactErrorBody(body, 'release_unavailable')) continue;
    fail('release_bypass_not_verified');
  }
  if (availableReleaseCount === 0) fail('release_bypass_not_verified');
  return 5;
}

export async function verifyIsolatedAccess(input) {
  if (!exactKeys(input, ['fetchImpl', 'readToken', 'runtimeMode', 'target'])) fail('input_invalid');
  let target;
  try {
    target = parseIsolatedCanaryTarget(input.target);
  } catch {
    fail('target_invalid');
  }
  if (
    typeof input.fetchImpl !== 'function' || typeof input.readToken !== 'function' ||
    !RUNTIME_MODES.includes(input.runtimeMode)
  ) {
    fail('input_invalid');
  }
  const contract = createIsolatedPrivateAccessContract(target.hostname);
  let token;
  try {
    token = await input.readToken();
    if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) fail('token_invalid');
    const applications = await readAllApplications(input.fetchImpl, token, target.accountId);
    const configuration = verifyConfiguration(applications, contract);
    const behaviorChecks = await verifyBehavior(input.fetchImpl, contract, input.runtimeMode);
    return Object.freeze({
      ...configuration,
      anonymousBehaviorChecks: behaviorChecks,
      runtimeMode: input.runtimeMode,
      schemaVersion: 1,
      status: 'verified',
    });
  } finally {
    token = undefined;
  }
}

async function readTokenFromStdin(stream) {
  const chunks = [];
  let total = 0;
  try {
    for await (const chunk of stream) {
      const bytes = Buffer.from(chunk);
      total += bytes.byteLength;
      if (total > MAX_TOKEN_BYTES) {
        bytes.fill(0);
        fail('token_invalid');
      }
      chunks.push(bytes);
    }
    const joined = Buffer.concat(chunks, total);
    try {
      return joined.toString('utf8').trim();
    } finally {
      joined.fill(0);
    }
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

const HELP = `Usage: <read-token-source> | node scripts/edge-gate/verify-isolated-access.mjs \\\n` +
  `  --target <exact-outside-repository-target.json> --runtime <disabled|active> \\\n` +
  `  --api-token-stdin\n`;

function parseArguments(argv) {
  if (argv.length === 1 && argv[0] === '--help') return Object.freeze({ help: true });
  const values = new Map();
  let stdinToken = false;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === '--api-token-stdin') {
      if (stdinToken) fail('input_invalid');
      stdinToken = true;
      continue;
    }
    if (
      !['--runtime', '--target'].includes(flag) || values.has(flag) ||
      index + 1 >= argv.length || argv[index + 1].startsWith('--')
    ) fail('input_invalid');
    values.set(flag, argv[index + 1]);
    index += 1;
  }
  const runtimeMode = values.get('--runtime');
  const targetFilename = values.get('--target');
  if (!stdinToken || !RUNTIME_MODES.includes(runtimeMode) || !targetFilename) fail('input_invalid');
  return Object.freeze({ help: false, runtimeMode, targetFilename });
}

export async function runIsolatedAccessVerifyCli({ argv, fetchImpl = fetch, stdin, stderr, stdout }) {
  try {
    const options = parseArguments(argv);
    if (options.help) {
      stdout.write(HELP);
      return 0;
    }
    const target = await readIsolatedCanaryTargetFile(options.targetFilename);
    const result = await verifyIsolatedAccess({
      fetchImpl,
      readToken: () => readTokenFromStdin(stdin),
      runtimeMode: options.runtimeMode,
      target,
    });
    stdout.write(`${JSON.stringify(result)}\n`);
    return 0;
  } catch (error) {
    const code = error instanceof IsolatedAccessVerificationError ? error.code : 'internal_error';
    stderr.write(`Isolated Access verification failed: ${code}.\n`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = await runIsolatedAccessVerifyCli({
    argv: process.argv.slice(2),
    stdin: process.stdin,
    stderr: process.stderr,
    stdout: process.stdout,
  });
}
