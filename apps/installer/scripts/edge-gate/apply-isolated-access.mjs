#!/usr/bin/env node

/** Create or resume the exact four-app Access contract for one non-live canary. */

import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

import {
  classifyAccessApplicationForHostname,
  createIsolatedPrivateAccessContract,
} from './access-contract.mjs';
import {
  parseIsolatedCanaryTarget,
  readIsolatedCanaryTargetFile,
} from '../isolated-canary-target.mjs';

const API = 'https://api.cloudflare.com/client/v4';
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{20,256}$/u;
const EMAIL_PATTERN = /^[^\s@]{1,64}@[^\s@]{1,189}$/u;
const MAX_TOKEN_BYTES = 512;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_PAGES = 10;
const PAGE_SIZE = 100;
const TIMEOUT_MS = 10_000;

export class IsolatedAccessApplyError extends Error {
  constructor(code = 'isolated_access_apply_failed') {
    super(code);
    this.name = 'IsolatedAccessApplyError';
    this.code = code;
  }
}

function fail(code = 'isolated_access_apply_failed') {
  throw new IsolatedAccessApplyError(code);
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

async function boundedJson(response) {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && (declared < 0 || declared > MAX_RESPONSE_BYTES)) {
    fail('provider_response_invalid');
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > MAX_RESPONSE_BYTES) {
    bytes.fill(0);
    fail('provider_response_invalid');
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    fail('provider_response_invalid');
  } finally {
    bytes.fill(0);
  }
}

async function providerCall(fetchImpl, token, pathname, init = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    let response;
    try {
      response = await fetchImpl(`${API}${pathname}`, {
        ...init,
        redirect: 'error',
        signal: controller.signal,
        headers: {
          accept: 'application/json',
          authorization: `Bearer ${token}`,
          ...(init.body === undefined ? {} : { 'content-type': 'application/json' }),
        },
      });
    } catch {
      fail('provider_unavailable');
    }
    if (!(response instanceof Response) || response.status < 200 || response.status >= 300) {
      fail('provider_request_failed');
    }
    const body = await boundedJson(response);
    if (!isRecord(body) || body.success !== true || !Object.hasOwn(body, 'result')) {
      fail('provider_response_invalid');
    }
    return body;
  } finally {
    clearTimeout(timeout);
  }
}

async function readAllApplications(fetchImpl, token, accountId) {
  const applications = [];
  const ids = new Set();
  let totalPages = null;
  for (let page = 1; page <= (totalPages ?? 1); page += 1) {
    const body = await providerCall(
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
        typeof application.id !== 'string' ||
        application.id.length < 1 ||
        application.id.length > 256 ||
        ids.has(application.id)
      ) fail('provider_response_invalid');
      ids.add(application.id);
      applications.push(application);
    }
  }
  return applications;
}

async function accountMemberIdentityProvider(fetchImpl, token, accountId) {
  const body = await providerCall(
    fetchImpl,
    token,
    `/accounts/${encodeURIComponent(accountId)}/access/identity_providers`,
  );
  if (!Array.isArray(body.result)) fail('provider_response_invalid');
  const matches = body.result.filter((idp) => (
    isRecord(idp) &&
    typeof idp.id === 'string' && idp.id.length > 0 && idp.id.length <= 256 &&
    idp.type === 'cloudflare' &&
    isRecord(idp.config) && idp.config.restrict_to_account_members === true
  ));
  if (matches.length > 1) fail('identity_provider_ambiguous');
  return matches[0]?.id ?? null;
}

function exactRequestedEmails(application, requested) {
  const include = application?.policies?.[0]?.include;
  if (!Array.isArray(include)) return false;
  const observed = include.map((rule) => rule?.email?.email).sort();
  return observed.length === requested.length &&
    observed.every((email, index) => email === [...requested].sort()[index]);
}

function existingContract(
  applications,
  contract,
  requestedEmails,
  sessionDuration,
  identityProviderId,
) {
  const exactDomains = new Set([
    contract.privateInstallerApplication.domain,
    ...contract.bypassApplications.map((entry) => entry.domain),
  ]);
  for (const application of applications) {
    const classification = classifyAccessApplicationForHostname(application, contract.accessHost);
    if (classification === 'unverifiable') fail('access_inventory_unverifiable');
    if (classification === 'covering' && !exactDomains.has(application.domain)) {
      fail('access_selector_conflict');
    }
  }
  const byDomain = new Map();
  for (const domain of exactDomains) {
    const matches = applications.filter((application) => application.domain === domain);
    if (matches.length > 1) fail('access_application_duplicate');
    byDomain.set(domain, matches[0] ?? null);
  }
  for (const specification of contract.bypassApplications) {
    const application = byDomain.get(specification.domain);
    if (application && !contract.assessBypassApplication(application, specification).ok) {
      fail('access_application_drift');
    }
  }
  const installer = byDomain.get(contract.privateInstallerApplication.domain);
  const expectedIdentityProviders = identityProviderId === null ? [] : [identityProviderId];
  const observedIdentityProviders = installer?.allowed_idps ?? [];
  if (installer && (
    !contract.assessInstallerApplication(installer).ok ||
    !exactRequestedEmails(installer, requestedEmails) ||
    installer.session_duration !== sessionDuration ||
    !Array.isArray(observedIdentityProviders) ||
    observedIdentityProviders.length !== expectedIdentityProviders.length ||
    observedIdentityProviders.some((id, index) => id !== expectedIdentityProviders[index])
  )) fail('access_application_drift');
  return byDomain;
}

function validateInputs(targetInput, emails, sessionDuration) {
  let target;
  try {
    target = parseIsolatedCanaryTarget(targetInput);
  } catch {
    fail('target_invalid');
  }
  if (
    !Array.isArray(emails) || emails.length < 1 || emails.length > 16 ||
    emails.some((email) => typeof email !== 'string' || !EMAIL_PATTERN.test(email)) ||
    new Set(emails).size !== emails.length ||
    typeof sessionDuration !== 'string' || !/^[1-9]\d*(?:m|h|d)$/u.test(sessionDuration)
  ) fail('input_invalid');
  return Object.freeze({
    emails: Object.freeze([...emails].sort()),
    sessionDuration,
    target,
  });
}

export async function applyIsolatedAccess(input) {
  if (!exactKeys(input, ['emails', 'fetchImpl', 'readToken', 'sessionDuration', 'target'])) {
    fail('input_invalid');
  }
  const { emails, sessionDuration, target } = validateInputs(
    input.target,
    input.emails,
    input.sessionDuration,
  );
  if (typeof input.fetchImpl !== 'function' || typeof input.readToken !== 'function') {
    fail('input_invalid');
  }
  const contract = createIsolatedPrivateAccessContract(target.hostname);
  let token;
  try {
    token = await input.readToken();
    if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) fail('token_invalid');
    let applications = await readAllApplications(input.fetchImpl, token, target.accountId);
    const identityProviderId = await accountMemberIdentityProvider(
      input.fetchImpl,
      token,
      target.accountId,
    );
    let byDomain = existingContract(
      applications,
      contract,
      emails,
      sessionDuration,
      identityProviderId,
    );
    let createdApplications = 0;

    for (const specification of contract.bypassApplications) {
      if (byDomain.get(specification.domain)) continue;
      await providerCall(
        input.fetchImpl,
        token,
        `/accounts/${encodeURIComponent(target.accountId)}/access/apps`,
        { method: 'POST', body: JSON.stringify(contract.bypassApplicationBody(specification)) },
      );
      createdApplications += 1;
    }

    applications = await readAllApplications(input.fetchImpl, token, target.accountId);
    byDomain = existingContract(
      applications,
      contract,
      emails,
      sessionDuration,
      identityProviderId,
    );
    if (!byDomain.get(contract.privateInstallerApplication.domain)) {
      await providerCall(
        input.fetchImpl,
        token,
        `/accounts/${encodeURIComponent(target.accountId)}/access/apps`,
        {
          method: 'POST',
          body: JSON.stringify(contract.protectedInstallerApplicationBody({
            emails,
            identityProviderId,
            sessionDuration,
          })),
        },
      );
      createdApplications += 1;
    }

    applications = await readAllApplications(input.fetchImpl, token, target.accountId);
    byDomain = existingContract(
      applications,
      contract,
      emails,
      sessionDuration,
      identityProviderId,
    );
    if ([
      contract.privateInstallerApplication.domain,
      ...contract.bypassApplications.map((entry) => entry.domain),
    ].some((domain) => byDomain.get(domain) === null)) fail('access_application_missing');

    return Object.freeze({
      applicationCount: 4,
      createdApplications,
      reusedApplications: 4 - createdApplications,
      schemaVersion: 1,
      status: 'applied',
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

const HELP = `Usage:\n` +
  `  node scripts/edge-gate/apply-isolated-access.mjs --target <outside-repository-target.json> \\\n` +
  `    --email <operator> [--email <operator>] [--session 8h] --dry-run\n` +
  `  <token-source> | node scripts/edge-gate/apply-isolated-access.mjs \\\n` +
  `    --target <outside-repository-target.json> --email <operator> [--email <operator>] \\\n` +
  `    [--session 8h] --api-token-stdin\n`;

function parseArguments(argv) {
  if (argv.length === 1 && argv[0] === '--help') return Object.freeze({ help: true });
  const emails = [];
  let targetFilename = null;
  let sessionDuration = '8h';
  let sessionSeen = false;
  let stdinToken = false;
  let dryRun = false;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === '--api-token-stdin') {
      if (stdinToken) fail('input_invalid');
      stdinToken = true;
      continue;
    }
    if (flag === '--dry-run') {
      if (dryRun) fail('input_invalid');
      dryRun = true;
      continue;
    }
    if (!['--email', '--session', '--target'].includes(flag) ||
        index + 1 >= argv.length || argv[index + 1].startsWith('--')) fail('input_invalid');
    const value = argv[index + 1];
    index += 1;
    if (flag === '--email') emails.push(value);
    else if (flag === '--session' && !sessionSeen) {
      sessionDuration = value;
      sessionSeen = true;
    }
    else if (flag === '--target' && targetFilename === null) targetFilename = value;
    else fail('input_invalid');
  }
  if (targetFilename === null || emails.length === 0 || dryRun === stdinToken) fail('input_invalid');
  return Object.freeze({ dryRun, emails, help: false, sessionDuration, targetFilename });
}

export async function runIsolatedAccessApplyCli({ argv, fetchImpl = fetch, stdin, stderr, stdout }) {
  try {
    const options = parseArguments(argv);
    if (options.help) {
      stdout.write(HELP);
      return 0;
    }
    const target = await readIsolatedCanaryTargetFile(options.targetFilename);
    const validated = validateInputs(target, options.emails, options.sessionDuration);
    if (options.dryRun) {
      stdout.write(`${JSON.stringify({
        applicationCount: 4,
        operatorIdentityCount: validated.emails.length,
        schemaVersion: 1,
        status: 'planned',
      })}\n`);
      return 0;
    }
    const result = await applyIsolatedAccess({
      emails: validated.emails,
      fetchImpl,
      readToken: () => readTokenFromStdin(stdin),
      sessionDuration: validated.sessionDuration,
      target: validated.target,
    });
    stdout.write(`${JSON.stringify(result)}\n`);
    return 0;
  } catch (error) {
    const code = error instanceof IsolatedAccessApplyError ? error.code : 'internal_error';
    stderr.write(`Isolated Access apply failed: ${code}.\n`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = await runIsolatedAccessApplyCli({
    argv: process.argv.slice(2),
    stdin: process.stdin,
    stderr: process.stderr,
    stdout: process.stdout,
  });
}
