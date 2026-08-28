import * as v from 'valibot';

import { boundaryValueSchema, type BoundaryValue } from './boundary';
import {
  parseAccountWorkersSubdomain,
  parseActiveGatewayRuntime,
  parseCurrentGatewayVersion,
  parseCurrentGatewayWorker,
  parseGatewayRuntimeBindings,
  parseGatewayWorkerDomains,
  parseGatewayWorkerSubdomainState,
} from './cloudflare-gateway-runtime-state';
import type { GatewayWorkerPlainTextBindings } from './cloudflare-worker-direct-upload';
import { CLOUDFLARE_API_ORIGIN } from './constants';
import { base64UrlDecode } from './crypto';
import { DeployError } from './errors';
import { readBoundedText, withDeadline } from './http';
import type { FetchTransport } from './oauth';
import {
  parseReturningUninstallImportedAuthority,
  returningUninstallAuthorityCanonicalJson,
  type ReturningUninstallAuthorityExpectation,
  type ReturningUninstallImportedAuthority,
  type ReturningUninstallRuntimeAuthority,
} from './returning-uninstall-authority';

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const ACTION_ID = /^action_[A-Za-z0-9_-]{32}$/u;
const ACTION_KEY = /^[A-Za-z0-9_-]{43}$/u;
const ACCESS_TOKEN = /^[A-Za-z0-9._~-]{20,16384}$/u;
const ARTIFACT = /^sha256:[a-f0-9]{64}$/u;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const EMAIL = /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u;
const INSTALLATION_ID = /^acg-[a-f0-9]{24}$/u;
const RELEASE = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[a-z0-9.-]+)?$/u;
const REQUEST_ID = /^[A-Za-z0-9_-]{22}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const MAX_RESPONSE_BYTES = 256 * 1024;
const READY_ATTEMPTS = 20;
const providerEnvelopeSchema = v.looseObject({
  result: boundaryValueSchema,
  success: v.literal(true),
});
const applyResultSchema = v.strictObject({
  actionId: v.string(),
  installationId: v.string(),
  removedResourceCount: v.pipe(v.number(), v.safeInteger(), v.minValue(4), v.maxValue(103)),
  schemaVersion: v.literal(1),
  status: v.literal('gateway_removed'),
});

type CurrentRuntimeBindings = GatewayWorkerPlainTextBindings;

export interface ReturningUninstallActionRelayInput extends ReturningUninstallAuthorityExpectation {
  readonly actionKey: string;
  readonly actorEmail: string;
  readonly expiresAt: number;
  readonly accessToken: string;
  readonly transport: FetchTransport;
  readonly now?: () => number;
}

function invalid(): never {
  throw new DeployError(400, 'bad_request');
}

function conflict(): never {
  throw new DeployError(409, 'session_conflict');
}

function unsafeGatewayNameCharacter(character: string): boolean {
  const codePoint = character.codePointAt(0);
  return codePoint === undefined || codePoint <= 0x1f || codePoint === 0x7f || '<>{}\\'.includes(character);
}

function validateInput(input: ReturningUninstallActionRelayInput, now: number): URL {
  let management: URL;
  try { management = new URL(input.managementOrigin); } catch { invalid(); }
  if (!ACCOUNT_ID.test(input.accountId) || !ACTION_ID.test(input.actionId) ||
    !INSTALLATION_ID.test(input.installationId) || !WORKER_NAME.test(input.workerName) ||
    !DNS_LABEL.test(input.workersSubdomain) || !ACTION_KEY.test(input.actionKey) ||
    !ACCESS_TOKEN.test(input.accessToken) || input.actorEmail !== input.actorEmail.toLowerCase() ||
    !EMAIL.test(input.actorEmail) || !Number.isSafeInteger(input.expiresAt) || input.expiresAt <= now ||
    input.expiresAt > now + 10 * 60 * 1000 || !v.is(v.string(), input.gatewayName) ||
    input.gatewayName.length < 1 || input.gatewayName.length > 128 ||
    [...input.gatewayName].some(unsafeGatewayNameCharacter) ||
    !input.portalHostname.includes('.') || input.portalHostname !== input.portalHostname.toLowerCase() ||
    input.portalHostname.split('.').some((label) => !DNS_LABEL.test(label)) ||
    management.protocol !== 'https:' ||
    management.username || management.password || management.port || management.pathname !== '/' ||
    management.search || management.hash) invalid();
  return management;
}

function providerUrl(accountId: string, path: string): URL {
  return new URL(`/client/v4/accounts/${encodeURIComponent(accountId)}${path}`, CLOUDFLARE_API_ORIGIN);
}

async function providerResult(
  input: ReturningUninstallActionRelayInput,
  path: string,
  init: RequestInit,
): Promise<BoundaryValue> {
  return withDeadline(async (signal) => {
    const headers = new Headers({
      accept: 'application/json',
      authorization: `Bearer ${input.accessToken}`,
    });
    if (init.body !== undefined && init.body !== null) headers.set('content-type', 'application/json');
    const response = await input.transport(providerUrl(input.accountId, path), {
      ...init,
      headers,
      redirect: 'manual',
      signal,
    });
    if (response.redirected || (response.status >= 300 && response.status < 400)) {
      await response.body?.cancel().catch(() => undefined);
      throw new DeployError(502, 'oauth_grant_invalid');
    }
    const body = await readBoundedText(response, 'oauth_grant_invalid', MAX_RESPONSE_BYTES);
    if (!response.ok) throw new DeployError(502, 'oauth_grant_invalid');
    try {
      const envelope = v.safeParse(providerEnvelopeSchema, JSON.parse(body));
      if (!envelope.success) throw new DeployError(502, 'oauth_grant_invalid');
      return envelope.output.result;
    } catch (error) {
      if (error instanceof DeployError) throw error;
      throw new DeployError(502, 'oauth_grant_invalid');
    }
  }, 'oauth_grant_invalid');
}

function subdomainState(value: BoundaryValue, expected: boolean): void {
  const state = parseGatewayWorkerSubdomainState(value);
  if (!state || state.enabled !== expected) {
    throw new DeployError(409, 'session_conflict');
  }
}

async function readSubdomain(input: ReturningUninstallActionRelayInput, expected: boolean): Promise<void> {
  subdomainState(await providerResult(
    input,
    `/workers/scripts/${encodeURIComponent(input.workerName)}/subdomain`,
    { method: 'GET' },
  ), expected);
}

async function setSubdomain(input: ReturningUninstallActionRelayInput, enabled: boolean): Promise<void> {
  subdomainState(await providerResult(
    input,
    `/workers/scripts/${encodeURIComponent(input.workerName)}/subdomain`,
    { method: 'POST', body: JSON.stringify({ enabled, previews_enabled: false }) },
  ), enabled);
  await readSubdomain(input, enabled);
}

function activeVersionId(value: BoundaryValue): string {
  const active = parseActiveGatewayRuntime(value);
  if (!active) conflict();
  return active.versionId;
}

function currentBindings(value: BoundaryValue): CurrentRuntimeBindings {
  const bindings = parseGatewayRuntimeBindings(value);
  if (!bindings) conflict();
  return bindings;
}

function validateRuntimeBindings(
  input: ReturningUninstallActionRelayInput,
  management: URL,
  bindings: CurrentRuntimeBindings,
): void {
  const admins = bindings.ADMIN_EMAILS.split(',');
  if (!RELEASE.test(bindings.ANKKA_GATEWAY_RELEASE) ||
    !ARTIFACT.test(bindings.ANKKA_GATEWAY_RELEASE_SHA256) ||
    !['canary', 'stable'].includes(bindings.ANKKA_UPDATE_CHANNEL) ||
    !/^[a-z0-9][a-z0-9._-]{0,63}$/u.test(bindings.ANKKA_UPDATE_KEY_ID) ||
    !/^[A-Za-z0-9_-]{43}$/u.test(bindings.ANKKA_UPDATE_PUBLIC_KEY) ||
    bindings.CLOUDFLARE_ACCOUNT_ID !== input.accountId ||
    bindings.ANKKA_WORKER_NAME !== input.workerName ||
    bindings.ANKKA_WORKERS_SUBDOMAIN !== input.workersSubdomain ||
    bindings.ANKKA_MANAGEMENT_HOSTNAME !== management.hostname ||
    bindings.ZERO_TRUST_READY !== 'true' || admins.length < 1 || admins.length > 16 ||
    new Set(admins).size !== admins.length ||
    admins.some((email) => email !== email.toLowerCase() || !EMAIL.test(email)) ||
    !admins.includes(input.actorEmail)) conflict();
}

async function verifyCurrentRuntime(
  input: ReturningUninstallActionRelayInput,
  management: URL,
): Promise<CurrentRuntimeBindings> {
  const worker = await providerResult(
    input,
    `/workers/workers/${encodeURIComponent(input.workerName)}`,
    { method: 'GET' },
  );
  const currentWorker = parseCurrentGatewayWorker(worker);
  if (!currentWorker || currentWorker.name !== input.workerName ||
      !currentWorker.tags.includes('ankka-mcp-gateway')) conflict();
  const versionId = activeVersionId(await providerResult(
    input,
    `/workers/scripts/${encodeURIComponent(input.workerName)}/deployments`,
    { method: 'GET' },
  ));
  const version = await providerResult(
    input,
    `/workers/workers/${currentWorker.id}/versions/${versionId}`,
    { method: 'GET' },
  );
  const currentVersion = parseCurrentGatewayVersion(version);
  if (!currentVersion || currentVersion.id !== versionId) conflict();
  const bindings = currentBindings(version);
  validateRuntimeBindings(input, management, bindings);
  return bindings;
}

function bindAuthorityToCurrentRuntime(
  input: ReturningUninstallActionRelayInput,
  authority: ReturningUninstallImportedAuthority,
  bindings: CurrentRuntimeBindings,
): void {
  const runtime: ReturningUninstallRuntimeAuthority = authority.runtime;
  if (authority.actionId !== input.actionId || authority.actorEmail !== input.actorEmail ||
    authority.installationId !== input.installationId || authority.receipt.installationId !== input.installationId ||
    authority.receipt.target.accountId !== input.accountId ||
    authority.receipt.target.hostname !== input.portalHostname ||
    authority.control.portal.hostname !== input.portalHostname || authority.control.portal.name !== input.gatewayName ||
    bindings.ADMIN_EMAILS !== authority.control.audienceEmails.join(',') ||
    bindings.ANKKA_GATEWAY_RELEASE !== runtime.release ||
    bindings.ANKKA_GATEWAY_RELEASE_SHA256 !== runtime.artifactSha256 ||
    bindings.ANKKA_UPDATE_CHANNEL !== runtime.updateChannel ||
    bindings.ANKKA_UPDATE_KEY_ID !== runtime.updateKeyId ||
    bindings.ANKKA_UPDATE_PUBLIC_KEY !== runtime.updatePublicKey ||
    bindings.CLOUDFLARE_ACCOUNT_ID !== runtime.accountId ||
    bindings.CLOUDFLARE_ZONE_ID !== runtime.zoneId ||
    bindings.CLOUDFLARE_ZONE_NAME !== runtime.zoneName ||
    bindings.ANKKA_WORKER_NAME !== runtime.workerName ||
    bindings.ANKKA_WORKERS_SUBDOMAIN !== runtime.workersSubdomain ||
    bindings.ANKKA_MANAGEMENT_HOSTNAME !== runtime.managementHostname ||
    bindings.ZERO_TRUST_READY !== 'true') conflict();
}

async function validateProviderOrigin(
  input: ReturningUninstallActionRelayInput,
  management: URL,
): Promise<CurrentRuntimeBindings> {
  const subdomain = await providerResult(input, '/workers/subdomain', { method: 'GET' });
  if (parseAccountWorkersSubdomain(subdomain) !== input.workersSubdomain) {
    throw new DeployError(409, 'session_conflict');
  }
  const query = new URLSearchParams({ hostname: management.hostname, page: '1', per_page: '50' });
  const domains = parseGatewayWorkerDomains(
    await providerResult(input, `/workers/domains?${query}`, { method: 'GET' }),
  );
  if (!domains || domains.length !== 1) throw new DeployError(409, 'session_conflict');
  const domain = domains[0];
  if (!domain) throw new DeployError(409, 'session_conflict');
  if (domain.hostname !== management.hostname || domain.service !== input.workerName ||
    (domain.environment !== undefined && domain.environment !== 'production')) {
    throw new DeployError(409, 'session_conflict');
  }
  await readSubdomain(input, false);
  return verifyCurrentRuntime(input, management);
}

async function hmac(actionKey: string, body: string): Promise<string> {
  const source = base64UrlDecode(actionKey);
  const owned = new Uint8Array(source.byteLength);
  owned.set(source);
  try {
    const key = await crypto.subtle.importKey('raw', owned, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body)));
    try { return `sha256=${[...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`; }
    finally { digest.fill(0); }
  } finally { source.fill(0); owned.fill(0); }
}

function actionUrl(input: ReturningUninstallActionRelayInput): URL {
  return new URL(`https://${input.workerName}.${input.workersSubdomain}.workers.dev/__ankka/teardown-action`);
}

async function awaitRoute(input: ReturningUninstallActionRelayInput): Promise<void> {
  for (let attempt = 0; attempt < READY_ATTEMPTS; attempt += 1) {
    try {
      const response = await input.transport(actionUrl(input), { method: 'HEAD', redirect: 'manual' });
      const accepted = !response.redirected && response.status === 204 &&
        response.headers.get('x-ankka-teardown-action') === 'ready';
      await response.body?.cancel().catch(() => undefined);
      if (accepted) return;
    } catch { /* bounded retry below */ }
    await new Promise<void>((resolve) => setTimeout(resolve, 250));
  }
  throw new DeployError(504, 'oauth_exchange_failed', 'customer_action_route_timeout');
}

async function prove(input: ReturningUninstallActionRelayInput, now: number): Promise<ReturningUninstallImportedAuthority> {
  const body = returningUninstallAuthorityCanonicalJson({
    schemaVersion: 1,
    command: 'prove',
    actionId: input.actionId,
    actionKey: input.actionKey,
    actorEmail: input.actorEmail,
    accountId: input.accountId,
    installationId: input.installationId,
    issuedAt: now,
    expiresAt: input.expiresAt,
  });
  const response = await input.transport(actionUrl(input), {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      'x-ankka-teardown-action-signature': await hmac(input.actionKey, body),
    },
    body,
    redirect: 'manual',
    credentials: 'omit',
  });
  if (response.redirected || response.status !== 200) {
    await response.body?.cancel().catch(() => undefined);
    throw new DeployError(409, 'session_conflict');
  }
  const serialized = await readBoundedText(response, 'session_conflict', MAX_RESPONSE_BYTES);
  try {
    const parsed = v.parse(boundaryValueSchema, JSON.parse(serialized));
    return parseReturningUninstallImportedAuthority(parsed, input);
  } catch (error) {
    if (error instanceof DeployError) throw error;
    throw new DeployError(409, 'session_conflict');
  }
}

export interface ReturningUninstallApplyResult {
  readonly schemaVersion: 1;
  readonly actionId: string;
  readonly status: 'gateway_removed';
  readonly installationId: string;
  readonly removedResourceCount: number;
}

async function apply(
  input: ReturningUninstallActionRelayInput,
  requestId: string,
  now: number,
): Promise<ReturningUninstallApplyResult> {
  const body = returningUninstallAuthorityCanonicalJson({
    schemaVersion: 1,
    command: 'apply',
    actionId: input.actionId,
    actionKey: input.actionKey,
    actorEmail: input.actorEmail,
    accountId: input.accountId,
    installationId: input.installationId,
    requestId,
    cloudflareAccessToken: input.accessToken,
    issuedAt: now,
    expiresAt: input.expiresAt,
  });
  const response = await input.transport(actionUrl(input), {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      'x-ankka-teardown-action-signature': await hmac(input.actionKey, body),
    },
    body,
    redirect: 'manual',
    credentials: 'omit',
  });
  if (response.redirected || response.status !== 200) {
    await response.body?.cancel().catch(() => undefined);
    throw new DeployError(409, 'session_conflict');
  }
  const serialized = await readBoundedText(response, 'session_conflict', MAX_RESPONSE_BYTES);
  let result: v.SafeParseResult<typeof applyResultSchema>;
  try {
    result = v.safeParse(applyResultSchema, JSON.parse(serialized));
  } catch {
    throw new DeployError(409, 'session_conflict');
  }
  if (!result.success || result.output.actionId !== input.actionId ||
      result.output.installationId !== input.installationId) throw new DeployError(409, 'session_conflict');
  return Object.freeze(result.output);
}

function operationFailure<Value>(error: Value): Error {
  return error instanceof Error ? error : new DeployError(409, 'session_conflict');
}

/**
 * Opens only the exact customer Worker route, proves the HMAC-bound one-time
 * action, imports secret-free receipt authority, and always closes the route.
 */
export async function relayReturningUninstallAction(
  input: ReturningUninstallActionRelayInput,
): Promise<ReturningUninstallImportedAuthority> {
  const now = input.now?.() ?? Date.now();
  const management = validateInput(input, now);
  let routeMayBeEnabled = false;
  let operationError: Error | null = null;
  let authority: ReturningUninstallImportedAuthority | null = null;
  try {
    const bindings = await validateProviderOrigin(input, management);
    // Set before the mutating call: an ambiguous response may mean enabled.
    routeMayBeEnabled = true;
    await setSubdomain(input, true);
    await awaitRoute(input);
    authority = await prove(input, now);
    bindAuthorityToCurrentRuntime(input, authority, bindings);
  } catch (error) {
    operationError = operationFailure(error);
  } finally {
    if (routeMayBeEnabled) {
      try { await setSubdomain(input, false); }
      catch { operationError = new DeployError(409, 'session_conflict'); }
    }
  }
  if (operationError) throw operationError;
  if (!authority) throw new DeployError(409, 'session_conflict');
  return authority;
}

/** Resume the receipt journal in the customer Worker and close workers.dev on every outcome. */
export async function applyReturningUninstallAction(
  input: ReturningUninstallActionRelayInput,
  requestId: string,
  authority: ReturningUninstallImportedAuthority,
  proveCurrentRuntime: () => Promise<void>,
): Promise<ReturningUninstallApplyResult> {
  const now = input.now?.() ?? Date.now();
  if (!REQUEST_ID.test(requestId) || !v.is(v.function(), proveCurrentRuntime)) invalid();
  const management = validateInput(input, now);
  let routeMayBeEnabled = false;
  let operationError: Error | null = null;
  let result: ReturningUninstallApplyResult | null = null;
  try {
    const bindings = await validateProviderOrigin(input, management);
    bindAuthorityToCurrentRuntime(input, authority, bindings);
    routeMayBeEnabled = true;
    await setSubdomain(input, true);
    await awaitRoute(input);
    // Route readiness is not ownership: immediately before the token-bearing
    // request, the reviewed executor must re-prove the exact signed historical
    // runtime that imported this authority is still solely active.
    await proveCurrentRuntime();
    result = await apply(input, requestId, now);
  } catch (error) {
    operationError = operationFailure(error);
  } finally {
    if (routeMayBeEnabled) {
      try { await setSubdomain(input, false); }
      catch { operationError = new DeployError(409, 'session_conflict'); }
    }
  }
  if (operationError) throw operationError;
  if (!result) throw new DeployError(409, 'session_conflict');
  return result;
}
