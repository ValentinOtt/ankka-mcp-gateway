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
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const WORKER_ID = /^[a-f0-9]{32}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const MAX_RESPONSE_BYTES = 256 * 1024;
const READY_ATTEMPTS = 20;
const BINDING_NAMES = Object.freeze([
  'ADMIN_EMAILS',
  'ANKKA_GATEWAY_RELEASE',
  'ANKKA_GATEWAY_RELEASE_SHA256',
  'ANKKA_MANAGEMENT_HOSTNAME',
  'ANKKA_UPDATE_CHANNEL',
  'ANKKA_UPDATE_KEY_ID',
  'ANKKA_UPDATE_PUBLIC_KEY',
  'ANKKA_WORKERS_SUBDOMAIN',
  'ANKKA_WORKER_NAME',
  'CF_ACCESS_AUD',
  'CF_ACCESS_ISSUER',
  'CLOUDFLARE_ACCOUNT_ID',
  'CLOUDFLARE_ZONE_ID',
  'CLOUDFLARE_ZONE_NAME',
  'ZERO_TRUST_READY',
] as const);

type CurrentRuntimeBindings = Readonly<Record<(typeof BINDING_NAMES)[number], string>>;

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

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expectedKeys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function validateInput(input: ReturningUninstallActionRelayInput, now: number): URL {
  let management: URL;
  try { management = new URL(input.managementOrigin); } catch { invalid(); }
  if (!ACCOUNT_ID.test(input.accountId) || !ACTION_ID.test(input.actionId) ||
    !INSTALLATION_ID.test(input.installationId) || !WORKER_NAME.test(input.workerName) ||
    !DNS_LABEL.test(input.workersSubdomain) || !ACTION_KEY.test(input.actionKey) ||
    !ACCESS_TOKEN.test(input.accessToken) || input.actorEmail !== input.actorEmail.toLowerCase() ||
    !EMAIL.test(input.actorEmail) || !Number.isSafeInteger(input.expiresAt) || input.expiresAt <= now ||
    input.expiresAt > now + 10 * 60 * 1000 || typeof input.gatewayName !== 'string' ||
    input.gatewayName.length < 1 || input.gatewayName.length > 128 ||
    /[\u0000-\u001f\u007f<>{}\\]/u.test(input.gatewayName) ||
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

async function providerResult(input: ReturningUninstallActionRelayInput, path: string, init: RequestInit): Promise<unknown> {
  return withDeadline(async (signal) => {
    const response = await input.transport(providerUrl(input.accountId, path), {
      ...init,
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${input.accessToken}`,
        ...(init.body ? { 'content-type': 'application/json' } : {}),
      },
      redirect: 'manual',
      signal,
    });
    if (response.redirected || (response.status >= 300 && response.status < 400)) {
      await response.body?.cancel().catch(() => undefined);
      throw new DeployError(502, 'oauth_grant_invalid');
    }
    const body = await readBoundedText(response, 'oauth_grant_invalid', MAX_RESPONSE_BYTES);
    if (!response.ok) throw new DeployError(502, 'oauth_grant_invalid');
    let envelope: unknown;
    try { envelope = JSON.parse(body); } catch { throw new DeployError(502, 'oauth_grant_invalid'); }
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope) ||
      (envelope as Record<string, unknown>).success !== true || !Object.hasOwn(envelope, 'result')) {
      throw new DeployError(502, 'oauth_grant_invalid');
    }
    return (envelope as Record<string, unknown>).result;
  }, 'oauth_grant_invalid');
}

function subdomainState(value: unknown, expected: boolean): void {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
    Object.keys(value).sort().join(',') !== 'enabled,previews_enabled' ||
    (value as Record<string, unknown>).enabled !== expected ||
    (value as Record<string, unknown>).previews_enabled !== false) {
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

function activeVersionId(value: unknown): string {
  if (!isRecord(value) || !exactKeys(value, ['deployments']) || !Array.isArray(value.deployments) ||
    value.deployments.length < 1 || value.deployments.length > 1_000) conflict();
  const active = value.deployments[0];
  if (!isRecord(active) || !UUID.test(String(active.id)) || !Array.isArray(active.versions) ||
    active.versions.length !== 1 || !isRecord(active.versions[0]) ||
    active.versions[0].percentage !== 100 || !UUID.test(String(active.versions[0].version_id))) conflict();
  return String(active.versions[0].version_id);
}

function currentBindings(value: unknown): CurrentRuntimeBindings {
  if (!isRecord(value) || !Array.isArray(value.bindings) ||
    value.bindings.length !== BINDING_NAMES.length + 2 || value.main_module !== 'index.js' ||
    value.compatibility_date !== '2026-08-08' || Object.hasOwn(value, 'migrations') ||
    Object.hasOwn(value, 'migration_tag')) conflict();
  const bindings = new Map<string, Record<string, unknown>>();
  for (const binding of value.bindings) {
    if (!isRecord(binding) || typeof binding.name !== 'string' || bindings.has(binding.name)) conflict();
    bindings.set(binding.name, binding);
  }
  const admin = bindings.get('ADMIN_STATE');
  const assets = bindings.get('ASSETS');
  if (!admin || admin.type !== 'durable_object_namespace' || admin.class_name !== 'AdminState' ||
    !assets || !exactKeys(assets, ['name', 'type']) || assets.type !== 'assets') conflict();
  const output = {} as Record<(typeof BINDING_NAMES)[number], string>;
  for (const name of BINDING_NAMES) {
    const binding = bindings.get(name);
    if (!binding || !exactKeys(binding, ['name', 'text', 'type']) || binding.type !== 'plain_text' ||
      typeof binding.text !== 'string' || binding.text.length < 1 || binding.text.length > 4_096) conflict();
    output[name] = binding.text;
  }
  return Object.freeze(output);
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
  if (!isRecord(worker) || worker.name !== input.workerName || !WORKER_ID.test(String(worker.id)) ||
    !Array.isArray(worker.tags) || !worker.tags.includes('ankka-mcp-gateway')) conflict();
  const versionId = activeVersionId(await providerResult(
    input,
    `/workers/scripts/${encodeURIComponent(input.workerName)}/deployments`,
    { method: 'GET' },
  ));
  const version = await providerResult(
    input,
    `/workers/workers/${String(worker.id)}/versions/${versionId}`,
    { method: 'GET' },
  );
  if (!isRecord(version) || version.id !== versionId) conflict();
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
  if (!subdomain || typeof subdomain !== 'object' || Array.isArray(subdomain) ||
    Object.keys(subdomain).join(',') !== 'subdomain' ||
    (subdomain as Record<string, unknown>).subdomain !== input.workersSubdomain) {
    throw new DeployError(409, 'session_conflict');
  }
  const query = new URLSearchParams({ hostname: management.hostname, page: '1', per_page: '50' });
  const domains = await providerResult(input, `/workers/domains?${query}`, { method: 'GET' });
  if (!Array.isArray(domains) || domains.length !== 1 || !domains[0] ||
    typeof domains[0] !== 'object' || Array.isArray(domains[0])) throw new DeployError(409, 'session_conflict');
  const domain = domains[0] as Record<string, unknown>;
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
  let parsed: unknown;
  try { parsed = JSON.parse(serialized); } catch { throw new DeployError(409, 'session_conflict'); }
  return parseReturningUninstallImportedAuthority(parsed, input);
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
  let value: unknown;
  try { value = JSON.parse(serialized); } catch { throw new DeployError(409, 'session_conflict'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new DeployError(409, 'session_conflict');
  }
  const result = value as Record<string, unknown>;
  if (Object.keys(result).sort().join(',') !==
      'actionId,installationId,removedResourceCount,schemaVersion,status' ||
    result.schemaVersion !== 1 || result.actionId !== input.actionId ||
    result.status !== 'gateway_removed' || result.installationId !== input.installationId ||
    !Number.isSafeInteger(result.removedResourceCount) || (result.removedResourceCount as number) < 4 ||
    (result.removedResourceCount as number) > 103) {
    throw new DeployError(409, 'session_conflict');
  }
  return Object.freeze(result as unknown as ReturningUninstallApplyResult);
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
  let operationError: unknown = null;
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
    operationError = error;
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
  if (!REQUEST_ID.test(requestId) || typeof proveCurrentRuntime !== 'function') invalid();
  const management = validateInput(input, now);
  let routeMayBeEnabled = false;
  let operationError: unknown = null;
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
    operationError = error;
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
