import { CLOUDFLARE_API_ORIGIN } from './constants';
import {
  prepareVerifiedWorkerRelease,
  prepareWorkerVersionRecoveryRecord,
  proveActiveWorkerVersionRecovery,
  type ActiveWorkerVersionProof,
  type GatewayWorkerPlainTextBindings,
} from './cloudflare-worker-direct-upload';
import { base64UrlDecode } from './crypto';
import { DeployError } from './errors';
import {
  assertExactReleaseBundleIdentity,
  parseExactReleaseBundleIdentity,
  type ExactReleaseBundleIdentity,
} from './exact-release-bundle';
import { readBoundedText, withDeadline } from './http';
import type { FetchTransport } from './oauth';
import { adaptVerifiedReleaseBundleForWorkerDirectUpload } from './release-direct-upload-adapter';
import type { VerifiedReleaseBundle } from './release';

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const ACTION_ID = /^action_[A-Za-z0-9_-]{32}$/u;
const NONCE = /^[A-Za-z0-9_-]{43}$/u;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const WORKER_ID = /^[a-f0-9]{32}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const EMAIL = /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u;
const MAX_CUSTOMER_RESPONSE_BYTES = 64 * 1024;
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

export interface SourceActionRelayInput {
  readonly accessToken: string;
  readonly accountId: string;
  readonly workerName: string;
  readonly workersSubdomain: string;
  readonly managementOrigin: string;
  readonly actionId: string;
  readonly actionKey: string;
  readonly actorEmail: string;
  readonly expiresAt: number;
  /** Exact historical signed release selected by the customer-owned handoff. */
  readonly releaseIdentity: ExactReleaseBundleIdentity;
  /** Independently loaded and signature-verified immutable bundle for that identity. */
  readonly releaseBundle: VerifiedReleaseBundle;
  readonly transport: FetchTransport;
  readonly now?: () => number;
}

export interface SourceActionRelayResult {
  readonly schemaVersion: 1;
  readonly actionId: string;
  readonly status: 'succeeded';
  readonly managementUrl: string;
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

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function validate(input: SourceActionRelayInput, now: number): URL {
  let management: URL;
  try { management = new URL(input.managementOrigin); } catch { invalid(); }
  if (!ACCOUNT_ID.test(input.accountId) || !WORKER_NAME.test(input.workerName) ||
      !DNS_LABEL.test(input.workersSubdomain) || !ACTION_ID.test(input.actionId) ||
      !NONCE.test(input.actionKey) || input.actorEmail !== input.actorEmail.toLowerCase() ||
      !EMAIL.test(input.actorEmail) || !Number.isSafeInteger(input.expiresAt) || input.expiresAt <= now ||
      input.expiresAt > now + 10 * 60 * 1000 || typeof input.accessToken !== 'string' ||
      input.accessToken.length < 20 || input.accessToken.length > 16 * 1024 ||
      management.protocol !== 'https:' || management.username !== '' || management.password !== '' ||
      management.port !== '' || management.pathname !== '/' || management.search !== '' || management.hash !== '') {
    invalid();
  }
  return management;
}

function providerUrl(accountId: string, path: string): URL {
  return new URL(`/client/v4/accounts/${encodeURIComponent(accountId)}${path}`, CLOUDFLARE_API_ORIGIN);
}

async function providerResult(
  input: SourceActionRelayInput,
  path: string,
  init: RequestInit,
): Promise<unknown> {
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
    if (response.redirected || response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new DeployError(502, 'oauth_grant_invalid');
    }
    const serialized = await readBoundedText(response, 'oauth_grant_invalid', MAX_CUSTOMER_RESPONSE_BYTES);
    if (!response.ok) throw new DeployError(502, 'oauth_grant_invalid');
    let envelope: unknown;
    try { envelope = JSON.parse(serialized); } catch { throw new DeployError(502, 'oauth_grant_invalid'); }
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope) ||
        (envelope as Record<string, unknown>).success !== true ||
        !Object.hasOwn(envelope, 'result')) throw new DeployError(502, 'oauth_grant_invalid');
    return (envelope as Record<string, unknown>).result;
  }, 'oauth_grant_invalid');
}

function subdomainState(value: unknown, expected: boolean): void {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join(',') !== 'enabled,previews_enabled' ||
      record.enabled !== expected || record.previews_enabled !== false) {
    throw new DeployError(409, 'session_conflict');
  }
}

async function readSubdomainState(input: SourceActionRelayInput, expected: boolean): Promise<void> {
  subdomainState(await providerResult(
    input,
    `/workers/scripts/${encodeURIComponent(input.workerName)}/subdomain`,
    { method: 'GET' },
  ), expected);
}

async function setSubdomainState(input: SourceActionRelayInput, enabled: boolean): Promise<void> {
  subdomainState(await providerResult(
    input,
    `/workers/scripts/${encodeURIComponent(input.workerName)}/subdomain`,
    { method: 'POST', body: JSON.stringify({ enabled, previews_enabled: false }) },
  ), enabled);
  await readSubdomainState(input, enabled);
}

async function verifyAccountSubdomain(input: SourceActionRelayInput): Promise<void> {
  const value = await providerResult(input, '/workers/subdomain', { method: 'GET' });
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).join(',') !== 'subdomain' ||
      (value as Record<string, unknown>).subdomain !== input.workersSubdomain) {
    throw new DeployError(409, 'session_conflict');
  }
}

async function verifyManagementDomain(
  input: SourceActionRelayInput,
  management: URL,
): Promise<void> {
  const path = new URLSearchParams({
    hostname: management.hostname,
    page: '1',
    per_page: '50',
  });
  const value = await providerResult(input, `/workers/domains?${path.toString()}`, { method: 'GET' });
  if (!Array.isArray(value) || value.length !== 1) throw new DeployError(409, 'session_conflict');
  const domain = value[0];
  if (!domain || typeof domain !== 'object' || Array.isArray(domain)) {
    throw new DeployError(409, 'session_conflict');
  }
  const record = domain as Record<string, unknown>;
  if (record.hostname !== management.hostname || record.service !== input.workerName ||
      (record.environment !== undefined && record.environment !== 'production')) {
    throw new DeployError(409, 'session_conflict');
  }
}

interface ActiveRuntime {
  readonly deploymentId: string;
  readonly versionId: string;
}

function activeRuntime(value: unknown): ActiveRuntime {
  if (!isRecord(value) || !exactKeys(value, ['deployments']) || !Array.isArray(value.deployments) ||
      value.deployments.length < 1 || value.deployments.length > 1_000) conflict();
  const active = value.deployments[0];
  if (!isRecord(active) || !UUID.test(String(active.id)) || !Array.isArray(active.versions) ||
      active.versions.length !== 1 || !isRecord(active.versions[0]) ||
      active.versions[0].percentage !== 100 || !UUID.test(String(active.versions[0].version_id))) {
    conflict();
  }
  return Object.freeze({
    deploymentId: String(active.id),
    versionId: String(active.versions[0].version_id),
  });
}

function currentBindings(value: unknown): Readonly<Record<(typeof BINDING_NAMES)[number], string>> {
  if (!isRecord(value) || !Array.isArray(value.bindings) || value.bindings.length !== BINDING_NAMES.length + 2 ||
      value.main_module !== 'index.js' || value.compatibility_date !== '2026-08-08' ||
      Object.hasOwn(value, 'migrations') || Object.hasOwn(value, 'migration_tag')) conflict();
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

interface CurrentRuntimeSeed {
  readonly active: ActiveRuntime;
  readonly bindings: GatewayWorkerPlainTextBindings;
  readonly worker: {
    readonly kind: 'worker';
    readonly accountId: string;
    readonly workerName: string;
    readonly workerId: string;
  };
}

function validateRuntimeBindings(
  input: SourceActionRelayInput,
  management: URL,
  bindings: GatewayWorkerPlainTextBindings,
  identity: ExactReleaseBundleIdentity,
): void {
  const admins = bindings.ADMIN_EMAILS.split(',');
  if (
    bindings.ANKKA_GATEWAY_RELEASE !== identity.release ||
    bindings.ANKKA_GATEWAY_RELEASE_SHA256 !== `sha256:${identity.artifactSha256}` ||
    bindings.ANKKA_UPDATE_CHANNEL !== identity.channel ||
    bindings.ANKKA_UPDATE_KEY_ID !== identity.keyId ||
    bindings.ANKKA_UPDATE_PUBLIC_KEY !== identity.publicKey ||
    bindings.CLOUDFLARE_ACCOUNT_ID !== input.accountId ||
    bindings.ANKKA_WORKER_NAME !== input.workerName ||
    bindings.ANKKA_WORKERS_SUBDOMAIN !== input.workersSubdomain ||
    bindings.ANKKA_MANAGEMENT_HOSTNAME !== management.hostname ||
    bindings.ZERO_TRUST_READY !== 'true' ||
    admins.length < 1 || admins.length > 16 || new Set(admins).size !== admins.length ||
    admins.some((email) => email !== email.toLowerCase() || !EMAIL.test(email)) ||
    !admins.includes(input.actorEmail)
  ) conflict();
}

async function readCurrentRuntimeSeed(
  input: SourceActionRelayInput,
  management: URL,
  identity: ExactReleaseBundleIdentity,
): Promise<CurrentRuntimeSeed> {
  const worker = await providerResult(
    input,
    `/workers/workers/${encodeURIComponent(input.workerName)}`,
    { method: 'GET' },
  );
  if (!isRecord(worker) || worker.name !== input.workerName || !WORKER_ID.test(String(worker.id)) ||
      !Array.isArray(worker.tags) || !worker.tags.includes('ankka-mcp-gateway')) conflict();
  const active = activeRuntime(await providerResult(
    input,
    `/workers/scripts/${encodeURIComponent(input.workerName)}/deployments`,
    { method: 'GET' },
  ));
  const version = await providerResult(
    input,
    `/workers/workers/${String(worker.id)}/versions/${active.versionId}`,
    { method: 'GET' },
  );
  if (!isRecord(version) || version.id !== active.versionId) conflict();
  const bindings = currentBindings(version);
  validateRuntimeBindings(input, management, bindings, identity);
  return Object.freeze({
    active,
    bindings,
    worker: Object.freeze({
      kind: 'worker' as const,
      accountId: input.accountId,
      workerName: input.workerName,
      workerId: String(worker.id),
    }),
  });
}

async function proveCurrentRuntime(
  input: SourceActionRelayInput,
  management: URL,
  identity: ExactReleaseBundleIdentity,
  directRelease: Awaited<ReturnType<typeof adaptVerifiedReleaseBundleForWorkerDirectUpload>>,
): Promise<ActiveWorkerVersionProof> {
  const seed = await readCurrentRuntimeSeed(input, management, identity);
  let proof: ActiveWorkerVersionProof;
  try {
    const prepared = await prepareVerifiedWorkerRelease({
      accountId: input.accountId,
      workerName: input.workerName,
      release: directRelease,
      plainTextBindings: seed.bindings,
      // A clean-version recovery record carries no bootstrap secret. This
      // fixed valid placeholder is consumed only by the pure input adapter.
      bootstrapNonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    });
    const recovery = await prepareWorkerVersionRecoveryRecord(prepared, seed.worker, 'clean');
    proof = await proveActiveWorkerVersionRecovery(recovery, {
      accessToken: input.accessToken,
      transport: (request: Request) => input.transport(request),
    });
  } catch {
    conflict();
  }
  if (proof.version.versionId !== seed.active.versionId ||
      proof.deployment.deploymentId !== seed.active.deploymentId) conflict();
  return proof;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value as Record<string, unknown>).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`
    )).join(',')}}`;
  }
  invalid();
}

async function signature(actionKey: string, body: string): Promise<string> {
  const keyBytes = base64UrlDecode(actionKey);
  const ownedKey = new Uint8Array(keyBytes.byteLength);
  ownedKey.set(keyBytes);
  try {
    const key = await crypto.subtle.importKey(
      'raw', ownedKey.buffer, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
    );
    const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body)));
    try {
      return `sha256=${[...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`;
    } finally { digest.fill(0); }
  } finally { keyBytes.fill(0); ownedKey.fill(0); }
}

function actionUrl(input: SourceActionRelayInput): URL {
  return new URL(
    `https://${input.workerName}.${input.workersSubdomain}.workers.dev/__ankka/source-action`,
  );
}

async function awaitCustomerRoute(input: SourceActionRelayInput): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      const response = await input.transport(actionUrl(input), { method: 'HEAD', redirect: 'manual' });
      if (response.status === 204 && response.headers.get('x-ankka-source-action') === 'ready') return;
      await response.body?.cancel();
    } catch {
      // The edge can lag the verified setting briefly.
    }
    await new Promise<void>((resolve) => setTimeout(resolve, 250));
  }
  throw new DeployError(504, 'oauth_exchange_failed', 'customer_action_route_timeout');
}

async function submitCustomerAction(
  input: SourceActionRelayInput,
  now: number,
): Promise<void> {
  const body = canonicalJson({
    schemaVersion: 1,
    actionId: input.actionId,
    actionKey: input.actionKey,
    actorEmail: input.actorEmail,
    accountId: input.accountId,
    issuedAt: now,
    expiresAt: input.expiresAt,
    cloudflareAccessToken: input.accessToken,
  });
  const response = await input.transport(actionUrl(input), {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      'x-ankka-source-action-signature': await signature(input.actionKey, body),
    },
    body,
    redirect: 'manual',
  });
  if (response.status !== 200 || response.redirected) {
    await response.body?.cancel();
    throw new DeployError(409, 'session_conflict');
  }
  const serialized = await readBoundedText(response, 'session_conflict', MAX_CUSTOMER_RESPONSE_BYTES);
  let result: unknown;
  try { result = JSON.parse(serialized); } catch { throw new DeployError(409, 'session_conflict'); }
  if (!result || typeof result !== 'object' || Array.isArray(result)) throw new DeployError(409, 'session_conflict');
  const record = result as Record<string, unknown>;
  if (record.schemaVersion !== 1 || record.actionId !== input.actionId || record.status !== 'succeeded') {
    throw new DeployError(409, 'session_conflict');
  }
}

export async function relaySourceAction(input: SourceActionRelayInput): Promise<SourceActionRelayResult> {
  const now = input.now?.() ?? Date.now();
  const management = validate(input, now);
  let identity: ExactReleaseBundleIdentity;
  let directRelease: Awaited<ReturnType<typeof adaptVerifiedReleaseBundleForWorkerDirectUpload>>;
  try {
    identity = parseExactReleaseBundleIdentity(input.releaseIdentity);
    assertExactReleaseBundleIdentity(input.releaseBundle, identity);
    directRelease = await adaptVerifiedReleaseBundleForWorkerDirectUpload(input.releaseBundle);
    if (directRelease.release !== identity.release ||
        directRelease.artifactSha256 !== identity.artifactSha256) conflict();
  } catch (error) {
    if (error instanceof DeployError && error.code === 'session_conflict') throw error;
    conflict();
  }
  let enabled = false;
  let operationError: unknown = null;
  try {
    await verifyAccountSubdomain(input);
    await verifyManagementDomain(input, management);
    await readSubdomainState(input, false);
    const before = await proveCurrentRuntime(input, management, identity, directRelease);
    // From this point onward an ambiguous provider response can mean the route
    // was enabled. Always execute and verify the compensating disable.
    enabled = true;
    await setSubdomainState(input, true);
    await awaitCustomerRoute(input);
    // The route wait is a race window. Re-prove the exact signed module bytes,
    // full binding set, and active deployment before the credential-bearing
    // request, and reject even another equivalent version/deployment ID.
    const after = await proveCurrentRuntime(input, management, identity, directRelease);
    if (after.version.versionId !== before.version.versionId ||
        after.deployment.deploymentId !== before.deployment.deploymentId) conflict();
    await submitCustomerAction(input, now);
  } catch (error) {
    operationError = error;
  } finally {
    if (enabled) {
      try { await setSubdomainState(input, false); } catch {
        operationError = new DeployError(409, 'session_conflict');
      }
    }
  }
  if (operationError) throw operationError;
  management.searchParams.set('sourceAction', input.actionId);
  return Object.freeze({
    schemaVersion: 1,
    actionId: input.actionId,
    status: 'succeeded',
    managementUrl: management.toString(),
  });
}
