import * as v from 'valibot';

import { boundaryValueSchema, type BoundaryValue } from './boundary';
import { canonicalJson } from './canonical-json';
import {
  parseAccountWorkersSubdomain,
  parseActiveGatewayRuntime,
  parseCurrentGatewayVersion,
  parseCurrentGatewayWorker,
  parseGatewayRuntimeBindings,
  parseGatewayWorkerDomains,
  parseGatewayWorkerSubdomainState,
} from './cloudflare-gateway-runtime-state';
import { CLOUDFLARE_API_ORIGIN, PUBLIC_ORIGIN } from './constants';
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
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const EMAIL = /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u;
const MAX_CUSTOMER_RESPONSE_BYTES = 64 * 1024;
const providerEnvelopeSchema = v.looseObject({
  result: boundaryValueSchema,
  success: v.literal(true),
});
const customerActionResultSchema = v.looseObject({
  schemaVersion: v.literal(1),
  action: v.exactOptional(v.literal('access')),
  actionId: v.string(),
  status: v.literal('succeeded'),
});

export interface SourceActionRelayInput {
  readonly action?: 'access';
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

function validate(input: SourceActionRelayInput, now: number): URL {
  let management: URL;
  try { management = new URL(input.managementOrigin); } catch { invalid(); }
  if (!ACCOUNT_ID.test(input.accountId) || !WORKER_NAME.test(input.workerName) ||
      !DNS_LABEL.test(input.workersSubdomain) || !ACTION_ID.test(input.actionId) ||
      (input.action !== undefined && input.action !== 'access') ||
      !NONCE.test(input.actionKey) || input.actorEmail !== input.actorEmail.toLowerCase() ||
      !EMAIL.test(input.actorEmail) || !Number.isSafeInteger(input.expiresAt) || input.expiresAt <= now ||
      input.expiresAt > now + 10 * 60 * 1000 || !v.is(v.string(), input.accessToken) ||
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
    if (response.redirected || response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new DeployError(502, 'oauth_grant_invalid');
    }
    const serialized = await readBoundedText(response, 'oauth_grant_invalid', MAX_CUSTOMER_RESPONSE_BYTES);
    if (!response.ok) throw new DeployError(502, 'oauth_grant_invalid');
    try {
      const envelope = v.safeParse(providerEnvelopeSchema, JSON.parse(serialized));
      if (!envelope.success) throw new DeployError(502, 'oauth_grant_invalid');
      return envelope.output.result;
    } catch (error) {
      if (error instanceof DeployError) throw error;
      throw new DeployError(502, 'oauth_grant_invalid');
    }
  }, 'oauth_grant_invalid');
}

function subdomainState(value: BoundaryValue, expected: boolean): void {
  const result = parseGatewayWorkerSubdomainState(value);
  if (!result || result.enabled !== expected) {
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
  if (parseAccountWorkersSubdomain(value) !== input.workersSubdomain) {
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
  const domains = parseGatewayWorkerDomains(value);
  if (!domains || domains.length !== 1) throw new DeployError(409, 'session_conflict');
  const domain = domains[0];
  if (!domain) throw new DeployError(409, 'session_conflict');
  if (domain.hostname !== management.hostname || domain.service !== input.workerName ||
      (domain.environment !== undefined && domain.environment !== 'production')) {
    throw new DeployError(409, 'session_conflict');
  }
}

interface ActiveRuntime {
  readonly deploymentId: string;
  readonly versionId: string;
}

function activeRuntime(value: BoundaryValue): ActiveRuntime {
  const active = parseActiveGatewayRuntime(value);
  if (!active) conflict();
  return active;
}

function currentBindings(value: BoundaryValue): GatewayWorkerPlainTextBindings {
  const bindings = parseGatewayRuntimeBindings(value);
  if (!bindings) conflict();
  return bindings;
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
  const currentWorker = parseCurrentGatewayWorker(worker);
  if (!currentWorker || currentWorker.name !== input.workerName ||
      !currentWorker.tags.includes('ankka-mcp-gateway')) conflict();
  const active = activeRuntime(await providerResult(
    input,
    `/workers/scripts/${encodeURIComponent(input.workerName)}/deployments`,
    { method: 'GET' },
  ));
  const version = await providerResult(
    input,
    `/workers/workers/${currentWorker.id}/versions/${active.versionId}`,
    { method: 'GET' },
  );
  const currentVersion = parseCurrentGatewayVersion(version);
  if (!currentVersion || currentVersion.id !== active.versionId) conflict();
  const bindings = currentBindings(version);
  validateRuntimeBindings(input, management, bindings, identity);
  return Object.freeze({
    active,
    bindings,
    worker: Object.freeze({
      kind: 'worker' as const,
      accountId: input.accountId,
      workerName: input.workerName,
      workerId: currentWorker.id,
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
  const claim = {
    schemaVersion: 1,
    actionId: input.actionId,
    actionKey: input.actionKey,
    actorEmail: input.actorEmail,
    accountId: input.accountId,
    issuedAt: now,
    expiresAt: input.expiresAt,
    cloudflareAccessToken: input.accessToken,
  };
  const body = canonicalJson(input.action === 'access' ? { ...claim, action: 'access' } : claim);
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
  let result: v.SafeParseResult<typeof customerActionResultSchema>;
  try {
    result = v.safeParse(customerActionResultSchema, JSON.parse(serialized));
  } catch {
    throw new DeployError(409, 'session_conflict');
  }
  if (!result.success || result.output.actionId !== input.actionId || result.output.action !== input.action) {
    throw new DeployError(409, 'session_conflict');
  }
}

function operationFailure<Value>(error: Value): Error {
  return error instanceof Error ? error : new DeployError(409, 'session_conflict');
}

export async function relaySourceAction(input: SourceActionRelayInput): Promise<SourceActionRelayResult> {
  const now = input.now?.() ?? Date.now();
  const management = validate(input, now);
  let identity: ExactReleaseBundleIdentity;
  let directRelease: Awaited<ReturnType<typeof adaptVerifiedReleaseBundleForWorkerDirectUpload>>;
  try {
    identity = parseExactReleaseBundleIdentity(input.releaseIdentity);
    if (identity.controlPlaneOrigin !== PUBLIC_ORIGIN) conflict();
    assertExactReleaseBundleIdentity(input.releaseBundle, identity);
    directRelease = await adaptVerifiedReleaseBundleForWorkerDirectUpload(input.releaseBundle);
    if (directRelease.release !== identity.release ||
        directRelease.artifactSha256 !== identity.artifactSha256) conflict();
  } catch (error) {
    if (error instanceof DeployError && error.code === 'session_conflict') throw error;
    conflict();
  }
  let enabled = false;
  let operationError: Error | null = null;
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
    operationError = operationFailure(error);
  } finally {
    if (enabled) {
      try { await setSubdomainState(input, false); } catch {
        operationError = new DeployError(409, 'session_conflict');
      }
    }
  }
  if (operationError) throw operationError;
  if (input.action === 'access') management.pathname = '/team';
  management.searchParams.set(input.action === 'access' ? 'accessAction' : 'sourceAction', input.actionId);
  return Object.freeze({
    schemaVersion: 1,
    actionId: input.actionId,
    status: 'succeeded',
    managementUrl: management.toString(),
  });
}
