import { CLOUDFLARE_API_ORIGIN } from './constants';
import { base64UrlDecode, base64UrlEncode } from './crypto';
import { DeployError } from './errors';
import {
  prepareAssetBucketMutation,
  prepareAssetUploadSessionMutation,
  prepareVerifiedWorkerRelease,
  prepareWorkerVersionMutation,
  submitAssetBucketMutation,
  submitAssetUploadSessionMutation,
  submitWorkerVersionMutation,
  verifyWorkerVersionSubmission,
  type GatewayWorkerPlainTextBindings,
  type VersionSubmission,
  type WorkerSubmission,
} from './cloudflare-worker-direct-upload';
import type { FetchTransport } from './oauth';
import { adaptVerifiedReleaseBundleForWorkerDirectUpload } from './release-direct-upload-adapter';
import type { VerifiedReleaseBundle } from './release';
import { canonicalJson } from './release-manifest';

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const ACTION_ID = /^action_[A-Za-z0-9_-]{32}$/u;
const ARTIFACT = /^sha256:[a-f0-9]{64}$/u;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const NONCE = /^[A-Za-z0-9_-]{43}$/u;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const WORKER_ID = /^[a-f0-9]{32}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const RELEASE = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const RUNTIME_PATH = '/__ankka/runtime-action';
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

type RuntimeVersion = Readonly<{
  release: string;
  artifactSha256: string;
  versionId: string | null;
}>;

export interface RuntimeUpdateRelayInput {
  readonly accessToken: string;
  readonly accountId: string;
  readonly workerName: string;
  readonly workersSubdomain: string;
  readonly managementOrigin: string;
  readonly actionId: string;
  readonly actionKey: string;
  readonly operation: 'update' | 'rollback';
  readonly from: RuntimeVersion;
  readonly to: RuntimeVersion;
  readonly expiresAt: number;
  readonly releaseBundle: VerifiedReleaseBundle;
  readonly transport: FetchTransport;
  readonly now?: () => number;
}

export interface RuntimeUpdateRelayResult {
  readonly schemaVersion: 1;
  readonly actionId: string;
  readonly operation: 'update' | 'rollback';
  readonly status: 'succeeded';
  readonly managementUrl: string;
}

interface CurrentRuntime {
  readonly worker: WorkerSubmission;
  readonly versionId: string;
  readonly deploymentId: string;
  readonly bindings: GatewayWorkerPlainTextBindings;
}

function invalid(code: 'bad_request' | 'session_conflict' = 'bad_request'): never {
  throw new DeployError(code === 'bad_request' ? 400 : 409, code);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function runtimeVersion(value: RuntimeVersion): boolean {
  return isRecord(value) && exactKeys(value, ['artifactSha256', 'release', 'versionId']) &&
    RELEASE.test(value.release) && ARTIFACT.test(value.artifactSha256) &&
    (value.versionId === null || UUID.test(value.versionId));
}

function validate(input: RuntimeUpdateRelayInput, now: number): URL {
  let management: URL;
  try { management = new URL(input.managementOrigin); } catch { invalid(); }
  if (!ACCOUNT_ID.test(input.accountId) || !WORKER_NAME.test(input.workerName) ||
      !DNS_LABEL.test(input.workersSubdomain) || !ACTION_ID.test(input.actionId) ||
      !NONCE.test(input.actionKey) || !runtimeVersion(input.from) || !runtimeVersion(input.to) ||
      (input.operation !== 'update' && input.operation !== 'rollback') ||
      !Number.isSafeInteger(input.expiresAt) || input.expiresAt <= now ||
      input.expiresAt > now + 10 * 60 * 1000 || typeof input.accessToken !== 'string' ||
      input.accessToken.length < 20 || input.accessToken.length > 16 * 1024 ||
      management.protocol !== 'https:' || management.username !== '' || management.password !== '' ||
      management.port !== '' || management.pathname !== '/' || management.search !== '' || management.hash !== '') {
    invalid();
  }
  if (input.operation === 'rollback' && !input.to.versionId) invalid();
  return management;
}

async function readJson(response: Response): Promise<unknown> {
  if (response.redirected || response.status >= 300 && response.status < 400) invalid('session_conflict');
  const declared = response.headers.get('content-length');
  if (declared !== null && (!Number.isSafeInteger(Number(declared)) || Number(declared) > MAX_RESPONSE_BYTES)) {
    invalid('session_conflict');
  }
  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES) invalid('session_conflict');
  try { return JSON.parse(text); } catch { invalid('session_conflict'); }
}

function providerUrl(accountId: string, path: string): URL {
  return new URL(`/client/v4/accounts/${accountId}${path}`, CLOUDFLARE_API_ORIGIN);
}

async function providerResult(
  input: RuntimeUpdateRelayInput,
  path: string,
  init: RequestInit = {},
): Promise<unknown> {
  const headers = new Headers(init.headers);
  headers.set('accept', 'application/json');
  headers.set('authorization', `Bearer ${input.accessToken}`);
  if (init.body) headers.set('content-type', 'application/json');
  const response = await input.transport(providerUrl(input.accountId, path), {
    ...init, headers, redirect: 'manual',
  });
  const value = await readJson(response);
  if (!response.ok || !isRecord(value) || value.success !== true || !Object.hasOwn(value, 'result')) {
    invalid('session_conflict');
  }
  return value.result;
}

function activeDeployment(value: unknown): { deploymentId: string; versionId: string } {
  if (!isRecord(value) || !exactKeys(value, ['deployments']) || !Array.isArray(value.deployments) ||
      value.deployments.length < 1 || value.deployments.length > 1_000) invalid('session_conflict');
  const active = value.deployments[0];
  if (!isRecord(active) || !UUID.test(String(active.id)) || !Array.isArray(active.versions) ||
      active.versions.length !== 1 || !isRecord(active.versions[0]) ||
      active.versions[0].percentage !== 100 || !UUID.test(String(active.versions[0].version_id))) {
    invalid('session_conflict');
  }
  return { deploymentId: String(active.id), versionId: String(active.versions[0].version_id) };
}

function exactCurrentBindings(value: unknown): GatewayWorkerPlainTextBindings {
  if (!isRecord(value) || !Array.isArray(value.bindings) || value.bindings.length !== BINDING_NAMES.length + 2 ||
      value.main_module !== 'index.js' || value.compatibility_date !== '2026-08-08' ||
      Object.hasOwn(value, 'migrations') || Object.hasOwn(value, 'migration_tag')) invalid('session_conflict');
  const bindings = new Map<string, Record<string, unknown>>();
  for (const binding of value.bindings) {
    if (!isRecord(binding) || typeof binding.name !== 'string' || bindings.has(binding.name)) invalid('session_conflict');
    bindings.set(binding.name, binding);
  }
  const admin = bindings.get('ADMIN_STATE');
  const assets = bindings.get('ASSETS');
  if (!admin || admin.type !== 'durable_object_namespace' || admin.class_name !== 'AdminState' ||
      !assets || !exactKeys(assets, ['name', 'type']) || assets.type !== 'assets') invalid('session_conflict');
  const output = {} as Record<(typeof BINDING_NAMES)[number], string>;
  for (const name of BINDING_NAMES) {
    const binding = bindings.get(name);
    if (!binding || !exactKeys(binding, ['name', 'text', 'type']) || binding.type !== 'plain_text' ||
        typeof binding.text !== 'string' || binding.text.length < 1 || binding.text.length > 4_096) {
      invalid('session_conflict');
    }
    output[name] = binding.text;
  }
  return Object.freeze(output);
}

async function inspectCurrent(input: RuntimeUpdateRelayInput): Promise<CurrentRuntime> {
  const worker = await providerResult(input, `/workers/workers/${encodeURIComponent(input.workerName)}`);
  if (!isRecord(worker) || worker.name !== input.workerName || !WORKER_ID.test(String(worker.id)) ||
      !Array.isArray(worker.tags) || !worker.tags.includes('ankka-mcp-gateway')) invalid('session_conflict');
  const deployment = activeDeployment(await providerResult(
    input, `/workers/scripts/${encodeURIComponent(input.workerName)}/deployments`,
  ));
  const version = await providerResult(
    input, `/workers/workers/${String(worker.id)}/versions/${deployment.versionId}`,
  );
  if (!isRecord(version) || version.id !== deployment.versionId) invalid('session_conflict');
  const bindings = exactCurrentBindings(version);
  if (bindings.ANKKA_GATEWAY_RELEASE !== input.from.release ||
      bindings.ANKKA_GATEWAY_RELEASE_SHA256 !== input.from.artifactSha256 ||
      bindings.CLOUDFLARE_ACCOUNT_ID !== input.accountId ||
      bindings.ANKKA_WORKER_NAME !== input.workerName ||
      bindings.ANKKA_WORKERS_SUBDOMAIN !== input.workersSubdomain ||
      `https://${bindings.ANKKA_MANAGEMENT_HOSTNAME}` !== input.managementOrigin ||
      bindings.ANKKA_UPDATE_CHANNEL !== input.releaseBundle.channel ||
      bindings.ANKKA_UPDATE_KEY_ID !== input.releaseBundle.keyId ||
      bindings.ANKKA_UPDATE_PUBLIC_KEY !== input.releaseBundle.publicKey) invalid('session_conflict');
  return Object.freeze({
    worker: Object.freeze({
      kind: 'worker', accountId: input.accountId, workerName: input.workerName, workerId: String(worker.id),
    }),
    versionId: deployment.versionId,
    deploymentId: deployment.deploymentId,
    bindings,
  });
}

function subdomainState(value: unknown, expected: boolean): void {
  const state = { enabled: expected, previews_enabled: false };
  if (!isRecord(value) || canonicalJson(value) !== canonicalJson(state)) {
    invalid('session_conflict');
  }
}

async function readSubdomain(input: RuntimeUpdateRelayInput, expected: boolean): Promise<void> {
  subdomainState(await providerResult(
    input,
    `/workers/scripts/${encodeURIComponent(input.workerName)}/subdomain`,
  ), expected);
}

async function verifyAccountSubdomain(input: RuntimeUpdateRelayInput): Promise<void> {
  const value = await providerResult(input, '/workers/subdomain');
  if (!isRecord(value) || !exactKeys(value, ['subdomain']) ||
      value.subdomain !== input.workersSubdomain) invalid('session_conflict');
}

async function verifyManagementDomain(
  input: RuntimeUpdateRelayInput,
  management: URL,
): Promise<void> {
  const query = new URLSearchParams({
    hostname: management.hostname,
    page: '1',
    per_page: '50',
  });
  const value = await providerResult(input, `/workers/domains?${query.toString()}`);
  if (!Array.isArray(value) || value.length !== 1 || !isRecord(value[0])) {
    invalid('session_conflict');
  }
  const domain = value[0];
  if (domain.hostname !== management.hostname || domain.service !== input.workerName ||
      (domain.environment !== undefined && domain.environment !== 'production')) {
    invalid('session_conflict');
  }
}

async function setSubdomain(input: RuntimeUpdateRelayInput, enabled: boolean): Promise<void> {
  const expected = { enabled, previews_enabled: false };
  const result = await providerResult(input, `/workers/scripts/${encodeURIComponent(input.workerName)}/subdomain`, {
    method: 'POST', body: JSON.stringify(expected),
  });
  subdomainState(result, enabled);
  await readSubdomain(input, enabled);
}

function runtimeUrl(input: RuntimeUpdateRelayInput): URL {
  return new URL(`https://${input.workerName}.${input.workersSubdomain}.workers.dev${RUNTIME_PATH}`);
}

async function awaitRuntimeRoute(input: RuntimeUpdateRelayInput): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      const response = await input.transport(runtimeUrl(input), { method: 'HEAD', redirect: 'manual' });
      if (response.status === 204 && response.headers.get('x-ankka-runtime-action') === 'ready') return;
      await response.body?.cancel();
    } catch { /* Edge propagation can lag briefly. */ }
    await new Promise<void>((resolve) => setTimeout(resolve, 250));
  }
  throw new DeployError(504, 'oauth_exchange_failed', 'customer_runtime_route_timeout');
}

async function hmac(actionKey: string, body: string): Promise<string> {
  const decoded = base64UrlDecode(actionKey);
  const keyBytes = new Uint8Array(decoded.byteLength);
  keyBytes.set(decoded);
  try {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body)));
    try { return `sha256=${[...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`; }
    finally { digest.fill(0); }
  } finally { decoded.fill(0); keyBytes.fill(0); }
}

async function control(
  input: RuntimeUpdateRelayInput,
  command: Record<string, unknown>,
  versionOverride?: string,
): Promise<Response> {
  const body = canonicalJson({
    schemaVersion: 1,
    actionId: input.actionId,
    actionKey: input.actionKey,
    operation: input.operation,
    issuedAt: input.now?.() ?? Date.now(),
    expiresAt: input.expiresAt,
    ...command,
  });
  const headers = new Headers({
    accept: 'application/json',
    'content-type': 'application/json',
    'x-ankka-runtime-action-signature': await hmac(input.actionKey, body),
  });
  if (versionOverride) {
    headers.set('Cloudflare-Workers-Version-Overrides', `${input.workerName}="${versionOverride}"`);
  }
  return input.transport(runtimeUrl(input), { method: 'POST', headers, body, redirect: 'manual' });
}

async function requireControl(input: RuntimeUpdateRelayInput, command: Record<string, unknown>): Promise<void> {
  const response = await control(input, command);
  if (response.status !== 200 || response.redirected) {
    await response.body?.cancel();
    invalid('session_conflict');
  }
  await response.body?.cancel();
}

async function progress(
  input: RuntimeUpdateRelayInput,
  stage: string,
  fromVersionId: string | null,
  toVersionId: string | null,
): Promise<void> {
  await requireControl(input, { command: 'progress', stage, fromVersionId, toVersionId });
}

async function probe(input: RuntimeUpdateRelayInput, versionId?: string): Promise<void> {
  const response = await control(input, {
    command: 'probe', targetRelease: input.to.release, targetArtifactSha256: input.to.artifactSha256,
  }, versionId);
  if (response.status !== 204 || response.redirected || response.headers.get('x-ankka-runtime-action') !== 'ready') {
    await response.body?.cancel();
    invalid('session_conflict');
  }
}

async function rawDeployment(
  input: RuntimeUpdateRelayInput,
  versions: readonly { readonly version_id: string; readonly percentage: number }[],
  message: string,
): Promise<string> {
  const result = await providerResult(input, `/workers/scripts/${encodeURIComponent(input.workerName)}/deployments`, {
    method: 'POST',
    body: JSON.stringify({ annotations: { 'workers/message': message }, strategy: 'percentage', versions }),
  });
  if (!isRecord(result) || !UUID.test(String(result.id))) invalid('session_conflict');
  return String(result.id);
}

async function verifyRawActive(
  input: RuntimeUpdateRelayInput,
  deploymentId: string,
  versions: readonly { readonly version_id: string; readonly percentage: number }[],
): Promise<void> {
  const result = await providerResult(input, `/workers/scripts/${encodeURIComponent(input.workerName)}/deployments`);
  if (!isRecord(result) || !Array.isArray(result.deployments) || result.deployments.length < 1) {
    invalid('session_conflict');
  }
  const active = result.deployments[0];
  if (!isRecord(active) || active.id !== deploymentId || !Array.isArray(active.versions) ||
      canonicalJson(active.versions) !== canonicalJson(versions.map((version) => ({
        percentage: version.percentage, version_id: version.version_id,
      })))) invalid('session_conflict');
}

async function createCandidate(
  input: RuntimeUpdateRelayInput,
  current: CurrentRuntime,
): Promise<VersionSubmission> {
  const direct = await adaptVerifiedReleaseBundleForWorkerDirectUpload(input.releaseBundle);
  if (direct.release !== input.to.release || `sha256:${direct.artifactSha256}` !== input.to.artifactSha256 ||
      input.releaseBundle.keyId !== current.bindings.ANKKA_UPDATE_KEY_ID ||
      input.releaseBundle.publicKey !== current.bindings.ANKKA_UPDATE_PUBLIC_KEY) invalid('session_conflict');
  const random = new Uint8Array(32);
  crypto.getRandomValues(random);
  const bootstrapNonce = base64UrlEncode(random);
  random.fill(0);
  const prepared = await prepareVerifiedWorkerRelease({
    accountId: input.accountId,
    workerName: input.workerName,
    release: direct,
    plainTextBindings: Object.freeze({
      ...current.bindings,
      ANKKA_GATEWAY_RELEASE: input.to.release,
      ANKKA_GATEWAY_RELEASE_SHA256: input.to.artifactSha256,
    }),
    bootstrapNonce,
  });
  const call = {
    accessToken: input.accessToken,
    transport: (request: Request) => input.transport(request),
  };
  const sessionIntent = await prepareAssetUploadSessionMutation(prepared);
  const session = await submitAssetUploadSessionMutation(sessionIntent, call);
  let completionJwt = session.uploadJwt;
  for (let index = 0; index < session.buckets.length; index += 1) {
    const intent = await prepareAssetBucketMutation(session, index);
    const submitted = await submitAssetBucketMutation(intent, session, prepared, call);
    if (submitted.isFinal) completionJwt = submitted.completionJwt;
  }
  await progress(input, 'assets_uploaded', current.versionId, null);
  const mutation = await prepareWorkerVersionMutation(prepared, current.worker, completionJwt, 'clean');
  const submitted = await submitWorkerVersionMutation(mutation.ephemeral, mutation.recovery, call);
  await verifyWorkerVersionSubmission(mutation.recovery, submitted, call);
  return submitted;
}

export async function relayRuntimeUpdate(input: RuntimeUpdateRelayInput): Promise<RuntimeUpdateRelayResult> {
  const now = input.now?.() ?? Date.now();
  const management = validate(input, now);
  let routeMayBeEnabled = false;
  let oldVersionId: string | null = null;
  let targetVersionId: string | null = null;
  let staged = false;
  let controlMayBeStarted = false;
  let operationError: unknown = null;
  let compensationConfirmed = false;
  try {
    await verifyAccountSubdomain(input);
    await verifyManagementDomain(input, management);
    await readSubdomain(input, false);
    const current = await inspectCurrent(input);
    // Set before the mutating call: an ambiguous provider response may mean the
    // route changed and therefore still requires the compensating disable.
    routeMayBeEnabled = true;
    await setSubdomain(input, true);
    await awaitRuntimeRoute(input);
    controlMayBeStarted = true;
    await requireControl(input, { command: 'begin' });
    oldVersionId = current.versionId;
    await progress(input, 'current_verified', oldVersionId, input.to.versionId);
    if (input.operation === 'update') {
      const candidate = await createCandidate(input, current);
      targetVersionId = candidate.versionId;
      await progress(input, 'candidate_created', oldVersionId, targetVersionId);
    } else {
      targetVersionId = input.to.versionId;
    }
    if (!targetVersionId || targetVersionId === oldVersionId) invalid('session_conflict');
    const stageVersions = [
      { version_id: oldVersionId, percentage: 100 },
      { version_id: targetVersionId, percentage: 0 },
    ] as const;
    const stagedId = await rawDeployment(input, stageVersions, `ankka-runtime-stage:${input.actionId}`);
    staged = true;
    await verifyRawActive(input, stagedId, stageVersions);
    await progress(input, 'candidate_staged', oldVersionId, targetVersionId);
    await probe(input, targetVersionId);
    await progress(input, 'candidate_verified', oldVersionId, targetVersionId);
    const activeVersions = [{ version_id: targetVersionId, percentage: 100 }] as const;
    const activeId = await rawDeployment(input, activeVersions, `ankka-runtime-activate:${input.actionId}`);
    await verifyRawActive(input, activeId, activeVersions);
    await progress(input, 'activated', oldVersionId, targetVersionId);
    await probe(input);
    await progress(input, 'health_verified', oldVersionId, targetVersionId);
    await requireControl(input, { command: 'complete', fromVersionId: oldVersionId, toVersionId: targetVersionId });
  } catch (error) {
    operationError = error;
    if (staged && oldVersionId) {
      try {
        const versions = [{ version_id: oldVersionId, percentage: 100 }] as const;
        const deploymentId = await rawDeployment(input, versions, `ankka-runtime-compensate:${input.actionId}`);
        await verifyRawActive(input, deploymentId, versions);
        await progress(input, 'rolled_back', oldVersionId, targetVersionId);
        compensationConfirmed = true;
      } catch {
        compensationConfirmed = false;
      }
    } else {
      compensationConfirmed = true;
    }
    if (controlMayBeStarted) {
      try {
        await requireControl(input, {
          command: 'fail',
          failureCode: compensationConfirmed ? 'runtime_action_failed' : 'runtime_action_recovery_required',
          recoveryRequired: !compensationConfirmed,
        });
      } catch { /* Preserve the provider failure. */ }
    }
  } finally {
    if (routeMayBeEnabled) {
      try { await setSubdomain(input, false); } catch {
        operationError = new DeployError(409, 'session_conflict');
      }
    }
  }
  if (operationError) throw operationError;
  management.searchParams.set('runtimeAction', input.actionId);
  return Object.freeze({
    schemaVersion: 1,
    actionId: input.actionId,
    operation: input.operation,
    status: 'succeeded',
    managementUrl: management.toString(),
  });
}
