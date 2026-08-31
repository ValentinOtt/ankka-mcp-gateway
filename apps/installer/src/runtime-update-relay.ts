import * as v from 'valibot';

import {
  boundaryObjectSchema,
  boundaryValueSchema,
  type BoundaryObject,
  type BoundaryValue,
  type JsonObject,
} from './boundary';
import { CLOUDFLARE_API_ORIGIN, PUBLIC_ORIGIN } from './constants';
import { base64UrlDecode, base64UrlEncode } from './crypto';
import { DeployError } from './errors';
import { readBoundedText, withDeadline } from './http';
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
const MAX_CONTROL_ERROR_BYTES = 1_024;
// Version creation includes provider-side compilation. Give this one POST a
// bounded allowance beyond the shared 10s request limit; never retry it here.
const VERSION_CREATE_TIMEOUT_MS = 30_000;
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
const runtimeVersionSchema = v.strictObject({
  artifactSha256: v.string(),
  release: v.string(),
  versionId: v.nullable(v.string()),
});
const providerResponseSchema = v.looseObject({
  result: boundaryValueSchema,
  success: v.literal(true),
});
const activeDeploymentsSchema = v.strictObject({
  deployments: v.array(v.looseObject({
    id: v.string(),
    versions: v.array(v.looseObject({
      percentage: v.number(),
      version_id: v.string(),
    })),
  })),
});
const currentWorkerSchema = v.looseObject({
  id: v.string(),
  name: v.string(),
  tags: v.array(v.string()),
});
const currentVersionSchema = v.looseObject({
  id: v.string(),
});
const currentBindingsSchema = v.looseObject({
  bindings: v.array(boundaryObjectSchema),
  compatibility_date: v.string(),
  main_module: v.string(),
});
const namedBindingSchema = v.looseObject({ name: v.string() });
const adminStateBindingSchema = v.looseObject({
  class_name: v.string(),
  name: v.string(),
  type: v.string(),
});
const assetsBindingSchema = v.strictObject({ name: v.string(), type: v.string() });
const plainTextBindingSchema = v.strictObject({
  name: v.string(),
  text: v.string(),
  type: v.string(),
});
const teamManagementBindingSchema = v.strictObject({
  name: v.literal('ANKKA_TEAM_MANAGEMENT_TOKEN'),
  type: v.literal('secret_text'),
});
const subdomainStateSchema = v.strictObject({
  enabled: v.boolean(),
  previews_enabled: v.literal(false),
});
const accountSubdomainSchema = v.strictObject({ subdomain: v.string() });
const workerDomainsSchema = v.array(v.looseObject({
  environment: v.optional(v.string()),
  hostname: v.string(),
  service: v.string(),
}));
const deploymentResultSchema = v.looseObject({ id: v.string() });
const controlErrorSchema = v.strictObject({
  schemaVersion: v.literal(1),
  error: v.picklist([
    'runtime_action_rejected', 'runtime_action_conflict', 'runtime_updates_unavailable',
    'runtime_probe_version_mismatch', 'team_action_conflict',
  ]),
});
const CONTROL_ERROR_DETAILS = Object.freeze({
  runtime_action_rejected: 'action_rejected',
  runtime_action_conflict: 'action_conflict',
  runtime_updates_unavailable: 'updates_unavailable',
  runtime_probe_version_mismatch: 'version_mismatch',
  team_action_conflict: 'team_conflict',
} as const);
type RuntimeProgressStage =
  | 'current_verified' | 'assets_uploaded' | 'candidate_created' | 'candidate_staged'
  | 'candidate_verified' | 'activated' | 'health_verified' | 'rolled_back';
type ControlPhase = 'begin' | 'complete' | 'fail' | 'candidate_probe' | 'active_probe'
  | `progress_${RuntimeProgressStage}`;
type RelayPhase = 'preflight' | 'route_enable' | 'route_wait' | 'candidate_upload'
  | 'candidate_stage' | 'candidate_stage_verify' | 'candidate_activate' | 'candidate_active_verify';

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
  readonly hasTeamManagementBinding: boolean;
}

interface ActiveDeployment {
  readonly deploymentId: string;
  readonly versionId: string;
}

function invalid(code: 'bad_request' | 'session_conflict' = 'bad_request'): never {
  throw new DeployError(code === 'bad_request' ? 400 : 409, code);
}

function runtimeVersion(value: RuntimeVersion): boolean {
  const result = v.safeParse(runtimeVersionSchema, value);
  return result.success && RELEASE.test(result.output.release) &&
    ARTIFACT.test(result.output.artifactSha256) &&
    (result.output.versionId === null || UUID.test(result.output.versionId));
}

function validate(input: RuntimeUpdateRelayInput, now: number): URL {
  let management: URL;
  try { management = new URL(input.managementOrigin); } catch { invalid(); }
  if (!ACCOUNT_ID.test(input.accountId) || !WORKER_NAME.test(input.workerName) ||
      !DNS_LABEL.test(input.workersSubdomain) || !ACTION_ID.test(input.actionId) ||
      !NONCE.test(input.actionKey) || !runtimeVersion(input.from) || !runtimeVersion(input.to) ||
      (input.operation !== 'update' && input.operation !== 'rollback') ||
      !Number.isSafeInteger(input.expiresAt) || input.expiresAt <= now ||
      input.expiresAt > now + 10 * 60 * 1000 ||
      input.accessToken.length < 20 || input.accessToken.length > 16 * 1024 ||
      management.protocol !== 'https:' || management.username !== '' || management.password !== '' ||
      management.port !== '' || management.pathname !== '/' || management.search !== '' || management.hash !== '') {
    invalid();
  }
  if (input.operation === 'rollback' && !input.to.versionId) invalid();
  return management;
}

async function readJson(response: Response): Promise<BoundaryValue> {
  if (response.redirected || response.status >= 300 && response.status < 400) invalid('session_conflict');
  const declared = response.headers.get('content-length');
  if (declared !== null && (!Number.isSafeInteger(Number(declared)) || Number(declared) > MAX_RESPONSE_BYTES)) {
    invalid('session_conflict');
  }
  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES) invalid('session_conflict');
  try {
    const result = v.safeParse(boundaryValueSchema, JSON.parse(text));
    if (!result.success) invalid('session_conflict');
    return result.output;
  } catch {
    invalid('session_conflict');
  }
}

function providerUrl(accountId: string, path: string): URL {
  return new URL(`/client/v4/accounts/${accountId}${path}`, CLOUDFLARE_API_ORIGIN);
}

async function providerResult(
  input: RuntimeUpdateRelayInput,
  path: string,
  init: RequestInit = {},
): Promise<BoundaryValue> {
  const headers = new Headers(init.headers);
  headers.set('accept', 'application/json');
  headers.set('authorization', `Bearer ${input.accessToken}`);
  if (init.body) headers.set('content-type', 'application/json');
  const response = await input.transport(providerUrl(input.accountId, path), {
    ...init, headers, redirect: 'manual',
  });
  const value = await readJson(response);
  const result = v.safeParse(providerResponseSchema, value);
  if (!response.ok || !result.success) invalid('session_conflict');
  return result.output.result;
}

function activeDeployment(value: BoundaryValue): ActiveDeployment {
  const result = v.safeParse(activeDeploymentsSchema, value);
  if (!result.success || result.output.deployments.length < 1 ||
      result.output.deployments.length > 1_000) invalid('session_conflict');
  const active = result.output.deployments.at(0);
  const version = active?.versions.length === 1 ? active.versions.at(0) : undefined;
  if (active === undefined || version === undefined || !UUID.test(active.id) ||
      version.percentage !== 100 || !UUID.test(version.version_id)) {
    invalid('session_conflict');
  }
  return { deploymentId: active.id, versionId: version.version_id };
}

function exactCurrentBindings(value: BoundaryValue): Readonly<{
  bindings: GatewayWorkerPlainTextBindings;
  hasTeamManagementBinding: boolean;
}> {
  const result = v.safeParse(currentBindingsSchema, value);
  if (!result.success || ![BINDING_NAMES.length + 2, BINDING_NAMES.length + 3].includes(result.output.bindings.length) ||
      result.output.main_module !== 'index.js' || result.output.compatibility_date !== '2026-08-08' ||
      Object.hasOwn(result.output, 'migrations') || Object.hasOwn(result.output, 'migration_tag')) {
    invalid('session_conflict');
  }
  const bindings = new Map<string, BoundaryObject>();
  for (const binding of result.output.bindings) {
    const named = v.safeParse(namedBindingSchema, binding);
    if (!named.success || bindings.has(named.output.name)) invalid('session_conflict');
    bindings.set(named.output.name, binding);
  }
  const management = bindings.get('ANKKA_TEAM_MANAGEMENT_TOKEN');
  const hasTeamManagementBinding = management !== undefined;
  if ((hasTeamManagementBinding && !v.safeParse(teamManagementBindingSchema, management).success) ||
      bindings.size !== BINDING_NAMES.length + 2 + Number(hasTeamManagementBinding)) {
    invalid('session_conflict');
  }
  const admin = v.safeParse(adminStateBindingSchema, bindings.get('ADMIN_STATE'));
  const assets = v.safeParse(assetsBindingSchema, bindings.get('ASSETS'));
  if (!admin.success || admin.output.type !== 'durable_object_namespace' ||
      admin.output.class_name !== 'AdminState' || !assets.success || assets.output.type !== 'assets') {
    invalid('session_conflict');
  }
  const bindingText = (name: (typeof BINDING_NAMES)[number]): string => {
    const binding = bindings.get(name);
    const parsed = v.safeParse(plainTextBindingSchema, binding);
    if (!parsed.success || parsed.output.name !== name || parsed.output.type !== 'plain_text' ||
        parsed.output.text.length < 1 || parsed.output.text.length > 4_096) {
      invalid('session_conflict');
    }
    return parsed.output.text;
  };
  const plainTextBindings = Object.freeze({
    ADMIN_EMAILS: bindingText('ADMIN_EMAILS'),
    ANKKA_GATEWAY_RELEASE: bindingText('ANKKA_GATEWAY_RELEASE'),
    ANKKA_GATEWAY_RELEASE_SHA256: bindingText('ANKKA_GATEWAY_RELEASE_SHA256'),
    ANKKA_MANAGEMENT_HOSTNAME: bindingText('ANKKA_MANAGEMENT_HOSTNAME'),
    ANKKA_UPDATE_CHANNEL: bindingText('ANKKA_UPDATE_CHANNEL'),
    ANKKA_UPDATE_KEY_ID: bindingText('ANKKA_UPDATE_KEY_ID'),
    ANKKA_UPDATE_PUBLIC_KEY: bindingText('ANKKA_UPDATE_PUBLIC_KEY'),
    ANKKA_WORKERS_SUBDOMAIN: bindingText('ANKKA_WORKERS_SUBDOMAIN'),
    ANKKA_WORKER_NAME: bindingText('ANKKA_WORKER_NAME'),
    CF_ACCESS_AUD: bindingText('CF_ACCESS_AUD'),
    CF_ACCESS_ISSUER: bindingText('CF_ACCESS_ISSUER'),
    CLOUDFLARE_ACCOUNT_ID: bindingText('CLOUDFLARE_ACCOUNT_ID'),
    CLOUDFLARE_ZONE_ID: bindingText('CLOUDFLARE_ZONE_ID'),
    CLOUDFLARE_ZONE_NAME: bindingText('CLOUDFLARE_ZONE_NAME'),
    ZERO_TRUST_READY: bindingText('ZERO_TRUST_READY'),
  });
  return Object.freeze({ bindings: plainTextBindings, hasTeamManagementBinding });
}

async function inspectCurrent(input: RuntimeUpdateRelayInput): Promise<CurrentRuntime> {
  const workerResult = v.safeParse(
    currentWorkerSchema,
    await providerResult(input, `/workers/workers/${encodeURIComponent(input.workerName)}`),
  );
  if (!workerResult.success || workerResult.output.name !== input.workerName ||
      !WORKER_ID.test(workerResult.output.id) ||
      !workerResult.output.tags.includes('ankka-mcp-gateway')) invalid('session_conflict');
  const worker = workerResult.output;
  const deployment = activeDeployment(await providerResult(
    input, `/workers/scripts/${encodeURIComponent(input.workerName)}/deployments`,
  ));
  const version = await providerResult(
    input, `/workers/workers/${worker.id}/versions/${deployment.versionId}`,
  );
  const versionResult = v.safeParse(currentVersionSchema, version);
  if (!versionResult.success || versionResult.output.id !== deployment.versionId) {
    invalid('session_conflict');
  }
  const { bindings, hasTeamManagementBinding } = exactCurrentBindings(version);
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
      kind: 'worker', accountId: input.accountId, workerName: input.workerName, workerId: worker.id,
    }),
    versionId: deployment.versionId,
    deploymentId: deployment.deploymentId,
    bindings,
    hasTeamManagementBinding,
  });
}

async function verifyRollbackBindings(input: RuntimeUpdateRelayInput, current: CurrentRuntime): Promise<void> {
  // Deploying an older version can restore a rotated/removed credential or drop
  // current standing authority. Neither is part of the code-only rollback.
  if (current.hasTeamManagementBinding || !input.to.versionId) invalid('session_conflict');
  const version = await providerResult(
    input, `/workers/workers/${current.worker.workerId}/versions/${input.to.versionId}`,
  );
  const parsed = v.safeParse(currentVersionSchema, version);
  const target = exactCurrentBindings(version);
  if (!parsed.success || parsed.output.id !== input.to.versionId || target.hasTeamManagementBinding ||
      canonicalJson(target.bindings) !== canonicalJson({
        ...current.bindings,
        ANKKA_GATEWAY_RELEASE: input.to.release,
        ANKKA_GATEWAY_RELEASE_SHA256: input.to.artifactSha256,
      })) invalid('session_conflict');
}

function subdomainState(value: BoundaryValue, expected: boolean): void {
  const result = v.safeParse(subdomainStateSchema, value);
  if (!result.success || result.output.enabled !== expected) {
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
  const result = v.safeParse(accountSubdomainSchema, await providerResult(input, '/workers/subdomain'));
  if (!result.success || result.output.subdomain !== input.workersSubdomain) {
    invalid('session_conflict');
  }
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
  const result = v.safeParse(
    workerDomainsSchema,
    await providerResult(input, `/workers/domains?${query.toString()}`),
  );
  if (!result.success || result.output.length !== 1) {
    invalid('session_conflict');
  }
  const domain = result.output.at(0);
  if (domain === undefined) invalid('session_conflict');
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
  command: JsonObject,
  signal: AbortSignal,
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
  return input.transport(runtimeUrl(input), { method: 'POST', headers, body, redirect: 'manual', signal });
}

async function controlFailure(response: Response, phase: ControlPhase): Promise<never> {
  let detail: string = 'rejected';
  if (response.redirected || response.status >= 300 && response.status < 400) {
    detail = 'redirect';
    await response.body?.cancel();
  } else if (response.status >= 400 && response.status < 600 &&
      response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() === 'application/json') {
    try {
      const text = await readBoundedText(response, 'session_conflict', MAX_CONTROL_ERROR_BYTES);
      const parsed = v.safeParse(controlErrorSchema, JSON.parse(text));
      if (parsed.success) detail = CONTROL_ERROR_DETAILS[parsed.output.error];
    } catch { /* Only the exact reviewed vocabulary may leave this request. */ }
  } else {
    await response.body?.cancel();
  }
  throw new DeployError(409, 'session_conflict', `runtime_${phase}_${detail}`);
}

async function checkedControl(
  input: RuntimeUpdateRelayInput,
  command: JsonObject,
  phase: ControlPhase,
  probeResponse = false,
  versionOverride?: string,
): Promise<void> {
  try {
    await withDeadline(async (signal) => {
      for (;;) {
        signal.throwIfAborted();
        const response = await control(input, command, signal, versionOverride);
        const expected = probeResponse ? 204 : 200;
        if (response.status !== expected || response.redirected ||
            probeResponse && response.headers.get('x-ankka-runtime-action') !== 'ready') {
          try {
            await controlFailure(response, phase);
          } catch (error) {
            // Normal routing can briefly lag the verified deployment. Only this
            // exact active-probe mismatch may wait within the same 10s deadline.
            if (phase !== 'active_probe' || !probeResponse || versionOverride !== undefined ||
                response.status !== 409 || response.redirected || signal.aborted ||
                !(error instanceof DeployError) || error.reason !== 'runtime_active_probe_version_mismatch') {
              throw error;
            }
            await new Promise<void>((resolve) => {
              const finish = (): void => {
                clearTimeout(timer);
                signal.removeEventListener('abort', finish);
                resolve();
              };
              const timer = setTimeout(finish, 250);
              signal.addEventListener('abort', finish, { once: true });
              if (signal.aborted) finish();
            });
            continue;
          }
        }
        await response.body?.cancel();
        return;
      }
    }, 'session_conflict');
  } catch (error) {
    if (error instanceof DeployError && error.reason !== null) throw error;
    const detail = error instanceof DeployError && error.status === 504 ? 'timeout' : 'request_failed';
    throw new DeployError(409, 'session_conflict', `runtime_${phase}_${detail}`);
  }
}

async function requireControl(
  input: RuntimeUpdateRelayInput,
  command: JsonObject,
  phase: ControlPhase,
): Promise<void> {
  await checkedControl(input, command, phase);
}

async function progress(
  input: RuntimeUpdateRelayInput,
  stage: RuntimeProgressStage,
  fromVersionId: string | null,
  toVersionId: string | null,
): Promise<void> {
  await requireControl(input, { command: 'progress', stage, fromVersionId, toVersionId }, `progress_${stage}`);
}

async function probe(input: RuntimeUpdateRelayInput, versionId?: string): Promise<void> {
  await checkedControl(input, {
    command: 'probe', targetRelease: input.to.release, targetArtifactSha256: input.to.artifactSha256,
  }, versionId ? 'candidate_probe' : 'active_probe', true, versionId);
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
  const parsed = v.safeParse(deploymentResultSchema, result);
  if (!parsed.success || !UUID.test(parsed.output.id)) invalid('session_conflict');
  return parsed.output.id;
}

async function verifyRawActive(
  input: RuntimeUpdateRelayInput,
  deploymentId: string,
  versions: readonly { readonly version_id: string; readonly percentage: number }[],
): Promise<void> {
  const result = v.safeParse(
    activeDeploymentsSchema,
    await providerResult(input, `/workers/scripts/${encodeURIComponent(input.workerName)}/deployments`),
  );
  if (!result.success || result.output.deployments.length < 1) {
    invalid('session_conflict');
  }
  const active = result.output.deployments.at(0);
  if (active === undefined) invalid('session_conflict');
  if (active.id !== deploymentId ||
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
  const mutation = await prepareWorkerVersionMutation(
    prepared, current.worker, completionJwt, 'clean',
    current.hasTeamManagementBinding ? current.versionId : undefined,
  );
  const submitted = await submitWorkerVersionMutation(mutation.ephemeral, mutation.recovery, {
    ...call,
    timeoutMs: VERSION_CREATE_TIMEOUT_MS,
  });
  await verifyWorkerVersionSubmission(mutation.recovery, submitted, call);
  return submitted;
}

export async function relayRuntimeUpdate(input: RuntimeUpdateRelayInput): Promise<RuntimeUpdateRelayResult> {
  const now = input.now?.() ?? Date.now();
  const management = validate(input, now);
  if (input.releaseBundle.manifest.controlPlaneOrigin !== PUBLIC_ORIGIN) {
    invalid('session_conflict');
  }
  let routeMayBeEnabled = false;
  let oldVersionId: string | null = null;
  let targetVersionId: string | null = null;
  let staged = false;
  let ownedDeployment: Readonly<{
    id: string;
    versions: readonly { readonly version_id: string; readonly percentage: number }[];
  }> | null = null;
  let controlMayBeStarted = false;
  let operationError: Error | null = null;
  let compensationConfirmed = false;
  let phase: RelayPhase = 'preflight';
  try {
    await verifyAccountSubdomain(input);
    await verifyManagementDomain(input, management);
    await readSubdomain(input, false);
    const current = await inspectCurrent(input);
    if (input.operation === 'rollback') await verifyRollbackBindings(input, current);
    // Set before the mutating call: an ambiguous provider response may mean the
    // route changed and therefore still requires the compensating disable.
    routeMayBeEnabled = true;
    phase = 'route_enable';
    await setSubdomain(input, true);
    phase = 'route_wait';
    await awaitRuntimeRoute(input);
    controlMayBeStarted = true;
    await requireControl(input, { command: 'begin' }, 'begin');
    oldVersionId = current.versionId;
    await progress(input, 'current_verified', oldVersionId, input.to.versionId);
    if (input.operation === 'update') {
      phase = 'candidate_upload';
      const candidate = await createCandidate(input, current);
      targetVersionId = candidate.versionId;
      await progress(input, 'candidate_created', oldVersionId, targetVersionId);
    } else {
      targetVersionId = input.to.versionId;
    }
    if (!targetVersionId || targetVersionId === oldVersionId) invalid('session_conflict');
    // A customer secret rotation/removal creates a new deployment. Do not
    // overwrite it with the previously inspected credential version.
    await verifyRawActive(input, current.deploymentId, [{ version_id: current.versionId, percentage: 100 }]);
    const stageVersions = [
      { version_id: oldVersionId, percentage: 100 },
      { version_id: targetVersionId, percentage: 0 },
    ] as const;
    phase = 'candidate_stage';
    const stagedId = await rawDeployment(input, stageVersions, `ankka-runtime-stage:${input.actionId}`);
    staged = true;
    ownedDeployment = { id: stagedId, versions: stageVersions };
    phase = 'candidate_stage_verify';
    await verifyRawActive(input, stagedId, stageVersions);
    await progress(input, 'candidate_staged', oldVersionId, targetVersionId);
    await probe(input, targetVersionId);
    await progress(input, 'candidate_verified', oldVersionId, targetVersionId);
    const activeVersions = [{ version_id: targetVersionId, percentage: 100 }] as const;
    phase = 'candidate_activate';
    await verifyRawActive(input, stagedId, stageVersions);
    const activeId = await rawDeployment(input, activeVersions, `ankka-runtime-activate:${input.actionId}`);
    ownedDeployment = { id: activeId, versions: activeVersions };
    phase = 'candidate_active_verify';
    await verifyRawActive(input, activeId, activeVersions);
    await progress(input, 'activated', oldVersionId, targetVersionId);
    await probe(input);
    await progress(input, 'health_verified', oldVersionId, targetVersionId);
    await verifyRawActive(input, activeId, activeVersions);
    await requireControl(input, { command: 'complete', fromVersionId: oldVersionId, toVersionId: targetVersionId }, 'complete');
  } catch (error) {
    operationError = error instanceof Error
      ? error
      : new DeployError(409, 'session_conflict');
    if (operationError instanceof DeployError && operationError.reason === null) {
      operationError = new DeployError(operationError.status, operationError.code, `runtime_${phase}`);
    }
    if (staged && oldVersionId) {
      try {
        // Never rewind another deployment (including customer credential
        // rotation/removal), or an unacknowledged write whose outcome is unknown.
        if (!ownedDeployment) invalid('session_conflict');
        await verifyRawActive(input, ownedDeployment.id, ownedDeployment.versions);
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
        }, 'fail');
      } catch { /* Preserve the provider failure. */ }
    }
  } finally {
    if (routeMayBeEnabled) {
      try { await setSubdomain(input, false); } catch {
        operationError = new DeployError(409, 'session_conflict', 'runtime_route_disable_failed');
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
