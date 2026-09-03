import * as v from 'valibot';

import { boundaryValueSchema, type BoundaryValue } from './boundary';
import {
  setWorkerBootstrapSubdomain,
  verifyWorkerBootstrapSubdomain,
  type CloudflareManagementTransport,
} from './cloudflare-management-surface';
import {
  CloudflareDirectUploadError,
  inspectAdminStateDurableObjectNamespace,
} from './cloudflare-worker-direct-upload';
import { CLOUDFLARE_API_ORIGIN } from './constants';
import {
  exactCustomerBootstrapModule,
  exactCustomerBootstrapVersionBindings,
} from './customer-bootstrap-worker-readback';
import { DeployError } from './errors';
import { executeHostedBootstrapGrant } from './hosted-bootstrap-grant';
import {
  expectedCustomerBootstrapBindings,
  type HostedStage1Provision,
} from './hosted-stage1-bootstrap';
import type { HostedStage1Session } from './hosted-stage1-session';
import { readBoundedText, withDeadline } from './http';
import type { CloudflareOauthConfig, FetchTransport } from './oauth';
import type { VerifiedReleaseBundle } from './release';
import type { StaticDeployPlan } from './schema';
import { parseVerifiedReleaseBundle } from './verified-release-bundle';

/**
 * Deterministic lost-cookie cleanup for one recorded Stage 1 root.
 *
 * A fresh `workers-scripts.write` grant may remove exactly the Worker and
 * SQLite namespace the durable session recorded, and nothing else. Every
 * identity is re-read from the provider and compared with the recorded
 * provision, the frozen plan, and the signed release before any mutation.
 * Names alone are never ownership evidence. Any mismatch or ambiguity fails
 * closed with nothing sent. The grant is revoked by the wrapper on every path.
 */

const VERSION_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const COMPATIBILITY_DATE = '2026-08-08';
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const MAX_LIST_PAGES = 100;
const ABSENCE_ATTEMPTS = 8;
const RETIREMENT_MODULE_PATH = 'payload/worker-retirement/index.js';

const envelopeSchema = v.looseObject({
  success: v.literal(true),
  errors: v.array(boundaryValueSchema),
  messages: v.array(boundaryValueSchema),
  result: boundaryValueSchema,
  result_info: v.optional(v.looseObject({
    total_pages: v.optional(v.number()),
    total_count: v.optional(v.number()),
  })),
});
const workerSchema = v.looseObject({
  id: v.string(),
  name: v.string(),
  tags: v.array(v.string()),
  tail_consumers: v.array(boundaryValueSchema),
});
const deploymentsSchema = v.looseObject({
  deployments: v.array(v.looseObject({
    id: v.pipe(v.string(), v.regex(VERSION_ID)),
    versions: v.array(v.looseObject({
      version_id: v.pipe(v.string(), v.regex(VERSION_ID)),
      percentage: v.number(),
    })),
  })),
});
const versionSchema = v.looseObject({
  id: v.pipe(v.string(), v.regex(VERSION_ID)),
  main_module: v.literal('index.js'),
  compatibility_date: v.literal(COMPATIBILITY_DATE),
  compatibility_flags: v.optional(v.array(v.string())),
  bindings: v.array(boundaryValueSchema),
  modules: v.array(v.looseObject({
    name: v.string(),
    content_type: v.string(),
    content_base64: v.string(),
  })),
});
const namespaceListSchema = v.array(v.looseObject({
  id: v.optional(v.string()),
  script: v.optional(v.string()),
  class: v.optional(v.string()),
}));
const scriptListSchema = v.array(v.looseObject({ id: v.optional(v.string()) }));

export type HostedStage1CleanupErrorCode =
  | 'invalid'
  | 'account_mismatch'
  | 'identity_mismatch'
  | 'ambiguous'
  | 'provider_rejected'
  | 'provider_unknown'
  | 'absence_not_proven';

export class HostedStage1CleanupError extends Error {
  constructor(readonly code: HostedStage1CleanupErrorCode, readonly stage: string) {
    super(code);
    this.name = 'HostedStage1CleanupError';
  }
}

export interface HostedStage1CleanupResult {
  readonly schemaVersion: 1;
  readonly accountId: string;
  readonly workerId: string;
  readonly workerName: string;
  readonly namespaceId: string;
  readonly retirementVersionId: string;
  readonly grantRevocation: 'confirmed';
  readonly verifiedAbsentAt: number;
}

export interface HostedStage1CleanupInput {
  readonly code: string;
  readonly verifier: string;
  readonly oauth: CloudflareOauthConfig;
  readonly transport: FetchTransport;
  readonly session: HostedStage1Session;
  readonly bundle: VerifiedReleaseBundle;
  readonly customerOauthClientId: string;
  readonly issuerKeyId: string;
  readonly issuerPublicKey: string;
  readonly now: () => number;
  readonly wait?: (milliseconds: number) => Promise<void>;
}

interface ProviderCall {
  readonly accessToken: string;
  readonly transport: FetchTransport;
}

interface ProviderResponse {
  readonly status: number;
  readonly value: BoundaryValue;
  readonly totalPages: number;
}

interface CleanupRoot {
  readonly plan: StaticDeployPlan;
  readonly provision: HostedStage1Provision;
}

function fail(code: HostedStage1CleanupErrorCode, stage: string): never {
  throw new HostedStage1CleanupError(code, stage);
}

function accountUrl(accountId: string, path: string): URL {
  return new URL(`/client/v4/accounts/${accountId}${path}`, CLOUDFLARE_API_ORIGIN);
}

function defaultWait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function providerRequest(
  call: ProviderCall,
  stage: string,
  url: URL,
  init: RequestInit,
  allowedStatuses: readonly number[],
): Promise<ProviderResponse> {
  let response: Response;
  let serialized: string;
  try {
    ({ response, serialized } = await withDeadline(async (signal) => {
      const raw = await call.transport(url, {
        ...init,
        headers: { accept: 'application/json', authorization: `Bearer ${call.accessToken}`, ...init.headers },
        redirect: 'manual',
        signal,
      });
      return { response: raw, serialized: await readBoundedText(raw, 'internal_error', MAX_RESPONSE_BYTES) };
    }, 'internal_error', 30_000));
  } catch {
    fail('provider_unknown', stage);
  }
  if (!allowedStatuses.includes(response.status)) {
    fail(response.status >= 500 ? 'provider_unknown' : 'provider_rejected', stage);
  }
  if (response.status === 404 || serialized === '') {
    return Object.freeze({ status: response.status, value: null, totalPages: 1 });
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(serialized);
  } catch {
    fail('provider_unknown', stage);
  }
  const envelope = v.safeParse(envelopeSchema, decoded);
  if (!envelope.success || envelope.output.errors.length !== 0) fail('provider_rejected', stage);
  const info = envelope.output.result_info;
  const totalPages = info?.total_pages !== undefined && Number.isSafeInteger(info.total_pages)
    ? Math.max(1, info.total_pages)
    : 1;
  if (totalPages > MAX_LIST_PAGES) fail('provider_unknown', stage);
  return Object.freeze({ status: response.status, value: envelope.output.result, totalPages });
}

function cleanupRoot(session: HostedStage1Session): CleanupRoot {
  if (session.phase !== 'cleanup_required' || session.plan === null || session.provision === null ||
      session.attempt === null || session.attempt.kind !== 'cleanup' || session.attempt.status !== 'exchanging') {
    fail('invalid', 'validate');
  }
  return Object.freeze({ plan: session.plan, provision: session.provision });
}

async function readExactWorker(call: ProviderCall, root: CleanupRoot): Promise<void> {
  const { provision } = root;
  const response = await providerRequest(
    call, 'worker_read',
    accountUrl(provision.accountId, `/workers/workers/${encodeURIComponent(provision.deployment.workerName)}`),
    { method: 'GET' }, [200, 404],
  );
  if (response.status === 404) fail('identity_mismatch', 'worker_read');
  const worker = v.safeParse(workerSchema, response.value);
  const expectedTags = ['ankka-mcp-gateway', 'ankka-stage1-bootstrap', `ankka-bootstrap-id:${provision.bootstrapId}`];
  if (!worker.success || worker.output.id !== provision.deployment.workerId ||
      worker.output.name !== provision.deployment.workerName || worker.output.tail_consumers.length !== 0 ||
      [...worker.output.tags].sort().join('\n') !== [...expectedTags].sort().join('\n')) {
    fail('identity_mismatch', 'worker_read');
  }
}

async function activeVersionId(call: ProviderCall, root: CleanupRoot, stage: string): Promise<string> {
  const response = await providerRequest(
    call, stage,
    accountUrl(root.provision.accountId, `/workers/scripts/${encodeURIComponent(root.provision.deployment.workerName)}/deployments`),
    { method: 'GET' }, [200],
  );
  const deployments = v.safeParse(deploymentsSchema, response.value);
  const active = deployments.success ? deployments.output.deployments.at(0) : undefined;
  const version = active?.versions.at(0);
  if (!deployments.success || active === undefined || active.versions.length !== 1 || version === undefined ||
      version.percentage !== 100) fail('identity_mismatch', stage);
  return version.version_id;
}

async function readExactVersion(
  call: ProviderCall,
  root: CleanupRoot,
  input: HostedStage1CleanupInput,
): Promise<void> {
  const { plan, provision } = root;
  const versionId = await activeVersionId(call, root, 'deployment_read');
  if (versionId !== provision.deployment.versionId) fail('identity_mismatch', 'deployment_read');
  const response = await providerRequest(
    call, 'version_read',
    accountUrl(provision.accountId, `/workers/workers/${provision.deployment.workerId}/versions/${versionId}?include=modules`),
    { method: 'GET' }, [200],
  );
  const version = v.safeParse(versionSchema, response.value);
  if (!version.success || version.output.id !== versionId || (version.output.compatibility_flags ?? []).length !== 0) {
    fail('identity_mismatch', 'version_read');
  }
  const release = parseVerifiedReleaseBundle(input.bundle);
  const expectedBindings = expectedCustomerBootstrapBindings({
    accountId: provision.accountId,
    bootstrapCallback: provision.bootstrapCallback,
    customerOauthClientId: input.customerOauthClientId,
    issuerKeyId: input.issuerKeyId,
    issuerPublicKey: input.issuerPublicKey,
    plan,
    release,
    capability: {
      bootstrapId: provision.bootstrapId,
      secret: '',
      secretCommitment: provision.bootstrapSecretCommitment,
      expiresAt: provision.capabilityExpiresAt,
    },
    workerName: provision.deployment.workerName,
  });
  if (!await exactCustomerBootstrapModule(version.output.modules, plan.bootstrapWorkerSourceSha256) ||
      !exactCustomerBootstrapVersionBindings(version.output.bindings, expectedBindings, provision.deployment.namespaceId)) {
    fail('identity_mismatch', 'version_read');
  }
}

async function readExactNamespace(call: ProviderCall, root: CleanupRoot): Promise<void> {
  const { provision } = root;
  try {
    const locator = await inspectAdminStateDurableObjectNamespace({
      accountId: provision.accountId,
      workerName: provision.deployment.workerName,
      className: 'AdminState',
      storage: 'sqlite',
      expectedNamespaceId: provision.deployment.namespaceId,
    }, { accessToken: call.accessToken, transport: (request: Request) => call.transport(request) });
    if (locator.namespaceId !== provision.deployment.namespaceId ||
        locator.namespaceName !== provision.deployment.namespaceName) fail('identity_mismatch', 'namespace_read');
  } catch (error) {
    if (error instanceof HostedStage1CleanupError) throw error;
    if (error instanceof CloudflareDirectUploadError && error.code === 'recovery_ambiguous') fail('ambiguous', 'namespace_read');
    if (error instanceof CloudflareDirectUploadError && error.code === 'provider_mismatch') fail('identity_mismatch', 'namespace_read');
    fail('provider_unknown', 'namespace_read');
  }
}

async function namespacePresent(call: ProviderCall, root: CleanupRoot): Promise<boolean> {
  const { provision } = root;
  let totalPages = 1;
  let matches = 0;
  for (let page = 1; page <= totalPages; page += 1) {
    const response = await providerRequest(
      call, 'namespace_list',
      accountUrl(provision.accountId, `/workers/durable_objects/namespaces?page=${page}&per_page=1000`),
      { method: 'GET' }, [200],
    );
    const items = v.safeParse(namespaceListSchema, response.value);
    if (!items.success) fail('provider_unknown', 'namespace_list');
    totalPages = response.totalPages;
    for (const item of items.output) {
      if (item.script === provision.deployment.workerName && item.class === 'AdminState') {
        if (item.id !== provision.deployment.namespaceId) fail('ambiguous', 'namespace_list');
        matches += 1;
      }
    }
  }
  if (matches > 1) fail('ambiguous', 'namespace_list');
  return matches === 1;
}

async function disableWorkersDev(call: ProviderCall, root: CleanupRoot): Promise<void> {
  const managementTransport: CloudflareManagementTransport = (request) => call.transport(request);
  const common = { accessToken: call.accessToken, transport: managementTransport, accountId: root.provision.accountId, plan: root.plan };
  try {
    await setWorkerBootstrapSubdomain({ ...common, enabled: false });
    await verifyWorkerBootstrapSubdomain({ ...common, expectedEnabled: false });
  } catch {
    fail('provider_unknown', 'workers_dev_disable');
  }
}

async function retirementModule(bundle: VerifiedReleaseBundle): Promise<Blob> {
  const parsed = parseVerifiedReleaseBundle(bundle);
  const records = parsed.manifest.components.workerRetirement.files;
  const record = records[0];
  if (records.length !== 1 || record === undefined || record.path !== RETIREMENT_MODULE_PATH) fail('invalid', 'retirement_module');
  const blob = parsed.payload.find((entry) => entry.path === record.path);
  if (blob === undefined || blob.sha256 !== record.sha256) fail('invalid', 'retirement_module');
  const bytes = new Uint8Array(await blob.bytes.arrayBuffer());
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  const actual = Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
  if (actual !== record.sha256) fail('invalid', 'retirement_module');
  return new Blob([bytes], { type: 'application/javascript+module' });
}

/** Deploys the signed retirement module so the SQLite class is marked deleted and the namespace retires. */
async function retireNamespace(
  call: ProviderCall,
  root: CleanupRoot,
  bundle: VerifiedReleaseBundle,
  wait: (milliseconds: number) => Promise<void>,
): Promise<string> {
  const { provision } = root;
  const metadata = {
    annotations: { 'workers/tag': `ankka-stage1-cleanup:${provision.bootstrapId}` },
    bindings: [],
    compatibility_date: COMPATIBILITY_DATE,
    compatibility_flags: [],
    exports: { AdminState: { state: 'deleted', type: 'durable-object' } },
    main_module: 'index.js',
    observability: { enabled: false },
  };
  const form = new FormData();
  form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }), 'metadata.json');
  form.append('index.js', await retirementModule(bundle), 'index.js');
  await providerRequest(
    call, 'retirement_upload',
    accountUrl(provision.accountId, `/workers/scripts/${encodeURIComponent(provision.deployment.workerName)}`),
    { method: 'PUT', body: form }, [200],
  );
  const retirementVersionId = await activeVersionId(call, root, 'retirement_deployment_read');
  if (retirementVersionId === provision.deployment.versionId) fail('provider_unknown', 'retirement_deployment_read');
  for (let attempt = 0; attempt < ABSENCE_ATTEMPTS; attempt += 1) {
    if (!await namespacePresent(call, root)) return retirementVersionId;
    await wait(300 * (attempt + 1));
  }
  fail('absence_not_proven', 'namespace_retire');
}

async function deleteWorker(call: ProviderCall, root: CleanupRoot): Promise<void> {
  const { provision } = root;
  await providerRequest(
    call, 'worker_delete',
    accountUrl(provision.accountId, `/workers/workers/${provision.deployment.workerId}`),
    { method: 'DELETE' }, [200, 202, 204],
  );
}

async function proveWorkerAbsent(
  call: ProviderCall,
  root: CleanupRoot,
  wait: (milliseconds: number) => Promise<void>,
): Promise<void> {
  const { provision } = root;
  for (let attempt = 0; attempt < ABSENCE_ATTEMPTS; attempt += 1) {
    const byId = await providerRequest(
      call, 'worker_absence',
      accountUrl(provision.accountId, `/workers/workers/${provision.deployment.workerId}`),
      { method: 'GET' }, [200, 404],
    );
    const byName = await providerRequest(
      call, 'worker_absence',
      accountUrl(provision.accountId, `/workers/scripts/${encodeURIComponent(provision.deployment.workerName)}`),
      { method: 'GET' }, [200, 404],
    );
    if (byId.status === 404 && byName.status === 404) {
      let totalPages = 1;
      for (let page = 1; page <= totalPages; page += 1) {
        const listing = await providerRequest(
          call, 'worker_absence',
          accountUrl(provision.accountId, `/workers/scripts?page=${page}&per_page=1000`),
          { method: 'GET' }, [200],
        );
        const scripts = v.safeParse(scriptListSchema, listing.value);
        if (!scripts.success) fail('provider_unknown', 'worker_absence');
        if (scripts.output.some((item) => item.id === provision.deployment.workerName)) fail('absence_not_proven', 'worker_absence');
        totalPages = listing.totalPages;
      }
      if (await namespacePresent(call, root)) fail('absence_not_proven', 'worker_absence');
      return;
    }
    await wait(300 * (attempt + 1));
  }
  fail('absence_not_proven', 'worker_absence');
}

/**
 * Runs exact-root cleanup under a fresh Stage 1 grant. Read-back precedes
 * every mutation; the grant is revoked before the result is returned.
 */
export async function executeHostedStage1Cleanup(input: HostedStage1CleanupInput): Promise<HostedStage1CleanupResult> {
  const root = cleanupRoot(input.session);
  const wait = input.wait ?? defaultWait;
  let captured: HostedStage1CleanupError | null = null;
  let retirementVersionId = '';
  let result;
  try {
    result = await executeHostedBootstrapGrant({
      code: input.code,
      verifier: input.verifier,
      config: input.oauth,
      transport: input.transport,
      deploy: async ({ accessToken, accountId }) => {
        const call: ProviderCall = Object.freeze({ accessToken, transport: input.transport });
        try {
          if (accountId !== root.provision.accountId) fail('account_mismatch', 'account_reassert');
          await readExactWorker(call, root);
          await readExactVersion(call, root, input);
          await readExactNamespace(call, root);
          if (!await namespacePresent(call, root)) fail('identity_mismatch', 'namespace_list');
          await disableWorkersDev(call, root);
          retirementVersionId = await retireNamespace(call, root, input.bundle, wait);
          await deleteWorker(call, root);
          await proveWorkerAbsent(call, root, wait);
          return Object.freeze({ retirementVersionId });
        } catch (error) {
          captured = error instanceof HostedStage1CleanupError ? error : new HostedStage1CleanupError('provider_unknown', 'cleanup');
          throw error;
        }
      },
    });
  } catch (error) {
    if (captured !== null) throw captured;
    if (error instanceof DeployError) throw error;
    fail('provider_unknown', 'grant');
  }
  const verifiedAbsentAt = input.now();
  if (!Number.isSafeInteger(verifiedAbsentAt) || verifiedAbsentAt < 0 || !VERSION_ID.test(retirementVersionId)) {
    fail('invalid', 'result');
  }
  return Object.freeze({
    schemaVersion: 1,
    accountId: result.accountId,
    workerId: root.provision.deployment.workerId,
    workerName: root.provision.deployment.workerName,
    namespaceId: root.provision.deployment.namespaceId,
    retirementVersionId,
    grantRevocation: result.grantRevocation,
    verifiedAbsentAt,
  });
}
