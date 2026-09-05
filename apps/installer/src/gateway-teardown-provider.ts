import * as v from 'valibot';
import { canonicalJson } from './canonical-json';

import { boundaryValueSchema, type BoundaryValue } from './boundary';
import { CLOUDFLARE_API_ORIGIN } from './constants';
import { assertExactReleaseBundleIdentity } from './exact-release-bundle';
import type { GatewayTeardownJobPort } from './gateway-teardown-durable-state';
import type { GatewayTeardownTrust, VerifiedGatewayTeardownHandoff } from './gateway-teardown-handoff';
import {
  GATEWAY_ROOT_REMOVAL_STEPS, armGatewayRootRemoval, verifyGatewayRootRemoval,
  verifyGatewayTeardownJobAuthority, type GatewayRootRemovalStep, type GatewayTeardownJob,
} from './gateway-teardown-job';
import { readBoundedText, withDeadline } from './http';
import type { FetchTransport } from './oauth';
import { verifySignedReleaseEnvelope, type VerifiedReleaseBundle } from './release';

const COMPATIBILITY_DATE = '2026-08-08';
const RETIREMENT_PATH = 'payload/worker-retirement/index.js';
const envelopeSchema = v.looseObject({
  success: v.literal(true), errors: v.optional(v.nullable(v.array(boundaryValueSchema))),
  result: v.optional(boundaryValueSchema),
  result_info: v.optional(v.looseObject({
    total_pages: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(0), v.maxValue(100))),
    total_count: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(0))),
  })),
});
const namedWorkerSchema = v.looseObject({ id: v.string(), name: v.string(), tail_consumers: v.optional(v.array(boundaryValueSchema)) });
const scriptSchema = v.looseObject({ id: v.string() });
const namespaceSchema = v.looseObject({ id: v.string(), script: v.string(), class: v.string(), use_sqlite: v.boolean() });
const domainSchema = v.looseObject({ id: v.string(), hostname: v.string(), service: v.string(), zone_id: v.string(), environment: v.optional(v.string()) });
const applicationSchema = v.looseObject({
  id: v.string(), name: v.string(), type: v.literal('self_hosted'), domain: v.string(), aud: v.string(),
  destinations: v.optional(v.array(v.looseObject({ type: v.literal('public'), uri: v.string() }))),
  self_hosted_domains: v.optional(v.array(v.string())),
});
const policySchema = v.looseObject({
  id: v.string(), name: v.string(), decision: v.literal('allow'), precedence: v.literal(1),
  include: v.pipe(v.array(v.strictObject({ email: v.strictObject({ email: v.pipe(v.string(), v.email()) }) })), v.minLength(1)),
  require: v.pipe(v.array(boundaryValueSchema), v.length(0)), exclude: v.pipe(v.array(boundaryValueSchema), v.length(0)),
  approval_required: v.optional(v.literal(false)), isolation_required: v.optional(v.literal(false)),
  purpose_justification_required: v.optional(v.literal(false)),
});
const bindingSchema = v.looseObject({ type: v.string(), name: v.string(), namespace_id: v.optional(v.string()), script_name: v.optional(v.string()), service: v.optional(v.string()), class_name: v.optional(v.string()) });
const settingsSchema = v.looseObject({ bindings: v.array(bindingSchema) });
const deploymentsSchema = v.looseObject({ deployments: v.array(v.looseObject({
  versions: v.array(v.looseObject({ version_id: v.string(), percentage: v.number() })),
})) });
const versionSchema = v.looseObject({
  id: v.string(), main_module: v.literal('index.js'), compatibility_date: v.literal(COMPATIBILITY_DATE),
  compatibility_flags: v.optional(v.pipe(v.array(v.string()), v.length(0))),
  bindings: v.pipe(v.array(boundaryValueSchema), v.length(0)),
  modules: v.pipe(v.array(v.looseObject({ name: v.literal('index.js'), content_type: v.string(), content_base64: v.string() })), v.length(1)),
});

export class GatewayTeardownProviderError extends Error {
  constructor(readonly stage: string, readonly code: 'identity_mismatch' | 'foreign_dependency' | 'provider_unknown' | 'provider_rejected' | 'absence_not_proven' | 'job_conflict') {
    super(`teardown_${stage}_${code}`);
    this.name = 'GatewayTeardownProviderError';
  }
}
function fail(stage: string, code: GatewayTeardownProviderError['code']): never { throw new GatewayTeardownProviderError(stage, code); }

interface Call {
  readonly accessToken: string;
  readonly transport: FetchTransport;
  readonly authority: VerifiedGatewayTeardownHandoff;
}
function account(call: Call, path: string): URL {
  return new URL(`/client/v4/accounts/${call.authority.certificate.statement.accountId}${path}`, CLOUDFLARE_API_ORIGIN);
}
function applicationUrl(call: Call, suffix = ''): URL {
  const management = call.authority.statement.management;
  return new URL(`/client/v4/zones/${management.zoneId}/access/apps/${management.applicationId}${suffix}`, CLOUDFLARE_API_ORIGIN);
}

async function request(call: Call, stage: string, url: URL, init: RequestInit = {}, missing = false) {
  try {
    return await withDeadline(async (signal) => {
      const response = await call.transport(url, { ...init, signal, redirect: 'manual',
        headers: { accept: 'application/json', authorization: `Bearer ${call.accessToken}` } });
      const serialized = await readBoundedText(response, 'internal_error', 16 * 1024 * 1024);
      if (response.status === 404 && missing) return { absent: true, value: null, pages: 1, count: undefined };
      if (!response.ok) fail(stage, response.status >= 500 ? 'provider_unknown' : 'provider_rejected');
      if (response.status === 204 && init.method === 'DELETE') return { absent: false, value: null, pages: 1, count: undefined };
      const parsed = v.safeParse(envelopeSchema, JSON.parse(serialized));
      if (!parsed.success || (parsed.output.errors?.length ?? 0) !== 0) fail(stage, 'provider_unknown');
      return { absent: false, value: parsed.output.result ?? null,
        pages: parsed.output.result_info?.total_pages, count: parsed.output.result_info?.total_count };
    }, 'internal_error', 30_000);
  } catch (error) {
    if (error instanceof GatewayTeardownProviderError) throw error;
    fail(stage, 'provider_unknown');
  }
}

/** No truncated or ambiguous provider list can establish absence. */
async function list(call: Call, stage: string, url: URL): Promise<BoundaryValue[]> {
  const values: BoundaryValue[] = [];
  let pages = 1;
  let count: number | undefined;
  for (let page = 1; page <= pages; page += 1) {
    const target = new URL(url);
    target.searchParams.set('page', String(page));
    target.searchParams.set('per_page', '100');
    const response = await request(call, stage, target);
    if (!Array.isArray(response.value)) fail(stage, 'provider_unknown');
    if (response.pages === undefined && response.value.length >= 100) fail(stage, 'provider_unknown');
    const observedPages = Math.max(1, response.pages ?? 1);
    if (page > 1 && (pages !== observedPages || count !== response.count)) fail(stage, 'provider_unknown');
    pages = observedPages;
    count = response.count;
    values.push(...response.value);
  }
  if (count !== undefined && count !== values.length) fail(stage, 'provider_unknown');
  return values;
}

async function workerPresent(call: Call): Promise<boolean> {
  const expected = call.authority.certificate.statement.worker;
  const byName = await request(call, 'worker_read', account(call, `/workers/workers/${expected.name}`), {}, true);
  const byId = await request(call, 'worker_read', account(call, `/workers/workers/${expected.providerId}`), {}, true);
  if (byName.absent !== byId.absent) fail('worker_read', 'identity_mismatch');
  if (byName.absent) return false;
  for (const value of [byName.value, byId.value]) {
    const parsed = v.safeParse(namedWorkerSchema, value);
    if (!parsed.success || parsed.output.id !== expected.providerId || parsed.output.name !== expected.name ||
        (parsed.output.tail_consumers?.length ?? 0) !== 0) fail('worker_read', 'identity_mismatch');
  }
  return true;
}

async function namespacePresent(call: Call): Promise<boolean> {
  const owner = call.authority.certificate.statement;
  const values = await list(call, 'namespace_list', account(call, '/workers/durable_objects/namespaces'));
  let found = 0;
  for (const value of values) {
    const parsed = v.safeParse(namespaceSchema, value);
    if (!parsed.success) fail('namespace_list', 'provider_unknown');
    const item = parsed.output;
    if (item.script === owner.worker.name || item.id === owner.adminStateNamespaceId) {
      if (item.script !== owner.worker.name || item.id !== owner.adminStateNamespaceId || item.class !== 'AdminState' || !item.use_sqlite) {
        fail('namespace_list', 'foreign_dependency');
      }
      found += 1;
    }
  }
  if (found > 1) fail('namespace_list', 'identity_mismatch');
  return found === 1;
}

async function scriptsUnshared(call: Call, rootPresent: boolean, namespaceExists: boolean, retirementSha256: string): Promise<void> {
  const owner = call.authority.certificate.statement;
  const values = await list(call, 'worker_list', account(call, '/workers/scripts'));
  const seen = new Set<string>();
  for (const value of values) {
    const parsed = v.safeParse(scriptSchema, value);
    if (!parsed.success || !/^[A-Za-z0-9_-]{1,128}$/u.test(parsed.output.id) || seen.has(parsed.output.id)) fail('worker_list', 'provider_unknown');
    const name = parsed.output.id;
    seen.add(name);
    const response = await request(call, 'worker_bindings', account(call, `/workers/scripts/${name}/settings`));
    const settings = v.safeParse(settingsSchema, response.value);
    if (!settings.success) fail('worker_bindings', 'provider_unknown');
    if (name !== owner.worker.name && settings.output.bindings.some((binding) =>
      binding.type === 'service' && binding.service === owner.worker.name)) fail('worker_bindings', 'foreign_dependency');
    const bindings = settings.output.bindings.filter((binding) => binding.type === 'durable_object_namespace');
    if (name === owner.worker.name) {
      if (rootPresent && namespaceExists && bindings.length === 0) {
        // The deployment can be visible before the namespace listing catches
        // up. Only the exact signed retirement module explains this gap.
        await retiredVersion(call, retirementSha256);
      } else if (!rootPresent || (namespaceExists ? bindings.length !== 1 ||
          bindings[0]?.namespace_id !== owner.adminStateNamespaceId || bindings[0]?.class_name !== 'AdminState'
        : bindings.length !== 0)) fail('worker_bindings', 'identity_mismatch');
    } else if (bindings.some((binding) => (binding.namespace_id === undefined && binding.script_name === undefined) ||
      binding.namespace_id === owner.adminStateNamespaceId || binding.script_name === owner.worker.name)) {
      fail('worker_bindings', 'foreign_dependency');
    }
  }
  if (seen.has(owner.worker.name) !== rootPresent) fail('worker_list', 'identity_mismatch');
}

async function domainPresent(call: Call): Promise<boolean> {
  const expected = call.authority.statement.management;
  const owner = call.authority.certificate.statement;
  const matches = (value: BoundaryValue): boolean => {
    const result = v.safeParse(domainSchema, value);
    if (!result.success) fail('domain_read', 'provider_unknown');
    const item = result.output;
    if (item.id !== expected.domainId && item.hostname !== expected.hostname && item.service !== owner.worker.name) return false;
    if (item.id !== expected.domainId || item.hostname !== expected.hostname || item.service !== owner.worker.name ||
        item.zone_id !== expected.zoneId || (item.environment !== undefined && item.environment !== 'production')) fail('domain_read', 'foreign_dependency');
    return true;
  };
  const values = await list(call, 'domain_list', account(call, '/workers/domains'));
  const count = values.filter(matches).length;
  const byId = await request(call, 'domain_read', account(call, `/workers/domains/${expected.domainId}`), {}, true);
  if (count > 1 || (count === 1) === byId.absent || (!byId.absent && !matches(byId.value))) fail('domain_read', 'identity_mismatch');
  return !byId.absent;
}

async function managementPresent(call: Call): Promise<{ application: boolean; policy: boolean }> {
  const expected = call.authority.statement.management;
  const response = await request(call, 'application_read', applicationUrl(call), {}, true);
  if (response.absent) return { application: false, policy: false };
  const result = v.safeParse(applicationSchema, response.value);
  if (!result.success || result.output.id !== expected.applicationId || result.output.name !== expected.applicationName ||
      result.output.aud !== expected.applicationAud || result.output.domain !== expected.hostname ||
      result.output.destinations?.some((destination) => destination.uri !== expected.hostname) ||
      result.output.self_hosted_domains?.some((domain) => domain !== expected.hostname)) fail('application_read', 'identity_mismatch');
  const policies = await list(call, 'policy_list', applicationUrl(call, '/policies'));
  if (policies.length > 1) fail('policy_list', 'foreign_dependency');
  for (const item of policies) {
    const policy = v.safeParse(policySchema, item);
    if (!policy.success || policy.output.id !== expected.policyId || policy.output.name !== expected.policyName) fail('policy_list', 'foreign_dependency');
  }
  const byId = await request(call, 'policy_read', applicationUrl(call, `/policies/${expected.policyId}`), {}, true);
  if (byId.absent !== (policies.length === 0)) fail('policy_read', 'identity_mismatch');
  if (!byId.absent) {
    const policy = v.safeParse(policySchema, byId.value);
    if (!policy.success || policy.output.id !== expected.policyId || policy.output.name !== expected.policyName) fail('policy_read', 'identity_mismatch');
  }
  return { application: true, policy: !byId.absent };
}

async function retiredVersion(call: Call, expectedSha256: string): Promise<void> {
  const owner = call.authority.certificate.statement;
  const response = await request(call, 'retirement_deployment', account(call, `/workers/scripts/${owner.worker.name}/deployments`));
  const deployments = v.safeParse(deploymentsSchema, response.value);
  const active = deployments.success ? deployments.output.deployments[0] : undefined;
  const versionId = active?.versions[0]?.version_id;
  if (active?.versions.length !== 1 || active.versions[0]?.percentage !== 100 ||
      versionId === undefined || !/^[a-f0-9-]{36}$/u.test(versionId)) fail('retirement_deployment', 'identity_mismatch');
  const versionResponse = await request(call, 'retirement_version', account(call, `/workers/workers/${owner.worker.providerId}/versions/${versionId}?include=modules`));
  const version = v.safeParse(versionSchema, versionResponse.value);
  if (!version.success || version.output.id !== versionId) fail('retirement_version', 'identity_mismatch');
  const module = version.output.modules[0];
  if (module === undefined || module.content_type !== 'application/javascript+module') fail('retirement_version', 'identity_mismatch');
  try {
    const raw = atob(module.content_base64);
    const bytes = Uint8Array.from(raw, (character) => character.charCodeAt(0));
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    if (Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('') !== expectedSha256) fail('retirement_version', 'identity_mismatch');
  } catch { fail('retirement_version', 'identity_mismatch'); }
}

interface Inventory { retire_namespace: boolean; management_domain: boolean; management_policy: boolean; management_application: boolean; worker: boolean }
async function inventory(call: Call, job: GatewayTeardownJob): Promise<Inventory> {
  const worker = await workerPresent(call);
  const namespace = await namespacePresent(call);
  if (namespace && !worker) fail('namespace_read', 'identity_mismatch');
  await scriptsUnshared(call, worker, namespace, job.retirementModuleSha256);
  const domain = await domainPresent(call);
  const management = await managementPresent(call);
  if (!namespace && worker) await retiredVersion(call, job.retirementModuleSha256);
  const present = { retire_namespace: namespace, management_domain: domain,
    management_policy: management.policy, management_application: management.application, worker };
  if (job.verifiedSteps.some((step) => present[step])) fail('preflight', 'identity_mismatch');
  return present;
}

async function retirementModule(job: GatewayTeardownJob, bundle: VerifiedReleaseBundle): Promise<Blob> {
  assertExactReleaseBundleIdentity(bundle, job.release);
  await verifySignedReleaseEnvelope(canonicalJson(bundle.envelope), job.release.channel,
    { [job.release.keyId]: job.release.publicKey }, await Promise.all(bundle.payload.map(async (entry) => ({
      path: entry.path, bytes: new Uint8Array(await entry.bytes.arrayBuffer()),
    }))));
  const files = bundle.manifest.components.workerRetirement.files;
  const file = files[0];
  const entry = bundle.payload.find((item) => item.path === RETIREMENT_PATH);
  if (files.length !== 1 || file?.path !== RETIREMENT_PATH || file.sha256 !== job.retirementModuleSha256 ||
      entry === undefined || entry.sha256 !== file.sha256) fail('retirement_module', 'identity_mismatch');
  return new Blob([await entry.bytes.arrayBuffer()], { type: 'application/javascript+module' });
}

async function remove(call: Call, step: GatewayRootRemovalStep, module: Blob): Promise<void> {
  const owner = call.authority.certificate.statement;
  const management = call.authority.statement.management;
  if (step === 'retire_namespace') {
    const form = new FormData();
    form.append('metadata', new Blob([JSON.stringify({
      bindings: [], compatibility_date: COMPATIBILITY_DATE, compatibility_flags: [],
      exports: { AdminState: { state: 'deleted', type: 'durable-object' } },
      main_module: 'index.js', observability: { enabled: false },
    })], { type: 'application/json' }), 'metadata.json');
    form.append('index.js', module, 'index.js');
    await request(call, step, account(call, `/workers/scripts/${owner.worker.name}`), { method: 'PUT', body: form });
    return;
  }
  const url = step === 'management_domain' ? account(call, `/workers/domains/${management.domainId}`)
    : step === 'management_policy' ? applicationUrl(call, `/policies/${management.policyId}`)
    : step === 'management_application' ? applicationUrl(call)
    : account(call, `/workers/workers/${owner.worker.providerId}`);
  await request(call, step, url, { method: 'DELETE' }, true);
}

/** All provider mutations run in the OAuth callback request; this port persists only evidence. */
export async function executeGatewayRootRemoval(input: {
  readonly port: GatewayTeardownJobPort; readonly trust: GatewayTeardownTrust;
  readonly bundle: VerifiedReleaseBundle; readonly attemptId: string;
  readonly accessToken: string; readonly authorizedAccountId: string;
  readonly transport: FetchTransport; readonly now: () => number;
  readonly wait?: (milliseconds: number) => Promise<void>;
}): Promise<GatewayTeardownJob> {
  let job = await input.port.read();
  if (job === null || job.phase !== 'exchanging' || job.attempt?.id !== input.attemptId || job.attempt.expiresAt <= input.now()) fail('start', 'job_conflict');
  const authority = await verifyGatewayTeardownJobAuthority({ job, trust: input.trust });
  if (authority.certificate.statement.accountId !== input.authorizedAccountId) fail('account', 'identity_mismatch');
  const call = { authority, accessToken: input.accessToken, transport: input.transport };
  const module = await retirementModule(job, input.bundle);
  const wait = input.wait ?? ((milliseconds) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  const commit = async (previous: GatewayTeardownJob, next: GatewayTeardownJob): Promise<GatewayTeardownJob> => {
    if (!await input.port.compareAndSet(previous.revision, next)) fail('persist', 'job_conflict');
    return next;
  };
  // Complete ownership preflight before the first destructive boundary, and
  // again before each deletion to notice a concurrent manual policy/domain change.
  let present = await inventory(call, job);
  for (const step of GATEWAY_ROOT_REMOVAL_STEPS.slice(job.verifiedSteps.length)) {
    if (job.pendingStep === null || present[step]) {
      job = await commit(job, armGatewayRootRemoval({ job, attemptId: input.attemptId, step, now: input.now() }));
    }
    if (present[step]) {
      // Arming is durable before sending. A rejected/unknown response leaves
      // this boundary pending; only a fresh consent can try the write again.
      if (job.attempt === null || job.attempt.expiresAt <= input.now()) fail('send', 'job_conflict');
      await remove(call, step, module);
      let absent = false;
      for (let attempt = 0; attempt < 8; attempt += 1) {
        present = await inventory(call, job);
        if (!present[step]) { absent = true; break; }
        await wait(300 * (attempt + 1));
      }
      if (!absent) fail(step, 'absence_not_proven');
    }
    job = await commit(job, verifyGatewayRootRemoval({ job, attemptId: input.attemptId, step, now: input.now() }));
    present = await inventory(call, job);
  }
  return job;
}
