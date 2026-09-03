import * as v from 'valibot';

import { PUBLIC_ORIGIN, REQUIRED_OAUTH_SCOPES } from '../src/constants';
import { CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH } from '../src/customer-install-paths';
import {
  createHostedStage1Secrets,
  expectedCustomerBootstrapBindings,
  type HostedStage1Provision,
  type HostedStage1Secrets,
} from '../src/hosted-stage1-bootstrap';
import { executeHostedStage1Cleanup, type HostedStage1CleanupInput } from '../src/hosted-stage1-cleanup';
import {
  authorizeHostedStage1Bootstrap,
  authorizeHostedStage1Cleanup,
  consumeHostedStage1Callback,
  freezeHostedStage1Plan,
  initializeHostedStage1Session,
  markHostedStage1CleanupRequired,
  recordHostedStage1Provision,
  saveHostedStage1Selection,
  type HostedStage1Session,
} from '../src/hosted-stage1-session';
import type { VerifiedReleaseBundle, VerifiedReleasePayloadBlob } from '../src/release';
import {
  APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
  canonicalJson,
  parseReleaseManifest,
  type ReleaseComponent,
  type ReleaseFileRecord,
} from '../src/release-manifest';
import { buildStaticDeployPlan, parseDeploySelection, type StaticDeployPlan } from '../src/schema';
import { parseVerifiedReleaseBundle } from '../src/verified-release-bundle';
import { CLIENT_ID, CLIENT_SECRET, selectionInput } from './fixtures';

const NOW = 1_800_000_000_000;
const ACCOUNT_ID = 'a'.repeat(32);
const WORKER_ID = 'b'.repeat(32);
const NAMESPACE_ID = 'c'.repeat(32);
const VERSION_ID = '11111111-1111-4111-8111-111111111111';
const DEPLOYMENT_ID = '22222222-2222-4222-8222-222222222222';
const RETIREMENT_VERSION_ID = '33333333-3333-4333-8333-333333333333';
const ACCESS_TOKEN = `token_${'d'.repeat(32)}`;
const AUTHORIZATION_CODE = `code_${'h'.repeat(32)}`;
const CUSTOMER_CLIENT_ID = 'g'.repeat(32);
const ISSUER_KEY_ID = 'ownership-key-v1';
const ISSUER_PUBLIC_KEY = 'I'.repeat(43);
const BOOTSTRAP_SOURCE = 'export class AdminState{};export default{fetch(){return new Response("bootstrap")}};';
const encoder = new TextEncoder();

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(input: Uint8Array | string): Promise<string> {
  const bytes = v.is(v.string(), input) ? encoder.encode(input) : input;
  const owned = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  owned.set(bytes);
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', owned)));
}

function base64(text: string): string {
  return btoa(String.fromCharCode(...encoder.encode(text)));
}

async function source(path: string, contentType: string, body: string) {
  const bytes = encoder.encode(body);
  return Object.freeze({
    bytes,
    record: Object.freeze({ path, contentType, byteSize: bytes.byteLength, sha256: await sha256(bytes) }),
  });
}

async function component(files: readonly { readonly record: ReleaseFileRecord }[]): Promise<ReleaseComponent> {
  const records = Object.freeze(files.map((file) => file.record));
  return Object.freeze({
    byteSize: records.reduce((sum, file) => sum + file.byteSize, 0),
    fileCount: records.length,
    files: records,
    treeSha256: await sha256(canonicalJson(records)),
  });
}

async function releaseFixture(): Promise<VerifiedReleaseBundle> {
  const admin = [await source('payload/admin/index.html', 'text/html; charset=utf-8', '<!doctype html><main>admin</main>')];
  const installer = [await source('payload/installer/index.html', 'text/html; charset=utf-8', '<!doctype html><main>install</main>')];
  const worker = [await source('payload/worker/index.js', 'application/javascript+module',
    '// ankka-control-plane-origin:https://deploy.ankka.ai\nexport default{fetch(){return new Response("ready")}};')];
  const workerBootstrap = [await source('payload/worker-bootstrap/index.js', 'application/javascript+module', BOOTSTRAP_SOURCE)];
  const workerCleanup = [await source('payload/worker-cleanup/index.js', 'application/javascript+module',
    'export class AdminState{};export default{fetch(){return new Response("cleanup")}};')];
  const workerRetirement = [await source('payload/worker-retirement/index.js', 'application/javascript+module',
    'export default{fetch(){return new Response(null,{status:410})}};')];
  const all = Object.freeze([...admin, ...installer, ...workerBootstrap, ...workerCleanup, ...workerRetirement, ...worker]);
  const manifest = parseReleaseManifest({
    artifact: {
      byteSize: all.reduce((sum, file) => sum + file.record.byteSize, 0),
      fileCount: all.length,
      treeSha256: await sha256(canonicalJson(all.map((file) => file.record))),
    },
    cloudflare: APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
    controlPlaneOrigin: PUBLIC_ORIGIN,
    components: {
      admin: await component(admin),
      installer: await component(installer),
      worker: await component(worker),
      workerBootstrap: await component(workerBootstrap),
      workerCleanup: await component(workerCleanup),
      workerRetirement: await component(workerRetirement),
    },
    oauthScopeIds: REQUIRED_OAUTH_SCOPES,
    release: 'gateway-v1.2.3',
    schemaVersion: 1,
    sourceCommit: '0123456789abcdef0123456789abcdef01234567',
  });
  const payload = Object.freeze(all.map((file): VerifiedReleasePayloadBlob => {
    const owned = new Uint8Array(new ArrayBuffer(file.bytes.byteLength));
    owned.set(file.bytes);
    return Object.freeze({ ...file.record, bytes: new Blob([owned], { type: file.record.contentType }) });
  }));
  return Object.freeze({
    verification: 'ed25519',
    channel: 'stable',
    keyId: 'release-key-v1',
    envelope: Object.freeze({
      schemaVersion: 2, channel: 'stable', keyId: 'release-key-v1',
      manifest: canonicalJson(manifest), signature: 'A'.repeat(86),
      signatureContext: 'ankka-mcp-gateway-release-envelope-v2',
    }),
    manifest,
    payload,
    publicKey: 'B'.repeat(43),
  });
}

function managementWorkerName(plan: StaticDeployPlan): string {
  const worker = plan.managementResources.find((resource) => resource.kind === 'management_worker');
  if (worker === undefined) throw new Error('fixture plan has no management worker');
  return worker.name;
}

function provisionFor(plan: StaticDeployPlan, secrets: HostedStage1Secrets): HostedStage1Provision {
  const workerName = managementWorkerName(plan);
  const bootstrapOrigin = `https://${workerName}.tenant.workers.dev/`;
  return Object.freeze({
    schemaVersion: 1,
    accountId: ACCOUNT_ID,
    bootstrapId: secrets.capability.bootstrapId,
    bootstrapSecretCommitment: secrets.capability.secretCommitment,
    capabilityExpiresAt: secrets.capability.expiresAt,
    bootstrapOrigin,
    bootstrapCallback: `${bootstrapOrigin.slice(0, -1)}${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`,
    deployment: Object.freeze({
      workerId: WORKER_ID,
      workerName,
      namespaceId: NAMESPACE_ID,
      namespaceName: `${workerName}_AdminState`,
      deploymentId: DEPLOYMENT_ID,
      versionId: VERSION_ID,
      release: plan.releaseId,
      artifactSha256: plan.releaseArtifactSha256,
      bootstrapComponentSha256: plan.bootstrapWorkerSourceSha256,
      sourceSha256: plan.bootstrapWorkerSourceSha256,
      recovery: 'created' as const,
    }),
    grantRevocation: 'confirmed' as const,
    handoff: `signed-handoff-${'s'.repeat(64)}`,
    installId: plan.managementOwnershipMarker,
    plan: Object.freeze({ id: plan.planId, hash: plan.planHash }),
    release: Object.freeze({ id: plan.releaseId, artifactSha256: plan.releaseArtifactSha256 }),
    workersSubdomain: 'tenant',
  });
}

function deterministicRandomBytes(): (length: number) => Uint8Array {
  let counter = 0;
  return (length: number): Uint8Array => {
    counter += 1;
    return new Uint8Array(length).map((_, index) => (index * 9 + counter * 41) & 255);
  };
}

interface FakeNamespaceItem {
  id: string;
  name: string;
  script: string;
  class: string;
  use_sqlite: boolean;
}

interface FakeVersion {
  id: string;
  bindings: readonly Record<string, string>[];
  modules: readonly { name: string; content_type: string; content_base64: string }[];
}

interface FakeAccount {
  accountId: string;
  workerName: string;
  worker: { id: string; name: string; tags: string[]; tail_consumers: string[] } | null;
  activeVersionId: string;
  versions: Map<string, FakeVersion>;
  namespaces: FakeNamespaceItem[];
  subdomainEnabled: boolean;
  stickyWorker: boolean;
  events: string[];
}

function json<Value>(value: Value, status = 200): Response {
  return Response.json({ success: true, errors: [], messages: [], result: value }, { status });
}

function page<Value>(items: readonly Value[]): Response {
  return Response.json({
    success: true, errors: [], messages: [], result: items,
    result_info: { page: 1, per_page: 1000, count: items.length, total_count: items.length, total_pages: 1 },
  });
}

function transportFor(account: FakeAccount): (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> {
  const prefix = `/client/v4/accounts/${ACCOUNT_ID}`;
  return async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === '/oauth2/token') {
      account.events.push('token-exchange');
      return Response.json({ access_token: ACCESS_TOKEN, token_type: 'bearer', scope: 'workers-scripts.write' });
    }
    if (path === '/oauth2/revoke') {
      account.events.push('revoke');
      return new Response(null, { status: 200 });
    }
    if (path === '/client/v4/accounts') {
      account.events.push('account-read');
      return json([{ id: account.accountId }]);
    }
    expect(request.headers.get('authorization')).toBe(`Bearer ${ACCESS_TOKEN}`);
    if (!path.startsWith(prefix)) return new Response(null, { status: 404 });
    const rest = path.slice(prefix.length);
    const worker = account.worker;
    const name = account.workerName;
    if (request.method === 'GET' && (rest === `/workers/workers/${name}` || rest === `/workers/workers/${WORKER_ID}`)) {
      account.events.push('worker-read');
      return worker === null ? new Response(null, { status: 404 }) : json(worker);
    }
    if (request.method === 'GET' && rest.startsWith('/workers/scripts/') && rest.endsWith('/deployments')) {
      account.events.push('deployments-read');
      return json({ deployments: [{ id: DEPLOYMENT_ID, versions: [{ version_id: account.activeVersionId, percentage: 100 }] }] });
    }
    if (request.method === 'GET' && rest.startsWith(`/workers/workers/${WORKER_ID}/versions/`)) {
      account.events.push('version-read');
      const versionId = rest.slice(`/workers/workers/${WORKER_ID}/versions/`.length);
      const version = account.versions.get(versionId);
      if (version === undefined) return new Response(null, { status: 404 });
      return json({
        id: version.id, main_module: 'index.js', compatibility_date: '2026-08-08', compatibility_flags: [],
        bindings: version.bindings, modules: version.modules,
      });
    }
    if (request.method === 'GET' && rest === '/workers/durable_objects/namespaces') {
      account.events.push('namespaces-read');
      return page(account.namespaces);
    }
    if (rest.startsWith('/workers/scripts/') && rest.endsWith('/subdomain')) {
      if (request.method === 'POST') {
        const body = v.parse(v.object({ enabled: v.boolean(), previews_enabled: v.literal(false) }), await request.json());
        account.subdomainEnabled = body.enabled;
        account.events.push(`subdomain-set:${String(body.enabled)}`);
      } else {
        account.events.push('subdomain-read');
      }
      return json({ enabled: account.subdomainEnabled, previews_enabled: false });
    }
    if (request.method === 'PUT' && rest === `/workers/scripts/${name}`) {
      const form = await request.formData();
      const metadata = v.parse(v.looseObject({
        exports: v.object({ AdminState: v.object({ state: v.literal('deleted'), type: v.literal('durable-object') }) }),
        bindings: v.array(v.unknown()),
      }), JSON.parse(await v.parse(v.instance(File), form.get('metadata')).text()));
      expect(metadata.bindings).toEqual([]);
      const module = v.parse(v.instance(File), form.get('index.js'));
      account.events.push('retire');
      account.versions.set(RETIREMENT_VERSION_ID, {
        id: RETIREMENT_VERSION_ID, bindings: [],
        modules: [{ name: 'index.js', content_type: 'application/javascript+module', content_base64: base64(await module.text()) }],
      });
      account.activeVersionId = RETIREMENT_VERSION_ID;
      account.namespaces = account.namespaces.filter((item) => item.script !== name);
      return json({ id: name });
    }
    if (request.method === 'DELETE' && rest === `/workers/workers/${WORKER_ID}`) {
      account.events.push('delete');
      if (!account.stickyWorker) account.worker = null;
      return new Response(null, { status: 204 });
    }
    if (request.method === 'GET' && rest === `/workers/scripts/${name}`) {
      account.events.push('script-read');
      return worker === null ? new Response(null, { status: 404 }) : json({ id: worker.name });
    }
    if (request.method === 'GET' && rest === '/workers/scripts') {
      account.events.push('scripts-list');
      return page(worker === null ? [] : [{ id: worker.name }]);
    }
    throw new Error(`unexpected transport ${request.method} ${request.url}`);
  };
}

async function fixture() {
  const bundle = await releaseFixture();
  const randomBytes = deterministicRandomBytes();
  const selection = parseDeploySelection(selectionInput);
  const plan = await buildStaticDeployPlan(selection, bundle.manifest, NOW + 20 * 60_000);
  const secrets = await createHostedStage1Secrets({ now: NOW + 30, randomBytes });
  const provision = provisionFor(plan, secrets);
  let session: HostedStage1Session = initializeHostedStage1Session({ now: NOW, randomBytes });
  session = saveHostedStage1Selection({ current: session, selection, now: NOW + 10 });
  session = await freezeHostedStage1Plan({ current: session, plan, now: NOW + 20 });
  const start = await authorizeHostedStage1Bootstrap({ current: session, capability: secrets.capability, now: NOW + 40, randomBytes });
  session = await consumeHostedStage1Callback({
    current: start.next, attemptId: start.attemptId, state: start.state, verifier: start.verifier, now: NOW + 50,
  });
  session = recordHostedStage1Provision({ current: session, attemptId: start.attemptId, provision, now: NOW + 60 });
  const provisioned = session;
  session = markHostedStage1CleanupRequired({ current: session, reason: 'cookie_lost', now: NOW + 70 });
  const cleanupStart = await authorizeHostedStage1Cleanup({ current: session, now: NOW + 80, randomBytes });
  session = await consumeHostedStage1Callback({
    current: cleanupStart.next, attemptId: cleanupStart.attemptId, state: cleanupStart.state,
    verifier: cleanupStart.verifier, now: NOW + 90,
  });
  const workerName = managementWorkerName(plan);
  const expected = expectedCustomerBootstrapBindings({
    accountId: ACCOUNT_ID,
    bootstrapCallback: provision.bootstrapCallback,
    customerOauthClientId: CUSTOMER_CLIENT_ID,
    issuerKeyId: ISSUER_KEY_ID,
    issuerPublicKey: ISSUER_PUBLIC_KEY,
    plan,
    release: parseVerifiedReleaseBundle(bundle),
    capability: secrets.capability,
    workerName,
  });
  const bindings: Record<string, string>[] = [
    { name: 'ADMIN_STATE', type: 'durable_object_namespace', class_name: 'AdminState', namespace_id: NAMESPACE_ID },
    { name: 'ASSETS', type: 'assets' },
    { name: 'ANKKA_BOOTSTRAP_NONCE', type: 'secret_text' },
    { name: 'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY', type: 'secret_text' },
    ...Object.entries(expected).map(([name, text]) => ({ name, type: 'plain_text', text })),
  ];
  const account: FakeAccount = {
    accountId: ACCOUNT_ID,
    workerName,
    worker: { id: WORKER_ID, name: workerName, tags: ['ankka-mcp-gateway', 'ankka-stage1-bootstrap', `ankka-bootstrap-id:${secrets.capability.bootstrapId}`], tail_consumers: [] },
    activeVersionId: VERSION_ID,
    versions: new Map([[VERSION_ID, {
      id: VERSION_ID,
      bindings,
      modules: [{ name: 'index.js', content_type: 'application/javascript+module', content_base64: base64(BOOTSTRAP_SOURCE) }],
    }]]),
    namespaces: [
      { id: 'e'.repeat(32), name: 'other_Foo', script: 'other-worker', class: 'Foo', use_sqlite: true },
      { id: NAMESPACE_ID, name: `${workerName}_AdminState`, script: workerName, class: 'AdminState', use_sqlite: true },
    ],
    subdomainEnabled: true,
    stickyWorker: false,
    events: [],
  };
  const waits: number[] = [];
  const input: HostedStage1CleanupInput = {
    code: AUTHORIZATION_CODE,
    verifier: 'i'.repeat(43),
    oauth: { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET },
    transport: transportFor(account),
    session,
    bundle,
    customerOauthClientId: CUSTOMER_CLIENT_ID,
    issuerKeyId: ISSUER_KEY_ID,
    issuerPublicKey: ISSUER_PUBLIC_KEY,
    now: () => NOW + 100,
    wait: async (milliseconds) => {
      waits.push(milliseconds);
    },
  };
  return { account, input, waits, session, provisioned, workerName, secrets };
}

const MUTATIONS = ['subdomain-set:false', 'retire', 'delete'];

describe('hosted Stage 1 lost-cookie cleanup', () => {
  it('reads back the exact root, disables workers.dev, retires the namespace, deletes the Worker, proves absence, then revokes', async () => {
    const f = await fixture();
    const result = await executeHostedStage1Cleanup(f.input);
    expect(result).toEqual({
      schemaVersion: 1,
      accountId: ACCOUNT_ID,
      workerId: WORKER_ID,
      workerName: f.workerName,
      namespaceId: NAMESPACE_ID,
      retirementVersionId: RETIREMENT_VERSION_ID,
      grantRevocation: 'confirmed',
      verifiedAbsentAt: NOW + 100,
    });
    const events = f.account.events;
    expect(events.slice(0, 2)).toEqual(['token-exchange', 'account-read']);
    expect(events.at(-1)).toBe('revoke');
    const firstMutation = events.findIndex((event) => MUTATIONS.includes(event));
    expect(events.slice(0, firstMutation)).toEqual(expect.arrayContaining(['worker-read', 'deployments-read', 'version-read', 'namespaces-read']));
    expect(events.filter((event) => MUTATIONS.includes(event))).toEqual(MUTATIONS);
    expect(events.indexOf('subdomain-set:false')).toBeLessThan(events.indexOf('retire'));
    expect(events.indexOf('retire')).toBeLessThan(events.indexOf('delete'));
    expect(events.indexOf('delete')).toBeLessThan(events.indexOf('revoke'));
    expect(f.account.worker).toBeNull();
    expect(f.account.subdomainEnabled).toBe(false);
    expect(f.account.namespaces.map((item) => item.script)).toEqual(['other-worker']);
    expect(f.waits).toEqual([]);
  });

  it('refuses before any mutation on account, identity, version, binding, or namespace mismatch and still revokes', async () => {
    const cases: readonly { name: string; code: string; mutate: (f: Awaited<ReturnType<typeof fixture>>) => void }[] = [
      { name: 'account', code: 'account_mismatch', mutate: (f) => { f.account.accountId = 'f'.repeat(32); } },
      { name: 'workerId', code: 'identity_mismatch', mutate: (f) => { if (f.account.worker) f.account.worker.id = 'f'.repeat(32); } },
      { name: 'workerMissing', code: 'identity_mismatch', mutate: (f) => { f.account.worker = null; } },
      { name: 'tags', code: 'identity_mismatch', mutate: (f) => { f.account.worker?.tags.push('ankka-stage1-live-canary'); } },
      { name: 'activeVersion', code: 'identity_mismatch', mutate: (f) => { f.account.activeVersionId = RETIREMENT_VERSION_ID; } },
      {
        name: 'binding',
        code: 'identity_mismatch',
        mutate: (f) => {
          const version = f.account.versions.get(VERSION_ID);
          if (version) f.account.versions.set(VERSION_ID, { ...version, bindings: version.bindings.map((binding) => binding.name === 'ANKKA_PLAN_ID' ? { ...binding, text: `plan-${'0'.repeat(24)}` } : binding) });
        },
      },
      {
        name: 'module',
        code: 'identity_mismatch',
        mutate: (f) => {
          const version = f.account.versions.get(VERSION_ID);
          if (version) f.account.versions.set(VERSION_ID, { ...version, modules: [{ ...version.modules[0], name: 'index.js', content_type: 'application/javascript+module', content_base64: base64('export default {}') }] });
        },
      },
      { name: 'namespaceId', code: 'identity_mismatch', mutate: (f) => { f.account.namespaces = f.account.namespaces.map((item) => item.script === f.workerName ? { ...item, id: 'f'.repeat(32) } : item); } },
      { name: 'namespaceAmbiguous', code: 'ambiguous', mutate: (f) => { f.account.namespaces.push({ id: 'd'.repeat(32), name: 'dup', script: f.workerName, class: 'AdminState', use_sqlite: true }); } },
      { name: 'namespaceMissing', code: 'identity_mismatch', mutate: (f) => { f.account.namespaces = f.account.namespaces.filter((item) => item.script !== f.workerName); } },
    ];
    for (const testCase of cases) {
      const f = await fixture();
      testCase.mutate(f);
      await expect(executeHostedStage1Cleanup(f.input), testCase.name).rejects.toMatchObject({ code: testCase.code });
      expect(f.account.events.filter((event) => MUTATIONS.includes(event)), testCase.name).toEqual([]);
      expect(f.account.events.at(-1), testCase.name).toBe('revoke');
      expect(f.account.subdomainEnabled, testCase.name).toBe(true);
    }
  });

  it('requires a consumed cleanup attempt and never contacts the provider otherwise', async () => {
    const f = await fixture();
    await expect(executeHostedStage1Cleanup({ ...f.input, session: f.provisioned })).rejects.toMatchObject({ code: 'invalid' });
    expect(f.account.events).toEqual([]);
  });

  it('fails closed when the Worker refuses to disappear, after bounded retries, and still revokes', async () => {
    const f = await fixture();
    f.account.stickyWorker = true;
    await expect(executeHostedStage1Cleanup(f.input)).rejects.toMatchObject({ code: 'absence_not_proven', stage: 'worker_absence' });
    expect(f.account.events.filter((event) => MUTATIONS.includes(event))).toEqual(MUTATIONS);
    expect(f.waits.length).toBeGreaterThanOrEqual(7);
    expect(f.account.events.at(-1)).toBe('revoke');
  });
});
