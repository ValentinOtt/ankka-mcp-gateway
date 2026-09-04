import * as v from 'valibot';

import type { BoundaryObject } from '../src/boundary';
import { BOOTSTRAP_COOKIE, PUBLIC_ORIGIN, REQUIRED_OAUTH_SCOPES, SESSION_COOKIE } from '../src/constants';
import { base64UrlDecode, base64UrlEncode } from '../src/crypto';
import { DeployError } from '../src/errors';
import type { HostedStage1Provider } from '../src/hosted-stage1-bootstrap';
import type { PinnedR2Release, R2ReleaseBundleProvider, R2ReleaseReadBucket } from '../src/r2-release-provider';
import type { VerifiedReleaseBundle, VerifiedReleasePayloadBlob } from '../src/release';
import {
  APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
  canonicalJson,
  parseReleaseManifest,
  type ReleaseComponent,
  type ReleaseFileRecord,
} from '../src/release-manifest';
import { TwoStageDeploySession, type TwoStageDeploySessionNamespace } from '../src/two-stage-deploy-session';
import {
  createTwoStageDeployEntrypoint,
  createTwoStageDeployRuntime,
  type TwoStageCleanupExecutor,
  type TwoStageDeployEnv,
  type TwoStageDeployWorker,
  type TwoStageRuntimeDependencies,
} from '../src/two-stage-runtime';
import { parsePublicUpdateChannel } from '../src/update-channel';
import { CLIENT_ID, CLIENT_SECRET, ENCRYPTION_KEY, cookiePair, selectionInput } from './fixtures';
import { FakeTwoStageState } from './hosted-stage1-sql-fake';

const NOW = 1_800_000_000_000;
const ACCOUNT_ID = 'a'.repeat(32);
const WORKER_ID = 'b'.repeat(32);
const NAMESPACE_ID = 'c'.repeat(32);
const VERSION_ID = '11111111-1111-4111-8111-111111111111';
const DEPLOYMENT_ID = '22222222-2222-4222-8222-222222222222';
const ACCESS_TOKEN = `token_${'d'.repeat(32)}`;
const AUTHORIZATION_CODE = `code_${'h'.repeat(32)}`;
const CUSTOMER_CLIENT_ID = 'g'.repeat(32);
const ISSUER_KEY_ID = 'ownership-key-v1';
const CUSTOMER_OWNERSHIP_PUBLIC_KEY = base64UrlEncode(new Uint8Array(32).fill(10));
const encoder = new TextEncoder();

const sessionResponseSchema = v.looseObject({
  csrfToken: v.string(),
  session: v.looseObject({
    phase: v.string(),
    plan: v.union([v.looseObject({ releaseId: v.string(), planId: v.string() }), v.null()]),
    provision: v.union([v.looseObject({ installId: v.string(), bootstrapOrigin: v.string() }), v.null()]),
    failure: v.union([v.looseObject({ code: v.string() }), v.null()]),
    cleanup: v.union([v.looseObject({ reason: v.string(), completedAt: v.union([v.number(), v.null()]) }), v.null()]),
  }),
});
const bootstrapResponseSchema = v.looseObject({ authorizationUrl: v.string(), expiresAt: v.number() });
const handoffResponseSchema = v.looseObject({
  status: v.string(),
  handoffUrl: v.optional(v.string()),
  retryAfterMs: v.optional(v.number()),
});
const errorSchema = v.looseObject({ code: v.string() });

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(input: Uint8Array | string): Promise<string> {
  const bytes = v.is(v.string(), input) ? encoder.encode(input) : input;
  const owned = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  owned.set(bytes);
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', owned)));
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

async function releaseFixture(): Promise<{ bundle: VerifiedReleaseBundle; pin: PinnedR2Release }> {
  const admin = [await source('payload/admin/index.html', 'text/html; charset=utf-8', '<!doctype html><main>admin</main>')];
  const installer = [
    await source('payload/installer/assets/app-A1b2C3d4.js', 'text/javascript; charset=utf-8', 'globalThis.__twoStage=true;'),
    await source('payload/installer/index.html', 'text/html; charset=utf-8',
      '<!doctype html><body><main>two-stage installer</main><script type="module" src="/assets/app-A1b2C3d4.js"></script></body>'),
  ];
  const worker = [await source('payload/worker/index.js', 'application/javascript+module',
    '// ankka-control-plane-origin:https://deploy.ankka.ai\nexport default{fetch(){return new Response("ready")}};')];
  const workerBootstrap = [await source('payload/worker-bootstrap/index.js', 'application/javascript+module',
    'export class AdminState{};export default{fetch(){return new Response("bootstrap")}};')];
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
  const bundle: VerifiedReleaseBundle = Object.freeze({
    verification: 'ed25519',
    channel: 'canary',
    keyId: 'reviewed-test-key',
    envelope: Object.freeze({
      schemaVersion: 2, channel: 'canary', keyId: 'reviewed-test-key',
      manifest: canonicalJson(manifest), signature: 'A'.repeat(86),
      signatureContext: 'ankka-mcp-gateway-release-envelope-v2',
    }),
    manifest,
    payload,
    publicKey: 'A'.repeat(43),
  });
  return {
    bundle,
    pin: {
      schemaVersion: 1,
      channel: 'canary',
      controlPlaneOrigin: manifest.controlPlaneOrigin,
      release: manifest.release,
      keyId: bundle.keyId,
      publicKey: 'A'.repeat(43),
      artifactSha256: manifest.artifact.treeSha256,
    },
  };
}

function deterministicRandomBytes(): (length: number) => Uint8Array {
  let counter = 0;
  return (length: number): Uint8Array => {
    counter += 1;
    return new Uint8Array(length).map((_, index) => (index * 3 + counter * 31) & 255);
  };
}

class FakeNamespace implements TwoStageDeploySessionNamespace {
  readonly objects = new Map<string, TwoStageDeploySession>();
  readonly states = new Map<string, FakeTwoStageState>();

  constructor(private readonly clock: () => number, private readonly randomBytes: (length: number) => Uint8Array) {}

  idFromName(name: string): DurableObjectId {
    const id: DurableObjectId = Object.create(null);
    Object.defineProperties(id, {
      toString: { value: () => name },
      equals: { value: (other: DurableObjectId) => other.toString() === name },
      name: { value: name },
    });
    return id;
  }

  get(id: DurableObjectId) {
    const name = id.toString();
    let object = this.objects.get(name);
    if (object === undefined) {
      const state = new FakeTwoStageState();
      object = new TwoStageDeploySession(state, undefined, { now: this.clock, randomBytes: this.randomBytes });
      this.states.set(name, state);
      this.objects.set(name, object);
    }
    const bound = object;
    return { fetch: (request: Request) => bound.fetch(request) };
  }
}

async function issuerMaterial() {
  // SAFETY: Ed25519 generateKey always yields a key pair; the union only exists for symmetric algorithms.
  const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair;
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keys.privateKey));
  return {
    seed: base64UrlEncode(pkcs8.subarray(pkcs8.byteLength - 32)),
    publicKey: base64UrlEncode(new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey))),
  };
}

function inertBucket(): R2ReleaseReadBucket {
  return { get: async () => null, list: async () => ({ objects: [], truncated: false }) };
}

function bundleProvider(bundle: VerifiedReleaseBundle): R2ReleaseBundleProvider {
  return { loadVerifiedReleaseBundle: async () => bundle };
}

interface Harness {
  readonly worker: TwoStageDeployWorker;
  readonly env: TwoStageDeployEnv;
  readonly clock: { now: number };
  readonly events: string[];
  readonly customer: { installId: string; release: string; healthStatus: number; tokenStatus: number };
  readonly namespace: FakeNamespace;
  readonly cleanupCalls: { code: string; verifier: string; phase: string }[];
}

async function harness(options: { policy?: 'disabled' | 'required' } = {}): Promise<Harness> {
  const clock = { now: NOW };
  const events: string[] = [];
  const customer = { installId: '', release: '', healthStatus: 404, tokenStatus: 200 };
  const cleanupCalls: { code: string; verifier: string; phase: string }[] = [];
  const release = await releaseFixture();
  const issuer = await issuerMaterial();
  const randomBytes = deterministicRandomBytes();
  const namespace = new FakeNamespace(() => clock.now, randomBytes);
  const transport = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (url.pathname === '/oauth2/token') {
      events.push('token-exchange');
      if (customer.tokenStatus !== 200) return new Response('{}', { status: customer.tokenStatus });
      return Response.json({ access_token: ACCESS_TOKEN, token_type: 'bearer', scope: 'workers-scripts.write' });
    }
    if (url.hostname === 'api.cloudflare.com' && url.pathname === '/client/v4/accounts') {
      events.push('account-read');
      return Response.json({ success: true, errors: [], messages: [], result: [{ id: ACCOUNT_ID }] });
    }
    if (url.pathname === '/oauth2/revoke') {
      events.push('revoke');
      return new Response(null, { status: 200 });
    }
    if (url.hostname.endsWith('.workers.dev') && url.pathname === '/__ankka/install/status') {
      events.push('customer-health');
      expect(request.headers.get('authorization')).toBeNull();
      expect(init?.redirect).toBe('manual');
      if (customer.healthStatus !== 200) return new Response(null, { status: customer.healthStatus });
      return Response.json({
        schemaVersion: 1,
        role: 'customer-gateway-bootstrap',
        status: 'INCOMPLETE',
        installId: customer.installId,
        release: customer.release,
        ownershipPublicKey: CUSTOMER_OWNERSHIP_PUBLIC_KEY,
        failure: null,
      }, { headers: { 'access-control-allow-origin': PUBLIC_ORIGIN, vary: 'Origin' } });
    }
    throw new Error(`unexpected transport ${request.method} ${request.url}`);
  };
  const getAccountWorkersSubdomain: HostedStage1Provider['getAccountWorkersSubdomain'] = async ({ accountId }) => {
    events.push('subdomain-read');
    return Object.freeze({ accountId, subdomain: 'tenant' });
  };
  const deployCustomerBootstrapWorker: HostedStage1Provider['deployCustomerBootstrapWorker'] = async (input) => {
    events.push('worker-deploy');
    return Object.freeze({
        workerId: WORKER_ID,
        workerName: input.workerName,
        namespaceId: NAMESPACE_ID,
        namespaceName: `${input.workerName}_AdminState`,
        deploymentId: DEPLOYMENT_ID,
        versionId: VERSION_ID,
        release: input.release.release,
        artifactSha256: input.release.artifactSha256,
        bootstrapComponentSha256: input.release.componentSha256,
        sourceSha256: input.release.worker.modules[0]?.sha256 ?? '',
        recovery: 'created' as const,
    });
  };
  const setWorkerBootstrapSubdomain: HostedStage1Provider['setWorkerBootstrapSubdomain'] = async () => {
    events.push('subdomain-enable');
    return Object.freeze({ enabled: true, previewsEnabled: false as const });
  };
  const verifyWorkerBootstrapSubdomain: HostedStage1Provider['verifyWorkerBootstrapSubdomain'] = async () => {
    events.push('subdomain-verify');
    return Object.freeze({ enabled: true, previewsEnabled: false as const });
  };
  const stage1Provider: HostedStage1Provider = Object.freeze({
    getAccountWorkersSubdomain,
    deployCustomerBootstrapWorker,
    setWorkerBootstrapSubdomain,
    verifyWorkerBootstrapSubdomain,
  });
  const cleanupExecutor: TwoStageCleanupExecutor = {
    execute: async (input) => {
      expect(input.bundle.manifest.release).toBe('gateway-v1.2.3');
      expect(input.customerOauthClientId).toBe(CUSTOMER_CLIENT_ID);
      cleanupCalls.push({ code: input.code, verifier: input.verifier, phase: input.session.phase });
      events.push('cleanup-executed');
    },
  };
  const dependencies: TwoStageRuntimeDependencies = {
    now: () => clock.now,
    randomBytes,
    transport,
    abuseControlPolicy: options.policy ?? 'disabled',
    releaseBundleProvider: bundleProvider(release.bundle),
    stage1Provider,
    cleanupExecutor,
  };
  const allow = { limit: async () => ({ success: true }) } satisfies RateLimit;
  const env: TwoStageDeployEnv = {
    TWO_STAGE_DEPLOY_SESSION: namespace,
    GATEWAY_RELEASE_BUCKET: inertBucket(),
    CLOUDFLARE_OAUTH_CLIENT_ID: CLIENT_ID,
    CLOUDFLARE_OAUTH_CLIENT_SECRET: CLIENT_SECRET,
    CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID: CUSTOMER_CLIENT_ID,
    DEPLOY_SESSION_ENCRYPTION_KEY: ENCRYPTION_KEY,
    CLOUDFLARE_OWNERSHIP_ISSUER_PRIVATE_KEY: issuer.seed,
    CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY: issuer.publicKey,
    CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID: ISSUER_KEY_ID,
    ANONYMOUS_SESSION_RATE_LIMIT: allow,
    SESSION_READ_RATE_LIMIT: allow,
    SESSION_MUTATION_RATE_LIMIT: allow,
  };
  return { worker: createTwoStageDeployRuntime(release.pin, dependencies), env, clock, events, customer, namespace, cleanupCalls };
}

interface Browser {
  sessionCookie: string;
  bootstrapCookie: string | null;
  csrfToken: string;
}

async function parsed<Schema extends v.GenericSchema>(response: Response, schema: Schema): Promise<v.InferOutput<Schema>> {
  return v.parse(schema, await response.json());
}

function cookieHeader(browser: Browser): string {
  return browser.bootstrapCookie === null ? browser.sessionCookie : `${browser.sessionCookie}; ${browser.bootstrapCookie}`;
}

function absorbCookies(browser: Browser, response: Response): void {
  const setCookie = response.headers.get('set-cookie');
  if (setCookie === null) return;
  for (const part of setCookie.split(/,(?=\s*__Host-)/u)) {
    const trimmed = part.trim();
    if (trimmed.startsWith(`${BOOTSTRAP_COOKIE}=`)) {
      browser.bootstrapCookie = trimmed.includes('Max-Age=0') ? null : cookiePair(trimmed, BOOTSTRAP_COOKIE);
    } else if (trimmed.startsWith(`${SESSION_COOKIE}=`)) {
      browser.sessionCookie = cookiePair(trimmed, SESSION_COOKIE);
    }
  }
}

async function openSession(h: Harness): Promise<Browser> {
  const response = await h.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
    headers: { 'cf-connecting-ip': '203.0.113.7' },
  }), h.env);
  expect(response.status).toBe(200);
  const body = await parsed(response, sessionResponseSchema);
  const browser: Browser = { sessionCookie: '', bootstrapCookie: null, csrfToken: body.csrfToken };
  absorbCookies(browser, response);
  expect(browser.sessionCookie.startsWith(`${SESSION_COOKIE}=`)).toBe(true);
  return browser;
}

async function mutate(
  h: Harness,
  browser: Browser,
  method: string,
  path: string,
  body?: BoundaryObject,
): Promise<Response> {
  const headers = new Headers({
    cookie: cookieHeader(browser),
    origin: PUBLIC_ORIGIN,
    'sec-fetch-site': 'same-origin',
    'x-csrf-token': browser.csrfToken,
    'cf-connecting-ip': '203.0.113.7',
  });
  const init: RequestInit = { method, headers };
  if (body !== undefined) {
    headers.set('content-type', 'application/json');
    init.body = JSON.stringify(body);
  }
  const response = await h.worker.fetch(new Request(`${PUBLIC_ORIGIN}${path}`, init), h.env);
  absorbCookies(browser, response);
  return response;
}

async function read(h: Harness, browser: Browser, path: string): Promise<Response> {
  const response = await h.worker.fetch(new Request(`${PUBLIC_ORIGIN}${path}`, {
    headers: { cookie: cookieHeader(browser), 'cf-connecting-ip': '203.0.113.7' },
  }), h.env);
  absorbCookies(browser, response);
  return response;
}

async function currentPhase(h: Harness, browser: Browser) {
  const body = await parsed(await read(h, browser, '/api/session'), sessionResponseSchema);
  return body.session;
}

async function authorized(h: Harness): Promise<{ browser: Browser; state: string; authorizationUrl: URL }> {
  const browser = await openSession(h);
  expect((await mutate(h, browser, 'PUT', '/api/selection', selectionInput)).status).toBe(200);
  expect((await mutate(h, browser, 'POST', '/api/plan', {})).status).toBe(200);
  const bootstrap = await mutate(h, browser, 'POST', '/api/bootstrap', {});
  expect(bootstrap.status).toBe(200);
  const body = await parsed(bootstrap, bootstrapResponseSchema);
  const authorizationUrl = new URL(body.authorizationUrl);
  const state = authorizationUrl.searchParams.get('state') ?? '';
  expect(browser.bootstrapCookie).not.toBeNull();
  return { browser, state, authorizationUrl };
}

async function callback(h: Harness, browser: Browser, query: string): Promise<Response> {
  return read(h, browser, `/oauth/callback?${query}`);
}

describe('clean hosted two-stage runtime', () => {
  it('serves the pinned public update descriptor token-free from the bucket alone', async () => {
    const h = await harness();
    // Installed Gateways poll this route for self-update; it must not depend on
    // any session, grant, or issuer binding, so every other binding is absent.
    // SAFETY: the descriptor route must succeed with every non-bucket binding missing; the cast expresses that gap.
    const bucketOnly = Object.freeze({ GATEWAY_RELEASE_BUCKET: h.env.GATEWAY_RELEASE_BUCKET }) as TwoStageDeployEnv;
    const descriptor = await h.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/releases/canary`), bucketOnly);
    expect(descriptor.status).toBe(200);
    expect(descriptor.headers.get('set-cookie')).toBeNull();
    expect(descriptor.headers.get('cache-control')).toBe('no-store');
    expect(descriptor.headers.get('content-type')).toBe('application/json; charset=utf-8');
    const channel = parsePublicUpdateChannel(await descriptor.json());
    expect(channel.channel).toBe('canary');
    expect(channel.release.id).toBe('gateway-v1.2.3');

    const other = await h.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/releases/stable`), h.env);
    expect(other.status).toBe(404);
    expect(await other.json()).toEqual({ code: 'release_unavailable' });
    const posted = await h.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/releases/canary`, { method: 'POST' }), h.env);
    expect(posted.status).toBe(405);
    const queried = await h.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/releases/canary?channel=stable`), h.env);
    expect(queried.status).toBe(404);
    expect(await queried.json()).toEqual({ code: 'bad_request' });
    const unknown = await h.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/releases/beta`), h.env);
    expect(unknown.status).toBe(404);
  });

  it('serves the pinned bundle files token-free for a Gateway that updates itself', async () => {
    const h = await harness();
    // SAFETY: the files route must succeed with every non-bucket binding missing; the cast expresses that gap.
    const bucketOnly = Object.freeze({ GATEWAY_RELEASE_BUCKET: h.env.GATEWAY_RELEASE_BUCKET }) as TwoStageDeployEnv;
    // The fixture bundle's worker module, byte for byte.
    const expected = '// ankka-control-plane-origin:https://deploy.ankka.ai\nexport default{fetch(){return new Response("ready")}};';
    const file = await h.worker.fetch(
      new Request(`${PUBLIC_ORIGIN}/api/releases/canary/files/payload/worker/index.js`),
      bucketOnly,
    );
    expect(file.status).toBe(200);
    expect(file.headers.get('set-cookie')).toBeNull();
    expect(file.headers.get('cache-control')).toBe('no-store');
    expect(file.headers.get('content-type')).toBe('application/javascript+module');
    expect(file.headers.get('content-length')).toBe(String(encoder.encode(expected).byteLength));
    expect(await file.text()).toBe(expected);

    for (const path of [
      '/api/releases/stable/files/payload/worker/index.js',
      '/api/releases/canary/files/payload/worker/missing.js',
      '/api/releases/canary/files/payload/../worker/index.js',
      '/api/releases/canary/files/manifest.json',
    ]) {
      const missing = await h.worker.fetch(new Request(`${PUBLIC_ORIGIN}${path}`), h.env);
      expect(missing.status).toBe(404);
    }
    const posted = await h.worker.fetch(
      new Request(`${PUBLIC_ORIGIN}/api/releases/canary/files/payload/worker/index.js`, { method: 'POST' }),
      h.env,
    );
    expect(posted.status).toBe(405);
    const queried = await h.worker.fetch(
      new Request(`${PUBLIC_ORIGIN}/api/releases/canary/files/payload/worker/index.js?x=1`),
      h.env,
    );
    expect(queried.status).toBe(404);
  });

  it('walks selection, plan, one temporary approval, callback provisioning, and token-free handoff', async () => {
    const h = await harness();
    const health = await h.worker.fetch(new Request(`${PUBLIC_ORIGIN}/health`), h.env);
    expect(await health.json()).toEqual({ ok: true, mutationsEnabled: true });

    const { browser, state, authorizationUrl } = await authorized(h);
    expect(authorizationUrl.origin).toBe('https://dash.cloudflare.com');
    expect(authorizationUrl.searchParams.get('scope')).toBe('workers-scripts.write');
    expect(authorizationUrl.searchParams.get('code_challenge_method')).toBe('S256');
    expect(authorizationUrl.searchParams.get('client_id')).toBe(CLIENT_ID);
    const authorizing = await currentPhase(h, browser);
    expect(authorizing.phase).toBe('authorizing');
    expect(authorizing.plan?.releaseId).toBe('gateway-v1.2.3');

    h.clock.now = NOW + 30_000;
    const provisioned = await callback(h, browser, `code=${AUTHORIZATION_CODE}&state=${state}`);
    expect(provisioned.status).toBe(303);
    expect(provisioned.headers.get('location')).toBe(`${PUBLIC_ORIGIN}/result`);
    expect(provisioned.headers.get('set-cookie')).toBeNull();
    expect(browser.bootstrapCookie).not.toBeNull();
    expect(h.events).toEqual([
      'token-exchange', 'account-read', 'subdomain-read', 'worker-deploy',
      'subdomain-enable', 'subdomain-verify', 'revoke',
    ]);
    const afterCallback = await currentPhase(h, browser);
    expect(afterCallback.phase).toBe('provisioned');
    expect(afterCallback.provision?.bootstrapOrigin).toMatch(/^https:\/\/ankka-gateway-.*\.tenant\.workers\.dev\/$/u);
    h.customer.installId = afterCallback.provision?.installId ?? '';
    h.customer.release = afterCallback.plan?.releaseId ?? '';

    const replay = await callback(h, browser, `code=${AUTHORIZATION_CODE}&state=${state}`);
    expect(replay.status).toBe(409);
    expect(await parsed(replay, errorSchema)).toEqual({ code: 'callback_invalid' });
    expect(browser.bootstrapCookie).not.toBeNull();
    expect(h.events.filter((event) => event === 'token-exchange')).toHaveLength(1);

    const notReady = await read(h, browser, '/api/bootstrap/handoff');
    expect(notReady.status).toBe(503);
    expect(await parsed(notReady, handoffResponseSchema)).toMatchObject({
      code: 'bootstrap_not_ready', status: 'not_ready', retryAfterMs: 3_000, reason: 'readiness_http_404',
    });
    expect(notReady.headers.get('set-cookie')).toBeNull();
    expect(browser.bootstrapCookie).not.toBeNull();

    h.customer.healthStatus = 200;
    const ready = await read(h, browser, '/api/bootstrap/handoff');
    expect(ready.status).toBe(200);
    const body = await parsed(ready, handoffResponseSchema);
    expect(body.status).toBe('ready');
    const handoffUrl = new URL(body.handoffUrl ?? '');
    expect(handoffUrl.origin).toBe(afterCallback.provision?.bootstrapOrigin.slice(0, -1));
    expect(handoffUrl.pathname).toBe('/__ankka/install');
    expect(handoffUrl.search).toBe('');
    const fragment = v.parse(v.looseObject({ bootstrapId: v.string(), secret: v.string() }),
      JSON.parse(new TextDecoder().decode(base64UrlDecode(handoffUrl.hash.slice(1)))));
    expect(fragment.secret).toHaveLength(43);
    expect(browser.bootstrapCookie).toBeNull();
    expect((await currentPhase(h, browser)).phase).toBe('handed_off');
    for (const state of h.namespace.states.values()) {
      const stored = state.storage.sqlFake.state?.stateJson ?? '';
      expect(stored).not.toContain(fragment.secret);
      expect(stored).not.toContain(ACCESS_TOKEN);
      expect(stored).not.toContain(AUTHORIZATION_CODE);
    }
    expect((await read(h, browser, '/api/bootstrap/handoff')).status).toBe(400);
  });

  it('records a denied approval and a failed exchange as failed attempts and lets the user start fresh', async () => {
    const denied = await harness();
    const first = await authorized(denied);
    const deniedResponse = await callback(denied, first.browser, `error=access_denied&error_description=user&state=${first.state}`);
    expect(deniedResponse.status).toBe(303);
    expect(first.browser.bootstrapCookie).toBeNull();
    expect(denied.events).toEqual([]);
    const afterDenied = await currentPhase(denied, first.browser);
    expect(afterDenied).toMatchObject({ phase: 'failed', failure: { code: 'authorization_rejected' } });
    const again = await mutate(denied, first.browser, 'POST', '/api/bootstrap', {});
    expect(again.status).toBe(200);
    expect((await currentPhase(denied, first.browser)).phase).toBe('authorizing');

    const failed = await harness();
    failed.customer.tokenStatus = 400;
    const second = await authorized(failed);
    const failedResponse = await callback(failed, second.browser, `code=${AUTHORIZATION_CODE}&state=${second.state}`);
    expect(failedResponse.status).toBe(303);
    expect(second.browser.bootstrapCookie).toBeNull();
    expect(failed.events).toEqual(['token-exchange']);
    expect(await currentPhase(failed, second.browser)).toMatchObject({
      phase: 'failed',
      failure: { code: 'provision_failed', reason: expect.stringMatching(/^[a-z][a-z0-9_]{0,159}$/u) },
    });
  });

  it('rejects callbacks whose state, cookie, or query do not match exactly, before any exchange', async () => {
    const h = await harness();
    const { browser, state } = await authorized(h);
    const savedCookie = browser.bootstrapCookie;
    const cases = [
      `code=${AUTHORIZATION_CODE}&state=${'z'.repeat(43)}`,
      `code=${AUTHORIZATION_CODE}&state=${state}&extra=1`,
      `code=short&state=${state}`,
      `state=${state}`,
      `code=${AUTHORIZATION_CODE}&code=${AUTHORIZATION_CODE}&state=${state}`,
      `code=${AUTHORIZATION_CODE}&state=${state}&scope=workers-scripts.write%20zone.read`,
    ];
    for (const query of cases) {
      browser.bootstrapCookie = savedCookie;
      const response = await callback(h, browser, query);
      expect(response.status, query).toBe(400);
      expect(await parsed(response, errorSchema)).toEqual({ code: 'callback_invalid' });
    }
    browser.bootstrapCookie = null;
    const missingCookie = await callback(h, browser, `code=${AUTHORIZATION_CODE}&state=${state}`);
    expect(missingCookie.status).toBe(400);
    expect(h.events).toEqual([]);
    expect((await currentPhase(h, browser)).phase).toBe('authorizing');

    browser.bootstrapCookie = savedCookie;
    h.clock.now = NOW + 11 * 60_000;
    const expired = await callback(h, browser, `code=${AUTHORIZATION_CODE}&state=${state}`);
    expect(expired.status).toBe(400);
    expect(await parsed(expired, errorSchema)).toEqual({ code: 'session_expired' });
    expect(browser.bootstrapCookie).toBeNull();
    expect(h.events).toEqual([]);
  });

  it('turns a rejected customer read-back into cleanup and runs the cleanup approval through the same callback', async () => {
    const h = await harness();
    const { browser, state } = await authorized(h);
    expect((await callback(h, browser, `code=${AUTHORIZATION_CODE}&state=${state}`)).status).toBe(303);
    h.customer.healthStatus = 200;
    h.customer.installId = `acg-${'0'.repeat(24)}`;
    h.customer.release = 'gateway-v1.2.3';
    const rejected = await read(h, browser, '/api/bootstrap/handoff');
    expect(rejected.status).toBe(502);
    expect(await parsed(rejected, v.strictObject({ code: v.string(), reason: v.string() }))).toEqual({
      code: 'bootstrap_failed', reason: 'readiness_install_id_mismatch',
    });
    expect(browser.bootstrapCookie).toBeNull();
    expect(await currentPhase(h, browser)).toMatchObject({
      phase: 'cleanup_required', cleanup: { reason: 'handoff_rejected', completedAt: null },
    });
    expect((await mutate(h, browser, 'POST', '/api/bootstrap', {})).status).toBe(409);

    const cleanup = await mutate(h, browser, 'POST', '/api/cleanup', {});
    expect(cleanup.status).toBe(200);
    const cleanupBody = await parsed(cleanup, bootstrapResponseSchema);
    const cleanupState = new URL(cleanupBody.authorizationUrl).searchParams.get('state') ?? '';
    expect(browser.bootstrapCookie).not.toBeNull();
    const cleaned = await callback(h, browser, `code=${AUTHORIZATION_CODE}&state=${cleanupState}`);
    expect(cleaned.status).toBe(303);
    expect(browser.bootstrapCookie).toBeNull();
    expect(h.cleanupCalls).toEqual([{ code: AUTHORIZATION_CODE, verifier: expect.any(String), phase: 'cleanup_required' }]);
    expect(await currentPhase(h, browser)).toMatchObject({
      phase: 'draft', plan: null, provision: null, cleanup: { reason: 'handoff_rejected', completedAt: expect.any(Number) },
    });
  });

  it('enforces the route allowlist, same-origin mutation headers, CSRF, and JSON bodies', async () => {
    const h = await harness();
    const browser = await openSession(h);
    const noOrigin = await h.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/selection`, {
      method: 'PUT',
      headers: { cookie: cookieHeader(browser), 'x-csrf-token': browser.csrfToken, 'content-type': 'application/json' },
      body: JSON.stringify(selectionInput),
    }), h.env);
    expect(noOrigin.status).toBe(403);
    expect(await parsed(noOrigin, errorSchema)).toEqual({ code: 'origin_invalid' });
    const badCsrf = await mutate(h, { ...browser, csrfToken: 'x'.repeat(43) }, 'PUT', '/api/selection', selectionInput);
    expect(badCsrf.status).toBe(403);
    expect(await parsed(badCsrf, errorSchema)).toEqual({ code: 'csrf_invalid' });
    const badBody = await mutate(h, browser, 'PUT', '/api/selection', { schemaVersion: 1, basics: {} });
    expect(badBody.status).toBe(400);
    const noSession = await h.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/plan`, {
      method: 'POST', headers: { origin: PUBLIC_ORIGIN, 'x-csrf-token': browser.csrfToken },
    }), h.env);
    expect(noSession.status).toBe(401);
    const planWithoutSelection = await mutate(h, browser, 'POST', '/api/plan', {});
    expect(planWithoutSelection.status).toBe(409);
    const bootstrapWithoutPlan = await mutate(h, browser, 'POST', '/api/bootstrap', {});
    expect(bootstrapWithoutPlan.status).toBe(409);

    const routes: readonly (readonly [string, string, number])[] = [
      ['GET', '/api/discovery', 404],
      ['POST', '/api/discovery', 404],
      ['GET', '/api/selection', 405],
      ['POST', '/api/session', 405],
      ['GET', '/api/session?x=1', 404],
      ['GET', '/api/oauth/handoff', 404],
      ['GET', '/', 200],
      ['GET', '/gateway', 200],
      ['GET', '/result', 200],
      ['GET', '/assets/app-A1b2C3d4.js', 200],
      ['GET', '/assets/missing.js', 404],
      ['POST', '/gateway', 405],
    ];
    for (const [method, path, status] of routes) {
      const response = await h.worker.fetch(new Request(`${PUBLIC_ORIGIN}${path}`, {
        method, headers: { cookie: cookieHeader(browser), 'cf-connecting-ip': '203.0.113.7' },
      }), h.env);
      expect(response.status, `${method} ${path}`).toBe(status);
    }
    const html = await h.worker.fetch(new Request(`${PUBLIC_ORIGIN}/deploy`), h.env);
    expect(html.headers.get('content-type')).toBe('text/html; charset=utf-8');
    expect(await html.text()).toContain('two-stage installer');
  });

  it('applies rate limits and authenticated session ids when abuse controls are required', async () => {
    const h = await harness({ policy: 'required' });
    const browser = await openSession(h);
    expect((await mutate(h, browser, 'PUT', '/api/selection', selectionInput)).status).toBe(200);
    const forged = { ...browser, sessionCookie: `${SESSION_COOKIE}=${'f'.repeat(43)}` };
    const response = await read(h, forged, '/api/session');
    expect(response.status).toBe(401);
    const limited: TwoStageDeployEnv = {
      ...h.env,
      SESSION_MUTATION_RATE_LIMIT: { limit: async () => ({ success: false }) },
    };
    const throttled = await h.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/plan`, {
      method: 'POST',
      headers: {
        cookie: cookieHeader(browser), origin: PUBLIC_ORIGIN, 'x-csrf-token': browser.csrfToken,
        'cf-connecting-ip': '203.0.113.7', 'content-type': 'application/json',
      },
      body: '{}',
    }), limited);
    expect(throttled.status).toBe(429);
    const anonymousWithoutAddress = await h.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`), h.env);
    expect(anonymousWithoutAddress.status).toBe(503);
  });

  it('keeps the disabled entrypoint zero-write and binding-free', async () => {
    let dependencyRead = false;
    const dependencies: TwoStageRuntimeDependencies = {
      get releaseBundleProvider(): R2ReleaseBundleProvider {
        dependencyRead = true;
        throw new Error('disabled activation read a runtime dependency');
      },
    };
    const worker = createTwoStageDeployEntrypoint({ enabled: false, pin: null }, dependencies);
    // SAFETY: every property read on the proxy throws, so the empty target is never observed as an env.
    const poisoned = new Proxy({} as TwoStageDeployEnv, {
      get() {
        throw new Error('disabled shell touched an environment binding');
      },
    });
    const health = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/health`), poisoned);
    expect(await health.json()).toEqual({ ok: true, mutationsEnabled: false });
    for (const path of ['/', '/api/session', '/oauth/callback?code=x&state=y', '/api/bootstrap/handoff']) {
      const response = await worker.fetch(new Request(`${PUBLIC_ORIGIN}${path}`, { method: 'GET' }), poisoned);
      expect(response.status, path).toBe(503);
      expect(await response.json()).toEqual({ code: 'release_unavailable' });
    }
    expect(dependencyRead).toBe(false);
    // SAFETY: the activation type forbids this shape; the assertion exists to prove the runtime parser rejects it.
    expect(() => createTwoStageDeployEntrypoint({ enabled: true, pin: null } as never, dependencies))
      .toThrow(DeployError);
  });
});
