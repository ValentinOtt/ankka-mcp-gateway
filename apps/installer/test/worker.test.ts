import {
  DISCOVERY_OAUTH_SCOPES,
  OAUTH_COOKIE,
  PUBLIC_ORIGIN,
  REQUIRED_OAUTH_SCOPES,
  SESSION_COOKIE,
  SESSION_TTL_MS,
} from '../src/constants';
import { openOauthCookie, sha256, sha256Hex } from '../src/crypto';
import { DeployError } from '../src/errors';
import { createGatewayDeployWorker } from '../src/index';
import { boundaryObjectSchema } from '../src/boundary';
import { canonicalJson } from '../src/canonical-json';
import {
  computeInstallJournalBindingHash,
  MAX_INSTALL_RECOVERY_RETENTION_MS,
} from '../src/install-journal';
import type { FetchTransport } from '../src/oauth';
import type { InstallExecutor } from '../src/install-executor';
import type { GatewayDeploySessionNamespace } from '../src/env';
import { buildStaticDeployPlan, parseDeploySelection, parseStaticDeployPlan, type StaticDeployPlan } from '../src/schema';
import type { AuthorizedTarget } from '../src/cloudflare-target';
import { deriveCustomerGatewayExpectedProjection } from '../src/customer-bootstrap-request';
import { UNCONFIRMED_GRANT_REVOCATION_DETAIL } from '../src/installer-contract';
import { publicSession, requireStoredSession, type StoredDeploySession } from '../src/session';
import {
  CLIENT_SECRET,
  BOOTSTRAP_NONCE_KEY,
  cookiePair,
  ENCRYPTION_KEY,
  env,
  FakeDeploySessionNamespace,
  internalRequest,
  manifest,
  NOW,
  releaseProvider,
  requiredFixture,
  selectionInput,
  verifiedReleaseBundle,
} from './fixtures';
import { requestJson, responseJson } from './boundary';

interface BrowserSession {
  cookie: string;
  csrf: string;
}

const csrfResponseSchema = v.object({ csrf: v.string() });
const planResponseSchema = v.object({
  plan: v.object({
    planId: v.string(),
    planHash: v.string(),
    expiresAt: v.string(),
  }),
});
const successfulCompletionSchema = v.strictObject({
  attemptId: v.string(),
  code: v.literal('install_complete'),
  completedAt: v.number(),
  installationId: v.string(),
  grantRevocation: v.picklist(['confirmed', 'unconfirmed']),
  reason: v.null(),
});
type SuccessfulCompletion = v.InferOutput<typeof successfulCompletionSchema>;
const authorizationResponseSchema = v.object({ authorizationUrl: v.string() });
const authorizationHandoffResponseSchema = v.object({
  authorizationUrl: v.string(),
  handoffUrl: v.string(),
});
const discoveryReadyResponseSchema = v.object({
  schemaVersion: v.literal(1),
  status: v.literal('ready'),
  actorEmail: v.string(),
  grantRevocation: v.picklist(['confirmed', 'unconfirmed']),
  targets: v.array(v.object({
    accountName: v.string(),
    zoneName: v.string(),
    targetIdHash: v.string(),
  })),
});
const deploymentFailureResponseSchema = v.object({
  deployment: v.object({
    failure: v.object({ code: v.string(), detail: v.string() }),
  }),
});
const deploymentViewResponseSchema = v.object({
  recovery: v.nullable(v.object({ status: v.string(), expiresAt: v.string() })),
  deployment: v.object({
    status: v.string(),
    failure: v.nullable(v.object({ code: v.string(), detail: v.string() })),
    canRetry: v.boolean(),
    receipt: v.nullable(v.object({
      receiptId: v.string(),
      managementUrl: v.nullable(v.string()),
      portalUrl: v.nullable(v.string()),
    })),
    operations: v.array(v.object({
      id: v.string(),
      label: v.string(),
      detail: v.nullable(v.string()),
      status: v.string(),
    })),
  }),
});
const renewedPlanResponseSchema = v.object({
  recovery: v.object({ status: v.string(), expiresAt: v.string() }),
  plan: v.object({ planId: v.string(), planHash: v.string(), expiresAt: v.string() }),
});

async function createBrowserSession(
  worker: ReturnType<typeof createGatewayDeployWorker>,
  workerEnv: ReturnType<typeof env>,
): Promise<BrowserSession> {
  const response = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`), workerEnv, undefined);
  const payload = await responseJson(response, csrfResponseSchema);
  return {
    cookie: cookiePair(response.headers.get('set-cookie') ?? '', SESSION_COOKIE),
    csrf: payload.csrf,
  };
}

function mutationHeaders(session: BrowserSession) {
  return {
    origin: PUBLIC_ORIGIN,
    'sec-fetch-site': 'same-origin',
    'x-csrf-token': session.csrf,
    cookie: session.cookie,
    'content-type': 'application/json',
  };
}

async function saveAndPlan(
  worker: ReturnType<typeof createGatewayDeployWorker>,
  workerEnv: ReturnType<typeof env>,
  browser: BrowserSession,
) {
  const saved = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/selection`, {
    method: 'PUT',
    headers: mutationHeaders(browser),
    body: JSON.stringify(selectionInput),
  }), workerEnv, undefined);
  expect(saved.status).toBe(200);
  const preview = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/plan`, {
    method: 'POST',
    headers: mutationHeaders(browser),
  }), workerEnv, undefined);
  const payload = await responseJson(preview, planResponseSchema);
  return { response: preview, plan: payload.plan };
}

function browserSessionId(browser: BrowserSession): string {
  const value = browser.cookie.slice(browser.cookie.indexOf('=') + 1);
  if (!/^[A-Za-z0-9_-]{43}$/u.test(value)) throw new Error('invalid test session id');
  return value;
}

const RECOVERY_TARGET: AuthorizedTarget = Object.freeze({
  actor: Object.freeze({ id: 'actor-test', email: 'owner@example.com' }),
  account: Object.freeze({ id: '1'.repeat(32), name: 'Disposable account' }),
  zone: Object.freeze({ id: '2'.repeat(32), name: 'example.com', status: 'active' }),
});

interface RecoveryFixture {
  browser: BrowserSession;
  namespace: FakeDeploySessionNamespace;
  plan: StaticDeployPlan;
  recoverUntil: number;
  staleOauthPair: string;
  staleState: string;
  worker: ReturnType<typeof createGatewayDeployWorker>;
  workerEnv: ReturnType<typeof env>;
  setNow(value: number): void;
}

async function recoveryFixture(armFirstWrite: boolean): Promise<RecoveryFixture> {
  let currentTime = NOW;
  const namespace = new FakeDeploySessionNamespace(() => currentTime);
  const workerEnv = env(namespace);
  const worker = createGatewayDeployWorker({ now: () => currentTime, releaseProvider });
  const browser = await createBrowserSession(worker, workerEnv);
  const preview = await saveAndPlan(worker, workerEnv, browser);
  const deploy = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/deploy`, {
    method: 'POST',
    headers: mutationHeaders(browser),
    body: JSON.stringify({ planId: preview.plan.planId, planHash: preview.plan.planHash }),
  }), workerEnv, undefined);
  expect(deploy.status).toBe(200);
  const authorization = await responseJson(deploy, authorizationResponseSchema);
  const authorizationUrl = new URL(authorization.authorizationUrl);
  const state = authorizationUrl.searchParams.get('state');
  if (!state || !/^[A-Za-z0-9_-]{43}$/u.test(state)) throw new Error('invalid OAuth state');
  const oauthPair = cookiePair(deploy.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
  const sealed = await openOauthCookie(ENCRYPTION_KEY, oauthPair.slice(oauthPair.indexOf('=') + 1));
  if (sealed.schemaVersion !== 3) throw new Error('unexpected OAuth cookie schema');
  const sessionId = browserSessionId(browser);
  const object = namespace.objects.get(sessionId);
  if (!object) throw new Error('missing test Durable Object');
  const consumed = await object.fetch(internalRequest('/consume', 'POST', {
    attemptId: sealed.attemptId,
    stateHash: await sha256(state),
    verifierHash: await sha256(sealed.verifier),
    now: NOW + 1,
  }));
  expect(consumed.status).toBe(200);
  const consumedBody = await responseJson(consumed, boundaryObjectSchema);
  const plan = parseStaticDeployPlan(consumedBody.plan);
  const selection = parseDeploySelection(selectionInput);
  const installationDigest = await sha256Hex(canonicalJson({
    accountId: RECOVERY_TARGET.account.id,
    hostname: selection.basics.portalHostname,
    zoneId: RECOVERY_TARGET.zone.id,
  }));
  const installationId = `acg-${installationDigest.slice(0, 24)}`;
  const bindingHash = await computeInstallJournalBindingHash({
    selection,
    plan,
    releasePin: {
      verification: 'ed25519',
      keyId: 'test-key',
      release: manifest.release,
      artifactSha256: manifest.artifact.treeSha256,
    },
    target: RECOVERY_TARGET,
    installationId,
  });
  const recoverUntil = NOW + SESSION_TTL_MS + MAX_INSTALL_RECOVERY_RETENTION_MS;
  const projection = await deriveCustomerGatewayExpectedProjection({
    selection,
    target: RECOVERY_TARGET,
    plan,
    release: { id: manifest.release, artifactSha256: manifest.artifact.treeSha256 },
  });
  const preflightCheckedAt = NOW;
  const preflightUnsigned = {
    schemaVersion: 1 as const,
    kind: 'customer_gateway_fresh_preflight' as const,
    accountId: RECOVERY_TARGET.account.id,
    zoneId: RECOVERY_TARGET.zone.id,
    planId: plan.planId,
    planHash: plan.planHash,
    installationId,
    configurationHash: projection.expected.configurationHash,
    desiredHash: projection.expected.desiredHash,
    releaseId: manifest.release,
    releaseArtifactSha256: manifest.artifact.treeSha256,
    zeroCandidateKinds: projection.resourceKinds,
    checkedAt: preflightCheckedAt,
    expiresAt: preflightCheckedAt + 30_000,
  };
  const initialized = await object.fetch(internalRequest('/install-journal/initialize', 'POST', {
    schemaVersion: 1,
    now: NOW + 2,
    recoverUntil,
    selection,
    plan,
    releasePin: {
      verification: 'ed25519',
      keyId: 'test-key',
      release: manifest.release,
      artifactSha256: manifest.artifact.treeSha256,
    },
    target: RECOVERY_TARGET,
    installationId,
    bindingHash,
    gatewayFreshPreflight: {
      ...preflightUnsigned,
      attestationHash: `sha256:${await sha256Hex(canonicalJson(preflightUnsigned))}`,
    },
  }));
  expect(initialized.status).toBe(201);

  const acquired = await object.fetch(internalRequest('/install-journal/lease/acquire', 'POST', {
    expectedRevision: 0,
    attemptId: sealed.attemptId,
    now: NOW + 3,
    leaseExpiresAt: NOW + 100_000,
  }));
  expect(acquired.status).toBe(200);
  const workerResource = plan.managementResources.find((resource) => resource.kind === 'management_worker');
  if (!workerResource) throw new Error('missing management worker');
  const workerCore = {
    logpush: false,
    name: workerResource.name,
    observability: { enabled: false },
    subdomain: { enabled: false, previews_enabled: false },
    tags: ['ankka-mcp-gateway'],
    tail_consumers: [],
  };
  const requestHash = await sha256Hex(canonicalJson(workerCore));
  const prepared = await object.fetch(internalRequest('/install-journal/action/prepare', 'POST', {
    expectedRevision: 1,
    attemptId: sealed.attemptId,
    now: NOW + 4,
    action: 'worker_create',
    record: {
      schemaVersion: 1,
      kind: 'worker_create',
      accountId: RECOVERY_TARGET.account.id,
      workerName: workerResource.name,
      requestHash,
      correlationTag: `ankka-worker-sha256:${requestHash}`,
    },
  }));
  expect(prepared.status).toBe(200);
  if (armFirstWrite) {
    const armed = await object.fetch(internalRequest('/install-journal/action/arm', 'POST', {
      expectedRevision: 2,
      attemptId: sealed.attemptId,
      now: NOW + 5,
      action: 'worker_create',
    }));
    expect(armed.status).toBe(200);
  }
  return {
    browser,
    namespace,
    plan,
    recoverUntil,
    staleOauthPair: oauthPair,
    staleState: state,
    worker,
    workerEnv,
    setNow(value: number) { currentTime = value; },
  };
}

function successfulTransport(
  calls: Array<{ url: string; body: string }>,
  tokenPayload = {
    token_type: 'Bearer',
    access_token: 'access-token-value-never-persist',
    refresh_token: 'refresh-token-value-never-persist',
    scope: REQUIRED_OAUTH_SCOPES.join(' '),
  },
  revokeStatus = 200,
): FetchTransport {
  return async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    calls.push({ url: url.toString(), body: String(init?.body ?? '') });
    if (url.pathname === '/oauth2/token') {
      expect(new Headers(init?.headers).get('authorization')).toBe(
        `Basic ${btoa(`27cbab94797bd7c22211ec6920fdd913:${CLIENT_SECRET}`)}`,
      );
      return new Response(JSON.stringify(tokenPayload));
    }
    if (url.pathname.endsWith('/user')) {
      return new Response(JSON.stringify({
        success: true,
        result: { id: 'user-12345678', email: 'owner@example.com' },
      }));
    }
    if (url.pathname.endsWith('/accounts')) {
      return new Response(JSON.stringify({
        success: true,
        result: [{ id: 'a'.repeat(32), name: 'Disposable account' }],
      }));
    }
    if (url.pathname.endsWith('/zones')) {
      return new Response(JSON.stringify({
        success: true,
        result: [{
          id: 'b'.repeat(32),
          name: 'example.com',
          status: 'active',
          account: { id: 'a'.repeat(32) },
        }],
      }));
    }
    if (url.pathname === '/oauth2/revoke') return new Response('{}', { status: revokeStatus });
    return new Response('{}', { status: 404 });
  };
}

function completionAcceptingNamespace(
  base: FakeDeploySessionNamespace,
  now: () => number,
  completions: SuccessfulCompletion[],
): GatewayDeploySessionNamespace {
  return {
    idFromName: (name: string) => base.idFromName(name),
    get: (id: DurableObjectId) => {
      const delegate = base.get(id);
      const name = id.name;
      if (!name) throw new Error('test Durable Object ID has no name');
      return {
        fetch: async (request: Request) => {
          const pathname = new URL(request.url).pathname;
          if (pathname === '/complete') {
            const completion = await requestJson(request, successfulCompletionSchema);
            completions.push(completion);
            const state = base.states.get(name);
            if (!state) throw new Error('missing test session state');
            const stored = requireStoredSession(state.storage.values.get('deploy-session-v1'));
            const completedAt = now();
            const next: StoredDeploySession = {
              ...stored,
              status: 'succeeded',
              updatedAt: Math.min(completedAt, stored.expiresAt),
              result: {
                code: 'install_complete',
                completedAt,
                installationId: completion.installationId,
                grantRevocation: completion.grantRevocation,
              },
            };
            state.storage.values.set('deploy-session-v1', structuredClone(next));
            return new Response(JSON.stringify({ session: publicSession(next) }), {
              headers: { 'content-type': 'application/json' },
            });
          }
          if (pathname === '/public') {
            const state = base.states.get(name);
            const storedValue = state?.storage.values.get('deploy-session-v1');
            if (storedValue) {
              const stored = requireStoredSession(storedValue);
              if (stored.status === 'succeeded' && stored.result?.code === 'install_complete') {
                const resultUntil = stored.expiresAt + MAX_INSTALL_RECOVERY_RETENTION_MS;
                return new Response(JSON.stringify({
                  session: publicSession(stored),
                  installProgress: null,
                  recovery: null,
                  resultRetention: now() >= stored.expiresAt
                    ? { status: 'result_available', resultUntil }
                    : null,
                  uninstall: null,
                  uninstallRecovery: null,
                }), { headers: { 'content-type': 'application/json' } });
              }
            }
          }
          return delegate.fetch(request);
        },
      };
    },
  };
}

describe('hosted deploy Worker boundary', () => {
  beforeEach(() => {
    vi.spyOn(Date, 'now').mockReturnValue(NOW);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('creates an opaque __Host session and returns only a dedicated CSRF value', async () => {
    const worker = createGatewayDeployWorker({ now: () => NOW });
    const response = await worker.fetch(
      new Request(`${PUBLIC_ORIGIN}/api/session`),
      env(),
      undefined,
    );
    const payload = await responseJson(response, boundaryObjectSchema);
    expect(response.status).toBe(200);
    expect(payload.csrf).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(JSON.stringify(payload)).not.toMatch(/accessToken|refreshToken|clientSecret|verifier/iu);
    const setCookie = response.headers.get('set-cookie') ?? '';
    expect(setCookie).toContain(`${SESSION_COOKIE}=`);
    expect(setCookie).toContain(`Max-Age=${Math.floor((SESSION_TTL_MS + MAX_INSTALL_RECOVERY_RETENTION_MS) / 1000)}`);
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).not.toContain('Domain=');
  });

  it('emits only server-authoritative hosted funnel milestones', async () => {
    const points: AnalyticsEngineDataPoint[] = [];
    const workerEnv = Object.assign(env(), {
      HOSTED_INSTALLER_ANALYTICS: {
        writeDataPoint(point?: AnalyticsEngineDataPoint) {
          points.push(structuredClone(point ?? {}));
        },
      },
      HOSTED_INSTALLER_ANALYTICS_CHANNEL: 'canary',
      HOSTED_INSTALLER_ANALYTICS_RELEASE: 'gateway-v1.2.3',
    });
    const worker = createGatewayDeployWorker({ now: () => NOW, releaseProvider });
    const browser = await createBrowserSession(worker, workerEnv);
    expect(points).toEqual([{
      indexes: ['installer_session_created'],
      blobs: ['gateway-v1.2.3', 'canary', 'none', 'none'],
      doubles: [1],
    }]);

    const rejected = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/selection`, {
      method: 'PUT',
      headers: { ...mutationHeaders(browser), 'x-csrf-token': 'A'.repeat(43) },
      body: JSON.stringify(selectionInput),
    }), workerEnv, undefined);
    expect(rejected.status).toBe(403);
    expect(points).toHaveLength(1);

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const saved = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/selection`, {
        method: 'PUT',
        headers: mutationHeaders(browser),
        body: JSON.stringify(selectionInput),
      }), workerEnv, undefined);
      expect(saved.status).toBe(200);
    }
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const planned = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/plan`, {
        method: 'POST',
        headers: mutationHeaders(browser),
      }), workerEnv, undefined);
      expect(planned.status).toBe(200);
    }
    expect(points.map((point) => point.indexes?.[0])).toEqual([
      'installer_session_created',
      'configuration_saved',
      'install_plan_created',
    ]);
  });

  it('drops a hosted analytics sink failure without changing session creation', async () => {
    const worker = createGatewayDeployWorker({ now: () => NOW });
    const response = await worker.fetch(
      new Request(`${PUBLIC_ORIGIN}/api/session`),
      Object.assign(env(), {
        HOSTED_INSTALLER_ANALYTICS: {
          writeDataPoint() { throw new Error('synthetic analytics failure'); },
        },
        HOSTED_INSTALLER_ANALYTICS_CHANNEL: 'canary',
        HOSTED_INSTALLER_ANALYTICS_RELEASE: 'gateway-v1.2.3',
      }),
      undefined,
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      schemaVersion: 1,
      capabilities: { deploy: false, uninstall: false },
    });
    expect(response.headers.get('set-cookie')).toContain(`${SESSION_COOKIE}=`);
  });

  it('serves only the exact anonymous release channel selected by the reviewed pin', async () => {
    const worker = createGatewayDeployWorker({ now: () => NOW, releaseProvider });
    const stable = await worker.fetch(
      new Request(`${PUBLIC_ORIGIN}/api/releases/stable`),
      env(),
      undefined,
    );
    expect(stable.status).toBe(200);
    expect(stable.headers.get('cache-control')).toBe('no-store');
    expect(await stable.json()).toMatchObject({
      schemaVersion: 1,
      channel: 'stable',
      release: {
        id: verifiedReleaseBundle.manifest.release,
        artifactSha256: `sha256:${verifiedReleaseBundle.manifest.artifact.treeSha256}`,
      },
      classification: { kind: 'normal', updaterProtocol: 2 },
      verification: {
        algorithm: 'ed25519', keyId: verifiedReleaseBundle.keyId,
        signature: verifiedReleaseBundle.envelope.signature,
      },
    });
    const wrongChannel = await worker.fetch(
      new Request(`${PUBLIC_ORIGIN}/api/releases/canary`),
      env(),
      undefined,
    );
    expect(wrongChannel.status).toBe(404);
    expect(await wrongChannel.json()).toEqual({ code: 'release_unavailable' });
  });

  it('requires exact same origin and the CSRF value on every mutation', async () => {
    const workerEnv = env();
    const worker = createGatewayDeployWorker({ now: () => NOW, releaseProvider });
    const browser = await createBrowserSession(worker, workerEnv);
    const crossSite = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/selection`, {
      method: 'PUT',
      headers: {
        ...mutationHeaders(browser),
        origin: 'https://evil.example',
      },
      body: JSON.stringify(selectionInput),
    }), workerEnv, undefined);
    expect(await crossSite.json()).toEqual({ code: 'origin_invalid' });

    const noCsrf = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/selection`, {
      method: 'PUT',
      headers: { origin: PUBLIC_ORIGIN, cookie: browser.cookie, 'content-type': 'application/json' },
      body: JSON.stringify(selectionInput),
    }), workerEnv, undefined);
    expect(await noCsrf.json()).toEqual({ code: 'csrf_invalid' });
  });

  it('synchronizes a retained session after the deployment encryption key rotates', async () => {
    const namespace = new FakeDeploySessionNamespace();
    const workerEnv = env(namespace);
    const worker = createGatewayDeployWorker({ now: () => NOW, releaseProvider });
    const browser = await createBrowserSession(worker, workerEnv);
    const rotatedEnv = {
      ...workerEnv,
      DEPLOY_SESSION_ENCRYPTION_KEY: btoa('\x09'.repeat(32)),
    };
    const refreshed = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: browser.cookie },
    }), rotatedEnv, undefined);
    expect(refreshed.status).toBe(200);
    const refreshedPayload = await responseJson(refreshed, csrfResponseSchema);
    expect(refreshedPayload.csrf).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(refreshedPayload.csrf).not.toBe(browser.csrf);

    const stale = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/discovery`, {
      method: 'POST', headers: mutationHeaders(browser), body: '{}',
    }), rotatedEnv, undefined);
    expect(stale.status).toBe(403);
    expect(await stale.json()).toEqual({ code: 'csrf_invalid' });

    const current = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/discovery`, {
      method: 'POST',
      headers: mutationHeaders({ cookie: browser.cookie, csrf: refreshedPayload.csrf }),
      body: '{}',
    }), rotatedEnv, undefined);
    expect(current.status).toBe(200);
  });

  it('returns only a fixed repair reason for an invalid selection field', async () => {
    const workerEnv = env();
    const worker = createGatewayDeployWorker({ now: () => NOW, releaseProvider });
    const browser = await createBrowserSession(worker, workerEnv);
    const response = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/selection`, {
      method: 'PUT',
      headers: mutationHeaders(browser),
      body: JSON.stringify({
        ...selectionInput,
        basics: { ...selectionInput.basics, adminEmail: '' },
      }),
    }), workerEnv, undefined);
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      code: 'bad_request',
      reason: 'admin_email_invalid',
    });
  });

  it('starts with read-only Cloudflare discovery, revokes it, and exposes only opaque target choices', async () => {
    const namespace = new FakeDeploySessionNamespace();
    const workerEnv = env(namespace);
    const calls: string[] = [];
    const transport: FetchTransport = async (input) => {
      const url = new URL(input instanceof Request ? input.url : input.toString());
      calls.push(url.pathname);
      if (url.pathname === '/oauth2/token') return new Response(JSON.stringify({
        token_type: 'Bearer',
        access_token: 'discovery-access-token-never-persist',
        refresh_token: 'discovery-refresh-token-never-persist',
        scope: DISCOVERY_OAUTH_SCOPES.join(' '),
      }));
      if (url.pathname.endsWith('/user')) return new Response(JSON.stringify({
        success: true,
        result: { id: 'user-12345678', email: 'owner@example.com' },
      }));
      if (url.pathname.endsWith('/accounts')) return new Response(JSON.stringify({
        success: true,
        result: [
          { id: 'a'.repeat(32), name: 'Primary account' },
          { id: 'c'.repeat(32), name: 'Second account' },
        ],
      }));
      if (url.pathname.endsWith('/zones')) {
        const second = url.searchParams.get('account.id') === 'c'.repeat(32);
        return new Response(JSON.stringify({ success: true, result: [{
          id: second ? 'd'.repeat(32) : 'b'.repeat(32),
          name: second ? 'second.example' : 'example.com',
          status: 'active',
          account: { id: second ? 'c'.repeat(32) : 'a'.repeat(32) },
        }] }));
      }
      if (url.pathname === '/oauth2/revoke') return new Response('{}');
      return new Response('{}', { status: 404 });
    };
    const worker = createGatewayDeployWorker({ now: () => NOW, releaseProvider, transport });
    const browser = await createBrowserSession(worker, workerEnv);
    const started = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/discovery`, {
      method: 'POST',
      headers: mutationHeaders(browser),
      body: '{}',
    }), workerEnv, undefined);
    expect(started.status).toBe(200);
    const startedPayload = await responseJson(started, authorizationResponseSchema);
    const authorization = new URL(startedPayload.authorizationUrl);
    expect(authorization.searchParams.get('scope')).toBe(DISCOVERY_OAUTH_SCOPES.join(' '));
    const oauthPair = cookiePair(started.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
    const callback = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${authorization.searchParams.get('state')}`,
      { headers: { cookie: `${browser.cookie}; ${oauthPair}` } },
    ), workerEnv, undefined);
    expect(callback.status, await callback.clone().text()).toBe(303);
    expect(callback.headers.get('location')).toBe(`${PUBLIC_ORIGIN}/`);
    const discovered = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/discovery`, {
      headers: { cookie: browser.cookie },
    }), workerEnv, undefined);
    const payload = await responseJson(discovered, discoveryReadyResponseSchema);
    expect(payload).toMatchObject({
      schemaVersion: 1,
      status: 'ready',
      actorEmail: 'owner@example.com',
      grantRevocation: 'confirmed',
    });
    expect(payload.targets).toEqual([
      { accountName: 'Primary account', zoneName: 'example.com', targetIdHash: expect.stringMatching(/^sha256:/u) },
      { accountName: 'Second account', zoneName: 'second.example', targetIdHash: expect.stringMatching(/^sha256:/u) },
    ]);
    expect(JSON.stringify(payload)).not.toContain('a'.repeat(32));
    expect(JSON.stringify(payload)).not.toContain('b'.repeat(32));
    expect(calls.filter((path) => path === '/oauth2/revoke')).toHaveLength(2);
    expect(namespace.serialized()).not.toMatch(/discovery-(?:access|refresh)-token/iu);
  });

  it('collects config and a zero-write static plan before returning OAuth', async () => {
    const namespace = new FakeDeploySessionNamespace();
    const workerEnv = env(namespace);
    let currentTime = NOW;
    const worker = createGatewayDeployWorker({ now: () => currentTime, releaseProvider });
    const browser = await createBrowserSession(worker, workerEnv);
    const preview = await saveAndPlan(worker, workerEnv, browser);
    expect(preview.response.status).toBe(200);
    expect(preview.plan.planId).toMatch(/^plan-[a-f0-9]{24}$/u);
    currentTime += 1_000;

    const deploy = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/deploy`, {
      method: 'POST',
      headers: mutationHeaders(browser),
      body: JSON.stringify({ planId: preview.plan.planId, planHash: preview.plan.planHash }),
    }), workerEnv, undefined);
    expect(deploy.status).toBe(200);
    const payload = await responseJson(deploy, authorizationHandoffResponseSchema);
    const authorization = new URL(payload.authorizationUrl);
    expect(authorization.origin + authorization.pathname).toBe('https://dash.cloudflare.com/oauth2/auth');
    expect(authorization.searchParams.get('redirect_uri')).toBe('https://deploy.ankka.ai/oauth/callback');
    expect(deploy.headers.get('set-cookie')).toContain(`${OAUTH_COOKIE}=`);
    const sealedPair = cookiePair(deploy.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
    const sealedValue = sealedPair.slice(sealedPair.indexOf('=') + 1);
    await expect(openOauthCookie(ENCRYPTION_KEY, sealedValue)).resolves.toMatchObject({
      schemaVersion: 3,
      state: authorization.searchParams.get('state'),
      expiresAt: Date.parse(preview.plan.expiresAt),
    });
    const handoff = new URL(payload.handoffUrl);
    expect(handoff.origin + handoff.pathname).toBe(`${PUBLIC_ORIGIN}/oauth/handoff`);
    expect(handoff.search).toBe('');
    expect(handoff.hash).toBe(`#${sealedValue}`);
    const exchanged = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/oauth/handoff`, {
      method: 'POST',
      headers: {
        origin: PUBLIC_ORIGIN,
        'sec-fetch-site': 'same-origin',
        'content-type': 'application/json',
      },
      body: JSON.stringify({ handoff: handoff.hash.slice(1) }),
    }), workerEnv, undefined);
    expect(exchanged.status).toBe(200);
    expect(await exchanged.json()).toEqual({ schemaVersion: 1, authorizationUrl: authorization.href });
    expect(exchanged.headers.get('set-cookie')).toContain(`${SESSION_COOKIE}=`);
    expect(exchanged.headers.get('set-cookie')).toContain(`${OAUTH_COOKIE}=`);
    const persisted = namespace.serialized();
    expect(persisted).not.toContain(authorization.searchParams.get('state'));
    expect(persisted).not.toMatch(/access-token|refresh-token|client-secret|codeVerifier/iu);
  });

  it('exchanges in memory and synchronously hands the exact release and same-DO journal port to an injected executor', async () => {
    const namespace = new FakeDeploySessionNamespace();
    const workerEnv = env(namespace);
    const calls: Array<{ url: string; body: string }> = [];
    let executedWithToken = false;
    let browserSessionId = '';
    const executor: InstallExecutor = {
      execute: async (input) => {
        executedWithToken = input.accessToken === 'access-token-value-never-persist';
        expect(input.target.actor.email).toBe('owner@example.com');
        expect(input.target.zone.name).toBe('example.com');
        expect(requiredFixture(input.plan.gatewayConfiguration.firstSource ?? undefined, 'first source').enabledTools).toEqual([
          'company_prepare', 'company_search',
        ]);
        expect(input.releaseBundle).toBe(verifiedReleaseBundle);
        expect(input.sessionId).toBe(browserSessionId);
        expect(input.bootstrapNonceDerivationKey).toBe(BOOTSTRAP_NONCE_KEY);
        expect(input.attemptId).toMatch(/^att_[A-Za-z0-9_-]{32}$/u);
        expect(input.recoverUntil).toBe(NOW + SESSION_TTL_MS + MAX_INSTALL_RECOVERY_RETENTION_MS);
        expect(Object.keys(input.journal).sort()).toEqual([
          'acquireLease',
          'appendApproval',
          'appendCustomerBootstrapCycle',
          'armAction',
          'initialize',
          'prepareAction',
          'read',
          'recordSubmitted',
          'releaseLease',
          'verifyAction',
        ]);
        expect(input.journal).not.toHaveProperty('fetch');
        expect(input.journal).not.toHaveProperty('stub');
        throw new DeployError(503, 'install_mutations_disabled');
      },
    };
    const worker = createGatewayDeployWorker({
      now: () => NOW,
      releaseProvider,
      transport: successfulTransport(calls),
      installExecutor: executor,
    });
    const browser = await createBrowserSession(worker, workerEnv);
    browserSessionId = browser.cookie.slice(browser.cookie.indexOf('=') + 1);
    const { plan } = await saveAndPlan(worker, workerEnv, browser);
    const deploy = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/deploy`, {
      method: 'POST', headers: mutationHeaders(browser),
      body: JSON.stringify({ planId: plan.planId, planHash: plan.planHash }),
    }), workerEnv, undefined);
    const deployPayload = await responseJson(deploy, authorizationHandoffResponseSchema);
    const state = new URL(deployPayload.authorizationUrl).searchParams.get('state');
    const handoff = new URL(deployPayload.handoffUrl).hash.slice(1);
    const exchanged = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/oauth/handoff`, {
      method: 'POST',
      headers: {
        origin: PUBLIC_ORIGIN,
        'sec-fetch-site': 'same-origin',
        'content-type': 'application/json',
      },
      body: JSON.stringify({ handoff }),
    }), workerEnv, undefined);
    const exchangedCookies = exchanged.headers.get('set-cookie') ?? '';
    const handoffSessionPair = cookiePair(exchangedCookies, SESSION_COOKIE);
    const oauthPair = cookiePair(exchangedCookies, OAUTH_COOKIE);
    const callback = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${state}`,
      { headers: { cookie: `${handoffSessionPair}; ${oauthPair}` } },
    ), workerEnv, undefined);
    expect(callback.status).toBe(303);
    expect(callback.headers.get('location')).toBe(`${PUBLIC_ORIGIN}/result`);
    expect(callback.headers.get('set-cookie')).toContain('Max-Age=0');
    expect(executedWithToken).toBe(true);
    expect(calls.filter((call) => call.url.includes('/oauth2/revoke'))).toHaveLength(2);
    expect(namespace.serialized()).not.toMatch(/access-token-value|refresh-token-value|authorization-code-value/iu);

    const result = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: browser.cookie },
    }), workerEnv, undefined);
    expect(await result.json()).toMatchObject({
      authorization: { status: 'expired', email: 'owner@example.com' },
      capabilities: { deploy: false, uninstall: false, events: false, signedRelease: true },
      deployment: {
        status: 'failed',
        failure: { code: 'install_mutations_disabled' },
        receipt: null,
      },
    });

    const replay = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${state}`,
      { headers: { cookie: `${browser.cookie}; ${oauthPair}` } },
    ), workerEnv, undefined);
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({ code: 'oauth_state_invalid' });
    expect(replay.headers.get('set-cookie')).toContain('Max-Age=0');
  });

  it('surfaces a secret-free diagnostic reason when the token exchange is rejected', async () => {
    const namespace = new FakeDeploySessionNamespace();
    const workerEnv = env(namespace);
    const calls: Array<{ url: string; body: string }> = [];
    const base = successfulTransport(calls);
    const worker = createGatewayDeployWorker({
      now: () => NOW,
      releaseProvider,
      transport: async (input, init) => {
        const url = new URL(input instanceof Request ? input.url : input.toString());
        if (url.pathname === '/oauth2/token') {
          calls.push({ url: url.toString(), body: String(init?.body ?? '') });
          return new Response(JSON.stringify({
            error: 'invalid_grant',
            error_description: 'secret-bearing description that must never surface cfoat_should_not_leak',
          }), { status: 400, headers: { 'content-type': 'application/json' } });
        }
        return base(input, init);
      },
    });
    const browser = await createBrowserSession(worker, workerEnv);
    const { plan } = await saveAndPlan(worker, workerEnv, browser);
    const deploy = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/deploy`, {
      method: 'POST', headers: mutationHeaders(browser),
      body: JSON.stringify({ planId: plan.planId, planHash: plan.planHash }),
    }), workerEnv, undefined);
    const deployPayload = await responseJson(deploy, authorizationResponseSchema);
    const state = new URL(deployPayload.authorizationUrl).searchParams.get('state');
    const oauthPair = cookiePair(deploy.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
    const callback = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${state}`,
      { headers: { cookie: `${browser.cookie}; ${oauthPair}` } },
    ), workerEnv, undefined);
    expect(callback.status).toBe(303);
    const result = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: browser.cookie },
    }), workerEnv, undefined);
    const session = await responseJson(result, deploymentFailureResponseSchema);
    expect(session.deployment.failure.code).toBe('oauth_exchange_failed');
    expect(session.deployment.failure.detail).toMatch(/Diagnostic: token_endpoint_400_invalid_grant_at_journal_unreadable\./u);
    expect(JSON.stringify(session)).not.toContain('cfoat_should_not_leak');
    expect(namespace.serialized()).not.toContain('cfoat_should_not_leak');
  });

  it('can return the installer shell while the memory-only grant is still executing', async () => {
    const namespace = new FakeDeploySessionNamespace();
    const workerEnv = env(namespace);
    const calls: Array<{ url: string; body: string }> = [];
    let releaseExecutor = (): void => undefined;
    let markStarted = (): void => undefined;
    const executorGate = new Promise<void>((resolve) => {
      releaseExecutor = resolve;
    });
    const executorStarted = new Promise<void>((resolve) => {
      markStarted = resolve;
    });
    let execution: Promise<void> | null = null;
    const worker = createGatewayDeployWorker({
      now: () => NOW,
      releaseProvider,
      transport: successfulTransport(calls),
      installExecutor: {
        execute: async () => {
          markStarted();
          await executorGate;
          throw new DeployError(503, 'install_mutations_disabled');
        },
      },
      installCallbackResponse: async ({ execute }) => {
        execution = execute();
        return new Response('<!doctype html><main>live progress</main>', {
          headers: { 'content-type': 'text/html; charset=utf-8' },
        });
      },
    });
    const browser = await createBrowserSession(worker, workerEnv);
    const { plan } = await saveAndPlan(worker, workerEnv, browser);
    const deploy = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/deploy`, {
      method: 'POST', headers: mutationHeaders(browser),
      body: JSON.stringify({ planId: plan.planId, planHash: plan.planHash }),
    }), workerEnv, undefined);
    const deployPayload = await responseJson(deploy, authorizationResponseSchema);
    const state = new URL(deployPayload.authorizationUrl).searchParams.get('state');
    const oauthPair = cookiePair(deploy.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
    const callback = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${state}`,
      { headers: { cookie: `${browser.cookie}; ${oauthPair}` } },
    ), workerEnv, undefined);

    expect(callback.status).toBe(200);
    expect(callback.headers.get('content-type')).toContain('text/html');
    expect(callback.headers.get('set-cookie')).toContain('Max-Age=0');
    await executorStarted;
    const running = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: browser.cookie },
    }), workerEnv, undefined);
    expect(await running.json()).toMatchObject({ deployment: { status: 'running' } });

    releaseExecutor();
    await execution;
    const completed = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: browser.cookie },
    }), workerEnv, undefined);
    expect(await completed.json()).toMatchObject({
      deployment: { status: 'failed', failure: { code: 'install_mutations_disabled' } },
    });
    expect(calls.filter(({ url }) => url.includes('/oauth2/revoke'))).toHaveLength(2);
    expect(namespace.serialized()).not.toMatch(/access-token-value|refresh-token-value/iu);
  });

  it('names the error class for an unclassified executor throw without leaking its message', async () => {
    const namespace = new FakeDeploySessionNamespace();
    const workerEnv = env(namespace);
    const calls: Array<{ url: string; body: string }> = [];
    const worker = createGatewayDeployWorker({
      now: () => NOW,
      releaseProvider,
      transport: successfulTransport(calls),
      installExecutor: {
        execute: async () => {
          throw new TypeError('Illegal invocation: secret-bearing message cfoat_never_surface');
        },
      },
    });
    const browser = await createBrowserSession(worker, workerEnv);
    const { plan } = await saveAndPlan(worker, workerEnv, browser);
    const deploy = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/deploy`, {
      method: 'POST', headers: mutationHeaders(browser),
      body: JSON.stringify({ planId: plan.planId, planHash: plan.planHash }),
    }), workerEnv, undefined);
    const deployPayload = await responseJson(deploy, authorizationResponseSchema);
    const state = new URL(deployPayload.authorizationUrl).searchParams.get('state');
    const oauthPair = cookiePair(deploy.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
    const callback = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${state}`,
      { headers: { cookie: `${browser.cookie}; ${oauthPair}` } },
    ), workerEnv, undefined);
    expect(callback.status).toBe(303);
    const result = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: browser.cookie },
    }), workerEnv, undefined);
    const session = await responseJson(result, deploymentFailureResponseSchema);
    expect(session.deployment.failure.code).toBe('internal_error');
    expect(session.deployment.failure.detail).toMatch(/Diagnostic: unclassified_typeerror_at_[a-z0-9_]+\./u);
    expect(JSON.stringify(session)).not.toContain('cfoat_never_surface');
    expect(namespace.serialized()).not.toContain('cfoat_never_surface');
  });

  it('accepts the scope Cloudflare echoes on the authorization response only when it is the exact required set', async () => {
    const exactScope = encodeURIComponent(REQUIRED_OAUTH_SCOPES.join(' '));
    const shortScope = encodeURIComponent(REQUIRED_OAUTH_SCOPES.slice(0, 9).join(' '));
    for (const [scopeQuery, expectedStatus] of [[`&scope=${shortScope}`, 400], [`&scope=${exactScope}`, 303]] as const) {
      const namespace = new FakeDeploySessionNamespace(() => NOW);
      const workerEnv = env(namespace);
      const calls: Array<{ url: string; body: string }> = [];
      const worker = createGatewayDeployWorker({
        now: () => NOW,
        releaseProvider,
        transport: successfulTransport(calls),
      });
      const browser = await createBrowserSession(worker, workerEnv);
      const { plan } = await saveAndPlan(worker, workerEnv, browser);
      const deploy = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/deploy`, {
        method: 'POST', headers: mutationHeaders(browser),
        body: JSON.stringify({ planId: plan.planId, planHash: plan.planHash }),
      }), workerEnv, undefined);
      const deployPayload = await responseJson(deploy, authorizationResponseSchema);
      const state = new URL(deployPayload.authorizationUrl).searchParams.get('state');
      const oauthPair = cookiePair(deploy.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
      const callback = await worker.fetch(new Request(
        `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value${scopeQuery}&state=${state}`,
        { headers: { cookie: `${browser.cookie}; ${oauthPair}` } },
      ), workerEnv, undefined);
      expect(callback.status, scopeQuery).toBe(expectedStatus);
      if (expectedStatus === 400) {
        expect(await callback.json()).toEqual({ code: 'callback_invalid' });
        expect(calls.filter((call) => call.url.includes('/oauth2/token'))).toHaveLength(0);
      } else {
        expect(callback.headers.get('location')).toBe(`${PUBLIC_ORIGIN}/result`);
        expect(calls.filter((call) => call.url.includes('/oauth2/token'))).toHaveLength(1);
      }
    }
  });

  it('retains a converged install and receipt when automatic grant revocation is unconfirmed', async () => {
    let currentTime = NOW;
    const baseNamespace = new FakeDeploySessionNamespace(() => currentTime);
    const completions: SuccessfulCompletion[] = [];
    const workerEnv = {
      ...env(baseNamespace),
      GATEWAY_DEPLOY_SESSION: completionAcceptingNamespace(
        baseNamespace,
        () => currentTime,
        completions,
      ),
    };
    const calls: Array<{ url: string; body: string }> = [];
    const executor: InstallExecutor = {
      execute: async () => ({ installationId: `acg-${'e'.repeat(24)}` }),
    };
    const worker = createGatewayDeployWorker({
      now: () => currentTime,
      releaseProvider,
      transport: successfulTransport(calls, undefined, 503),
      installExecutor: executor,
    });
    const browser = await createBrowserSession(worker, workerEnv);
    const { plan } = await saveAndPlan(worker, workerEnv, browser);
    const deploy = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/deploy`, {
      method: 'POST',
      headers: mutationHeaders(browser),
      body: JSON.stringify({ planId: plan.planId, planHash: plan.planHash }),
    }), workerEnv, undefined);
    const deployPayload = await responseJson(deploy, authorizationResponseSchema);
    const state = new URL(deployPayload.authorizationUrl).searchParams.get('state');
    const oauthPair = cookiePair(deploy.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
    const callback = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${state}`,
      { headers: { cookie: `${browser.cookie}; ${oauthPair}` } },
    ), workerEnv, undefined);

    expect(callback.status).toBe(303);
    expect(callback.headers.get('location')).toBe(`${PUBLIC_ORIGIN}/result`);
    expect(completions).toEqual([{
      attemptId: expect.stringMatching(/^att_[A-Za-z0-9_-]{32}$/u),
      code: 'install_complete',
      installationId: `acg-${'e'.repeat(24)}`,
      grantRevocation: 'unconfirmed',
      completedAt: NOW,
      reason: null,
    }]);
    expect(calls.filter(({ url }) => url.includes('/oauth2/revoke'))).toHaveLength(2);

    const result = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: browser.cookie },
    }), workerEnv, undefined);
    const payload = await responseJson(result, deploymentViewResponseSchema);
    expect(payload.deployment).toMatchObject({
      status: 'succeeded',
      failure: null,
      canRetry: false,
      receipt: {
        receiptId: `receipt-${'e'.repeat(24)}`,
        managementUrl: 'https://manage.example.com/',
        portalUrl: 'https://mcp.example.com/mcp',
      },
    });
    expect(payload.deployment.operations.find(({ id }: { id: string }) => id === 'revoke')).toEqual({
      id: 'revoke',
      label: 'Revoking the short-lived Cloudflare grant',
      detail: UNCONFIRMED_GRANT_REVOCATION_DETAIL,
      status: 'blocked',
    });
    expect(baseNamespace.serialized()).toContain(`acg-${'e'.repeat(24)}`);
    expect(baseNamespace.serialized()).not.toMatch(/access-token-value|refresh-token-value|authorization-code-value/iu);

    currentTime = NOW + SESSION_TTL_MS + 1;
    const retained = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: browser.cookie },
    }), workerEnv, undefined);
    const retainedPayload = await responseJson(retained, deploymentViewResponseSchema);
    expect(retained.status).toBe(200);
    expect(retainedPayload.recovery).toBeNull();
    expect(retainedPayload.deployment).toMatchObject({
      status: 'succeeded',
      canRetry: false,
      receipt: { receiptId: `receipt-${'e'.repeat(24)}` },
    });
    expect(retained.headers.get('set-cookie')).toContain(
      `Max-Age=${Math.floor((MAX_INSTALL_RECOVERY_RETENTION_MS - 1) / 1000)}`,
    );
  });

  it('keeps the default executor hard-disabled but still revokes both grants', async () => {
    const namespace = new FakeDeploySessionNamespace();
    const workerEnv = env(namespace);
    const calls: Array<{ url: string; body: string }> = [];
    const worker = createGatewayDeployWorker({
      now: () => NOW,
      releaseProvider,
      transport: successfulTransport(calls),
    });
    const browser = await createBrowserSession(worker, workerEnv);
    const { plan } = await saveAndPlan(worker, workerEnv, browser);
    const deploy = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/deploy`, {
      method: 'POST', headers: mutationHeaders(browser),
      body: JSON.stringify({ planId: plan.planId, planHash: plan.planHash }),
    }), workerEnv, undefined);
    const payload = await responseJson(deploy, authorizationResponseSchema);
    const state = new URL(payload.authorizationUrl).searchParams.get('state');
    const oauthPair = cookiePair(deploy.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
    const callback = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${state}`,
      { headers: { cookie: `${browser.cookie}; ${oauthPair}` } },
    ), workerEnv, undefined);
    expect(callback.status).toBe(303);
    expect(calls.filter((call) => call.url.includes('/oauth2/revoke'))).toHaveLength(2);
    expect(namespace.serialized()).toContain('install_mutations_disabled');
  });

  it('keeps oauth_revoke_failed for a non-converged attempt whose revocation cannot be confirmed', async () => {
    const namespace = new FakeDeploySessionNamespace();
    const workerEnv = env(namespace);
    const calls: Array<{ url: string; body: string }> = [];
    const worker = createGatewayDeployWorker({
      now: () => NOW,
      releaseProvider,
      transport: successfulTransport(calls, undefined, 503),
    });
    const browser = await createBrowserSession(worker, workerEnv);
    const { plan } = await saveAndPlan(worker, workerEnv, browser);
    const deploy = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/deploy`, {
      method: 'POST',
      headers: mutationHeaders(browser),
      body: JSON.stringify({ planId: plan.planId, planHash: plan.planHash }),
    }), workerEnv, undefined);
    const payload = await responseJson(deploy, authorizationResponseSchema);
    const state = new URL(payload.authorizationUrl).searchParams.get('state');
    const oauthPair = cookiePair(deploy.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
    const callback = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${state}`,
      { headers: { cookie: `${browser.cookie}; ${oauthPair}` } },
    ), workerEnv, undefined);

    expect(callback.status).toBe(303);
    expect(calls.filter(({ url }) => url.includes('/oauth2/revoke'))).toHaveLength(2);
    expect(namespace.serialized()).toContain('oauth_revoke_failed');
    const stored = requireStoredSession(
      [...namespace.states.values()][0]?.storage.values.get('deploy-session-v1'),
    );
    expect(stored.result).toEqual({ code: 'oauth_revoke_failed', completedAt: NOW });

    const result = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: browser.cookie },
    }), workerEnv, undefined);
    expect(await result.json()).toMatchObject({
      deployment: {
        status: 'failed',
        canRetry: true,
        failure: { code: 'oauth_revoke_failed' },
        receipt: null,
      },
    });
  });

  it.each([
    ['malformed token_type', {
      token_type: 'MAC',
      access_token: 'access-token-value-never-persist',
      refresh_token: 'refresh-token-value-never-persist',
      scope: REQUIRED_OAUTH_SCOPES.join(' '),
    }, 'refresh-token-value-never-persist', 'oauth_exchange_failed'],
    ['malformed refresh metadata', {
      token_type: 'Bearer',
      access_token: 'access-token-value-never-persist',
      refresh_token: 'short',
      scope: REQUIRED_OAUTH_SCOPES.join(' '),
    }, 'short', 'oauth_exchange_failed'],
    ['malformed scope metadata', {
      token_type: 'Bearer',
      access_token: 'access-token-value-never-persist',
      refresh_token: 'refresh-token-value-never-persist',
      scope: REQUIRED_OAUTH_SCOPES.slice(1).join(' '),
    }, 'refresh-token-value-never-persist', 'oauth_grant_invalid'],
  ])('revokes every captured credential after %s', async (
    _label,
    tokenPayload,
    expectedRefreshToken,
    expectedResultCode,
  ) => {
    const namespace = new FakeDeploySessionNamespace();
    const workerEnv = env(namespace);
    const calls: Array<{ url: string; body: string }> = [];
    const worker = createGatewayDeployWorker({
      now: () => NOW,
      releaseProvider,
      transport: successfulTransport(calls, tokenPayload),
    });
    const browser = await createBrowserSession(worker, workerEnv);
    const { plan } = await saveAndPlan(worker, workerEnv, browser);
    const deploy = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/deploy`, {
      method: 'POST',
      headers: mutationHeaders(browser),
      body: JSON.stringify({ planId: plan.planId, planHash: plan.planHash }),
    }), workerEnv, undefined);
    const payload = await responseJson(deploy, authorizationResponseSchema);
    const state = new URL(payload.authorizationUrl).searchParams.get('state');
    const oauthPair = cookiePair(deploy.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
    const callback = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${state}`,
      { headers: { cookie: `${browser.cookie}; ${oauthPair}` } },
    ), workerEnv, undefined);
    expect(callback.status).toBe(303);
    const revocations = calls.filter((call) => call.url.includes('/oauth2/revoke'));
    expect(revocations).toHaveLength(2);
    expect(revocations.map(({ body }) => new URLSearchParams(body).get('token'))).toEqual([
      'access-token-value-never-persist',
      expectedRefreshToken,
    ]);
    expect(namespace.serialized()).toContain(expectedResultCode);
    expect(namespace.serialized()).not.toMatch(/access-token-value|refresh-token-value|authorization-code-value/iu);
  });

  it('allows an expired session to be explicitly deleted and clears its PII', async () => {
    const namespace = new FakeDeploySessionNamespace();
    const workerEnv = env(namespace);
    let currentTime = NOW;
    const worker = createGatewayDeployWorker({ now: () => currentTime, releaseProvider });
    const browser = await createBrowserSession(worker, workerEnv);
    const saved = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/selection`, {
      method: 'PUT',
      headers: mutationHeaders(browser),
      body: JSON.stringify(selectionInput),
    }), workerEnv, undefined);
    expect(saved.status).toBe(200);
    expect(namespace.serialized()).toContain('owner@example.com');
    currentTime = NOW + SESSION_TTL_MS;
    const deleted = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      method: 'DELETE',
      headers: mutationHeaders(browser),
    }), workerEnv, undefined);
    expect(deleted.status).toBe(204);
    expect(deleted.headers.get('set-cookie')).toContain('Max-Age=0');
    expect(namespace.serialized()).not.toContain('owner@example.com');
  });

  it('keeps the same opaque session only across the exact armed recovery boundary', async () => {
    const fixture = await recoveryFixture(true);
    const sessionExpiresAt = NOW + SESSION_TTL_MS;
    const clock = vi.spyOn(Date, 'now').mockImplementation(() => sessionExpiresAt - 1);
    try {
      fixture.setNow(sessionExpiresAt - 1);
      const before = await fixture.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
        headers: { cookie: fixture.browser.cookie },
      }), fixture.workerEnv, undefined);
      expect(before.status).toBe(200);
      expect(await before.json()).toMatchObject({ recovery: null, csrf: fixture.browser.csrf });
      expect(before.headers.get('set-cookie')).toBeNull();

      fixture.setNow(sessionExpiresAt);
      clock.mockImplementation(() => sessionExpiresAt);
      const atExpiry = await fixture.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
        headers: { cookie: fixture.browser.cookie },
      }), fixture.workerEnv, undefined);
      const payload = await responseJson(atExpiry, boundaryObjectSchema);
      expect(atExpiry.status).toBe(200);
      expect(payload).toMatchObject({
        csrf: fixture.browser.csrf,
        recovery: {
          status: 'recovery_required',
          expiresAt: new Date(fixture.recoverUntil).toISOString(),
        },
        capabilities: { selection: false, plan: true, deploy: false, uninstall: false, events: false },
      });
      expect(JSON.stringify(payload)).not.toMatch(/install-journal|bindingHash|approvalHistory|leaseAttemptIds/iu);
      expect(cookiePair(atExpiry.headers.get('set-cookie') ?? '', SESSION_COOKIE)).toBe(fixture.browser.cookie);
      expect(atExpiry.headers.get('set-cookie')).toContain(`Max-Age=${MAX_INSTALL_RECOVERY_RETENTION_MS / 1000}`);
    } finally {
      clock.mockRestore();
    }
  });

  it('remints the same opaque session for a completed receipt after ordinary expiry without exposing recovery', async () => {
    const sessionId = 'r'.repeat(43);
    const sessionExpiresAt = NOW + SESSION_TTL_MS;
    const resultUntil = sessionExpiresAt + MAX_INSTALL_RECOVERY_RETENTION_MS;
    const plan = await buildStaticDeployPlan(parseDeploySelection(selectionInput), manifest, NOW + 600_000);
    const completedSession = {
      schemaVersion: 1 as const,
      status: 'succeeded' as const,
      expiresAt: sessionExpiresAt,
      updatedAt: sessionExpiresAt,
      selection: parseDeploySelection(selectionInput),
      plan,
      result: {
        code: 'install_complete' as const,
        completedAt: sessionExpiresAt + 1,
        installationId: `acg-${'9'.repeat(24)}`,
        grantRevocation: 'confirmed' as const,
      },
    };
    const currentTime = resultUntil - 1;
    const idNamespace = new FakeDeploySessionNamespace();
    const namespace: GatewayDeploySessionNamespace = {
      idFromName: (name: string) => idNamespace.idFromName(name),
      get: (id: DurableObjectId) => {
        const name = id.name;
        if (!name) throw new Error('test Durable Object ID has no name');
        return {
          fetch: async (request: Request) => {
            const pathname = new URL(request.url).pathname;
            if (name === sessionId && request.method === 'POST' && pathname === '/csrf/synchronize') {
              return new Response(JSON.stringify({ synchronized: true }), {
                headers: { 'content-type': 'application/json' },
              });
            }
            if (name !== sessionId || pathname !== '/public') {
              return new Response(JSON.stringify({ error: { code: 'session_invalid' } }), {
                status: 404,
                headers: { 'content-type': 'application/json' },
              });
            }
            return new Response(JSON.stringify({
              session: completedSession,
              installProgress: null,
              discovery: {
                schemaVersion: 1,
                status: 'not_started',
                actorEmail: null,
                targets: [],
                selectedTargetIdHash: null,
                failureCode: null,
                grantRevocation: null,
                updatedAt: null,
              },
              recovery: null,
              resultRetention: { status: 'result_available', resultUntil },
              uninstall: null,
              uninstallRecovery: null,
            }), { headers: { 'content-type': 'application/json' } });
          },
        };
      },
    };
    const workerEnv = { ...env(), GATEWAY_DEPLOY_SESSION: namespace };
    const worker = createGatewayDeployWorker({ now: () => currentTime, releaseProvider });
    const cookie = `${SESSION_COOKIE}=${sessionId}`;
    const response = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie },
    }), workerEnv, undefined);
    const payload = await responseJson(response, deploymentViewResponseSchema);
    expect(response.status).toBe(200);
    expect(cookiePair(response.headers.get('set-cookie') ?? '', SESSION_COOKIE)).toBe(cookie);
    expect(response.headers.get('set-cookie')).toContain('Max-Age=1');
    expect(payload.recovery).toBeNull();
    expect(payload.deployment).toMatchObject({
      status: 'succeeded',
      receipt: { receiptId: `receipt-${'9'.repeat(24)}` },
    });
  });

  it('rotates expired empty and prepared-only sessions instead of exposing recovery', async () => {
    const sessionExpiresAt = NOW + SESSION_TTL_MS;
    const clock = vi.spyOn(Date, 'now').mockImplementation(() => sessionExpiresAt);
    try {
      let emptyNow = NOW;
      const emptyNamespace = new FakeDeploySessionNamespace(() => emptyNow);
      const emptyEnv = env(emptyNamespace);
      const emptyWorker = createGatewayDeployWorker({ now: () => emptyNow, releaseProvider });
      const emptyBrowser = await createBrowserSession(emptyWorker, emptyEnv);
      const emptyId = browserSessionId(emptyBrowser);
      emptyNow = sessionExpiresAt;
      const emptyResponse = await emptyWorker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
        headers: { cookie: emptyBrowser.cookie },
      }), emptyEnv, undefined);
      const emptyPayload = await responseJson(emptyResponse, boundaryObjectSchema);
      expect(emptyPayload).toMatchObject({ recovery: null });
      expect(cookiePair(emptyResponse.headers.get('set-cookie') ?? '', SESSION_COOKIE)).not.toBe(emptyBrowser.cookie);
      expect(emptyNamespace.states.get(emptyId)?.storage.values.size).toBe(0);

      clock.mockImplementation(() => NOW);
      const prepared = await recoveryFixture(false);
      const preparedId = browserSessionId(prepared.browser);
      prepared.setNow(sessionExpiresAt);
      clock.mockImplementation(() => sessionExpiresAt);
      const preparedResponse = await prepared.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
        headers: { cookie: prepared.browser.cookie },
      }), prepared.workerEnv, undefined);
      expect(await preparedResponse.json()).toMatchObject({ recovery: null });
      expect(cookiePair(preparedResponse.headers.get('set-cookie') ?? '', SESSION_COOKIE)).not.toBe(prepared.browser.cookie);
      expect(prepared.namespace.states.get(preparedId)?.storage.values.size).toBe(0);
    } finally {
      clock.mockRestore();
    }
  });

  it('purges and rotates a terminal non-journal session at ordinary expiry', async () => {
    const namespace = new FakeDeploySessionNamespace();
    const workerEnv = env(namespace);
    let currentTime = NOW;
    const worker = createGatewayDeployWorker({ now: () => currentTime, releaseProvider });
    const browser = await createBrowserSession(worker, workerEnv);
    const { plan } = await saveAndPlan(worker, workerEnv, browser);
    const deploy = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/deploy`, {
      method: 'POST',
      headers: mutationHeaders(browser),
      body: JSON.stringify({ planId: plan.planId, planHash: plan.planHash }),
    }), workerEnv, undefined);
    const authorizationUrl = new URL((await responseJson(deploy, authorizationResponseSchema)).authorizationUrl);
    const state = authorizationUrl.searchParams.get('state');
    const oauthPair = cookiePair(deploy.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
    currentTime = NOW + 1;
    vi.mocked(Date.now).mockReturnValue(currentTime);
    const denied = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?error=access_denied&state=${state}`,
      { headers: { cookie: `${browser.cookie}; ${oauthPair}` } },
    ), workerEnv, undefined);
    expect(denied.status, await denied.clone().text()).toBe(303);

    const oldId = browserSessionId(browser);
    currentTime = NOW + SESSION_TTL_MS;
    vi.mocked(Date.now).mockReturnValue(currentTime);
    const rotated = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: browser.cookie },
    }), workerEnv, undefined);
    expect(await rotated.json()).toMatchObject({ recovery: null });
    expect(cookiePair(rotated.headers.get('set-cookie') ?? '', SESSION_COOKIE)).not.toBe(browser.cookie);
    expect(namespace.states.get(oldId)?.storage.values.size).toBe(0);
  });

  it('requires the exact cookie, Origin, and CSRF while preventing recovery selection drift', async () => {
    const fixture = await recoveryFixture(true);
    const recoveryNow = NOW + SESSION_TTL_MS;
    fixture.setNow(recoveryNow);
    const clock = vi.spyOn(Date, 'now').mockImplementation(() => recoveryNow);
    try {
      const wrongCookie = `${SESSION_COOKIE}=${'z'.repeat(43)}`;
      const missing = await fixture.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/plan`, {
        method: 'POST',
        headers: { ...mutationHeaders(fixture.browser), cookie: wrongCookie },
      }), fixture.workerEnv, undefined);
      expect(missing.status).toBe(404);
      expect(await missing.json()).toEqual({ code: 'session_invalid' });

      const wrongOrigin = await fixture.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/plan`, {
        method: 'POST',
        headers: { ...mutationHeaders(fixture.browser), origin: 'https://evil.example' },
      }), fixture.workerEnv, undefined);
      expect(wrongOrigin.status).toBe(403);
      expect(await wrongOrigin.json()).toEqual({ code: 'origin_invalid' });

      const wrongCsrf = await fixture.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/plan`, {
        method: 'POST',
        headers: { ...mutationHeaders(fixture.browser), 'x-csrf-token': 'x'.repeat(43) },
      }), fixture.workerEnv, undefined);
      expect(wrongCsrf.status).toBe(403);
      expect(await wrongCsrf.json()).toEqual({ code: 'csrf_invalid' });

      const selectionMutation = await fixture.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/selection`, {
        method: 'PUT',
        headers: mutationHeaders(fixture.browser),
        body: JSON.stringify(selectionInput),
      }), fixture.workerEnv, undefined);
      expect(selectionMutation.status).toBe(410);
      expect(await selectionMutation.json()).toEqual({ code: 'session_expired' });
    } finally {
      clock.mockRestore();
    }
  });

  it('renews the exact plan and completes a fresh recovery OAuth denial after ordinary expiry', async () => {
    const fixture = await recoveryFixture(true);
    let recoveryNow = NOW + SESSION_TTL_MS;
    fixture.setNow(recoveryNow);
    const clock = vi.spyOn(Date, 'now').mockImplementation(() => recoveryNow);
    try {
      const staleCallback = await fixture.worker.fetch(new Request(
        `${PUBLIC_ORIGIN}/oauth/callback?error=access_denied&state=${fixture.staleState}`,
        { headers: { cookie: `${fixture.browser.cookie}; ${fixture.staleOauthPair}` } },
      ), fixture.workerEnv, undefined);
      expect(staleCallback.status).toBe(400);
      expect(await staleCallback.json()).toEqual({ code: 'session_invalid' });
      expect(staleCallback.headers.get('set-cookie')).toContain(`${OAUTH_COOKIE}=;`);

      const renewed = await fixture.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/plan`, {
        method: 'POST',
        headers: mutationHeaders(fixture.browser),
      }), fixture.workerEnv, undefined);
      expect(renewed.status).toBe(200);
      const renewedPayload = await responseJson(renewed, renewedPlanResponseSchema);
      expect(renewedPayload.recovery).toEqual({
        status: 'recovery_required',
        expiresAt: new Date(fixture.recoverUntil).toISOString(),
      });
      expect(renewedPayload.plan.planId).toBe(fixture.plan.planId);
      expect(renewedPayload.plan.planHash).toBe(fixture.plan.planHash);
      expect(Date.parse(renewedPayload.plan.expiresAt)).toBe(recoveryNow + 600_000);

      const deploy = await fixture.worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/deploy`, {
        method: 'POST',
        headers: mutationHeaders(fixture.browser),
        body: JSON.stringify({
          planId: renewedPayload.plan.planId,
          planHash: renewedPayload.plan.planHash,
        }),
      }), fixture.workerEnv, undefined);
      expect(deploy.status).toBe(200);
      const authorizationUrl = new URL((await responseJson(deploy, authorizationResponseSchema)).authorizationUrl);
      const state = authorizationUrl.searchParams.get('state');
      const oauthPair = cookiePair(deploy.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
      const sealed = await openOauthCookie(
        ENCRYPTION_KEY,
        oauthPair.slice(oauthPair.indexOf('=') + 1),
      );
      expect(sealed.expiresAt).toBe(recoveryNow + 600_000);

      recoveryNow += 1;
      fixture.setNow(recoveryNow);
      const denied = await fixture.worker.fetch(new Request(
        `${PUBLIC_ORIGIN}/oauth/callback?error=access_denied&state=${state}`,
        { headers: { cookie: `${fixture.browser.cookie}; ${oauthPair}` } },
      ), fixture.workerEnv, undefined);
      expect(denied.status).toBe(303);
      expect(denied.headers.get('location')).toBe(`${PUBLIC_ORIGIN}/result`);
      expect(fixture.namespace.serialized()).not.toMatch(/access-token|refresh-token|client-secret|codeVerifier/iu);
    } finally {
      clock.mockRestore();
    }
  });

  it('fails before OAuth when no pinned signed release is loaded', async () => {
    const workerEnv = env();
    const worker = createGatewayDeployWorker({ now: () => NOW });
    const browser = await createBrowserSession(worker, workerEnv);
    const saved = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/selection`, {
      method: 'PUT', headers: mutationHeaders(browser), body: JSON.stringify(selectionInput),
    }), workerEnv, undefined);
    expect(saved.status).toBe(200);
    const preview = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/plan`, {
      method: 'POST', headers: mutationHeaders(browser),
    }), workerEnv, undefined);
    expect(preview.status).toBe(503);
    expect(await preview.json()).toEqual({ code: 'release_unavailable' });
  });
});
import * as v from 'valibot';
