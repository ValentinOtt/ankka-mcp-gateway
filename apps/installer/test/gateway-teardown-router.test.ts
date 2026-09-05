import * as v from 'valibot';
import { describe, expect, it } from 'vitest';
import { PUBLIC_ORIGIN, OAUTH_CALLBACK_URL, OAUTH_EXCHANGE_URL, OAUTH_REVOKE_URL } from '../src/constants';
import { openGatewayTeardownCookie } from '../src/crypto';
import { gatewayTeardownJobId } from '../src/gateway-teardown-handoff';
import { GatewayTeardownStoreClient } from '../src/gateway-teardown-store-client';
import { createGatewayTeardownRouter, GATEWAY_TEARDOWN_COOKIE } from '../src/gateway-teardown-router';
import { TwoStageDeploySession, type TwoStageDeploySessionNamespace, type TwoStageDeploySessionStub } from '../src/two-stage-deploy-session';
import { ROOT_TEST } from './gateway-teardown-fixture';
import { gatewayRootProviderFixture, TOKEN } from './gateway-teardown-provider-fixture';
import { teardownSqliteFixture } from './gateway-teardown-sqlite-fixture';
import { ENCRYPTION_KEY, CLIENT_ID, CLIENT_SECRET } from './fixtures';

const viewSchema = v.object({ csrfToken: v.string(), canAuthorize: v.boolean(), revocationUnconfirmed: v.boolean(),
  message: v.string(), failureReason: v.nullable(v.string()), steps: v.array(v.object({ done: v.boolean() })), handoff: v.string() });

async function fixture() {
  const provider = await gatewayRootProviderFixture();
  let time = ROOT_TEST.now;
  let cookie = '';
  let csrf = '';
  let grants = 0, revoked = 0;
  let revokeFails = false, wrongAccount = false, extraScope = false, returnsRefresh = false;
  const instances = new Map<string, { sql: ReturnType<typeof teardownSqliteFixture>; stub: TwoStageDeploySessionStub }>();
  const namespace: TwoStageDeploySessionNamespace = {
    idFromName: (name) => {
      const id: DurableObjectId = Object.create(null);
      Object.defineProperty(id, 'toString', { value: () => name });
      return id;
    },
    get: (id) => {
      const name = id.toString();
      let value = instances.get(name);
      if (value === undefined) {
        const sql = teardownSqliteFixture();
        value = { sql, stub: new TwoStageDeploySession(sql.state, undefined, { now: () => time }) };
        instances.set(name, value);
      }
      return value.stub;
    },
  };
  const jobId = await gatewayTeardownJobId(provider.handoff);
  const port = new GatewayTeardownStoreClient({ fetch: (request) => namespace.get(namespace.idFromName(`gateway-teardown:v1:${jobId}`)).fetch(request) });
  provider.readJobFrom(() => port.read());
  const makeRouter = () => createGatewayTeardownRouter({ encryptionKey: ENCRYPTION_KEY,
    oauth: { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET }, trust: provider.trust, release: provider.job.release, namespace }, {
    now: () => time,
    loadBundle: async (identity) => { expect(identity).toEqual(provider.job.release); return provider.bundle; },
    rateLimit: async () => undefined,
    transport: async (input, init) => {
      const request = new Request(input, init), url = new URL(request.url);
      if (url.href === OAUTH_EXCHANGE_URL) {
        grants += 1;
        const job = await port.read(); expect(job?.phase).toBe('exchanging');
        const value = { access_token: TOKEN, token_type: 'bearer', scope: `workers-scripts.write zone-access.write${extraScope ? ' dns.write' : ''}` };
        return Response.json(returnsRefresh ? { ...value, refresh_token: 'synthetic-refresh-token' } : value);
      }
      if (url.href === OAUTH_REVOKE_URL) { revoked += 1; return new Response('', { status: revokeFails ? 503 : 200 }); }
      if (url.pathname === '/client/v4/accounts') return Response.json({ success: true, errors: [], messages: [], result: [{ id: wrongAccount ? 'f'.repeat(32) : ROOT_TEST.accountId }] });
      return provider.transport(request);
    },
  });
  let router = makeRouter();
  const send = async (path: string, body?: { handoff: string } | Record<string, never>, options: { origin?: string; csrf?: string; cookie?: string } = {}) => {
    const headers = new Headers({ cookie: options.cookie ?? cookie });
    if (body !== undefined) {
      headers.set('content-type', 'application/json'); headers.set('origin', options.origin ?? PUBLIC_ORIGIN);
      headers.set('x-csrf-token', options.csrf ?? csrf);
    }
    const response = await router.fetch(new Request(new URL(path, PUBLIC_ORIGIN), { method: body === undefined ? 'GET' : 'POST', headers,
      body: body === undefined ? null : JSON.stringify(body) }));
    const updated = response.headers.get('set-cookie');
    if (updated !== null) cookie = updated.split(';')[0] ?? '';
    return response;
  };
  const view = async () => {
    const response = await send('/api/teardown');
    expect(response.status).toBe(200);
    const value = v.parse(viewSchema, await response.json()); csrf = value.csrfToken; return value;
  };
  const start = async () => {
    await view();
    const response = await send('/api/teardown/authorize', {});
    expect(response.status).toBe(200);
    const authorization = new URL(v.parse(v.object({ authorizationUrl: v.string() }), await response.json()).authorizationUrl);
    expect(authorization.searchParams.get('scope')?.split(' ').sort()).toEqual(['workers-scripts.write', 'zone-access.write']);
    const callback = new URL(OAUTH_CALLBACK_URL);
    callback.searchParams.set('state', authorization.searchParams.get('state') ?? '');
    callback.searchParams.set('code', 'synthetic-code-for-removal');
    return callback;
  };
  return { ...provider, send, view, start, port, grants: () => grants, revoked: () => revoked,
    cookie: () => cookie, router: () => router,
    import: () => send('/api/teardown/import', { handoff: provider.handoff }),
    advance: () => { time += 86_400_001; },
    reopen: () => {
      for (const value of instances.values()) value.stub = new TwoStageDeploySession(value.sql.state, undefined, { now: () => time });
      router = makeRouter(); cookie = ''; csrf = '';
    },
    alterGrant: (kind: 'revoke' | 'account' | 'scope' | 'refresh') => {
      revokeFails = kind === 'revoke'; wrongAccount = kind === 'account'; extraScope = kind === 'scope'; returnsRefresh = kind === 'refresh';
    },
    close: () => { for (const value of instances.values()) value.sql.close(); },
  };
}

describe('hosted removal browser callback and durable recovery', () => {
  it('reopens an existing job with equivalent fresh proof while preserving authority, progress, and revocation warnings', async () => {
    const f = await fixture();
    try {
      expect((await f.import()).status).toBe(200);
      const before = await f.port.read();
      f.advance(); f.reopen();
      const issuedAt = ROOT_TEST.now + 86_400_001;
      const statement = { ...f.statement, actionId: `action_${'z'.repeat(32)}`, issuedAt, expiresAt: issuedAt + 600_000,
        priorGrantRevocationUnconfirmed: true };
      const fresh = await f.sign(statement);
      expect((await f.send('/api/teardown/import', { handoff: fresh })).status).toBe(200);
      const resumed = await f.port.read();
      expect(resumed?.handoff).toBe(before?.handoff); expect(resumed?.acceptedAt).toBe(before?.acceptedAt);
      expect(resumed?.verifiedSteps).toEqual(before?.verifiedSteps); expect((await f.view()).revocationUnconfirmed).toBe(true);
      const drifted = await f.sign({ ...statement, management: { ...statement.management, policyId: 'foreign-policy' } });
      expect((await f.send('/api/teardown/import', { handoff: drifted })).status).toBe(409);
      const callback = await f.start(); expect((await f.send(callback.pathname + callback.search)).status).toBe(303);
      expect((await f.port.read())?.phase).toBe('removed_revocation_unconfirmed');
    } finally { f.close(); }
  });

  it('retains a content-free provider reason when a foreign dependency stops removal', async () => {
    const f = await fixture();
    try {
      await f.import(); f.drift('policy');
      const callback = await f.start(); await f.send(callback.pathname + callback.search);
      expect((await f.view()).failureReason).toBe('policy_list_foreign_dependency');
      expect(f.mutations).toEqual([]); expect(f.revoked()).toBe(1);
      const job = await f.port.read(); expect(job?.failureReason).not.toContain(TOKEN);
    } finally { f.close(); }
  });

  it('imports a signed handoff, removes the root, revokes its grant, and rejects callback replay', async () => {
    const test = await fixture();
    try {
      expect((await test.import()).status).toBe(200);
      const page = await test.send('/teardown'); expect(page.status).toBe(200);
      expect((await test.view()).canAuthorize).toBe(true);
      const callback = await test.start();
      const callbackCookie = test.cookie();
      const sealed = callbackCookie.slice(GATEWAY_TEARDOWN_COOKIE.length + 1);
      const opened = await openGatewayTeardownCookie(ENCRYPTION_KEY, sealed, ROOT_TEST.now);
      expect(callbackCookie).not.toContain(opened.attempt?.verifier);
      expect(JSON.stringify(await test.port.read())).not.toContain(opened.attempt?.verifier);
      const response = await test.send(callback.href);
      expect(response.status).toBe(303);
      const view = await test.view();
      expect(view.steps.every((step) => step.done)).toBe(true);
      expect(view.canAuthorize).toBe(false); expect(view.revocationUnconfirmed).toBe(false);
      expect(test.grants()).toBe(1); expect(test.revoked()).toBe(1);
      expect((await test.send(callback.href, undefined, { cookie: callbackCookie })).status).toBe(409);
      expect(test.grants()).toBe(1);
      expect(JSON.stringify(await test.port.read())).not.toContain(TOKEN);
    } finally { test.close(); }
  });

  it.each(['retire_namespace', 'worker'] as const)('recovers a lost %s response after the gateway and browser session are gone', async (step) => {
    const test = await fixture();
    try {
      await test.import(); test.failAfter(step);
      expect((await test.send((await test.start()).href)).status).toBe(303);
      expect((await test.port.read())?.phase).toBe('recovery_required');
      const acceptedAt = (await test.port.read())?.acceptedAt;
      test.advance(); test.reopen(); test.failAfter(null);
      expect((await test.import()).status).toBe(200); // Existing accepted authority survives import expiry.
      expect((await test.send((await test.start()).href)).status).toBe(303);
      expect((await test.port.read())?.phase).toBe('removed');
      expect((await test.port.read())?.acceptedAt).toBe(acceptedAt);
      expect(test.mutations).toHaveLength(5); expect(new Set(test.mutations).size).toBe(5);
    } finally { test.close(); }
  });

  it.each(['account', 'scope', 'refresh'] as const)('rejects an unexpected grant %s and still revokes every captured credential', async (kind) => {
    const test = await fixture();
    try {
      await test.import(); test.alterGrant(kind);
      expect((await test.send((await test.start()).href)).status).toBe(303);
      expect(test.mutations).toEqual([]);
      expect(test.revoked()).toBe(kind === 'refresh' ? 2 : 1);
      expect((await test.port.read())?.phase).toBe('recovery_required');
    } finally { test.close(); }
  });

  it('reports unconfirmed revocation separately from verified resource removal', async () => {
    const test = await fixture();
    try {
      await test.import(); test.alterGrant('revoke');
      expect((await test.send((await test.start()).href)).status).toBe(303);
      expect((await test.port.read())?.phase).toBe('removed_revocation_unconfirmed');
      expect((await test.view()).revocationUnconfirmed).toBe(true);
    } finally { test.close(); }
  });

  it('rejects new expired/tampered imports, cross-origin writes, CSRF, and denied or expired callbacks without a grant', async () => {
    const test = await fixture();
    try {
      expect((await test.send('/api/teardown/import', { handoff: test.handoff }, { origin: 'https://foreign.example.com' })).status).toBe(403);
      expect((await test.send('/api/teardown/import', { handoff: test.handoff.replace('gateway_teardown_handoff_envelope', 'other') })).status).toBe(409);
      await test.import();
      expect((await test.send('/api/teardown/authorize', {}, { csrf: 'wrong' })).status).toBe(403);
      const denied = await test.start(); denied.searchParams.delete('code'); denied.searchParams.set('error', 'access_denied');
      expect((await test.send(denied.href)).status).toBe(303);
      const expired = await test.start(); test.advance();
      expect((await test.send(expired.href)).status).toBe(404);
      expect(test.grants()).toBe(0); expect(test.mutations).toEqual([]);
    } finally { test.close(); }
    const fresh = await fixture();
    try { fresh.advance(); expect((await fresh.import()).status).toBe(409); }
    finally { fresh.close(); }
  });
});
