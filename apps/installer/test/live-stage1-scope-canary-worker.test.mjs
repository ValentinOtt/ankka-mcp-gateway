import { readFile } from 'node:fs/promises';

import { afterEach, describe, expect, it, vi } from 'vitest';

import worker from '../scripts/live-stage1-scope-canary-worker.mjs';

const ORIGIN = 'https://stage1-canary.example.workers.dev';
const CALLBACK = `${ORIGIN}/callback`;
const env = Object.freeze({
  CANARY_OAUTH_CLIENT_ID: 'c'.repeat(32),
  CANARY_EXPECTED_ACCOUNT_ID: 'a'.repeat(32),
  CANARY_CALLBACK_URL: CALLBACK,
  CANARY_TOKEN_ENDPOINT_AUTH_METHOD: 'client_secret_basic',
  CANARY_OAUTH_CLIENT_SECRET: `secret-${'s'.repeat(32)}`,
  CANARY_STATE_KEY: 'k'.repeat(43),
});
const finalizerEnv = Object.freeze({
  ...env,
  CANARY_FINALIZER_WORKER_NAME: 'ankka-gateway-finalizer-target',
  CANARY_FINALIZER_WORKER_ID: 'b'.repeat(32),
  CANARY_FINALIZER_NAMESPACE_ID: 'd'.repeat(32),
  CANARY_FINALIZER_ROOT_DOMAIN_ID: 'e'.repeat(40),
  CANARY_FINALIZER_ROOT_HOSTNAME: 'ankka-gateway-finalizer-target.example.com',
  CANARY_FINALIZER_INERT_SHA256: 'f'.repeat(64),
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('disposable live Stage 1 scope canary Worker', () => {
  it('starts exact-scope confidential-client PKCE with an authenticated, expiring cookie', async () => {
    const response = await worker.fetch(new Request(`${ORIGIN}/start`), env);
    expect(response.status).toBe(303);
    const authorization = new URL(response.headers.get('location'));
    expect(`${authorization.origin}${authorization.pathname}`).toBe('https://dash.cloudflare.com/oauth2/auth');
    expect(authorization.searchParams.get('response_type')).toBe('code');
    expect(authorization.searchParams.get('redirect_uri')).toBe(CALLBACK);
    expect(authorization.searchParams.get('scope')).toBe('workers-scripts.write');
    expect(authorization.searchParams.get('code_challenge_method')).toBe('S256');
    expect(authorization.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(authorization.searchParams.get('state')).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(response.headers.get('set-cookie')).toMatch(
      /^__Host-ankka-stage1-canary=.+; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=600$/u,
    );
    expect(response.headers.get('cache-control')).toContain('no-store');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
  });

  it('uses client_secret_basic for exchange and revocation without putting the client ID in either body', async () => {
    const start = await worker.fetch(new Request(`${ORIGIN}/start`), env);
    const authorization = new URL(start.headers.get('location'));
    const cookie = start.headers.get('set-cookie').split(';', 1)[0];
    const requests = [];
    vi.stubGlobal('fetch', vi.fn(async (input, init) => {
      const request = new Request(input, init);
      requests.push(request.clone());
      if (request.url.endsWith('/oauth2/token')) {
        return Response.json({
          access_token: `token-${'t'.repeat(32)}`,
          scope: 'unexpected.scope',
          token_type: 'bearer',
        });
      }
      if (request.url.endsWith('/oauth2/revoke')) return new Response(null, { status: 200 });
      if (request.url.includes('/client/v4/accounts')) {
        return Response.json({ errors: [{ code: 9109 }], messages: [], success: false }, { status: 403 });
      }
      throw new Error('unexpected request');
    }));

    const callback = new URL(CALLBACK);
    callback.search = new URLSearchParams({
      code: 'authorization-code',
      state: authorization.searchParams.get('state'),
    }).toString();
    const response = await worker.fetch(new Request(callback, { headers: { cookie } }), env);
    expect(response.status).toBe(500);
    const tokenRequest = requests.find((request) => request.url.endsWith('/oauth2/token'));
    const revokeRequest = requests.find((request) => request.url.endsWith('/oauth2/revoke'));
    expect(tokenRequest.headers.get('authorization')).toMatch(/^Basic /u);
    expect(revokeRequest.headers.get('authorization')).toBe(tokenRequest.headers.get('authorization'));
    expect(await tokenRequest.text()).not.toContain('client_id=');
    expect(await revokeRequest.text()).not.toContain('client_id=');
    expect(requests.some((request) => request.url.includes('/client/v4/accounts'))).toBe(true);
  });

  it('fails closed when client authentication bindings disagree and never exposes the secret in health output', async () => {
    const health = await worker.fetch(new Request(`${ORIGIN}/config-health`), env);
    const body = await health.text();
    expect(JSON.parse(body).clientAuthentication).toEqual({
      method: 'client_secret_basic',
      valid: true,
    });
    expect(body).not.toContain(env.CANARY_OAUTH_CLIENT_SECRET);
    await expect(worker.fetch(new Request(`${ORIGIN}/`), {
      ...env,
      CANARY_OAUTH_CLIENT_SECRET: undefined,
    })).resolves.toMatchObject({ status: 503 });
    await expect(worker.fetch(new Request(`${ORIGIN}/`), {
      ...env,
      CANARY_TOKEN_ENDPOINT_AUTH_METHOD: 'none',
    })).resolves.toMatchObject({ status: 503 });
  });

  it('binds startup to the registered callback origin and keeps every other route inert', async () => {
    await expect(worker.fetch(new Request('https://other.example.workers.dev/start'), env))
      .resolves.toMatchObject({ status: 404 });
    await expect(worker.fetch(new Request(`${ORIGIN}/anything`), env))
      .resolves.toMatchObject({ status: 404 });
    await expect(worker.fetch(new Request(`${ORIGIN}/start`, { method: 'POST' }), env))
      .resolves.toMatchObject({ status: 405 });
    await expect(worker.fetch(new Request(`${ORIGIN}/`), {
      ...env,
      CANARY_EXPECTED_ACCOUNT_ID: 'not-an-account',
    })).resolves.toMatchObject({ status: 503 });
  });

  it('offers a separate post-revocation customer handoff without widening OAuth', async () => {
    const root = await worker.fetch(new Request(`${ORIGIN}/`), env);
    expect(await root.text()).toContain('/handoff-start');

    const response = await worker.fetch(new Request(`${ORIGIN}/handoff-start`), env);
    expect(response.status).toBe(303);
    const authorization = new URL(response.headers.get('location'));
    expect(authorization.searchParams.get('scope')).toBe('workers-scripts.write');
    expect(authorization.searchParams.get('code_challenge_method')).toBe('S256');
    expect(authorization.searchParams.has('offline_access')).toBe(false);
    expect(response.headers.get('set-cookie')).toContain('; Secure; HttpOnly; SameSite=Lax;');
  });

  it('offers the fixed hosted finalizer only when every exact root binding is configured', async () => {
    const root = await worker.fetch(new Request(`${ORIGIN}/`), finalizerEnv);
    expect(await root.text()).toContain('/finalizer-start');

    const response = await worker.fetch(new Request(`${ORIGIN}/finalizer-start`), finalizerEnv);
    expect(response.status).toBe(303);
    const authorization = new URL(response.headers.get('location'));
    expect(authorization.searchParams.get('scope')).toBe('workers-scripts.write');
    expect(authorization.searchParams.get('code_challenge_method')).toBe('S256');
    expect(authorization.searchParams.has('offline_access')).toBe(false);

    const incomplete = await worker.fetch(new Request(`${ORIGIN}/`), {
      ...env,
      CANARY_FINALIZER_WORKER_NAME: 'ankka-gateway-finalizer-target',
    });
    expect(incomplete.status).toBe(503);
  });

  it('does not expose a handoff or capability without the authenticated installer cookie', async () => {
    const waiting = await worker.fetch(new Request(`${ORIGIN}/handoff`), env);
    expect(waiting.status).toBe(410);
    expect(waiting.headers.get('location')).toBeNull();
    expect(await waiting.text()).not.toContain('cap=');

    const ready = await worker.fetch(new Request(`${ORIGIN}/handoff/ready`), env);
    expect(ready.status).toBe(410);
    expect(ready.headers.get('location')).toBeNull();
    expect(await ready.text()).not.toContain('cap=');
  });

  it('keeps the canary feature-disabled and credential-free in public source', async () => {
    const source = await readFile(new URL('../scripts/live-stage1-scope-canary-worker.mjs', import.meta.url), 'utf8');
    expect(source).toContain("const EXACT_SCOPE = 'workers-scripts.write';");
    expect(source).toContain("tokenEndpointAuthMethod === 'client_secret_basic'");
    expect(source).toContain("headers.set('authorization', `Basic ${btoa(`${config.clientId}:${config.clientSecret}`)}`)");
    expect(source).toContain("state: 'deleted'");
    expect(source).toContain('/workers/workers/${workerId}/versions');
    expect(source).toContain("method: 'PUT'");
    expect(source).toContain("tokenRevocation:'confirmed_before_handoff'");
    expect(source).toContain("'access-control-allow-origin': this.env.ANKKA_INSTALLER_ORIGIN");
    expect(source).toContain("mode:'cors'");
    expect(source).toContain("headers.set('location', '/handoff')");
    expect(source).toContain("location.hash = new URLSearchParams({ cap: session.bootstrapSecret })");
    expect(source).toContain("history.replaceState(null,'','/')");
    expect(source).toContain("connect-src 'self'");
    expect(source).toContain('runHostedFinalizerCanary');
    expect(source).toContain('reverified_before_each_root_delete');
    expect(source).toContain('finalizer_namespace_delete_failed');
    expect(source).toContain('finalizer_root_domain_not_absent');
    expect(source.indexOf('await revokeAndProve')).toBeLessThan(source.indexOf("headers.set('location', '/handoff')"));
    expect(source).toContain('attempt < 8');
    expect(source).not.toContain('attempt < 40');
    expect(source).not.toMatch(/console\.|localStorage|sessionStorage|indexedDB/u);
    expect(source).not.toMatch(/\b[a-f0-9]{32}\b/u);
    expect(source).not.toContain('6ace98c3cfe05f58a7fbe18f88390bfc');
  });
});
