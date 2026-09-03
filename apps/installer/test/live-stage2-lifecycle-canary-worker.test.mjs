import { readFile } from 'node:fs/promises';

import { afterEach, describe, expect, it, vi } from 'vitest';

import gateway from '../scripts/live-stage2-lifecycle-canary-worker.mjs';

const ACCOUNT_ID = 'a'.repeat(32);
const WORKER_NAME = 'ankka-stage2-gateway-canary';
const CLIENT_ID = 'client_stage2_public_123456789';
const GATEWAY_ORIGIN = `https://${WORKER_NAME}.customer.workers.dev`;
const CALLBACK = `${GATEWAY_ORIGIN}/__ankka/install/oauth/callback`;
const RELAY_WORKER_NAME = 'ankka-stage2-relay';
const RELAY_ORIGIN = `https://${RELAY_WORKER_NAME}.publisher.workers.dev`;
const RELAY_START = `${RELAY_ORIGIN}/oauth/start/install`;
const STATE = 's'.repeat(43);
const CHALLENGE = 'c'.repeat(43);
const COOKIE = `${'p'.repeat(80)}.${'h'.repeat(43)}`;
const TICKET = `${'t'.repeat(80)}.${'k'.repeat(43)}`;

function jsonResponse(value, status = 200) {
  return Response.json(value, { status, headers: { 'cache-control': 'no-store' } });
}

function environment(stateFetch) {
  return {
    CANARY_EXPECTED_ACCOUNT_ID: ACCOUNT_ID,
    CANARY_ADMIN_EMAIL: 'customer@example.com',
    CANARY_GATEWAY_CALLBACK_URL: CALLBACK,
    CANARY_PUBLIC_CLIENT_ID: CLIENT_ID,
    CANARY_RELAY_START_URL: RELAY_START,
    CANARY_RELAY_TICKET: TICKET,
    CANARY_RELAY_WORKER_NAME: RELAY_WORKER_NAME,
    CANARY_WORKER_NAME: WORKER_NAME,
    CANARY_EXPECTED_ZONE_NAME: 'example.com',
    CANARY_STATE: {
      idFromName: () => ({ toString: () => 'state-id' }),
      get: () => ({ fetch: stateFetch }),
    },
  };
}

function authorizationUrl() {
  const url = new URL('https://dash.cloudflare.com/oauth2/auth');
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', CLIENT_ID);
  url.searchParams.set('redirect_uri', `${RELAY_ORIGIN}/oauth/callback`);
  url.searchParams.set('scope', [
    'access-acct.read', 'zone-access.write', 'dns.write', 'mcp-portals.write',
    'workers-routes.read', 'workers-scripts.write', 'zone.read',
  ].join(' '));
  url.searchParams.set('state', `${'x'.repeat(80)}.${'y'.repeat(43)}`);
  url.searchParams.set('code_challenge', CHALLENGE);
  url.searchParams.set('code_challenge_method', 'S256');
  return url.href;
}

afterEach(() => vi.unstubAllGlobals());

describe('disposable customer-owned Stage 2 lifecycle Worker', () => {
  it('sends only the challenge and fixed ticket to the relay while the verifier stays HttpOnly', async () => {
    const stateFetch = vi.fn(async (request) => {
      expect(new URL(request.url).pathname).toBe('/start');
      return jsonResponse({
        schemaVersion: 1,
        cookie: COOKIE,
        state: STATE,
        challenge: CHALLENGE,
        expiresAt: Date.now() + 5 * 60_000,
      });
    });
    const relayFetch = vi.fn(async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      expect(request.url).toBe(RELAY_START);
      const body = await request.json();
      expect(body).toEqual({
        relayTicket: TICKET,
        gatewayState: STATE,
        pkceChallenge: CHALLENGE,
        gatewayCallback: CALLBACK,
      });
      expect(JSON.stringify(body)).not.toContain(COOKIE);
      return jsonResponse({ schemaVersion: 1, authorizationUrl: authorizationUrl() });
    });
    vi.stubGlobal('fetch', relayFetch);
    const response = await gateway.fetch(new Request(`${GATEWAY_ORIGIN}/oauth/start`, {
      method: 'POST',
      headers: {
        origin: GATEWAY_ORIGIN,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: '',
    }), environment(stateFetch));
    expect(response.status, await response.clone().text()).toBe(303);
    expect(response.headers.get('location')).toBe(authorizationUrl());
    expect(response.headers.get('set-cookie')).toContain(`${COOKIE_NAME_FOR_TEST()}=${COOKIE}`);
    expect(response.headers.get('set-cookie')).toContain('HttpOnly');
    expect(response.headers.get('set-cookie')).toContain('Secure');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(stateFetch).toHaveBeenCalledOnce();
    expect(relayFetch).toHaveBeenCalledOnce();
  });

  it('rejects cross-origin starts and stale callbacks before provider exchange', async () => {
    const stateFetch = vi.fn(async () => jsonResponse({ schemaVersion: 1, error: 'replayed' }, 409));
    const providerFetch = vi.fn();
    vi.stubGlobal('fetch', providerFetch);
    const crossOrigin = await gateway.fetch(new Request(`${GATEWAY_ORIGIN}/oauth/start`, {
      method: 'POST',
      headers: {
        origin: 'https://attacker.example',
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: '',
    }), environment(stateFetch));
    expect(crossOrigin.status).toBe(403);
    expect(providerFetch).not.toHaveBeenCalled();

    const callback = await gateway.fetch(new Request(
      `${CALLBACK}?code=provider-code-123456&state=${STATE}`,
      { headers: { cookie: `${COOKIE_NAME_FOR_TEST()}=${COOKIE}` } },
    ), environment(stateFetch));
    expect(callback.status).toBe(500);
    expect(await callback.text()).toContain('Stage 2 canary failed');
    expect(providerFetch).not.toHaveBeenCalled();
  });

  it('exchanges PKCE from the Gateway using the relay callback registered at authorization', async () => {
    const stateFetch = vi.fn(async (request) => {
      expect(new URL(request.url).pathname).toBe('/consume');
      return jsonResponse({
        schemaVersion: 1,
        attemptId: 'a'.repeat(43),
        verifier: 'v'.repeat(43),
      });
    });
    const providerFetch = vi.fn(async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      expect(request.url).toBe('https://dash.cloudflare.com/oauth2/token');
      const body = new URLSearchParams(await request.text());
      expect(body.get('client_id')).toBe(CLIENT_ID);
      expect(body.get('code')).toBe('provider-code-123456');
      expect(body.get('code_verifier')).toBe('v'.repeat(43));
      expect(body.get('grant_type')).toBe('authorization_code');
      expect(body.get('redirect_uri')).toBe(`${RELAY_ORIGIN}/oauth/callback`);
      return jsonResponse({ error: 'invalid_grant' }, 400);
    });
    vi.stubGlobal('fetch', providerFetch);

    const response = await gateway.fetch(new Request(
      `${CALLBACK}?code=provider-code-123456&state=${STATE}`,
      { headers: { cookie: `${COOKIE_NAME_FOR_TEST()}=${COOKIE}` } },
    ), environment(stateFetch));

    expect(response.status).toBe(500);
    expect(await response.text()).toContain('oauth_exchange_failed');
    expect(stateFetch).toHaveBeenCalledOnce();
    expect(providerFetch).toHaveBeenCalledOnce();
  });

  it('accepts live Workers Domains and MCP success envelopes while reporting later shapes', async () => {
    const zoneId = 'd'.repeat(32);
    const accessToken = 'stage2-access-token-1234567890';
    let revoked = false;
    const stateFetch = vi.fn(async () => jsonResponse({
      schemaVersion: 1,
      attemptId: 'a'.repeat(43),
      verifier: 'v'.repeat(43),
    }));
    const providerEnvelope = (result) => jsonResponse({
      success: true,
      errors: [],
      messages: [],
      result,
    });
    const providerFetch = vi.fn(async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      if (url.href === 'https://dash.cloudflare.com/oauth2/token') {
        return jsonResponse({
          access_token: accessToken,
          token_type: 'Bearer',
          scope: [
            'access-acct.read', 'zone-access.write', 'dns.write', 'mcp-portals.write',
            'workers-routes.read', 'workers-scripts.write', 'zone.read',
          ].join(' '),
        });
      }
      if (url.href === 'https://dash.cloudflare.com/oauth2/revoke') {
        revoked = true;
        return new Response(null, { status: 200 });
      }
      if (url.pathname === '/client/v4/accounts') {
        if (revoked) return jsonResponse({ success: false, errors: [], result: null }, 401);
        return providerEnvelope([{ id: ACCOUNT_ID }]);
      }
      if (url.pathname === '/client/v4/zones') {
        return providerEnvelope([{ id: zoneId, name: 'example.com', account: { id: ACCOUNT_ID } }]);
      }
      if (url.pathname.endsWith('/access/organizations')) {
        return providerEnvelope({ auth_domain: 'example.cloudflareaccess.com' });
      }
      if (url.pathname.endsWith('/access/identity_providers')) {
        return providerEnvelope([{ id: 'e'.repeat(32), type: 'onetimepin' }]);
      }
      if (url.pathname.endsWith('/workers/routes') || url.pathname.endsWith('/dns_records')) {
        return providerEnvelope([]);
      }
      if (url.pathname.endsWith('/workers/domains')) {
        return jsonResponse({ success: true, errors: null, messages: [], result: [] });
      }
      if (url.pathname.endsWith('/access/apps')) return providerEnvelope([]);
      if (url.pathname.endsWith('/access/ai-controls/mcp/servers')) {
        return jsonResponse({ success: true, result: [] });
      }
      if (url.pathname.endsWith('/access/ai-controls/mcp/portals')) return jsonResponse([]);
      throw new Error(`unexpected provider path: ${url.pathname}`);
    });
    vi.stubGlobal('fetch', providerFetch);

    const response = await gateway.fetch(new Request(
      `${CALLBACK}?code=provider-code-123456&state=${STATE}`,
      { headers: { cookie: `${COOKIE_NAME_FOR_TEST()}=${COOKIE}` } },
    ), environment(stateFetch));
    const text = await response.text();

    expect(response.status).toBe(500);
    expect(text).toContain(
      'mcp_portal_baseline_failed_http_200_codes_none_envelope_array__cleanup_complete',
    );
    expect(text).toContain('&quot;tokenRevocation&quot;: &quot;confirmed&quot;');
    expect(text).not.toContain(ACCOUNT_ID);
    expect(text).not.toContain(zoneId);
    expect(text).not.toContain(accessToken);
  });

  it('keeps the canary-only browser runner on the reviewed start implementation', async () => {
    const stateFetch = vi.fn(async () => jsonResponse({
      schemaVersion: 1,
      cookie: COOKIE,
      state: STATE,
      challenge: CHALLENGE,
      expiresAt: Date.now() + 5 * 60_000,
    }));
    const relayFetch = vi.fn(async () => jsonResponse({
      schemaVersion: 1,
      authorizationUrl: authorizationUrl(),
    }));
    vi.stubGlobal('fetch', relayFetch);
    const response = await gateway.fetch(
      new Request(`${GATEWAY_ORIGIN}/run`),
      environment(stateFetch),
    );
    expect(response.status).toBe(303);
    expect(response.headers.get('location')).toBe(authorizationUrl());
    expect(response.headers.get('set-cookie')).toContain(`${COOKIE_NAME_FOR_TEST()}=${COOKIE}`);
    expect(stateFetch).toHaveBeenCalledOnce();
    expect(relayFetch).toHaveBeenCalledOnce();
  });

  it('keeps secrets and provider identifiers out of config health and source logging', async () => {
    const env = environment(async () => jsonResponse({}));
    const response = await gateway.fetch(new Request(`${GATEWAY_ORIGIN}/config-health`), env);
    expect(response.status).toBe(200);
    const health = await response.json();
    expect(health).toMatchObject({
      schemaVersion: 1,
      revision: 'stage2-secret-retirement-v15',
      configured: true,
      account: true,
      admin: true,
      callback: true,
      callbackHost: true,
      client: true,
      relay: true,
      relayHost: true,
      ticket: true,
      worker: true,
      zone: true,
      durableObject: true,
    });
    expect(JSON.stringify(health)).not.toContain(ACCOUNT_ID);
    expect(JSON.stringify(health)).not.toContain(CLIENT_ID);
    expect(JSON.stringify(health)).not.toContain(TICKET);

    const source = await readFile(
      new URL('../scripts/live-stage2-lifecycle-canary-worker.mjs', import.meta.url),
      'utf8',
    );
    expect(source).not.toMatch(/console\.|waitUntil\(|localStorage|sessionStorage/u);
    expect(source).not.toMatch(/storage\.(?:put|sql\.exec)\([^\n]*(?:accessToken|refreshToken|verifier)/u);
    expect(source).toContain('accessToken = undefined');
    expect(source).toContain('refreshToken = undefined');
    expect(source).toContain('const COOKIE_TTL_SECONDS = 30 * 60;');
    expect(source).toContain(
      'const WORKERS_DOMAIN_ID = /^(?:[a-f0-9]{32}|[a-f0-9]{40})$/u;',
    );
    expect(source).toContain('const serverId = `ankka-s-${suffix}`;');
    expect(source).toContain('const portalId = `ankka-p-${suffix}`;');
    expect(source).toContain("const portalAppRoot = zonePath(target.zoneId, '/access/apps');");
    expect(source).toContain("if (![200, 202, 204].includes(status)) fail(stage, `http_${status}`);");
    expect(source).toContain('const noErrors = errors === null || Array.isArray(errors) && errors.length === 0;');
    expect(source).toContain('const result = workersNamespaceResult(await api(');
    expect(source).not.toContain('Cloudflare-Workers-Version-Overrides');
    expect(source).toContain("publicReadiness: 'external_post_callback_required'");
    expect(source).toContain('/secrets/${secretName}`');
    expect(source).toContain('relay_ticket_secret_not_absent');
    expect(source).toContain('retired_version_secret_binding_present');
  });

  it('accepts exact Worker-derived custom hosts and rejects unrelated hosts', async () => {
    const stateFetch = vi.fn(async () => jsonResponse({}));
    const custom = {
      ...environment(stateFetch),
      CANARY_GATEWAY_CALLBACK_URL: `https://${WORKER_NAME}.ankka.ai/__ankka/install/oauth/callback`,
      CANARY_RELAY_START_URL: `https://${RELAY_WORKER_NAME}.ankka.ai/oauth/start/install`,
    };
    const healthy = await gateway.fetch(new Request(`${GATEWAY_ORIGIN}/config-health`), custom);
    expect(await healthy.json()).toMatchObject({
      configured: true,
      callbackHost: true,
      relayHost: true,
    });

    const unrelated = {
      ...custom,
      CANARY_RELAY_START_URL: 'https://attacker.ankka.ai/oauth/start/install',
    };
    const unhealthy = await gateway.fetch(new Request(`${GATEWAY_ORIGIN}/config-health`), unrelated);
    expect(await unhealthy.json()).toMatchObject({ configured: false, relayHost: false });
  });
});

function COOKIE_NAME_FOR_TEST() {
  return '__Host-ankka-stage2-canary';
}
