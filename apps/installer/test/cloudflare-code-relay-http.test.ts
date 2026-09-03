import * as v from 'valibot';

import { base64UrlDecode, base64UrlEncode } from '../src/crypto';
import { createCloudflareCodeRelayHttpHandler } from '../src/cloudflare-code-relay-http';
import { createCloudflareGatewayRelayTicket } from '../src/cloudflare-gateway-relay-ticket';
import { CLOUDFLARE_CODE_RELAY_TTL_MS } from '../src/cloudflare-code-relay';

const NOW = 1_800_000_000_000;
const STATE_KEY = base64UrlEncode(new Uint8Array(32).fill(3));
const TICKET_KEY = base64UrlEncode(new Uint8Array(32).fill(4));
const NONCE = base64UrlEncode(new Uint8Array(32).fill(5));
const GATEWAY_STATE = base64UrlEncode(new Uint8Array(32).fill(6));
const CHALLENGE = base64UrlEncode(new Uint8Array(32).fill(7));
const CLIENT_ID = 'c'.repeat(32);
const CALLBACK = 'https://ankka-bootstrap.customer.workers.dev/__ankka/install/oauth/callback';
const authorizationResponseSchema = v.strictObject({
  schemaVersion: v.literal(1),
  authorizationUrl: v.string(),
});
const relayStateNonceSchema = v.looseObject({ nonce: v.string() });

async function fixture(initialNow = NOW + 1) {
  const ticket = await createCloudflareGatewayRelayTicket({
    accountId: 'a'.repeat(32),
    installId: `acg-${'b'.repeat(24)}`,
    workerName: 'ankka-bootstrap',
    gatewayCallback: CALLBACK,
    publicClientId: CLIENT_ID,
    operation: 'install',
    nonce: NONCE,
    now: NOW,
    expiresAt: NOW + 60_000,
    signingKey: TICKET_KEY,
  });
  let currentTime = initialNow;
  const handler = createCloudflareCodeRelayHttpHandler({
    publicClientId: CLIENT_ID,
    relayStateKey: STATE_KEY,
    relayTicketKey: TICKET_KEY,
  }, { now: () => currentTime });
  return { handler, ticket, setNow: (value: number) => { currentTime = value; } };
}

async function begin() {
  const { handler, ticket } = await fixture();
  const response = await handler.fetch(new Request('https://auth.ankka.ai/oauth/start/install', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      relayTicket: ticket,
      gatewayState: GATEWAY_STATE,
      pkceChallenge: CHALLENGE,
      gatewayCallback: CALLBACK,
    }),
  }));
  const body = v.parse(authorizationResponseSchema, await response.json());
  return { handler, response, authorizationUrl: body.authorizationUrl };
}

function expectSecurityHeaders(response: Response): void {
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(response.headers.get('referrer-policy')).toBe('no-referrer');
  expect(response.headers.get('content-security-policy')).toBe(
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  );
  expect(response.headers.get('x-content-type-options')).toBe('nosniff');
}

describe('Cloudflare authorization-code relay HTTP boundary', () => {
  it('accepts no scope input and produces the exact fixed install authorization', async () => {
    const { response, authorizationUrl } = await begin();
    expect(response.status).toBe(200);
    expectSecurityHeaders(response);
    const authorization = new URL(authorizationUrl);
    expect(authorization.origin + authorization.pathname).toBe('https://dash.cloudflare.com/oauth2/auth');
    expect(authorization.searchParams.get('scope')).toBe(
      'access-acct.read zone-access.write dns.write mcp-portals.write workers-routes.read workers-scripts.write zone.read',
    );
    expect(authorization.searchParams.get('code_challenge')).toBe(CHALLENGE);
    expect(authorization.searchParams.get('redirect_uri')).toBe(
      'https://auth.ankka.ai/oauth/callback',
    );

    const { handler, ticket } = await fixture();
    const widened = await handler.fetch(new Request('https://auth.ankka.ai/oauth/start/install', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        relayTicket: ticket,
        gatewayState: GATEWAY_STATE,
        pkceChallenge: CHALLENGE,
        gatewayCallback: CALLBACK,
        scope: 'account-settings.write',
      }),
    }));
    expect(widened.status).toBe(400);
  });

  it('relays a code only to the ticket-bound callback and never exchanges it', async () => {
    const { handler, authorizationUrl } = await begin();
    const state = new URL(authorizationUrl).searchParams.get('state');
    if (state === null) throw new Error('state missing');
    const response = await handler.fetch(new Request(
      `https://auth.ankka.ai/oauth/callback?code=code_${'d'.repeat(32)}&state=${encodeURIComponent(state)}`,
    ));
    expect(response.status).toBe(302);
    expectSecurityHeaders(response);
    const location = new URL(response.headers.get('location') ?? '');
    expect(location.origin + location.pathname).toBe(
      'https://ankka-bootstrap.customer.workers.dev/__ankka/install/oauth/callback',
    );
    expect(location.searchParams.get('code')).toBe(`code_${'d'.repeat(32)}`);
    expect(location.searchParams.get('state')).toBe(GATEWAY_STATE);
    expect(await response.text()).not.toContain(`code_${'d'.repeat(32)}`);
    expect(JSON.stringify([...response.headers])).not.toContain('access_token');
  });

  it('parses bounded provider denial metadata but forwards only one fixed customer-side error', async () => {
    const { handler, authorizationUrl } = await begin();
    const state = new URL(authorizationUrl).searchParams.get('state');
    if (state === null) throw new Error('state missing');
    const callback = new URL('https://auth.ankka.ai/oauth/callback');
    callback.searchParams.set('error', 'access_denied');
    callback.searchParams.set('error_description', 'secret provider description cfoat_must_not_leak');
    callback.searchParams.set('error_uri', 'https://provider.example/error?secret=cfoat_must_not_leak');
    callback.searchParams.set('state', state);
    const response = await handler.fetch(new Request(callback));
    expect(response.status).toBe(302);
    expectSecurityHeaders(response);
    const location = new URL(response.headers.get('location') ?? '');
    expect(location.searchParams.get('error')).toBe('authorization_rejected');
    expect(location.searchParams.get('state')).toBe(GATEWAY_STATE);
    expect(location.toString()).not.toContain('access_denied');
    expect(location.toString()).not.toContain('cfoat_must_not_leak');
    expect(await response.text()).not.toContain('cfoat_must_not_leak');
  });

  it('rejects callback substitution, duplicate query values, and operation substitution', async () => {
    const { handler, ticket } = await fixture();
    const wrongCallback = await handler.fetch(new Request('https://auth.ankka.ai/oauth/start/install', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        relayTicket: ticket,
        gatewayState: GATEWAY_STATE,
        pkceChallenge: CHALLENGE,
        gatewayCallback: 'https://attacker.example/oauth/callback',
      }),
    }));
    expect(wrongCallback.status).toBe(400);
    const nonExactCallback = await handler.fetch(new Request('https://auth.ankka.ai/oauth/start/install', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        relayTicket: ticket,
        gatewayState: GATEWAY_STATE,
        pkceChallenge: CHALLENGE,
        gatewayCallback: `${CALLBACK}?`,
      }),
    }));
    expect(nonExactCallback.status).toBe(400);
    const wrongOperation = await handler.fetch(new Request('https://auth.ankka.ai/oauth/start/upgrade', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        relayTicket: ticket,
        gatewayState: GATEWAY_STATE,
        pkceChallenge: CHALLENGE,
        gatewayCallback: CALLBACK,
      }),
    }));
    expect(wrongOperation.status).toBe(400);
    const duplicate = await handler.fetch(new Request(
      'https://auth.ankka.ai/oauth/callback?code=one&code=two&state=bad',
    ));
    expect(duplicate.status).toBe(400);
  });

  it('tolerates the provider-echoed scope only within the sealed operation ceiling and never forwards it', async () => {
    const { handler, authorizationUrl } = await begin();
    const state = new URL(authorizationUrl).searchParams.get('state');
    if (state === null) throw new Error('state missing');
    const code = `code_${'d'.repeat(32)}`;
    const exact = 'access-acct.read zone-access.write dns.write mcp-portals.write workers-routes.read workers-scripts.write zone.read';
    for (const scope of [exact, 'workers-scripts.write', 'zone.read dns.write']) {
      const response = await handler.fetch(new Request(
        `https://auth.ankka.ai/oauth/callback?code=${code}&state=${encodeURIComponent(state)}&scope=${encodeURIComponent(scope)}`,
      ));
      expect(response.status, scope).toBe(302);
      const location = new URL(response.headers.get('location') ?? '');
      expect([...location.searchParams.keys()].sort()).toEqual(['code', 'state']);
      expect(location.searchParams.get('code')).toBe(code);
      expect(location.searchParams.get('state')).toBe(GATEWAY_STATE);
    }
    for (const scope of [
      'account-settings.write', `${exact} account-settings.write`, 'zone.read zone.read', '', 'workers-scripts.write '.repeat(60),
    ]) {
      const response = await handler.fetch(new Request(
        `https://auth.ankka.ai/oauth/callback?code=${code}&state=${encodeURIComponent(state)}&scope=${encodeURIComponent(scope)}`,
      ));
      expect(response.status, JSON.stringify(scope)).toBe(400);
      expect(response.headers.get('location')).toBeNull();
    }
  });

  it('rejects duplicate, unknown, mixed, and unbounded provider callback query input', async () => {
    const { handler, authorizationUrl } = await begin();
    const state = new URL(authorizationUrl).searchParams.get('state');
    if (state === null) throw new Error('state missing');
    const callbacks = [
      `?error=access_denied&error_description=one&error_description=two&state=${encodeURIComponent(state)}`,
      `?error=access_denied&state=${encodeURIComponent(state)}&unknown=value`,
      `?code=code_${'d'.repeat(32)}&error=access_denied&state=${encodeURIComponent(state)}`,
      `?error=access_denied&error_description=${'x'.repeat(1_025)}&state=${encodeURIComponent(state)}`,
      `?error=access_denied&error_uri=${encodeURIComponent('http://provider.example/error')}&state=${encodeURIComponent(state)}`,
    ];
    for (const query of callbacks) {
      const response = await handler.fetch(new Request(`https://auth.ankka.ai/oauth/callback${query}`));
      expect(response.status).toBe(400);
      expectSecurityHeaders(response);
      expect(await response.json()).toEqual({ schemaVersion: 1, error: 'relay_rejected' });
    }
  });

  it('rejects arbitrary destination, scope, token endpoint, and unsigned nonce start input', async () => {
    const attempts = [
      { scope: 'account-settings.write' },
      { destination: 'https://attacker.example/oauth/callback' },
      { tokenEndpoint: 'https://dash.cloudflare.com/oauth2/token' },
      { nonce: GATEWAY_STATE },
    ];
    for (const attempt of attempts) {
      const { handler, ticket } = await fixture();
      const response = await handler.fetch(new Request('https://auth.ankka.ai/oauth/start/install', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          relayTicket: ticket,
          gatewayState: GATEWAY_STATE,
          pkceChallenge: CHALLENGE,
          gatewayCallback: CALLBACK,
          ...attempt,
        }),
      }));
      expect(response.status).toBe(400);
    }
  });

  it('uses the signed ticket nonce in relay state', async () => {
    const { authorizationUrl } = await begin();
    const state = new URL(authorizationUrl).searchParams.get('state');
    if (state === null) throw new Error('state missing');
    const payload = state.split('.')[0];
    if (payload === undefined) throw new Error('state payload missing');
    const claims = v.parse(relayStateNonceSchema,
      JSON.parse(new TextDecoder().decode(base64UrlDecode(payload))));
    expect(claims.nonce).toBe(NONCE);
    expect(claims.nonce).not.toBe(GATEWAY_STATE);
  });

  it('is stateless across repeated callbacks but rejects the same signed state at expiry', async () => {
    const { handler, ticket, setNow } = await fixture();
    const started = await handler.fetch(new Request('https://auth.ankka.ai/oauth/start/install', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        relayTicket: ticket,
        gatewayState: GATEWAY_STATE,
        pkceChallenge: CHALLENGE,
        gatewayCallback: CALLBACK,
      }),
    }));
    const authorizationUrl = v.parse(authorizationResponseSchema, await started.json()).authorizationUrl;
    const state = new URL(authorizationUrl).searchParams.get('state');
    if (state === null) throw new Error('state missing');
    const callback = `https://auth.ankka.ai/oauth/callback?code=code_${'e'.repeat(32)}&state=${encodeURIComponent(state)}`;
    expect((await handler.fetch(new Request(callback))).status).toBe(302);
    expect((await handler.fetch(new Request(callback))).status).toBe(302);
    setNow(NOW + 1 + CLOUDFLARE_CODE_RELAY_TTL_MS);
    const expired = await handler.fetch(new Request(callback));
    expect(expired.status).toBe(410);
    expectSecurityHeaders(expired);
  });

  it('rejects expired gateway tickets before minting relay state', async () => {
    const { handler, ticket } = await fixture(NOW + 60_000);
    const response = await handler.fetch(new Request('https://auth.ankka.ai/oauth/start/install', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        relayTicket: ticket,
        gatewayState: GATEWAY_STATE,
        pkceChallenge: CHALLENGE,
        gatewayCallback: CALLBACK,
      }),
    }));
    expect(response.status).toBe(410);
    expectSecurityHeaders(response);
  });

  it('applies hardened headers to not-found responses', async () => {
    const { handler } = await fixture();
    const response = await handler.fetch(new Request('https://auth.ankka.ai/oauth2/token'));
    expect(response.status).toBe(404);
    expectSecurityHeaders(response);
  });
});
