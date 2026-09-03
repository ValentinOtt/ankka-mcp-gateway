import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import relay from '../scripts/live-stage2-code-relay-worker.mjs';

const ACCOUNT_ID = 'a'.repeat(32);
const INSTALL_ID = `acg-${'b'.repeat(24)}`;
const WORKER_NAME = 'ankka-stage2-gateway-canary';
const CLIENT_ID = 'client_stage2_public_123456789';
const RELAY_WORKER_NAME = 'ankka-stage2-relay';
const RELAY_ORIGIN = `https://${RELAY_WORKER_NAME}.publisher.workers.dev`;
const RELAY_CALLBACK = `${RELAY_ORIGIN}/oauth/callback`;
const GATEWAY_CALLBACK = `https://${WORKER_NAME}.customer.workers.dev/__ankka/install/oauth/callback`;
const TICKET_CONTEXT = 'ankka-live-stage2-relay-ticket-v1';
const EXACT_SCOPE = [
  'access-acct.read', 'zone-access.write', 'dns.write', 'mcp-portals.write',
  'workers-routes.read', 'workers-scripts.write', 'zone.read',
].join(' ');

const encoder = new TextEncoder();

function isRecord(value) {
  return Object.prototype.toString.call(value) === '[object Object]';
}

function isString(value) {
  return Object.prototype.toString.call(value) === '[object String]';
}

function isBoolean(value) {
  return Object.prototype.toString.call(value) === '[object Boolean]';
}

function isNumber(value) {
  return Object.prototype.toString.call(value) === '[object Number]';
}

function base64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function randomToken() {
  const value = new Uint8Array(32);
  crypto.getRandomValues(value);
  return base64Url(value);
}

function canonical(value) {
  if (value === null || isString(value) || isBoolean(value) || isNumber(value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (!isRecord(value)) throw new TypeError('unsupported canonical value');
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

async function hmac(keyValue, payload) {
  const keyBytes = Uint8Array.from(
    atob(keyValue.replaceAll('-', '+').replaceAll('_', '/') + '='),
    (character) => character.charCodeAt(0),
  );
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  return base64Url(new Uint8Array(await crypto.subtle.sign(
    'HMAC', key, encoder.encode(`${TICKET_CONTEXT}.${payload}`),
  )));
}

async function fixture({ customDomains = false } = {}) {
  const relayStateKey = randomToken();
  const relayTicketKey = randomToken();
  const now = Date.now();
  const relayOrigin = customDomains ? `https://${RELAY_WORKER_NAME}.ankka.ai` : RELAY_ORIGIN;
  const relayCallback = `${relayOrigin}/oauth/callback`;
  const gatewayCallback = customDomains
    ? `https://${WORKER_NAME}.ankka.ai/__ankka/install/oauth/callback`
    : GATEWAY_CALLBACK;
  const claims = {
    schemaVersion: 1,
    purpose: 'cloudflare-code-relay',
    operation: 'install',
    accountId: ACCOUNT_ID,
    installId: INSTALL_ID,
    workerName: WORKER_NAME,
    callback: gatewayCallback,
    clientId: CLIENT_ID,
    nonce: randomToken(),
    issuedAt: now - 1_000,
    expiresAt: now + 10 * 60_000,
  };
  const payload = base64Url(encoder.encode(canonical(claims)));
  const relayTicket = `${payload}.${await hmac(relayTicketKey, payload)}`;
  const env = {
    CANARY_EXPECTED_ACCOUNT_ID: ACCOUNT_ID,
    CANARY_RELAY_CALLBACK_URL: relayCallback,
    CANARY_PUBLIC_CLIENT_ID: CLIENT_ID,
    CANARY_GATEWAY_CALLBACK: gatewayCallback,
    CANARY_INSTALL_ID: INSTALL_ID,
    CANARY_RELAY_STATE_KEY: relayStateKey,
    CANARY_RELAY_TICKET_KEY: relayTicketKey,
    CANARY_RELAY_WORKER_NAME: RELAY_WORKER_NAME,
    CANARY_GATEWAY_WORKER_NAME: WORKER_NAME,
  };
  return { env, gatewayCallback, relayCallback, relayOrigin, relayTicket };
}

describe('disposable Stage 2 code-only relay Worker', () => {
  it('maps the fixed install ticket to exact scopes and relays only code and Gateway state', async () => {
    const { env, relayTicket } = await fixture();
    const gatewayState = randomToken();
    const pkceChallenge = randomToken();
    const start = await relay.fetch(new Request(`${RELAY_ORIGIN}/oauth/start/install`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        relayTicket,
        gatewayState,
        pkceChallenge,
        gatewayCallback: GATEWAY_CALLBACK,
      }),
    }), env);
    expect(start.status).toBe(200);
    expect(start.headers.get('cache-control')).toContain('no-store');
    expect(start.headers.get('referrer-policy')).toBe('no-referrer');
    const startValue = await start.json();
    expect(Object.keys(startValue).sort()).toEqual(['authorizationUrl', 'schemaVersion']);
    const authorization = new URL(startValue.authorizationUrl);
    expect(authorization.origin + authorization.pathname).toBe('https://dash.cloudflare.com/oauth2/auth');
    expect(authorization.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(authorization.searchParams.get('redirect_uri')).toBe(RELAY_CALLBACK);
    expect(authorization.searchParams.get('scope')).toBe(EXACT_SCOPE);
    expect(authorization.searchParams.get('code_challenge')).toBe(pkceChallenge);
    expect(authorization.searchParams.get('code_challenge_method')).toBe('S256');
    const sealedState = authorization.searchParams.get('state');
    expect(sealedState).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/u);

    const callback = await relay.fetch(new Request(
      `${RELAY_CALLBACK}?code=provider-code-123456&scope=${encodeURIComponent(EXACT_SCOPE)}` +
        `&state=${encodeURIComponent(sealedState)}`,
    ), env);
    expect(callback.status).toBe(302);
    const location = new URL(callback.headers.get('location'));
    expect(location.origin + location.pathname).toBe(GATEWAY_CALLBACK);
    expect([...location.searchParams.keys()].sort()).toEqual(['code', 'state']);
    expect(location.searchParams.get('code')).toBe('provider-code-123456');
    expect(location.searchParams.get('state')).toBe(gatewayState);
  });

  it('accepts only the exact non-duplicated Cloudflare scope echo', async () => {
    const { env, relayTicket } = await fixture();
    const start = await relay.fetch(new Request(`${RELAY_ORIGIN}/oauth/start/install`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        relayTicket,
        gatewayState: randomToken(),
        pkceChallenge: randomToken(),
        gatewayCallback: GATEWAY_CALLBACK,
      }),
    }), env);
    const sealedState = new URL((await start.json()).authorizationUrl).searchParams.get('state');
    const callback = (query) => relay.fetch(new Request(
      `${RELAY_CALLBACK}?code=provider-code-123456&state=${encodeURIComponent(sealedState)}&${query}`,
    ), env);

    expect((await callback(`scope=${encodeURIComponent(EXACT_SCOPE.replace(' zone.read', ''))}`)).status)
      .toBe(400);
    expect((await callback(
      `scope=${encodeURIComponent(EXACT_SCOPE)}&scope=${encodeURIComponent(EXACT_SCOPE)}`,
    )).status).toBe(400);
    expect((await callback(`scope=${encodeURIComponent(EXACT_SCOPE)}&extra=value`)).status).toBe(400);
  });

  it('rejects callback substitution, arbitrary operations, and ticket tampering', async () => {
    const { env, relayTicket } = await fixture();
    const body = {
      relayTicket,
      gatewayState: randomToken(),
      pkceChallenge: randomToken(),
      gatewayCallback: 'https://attacker.example/__ankka/install/oauth/callback',
    };
    const substituted = await relay.fetch(new Request(`${RELAY_ORIGIN}/oauth/start/install`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    }), env);
    expect(substituted.status).toBe(400);

    const arbitrary = await relay.fetch(new Request(`${RELAY_ORIGIN}/oauth/start/repair`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({
        ...body, gatewayCallback: GATEWAY_CALLBACK,
      }),
    }), env);
    expect(arbitrary.status).toBe(404);

    const tampered = await relay.fetch(new Request(`${RELAY_ORIGIN}/oauth/start/install`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({
        ...body,
        gatewayCallback: GATEWAY_CALLBACK,
        relayTicket: `${relayTicket.slice(0, -1)}x`,
      }),
    }), env);
    expect(tampered.status).toBe(400);
  });

  it('accepts only exact Worker-derived custom callback hosts', async () => {
    const { env, gatewayCallback, relayCallback, relayOrigin, relayTicket } = await fixture({
      customDomains: true,
    });
    const start = await relay.fetch(new Request(`${relayOrigin}/oauth/start/install`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        relayTicket,
        gatewayState: randomToken(),
        pkceChallenge: randomToken(),
        gatewayCallback,
      }),
    }), env);
    expect(start.status, await start.clone().text()).toBe(200);
    expect(new URL((await start.json()).authorizationUrl).searchParams.get('redirect_uri'))
      .toBe(relayCallback);

    const substitutedEnv = {
      ...env,
      CANARY_RELAY_CALLBACK_URL: 'https://attacker.ankka.ai/oauth/callback',
    };
    const substituted = await relay.fetch(new Request(`${relayOrigin}/oauth/start/install`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        relayTicket,
        gatewayState: randomToken(),
        pkceChallenge: randomToken(),
        gatewayCallback,
      }),
    }), substitutedEnv);
    expect(substituted.status).toBe(400);
  });

  it('has no provider token exchange or Cloudflare management transport in the relay artifact', async () => {
    const source = await readFile(
      new URL('../scripts/live-stage2-code-relay-worker.mjs', import.meta.url),
      'utf8',
    );
    for (const forbidden of [
      'api.cloudflare.com', '/oauth2/token', 'access_token', 'refresh_token', 'client_secret',
    ]) {
      expect(source).not.toContain(forbidden);
    }
    expect(source).toContain('const STATE_TTL_MS = 30 * 60 * 1_000;');
  });
});
