import * as v from 'valibot';

import { base64UrlEncode } from '../src/crypto';
import type { BoundaryValue } from '../src/boundary';
import {
  buildFixedRelayAuthorization,
  relayCloudflareAuthorizationCode,
} from '../src/cloudflare-code-relay';
import {
  CUSTOMER_BOOTSTRAP_OAUTH_TTL_MS,
  createCustomerBootstrapCapability,
  type CustomerBootstrapState,
} from '../src/customer-bootstrap-state';
import { createCustomerBootstrapRouter } from '../src/customer-bootstrap-router';
import {
  CUSTOMER_INSTALL_CONTINUE_PATH,
  CUSTOMER_INSTALL_OAUTH_START_PATH,
  CUSTOMER_INSTALL_STATUS_PATH,
} from '../src/customer-install-paths';
import { responseJson } from './boundary';

const NOW = 1_800_000_000_000;
const ORIGIN = 'https://ankka-gateway-example.customer.workers.dev';
const ACCOUNT_ID = 'a'.repeat(32);
const INSTALL_ID = `acg-${'b'.repeat(24)}`;
const CLIENT_ID = 'c'.repeat(32);
const ACCESS_TOKEN = `token_${'d'.repeat(32)}`;
const RELAY_KEY = base64UrlEncode(new Uint8Array(32).fill(9));
const RELAY_TICKET = `${'r'.repeat(64)}.${'s'.repeat(43)}`;
const HANDOFF = '{"signed":"handoff"}';
const SERIALIZED_PLAN = '{"schemaVersion":1}';
const OWNERSHIP_CERTIFICATE = '{"signed":"certificate"}';
const SESSION_COOKIE = '__Host-ankka_bootstrap_session';
const PKCE_COOKIE = '__Host-ankka_bootstrap_pkce';
const INSTALL_SCOPES = [
  'access-acct.read', 'zone-access.write', 'dns.write', 'mcp-portals.write',
  'workers-routes.read', 'workers-scripts.write', 'zone.read',
];
const COMPLETE_CONVERGENCE = Object.freeze({
  verified: true,
  ownershipReceipt: 'complete',
  managementAccess: 'enforced',
  portal: 'converged',
  sourceSet: 'converged',
  finalRuntime: 'active-recovery-capable',
  workersDev: 'disabled',
} as const);

function json(value: BoundaryValue, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function cookieValue(response: Response, name: string): string {
  const values = response.headers.getSetCookie();
  const serialized = values.find((value) => value.startsWith(`${name}=`)) ?? '';
  const pair = serialized.split(';', 1)[0] ?? '';
  if (!pair.startsWith(`${name}=`)) throw new Error(`${name} cookie missing`);
  return pair;
}

function expectPkceCleared(response: Response): void {
  const serialized = response.headers.get('set-cookie') ?? '';
  expect(serialized).toContain(`${PKCE_COOKIE}=; Path=/; Max-Age=0;`);
  expect(serialized).toContain('Secure');
  expect(serialized).toContain('HttpOnly');
  expect(serialized).toContain('SameSite=Lax');
}

function expectSessionCleared(response: Response): void {
  const serialized = response.headers.get('set-cookie') ?? '';
  expect(serialized).toContain(`${SESSION_COOKIE}=; Path=/; Max-Age=0;`);
  expect(serialized).toContain('Secure');
  expect(serialized).toContain('HttpOnly');
  expect(serialized).toContain('SameSite=Lax');
}

describe('restricted customer bootstrap router', () => {
  it('runs code relay -> customer exchange -> verify -> revoke and permanently closes bootstrap', async () => {
    const capability = await createCustomerBootstrapCapability({ now: NOW });
    let stored: CustomerBootstrapState | undefined;
    const persisted: string[] = [];
    let convergedWith: string | null = null;
    let revoked = false;
    const transport = async (input: RequestInfo | URL): Promise<Response> => {
      const url = String(input);
      if (url.endsWith('/oauth2/token')) return json({
        access_token: ACCESS_TOKEN,
        token_type: 'bearer',
        scope: INSTALL_SCOPES.join(' '),
      });
      if (url.startsWith('https://api.cloudflare.com/client/v4/accounts')) {
        return json({ success: true, errors: [], messages: [], result: [{ id: ACCOUNT_ID }] });
      }
      if (url.endsWith('/oauth2/revoke')) {
        revoked = true;
        return json({ revoked: true });
      }
      throw new Error('unexpected request');
    };
    const router = createCustomerBootstrapRouter({
      accountId: ACCOUNT_ID,
      installId: INSTALL_ID,
      bootstrapId: capability.bootstrapId,
      secretCommitment: capability.secretCommitment,
      capabilityExpiresAt: capability.expiresAt,
      publicClientId: CLIENT_ID,
    }, {
      now: () => NOW + 1,
      state: {
        read: async () => stored,
        compareAndSet: async (expectedRevision, state) => {
          if ((stored?.revision ?? null) !== expectedRevision) return false;
          stored = state;
          persisted.push(JSON.stringify(state));
          return true;
        },
      },
      transport,
      acceptHandoff: async () => undefined,
      issueRelayTicket: async () => ({ relayTicket: RELAY_TICKET, expiresAt: NOW + 120_000 }),
      beginRelay: async ({ gatewayState, pkceChallenge, gatewayCallback }) =>
        buildFixedRelayAuthorization({
          clientId: CLIENT_ID,
          relayStateKey: RELAY_KEY,
          gateway: { accountId: ACCOUNT_ID, installId: INSTALL_ID, callback: gatewayCallback },
          operation: 'install',
          gatewayState,
          pkceChallenge,
          nonce: base64UrlEncode(new Uint8Array(32).fill(8)),
          now: NOW + 1,
        }),
      converge: async (accessToken) => {
        convergedWith = accessToken;
        return COMPLETE_CONVERGENCE;
      },
    });

    const health = await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_STATUS_PATH}`));
    expect(await health.json()).toEqual({ schemaVersion: 1, status: 'INCOMPLETE', canRetry: false });
    const continued = await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_CONTINUE_PATH}`, {
      method: 'POST',
      headers: { origin: ORIGIN, 'content-type': 'application/json' },
      body: JSON.stringify({
        bootstrapId: capability.bootstrapId,
        secret: capability.secret,
        serializedHandoff: HANDOFF,
        serializedPlan: SERIALIZED_PLAN,
        ownershipCertificate: OWNERSHIP_CERTIFICATE,
      }),
    }));
    expect(continued.status).toBe(200);
    const sessionCookie = cookieValue(continued, SESSION_COOKIE);
    const started = await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_OAUTH_START_PATH}`, {
      method: 'POST',
      headers: { origin: ORIGIN, cookie: sessionCookie, 'content-type': 'application/json' },
      body: '{}',
    }));
    const startBody = await responseJson(started, v.strictObject({
      schemaVersion: v.literal(1),
      authorizationUrl: v.string(),
    }));
    const pkceSetCookie = started.headers.get('set-cookie') ?? '';
    const pkceCookie = cookieValue(started, PKCE_COOKIE);
    expect(pkceSetCookie).toContain('Path=/');
    expect(pkceSetCookie).toContain('Max-Age=300');
    expect(pkceSetCookie).toContain('Secure');
    expect(pkceSetCookie).toContain('HttpOnly');
    expect(pkceSetCookie).toContain('SameSite=Lax');
    expect(pkceSetCookie).not.toContain('Domain=');
    if (stored?.oauth === null || stored?.oauth === undefined) throw new Error('OAuth attempt missing');
    expect(pkceCookie).toContain(`${PKCE_COOKIE}=${stored.oauth.attemptId}.`);
    expect(persisted.join('\n')).not.toContain('"verifier"');
    const callbackCookies = `${sessionCookie}; ${pkceCookie}`;
    const relayState = new URL(startBody.authorizationUrl).searchParams.get('state');
    if (relayState === null) throw new Error('relay state missing');
    const relayed = await relayCloudflareAuthorizationCode({
      code: `code_${'e'.repeat(32)}`,
      state: relayState,
      relayStateKey: RELAY_KEY,
      now: NOW + 2,
    });
    const callbacks = await Promise.all([
      router.fetch(new Request(relayed.location, { headers: { cookie: callbackCookies } })),
      router.fetch(new Request(relayed.location, { headers: { cookie: callbackCookies } })),
    ]);
    for (const response of callbacks) expectPkceCleared(response);
    const callback = callbacks.find((response) => response.status === 200);
    if (callback === undefined) throw new Error('successful callback missing');
    expect(callback.status).toBe(200);
    expectSessionCleared(callback);
    expect(await callback.json()).toEqual({ schemaVersion: 1, status: 'READY', failureCode: null });
    expect(callbacks.filter((response) => response.status === 200)).toHaveLength(1);
    expect(callbacks.some((response) => response.status === 404 || response.status === 409)).toBe(true);
    expect(convergedWith).toBe(ACCESS_TOKEN);
    expect(revoked).toBe(true);
    expect(stored?.status).toBe('READY');
    expect(persisted.join('\n')).not.toContain(ACCESS_TOKEN);
    expect(persisted.join('\n')).not.toContain(capability.secret);
    expect(persisted.join('\n')).not.toContain('"verifier"');

    const callbackReplay = await router.fetch(new Request(relayed.location, {
      headers: { cookie: callbackCookies },
    }));
    expect(callbackReplay.status).toBe(404);
    expectPkceCleared(callbackReplay);
    expectSessionCleared(callbackReplay);

    const replay = await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_OAUTH_START_PATH}`, {
      method: 'POST',
      headers: { origin: ORIGIN, cookie: sessionCookie, 'content-type': 'application/json' },
      body: '{}',
    }));
    expect(replay.status).toBe(404);
    expect((await router.fetch(new Request(`${ORIGIN}/api/status`))).status).toBe(404);
    expect(await (await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_STATUS_PATH}`))).json()).toEqual({
      schemaVersion: 1, status: 'READY', canRetry: false,
    });
  });

  it('keeps a multi-account Stage 2 grant INCOMPLETE and revokes it', async () => {
    const capability = await createCustomerBootstrapCapability({ now: NOW });
    let stored: CustomerBootstrapState | undefined;
    let revoked = false;
    let converged = false;
    const router = createCustomerBootstrapRouter({
      accountId: ACCOUNT_ID,
      installId: INSTALL_ID,
      bootstrapId: capability.bootstrapId,
      secretCommitment: capability.secretCommitment,
      capabilityExpiresAt: capability.expiresAt,
      publicClientId: CLIENT_ID,
    }, {
      now: () => NOW + 1,
      state: {
        read: async () => stored,
        compareAndSet: async (expectedRevision, state) => {
          if ((stored?.revision ?? null) !== expectedRevision) return false;
          stored = state;
          return true;
        },
      },
      acceptHandoff: async () => undefined,
      issueRelayTicket: async () => ({ relayTicket: RELAY_TICKET, expiresAt: NOW + 120_000 }),
      transport: async (input) => {
        const url = String(input);
        if (url.endsWith('/oauth2/token')) return json({
          access_token: ACCESS_TOKEN, token_type: 'bearer', scope: INSTALL_SCOPES.join(' '),
        });
        if (url.startsWith('https://api.cloudflare.com/client/v4/accounts')) return json({
          success: true,
          errors: [],
          messages: [],
          result: [{ id: ACCOUNT_ID }, { id: 'f'.repeat(32) }],
        });
        if (url.endsWith('/oauth2/revoke')) { revoked = true; return json({ revoked: true }); }
        throw new Error('unexpected request');
      },
      beginRelay: async ({ gatewayState, pkceChallenge, gatewayCallback }) =>
        buildFixedRelayAuthorization({
          clientId: CLIENT_ID,
          relayStateKey: RELAY_KEY,
          gateway: { accountId: ACCOUNT_ID, installId: INSTALL_ID, callback: gatewayCallback },
          operation: 'install', gatewayState, pkceChallenge,
          nonce: base64UrlEncode(new Uint8Array(32).fill(7)), now: NOW + 1,
        }),
      converge: async () => { converged = true; return COMPLETE_CONVERGENCE; },
    });
    await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_STATUS_PATH}`));
    const continued = await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_CONTINUE_PATH}`, {
      method: 'POST', headers: { origin: ORIGIN, 'content-type': 'application/json' },
      body: JSON.stringify({
        bootstrapId: capability.bootstrapId,
        secret: capability.secret,
        serializedHandoff: HANDOFF,
        serializedPlan: SERIALIZED_PLAN,
        ownershipCertificate: OWNERSHIP_CERTIFICATE,
      }),
    }));
    const sessionCookie = cookieValue(continued, SESSION_COOKIE);
    const started = await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_OAUTH_START_PATH}`, {
      method: 'POST', headers: { origin: ORIGIN, cookie: sessionCookie, 'content-type': 'application/json' },
      body: '{}',
    }));
    const pkceCookie = cookieValue(started, PKCE_COOKIE);
    const authorizationUrl = (await responseJson(started, v.strictObject({
      schemaVersion: v.literal(1),
      authorizationUrl: v.string(),
    }))).authorizationUrl;
    const state = new URL(authorizationUrl).searchParams.get('state');
    if (state === null) throw new Error('relay state missing');
    const relayed = await relayCloudflareAuthorizationCode({
      code: `code_${'g'.repeat(32)}`, state, relayStateKey: RELAY_KEY, now: NOW + 2,
    });
    const callback = await router.fetch(new Request(relayed.location, {
      headers: { cookie: `${sessionCookie}; ${pkceCookie}` },
    }));
    expectPkceCleared(callback);
    expect(await callback.json()).toEqual({
      schemaVersion: 1, status: 'INCOMPLETE', failureCode: 'grant_invalid',
    });
    expect(stored).toMatchObject({ status: 'INCOMPLETE', failureCode: 'grant_invalid' });
    expect(revoked).toBe(true);
    expect(converged).toBe(false);
  });

  it('rejects an expired PKCE cookie, clears it, and requires a fresh attempt', async () => {
    const capability = await createCustomerBootstrapCapability({ now: NOW });
    let stored: CustomerBootstrapState | undefined;
    let clock = NOW + 1;
    let relayStarts = 0;
    let tokenExchangeAttempted = false;
    const router = createCustomerBootstrapRouter({
      accountId: ACCOUNT_ID,
      installId: INSTALL_ID,
      bootstrapId: capability.bootstrapId,
      secretCommitment: capability.secretCommitment,
      capabilityExpiresAt: capability.expiresAt,
      publicClientId: CLIENT_ID,
    }, {
      now: () => clock,
      state: {
        read: async () => stored,
        compareAndSet: async (expectedRevision, state) => {
          if ((stored?.revision ?? null) !== expectedRevision) return false;
          stored = state;
          return true;
        },
      },
      acceptHandoff: async () => undefined,
      issueRelayTicket: async () => ({ relayTicket: RELAY_TICKET, expiresAt: clock + 120_000 }),
      transport: async () => {
        tokenExchangeAttempted = true;
        throw new Error('token exchange must not run for an expired cookie');
      },
      beginRelay: async ({ gatewayState, pkceChallenge, gatewayCallback }) => {
        relayStarts += 1;
        return buildFixedRelayAuthorization({
          clientId: CLIENT_ID,
          relayStateKey: RELAY_KEY,
          gateway: { accountId: ACCOUNT_ID, installId: INSTALL_ID, callback: gatewayCallback },
          operation: 'install',
          gatewayState,
          pkceChallenge,
          nonce: base64UrlEncode(new Uint8Array(32).fill(relayStarts)),
          now: clock,
        });
      },
      converge: async () => COMPLETE_CONVERGENCE,
    });
    await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_STATUS_PATH}`));
    const continued = await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_CONTINUE_PATH}`, {
      method: 'POST',
      headers: { origin: ORIGIN, 'content-type': 'application/json' },
      body: JSON.stringify({
        bootstrapId: capability.bootstrapId,
        secret: capability.secret,
        serializedHandoff: HANDOFF,
        serializedPlan: SERIALIZED_PLAN,
        ownershipCertificate: OWNERSHIP_CERTIFICATE,
      }),
    }));
    const sessionCookie = cookieValue(continued, SESSION_COOKIE);
    const started = await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_OAUTH_START_PATH}`, {
      method: 'POST',
      headers: { origin: ORIGIN, cookie: sessionCookie, 'content-type': 'application/json' },
      body: '{}',
    }));
    const firstPkceCookie = cookieValue(started, PKCE_COOKIE);
    const authorizationUrl = (await responseJson(started, v.strictObject({
      schemaVersion: v.literal(1),
      authorizationUrl: v.string(),
    }))).authorizationUrl;
    const relayState = new URL(authorizationUrl).searchParams.get('state');
    if (relayState === null) throw new Error('relay state missing');
    const relayed = await relayCloudflareAuthorizationCode({
      code: `code_${'h'.repeat(32)}`,
      state: relayState,
      relayStateKey: RELAY_KEY,
      now: clock + 1,
    });

    clock += CUSTOMER_BOOTSTRAP_OAUTH_TTL_MS + 1;
    const expired = await router.fetch(new Request(relayed.location, {
      headers: { cookie: `${sessionCookie}; ${firstPkceCookie}` },
    }));
    expect(expired.status).toBe(400);
    expectPkceCleared(expired);
    expect(tokenExchangeAttempted).toBe(false);

    const retried = await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_OAUTH_START_PATH}`, {
      method: 'POST',
      headers: { origin: ORIGIN, cookie: sessionCookie, 'content-type': 'application/json' },
      body: '{}',
    }));
    expect(retried.status).toBe(200);
    expect(cookieValue(retried, PKCE_COOKIE)).not.toBe(firstPkceCookie);
    expect(relayStarts).toBe(2);
  });
});
