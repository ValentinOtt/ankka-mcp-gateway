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
import type { CustomerBootstrapConverge } from '../src/customer-bootstrap-callback';
import { CustomerBootstrapConvergenceDriver } from '../src/customer-bootstrap-convergence-driver';
import {
  createCustomerBootstrapRouter,
  type CustomerBootstrapRouterDependencies,
  type CustomerBootstrapStatePort,
} from '../src/customer-bootstrap-router';
import type { CustomerCloudflareTransport } from '../src/customer-cloudflare-grant';
import {
  CUSTOMER_INSTALL_CONTINUE_PATH,
  CUSTOMER_INSTALL_OAUTH_START_PATH,
  CUSTOMER_INSTALL_STATUS_PATH,
} from '../src/customer-install-paths';
import { responseJson } from './boundary';
import { parseDeploySelection } from '../src/schema';
import { selectionInput } from './fixtures';

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
/** Runs every converger pass inline, the way a host without a per-invocation budget would. */
function inlineConvergence(
  state: CustomerBootstrapStatePort,
  transport: CustomerCloudflareTransport,
  converge: CustomerBootstrapConverge,
  now: () => number = () => NOW + 1,
): CustomerBootstrapRouterDependencies['startConvergence'] {
  const driver = new CustomerBootstrapConvergenceDriver({
    state,
    transport,
    publicClientId: CLIENT_ID,
    converge,
    now,
    schedule: async () => {
      await driver.continue();
    },
  });
  return (input) => driver.start(input);
}

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
  it('protects Worker configuration with the consumed session and locks edits during approval', async () => {
    const capability = await createCustomerBootstrapCapability({ now: NOW });
    let stored: CustomerBootstrapState | undefined;
    const accepted: string[] = [];
    const configured: string[] = [];
    const selection = parseDeploySelection({ ...selectionInput, firstSource: null });
    const publicSetup = { availableZones: [{ id: 'e'.repeat(32), name: 'example.com' }], selection: null, plan: null, expiresAt: capability.expiresAt };
    const router = createCustomerBootstrapRouter({
      accountId: ACCOUNT_ID, installId: INSTALL_ID, bootstrapId: capability.bootstrapId,
      secretCommitment: capability.secretCommitment, capabilityExpiresAt: capability.expiresAt, publicClientId: CLIENT_ID,
    }, {
      now: () => NOW + 1,
      state: {
        read: async () => stored,
        compareAndSet: async (revision, next) => {
          if ((stored?.revision ?? null) !== revision) return false;
          stored = next;
          return true;
        },
      },
      transport: async () => { throw new Error('no provider call expected'); },
      acceptHandoff: async () => { throw new Error('no final handoff expected'); },
      acceptSetup: async (permit) => { accepted.push(permit); },
      readSetup: async () => publicSetup,
      configureSetup: async (value) => { configured.push(value.basics.gatewayName); return publicSetup; },
      issueRelayTicket: async () => ({ relayTicket: RELAY_TICKET, expiresAt: NOW + 120_000 }),
      beginRelay: async ({ gatewayState, pkceChallenge, gatewayCallback }) => buildFixedRelayAuthorization({
        clientId: CLIENT_ID, relayStateKey: RELAY_KEY,
        gateway: { accountId: ACCOUNT_ID, installId: INSTALL_ID, callback: gatewayCallback }, operation: 'install',
        gatewayState, pkceChallenge, nonce: base64UrlEncode(new Uint8Array(32).fill(8)), now: NOW + 1,
      }),
      startConvergence: async () => { throw new Error('no grant expected'); },
    });
    expect((await router.fetch(new Request(`${ORIGIN}/__ankka/install/setup`))).status).toBe(403);
    const continued = await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_CONTINUE_PATH}`, {
      method: 'POST', headers: { origin: ORIGIN, 'content-type': 'application/json' },
      body: JSON.stringify({ bootstrapId: capability.bootstrapId, secret: capability.secret, setupPermit: 'signed-permit' }),
    }));
    expect(accepted).toEqual(['signed-permit']);
    const cookie = cookieValue(continued, SESSION_COOKIE);
    const post = (path: string, origin = ORIGIN, body = JSON.stringify(selection)) => router.fetch(new Request(`${ORIGIN}/__ankka/install/${path}`, {
      method: 'POST', headers: { origin, cookie, 'content-type': 'application/json' }, body,
    }));
    expect((await post('configuration', 'https://another.example')).status).toBe(403);
    expect(configured).toHaveLength(0);
    const invalid = await post('configuration', ORIGIN, JSON.stringify({ ...selection, basics: { ...selection.basics, portalHostname: selection.basics.managementHostname } }));
    expect(invalid.status).toBe(400);
    expect(await invalid.json()).toEqual({ error: 'invalid_configuration', reason: 'gateway_hostnames_invalid' });
    expect((await post('configuration')).status).toBe(200);
    expect(configured).toEqual([selection.basics.gatewayName]);
    expect((await post('oauth/start', ORIGIN, '{}')).status).toBe(200);
    expect((await post('configuration')).status).toBe(409);
    expect(configured).toHaveLength(1);
  });

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
    const statePort: CustomerBootstrapStatePort = {
      read: async () => stored,
      compareAndSet: async (expectedRevision, state) => {
        if ((stored?.revision ?? null) !== expectedRevision) return false;
        stored = state;
        persisted.push(JSON.stringify(state));
        return true;
      },
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
      state: statePort,
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
      startConvergence: inlineConvergence(statePort, transport, async (accessToken) => {
        convergedWith = accessToken;
        return COMPLETE_CONVERGENCE;
      }),
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
    expect(await callback.json()).toEqual({ schemaVersion: 1, status: 'READY', failureCode: null, failureReason: null });
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
    const statePort: CustomerBootstrapStatePort = {
      read: async () => stored,
      compareAndSet: async (expectedRevision, state) => {
        if ((stored?.revision ?? null) !== expectedRevision) return false;
        stored = state;
        return true;
      },
    };
    const transport: CustomerCloudflareTransport = async (input) => {
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
      state: statePort,
      acceptHandoff: async () => undefined,
      issueRelayTicket: async () => ({ relayTicket: RELAY_TICKET, expiresAt: NOW + 120_000 }),
      transport,
      beginRelay: async ({ gatewayState, pkceChallenge, gatewayCallback }) =>
        buildFixedRelayAuthorization({
          clientId: CLIENT_ID,
          relayStateKey: RELAY_KEY,
          gateway: { accountId: ACCOUNT_ID, installId: INSTALL_ID, callback: gatewayCallback },
          operation: 'install', gatewayState, pkceChallenge,
          nonce: base64UrlEncode(new Uint8Array(32).fill(7)), now: NOW + 1,
        }),
      startConvergence: inlineConvergence(statePort, transport, async () => {
        converged = true;
        return COMPLETE_CONVERGENCE;
      }),
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
      schemaVersion: 1, status: 'INCOMPLETE', failureCode: 'grant_invalid', failureReason: 'grant_account_ambiguous_accounts_2'
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
    const statePort: CustomerBootstrapStatePort = {
      read: async () => stored,
      compareAndSet: async (expectedRevision, state) => {
        if ((stored?.revision ?? null) !== expectedRevision) return false;
        stored = state;
        return true;
      },
    };
    const transport: CustomerCloudflareTransport = async () => {
      tokenExchangeAttempted = true;
      throw new Error('token exchange must not run for an expired cookie');
    };
    const router = createCustomerBootstrapRouter({
      accountId: ACCOUNT_ID,
      installId: INSTALL_ID,
      bootstrapId: capability.bootstrapId,
      secretCommitment: capability.secretCommitment,
      capabilityExpiresAt: capability.expiresAt,
      publicClientId: CLIENT_ID,
    }, {
      now: () => clock,
      state: statePort,
      acceptHandoff: async () => undefined,
      issueRelayTicket: async () => ({ relayTicket: RELAY_TICKET, expiresAt: clock + 120_000 }),
      transport,
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
      startConvergence: inlineConvergence(statePort, transport, async () => COMPLETE_CONVERGENCE, () => clock),
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
