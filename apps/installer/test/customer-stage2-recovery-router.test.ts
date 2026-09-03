import * as v from 'valibot';

import type { BoundaryValue } from '../src/boundary';
import {
  buildFixedRelayAuthorization,
  relayCloudflareAuthorizationCode,
} from '../src/cloudflare-code-relay';
import { base64UrlEncode } from '../src/crypto';
import {
  consumeCustomerBootstrapCapability,
  createCustomerBootstrapCapability,
  initialCustomerBootstrapState,
  startCustomerBootstrapOauth,
  type CustomerBootstrapState,
} from '../src/customer-bootstrap-state';
import {
  CUSTOMER_INSTALL_CONTINUE_PATH,
  CUSTOMER_INSTALL_OAUTH_START_PATH,
} from '../src/customer-install-paths';
import { createCustomerStage2RecoveryRouter } from '../src/customer-stage2-recovery-router';
import { responseJson } from './boundary';

const NOW = 1_800_000_000_000;
const ORIGIN = 'https://manage.example.com';
const ACCOUNT_ID = 'a'.repeat(32);
const INSTALL_ID = `acg-${'b'.repeat(24)}`;
const CLIENT_ID = 'c'.repeat(32);
const ACCESS_TOKEN = `token_${'d'.repeat(32)}`;
const RELAY_KEY = base64UrlEncode(new Uint8Array(32).fill(9));
const RELAY_TICKET = `${'r'.repeat(64)}.${'s'.repeat(43)}`;
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

function json(value: BoundaryValue): Response {
  return Response.json(value);
}

function cookieValue(response: Response, name: string): string {
  const serialized = response.headers.getSetCookie().find((value) => value.startsWith(`${name}=`));
  if (serialized === undefined) throw new Error(`${name} cookie missing`);
  return serialized.split(';', 1)[0] ?? '';
}

async function consumedState(): Promise<CustomerBootstrapState> {
  const capability = await createCustomerBootstrapCapability({ now: NOW });
  const initial = initialCustomerBootstrapState({
    installId: INSTALL_ID,
    bootstrapId: capability.bootstrapId,
    secretCommitment: capability.secretCommitment,
    expiresAt: capability.expiresAt,
  });
  return (await consumeCustomerBootstrapCapability({
    current: initial,
    bootstrapId: capability.bootstrapId,
    secret: capability.secret,
    now: NOW + 1,
  })).state;
}

describe('final-runtime Stage 2 recovery router', () => {
  it('uses fresh customer-key authority, fresh PKCE, direct exchange, and revocation', async () => {
    let stored = await consumedState();
    const persisted: string[] = [];
    let ticketRequests = 0;
    let revoked = false;
    let convergedWith: string | null = null;
    const router = createCustomerStage2RecoveryRouter({
      accountId: ACCOUNT_ID,
      installId: INSTALL_ID,
      publicClientId: CLIENT_ID,
      managementOrigin: ORIGIN,
    }, {
      now: () => NOW + 2,
      state: {
        read: async () => stored,
        compareAndSet: async (revision, state) => {
          if (stored.revision !== revision) return false;
          stored = state;
          persisted.push(JSON.stringify(state));
          return true;
        },
      },
      assertRecoverable: async () => undefined,
      issueRelayTicket: async () => {
        ticketRequests += 1;
        return { relayTicket: RELAY_TICKET, expiresAt: NOW + 120_000 };
      },
      beginRelay: async ({ gatewayState, pkceChallenge, gatewayCallback }) =>
        buildFixedRelayAuthorization({
          clientId: CLIENT_ID,
          relayStateKey: RELAY_KEY,
          gateway: { accountId: ACCOUNT_ID, installId: INSTALL_ID, callback: gatewayCallback },
          operation: 'install',
          gatewayState,
          pkceChallenge,
          nonce: base64UrlEncode(new Uint8Array(32).fill(8)),
          now: NOW + 2,
        }),
      transport: async (input) => {
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
      },
      converge: async (accessToken) => {
        convergedWith = accessToken;
        return COMPLETE_CONVERGENCE;
      },
    });

    const start = await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_OAUTH_START_PATH}`, {
      method: 'POST',
      headers: { origin: ORIGIN, 'content-type': 'application/json' },
      body: '{}',
    }));
    expect(start.status).toBe(200);
    const session = cookieValue(start, SESSION_COOKIE);
    const pkce = cookieValue(start, PKCE_COOKIE);
    const authorization = await responseJson(start, v.strictObject({
      schemaVersion: v.literal(1),
      authorizationUrl: v.string(),
    }));
    const relayState = new URL(authorization.authorizationUrl).searchParams.get('state');
    if (relayState === null) throw new Error('relay state missing');
    const callback = await relayCloudflareAuthorizationCode({
      code: `code_${'e'.repeat(32)}`,
      state: relayState,
      relayStateKey: RELAY_KEY,
      now: NOW + 3,
    });
    const result = await router.fetch(new Request(callback.location, {
      headers: { cookie: `${session}; ${pkce}` },
    }));
    expect(result.status).toBe(200);
    await expect(result.json()).resolves.toEqual({
      schemaVersion: 1,
      status: 'READY',
      failureCode: null,
    });
    expect(ticketRequests).toBe(1);
    expect(convergedWith).toBe(ACCESS_TOKEN);
    expect(revoked).toBe(true);
    expect(stored.status).toBe('READY');
    expect(persisted.join('\n')).not.toContain(ACCESS_TOKEN);
    expect(persisted.join('\n')).not.toContain('verifier');

    const closed = await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_OAUTH_START_PATH}`, {
      method: 'POST',
      headers: { origin: ORIGIN, 'content-type': 'application/json' },
      body: '{}',
    }));
    expect(closed.status).toBe(404);
    expect((await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_CONTINUE_PATH}`))).status)
      .toBe(404);
  });

  it('does not replace a live attempt or request relay authority when recovery proof fails', async () => {
    const capability = await createCustomerBootstrapCapability({ now: NOW });
    const initial = initialCustomerBootstrapState({
      installId: INSTALL_ID,
      bootstrapId: capability.bootstrapId,
      secretCommitment: capability.secretCommitment,
      expiresAt: capability.expiresAt,
    });
    const consumed = await consumeCustomerBootstrapCapability({
      current: initial,
      bootstrapId: capability.bootstrapId,
      secret: capability.secret,
      now: NOW + 1,
    });
    const oauth = await startCustomerBootstrapOauth({
      current: consumed.state,
      sessionSecret: consumed.sessionSecret,
      now: NOW + 2,
    });
    let stored = oauth.next;
    let ticketRequests = 0;
    const router = createCustomerStage2RecoveryRouter({
      accountId: ACCOUNT_ID,
      installId: INSTALL_ID,
      publicClientId: CLIENT_ID,
      managementOrigin: ORIGIN,
    }, {
      now: () => NOW + 3,
      state: {
        read: async () => stored,
        compareAndSet: async (revision, state) => {
          if (stored.revision !== revision) return false;
          stored = state;
          return true;
        },
      },
      assertRecoverable: async () => undefined,
      issueRelayTicket: async () => {
        ticketRequests += 1;
        throw new Error('must not request');
      },
      beginRelay: async () => { throw new Error('must not relay'); },
      transport: async () => { throw new Error('must not exchange'); },
      converge: async () => COMPLETE_CONVERGENCE,
    });
    const response = await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_OAUTH_START_PATH}`, {
      method: 'POST',
      headers: { origin: ORIGIN, 'content-type': 'application/json' },
      body: '{}',
    }));
    expect(response.status).toBe(409);
    expect(ticketRequests).toBe(0);

    const blocked = createCustomerStage2RecoveryRouter({
      accountId: ACCOUNT_ID,
      installId: INSTALL_ID,
      publicClientId: CLIENT_ID,
      managementOrigin: ORIGIN,
    }, {
      now: () => NOW + 3,
      state: { read: async () => stored, compareAndSet: async () => false },
      assertRecoverable: async () => { throw new Error('ownership mismatch'); },
      issueRelayTicket: async () => {
        ticketRequests += 1;
        return { relayTicket: RELAY_TICKET, expiresAt: NOW + 120_000 };
      },
      beginRelay: async () => { throw new Error('must not relay'); },
      transport: async () => { throw new Error('must not exchange'); },
      converge: async () => COMPLETE_CONVERGENCE,
    });
    const denied = await blocked.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_OAUTH_START_PATH}`, {
      method: 'POST',
      headers: { origin: ORIGIN, 'content-type': 'application/json' },
      body: '{}',
    }));
    expect(denied.status).toBe(409);
    expect(ticketRequests).toBe(0);
  });
});
