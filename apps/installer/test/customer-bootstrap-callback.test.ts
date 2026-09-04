import type { BoundaryValue } from '../src/boundary';
import {
  executeCustomerBootstrapCallback,
  type CustomerBootstrapConvergenceResult,
} from '../src/customer-bootstrap-callback';
import {
  createCustomerBootstrapCapability,
  consumeCustomerBootstrapCapability,
  initialCustomerBootstrapState,
  startCustomerBootstrapOauth,
  type CustomerBootstrapState,
} from '../src/customer-bootstrap-state';
import { CustomerStage2ConvergerError } from '../src/customer-stage2-converger';

const NOW = 1_900_000_000_000;
const ACCOUNT_ID = 'a'.repeat(32);
const INSTALL_ID = `acg-${'b'.repeat(24)}`;
const CLIENT_ID = 'c'.repeat(32);
const ACCESS_TOKEN = `token_${'d'.repeat(32)}`;
const CODE = `code_${'e'.repeat(32)}`;
const INSTALL_SCOPES = [
  'access-acct.read', 'zone-access.write', 'dns.write', 'mcp-portals.write',
  'workers-routes.read', 'workers-scripts.write', 'zone.read',
];
const COMPLETE_CONVERGENCE: CustomerBootstrapConvergenceResult = Object.freeze({
  verified: true,
  ownershipReceipt: 'complete',
  managementAccess: 'enforced',
  portal: 'converged',
  sourceSet: 'converged',
  finalRuntime: 'active-recovery-capable',
  workersDev: 'disabled',
});

function json(value: BoundaryValue, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function deterministicRandom(): (length: number) => Uint8Array {
  let call = 0;
  return (length) => new Uint8Array(length).fill(++call);
}

async function callbackFixture(): Promise<{
  current: CustomerBootstrapState;
  sessionSecret: string;
  attemptId: string;
  verifier: string;
  oauthState: string;
}> {
  const randomBytes = deterministicRandom();
  const capability = await createCustomerBootstrapCapability({ now: NOW, randomBytes });
  const initial = initialCustomerBootstrapState({
    installId: INSTALL_ID,
    bootstrapId: capability.bootstrapId,
    secretCommitment: capability.secretCommitment,
    expiresAt: capability.expiresAt,
  });
  const session = await consumeCustomerBootstrapCapability({
    current: initial,
    bootstrapId: capability.bootstrapId,
    secret: capability.secret,
    now: NOW + 1,
    randomBytes,
  });
  const oauth = await startCustomerBootstrapOauth({
    current: session.state,
    sessionSecret: session.sessionSecret,
    now: NOW + 2,
    randomBytes,
  });
  return {
    current: oauth.next,
    sessionSecret: session.sessionSecret,
    attemptId: oauth.attemptId,
    verifier: oauth.verifier,
    oauthState: oauth.state,
  };
}

describe('customer bootstrap callback failure injection', () => {
  it('orders durable arm, exchange, convergence, revocation, then READY', async () => {
    const fixture = await callbackFixture();
    const events: string[] = [];
    const result = await executeCustomerBootstrapCallback({
      ...fixture,
      code: CODE,
      accountId: ACCOUNT_ID,
      publicClientId: CLIENT_ID,
      now: NOW + 3,
      transport: async (input) => {
        const url = String(input);
        if (url.endsWith('/oauth2/token')) {
          events.push('exchange');
          return json({
            access_token: ACCESS_TOKEN,
            token_type: 'bearer',
            scope: INSTALL_SCOPES.join(' '),
          });
        }
        if (url.startsWith('https://api.cloudflare.com/client/v4/accounts')) {
          events.push('account-readback');
          return json({ success: true, errors: [], messages: [], result: [{ id: ACCOUNT_ID }] });
        }
        if (url.endsWith('/oauth2/revoke')) {
          events.push('revoke');
          return json({ revoked: true });
        }
        throw new Error('unexpected request');
      },
      persist: async (_expected, next) => { events.push(`persist-${next.status}`); },
      converge: async () => {
        events.push('converge-final-runtime');
        return COMPLETE_CONVERGENCE;
      },
    });
    expect(result.status).toBe('READY');
    expect(events).toEqual([
      'persist-CONVERGING',
      'exchange',
      'account-readback',
      'converge-final-runtime',
      'revoke',
      'persist-READY',
    ]);
  });

  it('returns a partial convergence failure to INCOMPLETE and revokes', async () => {
    const fixture = await callbackFixture();
    let revoked = false;
    const result = await executeCustomerBootstrapCallback({
      ...fixture,
      code: CODE,
      accountId: ACCOUNT_ID,
      publicClientId: CLIENT_ID,
      now: NOW + 3,
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
      persist: async () => undefined,
      converge: async () => { throw new Error('injected halfway failure'); },
    });
    expect(result).toMatchObject({
      status: 'INCOMPLETE',
      failureCode: 'provider_recovery_required',
    });
    expect(revoked).toBe(true);
  });

  it('records the converger reason so a payload failure names itself in the status read', async () => {
    const fixture = await callbackFixture();
    let revoked = false;
    const result = await executeCustomerBootstrapCallback({
      ...fixture,
      code: CODE,
      accountId: ACCOUNT_ID,
      publicClientId: CLIENT_ID,
      now: NOW + 3,
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
      persist: async () => undefined,
      converge: async () => {
        throw new CustomerStage2ConvergerError(
          'payload_recovery_required',
          'payload_portal_create_auth_http_403_code_10000',
        );
      },
    });
    expect(result).toMatchObject({
      status: 'INCOMPLETE',
      failureCode: 'provider_recovery_required',
      failureReason: 'payload_portal_create_auth_http_403_code_10000',
    });
    expect(revoked).toBe(true);

    // A converger failure without a reason still names its code.
    const bare = await executeCustomerBootstrapCallback({
      ...(await callbackFixture()),
      code: CODE,
      accountId: ACCOUNT_ID,
      publicClientId: CLIENT_ID,
      now: NOW + 3,
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
        if (url.endsWith('/oauth2/revoke')) return json({ revoked: true });
        throw new Error('unexpected request');
      },
      persist: async () => undefined,
      converge: async () => { throw new CustomerStage2ConvergerError('runtime_source_unavailable'); },
    });
    expect(bare).toMatchObject({
      status: 'INCOMPLETE',
      failureReason: 'converge_runtime_source_unavailable',
    });
  });

  it('keeps the final recovery-capable runtime INCOMPLETE when revocation is unconfirmed', async () => {
    const fixture = await callbackFixture();
    let converged = false;
    const result = await executeCustomerBootstrapCallback({
      ...fixture,
      code: CODE,
      accountId: ACCOUNT_ID,
      publicClientId: CLIENT_ID,
      now: NOW + 3,
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
        if (url.endsWith('/oauth2/revoke')) return json({ error: 'injected' }, 503);
        throw new Error('unexpected request');
      },
      persist: async () => undefined,
      converge: async () => {
        converged = true;
        return COMPLETE_CONVERGENCE;
      },
    });
    expect(converged).toBe(true);
    expect(result).toMatchObject({ status: 'INCOMPLETE', failureCode: 'revocation_unconfirmed' });
  });

  it('arms CONVERGING before a failed token exchange and requires fresh authorization', async () => {
    const fixture = await callbackFixture();
    const states: string[] = [];
    const result = await executeCustomerBootstrapCallback({
      ...fixture,
      code: CODE,
      accountId: ACCOUNT_ID,
      publicClientId: CLIENT_ID,
      now: NOW + 3,
      transport: async () => json({ error: 'invalid_grant' }, 400),
      persist: async (_expected, next) => { states.push(next.status); },
      converge: async () => COMPLETE_CONVERGENCE,
    });
    expect(states).toEqual(['CONVERGING', 'INCOMPLETE']);
    expect(result).toMatchObject({ status: 'INCOMPLETE', failureCode: 'grant_invalid' });
    expect(result.state.oauth).toBeNull();
  });
});
