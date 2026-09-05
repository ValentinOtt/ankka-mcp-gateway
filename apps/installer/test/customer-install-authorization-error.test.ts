import { buildFixedRelayAuthorization } from '../src/cloudflare-code-relay';
import { base64UrlEncode } from '../src/crypto';
import { createCustomerBootstrapRouter } from '../src/customer-bootstrap-router';
import {
  consumeCustomerBootstrapCapability,
  createCustomerBootstrapCapability,
  initialCustomerBootstrapState,
  startCustomerBootstrapOauth,
} from '../src/customer-bootstrap-state';
import {
  CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH,
  CUSTOMER_INSTALL_OAUTH_START_PATH,
  CUSTOMER_INSTALL_ROOT_PATH,
} from '../src/customer-install-paths';
import { customerInstallProgressPage } from '../src/customer-install-progress-page';
import { createCustomerStage2RecoveryRouter } from '../src/customer-stage2-recovery-router';

const NOW = 1_800_000_000_000;
const ORIGIN = 'https://manage.example.com';
const ACCOUNT_ID = 'a'.repeat(32);
const INSTALL_ID = `acg-${'b'.repeat(24)}`;
const CLIENT_ID = 'c'.repeat(32);
const SESSION_COOKIE = '__Host-ankka_bootstrap_session';
const PKCE_COOKIE = '__Host-ankka_bootstrap_pkce';

describe.each(['bootstrap', 'recovery'] as const)('%s authorization rejection', (kind) => {
  it.each([true, false])('renders the rejection, clears PKCE, and allows a fresh approval (browser: %s)', async (browser) => {
    const capability = await createCustomerBootstrapCapability({ now: NOW });
    const consumed = await consumeCustomerBootstrapCapability({
      current: initialCustomerBootstrapState({
        installId: INSTALL_ID,
        bootstrapId: capability.bootstrapId,
        secretCommitment: capability.secretCommitment,
        expiresAt: capability.expiresAt,
      }),
      bootstrapId: capability.bootstrapId,
      secret: capability.secret,
      now: NOW + 1,
    });
    const attempt = await startCustomerBootstrapOauth({
      current: consumed.state, sessionSecret: consumed.sessionSecret, now: NOW + 2,
    });
    let stored = attempt.next;
    const transport = vi.fn(async () => { throw new Error('must not exchange a rejected authorization'); });
    const startConvergence = vi.fn(async () => { throw new Error('must not start an unauthorized install'); });
    const state = {
      read: async () => stored,
      compareAndSet: async (revision: number | null, next: typeof stored) => {
        if (stored.revision !== revision) return false;
        stored = next;
        return true;
      },
    };
    const commonDependencies = {
      now: () => NOW + 3,
      state,
      transport,
      startConvergence,
      issueRelayTicket: async () => ({
        relayTicket: `${'r'.repeat(64)}.${'s'.repeat(43)}`, expiresAt: NOW + 120_000,
      }),
      beginRelay: async (input: {
        gatewayState: string; pkceChallenge: string; gatewayCallback: string;
      }) => buildFixedRelayAuthorization({
        clientId: CLIENT_ID,
        relayStateKey: base64UrlEncode(new Uint8Array(32).fill(9)),
        gateway: { accountId: ACCOUNT_ID, installId: INSTALL_ID, callback: input.gatewayCallback },
        operation: 'install',
        gatewayState: input.gatewayState,
        pkceChallenge: input.pkceChallenge,
        nonce: base64UrlEncode(new Uint8Array(32).fill(8)),
        now: NOW + 3,
      }),
    };
    const dependencies = browser ? {
      ...commonDependencies,
      callbackResponse: (outcome: Parameters<typeof customerInstallProgressPage>[1], cookies: readonly string[]) =>
        customerInstallProgressPage('manage.example.com', outcome, cookies),
    } : commonDependencies;
    const config = { accountId: ACCOUNT_ID, installId: INSTALL_ID, publicClientId: CLIENT_ID };
    const router = kind === 'bootstrap'
      ? createCustomerBootstrapRouter({
        ...config, bootstrapId: capability.bootstrapId,
        secretCommitment: capability.secretCommitment, capabilityExpiresAt: capability.expiresAt,
      }, { ...dependencies, acceptHandoff: async () => undefined })
      : createCustomerStage2RecoveryRouter({ ...config, managementOrigin: ORIGIN }, {
        ...dependencies, assertRecoverable: async () => undefined,
      });
    const cookie = `${SESSION_COOKIE}=${consumed.sessionSecret}; ${PKCE_COOKIE}=${attempt.attemptId}.${attempt.expiresAt}.${attempt.verifier}`;
    const callback = new URL(`${ORIGIN}${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`);
    callback.searchParams.set('error', 'authorization_rejected');
    callback.searchParams.set('state', 'x'.repeat(43));
    const tampered = await router.fetch(new Request(callback, { headers: { cookie } }));
    expect(tampered.status).toBe(409);
    expect(stored).toEqual(attempt.next);

    callback.searchParams.set('state', attempt.state);
    const response = await router.fetch(new Request(callback, { headers: { cookie } }));
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(response.headers.getSetCookie().join('\n')).toContain(`${PKCE_COOKIE}=; Path=/; Max-Age=0;`);
    expect(response.headers.getSetCookie().some((value) => value.startsWith(`${SESSION_COOKIE}=`)))
      .toBe(kind === 'recovery');
    if (browser) {
      expect(response.headers.get('content-type')).toBe('text/html; charset=utf-8');
      const html = await response.text();
      expect(html).toContain('Cloudflare approval did not complete');
      expect(html).toContain(`href="${CUSTOMER_INSTALL_ROOT_PATH}"`);
      expect(html).not.toContain('Cloudflare approved');
      expect(html).not.toContain('<script');
      for (const secret of [consumed.sessionSecret, attempt.state, attempt.verifier]) {
        expect(html).not.toContain(secret);
      }
    } else {
      expect(await response.json()).toEqual({
        schemaVersion: 1, status: 'INCOMPLETE', failureCode: 'authorization_rejected',
      });
    }
    expect(stored.status).toBe('INCOMPLETE');
    expect(stored.failureCode).toBe('authorization_rejected');
    expect(stored.oauth).toBeNull();
    const rejectedRevision = stored.revision;
    expect((await router.fetch(new Request(callback, { headers: { cookie } }))).status).toBe(400);
    expect(stored.revision).toBe(rejectedRevision);

    const retryHeaders = new Headers({ origin: ORIGIN, 'content-type': 'application/json' });
    if (kind === 'bootstrap') retryHeaders.set('cookie', `${SESSION_COOKIE}=${consumed.sessionSecret}`);
    const retry = await router.fetch(new Request(`${ORIGIN}${CUSTOMER_INSTALL_OAUTH_START_PATH}`, {
      method: 'POST',
      headers: retryHeaders,
      body: '{}',
    }));
    expect(retry.status).toBe(200);
    expect(stored.oauth?.attemptId).not.toBe(attempt.attemptId);
    expect(retry.headers.getSetCookie().join('\n')).not.toContain(attempt.verifier);
    expect(transport).not.toHaveBeenCalled();
    expect(startConvergence).not.toHaveBeenCalled();
  });
});
