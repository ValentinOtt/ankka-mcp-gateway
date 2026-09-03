import { DeployError } from '../src/errors';
import type { BoundaryValue } from '../src/boundary';
import {
  buildHostedBootstrapAuthorizationUrl,
  executeHostedBootstrapGrant,
} from '../src/hosted-bootstrap-grant';

class StagedProviderError extends Error {
  constructor(readonly stage: string, readonly outcome: string) {
    super(`provider ${stage} ${outcome} token_${'z'.repeat(32)}`);
    this.name = 'StagedProviderError';
  }
}

const CLIENT_ID = 'a'.repeat(32);
const CLIENT_SECRET = `secret-${'b'.repeat(32)}`;
const VERIFIER = 'c'.repeat(43);
const STATE = 'd'.repeat(43);
const CHALLENGE = 'e'.repeat(43);
const CODE = `code_${'f'.repeat(32)}`;
const ACCESS_TOKEN = `token_${'g'.repeat(32)}`;
const ACCOUNT_ID = '1'.repeat(32);

function json(value: BoundaryValue, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/**
 * A JSON body that arrives only when pulled and errors once the request signal
 * has aborted, like a real fetch body. A consumer that reads after the deadline
 * has released the response sees the AbortError; one that reads inside it gets
 * the bytes.
 */
function streamedJson(value: BoundaryValue, signal: AbortSignal | null | undefined, status = 200): Response {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let delivered = false;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (signal?.aborted) {
        controller.error(new DOMException('The operation was aborted', 'AbortError'));
        return;
      }
      if (delivered) {
        controller.close();
        return;
      }
      delivered = true;
      controller.enqueue(bytes);
    },
  }, { highWaterMark: 0 });
  return new Response(body, { status, headers: { 'content-type': 'application/json' } });
}

describe('hosted Stage 1 bootstrap grant', () => {
  it('builds confidential Authorization Code + PKCE with one scope and no refresh request', () => {
    const url = new URL(buildHostedBootstrapAuthorizationUrl({
      clientId: CLIENT_ID, state: STATE, challenge: CHALLENGE,
    }));
    expect(url.searchParams.get('scope')).toBe('workers-scripts.write');
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('code_challenge')).toBe(CHALLENGE);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.toString()).not.toContain('offline_access');
    expect(url.toString()).not.toContain('refresh_token');
  });

  it('binds one account, exposes the token only to fixed deployment, then revokes', async () => {
    const requests: Array<{ readonly url: string; readonly authorization: string | null; readonly body: string }> = [];
    const result = await executeHostedBootstrapGrant({
      code: CODE,
      verifier: VERIFIER,
      config: { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET },
      transport: async (input, init) => {
        const request = new Request(input, init);
        requests.push({
          url: request.url,
          authorization: request.headers.get('authorization'),
          body: await request.clone().text(),
        });
        if (request.url.endsWith('/oauth2/token')) return json({
          access_token: ACCESS_TOKEN,
          token_type: 'bearer',
          scope: 'workers-scripts.write',
        });
        if (request.url.startsWith('https://api.cloudflare.com/client/v4/accounts')) return json({
          success: true, errors: [], messages: [], result: [{ id: ACCOUNT_ID }],
        });
        if (request.url.endsWith('/oauth2/revoke')) return json({ revoked: true });
        throw new Error('unexpected request');
      },
      deploy: async ({ accessToken, accountId }) => {
        expect(accessToken).toBe(ACCESS_TOKEN);
        expect(accountId).toBe(ACCOUNT_ID);
        return Object.freeze({ workerName: 'ankka-gateway-test' });
      },
    });
    expect(result).toEqual({
      accountId: ACCOUNT_ID,
      deployment: { workerName: 'ankka-gateway-test' },
      grantRevocation: 'confirmed',
    });
    expect(JSON.stringify(result)).not.toContain(ACCESS_TOKEN);
    const tokenRequest = requests.find((request) => request.url.endsWith('/oauth2/token'));
    if (tokenRequest === undefined) throw new Error('token request missing');
    expect(tokenRequest.authorization).toMatch(/^Basic /u);
    expect(tokenRequest.body).toContain(`code_verifier=${VERIFIER}`);
    expect(requests.filter((request) => request.url.endsWith('/oauth2/revoke'))).toHaveLength(1);
  });

  it('revokes even when fixed deployment fails', async () => {
    let revoked = false;
    await expect(executeHostedBootstrapGrant({
      code: CODE,
      verifier: VERIFIER,
      config: { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET },
      transport: async (input) => {
        const url = String(input);
        if (url.endsWith('/oauth2/token')) return json({
          access_token: ACCESS_TOKEN, token_type: 'bearer', scope: 'workers-scripts.write',
        });
        if (url.startsWith('https://api.cloudflare.com/client/v4/accounts')) return json({
          success: true, errors: [], messages: [], result: [{ id: ACCOUNT_ID }],
        });
        if (url.endsWith('/oauth2/revoke')) { revoked = true; return json({ revoked: true }); }
        throw new Error('unexpected request');
      },
      deploy: async () => { throw new Error(`must-not-escape-${ACCESS_TOKEN}`); },
    })).rejects.toMatchObject({ reason: 'bootstrap_deploy_failed' });
    expect(revoked).toBe(true);
  });

  it('keeps a provider stage and outcome, and only those, as the deploy failure reason', async () => {
    let revoked = false;
    await expect(executeHostedBootstrapGrant({
      code: CODE,
      verifier: VERIFIER,
      config: { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET },
      transport: async (input) => {
        const url = String(input);
        if (url.endsWith('/oauth2/token')) return json({
          access_token: ACCESS_TOKEN, token_type: 'bearer', scope: 'workers-scripts.write',
        });
        if (url.startsWith('https://api.cloudflare.com/client/v4/accounts')) return json({
          success: true, errors: [], messages: [], result: [{ id: ACCOUNT_ID }],
        });
        if (url.endsWith('/oauth2/revoke')) { revoked = true; return json({ revoked: true }); }
        throw new Error('unexpected request');
      },
      deploy: async () => { throw new StagedProviderError('account_worker_subdomain_get', 'rejected'); },
    })).rejects.toMatchObject({ reason: 'account_worker_subdomain_get_rejected' });
    expect(revoked).toBe(true);
  });

  it('keeps a stable deploy error code as the failure reason', async () => {
    let revoked = false;
    await expect(executeHostedBootstrapGrant({
      code: CODE,
      verifier: VERIFIER,
      config: { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET },
      transport: async (input) => {
        const url = String(input);
        if (url.endsWith('/oauth2/token')) return json({
          access_token: ACCESS_TOKEN, token_type: 'bearer', scope: 'workers-scripts.write',
        });
        if (url.startsWith('https://api.cloudflare.com/client/v4/accounts')) return json({
          success: true, errors: [], messages: [], result: [{ id: ACCOUNT_ID }],
        });
        if (url.endsWith('/oauth2/revoke')) { revoked = true; return json({ revoked: true }); }
        throw new Error('unexpected request');
      },
      deploy: async () => { throw new DeployError(503, 'bootstrap_not_ready'); },
    })).rejects.toMatchObject({ reason: 'bootstrap_not_ready' });
    expect(revoked).toBe(true);
  });

  it('rejects multi-account consent before deployment and still revokes', async () => {
    let deployed = false;
    let revoked = false;
    await expect(executeHostedBootstrapGrant({
      code: CODE,
      verifier: VERIFIER,
      config: { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET },
      transport: async (input) => {
        const url = String(input);
        if (url.endsWith('/oauth2/token')) return json({
          access_token: ACCESS_TOKEN, token_type: 'bearer', scope: 'workers-scripts.write',
        });
        if (url.startsWith('https://api.cloudflare.com/client/v4/accounts')) return json({
          success: true,
          errors: [],
          messages: [],
          result: [{ id: ACCOUNT_ID }, { id: '2'.repeat(32) }],
        });
        if (url.endsWith('/oauth2/revoke')) { revoked = true; return json({ revoked: true }); }
        throw new Error('unexpected request');
      },
      deploy: async () => { deployed = true; },
    // Translated at this boundary: the runtime maps this code to the operator's
    // "grant_invalid", where an untranslated grant error read as internal_error.
    // The reason carries the account count so zero and several stay apart.
    })).rejects.toMatchObject({
      code: 'target_account_ambiguous',
      status: 403,
      reason: 'account_read_account_ambiguous_accounts_2',
    });
    expect(deployed).toBe(false);
    expect(revoked).toBe(true);
  });

  it('rejects an unexpected refresh token, revokes both handles, and never deploys', async () => {
    const refreshToken = `refresh:+/${'h'.repeat(32)}==`;
    const revoked: string[] = [];
    let deployed = false;
    await expect(executeHostedBootstrapGrant({
      code: CODE,
      verifier: VERIFIER,
      config: { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET },
      transport: async (input, init) => {
        const url = String(input);
        if (url.endsWith('/oauth2/token')) return json({
          access_token: ACCESS_TOKEN,
          refresh_token: refreshToken,
          token_type: 'bearer',
          scope: 'workers-scripts.write',
        });
        if (url.endsWith('/oauth2/revoke')) {
          const body = init?.body;
          if (!(body instanceof URLSearchParams)) throw new Error('revocation body missing');
          revoked.push(body.get('token') ?? '');
          return new Response(null, { status: 200 });
        }
        throw new Error('unexpected request');
      },
      deploy: async () => { deployed = true; },
    })).rejects.toMatchObject({ code: 'oauth_grant_invalid' });
    expect(deployed).toBe(false);
    expect(revoked).toEqual([ACCESS_TOKEN, refreshToken]);
  });

  it('names the status and provider code when the account read is refused, deploying nothing', async () => {
    let deployed = false;
    const providerText = `Authentication error for token_${'z'.repeat(32)}`;
    await expect(executeHostedBootstrapGrant({
      code: CODE,
      verifier: VERIFIER,
      config: { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET },
      transport: async (input) => {
        const url = String(input);
        if (url.endsWith('/oauth2/token')) return json({
          access_token: ACCESS_TOKEN, token_type: 'bearer', scope: 'workers-scripts.write',
        });
        if (url.startsWith('https://api.cloudflare.com/client/v4/accounts')) {
          return json({
            success: false, errors: [{ code: 10000, message: providerText }], messages: [], result: null,
          }, 403);
        }
        if (url.endsWith('/oauth2/revoke')) return json({ revoked: true });
        throw new Error('unexpected request');
      },
      deploy: async () => { deployed = true; return null; },
    })).rejects.toMatchObject({
      code: 'oauth_exchange_failed',
      reason: 'account_read_provider_unavailable_http_403_code_10000',
    });
    expect(deployed).toBe(false);
  });

  it('names an envelope the provider decorated with messages, deploying nothing', async () => {
    let deployed = false;
    await expect(executeHostedBootstrapGrant({
      code: CODE,
      verifier: VERIFIER,
      config: { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET },
      transport: async (input) => {
        const url = String(input);
        if (url.endsWith('/oauth2/token')) return json({
          access_token: ACCESS_TOKEN, token_type: 'bearer', scope: 'workers-scripts.write',
        });
        if (url.startsWith('https://api.cloudflare.com/client/v4/accounts')) {
          return json({
            success: true, errors: [], messages: [{ code: 10001, message: 'notice' }], result: [{ id: ACCOUNT_ID }],
          });
        }
        if (url.endsWith('/oauth2/revoke')) return json({ revoked: true });
        throw new Error('unexpected request');
      },
      deploy: async () => { deployed = true; return null; },
    })).rejects.toMatchObject({
      code: 'oauth_exchange_failed',
      reason: 'account_read_provider_unavailable_messages_present',
    });
    expect(deployed).toBe(false);
  });

  it('reads the account list before the deadline releases the response', async () => {
    let deployedAccount: string | null = null;
    const result = await executeHostedBootstrapGrant({
      code: CODE,
      verifier: VERIFIER,
      config: { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET },
      transport: async (input, init) => {
        const url = String(input);
        if (url.endsWith('/oauth2/token')) return streamedJson({
          access_token: ACCESS_TOKEN, token_type: 'bearer', scope: 'workers-scripts.write',
        }, init?.signal);
        if (url.startsWith('https://api.cloudflare.com/client/v4/accounts')) return streamedJson({
          success: true, errors: [], messages: [], result: [{ id: ACCOUNT_ID }],
        }, init?.signal);
        if (url.endsWith('/oauth2/revoke')) return json({ revoked: true });
        throw new Error('unexpected request');
      },
      deploy: async ({ accountId }) => { deployedAccount = accountId; return null; },
    });
    expect(deployedAccount).toBe(ACCOUNT_ID);
    expect(result).toMatchObject({ accountId: ACCOUNT_ID, grantRevocation: 'confirmed' });
  });
});
