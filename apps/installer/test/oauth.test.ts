import { REQUIRED_OAUTH_SCOPES } from '../src/constants';
import { resolveAuthorizedTarget } from '../src/cloudflare-target';
import {
  assertExactGrantedScopes,
  buildAuthorizationUrl,
  exchangeAuthorizationCode,
  type FetchTransport,
} from '../src/oauth';
import { CLIENT_ID, CLIENT_SECRET } from './fixtures';

const verifier = 'v'.repeat(43);
const state = 's'.repeat(43);
const challenge = 'c'.repeat(43);

describe('confidential Cloudflare OAuth', () => {
  it('builds the fixed callback, exact current scopes, and S256 challenge', () => {
    const url = new URL(buildAuthorizationUrl({ clientId: CLIENT_ID, state, challenge }));
    expect(url.origin + url.pathname).toBe('https://dash.cloudflare.com/oauth2/auth');
    expect(url.searchParams.get('redirect_uri')).toBe('https://deploy.ankka.ai/oauth/callback');
    expect(url.searchParams.get('scope')).toBe(REQUIRED_OAUTH_SCOPES.join(' '));
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('state')).toBe(state);
  });

  it('exchanges by confidential Basic auth and keeps grant serialization impossible', async () => {
    let seenAuthorization = '';
    let seenBody = '';
    const transport: FetchTransport = async (_input, init) => {
      seenAuthorization = new Headers(init?.headers).get('authorization') ?? '';
      seenBody = String(init?.body);
      return new Response(JSON.stringify({
        token_type: 'Bearer',
        access_token: 'access-token-value-long',
        refresh_token: 'refresh-token-value-long',
        scope: REQUIRED_OAUTH_SCOPES.join(' '),
      }), { status: 200 });
    };
    const grant = await exchangeAuthorizationCode({
      code: 'authorization-code-value',
      verifier,
      config: { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET },
      transport,
    });
    expect(seenAuthorization).toBe(`Basic ${btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)}`);
    expect(new URLSearchParams(seenBody).get('redirect_uri')).toBe('https://deploy.ankka.ai/oauth/callback');
    expect(new URLSearchParams(seenBody).get('code_verifier')).toBe(verifier);
    expect(() => JSON.stringify(grant)).toThrow();
    expect(() => grant.assertUsable()).not.toThrow();
    assertExactGrantedScopes(grant.scopes);
    grant.discard();
    await expect(grant.withAccessToken(async () => true)).rejects.toMatchObject({ code: 'oauth_grant_invalid' });
  });

  it('survives a receiver-strict global fetch, the way workerd rejects method-style invocation', async () => {
    // workerd throws "Illegal invocation" when its global fetch is called with a
    // foreign `this`; every call site here invokes the transport as
    // `input.transport(...)`. Node's fetch ignores the receiver, so the suite
    // must simulate the strict behaviour explicitly.
    const originalFetch = globalThis.fetch;
    const strictFetch: typeof fetch = function (
      this: typeof globalThis | undefined,
      _input: RequestInfo | URL,
      _init?: RequestInit,
    ): Promise<Response> {
      if (this !== undefined && this !== globalThis) {
        throw new TypeError('Illegal invocation: function called with incorrect `this` reference.');
      }
      return Promise.resolve(new Response(JSON.stringify({
        token_type: 'Bearer',
        access_token: 'access-token-value-long',
        refresh_token: 'refresh-token-value-long',
        scope: REQUIRED_OAUTH_SCOPES.join(' '),
      }), { status: 200 }));
    };
    globalThis.fetch = strictFetch;
    try {
      await expect(exchangeAuthorizationCode({
        code: 'authorization-code-value',
        verifier,
        config: { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET },
        transport: globalThis.fetch,
      })).rejects.toMatchObject({ code: 'oauth_exchange_failed', reason: 'token_endpoint_unreachable' });
      const grant = await exchangeAuthorizationCode({
        code: 'authorization-code-value',
        verifier,
        config: { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET },
        transport: (input, init) => fetch(input, init),
      });
      expect(() => grant.assertUsable()).not.toThrow();
      grant.discard();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('rejects missing, extra, and old-format returned scopes exactly', () => {
    expect(() => assertExactGrantedScopes(REQUIRED_OAUTH_SCOPES)).not.toThrow();
    expect(() => assertExactGrantedScopes(REQUIRED_OAUTH_SCOPES.slice(1))).toThrow();
    expect(() => assertExactGrantedScopes([...REQUIRED_OAUTH_SCOPES, 'workers_scripts:write'])).toThrow();
  });

  it('attempts revocation of access and refresh grants even when the first fails', async () => {
    const revokeBodies: string[] = [];
    let calls = 0;
    const exchangeTransport: FetchTransport = async () => new Response(JSON.stringify({
      token_type: 'bearer',
      access_token: 'access-token-value-long',
      refresh_token: 'refresh-token-value-long',
      scope: REQUIRED_OAUTH_SCOPES.join(' '),
    }), { status: 200 });
    const grant = await exchangeAuthorizationCode({
      code: 'authorization-code-value', verifier,
      config: { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET },
      transport: exchangeTransport,
    });
    await expect(grant.revoke(async (_input, init) => {
      calls += 1;
      revokeBodies.push(String(init?.body));
      return new Response('{}', { status: calls === 1 ? 500 : 200 });
    }, { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET }))
      .rejects.toMatchObject({ code: 'oauth_revoke_failed' });
    expect(calls).toBe(2);
    expect(revokeBodies.join(' ')).toContain('access-token-value-long');
    expect(revokeBodies.join(' ')).toContain('refresh-token-value-long');
  });
});

describe('authorized account and typed active zone', () => {
  const ACCOUNT_ID = 'a'.repeat(32);
  const ZONE_ID = 'b'.repeat(32);

  function targetTransport(accountCount = 1, zoneStatus = 'active'): FetchTransport {
    return async (input) => {
      const url = new URL(input instanceof Request ? input.url : input.toString());
      if (url.pathname.endsWith('/user')) {
        return new Response(JSON.stringify({ success: true, result: { id: 'user-12345678', email: 'owner@example.com' } }));
      }
      if (url.pathname.endsWith('/accounts')) {
        return new Response(JSON.stringify({
          success: true,
          result: Array.from({ length: accountCount }, (_, index) => ({ id: index ? 'c'.repeat(32) : ACCOUNT_ID, name: `Account ${index}` })),
        }));
      }
      return new Response(JSON.stringify({
        success: true,
        result: [{ id: ZONE_ID, name: 'example.com', status: zoneStatus, account: { id: ACCOUNT_ID } }],
      }));
    };
  }

  it('binds the actor, exactly one authorized account, and exact active typed zone', async () => {
    await expect(resolveAuthorizedTarget({
      accessToken: 'access-token-value-long',
      typedZoneName: 'example.com',
      expectedAdminEmail: 'owner@example.com',
      transport: targetTransport(),
    })).resolves.toEqual({
      actor: { id: 'user-12345678', email: 'owner@example.com' },
      account: { id: ACCOUNT_ID, name: 'Account 0' },
      zone: { id: ZONE_ID, name: 'example.com', status: 'active' },
    });
  });

  it('fails zero-write on actor, account, or zone ambiguity', async () => {
    await expect(resolveAuthorizedTarget({
      accessToken: 'access-token-value-long', typedZoneName: 'example.com',
      expectedAdminEmail: 'other@example.com', transport: targetTransport(),
    })).rejects.toMatchObject({ code: 'oauth_grant_invalid' });
    await expect(resolveAuthorizedTarget({
      accessToken: 'access-token-value-long', typedZoneName: 'example.com',
      expectedAdminEmail: 'owner@example.com', transport: targetTransport(2),
    })).rejects.toMatchObject({ code: 'target_account_ambiguous' });
    await expect(resolveAuthorizedTarget({
      accessToken: 'access-token-value-long', typedZoneName: 'example.com',
      expectedAdminEmail: 'owner@example.com', transport: targetTransport(1, 'pending'),
    })).rejects.toMatchObject({ code: 'target_zone_invalid' });
  });

});
