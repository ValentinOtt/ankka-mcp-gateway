import {
  CustomerCloudflareGrantError,
  exchangeCustomerCloudflareAuthorizationCode,
  resolveAuthorizedCloudflareZone,
  verifyCustomerCloudflareGrantAccount,
} from '../src/customer-cloudflare-grant';
import type { BoundaryValue } from '../src/boundary';

const CLIENT_ID = 'a'.repeat(32);
const CODE = `code_${'b'.repeat(32)}`;
const VERIFIER = 'c'.repeat(43);
const ACCESS_TOKEN = `token_${'d'.repeat(32)}`;
const ACCOUNT_ID = 'e'.repeat(32);
const ZONE_ID = '1'.repeat(32);
const INSTALL_SCOPES = [
  'access-acct.read', 'zone-access.write', 'dns.write', 'mcp-portals.write',
  'workers-routes.read', 'workers-scripts.write', 'zone.read',
];

function json(value: BoundaryValue, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('customer-owned Cloudflare grant', () => {
  it('resolves only the exact active zone selected in the signed plan', async () => {
    const requests: string[] = [];
    const zone = await resolveAuthorizedCloudflareZone({
      accessToken: ACCESS_TOKEN,
      accountId: ACCOUNT_ID,
      zoneName: 'example.com',
      transport: async (input) => {
        requests.push(String(input));
        return json({
          success: true,
          errors: [],
          messages: [],
          result: [{
            id: ZONE_ID,
            name: 'example.com',
            status: 'active',
            account: { id: ACCOUNT_ID },
          }],
        });
      },
    });
    expect(zone).toEqual({ id: ZONE_ID, name: 'example.com', status: 'active' });
    const url = new URL(requests[0] ?? '');
    expect(Object.fromEntries(url.searchParams)).toEqual({
      'account.id': ACCOUNT_ID,
      name: 'example.com',
      status: 'active',
      page: '1',
      per_page: '2',
    });
  });

  it('uses public-client PKCE, verifies one exact account, revokes, and discards', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const transport = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      calls.push(init === undefined ? { url } : { url, init });
      if (url.endsWith('/oauth2/token')) {
        return json({
          access_token: ACCESS_TOKEN,
          token_type: 'Bearer',
          scope: INSTALL_SCOPES.join(' '),
        });
      }
      if (url.startsWith('https://api.cloudflare.com/client/v4/accounts')) {
        return json({ success: true, errors: [], messages: [], result: [{ id: ACCOUNT_ID }] });
      }
      if (url.endsWith('/oauth2/revoke')) return new Response(null, { status: 200 });
      throw new Error('unexpected request');
    };
    const grant = await exchangeCustomerCloudflareAuthorizationCode({
      clientId: CLIENT_ID,
      code: CODE,
      verifier: VERIFIER,
      operation: 'install',
      transport,
    });
    grant.assertUsable();
    await grant.withAccessToken((accessToken) => verifyCustomerCloudflareGrantAccount({
      accessToken,
      expectedAccountId: ACCOUNT_ID,
      transport,
    }));
    await grant.revoke({ clientId: CLIENT_ID, transport });
    grant.discard();
    await expect(grant.withAccessToken(async () => undefined)).rejects.toMatchObject({ code: 'invalid' });

    const tokenCall = calls.find((call) => call.url.endsWith('/oauth2/token'));
    const tokenBody = tokenCall?.init?.body;
    expect(tokenCall?.init?.headers).not.toHaveProperty('authorization');
    expect(tokenBody).toBeInstanceOf(URLSearchParams);
    if (!(tokenBody instanceof URLSearchParams)) throw new Error('token request body missing');
    expect(tokenBody.get('client_id')).toBe(CLIENT_ID);
    expect(tokenBody.get('code_verifier')).toBe(VERIFIER);
    expect(tokenBody.get('redirect_uri')).toBe(
      'https://auth.ankka.ai/oauth/callback',
    );
    expect(calls.some((call) => call.url.includes('/client/v4/accounts?page=1&per_page=2'))).toBe(true);
    const revokeCall = calls.find((call) => call.url.endsWith('/oauth2/revoke'));
    expect(revokeCall?.init?.body).toBeInstanceOf(URLSearchParams);
    if (!(revokeCall?.init?.body instanceof URLSearchParams)) throw new Error('revoke body missing');
    expect(revokeCall.init.body.get('client_id')).toBe(CLIENT_ID);
  });

  it('rejects multi-account authorization with the exact noob-facing message', async () => {
    const transport = async (): Promise<Response> => json({
      success: true,
      errors: [],
      messages: [],
      result: [{ id: ACCOUNT_ID }, { id: 'f'.repeat(32) }],
    });
    await expect(verifyCustomerCloudflareGrantAccount({
      accessToken: ACCESS_TOKEN,
      expectedAccountId: ACCOUNT_ID,
      transport,
    })).rejects.toMatchObject({
      code: 'account_ambiguous',
      userMessage: 'Please authorize exactly one Cloudflare account.',
    });
  });

  it('rejects a refresh token and still exposes both credentials for bounded revocation only', async () => {
    const revoked: string[] = [];
    const refreshToken = `refresh:+/${'f'.repeat(32)}==`;
    const transport = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      if (url.endsWith('/oauth2/token')) return json({
        access_token: ACCESS_TOKEN,
        refresh_token: refreshToken,
        token_type: 'bearer',
        scope: INSTALL_SCOPES.join(' '),
      });
      if (url.endsWith('/oauth2/revoke')) {
        const body = init?.body;
        if (!(body instanceof URLSearchParams)) throw new Error('revocation body missing');
        revoked.push(body.get('token') ?? '');
        return json({ revoked: true });
      }
      throw new Error('unexpected request');
    };
    const grant = await exchangeCustomerCloudflareAuthorizationCode({
      clientId: CLIENT_ID, code: CODE, verifier: VERIFIER, operation: 'install', transport,
    });
    expect(() => grant.assertUsable()).toThrowError(CustomerCloudflareGrantError);
    await grant.revoke({ clientId: CLIENT_ID, transport });
    grant.discard();
    expect(revoked).toEqual([ACCESS_TOKEN, refreshToken]);
  });

  it('cannot be serialized', async () => {
    const grant = await exchangeCustomerCloudflareAuthorizationCode({
      clientId: CLIENT_ID,
      code: CODE,
      verifier: VERIFIER,
      operation: 'install',
      transport: async () => json({
        access_token: ACCESS_TOKEN,
        token_type: 'bearer',
        scope: INSTALL_SCOPES.join(' '),
      }),
    });
    expect(() => JSON.stringify(grant)).toThrowError(CustomerCloudflareGrantError);
    grant.discard();
  });

  it('rejects an untyped operation before contacting Cloudflare', async () => {
    let called = false;
    await expect(exchangeCustomerCloudflareAuthorizationCode({
      clientId: CLIENT_ID,
      code: CODE,
      verifier: VERIFIER,
      operation: 'generic-repair',
      transport: async () => {
        called = true;
        throw new Error('must not run');
      },
    })).rejects.toMatchObject({ code: 'invalid' });
    expect(called).toBe(false);
  });

  it('does not expose the hosted uninstall finalizer through the customer exchange', async () => {
    let called = false;
    await expect(exchangeCustomerCloudflareAuthorizationCode({
      clientId: CLIENT_ID,
      code: CODE,
      verifier: VERIFIER,
      operation: 'uninstall-finalize',
      transport: async () => {
        called = true;
        throw new Error('must not run');
      },
    })).rejects.toMatchObject({ code: 'invalid' });
    expect(called).toBe(false);
  });
});
