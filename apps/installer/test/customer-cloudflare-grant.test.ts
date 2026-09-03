import {
  CustomerCloudflareGrantError,
  exchangeCustomerCloudflareAuthorizationCode,
  resolveAuthorizedCloudflareZone,
  resolveSingleAuthorizedCloudflareAccount,
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

describe('Stage 1 single-account resolution details', () => {
  const providerText = `refused token_${'q'.repeat(32)}`;

  async function detailFor(transport: (url: string) => Promise<Response>): Promise<CustomerCloudflareGrantError> {
    try {
      await resolveSingleAuthorizedCloudflareAccount({
        accessToken: ACCESS_TOKEN,
        transport: async (input) => transport(String(input)),
      });
    } catch (error) {
      if (error instanceof CustomerCloudflareGrantError) return error;
      throw error;
    }
    throw new Error('resolution unexpectedly succeeded');
  }

  it('names a refused read by HTTP status and numeric provider code only', async () => {
    const error = await detailFor(async () => json({
      success: false, errors: [{ code: 10000, message: providerText }], messages: [], result: null,
    }, 403));
    expect(error).toMatchObject({ code: 'provider_unavailable', detail: 'http_403_code_10000' });
    expect(JSON.stringify({ code: error.code, detail: error.detail })).not.toContain('token_');
  });

  it('names a transport failure without a status', async () => {
    const error = await detailFor(async () => { throw new Error(providerText); });
    expect(error).toMatchObject({ code: 'provider_unavailable', detail: 'transport_failed' });
  });

  it('names a non-JSON body by status', async () => {
    const error = await detailFor(async () => new Response('<html>maintenance</html>', {
      status: 502, headers: { 'content-type': 'text/html' },
    }));
    expect(error).toMatchObject({ code: 'provider_unavailable', detail: 'not_json_http_502' });
  });

  it('names a successful envelope the provider decorated with messages', async () => {
    const error = await detailFor(async () => json({
      success: true, errors: [], messages: [{ code: 10001, message: 'notice' }], result: [{ id: ACCOUNT_ID }],
    }));
    expect(error).toMatchObject({ code: 'provider_unavailable', detail: 'messages_present' });
  });

  it('counts the accounts when the grant sees zero or several', async () => {
    const none = await detailFor(async () => json({ success: true, errors: [], messages: [], result: [] }));
    expect(none).toMatchObject({ code: 'account_ambiguous', detail: 'accounts_0' });
    const two = await detailFor(async () => json({
      success: true, errors: [], messages: [], result: [{ id: ACCOUNT_ID }, { id: ZONE_ID }],
    }));
    expect(two).toMatchObject({ code: 'account_ambiguous', detail: 'accounts_2' });
  });

  it('names a body that fails to read', async () => {
    const error = await detailFor(async () => new Response(new ReadableStream<Uint8Array>({
      pull(controller) { controller.error(new DOMException('The operation was aborted', 'AbortError')); },
    }, { highWaterMark: 0 }), { status: 200, headers: { 'content-type': 'application/json' } }));
    expect(error).toMatchObject({ code: 'provider_unavailable', detail: 'body_read_failed' });
  });

  it('drops a detail that is not a plain lowercase token', () => {
    expect(new CustomerCloudflareGrantError('provider_unavailable', `Bearer ${providerText}`).detail).toBeNull();
    expect(new CustomerCloudflareGrantError('provider_unavailable').detail).toBeNull();
  });
});

describe('provider bodies are consumed inside the deadline', () => {
  it('resolves the account from a body that arrives after the headers', async () => {
    const accountId = await resolveSingleAuthorizedCloudflareAccount({
      accessToken: ACCESS_TOKEN,
      transport: async (_input, init) => streamedJson({
        success: true, errors: [], messages: [], result: [{ id: ACCOUNT_ID }],
      }, init?.signal),
    });
    expect(accountId).toBe(ACCOUNT_ID);
  });

  it('resolves the zone from a body that arrives after the headers', async () => {
    const zone = await resolveAuthorizedCloudflareZone({
      accessToken: ACCESS_TOKEN,
      accountId: ACCOUNT_ID,
      zoneName: 'example.com',
      transport: async (_input, init) => streamedJson({
        success: true,
        errors: [],
        messages: [],
        result: [{ id: ZONE_ID, name: 'example.com', status: 'active', account: { id: ACCOUNT_ID } }],
      }, init?.signal),
    });
    expect(zone).toEqual({ id: ZONE_ID, name: 'example.com', status: 'active' });
  });

  it('exchanges the code from a token body that arrives after the headers', async () => {
    const grant = await exchangeCustomerCloudflareAuthorizationCode({
      clientId: CLIENT_ID,
      code: CODE,
      verifier: VERIFIER,
      operation: 'install',
      transport: async (_input, init) => streamedJson({
        access_token: ACCESS_TOKEN, token_type: 'bearer', scope: INSTALL_SCOPES.join(' '),
      }, init?.signal),
    });
    expect(grant.metadataValid).toBe(true);
    expect(grant.scopes).toHaveLength(INSTALL_SCOPES.length);
  });
});
