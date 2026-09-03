import { beginCustomerBootstrapRelay } from '../src/customer-bootstrap-relay-client';
import {
  CLOUDFLARE_CODE_RELAY_CALLBACK,
  CLOUDFLARE_CODE_RELAY_ORIGIN,
} from '../src/cloudflare-code-relay';
import { CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH } from '../src/customer-install-paths';

const CLIENT_ID = 'a'.repeat(32);
const GATEWAY_STATE = 'b'.repeat(43);
const CHALLENGE = 'c'.repeat(43);
const CALLBACK = `https://ankka-bootstrap.customer.workers.dev${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`;
const RELAY_TICKET = `${'d'.repeat(96)}.${'e'.repeat(43)}`;
const RELAY_STATE = `${'f'.repeat(160)}.${'g'.repeat(43)}`;
const INSTALL_SCOPES =
  'access-acct.read zone-access.write dns.write mcp-portals.write workers-routes.read workers-scripts.write zone.read';

interface RelayResponseFixture {
  readonly schemaVersion: 1;
  readonly authorizationUrl: string;
  readonly accessToken?: string;
}

function authorizationUrl(): URL {
  const url = new URL('https://dash.cloudflare.com/oauth2/auth');
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', CLIENT_ID);
  url.searchParams.set('redirect_uri', CLOUDFLARE_CODE_RELAY_CALLBACK);
  url.searchParams.set('scope', INSTALL_SCOPES);
  url.searchParams.set('state', RELAY_STATE);
  url.searchParams.set('code_challenge', CHALLENGE);
  url.searchParams.set('code_challenge_method', 'S256');
  return url;
}

function json(
  value: RelayResponseFixture,
  status = 200,
  contentType = 'application/json; charset=utf-8',
): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': contentType } });
}

/**
 * A relay body that arrives only when pulled and errors once the request signal
 * has aborted, like a real fetch body.
 */
function streamedJson(value: RelayResponseFixture, signal: AbortSignal | null | undefined): Response {
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
  return new Response(body, { status: 200, headers: { 'content-type': 'application/json; charset=utf-8' } });
}

function input(transport: (request: RequestInfo | URL, init?: RequestInit) => Promise<Response>) {
  return {
    publicClientId: CLIENT_ID,
    relayTicket: RELAY_TICKET,
    gatewayState: GATEWAY_STATE,
    pkceChallenge: CHALLENGE,
    gatewayCallback: CALLBACK,
    transport,
  };
}

describe('customer bootstrap code-relay client', () => {
  it('calls only the fixed install relay and accepts the exact bound authorization response', async () => {
    const calls: Array<{ url: string; init: RequestInit | undefined; signalAborted: boolean }> = [];
    const result = await beginCustomerBootstrapRelay(input(async (request, init) => {
      calls.push({
        url: String(request),
        init,
        signalAborted: init?.signal?.aborted ?? false,
      });
      return json({ schemaVersion: 1, authorizationUrl: authorizationUrl().toString() });
    }));

    expect(result).toEqual({ authorizationUrl: authorizationUrl().toString() });
    expect(Object.isFrozen(result)).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(`${CLOUDFLARE_CODE_RELAY_ORIGIN}/oauth/start/install`);
    expect(calls[0]?.init?.method).toBe('POST');
    expect(calls[0]?.init?.redirect).toBe('manual');
    expect(calls[0]?.signalAborted).toBe(false);
    expect(calls[0]?.init?.headers).toEqual({
      accept: 'application/json',
      'content-type': 'application/json',
    });
    const expectedBody = {
      relayTicket: RELAY_TICKET,
      gatewayState: GATEWAY_STATE,
      pkceChallenge: CHALLENGE,
      gatewayCallback: CALLBACK,
    };
    expect(calls[0]?.init?.body).toBe(JSON.stringify(expectedBody));
    expect(JSON.stringify(expectedBody)).not.toContain('scope');
    expect(JSON.stringify(expectedBody)).not.toContain('destination');
    expect(JSON.stringify(expectedBody)).not.toContain('oauth2/token');
    expect(JSON.stringify(calls)).not.toContain('authorization');
  });

  it.each([
    ['wrong origin', (url: URL) => { url.hostname = 'attacker.example'; }],
    ['token endpoint', (url: URL) => { url.pathname = '/oauth2/token'; }],
    ['wrong client', (url: URL) => { url.searchParams.set('client_id', 'z'.repeat(32)); }],
    ['wrong redirect', (url: URL) => {
      url.searchParams.set('redirect_uri', 'https://attacker.example/oauth/callback');
    }],
    ['widened scope', (url: URL) => { url.searchParams.set('scope', `${INSTALL_SCOPES} account.write`); }],
    ['wrong challenge', (url: URL) => { url.searchParams.set('code_challenge', 'z'.repeat(43)); }],
    ['duplicate query key', (url: URL) => { url.searchParams.append('state', RELAY_STATE); }],
    ['unknown query key', (url: URL) => { url.searchParams.set('destination', CALLBACK); }],
    ['malformed relay state', (url: URL) => { url.searchParams.set('state', 'not-signed'); }],
  ])('rejects a relay response with %s', async (_label, mutate) => {
    const url = authorizationUrl();
    mutate(url);
    await expect(beginCustomerBootstrapRelay(input(async () =>
      json({ schemaVersion: 1, authorizationUrl: url.toString() })))).rejects.toThrow('relay_rejected');
  });

  it('reads the relay response before the deadline releases it', async () => {
    const result = await beginCustomerBootstrapRelay(input(async (_request, init) => streamedJson(
      { schemaVersion: 1, authorizationUrl: authorizationUrl().toString() },
      init?.signal,
    )));
    expect(result).toEqual({ authorizationUrl: authorizationUrl().toString() });
  });

  it('rejects extra response fields, non-JSON media types, redirects, and oversized bodies', async () => {
    await expect(beginCustomerBootstrapRelay(input(async () => json({
      schemaVersion: 1,
      authorizationUrl: authorizationUrl().toString(),
      accessToken: 'must-not-be-accepted',
    })))).rejects.toThrow('relay_rejected');
    await expect(beginCustomerBootstrapRelay(input(async () => json({
      schemaVersion: 1,
      authorizationUrl: authorizationUrl().toString(),
    }, 200, 'application/jsonp')))).rejects.toThrow('relay_rejected');
    await expect(beginCustomerBootstrapRelay(input(async () => json({
      schemaVersion: 1,
      authorizationUrl: authorizationUrl().toString(),
    }, 302)))).rejects.toThrow('relay_rejected');
    await expect(beginCustomerBootstrapRelay(input(async () => new Response('x'.repeat(16 * 1024 + 1), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })))).rejects.toThrow('relay_rejected');
  });

  it.each([
    ['public client ID', { publicClientId: 'short' }],
    ['relay ticket', { relayTicket: 'not-a-signed-ticket' }],
    ['gateway callback', { gatewayCallback: 'https://attacker.example/not-the-callback' }],
    ['PKCE challenge', { pkceChallenge: 'short' }],
  ])('rejects invalid %s before invoking the transport', async (_label, override) => {
    let called = false;
    await expect(beginCustomerBootstrapRelay({
      ...input(async () => {
        called = true;
        return json({ schemaVersion: 1, authorizationUrl: authorizationUrl().toString() });
      }),
      ...override,
    })).rejects.toThrow('relay_rejected');
    expect(called).toBe(false);
  });
});
