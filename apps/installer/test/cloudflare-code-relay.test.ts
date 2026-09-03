import { base64UrlEncode } from '../src/crypto';
import {
  buildFixedRelayAuthorization,
  relayCloudflareAuthorizationCode,
  relayCloudflareAuthorizationError,
  CloudflareCodeRelayError,
  CLOUDFLARE_CODE_RELAY_CALLBACK,
} from '../src/cloudflare-code-relay';

const NOW = 1_800_000_000_000;
const ACCOUNT_ID = 'a'.repeat(32);
const INSTALL_ID = `acg-${'b'.repeat(24)}`;
const CLIENT_ID = 'c'.repeat(32);
const STATE_KEY = base64UrlEncode(new Uint8Array(32).fill(9));
const GATEWAY_STATE = base64UrlEncode(new Uint8Array(32).fill(4));
const CHALLENGE = base64UrlEncode(new Uint8Array(32).fill(5));
const NONCE = base64UrlEncode(new Uint8Array(32).fill(6));

function baseInput() {
  return {
    clientId: CLIENT_ID,
    relayStateKey: STATE_KEY,
    gateway: {
      accountId: ACCOUNT_ID,
      installId: INSTALL_ID,
      callback: 'https://ankka-gateway-example.customer.workers.dev/__ankka/install/oauth/callback',
    },
    operation: 'install' as const,
    gatewayState: GATEWAY_STATE,
    pkceChallenge: CHALLENGE,
    nonce: NONCE,
    now: NOW,
  };
}

describe('Cloudflare authorization-code relay', () => {
  it('fixes client, redirect, operation scopes, PKCE, and omits refresh authority', async () => {
    const result = await buildFixedRelayAuthorization(baseInput());
    const url = new URL(result.authorizationUrl);
    expect(url.origin + url.pathname).toBe('https://dash.cloudflare.com/oauth2/auth');
    expect(url.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(url.searchParams.get('redirect_uri')).toBe(CLOUDFLARE_CODE_RELAY_CALLBACK);
    expect(url.searchParams.get('scope')).toBe(
      'access-acct.read zone-access.write dns.write mcp-portals.write workers-routes.read workers-scripts.write zone.read',
    );
    expect(url.searchParams.get('code_challenge')).toBe(CHALLENGE);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(result.authorizationUrl).not.toContain('offline_access');
    expect(result.authorizationUrl).not.toContain('refresh_token');
  });

  it('relays only code and the Gateway state to the signed callback', async () => {
    const authorization = await buildFixedRelayAuthorization(baseInput());
    const state = new URL(authorization.authorizationUrl).searchParams.get('state');
    if (state === null) throw new Error('state missing');
    const relayed = await relayCloudflareAuthorizationCode({
      code: `code_${'d'.repeat(32)}`,
      state,
      relayStateKey: STATE_KEY,
      now: NOW + 1,
    });
    const location = new URL(relayed.location);
    expect(location.origin + location.pathname).toBe(
      'https://ankka-gateway-example.customer.workers.dev/__ankka/install/oauth/callback',
    );
    expect(location.searchParams.get('code')).toBe(`code_${'d'.repeat(32)}`);
    expect(location.searchParams.get('state')).toBe(GATEWAY_STATE);
    expect(JSON.stringify(relayed)).not.toContain('access_token');
    expect(relayed).toMatchObject({ operation: 'install', accountId: ACCOUNT_ID, installId: INSTALL_ID });
  });

  it('accepts bounded provider error metadata for parsing but never forwards it', async () => {
    const authorization = await buildFixedRelayAuthorization(baseInput());
    const state = new URL(authorization.authorizationUrl).searchParams.get('state');
    if (state === null) throw new Error('state missing');
    const relayed = await relayCloudflareAuthorizationError({
      error: 'access_denied',
      errorDescription: 'provider detail cfoat_must_not_cross_the_relay',
      errorUri: 'https://developers.cloudflare.com/oauth/errors?secret=cfoat_must_not_cross_the_relay',
      state,
      relayStateKey: STATE_KEY,
      now: NOW + 1,
    });
    const location = new URL(relayed.location);
    expect([...location.searchParams.keys()]).toEqual(['error', 'state']);
    expect(location.searchParams.get('error')).toBe('authorization_rejected');
    expect(location.searchParams.get('state')).toBe(GATEWAY_STATE);
    expect(relayed.location).not.toContain('provider detail');
    expect(relayed.location).not.toContain('cfoat_must_not_cross_the_relay');
  });

  it('rejects oversized provider error metadata and unsafe provider error URIs', async () => {
    const authorization = await buildFixedRelayAuthorization(baseInput());
    const state = new URL(authorization.authorizationUrl).searchParams.get('state');
    if (state === null) throw new Error('state missing');
    await expect(relayCloudflareAuthorizationError({
      error: 'access_denied',
      errorDescription: 'x'.repeat(1_025),
      errorUri: null,
      state,
      relayStateKey: STATE_KEY,
      now: NOW + 1,
    })).rejects.toMatchObject({ code: 'invalid' });
    await expect(relayCloudflareAuthorizationError({
      error: 'access_denied',
      errorDescription: null,
      errorUri: 'http://provider.example/error',
      state,
      relayStateKey: STATE_KEY,
      now: NOW + 1,
    })).rejects.toMatchObject({ code: 'invalid' });
    await expect(relayCloudflareAuthorizationError({
      error: 'access_denied',
      errorDescription: null,
      errorUri: `https://provider.example/${'x'.repeat(2_048)}`,
      state,
      relayStateKey: STATE_KEY,
      now: NOW + 1,
    })).rejects.toMatchObject({ code: 'invalid' });
  });

  it('validates signed state independently on repeated callbacks and enforces expiry', async () => {
    const authorization = await buildFixedRelayAuthorization(baseInput());
    const state = new URL(authorization.authorizationUrl).searchParams.get('state');
    if (state === null) throw new Error('state missing');
    const callback = {
      code: `code_${'f'.repeat(32)}`,
      state,
      relayStateKey: STATE_KEY,
      now: NOW + 1,
    };
    const first = await relayCloudflareAuthorizationCode(callback);
    const repeated = await relayCloudflareAuthorizationCode(callback);
    expect(repeated).toEqual(first);
    await expect(relayCloudflareAuthorizationCode({
      ...callback,
      now: authorization.expiresAt,
    })).rejects.toMatchObject({ code: 'expired' });
  });

  it('rejects tampered, expired, and malformed callback state', async () => {
    const authorization = await buildFixedRelayAuthorization(baseInput());
    const state = new URL(authorization.authorizationUrl).searchParams.get('state');
    if (state === null) throw new Error('state missing');
    await expect(relayCloudflareAuthorizationCode({
      code: `code_${'e'.repeat(32)}`,
      state: `${state.slice(0, -1)}A`,
      relayStateKey: STATE_KEY,
      now: NOW + 1,
    })).rejects.toBeInstanceOf(CloudflareCodeRelayError);
    await expect(relayCloudflareAuthorizationCode({
      code: `code_${'e'.repeat(32)}`,
      state,
      relayStateKey: STATE_KEY,
      now: authorization.expiresAt,
    })).rejects.toMatchObject({ code: 'expired' });
    await expect(buildFixedRelayAuthorization({
      ...baseInput(),
      gateway: { ...baseInput().gateway, callback: 'http://example.com/oauth/callback' },
    })).rejects.toMatchObject({ code: 'invalid' });
  });

  it('derives uninstall scopes from receipt types without accepting scope strings', async () => {
    const result = await buildFixedRelayAuthorization({
      ...baseInput(),
      operation: 'uninstall',
      receiptResourceKinds: ['worker', 'mcp_portal'],
    });
    expect(new URL(result.authorizationUrl).searchParams.get('scope')).toBe(
      'mcp-portals.write workers-scripts.write',
    );
  });

  it('rejects untyped operation and receipt-kind input at the runtime boundary', async () => {
    await expect(buildFixedRelayAuthorization({
      ...baseInput(),
      operation: 'generic-repair',
    })).rejects.toMatchObject({ code: 'invalid' });
    await expect(buildFixedRelayAuthorization({
      ...baseInput(),
      operation: 'uninstall-finalize',
    })).rejects.toMatchObject({ code: 'invalid' });
    await expect(buildFixedRelayAuthorization({
      ...baseInput(),
      operation: 'uninstall',
      receiptResourceKinds: ['worker', 'foreign_resource'],
    })).rejects.toMatchObject({ code: 'invalid' });
  });

  it('supports the fixed source-remove operation without accepting scope input', async () => {
    const result = await buildFixedRelayAuthorization({
      ...baseInput(),
      operation: 'source-remove',
    });
    expect(new URL(result.authorizationUrl).searchParams.get('scope')).toBe(
      'zone-access.write mcp-portals.write',
    );
  });
});
