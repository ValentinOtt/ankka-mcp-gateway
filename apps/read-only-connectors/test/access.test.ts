import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { verifyAccess } from '../src/access';

const audience = 'a'.repeat(64);
const team = 'synthetic-team.cloudflareaccess.com';
const issuer = `https://${team}`;
let privateKey: CryptoKey;
let keys: string;
beforeAll(async () => {
  const pair = await generateKeyPair('RS256');
  privateKey = pair.privateKey;
  keys = JSON.stringify({ keys: [{ ...await exportJWK(pair.publicKey), kid: 'synthetic-key' }] });
});
async function assertion(overrides: Record<string, string | number | string[]> = {}): Promise<string> {
  return new SignJWT({ iss: issuer, aud: [audience], iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 300, ...overrides })
    .setProtectedHeader({ alg: 'RS256', kid: 'synthetic-key' }).sign(privateKey);
}
function request(token: string): Request {
  return new Request('https://connector.example.com/mcp', { headers: { 'Cf-Access-Jwt-Assertion': token } });
}
function fetchKeys(): typeof globalThis.fetch {
  return vi.fn(async () => new Response(keys, { headers: { 'Content-Type': 'application/json' } }));
}

describe('Access ingress verification', () => {
  it('verifies signature, issuer, audience and expiry against the fixed team JWKS', async () => {
    const fetcher = fetchKeys();
    expect(await verifyAccess(request(await assertion()), team, audience, fetcher)).toBe(true);
    expect(fetcher).toHaveBeenCalledOnce();
    expect(fetcher).toHaveBeenCalledWith(`${issuer}/cdn-cgi/access/certs`, expect.objectContaining({
      method: 'GET', redirect: 'manual',
    }));
    const init = vi.mocked(fetcher).mock.calls[0]?.[1];
    expect(new Headers(init?.headers).has('authorization')).toBe(false);
    expect(new Headers(init?.headers).has('cf-access-jwt-assertion')).toBe(false);
  });
  it.each([
    { iss: 'https://other-team.cloudflareaccess.com' }, { aud: ['b'.repeat(64)] },
    { exp: 1 }, { nbf: Math.floor(Date.now() / 1000) + 600 }, { iat: Math.floor(Date.now() / 1000) + 600 },
  ])('rejects mismatched or invalid claims: %j', async (claims) => {
    expect(await verifyAccess(request(await assertion(claims)), team, audience, fetchKeys())).toBe(false);
  });
  it('rejects a forged signature and unsigned tokens', async () => {
    const otherPair = await generateKeyPair('RS256');
    const token = await new SignJWT({ iss: issuer, aud: audience, iat: 1, exp: 9999999999 })
      .setProtectedHeader({ alg: 'RS256', kid: 'synthetic-key' }).sign(otherPair.privateKey);
    expect(await verifyAccess(request(token), team, audience, fetchKeys())).toBe(false);
    expect(await verifyAccess(request('eyJhbGciOiJub25lIn0.e30.'), team, audience, fetchKeys())).toBe(false);
  });
  it('requires expiry and issue time', async () => {
    const token = await new SignJWT({ iss: issuer, aud: audience })
      .setProtectedHeader({ alg: 'RS256', kid: 'synthetic-key' }).sign(privateKey);
    expect(await verifyAccess(request(token), team, audience, fetchKeys())).toBe(false);
  });
  it.each(['evil.example.com', 'team.cloudflareaccess.com.evil.com', 'team.cloudflareaccess.com/path', 'localhost'])
    ('never fetches arbitrary JWKS hosts: %s', async (domain) => {
      const fetcher = fetchKeys();
      expect(await verifyAccess(request(await assertion()), domain, audience, fetcher)).toBe(false);
      expect(fetcher).not.toHaveBeenCalled();
    });
  it('does not fetch keys for missing credentials or placeholder config', async () => {
    const fetcher = fetchKeys();
    expect(await verifyAccess(new Request('https://connector.example.com/mcp'), team, audience, fetcher)).toBe(false);
    expect(await verifyAccess(request(await assertion()), team, 'replace-me', fetcher)).toBe(false);
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('fails closed on JWKS errors without reflecting them', async () => {
    const fetcher = vi.fn(async () => new Response('synthetic-sensitive-provider-error', { status: 500 }));
    expect(await verifyAccess(request(await assertion()), team, audience, fetcher)).toBe(false);
  });
});
