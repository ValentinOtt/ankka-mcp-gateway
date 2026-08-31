import { CLIENT_CAPABILITIES_META_KEY, PROTOCOL_VERSION_META_KEY } from '@modelcontextprotocol/server';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { handleRequest } from '../src/index';
import { INCOMING_LIMITS } from '../src/incoming';
import type { ConnectorJson } from '../src/request';

const env: Env = {
  CONNECTOR_PROVIDER: 'hubspot', CONNECTOR_CONFIG_JSON: JSON.stringify({ objectProperties: { contacts: ['email'] } }),
  PUBLIC_ORIGIN: 'https://connector.example.com', ACCESS_TEAM_DOMAIN: 'synthetic-team.cloudflareaccess.com',
  ACCESS_AUD: 'a'.repeat(64), PROVIDER_TOKEN: 'synthetic-provider-token-not-a-secret',
};
let token: string;
let jwks: string;
beforeAll(async () => {
  const pair = await generateKeyPair('RS256');
  jwks = JSON.stringify({ keys: [{ ...await exportJWK(pair.publicKey), kid: 'synthetic-key' }] });
  token = await new SignJWT({}).setProtectedHeader({ alg: 'RS256', kid: 'synthetic-key' })
    .setIssuer(`https://${env.ACCESS_TEAM_DOMAIN}`).setAudience(env.ACCESS_AUD)
    .setIssuedAt().setExpirationTime('5m').sign(pair.privateKey);
});
function fetcher() {
  return vi.fn<typeof globalThis.fetch>(async (input) => {
    if (String(input) === `https://${env.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`) {
      return new Response(jwks, { headers: { 'Content-Type': 'application/json' } });
    }
    throw new Error('Unexpected upstream request');
  });
}
function request(body: string, authenticated = true): Request {
  const headers = new Headers({ 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' });
  if (authenticated) headers.set('Cf-Access-Jwt-Assertion', token);
  return new Request(`${env.PUBLIC_ORIGIN}/mcp`, { method: 'POST', headers, body });
}

interface RpcFixture {
  method: 'tools/list' | 'tools/call';
  params: Record<string, ConnectorJson>;
}
function protocolRequest(version: string, message: RpcFixture): Request {
  const params = { ...message.params };
  if (version === '2026-07-28') {
    params._meta = {
      [PROTOCOL_VERSION_META_KEY]: version,
      [CLIENT_CAPABILITIES_META_KEY]: {},
    };
  }
  const input = request(JSON.stringify({ jsonrpc: '2.0', id: 1, method: message.method, params }));
  input.headers.set('MCP-Protocol-Version', version);
  if (version === '2026-07-28') {
    input.headers.set('MCP-Method', message.method);
    if (message.method === 'tools/call') input.headers.set('MCP-Name', String(params.name));
  }
  return input;
}

describe('self-hosted MCP runtime', () => {
  it.each(['2025-06-18', '2026-07-28'])('preserves the global fetch receiver for Access and provider reads for MCP %s', async (version) => {
    const upstream = 'https://api.hubapi.com/crm/v3/objects/contacts/7?properties=email&archived=false';
    const outbound = vi.spyOn(globalThis, 'fetch').mockImplementation(async function (this: typeof globalThis | undefined, input) {
      if (this !== globalThis) throw new TypeError('Illegal invocation');
      if (String(input) === `https://${env.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`) {
        return new Response(jwks, { headers: { 'Content-Type': 'application/json' } });
      }
      expect(String(input)).toBe(upstream);
      return Response.json({ id: '7', properties: { email: 'synthetic@example.com' } });
    });
    try {
      const response = await handleRequest(protocolRequest(version, {
        method: 'tools/call', params: { name: 'hubspot_get_record', arguments: { objectType: 'contacts', recordId: '7' } },
      }), env);
      const text = await response.text();
      expect(response.status, text).toBe(200);
      expect(text).toContain('synthetic@example.com');
      expect(text).not.toContain(env.PROVIDER_TOKEN);
      expect(outbound).toHaveBeenCalledTimes(2);
      expect(new Headers(outbound.mock.calls[0]?.[1]?.headers).has('authorization')).toBe(false);
      expect(new Headers(outbound.mock.calls[1]?.[1]?.headers).get('authorization')).toBe(`Bearer ${env.PROVIDER_TOKEN}`);
    } finally {
      outbound.mockRestore();
    }
  });
  it.each(['2025-06-18', '2026-07-28'])('serves the same ordinary read tools for MCP %s', async (version) => {
    const input = protocolRequest(version, { method: 'tools/list', params: {} });
    const outbound = fetcher();
    const response = await handleRequest(input, env, outbound);
    const text = await response.text();
    expect(response.status, text).toBe(200);
    expect(text).toContain('readOnlyHint');
    expect(text).toContain('hubspot');
    expect(text).not.toContain(env.PROVIDER_TOKEN);
    expect(outbound).toHaveBeenCalledOnce(); // JWKS only, no provider API discovery.
    expect(response.headers.get('cache-control')).toBe('no-store');
  });
  it.each(['2025-06-18', '2026-07-28'])('executes only the approved read with isolated provider headers for MCP %s', async (version) => {
    const upstream = 'https://api.hubapi.com/crm/v3/objects/contacts/7?properties=email&archived=false';
    const outbound = vi.fn<typeof globalThis.fetch>(async (input) => {
      if (String(input) === `https://${env.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`) {
        return new Response(jwks, { headers: { 'Content-Type': 'application/json' } });
      }
      expect(String(input)).toBe(upstream);
      return Response.json({ id: '7', properties: { email: 'synthetic@example.com', hidden: 'sentinel-unapproved-property' } });
    });
    const input = protocolRequest(version, {
      method: 'tools/call', params: { name: 'hubspot_get_record', arguments: { objectType: 'contacts', recordId: '7' } },
    });
    input.headers.set('Authorization', 'Bearer sentinel-inbound-token');
    input.headers.set('Cookie', 'synthetic=sentinel-inbound-cookie');
    input.headers.set('X-Api-Key', 'sentinel-inbound-api-key');
    const response = await handleRequest(input, env, outbound);
    const text = await response.text();
    expect(response.status, text).toBe(200);
    expect(text).toContain('synthetic@example.com');
    expect(text).not.toContain('sentinel');
    expect(text).not.toContain(env.PROVIDER_TOKEN);
    expect(outbound).toHaveBeenCalledTimes(2);
    const [url, init] = outbound.mock.calls[1] ?? [];
    expect(url).toBe(upstream);
    expect(init?.method).toBe('GET');
    expect(init?.redirect).toBe('manual');
    expect(init?.body).toBeUndefined();
    expect([...new Headers(init?.headers).entries()]).toEqual([
      ['accept', 'application/json'], ['authorization', `Bearer ${env.PROVIDER_TOKEN}`],
    ]);
  });
  it.each(['2025-06-18', '2026-07-28'])('rejects unknown tools, malformed arguments, and nonconfigured objects before provider I/O for MCP %s', async (version) => {
    const calls = [
      { name: 'hubspot_delete_record', arguments: { objectType: 'contacts', recordId: '7' } },
      { name: 'hubspot_get_record', arguments: { objectType: 'contacts', recordId: '../7' } },
      { name: 'hubspot_get_record', arguments: { objectType: 'contacts', recordId: '7', url: 'https://evil.example.com' } },
      { name: 'hubspot_get_record', arguments: { objectType: 'companies', recordId: '7' } },
      { name: 'hubspot_get_record', arguments: {} },
    ];
    for (const params of calls) {
      const outbound = fetcher();
      const response = await handleRequest(protocolRequest(version, { method: 'tools/call', params }), env, outbound);
      const text = await response.text();
      expect(text).toMatch(/error|isError/i);
      expect(text).not.toContain(env.PROVIDER_TOKEN);
      expect(outbound).toHaveBeenCalledOnce();
    }
  });
  it('does not access provider credentials for authenticated oversized input', async () => {
    const readSecret = vi.fn(() => env.PROVIDER_TOKEN);
    const protectedEnv = { ...env, get PROVIDER_TOKEN(): string { return readSecret(); } };
    const outbound = fetcher();
    const response = await handleRequest(request('{' + 'x'.repeat(INCOMING_LIMITS.bytes)), protectedEnv, outbound);
    expect(response.status).toBe(400);
    expect(readSecret).not.toHaveBeenCalled();
    expect(outbound).toHaveBeenCalledOnce();
  });
  it('sanitizes upstream failures without returning or logging provider details', async () => {
    const log = vi.spyOn(console, 'log');
    const errorLog = vi.spyOn(console, 'error');
    try {
      for (const upstreamResponse of [
        () => new Response('sentinel-provider-detail', { status: 500 }),
        () => new Response('sentinel-provider-detail', { headers: { 'Content-Type': 'application/json' } }),
        () => { throw new Error('sentinel-provider-exception'); },
      ]) {
        const outbound = vi.fn<typeof globalThis.fetch>(async (input) => {
          if (String(input) === `https://${env.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`) {
            return new Response(jwks, { headers: { 'Content-Type': 'application/json' } });
          }
          return upstreamResponse();
        });
        const response = await handleRequest(protocolRequest('2026-07-28', {
          method: 'tools/call', params: { name: 'hubspot_get_record', arguments: { objectType: 'contacts', recordId: '7' } },
        }), env, outbound);
        const text = await response.text();
        expect(text).toContain('CONNECTOR_READ_FAILED');
        expect(text).not.toContain('sentinel');
        expect(text).not.toContain(env.PROVIDER_TOKEN);
        expect(outbound).toHaveBeenCalledTimes(2);
      }
      expect(log).not.toHaveBeenCalled();
      expect(errorLog).not.toHaveBeenCalled();
    } finally {
      log.mockRestore();
      errorLog.mockRestore();
    }
  });
  it('does not access provider credentials before authentication', async () => {
    const untrusted = { ...env, get PROVIDER_TOKEN(): string { throw new Error('Credential accessed'); } };
    const outbound = fetcher();
    const response = await handleRequest(request('{}', false), untrusted, outbound);
    expect(response.status).toBe(403);
    expect(await response.text()).toContain('CONNECTOR_ACCESS_REQUIRED');
    expect(outbound).not.toHaveBeenCalled();
  });
  it('ignores bearer, cookie, and forwarded identity as an Access assertion substitute', async () => {
    const input = request('{}', false);
    input.headers.set('Authorization', `Bearer ${token}`);
    input.headers.set('Cookie', `CF_Authorization=${token}`);
    input.headers.set('Cf-Access-Authenticated-User-Email', 'synthetic@example.com');
    expect((await handleRequest(input, env, fetcher())).status).toBe(403);
  });
  it('rejects alternate routes, origins, and browser origins before key or API fetches', async () => {
    const outbound = fetcher();
    for (const url of ['https://other.example.com/mcp', 'https://connector.example.com/mcp?url=https://evil.example.com',
      'https://connector.example.com/anything', 'http://connector.example.com/mcp']) {
      const input = new Request(url, request('{}'));
      expect((await handleRequest(input, env, outbound)).status).toBeGreaterThanOrEqual(400);
    }
    const input = request('{}');
    input.headers.set('Origin', 'https://evil.example.com');
    expect((await handleRequest(input, env, outbound)).status).toBe(403);
    expect(outbound).not.toHaveBeenCalled();
  });
  it.each(['[]', 'not json', '{"jsonrpc":"2.0","method":"subscriptions/listen"}',
    '{"jsonrpc":"2.0","method":"resources/subscribe"}'])('rejects amplification/non-read protocol payload %s', async (body) => {
    const outbound = fetcher();
    expect((await handleRequest(request(body), env, outbound)).status).toBe(400);
    expect(outbound).toHaveBeenCalledOnce();
  });
  it('rejects unknown deployment providers without exposing configuration or secrets', async () => {
    const response = await handleRequest(request('{"jsonrpc":"2.0","id":1,"method":"tools/list"}'),
      { ...env, CONNECTOR_PROVIDER: 'https://evil.example.com' }, fetcher());
    expect(response.status).toBe(503);
    expect(await response.text()).toBe('{"error":"CONNECTOR_UNAVAILABLE"}');
  });
});
