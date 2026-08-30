import { CLIENT_CAPABILITIES_META_KEY, PROTOCOL_VERSION_META_KEY } from '@modelcontextprotocol/server';
import { exportJWK, exportPKCS8, generateKeyPair, jwtVerify, SignJWT } from 'jose';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { handleRequest } from '../src/index';
import type { ConnectorJson } from '../src/request';

const tokenEndpoint = 'https://oauth2.googleapis.com/token';
const accessIssuer = 'https://synthetic-google-team.cloudflareaccess.com';
const accessKeysEndpoint = `${accessIssuer}/cdn-cgi/access/certs`;
const audience = 'a'.repeat(64);
const serviceAccountEmail = 'synthetic-reader@synthetic-project.iam.gserviceaccount.com';
const mintedToken = 'synthetic-minted-google-access-token';
const site = 'sc-domain:example.com';
const propertyId = '123456789';
const dates = { startDate: '2026-08-01', endDate: '2026-08-30' };
const protocolVersions = ['2025-06-18', '2026-07-28'] as const;
type GoogleProviderId = 'google-search-console' | 'google-analytics';

interface GoogleFixture {
  provider: GoogleProviderId;
  config: string;
  scope: string;
  tools: readonly string[];
}
const providers: readonly GoogleFixture[] = [
  {
    provider: 'google-search-console', config: JSON.stringify({ allowedSites: [site] }),
    scope: 'https://www.googleapis.com/auth/webmasters.readonly',
    tools: ['gsc_get_site', 'gsc_list_sitemaps', 'gsc_search_performance'],
  },
  {
    provider: 'google-analytics', config: JSON.stringify({ allowedPropertyIds: [propertyId] }),
    scope: 'https://www.googleapis.com/auth/analytics.readonly',
    tools: ['google_analytics_daily_traffic', 'google_analytics_realtime_by_device'],
  },
];

interface GoogleReadFixture {
  provider: GoogleProviderId;
  name: string;
  arguments: Record<string, ConnectorJson>;
  url: string;
  method: 'GET' | 'POST';
  body?: ConnectorJson;
  response: ConnectorJson;
  expectedText: string;
}
const reads: readonly GoogleReadFixture[] = [
  {
    provider: 'google-search-console', name: 'gsc_get_site', arguments: { site },
    url: 'https://www.googleapis.com/webmasters/v3/sites/sc-domain%3Aexample.com', method: 'GET',
    response: { siteUrl: site, permissionLevel: 'siteRestrictedUser', extra: 'sentinel-provider-extra' },
    expectedText: 'siteRestrictedUser',
  },
  {
    provider: 'google-search-console', name: 'gsc_list_sitemaps', arguments: { site },
    url: 'https://www.googleapis.com/webmasters/v3/sites/sc-domain%3Aexample.com/sitemaps', method: 'GET',
    response: { sitemap: [{ path: 'https://example.com/sitemap.xml', warnings: '0', errors: '0',
      contents: [{ type: 'web', submitted: '9007199254740993', indexed: 'sentinel-deprecated-field' }] }] },
    expectedText: '9007199254740993',
  },
  {
    provider: 'google-search-console', name: 'gsc_search_performance', arguments: { site, ...dates, report: 'date', rowLimit: 1 },
    url: 'https://www.googleapis.com/webmasters/v3/sites/sc-domain%3Aexample.com/searchAnalytics/query', method: 'POST',
    body: { ...dates, dimensions: ['date'], type: 'web', dataState: 'final', rowLimit: 1, startRow: 0 },
    response: { rows: [{ keys: ['2026-08-01'], clicks: 3, impressions: 10, ctr: 0.3, position: 4,
      extra: 'sentinel-provider-row' }], extra: 'sentinel-provider-extra' },
    expectedText: 'resultsAreExhaustive',
  },
  {
    provider: 'google-analytics', name: 'google_analytics_daily_traffic', arguments: { propertyId, ...dates, limit: 1 },
    url: 'https://analyticsdata.googleapis.com/v1beta/properties/123456789:runReport', method: 'POST',
    body: { dimensions: [{ name: 'date' }], metrics: [{ name: 'sessions' }, { name: 'activeUsers' },
      { name: 'screenPageViews' }], dateRanges: [dates], limit: '1' },
    response: {
      dimensionHeaders: [{ name: 'date' }], metricHeaders: [
        { name: 'sessions', type: 'TYPE_INTEGER' }, { name: 'activeUsers', type: 'TYPE_INTEGER' },
        { name: 'screenPageViews', type: 'TYPE_INTEGER' },
      ],
      rows: [{ dimensionValues: [{ value: '20260801' }], metricValues: [
        { value: '9007199254740993' }, { value: '20' }, { value: '42' },
      ], extra: 'sentinel-provider-row' }], rowCount: 1,
      metadata: { timeZone: 'Europe/Oslo', extra: 'sentinel-provider-metadata' },
      next: 'https://sentinel-next.example.com',
    },
    expectedText: '9007199254740993',
  },
  {
    provider: 'google-analytics', name: 'google_analytics_realtime_by_device', arguments: { propertyId, limit: 1 },
    url: 'https://analyticsdata.googleapis.com/v1beta/properties/123456789:runRealtimeReport', method: 'POST',
    body: { dimensions: [{ name: 'deviceCategory' }], metrics: [{ name: 'activeUsers' }],
      minuteRanges: [{ startMinutesAgo: 29, endMinutesAgo: 0 }], limit: '1' },
    response: {
      dimensionHeaders: [{ name: 'deviceCategory' }], metricHeaders: [{ name: 'activeUsers', type: 'TYPE_INTEGER' }],
      rows: [{ dimensionValues: [{ value: 'desktop' }], metricValues: [{ value: '12' }] }],
      rowCount: 1, extra: 'sentinel-provider-extra',
    },
    expectedText: 'desktop',
  },
];

let accessAssertion: string;
let jwks: string;
let serviceAccountSecret: string;
let serviceAccountPublicKey: CryptoKey;
beforeAll(async () => {
  // Generated only in memory: no real Access grant or persisted service-account key.
  const [accessPair, servicePair] = await Promise.all([
    generateKeyPair('RS256'), generateKeyPair('RS256', { extractable: true }),
  ]);
  jwks = JSON.stringify({ keys: [{ ...await exportJWK(accessPair.publicKey), kid: 'synthetic-access-key' }] });
  accessAssertion = await new SignJWT({}).setProtectedHeader({ alg: 'RS256', kid: 'synthetic-access-key' })
    .setIssuer(accessIssuer).setAudience(audience).setIssuedAt().setExpirationTime('5m').sign(accessPair.privateKey);
  serviceAccountPublicKey = servicePair.publicKey;
  serviceAccountSecret = JSON.stringify({
    type: 'service_account', project_id: 'synthetic-project', private_key_id: 'a'.repeat(40),
    private_key: await exportPKCS8(servicePair.privateKey), client_email: serviceAccountEmail, token_uri: tokenEndpoint,
  });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function environment(fixture: GoogleFixture): Env {
  return {
    CONNECTOR_PROVIDER: fixture.provider, CONNECTOR_CONFIG_JSON: fixture.config,
    PUBLIC_ORIGIN: 'https://connector.example.com', ACCESS_TEAM_DOMAIN: 'synthetic-google-team.cloudflareaccess.com',
    ACCESS_AUD: audience, PROVIDER_TOKEN: serviceAccountSecret,
  };
}
interface RpcFixture {
  method: 'tools/list' | 'tools/call';
  params: Record<string, ConnectorJson>;
}
function protocolRequest(version: string, message: RpcFixture): Request {
  const params = { ...message.params };
  const headers = new Headers({
    'Content-Type': 'application/json', Accept: 'application/json, text/event-stream',
    'Cf-Access-Jwt-Assertion': accessAssertion, 'MCP-Protocol-Version': version,
    Authorization: 'Bearer sentinel-caller-bearer', Cookie: 'synthetic=sentinel-caller-cookie',
    'X-Api-Key': 'sentinel-caller-api-key',
  });
  if (version === '2026-07-28') {
    params._meta = { [PROTOCOL_VERSION_META_KEY]: version, [CLIENT_CAPABILITIES_META_KEY]: {} };
    headers.set('MCP-Method', message.method);
    if (message.method === 'tools/call') headers.set('MCP-Name', String(params.name));
  }
  return new Request('https://connector.example.com/mcp', {
    method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: message.method, params }),
  });
}
function toolRequest(version: string, read: GoogleReadFixture): Request {
  return protocolRequest(version, { method: 'tools/call', params: { name: read.name, arguments: read.arguments } });
}
function tokenResponse(fixture: GoogleFixture): Response {
  return Response.json({ access_token: mintedToken, token_type: 'Bearer', expires_in: 3_600, scope: fixture.scope });
}
function mockFetch(fixture: GoogleFixture, read?: GoogleReadFixture, tokenReply?: () => Response, providerReply?: () => Response) {
  // Any accidental global fetch also fails locally rather than touching the network.
  vi.stubGlobal('fetch', vi.fn<typeof globalThis.fetch>(async () => { throw new Error('Unexpected global fetch'); }));
  return vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = String(input);
    if (url === accessKeysEndpoint) return new Response(jwks, { headers: { 'Content-Type': 'application/json' } });
    if (url === tokenEndpoint) return tokenReply === undefined ? tokenResponse(fixture) : tokenReply();
    if (read !== undefined && url === read.url) return providerReply === undefined ? Response.json(read.response) : providerReply();
    throw new Error('Unexpected mocked destination');
  });
}
function expectNoSecrets(text: string): void {
  for (const secret of [accessAssertion, serviceAccountSecret, serviceAccountEmail, mintedToken, 'PRIVATE KEY', 'sentinel']) {
    expect(text).not.toContain(secret);
  }
}
const listedTools = z.object({ result: z.object({ tools: z.array(z.object({
  name: z.string(), annotations: z.object({ readOnlyHint: z.literal(true) }),
})) }) });

describe.each(providers)('$provider authenticated Google runtime', (fixture) => {
  const providerReads = reads.filter((read) => read.provider === fixture.provider);
  describe.each(protocolVersions)('MCP %s', (version) => {
    it('lists exactly the authored read tools without minting a token or reading provider data', async () => {
      const outbound = mockFetch(fixture);
      const response = await handleRequest(protocolRequest(version, { method: 'tools/list', params: {} }), environment(fixture), outbound);
      const text = await response.text();
      expect(response.status, text).toBe(200);
      // Legacy stateless responses use SSE; the current protocol returns JSON.
      const messages = response.headers.get('content-type')?.startsWith('text/event-stream')
        ? text.split(/\r?\n/u).filter((line) => line.startsWith('data:')).map((line) => line.slice(5).trim())
        : [text];
      expect(messages).toHaveLength(1);
      expect(listedTools.parse(JSON.parse(messages[0] ?? '')).result.tools.map((tool) => tool.name).sort()).toEqual(fixture.tools);
      expect(outbound.mock.calls.map(([url]) => String(url))).toEqual([accessKeysEndpoint]);
      expectNoSecrets(text);
    });

    it.each(providerReads)('mints only the fixed scope and executes the exact $name read', async (read) => {
      const outbound = mockFetch(fixture, read);
      const response = await handleRequest(toolRequest(version, read), environment(fixture), outbound);
      const text = await response.text();
      expect(response.status, text).toBe(200);
      expect(text).toContain(read.expectedText);
      expect(text).not.toMatch(/"isError":true|CONNECTOR_READ_FAILED/);
      expectNoSecrets(text);
      expect(response.headers.get('cache-control')).toBe('no-store');
      expect(outbound.mock.calls.map(([url]) => String(url))).toEqual([accessKeysEndpoint, tokenEndpoint, read.url]);

      const accessInit = outbound.mock.calls[0]?.[1];
      expect(accessInit?.method).toBe('GET');
      expect(accessInit?.redirect).toBe('error');
      expect(accessInit?.body).toBeUndefined();
      expect([...new Headers(accessInit?.headers).entries()]).toEqual([['accept', 'application/json']]);
      const tokenInit = outbound.mock.calls[1]?.[1];
      expect(tokenInit?.method).toBe('POST');
      expect(tokenInit?.redirect).toBe('error');
      expect([...new Headers(tokenInit?.headers).entries()]).toEqual([
        ['accept', 'application/json'], ['content-type', 'application/x-www-form-urlencoded'],
      ]);
      const form = new URLSearchParams(String(tokenInit?.body));
      expect([...form.keys()]).toEqual(['grant_type', 'assertion']);
      expect(form.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:jwt-bearer');
      const assertion = form.get('assertion') ?? '';
      const signed = await jwtVerify(assertion, serviceAccountPublicKey, {
        algorithms: ['RS256'], audience: tokenEndpoint, issuer: serviceAccountEmail,
      });
      expect(signed.protectedHeader).toEqual({ alg: 'RS256', typ: 'JWT', kid: 'a'.repeat(40) });
      expect(signed.payload.scope).toBe(fixture.scope);
      expect(Object.keys(signed.payload).sort()).toEqual(['aud', 'exp', 'iat', 'iss', 'scope']);
      expect((signed.payload.exp ?? 0) - (signed.payload.iat ?? 0)).toBe(300);
      expect(assertion).not.toBe(accessAssertion);
      expectNoSecrets(String(tokenInit?.body));

      const providerInit = outbound.mock.calls[2]?.[1];
      expect(providerInit?.method).toBe(read.method);
      expect(providerInit?.redirect).toBe('error');
      const expectedHeaders = [['accept', 'application/json'], ['authorization', `Bearer ${mintedToken}`]];
      if (read.body !== undefined) expectedHeaders.push(['content-type', 'application/json']);
      expect([...new Headers(providerInit?.headers).entries()]).toEqual(expectedHeaders);
      expect(providerInit?.body).toBe(read.body === undefined ? undefined : JSON.stringify(read.body));
      expect(String(providerInit?.body)).not.toContain(assertion);
      expectNoSecrets(String(providerInit?.body));
      expectNoSecrets(read.url);
    });

    it('rejects unconfigured sites or properties before the token endpoint for every authored tool', async () => {
      for (const read of providerReads) {
        const outbound = mockFetch(fixture, read);
        const args = fixture.provider === 'google-search-console'
          ? { ...read.arguments, site: 'sc-domain:other.example.com' }
          : { ...read.arguments, propertyId: '987654321' };
        const response = await handleRequest(protocolRequest(version, {
          method: 'tools/call', params: { name: read.name, arguments: args },
        }), environment(fixture), outbound);
        const text = await response.text();
        expect(text).toContain('CONNECTOR_READ_FAILED');
        expectNoSecrets(text);
        expect(outbound.mock.calls.map(([url]) => String(url))).toEqual([accessKeysEndpoint]);
      }
    });

    it.each(['status', 'scope', 'redirect', 'exception'] as const)('sanitizes a token %s failure without attempting the provider read', async (failure) => {
      const read = providerReads[0];
      if (read === undefined) throw new Error('Missing synthetic read');
      const log = vi.spyOn(console, 'log');
      const errorLog = vi.spyOn(console, 'error');
      const outbound = mockFetch(fixture, read, () => {
        if (failure === 'status') return new Response('sentinel-token-provider-detail', { status: 500 });
        if (failure === 'scope') return Response.json({ access_token: mintedToken, token_type: 'Bearer', expires_in: 300, scope: 'sentinel-write-scope' });
        if (failure === 'redirect') return Response.redirect('https://sentinel-redirect.example.com/token');
        throw new Error(`sentinel-token-error:${accessAssertion}:${serviceAccountSecret}`);
      });
      const response = await handleRequest(toolRequest(version, read), environment(fixture), outbound);
      const text = await response.text();
      expect(text).toContain('CONNECTOR_READ_FAILED');
      expectNoSecrets(text);
      expect(outbound.mock.calls.map(([url]) => String(url))).toEqual([accessKeysEndpoint, tokenEndpoint]);
      expect(log).not.toHaveBeenCalled();
      expect(errorLog).not.toHaveBeenCalled();
    });

    it.each(['status', 'redirect', 'invalid-json', 'projection', 'exception'] as const)('sanitizes a provider %s failure after token minting', async (failure) => {
      const read = providerReads[0];
      if (read === undefined) throw new Error('Missing synthetic read');
      const log = vi.spyOn(console, 'log');
      const errorLog = vi.spyOn(console, 'error');
      const outbound = mockFetch(fixture, read, undefined, () => {
        if (failure === 'status') return new Response('sentinel-provider-detail', { status: 500 });
        if (failure === 'redirect') return Response.redirect('https://sentinel-redirect.example.com/provider');
        if (failure === 'invalid-json') return new Response('sentinel-invalid-json', { headers: { 'Content-Type': 'application/json' } });
        if (failure === 'projection') return Response.json({ unexpected: `sentinel-provider-data:${mintedToken}` });
        throw new Error(`sentinel-provider-error:${mintedToken}:${accessAssertion}`);
      });
      const response = await handleRequest(toolRequest(version, read), environment(fixture), outbound);
      const text = await response.text();
      expect(text).toContain('CONNECTOR_READ_FAILED');
      expectNoSecrets(text);
      expect(outbound.mock.calls.map(([url]) => String(url))).toEqual([accessKeysEndpoint, tokenEndpoint, read.url]);
      expect(log).not.toHaveBeenCalled();
      expect(errorLog).not.toHaveBeenCalled();
    });
  });

  it('does not read service-account credentials or contact any endpoint without an Access assertion', async () => {
    const readSecret = vi.fn(() => serviceAccountSecret);
    const protectedEnv = { ...environment(fixture), get PROVIDER_TOKEN(): string { return readSecret(); } };
    const outbound = mockFetch(fixture);
    const request = protocolRequest('2026-07-28', { method: 'tools/list', params: {} });
    request.headers.delete('Cf-Access-Jwt-Assertion');
    const response = await handleRequest(request, protectedEnv, outbound);
    expect(response.status).toBe(403);
    const text = await response.text();
    expect(text).toContain('CONNECTOR_ACCESS_REQUIRED');
    expectNoSecrets(text);
    expect(readSecret).not.toHaveBeenCalled();
    expect(outbound).not.toHaveBeenCalled();
  });
});
