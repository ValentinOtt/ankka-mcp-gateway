import { CLIENT_CAPABILITIES_META_KEY, createMcpHandler, McpServer, PROTOCOL_VERSION_META_KEY } from '@modelcontextprotocol/server';
import { describe, expect, it, vi } from 'vitest';
import type { ReadConnector, ReadExecutor } from '../src/connector';
import { GOOGLE_TOKEN_ENDPOINT } from '../src/google-auth';
import { createGoogleSearchConsoleConnector } from '../src/providers/google-search-console';
import { executeReadRequest, type ConnectorJson, type ReadRequestPlan } from '../src/request';

const site = 'sc-domain:example.com';
const base = '/webmasters/v3/sites/sc-domain%3Aexample.com';
const rawConfig = JSON.stringify({ allowedSites: [site] });
const rawSecret = JSON.stringify({
  type: 'service_account', project_id: 'synthetic-project', private_key_id: 'a'.repeat(40),
  private_key: 'synthetic-placeholder-key-never-used', client_email: 'synthetic-reader@synthetic-project.iam.gserviceaccount.com',
  token_uri: GOOGLE_TOKEN_ENDPOINT,
});
const connector = createGoogleSearchConsoleConnector(rawConfig, rawSecret);
const body = {
  startDate: '2026-07-01', endDate: '2026-07-31', dimensions: ['date'],
  type: 'web', dataState: 'final', rowLimit: 100, startRow: 0,
};

async function callTool(name: string, args: Record<string, ConnectorJson>, execute: ReadExecutor, selected: ReadConnector = connector): Promise<string> {
  const handler = createMcpHandler(() => {
    const server = new McpServer({ name: 'synthetic-google-test', version: '1.0.0' });
    selected.registerTools(server, execute);
    return server;
  });
  try {
    const response = await handler.fetch(new Request('https://connector.example.com/mcp', {
      method: 'POST', headers: {
        'Content-Type': 'application/json', Accept: 'application/json, text/event-stream',
        'MCP-Protocol-Version': '2026-07-28', 'MCP-Method': 'tools/call', 'MCP-Name': name,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {
        name, arguments: args, _meta: { [PROTOCOL_VERSION_META_KEY]: '2026-07-28', [CLIENT_CAPABILITIES_META_KEY]: {} },
      } }),
    }));
    return await response.text();
  } finally { await handler.close(); }
}

describe('ordinary Search Console domain-property reads', () => {
  it('pins the API origin and defers service-account authorization to actual reads', () => {
    expect(connector.id).toBe('google-search-console');
    expect(connector.origin).toBe('https://www.googleapis.com');
    expect(connector.headers).toEqual({});
    expect(connector.authorize).toBeTypeOf('function');
  });
  it.each([
    ['https://example.com/'], ['sc-domain:EXAMPLE.com'], ['sc-domain:example.com/'],
    ['sc-domain:example..com'], ['sc-domain:*.example.com'], ['sc-domain:127.0.0.1'],
    ['sc-domain:example.com?x=1'], ['sc-domain:singlelabel'], [], [site, site],
    Array.from({ length: 26 }, (_, index) => `sc-domain:site${index}.example.com`),
  ].map((allowedSites) => ({ allowedSites })))('rejects noncanonical/unbounded site configuration %j', ({ allowedSites }) => {
    expect(() => createGoogleSearchConsoleConnector(JSON.stringify({ allowedSites }), rawSecret)).toThrow('CONNECTOR_CONFIGURATION_INVALID');
  });
  it('rejects extra origin/scope controls in configuration', () => {
    expect(() => createGoogleSearchConsoleConnector(JSON.stringify({ allowedSites: [site], origin: 'https://evil.example.com' }), rawSecret))
      .toThrow('CONNECTOR_CONFIGURATION_INVALID');
  });
  it('accepts canonical ASCII punycode domain properties', () => {
    const selected = createGoogleSearchConsoleConnector(JSON.stringify({ allowedSites: ['sc-domain:example.xn--p1ai'] }), rawSecret);
    expect(selected.allowRequest({ method: 'GET', path: '/webmasters/v3/sites/sc-domain%3Aexample.xn--p1ai' })).toBe(true);
  });
  it.each<ReadRequestPlan>([
    { method: 'GET', path: base }, { method: 'GET', path: `${base}/sitemaps` },
    { method: 'POST', path: `${base}/searchAnalytics/query`, body },
  ])('allows exact statically authored reads %j', (plan) => expect(connector.allowRequest(plan)).toBe(true));
  it.each<ReadRequestPlan>([
    { method: 'POST', path: base, body: {} },
    { method: 'GET', path: `${base}/sitemaps`, query: { sitemapIndex: 'https://evil.example.com' } },
    { method: 'GET', path: `${base}/sitemaps`, body: {} },
    { method: 'GET', path: `${base}/../sites` },
    { method: 'GET', path: `${base}%2Fsitemaps` },
    { method: 'GET', path: '/webmasters/v3/sites/sc-domain%3Aother.example.com' },
    { method: 'GET', path: '/webmasters/v3/sites' },
    { method: 'GET', path: `${base}/searchAnalytics/query` },
    { method: 'POST', path: `${base}/searchAnalytics/query`, query: { key: 'synthetic' }, body },
    { method: 'POST', path: `${base}/searchAnalytics/query`, body: { ...body, type: 'discover' } },
    { method: 'POST', path: `${base}/searchAnalytics/query`, body: { ...body, dataState: 'all' } },
    { method: 'POST', path: `${base}/searchAnalytics/query`, body: { ...body, startRow: 100 } },
    { method: 'POST', path: `${base}/searchAnalytics/query`, body: { ...body, rowLimit: 251 } },
    { method: 'POST', path: `${base}/searchAnalytics/query`, body: { ...body, dimensions: ['date', 'query'] } },
    { method: 'POST', path: `${base}/searchAnalytics/query`, body: { ...body, dimensionFilterGroups: [] } },
    { method: 'POST', path: `${base}/searchAnalytics/query`, body: { ...body, startDate: '2026-02-30' } },
    { method: 'POST', path: `${base}/searchAnalytics/query`, body: { ...body, endDate: '2026-06-30' } },
    { method: 'POST', path: `${base}/searchAnalytics/query`, body: { ...body, endDate: '2026-10-31' } },
  ])('denies method/property/query/body expansion %j', (plan) => expect(connector.allowRequest(plan)).toBe(false));

  it('projects only the matching configured site metadata', async () => {
    const execute = vi.fn<ReadExecutor>(async () => ({ siteUrl: site, permissionLevel: 'siteRestrictedUser', extra: 'sentinel-private' }));
    const text = await callTool('gsc_get_site', { site }, execute);
    expect(execute).toHaveBeenCalledWith({ method: 'GET', path: base });
    expect(text).toContain('siteRestrictedUser');
    expect(text).not.toContain('sentinel');
    const mismatch = await callTool('gsc_get_site', { site }, async () => ({ siteUrl: 'sc-domain:other.example.com', permissionLevel: 'siteOwner' }));
    expect(mismatch).toContain('CONNECTOR_READ_FAILED');
    expect(mismatch).not.toContain('other.example.com');
  });
  it.each([
    ['SITE_OWNER', 'siteOwner'], ['SITE_FULL_USER', 'siteFullUser'],
    ['SITE_RESTRICTED_USER', 'siteRestrictedUser'], ['SITE_UNVERIFIED_USER', 'siteUnverifiedUser'],
  ])('normalizes the discovery permission alias %s to %s', async (upstream, normalized) => {
    const text = await callTool('gsc_get_site', { site }, async () => ({ siteUrl: site, permissionLevel: upstream }));
    expect(text).toContain(normalized);
    expect(text).not.toContain(upstream);
  });
  it('rejects unspecified permission labels', async () => {
    const text = await callTool('gsc_get_site', { site }, async () => ({ siteUrl: site, permissionLevel: 'SITE_PERMISSION_LEVEL_UNSPECIFIED' }));
    expect(text).toContain('CONNECTOR_READ_FAILED');
  });
  it('uses the shared guard for one fixed final web-search report and projects capped result metadata', async () => {
    const fetcher = vi.fn<typeof globalThis.fetch>(async () => Response.json({
      rows: [{ keys: ['2026-07-01'], clicks: 2, impressions: 10, ctr: 0.2, position: 3, private: 'sentinel-row' }],
      responseAggregationType: 'byProperty', metadata: { firstIncompleteDate: '2026-07-31', extra: 'sentinel-meta' },
      next: 'https://evil.example.com', private: 'sentinel-response',
    }));
    const execute: ReadExecutor = (plan) => executeReadRequest({
      origin: connector.origin, plan, allowRequest: connector.allowRequest,
      headers: { Authorization: 'Bearer synthetic-test-token' }, fetch: fetcher,
    });
    const text = await callTool('gsc_search_performance', { site, report: 'date', startDate: body.startDate, endDate: body.endDate, rowLimit: 1 }, execute);
    expect(text).toContain('firstIncompleteDate');
    expect(text).toContain('2026-07-31');
    expect(text).toContain('resultsAreExhaustive');
    expect(text).toContain('rowLimitReached');
    expect(text).not.toContain('sentinel');
    expect(text).not.toContain('evil.example.com');
    expect(fetcher).toHaveBeenCalledOnce();
    expect(fetcher.mock.calls[0]?.[0]).toBe(`https://www.googleapis.com${base}/searchAnalytics/query`);
    expect(JSON.parse(String(fetcher.mock.calls[0]?.[1]?.body))).toEqual({ ...body, rowLimit: 1 });
  });
  it('handles absent rows/keys without inventing metrics and rejects over-limit responses', async () => {
    const args = { site, report: 'date', startDate: body.startDate, endDate: body.endDate, rowLimit: 1 };
    expect(await callTool('gsc_search_performance', args, async () => ({}))).toContain('rows');
    expect(await callTool('gsc_search_performance', args, async () => ({ rows: [{ clicks: 0, impressions: 0, ctr: 0, position: 0 }] })))
      .not.toContain('CONNECTOR_READ_FAILED');
    const text = await callTool('gsc_search_performance', args, async () => ({
      rows: Array.from({ length: 2 }, () => ({ clicks: 0, impressions: 0, ctr: 0, position: 0 })),
    }));
    expect(text).toContain('CONNECTOR_READ_FAILED');
  });
  it('reads the singular sitemap response with int64 strings and omits deprecated indexed counts', async () => {
    const execute = vi.fn<ReadExecutor>(async () => ({ sitemap: [{
      path: 'https://example.com/sitemap.xml', warnings: '0', errors: '1', isPending: false,
      contents: [{ type: 'web', submitted: '9007199254740993', indexed: 'sentinel-deprecated-count' }],
      next: 'sentinel-next',
    }], extra: 'sentinel-response' }));
    const text = await callTool('gsc_list_sitemaps', { site }, execute);
    expect(text).toContain('9007199254740993');
    expect(text).toContain('https://example.com/sitemap.xml');
    expect(text).not.toContain('sentinel');
    expect(text).not.toContain('indexed');
    expect(execute).toHaveBeenCalledOnce();
    expect(execute).toHaveBeenCalledWith({ method: 'GET', path: `${base}/sitemaps` });
  });
  it.each([
    { site: 'sc-domain:other.example.com', report: 'date', startDate: body.startDate, endDate: body.endDate },
    { site, report: 'hour', startDate: body.startDate, endDate: body.endDate },
    { site, report: 'date', startDate: body.startDate, endDate: body.endDate, rowLimit: 251 },
    { site, report: 'date', startDate: body.startDate, endDate: body.endDate, filter: 'anything' },
    { site, report: 'date', startDate: '2026-02-30', endDate: body.endDate },
  ])('rejects unsupported tool arguments before execution %j', async (args) => {
    const execute = vi.fn<ReadExecutor>();
    await callTool('gsc_search_performance', args, execute);
    expect(execute).not.toHaveBeenCalled();
  });
});
