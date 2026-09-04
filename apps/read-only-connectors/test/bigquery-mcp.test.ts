import { beforeAll, afterEach, describe, expect, it, vi } from 'vitest';
import { exportJWK, exportPKCS8, generateKeyPair, jwtVerify, SignJWT } from 'jose';
import { CLIENT_CAPABILITIES_META_KEY, PROTOCOL_VERSION_META_KEY } from '@modelcontextprotocol/server';
import { handleRequest } from '../src/index';
import { createBigQueryMcpConnector, BIGQUERY_MCP_PROBE_QUERY } from '../src/providers/bigquery-mcp';
import { GOOGLE_TOKEN_ENDPOINT, GOOGLE_PROVIDER_SCOPES } from '../src/google-auth';
import type { ConnectorJson, ReadRequestPlan } from '../src/request';

const issuer = 'https://bridge-test.cloudflareaccess.com';
const keysUrl = `${issuer}/cdn-cgi/access/certs`;
const googleUrl = 'https://bigquery.googleapis.com/mcp';
const audience = 'b'.repeat(64);
const mintedToken = 'synthetic-google-access-token';
const config = JSON.stringify({ queryProjectId: 'synthetic-query-project',
  allowedDatasets: [{ projectId: 'synthetic-data-project', datasetId: 'sample_dataset' }] });
let assertion: string;
let jwks: string;
let secret: string;
let googlePublicKey: CryptoKey;
beforeAll(async () => {
  const access = await generateKeyPair('RS256');
  const google = await generateKeyPair('RS256', { extractable: true });
  googlePublicKey = google.publicKey;
  jwks = JSON.stringify({ keys: [{ ...await exportJWK(access.publicKey), kid: 'synthetic-access' }] });
  assertion = await new SignJWT({}).setProtectedHeader({ alg: 'RS256', kid: 'synthetic-access' })
    .setIssuer(issuer).setAudience(audience).setIssuedAt().setExpirationTime('5m').sign(access.privateKey);
  secret = JSON.stringify({ type: 'service_account', project_id: 'synthetic-query-project',
    private_key_id: 'a'.repeat(40), private_key: await exportPKCS8(google.privateKey),
    client_email: 'bridge-reader@synthetic-query-project.iam.gserviceaccount.com', token_uri: GOOGLE_TOKEN_ENDPOINT });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });
function environment(): Env {
  return { CONNECTOR_PROVIDER: 'bigquery-mcp', CONNECTOR_CONFIG_JSON: config,
    PUBLIC_ORIGIN: 'https://bridge.example.com', ACCESS_TEAM_DOMAIN: 'bridge-test.cloudflareaccess.com',
    ACCESS_AUD: audience, PROVIDER_TOKEN: secret };
}
function request(version: string, method: string, params: Record<string, ConnectorJson>): Request {
  const headers = new Headers({ 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream',
    'MCP-Protocol-Version': version, 'Cf-Access-Jwt-Assertion': assertion,
    Authorization: 'Bearer sentinel-inbound', Cookie: 'sentinel=cookie', 'X-Api-Key': 'sentinel-inbound-key' });
  if (version === '2026-07-28') {
    params = { ...params, _meta: { [PROTOCOL_VERSION_META_KEY]: version, [CLIENT_CAPABILITIES_META_KEY]: {} } };
    headers.set('MCP-Method', method);
    if (method === 'tools/call') headers.set('MCP-Name', String(params.name));
  }
  return new Request('https://bridge.example.com/mcp', {
    method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
}
const tableArgs = { projectId: 'synthetic-data-project', datasetId: 'sample_dataset', pageSize: 10 };
const queryArgs = { projectId: 'synthetic-query-project', query: BIGQUERY_MCP_PROBE_QUERY };
function outbound(reply: () => Response = () => Response.json({ jsonrpc: '2.0', id: 1,
  result: { content: [{ type: 'text', text: 'synthetic Google result' }] } })) {
  vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('Unexpected network'); }));
  return vi.fn<typeof globalThis.fetch>(async (input) => {
    if (String(input) === keysUrl) return new Response(jwks, { headers: { 'Content-Type': 'application/json' } });
    if (String(input) === GOOGLE_TOKEN_ENDPOINT) return Response.json({
      access_token: mintedToken, token_type: 'Bearer', expires_in: 3600, scope: GOOGLE_PROVIDER_SCOPES.bigquery });
    if (String(input) === googleUrl) return reply();
    throw new Error('Unexpected destination');
  });
}
describe.each(['2025-06-18', '2026-07-28'])('hosted BigQuery bridge, MCP %s', (version) => {
  it('lists only reviewed tools without contacting Google', async () => {
    const fetcher = outbound();
    const response = await handleRequest(request(version, 'tools/list', {}), environment(), fetcher);
    const body = await response.text();
    expect(response.status).toBe(200);
    for (const name of ['list_table_ids', 'get_table_info', 'execute_sql_readonly']) expect(body).toContain(name);
    expect(body).not.toContain('"name":"execute_sql"');
    expect(fetcher.mock.calls.map(([url]) => String(url))).toEqual([keysUrl]);
  });
  it.each([
    { name: 'list_table_ids', args: tableArgs },
    { name: 'get_table_info', args: { projectId: tableArgs.projectId, datasetId: tableArgs.datasetId, tableId: 'events_20260101' } },
    { name: 'execute_sql_readonly', args: queryArgs },
  ])('forwards $name to Google with a newly minted token', async ({ name, args }) => {
    const fetcher = outbound();
    const response = await handleRequest(request(version, 'tools/call', { name, arguments: args }), environment(), fetcher);
    const body = await response.text();
    expect(response.status).toBe(200);
    expect(body).toContain('synthetic Google result');
    expect(body).not.toContain('CONNECTOR_READ_FAILED');
    for (const value of [mintedToken, secret, assertion, 'sentinel']) expect(body).not.toContain(value);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(fetcher.mock.calls.map(([url]) => String(url))).toEqual([keysUrl, GOOGLE_TOKEN_ENDPOINT, googleUrl]);
    const form = new URLSearchParams(String(fetcher.mock.calls[1]?.[1]?.body));
    const signed = await jwtVerify(form.get('assertion') ?? '', googlePublicKey, {
      audience: GOOGLE_TOKEN_ENDPOINT, issuer: 'bridge-reader@synthetic-query-project.iam.gserviceaccount.com',
    });
    expect(signed.payload.scope).toBe(GOOGLE_PROVIDER_SCOPES.bigquery);
    expect(signed.payload.sub).toBeUndefined();
    const init = fetcher.mock.calls[2]?.[1];
    expect(init?.redirect).toBe('manual');
    expect([...new Headers(init?.headers).entries()]).toEqual([
      ['accept', 'application/json, text/event-stream'], ['authorization', `Bearer ${mintedToken}`],
      ['content-type', 'application/json'], ['mcp-protocol-version', '2025-06-18'],
    ]);
    expect(JSON.parse(String(init?.body))).toEqual({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {
      name, arguments: args,
    } });
  });
  it.each([
    { name: 'execute_sql', arguments: queryArgs },
    { name: 'execute_sql_readonly', arguments: { ...queryArgs, query: 'SELECT * FROM sample_dataset.events' } },
    { name: 'execute_sql_readonly', arguments: { ...queryArgs, projectId: 'unapproved-project' } },
    { name: 'list_table_ids', arguments: { ...tableArgs, datasetId: 'unapproved_dataset' } },
    { name: 'list_table_ids', arguments: { ...tableArgs, projectId: 'synthetic-query-project' } },
    { name: 'get_table_info', arguments: { ...tableArgs, tableId: '../secrets' } },
    { name: 'list_table_ids', arguments: { ...tableArgs, pageSize: 5000 } },
    { name: 'list_table_ids', arguments: { ...tableArgs, url: 'https://attacker.example.com' } },
  ])('rejects an unauthorized request before Google auth: $name', async (params) => {
    const fetcher = outbound();
    const response = await handleRequest(request(version, 'tools/call', params), environment(), fetcher);
    expect(await response.text()).not.toContain('synthetic Google result');
    expect(fetcher.mock.calls.map(([url]) => String(url))).toEqual([keysUrl]);
  });
});
it('rejects missing Access authentication before reading the provider secret', async () => {
  const req = request('2025-06-18', 'tools/call', { name: 'list_table_ids', arguments: tableArgs });
  req.headers.delete('Cf-Access-Jwt-Assertion');
  const env = environment();
  const readSecret = vi.fn(() => { throw new Error('Secret must stay unread'); });
  Object.defineProperty(env, 'PROVIDER_TOKEN', { get: readSecret });
  const fetcher = outbound();
  expect((await handleRequest(req, env, fetcher)).status).toBe(403);
  expect(readSecret).not.toHaveBeenCalled();
  expect(fetcher).not.toHaveBeenCalled();
});
it.each([
  () => Response.redirect('https://attacker.example.com', 302),
  () => Response.json({ error: { message: 'sentinel-private-provider-error' } }, { status: 403 }),
  () => Response.json({ jsonrpc: '2.0', id: 1, result: { isError: true, content: [{ type: 'text', text: 'sentinel-private-provider-error' }] } }),
  () => Response.json({ jsonrpc: '2.0', id: 99, result: { content: [{ type: 'text', text: 'sentinel-wrong-response' }] } }),
  () => new Response('data: sentinel-unsupported-stream\n\n', { headers: { 'Content-Type': 'text/event-stream' } }),
])('redacts upstream failures and refuses redirects or unsupported transport', async (reply) => {
  const fetcher = outbound(reply);
  const response = await handleRequest(request('2025-06-18', 'tools/call', { name: 'list_table_ids', arguments: tableArgs }), environment(), fetcher);
  const body = await response.text();
  expect(body).toContain('CONNECTOR_READ_FAILED');
  expect(body).not.toContain('sentinel');
  expect(fetcher.mock.calls.map(([url]) => String(url))).toEqual([keysUrl, GOOGLE_TOKEN_ENDPOINT, googleUrl]);
});
it('keeps the outbound gate exact even without the MCP SDK', () => {
  const connector = createBigQueryMcpConnector(config, secret);
  const good: ReadRequestPlan = { method: 'POST', path: '/mcp', body: {
    jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_table_ids', arguments: tableArgs },
  } };
  expect(connector.allowRequest(good)).toBe(true);
  expect(connector.allowRequest({ ...good, path: '/other' })).toBe(false);
  expect(connector.allowRequest({ ...good, query: { url: 'https://attacker.example.com' } })).toBe(false);
  expect(connector.allowRequest({ ...good, body: { jsonrpc: '2.0', id: 1, method: 'tools/list' } })).toBe(false);
});
