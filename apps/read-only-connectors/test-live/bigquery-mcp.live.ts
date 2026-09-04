import { readFileSync } from 'node:fs';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { expect, it } from 'vitest';
import { z } from 'zod';
import type { ConnectorJson } from '../src/request';
import { handleRequest } from '../src/index';
import { BIGQUERY_MCP_PROBE_QUERY } from '../src/providers/bigquery-mcp';
import { GOOGLE_TOKEN_ENDPOINT } from '../src/google-auth';

const enabled = process.env.ANKKA_BIGQUERY_BRIDGE_LIVE === '1';
const privateConfig = z.object({
  queryProjectId: z.string(), allowedDatasets: z.array(z.object({ projectId: z.string(), datasetId: z.string() })).min(1),
  probeTableId: z.string().optional(),
}).strict();
const queryResponse = z.object({ result: z.object({
  isError: z.boolean().optional(), content: z.array(z.object({ type: z.literal('text'), text: z.string() })),
}) });
const upstreamDiagnostic = z.object({
  error: z.object({ code: z.number(), message: z.string().optional() }).optional(),
  result: z.object({
    isError: z.boolean().optional(),
    content: z.array(z.object({ type: z.string(), text: z.string().optional() })).optional(),
  }).optional(),
});
async function diagnose(response: Response): Promise<string[]> {
  const notes: string[] = [];
  const media = response.headers.get('content-type') ?? '';
  notes.push(media.startsWith('application/json') ? 'json' : media.startsWith('text/event-stream') ? 'sse' : 'other_media');
  const reader = response.body?.getReader();
  if (reader === undefined) return notes;
  let size = 0;
  let text = '';
  try {
    const decoder = new TextDecoder();
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > 524288) { await reader.cancel(); return [...notes, 'oversize']; }
      text += decoder.decode(chunk.value, { stream: true });
    }
    text += decoder.decode();
    const parsed = upstreamDiagnostic.safeParse(JSON.parse(text));
    if (parsed.success) {
      if (parsed.data.error !== undefined) notes.push(`rpc_error_${parsed.data.error.code}`);
      if (parsed.data.result !== undefined) notes.push(parsed.data.result.isError === true ? 'tool_error' : 'tool_success');
      const message = parsed.data.result?.content?.map((item) => item.text ?? '').join(' ') ?? parsed.data.error?.message ?? '';
      const words = message.match(/\b(?:permission|denied|invalid|missing|required|argument|arguments|field|fields|unknown|unexpected|unsupported|authentication|authorization|scope|scopes|project|query|dataset|service|account|token|disabled|enabled|not|found|unable|failed|execute|parse|parameter|parameters|access|sufficient|insufficient|bigquery|billing|request|provided|error)\b/giu) ?? [];
      if (words.length > 0) notes.push(`message_keywords:${words.slice(0,50).join('_').toLowerCase()}`);
    }
    for (const marker of ['mcp.tools.call', 'bigquery.jobs.create', 'bigquery.tables.getData', 'bigquery.datasets.get',
      'PERMISSION_DENIED', 'SERVICE_DISABLED', 'ACCESS_TOKEN_SCOPE_INSUFFICIENT', 'Invalid argument', 'Unknown argument',
      'project_id', 'projectId', 'jobTimeoutMs', 'timeoutMs']) {
      if (text.includes(marker)) notes.push(marker);
    }
  } catch { notes.push('unrecognized_response'); }
  return notes;
}

it.skipIf(!enabled)('calls hosted Google MCP through the bridge with a private test identity', async () => {
  let config: z.infer<typeof privateConfig>;
  let secret: string;
  try {
    config = privateConfig.parse(JSON.parse(readFileSync(process.env.ANKKA_BIGQUERY_BRIDGE_CONFIG_FILE ?? '', 'utf8')));
    secret = readFileSync(process.env.ANKKA_BIGQUERY_BRIDGE_KEY_FILE ?? '', 'utf8');
  } catch { throw new Error('BRIDGE_LIVE_PRIVATE_INPUT_INVALID'); }
  const { probeTableId, ...connectorConfig } = config;
  const pair = await generateKeyPair('RS256');
  const issuer = 'https://bridge-live-local.cloudflareaccess.com';
  const audience = 'c'.repeat(64);
  const assertion = await new SignJWT({}).setProtectedHeader({ alg: 'RS256', kid: 'local-only' })
    .setIssuer(issuer).setAudience(audience).setIssuedAt().setExpirationTime('5m').sign(pair.privateKey);
  const jwks = { keys: [{ ...await exportJWK(pair.publicKey), kid: 'local-only' }] };
  const env: Env = { CONNECTOR_PROVIDER: 'bigquery-mcp', CONNECTOR_CONFIG_JSON: JSON.stringify(connectorConfig),
    PUBLIC_ORIGIN: 'https://bridge.example.com', ACCESS_TEAM_DOMAIN: 'bridge-live-local.cloudflareaccess.com',
    ACCESS_AUD: audience, PROVIDER_TOKEN: secret };
  const steps: string[] = [];
  const fetcher: typeof globalThis.fetch = async (url, init) => {
    const endpoint = String(url);
    if (endpoint === `${issuer}/cdn-cgi/access/certs`) return Response.json(jwks);
    const stage = endpoint === GOOGLE_TOKEN_ENDPOINT ? 'google_token' : 'google_mcp';
    if (endpoint !== GOOGLE_TOKEN_ENDPOINT && endpoint !== 'https://bigquery.googleapis.com/mcp') {
      throw new Error('BRIDGE_LIVE_DESTINATION_REJECTED');
    }
    try {
      const response = await fetch(url, init);
      steps.push(`${stage}_http_${response.status}`);
      if (stage === 'google_mcp') steps.push(...await diagnose(response.clone()));
      return response;
    } catch {
      steps.push(`${stage}_network_failed`);
      throw new Error('BRIDGE_LIVE_NETWORK_FAILED');
    }
  };
  const dataset = config.allowedDatasets[0];
  if (dataset === undefined) throw new Error('BRIDGE_LIVE_PRIVATE_INPUT_INVALID');
  const probes: { name: string; arguments: Record<string, ConnectorJson> }[] = [
    { name: 'execute_sql_readonly', arguments: { projectId: config.queryProjectId, query: BIGQUERY_MCP_PROBE_QUERY } },
    { name: 'list_table_ids', arguments: { ...dataset, pageSize: 1 } },
  ];
  if (probeTableId !== undefined) probes.push({ name: 'get_table_info', arguments: { ...dataset, tableId: probeTableId } });
  for (const probe of probes) {
    const response = await handleRequest(new Request('https://bridge.example.com/mcp', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream',
        'MCP-Protocol-Version': '2025-06-18', 'Cf-Access-Jwt-Assertion': assertion },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: probe }),
    }), env, fetcher);
    const text = await response.text();
    let passed = false;
    try {
      const payload = response.headers.get('content-type')?.startsWith('text/event-stream')
        ? text.split(/\r?\n/u).find((line) => line.startsWith('data:'))?.slice(5).trim() ?? '' : text;
      const parsed = queryResponse.parse(JSON.parse(payload));
      passed = response.status === 200 && parsed.result.isError !== true;
      if (passed && probe.name === 'execute_sql_readonly') {
        const data = JSON.parse(parsed.result.content.map((item) => item.text).join('\n'));
        const direct = z.object({ rows: z.array(z.object({ bridge_ok: z.union([z.literal(1), z.literal('1')]) })).min(1) }).safeParse(data);
        const bigquery = z.object({
          schema: z.object({ fields: z.array(z.object({ name: z.string() })) }),
          rows: z.array(z.object({ f: z.array(z.object({ v: z.union([z.literal(1), z.literal('1')]) })) })).min(1),
        }).safeParse(data);
        passed = direct.success || (bigquery.success && bigquery.data.schema.fields.length === 1 && bigquery.data.schema.fields[0]?.name === 'bridge_ok');
      }
      if (passed && probe.name === 'list_table_ids' && probeTableId === undefined) {
        const data = JSON.parse(parsed.result.content.map((item) => item.text).join('\n'));
        const listed = z.object({ tables: z.array(z.object({ id: z.string() })) }).safeParse(data);
        const tableId = listed.success ? listed.data.tables[0]?.id.split('.').at(-1) : undefined;
        if (tableId !== undefined && /^[A-Za-z0-9_]{1,1024}$/u.test(tableId)) {
          probes.push({ name: 'get_table_info', arguments: { ...dataset, tableId } });
        }
      }
    } catch { passed = false; /* Never include private response content in diagnostics. */ }
    // Only stage names and HTTP statuses are emitted, including on failure.
    expect(passed, `${probe.name}: bridge_http_${response.status},${steps.join(',')}`).toBe(true);
    console.info(JSON.stringify({ probe: probe.name, passed: true }));
  }
});
