import { readFileSync } from 'node:fs';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { it } from 'vitest';
import { z } from 'zod';
import { handleRequest } from '../src/index';
import { GOOGLE_TOKEN_ENDPOINT } from '../src/google-auth';

// One operator-selected aggregate with a dry run, an excluded-read attempt,
// and harmless temporary-DDL rejection. Private provider content is never printed.
const enabled = process.env.ANKKA_BIGQUERY_QUERIES_LIVE === '1';
const inputSchema = z.object({
  queryProjectId: z.string(),
  allowedDatasets: z.array(z.object({ projectId: z.string(), datasetId: z.string() })).min(1),
  probeQuery: z.string().min(1).max(8_192),
  deniedQuery: z.string().min(1).max(8_192),
}).strict();
const envelope = z.object({ result: z.object({ isError: z.boolean().optional(),
  content: z.array(z.object({ type: z.literal('text'), text: z.string() })),
}) });
const queryResult = z.object({
  jobComplete: z.literal(true), totalBytesProcessed: z.string().regex(/^\d+$/u),
  rows: z.array(z.unknown()).max(20).optional(),
});

it.skipIf(!enabled)('qualifies useful hosted queries with a private read-only identity', async () => {
  try {
    const input = inputSchema.parse(JSON.parse(readFileSync(process.env.ANKKA_BIGQUERY_QUERIES_CONFIG_FILE ?? '', 'utf8')));
    const secret = readFileSync(process.env.ANKKA_BIGQUERY_BRIDGE_KEY_FILE ?? '', 'utf8');
    const pair = await generateKeyPair('RS256');
    const issuer = 'https://query-live-local.cloudflareaccess.com';
    const audience = 'd'.repeat(64);
    const assertion = await new SignJWT({}).setProtectedHeader({ alg: 'RS256', kid: 'local-only' })
      .setIssuer(issuer).setAudience(audience).setIssuedAt().setExpirationTime('5m').sign(pair.privateKey);
    const jwks = { keys: [{ ...await exportJWK(pair.publicKey), kid: 'local-only' }] };
    const env: Env = { CONNECTOR_PROVIDER: 'bigquery-mcp',
      CONNECTOR_CONFIG_JSON: JSON.stringify({ queryProjectId: input.queryProjectId, allowedDatasets: input.allowedDatasets, allowQueries: true }),
      PUBLIC_ORIGIN: 'https://bridge.example.com', ACCESS_TEAM_DOMAIN: 'query-live-local.cloudflareaccess.com',
      ACCESS_AUD: audience, PROVIDER_TOKEN: secret };
    const fetcher: typeof globalThis.fetch = async (url, init) => {
      if (String(url) === `${issuer}/cdn-cgi/access/certs`) return Response.json(jwks);
      if (String(url) !== GOOGLE_TOKEN_ENDPOINT && String(url) !== 'https://bigquery.googleapis.com/mcp') throw new Error();
      return fetch(url, init);
    };
    async function call(query: string, dryRun: boolean) {
      const response = await handleRequest(new Request('https://bridge.example.com/mcp', {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream',
          'MCP-Protocol-Version': '2025-06-18', 'Cf-Access-Jwt-Assertion': assertion },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {
          name: 'execute_sql_readonly', arguments: { projectId: input.queryProjectId, query, dryRun },
        } }),
      }), env, fetcher);
      const text = await response.text();
      const payload = response.headers.get('content-type')?.startsWith('text/event-stream')
        ? text.split(/\r?\n/u).find((line) => line.startsWith('data:'))?.slice(5).trim() ?? '' : text;
      if (response.status !== 200) throw new Error();
      return envelope.parse(JSON.parse(payload)).result;
    }
    const dry = await call(input.probeQuery, true);
    if (dry.isError) throw new Error();
    queryResult.parse(JSON.parse(dry.content.map((item) => item.text).join('\n')));
    console.info(JSON.stringify({ probe: 'allowed_dry_run', passed: true }));
    const denied = await call(input.deniedQuery, false);
    if (denied.isError !== true) throw new Error();
    console.info(JSON.stringify({ probe: 'excluded_query_rejected', passed: true }));
    // Even if Google regressed, this creates only an empty session-local table.
    const ddl = await call('CREATE TEMP TABLE ankka_readonly_probe AS SELECT 1 AS synthetic_value WHERE FALSE', false);
    if (ddl.isError !== true) throw new Error();
    console.info(JSON.stringify({ probe: 'temporary_ddl_rejected', passed: true }));
    const executed = await call(input.probeQuery, false);
    if (executed.isError) throw new Error();
    const result = queryResult.parse(JSON.parse(executed.content.map((item) => item.text).join('\n')));
    if (result.rows === undefined || result.rows.length === 0) throw new Error();
    console.info(JSON.stringify({ probe: 'aggregate', passed: true }));
  } catch { throw new Error('BIGQUERY_QUERIES_LIVE_FAILED'); }
});
