import { z } from 'zod';
import { executeReadRequest, type ConnectorJson } from '../src/request';

const reviewedNames = ['list_table_ids', 'get_table_info', 'execute_sql_readonly'] as const;
const reviewedFields = ['projectId', 'query', 'dryRun', 'labels', 'maximumBytesBilled',
  'timeoutMs', 'jobTimeoutMs', 'maxResults', 'location'] as const;
const discovery = z.object({
  jsonrpc: z.literal('2.0'), id: z.literal(1),
  error: z.undefined().optional(),
  result: z.object({
    // An incomplete catalogue is not evidence that a control is absent.
    nextCursor: z.undefined().optional(),
    tools: z.array(z.object({
      name: z.string().min(1).max(256),
      inputSchema: z.object({
        type: z.literal('object'),
        properties: z.record(z.string(), z.unknown()),
      }),
    })).min(1).max(128),
  }),
});

/** Report advertised fields only. Presence is not proof that Google enforces a control. */
export function summarizeBigQueryMcpCapabilities(value: ConnectorJson) {
  const parsed = discovery.safeParse(value);
  if (!parsed.success) throw new Error('BIGQUERY_MCP_DISCOVERY_INVALID');
  const tools = parsed.data.result.tools;
  if (new Set(tools.map((tool) => tool.name)).size !== tools.length
    || !reviewedNames.every((name) => tools.some((tool) => tool.name === name))) {
    throw new Error('BIGQUERY_MCP_DISCOVERY_INVALID');
  }
  const sql = tools.find((tool) => tool.name === 'execute_sql_readonly');
  if (sql === undefined) throw new Error('BIGQUERY_MCP_DISCOVERY_INVALID');
  // Fixed keys/booleans only: never emit upstream descriptions, schemas, or errors.
  return {
    reviewedToolsPresent: true,
    advertisedSqlFields: Object.fromEntries(reviewedFields.map((field) =>
      [field, Object.hasOwn(sql.inputSchema.properties, field)])),
  };
}

/** Google currently permits public discovery. Never mint a token or fall back to credentials. */
export async function probeBigQueryMcpCapabilities(fetcher: typeof globalThis.fetch) {
  try {
    const result = await executeReadRequest({
      origin: 'https://bigquery.googleapis.com',
      plan: { method: 'POST', path: '/mcp', body: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} } },
      headers: { Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-06-18' },
      allowRequest: (plan) => plan.method === 'POST' && plan.path === '/mcp' && plan.query === undefined
        && JSON.stringify(plan.body) === JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
      fetch: fetcher,
    });
    return summarizeBigQueryMcpCapabilities(result);
  } catch {
    throw new Error('BIGQUERY_MCP_DISCOVERY_FAILED');
  }
}
