import type { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { parseConfig, type ReadConnector, type ReadExecutor } from '../connector';
import { createGoogleAuthorization } from '../google-auth';
import type { ReadRequestPlan } from '../request';

// This experiment proves authentication without enabling table-scanning SQL.
export const BIGQUERY_MCP_PROBE_QUERY = 'SELECT 1 AS bridge_ok';
const project = z.string().regex(/^[a-z][a-z0-9-]{4,61}[a-z0-9]$/u);
const dataset = z.string().regex(/^[A-Za-z0-9_]{1,1024}$/u);
const table = z.string().regex(/^[A-Za-z0-9_]{1,1024}$/u);
const configSchema = z.object({
  queryProjectId: project,
  allowedDatasets: z.array(z.object({ projectId: project, datasetId: dataset }).strict()).min(1).max(16),
}).strict();
const tableListInput = z.object({
  projectId: project, datasetId: dataset,
  pageSize: z.number().int().min(1).max(50).default(10),
  pageToken: z.string().min(1).max(2048).regex(/^[A-Za-z0-9._~+/-]+=*$/u).optional(),
}).strict();
const tableInfoInput = z.object({ projectId: project, datasetId: dataset, tableId: table }).strict();
const queryInput = z.object({ projectId: project, query: z.literal(BIGQUERY_MCP_PROBE_QUERY) }).strict();
const rpcCall = z.object({
  jsonrpc: z.literal('2.0'), id: z.literal(1), method: z.literal('tools/call'),
  params: z.discriminatedUnion('name', [
    z.object({ name: z.literal('list_table_ids'), arguments: tableListInput }).strict(),
    z.object({ name: z.literal('get_table_info'), arguments: tableInfoInput }).strict(),
    z.object({ name: z.literal('execute_sql_readonly'), arguments: queryInput }).strict(),
  ]),
}).strict();
// Only text tool content is exposed. Unknown transport/result forms fail closed.
const toolResponse = z.object({
  jsonrpc: z.literal('2.0'), id: z.literal(1),
  result: z.object({
    content: z.array(z.object({ type: z.literal('text'), text: z.string() }).strict()).min(1).max(16),
    isError: z.boolean().optional(),
  }),
}).strict();

/** Fixed Google MCP endpoint; no caller-controlled URL, credential, or RPC method. */
export function createBigQueryMcpConnector(rawConfig: string, secret: string): ReadConnector {
  const config = parseConfig(rawConfig, configSchema);
  const googleAuthorization = createGoogleAuthorization(secret, 'bigquery');
  const authorize = async (fetcher: typeof globalThis.fetch) => ({
    ...await googleAuthorization(fetcher),
    Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-06-18',
  });
  const datasets = new Set(config.allowedDatasets.map(({ projectId, datasetId }) => `${projectId}/${datasetId}`));

  function allowRequest(plan: ReadRequestPlan): boolean {
    if (plan.method !== 'POST' || plan.path !== '/mcp' || plan.query !== undefined) return false;
    const call = rpcCall.safeParse(plan.body);
    if (!call.success) return false;
    const params = call.data.params;
    if (params.name === 'execute_sql_readonly') return params.arguments.projectId === config.queryProjectId;
    return datasets.has(`${params.arguments.projectId}/${params.arguments.datasetId}`);
  }

  // oxlint-disable-next-line anti-slop/no-shape-in-symbol-names -- ZodRawShape is the SDK schema generic.
  function register<T extends z.ZodRawShape>(
    server: McpServer, execute: ReadExecutor, name: 'list_table_ids' | 'get_table_info' | 'execute_sql_readonly',
    description: string, inputSchema: z.ZodObject<T>,
  ): void {
    server.registerTool(name, {
      description, inputSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    }, async (input) => {
      try {
        const plan: ReadRequestPlan = {
          method: 'POST', path: '/mcp',
          body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: input } },
        };
        if (!allowRequest(plan)) throw new Error('CONNECTOR_REQUEST_NOT_ALLOWED');
        const response = toolResponse.parse(await execute(plan));
        if (response.result.isError === true) throw new Error('CONNECTOR_READ_FAILED');
        // Successful provider content remains untrusted data; links are never followed.
        return { content: response.result.content };
      } catch {
        // Never return provider errors, transport exceptions, or credentials.
        return { isError: true, content: [{ type: 'text', text: 'CONNECTOR_READ_FAILED' }] };
      }
    });
  }

  return {
    id: 'bigquery-mcp', origin: 'https://bigquery.googleapis.com', headers: {}, authorize, allowRequest,
    registerTools(server, execute) {
      register(server, execute, 'list_table_ids',
        'Ask Google’s hosted MCP for one page of tables in a configured dataset. No automatic pagination.', tableListInput);
      register(server, execute, 'get_table_info',
        'Ask Google’s hosted MCP for metadata of one table in a configured dataset.', tableInfoInput);
      register(server, execute, 'execute_sql_readonly',
        'Authentication experiment: run only SELECT 1 AS bridge_ok in the configured query project. No table data is scanned.', queryInput);
    },
  };
}
