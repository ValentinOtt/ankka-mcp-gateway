import type { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { parseConfig, type ReadConnector, type ReadExecutor } from '../connector';
import { createGoogleAuthorization } from '../google-auth';
import type { ReadRequestPlan } from '../request';

// Existing deployments retain the connectivity-only query until explicitly enabled.
export const BIGQUERY_MCP_PROBE_QUERY = 'SELECT 1 AS bridge_ok';
export const BIGQUERY_MCP_QUERY_BYTES = 8_192;
const project = z.string().regex(/^[a-z][a-z0-9-]{4,61}[a-z0-9]$/u);
const dataset = z.string().regex(/^[A-Za-z0-9_]{1,1024}$/u);
const table = z.string().regex(/^[A-Za-z0-9_]{1,1024}$/u);
const configSchema = z.object({
  queryProjectId: project,
  allowedDatasets: z.array(z.object({ projectId: project, datasetId: dataset }).strict()).min(1).max(16),
  allowQueries: z.boolean().default(false),
}).strict();
const tableListInput = z.object({
  projectId: project, datasetId: dataset,
  pageSize: z.number().int().min(1).max(50).default(10),
  pageToken: z.string().min(1).max(2048).regex(/^[A-Za-z0-9._~+/-]+=*$/u).optional(),
}).strict();
const tableInfoInput = z.object({ projectId: project, datasetId: dataset, tableId: table }).strict();
const queryText = z.string().min(1).max(BIGQUERY_MCP_QUERY_BYTES)
  .refine((value) => value.trim().length > 0 && new TextEncoder().encode(value).byteLength <= BIGQUERY_MCP_QUERY_BYTES)
  .refine((value) => ![...value].some((character) => {
    const code = character.charCodeAt(0);
    return (code < 32 && code !== 9 && code !== 10 && code !== 13) || code === 127;
  }));
const queryInput = z.object({ projectId: project, query: queryText, dryRun: z.boolean().optional() }).strict();
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
const completedQuery = z.object({
  jobComplete: z.literal(true),
  errors: z.array(z.unknown()).length(0).optional(),
});

/** Fixed Google MCP endpoint; no caller-controlled URL, credential, or RPC method. */
export function createBigQueryMcpConnector(rawConfig: string, secret: string): ReadConnector {
  const config = parseConfig(rawConfig, configSchema);
  const googleAuthorization = createGoogleAuthorization(secret, 'bigquery');
  const authorize = async (fetcher: typeof globalThis.fetch) => ({
    ...await googleAuthorization(fetcher),
    Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-06-18',
  });
  const datasets = new Set(config.allowedDatasets.map(({ projectId, datasetId }) => `${projectId}/${datasetId}`));
  const configuredQueryInput = queryInput.extend({
    query: config.allowQueries ? queryText : z.literal(BIGQUERY_MCP_PROBE_QUERY),
  });

  function allowRequest(plan: ReadRequestPlan): boolean {
    if (plan.method !== 'POST' || plan.path !== '/mcp' || plan.query !== undefined) return false;
    const call = rpcCall.safeParse(plan.body);
    if (!call.success) return false;
    const params = call.data.params;
    if (params.name === 'execute_sql_readonly') {
      // SQL dataset access is enforced by the dedicated Google identity's IAM.
      // Parsing SQL here would not establish an authorization boundary.
      return params.arguments.projectId === config.queryProjectId
        && (config.allowQueries || params.arguments.query === BIGQUERY_MCP_PROBE_QUERY);
    }
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
        if (name === 'execute_sql_readonly') {
          // No job polling or retries: a pending job is not a completed read.
          const text = response.result.content.map((item) => item.text).join('\n');
          completedQuery.parse(JSON.parse(text));
        }
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
        config.allowQueries
          ? 'Run GoogleSQL through Google’s hosted read-only MCP tool in the configured query project. Google enforces read-only statements; the dedicated identity’s IAM controls dataset and routine access. Query text is limited to 8 KiB UTF-8. Set dryRun to true for an estimate without execution. Queries incur Google charges with no per-query byte ceiling. Use small aggregates; results are bounded and never paginated. A failed or timed-out response may leave a query running; do not retry automatically.'
          : 'Connectivity check: run only SELECT 1 AS bridge_ok in the configured query project. No table data is scanned.',
        configuredQueryInput);
    },
  };
}
