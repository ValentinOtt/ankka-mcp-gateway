import type { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { parseConfig, registerReadTool, type ReadConnector, type ReadExecutor } from '../connector';
import { createGoogleAuthorization } from '../google-auth';
import type { ConnectorJson, ReadRequestPlan } from '../request';

export const BIGQUERY_LIMITS = {
  projects: 4, datasets: 16, pageSize: 50, queryBytes: 8_192, rows: 200,
  labels: 4, timeoutMs: 6_500, maximumBytesBilled: 1_099_511_627_776,
} as const;

// Tool names and camelCase argument names mirror Google's hosted BigQuery MCP
// read tools so a future move to the native server does not retrain clients.
// The write-capable execute_sql tool is intentionally never implemented.
const project = z.string().regex(/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/u);
const dataset = z.string().regex(/^[A-Za-z0-9_]{1,1024}$/u);
// Partition decorators and wildcard suffixes are not valid table arguments.
const table = z.string().regex(/^[A-Za-z0-9_]{1,1024}$/u);
const pageToken = z.string().regex(/^[A-Za-z0-9._=+/-]{1,512}$/u);
const pageSizeText = z.string().regex(/^(?:[1-9]|[1-4][0-9]|50)$/u);
const int64Text = z.string().regex(/^(?:0|[1-9][0-9]{0,19})$/u);
const boundedText = (length: number) => z.string().max(length);
const fieldName = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,299}$/u);
const budgetText = int64Text.refine((value) =>
  BigInt(value) >= 1n && BigInt(value) <= BigInt(BIGQUERY_LIMITS.maximumBytesBilled));
const configSchema = z.object({
  allowedProjectIds: z.array(project).min(1).max(BIGQUERY_LIMITS.projects)
    .refine((values) => new Set(values).size === values.length),
  allowedDatasetIds: z.array(dataset).min(1).max(BIGQUERY_LIMITS.datasets)
    .refine((values) => new Set(values).size === values.length),
  maximumBytesBilled: budgetText,
}).strict();
const queryText = z.string().min(1).max(BIGQUERY_LIMITS.queryBytes)
  .refine((value) => ![...value].some((character) => {
    const code = character.charCodeAt(0);
    return (code < 32 && code !== 9 && code !== 10 && code !== 13) || code === 127;
  }));
const labelRecord = z.record(
  z.string().regex(/^[a-z][a-z0-9_-]{0,62}$/u),
  z.string().regex(/^[a-z0-9_-]{0,63}$/u),
).refine((value) => Object.keys(value).length >= 1 && Object.keys(value).length <= BIGQUERY_LIMITS.labels);

const getPlan = z.object({ method: z.literal('GET'), path: z.string() }).strict();
const listPlan = z.object({
  method: z.literal('GET'), path: z.string(),
  query: z.object({ maxResults: pageSizeText, pageToken: pageToken.optional() }).strict(),
}).strict();
const dryRunBody = z.object({
  query: queryText, useLegacySql: z.literal(false), dryRun: z.literal(true),
  labels: labelRecord.optional(),
}).strict();

// Bounded nested TableFieldSchema: the GA4 export nests event_params and
// items item_params records four levels deep; one spare level is allowed.
const leafField = z.object({
  name: fieldName, type: boundedText(64),
  mode: boundedText(16).optional(), description: boundedText(1_024).optional(),
});
type ParsedField = {
  name: string; type: string;
  mode?: string | undefined; description?: string | undefined;
  fields?: ParsedField[] | undefined;
};
let nestedField: z.ZodType<ParsedField> = leafField;
for (let level = 0; level < 4; level += 1) {
  nestedField = leafField.extend({ fields: z.array(nestedField).max(200).optional() });
}
const tableSchema = z.object({ fields: z.array(nestedField).max(200).default([]) });

// REST result cells encode scalars as strings; records and repeated values
// nest as f/v wrappers. Depth stays bounded and unknown shapes fail closed.
let cellValue: z.ZodType<ConnectorJson> = z.union([boundedText(4_096), z.null()]);
for (let level = 0; level < 5; level += 1) {
  cellValue = z.union([
    boundedText(4_096), z.null(),
    z.array(z.object({ v: cellValue })).max(BIGQUERY_LIMITS.rows),
    z.object({ f: z.array(z.object({ v: cellValue })).max(200) }),
  ]);
}
const resultRow = z.object({ f: z.array(z.object({ v: cellValue })).max(200) });

const datasetsListResponse = z.object({
  datasets: z.array(z.object({
    datasetReference: z.object({ projectId: project, datasetId: dataset }),
  })).max(BIGQUERY_LIMITS.pageSize).default([]),
  nextPageToken: pageToken.optional(),
});
const datasetResponse = z.object({
  datasetReference: z.object({ projectId: project, datasetId: dataset }),
  type: boundedText(64).optional(), location: boundedText(64).optional(),
  description: boundedText(2_048).optional(),
  creationTime: int64Text.optional(), lastModifiedTime: int64Text.optional(),
  defaultPartitionExpirationMs: int64Text.optional(),
});
const tablesListResponse = z.object({
  tables: z.array(z.object({
    tableReference: z.object({ projectId: project, datasetId: dataset, tableId: table }),
    type: boundedText(64).optional(),
  })).max(BIGQUERY_LIMITS.pageSize).default([]),
  totalItems: z.number().int().nonnegative().optional(),
  nextPageToken: pageToken.optional(),
});
const tableResponse = z.object({
  tableReference: z.object({ projectId: project, datasetId: dataset, tableId: table }),
  type: boundedText(64).optional(), description: boundedText(2_048).optional(),
  schema: tableSchema.optional(),
  numRows: int64Text.optional(), numBytes: int64Text.optional(),
  creationTime: int64Text.optional(), lastModifiedTime: int64Text.optional(),
  requirePartitionFilter: z.boolean().optional(),
  timePartitioning: z.object({
    type: boundedText(16), field: fieldName.optional(), expirationMs: int64Text.optional(),
  }).optional(),
});
const dryRunResponse = z.object({
  jobComplete: z.literal(true), statementType: boundedText(64),
  totalBytesProcessed: int64Text, schema: tableSchema.optional(),
  cacheHit: z.boolean().optional(),
  // Forbidden result keys: any present JSON value fails these markers closed.
  rows: z.undefined().optional(), errors: z.undefined().optional(),
  numDmlAffectedRows: z.undefined().optional(),
});
const executeResponse = z.object({
  jobComplete: z.literal(true), statementType: boundedText(64).optional(),
  schema: tableSchema, rows: z.array(resultRow).max(BIGQUERY_LIMITS.rows).default([]),
  totalRows: int64Text, totalBytesProcessed: int64Text.optional(),
  totalBytesBilled: int64Text.optional(), cacheHit: z.boolean().optional(),
  pageToken: pageToken.optional(),
  errors: z.undefined().optional(), numDmlAffectedRows: z.undefined().optional(),
});

type ProjectedField = {
  name: string;
  type: string;
  mode: string | null;
  description: string | null;
  fields: ProjectedField[];
};
function projectFields(fields: readonly ParsedField[]): ProjectedField[] {
  return fields.map((field) => ({
    name: field.name, type: field.type,
    mode: field.mode ?? null, description: field.description ?? null,
    fields: projectFields(field.fields ?? []),
  }));
}
function projectSchema(value: z.output<typeof tableSchema> | undefined) {
  return { fields: projectFields(value?.fields ?? []) };
}

export function createBigQueryConnector(rawConfig: string, rawSecret: string): ReadConnector {
  const config = parseConfig(rawConfig, configSchema);
  const projects = new Set(config.allowedProjectIds);
  const datasets = new Set(config.allowedDatasetIds);
  const authorize = createGoogleAuthorization(rawSecret, 'bigquery');
  const executeBody = z.object({
    query: queryText, useLegacySql: z.literal(false),
    maximumBytesBilled: z.literal(config.maximumBytesBilled),
    maxResults: z.literal(BIGQUERY_LIMITS.rows), timeoutMs: z.literal(BIGQUERY_LIMITS.timeoutMs),
    jobCreationMode: z.literal('JOB_CREATION_OPTIONAL'), useQueryCache: z.literal(true),
    labels: labelRecord.optional(),
  }).strict();
  const dryPlanSchema = z.object({ method: z.literal('POST'), path: z.string(), body: dryRunBody }).strict();
  const executePlanSchema = z.object({ method: z.literal('POST'), path: z.string(), body: executeBody }).strict();

  function allowRequest(plan: ReadRequestPlan): boolean {
    const matched = /^\/bigquery\/v2\/projects\/([a-z][a-z0-9-]{4,28}[a-z0-9])(?:\/(queries|datasets)(?:\/([A-Za-z0-9_]{1,1024})(?:\/(tables)(?:\/([A-Za-z0-9_]{1,1024}))?)?)?)?$/u
      .exec(plan.path);
    const [, projectId, resource, datasetId, tables, tableId] = matched ?? [];
    if (projectId === undefined || resource === undefined || !projects.has(projectId)) return false;
    if (resource === 'queries') {
      if (datasetId !== undefined) return false;
      return dryPlanSchema.safeParse(plan).success || executePlanSchema.safeParse(plan).success;
    }
    if (datasetId === undefined) return listPlan.safeParse(plan).success;
    if (!datasets.has(datasetId)) return false;
    if (tables === undefined) return getPlan.safeParse(plan).success;
    if (tableId === undefined) return listPlan.safeParse(plan).success;
    return getPlan.safeParse(plan).success;
  }

  function assertReadWithinBudget(statementType: string, totalBytesProcessed: string): void {
    if (statementType !== 'SELECT') throw new Error('CONNECTOR_QUERY_NOT_READ_ONLY');
    if (BigInt(totalBytesProcessed) > BigInt(config.maximumBytesBilled)) {
      throw new Error('CONNECTOR_QUERY_BUDGET_EXCEEDED');
    }
  }

  function registerReadOnlySql(server: McpServer, execute: ReadExecutor): void {
    server.registerTool('execute_sql_readonly', {
      description: `Run one bounded GoogleSQL SELECT statement in a configured project. Every call dry-runs first: non-SELECT statement types and estimated scans above the configured maximumBytesBilled are refused before execution, and execution enforces that budget, a ${BIGQUERY_LIMITS.timeoutMs} ms timeout, and at most ${BIGQUERY_LIMITS.rows} returned rows without pagination. Table access comes from the deployment identity's read-only IAM, not from this tool. Set dryRun to true to review the statement type and byte estimate without running.`,
      inputSchema: z.object({
        projectId: project, query: queryText,
        dryRun: z.boolean().default(false), labels: labelRecord.optional(),
      }).strict(),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    }, async (input) => {
      try {
        if (!projects.has(input.projectId)) throw new Error('CONNECTOR_REQUEST_NOT_ALLOWED');
        const path = `/bigquery/v2/projects/${input.projectId}/queries`;
        const labels = input.labels === undefined ? {} : { labels: input.labels };
        const dryPlan: ReadRequestPlan = {
          method: 'POST', path,
          body: { query: input.query, useLegacySql: false, dryRun: true, ...labels },
        };
        if (!allowRequest(dryPlan)) throw new Error('CONNECTOR_REQUEST_NOT_ALLOWED');
        const estimate = dryRunResponse.parse(await execute(dryPlan));
        assertReadWithinBudget(estimate.statementType, estimate.totalBytesProcessed);
        if (input.dryRun) {
          return { content: [{ type: 'text', text: JSON.stringify({
            dryRun: true, statementType: estimate.statementType,
            totalBytesProcessed: estimate.totalBytesProcessed,
            maximumBytesBilled: config.maximumBytesBilled,
            schema: projectSchema(estimate.schema),
          }) }] };
        }
        const executePlan: ReadRequestPlan = {
          method: 'POST', path,
          body: {
            query: input.query, useLegacySql: false,
            maximumBytesBilled: config.maximumBytesBilled,
            maxResults: BIGQUERY_LIMITS.rows, timeoutMs: BIGQUERY_LIMITS.timeoutMs,
            jobCreationMode: 'JOB_CREATION_OPTIONAL', useQueryCache: true, ...labels,
          },
        };
        if (!allowRequest(executePlan)) throw new Error('CONNECTOR_REQUEST_NOT_ALLOWED');
        const result = executeResponse.parse(await execute(executePlan));
        if (result.statementType !== undefined && result.statementType !== 'SELECT') {
          throw new Error('CONNECTOR_QUERY_NOT_READ_ONLY');
        }
        return { content: [{ type: 'text', text: JSON.stringify({
          dryRun: false, statementType: 'SELECT', schema: projectSchema(result.schema),
          rows: result.rows, rowCount: result.rows.length, totalRows: result.totalRows,
          rowsTruncated: result.pageToken !== undefined || BigInt(result.totalRows) > BigInt(result.rows.length),
          totalBytesProcessed: result.totalBytesProcessed ?? null,
          totalBytesBilled: result.totalBytesBilled ?? null,
          cacheHit: result.cacheHit ?? null,
          maximumBytesBilled: config.maximumBytesBilled,
        }) }] };
      } catch (error) {
        // Provider bodies, SQL, byte counts, and exceptions are never reflected.
        const code = error instanceof Error &&
          ['CONNECTOR_QUERY_NOT_READ_ONLY', 'CONNECTOR_QUERY_BUDGET_EXCEEDED'].includes(error.message)
          ? error.message
          : 'CONNECTOR_READ_FAILED';
        return { isError: true, content: [{ type: 'text', text: code }] };
      }
    });
  }

  return {
    id: 'bigquery', origin: 'https://bigquery.googleapis.com', headers: {}, authorize, allowRequest,
    registerTools(server, execute) {
      const projected: ReadExecutor = async (plan) => {
        if (!allowRequest(plan)) throw new Error('CONNECTOR_REQUEST_NOT_ALLOWED');
        const value = await execute(plan);
        if (plan.path.endsWith('/datasets')) {
          const listed = datasetsListResponse.parse(value);
          return {
            datasetIds: listed.datasets
              .map((entry) => entry.datasetReference.datasetId)
              .filter((id) => datasets.has(id)),
            nextPageToken: listed.nextPageToken ?? null,
          };
        }
        if (plan.path.endsWith('/tables')) {
          const listed = tablesListResponse.parse(value);
          return {
            tableIds: listed.tables.map((entry) => entry.tableReference.tableId),
            totalTables: listed.totalItems ?? null,
            nextPageToken: listed.nextPageToken ?? null,
          };
        }
        if (/\/tables\/[A-Za-z0-9_]{1,1024}$/u.test(plan.path)) {
          const info = tableResponse.parse(value);
          return {
            tableReference: info.tableReference, type: info.type ?? null,
            description: info.description ?? null, schema: projectSchema(info.schema),
            numRows: info.numRows ?? null, numBytes: info.numBytes ?? null,
            creationTime: info.creationTime ?? null, lastModifiedTime: info.lastModifiedTime ?? null,
            requirePartitionFilter: info.requirePartitionFilter ?? null,
            timePartitioning: info.timePartitioning === undefined ? null : {
              type: info.timePartitioning.type,
              field: info.timePartitioning.field ?? null,
              expirationMs: info.timePartitioning.expirationMs ?? null,
            },
          };
        }
        const info = datasetResponse.parse(value);
        return {
          datasetReference: info.datasetReference, type: info.type ?? null,
          location: info.location ?? null, description: info.description ?? null,
          creationTime: info.creationTime ?? null, lastModifiedTime: info.lastModifiedTime ?? null,
          defaultPartitionExpirationMs: info.defaultPartitionExpirationMs ?? null,
        };
      };
      const page = { pageSize: z.number().int().min(1).max(BIGQUERY_LIMITS.pageSize).default(BIGQUERY_LIMITS.pageSize), pageToken: pageToken.optional() };
      const withToken = (token: string | undefined) => token === undefined ? {} : { pageToken: token };
      registerReadTool(server, projected, 'list_dataset_ids',
        'List configured-and-visible dataset ids in an approved project, one bounded page at a time. Datasets outside the deployment allowlist are omitted, so a page may be empty while nextPageToken continues.',
        z.object({ projectId: project, ...page }).strict(),
        ({ projectId, pageSize, pageToken: token }) => ({
          method: 'GET', path: `/bigquery/v2/projects/${projectId}/datasets`,
          query: { maxResults: String(pageSize), ...withToken(token) },
        }));
      registerReadTool(server, projected, 'get_dataset_info',
        'Read location, type, and timestamps for one approved dataset. Access rules and labels are not exposed.',
        z.object({ projectId: project, datasetId: dataset }).strict(),
        ({ projectId, datasetId }) => ({
          method: 'GET', path: `/bigquery/v2/projects/${projectId}/datasets/${datasetId}`,
        }));
      registerReadTool(server, projected, 'list_table_ids',
        'List table ids in one approved dataset, one bounded page at a time; daily export tables appear as dated ids. No automatic pagination.',
        z.object({ projectId: project, datasetId: dataset, ...page }).strict(),
        ({ projectId, datasetId, pageSize, pageToken: token }) => ({
          method: 'GET', path: `/bigquery/v2/projects/${projectId}/datasets/${datasetId}/tables`,
          query: { maxResults: String(pageSize), ...withToken(token) },
        }));
      registerReadTool(server, projected, 'get_table_info',
        'Read one approved table’s bounded schema, row and byte counts, and partitioning metadata. Partition decorators are not accepted.',
        z.object({ projectId: project, datasetId: dataset, tableId: table }).strict(),
        ({ projectId, datasetId, tableId }) => ({
          method: 'GET', path: `/bigquery/v2/projects/${projectId}/datasets/${datasetId}/tables/${tableId}`,
        }));
      registerReadOnlySql(server, execute);
    },
  };
}
