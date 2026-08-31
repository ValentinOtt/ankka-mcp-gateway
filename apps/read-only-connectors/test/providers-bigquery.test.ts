import { CLIENT_CAPABILITIES_META_KEY, CLIENT_INFO_META_KEY, createMcpHandler, McpServer, PROTOCOL_VERSION_META_KEY } from '@modelcontextprotocol/server';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import type { ReadConnector, ReadExecutor } from '../src/connector';
import type { ConnectorJson, ReadRequestPlan } from '../src/request';
import { createBigQueryConnector } from '../src/providers/bigquery';

const projectId = 'synthetic-project';
const datasetId = 'analytics_123456';
const budget = '104857600';
const location = 'europe-north1';
const jobUuid = '00000000-0000-4000-8000-000000000001';
const configured = { allowedProjectIds: [projectId], allowedDatasetIds: [datasetId], maximumBytesBilled: budget, location };
const config = JSON.stringify(configured);
// Deliberately not signing material; these tests never mint tokens or call Google.
const secret = JSON.stringify({
  type: 'service_account', project_id: projectId, private_key_id: 'a'.repeat(40),
  private_key: 'synthetic-placeholder-not-a-private-key',
  client_email: `synthetic-reader@${projectId}.iam.gserviceaccount.com`,
  token_uri: 'https://oauth2.googleapis.com/token',
});
type ToolArguments = Readonly<Record<string, ConnectorJson>>;
// Tool JSON is nested inside the JSON-RPC envelope, so quotes arrive escaped.
const embedded = (fragment: string) => JSON.stringify(fragment).slice(1, -1);
const isDryRunPlan = (plan: ReadRequestPlan) =>
  z.object({ configuration: z.object({ dryRun: z.literal(true) }) }).safeParse(plan.body).success;

const base = `/bigquery/v2/projects/${projectId}`;
const queriesPath = `${base}/queries`;
const jobsPath = `${base}/jobs`;
function listDatasetsPlan(query: Record<string, string> = { maxResults: '50' }): ReadRequestPlan {
  return { method: 'GET', path: `${base}/datasets`, query };
}
function listTablesPlan(query: Record<string, string> = { maxResults: '50' }): ReadRequestPlan {
  return { method: 'GET', path: `${base}/datasets/${datasetId}/tables`, query };
}
const getDatasetPlan: ReadRequestPlan = { method: 'GET', path: `${base}/datasets/${datasetId}` };
const getTablePlan: ReadRequestPlan = { method: 'GET', path: `${base}/datasets/${datasetId}/tables/events_20260830` };
function dryPlan(query = 'SELECT event_name FROM events', overrides: Record<string, ConnectorJson> = {}): ReadRequestPlan {
  return { method: 'POST', path: jobsPath, body: {
    jobReference: { projectId, jobId: `ankka_dry_run_${jobUuid}`, location },
    configuration: { dryRun: true, query: { query, useLegacySql: false }, ...overrides },
  } };
}
function executePlan(overrides: Record<string, ConnectorJson> = {}): ReadRequestPlan {
  return { method: 'POST', path: queriesPath, body: {
    query: 'SELECT event_name FROM events', useLegacySql: false, location,
    maximumBytesBilled: budget, maxResults: 200, timeoutMs: 6_500,
    jobCreationMode: 'JOB_CREATION_OPTIONAL', useQueryCache: true, ...overrides,
  } };
}
const exportSchema = {
  fields: [
    { name: 'event_name', type: 'STRING', mode: 'NULLABLE' },
    { name: 'event_params', type: 'RECORD', mode: 'REPEATED', fields: [
      { name: 'key', type: 'STRING', mode: 'NULLABLE' },
      { name: 'value', type: 'RECORD', mode: 'NULLABLE', fields: [
        { name: 'string_value', type: 'STRING', mode: 'NULLABLE' },
      ] },
    ] },
  ],
};
const dryResult = {
  statistics: { query: { statementType: 'SELECT', totalBytesProcessed: '1024', schema: exportSchema } },
};
const executeResult = {
  jobComplete: true, schema: exportSchema,
  rows: [{ f: [{ v: 'page_view' }, { v: [{ v: { f: [{ v: 'engaged' }, { v: { f: [{ v: 'true' }] } }] } }] }] }],
  totalRows: '1', totalBytesProcessed: '1024', totalBytesBilled: '10485760', cacheHit: false,
};

async function callTool(connector: ReadConnector, name: string, args: ToolArguments, execute: ReadExecutor) {
  const randomUuid = vi.spyOn(crypto, 'randomUUID').mockReturnValue(jobUuid);
  const handler = createMcpHandler(() => {
    const server = new McpServer({ name: 'synthetic-bigquery-test', version: '1.0.0' });
    connector.registerTools(server, execute);
    return server;
  });
  try {
    const response = await handler.fetch(new Request('https://connector.example.com/mcp', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json', Accept: 'application/json, text/event-stream',
        'MCP-Protocol-Version': '2026-07-28', 'MCP-Method': 'tools/call', 'MCP-Name': name,
      },
      body: JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: { name, arguments: args, _meta: {
          [PROTOCOL_VERSION_META_KEY]: '2026-07-28', [CLIENT_CAPABILITIES_META_KEY]: {},
          [CLIENT_INFO_META_KEY]: { name: 'synthetic-bigquery-test', version: '1.0.0' },
        } },
      }),
    }));
    return await response.text();
  } finally {
    randomUuid.mockRestore();
    await handler.close();
  }
}

describe('BigQuery read plans', () => {
  const connector = createBigQueryConnector(config, secret);
  it('pins the BigQuery origin and defers authorization to the shared Google boundary', () => {
    expect(connector.id).toBe('bigquery');
    expect(connector.origin).toBe('https://bigquery.googleapis.com');
    expect(connector.headers).toEqual({});
    expect(connector.authorize).toBeTypeOf('function');
  });
  it.each([
    listDatasetsPlan(), listDatasetsPlan({ maxResults: '1', pageToken: 'synthetic-token=' }),
    getDatasetPlan, listTablesPlan(), getTablePlan, dryPlan(), executePlan(),
  ])('allows the exact authored plan %j', (plan) => expect(connector.allowRequest(plan)).toBe(true));
  it.each<ReadRequestPlan>([
    { ...listDatasetsPlan(), method: 'POST' },
    { method: 'GET', path: '/bigquery/v2/projects/other-project/datasets', query: { maxResults: '50' } },
    { method: 'GET', path: `${base}/datasets/other_dataset` },
    { method: 'GET', path: `${base}/datasets/${datasetId}/tables/events$20260830` },
    { method: 'GET', path: `${base}/datasets/${datasetId}/tables/events_20260830/data` },
    { method: 'GET', path: `${base}/jobs` },
    { method: 'GET', path: `${base}/datasets` },
    listDatasetsPlan({ maxResults: '0' }),
    listDatasetsPlan({ maxResults: '51' }),
    listDatasetsPlan({ maxResults: '50', all: 'true' }),
    { ...getDatasetPlan, query: { fields: 'access' } },
    { method: 'POST', path: `${base}/datasets/${datasetId}/queries`, body: dryPlan().body },
    { method: 'POST', path: queriesPath, body: { query: 'SELECT 1', useLegacySql: false } },
    { method: 'POST', path: queriesPath, body: { query: 'SELECT 1', useLegacySql: true, dryRun: true } },
    { method: 'POST', path: queriesPath, body: { query: 'SELECT 1', useLegacySql: false, dryRun: true, destinationTable: {} } },
    executePlan({ maximumBytesBilled: '999999999999999' }),
    executePlan({ maxResults: 3_000 }),
    executePlan({ timeoutMs: 60_000 }),
    executePlan({ jobCreationMode: 'JOB_CREATION_REQUIRED' }),
    executePlan({ createSession: true }),
    executePlan({ defaultDataset: { datasetId } }),
    executePlan({ labels: { 'Invalid-Key': 'x' } }),
    executePlan({ location: 'US' }),
    { method: 'POST', path: queriesPath, body: dryPlan().body },
    { ...executePlan(), path: jobsPath },
    dryPlan('SELECT 1', { dryRun: false }),
    dryPlan('SELECT 1', { query: { query: 'SELECT 1', useLegacySql: true } }),
    dryPlan('SELECT 1', { query: { query: 'SELECT 1', useLegacySql: false, destinationTable: {} } }),
    dryPlan('SELECT 1', { load: {} }),
    { method: 'POST', path: jobsPath, body: {
      jobReference: { projectId: 'other-project', jobId: `ankka_dry_run_${jobUuid}`, location },
      configuration: { dryRun: true, query: { query: 'SELECT 1', useLegacySql: false } },
    } },
    { method: 'POST', path: jobsPath, body: {
      jobReference: { projectId, jobId: `ankka_dry_run_${jobUuid}`, location: 'US' },
      configuration: { dryRun: true, query: { query: 'SELECT 1', useLegacySql: false } },
    } },
  ])('denies project, dataset, operation, and query widening %j', (plan) => {
    expect(connector.allowRequest(plan)).toBe(false);
  });
});

describe('BigQuery tools and response projection', () => {
  const connector = createBigQueryConnector(config, secret);
  it('lists only configured dataset ids from a wider provider listing', async () => {
    const execute = vi.fn<ReadExecutor>(async (plan) => {
      expect(plan).toEqual(listDatasetsPlan());
      return { datasets: [
        { datasetReference: { projectId, datasetId }, location: 'EU' },
        { datasetReference: { projectId, datasetId: 'private_dataset' } },
      ], nextPageToken: 'synthetic-token=' };
    });
    const response = await callTool(connector, 'list_dataset_ids', { projectId }, execute);
    expect(response).toContain(datasetId);
    expect(response).not.toContain('private_dataset');
    expect(response).toContain('synthetic-token=');
    expect(execute).toHaveBeenCalledOnce();
  });
  it('projects table metadata and the bounded nested export schema', async () => {
    const execute = vi.fn<ReadExecutor>(async (plan) => {
      expect(plan).toEqual(getTablePlan);
      return {
        tableReference: { projectId, datasetId, tableId: 'events_20260830' },
        type: 'TABLE', schema: exportSchema, numRows: '1200', numBytes: '4096',
        creationTime: '1767139200000', lastModifiedTime: '1767139200000',
        selfLink: 'https://not-approved.example.com', labels: { private: 'not-approved' },
      };
    });
    const response = await callTool(connector, 'get_table_info',
      { projectId, datasetId, tableId: 'events_20260830' }, execute);
    expect(response).toContain('string_value');
    expect(response).toContain(embedded('"numRows":"1200"'));
    expect(response).not.toContain('not-approved');
  });
  it('dry-runs first, enforces the budget, then executes one bounded SELECT', async () => {
    const execute = vi.fn<ReadExecutor>(async (plan) =>
      isDryRunPlan(plan) ? dryResult : executeResult);
    const response = await callTool(connector, 'execute_sql_readonly',
      { projectId, query: 'SELECT event_name FROM events' }, execute);
    expect(execute).toHaveBeenCalledTimes(2);
    expect(execute.mock.calls[0]?.[0]).toEqual(dryPlan());
    expect(execute.mock.calls[1]?.[0]).toEqual(executePlan());
    expect(response).toContain('page_view');
    expect(response).toContain('engaged');
    expect(response).toContain(embedded(`"maximumBytesBilled":"${budget}"`));
    expect(response).toContain(embedded('"rowsTruncated":false'));
  });
  it('returns the dry-run estimate without executing when dryRun is requested', async () => {
    const execute = vi.fn<ReadExecutor>(async () => dryResult);
    const response = await callTool(connector, 'execute_sql_readonly',
      { projectId, query: 'SELECT event_name FROM events', dryRun: true }, execute);
    expect(execute).toHaveBeenCalledOnce();
    expect(response).toContain(embedded('"dryRun":true'));
    expect(response).toContain(embedded('"totalBytesProcessed":"1024"'));
  });
  it('marks truncation when the provider reports more rows than returned', async () => {
    const execute = vi.fn<ReadExecutor>(async (plan) =>
      isDryRunPlan(plan)
        ? dryResult
        : { ...executeResult, totalRows: '5000', pageToken: 'synthetic-token=' });
    const response = await callTool(connector, 'execute_sql_readonly',
      { projectId, query: 'SELECT event_name FROM events' }, execute);
    expect(response).toContain(embedded('"rowsTruncated":true'));
    expect(response).not.toContain('synthetic-token=');
  });
  it.each(['DELETE', 'UPDATE', 'INSERT', 'MERGE', 'CREATE_TABLE', 'SCRIPT', 'CALL', 'EXPORT_DATA', 'CREATE_FUNCTION', 'DROP_TABLE', 'select'])('refuses Google classification %s before execution', async (statementType) => {
    const execute = vi.fn<ReadExecutor>(async () => ({ statistics: { query: { ...dryResult.statistics.query, statementType } } }));
    const response = await callTool(connector, 'execute_sql_readonly',
      { projectId, query: 'SELECT event_name FROM events' }, execute);
    expect(execute).toHaveBeenCalledOnce();
    expect(response).toContain('CONNECTOR_QUERY_NOT_READ_ONLY');
  });
  it('refuses an estimated scan above the configured byte budget before execution', async () => {
    const execute = vi.fn<ReadExecutor>(async () => ({ statistics: { query: { ...dryResult.statistics.query, totalBytesProcessed: '104857601' } } }));
    const response = await callTool(connector, 'execute_sql_readonly',
      { projectId, query: 'SELECT event_name FROM events' }, execute);
    expect(execute).toHaveBeenCalledOnce();
    expect(response).toContain('CONNECTOR_QUERY_BUDGET_EXCEEDED');
  });
  it.each<ToolArguments>([
    { projectId: 'other-project', query: 'SELECT 1' },
    { projectId, query: '' },
    { projectId, query: 'SELECT 1', maximumBytesBilled: '1' },
    { projectId, query: 'SELECT 1', location: 'US' },
    { projectId, query: 'SELECT 1', jobId: 'caller-job' },
    { projectId, query: 'SELECT 1', labels: { 'Invalid-Key': 'x' } },
    { projectId, query: `SELECT ${'x'.repeat(8_192)}` },
  ])('rejects unsupported query inputs before executing %j', async (args) => {
    const execute = vi.fn<ReadExecutor>();
    await callTool(connector, 'execute_sql_readonly', args, execute);
    expect(execute).not.toHaveBeenCalled();
  });
  it.each<ConnectorJson>([
    null,
    { jobComplete: true, statementType: 'SELECT', totalBytesProcessed: '1024' },
    { statistics: { query: { ...dryResult.statistics.query, statementType: 12345 } } },
    { statistics: { query: { totalBytesProcessed: '1024' } } },
    { statistics: { query: { statementType: 'SELECT' } } },
    { statistics: { query: { ...dryResult.statistics.query, dmlStats: { insertedRowCount: '1' } } } },
    { ...dryResult, status: { state: 'RUNNING' } },
    { ...dryResult, status: { errorResult: { message: 'synthetic-sensitive' } } },
    { ...dryResult, status: { state: 'DONE', errors: [{ message: 'synthetic-sensitive' }] } },
    { ...dryResult, errors: [{ reason: 'synthetic-sensitive-reason' }] },
    { ...dryResult, rows: [] },
  ])('fails closed on malformed dry-run responses %j', async (value) => {
    const execute = vi.fn<ReadExecutor>(async () => value);
    const response = await callTool(connector, 'execute_sql_readonly',
      { projectId, query: 'SELECT event_name FROM events' }, execute);
    expect(execute).toHaveBeenCalledOnce();
    expect(response).toContain('CONNECTOR_READ_FAILED');
    expect(response).not.toContain('synthetic-sensitive');
  });
  it('accepts an explicitly completed dry run and preserves identical query text and labels across phases', async () => {
    const query = 'SELECT 1 AS answer';
    const labels = { purpose: 'synthetic-read' };
    const execute = vi.fn<ReadExecutor>(async (plan) =>
      isDryRunPlan(plan) ? { ...dryResult, status: { state: 'DONE' } } : executeResult);
    await callTool(connector, 'execute_sql_readonly', { projectId, query, labels }, execute);
    expect(execute.mock.calls[0]?.[0]).toEqual(dryPlan(query, { labels }));
    expect(execute.mock.calls[1]?.[0]).toEqual(executePlan({ query, labels }));
  });
  it('rejects UTF-8 query overflow before any upstream call even below the character cap', async () => {
    const execute = vi.fn<ReadExecutor>();
    const query = `SELECT '${'é'.repeat(4_096)}'`;
    expect(query.length).toBeLessThan(8_192);
    expect(connector.allowRequest(dryPlan(query))).toBe(false);
    expect(connector.allowRequest(executePlan({ query }))).toBe(false);
    await callTool(connector, 'execute_sql_readonly', { projectId, query }, execute);
    expect(execute).not.toHaveBeenCalled();
  });
  it('accepts a query exactly at the UTF-8 byte limit', async () => {
    const query = `SELECT '${'é'.repeat(4_091)}' `;
    expect(new TextEncoder().encode(query).byteLength).toBe(8_192);
    const execute = vi.fn<ReadExecutor>(async () => dryResult);
    const response = await callTool(connector, 'execute_sql_readonly', { projectId, query, dryRun: true }, execute);
    expect(response).not.toContain('isError');
    expect(execute).toHaveBeenCalledOnce();
  });
  it.each<ConnectorJson>([
    { ...executeResult, jobComplete: false },
    { ...executeResult, numDmlAffectedRows: '1' },
    { ...executeResult, dmlStats: { insertedRowCount: '1' } },
    { ...executeResult, errors: [{ message: 'synthetic-sensitive-message' }] },
    { ...executeResult, rows: Array.from({ length: 201 }, () => executeResult.rows[0] ?? {}) },
    { ...executeResult, totalRows: 'many' },
  ])('fails closed on malformed execution responses %j', async (value) => {
    const execute = vi.fn<ReadExecutor>(async (plan) =>
      isDryRunPlan(plan) ? dryResult : value);
    const response = await callTool(connector, 'execute_sql_readonly',
      { projectId, query: 'SELECT event_name FROM events' }, execute);
    expect(response).toContain('CONNECTOR_READ_FAILED');
    expect(response).not.toContain('synthetic-sensitive');
  });
  it('sanitizes upstream exceptions without logging or exposing input', async () => {
    const logged = vi.spyOn(console, 'error');
    try {
      const execute: ReadExecutor = async () => { throw new Error('synthetic-sensitive-upstream-detail'); };
      const response = await callTool(connector, 'execute_sql_readonly',
        { projectId, query: 'SELECT event_name FROM events' }, execute);
      expect(response).toContain('CONNECTOR_READ_FAILED');
      expect(response).not.toContain('synthetic-sensitive');
      expect(logged).not.toHaveBeenCalled();
    } finally {
      logged.mockRestore();
    }
  });
  it.each<ToolArguments>([
    { projectId: 'other-project' },
    { projectId, pageSize: 51 },
    { projectId, pageSize: 0 },
    { projectId, pageToken: 'bad token' },
    { projectId, all: true },
  ])('rejects unsupported listing inputs before executing %j', async (args) => {
    const execute = vi.fn<ReadExecutor>();
    await callTool(connector, 'list_dataset_ids', args, execute);
    expect(execute).not.toHaveBeenCalled();
  });
});

describe('BigQuery deployment configuration', () => {
  it.each([
    {},
    { allowedProjectIds: [projectId], allowedDatasetIds: [datasetId] },
    { allowedProjectIds: [], allowedDatasetIds: [datasetId], maximumBytesBilled: budget },
    { allowedProjectIds: [projectId, projectId], allowedDatasetIds: [datasetId], maximumBytesBilled: budget },
    { allowedProjectIds: [projectId], allowedDatasetIds: ['analytics-123456!'], maximumBytesBilled: budget },
    { allowedProjectIds: [projectId], allowedDatasetIds: [datasetId], maximumBytesBilled: '0' },
    { allowedProjectIds: [projectId], allowedDatasetIds: [datasetId], maximumBytesBilled: '1099511627777' },
    { allowedProjectIds: [projectId], allowedDatasetIds: [datasetId], maximumBytesBilled: 104857600 },
    { allowedProjectIds: [projectId], allowedDatasetIds: [datasetId], maximumBytesBilled: budget, origin: 'https://other.example.com' },
    { allowedProjectIds: Array.from({ length: 5 }, (_, index) => `synthetic-project-${index}`), allowedDatasetIds: [datasetId], maximumBytesBilled: budget },
  ])('rejects malformed or widened configuration %j', (value) => {
    expect(() => createBigQueryConnector(JSON.stringify({ location, ...value }), secret)).toThrow('CONNECTOR_CONFIGURATION_INVALID');
  });
  it.each([undefined, '', 'us', 'europe_north1', 'europe-north1/queries', 'europe-north1?x=y', 'EU\n'])('rejects a missing or malformed location %j', (value) => {
    expect(() => createBigQueryConnector(JSON.stringify({ ...configured, location: value }), secret)).toThrow('CONNECTOR_CONFIGURATION_INVALID');
  });
  it.each(['US', 'EU', 'europe-north1', 'asia-northeast2'])('accepts a deployment-owned location %s', (value) => {
    expect(() => createBigQueryConnector(JSON.stringify({ ...configured, location: value }), secret)).not.toThrow();
  });
  it('accepts the documented budget bound and distinct resource sets', () => {
    const value = {
      allowedProjectIds: [projectId, 'synthetic-billing'],
      allowedDatasetIds: [datasetId, 'analytics_intraday'],
      maximumBytesBilled: '1099511627776',
      location,
    };
    expect(() => createBigQueryConnector(JSON.stringify(value), secret)).not.toThrow();
  });
  it('rejects non-service-account credential material at creation', () => {
    expect(() => createBigQueryConnector(config, 'synthetic-bearer-token')).toThrow('GOOGLE_AUTH_CONFIGURATION_INVALID');
  });
});
