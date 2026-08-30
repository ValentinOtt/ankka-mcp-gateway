import { CLIENT_CAPABILITIES_META_KEY, CLIENT_INFO_META_KEY, createMcpHandler, McpServer, PROTOCOL_VERSION_META_KEY } from '@modelcontextprotocol/server';
import { describe, expect, it, vi } from 'vitest';
import type { ReadConnector, ReadExecutor } from '../src/connector';
import type { ConnectorJson, ReadRequestPlan } from '../src/request';
import { createGoogleAnalyticsConnector } from '../src/providers/google-analytics';

const propertyId = '123456789';
const config = JSON.stringify({ allowedPropertyIds: [propertyId] });
// Deliberately not signing material; these tests never mint tokens or call Google.
const secret = JSON.stringify({
  type: 'service_account', project_id: 'synthetic-project', private_key_id: 'a'.repeat(40),
  private_key: 'synthetic-placeholder-not-a-private-key',
  client_email: 'synthetic-reader@synthetic-project.iam.gserviceaccount.com',
  token_uri: 'https://oauth2.googleapis.com/token',
});
type ToolArguments = Readonly<Record<string, ConnectorJson>>;
type ReportBodyOverrides = Readonly<Record<string, ConnectorJson>>;

function dailyPlan(overrides: ReportBodyOverrides = {}): ReadRequestPlan {
  return {
    method: 'POST', path: `/v1beta/properties/${propertyId}:runReport`,
    body: {
      dimensions: [{ name: 'date' }],
      metrics: [{ name: 'sessions' }, { name: 'activeUsers' }, { name: 'screenPageViews' }],
      dateRanges: [{ startDate: '2026-08-01', endDate: '2026-08-30' }],
      limit: '250', ...overrides,
    },
  };
}
function realtimePlan(overrides: ReportBodyOverrides = {}): ReadRequestPlan {
  return {
    method: 'POST', path: `/v1beta/properties/${propertyId}:runRealtimeReport`,
    body: {
      dimensions: [{ name: 'deviceCategory' }], metrics: [{ name: 'activeUsers' }],
      minuteRanges: [{ startMinutesAgo: 29, endMinutesAgo: 0 }], limit: '50', ...overrides,
    },
  };
}
const dailyRow = {
  dimensionValues: [{ value: '20260801' }],
  metricValues: [{ value: '24' }, { value: '20' }, { value: '42' }],
};
const dailyReport = {
  dimensionHeaders: [{ name: 'date' }],
  metricHeaders: [
    { name: 'sessions', type: 'TYPE_INTEGER' }, { name: 'activeUsers', type: 'TYPE_INTEGER' },
    { name: 'screenPageViews', type: 'TYPE_INTEGER' },
  ],
  rows: [dailyRow], rowCount: 1,
  metadata: { timeZone: 'Europe/Oslo', currencyCode: 'NOK', subjectToThresholding: false },
};
const realtimeReport = {
  dimensionHeaders: [{ name: 'deviceCategory' }], metricHeaders: [{ name: 'activeUsers', type: 'TYPE_INTEGER' }],
  rows: [{ dimensionValues: [{ value: 'desktop' }], metricValues: [{ value: '12' }] }], rowCount: 1,
};

async function callTool(connector: ReadConnector, name: string, args: ToolArguments, execute: ReadExecutor) {
  const handler = createMcpHandler(() => {
    const server = new McpServer({ name: 'synthetic-ga4-test', version: '1.0.0' });
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
          [CLIENT_INFO_META_KEY]: { name: 'synthetic-ga4-test', version: '1.0.0' },
        } },
      }),
    }));
    return await response.text();
  } finally {
    await handler.close();
  }
}

describe('Google Analytics fixed read plans', () => {
  const connector = createGoogleAnalyticsConnector(config, secret);
  it('pins the Data API origin and defers authorization to the shared Google boundary', () => {
    expect(connector.id).toBe('google-analytics');
    expect(connector.origin).toBe('https://analyticsdata.googleapis.com');
    expect(connector.headers).toEqual({});
    expect(connector.authorize).toBeTypeOf('function');
  });
  it.each([dailyPlan(), realtimePlan(), dailyPlan({ limit: '1' }), realtimePlan({ limit: '1' })])
    ('allows the exact authored plan %j', (plan) => expect(connector.allowRequest(plan)).toBe(true));
  it.each<ReadRequestPlan>([
    { ...dailyPlan(), method: 'GET' },
    { ...dailyPlan(), path: '/v1beta/properties/987654321:runReport' },
    { ...dailyPlan(), path: `/v1alpha/properties/${propertyId}:runReport` },
    { ...dailyPlan(), path: `/v1beta/properties/${propertyId}:batchRunReports` },
    { ...dailyPlan(), path: `/v1beta/properties/${propertyId}/audienceExports` },
    { ...dailyPlan(), path: `/v1beta/properties/${propertyId}:runReport?key=synthetic` },
    { ...dailyPlan(), path: `/v1beta/properties/${propertyId}%2f..:runReport` },
    { ...dailyPlan(), query: {} },
    { ...dailyPlan(), query: { fields: 'rows', key: 'synthetic' } },
    dailyPlan({ dimensions: [{ name: 'country' }] }),
    dailyPlan({ dimensions: [{ name: 'date', dimensionExpression: { lowerCase: { dimensionName: 'country' } } }] }),
    dailyPlan({ metrics: [{ name: 'sessions' }] }),
    dailyPlan({ metrics: [{ name: 'sessions', expression: 'totalRevenue' }, { name: 'activeUsers' }, { name: 'screenPageViews' }] }),
    dailyPlan({ offset: '250' }),
    dailyPlan({ dimensionFilter: {} }),
    dailyPlan({ metricFilter: {} }),
    dailyPlan({ orderBys: [] }),
    dailyPlan({ returnPropertyQuota: true }),
    dailyPlan({ cohortSpec: {} }),
    dailyPlan({ comparisons: [] }),
    dailyPlan({ limit: 250 }),
    dailyPlan({ limit: '0' }),
    dailyPlan({ limit: '251' }),
    dailyPlan({ limit: '025' }),
    realtimePlan({ metrics: [{ name: 'sessions' }] }),
    realtimePlan({ dimensions: [{ name: 'customUser:private' }] }),
    realtimePlan({ dateRanges: [{ startDate: '2026-08-01', endDate: '2026-08-30' }] }),
    realtimePlan({ minuteRanges: [{ startMinutesAgo: 59, endMinutesAgo: 0 }] }),
    realtimePlan({ minuteRanges: [{ startMinutesAgo: 29, endMinutesAgo: 0 }, { startMinutesAgo: 10, endMinutesAgo: 0 }] }),
    realtimePlan({ limit: '51' }),
    realtimePlan({ limit: 10 }),
  ])('denies property, operation, query, and report widening %j', (plan) => {
    expect(connector.allowRequest(plan)).toBe(false);
  });
  it.each([
    ['2026-01-01', '2026-04-03', true],
    ['2026-01-01', '2026-04-04', false],
    ['2026-08-30', '2026-08-01', false],
    ['2024-02-29', '2024-02-29', true],
    ['2026-02-29', '2026-03-01', false],
    ['2026-02-30', '2026-03-01', false],
    ['2026-04-31', '2026-05-01', false],
    ['30daysAgo', 'yesterday', false],
    ['2026-08-01T00:00:00Z', '2026-08-30', false],
  ] as const)('validates inclusive calendar dates %s to %s', (startDate, endDate, allowed) => {
    expect(connector.allowRequest(dailyPlan({ dateRanges: [{ startDate, endDate }] }))).toBe(allowed);
  });
  it('rejects extra and repeated date ranges', () => {
    expect(connector.allowRequest(dailyPlan({ dateRanges: [{ startDate: '2026-08-01', endDate: '2026-08-30', name: 'custom' }] }))).toBe(false);
    expect(connector.allowRequest(dailyPlan({ dateRanges: [
      { startDate: '2026-08-01', endDate: '2026-08-30' }, { startDate: '2026-07-01', endDate: '2026-07-30' },
    ] }))).toBe(false);
  });
});

describe('Google Analytics tools and successful response projection', () => {
  const connector = createGoogleAnalyticsConnector(config, secret);
  const dailyArgs = { propertyId, startDate: '2026-08-01', endDate: '2026-08-30' };
  it('executes only the fixed daily template and strips provider-added response fields', async () => {
    const execute = vi.fn<ReadExecutor>(async (plan) => {
      expect(plan).toEqual(dailyPlan());
      expect(connector.allowRequest(plan)).toBe(true);
      return { ...dailyReport, unexpected: 'not-approved-extra', next: 'https://not-approved.example.com',
        metadata: { ...dailyReport.metadata, private: 'not-approved-metadata' },
        rows: [{ ...dailyRow, extra: 'not-approved-row' }],
      };
    });
    const response = await callTool(connector, 'google_analytics_daily_traffic', dailyArgs, execute);
    expect(response).toContain('20260801');
    expect(response).toContain('Europe/Oslo');
    expect(response).not.toContain('not-approved');
    expect(execute).toHaveBeenCalledOnce();
  });
  it('executes the last-30-minutes realtime template with only compatible fields', async () => {
    const execute = vi.fn<ReadExecutor>(async (plan) => {
      expect(plan).toEqual(realtimePlan());
      expect(connector.allowRequest(plan)).toBe(true);
      return { ...realtimeReport, next: 'not-approved-next', metadata: { unexpected: 'not-approved-metadata' } };
    });
    const response = await callTool(connector, 'google_analytics_realtime_by_device', { propertyId }, execute);
    expect(response).toContain('desktop');
    expect(response).not.toContain('not-approved');
    expect(execute).toHaveBeenCalledOnce();
  });
  it('preserves total rowCount and string metrics without following more results', async () => {
    const execute = vi.fn<ReadExecutor>(async (plan) => {
      expect(plan).toEqual(dailyPlan({ limit: '1' }));
      return { ...dailyReport, rowCount: 30, rows: [{ ...dailyRow,
        metricValues: [{ value: '9007199254740993' }, { value: '20' }, { value: '42' }],
      }] };
    });
    const response = await callTool(connector, 'google_analytics_daily_traffic', { ...dailyArgs, limit: 1 }, execute);
    expect(response).toContain('9007199254740993');
    expect(response).toContain('rowCount');
    expect(execute).toHaveBeenCalledOnce();
  });
  it('accepts a valid empty report with omitted protobuf zero/empty fields', async () => {
    const execute = vi.fn<ReadExecutor>(async () => ({
      dimensionHeaders: dailyReport.dimensionHeaders, metricHeaders: dailyReport.metricHeaders,
    }));
    expect(await callTool(connector, 'google_analytics_daily_traffic', dailyArgs, execute)).not.toContain('CONNECTOR_READ_FAILED');
  });
  it.each<ToolArguments>([
    { ...dailyArgs, propertyId: '987654321' },
    { ...dailyArgs, propertyId: '../123456789' },
    { ...dailyArgs, limit: 251 },
    { ...dailyArgs, limit: 0 },
    { ...dailyArgs, limit: '10' },
    { ...dailyArgs, endDate: '2026-07-01' },
    { ...dailyArgs, startDate: '2026-01-01' },
    { ...dailyArgs, endDate: '2026-02-29' },
    { ...dailyArgs, startDate: '2026-02-30' },
    { ...dailyArgs, metrics: ['totalRevenue'] },
    { ...dailyArgs, filter: 'private' },
    { ...dailyArgs, url: 'https://other.example.com' },
  ])('rejects unsupported daily inputs before executing %j', async (args) => {
    const execute = vi.fn<ReadExecutor>();
    await callTool(connector, 'google_analytics_daily_traffic', args, execute);
    expect(execute).not.toHaveBeenCalled();
  });
  it.each<ToolArguments>([
    { propertyId: '987654321' }, { propertyId, limit: 51 },
    { propertyId, startMinutesAgo: 59 }, { propertyId, dimensions: ['country'] },
    { propertyId, metrics: ['sessions'] }, { propertyId, offset: '50' },
  ])('rejects unsupported realtime inputs before executing %j', async (args) => {
    const execute = vi.fn<ReadExecutor>();
    await callTool(connector, 'google_analytics_realtime_by_device', args, execute);
    expect(execute).not.toHaveBeenCalled();
  });
  it.each<ConnectorJson>([
    null, {}, { ...dailyReport, rows: [{ ...dailyRow, metricValues: [{ value: '24' }] }] },
    { ...dailyReport, metricHeaders: [{ name: 'totalRevenue', type: 'TYPE_CURRENCY' }] },
    { ...dailyReport, rowCount: 0 },
    { ...dailyReport, rowCount: -1 },
    { ...dailyReport, rows: Array.from({ length: 251 }, () => dailyRow) },
    { ...dailyReport, rows: [{ ...dailyRow, metricValues: [{ value: 24 }, { value: '20' }, { value: '42' }] }] },
    { ...dailyReport, metadata: { subjectToThresholding: 'false' } },
  ])('fails closed on malformed daily responses without exposing them %j', async (value) => {
    const execute = vi.fn<ReadExecutor>(async () => value);
    expect(await callTool(connector, 'google_analytics_daily_traffic', dailyArgs, execute)).toContain('CONNECTOR_READ_FAILED');
    expect(execute).toHaveBeenCalledOnce();
  });
  it('rejects a response larger than the caller-selected row cap', async () => {
    const execute = vi.fn<ReadExecutor>(async () => ({ ...dailyReport, rows: [dailyRow, dailyRow], rowCount: 2 }));
    expect(await callTool(connector, 'google_analytics_daily_traffic', { ...dailyArgs, limit: 1 }, execute))
      .toContain('CONNECTOR_READ_FAILED');
  });
  it.each<ConnectorJson>([
    { ...realtimeReport, metricHeaders: [{ name: 'sessions', type: 'TYPE_INTEGER' }] },
    { ...realtimeReport, rows: Array.from({ length: 51 }, () => realtimeReport.rows[0] ?? {}) },
    { ...realtimeReport, rowCount: 0 },
  ])('fails closed on malformed realtime responses %j', async (value) => {
    const execute = vi.fn<ReadExecutor>(async () => value);
    expect(await callTool(connector, 'google_analytics_realtime_by_device', { propertyId }, execute)).toContain('CONNECTOR_READ_FAILED');
  });
  it('sanitizes upstream exceptions without logging or exposing input', async () => {
    const logged = vi.spyOn(console, 'error');
    try {
      const execute: ReadExecutor = async () => { throw new Error('synthetic-sensitive-upstream-detail'); };
      const response = await callTool(connector, 'google_analytics_daily_traffic', dailyArgs, execute);
      expect(response).toContain('CONNECTOR_READ_FAILED');
      expect(response).not.toContain('synthetic-sensitive');
      expect(logged).not.toHaveBeenCalled();
    } finally {
      logged.mockRestore();
    }
  });
});

describe('Google Analytics deployment configuration', () => {
  it.each([
    {}, { allowedPropertyIds: [] }, { allowedPropertyIds: [propertyId, propertyId] },
    { allowedPropertyIds: ['00123'] }, { allowedPropertyIds: ['0'] }, { allowedPropertyIds: [123] },
    { allowedPropertyIds: ['properties/123'] }, { allowedPropertyIds: ['123:runRealtimeReport'] },
    { allowedPropertyIds: Array.from({ length: 26 }, (_, index) => String(index + 1)) },
    { allowedPropertyIds: [propertyId], origin: 'https://other.example.com' },
    { allowedPropertyIds: [propertyId], scopes: ['https://www.googleapis.com/auth/analytics'] },
  ])('rejects malformed or widened configuration %j', (value) => {
    expect(() => createGoogleAnalyticsConnector(JSON.stringify(value), secret)).toThrow('CONNECTOR_CONFIGURATION_INVALID');
  });
  it('accepts the maximum distinct configured property set', () => {
    const value = { allowedPropertyIds: Array.from({ length: 25 }, (_, index) => String(index + 1)) };
    expect(() => createGoogleAnalyticsConnector(JSON.stringify(value), secret)).not.toThrow();
  });
  it('rejects non-service-account credential material at creation', () => {
    expect(() => createGoogleAnalyticsConnector(config, 'synthetic-bearer-token')).toThrow('GOOGLE_AUTH_CONFIGURATION_INVALID');
  });
});
