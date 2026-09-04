import { describe, expect, it, vi } from 'vitest';
import { probeBigQueryMcpCapabilities, summarizeBigQueryMcpCapabilities } from '../test-live/bigquery-mcp-capabilities';
import type { ConnectorJson } from '../src/request';

function catalogue(sqlFields: Record<string, ConnectorJson> = {}) {
  return { jsonrpc: '2.0', id: 1, result: { tools: ['list_table_ids', 'get_table_info', 'execute_sql_readonly'].map((name) => ({
    name, inputSchema: { type: 'object', properties: name === 'execute_sql_readonly' ? sqlFields : {} },
  })) } };
}

describe('hosted BigQuery capability qualification', () => {
  it('reports only reviewed field presence, without implying enforcement', () => {
    const report = summarizeBigQueryMcpCapabilities(catalogue({
      projectId: { type: 'string' }, query: { type: 'string' }, dryRun: { type: 'boolean' },
      labels: { description: 'synthetic-private-description' }, unrelatedField: { type: 'string' },
    }));
    expect(report.advertisedSqlFields).toEqual({ projectId: true, query: true, dryRun: true, labels: true,
      maximumBytesBilled: false, timeoutMs: false, jobTimeoutMs: false, maxResults: false, location: false });
    expect(JSON.stringify(report)).not.toContain('synthetic-private-description');
    expect(JSON.stringify(report)).not.toContain('unrelatedField');
    expect(summarizeBigQueryMcpCapabilities(catalogue({ maximumBytesBilled: { type: 'string' } }))
      .advertisedSqlFields.maximumBytesBilled).toBe(true);
  });

  it('rejects incomplete, duplicate, missing, or invalid discovery without echoing it', () => {
    const complete = catalogue();
    for (const value of [
      { ...complete, result: { ...complete.result, nextCursor: 'synthetic-private-cursor' } },
      { ...complete, result: { tools: [...complete.result.tools, ...complete.result.tools] } },
      { ...complete, result: { tools: complete.result.tools.slice(0, 2) } },
      { jsonrpc: '2.0', id: 1, error: { message: 'synthetic-private-error' } },
      { ...complete, id: 2 },
    ]) expect(() => summarizeBigQueryMcpCapabilities(value)).toThrow('BIGQUERY_MCP_DISCOVERY_INVALID');
  });

  it('makes one fixed discovery request without authorization or query execution', async () => {
    const fetcher = vi.fn<typeof globalThis.fetch>(async () => Response.json(catalogue()));
    await probeBigQueryMcpCapabilities(fetcher);
    expect(fetcher).toHaveBeenCalledTimes(1);
    const call = fetcher.mock.calls[0];
    if (call === undefined) throw new Error('EXPECTED_DISCOVERY_REQUEST');
    const [url, init] = call;
    expect(url).toBe('https://bigquery.googleapis.com/mcp');
    expect(init?.method).toBe('POST');
    expect(init?.redirect).toBe('manual');
    expect(new Headers(init?.headers).has('Authorization')).toBe(false);
    expect(JSON.parse(String(init?.body))).toEqual({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
  });

  it.each([401, 302, 500])('fails closed on HTTP %s without retries or credential fallback', async (status) => {
    const fetcher = vi.fn<typeof globalThis.fetch>(async () => new Response('synthetic-private-body', {
      status, headers: { Location: 'https://other.example.com' },
    }));
    await expect(probeBigQueryMcpCapabilities(fetcher)).rejects.toThrow('BIGQUERY_MCP_DISCOVERY_FAILED');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('rejects an oversized catalogue with a fixed diagnostic', async () => {
    const fetcher = vi.fn<typeof globalThis.fetch>(async () => new Response('x'.repeat(524_289), {
      headers: { 'Content-Type': 'application/json' },
    }));
    await expect(probeBigQueryMcpCapabilities(fetcher)).rejects.toThrow('BIGQUERY_MCP_DISCOVERY_FAILED');
  });
});
