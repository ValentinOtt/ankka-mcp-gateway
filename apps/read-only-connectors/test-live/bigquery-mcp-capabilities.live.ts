import { it } from 'vitest';
import { probeBigQueryMcpCapabilities } from './bigquery-mcp-capabilities';

it.skipIf(process.env.ANKKA_BIGQUERY_MCP_DISCOVERY_LIVE !== '1')(
  'reports the public hosted BigQuery MCP query controls without credentials or SQL', async () => {
    const report = await probeBigQueryMcpCapabilities((input, init) => globalThis.fetch(input, init));
    console.info(JSON.stringify({ probe: 'bigquery_mcp_capabilities', ...report }));
  },
);
