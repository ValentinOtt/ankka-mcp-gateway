import { CLIENT_CAPABILITIES_META_KEY, CLIENT_INFO_META_KEY, createMcpHandler, McpServer, PROTOCOL_VERSION_META_KEY } from '@modelcontextprotocol/server';
import { describe, expect, it, vi } from 'vitest';
import type { ReadConnector, ReadExecutor } from '../src/connector';
import type { ConnectorJson, ReadRequestPlan } from '../src/request';
import { createNotionConnector, NOTION_API_VERSION } from '../src/providers/notion';
import { createHubSpotConnector } from '../src/providers/hubspot';
import { createZendeskConnector } from '../src/providers/zendesk';

const credential = 'synthetic-provider-token-not-a-secret';
const pageId = '00000000-0000-4000-8000-000000000101';
const dataSourceId = '00000000-0000-4000-8000-000000000102';
const otherId = '00000000-0000-4000-8000-000000000103';
const notionConfig = JSON.stringify({ allowedPageIds: [pageId], allowedDataSourceIds: [dataSourceId] });
const hubspotConfig = JSON.stringify({ objectProperties: { contacts: ['email'], companies: ['name'], deals: ['amount'] } });
const zendeskConfig = JSON.stringify({ subdomain: 'synthetic-team', allowedOrganizationIds: ['101'], allowedTicketIds: ['201'] });

type TestToolArguments = Readonly<Record<string, string | number | readonly string[]>>;

async function callTool(connector: ReadConnector, name: string, args: TestToolArguments, execute: ReadExecutor) {
  const handler = createMcpHandler(() => {
    const server = new McpServer({ name: 'synthetic-reader-test', version: '1.0.0' });
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
          [CLIENT_INFO_META_KEY]: { name: 'synthetic-reader-test', version: '1.0.0' },
        } },
      }),
    }));
    return await response.text();
  } finally {
    await handler.close();
  }
}

describe('Notion fixed read boundary', () => {
  const connector = createNotionConnector(notionConfig, credential);
  const goodPlans: ReadRequestPlan[] = [
    { method: 'GET', path: `/v1/pages/${pageId}` },
    { method: 'GET', path: `/v1/blocks/${pageId}/children`, query: { page_size: '25' } },
    { method: 'GET', path: `/v1/data_sources/${dataSourceId}` },
    { method: 'POST', path: `/v1/data_sources/${dataSourceId}/query`, body: { page_size: 50, start_cursor: 'cursor_01' } },
  ];
  it.each(goodPlans)('allows only authored read plan %j', (plan) => expect(connector.allowRequest(plan)).toBe(true));
  it('pins the origin and API revision without accepting a URL or extra header configuration', () => {
    expect(connector.origin).toBe('https://api.notion.com');
    expect(connector.headers).toEqual({ Authorization: `Bearer ${credential}`, 'Notion-Version': NOTION_API_VERSION });
    expect(NOTION_API_VERSION).toBe('2025-09-03');
    expect(() => createNotionConnector(JSON.stringify({ allowedPageIds: [pageId], origin: 'https://other.example.com' }), credential))
      .toThrow('CONNECTOR_CONFIGURATION_INVALID');
  });
  it.each<ReadRequestPlan>([
    { method: 'POST', path: `/v1/pages/${pageId}`, body: {} },
    { method: 'GET', path: `/v1/pages/${otherId}` },
    { method: 'GET', path: `/v1/pages/${pageId}/../${otherId}` },
    { method: 'GET', path: `/v1/pages/${pageId}%2fanything` },
    { method: 'GET', path: `/v1/pages/${pageId}`, query: { filter_properties: 'title' } },
    { method: 'GET', path: `/v1/blocks/${otherId}/children`, query: { page_size: '25' } },
    { method: 'GET', path: `/v1/blocks/${pageId}/children`, query: { page_size: '51' } },
    { method: 'GET', path: `/v1/blocks/${pageId}/children`, query: { page_size: '25', start_cursor: 'a&url=https://other.example.com' } },
    { method: 'GET', path: `/v1/data_sources/${pageId}` },
    { method: 'POST', path: `/v1/data_sources/${dataSourceId}/query`, body: { page_size: 0 } },
    { method: 'POST', path: `/v1/data_sources/${dataSourceId}/query`, body: { page_size: 25, filter: {} } },
    { method: 'POST', path: `/v1/data_sources/${dataSourceId}/query`, body: { page_size: 25 }, query: { url: 'https://other.example.com' } },
    { method: 'POST', path: '/v1/search', body: { page_size: 25 } },
  ])('denies resource/method/parameter escape %j', (plan) => expect(connector.allowRequest(plan)).toBe(false));
  it.each([
    ['notion_get_page', { pageId }, `/v1/pages/${pageId}`],
    ['notion_list_page_blocks', { pageId, pageSize: 10 }, `/v1/blocks/${pageId}/children`],
    ['notion_get_data_source', { dataSourceId }, `/v1/data_sources/${dataSourceId}`],
    ['notion_list_data_source_pages', { dataSourceId, pageSize: 10 }, `/v1/data_sources/${dataSourceId}/query`],
  ] as const)('registers and executes %s with an allowed request', async (name, args, path) => {
    const execute = vi.fn<ReadExecutor>(async (plan) => {
      expect(connector.allowRequest(plan)).toBe(true);
      expect(plan.path).toBe(path);
      return { synthetic: true };
    });
    expect(await callTool(connector, name, args, execute)).toContain('synthetic');
    expect(execute).toHaveBeenCalledOnce();
  });
  it.each([
    { pageId: `${pageId}/../${otherId}` }, { pageId, url: 'https://other.example.com' },
    { pageId, pageSize: 51 }, { pageId, startCursor: 'x'.repeat(257) },
  ])('rejects malformed tool inputs before execution %j', async (args) => {
    const execute = vi.fn<ReadExecutor>();
    await callTool(connector, 'notion_list_page_blocks', args, execute);
    expect(execute).not.toHaveBeenCalled();
  });
});

describe('HubSpot selected-object and selected-property reads', () => {
  const connector = createHubSpotConnector(hubspotConfig, credential);
  const query = { properties: 'email', archived: 'false' };
  it.each<ReadRequestPlan>([
    { method: 'GET', path: '/crm/v3/objects/contacts', query: { ...query, limit: '50', after: '101' } },
    { method: 'GET', path: '/crm/v3/objects/contacts/101', query },
    { method: 'POST', path: '/crm/v3/objects/contacts/batch/read', body: { properties: ['email'], inputs: [{ id: '101' }] } },
  ])('allows exact object reads %j', (plan) => expect(connector.allowRequest(plan)).toBe(true));
  it.each<ReadRequestPlan>([
    { method: 'POST', path: '/crm/v3/objects/contacts/101', body: { properties: { email: 'synthetic@example.com' } } },
    { method: 'GET', path: '/crm/v3/objects/contacts/../companies', query: { ...query, limit: '25' } },
    { method: 'GET', path: '/crm/v3/objects/tickets/101', query },
    { method: 'GET', path: '/crm/v3/objects/contacts/101', query: { ...query, idProperty: 'email' } },
    { method: 'GET', path: '/crm/v3/objects/contacts/101', query: { properties: 'email,phone', archived: 'false' } },
    { method: 'GET', path: '/crm/v3/objects/contacts/101', query: { ...query, archived: 'true' } },
    { method: 'GET', path: '/crm/v3/objects/contacts', query: { ...query, limit: '51' } },
    { method: 'GET', path: '/crm/v3/objects/contacts', query: { ...query, limit: '25', after: 'next&properties=phone' } },
    { method: 'POST', path: '/crm/v3/objects/contacts/search', body: { limit: 25 } },
    { method: 'POST', path: '/crm/v3/objects/contacts/batch/read', body: { properties: ['email'], inputs: [{ id: '../101' }] } },
    { method: 'POST', path: '/crm/v3/objects/contacts/batch/read', body: { properties: ['email'], inputs: [{ id: '101' }], idProperty: 'email' } },
    { method: 'POST', path: '/crm/v3/objects/contacts/batch/read', body: { properties: ['email'], inputs: [{ id: '101' }, { id: '101' }] } },
    { method: 'POST', path: '/crm/v3/objects/contacts/batch/read', body: { properties: ['email'], inputs: Array.from({ length: 26 }, (_, index) => ({ id: String(index + 1) })) } },
  ])('denies query, property, object and method widening %j', (plan) => expect(connector.allowRequest(plan)).toBe(false));
  it.each([
    ['hubspot_list_records', { objectType: 'contacts', limit: 10 }, '/crm/v3/objects/contacts'],
    ['hubspot_get_record', { objectType: 'contacts', recordId: '101' }, '/crm/v3/objects/contacts/101'],
    ['hubspot_batch_read_records', { objectType: 'contacts', recordIds: ['101'] }, '/crm/v3/objects/contacts/batch/read'],
  ] as const)('executes %s and excludes provider-added properties and metadata', async (name, args, path) => {
    const record = { id: '101', properties: { email: 'synthetic@example.com', phone: 'not-approved-field' }, associations: { private: 'not-approved-association' } };
    const execute = vi.fn<ReadExecutor>(async (plan) => {
      expect(plan.path).toBe(path);
      expect(connector.allowRequest(plan)).toBe(true);
      return name === 'hubspot_get_record' ? record : { results: [record], paging: { next: { after: '102', link: 'not-approved-link' } } };
    });
    const response = await callTool(connector, name, args, execute);
    expect(execute).toHaveBeenCalledOnce();
    expect(response).toContain('synthetic@example.com');
    expect(response).not.toContain('not-approved');
  });
  it('does not allow unconfigured object types even when they have a registered tool', async () => {
    const narrow = createHubSpotConnector(JSON.stringify({ objectProperties: { contacts: ['email'] } }), credential);
    const execute = vi.fn<ReadExecutor>();
    expect(await callTool(narrow, 'hubspot_get_record', { objectType: 'deals', recordId: '101' }, execute))
      .toContain('CONNECTOR_READ_FAILED');
    expect(execute).not.toHaveBeenCalled();
    expect(narrow.allowRequest({ method: 'GET', path: '/crm/v3/objects/deals/101', query: { properties: 'amount', archived: 'false' } })).toBe(false);
  });
  it.each([
    { objectType: 'contacts', recordId: '../101' },
    { objectType: 'contacts', recordId: '101', properties: ['phone'] },
    { objectType: 'tickets', recordId: '101' },
  ])('rejects unsupported tool arguments %j', async (args) => {
    const execute = vi.fn<ReadExecutor>();
    await callTool(connector, 'hubspot_get_record', args, execute);
    expect(execute).not.toHaveBeenCalled();
  });
});

describe('Zendesk fixed tenant and explicit resource reads', () => {
  const connector = createZendeskConnector(zendeskConfig, credential);
  it('pins the Zendesk suffix and carries only the provider authorization header', () => {
    expect(connector.origin).toBe('https://synthetic-team.zendesk.com');
    expect(connector.headers).toEqual({ Authorization: `Bearer ${credential}` });
  });
  it.each<ReadRequestPlan>([
    { method: 'GET', path: '/api/v2/organizations/101' },
    { method: 'GET', path: '/api/v2/organizations/101/tickets', query: { 'page[size]': '50' } },
    { method: 'GET', path: '/api/v2/tickets/201' },
    { method: 'GET', path: '/api/v2/tickets/201/comments', query: { 'page[size]': '25', 'page[after]': 'cursor_01==' } },
  ])('allows exact configured reads %j', (plan) => expect(connector.allowRequest(plan)).toBe(true));
  it.each<ReadRequestPlan>([
    { method: 'POST', path: '/api/v2/tickets/201', body: {} },
    { method: 'GET', path: '/api/v2/tickets' },
    { method: 'GET', path: '/api/v2/tickets/202' },
    { method: 'GET', path: '/api/v2/organizations/102/tickets', query: { 'page[size]': '25' } },
    { method: 'GET', path: '/api/v2/tickets/201/../202' },
    { method: 'GET', path: '/api/v2/tickets/201%2fcomments' },
    { method: 'GET', path: '/api/v2/tickets/201', query: { include: 'users' } },
    { method: 'GET', path: '/api/v2/tickets/201/comments', query: { 'page[size]': '51' } },
    { method: 'GET', path: '/api/v2/tickets/201/comments', query: { 'page[size]': '25', include_inline_images: 'true' } },
    { method: 'GET', path: '/api/v2/tickets/201/comments', query: { 'page[size]': '25', 'page[after]': 'x&url=https://other.example.com' } },
    { method: 'GET', path: '/api/v2/search', query: { query: 'type:ticket' } },
  ])('denies tenant-wide lists, side loads and mutations %j', (plan) => expect(connector.allowRequest(plan)).toBe(false));
  it.each([
    ['zendesk_get_organization', { organizationId: '101' }, '/api/v2/organizations/101'],
    ['zendesk_list_organization_tickets', { organizationId: '101', pageSize: 10 }, '/api/v2/organizations/101/tickets'],
    ['zendesk_get_ticket', { ticketId: '201' }, '/api/v2/tickets/201'],
    ['zendesk_list_ticket_comments', { ticketId: '201', pageSize: 10 }, '/api/v2/tickets/201/comments'],
  ] as const)('executes %s with the resource bound to the authored path', async (name, args, path) => {
    const execute = vi.fn<ReadExecutor>(async (plan) => {
      expect(connector.allowRequest(plan)).toBe(true);
      expect(plan.path).toBe(path);
      return { synthetic: true };
    });
    expect(await callTool(connector, name, args, execute)).toContain('synthetic');
    expect(execute).toHaveBeenCalledOnce();
  });
  it.each(['https://other.example.com', 'tenant.zendesk.com', 'tenant@other', 'tenant/..', 'tenant:443', 'LOCALHOST', 'support'])
    ('rejects non-tenant subdomain %s', (subdomain) => {
      expect(() => createZendeskConnector(JSON.stringify({ subdomain, allowedTicketIds: ['201'] }), credential))
        .toThrow('CONNECTOR_CONFIGURATION_INVALID');
    });
});

describe('reader configuration and error secrecy', () => {
  it.each([
    ['notion', () => createNotionConnector('{}', credential)],
    ['notion-duplicate', () => createNotionConnector(JSON.stringify({ allowedPageIds: [pageId, pageId] }), credential)],
    ['hubspot', () => createHubSpotConnector('{"objectProperties":{}}', credential)],
    ['hubspot-unknown', () => createHubSpotConnector('{"objectProperties":{"tickets":["subject"]}}', credential)],
    ['hubspot-property-injection', () => createHubSpotConnector('{"objectProperties":{"contacts":["email,phone"]}}', credential)],
    ['zendesk', () => createZendeskConnector('{"subdomain":"synthetic-team"}', credential)],
    ['credential', () => createNotionConnector(notionConfig, 'synthetic\r\nInjected: value')],
  ] as const)('rejects invalid configuration without echoing it: %s', (_label, create) => {
    expect(create).toThrow('CONNECTOR_CONFIGURATION_INVALID');
  });
  it.each([
    ['notion', createNotionConnector(notionConfig, credential), 'notion_get_page', { pageId }],
    ['hubspot', createHubSpotConnector(hubspotConfig, credential), 'hubspot_get_record', { objectType: 'contacts', recordId: '101' }],
    ['zendesk', createZendeskConnector(zendeskConfig, credential), 'zendesk_get_ticket', { ticketId: '201' }],
  ] as const)('sanitizes upstream exceptions for %s', async (_label, connector, name, args) => {
    const execute: ReadExecutor = async (): Promise<ConnectorJson> => { throw new Error(credential); };
    const response = await callTool(connector, name, args, execute);
    expect(response).toContain('CONNECTOR_READ_FAILED');
    expect(response).not.toContain(credential);
  });
});
