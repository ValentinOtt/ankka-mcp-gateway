import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import { describe, expect, it, vi } from 'vitest';
import { createGorgiasConnector } from '../src/providers/gorgias';
import type { ReadExecutor } from '../src/connector';
import type { ReadRequestPlan } from '../src/request';

const config = { subdomain: 'synthetic-helpdesk', allowedTicketIds: ['11'], allowedCustomerIds: ['22'] };
const connector = createGorgiasConnector(JSON.stringify(config), 'synthetic-not-a-real-token');
async function call(name: string, args: Record<string, string | number>) {
  const execute = vi.fn<ReadExecutor>(async () => ({ data: [] }));
  const handler = createMcpHandler(() => {
    const server = new McpServer({ name: 'synthetic', version: '1' });
    connector.registerTools(server, execute);
    return server;
  }, { keepAliveMs: 0 });
  const response = await handler.fetch(new Request('https://connector.example.com/mcp', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }),
  }));
  const text = await response.text();
  await handler.close();
  return { execute, text };
}
describe('Gorgias fixed read operations', () => {
  it('uses only the deployment-owned Gorgias subdomain and bearer credential', () => {
    expect(connector.origin).toBe('https://synthetic-helpdesk.gorgias.com');
    expect(connector.headers).toEqual({ Authorization: 'Bearer synthetic-not-a-real-token' });
  });
  it('builds a specific approved ticket read', async () => {
    const result = await call('gorgias_get_ticket', { ticketId: '11' });
    expect(result.execute).toHaveBeenCalledWith({ method: 'GET', path: '/api/tickets/11' });
  });
  it('uses the current bounded message endpoint, never the deprecated ticket-message list', async () => {
    const result = await call('gorgias_list_ticket_messages', { ticketId: '11', limit: 10, cursor: 'next-page==' });
    expect(result.execute).toHaveBeenCalledWith({ method: 'GET', path: '/api/messages', query: {
      ticket_id: '11', limit: '10', order_by: 'created_datetime:desc', cursor: 'next-page==',
    } });
    expect(connector.allowRequest(result.execute.mock.calls[0]?.[0] ?? { method: 'GET', path: '/' })).toBe(true);
  });
  it('requires customer scope and excludes trashed tickets on lists', async () => {
    const result = await call('gorgias_list_customer_tickets', { customerId: '22' });
    expect(result.execute).toHaveBeenCalledWith({ method: 'GET', path: '/api/tickets', query: {
      customer_id: '22', limit: '20', order_by: 'created_datetime:desc', trashed: 'false',
    } });
  });
  it.each([
    ['gorgias_get_ticket', { ticketId: '12' }], ['gorgias_get_ticket', { ticketId: '../users' }],
    ['gorgias_list_ticket_messages', { ticketId: '11', limit: 51 }],
    ['gorgias_list_ticket_messages', { ticketId: '11', cursor: 'https://evil.example.com' }],
    ['gorgias_list_customer_tickets', { customerId: '99' }],
    ['gorgias_get_ticket', { ticketId: '11', url: 'https://evil.example.com' }],
    ['gorgias_update_ticket', { ticketId: '11' }],
  ] satisfies [string, Record<string, string | number>][])('rejects unsafe tool input for %s', async (name, args) => {
    const result = await call(name, args);
    expect(result.execute).not.toHaveBeenCalled();
    expect(result.text).toMatch(/error|isError/);
  });
  it.each([
    { method: 'POST', path: '/api/tickets/11' },
    { method: 'GET', path: '/api/tickets/99' },
    { method: 'GET', path: '/api/tickets' },
    { method: 'GET', path: '/api/messages', query: { ticket_id: '99', limit: '10', order_by: 'created_datetime:desc' } },
    { method: 'GET', path: '/api/tickets/11', query: { relationships: 'integrations' } },
    { method: 'GET', path: '/api/tickets/11', body: {} },
    { method: 'GET', path: '/api/tickets/11/messages' },
    { method: 'GET', path: '/api/tickets/11%2f..%2fusers' },
  ] satisfies ReadRequestPlan[])('denies requests outside the authored operation contract: %j', (plan) => {
    expect(connector.allowRequest(plan)).toBe(false);
  });
  it.each(['evil.example.com', 'helpdesk.gorgias.com', 'https://helpdesk', '../helpdesk', 'helpdesk@evil'])
    ('rejects origin confusion in configuration: %s', (subdomain) => {
      expect(() => createGorgiasConnector(JSON.stringify({ ...config, subdomain }), 'synthetic'))
        .toThrow('CONNECTOR_CONFIGURATION_INVALID');
    });
  it('rejects empty resource grants and unrecognized configuration', () => {
    expect(() => createGorgiasConnector(JSON.stringify({ ...config, allowedTicketIds: [], allowedCustomerIds: [] }), 'synthetic')).toThrow();
    expect(() => createGorgiasConnector(JSON.stringify({ ...config, headers: { Authorization: 'synthetic' } }), 'synthetic')).toThrow();
  });
});
