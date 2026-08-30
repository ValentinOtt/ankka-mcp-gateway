import { z } from 'zod';
import { bearerHeaders, parseConfig, registerReadTool, type ReadConnector } from '../connector';
import type { ReadRequestPlan } from '../request';

const recordId = z.string().regex(/^[1-9][0-9]{0,19}$/u);
const ids = z.array(recordId).max(128).refine((values) => new Set(values).size === values.length);
const cursor = z.string().min(1).max(512).regex(/^[A-Za-z0-9+/=_-]+$/u);
const pageSize = z.number().int().min(1).max(50).default(25);
const configSchema = z.object({
  // A label, never a URL. The provider suffix is authored here, not supplied by a tool.
  subdomain: z.string().regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u)
    .refine((value) => !['www', 'api', 'support', 'help', 'developer', 'developers'].includes(value)),
  allowedOrganizationIds: ids.default([]),
  allowedTicketIds: ids.default([]),
}).strict().refine((value) => value.allowedOrganizationIds.length + value.allowedTicketIds.length > 0);
const readOne = z.object({ method: z.literal('GET'), path: z.string() }).strict();
const readPage = z.object({
  method: z.literal('GET'), path: z.string(),
  query: z.object({
    'page[size]': z.string().regex(/^(?:[1-9]|[1-4][0-9]|50)$/u),
    'page[after]': cursor.optional(),
  }).strict(),
}).strict();
type ZendeskPageQuery = { 'page[size]': string; 'page[after]'?: string };

function pageQuery(size: number, after: string | undefined): ZendeskPageQuery {
  const query: ZendeskPageQuery = { 'page[size]': String(size) };
  if (after !== undefined) query['page[after]'] = after;
  return query;
}

export function createZendeskConnector(rawConfig: string, token: string): ReadConnector {
  const config = parseConfig(rawConfig, configSchema);
  const organizations = new Set(config.allowedOrganizationIds);
  const tickets = new Set(config.allowedTicketIds);

  function allowRequest(plan: ReadRequestPlan): boolean {
    const organization = /^\/api\/v2\/organizations\/([1-9][0-9]{0,19})$/u.exec(plan.path);
    if (organization) return readOne.safeParse(plan).success && organizations.has(organization[1] ?? '');
    const ticket = /^\/api\/v2\/tickets\/([1-9][0-9]{0,19})$/u.exec(plan.path);
    if (ticket) return readOne.safeParse(plan).success && tickets.has(ticket[1] ?? '');
    const organizationTickets = /^\/api\/v2\/organizations\/([1-9][0-9]{0,19})\/tickets$/u.exec(plan.path);
    if (organizationTickets) return readPage.safeParse(plan).success && organizations.has(organizationTickets[1] ?? '');
    const comments = /^\/api\/v2\/tickets\/([1-9][0-9]{0,19})\/comments$/u.exec(plan.path);
    return comments !== null && readPage.safeParse(plan).success && tickets.has(comments[1] ?? '');
  }

  return {
    id: 'zendesk', origin: `https://${config.subdomain}.zendesk.com`, headers: bearerHeaders(token), allowRequest,
    registerTools(server, execute) {
      registerReadTool(server, execute, 'zendesk_get_organization',
        'Read one explicitly configured Zendesk organization.',
        z.object({ organizationId: recordId }).strict(),
        ({ organizationId }) => ({ method: 'GET', path: `/api/v2/organizations/${organizationId}` }));
      registerReadTool(server, execute, 'zendesk_list_organization_tickets',
        'Read at most 50 tickets belonging to an explicitly configured organization. Does not list tickets across the tenant.',
        z.object({ organizationId: recordId, pageSize, after: cursor.optional() }).strict(),
        ({ organizationId, pageSize: size, after }) => ({
          method: 'GET', path: `/api/v2/organizations/${organizationId}/tickets`,
          query: pageQuery(size, after),
        }));
      registerReadTool(server, execute, 'zendesk_get_ticket',
        'Read a ticket whose exact ID is configured. Organization listing does not automatically grant ticket-detail access.',
        z.object({ ticketId: recordId }).strict(),
        ({ ticketId }) => ({ method: 'GET', path: `/api/v2/tickets/${ticketId}` }));
      registerReadTool(server, execute, 'zendesk_list_ticket_comments',
        'Read one bounded page of comments on an explicitly configured ticket. Attachment URLs are not followed.',
        z.object({ ticketId: recordId, pageSize, after: cursor.optional() }).strict(),
        ({ ticketId, pageSize: size, after }) => ({
          method: 'GET', path: `/api/v2/tickets/${ticketId}/comments`,
          query: pageQuery(size, after),
        }));
    },
  };
}
