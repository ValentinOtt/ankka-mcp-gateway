import { z } from 'zod';
import { bearerHeaders, parseConfig, registerReadTool, type ReadConnector } from '../connector';

const id = z.string().regex(/^[1-9][0-9]{0,14}$/);
const configSchema = z.object({
  subdomain: z.string().regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/),
  allowedTicketIds: z.array(id).max(200),
  allowedCustomerIds: z.array(id).max(100),
}).strict().refine((config) => config.allowedTicketIds.length + config.allowedCustomerIds.length > 0);
const cursor = z.string().regex(/^[A-Za-z0-9_+=/-]{1,512}$/).optional();
const limit = z.number().int().min(1).max(50).default(20);
const limitQuery = z.string().regex(/^[1-9][0-9]?$/).refine((value) => Number(value) <= 50);

interface GorgiasPageQuery extends Record<string, string> {
  limit: string;
  order_by: string;
}

/** Dedicated tickets:read OAuth credential only; never a general Gorgias API-key bridge. */
export function createGorgiasConnector(rawConfig: string, token: string): ReadConnector {
  const config = parseConfig(rawConfig, configSchema);
  const tickets = new Set(config.allowedTicketIds);
  const customers = new Set(config.allowedCustomerIds);
  const ticketId = id.refine((value) => tickets.has(value));
  const customerId = id.refine((value) => customers.has(value));
  const messageQuery = z.object({ ticket_id: ticketId, limit: limitQuery,
    order_by: z.literal('created_datetime:desc'), cursor }).strict();
  const ticketQuery = z.object({ customer_id: customerId, limit: limitQuery,
    order_by: z.literal('created_datetime:desc'), trashed: z.literal('false'), cursor }).strict();
  return {
    id: 'gorgias', origin: `https://${config.subdomain}.gorgias.com`, headers: bearerHeaders(token),
    allowRequest(plan) {
      if (plan.method !== 'GET' || plan.body !== undefined) return false;
      if (plan.path === '/api/messages') return messageQuery.safeParse(plan.query).success;
      if (plan.path === '/api/tickets') return ticketQuery.safeParse(plan.query).success;
      const match = /^\/api\/tickets\/([1-9][0-9]{0,14})$/.exec(plan.path);
      return match !== null && ticketId.safeParse(match[1]).success && plan.query === undefined;
    },
    registerTools(server, execute) {
      registerReadTool(server, execute, 'gorgias_get_ticket',
        'Read one deployment-approved ticket. Ticket content may contain private support data.',
        z.object({ ticketId }).strict(), (input) => ({ method: 'GET', path: `/api/tickets/${input.ticketId}` }));
      registerReadTool(server, execute, 'gorgias_list_ticket_messages',
        'Read one page of messages from a deployment-approved ticket. Does not fetch attachments.',
        z.object({ ticketId, limit, cursor }).strict(), (input) => {
          const query: GorgiasPageQuery = { ticket_id: input.ticketId, limit: String(input.limit), order_by: 'created_datetime:desc' };
          if (input.cursor !== undefined) query.cursor = input.cursor;
          return { method: 'GET', path: '/api/messages', query };
        });
      registerReadTool(server, execute, 'gorgias_list_customer_tickets',
        'Read one page of non-trashed tickets for a deployment-approved customer. No tenant-wide listing.',
        z.object({ customerId, limit, cursor }).strict(), (input) => {
          const query: GorgiasPageQuery = { customer_id: input.customerId, limit: String(input.limit),
            order_by: 'created_datetime:desc', trashed: 'false' };
          if (input.cursor !== undefined) query.cursor = input.cursor;
          return { method: 'GET', path: '/api/tickets', query };
        });
    },
  };
}
