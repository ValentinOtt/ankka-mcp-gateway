import { z } from 'zod';
import { bearerHeaders, parseConfig, registerReadTool, type ReadConnector, type ReadExecutor } from '../connector';
import type { ReadRequestPlan } from '../request';

// Tickets are deliberately excluded: the legacy tickets scope is not read-only.
const objectType = z.enum(['contacts', 'companies', 'deals']);
const recordId = z.string().regex(/^[1-9][0-9]{0,19}$/u);
const afterCursor = z.string().regex(/^(?:0|[1-9][0-9]{0,19})$/u);
const propertyName = z.string().regex(/^[a-z][a-z0-9_]{0,99}$/u);
const properties = z.array(propertyName).min(1).max(32)
  .refine((values) => new Set(values).size === values.length);
const configSchema = z.object({
  objectProperties: z.object({
    contacts: properties.optional(), companies: properties.optional(), deals: properties.optional(),
  }).strict().refine((value) => Object.keys(value).length > 0),
}).strict();
const idList = z.array(recordId).min(1).max(25)
  .refine((values) => new Set(values).size === values.length);
const objectQuery = z.object({ properties: z.string(), archived: z.literal('false') }).strict();
const listQuery = objectQuery.extend({
  limit: z.string().regex(/^(?:[1-9]|[1-4][0-9]|50)$/u), after: afterCursor.optional(),
}).strict();
const readOne = z.object({ method: z.literal('GET'), path: z.string(), query: objectQuery }).strict();
const readList = z.object({ method: z.literal('GET'), path: z.string(), query: listQuery }).strict();
const readBatch = z.object({
  method: z.literal('POST'), path: z.string(),
  body: z.object({
    properties,
    inputs: z.array(z.object({ id: recordId }).strict()).min(1).max(25)
      .refine((values) => new Set(values.map((value) => value.id)).size === values.length),
  }).strict(),
}).strict();
const responseRecord = z.object({
  id: recordId,
  properties: z.record(z.string(), z.union([z.string(), z.null()])),
});
const responseList = z.object({
  results: z.array(responseRecord).max(50),
  paging: z.object({ next: z.object({ after: afterCursor }).optional() }).optional(),
});
type HubSpotListQuery = { properties: string; archived: 'false'; limit: string; after?: string };
type HubSpotPage = {
  results: Array<{ id: string; properties: Record<string, string | null> }>;
  nextAfter?: string;
};

export function createHubSpotConnector(rawConfig: string, token: string): ReadConnector {
  const config = parseConfig(rawConfig, configSchema);

  function selectedProperties(path: string): readonly string[] | undefined {
    const matched = /^\/crm\/v3\/objects\/(contacts|companies|deals)(?:\/|$)/u.exec(path);
    const parsed = objectType.safeParse(matched?.[1]);
    return parsed.success ? config.objectProperties[parsed.data] : undefined;
  }

  function allowRequest(plan: ReadRequestPlan): boolean {
    const selected = selectedProperties(plan.path);
    if (!selected) return false;
    if (/^\/crm\/v3\/objects\/(contacts|companies|deals)$/u.test(plan.path)) {
      const parsed = readList.safeParse(plan);
      return parsed.success && parsed.data.query.properties === selected.join(',');
    }
    if (/^\/crm\/v3\/objects\/(contacts|companies|deals)\/[1-9][0-9]{0,19}$/u.test(plan.path)) {
      const parsed = readOne.safeParse(plan);
      return parsed.success && parsed.data.query.properties === selected.join(',');
    }
    if (/^\/crm\/v3\/objects\/(contacts|companies|deals)\/batch\/read$/u.test(plan.path)) {
      const parsed = readBatch.safeParse(plan);
      return parsed.success && parsed.data.body.properties.length === selected.length &&
        parsed.data.body.properties.every((value, index) => value === selected[index]);
    }
    return false;
  }

  function projectRecord(value: z.infer<typeof responseRecord>, selected: readonly string[]) {
    const projected: Record<string, string | null> = {};
    for (const key of selected) {
      const field = value.properties[key];
      if (Object.hasOwn(value.properties, key) && field !== undefined) projected[key] = field;
    }
    return { id: value.id, properties: projected };
  }

  return {
    id: 'hubspot', origin: 'https://api.hubapi.com', headers: bearerHeaders(token), allowRequest,
    registerTools(server, execute) {
      // Provider-added/default properties and association data must not escape
      // the deployment's explicit property selection in successful responses.
      const projectedExecute: ReadExecutor = async (plan) => {
        if (!allowRequest(plan)) throw new Error('CONNECTOR_REQUEST_NOT_ALLOWED');
        const selected = selectedProperties(plan.path);
        if (!selected) throw new Error('CONNECTOR_REQUEST_NOT_ALLOWED');
        const value = await execute(plan);
        if (/\/[1-9][0-9]{0,19}$/u.test(plan.path)) return projectRecord(responseRecord.parse(value), selected);
        const list = responseList.parse(value);
        const result: HubSpotPage = {
          results: list.results.map((record) => projectRecord(record, selected)),
        };
        if (list.paging?.next !== undefined) result.nextAfter = list.paging.next.after;
        return result;
      };
      const queryFor = (type: z.infer<typeof objectType>) => {
        const selected = config.objectProperties[type];
        if (!selected) throw new Error('CONNECTOR_REQUEST_NOT_ALLOWED');
        return { properties: selected.join(','), archived: 'false' } as const;
      };
      registerReadTool(server, projectedExecute, 'hubspot_list_records',
        'Read a bounded page of active contacts, companies, or deals, returning only deployment-approved properties.',
        z.object({ objectType, limit: z.number().int().min(1).max(50).default(25), after: afterCursor.optional() }).strict(),
        ({ objectType: type, limit, after }) => {
          const query: HubSpotListQuery = { ...queryFor(type), limit: String(limit) };
          if (after !== undefined) query.after = after;
          return { method: 'GET', path: `/crm/v3/objects/${type}`, query };
        });
      registerReadTool(server, projectedExecute, 'hubspot_get_record',
        'Read one active CRM record by numeric ID, returning only deployment-approved properties.',
        z.object({ objectType, recordId }).strict(),
        ({ objectType: type, recordId: selectedId }) => ({
          method: 'GET', path: `/crm/v3/objects/${type}/${selectedId}`, query: queryFor(type),
        }));
      registerReadTool(server, projectedExecute, 'hubspot_batch_read_records',
        'Read at most 25 known CRM record IDs, without search filters, associations, or property history.',
        z.object({ objectType, recordIds: idList }).strict(),
        ({ objectType: type, recordIds }) => {
          const selected = config.objectProperties[type];
          if (!selected) throw new Error('CONNECTOR_REQUEST_NOT_ALLOWED');
          return {
            method: 'POST', path: `/crm/v3/objects/${type}/batch/read`,
            body: { properties: selected, inputs: recordIds.map((selectedId) => ({ id: selectedId })) },
          };
        });
    },
  };
}
