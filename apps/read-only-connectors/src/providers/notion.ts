import { z } from 'zod';
import { bearerHeaders, parseConfig, registerReadTool, type ReadConnector } from '../connector';
import type { ReadRequestPlan } from '../request';

// Reviewed data-source API revision; do not inherit the provider's latest default.
export const NOTION_API_VERSION = '2025-09-03';
const id = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u);
const ids = z.array(id).max(128).refine((values) => new Set(values).size === values.length);
const cursor = z.string().min(1).max(256).regex(/^[A-Za-z0-9+/=_-]+$/u);
const pageSize = z.number().int().min(1).max(50).default(25);
const configSchema = z.object({
  allowedPageIds: ids.default([]),
  allowedDataSourceIds: ids.default([]),
}).strict().refine((value) => value.allowedPageIds.length + value.allowedDataSourceIds.length > 0);
const noQuery = z.object({ method: z.literal('GET'), path: z.string() }).strict();
const pagination = z.object({
  page_size: z.string().regex(/^(?:[1-9]|[1-4][0-9]|50)$/u),
  start_cursor: cursor.optional(),
}).strict();
const blockRead = z.object({ method: z.literal('GET'), path: z.string(), query: pagination }).strict();
const sourceQuery = z.object({
  method: z.literal('POST'),
  path: z.string(),
  body: z.object({ page_size: z.number().int().min(1).max(50), start_cursor: cursor.optional() }).strict(),
}).strict();
type NotionPagination = { page_size: string; start_cursor?: string };
type NotionQueryBody = z.infer<typeof sourceQuery>['body'];

export function createNotionConnector(rawConfig: string, token: string): ReadConnector {
  const config = parseConfig(rawConfig, configSchema);
  const pages = new Set(config.allowedPageIds);
  const sources = new Set(config.allowedDataSourceIds);

  function allowRequest(plan: ReadRequestPlan): boolean {
    const page = /^\/v1\/pages\/([^/]+)$/u.exec(plan.path);
    if (page) return noQuery.safeParse(plan).success && pages.has(page[1] ?? '');
    const blocks = /^\/v1\/blocks\/([^/]+)\/children$/u.exec(plan.path);
    if (blocks) return blockRead.safeParse(plan).success && pages.has(blocks[1] ?? '');
    const source = /^\/v1\/data_sources\/([^/]+)$/u.exec(plan.path);
    if (source) return noQuery.safeParse(plan).success && sources.has(source[1] ?? '');
    const query = /^\/v1\/data_sources\/([^/]+)\/query$/u.exec(plan.path);
    return query !== null && sourceQuery.safeParse(plan).success && sources.has(query[1] ?? '');
  }

  return {
    id: 'notion',
    origin: 'https://api.notion.com',
    headers: { ...bearerHeaders(token), 'Notion-Version': NOTION_API_VERSION },
    allowRequest,
    registerTools(server, execute) {
      registerReadTool(server, execute, 'notion_get_page',
        'Read metadata and properties of an explicitly configured Notion page.',
        z.object({ pageId: id }).strict(),
        ({ pageId }) => ({ method: 'GET', path: `/v1/pages/${pageId}` }));
      registerReadTool(server, execute, 'notion_list_page_blocks',
        'Read one bounded page of top-level content blocks from a configured Notion page. Does not follow child blocks or URLs.',
        z.object({ pageId: id, pageSize, startCursor: cursor.optional() }).strict(),
        ({ pageId, pageSize: size, startCursor }) => {
          const query: NotionPagination = { page_size: String(size) };
          if (startCursor !== undefined) query.start_cursor = startCursor;
          return { method: 'GET', path: `/v1/blocks/${pageId}/children`, query };
        });
      registerReadTool(server, execute, 'notion_get_data_source',
        'Read the schema and metadata of an explicitly configured Notion data source.',
        z.object({ dataSourceId: id }).strict(),
        ({ dataSourceId }) => ({ method: 'GET', path: `/v1/data_sources/${dataSourceId}` }));
      registerReadTool(server, execute, 'notion_list_data_source_pages',
        'Read one bounded page of rows from a configured Notion data source, without arbitrary filters or sorts.',
        z.object({ dataSourceId: id, pageSize, startCursor: cursor.optional() }).strict(),
        ({ dataSourceId, pageSize: size, startCursor }) => {
          const body: NotionQueryBody = { page_size: size };
          if (startCursor !== undefined) body.start_cursor = startCursor;
          return { method: 'POST', path: `/v1/data_sources/${dataSourceId}/query`, body };
        });
    },
  };
}
