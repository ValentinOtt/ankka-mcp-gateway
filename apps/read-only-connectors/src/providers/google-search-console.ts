import { z } from 'zod';
import { parseConfig, registerReadTool, type ReadConnector, type ReadExecutor } from '../connector';
import { createGoogleAuthorization } from '../google-auth';
import type { ReadRequestPlan } from '../request';

export const GOOGLE_SEARCH_CONSOLE_LIMITS = { sites: 25, dateRangeDays: 93, rows: 250, sitemaps: 1_000 } as const;
const site = z.string().max(263).regex(/^sc-domain:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/u).refine((value) => {
  const domain = value.slice('sc-domain:'.length);
  const labels = domain.split('.');
  return domain.length <= 253 && labels.length >= 2 && /[a-z]/u.test(labels.at(-1) ?? '') &&
    labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label));
});
const configSchema = z.object({
  allowedSites: z.array(site).min(1).max(GOOGLE_SEARCH_CONSOLE_LIMITS.sites)
    .refine((values) => new Set(values).size === values.length),
}).strict();
const date = z.string().regex(/^\d{4}-\d{2}-\d{2}$/u).refine((value) => {
  const parsed = Date.parse(`${value}T00:00:00Z`);
  return Number.isFinite(parsed) && new Date(parsed).toISOString().slice(0, 10) === value;
});
const report = z.enum(['date', 'page', 'query', 'country', 'device']);
const rowLimit = z.number().int().min(1).max(GOOGLE_SEARCH_CONSOLE_LIMITS.rows);
const dates = z.object({ startDate: date, endDate: date });
function boundedDates(value: z.infer<typeof dates>): boolean {
  const days = (Date.parse(value.endDate) - Date.parse(value.startDate)) / 86_400_000 + 1;
  return days >= 1 && days <= GOOGLE_SEARCH_CONSOLE_LIMITS.dateRangeDays;
}
const performanceBody = dates.extend({
  dimensions: z.tuple([report]), type: z.literal('web'), dataState: z.literal('final'),
  rowLimit, startRow: z.literal(0),
}).strict().refine(boundedDates);
const performancePlan = z.object({
  method: z.literal('POST'), path: z.string(), body: performanceBody,
}).strict();
const getPlan = z.object({ method: z.literal('GET'), path: z.string() }).strict();
const permissionLevel = z.enum([
  'siteOwner', 'siteFullUser', 'siteRestrictedUser', 'siteUnverifiedUser',
  'SITE_OWNER', 'SITE_FULL_USER', 'SITE_RESTRICTED_USER', 'SITE_UNVERIFIED_USER',
]).transform((value) => {
  // Legacy endpoint documentation and current discovery use different aliases.
  switch (value) {
    case 'SITE_OWNER': return 'siteOwner';
    case 'SITE_FULL_USER': return 'siteFullUser';
    case 'SITE_RESTRICTED_USER': return 'siteRestrictedUser';
    case 'SITE_UNVERIFIED_USER': return 'siteUnverifiedUser';
    default: return value;
  }
});
const siteResponse = z.object({
  siteUrl: site, permissionLevel,
});
const analyticsResponse = z.object({
  rows: z.array(z.object({
    keys: z.array(z.string().max(2_048)).max(1).default([]),
    clicks: z.number().finite().nonnegative(), impressions: z.number().finite().nonnegative(),
    ctr: z.number().finite().min(0).max(1), position: z.number().finite().nonnegative(),
  })).max(GOOGLE_SEARCH_CONSOLE_LIMITS.rows).default([]),
  responseAggregationType: z.string().max(64).optional(),
  metadata: z.object({ firstIncompleteDate: z.string().max(32).optional(), firstIncompleteHour: z.string().max(64).optional() }).optional(),
});
const count = z.string().regex(/^(?:0|[1-9][0-9]{0,19})$/u);
const sitemapResponse = z.object({
  sitemap: z.array(z.object({
    path: z.string().max(2_048), type: z.string().max(64).optional(),
    lastSubmitted: z.string().max(64).optional(), lastDownloaded: z.string().max(64).optional(),
    isPending: z.boolean().optional(), isSitemapsIndex: z.boolean().optional(),
    warnings: count.optional(), errors: count.optional(),
    contents: z.array(z.object({ type: z.string().max(64).optional(), submitted: count.optional() })).max(10).default([]),
  })).max(GOOGLE_SEARCH_CONSOLE_LIMITS.sitemaps).default([]),
});

/** Domain properties only: URL-prefix properties require a separately reviewed encoded-path boundary. */
export function createGoogleSearchConsoleConnector(rawConfig: string, rawSecret: string): ReadConnector {
  const config = parseConfig(rawConfig, configSchema);
  const paths = new Map(config.allowedSites.map((value) => [`/webmasters/v3/sites/${encodeURIComponent(value)}`, value]));
  function allowedSite(plan: ReadRequestPlan): string | undefined {
    return paths.get(plan.path.replace(/\/(?:searchAnalytics\/query|sitemaps)$/u, ''));
  }
  function allowRequest(plan: ReadRequestPlan): boolean {
    if (allowedSite(plan) === undefined) return false;
    if (plan.path.endsWith('/searchAnalytics/query')) return performancePlan.safeParse(plan).success;
    return getPlan.safeParse(plan).success;
  }
  return {
    id: 'google-search-console', origin: 'https://www.googleapis.com', headers: {},
    authorize: createGoogleAuthorization(rawSecret, 'search-console'), allowRequest,
    registerTools(server, execute) {
      const projected: ReadExecutor = async (plan) => {
        if (!allowRequest(plan)) throw new Error('CONNECTOR_REQUEST_NOT_ALLOWED');
        const requestedSite = allowedSite(plan);
        if (requestedSite === undefined) throw new Error('CONNECTOR_REQUEST_NOT_ALLOWED');
        const response = await execute(plan);
        if (plan.path.endsWith('/searchAnalytics/query')) {
          const input = performancePlan.parse(plan).body;
          const value = analyticsResponse.parse(response);
          if (value.rows.length > input.rowLimit) throw new Error('CONNECTOR_RESPONSE_REJECTED');
          return {
            site: requestedSite, report: input.dimensions[0], startDate: input.startDate, endDate: input.endDate,
            searchType: 'web', dataState: 'final', rowLimit: input.rowLimit, rows: value.rows,
            resultsAreExhaustive: false, rowLimitReached: value.rows.length === input.rowLimit,
            responseAggregationType: value.responseAggregationType ?? null,
            firstIncompleteDate: value.metadata?.firstIncompleteDate ?? null,
            firstIncompleteHour: value.metadata?.firstIncompleteHour ?? null,
          };
        }
        if (plan.path.endsWith('/sitemaps')) {
          const value = sitemapResponse.parse(response);
          return { site: requestedSite, sitemaps: value.sitemap.map((entry) => ({
            path: entry.path, type: entry.type ?? null,
            lastSubmitted: entry.lastSubmitted ?? null, lastDownloaded: entry.lastDownloaded ?? null,
            isPending: entry.isPending ?? null, isSitemapsIndex: entry.isSitemapsIndex ?? null,
            warnings: entry.warnings ?? null, errors: entry.errors ?? null,
            contents: entry.contents.map((content) => ({ type: content.type ?? null, submitted: content.submitted ?? null })),
          })) };
        }
        const value = siteResponse.parse(response);
        if (value.siteUrl !== requestedSite) throw new Error('CONNECTOR_RESPONSE_REJECTED');
        return { siteUrl: value.siteUrl, permissionLevel: value.permissionLevel };
      };
      registerReadTool(server, projected, 'gsc_get_site',
        'Read metadata for an explicitly configured Search Console domain property; URL-prefix properties are unsupported.',
        z.object({ site }).strict(), ({ site: selected }) => ({ method: 'GET', path: `/webmasters/v3/sites/${encodeURIComponent(selected)}` }));
      registerReadTool(server, projected, 'gsc_search_performance',
        'Read up to 250 final web-search rows for at most 93 inclusive Pacific-calendar dates, grouped by one fixed dimension. Results are not exhaustive; no filters or pagination.',
        dates.extend({ site, report, rowLimit: rowLimit.default(100) }).strict().refine(boundedDates),
        ({ site: selected, startDate, endDate, report: dimension, rowLimit: rows }) => ({
          method: 'POST', path: `/webmasters/v3/sites/${encodeURIComponent(selected)}/searchAnalytics/query`,
          body: { startDate, endDate, dimensions: [dimension], type: 'web', dataState: 'final', rowLimit: rows, startRow: 0 },
        }));
      registerReadTool(server, projected, 'gsc_list_sitemaps',
        'Read submitted sitemap metadata for a configured domain property. Does not follow sitemap URLs or expose the deprecated indexed count.',
        z.object({ site }).strict(), ({ site: selected }) => ({ method: 'GET', path: `/webmasters/v3/sites/${encodeURIComponent(selected)}/sitemaps` }));
    },
  };
}
