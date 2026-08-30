import { z } from 'zod';
import { parseConfig, registerReadTool, type ReadConnector, type ReadExecutor } from '../connector';
import { createGoogleAuthorization } from '../google-auth';
import type { ReadRequestPlan } from '../request';

const propertyId = z.string().regex(/^[1-9][0-9]{0,19}$/u);
const configSchema = z.object({
  allowedPropertyIds: z.array(propertyId).min(1).max(25)
    .refine((values) => new Set(values).size === values.length),
}).strict();
const dateFields = { startDate: z.iso.date(), endDate: z.iso.date() };
type ReportDateRange = { startDate: string; endDate: string };
function withinDateRange(value: ReportDateRange): boolean {
  const days = (Date.parse(value.endDate) - Date.parse(value.startDate)) / 86_400_000;
  return days >= 0 && days < 93;
}
const dateRange = z.object(dateFields).strict().refine(withinDateRange);
const dailyBody = z.object({
  dimensions: z.tuple([z.object({ name: z.literal('date') }).strict()]),
  metrics: z.tuple([
    z.object({ name: z.literal('sessions') }).strict(),
    z.object({ name: z.literal('activeUsers') }).strict(),
    z.object({ name: z.literal('screenPageViews') }).strict(),
  ]),
  dateRanges: z.tuple([dateRange]),
  limit: z.string().regex(/^(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|250)$/u),
}).strict();
const realtimeBody = z.object({
  dimensions: z.tuple([z.object({ name: z.literal('deviceCategory') }).strict()]),
  metrics: z.tuple([z.object({ name: z.literal('activeUsers') }).strict()]),
  minuteRanges: z.tuple([z.object({ startMinutesAgo: z.literal(29), endMinutesAgo: z.literal(0) }).strict()]),
  limit: z.string().regex(/^(?:[1-9]|[1-4][0-9]|50)$/u),
}).strict();
const dailyPlan = z.object({ method: z.literal('POST'), path: z.string(), body: dailyBody }).strict();
const realtimePlan = z.object({ method: z.literal('POST'), path: z.string(), body: realtimeBody }).strict();

// GA4 encodes metric values as strings; do not lose integer precision.
const metricValue = z.object({ value: z.string().regex(/^[0-9]{1,32}$/u) });
const metricType = z.literal('TYPE_INTEGER');
const dailyResponse = z.object({
  dimensionHeaders: z.tuple([z.object({ name: z.literal('date') })]),
  metricHeaders: z.tuple([
    z.object({ name: z.literal('sessions'), type: metricType }),
    z.object({ name: z.literal('activeUsers'), type: metricType }),
    z.object({ name: z.literal('screenPageViews'), type: metricType }),
  ]),
  rows: z.array(z.object({
    dimensionValues: z.tuple([z.object({ value: z.string().regex(/^[0-9]{8}$/u) })]),
    metricValues: z.tuple([metricValue, metricValue, metricValue]),
  })).max(250).default([]),
  rowCount: z.number().int().nonnegative().default(0),
  metadata: z.object({
    timeZone: z.string().max(128).optional(),
    currencyCode: z.string().regex(/^[A-Z]{3}$/u).optional(),
    dataLossFromOtherRow: z.boolean().optional(),
    subjectToThresholding: z.boolean().optional(),
    emptyReason: z.string().max(2_048).optional(),
    samplingMetadatas: z.array(z.object({
      samplesReadCount: z.string().regex(/^[0-9]{1,32}$/u),
      samplingSpaceSize: z.string().regex(/^[0-9]{1,32}$/u),
    })).max(1).optional(),
  }).optional(),
});
const realtimeResponse = z.object({
  dimensionHeaders: z.tuple([z.object({ name: z.literal('deviceCategory') })]),
  metricHeaders: z.tuple([z.object({ name: z.literal('activeUsers'), type: metricType })]),
  rows: z.array(z.object({
    dimensionValues: z.tuple([z.object({ value: z.string().max(256) })]),
    metricValues: z.tuple([metricValue]),
  })).max(50).default([]),
  rowCount: z.number().int().nonnegative().default(0),
});

export function createGoogleAnalyticsConnector(rawConfig: string, rawSecret: string): ReadConnector {
  const config = parseConfig(rawConfig, configSchema);
  const properties = new Set(config.allowedPropertyIds);
  const authorize = createGoogleAuthorization(rawSecret, 'google-analytics');

  function allowRequest(plan: ReadRequestPlan): boolean {
    const matched = /^\/v1beta\/properties\/([1-9][0-9]{0,19}):(runReport|runRealtimeReport)$/u.exec(plan.path);
    if (matched === null || !properties.has(matched[1] ?? '')) return false;
    return matched[2] === 'runReport' ? dailyPlan.safeParse(plan).success : realtimePlan.safeParse(plan).success;
  }

  return {
    id: 'google-analytics', origin: 'https://analyticsdata.googleapis.com', headers: {}, authorize, allowRequest,
    registerTools(server, execute) {
      const projectedExecute: ReadExecutor = async (plan) => {
        if (!allowRequest(plan)) throw new Error('CONNECTOR_REQUEST_NOT_ALLOWED');
        const value = await execute(plan);
        if (plan.path.endsWith(':runRealtimeReport')) {
          const request = realtimePlan.parse(plan);
          const report = realtimeResponse.parse(value);
          if (report.rows.length > Number(request.body.limit) || report.rowCount < report.rows.length) {
            throw new Error('CONNECTOR_RESPONSE_REJECTED');
          }
          return report;
        }
        const request = dailyPlan.parse(plan);
        const report = dailyResponse.parse(value);
        if (report.rows.length > Number(request.body.limit) || report.rowCount < report.rows.length) {
          throw new Error('CONNECTOR_RESPONSE_REJECTED');
        }
        return {
          dimensionHeaders: report.dimensionHeaders,
          metricHeaders: report.metricHeaders,
          rows: report.rows,
          rowCount: report.rowCount,
          metadata: {
            timeZone: report.metadata?.timeZone ?? null,
            currencyCode: report.metadata?.currencyCode ?? null,
            dataLossFromOtherRow: report.metadata?.dataLossFromOtherRow ?? null,
            subjectToThresholding: report.metadata?.subjectToThresholding ?? null,
            emptyReason: report.metadata?.emptyReason ?? null,
            samplingMetadatas: report.metadata?.samplingMetadatas ?? [],
          },
        };
      };
      registerReadTool(server, projectedExecute, 'google_analytics_daily_traffic',
        'Read daily sessions, active users, and page/screen views for a configured GA4 property over at most 93 calendar days. Dates use the property timezone; capped results are not a complete export. No arbitrary reports, filters, or pagination.',
        z.object({ propertyId, ...dateFields, limit: z.number().int().min(1).max(250).default(250) })
          .strict().refine(withinDateRange),
        ({ propertyId: selected, startDate, endDate, limit }) => ({
          method: 'POST', path: `/v1beta/properties/${selected}:runReport`,
          body: {
            dimensions: [{ name: 'date' }],
            metrics: [{ name: 'sessions' }, { name: 'activeUsers' }, { name: 'screenPageViews' }],
            dateRanges: [{ startDate, endDate }], limit: String(limit),
          },
        }));
      registerReadTool(server, projectedExecute, 'google_analytics_realtime_by_device',
        'Read active users by device category for a configured GA4 property over the last 30 minutes. Returns one bounded report without custom dimensions, filters, or pagination.',
        z.object({ propertyId, limit: z.number().int().min(1).max(50).default(50) }).strict(),
        ({ propertyId: selected, limit }) => ({
          method: 'POST', path: `/v1beta/properties/${selected}:runRealtimeReport`,
          body: {
            dimensions: [{ name: 'deviceCategory' }], metrics: [{ name: 'activeUsers' }],
            minuteRanges: [{ startMinutesAgo: 29, endMinutesAgo: 0 }], limit: String(limit),
          },
        }));
    },
  };
}
