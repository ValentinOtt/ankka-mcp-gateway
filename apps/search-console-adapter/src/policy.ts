import type { RequestOptions } from "@cloudflare/codemode/mcp";
import { z } from "zod";

export const GOOGLE_SEARCH_CONSOLE_READONLY_SCOPE =
  "https://www.googleapis.com/auth/webmasters.readonly";

export const SEARCH_CONSOLE_LIMITS = {
  approvedSites: 25,
  authorizationCallsPerRequest: 1,
  callsPerExecution: 4,
  concurrentCalls: 2,
  executionMilliseconds: 20_000,
  upstreamCallMilliseconds: 8_000,
  requestBytes: 16_384,
  responseBytesPerCall: 524_288,
  responseBytesPerExecution: 1_048_576,
  analyticsRows: 2_500,
  analyticsDateRangeDays: 93,
} as const;

export const SEARCH_CONSOLE_OPERATIONS = [
  {
    operationId: "listApprovedSites",
    method: "GET",
    path: "/sites",
    upstreamOrigin: "https://www.googleapis.com",
    upstreamPath: "/webmasters/v3/sites",
  },
  {
    operationId: "querySearchAnalytics",
    method: "POST",
    path: "/search-analytics/query",
    upstreamOrigin: "https://www.googleapis.com",
    upstreamPath: "/webmasters/v3/sites/{siteUrl}/searchAnalytics/query",
  },
  {
    operationId: "inspectUrlIndexStatus",
    method: "POST",
    path: "/url-inspection/inspect",
    upstreamOrigin: "https://searchconsole.googleapis.com",
    upstreamPath: "/v1/urlInspection/index:inspect",
  },
] as const;

export const SEARCH_CONSOLE_POLICY_DESCRIPTOR = {
  revision: 1,
  oauthScope: GOOGLE_SEARCH_CONSOLE_READONLY_SCOPE,
  operations: SEARCH_CONSOLE_OPERATIONS,
  limits: SEARCH_CONSOLE_LIMITS,
  sandboxGlobalOutbound: null,
} as const;

export const SEARCH_CONSOLE_POLICY_SHA256 =
  "d3bc57acfc9b21da67341c1bcd7ddf18de84e3e05caae78785804ae523085a75";

const POLICY_ERROR_CODES = [
  "ADAPTER_CONFIGURATION_INVALID",
  "REQUEST_NOT_ALLOWED",
  "REQUEST_INVALID",
  "REQUEST_BUDGET_EXCEEDED",
  "UPSTREAM_AUTHORIZATION_FAILED",
  "UPSTREAM_RATE_LIMITED",
  "UPSTREAM_RESPONSE_REJECTED",
  "UPSTREAM_UNAVAILABLE",
] as const;

type PolicyErrorCode = (typeof POLICY_ERROR_CODES)[number];

export class SearchConsolePolicyError extends Error {
  readonly code: PolicyErrorCode;

  constructor(code: PolicyErrorCode) {
    super(code);
    this.name = "SearchConsolePolicyError";
    this.code = code;
  }
}

const jsonValueSchema = z.json();
type JsonValue = z.infer<typeof jsonValueSchema>;

const propertyUrlSchema = z
  .string()
  .min(1)
  .max(2048)
  .refine(isCanonicalSearchConsoleProperty);

const dateSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/u)
  .refine((value) => parseIsoDate(value) !== undefined);

const analyticsDimensionSchema = z.enum([
  "country",
  "date",
  "device",
  "hour",
  "page",
  "query",
  "searchAppearance",
]);

const filterDimensionSchema = z.enum([
  "country",
  "device",
  "page",
  "query",
  "searchAppearance",
]);

const dimensionFilterSchema = z
  .object({
    dimension: filterDimensionSchema,
    operator: z
      .enum([
        "contains",
        "equals",
        "excludingRegex",
        "includingRegex",
        "notContains",
        "notEquals",
      ])
      .optional(),
    expression: z.string().min(1).max(256),
  })
  .strict();

const dimensionFilterGroupSchema = z
  .object({
    groupType: z.literal("and").optional(),
    filters: z.array(dimensionFilterSchema).min(1).max(10),
  })
  .strict();

const searchAnalyticsRequestSchema = z
  .object({
    siteUrl: propertyUrlSchema,
    startDate: dateSchema,
    endDate: dateSchema,
    dimensions: z
      .array(analyticsDimensionSchema)
      .max(5)
      .refine((dimensions) => new Set(dimensions).size === dimensions.length)
      .optional(),
    type: z
      .enum(["discover", "googleNews", "image", "news", "video", "web"])
      .optional(),
    aggregationType: z
      .enum(["auto", "byNewsShowcasePanel", "byPage", "byProperty"])
      .optional(),
    dataState: z.enum(["all", "final", "hourly_all"]).optional(),
    rowLimit: z.number().int().min(1).max(SEARCH_CONSOLE_LIMITS.analyticsRows).optional(),
    startRow: z.number().int().min(0).max(100_000).optional(),
    dimensionFilterGroups: z.array(dimensionFilterGroupSchema).max(3).optional(),
  })
  .strict()
  .refine(
    ({ startDate, endDate }) => {
      const start = parseIsoDate(startDate);
      const end = parseIsoDate(endDate);
      if (start === undefined || end === undefined || start > end) {
        return false;
      }
      const inclusiveDays = Math.floor((end - start) / 86_400_000) + 1;
      return inclusiveDays <= SEARCH_CONSOLE_LIMITS.analyticsDateRangeDays;
    },
    { path: ["endDate"] },
  );

type SearchAnalyticsRequest = z.infer<typeof searchAnalyticsRequestSchema>;
type SearchAnalyticsUpstreamRequest = Omit<SearchAnalyticsRequest, "siteUrl"> & {
  rowLimit: number;
};

const languageCodeSchema = z
  .string()
  .min(2)
  .max(35)
  .regex(/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/u);

const urlInspectionRequestSchema = z
  .object({
    inspectionUrl: z.url().max(2048),
    siteUrl: propertyUrlSchema,
    languageCode: languageCodeSchema.optional(),
  })
  .strict();

type UrlInspectionRequest = z.infer<typeof urlInspectionRequestSchema>;
type GoogleRequestBody = SearchAnalyticsUpstreamRequest | UrlInspectionRequest;

const siteListResponseSchema = z
  .object({
    siteEntry: z
      .array(
        z
          .object({
            siteUrl: z.string().max(2048),
            permissionLevel: z.string().max(64).optional(),
          })
          .passthrough(),
      )
      .max(10_000)
      .optional(),
  })
  .passthrough();

const searchAnalyticsResponseSchema = z
  .object({
    rows: z
      .array(
        z
          .object({
            keys: z.array(z.string().max(2048)).max(5).optional(),
            clicks: z.number().finite(),
            impressions: z.number().finite(),
            ctr: z.number().finite(),
            position: z.number().finite(),
          })
          .passthrough(),
      )
      .max(SEARCH_CONSOLE_LIMITS.analyticsRows)
      .optional(),
    responseAggregationType: z.string().max(64).optional(),
    metadata: z
      .object({
        firstIncompleteDate: z.string().max(32).optional(),
        firstIncompleteHour: z.string().max(64).optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough();

const boundedProviderString = z.string().max(4096);
const boundedProviderStringArray = z.array(boundedProviderString).max(50);

const urlInspectionResponseSchema = z
  .object({
    inspectionResult: z
      .object({
        inspectionUrl: z.url().max(2048).optional(),
        indexStatusResult: z
          .object({
            verdict: boundedProviderString.optional(),
            coverageState: boundedProviderString.optional(),
            robotsTxtState: boundedProviderString.optional(),
            indexingState: boundedProviderString.optional(),
            lastCrawlTime: boundedProviderString.optional(),
            pageFetchState: boundedProviderString.optional(),
            googleCanonical: boundedProviderString.optional(),
            userCanonical: boundedProviderString.optional(),
            referringUrls: boundedProviderStringArray.optional(),
            sitemap: boundedProviderStringArray.optional(),
            crawledAs: boundedProviderString.optional(),
          })
          .strip()
          .optional(),
        mobileUsabilityResult: z
          .object({
            verdict: boundedProviderString.optional(),
            issues: z
              .array(
                z
                  .object({
                    issueType: boundedProviderString.optional(),
                    severity: boundedProviderString.optional(),
                    message: boundedProviderString.optional(),
                  })
                  .strip(),
              )
              .max(50)
              .optional(),
          })
          .strip()
          .optional(),
        richResultsResult: z
          .object({
            verdict: boundedProviderString.optional(),
            detectedItems: z
              .array(
                z
                  .object({
                    richResultType: boundedProviderString.optional(),
                    items: z
                      .array(
                        z
                          .object({
                            name: boundedProviderString.optional(),
                            issues: z
                              .array(
                                z
                                  .object({
                                    issueMessage: boundedProviderString.optional(),
                                    severity: boundedProviderString.optional(),
                                  })
                                  .strip(),
                              )
                              .max(50)
                              .optional(),
                          })
                          .strip(),
                      )
                      .max(50)
                      .optional(),
                  })
                  .strip(),
              )
              .max(50)
              .optional(),
          })
          .strip()
          .optional(),
      })
      .strip(),
  })
  .strip();

interface ApprovedSite {
  siteUrl: string;
  permissionLevel?: string;
}

interface ApprovedSitesResult {
  siteEntry: ApprovedSite[];
}

interface SearchAnalyticsRow {
  keys: string[];
  clicks: number;
  impressions: number;
  ctr: number;
  position: number;
}

interface SearchAnalyticsMetadata {
  firstIncompleteDate?: string;
  firstIncompleteHour?: string;
}

interface SearchAnalyticsResult {
  rows: SearchAnalyticsRow[];
  responseAggregationType?: string;
  metadata?: SearchAnalyticsMetadata;
}

type UrlInspectionResult = z.infer<typeof urlInspectionResponseSchema>;
type SearchConsoleResult = ApprovedSitesResult | SearchAnalyticsResult | UrlInspectionResult;

type Fetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

interface RequestState {
  calls: number;
  inFlight: number;
  responseBytes: number;
  startedAt: number;
}

interface HandlerDependencies {
  fetcher?: Fetcher;
  now?: () => number;
}

type UntrustedRequestBody = RequestOptions["body"];

const requestEnvelopeSchema = z
  .object({
    method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
    path: z.string().min(1).max(2048),
    query: z
      .record(
        z.string(),
        z.union([z.string(), z.number().finite(), z.boolean(), z.undefined()]),
      )
      .optional(),
    body: jsonValueSchema.optional(),
    contentType: z.string().max(128).optional(),
    rawBody: z.boolean().optional(),
  })
  .strict();

type RequestEnvelope = z.infer<typeof requestEnvelopeSchema>;

export function parseAllowedSiteUrls(serialized: string | undefined): ReadonlySet<string> {
  if (serialized === undefined || serialized.length > 65_536) {
    throw new SearchConsolePolicyError("ADAPTER_CONFIGURATION_INVALID");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new SearchConsolePolicyError("ADAPTER_CONFIGURATION_INVALID");
  }

  const result = z
    .array(propertyUrlSchema)
    .min(1)
    .max(SEARCH_CONSOLE_LIMITS.approvedSites)
    .safeParse(parsed);
  if (!result.success || new Set(result.data).size !== result.data.length) {
    throw new SearchConsolePolicyError("ADAPTER_CONFIGURATION_INVALID");
  }
  return new Set(result.data);
}

export function parseGoogleBearerAuthorization(value: string | null): string | undefined {
  if (value === null || value.length > 4_103) {
    return undefined;
  }
  const match = /^Bearer ([A-Za-z0-9\-._~+/]+={0,2})$/u.exec(value);
  const tokenLength = match?.[1]?.length ?? 0;
  return tokenLength >= 16 && tokenLength <= 4_096 ? value : undefined;
}

export async function verifySearchConsoleAuthorization(
  authorization: string,
  allowedSiteUrls: ReadonlySet<string>,
  dependencies: HandlerDependencies = {},
): Promise<void> {
  const fetcher = dependencies.fetcher ?? fetch;
  const now = dependencies.now ?? Date.now;
  const response = await callGoogle(
    "https://www.googleapis.com/webmasters/v3/sites",
    "GET",
    authorization,
    undefined,
    createRequestState(now),
    fetcher,
    now,
  );
  const parsed = siteListResponseSchema.safeParse(response);
  if (!parsed.success) {
    throw new SearchConsolePolicyError("UPSTREAM_RESPONSE_REJECTED");
  }

  const readableSites = new Set(
    (parsed.data.siteEntry ?? [])
      .filter(({ permissionLevel }) =>
        permissionLevel === "siteOwner" ||
        permissionLevel === "siteFullUser" ||
        permissionLevel === "siteRestrictedUser",
      )
      .map(({ siteUrl }) => siteUrl),
  );
  if ([...allowedSiteUrls].some((siteUrl) => !readableSites.has(siteUrl))) {
    throw new SearchConsolePolicyError("UPSTREAM_AUTHORIZATION_FAILED");
  }
}

export function createSearchConsoleRequestHandler(
  authorization: string,
  allowedSiteUrls: ReadonlySet<string>,
  dependencies: HandlerDependencies = {},
): (options: RequestOptions) => Promise<SearchConsoleResult> {
  const fetcher = dependencies.fetcher ?? fetch;
  const now = dependencies.now ?? Date.now;
  const state = createRequestState(now);

  return async (options) => {
    const request = parseRequestEnvelope(options);

    if (request.method === "GET" && request.path === "/sites") {
      assertNoRequestPayload(request);
      const response = await callGoogle(
        "https://www.googleapis.com/webmasters/v3/sites",
        "GET",
        authorization,
        undefined,
        state,
        fetcher,
        now,
      );
      return projectSites(response, allowedSiteUrls);
    }

    if (request.method === "POST" && request.path === "/search-analytics/query") {
      assertJsonRequest(request);
      const parsed = searchAnalyticsRequestSchema.safeParse(request.body);
      if (!parsed.success || !allowedSiteUrls.has(parsed.data.siteUrl)) {
        throw new SearchConsolePolicyError("REQUEST_INVALID");
      }

      const { siteUrl, ...googleBody } = parsed.data;
      const body = {
        ...googleBody,
        rowLimit: googleBody.rowLimit ?? 1_000,
      };
      assertRequestBodySize(body);
      const response = await callGoogle(
        `https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(siteUrl)}/searchAnalytics/query`,
        "POST",
        authorization,
        body,
        state,
        fetcher,
        now,
      );
      return projectSearchAnalytics(response);
    }

    if (request.method === "POST" && request.path === "/url-inspection/inspect") {
      assertJsonRequest(request);
      const parsed = urlInspectionRequestSchema.safeParse(request.body);
      if (
        !parsed.success ||
        !allowedSiteUrls.has(parsed.data.siteUrl) ||
        !isUrlWithinProperty(parsed.data.inspectionUrl, parsed.data.siteUrl)
      ) {
        throw new SearchConsolePolicyError("REQUEST_INVALID");
      }

      assertRequestBodySize(parsed.data);
      const response = await callGoogle(
        "https://searchconsole.googleapis.com/v1/urlInspection/index:inspect",
        "POST",
        authorization,
        parsed.data,
        state,
        fetcher,
        now,
      );
      return projectUrlInspection(response, parsed.data.siteUrl);
    }

    throw new SearchConsolePolicyError("REQUEST_NOT_ALLOWED");
  };
}

function parseRequestEnvelope(options: RequestOptions): RequestEnvelope {
  const candidate: RequestOptions = { ...options };
  if (options.body !== undefined) {
    candidate.body = parseBoundedRequestBody(options.body);
  }
  const parsed = requestEnvelopeSchema.safeParse(candidate);
  if (
    !parsed.success ||
    parsed.data.query !== undefined ||
    parsed.data.rawBody !== undefined
  ) {
    throw new SearchConsolePolicyError("REQUEST_INVALID");
  }
  return parsed.data;
}

function parseBoundedRequestBody(body: UntrustedRequestBody): JsonValue {
  let serialized: string | undefined;
  try {
    serialized = JSON.stringify(body);
  } catch {
    throw new SearchConsolePolicyError("REQUEST_INVALID");
  }
  if (
    serialized === undefined ||
    new TextEncoder().encode(serialized).byteLength > SEARCH_CONSOLE_LIMITS.requestBytes
  ) {
    throw new SearchConsolePolicyError("REQUEST_INVALID");
  }
  try {
    return jsonValueSchema.parse(JSON.parse(serialized));
  } catch {
    throw new SearchConsolePolicyError("REQUEST_INVALID");
  }
}

function assertNoRequestPayload(options: RequestEnvelope): void {
  if (options.body !== undefined || options.contentType !== undefined) {
    throw new SearchConsolePolicyError("REQUEST_INVALID");
  }
}

function assertJsonRequest(options: RequestEnvelope): void {
  if (
    options.body === undefined ||
    (options.contentType !== undefined && options.contentType !== "application/json")
  ) {
    throw new SearchConsolePolicyError("REQUEST_INVALID");
  }
}

function assertRequestBodySize(body: GoogleRequestBody): void {
  let serialized: string;
  try {
    serialized = JSON.stringify(body);
  } catch {
    throw new SearchConsolePolicyError("REQUEST_INVALID");
  }
  if (new TextEncoder().encode(serialized).byteLength > SEARCH_CONSOLE_LIMITS.requestBytes) {
    throw new SearchConsolePolicyError("REQUEST_INVALID");
  }
}

function createRequestState(now: () => number): RequestState {
  return {
    calls: 0,
    inFlight: 0,
    responseBytes: 0,
    startedAt: now(),
  };
}

async function callGoogle(
  url: string,
  method: "GET" | "POST",
  authorization: string,
  body: GoogleRequestBody | undefined,
  state: RequestState,
  fetcher: Fetcher,
  now: () => number,
): Promise<JsonValue> {
  if (
    state.calls >= SEARCH_CONSOLE_LIMITS.callsPerExecution ||
    state.inFlight >= SEARCH_CONSOLE_LIMITS.concurrentCalls ||
    now() - state.startedAt >= SEARCH_CONSOLE_LIMITS.executionMilliseconds
  ) {
    throw new SearchConsolePolicyError("REQUEST_BUDGET_EXCEEDED");
  }

  state.calls += 1;
  state.inFlight += 1;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SEARCH_CONSOLE_LIMITS.upstreamCallMilliseconds);

  try {
    const headers = new Headers({
      Accept: "application/json",
      Authorization: authorization,
    });
    if (body !== undefined) {
      headers.set("Content-Type", "application/json");
    }

    let response: Response;
    try {
      const requestInit: RequestInit = {
        method,
        headers,
        redirect: "error",
        signal: controller.signal,
      };
      if (body !== undefined) {
        requestInit.body = JSON.stringify(body);
      }
      response = await fetcher(url, requestInit);
    } catch {
      throw new SearchConsolePolicyError("UPSTREAM_UNAVAILABLE");
    }

    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        throw new SearchConsolePolicyError("UPSTREAM_AUTHORIZATION_FAILED");
      }
      if (response.status === 429) {
        throw new SearchConsolePolicyError("UPSTREAM_RATE_LIMITED");
      }
      throw new SearchConsolePolicyError("UPSTREAM_UNAVAILABLE");
    }

    try {
      return await readBoundedJson(response, state);
    } catch (error) {
      if (error instanceof SearchConsolePolicyError) {
        throw error;
      }
      throw new SearchConsolePolicyError("UPSTREAM_UNAVAILABLE");
    }
  } finally {
    clearTimeout(timer);
    state.inFlight -= 1;
  }
}

async function readBoundedJson(response: Response, state: RequestState): Promise<JsonValue> {
  const contentType = response.headers.get("Content-Type") ?? "";
  if (!/^application\/json(?:\s*;|$)/iu.test(contentType)) {
    throw new SearchConsolePolicyError("UPSTREAM_RESPONSE_REJECTED");
  }

  const contentLength = response.headers.get("Content-Length");
  if (contentLength !== null) {
    const declared = Number(contentLength);
    if (
      !Number.isSafeInteger(declared) ||
      declared < 0 ||
      declared > SEARCH_CONSOLE_LIMITS.responseBytesPerCall ||
      declared + state.responseBytes > SEARCH_CONSOLE_LIMITS.responseBytesPerExecution
    ) {
      throw new SearchConsolePolicyError("UPSTREAM_RESPONSE_REJECTED");
    }
  }

  if (response.body === null) {
    throw new SearchConsolePolicyError("UPSTREAM_RESPONSE_REJECTED");
  }

  const chunks: Uint8Array[] = [];
  let bytes = 0;
  const reader = response.body.getReader();
  while (true) {
    const read = await reader.read();
    if (read.done) {
      break;
    }
    bytes += read.value.byteLength;
    state.responseBytes += read.value.byteLength;
    if (
      bytes > SEARCH_CONSOLE_LIMITS.responseBytesPerCall ||
      state.responseBytes > SEARCH_CONSOLE_LIMITS.responseBytesPerExecution
    ) {
      try {
        await reader.cancel();
      } catch {
        // The fixed policy error below is authoritative even if stream cleanup fails.
      }
      throw new SearchConsolePolicyError("UPSTREAM_RESPONSE_REJECTED");
    }
    chunks.push(read.value);
  }

  const combined = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(combined);
    return jsonValueSchema.parse(JSON.parse(text));
  } catch {
    throw new SearchConsolePolicyError("UPSTREAM_RESPONSE_REJECTED");
  }
}

function projectSites(value: JsonValue, allowedSiteUrls: ReadonlySet<string>): ApprovedSitesResult {
  const parsed = siteListResponseSchema.safeParse(value);
  if (!parsed.success) {
    throw new SearchConsolePolicyError("UPSTREAM_RESPONSE_REJECTED");
  }
  const siteEntry = (parsed.data.siteEntry ?? [])
    .filter(({ siteUrl }) => allowedSiteUrls.has(siteUrl))
    .slice(0, SEARCH_CONSOLE_LIMITS.approvedSites)
    .map(({ siteUrl, permissionLevel }) => {
      const approvedSite: ApprovedSite = { siteUrl };
      if (permissionLevel !== undefined) {
        approvedSite.permissionLevel = permissionLevel;
      }
      return approvedSite;
    });
  return { siteEntry };
}

function projectSearchAnalytics(value: JsonValue): SearchAnalyticsResult {
  const parsed = searchAnalyticsResponseSchema.safeParse(value);
  if (!parsed.success) {
    throw new SearchConsolePolicyError("UPSTREAM_RESPONSE_REJECTED");
  }
  const result: SearchAnalyticsResult = {
    rows: (parsed.data.rows ?? []).map(({ keys, clicks, impressions, ctr, position }) => ({
      keys: keys ?? [],
      clicks,
      impressions,
      ctr,
      position,
    })),
  };
  if (parsed.data.responseAggregationType !== undefined) {
    result.responseAggregationType = parsed.data.responseAggregationType;
  }
  if (parsed.data.metadata !== undefined) {
    const metadata: SearchAnalyticsMetadata = {};
    if (parsed.data.metadata.firstIncompleteDate !== undefined) {
      metadata.firstIncompleteDate = parsed.data.metadata.firstIncompleteDate;
    }
    if (parsed.data.metadata.firstIncompleteHour !== undefined) {
      metadata.firstIncompleteHour = parsed.data.metadata.firstIncompleteHour;
    }
    result.metadata = metadata;
  }
  return result;
}

function projectUrlInspection(value: JsonValue, siteUrl: string): UrlInspectionResult {
  const parsed = urlInspectionResponseSchema.safeParse(value);
  if (
    !parsed.success ||
    (parsed.data.inspectionResult.inspectionUrl !== undefined &&
      !isUrlWithinProperty(parsed.data.inspectionResult.inspectionUrl, siteUrl))
  ) {
    throw new SearchConsolePolicyError("UPSTREAM_RESPONSE_REJECTED");
  }
  return parsed.data;
}

function isCanonicalSearchConsoleProperty(value: string): boolean {
  if (value.startsWith("sc-domain:")) {
    const domain = value.slice("sc-domain:".length);
    return (
      domain === domain.toLowerCase() &&
      domain.length <= 253 &&
      /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(
        domain,
      )
    );
  }

  try {
    const url = new URL(value);
    return (
      (url.protocol === "https:" || url.protocol === "http:") &&
      url.username === "" &&
      url.password === "" &&
      url.search === "" &&
      url.hash === "" &&
      value.endsWith("/") &&
      url.toString() === value
    );
  } catch {
    return false;
  }
}

function isUrlWithinProperty(candidate: string, siteUrl: string): boolean {
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return false;
  }
  if (
    (url.protocol !== "https:" && url.protocol !== "http:") ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== ""
  ) {
    return false;
  }

  if (siteUrl.startsWith("sc-domain:")) {
    const domain = siteUrl.slice("sc-domain:".length);
    const hostname = url.hostname.toLowerCase().replace(/\.$/u, "");
    return hostname === domain || hostname.endsWith(`.${domain}`);
  }

  try {
    const property = new URL(siteUrl);
    return url.origin === property.origin && url.href.startsWith(property.href);
  } catch {
    return false;
  }
}

function parseIsoDate(value: string): number | undefined {
  const timestamp = Date.parse(`${value}T00:00:00.000Z`);
  if (!Number.isFinite(timestamp)) {
    return undefined;
  }
  return new Date(timestamp).toISOString().slice(0, 10) === value ? timestamp : undefined;
}
