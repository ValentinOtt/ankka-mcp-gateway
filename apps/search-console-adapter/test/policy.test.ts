import type { RequestOptions } from "@cloudflare/codemode/mcp";
import { describe, expect, it, vi } from "vitest";

import {
  SEARCH_CONSOLE_LIMITS,
  SearchConsolePolicyError,
  createSearchConsoleRequestHandler,
  parseAllowedSiteUrls,
  parseGoogleBearerAuthorization,
  verifySearchConsoleAuthorization,
} from "../src/policy";

const SYNTHETIC_AUTHORIZATION = "Bearer synthetic-token-a";
const URL_PREFIX_PROPERTY = "https://example.test/";
const DOMAIN_PROPERTY = "sc-domain:example.test";
const ALLOWED_SITES = new Set([URL_PREFIX_PROPERTY, DOMAIN_PROPERTY]);

describe("Search Console request policy", () => {
  it("parses only canonical, unique approved properties", () => {
    expect(
      [...parseAllowedSiteUrls(JSON.stringify([URL_PREFIX_PROPERTY, DOMAIN_PROPERTY]))],
    ).toEqual([URL_PREFIX_PROPERTY, DOMAIN_PROPERTY]);

    for (const invalid of [
      undefined,
      "not-json",
      "[]",
      JSON.stringify([URL_PREFIX_PROPERTY, URL_PREFIX_PROPERTY]),
      JSON.stringify(["https://example.test/no-trailing-slash"]),
      JSON.stringify(["sc-domain:Example.test"]),
    ]) {
      expect(() => parseAllowedSiteUrls(invalid)).toThrowError(
        new SearchConsolePolicyError("ADAPTER_CONFIGURATION_INVALID"),
      );
    }
  });

  it("accepts only a bounded RFC bearer token", () => {
    expect(parseGoogleBearerAuthorization(SYNTHETIC_AUTHORIZATION)).toBe(
      SYNTHETIC_AUTHORIZATION,
    );
    for (const invalid of [
      null,
      "",
      "bearer synthetic-token-a",
      "Bearer too-short",
      "Bearer token with spaces",
      "Bearer token\nsecond-header",
      `Bearer ${"a".repeat(4_100)}`,
    ]) {
      expect(parseGoogleBearerAuthorization(invalid)).toBeUndefined();
    }
  });

  it("verifies access to every approved property before sandbox work starts", async () => {
    const fetcher = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        jsonResponse({
          siteEntry: [
            { siteUrl: URL_PREFIX_PROPERTY, permissionLevel: "siteOwner" },
            { siteUrl: DOMAIN_PROPERTY, permissionLevel: "siteRestrictedUser" },
          ],
        }),
    );

    await expect(
      verifySearchConsoleAuthorization(SYNTHETIC_AUTHORIZATION, ALLOWED_SITES, {
        fetcher,
      }),
    ).resolves.toBeUndefined();

    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe("https://www.googleapis.com/webmasters/v3/sites");
    expect(init?.method).toBe("GET");
    expect(init?.redirect).toBe("error");
    expect(init?.body).toBeUndefined();
    expect([...new Headers(init?.headers).entries()]).toEqual([
      ["accept", "application/json"],
      ["authorization", SYNTHETIC_AUTHORIZATION],
    ]);

    for (const siteEntry of [
      [{ siteUrl: URL_PREFIX_PROPERTY, permissionLevel: "siteOwner" }],
      [
        { siteUrl: URL_PREFIX_PROPERTY, permissionLevel: "siteOwner" },
        { siteUrl: DOMAIN_PROPERTY, permissionLevel: "siteUnverifiedUser" },
      ],
    ]) {
      await expect(
        verifySearchConsoleAuthorization(SYNTHETIC_AUTHORIZATION, ALLOWED_SITES, {
          fetcher: async () => jsonResponse({ siteEntry }),
        }),
      ).rejects.toMatchObject({ code: "UPSTREAM_AUTHORIZATION_FAILED" });
    }
  });

  it("lists only approved properties and constructs minimal outbound headers", async () => {
    const fetcher = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        jsonResponse({
          siteEntry: [
            { siteUrl: URL_PREFIX_PROPERTY, permissionLevel: "siteOwner", ignored: "strip" },
            { siteUrl: "https://other.test/", permissionLevel: "siteOwner" },
          ],
          ignored: "strip",
        }),
    );
    const request = createSearchConsoleRequestHandler(
      SYNTHETIC_AUTHORIZATION,
      ALLOWED_SITES,
      { fetcher },
    );

    await expect(request({ method: "GET", path: "/sites" })).resolves.toEqual({
      siteEntry: [{ siteUrl: URL_PREFIX_PROPERTY, permissionLevel: "siteOwner" }],
    });

    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe("https://www.googleapis.com/webmasters/v3/sites");
    expect(init?.method).toBe("GET");
    expect(init?.redirect).toBe("error");
    expect(init?.body).toBeUndefined();
    expect([...new Headers(init?.headers).entries()]).toEqual([
      ["accept", "application/json"],
      ["authorization", SYNTHETIC_AUTHORIZATION],
    ]);
  });

  it("maps a bounded analytics query to the fixed Google origin", async () => {
    const fetcher = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        jsonResponse({
          rows: [
            {
              clicks: 2,
              impressions: 10,
              ctr: 0.2,
              position: 3,
              ignored: "strip",
            },
          ],
          responseAggregationType: "byProperty",
          metadata: {
            firstIncompleteDate: "2026-07-30",
            firstIncompleteHour: "2026-07-31T14:00:00Z",
            ignored: "strip",
          },
          ignored: "strip",
        }),
    );
    const request = createSearchConsoleRequestHandler(
      SYNTHETIC_AUTHORIZATION,
      ALLOWED_SITES,
      { fetcher },
    );

    await expect(
      request({
        method: "POST",
        path: "/search-analytics/query",
        contentType: "application/json",
        body: {
          siteUrl: DOMAIN_PROPERTY,
          startDate: "2026-07-01",
          endDate: "2026-07-31",
        },
      }),
    ).resolves.toEqual({
      rows: [
        { keys: [], clicks: 2, impressions: 10, ctr: 0.2, position: 3 },
      ],
      responseAggregationType: "byProperty",
      metadata: {
        firstIncompleteDate: "2026-07-30",
        firstIncompleteHour: "2026-07-31T14:00:00Z",
      },
    });

    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe(
      "https://www.googleapis.com/webmasters/v3/sites/sc-domain%3Aexample.test/searchAnalytics/query",
    );
    expect(init?.method).toBe("POST");
    expect(init?.redirect).toBe("error");
    expect([...new Headers(init?.headers).entries()]).toEqual([
      ["accept", "application/json"],
      ["authorization", SYNTHETIC_AUTHORIZATION],
      ["content-type", "application/json"],
    ]);
    expect(JSON.parse(String(init?.body))).toEqual({
      startDate: "2026-07-01",
      endDate: "2026-07-31",
      rowLimit: 1_000,
    });
  });

  it("allows inspection only when the inspected URL belongs to an approved property", async () => {
    const fetcher = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        jsonResponse({
          inspectionResult: {
            inspectionUrl: "https://shop.example.test/product",
            indexStatusResult: {
              verdict: "PASS",
              coverageState: "Submitted and indexed",
              ignored: "strip",
            },
            ignored: "strip",
          },
          ignored: "strip",
        }),
    );
    const request = createSearchConsoleRequestHandler(
      SYNTHETIC_AUTHORIZATION,
      ALLOWED_SITES,
      { fetcher },
    );

    await expect(
      request({
        method: "POST",
        path: "/url-inspection/inspect",
        body: {
          siteUrl: DOMAIN_PROPERTY,
          inspectionUrl: "https://shop.example.test/product",
          languageCode: "en-US",
        },
      }),
    ).resolves.toEqual({
      inspectionResult: {
        inspectionUrl: "https://shop.example.test/product",
        indexStatusResult: {
          verdict: "PASS",
          coverageState: "Submitted and indexed",
        },
      },
    });

    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe("https://searchconsole.googleapis.com/v1/urlInspection/index:inspect");
    expect(JSON.parse(String(init?.body))).toEqual({
      siteUrl: DOMAIN_PROPERTY,
      inspectionUrl: "https://shop.example.test/product",
      languageCode: "en-US",
    });
  });

  it("denies writes, unknown paths, and path-smuggling forms before fetch", async () => {
    const fetcher = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        jsonResponse({}),
    );
    const request = createSearchConsoleRequestHandler(
      SYNTHETIC_AUTHORIZATION,
      ALLOWED_SITES,
      { fetcher },
    );
    const denied: RequestOptions[] = [
      { method: "DELETE", path: "/sites" },
      { method: "POST", path: "/sites" },
      { method: "GET", path: "/webmasters/v3/sites" },
      { method: "GET", path: "https://evil.test/sites" },
      { method: "GET", path: "//evil.test/sites" },
      { method: "GET", path: "/\\evil.test" },
      { method: "GET", path: "/%2e%2e/sites" },
      { method: "GET", path: "/%252e%252e/sites" },
      { method: "GET", path: "/sites?key=synthetic" },
      { method: "GET", path: "/sites#fragment" },
      { method: "GET", path: "/sites\u0000" },
    ];

    for (const options of denied) {
      await expect(request(options)).rejects.toMatchObject({ code: "REQUEST_NOT_ALLOWED" });
    }
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects unexpected request controls and invalid structured bodies", async () => {
    const fetcher = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        jsonResponse({}),
    );
    const request = createSearchConsoleRequestHandler(
      SYNTHETIC_AUTHORIZATION,
      ALLOWED_SITES,
      { fetcher },
    );
    const unexpectedKeyRequest = {
      method: "GET",
      path: "/sites",
      cookie: "sentinel",
    } satisfies RequestOptions & { cookie: string };
    const multibyteFilters = Array.from({ length: 3 }, () => ({
      filters: Array.from({ length: 10 }, () => ({
        dimension: "query",
        expression: "é".repeat(256),
      })),
    }));
    const cyclicBody: CyclicFixture = {};
    cyclicBody.self = cyclicBody;
    const invalid: RequestOptions[] = [
      { method: "GET", path: "/sites", query: { key: "synthetic" } },
      { method: "GET", path: "/sites", rawBody: false },
      unexpectedKeyRequest,
      { method: "GET", path: "/sites", body: {} },
      {
        method: "POST",
        path: "/search-analytics/query",
        contentType: "text/plain",
        body: {},
      },
      {
        method: "POST",
        path: "/search-analytics/query",
        body: {
          siteUrl: "https://other.test/",
          startDate: "2026-07-01",
          endDate: "2026-07-02",
        },
      },
      {
        method: "POST",
        path: "/search-analytics/query",
        body: {
          siteUrl: URL_PREFIX_PROPERTY,
          startDate: "2026-01-01",
          endDate: "2026-08-01",
        },
      },
      {
        method: "POST",
        path: "/search-analytics/query",
        body: {
          siteUrl: URL_PREFIX_PROPERTY,
          startDate: "2026-07-01",
          endDate: "2026-07-02",
          rowLimit: SEARCH_CONSOLE_LIMITS.analyticsRows + 1,
          unexpected: true,
        },
      },
      {
        method: "POST",
        path: "/url-inspection/inspect",
        body: {
          siteUrl: URL_PREFIX_PROPERTY,
          inspectionUrl: "https://example.test.evil.test/product",
        },
      },
      {
        method: "POST",
        path: "/search-analytics/query",
        body: {
          siteUrl: URL_PREFIX_PROPERTY,
          startDate: "2026-07-01",
          endDate: "2026-07-02",
          dimensionFilterGroups: multibyteFilters,
        },
      },
      {
        method: "POST",
        path: "/search-analytics/query",
        body: cyclicBody,
      },
    ];

    for (const options of invalid) {
      await expect(request(options)).rejects.toMatchObject({ code: "REQUEST_INVALID" });
    }
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("enforces the per-execution call budget", async () => {
    const fetcher = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        jsonResponse({ siteEntry: [] }),
    );
    const request = createSearchConsoleRequestHandler(
      SYNTHETIC_AUTHORIZATION,
      ALLOWED_SITES,
      { fetcher },
    );

    for (let index = 0; index < SEARCH_CONSOLE_LIMITS.callsPerExecution; index += 1) {
      await expect(request({ method: "GET", path: "/sites" })).resolves.toEqual({
        siteEntry: [],
      });
    }
    await expect(request({ method: "GET", path: "/sites" })).rejects.toMatchObject({
      code: "REQUEST_BUDGET_EXCEEDED",
    });
    expect(fetcher).toHaveBeenCalledTimes(SEARCH_CONSOLE_LIMITS.callsPerExecution);
  });

  it("rejects oversized or non-JSON upstream responses with fixed codes", async () => {
    const responses = [
      new Response("text", { status: 200, headers: { "Content-Type": "text/plain" } }),
      jsonResponse({ padding: "x".repeat(SEARCH_CONSOLE_LIMITS.responseBytesPerCall) }),
      new Response("{}", { status: 403, headers: { "Content-Type": "application/json" } }),
    ];
    const fetcher = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
        responses.shift() ?? jsonResponse({}),
    );

    for (const code of [
      "UPSTREAM_RESPONSE_REJECTED",
      "UPSTREAM_RESPONSE_REJECTED",
      "UPSTREAM_AUTHORIZATION_FAILED",
    ]) {
      const request = createSearchConsoleRequestHandler(
        SYNTHETIC_AUTHORIZATION,
        ALLOWED_SITES,
        { fetcher },
      );
      await expect(request({ method: "GET", path: "/sites" })).rejects.toMatchObject({ code });
    }
  });

  it("maps response-stream failures to a fixed provider error", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(new Error("sentinel-provider-detail"));
      },
    });
    const request = createSearchConsoleRequestHandler(
      SYNTHETIC_AUTHORIZATION,
      ALLOWED_SITES,
      {
        fetcher: async () =>
          new Response(stream, {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
      },
    );

    await expect(request({ method: "GET", path: "/sites" })).rejects.toEqual(
      new SearchConsolePolicyError("UPSTREAM_UNAVAILABLE"),
    );
  });

  it("keeps concurrent bearer tokens isolated and never forwards inbound headers", async () => {
    const observed: Array<{ authorization: string | null; headers: string[] }> = [];
    const fetcher = vi.fn(
      async (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const headers = new Headers(init?.headers);
        observed.push({
          authorization: headers.get("Authorization"),
          headers: [...headers.keys()],
        });
        await Promise.resolve();
        return jsonResponse({ siteEntry: [] });
      },
    );
    const first = createSearchConsoleRequestHandler(
      "Bearer synthetic-token-a",
      ALLOWED_SITES,
      { fetcher },
    );
    const second = createSearchConsoleRequestHandler(
      "Bearer synthetic-token-b",
      ALLOWED_SITES,
      { fetcher },
    );

    await Promise.all([
      first({ method: "GET", path: "/sites" }),
      second({ method: "GET", path: "/sites" }),
    ]);
    expect(observed).toEqual([
      {
        authorization: "Bearer synthetic-token-a",
        headers: ["accept", "authorization"],
      },
      {
        authorization: "Bearer synthetic-token-b",
        headers: ["accept", "authorization"],
      },
    ]);
  });
});

type JsonFixtureValue = string | number | boolean | null | JsonFixture | JsonFixtureValue[];

interface CyclicFixture {
  self?: CyclicFixture;
}

interface JsonFixture {
  [key: string]: JsonFixtureValue;
}

function jsonResponse(value: JsonFixture): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
