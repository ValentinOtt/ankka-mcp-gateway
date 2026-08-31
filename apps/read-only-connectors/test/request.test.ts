import { afterEach, describe, expect, it, vi } from "vitest";

import {
  CONNECTOR_REQUEST_LIMITS,
  ConnectorRequestError,
  executeReadRequest,
  type ConnectorJson,
  type ExecuteReadRequestOptions,
  type ReadRequestPlan,
} from "../src/request";

const ORIGIN = "https://api.example.com";
const HEADERS = { Authorization: "Bearer synthetic-provider-token" };
const GET_PLAN = { method: "GET", path: "/v1/search" } as const;
const allowGet = (plan: ReadRequestPlan): boolean =>
  plan.method === "GET" && plan.path === "/v1/search" && plan.body === undefined;

interface CyclicFixture { self?: CyclicFixture }
interface NestedFixture { child: NestedFixture | null }

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("shared read-only connector outbound boundary", () => {
  it("preserves the global fetch receiver when no custom fetch is injected", async () => {
    const outbound = vi.spyOn(globalThis, "fetch").mockImplementation(async function (this: typeof globalThis | undefined) {
      if (this !== globalThis) throw new TypeError("Illegal invocation");
      return jsonResponse({ rows: [] });
    });
    await expect(executeReadRequest({
      origin: ORIGIN, plan: GET_PLAN, headers: HEADERS, allowRequest: allowGet,
    })).resolves.toEqual({ rows: [] });
    expect(outbound).toHaveBeenCalledOnce();
    expect(outbound).toHaveBeenCalledWith(`${ORIGIN}/v1/search`, expect.objectContaining({
      method: "GET", redirect: "manual", signal: expect.any(AbortSignal),
    }));
  });

  it("does not rebind an injected fetch or fall back to global fetch", async () => {
    const globalFetch = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      throw new Error("Unexpected global fetch");
    });
    const outbound = vi.fn<typeof globalThis.fetch>(async function (this: undefined) {
      expect(this).toBeUndefined();
      return jsonResponse({ rows: [] });
    });
    await expect(runWith(outbound)).resolves.toEqual({ rows: [] });
    expect(outbound).toHaveBeenCalledOnce();
    expect(globalFetch).not.toHaveBeenCalled();
  });

  it("sends one exact destination with only explicit trusted headers and encoded query values", async () => {
    const fetcher = vi.fn<typeof globalThis.fetch>(async () => jsonResponse({ rows: [] }));
    await expect(executeReadRequest({
      origin: ORIGIN,
      plan: {
        ...GET_PLAN,
        query: { q: "name=a&after=b", cursor: "opaque/../value?x#y", limit: "25" },
      },
      headers: HEADERS,
      allowRequest: allowGet,
      fetch: fetcher,
    })).resolves.toEqual({ rows: [] });

    expect(fetcher).toHaveBeenCalledTimes(1);
    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe("https://api.example.com/v1/search?q=name%3Da%26after%3Db&cursor=opaque%2F..%2Fvalue%3Fx%23y&limit=25");
    expect(init?.method).toBe("GET");
    expect(init?.body).toBeUndefined();
    expect(init?.redirect).toBe("manual");
    expect(init?.signal).toBeInstanceOf(AbortSignal);
    expect([...new Headers(init?.headers).entries()]).toEqual([
      ["accept", "application/json"],
      ["authorization", "Bearer synthetic-provider-token"],
    ]);
  });

  it("requires provider approval before reading credentials or making any I/O", async () => {
    const fetcher = vi.fn<typeof globalThis.fetch>();
    let headerReads = 0;
    for (const allowRequest of [
      () => false,
      () => { throw new Error("sentinel-provider-policy-detail"); },
    ]) {
      const options: ExecuteReadRequestOptions = {
        origin: ORIGIN,
        plan: GET_PLAN,
        get headers(): Readonly<Record<string, string>> {
          headerReads += 1;
          throw new Error("sentinel-credential-detail");
        },
        allowRequest,
        fetch: fetcher,
      };
      await expect(executeReadRequest(options)).rejects.toEqual(
        new ConnectorRequestError("CONNECTOR_REQUEST_NOT_ALLOWED"),
      );
    }
    expect(headerReads).toBe(0);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("preserves provider-authored API version headers without accepting inbound headers", async () => {
    const fetcher = vi.fn<typeof globalThis.fetch>(async () => jsonResponse({ rows: [] }));
    await executeReadRequest({
      origin: ORIGIN, plan: GET_PLAN, allowRequest: allowGet, fetch: fetcher,
      headers: { ...HEADERS, "Notion-Version": "2025-09-03", "X-GitHub-Api-Version": "2022-11-28" },
    });
    expect([...new Headers(fetcher.mock.calls[0]?.[1]?.headers).entries()]).toEqual([
      ["accept", "application/json"],
      ["authorization", "Bearer synthetic-provider-token"],
      ["notion-version", "2025-09-03"],
      ["x-github-api-version", "2022-11-28"],
    ]);
  });

  it("fails closed when the mandatory runtime provider gate is absent", async () => {
    const fetcher = vi.fn<typeof globalThis.fetch>();
    const options = { origin: ORIGIN, plan: GET_PLAN, headers: HEADERS, allowRequest: allowGet, fetch: fetcher };
    Object.defineProperty(options, "allowRequest", { value: undefined });
    await expect(executeReadRequest(options)).rejects.toEqual(
      new ConnectorRequestError("CONNECTOR_REQUEST_NOT_ALLOWED"),
    );
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("sends POST only after an exact provider-authored read body check, using a frozen detached snapshot", async () => {
    const query = "query ReadTicket { ticket(id: 7) { id subject } }";
    const sourceBody = { query, variables: { id: 7 } };
    const fetcher = vi.fn<typeof globalThis.fetch>(async () => jsonResponse({ data: { ticket: { id: 7 } } }));
    const allowRequest = vi.fn((plan: ReadRequestPlan): boolean => {
      expect(Object.isFrozen(plan)).toBe(true);
      expect(Object.isFrozen(plan.body)).toBe(true);
      expect(Object.isFrozen(Object.getOwnPropertyDescriptor(plan.body, "variables")?.value)).toBe(true);
      sourceBody.query = "mutation DeleteTicket { deleteTicket(id: 7) }";
      return plan.method === "POST" && plan.path === "/graphql" &&
        JSON.stringify(plan.body) === JSON.stringify({ query, variables: { id: 7 } });
    });

    await executeReadRequest({
      origin: ORIGIN,
      plan: { method: "POST", path: "/graphql", body: sourceBody },
      headers: HEADERS,
      allowRequest,
      fetch: fetcher,
    });
    const [, init] = fetcher.mock.calls[0] ?? [];
    expect(allowRequest).toHaveBeenCalledTimes(1);
    expect(init?.body).toBe(JSON.stringify({ query, variables: { id: 7 } }));
    expect(new Headers(init?.headers).get("Content-Type")).toBe("application/json");

    await expect(executeReadRequest({
      origin: ORIGIN,
      plan: { method: "POST", path: "/graphql", body: sourceBody },
      headers: HEADERS,
      allowRequest,
      fetch: fetcher,
    })).rejects.toEqual(new ConnectorRequestError("CONNECTOR_REQUEST_NOT_ALLOWED"));
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it.each([
    "https://evil.example.com/v1/search", "//evil.example.com/v1/search",
    "/\\evil.example.com/v1/search", "/v1/../search", "/./v1/search", "/v1//search",
    "/v1/%2e%2e/search", "/v1/%2E/search", "/v1/%2fsearch", "/v1/%5csearch",
    "/v1/%252e%252e/search", "/v1/%25252fsearch", "/v1/%GG/search", "/v1/search%",
    "/v1/search?origin=https://evil.example.com", "/v1/search#fragment", "/v1/search\n",
    "/v1/検索", "v1/search", "",
  ])("rejects unsafe path %j before provider approval and fetch", async (path) => {
    const fetcher = vi.fn<typeof globalThis.fetch>();
    const allowRequest = vi.fn(() => true);
    await expect(executeReadRequest({ origin: ORIGIN, plan: { method: "GET", path }, headers: HEADERS, allowRequest, fetch: fetcher }))
      .rejects.toEqual(new ConnectorRequestError("CONNECTOR_REQUEST_INVALID"));
    expect(allowRequest).not.toHaveBeenCalled();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each([
    "http://api.example.com", "https://api.example.com/", "https://api.example.com/base",
    "https://api.example.com?x=1", "https://api.example.com#fragment",
    "https://user:secret@api.example.com", "https://api.example.com:8443", "https://api.example.com:443",
    "https://API.example.com", "https://api.example.com.", "https://api%2eexample.com",
    "https://localhost", "https://api.localhost", "https://metadata.google.internal",
    "https://api.home.arpa", "https://service.local", "https://service.lan", "https://singlelabel",
    "https://127.0.0.1", "https://10.0.0.1", "https://169.254.169.254", "https://172.16.0.1",
    "https://192.168.1.1", "https://0.0.0.0", "https://2130706433", "https://0x7f000001",
    "https://[::1]", "https://[fe80::1]", "https://[::ffff:127.0.0.1]", "https://8.8.8.8",
  ])("rejects noncanonical or non-public origin %j", async (origin) => {
    const fetcher = vi.fn<typeof globalThis.fetch>();
    await expect(executeReadRequest({ origin, plan: GET_PLAN, headers: HEADERS, allowRequest: allowGet, fetch: fetcher }))
      .rejects.toEqual(new ConnectorRequestError("CONNECTOR_CONFIGURATION_INVALID"));
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects method/body controls and non-JSON values before fetch", async () => {
    const fetcher = vi.fn<typeof globalThis.fetch>();
    const cyclic: CyclicFixture = {};
    cyclic.self = cyclic;
    let getterReads = 0;
    const getterBody = { get value() { getterReads += 1; return "sentinel"; } };
    const invalidPlans: ReadRequestPlan[] = [
      { ...GET_PLAN, body: {} },
      { method: "POST", path: "/graphql", body: cyclic },
      { method: "POST", path: "/graphql", body: { value: Number.NaN } },
      { method: "POST", path: "/graphql", body: { value: () => "sentinel" } },
      { method: "POST", path: "/graphql", body: new Date(0) },
      { method: "POST", path: "/graphql", body: getterBody },
      { method: "POST", path: "/graphql", body: Array(2) },
    ];
    const invalidMethod: ReadRequestPlan = { ...GET_PLAN };
    Object.defineProperty(invalidMethod, "method", { value: "DELETE" });
    invalidPlans.push(invalidMethod);
    for (const plan of invalidPlans) {
      await expect(executeReadRequest({ origin: ORIGIN, plan, headers: HEADERS, allowRequest: () => true, fetch: fetcher }))
        .rejects.toEqual(new ConnectorRequestError("CONNECTOR_REQUEST_INVALID"));
    }
    expect(getterReads).toBe(0);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("bounds UTF-8 request bytes, nesting, and node count before approval", async () => {
    const fetcher = vi.fn<typeof globalThis.fetch>();
    const allowRequest = vi.fn(() => true);
    let nested: NestedFixture | null = null;
    for (let index = 0; index <= CONNECTOR_REQUEST_LIMITS.jsonDepth; index += 1) {
      nested = { child: nested };
    }
    const plans: ReadRequestPlan[] = [
      { method: "POST", path: "/graphql", body: { query: "é".repeat(CONNECTOR_REQUEST_LIMITS.requestBytes / 2) } },
      { ...GET_PLAN, query: { q: "é".repeat(CONNECTOR_REQUEST_LIMITS.requestBytes / 2) } },
      { method: "POST", path: "/graphql", body: nested },
      { method: "POST", path: "/graphql", body: Array.from({ length: CONNECTOR_REQUEST_LIMITS.jsonNodes + 1 }, () => 0) },
    ];
    for (const plan of plans) {
      await expect(executeReadRequest({ origin: ORIGIN, plan, headers: HEADERS, allowRequest, fetch: fetcher }))
        .rejects.toEqual(new ConnectorRequestError("CONNECTOR_REQUEST_TOO_LARGE"));
    }
    expect(allowRequest).not.toHaveBeenCalled();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each([
    { Host: "evil.example.com" }, { Cookie: "synthetic=session" }, { "X-Forwarded-Host": "evil.example.com" },
    { "CF-Access-Client-Secret": "synthetic" }, { Authorization: "synthetic\r\nX-Evil: yes" },
    { Authorization: "synthetic-a", authorization: "synthetic-b" }, { Accept: "text/html" },
    { "Content-Type": "text/plain" }, { "Content-Length": "1" },
  ])("rejects credential/header routing confusion %j", async (headers) => {
    const fetcher = vi.fn<typeof globalThis.fetch>();
    await expect(executeReadRequest({ origin: ORIGIN, plan: GET_PLAN, headers, allowRequest: allowGet, fetch: fetcher }))
      .rejects.toEqual(new ConnectorRequestError("CONNECTOR_CONFIGURATION_INVALID"));
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each([301, 302, 303, 307, 308])("rejects redirect status %s without forwarding credentials or making a second fetch", async (status) => {
    const redirectTarget = "https://evil.example.com/next";
    const fetcher = vi.fn<typeof globalThis.fetch>(async () => Response.redirect(redirectTarget, status));
    await expect(runWith(fetcher)).rejects.toEqual(new ConnectorRequestError("CONNECTOR_UPSTREAM_REJECTED"));
    expect(fetcher).toHaveBeenCalledOnce();
    const [url, init] = fetcher.mock.calls[0] ?? [];
    expect(url).toBe(`${ORIGIN}/v1/search`);
    expect(init?.redirect).toBe("manual");
    expect(new Headers(init?.headers).get("authorization")).toBe(HEADERS.Authorization);
    expect(fetcher.mock.calls.some(([destination]) => String(destination) === redirectTarget)).toBe(false);
  });

  it("rejects already-followed responses, retries no rejected requests, and follows no pagination URLs", async () => {
    const redirected = jsonResponse({ rows: [] });
    Object.defineProperty(redirected, "redirected", { value: true });
    const wrongUrl = jsonResponse({ rows: [] });
    Object.defineProperty(wrongUrl, "url", { value: "https://evil.example.com/next" });
    for (const response of [redirected, wrongUrl, new Response("sentinel-provider-detail", { status: 429 })]) {
      const fetcher = vi.fn<typeof globalThis.fetch>(async () => response);
      await expect(runWith(fetcher)).rejects.toEqual(new ConnectorRequestError("CONNECTOR_UPSTREAM_REJECTED"));
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect(fetcher.mock.calls[0]?.[1]?.redirect).toBe("manual");
    }
    const fetcher = vi.fn<typeof globalThis.fetch>(async () => jsonResponse({ next: "https://evil.example.com/next" }));
    await expect(runWith(fetcher)).resolves.toEqual({ next: "https://evil.example.com/next" });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("accepts JSON and structured JSON media types but rejects malformed or oversized responses", async () => {
    const structured = new Response('{"data":{}}', { headers: { "Content-Type": "application/graphql-response+json; charset=utf-8" } });
    await expect(runWith(vi.fn<typeof globalThis.fetch>(async () => structured))).resolves.toEqual({ data: {} });
    const responses = [
      new Response("sentinel", { headers: { "Content-Type": "text/plain" } }),
      new Response("not-json", { headers: { "Content-Type": "application/json" } }),
      new Response(new Uint8Array([0xc3, 0x28]), { headers: { "Content-Type": "application/json" } }),
      new Response(null, { headers: { "Content-Type": "application/json" } }),
      new Response("{}", { headers: { "Content-Type": "application/json", "Content-Length": String(CONNECTOR_REQUEST_LIMITS.responseBytes + 1) } }),
      new Response("{}", { headers: { "Content-Type": "application/json", "Content-Length": "1e3" } }),
      jsonResponse({ padding: "x".repeat(CONNECTOR_REQUEST_LIMITS.responseBytes) }),
    ];
    for (const response of responses) {
      await expect(runWith(vi.fn<typeof globalThis.fetch>(async () => response)))
        .rejects.toEqual(new ConnectorRequestError("CONNECTOR_RESPONSE_REJECTED"));
    }
  });

  it("accepts an exact byte-limit JSON response and bounds even empty stream chunks", async () => {
    const value = { value: "x".repeat(CONNECTOR_REQUEST_LIMITS.responseBytes - JSON.stringify({ value: "" }).length) };
    await expect(runWith(vi.fn<typeof globalThis.fetch>(async () => jsonResponse(value)))).resolves.toEqual(value);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let index = 0; index <= CONNECTOR_REQUEST_LIMITS.responseChunks; index += 1) {
          controller.enqueue(new Uint8Array());
        }
        controller.close();
      },
    });
    await expect(runWith(vi.fn<typeof globalThis.fetch>(async () => streamResponse(stream))))
      .rejects.toEqual(new ConnectorRequestError("CONNECTOR_RESPONSE_REJECTED"));
  });

  it("keeps size rejection authoritative when stream cancellation fails", async () => {
    const cancel = vi.fn(async () => { throw new Error("sentinel-cancel-secret"); });
    const stream = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new Uint8Array(CONNECTOR_REQUEST_LIMITS.responseBytes + 1)); },
      cancel,
    });
    await expect(runWith(vi.fn<typeof globalThis.fetch>(async () => streamResponse(stream))))
      .rejects.toEqual(new ConnectorRequestError("CONNECTOR_RESPONSE_REJECTED"));
    expect(cancel).toHaveBeenCalled();
  });

  it("returns fixed errors without raw fetch/stream details, causes, or logs", async () => {
    const log = vi.spyOn(console, "log");
    const errorLog = vi.spyOn(console, "error");
    const failures: Array<typeof globalThis.fetch> = [
      vi.fn(async () => { throw new Error("sentinel-fetch-secret"); }),
      vi.fn(async () => streamResponse(new ReadableStream<Uint8Array>({
        start(controller) { controller.error(new Error("sentinel-stream-secret")); },
      }))),
    ];
    for (const fetcher of failures) {
      const error = await runWith(fetcher).catch((caught: ConnectorRequestError) => caught);
      expect(error).toEqual(new ConnectorRequestError("CONNECTOR_UPSTREAM_UNAVAILABLE"));
      expect(JSON.stringify(error)).not.toContain("sentinel");
      expect(error).not.toHaveProperty("cause");
    }
    expect(log).not.toHaveBeenCalled();
    expect(errorLog).not.toHaveBeenCalled();
  });

  it("times out a fetch that never resolves even when it ignores AbortSignal", async () => {
    vi.useFakeTimers();
    const fetcher = vi.fn<typeof globalThis.fetch>(() => new Promise<Response>(() => {}));
    const outcome = runWith(fetcher).catch((error: ConnectorRequestError) => error);
    await vi.advanceTimersByTimeAsync(CONNECTOR_REQUEST_LIMITS.timeoutMilliseconds);
    expect(await outcome).toEqual(new ConnectorRequestError("CONNECTOR_UPSTREAM_TIMEOUT"));
    expect(fetcher.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("includes stalled response bodies and stalled cancellation in the same deadline", async () => {
    vi.useFakeTimers();
    const cancel = vi.fn(() => new Promise<void>(() => {}));
    const stream = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new TextEncoder().encode('{"rows":')); },
      cancel,
    });
    const fetcher = vi.fn<typeof globalThis.fetch>(async () => streamResponse(stream));
    const outcome = runWith(fetcher).catch((error: ConnectorRequestError) => error);
    await vi.advanceTimersByTimeAsync(CONNECTOR_REQUEST_LIMITS.timeoutMilliseconds);
    expect(await outcome).toEqual(new ConnectorRequestError("CONNECTOR_UPSTREAM_TIMEOUT"));
    expect(cancel).toHaveBeenCalled();
    expect(fetcher.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
  });
});

function runWith(fetcher: typeof globalThis.fetch): Promise<ConnectorJson> {
  return executeReadRequest({ origin: ORIGIN, plan: GET_PLAN, headers: HEADERS, allowRequest: allowGet, fetch: fetcher });
}

function jsonResponse(value: ConnectorJson): Response {
  return new Response(JSON.stringify(value), { headers: { "Content-Type": "application/json" } });
}

function streamResponse(stream: ReadableStream<Uint8Array>): Response {
  return new Response(stream, { headers: { "Content-Type": "application/json" } });
}
