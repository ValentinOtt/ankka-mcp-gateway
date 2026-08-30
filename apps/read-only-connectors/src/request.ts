export const CONNECTOR_REQUEST_LIMITS = {
  requestBytes: 16_384,
  responseBytes: 524_288,
  responseChunks: 128,
  timeoutMilliseconds: 8_000,
  headerBytes: 16_384,
  jsonDepth: 16,
  jsonNodes: 4_096,
} as const;

export type ConnectorRequestErrorCode =
  | "CONNECTOR_CONFIGURATION_INVALID"
  | "CONNECTOR_REQUEST_INVALID"
  | "CONNECTOR_REQUEST_NOT_ALLOWED"
  | "CONNECTOR_REQUEST_TOO_LARGE"
  | "CONNECTOR_RESPONSE_REJECTED"
  | "CONNECTOR_UPSTREAM_REJECTED"
  | "CONNECTOR_UPSTREAM_UNAVAILABLE"
  | "CONNECTOR_UPSTREAM_TIMEOUT";

export class ConnectorRequestError extends Error {
  readonly code: ConnectorRequestErrorCode;

  constructor(code: ConnectorRequestErrorCode) {
    super(code);
    this.name = "ConnectorRequestError";
    this.code = code;
  }
}

export interface ReadRequestPlan {
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly query?: Readonly<Record<string, string>>;
  readonly body?: unknown;
}

export interface ExecuteReadRequestOptions {
  /** A canonical HTTPS origin pinned by provider code or trusted deployment configuration. */
  readonly origin: string;
  readonly plan: ReadRequestPlan;
  /** Explicit provider headers from trusted deployment configuration/secrets, never inbound headers. */
  readonly headers: Readonly<Record<string, string>>;
  /** Must check the exact method, path, query, and body. POST is not assumed to be a read. */
  readonly allowRequest: (plan: ReadRequestPlan) => boolean;
  readonly fetch?: typeof globalThis.fetch;
}

export type ConnectorJson = null | boolean | number | string | ConnectorJson[] | { [key: string]: ConnectorJson };

interface JsonBudget {
  bytes: number;
  nodes: number;
  ancestors: Set<object>;
}

interface PreparedRequest {
  readonly plan: ReadRequestPlan;
  readonly url: URL;
  readonly body: string | undefined;
}

const encoder = new TextEncoder();
const localHostSuffixes = [
  "localhost", "local", "localdomain", "internal", "intranet", "lan", "home",
  "home.arpa", "corp", "test", "invalid", "example", "onion",
] as const;
const forbiddenHeaders = new Set([
  "host", "cookie", "cookie2", "connection", "content-length", "transfer-encoding",
  "te", "trailer", "upgrade", "proxy-authorization", "proxy-connection", "forwarded",
  "origin", "referer",
]);

/**
 * Execute one provider-approved read. This is not an arbitrary-origin proxy:
 * providers must pin their public service domain; hostname syntax checks are
 * not DNS resolution or a substitute for that deployment boundary.
 */
export async function executeReadRequest(options: ExecuteReadRequestOptions): Promise<ConnectorJson> {
  let prepared: PreparedRequest;
  let headers: Headers;
  let fetcher: typeof globalThis.fetch;
  try {
    prepared = prepareRequest(options.origin, options.plan);
    let allowed = false;
    try {
      allowed = options.allowRequest(prepared.plan) === true;
    } catch {
      throw new ConnectorRequestError("CONNECTOR_REQUEST_NOT_ALLOWED");
    }
    if (!allowed) {
      throw new ConnectorRequestError("CONNECTOR_REQUEST_NOT_ALLOWED");
    }

    // Do not even read the trusted credential object until the provider gate passes.
    headers = prepareHeaders(options.headers, prepared.body !== undefined);
    fetcher = options.fetch ?? globalThis.fetch;
  } catch (error) {
    if (error instanceof ConnectorRequestError) {
      throw error;
    }
    throw new ConnectorRequestError("CONNECTOR_CONFIGURATION_INVALID");
  }

  const controller = new AbortController();
  let timedOut = false;
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
      cancelReader(reader);
      reject(new ConnectorRequestError("CONNECTOR_UPSTREAM_TIMEOUT"));
    }, CONNECTOR_REQUEST_LIMITS.timeoutMilliseconds);
  });

  const operation = async (): Promise<ConnectorJson> => {
    try {
      const init: RequestInit = {
        method: prepared.plan.method,
        headers,
        redirect: "error",
        signal: controller.signal,
      };
      if (prepared.body !== undefined) {
        init.body = prepared.body;
      }
      const response = await fetcher(prepared.url.href, init);
      if (timedOut) {
        cancelBody(response.body);
        throw new ConnectorRequestError("CONNECTOR_UPSTREAM_TIMEOUT");
      }
      if (
        response.redirected ||
        (response.url !== "" && response.url !== prepared.url.href) ||
        !response.ok
      ) {
        cancelBody(response.body);
        throw new ConnectorRequestError("CONNECTOR_UPSTREAM_REJECTED");
      }
      validateResponseHeaders(response);
      if (response.body === null) {
        throw new ConnectorRequestError("CONNECTOR_RESPONSE_REJECTED");
      }
      reader = response.body.getReader();
      const result = await readJson(reader, () => timedOut);
      if (timedOut) {
        throw new ConnectorRequestError("CONNECTOR_UPSTREAM_TIMEOUT");
      }
      return result;
    } catch (error) {
      cancelReader(reader);
      if (timedOut) {
        throw new ConnectorRequestError("CONNECTOR_UPSTREAM_TIMEOUT");
      }
      if (error instanceof ConnectorRequestError) {
        throw error;
      }
      throw new ConnectorRequestError("CONNECTOR_UPSTREAM_UNAVAILABLE");
    }
  };

  try {
    // The race also bounds fetch implementations and response streams that ignore abort.
    return await Promise.race([operation(), deadline]);
  } finally {
    clearTimeout(timer);
  }
}

function prepareRequest(origin: string, input: ReadRequestPlan): PreparedRequest {
  const base = parseOrigin(origin);
  if (!isPlainRecord(input) || !hasOnlyDataProperties(input, ["method", "path", "query", "body"])) {
    throw new ConnectorRequestError("CONNECTOR_REQUEST_INVALID");
  }
  if (input.method !== "GET" && input.method !== "POST") {
    throw new ConnectorRequestError("CONNECTOR_REQUEST_INVALID");
  }
  if (
    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- The outbound boundary rejects malformed JavaScript callers before URL parsing.
    typeof input.path !== "string" || input.path.length > 2_048 ||
    !input.path.startsWith("/") || input.path.includes("//") ||
    /[\s\\?#]/u.test(input.path) || hasControlCharacters(input.path) ||
    /%(?:2e|2f|5c|25)/iu.test(input.path) ||
    /%(?![0-9a-f]{2})/iu.test(input.path) ||
    input.path.split("/").some((part) => part === "." || part === "..")
  ) {
    throw new ConnectorRequestError("CONNECTOR_REQUEST_INVALID");
  }
  const url = new URL(input.path, base);
  if (url.origin !== base.origin || url.pathname !== input.path || url.search !== "" || url.hash !== "") {
    throw new ConnectorRequestError("CONNECTOR_REQUEST_INVALID");
  }

  const plan: ReadRequestPlan = { method: input.method, path: input.path };
  let query: Readonly<Record<string, string>> | undefined;
  if (input.query !== undefined) {
    if (!isPlainRecord(input.query) || !hasOnlyDataProperties(input.query)) {
      throw new ConnectorRequestError("CONNECTOR_REQUEST_INVALID");
    }
    const entries = Object.entries(input.query);
    if (entries.length > 64) {
      throw new ConnectorRequestError("CONNECTOR_REQUEST_TOO_LARGE");
    }
    const copied: Record<string, string> = {};
    for (const [key, value] of entries) {
      // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Query values cross the outbound serialization boundary and must be strings.
      if (key.length === 0 || key.length > 128 || typeof value !== "string") {
        throw new ConnectorRequestError("CONNECTOR_REQUEST_INVALID");
      }
      if (value.length > CONNECTOR_REQUEST_LIMITS.requestBytes) {
        throw new ConnectorRequestError("CONNECTOR_REQUEST_TOO_LARGE");
      }
      Object.defineProperty(copied, key, { value, enumerable: true });
      url.searchParams.append(key, value);
    }
    query = Object.freeze(copied);
  }

  let body: ConnectorJson | undefined;
  let serialized: string | undefined;
  if (input.body !== undefined) {
    if (input.method === "GET") {
      throw new ConnectorRequestError("CONNECTOR_REQUEST_INVALID");
    }
    body = copyJson(input.body, { bytes: 0, nodes: 0, ancestors: new Set() }, 0);
    serialized = JSON.stringify(body);
  }
  if (encoder.encode(url.href).byteLength + (serialized === undefined ? 0 : encoder.encode(serialized).byteLength) > CONNECTOR_REQUEST_LIMITS.requestBytes) {
    throw new ConnectorRequestError("CONNECTOR_REQUEST_TOO_LARGE");
  }
  if (query !== undefined) {
    Object.defineProperty(plan, "query", { value: query, enumerable: true });
  }
  if (body !== undefined) {
    Object.defineProperty(plan, "body", { value: body, enumerable: true });
  }
  return { plan: Object.freeze(plan), url, body: serialized };
}

function parseOrigin(origin: string): URL {
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Deployment configuration is validated before credentials are attached.
  if (typeof origin !== "string" || origin.length > 2_048 || /[\s\\%]/u.test(origin) || hasControlCharacters(origin)) {
    throw new ConnectorRequestError("CONNECTOR_CONFIGURATION_INVALID");
  }
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    throw new ConnectorRequestError("CONNECTOR_CONFIGURATION_INVALID");
  }
  const labels = url.hostname.split(".");
  if (
    url.protocol !== "https:" || url.origin !== origin || url.port !== "" ||
    url.username !== "" || url.password !== "" || url.pathname !== "/" ||
    url.search !== "" || url.hash !== "" || labels.length < 2 ||
    labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label)) ||
    !/[a-z]/u.test(labels.at(-1) ?? "") ||
    localHostSuffixes.some((suffix) => url.hostname === suffix || url.hostname.endsWith(`.${suffix}`))
  ) {
    throw new ConnectorRequestError("CONNECTOR_CONFIGURATION_INVALID");
  }
  return url;
}

function prepareHeaders(input: Readonly<Record<string, string>>, hasBody: boolean): Headers {
  if (!isPlainRecord(input) || !hasOnlyDataProperties(input)) {
    throw new ConnectorRequestError("CONNECTOR_CONFIGURATION_INVALID");
  }
  const headers = new Headers();
  const names = new Set<string>();
  let bytes = 0;
  for (const [name, value] of Object.entries(input)) {
    const lower = name.toLowerCase();
    if (
      // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Header values cross the credential-bearing outbound serialization boundary.
      !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u.test(name) || typeof value !== "string" ||
      value.length > CONNECTOR_REQUEST_LIMITS.headerBytes || hasControlCharacters(value) || names.has(lower) ||
      forbiddenHeaders.has(lower) || lower.startsWith("x-forwarded-") || lower.startsWith("cf-") ||
      ((lower === "accept" || lower === "content-type") && value !== "application/json")
    ) {
      throw new ConnectorRequestError("CONNECTOR_CONFIGURATION_INVALID");
    }
    names.add(lower);
    bytes += encoder.encode(name).byteLength + encoder.encode(value).byteLength;
    if (bytes > CONNECTOR_REQUEST_LIMITS.headerBytes) {
      throw new ConnectorRequestError("CONNECTOR_CONFIGURATION_INVALID");
    }
    headers.set(name, value);
  }
  headers.set("Accept", "application/json");
  if (hasBody) {
    headers.set("Content-Type", "application/json");
  } else {
    headers.delete("Content-Type");
  }
  return headers;
}

/* oxlint-disable anti-slop/no-unknown-parameters, anti-slop/no-runtime-typeof -- This bounded JSON parser is the explicit untrusted request-body boundary. */
function copyJson(value: unknown, budget: JsonBudget, depth: number): ConnectorJson {
  budget.nodes += 1;
  if (depth > CONNECTOR_REQUEST_LIMITS.jsonDepth || budget.nodes > CONNECTOR_REQUEST_LIMITS.jsonNodes) {
    throw new ConnectorRequestError("CONNECTOR_REQUEST_TOO_LARGE");
  }
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    if ((typeof value === "number" && !Number.isFinite(value)) || (typeof value === "string" && value.length > CONNECTOR_REQUEST_LIMITS.requestBytes)) {
      throw new ConnectorRequestError(typeof value === "string" ? "CONNECTOR_REQUEST_TOO_LARGE" : "CONNECTOR_REQUEST_INVALID");
    }
    spendJsonBytes(budget, encoder.encode(JSON.stringify(value)).byteLength);
    return value;
  }
  if (typeof value !== "object" || budget.ancestors.has(value)) {
    throw new ConnectorRequestError("CONNECTOR_REQUEST_INVALID");
  }
  budget.ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (value.length > CONNECTOR_REQUEST_LIMITS.jsonNodes || !hasOnlyDataProperties(value)) {
        throw new ConnectorRequestError("CONNECTOR_REQUEST_TOO_LARGE");
      }
      spendJsonBytes(budget, 2 + Math.max(0, value.length - 1));
      const result: ConnectorJson[] = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) {
          throw new ConnectorRequestError("CONNECTOR_REQUEST_INVALID");
        }
        result.push(copyJson(value[index], budget, depth + 1));
      }
      Object.freeze(result);
      return result;
    }
    if (!isPlainRecord(value) || !hasOnlyDataProperties(value)) {
      throw new ConnectorRequestError("CONNECTOR_REQUEST_INVALID");
    }
    const entries = Object.entries(value);
    if (entries.length > CONNECTOR_REQUEST_LIMITS.jsonNodes) {
      throw new ConnectorRequestError("CONNECTOR_REQUEST_TOO_LARGE");
    }
    spendJsonBytes(budget, 2 + Math.max(0, entries.length - 1));
    const result: { [key: string]: ConnectorJson } = {};
    for (const [key, child] of entries) {
      if (key.length > CONNECTOR_REQUEST_LIMITS.requestBytes) {
        throw new ConnectorRequestError("CONNECTOR_REQUEST_TOO_LARGE");
      }
      spendJsonBytes(budget, encoder.encode(JSON.stringify(key)).byteLength + 1);
      Object.defineProperty(result, key, {
        value: copyJson(child, budget, depth + 1), enumerable: true,
      });
    }
    Object.freeze(result);
    return result;
  } finally {
    budget.ancestors.delete(value);
  }
}
/* oxlint-enable anti-slop/no-unknown-parameters, anti-slop/no-runtime-typeof */

function spendJsonBytes(budget: JsonBudget, bytes: number): void {
  budget.bytes += bytes;
  if (budget.bytes > CONNECTOR_REQUEST_LIMITS.requestBytes) {
    throw new ConnectorRequestError("CONNECTOR_REQUEST_TOO_LARGE");
  }
}

/* oxlint-disable anti-slop/no-unknown-parameters, anti-slop/no-unsafe-dictionary-type, anti-slop/no-runtime-typeof -- Structural inspection rejects accessors and exotic values before serializing untrusted request data. */
function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
/* oxlint-enable anti-slop/no-unknown-parameters, anti-slop/no-unsafe-dictionary-type, anti-slop/no-runtime-typeof */

// oxlint-disable-next-line anti-slop/no-object-parameters -- Both JSON arrays and plain records require own-descriptor inspection without evaluating getters.
function hasOnlyDataProperties(value: object, allowedKeys?: readonly string[]): boolean {
  return Reflect.ownKeys(value).every((key) => {
    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Reflect.ownKeys returns strings or symbols; JSON only permits string keys.
    if (typeof key !== "string" || (allowedKeys !== undefined && !allowedKeys.includes(key))) {
      return false;
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor !== undefined && "value" in descriptor;
  });
}

function hasControlCharacters(value: string): boolean {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code < 32 || code === 127) {
      return true;
    }
  }
  return false;
}

function validateResponseHeaders(response: Response): void {
  if (!/^application\/(?:json|[a-z0-9!#$&^_.+-]+\+json)(?:\s*;[^\r\n]*)?$/iu.test(response.headers.get("Content-Type") ?? "")) {
    cancelBody(response.body);
    throw new ConnectorRequestError("CONNECTOR_RESPONSE_REJECTED");
  }
  const length = response.headers.get("Content-Length");
  if (length !== null && (!/^(?:0|[1-9]\d*)$/u.test(length) || !Number.isSafeInteger(Number(length)) || Number(length) > CONNECTOR_REQUEST_LIMITS.responseBytes)) {
    cancelBody(response.body);
    throw new ConnectorRequestError("CONNECTOR_RESPONSE_REJECTED");
  }
}

async function readJson(reader: ReadableStreamDefaultReader<Uint8Array>, timedOut: () => boolean): Promise<ConnectorJson> {
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  let count = 0;
  while (true) {
    const chunk = await reader.read();
    if (timedOut()) {
      throw new ConnectorRequestError("CONNECTOR_UPSTREAM_TIMEOUT");
    }
    if (chunk.done) {
      break;
    }
    count += 1;
    if (!(chunk.value instanceof Uint8Array)) {
      throw new ConnectorRequestError("CONNECTOR_RESPONSE_REJECTED");
    }
    bytes += chunk.value.byteLength;
    if (bytes > CONNECTOR_REQUEST_LIMITS.responseBytes || count > CONNECTOR_REQUEST_LIMITS.responseChunks) {
      throw new ConnectorRequestError("CONNECTOR_RESPONSE_REJECTED");
    }
    chunks.push(chunk.value);
  }
  const combined = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(combined));
  } catch {
    throw new ConnectorRequestError("CONNECTOR_RESPONSE_REJECTED");
  }
}

function cancelReader(reader: ReadableStreamDefaultReader<Uint8Array> | undefined): void {
  if (reader !== undefined) {
    // Cleanup must not extend the deadline if a broken stream never settles cancel().
    void reader.cancel().catch(() => {});
  }
}

function cancelBody(body: ReadableStream<Uint8Array> | null): void {
  if (body !== null) {
    void body.cancel().catch(() => {});
  }
}
