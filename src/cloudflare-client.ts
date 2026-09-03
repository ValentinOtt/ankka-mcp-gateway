import * as v from 'valibot';

import {
  boundaryObjectSchema,
  boundaryValueSchema,
  jsonObjectSchema,
  type BoundaryObject,
  type BoundaryValue,
  type JsonObject,
  type JsonValue,
} from './json.ts';

const DEFAULT_BASE_URL = 'https://api.cloudflare.com/client/v4';
const PAGE_SIZE = 100;
const MAX_PAGES = 100;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const SAFE_CODE = /^[A-Za-z0-9_.:-]{1,64}$/;
const SAFE_REQUEST_ID = /^[A-Za-z0-9_.:/-]{1,128}$/;

const stringSchema = v.string();
const numberSchema = v.number();
const fetchSchema = v.function();
const abortSignalSchema = v.object({
  aborted: v.boolean(),
  addEventListener: v.function(),
  removeEventListener: v.function(),
});
const queryPrimitiveSchema = v.union([
  v.boolean(),
  v.null(),
  v.number(),
  v.string(),
  v.undefined(),
]);
const queryValueSchema = v.union([queryPrimitiveSchema, v.array(queryPrimitiveSchema)]);
const querySchema = v.record(v.string(), queryValueSchema);
const pageResponseSchema = v.object({
  result: v.array(boundaryValueSchema),
  resultInfo: boundaryValueSchema,
});

export type CloudflareQuery = v.InferOutput<typeof querySchema>;

interface CloudflareResponse {
  readonly headers?: HeadersReader;
  readonly json?: () => Promise<BoundaryValue>;
  readonly ok?: boolean;
  readonly status?: number;
  readonly text?: () => Promise<string>;
}

interface HeadersReader {
  get(name: string): string | null;
}

type CloudflareRequestHeaders = {
  Accept: string;
  Authorization: string;
  'Content-Type'?: string;
};

interface CloudflareRequestInit {
  body?: string;
  headers: CloudflareRequestHeaders;
  method: string;
  signal?: AbortSignal;
}

export type CloudflareFetch = (
  url: string,
  init: CloudflareRequestInit,
) => Promise<CloudflareResponse>;

export interface CloudflareClientOptions {
  readonly accountId: string;
  readonly fetchImpl?: CloudflareFetch;
  readonly requestTimeoutMs?: number;
  readonly signal?: AbortSignal;
  readonly token: string;
  readonly zoneId: string;
}

interface CloudflareApiErrorOptions {
  readonly codes?: readonly BoundaryValue[];
  readonly requestId?: BoundaryValue;
  readonly status?: BoundaryValue;
}

interface RequestOptions {
  readonly body?: JsonValue;
  readonly nullOn404?: boolean;
  readonly query?: CloudflareQuery;
  readonly withInfo?: boolean;
}

interface RequestAbort {
  readonly cleanup: () => void;
  readonly signal: AbortSignal;
}

export class CloudflareApiError extends Error {
  readonly codes: readonly string[];
  readonly operation: string;
  readonly requestId: string | undefined;
  readonly status: number;

  constructor(
    operation: string,
    { status = 0, codes = [], requestId }: CloudflareApiErrorOptions = {},
  ) {
    const safeOperation = SAFE_CODE.test(operation) ? operation : 'unknown_operation';
    const statusCode = safeStatus(status);
    const safeCodes = sanitizeCodes(codes);
    const safeRequestId = sanitizeRequestId(requestId);
    const details = [
      `operation=${safeOperation}`,
      `status=${statusCode}`,
      `codes=${safeCodes.length > 0 ? safeCodes.join(',') : 'none'}`,
    ];
    if (safeRequestId) details.push(`request_id=${safeRequestId}`);
    super(`Cloudflare API request failed: ${details.join(' ')}`);
    this.name = 'CloudflareApiError';
    this.operation = safeOperation;
    this.status = statusCode;
    this.codes = Object.freeze(safeCodes);
    this.requestId = safeRequestId;
  }
}

const defaultCloudflareFetch: CloudflareFetch = async (url, init) =>
  globalThis.fetch(url, init);

export function createCloudflareClient(options: CloudflareClientOptions) {
  if (!v.is(v.object({}), options)) throw new TypeError('client options must be an object');
  const unknownOptions = Object.keys(options).filter(
    (key) => !['token', 'accountId', 'zoneId', 'fetchImpl', 'signal', 'requestTimeoutMs'].includes(key),
  );
  if (unknownOptions.length > 0) {
    throw new TypeError('client options contain unsupported fields');
  }
  const {
    token,
    accountId,
    zoneId,
    fetchImpl = defaultCloudflareFetch,
    signal,
    requestTimeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
  } = options;
  requireSecret(token, 'token');
  requireIdentifier(accountId, 'accountId');
  requireIdentifier(zoneId, 'zoneId');
  if (!v.safeParse(fetchSchema, fetchImpl).success) {
    throw new TypeError('fetchImpl must be a function');
  }
  requireAbortSignal(signal);
  if (!Number.isInteger(requestTimeoutMs) || requestTimeoutMs < 1 || requestTimeoutMs > 120_000) {
    throw new TypeError('requestTimeoutMs must be an integer from 1 to 120000');
  }
  const apiBase = DEFAULT_BASE_URL;

  const account = ['accounts', accountId];
  const zone = ['zones', zoneId];
  const aiMcp = [...account, 'access', 'ai-controls', 'mcp'];
  const mcpServers = [...aiMcp, 'servers'];
  const portals = [...aiMcp, 'portals'];
  const accessApps = [...zone, 'access', 'apps'];
  const dnsRecords = [...zone, 'dns_records'];

  const request = async (
    operation: string,
    method: string,
    path: readonly string[],
    { query, body, nullOn404 = false, withInfo = false }: RequestOptions = {},
  ): Promise<BoundaryValue> => {
    const url = buildUrl(apiBase, path, query);
    const headers: CloudflareRequestHeaders = {
      Accept: 'application/json',
      Authorization: `Bearer ${token}`,
    };
    const init: CloudflareRequestInit = { method, headers };
    if (body !== undefined) {
      const requestBody = requireBody(body);
      headers['Content-Type'] = 'application/json';
      try {
        init.body = JSON.stringify(requestBody);
      } catch {
        throw new CloudflareApiError(operation, { codes: ['invalid_request_body'] });
      }
    }

    const requestAbort = createRequestAbort(signal, requestTimeoutMs);
    init.signal = requestAbort.signal;
    try {
      let response: CloudflareResponse;
      try {
        if (requestAbort.signal.aborted) throw new Error('request_aborted');
        response = await raceAbort(fetchImpl(url, init), requestAbort.signal);
      } catch {
        throw new CloudflareApiError(operation, { codes: ['network_error'] });
      }
      const status = safeStatus(response.status);
      const requestId = getRequestId(response.headers);
      if (nullOn404 && status === 404) return null;
      if (response.ok && status === 204) return null;

      const envelope = await readEnvelope(response, requestAbort.signal);
      if (!response.ok || !isObject(envelope) || envelope.success !== true) {
        const codes = isObject(envelope)
          ? sanitizeCodes(readErrorCodes(envelope.errors))
          : [];
        throw new CloudflareApiError(operation, {
          status,
          codes: codes.length > 0 ? codes : ['invalid_response'],
          requestId,
        });
      }
      if (!Object.hasOwn(envelope, 'result')) {
        throw new CloudflareApiError(operation, {
          status,
          codes: ['invalid_response'],
          requestId,
        });
      }
      return withInfo ? { result: envelope.result, resultInfo: envelope.result_info } : envelope.result;
    } finally {
      requestAbort.cleanup();
    }
  };

  const paginate = async (
    operation: string,
    path: readonly string[],
    query: CloudflareQuery = {},
  ): Promise<BoundaryValue[]> => {
    const safeQuery = requireQuery(query);
    const results: BoundaryValue[] = [];
    for (let page = 1; page <= MAX_PAGES; page += 1) {
      const response = v.parse(pageResponseSchema, await request(operation, 'GET', path, {
        query: { ...safeQuery, page, per_page: PAGE_SIZE },
        withInfo: true,
      }));
      results.push(...response.result);

      const totalPages = readTotalPages(response.resultInfo);
      if (totalPages !== null && totalPages > MAX_PAGES) {
        throw new CloudflareApiError(operation, {
          status: 200,
          codes: ['pagination_limit'],
        });
      }
      if (
        (totalPages !== null && page >= totalPages) ||
        (totalPages === null && response.result.length < PAGE_SIZE)
      ) {
        return results;
      }
      if (page === MAX_PAGES) {
        throw new CloudflareApiError(operation, {
          status: 200,
          codes: ['pagination_limit'],
        });
      }
    }
    throw new CloudflareApiError(operation, { status: 200, codes: ['pagination_limit'] });
  };

  return Object.freeze({
    getZone: () =>
      request('get_zone', 'GET', ['zones', zoneId], { nullOn404: true }),
    listIdentityProviders: (query: CloudflareQuery = {}) =>
      paginate('list_identity_providers', [...account, 'access', 'identity_providers'], query),

    listMcpServers: (query: CloudflareQuery = {}) => paginate('list_mcp_servers', mcpServers, query),
    getMcpServer: (serverId: string) =>
      request('get_mcp_server', 'GET', [...mcpServers, id(serverId, 'serverId')], {
        nullOn404: true,
      }),
    createMcpServer: (body: JsonValue) => request('create_mcp_server', 'POST', mcpServers, { body }),
    updateMcpServer: (serverId: string, body: JsonValue) =>
      request('update_mcp_server', 'PUT', [...mcpServers, id(serverId, 'serverId')], { body }),
    deleteMcpServer: (serverId: string) =>
      request('delete_mcp_server', 'DELETE', [...mcpServers, id(serverId, 'serverId')]),
    syncMcpServer: (serverId: string) =>
      request('sync_mcp_server', 'POST', [...mcpServers, id(serverId, 'serverId'), 'sync']),

    listPortals: (query: CloudflareQuery = {}) => paginate('list_portals', portals, query),
    getPortal: (portalId: string) =>
      request('get_portal', 'GET', [...portals, id(portalId, 'portalId')], {
        nullOn404: true,
      }),
    createPortal: (body: JsonValue) => request('create_portal', 'POST', portals, { body }),
    updatePortal: (portalId: string, body: JsonValue) =>
      request('update_portal', 'PUT', [...portals, id(portalId, 'portalId')], { body }),
    deletePortal: (portalId: string) =>
      request('delete_portal', 'DELETE', [...portals, id(portalId, 'portalId')]),

    listAccessApps: (query: CloudflareQuery = {}) => paginate('list_access_apps', accessApps, query),
    getAccessApp: (appId: string) =>
      request('get_access_app', 'GET', [...accessApps, id(appId, 'appId')], {
        nullOn404: true,
      }),
    createAccessApp: (body: JsonValue) =>
      request('create_access_app', 'POST', accessApps, { body }),
    updateAccessApp: (appId: string, body: JsonValue) =>
      request('update_access_app', 'PUT', [...accessApps, id(appId, 'appId')], { body }),
    deleteAccessApp: (appId: string) =>
      request('delete_access_app', 'DELETE', [...accessApps, id(appId, 'appId')]),

    listAppPolicies: (appId: string, query: CloudflareQuery = {}) =>
      paginate(
        'list_app_policies',
        [...accessApps, id(appId, 'appId'), 'policies'],
        query,
      ),
    getAppPolicy: (appId: string, policyId: string) =>
      request(
        'get_app_policy',
        'GET',
        [...accessApps, id(appId, 'appId'), 'policies', id(policyId, 'policyId')],
        { nullOn404: true },
      ),
    createAppPolicy: (appId: string, body: JsonValue) =>
      request(
        'create_app_policy',
        'POST',
        [...accessApps, id(appId, 'appId'), 'policies'],
        { body },
      ),
    updateAppPolicy: (appId: string, policyId: string, body: JsonValue) =>
      request(
        'update_app_policy',
        'PUT',
        [...accessApps, id(appId, 'appId'), 'policies', id(policyId, 'policyId')],
        { body },
      ),
    deleteAppPolicy: (appId: string, policyId: string) =>
      request(
        'delete_app_policy',
        'DELETE',
        [...accessApps, id(appId, 'appId'), 'policies', id(policyId, 'policyId')],
      ),

    listDnsRecords: (query: CloudflareQuery = {}) => paginate('list_dns_records', dnsRecords, query),
    getDnsRecord: (recordId: string) =>
      request('get_dns_record', 'GET', [...dnsRecords, id(recordId, 'recordId')], {
        nullOn404: true,
      }),
    createDnsRecord: (body: JsonValue) => request('create_dns_record', 'POST', dnsRecords, { body }),
    updateDnsRecord: (recordId: string, body: JsonValue) =>
      request('update_dns_record', 'PUT', [...dnsRecords, id(recordId, 'recordId')], { body }),
    deleteDnsRecord: (recordId: string) =>
      request('delete_dns_record', 'DELETE', [...dnsRecords, id(recordId, 'recordId')]),
  });
}

export type CloudflareClient = ReturnType<typeof createCloudflareClient>;

function createRequestAbort(
  externalSignal: AbortSignal | undefined,
  requestTimeoutMs: number,
): RequestAbort {
  const controller = new AbortController();
  const forwardAbort = () => controller.abort();
  if (externalSignal?.aborted) controller.abort();
  else externalSignal?.addEventListener('abort', forwardAbort, { once: true });
  const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);
  return {
    signal: controller.signal,
    cleanup() {
      clearTimeout(timeout);
      externalSignal?.removeEventListener('abort', forwardAbort);
    },
  };
}

function raceAbort<Result>(
  value: PromiseLike<Result> | Result,
  signal: AbortSignal,
): Promise<Result> {
  if (signal.aborted) return Promise.reject(new Error('request_aborted'));
  return new Promise((resolve, reject) => {
    const abort = () => reject(new Error('request_aborted'));
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve(value).then(
      (result) => {
        signal.removeEventListener('abort', abort);
        resolve(result);
      },
      (error) => {
        signal.removeEventListener('abort', abort);
        reject(error);
      },
    );
  });
}

function buildUrl(baseUrl: string, path: readonly string[], query: CloudflareQuery | undefined): string {
  const encodedPath = path.map((segment) => encodeURIComponent(segment)).join('/');
  const url = new URL(`${baseUrl}/${encodedPath}`);
  if (query !== undefined) {
    const safeQuery = requireQuery(query);
    for (const [key, rawValue] of Object.entries(safeQuery)) {
      const values = Array.isArray(rawValue) ? rawValue : [rawValue];
      for (const value of values) {
        if (value === undefined || value === null) continue;
        if (!v.is(queryPrimitiveSchema, value)) {
          throw new TypeError('query values must be strings, numbers, booleans, or arrays of them');
        }
        url.searchParams.append(key, String(value));
      }
    }
  }
  return url.toString();
}

async function readEnvelope(
  response: CloudflareResponse,
  signal: AbortSignal,
): Promise<BoundaryValue> {
  if (!v.is(v.object({}), response)) return null;
  try {
    if (response.text && v.safeParse(fetchSchema, response.text).success) {
      const text = await raceAbort(response.text(), signal);
      if (text === '') return null;
      const parsed = v.safeParse(boundaryValueSchema, JSON.parse(text));
      return parsed.success ? parsed.output : null;
    }
    if (response.json && v.safeParse(fetchSchema, response.json).success) {
      const parsed = v.safeParse(boundaryValueSchema, await raceAbort(response.json(), signal));
      return parsed.success ? parsed.output : null;
    }
  } catch {
    return null;
  }
  return null;
}

function getRequestId(headers: HeadersReader | undefined): string | undefined {
  if (!headers || !v.safeParse(fetchSchema, headers.get).success) return undefined;
  return sanitizeRequestId(headers.get('cf-ray') ?? headers.get('x-request-id'));
}

function readErrorCodes(value: BoundaryValue): BoundaryValue[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => isObject(item) ? item.code : undefined);
}

function sanitizeCodes(values: readonly BoundaryValue[]): string[] {
  const result: string[] = [];
  for (const value of Array.isArray(values) ? values : []) {
    const code = v.is(numberSchema, value) && Number.isFinite(value) ? String(value) : value;
    if (v.is(stringSchema, code) && SAFE_CODE.test(code) && !result.includes(code)) {
      result.push(code);
    }
    if (result.length === 20) break;
  }
  return result;
}

function sanitizeRequestId(value: BoundaryValue): string | undefined {
  return v.is(stringSchema, value) && SAFE_REQUEST_ID.test(value) ? value : undefined;
}

function safeStatus(value: BoundaryValue): number {
  return v.is(numberSchema, value) && Number.isInteger(value) && value >= 0 && value <= 599
    ? value
    : 0;
}

function readTotalPages(resultInfo: BoundaryValue): number | null {
  if (!isObject(resultInfo) || resultInfo.total_pages === undefined) return null;
  const value = Number(resultInfo.total_pages);
  return Number.isSafeInteger(value) && value >= 1 ? value : null;
}

function id(value: string, label: string): string {
  requireIdentifier(value, label);
  return value;
}

function requireSecret(value: BoundaryValue, label: string): void {
  if (!v.is(stringSchema, value) || value.length === 0 || hasControlCharacters(value)) {
    throw new TypeError(`${label} must be a non-empty string without control characters`);
  }
}

function requireIdentifier(value: BoundaryValue, label: string): void {
  if (
    !v.is(stringSchema, value) ||
    value.trim() === '' ||
    value.length > 256 ||
    hasControlCharacters(value)
  ) {
    throw new TypeError(`${label} must be a non-empty identifier`);
  }
}

function requireBody(value: JsonValue): JsonObject {
  const parsed = v.safeParse(jsonObjectSchema, value);
  if (!parsed.success) throw new TypeError('request body must be a JSON object');
  return parsed.output;
}

function requireQuery(value: CloudflareQuery): CloudflareQuery {
  const parsed = v.safeParse(querySchema, value);
  if (!parsed.success) throw new TypeError('query must be an object');
  return parsed.output;
}

function requireAbortSignal(value: AbortSignal | undefined): void {
  if (value === undefined) return;
  if (!v.safeParse(abortSignalSchema, value).success) {
    throw new TypeError('signal must be an AbortSignal');
  }
}

function hasControlCharacters(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && (codePoint <= 31 || codePoint === 127);
  });
}

function isObject(value: BoundaryValue): value is BoundaryObject {
  return v.is(boundaryObjectSchema, value);
}
