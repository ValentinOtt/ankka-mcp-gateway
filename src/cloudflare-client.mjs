const DEFAULT_BASE_URL = 'https://api.cloudflare.com/client/v4';
const PAGE_SIZE = 100;
const MAX_PAGES = 100;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const SAFE_CODE = /^[A-Za-z0-9_.:-]{1,64}$/;
const SAFE_REQUEST_ID = /^[A-Za-z0-9_.:/-]{1,128}$/;

export class CloudflareApiError extends Error {
  constructor(operation, { status = 0, codes = [], requestId } = {}) {
    const safeOperation = SAFE_CODE.test(operation) ? operation : 'unknown_operation';
    const safeStatus = Number.isInteger(status) && status >= 0 && status <= 599 ? status : 0;
    const safeCodes = sanitizeCodes(codes);
    const safeRequestId = sanitizeRequestId(requestId);
    const details = [
      `operation=${safeOperation}`,
      `status=${safeStatus}`,
      `codes=${safeCodes.length > 0 ? safeCodes.join(',') : 'none'}`,
    ];
    if (safeRequestId) details.push(`request_id=${safeRequestId}`);
    super(`Cloudflare API request failed: ${details.join(' ')}`);
    this.name = 'CloudflareApiError';
    this.operation = safeOperation;
    this.status = safeStatus;
    this.codes = Object.freeze(safeCodes);
    this.requestId = safeRequestId;
  }
}

export function createCloudflareClient(options = {}) {
  if (!isObject(options)) throw new TypeError('client options must be an object');
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
    fetchImpl = globalThis.fetch,
    signal,
    requestTimeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
  } = options;
  requireSecret(token, 'token');
  requireIdentifier(accountId, 'accountId');
  requireIdentifier(zoneId, 'zoneId');
  if (typeof fetchImpl !== 'function') throw new TypeError('fetchImpl must be a function');
  requireAbortSignal(signal);
  if (!Number.isInteger(requestTimeoutMs) || requestTimeoutMs < 1 || requestTimeoutMs > 120_000) {
    throw new TypeError('requestTimeoutMs must be an integer from 1 to 120000');
  }
  const apiBase = DEFAULT_BASE_URL;

  const account = ['accounts', accountId];
  const aiMcp = [...account, 'access', 'ai-controls', 'mcp'];
  const mcpServers = [...aiMcp, 'servers'];
  const portals = [...aiMcp, 'portals'];
  const accessApps = [...account, 'access', 'apps'];
  const dnsRecords = ['zones', zoneId, 'dns_records'];

  const request = async (
    operation,
    method,
    path,
    { query, body, nullOn404 = false, withInfo = false } = {},
  ) => {
    const url = buildUrl(apiBase, path, query);
    const headers = {
      Accept: 'application/json',
      Authorization: `Bearer ${token}`,
    };
    const init = { method, headers };
    if (body !== undefined) {
      requireBody(body);
      headers['Content-Type'] = 'application/json';
      try {
        init.body = JSON.stringify(body);
      } catch {
        throw new CloudflareApiError(operation, { codes: ['invalid_request_body'] });
      }
    }

    const requestAbort = createRequestAbort(signal, requestTimeoutMs);
    init.signal = requestAbort.signal;
    try {
      let response;
      try {
        if (requestAbort.signal.aborted) throw new Error('request_aborted');
        response = await raceAbort(fetchImpl(url, init), requestAbort.signal);
      } catch {
        throw new CloudflareApiError(operation, { codes: ['network_error'] });
      }
      const status = safeStatus(response?.status);
      const requestId = getRequestId(response?.headers);
      if (nullOn404 && status === 404) return null;
      if (response?.ok && status === 204) return null;

      const envelope = await readEnvelope(response, requestAbort.signal);
      if (!response?.ok || !isObject(envelope) || envelope.success !== true) {
        const codes = isObject(envelope)
          ? sanitizeCodes(Array.isArray(envelope.errors) ? envelope.errors.map((item) => item?.code) : [])
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

  const paginate = async (operation, path, query = {}) => {
    requireQuery(query);
    const results = [];
    for (let page = 1; page <= MAX_PAGES; page += 1) {
      const response = await request(operation, 'GET', path, {
        query: { ...query, page, per_page: PAGE_SIZE },
        withInfo: true,
      });
      if (!Array.isArray(response.result)) {
        throw new CloudflareApiError(operation, {
          status: 200,
          codes: ['invalid_response'],
        });
      }
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
    listIdentityProviders: (query = {}) =>
      paginate('list_identity_providers', [...account, 'access', 'identity_providers'], query),

    listMcpServers: (query = {}) => paginate('list_mcp_servers', mcpServers, query),
    getMcpServer: (serverId) =>
      request('get_mcp_server', 'GET', [...mcpServers, id(serverId, 'serverId')], {
        nullOn404: true,
      }),
    createMcpServer: (body) => request('create_mcp_server', 'POST', mcpServers, { body }),
    updateMcpServer: (serverId, body) =>
      request('update_mcp_server', 'PUT', [...mcpServers, id(serverId, 'serverId')], { body }),
    deleteMcpServer: (serverId) =>
      request('delete_mcp_server', 'DELETE', [...mcpServers, id(serverId, 'serverId')]),
    syncMcpServer: (serverId) =>
      request('sync_mcp_server', 'POST', [...mcpServers, id(serverId, 'serverId'), 'sync']),

    listPortals: (query = {}) => paginate('list_portals', portals, query),
    getPortal: (portalId) =>
      request('get_portal', 'GET', [...portals, id(portalId, 'portalId')], {
        nullOn404: true,
      }),
    createPortal: (body) => request('create_portal', 'POST', portals, { body }),
    updatePortal: (portalId, body) =>
      request('update_portal', 'PUT', [...portals, id(portalId, 'portalId')], { body }),
    deletePortal: (portalId) =>
      request('delete_portal', 'DELETE', [...portals, id(portalId, 'portalId')]),

    listAccessApps: (query = {}) => paginate('list_access_apps', accessApps, query),
    getAccessApp: (appId) =>
      request('get_access_app', 'GET', [...accessApps, id(appId, 'appId')], {
        nullOn404: true,
      }),
    createAccessApp: (body) =>
      request('create_access_app', 'POST', accessApps, { body }),
    updateAccessApp: (appId, body) =>
      request('update_access_app', 'PUT', [...accessApps, id(appId, 'appId')], { body }),
    deleteAccessApp: (appId) =>
      request('delete_access_app', 'DELETE', [...accessApps, id(appId, 'appId')]),

    listAppPolicies: (appId, query = {}) =>
      paginate(
        'list_app_policies',
        [...accessApps, id(appId, 'appId'), 'policies'],
        query,
      ),
    getAppPolicy: (appId, policyId) =>
      request(
        'get_app_policy',
        'GET',
        [...accessApps, id(appId, 'appId'), 'policies', id(policyId, 'policyId')],
        { nullOn404: true },
      ),
    createAppPolicy: (appId, body) =>
      request(
        'create_app_policy',
        'POST',
        [...accessApps, id(appId, 'appId'), 'policies'],
        { body },
      ),
    updateAppPolicy: (appId, policyId, body) =>
      request(
        'update_app_policy',
        'PUT',
        [...accessApps, id(appId, 'appId'), 'policies', id(policyId, 'policyId')],
        { body },
      ),
    deleteAppPolicy: (appId, policyId) =>
      request(
        'delete_app_policy',
        'DELETE',
        [...accessApps, id(appId, 'appId'), 'policies', id(policyId, 'policyId')],
      ),

    listDnsRecords: (query = {}) => paginate('list_dns_records', dnsRecords, query),
    getDnsRecord: (recordId) =>
      request('get_dns_record', 'GET', [...dnsRecords, id(recordId, 'recordId')], {
        nullOn404: true,
      }),
    createDnsRecord: (body) => request('create_dns_record', 'POST', dnsRecords, { body }),
    updateDnsRecord: (recordId, body) =>
      request('update_dns_record', 'PUT', [...dnsRecords, id(recordId, 'recordId')], { body }),
    deleteDnsRecord: (recordId) =>
      request('delete_dns_record', 'DELETE', [...dnsRecords, id(recordId, 'recordId')]),
  });
}

function createRequestAbort(externalSignal, requestTimeoutMs) {
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

function raceAbort(value, signal) {
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

function buildUrl(baseUrl, path, query) {
  const encodedPath = path.map((segment) => encodeURIComponent(segment)).join('/');
  const url = new URL(`${baseUrl}/${encodedPath}`);
  if (query !== undefined) {
    requireQuery(query);
    for (const [key, rawValue] of Object.entries(query)) {
      const values = Array.isArray(rawValue) ? rawValue : [rawValue];
      for (const value of values) {
        if (value === undefined || value === null) continue;
        if (!['string', 'number', 'boolean'].includes(typeof value)) {
          throw new TypeError('query values must be strings, numbers, booleans, or arrays of them');
        }
        url.searchParams.append(key, String(value));
      }
    }
  }
  return url.toString();
}

async function readEnvelope(response, signal) {
  if (!response || typeof response !== 'object') return null;
  try {
    if (typeof response.text === 'function') {
      const text = await raceAbort(response.text(), signal);
      return text === '' ? null : JSON.parse(text);
    }
    if (typeof response.json === 'function') return await raceAbort(response.json(), signal);
  } catch {
    return null;
  }
  return null;
}

function getRequestId(headers) {
  if (!headers || typeof headers.get !== 'function') return undefined;
  return sanitizeRequestId(headers.get('cf-ray') ?? headers.get('x-request-id'));
}

function sanitizeCodes(values) {
  const result = [];
  for (const value of Array.isArray(values) ? values : []) {
    const code = typeof value === 'number' && Number.isFinite(value) ? String(value) : value;
    if (typeof code === 'string' && SAFE_CODE.test(code) && !result.includes(code)) result.push(code);
    if (result.length === 20) break;
  }
  return result;
}

function sanitizeRequestId(value) {
  return typeof value === 'string' && SAFE_REQUEST_ID.test(value) ? value : undefined;
}

function safeStatus(value) {
  return Number.isInteger(value) && value >= 0 && value <= 599 ? value : 0;
}

function readTotalPages(resultInfo) {
  if (!isObject(resultInfo) || resultInfo.total_pages === undefined) return null;
  const value = Number(resultInfo.total_pages);
  return Number.isSafeInteger(value) && value >= 1 ? value : null;
}

function id(value, label) {
  requireIdentifier(value, label);
  return value;
}

function requireSecret(value, label) {
  if (typeof value !== 'string' || value.length === 0 || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new TypeError(`${label} must be a non-empty string without control characters`);
  }
}

function requireIdentifier(value, label) {
  if (
    typeof value !== 'string' ||
    value.trim() === '' ||
    value.length > 256 ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new TypeError(`${label} must be a non-empty identifier`);
  }
}

function requireBody(value) {
  if (!isObject(value)) throw new TypeError('request body must be a JSON object');
}

function requireQuery(value) {
  if (!isObject(value)) throw new TypeError('query must be an object');
}

function requireAbortSignal(value) {
  if (value === undefined) return;
  if (!isObject(value)
    || typeof value.aborted !== 'boolean'
    || typeof value.addEventListener !== 'function'
    || typeof value.removeEventListener !== 'function') {
    throw new TypeError('signal must be an AbortSignal');
  }
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
