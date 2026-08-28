import * as v from 'valibot';

const JSON_RPC_VERSION = '2.0';
export const SYNTHETIC_MAX_BODY_BYTES = 64 * 1024;
const LATEST_LEGACY_PROTOCOL_VERSION = '2025-11-25';
const MODERN_PROTOCOL_VERSION = '2026-07-28';
const LEGACY_PROTOCOL_VERSIONS = new Set([
  '2025-03-26',
  '2025-06-18',
  LATEST_LEGACY_PROTOCOL_VERSION,
]);
const rpcIdSchema = v.union([v.null(), v.string(), v.pipe(v.number(), v.finite())]);
const rpcMessageSchema = v.looseObject({
  jsonrpc: v.literal(JSON_RPC_VERSION),
  method: v.string(),
});
const initializeParamsSchema = v.looseObject({ protocolVersion: v.string() });

export const SYNTHETIC_TOOL_NAME = 'ankka_canary_status';
export const SYNTHETIC_FIXTURE_ID = 'ankka-synthetic-mcp-canary';

export const SYNTHETIC_TOOL = Object.freeze({
  name: SYNTHETIC_TOOL_NAME,
  title: 'Synthetic canary status',
  description: 'Returns a constant health result from the disposable Ankka MCP canary.',
  inputSchema: {
    type: 'object',
    properties: {},
    additionalProperties: false,
  },
  outputSchema: {
    type: 'object',
    properties: {
      ok: { type: 'boolean' },
      fixture: { type: 'string' },
      version: { type: 'integer' },
    },
    required: ['ok', 'fixture', 'version'],
    additionalProperties: false,
  },
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
});

const RESPONSE_HEADERS = Object.freeze({
  'Cache-Control': 'no-store',
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
});

const TOOL_RESULT = Object.freeze({
  content: [
    {
      type: 'text',
      text: 'Synthetic canary is healthy.',
    },
  ],
  structuredContent: {
    ok: true,
    fixture: SYNTHETIC_FIXTURE_ID,
    version: 1,
  },
  isError: false,
});

export async function handleSyntheticMcpRequest(request) {
  const url = new URL(request.url);
  if (!validOrigin(request, url)) return jsonResponse(403, { error: 'origin_not_allowed' });

  if (url.pathname === '/health') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    return jsonResponse(200, {
      status: 'ok',
      fixture: SYNTHETIC_FIXTURE_ID,
      tool: SYNTHETIC_TOOL_NAME,
    });
  }

  if (url.pathname !== '/mcp') return jsonResponse(404, { error: 'not_found' });
  if (request.method === 'GET') return methodNotAllowed('POST');
  if (request.method !== 'POST') return methodNotAllowed('POST');

  const contentType = request.headers.get('content-type') ?? '';
  if (!contentType.toLowerCase().startsWith('application/json')) {
    return jsonResponse(415, { error: 'content_type_must_be_application_json' });
  }

  const declaredLength = Number(request.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > SYNTHETIC_MAX_BODY_BYTES) {
    return jsonResponse(413, { error: 'request_too_large' });
  }

  let bodyText;
  try {
    bodyText = await request.text();
  } catch {
    return rpcResponse(null, undefined, rpcError(-32700, 'Parse error'));
  }
  if (new TextEncoder().encode(bodyText).byteLength > SYNTHETIC_MAX_BODY_BYTES) {
    return jsonResponse(413, { error: 'request_too_large' });
  }

  let message;
  try {
    message = JSON.parse(bodyText);
  } catch {
    return rpcResponse(null, undefined, rpcError(-32700, 'Parse error'));
  }

  if (!isRpcMessage(message)) {
    return rpcResponse(null, undefined, rpcError(-32600, 'Invalid Request'));
  }

  const transport = validateTransport(request, message);
  if (transport.error) {
    return rpcResponse(message.id ?? null, undefined, transport.error, transport.status);
  }

  if (!Object.hasOwn(message, 'id')) {
    return new Response(null, {
      status: 202,
      headers: {
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  }

  const result = dispatch(message.method, message.params, transport.modern);
  if (result.error) return rpcResponse(message.id, undefined, result.error);
  return rpcResponse(
    message.id,
    transport.modern ? modernResult(message.method, result.value) : result.value,
  );
}

function dispatch(method, params, modern) {
  switch (method) {
    case 'initialize':
      if (modern) return failed(-32601, 'Method not found');
      return initialize(params);
    case 'server/discover':
      if (!modern) return failed(-32601, 'Method not found');
      return ok({
        supportedVersions: [MODERN_PROTOCOL_VERSION],
        capabilities: { tools: {} },
        instructions: 'Disposable test fixture. The only tool returns constant synthetic data.',
        ttlMs: 3_600_000,
        cacheScope: 'public',
      });
    case 'ping':
      return ok({});
    case 'tools/list':
      return ok(modern
        ? { tools: [SYNTHETIC_TOOL], ttlMs: 3_600_000, cacheScope: 'public' }
        : { tools: [SYNTHETIC_TOOL] });
    case 'tools/call':
      return callTool(params);
    default:
      return failed(-32601, 'Method not found');
  }
}

function initialize(params) {
  if (!v.is(initializeParamsSchema, params)) {
    return failed(-32602, 'Invalid params');
  }
  const requested = params.protocolVersion;
  const protocolVersion = LEGACY_PROTOCOL_VERSIONS.has(requested)
    ? requested
    : LATEST_LEGACY_PROTOCOL_VERSION;
  return ok({
    protocolVersion,
    capabilities: {
      tools: { listChanged: false },
    },
    serverInfo: {
      name: SYNTHETIC_FIXTURE_ID,
      title: 'Ankka synthetic MCP canary',
      version: '1.0.0',
    },
    instructions: 'Disposable test fixture. The only tool returns constant synthetic data.',
  });
}

function callTool(params) {
  if (!isObject(params) || params.name !== SYNTHETIC_TOOL_NAME) {
    return failed(-32602, 'Unknown tool');
  }
  const args = params.arguments ?? {};
  if (!isObject(args) || Object.keys(args).length !== 0) {
    return failed(-32602, 'Invalid tool arguments');
  }
  return ok(TOOL_RESULT);
}

function validateTransport(request, message) {
  const protocolVersion = request.headers.get('mcp-protocol-version');
  const modern = protocolVersion === MODERN_PROTOCOL_VERSION;
  if (
    protocolVersion !== null
    && protocolVersion !== MODERN_PROTOCOL_VERSION
    && !LEGACY_PROTOCOL_VERSIONS.has(protocolVersion)
  ) {
    return {
      status: 400,
      error: rpcError(-32600, 'Unsupported protocol version'),
    };
  }

  const methodHeader = request.headers.get('mcp-method');
  const nameHeader = request.headers.get('mcp-name');
  if (
    (methodHeader !== null && methodHeader !== message.method)
    || (modern && methodHeader === null)
    || (message.method === 'tools/call' && nameHeader !== null && nameHeader !== message.params?.name)
    || (modern && message.method === 'tools/call' && nameHeader === null)
  ) {
    return {
      status: 400,
      error: rpcError(-32001, 'Header mismatch'),
    };
  }

  if (modern) {
    const envelopeVersion = message.params?._meta?.['io.modelcontextprotocol/protocolVersion'];
    if (envelopeVersion !== MODERN_PROTOCOL_VERSION) {
      return {
        status: 400,
        error: rpcError(-32600, 'Unsupported protocol version'),
      };
    }
  }

  return { modern };
}

function modernResult(_method, value) {
  return {
    resultType: 'complete',
    ...value,
    _meta: {
      'io.modelcontextprotocol/serverInfo': {
        name: SYNTHETIC_FIXTURE_ID,
        version: '1.0.0',
      },
    },
  };
}

function validOrigin(request, url) {
  const origin = request.headers.get('origin');
  if (origin === null) return true;
  try {
    return new URL(origin).origin === url.origin;
  } catch {
    return false;
  }
}

function isRpcMessage(value) {
  if (!v.is(rpcMessageSchema, value)) return false;
  if (!Object.hasOwn(value, 'id')) return true;
  return v.is(rpcIdSchema, value.id);
}

function isObject(value) {
  return v.is(v.record(v.string(), v.unknown()), value);
}

function ok(value) {
  return { value };
}

function failed(code, message) {
  return { error: rpcError(code, message) };
}

function rpcError(code, message) {
  return { code, message };
}

function rpcResponse(id, result, error, status = 200) {
  const body = { jsonrpc: JSON_RPC_VERSION, id };
  if (error) body.error = error;
  else body.result = result;
  return jsonResponse(status, body);
}

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: RESPONSE_HEADERS,
  });
}

function methodNotAllowed(allow) {
  const response = jsonResponse(405, { error: 'method_not_allowed' });
  response.headers.set('Allow', allow);
  return response;
}

export default {
  fetch: handleSyntheticMcpRequest,
};
