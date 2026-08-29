import { createHash } from 'node:crypto';
import { open } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { performance } from 'node:perf_hooks';
import { isIP } from 'node:net';
import { pathToFileURL } from 'node:url';
import * as v from 'valibot';

const PROTOCOL_VERSION = '2026-07-28';
const CLIENT_NAME = 'ankka-live-portal-canary';
const CLIENT_VERSION = '1.0.0';
const CONFIG_LIMIT_BYTES = 16 * 1024;
const RESPONSE_LIMIT_BYTES = 128 * 1024;
const RESPONSE_AGGREGATE_LIMIT_BYTES = 3 * RESPONSE_LIMIT_BYTES;
const CANONICAL_RESULT_LIMIT_BYTES = 64 * 1024;
const TOTAL_DEADLINE_MS = 20_000;
const REQUEST_TIMEOUT_MS = 7_000;
const MAX_PORTAL_TOOLS = 32;
const MAX_RESULT_NODES = 4_096;
const MAX_RESULT_DEPTH = 24;
const MAX_CONTENT_BLOCKS = 16;
const MAX_IDENTIFIER_LENGTH = 192;
const MAX_CREDENTIAL_LENGTH = 4_096;
const HASH = /^sha256:[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/u;
const BOOLEAN_SCHEMA = v.boolean();
const FUNCTION_SCHEMA = v.function();
const NUMBER_SCHEMA = v.number();
const OBJECT_SCHEMA = v.object({});
const STRING_SCHEMA = v.string();
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const CONFIG_KEYS = Object.freeze([
  'arguments',
  'expectedCanonicalResultSha256',
  'healthToolIdentifier',
  'portalUrl',
  'schemaVersion',
]);
const REQUIRED_CODE_MODE_TOOLS = Object.freeze([
  'portal_codemode_execute',
  'portal_codemode_search',
]);
const ALLOWED_PORTAL_TOOLS = new Set([
  ...REQUIRED_CODE_MODE_TOOLS,
  'portal_list_servers',
  'portal_toggle_servers',
  'portal_toggle_single_server',
]);
const BLOCKED_HOSTNAME_SUFFIXES = Object.freeze([
  '.internal',
  '.invalid',
  '.local',
  '.localhost',
  '.onion',
  '.test',
]);
const BLOCKED_IDENTIFIERS = new Set(['__proto__', 'constructor', 'prototype']);
const CODE_LITERAL_ESCAPES = Object.freeze({
  '<': '\\u003C',
  '>': '\\u003E',
  '/': '\\u002F',
  '\b': '\\b',
  '\f': '\\f',
  '\n': '\\n',
  '\r': '\\r',
  '\t': '\\t',
  '\0': '\\0',
  '\u2028': '\\u2028',
  '\u2029': '\\u2029',
});

export const SEARCH_RESULT_MARKER = '__ankka_live_portal_canary_search_v1';
export const EXECUTE_RESULT_MARKER = '__ankka_live_portal_canary_result_v1';

export const LIVE_PORTAL_CANARY_CODES = Object.freeze([
  'ok',
  'argument_invalid',
  'config_read_failed',
  'config_too_large',
  'config_json_invalid',
  'config_invalid',
  'credential_missing',
  'credential_invalid',
  'transport_invalid',
  'portal_unreachable',
  'portal_request_timeout',
  'portal_deadline_exceeded',
  'portal_redirect_rejected',
  'portal_auth_rejected',
  'portal_http_rejected',
  'portal_response_too_large',
  'portal_response_invalid',
  'portal_rpc_rejected',
  'portal_tool_surface_invalid',
  'code_mode_tools_missing',
  'upstream_tools_exposed',
  'health_search_failed',
  'health_tool_not_found',
  'health_execute_failed',
  'health_result_invalid',
  'health_result_mismatch',
  'internal_failure',
]);

const CODE_SET = new Set(LIVE_PORTAL_CANARY_CODES);

export class LivePortalCanaryError extends Error {
  constructor(code) {
    super('live_portal_canary_failure');
    this.name = 'LivePortalCanaryError';
    this.code = CODE_SET.has(code) && code !== 'ok' ? code : 'internal_failure';
  }
}

function fail(code) {
  throw new LivePortalCanaryError(code);
}

function isRecord(value) {
  if (!v.is(OBJECT_SCHEMA, value) || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function exactKeys(value, expected) {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value).sort(compareText);
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function exactPortalUrl(value) {
  if (!v.is(STRING_SCHEMA, value) || value.length === 0 || value.length > 2_048) return null;
  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  const hostname = url.hostname.toLowerCase();
  if (
    url.href !== value
    || url.protocol !== 'https:'
    || url.username !== ''
    || url.password !== ''
    || url.port !== ''
    || url.pathname !== '/mcp'
    || url.search !== ''
    || url.hash !== ''
    || !HOSTNAME.test(hostname)
    || isIP(hostname) !== 0
    || hostname === 'localhost'
    || BLOCKED_HOSTNAME_SUFFIXES.some((suffix) => hostname.endsWith(suffix))
  ) {
    return null;
  }
  return url.href;
}

function safeIdentifier(value) {
  return v.is(STRING_SCHEMA, value)
    && value.length > 0
    && value.length <= MAX_IDENTIFIER_LENGTH
    && IDENTIFIER.test(value)
    && !value.startsWith('portal_')
    && !BLOCKED_IDENTIFIERS.has(value);
}

/** Validate the complete, secret-free live canary configuration contract. */
export function validateLivePortalCanaryConfig(value) {
  if (!exactKeys(value, CONFIG_KEYS)) fail('config_invalid');
  const portalUrl = exactPortalUrl(value.portalUrl);
  if (
    value.schemaVersion !== 1
    || portalUrl === null
    || !safeIdentifier(value.healthToolIdentifier)
    || !exactKeys(value.arguments, [])
    || !v.is(STRING_SCHEMA, value.expectedCanonicalResultSha256)
    || !HASH.test(value.expectedCanonicalResultSha256)
  ) {
    fail('config_invalid');
  }
  return Object.freeze({
    schemaVersion: 1,
    portalUrl,
    healthToolIdentifier: value.healthToolIdentifier,
    arguments: Object.freeze({}),
    expectedCanonicalResultSha256: value.expectedCanonicalResultSha256,
  });
}

function canonicalJsonValue(value, state, depth) {
  state.nodes += 1;
  if (state.nodes > MAX_RESULT_NODES || depth > MAX_RESULT_DEPTH) fail('health_result_invalid');
  if (value === null || v.is(BOOLEAN_SCHEMA, value) || v.is(STRING_SCHEMA, value)) {
    if (v.is(STRING_SCHEMA, value) && Buffer.byteLength(value, 'utf8') > CANONICAL_RESULT_LIMIT_BYTES) {
      fail('health_result_invalid');
    }
    return boundedCanonicalJson(JSON.stringify(value));
  }
  if (v.is(NUMBER_SCHEMA, value)) {
    if (!Number.isFinite(value)) fail('health_result_invalid');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (state.seen.has(value)) fail('health_result_invalid');
    state.seen.add(value);
    let serialized = '[';
    for (const [index, entry] of value.entries()) {
      if (index > 0) serialized += ',';
      serialized += canonicalJsonValue(entry, state, depth + 1);
      boundedCanonicalJson(serialized);
    }
    serialized += ']';
    state.seen.delete(value);
    return boundedCanonicalJson(serialized);
  }
  if (!isRecord(value) || state.seen.has(value)) fail('health_result_invalid');
  state.seen.add(value);
  let serialized = '{';
  for (const [index, key] of Object.keys(value).sort(compareText).entries()) {
    if (Buffer.byteLength(key, 'utf8') > CANONICAL_RESULT_LIMIT_BYTES) {
      fail('health_result_invalid');
    }
    if (index > 0) serialized += ',';
    serialized += `${JSON.stringify(key)}:${canonicalJsonValue(value[key], state, depth + 1)}`;
    boundedCanonicalJson(serialized);
  }
  serialized += '}';
  state.seen.delete(value);
  return boundedCanonicalJson(serialized);
}

function boundedCanonicalJson(serialized) {
  if (Buffer.byteLength(serialized, 'utf8') > CANONICAL_RESULT_LIMIT_BYTES) {
    fail('health_result_invalid');
  }
  return serialized;
}

/** Serialize JSON values with recursively sorted object keys. */
export function canonicalResultJson(value) {
  return canonicalJsonValue(value, { nodes: 0, seen: new WeakSet() }, 0);
}

/** Hash the exact canonical value returned by the no-argument health tool. */
export function canonicalResultSha256(value) {
  return `sha256:${createHash('sha256').update(canonicalResultJson(value), 'utf8').digest('hex')}`;
}

function credential(environment, name) {
  const value = environment?.[name];
  if (value === undefined || value === '') fail('credential_missing');
  if (
    !v.is(STRING_SCHEMA, value)
    || value.length > MAX_CREDENTIAL_LENGTH
    || value.trim() !== value
    || /[^\x21-\x7e]/u.test(value)
  ) {
    fail('credential_invalid');
  }
  return value;
}

async function readBoundedResponse(response, maximumBytes) {
  const declared = response.headers.get('content-length');
  if (declared !== null) {
    if (!/^\d+$/u.test(declared)) {
      cancelResponseBody(response);
      fail('portal_response_invalid');
    }
    if (!Number.isSafeInteger(Number(declared)) || Number(declared) > maximumBytes) {
      cancelResponseBody(response);
      fail('portal_response_too_large');
    }
  }
  if (response.body === null) {
    fail('portal_response_invalid');
  }
  const reader = response.body.getReader();
  const chunks = [];
  let byteLength = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      if (!(next.value instanceof Uint8Array)) fail('portal_response_invalid');
      byteLength += next.value.byteLength;
      if (byteLength > maximumBytes) {
        try {
          await reader.cancel();
        } catch {
          // The fixed size failure remains authoritative.
        }
        fail('portal_response_too_large');
      }
      chunks.push(next.value);
    }
  } catch (error) {
    if (error instanceof LivePortalCanaryError) throw error;
    fail('portal_response_invalid');
  }
  const bytes = new Uint8Array(byteLength);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail('portal_response_invalid');
  }
  return Object.freeze({ byteLength, text });
}

function cancelResponseBody(response) {
  try {
    const cancellation = response.body?.cancel();
    cancellation?.catch(() => {
      // The fixed response failure remains authoritative.
    });
  } catch {
    // The fixed response failure remains authoritative.
  }
}

function parseJsonRpcResponse(serialized, contentType, requestId) {
  const candidates = [];
  if (contentType.startsWith('application/json')) {
    try {
      candidates.push(JSON.parse(serialized));
    } catch {
      fail('portal_response_invalid');
    }
  } else if (contentType.startsWith('text/event-stream')) {
    const events = serialized.split(/\r?\n\r?\n/u);
    if (events.length > 64) fail('portal_response_invalid');
    for (const event of events) {
      const data = event.split(/\r?\n/u)
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice(5).trimStart())
        .join('\n');
      if (data === '') continue;
      try {
        candidates.push(JSON.parse(data));
      } catch {
        fail('portal_response_invalid');
      }
    }
  } else {
    fail('portal_response_invalid');
  }
  const matching = candidates.filter((candidate) => (
    isRecord(candidate)
    && candidate.jsonrpc === '2.0'
    && candidate.id === requestId
  ));
  if (matching.length !== 1) fail('portal_response_invalid');
  return matching[0];
}

function requestHeaders(clientId, clientSecret, method, name) {
  const headers = {
    Accept: 'application/json, text/event-stream',
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json',
    'CF-Access-Client-Id': clientId,
    'CF-Access-Client-Secret': clientSecret,
    'MCP-Protocol-Version': PROTOCOL_VERSION,
    'Mcp-Method': method,
  };
  if (name !== undefined) headers['Mcp-Name'] = name;
  return headers;
}

/**
 * Create the real stateless HTTP transport. Access credentials are read only
 * from the two documented environment variables and are retained in memory.
 */
export function createStatelessPortalTransport(
  portalUrl,
  { environment = process.env, fetchImpl = globalThis.fetch } = {},
) {
  const endpoint = exactPortalUrl(portalUrl);
  if (endpoint === null) fail('config_invalid');
  if (!v.is(FUNCTION_SCHEMA, fetchImpl)) fail('transport_invalid');
  const clientId = credential(environment, 'CF_ACCESS_CLIENT_ID');
  const clientSecret = credential(environment, 'CF_ACCESS_CLIENT_SECRET');
  let aggregateBytes = 0;

  return async function statelessPortalTransport({ id, method, name, params, signal }) {
    if (signal?.aborted) fail('portal_deadline_exceeded');
    const controller = new AbortController();
    let deadlineAborted = false;
    let requestTimedOut = false;
    const abortForDeadline = () => {
      deadlineAborted = true;
      controller.abort();
    };
    if (signal?.aborted) abortForDeadline();
    else signal?.addEventListener('abort', abortForDeadline, { once: true });
    const timeout = setTimeout(() => {
      requestTimedOut = true;
      controller.abort();
    }, REQUEST_TIMEOUT_MS);
    const message = { jsonrpc: '2.0', id, method, params };
    try {
      let response;
      try {
        response = await fetchImpl(endpoint, {
          method: 'POST',
          redirect: 'error',
          headers: requestHeaders(clientId, clientSecret, method, name),
          body: canonicalJsonValue(message, { nodes: 0, seen: new WeakSet() }, 0),
          signal: controller.signal,
        });
      } catch {
        if (deadlineAborted) fail('portal_deadline_exceeded');
        if (requestTimedOut) fail('portal_request_timeout');
        fail('portal_unreachable');
      }
      if (!(response instanceof Response)) {
        fail('portal_response_invalid');
      }
      if (response.redirected || response.status >= 300 && response.status < 400) {
        cancelResponseBody(response);
        fail('portal_redirect_rejected');
      }
      if (response.status === 401 || response.status === 403) {
        cancelResponseBody(response);
        fail('portal_auth_rejected');
      }
      if (response.status !== 200) {
        cancelResponseBody(response);
        fail('portal_http_rejected');
      }
      const contentType = (response.headers.get('content-type') ?? '').toLowerCase();
      if (
        !contentType.startsWith('application/json')
        && !contentType.startsWith('text/event-stream')
      ) {
        cancelResponseBody(response);
        fail('portal_response_invalid');
      }
      let bounded;
      try {
        bounded = await readBoundedResponse(response, RESPONSE_LIMIT_BYTES);
      } catch (error) {
        if (deadlineAborted) fail('portal_deadline_exceeded');
        if (requestTimedOut) fail('portal_request_timeout');
        throw error;
      }
      aggregateBytes += bounded.byteLength;
      if (aggregateBytes > RESPONSE_AGGREGATE_LIMIT_BYTES) fail('portal_response_too_large');
      return parseJsonRpcResponse(bounded.text, contentType, id);
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener('abort', abortForDeadline);
      controller.abort();
    }
  };
}

function modernMeta() {
  return {
    'io.modelcontextprotocol/clientInfo': {
      name: CLIENT_NAME,
      version: CLIENT_VERSION,
    },
  };
}

function requireRpcResult(message, expectedId, rejectedCode) {
  if (
    !isRecord(message)
    || message.jsonrpc !== '2.0'
    || message.id !== expectedId
  ) {
    fail('portal_response_invalid');
  }
  if (Object.hasOwn(message, 'error')) fail(rejectedCode);
  if (!Object.hasOwn(message, 'result')) fail('portal_response_invalid');
  return message.result;
}

function verifyPortalToolSurface(result) {
  if (
    !isRecord(result)
    || !Array.isArray(result.tools)
    || result.tools.length === 0
    || result.tools.length > MAX_PORTAL_TOOLS
    || Object.hasOwn(result, 'nextCursor')
  ) {
    fail('portal_tool_surface_invalid');
  }
  const names = [];
  const seen = new Set();
  for (const tool of result.tools) {
    if (
      !isRecord(tool)
      || !v.is(STRING_SCHEMA, tool.name)
      || tool.name.length === 0
      || tool.name.length > 256
      || seen.has(tool.name)
    ) {
      fail('portal_tool_surface_invalid');
    }
    seen.add(tool.name);
    names.push(tool.name);
  }
  if (names.some((name) => !ALLOWED_PORTAL_TOOLS.has(name))) fail('upstream_tools_exposed');
  if (REQUIRED_CODE_MODE_TOOLS.some((name) => !seen.has(name))) fail('code_mode_tools_missing');
}

function collectMarker(value, marker, matches, state, depth) {
  state.nodes += 1;
  if (state.nodes > MAX_RESULT_NODES || depth > MAX_RESULT_DEPTH) fail('health_result_invalid');
  if (Array.isArray(value)) {
    if (state.seen.has(value)) fail('health_result_invalid');
    state.seen.add(value);
    for (const entry of value) collectMarker(entry, marker, matches, state, depth + 1);
    state.seen.delete(value);
    return;
  }
  if (!isRecord(value)) return;
  if (state.seen.has(value)) fail('health_result_invalid');
  state.seen.add(value);
  for (const [key, entry] of Object.entries(value)) {
    if (key === marker) matches.push(entry);
    else collectMarker(entry, marker, matches, state, depth + 1);
  }
  state.seen.delete(value);
}

function markerMatches(value, marker) {
  const matches = [];
  collectMarker(value, marker, matches, { nodes: 0, seen: new WeakSet() }, 0);
  return matches;
}

function extractMarkedCallResult(result, marker, failureCode) {
  if (!isRecord(result) || result.isError === true) fail(failureCode);
  if (Object.hasOwn(result, 'isError') && !v.is(BOOLEAN_SCHEMA, result.isError)) {
    fail('health_result_invalid');
  }
  if (Object.hasOwn(result, 'structuredContent')) {
    const structured = markerMatches(result.structuredContent, marker);
    if (structured.length === 1) return structured[0];
    if (structured.length > 1) fail('health_result_invalid');
  }
  if (!Array.isArray(result.content) || result.content.length > MAX_CONTENT_BLOCKS) {
    fail('health_result_invalid');
  }
  const matches = [];
  for (const block of result.content) {
    if (!isRecord(block) || block.type !== 'text' || !v.is(STRING_SCHEMA, block.text)) continue;
    let parsed;
    try {
      parsed = JSON.parse(block.text);
    } catch {
      continue;
    }
    matches.push(...markerMatches(parsed, marker));
  }
  if (matches.length !== 1) fail('health_result_invalid');
  return matches[0];
}

function codeStringLiteral(value) {
  return JSON.stringify(value).replace(
    /[<>/\b\f\n\r\t\0\u2028\u2029]/gu,
    (character) => CODE_LITERAL_ESCAPES[character],
  );
}

function searchCode(identifier) {
  const encoded = codeStringLiteral(identifier);
  return `async () => {\n  const tools = await codemode.tools();\n  return {${codeStringLiteral(SEARCH_RESULT_MARKER)}: tools.filter((tool) => tool && tool.name === ${encoded}).map((tool) => tool.name)};\n}`;
}

function executeCode(identifier) {
  return `async () => ({${codeStringLiteral(EXECUTE_RESULT_MARKER)}: await codemode[${codeStringLiteral(identifier)}]({})})`;
}

function createDeadline(durationMs) {
  const controller = new AbortController();
  let rejectDeadline;
  const expired = new Promise((_, reject) => {
    rejectDeadline = reject;
  });
  const timer = setTimeout(() => {
    controller.abort();
    rejectDeadline(new LivePortalCanaryError('portal_deadline_exceeded'));
  }, durationMs);
  return Object.freeze({
    signal: controller.signal,
    wait(operation) {
      return Promise.race([operation, expired]);
    },
    close() {
      clearTimeout(timer);
      controller.abort();
    },
  });
}

async function runPhase(deadline, transport, request, latencies, phase) {
  const started = performance.now();
  try {
    return await deadline.wait(Promise.resolve().then(() => transport(request)));
  } finally {
    latencies[phase] = elapsed(started);
  }
}

function elapsed(started) {
  const duration = Math.round(performance.now() - started);
  return Number.isSafeInteger(duration) && duration >= 0 ? Math.min(duration, TOTAL_DEADLINE_MS) : 0;
}

function report(status, code, startedAt, started, latencies) {
  return Object.freeze({
    schemaVersion: 1,
    status,
    code,
    startedAt,
    finishedAt: new Date().toISOString(),
    latenciesMs: Object.freeze({
      total: elapsed(started),
      list_tools: latencies.list_tools,
      search: latencies.search,
      execute: latencies.execute,
    }),
  });
}

function fixedFailureCode(error) {
  return error instanceof LivePortalCanaryError && CODE_SET.has(error.code) && error.code !== 'ok'
    ? error.code
    : 'internal_failure';
}

/** Run one read-only live Portal check and return a bounded, content-free report. */
export async function runLivePortalCanary(
  input,
  {
    transport,
    environment = process.env,
    fetchImpl = globalThis.fetch,
    deadlineMs = TOTAL_DEADLINE_MS,
  } = {},
) {
  const started = performance.now();
  const startedAt = new Date().toISOString();
  const latencies = { list_tools: null, search: null, execute: null };
  let deadline;
  try {
    const config = validateLivePortalCanaryConfig(input);
    if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > TOTAL_DEADLINE_MS) {
      fail('internal_failure');
    }
    const activeTransport = transport ?? createStatelessPortalTransport(config.portalUrl, {
      environment,
      fetchImpl,
    });
    if (!v.is(FUNCTION_SCHEMA, activeTransport)) fail('transport_invalid');
    deadline = createDeadline(deadlineMs);
    const listedMessage = await runPhase(deadline, activeTransport, {
      id: 'ankka-live-list',
      method: 'tools/list',
      params: { _meta: modernMeta() },
      signal: deadline.signal,
    }, latencies, 'list_tools');
    verifyPortalToolSurface(requireRpcResult(
      listedMessage,
      'ankka-live-list',
      'portal_rpc_rejected',
    ));

    const searchedMessage = await runPhase(deadline, activeTransport, {
      id: 'ankka-live-search',
      method: 'tools/call',
      name: 'portal_codemode_search',
      params: {
        name: 'portal_codemode_search',
        arguments: { code: searchCode(config.healthToolIdentifier) },
        _meta: modernMeta(),
      },
      signal: deadline.signal,
    }, latencies, 'search');
    const searched = extractMarkedCallResult(
      requireRpcResult(searchedMessage, 'ankka-live-search', 'health_search_failed'),
      SEARCH_RESULT_MARKER,
      'health_search_failed',
    );
    if (
      !Array.isArray(searched)
      || searched.length !== 1
      || searched[0] !== config.healthToolIdentifier
    ) {
      fail('health_tool_not_found');
    }

    const executedMessage = await runPhase(deadline, activeTransport, {
      id: 'ankka-live-execute',
      method: 'tools/call',
      name: 'portal_codemode_execute',
      params: {
        name: 'portal_codemode_execute',
        arguments: { code: executeCode(config.healthToolIdentifier) },
        _meta: modernMeta(),
      },
      signal: deadline.signal,
    }, latencies, 'execute');
    const executed = extractMarkedCallResult(
      requireRpcResult(executedMessage, 'ankka-live-execute', 'health_execute_failed'),
      EXECUTE_RESULT_MARKER,
      'health_execute_failed',
    );
    if (canonicalResultSha256(executed) !== config.expectedCanonicalResultSha256) {
      fail('health_result_mismatch');
    }
    return report('passed', 'ok', startedAt, started, latencies);
  } catch (error) {
    return report('failed', fixedFailureCode(error), startedAt, started, latencies);
  } finally {
    deadline?.close();
  }
}

async function readBoundedConfig(file) {
  let handle;
  try {
    handle = await open(file, 'r');
    const metadata = await handle.stat();
    if (!metadata.isFile()) fail('config_read_failed');
    if (metadata.size > CONFIG_LIMIT_BYTES) fail('config_too_large');
    const buffer = Buffer.alloc(CONFIG_LIMIT_BYTES + 1);
    let offset = 0;
    while (offset < buffer.byteLength) {
      const next = await handle.read(buffer, offset, buffer.byteLength - offset, null);
      if (next.bytesRead === 0) break;
      offset += next.bytesRead;
    }
    if (offset > CONFIG_LIMIT_BYTES) fail('config_too_large');
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, offset));
    } catch {
      fail('config_json_invalid');
    }
    try {
      return JSON.parse(text);
    } catch {
      fail('config_json_invalid');
    }
  } catch (error) {
    if (error instanceof LivePortalCanaryError) throw error;
    fail('config_read_failed');
  } finally {
    try {
      await handle?.close();
    } catch {
      // A fixed configuration failure is safer than exposing a filesystem error.
    }
  }
}

function parseArguments(argv) {
  if (
    argv.length !== 2
    || argv[0] !== '--config'
    || !v.is(STRING_SCHEMA, argv[1])
    || argv[1].length === 0
    || argv[1].startsWith('--')
  ) {
    fail('argument_invalid');
  }
  return path.resolve(argv[1]);
}

function immediateFailureReport(code) {
  const started = performance.now();
  const startedAt = new Date().toISOString();
  return report('failed', code, startedAt, started, {
    list_tools: null,
    search: null,
    execute: null,
  });
}

/** CLI entry point. It writes one bounded JSON record and no diagnostic text. */
export async function runLivePortalCanaryCli(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  let output;
  try {
    const file = parseArguments(argv);
    const config = await readBoundedConfig(file);
    output = await runLivePortalCanary(config, {
      transport: io.transport,
      environment: io.environment ?? process.env,
      fetchImpl: io.fetchImpl ?? globalThis.fetch,
      deadlineMs: io.deadlineMs ?? TOTAL_DEADLINE_MS,
    });
  } catch (error) {
    output = immediateFailureReport(fixedFailureCode(error));
  }
  stdout.write(`${JSON.stringify(output)}\n`);
  return output;
}

function isMainModule() {
  return process.argv[1] !== undefined
    && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
}

if (isMainModule()) {
  runLivePortalCanaryCli(process.argv.slice(2)).then((output) => {
    process.exitCode = output.status === 'passed' ? 0 : 1;
  }).catch(() => {
    process.stdout.write(`${JSON.stringify(immediateFailureReport('internal_failure'))}\n`);
    process.exitCode = 1;
  });
}
