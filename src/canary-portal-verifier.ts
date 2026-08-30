import * as v from 'valibot';

import { type JsonObject, type JsonValue, jsonObjectSchema } from './json.ts';

const PROTOCOL_VERSION = '2026-07-28';
const FIXTURE_ID = 'ankka-synthetic-mcp-canary';
const TOOL_NAME = 'ankka_canary_status';
const RESPONSE_LIMIT_BYTES = 128 * 1024;
const DEADLINE_MS = 9_000;
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const CANARY_LABEL = /^ankka-canary(?:-[a-z0-9-]+)?$/u;
const TOOL_IDENTIFIER = /^[A-Za-z0-9_.-]+_ankka_canary_status$/u;
const BLOCKED_SUFFIXES = ['.internal', '.invalid', '.local', '.localhost', '.onion', '.test'];
const PORTAL_NATIVE_TOOLS = new Set([
  'portal_list_servers',
  'portal_toggle_servers',
  'portal_toggle_single_server',
]);
const stringSchema = v.string();
const objectSchema = v.object({});
const functionSchema = v.function();

const FAILURE_CODES = Object.freeze({
  input_invalid: true,
  credential_invalid: true,
  portal_aborted: true,
  portal_timeout: true,
  portal_unreachable: true,
  portal_redirect_rejected: true,
  portal_auth_rejected: true,
  portal_http_rejected: true,
  portal_response_too_large: true,
  portal_response_invalid: true,
  portal_rpc_rejected: true,
  portal_tool_surface_invalid: true,
  portal_result_mismatch: true,
});
type FailureCode = keyof typeof FAILURE_CODES;

export class CanaryPortalVerificationError extends Error {
  readonly code: FailureCode;

  constructor(code: FailureCode) {
    super('canary_portal_verification_failed');
    this.name = 'CanaryPortalVerificationError';
    this.code = Object.hasOwn(FAILURE_CODES, code) ? code : 'portal_response_invalid';
  }
}

export interface CanaryPortalVerificationInput {
  readonly hostname: string;
  readonly expectedFixture: string;
  readonly expectedTool: string;
  readonly signal: AbortSignal;
}

export interface CanaryPortalVerificationOptions {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly fetchImpl?: (url: string, init: RequestInit) => Promise<Response>;
}

export interface CanaryPortalVerificationResult {
  readonly ready: true;
  readonly fixture: 'ankka-synthetic-mcp-canary';
  readonly toolName: 'ankka_canary_status';
}

interface RequestContext {
  readonly endpoint: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly fetchImpl: (url: string, init: RequestInit) => Promise<Response>;
  readonly signal: AbortSignal;
}

interface PortalParams {
  _meta: JsonObject;
  name?: string;
  arguments?: JsonObject;
}

function fail(code: FailureCode): never {
  throw new CanaryPortalVerificationError(code);
}

function isRecord(value: JsonValue | undefined): value is JsonObject {
  return value !== undefined && value !== null && !Array.isArray(value) && v.is(objectSchema, value);
}

function hasKeys(value: JsonObject, required: readonly string[], optional: readonly string[] = []): boolean {
  return required.every((key) => Object.hasOwn(value, key))
    && Object.keys(value).every((key) => required.includes(key) || optional.includes(key));
}

function validateInput(input: CanaryPortalVerificationInput): string {
  if (
    !v.is(objectSchema, input)
    || Object.keys(input).length !== 4
    || !['hostname', 'expectedFixture', 'expectedTool', 'signal'].every((key) => Object.hasOwn(input, key))
    || !v.is(stringSchema, input.hostname)
    || !HOSTNAME.test(input.hostname)
    || !CANARY_LABEL.test(input.hostname.split('.')[0] ?? '')
    || BLOCKED_SUFFIXES.some((suffix) => input.hostname.endsWith(suffix))
    || input.expectedFixture !== FIXTURE_ID
    || input.expectedTool !== TOOL_NAME
    || !(input.signal instanceof AbortSignal)
  ) fail('input_invalid');
  return `https://${input.hostname}/mcp`;
}

function validateCredential(value: string): string {
  if (!v.is(stringSchema, value) || value.length === 0 || value.length > 4_096 || /[^\x21-\x7e]/u.test(value)) {
    fail('credential_invalid');
  }
  return value;
}

function cancelBody(response: Response): void {
  try {
    void response.body?.cancel().catch(() => {});
  } catch {
    // A fixed failure remains authoritative if body cancellation is unavailable.
  }
}

async function readResponse(response: Response, signal: AbortSignal): Promise<string> {
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null && (!/^\d+$/u.test(declaredLength) || !Number.isSafeInteger(Number(declaredLength)))) {
    cancelBody(response);
    fail('portal_response_invalid');
  }
  if (declaredLength !== null && Number(declaredLength) > RESPONSE_LIMIT_BYTES) {
    cancelBody(response);
    fail('portal_response_too_large');
  }
  if (response.body === null) fail('portal_response_invalid');
  const reader = response.body.getReader();
  const cancel = () => { void reader.cancel().catch(() => {}); };
  const chunks: Uint8Array[] = [];
  let byteLength = 0;
  signal.addEventListener('abort', cancel, { once: true });
  try {
    while (true) {
      if (signal.aborted) fail('portal_aborted');
      const next = await reader.read();
      if (signal.aborted) fail('portal_aborted');
      if (next.done) break;
      if (!(next.value instanceof Uint8Array)) fail('portal_response_invalid');
      byteLength += next.value.byteLength;
      if (byteLength > RESPONSE_LIMIT_BYTES) fail('portal_response_too_large');
      chunks.push(next.value);
    }
    const bytes = new Uint8Array(byteLength);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (error) {
    cancel();
    if (error instanceof CanaryPortalVerificationError) throw error;
    fail('portal_response_invalid');
  } finally {
    signal.removeEventListener('abort', cancel);
    reader.releaseLock();
  }
}

function parseMessage(text: string): JsonObject {
  try {
    return v.parse(jsonObjectSchema, JSON.parse(text));
  } catch {
    fail('portal_response_invalid');
  }
}

function parseResponse(serialized: string, contentType: string, id: string): JsonObject {
  const candidates: JsonObject[] = [];
  if (contentType === 'application/json') {
    candidates.push(parseMessage(serialized));
  } else if (contentType === 'text/event-stream') {
    const events = serialized.split(/\r?\n\r?\n/u);
    if (events.length > 32) fail('portal_response_invalid');
    for (const event of events) {
      const data = event.split(/\r?\n/u)
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice(5).trimStart())
        .join('\n');
      if (data !== '') candidates.push(parseMessage(data));
    }
  } else fail('portal_response_invalid');
  const matching = candidates.filter((candidate) => candidate.jsonrpc === '2.0' && candidate.id === id);
  if (matching.length !== 1) fail('portal_response_invalid');
  const message = matching[0];
  if (message === undefined) fail('portal_response_invalid');
  if (Object.hasOwn(message, 'error')) fail('portal_rpc_rejected');
  if (!hasKeys(message, ['jsonrpc', 'id', 'result']) || !isRecord(message.result)) fail('portal_response_invalid');
  if (message.result.resultType !== undefined && message.result.resultType !== 'complete') fail('portal_rpc_rejected');
  return message.result;
}

async function request(context: RequestContext, method: 'tools/list' | 'tools/call', name?: string): Promise<JsonObject> {
  if (context.signal.aborted) fail('portal_aborted');
  const id = method === 'tools/list' ? 'ankka-canary-list' : 'ankka-canary-call';
  const headers = new Headers({
    Accept: 'application/json, text/event-stream',
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json',
    'CF-Access-Client-Id': context.clientId,
    'CF-Access-Client-Secret': context.clientSecret,
    'MCP-Protocol-Version': PROTOCOL_VERSION,
    'Mcp-Method': method,
  });
  const params: PortalParams = {
    _meta: {
      'io.modelcontextprotocol/protocolVersion': PROTOCOL_VERSION,
      'io.modelcontextprotocol/clientCapabilities': {},
      'io.modelcontextprotocol/clientInfo': { name: 'ankka-disposable-canary', version: '1.0.0' },
    },
  };
  if (name !== undefined) {
    headers.set('Mcp-Name', name);
    params.name = name;
    params.arguments = {};
  }
  let response: Response;
  try {
    response = await context.fetchImpl(context.endpoint, {
      method: 'POST',
      redirect: 'manual',
      credentials: 'omit',
      cache: 'no-store',
      headers,
      body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
      signal: context.signal,
    });
  } catch {
    fail('portal_unreachable');
  }
  if (!(response instanceof Response)) fail('portal_response_invalid');
  if (context.signal.aborted) {
    cancelBody(response);
    fail('portal_aborted');
  }
  if (response.redirected || response.status >= 300 && response.status < 400) {
    cancelBody(response);
    fail('portal_redirect_rejected');
  }
  if (response.status === 401 || response.status === 403) {
    cancelBody(response);
    fail('portal_auth_rejected');
  }
  if (response.status !== 200) {
    cancelBody(response);
    fail('portal_http_rejected');
  }
  const contentType = (response.headers.get('content-type') ?? '').split(';')[0]?.trim().toLowerCase() ?? '';
  if (contentType !== 'application/json' && contentType !== 'text/event-stream') {
    cancelBody(response);
    fail('portal_response_invalid');
  }
  return parseResponse(await readResponse(response, context.signal), contentType, id);
}

function validateTool(tool: JsonObject): void {
  const schema = tool.inputSchema;
  if (
    !isRecord(schema)
    || !hasKeys(schema, ['type', 'properties', 'additionalProperties'], ['required'])
    || schema.type !== 'object'
    || schema.additionalProperties !== false
    || !isRecord(schema.properties)
    || Object.keys(schema.properties).length !== 0
    || schema.required !== undefined && (!Array.isArray(schema.required) || schema.required.length !== 0)
  ) fail('portal_tool_surface_invalid');
  if (tool.annotations !== undefined) {
    const annotations = tool.annotations;
    if (
      !isRecord(annotations)
      || annotations.readOnlyHint !== undefined && annotations.readOnlyHint !== true
      || annotations.destructiveHint !== undefined && annotations.destructiveHint !== false
      || annotations.idempotentHint !== undefined && annotations.idempotentHint !== true
      || annotations.openWorldHint !== undefined && annotations.openWorldHint !== false
    ) fail('portal_tool_surface_invalid');
  }
}

function syntheticTool(result: JsonObject): string {
  if (!Array.isArray(result.tools) || result.tools.length === 0 || result.tools.length > 4 || Object.hasOwn(result, 'nextCursor')) {
    fail('portal_tool_surface_invalid');
  }
  const seen = new Set<string>();
  let selected: string | undefined;
  for (const tool of result.tools) {
    if (!isRecord(tool) || !v.is(stringSchema, tool.name) || tool.name.length > 192 || seen.has(tool.name)) {
      fail('portal_tool_surface_invalid');
    }
    seen.add(tool.name);
    if (PORTAL_NATIVE_TOOLS.has(tool.name)) continue;
    if (tool.name.startsWith('portal_') || (tool.name !== TOOL_NAME && !TOOL_IDENTIFIER.test(tool.name)) || selected !== undefined) {
      fail('portal_tool_surface_invalid');
    }
    validateTool(tool);
    selected = tool.name;
  }
  if (selected === undefined) fail('portal_tool_surface_invalid');
  return selected;
}

function validateResult(result: JsonObject): void {
  const structured = result.structuredContent;
  const content = result.content;
  if (
    !hasKeys(result, ['content', 'structuredContent', 'isError'], ['resultType', '_meta'])
    || result.isError !== false
    || !isRecord(structured)
    || !hasKeys(structured, ['ok', 'fixture', 'version'])
    || structured.ok !== true
    || structured.fixture !== FIXTURE_ID
    || structured.version !== 1
    || !Array.isArray(content)
    || content.length !== 1
  ) fail('portal_result_mismatch');
  const block = content[0];
  if (!isRecord(block) || !hasKeys(block, ['type', 'text']) || block.type !== 'text' || block.text !== 'Synthetic canary is healthy.') {
    fail('portal_result_mismatch');
  }
}

/** Check only the fixed synthetic tool. This never proves browser OAuth works. */
export async function verifyCanaryPortal(
  input: CanaryPortalVerificationInput,
  options: CanaryPortalVerificationOptions,
): Promise<CanaryPortalVerificationResult> {
  try {
    const endpoint = validateInput(input);
    if (!v.is(objectSchema, options) || !Object.keys(options).every((key) => ['clientId', 'clientSecret', 'fetchImpl'].includes(key))) {
      fail('input_invalid');
    }
    const clientId = validateCredential(options.clientId);
    const clientSecret = validateCredential(options.clientSecret);
    const fetchImpl = options.fetchImpl ?? globalThis.fetch;
    if (!v.is(functionSchema, fetchImpl)) fail('input_invalid');
    if (input.signal.aborted) fail('portal_aborted');
    const controller = new AbortController();
    let abort = () => {};
    let timeout = () => {};
    const cancelled = new Promise<never>((_resolve, reject) => {
      abort = () => { reject(new CanaryPortalVerificationError('portal_aborted')); controller.abort(); };
      timeout = () => { reject(new CanaryPortalVerificationError('portal_timeout')); controller.abort(); };
    });
    input.signal.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(timeout, DEADLINE_MS);
    try {
      const context = { endpoint, clientId, clientSecret, fetchImpl, signal: controller.signal };
      const verification = async () => {
        const tool = syntheticTool(await request(context, 'tools/list'));
        validateResult(await request(context, 'tools/call', tool));
      };
      await Promise.race([verification(), cancelled]);
      return Object.freeze({ ready: true, fixture: FIXTURE_ID, toolName: TOOL_NAME });
    } finally {
      clearTimeout(timer);
      input.signal.removeEventListener('abort', abort);
      controller.abort();
    }
  } catch (error) {
    if (error instanceof CanaryPortalVerificationError) throw new CanaryPortalVerificationError(error.code);
    fail('portal_response_invalid');
  }
}
