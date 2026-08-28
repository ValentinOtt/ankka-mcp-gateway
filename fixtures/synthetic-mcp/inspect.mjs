import * as v from 'valibot';
import {
  SYNTHETIC_FIXTURE_ID,
  SYNTHETIC_TOOL_NAME,
} from './worker.mjs';

const PROTOCOL_VERSION = '2025-11-25';
const TIMEOUT_MS = 10_000;

export class SyntheticMcpInspectionError extends Error {
  constructor(code) {
    super(`Synthetic MCP inspection failed: ${code}`);
    this.name = 'SyntheticMcpInspectionError';
    this.code = code;
  }
}

export async function inspectSyntheticEndpoint(endpoint, { fetchImpl = globalThis.fetch } = {}) {
  const url = parseEndpoint(endpoint);
  if (!v.is(v.function(), fetchImpl)) throw new TypeError('fetchImpl must be a function');

  const initialize = await rpc(fetchImpl, url, 'initialize', {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: 'ankka-canary-inspector', version: '1.0.0' },
  }, 'inspect-initialize');
  if (
    initialize?.protocolVersion !== PROTOCOL_VERSION
    || initialize?.serverInfo?.name !== SYNTHETIC_FIXTURE_ID
    || initialize?.capabilities?.tools?.listChanged !== false
  ) {
    throw new SyntheticMcpInspectionError('fixture_identity_mismatch');
  }

  await notification(fetchImpl, url, 'notifications/initialized');

  const listed = await rpc(fetchImpl, url, 'tools/list', {}, 'inspect-list');
  if (
    !Array.isArray(listed?.tools)
    || listed.tools.length !== 1
    || listed.tools[0]?.name !== SYNTHETIC_TOOL_NAME
    || listed.tools[0]?.annotations?.readOnlyHint !== true
    || listed.tools[0]?.annotations?.destructiveHint !== false
  ) {
    throw new SyntheticMcpInspectionError('tool_contract_mismatch');
  }

  const called = await rpc(fetchImpl, url, 'tools/call', {
    name: SYNTHETIC_TOOL_NAME,
    arguments: {},
  }, 'inspect-call');
  if (
    called?.isError !== false
    || called?.structuredContent?.ok !== true
    || called?.structuredContent?.fixture !== SYNTHETIC_FIXTURE_ID
    || called?.structuredContent?.version !== 1
  ) {
    throw new SyntheticMcpInspectionError('tool_call_mismatch');
  }

  return Object.freeze({
    fixture: SYNTHETIC_FIXTURE_ID,
    schemaVersion: 1,
    toolNames: Object.freeze([SYNTHETIC_TOOL_NAME]),
    callVerified: true,
  });
}

function parseEndpoint(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new SyntheticMcpInspectionError('invalid_endpoint');
  }
  const loopback = url.hostname === '127.0.0.1' || url.hostname === 'localhost';
  if (
    (url.protocol !== 'https:' && !(loopback && url.protocol === 'http:'))
    || url.pathname !== '/mcp'
    || url.username !== ''
    || url.password !== ''
    || url.search !== ''
    || url.hash !== ''
  ) {
    throw new SyntheticMcpInspectionError('invalid_endpoint');
  }
  return url.toString();
}

async function rpc(fetchImpl, endpoint, method, params, id) {
  const response = await post(fetchImpl, endpoint, { jsonrpc: '2.0', id, method, params });
  const body = await parseJson(response);
  if (
    response.status !== 200
    || body?.jsonrpc !== '2.0'
    || body?.id !== id
    || !Object.hasOwn(body, 'result')
    || Object.hasOwn(body, 'error')
  ) {
    throw new SyntheticMcpInspectionError('invalid_rpc_response');
  }
  return body.result;
}

async function notification(fetchImpl, endpoint, method) {
  const response = await post(fetchImpl, endpoint, { jsonrpc: '2.0', method });
  if (response.status !== 202 || (await response.text()) !== '') {
    throw new SyntheticMcpInspectionError('invalid_notification_response');
  }
}

async function post(fetchImpl, endpoint, body) {
  const headers = {
    Accept: 'application/json, text/event-stream',
    'Content-Type': 'application/json',
    'MCP-Protocol-Version': PROTOCOL_VERSION,
    'Mcp-Method': body.method,
  };
  if (body.method === 'tools/call') headers['Mcp-Name'] = body.params.name;
  try {
    return await fetchImpl(endpoint, {
      method: 'POST',
      redirect: 'error',
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch {
    throw new SyntheticMcpInspectionError('endpoint_unreachable');
  }
}

async function parseJson(response) {
  if (!response.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
    throw new SyntheticMcpInspectionError('invalid_content_type');
  }
  try {
    return await response.json();
  } catch {
    throw new SyntheticMcpInspectionError('invalid_json_response');
  }
}
