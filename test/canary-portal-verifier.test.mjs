import assert from 'node:assert/strict';
import test from 'node:test';

import { handleSyntheticMcpRequest, SYNTHETIC_TOOL } from '../fixtures/synthetic-mcp/worker.mjs';
import { CanaryPortalVerificationError, verifyCanaryPortal } from '../src/canary-portal-verifier.ts';

const HOSTNAME = 'ankka-canary-machine.example.com';
const TOOL = 'synthetic-canary_ankka_canary_status';
const CLIENT_ID = 'synthetic-client-id.access';
const CLIENT_SECRET = 'synthetic-client-secret-not-for-output';
const PRIVATE_ERROR = 'untrusted-response-not-for-output';
const EXPECTED = Object.freeze({ ready: true, fixture: 'ankka-synthetic-mcp-canary', toolName: 'ankka_canary_status' });
const NATIVE_TOOLS = ['portal_list_servers', 'portal_toggle_servers', 'portal_toggle_single_server'];

function input(overrides = {}) {
  return {
    hostname: HOSTNAME,
    expectedFixture: EXPECTED.fixture,
    expectedTool: EXPECTED.toolName,
    signal: new AbortController().signal,
    ...overrides,
  };
}

function options(fetchImpl, overrides = {}) {
  return { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, fetchImpl, ...overrides };
}

function toolList(toolName = TOOL) {
  return { tools: [
    ...NATIVE_TOOLS.map((name) => ({ name })),
    { ...SYNTHETIC_TOOL, name: toolName },
  ] };
}

function toolResult() {
  return {
    resultType: 'complete',
    content: [{ type: 'text', text: 'Synthetic canary is healthy.' }],
    structuredContent: { ok: true, fixture: EXPECTED.fixture, version: 1 },
    isError: false,
  };
}

function response(init, result) {
  return Response.json({ jsonrpc: '2.0', id: JSON.parse(init.body).id, result });
}

function successfulFetch(calls = [], { list = toolList(), result = toolResult() } = {}) {
  return async (url, init) => {
    calls.push({ url, init });
    return response(init, JSON.parse(init.body).method === 'tools/list' ? list : result);
  };
}

async function rejectsCode(operation, code) {
  await assert.rejects(operation, (error) => {
    assert.equal(error.name, 'CanaryPortalVerificationError');
    assert.equal(error.message, 'canary_portal_verification_failed');
    assert.equal(error.code, code);
    for (const forbidden of [CLIENT_ID, CLIENT_SECRET, PRIVATE_ERROR, HOSTNAME]) {
      assert.equal(`${String(error)} ${JSON.stringify(error)} ${error.stack}`.includes(forbidden), false);
    }
    assert.equal(Object.hasOwn(error, 'cause'), false);
    return true;
  });
}

test('calls only the exact discovered synthetic tool using stateless Access headers', async () => {
  const calls = [];
  const result = await verifyCanaryPortal(input(), options(successfulFetch(calls)));
  assert.deepEqual(result, EXPECTED);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(calls.length, 2);
  for (const { url, init } of calls) {
    assert.equal(url, `https://${HOSTNAME}/mcp`);
    assert.equal(init.method, 'POST');
    assert.equal(init.redirect, 'manual');
    assert.equal(init.credentials, 'omit');
    assert.equal(init.cache, 'no-store');
    assert.ok(init.signal instanceof AbortSignal);
    const headers = new Headers(init.headers);
    assert.equal(headers.get('CF-Access-Client-Id'), CLIENT_ID);
    assert.equal(headers.get('CF-Access-Client-Secret'), CLIENT_SECRET);
    assert.equal(headers.get('MCP-Protocol-Version'), '2026-07-28');
    for (const blocked of ['authorization', 'cookie', 'mcp-session-id']) assert.equal(headers.has(blocked), false);
    const message = JSON.parse(init.body);
    assert.equal(headers.get('Mcp-Method'), message.method);
    assert.equal(message.params._meta['io.modelcontextprotocol/protocolVersion'], '2026-07-28');
    assert.deepEqual(message.params._meta['io.modelcontextprotocol/clientCapabilities'], {});
    assert.equal(JSON.stringify(message).includes(CLIENT_SECRET), false);
  }
  assert.deepEqual(calls.map(({ init }) => JSON.parse(init.body).method), ['tools/list', 'tools/call']);
  assert.equal(new Headers(calls[0].init.headers).get('Mcp-Name'), null);
  const call = JSON.parse(calls[1].init.body);
  assert.equal(call.params.name, TOOL);
  assert.deepEqual(call.params.arguments, {});
  assert.equal(new Headers(calls[1].init.headers).get('Mcp-Name'), TOOL);
});

test('is compatible with the actual stateless synthetic fixture without initialization', async () => {
  let requests = 0;
  const result = await verifyCanaryPortal(input(), options(async (url, init) => {
    requests += 1;
    return handleSyntheticMcpRequest(new Request(url, init));
  }));
  assert.deepEqual(result, EXPECTED);
  assert.equal(requests, 2);
});

test('accepts a bounded SSE response and legacy complete results from the Portal bridge', async () => {
  const result = await verifyCanaryPortal(input(), options(async (_url, init) => {
    const message = JSON.parse(init.body);
    const body = message.method === 'tools/list' ? toolList() : toolResult();
    delete body.resultType;
    return new Response(`: keepalive\n\ndata: ${JSON.stringify({ jsonrpc: '2.0', id: message.id, result: body })}\n\n`, {
      headers: { 'content-type': 'text/event-stream; charset=utf-8' },
    });
  }));
  assert.deepEqual(result, EXPECTED);
});

test('validates the canary-only endpoint and fixed expected fixture before any request', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls += 1; throw new Error(PRIVATE_ERROR); };
  for (const change of [
    { hostname: 'portal.example.com' },
    { hostname: 'ankka-canary.example.com/path' },
    { hostname: 'ankka-canary.example.com:443' },
    { hostname: 'ankka-canary.example.com?key=secret' },
    { hostname: 'ankka-canary.localhost' },
    { hostname: 'ankka-canary.internal' },
    { hostname: 'Ankka-canary.example.com' },
    { hostname: 'ankka-canaryexample.com' },
    { hostname: 'ankka-canary.127.0.0.1' },
    { expectedFixture: 'business-data' },
    { expectedTool: 'delete_all' },
    { signal: {} },
    { extra: CLIENT_SECRET },
  ]) {
    await rejectsCode(() => verifyCanaryPortal(input(change), options(fetchImpl)), 'input_invalid');
  }
  assert.equal(calls, 0);
});

test('rejects missing, unsafe, oversized, and unrelated credentials before a request', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls += 1; throw new Error(PRIVATE_ERROR); };
  for (const change of [
    { clientId: '' }, { clientSecret: undefined }, { clientId: 'two words' },
    { clientSecret: 'unsafe\nheader' }, { clientSecret: 'a'.repeat(4097) }, { clientId: 2 },
  ]) {
    await rejectsCode(() => verifyCanaryPortal(input(), options(fetchImpl, change)), 'credential_invalid');
  }
  await rejectsCode(() => verifyCanaryPortal(input(), options(fetchImpl, { apiToken: CLIENT_SECRET })), 'input_invalid');
  assert.equal(calls, 0);
});

test('reconstructs a fixed failure even if a dependency throws a modified verifier error', async () => {
  const supplied = options(successfulFetch());
  Object.defineProperty(supplied, 'clientId', { get() {
    const error = new CanaryPortalVerificationError('input_invalid');
    error.code = CLIENT_SECRET;
    error.message = PRIVATE_ERROR;
    throw error;
  } });
  await rejectsCode(() => verifyCanaryPortal(input(), supplied), 'portal_response_invalid');
});

test('never follows redirects or forwards service credentials to another destination', async () => {
  for (const status of [301, 302, 303, 307, 308]) {
    const calls = [];
    await rejectsCode(() => verifyCanaryPortal(input(), options(async (url, init) => {
      calls.push({ url, init });
      return new Response(PRIVATE_ERROR, { status, headers: { location: `https://other.example.com/${CLIENT_SECRET}` } });
    })), 'portal_redirect_rejected');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, `https://${HOSTNAME}/mcp`);
    assert.equal(calls[0].init.redirect, 'manual');
  }
});

test('redacts HTTP, network, RPC, and invalid-response failure details', async () => {
  for (const [fetchImpl, expected] of [
    [async () => { throw new Error(`${CLIENT_SECRET} ${PRIVATE_ERROR}`); }, 'portal_unreachable'],
    [async () => new Response(PRIVATE_ERROR, { status: 401 }), 'portal_auth_rejected'],
    [async () => new Response(PRIVATE_ERROR, { status: 403 }), 'portal_auth_rejected'],
    [async () => new Response(PRIVATE_ERROR, { status: 500 }), 'portal_http_rejected'],
    [async () => new Response(PRIVATE_ERROR), 'portal_response_invalid'],
    [async () => new Response(PRIVATE_ERROR, { headers: { 'content-type': 'application/json' } }), 'portal_response_invalid'],
    [async (_url, init) => Response.json({ jsonrpc: '2.0', id: JSON.parse(init.body).id, error: { message: CLIENT_SECRET } }), 'portal_rpc_rejected'],
    [async (_url, init) => response(init, { resultType: 'input_required', inputRequests: [{ url: PRIVATE_ERROR }] }), 'portal_rpc_rejected'],
  ]) {
    await rejectsCode(() => verifyCanaryPortal(input(), options(fetchImpl)), expected);
  }
});

test('refuses hidden, additional, ambiguous, paginated, or unsafe upstream tools before calling any', async () => {
  const good = { ...SYNTHETIC_TOOL, name: TOOL };
  for (const list of [
    { tools: [] },
    { tools: [{ name: 'portal_list_servers' }] },
    { tools: [good, { name: 'customer_records' }] },
    { tools: [good, { ...good, name: 'other_ankka_canary_status' }] },
    { tools: [good, good] },
    { tools: [{ ...good, name: 'portal_ankka_canary_status' }] },
    { tools: [{ ...good, name: 'synthetic_ankka_canary_status_extra' }] },
    { tools: [good], nextCursor: 'another-page' },
    { tools: [{ ...good, inputSchema: { type: 'object', properties: {} } }] },
    { tools: [{ ...good, inputSchema: { ...good.inputSchema, properties: { id: { type: 'string' } } } }] },
    { tools: [{ ...good, inputSchema: { ...good.inputSchema, required: ['id'] } }] },
    { tools: [{ ...good, inputSchema: { ...good.inputSchema, additionalProperties: true } }] },
    { tools: [{ ...good, annotations: { readOnlyHint: false } }] },
    { tools: [{ ...good, annotations: { destructiveHint: true } }] },
    { tools: [{ ...good, annotations: { openWorldHint: true } }] },
    { tools: [{ ...good, annotations: { idempotentHint: false } }] },
  ]) {
    const calls = [];
    await rejectsCode(() => verifyCanaryPortal(input(), options(successfulFetch(calls, { list }))), 'portal_tool_surface_invalid');
    assert.equal(calls.length, 1);
  }
});

test('refuses changed synthetic output, error calls, and any additional result data', async () => {
  for (const result of [
    { ...toolResult(), isError: true },
    { ...toolResult(), structuredContent: { ok: false, fixture: EXPECTED.fixture, version: 1 } },
    { ...toolResult(), structuredContent: { ok: true, fixture: 'wrong', version: 1 } },
    { ...toolResult(), structuredContent: { ok: true, fixture: EXPECTED.fixture, version: 2 } },
    { ...toolResult(), structuredContent: { ...toolResult().structuredContent, privateData: CLIENT_SECRET } },
    { ...toolResult(), content: [{ type: 'text', text: PRIVATE_ERROR }] },
    { ...toolResult(), content: [...toolResult().content, { type: 'resource', uri: PRIVATE_ERROR }] },
    { ...toolResult(), extraData: CLIENT_SECRET },
  ]) {
    const calls = [];
    await rejectsCode(() => verifyCanaryPortal(input(), options(successfulFetch(calls, { result }))), 'portal_result_mismatch');
    assert.equal(calls.length, 2);
  }
});

test('bounds declared and streamed bytes and cancels oversized response streams', async () => {
  let cancellations = 0;
  for (const declared of [false, true]) {
    const headers = { 'content-type': 'application/json' };
    if (declared) headers['content-length'] = `${128 * 1024 + 1}`;
    await rejectsCode(() => verifyCanaryPortal(input(), options(async () => new Response(new ReadableStream({
      start(controller) { if (!declared) controller.enqueue(new Uint8Array(128 * 1024 + 1)); },
      cancel() { cancellations += 1; },
    }), {
      headers,
    }))), 'portal_response_too_large');
  }
  assert.equal(cancellations, 2);
});

test('pre-aborted requests make no calls and in-flight aborts cancel response streams', async () => {
  const alreadyAborted = new AbortController();
  alreadyAborted.abort(PRIVATE_ERROR);
  let requests = 0;
  await rejectsCode(() => verifyCanaryPortal(input({ signal: alreadyAborted.signal }), options(async () => {
    requests += 1;
    throw new Error(PRIVATE_ERROR);
  })), 'portal_aborted');
  assert.equal(requests, 0);

  const controller = new AbortController();
  let cancelled = false;
  const operation = verifyCanaryPortal(input({ signal: controller.signal }), options(async () => new Response(new ReadableStream({
    start() { queueMicrotask(() => controller.abort(PRIVATE_ERROR)); },
    cancel() { cancelled = true; },
  }), { headers: { 'content-type': 'application/json' } })));
  await rejectsCode(() => operation, 'portal_aborted');
  assert.equal(cancelled, true);
});

test('enforces a fixed deadline even when a transport ignores cancellation', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let calls = 0;
  let requestSignal;
  const operation = verifyCanaryPortal(input(), options(async (_url, init) => {
    calls += 1;
    requestSignal = init.signal;
    return new Promise(() => {});
  }));
  const rejection = rejectsCode(() => operation, 'portal_timeout');
  t.mock.timers.tick(9_000);
  await rejection;
  assert.equal(calls, 1);
  assert.equal(requestSignal.aborted, true);
});

test('deadline cancels a stalled response body without making a tool call', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let calls = 0;
  let cancelled = false;
  let bodyStarted;
  const started = new Promise((resolve) => { bodyStarted = resolve; });
  const operation = verifyCanaryPortal(input(), options(async () => {
    calls += 1;
    return new Response(new ReadableStream({
      pull() { bodyStarted(); },
      cancel() { cancelled = true; },
    }), { headers: { 'content-type': 'application/json' } });
  }));
  const rejection = rejectsCode(() => operation, 'portal_timeout');
  await started;
  t.mock.timers.tick(9_000);
  await rejection;
  assert.equal(calls, 1);
  assert.equal(cancelled, true);
});

test('rejects mismatched or duplicate RPC responses and unexpected content types', async () => {
  for (const fetchImpl of [
    async () => Response.json({ jsonrpc: '2.0', id: 'wrong', result: toolList() }),
    async (_url, init) => new Response(`data: ${JSON.stringify({ jsonrpc: '2.0', id: JSON.parse(init.body).id, result: toolList() })}\n\n`.repeat(2), { headers: { 'content-type': 'text/event-stream' } }),
    async (_url, init) => new Response(JSON.stringify({ jsonrpc: '2.0', id: JSON.parse(init.body).id, result: toolList() }), { headers: { 'content-type': 'application/jsonx' } }),
  ]) await rejectsCode(() => verifyCanaryPortal(input(), options(fetchImpl)), 'portal_response_invalid');
});
