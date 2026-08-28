import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import worker, {
  SYNTHETIC_FIXTURE_ID,
  SYNTHETIC_TOOL,
  SYNTHETIC_TOOL_NAME,
  handleSyntheticMcpRequest,
} from '../fixtures/synthetic-mcp/worker.mjs';
import {
  SyntheticMcpInspectionError,
  inspectSyntheticEndpoint,
} from '../fixtures/synthetic-mcp/inspect.mjs';
import { startSyntheticMcpServer } from '../fixtures/synthetic-mcp/server.mjs';

const ENDPOINT = 'https://synthetic.invalid/mcp';

function rpc(method, params, id = 1) {
  return handleSyntheticMcpRequest(new Request(ENDPOINT, {
    method: 'POST',
    headers: {
      accept: 'application/json, text/event-stream',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
  }));
}

test('exports a Worker fetch handler and a constant health response', async () => {
  assert.equal(worker.fetch, handleSyntheticMcpRequest);
  const response = await worker.fetch(new Request('https://synthetic.invalid/health'));

  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await response.json(), {
    status: 'ok',
    fixture: SYNTHETIC_FIXTURE_ID,
    tool: SYNTHETIC_TOOL_NAME,
  });
});

test('first canary exposes no Wrangler deploy or delete surface', async () => {
  const packageJson = JSON.parse(await readFile(
    new URL('../package.json', import.meta.url),
    'utf8',
  ));
  assert.equal(packageJson.scripts['canary:fixture:deploy'], undefined);
  assert.equal(packageJson.scripts['canary:fixture:delete'], undefined);
  await assert.rejects(
    readFile(new URL('../fixtures/synthetic-mcp/wrangler.jsonc', import.meta.url), 'utf8'),
    (error) => error?.code === 'ENOENT',
  );
});

test('initializes a stateless MCP server with only tool capabilities', async () => {
  const response = await rpc('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'synthetic-client', version: '1.0.0' },
  }, 'init-1');

  assert.equal(response.status, 200);
  assert.equal(response.headers.get('content-type'), 'application/json; charset=utf-8');
  assert.deepEqual(await response.json(), {
    jsonrpc: '2.0',
    id: 'init-1',
    result: {
      protocolVersion: '2025-06-18',
      capabilities: { tools: { listChanged: false } },
      serverInfo: {
        name: SYNTHETIC_FIXTURE_ID,
        title: 'Ankka synthetic MCP canary',
        version: '1.0.0',
      },
      instructions: 'Disposable test fixture. The only tool returns constant synthetic data.',
    },
  });
});

test('falls back to the current supported protocol version', async () => {
  const response = await rpc('initialize', {
    protocolVersion: '2099-01-01',
    capabilities: {},
    clientInfo: { name: 'future-client', version: '1.0.0' },
  });

  assert.equal((await response.json()).result.protocolVersion, '2025-11-25');
});

test('supports current stateless discovery and tools with mirrored headers', async () => {
  const modernParams = {
    _meta: {
      'io.modelcontextprotocol/protocolVersion': '2026-07-28',
      'io.modelcontextprotocol/clientInfo': { name: 'modern-client', version: '1.0.0' },
      'io.modelcontextprotocol/clientCapabilities': {},
    },
  };
  const modernRpc = (method, params, name) => handleSyntheticMcpRequest(new Request(ENDPOINT, {
    method: 'POST',
    headers: {
      accept: 'application/json, text/event-stream',
      'content-type': 'application/json',
      'mcp-protocol-version': '2026-07-28',
      'mcp-method': method,
      ...(name ? { 'mcp-name': name } : {}),
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 'modern-1', method, params }),
  }));

  const discovery = await (await modernRpc('server/discover', modernParams)).json();
  assert.deepEqual(discovery.result, {
    resultType: 'complete',
    supportedVersions: ['2026-07-28'],
    capabilities: { tools: {} },
    instructions: 'Disposable test fixture. The only tool returns constant synthetic data.',
    ttlMs: 3_600_000,
    cacheScope: 'public',
    _meta: {
      'io.modelcontextprotocol/serverInfo': {
        name: SYNTHETIC_FIXTURE_ID,
        version: '1.0.0',
      },
    },
  });

  const listed = await (await modernRpc('tools/list', modernParams)).json();
  assert.equal(listed.result.resultType, 'complete');
  assert.deepEqual(listed.result.tools, [SYNTHETIC_TOOL]);
  assert.equal(listed.result.ttlMs, 3_600_000);
  assert.equal(listed.result.cacheScope, 'public');

  const called = await (await modernRpc('tools/call', {
    name: SYNTHETIC_TOOL_NAME,
    arguments: {},
    ...modernParams,
  }, SYNTHETIC_TOOL_NAME)).json();
  assert.equal(called.result.resultType, 'complete');
  assert.equal(called.result.structuredContent.fixture, SYNTHETIC_FIXTURE_ID);
});

test('rejects mismatched modern routing headers', async () => {
  const response = await handleSyntheticMcpRequest(new Request(ENDPOINT, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'mcp-protocol-version': '2026-07-28',
      'mcp-method': 'resources/list',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 9,
      method: 'tools/list',
      params: {
        _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' },
      },
    }),
  }));

  assert.equal(response.status, 400);
  assert.deepEqual((await response.json()).error, { code: -32001, message: 'Header mismatch' });
});

test('advertises exactly one explicitly read-only tool', async () => {
  const response = await rpc('tools/list', {});
  const body = await response.json();

  assert.equal(body.result.tools.length, 1);
  assert.deepEqual(body.result.tools[0], SYNTHETIC_TOOL);
  assert.equal(body.result.tools[0].name, 'ankka_canary_status');
  assert.deepEqual(body.result.tools[0].annotations, {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  });
  assert.equal(body.result.tools[0].inputSchema.additionalProperties, false);
});

test('calls the harmless tool with a deterministic response', async () => {
  const first = await rpc('tools/call', { name: SYNTHETIC_TOOL_NAME, arguments: {} }, 4);
  const second = await rpc('tools/call', { name: SYNTHETIC_TOOL_NAME, arguments: {} }, 4);
  const firstText = await first.text();
  const secondText = await second.text();

  assert.equal(firstText, secondText);
  assert.deepEqual(JSON.parse(firstText), {
    jsonrpc: '2.0',
    id: 4,
    result: {
      content: [{ type: 'text', text: 'Synthetic canary is healthy.' }],
      structuredContent: {
        ok: true,
        fixture: SYNTHETIC_FIXTURE_ID,
        version: 1,
      },
      isError: false,
    },
  });
});

test('accepts initialized notifications without starting a session', async () => {
  const response = await handleSyntheticMcpRequest(new Request(ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
  }));

  assert.equal(response.status, 202);
  assert.equal(response.headers.has('mcp-session-id'), false);
  assert.equal(await response.text(), '');
});

test('supports ping and rejects unknown methods and invalid tool input', async () => {
  assert.deepEqual(await (await rpc('ping', {})).json(), {
    jsonrpc: '2.0',
    id: 1,
    result: {},
  });
  assert.deepEqual((await (await rpc('resources/list', {})).json()).error, {
    code: -32601,
    message: 'Method not found',
  });
  assert.deepEqual((await (await rpc('tools/call', {
    name: SYNTHETIC_TOOL_NAME,
    arguments: { unsafe: true },
  })).json()).error, {
    code: -32602,
    message: 'Invalid tool arguments',
  });
});

test('fails closed on unsupported transport shapes', async () => {
  const getResponse = await handleSyntheticMcpRequest(new Request(ENDPOINT));
  assert.equal(getResponse.status, 405);
  assert.equal(getResponse.headers.get('allow'), 'POST');

  const wrongType = await handleSyntheticMcpRequest(new Request(ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'text/plain' },
    body: '{}',
  }));
  assert.equal(wrongType.status, 415);

  const malformed = await handleSyntheticMcpRequest(new Request(ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{',
  }));
  assert.deepEqual((await malformed.json()).error, { code: -32700, message: 'Parse error' });

  const batch = await handleSyntheticMcpRequest(new Request(ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '[]',
  }));
  assert.deepEqual((await batch.json()).error, { code: -32600, message: 'Invalid Request' });

  const crossOrigin = await handleSyntheticMcpRequest(new Request(ENDPOINT, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: 'https://untrusted.invalid',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
  }));
  assert.equal(crossOrigin.status, 403);
  assert.deepEqual(await crossOrigin.json(), { error: 'origin_not_allowed' });
});

test('rejects requests larger than the fixture limit', async () => {
  const response = await handleSyntheticMcpRequest(new Request(ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
      padding: 'x'.repeat(70_000),
    }),
  }));

  assert.equal(response.status, 413);
  assert.deepEqual(await response.json(), { error: 'request_too_large' });
});

test('serves and verifies the complete protocol over a loopback Node listener', async (context) => {
  const listener = await startSyntheticMcpServer({ port: 0 });
  context.after(() => listener.close());

  assert.match(listener.origin, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.equal(listener.endpoint, `${listener.origin}/mcp`);
  assert.deepEqual(await inspectSyntheticEndpoint(listener.endpoint), {
    fixture: SYNTHETIC_FIXTURE_ID,
    schemaVersion: 1,
    toolNames: [SYNTHETIC_TOOL_NAME],
    callVerified: true,
  });

  const oversized = await fetch(listener.endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ padding: 'x'.repeat(70_000) }),
  });
  assert.equal(oversized.status, 413);
  assert.deepEqual(await oversized.json(), { error: 'request_too_large' });
});

test('inspector rejects non-fixture endpoints without exposing response data', async () => {
  const privateValue = 'private-upstream-value';
  const fetchImpl = async (_url, init) => {
    const request = JSON.parse(init.body);
    return new Response(JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      result: {
        protocolVersion: '2025-06-18',
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: privateValue, version: '1.0.0' },
      },
    }), { headers: { 'content-type': 'application/json' } });
  };

  await assert.rejects(
    inspectSyntheticEndpoint('https://fixture.example/mcp', { fetchImpl }),
    (error) => {
      assert.ok(error instanceof SyntheticMcpInspectionError);
      assert.equal(error.code, 'fixture_identity_mismatch');
      assert.doesNotMatch(error.message, new RegExp(privateValue));
      return true;
    },
  );
});

test('local listener refuses non-loopback binding', async () => {
  await assert.rejects(
    startSyntheticMcpServer({ host: '0.0.0.0', port: 0 }),
    /must bind to 127\.0\.0\.1/,
  );
});
