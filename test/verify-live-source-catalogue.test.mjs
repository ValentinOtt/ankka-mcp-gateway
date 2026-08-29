import test from 'node:test';
import assert from 'node:assert/strict';
import {
  LiveSourceCatalogueError,
  verifyLiveSourceCatalogue,
} from '../tools/verify-live-source-catalogue.mjs';

function config(authenticationMode = 'none') {
  return {
    schemaVersion: 1,
    gateway: {
      name: 'Synthetic catalogue gate',
      hostname: 'catalogue-gate.example.com',
      codeMode: 'default_on',
    },
    policy: {
      capabilityMode: 'read_only',
      credentialCustody: 'customer',
      telemetry: 'off',
    },
    sources: [{
      id: 'synthetic-source',
      label: 'Synthetic source',
      url: 'https://source.example.com/mcp',
      authentication: {
        mode: authenticationMode,
        onBehalfOfUser: authenticationMode === 'oauth',
      },
      enabledTools: [
        '1st-read',
        'catalog-item.read',
        'catalog_item_read',
      ],
    }],
  };
}

function rpcResult(id, result) {
  return Response.json({ jsonrpc: '2.0', id, result });
}

test('verifies an exact paginated catalogue and reports only counts and digests', async () => {
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    const message = JSON.parse(options.body);
    if (message.params.cursor === undefined) {
      return rpcResult(message.id, {
        tools: [{ name: 'catalog_item_read' }, { name: '1st-read' }],
        nextCursor: 'page-2',
      });
    }
    assert.equal(message.params.cursor, 'page-2');
    return rpcResult(message.id, { tools: [{ name: 'catalog-item.read' }] });
  };

  const result = await verifyLiveSourceCatalogue(
    config(),
    'synthetic-source',
    { fetchImpl },
  );

  assert.deepEqual(Object.keys(result), [
    'schemaVersion',
    'status',
    'expectedCount',
    'actualCount',
    'expectedSha256',
    'actualSha256',
  ]);
  assert.equal(result.status, 'verified');
  assert.equal(result.expectedCount, 3);
  assert.equal(result.actualCount, 3);
  assert.equal(result.expectedSha256, result.actualSha256);
  assert.equal(requests.length, 2);
  assert.equal(requests[0].url, 'https://source.example.com/mcp');
  assert.equal(requests[0].options.redirect, 'error');
  assert.equal(requests[0].options.headers.authorization, undefined);
  assert.equal(requests[0].options.headers['mcp-method'], 'tools/list');
  assert.equal(requests[0].options.headers['mcp-protocol-version'], '2026-07-28');
});

test('accepts an OAuth token only from the caller and sends it to the exact source', async () => {
  const token = 'synthetic-oauth-token';
  const fetchImpl = async (url, options) => {
    assert.equal(url, 'https://source.example.com/mcp');
    assert.equal(options.headers.authorization, `Bearer ${token}`);
    const message = JSON.parse(options.body);
    return rpcResult(message.id, {
      tools: config('oauth').sources[0].enabledTools.map((name) => ({ name })),
    });
  };

  const result = await verifyLiveSourceCatalogue(
    config('oauth'),
    'synthetic-source',
    { fetchImpl, oauthAccessToken: token },
  );
  assert.equal(result.status, 'verified');
  assert.doesNotMatch(JSON.stringify(result), /synthetic-oauth-token/u);
});

test('accepts the event-stream response shape used by MCP transports', async () => {
  const fetchImpl = async (_url, options) => {
    const { id } = JSON.parse(options.body);
    return new Response(
      `event: message\ndata: ${JSON.stringify({
        jsonrpc: '2.0',
        id,
        result: { tools: config().sources[0].enabledTools.map((name) => ({ name })) },
      })}\n\n`,
      { headers: { 'content-type': 'text/event-stream; charset=utf-8' } },
    );
  };

  const result = await verifyLiveSourceCatalogue(
    config(),
    'synthetic-source',
    { fetchImpl },
  );
  assert.equal(result.status, 'verified');
});

test('requires OAuth authority and rejects credential modes the gate cannot handle', async () => {
  await assert.rejects(
    verifyLiveSourceCatalogue(config('oauth'), 'synthetic-source'),
    (error) => error instanceof LiveSourceCatalogueError
      && error.code === 'source_authentication_required',
  );
  await assert.rejects(
    verifyLiveSourceCatalogue(config('bearer'), 'synthetic-source'),
    (error) => error instanceof LiveSourceCatalogueError
      && error.code === 'source_authentication_unsupported',
  );
});

test('fails closed without disclosing names when the live catalogue differs', async () => {
  const fetchImpl = async (_url, options) => {
    const message = JSON.parse(options.body);
    return rpcResult(message.id, {
      tools: [
        { name: '1st-read' },
        { name: 'catalog-item.read' },
        { name: 'unexpected-private-looking-name' },
      ],
    });
  };

  await assert.rejects(
    verifyLiveSourceCatalogue(config(), 'synthetic-source', { fetchImpl }),
    (error) => {
      assert.equal(error.message, 'live_source_catalogue_failure');
      assert.equal(error.code, 'catalogue_mismatch');
      assert.doesNotMatch(JSON.stringify(error), /unexpected-private-looking-name/u);
      return true;
    },
  );
});

test('rejects duplicate names, cursor loops, oversized responses, and redirects', async (context) => {
  const cases = [
    {
      name: 'duplicate name',
      expected: 'source_tool_list_invalid',
      fetchImpl: async (_url, options) => {
        const { id } = JSON.parse(options.body);
        return rpcResult(id, { tools: [{ name: '1st-read' }, { name: '1st-read' }] });
      },
    },
    {
      name: 'cursor loop',
      expected: 'source_tool_list_invalid',
      fetchImpl: async (_url, options) => {
        const { id } = JSON.parse(options.body);
        return rpcResult(id, { tools: [], nextCursor: 'same' });
      },
    },
    {
      name: 'oversized response',
      expected: 'source_response_too_large',
      fetchImpl: async () => new Response('', {
        headers: { 'content-length': String((4 * 1024 * 1024) + 1) },
      }),
    },
    {
      name: 'oversized chunked response',
      expected: 'source_response_too_large',
      fetchImpl: async () => new Response(new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(4 * 1024 * 1024));
          controller.enqueue(new Uint8Array([0x20]));
          controller.close();
        },
      }), {
        headers: { 'content-type': 'application/json' },
      }),
    },
    {
      name: 'redirect',
      expected: 'source_http_rejected',
      fetchImpl: async () => new Response(null, { status: 302 }),
    },
  ];

  for (const scenario of cases) {
    await context.test(scenario.name, async () => {
      await assert.rejects(
        verifyLiveSourceCatalogue(config(), 'synthetic-source', {
          fetchImpl: scenario.fetchImpl,
        }),
        (error) => error instanceof LiveSourceCatalogueError
          && error.code === scenario.expected,
      );
    });
  }
});
