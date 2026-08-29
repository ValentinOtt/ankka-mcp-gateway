import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  EXECUTE_RESULT_MARKER,
  SEARCH_RESULT_MARKER,
  canonicalResultJson,
  canonicalResultSha256,
  createStatelessPortalTransport,
  runLivePortalCanary,
  runLivePortalCanaryCli,
  validateLivePortalCanaryConfig,
} from '../tools/live-portal-canary.mjs';

const PORTAL_URL = 'https://portal.example.com/mcp';
const HEALTH_TOOL = 'bls_read_ankka_canary_status';
const RAW_RESULT = Object.freeze({
  fixture: 'synthetic-live-canary',
  ok: true,
  privateRecord: 'raw-response-must-never-escape',
  version: 1,
});
const CLIENT_ID = 'client-id-must-never-escape.access';
const CLIENT_SECRET = 'client-secret-must-never-escape';
const EMAIL = 'canary-person@example.com';
const RAW_ERROR = 'provider-error-must-never-escape';

function config(overrides = {}) {
  return {
    schemaVersion: 1,
    portalUrl: PORTAL_URL,
    healthToolIdentifier: HEALTH_TOOL,
    arguments: {},
    expectedCanonicalResultSha256: canonicalResultSha256(RAW_RESULT),
    ...overrides,
  };
}

function rpc(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function portalTools(extra = []) {
  return [
    { name: 'portal_list_servers' },
    { name: 'portal_codemode_search' },
    { name: 'portal_codemode_execute' },
    ...extra.map((name) => ({ name })),
  ];
}

function successfulTransport(requests = []) {
  return async (request) => {
    requests.push(request);
    if (request.id === 'ankka-live-list') {
      return rpc(request.id, { tools: portalTools() });
    }
    if (request.id === 'ankka-live-search') {
      return rpc(request.id, {
        isError: false,
        structuredContent: {
          status: 'completed',
          result: { [SEARCH_RESULT_MARKER]: [HEALTH_TOOL] },
        },
        content: [{
          type: 'text',
          text: JSON.stringify({ [SEARCH_RESULT_MARKER]: [HEALTH_TOOL] }),
        }],
      });
    }
    if (request.id === 'ankka-live-execute') {
      return rpc(request.id, {
        isError: false,
        content: [{
          type: 'text',
          text: JSON.stringify({
            status: 'completed',
            result: { [EXECUTE_RESULT_MARKER]: RAW_RESULT },
          }),
        }],
      });
    }
    throw new Error(RAW_ERROR);
  };
}

function assertFixedReport(report) {
  assert.deepEqual(Object.keys(report), [
    'schemaVersion',
    'status',
    'code',
    'startedAt',
    'finishedAt',
    'latenciesMs',
  ]);
  assert.deepEqual(Object.keys(report.latenciesMs), [
    'total',
    'list_tools',
    'search',
    'execute',
  ]);
  assert.equal(Number.isNaN(Date.parse(report.startedAt)), false);
  assert.equal(Number.isNaN(Date.parse(report.finishedAt)), false);
  assert.ok(JSON.stringify(report).length < 512);
}

test('validates an exact secret-free no-argument canary configuration', () => {
  const validated = validateLivePortalCanaryConfig(config());
  assert.equal(validated.portalUrl, PORTAL_URL);
  assert.equal(validated.healthToolIdentifier, HEALTH_TOOL);
  assert.deepEqual(validated.arguments, {});

  for (const invalid of [
    config({ portalUrl: `${PORTAL_URL}?codemode=search_and_execute` }),
    config({ portalUrl: 'http://portal.example.com/mcp' }),
    config({ portalUrl: 'https://portal.example.com/' }),
    config({ healthToolIdentifier: 'bls-read-health' }),
    config({ healthToolIdentifier: 'bls_read_health</script>' }),
    config({ healthToolIdentifier: `bls_read_health${String.fromCodePoint(0x2028)}next` }),
    config({ healthToolIdentifier: 'portal_codemode_execute' }),
    config({ arguments: { recordId: 'forbidden' } }),
    config({ expectedCanonicalResultSha256: '0'.repeat(64) }),
    { ...config(), CF_ACCESS_CLIENT_SECRET: CLIENT_SECRET },
  ]) {
    assert.throws(
      () => validateLivePortalCanaryConfig(invalid),
      (error) => error?.code === 'config_invalid',
    );
  }
});

test('canonicalizes the health result recursively before SHA-256', () => {
  const value = { z: [3, { b: true, a: null }], a: 'first' };
  const canonical = '{"a":"first","z":[3,{"a":null,"b":true}]}';
  assert.equal(canonicalResultJson(value), canonical);
  assert.equal(
    canonicalResultSha256(value),
    `sha256:${createHash('sha256').update(canonical, 'utf8').digest('hex')}`,
  );
});

test('uses injected transport to list, search the exact identifier, and execute with no arguments', async () => {
  const requests = [];
  const result = await runLivePortalCanary(config(), {
    transport: successfulTransport(requests),
  });

  assert.equal(result.status, 'passed');
  assert.equal(result.code, 'ok');
  assertFixedReport(result);
  assert.deepEqual(requests.map(({ id, method, name }) => ({ id, method, name })), [
    { id: 'ankka-live-list', method: 'tools/list', name: undefined },
    { id: 'ankka-live-search', method: 'tools/call', name: 'portal_codemode_search' },
    { id: 'ankka-live-execute', method: 'tools/call', name: 'portal_codemode_execute' },
  ]);
  assert.ok(requests.every((request) => request.signal instanceof AbortSignal));
  assert.deepEqual(Object.keys(requests[1].params.arguments), ['code']);
  assert.match(requests[1].params.arguments.code, /tool\.name === "bls_read_ankka_canary_status"/u);
  assert.doesNotMatch(requests[1].params.arguments.code, /\.includes\(/u);
  assert.deepEqual(Object.keys(requests[2].params.arguments), ['code']);
  assert.match(
    requests[2].params.arguments.code,
    /codemode\["bls_read_ankka_canary_status"\]\(\{\}\)/u,
  );

  const serialized = JSON.stringify(result);
  for (const forbidden of [
    HEALTH_TOOL,
    RAW_RESULT.privateRecord,
    CLIENT_ID,
    CLIENT_SECRET,
    EMAIL,
    RAW_ERROR,
    requests[1].params.arguments.code,
    requests[2].params.arguments.code,
  ]) {
    assert.equal(serialized.includes(forbidden), false);
  }
});

test('fails closed when Code Mode is incomplete or any direct tool is listed', async (t) => {
  await t.test('missing execute tool', async () => {
    const result = await runLivePortalCanary(config(), {
      transport: async ({ id }) => rpc(id, {
        tools: [{ name: 'portal_codemode_search' }],
      }),
    });
    assert.equal(result.code, 'code_mode_tools_missing');
  });

  await t.test('direct upstream tool', async () => {
    const result = await runLivePortalCanary(config(), {
      transport: async ({ id }) => rpc(id, {
        tools: portalTools([HEALTH_TOOL]),
      }),
    });
    assert.equal(result.code, 'upstream_tools_exposed');
  });

  await t.test('unknown portal-prefixed tool', async () => {
    const result = await runLivePortalCanary(config(), {
      transport: async ({ id }) => rpc(id, {
        tools: portalTools(['portal_unreviewed_surface']),
      }),
    });
    assert.equal(result.code, 'upstream_tools_exposed');
  });
});

test('fails closed on an ambiguous search or canonical-result drift', async (t) => {
  await t.test('exact tool is absent', async () => {
    const requests = [];
    const transport = successfulTransport(requests);
    const result = await runLivePortalCanary(config(), {
      transport: async (request) => request.id === 'ankka-live-search'
        ? rpc(request.id, {
            isError: false,
            structuredContent: { [SEARCH_RESULT_MARKER]: [] },
          })
        : transport(request),
    });
    assert.equal(result.code, 'health_tool_not_found');
  });

  await t.test('health result hash changed', async () => {
    const result = await runLivePortalCanary(config({
      expectedCanonicalResultSha256: `sha256:${'0'.repeat(64)}`,
    }), { transport: successfulTransport() });
    assert.equal(result.code, 'health_result_mismatch');
  });
});

test('maps transport errors and total deadline expiry to content-free fixed codes', async (t) => {
  await t.test('raw transport error', async () => {
    const result = await runLivePortalCanary(config(), {
      transport: async () => {
        throw new Error(`${RAW_ERROR} ${EMAIL} ${CLIENT_SECRET}`);
      },
    });
    assert.equal(result.code, 'internal_failure');
    assertFixedReport(result);
    const serialized = JSON.stringify(result);
    assert.equal(serialized.includes(RAW_ERROR), false);
    assert.equal(serialized.includes(EMAIL), false);
    assert.equal(serialized.includes(CLIENT_SECRET), false);
  });

  await t.test('transport ignores AbortSignal', async () => {
    const result = await runLivePortalCanary(config(), {
      transport: () => new Promise(() => {}),
      deadlineMs: 5,
    });
    assert.equal(result.code, 'portal_deadline_exceeded');
    assert.equal(Number.isSafeInteger(result.latenciesMs.list_tools), true);
  });
});

test('real transport sends only the two environment credentials on bounded stateless JSON-RPC', async () => {
  let captured;
  const transport = createStatelessPortalTransport(PORTAL_URL, {
    environment: {
      CF_ACCESS_CLIENT_ID: CLIENT_ID,
      CF_ACCESS_CLIENT_SECRET: CLIENT_SECRET,
      FORBIDDEN_ALTERNATE_TOKEN: 'must-not-be-read',
    },
    fetchImpl: async (url, options) => {
      captured = { url, options };
      const request = JSON.parse(options.body);
      return Response.json(rpc(request.id, { tools: portalTools() }));
    },
  });
  const message = await transport({
    id: 'transport-test',
    method: 'tools/list',
    params: {},
    signal: new AbortController().signal,
  });

  assert.equal(message.id, 'transport-test');
  assert.equal(captured.url, PORTAL_URL);
  assert.equal(captured.options.method, 'POST');
  assert.equal(captured.options.redirect, 'error');
  assert.equal(captured.options.headers['CF-Access-Client-Id'], CLIENT_ID);
  assert.equal(captured.options.headers['CF-Access-Client-Secret'], CLIENT_SECRET);
  assert.equal(captured.options.headers.Authorization, undefined);
  assert.equal(captured.options.headers.Cookie, undefined);
  assert.equal(captured.options.headers['MCP-Protocol-Version'], '2026-07-28');
  assert.equal(captured.options.headers['Mcp-Method'], 'tools/list');
  assert.equal(captured.options.headers['Mcp-Session-Id'], undefined);
  assert.deepEqual(JSON.parse(captured.options.body), {
    id: 'transport-test',
    jsonrpc: '2.0',
    method: 'tools/list',
    params: {},
  });
});

test('real transport rejects missing credentials and oversized responses without exposing content', async (t) => {
  await t.test('missing environment credential', () => {
    assert.throws(
      () => createStatelessPortalTransport(PORTAL_URL, {
        environment: { CF_ACCESS_CLIENT_ID: CLIENT_ID },
        fetchImpl: async () => Response.json({}),
      }),
      (error) => error?.code === 'credential_missing'
        && !error.message.includes(CLIENT_ID),
    );
  });

  await t.test('response body bound', async () => {
    const transport = createStatelessPortalTransport(PORTAL_URL, {
      environment: {
        CF_ACCESS_CLIENT_ID: CLIENT_ID,
        CF_ACCESS_CLIENT_SECRET: CLIENT_SECRET,
      },
      fetchImpl: async () => new Response('x'.repeat(128 * 1024 + 1), {
        headers: { 'content-type': 'application/json' },
      }),
    });
    await assert.rejects(
      transport({
        id: 'oversized',
        method: 'tools/list',
        params: {},
        signal: new AbortController().signal,
      }),
      (error) => error?.code === 'portal_response_too_large'
        && !error.message.includes(CLIENT_SECRET),
    );
  });

  await t.test('raw fetch error becomes a fixed error', async () => {
    const transport = createStatelessPortalTransport(PORTAL_URL, {
      environment: {
        CF_ACCESS_CLIENT_ID: CLIENT_ID,
        CF_ACCESS_CLIENT_SECRET: CLIENT_SECRET,
      },
      fetchImpl: async () => {
        throw new Error(`${RAW_ERROR} ${EMAIL} ${CLIENT_SECRET}`);
      },
    });
    await assert.rejects(
      transport({
        id: 'unreachable',
        method: 'tools/list',
        params: {},
        signal: new AbortController().signal,
      }),
      (error) => error?.code === 'portal_unreachable'
        && !error.message.includes(RAW_ERROR)
        && !error.message.includes(EMAIL)
        && !error.message.includes(CLIENT_SECRET),
    );
  });

  await t.test('rejected status cancels its body', async () => {
    let canceled = false;
    const transport = createStatelessPortalTransport(PORTAL_URL, {
      environment: {
        CF_ACCESS_CLIENT_ID: CLIENT_ID,
        CF_ACCESS_CLIENT_SECRET: CLIENT_SECRET,
      },
      fetchImpl: async () => new Response(new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(RAW_RESULT.privateRecord));
        },
        cancel() {
          canceled = true;
        },
      }), { status: 401 }),
    });
    await assert.rejects(
      transport({
        id: 'rejected',
        method: 'tools/list',
        params: {},
        signal: new AbortController().signal,
      }),
      (error) => error?.code === 'portal_auth_rejected',
    );
    await Promise.resolve();
    assert.equal(canceled, true);
  });

  await t.test('malformed Content-Length is rejected and canceled', async () => {
    let canceled = false;
    const transport = createStatelessPortalTransport(PORTAL_URL, {
      environment: {
        CF_ACCESS_CLIENT_ID: CLIENT_ID,
        CF_ACCESS_CLIENT_SECRET: CLIENT_SECRET,
      },
      fetchImpl: async () => new Response(new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('{}'));
        },
        cancel() {
          canceled = true;
        },
      }), {
        headers: {
          'content-length': 'not-a-length',
          'content-type': 'application/json',
        },
      }),
    });
    await assert.rejects(
      transport({
        id: 'malformed-length',
        method: 'tools/list',
        params: {},
        signal: new AbortController().signal,
      }),
      (error) => error?.code === 'portal_response_invalid',
    );
    await Promise.resolve();
    assert.equal(canceled, true);
  });
});

test('CLI reads a secret-free file and emits exactly one bounded JSON record', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ankka-live-portal-canary-'));
  const file = path.join(directory, 'canary.json');
  try {
    await writeFile(file, `${JSON.stringify(config(), null, 2)}\n`, 'utf8');
    let stdout = '';
    const output = await runLivePortalCanaryCli(['--config', file], {
      transport: successfulTransport(),
      stdout: { write: (chunk) => { stdout += chunk; } },
    });
    assert.equal(output.status, 'passed');
    assert.equal(stdout.split('\n').filter(Boolean).length, 1);
    assert.deepEqual(JSON.parse(stdout), output);
    assert.ok(stdout.length < 512);
    for (const forbidden of [HEALTH_TOOL, RAW_RESULT.privateRecord, CLIENT_SECRET, EMAIL]) {
      assert.equal(stdout.includes(forbidden), false);
    }

    let failureStdout = '';
    const failure = await runLivePortalCanaryCli(['--config', file], {
      transport: async () => {
        throw new Error(`${RAW_ERROR} ${RAW_RESULT.privateRecord} ${CLIENT_ID} ${CLIENT_SECRET} ${EMAIL}`);
      },
      stdout: { write: (chunk) => { failureStdout += chunk; } },
    });
    assert.equal(failure.status, 'failed');
    assert.equal(failure.code, 'internal_failure');
    for (const forbidden of [
      RAW_ERROR,
      RAW_RESULT.privateRecord,
      CLIENT_ID,
      CLIENT_SECRET,
      EMAIL,
    ]) {
      assert.equal(failureStdout.includes(forbidden), false);
      assert.equal(JSON.stringify(failure).includes(forbidden), false);
    }

    const packageJson = JSON.parse(await readFile(
      new URL('../package.json', import.meta.url),
      'utf8',
    ));
    assert.equal(packageJson.scripts['canary:live'], 'node tools/live-portal-canary.mjs');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
