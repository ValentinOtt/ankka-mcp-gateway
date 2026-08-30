import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';

import {
  canonicalRegistryJson,
  checkOfficialRegistryRecord,
  inspectRegistryRecord,
  McpRegistryCheckError,
  OFFICIAL_REGISTRY_ORIGIN,
  SUPPORTED_SERVER_SCHEMA_URL,
} from '../tools/mcp-registry-check.mjs';

const execFileAsync = promisify(execFile);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TOOL = path.join(ROOT, 'tools/mcp-registry-check.mjs');
const SERVER_NAME = 'com.example/analytics';
const SERVER_VERSION = '1.2.3';
const OBSERVED_AT = '2026-08-29';

function record(overrides = {}) {
  return {
    server: {
      $schema: SUPPORTED_SERVER_SCHEMA_URL,
      name: SERVER_NAME,
      description: 'Synthetic analytics server.',
      version: SERVER_VERSION,
      title: 'Synthetic analytics',
      remotes: [{ type: 'streamable-http', url: 'https://mcp.example.com/mcp' }],
      packages: [],
      ...overrides,
    },
    _meta: {
      'io.modelcontextprotocol.registry/official': {
        status: 'active',
        isLatest: true,
      },
    },
  };
}

function response(value, init = {}) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init,
  });
}

function expectCode(callback, code) {
  assert.throws(callback, (error) =>
    error instanceof McpRegistryCheckError && error.code === code);
}

test('reduces an exact record to deterministic public review fields', () => {
  const payload = record({
    remotes: [
      { type: 'sse', url: 'https://mcp.example.com/sse' },
      { type: 'streamable-http', url: 'https://mcp.example.com/mcp' },
      {
        type: 'streamable-http',
        url: 'https://{tenant}.example.com/mcp',
        variables: { tenant: { description: 'Synthetic tenant.' } },
      },
      {
        type: 'streamable-http',
        url: 'https://header.example.com/mcp',
        headers: [{ name: 'X-Synthetic', value: 'synthetic' }],
      },
    ],
    packages: [{ registryType: 'npm', identifier: '@example/synthetic' }],
  });
  const result = inspectRegistryRecord(payload, {
    serverName: SERVER_NAME,
    serverVersion: SERVER_VERSION,
    observedAt: OBSERVED_AT,
  });
  const expectedDigest = `sha256:${createHash('sha256')
    .update(canonicalRegistryJson(payload.server), 'utf8').digest('hex')}`;

  assert.deepEqual(result, {
    schemaVersion: 1,
    registryOrigin: OFFICIAL_REGISTRY_ORIGIN,
    registryApiVersion: 'v0.1',
    serverSchemaRevision: '2025-12-11',
    serverName: SERVER_NAME,
    serverVersion: SERVER_VERSION,
    status: 'active',
    isLatest: true,
    observedAt: OBSERVED_AT,
    recordSha256: expectedDigest,
    packageCount: 1,
    remoteCount: 4,
    phaseOneCandidateCount: 1,
    phaseOneRemotes: [
      {
        type: 'streamable-http',
        url: 'https://mcp.example.com/mcp',
      },
    ],
  });
});

test('rejects drift from the exact identity, digest, and Registry status contract', () => {
  expectCode(() => inspectRegistryRecord(record({ name: 'com.example/other' }), {
    serverName: SERVER_NAME,
    serverVersion: SERVER_VERSION,
  }), 'registry_record_invalid');
  expectCode(() => inspectRegistryRecord(record(), {
    serverName: SERVER_NAME,
    serverVersion: SERVER_VERSION,
    expectedRecordSha256: `sha256:${'0'.repeat(64)}`,
  }), 'registry_record_digest_mismatch');

  const deprecated = record();
  deprecated._meta['io.modelcontextprotocol.registry/official'].status = 'unknown';
  expectCode(() => inspectRegistryRecord(deprecated, {
    serverName: SERVER_NAME,
    serverVersion: SERVER_VERSION,
  }), 'registry_record_invalid');

  expectCode(() => inspectRegistryRecord(record({
    $schema: 'https://static.modelcontextprotocol.io/schemas/2099-01-01/server.schema.json',
  }), {
    serverName: SERVER_NAME,
    serverVersion: SERVER_VERSION,
  }), 'registry_schema_unsupported');
});

test('rejects latest, malformed remotes, duplicate remotes, and hides unsafe remote URLs', () => {
  for (const version of ['latest', '*', '.', '..']) {
    expectCode(() => inspectRegistryRecord(record(), {
      serverName: SERVER_NAME,
      serverVersion: version,
    }), 'argument_invalid');
  }
  expectCode(() => inspectRegistryRecord(record({
    remotes: [{ type: 'websocket', url: 'https://mcp.example.com/mcp' }],
  }), {
    serverName: SERVER_NAME,
    serverVersion: SERVER_VERSION,
  }), 'registry_record_invalid');
  expectCode(() => inspectRegistryRecord(record({
    remotes: [{
      type: 'streamable-http',
      url: 'https://mcp.example.com/mcp',
      authorization: { mode: 'synthetic' },
    }],
  }), {
    serverName: SERVER_NAME,
    serverVersion: SERVER_VERSION,
  }), 'registry_record_invalid');
  expectCode(() => inspectRegistryRecord(record({
    remotes: [{
      type: 'streamable-http',
      url: 'https://mcp.example.com/mcp',
      headers: { name: 'X-Synthetic' },
    }],
  }), {
    serverName: SERVER_NAME,
    serverVersion: SERVER_VERSION,
  }), 'registry_record_invalid');
  expectCode(() => inspectRegistryRecord(record({
    remotes: [
      { type: 'streamable-http', url: 'https://mcp.example.com/mcp' },
      { type: 'streamable-http', url: 'https://mcp.example.com/mcp' },
    ],
  }), {
    serverName: SERVER_NAME,
    serverVersion: SERVER_VERSION,
  }), 'registry_record_invalid');
  for (const malformedInput of [
    { headers: [{}] },
    { headers: [{ name: 'X-Synthetic', isSecret: 'yes' }] },
    { variables: { tenant: null } },
  ]) {
    expectCode(() => inspectRegistryRecord(record({
      remotes: [{
        type: 'streamable-http',
        url: 'https://mcp.example.com/mcp',
        ...malformedInput,
      }],
    }), {
      serverName: SERVER_NAME,
      serverVersion: SERVER_VERSION,
    }), 'registry_record_invalid');
  }

  const unsafeValues = [
    'https://mcp.example.com/mcp?token=query-secret',
    'https://user:userinfo-secret@mcp.example.com/mcp',
    'http://mcp.example.com/scheme-secret',
    'https://mcp.example.com/bidi-\u202E-secret',
    'https://mcp.example.com/{unresolved-template}/mcp',
  ];
  const unsafe = inspectRegistryRecord(record({
    remotes: unsafeValues.map((url) => ({ type: 'streamable-http', url })),
  }), {
    serverName: SERVER_NAME,
    serverVersion: SERVER_VERSION,
  });
  assert.equal(unsafe.phaseOneCandidateCount, 0);
  assert.equal(unsafe.remoteCount, unsafeValues.length);
  assert.deepEqual(unsafe.phaseOneRemotes, []);
  const serialized = canonicalRegistryJson(unsafe);
  for (const marker of [
    'query-secret',
    'userinfo-secret',
    'scheme-secret',
    'bidi',
    'unresolved-template',
  ]) {
    assert.doesNotMatch(serialized, new RegExp(marker, 'u'));
  }
});

test('fetches only the fixed exact Registry route with bounded request options', async () => {
  let rejectedFetchCalled = false;
  await assert.rejects(
    checkOfficialRegistryRecord(SERVER_NAME, '..', {
      fetchImpl: async () => {
        rejectedFetchCalled = true;
        return response(record());
      },
    }),
    (error) => error instanceof McpRegistryCheckError && error.code === 'argument_invalid',
  );
  assert.equal(rejectedFetchCalled, false);

  const fetchImpl = async (url, init) => {
    assert.equal(
      url,
      `${OFFICIAL_REGISTRY_ORIGIN}/v0.1/servers/com.example%2Fanalytics/versions/1.2.3`,
    );
    assert.equal(init.method, 'GET');
    assert.equal(init.redirect, 'error');
    assert.deepEqual(init.headers, { Accept: 'application/json' });
    assert.ok(init.signal instanceof AbortSignal);
    return response(record());
  };
  const result = await checkOfficialRegistryRecord(SERVER_NAME, SERVER_VERSION, {
    fetchImpl,
    observedAt: OBSERVED_AT,
  });
  assert.equal(result.phaseOneCandidateCount, 1);
});

test('maps network, HTTP, media-type, and size failures to fixed error codes', async () => {
  const cases = [
    [async () => { throw Object.assign(new Error('sensitive'), { name: 'TimeoutError' }); },
      'registry_request_timeout'],
    [async () => new Response(null, { status: 404 }), 'registry_record_not_found'],
    [async () => new Response(null, { status: 503 }), 'registry_unavailable'],
    [async () => new Response('{}', { headers: { 'content-type': 'text/plain' } }),
      'registry_response_invalid'],
    [async () => new Response('{}', {
      headers: { 'content-type': 'application/json', 'content-length': String(1024 * 1024 + 1) },
    }), 'registry_response_too_large'],
  ];
  for (const [fetchImpl, code] of cases) {
    await assert.rejects(
      checkOfficialRegistryRecord(SERVER_NAME, SERVER_VERSION, { fetchImpl }),
      (error) => error instanceof McpRegistryCheckError && error.code === code,
    );
  }
});

test('prints help without network access or accepting runtime origins', async () => {
  const { stdout, stderr } = await execFileAsync(process.execPath, [TOOL, '--help'], { cwd: ROOT });
  assert.match(stdout, /official MCP Registry/u);
  assert.match(stdout, /--server/u);
  assert.equal(stderr, '');

  await assert.rejects(
    execFileAsync(process.execPath, [
      TOOL,
      '--server', SERVER_NAME,
      '--version', SERVER_VERSION,
      '--registry-origin', 'https://registry.example.com',
    ], { cwd: ROOT }),
    (error) => error.code === 1 && /argument_invalid/u.test(error.stderr) &&
      !error.stderr.includes('registry.example.com'),
  );
});
