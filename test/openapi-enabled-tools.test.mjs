import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { after, before, test } from 'node:test';

import {
  extractEnabledTools,
  mergeEnabledTools,
  OpenApiEnabledToolsError,
  serializeGatewayConfig,
  validateSelectionManifest,
} from '../tools/openapi-enabled-tools.mjs';

const execFileAsync = promisify(execFile);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TOOL = path.join(ROOT, 'tools/openapi-enabled-tools.mjs');

function openApi(paths) {
  return { openapi: '3.1.0', info: { title: 'Synthetic API', version: '1' }, paths };
}

function securedOpenApi(paths, security = [{ bearerAuth: [] }]) {
  return {
    ...openApi(paths),
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer' },
      },
    },
    security,
  };
}

function manifest(entries = [], syntheticTools = []) {
  return {
    $comment: 'Synthetic reviewed selection; contains no credentials.',
    entries,
    syntheticTools,
  };
}

function manifestEntry(overrides = {}) {
  return {
    operationId: 'read_by_post',
    method: 'POST',
    path: '/read-by-post',
    reason: 'A structured read query whose body does not mutate state.',
    verified: 'Synthetic code review',
    ...overrides,
  };
}

function syntheticTool(overrides = {}) {
  return {
    name: 'worker_health',
    reason: 'A fixed Worker-local health response with no upstream request.',
    ...overrides,
  };
}

function expectErrorCode(callback, code) {
  assert.throws(
    callback,
    (error) => error instanceof OpenApiEnabledToolsError && error.code === code,
  );
}

function config(enabledTools = ['old_tool']) {
  return {
    schemaVersion: 1,
    gateway: {
      name: 'Synthetic MCP Gateway',
      hostname: 'mcp.example.com',
      codeMode: 'default_on',
    },
    policy: {
      capabilityMode: 'read_only',
      credentialCustody: 'customer',
      telemetry: 'off',
    },
    sources: [{
      id: 'synthetic-read',
      label: 'Synthetic read source',
      url: 'https://source.example.com/mcp',
      authentication: { mode: 'none', onBehalfOfUser: false },
      enabledTools,
    }],
  };
}

let temporaryDirectory;

before(async () => {
  temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'ankka-openapi-enabled-tools-'));
});

after(async () => {
  if (temporaryDirectory) await rm(temporaryDirectory, { force: true, recursive: true });
});

test('maps selected operationIds verbatim and deterministically', () => {
  const first = openApi({
    '/zeta': {
      post: { operationId: 'write_zeta' },
      get: { operationId: 'read_zeta', summary: 'Read zeta' },
    },
    '/alpha': { get: { operationId: 'read.alpha/v1' } },
  });
  const second = openApi({
    '/alpha': { get: { operationId: 'read.alpha/v1' } },
    '/zeta': {
      get: { summary: 'Changed prose does not change the tool name', operationId: 'read_zeta' },
      post: { operationId: 'write_zeta' },
    },
  });

  assert.deepEqual(extractEnabledTools(first, { methods: ['GET'] }), [
    'read.alpha/v1',
    'read_zeta',
  ]);
  assert.deepEqual(
    extractEnabledTools(second, { methods: ['get'] }),
    extractEnabledTools(first, { methods: ['GET'] }),
  );
});

test('unions exact protected non-GET and synthetic manifest selections with GET tools', () => {
  const document = securedOpenApi({
    '/zeta': { get: { operationId: 'read_zeta' } },
    '/read-by-post': { post: { operationId: 'read_by_post' } },
    '/alpha': { get: { operationId: 'read_alpha' } },
    '/public-callback': {
      post: { operationId: 'public_callback', security: [] },
    },
  });
  const selection = manifest(
    [manifestEntry()],
    [syntheticTool()],
  );

  assert.deepEqual(extractEnabledTools(document, {
    methods: ['GET'],
    manifest: selection,
  }), [
    'read_alpha',
    'read_by_post',
    'read_zeta',
    'worker_health',
  ]);
  assert.deepEqual(extractEnabledTools(document, { methods: ['GET'] }), [
    'read_alpha',
    'read_zeta',
  ]);
  assert.deepEqual(validateSelectionManifest(selection), {
    entries: [{
      method: 'POST',
      operationId: 'read_by_post',
      path: '/read-by-post',
    }],
    syntheticTools: ['worker_health'],
  });

  assert.deepEqual(extractEnabledTools(securedOpenApi({
    '/read-by-post': { post: { operationId: 'read_by_post' } },
  }), {
    methods: ['GET'],
    manifest: manifest([manifestEntry()]),
  }), ['read_by_post']);
});

test('requires an exact, review-bearing, unknown-field-free manifest shape', () => {
  const invalidManifests = [
    [{ entries: [], syntheticTools: [], extra: true }, 'manifest_shape_invalid'],
    [{ entries: [] }, 'manifest_shape_invalid'],
    [manifest(), 'manifest_selection_empty'],
    [manifest([manifestEntry({ extra: true })]), 'manifest_entry_shape_invalid'],
    [manifest([manifestEntry({ operationId: 'unsafe name' })]), 'manifest_operation_id_invalid'],
    [manifest([manifestEntry({ method: 'post' })]), 'manifest_method_invalid'],
    [manifest([manifestEntry({ method: 'GET' })]), 'manifest_get_operation_forbidden'],
    [manifest([manifestEntry({ path: '/read-by-post?scope=all' })]), 'manifest_path_invalid'],
    [manifest([manifestEntry({ reason: ' ' })]), 'manifest_reason_invalid'],
    [manifest([manifestEntry({ reason: 'Reviewed\u202eignored' })]), 'manifest_reason_invalid'],
    [manifest([manifestEntry({ verified: '' })]), 'manifest_verification_invalid'],
    [manifest([], [syntheticTool({ extra: true })]), 'manifest_synthetic_tool_shape_invalid'],
    [manifest([], [syntheticTool({ name: 'unsafe name' })]), 'manifest_synthetic_tool_name_invalid'],
    [manifest([], [syntheticTool({ reason: '\n' })]), 'manifest_synthetic_tool_reason_invalid'],
  ];
  for (const [selection, code] of invalidManifests) {
    expectErrorCode(() => validateSelectionManifest(selection), code);
  }
});

test('rejects duplicate and colliding manifest selections', () => {
  expectErrorCode(
    () => validateSelectionManifest(manifest([
      manifestEntry(),
      manifestEntry({ path: '/other' }),
    ])),
    'manifest_operation_duplicate',
  );
  expectErrorCode(
    () => validateSelectionManifest(manifest([
      manifestEntry(),
      manifestEntry({ operationId: 'other_read' }),
    ])),
    'manifest_endpoint_duplicate',
  );
  expectErrorCode(
    () => validateSelectionManifest(manifest([], [syntheticTool(), syntheticTool()])),
    'manifest_synthetic_tool_duplicate',
  );
  expectErrorCode(
    () => validateSelectionManifest(manifest(
      [manifestEntry()],
      [syntheticTool({ name: 'read_by_post' })],
    )),
    'manifest_tool_name_collision',
  );
});

test('enforces the shared 500-tool source limit on manifests and their GET union', () => {
  const tooManySynthetic = Array.from(
    { length: 501 },
    (_, index) => syntheticTool({ name: `worker_health_${String(index).padStart(3, '0')}` }),
  );
  expectErrorCode(
    () => validateSelectionManifest(manifest([], tooManySynthetic)),
    'manifest_selection_limit_exceeded',
  );

  const paths = Object.fromEntries(Array.from({ length: 500 }, (_, index) => [
    `/read/${String(index)}`,
    { get: { operationId: `read_${String(index).padStart(3, '0')}` } },
  ]));
  expectErrorCode(
    () => extractEnabledTools(openApi(paths), {
      methods: ['GET'],
      manifest: manifest([], [syntheticTool()]),
    }),
    'manifest_selection_limit_exceeded',
  );
});

test('rejects manifest drift, ambiguous operationIds, and synthetic/spec collisions', () => {
  const selection = manifest([manifestEntry()]);
  const driftedDocuments = [
    securedOpenApi({
      '/moved': { post: { operationId: 'read_by_post' } },
      '/read': { get: { operationId: 'read_default' } },
    }),
    securedOpenApi({
      '/read-by-post': { post: { operationId: 'renamed_read' } },
      '/read': { get: { operationId: 'read_default' } },
    }),
    securedOpenApi({
      '/read-by-post': { patch: { operationId: 'read_by_post' } },
      '/read': { get: { operationId: 'read_default' } },
    }),
  ];
  for (const document of driftedDocuments) {
    expectErrorCode(
      () => extractEnabledTools(document, { methods: ['GET'], manifest: selection }),
      'manifest_operation_drift',
    );
  }

  const ambiguous = securedOpenApi({
    '/read-by-post': { post: { operationId: 'read_by_post' } },
    '/duplicate': { patch: { operationId: 'read_by_post' } },
    '/read': { get: { operationId: 'read_default' } },
  });
  expectErrorCode(
    () => extractEnabledTools(ambiguous, { methods: ['GET'], manifest: selection }),
    'manifest_operation_ambiguous',
  );

  const collision = securedOpenApi({
    '/read': { get: { operationId: 'read_default' } },
    '/worker-health': { post: { operationId: 'worker_health' } },
  });
  expectErrorCode(
    () => extractEnabledTools(collision, {
      methods: ['GET'],
      manifest: manifest([], [syntheticTool()]),
    }),
    'manifest_tool_name_collision',
  );
});

test('only admits manifest operations whose effective OpenAPI security requires credentials', () => {
  const operation = { operationId: 'read_by_post' };
  const publicDocuments = [
    openApi({
      '/read': { get: { operationId: 'read_default' } },
      '/read-by-post': { post: operation },
    }),
    securedOpenApi({
      '/read': { get: { operationId: 'read_default' } },
      '/read-by-post': { post: { ...operation, security: [] } },
    }),
    securedOpenApi({
      '/read': { get: { operationId: 'read_default' } },
      '/read-by-post': { post: { ...operation, security: [{}] } },
    }),
  ];
  for (const document of publicDocuments) {
    expectErrorCode(
      () => extractEnabledTools(document, {
        methods: ['GET'],
        manifest: manifest([manifestEntry()]),
      }),
      'manifest_operation_public',
    );
  }

  const invalidSecurity = securedOpenApi({
    '/read': { get: { operationId: 'read_default' } },
    '/read-by-post': {
      post: { ...operation, security: [{ missingScheme: [] }] },
    },
  });
  expectErrorCode(
    () => extractEnabledTools(invalidSecurity, {
      methods: ['GET'],
      manifest: manifest([manifestEntry()]),
    }),
    'manifest_operation_security_invalid',
  );

  const protectedOverride = securedOpenApi({
    '/read': { get: { operationId: 'read_default' } },
    '/read-by-post': {
      post: { ...operation, security: [{ bearerAuth: [] }] },
    },
  }, []);
  assert.deepEqual(extractEnabledTools(protectedOverride, {
    methods: ['GET'],
    manifest: manifest([manifestEntry()]),
  }), ['read_by_post', 'read_default']);
});

test('fails closed on missing, transformed, invalid, duplicate, and referenced operations', () => {
  const invalidDocuments = [
    [openApi({ '/missing': { get: { summary: 'No ID' } } }), 'operation_id_missing'],
    [openApi({ '/space': { get: { operationId: ' read_space' } } }), 'operation_id_not_verbatim_safe'],
    [openApi({ '/invalid': { get: { operationId: 'read operation' } } }), 'operation_id_not_tool_safe'],
    [openApi({
      '/first': { get: { operationId: 'read_same' } },
      '/second': { get: { operationId: 'read_same' } },
    }), 'operation_id_duplicate'],
    [openApi({ '/reference': { $ref: '#/components/pathItems/Reference' } }), 'path_item_reference_unsupported'],
  ];

  for (const [document, code] of invalidDocuments) {
    assert.throws(
      () => extractEnabledTools(document, { methods: ['GET'] }),
      (error) => error instanceof OpenApiEnabledToolsError && error.code === code,
    );
  }

  assert.throws(
    () => extractEnabledTools(
      openApi({ '/records/synthetic-token-value': { get: {} } }),
      { methods: ['GET'] },
    ),
    (error) => error instanceof OpenApiEnabledToolsError &&
      error.message === 'operation_id_missing: GET operation at paths[0]' &&
      !error.message.includes('synthetic-token-value'),
  );
});

test('requires an explicit read-only method and at least one selected operation', () => {
  const document = openApi({ '/resource': { post: { operationId: 'search_resource' } } });
  assert.throws(
    () => extractEnabledTools(document, { methods: [] }),
    (error) => error instanceof OpenApiEnabledToolsError && error.code === 'method_required',
  );
  assert.throws(
    () => extractEnabledTools(document, { methods: ['POST'] }),
    (error) => error instanceof OpenApiEnabledToolsError &&
      error.code === 'method_outside_read_only_boundary',
  );
  assert.throws(
    () => extractEnabledTools(document, { methods: ['GET'] }),
    (error) => error instanceof OpenApiEnabledToolsError &&
      error.code === 'selected_operations_empty',
  );
});

test('replaces one exact allowlist without changing another source', () => {
  const input = config();
  input.sources.push({
    ...input.sources[0],
    id: 'other-source',
    enabledTools: ['keep_me'],
  });
  const merged = mergeEnabledTools(input, 'synthetic-read', ['zeta', 'alpha']);

  assert.deepEqual(merged.sources[0].enabledTools, ['alpha', 'zeta']);
  assert.deepEqual(merged.sources[1].enabledTools, ['keep_me']);
  assert.deepEqual(input.sources[0].enabledTools, ['old_tool']);
  assert.equal(serializeGatewayConfig(merged).endsWith('\n'), true);
});

test('serializes identical bytes despite input object and tool ordering', () => {
  const reordered = {
    sources: [{
      enabledTools: ['old_tool'],
      authentication: { onBehalfOfUser: false, mode: 'none' },
      url: 'https://source.example.com/mcp',
      label: 'Synthetic read source',
      id: 'synthetic-read',
    }],
    policy: {
      telemetry: 'off',
      credentialCustody: 'customer',
      capabilityMode: 'read_only',
    },
    gateway: {
      codeMode: 'default_on',
      hostname: 'mcp.example.com',
      name: 'Synthetic MCP Gateway',
    },
    schemaVersion: 1,
  };

  assert.equal(
    serializeGatewayConfig(mergeEnabledTools(config(), 'synthetic-read', ['zeta', 'alpha'])),
    serializeGatewayConfig(mergeEnabledTools(reordered, 'synthetic-read', ['alpha', 'zeta'])),
  );
});

test('writes a deterministic config and check mode detects later drift', async () => {
  const specPath = path.join(temporaryDirectory, 'openapi.json');
  const configPath = path.join(temporaryDirectory, 'gateway.config.json');
  await Promise.all([
    writeFile(specPath, JSON.stringify(openApi({
      '/zeta': { get: { operationId: 'read_zeta' } },
      '/alpha': { get: { operationId: 'read_alpha' } },
    }))),
    writeFile(configPath, serializeGatewayConfig(config())),
  ]);
  const arguments_ = [
    TOOL,
    '--spec', specPath,
    '--config', configPath,
    '--source', 'synthetic-read',
    '--method', 'GET',
  ];

  const written = await execFileAsync(process.execPath, [...arguments_, '--write'], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  assert.equal(written.stderr, '');
  assert.match(written.stdout, /Updated enabledTools/u);
  assert.deepEqual(JSON.parse(await readFile(configPath, 'utf8')).sources[0].enabledTools, [
    'read_alpha',
    'read_zeta',
  ]);
  assert.deepEqual((await readdir(temporaryDirectory)).sort(), [
    'gateway.config.json',
    'openapi.json',
  ]);

  const checked = await execFileAsync(process.execPath, [...arguments_, '--check'], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  assert.match(checked.stdout, /enabledTools is current/u);

  await writeFile(configPath, serializeGatewayConfig(config(['read_alpha'])));
  await assert.rejects(
    execFileAsync(process.execPath, [...arguments_, '--check'], { cwd: ROOT, encoding: 'utf8' }),
    (error) => error.code === 1 && /enabled_tools_stale/u.test(error.stderr),
  );
});

test('CLI manifest mode writes the reviewed union and check fails on spec/manifest drift', async () => {
  const specPath = path.join(temporaryDirectory, 'manifest-openapi.json');
  const configPath = path.join(temporaryDirectory, 'manifest-gateway.config.json');
  const manifestPath = path.join(temporaryDirectory, 'selection-manifest.json');
  await Promise.all([
    writeFile(specPath, JSON.stringify(securedOpenApi({
      '/read': { get: { operationId: 'read_default' } },
      '/read-by-post': { post: { operationId: 'read_by_post' } },
    }))),
    writeFile(configPath, serializeGatewayConfig(config())),
    writeFile(manifestPath, JSON.stringify(manifest(
      [manifestEntry()],
      [syntheticTool()],
    ))),
  ]);
  const arguments_ = [
    TOOL,
    '--spec', specPath,
    '--config', configPath,
    '--source', 'synthetic-read',
    '--method', 'GET',
    '--manifest', manifestPath,
  ];

  await execFileAsync(process.execPath, [...arguments_, '--write'], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  assert.deepEqual(JSON.parse(await readFile(configPath, 'utf8')).sources[0].enabledTools, [
    'read_by_post',
    'read_default',
    'worker_health',
  ]);

  const checked = await execFileAsync(process.execPath, [...arguments_, '--check'], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  assert.match(checked.stdout, /enabledTools is current/u);

  await writeFile(manifestPath, JSON.stringify(manifest([
    manifestEntry({ path: '/drifted' }),
  ], [syntheticTool()])));
  await assert.rejects(
    execFileAsync(process.execPath, [...arguments_, '--check'], { cwd: ROOT, encoding: 'utf8' }),
    (error) => error.code === 1 &&
      /manifest_operation_drift/u.test(error.stderr) &&
      !error.stderr.includes('/drifted'),
  );
});

test('CLI rejects ambiguous duplicate manifest arguments and invalid manifest JSON', async () => {
  const specPath = path.join(temporaryDirectory, 'argument-openapi.json');
  const configPath = path.join(temporaryDirectory, 'argument-gateway.config.json');
  const manifestPath = path.join(temporaryDirectory, 'argument-manifest.json');
  await Promise.all([
    writeFile(specPath, JSON.stringify(openApi({
      '/read': { get: { operationId: 'read_default' } },
    }))),
    writeFile(configPath, serializeGatewayConfig(config())),
    writeFile(manifestPath, '{'),
  ]);
  const arguments_ = [
    TOOL,
    '--spec', specPath,
    '--config', configPath,
    '--source', 'synthetic-read',
    '--method', 'GET',
  ];

  await assert.rejects(
    execFileAsync(process.execPath, [
      ...arguments_,
      '--manifest', manifestPath,
      '--manifest', manifestPath,
      '--check',
    ], { cwd: ROOT, encoding: 'utf8' }),
    (error) => error.code === 1 && /argument_duplicate/u.test(error.stderr),
  );
  await assert.rejects(
    execFileAsync(process.execPath, [
      ...arguments_,
      '--manifest', manifestPath,
      '--check',
    ], { cwd: ROOT, encoding: 'utf8' }),
    (error) => error.code === 1 && /manifest_json_invalid/u.test(error.stderr),
  );
});

test('never emits a secret-bearing or otherwise invalid gateway config', () => {
  const input = config();
  input.sources[0].authentication.token = 'synthetic-placeholder';
  assert.throws(
    () => mergeEnabledTools(input, 'synthetic-read', ['read_alpha']),
    (error) => error instanceof OpenApiEnabledToolsError &&
      error.code === 'gateway_config_invalid' &&
      !error.message.includes('synthetic-placeholder'),
  );
});
