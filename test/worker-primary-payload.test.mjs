import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, sign } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';
import * as v from 'valibot';

import worker, { AdminState } from '../payload/worker/index.js';
import {
  APPROVED_CLOUDFLARE_CONTRACT,
  RELEASE_ENVELOPE_SCHEMA_VERSION,
  RELEASE_SIGNATURE_CONTEXT,
  REQUIRED_OAUTH_SCOPES,
  releaseSignatureCanonicalJson,
} from '../apps/installer/scripts/sign-gateway-release.mjs';
import {
  ACCOUNT_ID,
  BOOTSTRAP_NONCE,
  CONFIGURATION_HASH,
  DESIRED_HASH,
  DURABLE_OBJECT_NAME,
  GATEWAY_NAME,
  HOSTNAME,
  INSTALLATION_ID,
  MANAGED_OAUTH,
  RELEASE_SHA256,
  RESOURCE_ORDER,
  PORTAL_RESOURCE_ORDER,
  bootstrapRequest,
  canonicalJson,
  cloudflareProvider,
  goldenClaim as claim,
  hmac as signWith,
  installReadyGateway,
  maximumBootstrapClaim,
  prefixedSha256,
  portalOnlyClaim,
  primaryEnvironment as environment,
  withProviderFetch,
  BOOTSTRAP_NONCE_BYTES,
} from './payload-lifecycle.mjs';

const hmac = (rawBody) => signWith(rawBody, BOOTSTRAP_NONCE_BYTES);

const MANAGEMENT_SOURCES_KEY = 'ankka-mcp-gateway/management-sources/v1';
const MANAGEMENT_SOURCES_LIMIT_BYTES = 1024 * 1024;
const DURABLE_OBJECT_ENTRY_LIMIT_BYTES = 2 * 1024 * 1024;

function canonicalByteLength(value) {
  return Buffer.byteLength(canonicalJson(value));
}

function aggregateToolNames(length = 128, extraCharacters = 0) {
  return Array.from({ length: 500 }, (_value, index) => (
    `boundary_${String(index).padStart(3, '0')}_`.padEnd(
      length + (index < extraCharacters ? 1 : 0),
      'x',
    )
  ));
}

function aggregateManagedSource(index, enabledTools) {
  return {
    id: `source-${index.toString(16).padStart(16, '0')}`,
    label: `Source ${index}`,
    url: `https://source-${index}.example.com/mcp`,
    authMode: 'none',
    onBehalfOfUser: false,
    enabledTools,
    status: 'draft',
  };
}

function aggregateManagementSources(sources, revision = sources.length) {
  return { schemaVersion: 1, revision, applyMode: 'oauth_per_action', sources };
}

function aggregateInstalledProjection(record) {
  return {
    ...record,
    revision: Number.MAX_SAFE_INTEGER,
    sources: record.sources.map((source) => ({ ...source, status: 'installed' })),
  };
}

function platformBoundedStorage(initialEntries = []) {
  const values = new Map(initialEntries.map(([key, value]) => [key, structuredClone(value)]));
  const stats = { writeAttempts: 0, platformRejections: 0 };
  return {
    stats,
    async get(key) {
      const value = values.get(key);
      return value === undefined ? undefined : structuredClone(value);
    },
    async put(key, value) {
      stats.writeAttempts += 1;
      const entryBytes = Buffer.byteLength(key) + canonicalByteLength(value);
      if (entryBytes > DURABLE_OBJECT_ENTRY_LIMIT_BYTES) {
        stats.platformRejections += 1;
        throw new TypeError('synthetic_durable_object_entry_limit');
      }
      values.set(key, structuredClone(value));
    },
    snapshot(key) {
      const value = values.get(key);
      return value === undefined ? undefined : structuredClone(value);
    },
  };
}

const UPDATE_COMPONENTS = Object.freeze([
  ['admin', 'admin'],
  ['installer', 'installer'],
  ['worker', 'worker'],
  ['workerCleanup', 'worker-cleanup'],
  ['workerRetirement', 'worker-retirement'],
]);

function updateContentType(component, filePath) {
  if (filePath.endsWith('.html')) return 'text/html; charset=utf-8';
  if (filePath.endsWith('.css')) return 'text/css; charset=utf-8';
  if (filePath.endsWith('.txt')) return 'text/plain; charset=utf-8';
  return component === 'admin' || component === 'installer'
    ? 'text/javascript; charset=utf-8'
    : 'application/javascript+module';
}

function updateComponentRoot(component, directory) {
  return component === 'admin'
    ? new URL('../apps/admin/dist/', import.meta.url)
    : new URL(`../payload/${directory}/`, import.meta.url);
}

async function signedUpdateChannel(
  release = 'gateway-v0.1.1',
  channel = 'canary',
  controlPlaneOrigin = 'https://deploy.ankka.ai',
) {
  const components = {};
  const allFiles = [];
  for (const [name, directory] of UPDATE_COMPONENTS) {
    const sourceRoot = updateComponentRoot(name, directory);
    const files = [];
    const visit = async (relative = '') => {
      const root = new URL(relative, sourceRoot);
      const entries = await readdir(root, { withFileTypes: true });
      entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
      for (const entry of entries) {
        const child = relative ? `${relative}/${entry.name}` : entry.name;
        if (entry.isDirectory()) await visit(child);
        else {
          const bytes = await readFile(new URL(child, sourceRoot));
          files.push(Object.freeze({
            byteSize: bytes.byteLength,
            contentType: updateContentType(name, child),
            path: `payload/${directory}/${child}`,
            sha256: createHash('sha256').update(bytes).digest('hex'),
          }));
        }
      }
    };
    await visit();
    files.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
    components[name] = Object.freeze({
      byteSize: files.reduce((total, file) => total + file.byteSize, 0),
      fileCount: files.length,
      files: Object.freeze(files),
      treeSha256: createHash('sha256').update(canonicalJson(files)).digest('hex'),
    });
    allFiles.push(...files);
  }
  allFiles.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  const manifest = Object.freeze({
    artifact: Object.freeze({
      byteSize: allFiles.reduce((total, file) => total + file.byteSize, 0),
      fileCount: allFiles.length,
      treeSha256: createHash('sha256').update(canonicalJson(allFiles)).digest('hex'),
    }),
    cloudflare: APPROVED_CLOUDFLARE_CONTRACT,
    controlPlaneOrigin,
    components: Object.freeze(components),
    oauthScopeIds: REQUIRED_OAUTH_SCOPES,
    release,
    schemaVersion: 1,
    sourceCommit: 'b'.repeat(40),
  });
  const serialized = canonicalJson(manifest);
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const rawPublicKey = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url');
  return Object.freeze({
    publicKey: rawPublicKey,
    body: Object.freeze({
      schemaVersion: 1,
      channel,
      release: Object.freeze({
        id: release,
        artifactSha256: `sha256:${manifest.artifact.treeSha256}`,
        sourceCommit: manifest.sourceCommit,
      }),
      classification: Object.freeze({
        kind: 'normal', updaterProtocol: 2,
        changes: Object.freeze(['customer_worker_code', 'management_assets']),
        excludes: Object.freeze([
          'access_policies', 'credentials', 'dns', 'durable_object_migrations',
          'mcp_portal_configuration', 'sources', 'tool_allowlists',
        ]),
      }),
      notes: Object.freeze(['Signed runtime update fixture.']),
      verification: Object.freeze({
        algorithm: 'ed25519', channel, keyId: 'test-update-key', manifest: serialized,
        schemaVersion: RELEASE_ENVELOPE_SCHEMA_VERSION,
        signature: sign(null, Buffer.from(releaseSignatureCanonicalJson(
          channel,
          'test-update-key',
          serialized,
        )), privateKey).toString('base64url'),
        signatureContext: RELEASE_SIGNATURE_CONTEXT,
      }),
    }),
  });
}

async function accessAssertion(email, issuer, audience, privateKey, kid) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const now = Math.floor(Date.now() / 1_000);
  const header = encode({ alg: 'RS256', kid, typ: 'JWT' });
  const payload = encode({ iss: issuer, aud: [audience], email, nbf: now - 1, exp: now + 300 });
  const signature = new Uint8Array(await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5', privateKey, new TextEncoder().encode(`${header}.${payload}`),
  ));
  return `${header}.${payload}.${Buffer.from(signature).toString('base64url')}`;
}

test('primary payload has the exact dependency-free Worker export and layout', async () => {
  const entries = await readdir(new URL('../payload/worker/', import.meta.url));
  assert.deepEqual(entries, ['index.js']);
  assert.equal(v.is(v.function(), AdminState), true);
  assert.equal(v.is(v.function(), worker.fetch), true);
  const source = await readFile(new URL('../payload/worker/index.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /\b(?:console|eval|WebSocket)\b/u);
  assert.doesNotMatch(source, /sourceMappingURL\s*=/iu);
  assert.match(source, /export class AdminState/u);
  assert.match(source, /export default/u);
});

test('bounded provider reads cover the independent 32-source and 500-tool response ceilings', async () => {
  const maxLengthName = (sourceIndex, toolIndex) => (
    `tool_${String(sourceIndex).padStart(2, '0')}_${String(toolIndex).padStart(3, '0')}_`.padEnd(128, 'x')
  );
  const servers = Array.from({ length: 32 }, (_source, sourceIndex) => ({
    server_id: `server_${String(sourceIndex).padStart(2, '0')}_`.padEnd(128, 'a'),
    default_disabled: true,
    on_behalf: false,
    updated_tools: Array.from({ length: 500 }, (_tool, toolIndex) => ({
      name: maxLengthName(sourceIndex, toolIndex),
      enabled: true,
    })),
  }));
  const envelope = JSON.stringify({
    success: true,
    errors: [],
    messages: [],
    result: {
      id: 'p'.repeat(128),
      name: 'n'.repeat(128),
      hostname: `${'h'.repeat(63)}.${'h'.repeat(63)}.${'h'.repeat(63)}.${'h'.repeat(61)}`,
      description: 'd'.repeat(256),
      code_mode: 'default_on',
      secure_web_gateway: false,
      servers,
    },
  });
  const bytes = Buffer.byteLength(envelope);
  assert.ok(bytes > 64 * 1024, 'the fixture must catch the former 64 KiB incompatibility');
  assert.ok(bytes < 3 * 1024 * 1024, 'the schema-shaped response should retain at least 1 MiB of headroom');

  const [primarySource, cleanupSource] = await Promise.all([
    readFile(new URL('../payload/worker/index.js', import.meta.url), 'utf8'),
    readFile(new URL('../payload/worker-cleanup/index.js', import.meta.url), 'utf8'),
  ]);
  for (const source of [primarySource, cleanupSource]) {
    assert.match(source, /const PROVIDER_RESPONSE_LIMIT_BYTES = 4 \* 1024 \* 1024;/u);
  }
});

test('primary provider reads accept a streamed response above the former 64 KiB cap', async () => {
  let injectedBytes = 0;
  const provider = cloudflareProvider({
    onRequest: ({ request, state }) => {
      const url = new URL(request.url);
      if (injectedBytes === 0 && request.method === 'GET' && state.server &&
          url.pathname.endsWith(`/mcp/servers/${state.server.id}`)) {
        const serialized = JSON.stringify({
          success: true,
          errors: [],
          messages: [],
          result: { ...state.server, padding: 'x'.repeat(2_500_000) },
        });
        injectedBytes = Buffer.byteLength(serialized);
        return new Response(serialized, {
          headers: { 'content-type': 'application/json; charset=utf-8' },
        });
      }
      return undefined;
    },
  });
  await installReadyGateway({ provider });
  assert.ok(injectedBytes > 64 * 1024);
  assert.ok(injectedBytes < 4 * 1024 * 1024);
});

test('primary provider reads cancel a 4 MiB+1 response before any provider mutation', async () => {
  let cancelled = false;
  const provider = cloudflareProvider({
    onRequest: ({ request }) => request.method === 'GET'
      ? new Response(new ReadableStream({ cancel() { cancelled = true; } }), {
        headers: {
          'content-type': 'application/json',
          'content-length': String((4 * 1024 * 1024) + 1),
        },
      })
      : undefined,
  });
  const response = await withProviderFetch(provider.fetch, async () => (
    worker.fetch(await bootstrapRequest(), environment())
  ));
  assert.equal(response.status, 409);
  assert.equal(cancelled, true);
  assert.equal(provider.posts().length, 0);
  assert.equal(provider.requests.some(({ method }) => method === 'DELETE'), false);
});

test('management source state preserves legacy OAuth intent and explicit shared connections', async () => {
  const storage = platformBoundedStorage([[MANAGEMENT_SOURCES_KEY, {
    schemaVersion: 1,
    revision: 3,
    applyMode: 'oauth_per_action',
    sources: [{
      id: 'source-1111111111111111',
      label: 'Legacy protected source',
      url: 'https://legacy-protected.example.com/mcp',
      authMode: 'oauth',
      enabledTools: ['legacy_read'],
      status: 'installed',
    }, {
      id: 'source-2222222222222222',
      label: 'Operator-connected source',
      url: 'https://operator-connected.example.com/mcp',
      authMode: 'oauth',
      onBehalfOfUser: false,
      enabledTools: ['shared_read'],
      status: 'installed',
    }, {
      id: 'source-3333333333333333',
      label: 'Legacy public source',
      url: 'https://public.example.com/mcp',
      enabledTools: ['public_read'],
      status: 'installed',
    }],
  }]]);
  const state = new AdminState({ storage }, {});
  const response = await state.fetch(new Request('https://admin-state.invalid/sources'));
  assert.equal(response.status, 200);
  const record = await response.json();
  assert.deepEqual(
    record.sources.map(({ authMode, onBehalfOfUser }) => ({ authMode, onBehalfOfUser })),
    [
      { authMode: 'oauth', onBehalfOfUser: true },
      { authMode: 'oauth', onBehalfOfUser: false },
      { authMode: 'none', onBehalfOfUser: false },
    ],
  );

  await storage.put(MANAGEMENT_SOURCES_KEY, {
    ...record,
    sources: [{ ...record.sources[2], onBehalfOfUser: true }],
  });
  const invalid = await state.fetch(new Request('https://admin-state.invalid/sources'));
  assert.equal(invalid.status, 503);
});

test('management source state enforces the canonical 1 MiB aggregate before the Durable Object entry limit', async () => {
  const maximumTools = aggregateToolNames();
  const retainedSources = Array.from(
    { length: 15 },
    (_value, index) => aggregateManagedSource(index, maximumTools),
  );
  const retained = aggregateManagementSources(retainedSources, 15);
  const exactTools = aggregateToolNames(123, 222);
  const overTools = aggregateToolNames(123, 223);
  const storedOverTools = aggregateToolNames(123, 301);
  const exactRecord = aggregateManagementSources([
    ...retainedSources,
    aggregateManagedSource(15, exactTools),
  ], 16);
  const overRecord = aggregateManagementSources([
    ...retainedSources,
    aggregateManagedSource(15, overTools),
  ], 16);
  const storedOverRecord = aggregateManagementSources([
    ...retainedSources,
    aggregateManagedSource(15, storedOverTools),
  ], 16);
  assert.ok(canonicalByteLength(retained) < MANAGEMENT_SOURCES_LIMIT_BYTES);
  assert.equal(
    canonicalByteLength(aggregateInstalledProjection(exactRecord)),
    MANAGEMENT_SOURCES_LIMIT_BYTES,
  );
  assert.equal(
    canonicalByteLength(aggregateInstalledProjection(overRecord)),
    MANAGEMENT_SOURCES_LIMIT_BYTES + 1,
  );
  assert.equal(canonicalByteLength(storedOverRecord), MANAGEMENT_SOURCES_LIMIT_BYTES + 1);

  const platformProbe = platformBoundedStorage();
  const platformOversized = aggregateManagementSources(Array.from(
    { length: 32 },
    (_value, index) => aggregateManagedSource(index, maximumTools),
  ), 32);
  assert.ok(
    Buffer.byteLength(MANAGEMENT_SOURCES_KEY) + canonicalByteLength(platformOversized) >
      DURABLE_OBJECT_ENTRY_LIMIT_BYTES,
  );
  await assert.rejects(
    platformProbe.put(MANAGEMENT_SOURCES_KEY, platformOversized),
    /synthetic_durable_object_entry_limit/u,
  );
  assert.deepEqual(platformProbe.stats, { writeAttempts: 1, platformRejections: 1 });

  const saveRequest = (revision, enabledTools) => new Request('https://admin-state.invalid/sources', {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: canonicalJson({
      schemaVersion: 1,
      revision,
      source: {
        label: 'Source 15',
        url: 'https://source-15.example.com/mcp',
        authMode: 'none',
        enabledTools,
      },
    }),
  });

  const exactStorage = platformBoundedStorage([[MANAGEMENT_SOURCES_KEY, retained]]);
  const exactState = new AdminState({ storage: exactStorage }, {});
  const exactResponse = await exactState.fetch(saveRequest(15, exactTools));
  assert.equal(exactResponse.status, 200, await exactResponse.clone().text());
  assert.deepEqual(exactStorage.stats, { writeAttempts: 1, platformRejections: 0 });
  assert.equal(
    canonicalByteLength(aggregateInstalledProjection(exactStorage.snapshot(MANAGEMENT_SOURCES_KEY))),
    MANAGEMENT_SOURCES_LIMIT_BYTES,
  );
  const exactRead = await exactState.fetch(new Request('https://admin-state.invalid/sources'));
  assert.equal(exactRead.status, 200);
  const installedProjection = aggregateInstalledProjection(
    exactStorage.snapshot(MANAGEMENT_SOURCES_KEY),
  );
  await exactStorage.put(MANAGEMENT_SOURCES_KEY, installedProjection);
  const installedRead = await exactState.fetch(new Request('https://admin-state.invalid/sources'));
  assert.equal(installedRead.status, 200);
  assert.equal(canonicalByteLength(await installedRead.clone().json()), MANAGEMENT_SOURCES_LIMIT_BYTES);
  assert.deepEqual(exactStorage.stats, { writeAttempts: 2, platformRejections: 0 });

  const overStorage = platformBoundedStorage([[MANAGEMENT_SOURCES_KEY, retained]]);
  const overState = new AdminState({ storage: overStorage }, {});
  const overResponse = await overState.fetch(saveRequest(15, overTools));
  assert.equal(overResponse.status, 413);
  assert.deepEqual(await overResponse.json(), {
    schemaVersion: 1,
    error: 'source_capacity_exceeded',
    revision: 15,
  });
  assert.deepEqual(overStorage.stats, { writeAttempts: 0, platformRejections: 0 });
  assert.equal(canonicalJson(overStorage.snapshot(MANAGEMENT_SOURCES_KEY)), canonicalJson(retained));

  const invalidStorage = platformBoundedStorage([[MANAGEMENT_SOURCES_KEY, storedOverRecord]]);
  const invalidState = new AdminState({ storage: invalidStorage }, {});
  const invalidRead = await invalidState.fetch(new Request('https://admin-state.invalid/sources'));
  assert.equal(invalidRead.status, 503);
  assert.deepEqual(await invalidRead.json(), { schemaVersion: 1, error: 'sources_unavailable' });
  assert.deepEqual(invalidStorage.stats, { writeAttempts: 0, platformRejections: 0 });

  const gateway = await installReadyGateway();
  const managementStorage = gateway.env.ADMIN_STATE.objects.get('v1:management').storage;
  await managementStorage.put(MANAGEMENT_SOURCES_KEY, exactRecord);
  const management = gateway.env.ADMIN_STATE.get(
    gateway.env.ADMIN_STATE.idFromName('v1:management'),
  );
  const source = exactRecord.sources.at(-1);
  const actionId = `action_${'C'.repeat(32)}`;
  const issuedAt = Date.now();
  const expiresAt = issuedAt + 10 * 60 * 1000;
  const prepared = await management.fetch(new Request('https://admin-state.invalid/source-actions', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: canonicalJson({
      schemaVersion: 1,
      actionId,
      sourceId: source.id,
      sourceRevision: exactRecord.revision,
      actorEmail: 'admin@example.com',
      issuedAt,
      expiresAt,
      actionKeyHash: await prefixedSha256(BOOTSTRAP_NONCE),
      sourceHash: await prefixedSha256({
        id: source.id,
        label: source.label,
        url: source.url,
        authMode: source.authMode,
        onBehalfOfUser: source.onBehalfOfUser,
        enabledTools: source.enabledTools,
      }),
    }),
  }));
  assert.equal(prepared.status, 200, await prepared.clone().text());

  const legacyUnsafeRecord = structuredClone(exactRecord);
  legacyUnsafeRecord.sources[0].label += 'x';
  assert.ok(canonicalByteLength(legacyUnsafeRecord) < MANAGEMENT_SOURCES_LIMIT_BYTES);
  assert.equal(
    canonicalByteLength(aggregateInstalledProjection(legacyUnsafeRecord)),
    MANAGEMENT_SOURCES_LIMIT_BYTES + 1,
  );
  await managementStorage.put(MANAGEMENT_SOURCES_KEY, legacyUnsafeRecord);
  const unsafeSource = legacyUnsafeRecord.sources.at(-2);
  const prepareWrites = managementStorage.writes.length;
  const unsafePrepare = await management.fetch(new Request(
    'https://admin-state.invalid/source-actions',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: canonicalJson({
        schemaVersion: 1,
        actionId: `action_${'D'.repeat(32)}`,
        sourceId: unsafeSource.id,
        sourceRevision: legacyUnsafeRecord.revision,
        actorEmail: 'admin@example.com',
        issuedAt,
        expiresAt,
        actionKeyHash: await prefixedSha256(BOOTSTRAP_NONCE),
        sourceHash: await prefixedSha256({
          id: unsafeSource.id,
          label: unsafeSource.label,
          url: unsafeSource.url,
          authMode: unsafeSource.authMode,
          onBehalfOfUser: unsafeSource.onBehalfOfUser,
          enabledTools: unsafeSource.enabledTools,
        }),
      }),
    },
  ));
  assert.equal(unsafePrepare.status, 409);
  assert.deepEqual(await unsafePrepare.json(), {
    schemaVersion: 1, error: 'source_action_conflict',
  });
  assert.equal(managementStorage.writes.length, prepareWrites);

  const exhaustedRevisionRecord = { ...exactRecord, revision: Number.MAX_SAFE_INTEGER };
  await managementStorage.put(MANAGEMENT_SOURCES_KEY, exhaustedRevisionRecord);
  const revisionWrites = managementStorage.writes.length;
  const exhaustedPrepare = await management.fetch(new Request(
    'https://admin-state.invalid/source-actions',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: canonicalJson({
        schemaVersion: 1,
        actionId: `action_${'E'.repeat(32)}`,
        sourceId: unsafeSource.id,
        sourceRevision: Number.MAX_SAFE_INTEGER,
        actorEmail: 'admin@example.com',
        issuedAt,
        expiresAt,
        actionKeyHash: await prefixedSha256(BOOTSTRAP_NONCE),
        sourceHash: await prefixedSha256({
          id: unsafeSource.id,
          label: unsafeSource.label,
          url: unsafeSource.url,
          authMode: unsafeSource.authMode,
          onBehalfOfUser: unsafeSource.onBehalfOfUser,
          enabledTools: unsafeSource.enabledTools,
        }),
      }),
    },
  ));
  assert.equal(exhaustedPrepare.status, 409);
  assert.equal(managementStorage.writes.length, revisionWrites);

  await managementStorage.put(MANAGEMENT_SOURCES_KEY, legacyUnsafeRecord);
  const actionBody = canonicalJson({
    schemaVersion: 1,
    actionId,
    actionKey: BOOTSTRAP_NONCE,
    actorEmail: 'admin@example.com',
    accountId: ACCOUNT_ID,
    issuedAt,
    expiresAt,
    cloudflareAccessToken: 'ephemeral-capacity-guard-grant',
  });
  const actionSignature = `sha256=${createHmac(
    'sha256', Buffer.from(BOOTSTRAP_NONCE, 'base64url'),
  ).update(actionBody).digest('hex')}`;
  const providerRequests = gateway.provider.requests.length;
  const storageWrites = managementStorage.writes.length;
  const rejectedApply = await withProviderFetch(gateway.provider.fetch, () => worker.fetch(new Request(
    'https://ankka-gateway-test.tenant.workers.dev/__ankka/source-action',
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-ankka-source-action-signature': actionSignature,
      },
      body: actionBody,
    },
  ), gateway.env));
  assert.equal(rejectedApply.status, 400);
  assert.deepEqual(await rejectedApply.json(), {
    schemaVersion: 1, error: 'source_action_rejected', retryable: false,
  });
  assert.equal(gateway.provider.requests.length, providerRequests);
  assert.equal(managementStorage.writes.length, storageWrites);
});

test('bootstrap validates the private golden claim, explicitly creates seven resources, and stores an exact ready receipt', async () => {
  const { env, provider: cloudflare, body: result, storage } = await installReadyGateway();
  assert.deepEqual({
    installationId: result.installationId,
    configurationHash: result.configurationHash,
    desiredHash: result.desiredHash,
    resourceCount: result.receipt.resourceCount,
    status: result.status,
    applyInvoked: result.applyInvoked,
    resumed: result.resumed,
  }, {
    installationId: INSTALLATION_ID,
    configurationHash: CONFIGURATION_HASH,
    desiredHash: DESIRED_HASH,
    resourceCount: 7,
    status: 'ready',
    applyInvoked: true,
    resumed: false,
  });
  assert.match(result.approvedPlanId, /^plan-[a-f0-9]{24}$/u);
  assert.equal(result.receipt.evidence.resources.length, 7);
  assert.deepEqual(result.receipt.evidence.resources.map(({ kind }) => kind), RESOURCE_ORDER);
  assert.equal(result.receipt.evidence.pending, null);
  const { checksum, ...unsigned } = result.receipt.evidence;
  assert.equal(checksum, `sha256:${createHash('sha256').update(canonicalJson(unsigned)).digest('hex')}`);
  assert.doesNotMatch(JSON.stringify(result), /synthetic-cloudflare-grant-never-store/u);
  assert.deepEqual(storage.snapshot(), result.receipt.evidence);

  // Every resource, including both Access applications, exists because the
  // Worker created it with the canary-proven request shape.
  const posts = cloudflare.posts();
  assert.equal(posts.length, 7);
  const resources = Object.fromEntries(result.receipt.evidence.resources.map((resource) => [resource.kind, resource]));
  const serverId = resources.mcp_server.provider.id;
  assert.deepEqual(posts[1].body, {
    name: resources.source_access_application.marker,
    type: 'mcp',
    destinations: [{ type: 'via_mcp_server_portal', mcp_server_id: serverId }],
  });
  assert.deepEqual(posts[4].body, {
    name: GATEWAY_NAME,
    type: 'mcp_portal',
    domain: HOSTNAME,
    destinations: [{ type: 'public', uri: HOSTNAME }],
    oauth_configuration: MANAGED_OAUTH,
  });
  assert.equal(resources.source_access_application.provider.id, 'a'.repeat(32));
  assert.equal(resources.portal_access_application.provider.id, 'b'.repeat(32));
  assert.equal(resources.source_access_policy.provider.parentId, 'a'.repeat(32));
  assert.equal(resources.portal_access_policy.provider.parentId, 'b'.repeat(32));
  assert.deepEqual([...cloudflare.state.apps.keys()], ['a'.repeat(32), 'b'.repeat(32)]);
  assert.equal(cloudflare.liveResourceCount(), 7);

  // Each create was journaled as send_armed before the provider write and the
  // grant/nonce never reached storage.
  const journal = storage.writes.map(({ value }) => value.pending?.phase ?? value.status ?? value.state);
  assert.equal(journal.filter((phase) => phase === 'send_armed').length, 7);
  assert.equal(journal.filter((phase) => phase === 'submitted').length, 7);
  assert.equal(journal.at(-1), 'ready');
  const persisted = JSON.stringify(storage.writes);
  assert.doesNotMatch(persisted, /synthetic-cloudflare-grant-never-store/u);
  assert.equal(persisted.includes(BOOTSTRAP_NONCE), false);

  const repeated = await withProviderFetch(cloudflare.fetch, async () => (
    worker.fetch(await bootstrapRequest(claim('B'.repeat(22))), env)
  ));
  assert.equal(repeated.status, 200);
  assert.deepEqual(await repeated.json(), { ...result, applyInvoked: false, resumed: true });
  assert.equal(cloudflare.posts().length, 7);
  assert.deepEqual([...env.ADMIN_STATE.objects.keys()].sort(), [DURABLE_OBJECT_NAME, 'v1:management']);
  assert.equal(env.ADMIN_STATE.objects.get('v1:management').storage.snapshot(), undefined);
});

test('bootstrap accepts its maximum valid canonical envelope and cancels limit+1 bodies', async () => {
  const maximumClaim = await maximumBootstrapClaim();
  const maximumBody = canonicalJson(maximumClaim);
  const maximumBytes = Buffer.byteLength(maximumBody);
  assert.ok(maximumBytes > 96 * 1024, 'the fixture must catch the former bootstrap request cap');
  assert.ok(maximumBytes < 128 * 1024, 'the maximum valid envelope must fit the dedicated cap');
  assert.equal(maximumClaim.settings.sources[0].enabledTools.length, 500);
  assert.equal(maximumClaim.settings.sources[0].enabledTools.every((tool) => tool.length === 128), true);
  assert.equal(maximumClaim.settings.access.memberEmails.length, 50);
  assert.equal(maximumClaim.settings.sources[0].url.length, 2048);
  assert.equal(maximumClaim.cloudflareAccessToken.length, 16 * 1024);
  await installReadyGateway({
    claimInput: maximumClaim,
    environmentBindings: {
      CLOUDFLARE_ZONE_NAME: maximumClaim.target.zoneName,
      ANKKA_GATEWAY_RELEASE: maximumClaim.release.id,
    },
  });

  let cancelled = false;
  const oversized = new Request('https://worker.tenant.workers.dev/__ankka/bootstrap', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'content-length': String((128 * 1024) + 1),
      'x-ankka-bootstrap-signature': `sha256=${'0'.repeat(64)}`,
    },
    body: new ReadableStream({ cancel() { cancelled = true; } }),
    duplex: 'half',
  });
  const cloudflare = cloudflareProvider();
  const response = await withProviderFetch(cloudflare.fetch, () => (
    worker.fetch(oversized, environment())
  ));
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    schemaVersion: 1, error: 'bootstrap_rejected', retryable: false,
  });
  assert.equal(cancelled, true);
  assert.equal(cloudflare.requests.length, 0);
});

test('bootstrap creates a real empty Portal without placeholder source resources', async () => {
  const portalClaim = await portalOnlyClaim();
  const { provider: cloudflare, body: result, storage } = await installReadyGateway({
    claimInput: portalClaim,
  });

  assert.equal(portalClaim.expected.installationId, INSTALLATION_ID);
  assert.equal(result.status, 'ready');
  assert.equal(result.receipt.resourceCount, 4);
  assert.equal(result.receipt.revision, 5);
  assert.deepEqual(result.receipt.evidence.resources.map(({ kind }) => kind), PORTAL_RESOURCE_ORDER);
  assert.equal(result.receipt.evidence.resources.some(({ kind }) => kind === 'mcp_server'), false);
  assert.deepEqual(storage.snapshot(), result.receipt.evidence);
  assert.equal(cloudflare.liveResourceCount(), 4);
  assert.equal(cloudflare.state.server, null);

  const posts = cloudflare.posts();
  assert.equal(posts.length, 4);
  assert.equal(posts[0].pathname.endsWith('/mcp/portals'), true);
  assert.equal(Object.hasOwn(posts[0].body, 'servers'), false);
  assert.equal(posts[1].body.type, 'mcp_portal');
  assert.deepEqual([...cloudflare.state.apps.keys()], ['a'.repeat(32)]);
});

test('bootstrap rejects noncanonical, tampered, browser-authorized, and malformed requests before provider I/O', async () => {
  const env = environment();
  const cloudflare = cloudflareProvider();
  await withProviderFetch(cloudflare.fetch, async () => {
    const input = claim();
    const pretty = JSON.stringify(input, null, 2);
    const cases = [
      new Request('https://worker.tenant.workers.dev/__ankka/bootstrap', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-ankka-bootstrap-signature': await hmac(pretty) },
        body: pretty,
      }),
      new Request('https://worker.tenant.workers.dev/__ankka/bootstrap', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-ankka-bootstrap-signature': 'sha256=' + '0'.repeat(64) },
        body: canonicalJson(input),
      }),
      new Request('https://worker.tenant.workers.dev/__ankka/bootstrap', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-ankka-bootstrap-signature': await hmac(canonicalJson(input)),
          origin: 'https://browser.example',
        },
        body: canonicalJson(input),
      }),
    ];
    for (const request of cases) {
      const response = await worker.fetch(request, env);
      assert.equal(response.status, 400);
      assert.deepEqual(await response.json(), {
        schemaVersion: 1, error: 'bootstrap_rejected', retryable: false,
      });
    }
    assert.equal(cloudflare.requests.length, 0);
  });
});

test('bootstrap fails closed when the created Portal application does not expose the exact Managed OAuth contract', async () => {
  const env = environment();
  const cloudflare = cloudflareProvider({ stripOauth: true });
  await withProviderFetch(cloudflare.fetch, async () => {
    const response = await worker.fetch(await bootstrapRequest(), env);
    assert.equal(response.status, 409);
    assert.deepEqual(await response.json(), {
      schemaVersion: 1,
      error: 'bootstrap_requires_repair',
      retryable: false,
    });
  });
  // The incompatible application is never mutated into shape; no later gateway
  // resource is created and the install stays in its journaled state.
  assert.equal(cloudflare.posts().length, 5);
  assert.equal(cloudflare.requests.filter(({ method }) => !['GET', 'POST'].includes(method)).length, 0);
  assert.equal([...cloudflare.policies().values()].flat().length, 1);
  assert.equal(cloudflare.state.dns, null);
  const storage = env.ADMIN_STATE.objects.get(DURABLE_OBJECT_NAME).storage;
  assert.equal(storage.snapshot().status, 'installing');
  assert.deepEqual(storage.snapshot().pending, {
    kind: 'portal_access_application',
    key: storage.snapshot().pending.key,
    requestId: 'A'.repeat(22),
    phase: 'submitted',
  });
});

test('bootstrap fails closed when a foreign Access application already claims the Portal hostname', async () => {
  const env = environment();
  const cloudflare = cloudflareProvider({
    foreignApps: [{
      id: 'g'.repeat(32),
      type: 'mcp_portal',
      name: GATEWAY_NAME,
      domain: HOSTNAME,
      destinations: [{ type: 'public', uri: HOSTNAME }],
      oauth_configuration: MANAGED_OAUTH,
    }],
  });
  await withProviderFetch(cloudflare.fetch, async () => {
    const response = await worker.fetch(await bootstrapRequest(), env);
    assert.equal(response.status, 409);
    assert.deepEqual(await response.json(), {
      schemaVersion: 1, error: 'bootstrap_requires_repair', retryable: false,
    });
  });
  // The look-alike is never adopted: no Portal application POST, no Portal
  // policy, no DNS, and the foreign application is untouched.
  const appPosts = cloudflare.posts().filter(({ pathname }) => pathname.endsWith('/access/apps'));
  assert.equal(appPosts.length, 1);
  assert.equal(appPosts[0].body.type, 'mcp');
  assert.ok(cloudflare.state.apps.has('g'.repeat(32)));
  assert.deepEqual(cloudflare.policies().get('g'.repeat(32)), []);
  assert.equal(cloudflare.state.dns, null);
  assert.equal(cloudflare.deletes().length, 0);
});

test('bootstrap fails closed when Cloudflare generates a source application for the MCP server', async () => {
  const env = environment();
  let generated = false;
  const cloudflare = cloudflareProvider({
    onRequest: ({ request, state }) => {
      if (!generated && state.server && new URL(request.url).pathname.endsWith('/access/apps') &&
          request.method === 'GET') {
        generated = true;
        state.apps.set('g'.repeat(32), {
          id: 'g'.repeat(32),
          type: 'mcp',
          name: 'Generated source application',
          destinations: [{ type: 'via_mcp_server_portal', mcp_server_id: state.server.id }],
        });
        state.policies.set('g'.repeat(32), []);
      }
      return undefined;
    },
  });
  await withProviderFetch(cloudflare.fetch, async () => {
    const response = await worker.fetch(await bootstrapRequest(), env);
    assert.equal(response.status, 409);
    assert.deepEqual(await response.json(), {
      schemaVersion: 1, error: 'bootstrap_requires_repair', retryable: false,
    });
  });
  assert.equal(cloudflare.posts().length, 1);
  assert.equal(cloudflare.posts()[0].pathname.endsWith('/mcp/servers'), true);
  assert.equal(cloudflare.deletes().length, 0);
  assert.deepEqual([...cloudflare.state.apps.keys()], ['g'.repeat(32)]);
});

test('management status requires a verified Access JWT and exposes no provider or receipt internals', async () => {
  const { env, provider: cloudflare } = await installReadyGateway();
  const originalFetch = globalThis.fetch;
  try {
    const denied = await worker.fetch(new Request('https://manage.example.com/api/status'), env);
    assert.equal(denied.status, 401);

    const keys = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    );
    const kid = 'test-access-key';
    const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
    const assertion = await accessAssertion(
      'admin@example.com', env.CF_ACCESS_ISSUER, env.CF_ACCESS_AUD, keys.privateKey, kid,
    );
    globalThis.fetch = async (request) => {
      const url = new URL(request.url);
      if (url.href === `${env.CF_ACCESS_ISSUER}/cdn-cgi/access/certs`) {
        return new Response(JSON.stringify({ keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] }), {
          headers: { 'content-type': 'application/json; charset=utf-8' },
        });
      }
      return cloudflare.fetch(request);
    };
    const response = await worker.fetch(new Request('https://manage.example.com/api/status', {
      headers: {
        'cf-access-authenticated-user-email': 'admin@example.com',
        'cf-access-jwt-assertion': assertion,
      },
    }), env);
    assert.equal(response.status, 200);
    const status = await response.json();
    assert.deepEqual(Object.keys(status).sort(), [
      'access', 'controlPlaneOrigin', 'gateway', 'release', 'schemaVersion', 'source', 'status', 'updatedAt',
    ]);
    assert.equal(status.controlPlaneOrigin, 'https://deploy.ankka.ai');
    const serialized = JSON.stringify(status);
    assert.doesNotMatch(serialized, /(?:provider|receipt|journal|tombstone|installationId|accountId|zoneId)/iu);
    assert.doesNotMatch(serialized, /synthetic-cloudflare-grant-never-store/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('management teardown handoff is actor-bound, same-origin, receipt-backed, and credential-free', async () => {
  const { env, objects, provider: cloudflare } = await installReadyGateway();
  const originalFetch = globalThis.fetch;
  try {
    const keys = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    );
    const kid = 'test-access-key';
    const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
    const assertion = await accessAssertion(
      'admin@example.com', env.CF_ACCESS_ISSUER, env.CF_ACCESS_AUD, keys.privateKey, kid,
    );
    globalThis.fetch = async (request) => {
      const url = new URL(request.url);
      if (url.href === `${env.CF_ACCESS_ISSUER}/cdn-cgi/access/certs`) {
        return new Response(JSON.stringify({ keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] }), {
          headers: { 'content-type': 'application/json; charset=utf-8' },
        });
      }
      return cloudflare.fetch(request);
    };
    const accessHeaders = {
      'cf-access-authenticated-user-email': 'admin@example.com',
      'cf-access-jwt-assertion': assertion,
      'content-type': 'application/json',
    };

    const crossed = await worker.fetch(new Request('https://manage.example.com/api/teardown-actions', {
      method: 'POST',
      headers: { ...accessHeaders, origin: 'https://foreign.example.com' },
      body: JSON.stringify({ schemaVersion: 1 }),
    }), env);
    assert.equal(crossed.status, 403);

    const response = await worker.fetch(new Request('https://manage.example.com/api/teardown-actions', {
      method: 'POST',
      headers: { ...accessHeaders, origin: 'https://manage.example.com' },
      body: JSON.stringify({ schemaVersion: 1 }),
    }), env);
    assert.equal(response.status, 200, await response.clone().text());
    const prepared = await response.json();
    const handoff = new URL(prepared.handoffUrl);
    assert.equal(handoff.origin, 'https://deploy.ankka.ai');
    assert.equal(handoff.pathname, '/manage');
    assert.equal(handoff.search, '');
    const action = JSON.parse(Buffer.from(handoff.hash.slice(1), 'base64url').toString('utf8'));
    assert.deepEqual(Object.keys(action).sort(), [
      'accountId', 'actionId', 'actionKey', 'actionType', 'actorEmail', 'expiresAt', 'gatewayName',
      'controlPlaneOrigin', 'installationId', 'managementOrigin', 'portalHostname', 'schemaVersion', 'workerName',
      'workersSubdomain',
    ].sort());
    assert.deepEqual({
      schemaVersion: action.schemaVersion,
      actionType: action.actionType,
      actionId: action.actionId,
      actorEmail: action.actorEmail,
      controlPlaneOrigin: action.controlPlaneOrigin,
      accountId: action.accountId,
      installationId: action.installationId,
      gatewayName: action.gatewayName,
      portalHostname: action.portalHostname,
      workerName: action.workerName,
      workersSubdomain: action.workersSubdomain,
      managementOrigin: action.managementOrigin,
    }, {
      schemaVersion: 3,
      actionType: 'gateway_teardown',
      actionId: prepared.actionId,
      actorEmail: 'admin@example.com',
      controlPlaneOrigin: 'https://deploy.ankka.ai',
      accountId: ACCOUNT_ID,
      installationId: INSTALLATION_ID,
      gatewayName: GATEWAY_NAME,
      portalHostname: HOSTNAME,
      workerName: 'ankka-gateway-test',
      workersSubdomain: 'tenant',
      managementOrigin: 'https://manage.example.com',
    });
    assert.match(action.actionKey, /^[A-Za-z0-9_-]{43}$/u);
    assert.doesNotMatch(JSON.stringify(action), /cloudflareAccessToken|access_token|refresh_token|authorizationCode/iu);

    const management = objects.get('v1:management');
    assert.ok(management);
    assert.doesNotMatch(JSON.stringify(management.storage.writes), new RegExp(action.actionKey, 'u'));

    const publicStatus = await worker.fetch(new Request(
      `https://manage.example.com/api/teardown-actions/${prepared.actionId}`,
      { headers: accessHeaders },
    ), env);
    assert.equal(publicStatus.status, 200);
    assert.deepEqual(await publicStatus.json(), {
      schemaVersion: 1,
      actionId: prepared.actionId,
      status: 'authorization_required',
      expiresAt: prepared.expiresAt,
      failureCode: null,
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('signed runtime updates require explicit authorization, journal progress in customer storage, and retain rollback', async () => {
  const { env, provider: cloudflare } = await installReadyGateway();
  const channel = await signedUpdateChannel();
  env.ANKKA_UPDATE_CHANNEL = channel.body.channel;
  env.ANKKA_UPDATE_KEY_ID = channel.body.verification.keyId;
  env.ANKKA_UPDATE_PUBLIC_KEY = channel.publicKey;
  const originalFetch = globalThis.fetch;
  let updateFetches = 0;
  let updateChannelAvailable = false;
  let servedUpdateChannel = channel.body;
  try {
    const keys = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    );
    const kid = 'test-update-access-key';
    const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
    const assertion = await accessAssertion(
      'admin@example.com', env.CF_ACCESS_ISSUER, env.CF_ACCESS_AUD, keys.privateKey, kid,
    );
    const accessHeaders = {
      'cf-access-authenticated-user-email': 'admin@example.com',
      'cf-access-jwt-assertion': assertion,
    };
    globalThis.fetch = async (request, init) => {
      const normalized = request instanceof Request ? request : new Request(request, init);
      const url = new URL(normalized.url);
      if (url.href === `${env.CF_ACCESS_ISSUER}/cdn-cgi/access/certs`) {
        return new Response(JSON.stringify({ keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] }), {
          headers: { 'content-type': 'application/json; charset=utf-8' },
        });
      }
      if (url.href === `https://deploy.ankka.ai/api/releases/${env.ANKKA_UPDATE_CHANNEL}`) {
        updateFetches += 1;
        assert.equal(normalized.headers.get('authorization'), null);
        assert.equal(normalized.headers.get('cookie'), null);
        assert.equal(normalized.headers.get('referer'), null);
        if (!updateChannelAvailable) {
          return new Response(JSON.stringify({ schemaVersion: 1, error: 'release_unavailable' }), {
            status: 503,
            headers: { 'content-type': 'application/json; charset=utf-8' },
          });
        }
        return new Response(JSON.stringify(servedUpdateChannel), {
          headers: { 'content-type': 'application/json; charset=utf-8' },
        });
      }
      return cloudflare.fetch(normalized);
    };

    assert.equal((await worker.fetch(new Request(
      'https://ankka-gateway-test.tenant.workers.dev/__ankka/runtime-action', { method: 'HEAD' },
    ), env)).status, 204);

    const unavailableResponse = await worker.fetch(new Request('https://manage.example.com/api/update', {
      headers: accessHeaders,
    }), env);
    assert.equal(unavailableResponse.status, 200);
    assert.deepEqual(await unavailableResponse.json(), {
      schemaVersion: 1,
      channel: 'canary',
      status: 'unavailable',
      current: { release: 'gateway-v0.1.0', artifactSha256: RELEASE_SHA256 },
      available: null,
      rollback: { available: false },
    });
    updateChannelAvailable = true;

    const replayed = structuredClone(channel.body);
    replayed.channel = 'stable';
    replayed.verification.channel = 'stable';
    env.ANKKA_UPDATE_CHANNEL = 'stable';
    servedUpdateChannel = replayed;
    const replayedResponse = await worker.fetch(new Request('https://manage.example.com/api/update', {
      headers: accessHeaders,
    }), env);
    assert.equal(replayedResponse.status, 200);
    assert.equal((await replayedResponse.json()).status, 'unavailable');

    env.ANKKA_UPDATE_CHANNEL = channel.body.channel;
    const legacy = structuredClone(channel.body);
    legacy.classification.updaterProtocol = 1;
    delete legacy.verification.channel;
    delete legacy.verification.signatureContext;
    legacy.verification.schemaVersion = 1;
    servedUpdateChannel = legacy;
    const legacyResponse = await worker.fetch(new Request('https://manage.example.com/api/update', {
      headers: accessHeaders,
    }), env);
    assert.equal(legacyResponse.status, 200);
    assert.equal((await legacyResponse.json()).status, 'unavailable');

    const crossOriginChannel = await signedUpdateChannel(
      'gateway-v0.1.1',
      channel.body.channel,
      'https://foreign-control.example',
    );
    env.ANKKA_UPDATE_PUBLIC_KEY = crossOriginChannel.publicKey;
    servedUpdateChannel = crossOriginChannel.body;
    const crossOriginResponse = await worker.fetch(new Request('https://manage.example.com/api/update', {
      headers: accessHeaders,
    }), env);
    assert.equal(crossOriginResponse.status, 200);
    assert.equal((await crossOriginResponse.json()).status, 'unavailable');

    env.ANKKA_UPDATE_PUBLIC_KEY = channel.publicKey;
    servedUpdateChannel = channel.body;

    const availableResponse = await worker.fetch(new Request('https://manage.example.com/api/update', {
      headers: accessHeaders,
    }), env);
    assert.equal(availableResponse.status, 200);
    const available = await availableResponse.json();
    assert.equal(updateFetches, 5);
    assert.notEqual(available.status, 'unavailable', JSON.stringify(available));
    assert.deepEqual({
      channel: available.channel,
      status: available.status,
      current: available.current.release,
      next: available.available.release,
      kind: available.available.classification.kind,
      rollback: available.rollback.available,
    }, {
      channel: 'canary',
      status: 'available', current: 'gateway-v0.1.0', next: 'gateway-v0.1.1', kind: 'normal', rollback: false,
    });

    const preparedResponse = await worker.fetch(new Request('https://manage.example.com/api/update-actions', {
      method: 'POST',
      headers: { ...accessHeaders, origin: 'https://manage.example.com', 'content-type': 'application/json' },
      body: JSON.stringify({ schemaVersion: 1, operation: 'update' }),
    }), env);
    assert.equal(preparedResponse.status, 200, await preparedResponse.clone().text());
    const prepared = await preparedResponse.json();
    assert.equal(prepared.status, 'authorization_required');
    const handoff = new URL(prepared.handoffUrl);
    assert.equal(handoff.origin, 'https://deploy.ankka.ai');
    assert.equal(handoff.pathname, '/manage');
    assert.equal(handoff.search, '');
    const action = JSON.parse(Buffer.from(handoff.hash.slice(1), 'base64url').toString('utf8'));
    assert.deepEqual({
      schemaVersion: action.schemaVersion,
      actionType: action.actionType,
      actionId: action.actionId,
      actorEmail: action.actorEmail,
      controlPlaneOrigin: action.controlPlaneOrigin,
      operation: action.operation,
      from: action.from.release,
      to: action.to.release,
    }, {
      schemaVersion: 2,
      actionType: 'runtime_update',
      actionId: prepared.actionId,
      actorEmail: 'admin@example.com',
      controlPlaneOrigin: 'https://deploy.ankka.ai',
      operation: 'update',
      from: 'gateway-v0.1.0',
      to: 'gateway-v0.1.1',
    });

    const sendControl = async (command) => {
      const body = canonicalJson({
        schemaVersion: 1,
        actionId: action.actionId,
        actionKey: action.actionKey,
        operation: action.operation,
        issuedAt: Date.now(),
        expiresAt: action.expiresAt,
        ...command,
      });
      const signature = `sha256=${createHmac('sha256', Buffer.from(action.actionKey, 'base64url'))
        .update(body).digest('hex')}`;
      return worker.fetch(new Request(
        'https://ankka-gateway-test.tenant.workers.dev/__ankka/runtime-action',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-ankka-runtime-action-signature': signature },
          body,
        },
      ), env);
    };
    const oldVersionId = '11111111-1111-4111-8111-111111111111';
    const newVersionId = '22222222-2222-4222-8222-222222222222';
    assert.equal((await sendControl({ command: 'begin' })).status, 200);
    assert.equal((await sendControl({
      command: 'progress', stage: 'candidate_staged',
      fromVersionId: oldVersionId, toVersionId: newVersionId,
    })).status, 200);
    const completed = await sendControl({
      command: 'complete', fromVersionId: oldVersionId, toVersionId: newVersionId,
    });
    assert.equal(completed.status, 200, await completed.clone().text());
    assert.equal((await completed.json()).status, 'succeeded');

    env.ANKKA_GATEWAY_RELEASE = channel.body.release.id;
    env.ANKKA_GATEWAY_RELEASE_SHA256 = channel.body.release.artifactSha256;
    const converged = await worker.fetch(new Request('https://manage.example.com/api/update', {
      headers: accessHeaders,
    }), env);
    const status = await converged.json();
    assert.equal(status.status, 'up_to_date');
    assert.deepEqual(status.rollback, {
      available: true,
      release: 'gateway-v0.1.0',
      artifactSha256: RELEASE_SHA256,
      dataRollback: false,
    });

    const rollbackResponse = await worker.fetch(new Request('https://manage.example.com/api/update-actions', {
      method: 'POST',
      headers: { ...accessHeaders, origin: 'https://manage.example.com', 'content-type': 'application/json' },
      body: JSON.stringify({ schemaVersion: 1, operation: 'rollback' }),
    }), env);
    assert.equal(rollbackResponse.status, 200, await rollbackResponse.clone().text());
    const rollback = await rollbackResponse.json();
    const rollbackClaim = JSON.parse(Buffer.from(new URL(rollback.handoffUrl).hash.slice(1), 'base64url').toString('utf8'));
    assert.equal(rollbackClaim.operation, 'rollback');
    assert.equal(rollbackClaim.to.release, 'gateway-v0.1.0');
    assert.equal(rollbackClaim.to.versionId, oldVersionId);

    const writes = JSON.stringify(env.ADMIN_STATE.objects.get('v1:management').storage.writes);
    assert.equal(writes.includes(action.actionKey), false);
    assert.doesNotMatch(writes, /(?:cloudflareAccessToken|bearer\s|cookie)/iu);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('management API discovers and applies a customer-owned MCP source through one ephemeral grant', async () => {
  const { env, provider: cloudflare, readyReceipt } = await installReadyGateway();
  const largeSourceFixture = JSON.parse(await readFile(
    new URL('../fixtures/large-source/gateway.config.json', import.meta.url),
    'utf8',
  ));
  const largeToolNames = largeSourceFixture.sources[0].enabledTools;
  const largeToolCatalogue = largeToolNames.map((name) => ({
    name,
    title: name.replaceAll('_', ' '),
    description: `Synthetic read operation ${name}. ${'x'.repeat(1_100)}`,
    inputSchema: { type: 'object' },
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
  }));
  const largeDiscoveryCatalogue = [...largeToolCatalogue, {
    name: 'company_delete',
    description: 'Delete context.',
    inputSchema: { type: 'object' },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
  }];
  const maximumToolCatalogue = Array.from({ length: 500 }, (_value, index) => ({
    name: `maximum_read_${String(index + 1).padStart(3, '0')}_`.padEnd(128, 'x'),
  }));
  const cataloguePageSize = 25;
  const expectedCatalogueCursors = Array.from(
    { length: Math.ceil(largeDiscoveryCatalogue.length / cataloguePageSize) },
    (_value, index) => index === 0 ? null : `offset-${index * cataloguePageSize}`,
  );
  const expectedMaximumCursors = Array.from(
    { length: maximumToolCatalogue.length / cataloguePageSize },
    (_value, index) => index === 0 ? null : `offset-${index * cataloguePageSize}`,
  );
  const expectedExcessivePageCursors = Array.from(
    { length: 20 },
    (_value, index) => index === 0 ? null : `offset-${index}`,
  );
  const pagedResult = (message, tools, pageSize) => {
    const cursor = message.params.cursor;
    const match = cursor === undefined ? null : cursor.match(/^offset-([1-9][0-9]*)$/u);
    assert.ok(cursor === undefined || match);
    const offset = match ? Number(match[1]) : 0;
    assert.ok(Number.isSafeInteger(offset) && offset < tools.length);
    const end = Math.min(offset + pageSize, tools.length);
    const result = { tools: tools.slice(offset, end) };
    if (end < tools.length) result.nextCursor = `offset-${end}`;
    return result;
  };
  assert.equal(largeToolNames.length, 228);
  const originalFetch = globalThis.fetch;
  try {
    const keys = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    );
    const kid = 'test-source-access-key';
    const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
    const assertion = await accessAssertion(
      'admin@example.com', env.CF_ACCESS_ISSUER, env.CF_ACCESS_AUD, keys.privateKey, kid,
    );
    const accessHeaders = {
      'cf-access-authenticated-user-email': 'admin@example.com',
      'cf-access-jwt-assertion': assertion,
    };
    const mcpRequests = [];
    const catalogueCursors = [];
    const maximumCursors = [];
    const excessivePageCursors = [];
    let aggregatePageCalls = 0;
    let oversizedCatalogueRequest = null;
    let oversizedCatalogueBodyCancelled = false;
    let loseNextSourceCreateResponse = false;
    globalThis.fetch = async (request) => {
      const url = new URL(request.url);
      if (url.href === `${env.CF_ACCESS_ISSUER}/cdn-cgi/access/certs`) {
        return new Response(JSON.stringify({ keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] }), {
          headers: { 'content-type': 'application/json; charset=utf-8' },
        });
      }
      if (url.href === 'https://catalog.example.net/mcp') {
        mcpRequests.push(request.clone());
        assert.equal(request.headers.get('authorization'), null);
        assert.equal(request.headers.get('mcp-protocol-version'), '2026-07-28');
        assert.equal(request.headers.get('mcp-method'), 'tools/list');
        const message = await request.json();
        assert.equal(message.method, 'tools/list');
        assert.equal(message.params._meta['io.modelcontextprotocol/clientInfo'].name, 'ankka-mcp-gateway');
        catalogueCursors.push(message.params.cursor ?? null);
        return new Response(JSON.stringify({
          jsonrpc: '2.0',
          id: message.id,
          result: pagedResult(message, largeDiscoveryCatalogue, cataloguePageSize),
        }), { headers: { 'content-type': 'application/json; charset=utf-8' } });
      }
      if (url.href === 'https://maximum-paged-tools.example.net/mcp') {
        const message = await request.json();
        maximumCursors.push(message.params.cursor ?? null);
        return Response.json({
          jsonrpc: '2.0',
          id: message.id,
          result: pagedResult(message, maximumToolCatalogue, cataloguePageSize),
        });
      }
      if (url.href === 'https://too-many-pages.example.net/mcp') {
        const message = await request.json();
        excessivePageCursors.push(message.params.cursor ?? null);
        return Response.json({
          jsonrpc: '2.0',
          id: message.id,
          result: pagedResult(message, maximumToolCatalogue.slice(0, 21), 1),
        });
      }
      if (url.href === 'https://aggregate-limit.example.net/mcp') {
        const message = await request.json();
        const page = message.params.cursor === undefined
          ? 1
          : Number(message.params.cursor.slice('page-'.length));
        aggregatePageCalls += 1;
        const result = {
          tools: [{ name: `aggregate_read_${page}` }],
          padding: 'x'.repeat(3 * 1024 * 1024),
        };
        if (page < 3) result.nextCursor = `page-${page + 1}`;
        return Response.json({ jsonrpc: '2.0', id: message.id, result });
      }
      if (url.href === 'https://too-many-tools.example.net/mcp') {
        const message = await request.json();
        return Response.json({
          jsonrpc: '2.0',
          id: message.id,
          result: {
            tools: Array.from({ length: 501 }, (_value, index) => ({
              name: `synthetic_read_${String(index + 1).padStart(3, '0')}`,
            })),
          },
        });
      }
      if (url.href === 'https://oversized-catalogue.example.net/mcp') {
        oversizedCatalogueRequest = request;
        return new Response(new ReadableStream({
          cancel() { oversizedCatalogueBodyCancelled = true; },
        }), {
          headers: {
            'content-length': String((4 * 1024 * 1024) + 1),
            'content-type': 'application/json; charset=utf-8',
          },
        });
      }
      if (url.href === 'https://oauth-source.example.net/mcp') {
        return new Response(null, {
          status: 401,
          headers: {
            'www-authenticate': 'Bearer resource_metadata="https://oauth-source.example.net/.well-known/oauth-protected-resource", scope="company:read"',
          },
        });
      }
      if (url.href === 'https://legacy-auth.example.net/mcp') {
        return new Response(null, { status: 401 });
      }
      if (loseNextSourceCreateResponse && request.method === 'POST' &&
          url.pathname.endsWith('/access/ai-controls/mcp/servers')) {
        loseNextSourceCreateResponse = false;
        await cloudflare.fetch(request);
        throw new Error('response lost after provider apply');
      }
      return cloudflare.fetch(request);
    };

    const initial = await worker.fetch(new Request('https://manage.example.com/api/sources', {
      headers: accessHeaders,
    }), env);
    assert.equal(initial.status, 200);
    const initialSources = await initial.json();
    assert.equal(initialSources.revision, 1);
    assert.equal(initialSources.applyMode, 'oauth_per_action');
    assert.deepEqual(initialSources.sources.map(({ status, url }) => ({ status, url })), [{
      status: 'installed', url: 'https://source.example.net/mcp',
    }]);

    const discovered = await worker.fetch(new Request('https://manage.example.com/api/sources/discover', {
      method: 'POST',
      headers: { ...accessHeaders, origin: 'https://manage.example.com', 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://catalog.example.net/mcp' }),
    }), env);
    assert.equal(discovered.status, 200);
    const catalogue = await discovered.json();
    assert.equal(catalogue.protocolVersion, '2026-07-28');
    assert.equal(catalogue.tools.length, 229);
    assert.deepEqual(
      catalogue.tools.slice(0, 2).map(({ name, defaultSelected }) => ({ name, defaultSelected })),
      largeToolNames.slice(0, 2).map((name) => ({ name, defaultSelected: true })),
    );
    assert.deepEqual(catalogue.tools.at(-1), {
      name: 'company_delete',
      title: null,
      description: 'Delete context.',
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: true,
      defaultSelected: false,
    });

    const saved = await worker.fetch(new Request('https://manage.example.com/api/sources', {
      method: 'PUT',
      headers: { ...accessHeaders, origin: 'https://manage.example.com', 'content-type': 'application/json' },
      body: JSON.stringify({
        schemaVersion: 1,
        revision: initialSources.revision,
        source: {
          label: 'Approved catalogue',
          url: 'https://catalog.example.net/mcp',
          authMode: 'none',
          enabledTools: largeToolNames,
        },
      }),
    }), env);
    assert.equal(saved.status, 200, await saved.clone().text());
    const updated = await saved.json();
    assert.equal(updated.revision, 2);
    assert.equal(updated.applyMode, 'oauth_per_action');
    assert.deepEqual(updated.sources[0].enabledTools, ['company_prepare', 'company_search']);
    assert.deepEqual(updated.sources[1].enabledTools, largeToolNames);
    assert.equal(updated.sources[1].label, 'Approved catalogue');
    assert.equal(updated.sources[1].status, 'draft');
    assert.equal(mcpRequests.length, expectedCatalogueCursors.length * 2);
    assert.deepEqual(catalogueCursors, [
      ...expectedCatalogueCursors,
      ...expectedCatalogueCursors,
    ]);
    assert.doesNotMatch(JSON.stringify(updated), /(?:authorization|credential|secret|token)/iu);

    const nestedPrepare = await worker.fetch(new Request('https://manage.example.com/api/source-actions/not-an-action', {
      method: 'POST',
      headers: { ...accessHeaders, origin: 'https://manage.example.com', 'content-type': 'application/json' },
      body: JSON.stringify({
        schemaVersion: 1,
        revision: updated.revision,
        sourceId: updated.sources[1].id,
      }),
    }), env);
    assert.equal(nestedPrepare.status, 404);
    assert.deepEqual(await nestedPrepare.json(), { schemaVersion: 1, error: 'source_action_not_found' });

    const firstPrepared = await worker.fetch(new Request('https://manage.example.com/api/source-actions', {
      method: 'POST',
      headers: { ...accessHeaders, origin: 'https://manage.example.com', 'content-type': 'application/json' },
      body: JSON.stringify({
        schemaVersion: 1,
        revision: updated.revision,
        sourceId: updated.sources[1].id,
      }),
    }), env);
    assert.equal(firstPrepared.status, 200);
    const firstAuthorization = await firstPrepared.json();
    const cancelled = await worker.fetch(new Request(
      `https://manage.example.com/api/source-actions/${firstAuthorization.actionId}`,
      {
        method: 'DELETE',
        headers: { ...accessHeaders, origin: 'https://manage.example.com', 'content-type': 'application/json' },
        body: '{}',
      },
    ), env);
    assert.equal(cancelled.status, 200);
    assert.deepEqual(await cancelled.json(), {
      schemaVersion: 1,
      actionId: firstAuthorization.actionId,
      sourceId: updated.sources[1].id,
      status: 'failed',
      expiresAt: firstAuthorization.expiresAt,
      failureCode: 'source_action_denied',
    });

    const prepared = await worker.fetch(new Request('https://manage.example.com/api/source-actions', {
      method: 'POST',
      headers: { ...accessHeaders, origin: 'https://manage.example.com', 'content-type': 'application/json' },
      body: JSON.stringify({
        schemaVersion: 1,
        revision: updated.revision,
        sourceId: updated.sources[1].id,
      }),
    }), env);
    assert.equal(prepared.status, 200);
    const authorization = await prepared.json();
    const handoff = new URL(authorization.handoffUrl);
    assert.equal(handoff.origin, 'https://deploy.ankka.ai');
    assert.equal(handoff.pathname, '/manage');
    assert.equal(handoff.search, '');
    const actionClaim = JSON.parse(Buffer.from(handoff.hash.slice(1), 'base64url').toString('utf8'));
    assert.equal(actionClaim.actionId, authorization.actionId);
    assert.equal(actionClaim.actorEmail, 'admin@example.com');
    assert.equal(actionClaim.accountId, ACCOUNT_ID);
    assert.equal(actionClaim.workerName, 'ankka-gateway-test');
    assert.equal(actionClaim.workersSubdomain, 'tenant');
    assert.equal(actionClaim.controlPlaneOrigin, 'https://deploy.ankka.ai');
    assert.deepEqual(Object.keys(actionClaim).sort(), [
      'accountId', 'actionId', 'actionKey', 'actorEmail', 'expiresAt', 'managementOrigin',
      'controlPlaneOrigin', 'releaseIdentity', 'schemaVersion', 'workerName', 'workersSubdomain',
    ].sort());
    assert.deepEqual(actionClaim.releaseIdentity, {
      schemaVersion: 1,
      channel: env.ANKKA_UPDATE_CHANNEL,
      controlPlaneOrigin: 'https://deploy.ankka.ai',
      release: env.ANKKA_GATEWAY_RELEASE,
      keyId: env.ANKKA_UPDATE_KEY_ID,
      publicKey: env.ANKKA_UPDATE_PUBLIC_KEY,
      artifactSha256: env.ANKKA_GATEWAY_RELEASE_SHA256.slice('sha256:'.length),
    });
    assert.doesNotMatch(JSON.stringify(actionClaim), /(?:cloudflareAccessToken|access_token|refresh_token)/iu);

    const actionBody = canonicalJson({
      schemaVersion: 1,
      actionId: actionClaim.actionId,
      actionKey: actionClaim.actionKey,
      actorEmail: actionClaim.actorEmail,
      accountId: actionClaim.accountId,
      issuedAt: Date.now(),
      expiresAt: actionClaim.expiresAt,
      cloudflareAccessToken: 'ephemeral-source-action-grant',
    });
    const actionSignature = `sha256=${createHmac(
      'sha256', Buffer.from(actionClaim.actionKey, 'base64url'),
    ).update(actionBody).digest('hex')}`;
    loseNextSourceCreateResponse = true;
    const applied = await worker.fetch(new Request(
      'https://ankka-gateway-test.tenant.workers.dev/__ankka/source-action',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-ankka-source-action-signature': actionSignature,
        },
        body: actionBody,
      },
    ), env);
    assert.equal(applied.status, 409);
    assert.equal((await applied.json()).error, 'source_action_recovery_required');

    const recoveredPrepare = await worker.fetch(new Request('https://manage.example.com/api/source-actions', {
      method: 'POST',
      headers: { ...accessHeaders, origin: 'https://manage.example.com', 'content-type': 'application/json' },
      body: JSON.stringify({
        schemaVersion: 1,
        revision: updated.revision,
        sourceId: updated.sources[1].id,
      }),
    }), env);
    assert.equal(recoveredPrepare.status, 200);
    const recoveredAuthorization = await recoveredPrepare.json();
    assert.notEqual(recoveredAuthorization.actionId, authorization.actionId);
    const recoveredHandoff = new URL(recoveredAuthorization.handoffUrl);
    const recoveredClaim = JSON.parse(Buffer.from(recoveredHandoff.hash.slice(1), 'base64url').toString('utf8'));
    const recoveredBody = canonicalJson({
      schemaVersion: 1,
      actionId: recoveredClaim.actionId,
      actionKey: recoveredClaim.actionKey,
      actorEmail: recoveredClaim.actorEmail,
      accountId: recoveredClaim.accountId,
      issuedAt: Date.now(),
      expiresAt: recoveredClaim.expiresAt,
      cloudflareAccessToken: 'ephemeral-source-action-recovery-grant',
    });
    const recoveredSignature = `sha256=${createHmac(
      'sha256', Buffer.from(recoveredClaim.actionKey, 'base64url'),
    ).update(recoveredBody).digest('hex')}`;
    const recovered = await worker.fetch(new Request(
      'https://ankka-gateway-test.tenant.workers.dev/__ankka/source-action',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-ankka-source-action-signature': recoveredSignature,
        },
        body: recoveredBody,
      },
    ), env);
    assert.equal(recovered.status, 200, await recovered.clone().text());
    assert.equal((await recovered.json()).status, 'succeeded');
    assert.equal(catalogueCursors.length % expectedCatalogueCursors.length, 0);
    const lifecycleDiscoveryPasses = catalogueCursors.length / expectedCatalogueCursors.length;
    assert.ok(lifecycleDiscoveryPasses >= 4);
    assert.deepEqual(catalogueCursors, Array.from(
      { length: lifecycleDiscoveryPasses },
      () => expectedCatalogueCursors,
    ).flat());
    const installed = await worker.fetch(new Request('https://manage.example.com/api/sources', {
      headers: accessHeaders,
    }), env);
    const installedSources = await installed.json();
    assert.deepEqual(installedSources.sources.map(({ label, status }) => ({ label, status })), [
      { label: 'Company context', status: 'installed' },
      { label: 'Approved catalogue', status: 'installed' },
    ]);
    assert.equal(cloudflare.state.servers.size, 2);
    assert.equal(cloudflare.state.apps.size, 3);
    assert.equal(cloudflare.state.portal.servers.length, 2);
    const largeServer = [...cloudflare.state.servers.values()].find(
      (server) => server.hostname === 'https://catalog.example.net/mcp',
    );
    assert.ok(largeServer);
    const largeMapping = cloudflare.state.portal.servers.find(
      (mapping) => mapping.server_id === largeServer.id,
    );
    assert.ok(largeMapping);
    assert.deepEqual(
      largeMapping.updated_tools.map(({ name }) => name),
      largeToolNames,
    );
    assert.doesNotMatch(JSON.stringify(env.ADMIN_STATE.objects.get('v1:management').storage.writes),
      /ephemeral-source-action-(?:grant|recovery-grant)/u);

    const oauthDiscovery = await worker.fetch(new Request('https://manage.example.com/api/sources/discover', {
      method: 'POST',
      headers: { ...accessHeaders, origin: 'https://manage.example.com', 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://oauth-source.example.net/mcp' }),
    }), env);
    assert.equal(oauthDiscovery.status, 200);
    assert.deepEqual(await oauthDiscovery.json(), {
      schemaVersion: 1,
      status: 'authorization_required',
      endpoint: 'https://oauth-source.example.net/mcp',
      protocolVersion: '2026-07-28',
      authentication: 'oauth',
      tools: [],
    });

    const unsupportedAuthentication = await worker.fetch(new Request(
      'https://manage.example.com/api/sources/discover',
      {
        method: 'POST',
        headers: { ...accessHeaders, origin: 'https://manage.example.com', 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://legacy-auth.example.net/mcp' }),
      },
    ), env);
    assert.equal(unsupportedAuthentication.status, 401);
    assert.deepEqual(await unsupportedAuthentication.json(), {
      schemaVersion: 1,
      error: 'source_authentication_unsupported',
    });

    const maximumPagedDiscovery = await worker.fetch(new Request(
      'https://manage.example.com/api/sources/discover',
      {
        method: 'POST',
        headers: {
          ...accessHeaders,
          origin: 'https://manage.example.com',
          'content-type': 'application/json',
        },
        body: JSON.stringify({ url: 'https://maximum-paged-tools.example.net/mcp' }),
      },
    ), env);
    assert.equal(maximumPagedDiscovery.status, 200);
    const maximumCatalogue = await maximumPagedDiscovery.json();
    assert.equal(maximumCatalogue.tools.length, 500);
    assert.equal(maximumCatalogue.tools[0].name, maximumToolCatalogue[0].name);
    assert.equal(maximumCatalogue.tools.at(-1).name, maximumToolCatalogue.at(-1).name);
    assert.equal(maximumCatalogue.tools.every(({ name }) => name.length === 128), true);
    assert.deepEqual(maximumCursors, expectedMaximumCursors);

    const sourceStateStorage = env.ADMIN_STATE.objects.get('v1:management').storage;
    for (const declared of [true, false]) {
      let oversizedSaveBodyCancelled = false;
      const beforeMcpRequests = mcpRequests.length;
      const beforeProviderRequests = cloudflare.requests.length;
      const beforeStorageWrites = sourceStateStorage.writes.length;
      const headers = {
        ...accessHeaders,
        origin: 'https://manage.example.com',
        'content-type': 'application/json',
      };
      if (declared) headers['content-length'] = String((96 * 1024) + 1);
      const oversizedSave = await worker.fetch(new Request(
        'https://manage.example.com/api/sources',
        {
          method: 'PUT',
          headers,
          body: new ReadableStream({
            pull(controller) {
              if (!declared) controller.enqueue(new Uint8Array((96 * 1024) + 1));
            },
            cancel() { oversizedSaveBodyCancelled = true; },
          }),
          duplex: 'half',
        },
      ), env);
      assert.equal(oversizedSave.status, 400);
      assert.deepEqual(await oversizedSave.json(), { schemaVersion: 1, error: 'source_invalid' });
      assert.equal(oversizedSaveBodyCancelled, true);
      assert.equal(mcpRequests.length, beforeMcpRequests);
      assert.equal(cloudflare.requests.length, beforeProviderRequests);
      assert.equal(sourceStateStorage.writes.length, beforeStorageWrites);
    }

    const maximumSaveBody = JSON.stringify({
      schemaVersion: 1,
      revision: installedSources.revision,
      source: {
        label: 'Maximum bounded catalogue',
        url: 'https://maximum-paged-tools.example.net/mcp',
        authMode: 'none',
        enabledTools: maximumToolCatalogue.map(({ name }) => name),
      },
    });
    assert.ok(Buffer.byteLength(maximumSaveBody) > 32 * 1024);
    assert.ok(Buffer.byteLength(maximumSaveBody) < 96 * 1024);
    const maximumSavedResponse = await worker.fetch(new Request(
      'https://manage.example.com/api/sources',
      {
        method: 'PUT',
        headers: {
          ...accessHeaders,
          origin: 'https://manage.example.com',
          'content-type': 'application/json',
        },
        body: maximumSaveBody,
      },
    ), env);
    assert.equal(maximumSavedResponse.status, 200, await maximumSavedResponse.clone().text());
    const maximumSavedSources = await maximumSavedResponse.json();
    const maximumDraft = maximumSavedSources.sources.find(
      ({ url }) => url === 'https://maximum-paged-tools.example.net/mcp',
    );
    assert.ok(maximumDraft);
    assert.equal(maximumDraft.status, 'draft');
    assert.deepEqual(maximumDraft.enabledTools, maximumToolCatalogue.map(({ name }) => name));
    assert.deepEqual(maximumCursors, [
      ...expectedMaximumCursors,
      ...expectedMaximumCursors,
    ]);

    for (const [url, error] of [
      ['https://too-many-tools.example.net/mcp', 'source_tool_list_invalid'],
      ['https://too-many-pages.example.net/mcp', 'source_tool_list_invalid'],
      ['https://aggregate-limit.example.net/mcp', 'source_response_invalid'],
      ['https://oversized-catalogue.example.net/mcp', 'source_response_invalid'],
    ]) {
      const rejectedCatalogue = await worker.fetch(new Request(
        'https://manage.example.com/api/sources/discover',
        {
          method: 'POST',
          headers: {
            ...accessHeaders,
            origin: 'https://manage.example.com',
            'content-type': 'application/json',
          },
          body: JSON.stringify({ url }),
        },
      ), env);
      assert.equal(rejectedCatalogue.status, 502);
      assert.deepEqual(await rejectedCatalogue.json(), { schemaVersion: 1, error });
    }
    assert.deepEqual(excessivePageCursors, expectedExcessivePageCursors);
    assert.equal(aggregatePageCalls, 3);
    assert.ok(oversizedCatalogueRequest);
    assert.equal(oversizedCatalogueRequest.signal.aborted, true);
    assert.equal(oversizedCatalogueBodyCancelled, true);

    const sourceStateBeforeUserAuthOptIn = env.ADMIN_STATE.objects
      .get('v1:management').storage.writes.length;
    const userAuthOptIn = await worker.fetch(new Request('https://manage.example.com/api/sources', {
      method: 'PUT',
      headers: { ...accessHeaders, origin: 'https://manage.example.com', 'content-type': 'application/json' },
      body: JSON.stringify({
        schemaVersion: 1,
        revision: maximumSavedSources.revision,
        source: {
          label: 'Private company files',
          url: 'https://oauth-source.example.net/mcp',
          authMode: 'oauth',
          onBehalfOfUser: true,
          enabledTools: ['company_files_search'],
        },
      }),
    }), env);
    assert.equal(userAuthOptIn.status, 400);
    assert.deepEqual(await userAuthOptIn.json(), { schemaVersion: 1, error: 'source_invalid' });
    assert.equal(
      env.ADMIN_STATE.objects.get('v1:management').storage.writes.length,
      sourceStateBeforeUserAuthOptIn,
    );

    const oauthSaved = await worker.fetch(new Request('https://manage.example.com/api/sources', {
      method: 'PUT',
      headers: { ...accessHeaders, origin: 'https://manage.example.com', 'content-type': 'application/json' },
      body: JSON.stringify({
        schemaVersion: 1,
        revision: maximumSavedSources.revision,
        source: {
          label: 'Private company files',
          url: 'https://oauth-source.example.net/mcp',
          authMode: 'oauth',
          enabledTools: ['company_files_search'],
        },
      }),
    }), env);
    assert.equal(oauthSaved.status, 200, await oauthSaved.clone().text());
    const oauthDrafts = await oauthSaved.json();
    const oauthDraft = oauthDrafts.sources.find((source) => source.url === 'https://oauth-source.example.net/mcp');
    assert.deepEqual(oauthDraft, {
      id: oauthDraft.id,
      label: 'Private company files',
      url: 'https://oauth-source.example.net/mcp',
      authMode: 'oauth',
      onBehalfOfUser: false,
      enabledTools: ['company_files_search'],
      status: 'draft',
    });

    const sourceActionPreparedResponse = await worker.fetch(new Request('https://manage.example.com/api/source-actions', {
      method: 'POST',
      headers: { ...accessHeaders, origin: 'https://manage.example.com', 'content-type': 'application/json' },
      body: JSON.stringify({
        schemaVersion: 1,
        revision: oauthDrafts.revision,
        sourceId: oauthDraft.id,
      }),
    }), env);
    assert.equal(sourceActionPreparedResponse.status, 200);
    const sourceActionAuthorization = await sourceActionPreparedResponse.json();
    const sourceActionHandoff = new URL(sourceActionAuthorization.handoffUrl);
    const sourceActionClaim = JSON.parse(Buffer.from(
      sourceActionHandoff.hash.slice(1),
      'base64url',
    ).toString('utf8'));
    const sourceActionBody = canonicalJson({
      schemaVersion: 1,
      actionId: sourceActionClaim.actionId,
      actionKey: sourceActionClaim.actionKey,
      actorEmail: sourceActionClaim.actorEmail,
      accountId: sourceActionClaim.accountId,
      issuedAt: Date.now(),
      expiresAt: sourceActionClaim.expiresAt,
      cloudflareAccessToken: 'ephemeral-oauth-source-action-grant',
    });
    const sourceActionSignature = `sha256=${createHmac(
      'sha256', Buffer.from(sourceActionClaim.actionKey, 'base64url'),
    ).update(sourceActionBody).digest('hex')}`;
    const oauthApplied = await worker.fetch(new Request(
      'https://ankka-gateway-test.tenant.workers.dev/__ankka/source-action',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-ankka-source-action-signature': sourceActionSignature,
        },
        body: sourceActionBody,
      },
    ), env);
    assert.equal(oauthApplied.status, 200, await oauthApplied.clone().text());
    const oauthServer = [...cloudflare.state.servers.values()].find(
      (server) => server.hostname === 'https://oauth-source.example.net/mcp',
    );
    assert.equal(oauthServer.auth_type, 'oauth');
    assert.equal(oauthServer.is_shared_oauth_callback_enabled, true);
    const oauthMapping = cloudflare.state.portal.servers.find(
      (mapping) => mapping.server_id === oauthServer.id,
    );
    assert.equal(oauthMapping.on_behalf, false);
    assert.deepEqual(oauthMapping.updated_tools, [{ name: 'company_files_search', enabled: true }]);
    assert.doesNotMatch(JSON.stringify(env.ADMIN_STATE.objects.get('v1:management').storage.writes),
      /ephemeral-oauth-source-action-grant/u);

    const rejectedOrigin = await worker.fetch(new Request('https://manage.example.com/api/sources/discover', {
      method: 'POST',
      headers: { ...accessHeaders, 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://catalog.example.net/mcp' }),
    }), env);
    assert.equal(rejectedOrigin.status, 403);

    const teardownPrepared = await worker.fetch(new Request('https://manage.example.com/api/teardown-actions', {
      method: 'POST',
      headers: { ...accessHeaders, origin: 'https://manage.example.com', 'content-type': 'application/json' },
      body: JSON.stringify({ schemaVersion: 1 }),
    }), env);
    assert.equal(teardownPrepared.status, 200, await teardownPrepared.clone().text());
    const teardownAuthorization = await teardownPrepared.json();
    const teardownClaim = JSON.parse(Buffer.from(
      new URL(teardownAuthorization.handoffUrl).hash.slice(1), 'base64url',
    ).toString('utf8'));
    const sendTeardown = async (command, requestId = undefined) => {
      const teardownRequest = {
        schemaVersion: 1,
        command,
        actionId: teardownClaim.actionId,
        actionKey: teardownClaim.actionKey,
        actorEmail: teardownClaim.actorEmail,
        accountId: teardownClaim.accountId,
        installationId: teardownClaim.installationId,
        issuedAt: Date.now(),
        expiresAt: teardownClaim.expiresAt,
      };
      if (requestId !== undefined) {
        teardownRequest.requestId = requestId;
        teardownRequest.cloudflareAccessToken = 'ephemeral-returning-teardown-grant';
      }
      const body = canonicalJson(teardownRequest);
      const signature = `sha256=${createHmac(
        'sha256', Buffer.from(teardownClaim.actionKey, 'base64url'),
      ).update(body).digest('hex')}`;
      return worker.fetch(new Request(
        'https://ankka-gateway-test.tenant.workers.dev/__ankka/teardown-action',
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-ankka-teardown-action-signature': signature,
          },
          body,
        },
      ), env);
    };
    const managementStorage = env.ADMIN_STATE.objects.get('v1:management').storage;
    const control = managementStorage.snapshot('ankka-mcp-gateway/management-control/v1');
    const rootSourceResources = readyReceipt.resources.slice(0, 3);
    const initialOwner = control.sourceOwnership.find((ownership) => (
      canonicalJson(ownership.resources) === canonicalJson(rootSourceResources)
    ));
    assert.ok(initialOwner);
    const collidingControl = structuredClone(control);
    const collidingOwner = collidingControl.sourceOwnership.find((ownership) => (
      ownership.sourceId !== initialOwner.sourceId
    ));
    const rootPortalApplication = readyReceipt.resources.find(
      (resource) => resource.kind === 'portal_access_application',
    );
    assert.ok(collidingOwner);
    assert.ok(rootPortalApplication);
    collidingOwner.resources[1].provider.id = rootPortalApplication.provider.id;
    collidingOwner.resources[2].provider.parentId = rootPortalApplication.provider.id;
    await managementStorage.put('ankka-mcp-gateway/management-control/v1', collidingControl);
    const collisionProof = await sendTeardown('prove');
    assert.equal(collisionProof.status, 409);
    assert.equal(cloudflare.deletes().length, 0);
    await managementStorage.put('ankka-mcp-gateway/management-control/v1', control);

    const proof = await sendTeardown('prove');
    assert.equal(proof.status, 200, await proof.clone().text());
    const importedAuthority = await proof.json();
    assert.equal(importedAuthority.status, 'authorized');
    assert.deepEqual(Object.keys(importedAuthority.authority).sort(), [
      'control', 'installationId', 'root', 'runtime', 'schemaVersion', 'sources',
    ]);
    assert.deepEqual(importedAuthority.authority.runtime, {
      release: env.ANKKA_GATEWAY_RELEASE,
      artifactSha256: env.ANKKA_GATEWAY_RELEASE_SHA256,
      updateChannel: env.ANKKA_UPDATE_CHANNEL,
      updateKeyId: env.ANKKA_UPDATE_KEY_ID,
      updatePublicKey: env.ANKKA_UPDATE_PUBLIC_KEY,
      controlPlaneOrigin: 'https://deploy.ankka.ai',
      accountId: env.CLOUDFLARE_ACCOUNT_ID,
      zoneId: env.CLOUDFLARE_ZONE_ID,
      zoneName: env.CLOUDFLARE_ZONE_NAME,
      workerName: env.ANKKA_WORKER_NAME,
      workersSubdomain: env.ANKKA_WORKERS_SUBDOMAIN,
      managementHostname: env.ANKKA_MANAGEMENT_HOSTNAME,
    });
    assert.doesNotMatch(JSON.stringify(importedAuthority),
      /(?:cloudflareAccessToken|access_token|refresh_token|authorizationCode|actionKey)/iu);

    const receiptSources = importedAuthority.authority.root.receipt.resources.slice(0, 3);
    const rootSourceOwner = control.sourceOwnership.find((ownership) => (
      canonicalJson(ownership.resources) === canonicalJson(receiptSources)
    ));
    assert.ok(rootSourceOwner);
    const dayTwoOwnership = control.sourceOwnership
      .filter((ownership) => ownership.sourceId !== rootSourceOwner.sourceId)
      .sort((left, right) => left.sourceId < right.sourceId ? -1 : left.sourceId > right.sourceId ? 1 : 0);
    assert.equal(dayTwoOwnership.length, 2);
    const expectedRemoval = [
      ...dayTwoOwnership.flatMap((ownership) => ownership.resources).reverse(),
      ...importedAuthority.authority.root.receipt.resources.slice().reverse(),
    ];
    const providerPath = (resource) => {
      if (resource.kind === 'mcp_server') {
        return `/client/v4/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/servers/${resource.provider.id}`;
      }
      if (resource.kind === 'portal') {
        return `/client/v4/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/portals/${resource.provider.id}`;
      }
      if (resource.kind.endsWith('_access_application')) {
        return `/client/v4/accounts/${ACCOUNT_ID}/access/apps/${resource.provider.id}`;
      }
      if (resource.kind.endsWith('_access_policy')) {
        return `/client/v4/accounts/${ACCOUNT_ID}/access/apps/${resource.provider.parentId}/policies/${resource.provider.id}`;
      }
      return `/client/v4/zones/${env.CLOUDFLARE_ZONE_ID}/dns_records/${resource.provider.id}`;
    };

    // A suffix marker alone is not ownership. The whole graph is preflighted,
    // so either this policy drift or a Portal application drift blocks before
    // any provider deletion.
    const firstPolicyAuthority = expectedRemoval[0];
    assert.equal(firstPolicyAuthority.kind, 'source_access_policy');
    const policyList = cloudflare.state.policies.get(firstPolicyAuthority.provider.parentId);
    const livePolicy = policyList.find((policy) => policy.id === firstPolicyAuthority.provider.id);
    const ownedPolicyName = livePolicy.name;
    livePolicy.name = `Unrelated users [${firstPolicyAuthority.marker}]`;
    const policyConflict = await sendTeardown('apply', 'T'.repeat(22));
    assert.equal(policyConflict.status, 409);
    assert.equal(cloudflare.deletes().length, 0);
    livePolicy.name = ownedPolicyName;

    const portalApplication = importedAuthority.authority.root.receipt.resources.find(
      (resource) => resource.kind === 'portal_access_application',
    );
    const livePortalApplication = cloudflare.state.apps.get(portalApplication.provider.id);
    const ownedPortalApplicationName = livePortalApplication.name;
    livePortalApplication.name = 'Unrelated portal application';
    const applicationConflict = await sendTeardown('apply', 'U'.repeat(22));
    assert.equal(applicationConflict.status, 409);
    assert.equal(cloudflare.deletes().length, 0);
    livePortalApplication.name = ownedPortalApplicationName;

    const appliedTeardown = await sendTeardown('apply', 'V'.repeat(22));
    assert.equal(appliedTeardown.status, 200, await appliedTeardown.clone().text());
    assert.equal((await appliedTeardown.json()).status, 'gateway_removed');
    assert.deepEqual(
      cloudflare.deletes().map(({ pathname }) => pathname),
      expectedRemoval.map(providerPath),
    );
    assert.equal(cloudflare.liveResourceCount(), 0);
    const deleteCount = cloudflare.deletes().length;
    const replayedTeardown = await sendTeardown('apply', 'W'.repeat(22));
    assert.equal(replayedTeardown.status, 200, await replayedTeardown.clone().text());
    assert.equal((await replayedTeardown.json()).status, 'gateway_removed');
    assert.equal(cloudflare.deletes().length, deleteCount);

    const persistedTeardown = JSON.stringify([...env.ADMIN_STATE.objects.values()].map((entry) => (
      entry.storage.writes
    )));
    assert.equal(persistedTeardown.includes(teardownClaim.actionKey), false);
    assert.doesNotMatch(persistedTeardown,
      /ephemeral-returning-teardown-grant|cloudflareAccessToken|bearer\s/iu);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
