import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';

import primaryWorker from '../payload/worker/index.js';
import cleanupWorker, { AdminState } from '../payload/worker-cleanup/index.js';
import retirementWorker from '../payload/worker-retirement/index.js';
import { addHistoricalInstalledSource } from './historical-source-fixture.mjs';
import {
  BOOTSTRAP_GRANT,
  BOOTSTRAP_NONCE,
  CONFIGURATION_HASH,
  DELETE_ORDER,
  DESIRED_HASH,
  DURABLE_OBJECT_NAME,
  HOSTNAME,
  INSTALLATION_ID,
  RELEASE,
  RELEASE_SHA256,
  RESOURCE_ORDER,
  PORTAL_RESOURCE_ORDER,
  UNINSTALL_GRANT,
  UNINSTALL_NONCE,
  UNINSTALL_NONCE_BYTES,
  bootstrapRequest,
  canonicalJson,
  cleanupEnvironment as environment,
  cloudflareProvider,
  compareText,
  durableNamespace,
  hmac,
  installReadyGateway,
  memoryStorage,
  prefixedSha256,
  portalOnlyClaim,
  primaryEnvironment,
  resealReadyReceipt,
  uninstallClaim,
  uninstallRequest,
  withProviderFetch,
} from './payload-lifecycle.mjs';

const NOW_SECONDS = Math.floor(Date.now() / 1_000);
const SECRET_STRINGS = Object.freeze([BOOTSTRAP_GRANT, UNINSTALL_GRANT, BOOTSTRAP_NONCE, UNINSTALL_NONCE]);

const signature = (rawBody) => hmac(rawBody, UNINSTALL_NONCE_BYTES);

/**
 * Runs the real primary Worker to `ready`, then returns everything the cleanup
 * Worker inherits: the same Durable Object storage, the same live provider
 * state, and the exact receipt the hosted installer presents at uninstall.
 */
async function installed(options = {}) {
  const lifecycle = await installReadyGateway(options);
  const installWrites = lifecycle.storage.writes.length;
  const installRequests = lifecycle.provider.requests.length;
  return {
    ...lifecycle,
    cleanupWrites: () => lifecycle.storage.writes.slice(installWrites),
    cleanupRequests: () => lifecycle.provider.requests.slice(installRequests),
    cleanupDeletes: () => lifecycle.provider.requests.slice(installRequests)
      .filter(({ method }) => method === 'DELETE'),
  };
}

async function installedWithAdditionalSource(options = {}) {
  const gateway = await installed(options);
  await addHistoricalInstalledSource(gateway);
  return gateway;
}

async function runCleanupCore(request, env, storage, providerFetch) {
  const rawBody = request.method === 'POST' ? await request.clone().text() : undefined;
  const requestInit = {
    method: request.method,
    headers: request.headers,
    redirect: 'manual',
  };
  if (rawBody !== undefined) requestInit.body = rawBody;
  const internal = new Request('https://admin-state.invalid/uninstall', requestInit);
  return withProviderFetch(providerFetch, () => new AdminState({ storage }, env).fetch(internal));
}

function resourcePath(resource) {
  const account = `/client/v4/accounts/${resource.target.accountId}`;
  const zone = `/client/v4/zones/${resource.target.zoneId}`;
  if (resource.kind === 'mcp_server') return `${account}/access/ai-controls/mcp/servers/${resource.provider.id}`;
  if (resource.kind === 'portal') return `${account}/access/ai-controls/mcp/portals/${resource.provider.id}`;
  if (resource.kind.endsWith('_application')) return `${zone}/access/apps/${resource.provider.id}`;
  if (resource.kind.endsWith('_policy')) {
    return `${zone}/access/apps/${resource.provider.parentId}/policies/${resource.provider.id}`;
  }
  return `/client/v4/zones/${resource.target.zoneId}/dns_records/${resource.provider.id}`;
}

function expectedDeletePaths(receipt) {
  return DELETE_ORDER.map((kind) => resourcePath({
    ...receipt.resources.find((resource) => resource.kind === kind),
    target: receipt.target,
  }));
}

async function responseJson(response) {
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('content-type'), 'application/json; charset=utf-8');
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  return response.json();
}

function assertNoSecretsPersisted(storage) {
  const persisted = JSON.stringify(storage.writes);
  for (const secret of SECRET_STRINGS) {
    assert.equal(persisted.includes(secret), false, `storage must never contain ${secret}`);
  }
}

function removedBody(storage, { uninstallInvoked, resumed }) {
  return {
    schemaVersion: 1,
    status: 'removed',
    installationId: INSTALLATION_ID,
    configurationHash: CONFIGURATION_HASH,
    uninstallId: storage.snapshot().uninstallId,
    release: { id: RELEASE, artifactSha256: RELEASE_SHA256 },
    receipt: { revision: 23, resourceCount: 0, evidence: storage.snapshot().removedReceipt },
    uninstallInvoked,
    resumed,
  };
}

test('cleanup accepts the exact primary-generated ready receipt, removes the seven created resources in reverse order, and persists a tombstone', async () => {
  const gateway = await installed();
  const { readyReceipt, storage, provider } = gateway;
  assert.equal(storage.snapshot().state, 'ready');
  assert.equal(provider.liveResourceCount(), 7);

  // Interleave storage writes and provider calls to prove the durable
  // ready -> uninstalling transition precedes the first provider read.
  const timeline = [];
  const originalPut = storage.put;
  storage.put = async (key, value) => {
    timeline.push(`put:${value.status ?? value.state}`);
    return originalPut(key, value);
  };
  provider.intercept(({ request }) => {
    timeline.push(`${request.method}:${new URL(request.url).pathname}`);
    return undefined;
  });

  const response = await runCleanupCore(
    await uninstallRequest({ readyReceipt }), environment(), storage, provider.fetch,
  );
  assert.equal(response.status, 200);
  const body = await responseJson(response);
  assert.deepEqual(Object.keys(body).sort(compareText), [
    'configurationHash', 'installationId', 'receipt', 'release', 'resumed',
    'schemaVersion', 'status', 'uninstallId', 'uninstallInvoked',
  ].sort(compareText));
  assert.deepEqual(body, removedBody(storage, { uninstallInvoked: true, resumed: false }));
  assert.match(body.uninstallId, /^uninstall-[a-f0-9]{24}$/u);
  assert.deepEqual(body.receipt.evidence, {
    schemaVersion: 1,
    manager: 'ankka-mcp-gateway',
    installationId: INSTALLATION_ID,
    state: 'removed',
    revision: 23,
    release: RELEASE,
    target: readyReceipt.target,
    accessPolicy: readyReceipt.accessPolicy,
    desiredHash: DESIRED_HASH,
    resources: [],
    pending: null,
    checksum: body.receipt.evidence.checksum,
  });
  const { checksum, ...unsignedTombstone } = body.receipt.evidence;
  assert.equal(checksum, await prefixedSha256(unsignedTombstone));

  // The first cleanup write is the uninstalling envelope rooted in the exact
  // stored receipt, and it lands before any provider traffic.
  assert.equal(timeline[0], 'put:uninstalling');
  assert.equal(timeline.findIndex((entry) => !entry.startsWith('put:')), 1);
  const envelope = gateway.cleanupWrites()[0].value;
  assert.equal(envelope.status, 'uninstalling');
  assert.deepEqual(envelope.rootReceipt, readyReceipt);
  assert.deepEqual(envelope.removedKinds, []);
  assert.equal(envelope.pending, null);
  assert.equal(envelope.removedReceipt, null);
  assert.deepEqual(storage.snapshot().rootReceipt, readyReceipt);

  // Exactly the seven resources the primary created, in exact reverse
  // dependency order, each deleted once, leaving no live provider residue.
  const deletes = gateway.cleanupDeletes().map(({ pathname }) => pathname);
  assert.deepEqual(deletes, expectedDeletePaths(readyReceipt));
  assert.equal(new Set(deletes).size, RESOURCE_ORDER.length);
  assert.equal(gateway.cleanupRequests().length, RESOURCE_ORDER.length * 3);
  assert.equal(provider.liveResourceCount(), 0);
  assert.deepEqual(storage.snapshot().removedKinds, DELETE_ORDER);
  assert.equal(storage.snapshot().status, 'removed');
  assertNoSecretsPersisted(storage);
});

test('cleanup removes a portal-only wizard installation from its four-resource receipt', async () => {
  const claimInput = await portalOnlyClaim();
  const gateway = await installed({ claimInput });
  const { readyReceipt, storage, provider } = gateway;
  assert.deepEqual(readyReceipt.resources.map(({ kind }) => kind), PORTAL_RESOURCE_ORDER);

  const response = await runCleanupCore(
    await uninstallRequest({
      readyReceipt,
      configurationHash: claimInput.expected.configurationHash,
      installationId: claimInput.expected.installationId,
      desiredHash: claimInput.expected.desiredHash,
    }),
    environment(),
    storage,
    provider.fetch,
  );
  assert.equal(response.status, 200, await response.clone().text());
  const body = await responseJson(response);
  assert.equal(body.status, 'removed');
  assert.equal(body.configurationHash, claimInput.expected.configurationHash);
  assert.equal(body.receipt.revision, 14);
  assert.equal(body.receipt.resourceCount, 0);
  assert.deepEqual(storage.snapshot().removedKinds, [...PORTAL_RESOURCE_ORDER].reverse());
  assert.deepEqual(
    gateway.cleanupDeletes().map(({ pathname }) => pathname),
    [...readyReceipt.resources].reverse().map((resource) => resourcePath({
      ...resource,
      target: readyReceipt.target,
    })),
  );
  assert.equal(provider.liveResourceCount(), 0);
  assertNoSecretsPersisted(storage);
});

test('cleanup through the public route opens the same Durable Object the primary populated', async () => {
  const { readyReceipt, objects, provider } = await installed();
  const env = environment();
  env.ADMIN_STATE = durableNamespace(env, AdminState, objects);
  const response = await withProviderFetch(provider.fetch, async () => (
    cleanupWorker.fetch(await uninstallRequest({ readyReceipt }), env)
  ));
  assert.equal(response.status, 200);
  assert.equal((await response.json()).status, 'removed');
  assert.deepEqual([...objects.keys()].sort(), [DURABLE_OBJECT_NAME, 'v1:management']);
  const storage = objects.get(DURABLE_OBJECT_NAME).storage;
  assert.equal(storage.snapshot().status, 'removed');
  assert.deepEqual(storage.snapshot().rootReceipt, readyReceipt);
  assert.equal(provider.liveResourceCount(), 0);
  assertNoSecretsPersisted(storage);
});

test('public cleanup accepts untouched portal-only management state above 51 users', async () => {
  const memberEmails = ['owner@example.com', ...Array.from({ length: 100 }, (_value, index) =>
    `user-${String(index).padStart(3, '0')}@example.com`)];
  const claimInput = await portalOnlyClaim(undefined, memberEmails);
  const gateway = await installed({ claimInput });
  const env = environment();
  env.ADMIN_STATE = durableNamespace(env, AdminState, gateway.objects);
  const response = await withProviderFetch(gateway.provider.fetch, async () => cleanupWorker.fetch(
    await uninstallRequest({
      readyReceipt: gateway.readyReceipt,
      configurationHash: claimInput.expected.configurationHash,
      installationId: claimInput.expected.installationId,
      desiredHash: claimInput.expected.desiredHash,
    }),
    env,
  ));

  assert.equal(response.status, 200, await response.clone().text());
  assert.equal((await response.json()).status, 'removed');
  assert.equal(gateway.provider.liveResourceCount(), 0);
});

test('cleanup rejects a source journal above the 1 MiB contract before provider access', async () => {
  const gateway = await installed();
  const tools = Array.from({ length: 500 }, (_value, index) => (
    `tool_${String(index).padStart(3, '0')}_`.padEnd(128, 'x')
  ));
  const oversizedSources = {
    schemaVersion: 1,
    revision: 32,
    applyMode: 'oauth_per_action',
    sources: Array.from({ length: 32 }, (_value, index) => ({
      id: `source-${index.toString(16).padStart(16, '0')}`,
      label: `Source ${index}`,
      url: `https://source-${index}.example.com/mcp`,
      authMode: 'none',
      onBehalfOfUser: false,
      enabledTools: tools,
      status: 'draft',
    })),
  };
  assert.ok(Buffer.byteLength(canonicalJson(oversizedSources)) > 1024 * 1024);
  const managementStorage = gateway.objects.get('v1:management').storage;
  await managementStorage.put('ankka-mcp-gateway/management-sources/v1', oversizedSources);
  const providerRequests = gateway.provider.requests.length;
  const managementWrites = managementStorage.writes.length;

  const env = environment();
  env.ADMIN_STATE = durableNamespace(env, AdminState, gateway.objects);
  const request = await uninstallRequest({ readyReceipt: gateway.readyReceipt });
  const response = await withProviderFetch(gateway.provider.fetch, () => (
    cleanupWorker.fetch(request, env)
  ));
  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), {
    schemaVersion: 1, error: 'uninstall_requires_repair', retryable: false,
  });
  assert.equal(gateway.provider.requests.length, providerRequests);
  assert.equal(managementStorage.writes.length, managementWrites);
  assert.equal(gateway.provider.liveResourceCount(), 7);
});

test('cleanup first removes every day-two source and Portal mapping, then removes the original gateway', async () => {
  const gateway = await installedWithAdditionalSource();
  assert.equal(gateway.provider.liveResourceCount(), 10);
  assert.equal(gateway.provider.state.portal.servers.length, 2);
  const managementStorage = gateway.objects.get('v1:management').storage;
  const control = managementStorage.snapshot('ankka-mcp-gateway/management-control/v1');
  const rootServerId = gateway.readyReceipt.resources.find(({ kind }) => kind === 'mcp_server').provider.id;
  const extraOwnership = control.sourceOwnership.find(({ resources }) => resources[0].provider.id !== rootServerId);
  const expectedExtraIds = [...extraOwnership.resources].reverse().map(({ provider }) => provider.id);
  const requestOffset = gateway.provider.requests.length;
  const env = environment();
  env.ADMIN_STATE = durableNamespace(env, AdminState, gateway.objects);
  const request = await uninstallRequest({ readyReceipt: gateway.readyReceipt });
  const response = await withProviderFetch(gateway.provider.fetch, () => cleanupWorker.fetch(request, env));
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal((await response.json()).status, 'removed');
  assert.equal(gateway.provider.liveResourceCount(), 0);

  const cleanupRequests = gateway.provider.requests.slice(requestOffset);
  const portalUpdateIndex = cleanupRequests.findIndex(({ method, pathname }) => (
    method === 'PUT' && pathname.includes('/access/ai-controls/mcp/portals/')
  ));
  const firstDeleteIndex = cleanupRequests.findIndex(({ method }) => method === 'DELETE');
  assert.ok(portalUpdateIndex >= 0 && portalUpdateIndex < firstDeleteIndex);
  assert.equal(cleanupRequests[portalUpdateIndex].body.servers.length, 1);
  const deletes = cleanupRequests.filter(({ method }) => method === 'DELETE');
  assert.equal(deletes.length, 10);
  assert.deepEqual(deletes.slice(0, 3).map(({ pathname }) => pathname.split('/').at(-1)), expectedExtraIds);
  assert.doesNotMatch(JSON.stringify(managementStorage.writes), /ephemeral-source-action-grant/u);
  assertNoSecretsPersisted(gateway.storage);
});

test('cleanup removes every day-two source before an originally empty Portal', async () => {
  const claimInput = await portalOnlyClaim();
  const gateway = await installedWithAdditionalSource({ claimInput });
  assert.equal(gateway.provider.liveResourceCount(), 7);
  assert.equal(gateway.provider.state.portal.servers.length, 1);

  const requestOffset = gateway.provider.requests.length;
  const env = environment();
  env.ADMIN_STATE = durableNamespace(env, AdminState, gateway.objects);
  const response = await withProviderFetch(gateway.provider.fetch, async () => cleanupWorker.fetch(
    await uninstallRequest({
      readyReceipt: gateway.readyReceipt,
      configurationHash: claimInput.expected.configurationHash,
      installationId: claimInput.expected.installationId,
      desiredHash: claimInput.expected.desiredHash,
    }),
    env,
  ));
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal((await response.json()).status, 'removed');
  assert.equal(gateway.provider.liveResourceCount(), 0);

  const cleanupRequests = gateway.provider.requests.slice(requestOffset);
  const portalUpdate = cleanupRequests.find(({ method, pathname }) => (
    method === 'PUT' && pathname.includes('/access/ai-controls/mcp/portals/')
  ));
  assert.ok(portalUpdate);
  assert.deepEqual(portalUpdate.body.servers, []);
  assert.equal(cleanupRequests.filter(({ method }) => method === 'DELETE').length, 7);
});

test('cleanup never starts from a claim alone: absent, in-progress, corrupted, or different stored receipts are rejected before provider access', async () => {
  const { readyReceipt } = await installed();

  // A primary journal that never reached ready (incompatible Portal application).
  const incompatibleEnv = primaryEnvironment();
  const incompatibleProvider = cloudflareProvider({ stripOauth: true });
  const incompatibleResponse = await withProviderFetch(incompatibleProvider.fetch, async () => (
    primaryWorker.fetch(await bootstrapRequest(), incompatibleEnv)
  ));
  assert.equal(incompatibleResponse.status, 409);
  const installing = incompatibleEnv.ADMIN_STATE.objects.get(DURABLE_OBJECT_NAME).storage.snapshot();
  assert.equal(installing.status, 'installing');

  const corrupted = structuredClone(readyReceipt);
  corrupted.checksum = `sha256:${'0'.repeat(64)}`;

  const partial = structuredClone(readyReceipt);
  partial.resources[4].provider.id = 'f'.repeat(32);
  partial.resources[5].provider.parentId = 'f'.repeat(32);
  const differentButValid = await resealReadyReceipt(partial);

  const extraKey = { ...structuredClone(readyReceipt), note: 'x' };

  const cases = [
    ['absent', undefined, readyReceipt],
    ['primary still installing', installing, readyReceipt],
    ['corrupted checksum', corrupted, readyReceipt],
    ['stored receipt differs from claim', differentButValid, readyReceipt],
    ['claim receipt differs from stored', readyReceipt, differentButValid],
    ['stored receipt carries an extra key', extraKey, readyReceipt],
    ['stored receipt is not an object', 'ready', readyReceipt],
  ];
  for (const [label, initial, claimed] of cases) {
    const storage = memoryStorage(initial);
    const response = await runCleanupCore(
      await uninstallRequest({ readyReceipt: claimed }),
      environment(),
      storage,
      async () => assert.fail(`${label}: must not reach provider`),
    );
    assert.equal(response.status, 409, label);
    assert.deepEqual(await response.json(), {
      schemaVersion: 1, error: 'uninstall_request_mismatch', retryable: false,
    }, label);
    assert.equal(storage.writes.length, 0, `${label}: must not write state`);
    assert.deepEqual(storage.snapshot(), initial, `${label}: stored state untouched`);
  }
});

test('cleanup returns the exact retained tombstone without replaying provider calls', async () => {
  const { readyReceipt, storage, provider } = await installed();
  await runCleanupCore(await uninstallRequest({ readyReceipt }), environment(), storage, provider.fetch);
  const expected = storage.snapshot().removedReceipt;
  const requestsAfterCleanup = provider.requests.length;
  const writesAfterCleanup = storage.writes.length;
  let providerCalls = 0;
  const second = await runCleanupCore(
    await uninstallRequest({ readyReceipt, requestId: 'B'.repeat(22) }),
    environment(),
    storage,
    async () => { providerCalls += 1; throw new Error('must not call provider'); },
  );
  const secondBody = await second.json();
  assert.equal(second.status, 200, canonicalJson(secondBody));
  assert.deepEqual(secondBody, removedBody(storage, { uninstallInvoked: false, resumed: true }));
  assert.deepEqual(secondBody.receipt.evidence, expected);
  assert.equal(providerCalls, 0);
  assert.equal(provider.requests.length, requestsAfterCleanup);
  assert.equal(storage.writes.length, writesAfterCleanup);
  assert.equal(provider.liveResourceCount(), 0);
});

test('AdminState serializes concurrent uninstall requests and allows only one mutation pass', async () => {
  const gateway = await installed();
  const { readyReceipt, storage, provider } = gateway;
  const external = await uninstallRequest({ readyReceipt });
  const rawBody = await external.text();
  const internalRequest = () => new Request('https://admin-state.invalid/uninstall', {
    method: 'POST',
    headers: external.headers,
    body: rawBody,
  });
  const object = new AdminState({ storage }, environment());
  const responses = await withProviderFetch(provider.fetch, () => Promise.all([
    object.fetch(internalRequest()),
    object.fetch(internalRequest()),
  ]));
  assert.deepEqual(await Promise.all(responses.map((response) => response.json())), [
    removedBody(storage, { uninstallInvoked: true, resumed: false }),
    removedBody(storage, { uninstallInvoked: false, resumed: true }),
  ]);
  assert.equal(gateway.cleanupDeletes().length, 7);
  assert.equal(provider.liveResourceCount(), 0);
});

test('a failed final tombstone write resumes from the durable seven-resource prefix', async () => {
  const { readyReceipt, storage, provider } = await installed();
  let failTombstoneOnce = true;
  const originalPut = storage.put;
  storage.put = async (key, value) => {
    if (value.status === 'removed' && failTombstoneOnce) {
      failTombstoneOnce = false;
      throw new Error('synthetic final storage failure');
    }
    return originalPut(key, value);
  };
  const request = await uninstallRequest({ readyReceipt });
  const first = await runCleanupCore(request.clone(), environment(), storage, provider.fetch);
  assert.equal(first.status, 409);
  assert.deepEqual(await first.json(), {
    schemaVersion: 1, error: 'uninstall_recovery_required', retryable: true,
  });
  assert.equal(storage.snapshot().status, 'uninstalling');
  assert.deepEqual(storage.snapshot().removedKinds, DELETE_ORDER);
  assert.equal(storage.snapshot().removedReceipt, null);
  assert.equal(provider.liveResourceCount(), 0);
  const providerCalls = provider.requests.length;

  const resumed = await runCleanupCore(request.clone(), environment(), storage, provider.fetch);
  assert.equal(resumed.status, 200);
  assert.deepEqual(await resumed.json(), removedBody(storage, { uninstallInvoked: true, resumed: true }));
  assert.equal(provider.requests.length, providerCalls);
});

test('an unknown DELETE is never replayed under the same request and a fresh request can settle it', async () => {
  const gateway = await installed();
  const { readyReceipt, storage, provider } = gateway;
  const dnsPath = expectedDeletePaths(readyReceipt)[0];
  let ambiguousDelete = true;
  provider.intercept(({ request }) => {
    if (request.method === 'DELETE' && new URL(request.url).pathname === dnsPath && ambiguousDelete) {
      ambiguousDelete = false;
      throw new Error('synthetic ambiguous transport outcome');
    }
    return undefined;
  });
  const firstRequest = await uninstallRequest({ readyReceipt });
  const first = await runCleanupCore(firstRequest.clone(), environment(), storage, provider.fetch);
  assert.equal(first.status, 409);
  assert.deepEqual(await first.json(), {
    schemaVersion: 1, error: 'uninstall_recovery_required', retryable: true,
  });
  assert.deepEqual(storage.snapshot().pending, {
    kind: 'dns_record',
    key: readyReceipt.resources[6].key,
    requestId: 'A'.repeat(22),
    phase: 'send_armed',
  });
  assert.equal(provider.liveResourceCount(), 7);

  const sameAttempt = await runCleanupCore(firstRequest.clone(), environment(), storage, provider.fetch);
  assert.equal(sameAttempt.status, 409);
  assert.deepEqual(await sameAttempt.json(), {
    schemaVersion: 1, error: 'uninstall_recovery_required', retryable: true,
  });
  assert.equal(gateway.cleanupDeletes().length, 1);
  assert.equal(provider.liveResourceCount(), 7);

  const fresh = await runCleanupCore(
    await uninstallRequest({ readyReceipt, requestId: 'B'.repeat(22) }),
    environment(),
    storage,
    provider.fetch,
  );
  assert.equal(fresh.status, 200);
  assert.equal((await fresh.json()).resumed, true);
  assert.equal(gateway.cleanupDeletes().length, 8);
  assert.ok(gateway.cleanupWrites().some(({ value }) => value.pending?.phase === 'not_applied'));
  assert.deepEqual(
    gateway.cleanupDeletes().slice(1).map(({ pathname }) => pathname),
    expectedDeletePaths(readyReceipt),
  );
  assert.equal(storage.snapshot().status, 'removed');
  assert.equal(provider.liveResourceCount(), 0);
});

test('retained uninstall state rejects a newly signed but different root receipt before provider access', async () => {
  const { readyReceipt, storage, provider } = await installed();
  const dnsPath = expectedDeletePaths(readyReceipt)[0];
  let ambiguousDelete = true;
  provider.intercept(({ request }) => {
    if (request.method === 'DELETE' && new URL(request.url).pathname === dnsPath && ambiguousDelete) {
      ambiguousDelete = false;
      throw new Error('synthetic ambiguous transport outcome');
    }
    return undefined;
  });
  const first = await runCleanupCore(
    await uninstallRequest({ readyReceipt }), environment(), storage, provider.fetch,
  );
  assert.equal(first.status, 409);
  const providerCalls = provider.requests.length;

  const different = structuredClone(readyReceipt);
  different.resources[0].desiredHash = `sha256:${'9'.repeat(64)}`;
  const differentReceipt = await resealReadyReceipt(different);
  const mismatch = await runCleanupCore(
    await uninstallRequest({ readyReceipt: differentReceipt, requestId: 'B'.repeat(22) }),
    environment(),
    storage,
    async () => assert.fail('mismatched root receipt must not reach provider'),
  );
  assert.equal(mismatch.status, 409);
  assert.deepEqual(await mismatch.json(), {
    schemaVersion: 1, error: 'uninstall_request_mismatch', retryable: false,
  });
  assert.equal(provider.requests.length, providerCalls);
  assert.equal(storage.snapshot().status, 'uninstalling');
});

test('a corrupted retained removed receipt fails as repair-required without provider access', async () => {
  const { readyReceipt, storage, provider } = await installed();
  await runCleanupCore(await uninstallRequest({ readyReceipt }), environment(), storage, provider.fetch);
  const corrupted = storage.snapshot();
  corrupted.removedReceipt.checksum = `sha256:${'0'.repeat(64)}`;
  const corruptedStorage = memoryStorage(corrupted);
  const response = await runCleanupCore(
    await uninstallRequest({ readyReceipt, requestId: 'B'.repeat(22) }),
    environment(),
    corruptedStorage,
    async () => assert.fail('corrupt tombstone must not reach provider'),
  );
  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), {
    schemaVersion: 1, error: 'uninstall_requires_repair', retryable: false,
  });
});

test('cleanup refuses ownership drift before issuing a DELETE', async () => {
  const gateway = await installed();
  const { readyReceipt, storage, provider } = gateway;
  const dnsPath = expectedDeletePaths(readyReceipt)[0];
  provider.intercept(({ request }) => {
    if (request.method === 'GET' && new URL(request.url).pathname === dnsPath) {
      return Response.json({
        success: true,
        result: { id: readyReceipt.resources[6].provider.id, name: HOSTNAME, comment: 'foreign-owner' },
      });
    }
    return undefined;
  });
  const response = await runCleanupCore(
    await uninstallRequest({ readyReceipt }), environment(), storage, provider.fetch,
  );
  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), {
    schemaVersion: 1, error: 'uninstall_requires_repair', retryable: false,
  });
  assert.equal(gateway.cleanupDeletes().length, 0);
  assert.deepEqual(storage.snapshot().removedKinds, []);
  assert.equal(storage.snapshot().pending, null);
  assert.equal(storage.snapshot().status, 'uninstalling');
  assert.equal(provider.liveResourceCount(), 7);
});

test('cleanup refuses a source application that lost its ownership marker', async () => {
  const gateway = await installed();
  const { readyReceipt, storage, provider } = gateway;
  const sourceApp = readyReceipt.resources[1];
  provider.state.apps.get(sourceApp.provider.id).name = 'Renamed by an operator';
  const response = await runCleanupCore(
    await uninstallRequest({ readyReceipt }), environment(), storage, provider.fetch,
  );
  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), {
    schemaVersion: 1, error: 'uninstall_requires_repair', retryable: false,
  });
  // DNS, the Portal policy and application, the Portal, and the source policy
  // were removed; the renamed application and its server await a separate
  // authority rather than an inferred deletion.
  assert.deepEqual(storage.snapshot().removedKinds, DELETE_ORDER.slice(0, 5));
  assert.equal(gateway.cleanupDeletes().length, 5);
  assert.equal(provider.liveResourceCount(), 2);
  assert.ok(provider.state.apps.has(sourceApp.provider.id));
  assert.ok(provider.state.server);
});

test('a provider response stream failure remains an unknown read and performs no DELETE', async () => {
  const gateway = await installed();
  const { readyReceipt, storage, provider } = gateway;
  const dnsPath = expectedDeletePaths(readyReceipt)[0];
  provider.intercept(({ request }) => {
    if (request.method === 'GET' && new URL(request.url).pathname === dnsPath) {
      return new Response(new ReadableStream({
        start(controller) {
          controller.error(new Error('synthetic provider stream failure'));
        },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    return undefined;
  });
  const response = await runCleanupCore(
    await uninstallRequest({ readyReceipt }), environment(), storage, provider.fetch,
  );
  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), {
    schemaVersion: 1, error: 'uninstall_recovery_required', retryable: true,
  });
  assert.equal(gateway.cleanupDeletes().length, 0);
  assert.equal(provider.liveResourceCount(), 7);
});

test('cleanup accepts a streamed provider response above the former 64 KiB cap', async () => {
  const gateway = await installed();
  const { readyReceipt, storage, provider } = gateway;
  const dnsPath = expectedDeletePaths(readyReceipt)[0];
  let injectedBytes = 0;
  provider.intercept(({ request }) => {
    if (injectedBytes === 0 && request.method === 'GET' && new URL(request.url).pathname === dnsPath) {
      const serialized = JSON.stringify({
        success: true,
        errors: [],
        messages: [],
        result: { ...provider.state.dns, padding: 'x'.repeat(2_500_000) },
      });
      injectedBytes = Buffer.byteLength(serialized);
      return new Response(serialized, {
        headers: { 'content-type': 'application/json; charset=utf-8' },
      });
    }
    return undefined;
  });
  const response = await runCleanupCore(
    await uninstallRequest({ readyReceipt }), environment(), storage, provider.fetch,
  );
  assert.equal(response.status, 200, await response.clone().text());
  assert.ok(injectedBytes > 64 * 1024);
  assert.ok(injectedBytes < 4 * 1024 * 1024);
  assert.equal(gateway.cleanupDeletes().length, 7);
  assert.equal(provider.liveResourceCount(), 0);
});

test('a provider response above the 4 MiB bound performs no DELETE', async () => {
  const gateway = await installed();
  const { readyReceipt, storage, provider } = gateway;
  const dnsPath = expectedDeletePaths(readyReceipt)[0];
  let responseBodyCancelled = false;
  provider.intercept(({ request }) => {
    if (request.method === 'GET' && new URL(request.url).pathname === dnsPath) {
      return new Response(new ReadableStream({
        cancel() { responseBodyCancelled = true; },
      }), {
        headers: {
          'content-length': String((4 * 1024 * 1024) + 1),
          'content-type': 'application/json',
        },
      });
    }
    return undefined;
  });
  const response = await runCleanupCore(
    await uninstallRequest({ readyReceipt }), environment(), storage, provider.fetch,
  );
  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), {
    schemaVersion: 1, error: 'uninstall_requires_repair', retryable: false,
  });
  assert.equal(responseBodyCancelled, true);
  assert.equal(gateway.cleanupDeletes().length, 0);
  assert.equal(provider.liveResourceCount(), 7);
});

test('a chunked provider response crossing the 4 MiB bound performs no DELETE', async () => {
  const gateway = await installed();
  const { readyReceipt, storage, provider } = gateway;
  const dnsPath = expectedDeletePaths(readyReceipt)[0];
  provider.intercept(({ request }) => {
    if (request.method === 'GET' && new URL(request.url).pathname === dnsPath) {
      return new Response(new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(4 * 1024 * 1024));
          controller.enqueue(new Uint8Array(1));
          controller.close();
        },
      }), { headers: { 'content-type': 'application/json' } });
    }
    return undefined;
  });
  const response = await runCleanupCore(
    await uninstallRequest({ readyReceipt }), environment(), storage, provider.fetch,
  );
  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), {
    schemaVersion: 1, error: 'uninstall_requires_repair', retryable: false,
  });
  assert.equal(gateway.cleanupDeletes().length, 0);
  assert.equal(provider.liveResourceCount(), 7);
});

test('cleanup rejects bad HMAC, noncanonical bodies, drifted receipts, and expired grants before state access', async () => {
  const { readyReceipt } = await installed();
  const cases = [];
  cases.push(await uninstallRequest({ readyReceipt, signatureHeader: `sha256=${'0'.repeat(64)}` }));

  const claim = await uninstallClaim({ requestId: 'C'.repeat(22), readyReceipt });
  const noncanonical = JSON.stringify(claim, null, 2);
  cases.push(await uninstallRequest({ rawBody: noncanonical, signatureHeader: await signature(noncanonical) }));

  const driftedReceipt = structuredClone(readyReceipt);
  driftedReceipt.resources[6].marker = 'acg:v1:foreign:dns-record';
  const driftedBody = canonicalJson(await uninstallClaim({ requestId: 'D'.repeat(22), readyReceipt: driftedReceipt }));
  cases.push(await uninstallRequest({ rawBody: driftedBody, signatureHeader: await signature(driftedBody) }));

  const duplicateApplicationReceipt = structuredClone(readyReceipt);
  duplicateApplicationReceipt.resources[4].provider.id = duplicateApplicationReceipt.resources[1].provider.id;
  duplicateApplicationReceipt.resources[5].provider.parentId = duplicateApplicationReceipt.resources[1].provider.id;
  const duplicateBody = canonicalJson(await uninstallClaim({
    requestId: 'F'.repeat(22),
    readyReceipt: await resealReadyReceipt(duplicateApplicationReceipt),
  }));
  cases.push(await uninstallRequest({ rawBody: duplicateBody, signatureHeader: await signature(duplicateBody) }));

  const expiredClaim = await uninstallClaim({ requestId: 'E'.repeat(22), readyReceipt });
  expiredClaim.issuedAt = NOW_SECONDS - 301;
  expiredClaim.expiresAt = NOW_SECONDS - 1;
  const expiredBody = canonicalJson(expiredClaim);
  cases.push(await uninstallRequest({ rawBody: expiredBody, signatureHeader: await signature(expiredBody) }));

  for (const request of cases) {
    let storageReads = 0;
    const storage = {
      async get() { storageReads += 1; return undefined; },
      async put() { assert.fail('invalid request must not write state'); },
    };
    const response = await runCleanupCore(
      request, environment(), storage, async () => assert.fail('must not call provider'),
    );
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), {
      schemaVersion: 1, error: 'uninstall_rejected', retryable: false,
    });
    assert.equal(storageReads, 0);
  }
});

test('cleanup route is HMAC-only and locks all other API surfaces while uninstall is active', async () => {
  assert.equal((await cleanupWorker.fetch(new Request(`https://${HOSTNAME}/api/status`), {})).status, 423);
  assert.deepEqual(
    await (await cleanupWorker.fetch(new Request(`https://${HOSTNAME}/api/status`), {})).json(),
    { schemaVersion: 1, error: 'uninstall_in_progress' },
  );
  assert.equal((await cleanupWorker.fetch(new Request(`https://${HOSTNAME}/`), {})).status, 404);
  assert.equal((await cleanupWorker.fetch(new Request(`https://${HOSTNAME}/assets/app.js`), {})).status, 404);
  const methodResponse = await cleanupWorker.fetch(
    await uninstallRequest({ method: 'GET', readyReceipt: {} }), environment(),
  );
  assert.equal(methodResponse.status, 405);
  assert.equal(methodResponse.headers.get('allow'), 'POST');

  const { readyReceipt } = await installed();
  const request = await uninstallRequest({ readyReceipt });
  const expectedRawBody = await request.clone().text();
  const objectNames = [];
  let forwarded;
  const env = environment({
    ADMIN_STATE: {
      idFromName(name) { objectNames.push(name); return `id:${name}`; },
      get(id) {
        assert.ok(id === `id:${DURABLE_OBJECT_NAME}` || id === 'id:v1:management');
        return {
          async fetch(internal) {
            if (id === 'id:v1:management') {
              assert.equal(new URL(internal.url).pathname, '/source-uninstall');
              return Response.json({ schemaVersion: 1, status: 'removed', resourceCount: 0 });
            }
            forwarded = internal;
            return Response.json({ schemaVersion: 1, status: 'synthetic-do-result' });
          },
        };
      },
    },
  });
  const response = await cleanupWorker.fetch(request, env);
  assert.equal(response.status, 200);
  assert.deepEqual(objectNames, [DURABLE_OBJECT_NAME, 'v1:management']);
  assert.equal(new URL(forwarded.url).pathname, '/uninstall');
  assert.equal(forwarded.method, 'POST');
  assert.equal(forwarded.headers.get('authorization'), null);
  assert.equal(forwarded.headers.get('cookie'), null);
  assert.equal(await forwarded.text(), expectedRawBody);
  assert.equal(
    forwarded.headers.get('x-ankka-uninstall-signature'),
    await signature(expectedRawBody),
  );
});

test('cleanup rejects ambient browser authority headers and never reaches the Durable Object binding', async () => {
  const { readyReceipt } = await installed();
  const base = await uninstallRequest({ readyReceipt });
  const rawBody = await base.text();
  let bindingCalls = 0;
  const env = environment({
    ADMIN_STATE: {
      idFromName() { bindingCalls += 1; return 'id'; },
      get() { bindingCalls += 1; return { fetch: async () => new Response() }; },
    },
  });
  for (const [name, value] of [
    ['authorization', 'Bearer synthetic-browser-value'],
    ['cookie', 'session=synthetic'],
    ['origin', 'https://foreign.example'],
    ['referer', 'https://foreign.example/page'],
  ]) {
    const headers = new Headers(base.headers);
    headers.set(name, value);
    const response = await cleanupWorker.fetch(new Request(base.url, {
      method: 'POST', headers, body: rawBody,
    }), env);
    assert.equal(response.status, 400);
  }
  assert.equal(bindingCalls, 0);
});

test('retirement entrypoint is inert and exposes no active Durable Object class or binding surface', async () => {
  const module = await import('../payload/worker-retirement/index.js');
  assert.deepEqual(Object.keys(module), ['default']);
  for (const request of [
    new Request(`https://${HOSTNAME}/`),
    new Request(`https://${HOSTNAME}/__ankka/uninstall`, { method: 'POST', body: '{}' }),
    new Request(`https://${HOSTNAME}/api/status`),
  ]) {
    const response = await retirementWorker.fetch(request, {
      ADMIN_STATE: { get: () => assert.fail('retirement must not inspect bindings') },
    });
    assert.equal(response.status, 410);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.deepEqual(await response.json(), { schemaVersion: 1, status: 'retired' });
  }

  const source = await readFile(new URL('../payload/worker-retirement/index.js', import.meta.url), 'utf8');
  assert.equal(source.includes('export class AdminState'), false);
  assert.equal(source.includes('ADMIN_STATE'), false);
  assert.equal(source.includes('globalThis.fetch'), false);
  assert.equal(source.includes('.storage'), false);
  assert.equal(source.includes('console.'), false);
});

test('hand-authored payload layout keeps cleanup and retirement as single-module components', async () => {
  const cleanupModule = await import('../payload/worker-cleanup/index.js');
  assert.deepEqual(Object.keys(cleanupModule), ['AdminState', 'default']);
  assert.deepEqual(
    (await readdir(new URL('../payload/', import.meta.url), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort(compareText),
    ['installer', 'worker', 'worker-cleanup', 'worker-retirement'],
  );
  assert.deepEqual(await readdir(new URL('../payload/worker-cleanup/', import.meta.url)), ['index.js']);
  assert.deepEqual(await readdir(new URL('../payload/worker-retirement/', import.meta.url)), ['index.js']);
  const cleanupSource = await readFile(new URL('../payload/worker-cleanup/index.js', import.meta.url), 'utf8');
  assert.equal(cleanupSource.includes('console.'), false);
  assert.equal(cleanupSource.includes('ANKKA_BOOTSTRAP_NONCE'), false);
  assert.equal(cleanupSource.includes('/__ankka/bootstrap'), false);
  assert.equal(cleanupSource.includes("const UNINSTALL_PATH = '/__ankka/uninstall'"), true);
});
