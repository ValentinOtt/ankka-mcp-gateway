import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CloudflareGatewayProviderError,
  createCloudflareGatewayProvider,
} from '../src/cloudflare-provider.ts';
import { buildGatewayDesiredState } from '../src/plan.ts';
import {
  beginReceiptAction,
  commitReceiptAction,
  createInstallationReceipt,
  ownershipMarker,
  receiptChecksum,
} from '../src/receipt.ts';
import { CANARY_SERVICE_ID, OTHER_SERVICE_ID, canaryConfig } from './fixtures/canary-service-identity.mjs';

const TOKEN = 'test-only-provider-token';
const ACCOUNT_ID = 'account_123';
const ZONE_ID = 'zone_123';
const TARGET = {
  accountId: ACCOUNT_ID,
  zoneId: ZONE_ID,
  zoneName: 'example.com',
  zoneStatus: 'active',
  zeroTrustReady: true,
};
const ACCESS = { allowedEmails: ['Member@example.com', 'owner@example.com'] };

function config(authentication = { mode: 'none', onBehalfOfUser: false }) {
  return {
    schemaVersion: 1,
    gateway: { name: 'Example Gateway', hostname: 'mcp.example.com', codeMode: 'default_on' },
    policy: { capabilityMode: 'read_only', credentialCustody: 'customer', telemetry: 'off' },
    sources: [{
      id: 'context',
      label: 'Company context',
      url: 'https://context.example.com/mcp',
      authentication,
      enabledTools: ['company_search', 'company_prepare'],
    }],
  };
}

function success(result) {
  return new Response(JSON.stringify({ success: true, errors: [], result }), { status: 200 });
}

function notFound() {
  return new Response('not found', { status: 404 });
}

function scriptedFetch(steps) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const call = { url: new URL(url), init, body: init.body ? JSON.parse(init.body) : undefined };
    calls.push(call);
    const step = steps.shift();
    if (!step) throw new Error('unexpected request');
    if (step.method) assert.equal(init.method, step.method);
    if (step.path) assert.equal(call.url.pathname, step.path);
    if (step.error) throw step.error;
    return step.response;
  };
  return { calls, fetchImpl, remaining: steps };
}

async function resealReceipt(receipt, mutate) {
  const copy = structuredClone(receipt);
  mutate(copy);
  copy.checksum = await receiptChecksum(copy);
  return copy;
}

function provider(fetchImpl, overrides = {}) {
  return createCloudflareGatewayProvider({
    token: TOKEN,
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
    fetchImpl,
    delayImpl: async () => {},
    discoveryAttempts: 2,
    discoveryIntervalMs: 0,
    ...overrides,
  });
}

function exactSourceApp({
  id = 'app_source_123',
  serverId,
  marker,
  ...extra
}) {
  return {
    id,
    name: marker,
    type: 'mcp',
    domain: null,
    destinations: [{ type: 'via_mcp_server_portal', mcp_server_id: serverId }],
    ...extra,
  };
}

function exactPortalApp({
  id = 'app_portal_123',
  hostname = 'mcp.example.com',
  name = 'Example Gateway',
  ...extra
} = {}) {
  return {
    id,
    name,
    type: 'mcp_portal',
    domain: hostname,
    destinations: [{ type: 'public', uri: hostname }],
    oauth_configuration: {
      enabled: true,
      dynamic_client_registration: {
        enabled: true,
        allow_any_on_localhost: true,
        allow_any_on_loopback: true,
      },
      grant: { access_token_lifetime: '15m', session_duration: '336h' },
    },
    ...extra,
  };
}

function exactPendingPortal(fixture, overrides = {}) {
  return {
    id: fixture.resource.key,
    hostname: fixture.resource.desired.hostname,
    name: fixture.resource.desired.name,
    code_mode: fixture.resource.desired.codeMode,
    description: fixture.marker,
    secure_web_gateway: false,
    servers: fixture.resource.desired.sourceMappings.map((mapping) => ({
      server_id: mapping.sourceResourceKey,
      default_disabled: true,
      on_behalf: mapping.onBehalfOfUser,
      updated_prompts: [],
      updated_tools: mapping.allowedTools.map((name) => ({ name, enabled: true })),
    })),
    ...overrides,
  };
}

function exactOwnedPortal(fixture, overrides = {}) {
  const portal = fixture.desired.resources.find((resource) => resource.kind === 'portal');
  return {
    id: portal.key,
    hostname: portal.desired.hostname,
    name: portal.desired.name,
    code_mode: portal.desired.codeMode,
    description: ownershipMarker(fixture.desired.installationId, portal.key),
    secure_web_gateway: false,
    servers: portal.desired.sourceMappings.map((mapping) => ({
      server_id: mapping.sourceResourceKey,
      default_disabled: true,
      on_behalf: mapping.onBehalfOfUser,
      updated_prompts: [],
      updated_tools: mapping.allowedTools.map((name) => ({ name, enabled: true })),
    })),
    ...overrides,
  };
}

function sourcePolicyParent(fixture) {
  const applicationKey = fixture.resource.desired.sourceApplicationResourceKey;
  const application = fixture.desired.resources.find((resource) =>
    resource.kind === 'source_access_application' && resource.key === applicationKey);
  assert.ok(application);
  return {
    application,
    serverId: application.desired.sourceResourceKey,
    marker: ownershipMarker(fixture.desired.installationId, application.key),
  };
}

function exactPortalPolicy(fixture, overrides = {}) {
  const policy = fixture.desired.resources.find((resource) =>
    resource.kind === 'portal_access_policy');
  assert.ok(policy);
  return {
    id: 'policy_portal_123',
    name: ownershipMarker(fixture.desired.installationId, policy.key),
    decision: 'allow',
    include: [
      { email: { email: 'member@example.com' } },
      { email: { email: 'owner@example.com' } },
    ],
    exclude: [],
    require: [],
    ...overrides,
  };
}

function exactSourcePolicy(fixture, overrides = {}) {
  const policy = fixture.desired.resources.find((resource) =>
    resource.kind === 'source_access_policy');
  assert.ok(policy);
  return {
    id: 'policy_source_123',
    name: ownershipMarker(fixture.desired.installationId, policy.key),
    decision: 'allow',
    include: [
      { email: { email: 'member@example.com' } },
      { email: { email: 'owner@example.com' } },
    ],
    exclude: [],
    require: [],
    ...overrides,
  };
}

function dnsDependencySteps(fixture, {
  portal = exactOwnedPortal(fixture),
  app = exactPortalApp(),
  policy = exactPortalPolicy(fixture),
} = {}) {
  return [
    { response: success(portal) },
    { response: success(app) },
    { response: success([app]) },
    { response: success([policy]) },
    { response: success(policy) },
  ];
}

async function mutationFixture(kind, action, {
  accessInput = ACCESS,
  locator,
  gatewayConfig = config(),
  extraResources = [],
  includePolicyParent = true,
  receiptDesiredHash,
} = {}) {
  const desired = await buildGatewayDesiredState(gatewayConfig, {
    target: TARGET,
    access: accessInput,
  });
  const resource = desired.resources.find((candidate) => candidate.kind === kind);
  assert.ok(resource, `missing desired resource ${kind}`);
  const marker = ownershipMarker(desired.installationId, resource.key);
  const resources = action === 'create' ? [] : [{
    kind,
    key: resource.key,
    provider: locator,
    desiredHash: resource.desiredHash,
    marker,
  }];
  if (resource.desired.allow?.identityType === 'service_token' && resources.length === 1) {
    resources[0].identityHash = resource.desired.allow.identitiesHash;
  }
  if (kind === 'portal' && action === 'create') {
    const server = desired.resources.find((candidate) => candidate.kind === 'mcp_server');
    const application = desired.resources.find((candidate) =>
      candidate.kind === 'source_access_application');
    const sourcePolicy = desired.resources.find((candidate) =>
      candidate.kind === 'source_access_policy');
    resources.push(
      {
        kind: server.kind,
        key: server.key,
        provider: { id: server.key },
        desiredHash: server.desiredHash,
        marker: ownershipMarker(desired.installationId, server.key),
      },
      {
        kind: application.kind,
        key: application.key,
        provider: { id: 'app_source_123' },
        desiredHash: application.desiredHash,
        marker: ownershipMarker(desired.installationId, application.key),
      },
      {
        kind: sourcePolicy.kind,
        key: sourcePolicy.key,
        provider: { id: 'policy_source_123', parentId: 'app_source_123' },
        desiredHash: sourcePolicy.desiredHash,
        marker: ownershipMarker(desired.installationId, sourcePolicy.key),
        identityHash: sourcePolicy.desired.allow.identitiesHash,
      },
    );
  }
  const addServerParent = () => {
    const parent = desired.resources.find((candidate) => candidate.kind === 'mcp_server');
    resources.push({
      kind: parent.kind,
      key: parent.key,
      provider: { id: parent.key },
      desiredHash: parent.desiredHash,
      marker: ownershipMarker(desired.installationId, parent.key),
    });
  };
  if (includePolicyParent && kind === 'source_access_application') addServerParent();
  if (includePolicyParent && kind === 'source_access_policy') {
    addServerParent();
    const parent = desired.resources.find((candidate) => candidate.kind === 'source_access_application');
    resources.push({
      kind: parent.kind,
      key: parent.key,
      provider: { id: 'app_source_123' },
      desiredHash: parent.desiredHash,
      marker: ownershipMarker(desired.installationId, parent.key),
    });
  }
  if (includePolicyParent && (kind === 'portal_access_application'
    || kind === 'portal_access_policy')) {
    const parent = desired.resources.find((candidate) => candidate.kind === 'portal');
    resources.push({
      kind: parent.kind,
      key: parent.key,
      provider: { id: parent.key },
      desiredHash: parent.desiredHash,
      marker: ownershipMarker(desired.installationId, parent.key),
    });
  }
  if (includePolicyParent && kind === 'portal_access_policy') {
    const parent = desired.resources.find((candidate) =>
      candidate.kind === 'portal_access_application');
    resources.push({
      kind: parent.kind,
      key: parent.key,
      provider: { id: 'app_portal_123' },
      desiredHash: parent.desiredHash,
      marker: ownershipMarker(desired.installationId, parent.key),
    });
  }
  if (includePolicyParent && kind === 'dns_record') {
    const portal = desired.resources.find((candidate) => candidate.kind === 'portal');
    const application = desired.resources.find((candidate) =>
      candidate.kind === 'portal_access_application');
    const policy = desired.resources.find((candidate) =>
      candidate.kind === 'portal_access_policy');
    resources.push(
      {
        kind: portal.kind,
        key: portal.key,
        provider: { id: portal.key },
        desiredHash: portal.desiredHash,
        marker: ownershipMarker(desired.installationId, portal.key),
      },
      {
        kind: application.kind,
        key: application.key,
        provider: { id: 'app_portal_123' },
        desiredHash: application.desiredHash,
        marker: ownershipMarker(desired.installationId, application.key),
      },
      {
        kind: policy.kind,
        key: policy.key,
        provider: { id: 'policy_portal_123', parentId: 'app_portal_123' },
        desiredHash: policy.desiredHash,
        marker: ownershipMarker(desired.installationId, policy.key),
        identityHash: policy.desired.allow.identitiesHash,
      },
    );
  }
  resources.push(...extraResources);
  let receipt = await createInstallationReceipt({
    plan: {
      installationId: desired.installationId,
      desiredHash: receiptDesiredHash ?? desired.desiredHash,
      release: 'test',
    },
    target: {
      accountId: ACCOUNT_ID,
      zoneId: ZONE_ID,
      zoneName: 'example.com',
      hostname: gatewayConfig.gateway.hostname,
    },
    accessPolicy: desired.accessPolicy,
    resources,
  });
  receipt = await beginReceiptAction(receipt, {
    operationId: 'operation_123',
    type: 'apply',
    planId: 'plan_123',
    action,
    kind,
    key: resource.key,
    expectedDesiredHash: action === 'delete' ? resource.desiredHash : resource.desiredHash,
    requestHash: `sha256:${'1'.repeat(64)}`,
  });
  const change = {
    action,
    kind,
    key: resource.key,
  };
  if (action !== 'delete') {
    change.desiredHash = resource.desiredHash;
    change.desired = resource.desired;
  }
  if (locator) change.provider = locator;
  return {
    input: { change, receipt, config: gatewayConfig, target: TARGET, access: accessInput },
    desired,
    resource,
    marker,
  };
}

test('creates, syncs, and reapplies an unauthenticated server using only strict fields', async () => {
  const fixture = await mutationFixture('mcp_server', 'create');
  const key = fixture.resource.key;
  const root = `/client/v4/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/servers`;
  const mock = scriptedFetch([
    { method: 'GET', path: `${root}/${key}`, response: notFound() },
    { method: 'GET', response: success([]) },
    { method: 'POST', path: root, response: success({ id: key }) },
    { method: 'POST', path: `${root}/${key}/sync`, response: success({ status: 'waiting' }) },
    { method: 'GET', path: `${root}/${key}`, response: success({
      id: key,
      status: 'ready',
      tools: [{ name: 'company_prepare' }, { name: 'company_search' }],
    }) },
    { method: 'PUT', path: `${root}/${key}`, response: success({ id: key }) },
  ]);

  assert.deepEqual(await provider(mock.fetchImpl).applyChange(fixture.input), {
    status: 'submitted',
  });
  assert.deepEqual(mock.calls[2].body, {
    id: key,
    auth_type: 'unauthenticated',
    hostname: 'https://context.example.com/mcp',
    name: 'Company context',
    description: fixture.marker,
    secure_web_gateway: false,
    updated_prompts: [],
    updated_tools: [
      { name: 'company_prepare', enabled: true },
      { name: 'company_search', enabled: true },
    ],
  });
  assert.deepEqual(mock.calls[5].body, {
    name: 'Company context',
    description: fixture.marker,
    secure_web_gateway: false,
    updated_prompts: [],
    updated_tools: [
      { name: 'company_prepare', enabled: true },
      { name: 'company_search', enabled: true },
    ],
  });
  assert.equal(JSON.stringify(mock.calls[5].body).includes('auth_credentials'), false);
});

test('never advances to sync after an outcome-unknown server POST', async () => {
  const fixture = await mutationFixture('mcp_server', 'create');
  const key = fixture.resource.key;
  const root = `/client/v4/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/servers`;
  const mock = scriptedFetch([
    { method: 'GET', path: `${root}/${key}`, response: notFound() },
    { method: 'GET', response: success([]) },
    { method: 'POST', path: root, error: new Error('outcome unknown') },
  ]);
  await assert.rejects(
    provider(mock.fetchImpl).applyChange(fixture.input),
    (error) => error.code === 'provider_write_failed',
  );
  assert.deepEqual(mock.calls.map((call) => call.init.method), ['GET', 'GET', 'POST']);
});

test('creates an explicit source Access application under the exact receipt-owned server', async () => {
  const fixture = await mutationFixture('source_access_application', 'create');
  const serverId = fixture.resource.desired.sourceResourceKey;
  const appsRoot = `/client/v4/zones/${ZONE_ID}/access/apps`;
  const app = exactSourceApp({
    id: 'created_source_app',
    serverId,
    marker: fixture.marker,
    policies: [],
  });
  delete app.domain;
  const server = {
    id: serverId,
    description: ownershipMarker(fixture.desired.installationId, serverId),
  };
  const mock = scriptedFetch([
    { method: 'GET', response: success(server) },
    { method: 'GET', path: appsRoot, response: success([]) },
    { method: 'POST', path: appsRoot, response: success({ id: app.id }) },
    { method: 'GET', path: `${appsRoot}/${app.id}`, response: success(app) },
    { method: 'GET', response: success(server) },
    { method: 'GET', path: `${appsRoot}/${app.id}/policies`, response: success([]) },
  ]);

  assert.deepEqual(await provider(mock.fetchImpl).applyChange(fixture.input), {
    status: 'submitted',
  });
  assert.deepEqual(mock.calls[2].body, {
    name: fixture.marker,
    type: 'mcp',
    destinations: [{ type: 'via_mcp_server_portal', mcp_server_id: serverId }],
  });
});

test('never replays or continues after an outcome-unknown source Access-app POST', async () => {
  const fixture = await mutationFixture('source_access_application', 'create');
  const serverId = fixture.resource.desired.sourceResourceKey;
  const mock = scriptedFetch([
    { response: success({
      id: serverId,
      description: ownershipMarker(fixture.desired.installationId, serverId),
    }) },
    { response: success([]) },
    { method: 'POST', error: new Error('outcome unknown') },
  ]);

  await assert.rejects(
    provider(mock.fetchImpl).applyChange(fixture.input),
    (error) => error.code === 'provider_write_failed',
  );
  assert.deepEqual(mock.calls.map((call) => call.init.method), ['GET', 'GET', 'POST']);
});

for (const collision of ['marker', 'relationship']) {
  test(`source Access-app create rejects a ${collision} collision`, async () => {
    const fixture = await mutationFixture('source_access_application', 'create');
    const serverId = fixture.resource.desired.sourceResourceKey;
    const app = collision === 'marker'
      ? exactSourceApp({
        id: 'marker_collision',
        serverId: 'other-server',
        marker: fixture.marker,
      })
      : exactSourceApp({
        id: 'relationship_collision',
        serverId,
        marker: 'foreign-marker',
      });
    const mock = scriptedFetch([
      { response: success({
        id: serverId,
        description: ownershipMarker(fixture.desired.installationId, serverId),
      }) },
      { response: success([app]) },
    ]);

    await assert.rejects(
      provider(mock.fetchImpl).applyChange(fixture.input),
      (error) => error.code === 'resource_collision',
    );
    assert.equal(mock.calls.some((call) => call.init.method === 'POST'), false);
  });
}

test('deletes only the exact explicit source Access app after two empty policy checks', async () => {
  const appId = 'app_source_123';
  const fixture = await mutationFixture('source_access_application', 'delete', {
    locator: { id: appId },
  });
  const serverId = fixture.resource.desired.sourceResourceKey;
  const app = exactSourceApp({ id: appId, serverId, marker: fixture.marker, policies: [] });
  const server = {
    id: serverId,
    description: ownershipMarker(fixture.desired.installationId, serverId),
  };
  const mock = scriptedFetch([
    { response: success(app) },
    { response: success(server) },
    { response: success([]) },
    { response: success(app) },
    { response: success(server) },
    { response: success([]) },
    { method: 'DELETE', response: success(null) },
    { response: notFound() },
  ]);

  await provider(mock.fetchImpl).applyChange(fixture.input);
  assert.equal(mock.calls[6].url.pathname.endsWith(`/access/apps/${appId}`), true);
});

test('deletes an exact receipt-owned source app after its MCP server is already absent', async () => {
  const appId = 'app_source_123';
  const fixture = await mutationFixture('source_access_application', 'delete', {
    locator: { id: appId },
  });
  const serverId = fixture.resource.desired.sourceResourceKey;
  const app = exactSourceApp({ id: appId, serverId, marker: fixture.marker, policies: [] });
  const mock = scriptedFetch([
    { response: success(app) },
    { response: notFound() },
    { response: success([]) },
    { response: success(app) },
    { response: notFound() },
    { response: success([]) },
    { method: 'DELETE', response: success(null) },
    { response: notFound() },
  ]);

  await provider(mock.fetchImpl).applyChange(fixture.input);
  assert.equal(mock.calls[6].url.pathname.endsWith(`/access/apps/${appId}`), true);
});

test('source Access-app delete refuses a late policy and malformed relationship shape', async () => {
  const appId = 'app_source_123';
  const fixture = await mutationFixture('source_access_application', 'delete', {
    locator: { id: appId },
  });
  const serverId = fixture.resource.desired.sourceResourceKey;
  const app = exactSourceApp({ id: appId, serverId, marker: fixture.marker, policies: [] });
  const server = {
    id: serverId,
    description: ownershipMarker(fixture.desired.installationId, serverId),
  };
  const latePolicy = scriptedFetch([
    { response: success(app) },
    { response: success(server) },
    { response: success([]) },
    { response: success(app) },
    { response: success(server) },
    { response: success([{ id: 'late_policy', name: 'foreign' }]) },
  ]);
  await assert.rejects(
    provider(latePolicy.fetchImpl).applyChange(fixture.input),
    (error) => error.code === 'ownership_conflict',
  );
  assert.equal(latePolicy.calls.some((call) => call.init.method === 'DELETE'), false);

  const malformed = scriptedFetch([{ response: success({ ...app, domain: 'foreign.example.com' }) }]);
  await assert.rejects(
    provider(malformed.fetchImpl).applyChange(fixture.input),
    (error) => error.code === 'ownership_conflict',
  );
  assert.equal(malformed.calls.length, 1);
});

for (const kind of ['mcp_server', 'portal']) {
  const collisionLabel = kind === 'mcp_server'
    ? 'a pre-existing source Access-app relationship'
    : 'an exact orphan same-host app';
  test(`${kind} create rejects ${collisionLabel} from the pre-write baseline`, async () => {
    const fixture = await mutationFixture(kind, 'create');
    const app = kind === 'mcp_server'
      ? {
        id: 'orphan_source_app',
        type: 'mcp',
        destinations: [{ type: 'via_mcp_server_portal', mcp_server_id: fixture.resource.key }],
      }
      : exactPortalApp({ id: 'orphan_portal_app' });
    const mock = scriptedFetch([
      { response: notFound() },
      { response: success([app]) },
    ]);
    await assert.rejects(
      provider(mock.fetchImpl).applyChange(fixture.input),
      (error) => error.code === 'resource_collision',
    );
    assert.equal(mock.calls.some((call) => call.init.method === 'POST'), false);
  });
}

test('Portal create rejects a malformed same-host app before POST', async () => {
  const fixture = await mutationFixture('portal', 'create');
  const malformed = exactPortalApp({
    id: 'malformed_portal_app',
    destinations: [
      { type: 'public', uri: 'mcp.example.com' },
      { type: 'public', uri: 'other.example.com' },
    ],
  });
  const mock = scriptedFetch([
    { response: notFound() },
    { response: success([malformed]) },
  ]);

  await assert.rejects(
    provider(mock.fetchImpl).applyChange(fixture.input),
    (error) => error.code === 'resource_collision',
  );
  assert.equal(mock.calls.some((call) => call.init.method === 'POST'), false);
});

test('inspects only an exact pending-created Portal with no same-host app candidates', async () => {
  const fixture = await mutationFixture('portal', 'create');
  const live = exactPendingPortal(fixture);
  delete live.servers[0].updated_prompts;
  const mock = scriptedFetch([
    { method: 'GET', response: success(live) },
    { method: 'GET', response: success([]) },
    { method: 'GET', response: success([]) },
  ]);

  assert.deepEqual(
    await provider(mock.fetchImpl).inspectPendingPortalCreateRollback(fixture.input),
    { status: 'ready', portalKey: fixture.resource.key },
  );
  assert.deepEqual(mock.calls.map((call) => call.init.method), ['GET', 'GET', 'GET']);
  assert.equal(mock.calls[2].url.searchParams.get('name.exact'), fixture.resource.desired.hostname);
  assert.equal(mock.calls[2].url.searchParams.get('match'), 'all');
});

test('pending Portal rollback accepts an old receipt root when exact owned intent is unchanged', async () => {
  const fixture = await mutationFixture('portal', 'create', {
    receiptDesiredHash: `sha256:${'8'.repeat(64)}`,
  });
  const live = exactPendingPortal(fixture);
  const mock = scriptedFetch([
    { response: success(live) },
    { response: success([]) },
    { response: success([]) },
  ]);

  assert.deepEqual(
    await provider(mock.fetchImpl).inspectPendingPortalCreateRollback(fixture.input),
    { status: 'ready', portalKey: fixture.resource.key },
  );
  assert.equal(mock.calls.length, 3);
});

test('pending Portal root-hash exception rejects lower ownership, pending, and access drift', async () => {
  const lower = await mutationFixture('portal', 'create', {
    receiptDesiredHash: `sha256:${'8'.repeat(64)}`,
  });
  lower.input.receipt = await resealReceipt(lower.input.receipt, (receipt) => {
    receipt.resources[0].desiredHash = `sha256:${'7'.repeat(64)}`;
  });
  const lowerMock = scriptedFetch([]);
  await assert.rejects(
    provider(lowerMock.fetchImpl).inspectPendingPortalCreateRollback(lower.input),
    (error) => error.code === 'invalid_input',
  );
  assert.equal(lowerMock.calls.length, 0);

  const pending = await mutationFixture('portal', 'create', {
    receiptDesiredHash: `sha256:${'8'.repeat(64)}`,
  });
  pending.input.receipt = await resealReceipt(pending.input.receipt, (receipt) => {
    receipt.pending.expectedDesiredHash = `sha256:${'7'.repeat(64)}`;
  });
  const pendingMock = scriptedFetch([]);
  await assert.rejects(
    provider(pendingMock.fetchImpl).inspectPendingPortalCreateRollback(pending.input),
    (error) => error.code === 'invalid_input',
  );
  assert.equal(pendingMock.calls.length, 0);

  const accessDrift = await mutationFixture('portal', 'create', {
    receiptDesiredHash: `sha256:${'8'.repeat(64)}`,
  });
  accessDrift.input = {
    ...accessDrift.input,
    access: { allowedEmails: ['different@example.com'] },
  };
  const accessMock = scriptedFetch([]);
  await assert.rejects(
    provider(accessMock.fetchImpl).inspectPendingPortalCreateRollback(accessDrift.input),
    (error) => error.code === 'invalid_input',
  );
  assert.equal(accessMock.calls.length, 0);
});

test('pending Portal rollback validation binds the receipt to the complete config desired state', async () => {
  const fixture = await mutationFixture('portal', 'create');
  const mock = scriptedFetch([]);
  const mismatched = {
    ...fixture.input,
    config: {
      ...fixture.input.config,
      gateway: { ...fixture.input.config.gateway, name: 'Different Gateway' },
    },
  };

  await assert.rejects(
    provider(mock.fetchImpl).inspectPendingPortalCreateRollback(mismatched),
    (error) => error.code === 'invalid_input',
  );
  assert.equal(mock.calls.length, 0);
});

test('pending Portal rollback rejects a different selected zone name and downstream receipt ownership', async () => {
  const fixture = await mutationFixture('portal', 'create');
  const targetMock = scriptedFetch([]);
  await assert.rejects(
    provider(targetMock.fetchImpl).inspectPendingPortalCreateRollback({
      ...fixture.input,
      target: { ...fixture.input.target, zoneName: 'other.example.com' },
    }),
    (error) => error.code === 'target_mismatch',
  );
  assert.equal(targetMock.calls.length, 0);

  const downstream = await mutationFixture('portal', 'create', {
    extraResources: [{
      kind: 'dns_record',
      key: 'unexpected-dns',
      provider: { id: 'dns_record_123' },
      desiredHash: `sha256:${'2'.repeat(64)}`,
    }],
  });
  const downstreamMock = scriptedFetch([]);
  await assert.rejects(
    provider(downstreamMock.fetchImpl).inspectPendingPortalCreateRollback(downstream.input),
    (error) => error.code === 'ownership_conflict',
  );
  assert.equal(downstreamMock.calls.length, 0);
});

test('rolls back only the exact pending-created Portal after two full pre-delete reads', async () => {
  const fixture = await mutationFixture('portal', 'create');
  const live = exactPendingPortal(fixture);
  const portalRoot = `/client/v4/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/portals`;
  const mock = scriptedFetch([
    { method: 'GET', response: success(live) },
    { method: 'GET', response: success([]) },
    { method: 'GET', response: success([]) },
    { method: 'GET', response: success(live) },
    { method: 'GET', response: success([]) },
    { method: 'GET', response: success([]) },
    { method: 'DELETE', path: `${portalRoot}/${fixture.resource.key}`, response: success(null) },
    { method: 'GET', response: notFound() },
    { method: 'GET', response: success([]) },
    { method: 'GET', response: success([]) },
    { method: 'GET', response: notFound() },
    { method: 'GET', response: success([]) },
    { method: 'GET', response: success([]) },
  ]);

  assert.deepEqual(
    await provider(mock.fetchImpl).rollbackPendingPortalCreate(fixture.input),
    {
      status: 'rolled_back',
      portalKey: fixture.resource.key,
      deleteRequest: 'confirmed',
    },
  );
  assert.deepEqual(mock.calls.map((call) => call.init.method), [
    'GET', 'GET', 'GET', 'GET', 'GET', 'GET', 'DELETE',
    'GET', 'GET', 'GET', 'GET', 'GET', 'GET',
  ]);
  assert.equal(mock.calls.filter((call) => call.init.method === 'DELETE').length, 1);
  assert.equal(mock.calls.some((call) => ['POST', 'PUT'].includes(call.init.method)), false);
});

test('proves quiet absence and skips DELETE when the pending-created Portal is already gone', async () => {
  const fixture = await mutationFixture('portal', 'create');
  const mock = scriptedFetch([
    { response: notFound() },
    { response: success([]) },
    { response: success([]) },
    { response: notFound() },
    { response: success([]) },
    { response: success([]) },
    { response: notFound() },
    { response: success([]) },
    { response: success([]) },
  ]);

  assert.deepEqual(
    await provider(mock.fetchImpl).rollbackPendingPortalCreate(fixture.input),
    {
      status: 'already_absent',
      portalKey: fixture.resource.key,
      deleteRequest: 'not_needed',
    },
  );
  assert.equal(mock.calls.every((call) => call.init.method === 'GET'), true);
});

test('accepts an outcome-unknown Portal DELETE only after the whole quiet proof succeeds', async () => {
  const fixture = await mutationFixture('portal', 'create');
  const live = exactPendingPortal(fixture);
  const mock = scriptedFetch([
    { response: success(live) },
    { response: success([]) },
    { response: success([]) },
    { response: success(live) },
    { response: success([]) },
    { response: success([]) },
    { method: 'DELETE', error: new Error('outcome unknown') },
    { response: notFound() },
    { response: success([]) },
    { response: success([]) },
    { response: notFound() },
    { response: success([]) },
    { response: success([]) },
  ]);

  assert.deepEqual(
    await provider(mock.fetchImpl).rollbackPendingPortalCreate(fixture.input),
    {
      status: 'rolled_back',
      portalKey: fixture.resource.key,
      deleteRequest: 'outcome_unknown',
    },
  );
  assert.equal(mock.calls.filter((call) => call.init.method === 'DELETE').length, 1);
});

test('blocks late Portal app materialization immediately before pending-create DELETE', async () => {
  const fixture = await mutationFixture('portal', 'create');
  const live = exactPendingPortal(fixture);
  const lateApp = exactPortalApp({ id: 'late_portal_app' });
  const mock = scriptedFetch([
    { response: success(live) },
    { response: success([]) },
    { response: success([]) },
    { response: success(live) },
    { response: success([lateApp]) },
    { response: success([]) },
  ]);

  await assert.rejects(
    provider(mock.fetchImpl).rollbackPendingPortalCreate(fixture.input),
    (error) => error.code === 'ownership_conflict',
  );
  assert.equal(mock.calls.some((call) => call.init.method === 'DELETE'), false);
});

test('blocks an exact-host DNS record inserted on the second pending-create pre-delete read', async () => {
  const fixture = await mutationFixture('portal', 'create');
  const live = exactPendingPortal(fixture);
  const dnsRoot = `/client/v4/zones/${ZONE_ID}/dns_records`;
  const mock = scriptedFetch([
    { response: success(live) },
    { response: success([]) },
    { path: dnsRoot, response: success([]) },
    { response: success(live) },
    { response: success([]) },
    { path: dnsRoot, response: success([{
      id: 'late_dns_record',
      name: fixture.resource.desired.hostname,
      type: 'CNAME',
    }]) },
  ]);

  await assert.rejects(
    provider(mock.fetchImpl).rollbackPendingPortalCreate(fixture.input),
    (error) => error.code === 'ownership_conflict',
  );
  const dnsCalls = mock.calls.filter((call) => call.url.pathname === dnsRoot);
  assert.equal(dnsCalls.length, 2);
  assert.equal(dnsCalls.every((call) =>
    call.url.searchParams.get('name.exact') === fixture.resource.desired.hostname
      && call.url.searchParams.get('match') === 'all'), true);
  assert.equal(mock.calls.some((call) => call.init.method === 'DELETE'), false);
});

test('blocks Portal base drift on the second pending-create pre-delete read', async () => {
  const fixture = await mutationFixture('portal', 'create');
  const live = exactPendingPortal(fixture);
  const mock = scriptedFetch([
    { response: success(live) },
    { response: success([]) },
    { response: success([]) },
    { response: success({ ...live, name: 'Foreign Portal' }) },
    { response: success([]) },
    { response: success([]) },
  ]);

  await assert.rejects(
    provider(mock.fetchImpl).rollbackPendingPortalCreate(fixture.input),
    (error) => error.code === 'ownership_conflict',
  );
  assert.equal(mock.calls.some((call) => call.init.method === 'DELETE'), false);
});

test('keeps pending Portal cleanup blocked when a same-host app appears after DELETE', async () => {
  const fixture = await mutationFixture('portal', 'create');
  const live = exactPendingPortal(fixture);
  const lateApp = exactPortalApp({ id: 'late_portal_app' });
  const mock = scriptedFetch([
    { response: success(live) },
    { response: success([]) },
    { response: success([]) },
    { response: success(live) },
    { response: success([]) },
    { response: success([]) },
    { method: 'DELETE', response: success(null) },
    { response: notFound() },
    { response: success([lateApp]) },
    { response: success([]) },
  ]);

  await assert.rejects(
    provider(mock.fetchImpl).rollbackPendingPortalCreate(fixture.input),
    (error) => error.code === 'ownership_conflict',
  );
  assert.equal(mock.calls.filter((call) => call.init.method === 'DELETE').length, 1);
  assert.equal(mock.calls.some((call) => ['POST', 'PUT'].includes(call.init.method)), false);
});

test('does not accept a quiet proof if the exact Portal lingers in any post-delete sample', async () => {
  const fixture = await mutationFixture('portal', 'create');
  const live = exactPendingPortal(fixture);
  const mock = scriptedFetch([
    { response: success(live) },
    { response: success([]) },
    { response: success([]) },
    { response: success(live) },
    { response: success([]) },
    { response: success([]) },
    { method: 'DELETE', response: success(null) },
    { response: success(live) },
    { response: success([]) },
    { response: success([]) },
    { response: notFound() },
    { response: success([]) },
    { response: success([]) },
  ]);

  await assert.rejects(
    provider(mock.fetchImpl).rollbackPendingPortalCreate(fixture.input),
    (error) => error.code === 'sync_timeout',
  );
  assert.equal(mock.calls.filter((call) => call.init.method === 'DELETE').length, 1);
});

test('fails closed on immutable and authenticated server updates', async () => {
  const createOauth = await mutationFixture(
    'mcp_server',
    'create',
    { gatewayConfig: config({ mode: 'oauth', onBehalfOfUser: true }) },
  );
  const createMock = scriptedFetch([{ response: notFound() }]);
  await assert.rejects(provider(createMock.fetchImpl).applyChange(createOauth.input), (error) => {
    assert.equal(error.code, 'source_authorization_required');
    return true;
  });
  assert.equal(createMock.calls.length, 1);

  const initial = await buildGatewayDesiredState(config(), { target: TARGET, access: ACCESS });
  const key = initial.resources.find((resource) => resource.kind === 'mcp_server').key;
  const fixture = await mutationFixture('mcp_server', 'update', { locator: { id: key } });
  const mock = scriptedFetch([{
    response: success({
      id: key,
      hostname: 'https://other.example.com/mcp',
      auth_type: 'unauthenticated',
      description: fixture.marker,
    }),
  }]);
  await assert.rejects(provider(mock.fetchImpl).applyChange(fixture.input), (error) => {
    assert.equal(error.code, 'immutable_server_drift');
    return true;
  });
  assert.equal(mock.calls.length, 1);
});

test('creates the explicit Portal app with the native Portal name and no inline policies', async () => {
  const fixture = await mutationFixture('portal_access_application', 'create');
  const portal = exactOwnedPortal(fixture);
  const app = exactPortalApp();
  const appsRoot = `/client/v4/zones/${ZONE_ID}/access/apps`;
  const portalsRoot = `/client/v4/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/portals`;
  const mock = scriptedFetch([
    { method: 'GET', path: `${portalsRoot}/${portal.id}`, response: success(portal) },
    { method: 'GET', path: appsRoot, response: success([]) },
    { method: 'GET', path: appsRoot, response: success([]) },
    { method: 'GET', path: `${portalsRoot}/${portal.id}`, response: success(portal) },
    { method: 'GET', path: appsRoot, response: success([]) },
    { method: 'POST', path: appsRoot, response: success({ id: app.id }) },
    { method: 'GET', path: `${appsRoot}/${app.id}`, response: success(app) },
  ]);

  assert.deepEqual(await provider(mock.fetchImpl).applyChange(fixture.input), {
    status: 'submitted',
    provider: { id: app.id },
  });
  const create = mock.calls.find((call) => call.init.method === 'POST');
  assert.deepEqual(create.body, {
    name: 'Example Gateway',
    type: 'mcp_portal',
    domain: 'mcp.example.com',
    destinations: [{ type: 'public', uri: 'mcp.example.com' }],
    oauth_configuration: app.oauth_configuration,
  });
  assert.equal(create.body.name, portal.name);
  assert.equal(Object.hasOwn(create.body, 'policies'), false);
  assert.equal(mock.calls.at(-1).url.pathname, `${appsRoot}/${app.id}`);
});

test('blocks a late same-host Portal app during the quiet window before any mutation', async () => {
  const fixture = await mutationFixture('portal_access_application', 'create');
  const portal = exactOwnedPortal(fixture);
  const late = exactPortalApp({ id: 'late_portal_app' });
  let delays = 0;
  const mock = scriptedFetch([
    { response: success(portal) },
    { response: success([]) },
    { response: success([late]) },
  ]);
  await assert.rejects(
    provider(mock.fetchImpl, { delayImpl: async () => { delays += 1; } }).applyChange(fixture.input),
    (error) => error.code === 'resource_collision'
      && error.mutationOutcome === 'not_submitted',
  );
  assert.equal(delays, 1);
  assert.equal(mock.calls.some((call) => call.init.method !== 'GET'), false);
});

test('rechecks the full native Portal after the app quiet window', async () => {
  const fixture = await mutationFixture('portal_access_application', 'create');
  const portal = exactOwnedPortal(fixture);
  const mock = scriptedFetch([
    { response: success(portal) },
    { response: success([]) },
    { response: success([]) },
    { response: success({ ...portal, code_mode: 'off' }) },
  ]);
  await assert.rejects(
    provider(mock.fetchImpl).applyChange(fixture.input),
    (error) => error.code === 'ownership_conflict'
      && error.mutationOutcome === 'not_submitted',
  );
  assert.equal(mock.calls.some((call) => call.init.method !== 'GET'), false);
});

test('never classifies an app POST throw or exact-GET proof failure as not submitted', async () => {
  for (const failure of ['post', 'proof']) {
    const fixture = await mutationFixture('portal_access_application', 'create');
    const portal = exactOwnedPortal(fixture);
    const app = exactPortalApp();
    const steps = [
      { response: success(portal) },
      { response: success([]) },
      { response: success([]) },
      { response: success(portal) },
      { response: success([]) },
      failure === 'post'
        ? { method: 'POST', error: new Error('outcome unknown') }
        : { method: 'POST', response: success({ id: app.id }) },
    ];
    if (failure === 'proof') {
      steps.push({ response: success({ ...app, domain: 'other.example.com' }) });
    }
    const mock = scriptedFetch(steps);
    await assert.rejects(provider(mock.fetchImpl).applyChange(fixture.input), (error) => {
      assert.equal(error.mutationOutcome, undefined, failure);
      return true;
    });
    assert.equal(mock.calls.filter((call) => call.init.method === 'POST').length, 1);
  }
});

test('updates a receipt-owned base-only Portal app instead of replaying POST', async () => {
  const fixture = await mutationFixture('portal_access_application', 'update', {
    locator: { id: 'app_portal_123' },
  });
  const portal = exactOwnedPortal(fixture);
  const baseApp = exactPortalApp({ oauth_configuration: { enabled: false } });
  const mock = scriptedFetch([
    { response: success(portal) },
    { response: success(baseApp) },
    { response: success([baseApp]) },
    { response: success([]) },
    { response: success(baseApp) },
    { response: success(portal) },
    { response: success([]) },
    { method: 'PUT', response: success({ id: baseApp.id }) },
  ]);
  await provider(mock.fetchImpl).applyChange(fixture.input);
  assert.equal(mock.calls.some((call) => call.init.method === 'POST'), false);
  const update = mock.calls.find((call) => call.init.method === 'PUT');
  assert.equal(update.body.name, portal.name);
  assert.equal(Object.hasOwn(update.body, 'policies'), false);
  assert.equal(update.body.oauth_configuration.enabled, true);
});

test('updates a receipt-owned Portal app when its exact policy is reflected inline', async () => {
  const desired = await buildGatewayDesiredState(config(), { target: TARGET, access: ACCESS });
  const policyResource = desired.resources.find((resource) =>
    resource.kind === 'portal_access_policy');
  const fixture = await mutationFixture('portal_access_application', 'update', {
    locator: { id: 'app_portal_123' },
    extraResources: [{
      kind: policyResource.kind,
      key: policyResource.key,
      provider: { id: 'policy_portal_123', parentId: 'app_portal_123' },
      desiredHash: policyResource.desiredHash,
      marker: ownershipMarker(desired.installationId, policyResource.key),
      identityHash: policyResource.desired.allow.identitiesHash,
    }],
  });
  const policy = exactPortalPolicy(fixture);
  const app = exactPortalApp({
    oauth_configuration: { enabled: false },
    policies: [{ id: policy.id, name: policy.name }],
  });
  const mock = scriptedFetch([
    { response: success(exactOwnedPortal(fixture)) },
    { response: success(app) },
    { response: success([app]) },
    { response: success([policy]) },
    { response: success(app) },
    { response: success(exactOwnedPortal(fixture)) },
    { response: success([policy]) },
    { method: 'PUT', response: success({ id: app.id }) },
  ]);

  await provider(mock.fetchImpl).applyChange(fixture.input);

  const update = mock.calls.find((call) => call.init.method === 'PUT');
  assert.equal(update.body.oauth_configuration.enabled, true);
  assert.equal(Object.hasOwn(update.body, 'policies'), false);
});

test('updates owned server, Portal, policy, and DNS resources through exact locators', async () => {
  const serverDesired = await buildGatewayDesiredState(config(), { target: TARGET, access: ACCESS });
  const serverResource = serverDesired.resources.find((resource) => resource.kind === 'mcp_server');
  const serverFixture = await mutationFixture('mcp_server', 'update', {
    locator: { id: serverResource.key },
  });
  const serverMock = scriptedFetch([
    { response: success({
      id: serverResource.key,
      hostname: serverResource.desired.endpoint,
      auth_type: 'unauthenticated',
      description: serverFixture.marker,
    }) },
    { method: 'POST', response: success({ status: 'waiting' }) },
    { response: success({
      id: serverResource.key,
      status: 'ready',
      tools: [{ name: 'company_prepare' }, { name: 'company_search' }],
    }) },
    { method: 'PUT', response: success({ id: serverResource.key }) },
  ]);
  await provider(serverMock.fetchImpl).applyChange(serverFixture.input);
  assert.equal(serverMock.calls[3].init.method, 'PUT');
  assert.equal(Object.hasOwn(serverMock.calls[3].body, 'hostname'), false);
  assert.equal(Object.hasOwn(serverMock.calls[3].body, 'auth_type'), false);

  const portalResource = serverDesired.resources.find((resource) => resource.kind === 'portal');
  const portalFixture = await mutationFixture('portal', 'update', {
    locator: { id: portalResource.key },
  });
  const portalMock = scriptedFetch([
    { response: success({
      id: portalResource.key,
      hostname: 'mcp.example.com',
      description: portalFixture.marker,
    }) },
    { method: 'PUT', response: success({ id: portalResource.key }) },
  ]);
  await provider(portalMock.fetchImpl).applyChange(portalFixture.input);
  assert.equal(Object.hasOwn(portalMock.calls[1].body, 'id'), false);
  assert.equal(portalMock.calls[1].body.hostname, 'mcp.example.com');
  assert.equal(portalMock.calls[1].body.servers[0].id, serverResource.key);
  assert.equal(portalMock.calls[1].body.servers[0].server_id, serverResource.key);

  const sourceAppId = 'app_source_123';
  const sourcePolicyId = 'policy_source_123';
  const sourceFixture = await mutationFixture('source_access_policy', 'update', {
    locator: { id: sourcePolicyId, parentId: sourceAppId },
  });
  const sourceParent = sourcePolicyParent(sourceFixture);
  const sourceApp = exactSourceApp({
    id: sourceAppId,
    serverId: sourceParent.serverId,
    marker: sourceParent.marker,
  });
  const policyMock = scriptedFetch([
    { response: success(sourceApp) },
    { response: success({
      id: sourceParent.serverId,
      description: ownershipMarker(serverDesired.installationId, sourceParent.serverId),
    }) },
    { response: success([{ id: sourcePolicyId, name: sourceFixture.marker }]) },
    { response: success({ id: sourcePolicyId, name: sourceFixture.marker }) },
    { response: success(sourceApp) },
    { response: success({
      id: sourceParent.serverId,
      description: ownershipMarker(serverDesired.installationId, sourceParent.serverId),
    }) },
    { response: success([{ id: sourcePolicyId, name: sourceFixture.marker }]) },
    { method: 'PUT', response: success({ id: sourcePolicyId }) },
  ]);
  await provider(policyMock.fetchImpl).applyChange(sourceFixture.input);
  assert.equal(policyMock.calls[7].body.name, sourceFixture.marker);
  assert.deepEqual(policyMock.calls[7].body.exclude, []);

  const dnsId = 'dns_123';
  const dnsFixture = await mutationFixture('dns_record', 'update', { locator: { id: dnsId } });
  const dnsPolicy = exactPortalPolicy(dnsFixture);
  const dnsApp = exactPortalApp({
    policies: [{ id: dnsPolicy.id, name: dnsPolicy.name }],
  });
  const dnsMock = scriptedFetch([
    ...dnsDependencySteps(dnsFixture, { app: dnsApp, policy: dnsPolicy }),
    { response: success({ id: dnsId, name: 'mcp.example.com', comment: dnsFixture.marker }) },
    ...dnsDependencySteps(dnsFixture, { app: dnsApp, policy: dnsPolicy }),
    { method: 'PUT', response: success({ id: dnsId }) },
  ]);
  await provider(dnsMock.fetchImpl).applyChange(dnsFixture.input);
  const dnsUpdate = dnsMock.calls.find((call) => call.init.method === 'PUT');
  assert.equal(dnsUpdate.body.content, 'gateway.agents.cloudflare.com');
  assert.equal(dnsUpdate.body.ttl, 1);
});

for (const policyKind of ['source_access_policy', 'portal_access_policy']) {
  const setup = async (action, options = {}) => {
    const source = policyKind === 'source_access_policy';
    const appId = source ? 'app_source_123' : 'app_portal_123';
    const fixtureOptions = {
      gatewayConfig: canaryConfig(),
      accessInput: { canaryServiceTokenId: CANARY_SERVICE_ID },
      ...options,
    };
    if (action !== 'create') fixtureOptions.locator = { id: 'policy_123', parentId: appId };
    const fixture = await mutationFixture(policyKind, action, fixtureOptions);
    const sourceParent = source ? sourcePolicyParent(fixture) : null;
    const app = source
      ? exactSourceApp({ id: appId, serverId: sourceParent.serverId, marker: sourceParent.marker })
      : exactPortalApp({ id: appId, ...canaryConfig().gateway });
    const parent = source
      ? { id: sourceParent.serverId, description: ownershipMarker(fixture.desired.installationId, sourceParent.serverId) }
      : exactOwnedPortal(fixture);
    const policy = {
      id: 'policy_123', name: fixture.marker, decision: 'non_identity',
      include: [{ service_token: { token_id: CANARY_SERVICE_ID } }], exclude: [], require: [],
    };
    return { fixture, appId, app, parent, policy };
  };

  test(`${policyKind} creates only the exact canary Service Auth selector`, async () => {
    const { fixture, appId, app, parent, policy } = await setup('create');
    const mock = scriptedFetch([
      { response: success(app) }, { response: success(parent) }, { response: success([]) },
      { response: success(app) }, { response: success(parent) }, { response: success([]) },
      { method: 'POST', path: `/client/v4/zones/${ZONE_ID}/access/apps/${appId}/policies`, response: success({ id: policy.id }) },
    ]);
    await provider(mock.fetchImpl).applyChange(fixture.input);
    const { id: _id, ...expectedBody } = policy;
    assert.deepEqual(mock.calls[6].body, expectedBody);
    assert.equal(mock.remaining.length, 0);
    const committed = await commitReceiptAction(fixture.input.receipt, {
      provider: { id: policy.id, parentId: appId }, desiredHash: fixture.resource.desiredHash,
      marker: fixture.marker, identityHash: fixture.resource.desired.allow.identitiesHash,
    });
    assert.equal(JSON.stringify({ committed, desired: fixture.desired }).includes(CANARY_SERVICE_ID), false);
  });

  test(`${policyKind} rejects changed or mixed canary credentials before network I/O`, async () => {
    for (const accessInput of [
      { canaryServiceTokenId: OTHER_SERVICE_ID },
      { canaryServiceTokenId: CANARY_SERVICE_ID, allowedEmails: [] },
    ]) {
      const { fixture } = await setup('create');
      fixture.input.access = accessInput;
      const mock = scriptedFetch([]);
      await assert.rejects(provider(mock.fetchImpl).applyChange(fixture.input), (error) =>
        error.code === 'access_identity_mismatch' && error.mutationOutcome === 'not_submitted');
      assert.equal(mock.calls.length, 0);
    }
  });

  test(`${policyKind} refuses canary identity drift during receipt-owned cleanup`, async () => {
    for (const override of [
      { decision: 'allow' },
      { include: [{ service_token: { token_id: OTHER_SERVICE_ID } }] },
      { include: [{ any_valid_service_token: {} }] },
      { include: [{ service_token: { token_id: CANARY_SERVICE_ID, extra: true } }] },
      { include: [{ service_token: { token_id: CANARY_SERVICE_ID }, everyone: {} }] },
      { require: [{ email: { email: 'owner@example.com' } }] },
    ]) {
      const { fixture, app, parent, policy } = await setup('delete');
      const drifted = { ...policy, ...override };
      const mock = scriptedFetch([
        { response: success(app) }, { response: success(parent) },
        { response: success([drifted]) }, { response: success(drifted) },
      ]);
      await assert.rejects(provider(mock.fetchImpl).applyChange(fixture.input), (error) =>
        error.code === 'ownership_conflict' && error.mutationOutcome === 'not_submitted');
      assert.equal(mock.calls.some(({ init }) => init.method !== 'GET'), false);
    }
  });

  test(`${policyKind} rechecks machine identity before deletion and preserves an exact cleanup path`, async () => {
    for (const lateDrift of [false, true]) {
      const { fixture, app, parent, policy } = await setup('delete');
      const confirmedPolicy = lateDrift
        ? { ...policy, include: [{ service_token: { token_id: OTHER_SERVICE_ID } }] }
        : policy;
      const steps = [
        { response: success(app) }, { response: success(parent) },
        { response: success([policy]) }, { response: success(policy) },
        { response: success(app) }, { response: success(parent) },
        { response: success([confirmedPolicy]) },
      ];
      if (!lateDrift) steps.push({ method: 'DELETE', response: success({ id: policy.id }) });
      const mock = scriptedFetch(steps);
      if (lateDrift) {
        await assert.rejects(provider(mock.fetchImpl).applyChange(fixture.input), (error) =>
          error.code === 'ownership_conflict' && error.mutationOutcome === 'not_submitted');
      } else {
        await provider(mock.fetchImpl).applyChange(fixture.input);
      }
      assert.equal(mock.calls.filter(({ init }) => init.method === 'DELETE').length, lateDrift ? 0 : 1);
      assert.equal(mock.remaining.length, 0);
    }
  });
}

test('provider enforces the narrow canary guard before non-policy writes as well', async () => {
  for (const mutate of [
    (input) => { input.config.gateway.name = 'Customer gateway'; },
    (input) => { input.config.gateway.codeMode = 'default_on'; },
    (input) => { input.config.sources[0].enabledTools.push('customer_search'); },
    (input) => { input.access = { canaryServiceTokenId: OTHER_SERVICE_ID }; },
    (input) => { input.access = ACCESS; },
  ]) {
    const fixture = await mutationFixture('mcp_server', 'create', {
      gatewayConfig: canaryConfig(), accessInput: { canaryServiceTokenId: CANARY_SERVICE_ID },
    });
    mutate(fixture.input);
    const mock = scriptedFetch([]);
    await assert.rejects(provider(mock.fetchImpl).applyChange(fixture.input), (error) =>
      error.code === 'access_identity_mismatch' && error.mutationOutcome === 'not_submitted');
    assert.equal(mock.calls.length, 0);
  }
});

test('canary DNS publication requires the exact Service Auth policy at both dependency checks', async () => {
  for (const lateDrift of [false, true]) {
    const gatewayConfig = canaryConfig();
    const fixture = await mutationFixture('dns_record', 'create', {
      gatewayConfig, accessInput: { canaryServiceTokenId: CANARY_SERVICE_ID },
    });
    const app = exactPortalApp(gatewayConfig.gateway);
    const policy = exactPortalPolicy(fixture, {
      decision: 'non_identity',
      include: [{ service_token: { token_id: CANARY_SERVICE_ID } }],
    });
    const confirmedPolicy = lateDrift
      ? { ...policy, include: [{ any_valid_service_token: {} }] }
      : policy;
    const steps = [
      ...dnsDependencySteps(fixture, { app, policy }),
      { response: success([]) },
      ...dnsDependencySteps(fixture, { app, policy: confirmedPolicy }),
    ];
    if (!lateDrift) steps.push({ method: 'POST', response: success({ id: 'dns_123' }) });
    const mock = scriptedFetch(steps);
    if (lateDrift) {
      await assert.rejects(provider(mock.fetchImpl).applyChange(fixture.input), (error) =>
        error.code === 'ownership_conflict' && error.mutationOutcome === 'not_submitted');
    } else {
      await provider(mock.fetchImpl).applyChange(fixture.input);
    }
    assert.equal(mock.calls.filter(({ init }) => init.method === 'POST').length, lateDrift ? 0 : 1);
    assert.equal(mock.remaining.length, 0);
  }
});

test('creates an exact source application email policy after exact parent discovery', async () => {
  const fixture = await mutationFixture('source_access_policy', 'create');
  const parent = sourcePolicyParent(fixture);
  const serverId = parent.serverId;
  const appId = 'app_source_123';
  const appsRoot = `/client/v4/zones/${ZONE_ID}/access/apps`;
  const app = exactSourceApp({ id: appId, serverId, marker: parent.marker });
  const mock = scriptedFetch([
    { method: 'GET', path: `${appsRoot}/${appId}`, response: success(app) },
    { method: 'GET', response: success({
      id: serverId,
      description: ownershipMarker(fixture.desired.installationId, serverId),
    }) },
    { method: 'GET', path: `${appsRoot}/${appId}/policies`, response: success([]) },
    { method: 'GET', path: `${appsRoot}/${appId}`, response: success(app) },
    { method: 'GET', response: success({
      id: serverId,
      description: ownershipMarker(fixture.desired.installationId, serverId),
    }) },
    { method: 'GET', path: `${appsRoot}/${appId}/policies`, response: success([]) },
    { method: 'POST', path: `${appsRoot}/${appId}/policies`, response: success({ id: 'policy_123' }) },
  ]);

  await provider(mock.fetchImpl).applyChange(fixture.input);
  assert.deepEqual(mock.calls[6].body, {
    name: fixture.marker,
    decision: 'allow',
    include: [
      { email: { email: 'member@example.com' } },
      { email: { email: 'owner@example.com' } },
    ],
    exclude: [],
    require: [],
  });
});

test('creates one exact source Access group selector without exposing it in desired state', async () => {
  const gatewayConfig = config();
  gatewayConfig.sources[0].accessGroup = 'ERP Readers';
  const accessInput = {
    ...ACCESS,
    groups: [
      { id: 'group-unrelated', name: 'Unrelated Readers' },
      { id: 'group-erp-readers', name: 'ERP Readers' },
    ],
  };
  const fixture = await mutationFixture('source_access_policy', 'create', {
    gatewayConfig,
    accessInput,
  });
  const parent = sourcePolicyParent(fixture);
  const appId = 'app_source_123';
  const appsRoot = `/client/v4/zones/${ZONE_ID}/access/apps`;
  const app = exactSourceApp({ id: appId, serverId: parent.serverId, marker: parent.marker });
  const mock = scriptedFetch([
    { method: 'GET', path: `${appsRoot}/${appId}`, response: success(app) },
    { method: 'GET', response: success({
      id: parent.serverId,
      description: ownershipMarker(fixture.desired.installationId, parent.serverId),
    }) },
    { method: 'GET', path: `${appsRoot}/${appId}/policies`, response: success([]) },
    { method: 'GET', path: `${appsRoot}/${appId}`, response: success(app) },
    { method: 'GET', response: success({
      id: parent.serverId,
      description: ownershipMarker(fixture.desired.installationId, parent.serverId),
    }) },
    { method: 'GET', path: `${appsRoot}/${appId}/policies`, response: success([]) },
    { method: 'POST', path: `${appsRoot}/${appId}/policies`, response: success({ id: 'policy_123' }) },
  ]);

  await provider(mock.fetchImpl).applyChange(fixture.input);
  assert.deepEqual(mock.calls[6].body, {
    name: fixture.marker,
    decision: 'allow',
    include: [{ group: { id: 'group-erp-readers' } }],
    exclude: [],
    require: [],
  });
  const desiredOutput = JSON.stringify(fixture.resource.desired);
  assert.equal(desiredOutput.includes('group-erp-readers'), false);
  assert.equal(desiredOutput.includes('ERP Readers'), false);

  const receipt = await commitReceiptAction(fixture.input.receipt, {
    provider: { id: 'policy_123', parentId: appId },
    desiredHash: fixture.resource.desiredHash,
    marker: fixture.marker,
    identityHash: fixture.resource.desired.allow.identitiesHash,
  });
  const receiptPolicy = receipt.resources.find((resource) =>
    resource.kind === 'source_access_policy');
  assert.equal(receiptPolicy.identityHash, fixture.resource.desired.allow.identitiesHash);
  assert.match(receiptPolicy.identityHash, /^sha256:[0-9a-f]{64}$/);
  const receiptOutput = JSON.stringify(receipt);
  assert.equal(receiptOutput.includes('group-erp-readers'), false);
  assert.equal(receiptOutput.includes('ERP Readers'), false);
});

test('updates a changed source group binding without changing the owned policy locator', async () => {
  const gatewayConfig = config();
  gatewayConfig.sources[0].accessGroup = 'ERP Readers';
  const oldAccess = {
    ...ACCESS,
    groups: [{ id: 'group-old-sentinel', name: 'ERP Readers' }],
  };
  const newAccess = {
    ...ACCESS,
    groups: [{ id: 'group-new-sentinel', name: 'ERP Readers' }],
  };
  const oldDesired = await buildGatewayDesiredState(gatewayConfig, {
    target: TARGET,
    access: oldAccess,
  });
  const oldPolicy = oldDesired.resources.find(({ kind }) => kind === 'source_access_policy');
  const policyId = 'policy_source_123';
  const appId = 'app_source_123';
  const fixture = await mutationFixture('source_access_policy', 'update', {
    gatewayConfig,
    accessInput: newAccess,
    locator: { id: policyId, parentId: appId },
    receiptDesiredHash: oldDesired.desiredHash,
  });
  fixture.input.receipt = await resealReceipt(fixture.input.receipt, (receipt) => {
    const receiptPolicy = receipt.resources.find((resource) =>
      resource.kind === 'source_access_policy');
    receiptPolicy.desiredHash = oldPolicy.desiredHash;
    receiptPolicy.identityHash = oldPolicy.desired.allow.identitiesHash;
  });
  const parent = sourcePolicyParent(fixture);
  const app = exactSourceApp({ id: appId, serverId: parent.serverId, marker: parent.marker });
  const mock = scriptedFetch([
    { response: success(app) },
    { response: success({
      id: parent.serverId,
      description: ownershipMarker(fixture.desired.installationId, parent.serverId),
    }) },
    { response: success([{ id: policyId, name: fixture.marker }]) },
    { response: success({ id: policyId, name: fixture.marker }) },
    { response: success(app) },
    { response: success({
      id: parent.serverId,
      description: ownershipMarker(fixture.desired.installationId, parent.serverId),
    }) },
    { response: success([{ id: policyId, name: fixture.marker }]) },
    { method: 'PUT', response: success({ id: policyId }) },
  ]);

  await provider(mock.fetchImpl).applyChange(fixture.input);
  assert.deepEqual(mock.calls[7].body, {
    name: fixture.marker,
    decision: 'allow',
    include: [{ group: { id: 'group-new-sentinel' } }],
    exclude: [],
    require: [],
  });
  const committed = await commitReceiptAction(fixture.input.receipt, {
    desiredHash: fixture.resource.desiredHash,
    marker: fixture.marker,
    identityHash: fixture.resource.desired.allow.identitiesHash,
  });
  const committedPolicy = committed.resources.find((resource) =>
    resource.kind === 'source_access_policy');
  assert.deepEqual(committedPolicy.provider, { id: policyId, parentId: appId });
  assert.notEqual(committedPolicy.desiredHash, oldPolicy.desiredHash);
  assert.notEqual(committedPolicy.identityHash, oldPolicy.desired.allow.identitiesHash);
  const receiptOutput = JSON.stringify(committed);
  for (const forbidden of [
    'group-old-sentinel',
    'group-new-sentinel',
    'ERP Readers',
  ]) assert.equal(receiptOutput.includes(forbidden), false);
});

test('source group policy mutation fails closed on stale or ambiguous observations', async () => {
  const gatewayConfig = config();
  gatewayConfig.sources[0].accessGroup = 'ERP Readers';
  const validAccess = {
    ...ACCESS,
    groups: [{ id: 'group-erp-readers', name: 'ERP Readers' }],
  };
  const stale = await mutationFixture('source_access_policy', 'create', {
    gatewayConfig,
    accessInput: validAccess,
  });
  stale.input.access = {
    ...ACCESS,
    groups: [{ id: 'group-replaced', name: 'ERP Readers' }],
  };
  const staleMock = scriptedFetch([]);
  await assert.rejects(provider(staleMock.fetchImpl).applyChange(stale.input), (error) =>
    error instanceof CloudflareGatewayProviderError
      && error.code === 'access_identity_mismatch'
      && error.mutationOutcome === 'not_submitted');
  assert.equal(staleMock.calls.length, 0);

  for (const { groups, forbidden } of [
    {
      groups: [
        ...validAccess.groups,
        { id: 'group-erp-second', name: 'ERP Readers' },
      ],
      forbidden: ['group-erp-second', 'ERP Readers'],
    },
    {
      groups: [
        ...validAccess.groups,
        { id: 'group-erp-readers', name: 'Finance Readers' },
      ],
      forbidden: ['group-erp-readers', 'Finance Readers'],
    },
    {
      groups: [
        ...validAccess.groups,
        { id: 'group-unrelated-duplicate', name: 'Unrelated Readers' },
        { id: 'group-unrelated-duplicate', name: 'Unrelated Readers' },
      ],
      forbidden: ['group-unrelated-duplicate', 'Unrelated Readers'],
    },
  ]) {
    const changed = await mutationFixture('source_access_policy', 'create', {
      gatewayConfig,
      accessInput: validAccess,
    });
    changed.input.access = { ...ACCESS, groups };
    const changedMock = scriptedFetch([]);
    await assert.rejects(provider(changedMock.fetchImpl).applyChange(changed.input), (error) => {
      assert.ok(error instanceof CloudflareGatewayProviderError);
      assert.equal(error.code, 'access_identity_mismatch');
      assert.equal(error.mutationOutcome, 'not_submitted');
      const safeOutput = `${String(error)}\n${JSON.stringify(error)}`;
      for (const value of forbidden) assert.equal(safeOutput.includes(value), false);
      return true;
    });
    assert.equal(changedMock.calls.length, 0);
  }

  const ambiguous = await mutationFixture('source_access_policy', 'create', {
    gatewayConfig,
    accessInput: {
      ...ACCESS,
      groups: [
        { id: 'group-erp-a', name: 'ERP Readers' },
        { id: 'group-erp-b', name: 'ERP Readers' },
      ],
    },
  });
  const ambiguousMock = scriptedFetch([]);
  await assert.rejects(provider(ambiguousMock.fetchImpl).applyChange(ambiguous.input), (error) =>
    error instanceof CloudflareGatewayProviderError
      && error.code === 'access_identity_mismatch'
      && error.mutationOutcome === 'not_submitted');
  assert.equal(ambiguousMock.calls.length, 0);

  const rebound = await mutationFixture('source_access_policy', 'create', {
    gatewayConfig: structuredClone(gatewayConfig),
    accessInput: validAccess,
  });
  rebound.input.config.sources[0].accessGroup = 'Finance Readers';
  rebound.input.access = {
    ...validAccess,
    groups: [
      ...validAccess.groups,
      { id: 'group-finance-readers', name: 'Finance Readers' },
    ],
  };
  const reboundMock = scriptedFetch([]);
  await assert.rejects(provider(reboundMock.fetchImpl).applyChange(rebound.input), (error) =>
    error instanceof CloudflareGatewayProviderError
      && error.code === 'invalid_input'
      && error.mutationOutcome === 'not_submitted');
  assert.equal(reboundMock.calls.length, 0);
});

test('deletes an exact receipt-owned source policy after its MCP server is already absent', async () => {
  const appId = 'app_source_123';
  const policyId = 'policy_source_123';
  const fixture = await mutationFixture('source_access_policy', 'delete', {
    locator: { id: policyId, parentId: appId },
  });
  const parent = sourcePolicyParent(fixture);
  const app = exactSourceApp({
    id: appId,
    serverId: parent.serverId,
    marker: parent.marker,
  });
  const policy = { id: policyId, name: fixture.marker };
  const mock = scriptedFetch([
    { response: success(app) },
    { response: notFound() },
    { response: success([policy]) },
    { response: success(policy) },
    { response: success(app) },
    { response: notFound() },
    { response: success([policy]) },
    { method: 'DELETE', response: success(null) },
  ]);

  await provider(mock.fetchImpl).applyChange(fixture.input);
  assert.equal(mock.calls[7].url.pathname.endsWith(`/policies/${policyId}`), true);
});

test('source policy update accepts its exact inline reflection and rechecks it before PUT', async () => {
  const fixture = await mutationFixture('source_access_policy', 'update', {
    locator: { id: 'policy_source_123', parentId: 'app_source_123' },
  });
  const parent = sourcePolicyParent(fixture);
  const policy = exactSourcePolicy(fixture);
  const app = exactSourceApp({
    id: 'app_source_123',
    serverId: parent.serverId,
    marker: parent.marker,
    policies: [{ id: policy.id, name: policy.name }],
  });
  const server = {
    id: parent.serverId,
    description: ownershipMarker(fixture.desired.installationId, parent.serverId),
  };
  const mock = scriptedFetch([
    { response: success(app) },
    { response: success(server) },
    { response: success([policy]) },
    { response: success(policy) },
    { response: success(app) },
    { response: success(server) },
    { response: success([policy]) },
    { method: 'PUT', response: success({ id: policy.id }) },
  ]);

  await provider(mock.fetchImpl).applyChange(fixture.input);

  assert.equal(mock.calls.filter((call) => call.init.method === 'PUT').length, 1);
});

test('source policy update rejects foreign, duplicate, and malformed inline policies', async () => {
  for (const inlinePolicyState of ['foreign', 'duplicate', 'malformed']) {
    const fixture = await mutationFixture('source_access_policy', 'update', {
      locator: { id: 'policy_source_123', parentId: 'app_source_123' },
    });
    const parent = sourcePolicyParent(fixture);
    const policy = exactSourcePolicy(fixture);
    const exact = { id: policy.id, name: policy.name };
    const app = exactSourceApp({
      id: 'app_source_123',
      serverId: parent.serverId,
      marker: parent.marker,
      policies: inlinePolicyState === 'foreign'
        ? [exact, { id: 'policy_foreign_inline', name: 'foreign' }]
        : inlinePolicyState === 'duplicate'
          ? [exact, { ...exact }]
          : [{ name: policy.name }],
    });
    const mock = scriptedFetch([
      { response: success(app) },
      { response: success({
        id: parent.serverId,
        description: ownershipMarker(fixture.desired.installationId, parent.serverId),
      }) },
      { response: success([policy]) },
    ]);

    await assert.rejects(provider(mock.fetchImpl).applyChange(fixture.input), (error) =>
      error.code === 'ownership_conflict'
        && error.mutationOutcome === 'not_submitted');
    assert.equal(mock.calls.some((call) => call.init.method === 'PUT'), false, inlinePolicyState);
  }
});

test('source app update retains the strict empty-policy gate', async () => {
  const fixture = await mutationFixture('source_access_application', 'update', {
    locator: { id: 'app_source_123' },
  });
  const application = fixture.resource;
  const app = exactSourceApp({
    id: 'app_source_123',
    serverId: application.desired.sourceResourceKey,
    marker: fixture.marker,
    policies: [{ id: 'policy_source_123' }],
  });
  const mock = scriptedFetch([
    { response: success({
      id: application.desired.sourceResourceKey,
      description: ownershipMarker(
        fixture.desired.installationId,
        application.desired.sourceResourceKey,
      ),
    }) },
    { response: success(app) },
    { response: success([{ id: 'policy_source_123', name: 'owned' }]) },
  ]);

  await assert.rejects(provider(mock.fetchImpl).applyChange(fixture.input), (error) =>
    error.code === 'ownership_conflict'
      && error.mutationOutcome === 'not_submitted');
  assert.equal(mock.calls.some((call) => call.init.method !== 'GET'), false);
});

test('creates the Portal policy only under its exact receipt-owned explicit app', async () => {
  const fixture = await mutationFixture('portal_access_policy', 'create');
  const appId = 'app_portal_123';
  const appsRoot = `/client/v4/zones/${ZONE_ID}/access/apps`;
  const app = exactPortalApp({ id: appId });
  const portal = exactOwnedPortal(fixture);
  const mock = scriptedFetch([
    { response: success(app) },
    { response: success(portal) },
    { response: success([]) },
    { response: success(app) },
    { response: success(portal) },
    { response: success([]) },
    { method: 'POST', path: `${appsRoot}/${appId}/policies`, response: success({ id: 'policy_123' }) },
  ]);

  await provider(mock.fetchImpl).applyChange(fixture.input);
  assert.equal(mock.calls[6].body.name, fixture.marker);
  assert.equal(mock.calls.some((call) => call.url.pathname === `${appsRoot}/${appId}` && call.init.method === 'PUT'), false);
});

test('Portal policy update accepts its exact inline reflection and rechecks it before PUT', async () => {
  const fixture = await mutationFixture('portal_access_policy', 'update', {
    locator: { id: 'policy_portal_123', parentId: 'app_portal_123' },
  });
  const policy = exactPortalPolicy(fixture);
  const app = exactPortalApp({ policies: [{ id: policy.id, name: policy.name }] });
  const mock = scriptedFetch([
    { response: success(app) },
    { response: success(exactOwnedPortal(fixture)) },
    { response: success([policy]) },
    { response: success(policy) },
    { response: success(app) },
    { response: success(exactOwnedPortal(fixture)) },
    { response: success([policy]) },
    { method: 'PUT', response: success({ id: policy.id }) },
  ]);

  await provider(mock.fetchImpl).applyChange(fixture.input);

  assert.equal(mock.calls.filter((call) => call.init.method === 'PUT').length, 1);
});

test('Portal policy update blocks a foreign inline policy inserted immediately before PUT', async () => {
  const fixture = await mutationFixture('portal_access_policy', 'update', {
    locator: { id: 'policy_portal_123', parentId: 'app_portal_123' },
  });
  const policy = exactPortalPolicy(fixture);
  const app = exactPortalApp({ policies: [{ id: policy.id, name: policy.name }] });
  const lateApp = {
    ...app,
    policies: [
      ...app.policies,
      { id: 'policy_foreign_inline', name: 'foreign' },
    ],
  };
  const mock = scriptedFetch([
    { response: success(app) },
    { response: success(exactOwnedPortal(fixture)) },
    { response: success([policy]) },
    { response: success(policy) },
    { response: success(lateApp) },
    { response: success(exactOwnedPortal(fixture)) },
    { response: success([policy]) },
  ]);

  await assert.rejects(provider(mock.fetchImpl).applyChange(fixture.input), (error) =>
    error.code === 'ownership_conflict'
      && error.mutationOutcome === 'not_submitted');
  assert.equal(mock.calls.some((call) => call.init.method === 'PUT'), false);
});

test('policy create rechecks both inline and listed policy surfaces immediately before POST', async () => {
  for (const policyKind of ['source_access_policy', 'portal_access_policy']) {
    for (const lateSurface of ['inline', 'listed']) {
      const fixture = await mutationFixture(policyKind, 'create');
      const sourceParent = policyKind === 'source_access_policy'
        ? sourcePolicyParent(fixture)
        : null;
      const app = sourceParent
        ? exactSourceApp({
          id: 'app_source_123',
          serverId: sourceParent.serverId,
          marker: sourceParent.marker,
        })
        : exactPortalApp();
      const parent = sourceParent
        ? {
          id: sourceParent.serverId,
          description: ownershipMarker(fixture.desired.installationId, sourceParent.serverId),
        }
        : exactOwnedPortal(fixture);
      const lateApp = lateSurface === 'inline'
        ? { ...app, policies: [{ id: 'late_policy' }] }
        : app;
      const steps = [
        { response: success(app) },
        { response: success(parent) },
        { response: success([]) },
        { response: success(lateApp) },
        { response: success(parent) },
      ];
      if (lateSurface === 'listed') {
        steps.push({ response: success([{ id: 'late_policy', name: 'foreign' }]) });
      }
      const mock = scriptedFetch(steps);
      await assert.rejects(provider(mock.fetchImpl).applyChange(fixture.input), (error) =>
        error.code === 'ownership_conflict'
          && error.mutationOutcome === 'not_submitted');
      assert.equal(mock.calls.some((call) => call.init.method !== 'GET'), false,
        `${policyKind}:${lateSurface}`);
    }
  }
});

for (const policyKind of ['source_access_policy', 'portal_access_policy']) {
  test(`${policyKind} refuses a relationship-only parent without the exact receipt resource`, async () => {
    const fixture = await mutationFixture(policyKind, 'create', { includePolicyParent: false });
    const mock = scriptedFetch([]);
    await assert.rejects(
      provider(mock.fetchImpl).applyChange(fixture.input),
      (error) => error.code === 'ownership_conflict',
    );
    assert.equal(mock.calls.some((call) => call.init.method === 'POST'), false);
  });

  test(`${policyKind} refuses a receipt parent whose live marker drifted`, async () => {
    const fixture = await mutationFixture(policyKind, 'create');
    const sourceParent = policyKind === 'source_access_policy'
      ? sourcePolicyParent(fixture)
      : null;
    const parentId = sourceParent?.serverId ?? fixture.desired.resources.find((resource) =>
      resource.kind === 'portal').key;
    const app = policyKind === 'source_access_policy'
      ? exactSourceApp({
        id: 'app_source_123',
        serverId: parentId,
        marker: sourceParent.marker,
      })
      : exactPortalApp();
    const parent = {
      id: parentId,
      description: 'foreign-marker',
    };
    if (policyKind === 'portal_access_policy') parent.hostname = 'mcp.example.com';
    const mock = scriptedFetch([
      { response: success(app) },
      { response: success(parent) },
    ]);
    await assert.rejects(
      provider(mock.fetchImpl).applyChange(fixture.input),
      (error) => error.code === 'ownership_conflict',
    );
    assert.equal(mock.calls.some((call) => call.init.method === 'POST'), false);
  });
}

for (const action of ['create', 'update', 'delete']) {
  test(`source policy ${action} revalidates its exact bound parent immediately before mutation`, async () => {
    const policyId = 'policy_source_123';
    const appId = 'app_source_123';
    const fixtureOptions = {};
    if (action !== 'create') fixtureOptions.locator = { id: policyId, parentId: appId };
    const fixture = await mutationFixture('source_access_policy', action, fixtureOptions);
    const sourceParent = sourcePolicyParent(fixture);
    const serverId = sourceParent.serverId;
    const app = exactSourceApp({ id: appId, serverId, marker: sourceParent.marker });
    const parent = {
      id: serverId,
      description: ownershipMarker(fixture.desired.installationId, serverId),
    };
    const policy = { id: policyId, name: fixture.marker };
    const steps = action === 'create'
      ? [
        { response: success(app) },
        { response: success(parent) },
        { response: success([]) },
        { response: success(app) },
        { response: success({ ...parent, description: 'late-foreign-marker' }) },
      ]
      : [
        { response: success(app) },
        { response: success(parent) },
        { response: success([policy]) },
        { response: success(policy) },
        { response: success(app) },
        { response: success({ ...parent, description: 'late-foreign-marker' }) },
      ];
    const mock = scriptedFetch(steps);

    await assert.rejects(
      provider(mock.fetchImpl).applyChange(fixture.input),
      (error) => error.code === 'ownership_conflict',
    );
    assert.equal(
      mock.calls.some((call) => ['POST', 'PUT', 'DELETE'].includes(call.init.method)),
      false,
    );
  });
}

test('refuses unexpected Access-app policies before policy creation or Access-app update', async () => {
  const policyFixture = await mutationFixture('source_access_policy', 'create');
  const sourceParent = sourcePolicyParent(policyFixture);
  const serverId = sourceParent.serverId;
  const sourceApp = exactSourceApp({
    id: 'app_source_123', serverId, marker: sourceParent.marker,
  });
  const policyMock = scriptedFetch([
    { response: success(sourceApp) },
    { response: success({
      id: serverId,
      description: ownershipMarker(policyFixture.desired.installationId, serverId),
    }) },
    { response: success([{ id: 'foreign_policy', name: 'foreign' }]) },
  ]);
  await assert.rejects(
    provider(policyMock.fetchImpl).applyChange(policyFixture.input),
    (error) => error.code === 'ownership_conflict',
  );
  assert.equal(policyMock.calls.some((call) => call.init.method === 'POST'), false);

  const portalFixture = await mutationFixture('portal_access_application', 'update', {
    locator: { id: 'app_portal_123' },
  });
  const portal = exactOwnedPortal(portalFixture);
  const portalApp = exactPortalApp({ oauth_configuration: { enabled: false } });
  const oauthMock = scriptedFetch([
    { response: success(portal) },
    { response: success(portalApp) },
    { response: success([portalApp]) },
    { response: success([{ id: 'foreign_policy', name: 'foreign' }]) },
  ]);
  await assert.rejects(
    provider(oauthMock.fetchImpl).applyChange(portalFixture.input),
    (error) => error.code === 'ownership_conflict',
  );
  assert.equal(oauthMock.calls.some((call) => call.init.method !== 'GET'), false);
});

test('never forwards unrelated fields from an Access-app response', async () => {
  const fixture = await mutationFixture('portal_access_application', 'update', {
    locator: { id: 'app_portal_123' },
  });
  const portal = exactOwnedPortal(fixture);
  const app = exactPortalApp({
    oauth_configuration: { enabled: false },
    client_secret: 'must-never-be-forwarded',
    allowed_idps: ['idp_123'],
  });
  const mock = scriptedFetch([
    { response: success(portal) },
    { response: success(app) },
    { response: success([app]) },
    { response: success([]) },
    { response: success(app) },
    { response: success(portal) },
    { response: success([]) },
    { method: 'PUT', response: success({ id: app.id }) },
  ]);

  await provider(mock.fetchImpl).applyChange(fixture.input);
  const update = mock.calls.find((call) => call.init.method === 'PUT');
  assert.equal(JSON.stringify(update.body).includes('must-never-be-forwarded'), false);
  assert.equal(Object.hasOwn(update.body, 'allowed_idps'), false);
});

test('creates only the exact proxied automatic-TTL Portal CNAME', async () => {
  const fixture = await mutationFixture('dns_record', 'create');
  const portal = exactOwnedPortal(fixture);
  const policy = exactPortalPolicy(fixture);
  const app = exactPortalApp({ policies: [{ id: policy.id, name: policy.name }] });
  const dnsRoot = `/client/v4/zones/${ZONE_ID}/dns_records`;
  const mock = scriptedFetch([
    { response: success(portal) },
    { response: success(app) },
    { response: success([app]) },
    { response: success([policy]) },
    { response: success(policy) },
    { method: 'GET', path: dnsRoot, response: success([]) },
    { response: success(portal) },
    { response: success(app) },
    { response: success([app]) },
    { response: success([policy]) },
    { response: success(policy) },
    { method: 'POST', path: dnsRoot, response: success({ id: 'dns_123' }) },
  ]);

  await provider(mock.fetchImpl).applyChange(fixture.input);
  assert.equal(mock.calls[5].url.search, '?name.exact=mcp.example.com&match=all&page=1&per_page=100');
  assert.deepEqual(mock.calls[11].body, {
    type: 'CNAME',
    name: 'mcp.example.com',
    content: 'gateway.agents.cloudflare.com',
    proxied: true,
    ttl: 1,
    comment: fixture.marker,
  });
});

test('DNS create rechecks explicit-app and Portal-policy authority after the DNS lookup', async () => {
  for (const drift of ['application', 'policy']) {
    const fixture = await mutationFixture('dns_record', 'create');
    const portal = exactOwnedPortal(fixture);
    const app = exactPortalApp();
    const policyResource = fixture.desired.resources.find((resource) =>
      resource.kind === 'portal_access_policy');
    const policy = {
      id: 'policy_portal_123',
      name: ownershipMarker(fixture.desired.installationId, policyResource.key),
      decision: 'allow',
      include: [
        { email: { email: 'member@example.com' } },
        { email: { email: 'owner@example.com' } },
      ],
      exclude: [],
      require: [],
    };
    const steps = [
      { response: success(portal) },
      { response: success(app) },
      { response: success([app]) },
      { response: success([policy]) },
      { response: success(policy) },
      { response: success([]) },
      { response: success(portal) },
      { response: success(drift === 'application'
        ? { ...app, oauth_configuration: { enabled: false } }
        : app) },
    ];
    if (drift === 'policy') steps.push(
      { response: success([app]) },
      { response: success([policy]) },
      { response: success({ ...policy, decision: 'deny' }) },
    );
    const mock = scriptedFetch(steps);
    await assert.rejects(provider(mock.fetchImpl).applyChange(fixture.input), (error) =>
      error.code === 'ownership_conflict'
        && error.mutationOutcome === 'not_submitted');
    assert.equal(mock.calls.some((call) => call.init.method !== 'GET'), false, drift);
  }
});

test('DNS update proves the exact Portal, app, and policy both before and after its DNS read', async () => {
  const fixture = await mutationFixture('dns_record', 'update', {
    locator: { id: 'dns_123' },
  });
  const policy = exactPortalPolicy(fixture);
  const app = exactPortalApp({ policies: [{ id: policy.id, name: policy.name }] });
  const mock = scriptedFetch([
    ...dnsDependencySteps(fixture, { app, policy }),
    { response: success({ id: 'dns_123', name: 'mcp.example.com', comment: fixture.marker }) },
    ...dnsDependencySteps(fixture, { app, policy }),
    { method: 'PUT', response: success({ id: 'dns_123' }) },
  ]);

  await provider(mock.fetchImpl).applyChange(fixture.input);

  assert.equal(mock.calls.filter((call) => call.init.method === 'GET').length, 11);
  assert.equal(mock.calls.filter((call) => call.init.method === 'PUT').length, 1);
});

test('DNS update blocks dependency drift or disappearance after its first proof', async () => {
  for (const lateFailure of ['portal_drift', 'application_missing', 'policy_missing']) {
    const fixture = await mutationFixture('dns_record', 'update', {
      locator: { id: 'dns_123' },
    });
    const policy = exactPortalPolicy(fixture);
    const app = exactPortalApp({ policies: [{ id: policy.id, name: policy.name }] });
    const steps = [
      ...dnsDependencySteps(fixture, { app, policy }),
      { response: success({ id: 'dns_123', name: 'mcp.example.com', comment: fixture.marker }) },
    ];
    if (lateFailure === 'portal_drift') {
      steps.push({ response: success(exactOwnedPortal(fixture, { description: 'foreign' })) });
    } else if (lateFailure === 'application_missing') {
      steps.push(
        { response: success(exactOwnedPortal(fixture)) },
        { response: notFound() },
      );
    } else {
      steps.push(
        { response: success(exactOwnedPortal(fixture)) },
        { response: success(app) },
        { response: success([app]) },
        { response: success([]) },
      );
    }
    const mock = scriptedFetch(steps);

    await assert.rejects(provider(mock.fetchImpl).applyChange(fixture.input), (error) =>
      error.code === 'ownership_conflict'
        && error.mutationOutcome === 'not_submitted');
    assert.equal(mock.calls.some((call) => call.init.method === 'PUT'), false, lateFailure);
  }
});

test('DNS mutations reject foreign or duplicate Portal policies reflected inline', async () => {
  for (const inlinePolicyState of ['foreign', 'duplicate']) {
    const fixture = await mutationFixture('dns_record', 'update', {
      locator: { id: 'dns_123' },
    });
    const policy = exactPortalPolicy(fixture);
    const exact = { id: policy.id, name: policy.name };
    const app = exactPortalApp({
      policies: inlinePolicyState === 'foreign'
        ? [exact, { id: 'policy_foreign_inline', name: 'foreign' }]
        : [exact, { ...exact }],
    });
    const mock = scriptedFetch([
      { response: success(exactOwnedPortal(fixture)) },
      { response: success(app) },
      { response: success([app]) },
      { response: success([policy]) },
    ]);

    await assert.rejects(provider(mock.fetchImpl).applyChange(fixture.input), (error) =>
      error.code === 'ownership_conflict'
        && error.mutationOutcome === 'not_submitted');
    assert.equal(mock.calls.some((call) => call.init.method === 'PUT'), false, inlinePolicyState);
  }
});

test('refuses deletes whose live ownership marker no longer matches', async () => {
  const desired = await buildGatewayDesiredState(config(), { target: TARGET, access: ACCESS });
  const portal = desired.resources.find((resource) => resource.kind === 'portal');
  const fixture = await mutationFixture('portal', 'delete', { locator: { id: portal.key } });
  const mock = scriptedFetch([{ response: success({ id: portal.key, description: 'foreign' }) }]);

  await assert.rejects(provider(mock.fetchImpl).applyChange(fixture.input), (error) => {
    assert.equal(error.code, 'ownership_conflict');
    return true;
  });
  assert.equal(mock.calls.length, 1);
});

test('Portal delete refuses a late policy attached to a same-host app', async () => {
    const desired = await buildGatewayDesiredState(config(), { target: TARGET, access: ACCESS });
    const resource = desired.resources.find((candidate) => candidate.kind === 'portal');
    const fixture = await mutationFixture('portal', 'delete', { locator: { id: resource.key } });
    const app = exactPortalApp();
    const mock = scriptedFetch([
      { response: success({ id: resource.key, description: fixture.marker }) },
      { response: success([app]) },
      { response: success(app) },
      { response: success([{ id: 'late_policy', name: 'late foreign policy' }]) },
    ]);
    await assert.rejects(
      provider(mock.fetchImpl).applyChange(fixture.input),
      (error) => error.code === 'ownership_conflict',
    );
    assert.equal(mock.calls.some((call) => call.init.method === 'DELETE'), false);
});

test('server delete succeeds only after two reads prove no source Access applications remain', async () => {
  const desired = await buildGatewayDesiredState(config(), { target: TARGET, access: ACCESS });
  const server = desired.resources.find((resource) => resource.kind === 'mcp_server');
  const absentFixture = await mutationFixture('mcp_server', 'delete', { locator: { id: server.key } });
  const absentMock = scriptedFetch([
    { response: success({ id: server.key, description: absentFixture.marker }) },
    { response: success([]) },
    { response: success({ id: server.key, description: absentFixture.marker }) },
    { response: success([]) },
    { method: 'DELETE', response: success(null) },
  ]);
  await provider(absentMock.fetchImpl).applyChange(absentFixture.input);

  const app = {
    id: 'app_source_123',
    type: 'mcp',
    destinations: [{ type: 'via_mcp_server_portal', mcp_server_id: server.key }],
  };
  const ambiguousFixture = await mutationFixture('mcp_server', 'delete', { locator: { id: server.key } });
  const ambiguousMock = scriptedFetch([
    { response: success({ id: server.key, description: ambiguousFixture.marker }) },
    { response: success([app, { ...app, id: 'generated_source_app_2' }]) },
  ]);
  await assert.rejects(
    provider(ambiguousMock.fetchImpl).applyChange(ambiguousFixture.input),
    (error) => error.code === 'ownership_conflict',
  );
  assert.equal(ambiguousMock.calls.some((call) => call.init.method === 'DELETE'), false);
});

test('server delete rejects a source Access application targeting the server', async () => {
  const desired = await buildGatewayDesiredState(config(), { target: TARGET, access: ACCESS });
  const server = desired.resources.find((resource) => resource.kind === 'mcp_server');
  const fixture = await mutationFixture('mcp_server', 'delete', { locator: { id: server.key } });
  const replacement = {
    id: 'replacement_source_app',
    type: 'mcp',
    destinations: [{ type: 'via_mcp_server_portal', mcp_server_id: server.key }],
  };
  const mock = scriptedFetch([
    { response: success({ id: server.key, description: fixture.marker }) },
    { response: success([replacement]) },
  ]);

  await assert.rejects(
    provider(mock.fetchImpl).applyChange(fixture.input),
    (error) => error.code === 'ownership_conflict',
  );
  assert.equal(mock.calls.some((call) => call.init.method === 'DELETE'), false);
});

for (const kind of ['portal']) {
  test(`${kind} delete rejects a broad same-host app after parent 404`, async () => {
    const desired = await buildGatewayDesiredState(config(), { target: TARGET, access: ACCESS });
    const resource = desired.resources.find((candidate) => candidate.kind === kind);
    const fixture = await mutationFixture(kind, 'delete', { locator: { id: resource.key } });
    const app = exactPortalApp();
    const mock = scriptedFetch([
      { response: notFound() },
      { response: success([app]) },
    ]);

    await assert.rejects(
      provider(mock.fetchImpl).applyChange(fixture.input),
      (error) => error.code === 'ownership_conflict',
    );
    assert.equal(mock.calls.some((call) => call.init.method === 'DELETE'), false);
  });

  test(`${kind} delete converges only when both the parent and exact bound app are absent`, async () => {
    const desired = await buildGatewayDesiredState(config(), { target: TARGET, access: ACCESS });
    const resource = desired.resources.find((candidate) => candidate.kind === kind);
    const fixture = await mutationFixture(kind, 'delete', { locator: { id: resource.key } });
    const mock = scriptedFetch([
      { response: notFound() },
      { response: success([]) },
      { response: notFound() },
    ]);

    assert.deepEqual(await provider(mock.fetchImpl).applyChange(fixture.input), {
      status: 'submitted',
    });
    assert.equal(mock.calls.some((call) => call.init.method === 'DELETE'), false);
  });
}

test('Portal delete requires the explicit Portal-app receipt to be removed first', async () => {
  const desired = await buildGatewayDesiredState(config(), { target: TARGET, access: ACCESS });
  const portal = desired.resources.find((resource) => resource.kind === 'portal');
  const application = desired.resources.find((resource) =>
    resource.kind === 'portal_access_application');
  const fixture = await mutationFixture('portal', 'delete', {
    locator: { id: portal.key },
    extraResources: [{
      kind: application.kind,
      key: application.key,
      provider: { id: 'app_portal_123' },
      desiredHash: application.desiredHash,
      marker: ownershipMarker(desired.installationId, application.key),
    }],
  });
  const mock = scriptedFetch([]);

  await assert.rejects(
    provider(mock.fetchImpl).applyChange(fixture.input),
    (error) => error.code === 'ownership_conflict'
      && error.mutationOutcome === 'not_submitted',
  );
  assert.equal(mock.calls.length, 0);
});

test('parent delete catches a policy inserted after its first safety read', async () => {
  const desired = await buildGatewayDesiredState(config(), { target: TARGET, access: ACCESS });
  const portal = desired.resources.find((resource) => resource.kind === 'portal');
  const fixture = await mutationFixture('portal', 'delete', { locator: { id: portal.key } });
  const app = exactPortalApp();
  const parent = {
    id: portal.key,
    hostname: 'mcp.example.com',
    description: fixture.marker,
  };
  const mock = scriptedFetch([
    { response: success(parent) },
    { response: success([app]) },
    { response: success(app) },
    { response: success([]) },
    { response: success(parent) },
    { response: success([app]) },
    { response: success(app) },
    { response: success([{ id: 'late_policy', name: 'late policy' }]) },
  ]);

  await assert.rejects(
    provider(mock.fetchImpl).applyChange(fixture.input),
    (error) => error.code === 'ownership_conflict',
  );
  assert.equal(mock.calls.some((call) => call.init.method === 'DELETE'), false);
});

for (const { kind, inlinePolicies } of [
  { kind: 'portal', inlinePolicies: { id: 'invalid_policy_shape' } },
]) {
  test(`${kind} delete rejects late inline Access-app policies even when policy listing is empty`, async () => {
    const desired = await buildGatewayDesiredState(config(), { target: TARGET, access: ACCESS });
    const resource = desired.resources.find((candidate) => candidate.kind === kind);
    const fixture = await mutationFixture(kind, 'delete', { locator: { id: resource.key } });
    const app = exactPortalApp();
    const parent = {
      id: resource.key,
      description: fixture.marker,
    };
    if (kind === 'portal') parent.hostname = 'mcp.example.com';
    const mock = scriptedFetch([
      { response: success(parent) },
      { response: success([app]) },
      { response: success(app) },
      { response: success([]) },
      { response: success(parent) },
      { response: success([app]) },
      { response: success({ ...app, policies: inlinePolicies }) },
      { response: success([]) },
    ]);

    await assert.rejects(
      provider(mock.fetchImpl).applyChange(fixture.input),
      (error) => error.code === 'ownership_conflict',
    );
    assert.equal(mock.calls.some((call) => call.init.method === 'DELETE'), false);
  });
}

test('wraps provider failures without exposing tokens or raw response details', async () => {
  const fixture = await mutationFixture('portal', 'create');
  const privateDetails = `${TOKEN} owner@example.com private-body`;
  const mock = scriptedFetch([{ error: new Error(privateDetails) }]);

  await assert.rejects(provider(mock.fetchImpl).applyChange(fixture.input), (error) => {
    assert.ok(error instanceof CloudflareGatewayProviderError);
    assert.equal(error.code, 'provider_write_failed');
    assert.doesNotMatch(error.message, new RegExp(TOKEN));
    assert.doesNotMatch(error.stack, /owner@example\.com|private-body/);
    return true;
  });
});

test('conservatively reports exact receipt IDs and broad same-host residue', async () => {
  const desired = await buildGatewayDesiredState(config(), { target: TARGET, access: ACCESS });
  const server = desired.resources.find((resource) => resource.kind === 'mcp_server');
  const sourceApplication = desired.resources.find((resource) =>
    resource.kind === 'source_access_application');
  const portal = desired.resources.find((resource) => resource.kind === 'portal');
  const portalApplication = desired.resources.find((resource) =>
    resource.kind === 'portal_access_application');
  const portalPolicy = desired.resources.find((resource) => resource.kind === 'portal_access_policy');
  const resources = [{
    kind: server.kind,
    key: server.key,
    provider: { id: server.key },
    desiredHash: server.desiredHash,
    marker: ownershipMarker(desired.installationId, server.key),
  }, {
    kind: sourceApplication.kind,
    key: sourceApplication.key,
    provider: { id: 'source_app' },
    desiredHash: sourceApplication.desiredHash,
    marker: ownershipMarker(desired.installationId, sourceApplication.key),
  }, {
    kind: portal.kind,
    key: portal.key,
    provider: { id: portal.key },
    desiredHash: portal.desiredHash,
    marker: ownershipMarker(desired.installationId, portal.key),
  }, {
    kind: portalApplication.kind,
    key: portalApplication.key,
    provider: { id: 'portal_app' },
    desiredHash: portalApplication.desiredHash,
    marker: ownershipMarker(desired.installationId, portalApplication.key),
  }];
  resources.push({
    kind: portalPolicy.kind,
    key: portalPolicy.key,
    provider: { id: 'policy_missing', parentId: 'portal_app' },
    desiredHash: portalPolicy.desiredHash,
    marker: ownershipMarker(desired.installationId, portalPolicy.key),
    identityHash: portalPolicy.desired.allow.identitiesHash,
  });
  const receipt = await createInstallationReceipt({
    plan: { installationId: desired.installationId, desiredHash: desired.desiredHash, release: 'test' },
    target: {
      accountId: ACCOUNT_ID,
      zoneId: ZONE_ID,
      zoneName: 'example.com',
      hostname: 'mcp.example.com',
    },
    accessPolicy: desired.accessPolicy,
    resources,
  });
  const appsRoot = `/client/v4/zones/${ZONE_ID}/access/apps`;
  const mock = scriptedFetch([
    { response: success({ id: server.key, description: 'drifted-marker' }) },
    { response: success({ id: 'source_app', type: 'self_hosted' }) },
    { response: success({ id: portal.key, description: 'foreign-marker' }) },
    { response: success({ id: 'portal_app', type: 'self_hosted', domain: 'drifted.example.com' }) },
    { response: notFound() },
    { method: 'GET', path: appsRoot, response: success([
      exactPortalApp({ id: 'portal_app' }),
      exactPortalApp({ id: 'unbound_same_host' }),
      exactPortalApp({ id: 'foreign_app', hostname: 'other.example.com' }),
    ]) },
  ]);

  const result = await provider(mock.fetchImpl).inspectCanaryResidue({
    config: config(), target: TARGET, receipt,
  });
  assert.deepEqual(result, { ownedResourceCount: 5 });
  assert.deepEqual(Object.keys(result), ['ownedResourceCount']);
});

test('residue exact-GETs a receipt-bound explicit app omitted from the Access-app list', async () => {
  const desired = await buildGatewayDesiredState(config(), { target: TARGET, access: ACCESS });
  const application = desired.resources.find((resource) =>
    resource.kind === 'portal_access_application');
  const boundAppId = 'portal_app_exact_only';
  const receipt = await createInstallationReceipt({
    plan: { installationId: desired.installationId, desiredHash: desired.desiredHash, release: 'test' },
    target: {
      accountId: ACCOUNT_ID,
      zoneId: ZONE_ID,
      zoneName: 'example.com',
      hostname: 'mcp.example.com',
    },
    accessPolicy: desired.accessPolicy,
    resources: [{
      kind: application.kind,
      key: application.key,
      provider: { id: boundAppId },
      desiredHash: application.desiredHash,
      marker: ownershipMarker(desired.installationId, application.key),
    }],
  });
  const mock = scriptedFetch([
    { response: success({ id: boundAppId, type: 'self_hosted', domain: 'drifted.example.com' }) },
    { response: success([]) },
  ]);

  assert.deepEqual(await provider(mock.fetchImpl).inspectCanaryResidue({
    config: config(), target: TARGET, receipt,
  }), {
    ownedResourceCount: 1,
  });
});

test('residue counts an unbound malformed same-host Portal app', async () => {
  const desired = await buildGatewayDesiredState(config(), { target: TARGET, access: ACCESS });
  const receipt = await createInstallationReceipt({
    plan: { installationId: desired.installationId, desiredHash: desired.desiredHash, release: 'test' },
    target: {
      accountId: ACCOUNT_ID,
      zoneId: ZONE_ID,
      zoneName: 'example.com',
      hostname: 'mcp.example.com',
    },
    accessPolicy: desired.accessPolicy,
    resources: [],
  });
  const malformed = exactPortalApp({
    id: 'malformed_portal_app',
    destinations: [
      { type: 'public', uri: 'mcp.example.com' },
      { type: 'public', uri: 'other.example.com' },
    ],
  });
  const mock = scriptedFetch([{ response: success([malformed]) }]);

  assert.deepEqual(await provider(mock.fetchImpl).inspectCanaryResidue({
    config: config(), target: TARGET, receipt,
  }), {
    ownedResourceCount: 1,
  });
});

test('propagates a canary residue AbortSignal through the bound client', async () => {
  const desired = await buildGatewayDesiredState(config(), { target: TARGET, access: ACCESS });
  const receipt = await createInstallationReceipt({
    plan: { installationId: desired.installationId, desiredHash: desired.desiredHash, release: 'test' },
    target: {
      accountId: ACCOUNT_ID,
      zoneId: ZONE_ID,
      zoneName: 'example.com',
      hostname: 'mcp.example.com',
    },
    accessPolicy: desired.accessPolicy,
  });
  const controller = new AbortController();
  let receivedSignal;
  let markStarted;
  const started = new Promise((resolve) => { markStarted = resolve; });
  const fetchImpl = async (_url, init) => {
    receivedSignal = init.signal;
    markStarted();
    return new Promise((_resolve, reject) => {
      init.signal.addEventListener('abort', () => reject(new Error('private abort')), { once: true });
    });
  };
  const inspection = provider(fetchImpl, { requestTimeoutMs: 1_000 }).inspectCanaryResidue({
    config: config(), target: TARGET, receipt, signal: controller.signal,
  });
  await started;
  controller.abort();
  await assert.rejects(
    inspection,
    (error) => error.code === 'provider_read_failed',
  );
  assert.equal(receivedSignal.aborted, true);
});

test('rejects unsupported construction and mutation fields before any request', async () => {
  assert.throws(
    () => createCloudflareGatewayProvider({
      token: TOKEN,
      accountId: ACCOUNT_ID,
      zoneId: ZONE_ID,
      baseUrl: 'https://attacker.invalid',
    }),
    /unsupported fields/,
  );
  const fixture = await mutationFixture('portal', 'create');
  const mock = scriptedFetch([]);
  await assert.rejects(
    provider(mock.fetchImpl).applyChange({ ...fixture.input, arbitraryBody: { unsafe: true } }),
    (error) => error.code === 'invalid_input',
  );
  assert.equal(mock.calls.length, 0);

  const tampered = structuredClone(fixture.input);
  tampered.change.desired.name = 'Tampered but schema-valid name';
  await assert.rejects(
    provider(mock.fetchImpl).applyChange(tampered),
    (error) => error.code === 'invalid_input',
  );
  assert.equal(mock.calls.length, 0);
});
