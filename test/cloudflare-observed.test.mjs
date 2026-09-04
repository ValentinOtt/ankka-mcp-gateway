import test from 'node:test';
import assert from 'node:assert/strict';
import { readCloudflareObservedState, ObservedStateError } from '../src/cloudflare-observed.ts';
import { buildGatewayDesiredState, buildGatewayPlan } from '../src/plan.ts';
import {
  beginReceiptAction,
  commitReceiptAction,
  createInstallationReceipt,
  ownershipMarker,
} from '../src/receipt.ts';
import { CANARY_SERVICE_ID, OTHER_SERVICE_ID, canaryConfig } from './fixtures/canary-service-identity.mjs';

function config() {
  return {
    schemaVersion: 1,
    gateway: { name: 'Example Gateway', hostname: 'mcp.example.com', codeMode: 'default_on' },
    policy: { capabilityMode: 'read_only', credentialCustody: 'customer', telemetry: 'off' },
    sources: [{
      id: 'context',
      label: 'Company context',
      url: 'https://context.example.com/mcp',
      authentication: { mode: 'oauth', onBehalfOfUser: true },
      enabledTools: ['company_prepare', 'company_search'],
    }],
  };
}

const target = { accountId: 'account_123', zoneId: 'zone_123' };
const access = { allowedEmails: ['OWNER@example.com', 'member@example.com'] };

async function fixture({
  accessInput = access,
  gatewayConfig = config(),
  mappingIdField = 'id',
  includeReceipt = true,
} = {}) {
  const desired = await buildGatewayDesiredState(gatewayConfig, {
    target: {
      ...target,
      zoneName: 'example.com',
      zoneStatus: 'active',
      zeroTrustReady: true,
    },
    access: accessInput,
  });
  const byKind = Object.fromEntries(desired.resources.map((resource) => [resource.kind, resource]));
  const server = byKind.mcp_server;
  const sourceApplication = byKind.source_access_application;
  const sourcePolicy = byKind.source_access_policy;
  const portal = byKind.portal;
  const portalApplication = byKind.portal_access_application;
  const portalPolicy = byKind.portal_access_policy;
  const dns = byKind.dns_record;
  const serverAppId = 'app_server_123';
  const portalAppId = 'app_portal_123';
  const sourcePolicyId = 'policy_source_123';
  const portalPolicyId = 'policy_portal_123';
  const dnsId = 'dns_123';
  const serverLive = {
    id: server.key,
    name: server.desired.name,
    hostname: server.desired.endpoint,
    auth_type: server.desired.authentication.mode === 'none' ? 'unauthenticated' : 'oauth',
    secure_web_gateway: false,
    description: ownershipMarker(desired.installationId, server.key),
    status: 'ready',
    updated_prompts: [],
    updated_tools: server.desired.toolPolicy.allowedTools.map((name) => ({ name, enabled: true })),
    auth_credentials: { client_secret: 'TOP-SECRET-SENTINEL' },
    response_body: 'RAW-BODY-SENTINEL',
    tools: [
      ...server.desired.toolPolicy.allowedTools.map((name) => ({ name })),
      { name: 'future_admin_tool' },
    ],
  };
  const portalMapping = {
    [mappingIdField]: server.key,
    default_disabled: true,
    on_behalf: gatewayConfig.sources[0].authentication.onBehalfOfUser,
    updated_prompts: [],
    updated_tools: server.desired.toolPolicy.allowedTools.map((name) => ({ name, enabled: true })),
    tools: [{ name: 'future_admin_tool', enabled: true }],
  };
  const portalLive = {
    id: portal.key,
    name: portal.desired.name,
    hostname: portal.desired.hostname,
    code_mode: portal.desired.codeMode,
    secure_web_gateway: false,
    description: ownershipMarker(desired.installationId, portal.key),
    servers: [portalMapping],
  };
  const serverApp = {
    id: serverAppId,
    name: ownershipMarker(desired.installationId, sourceApplication.key),
    type: 'mcp',
    domain: null,
    destinations: [{ type: 'via_mcp_server_portal', mcp_server_id: server.key }],
    client_secret: 'APP-SECRET-SENTINEL',
  };
  const portalApp = {
    id: portalAppId,
    name: portalApplication.desired.name,
    type: 'mcp_portal',
    domain: gatewayConfig.gateway.hostname,
    destinations: [{ type: 'public', uri: gatewayConfig.gateway.hostname }],
    oauth_configuration: {
      enabled: true,
      dynamic_client_registration: {
        enabled: true,
        allow_any_on_localhost: true,
        allow_any_on_loopback: true,
      },
      grant: { access_token_lifetime: '15m', session_duration: '336h' },
    },
  };
  const sourceGroup = sourcePolicy.desired.allow.identityType === 'group'
    ? accessInput.groups?.find((group) => group.name === gatewayConfig.sources[0].accessGroup)
    : undefined;
  const policies = {
    [serverAppId]: [{
      id: sourcePolicyId,
      name: ownershipMarker(desired.installationId, sourcePolicy.key),
      decision: 'allow',
      include: sourceGroup
        ? [{ group: { id: sourceGroup.id } }]
        : [{ email: { email: 'member@example.com' } }, { email: { email: 'owner@example.com' } }],
      exclude: [],
      require: [],
    }],
    [portalAppId]: [{
      id: portalPolicyId,
      name: ownershipMarker(desired.installationId, portalPolicy.key),
      decision: 'allow',
      include: [{ email: { email: 'owner@example.com' } }, { email: { email: 'member@example.com' } }],
      exclude: [],
      require: [],
    }],
  };
  if (desired.accessPolicy.identityType === 'service_token') {
    for (const policy of Object.values(policies).flat()) {
      policy.decision = 'non_identity';
      policy.include = [{ service_token: { token_id: accessInput.canaryServiceTokenId } }];
    }
  }
  const dnsLive = {
    id: dnsId,
    type: 'CNAME',
    name: dns.desired.hostname,
    content: `${dns.desired.content}.`,
    proxied: true,
    comment: ownershipMarker(desired.installationId, dns.key),
  };
  const resourceReceipts = [
    { kind: server.kind, key: server.key, provider: { id: server.key }, desiredHash: server.desiredHash, marker: serverLive.description },
    { kind: sourceApplication.kind, key: sourceApplication.key, provider: { id: serverAppId }, desiredHash: sourceApplication.desiredHash, marker: serverApp.name },
    { kind: sourcePolicy.kind, key: sourcePolicy.key, provider: { id: sourcePolicyId, parentId: serverAppId }, desiredHash: sourcePolicy.desiredHash, marker: policies[serverAppId][0].name },
    { kind: portal.kind, key: portal.key, provider: { id: portal.key }, desiredHash: portal.desiredHash, marker: portalLive.description },
    { kind: portalApplication.kind, key: portalApplication.key, provider: { id: portalAppId }, desiredHash: portalApplication.desiredHash, marker: ownershipMarker(desired.installationId, portalApplication.key) },
    { kind: portalPolicy.kind, key: portalPolicy.key, provider: { id: portalPolicyId, parentId: portalAppId }, desiredHash: portalPolicy.desiredHash, marker: policies[portalAppId][0].name },
    { kind: dns.kind, key: dns.key, provider: { id: dnsId }, desiredHash: dns.desiredHash, marker: dnsLive.comment },
  ];
  if (desired.accessPolicy.identityType === 'service_token') {
    for (const resource of resourceReceipts.filter(({ kind }) => kind.endsWith('_policy'))) {
      resource.identityHash = desired.accessPolicy.identitiesHash;
    }
  }
  const receipt = includeReceipt
    ? await createInstallationReceipt({
      plan: { installationId: desired.installationId, desiredHash: desired.desiredHash, release: 'test' },
      target: { ...target, zoneName: 'example.com', hostname: gatewayConfig.gateway.hostname },
      accessPolicy: desired.accessPolicy,
      resources: resourceReceipts,
    })
    : undefined;
  const calls = [];
  const cloudflare = {
    async getZone() { calls.push(['getZone']); return { id: target.zoneId, name: 'example.com', status: 'active', account: { id: target.accountId }, raw: 'ZONE-RAW-SENTINEL' }; },
    async listIdentityProviders() { calls.push(['listIdentityProviders']); return [{ id: 'idp_123' }]; },
    async getMcpServer(id) { calls.push(['getMcpServer', id]); return id === server.key ? serverLive : null; },
    async getPortal(id) { calls.push(['getPortal', id]); return id === portal.key ? portalLive : null; },
    async listDnsRecords(query) { calls.push(['listDnsRecords', query]); return [dnsLive]; },
    async getDnsRecord(id) { calls.push(['getDnsRecord', id]); return id === dnsId ? dnsLive : null; },
    async listAccessApps() { calls.push(['listAccessApps']); return [serverApp, portalApp]; },
    async getAccessApp(id) {
      calls.push(['getAccessApp', id]);
      return [serverApp, portalApp].find((app) => app.id === id) ?? null;
    },
    async listAppPolicies(id) { calls.push(['listAppPolicies', id]); return policies[id] ?? []; },
    async getAppPolicy(parentId, id) { calls.push(['getAppPolicy', parentId, id]); return (policies[parentId] ?? []).find((policy) => policy.id === id) ?? null; },
  };
  return {
    accessInput,
    gatewayConfig,
    desired,
    byKind,
    receipt,
    cloudflare,
    calls,
    serverLive,
    portalLive,
    serverApp,
    portalApp,
    policies,
    dnsLive,
    resourceReceipts,
  };
}

async function pendingCreateReceipt(data, resource, excludedKinds = [resource.kind]) {
  const receipt = await createInstallationReceipt({
    plan: { installationId: data.desired.installationId, desiredHash: data.desired.desiredHash, release: 'test' },
    target: { ...target, zoneName: 'example.com', hostname: data.gatewayConfig.gateway.hostname },
    accessPolicy: data.desired.accessPolicy,
    resources: data.resourceReceipts.filter((candidate) => !excludedKinds.includes(candidate.kind)),
  });
  return beginReceiptAction(receipt, {
    operationId: 'operation_123',
    type: 'apply',
    planId: 'plan_123',
    action: 'create',
    kind: resource.kind,
    key: resource.key,
    expectedDesiredHash: resource.desiredHash,
    requestHash: `sha256:${'2'.repeat(64)}`,
  });
}

test('verifies Cloudflare prerequisites and reduces exact receipt-owned state to planner noops', async () => {
  const data = await fixture();
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare,
    config: config(),
    target,
    access,
    receipt: data.receipt,
  });
  assert.deepEqual(observed.target, {
    accountId: 'account_123',
    zoneId: 'zone_123',
    zoneName: 'example.com',
    zoneStatus: 'active',
    zeroTrustReady: true,
  });
  assert.equal(observed.resources.length, 7);
  assert.ok(observed.resources.every((resource) => resource.owner.manager === 'ankka-mcp-gateway'));
  assert.ok(observed.resources.every((resource) => resource.desiredHash.startsWith('sha256:')));
  assert.deepEqual(data.calls.find(([name]) => name === 'listDnsRecords')[1], {
    'name.exact': 'mcp.example.com',
    match: 'all',
  });

  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.deepEqual(plan.changes.map((change) => change.action), Array(7).fill('noop'));
});

test('adding the Claude callback preserves existing receipt hashes and planner noops', async () => {
  const data = await fixture();
  data.portalApp.oauth_configuration.dynamic_client_registration.allowed_uris = [
    'https://claude.ai/api/mcp/auth_callback',
  ];
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
  });
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.deepEqual(plan.changes.map(({ action }) => action), Array(7).fill('noop'));
});

test('canary Service Auth readback is digest-only and idempotent for both applications', async () => {
  const data = await fixture({
    gatewayConfig: canaryConfig(), accessInput: { canaryServiceTokenId: CANARY_SERVICE_ID },
  });
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: data.gatewayConfig, target,
    access: data.accessInput, receipt: data.receipt,
  });
  const plan = await buildGatewayPlan(data.gatewayConfig, observed, { access: data.accessInput });
  assert.deepEqual(plan.changes.map(({ action }) => action), Array(7).fill('noop'));
  assert.equal(JSON.stringify({ observed, plan, receipt: data.receipt }).includes(CANARY_SERVICE_ID), false);
});

test('canary policy readback conflicts on every changed decision or broadened selector', async () => {
  for (const policyKind of ['source_access_policy', 'portal_access_policy']) {
    for (const override of [
      { decision: 'allow' },
      { include: [{ service_token: { token_id: OTHER_SERVICE_ID } }] },
      { include: [{ any_valid_service_token: {} }] },
      { include: [{ service_token: { token_id: CANARY_SERVICE_ID, extra: true } }] },
      { include: [{ service_token: { token_id: CANARY_SERVICE_ID }, everyone: {} }] },
      { include: [{ service_token: { token_id: CANARY_SERVICE_ID } }, { service_token: { token_id: CANARY_SERVICE_ID } }] },
      { exclude: undefined },
      { require: [{ email: { email: 'owner@example.com' } }] },
    ]) {
      const data = await fixture({
        gatewayConfig: canaryConfig(), accessInput: { canaryServiceTokenId: CANARY_SERVICE_ID },
      });
      const appId = policyKind === 'source_access_policy' ? data.serverApp.id : data.portalApp.id;
      Object.assign(data.policies[appId][0], override);
      const observed = await readCloudflareObservedState({
        cloudflare: data.cloudflare, config: data.gatewayConfig, target,
        access: data.accessInput, receipt: data.receipt,
      });
      const plan = await buildGatewayPlan(data.gatewayConfig, observed, { access: data.accessInput });
      assert.equal(plan.changes.find(({ kind }) => kind === policyKind).action, 'conflict');
    }
  }
});

test('changing a canary service identity cannot rebind receipt-owned policies', async () => {
  const data = await fixture({
    gatewayConfig: canaryConfig(), accessInput: { canaryServiceTokenId: CANARY_SERVICE_ID },
  });
  const changedAccess = { canaryServiceTokenId: OTHER_SERVICE_ID };
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: data.gatewayConfig, target,
    access: changedAccess, receipt: data.receipt,
  });
  const plan = await buildGatewayPlan(data.gatewayConfig, observed, { access: changedAccess });
  assert.deepEqual(plan.changes.filter(({ kind }) => kind.endsWith('_policy'))
    .map(({ action }) => action), ['conflict', 'conflict']);
});

test('pending canary policy recovery requires the exact live service identity proof', async () => {
  for (const policyKind of ['source_access_policy', 'portal_access_policy']) {
    for (const matching of [true, false]) {
      const data = await fixture({
        gatewayConfig: canaryConfig(), accessInput: { canaryServiceTokenId: CANARY_SERVICE_ID },
      });
      const policy = data.byKind[policyKind];
      const app = policyKind === 'source_access_policy' ? data.serverApp : data.portalApp;
      const live = data.policies[app.id][0];
      if (!matching) live.include = [{ service_token: { token_id: OTHER_SERVICE_ID } }];
      app.policies = [{ id: live.id, name: live.name }];
      const pending = await pendingCreateReceipt(data, policy);
      const observed = await readCloudflareObservedState({
        cloudflare: data.cloudflare, config: data.gatewayConfig, target,
        access: data.accessInput, receipt: pending,
      });
      const plan = await buildGatewayPlan(data.gatewayConfig, observed, { access: data.accessInput });
      assert.equal(plan.changes.find(({ kind }) => kind === policyKind).action, matching ? 'noop' : 'conflict');
    }
  }
});

test('reads back one exact source group selector and detects every selector drift', async () => {
  const gatewayConfig = config();
  gatewayConfig.sources[0].accessGroup = 'ERP Readers';
  const accessInput = {
    ...access,
    groups: [{ id: 'group-erp-readers', name: 'ERP Readers' }],
  };
  const exact = await fixture({ gatewayConfig, accessInput });
  const observed = await readCloudflareObservedState({
    cloudflare: exact.cloudflare,
    config: gatewayConfig,
    target,
    access: accessInput,
    receipt: exact.receipt,
  });
  const exactPlan = await buildGatewayPlan(gatewayConfig, observed, {
    release: 'test',
    access: accessInput,
  });
  assert.equal(
    exactPlan.changes.find((change) => change.kind === 'source_access_policy').action,
    'noop',
  );
  assert.equal(JSON.stringify(observed).includes('group-erp-readers'), false);

  for (const include of [
    [{ group: { id: 'group-wrong' } }],
    [{ group: { id: 'group-erp-readers', name: 'ERP Readers' } }],
    [{ group: { id: 'group-erp-readers' } }, { email: { email: 'owner@example.com' } }],
  ]) {
    const drift = await fixture({ gatewayConfig, accessInput });
    drift.policies.app_server_123[0].include = include;
    const driftObserved = await readCloudflareObservedState({
      cloudflare: drift.cloudflare,
      config: gatewayConfig,
      target,
      access: accessInput,
      receipt: drift.receipt,
    });
    const driftPlan = await buildGatewayPlan(gatewayConfig, driftObserved, {
      release: 'test',
      access: accessInput,
    });
    assert.equal(
      driftPlan.changes.find((change) => change.kind === 'source_access_policy').action,
      'update',
      JSON.stringify(include),
    );
  }
});

for (const mappingIdField of ['id', 'server_id']) {
  test(`normalizes portal mapping ${mappingIdField} and keeps newly discovered tools disabled`, async () => {
    const data = await fixture({ mappingIdField });
    const observed = await readCloudflareObservedState({
      cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
    });
    const portal = observed.resources.find((resource) => resource.kind === 'portal');
    assert.equal(portal.desiredHash, data.byKind.portal.desiredHash);
    assert.equal(JSON.stringify(observed).includes('future_admin_tool'), false);
  });
}

test('never returns credentials, provider bodies, errors, or raw Access identities', async () => {
  const data = await fixture();
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
  });
  const serialized = JSON.stringify(observed);
  for (const forbidden of [
    'TOP-SECRET-SENTINEL', 'RAW-BODY-SENTINEL', 'APP-SECRET-SENTINEL',
    'ZONE-RAW-SENTINEL', 'owner@example.com', 'member@example.com',
  ]) assert.equal(serialized.includes(forbidden), false);
});

test('a matching marker without a receipt is not ownership evidence', async () => {
  const data = await fixture({ includeReceipt: false });
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access,
  });
  assert.ok(observed.resources.every((resource) => Object.keys(resource.owner).length === 0));
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.ok(plan.blockers.some((blocker) => blocker.code === 'resource_conflicts'));
  assert.equal(plan.changes.find((change) =>
    change.kind === 'source_access_application').action, 'conflict');
});

test('a malformed same-host explicit Portal app conflicts without claiming the native Portal', async () => {
  const data = await fixture({ includeReceipt: false });
  const malformed = {
    ...data.portalApp,
    id: 'app_portal_malformed',
    destinations: [
      { type: 'public', uri: config().gateway.hostname },
      { type: 'public', uri: 'other.example.com' },
    ],
  };
  data.cloudflare.getMcpServer = async () => null;
  data.cloudflare.getPortal = async () => null;
  data.cloudflare.listDnsRecords = async () => [];
  data.cloudflare.listAccessApps = async () => [malformed];
  data.cloudflare.getAccessApp = async (id) => id === malformed.id ? malformed : null;

  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access,
  });
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.equal(plan.changes.find((change) => change.kind === 'portal').action, 'create');
  assert.equal(plan.changes.find((change) =>
    change.kind === 'portal_access_application').action, 'conflict');
});

test('an exact checksum-protected pending create intent can recover ownership after a timeout', async () => {
  const data = await fixture();
  const server = data.byKind.mcp_server;
  delete data.serverLive.updated_prompts;
  const baseReceipt = await createInstallationReceipt({
    plan: { installationId: data.desired.installationId, desiredHash: data.desired.desiredHash, release: 'test' },
    target: { ...target, zoneName: 'example.com', hostname: config().gateway.hostname },
    accessPolicy: data.desired.accessPolicy,
    resources: [],
  });
  const pendingReceipt = await beginReceiptAction(baseReceipt, {
    operationId: 'operation_123',
    type: 'apply',
    planId: 'plan_123',
    action: 'create',
    kind: server.kind,
    key: server.key,
    expectedDesiredHash: server.desiredHash,
    requestHash: `sha256:${'2'.repeat(64)}`,
  });
  data.cloudflare.listAccessApps = async () => [];
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: pendingReceipt,
  });
  assert.deepEqual(observed.resources.find((resource) => resource.kind === 'mcp_server').owner, {
    manager: 'ankka-mcp-gateway',
    installationId: data.desired.installationId,
  });
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.equal(plan.changes.find((change) => change.kind === 'mcp_server').action, 'noop');
});

test('a pending server is owned but cannot converge before ready tool discovery', async () => {
  const data = await fixture();
  const server = data.byKind.mcp_server;
  const sourcePolicy = data.byKind.source_access_policy;
  data.serverLive.status = 'waiting';
  data.serverLive.tools = [];
  data.serverLive.updated_tools = [];
  data.policies[data.serverApp.id] = [];
  const pending = await pendingCreateReceipt(data, server, [
    'mcp_server', 'source_access_application', 'source_access_policy',
  ]);

  const recovering = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: pending,
  });
  const recoveringPlan = await buildGatewayPlan(config(), recovering, { release: 'test', access });
  assert.equal(recoveringPlan.changes.find((change) => change.kind === 'mcp_server').action, 'update');
  assert.equal(recoveringPlan.changes.find((change) => change.kind === 'source_access_policy').action, 'create');
  assert.equal(recovering.resources.some((resource) => resource.kind === sourcePolicy.kind), false);

  const committed = await commitReceiptAction(pending, {
    provider: { id: server.key },
    desiredHash: server.desiredHash,
    marker: ownershipMarker(data.desired.installationId, server.key),
  });
  const fresh = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: committed,
  });
  const freshPlan = await buildGatewayPlan(config(), fresh, { release: 'test', access });
  assert.equal(freshPlan.changes.find((change) => change.kind === 'mcp_server').action, 'update');
});

test('pending server recovery requires the exact empty prompt configuration', async () => {
  const data = await fixture();
  const server = data.byKind.mcp_server;
  data.serverLive.updated_prompts = [{ name: 'unexpected_prompt', enabled: true }];
  data.cloudflare.listAccessApps = async () => [];
  const pending = await pendingCreateReceipt(data, server, [
    'mcp_server', 'source_access_application', 'source_access_policy',
  ]);

  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: pending,
  });
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.equal(plan.changes.find((change) => change.kind === 'mcp_server').action, 'update');
});

test('server matching rejects null and non-array prompt configurations', async () => {
  for (const invalidPrompts of [null, {}]) {
    const data = await fixture();
    data.serverLive.updated_prompts = invalidPrompts;
    const observed = await readCloudflareObservedState({
      cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
    });
    const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
    assert.equal(plan.changes.find((change) => change.kind === 'mcp_server').action, 'update');
  }
});

test('Portal matching rejects prompt drift in a source mapping', async () => {
  const data = await fixture();
  data.portalLive.servers[0].updated_prompts = [{ name: 'unexpected_prompt', enabled: true }];
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
  });
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.equal(plan.changes.find((change) => change.kind === 'portal').action, 'update');
});

test('Portal matching accepts Cloudflare omission of an empty prompt configuration', async () => {
  const data = await fixture();
  delete data.portalLive.servers[0].updated_prompts;
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
  });
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.equal(plan.changes.find((change) => change.kind === 'portal').action, 'noop');
});

test('recovers an outcome-unknown explicit source app only from its exact marker and singleton relation', async () => {
  const data = await fixture();
  const application = data.byKind.source_access_application;
  delete data.serverApp.domain;
  data.policies[data.serverApp.id] = [];
  const pending = await pendingCreateReceipt(data, application, [
    'source_access_application', 'source_access_policy',
  ]);
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: pending,
  });
  const recovered = observed.resources.find((resource) =>
    resource.kind === 'source_access_application');
  assert.deepEqual(recovered.owner, {
    manager: 'ankka-mcp-gateway',
    installationId: data.desired.installationId,
  });
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.equal(plan.changes.find((change) =>
    change.kind === 'source_access_application').action, 'noop');
});

test('pending explicit-app recovery requires empty inline and listed policy surfaces', async () => {
  for (const applicationKind of ['source_access_application', 'portal_access_application']) {
    for (const surface of ['inline', 'listed']) {
      const data = await fixture();
      const application = data.byKind[applicationKind];
      const live = applicationKind === 'source_access_application'
        ? data.serverApp
        : data.portalApp;
      data.policies[live.id] = surface === 'listed'
        ? [{ id: 'unexpected_policy', name: 'foreign' }]
        : [];
      if (surface === 'inline') live.policies = [{ id: 'unexpected_inline_policy' }];
      const excludedKinds = applicationKind === 'source_access_application'
        ? ['source_access_application', 'source_access_policy']
        : ['portal_access_application', 'portal_access_policy', 'dns_record'];
      const pending = await pendingCreateReceipt(data, application, excludedKinds);
      const observed = await readCloudflareObservedState({
        cloudflare: data.cloudflare, config: config(), target, access, receipt: pending,
      });
      const candidate = observed.resources.find((resource) =>
        resource.kind === applicationKind && resource.provider?.id === live.id);
      assert.deepEqual(candidate.owner, {}, `${applicationKind}:${surface}`);
      const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
      assert.equal(plan.changes.find((change) =>
        change.kind === applicationKind).action, 'conflict', `${applicationKind}:${surface}`);
    }
  }
});

test('source app matching rejects any present non-null domain', async () => {
  for (const invalidDomain of ['source.example.com', 0, {}]) {
    const data = await fixture();
    data.serverApp.domain = invalidDomain;
    const observed = await readCloudflareObservedState({
      cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
    });
    const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
    assert.equal(plan.changes.find((change) =>
      change.kind === 'source_access_application').action, 'conflict');
  }
});

test('pending native Portal recovery is independent of the explicit Portal app', async () => {
  const data = await fixture();
  const portal = data.byKind.portal;
  data.cloudflare.listAccessApps = async () => [data.serverApp];
  data.cloudflare.getAccessApp = async (id) => id === data.serverApp.id ? data.serverApp : null;
  data.cloudflare.listDnsRecords = async () => [];
  const pending = await pendingCreateReceipt(data, portal, [
    'portal', 'portal_access_application', 'portal_access_policy', 'dns_record',
  ]);

  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: pending,
  });
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });

  assert.equal(plan.changes.find(({ kind }) => kind === 'portal').action, 'noop');
  assert.equal(plan.changes.find(({ kind }) => kind === 'portal_access_application').action, 'create');
  assert.equal(plan.changes.find(({ kind }) => kind === 'portal_access_policy').action, 'create');
  assert.equal(plan.changes.find(({ kind }) => kind === 'dns_record').action, 'create');
});

test('never adopts a singleton markerless Portal app from pending create intent', async () => {
  for (const portalConfiguration of ['base_only', 'full']) {
    const data = await fixture();
    const application = data.byKind.portal_access_application;
    data.portalApp.id = 'unowned_portal_app_b';
    if (portalConfiguration === 'base_only') delete data.portalApp.oauth_configuration;
    data.policies[data.portalApp.id] = [];
    data.cloudflare.listAccessApps = async () => [data.serverApp, data.portalApp];
    data.cloudflare.getAccessApp = async (id) =>
      [data.serverApp, data.portalApp].find((app) => app.id === id) ?? null;
    data.cloudflare.listDnsRecords = async () => [];
    const pending = await pendingCreateReceipt(data, application, [
      'portal_access_application', 'portal_access_policy', 'dns_record',
    ]);

    const observed = await readCloudflareObservedState({
      cloudflare: data.cloudflare, config: config(), target, access, receipt: pending,
    });
    const candidate = observed.resources.find(({ kind }) =>
      kind === 'portal_access_application');
    assert.deepEqual(candidate.owner, {}, portalConfiguration);
    const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
    assert.equal(plan.changes.find(({ kind }) =>
      kind === 'portal_access_application').action, 'conflict', portalConfiguration);
  }
});

test('pending explicit Portal-app recovery rejects malformed and ambiguous candidates', async () => {
  for (const collision of ['malformed', 'ambiguous']) {
    const data = await fixture();
    const application = data.byKind.portal_access_application;
    const malformed = {
      ...data.portalApp,
      id: 'malformed_portal_app',
      destinations: [
        { type: 'public', uri: config().gateway.hostname },
        { type: 'public', uri: 'other.example.com' },
      ],
    };
    const portalApps = collision === 'malformed'
      ? [malformed]
      : [data.portalApp, { ...data.portalApp, id: 'duplicate_portal_app' }];
    data.cloudflare.listAccessApps = async () => [data.serverApp, ...portalApps];
    data.cloudflare.getAccessApp = async (id) =>
      [data.serverApp, ...portalApps].find((app) => app.id === id) ?? null;
    data.cloudflare.listDnsRecords = async () => [];
    const pending = await pendingCreateReceipt(data, application, [
      'portal_access_application', 'portal_access_policy', 'dns_record',
    ]);

    const observed = await readCloudflareObservedState({
      cloudflare: data.cloudflare, config: config(), target, access, receipt: pending,
    });
    const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
    assert.equal(
      plan.changes.find(({ kind }) => kind === 'portal_access_application').action,
      'conflict',
      collision,
    );
  }
});

test('a foreign native Portal conflicts without lending ownership to the explicit app', async () => {
  const data = await fixture({ includeReceipt: false });
  data.cloudflare.listAccessApps = async () => [data.serverApp];
  data.cloudflare.getAccessApp = async (id) => id === data.serverApp.id ? data.serverApp : null;
  data.cloudflare.listDnsRecords = async () => [];

  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access,
  });
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.equal(plan.changes.find(({ kind }) => kind === 'portal').action, 'conflict');
  assert.equal(plan.changes.find(({ kind }) => kind === 'portal_access_application').action, 'create');
});

test('ambiguous explicit apps do not affect pending native Portal recovery', async () => {
  const data = await fixture();
  const portal = data.byKind.portal;
  data.cloudflare.listAccessApps = async () => [
    data.serverApp,
    data.portalApp,
    { ...data.portalApp, id: 'app_portal_duplicate' },
  ];
  const pending = await pendingCreateReceipt(data, portal, [
    'portal', 'portal_access_application', 'portal_access_policy', 'dns_record',
  ]);
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: pending,
  });
  const portalObserved = observed.resources.find((resource) => resource.kind === 'portal');
  assert.equal(portalObserved.desiredHash, portal.desiredHash);
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.equal(plan.changes.find((change) => change.kind === 'portal').action, 'noop');
  assert.equal(plan.changes.find((change) =>
    change.kind === 'portal_access_application').action, 'conflict');
  assert.ok(plan.blockers.some((blocker) => blocker.code === 'resource_conflicts'));
});

test('requires ready server discovery and exact explicit Portal-app OAuth', async () => {
  const data = await fixture();
  data.serverLive.status = undefined;
  data.serverLive.tools = [{ name: 'company_prepare' }];
  data.portalApp.oauth_configuration.enabled = false;
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
  });
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.equal(plan.changes.find((change) => change.kind === 'mcp_server').action, 'update');
  assert.equal(plan.changes.find((change) => change.kind === 'portal').action, 'noop');
  assert.equal(plan.changes.find((change) =>
    change.kind === 'portal_access_application').action, 'update');
});

test('recognizes a present pending policy but leaves an absent outcome unknown for the reconciler', async () => {
  for (const present of [true, false]) {
    const data = await fixture();
    const policy = data.byKind.portal_access_policy;
    if (!present) data.policies[data.portalApp.id] = [];
    const pending = await pendingCreateReceipt(data, policy);
    const observed = await readCloudflareObservedState({
      cloudflare: data.cloudflare, config: config(), target, access, receipt: pending,
    });
    const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
    assert.equal(
      plan.changes.find((change) => change.kind === policy.kind).action,
      present ? 'noop' : 'create',
    );
  }
});

test('recovers a pending source policy reflected inline by its exact receipt-owned app', async () => {
  const data = await fixture();
  const policy = data.byKind.source_access_policy;
  const livePolicy = data.policies[data.serverApp.id][0];
  data.serverApp.policies = [{ id: livePolicy.id, name: livePolicy.name }];
  const pending = await pendingCreateReceipt(data, policy);

  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: pending,
  });
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });

  assert.equal(observed.diagnostics.some((diagnostic) =>
    diagnostic.code === 'unexpected_access_policy'
      && diagnostic.kind === 'source_access_policy'), false);
  assert.equal(plan.changes.find((change) =>
    change.kind === 'source_access_application').action, 'noop');
  assert.equal(plan.changes.find((change) =>
    change.kind === 'source_access_policy').action, 'noop');
});

test('rejects foreign, duplicate, and malformed inline source policies', async () => {
  for (const inlinePolicyState of ['foreign', 'duplicate', 'malformed']) {
    const data = await fixture();
    const policy = data.policies[data.serverApp.id][0];
    const exact = { id: policy.id, name: policy.name };
    data.serverApp.policies = inlinePolicyState === 'foreign'
      ? [exact, { id: 'policy_foreign_inline', name: 'foreign' }]
      : inlinePolicyState === 'duplicate'
        ? [exact, { ...exact }]
        : [{ name: policy.name }];

    const observed = await readCloudflareObservedState({
      cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
    });
    const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });

    assert.ok(observed.diagnostics.some((diagnostic) =>
      diagnostic.code === 'unexpected_access_policy'
        && diagnostic.kind === 'source_access_policy'), inlinePolicyState);
    assert.equal(plan.changes.find((change) =>
      change.kind === 'source_access_policy').action, 'conflict', inlinePolicyState);
  }
});

test('surfaces every unexpected explicit Portal-app policy as a planner conflict', async () => {
  const data = await fixture();
  data.policies[data.portalApp.id].push({
    id: 'policy_foreign_123',
    name: 'foreign policy',
    decision: 'allow',
    include: [],
  });
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
  });
  assert.ok(observed.diagnostics.some((diagnostic) =>
    diagnostic.code === 'unexpected_access_policy'
    && diagnostic.kind === 'portal_access_policy'));
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.equal(plan.changes.find((change) => change.kind === 'portal_access_policy').action, 'conflict');
});

test('accepts an exact separately-created Portal policy reflected inline by the app GET', async () => {
  const data = await fixture();
  const policy = data.policies[data.portalApp.id][0];
  data.portalApp.policies = [{ id: policy.id, name: policy.name }];

  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
  });
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });

  assert.equal(observed.diagnostics.some((diagnostic) =>
    diagnostic.code === 'unexpected_access_policy'
      && diagnostic.kind === 'portal_access_policy'), false);
  assert.deepEqual(
    plan.changes.map(({ kind, action }) => [kind, action]),
    data.desired.resources.map(({ kind }) => [kind, 'noop']),
  );
});

test('rejects foreign and duplicate inline Portal policies against the authoritative policy list', async () => {
  for (const inlinePolicyState of ['foreign', 'duplicate']) {
    const data = await fixture();
    const policy = data.policies[data.portalApp.id][0];
    const exact = { id: policy.id, name: policy.name };
    data.portalApp.policies = inlinePolicyState === 'foreign'
      ? [exact, { id: 'policy_foreign_inline', name: 'foreign' }]
      : [exact, { ...exact }];

    const observed = await readCloudflareObservedState({
      cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
    });
    const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });

    assert.ok(observed.diagnostics.some((diagnostic) =>
      diagnostic.code === 'unexpected_access_policy'
        && diagnostic.kind === 'portal_access_policy'), inlinePolicyState);
    assert.equal(plan.changes.find((change) =>
      change.kind === 'portal_access_policy').action, 'conflict', inlinePolicyState);
  }
});

test('a receipt locator cannot claim a same-id resource with a foreign marker', async () => {
  const data = await fixture();
  data.serverLive.description = 'foreign-marker';
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
  });
  const server = observed.resources.find((resource) => resource.kind === 'mcp_server');
  assert.deepEqual(server.owner, {});
  assert.equal(server.desiredHash, '');
});

test('a same-shaped replacement Access app cannot inherit receipt ownership', async () => {
  const data = await fixture();
  const replacement = {
    ...data.serverApp,
    id: 'app_server_replacement',
  };
  data.cloudflare.listAccessApps = async () => [replacement, data.portalApp];
  const originalGetAccessApp = data.cloudflare.getAccessApp;
  data.cloudflare.getAccessApp = async (id) => id === replacement.id
    ? replacement
    : originalGetAccessApp(id);

  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
  });
  const application = observed.resources.find((resource) =>
    resource.kind === 'source_access_application' && resource.provider.id === replacement.id);
  assert.deepEqual(application.owner, {});
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.equal(plan.changes.find((change) => change.kind === 'source_access_application').action, 'conflict');
});

test('an explicit source app omitted from the list remains bound by its exact receipt ID', async () => {
  const data = await fixture();
  data.cloudflare.listAccessApps = async () => [data.portalApp];
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
  });
  const application = observed.resources.find((resource) =>
    resource.kind === 'source_access_application');
  assert.deepEqual(application.owner, {
    manager: 'ankka-mcp-gateway',
    installationId: data.desired.installationId,
  });
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.equal(plan.changes.find((change) => change.kind === 'source_access_application').action, 'noop');
});

test('an explicit Portal app omitted from the list remains bound by its exact receipt ID', async () => {
  const data = await fixture();
  data.cloudflare.listAccessApps = async () => [data.serverApp];
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
  });
  const application = observed.resources.find((resource) =>
    resource.kind === 'portal_access_application');
  assert.equal(application.provider.id, data.portalApp.id);
  assert.deepEqual(application.owner, {
    manager: 'ankka-mcp-gateway',
    installationId: data.desired.installationId,
  });
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.equal(plan.changes.find((change) =>
    change.kind === 'portal_access_application').action, 'noop');
});

test('an exact Access-app GET that drifts from its listed relation is not ownership evidence', async () => {
  const data = await fixture();
  const originalGetAccessApp = data.cloudflare.getAccessApp;
  data.cloudflare.getAccessApp = async (id) => id === data.serverApp.id
    ? { ...data.serverApp, destinations: [] }
    : originalGetAccessApp(id);
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
  });
  const application = observed.resources.find((resource) =>
    resource.kind === 'source_access_application');
  assert.deepEqual(application.owner, {});
});

test('duplicates ambiguous DNS and Access-app observations so the planner conflicts', async () => {
  const data = await fixture();
  const foreignDns = { id: 'dns_foreign', type: 'A', name: 'mcp.example.com', content: '192.0.2.1', proxied: false };
  data.cloudflare.listDnsRecords = async () => [data.dnsLive, foreignDns];
  data.cloudflare.listAccessApps = async () => [
    data.serverApp,
    { ...data.serverApp, id: 'app_server_duplicate' },
    data.portalApp,
  ];
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt: data.receipt,
  });
  assert.equal(observed.resources.filter((resource) => resource.kind === 'dns_record').length, 2);
  assert.ok(observed.resources.filter((resource) =>
    resource.kind === 'source_access_application').length >= 2);
  assert.ok(observed.diagnostics.some((diagnostic) => diagnostic.code === 'ambiguous_dns_record'));
  assert.ok(observed.diagnostics.some((diagnostic) => diagnostic.code === 'access_app_ambiguous'));
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.equal(plan.changes.find((change) => change.kind === 'dns_record').action, 'conflict');
  assert.equal(plan.changes.find((change) => change.kind === 'source_access_application').action, 'conflict');
});

test('reads receipt-listed stale resources by locator for prune and uninstall', async () => {
  const data = await fixture();
  const staleKey = 'mcp-stale-123';
  const staleHash = `sha256:${'1'.repeat(64)}`;
  const staleLive = {
    id: staleKey,
    name: 'Removed source',
    hostname: 'https://removed.example.com/mcp',
    auth_type: 'oauth',
    description: ownershipMarker(data.desired.installationId, staleKey),
    updated_tools: [],
  };
  const receipt = await createInstallationReceipt({
    plan: { installationId: data.desired.installationId, desiredHash: data.desired.desiredHash, release: 'test' },
    target: { ...target, zoneName: 'example.com', hostname: config().gateway.hostname },
    accessPolicy: data.desired.accessPolicy,
    resources: [...data.resourceReceipts, {
      kind: 'mcp_server', key: staleKey, provider: { id: staleKey }, desiredHash: staleHash,
      marker: staleLive.description,
    }],
  });
  const original = data.cloudflare.getMcpServer;
  data.cloudflare.getMcpServer = async (id) => id === staleKey ? staleLive : original(id);
  const observed = await readCloudflareObservedState({
    cloudflare: data.cloudflare, config: config(), target, access, receipt,
  });
  const stale = observed.resources.find((resource) => resource.key === staleKey);
  assert.deepEqual(stale.owner, { manager: 'ankka-mcp-gateway', installationId: data.desired.installationId });
  assert.equal(stale.desiredHash, '');
  const plan = await buildGatewayPlan(config(), observed, { release: 'test', access });
  assert.equal(plan.changes.find((change) => change.key === staleKey).action, 'delete');
  assert.ok(plan.uninstall.some((change) => change.key === staleKey));
});

test('uses safe error codes without reflecting provider failures', async () => {
  const data = await fixture();
  data.cloudflare.getZone = async () => { throw new Error('secret provider body'); };
  await assert.rejects(
    readCloudflareObservedState({ cloudflare: data.cloudflare, config: config(), target, access }),
    (error) => error instanceof ObservedStateError
      && error.code === 'provider_read_failed'
      && !error.message.includes('secret provider body'),
  );
});
