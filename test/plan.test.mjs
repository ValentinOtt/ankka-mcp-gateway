import test from 'node:test';
import assert from 'node:assert/strict';
import { GatewayConfigError } from '../src/config.ts';
import {
  buildGatewayDesiredState,
  buildGatewayPlan,
  GATEWAY_REQUIRED_CAPABILITIES,
} from '../src/plan.ts';

const FIXED_CAPABILITIES = [
  'identity.discovery',
  'account.discovery',
  'zone.discovery',
  'mcp.server.read',
  'mcp.server.write',
  'mcp.server.sync',
  'mcp.portal.read',
  'mcp.portal.write',
  'access.application.read',
  'access.application.write',
  'access.policy.read',
  'access.policy.write',
  'dns.record.read',
  'dns.record.write',
];

function config() {
  return {
    schemaVersion: 1,
    gateway: {
      name: 'Example MCP Gateway',
      hostname: 'mcp.example.com',
      codeMode: 'default_on',
    },
    policy: {
      capabilityMode: 'read_only',
      credentialCustody: 'customer',
      telemetry: 'off',
    },
    sources: [
      {
        id: 'company-context',
        label: 'Company context',
        url: 'https://context.example.com/mcp',
        authentication: { mode: 'oauth', onBehalfOfUser: true },
        enabledTools: ['company_search', 'company_prepare'],
      },
    ],
  };
}

function target(overrides = {}) {
  return {
    accountId: 'account_123',
    zoneId: 'zone_123',
    zoneName: 'example.com',
    zoneStatus: 'active',
    zeroTrustReady: true,
    ...overrides,
  };
}

function access(overrides = {}) {
  return {
    allowedEmails: ['owner@example.com'],
    ...overrides,
  };
}

async function createPlan(overrides = {}) {
  return buildGatewayPlan(
    config(),
    { target: target(), resources: [], ...overrides },
    { release: '0.1.0', access: access() },
  );
}

function observedFromPlan(plan, owner = {}) {
  return plan.changes
    .filter((change) => change.desiredHash)
    .map((change, index) => ({
      kind: change.kind,
      key: change.key,
      provider:
        change.kind === 'source_access_policy'
          ? { id: `provider-${index + 1}`, parentId: 'provider-2' }
          : change.kind === 'portal_access_policy'
            ? { id: `provider-${index + 1}`, parentId: 'provider-5' }
          : { id: `provider-${index + 1}` },
      owner: {
        manager: 'ankka-mcp-gateway',
        installationId: plan.installationId,
        ...owner,
      },
      desiredHash: change.desiredHash,
    }));
}

test('is canonical and deterministic despite object key ordering', async () => {
  const firstConfig = config();
  const secondConfig = {
    sources: firstConfig.sources.map((source) => ({
      enabledTools: source.enabledTools,
      authentication: {
        onBehalfOfUser: source.authentication.onBehalfOfUser,
        mode: source.authentication.mode,
      },
      url: source.url,
      label: source.label,
      id: source.id,
    })),
    policy: {
      telemetry: firstConfig.policy.telemetry,
      credentialCustody: firstConfig.policy.credentialCustody,
      capabilityMode: firstConfig.policy.capabilityMode,
    },
    gateway: {
      codeMode: firstConfig.gateway.codeMode,
      hostname: firstConfig.gateway.hostname,
      name: firstConfig.gateway.name,
    },
    schemaVersion: 1,
  };
  const first = await buildGatewayPlan(
    firstConfig,
    { target: target(), resources: [] },
    { release: '0.1.0', access: access() },
  );
  const second = await buildGatewayPlan(
    secondConfig,
    {
      resources: [],
      target: {
        zeroTrustReady: true,
        zoneStatus: 'active',
        zoneName: 'example.com',
        zoneId: 'zone_123',
        accountId: 'account_123',
      },
    },
    { release: '0.1.0', access: access() },
  );

  assert.deepEqual(second, first);
  assert.match(first.desiredHash, /^sha256:[0-9a-f]{64}$/);
});

test('creates dependency-ordered resources with exact least-privilege policy', async () => {
  const plan = await createPlan();

  assert.deepEqual(plan.requiredCapabilities, FIXED_CAPABILITIES);
  assert.deepEqual(GATEWAY_REQUIRED_CAPABILITIES, FIXED_CAPABILITIES);
  assert.equal(Object.hasOwn(plan, 'permissions'), false);
  assert.deepEqual(plan.blockers, []);
  assert.deepEqual(
    plan.changes.map(({ action, kind }) => [action, kind]),
    [
      ['create', 'mcp_server'],
      ['create', 'source_access_application'],
      ['create', 'source_access_policy'],
      ['create', 'portal'],
      ['create', 'portal_access_application'],
      ['create', 'portal_access_policy'],
      ['create', 'dns_record'],
    ],
  );

  const source = plan.changes[0].desired;
  assert.equal(source.capabilityMode, 'read_only');
  assert.equal(source.secureWebGateway, false);
  assert.equal(source.toolPolicy.defaultDisabled, true);
  assert.deepEqual(source.toolPolicy.allowedTools, ['company_prepare', 'company_search']);
  assert.deepEqual(source.authentication, {
    mode: 'oauth',
    onBehalfOfUser: true,
    credentialCustody: 'customer',
  });
  assert.deepEqual(plan.changes[1].desired, {
    metadata: plan.changes[1].desired.metadata,
    sourceResourceKey: plan.changes[0].key,
    applicationType: 'mcp',
  });
  assert.equal(plan.changes[3].desired.codeMode, 'default_on');
  assert.equal(plan.changes[3].desired.secureWebGateway, false);
  assert.deepEqual(plan.changes[3].desired.sourceMappings, [
    {
      sourceResourceKey: plan.changes[0].key,
      defaultDisabled: true,
      allowedTools: ['company_prepare', 'company_search'],
      onBehalfOfUser: true,
    },
  ]);
  assert.deepEqual(plan.changes[2].desired.allow, plan.changes[5].desired.allow);
  assert.deepEqual(
    {
      identitiesRef: plan.changes[2].desired.allow.identitiesRef,
      identityType: plan.changes[2].desired.allow.identityType,
      identityCount: plan.changes[2].desired.allow.identityCount,
    },
    {
      identitiesRef: 'access.allowedEmails',
      identityType: 'email',
      identityCount: 1,
    },
  );
  assert.match(plan.changes[2].desired.allow.identitiesHash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(Object.hasOwn(plan.changes[3].desired, 'authentication'), false);
  assert.equal(plan.changes[4].desired.name, plan.changes[3].desired.name);
  assert.deepEqual(plan.changes[4].desired, {
    metadata: plan.changes[4].desired.metadata,
    portalResourceKey: plan.changes[3].key,
    name: 'Example MCP Gateway',
    hostname: 'mcp.example.com',
    applicationType: 'mcp_portal',
    destination: { type: 'public', uri: 'mcp.example.com' },
    authentication: {
      mode: 'managed_oauth',
      dynamicClientRegistration: {
        enabled: true,
        allowAnyOnLocalhost: true,
        allowAnyOnLoopback: true,
      },
      grant: {
        accessTokenLifetime: '15m',
        sessionDuration: '336h',
      },
    },
  });
  assert.equal(plan.changes[5].desired.portalApplicationResourceKey, plan.changes[4].key);
  assert.equal(Object.hasOwn(plan.changes[5].desired, 'authentication'), false);
  assert.deepEqual(plan.changes[6].desired, {
    metadata: plan.changes[6].desired.metadata,
    recordType: 'CNAME',
    hostname: 'mcp.example.com',
    content: 'gateway.agents.cloudflare.com',
    proxied: true,
    dependsOnResourceKey: plan.changes[3].key,
  });
  assert.equal(JSON.stringify(plan).includes('owner@example.com'), false);
});

test('desired-state helper consumes Access emails without returning them', async () => {
  const desired = await buildGatewayDesiredState(config(), {
    target: target(),
    access: access({ allowedEmails: ['OWNER@example.com', 'member@example.com'] }),
  });
  const output = JSON.stringify(desired);

  assert.equal(output.includes('owner@example.com'), false);
  assert.equal(output.includes('member@example.com'), false);
  assert.deepEqual(desired.accessPolicy, {
    identityType: 'email',
    identityCount: 2,
    identitiesHash: desired.resources[2].desired.allow.identitiesHash,
  });
  assert.equal(desired.resources[2].desired.allow.identitiesRef, 'access.allowedEmails');
  assert.equal(desired.resources[5].desired.allow.identitiesRef, 'access.allowedEmails');
});

test('reports noops, owned drift, and foreign collisions without ambiguity', async () => {
  const initial = await createPlan();
  const observed = observedFromPlan(initial);
  const noopPlan = await buildGatewayPlan(
    config(),
    { target: target(), resources: observed },
    { release: '0.1.0', access: access() },
  );
  assert.deepEqual(noopPlan.changes.map((change) => change.action), Array(7).fill('noop'));
  assert.deepEqual(noopPlan.changes[0].provider, { id: 'provider-1' });
  assert.deepEqual(noopPlan.changes[1].provider, {
    id: 'provider-2',
  });

  observed[0].desiredHash = `sha256:${'0'.repeat(64)}`;
  const driftPlan = await buildGatewayPlan(
    config(),
    { target: target(), resources: observed },
    { release: '0.1.0', access: access() },
  );
  assert.equal(driftPlan.changes[0].action, 'update');
  assert.equal(driftPlan.changes[0].reason, 'owned_resource_drift');

  observed[0].owner.installationId = 'acg-foreign';
  const collisionPlan = await buildGatewayPlan(
    config(),
    { target: target(), resources: observed },
    { release: '0.1.0', access: access() },
  );
  assert.equal(collisionPlan.changes[0].action, 'conflict');
  assert.equal(collisionPlan.changes[0].reason, 'foreign_resource_collision');
  assert.deepEqual(collisionPlan.blockers.at(-1), {
    code: 'resource_conflicts',
    message: 'Resolve existing resource ownership conflicts before deployment.',
  });
  assert.equal(
    collisionPlan.uninstall.some((entry) => entry.provider?.id === observed[0].provider.id),
    false,
  );
});

test('accepts only strict kind-specific provider locators', async () => {
  const initial = await createPlan();
  const observed = observedFromPlan(initial);
  observed[0].provider = { id: 'server-id', unexpected: 'ignored-marker' };
  observed[0].providerId = 'legacy-marker';
  observed[2].provider = { id: 'policy-id' };

  const plan = await buildGatewayPlan(
    config(),
    { target: target(), resources: observed },
    { release: '0.1.0', access: access() },
  );
  const output = JSON.stringify(plan);

  assert.equal(plan.changes[0].provider, undefined);
  assert.deepEqual(plan.changes[1].provider, { id: 'provider-2' });
  assert.equal(plan.changes[2].provider, undefined);
  assert.equal(output.includes('ignored-marker'), false);
  assert.equal(output.includes('legacy-marker'), false);
  assert.deepEqual(plan.changes[3].provider, { id: 'provider-4' });
  assert.deepEqual(plan.changes[4].provider, {
    id: 'provider-5',
  });
  assert.deepEqual(plan.changes[5].provider, { id: 'provider-6', parentId: 'provider-5' });
});

test('plan-binds the explicit Portal Access application and policy parent locators', async () => {
  const initial = await createPlan();
  const observed = observedFromPlan(initial);
  const exact = await buildGatewayPlan(
    config(),
    { target: target(), resources: observed },
    { release: '0.1.0', access: access() },
  );
  assert.equal(exact.changes[4].kind, 'portal_access_application');
  assert.deepEqual(exact.changes[4].provider, { id: 'provider-5' });
  assert.deepEqual(exact.changes[5].provider, { id: 'provider-6', parentId: 'provider-5' });

  const withoutApplication = observed.filter(({ kind }) => kind !== 'portal_access_application');
  const missing = await buildGatewayPlan(
    config(),
    { target: target(), resources: withoutApplication },
    { release: '0.1.0', access: access() },
  );
  assert.equal(missing.changes[4].action, 'create');
  assert.notEqual(missing.planId, exact.planId);

  const replacement = structuredClone(observed);
  replacement[4].provider.id = 'app-replacement';
  replacement[5].provider.parentId = 'app-replacement';
  const replaced = await buildGatewayPlan(
    config(),
    { target: target(), resources: replacement },
    { release: '0.1.0', access: access() },
  );
  assert.deepEqual(replaced.changes[4].provider, { id: 'app-replacement' });
  assert.equal(replaced.changes[5].provider.parentId, 'app-replacement');
  assert.notEqual(replaced.planId, exact.planId);
});

test('tracks installer releases without manufacturing Cloudflare resource drift', async () => {
  const initial = await createPlan();
  const upgraded = await buildGatewayPlan(
    config(),
    { target: target(), resources: observedFromPlan(initial) },
    { release: '0.2.0', access: access() },
  );

  assert.equal(upgraded.desiredHash, initial.desiredHash);
  assert.notEqual(upgraded.planId, initial.planId);
  assert.deepEqual(upgraded.changes.map((change) => change.action), Array(7).fill('noop'));
});

test('emits prerequisite blockers with no observed values in messages', async () => {
  const plan = await buildGatewayPlan(
    config(),
    {
      target: target({
        accountId: undefined,
        zoneId: undefined,
        zoneName: 'other.example',
        zoneStatus: 'pending',
        zeroTrustReady: false,
      }),
      resources: [],
    },
    { release: '0.1.0', access: access({ allowedEmails: ['not-an-email'] }) },
  );

  assert.deepEqual(
    plan.blockers.map((blocker) => blocker.code),
    [
      'account_required',
      'active_zone_required',
      'hostname_outside_zone',
      'zero_trust_required',
      'allowed_emails_required',
      'invalid_allowed_emails',
    ],
  );
  assert.equal(plan.blockers.some((blocker) => blocker.message.includes('other.example')), false);
});

test('never reflects arbitrary or credential-like observed payload fields', async () => {
  const initial = await createPlan();
  const [resource] = observedFromPlan(initial);
  const marker = 'do-not-reflect-this-value';
  const plan = await buildGatewayPlan(
    config(),
    {
      apiToken: marker,
      target: {
        ...target(),
        credential: marker,
        responseBody: { authorization: marker },
      },
      resources: [
        {
          ...resource,
          bearerToken: marker,
          raw: { privateKey: marker },
          owner: { ...resource.owner, secret: marker },
        },
      ],
    },
    { release: '0.1.0', access: access() },
  );
  const output = JSON.stringify(plan);

  assert.equal(output.includes(marker), false);
  assert.equal(output.includes('apiToken'), false);
  assert.equal(output.includes('bearerToken'), false);
  assert.equal(output.includes('privateKey'), false);
});

test('generates stable IDs and resource keys no longer than 32 characters', async () => {
  const first = await createPlan();
  const second = await createPlan();

  assert.equal(first.installationId, second.installationId);
  assert.equal(first.planId, second.planId);
  assert.ok(first.installationId.length <= 32);
  assert.ok(first.planId.length <= 32);
  for (const change of first.changes) {
    assert.match(change.key, /^[a-z][a-z0-9-]*$/);
    assert.ok(change.key.length <= 32);
  }
});

test('deletes stale owned resources and builds reverse-order owned-only uninstall', async () => {
  const initial = await createPlan();
  const owned = observedFromPlan(initial);
  owned.push({
    kind: 'mcp_server',
    key: 'mcp-stale-owned',
    provider: { id: 'provider-stale' },
    owner: {
      manager: 'ankka-mcp-gateway',
      installationId: initial.installationId,
    },
    desiredHash: `sha256:${'1'.repeat(64)}`,
  });
  const foreign = {
    kind: 'dns_record',
    key: 'dns-foreign',
    provider: { id: 'provider-foreign' },
    owner: { manager: 'someone-else', installationId: initial.installationId },
    desiredHash: `sha256:${'2'.repeat(64)}`,
  };

  const plan = await buildGatewayPlan(
    config(),
    { target: target(), resources: [...owned, foreign].reverse() },
    { release: '0.1.0', access: access() },
  );
  const stale = plan.changes.find((change) => change.provider?.id === 'provider-stale');
  assert.deepEqual(stale, {
    action: 'delete',
    kind: 'mcp_server',
    key: 'mcp-stale-owned',
    provider: { id: 'provider-stale' },
    reason: 'stale_owned_resource',
  });
  assert.equal(plan.changes.some((change) => change.provider?.id === 'provider-foreign'), false);
  assert.deepEqual(
    plan.uninstall.map((entry) => entry.kind),
    [
      'dns_record',
      'portal_access_policy',
      'portal_access_application',
      'portal',
      'source_access_policy',
      'source_access_application',
      'mcp_server',
      'mcp_server',
    ],
  );
  assert.equal(plan.uninstall.some((entry) => entry.provider?.id === 'provider-foreign'), false);
});

test('defensively validates configuration before planning', async () => {
  const invalid = config();
  invalid.sources[0].enabledTools = ['*'];

  await assert.rejects(
    () => buildGatewayPlan(invalid, { target: target(), resources: [] }),
    (error) => error instanceof GatewayConfigError,
  );
});
