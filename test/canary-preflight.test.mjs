import test from 'node:test';
import assert from 'node:assert/strict';
import { CloudflareApiError } from '../src/cloudflare-client.mjs';
import { runCloudflareCanaryPreflight } from '../src/canary-preflight.mjs';

const ACCOUNT_ID = 'a'.repeat(32);
const ZONE_ID = 'b'.repeat(32);
const ZONE_NAME = 'canary.example';
const HOSTNAME = `gateway.${ZONE_NAME}`;
const PRIVATE_VALUES = [
  ACCOUNT_ID,
  ZONE_ID,
  ZONE_NAME,
  HOSTNAME,
  'person@example.com',
  'test-only-sensitive-token',
];

function run(cloudflare, overrides = {}) {
  return runCloudflareCanaryPreflight({
    cloudflare,
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
    hostname: HOSTNAME,
    ...overrides,
  });
}

function readyClient(overrides = {}) {
  const calls = [];
  const writeCalls = [];
  const reads = {
    getZone: async () => ({
      id: ZONE_ID,
      name: ZONE_NAME,
      status: 'active',
      account: { id: ACCOUNT_ID },
    }),
    listIdentityProviders: async () => [{ id: ZONE_ID, email: PRIVATE_VALUES[4] }],
    listMcpServers: async () => [{ id: ZONE_ID, token: PRIVATE_VALUES[5] }],
    listPortals: async () => [{ id: ZONE_ID }],
    listAccessApps: async () => [{ id: ZONE_ID }],
    listDnsRecords: async () => [{ id: ZONE_ID, name: HOSTNAME }],
    ...overrides,
  };
  const cloudflare = {};
  for (const [name, implementation] of Object.entries(reads)) {
    cloudflare[name] = async (...args) => {
      calls.push([name, ...args]);
      return implementation(...args);
    };
  }
  for (const name of [
    'createMcpServer',
    'updateMcpServer',
    'deleteMcpServer',
    'syncMcpServer',
    'createPortal',
    'updatePortal',
    'deletePortal',
    'updateAccessApp',
    'createAppPolicy',
    'updateAppPolicy',
    'deleteAppPolicy',
    'createDnsRecord',
    'updateDnsRecord',
    'deleteDnsRecord',
  ]) {
    cloudflare[name] = async () => {
      writeCalls.push(name);
      throw new Error(`write method invoked: ${name}`);
    };
  }
  return { calls, cloudflare, writeCalls };
}

test('checks the complete read surface and returns only sanitized readiness', async () => {
  const fake = readyClient();
  const report = await run(fake.cloudflare);

  assert.equal(report.schemaVersion, 1);
  assert.equal(report.kind, 'cloudflare_canary_preflight');
  assert.equal(report.ready, true);
  assert.equal(report.writesPerformed, false);
  assert.deepEqual(
    report.prerequisites,
    [
      { key: 'selected_target_matches', status: 'ready' },
      { key: 'zone_active', status: 'ready' },
      { key: 'hostname_in_zone', status: 'ready' },
      { key: 'zero_trust_identity_provider', status: 'ready' },
    ],
  );
  assert.deepEqual(
    report.capabilities.map(({ key, status }) => [key, status]),
    [
      ['zone.read', 'available'],
      ['access.identity_providers.read', 'available'],
      ['mcp.servers.read', 'available'],
      ['mcp.portals.read', 'available'],
      ['access.applications.read', 'available'],
      ['dns.records.read', 'available'],
    ],
  );
  assert.deepEqual(report.diagnostics, []);
  assert.deepEqual(
    fake.calls.map(([name]) => name),
    [
      'getZone',
      'listIdentityProviders',
      'listMcpServers',
      'listPortals',
      'listAccessApps',
      'listDnsRecords',
    ],
  );
  assert.deepEqual(fake.calls.at(-1), [
    'listDnsRecords',
    { 'name.exact': HOSTNAME, match: 'all' },
  ]);
  assert.deepEqual(fake.writeCalls, []);
  const serialized = JSON.stringify(report);
  for (const privateValue of PRIVATE_VALUES) assert.doesNotMatch(serialized, new RegExp(privateValue));
});

test('stops before account discovery when the selected zone is inactive', async () => {
  const fake = readyClient({
    getZone: async () => ({
      id: ZONE_ID,
      name: ZONE_NAME,
      status: 'pending',
      account: { id: ACCOUNT_ID },
    }),
  });

  const report = await run(fake.cloudflare);

  assert.equal(report.ready, false);
  assert.equal(report.capabilities[0].status, 'available');
  assert.ok(report.capabilities.slice(1).every(({ status }) => status === 'skipped'));
  assert.deepEqual(report.prerequisites[1], { key: 'zone_active', status: 'not_ready' });
  assert.deepEqual(report.diagnostics, [
    { capability: 'zone.read', httpStatus: 0, codes: ['zone_inactive'] },
  ]);
  assert.equal(fake.calls.length, 1);
});

test('sanitizes provider, malformed-response, and unexpected failures', async () => {
  const fake = readyClient({
    listMcpServers: async () => {
      throw new CloudflareApiError('list_mcp_servers', {
        status: 403,
        codes: ['10000', ZONE_ID],
        requestId: ZONE_ID,
      });
    },
    listPortals: async () => {
      throw new Error(`${PRIVATE_VALUES[5]} ${PRIVATE_VALUES[4]}`);
    },
    listAccessApps: async () => ({ secret: PRIVATE_VALUES[5] }),
  });

  const report = await run(fake.cloudflare);
  const serialized = JSON.stringify(report);

  assert.equal(report.ready, false);
  assert.deepEqual(
    report.capabilities.slice(2, 5).map(({ status }) => status),
    ['denied', 'failed', 'failed'],
  );
  assert.deepEqual(report.diagnostics, [
    { capability: 'mcp.servers.read', httpStatus: 403, codes: ['10000'] },
    { capability: 'mcp.portals.read', httpStatus: 0, codes: ['unexpected_error'] },
    { capability: 'access.applications.read', httpStatus: 0, codes: ['invalid_response'] },
  ]);
  for (const privateValue of PRIVATE_VALUES) assert.doesNotMatch(serialized, new RegExp(privateValue));
  assert.equal(Object.hasOwn(report.diagnostics[0], 'requestId'), false);
});

test('reports a missing identity-provider prerequisite after all reads succeed', async () => {
  const fake = readyClient({ listIdentityProviders: async () => [] });

  const report = await run(fake.cloudflare);

  assert.equal(report.ready, false);
  assert.deepEqual(report.prerequisites.at(-1), {
    key: 'zero_trust_identity_provider',
    status: 'not_ready',
  });
  assert.ok(report.capabilities.every(({ status }) => status === 'available'));
  assert.equal(fake.calls.length, 6);
});

test('treats an absent selected zone as not found and stops further discovery', async () => {
  const fake = readyClient({ getZone: async () => null });

  const report = await run(fake.cloudflare);

  assert.equal(report.ready, false);
  assert.deepEqual(report.capabilities[0], { key: 'zone.read', status: 'not_found' });
  assert.deepEqual(report.prerequisites[0], {
    key: 'selected_target_matches',
    status: 'unavailable',
  });
  assert.deepEqual(report.diagnostics[0], {
    capability: 'zone.read',
    httpStatus: 404,
    codes: ['not_found'],
  });
  assert.equal(fake.calls.length, 1);
});

test('refuses an incomplete injected client before issuing any request', async () => {
  let calls = 0;
  await assert.rejects(
    runCloudflareCanaryPreflight({
      cloudflare: {
        getZone: async () => {
          calls += 1;
          return { status: 'active' };
        },
      },
      accountId: ACCOUNT_ID,
      zoneId: ZONE_ID,
      hostname: HOSTNAME,
    }),
    /complete preflight read surface/,
  );
  assert.equal(calls, 0);
});

test('rejects unsupported options before accessing the injected client', async () => {
  const fake = readyClient();
  await assert.rejects(
    runCloudflareCanaryPreflight({
      cloudflare: fake.cloudflare,
      accountId: ACCOUNT_ID,
      zoneId: ZONE_ID,
      hostname: HOSTNAME,
      token: PRIVATE_VALUES[5],
    }),
    /unsupported fields/,
  );
  assert.equal(fake.calls.length, 0);
});

test('stops before account discovery on either an account or zone mismatch', async () => {
  for (const mismatch of [
    { id: 'c'.repeat(32), accountId: ACCOUNT_ID },
    { id: ZONE_ID, accountId: 'd'.repeat(32) },
  ]) {
    const fake = readyClient({
      getZone: async () => ({
        id: mismatch.id,
        name: ZONE_NAME,
        status: 'active',
        account: { id: mismatch.accountId },
      }),
    });

    const report = await run(fake.cloudflare);

    assert.equal(report.ready, false);
    assert.deepEqual(report.prerequisites[0], {
      key: 'selected_target_matches',
      status: 'not_ready',
    });
    assert.deepEqual(report.diagnostics, [
      { capability: 'zone.read', httpStatus: 0, codes: ['target_mismatch'] },
    ]);
    assert.ok(report.capabilities.slice(1).every(({ status }) => status === 'skipped'));
    assert.deepEqual(fake.calls.map(([name]) => name), ['getZone']);
    assert.doesNotMatch(JSON.stringify(report), /c{32}|d{32}/);
  }
});

test('stops before account discovery when the hostname is outside the selected zone', async () => {
  const fake = readyClient();
  const outsideHostname = 'gateway.outside.example';

  const report = await run(fake.cloudflare, { hostname: outsideHostname });

  assert.equal(report.ready, false);
  assert.deepEqual(report.prerequisites[2], {
    key: 'hostname_in_zone',
    status: 'not_ready',
  });
  assert.deepEqual(report.diagnostics, [
    { capability: 'zone.read', httpStatus: 0, codes: ['hostname_outside_zone'] },
  ]);
  assert.deepEqual(fake.calls.map(([name]) => name), ['getZone']);
  assert.doesNotMatch(JSON.stringify(report), new RegExp(outsideHostname));
});
