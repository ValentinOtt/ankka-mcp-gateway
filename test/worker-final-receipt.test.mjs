import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test, { after } from 'node:test';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';

import { canonicalJson, installReadyGateway, portalOnlyClaim, prefixedSha256, STORAGE_KEY } from './payload-lifecycle.mjs';

const directory = await mkdtemp(path.join(tmpdir(), 'ankka-final-receipt-'));
after(() => rm(directory, { recursive: true, force: true }));
const outfile = path.join(directory, 'runtime.mjs');
await build({
  stdin: {
    contents: `export { AdminState } from './apps/installer/src/customer-gateway-entrypoint.ts';
      export { initializeCustomerGatewayOwnershipState } from './apps/installer/src/customer-gateway-ownership-state.ts';`,
    resolveDir: path.resolve(import.meta.dirname, '..'),
    loader: 'ts',
  },
  bundle: true, format: 'esm', platform: 'browser', target: 'es2022', outfile, logLevel: 'silent',
});
const { AdminState, initializeCustomerGatewayOwnershipState } = await import(pathToFileURL(outfile).href);
const OWNERSHIP_KEY = 'ankka-mcp-gateway/ownership-state/v2';

async function fixture(context, { managementOwnership = true } = {}) {
  const gateway = await installReadyGateway({ claimInput: await portalOnlyClaim() });
  gateway.env.ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY = 'A'.repeat(43);
  const management = gateway.objects.get('v1:management').storage;
  if (managementOwnership) await initializeCustomerGatewayOwnershipState({
    storage: management, wrappingKey: gateway.env.ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY,
  });
  const instances = new Map();
  gateway.env.ADMIN_STATE = {
    idFromName: (name) => name,
    get(name) {
      if (!instances.has(name)) {
        const storage = gateway.objects.get(name)?.storage;
        assert.ok(storage, 'only the installation and management objects are used');
        const database = new DatabaseSync(':memory:');
        context.after(() => database.close());
        storage.sql = {
          exec(query, ...bindings) {
            const rows = database.prepare(query).all(...bindings);
            return { toArray: () => rows, [Symbol.iterator]: () => rows[Symbol.iterator]() };
          },
        };
        instances.set(name, new AdminState({
          id: { name }, storage, blockConcurrencyWhile: async (callback) => callback(),
        }, gateway.env));
      }
      return { fetch: (request) => instances.get(name).fetch(request) };
    },
  };
  return gateway;
}

function rootRequest(installationId) {
  return new Request('https://admin-state.invalid/teardown-root', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: canonicalJson({ schemaVersion: 1, installationId }),
  });
}

test('the compiled final runtime reads the installation receipt without a management ownership key', async (context) => {
  const gateway = await fixture(context);
  assert.equal(await gateway.storage.get(OWNERSHIP_KEY), undefined);
  const root = gateway.env.ADMIN_STATE.get(`v1:${gateway.readyReceipt.installationId}`);
  const response = await root.fetch(rootRequest(gateway.readyReceipt.installationId));
  assert.equal(response.status, 200);
  assert.deepEqual((await response.json()).root.receipt, gateway.readyReceipt);
  assert.equal(await gateway.storage.get(OWNERSHIP_KEY), undefined, 'receipt access must not create an ownership key');
});

test('the compiled management object can prepare teardown using the separate receipt object', async (context) => {
  const gateway = await fixture(context);
  const issuedAt = Date.now();
  const response = await gateway.env.ADMIN_STATE.get('v1:management').fetch(new Request(
    'https://admin-state.invalid/teardown-actions/prepare-current', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: canonicalJson({ schemaVersion: 1, actionId: `action_${'A'.repeat(32)}`,
        actionKeyHash: await prefixedSha256('A'.repeat(43)), actorEmail: 'admin@example.com',
        installationId: gateway.readyReceipt.installationId, issuedAt, expiresAt: issuedAt + 600_000 }),
    },
  ));
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal((await response.json()).status, 'authorization_required');
  assert.equal(gateway.provider.deletes().length, 0);
});

test('the compiled final runtime still rejects a management object without ownership state', async (context) => {
  const gateway = await fixture(context, { managementOwnership: false });
  const management = gateway.env.ADMIN_STATE.get('v1:management');
  await assert.rejects(management.fetch(new Request('https://admin-state.invalid/status')), /customer_gateway_ownership_invalid/);
});

test('an installation object without a valid receipt cannot prepare root removal', async (context) => {
  const gateway = await fixture(context);
  await gateway.storage.put(STORAGE_KEY, { ...gateway.readyReceipt, checksum: `sha256:${'0'.repeat(64)}` });
  const root = gateway.env.ADMIN_STATE.get(`v1:${gateway.readyReceipt.installationId}`);
  const response = await root.fetch(rootRequest(gateway.readyReceipt.installationId));
  assert.equal(response.status, 409);
  assert.equal(gateway.provider.deletes().length, 0);
});
