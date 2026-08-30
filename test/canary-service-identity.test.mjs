import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import { buildGatewayDesiredState, buildGatewayPlan } from '../src/plan.ts';
import {
  createInstallationReceipt,
  ownershipMarker,
  ReceiptValidationError,
  updateInstallationReceipt,
  validateInstallationReceipt,
} from '../src/receipt.ts';
import { CANARY_SERVICE_ID, OTHER_SERVICE_ID, canaryConfig } from './fixtures/canary-service-identity.mjs';

const target = {
  accountId: 'account_123', zoneId: 'zone_123', zoneName: 'example.com',
  zoneStatus: 'active', zeroTrustReady: true,
};
const access = { canaryServiceTokenId: CANARY_SERVICE_ID };
const digest = `sha256:${createHash('sha256').update(JSON.stringify(access)).digest('hex')}`;

test('canary service identity produces two digest-only policies without changing topology', async () => {
  const config = canaryConfig();
  const desired = await buildGatewayDesiredState(config, { target, access });
  const plan = await buildGatewayPlan(config, { target, resources: [] }, { access });
  assert.deepEqual(desired.blockers, []);
  assert.equal(desired.resources.length, 7);
  assert.deepEqual(desired.accessPolicy, {
    identityType: 'service_token', identityCount: 1, identitiesHash: digest,
  });
  const policies = desired.resources.filter(({ kind }) => kind.endsWith('_policy'));
  assert.equal(policies.length, 2);
  for (const policy of policies) {
    assert.deepEqual(policy.desired.allow, {
      identitiesRef: 'access.canaryServiceTokenId',
      identityType: 'service_token', identityCount: 1, identitiesHash: digest,
    });
  }
  assert.equal(JSON.stringify({ plan, desired }).includes(CANARY_SERVICE_ID), false);
  const changed = await buildGatewayDesiredState(config, {
    target, access: { canaryServiceTokenId: OTHER_SERVICE_ID },
  });
  assert.notEqual(changed.accessPolicy.identitiesHash, digest);
  assert.notEqual(changed.desiredHash, desired.desiredHash);
});

test('machine identity rejects mixed inputs and malformed identifiers without reflecting values', async () => {
  for (const invalid of [
    { ...access, allowedEmails: [] },
    { ...access, groups: [] },
    { canaryServiceTokenId: undefined },
    { canaryServiceTokenId: 'invalid-secret-sentinel' },
    { canaryServiceTokenId: `${CANARY_SERVICE_ID} ` },
    { canaryServiceTokenId: [CANARY_SERVICE_ID] },
  ]) {
    await assert.rejects(() => buildGatewayDesiredState(canaryConfig(), { target, access: invalid }),
      (error) => error instanceof TypeError && !error.message.includes('invalid-secret-sentinel'));
  }
});

test('machine identity is unavailable outside the exact read-only synthetic canary', async () => {
  for (const mutate of [
    (config) => { config.gateway.name = 'Customer gateway'; },
    (config) => { config.gateway.hostname = 'mcp.example.com'; },
    (config) => { config.gateway.hostname = 'ankka-canaryx.example.com'; },
    (config) => { config.gateway.codeMode = 'default_on'; },
    (config) => { config.sources.push({ ...config.sources[0], id: 'second' }); },
    (config) => { config.sources[0].id = 'customer-source'; },
    (config) => { config.sources[0].enabledTools = ['customer_read']; },
    (config) => { config.sources[0].enabledTools.push('customer_read'); },
    (config) => { config.sources[0].authentication.mode = 'oauth'; },
    (config) => { config.sources[0].authentication.onBehalfOfUser = true; },
    (config) => { config.sources[0].accessGroup = 'Readers'; },
  ]) {
    const config = canaryConfig();
    mutate(config);
    await assert.rejects(() => buildGatewayDesiredState(config, { target, access }));
  }
});

test('service identity receipts contain only one digest and require matching policy identity proofs', async () => {
  const config = canaryConfig();
  const plan = await buildGatewayPlan(config, { target, resources: [] }, { access, release: 'test' });
  const receiptTarget = { ...target, hostname: config.gateway.hostname };
  delete receiptTarget.zoneStatus;
  delete receiptTarget.zeroTrustReady;
  const receipt = await createInstallationReceipt({ plan, target: receiptTarget });
  assert.deepEqual(receipt.accessPolicy, {
    identityType: 'service_token', identityCount: 1, identitiesHash: digest,
  });
  assert.deepEqual(await validateInstallationReceipt(receipt), receipt);
  assert.equal(JSON.stringify(receipt).includes(CANARY_SERVICE_ID), false);

  const policy = plan.changes.find(({ kind }) => kind === 'portal_access_policy');
  const resource = {
    kind: policy.kind, key: policy.key,
    provider: { id: 'policy_123', parentId: 'app_123' },
    desiredHash: policy.desiredHash,
    marker: ownershipMarker(plan.installationId, policy.key),
    identityHash: digest,
  };
  await createInstallationReceipt({ plan, target: receiptTarget, resources: [resource] });
  for (const identityHash of [undefined, `sha256:${'0'.repeat(64)}`]) {
    await assert.rejects(() => createInstallationReceipt({
      plan, target: receiptTarget, resources: [{ ...resource, identityHash }],
    }), ReceiptValidationError);
  }
  for (const identityCount of [0, 2]) {
    await assert.rejects(() => createInstallationReceipt({
      plan, target: receiptTarget, accessPolicy: { ...receipt.accessPolicy, identityCount },
    }), ReceiptValidationError);
  }
  const changed = await buildGatewayPlan(config, { target, resources: [] }, {
    access: { canaryServiceTokenId: OTHER_SERVICE_ID }, release: 'test',
  });
  await assert.rejects(() => updateInstallationReceipt(receipt, {
    plan: changed, target: receiptTarget,
  }), /canary service identity cannot change/);
  await assert.rejects(() => updateInstallationReceipt(receipt, {
    plan, target: receiptTarget,
    accessPolicy: { identityType: 'email', identityCount: 1, identitiesHash: digest },
  }), /canary service identity cannot change/);
});
