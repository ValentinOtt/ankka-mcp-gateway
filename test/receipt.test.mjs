import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ReceiptValidationError,
  beginReceiptAction,
  clearReceiptAction,
  commitReceiptAction,
  createInstallationReceipt,
  markReceiptRemoved,
  ownershipMarker,
  receiptChecksum,
  updateInstallationReceipt,
  validateInstallationReceipt,
} from '../src/receipt.ts';

const HASH_A = `sha256:${'a'.repeat(64)}`;
const HASH_B = `sha256:${'b'.repeat(64)}`;
const HASH_C = `sha256:${'c'.repeat(64)}`;

function plan(overrides = {}) {
  return {
    schemaVersion: 1,
    installationId: 'acg-0123456789abcdef01234567',
    desiredHash: HASH_A,
    release: '0.1.0',
    changes: [
      {
        kind: 'portal_access_policy',
        desired: {
          allow: {
            identityType: 'email',
            identityCount: 1,
            identitiesHash: HASH_B,
          },
        },
      },
    ],
    ...overrides,
  };
}

function target(overrides = {}) {
  return {
    accountId: 'account_123',
    zoneId: 'zone_123',
    zoneName: 'example.com',
    hostname: 'mcp.example.com',
    ...overrides,
  };
}

function resource(overrides = {}) {
  return {
    kind: 'mcp_server',
    key: 'mcp-company-context-a1b2c3d4',
    provider: { id: 'provider-server-1' },
    desiredHash: HASH_A,
    marker: ownershipMarker(
      'acg-0123456789abcdef01234567',
      'mcp-company-context-a1b2c3d4',
    ),
    identityHash: HASH_C,
    ...overrides,
  };
}

function createIntent(overrides = {}) {
  return {
    operationId: 'op-create-1',
    type: 'apply',
    planId: 'plan-0123456789abcdef01234567',
    action: 'create',
    kind: 'mcp_server',
    key: 'mcp-company-context-a1b2c3d4',
    expectedDesiredHash: HASH_A,
    requestHash: HASH_C,
    ...overrides,
  };
}

async function emptyReceipt(overrides = {}) {
  const input = {
    plan: plan(overrides.plan),
    target: target(overrides.target),
  };
  if (overrides.accessPolicy) input.accessPolicy = overrides.accessPolicy;
  if (overrides.resources) input.resources = overrides.resources;
  return createInstallationReceipt(input);
}

test('creates a strict, checksum-protected, non-secret v1 receipt', async () => {
  const receipt = await emptyReceipt();

  assert.deepEqual(receipt, {
    schemaVersion: 1,
    manager: 'ankka-mcp-gateway',
    installationId: 'acg-0123456789abcdef01234567',
    state: 'ready',
    revision: 0,
    release: '0.1.0',
    target: target(),
    accessPolicy: {
      identityType: 'email',
      identityCount: 1,
      identitiesHash: HASH_B,
    },
    desiredHash: HASH_A,
    resources: [],
    pending: null,
    checksum: await receiptChecksum(receipt),
  });
  assert.deepEqual(await validateInstallationReceipt(receipt), receipt);
  assert.doesNotMatch(JSON.stringify(receipt), /owner@example\.com|apiToken|credential/i);
});

test('canonical checksum ignores object-key and resource ordering', async () => {
  const server = resource();
  const dns = resource({
    kind: 'dns_record',
    key: 'dns-mcp-example-com-a1b2c3d4',
    provider: { id: 'provider-dns-1' },
    marker: ownershipMarker(
      'acg-0123456789abcdef01234567',
      'dns-mcp-example-com-a1b2c3d4',
    ),
  });
  const receipt = await emptyReceipt({ resources: [dns, server] });
  const reordered = {
    checksum: receipt.checksum,
    pending: receipt.pending,
    resources: [...receipt.resources].reverse().map((entry) => ({
      identityHash: entry.identityHash,
      marker: entry.marker,
      desiredHash: entry.desiredHash,
      provider: { ...entry.provider },
      key: entry.key,
      kind: entry.kind,
    })),
    desiredHash: receipt.desiredHash,
    accessPolicy: {
      identitiesHash: receipt.accessPolicy.identitiesHash,
      identityCount: receipt.accessPolicy.identityCount,
      identityType: receipt.accessPolicy.identityType,
    },
    target: {
      hostname: receipt.target.hostname,
      zoneName: receipt.target.zoneName,
      zoneId: receipt.target.zoneId,
      accountId: receipt.target.accountId,
    },
    release: receipt.release,
    revision: receipt.revision,
    state: receipt.state,
    installationId: receipt.installationId,
    manager: receipt.manager,
    schemaVersion: receipt.schemaVersion,
  };

  assert.equal(await receiptChecksum(reordered), receipt.checksum);
  assert.deepEqual(await validateInstallationReceipt(reordered), receipt);
  assert.deepEqual(receipt.resources.map(({ kind }) => kind), ['mcp_server', 'dns_record']);
});

test('rejects unknown and sensitive fields without reflecting their values', async () => {
  const receipt = await emptyReceipt();
  const sensitiveValue = 'owner@example.com';
  const tampered = {
    ...receipt,
    allowedEmails: [sensitiveValue],
    target: { ...receipt.target, apiToken: 'do-not-print-me' },
  };

  await assert.rejects(
    () => validateInstallationReceipt(tampered),
    (error) => {
      assert.ok(error instanceof ReceiptValidationError);
      assert.match(error.message, /forbidden sensitive field/);
      assert.doesNotMatch(error.message, /owner@example\.com|do-not-print-me/);
      return true;
    },
  );

  await assert.rejects(
    () => emptyReceipt({ target: { allowedEmails: [sensitiveValue] } }),
    ReceiptValidationError,
  );
  await assert.rejects(
    () => createInstallationReceipt({
      plan: plan(),
      target: target(),
      allowedEmails: [sensitiveValue],
    }),
    (error) => error instanceof ReceiptValidationError && /input\.allowedEmails is not supported/.test(error.message),
  );
});

test('strictly rejects unknown nested keys and unsafe values', async () => {
  const receipt = await emptyReceipt({ resources: [resource()] });
  const unknown = structuredClone(receipt);
  unknown.resources[0].provider.region = 'global';
  await assert.rejects(
    () => validateInstallationReceipt(unknown),
    (error) => error instanceof ReceiptValidationError && /provider\.region is not supported/.test(error.message),
  );

  assert.throws(
    () => ownershipMarker('not valid', 'valid-key'),
    ReceiptValidationError,
  );
});

test('binds validation to the selected customer target', async () => {
  const receipt = await emptyReceipt();
  assert.deepEqual(
    await validateInstallationReceipt(receipt, { expectedTarget: target() }),
    receipt,
  );
  await assert.rejects(
    () => validateInstallationReceipt(receipt, {
      expectedTarget: target({ accountId: 'another-account' }),
    }),
    (error) => error instanceof ReceiptValidationError && /target does not match/.test(error.message),
  );
  await assert.rejects(
    () => emptyReceipt({ target: { zoneName: 'other.example' } }),
    (error) => error instanceof ReceiptValidationError && /must belong/.test(error.message),
  );
});

test('updates approved root metadata without retargeting or changing ownership', async () => {
  const original = await emptyReceipt({ resources: [resource()] });
  const upgradedPlan = plan({ release: '0.2.0', desiredHash: HASH_C });
  const upgraded = await updateInstallationReceipt(original, {
    plan: upgradedPlan,
    target: target(),
    accessPolicy: {
      identityType: 'email',
      identityCount: 2,
      identitiesHash: HASH_C,
    },
  });

  assert.equal(original.release, '0.1.0');
  assert.equal(upgraded.release, '0.2.0');
  assert.equal(upgraded.desiredHash, HASH_C);
  assert.deepEqual(upgraded.accessPolicy, {
    identityType: 'email',
    identityCount: 2,
    identitiesHash: HASH_C,
  });
  assert.deepEqual(upgraded.resources, original.resources);
  assert.equal(upgraded.revision, original.revision + 1);
  assert.deepEqual(await validateInstallationReceipt(upgraded), upgraded);
  assert.deepEqual(
    await updateInstallationReceipt(upgraded, {
      plan: upgradedPlan,
      target: target(),
      accessPolicy: upgraded.accessPolicy,
    }),
    upgraded,
  );

  await assert.rejects(
    () => updateInstallationReceipt(original, {
      plan: upgradedPlan,
      target: target({ zoneId: 'another-zone' }),
      accessPolicy: upgraded.accessPolicy,
    }),
    (error) => error instanceof ReceiptValidationError && /target does not match/.test(error.message),
  );
  await assert.rejects(
    () => updateInstallationReceipt(original, {
      plan: plan({ installationId: 'acg-another-installation' }),
      target: target(),
      accessPolicy: upgraded.accessPolicy,
    }),
    (error) => error instanceof ReceiptValidationError && /installationId does not match/.test(error.message),
  );
});

test('journals exact create intent before committing ownership copy-on-write', async () => {
  const original = await emptyReceipt();
  const pending = await beginReceiptAction(original, createIntent());

  assert.equal(original.revision, 0);
  assert.equal(original.pending, null);
  assert.equal(pending.state, 'installing');
  assert.equal(pending.revision, 1);
  assert.deepEqual(pending.pending, createIntent());
  assert.notEqual(pending.checksum, original.checksum);

  const marker = ownershipMarker(pending.installationId, pending.pending.key);
  const committed = await commitReceiptAction(pending, {
    provider: { id: 'provider-server-1' },
    desiredHash: HASH_A,
    marker,
    identityHash: HASH_C,
  });

  assert.equal(pending.resources.length, 0);
  assert.equal(pending.pending.action, 'create');
  assert.equal(committed.state, 'ready');
  assert.equal(committed.revision, 2);
  assert.equal(committed.pending, null);
  assert.deepEqual(committed.resources, [resource()]);
  assert.deepEqual(await validateInstallationReceipt(committed), committed);
});

test('binds a prune approval only to an apply delete journal entry', async () => {
  const original = await emptyReceipt({ resources: [resource()] });
  const empty = await emptyReceipt();
  const intent = createIntent({
    operationId: 'op-prune-1',
    action: 'delete',
    pruneApprovalId: 'prune-0123456789abcdef01234567',
    requestHash: HASH_B,
  });
  const pending = await beginReceiptAction(original, intent);

  assert.deepEqual(pending.pending, intent);
  assert.deepEqual(await validateInstallationReceipt(pending), pending);
  assert.equal(original.pending, null);

  await assert.rejects(
    () => beginReceiptAction(empty, createIntent({
      pruneApprovalId: 'prune-0123456789abcdef01234567',
    })),
    (error) =>
      error instanceof ReceiptValidationError &&
      /supported only for apply delete/.test(error.message),
  );
  await assert.rejects(
    () => beginReceiptAction(original, createIntent({
      type: 'uninstall',
      action: 'delete',
      planId: 'uninstall-0123456789abcdef',
      pruneApprovalId: 'prune-0123456789abcdef01234567',
    })),
    (error) =>
      error instanceof ReceiptValidationError &&
      /supported only for apply delete/.test(error.message),
  );
});

test('clear only abandons the matching journal entry and claims no resource', async () => {
  const receipt = await beginReceiptAction(await emptyReceipt(), createIntent());

  await assert.rejects(
    () => clearReceiptAction(receipt, 'op-other'),
    (error) => error instanceof ReceiptValidationError && /operationId does not match/.test(error.message),
  );
  const cleared = await clearReceiptAction(receipt, 'op-create-1');
  assert.equal(cleared.pending, null);
  assert.equal(cleared.state, 'ready');
  assert.equal(cleared.resources.length, 0);
  assert.equal(cleared.revision, receipt.revision + 1);
});

test('does not update receipt metadata during a pending action or after removal', async () => {
  const pending = await beginReceiptAction(await emptyReceipt(), createIntent());
  await assert.rejects(
    () => updateInstallationReceipt(pending, {
      plan: plan({ release: '0.2.0' }),
      target: target(),
    }),
    (error) => error instanceof ReceiptValidationError && /pending action/.test(error.message),
  );

  const removed = await markReceiptRemoved(await emptyReceipt());
  await assert.rejects(
    () => updateInstallationReceipt(removed, {
      plan: plan({ release: '0.2.0' }),
      target: target(),
    }),
    (error) => error instanceof ReceiptValidationError && /removed receipts/.test(error.message),
  );
});

test('commits update without changing provider ownership', async () => {
  const receipt = await emptyReceipt({ resources: [resource()] });
  const pending = await beginReceiptAction(receipt, createIntent({
    operationId: 'op-update-1',
    action: 'update',
    expectedDesiredHash: HASH_B,
    requestHash: HASH_B,
  }));
  const updated = await commitReceiptAction(pending, {
    provider: { id: 'provider-server-1' },
    desiredHash: HASH_B,
    identityHash: HASH_B,
  });

  assert.equal(updated.resources[0].desiredHash, HASH_B);
  assert.equal(updated.resources[0].identityHash, HASH_B);
  assert.equal(updated.resources[0].marker, resource().marker);
  await assert.rejects(
    () => commitReceiptAction(pending, {
      provider: { id: 'foreign-resource' },
    }),
    (error) => error instanceof ReceiptValidationError && /cannot change/.test(error.message),
  );
});

test('updates a group-bound policy receipt using only changed digests', async () => {
  const policy = resource({
    kind: 'source_access_policy',
    key: 'source-access-context-a1b2c3d4',
    provider: { id: 'policy-1', parentId: 'application-1' },
    marker: ownershipMarker(
      'acg-0123456789abcdef01234567',
      'source-access-context-a1b2c3d4',
    ),
    desiredHash: HASH_A,
    identityHash: HASH_B,
  });
  const receipt = await emptyReceipt({ resources: [policy] });
  const updating = await beginReceiptAction(receipt, createIntent({
    operationId: 'op-update-group-policy',
    action: 'update',
    kind: policy.kind,
    key: policy.key,
    expectedDesiredHash: HASH_B,
  }));
  const updated = await commitReceiptAction(updating, {
    provider: { ...policy.provider },
    desiredHash: HASH_B,
    marker: policy.marker,
    identityHash: HASH_C,
  });
  const updatedPolicy = updated.resources[0];

  assert.deepEqual(updatedPolicy.provider, policy.provider);
  assert.equal(updatedPolicy.desiredHash, HASH_B);
  assert.equal(updatedPolicy.identityHash, HASH_C);
  assert.deepEqual(Object.keys(updatedPolicy).sort(), [
    'desiredHash',
    'identityHash',
    'key',
    'kind',
    'marker',
    'provider',
  ]);
  const output = JSON.stringify(updated);
  for (const forbidden of [
    'group-provider-id-sentinel',
    'ERP Readers',
    'member@example.com',
  ]) assert.equal(output.includes(forbidden), false);
});

test('owns the explicit Portal Access app by exact provider ID and policy parent binding', async () => {
  const portalApp = resource({
    kind: 'portal_access_application',
    key: 'portal-app-example-a1b2c3d4',
    provider: { id: 'app-portal-1' },
    marker: ownershipMarker(
      'acg-0123456789abcdef01234567',
      'portal-app-example-a1b2c3d4',
    ),
  });
  const appIntent = createIntent({
    kind: portalApp.kind,
    key: portalApp.key,
  });
  const creating = await beginReceiptAction(await emptyReceipt(), appIntent);
  await assert.rejects(
    () => commitReceiptAction(creating),
    (error) => error instanceof ReceiptValidationError && /result.provider is required/.test(error.message),
  );
  const created = await commitReceiptAction(creating, {
    provider: { id: portalApp.provider.id },
    marker: portalApp.marker,
  });
  assert.deepEqual(created.resources[0].provider, { id: 'app-portal-1' });

  const receipt = await emptyReceipt({ resources: [portalApp] });
  const updating = await beginReceiptAction(receipt, {
    ...appIntent,
    operationId: 'op-update-portal-app',
    action: 'update',
    expectedDesiredHash: HASH_B,
  });
  await assert.rejects(
    () => commitReceiptAction(updating, {
      provider: { id: 'replacement-app' },
    }),
    (error) => error instanceof ReceiptValidationError && /cannot change/.test(error.message),
  );

  const duplicateAccessApp = resource({
    kind: 'source_access_application',
    key: 'source-app-other-a1b2c3d4',
    provider: { id: 'app-portal-1' },
    marker: ownershipMarker(
      'acg-0123456789abcdef01234567',
      'source-app-other-a1b2c3d4',
    ),
  });
  await assert.rejects(
    () => emptyReceipt({ resources: [portalApp, duplicateAccessApp] }),
    (error) => error instanceof ReceiptValidationError
      && /duplicate an Access application provider ID/.test(error.message),
  );

  const wrongPolicy = resource({
    kind: 'portal_access_policy',
    key: 'portal-access-example-a1b2c3d4',
    provider: { id: 'portal-policy-1', parentId: 'other-app' },
  });
  await assert.rejects(
    () => emptyReceipt({ resources: [portalApp, wrongPolicy] }),
    (error) => error instanceof ReceiptValidationError && /parentId does not match/.test(error.message),
  );
});

test('deletes only a journaled owned resource and retains a removed tombstone', async () => {
  const receipt = await emptyReceipt({ resources: [resource()] });
  const deleting = await beginReceiptAction(receipt, createIntent({
    operationId: 'op-delete-1',
    type: 'uninstall',
    planId: 'uninstall-0123456789abcdef',
    action: 'delete',
    expectedDesiredHash: HASH_A,
    requestHash: HASH_B,
  }));
  const deleted = await commitReceiptAction(deleting);

  assert.equal(deleted.state, 'uninstalling');
  assert.deepEqual(deleted.resources, []);
  assert.equal(deleted.pending, null);

  const tombstone = await markReceiptRemoved(deleted);
  assert.equal(tombstone.state, 'removed');
  assert.equal(tombstone.revision, deleted.revision + 1);
  assert.equal(tombstone.installationId, receipt.installationId);
  assert.equal(tombstone.target.accountId, receipt.target.accountId);
  assert.deepEqual(await validateInstallationReceipt(tombstone), tombstone);
  assert.deepEqual(await markReceiptRemoved(tombstone), tombstone);
  await assert.rejects(
    () => beginReceiptAction(tombstone, createIntent()),
    (error) => error instanceof ReceiptValidationError && /cannot begin/.test(error.message),
  );
});

test('fails safely when update or delete intent does not name an owned resource', async () => {
  const receipt = await emptyReceipt();
  await assert.rejects(
    () => beginReceiptAction(receipt, createIntent({
      operationId: 'op-delete-missing',
      type: 'uninstall',
      planId: 'uninstall-0123456789abcdef',
      action: 'delete',
    })),
    (error) => {
      assert.ok(error instanceof ReceiptValidationError);
      assert.match(error.message, /does not target a receipt-owned resource/);
      return true;
    },
  );
});

test('rejects duplicate logical resources and provider locators', async () => {
  await assert.rejects(
    () => emptyReceipt({
      resources: [resource(), resource({ provider: { id: 'provider-server-2' } })],
    }),
    (error) => error instanceof ReceiptValidationError && /resources duplicate mcp_server/.test(error.message),
  );
  await assert.rejects(
    () => emptyReceipt({
      resources: [
        resource(),
        resource({ key: 'mcp-another-source-a1b2c3d4' }),
      ],
    }),
    (error) => error instanceof ReceiptValidationError && /duplicate a mcp_server provider locator/.test(error.message),
  );

  const nestedPolicies = await emptyReceipt({
    resources: [
      resource({
        kind: 'source_access_policy',
        key: 'source-access-one-a1b2c3d4',
        provider: { id: 'policy-1', parentId: 'application-1' },
        marker: undefined,
      }),
      resource({
        kind: 'source_access_policy',
        key: 'source-access-two-a1b2c3d4',
        provider: { id: 'policy-1', parentId: 'application-2' },
        marker: undefined,
      }),
    ],
  });
  assert.equal(nestedPolicies.resources.length, 2);
});

test('requires exact provider locator shape for each resource kind', async () => {
  await assert.rejects(
    () => emptyReceipt({
      resources: [resource({
        kind: 'source_access_policy',
        key: 'source-access-one-a1b2c3d4',
        provider: { id: 'policy-1' },
        marker: undefined,
      })],
    }),
    (error) => error instanceof ReceiptValidationError && /provider\.parentId/.test(error.message),
  );
  await assert.rejects(
    () => emptyReceipt({
      resources: [resource({ provider: { id: 'server-1', parentId: 'unexpected-parent' } })],
    }),
    (error) => error instanceof ReceiptValidationError && /parentId is not supported/.test(error.message),
  );
});

test('detects any checksum-protected receipt tampering', async () => {
  const receipt = await emptyReceipt({ resources: [resource()] });
  const tampered = structuredClone(receipt);
  tampered.release = '0.2.0';

  await assert.rejects(
    () => validateInstallationReceipt(tampered),
    (error) => error instanceof ReceiptValidationError && /checksum does not match/.test(error.message),
  );
  assert.notEqual(await receiptChecksum(tampered), receipt.checksum);
});

test('does not accept provider credentials or raw execution payloads at commit', async () => {
  const receipt = await beginReceiptAction(await emptyReceipt(), createIntent());
  const marker = ownershipMarker(receipt.installationId, receipt.pending.key);

  await assert.rejects(
    () => commitReceiptAction(receipt, {
      provider: { id: 'provider-server-1' },
      marker,
      apiToken: 'sensitive-value',
    }),
    (error) => {
      assert.ok(error instanceof ReceiptValidationError);
      assert.match(error.message, /forbidden sensitive field/);
      assert.doesNotMatch(error.message, /sensitive-value/);
      return true;
    },
  );
  await assert.rejects(
    () => commitReceiptAction(receipt, {
      provider: { id: 'provider-server-1' },
      marker: 'acg:v1:wrong:marker',
    }),
    (error) => error instanceof ReceiptValidationError && /expected ownership marker/.test(error.message),
  );
});
