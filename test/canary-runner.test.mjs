import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CANARY_FIXTURE_ID,
  CANARY_TOOL_NAME,
  CanaryLifecycleError,
  previewCloudflareCanaryLifecycle,
  runCloudflareCanaryLifecycle,
} from '../src/canary-runner.ts';
import { buildGatewayDesiredState } from '../src/plan.ts';
import { ownershipMarker, receiptChecksum } from '../src/receipt.ts';
import { applyGateway, planLiveGateway } from '../src/reconciler.ts';

const ACCOUNT_ID = 'a'.repeat(32);
const ZONE_ID = 'b'.repeat(32);
const ZONE_NAME = 'disposable.example';
const HOSTNAME = `ankka-canary-gateway.${ZONE_NAME}`;
const ENDPOINT = 'https://ankka-synthetic-canary.example.net/mcp';
const EMAIL = 'canary-owner@example.net';
const SENSITIVE = 'must-never-escape';
const ORDER = [
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
];

function assertDoesNotInclude(value, forbidden) {
  assert.equal(value.includes(forbidden), false);
}

class MemoryReceiptStore {
  constructor() {
    this.value = null;
    this.writes = [];
    this.locked = false;
    this.failRemovedWriteOnce = false;
    this.failNextWrite = false;
  }

  async read() {
    return clone(this.value);
  }

  async writeAtomic(value) {
    if (this.failNextWrite) {
      this.failNextWrite = false;
      throw new Error(SENSITIVE);
    }
    if (value?.state === 'removed' && this.failRemovedWriteOnce) {
      this.failRemovedWriteOnce = false;
      throw new Error(SENSITIVE);
    }
    this.value = clone(value);
    this.writes.push(clone(value));
  }

  async withExclusiveLock(operation) {
    if (this.locked) throw Object.assign(new Error('locked'), { code: 'locked' });
    this.locked = true;
    try {
      return await operation();
    } finally {
      this.locked = false;
    }
  }
}

class FakeProvider {
  constructor() {
    this.resources = [];
    this.mutations = [];
    this.sequence = 0;
    this.failDeleteOnce = false;
    this.failCreateOnce = false;
    this.failUpdateOnce = false;
    this.definiteNotSubmittedOnce = false;
    this.failPortalCreateWithoutGeneratedAppOnce = false;
    this.failPortalCreateAfterCommitOnce = false;
    this.blockPendingPortalObservation = false;
    this.failReadAfterCommittedCreateCount = null;
    this.failReadAfterCommittedDeleteOnce = false;
    this.failReadCountdown = 0;
    this.forceClaimOwnership = false;
    this.portalRollbackInspections = 0;
    this.portalRollbackMutations = 0;
  }

  async readObservedState({ config, access, receipt }) {
    if (this.failReadCountdown > 0) {
      this.failReadCountdown -= 1;
      if (this.failReadCountdown === 0) throw new Error(SENSITIVE);
    }
    if (
      Number.isSafeInteger(this.failReadAfterCommittedCreateCount) &&
      receipt?.state === 'ready' &&
      receipt.pending === null &&
      receipt.resources.length === this.failReadAfterCommittedCreateCount &&
      this.resources.length === this.failReadAfterCommittedCreateCount
    ) {
      this.failReadAfterCommittedCreateCount = null;
      throw new Error(SENSITIVE);
    }
    if (
      this.failReadAfterCommittedDeleteOnce &&
      receipt?.state === 'uninstalling' &&
      receipt.pending === null &&
      receipt.resources.length > 0 &&
      receipt.resources.length < ORDER.length
    ) {
      this.failReadAfterCommittedDeleteOnce = false;
      throw new Error(SENSITIVE);
    }
    await buildGatewayDesiredState(config, { target: liveTarget(), access });
    return {
      target: liveTarget(),
      resources: this.resources.map((resource) => {
        const marker = receipt
          ? ownershipMarker(receipt.installationId, resource.key)
          : null;
        const owned = receipt?.resources.some((candidate) =>
          candidate.kind === resource.kind &&
          candidate.key === resource.key &&
          sameProvider(candidate.provider, resource.provider));
        const pending = receipt?.pending;
        const pendingCreate =
          pending?.type === 'apply' &&
          pending.action === 'create' &&
          pending.kind === resource.kind &&
          pending.key === resource.key &&
          pending.expectedDesiredHash === resource.desiredHash;
        const pendingCreateClaimsOwnership =
          pendingCreate && resource.kind !== 'portal_access_application';
        return {
          kind: resource.kind,
          key: resource.key,
          provider: clone(resource.provider),
          owner:
            !(
              this.blockPendingPortalObservation &&
              resource.kind === 'portal' &&
              pendingCreate
            ) &&
            (owned || pendingCreateClaimsOwnership || (this.forceClaimOwnership && receipt)) &&
            resource.marker === marker
              ? {
                  manager: 'ankka-mcp-gateway',
                  installationId: receipt.installationId,
                }
              : {},
          desiredHash: resource.desiredHash,
        };
      }),
      diagnostics: [{ code: 'synthetic_ok', rawBody: SENSITIVE }],
    };
  }

  async applyChange({ change, receipt }) {
    if (this.definiteNotSubmittedOnce) {
      this.definiteNotSubmittedOnce = false;
      const error = new Error(SENSITIVE);
      error.mutationOutcome = 'not_submitted';
      throw error;
    }
    this.mutations.push({ action: change.action, kind: change.kind });
    if (change.action === 'create' && this.failCreateOnce) {
      this.failCreateOnce = false;
      throw new Error(SENSITIVE);
    }
    if (change.action === 'delete' && this.failDeleteOnce) {
      this.failDeleteOnce = false;
      throw new Error(SENSITIVE);
    }
    if (change.action === 'update' && this.failUpdateOnce) {
      this.failUpdateOnce = false;
      throw new Error(SENSITIVE);
    }
    if (change.action === 'create') {
      this.sequence += 1;
      const policy = change.kind.endsWith('_access_policy');
      const parentKey = change.desired?.sourceApplicationResourceKey ??
        change.desired?.portalApplicationResourceKey;
      const policyParent = policy
        ? this.resources.find((resource) =>
          (
            resource.kind === 'source_access_application' ||
            resource.kind === 'portal_access_application'
          ) &&
          resource.key === parentKey)
        : null;
      const created = {
        kind: change.kind,
        key: change.key,
        provider: policy
          ? {
              id: `policy-${this.sequence}`,
              parentId: policyParent.provider.id,
            }
          : { id: change.kind === 'portal' ? change.key : `resource-${this.sequence}` },
        marker: ownershipMarker(receipt.installationId, change.key),
        desiredHash: change.desiredHash,
      };
      this.resources.push(created);
      if (change.kind === 'portal' && this.failPortalCreateWithoutGeneratedAppOnce) {
        this.failPortalCreateWithoutGeneratedAppOnce = false;
        this.blockPendingPortalObservation = true;
        throw new Error(SENSITIVE);
      }
      if (change.kind === 'portal' && this.failPortalCreateAfterCommitOnce) {
        this.failPortalCreateAfterCommitOnce = false;
        throw new Error(SENSITIVE);
      }
      return change.kind === 'portal_access_application'
        ? { status: 'submitted', provider: clone(created.provider) }
        : { status: 'submitted' };
    }
    const index = this.resources.findIndex((resource) =>
      resource.kind === change.kind &&
      resource.key === change.key &&
      sameProvider(resource.provider, change.provider));
    if (change.action === 'delete') {
      if (index !== -1) this.resources.splice(index, 1);
      return { status: 'submitted' };
    }
    if (change.action === 'update' && index !== -1) {
      this.resources[index].desiredHash = change.desiredHash;
      return { status: 'submitted' };
    }
  }

  async inspectPendingPortalCreateRollback({ change }) {
    this.portalRollbackInspections += 1;
    const portal = this.resources.find((resource) =>
      resource.kind === 'portal' && resource.key === change.key);
    return {
      status: portal ? 'ready' : 'already_absent',
      portalKey: change.key,
    };
  }

  async rollbackPendingPortalCreate({ change }) {
    this.portalRollbackMutations += 1;
    const index = this.resources.findIndex((resource) =>
      resource.kind === 'portal' && resource.key === change.key);
    if (index === -1) {
      return {
        status: 'already_absent',
        portalKey: change.key,
        deleteRequest: 'not_needed',
      };
    }
    this.resources.splice(index, 1);
    this.blockPendingPortalObservation = false;
    return {
      status: 'rolled_back',
      portalKey: change.key,
      deleteRequest: 'confirmed',
    };
  }
}

function liveTarget() {
  return {
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
    zoneName: ZONE_NAME,
    zoneStatus: 'active',
    zeroTrustReady: true,
  };
}

function cloudflare() {
  return {
    getZone: async () => ({
      id: ZONE_ID,
      name: ZONE_NAME,
      status: 'active',
      account: { id: ACCOUNT_ID },
    }),
    listIdentityProviders: async () => [{ id: 'synthetic-idp' }],
    listMcpServers: async () => [],
    listPortals: async () => [],
    listAccessApps: async () => [],
    listDnsRecords: async () => [],
  };
}

function input(overrides = {}) {
  return {
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
    hostname: HOSTNAME,
    syntheticMcpUrl: ENDPOINT,
    allowedEmail: EMAIL,
    ...overrides,
  };
}

function fixtureEvidence() {
  return {
    fixture: CANARY_FIXTURE_ID,
    schemaVersion: 1,
    toolNames: [CANARY_TOOL_NAME],
    callVerified: true,
  };
}

function dependencies(overrides = {}) {
  const provider = overrides.provider ?? new FakeProvider();
  const receiptStore = overrides.receiptStore ?? new MemoryReceiptStore();
  const cleanupStore = overrides.cleanupStore ?? new MemoryReceiptStore();
  return {
    cloudflare: cloudflare(),
    inspectSyntheticUpstream: async () => fixtureEvidence(),
    verifyInstalledGateway: async () => ({
      ready: true,
      fixture: CANARY_FIXTURE_ID,
      toolName: CANARY_TOOL_NAME,
    }),
    inspectCanaryResidue: async ({ signal }) => {
      provider.lastResidueSignal = signal;
      return {
        ownedResourceCount: provider.resources.length,
      };
    },
    sleep: async () => {},
    ...overrides,
    provider,
    receiptStore,
    cleanupStore,
  };
}

test('preview is zero-write, sanitized, and binds the complete reverse cleanup', async () => {
  const deps = dependencies();
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);

  assert.equal(preview.ready, true);
  assert.equal(preview.writesPerformed, false);
  assert.match(preview.approvalId, /^canary-lifecycle-[0-9a-f]{24}$/);
  assert.match(preview.targetConfirmationId, /^canary-target-[0-9a-f]{24}$/);
  assert.deepEqual(preview.changes.map(({ action }) => action), Array(ORDER.length).fill('create'));
  assert.deepEqual(preview.changes.map(({ kind }) => kind), ORDER);
  assert.deepEqual(preview.cleanup.map(({ kind }) => kind), [...ORDER].reverse());
  assert.equal(deps.provider.mutations.length, 0);
  assert.equal(deps.receiptStore.writes.length, 0);

  const serialized = JSON.stringify(preview);
  for (const forbidden of [ACCOUNT_ID, ZONE_ID, HOSTNAME, ENDPOINT, EMAIL, SENSITIVE]) {
    assertDoesNotInclude(serialized, forbidden);
  }
  assert.equal(Object.hasOwn(preview, 'internal'), false);
  assert.equal(Object.hasOwn(preview, 'planId'), false);
});

test('exact approval runs apply, no-op reapply, verification, and reverse uninstall', async () => {
  const deps = dependencies();
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  const progress = [];
  const result = await runCloudflareCanaryLifecycle(
    input({
      approvalId: preview.approvalId,
      targetConfirmationId: preview.targetConfirmationId,
    }),
    { ...deps, onProgress: (event) => progress.push(event) },
  );

  assert.deepEqual(
    deps.provider.mutations.map(({ action, kind }) => `${action}:${kind}`),
    [
      ...ORDER.map((kind) => `create:${kind}`),
      ...[...ORDER].reverse().map((kind) => `delete:${kind}`),
    ],
  );
  assert.equal(result.status, 'complete');
  assert.equal(result.resourceLifecycle, 'removed');
  assert.equal(result.interactiveVerification, 'verified');
  assert.equal(result.installedStateVerified, true);
  assert.equal(result.portalToolCallVerified, true);
  assert.equal(result.idempotentApplyVerified, true);
  assert.deepEqual(result.cleanup, {
    status: 'removed',
    reverseOrderVerified: true,
    ownedResourceCount: 0,
  });
  assert.equal(deps.provider.resources.length, 0);
  assert.ok(deps.provider.lastResidueSignal instanceof AbortSignal);
  assert.equal(deps.receiptStore.value.state, 'removed');
  assert.equal(deps.receiptStore.value.resources.length, 0);
  assert.deepEqual(deps.cleanupStore.value.resources.map(({ kind }) => kind), ORDER);
  const portalApplication = deps.cleanupStore.value.resources.find(({ kind }) =>
    kind === 'portal_access_application');
  const portalPolicy = deps.cleanupStore.value.resources.find(({ kind }) =>
    kind === 'portal_access_policy');
  assert.equal(portalPolicy.provider.parentId, portalApplication.provider.id);
  assert.ok(progress.some(({ stage, status }) => stage === 'uninstall' && status === 'verified'));
  assertDoesNotInclude(JSON.stringify({ result, progress }), SENSITIVE);
});

test('inspection hold exposes only the installed hostname and cleanup starts after release', async () => {
  let releaseHold;
  let holdReached;
  const reached = new Promise((resolve) => {
    holdReached = resolve;
  });
  let holdInput;
  let verifierCalled = false;
  const progress = [];
  const deps = dependencies({
    holdForInspection(value) {
      holdInput = value;
      holdReached();
      return new Promise((resolve) => {
        releaseHold = resolve;
      });
    },
    async verifyInstalledGateway() {
      verifierCalled = true;
      return {
        ready: true,
        fixture: CANARY_FIXTURE_ID,
        toolName: CANARY_TOOL_NAME,
      };
    },
    onProgress: (event) => progress.push(event),
  });
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  const running = runCloudflareCanaryLifecycle(
    input({
      approvalId: preview.approvalId,
      targetConfirmationId: preview.targetConfirmationId,
    }),
    deps,
  );

  await reached;
  assert.deepEqual(Object.keys(holdInput).sort(), ['hostname', 'signal']);
  assert.equal(holdInput.hostname, HOSTNAME);
  assert.ok(holdInput.signal instanceof AbortSignal);
  assert.equal(holdInput.signal.aborted, false);
  assert.equal(verifierCalled, false);
  assert.equal(deps.receiptStore.value.state, 'ready');
  assert.deepEqual(deps.receiptStore.value.resources.map(({ kind }) => kind), ORDER);
  assert.equal(deps.provider.mutations.some(({ action }) => action === 'delete'), false);

  releaseHold();
  const result = await running;
  assert.equal(verifierCalled, true);
  assert.equal(result.status, 'complete');
  assert.equal(result.portalToolCallVerified, true);
  assert.equal(deps.receiptStore.value.state, 'removed');
  assert.equal(deps.provider.resources.length, 0);
  assert.deepEqual(
    progress.filter(({ stage }) => stage === 'inspection'),
    [
      { stage: 'inspection', status: 'started' },
      { stage: 'inspection', status: 'verified' },
    ],
  );
});

test('timed-out inspection hold is aborted and still runs exact reverse cleanup', async () => {
  let holdSignal;
  let aborted = false;
  let verifierCalled = false;
  const deps = dependencies({
    holdForInspection({ signal }) {
      holdSignal = signal;
      return new Promise((_, reject) => {
        signal.addEventListener('abort', () => {
          aborted = true;
          reject(new Error(SENSITIVE));
        }, { once: true });
      });
    },
    inspectionHoldTimeoutMs: 5,
    async verifyInstalledGateway() {
      verifierCalled = true;
      throw new Error(SENSITIVE);
    },
  });
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);

  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: preview.approvalId,
        targetConfirmationId: preview.targetConfirmationId,
      }),
      deps,
    ),
    (error) => {
      assert.ok(error instanceof CanaryLifecycleError);
      assert.equal(error.code, 'lifecycle_failed');
      assert.equal(error.cleanup, 'removed');
      assertDoesNotInclude(error.message, SENSITIVE);
      return true;
    },
  );
  assert.ok(holdSignal instanceof AbortSignal);
  assert.equal(aborted, true);
  assert.equal(verifierCalled, false);
  assert.deepEqual(
    deps.provider.mutations.filter(({ action }) => action === 'delete').map(({ kind }) => kind),
    [...ORDER].reverse(),
  );
  assert.equal(deps.receiptStore.value.state, 'removed');
  assert.equal(deps.provider.resources.length, 0);
});

test('wrong lifecycle approval or target confirmation performs no writes', async () => {
  for (const wrong of ['approvalId', 'targetConfirmationId']) {
    const deps = dependencies();
    const preview = await previewCloudflareCanaryLifecycle(input(), deps);
    const invocation = input({
      approvalId: preview.approvalId,
      targetConfirmationId: preview.targetConfirmationId,
      [wrong]: `wrong-${wrong}`,
    });
    await assert.rejects(
      runCloudflareCanaryLifecycle(invocation, deps),
      (error) => {
        assert.ok(error instanceof CanaryLifecycleError);
        assert.equal(
          error.code,
          wrong === 'approvalId'
            ? 'approval_required'
            : 'disposable_target_confirmation_required',
        );
        return true;
      },
    );
    assert.equal(deps.provider.mutations.length, 0);
    assert.equal(deps.receiptStore.writes.length, 0);
  }
});

test('runner-level lifecycle lock prevents a second mutation sequence', async () => {
  const deps = dependencies();
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  deps.cleanupStore.locked = true;
  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: preview.approvalId,
        targetConfirmationId: preview.targetConfirmationId,
      }),
      deps,
    ),
    (error) => error instanceof CanaryLifecycleError && error.code === 'lifecycle_locked',
  );
  assert.equal(deps.provider.mutations.length, 0);
  assert.equal(deps.receiptStore.writes.length, 0);
});

test('pre-mutation apply failure never uninstalls pre-existing receipt-owned state', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const deps = dependencies({ provider, receiptStore });
  const seed = {
    config: fixedTestCanaryConfig(),
    target: { accountId: ACCOUNT_ID, zoneId: ZONE_ID },
    access: { allowedEmails: [EMAIL] },
    release: 'cloudflare-canary-v1',
    provider,
    receiptStore,
  };
  const installPreview = await planLiveGateway(seed);
  await applyGateway({
    ...seed,
    approvedPlanId: installPreview.plan.planId,
  });
  assert.equal(provider.resources.length, ORDER.length);
  assert.equal(receiptStore.value.state, 'ready');
  const mutationCount = provider.mutations.length;

  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  provider.failReadCountdown = 2;
  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: preview.approvalId,
        targetConfirmationId: preview.targetConfirmationId,
      }),
      deps,
    ),
    (error) => {
      assert.ok(error instanceof CanaryLifecycleError);
      assert.equal(error.code, 'lifecycle_failed_before_mutation');
      assert.equal(error.cleanup, 'not_started');
      return true;
    },
  );
  assert.equal(provider.mutations.length, mutationCount);
  assert.equal(provider.mutations.some(({ action }) => action === 'delete'), false);
  assert.equal(provider.resources.length, ORDER.length);
  assert.equal(receiptStore.value.state, 'ready');
});

test('provider-proven not-submitted update cannot authorize cleanup of a ready installation', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const deps = dependencies({ provider, receiptStore });
  await installTestCanary(provider, receiptStore);
  provider.resources.find(({ kind }) => kind === 'mcp_server').desiredHash =
    `sha256:${'f'.repeat(64)}`;
  const retainedResources = clone(provider.resources);
  const retainedReceiptResources = clone(receiptStore.value.resources);
  const mutationCount = provider.mutations.length;
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  provider.definiteNotSubmittedOnce = true;

  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: preview.approvalId,
        targetConfirmationId: preview.targetConfirmationId,
      }),
      deps,
    ),
    (error) => {
      assert.ok(error instanceof CanaryLifecycleError);
      assert.equal(error.code, 'lifecycle_failed_before_mutation');
      assert.equal(error.cleanup, 'not_started');
      return true;
    },
  );

  assert.deepEqual(provider.mutations.slice(mutationCount), []);
  assert.equal(provider.mutations.some(({ action }) => action === 'delete'), false);
  assert.deepEqual(provider.resources, retainedResources);
  assert.equal(receiptStore.value.state, 'ready');
  assert.equal(receiptStore.value.pending, null);
  assert.deepEqual(receiptStore.value.resources, retainedReceiptResources);
  assert.equal(deps.cleanupStore.writes.length, 0);
});

for (const updateKind of ['mcp_server', 'portal']) {
  test(`exact receipt-owned ${updateKind} update is approved, finalized, and cleaned up`, async () => {
    const provider = new FakeProvider();
    const receiptStore = new MemoryReceiptStore();
    const deps = dependencies({ provider, receiptStore });
    await installTestCanary(provider, receiptStore);
    const drifted = provider.resources.find(({ kind }) => kind === updateKind);
    drifted.desiredHash = `sha256:${'f'.repeat(64)}`;
    const mutationCount = provider.mutations.length;

    const preview = await previewCloudflareCanaryLifecycle(input(), deps);
    assert.deepEqual(
      preview.changes.filter(({ action }) => action === 'update'),
      [{ action: 'update', kind: updateKind }],
    );
    const result = await runCloudflareCanaryLifecycle(
      input({
        approvalId: preview.approvalId,
        targetConfirmationId: preview.targetConfirmationId,
      }),
      deps,
    );

    assert.equal(result.status, 'complete');
    assert.deepEqual(provider.mutations.slice(mutationCount), [
      { action: 'update', kind: updateKind },
      ...[...ORDER].reverse().map((kind) => ({ action: 'delete', kind })),
    ]);
    assert.equal(receiptStore.value.state, 'removed');
    assert.equal(provider.resources.length, 0);
  });
}

test('a journaled receipt-owned update retries under its original plan and then cleans up', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const deps = dependencies({ provider, receiptStore });
  await installTestCanary(provider, receiptStore);
  provider.resources.find(({ kind }) => kind === 'mcp_server').desiredHash =
    `sha256:${'f'.repeat(64)}`;
  provider.failUpdateOnce = true;

  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: preview.approvalId,
        targetConfirmationId: preview.targetConfirmationId,
      }),
      deps,
    ),
    (error) => error instanceof CanaryLifecycleError && error.code === 'pending_apply_blocked',
  );
  assert.equal(receiptStore.value.state, 'installing');
  assert.equal(receiptStore.value.pending.type, 'apply');
  assert.equal(receiptStore.value.pending.action, 'update');
  const journaledPlanId = receiptStore.value.pending.planId;
  assert.match(journaledPlanId, /^plan-[0-9a-f]{24}$/);
  assert.equal(deps.cleanupStore.writes.length, 0);

  const recoveryPreview = await previewCloudflareCanaryLifecycle(input(), deps);
  assert.equal(receiptStore.value.pending.planId, journaledPlanId);
  assert.deepEqual(
    recoveryPreview.changes.filter(({ action }) => action === 'update'),
    [{ action: 'update', kind: 'mcp_server' }],
  );
  const recovered = await runCloudflareCanaryLifecycle(
    input({
      approvalId: recoveryPreview.approvalId,
      targetConfirmationId: recoveryPreview.targetConfirmationId,
    }),
    deps,
  );
  assert.equal(recovered.status, 'complete');
  assert.equal(receiptStore.value.state, 'removed');
  assert.equal(provider.resources.length, 0);
  assert.equal(
    provider.mutations.filter(({ action, kind }) =>
      action === 'update' && kind === 'mcp_server').length,
    2,
  );
});

test('foreign noop beside an owned update is rejected despite a falsely claiming observer', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const deps = dependencies({ provider, receiptStore });
  await installTestCanary(provider, receiptStore);
  const server = provider.resources.find(({ kind }) => kind === 'mcp_server');
  server.provider = { id: 'foreign-server-locator' };
  const portal = provider.resources.find(({ kind }) => kind === 'portal');
  portal.desiredHash = `sha256:${'f'.repeat(64)}`;
  provider.forceClaimOwnership = true;
  const mutationCount = provider.mutations.length;

  await assert.rejects(
    previewCloudflareCanaryLifecycle(input(), deps),
    (error) => error instanceof CanaryLifecycleError && error.code === 'plan_blocked',
  );
  assert.equal(provider.mutations.length, mutationCount);
  assert.equal(receiptStore.value.state, 'ready');
  assert.equal(receiptStore.value.resources.length, ORDER.length);
});

test('outcome-unknown create remains pending and is never replayed or cleaned up', async () => {
  const provider = new FakeProvider();
  provider.failCreateOnce = true;
  const deps = dependencies({ provider });
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: preview.approvalId,
        targetConfirmationId: preview.targetConfirmationId,
      }),
      deps,
    ),
    (error) => {
      assert.ok(error instanceof CanaryLifecycleError);
      assert.equal(error.code, 'pending_apply_blocked');
      assert.equal(error.cleanup, 'blocked_pending_apply');
      return true;
    },
  );
  assert.equal(deps.receiptStore.value.pending.type, 'apply');
  assert.equal(deps.receiptStore.value.pending.action, 'create');
  assert.deepEqual(
    deps.provider.mutations.map(({ action }) => action),
    ['create'],
  );

  const recoveryPreview = await previewCloudflareCanaryLifecycle(input(), deps);
  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: recoveryPreview.approvalId,
        targetConfirmationId: recoveryPreview.targetConfirmationId,
      }),
      deps,
    ),
    (error) => error instanceof CanaryLifecycleError && error.code === 'pending_apply_blocked',
  );
  assert.deepEqual(
    deps.provider.mutations.map(({ action }) => action),
    ['create'],
  );
  assert.equal(deps.receiptStore.value.pending.type, 'apply');
});

test('an exact partial Portal gets a separate rollback approval and the run stops after rollback', async () => {
  const provider = new FakeProvider();
  provider.failPortalCreateWithoutGeneratedAppOnce = true;
  const deps = dependencies({ provider });
  const initial = await previewCloudflareCanaryLifecycle(input(), deps);
  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: initial.approvalId,
        targetConfirmationId: initial.targetConfirmationId,
      }),
      deps,
    ),
    (error) => error instanceof CanaryLifecycleError && error.code === 'pending_apply_blocked',
  );
  assert.equal(deps.receiptStore.value.pending?.kind, 'portal');
  assert.equal(provider.resources.length, 4);
  assert.deepEqual(provider.mutations.map(({ kind }) => kind), [
    'mcp_server',
    'source_access_application',
    'source_access_policy',
    'portal',
  ]);
  const recovery = await previewCloudflareCanaryLifecycle(input(), deps);
  assert.equal(recovery.operation, 'rollback_pending_portal_create');
  assert.deepEqual(recovery.changes, [{ action: 'rollback', kind: 'portal' }]);
  assert.deepEqual(recovery.cleanup, []);
  const beforeNormalMutations = provider.mutations.length;
  const result = await runCloudflareCanaryLifecycle(
    input({
      approvalId: recovery.approvalId,
      targetConfirmationId: recovery.targetConfirmationId,
    }),
    deps,
  );

  assert.equal(result.status, 'rollback_complete');
  assert.equal(result.operation, 'rollback_pending_portal_create');
  assert.equal(result.resourceLifecycle, 'partial');
  assert.deepEqual(result.cleanup, {
    status: 'rollback_complete',
    remainingReceiptResourceCount: 3,
  });
  assert.equal(provider.portalRollbackMutations, 1);
  assert.equal(provider.mutations.length, beforeNormalMutations);
  assert.equal(provider.resources.length, 3);
  assert.equal(deps.receiptStore.value.state, 'ready');
  assert.equal(deps.receiptStore.value.pending, null);
  assert.equal(deps.receiptStore.value.resources.length, 3);
  assert.equal(deps.cleanupStore.value.state, 'installing');
  assert.equal(deps.cleanupStore.value.pending.kind, 'portal');
  assert.equal(deps.cleanupStore.value.resources.length, 3);

  const fresh = await previewCloudflareCanaryLifecycle(input(), deps);
  assert.equal(fresh.operation, 'cleanup_partial_install');
  assert.deepEqual(fresh.changes, []);
  assert.deepEqual(fresh.cleanup.map(({ action, kind }) => `${action}:${kind}`), [
    'delete:source_access_policy',
    'delete:source_access_application',
    'delete:mcp_server',
  ]);
});

test('separate partial-install cleanup deletes the exact lower-three receipt prefix in reverse', async () => {
  const deps = await seedPostRollbackPartial();
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  const mutationCount = deps.provider.mutations.length;

  assert.equal(preview.operation, 'cleanup_partial_install');
  assert.deepEqual(preview.changes, []);
  assert.deepEqual(preview.cleanup.map(({ action, kind }) => `${action}:${kind}`), [
    'delete:source_access_policy',
    'delete:source_access_application',
    'delete:mcp_server',
  ]);

  const result = await runCloudflareCanaryLifecycle(
    input({
      approvalId: preview.approvalId,
      targetConfirmationId: preview.targetConfirmationId,
    }),
    deps,
  );
  assert.equal(result.status, 'cleanup_complete');
  assert.equal(result.operation, 'cleanup_partial_install');
  assert.equal(result.interactiveVerification, 'not_applicable');
  assert.deepEqual(result.cleanup, {
    status: 'removed',
    reverseOrderVerified: true,
    ownedResourceCount: 0,
    partialInstallRemoved: true,
  });
  assert.deepEqual(deps.provider.mutations.slice(mutationCount), [
    { action: 'delete', kind: 'source_access_policy' },
    { action: 'delete', kind: 'source_access_application' },
    { action: 'delete', kind: 'mcp_server' },
  ]);
  assert.equal(deps.provider.resources.length, 0);
  assert.equal(deps.receiptStore.value.state, 'removed');
  assert.equal(deps.receiptStore.value.resources.length, 0);
  assert.equal(deps.cleanupStore.value.state, 'ready');
  assert.deepEqual(deps.cleanupStore.value.resources.map(({ kind }) => kind), ORDER.slice(0, 3));
  assert.ok(deps.provider.lastResidueSignal instanceof AbortSignal);
});

test('the exact legacy revision-8 rollback receipt bootstraps cleanup without a sidecar', async () => {
  const deps = await seedPostRollbackPartial({ rootDesiredHashMismatch: true });
  assert.equal(deps.receiptStore.value.revision, 8);
  deps.cleanupStore.value = null;
  deps.cleanupStore.writes = [];

  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  assert.equal(preview.operation, 'cleanup_partial_install');
  const result = await runCloudflareCanaryLifecycle(
    input({
      approvalId: preview.approvalId,
      targetConfirmationId: preview.targetConfirmationId,
    }),
    deps,
  );
  assert.equal(result.status, 'cleanup_complete');
  assert.equal(deps.cleanupStore.writes[0].state, 'ready');
  assert.equal(deps.cleanupStore.writes[0].resources.length, 3);
  assert.equal(deps.receiptStore.value.state, 'removed');
});

test('partial cleanup preserves and approves the live legacy root-hash mismatch shape', async () => {
  const deps = await seedPostRollbackPartial({ rootDesiredHashMismatch: true });
  const currentDesired = await buildGatewayDesiredState(fixedTestCanaryConfig(), {
    target: liveTarget(),
    access: { allowedEmails: [EMAIL] },
  });
  assert.notEqual(deps.receiptStore.value.desiredHash, currentDesired.desiredHash);
  assert.equal(deps.cleanupStore.value.desiredHash, deps.receiptStore.value.desiredHash);
  assert.deepEqual(
    deps.receiptStore.value.resources.map(({ desiredHash }) => desiredHash),
    currentDesired.resources.slice(0, 3).map(({ desiredHash }) => desiredHash),
  );

  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  assert.equal(preview.operation, 'cleanup_partial_install');
  const result = await runCloudflareCanaryLifecycle(
    input({
      approvalId: preview.approvalId,
      targetConfirmationId: preview.targetConfirmationId,
    }),
    deps,
  );
  assert.equal(result.status, 'cleanup_complete');
  assert.equal(deps.receiptStore.value.state, 'removed');
  assert.equal(deps.provider.resources.length, 0);
});

test('partial cleanup approval and live state drift both fail before any delete', async () => {
  {
    const deps = await seedPostRollbackPartial();
    const preview = await previewCloudflareCanaryLifecycle(input(), deps);
    const mutationCount = deps.provider.mutations.length;
    await assert.rejects(
      runCloudflareCanaryLifecycle(
        input({
          approvalId: `canary-lifecycle-${'0'.repeat(24)}`,
          targetConfirmationId: preview.targetConfirmationId,
        }),
        deps,
      ),
      (error) => error instanceof CanaryLifecycleError && error.code === 'approval_required',
    );
    assert.equal(deps.provider.mutations.length, mutationCount);
    assert.equal(deps.receiptStore.value.state, 'ready');
  }

  {
    const deps = await seedPostRollbackPartial();
    const preview = await previewCloudflareCanaryLifecycle(input(), deps);
    const mutationCount = deps.provider.mutations.length;
    deps.provider.resources[0].desiredHash = `sha256:${'f'.repeat(64)}`;
    await assert.rejects(
      runCloudflareCanaryLifecycle(
        input({
          approvalId: preview.approvalId,
          targetConfirmationId: preview.targetConfirmationId,
        }),
        deps,
      ),
      (error) => error instanceof CanaryLifecycleError && error.code === 'plan_blocked',
    );
    assert.equal(deps.provider.mutations.length, mutationCount);
    assert.equal(deps.provider.mutations.slice(mutationCount).some(({ action }) => action === 'delete'), false);
    assert.equal(deps.receiptStore.value.state, 'ready');
  }
});

test('partial cleanup persists its immutable snapshot before deletion and stops if that write fails', async () => {
  const deps = await seedPostRollbackPartial();
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  const markerChecksum = deps.cleanupStore.value.checksum;
  const mutationCount = deps.provider.mutations.length;
  deps.cleanupStore.failNextWrite = true;

  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: preview.approvalId,
        targetConfirmationId: preview.targetConfirmationId,
      }),
      deps,
    ),
    (error) => error instanceof CanaryLifecycleError && error.code === 'cleanup_failed',
  );
  assert.equal(deps.provider.mutations.length, mutationCount);
  assert.equal(deps.receiptStore.value.state, 'ready');
  assert.equal(deps.receiptStore.value.resources.length, 3);
  assert.equal(deps.cleanupStore.value.checksum, markerChecksum);
});

test('Portal rollback marker never overwrites a different valid cleanup sidecar', async () => {
  const provider = new FakeProvider();
  provider.failPortalCreateWithoutGeneratedAppOnce = true;
  const deps = dependencies({ provider });
  const initial = await previewCloudflareCanaryLifecycle(input(), deps);
  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: initial.approvalId,
        targetConfirmationId: initial.targetConfirmationId,
      }),
      deps,
    ),
    (error) => error instanceof CanaryLifecycleError && error.code === 'pending_apply_blocked',
  );
  const rollback = await previewCloudflareCanaryLifecycle(input(), deps);
  const conflicting = clone(deps.receiptStore.value);
  conflicting.desiredHash = `sha256:${'8'.repeat(64)}`;
  conflicting.checksum = await receiptChecksum(conflicting);
  await deps.cleanupStore.writeAtomic(conflicting);
  const conflictingChecksum = deps.cleanupStore.value.checksum;

  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: rollback.approvalId,
        targetConfirmationId: rollback.targetConfirmationId,
      }),
      deps,
    ),
    (error) => error instanceof CanaryLifecycleError && error.code === 'rollback_failed',
  );
  assert.equal(provider.portalRollbackMutations, 0);
  assert.equal(provider.resources.some(({ kind }) => kind === 'portal'), true);
  assert.equal(deps.cleanupStore.value.checksum, conflictingChecksum);
  assert.equal(deps.receiptStore.value.pending.kind, 'portal');
});

test('ordinary partial receipts and foreign partial topology never enter cleanup-only mode', async () => {
  for (const resourceIndexes of [[0], [0, 1], [0, 2]]) {
    const deps = await seedPostRollbackPartial();
    deps.receiptStore.value.resources = resourceIndexes.map((index) =>
      clone(deps.receiptStore.value.resources[index]));
    deps.receiptStore.value.revision = resourceIndexes.length * 2;
    deps.receiptStore.value.checksum = await receiptChecksum(deps.receiptStore.value);
    deps.provider.resources = resourceIndexes.map((index) => clone(deps.provider.resources[index]));
    deps.cleanupStore.value = null;

    const preview = await previewCloudflareCanaryLifecycle(input(), deps);
    assert.equal(preview.operation, 'apply_verify_uninstall');
  }

  const foreign = await seedPostRollbackPartial();
  foreign.provider.resources[0].provider = { id: 'foreign-server-locator' };
  foreign.provider.forceClaimOwnership = true;
  const mutationCount = foreign.provider.mutations.length;
  await assert.rejects(
    previewCloudflareCanaryLifecycle(input(), foreign),
    (error) => error instanceof CanaryLifecycleError && error.code === 'plan_blocked',
  );
  assert.equal(foreign.provider.mutations.length, mutationCount);
});

test('a pre-release generated-app receipt requires manual cleanup without mutation', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const deps = dependencies({ provider, receiptStore });
  await installTestCanary(provider, receiptStore);
  receiptStore.value = asLegacyGeneratedAppReceipt(receiptStore.value);
  provider.resources = provider.resources.filter(({ kind }) =>
    kind !== 'portal_access_application');
  const mutationCount = provider.mutations.length;
  const receiptWriteCount = receiptStore.writes.length;
  const cleanupWriteCount = deps.cleanupStore.writes.length;

  await assert.rejects(
    previewCloudflareCanaryLifecycle(input(), deps),
    (error) => {
      assert.ok(error instanceof CanaryLifecycleError);
      assert.equal(error.code, 'legacy_manual_cleanup_required');
      assert.equal(
        error.message,
        'This pre-release legacy receipt requires manual cleanup; no automated mutation was authorized.',
      );
      return true;
    },
  );
  assert.equal(provider.mutations.length, mutationCount);
  assert.equal(receiptStore.writes.length, receiptWriteCount);
  assert.equal(deps.cleanupStore.writes.length, cleanupWriteCount);
});

test('a legacy cleanup snapshot behind a current tombstone also fails closed', async () => {
  const deps = dependencies();
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  await runCloudflareCanaryLifecycle(
    input({
      approvalId: preview.approvalId,
      targetConfirmationId: preview.targetConfirmationId,
    }),
    deps,
  );
  deps.cleanupStore.value = asLegacyGeneratedAppReceipt(deps.cleanupStore.value);
  const mutationCount = deps.provider.mutations.length;
  const receiptWriteCount = deps.receiptStore.writes.length;
  const cleanupWriteCount = deps.cleanupStore.writes.length;

  await assert.rejects(
    previewCloudflareCanaryLifecycle(input(), deps),
    (error) =>
      error instanceof CanaryLifecycleError &&
      error.code === 'legacy_manual_cleanup_required',
  );
  assert.equal(deps.receiptStore.value.state, 'removed');
  assert.equal(deps.provider.mutations.length, mutationCount);
  assert.equal(deps.receiptStore.writes.length, receiptWriteCount);
  assert.equal(deps.cleanupStore.writes.length, cleanupWriteCount);
});

test('any upper-layer residue blocks partial cleanup before mutation', async () => {
  const deps = await seedPostRollbackPartial();
  const desired = await buildGatewayDesiredState(fixedTestCanaryConfig(), {
    target: liveTarget(),
    access: { allowedEmails: [EMAIL] },
  });
  const portal = desired.resources.find(({ kind }) => kind === 'portal');
  deps.provider.forceClaimOwnership = true;
  deps.provider.resources.push({
    kind: portal.kind,
    key: portal.key,
    provider: { id: portal.key },
    marker: ownershipMarker(deps.receiptStore.value.installationId, portal.key),
    desiredHash: portal.desiredHash,
  });
  const mutationCount = deps.provider.mutations.length;

  await assert.rejects(
    previewCloudflareCanaryLifecycle(input(), deps),
    (error) => error instanceof CanaryLifecycleError && error.code === 'plan_blocked',
  );
  assert.equal(deps.provider.mutations.length, mutationCount);
  assert.equal(deps.receiptStore.value.state, 'ready');
  assert.equal(deps.receiptStore.value.resources.length, 3);
});

test('partial cleanup crash after a committed delete resumes from the immutable snapshot', async () => {
  const deps = await seedPostRollbackPartial();
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  deps.provider.failReadAfterCommittedDeleteOnce = true;

  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: preview.approvalId,
        targetConfirmationId: preview.targetConfirmationId,
      }),
      deps,
    ),
    (error) => error instanceof CanaryLifecycleError && error.code === 'cleanup_failed',
  );
  assert.equal(deps.receiptStore.value.state, 'uninstalling');
  assert.equal(deps.receiptStore.value.pending, null);
  assert.ok(deps.receiptStore.value.resources.length < 3);
  assert.equal(deps.cleanupStore.value.state, 'ready');
  assert.equal(deps.cleanupStore.value.resources.length, 3);

  const recovery = await previewCloudflareCanaryLifecycle(input(), deps);
  assert.equal(recovery.operation, 'resume_uninstall');
  const result = await runCloudflareCanaryLifecycle(
    input({
      approvalId: recovery.approvalId,
      targetConfirmationId: recovery.targetConfirmationId,
    }),
    deps,
  );
  assert.equal(result.cleanup.recoveredInterruptedUninstall, true);
  assert.equal(deps.receiptStore.value.state, 'removed');
  assert.equal(deps.provider.resources.length, 0);
  assert.equal(deps.cleanupStore.value.resources.length, 3);
});

test('an exact pending Portal takes ordinary no-replay recovery before legacy rollback', async () => {
  const provider = new FakeProvider();
  provider.failPortalCreateAfterCommitOnce = true;
  const deps = dependencies({ provider });
  const initial = await previewCloudflareCanaryLifecycle(input(), deps);
  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: initial.approvalId,
        targetConfirmationId: initial.targetConfirmationId,
      }),
      deps,
    ),
    (error) => error instanceof CanaryLifecycleError && error.code === 'pending_apply_blocked',
  );
  const pendingPortal = provider.resources.find(({ kind }) => kind === 'portal');
  assert.ok(pendingPortal);
  const portalCreateCount = provider.mutations.filter(({ action, kind }) =>
    action === 'create' && kind === 'portal').length;

  const recovery = await previewCloudflareCanaryLifecycle(input(), deps);
  assert.equal(recovery.operation, 'apply_verify_uninstall');
  assert.deepEqual(recovery.changes.map(({ action }) => action), [
    'noop', 'noop', 'noop', 'noop', 'create', 'create', 'create',
  ]);
  const result = await runCloudflareCanaryLifecycle(
    input({
      approvalId: recovery.approvalId,
      targetConfirmationId: recovery.targetConfirmationId,
    }),
    deps,
  );

  assert.equal(result.status, 'complete');
  assert.equal(provider.portalRollbackInspections, 0);
  assert.equal(provider.portalRollbackMutations, 0);
  assert.equal(provider.mutations.filter(({ action, kind }) =>
    action === 'create' && kind === 'portal').length, portalCreateCount);
  assert.equal(deps.receiptStore.value.state, 'removed');
});

test('malformed or ambiguous late Portal state is neither recovered nor rolled back', async () => {
  for (const collision of ['malformed', 'ambiguous']) {
    const provider = new FakeProvider();
    provider.failPortalCreateWithoutGeneratedAppOnce = true;
    const deps = dependencies({ provider });
    const initial = await previewCloudflareCanaryLifecycle(input(), deps);
    await assert.rejects(
      runCloudflareCanaryLifecycle(
        input({
          approvalId: initial.approvalId,
          targetConfirmationId: initial.targetConfirmationId,
        }),
        deps,
      ),
      (error) => error instanceof CanaryLifecycleError && error.code === 'pending_apply_blocked',
    );
    const pendingPortal = provider.resources.find(({ kind }) => kind === 'portal');
    pendingPortal.marker = 'foreign-marker';
    if (collision === 'ambiguous') {
      provider.resources.push(clone(pendingPortal));
    }
    provider.inspectPendingPortalCreateRollback = async () => {
      provider.portalRollbackInspections += 1;
      throw new Error(SENSITIVE);
    };
    const beforeMutations = provider.mutations.length;

    await assert.rejects(
      previewCloudflareCanaryLifecycle(input(), deps),
      (error) => error instanceof CanaryLifecycleError && error.code === 'plan_blocked',
      collision,
    );
    assert.equal(provider.portalRollbackInspections, 1, collision);
    assert.equal(provider.portalRollbackMutations, 0, collision);
    assert.equal(provider.mutations.length, beforeMutations, collision);
    assert.equal(deps.receiptStore.value.pending?.kind, 'portal', collision);
  }
});

test('synthetic fixture proof is mandatory before planning or writing', async () => {
  const deps = dependencies({
    inspectSyntheticUpstream: async () => ({
      ...fixtureEvidence(),
      toolNames: ['unsafe_production_tool'],
      rawBody: SENSITIVE,
    }),
  });
  await assert.rejects(
    previewCloudflareCanaryLifecycle(input(), deps),
    (error) => {
      assert.ok(error instanceof CanaryLifecycleError);
      assert.equal(error.code, 'synthetic_upstream_invalid');
      assertDoesNotInclude(error.message, SENSITIVE);
      return true;
    },
  );
  assert.equal(deps.provider.mutations.length, 0);
  assert.equal(deps.receiptStore.writes.length, 0);
});

test('failed installed verification still cleans up receipt-owned resources', async () => {
  const deps = dependencies({
    verifyInstalledGateway: async () => {
      throw new Error(SENSITIVE);
    },
  });
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: preview.approvalId,
        targetConfirmationId: preview.targetConfirmationId,
      }),
      deps,
    ),
    (error) => {
      assert.ok(error instanceof CanaryLifecycleError);
      assert.equal(error.code, 'lifecycle_failed');
      assert.equal(error.cleanup, 'removed');
      assertDoesNotInclude(error.message, SENSITIVE);
      return true;
    },
  );
  assert.equal(deps.provider.resources.length, 0);
  assert.equal(deps.receiptStore.value.state, 'removed');
});

for (const committedResourceCount of [1, 2]) {
  test(`cleanup preserves and verifies an immutable ${committedResourceCount}-resource snapshot`, async () => {
    const provider = new FakeProvider();
    provider.failReadAfterCommittedCreateCount = committedResourceCount;
    let residueReceipt;
    const deps = dependencies({
      provider,
      inspectCanaryResidue: async ({ receipt, signal }) => {
        residueReceipt = clone(receipt);
        provider.lastResidueSignal = signal;
        return { ownedResourceCount: 0 };
      },
    });
    const preview = await previewCloudflareCanaryLifecycle(input(), deps);

    await assert.rejects(
      runCloudflareCanaryLifecycle(
        input({
          approvalId: preview.approvalId,
          targetConfirmationId: preview.targetConfirmationId,
        }),
        deps,
      ),
      (error) => {
        assert.ok(error instanceof CanaryLifecycleError);
        assert.equal(error.code, 'lifecycle_failed');
        assert.equal(error.cleanup, 'removed');
        return true;
      },
    );
    assert.equal(deps.receiptStore.value.state, 'removed');
    assert.equal(provider.resources.length, 0);
    assert.equal(deps.cleanupStore.value.resources.length, committedResourceCount);
    assert.equal(residueReceipt.resources.length, committedResourceCount);
    assert.deepEqual(
      residueReceipt.resources.map(({ kind }) => kind),
      ORDER.slice(0, committedResourceCount),
    );
    assert.deepEqual(
      provider.mutations.map(({ action, kind }) => `${action}:${kind}`),
      [
        ...ORDER.slice(0, committedResourceCount).map((kind) => `create:${kind}`),
        ...ORDER.slice(0, committedResourceCount).reverse().map((kind) => `delete:${kind}`),
      ],
    );
  });
}

test('API-state canary remains honest when interactive Portal OAuth is not performed', async () => {
  const deps = dependencies();
  delete deps.verifyInstalledGateway;
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  const result = await runCloudflareCanaryLifecycle(
    input({
      approvalId: preview.approvalId,
      targetConfirmationId: preview.targetConfirmationId,
    }),
    deps,
  );

  assert.equal(result.installedStateVerified, true);
  assert.equal(result.portalToolCallVerified, false);
  assert.equal(result.status, 'verification_pending');
  assert.equal(result.resourceLifecycle, 'removed');
  assert.equal(result.interactiveVerification, 'pending');
  assert.equal(result.cleanup.status, 'removed');
});

test('real random Quick Tunnel hostname is accepted only after strict fixture proof', async () => {
  const quickTunnel = 'https://painted-cloud-river.trycloudflare.com/mcp';
  const deps = dependencies();
  let inspectedEndpoint;
  deps.inspectSyntheticUpstream = async ({ endpoint }) => {
    inspectedEndpoint = endpoint;
    return fixtureEvidence();
  };

  const preview = await previewCloudflareCanaryLifecycle(
    input({ syntheticMcpUrl: quickTunnel }),
    deps,
  );
  assert.equal(preview.ready, true);
  assert.equal(inspectedEndpoint, quickTunnel);

  deps.inspectSyntheticUpstream = async () => ({
    ...fixtureEvidence(),
    toolNames: ['not_the_canary_tool'],
  });
  await assert.rejects(
    previewCloudflareCanaryLifecycle(input({ syntheticMcpUrl: quickTunnel }), deps),
    (error) => error instanceof CanaryLifecycleError && error.code === 'synthetic_upstream_invalid',
  );
});

test('removed receipt resumes residue verification from the crash-safe cleanup snapshot', async () => {
  let residueReadsFail = true;
  const deps = dependencies({
    inspectCanaryResidue: async () => {
      if (residueReadsFail) throw new Error(SENSITIVE);
      return { ownedResourceCount: 0 };
    },
    pollAttemptTimeoutMs: 5,
    pollOverallTimeoutMs: 25,
  });
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: preview.approvalId,
        targetConfirmationId: preview.targetConfirmationId,
      }),
      deps,
    ),
    (error) => error instanceof CanaryLifecycleError && error.code === 'cleanup_failed',
  );
  assert.equal(deps.receiptStore.value.state, 'removed');
  assert.equal(deps.cleanupStore.value.state, 'ready');
  assert.equal(deps.cleanupStore.value.resources.length, ORDER.length);

  residueReadsFail = false;
  const recoveryPreview = await previewCloudflareCanaryLifecycle(input(), deps);
  assert.equal(recoveryPreview.operation, 'residue_recovery');
  assert.deepEqual(recoveryPreview.changes, []);
  const mutationCount = deps.provider.mutations.length;
  const recovered = await runCloudflareCanaryLifecycle(
    input({
      approvalId: recoveryPreview.approvalId,
      targetConfirmationId: recoveryPreview.targetConfirmationId,
    }),
    deps,
  );
  assert.equal(recovered.cleanup.recoveredAfterTombstone, true);
  assert.equal(recovered.writesPerformed, false);
  assert.equal(deps.provider.mutations.length, mutationCount);
});

test('pending uninstall resumes with the originally journaled exact approval', async () => {
  const provider = new FakeProvider();
  provider.failDeleteOnce = true;
  const deps = dependencies({ provider });
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: preview.approvalId,
        targetConfirmationId: preview.targetConfirmationId,
      }),
      deps,
    ),
    (error) => error instanceof CanaryLifecycleError && error.code === 'cleanup_failed',
  );
  assert.equal(deps.receiptStore.value.state, 'uninstalling');
  assert.equal(deps.receiptStore.value.pending.type, 'uninstall');

  const recoveryPreview = await previewCloudflareCanaryLifecycle(input(), deps);
  assert.equal(recoveryPreview.operation, 'resume_uninstall');
  assert.deepEqual(recoveryPreview.changes, []);
  const recovered = await runCloudflareCanaryLifecycle(
    input({
      approvalId: recoveryPreview.approvalId,
      targetConfirmationId: recoveryPreview.targetConfirmationId,
    }),
    deps,
  );
  assert.equal(recovered.cleanup.recoveredInterruptedUninstall, true);
  assert.equal(deps.receiptStore.value.state, 'removed');
  assert.equal(deps.provider.resources.length, 0);
});

test('uninstalling receipt with committed deletions and no pending action resumes safely', async () => {
  const provider = new FakeProvider();
  provider.failReadAfterCommittedDeleteOnce = true;
  const deps = dependencies({ provider });
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: preview.approvalId,
        targetConfirmationId: preview.targetConfirmationId,
      }),
      deps,
    ),
    (error) => error instanceof CanaryLifecycleError && error.code === 'cleanup_failed',
  );
  assert.equal(deps.receiptStore.value.state, 'uninstalling');
  assert.equal(deps.receiptStore.value.pending, null);
  assert.ok(deps.receiptStore.value.resources.length > 0);
  assert.ok(deps.receiptStore.value.resources.length < ORDER.length);
  const originalCleanupLocators = receiptLocators(deps.cleanupStore.value);
  assert.equal(originalCleanupLocators.length, ORDER.length);

  const recoveryPreview = await previewCloudflareCanaryLifecycle(input(), deps);
  assert.equal(recoveryPreview.operation, 'resume_uninstall');
  const recovered = await runCloudflareCanaryLifecycle(
    input({
      approvalId: recoveryPreview.approvalId,
      targetConfirmationId: recoveryPreview.targetConfirmationId,
    }),
    deps,
  );
  assert.equal(recovered.cleanup.recoveredInterruptedUninstall, true);
  assert.equal(deps.receiptStore.value.state, 'removed');
  assert.equal(deps.provider.resources.length, 0);
  assert.deepEqual(receiptLocators(deps.cleanupStore.value), originalCleanupLocators);
  assert.equal(deps.cleanupStore.value.resources.length, ORDER.length);
});

test('exhausted uninstall finalizes after a failed tombstone write', async () => {
  const receiptStore = new MemoryReceiptStore();
  receiptStore.failRemovedWriteOnce = true;
  const deps = dependencies({ receiptStore });
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: preview.approvalId,
        targetConfirmationId: preview.targetConfirmationId,
      }),
      deps,
    ),
    (error) => error instanceof CanaryLifecycleError && error.code === 'cleanup_failed',
  );
  assert.equal(deps.receiptStore.value.state, 'uninstalling');
  assert.equal(deps.receiptStore.value.pending, null);
  assert.equal(deps.receiptStore.value.resources.length, 0);

  const recoveryPreview = await previewCloudflareCanaryLifecycle(input(), deps);
  assert.equal(recoveryPreview.operation, 'resume_uninstall');
  assert.deepEqual(recoveryPreview.cleanup, []);
  const recovered = await runCloudflareCanaryLifecycle(
    input({
      approvalId: recoveryPreview.approvalId,
      targetConfirmationId: recoveryPreview.targetConfirmationId,
    }),
    deps,
  );
  assert.equal(recovered.cleanup.recoveredInterruptedUninstall, true);
  assert.equal(deps.receiptStore.value.state, 'removed');
});

test('hung installed verification is wall-clock bounded and cleanup still runs', {
  timeout: 5_000,
}, async () => {
  let receivedSignal;
  const deps = dependencies({
    verifyInstalledGateway: ({ signal }) => {
      receivedSignal = signal;
      return new Promise(() => {});
    },
    pollAttemptTimeoutMs: 5,
    pollOverallTimeoutMs: 20,
  });
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: preview.approvalId,
        targetConfirmationId: preview.targetConfirmationId,
      }),
      deps,
    ),
    (error) => error instanceof CanaryLifecycleError && error.code === 'lifecycle_failed',
  );
  assert.equal(receivedSignal?.aborted, true);
  assert.equal(deps.receiptStore.value.state, 'removed');
  assert.equal(deps.provider.resources.length, 0);
});

test('owned residue is reported after the exact seven-resource cleanup', async () => {
  const deps = dependencies({
    inspectCanaryResidue: async () => ({
      ownedResourceCount: 1,
    }),
  });
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: preview.approvalId,
        targetConfirmationId: preview.targetConfirmationId,
      }),
      deps,
    ),
    (error) => {
      assert.ok(error instanceof CanaryLifecycleError);
      assert.equal(error.code, 'residue_detected');
      assert.equal(error.cleanup, 'removed');
      return true;
    },
  );
  assert.equal(deps.provider.resources.length, 0);
  assert.deepEqual(
    deps.provider.mutations.map(({ action, kind }) => `${action}:${kind}`),
    [
      ...ORDER.map((kind) => `create:${kind}`),
      ...[...ORDER].reverse().map((kind) => `delete:${kind}`),
    ],
  );
});

test('residue warning dominates an earlier installed-verification failure', async () => {
  const deps = dependencies({
    verifyInstalledGateway: async () => {
      throw new Error(SENSITIVE);
    },
    inspectCanaryResidue: async () => ({
      ownedResourceCount: 1,
    }),
  });
  const preview = await previewCloudflareCanaryLifecycle(input(), deps);
  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: preview.approvalId,
        targetConfirmationId: preview.targetConfirmationId,
      }),
      deps,
    ),
    (error) => {
      assert.ok(error instanceof CanaryLifecycleError);
      assert.equal(error.code, 'residue_detected');
      assert.equal(error.cleanup, 'removed');
      assertDoesNotInclude(error.message, SENSITIVE);
      return true;
    },
  );
  assert.equal(deps.receiptStore.value.state, 'removed');
  assert.equal(deps.provider.resources.length, 0);
});

test('production-looking gateway hostnames and non-synthetic endpoints fail closed', async () => {
  const deps = dependencies();
  await assert.rejects(
    previewCloudflareCanaryLifecycle(input({ hostname: `gateway.${ZONE_NAME}` }), deps),
    (error) => error instanceof CanaryLifecycleError && error.code === 'invalid_input',
  );
  await assert.rejects(
    previewCloudflareCanaryLifecycle(
      input({ syntheticMcpUrl: 'https://production.example.net/mcp' }),
      deps,
    ),
    (error) => error instanceof CanaryLifecycleError && error.code === 'invalid_input',
  );
  await assert.rejects(
    previewCloudflareCanaryLifecycle(
      input({ syntheticMcpUrl: 'https://trycloudflare.com/mcp' }),
      deps,
    ),
    (error) => error instanceof CanaryLifecycleError && error.code === 'invalid_input',
  );
  assert.equal(deps.provider.mutations.length, 0);
});

function sameProvider(left, right) {
  return left?.id === right?.id && (left?.parentId ?? '') === (right?.parentId ?? '');
}

function receiptLocators(receipt) {
  return receipt.resources
    .map((resource) => ({
      kind: resource.kind,
      key: resource.key,
      id: resource.provider.id,
      parentId: resource.provider.parentId ?? '',
    }))
    .sort((left, right) => left.kind.localeCompare(right.kind));
}

function fixedTestCanaryConfig() {
  return {
    schemaVersion: 1,
    gateway: {
      name: 'Ankka disposable canary',
      hostname: HOSTNAME,
      codeMode: 'off',
    },
    policy: {
      capabilityMode: 'read_only',
      credentialCustody: 'customer',
      telemetry: 'off',
    },
    sources: [{
      id: 'synthetic-canary',
      label: 'Ankka synthetic canary',
      url: ENDPOINT,
      authentication: { mode: 'none', onBehalfOfUser: false },
      enabledTools: [CANARY_TOOL_NAME],
    }],
  };
}

async function installTestCanary(provider, receiptStore) {
  const seed = {
    config: fixedTestCanaryConfig(),
    target: { accountId: ACCOUNT_ID, zoneId: ZONE_ID },
    access: { allowedEmails: [EMAIL] },
    release: 'cloudflare-canary-v1',
    provider,
    receiptStore,
  };
  const preview = await planLiveGateway(seed);
  await applyGateway({ ...seed, approvedPlanId: preview.plan.planId });
}

async function seedPostRollbackPartial(overrides = {}) {
  const {
    rootDesiredHashMismatch = false,
    ...dependencyOverrides
  } = overrides;
  const provider = dependencyOverrides.provider ?? new FakeProvider();
  provider.failPortalCreateWithoutGeneratedAppOnce = true;
  const deps = dependencies({ ...dependencyOverrides, provider });
  const initial = await previewCloudflareCanaryLifecycle(input(), deps);
  await assert.rejects(
    runCloudflareCanaryLifecycle(
      input({
        approvalId: initial.approvalId,
        targetConfirmationId: initial.targetConfirmationId,
      }),
      deps,
    ),
    (error) => error instanceof CanaryLifecycleError && error.code === 'pending_apply_blocked',
  );
  if (rootDesiredHashMismatch) {
    deps.receiptStore.value.desiredHash = `sha256:${'8'.repeat(64)}`;
    deps.receiptStore.value.checksum = await receiptChecksum(deps.receiptStore.value);
  }
  const rollback = await previewCloudflareCanaryLifecycle(input(), deps);
  assert.equal(rollback.operation, 'rollback_pending_portal_create');
  await runCloudflareCanaryLifecycle(
    input({
      approvalId: rollback.approvalId,
      targetConfirmationId: rollback.targetConfirmationId,
    }),
    deps,
  );
  assert.equal(deps.receiptStore.value.state, 'ready');
  assert.equal(deps.receiptStore.value.resources.length, 3);
  return deps;
}

function asLegacyGeneratedAppReceipt(receipt) {
  const legacy = clone(receipt);
  const portalApplication = legacy.resources.find(({ kind }) =>
    kind === 'portal_access_application');
  const portal = legacy.resources.find(({ kind }) => kind === 'portal');
  assert.ok(portalApplication);
  assert.ok(portal);
  portal.generatedAccessAppId = portalApplication.provider.id;
  legacy.resources = legacy.resources.filter(({ kind }) =>
    kind !== 'portal_access_application');
  return legacy;
}

function clone(value) {
  return value === null || value === undefined ? value : structuredClone(value);
}
