import test from 'node:test';
import assert from 'node:assert/strict';
import * as v from 'valibot';
import {
  GatewayReconcileError,
  applyGateway,
  getGatewayStatus,
  planPendingPortalCreateRollback,
  planGatewayUninstall,
  planLiveGateway,
  rollbackPendingPortalCreate,
  uninstallGateway,
} from '../src/reconciler.ts';
import { buildGatewayDesiredState } from '../src/plan.ts';
import { readCloudflareObservedState } from '../src/cloudflare-observed.ts';
import {
  beginReceiptAction,
  clearReceiptAction,
  commitReceiptAction,
  createInstallationReceipt,
  ownershipMarker,
  validateInstallationReceipt,
} from '../src/receipt.ts';

const EXPECTED_ORDER = [
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
];

const canonicalPrimitiveSchema = v.union([v.null(), v.boolean(), v.string()]);
const canonicalNumberSchema = v.pipe(v.number(), v.finite());
const canonicalRecordSchema = v.record(v.string(), v.unknown());
const REVERSE_ORDER = [...EXPECTED_ORDER].reverse();
const DRIFT_HASH = `sha256:${'0'.repeat(64)}`;

function config(sourceCount = 1) {
  const sources = [
    {
      id: 'company-context',
      label: 'Company context',
      url: 'https://context.example.com/mcp',
      authentication: { mode: 'oauth', onBehalfOfUser: true },
      enabledTools: ['company_search', 'company_prepare'],
    },
    {
      id: 'analytics',
      label: 'Analytics',
      url: 'https://analytics.example.com/mcp',
      authentication: { mode: 'oauth', onBehalfOfUser: true },
      enabledTools: ['analytics_report'],
    },
  ];
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
    sources: sources.slice(0, sourceCount),
  };
}

function selectedTarget(overrides = {}) {
  return {
    accountId: 'account_123',
    zoneId: 'zone_123',
    zoneName: 'example.com',
    ...overrides,
  };
}

function liveTarget(overrides = {}) {
  return {
    ...selectedTarget(),
    zoneStatus: 'active',
    zeroTrustReady: true,
    ...overrides,
  };
}

function access() {
  return { allowedEmails: ['owner@example.com'] };
}

function clone(value) {
  return value === null || value === undefined ? value : structuredClone(value);
}

async function testHashCanonical(value) {
  const bytes = new TextEncoder().encode(testCanonicalJson(value));
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return `sha256:${[...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}`;
}

function testCanonicalJson(value) {
  if (v.safeParse(canonicalPrimitiveSchema, value).success) return JSON.stringify(value);
  if (v.safeParse(canonicalNumberSchema, value).success) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(testCanonicalJson).join(',')}]`;
  const record = v.safeParse(canonicalRecordSchema, value);
  if (record.success) {
    return `{${Object.keys(record.output)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${testCanonicalJson(record.output[key])}`)
      .join(',')}}`;
  }
  throw new TypeError('unsupported test hash value');
}

function sameProvider(left, right) {
  return (
    left?.id === right?.id &&
    (left?.parentId ?? '') === (right?.parentId ?? '')
  );
}

function isPolicy(kind) {
  return kind === 'source_access_policy' || kind === 'portal_access_policy';
}

class MemoryReceiptStore {
  constructor(timeline = []) {
    this.value = null;
    this.writes = [];
    this.timeline = timeline;
    this.onWrite = null;
    this.locked = false;
  }

  async withExclusiveLock(operation) {
    if (this.locked) {
      const error = new Error('locked');
      error.code = 'locked';
      throw error;
    }
    this.locked = true;
    try {
      return await operation();
    } finally {
      this.locked = false;
    }
  }

  async read() {
    return clone(this.value);
  }

  async writeAtomic(value) {
    const copy = clone(value);
    this.value = copy;
    this.writes.push(copy);
    this.timeline.push({ type: 'receipt_write', pending: copy.pending?.action ?? null });
    if (this.onWrite) await this.onWrite(copy);
  }
}

class FakeProvider {
  constructor({ target = liveTarget(), timeline = [] } = {}) {
    this.target = clone(target);
    this.timeline = timeline;
    this.resources = [];
    this.mutations = [];
    this.mutationTargets = [];
    this.readCount = 0;
    this.nextId = 1;
    this.definiteNotSubmittedOnce = false;
    this.failBeforeRemoteMutationOnce = false;
    this.failAfterRemoteMutationOnce = false;
    this.duplicateFailedCreate = false;
    this.beforeMutation = null;
    this.beforePortalRollback = null;
    this.portalRollbackInspections = 0;
    this.portalRollbackMutations = 0;
  }

  async readObservedState({ config: gatewayConfig, access: accessInput, receipt }) {
    // Deriving desired state here makes the fake fail when its target/config no
    // longer satisfy the same planner contract as the production reader.
    await buildGatewayDesiredState(gatewayConfig, {
      target: this.target,
      access: accessInput,
    });
    this.readCount += 1;
    this.timeline.push({ type: 'read', number: this.readCount });

    return {
      target: clone(this.target),
      resources: this.resources.map((resource) => {
        const owned = receipt?.resources.find(
          (candidate) =>
            candidate.kind === resource.kind &&
            candidate.key === resource.key &&
            sameProvider(candidate.provider, resource.provider),
        );
        const pending = receipt?.pending;
        const pendingCreate =
          pending?.action === 'create' &&
          pending.kind === resource.kind &&
          pending.key === resource.key &&
          pending.expectedDesiredHash === resource.desiredHash;
        const expectedMarker = receipt
          ? ownershipMarker(receipt.installationId, resource.key)
          : null;
        const markerlessApplication = resource.kind === 'portal_access_application';
        const receiptProof =
          owned &&
          (markerlessApplication ||
            (resource.marker === expectedMarker) ||
            (isPolicy(resource.kind) &&
              owned.identityHash !== undefined &&
              owned.identityHash === resource.identityHash));
        const pendingProof = pendingCreate
          && !markerlessApplication
          && resource.marker === expectedMarker;
        const isOwned = !resource.forceForeign && (receiptProof || pendingProof);
        return {
          kind: resource.kind,
          key: resource.key,
          provider: clone(resource.provider),
          owner: isOwned
            ? {
                manager: 'ankka-mcp-gateway',
                installationId: receipt.installationId,
              }
            : { manager: 'someone-else', installationId: 'foreign-installation' },
          desiredHash: resource.desiredHash,
        };
      }),
      diagnostics: [{ code: 'synthetic_ok', rawBody: 'must-not-escape' }],
    };
  }

  async applyChange({ change, receipt, target }) {
    this.mutationTargets.push(clone(target));
    if (this.beforeMutation) await this.beforeMutation(change, receipt);
    if (this.definiteNotSubmittedOnce) {
      this.definiteNotSubmittedOnce = false;
      const error = new Error('synthetic definite pre-write refusal');
      error.mutationOutcome = 'not_submitted';
      throw error;
    }
    this.mutations.push({ action: change.action, kind: change.kind, key: change.key });
    this.timeline.push({ type: 'mutation', action: change.action, kind: change.kind });

    if (this.failBeforeRemoteMutationOnce) {
      this.failBeforeRemoteMutationOnce = false;
      throw new Error('synthetic outcome-unknown transport failure');
    }

    let submittedProvider;
    if (change.action === 'create') {
      const sequence = this.nextId++;
      const parentKey = change.desired?.sourceApplicationResourceKey ??
        change.desired?.portalApplicationResourceKey;
      const policyParent = isPolicy(change.kind)
        ? this.resources.find((resource) =>
          (resource.kind === 'source_access_application' ||
            resource.kind === 'portal_access_application') &&
          resource.key === parentKey)
        : null;
      const provider = isPolicy(change.kind)
        ? {
            id: `policy-${sequence}`,
            parentId: policyParent.provider.id,
          }
        : { id: `resource-${sequence}` };
      submittedProvider = provider;
      const created = {
        kind: change.kind,
        key: change.key,
        provider,
        desiredHash: change.desiredHash,
        marker: ownershipMarker(receipt.installationId, change.key),
        identityHash: change.desired?.allow?.identitiesHash,
      };
      this.resources.push(created);
      if (this.duplicateFailedCreate) {
        this.resources.push({
          ...clone(created),
          provider: isPolicy(change.kind)
            ? { id: `policy-${this.nextId}`, parentId: provider.parentId }
            : { id: `resource-${this.nextId}` },
        });
        this.nextId += 1;
      }
    } else {
      const index = this.resources.findIndex(
        (resource) =>
          resource.kind === change.kind &&
          resource.key === change.key &&
          sameProvider(resource.provider, change.provider),
      );
      if (change.action === 'update') {
        if (index === -1) throw new Error('not found');
        this.resources[index] = {
          ...this.resources[index],
          desiredHash: change.desiredHash,
          marker: ownershipMarker(receipt.installationId, change.key),
          identityHash: change.desired?.allow?.identitiesHash,
        };
      } else if (change.action === 'delete' && index !== -1) {
        // Missing entries are the fake provider's normalized 404 convergence.
        this.resources.splice(index, 1);
      }
    }

    if (this.failAfterRemoteMutationOnce) {
      this.failAfterRemoteMutationOnce = false;
      throw new Error('synthetic ambiguous transport failure');
    }
    if (change.action === 'create' && change.kind === 'portal_access_application') {
      return { status: 'submitted', provider: clone(submittedProvider) };
    }
    return { status: 'submitted' };
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
    if (this.beforePortalRollback) await this.beforePortalRollback(change);
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
    return {
      status: 'rolled_back',
      portalKey: change.key,
      deleteRequest: 'confirmed',
    };
  }
}

function context(provider, receiptStore, overrides = {}) {
  return {
    config: config(),
    target: selectedTarget(),
    access: access(),
    release: 'test-release',
    provider,
    receiptStore,
    ...overrides,
  };
}

async function install(provider, receiptStore, overrides = {}) {
  const base = context(provider, receiptStore, overrides);
  const preview = await planLiveGateway(base);
  const result = await applyGateway({ ...base, approvedPlanId: preview.plan.planId });
  return { base, preview, result };
}

async function expectCode(promise, code) {
  await assert.rejects(
    promise,
    (error) => error instanceof GatewayReconcileError && error.code === code,
  );
}

async function seedPendingPortalRollback(provider, receiptStore, {
  portalPresent = true,
  portalForeign = true,
  receiptDesiredHash,
} = {}) {
  const base = context(provider, receiptStore);
  const desired = await buildGatewayDesiredState(base.config, {
    target: provider.target,
    access: base.access,
  });
  const server = desired.resources.find(({ kind }) => kind === 'mcp_server');
  const application = desired.resources.find(({ kind }) => kind === 'source_access_application');
  const sourcePolicy = desired.resources.find(({ kind }) => kind === 'source_access_policy');
  const portal = desired.resources.find(({ kind }) => kind === 'portal');
  const applicationId = 'source-app-pending-portal';
  const lowerResources = [
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
      provider: { id: applicationId },
      desiredHash: application.desiredHash,
      marker: ownershipMarker(desired.installationId, application.key),
    },
    {
      kind: sourcePolicy.kind,
      key: sourcePolicy.key,
      provider: { id: 'source-policy-pending-portal', parentId: applicationId },
      desiredHash: sourcePolicy.desiredHash,
      marker: ownershipMarker(desired.installationId, sourcePolicy.key),
      identityHash: sourcePolicy.desired.allow.identitiesHash,
    },
  ];
  receiptStore.value = await createInstallationReceipt({
    plan: {
      installationId: desired.installationId,
      release: base.release,
      desiredHash: receiptDesiredHash ?? desired.desiredHash,
    },
    target: {
      accountId: provider.target.accountId,
      zoneId: provider.target.zoneId,
      zoneName: provider.target.zoneName,
      hostname: base.config.gateway.hostname,
    },
    accessPolicy: desired.accessPolicy,
    resources: lowerResources,
  });
  const request = {
    type: 'apply',
    planId: 'plan-pending-portal-create',
    action: 'create',
    kind: portal.kind,
    key: portal.key,
    expectedDesiredHash: portal.desiredHash,
  };
  receiptStore.value = await beginReceiptAction(receiptStore.value, {
    operationId: 'operation-pending-portal-create',
    ...request,
    requestHash: await testHashCanonical({ schemaVersion: 1, ...request }),
  });
  provider.resources = lowerResources.map((resource) => ({ ...clone(resource) }));
  if (portalPresent) {
    const portalResource = {
      kind: portal.kind,
      key: portal.key,
      provider: { id: portal.key },
      desiredHash: portal.desiredHash,
      marker: ownershipMarker(desired.installationId, portal.key),
    };
    if (portalForeign) portalResource.forceForeign = true;
    provider.resources.push(portalResource);
  }
  return { base, desired, portal };
}

test('live plan and status report fresh drift without performing writes', async () => {
  const timeline = [];
  const provider = new FakeProvider({ timeline });
  const receiptStore = new MemoryReceiptStore(timeline);
  const input = context(provider, receiptStore);

  const live = await planLiveGateway(input);
  const status = await getGatewayStatus(input);

  assert.equal(live.receipt, null);
  assert.deepEqual(live.plan.blockers, []);
  assert.deepEqual(live.diagnostics, [{ code: 'synthetic_ok' }]);
  assert.equal(Object.hasOwn(live, 'observed'), false);
  assert.equal(JSON.stringify(live).includes('must-not-escape'), false);
  assert.deepEqual(
    live.plan.changes.map(({ action, kind }) => [action, kind]),
    EXPECTED_ORDER.map((kind) => ['create', kind]),
  );
  assert.equal(status.state, 'drift');
  assert.deepEqual(status.changes.map(({ action }) => action), Array(7).fill('create'));
  assert.deepEqual(status.diagnostics, [{ code: 'synthetic_ok' }]);
  assert.equal(JSON.stringify(status).includes('must-not-escape'), false);
  assert.equal(provider.mutations.length, 0);
  assert.equal(receiptStore.writes.length, 0);
});

test('provider mutations receive the full fresh target when the caller selects only IDs', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const selected = selectedTarget();
  delete selected.zoneName;
  const base = context(provider, receiptStore, { target: selected });
  const preview = await planLiveGateway(base);

  await applyGateway({ ...base, approvedPlanId: preview.plan.planId });

  assert.equal(provider.mutationTargets.length, EXPECTED_ORDER.length);
  for (const target of provider.mutationTargets) {
    assert.deepEqual(target, liveTarget());
  }
});

test('rejects malformed normalized ownership before planning or mutation', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  provider.readObservedState = async () => ({
    target: liveTarget(),
    resources: [{
      kind: 'mcp_server',
      key: 'mcp-invalid-owner',
      provider: { id: 'server', parentId: 'unexpected' },
      owner: { manager: 'ankka-mcp-gateway', installationId: 'acg-invalid' },
      desiredHash: DRIFT_HASH,
    }],
    diagnostics: [],
  });

  await expectCode(planLiveGateway(context(provider, receiptStore)), 'invalid_observed_state');
  assert.equal(provider.mutations.length, 0);
});

test('normalized owner claims cannot update a locator that the receipt does not own', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const { base } = await install(provider, receiptStore);
  provider.resources[0].desiredHash = DRIFT_HASH;
  const readObservedState = provider.readObservedState.bind(provider);
  provider.readObservedState = async (input) => {
    const observed = await readObservedState(input);
    const forged = observed.resources.find((resource) => resource.kind === 'mcp_server');
    forged.provider = { id: 'foreign-locator' };
    forged.owner = {
      manager: 'ankka-mcp-gateway',
      installationId: receiptStore.value.installationId,
    };
    return observed;
  };
  const preview = await planLiveGateway(base);
  assert.equal(preview.plan.changes[0].action, 'update');
  const beforeMutations = provider.mutations.length;
  const beforeWrites = receiptStore.writes.length;

  await expectCode(
    applyGateway({ ...base, approvedPlanId: preview.plan.planId }),
    'ownership_conflict',
  );
  assert.equal(provider.mutations.length, beforeMutations);
  assert.equal(receiptStore.writes.length, beforeWrites);
});

test('approval mismatch and prerequisite blockers perform zero writes', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const input = context(provider, receiptStore);
  await expectCode(
    applyGateway({ ...input, approvedPlanId: 'plan-not-current' }),
    'approval_required',
  );
  assert.equal(provider.mutations.length, 0);
  assert.equal(receiptStore.writes.length, 0);

  const blockedProvider = new FakeProvider({
    target: liveTarget({ zeroTrustReady: false }),
  });
  const blockedStore = new MemoryReceiptStore();
  await expectCode(
    applyGateway({
      ...context(blockedProvider, blockedStore),
      approvedPlanId: 'plan-not-current',
    }),
    'plan_blocked',
  );
  assert.equal(blockedProvider.mutations.length, 0);
  assert.equal(blockedStore.writes.length, 0);
});

test('receipt release and selected target mismatches perform zero remote mutations', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const { base } = await install(provider, receiptStore);
  const before = provider.mutations.length;

  const changedRelease = { ...base, release: 'different-release' };
  const releasePreview = await planLiveGateway(changedRelease);
  await expectCode(
    applyGateway({ ...changedRelease, approvedPlanId: releasePreview.plan.planId }),
    'receipt_mismatch',
  );
  assert.equal(provider.mutations.length, before);

  await expectCode(
    planLiveGateway({
      ...base,
      target: { ...base.target, zoneId: 'different-zone' },
    }),
    'target_mismatch',
  );
  assert.equal(provider.mutations.length, before);
});

test('a fresh prerequisite blocker stops all later mutations', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const input = context(provider, receiptStore);
  const preview = await planLiveGateway(input);
  let changed = false;
  provider.beforeMutation = () => {
    if (changed) return;
    changed = true;
    provider.target.zeroTrustReady = false;
  };

  await expectCode(
    applyGateway({ ...input, approvedPlanId: preview.plan.planId }),
    'plan_blocked',
  );
  assert.equal(provider.mutations.length, 1);
  assert.equal(receiptStore.value.pending, null);
  assert.equal(receiptStore.value.resources.length, 1);
});

test('concurrent apply is rejected before a second mutation path starts', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const input = context(provider, receiptStore);
  const preview = await planLiveGateway(input);
  let release;
  let signalEntered;
  const gate = new Promise((resolve) => { release = resolve; });
  const entered = new Promise((resolve) => { signalEntered = resolve; });
  let held = false;
  provider.beforeMutation = async () => {
    if (held) return;
    held = true;
    signalEntered();
    await gate;
  };

  const first = applyGateway({ ...input, approvedPlanId: preview.plan.planId });
  await entered;
  await expectCode(
    applyGateway({ ...input, approvedPlanId: preview.plan.planId }),
    'receipt_locked',
  );
  assert.equal(provider.mutations.length, 0);
  release();
  await first;
  assert.equal(provider.mutations.length, 7);
});

test('apply creates in dependency order and a fresh rerun is all no-op', async () => {
  const timeline = [];
  const provider = new FakeProvider({ timeline });
  const receiptStore = new MemoryReceiptStore(timeline);
  const { base, result } = await install(provider, receiptStore);

  assert.equal(result.status, 'ready');
  assert.deepEqual(provider.mutations.map(({ action }) => action), Array(7).fill('create'));
  assert.deepEqual(provider.mutations.map(({ kind }) => kind), EXPECTED_ORDER);
  assert.equal(receiptStore.value.resources.length, 7);
  assert.equal(receiptStore.value.pending, null);
  assert.deepEqual(await validateInstallationReceipt(receiptStore.value), receiptStore.value);

  const fresh = await planLiveGateway(base);
  assert.deepEqual(fresh.plan.changes.map(({ action }) => action), Array(7).fill('noop'));
  const before = provider.mutations.length;
  const rerun = await applyGateway({ ...base, approvedPlanId: fresh.plan.planId });
  assert.equal(rerun.status, 'ready');
  assert.equal(provider.mutations.length, before);
});

test('markerless Portal app create commits only the exact provider-returned ID', async () => {
  let submittedId;
  const provider = new class extends FakeProvider {
    async applyChange(input) {
      const result = await super.applyChange(input);
      if (input.change.action === 'create'
        && input.change.kind === 'portal_access_application') {
        submittedId = result.provider.id;
        const created = this.resources.find((resource) =>
          resource.kind === input.change.kind
          && resource.key === input.change.key
          && resource.provider.id === submittedId);
        // The exact POST result A was already proved by the adapter, but only a
        // late same-shaped automatic app B is visible to the following list.
        // Production observation adds exact receipt-bound A beside listed B.
        this.resources.push({
          ...clone(created),
          provider: { id: 'late-automatic-portal-app' },
          forceForeign: true,
        });
      }
      return result;
    }
  }();
  const receiptStore = new MemoryReceiptStore();
  const input = context(provider, receiptStore);
  const preview = await planLiveGateway(input);

  await expectCode(
    applyGateway({ ...input, approvedPlanId: preview.plan.planId }),
    'verification_failed',
  );

  const ownedApplication = receiptStore.value.resources.find((resource) =>
    resource.kind === 'portal_access_application');
  assert.equal(ownedApplication.provider.id, submittedId);
  assert.notEqual(ownedApplication.provider.id, 'late-automatic-portal-app');
  assert.equal(receiptStore.value.resources.some((resource) =>
    resource.provider.id === 'late-automatic-portal-app'), false);
  assert.equal(provider.mutations.some((mutation) =>
    mutation.action === 'delete' && mutation.kind === 'portal_access_application'), false);
  assert.equal(receiptStore.value.pending, null);
  const fresh = await planLiveGateway(input);
  assert.equal(
    fresh.plan.changes.find((change) => change.kind === 'portal_access_application').action,
    'conflict',
  );
});

test('multiple sources are created in global dependency ranks', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const input = context(provider, receiptStore, { config: config(2) });
  const preview = await planLiveGateway(input);

  await applyGateway({ ...input, approvedPlanId: preview.plan.planId });

  assert.deepEqual(provider.mutations.map(({ kind }) => kind), [
    'mcp_server',
    'mcp_server',
    'source_access_application',
    'source_access_application',
    'source_access_policy',
    'source_access_policy',
    'portal',
    'portal_access_application',
    'portal_access_policy',
    'dns_record',
  ]);
});

test('dependency drift after a committed step blocks every later-rank mutation', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const input = context(provider, receiptStore);
  const preview = await planLiveGateway(input);
  let drifted = false;
  receiptStore.onWrite = async (written) => {
    if (drifted || written.pending !== null || written.resources.length !== 1) return;
    const server = provider.resources.find(({ kind }) => kind === 'mcp_server');
    if (!server) return;
    drifted = true;
    server.desiredHash = DRIFT_HASH;
  };

  await expectCode(
    applyGateway({ ...input, approvedPlanId: preview.plan.planId }),
    'plan_changed',
  );

  assert.equal(drifted, true);
  assert.deepEqual(provider.mutations.map(({ kind }) => kind), ['mcp_server']);
  assert.equal(receiptStore.value.pending, null);
  assert.equal(receiptStore.value.resources.length, 1);
});

test('recovers a remotely created resource from pending intent without duplicating it', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const input = context(provider, receiptStore);
  const firstPlan = await planLiveGateway(input);
  provider.failAfterRemoteMutationOnce = true;

  await expectCode(
    applyGateway({ ...input, approvedPlanId: firstPlan.plan.planId }),
    'mutation_failed',
  );
  assert.equal(provider.resources.length, 1);
  assert.equal(provider.mutations.length, 1);
  assert.equal(receiptStore.value.pending?.action, 'create');

  const recoveryPlan = await planLiveGateway(input);
  assert.equal(recoveryPlan.plan.changes[0].action, 'noop');
  assert.equal((await getGatewayStatus(input)).state, 'recovering');
  const recovered = await applyGateway({
    ...input,
    approvedPlanId: recoveryPlan.plan.planId,
  });

  assert.equal(recovered.status, 'ready');
  assert.equal(provider.resources.length, 7);
  assert.equal(provider.mutations.length, 7);
  assert.equal(
    provider.mutations.filter(({ key }) => key === firstPlan.plan.changes[0].key).length,
    1,
  );
  assert.equal(receiptStore.value.pending, null);
});

test('rebases an old five-resource pending server receipt after local recovery without replay', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const input = context(provider, receiptStore);
  const desired = await buildGatewayDesiredState(input.config, {
    target: liveTarget(),
    access: input.access,
  });
  const server = desired.resources.find(({ kind }) => kind === 'mcp_server');
  const legacyResources = [];
  const portalApplication = desired.resources.find(({ kind }) =>
    kind === 'portal_access_application');
  for (const resource of desired.resources) {
    if (
      resource.kind === 'source_access_application' ||
      resource.kind === 'portal_access_application'
    ) continue;
    if (resource.kind === 'portal') {
      const legacyDesired = {
        ...resource.desired,
        authentication: clone(portalApplication.desired.authentication),
      };
      legacyResources.push({
        ...resource,
        desired: legacyDesired,
        desiredHash: await testHashCanonical({
          schemaVersion: 1,
          kind: resource.kind,
          key: resource.key,
          desired: legacyDesired,
        }),
      });
      continue;
    }
    if (resource.kind === 'portal_access_policy') {
      const legacyDesired = {
        ...resource.desired,
        portalResourceKey: desired.resources.find(({ kind }) => kind === 'portal').key,
      };
      delete legacyDesired.portalApplicationResourceKey;
      legacyResources.push({
        ...resource,
        desired: legacyDesired,
        desiredHash: await testHashCanonical({
          schemaVersion: 1,
          kind: resource.kind,
          key: resource.key,
          desired: legacyDesired,
        }),
      });
      continue;
    }
    if (resource.kind !== 'source_access_policy') {
      legacyResources.push(clone(resource));
      continue;
    }
    const legacyDesired = {
      ...resource.desired,
      sourceResourceKey: server.key,
    };
    delete legacyDesired.sourceApplicationResourceKey;
    legacyResources.push({
      ...resource,
      desired: legacyDesired,
      desiredHash: await testHashCanonical({
        schemaVersion: 1,
        kind: resource.kind,
        key: resource.key,
        desired: legacyDesired,
      }),
    });
  }
  assert.equal(legacyResources.length, 5);
  const legacyDesiredHash = await testHashCanonical({
    schemaVersion: 1,
    installationId: desired.installationId,
    resources: legacyResources,
  });
  const legacyPlanDigest = await testHashCanonical({
    schemaVersion: 1,
    installationId: desired.installationId,
    desiredHash: legacyDesiredHash,
    resources: legacyResources,
  });
  const legacyPlanId = `plan-${legacyPlanDigest.slice('sha256:'.length, 'sha256:'.length + 24)}`;
  const baseReceipt = await createInstallationReceipt({
    plan: {
      installationId: desired.installationId,
      release: input.release,
      desiredHash: legacyDesiredHash,
    },
    target: {
      accountId: provider.target.accountId,
      zoneId: provider.target.zoneId,
      zoneName: provider.target.zoneName,
      hostname: input.config.gateway.hostname,
    },
    accessPolicy: desired.accessPolicy,
  });
  const request = {
    type: 'apply',
    planId: legacyPlanId,
    action: 'create',
    kind: server.kind,
    key: server.key,
    expectedDesiredHash: server.desiredHash,
  };
  receiptStore.value = await beginReceiptAction(baseReceipt, {
    operationId: 'operation-old-five-server-create',
    ...request,
    requestHash: await testHashCanonical({ schemaVersion: 1, ...request }),
  });
  provider.resources.push({
    kind: server.kind,
    key: server.key,
    provider: { id: server.key },
    desiredHash: server.desiredHash,
    marker: ownershipMarker(desired.installationId, server.key),
  });
  const fakeReadObservedState = provider.readObservedState.bind(provider);
  let productionObserverReads = 0;
  const liveServer = {
    id: server.key,
    name: server.desired.name,
    hostname: server.desired.endpoint,
    auth_type: 'oauth',
    secure_web_gateway: false,
    description: ownershipMarker(desired.installationId, server.key),
    status: 'ready',
    tools: server.desired.toolPolicy.allowedTools.map((name) => ({ name })),
    updated_prompts: [],
    updated_tools: server.desired.toolPolicy.allowedTools.map((name) => ({ name, enabled: true })),
  };
  const cloudflare = {
    getZone: async () => ({
      id: provider.target.zoneId,
      name: provider.target.zoneName,
      status: 'active',
      account: { id: provider.target.accountId },
    }),
    listIdentityProviders: async () => [{ id: 'idp-1' }],
    getMcpServer: async (id) => id === server.key ? liveServer : null,
    getPortal: async () => null,
    listDnsRecords: async () => [],
    getDnsRecord: async () => null,
    listAccessApps: async () => [],
    getAccessApp: async () => null,
    listAppPolicies: async () => [],
    getAppPolicy: async () => null,
  };
  provider.readObservedState = async (readInput) => {
    if (readInput.receipt?.pending?.kind === 'mcp_server') {
      productionObserverReads += 1;
      return readCloudflareObservedState({ ...readInput, cloudflare });
    }
    return fakeReadObservedState(readInput);
  };

  const preview = await planLiveGateway(input);
  assert.notEqual(preview.plan.desiredHash, legacyDesiredHash);
  assert.equal(preview.plan.changes[0].action, 'noop');
  assert.equal(receiptStore.value.pending.planId, legacyPlanId);

  const result = await applyGateway({ ...input, approvedPlanId: preview.plan.planId });

  assert.equal(result.status, 'ready');
  assert.ok(productionObserverReads >= 2);
  assert.equal(provider.mutations.some(({ kind }) => kind === 'mcp_server'), false);
  assert.deepEqual(
    provider.mutations.map(({ kind }) => kind),
    EXPECTED_ORDER.slice(1),
  );
  assert.equal(receiptStore.value.release, input.release);
  assert.equal(receiptStore.value.desiredHash, preview.plan.desiredHash);
  assert.equal(receiptStore.value.resources.length, 7);
  assert.equal(receiptStore.value.pending, null);
  assert.deepEqual(await validateInstallationReceipt(receiptStore.value), receiptStore.value);
});

test('recovers an outcome-unknown explicit source app through the production observer without replay', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const input = context(provider, receiptStore);
  const desired = await buildGatewayDesiredState(input.config, {
    target: liveTarget(),
    access: input.access,
  });
  const server = desired.resources.find(({ kind }) => kind === 'mcp_server');
  const application = desired.resources.find(({ kind }) => kind === 'source_access_application');
  const serverMarker = ownershipMarker(desired.installationId, server.key);
  const applicationMarker = ownershipMarker(desired.installationId, application.key);
  const baseReceipt = await createInstallationReceipt({
    plan: {
      installationId: desired.installationId,
      release: input.release,
      desiredHash: desired.desiredHash,
    },
    target: {
      accountId: provider.target.accountId,
      zoneId: provider.target.zoneId,
      zoneName: provider.target.zoneName,
      hostname: input.config.gateway.hostname,
    },
    accessPolicy: desired.accessPolicy,
    resources: [{
      kind: server.kind,
      key: server.key,
      provider: { id: server.key },
      desiredHash: server.desiredHash,
      marker: serverMarker,
    }],
  });
  const pendingRequest = {
    type: 'apply',
    planId: 'plan-outcome-unknown-source-app',
    action: 'create',
    kind: application.kind,
    key: application.key,
    expectedDesiredHash: application.desiredHash,
  };
  receiptStore.value = await beginReceiptAction(baseReceipt, {
    operationId: 'operation-outcome-unknown-source-app',
    ...pendingRequest,
    requestHash: await testHashCanonical({ schemaVersion: 1, ...pendingRequest }),
  });
  const applicationId = 'source-app-outcome-unknown';
  provider.resources.push({
    kind: server.kind,
    key: server.key,
    provider: { id: server.key },
    desiredHash: server.desiredHash,
    marker: serverMarker,
  }, {
    kind: application.kind,
    key: application.key,
    provider: { id: applicationId },
    desiredHash: application.desiredHash,
    marker: applicationMarker,
  });
  const liveServer = {
    id: server.key,
    name: server.desired.name,
    hostname: server.desired.endpoint,
    auth_type: 'oauth',
    secure_web_gateway: false,
    description: serverMarker,
    status: 'ready',
    tools: server.desired.toolPolicy.allowedTools.map((name) => ({ name })),
    updated_prompts: [],
    updated_tools: server.desired.toolPolicy.allowedTools.map((name) => ({ name, enabled: true })),
  };
  const liveApplication = {
    id: applicationId,
    name: applicationMarker,
    type: 'mcp',
    destinations: [{ type: 'via_mcp_server_portal', mcp_server_id: server.key }],
  };
  const cloudflare = {
    getZone: async () => ({
      id: provider.target.zoneId,
      name: provider.target.zoneName,
      status: 'active',
      account: { id: provider.target.accountId },
    }),
    listIdentityProviders: async () => [{ id: 'idp-1' }],
    getMcpServer: async (id) => id === server.key ? liveServer : null,
    getPortal: async () => null,
    listDnsRecords: async () => [],
    getDnsRecord: async () => null,
    listAccessApps: async () => [liveApplication],
    getAccessApp: async (id) => id === applicationId ? liveApplication : null,
    listAppPolicies: async () => [],
    getAppPolicy: async () => null,
  };
  const fakeReadObservedState = provider.readObservedState.bind(provider);
  let productionObserverReads = 0;
  provider.readObservedState = async (readInput) => {
    if (readInput.receipt?.pending?.kind === 'source_access_application') {
      productionObserverReads += 1;
      return readCloudflareObservedState({ ...readInput, cloudflare });
    }
    return fakeReadObservedState(readInput);
  };

  const preview = await planLiveGateway(input);
  assert.equal(preview.plan.changes.find(({ kind }) => kind === application.kind).action, 'noop');
  const result = await applyGateway({ ...input, approvedPlanId: preview.plan.planId });

  assert.equal(result.status, 'ready');
  assert.ok(productionObserverReads >= 2);
  assert.equal(provider.mutations.some(({ kind }) => kind === application.kind), false);
  assert.deepEqual(provider.mutations.map(({ kind }) => kind), EXPECTED_ORDER.slice(2));
  assert.equal(receiptStore.value.resources.length, 7);
  assert.equal(receiptStore.value.pending, null);
});

test('ambiguous pending-create recovery blocks without another mutation', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const input = context(provider, receiptStore);
  const preview = await planLiveGateway(input);
  provider.failAfterRemoteMutationOnce = true;
  provider.duplicateFailedCreate = true;

  await expectCode(
    applyGateway({ ...input, approvedPlanId: preview.plan.planId }),
    'mutation_failed',
  );
  assert.equal(provider.resources.length, 2);
  const before = provider.mutations.length;
  await expectCode(
    applyGateway({ ...input, approvedPlanId: preview.plan.planId }),
    'pending_conflict',
  );
  assert.equal(provider.mutations.length, before);
  assert.notEqual(receiptStore.value.pending, null);
});

test('a proven not-submitted mutation clears only its exact journal before replanning', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const input = context(provider, receiptStore);
  const preview = await planLiveGateway(input);
  provider.definiteNotSubmittedOnce = true;
  provider.beforeMutation = async (change, receipt) => {
    provider.beforeMutation = null;
    provider.resources.push({
      kind: change.kind,
      key: change.key,
      provider: { id: 'late-foreign-resource' },
      desiredHash: change.desiredHash,
      marker: ownershipMarker(receipt.installationId, change.key),
      forceForeign: true,
    });
  };

  await expectCode(
    applyGateway({ ...input, approvedPlanId: preview.plan.planId }),
    'mutation_not_submitted',
  );

  assert.equal(provider.mutations.length, 0);
  assert.equal(receiptStore.value.pending, null);
  assert.equal(receiptStore.value.resources.length, 0);
  const fresh = await planLiveGateway(input);
  assert.equal(fresh.plan.changes[0].action, 'conflict');
  assert.deepEqual(fresh.plan.blockers.map(({ code }) => code), ['resource_conflicts']);
});

test('not-submitted cleanup never overwrites a concurrently changed receipt', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const input = context(provider, receiptStore);
  const preview = await planLiveGateway(input);
  provider.definiteNotSubmittedOnce = true;
  provider.beforeMutation = async (_change, receipt) => {
    provider.beforeMutation = null;
    const concurrentlyCleared = await clearReceiptAction(
      receipt,
      receipt.pending.operationId,
    );
    await receiptStore.writeAtomic(concurrentlyCleared);
  };

  await expectCode(
    applyGateway({ ...input, approvedPlanId: preview.plan.planId }),
    'receipt_changed',
  );

  assert.equal(provider.mutations.length, 0);
  assert.equal(receiptStore.value.pending, null);
  assert.equal(receiptStore.value.resources.length, 0);
});

test('an outcome-unknown absent create is retained and never replayed automatically', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const input = context(provider, receiptStore);
  const preview = await planLiveGateway(input);
  provider.failBeforeRemoteMutationOnce = true;

  await expectCode(
    applyGateway({ ...input, approvedPlanId: preview.plan.planId }),
    'mutation_failed',
  );
  assert.equal(provider.resources.length, 0);
  assert.equal(provider.mutations.length, 1);

  const pendingPlan = await planLiveGateway(input);
  assert.equal(pendingPlan.plan.changes[0].action, 'create');
  await expectCode(
    applyGateway({ ...input, approvedPlanId: pendingPlan.plan.planId }),
    'pending_outcome_unknown',
  );
  assert.equal(provider.mutations.length, 1);
  assert.equal(receiptStore.value.pending?.action, 'create');
});

test('an exact legacy pending Portal is recovered locally before creating its explicit app', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const { base } = await seedPendingPortalRollback(provider, receiptStore, {
    portalForeign: false,
  });
  const preview = await planLiveGateway(base);
  assert.equal(preview.plan.changes.find(({ kind }) => kind === 'portal').action, 'noop');

  const result = await applyGateway({
    ...base,
    approvedPlanId: preview.plan.planId,
  });

  assert.equal(result.status, 'ready');
  assert.equal(receiptStore.value.pending, null);
  assert.equal(receiptStore.value.resources.length, 7);
  assert.equal(
    provider.mutations.some(({ action, kind }) => action === 'create' && kind === 'portal'),
    false,
  );
  assert.deepEqual(provider.mutations.map(({ kind }) => kind), [
    'portal_access_application',
    'portal_access_policy',
    'dns_record',
  ]);
});

test('separately approved pending Portal rollback clears only after exact remote absence', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const { base, portal } = await seedPendingPortalRollback(provider, receiptStore);
  const ordinary = await planLiveGateway(base);
  assert.equal(ordinary.plan.changes.find(({ kind }) => kind === 'portal').action, 'conflict');

  const preview = await planPendingPortalCreateRollback(base);
  assert.equal(preview.operation, 'rollback_pending_portal_create');
  assert.equal(preview.portalState, 'present_exact');
  assert.match(preview.rollbackId, /^rollback-[0-9a-f]{24}$/);
  const result = await rollbackPendingPortalCreate({
    ...base,
    approvedRollbackId: preview.rollbackId,
  });

  assert.equal(result.status, 'rollback_complete');
  assert.equal(receiptStore.value.state, 'ready');
  assert.equal(receiptStore.value.pending, null);
  assert.equal(receiptStore.value.resources.length, 3);
  assert.equal(provider.resources.some((resource) => resource.key === portal.key), false);
  assert.equal(provider.portalRollbackMutations, 1);
  assert.deepEqual(provider.mutations, []);
  const fresh = await planLiveGateway(base);
  assert.deepEqual(
    fresh.plan.changes.map(({ action, kind }) => [action, kind]),
    [
      ['noop', 'mcp_server'],
      ['noop', 'source_access_application'],
      ['noop', 'source_access_policy'],
      ['create', 'portal'],
      ['create', 'portal_access_application'],
      ['create', 'portal_access_policy'],
      ['create', 'dns_record'],
    ],
  );
});

test('pending Portal rollback retains old root authority across downstream-only desired drift', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const oldRootHash = `sha256:${'8'.repeat(64)}`;
  const { base, desired } = await seedPendingPortalRollback(provider, receiptStore, {
    receiptDesiredHash: oldRootHash,
  });
  assert.notEqual(oldRootHash, desired.desiredHash);

  const preview = await planPendingPortalCreateRollback(base);
  const result = await rollbackPendingPortalCreate({
    ...base,
    approvedRollbackId: preview.rollbackId,
  });

  assert.equal(result.status, 'rollback_complete');
  assert.equal(provider.portalRollbackMutations, 1);
  assert.equal(receiptStore.value.desiredHash, oldRootHash);
  assert.equal(receiptStore.value.pending, null);
  assert.equal(receiptStore.value.resources.length, 3);
});

test('root-hash exception still rejects owned, pending, access, and target drift', async () => {
  const cases = [
    {
      name: 'owned',
      mutate({ provider }) {
        provider.resources.find(({ kind }) => kind === 'mcp_server').desiredHash = DRIFT_HASH;
      },
    },
    {
      name: 'pending',
      mutate({ base }) {
        base.config = {
          ...base.config,
          gateway: { ...base.config.gateway, name: 'Changed pending Portal' },
        };
      },
    },
    {
      name: 'access',
      mutate({ base }) {
        base.access = { allowedEmails: ['different@example.com'] };
      },
    },
    {
      name: 'target',
      mutate({ base }) {
        base.target = { ...base.target, accountId: 'different-account' };
      },
    },
  ];

  for (const drift of cases) {
    const provider = new FakeProvider();
    const receiptStore = new MemoryReceiptStore();
    const seeded = await seedPendingPortalRollback(provider, receiptStore, {
      receiptDesiredHash: `sha256:${'7'.repeat(64)}`,
    });
    drift.mutate({ ...seeded, provider, receiptStore });
    const before = provider.portalRollbackMutations;
    await assert.rejects(
      planPendingPortalCreateRollback(seeded.base),
      (error) => error instanceof GatewayReconcileError,
      drift.name,
    );
    assert.equal(provider.portalRollbackMutations, before, drift.name);
    assert.equal(receiptStore.value.pending?.kind, 'portal', drift.name);
  }
});

test('an already absent pending Portal is cleared locally through the same approved proof', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const { base } = await seedPendingPortalRollback(provider, receiptStore, {
    portalPresent: false,
  });
  const preview = await planPendingPortalCreateRollback(base);
  assert.equal(preview.portalState, 'already_absent');

  const result = await rollbackPendingPortalCreate({
    ...base,
    approvedRollbackId: preview.rollbackId,
  });
  assert.equal(result.status, 'rollback_complete');
  assert.equal(provider.portalRollbackMutations, 1);
  assert.deepEqual(provider.mutations, []);
  assert.equal(receiptStore.value.pending, null);
  assert.equal(receiptStore.value.resources.length, 3);
});

test('stale pending Portal rollback approval performs no recovery mutation', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const { base, portal } = await seedPendingPortalRollback(provider, receiptStore);
  const preview = await planPendingPortalCreateRollback(base);
  provider.resources = provider.resources.filter((resource) => resource.key !== portal.key);

  await expectCode(
    rollbackPendingPortalCreate({
      ...base,
      approvedRollbackId: preview.rollbackId,
    }),
    'rollback_approval_required',
  );
  assert.equal(provider.portalRollbackMutations, 0);
  assert.equal(receiptStore.value.pending?.kind, 'portal');
});

test('pending Portal rollback preserves the journal on provider failure or concurrent receipt change', async () => {
  const failedProvider = new FakeProvider();
  const failedStore = new MemoryReceiptStore();
  const failed = await seedPendingPortalRollback(failedProvider, failedStore);
  const failedPreview = await planPendingPortalCreateRollback(failed.base);
  failedProvider.rollbackPendingPortalCreate = async () => {
    failedProvider.portalRollbackMutations += 1;
    throw new Error('outcome unknown');
  };
  await expectCode(
    rollbackPendingPortalCreate({
      ...failed.base,
      approvedRollbackId: failedPreview.rollbackId,
    }),
    'mutation_failed',
  );
  assert.equal(failedStore.value.pending?.kind, 'portal');

  const concurrentProvider = new FakeProvider();
  const concurrentStore = new MemoryReceiptStore();
  const concurrent = await seedPendingPortalRollback(concurrentProvider, concurrentStore);
  const concurrentPreview = await planPendingPortalCreateRollback(concurrent.base);
  concurrentProvider.beforePortalRollback = async () => {
    concurrentStore.value = await clearReceiptAction(
      concurrentStore.value,
      concurrentStore.value.pending.operationId,
    );
  };
  await expectCode(
    rollbackPendingPortalCreate({
      ...concurrent.base,
      approvedRollbackId: concurrentPreview.rollbackId,
    }),
    'receipt_changed',
  );
  assert.equal(concurrentProvider.portalRollbackMutations, 1);
  assert.equal(concurrentStore.value.pending, null);
});

test('detects a concurrent receipt replacement and performs no second remote mutation', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const input = context(provider, receiptStore);
  const preview = await planLiveGateway(input);
  let replaced = false;
  receiptStore.onWrite = async (written) => {
    if (replaced || written.pending?.action !== 'create') return;
    replaced = true;
    receiptStore.value = await clearReceiptAction(written, written.pending.operationId);
  };

  await expectCode(
    applyGateway({ ...input, approvedPlanId: preview.plan.planId }),
    'receipt_changed',
  );
  assert.equal(provider.mutations.length, 1);
  assert.equal(provider.resources.length, 1);

  receiptStore.onWrite = null;
  const conflicted = await planLiveGateway(input);
  assert.equal(conflicted.plan.changes[0].action, 'conflict');
  await expectCode(
    applyGateway({ ...input, approvedPlanId: conflicted.plan.planId }),
    'plan_blocked',
  );
  assert.equal(provider.mutations.length, 1);
});

test('owned drift is re-read before update and converges in place', async () => {
  const timeline = [];
  const provider = new FakeProvider({ timeline });
  const receiptStore = new MemoryReceiptStore(timeline);
  const { base } = await install(provider, receiptStore);
  provider.resources[0].desiredHash = DRIFT_HASH;
  timeline.length = 0;

  const preview = await planLiveGateway(base);
  assert.equal(preview.plan.changes[0].action, 'update');
  timeline.length = 0;
  const before = provider.mutations.length;
  await applyGateway({ ...base, approvedPlanId: preview.plan.planId });

  assert.equal(provider.mutations.length, before + 1);
  assert.equal(provider.mutations.at(-1).action, 'update');
  const mutationIndex = timeline.findIndex((event) => event.type === 'mutation');
  assert.ok(mutationIndex >= 2);
  assert.ok(timeline.slice(0, mutationIndex).filter((event) => event.type === 'read').length >= 2);
  assert.equal((await getGatewayStatus(base)).state, 'ready');
});

test('journal-retires an absent owned locator before recreating the desired resource', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const { base } = await install(provider, receiptStore);
  const missing = provider.resources.find((resource) => resource.kind === 'dns_record');
  const oldProvider = clone(missing.provider);
  provider.resources = provider.resources.filter((resource) => resource !== missing);
  const preview = await planLiveGateway(base);
  const create = preview.plan.changes.find((change) => change.kind === 'dns_record');
  assert.equal(create.action, 'create');
  assert.equal(preview.pruneApprovalId, null);

  let failRetirementWrite = true;
  receiptStore.onWrite = async (written) => {
    if (
      failRetirementWrite &&
      written.pending?.type === 'apply' &&
      written.pending.action === 'delete' &&
      written.pending.kind === 'dns_record'
    ) {
      failRetirementWrite = false;
      throw new Error('synthetic crash after retirement journal');
    }
  };
  const before = provider.mutations.length;
  await expectCode(
    applyGateway({ ...base, approvedPlanId: preview.plan.planId }),
    'receipt_write_failed',
  );
  assert.equal(provider.mutations.length, before);
  assert.equal(receiptStore.value.pending?.action, 'delete');
  assert.deepEqual(receiptStore.value.resources.find(({ kind }) => kind === 'dns_record').provider, oldProvider);

  receiptStore.onWrite = null;
  const result = await applyGateway({ ...base, approvedPlanId: preview.plan.planId });
  assert.equal(result.status, 'ready');
  assert.deepEqual(
    provider.mutations.slice(before).map(({ action, kind }) => [action, kind]),
    [['create', 'dns_record']],
  );
  const replacement = receiptStore.value.resources.find(({ kind }) => kind === 'dns_record');
  assert.notDeepEqual(replacement.provider, oldProvider);
  assert.equal(receiptStore.value.pending, null);
});

test('pending update retry requires fresh prerequisites and exact approval', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const { base } = await install(provider, receiptStore);
  provider.resources[0].desiredHash = DRIFT_HASH;
  const preview = await planLiveGateway(base);
  const before = provider.mutations.length;
  provider.failBeforeRemoteMutationOnce = true;

  await expectCode(
    applyGateway({ ...base, approvedPlanId: preview.plan.planId }),
    'mutation_failed',
  );
  assert.equal(provider.mutations.length, before + 1);
  const pendingPlanId = receiptStore.value.pending.planId;

  provider.target.zeroTrustReady = false;
  await expectCode(
    applyGateway({ ...base, approvedPlanId: pendingPlanId }),
    'plan_blocked',
  );
  assert.equal(provider.mutations.length, before + 1);

  provider.target.zeroTrustReady = true;
  await expectCode(
    applyGateway({ ...base, approvedPlanId: 'plan-not-current' }),
    'approval_required',
  );
  assert.equal(provider.mutations.length, before + 1);

  await expectCode(
    applyGateway({ ...base, approvedPlanId: pendingPlanId }),
    'approval_required',
  );
  assert.equal(provider.mutations.length, before + 2);
  assert.equal(receiptStore.value.pending, null);
  const converged = await planLiveGateway(base);
  const result = await applyGateway({ ...base, approvedPlanId: converged.plan.planId });
  assert.equal(result.status, 'ready');
  assert.equal(provider.mutations.length, before + 2);
});

test('recovers a group-policy ID change and commits only new hashes to the same locator', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const gatewayConfig = config();
  gatewayConfig.sources[0].accessGroup = 'Context Readers';
  const oldAccess = {
    ...access(),
    groups: [{ id: 'group-old-recovery-sentinel', name: 'Context Readers' }],
  };
  const { base } = await install(provider, receiptStore, {
    config: gatewayConfig,
    access: oldAccess,
  });
  const oldPolicy = clone(receiptStore.value.resources.find(({ kind }) =>
    kind === 'source_access_policy'));
  const changed = {
    ...base,
    access: {
      ...access(),
      groups: [{ id: 'group-new-recovery-sentinel', name: 'Context Readers' }],
    },
  };
  const preview = await planLiveGateway(changed);
  assert.deepEqual(
    preview.plan.changes.filter(({ action }) => action !== 'noop').map(({ action, kind }) => [
      action,
      kind,
    ]),
    [['update', 'source_access_policy']],
  );
  provider.failBeforeRemoteMutationOnce = true;
  await expectCode(
    applyGateway({ ...changed, approvedPlanId: preview.plan.planId }),
    'mutation_failed',
  );
  const pendingPlanId = receiptStore.value.pending.planId;
  assert.equal(
    receiptStore.value.resources.find(({ kind }) => kind === 'source_access_policy').desiredHash,
    oldPolicy.desiredHash,
  );

  await expectCode(
    applyGateway({ ...changed, approvedPlanId: pendingPlanId }),
    'approval_required',
  );
  const updatedPolicy = receiptStore.value.resources.find(({ kind }) =>
    kind === 'source_access_policy');
  assert.equal(receiptStore.value.pending, null);
  assert.deepEqual(updatedPolicy.provider, oldPolicy.provider);
  assert.notEqual(updatedPolicy.desiredHash, oldPolicy.desiredHash);
  assert.notEqual(updatedPolicy.identityHash, oldPolicy.identityHash);
  const output = JSON.stringify({ preview, receipt: receiptStore.value });
  for (const forbidden of [
    'group-old-recovery-sentinel',
    'group-new-recovery-sentinel',
    'Context Readers',
  ]) assert.equal(output.includes(forbidden), false);

  const converged = await planLiveGateway(changed);
  assert.ok(converged.plan.changes.every(({ action }) => action === 'noop'));
  const result = await applyGateway({ ...changed, approvedPlanId: converged.plan.planId });
  assert.equal(result.status, 'ready');
});

test('stale owned resources are retained unless apply explicitly enables prune', async () => {
  const timeline = [];
  const provider = new FakeProvider({ timeline });
  const receiptStore = new MemoryReceiptStore(timeline);
  const initial = context(provider, receiptStore, { config: config(2) });
  const first = await planLiveGateway(initial);
  await applyGateway({ ...initial, approvedPlanId: first.plan.planId });
  assert.equal(provider.resources.length, 10);

  const reduced = context(provider, receiptStore, { config: config(1) });
  let stalePlan = await planLiveGateway(reduced);
  assert.deepEqual(
    stalePlan.plan.changes.filter(({ action }) => action === 'delete').map(({ kind }) => kind),
    ['source_access_policy', 'source_access_application', 'mcp_server'],
  );
  assert.match(stalePlan.pruneApprovalId, /^prune-[0-9a-f]{24}$/);
  assert.equal(stalePlan.pruneSummary.remoteDeleteCount, 3);
  assert.equal(stalePlan.pruneSummary.receiptRetirementCount, 0);
  const before = provider.mutations.length;
  const writesBeforeRejectedPrune = receiptStore.writes.length;
  await expectCode(
    applyGateway({
      ...reduced,
      approvedPlanId: stalePlan.plan.planId,
      prune: true,
    }),
    'prune_approval_required',
  );
  assert.equal(provider.mutations.length, before);
  assert.equal(receiptStore.writes.length, writesBeforeRejectedPrune);

  const retained = await applyGateway({
    ...reduced,
    approvedPlanId: stalePlan.plan.planId,
  });
  assert.equal(retained.status, 'drift');
  assert.deepEqual(
    provider.mutations.slice(before).map(({ action, kind }) => [action, kind]),
    [['update', 'portal']],
  );
  assert.equal(provider.mutations.slice(before).some(({ action }) => action === 'delete'), false);
  assert.equal(provider.resources.length, 10);

  stalePlan = await planLiveGateway(reduced);
  const beforePrune = provider.mutations.length;
  timeline.length = 0;
  await applyGateway({
    ...reduced,
    approvedPlanId: stalePlan.plan.planId,
    approvedPruneId: stalePlan.pruneApprovalId,
    prune: true,
  });
  assert.deepEqual(
    provider.mutations.slice(beforePrune).map(({ action, kind }) => [action, kind]),
    [
      ['delete', 'source_access_policy'],
      ['delete', 'source_access_application'],
      ['delete', 'mcp_server'],
    ],
  );
  assert.equal(provider.resources.length, 7);
  let previousMutationIndex = -1;
  for (const mutation of timeline
    .map((event, index) => ({ event, index }))
    .filter(({ event }) => event.type === 'mutation')) {
    assert.ok(
      timeline
        .slice(previousMutationIndex + 1, mutation.index)
        .some((event) => event.type === 'read'),
      'delete must be preceded by a fresh live read',
    );
    previousMutationIndex = mutation.index;
  }
});

test('prunes a removed group-bound source from receipt ownership without its old observation', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const initialConfig = config(2);
  initialConfig.sources[1].accessGroup = 'Analytics Readers';
  const initial = context(provider, receiptStore, {
    config: initialConfig,
    access: {
      ...access(),
      groups: [{ id: 'group-prune-sentinel', name: 'Analytics Readers' }],
    },
  });
  const initialPlan = await planLiveGateway(initial);
  await applyGateway({ ...initial, approvedPlanId: initialPlan.plan.planId });
  const installedOutput = JSON.stringify(receiptStore.value);
  assert.equal(installedOutput.includes('group-prune-sentinel'), false);
  assert.equal(installedOutput.includes('Analytics Readers'), false);

  const reduced = context(provider, receiptStore, {
    config: config(1),
    access: access(),
  });
  const preview = await planLiveGateway(reduced);
  assert.deepEqual(
    preview.plan.changes.filter(({ action }) => action === 'delete').map(({ kind }) => kind),
    ['source_access_policy', 'source_access_application', 'mcp_server'],
  );
  const before = provider.mutations.length;
  await applyGateway({
    ...reduced,
    approvedPlanId: preview.plan.planId,
    approvedPruneId: preview.pruneApprovalId,
    prune: true,
  });
  assert.deepEqual(
    provider.mutations.slice(before).filter(({ action }) => action === 'delete')
      .map(({ kind }) => kind),
    ['source_access_policy', 'source_access_application', 'mcp_server'],
  );
  assert.equal(receiptStore.value.resources.length, 7);
  const output = JSON.stringify({ preview, receipt: receiptStore.value });
  assert.equal(output.includes('group-prune-sentinel'), false);
  assert.equal(output.includes('Analytics Readers'), false);
});

test('interrupted prune retry requires the originally journaled destructive approval', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const initial = context(provider, receiptStore, { config: config(2) });
  const first = await planLiveGateway(initial);
  await applyGateway({ ...initial, approvedPlanId: first.plan.planId });

  const reduced = context(provider, receiptStore, { config: config(1) });
  const metadataPlan = await planLiveGateway(reduced);
  await applyGateway({
    ...reduced,
    approvedPlanId: metadataPlan.plan.planId,
  });
  const prune = await planLiveGateway(reduced);
  assert.equal(prune.pruneSummary.remoteDeleteCount, 3);

  const before = provider.mutations.length;
  provider.failBeforeRemoteMutationOnce = true;
  await expectCode(
    applyGateway({
      ...reduced,
      approvedPlanId: prune.plan.planId,
      approvedPruneId: prune.pruneApprovalId,
      prune: true,
    }),
    'mutation_failed',
  );
  assert.equal(provider.mutations.length, before + 1);
  assert.equal(receiptStore.value.pending?.action, 'delete');
  assert.equal(receiptStore.value.pending?.pruneApprovalId, prune.pruneApprovalId);

  const pendingPlanId = receiptStore.value.pending.planId;
  await expectCode(
    applyGateway({
      ...reduced,
      approvedPlanId: pendingPlanId,
    }),
    'prune_approval_required',
  );
  assert.equal(provider.mutations.length, before + 1);
  await expectCode(
    applyGateway({
      ...reduced,
      approvedPlanId: pendingPlanId,
      approvedPruneId: 'prune-not-the-journaled-approval',
      prune: true,
    }),
    'prune_approval_required',
  );
  assert.equal(provider.mutations.length, before + 1);

  // The exact stored approval may resume only the pending delete. The plan then
  // changes, so the remaining destructive action requires a fresh preview.
  await expectCode(
    applyGateway({
      ...reduced,
      approvedPlanId: pendingPlanId,
      approvedPruneId: prune.pruneApprovalId,
      prune: true,
    }),
    'approval_required',
  );
  assert.equal(provider.mutations.length, before + 2);
  assert.equal(receiptStore.value.pending, null);

  const remaining = await planLiveGateway(reduced);
  const result = await applyGateway({
    ...reduced,
    approvedPlanId: remaining.plan.planId,
    approvedPruneId: remaining.pruneApprovalId,
    prune: true,
  });
  assert.equal(result.status, 'ready');
});

test('absent stale receipt entries remain uninstall authority until exact prune approval', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const initial = context(provider, receiptStore, { config: config(2) });
  const first = await planLiveGateway(initial);
  await applyGateway({ ...initial, approvedPlanId: first.plan.planId });

  const reduced = context(provider, receiptStore, { config: config(1) });
  const liveStale = await planLiveGateway(reduced);
  const staleKeys = new Set(
    liveStale.plan.changes
      .filter(({ action }) => action === 'delete')
      .map(({ key }) => key),
  );
  assert.equal(staleKeys.size, 3);
  provider.resources = provider.resources.filter((resource) => !staleKeys.has(resource.key));

  const absentStale = await planLiveGateway(reduced);
  assert.equal(absentStale.plan.changes.some(({ action }) => action === 'delete'), false);
  assert.equal(absentStale.pruneSummary.remoteDeleteCount, 0);
  assert.equal(absentStale.pruneSummary.receiptRetirementCount, 3);
  assert.deepEqual(
    absentStale.pruneSummary.actions.map(({ action }) => action),
    ['retire_receipt', 'retire_receipt', 'retire_receipt'],
  );

  const before = provider.mutations.length;
  const retained = await applyGateway({
    ...reduced,
    approvedPlanId: absentStale.plan.planId,
  });
  assert.equal(retained.status, 'drift');
  assert.equal(receiptStore.value.resources.length, 10);
  assert.deepEqual(
    provider.mutations.slice(before).map(({ action, kind }) => [action, kind]),
    [['update', 'portal']],
  );
  assert.equal((await getGatewayStatus(reduced)).state, 'drift');

  const prune = await planLiveGateway(reduced);
  assert.equal(prune.pruneSummary.receiptRetirementCount, 3);
  const beforePrune = provider.mutations.length;
  const cleaned = await applyGateway({
    ...reduced,
    approvedPlanId: prune.plan.planId,
    approvedPruneId: prune.pruneApprovalId,
    prune: true,
  });
  assert.equal(cleaned.status, 'ready');
  assert.equal(provider.mutations.length, beforePrune);
  assert.equal(receiptStore.value.resources.length, 7);
  assert.equal(receiptStore.value.pending, null);
});

test('uninstall requires exact approval, deletes in reverse order, converges on absence, and retains tombstone', async () => {
  const timeline = [];
  const provider = new FakeProvider({ timeline });
  const receiptStore = new MemoryReceiptStore(timeline);
  const { base } = await install(provider, receiptStore);
  const preview = await planGatewayUninstall(base);
  assert.equal(Object.hasOwn(preview, 'observed'), false);
  assert.equal(JSON.stringify(preview).includes('must-not-escape'), false);
  assert.deepEqual(preview.actions.map(({ action }) => action), Array(7).fill('delete'));
  assert.deepEqual(preview.actions.map(({ kind }) => kind), REVERSE_ORDER);

  const before = provider.mutations.length;
  await expectCode(
    uninstallGateway({ ...base, approvedUninstallId: 'uninstall-not-current' }),
    'uninstall_approval_required',
  );
  assert.equal(provider.mutations.length, before);

  timeline.length = 0;
  let simulate404 = true;
  provider.beforeMutation = (change) => {
    if (!simulate404 || change.action !== 'delete') return;
    simulate404 = false;
    const index = provider.resources.findIndex(
      (resource) => resource.kind === change.kind && resource.key === change.key,
    );
    if (index !== -1) provider.resources.splice(index, 1);
  };
  const removed = await uninstallGateway({
    ...base,
    approvedUninstallId: preview.uninstallId,
  });

  assert.equal(removed.status, 'removed');
  assert.deepEqual(provider.mutations.slice(before).map(({ kind }) => kind), REVERSE_ORDER);
  assert.equal(provider.resources.length, 0);
  assert.equal(receiptStore.value.state, 'removed');
  assert.equal(receiptStore.value.resources.length, 0);
  assert.equal(receiptStore.value.pending, null);
  assert.deepEqual(await validateInstallationReceipt(receiptStore.value), receiptStore.value);

  let previousDeleteIndex = -1;
  for (const deletion of timeline
    .map((event, index) => ({ event, index }))
    .filter(({ event }) => event.type === 'mutation')) {
    assert.ok(
      timeline
        .slice(previousDeleteIndex + 1, deletion.index)
        .some((event) => event.type === 'read'),
      'each uninstall delete must follow a fresh live read',
    );
    previousDeleteIndex = deletion.index;
  }
});

test('uninstalls a group-bound installation from receipt authority without the group snapshot', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const gatewayConfig = config();
  gatewayConfig.sources[0].accessGroup = 'Context Readers';
  const { base } = await install(provider, receiptStore, {
    config: gatewayConfig,
    access: {
      ...access(),
      groups: [{ id: 'group-uninstall-sentinel', name: 'Context Readers' }],
    },
  });
  const removal = { ...base, access: access() };
  const preview = await planGatewayUninstall(removal);
  assert.deepEqual(preview.blockers, []);
  assert.deepEqual(preview.actions.map(({ kind }) => kind), REVERSE_ORDER);
  const before = provider.mutations.length;
  const result = await uninstallGateway({
    ...removal,
    approvedUninstallId: preview.uninstallId,
  });

  assert.equal(result.status, 'removed');
  assert.deepEqual(provider.mutations.slice(before).map(({ kind }) => kind), REVERSE_ORDER);
  assert.equal(receiptStore.value.state, 'removed');
  assert.deepEqual(receiptStore.value.resources, []);
  const output = JSON.stringify({ preview, result, receipt: receiptStore.value });
  assert.equal(output.includes('group-uninstall-sentinel'), false);
  assert.equal(output.includes('Context Readers'), false);
});

test('an interrupted uninstall cannot be reversed through apply', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const { base } = await install(provider, receiptStore);
  const uninstall = await planGatewayUninstall(base);
  const first = uninstall.actions[0];
  const owned = receiptStore.value.resources.find(
    (resource) => resource.kind === first.kind && resource.key === first.key,
  );
  let receipt = await beginReceiptAction(receiptStore.value, {
    operationId: 'operation_interrupted_uninstall',
    type: 'uninstall',
    planId: uninstall.uninstallId,
    action: 'delete',
    kind: owned.kind,
    key: owned.key,
    expectedDesiredHash: owned.desiredHash,
    requestHash: `sha256:${'7'.repeat(64)}`,
  });
  provider.resources = provider.resources.filter(
    (resource) => !(resource.kind === owned.kind && resource.key === owned.key),
  );
  receipt = await commitReceiptAction(receipt);
  await receiptStore.writeAtomic(receipt);

  assert.equal((await getGatewayStatus(base)).state, 'uninstalling');
  const live = await planLiveGateway(base);
  await expectCode(
    applyGateway({ ...base, approvedPlanId: live.plan.planId }),
    'pending_uninstall',
  );
});

test('pending uninstall delete retry requires the stored exact approval', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const { base } = await install(provider, receiptStore);
  const preview = await planGatewayUninstall(base);
  const before = provider.mutations.length;
  provider.failBeforeRemoteMutationOnce = true;

  await expectCode(
    uninstallGateway({ ...base, approvedUninstallId: preview.uninstallId }),
    'mutation_failed',
  );
  assert.equal(provider.mutations.length, before + 1);
  await expectCode(
    uninstallGateway({ ...base, approvedUninstallId: 'uninstall-not-current' }),
    'uninstall_approval_required',
  );
  assert.equal(provider.mutations.length, before + 1);

  const result = await uninstallGateway({
    ...base,
    approvedUninstallId: preview.uninstallId,
  });
  assert.equal(result.status, 'removed');
  assert.equal(provider.resources.length, 0);
});

test('lost native ownership marker blocks apply and uninstall without mutation', async () => {
  const provider = new FakeProvider();
  const receiptStore = new MemoryReceiptStore();
  const { base } = await install(provider, receiptStore);
  provider.resources.at(-1).marker = 'foreign-marker';
  const before = provider.mutations.length;

  const live = await planLiveGateway(base);
  assert.equal(live.plan.changes.at(-1).action, 'conflict');
  assert.equal((await getGatewayStatus(base)).state, 'conflict');
  await expectCode(
    applyGateway({ ...base, approvedPlanId: live.plan.planId }),
    'plan_blocked',
  );
  const uninstall = await planGatewayUninstall(base);
  assert.equal(uninstall.blockers[0].code, 'ownership_conflict');
  await expectCode(
    uninstallGateway({ ...base, approvedUninstallId: uninstall.uninstallId }),
    'ownership_conflict',
  );
  assert.equal(provider.mutations.length, before);
});
