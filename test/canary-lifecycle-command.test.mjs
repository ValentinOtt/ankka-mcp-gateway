import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CanaryLockCommandError,
  CanaryLifecycleCommandError,
  executeCanaryLockCommand,
  executeCanaryLifecycleCommand,
  lifecycleResultExitCode,
  renderLifecyclePreview,
  renderLifecycleResult,
} from '../src/canary-lifecycle-command.ts';
import { STALE_LOCK_RECOVERY_CONFIRMATION } from '../src/receipt-store.ts';
import { ownershipMarker } from '../src/receipt.ts';
import {
  CANARY_FIXTURE_ID,
  CANARY_TOOL_NAME,
  CanaryLifecycleError,
} from '../src/canary-runner.ts';

const ACCOUNT_ID = 'a'.repeat(32);
const ZONE_ID = 'b'.repeat(32);
const ZONE_NAME = 'disposable.example';
const HOSTNAME = `ankka-canary-command.${ZONE_NAME}`;
const ENDPOINT = 'https://ankka-synthetic-canary.example.net/mcp';
const TOKEN = 'sensitive-cloudflare-token';
const EMAIL = 'canary@example.net';
const RECEIPT_PATH = '/tmp/ankka-canary-command.receipt.json';
const RESOURCE_ORDER = [
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
];
const LOCK_ID = 'canary-lock-test';
const LOCK_METADATA = Object.freeze({
  version: 1,
  lockId: LOCK_ID,
  ownerId: 'owner-must-not-escape',
  pid: 424242,
  createdAt: '2026-08-22T12:00:00.000Z',
  operationId: 'canary-lifecycle',
});

function assertDoesNotInclude(value, forbidden) {
  assert.equal(value.includes(forbidden), false);
}

class MemoryStore {
  constructor() {
    this.value = null;
    this.writes = 0;
  }
  async read() { return this.value; }
  async writeAtomic(value) { this.value = structuredClone(value); this.writes += 1; }
  async withExclusiveLock(operation) { return operation(); }
}

class MemoryLockStore {
  constructor(inspection) {
    this.inspection = inspection;
    this.recoveries = [];
  }
  async inspectLock() { return structuredClone(this.inspection); }
  async recoverStaleLock(input) {
    this.recoveries.push(structuredClone(input));
    return { status: 'removed', lockId: input.evidence.lockId };
  }
}

function lockInspection(status = 'stale_candidate') {
  if (status === 'ambiguous') return { status };
  return {
    status,
    metadata: structuredClone(LOCK_METADATA),
    evidence: structuredClone(LOCK_METADATA),
  };
}

function lockInvocation(overrides = {}) {
  return {
    operation: 'inspect',
    store: 'receipt',
    receiptPath: RECEIPT_PATH,
    ...overrides,
  };
}

function cloudflareReadClient() {
  return {
    getZone: async () => ({
      id: ZONE_ID,
      name: ZONE_NAME,
      status: 'active',
      account: { id: ACCOUNT_ID },
    }),
    listIdentityProviders: async () => [{ id: 'idp' }],
    listMcpServers: async () => [],
    listPortals: async () => [],
    listAccessApps: async () => [],
    listDnsRecords: async () => [],
  };
}

function emptyProvider() {
  return {
    mutations: 0,
    async readObservedState() {
      return {
        target: {
          accountId: ACCOUNT_ID,
          zoneId: ZONE_ID,
          zoneName: ZONE_NAME,
          zoneStatus: 'active',
          zeroTrustReady: true,
        },
        resources: [],
        diagnostics: [],
      };
    },
    async applyChange() {
      this.mutations += 1;
    },
    async inspectCanaryResidue() {
      return { ownedResourceCount: 0 };
    },
  };
}

class LifecycleProvider {
  constructor() {
    this.resources = [];
    this.mutations = [];
    this.sequence = 0;
  }

  async readObservedState({ receipt }) {
    return {
      target: {
        accountId: ACCOUNT_ID,
        zoneId: ZONE_ID,
        zoneName: ZONE_NAME,
        zoneStatus: 'active',
        zeroTrustReady: true,
      },
      resources: this.resources.map((resource) => {
        const marker = receipt
          ? ownershipMarker(receipt.installationId, resource.key)
          : null;
        const owned = receipt?.resources.some((candidate) =>
          candidate.kind === resource.kind &&
          candidate.key === resource.key &&
          sameProvider(candidate.provider, resource.provider));
        const pendingCreate =
          receipt?.pending?.type === 'apply' &&
          receipt.pending.action === 'create' &&
          receipt.pending.kind === resource.kind &&
          receipt.pending.key === resource.key &&
          receipt.pending.expectedDesiredHash === resource.desiredHash;
        const markerlessApplication = resource.kind === 'portal_access_application';
        return {
          kind: resource.kind,
          key: resource.key,
          provider: structuredClone(resource.provider),
          owner:
            (owned && (markerlessApplication || resource.marker === marker))
              || (pendingCreate && !markerlessApplication && resource.marker === marker)
              ? {
                  manager: 'ankka-mcp-gateway',
                  installationId: receipt.installationId,
                }
              : {},
          desiredHash: resource.desiredHash,
        };
      }),
      diagnostics: [],
    };
  }

  async applyChange({ change, receipt }) {
    this.mutations.push({ action: change.action, kind: change.kind });
    if (change.action === 'create') {
      this.sequence += 1;
      const policy = change.kind.endsWith('_access_policy');
      const parentKey = change.desired?.sourceApplicationResourceKey ??
        change.desired?.portalApplicationResourceKey;
      const parent = policy
        ? this.resources.find((resource) =>
          (
            resource.kind === 'source_access_application' ||
            resource.kind === 'portal_access_application'
          ) && resource.key === parentKey)
        : null;
      const provider = policy
        ? { id: `policy-${this.sequence}`, parentId: parent.provider.id }
        : {
            id: change.kind === 'mcp_server' || change.kind === 'portal'
              ? change.key
              : `resource-${this.sequence}`,
          };
      this.resources.push({
        kind: change.kind,
        key: change.key,
        provider,
        marker: ownershipMarker(receipt.installationId, change.key),
        desiredHash: change.desiredHash,
      });
      if (change.kind === 'portal_access_application') {
        return { status: 'submitted', provider: structuredClone(provider) };
      }
      return { status: 'submitted' };
    }
    const index = this.resources.findIndex((resource) =>
      resource.kind === change.kind &&
      resource.key === change.key &&
      sameProvider(resource.provider, change.provider));
    if (change.action === 'delete' && index !== -1) {
      this.resources.splice(index, 1);
    }
    return { status: 'submitted' };
  }

  async inspectCanaryResidue() {
    return { ownedResourceCount: this.resources.length };
  }
}

function sameProvider(left, right) {
  return left?.id === right?.id &&
    (left?.parentId ?? '') === (right?.parentId ?? '');
}

function invocation(overrides = {}) {
  return {
    mode: 'preview',
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
    hostname: HOSTNAME,
    syntheticMcpUrl: ENDPOINT,
    receiptPath: RECEIPT_PATH,
    ...overrides,
  };
}

function runtime(overrides = {}) {
  const provider = overrides.provider ?? emptyProvider();
  const store = overrides.store ?? new MemoryStore();
  const cleanupStore = overrides.cleanupStore ?? new MemoryStore();
  const dependencies = {
    readToken: () => TOKEN,
    readAllowedEmail: () => EMAIL,
    clientFactory(options) {
      assert.equal(options.token, TOKEN);
      assert.equal(options.accountId, ACCOUNT_ID);
      assert.equal(options.zoneId, ZONE_ID);
      return cloudflareReadClient();
    },
    providerFactory(options) {
      assert.equal(options.token, TOKEN);
      return provider;
    },
    inspectSyntheticUpstream: async () => ({
      fixture: CANARY_FIXTURE_ID,
      schemaVersion: 1,
      toolNames: [CANARY_TOOL_NAME],
      callVerified: true,
    }),
    verifyInstalledGateway: async () => ({
      ready: true,
      fixture: CANARY_FIXTURE_ID,
      toolName: CANARY_TOOL_NAME,
    }),
    fetchImpl: async () => { throw new Error('unused'); },
    sleep: async () => {},
    ...Object.fromEntries(
      Object.entries(overrides).filter(
        ([key]) => key !== 'provider' && key !== 'store' && key !== 'cleanupStore',
      ),
    ),
    receiptStoreFactory: overrides.receiptStoreFactory ?? ((path) => {
      if (path === RECEIPT_PATH) return store;
      assert.equal(path, `${RECEIPT_PATH}.cleanup-recovery`);
      return cleanupStore;
    }),
  };
  Object.defineProperties(dependencies, {
    testProvider: { value: provider },
    testStore: { value: store },
    testCleanupStore: { value: cleanupStore },
  });
  return dependencies;
}

test('command reads token and Access email only from closures and renders a safe preview', async () => {
  const deps = runtime();
  const result = await executeCanaryLifecycleCommand(invocation(), deps);

  assert.equal(result.exitCode, 0);
  assert.equal(result.report.writesPerformed, false);
  assert.match(result.output, /READY FOR REVIEW/);
  assert.match(result.output, /No Cloudflare resources were changed/);
  for (const forbidden of [TOKEN, EMAIL, ACCOUNT_ID, ZONE_ID, HOSTNAME, ENDPOINT, RECEIPT_PATH]) {
    assertDoesNotInclude(result.output, forbidden);
  }
  assert.equal(deps.testProvider.mutations, 0);
});

test('JSON preview contains approval evidence but no secret or selected target values', async () => {
  const result = await executeCanaryLifecycleCommand(
    invocation({ json: true }),
    runtime(),
  );
  const parsed = JSON.parse(result.output);
  assert.match(parsed.approvalId, /^canary-lifecycle-/);
  assert.match(parsed.targetConfirmationId, /^canary-target-/);
  for (const forbidden of [TOKEN, EMAIL, ACCOUNT_ID, ZONE_ID, HOSTNAME, ENDPOINT]) {
    assertDoesNotInclude(result.output, forbidden);
  }
});

test('normalizes uppercase Cloudflare IDs before constructing clients and the runner', async () => {
  const result = await executeCanaryLifecycleCommand(
    invocation({
      accountId: ACCOUNT_ID.toUpperCase(),
      zoneId: ZONE_ID.toUpperCase(),
    }),
    runtime(),
  );
  assert.equal(result.report.ready, true);
  assert.equal(result.exitCode, 0);
});

test('an injected inspection hold is forwarded only to run and remains outside CLI input', async () => {
  const provider = new LifecycleProvider();
  let releaseHold;
  let reachedHold;
  const reached = new Promise((resolve) => {
    reachedHold = resolve;
  });
  let holdCalls = 0;
  let holdInput;
  const deps = runtime({
    provider,
    holdForInspection(value) {
      holdCalls += 1;
      holdInput = value;
      reachedHold();
      return new Promise((resolve) => {
        releaseHold = resolve;
      });
    },
  });

  await assert.rejects(
    executeCanaryLifecycleCommand(
      { ...invocation(), holdForInspection: () => {} },
      deps,
    ),
    (error) =>
      error instanceof CanaryLifecycleCommandError &&
      error.code === 'invalid_invocation',
  );
  const preview = await executeCanaryLifecycleCommand(invocation(), deps);
  assert.equal(holdCalls, 0);
  const running = executeCanaryLifecycleCommand(
    invocation({
      mode: 'run',
      approvalId: preview.report.approvalId,
      targetConfirmationId: preview.report.targetConfirmationId,
    }),
    deps,
  );

  await reached;
  assert.equal(holdCalls, 1);
  assert.deepEqual(Object.keys(holdInput).sort(), ['hostname', 'signal']);
  assert.equal(holdInput.hostname, HOSTNAME);
  assert.ok(holdInput.signal instanceof AbortSignal);
  assert.equal(holdInput.signal.aborted, false);
  assert.deepEqual(provider.resources.map(({ kind }) => kind), RESOURCE_ORDER);
  assert.equal(provider.mutations.some(({ action }) => action === 'delete'), false);

  releaseHold();
  const result = await running;
  assert.equal(result.report.status, 'complete');
  assert.equal(result.exitCode, 0);
  assert.equal(provider.resources.length, 0);
  assert.deepEqual(
    provider.mutations.filter(({ action }) => action === 'delete').map(({ kind }) => kind),
    [...RESOURCE_ORDER].reverse(),
  );

  let secretReads = 0;
  await assert.rejects(
    executeCanaryLifecycleCommand(invocation(), {
      ...runtime(),
      holdForInspection: 'not-a-function',
      readToken() { secretReads += 1; return TOKEN; },
    }),
    (error) =>
      error instanceof CanaryLifecycleCommandError &&
      error.code === 'runtime_not_configured',
  );
  assert.equal(secretReads, 0);
});

test('token and email invocation fields are rejected before secret reads', async () => {
  let secretReads = 0;
  for (const forbidden of [
    { token: TOKEN },
    { allowedEmail: EMAIL },
  ]) {
    await assert.rejects(
      executeCanaryLifecycleCommand(invocation(forbidden), {
        ...runtime(),
        readToken() { secretReads += 1; return TOKEN; },
      }),
      (error) => error instanceof CanaryLifecycleCommandError && error.code === 'invalid_invocation',
    );
  }
  assert.equal(secretReads, 0);
});

test('exact lifecycle approval is checked after a fresh preview and before any mutation', async () => {
  const deps = runtime();
  await assert.rejects(
    executeCanaryLifecycleCommand(
      invocation({
        mode: 'run',
        approvalId: `canary-lifecycle-${'0'.repeat(24)}`,
        targetConfirmationId: `canary-target-${'1'.repeat(24)}`,
      }),
      deps,
    ),
    (error) => {
      assert.ok(error instanceof CanaryLifecycleError);
      assert.equal(error.code, 'disposable_target_confirmation_required');
      return true;
    },
  );
  assert.equal(deps.testProvider.mutations, 0);
});

test('secret-reader and factory failures expose only fixed errors', async () => {
  await assert.rejects(
    executeCanaryLifecycleCommand(invocation(), {
      ...runtime(),
      readToken() { throw new Error(TOKEN); },
    }),
    (error) => {
      assert.ok(error instanceof CanaryLifecycleCommandError);
      assert.equal(error.code, 'secret_unavailable');
      assertDoesNotInclude(error.message, TOKEN);
      return true;
    },
  );
  await assert.rejects(
    executeCanaryLifecycleCommand(invocation(), {
      ...runtime(),
      providerFactory() { throw new Error(TOKEN); },
    }),
    (error) => {
      assert.ok(error instanceof CanaryLifecycleCommandError);
      assert.equal(error.code, 'runtime_not_configured');
      assertDoesNotInclude(error.message, TOKEN);
      return true;
    },
  );
});

test('resource cleanup without interactive Portal verification is partial, never COMPLETE', () => {
  const partial = {
    schemaVersion: 1,
    kind: 'cloudflare_canary_lifecycle_result',
    status: 'verification_pending',
    resourceLifecycle: 'removed',
    interactiveVerification: 'pending',
    installedStateVerified: true,
    portalToolCallVerified: false,
    idempotentApplyVerified: true,
    cleanup: {
      status: 'removed',
      ownedResourceCount: 0,
    },
  };
  const output = renderLifecycleResult(partial);
  assert.equal(lifecycleResultExitCode(partial), 3);
  assert.match(output, /RESOURCE LIFECYCLE REMOVED/);
  assert.match(output, /Interactive Portal tool call: pending/);
  assert.match(output, /verification is still pending/);
  assert.doesNotMatch(output, /COMPLETE/);
});

test('a fully verified and removed lifecycle exits zero', () => {
  const complete = {
    schemaVersion: 1,
    kind: 'cloudflare_canary_lifecycle_result',
    status: 'complete',
    resourceLifecycle: 'removed',
    interactiveVerification: 'verified',
    installedStateVerified: true,
    portalToolCallVerified: true,
    idempotentApplyVerified: true,
    cleanup: {
      status: 'removed',
      ownedResourceCount: 0,
    },
  };
  assert.equal(lifecycleResultExitCode(complete), 0);
  assert.match(renderLifecycleResult(complete), /: COMPLETE/);
});

test('pending Portal rollback preview and result render as a bounded recovery, not a completed canary', () => {
  const preview = {
    schemaVersion: 1,
    kind: 'cloudflare_canary_lifecycle_preview',
    operation: 'rollback_pending_portal_create',
    ready: true,
    writesPerformed: false,
    approvalId: `canary-lifecycle-${'1'.repeat(24)}`,
    targetConfirmationId: `canary-target-${'2'.repeat(24)}`,
    changes: [{ action: 'rollback', kind: 'portal' }],
    cleanup: [],
  };
  const result = {
    schemaVersion: 1,
    kind: 'cloudflare_canary_lifecycle_result',
    status: 'rollback_complete',
    operation: 'rollback_pending_portal_create',
    resourceLifecycle: 'partial',
    interactiveVerification: 'pending',
    installedStateVerified: false,
    portalToolCallVerified: false,
    idempotentApplyVerified: false,
    cleanup: { status: 'rollback_complete', remainingReceiptResourceCount: 3 },
  };

  assert.match(renderLifecyclePreview(preview), /PENDING PORTAL ROLLBACK READY FOR REVIEW/);
  assert.match(renderLifecycleResult(result), /PENDING PORTAL ROLLBACK COMPLETE/);
  assert.match(renderLifecycleResult(result), /fresh preview/);
  assert.doesNotMatch(renderLifecycleResult(result), /canary: COMPLETE/);
  assert.equal(lifecycleResultExitCode(result), 0);
});

test('partial-install cleanup has dedicated redacted preview/result rendering and exits zero', () => {
  const preview = {
    schemaVersion: 1,
    kind: 'cloudflare_canary_lifecycle_preview',
    operation: 'cleanup_partial_install',
    ready: true,
    writesPerformed: false,
    approvalId: `canary-lifecycle-${'3'.repeat(24)}`,
    targetConfirmationId: `canary-target-${'4'.repeat(24)}`,
    changes: [],
    cleanup: [
      { action: 'delete', kind: 'source_access_policy' },
      { action: 'delete', kind: 'source_access_application' },
      { action: 'delete', kind: 'mcp_server' },
    ],
  };
  const result = {
    schemaVersion: 1,
    kind: 'cloudflare_canary_lifecycle_result',
    status: 'cleanup_complete',
    operation: 'cleanup_partial_install',
    resourceLifecycle: 'removed',
    interactiveVerification: 'not_applicable',
    writesPerformed: true,
    installedStateVerified: false,
    portalToolCallVerified: false,
    idempotentApplyVerified: false,
    cleanup: {
      status: 'removed',
      reverseOrderVerified: true,
      ownedResourceCount: 0,
      partialInstallRemoved: true,
    },
  };

  const previewOutput = renderLifecyclePreview(preview);
  const resultOutput = renderLifecycleResult(result);
  assert.match(previewOutput, /PARTIAL INSTALL CLEANUP READY FOR REVIEW/);
  assert.match(previewOutput, /delete source_access_policy[\s\S]*delete source_access_application[\s\S]*delete mcp_server/);
  assert.match(previewOutput, /No Cloudflare resources were changed/);
  assert.match(resultOutput, /PARTIAL INSTALL CLEANUP COMPLETE/);
  assert.match(resultOutput, /tombstone was retained/);
  assert.doesNotMatch(resultOutput, /Interactive Portal/);
  assert.equal(lifecycleResultExitCode(result), 0);
  for (const forbidden of [ACCOUNT_ID, ZONE_ID, HOSTNAME, ENDPOINT, TOKEN, EMAIL, RECEIPT_PATH]) {
    assertDoesNotInclude(`${previewOutput}\n${resultOutput}`, forbidden);
  }
});

test('lock inspection is secret-free and exposes only sanitized operation metadata', async () => {
  const store = new MemoryLockStore(lockInspection());
  let selectedPath;
  const result = await executeCanaryLockCommand(lockInvocation(), {
    receiptStoreFactory(path) {
      selectedPath = path;
      return store;
    },
  });

  assert.equal(selectedPath, RECEIPT_PATH);
  assert.deepEqual(result.report, {
    schemaVersion: 1,
    kind: 'canary_lock_inspection',
    store: 'receipt',
    status: 'stale_candidate',
    lockId: LOCK_ID,
    operationId: 'canary-lifecycle',
    createdAt: '2026-08-22T12:00:00.000Z',
    lockRemoved: false,
  });
  assert.match(result.output, /STALE CANDIDATE/);
  assert.equal(result.output.includes(LOCK_ID), true);
  for (const forbidden of [
    LOCK_METADATA.ownerId,
    String(LOCK_METADATA.pid),
    RECEIPT_PATH,
    TOKEN,
    EMAIL,
  ]) {
    assertDoesNotInclude(result.output, forbidden);
  }
  assert.equal(store.recoveries.length, 0);
});

test('lock inspection selects the cleanup sidecar explicitly and handles no lock', async () => {
  let selectedPath;
  const result = await executeCanaryLockCommand(
    lockInvocation({ store: 'cleanup', json: true }),
    {
      receiptStoreFactory(path) {
        selectedPath = path;
        return new MemoryLockStore(null);
      },
    },
  );
  assert.equal(selectedPath, `${RECEIPT_PATH}.cleanup-recovery`);
  assert.deepEqual(JSON.parse(result.output), {
    schemaVersion: 1,
    kind: 'canary_lock_inspection',
    store: 'cleanup',
    status: 'not_found',
    lockRemoved: false,
  });
});

test('lock recovery requires the freshly inspected exact lock ID and passes full evidence', async () => {
  const store = new MemoryLockStore(lockInspection());
  const result = await executeCanaryLockCommand(
    lockInvocation({
      operation: 'recover',
      lockId: LOCK_ID,
      confirmation: STALE_LOCK_RECOVERY_CONFIRMATION,
    }),
    { receiptStoreFactory: () => store },
  );
  assert.equal(result.report.status, 'removed');
  assert.equal(result.report.lockId, LOCK_ID);
  assert.deepEqual(store.recoveries, [{
    evidence: LOCK_METADATA,
    confirmation: STALE_LOCK_RECOVERY_CONFIRMATION,
  }]);

  const mismatchStore = new MemoryLockStore(lockInspection());
  await assert.rejects(
    executeCanaryLockCommand(
      lockInvocation({
        operation: 'recover',
        lockId: 'different-lock-id',
        confirmation: STALE_LOCK_RECOVERY_CONFIRMATION,
      }),
      { receiptStoreFactory: () => mismatchStore },
    ),
    (error) => error instanceof CanaryLockCommandError && error.code === 'lock_id_mismatch',
  );
  assert.equal(mismatchStore.recoveries.length, 0);
});

test('live and ambiguous locks fail closed without calling recovery', async () => {
  for (const [status, code] of [
    ['live', 'lock_live'],
    ['ambiguous', 'lock_ambiguous'],
  ]) {
    const store = new MemoryLockStore(lockInspection(status));
    await assert.rejects(
      executeCanaryLockCommand(
        lockInvocation({
          operation: 'recover',
          lockId: LOCK_ID,
          confirmation: STALE_LOCK_RECOVERY_CONFIRMATION,
        }),
        { receiptStoreFactory: () => store },
      ),
      (error) => error instanceof CanaryLockCommandError && error.code === code,
    );
    assert.equal(store.recoveries.length, 0);
  }
});

test('wrong recovery confirmation is rejected before constructing a store', async () => {
  let factories = 0;
  await assert.rejects(
    executeCanaryLockCommand(
      lockInvocation({
        operation: 'recover',
        lockId: LOCK_ID,
        confirmation: 'yes',
      }),
      { receiptStoreFactory() { factories += 1; } },
    ),
    (error) => error instanceof CanaryLockCommandError && error.code === 'invalid_invocation',
  );
  assert.equal(factories, 0);
});
