import { runCloudflareCanaryPreflight } from './canary-preflight.mjs';
import { validateCloudflareId, validateHostname } from './canary-command.mjs';
import { buildGatewayDesiredState } from './plan.mjs';
import {
  applyGateway,
  getGatewayStatus,
  planPendingPortalCreateRollback,
  planGatewayUninstall,
  planLiveGateway,
  rollbackPendingPortalCreate,
  uninstallGateway,
} from './reconciler.mjs';
import { validateInstallationReceipt } from './receipt.mjs';

export const CANARY_TOOL_NAME = 'ankka_canary_status';
export const CANARY_FIXTURE_ID = 'ankka-synthetic-mcp-canary';

const RELEASE = 'cloudflare-canary-v1';
const EXPECTED_ORDER = Object.freeze([
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
]);
const REVERSE_ORDER = Object.freeze([...EXPECTED_ORDER].reverse());
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const SAFE_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const POLL_ATTEMPTS = 12;
const POLL_INTERVAL_MS = 2_000;
const POLL_ATTEMPT_TIMEOUT_MS = 10_000;
const POLL_OVERALL_TIMEOUT_MS = 60_000;
const INSPECTION_HOLD_TIMEOUT_MS = 15 * 60_000;

const MESSAGES = Object.freeze({
  approval_required: 'The exact current canary lifecycle approval is required.',
  cleanup_failed: 'Receipt-owned cleanup did not converge; retain the receipt for recovery.',
  disposable_target_confirmation_required:
    'The exact disposable-target confirmation is required before any write.',
  invalid_input: 'The canary lifecycle input is invalid.',
  lifecycle_and_cleanup_failed:
    'The canary lifecycle failed and receipt-owned cleanup did not converge.',
  lifecycle_failed: 'The canary lifecycle failed; receipt-owned cleanup completed.',
  lifecycle_failed_before_mutation:
    'The canary lifecycle failed before any apply mutation; no cleanup was authorized.',
  legacy_manual_cleanup_required:
    'This pre-release legacy receipt requires manual cleanup; no automated mutation was authorized.',
  lifecycle_lock_failed: 'The canary lifecycle lock could not be acquired safely.',
  lifecycle_locked: 'Another canary lifecycle operation is already running.',
  pending_apply_blocked:
    'The apply outcome is unknown; the pending receipt was retained without replay or cleanup.',
  plan_blocked: 'The disposable-account canary plan is not safe to execute.',
  preflight_not_ready: 'The zero-write Cloudflare preflight is not ready.',
  residue_detected: 'Canary cleanup left provider residue for manual inspection.',
  rollback_failed: 'The exact pending Portal rollback did not converge; the receipt was retained.',
  synthetic_upstream_invalid: 'The upstream is not the exact synthetic canary fixture.',
  verification_failed: 'The installed synthetic canary could not be verified.',
});

/** Body-free and identifier-free error safe to surface from a canary CLI. */
export class CanaryLifecycleError extends Error {
  constructor(code, details = {}) {
    const safeCode = typeof code === 'string' && SAFE_CODE.test(code) ? code : 'lifecycle_failed';
    super(MESSAGES[safeCode] ?? MESSAGES.lifecycle_failed);
    this.name = 'CanaryLifecycleError';
    this.code = safeCode;
    this.cleanup = safeCleanupState(details.cleanup);
  }
}

/**
 * Build a read-only, target-bound approval preview. This function validates
 * the synthetic fixture and Cloudflare read surface but performs no writes.
 */
export async function previewCloudflareCanaryLifecycle(input = {}, dependencies = {}) {
  const context = requireContext(input, dependencies, { mutations: false });
  return (await buildPreview(context)).report;
}

/**
 * Apply, verify, idempotently re-apply, and uninstall one disposable-account
 * canary. Exact approval and target confirmation are recomputed from fresh
 * reads immediately before the first write. The receipt remains the recovery
 * authority if the process or provider fails mid-operation.
 */
export async function runCloudflareCanaryLifecycle(input = {}, dependencies = {}) {
  const context = requireContext(input, dependencies, { mutations: true });
  try {
    return await context.cleanupStore.withExclusiveLock(
      () => runCloudflareCanaryLifecycleLocked(input, context),
      { operationId: 'canary-lifecycle' },
    );
  } catch (error) {
    if (error instanceof CanaryLifecycleError) throw error;
    if (error?.code === 'locked') throw new CanaryLifecycleError('lifecycle_locked');
    throw new CanaryLifecycleError('lifecycle_lock_failed');
  }
}

async function runCloudflareCanaryLifecycleLocked(input, context) {
  const preview = await buildPreview(context);
  if (input.targetConfirmationId !== preview.report.targetConfirmationId) {
    throw new CanaryLifecycleError('disposable_target_confirmation_required');
  }
  if (input.approvalId !== preview.report.approvalId) {
    throw new CanaryLifecycleError('approval_required');
  }

  if (preview.operation === 'residue_recovery') {
    return verifyRemovedCanaryResidue(context, preview.recoveryReceipt);
  }
  if (preview.operation === 'resume_uninstall') {
    return resumeInterruptedUninstall(context, reconciliationContext(context));
  }
  if (preview.operation === 'cleanup_partial_install') {
    const cleanup = await cleanupCanary(context, reconciliationContext(context), {
      expectedReceiptChecksum: preview.receiptChecksum,
      expectedProvenanceSnapshotChecksum: preview.provenanceSnapshotChecksum,
      approvedUninstallId: preview.uninstallId,
      expectedUninstallActions: preview.uninstallActions,
    });
    if (cleanup.status !== 'removed') {
      throw new CanaryLifecycleError('cleanup_failed', { cleanup });
    }
    if (!residueIsEmpty(cleanup.residue)) {
      throw new CanaryLifecycleError('residue_detected', { cleanup });
    }
    return Object.freeze({
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
      cleanup: Object.freeze({
        status: 'removed',
        reverseOrderVerified: cleanup.reverseOrderVerified,
        ownedResourceCount: 0,
        partialInstallRemoved: true,
      }),
    });
  }
  if (preview.operation === 'rollback_pending_portal_create') {
    emit(context, { stage: 'rollback', status: 'started', action: 'delete', kind: 'portal' });
    let rolledBack;
    try {
      await persistPartialCleanupMarker(context, preview.rollbackRecoveryReceipt);
      rolledBack = await rollbackPendingPortalCreate({
        ...reconciliationContext(context),
        approvedRollbackId: preview.rollbackId,
      });
    } catch {
      throw new CanaryLifecycleError('rollback_failed');
    }
    if (rolledBack?.status !== 'rollback_complete') {
      throw new CanaryLifecycleError('rollback_failed');
    }
    emit(context, { stage: 'rollback', status: 'verified', action: 'delete', kind: 'portal' });
    return Object.freeze({
      schemaVersion: 1,
      kind: 'cloudflare_canary_lifecycle_result',
      status: 'rollback_complete',
      operation: 'rollback_pending_portal_create',
      resourceLifecycle: 'partial',
      interactiveVerification: 'pending',
      writesPerformed: true,
      installedStateVerified: false,
      portalToolCallVerified: false,
      idempotentApplyVerified: false,
      cleanup: Object.freeze({
        status: 'rollback_complete',
        remainingReceiptResourceCount: rolledBack.receipt?.resourceCount ?? 0,
      }),
    });
  }

  let cleanupAuthorized = false;
  const reconcileContext = reconciliationContext(context, {
    // Journaling an intent is not mutation authority. Cleanup becomes safe
    // only after the provider adapter has returned a normalized `submitted`
    // result; a proven `not_submitted` refusal therefore leaves an existing
    // installation untouched.
    onApplyMutationSubmitted() {
      cleanupAuthorized = true;
    },
  });
  let lifecycleFailure = null;
  let applyAttempted = false;
  let stateVerified = false;
  let portalToolCallVerified = false;
  let idempotent = false;
  let cleanup = { status: 'not_started' };

  try {
    applyAttempted = true;
    emit(context, { stage: 'apply', status: 'started' });
    try {
      await applyGateway({
        ...reconcileContext,
        approvedPlanId: preview.planId,
      });
    } catch (error) {
      if (
        !preview.pendingUpdateRecovery ||
        !await pendingUpdateRecoveryWasCommitted(context, preview)
      ) {
        throw error;
      }
    }
    // A successful no-op apply of a pre-existing canary installation still
    // authorizes the exact lifecycle cleanup approved in the preview.
    cleanupAuthorized = true;
    const installed = await getGatewayStatus(reconcileContext);
    if (installed.state !== 'ready' || installed.changes.some(({ action }) => action !== 'noop')) {
      throw new CanaryLifecycleError('verification_failed');
    }
    stateVerified = true;
    emit(context, { stage: 'apply', status: 'verified' });

    const noOpPreview = await planLiveGateway(reconcileContext);
    if (
      noOpPreview.plan.blockers.length > 0 ||
      noOpPreview.plan.changes.some(({ action }) => action !== 'noop') ||
      noOpPreview.pruneApprovalId !== null
    ) {
      throw new CanaryLifecycleError('verification_failed');
    }
    await applyGateway({
      ...reconcileContext,
      approvedPlanId: noOpPreview.plan.planId,
    });
    idempotent = true;
    emit(context, { stage: 'idempotency', status: 'verified' });

    if (context.holdForInspection) {
      emit(context, { stage: 'inspection', status: 'started' });
      await withDeadline(
        (signal) => context.holdForInspection({
          hostname: context.hostname,
          signal,
        }),
        context.inspectionHoldTimeoutMs,
      );
      emit(context, { stage: 'inspection', status: 'verified' });
    }

    if (context.verifyInstalledGateway) {
      await pollBounded({
        probe: (signal) => context.verifyInstalledGateway({
          hostname: context.hostname,
          expectedFixture: CANARY_FIXTURE_ID,
          expectedTool: CANARY_TOOL_NAME,
          signal,
        }),
        accept: validInstalledVerification,
        sleep: context.sleep,
        attemptTimeoutMs: context.pollAttemptTimeoutMs,
        overallTimeoutMs: context.pollOverallTimeoutMs,
      });
      portalToolCallVerified = true;
      emit(context, { stage: 'synthetic_tool', status: 'verified' });
    }
  } catch (error) {
    lifecycleFailure = normalizeLifecycleFailure(error);
    emit(context, { stage: 'lifecycle', status: 'failed' });
  }

  const pendingApply = applyAttempted && await hasPendingApply(context.receiptStore);
  if (cleanupAuthorized && !pendingApply) {
    cleanup = await cleanupCanary(context, reconcileContext);
  }

  if (pendingApply) {
    throw new CanaryLifecycleError('pending_apply_blocked', {
      cleanup: { status: 'blocked_pending_apply' },
    });
  }

  if (cleanup.status === 'removed' && !residueIsEmpty(cleanup.residue)) {
    throw new CanaryLifecycleError('residue_detected', { cleanup });
  }

  if (lifecycleFailure !== null) {
    if (!cleanupAuthorized) {
      throw new CanaryLifecycleError('lifecycle_failed_before_mutation', { cleanup });
    }
    throw new CanaryLifecycleError(
      cleanup.status === 'removed' ? 'lifecycle_failed' : 'lifecycle_and_cleanup_failed',
      { cleanup },
    );
  }
  if (cleanup.status !== 'removed') {
    throw new CanaryLifecycleError('cleanup_failed', { cleanup });
  }
  const report = Object.freeze({
    schemaVersion: 1,
    kind: 'cloudflare_canary_lifecycle_result',
    status: portalToolCallVerified ? 'complete' : 'verification_pending',
    resourceLifecycle: 'removed',
    interactiveVerification: portalToolCallVerified ? 'verified' : 'pending',
    writesPerformed: true,
    installedStateVerified: stateVerified,
    portalToolCallVerified,
    idempotentApplyVerified: idempotent,
    cleanup: Object.freeze({
      status: cleanup.status,
      reverseOrderVerified: cleanup.reverseOrderVerified,
      ownedResourceCount: cleanup.residue.ownedResourceCount,
    }),
  });
  return report;
}

async function buildPreview(context) {
  const preflight = await runCloudflareCanaryPreflight({
    cloudflare: context.cloudflare,
    accountId: context.accountId,
    zoneId: context.zoneId,
    hostname: context.hostname,
  });
  if (!preflight.ready) throw new CanaryLifecycleError('preflight_not_ready');

  const recovery = await readCanaryRecovery(context);
  const targetConfirmationId = await buildTargetConfirmationId(context);
  let pendingPortalCreateRecoveryReceiptChecksum = null;
  if (recovery?.type === 'pending_portal_create') {
    const ordinary = await planLiveGateway(reconciliationContext(context));
    if (await isExactPendingPortalCreateNoopRecovery(ordinary, recovery.receipt, context)) {
      pendingPortalCreateRecoveryReceiptChecksum = recovery.receipt.checksum;
    } else {
      let rollback;
      try {
        rollback = await planPendingPortalCreateRollback(reconciliationContext(context));
      } catch {
        throw new CanaryLifecycleError('plan_blocked');
      }
      const approvalId = await stableId('canary-lifecycle', {
        operation: 'rollback_pending_portal_create',
        targetConfirmationId,
        rollbackId: rollback.rollbackId,
        receiptChecksum: recovery.receipt.checksum,
        pending: {
          operationId: recovery.receipt.pending.operationId,
          requestHash: recovery.receipt.pending.requestHash,
          kind: recovery.receipt.pending.kind,
          key: recovery.receipt.pending.key,
          expectedDesiredHash: recovery.receipt.pending.expectedDesiredHash,
        },
        portalState: rollback.portalState,
      });
      return {
        operation: 'rollback_pending_portal_create',
        rollbackId: rollback.rollbackId,
        rollbackRecoveryReceipt: recovery.receipt,
        report: Object.freeze({
          schemaVersion: 1,
          kind: 'cloudflare_canary_lifecycle_preview',
          operation: 'rollback_pending_portal_create',
          ready: true,
          writesPerformed: false,
          approvalId,
          targetConfirmationId,
          changes: Object.freeze([
            Object.freeze({ action: 'rollback', kind: 'portal' }),
          ]),
          cleanup: Object.freeze([]),
        }),
      };
    }
  }
  if (recovery?.type === 'partial_install_cleanup') {
    const live = await planLiveGateway(reconciliationContext(context));
    await assertExactPartialCleanupPlan(live, recovery.receipt, context);
    const uninstall = await planGatewayUninstall(reconciliationContext(context));
    assertExactPartialCleanupUninstall(uninstall, recovery.receipt);
    const immutableSubset = recovery.receipt.resources.map(copyReceiptResourceFingerprint);
    const approvalId = await stableId('canary-lifecycle', {
      operation: 'cleanup_partial_install',
      targetConfirmationId,
      receiptChecksum: recovery.receipt.checksum,
      provenanceSnapshotChecksum: recovery.snapshot.checksum,
      planId: live.plan.planId,
      receiptDesiredHash: recovery.receipt.desiredHash,
      currentDesiredHash: live.plan.desiredHash,
      uninstallId: uninstall.uninstallId,
      actions: uninstall.actions,
      immutableSubset,
    });
    return {
      operation: 'cleanup_partial_install',
      cleanupSnapshot: recovery.receipt,
      receiptChecksum: recovery.receipt.checksum,
      provenanceSnapshotChecksum: recovery.snapshot.checksum,
      uninstallId: uninstall.uninstallId,
      uninstallActions: uninstall.actions.map(copyUninstallAction),
      report: Object.freeze({
        schemaVersion: 1,
        kind: 'cloudflare_canary_lifecycle_preview',
        operation: 'cleanup_partial_install',
        ready: true,
        writesPerformed: false,
        approvalId,
        targetConfirmationId,
        changes: Object.freeze([]),
        cleanup: Object.freeze(
          uninstall.actions.map(({ action, kind }) => Object.freeze({ action, kind })),
        ),
      }),
    };
  }
  if (recovery?.type === 'removed') {
    const approvalId = await stableId('canary-lifecycle', {
      operation: 'verify_cleanup_residue',
      targetConfirmationId,
      removedReceiptChecksum: recovery.removed.checksum,
      recoveryReceiptChecksum: recovery.snapshot.checksum,
    });
    return {
      operation: 'residue_recovery',
      recoveryReceipt: recovery.snapshot,
      report: Object.freeze({
        schemaVersion: 1,
        kind: 'cloudflare_canary_lifecycle_preview',
        operation: 'residue_recovery',
        ready: true,
        writesPerformed: false,
        approvalId,
        targetConfirmationId,
        changes: Object.freeze([]),
        cleanup: Object.freeze([
          Object.freeze({ action: 'verify_residue', kind: 'installation' }),
        ]),
      }),
    };
  }
  if (
    recovery?.type === 'uninstalling' ||
    recovery?.type === 'uninstall_exhausted'
  ) {
    const uninstall = await planGatewayUninstall(reconciliationContext(context));
    if (
      uninstall.blockers.length > 0 ||
      !validReverseCleanup(uninstall.actions, {
        allowEmpty: recovery.type === 'uninstall_exhausted',
      })
    ) {
      throw new CanaryLifecycleError('plan_blocked');
    }
    const approvalId = await stableId('canary-lifecycle', {
      operation: 'resume_receipt_owned_uninstall',
      targetConfirmationId,
      receiptChecksum: recovery.receipt.checksum,
      uninstallApprovalId:
        recovery.receipt.pending?.planId ?? uninstall.uninstallId,
    });
    return {
      operation: 'resume_uninstall',
      report: Object.freeze({
        schemaVersion: 1,
        kind: 'cloudflare_canary_lifecycle_preview',
        operation: 'resume_uninstall',
        ready: true,
        writesPerformed: false,
        approvalId,
        targetConfirmationId,
        changes: Object.freeze([]),
        cleanup: Object.freeze(
          uninstall.actions.map(({ action, kind }) => Object.freeze({ action, kind })),
        ),
      }),
    };
  }
  const fixture = await inspectFixture(context);
  const live = await planLiveGateway(reconciliationContext(context));
  const planSafety = await assertSafeCanaryPlan(live, context, {
    pendingPortalCreateRecoveryReceiptChecksum,
  });
  const approvalId = await stableId('canary-lifecycle', {
    operation: 'apply_verify_uninstall',
    planId: live.plan.planId,
    targetConfirmationId,
    fixture,
    cleanupOrder: REVERSE_ORDER,
    updateRecoveryReceiptChecksum: planSafety.updateRecoveryReceiptChecksum,
    pendingPortalCreateRecoveryReceiptChecksum:
      planSafety.pendingPortalCreateRecoveryReceiptChecksum,
  });

  const report = Object.freeze({
    schemaVersion: 1,
    kind: 'cloudflare_canary_lifecycle_preview',
    operation: 'apply_verify_uninstall',
    ready: true,
    writesPerformed: false,
    approvalId,
    targetConfirmationId,
    changes: Object.freeze(
      live.plan.changes.map(({ action, kind }) => Object.freeze({ action, kind })),
    ),
    cleanup: Object.freeze(
      REVERSE_ORDER.map((kind) => Object.freeze({ action: 'delete', kind })),
    ),
  });
  return {
    operation: 'apply_verify_uninstall',
    report,
    planId: live.plan.planId,
    installationId: live.plan.installationId,
    desiredHash: live.plan.desiredHash,
    pendingUpdateRecovery: planSafety.pendingUpdateRecovery,
    updateRecoveryReceiptChecksum: planSafety.updateRecoveryReceiptChecksum,
    pendingPortalCreateRecoveryReceiptChecksum:
      planSafety.pendingPortalCreateRecoveryReceiptChecksum,
  };
}

async function readCanaryRecovery(context) {
  let raw;
  try {
    raw = await context.receiptStore.read();
  } catch {
    throw new CanaryLifecycleError('plan_blocked');
  }
  if (!isObject(raw)) return null;
  assertNoLegacyGeneratedAppReceipt(raw);

  if (raw.state === 'ready' || raw.state === 'installing') {
    let receipt;
    try {
      receipt = await validateInstallationReceipt(raw);
    } catch {
      throw new CanaryLifecycleError('plan_blocked');
    }
    if (
      receipt.pending?.type === 'apply' &&
      receipt.pending.action === 'create' &&
      receipt.pending.kind === 'portal'
    ) {
      return { type: 'pending_portal_create', receipt };
    }
    if (receipt.pending === null) {
      return readPartialCleanupRecovery(context, receipt);
    }
    return null;
  }
  if (!['removed', 'uninstalling'].includes(raw.state)) return null;

  let receipt;
  let rawSnapshot;
  try {
    receipt = await validateInstallationReceipt(raw);
    rawSnapshot = await context.cleanupStore.read();
  } catch {
    throw new CanaryLifecycleError('plan_blocked');
  }
  assertNoLegacyGeneratedAppReceipt(rawSnapshot);
  let snapshot;
  try {
    snapshot = await validateInstallationReceipt(rawSnapshot);
  } catch {
    throw new CanaryLifecycleError('plan_blocked');
  }
  if (
    !sameCanaryTarget(receipt.target, snapshot.target, context) ||
    !isStrictCanarySnapshot(snapshot.resources) ||
    receipt.installationId !== snapshot.installationId
  ) {
    throw new CanaryLifecycleError('plan_blocked');
  }
  if (receipt.state === 'removed') {
    if (receipt.resources.length !== 0) throw new CanaryLifecycleError('plan_blocked');
    return { type: 'removed', removed: receipt, snapshot };
  }
  if (receipt.pending?.type === 'uninstall') {
    return { type: 'uninstalling', receipt, snapshot };
  }
  if (receipt.pending === null) {
    return receipt.resources.length === 0
      ? { type: 'uninstall_exhausted', receipt, snapshot }
      : { type: 'uninstalling', receipt, snapshot };
  }
  throw new CanaryLifecycleError('plan_blocked');
}

async function readPartialCleanupRecovery(context, receipt) {
  if (
    receipt.state !== 'ready' ||
    receipt.pending !== null ||
    receipt.release !== RELEASE ||
    !isExactPostRollbackResourcePrefix(receipt.resources) ||
    !sameReceiptTarget(receipt.target, context) ||
    !isStrictCanarySnapshot(receipt.resources)
  ) {
    return null;
  }

  let rawSnapshot;
  try {
    rawSnapshot = await context.cleanupStore.read();
  } catch {
    throw new CanaryLifecycleError('plan_blocked');
  }
  if (rawSnapshot === null) {
    return await isLegacyPostRollbackReceipt(receipt, context)
      ? { type: 'partial_install_cleanup', receipt, snapshot: receipt, bootstrap: true }
      : null;
  }

  assertNoLegacyGeneratedAppReceipt(rawSnapshot);
  let snapshot;
  try {
    snapshot = await validateInstallationReceipt(rawSnapshot);
  } catch {
    throw new CanaryLifecycleError('plan_blocked');
  }
  const snapshotProvesRollback =
    snapshot.state === 'installing' &&
    snapshot.pending?.type === 'apply' &&
    snapshot.pending.action === 'create' &&
    snapshot.pending.kind === 'portal' &&
    receipt.revision === snapshot.revision + 1 &&
    await isExactPendingPortalMarker(snapshot, context);
  const snapshotProvesCleanupStarted =
    snapshot.checksum === receipt.checksum &&
    snapshot.pending === null;
  if (
    (!snapshotProvesRollback && !snapshotProvesCleanupStarted) ||
    snapshot.installationId !== receipt.installationId ||
    snapshot.release !== receipt.release ||
    snapshot.desiredHash !== receipt.desiredHash ||
    !sameAccessPolicy(snapshot.accessPolicy, receipt.accessPolicy) ||
    !sameCanaryTarget(receipt.target, snapshot.target, context) ||
    !sameReceiptResourceSet(receipt.resources, snapshot.resources)
  ) {
    throw new CanaryLifecycleError('plan_blocked');
  }
  return { type: 'partial_install_cleanup', receipt, snapshot, bootstrap: false };
}

async function isLegacyPostRollbackReceipt(receipt, context) {
  const portalIndex = EXPECTED_ORDER.indexOf('portal');
  if (!(receipt.state === 'ready' &&
    receipt.revision === (portalIndex * 2) + 2 &&
    isExactPostRollbackResourcePrefix(receipt.resources))) return false;
  let desired;
  try {
    desired = await buildDesiredForReceipt(receipt, context);
  } catch {
    return false;
  }
  return desired.installationId === receipt.installationId &&
    desired.desiredHash !== receipt.desiredHash &&
    sameAccessPolicy(desired.accessPolicy, receipt.accessPolicy) &&
    receipt.resources.every((resource, index) => {
      const expected = desired.resources[index];
      return expected?.kind === resource.kind &&
        expected.key === resource.key &&
        expected.desiredHash === resource.desiredHash;
    });
}

async function isExactPendingPortalMarker(receipt, context) {
  let desired;
  try {
    desired = await buildDesiredForReceipt(receipt, context);
  } catch {
    return false;
  }
  const portal = desired.resources.find(({ kind }) => kind === 'portal');
  return desired.installationId === receipt.installationId &&
    sameAccessPolicy(desired.accessPolicy, receipt.accessPolicy) &&
    portal?.key === receipt.pending?.key &&
    portal.desiredHash === receipt.pending.expectedDesiredHash;
}

async function buildTargetConfirmationId(context) {
  return stableId('canary-target', {
    operation: 'confirm_disposable_target',
    accountId: context.accountId,
    zoneId: context.zoneId,
    hostname: context.hostname,
  });
}

async function verifyRemovedCanaryResidue(context, recoveryReceipt) {
  const residue = await pollBounded({
    probe: (signal) => context.inspectCanaryResidue({
      config: context.config,
      target: { accountId: context.accountId, zoneId: context.zoneId },
      receipt: recoveryReceipt,
      signal,
    }),
    accept: validResidueEvidence,
    sleep: context.sleep,
    attemptTimeoutMs: context.pollAttemptTimeoutMs,
    overallTimeoutMs: context.pollOverallTimeoutMs,
    returnLast: true,
  });
  if (!residueIsEmpty(residue)) {
    throw new CanaryLifecycleError('residue_detected', { cleanup: { status: 'removed' } });
  }
  emit(context, { stage: 'uninstall', status: 'verified' });
  return Object.freeze({
    schemaVersion: 1,
    kind: 'cloudflare_canary_lifecycle_result',
    status: 'verification_pending',
    resourceLifecycle: 'removed',
    interactiveVerification: 'pending',
    writesPerformed: false,
    installedStateVerified: false,
    portalToolCallVerified: false,
    idempotentApplyVerified: false,
    cleanup: Object.freeze({
      status: 'removed',
      reverseOrderVerified: true,
      ownedResourceCount: 0,
      recoveredAfterTombstone: true,
    }),
  });
}

async function resumeInterruptedUninstall(context, reconcileContext) {
  const cleanup = await cleanupCanary(context, reconcileContext);
  if (cleanup.status !== 'removed') {
    throw new CanaryLifecycleError('cleanup_failed', { cleanup });
  }
  if (!residueIsEmpty(cleanup.residue)) {
    throw new CanaryLifecycleError('residue_detected', { cleanup });
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: 'cloudflare_canary_lifecycle_result',
    status: 'verification_pending',
    resourceLifecycle: 'removed',
    interactiveVerification: 'pending',
    writesPerformed: true,
    installedStateVerified: false,
    portalToolCallVerified: false,
    idempotentApplyVerified: false,
    cleanup: Object.freeze({
      status: 'removed',
      reverseOrderVerified: cleanup.reverseOrderVerified,
      ownedResourceCount: 0,
      recoveredInterruptedUninstall: true,
    }),
  });
}

async function inspectFixture(context) {
  let evidence;
  try {
    evidence = await context.inspectSyntheticUpstream({
      endpoint: context.syntheticMcpUrl,
      expectedTool: CANARY_TOOL_NAME,
    });
  } catch {
    throw new CanaryLifecycleError('synthetic_upstream_invalid');
  }
  if (!validFixtureEvidence(evidence)) {
    throw new CanaryLifecycleError('synthetic_upstream_invalid');
  }
  return {
    fixture: CANARY_FIXTURE_ID,
    schemaVersion: 1,
    toolNames: [CANARY_TOOL_NAME],
    callVerified: true,
  };
}

function validFixtureEvidence(value) {
  return isObject(value) &&
    value.fixture === CANARY_FIXTURE_ID &&
    value.schemaVersion === 1 &&
    value.callVerified === true &&
    Array.isArray(value.toolNames) &&
    value.toolNames.length === 1 &&
    value.toolNames[0] === CANARY_TOOL_NAME;
}

function validInstalledVerification(value) {
  return isObject(value) &&
    value.ready === true &&
    value.fixture === CANARY_FIXTURE_ID &&
    value.toolName === CANARY_TOOL_NAME;
}

async function cleanupCanary(context, reconcileContext, expectedApproval = null) {
  try {
    emit(context, { stage: 'uninstall', status: 'started' });
    const currentReceipt = await validateInstallationReceipt(
      await context.receiptStore.read(),
    );
    const preview = await planGatewayUninstall(reconcileContext);
    if (expectedApproval !== null) {
      if (
        !matchesExpectedCleanupApproval(currentReceipt, preview, expectedApproval) ||
        !await matchesExpectedCleanupProvenance(context, expectedApproval)
      ) {
        return { status: 'blocked', reverseOrderVerified: false };
      }
    }
    const exhausted =
      currentReceipt.state === 'uninstalling' &&
      currentReceipt.pending === null &&
      currentReceipt.resources.length === 0;
    if (
      preview.blockers.length > 0 ||
      !validReverseCleanup(preview.actions, { allowEmpty: exhausted })
    ) {
      return { status: 'blocked', reverseOrderVerified: false };
    }
    let recoveryReceipt;
    if (
      currentReceipt.state === 'ready' ||
      (currentReceipt.state === 'installing' && currentReceipt.pending === null)
    ) {
      if (!isStrictCanarySnapshot(currentReceipt.resources)) {
        return { status: 'blocked', reverseOrderVerified: false };
      }
      recoveryReceipt = currentReceipt;
      await context.cleanupStore.writeAtomic(recoveryReceipt);
    } else if (currentReceipt.state === 'uninstalling') {
      recoveryReceipt = await validateInstallationReceipt(
        await context.cleanupStore.read(),
      );
      if (
        recoveryReceipt.installationId !== currentReceipt.installationId ||
        !sameCanaryTarget(currentReceipt.target, recoveryReceipt.target, context) ||
        !isStrictCanarySnapshot(recoveryReceipt.resources) ||
        !receiptResourcesAreExactSubset(
          currentReceipt.resources,
          recoveryReceipt.resources,
        )
      ) {
        return { status: 'blocked', reverseOrderVerified: false };
      }
    } else {
      return { status: 'blocked', reverseOrderVerified: false };
    }
    const approvedUninstallId = expectedApproval?.approvedUninstallId ?? (
      currentReceipt.pending?.type === 'uninstall'
        ? currentReceipt.pending.planId
        : preview.uninstallId
    );
    const removed = await uninstallGateway({
      ...reconcileContext,
      approvedUninstallId,
    });
    if (removed.status !== 'removed' || removed.receipt?.state !== 'removed') {
      return { status: 'incomplete', reverseOrderVerified: true };
    }

    const residue = await pollBounded({
      probe: (signal) => context.inspectCanaryResidue({
        config: context.config,
        target: { accountId: context.accountId, zoneId: context.zoneId },
        receipt: recoveryReceipt,
        signal,
      }),
      accept: validResidueEvidence,
      sleep: context.sleep,
      attemptTimeoutMs: context.pollAttemptTimeoutMs,
      overallTimeoutMs: context.pollOverallTimeoutMs,
      returnLast: true,
    });
    emit(context, { stage: 'uninstall', status: 'verified' });
    return {
      status: 'removed',
      reverseOrderVerified: true,
      residue,
    };
  } catch {
    return { status: 'failed', reverseOrderVerified: false };
  }
}

function matchesExpectedCleanupApproval(receipt, preview, expected) {
  return isObject(expected) &&
    typeof expected.expectedReceiptChecksum === 'string' &&
    typeof expected.approvedUninstallId === 'string' &&
    Array.isArray(expected.expectedUninstallActions) &&
    receipt.state === 'ready' &&
    receipt.pending === null &&
    receipt.checksum === expected.expectedReceiptChecksum &&
    preview.installationId === receipt.installationId &&
    preview.uninstallId === expected.approvedUninstallId &&
    sameUninstallActions(preview.actions, expected.expectedUninstallActions);
}

async function matchesExpectedCleanupProvenance(context, expected) {
  if (typeof expected.expectedProvenanceSnapshotChecksum !== 'string') return false;
  let raw;
  try {
    raw = await context.cleanupStore.read();
  } catch {
    return false;
  }
  if (raw === null) {
    return expected.expectedProvenanceSnapshotChecksum === expected.expectedReceiptChecksum;
  }
  try {
    const snapshot = await validateInstallationReceipt(raw);
    return snapshot.checksum === expected.expectedProvenanceSnapshotChecksum;
  } catch {
    return false;
  }
}

function sameUninstallActions(left, right) {
  return Array.isArray(left) &&
    Array.isArray(right) &&
    left.length === right.length &&
    left.every((action, index) =>
      action?.action === right[index]?.action &&
      action?.kind === right[index]?.kind &&
      action?.key === right[index]?.key &&
      (action?.reason ?? '') === (right[index]?.reason ?? ''));
}

function validReverseCleanup(actions, { allowEmpty = false } = {}) {
  if (
    !Array.isArray(actions) ||
    (!allowEmpty && actions.length === 0) ||
    actions.length > REVERSE_ORDER.length
  ) {
    return false;
  }
  if (actions.length === 0) return true;
  const indexes = actions.map((action) => REVERSE_ORDER.indexOf(action?.kind));
  return actions.every((action, index) =>
    isObject(action) &&
    (action.action === 'delete' || action.action === 'noop') &&
    indexes[index] !== -1 &&
    (index === 0 || indexes[index - 1] < indexes[index]));
}

function validResidueEvidence(value) {
  return isObject(value) &&
    Number.isSafeInteger(value.ownedResourceCount) &&
    value.ownedResourceCount >= 0;
}

async function pollBounded({
  probe,
  accept,
  sleep,
  attemptTimeoutMs,
  overallTimeoutMs,
  returnLast = false,
}) {
  let last;
  const startedAt = Date.now();
  for (let attempt = 1; attempt <= POLL_ATTEMPTS; attempt += 1) {
    const remaining = overallTimeoutMs - (Date.now() - startedAt);
    if (remaining <= 0) break;
    try {
      last = await withDeadline(
        (signal) => probe(signal),
        Math.min(attemptTimeoutMs, remaining),
      );
      if (accept(last)) {
        if (!returnLast || residueIsEmpty(last)) return last;
      }
    } catch {
      last = undefined;
    }
    if (attempt < POLL_ATTEMPTS) {
      const sleepRemaining = overallTimeoutMs - (Date.now() - startedAt);
      if (sleepRemaining <= 0) break;
      try {
        await withDeadline(
          () => sleep(Math.min(POLL_INTERVAL_MS, sleepRemaining)),
          Math.min(attemptTimeoutMs, sleepRemaining),
        );
      } catch {
        break;
      }
    }
  }
  if (returnLast && validResidueEvidence(last)) return last;
  throw new CanaryLifecycleError('verification_failed');
}

async function withDeadline(operation, timeoutMs) {
  const controller = new AbortController();
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(() => operation(controller.signal)),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new CanaryLifecycleError('verification_failed'));
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function residueIsEmpty(value) {
  return validResidueEvidence(value) &&
    value.ownedResourceCount === 0;
}

function requireContext(input, dependencies, { mutations }) {
  requireExactObject(input, [
    'accountId',
    'zoneId',
    'hostname',
    'syntheticMcpUrl',
    'allowedEmail',
    ...(mutations ? ['approvalId', 'targetConfirmationId'] : []),
  ]);
  requireExactObject(dependencies, [
    'cloudflare',
    'provider',
    'receiptStore',
    'cleanupStore',
    'inspectSyntheticUpstream',
    'verifyInstalledGateway',
    'holdForInspection',
    'inspectCanaryResidue',
    'sleep',
    'pollAttemptTimeoutMs',
    'pollOverallTimeoutMs',
    'inspectionHoldTimeoutMs',
    'onProgress',
  ]);
  try {
    validateCloudflareId(input.accountId, 'account');
    validateCloudflareId(input.zoneId, 'zone');
  } catch {
    throw new CanaryLifecycleError('invalid_input');
  }
  let hostname;
  try {
    hostname = validateHostname(input.hostname);
  } catch {
    throw new CanaryLifecycleError('invalid_input');
  }
  if (!/^ankka-canary(?:-[a-z0-9-]+)?$/.test(hostname.split('.')[0])) {
    throw new CanaryLifecycleError('invalid_input');
  }
  const syntheticMcpUrl = normalizeSyntheticUrl(input.syntheticMcpUrl);
  const allowedEmail = normalizeEmail(input.allowedEmail);
  requireCloudflare(dependencies.cloudflare);
  requireProvider(dependencies.provider, mutations);
  requireReceiptStore(dependencies.receiptStore, mutations);
  requireReceiptStore(dependencies.cleanupStore, mutations);
  if (typeof dependencies.inspectSyntheticUpstream !== 'function') {
    throw new CanaryLifecycleError('invalid_input');
  }
  if (mutations && typeof dependencies.inspectCanaryResidue !== 'function') {
    throw new CanaryLifecycleError('invalid_input');
  }
  if (
    dependencies.verifyInstalledGateway !== undefined &&
    typeof dependencies.verifyInstalledGateway !== 'function'
  ) {
    throw new CanaryLifecycleError('invalid_input');
  }
  if (
    dependencies.holdForInspection !== undefined &&
    typeof dependencies.holdForInspection !== 'function'
  ) {
    throw new CanaryLifecycleError('invalid_input');
  }
  if (mutations && (
    typeof input.approvalId !== 'string' ||
    typeof input.targetConfirmationId !== 'string'
  )) {
    throw new CanaryLifecycleError('invalid_input');
  }
  const sleep = dependencies.sleep ?? ((milliseconds) =>
    new Promise((resolve) => setTimeout(resolve, milliseconds)));
  if (typeof sleep !== 'function') throw new CanaryLifecycleError('invalid_input');
  if (dependencies.onProgress !== undefined && typeof dependencies.onProgress !== 'function') {
    throw new CanaryLifecycleError('invalid_input');
  }
  const pollAttemptTimeoutMs = boundedTimeout(
    dependencies.pollAttemptTimeoutMs,
    POLL_ATTEMPT_TIMEOUT_MS,
  );
  const pollOverallTimeoutMs = boundedTimeout(
    dependencies.pollOverallTimeoutMs,
    POLL_OVERALL_TIMEOUT_MS,
  );
  const inspectionHoldTimeoutMs = boundedTimeout(
    dependencies.inspectionHoldTimeoutMs,
    INSPECTION_HOLD_TIMEOUT_MS,
  );
  const config = fixedCanaryConfig(hostname, syntheticMcpUrl);
  return {
    accountId: input.accountId.toLowerCase(),
    zoneId: input.zoneId.toLowerCase(),
    hostname,
    syntheticMcpUrl,
    allowedEmail,
    config,
    cloudflare: dependencies.cloudflare,
    provider: dependencies.provider,
    receiptStore: dependencies.receiptStore,
    cleanupStore: dependencies.cleanupStore,
    inspectSyntheticUpstream: dependencies.inspectSyntheticUpstream,
    verifyInstalledGateway: dependencies.verifyInstalledGateway,
    holdForInspection: dependencies.holdForInspection,
    inspectCanaryResidue: dependencies.inspectCanaryResidue,
    sleep,
    pollAttemptTimeoutMs,
    pollOverallTimeoutMs,
    inspectionHoldTimeoutMs,
    onProgress: dependencies.onProgress ?? null,
  };
}

function reconciliationContext(context, hooks = {}) {
  return {
    config: context.config,
    target: { accountId: context.accountId, zoneId: context.zoneId },
    access: { allowedEmails: [context.allowedEmail] },
    release: RELEASE,
    provider: context.provider,
    receiptStore: context.receiptStore,
    onProgress(event) {
      if (
        event?.stage === 'apply' &&
        event?.status === 'verifying' &&
        typeof hooks.onApplyMutationSubmitted === 'function'
      ) {
        hooks.onApplyMutationSubmitted();
      }
      emit(context, {
        stage: safeStage(event?.stage),
        action: safeAction(event?.action),
        kind: safeKind(event?.kind),
        status: safeStatus(event?.status),
      });
    },
  };
}

function fixedCanaryConfig(hostname, syntheticMcpUrl) {
  return {
    schemaVersion: 1,
    gateway: {
      name: 'Ankka disposable canary',
      hostname,
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
      url: syntheticMcpUrl,
      authentication: { mode: 'none', onBehalfOfUser: false },
      enabledTools: [CANARY_TOOL_NAME],
    }],
  };
}

async function persistPartialCleanupMarker(context, previewReceipt) {
  const receipt = await validateInstallationReceipt(previewReceipt);
  const current = await validateInstallationReceipt(await context.receiptStore.read());
  if (
    current.checksum !== receipt.checksum ||
    receipt.state !== 'installing' ||
    receipt.pending?.type !== 'apply' ||
    receipt.pending.action !== 'create' ||
    receipt.pending.kind !== 'portal' ||
    receipt.release !== RELEASE ||
    !sameReceiptTarget(receipt.target, context) ||
    !isExactPostRollbackResourcePrefix(receipt.resources) ||
    !isStrictCanarySnapshot(receipt.resources)
  ) {
    throw new CanaryLifecycleError('plan_blocked');
  }

  const desired = await buildDesiredForReceipt(receipt, context);
  const desiredPortal = desired.resources.find(({ kind }) => kind === 'portal');
  if (
    desired.installationId !== receipt.installationId ||
    !sameAccessPolicy(desired.accessPolicy, receipt.accessPolicy) ||
    desiredPortal?.key !== receipt.pending.key ||
    desiredPortal.desiredHash !== receipt.pending.expectedDesiredHash
  ) {
    throw new CanaryLifecycleError('plan_blocked');
  }

  const existing = await context.cleanupStore.read();
  if (existing !== null) {
    const snapshot = await validateInstallationReceipt(existing);
    if (snapshot.checksum !== receipt.checksum) {
      throw new CanaryLifecycleError('plan_blocked');
    }
    return;
  }
  await context.cleanupStore.writeAtomic(receipt);
}

async function assertExactPartialCleanupPlan(value, receipt, context) {
  const plan = value?.plan;
  if (
    !isObject(plan) ||
    receipt.state !== 'ready' ||
    receipt.pending !== null ||
    receipt.release !== RELEASE ||
    !sameReceiptTarget(receipt.target, context) ||
    !isExactPostRollbackResourcePrefix(receipt.resources) ||
    !isStrictCanarySnapshot(receipt.resources) ||
    !Array.isArray(plan.blockers) ||
    plan.blockers.length !== 0 ||
    !Array.isArray(plan.changes) ||
    plan.changes.length !== EXPECTED_ORDER.length ||
    value.pruneApprovalId !== null ||
    !isObject(value.pruneSummary) ||
    value.pruneSummary.remoteDeleteCount !== 0 ||
    value.pruneSummary.receiptRetirementCount !== 0 ||
    !Array.isArray(value.pruneSummary.actions) ||
    value.pruneSummary.actions.length !== 0
  ) {
    throw new CanaryLifecycleError('plan_blocked');
  }

  let desired;
  try {
    desired = await buildDesiredForReceipt(receipt, context);
  } catch {
    throw new CanaryLifecycleError('plan_blocked');
  }
  if (
    plan.installationId !== receipt.installationId ||
    plan.installationId !== desired.installationId ||
    plan.desiredHash !== desired.desiredHash ||
    plan.release !== RELEASE ||
    !sameAccessPolicy(receipt.accessPolicy, desired.accessPolicy)
  ) {
    throw new CanaryLifecycleError('plan_blocked');
  }

  for (let index = 0; index < EXPECTED_ORDER.length; index += 1) {
    const kind = EXPECTED_ORDER[index];
    const desiredResource = desired.resources.find((resource) => resource.kind === kind);
    const change = plan.changes[index];
    if (
      !desiredResource ||
      change?.kind !== kind ||
      change.key !== desiredResource.key ||
      change.desiredHash !== desiredResource.desiredHash
    ) {
      throw new CanaryLifecycleError('plan_blocked');
    }
    if (index < EXPECTED_ORDER.indexOf('portal')) {
      const owned = receipt.resources[index];
      if (
        change.action !== 'noop' ||
        owned.kind !== kind ||
        owned.key !== desiredResource.key ||
        owned.desiredHash !== desiredResource.desiredHash ||
        !sameProviderLocator(owned.provider, change.provider)
      ) {
        throw new CanaryLifecycleError('plan_blocked');
      }
    } else if (
      change.action !== 'create' ||
      change.provider !== undefined
    ) {
      throw new CanaryLifecycleError('plan_blocked');
    }
  }
}

function assertExactPartialCleanupUninstall(uninstall, receipt) {
  const expected = [...receipt.resources]
    .sort((left, right) => EXPECTED_ORDER.indexOf(right.kind) - EXPECTED_ORDER.indexOf(left.kind));
  if (
    !isObject(uninstall) ||
    uninstall.installationId !== receipt.installationId ||
    !Array.isArray(uninstall.blockers) ||
    uninstall.blockers.length !== 0 ||
    !Array.isArray(uninstall.actions) ||
    uninstall.actions.length !== expected.length ||
    uninstall.actions.some((action, index) =>
      action?.action !== 'delete' ||
      action.kind !== expected[index].kind ||
      action.key !== expected[index].key ||
      action.reason !== undefined)
  ) {
    throw new CanaryLifecycleError('plan_blocked');
  }
}

async function buildDesiredForReceipt(receipt, context) {
  return buildGatewayDesiredState(context.config, {
    target: {
      accountId: context.accountId,
      zoneId: context.zoneId,
      zoneName: receipt.target.zoneName,
      zoneStatus: 'active',
      zeroTrustReady: true,
    },
    access: { allowedEmails: [context.allowedEmail] },
  });
}

function copyReceiptResourceFingerprint(resource) {
  return {
    kind: resource.kind,
    key: resource.key,
    provider: { ...resource.provider },
    desiredHash: resource.desiredHash,
    ...(resource.marker !== undefined ? { marker: resource.marker } : {}),
    ...(resource.identityHash !== undefined ? { identityHash: resource.identityHash } : {}),
  };
}

function copyUninstallAction(action) {
  return {
    action: action.action,
    kind: action.kind,
    key: action.key,
    ...(action.reason !== undefined ? { reason: action.reason } : {}),
  };
}

async function assertSafeCanaryPlan(value, context, {
  pendingPortalCreateRecoveryReceiptChecksum = null,
} = {}) {
  const plan = value?.plan;
  if (
    !isObject(plan) ||
    !Array.isArray(plan.blockers) ||
    plan.blockers.length !== 0 ||
    !Array.isArray(plan.changes) ||
    plan.changes.length !== EXPECTED_ORDER.length ||
    plan.changes.some((change, index) =>
      change?.kind !== EXPECTED_ORDER[index] ||
      !['create', 'update', 'noop'].includes(change.action)) ||
    value.pruneApprovalId !== null ||
    !isObject(value.pruneSummary) ||
    value.pruneSummary.remoteDeleteCount !== 0 ||
    value.pruneSummary.receiptRetirementCount !== 0 ||
    !Array.isArray(value.pruneSummary.actions) ||
    value.pruneSummary.actions.length !== 0
  ) {
    throw new CanaryLifecycleError('plan_blocked');
  }

  if (pendingPortalCreateRecoveryReceiptChecksum !== null) {
    let receipt;
    try {
      receipt = await validateInstallationReceipt(await context.receiptStore.read());
    } catch {
      throw new CanaryLifecycleError('plan_blocked');
    }
    if (
      receipt.checksum !== pendingPortalCreateRecoveryReceiptChecksum ||
      !await isExactPendingPortalCreateNoopRecovery(value, receipt, context)
    ) {
      throw new CanaryLifecycleError('plan_blocked');
    }
    return {
      pendingUpdateRecovery: false,
      updateRecoveryReceiptChecksum: null,
      pendingPortalCreateRecoveryReceiptChecksum,
    };
  }

  const updates = plan.changes.filter(({ action }) => action === 'update');
  if (updates.length === 0) {
    return {
      pendingUpdateRecovery: false,
      updateRecoveryReceiptChecksum: null,
      pendingPortalCreateRecoveryReceiptChecksum: null,
    };
  }
  const observedChanges = plan.changes.filter(({ action }) => action !== 'create');

  let receipt;
  try {
    receipt = await validateInstallationReceipt(await context.receiptStore.read());
  } catch {
    throw new CanaryLifecycleError('plan_blocked');
  }
  const ordinaryOwnedUpdate = receipt.state === 'ready' && receipt.pending === null;
  const pendingOwnedUpdate =
    receipt.state === 'installing' &&
    receipt.pending?.type === 'apply' &&
    receipt.pending.action === 'update' &&
    receipt.pending.planId === plan.planId &&
    updates.some((change) =>
      change.kind === receipt.pending.kind &&
      change.key === receipt.pending.key &&
      change.desiredHash === receipt.pending.expectedDesiredHash);
  if (
    (!ordinaryOwnedUpdate && !pendingOwnedUpdate) ||
    receipt.installationId !== plan.installationId ||
    receipt.release !== RELEASE ||
    receipt.desiredHash !== plan.desiredHash ||
    receipt.target.accountId !== context.accountId ||
    receipt.target.zoneId !== context.zoneId ||
    receipt.target.hostname !== context.hostname ||
    observedChanges.some((change) => {
      const owned = receipt.resources.find((resource) =>
        resource.kind === change.kind && resource.key === change.key);
      return !owned ||
        owned.desiredHash !== change.desiredHash ||
        !sameProviderLocator(owned.provider, change.provider);
    })
  ) {
    throw new CanaryLifecycleError('plan_blocked');
  }
  return {
    pendingUpdateRecovery: pendingOwnedUpdate,
    updateRecoveryReceiptChecksum: receipt.checksum,
    pendingPortalCreateRecoveryReceiptChecksum: null,
  };
}

async function isExactPendingPortalCreateNoopRecovery(value, receipt, context) {
  const plan = value?.plan;
  const pending = receipt?.pending;
  if (
    receipt?.state !== 'installing' ||
    pending?.type !== 'apply' ||
    pending.action !== 'create' ||
    pending.kind !== 'portal' ||
    receipt.release !== RELEASE ||
    receipt.installationId !== plan?.installationId ||
    receipt.target.accountId !== context.accountId ||
    receipt.target.zoneId !== context.zoneId ||
    receipt.target.hostname !== context.hostname ||
    !Array.isArray(plan?.blockers) ||
    plan.blockers.length !== 0 ||
    !Array.isArray(plan.changes) ||
    plan.changes.length !== EXPECTED_ORDER.length
  ) {
    return false;
  }

  let desired;
  try {
    desired = await buildGatewayDesiredState(context.config, {
      target: {
        accountId: context.accountId,
        zoneId: context.zoneId,
        zoneName: receipt.target.zoneName,
        zoneStatus: 'active',
        zeroTrustReady: true,
      },
      access: { allowedEmails: [context.allowedEmail] },
    });
  } catch {
    return false;
  }
  if (
    desired.installationId !== receipt.installationId ||
    desired.desiredHash !== plan.desiredHash ||
    !sameAccessPolicy(desired.accessPolicy, receipt.accessPolicy)
  ) {
    return false;
  }

  const portalIndex = EXPECTED_ORDER.indexOf('portal');
  if (
    receipt.resources.length !== portalIndex ||
    receipt.resources.some((resource) =>
      EXPECTED_ORDER.indexOf(resource.kind) >= portalIndex)
  ) {
    return false;
  }
  for (let index = 0; index < portalIndex; index += 1) {
    const desiredResource = desired.resources.find(({ kind }) => kind === EXPECTED_ORDER[index]);
    const change = plan.changes[index];
    const owned = receipt.resources.find((resource) =>
      resource.kind === desiredResource?.kind && resource.key === desiredResource?.key);
    if (
      !desiredResource ||
      change?.kind !== desiredResource.kind ||
      change.key !== desiredResource.key ||
      change.action !== 'noop' ||
      change.desiredHash !== desiredResource.desiredHash ||
      !owned ||
      owned.desiredHash !== desiredResource.desiredHash ||
      !sameProviderLocator(owned.provider, change.provider)
    ) {
      return false;
    }
  }

  const desiredPortal = desired.resources.find(({ kind }) => kind === 'portal');
  const portal = plan.changes[portalIndex];
  if (
    !desiredPortal ||
    portal?.kind !== 'portal' ||
    portal.key !== pending.key ||
    portal.action !== 'noop' ||
    portal.desiredHash !== pending.expectedDesiredHash ||
    portal.desiredHash !== desiredPortal.desiredHash ||
    portal.provider?.id !== portal.key
  ) {
    return false;
  }
  return plan.changes.slice(portalIndex + 1).every((change, offset) =>
    change.kind === EXPECTED_ORDER[portalIndex + 1 + offset] &&
    change.action === 'create' &&
    change.provider === undefined);
}

function sameAccessPolicy(left, right) {
  return isObject(left) &&
    isObject(right) &&
    left.identityType === right.identityType &&
    left.identityCount === right.identityCount &&
    left.identitiesHash === right.identitiesHash;
}

async function pendingUpdateRecoveryWasCommitted(context, preview) {
  let receipt;
  try {
    receipt = await validateInstallationReceipt(await context.receiptStore.read());
  } catch {
    return false;
  }
  return receipt.checksum !== preview.updateRecoveryReceiptChecksum &&
    receipt.state === 'ready' &&
    receipt.pending === null &&
    receipt.installationId === preview.installationId &&
    receipt.desiredHash === preview.desiredHash &&
    receipt.release === RELEASE &&
    receipt.target.accountId === context.accountId &&
    receipt.target.zoneId === context.zoneId &&
    receipt.target.hostname === context.hostname;
}

function sameProviderLocator(left, right) {
  return isObject(left) &&
    isObject(right) &&
    left.id === right.id &&
    (left.parentId ?? '') === (right.parentId ?? '');
}

function normalizeSyntheticUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new CanaryLifecycleError('invalid_input');
  }
  const hostname = url.hostname.toLowerCase();
  const quickTunnel = isQuickTunnelHostname(hostname);
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== '/mcp' ||
    (!hostname.includes('canary') && !quickTunnel)
  ) {
    throw new CanaryLifecycleError('invalid_input');
  }
  return url.toString();
}

function isQuickTunnelHostname(hostname) {
  const labels = hostname.split('.');
  return labels.length === 3 &&
    labels[1] === 'trycloudflare' &&
    labels[2] === 'com' &&
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(labels[0]);
}

function normalizeEmail(value) {
  if (typeof value !== 'string') throw new CanaryLifecycleError('invalid_input');
  const normalized = value.trim().toLowerCase();
  if (normalized.length === 0 || normalized.length > 254 || !EMAIL.test(normalized)) {
    throw new CanaryLifecycleError('invalid_input');
  }
  return normalized;
}

function boundedTimeout(value, maximum) {
  if (value === undefined) return maximum;
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new CanaryLifecycleError('invalid_input');
  }
  return value;
}

function sameCanaryTarget(removed, snapshot, context) {
  return removed.accountId === context.accountId &&
    removed.zoneId === context.zoneId &&
    removed.hostname === context.hostname &&
    snapshot.accountId === context.accountId &&
    snapshot.zoneId === context.zoneId &&
    snapshot.hostname === context.hostname &&
    removed.zoneName === snapshot.zoneName;
}

function sameReceiptTarget(target, context) {
  return isObject(target) &&
    target.accountId === context.accountId &&
    target.zoneId === context.zoneId &&
    target.hostname === context.hostname;
}

function sameReceiptResourceSet(left, right) {
  return Array.isArray(left) &&
    Array.isArray(right) &&
    left.length === right.length &&
    receiptResourcesAreExactSubset(left, right) &&
    receiptResourcesAreExactSubset(right, left);
}

function isExactPostRollbackResourcePrefix(resources) {
  const prefixLength = EXPECTED_ORDER.indexOf('portal');
  return Array.isArray(resources) &&
    resources.length === prefixLength &&
    resources.every((resource, index) => resource?.kind === EXPECTED_ORDER[index]);
}

function receiptResourcesAreExactSubset(current, snapshot) {
  if (
    !Array.isArray(current) ||
    !Array.isArray(snapshot) ||
    current.length > snapshot.length
  ) {
    return false;
  }
  return current.every((resource) => snapshot.some((candidate) =>
    resource.kind === candidate.kind &&
    resource.key === candidate.key &&
    resource.desiredHash === candidate.desiredHash &&
    resource.marker === candidate.marker &&
    resource.identityHash === candidate.identityHash &&
    resource.provider?.id === candidate.provider?.id &&
    (resource.provider?.parentId ?? '') === (candidate.provider?.parentId ?? '')));
}

function isStrictCanarySnapshot(resources) {
  if (!(Array.isArray(resources) &&
    resources.length > 0 &&
    resources.length <= EXPECTED_ORDER.length &&
    resources.every((resource) => EXPECTED_ORDER.includes(resource?.kind)) &&
    new Set(resources.map(({ kind }) => kind)).size === resources.length)) return false;
  const sourceApplications = resources.filter((resource) =>
    resource.kind === 'source_access_application');
  const portalApplications = resources.filter((resource) =>
    resource.kind === 'portal_access_application');
  return resources.every((resource) => {
    if (resource.kind !== 'source_access_policy' && resource.kind !== 'portal_access_policy') {
      return true;
    }
    if (resource.kind === 'source_access_policy') {
      return sourceApplications.some((parent) =>
        parent.provider?.id === resource.provider?.parentId);
    }
    return portalApplications.some((parent) =>
      parent.provider?.id === resource.provider?.parentId);
  });
}

function assertNoLegacyGeneratedAppReceipt(value) {
  if (
    isObject(value) &&
    value.manager === 'ankka-mcp-gateway' &&
    Array.isArray(value.resources) &&
    value.resources.some((resource) =>
      isObject(resource) &&
      resource.kind === 'portal' &&
      Object.hasOwn(resource, 'generatedAccessAppId'))
  ) {
    throw new CanaryLifecycleError('legacy_manual_cleanup_required');
  }
}

function requireCloudflare(value) {
  const methods = [
    'getZone',
    'listIdentityProviders',
    'listMcpServers',
    'listPortals',
    'listAccessApps',
    'listDnsRecords',
  ];
  if (!isObject(value) || methods.some((method) => typeof value[method] !== 'function')) {
    throw new CanaryLifecycleError('invalid_input');
  }
}

function requireProvider(value, mutations) {
  if (!isObject(value) || typeof value.readObservedState !== 'function') {
    throw new CanaryLifecycleError('invalid_input');
  }
  if (mutations && typeof value.applyChange !== 'function') {
    throw new CanaryLifecycleError('invalid_input');
  }
}

function requireReceiptStore(value, mutations) {
  if (!isObject(value) || typeof value.read !== 'function' || typeof value.writeAtomic !== 'function') {
    throw new CanaryLifecycleError('invalid_input');
  }
  if (mutations && typeof value.withExclusiveLock !== 'function') {
    throw new CanaryLifecycleError('invalid_input');
  }
}

function requireExactObject(value, allowed) {
  if (!isObject(value) || Object.keys(value).some((key) => !allowed.includes(key))) {
    throw new CanaryLifecycleError('invalid_input');
  }
}

async function stableId(prefix, value) {
  if (!globalThis.crypto?.subtle) throw new CanaryLifecycleError('invalid_input');
  const bytes = new TextEncoder().encode(canonicalJson(value));
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  const hash = [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
  return `${prefix}-${hash.slice(0, 24)}`;
}

function canonicalJson(value) {
  if (value === null || ['boolean', 'string'].includes(typeof value)) return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isObject(value)) {
    return `{${Object.keys(value)
      .sort(compareText)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  throw new CanaryLifecycleError('invalid_input');
}

function normalizeLifecycleFailure(error) {
  return error instanceof CanaryLifecycleError ? error : new CanaryLifecycleError('lifecycle_failed');
}

function safeCleanupState(value) {
  const allowed = new Set([
    'not_started',
    'blocked',
    'blocked_pending_apply',
    'incomplete',
    'failed',
    'removed',
    'rollback_complete',
  ]);
  return allowed.has(value?.status) ? value.status : 'not_started';
}

async function hasPendingApply(receiptStore) {
  try {
    const receipt = await receiptStore.read();
    if (receipt === null) return false;
    const validated = await validateInstallationReceipt(receipt);
    return validated.pending?.type === 'apply';
  } catch {
    // An unreadable receipt can never authorize cleanup.
    return true;
  }
}

function emit(context, event) {
  if (!context.onProgress) return;
  const sanitized = {
    stage: safeStage(event.stage),
    status: safeStatus(event.status),
    ...(safeAction(event.action) ? { action: safeAction(event.action) } : {}),
    ...(safeKind(event.kind) ? { kind: safeKind(event.kind) } : {}),
  };
  try {
    context.onProgress(Object.freeze(sanitized));
  } catch {
    // Observational output cannot affect resource convergence.
  }
}

function safeStage(value) {
  return [
    'apply',
    'idempotency',
    'inspection',
    'synthetic_tool',
    'uninstall',
    'rollback',
    'lifecycle',
  ].includes(value)
    ? value
    : 'lifecycle';
}

function safeAction(value) {
  return ['create', 'update', 'delete'].includes(value) ? value : undefined;
}

function safeKind(value) {
  return EXPECTED_ORDER.includes(value) ? value : undefined;
}

function safeStatus(value) {
  return ['started', 'verifying', 'verified', 'failed'].includes(value) ? value : 'failed';
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
