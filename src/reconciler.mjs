import { buildGatewayDesiredState, buildGatewayPlan } from './plan.mjs';
import {
  beginReceiptAction,
  clearReceiptAction,
  commitReceiptAction,
  createInstallationReceipt,
  markReceiptRemoved,
  ownershipMarker,
  updateInstallationReceipt,
  validateInstallationReceipt,
} from './receipt.mjs';

const HASH_PREFIX = 'sha256:';
const SAFE_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const RESOURCE_KEY = /^[a-z][a-z0-9-]{0,31}$/;
const DESIRED_HASH = /^sha256:[0-9a-f]{64}$/;
const RESOURCE_ORDER = new Map([
  ['mcp_server', 0],
  ['source_access_application', 1],
  ['source_access_policy', 2],
  ['portal', 3],
  ['portal_access_application', 4],
  ['portal_access_policy', 5],
  ['dns_record', 6],
]);
const RESOURCE_KINDS = new Set(RESOURCE_ORDER.keys());

/** A deliberately body-free error safe to surface in a local or hosted installer. */
export class GatewayReconcileError extends Error {
  constructor(code) {
    const safeCode = typeof code === 'string' && SAFE_CODE.test(code) ? code : 'reconcile_failed';
    super(messageFor(safeCode));
    this.name = 'GatewayReconcileError';
    this.code = safeCode;
  }
}

/**
 * Read customer-owned live state and calculate a fresh, approval-ready plan.
 * The provider is injected; this module never reads tokens or environment variables.
 */
export async function planLiveGateway(input) {
  const context = requireContext(input, { mutations: false });
  const live = await readLive(context);
  const prune = await buildPruneApproval(live);
  return {
    plan: live.plan,
    ...publicPruneApproval(prune),
    receipt: live.receipt ? receiptSummary(live.receipt) : null,
    diagnostics: sanitizeDiagnostics(live.observed.diagnostics),
  };
}

/** Return a small status vocabulary without copying provider response bodies. */
export async function getGatewayStatus(input) {
  const context = requireContext(input, { mutations: false });
  const live = await readLive(context);
  const blockers = live.plan.blockers.map((blocker) => blocker.code);
  const actions = live.plan.changes.map((change) => change.action);
  const prune = await buildPruneApproval(live);
  let state = 'ready';

  if (live.receipt?.state === 'uninstalling') state = 'uninstalling';
  else if (live.receipt?.pending) state = 'recovering';
  else if (blockers.includes('resource_conflicts')) state = 'conflict';
  else if (blockers.length > 0) state = 'blocked';
  else if (actions.some((action) => action !== 'noop') || prune.actions.length > 0) state = 'drift';
  if (live.receipt?.state === 'removed') state = 'removed';

  return {
    state,
    planId: live.plan.planId,
    installationId: live.plan.installationId,
    desiredHash: live.plan.desiredHash,
    blockers,
    changes: summarizeChanges(live.plan.changes),
    ...publicPruneApproval(prune),
    diagnostics: sanitizeDiagnostics(live.observed.diagnostics),
    receipt: live.receipt
      ? { state: live.receipt.state, revision: live.receipt.revision }
      : null,
  };
}

/**
 * Execute an approved plan through an injected provider mutation adapter.
 * No Cloudflare mutation adapter is exported in the current canary slice.
 */
export async function applyGateway(input) {
  const context = requireContext(input, { mutations: true });
  return withReceiptLock(context, () => applyGatewayLocked(context));
}

/**
 * Build a destructive, receipt-bound recovery preview for the one supported
 * partial-create shape: a canary Portal POST whose generated Access app never
 * became visible. This is deliberately separate from normal apply/uninstall.
 */
export async function planPendingPortalCreateRollback(input) {
  const context = requirePendingPortalRollbackContext(input, { mutations: false });
  return publicPendingPortalRollbackPreview(
    await buildPendingPortalRollbackPreview(context),
  );
}

/**
 * Roll back one exactly proven pending Portal create, clear only that pending
 * journal entry after remote absence is proven, and stop for a fresh preview.
 */
export async function rollbackPendingPortalCreate(input) {
  const context = requirePendingPortalRollbackContext(input, { mutations: true });
  return withReceiptLock(context, () => rollbackPendingPortalCreateLocked(context));
}

async function rollbackPendingPortalCreateLocked(context) {
  const preview = await buildPendingPortalRollbackPreview(context);
  if (context.approvedRollbackId !== preview.rollbackId) {
    throw new GatewayReconcileError('rollback_approval_required');
  }

  let mutationResult;
  try {
    mutationResult = normalizePendingPortalRollbackMutationResult(
      await context.provider.rollbackPendingPortalCreate(preview.providerInput),
      preview.portal.key,
    );
  } catch {
    throw new GatewayReconcileError('mutation_failed');
  }
  if (!['rolled_back', 'already_absent'].includes(mutationResult.status)) {
    throw new GatewayReconcileError('verification_failed');
  }

  let verifiedEvidence;
  try {
    verifiedEvidence = normalizePendingPortalRollbackEvidence(
      await context.provider.inspectPendingPortalCreateRollback(preview.providerInput),
      preview.portal.key,
    );
  } catch {
    throw new GatewayReconcileError('verification_failed');
  }
  if (verifiedEvidence.status !== 'already_absent') {
    throw new GatewayReconcileError('verification_failed');
  }

  const stored = await readReceipt(context.receiptStore);
  const current = stored ? await validateReceiptSafe(stored) : null;
  if (!current || current.checksum !== preview.receipt.checksum) {
    throw new GatewayReconcileError('receipt_changed');
  }
  const cleared = await clearReceiptAction(current, preview.receipt.pending.operationId);
  await writeReceipt(context.receiptStore, cleared);
  return {
    status: 'rollback_complete',
    rollbackId: preview.rollbackId,
    receipt: receiptSummary(cleared),
  };
}

async function buildPendingPortalRollbackPreview(context) {
  const live = await readLive(context);
  const { receipt, plan } = live;
  const pending = receipt?.pending;
  if (
    receipt?.state !== 'installing' ||
    pending?.type !== 'apply' ||
    pending.action !== 'create' ||
    pending.kind !== 'portal'
  ) {
    throw new GatewayReconcileError('pending_conflict');
  }
  await assertPendingRequestHash(pending);
  if (
    receipt.release !== context.release ||
    receipt.installationId !== plan.installationId
  ) {
    throw new GatewayReconcileError('receipt_mismatch');
  }

  const desired = await buildGatewayDesiredState(context.config, {
    target: live.observed.target,
    access: context.access,
  });
  const portal = desired.resources.find((resource) =>
    resource.kind === 'portal' && resource.key === pending.key);
  if (
    !portal ||
    portal.desiredHash !== pending.expectedDesiredHash ||
    canonicalJson(desired.accessPolicy) !== canonicalJson(receipt.accessPolicy)
  ) {
    throw new GatewayReconcileError('pending_conflict');
  }

  assertPendingPortalRollbackTopology(plan, receipt, desired.resources, portal);
  const providerInput = {
    change: {
      action: 'create',
      kind: portal.kind,
      key: portal.key,
      desiredHash: portal.desiredHash,
      desired: structuredClone(portal.desired),
    },
    receipt,
    config: context.config,
    target: {
      ...context.target,
      zoneName: receipt.target.zoneName,
    },
    access: context.access,
  };

  let evidence;
  try {
    evidence = normalizePendingPortalRollbackEvidence(
      await context.provider.inspectPendingPortalCreateRollback(providerInput),
      portal.key,
    );
  } catch {
    throw new GatewayReconcileError('pending_conflict');
  }
  const portalChange = findChange(plan, portal.kind, portal.key);
  if (
    (evidence.status === 'ready' && portalChange?.action !== 'conflict') ||
    (evidence.status === 'already_absent' && portalChange?.action !== 'create')
  ) {
    throw new GatewayReconcileError('pending_conflict');
  }
  const blockerCodes = plan.blockers.map((blocker) => blocker.code);
  if (
    (evidence.status === 'ready' && (
      blockerCodes.length !== 1 || blockerCodes[0] !== 'resource_conflicts'
    )) ||
    (evidence.status === 'already_absent' && blockerCodes.length !== 0)
  ) {
    throw new GatewayReconcileError('plan_blocked');
  }

  const rollbackHash = await hashCanonical({
    schemaVersion: 1,
    operation: 'rollback_pending_portal_create',
    target: {
      accountId: receipt.target.accountId,
      zoneId: receipt.target.zoneId,
      hostname: receipt.target.hostname,
    },
    installationId: receipt.installationId,
    release: receipt.release,
    receiptDesiredHash: receipt.desiredHash,
    currentDesiredHash: plan.desiredHash,
    currentPlanId: plan.planId,
    receiptChecksum: receipt.checksum,
    pending: {
      operationId: pending.operationId,
      requestHash: pending.requestHash,
      type: pending.type,
      planId: pending.planId,
      action: pending.action,
      kind: pending.kind,
      key: pending.key,
      expectedDesiredHash: pending.expectedDesiredHash,
    },
    evidence,
  });
  return {
    rollbackId: `rollback-${rollbackHash.slice(HASH_PREFIX.length, HASH_PREFIX.length + 24)}`,
    receipt,
    portal,
    evidence,
    providerInput,
  };
}

function assertPendingPortalRollbackTopology(plan, receipt, desiredResources, portal) {
  const portalRank = RESOURCE_ORDER.get('portal');
  const lowerDesired = desiredResources.filter((resource) =>
    RESOURCE_ORDER.get(resource.kind) < portalRank);
  if (
    receipt.resources.length !== lowerDesired.length ||
    receipt.resources.some((resource) => RESOURCE_ORDER.get(resource.kind) >= portalRank) ||
    plan.changes.length !== desiredResources.length
  ) {
    throw new GatewayReconcileError('pending_conflict');
  }
  for (const dependency of lowerDesired) {
    const owned = findReceiptResource(receipt, dependency.kind, dependency.key);
    const change = findChange(plan, dependency.kind, dependency.key);
    if (
      !owned ||
      change?.action !== 'noop' ||
      owned.desiredHash !== dependency.desiredHash ||
      !sameProvider(owned.provider, change.provider)
    ) {
      throw new GatewayReconcileError('pending_conflict');
    }
  }
  for (const resource of desiredResources) {
    if (resource.key === portal.key && resource.kind === portal.kind) continue;
    if (RESOURCE_ORDER.get(resource.kind) <= portalRank) continue;
    const change = findChange(plan, resource.kind, resource.key);
    if (change?.action !== 'create' || change.provider !== undefined) {
      throw new GatewayReconcileError('pending_conflict');
    }
  }
  if (plan.changes.some((change) => change.action === 'delete')) {
    throw new GatewayReconcileError('pending_conflict');
  }
}

function normalizePendingPortalRollbackEvidence(value, portalKey) {
  if (
    !isObject(value) ||
    !['ready', 'already_absent'].includes(value.status) ||
    value.portalKey !== portalKey ||
    Object.keys(value).sort().join(',') !== 'portalKey,status'
  ) {
    throw new GatewayReconcileError('invalid_observed_state');
  }
  return { status: value.status, portalKey };
}

function normalizePendingPortalRollbackMutationResult(value, portalKey) {
  if (
    !isObject(value) ||
    !['rolled_back', 'already_absent'].includes(value.status) ||
    value.portalKey !== portalKey ||
    !['confirmed', 'outcome_unknown', 'not_needed'].includes(value.deleteRequest) ||
    (value.status === 'already_absent' && value.deleteRequest !== 'not_needed') ||
    (value.status === 'rolled_back' && value.deleteRequest === 'not_needed') ||
    Object.keys(value).sort().join(',') !== 'deleteRequest,portalKey,status'
  ) {
    throw new GatewayReconcileError('verification_failed');
  }
  return {
    status: value.status,
    portalKey,
    deleteRequest: value.deleteRequest,
  };
}

function publicPendingPortalRollbackPreview(preview) {
  return {
    schemaVersion: 1,
    operation: 'rollback_pending_portal_create',
    rollbackId: preview.rollbackId,
    portalState: preview.evidence.status === 'ready' ? 'present_exact' : 'already_absent',
    receipt: receiptSummary(preview.receipt),
  };
}

async function applyGatewayLocked(context) {
  let live = await readLive(context);

  if (live.receipt?.state === 'removed') {
    throw new GatewayReconcileError('installation_removed');
  }
  if (live.receipt?.state === 'uninstalling') {
    throw new GatewayReconcileError('pending_uninstall');
  }
  if (live.receipt?.pending) {
    if (live.receipt.pending.type !== 'apply') {
      throw new GatewayReconcileError('pending_uninstall');
    }
    live = await recoverApplyPending(context, live);
  }

  assertPlanExecutable(live.plan);
  if (context.approvedPlanId !== live.plan.planId) {
    throw new GatewayReconcileError('approval_required');
  }
  const approvedPrune = await buildPruneApproval(live);
  await assertPruneApproval(context, approvedPrune);

  let receipt = live.receipt;
  if (!receipt) {
    const desired = await buildGatewayDesiredState(context.config, {
      target: live.observed.target,
      access: context.access,
    });
    receipt = await createInstallationReceipt({
      plan: live.plan,
      target: receiptTarget(context.config, live.observed.target),
      accessPolicy: desired.accessPolicy,
    });
    await writeReceipt(context.receiptStore, receipt);
    live = await readLive({ ...context, receiptOverride: receipt });
    assertPlanExecutable(live.plan);
  }

  assertReceiptMatchesPlan(receipt, live.plan);
  ({ live, receipt } = await retireAbsentReceiptEntries(
    context,
    live,
    receipt,
    approvedPrune,
  ));
  const approvedChanges = live.plan.changes.filter((change) => {
    if (change.action === 'noop') return false;
    if (change.action === 'delete' && !context.prune) return false;
    return change.action === 'create' || change.action === 'update' || change.action === 'delete';
  }).sort(compareApprovedChanges);

  for (const approved of approvedChanges) {
    live = await readLive({ ...context, receiptOverride: receipt });
    assertPlanExecutable(live.plan);
    const current = findChange(live.plan, approved.kind, approved.key);
    if (current?.action === 'noop') continue;
    assertApprovedChangeStillMatches(approved, current);
    assertLowerRankDependenciesConverged(live.plan, receipt, current);

    receipt = await journalAction(
      context,
      receipt,
      live.plan.planId,
      current,
      'apply',
      current.action === 'delete' ? approvedPrune.approvalId : undefined,
    );
    live = await performPendingMutation(context, { ...live, receipt });
    receipt = live.receipt;
  }

  live = await readLive({ ...context, receiptOverride: receipt });
  assertPlanExecutable(live.plan);
  const incomplete = live.plan.changes.filter(
    (change) =>
      change.action === 'create' ||
      change.action === 'update' ||
      (change.action === 'delete' && context.prune),
  );
  if (incomplete.length > 0) {
    throw new GatewayReconcileError('verification_failed');
  }

  const desired = await buildGatewayDesiredState(context.config, {
    target: live.observed.target,
    access: context.access,
  });
  receipt = await updateInstallationReceipt(receipt, {
    plan: live.plan,
    target: receiptTarget(context.config, live.observed.target),
    accessPolicy: desired.accessPolicy,
  });
  await writeReceipt(context.receiptStore, receipt);
  live = await readLive({ ...context, receiptOverride: receipt });
  const remainingPrune = await buildPruneApproval(live);

  return {
    status:
      live.plan.changes.every((change) => change.action === 'noop') &&
      remainingPrune.actions.length === 0
        ? 'ready'
        : 'drift',
    plan: live.plan,
    ...publicPruneApproval(remainingPrune),
    receipt: receiptSummary(receipt),
    diagnostics: sanitizeDiagnostics(live.observed.diagnostics),
  };
}

/** Build a deletion preview using only receipt-bound, freshly observed ownership. */
export async function planGatewayUninstall(input) {
  const context = requireContext(input, { mutations: false });
  const preview = await buildGatewayUninstallPlan(context);
  return publicUninstallPreview(preview);
}

async function buildGatewayUninstallPlan(context) {
  const live = await readLive(context);
  const receipt = live.receipt;

  if (!receipt) throw new GatewayReconcileError('receipt_required');
  if (receipt.pending && receipt.pending.type !== 'uninstall') {
    throw new GatewayReconcileError('pending_apply');
  }

  const blockers = [];
  const actions = [];
  for (const owned of [...receipt.resources].sort(compareReceiptResourcesReverse)) {
    const matches = matchingResources(live.observed.resources, owned.kind, owned.key);
    if (matches.length === 0) {
      actions.push({ action: 'noop', kind: owned.kind, key: owned.key, reason: 'already_absent' });
      continue;
    }
    if (matches.length !== 1 || !isExactOwnedMatch(matches[0], owned, receipt.installationId)) {
      blockers.push({
        code: 'ownership_conflict',
        kind: owned.kind,
        key: owned.key,
      });
      continue;
    }
    actions.push({ action: 'delete', kind: owned.kind, key: owned.key });
  }

  const uninstallId = `uninstall-${(
    await hashCanonical({
      schemaVersion: 1,
      installationId: receipt.installationId,
      revision: receipt.revision,
      state: receipt.state,
      receiptChecksum: receipt.checksum,
      receiptResources: receipt.resources.map((resource) => ({
        kind: resource.kind,
        key: resource.key,
        provider: { ...resource.provider },
        desiredHash: resource.desiredHash,
      })),
      blockers,
      actions,
      live: liveFingerprints(
        live.observed.resources,
        receipt.resources,
        receipt.installationId,
      ),
    })
  ).slice(HASH_PREFIX.length, HASH_PREFIX.length + 24)}`;

  return {
    schemaVersion: 1,
    uninstallId,
    installationId: receipt.installationId,
    blockers,
    actions,
    receipt,
    observed: live.observed,
  };
}

/** Delete receipt-owned resources in reverse dependency order and retain a tombstone. */
export async function uninstallGateway(input) {
  const context = requireContext(input, { mutations: true });
  return withReceiptLock(context, () => uninstallGatewayLocked(context));
}

async function uninstallGatewayLocked(context) {
  let preview = await buildGatewayUninstallPlan(context);
  let receipt = preview.receipt;
  let approvalId = preview.uninstallId;

  if (receipt.state === 'removed') {
    return { status: 'removed', uninstallId: preview.uninstallId, receipt: receiptSummary(receipt) };
  }
  if (receipt.pending) {
    approvalId = receipt.pending.planId;
    preview = await recoverUninstallPending(context, preview);
    receipt = preview.receipt;
  }
  if (preview.blockers.length > 0) {
    throw new GatewayReconcileError('ownership_conflict');
  }
  if (context.approvedUninstallId !== approvalId) {
    throw new GatewayReconcileError('uninstall_approval_required');
  }

  for (const approved of preview.actions) {
    const fresh = await buildGatewayUninstallPlan({ ...context, receiptOverride: receipt });
    const current = fresh.actions.find(
      (action) => action.kind === approved.kind && action.key === approved.key,
    );
    if (!current) throw new GatewayReconcileError('ownership_conflict');
    if (fresh.blockers.some((blocker) => blocker.kind === approved.kind && blocker.key === approved.key)) {
      throw new GatewayReconcileError('ownership_conflict');
    }

    const owned = findReceiptResource(receipt, approved.kind, approved.key);
    if (!owned) continue;
    const change = {
      action: 'delete',
      kind: owned.kind,
      key: owned.key,
      provider: { ...owned.provider },
      desiredHash: owned.desiredHash,
    };
    receipt = await journalAction(context, receipt, preview.uninstallId, change, 'uninstall');

    if (current.action === 'delete') {
      await mutate(context, change, receipt);
      const verified = await readLive({ ...context, receiptOverride: receipt });
      if (matchingResources(verified.observed.resources, owned.kind, owned.key).length !== 0) {
        throw new GatewayReconcileError('verification_failed');
      }
    }

    receipt = await commitReceiptAction(receipt);
    await writeReceipt(context.receiptStore, receipt);
  }

  if (receipt.resources.length !== 0) throw new GatewayReconcileError('verification_failed');
  receipt = await markReceiptRemoved(receipt);
  await writeReceipt(context.receiptStore, receipt);
  return { status: 'removed', uninstallId: approvalId, receipt: receiptSummary(receipt) };
}

async function recoverApplyPending(context, live) {
  const pending = live.receipt.pending;
  await assertPendingRequestHash(pending);
  const change = findChange(live.plan, pending.kind, pending.key);
  if (pending.action === 'delete') {
    const matches = matchingResources(live.observed.resources, pending.kind, pending.key);
    if (matches.length === 0) {
      const receipt = await commitReceiptAction(live.receipt);
      await writeReceipt(context.receiptStore, receipt);
      return readLive({ ...context, receiptOverride: receipt });
    }
    if (change?.action === 'delete') {
      await assertRecoveryApplyRetry(context, pending, live);
      await mutate(context, change, live.receipt);
      const verified = await readLive({ ...context, receiptOverride: live.receipt });
      if (matchingResources(verified.observed.resources, pending.kind, pending.key).length > 0) {
        throw new GatewayReconcileError('pending_conflict');
      }
      const receipt = await commitReceiptAction(live.receipt);
      await writeReceipt(context.receiptStore, receipt);
      return readLive({ ...context, receiptOverride: receipt });
    }
    throw new GatewayReconcileError('pending_conflict');
  }

  if (change?.action === 'noop' && change.desiredHash === pending.expectedDesiredHash) {
    const receipt = await commitVerifiedChange(context, live.receipt, change);
    return readLive({ ...context, receiptOverride: receipt });
  }
  if (pending.action === 'create') {
    // Cloudflare exposes no general idempotency key and newly created Access
    // policies use server-generated IDs. An absent read may be eventual
    // consistency, so replaying the POST could duplicate a resource.
    if (change?.action === 'create') {
      throw new GatewayReconcileError('pending_outcome_unknown');
    }
    throw new GatewayReconcileError('pending_conflict');
  }
  if (change?.action !== pending.action || change.desiredHash !== pending.expectedDesiredHash) {
    throw new GatewayReconcileError('pending_conflict');
  }
  await assertRecoveryApplyRetry(context, pending, live);
  return performPendingMutation(context, live);
}

async function retireAbsentReceiptEntries(
  context,
  initialLive,
  initialReceipt,
  approvedPrune,
) {
  const approvedPlanId = initialLive.plan.planId;
  let live = initialLive;
  let receipt = initialReceipt;
  const candidates = [...initialReceipt.resources]
    .sort(compareReceiptResourcesReverse)
    .map(({ kind, key }) => ({ kind, key }));

  for (const candidate of candidates) {
    live = await readLive({ ...context, receiptOverride: receipt });
    assertPlanExecutable(live.plan);
    if (live.plan.planId !== approvedPlanId) {
      throw new GatewayReconcileError('plan_changed');
    }

    const owned = findReceiptResource(receipt, candidate.kind, candidate.key);
    if (!owned) continue;
    if (matchingResources(live.observed.resources, owned.kind, owned.key).length !== 0) continue;

    // A desired resource that disappeared is represented by a create. No
    // change means the absent receipt entry is stale after a config removal.
    // Any other action means the provider did not prove an unambiguous absence.
    const current = findChange(live.plan, owned.kind, owned.key);
    if (current && current.action !== 'create') continue;
    if (
      !current &&
      (
        !context.prune ||
        !approvedPrune.receiptRetirements.some((retirement) =>
          sameReceiptResource(retirement, owned))
      )
    ) {
      continue;
    }

    const retirement = {
      action: 'delete',
      kind: owned.kind,
      key: owned.key,
      provider: { ...owned.provider },
      desiredHash: owned.desiredHash,
    };
    receipt = await journalAction(
      context,
      receipt,
      approvedPlanId,
      retirement,
      'apply',
      current ? undefined : approvedPrune.approvalId,
    );
    const verified = await readLive({ ...context, receiptOverride: receipt });
    if (matchingResources(verified.observed.resources, owned.kind, owned.key).length !== 0) {
      throw new GatewayReconcileError('pending_conflict');
    }
    receipt = await commitReceiptAction(receipt);
    await writeReceipt(context.receiptStore, receipt);
    live = await readLive({ ...context, receiptOverride: receipt });
  }

  return { live, receipt };
}

async function recoverUninstallPending(context, preview) {
  const pending = preview.receipt.pending;
  await assertPendingRequestHash(pending);
  if (pending.type !== 'uninstall' || pending.action !== 'delete') {
    throw new GatewayReconcileError('pending_apply');
  }
  const owned = findReceiptResource(preview.receipt, pending.kind, pending.key);
  if (!owned) throw new GatewayReconcileError('pending_conflict');
  const matches = matchingResources(preview.observed.resources, pending.kind, pending.key);
  if (matches.length > 1) throw new GatewayReconcileError('pending_conflict');
  if (matches.length === 1) {
    if (!isExactOwnedMatch(matches[0], owned, preview.receipt.installationId)) {
      throw new GatewayReconcileError('pending_conflict');
    }
    if (context.approvedUninstallId !== pending.planId) {
      throw new GatewayReconcileError('uninstall_approval_required');
    }
    await mutate(
      context,
      {
        action: 'delete',
        kind: owned.kind,
        key: owned.key,
        provider: owned.provider,
        desiredHash: owned.desiredHash,
      },
      preview.receipt,
    );
    const verified = await readLive({ ...context, receiptOverride: preview.receipt });
    if (matchingResources(verified.observed.resources, pending.kind, pending.key).length !== 0) {
      throw new GatewayReconcileError('verification_failed');
    }
  }
  const receipt = await commitReceiptAction(preview.receipt);
  await writeReceipt(context.receiptStore, receipt);
  return buildGatewayUninstallPlan({ ...context, receiptOverride: receipt });
}

async function performPendingMutation(context, live) {
  const pending = live.receipt.pending;
  const change = findChange(live.plan, pending.kind, pending.key);
  if (!change || change.action !== pending.action || change.desiredHash !== pending.expectedDesiredHash) {
    if (pending.action !== 'delete' || change?.action !== 'delete') {
      throw new GatewayReconcileError('pending_conflict');
    }
  }
  if (pending.action === 'delete') {
    await mutate(context, change, live.receipt);
    const verified = await readLive({ ...context, receiptOverride: live.receipt });
    if (matchingResources(verified.observed.resources, pending.kind, pending.key).length !== 0) {
      throw new GatewayReconcileError('verification_failed');
    }
    const receipt = await commitReceiptAction(live.receipt);
    await writeReceipt(context.receiptStore, receipt);
    return readLive({ ...context, receiptOverride: receipt });
  }
  if (!change || change.action !== pending.action || change.desiredHash !== pending.expectedDesiredHash) {
    throw new GatewayReconcileError('pending_conflict');
  }
  assertLowerRankDependenciesConverged(live.plan, live.receipt, change);
  const mutationResult = await mutate(context, change, live.receipt);

  // Portal Access applications have no ownership marker. A newly created app
  // may therefore be claimed only from the exact ID returned and fully proved
  // by the mutation adapter in this same invocation. Persist that locator
  // before a list read can confuse it with a late, same-shaped application.
  // A crash before this atomic receipt write deliberately leaves the create
  // pending for manual recovery; observation never adopts a markerless app.
  if (isMarkerlessApplicationCreate(change)) {
    const receipt = await commitVerifiedChange(
      context,
      live.receipt,
      { ...change, provider: mutationResult.provider },
      mutationResult,
    );
    const verified = await readLive({ ...context, receiptOverride: receipt });
    const verifiedChange = findChange(verified.plan, change.kind, change.key);
    if (verifiedChange?.action !== 'noop'
      || verifiedChange.desiredHash !== pending.expectedDesiredHash
      || !sameProvider(verifiedChange.provider, mutationResult.provider)) {
      throw new GatewayReconcileError('verification_failed');
    }
    return verified;
  }

  const verified = await readLive({ ...context, receiptOverride: live.receipt });
  const verifiedChange = findChange(verified.plan, change.kind, change.key);
  if (verifiedChange?.action !== 'noop' || verifiedChange.desiredHash !== pending.expectedDesiredHash) {
    throw new GatewayReconcileError('verification_failed');
  }
  const receipt = await commitVerifiedChange(
    context,
    live.receipt,
    verifiedChange,
    mutationResult,
  );
  return readLive({ ...context, receiptOverride: receipt });
}

async function commitVerifiedChange(context, receipt, change, mutationResult = null) {
  if (!change.provider?.id) throw new GatewayReconcileError('verification_failed');
  const desired = change.desired ?? {};
  if (mutationResult !== null && mutationResult.status !== 'submitted') {
    throw new GatewayReconcileError('verification_failed');
  }
  const identityHash = isPolicyKind(change.kind) ? desired.allow?.identitiesHash : undefined;
  const result = {
    desiredHash: change.desiredHash,
    marker: ownershipMarker(receipt.installationId, change.key),
    ...(identityHash ? { identityHash } : {}),
  };
  if (receipt.pending.action === 'create') result.provider = { ...change.provider };
  const committed = await commitReceiptAction(receipt, result);
  await writeReceipt(context.receiptStore, committed);
  return committed;
}

async function journalAction(
  context,
  receipt,
  planId,
  change,
  type,
  pruneApprovalId = undefined,
) {
  const expectedDesiredHash = expectedHash(receipt, change);
  const request = {
    type,
    planId,
    action: change.action,
    kind: change.kind,
    key: change.key,
    expectedDesiredHash,
    ...(pruneApprovalId !== undefined && pruneApprovalId !== null
      ? { pruneApprovalId }
      : {}),
  };
  const intent = {
    operationId: operationId(),
    ...request,
    requestHash: await mutationRequestHash(request),
  };
  const pending = await beginReceiptAction(receipt, intent);
  await writeReceipt(context.receiptStore, pending);
  progress(context, { stage: type, action: change.action, kind: change.kind, status: 'started' });
  return pending;
}

async function mutate(context, change, receipt) {
  let normalizedResult;
  try {
    const result = await context.provider.applyChange({
      change: copyChange(change),
      receipt,
      config: context.config,
      target: context.target,
      access: context.access,
    });
    normalizedResult = normalizeMutationResult(change, result);
  } catch (error) {
    progress(context, { stage: receipt.pending?.type ?? 'apply', action: change.action, kind: change.kind, status: 'failed' });
    if (
      error?.mutationOutcome === 'not_submitted' &&
      receipt.pending?.type === 'apply'
    ) {
      await clearDefinitelyUnsubmittedMutation(context, receipt, change);
      throw new GatewayReconcileError('mutation_not_submitted');
    }
    throw new GatewayReconcileError('mutation_failed');
  }
  progress(context, { stage: receipt.pending?.type ?? 'apply', action: change.action, kind: change.kind, status: 'verifying' });
  return normalizedResult;
}

async function clearDefinitelyUnsubmittedMutation(context, receipt, change) {
  const current = await readReceipt(context.receiptStore);
  const trusted = current ? await validateReceiptSafe(current) : null;
  if (
    !trusted ||
    trusted.checksum !== receipt.checksum ||
    trusted.pending?.operationId !== receipt.pending?.operationId ||
    trusted.pending?.action !== change.action ||
    trusted.pending?.kind !== change.kind ||
    trusted.pending?.key !== change.key
  ) {
    throw new GatewayReconcileError('receipt_changed');
  }
  await assertPendingRequestHash(trusted.pending);
  const cleared = await clearReceiptAction(trusted, trusted.pending.operationId);
  await writeReceipt(context.receiptStore, cleared);
}

async function readLive(context) {
  const storedReceipt = await readReceipt(context.receiptStore);
  let receipt = storedReceipt;
  if (context.receiptOverride !== undefined) {
    const expected = context.receiptOverride
      ? await validateReceiptSafe(context.receiptOverride)
      : null;
    const stored = storedReceipt ? await validateReceiptSafe(storedReceipt) : null;
    if (expected?.checksum !== stored?.checksum) {
      throw new GatewayReconcileError('receipt_changed');
    }
    receipt = stored;
  } else if (receipt) {
    receipt = await validateReceiptSafe(receipt);
  }

  let observed;
  try {
    observed = await context.provider.readObservedState({
      config: context.config,
      target: { ...context.target },
      access: context.access,
      receipt,
    });
  } catch (error) {
    if (error instanceof GatewayReconcileError) throw error;
    throw new GatewayReconcileError('observation_failed');
  }
  if (!isObject(observed) || !isObject(observed.target) || !Array.isArray(observed.resources)) {
    throw new GatewayReconcileError('invalid_observed_state');
  }
  assertObservedResources(observed.resources);
  assertSelectedTarget(context.target, observed.target);

  if (receipt) {
    receipt = await validateReceiptSafe(receipt, {
      expectedTarget: receiptTarget(context.config, observed.target),
    });
  }
  const plan = await buildGatewayPlan(context.config, observed, {
    release: context.release,
    access: context.access,
  });
  if (receipt && receipt.installationId !== plan.installationId) {
    throw new GatewayReconcileError('receipt_mismatch');
  }
  return { plan, observed, receipt };
}

function requireContext(input, { mutations }) {
  if (!isObject(input)) throw new TypeError('reconciler input must be an object');
  if (!isObject(input.config)) throw new TypeError('config must be an object');
  if (!isObject(input.target)) throw new TypeError('target must be an object');
  if (!isObject(input.access)) throw new TypeError('access must be an object');
  if (!isObject(input.provider) || typeof input.provider.readObservedState !== 'function') {
    throw new TypeError('provider.readObservedState must be a function');
  }
  if (mutations && typeof input.provider.applyChange !== 'function') {
    throw new TypeError('provider.applyChange must be a function');
  }
  if (!isObject(input.receiptStore) || typeof input.receiptStore.read !== 'function' || typeof input.receiptStore.writeAtomic !== 'function') {
    throw new TypeError('receiptStore must provide read and writeAtomic functions');
  }
  if (mutations && typeof input.receiptStore.withExclusiveLock !== 'function') {
    throw new TypeError('receiptStore.withExclusiveLock must serialize mutations');
  }
  if (mutations && input.approvedPlanId !== undefined && typeof input.approvedPlanId !== 'string') {
    throw new TypeError('approvedPlanId must be a string');
  }
  if (mutations && input.approvedPruneId !== undefined && typeof input.approvedPruneId !== 'string') {
    throw new TypeError('approvedPruneId must be a string');
  }
  if (mutations && input.approvedUninstallId !== undefined && typeof input.approvedUninstallId !== 'string') {
    throw new TypeError('approvedUninstallId must be a string');
  }
  return {
    ...input,
    release: input.release ?? 'development',
    prune: input.prune === true,
    onProgress: typeof input.onProgress === 'function' ? input.onProgress : null,
  };
}

function requirePendingPortalRollbackContext(input, { mutations }) {
  const context = requireContext(input, { mutations: false });
  if (typeof input.provider.inspectPendingPortalCreateRollback !== 'function') {
    throw new TypeError('provider.inspectPendingPortalCreateRollback must be a function');
  }
  if (mutations) {
    if (typeof input.provider.rollbackPendingPortalCreate !== 'function') {
      throw new TypeError('provider.rollbackPendingPortalCreate must be a function');
    }
    if (typeof input.receiptStore.withExclusiveLock !== 'function') {
      throw new TypeError('receiptStore.withExclusiveLock must serialize mutations');
    }
    if (
      typeof input.approvedRollbackId !== 'string' ||
      !/^rollback-[0-9a-f]{24}$/.test(input.approvedRollbackId)
    ) {
      throw new TypeError('approvedRollbackId must be an exact rollback approval identifier');
    }
  }
  return context;
}

async function readReceipt(store) {
  try {
    return await store.read();
  } catch {
    throw new GatewayReconcileError('receipt_read_failed');
  }
}

async function writeReceipt(store, receipt) {
  try {
    await store.writeAtomic(receipt);
  } catch {
    throw new GatewayReconcileError('receipt_write_failed');
  }
}

async function withReceiptLock(context, operation) {
  try {
    return await context.receiptStore.withExclusiveLock(operation);
  } catch (error) {
    if (error instanceof GatewayReconcileError) throw error;
    if (error?.code === 'locked') throw new GatewayReconcileError('receipt_locked');
    throw new GatewayReconcileError('receipt_lock_failed');
  }
}

async function validateReceiptSafe(receipt, options) {
  try {
    return await validateInstallationReceipt(receipt, options);
  } catch {
    throw new GatewayReconcileError('receipt_invalid');
  }
}

function assertPlanExecutable(plan) {
  if (plan.blockers.length > 0 || plan.changes.some((change) => change.action === 'conflict')) {
    throw new GatewayReconcileError('plan_blocked');
  }
  if (
    plan.changes.some(
      (change) =>
        change.action !== 'create' &&
        !validProviderForKind(change.kind, change.provider),
    )
  ) {
    throw new GatewayReconcileError('invalid_observed_state');
  }
}

function assertObservedResources(resources) {
  for (const resource of resources) {
    if (
      !isObject(resource) ||
      !RESOURCE_KINDS.has(resource.kind) ||
      typeof resource.key !== 'string' ||
      !RESOURCE_KEY.test(resource.key) ||
      !isObject(resource.owner) ||
      !(
        resource.desiredHash === '' ||
        (typeof resource.desiredHash === 'string' && DESIRED_HASH.test(resource.desiredHash))
      )
    ) {
      throw new GatewayReconcileError('invalid_observed_state');
    }
    if (resource.provider !== undefined && !validProviderForKind(resource.kind, resource.provider)) {
      throw new GatewayReconcileError('invalid_observed_state');
    }
    if (
      resource.owner.manager === 'ankka-mcp-gateway' &&
      !validProviderForKind(resource.kind, resource.provider)
    ) {
      throw new GatewayReconcileError('invalid_observed_state');
    }
  }
}

function normalizeMutationResult(change, value) {
  if (isMarkerlessApplicationCreate(change)) {
    if (
      !isObject(value) ||
      value.status !== 'submitted' ||
      Object.keys(value).sort(compareText).join(',') !== 'provider,status' ||
      !validProviderForKind(change.kind, value.provider)
    ) {
      throw new GatewayReconcileError('mutation_failed');
    }
    return { status: 'submitted', provider: { ...value.provider } };
  }
  if (
    !isObject(value) ||
    value.status !== 'submitted' ||
    Object.keys(value).length !== 1
  ) {
    throw new GatewayReconcileError('mutation_failed');
  }
  return { status: 'submitted' };
}

function isMarkerlessApplicationCreate(change) {
  return change?.action === 'create' && change.kind === 'portal_access_application';
}

function validProviderForKind(kind, provider) {
  if (!isObject(provider) || typeof provider.id !== 'string' || !SAFE_ID.test(provider.id)) {
    return false;
  }
  const policy = kind === 'source_access_policy' || kind === 'portal_access_policy';
  const keys = Object.keys(provider).sort(compareText);
  const expectedKeys = policy ? ['id', 'parentId'] : ['id'];
  if (keys.length !== expectedKeys.length || !expectedKeys.every((key) => keys.includes(key))) {
    return false;
  }
  return !policy || (typeof provider.parentId === 'string' && SAFE_ID.test(provider.parentId));
}

function assertReceiptMatchesPlan(receipt, plan) {
  if (
    receipt.installationId !== plan.installationId ||
    receipt.release !== plan.release
  ) {
    throw new GatewayReconcileError('receipt_mismatch');
  }
}

function assertApprovedChangeStillMatches(approved, current) {
  if (!current || current.action !== approved.action) {
    throw new GatewayReconcileError('plan_changed');
  }
  if (approved.desiredHash && current.desiredHash !== approved.desiredHash) {
    throw new GatewayReconcileError('plan_changed');
  }
  if (!sameProvider(approved.provider, current.provider)) {
    throw new GatewayReconcileError('plan_changed');
  }
}

function assertLowerRankDependenciesConverged(plan, receipt, current) {
  if (current.action !== 'create' && current.action !== 'update') return;
  const rank = RESOURCE_ORDER.get(current.kind);
  for (const dependency of plan.changes) {
    if (!isObject(dependency.desired) || RESOURCE_ORDER.get(dependency.kind) >= rank) continue;
    const owned = findReceiptResource(receipt, dependency.kind, dependency.key);
    if (
      dependency.action !== 'noop' ||
      !owned ||
      owned.desiredHash !== dependency.desiredHash ||
      !sameProvider(owned.provider, dependency.provider)
    ) {
      throw new GatewayReconcileError('plan_changed');
    }
  }
}

function compareApprovedChanges(left, right) {
  const leftDelete = left.action === 'delete';
  const rightDelete = right.action === 'delete';
  if (leftDelete !== rightDelete) return leftDelete ? 1 : -1;
  const direction = leftDelete ? -1 : 1;
  return direction * (
    (RESOURCE_ORDER.get(left.kind) ?? -1) - (RESOURCE_ORDER.get(right.kind) ?? -1)
  ) || compareText(left.key, right.key);
}

function assertSelectedTarget(selected, observed) {
  for (const field of ['accountId', 'zoneId']) {
    if (typeof selected[field] === 'string' && selected[field] !== observed[field]) {
      throw new GatewayReconcileError('target_mismatch');
    }
  }
  if (typeof selected.zoneName === 'string' && selected.zoneName !== observed.zoneName) {
    throw new GatewayReconcileError('target_mismatch');
  }
}

function assertPendingRequestHash(pending) {
  return mutationRequestHash({
    type: pending.type,
    planId: pending.planId,
    action: pending.action,
    kind: pending.kind,
    key: pending.key,
    expectedDesiredHash: pending.expectedDesiredHash,
    ...(pending.pruneApprovalId !== undefined
      ? { pruneApprovalId: pending.pruneApprovalId }
      : {}),
  }).then((expected) => {
    if (expected !== pending.requestHash) throw new GatewayReconcileError('pending_conflict');
  });
}

async function assertRecoveryApplyRetry(context, pending, live) {
  assertPlanExecutable(live.plan);
  if (
    context.approvedPlanId !== pending.planId ||
    live.plan.planId !== pending.planId
  ) {
    throw new GatewayReconcileError('approval_required');
  }
  if (pending.action === 'delete') {
    if (
      !pending.pruneApprovalId ||
      !context.prune ||
      context.approvedPruneId !== pending.pruneApprovalId
    ) {
      throw new GatewayReconcileError('prune_approval_required');
    }
  }
}

async function assertPruneApproval(context, prune) {
  if (!context.prune) return;
  if (prune.approvalId !== null && context.approvedPruneId !== prune.approvalId) {
    throw new GatewayReconcileError('prune_approval_required');
  }
}

async function buildPruneApproval(live) {
  const remoteDeletions = live.plan.changes
    .filter((change) => change.action === 'delete')
    .map((change) => ({
      kind: change.kind,
      key: change.key,
      provider: { ...change.provider },
    }))
    .sort(comparePruneResources);
  const receiptRetirements = live.receipt
    ? live.receipt.resources
      .filter((owned) =>
        !findChange(live.plan, owned.kind, owned.key) &&
        matchingResources(live.observed.resources, owned.kind, owned.key).length === 0)
      .map(copyReceiptResourceForPrune)
      .sort(comparePruneResources)
    : [];
  const actions = [
    ...remoteDeletions.map(({ kind, key }) => ({ action: 'delete', kind, key })),
    ...receiptRetirements.map(({ kind, key }) => ({
      action: 'retire_receipt',
      kind,
      key,
    })),
  ];
  if (actions.length === 0) {
    return { approvalId: null, remoteDeletions, receiptRetirements, actions };
  }
  const digest = await hashCanonical({
    schemaVersion: 1,
    operation: 'prune',
    planId: live.plan.planId,
    receiptChecksum: live.receipt?.checksum ?? null,
    remoteDeletions,
    receiptRetirements,
  });
  return {
    approvalId: `prune-${digest.slice(HASH_PREFIX.length, HASH_PREFIX.length + 24)}`,
    remoteDeletions,
    receiptRetirements,
    actions,
  };
}

function expectedHash(receipt, change) {
  if (change.action === 'create') {
    if (typeof change.desiredHash !== 'string') throw new GatewayReconcileError('plan_changed');
    return change.desiredHash;
  }
  const owned = findReceiptResource(receipt, change.kind, change.key);
  if (
    !owned ||
    !sameProvider(owned.provider, change.provider)
  ) {
    throw new GatewayReconcileError('ownership_conflict');
  }
  if (change.action === 'delete') return owned.desiredHash;
  if (typeof change.desiredHash !== 'string') throw new GatewayReconcileError('plan_changed');
  return change.desiredHash;
}

function findChange(plan, kind, key) {
  return plan.changes.find((change) => change.kind === kind && change.key === key);
}

function findReceiptResource(receipt, kind, key) {
  return receipt.resources.find((resource) => resource.kind === kind && resource.key === key);
}

function matchingResources(resources, kind, key) {
  return resources.filter((resource) => resource.kind === kind && resource.key === key);
}

function isExactOwnedMatch(observed, owned, installationId) {
  return (
    observed.owner?.manager === 'ankka-mcp-gateway' &&
    observed.owner?.installationId === installationId &&
    sameProvider(observed.provider, owned.provider)
  );
}

function isPolicyKind(kind) {
  return kind === 'source_access_policy' || kind === 'portal_access_policy';
}

function sameProvider(left, right) {
  if (!left && !right) return true;
  if (!isObject(left) || !isObject(right)) return false;
  return left.id === right.id && (left.parentId ?? '') === (right.parentId ?? '');
}

function compareReceiptResourcesReverse(left, right) {
  return (
    (RESOURCE_ORDER.get(right.kind) ?? -1) - (RESOURCE_ORDER.get(left.kind) ?? -1) ||
    compareText(left.key, right.key)
  );
}

function liveFingerprints(observedResources, receiptResources, installationId) {
  return receiptResources
    .map((owned) => {
      const matches = matchingResources(observedResources, owned.kind, owned.key);
      return {
        kind: owned.kind,
        key: owned.key,
        count: matches.length,
        owned:
          matches.length === 1 &&
          isExactOwnedMatch(matches[0], owned, installationId),
        providers: matches
          .map((resource) => ({
            id: resource.provider?.id ?? '',
            ...(resource.provider?.parentId
              ? { parentId: resource.provider.parentId }
              : {}),
          }))
          .sort((left, right) =>
            compareText(
              `${left.parentId ?? ''}\u0000${left.id}`,
              `${right.parentId ?? ''}\u0000${right.id}`,
            )),
        hashes: matches.map((resource) => resource.desiredHash ?? '').sort(compareText),
      };
    })
    .sort((left, right) => compareText(`${left.kind}:${left.key}`, `${right.kind}:${right.key}`));
}

function receiptTarget(config, observedTarget) {
  return {
    accountId: observedTarget.accountId,
    zoneId: observedTarget.zoneId,
    zoneName: observedTarget.zoneName,
    hostname: config.gateway.hostname,
  };
}

function copyChange(change) {
  return structuredClone(change);
}

function receiptSummary(receipt) {
  return {
    state: receipt.state,
    revision: receipt.revision,
    installationId: receipt.installationId,
    resourceCount: receipt.resources.length,
  };
}

function publicPruneApproval(prune) {
  return {
    pruneApprovalId: prune.approvalId,
    pruneSummary: {
      remoteDeleteCount: prune.remoteDeletions.length,
      receiptRetirementCount: prune.receiptRetirements.length,
      actions: prune.actions.map((action) => ({ ...action })),
    },
  };
}

function copyReceiptResourceForPrune(resource) {
  return {
    kind: resource.kind,
    key: resource.key,
    provider: { ...resource.provider },
    desiredHash: resource.desiredHash,
  };
}

function sameReceiptResource(left, right) {
  return (
    left.kind === right.kind &&
    left.key === right.key &&
    left.desiredHash === right.desiredHash &&
    sameProvider(left.provider, right.provider)
  );
}

function comparePruneResources(left, right) {
  return (
    compareReceiptResourcesReverse(left, right) ||
    compareText(left.provider?.parentId ?? '', right.provider?.parentId ?? '') ||
    compareText(left.provider?.id ?? '', right.provider?.id ?? '')
  );
}

function publicUninstallPreview(preview) {
  return {
    schemaVersion: preview.schemaVersion,
    uninstallId: preview.uninstallId,
    installationId: preview.installationId,
    blockers: preview.blockers.map((blocker) => ({ ...blocker })),
    actions: preview.actions.map((action) => ({ ...action })),
    receipt: receiptSummary(preview.receipt),
    diagnostics: sanitizeDiagnostics(preview.observed.diagnostics),
  };
}

function summarizeChanges(changes) {
  return changes.map((change) => ({ action: change.action, kind: change.kind, key: change.key }));
}

function sanitizeDiagnostics(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item) => isObject(item) && typeof item.code === 'string' && SAFE_CODE.test(item.code))
    .slice(0, 100)
    .map((item) => ({ code: item.code }));
}

function progress(context, event) {
  if (!context.onProgress) return;
  try {
    context.onProgress({ ...event });
  } catch {
    // Progress sinks are observational and cannot affect customer resources.
  }
}

function operationId() {
  if (!globalThis.crypto?.randomUUID) throw new Error('Web Crypto randomUUID is required');
  return `op-${globalThis.crypto.randomUUID()}`;
}

async function mutationRequestHash(value) {
  return hashCanonical({ schemaVersion: 1, ...value });
}

async function hashCanonical(value) {
  if (!globalThis.crypto?.subtle) throw new Error('Web Crypto is required');
  const bytes = new TextEncoder().encode(canonicalJson(value));
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return `${HASH_PREFIX}${[...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}`;
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
  throw new TypeError('Cannot hash unsupported value');
}

function messageFor(code) {
  const messages = {
    approval_required: 'Apply requires the exact current plan approval.',
    installation_removed: 'This installation receipt is a completed uninstall tombstone.',
    invalid_observed_state: 'The provider returned an invalid normalized state.',
    mutation_failed: 'The provider mutation failed; the receipt retains its recovery intent.',
    mutation_not_submitted: 'The provider proved that no mutation was submitted; review a fresh plan.',
    observation_failed: 'Live provider state could not be read safely.',
    ownership_conflict: 'Live ownership could not be proven from the receipt and resource marker.',
    pending_apply: 'Finish the pending apply operation before uninstalling.',
    pending_conflict: 'A pending operation cannot be recovered unambiguously.',
    pending_outcome_unknown: 'The pending create outcome is not visible yet and will not be replayed automatically.',
    pending_uninstall: 'Finish the pending uninstall operation before applying changes.',
    plan_blocked: 'The current plan has blockers and cannot be applied.',
    plan_changed: 'Live state changed after approval; review a fresh plan.',
    prune_approval_required: 'Prune requires the exact destructive-change approval.',
    receipt_invalid: 'The customer-owned installation receipt is invalid.',
    receipt_changed: 'The customer-owned installation receipt changed during the operation.',
    receipt_locked: 'Another receipt mutation is already in progress.',
    receipt_lock_failed: 'The customer-owned receipt could not be locked for mutation.',
    rollback_approval_required: 'Rollback requires the exact current pending-create recovery approval.',
    receipt_mismatch: 'The receipt belongs to a different installation.',
    receipt_read_failed: 'The customer-owned installation receipt could not be read.',
    receipt_required: 'A customer-owned installation receipt is required.',
    receipt_write_failed: 'The customer-owned installation receipt could not be persisted safely.',
    target_mismatch: 'Cloudflare returned a different account or zone than the selected target.',
    uninstall_approval_required: 'Uninstall requires the exact current uninstall approval.',
    verification_failed: 'The provider mutation could not be verified from fresh live state.',
  };
  return messages[code] ?? 'Gateway reconciliation failed.';
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
