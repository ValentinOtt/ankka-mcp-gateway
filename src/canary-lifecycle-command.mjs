import { inspectSyntheticEndpoint } from '../fixtures/synthetic-mcp/inspect.mjs';
import { validateCloudflareId } from './canary-command.mjs';
import { createCloudflareClient } from './cloudflare-client.mjs';
import { createCloudflareGatewayProvider } from './cloudflare-provider.mjs';
import {
  createFileReceiptStore,
  STALE_LOCK_RECOVERY_CONFIRMATION,
} from './receipt-store.mjs';
import {
  CanaryLifecycleError,
  previewCloudflareCanaryLifecycle,
  runCloudflareCanaryLifecycle,
} from './canary-runner.mjs';

const SAFE_SECRET = /^[^\u0000-\u001f\u007f]+$/;
const SAFE_APPROVAL = /^(?:canary-lifecycle|canary-target)-[0-9a-f]{24}$/;
const SAFE_LOCK_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const SAFE_OPERATION_ID = /^[a-z][a-z0-9._:-]{0,63}$/;
const LOCK_STORES = new Set(['receipt', 'cleanup']);

export class CanaryLifecycleCommandError extends Error {
  constructor(code) {
    const safeCode = [
      'invalid_invocation',
      'runtime_not_configured',
      'secret_unavailable',
      'command_failed',
    ].includes(code) ? code : 'command_failed';
    const messages = {
      invalid_invocation: 'The canary lifecycle command is invalid.',
      runtime_not_configured: 'The canary lifecycle runtime is not configured.',
      secret_unavailable:
        'Required canary values could not be read from the customer-controlled environment.',
      command_failed: 'The canary lifecycle command failed safely.',
    };
    super(messages[safeCode]);
    this.name = 'CanaryLifecycleCommandError';
    this.code = safeCode;
  }
}

export class CanaryLockCommandError extends Error {
  constructor(code) {
    const safeCode = [
      'invalid_invocation',
      'runtime_not_configured',
      'lock_not_found',
      'lock_live',
      'lock_ambiguous',
      'lock_id_mismatch',
      'lock_inspection_failed',
      'lock_recovery_failed',
    ].includes(code) ? code : 'lock_recovery_failed';
    const messages = {
      invalid_invocation: 'The canary lock command is invalid.',
      runtime_not_configured: 'The canary lock runtime is not configured.',
      lock_not_found: 'No lifecycle lock exists for the selected store.',
      lock_live: 'The selected lifecycle lock belongs to a live process and was not removed.',
      lock_ambiguous: 'The selected lifecycle lock is ambiguous and was not removed.',
      lock_id_mismatch: 'The freshly inspected lifecycle lock does not match the approved lock ID.',
      lock_inspection_failed: 'The lifecycle lock could not be inspected safely.',
      lock_recovery_failed: 'The stale lifecycle lock was not removed.',
    };
    super(messages[safeCode]);
    this.name = 'CanaryLockCommandError';
    this.code = safeCode;
  }
}

/**
 * Inspect or explicitly recover one local lifecycle lock without reading any
 * Cloudflare or Access secrets. Recovery is bound to a fresh inspection and
 * the receipt store performs its own final evidence/file-identity recheck.
 */
export async function executeCanaryLockCommand(invocation = {}, dependencies = {}) {
  const parsed = validateLockInvocation(invocation);
  const runtime = validateLockDependencies(dependencies);
  const storePath = parsed.store === 'receipt'
    ? parsed.receiptPath
    : `${parsed.receiptPath}.cleanup-recovery`;
  let store;
  try {
    store = runtime.receiptStoreFactory(storePath);
  } catch {
    throw new CanaryLockCommandError('runtime_not_configured');
  }
  if (
    !isObject(store) ||
    typeof store.inspectLock !== 'function' ||
    (parsed.operation === 'recover' && typeof store.recoverStaleLock !== 'function')
  ) {
    throw new CanaryLockCommandError('runtime_not_configured');
  }

  let rawInspection;
  try {
    rawInspection = await store.inspectLock();
  } catch {
    throw new CanaryLockCommandError('lock_inspection_failed');
  }
  const inspection = sanitizeLockInspection(rawInspection, parsed.store);

  if (parsed.operation === 'inspect') {
    const report = Object.freeze({
      schemaVersion: 1,
      kind: 'canary_lock_inspection',
      store: parsed.store,
      ...inspection,
      lockRemoved: false,
    });
    return Object.freeze({
      report,
      output: parsed.json ? JSON.stringify(report, null, 2) : renderCanaryLockInspection(report),
      exitCode: 0,
    });
  }

  if (inspection.status === 'not_found') {
    throw new CanaryLockCommandError('lock_not_found');
  }
  if (inspection.status === 'live') {
    throw new CanaryLockCommandError('lock_live');
  }
  if (inspection.status !== 'stale_candidate') {
    throw new CanaryLockCommandError('lock_ambiguous');
  }
  if (inspection.lockId !== parsed.lockId) {
    throw new CanaryLockCommandError('lock_id_mismatch');
  }
  if (!isObject(rawInspection?.evidence) || rawInspection.evidence.lockId !== parsed.lockId) {
    throw new CanaryLockCommandError('lock_ambiguous');
  }

  let removed;
  try {
    removed = await store.recoverStaleLock({
      evidence: rawInspection.evidence,
      confirmation: STALE_LOCK_RECOVERY_CONFIRMATION,
    });
  } catch (error) {
    if (error?.code === 'lock_live') throw new CanaryLockCommandError('lock_live');
    if (error?.code === 'lock_ambiguous') throw new CanaryLockCommandError('lock_ambiguous');
    throw new CanaryLockCommandError('lock_recovery_failed');
  }
  if (removed?.status !== 'removed' || removed.lockId !== parsed.lockId) {
    throw new CanaryLockCommandError('lock_recovery_failed');
  }
  const report = Object.freeze({
    schemaVersion: 1,
    kind: 'canary_lock_recovery_result',
    store: parsed.store,
    status: 'removed',
    lockId: parsed.lockId,
    lockRemoved: true,
  });
  return Object.freeze({
    report,
    output: parsed.json ? JSON.stringify(report, null, 2) : renderCanaryLockRecovery(report),
    exitCode: 0,
  });
}

export function renderCanaryLockInspection(report) {
  if (report?.kind !== 'canary_lock_inspection') {
    throw new TypeError('report must be a canary lock inspection');
  }
  const lines = [
    `Canary lifecycle lock (${lockStoreLabel(report.store)}): ${lockStatusLabel(report.status)}`,
  ];
  if (typeof report.lockId === 'string') lines.push(`Lock ID: ${report.lockId}`);
  if (typeof report.operationId === 'string') lines.push(`Operation: ${report.operationId}`);
  if (typeof report.createdAt === 'string') lines.push(`Created: ${report.createdAt}`);
  lines.push('No lock was removed.');
  return lines.join('\n');
}

export function renderCanaryLockRecovery(report) {
  if (report?.kind !== 'canary_lock_recovery_result') {
    throw new TypeError('report must be a canary lock recovery result');
  }
  return [
    `Canary lifecycle lock (${lockStoreLabel(report.store)}): REMOVED`,
    `Lock ID: ${report.lockId}`,
  ].join('\n');
}

/**
 * CLI-facing composition. Cloudflare credentials and the Access email are read
 * only through closures/environment and are never accepted in the invocation,
 * returned report, or rendered output.
 */
export async function executeCanaryLifecycleCommand(invocation = {}, dependencies = {}) {
  const parsed = validateInvocation(invocation);
  const runtime = validateDependencies(dependencies, parsed.mode);
  let token;
  let allowedEmail;
  try {
    token = await runtime.readToken();
    allowedEmail = await runtime.readAllowedEmail();
  } catch {
    throw new CanaryLifecycleCommandError('secret_unavailable');
  }
  if (!validSecret(token) || !validSecret(allowedEmail)) {
    throw new CanaryLifecycleCommandError('secret_unavailable');
  }

  let cloudflare;
  let provider;
  let receiptStore;
  let cleanupStore;
  try {
    const providerOptions = {
      token,
      accountId: parsed.accountId,
      zoneId: parsed.zoneId,
      fetchImpl: runtime.fetchImpl,
    };
    cloudflare = runtime.clientFactory(providerOptions);
    provider = runtime.providerFactory(providerOptions);
    receiptStore = runtime.receiptStoreFactory(parsed.receiptPath);
    cleanupStore = runtime.receiptStoreFactory(`${parsed.receiptPath}.cleanup-recovery`);
  } catch {
    throw new CanaryLifecycleCommandError('runtime_not_configured');
  } finally {
    token = undefined;
  }

  const input = {
    accountId: parsed.accountId,
    zoneId: parsed.zoneId,
    hostname: parsed.hostname,
    syntheticMcpUrl: parsed.syntheticMcpUrl,
    allowedEmail,
    ...(parsed.mode === 'run'
      ? {
          approvalId: parsed.approvalId,
          targetConfirmationId: parsed.targetConfirmationId,
        }
      : {}),
  };
  allowedEmail = undefined;
  const runnerDependencies = {
    cloudflare,
    provider,
    receiptStore,
    cleanupStore,
    inspectSyntheticUpstream: ({ endpoint }) =>
      runtime.inspectSyntheticUpstream(endpoint, { fetchImpl: runtime.fetchImpl }),
    ...(parsed.mode === 'run'
      ? {
          verifyInstalledGateway: runtime.verifyInstalledGateway,
          ...(runtime.holdForInspection
            ? { holdForInspection: runtime.holdForInspection }
            : {}),
          inspectCanaryResidue: provider.inspectCanaryResidue?.bind(provider),
        }
      : {}),
    sleep: runtime.sleep,
    onProgress: runtime.onProgress,
  };

  let report;
  try {
    report = parsed.mode === 'preview'
      ? await previewCloudflareCanaryLifecycle(input, runnerDependencies)
      : await runCloudflareCanaryLifecycle(input, runnerDependencies);
  } catch (error) {
    if (error instanceof CanaryLifecycleError) throw error;
    throw new CanaryLifecycleCommandError('command_failed');
  }
  return Object.freeze({
    report,
    output: parsed.json
      ? JSON.stringify(report, null, 2)
      : parsed.mode === 'preview'
        ? renderLifecyclePreview(report)
        : renderLifecycleResult(report),
    exitCode: parsed.mode === 'preview' ? 0 : lifecycleResultExitCode(report),
  });
}

export function lifecycleResultExitCode(report) {
  if (report?.kind !== 'cloudflare_canary_lifecycle_result') {
    throw new TypeError('report must be a canary lifecycle result');
  }
  if (
    report.status === 'cleanup_complete' &&
    report.operation === 'cleanup_partial_install' &&
    report.resourceLifecycle === 'removed' &&
    report.interactiveVerification === 'not_applicable' &&
    report.cleanup?.status === 'removed' &&
    report.cleanup?.partialInstallRemoved === true &&
    report.cleanup?.ownedResourceCount === 0
  ) {
    return 0;
  }
  if (
    report.status === 'rollback_complete' &&
    report.operation === 'rollback_pending_portal_create' &&
    report.resourceLifecycle === 'partial' &&
    report.cleanup?.status === 'rollback_complete' &&
    Number.isSafeInteger(report.cleanup.remainingReceiptResourceCount) &&
    report.cleanup.remainingReceiptResourceCount >= 0
  ) {
    return 0;
  }
  return report.status === 'complete' &&
    report.installedStateVerified === true &&
    report.idempotentApplyVerified === true &&
    report.portalToolCallVerified === true &&
    report.resourceLifecycle === 'removed' &&
    report.interactiveVerification === 'verified' &&
    report.cleanup?.status === 'removed' &&
    report.cleanup?.ownedResourceCount === 0
    ? 0
    : 3;
}

export function renderLifecyclePreview(report) {
  if (report?.kind !== 'cloudflare_canary_lifecycle_preview') {
    throw new TypeError('report must be a canary lifecycle preview');
  }
  if (report.operation === 'rollback_pending_portal_create') {
    return [
      'Cloudflare disposable canary: PENDING PORTAL ROLLBACK READY FOR REVIEW',
      '',
      `Lifecycle approval: ${report.approvalId}`,
      `Disposable-target confirmation: ${report.targetConfirmationId}`,
      '',
      'Recovery preview:',
      '  - rollback exact pending-created portal',
      '',
      'No Cloudflare resources were changed. A successful run stops for a fresh preview.',
    ].join('\n');
  }
  if (report.operation === 'cleanup_partial_install') {
    return [
      'Cloudflare disposable canary: PARTIAL INSTALL CLEANUP READY FOR REVIEW',
      '',
      `Lifecycle approval: ${report.approvalId}`,
      `Disposable-target confirmation: ${report.targetConfirmationId}`,
      '',
      'Receipt-owned cleanup preview:',
      ...report.cleanup.map(({ action, kind }) => `  - ${action} ${kind}`),
      '',
      'No Cloudflare resources were changed. This operation only removes the exact receipt-owned partial install.',
    ].join('\n');
  }
  return [
    'Cloudflare disposable canary: READY FOR REVIEW',
    '',
    `Lifecycle approval: ${report.approvalId}`,
    `Disposable-target confirmation: ${report.targetConfirmationId}`,
    '',
    'Apply preview:',
    ...report.changes.map(({ action, kind }) => `  - ${action} ${kind}`),
    '',
    'Planned receipt-owned cleanup:',
    ...report.cleanup.map(({ action, kind }) => `  - ${action} ${kind}`),
    '',
    'No Cloudflare resources were changed.',
  ].join('\n');
}

export function renderLifecycleResult(report) {
  if (report?.kind !== 'cloudflare_canary_lifecycle_result') {
    throw new TypeError('report must be a canary lifecycle result');
  }
  if (report.status === 'rollback_complete') {
    return [
      'Cloudflare disposable canary: PENDING PORTAL ROLLBACK COMPLETE',
      '',
      'The exact partial Portal was removed and its pending receipt action was cleared.',
      `Receipt-owned resources retained: ${safeCount(report.cleanup?.remainingReceiptResourceCount)}`,
      'Run a fresh preview before retrying deployment or cleanup.',
    ].join('\n');
  }
  if (
    report.status === 'cleanup_complete' &&
    report.operation === 'cleanup_partial_install'
  ) {
    return [
      'Cloudflare disposable canary: PARTIAL INSTALL CLEANUP COMPLETE',
      '',
      'The exact receipt-owned partial installation was removed in reverse dependency order.',
      `Owned resources remaining: ${safeCount(report.cleanup?.ownedResourceCount)}`,
      'The checksum-protected receipt tombstone was retained.',
    ].join('\n');
  }
  const fullyVerified = lifecycleResultExitCode(report) === 0;
  return [
    fullyVerified
      ? 'Cloudflare disposable canary: COMPLETE'
      : 'Cloudflare disposable canary: RESOURCE LIFECYCLE REMOVED',
    '',
    `Resource lifecycle: ${report.resourceLifecycle === 'removed' ? 'removed' : 'incomplete'}`,
    `Installed provider state verified: ${report.installedStateVerified === true ? 'yes' : 'no'}`,
    `Interactive Portal tool call: ${report.portalToolCallVerified === true ? 'verified' : 'pending'}`,
    `Idempotent apply verified: ${report.idempotentApplyVerified === true ? 'yes' : 'no'}`,
    `Receipt-owned cleanup: ${report.cleanup?.status === 'removed' ? 'removed' : 'incomplete'}`,
    `Owned resources remaining: ${safeCount(report.cleanup?.ownedResourceCount)}`,
    ...(fullyVerified ? [] : ['', 'Interactive Portal verification is still pending.']),
  ].join('\n');
}

function validateInvocation(value) {
  if (!isObject(value)) throw new CanaryLifecycleCommandError('invalid_invocation');
  const allowed = [
    'mode',
    'accountId',
    'zoneId',
    'hostname',
    'syntheticMcpUrl',
    'receiptPath',
    'approvalId',
    'targetConfirmationId',
    'json',
  ];
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    throw new CanaryLifecycleCommandError('invalid_invocation');
  }
  if (!['preview', 'run'].includes(value.mode)) {
    throw new CanaryLifecycleCommandError('invalid_invocation');
  }
  for (const field of [
    'accountId',
    'zoneId',
    'hostname',
    'syntheticMcpUrl',
    'receiptPath',
  ]) {
    if (typeof value[field] !== 'string' || value[field].length === 0) {
      throw new CanaryLifecycleCommandError('invalid_invocation');
    }
  }
  if (typeof value.json !== 'undefined' && typeof value.json !== 'boolean') {
    throw new CanaryLifecycleCommandError('invalid_invocation');
  }
  if (value.mode === 'preview') {
    if (value.approvalId !== undefined || value.targetConfirmationId !== undefined) {
      throw new CanaryLifecycleCommandError('invalid_invocation');
    }
  } else if (
    typeof value.approvalId !== 'string' ||
    !SAFE_APPROVAL.test(value.approvalId) ||
    typeof value.targetConfirmationId !== 'string' ||
    !SAFE_APPROVAL.test(value.targetConfirmationId)
  ) {
    throw new CanaryLifecycleCommandError('invalid_invocation');
  }
  try {
    validateCloudflareId(value.accountId, 'account');
    validateCloudflareId(value.zoneId, 'zone');
  } catch {
    throw new CanaryLifecycleCommandError('invalid_invocation');
  }
  return {
    ...value,
    accountId: value.accountId.toLowerCase(),
    zoneId: value.zoneId.toLowerCase(),
    json: value.json === true,
  };
}

function validateLockInvocation(value) {
  if (!isObject(value)) throw new CanaryLockCommandError('invalid_invocation');
  const allowed = [
    'operation',
    'store',
    'receiptPath',
    'lockId',
    'confirmation',
    'json',
  ];
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    throw new CanaryLockCommandError('invalid_invocation');
  }
  if (!['inspect', 'recover'].includes(value.operation) || !LOCK_STORES.has(value.store)) {
    throw new CanaryLockCommandError('invalid_invocation');
  }
  if (typeof value.receiptPath !== 'string' || value.receiptPath.length === 0) {
    throw new CanaryLockCommandError('invalid_invocation');
  }
  if (typeof value.json !== 'undefined' && typeof value.json !== 'boolean') {
    throw new CanaryLockCommandError('invalid_invocation');
  }
  if (value.operation === 'inspect') {
    if (value.lockId !== undefined || value.confirmation !== undefined) {
      throw new CanaryLockCommandError('invalid_invocation');
    }
  } else if (
    typeof value.lockId !== 'string' ||
    !SAFE_LOCK_ID.test(value.lockId) ||
    value.confirmation !== STALE_LOCK_RECOVERY_CONFIRMATION
  ) {
    throw new CanaryLockCommandError('invalid_invocation');
  }
  return { ...value, json: value.json === true };
}

function validateDependencies(value, mode) {
  if (!isObject(value)) throw new CanaryLifecycleCommandError('runtime_not_configured');
  const allowed = [
    'readToken',
    'readAllowedEmail',
    'clientFactory',
    'providerFactory',
    'receiptStoreFactory',
    'inspectSyntheticUpstream',
    'verifyInstalledGateway',
    'holdForInspection',
    'fetchImpl',
    'sleep',
    'onProgress',
  ];
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    throw new CanaryLifecycleCommandError('runtime_not_configured');
  }
  const runtime = {
    readToken: value.readToken ?? (() => process.env.CLOUDFLARE_API_TOKEN),
    readAllowedEmail: value.readAllowedEmail ?? (() => process.env.ANKKA_CANARY_ALLOWED_EMAIL),
    clientFactory: value.clientFactory ?? createCloudflareClient,
    providerFactory: value.providerFactory ?? createCloudflareGatewayProvider,
    receiptStoreFactory: value.receiptStoreFactory ?? createFileReceiptStore,
    inspectSyntheticUpstream: value.inspectSyntheticUpstream ?? inspectSyntheticEndpoint,
    verifyInstalledGateway: value.verifyInstalledGateway,
    holdForInspection: value.holdForInspection,
    fetchImpl: value.fetchImpl ?? globalThis.fetch,
    sleep: value.sleep ?? ((milliseconds) =>
      new Promise((resolve) => setTimeout(resolve, milliseconds))),
    onProgress: value.onProgress,
  };
  const required = [
    'readToken',
    'readAllowedEmail',
    'clientFactory',
    'providerFactory',
    'receiptStoreFactory',
    'inspectSyntheticUpstream',
    'fetchImpl',
    'sleep',
  ];
  if (required.some((field) => typeof runtime[field] !== 'function')) {
    throw new CanaryLifecycleCommandError('runtime_not_configured');
  }
  if (runtime.onProgress !== undefined && typeof runtime.onProgress !== 'function') {
    throw new CanaryLifecycleCommandError('runtime_not_configured');
  }
  if (
    runtime.holdForInspection !== undefined &&
    typeof runtime.holdForInspection !== 'function'
  ) {
    throw new CanaryLifecycleCommandError('runtime_not_configured');
  }
  return runtime;
}

function validateLockDependencies(value) {
  if (!isObject(value)) throw new CanaryLockCommandError('runtime_not_configured');
  const allowed = ['receiptStoreFactory'];
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    throw new CanaryLockCommandError('runtime_not_configured');
  }
  const receiptStoreFactory = value.receiptStoreFactory ?? createFileReceiptStore;
  if (typeof receiptStoreFactory !== 'function') {
    throw new CanaryLockCommandError('runtime_not_configured');
  }
  return { receiptStoreFactory };
}

function sanitizeLockInspection(value, store) {
  if (value === null) return Object.freeze({ status: 'not_found' });
  if (!isObject(value) || !['live', 'stale_candidate', 'ambiguous'].includes(value.status)) {
    throw new CanaryLockCommandError('lock_inspection_failed');
  }
  if (value.status === 'ambiguous') return Object.freeze({ status: 'ambiguous' });
  const metadata = value.metadata;
  if (
    !isObject(metadata) ||
    typeof metadata.lockId !== 'string' ||
    !SAFE_LOCK_ID.test(metadata.lockId) ||
    typeof metadata.operationId !== 'string' ||
    !SAFE_OPERATION_ID.test(metadata.operationId) ||
    typeof metadata.createdAt !== 'string' ||
    !isCanonicalIsoDate(metadata.createdAt)
  ) {
    throw new CanaryLockCommandError('lock_inspection_failed');
  }
  return Object.freeze({
    status: value.status,
    lockId: metadata.lockId,
    operationId: metadata.operationId,
    createdAt: metadata.createdAt,
  });
}

function isCanonicalIsoDate(value) {
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value;
}

function lockStoreLabel(value) {
  return value === 'receipt' ? 'receipt' : 'cleanup sidecar';
}

function lockStatusLabel(value) {
  if (value === 'not_found') return 'NOT FOUND';
  if (value === 'live') return 'LIVE';
  if (value === 'stale_candidate') return 'STALE CANDIDATE';
  return 'AMBIGUOUS';
}

function validSecret(value) {
  return typeof value === 'string' && value.length > 0 && SAFE_SECRET.test(value);
}

function safeCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
