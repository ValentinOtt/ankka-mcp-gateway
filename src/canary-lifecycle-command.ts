import { inspectSyntheticEndpoint } from '../fixtures/synthetic-mcp/inspect.mjs';
import * as v from 'valibot';

import { validateCloudflareId } from './canary-command.ts';
import { createCloudflareClient, type CloudflareFetch } from './cloudflare-client.ts';
import { createCloudflareGatewayProvider } from './cloudflare-provider.ts';
import { boundaryObjectSchema, type BoundaryValue } from './json.ts';
import {
  createFileReceiptStore,
  STALE_LOCK_RECOVERY_CONFIRMATION,
  type FileReceiptStore,
  type LockInspection,
  type LockMetadata,
} from './receipt-store.ts';
import {
  CanaryLifecycleError,
  previewCloudflareCanaryLifecycle,
  runCloudflareCanaryLifecycle,
} from './canary-runner.ts';

const SAFE_APPROVAL = /^(?:canary-lifecycle|canary-target)-[0-9a-f]{24}$/;
const SAFE_LOCK_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const SAFE_OPERATION_ID = /^[a-z][a-z0-9._:-]{0,63}$/;
const LOCK_STORES = new Set(['receipt', 'cleanup']);
const stringSchema = v.string();
const numberSchema = v.number();
const functionSchema = v.function();
const codedErrorSchema = v.object({ code: stringSchema });
const lifecycleCommandCodeSchema = v.picklist([
  'invalid_invocation',
  'runtime_not_configured',
  'secret_unavailable',
  'command_failed',
]);
const lockCommandCodeSchema = v.picklist([
  'invalid_invocation',
  'runtime_not_configured',
  'lock_not_found',
  'lock_live',
  'lock_ambiguous',
  'lock_id_mismatch',
  'lock_inspection_failed',
  'lock_recovery_failed',
]);

type LifecycleCommandCode = v.InferOutput<typeof lifecycleCommandCodeSchema>;
type LockCommandCode = v.InferOutput<typeof lockCommandCodeSchema>;
type RunnerDependencies = NonNullable<Parameters<typeof runCloudflareCanaryLifecycle>[1]>;
type LifecyclePreviewReport = Awaited<ReturnType<typeof previewCloudflareCanaryLifecycle>>;
type LifecycleResultReport = Awaited<ReturnType<typeof runCloudflareCanaryLifecycle>>;
type CloudflareClient = ReturnType<typeof createCloudflareClient>;
type GatewayProvider = ReturnType<typeof createCloudflareGatewayProvider>;
type ReceiptStoreFactory = (path: string) => FileReceiptStore;
type LockStore = 'cleanup' | 'receipt';

export interface LifecycleInvocation {
  readonly accountId?: BoundaryValue;
  readonly allowedEmail?: never;
  readonly approvalId?: BoundaryValue;
  readonly hostname?: BoundaryValue;
  readonly json?: BoundaryValue;
  readonly mode?: BoundaryValue;
  readonly receiptPath?: BoundaryValue;
  readonly syntheticMcpUrl?: BoundaryValue;
  readonly targetConfirmationId?: BoundaryValue;
  readonly zoneId?: BoundaryValue;
}

interface ParsedLifecycleInvocationBase {
  readonly accountId: string;
  readonly hostname: string;
  readonly json: boolean;
  readonly receiptPath: string;
  readonly syntheticMcpUrl: string;
  readonly zoneId: string;
}

type ParsedLifecycleInvocation =
  | (ParsedLifecycleInvocationBase & { readonly mode: 'preview' })
  | (ParsedLifecycleInvocationBase & {
    readonly approvalId: string;
    readonly mode: 'run';
    readonly targetConfirmationId: string;
  });

export interface LockInvocation {
  readonly confirmation?: BoundaryValue;
  readonly json?: BoundaryValue;
  readonly lockId?: BoundaryValue;
  readonly operation?: BoundaryValue;
  readonly receiptPath?: BoundaryValue;
  readonly store?: BoundaryValue;
}

type ParsedLockInvocation =
  | {
    readonly json: boolean;
    readonly operation: 'inspect';
    readonly receiptPath: string;
    readonly store: LockStore;
  }
  | {
    readonly confirmation: typeof STALE_LOCK_RECOVERY_CONFIRMATION;
    readonly json: boolean;
    readonly lockId: string;
    readonly operation: 'recover';
    readonly receiptPath: string;
    readonly store: LockStore;
  };

interface LifecycleDependencies {
  readonly clientFactory?: (options: ProviderOptions) => CloudflareClient;
  readonly fetchImpl?: CloudflareFetch;
  readonly holdForInspection?: RunnerDependencies['holdForInspection'];
  readonly inspectSyntheticUpstream?: typeof inspectSyntheticEndpoint;
  readonly onProgress?: RunnerDependencies['onProgress'];
  readonly providerFactory?: (options: ProviderOptions) => GatewayProvider;
  readonly readAllowedEmail?: SecretReader;
  readonly readToken?: SecretReader;
  readonly receiptStoreFactory?: ReceiptStoreFactory;
  readonly sleep?: RunnerDependencies['sleep'];
  readonly verifyInstalledGateway?: RunnerDependencies['verifyInstalledGateway'];
}

interface NormalizedLifecycleDependencies {
  readonly clientFactory: (options: ProviderOptions) => CloudflareClient;
  readonly fetchImpl: CloudflareFetch;
  readonly holdForInspection: RunnerDependencies['holdForInspection'];
  readonly inspectSyntheticUpstream: typeof inspectSyntheticEndpoint;
  readonly onProgress: RunnerDependencies['onProgress'];
  readonly providerFactory: (options: ProviderOptions) => GatewayProvider;
  readonly readAllowedEmail: SecretReader;
  readonly readToken: SecretReader;
  readonly receiptStoreFactory: ReceiptStoreFactory;
  readonly sleep: NonNullable<RunnerDependencies['sleep']>;
  readonly verifyInstalledGateway: RunnerDependencies['verifyInstalledGateway'];
}

interface LockDependencies {
  readonly receiptStoreFactory?: ReceiptStoreFactory;
}

interface NormalizedLockDependencies {
  readonly receiptStoreFactory: ReceiptStoreFactory;
}

interface ProviderOptions {
  readonly accountId: string;
  readonly fetchImpl: CloudflareFetch;
  readonly token: string;
  readonly zoneId: string;
}

type SecretReader = () => BoundaryValue | Promise<BoundaryValue>;

type SanitizedLockInspection =
  | { readonly status: 'ambiguous' | 'not_found' }
  | {
    readonly createdAt: string;
    readonly lockId: string;
    readonly operationId: string;
    readonly status: 'live' | 'stale_candidate';
  };

interface LockInspectionReport {
  readonly createdAt?: string;
  readonly kind: 'canary_lock_inspection';
  readonly lockId?: string;
  readonly lockRemoved: false;
  readonly operationId?: string;
  readonly schemaVersion: 1;
  readonly status: 'ambiguous' | 'live' | 'not_found' | 'stale_candidate';
  readonly store: LockStore;
}

interface LockRecoveryReport {
  readonly kind: 'canary_lock_recovery_result';
  readonly lockId: string;
  readonly lockRemoved: true;
  readonly schemaVersion: 1;
  readonly status: 'removed';
  readonly store: LockStore;
}

export class CanaryLifecycleCommandError extends Error {
  readonly code: LifecycleCommandCode;

  constructor(code: BoundaryValue) {
    const safeCode = v.is(lifecycleCommandCodeSchema, code) ? code : 'command_failed';
    const messages = new Map<LifecycleCommandCode, string>([
      ['invalid_invocation', 'The canary lifecycle command is invalid.'],
      ['runtime_not_configured', 'The canary lifecycle runtime is not configured.'],
      [
        'secret_unavailable',
        'Required canary values could not be read from the customer-controlled environment.',
      ],
      ['command_failed', 'The canary lifecycle command failed safely.'],
    ]);
    super(messages.get(safeCode));
    this.name = 'CanaryLifecycleCommandError';
    this.code = safeCode;
  }
}

export class CanaryLockCommandError extends Error {
  readonly code: LockCommandCode;

  constructor(code: BoundaryValue) {
    const safeCode = v.is(lockCommandCodeSchema, code) ? code : 'lock_recovery_failed';
    const messages = new Map<LockCommandCode, string>([
      ['invalid_invocation', 'The canary lock command is invalid.'],
      ['runtime_not_configured', 'The canary lock runtime is not configured.'],
      ['lock_not_found', 'No lifecycle lock exists for the selected store.'],
      ['lock_live', 'The selected lifecycle lock belongs to a live process and was not removed.'],
      ['lock_ambiguous', 'The selected lifecycle lock is ambiguous and was not removed.'],
      ['lock_id_mismatch', 'The freshly inspected lifecycle lock does not match the approved lock ID.'],
      ['lock_inspection_failed', 'The lifecycle lock could not be inspected safely.'],
      ['lock_recovery_failed', 'The stale lifecycle lock was not removed.'],
    ]);
    super(messages.get(safeCode));
    this.name = 'CanaryLockCommandError';
    this.code = safeCode;
  }
}

/**
 * Inspect or explicitly recover one local lifecycle lock without reading any
 * Cloudflare or Access secrets. Recovery is bound to a fresh inspection and
 * the receipt store performs its own final evidence/file-identity recheck.
 */
export async function executeCanaryLockCommand(
  invocation: LockInvocation = {},
  dependencies: LockDependencies = {},
) {
  const parsed = validateLockInvocation(invocation);
  const runtime = validateLockDependencies(dependencies);
  const storePath = parsed.store === 'receipt'
    ? parsed.receiptPath
    : `${parsed.receiptPath}.cleanup-recovery`;
  let store: FileReceiptStore;
  try {
    store = runtime.receiptStoreFactory(storePath);
  } catch {
    throw new CanaryLockCommandError('runtime_not_configured');
  }
  if (
    !v.is(v.object({}), store) ||
    !v.is(functionSchema, store.inspectLock) ||
    (parsed.operation === 'recover' && !v.is(functionSchema, store.recoverStaleLock))
  ) {
    throw new CanaryLockCommandError('runtime_not_configured');
  }

  let rawInspection: LockInspection | null;
  try {
    rawInspection = await store.inspectLock();
  } catch {
    throw new CanaryLockCommandError('lock_inspection_failed');
  }
  const inspection = sanitizeLockInspection(rawInspection);

  if (parsed.operation === 'inspect') {
    const report: LockInspectionReport = Object.freeze({
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
  const evidence = rawInspection?.evidence;
  if (!validLockEvidence(evidence, parsed.lockId)) {
    throw new CanaryLockCommandError('lock_ambiguous');
  }

  let removed: Awaited<ReturnType<FileReceiptStore['recoverStaleLock']>>;
  try {
    removed = await store.recoverStaleLock({
      evidence,
      confirmation: STALE_LOCK_RECOVERY_CONFIRMATION,
    });
  } catch (error) {
    if (v.is(codedErrorSchema, error) && error.code === 'lock_live') {
      throw new CanaryLockCommandError('lock_live');
    }
    if (v.is(codedErrorSchema, error) && error.code === 'lock_ambiguous') {
      throw new CanaryLockCommandError('lock_ambiguous');
    }
    throw new CanaryLockCommandError('lock_recovery_failed');
  }
  if (removed?.status !== 'removed' || removed.lockId !== parsed.lockId) {
    throw new CanaryLockCommandError('lock_recovery_failed');
  }
  const report: LockRecoveryReport = Object.freeze({
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

export function renderCanaryLockInspection(report: LockInspectionReport): string {
  if (report.kind !== 'canary_lock_inspection') {
    throw new TypeError('report must be a canary lock inspection');
  }
  const lines = [
    `Canary lifecycle lock (${lockStoreLabel(report.store)}): ${lockStatusLabel(report.status)}`,
  ];
  if (report.lockId !== undefined) lines.push(`Lock ID: ${report.lockId}`);
  if (report.operationId !== undefined) lines.push(`Operation: ${report.operationId}`);
  if (report.createdAt !== undefined) lines.push(`Created: ${report.createdAt}`);
  lines.push('No lock was removed.');
  return lines.join('\n');
}

export function renderCanaryLockRecovery(report: LockRecoveryReport): string {
  if (report.kind !== 'canary_lock_recovery_result') {
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
export async function executeCanaryLifecycleCommand(
  invocation: LifecycleInvocation = {},
  dependencies: LifecycleDependencies = {},
) {
  const parsed = validateInvocation(invocation);
  const runtime = validateDependencies(dependencies);
  let token: BoundaryValue;
  let allowedEmail: BoundaryValue;
  try {
    token = await runtime.readToken();
    allowedEmail = await runtime.readAllowedEmail();
  } catch {
    throw new CanaryLifecycleCommandError('secret_unavailable');
  }
  if (!validSecret(token) || !validSecret(allowedEmail)) {
    throw new CanaryLifecycleCommandError('secret_unavailable');
  }

  let cloudflare: CloudflareClient;
  let provider: GatewayProvider;
  let receiptStore: FileReceiptStore;
  let cleanupStore: FileReceiptStore;
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

  const baseInput = {
    accountId: parsed.accountId,
    zoneId: parsed.zoneId,
    hostname: parsed.hostname,
    syntheticMcpUrl: parsed.syntheticMcpUrl,
    allowedEmail,
  };
  const input = parsed.mode === 'run'
    ? {
      ...baseInput,
      approvalId: parsed.approvalId,
      targetConfirmationId: parsed.targetConfirmationId,
    }
    : baseInput;
  allowedEmail = undefined;
  const reconcilerProvider: NonNullable<RunnerDependencies['provider']> = {
    readObservedState: async (providerInput) => v.parse(
      boundaryObjectSchema,
      await provider.readObservedState(providerInput),
    ),
    applyChange: (providerInput) => provider.applyChange(
      v.parse(boundaryObjectSchema, providerInput),
    ),
    inspectPendingPortalCreateRollback: (providerInput) =>
      provider.inspectPendingPortalCreateRollback(
        v.parse(boundaryObjectSchema, providerInput),
      ),
    rollbackPendingPortalCreate: (providerInput) => provider.rollbackPendingPortalCreate(
      v.parse(boundaryObjectSchema, providerInput),
    ),
  };
  const runnerDependencies: RunnerDependencies = {
    cloudflare,
    provider: reconcilerProvider,
    receiptStore,
    cleanupStore,
    inspectSyntheticUpstream: async ({ endpoint }: { readonly endpoint: string }) => v.parse(
      boundaryObjectSchema,
      await runtime.inspectSyntheticUpstream(endpoint, { fetchImpl: runtime.fetchImpl }),
    ),
    inspectCanaryResidue: parsed.mode === 'run'
      ? async (residueInput) => v.parse(
        boundaryObjectSchema,
        await provider.inspectCanaryResidue(v.parse(boundaryObjectSchema, residueInput)),
      )
      : undefined,
    holdForInspection: parsed.mode === 'run' ? runtime.holdForInspection : undefined,
    verifyInstalledGateway: parsed.mode === 'run'
      ? runtime.verifyInstalledGateway
      : undefined,
    onProgress: runtime.onProgress,
    sleep: runtime.sleep,
  };

  try {
    if (parsed.mode === 'preview') {
      const report = await previewCloudflareCanaryLifecycle(input, runnerDependencies);
      return Object.freeze({
        report,
        output: parsed.json
          ? JSON.stringify(report, null, 2)
          : renderLifecyclePreview(report),
        exitCode: 0,
      });
    }
    const report = await runCloudflareCanaryLifecycle(input, runnerDependencies);
    return Object.freeze({
      report,
      output: parsed.json
        ? JSON.stringify(report, null, 2)
        : renderLifecycleResult(report),
      exitCode: lifecycleResultExitCode(report),
    });
  } catch (error) {
    if (error instanceof CanaryLifecycleError) throw error;
    throw new CanaryLifecycleCommandError('command_failed');
  }
}

export function lifecycleResultExitCode(report: LifecycleResultReport): 0 | 3 {
  if (report.kind !== 'cloudflare_canary_lifecycle_result') {
    throw new TypeError('report must be a canary lifecycle result');
  }
  const remainingReceiptResourceCount = report.cleanup.remainingReceiptResourceCount;
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
    remainingReceiptResourceCount !== undefined &&
    Number.isSafeInteger(remainingReceiptResourceCount) &&
    remainingReceiptResourceCount >= 0
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

export function renderLifecyclePreview(report: LifecyclePreviewReport): string {
  if (report.kind !== 'cloudflare_canary_lifecycle_preview') {
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

export function renderLifecycleResult(report: LifecycleResultReport): string {
  if (report.kind !== 'cloudflare_canary_lifecycle_result') {
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
  const lines = [
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
  ];
  if (!fullyVerified) lines.push('', 'Interactive Portal verification is still pending.');
  return lines.join('\n');
}

function validateInvocation(value: LifecycleInvocation): ParsedLifecycleInvocation {
  if (!v.is(v.object({}), value)) {
    throw new CanaryLifecycleCommandError('invalid_invocation');
  }
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
  if (!v.is(v.picklist(['preview', 'run']), value.mode)) {
    throw new CanaryLifecycleCommandError('invalid_invocation');
  }
  if (
    !v.is(stringSchema, value.accountId) || value.accountId.length === 0 ||
    !v.is(stringSchema, value.zoneId) || value.zoneId.length === 0 ||
    !v.is(stringSchema, value.hostname) || value.hostname.length === 0 ||
    !v.is(stringSchema, value.syntheticMcpUrl) || value.syntheticMcpUrl.length === 0 ||
    !v.is(stringSchema, value.receiptPath) || value.receiptPath.length === 0
  ) {
    throw new CanaryLifecycleCommandError('invalid_invocation');
  }
  if (value.json !== undefined && !v.is(v.boolean(), value.json)) {
    throw new CanaryLifecycleCommandError('invalid_invocation');
  }
  let approvalId: string | undefined;
  let targetConfirmationId: string | undefined;
  if (value.mode === 'preview') {
    if (value.approvalId !== undefined || value.targetConfirmationId !== undefined) {
      throw new CanaryLifecycleCommandError('invalid_invocation');
    }
  } else if (
    !v.is(stringSchema, value.approvalId) ||
    !SAFE_APPROVAL.test(value.approvalId) ||
    !v.is(stringSchema, value.targetConfirmationId) ||
    !SAFE_APPROVAL.test(value.targetConfirmationId)
  ) {
    throw new CanaryLifecycleCommandError('invalid_invocation');
  } else {
    approvalId = value.approvalId;
    targetConfirmationId = value.targetConfirmationId;
  }
  try {
    validateCloudflareId(value.accountId, 'account');
    validateCloudflareId(value.zoneId, 'zone');
  } catch {
    throw new CanaryLifecycleCommandError('invalid_invocation');
  }
  const parsedBase = {
    accountId: value.accountId.toLowerCase(),
    zoneId: value.zoneId.toLowerCase(),
    hostname: value.hostname,
    syntheticMcpUrl: value.syntheticMcpUrl,
    receiptPath: value.receiptPath,
    json: value.json === true,
  };
  if (value.mode === 'preview') return { ...parsedBase, mode: 'preview' };
  if (approvalId === undefined || targetConfirmationId === undefined) {
    throw new CanaryLifecycleCommandError('invalid_invocation');
  }
  return {
    ...parsedBase,
    mode: 'run',
    approvalId,
    targetConfirmationId,
  };
}

function validateLockInvocation(value: LockInvocation): ParsedLockInvocation {
  if (!v.is(v.object({}), value)) throw new CanaryLockCommandError('invalid_invocation');
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
  if (
    !v.is(v.picklist(['inspect', 'recover']), value.operation) ||
    !v.is(v.picklist(['cleanup', 'receipt']), value.store) ||
    !LOCK_STORES.has(value.store)
  ) {
    throw new CanaryLockCommandError('invalid_invocation');
  }
  if (!v.is(stringSchema, value.receiptPath) || value.receiptPath.length === 0) {
    throw new CanaryLockCommandError('invalid_invocation');
  }
  if (value.json !== undefined && !v.is(v.boolean(), value.json)) {
    throw new CanaryLockCommandError('invalid_invocation');
  }
  if (value.operation === 'inspect') {
    if (value.lockId !== undefined || value.confirmation !== undefined) {
      throw new CanaryLockCommandError('invalid_invocation');
    }
  } else if (
    !v.is(stringSchema, value.lockId) ||
    !SAFE_LOCK_ID.test(value.lockId) ||
    value.confirmation !== STALE_LOCK_RECOVERY_CONFIRMATION
  ) {
    throw new CanaryLockCommandError('invalid_invocation');
  }
  if (value.operation === 'inspect') {
    return {
      operation: 'inspect',
      store: value.store,
      receiptPath: value.receiptPath,
      json: value.json === true,
    };
  }
  if (!v.is(stringSchema, value.lockId)) {
    throw new CanaryLockCommandError('invalid_invocation');
  }
  return {
    operation: 'recover',
    store: value.store,
    receiptPath: value.receiptPath,
    lockId: value.lockId,
    confirmation: STALE_LOCK_RECOVERY_CONFIRMATION,
    json: value.json === true,
  };
}

function validateDependencies(value: LifecycleDependencies): NormalizedLifecycleDependencies {
  if (!v.is(v.object({}), value)) {
    throw new CanaryLifecycleCommandError('runtime_not_configured');
  }
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
    sleep: value.sleep ?? ((milliseconds: number) =>
      new Promise((resolve) => setTimeout(resolve, milliseconds))),
    onProgress: value.onProgress,
  };
  if (
    !v.is(functionSchema, runtime.readToken) ||
    !v.is(functionSchema, runtime.readAllowedEmail) ||
    !v.is(functionSchema, runtime.clientFactory) ||
    !v.is(functionSchema, runtime.providerFactory) ||
    !v.is(functionSchema, runtime.receiptStoreFactory) ||
    !v.is(functionSchema, runtime.inspectSyntheticUpstream) ||
    !v.is(functionSchema, runtime.fetchImpl) ||
    !v.is(functionSchema, runtime.sleep)
  ) {
    throw new CanaryLifecycleCommandError('runtime_not_configured');
  }
  if (runtime.onProgress !== undefined && !v.is(functionSchema, runtime.onProgress)) {
    throw new CanaryLifecycleCommandError('runtime_not_configured');
  }
  if (
    runtime.holdForInspection !== undefined &&
    !v.is(functionSchema, runtime.holdForInspection)
  ) {
    throw new CanaryLifecycleCommandError('runtime_not_configured');
  }
  return runtime;
}

function validateLockDependencies(value: LockDependencies): NormalizedLockDependencies {
  if (!v.is(v.object({}), value)) throw new CanaryLockCommandError('runtime_not_configured');
  const allowed = ['receiptStoreFactory'];
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    throw new CanaryLockCommandError('runtime_not_configured');
  }
  const receiptStoreFactory = value.receiptStoreFactory ?? createFileReceiptStore;
  if (!v.is(functionSchema, receiptStoreFactory)) {
    throw new CanaryLockCommandError('runtime_not_configured');
  }
  return { receiptStoreFactory };
}

function sanitizeLockInspection(value: LockInspection | null): SanitizedLockInspection {
  if (value === null) return Object.freeze({ status: 'not_found' });
  if (!['live', 'stale_candidate', 'ambiguous'].includes(value.status)) {
    throw new CanaryLockCommandError('lock_inspection_failed');
  }
  if (value.status === 'ambiguous') return Object.freeze({ status: 'ambiguous' });
  const metadata = value.metadata;
  if (
    metadata === undefined ||
    !v.is(stringSchema, metadata.lockId) ||
    !SAFE_LOCK_ID.test(metadata.lockId) ||
    !v.is(stringSchema, metadata.operationId) ||
    !SAFE_OPERATION_ID.test(metadata.operationId) ||
    !v.is(stringSchema, metadata.createdAt) ||
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

function isCanonicalIsoDate(value: string): boolean {
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value;
}

function lockStoreLabel(value: LockStore): string {
  return value === 'receipt' ? 'receipt' : 'cleanup sidecar';
}

function lockStatusLabel(value: LockInspectionReport['status']): string {
  if (value === 'not_found') return 'NOT FOUND';
  if (value === 'live') return 'LIVE';
  if (value === 'stale_candidate') return 'STALE CANDIDATE';
  return 'AMBIGUOUS';
}

function validSecret(value: BoundaryValue): value is string {
  return v.is(stringSchema, value) &&
    value.length > 0 &&
    [...value].every((character) => {
      const codePoint = character.codePointAt(0);
      return codePoint !== undefined && codePoint >= 32 && codePoint !== 127;
    });
}

function safeCount(value: BoundaryValue): number {
  return v.is(numberSchema, value) && Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function validLockEvidence(
  value: LockMetadata | undefined,
  expectedLockId: string,
): value is LockMetadata {
  return value !== undefined && value.lockId === expectedLockId;
}
