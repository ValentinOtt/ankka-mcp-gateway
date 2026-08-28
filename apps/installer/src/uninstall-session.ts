import { DeployError, isDeployErrorCode, type DeployErrorCode, isFailureReason } from './errors';
import { assertSecretFree } from './schema';
import { parseStaticUninstallPlan, type StaticUninstallPlan } from './uninstall-plan';

const ATTEMPT_ID = /^att_[A-Za-z0-9_-]{32}$/u;
const HASH = /^[A-Za-z0-9_-]{43}$/u;
const INSTALLATION_ID = /^acg-[a-f0-9]{24}$/u;
const PREFIXED_SHA256 = /^sha256:[a-f0-9]{64}$/u;

export type UninstallSessionStatus =
  | 'planned'
  | 'authorizing'
  | 'uninstalling'
  | 'removed'
  | 'failed';

export interface StoredUninstallOauthAttempt {
  readonly purpose: 'uninstall';
  readonly attemptId: string;
  readonly stateHash: string;
  readonly verifierHash: string;
  readonly expiresAt: number;
  readonly usedAt: number | null;
}

export type UninstallResult =
  | {
      readonly code: 'uninstall_complete';
      readonly completedAt: number;
      readonly installationId: string;
      readonly grantRevocation: 'confirmed' | 'unconfirmed';
    }
  | { readonly code: DeployErrorCode; readonly completedAt: number; readonly reason?: string };

/**
 * Operation state stored beside, never inside, the immutable successful install
 * session. It contains no OAuth grant, PKCE verifier, provider body, or journal
 * locator.
 */
export interface StoredUninstallControl {
  readonly schemaVersion: 1;
  readonly status: UninstallSessionStatus;
  readonly installationId: string;
  readonly installBindingHash: string;
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly recoverUntil: number;
  readonly plan: StaticUninstallPlan;
  readonly oauthAttempt: StoredUninstallOauthAttempt | null;
  readonly result: UninstallResult | null;
}

export interface PublicUninstallSession {
  readonly schemaVersion: 1;
  readonly status: UninstallSessionStatus;
  readonly recoverUntil: number;
  readonly updatedAt: number;
  readonly plan: StaticUninstallPlan;
  readonly result: UninstallResult | null;
}

export interface PublicUninstallRecovery {
  readonly status: 'recovery_required';
  readonly recoverUntil: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function safeTime(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function parseAttempt(value: unknown): StoredUninstallOauthAttempt | null {
  if (value === null) return null;
  if (!isRecord(value) || !exactKeys(value, [
    'purpose', 'attemptId', 'stateHash', 'verifierHash', 'expiresAt', 'usedAt',
  ]) || value.purpose !== 'uninstall' || typeof value.attemptId !== 'string' ||
    !ATTEMPT_ID.test(value.attemptId) || typeof value.stateHash !== 'string' ||
    !HASH.test(value.stateHash) || typeof value.verifierHash !== 'string' ||
    !HASH.test(value.verifierHash) || !safeTime(value.expiresAt) ||
    (value.usedAt !== null && (!safeTime(value.usedAt) || value.usedAt >= value.expiresAt))) return null;
  return Object.freeze({
    purpose: 'uninstall',
    attemptId: value.attemptId,
    stateHash: value.stateHash,
    verifierHash: value.verifierHash,
    expiresAt: value.expiresAt,
    usedAt: value.usedAt as number | null,
  });
}

function parseResult(value: unknown): UninstallResult | null {
  if (value === null) return null;
  if (!isRecord(value) || !safeTime(value.completedAt)) return null;
  if (value.code === 'uninstall_complete') {
    if (!exactKeys(value, ['code', 'completedAt', 'installationId', 'grantRevocation']) ||
      typeof value.installationId !== 'string' || !INSTALLATION_ID.test(value.installationId) ||
      (value.grantRevocation !== 'confirmed' && value.grantRevocation !== 'unconfirmed')) return null;
    return Object.freeze({
      code: 'uninstall_complete',
      completedAt: value.completedAt,
      installationId: value.installationId,
      grantRevocation: value.grantRevocation,
    });
  }
  if (!isDeployErrorCode(value.code)) return null;
  if (exactKeys(value, ['code', 'completedAt', 'reason'])) {
    if (!isFailureReason(value.reason)) return null;
    return Object.freeze({ code: value.code, completedAt: value.completedAt, reason: value.reason });
  }
  if (!exactKeys(value, ['code', 'completedAt'])) return null;
  return Object.freeze({ code: value.code, completedAt: value.completedAt });
}

export async function requireStoredUninstallControl(value: unknown): Promise<StoredUninstallControl> {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'status', 'installationId', 'installBindingHash', 'createdAt', 'updatedAt',
    'recoverUntil', 'plan', 'oauthAttempt', 'result',
  ]) || value.schemaVersion !== 1 || !['planned', 'authorizing', 'uninstalling', 'removed', 'failed']
    .includes(String(value.status)) || typeof value.installationId !== 'string' ||
    !INSTALLATION_ID.test(value.installationId) || typeof value.installBindingHash !== 'string' ||
    !PREFIXED_SHA256.test(value.installBindingHash) || !safeTime(value.createdAt) ||
    !safeTime(value.updatedAt) || !safeTime(value.recoverUntil) || value.createdAt > value.updatedAt ||
    value.updatedAt >= value.recoverUntil) throw new DeployError(500, 'session_invalid');

  let plan: StaticUninstallPlan;
  try {
    plan = await parseStaticUninstallPlan(value.plan);
  } catch {
    throw new DeployError(500, 'session_invalid');
  }
  const attempt = parseAttempt(value.oauthAttempt);
  const result = parseResult(value.result);
  const status = value.status as UninstallSessionStatus;
  if (
    plan.installationId !== value.installationId || plan.expiresAt > value.recoverUntil ||
    (value.oauthAttempt !== null && attempt === null) || (value.result !== null && result === null) ||
    (status === 'planned' && (attempt !== null || result !== null)) ||
    (status === 'authorizing' && (!attempt || attempt.usedAt !== null || result !== null)) ||
    (status === 'uninstalling' && (!attempt || attempt.usedAt === null || result !== null)) ||
    (status === 'removed' && (attempt === null || attempt.usedAt === null || result?.code !== 'uninstall_complete')) ||
    (status === 'failed' && (attempt === null || attempt.usedAt === null || !result || result.code === 'uninstall_complete')) ||
    (attempt !== null && (attempt.expiresAt > plan.expiresAt || attempt.expiresAt > value.recoverUntil)) ||
    (result !== null && (result.completedAt < (attempt?.usedAt ?? value.createdAt) ||
      result.completedAt >= value.recoverUntil))
  ) throw new DeployError(500, 'session_invalid');

  const control: StoredUninstallControl = Object.freeze({
    schemaVersion: 1,
    status,
    installationId: value.installationId,
    installBindingHash: value.installBindingHash,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
    recoverUntil: value.recoverUntil,
    plan,
    oauthAttempt: attempt,
    result,
  });
  assertSecretFree(control);
  return control;
}

export function publicUninstallSession(control: StoredUninstallControl): PublicUninstallSession {
  return Object.freeze({
    schemaVersion: 1,
    status: control.status,
    recoverUntil: control.recoverUntil,
    updatedAt: control.updatedAt,
    plan: control.plan,
    result: control.result,
  });
}

export async function parsePublicUninstallSession(value: unknown): Promise<PublicUninstallSession | null> {
  if (value === null) return null;
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'status', 'recoverUntil', 'updatedAt', 'plan', 'result',
  ]) || value.schemaVersion !== 1 || !['planned', 'authorizing', 'uninstalling', 'removed', 'failed']
    .includes(String(value.status)) || !safeTime(value.recoverUntil) || !safeTime(value.updatedAt) ||
    value.updatedAt >= value.recoverUntil) throw new DeployError(500, 'session_invalid');
  let plan: StaticUninstallPlan;
  try {
    plan = await parseStaticUninstallPlan(value.plan);
  } catch {
    throw new DeployError(500, 'session_invalid');
  }
  const result = parseResult(value.result);
  const status = value.status as UninstallSessionStatus;
  if (plan.expiresAt > value.recoverUntil || (value.result !== null && result === null) ||
    ((status === 'planned' || status === 'authorizing' || status === 'uninstalling') && result !== null) ||
    (status === 'removed' && result?.code !== 'uninstall_complete') ||
    (status === 'failed' && (!result || result.code === 'uninstall_complete'))) {
    throw new DeployError(500, 'session_invalid');
  }
  return Object.freeze({
    schemaVersion: 1,
    status,
    recoverUntil: value.recoverUntil,
    updatedAt: value.updatedAt,
    plan,
    result,
  });
}

export function parsePublicUninstallRecovery(value: unknown): PublicUninstallRecovery | null {
  if (value === null) return null;
  if (!isRecord(value) || !exactKeys(value, ['status', 'recoverUntil']) ||
    value.status !== 'recovery_required' || !safeTime(value.recoverUntil)) {
    throw new DeployError(500, 'session_invalid');
  }
  return Object.freeze({ status: 'recovery_required', recoverUntil: value.recoverUntil });
}
