import { DeployError, isDeployErrorCode, type DeployErrorCode } from './errors';
import {
  parseReturningUninstallPlan,
  type ReturningUninstallPlan,
} from './returning-uninstall-plan';
import { assertSecretFree } from './schema';
import { MAX_RETURNING_UNINSTALL_RECOVERY_RETENTION_MS } from './returning-uninstall-journal';

const ACTION_ID = /^action_[A-Za-z0-9_-]{32}$/u;
const HASH = /^[A-Za-z0-9_-]{43}$/u;
const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const EMAIL = /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u;

export type ReturningUninstallStatus = 'planned' | 'authorizing' | 'removing' | 'failed' | 'removed';

export interface ReturningUninstallActionAuthority {
  readonly actionId: string;
  readonly actionKeyHash: string;
  readonly actorEmail: string;
  readonly accountId: string;
  readonly workerName: string;
  readonly workersSubdomain: string;
  readonly managementOrigin: string;
  readonly expiresAt: number;
}

export interface ReturningUninstallOauthAttempt {
  readonly purpose: 'customer_action' | 'hosted_recovery';
  readonly attemptId: string;
  readonly stateHash: string;
  readonly verifierHash: string;
  readonly expiresAt: number;
  readonly usedAt: number | null;
}

export interface StoredReturningUninstall {
  readonly schemaVersion: 1;
  readonly status: ReturningUninstallStatus;
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly recoverUntil: number;
  readonly plan: ReturningUninstallPlan;
  readonly action: ReturningUninstallActionAuthority;
  readonly oauthAttempt: ReturningUninstallOauthAttempt | null;
  readonly result: null | {
    readonly code: 'returning_uninstall_complete';
    readonly completedAt: number;
    readonly installationId: string;
    readonly grantRevocation: 'confirmed' | 'unconfirmed';
  } | {
    readonly code: DeployErrorCode;
    readonly completedAt: number;
    readonly reason?: string;
  };
}

export interface PublicReturningUninstall {
  readonly schemaVersion: 1;
  readonly status: ReturningUninstallStatus;
  readonly updatedAt: number;
  readonly recoverUntil: number;
  readonly recoveryAvailable: boolean;
  readonly plan: ReturningUninstallPlan;
  readonly result: StoredReturningUninstall['result'];
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function exact(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function managementOrigin(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && !url.port &&
      url.pathname === '/' && !url.search && !url.hash;
  } catch { return false; }
}

function action(value: unknown): ReturningUninstallActionAuthority | null {
  if (!record(value) || !exact(value, [
    'actionId', 'actionKeyHash', 'actorEmail', 'accountId', 'workerName',
    'workersSubdomain', 'managementOrigin', 'expiresAt',
  ]) || typeof value.actionId !== 'string' || !ACTION_ID.test(value.actionId) ||
    typeof value.actionKeyHash !== 'string' || !HASH.test(value.actionKeyHash) ||
    typeof value.actorEmail !== 'string' || value.actorEmail !== value.actorEmail.toLowerCase() ||
    !EMAIL.test(value.actorEmail) || typeof value.accountId !== 'string' || !ACCOUNT_ID.test(value.accountId) ||
    typeof value.workerName !== 'string' || !WORKER_NAME.test(value.workerName) ||
    typeof value.workersSubdomain !== 'string' || !DNS_LABEL.test(value.workersSubdomain) ||
    !managementOrigin(value.managementOrigin) || !Number.isSafeInteger(value.expiresAt)) return null;
  return Object.freeze({
    actionId: value.actionId,
    actionKeyHash: value.actionKeyHash,
    actorEmail: value.actorEmail,
    accountId: value.accountId,
    workerName: value.workerName,
    workersSubdomain: value.workersSubdomain,
    managementOrigin: value.managementOrigin,
    expiresAt: value.expiresAt as number,
  });
}

export async function requireStoredReturningUninstall(value: unknown): Promise<StoredReturningUninstall> {
  if (!record(value) || !exact(value, [
    'schemaVersion', 'status', 'createdAt', 'updatedAt', 'recoverUntil', 'plan', 'action', 'oauthAttempt', 'result',
  ]) || value.schemaVersion !== 1 || !['planned', 'authorizing', 'removing', 'failed', 'removed'].includes(
    String(value.status),
  ) || !Number.isSafeInteger(value.createdAt) || !Number.isSafeInteger(value.updatedAt) ||
    (value.updatedAt as number) < (value.createdAt as number) || !Number.isSafeInteger(value.recoverUntil) ||
    (value.recoverUntil as number) <= (value.createdAt as number) ||
    (value.recoverUntil as number) - (value.createdAt as number) > MAX_RETURNING_UNINSTALL_RECOVERY_RETENTION_MS ||
    (value.recoverUntil as number) < (record(value.plan) && Number.isSafeInteger(value.plan.expiresAt)
      ? value.plan.expiresAt as number : Number.MAX_SAFE_INTEGER)) throw new DeployError(500, 'session_invalid');
  const plan = await parseReturningUninstallPlan(value.plan).catch(() => null);
  const parsedAction = action(value.action);
  if (!plan || !parsedAction || parsedAction.expiresAt !== plan.expiresAt ||
    parsedAction.expiresAt > (value.recoverUntil as number) ||
    parsedAction.workerName !== plan.gateway.workerName ||
    parsedAction.managementOrigin !== `https://${plan.gateway.managementHostname}`) {
    throw new DeployError(500, 'session_invalid');
  }
  let oauthAttempt: ReturningUninstallOauthAttempt | null = null;
  if (value.oauthAttempt !== null) {
    if (!record(value.oauthAttempt) || !exact(value.oauthAttempt, [
      'purpose', 'attemptId', 'stateHash', 'verifierHash', 'expiresAt', 'usedAt',
    ]) || (value.oauthAttempt.purpose !== 'customer_action' && value.oauthAttempt.purpose !== 'hosted_recovery') ||
      typeof value.oauthAttempt.attemptId !== 'string' ||
      !/^att_[A-Za-z0-9_-]{32}$/u.test(value.oauthAttempt.attemptId) ||
      typeof value.oauthAttempt.stateHash !== 'string' || !HASH.test(value.oauthAttempt.stateHash) ||
      typeof value.oauthAttempt.verifierHash !== 'string' || !HASH.test(value.oauthAttempt.verifierHash) ||
      !Number.isSafeInteger(value.oauthAttempt.expiresAt) ||
      (value.oauthAttempt.usedAt !== null && !Number.isSafeInteger(value.oauthAttempt.usedAt))) {
      throw new DeployError(500, 'session_invalid');
    }
    oauthAttempt = Object.freeze({
      purpose: value.oauthAttempt.purpose,
      attemptId: value.oauthAttempt.attemptId,
      stateHash: value.oauthAttempt.stateHash,
      verifierHash: value.oauthAttempt.verifierHash,
      expiresAt: value.oauthAttempt.expiresAt as number,
      usedAt: value.oauthAttempt.usedAt as number | null,
    });
  }
  let result: StoredReturningUninstall['result'] = null;
  if (value.result !== null) {
    if (!record(value.result)) throw new DeployError(500, 'session_invalid');
    const resultValue = value.result;
    const success = resultValue.code === 'returning_uninstall_complete';
    if (!exact(resultValue, success
      ? ['code', 'completedAt', 'installationId', 'grantRevocation']
      : resultValue.reason === undefined ? ['code', 'completedAt'] : ['code', 'completedAt', 'reason']) ||
      (!success && !isDeployErrorCode(resultValue.code)) || !Number.isSafeInteger(resultValue.completedAt) ||
      (success && (resultValue.installationId !== plan.gateway.installationId ||
        (resultValue.grantRevocation !== 'confirmed' && resultValue.grantRevocation !== 'unconfirmed'))) ||
      (!success && resultValue.reason !== undefined && (typeof resultValue.reason !== 'string' ||
        !/^[a-z][a-z0-9_]{0,159}$/u.test(resultValue.reason)))) {
      throw new DeployError(500, 'session_invalid');
    }
    result = Object.freeze({ ...resultValue }) as StoredReturningUninstall['result'];
  }
  const status = value.status as ReturningUninstallStatus;
  if (
    (status === 'planned' && (oauthAttempt !== null || result !== null)) ||
    (status === 'authorizing' && (!oauthAttempt || oauthAttempt.usedAt !== null || result !== null)) ||
    (status === 'removing' && (!oauthAttempt || oauthAttempt.usedAt === null || result !== null)) ||
    (status === 'removed' && (!oauthAttempt || oauthAttempt.usedAt === null ||
      result?.code !== 'returning_uninstall_complete')) ||
    (status === 'failed' && (!oauthAttempt || oauthAttempt.usedAt === null || !result ||
      result.code === 'returning_uninstall_complete')) ||
    (oauthAttempt && oauthAttempt.expiresAt > plan.expiresAt) ||
    (result && result.completedAt < (oauthAttempt?.usedAt ?? value.createdAt as number))
  ) throw new DeployError(500, 'session_invalid');
  const parsed = Object.freeze({
    schemaVersion: 1 as const,
    status,
    createdAt: value.createdAt as number,
    updatedAt: value.updatedAt as number,
    recoverUntil: value.recoverUntil as number,
    plan,
    action: parsedAction,
    oauthAttempt,
    result,
  });
  assertSecretFree(parsed);
  return parsed;
}

export function publicReturningUninstall(
  value: StoredReturningUninstall,
  recoveryAvailable = false,
): PublicReturningUninstall {
  return Object.freeze({
    schemaVersion: 1,
    status: value.status,
    updatedAt: value.updatedAt,
    recoverUntil: value.recoverUntil,
    recoveryAvailable,
    plan: value.plan,
    result: value.result,
  });
}

export async function parsePublicReturningUninstall(
  value: unknown,
): Promise<PublicReturningUninstall | null> {
  if (value === null) return null;
  if (!record(value) || !exact(value, [
    'schemaVersion', 'status', 'updatedAt', 'recoverUntil', 'recoveryAvailable', 'plan', 'result',
  ]) ||
    value.schemaVersion !== 1 || !['planned', 'authorizing', 'removing', 'failed', 'removed'].includes(
    String(value.status),
    ) || !Number.isSafeInteger(value.updatedAt) || !Number.isSafeInteger(value.recoverUntil) ||
    typeof value.recoveryAvailable !== 'boolean') {
    throw new DeployError(500, 'session_invalid');
  }
  const plan = await parseReturningUninstallPlan(value.plan).catch(() => null);
  if (!plan) throw new DeployError(500, 'session_invalid');
  let result: StoredReturningUninstall['result'] = null;
  if (value.result !== null) {
    if (!record(value.result)) throw new DeployError(500, 'session_invalid');
    const resultValue = value.result;
    const success = resultValue.code === 'returning_uninstall_complete';
    if (!exact(resultValue, success
      ? ['code', 'completedAt', 'installationId', 'grantRevocation']
      : resultValue.reason === undefined ? ['code', 'completedAt'] : ['code', 'completedAt', 'reason']) ||
      (!success && !isDeployErrorCode(resultValue.code)) || !Number.isSafeInteger(resultValue.completedAt) ||
      (success && (resultValue.installationId !== plan.gateway.installationId ||
        (resultValue.grantRevocation !== 'confirmed' && resultValue.grantRevocation !== 'unconfirmed'))) ||
      (!success && resultValue.reason !== undefined && (typeof resultValue.reason !== 'string' ||
        !/^[a-z][a-z0-9_]{0,159}$/u.test(resultValue.reason)))) {
      throw new DeployError(500, 'session_invalid');
    }
    result = Object.freeze({ ...resultValue }) as StoredReturningUninstall['result'];
  }
  const status = value.status as ReturningUninstallStatus;
  if ((status === 'removed') !== (result?.code === 'returning_uninstall_complete') ||
    (status === 'failed') !== Boolean(result && result.code !== 'returning_uninstall_complete') ||
    (['planned', 'authorizing', 'removing'].includes(status) && result !== null)) {
    throw new DeployError(500, 'session_invalid');
  }
  return Object.freeze({
    schemaVersion: 1,
    status,
    updatedAt: value.updatedAt as number,
    recoverUntil: value.recoverUntil as number,
    recoveryAvailable: value.recoveryAvailable,
    plan,
    result,
  });
}
