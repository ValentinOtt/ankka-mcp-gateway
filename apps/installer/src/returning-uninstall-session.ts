import * as v from 'valibot';

import { boundaryValueSchema } from './boundary';
import { DeployError, isDeployErrorCode, type DeployErrorCode } from './errors';
import { MAX_RETURNING_UNINSTALL_RECOVERY_RETENTION_MS } from './returning-uninstall-journal';
import {
  parseReturningUninstallPlan,
  type ReturningUninstallPlan,
} from './returning-uninstall-plan';
import { assertSecretFree } from './schema';

const ACTION_ID = /^action_[A-Za-z0-9_-]{32}$/u;
const HASH = /^[A-Za-z0-9_-]{43}$/u;
const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const EMAIL = /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u;
const ATTEMPT_ID = /^att_[A-Za-z0-9_-]{32}$/u;
const FAILURE_REASON = /^[a-z][a-z0-9_]{0,159}$/u;

export type ReturningUninstallStatus = 'planned' | 'authorizing' | 'removing' | 'failed' | 'removed';

const safeNonnegativeIntegerSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const statusSchema = v.picklist(['planned', 'authorizing', 'removing', 'failed', 'removed']);
const actionSchema = v.strictObject({
  actionId: v.pipe(v.string(), v.regex(ACTION_ID)),
  actionKeyHash: v.pipe(v.string(), v.regex(HASH)),
  actorEmail: v.pipe(v.string(), v.regex(EMAIL)),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  workerName: v.pipe(v.string(), v.regex(WORKER_NAME)),
  workersSubdomain: v.pipe(v.string(), v.regex(DNS_LABEL)),
  managementOrigin: v.string(),
  expiresAt: safeNonnegativeIntegerSchema,
});
const oauthAttemptSchema = v.strictObject({
  purpose: v.picklist(['customer_action', 'hosted_recovery']),
  attemptId: v.pipe(v.string(), v.regex(ATTEMPT_ID)),
  stateHash: v.pipe(v.string(), v.regex(HASH)),
  verifierHash: v.pipe(v.string(), v.regex(HASH)),
  expiresAt: safeNonnegativeIntegerSchema,
  usedAt: v.nullable(safeNonnegativeIntegerSchema),
});
const successfulResultSchema = v.strictObject({
  code: v.literal('returning_uninstall_complete'),
  completedAt: safeNonnegativeIntegerSchema,
  installationId: v.string(),
  grantRevocation: v.picklist(['confirmed', 'unconfirmed']),
});
const failedResultSchema = v.strictObject({
  code: v.string(),
  completedAt: safeNonnegativeIntegerSchema,
  reason: v.optional(v.string()),
});
const storedSessionSchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: statusSchema,
  createdAt: safeNonnegativeIntegerSchema,
  updatedAt: safeNonnegativeIntegerSchema,
  recoverUntil: safeNonnegativeIntegerSchema,
  plan: boundaryValueSchema,
  action: actionSchema,
  oauthAttempt: v.nullable(oauthAttemptSchema),
  result: v.nullable(boundaryValueSchema),
});
const publicSessionSchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: statusSchema,
  updatedAt: safeNonnegativeIntegerSchema,
  recoverUntil: safeNonnegativeIntegerSchema,
  recoveryAvailable: v.boolean(),
  plan: boundaryValueSchema,
  result: v.nullable(boundaryValueSchema),
});

type ParsedAction = v.InferOutput<typeof actionSchema>;

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

export interface SuccessfulReturningUninstallResult {
  readonly code: 'returning_uninstall_complete';
  readonly completedAt: number;
  readonly installationId: string;
  readonly grantRevocation: 'confirmed' | 'unconfirmed';
}

export interface FailedReturningUninstallResult {
  readonly code: DeployErrorCode;
  readonly completedAt: number;
  readonly reason?: string;
}

export type ReturningUninstallResult =
  | SuccessfulReturningUninstallResult
  | FailedReturningUninstallResult;

export interface StoredReturningUninstall {
  readonly schemaVersion: 1;
  readonly status: ReturningUninstallStatus;
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly recoverUntil: number;
  readonly plan: ReturningUninstallPlan;
  readonly action: ReturningUninstallActionAuthority;
  readonly oauthAttempt: ReturningUninstallOauthAttempt | null;
  readonly result: ReturningUninstallResult | null;
}

export interface PublicReturningUninstall {
  readonly schemaVersion: 1;
  readonly status: ReturningUninstallStatus;
  readonly updatedAt: number;
  readonly recoverUntil: number;
  readonly recoveryAvailable: boolean;
  readonly plan: ReturningUninstallPlan;
  readonly result: ReturningUninstallResult | null;
}

function validManagementOrigin(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && !url.port &&
      url.pathname === '/' && !url.search && !url.hash;
  } catch {
    return false;
  }
}

function parseAction(value: ParsedAction): ReturningUninstallActionAuthority | null {
  if (value.actorEmail !== value.actorEmail.toLowerCase() || !validManagementOrigin(value.managementOrigin)) {
    return null;
  }
  return Object.freeze(value);
}

function parseResult<Input>(
  value: Input,
  plan: ReturningUninstallPlan,
): ReturningUninstallResult | null {
  const success = v.safeParse(successfulResultSchema, value);
  if (success.success) {
    if (success.output.installationId !== plan.gateway.installationId) return null;
    return Object.freeze(success.output);
  }
  const failure = v.safeParse(failedResultSchema, value);
  if (!failure.success || !isDeployErrorCode(failure.output.code) ||
      (failure.output.reason !== undefined && !FAILURE_REASON.test(failure.output.reason))) return null;
  return failure.output.reason === undefined
    ? Object.freeze({ code: failure.output.code, completedAt: failure.output.completedAt })
    : Object.freeze({
        code: failure.output.code,
        completedAt: failure.output.completedAt,
        reason: failure.output.reason,
      });
}

function invalid(): never {
  throw new DeployError(500, 'session_invalid');
}

export async function requireStoredReturningUninstall<Input>(input: Input): Promise<StoredReturningUninstall> {
  const storedResult = v.safeParse(storedSessionSchema, input);
  if (!storedResult.success) invalid();
  const stored = storedResult.output;
  if (stored.updatedAt < stored.createdAt || stored.recoverUntil <= stored.createdAt ||
      stored.recoverUntil - stored.createdAt > MAX_RETURNING_UNINSTALL_RECOVERY_RETENTION_MS) invalid();
  const plan = await parseReturningUninstallPlan(stored.plan).catch(() => null);
  const action = parseAction(stored.action);
  if (!plan || !action || plan.expiresAt > stored.recoverUntil || action.expiresAt !== plan.expiresAt ||
      action.workerName !== plan.gateway.workerName ||
      action.managementOrigin !== `https://${plan.gateway.managementHostname}`) invalid();

  const oauthAttempt = stored.oauthAttempt === null ? null : Object.freeze(stored.oauthAttempt);
  const result = stored.result === null ? null : parseResult(stored.result, plan);
  if (stored.result !== null && result === null) invalid();
  if (
    (stored.status === 'planned' && (oauthAttempt !== null || result !== null)) ||
    (stored.status === 'authorizing' && (!oauthAttempt || oauthAttempt.usedAt !== null || result !== null)) ||
    (stored.status === 'removing' && (!oauthAttempt || oauthAttempt.usedAt === null || result !== null)) ||
    (stored.status === 'removed' && (!oauthAttempt || oauthAttempt.usedAt === null ||
      result?.code !== 'returning_uninstall_complete')) ||
    (stored.status === 'failed' && (!oauthAttempt || oauthAttempt.usedAt === null || !result ||
      result.code === 'returning_uninstall_complete')) ||
    (oauthAttempt && oauthAttempt.expiresAt > plan.expiresAt) ||
    (result && result.completedAt < (oauthAttempt?.usedAt ?? stored.createdAt))
  ) invalid();
  const parsed = Object.freeze({
    schemaVersion: 1,
    status: stored.status,
    createdAt: stored.createdAt,
    updatedAt: stored.updatedAt,
    recoverUntil: stored.recoverUntil,
    plan,
    action,
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

export async function parsePublicReturningUninstall<Input>(
  input: Input,
): Promise<PublicReturningUninstall | null> {
  if (input === null) return null;
  const publicResult = v.safeParse(publicSessionSchema, input);
  if (!publicResult.success) invalid();
  const stored = publicResult.output;
  const plan = await parseReturningUninstallPlan(stored.plan).catch(() => null);
  if (!plan) invalid();
  const result = stored.result === null ? null : parseResult(stored.result, plan);
  if (stored.result !== null && result === null) invalid();
  if ((stored.status === 'removed') !== (result?.code === 'returning_uninstall_complete') ||
      (stored.status === 'failed') !== Boolean(result && result.code !== 'returning_uninstall_complete') ||
      (['planned', 'authorizing', 'removing'].includes(stored.status) && result !== null)) invalid();
  return Object.freeze({
    schemaVersion: 1,
    status: stored.status,
    updatedAt: stored.updatedAt,
    recoverUntil: stored.recoverUntil,
    recoveryAvailable: stored.recoveryAvailable,
    plan,
    result,
  });
}
