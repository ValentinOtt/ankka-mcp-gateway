import * as v from 'valibot';

import { boundaryValueSchema } from './boundary';
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
const uninstallSessionStatuses = Object.freeze([
  'planned',
  'authorizing',
  'uninstalling',
  'removed',
  'failed',
] as const);
const uninstallSessionStatusSchema = v.picklist(uninstallSessionStatuses);
const safeTimeSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const uninstallOauthAttemptSchema = v.strictObject({
  attemptId: v.string(),
  expiresAt: safeTimeSchema,
  purpose: v.literal('uninstall'),
  stateHash: v.string(),
  usedAt: v.nullable(safeTimeSchema),
  verifierHash: v.string(),
});
const completeUninstallResultSchema = v.strictObject({
  code: v.literal('uninstall_complete'),
  completedAt: safeTimeSchema,
  grantRevocation: v.picklist(['confirmed', 'unconfirmed']),
  installationId: v.string(),
});
const failedUninstallResultSchema = v.strictObject({
  code: v.string(),
  completedAt: safeTimeSchema,
  reason: v.optional(v.string()),
});
const storedUninstallControlSchema = v.strictObject({
  createdAt: safeTimeSchema,
  installationId: v.string(),
  installBindingHash: v.string(),
  oauthAttempt: v.nullable(boundaryValueSchema),
  plan: boundaryValueSchema,
  recoverUntil: safeTimeSchema,
  result: v.nullable(boundaryValueSchema),
  schemaVersion: v.literal(1),
  status: uninstallSessionStatusSchema,
  updatedAt: safeTimeSchema,
});
const publicUninstallSessionSchema = v.strictObject({
  plan: boundaryValueSchema,
  recoverUntil: safeTimeSchema,
  result: v.nullable(boundaryValueSchema),
  schemaVersion: v.literal(1),
  status: uninstallSessionStatusSchema,
  updatedAt: safeTimeSchema,
});
const publicUninstallRecoverySchema = v.strictObject({
  recoverUntil: safeTimeSchema,
  status: v.literal('recovery_required'),
});

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

/** Secret-free subset exposed to the installer UI projection. */
export type PublicUninstallPlan = Pick<
  StaticUninstallPlan,
  | 'schemaVersion'
  | 'writesPerformed'
  | 'installationId'
  | 'release'
  | 'steps'
  | 'providerNotice'
  | 'planId'
  | 'planHash'
  | 'expiresAt'
>;

export interface PublicUninstallRecovery {
  readonly status: 'recovery_required';
  readonly recoverUntil: number;
}

function parseAttempt<Input>(value: Input): StoredUninstallOauthAttempt | null {
  if (value === null) return null;
  const result = v.safeParse(uninstallOauthAttemptSchema, value);
  if (!result.success || !ATTEMPT_ID.test(result.output.attemptId) ||
    !HASH.test(result.output.stateHash) || !HASH.test(result.output.verifierHash) ||
    (result.output.usedAt !== null && result.output.usedAt >= result.output.expiresAt)) return null;
  return Object.freeze({
    purpose: 'uninstall',
    attemptId: result.output.attemptId,
    stateHash: result.output.stateHash,
    verifierHash: result.output.verifierHash,
    expiresAt: result.output.expiresAt,
    usedAt: result.output.usedAt,
  });
}

function parseResult<Input>(value: Input): UninstallResult | null {
  if (value === null) return null;
  const complete = v.safeParse(completeUninstallResultSchema, value);
  if (complete.success) {
    if (!INSTALLATION_ID.test(complete.output.installationId)) return null;
    return Object.freeze(complete.output);
  }
  const failed = v.safeParse(failedUninstallResultSchema, value);
  if (!failed.success || !isDeployErrorCode(failed.output.code)) return null;
  if (failed.output.reason !== undefined) {
    if (!isFailureReason(failed.output.reason)) return null;
    return Object.freeze({
      code: failed.output.code,
      completedAt: failed.output.completedAt,
      reason: failed.output.reason,
    });
  }
  return Object.freeze({ code: failed.output.code, completedAt: failed.output.completedAt });
}

export async function requireStoredUninstallControl<Input>(value: Input): Promise<StoredUninstallControl> {
  const parsed = v.safeParse(storedUninstallControlSchema, value);
  if (!parsed.success) throw new DeployError(500, 'session_invalid');
  const input = parsed.output;
  if (!INSTALLATION_ID.test(input.installationId) ||
    !PREFIXED_SHA256.test(input.installBindingHash) || input.createdAt > input.updatedAt ||
    input.updatedAt >= input.recoverUntil) throw new DeployError(500, 'session_invalid');

  let plan: StaticUninstallPlan;
  try {
    plan = await parseStaticUninstallPlan(input.plan);
  } catch {
    throw new DeployError(500, 'session_invalid');
  }
  const attempt = parseAttempt(input.oauthAttempt);
  const result = parseResult(input.result);
  const { status } = input;
  if (
    plan.installationId !== input.installationId || plan.expiresAt > input.recoverUntil ||
    (input.oauthAttempt !== null && attempt === null) || (input.result !== null && result === null) ||
    (status === 'planned' && (attempt !== null || result !== null)) ||
    (status === 'authorizing' && (!attempt || attempt.usedAt !== null || result !== null)) ||
    (status === 'uninstalling' && (!attempt || attempt.usedAt === null || result !== null)) ||
    (status === 'removed' && (attempt === null || attempt.usedAt === null || result?.code !== 'uninstall_complete')) ||
    (status === 'failed' && (attempt === null || attempt.usedAt === null || !result || result.code === 'uninstall_complete')) ||
    (attempt !== null && (attempt.expiresAt > plan.expiresAt || attempt.expiresAt > input.recoverUntil)) ||
    (result !== null && (result.completedAt < (attempt?.usedAt ?? input.createdAt) ||
      result.completedAt >= input.recoverUntil))
  ) throw new DeployError(500, 'session_invalid');

  const control: StoredUninstallControl = Object.freeze({
    schemaVersion: 1,
    status,
    installationId: input.installationId,
    installBindingHash: input.installBindingHash,
    createdAt: input.createdAt,
    updatedAt: input.updatedAt,
    recoverUntil: input.recoverUntil,
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

export async function parsePublicUninstallSession<Input>(value: Input): Promise<PublicUninstallSession | null> {
  if (value === null) return null;
  const parsed = v.safeParse(publicUninstallSessionSchema, value);
  if (!parsed.success || parsed.output.updatedAt >= parsed.output.recoverUntil) {
    throw new DeployError(500, 'session_invalid');
  }
  const input = parsed.output;
  let plan: StaticUninstallPlan;
  try {
    plan = await parseStaticUninstallPlan(input.plan);
  } catch {
    throw new DeployError(500, 'session_invalid');
  }
  const result = parseResult(input.result);
  const { status } = input;
  if (plan.expiresAt > input.recoverUntil || (input.result !== null && result === null) ||
    ((status === 'planned' || status === 'authorizing' || status === 'uninstalling') && result !== null) ||
    (status === 'removed' && result?.code !== 'uninstall_complete') ||
    (status === 'failed' && (!result || result.code === 'uninstall_complete'))) {
    throw new DeployError(500, 'session_invalid');
  }
  return Object.freeze({
    schemaVersion: 1,
    status,
    recoverUntil: input.recoverUntil,
    updatedAt: input.updatedAt,
    plan,
    result,
  });
}

export function parsePublicUninstallRecovery<Input>(value: Input): PublicUninstallRecovery | null {
  if (value === null) return null;
  const result = v.safeParse(publicUninstallRecoverySchema, value);
  if (!result.success) {
    throw new DeployError(500, 'session_invalid');
  }
  return Object.freeze(result.output);
}
