import * as v from 'valibot';

import { boundaryValueSchema, type BoundaryValue } from './boundary';
import { constantTimeEqual } from './crypto';
import {
  parseExistingAnkkaGatewaySummary,
  type ExistingAnkkaGatewaySummary,
} from './cloudflare-gateway-fresh-preflight';
import { DeployError, isDeployErrorCode, type DeployErrorCode, isFailureReason } from './errors';
import {
  assertSecretFree,
  parseDeploySelection,
  parseStaticDeployPlan,
  type DeploySelection,
  type StaticDeployPlan,
} from './schema';

export type DeploySessionStatus = 'draft' | 'authorizing' | 'installing' | 'succeeded' | 'failed';
const deploySessionStatusSchema = v.picklist([
  'draft',
  'authorizing',
  'installing',
  'succeeded',
  'failed',
]);
const safeIntegerSchema = v.pipe(v.number(), v.safeInteger());
const storedOauthAttemptSchema = v.strictObject({
  attemptId: v.string(),
  expiresAt: safeIntegerSchema,
  stateHash: v.string(),
  usedAt: v.nullable(safeIntegerSchema),
  verifierHash: v.string(),
});
const successfulDeployResultSchema = v.strictObject({
  code: v.literal('install_complete'),
  completedAt: safeIntegerSchema,
  grantRevocation: v.picklist(['confirmed', 'unconfirmed']),
  installationId: v.string(),
});
const failedDeployResultSchema = v.strictObject({
  code: v.string(),
  completedAt: safeIntegerSchema,
  existingGateway: v.optional(boundaryValueSchema),
  reason: v.optional(v.string()),
});
const storedDeploySessionSchema = v.strictObject({
  createdAt: safeIntegerSchema,
  csrfHash: v.string(),
  expiresAt: safeIntegerSchema,
  oauthAttempt: v.nullable(boundaryValueSchema),
  plan: v.nullable(boundaryValueSchema),
  result: v.nullable(boundaryValueSchema),
  schemaVersion: v.literal(1),
  selection: v.nullable(boundaryValueSchema),
  status: deploySessionStatusSchema,
  updatedAt: safeIntegerSchema,
});
const publicDeployRecoverySchema = v.strictObject({
  recoverUntil: safeIntegerSchema,
  status: v.literal('recovery_required'),
});
const publicDeployResultRetentionSchema = v.strictObject({
  resultUntil: safeIntegerSchema,
  status: v.literal('result_available'),
});

export interface StoredOauthAttempt {
  attemptId: string;
  stateHash: string;
  verifierHash: string;
  expiresAt: number;
  usedAt: number | null;
}

export type DeployResult =
  | {
      code: 'install_complete';
      completedAt: number;
      installationId: string;
      grantRevocation: 'confirmed' | 'unconfirmed';
    }
  | {
      code: DeployErrorCode;
      completedAt: number;
      reason?: string;
      existingGateway?: ExistingAnkkaGatewaySummary;
    };

export interface StoredDeploySession {
  schemaVersion: 1;
  status: DeploySessionStatus;
  csrfHash: string;
  createdAt: number;
  updatedAt: number;
  expiresAt: number;
  selection: DeploySelection | null;
  plan: StaticDeployPlan | null;
  oauthAttempt: StoredOauthAttempt | null;
  result: DeployResult | null;
}

export interface PublicDeploySession {
  schemaVersion: 1;
  status: DeploySessionStatus;
  expiresAt: number;
  updatedAt: number;
  selection: DeploySelection | null;
  plan: StaticDeployPlan | null;
  result: DeployResult | null;
}

export interface PublicDeployRecovery {
  status: 'recovery_required';
  recoverUntil: number;
}

export interface PublicDeployResultRetention {
  status: 'result_available';
  resultUntil: number;
}

export function parsePublicDeployRecovery<Input>(value: Input): PublicDeployRecovery | null {
  if (value === null) return null;
  const result = v.safeParse(publicDeployRecoverySchema, value);
  if (!result.success) throw new DeployError(500, 'session_invalid');
  return Object.freeze(result.output);
}

export function parsePublicDeployResultRetention<Input>(value: Input): PublicDeployResultRetention | null {
  if (value === null) return null;
  const result = v.safeParse(publicDeployResultRetentionSchema, value);
  if (!result.success) throw new DeployError(500, 'session_invalid');
  return Object.freeze(result.output);
}

export function publicSession(session: StoredDeploySession): PublicDeploySession {
  return {
    schemaVersion: 1,
    status: session.status,
    expiresAt: session.expiresAt,
    updatedAt: session.updatedAt,
    selection: session.selection,
    plan: session.plan,
    result: session.result,
  };
}

function parseOauthAttempt(value: BoundaryValue): StoredOauthAttempt | null {
  const result = v.safeParse(storedOauthAttemptSchema, value);
  if (!result.success || !/^att_[A-Za-z0-9_-]{32}$/u.test(result.output.attemptId) ||
    !/^[A-Za-z0-9_-]{43}$/u.test(result.output.stateHash) ||
    !/^[A-Za-z0-9_-]{43}$/u.test(result.output.verifierHash)) return null;
  return Object.freeze(result.output);
}

function parseDeployResult(value: BoundaryValue): DeployResult | null {
  const successful = v.safeParse(successfulDeployResultSchema, value);
  if (successful.success) {
    if (!/^acg-[a-f0-9]{24}$/u.test(successful.output.installationId)) return null;
    return Object.freeze(successful.output);
  }
  const failed = v.safeParse(failedDeployResultSchema, value);
  if (!failed.success || !isDeployErrorCode(failed.output.code)) return null;
  if (failed.output.reason !== undefined && !isFailureReason(failed.output.reason)) return null;
  const existingGateway = failed.output.existingGateway === undefined
    ? undefined
    : parseExistingAnkkaGatewaySummary(failed.output.existingGateway) ?? undefined;
  if (
    (failed.output.existingGateway !== undefined && existingGateway === undefined) ||
    (existingGateway !== undefined && failed.output.code !== 'existing_gateway_detected') ||
    (failed.output.code === 'existing_gateway_detected' && existingGateway === undefined)
  ) return null;
  const result: DeployResult = {
    code: failed.output.code,
    completedAt: failed.output.completedAt,
  };
  if (failed.output.reason !== undefined) result.reason = failed.output.reason;
  if (existingGateway !== undefined) result.existingGateway = existingGateway;
  return Object.freeze(result);
}

function parseStoredSession<Input>(value: Input): StoredDeploySession | null {
  const parsed = v.safeParse(storedDeploySessionSchema, value);
  if (!parsed.success) return null;
  const input = parsed.output;
  if (!/^[A-Za-z0-9_-]{43}$/u.test(input.csrfHash) ||
    input.createdAt > input.updatedAt || input.updatedAt > input.expiresAt) return null;
  let selection: DeploySelection | null = null;
  let plan: StaticDeployPlan | null = null;
  try {
    if (input.selection !== null) selection = parseDeploySelection(input.selection);
    if (input.plan !== null) plan = parseStaticDeployPlan(input.plan);
  } catch {
    return null;
  }
  const oauthAttempt = input.oauthAttempt === null ? null : parseOauthAttempt(input.oauthAttempt);
  const result = input.result === null ? null : parseDeployResult(input.result);
  if ((input.oauthAttempt !== null && oauthAttempt === null) ||
      (input.result !== null && result === null)) return null;
  return Object.freeze({
    schemaVersion: 1,
    status: input.status,
    csrfHash: input.csrfHash,
    createdAt: input.createdAt,
    updatedAt: input.updatedAt,
    expiresAt: input.expiresAt,
    selection,
    plan,
    oauthAttempt,
    result,
  });
}

export function requireStoredSession<Input>(value: Input): StoredDeploySession {
  const session = parseStoredSession(value);
  if (!session) throw new DeployError(500, 'session_invalid');
  assertSecretFree(session);
  return session;
}

export function verifyHash(actual: string, expected: string): void {
  if (!constantTimeEqual(actual, expected)) throw new DeployError(403, 'csrf_invalid');
}
