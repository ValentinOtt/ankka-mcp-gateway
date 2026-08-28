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

export function parsePublicDeployRecovery(value: unknown): PublicDeployRecovery | null {
  if (value === null) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new DeployError(500, 'session_invalid');
  }
  const input = value as Record<string, unknown>;
  if (
    Object.keys(input).sort().join(',') !== ['recoverUntil', 'status'].sort().join(',') ||
    input.status !== 'recovery_required' ||
    typeof input.recoverUntil !== 'number' ||
    !Number.isSafeInteger(input.recoverUntil)
  ) throw new DeployError(500, 'session_invalid');
  return Object.freeze({ status: 'recovery_required', recoverUntil: input.recoverUntil });
}

export function parsePublicDeployResultRetention(value: unknown): PublicDeployResultRetention | null {
  if (value === null) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new DeployError(500, 'session_invalid');
  }
  const input = value as Record<string, unknown>;
  if (
    Object.keys(input).sort().join(',') !== ['resultUntil', 'status'].sort().join(',') ||
    input.status !== 'result_available' ||
    typeof input.resultUntil !== 'number' ||
    !Number.isSafeInteger(input.resultUntil)
  ) throw new DeployError(500, 'session_invalid');
  return Object.freeze({ status: 'result_available', resultUntil: input.resultUntil });
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

function isStoredSession(value: unknown): value is StoredDeploySession {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const input = value as Record<string, unknown>;
  if (Object.keys(input).sort().join(',') !== [
    'schemaVersion', 'status', 'csrfHash', 'createdAt', 'updatedAt', 'expiresAt',
    'selection', 'plan', 'oauthAttempt', 'result',
  ].sort().join(',')) return false;
  if (
    input.schemaVersion !== 1 ||
    typeof input.status !== 'string' ||
    !['draft', 'authorizing', 'installing', 'succeeded', 'failed'].includes(input.status) ||
    typeof input.csrfHash !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(input.csrfHash) ||
    typeof input.createdAt !== 'number' || !Number.isSafeInteger(input.createdAt) ||
    typeof input.updatedAt !== 'number' || !Number.isSafeInteger(input.updatedAt) ||
    typeof input.expiresAt !== 'number' || !Number.isSafeInteger(input.expiresAt) ||
    input.createdAt > input.updatedAt || input.updatedAt > input.expiresAt
  ) return false;
  try {
    if (input.selection !== null) parseDeploySelection(input.selection);
    if (input.plan !== null) parseStaticDeployPlan(input.plan);
  } catch {
    return false;
  }
  if (input.oauthAttempt !== null) {
    if (!input.oauthAttempt || typeof input.oauthAttempt !== 'object' || Array.isArray(input.oauthAttempt)) return false;
    const attempt = input.oauthAttempt as Record<string, unknown>;
    if (
      Object.keys(attempt).sort().join(',') !== ['attemptId', 'stateHash', 'verifierHash', 'expiresAt', 'usedAt'].sort().join(',') ||
      typeof attempt.attemptId !== 'string' || !/^att_[A-Za-z0-9_-]{32}$/u.test(attempt.attemptId) ||
      typeof attempt.stateHash !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(attempt.stateHash) ||
      typeof attempt.verifierHash !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(attempt.verifierHash) ||
      typeof attempt.expiresAt !== 'number' ||
      (attempt.usedAt !== null && typeof attempt.usedAt !== 'number')
    ) return false;
  }
  if (input.result !== null) {
    if (!input.result || typeof input.result !== 'object' || Array.isArray(input.result)) return false;
    const result = input.result as Record<string, unknown>;
    const keys = Object.keys(result).sort().join(',');
    if (
      keys !== ['code', 'completedAt'].sort().join(',') &&
      keys !== ['code', 'completedAt', 'reason'].sort().join(',') &&
      keys !== ['code', 'completedAt', 'existingGateway'].sort().join(',') &&
      keys !== ['code', 'completedAt', 'existingGateway', 'reason'].sort().join(',') &&
      keys !== ['code', 'completedAt', 'installationId', 'grantRevocation'].sort().join(',')
    ) return false;
    if (typeof result.completedAt !== 'number' || !Number.isSafeInteger(result.completedAt)) return false;
    if (result.reason !== undefined && !isFailureReason(result.reason)) return false;
    if (result.existingGateway !== undefined && (
      result.code !== 'existing_gateway_detected' ||
      parseExistingAnkkaGatewaySummary(result.existingGateway) === null
    )) return false;
    if (result.code === 'existing_gateway_detected' && result.existingGateway === undefined) return false;
    if (result.reason !== undefined && result.code === 'install_complete') return false;
    if (result.code === 'install_complete') {
      if (
        typeof result.installationId !== 'string' ||
        !/^acg-[a-f0-9]{24}$/u.test(result.installationId) ||
        (result.grantRevocation !== 'confirmed' && result.grantRevocation !== 'unconfirmed')
      ) {
        return false;
      }
    } else if (
      !isDeployErrorCode(result.code) ||
      result.installationId !== undefined ||
      result.grantRevocation !== undefined
    ) {
      return false;
    }
  }
  return true;
}

export function requireStoredSession(value: unknown): StoredDeploySession {
  if (!isStoredSession(value)) throw new DeployError(500, 'session_invalid');
  assertSecretFree(value);
  return value;
}

export function verifyHash(actual: string, expected: string): void {
  if (!constantTimeEqual(actual, expected)) throw new DeployError(403, 'csrf_invalid');
}
