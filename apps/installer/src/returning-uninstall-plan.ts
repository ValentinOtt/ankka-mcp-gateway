import { REQUIRED_OAUTH_SCOPES, type RequiredOauthScope } from './constants';
import { sha256Hex } from './crypto';
import { DeployError } from './errors';
import {
  parseExistingAnkkaGatewaySummary,
  type ExistingAnkkaGatewaySummary,
} from './cloudflare-gateway-fresh-preflight';
import { assertSecretFree } from './schema';

const PLAN_ID = /^returning-uninstall-plan-[a-f0-9]{24}$/u;
const HASH = /^sha256:[a-f0-9]{64}$/u;
export const MAX_RETURNING_UNINSTALL_PLAN_TTL_MS = 10 * 60 * 1_000;

export const RETURNING_UNINSTALL_STEPS = Object.freeze([
  'Prove the one-time action and exact root receipt in the customer-owned Worker.',
  'Deploy the signed cleanup Worker and remove only receipt-owned gateway resources.',
  'Remove the exact management Custom Domain, Access policy, and Access application.',
  'Retire AdminState, remove the exact management Worker, and prove no managed residue remains.',
] as const);

export interface ReturningUninstallPlan {
  readonly schemaVersion: 1;
  readonly planId: string;
  readonly planHash: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly writesPerformed: false;
  readonly authority: 'customer_receipt_one_time_action';
  readonly requiredScopes: readonly RequiredOauthScope[];
  readonly gateway: ExistingAnkkaGatewaySummary;
  readonly steps: typeof RETURNING_UNINSTALL_STEPS;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  throw new TypeError('canonical_returning_uninstall_plan');
}

function semantic(gateway: ExistingAnkkaGatewaySummary) {
  return Object.freeze({
    schemaVersion: 1 as const,
    writesPerformed: false as const,
    authority: 'customer_receipt_one_time_action' as const,
    requiredScopes: REQUIRED_OAUTH_SCOPES,
    gateway,
    steps: RETURNING_UNINSTALL_STEPS,
  });
}

export async function buildReturningUninstallPlan(
  gatewayValue: unknown,
  createdAt: number,
  expiresAt: number,
): Promise<ReturningUninstallPlan> {
  const gateway = parseExistingAnkkaGatewaySummary(gatewayValue);
  if (!gateway || !Number.isSafeInteger(createdAt) || createdAt < 0 ||
    !Number.isSafeInteger(expiresAt) || expiresAt <= createdAt ||
    expiresAt - createdAt > MAX_RETURNING_UNINSTALL_PLAN_TTL_MS) {
    throw new DeployError(400, 'bad_request');
  }
  const core = semantic(gateway);
  const digest = await sha256Hex(canonicalJson(core));
  const plan = Object.freeze({
    ...core,
    planId: `returning-uninstall-plan-${digest.slice(0, 24)}`,
    planHash: `sha256:${digest}`,
    createdAt,
    expiresAt,
  });
  assertSecretFree(plan);
  return plan;
}

export async function parseReturningUninstallPlan(value: unknown): Promise<ReturningUninstallPlan> {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'planId', 'planHash', 'createdAt', 'expiresAt', 'writesPerformed',
    'authority', 'requiredScopes', 'gateway', 'steps',
  ]) || value.schemaVersion !== 1 || typeof value.planId !== 'string' || !PLAN_ID.test(value.planId) ||
    typeof value.planHash !== 'string' || !HASH.test(value.planHash) ||
    !Number.isSafeInteger(value.createdAt) || !Number.isSafeInteger(value.expiresAt) ||
    (value.expiresAt as number) <= (value.createdAt as number) ||
    (value.expiresAt as number) - (value.createdAt as number) > MAX_RETURNING_UNINSTALL_PLAN_TTL_MS ||
    value.writesPerformed !== false || value.authority !== 'customer_receipt_one_time_action' ||
    !Array.isArray(value.requiredScopes) || value.requiredScopes.length !== REQUIRED_OAUTH_SCOPES.length ||
    value.requiredScopes.some((scope, index) => scope !== REQUIRED_OAUTH_SCOPES[index]) ||
    canonicalJson(value.steps) !== canonicalJson(RETURNING_UNINSTALL_STEPS)) {
    throw new DeployError(400, 'bad_request');
  }
  const gateway = parseExistingAnkkaGatewaySummary(value.gateway);
  if (!gateway) throw new DeployError(400, 'bad_request');
  const expected = await buildReturningUninstallPlan(gateway, value.createdAt as number, value.expiresAt as number);
  if (expected.planId !== value.planId || expected.planHash !== value.planHash) {
    throw new DeployError(400, 'bad_request');
  }
  return expected;
}
