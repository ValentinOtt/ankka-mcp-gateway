import * as v from 'valibot';

import { boundaryValueSchema } from './boundary';
import { REQUIRED_OAUTH_SCOPES, type RequiredOauthScope } from './constants';
import { sha256Hex } from './crypto';
import { DeployError } from './errors';
import {
  parseExistingAnkkaGatewaySummary,
  type ExistingAnkkaGatewaySummary,
} from './cloudflare-gateway-fresh-preflight';
import { canonicalJson } from './release-manifest';
import { assertSecretFree } from './schema';

const PLAN_ID = /^returning-uninstall-plan-[a-f0-9]{24}$/u;
const HASH = /^sha256:[a-f0-9]{64}$/u;
export const MAX_RETURNING_UNINSTALL_PLAN_TTL_MS = 10 * 60 * 1_000;

// Schema-v1 hash/parser values, not display-only copy; preserve published plans.
export const RETURNING_UNINSTALL_STEPS = Object.freeze([
  'Prove the one-time action and exact root receipt in the customer-owned Worker.',
  'Deploy the signed cleanup Worker and remove only receipt-owned gateway resources.',
  'Remove the exact management Custom Domain, Access policy, and Access application.',
  'Retire AdminState, remove the exact management Worker, and prove no managed residue remains.',
] as const);
const safeNonnegativeIntegerSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const returningUninstallPlanSchema = v.strictObject({
  authority: v.literal('customer_receipt_one_time_action'),
  createdAt: safeNonnegativeIntegerSchema,
  expiresAt: safeNonnegativeIntegerSchema,
  gateway: boundaryValueSchema,
  planHash: v.string(),
  planId: v.string(),
  requiredScopes: v.array(v.string()),
  schemaVersion: v.literal(1),
  steps: v.tuple([
    v.literal(RETURNING_UNINSTALL_STEPS[0]),
    v.literal(RETURNING_UNINSTALL_STEPS[1]),
    v.literal(RETURNING_UNINSTALL_STEPS[2]),
    v.literal(RETURNING_UNINSTALL_STEPS[3]),
  ]),
  writesPerformed: v.literal(false),
});

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

export async function buildReturningUninstallPlan<Gateway>(
  gatewayValue: Gateway,
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

export async function parseReturningUninstallPlan<Input>(value: Input): Promise<ReturningUninstallPlan> {
  const result = v.safeParse(returningUninstallPlanSchema, value);
  if (!result.success) throw new DeployError(400, 'bad_request');
  const input = result.output;
  if (!PLAN_ID.test(input.planId) || !HASH.test(input.planHash) ||
    input.expiresAt <= input.createdAt ||
    input.expiresAt - input.createdAt > MAX_RETURNING_UNINSTALL_PLAN_TTL_MS ||
    input.requiredScopes.length !== REQUIRED_OAUTH_SCOPES.length ||
    input.requiredScopes.some((scope, index) => scope !== REQUIRED_OAUTH_SCOPES[index])) {
    throw new DeployError(400, 'bad_request');
  }
  const gateway = parseExistingAnkkaGatewaySummary(input.gateway);
  if (!gateway) throw new DeployError(400, 'bad_request');
  const expected = await buildReturningUninstallPlan(gateway, input.createdAt, input.expiresAt);
  if (expected.planId !== input.planId || expected.planHash !== input.planHash) {
    throw new DeployError(400, 'bad_request');
  }
  return expected;
}
