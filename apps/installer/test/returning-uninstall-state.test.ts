import { REQUIRED_OAUTH_SCOPES } from '../src/constants';
import { sha256 } from '../src/crypto';
import {
  buildReturningUninstallPlan,
  MAX_RETURNING_UNINSTALL_PLAN_TTL_MS,
  parseReturningUninstallPlan,
  RETURNING_UNINSTALL_STEPS,
} from '../src/returning-uninstall-plan';
import {
  parsePublicReturningUninstall,
  publicReturningUninstall,
  requireStoredReturningUninstall,
} from '../src/returning-uninstall-session';
import { MAX_RETURNING_UNINSTALL_RECOVERY_RETENTION_MS } from '../src/returning-uninstall-journal';
import { NOW } from './fixtures';

const gateway = Object.freeze({
  schemaVersion: 1 as const,
  installationId: `acg-${'d'.repeat(24)}`,
  name: 'Example Gateway',
  managementHostname: 'manage.example.com',
  portalHostname: 'mcp.example.com',
  workerName: 'ankka-gateway-example',
});

async function plannedState() {
  const expiresAt = NOW + MAX_RETURNING_UNINSTALL_PLAN_TTL_MS;
  const plan = await buildReturningUninstallPlan(gateway, NOW, expiresAt);
  return {
    schemaVersion: 1 as const,
    status: 'planned' as const,
    createdAt: NOW,
    updatedAt: NOW,
    recoverUntil: NOW + MAX_RETURNING_UNINSTALL_RECOVERY_RETENTION_MS,
    plan,
    action: {
      actionId: `action_${'A'.repeat(32)}`,
      actionKeyHash: await sha256('one-time-customer-action-key'),
      actorEmail: 'owner@example.com',
      accountId: 'a'.repeat(32),
      workerName: gateway.workerName,
      workersSubdomain: 'customer-workers',
      managementOrigin: `https://${gateway.managementHostname}`,
      expiresAt,
    },
    oauthAttempt: null,
    result: null,
  };
}

function oauthAttempt(expiresAt: number, usedAt: number | null = null) {
  return {
    purpose: 'customer_action' as const,
    attemptId: `att_${'B'.repeat(32)}`,
    stateHash: 's'.repeat(43),
    verifierHash: 'v'.repeat(43),
    expiresAt,
    usedAt,
  };
}

describe('returning-customer uninstall plan', () => {
  it('builds and reparses a deterministic, zero-write, exact-scope plan', async () => {
    const plan = await buildReturningUninstallPlan(
      gateway,
      NOW,
      NOW + MAX_RETURNING_UNINSTALL_PLAN_TTL_MS,
    );

    expect(plan).toMatchObject({
      schemaVersion: 1,
      planId: expect.stringMatching(/^returning-uninstall-plan-[a-f0-9]{24}$/u),
      planHash: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
      writesPerformed: false,
      authority: 'customer_receipt_one_time_action',
      gateway,
    });
    expect(plan.requiredScopes).toEqual(REQUIRED_OAUTH_SCOPES);
    expect(plan.steps).toEqual(RETURNING_UNINSTALL_STEPS);
    await expect(parseReturningUninstallPlan(structuredClone(plan))).resolves.toEqual(plan);

    const rebuilt = await buildReturningUninstallPlan(gateway, NOW + 1, NOW + 10_001);
    expect(rebuilt.planId).toBe(plan.planId);
    expect(rebuilt.planHash).toBe(plan.planHash);
  });

  it('rejects widened, re-ordered, overlong, and semantically tampered plans', async () => {
    const plan = await buildReturningUninstallPlan(gateway, NOW, NOW + 10_000);
    const candidates = [
      { ...plan, surprise: true },
      { ...plan, requiredScopes: [...plan.requiredScopes].reverse() },
      { ...plan, steps: [...plan.steps].reverse() },
      { ...plan, gateway: { ...plan.gateway, portalHostname: 'other.example.com' } },
      { ...plan, planHash: `sha256:${'0'.repeat(64)}` },
      { ...plan, expiresAt: plan.createdAt + MAX_RETURNING_UNINSTALL_PLAN_TTL_MS + 1 },
    ];

    for (const candidate of candidates) {
      await expect(parseReturningUninstallPlan(candidate))
        .rejects.toMatchObject({ code: 'bad_request' });
    }
  });
});

describe('returning-customer uninstall stored and public state', () => {
  it('accepts each valid lifecycle state and projects no action authority or OAuth hashes publicly', async () => {
    const planned = await plannedState();
    const attempt = oauthAttempt(planned.plan.expiresAt - 1);
    const states = [
      planned,
      { ...planned, status: 'authorizing', updatedAt: NOW + 1, oauthAttempt: attempt },
      {
        ...planned,
        status: 'removing',
        updatedAt: NOW + 2,
        oauthAttempt: { ...attempt, usedAt: NOW + 2 },
      },
      {
        ...planned,
        status: 'removed',
        updatedAt: NOW + 3,
        oauthAttempt: { ...attempt, usedAt: NOW + 2 },
        result: {
          code: 'returning_uninstall_complete',
          completedAt: NOW + 3,
          installationId: gateway.installationId,
          grantRevocation: 'confirmed',
        },
      },
      {
        ...planned,
        status: 'failed',
        updatedAt: NOW + 3,
        oauthAttempt: { ...attempt, usedAt: NOW + 2 },
        result: { code: 'internal_error', completedAt: NOW + 3, reason: 'provider_unavailable' },
      },
    ];

    for (const state of states) {
      const parsed = await requireStoredReturningUninstall(state);
      const projected = publicReturningUninstall(parsed);
      await expect(parsePublicReturningUninstall(structuredClone(projected))).resolves.toEqual(projected);
      expect(Object.keys(projected).sort()).toEqual([
        'plan', 'recoverUntil', 'recoveryAvailable', 'result', 'schemaVersion', 'status', 'updatedAt',
      ]);
      expect(JSON.stringify(projected)).not.toMatch(
        /actionId|actionKey|actorEmail|accountId|stateHash|verifierHash|attemptId|workersSubdomain/iu,
      );
    }
  });

  it('rejects impossible lifecycle combinations and authority that is not bound to the reviewed gateway', async () => {
    const planned = await plannedState();
    const attempt = oauthAttempt(planned.plan.expiresAt - 1);
    const usedAttempt = { ...attempt, usedAt: NOW + 2 };
    const success = {
      code: 'returning_uninstall_complete',
      completedAt: NOW + 3,
      installationId: gateway.installationId,
      grantRevocation: 'confirmed',
    };
    const candidates = [
      { ...planned, oauthAttempt: attempt },
      { ...planned, status: 'authorizing', oauthAttempt: usedAttempt },
      { ...planned, status: 'removing', oauthAttempt: attempt },
      { ...planned, status: 'removed', oauthAttempt: usedAttempt, result: null },
      { ...planned, status: 'failed', oauthAttempt: usedAttempt, result: success },
      { ...planned, status: 'authorizing', oauthAttempt: { ...attempt, expiresAt: planned.plan.expiresAt + 1 } },
      { ...planned, action: { ...planned.action, workerName: 'another-worker' } },
      { ...planned, action: { ...planned.action, managementOrigin: 'https://other.example.com' } },
      { ...planned, action: { ...planned.action, expiresAt: planned.plan.expiresAt - 1 } },
    ];

    for (const candidate of candidates) {
      await expect(requireStoredReturningUninstall(candidate))
        .rejects.toMatchObject({ code: 'session_invalid' });
    }
  });

  it('rejects public projections with private fields or contradictory terminal results', async () => {
    const planned = await requireStoredReturningUninstall(await plannedState());
    const publicState = publicReturningUninstall(planned);
    const success = {
      code: 'returning_uninstall_complete',
      completedAt: NOW + 3,
      installationId: gateway.installationId,
      grantRevocation: 'confirmed',
    };
    const candidates = [
      { ...publicState, action: planned.action },
      { ...publicState, status: 'planned', result: success },
      { ...publicState, status: 'removed', result: null },
      { ...publicState, status: 'failed', result: success },
    ];

    for (const candidate of candidates) {
      await expect(parsePublicReturningUninstall(candidate))
        .rejects.toMatchObject({ code: 'session_invalid' });
    }
  });
});
