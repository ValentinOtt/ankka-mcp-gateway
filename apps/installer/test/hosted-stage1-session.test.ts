import { canonicalJson } from '../src/canonical-json';
import { CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH } from '../src/customer-install-paths';
import {
  createHostedStage1Secrets,
  type HostedStage1Provision,
  type HostedStage1Secrets,
} from '../src/hosted-stage1-bootstrap';
import {
  HOSTED_STAGE1_CLEANUP_ATTEMPT_TTL_MS,
  HOSTED_STAGE1_SESSION_TTL_MS,
  authorizeHostedStage1Bootstrap,
  authorizeHostedStage1Cleanup,
  completeHostedStage1Cleanup,
  consumeHostedStage1Callback,
  failHostedStage1Attempt,
  freezeHostedStage1Plan,
  initializeHostedStage1Session,
  markHostedStage1CleanupRequired,
  markHostedStage1HandedOff,
  parseHostedStage1Session,
  publicHostedStage1Session,
  reapHostedStage1Session,
  recordHostedStage1Provision,
  saveHostedStage1Selection,
  type HostedStage1AuthorizationStart,
  type HostedStage1Session,
} from '../src/hosted-stage1-session';
import {
  buildStaticDeployPlan,
  forbiddenStoredKeyPath,
  parseDeploySelection,
  type StaticDeployPlan,
} from '../src/schema';
import { manifest, selectionInput } from './fixtures';

const NOW = 1_800_000_000_000;
const ACCOUNT_ID = 'a'.repeat(32);
const WORKER_ID = 'b'.repeat(32);
const NAMESPACE_ID = 'c'.repeat(32);
const VERSION_ID = '11111111-1111-4111-8111-111111111111';
const DEPLOYMENT_ID = '22222222-2222-4222-8222-222222222222';
const ACCESS_TOKEN = `token_${'d'.repeat(32)}`;
const AUTHORIZATION_CODE = `code_${'h'.repeat(32)}`;

function deterministicRandomBytes(): (length: number) => Uint8Array {
  let counter = 0;
  return (length: number): Uint8Array => {
    counter += 1;
    return new Uint8Array(length).map((_, index) => (index * 7 + counter * 13) & 255);
  };
}

function managementWorkerName(plan: StaticDeployPlan): string {
  const worker = plan.managementResources.find((resource) => resource.kind === 'management_worker');
  if (worker === undefined) throw new Error('fixture plan has no management worker');
  return worker.name;
}

function provisionFor(plan: StaticDeployPlan, secrets: HostedStage1Secrets): HostedStage1Provision {
  const workerName = managementWorkerName(plan);
  const bootstrapOrigin = `https://${workerName}.tenant.workers.dev/`;
  return Object.freeze({
    schemaVersion: 1,
    accountId: ACCOUNT_ID,
    bootstrapId: secrets.capability.bootstrapId,
    bootstrapSecretCommitment: secrets.capability.secretCommitment,
    capabilityExpiresAt: secrets.capability.expiresAt,
    bootstrapOrigin,
    bootstrapCallback: `${bootstrapOrigin.slice(0, -1)}${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`,
    deployment: Object.freeze({
      workerId: WORKER_ID,
      workerName,
      namespaceId: NAMESPACE_ID,
      namespaceName: `${workerName}_AdminState`,
      deploymentId: DEPLOYMENT_ID,
      versionId: VERSION_ID,
      release: plan.releaseId,
      artifactSha256: plan.releaseArtifactSha256,
      bootstrapComponentSha256: plan.bootstrapWorkerSourceSha256,
      sourceSha256: plan.bootstrapWorkerSourceSha256,
      recovery: 'created' as const,
    }),
    grantRevocation: 'confirmed' as const,
    handoff: `signed-handoff-${'s'.repeat(64)}`,
    installId: plan.managementOwnershipMarker,
    plan: Object.freeze({ id: plan.planId, hash: plan.planHash }),
    release: Object.freeze({ id: plan.releaseId, artifactSha256: plan.releaseArtifactSha256 }),
    workersSubdomain: 'tenant',
  });
}

function expectSecretFree(
  session: HostedStage1Session,
  secrets: HostedStage1Secrets,
  starts: readonly HostedStage1AuthorizationStart[],
): void {
  const serialized = canonicalJson(session);
  expect(forbiddenStoredKeyPath(session)).toBeNull();
  expect(serialized).not.toContain(secrets.capability.secret);
  expect(serialized).not.toContain(secrets.bootstrapNonce);
  expect(serialized).not.toContain(secrets.ownershipWrapKey);
  expect(serialized).not.toContain(ACCESS_TOKEN);
  expect(serialized).not.toContain(AUTHORIZATION_CODE);
  for (const start of starts) {
    expect(serialized).not.toContain(start.state);
    expect(serialized).not.toContain(start.verifier);
  }
  expect(parseHostedStage1Session(JSON.parse(serialized))).toEqual(session);
}

async function draftWithPlan() {
  const randomBytes = deterministicRandomBytes();
  const initial = initializeHostedStage1Session({ now: NOW, randomBytes });
  const selection = parseDeploySelection(selectionInput);
  const withSelection = saveHostedStage1Selection({ current: initial, selection, now: NOW + 10 });
  const plan = await buildStaticDeployPlan(selection, manifest, NOW + 20 * 60_000);
  const withPlan = await freezeHostedStage1Plan({ current: withSelection, plan, now: NOW + 20 });
  const secrets = await createHostedStage1Secrets({ now: NOW + 30, randomBytes });
  return { randomBytes, initial, selection, withSelection, plan, withPlan, secrets };
}

async function provisioned() {
  const fixture = await draftWithPlan();
  const start = await authorizeHostedStage1Bootstrap({
    current: fixture.withPlan,
    capability: fixture.secrets.capability,
    now: NOW + 40,
    randomBytes: fixture.randomBytes,
  });
  const exchanging = await consumeHostedStage1Callback({
    current: start.next,
    attemptId: start.attemptId,
    state: start.state,
    verifier: start.verifier,
    now: NOW + 50,
  });
  const provision = provisionFor(fixture.plan, fixture.secrets);
  const recorded = recordHostedStage1Provision({
    current: exchanging,
    attemptId: start.attemptId,
    provision,
    now: NOW + 60,
  });
  return { ...fixture, start, exchanging, provision, recorded };
}

describe('hosted Stage 1 session model', () => {
  it('walks draft to handed_off with revision-checked, secret-free state', async () => {
    const fixture = await provisioned();
    expect(fixture.initial).toMatchObject({ revision: 1, phase: 'draft', selection: null, plan: null });
    expect(fixture.initial.expiresAt).toBe(NOW + HOSTED_STAGE1_SESSION_TTL_MS);
    expect(fixture.withSelection).toMatchObject({ revision: 2, phase: 'draft', selection: fixture.selection });
    expect(fixture.withPlan).toMatchObject({ revision: 3, phase: 'draft', plan: fixture.plan });
    expect(fixture.start.next).toMatchObject({
      revision: 4,
      phase: 'authorizing',
      attempt: {
        attemptId: fixture.start.attemptId,
        kind: 'bootstrap',
        status: 'authorizing',
        expiresAt: fixture.secrets.capability.expiresAt,
        capability: {
          bootstrapId: fixture.secrets.capability.bootstrapId,
          secretCommitment: fixture.secrets.capability.secretCommitment,
          expiresAt: fixture.secrets.capability.expiresAt,
        },
      },
    });
    expect(fixture.start.state).not.toBe(fixture.start.verifier);
    expect(fixture.exchanging).toMatchObject({ revision: 5, phase: 'authorizing', attempt: { status: 'exchanging' } });
    expect(fixture.recorded).toMatchObject({
      revision: 6,
      phase: 'provisioned',
      attempt: null,
      provisionedAttemptId: fixture.start.attemptId,
      provision: fixture.provision,
    });

    const handedOff = markHostedStage1HandedOff({
      current: fixture.recorded,
      bootstrapId: fixture.secrets.capability.bootstrapId,
      secretCommitment: fixture.secrets.capability.secretCommitment,
      now: NOW + 70,
    });
    expect(handedOff).toMatchObject({ revision: 7, phase: 'handed_off', handedOffAt: NOW + 70 });

    for (const session of [
      fixture.initial, fixture.withSelection, fixture.withPlan, fixture.start.next,
      fixture.exchanging, fixture.recorded, handedOff,
    ]) {
      expectSecretFree(session, fixture.secrets, [fixture.start]);
    }

    const publicView = canonicalJson(publicHostedStage1Session(fixture.recorded));
    expect(publicView).not.toContain(fixture.provision.handoff);
    expect(publicView).not.toContain(fixture.start.next.attempt?.stateHash ?? 'unreachable');
    expect(publicView).not.toContain('stateHash');
    expect(publicView).toContain(fixture.provision.bootstrapOrigin);
    expect(publicHostedStage1Session(fixture.start.next)).toMatchObject({
      phase: 'authorizing',
      attempt: { attemptId: fixture.start.attemptId, kind: 'bootstrap' },
      plan: { planId: fixture.plan.planId, managementHostname: 'manage.example.com' },
    });
  });

  it('rejects duplicate, stale, mismatched, and expired callbacks before any exchange', async () => {
    const fixture = await draftWithPlan();
    const start = await authorizeHostedStage1Bootstrap({
      current: fixture.withPlan, capability: fixture.secrets.capability, now: NOW + 40, randomBytes: fixture.randomBytes,
    });
    const callback = { current: start.next, attemptId: start.attemptId, state: start.state, verifier: start.verifier };

    await expect(consumeHostedStage1Callback({ ...callback, state: start.verifier, now: NOW + 41 }))
      .rejects.toMatchObject({ code: 'invalid' });
    await expect(consumeHostedStage1Callback({ ...callback, verifier: start.state, now: NOW + 41 }))
      .rejects.toMatchObject({ code: 'invalid' });
    await expect(consumeHostedStage1Callback({ ...callback, attemptId: `attempt_${'z'.repeat(24)}`, now: NOW + 41 }))
      .rejects.toMatchObject({ code: 'invalid' });
    await expect(consumeHostedStage1Callback({ ...callback, now: fixture.secrets.capability.expiresAt }))
      .rejects.toMatchObject({ code: 'expired' });

    const exchanging = await consumeHostedStage1Callback({ ...callback, now: NOW + 42 });
    await expect(consumeHostedStage1Callback({ ...callback, current: exchanging, now: NOW + 43 }))
      .rejects.toMatchObject({ code: 'consumed' });
    await expect(consumeHostedStage1Callback({ ...callback, current: fixture.withPlan, now: NOW + 43 }))
      .rejects.toMatchObject({ code: 'phase' });
  });

  it('records a provision only for the exchanging attempt with exact commitments and confirmed revocation', async () => {
    const fixture = await draftWithPlan();
    const start = await authorizeHostedStage1Bootstrap({
      current: fixture.withPlan, capability: fixture.secrets.capability, now: NOW + 40, randomBytes: fixture.randomBytes,
    });
    const provision = provisionFor(fixture.plan, fixture.secrets);
    expect(() => recordHostedStage1Provision({
      current: start.next, attemptId: start.attemptId, provision, now: NOW + 41,
    })).toThrow(expect.objectContaining({ code: 'phase' }));

    const exchanging = await consumeHostedStage1Callback({
      current: start.next, attemptId: start.attemptId, state: start.state, verifier: start.verifier, now: NOW + 42,
    });
    const otherSecrets = await createHostedStage1Secrets({ now: NOW + 30, randomBytes: fixture.randomBytes });
    expect(() => recordHostedStage1Provision({
      current: exchanging, attemptId: start.attemptId, provision: provisionFor(fixture.plan, otherSecrets), now: NOW + 43,
    })).toThrow(expect.objectContaining({ code: 'invalid' }));
    expect(() => recordHostedStage1Provision({
      current: exchanging,
      attemptId: start.attemptId,
      provision: { ...provision, plan: { id: provision.plan.id, hash: `sha256:${'0'.repeat(64)}` } },
      now: NOW + 43,
    })).toThrow(expect.objectContaining({ code: 'invalid' }));
    expect(() => recordHostedStage1Provision({
      current: exchanging,
      attemptId: start.attemptId,
      // Anything other than confirmed revocation is not a provision at all.
      provision: JSON.parse(canonicalJson(provision).replace('"confirmed"', '"attempted"')),
      now: NOW + 43,
    })).toThrow();

    const recorded = recordHostedStage1Provision({
      current: exchanging, attemptId: start.attemptId, provision, now: NOW + 44,
    });
    expect(recorded.phase).toBe('provisioned');
    expect(() => recordHostedStage1Provision({
      current: recorded, attemptId: start.attemptId, provision, now: NOW + 45,
    })).toThrow(expect.objectContaining({ code: 'phase' }));
  });

  it('records attempt failures without provider text and permits a fresh approval of the same plan', async () => {
    const fixture = await draftWithPlan();
    const start = await authorizeHostedStage1Bootstrap({
      current: fixture.withPlan, capability: fixture.secrets.capability, now: NOW + 40, randomBytes: fixture.randomBytes,
    });
    const failed = failHostedStage1Attempt({
      current: start.next, attemptId: start.attemptId, code: 'authorization_rejected', now: NOW + 50,
    });
    expect(failed).toMatchObject({
      phase: 'failed',
      attempt: null,
      failure: { code: 'authorization_rejected', attemptId: start.attemptId, at: NOW + 50 },
      plan: fixture.plan,
    });
    expect(() => failHostedStage1Attempt({
      current: failed, attemptId: start.attemptId, code: 'grant_invalid', now: NOW + 51,
    })).toThrow(expect.objectContaining({ code: 'invalid' }));

    const freshSecrets = await createHostedStage1Secrets({ now: NOW + 60, randomBytes: fixture.randomBytes });
    const fresh = await authorizeHostedStage1Bootstrap({
      current: failed, capability: freshSecrets.capability, now: NOW + 60, randomBytes: fixture.randomBytes,
    });
    expect(fresh.next).toMatchObject({ phase: 'authorizing', failure: null });
    expect(fresh.attemptId).not.toBe(start.attemptId);
    expectSecretFree(fresh.next, freshSecrets, [start, fresh]);

    const edited = saveHostedStage1Selection({
      current: failed,
      selection: parseDeploySelection({ ...selectionInput, firstSource: null }),
      now: NOW + 70,
    });
    expect(edited).toMatchObject({ phase: 'draft', plan: null, failure: null });
    await expect(authorizeHostedStage1Bootstrap({
      current: edited, capability: freshSecrets.capability, now: NOW + 71, randomBytes: fixture.randomBytes,
    })).rejects.toMatchObject({ code: 'phase' });
  });

  it('refuses a plan for a different selection, an expired plan, or a capability beyond the plan window', async () => {
    const fixture = await draftWithPlan();
    const otherSelection = parseDeploySelection({ ...selectionInput, firstSource: null });
    const otherPlan = await buildStaticDeployPlan(otherSelection, manifest, NOW + 20 * 60_000);
    await expect(freezeHostedStage1Plan({ current: fixture.withSelection, plan: otherPlan, now: NOW + 20 }))
      .rejects.toMatchObject({ code: 'invalid' });
    const expiredPlan = await buildStaticDeployPlan(fixture.selection, manifest, NOW + 5);
    await expect(freezeHostedStage1Plan({ current: fixture.withSelection, plan: expiredPlan, now: NOW + 20 }))
      .rejects.toMatchObject({ code: 'invalid' });
    await expect(freezeHostedStage1Plan({ current: fixture.initial, plan: fixture.plan, now: NOW + 20 }))
      .rejects.toMatchObject({ code: 'phase' });

    const lateSecrets = await createHostedStage1Secrets({ now: NOW + 15 * 60_000, randomBytes: fixture.randomBytes });
    await expect(authorizeHostedStage1Bootstrap({
      current: fixture.withPlan, capability: lateSecrets.capability, now: NOW + 15 * 60_000, randomBytes: fixture.randomBytes,
    })).rejects.toMatchObject({ code: 'invalid' });
    await expect(authorizeHostedStage1Bootstrap({
      current: fixture.withPlan, capability: fixture.secrets.capability, now: NOW + HOSTED_STAGE1_SESSION_TTL_MS,
    })).rejects.toMatchObject({ code: 'expired' });
  });

  it('binds handoff to the recorded capability commitment and its expiry', async () => {
    const fixture = await provisioned();
    expect(() => markHostedStage1HandedOff({
      current: fixture.recorded,
      bootstrapId: fixture.secrets.capability.bootstrapId,
      secretCommitment: `sha256:${'1'.repeat(64)}`,
      now: NOW + 70,
    })).toThrow(expect.objectContaining({ code: 'invalid' }));
    expect(() => markHostedStage1HandedOff({
      current: fixture.recorded,
      bootstrapId: fixture.secrets.capability.bootstrapId,
      secretCommitment: fixture.secrets.capability.secretCommitment,
      now: fixture.secrets.capability.expiresAt,
    })).toThrow(expect.objectContaining({ code: 'expired' }));
    expect(() => markHostedStage1HandedOff({
      current: fixture.withPlan,
      bootstrapId: fixture.secrets.capability.bootstrapId,
      secretCommitment: fixture.secrets.capability.secretCommitment,
      now: NOW + 70,
    })).toThrow(expect.objectContaining({ code: 'phase' }));
  });

  it('turns a lost cookie into an exact cleanup obligation and returns to draft only after cleanup', async () => {
    const fixture = await provisioned();
    const required = markHostedStage1CleanupRequired({
      current: fixture.recorded, reason: 'cookie_lost', now: NOW + 80,
    });
    expect(required).toMatchObject({
      phase: 'cleanup_required',
      provision: fixture.provision,
      cleanup: { reason: 'cookie_lost', requiredAt: NOW + 80, completedAt: null },
    });
    expect(() => markHostedStage1HandedOff({
      current: required,
      bootstrapId: fixture.secrets.capability.bootstrapId,
      secretCommitment: fixture.secrets.capability.secretCommitment,
      now: NOW + 81,
    })).toThrow(expect.objectContaining({ code: 'phase' }));
    expect(publicHostedStage1Session(required).provision).toEqual({
      installId: fixture.plan.managementOwnershipMarker,
      workerName: managementWorkerName(fixture.plan),
      bootstrapOrigin: fixture.provision.bootstrapOrigin,
      capabilityExpiresAt: fixture.secrets.capability.expiresAt,
    });

    const cleanupStart = await authorizeHostedStage1Cleanup({
      current: required, now: NOW + 90, randomBytes: fixture.randomBytes,
    });
    expect(cleanupStart.next).toMatchObject({
      phase: 'cleanup_required',
      attempt: { kind: 'cleanup', status: 'authorizing', capability: null, expiresAt: NOW + 90 + HOSTED_STAGE1_CLEANUP_ATTEMPT_TTL_MS },
    });
    await expect(authorizeHostedStage1Cleanup({ current: cleanupStart.next, now: NOW + 91 }))
      .rejects.toMatchObject({ code: 'conflict' });
    expectSecretFree(cleanupStart.next, fixture.secrets, [fixture.start, cleanupStart]);

    const lostCleanup = failHostedStage1Attempt({
      current: cleanupStart.next, attemptId: cleanupStart.attemptId, code: 'cleanup_failed', now: NOW + 92,
    });
    expect(lostCleanup).toMatchObject({
      phase: 'cleanup_required', attempt: null, failure: { code: 'cleanup_failed' }, provision: fixture.provision,
    });

    const retry = await authorizeHostedStage1Cleanup({
      current: lostCleanup, now: NOW + 93, randomBytes: fixture.randomBytes,
    });
    expect(() => completeHostedStage1Cleanup({
      current: retry.next, attemptId: retry.attemptId, now: NOW + 94,
    })).toThrow(expect.objectContaining({ code: 'phase' }));
    const exchanging = await consumeHostedStage1Callback({
      current: retry.next, attemptId: retry.attemptId, state: retry.state, verifier: retry.verifier, now: NOW + 94,
    });
    const completed = completeHostedStage1Cleanup({
      current: exchanging, attemptId: retry.attemptId, now: NOW + 95,
    });
    expect(completed).toMatchObject({
      phase: 'draft',
      selection: fixture.selection,
      plan: null,
      provision: null,
      attempt: null,
      provisionedAttemptId: null,
      failure: null,
      cleanup: { reason: 'cookie_lost', requiredAt: NOW + 80, completedAt: NOW + 95 },
      expiresAt: NOW + 95 + HOSTED_STAGE1_SESSION_TTL_MS,
    });
    expectSecretFree(completed, fixture.secrets, [fixture.start, cleanupStart, retry]);
  });

  it('reaps expired drafts, lapsed capabilities, and expired attempts but never cleanup obligations', async () => {
    const fixture = await provisioned();
    expect(reapHostedStage1Session({ current: fixture.withPlan, now: NOW + 100 })).toEqual({ action: 'retain' });
    expect(reapHostedStage1Session({ current: fixture.withPlan, now: NOW + HOSTED_STAGE1_SESSION_TTL_MS }))
      .toEqual({ action: 'erase' });

    const lapsed = reapHostedStage1Session({
      current: fixture.recorded, now: fixture.secrets.capability.expiresAt,
    });
    expect(lapsed).toMatchObject({
      action: 'replace',
      next: { phase: 'cleanup_required', cleanup: { reason: 'capability_expired', completedAt: null } },
    });
    if (lapsed.action !== 'replace') throw new Error('expected replacement');
    expect(reapHostedStage1Session({ current: lapsed.next, now: NOW + 10 * HOSTED_STAGE1_SESSION_TTL_MS }))
      .toEqual({ action: 'retain' });

    const expiredAttempt = reapHostedStage1Session({
      current: fixture.start.next, now: fixture.secrets.capability.expiresAt,
    });
    expect(expiredAttempt).toMatchObject({
      action: 'replace',
      next: { phase: 'failed', attempt: null, failure: { code: 'attempt_expired', attemptId: fixture.start.attemptId } },
    });

    const handedOff = markHostedStage1HandedOff({
      current: fixture.recorded,
      bootstrapId: fixture.secrets.capability.bootstrapId,
      secretCommitment: fixture.secrets.capability.secretCommitment,
      now: NOW + 70,
    });
    expect(reapHostedStage1Session({ current: handedOff, now: NOW + 71 })).toEqual({ action: 'retain' });
    expect(reapHostedStage1Session({ current: handedOff, now: NOW + HOSTED_STAGE1_SESSION_TTL_MS }))
      .toEqual({ action: 'erase' });
  });

  it('parses only exact, canonical, secret-free state that satisfies the phase invariants', async () => {
    const fixture = await provisioned();
    const serialized = canonicalJson(fixture.recorded);
    expect(parseHostedStage1Session(JSON.parse(serialized))).toEqual(fixture.recorded);

    expect(parseHostedStage1Session({ ...fixture.recorded, revision: 0 })).toBeNull();
    expect(parseHostedStage1Session({ ...fixture.recorded, phase: 'draft' })).toBeNull();
    expect(parseHostedStage1Session({ ...fixture.recorded, plan: null })).toBeNull();
    expect(parseHostedStage1Session({ ...fixture.recorded, attempt: fixture.start.next.attempt })).toBeNull();
    expect(parseHostedStage1Session({ ...fixture.withPlan, provision: fixture.provision })).toBeNull();
    expect(parseHostedStage1Session({
      ...fixture.withSelection,
      selection: { ...fixture.selection, basics: { ...fixture.selection.basics, adminEmail: 'Owner@Example.com' } },
    })).toBeNull();
    expect(parseHostedStage1Session({
      ...fixture.recorded,
      provision: { ...fixture.provision, accessToken: ACCESS_TOKEN },
    })).toBeNull();
    expect(parseHostedStage1Session({
      ...fixture.recorded,
      attempt: { ...fixture.start.next.attempt, verifier: fixture.start.verifier },
    })).toBeNull();
    expect(parseHostedStage1Session(JSON.parse(serialized.replace(
      fixture.provision.plan.hash, `sha256:${'0'.repeat(64)}`,
    )))).toBeNull();
    expect(parseHostedStage1Session({ ...fixture.recorded, updatedAt: fixture.recorded.createdAt - 1 })).toBeNull();
    expect(parseHostedStage1Session('not a session')).toBeNull();
  });
});
