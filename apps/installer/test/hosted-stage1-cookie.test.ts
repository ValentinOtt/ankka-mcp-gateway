import { BOOTSTRAP_COOKIE } from '../src/constants';
import { bootstrapCookie, clearBootstrapCookie, readBootstrapCookie } from '../src/cookies';
import {
  HOSTED_STAGE1_COOKIE_TTL_MS,
  base64UrlEncode,
  openHostedStage1Cookie,
  openOauthCookie,
  sealHostedStage1Cookie,
  sealOauthCookie,
  type SealedBootstrapCookie,
} from '../src/crypto';
import { CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH } from '../src/customer-install-paths';
import {
  createHostedStage1Secrets,
  type HostedStage1Provision,
  type HostedStage1Secrets,
} from '../src/hosted-stage1-bootstrap';
import {
  authorizeHostedStage1Bootstrap,
  authorizeHostedStage1Cleanup,
  consumeHostedStage1Callback,
  freezeHostedStage1Plan,
  initializeHostedStage1Session,
  markHostedStage1CleanupRequired,
  markHostedStage1HandedOff,
  matchHostedStage1Cookie,
  recordHostedStage1Provision,
  saveHostedStage1Selection,
  type HostedStage1AuthorizationStart,
  type HostedStage1Session,
} from '../src/hosted-stage1-session';
import { buildStaticDeployPlan, parseDeploySelection, type StaticDeployPlan } from '../src/schema';
import { ENCRYPTION_KEY, manifest, selectionInput } from './fixtures';

const NOW = 1_800_000_000_000;
const ACCOUNT_ID = 'a'.repeat(32);
const WORKER_ID = 'b'.repeat(32);
const NAMESPACE_ID = 'c'.repeat(32);
const VERSION_ID = '11111111-1111-4111-8111-111111111111';
const DEPLOYMENT_ID = '22222222-2222-4222-8222-222222222222';

function deterministicRandomBytes(): (length: number) => Uint8Array {
  let counter = 0;
  return (length: number): Uint8Array => {
    counter += 1;
    return new Uint8Array(length).map((_, index) => (index * 11 + counter * 17) & 255);
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

function cookieFor(
  session: HostedStage1Session,
  start: HostedStage1AuthorizationStart,
  secrets: HostedStage1Secrets | null,
): SealedBootstrapCookie {
  if (session.plan === null) throw new Error('fixture session has no plan');
  return Object.freeze({
    schemaVersion: 10,
    purpose: 'bootstrap',
    kind: start.kind,
    sessionId: session.sessionId,
    attemptId: start.attemptId,
    state: start.state,
    verifier: start.verifier,
    expiresAt: start.expiresAt,
    planId: session.plan.planId,
    planHash: session.plan.planHash,
    capability: secrets === null ? null : Object.freeze({
      bootstrapId: secrets.capability.bootstrapId,
      capabilitySecret: secrets.capability.secret,
      capabilityExpiresAt: secrets.capability.expiresAt,
      bootstrapNonce: secrets.bootstrapNonce,
      ownershipWrapKey: secrets.ownershipWrapKey,
    }),
  });
}

async function authorizedFixture() {
  const randomBytes = deterministicRandomBytes();
  const initial = initializeHostedStage1Session({ now: NOW, randomBytes });
  const selection = parseDeploySelection(selectionInput);
  const withSelection = saveHostedStage1Selection({ current: initial, selection, now: NOW + 10 });
  const plan = await buildStaticDeployPlan(selection, manifest, NOW + 20 * 60_000);
  const withPlan = await freezeHostedStage1Plan({ current: withSelection, plan, now: NOW + 20 });
  const secrets = await createHostedStage1Secrets({ now: NOW + 30, randomBytes });
  const start = await authorizeHostedStage1Bootstrap({
    current: withPlan, capability: secrets.capability, now: NOW + 40, randomBytes,
  });
  const cookie = cookieFor(start.next, start, secrets);
  return { randomBytes, plan, secrets, start, cookie };
}

describe('hosted Stage 1 bootstrap cookie', () => {
  it('round trips every redirect secret only through authenticated encryption under its own AAD', async () => {
    const fixture = await authorizedFixture();
    const sealed = await sealHostedStage1Cookie(ENCRYPTION_KEY, fixture.cookie, NOW + 41);
    for (const secret of [
      fixture.cookie.state, fixture.cookie.verifier, fixture.secrets.capability.secret,
      fixture.secrets.bootstrapNonce, fixture.secrets.ownershipWrapKey, fixture.cookie.sessionId,
      fixture.cookie.attemptId,
    ]) {
      expect(sealed).not.toContain(secret);
    }
    await expect(openHostedStage1Cookie(ENCRYPTION_KEY, sealed, NOW + 42)).resolves.toEqual(fixture.cookie);

    const tampered = `${sealed.slice(0, -1)}${sealed.endsWith('A') ? 'B' : 'A'}`;
    await expect(openHostedStage1Cookie(ENCRYPTION_KEY, tampered, NOW + 42))
      .rejects.toMatchObject({ code: 'session_invalid' });
    await expect(openHostedStage1Cookie(base64UrlEncode(new Uint8Array(32).fill(9)), sealed, NOW + 42))
      .rejects.toMatchObject({ code: 'session_invalid' });
    // Neither cookie family can be opened by the other path.
    await expect(openOauthCookie(ENCRYPTION_KEY, sealed)).rejects.toMatchObject({ code: 'session_invalid' });
    const legacy = await sealOauthCookie(ENCRYPTION_KEY, {
      schemaVersion: 3,
      purpose: 'install',
      sessionId: base64UrlEncode(new Uint8Array(32).fill(1)),
      attemptId: `att_${base64UrlEncode(new Uint8Array(24).fill(2))}`,
      state: fixture.cookie.state,
      verifier: fixture.cookie.verifier,
      expiresAt: NOW + 600_000,
    });
    await expect(openHostedStage1Cookie(ENCRYPTION_KEY, legacy, NOW + 42))
      .rejects.toMatchObject({ code: 'session_invalid' });
  });

  it('rejects every malformed, widened, inconsistent, or out-of-window field at seal time', async () => {
    const fixture = await authorizedFixture();
    const cookie = fixture.cookie;
    const capability = cookie.capability;
    if (capability === null) throw new Error('bootstrap cookie must carry the capability');
    const rejected = [
      { name: 'legacySchema', payload: { ...cookie, schemaVersion: 3 } },
      { name: 'legacyPurpose', payload: { ...cookie, purpose: 'install' } },
      { name: 'unknownKind', payload: { ...cookie, kind: 'discover' } },
      { name: 'legacySessionId', payload: { ...cookie, sessionId: base64UrlEncode(new Uint8Array(32).fill(1)) } },
      { name: 'legacyAttemptId', payload: { ...cookie, attemptId: `att_${base64UrlEncode(new Uint8Array(24).fill(2))}` } },
      { name: 'shortState', payload: { ...cookie, state: cookie.state.slice(1) } },
      { name: 'shortVerifier', payload: { ...cookie, verifier: cookie.verifier.slice(1) } },
      { name: 'stateEqualsVerifier', payload: { ...cookie, verifier: cookie.state } },
      { name: 'badPlanId', payload: { ...cookie, planId: 'plan-nothex' } },
      { name: 'badPlanHash', payload: { ...cookie, planHash: `sha256:${'z'.repeat(64)}` } },
      { name: 'missingCapability', payload: { ...cookie, capability: null } },
      { name: 'cleanupWithCapability', payload: { ...cookie, kind: 'cleanup' } },
      { name: 'capabilityExpiryDrift', payload: { ...cookie, capability: { ...capability, capabilityExpiresAt: cookie.expiresAt + 1 } } },
      { name: 'shortSecret', payload: { ...cookie, capability: { ...capability, capabilitySecret: 'short' } } },
      { name: 'shortNonce', payload: { ...cookie, capability: { ...capability, bootstrapNonce: 'short' } } },
      { name: 'shortWrapKey', payload: { ...cookie, capability: { ...capability, ownershipWrapKey: 'short' } } },
      { name: 'extraCapabilityKey', payload: { ...cookie, capability: { ...capability, accessToken: 'x'.repeat(43) } } },
      { name: 'extraTopLevelKey', payload: { ...cookie, code: `code_${'h'.repeat(32)}` } },
      { name: 'beyondWindow', payload: {
        ...cookie,
        expiresAt: NOW + 41 + HOSTED_STAGE1_COOKIE_TTL_MS + 1,
        capability: { ...capability, capabilityExpiresAt: NOW + 41 + HOSTED_STAGE1_COOKIE_TTL_MS + 1 },
      } },
    ];
    for (const { name, payload } of rejected) {
      await expect(sealHostedStage1Cookie(ENCRYPTION_KEY, payload, NOW + 41), name)
        .rejects.toMatchObject({ code: 'session_invalid' });
    }
    await expect(sealHostedStage1Cookie(ENCRYPTION_KEY, cookie, cookie.expiresAt))
      .rejects.toMatchObject({ code: 'session_expired' });
    await expect(sealHostedStage1Cookie(ENCRYPTION_KEY, cookie, -1))
      .rejects.toMatchObject({ code: 'session_invalid' });
    await expect(sealHostedStage1Cookie(ENCRYPTION_KEY, 'not a cookie', NOW + 41))
      .rejects.toMatchObject({ code: 'session_invalid' });

    const sealed = await sealHostedStage1Cookie(ENCRYPTION_KEY, cookie, NOW + 41);
    await expect(openHostedStage1Cookie(ENCRYPTION_KEY, sealed, cookie.expiresAt))
      .rejects.toMatchObject({ code: 'session_expired' });
    await expect(openHostedStage1Cookie(ENCRYPTION_KEY, sealed, NOW))
      .rejects.toMatchObject({ code: 'session_invalid' });
  });

  it('emits and reads a __Host- HttpOnly Secure Lax cookie bounded to the bootstrap window', async () => {
    const fixture = await authorizedFixture();
    const sealed = await sealHostedStage1Cookie(ENCRYPTION_KEY, fixture.cookie, NOW + 41);
    const header = bootstrapCookie(sealed, 600);
    expect(BOOTSTRAP_COOKIE.startsWith('__Host-')).toBe(true);
    expect(header).toBe(`${BOOTSTRAP_COOKIE}=${sealed}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax`);
    expect(clearBootstrapCookie()).toBe(`${BOOTSTRAP_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
    expect(() => bootstrapCookie(sealed, 601)).toThrow(expect.objectContaining({ code: 'session_invalid' }));
    expect(() => bootstrapCookie(sealed, 0)).toThrow(expect.objectContaining({ code: 'session_invalid' }));
    expect(() => bootstrapCookie('not;sealed', 60)).toThrow(expect.objectContaining({ code: 'session_invalid' }));

    const request = new Request('https://deploy.ankka.ai/oauth/callback', {
      headers: { cookie: `other=1; ${BOOTSTRAP_COOKIE}=${sealed}; ${BOOTSTRAP_COOKIE}=second` },
    });
    expect(readBootstrapCookie(request)).toBe(sealed);
    expect(readBootstrapCookie(new Request('https://deploy.ankka.ai/'))).toBeNull();
    expect(readBootstrapCookie(new Request('https://deploy.ankka.ai/', {
      headers: { cookie: `${BOOTSTRAP_COOKIE}=%00bad` },
    }))).toBeNull();
  });

  it('exact-matches the cookie against session, attempt, plan, and capability commitments in each phase', async () => {
    const fixture = await authorizedFixture();
    const authorizing = fixture.start.next;
    await expect(matchHostedStage1Cookie({ current: authorizing, cookie: fixture.cookie, now: NOW + 41 }))
      .resolves.toEqual({ phase: 'authorizing', attemptId: fixture.start.attemptId });

    const otherSecrets = await createHostedStage1Secrets({ now: NOW + 30, randomBytes: fixture.randomBytes });
    const otherSession = initializeHostedStage1Session({ now: NOW, randomBytes: fixture.randomBytes });
    const wrong = [
      { name: 'foreignSession', cookie: { ...fixture.cookie, sessionId: otherSession.sessionId } },
      { name: 'foreignAttempt', cookie: { ...fixture.cookie, attemptId: `attempt_${'z'.repeat(24)}` } },
      { name: 'foreignPlanHash', cookie: { ...fixture.cookie, planHash: `sha256:${'0'.repeat(64)}` } },
      { name: 'foreignPlanId', cookie: { ...fixture.cookie, planId: `plan-${'0'.repeat(24)}` } },
      { name: 'otherCapability', cookie: cookieFor(authorizing, fixture.start, otherSecrets) },
      { name: 'noCapability', cookie: { ...fixture.cookie, kind: 'cleanup' as const, capability: null } },
    ];
    for (const { name, cookie } of wrong) {
      await expect(matchHostedStage1Cookie({ current: authorizing, cookie, now: NOW + 41 }), name)
        .rejects.toMatchObject({ code: 'invalid' });
    }
    await expect(matchHostedStage1Cookie({
      current: authorizing, cookie: fixture.cookie, now: fixture.cookie.expiresAt,
    })).rejects.toMatchObject({ code: 'expired' });

    const exchanging = await consumeHostedStage1Callback({
      current: authorizing,
      attemptId: fixture.start.attemptId,
      state: fixture.cookie.state,
      verifier: fixture.cookie.verifier,
      now: NOW + 50,
    });
    await expect(matchHostedStage1Cookie({ current: exchanging, cookie: fixture.cookie, now: NOW + 51 }))
      .resolves.toEqual({ phase: 'authorizing', attemptId: fixture.start.attemptId });

    const provisioned = recordHostedStage1Provision({
      current: exchanging,
      attemptId: fixture.start.attemptId,
      provision: provisionFor(fixture.plan, fixture.secrets),
      now: NOW + 60,
    });
    await expect(matchHostedStage1Cookie({ current: provisioned, cookie: fixture.cookie, now: NOW + 61 }))
      .resolves.toEqual({ phase: 'provisioned', attemptId: fixture.start.attemptId });
    await expect(matchHostedStage1Cookie({
      current: provisioned, cookie: cookieFor(provisioned, fixture.start, otherSecrets), now: NOW + 61,
    })).rejects.toMatchObject({ code: 'invalid' });

    const handedOff = markHostedStage1HandedOff({
      current: provisioned,
      bootstrapId: fixture.secrets.capability.bootstrapId,
      secretCommitment: fixture.secrets.capability.secretCommitment,
      now: NOW + 70,
    });
    await expect(matchHostedStage1Cookie({ current: handedOff, cookie: fixture.cookie, now: NOW + 71 }))
      .rejects.toMatchObject({ code: 'phase' });

    const cleanupRequired = markHostedStage1CleanupRequired({
      current: provisioned, reason: 'cookie_lost', now: NOW + 80,
    });
    await expect(matchHostedStage1Cookie({ current: cleanupRequired, cookie: fixture.cookie, now: NOW + 81 }))
      .rejects.toMatchObject({ code: 'invalid' });
    const cleanupStart = await authorizeHostedStage1Cleanup({
      current: cleanupRequired, now: NOW + 90, randomBytes: fixture.randomBytes,
    });
    const cleanupCookie = cookieFor(cleanupStart.next, cleanupStart, null);
    const sealed = await sealHostedStage1Cookie(ENCRYPTION_KEY, cleanupCookie, NOW + 91);
    await expect(openHostedStage1Cookie(ENCRYPTION_KEY, sealed, NOW + 92)).resolves.toEqual(cleanupCookie);
    await expect(matchHostedStage1Cookie({ current: cleanupStart.next, cookie: cleanupCookie, now: NOW + 92 }))
      .resolves.toEqual({ phase: 'cleanup_required', attemptId: cleanupStart.attemptId });
    await expect(matchHostedStage1Cookie({
      current: cleanupStart.next,
      cookie: { ...cleanupCookie, kind: 'bootstrap', capability: fixture.cookie.capability },
      now: NOW + 92,
    })).rejects.toMatchObject({ code: 'invalid' });
    await expect(matchHostedStage1Cookie({
      current: cleanupStart.next, cookie: { ...cleanupCookie, expiresAt: cleanupCookie.expiresAt - 1 }, now: NOW + 92,
    })).rejects.toMatchObject({ code: 'invalid' });
  });
});
