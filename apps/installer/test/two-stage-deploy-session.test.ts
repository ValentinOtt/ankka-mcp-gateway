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
  type HostedStage1AuthorizationStart,
} from '../src/hosted-stage1-session';
import { buildStaticDeployPlan, parseDeploySelection, type StaticDeployPlan } from '../src/schema';
import {
  TWO_STAGE_SESSION_INTERNAL_ORIGIN,
  TwoStageDeploySession,
  TwoStageDeploySessionClient,
} from '../src/two-stage-deploy-session';
import { manifest, selectionInput } from './fixtures';
import { FakeTwoStageState } from './hosted-stage1-sql-fake';

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
    return new Uint8Array(length).map((_, index) => (index * 5 + counter * 23) & 255);
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

function harness() {
  const clock = { now: NOW };
  const state = new FakeTwoStageState();
  const object = new TwoStageDeploySession(state, undefined, {
    now: () => clock.now,
    randomBytes: deterministicRandomBytes(),
  });
  const stub = { fetch: (request: Request) => object.fetch(request) };
  const client = new TwoStageDeploySessionClient(stub);
  return { clock, state, object, stub, client };
}

function internal(path: string, init?: RequestInit): Request {
  return new Request(`${TWO_STAGE_SESSION_INTERNAL_ORIGIN}${path}`, init);
}

async function provisionedHarness() {
  const h = harness();
  await h.client.initialize();
  const selection = parseDeploySelection(selectionInput);
  h.clock.now = NOW + 10;
  await h.client.saveSelection(selection);
  const plan = await buildStaticDeployPlan(selection, manifest, NOW + 20 * 60_000);
  h.clock.now = NOW + 20;
  await h.client.freezePlan(plan);
  const secrets = await createHostedStage1Secrets({ now: NOW + 30, randomBytes: deterministicRandomBytes() });
  h.clock.now = NOW + 40;
  const start = await h.client.authorizeBootstrap(secrets.capability);
  h.clock.now = NOW + 50;
  await h.client.consumeCallback({ attemptId: start.attemptId, state: start.state, verifier: start.verifier });
  h.clock.now = NOW + 60;
  const provision = provisionFor(plan, secrets);
  const provisioned = await h.client.recordProvision({ attemptId: start.attemptId, provision });
  return { ...h, selection, plan, secrets, start, provision, provisioned };
}

describe('TwoStageDeploySession Durable Object', () => {
  it('drives the session through RPC with revision checks, secret-free storage, and exact alarms', async () => {
    const h = harness();
    expect(await h.client.read()).toBeNull();
    const initial = await h.client.initialize();
    expect(initial).toMatchObject({ revision: 1, phase: 'draft' });
    expect(h.state.storage.alarmAt).toBe(NOW + HOSTED_STAGE1_SESSION_TTL_MS);
    await expect(h.client.initialize()).rejects.toMatchObject({ status: 409, code: 'session_conflict' });

    const selection = parseDeploySelection(selectionInput);
    h.clock.now = NOW + 10;
    const withSelection = await h.client.saveSelection(selection);
    expect(withSelection).toMatchObject({ revision: 2, selection });
    const plan = await buildStaticDeployPlan(selection, manifest, NOW + 20 * 60_000);
    h.clock.now = NOW + 20;
    const withPlan = await h.client.freezePlan(plan);
    expect(withPlan).toMatchObject({ revision: 3, plan });

    const secrets = await createHostedStage1Secrets({ now: NOW + 30, randomBytes: deterministicRandomBytes() });
    h.clock.now = NOW + 40;
    const start = await h.client.authorizeBootstrap(secrets.capability);
    expect(start.kind).toBe('bootstrap');
    expect(start.next).toMatchObject({ revision: 4, phase: 'authorizing' });
    expect(h.state.storage.alarmAt).toBe(secrets.capability.expiresAt);
    const stored = h.state.storage.sqlFake.state?.stateJson ?? '';
    expect(stored).not.toContain(start.state);
    expect(stored).not.toContain(start.verifier);
    expect(stored).not.toContain(secrets.capability.secret);
    expect(stored).toContain(secrets.capability.secretCommitment);

    h.clock.now = NOW + 50;
    const exchanging = await h.client.consumeCallback({
      attemptId: start.attemptId, state: start.state, verifier: start.verifier,
    });
    expect(exchanging).toMatchObject({ revision: 5, attempt: { status: 'exchanging' } });
    await expect(h.client.consumeCallback({
      attemptId: start.attemptId, state: start.state, verifier: start.verifier,
    })).rejects.toMatchObject({ status: 409, code: 'callback_invalid' });

    h.clock.now = NOW + 60;
    const provision = provisionFor(plan, secrets);
    const provisioned = await h.client.recordProvision({ attemptId: start.attemptId, provision });
    expect(provisioned).toMatchObject({ revision: 6, phase: 'provisioned', provision });
    expect(h.state.storage.alarmAt).toBe(secrets.capability.expiresAt);

    h.clock.now = NOW + 70;
    const handedOff = await h.client.markHandedOff({
      bootstrapId: secrets.capability.bootstrapId,
      secretCommitment: secrets.capability.secretCommitment,
    });
    expect(handedOff).toMatchObject({ revision: 7, phase: 'handed_off', handedOffAt: NOW + 70 });
    expect(h.state.storage.alarmAt).toBe(NOW + HOSTED_STAGE1_SESSION_TTL_MS);
    expect(await h.client.read()).toEqual(handedOff);
    expect(canonicalJson(await h.client.read())).toBe(h.state.storage.sqlFake.state?.stateJson);
  });

  it('rejects foreign origins, unknown paths, wrong methods, and malformed bodies without touching state', async () => {
    const h = harness();
    await h.client.initialize();
    const before = h.state.storage.sqlFake.state;
    const cases: readonly (readonly [Request, number])[] = [
      [new Request('https://deploy.ankka.ai/session'), 404],
      [internal('/session?x=1'), 404],
      [internal('/unknown', { method: 'POST' }), 404],
      [internal('/session', { method: 'POST' }), 405],
      [internal('/selection', { method: 'GET' }), 405],
      [internal('/selection', { method: 'POST', body: '{}' }), 400],
      [internal('/selection', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: '{not json',
      }), 400],
      [internal('/selection', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ selection: {}, extra: 1 }),
      }), 400],
      [internal('/selection', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ selection: { bogus: true } }),
      }), 400],
      [internal('/bootstrap/consume', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ attemptId: 'attempt_x', state: 'x', verifier: 'y' }),
      }), 400],
      [internal('/attempt/fail', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ attemptId: `attempt_${'z'.repeat(24)}`, code: 'made_up' }),
      }), 400],
      [internal('/bootstrap/authorize', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ capability: { bootstrapId: `boot_${'z'.repeat(24)}`, secret: 'x'.repeat(43), secretCommitment: `sha256:${'0'.repeat(64)}`, expiresAt: NOW + 1 } }),
      }), 400],
      [internal('/plan', {
        method: 'POST', headers: { 'content-type': 'application/json', 'content-length': String(300 * 1024) }, body: '{}',
      }), 413],
    ];
    for (const [request, status] of cases) {
      const response = await h.object.fetch(request);
      expect(response.status, request.url).toBe(status);
      expect(await response.json()).toMatchObject({ error: { code: expect.any(String) } });
    }
    expect(h.state.storage.sqlFake.state).toEqual(before);

    const missing = harness();
    await expect(missing.client.saveSelection(parseDeploySelection(selectionInput)))
      .rejects.toMatchObject({ status: 404, code: 'session_invalid' });
  });

  it('maps model errors to stable codes: phase and conflict to 409, expiry to 410, invalid to 400', async () => {
    const h = await provisionedHarness();
    await expect(h.client.saveSelection(h.selection)).rejects.toMatchObject({ status: 409, code: 'session_conflict' });
    await expect(h.client.markHandedOff({
      bootstrapId: h.secrets.capability.bootstrapId,
      secretCommitment: `sha256:${'1'.repeat(64)}`,
    })).rejects.toMatchObject({ status: 400, code: 'session_invalid' });
    h.clock.now = h.secrets.capability.expiresAt;
    await expect(h.client.markHandedOff({
      bootstrapId: h.secrets.capability.bootstrapId,
      secretCommitment: h.secrets.capability.secretCommitment,
    })).rejects.toMatchObject({ status: 410, code: 'session_expired' });
    expect((await h.client.read())?.revision).toBe(h.provisioned.revision);
  });

  it('runs the lost-cookie cleanup cycle over RPC and returns to draft with the plan discarded', async () => {
    const h = await provisionedHarness();
    h.clock.now = NOW + 80;
    const required = await h.client.requireCleanup('cookie_lost');
    expect(required).toMatchObject({ phase: 'cleanup_required', cleanup: { reason: 'cookie_lost' } });
    expect(h.state.storage.alarmAt).toBeNull();

    h.clock.now = NOW + 90;
    const cleanupStart = await h.client.authorizeCleanup();
    expect(cleanupStart).toMatchObject({ kind: 'cleanup', expiresAt: NOW + 90 + HOSTED_STAGE1_CLEANUP_ATTEMPT_TTL_MS });
    await expect(h.client.authorizeCleanup()).rejects.toMatchObject({ status: 409, code: 'session_conflict' });
    expect(h.state.storage.alarmAt).toBeNull();

    h.clock.now = NOW + 91;
    await expect(h.client.completeCleanup(cleanupStart.attemptId))
      .rejects.toMatchObject({ status: 409, code: 'session_conflict' });
    await h.client.consumeCallback({
      attemptId: cleanupStart.attemptId, state: cleanupStart.state, verifier: cleanupStart.verifier,
    });
    h.clock.now = NOW + 92;
    const completed = await h.client.completeCleanup(cleanupStart.attemptId);
    expect(completed).toMatchObject({
      phase: 'draft', plan: null, provision: null, selection: h.selection, cleanup: { completedAt: NOW + 92 },
    });
    expect(h.state.storage.alarmAt).toBe(NOW + 92 + HOSTED_STAGE1_SESSION_TTL_MS);

    h.clock.now = NOW + 93;
    const failedCleanup = await provisionedHarness();
    failedCleanup.clock.now = NOW + 80;
    await failedCleanup.client.requireCleanup('handoff_rejected');
    const attempt = await failedCleanup.client.authorizeCleanup();
    const failed = await failedCleanup.client.failAttempt({ attemptId: attempt.attemptId, code: 'cleanup_failed' });
    expect(failed).toMatchObject({ phase: 'cleanup_required', attempt: null, failure: { code: 'cleanup_failed' } });
  });

  it('reaps on alarm: erases dead drafts, escalates lapsed capabilities, fails expired attempts, keeps obligations', async () => {
    const draft = harness();
    await draft.client.initialize();
    draft.clock.now = NOW + HOSTED_STAGE1_SESSION_TTL_MS;
    await draft.object.alarm();
    expect(draft.state.storage.deleteAllCalls).toBe(1);
    expect(draft.state.storage.alarmAt).toBeNull();
    expect(await draft.client.read()).toBeNull();
    const reborn = await draft.client.initialize();
    expect(reborn.revision).toBe(1);

    const lapsed = await provisionedHarness();
    lapsed.clock.now = lapsed.secrets.capability.expiresAt;
    await lapsed.object.alarm();
    expect(await lapsed.client.read()).toMatchObject({
      phase: 'cleanup_required', cleanup: { reason: 'capability_expired', completedAt: null },
    });
    expect(lapsed.state.storage.alarmAt).toBeNull();
    lapsed.clock.now = NOW + 10 * HOSTED_STAGE1_SESSION_TTL_MS;
    await lapsed.object.alarm();
    expect((await lapsed.client.read())?.phase).toBe('cleanup_required');
    expect(lapsed.state.storage.deleteAllCalls).toBe(0);

    const abandoned = harness();
    await abandoned.client.initialize();
    const selection = parseDeploySelection(selectionInput);
    await abandoned.client.saveSelection(selection);
    await abandoned.client.freezePlan(await buildStaticDeployPlan(selection, manifest, NOW + 20 * 60_000));
    const secrets = await createHostedStage1Secrets({ now: NOW + 30, randomBytes: deterministicRandomBytes() });
    abandoned.clock.now = NOW + 40;
    const start: HostedStage1AuthorizationStart = await abandoned.client.authorizeBootstrap(secrets.capability);
    abandoned.clock.now = NOW + 41;
    await abandoned.object.alarm();
    expect((await abandoned.client.read())?.phase).toBe('authorizing');
    expect(abandoned.state.storage.alarmAt).toBe(secrets.capability.expiresAt);
    abandoned.clock.now = secrets.capability.expiresAt;
    await abandoned.object.alarm();
    expect(await abandoned.client.read()).toMatchObject({
      phase: 'failed', failure: { code: 'attempt_expired', attemptId: start.attemptId },
    });
    expect(abandoned.state.storage.alarmAt).toBe(NOW + HOSTED_STAGE1_SESSION_TTL_MS);

    const empty = harness();
    await empty.object.alarm();
    expect(empty.state.storage.alarmAt).toBeNull();
  });
});
