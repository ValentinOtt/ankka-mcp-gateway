import { OAUTH_COOKIE, PUBLIC_ORIGIN, SESSION_COOKIE } from '../src/constants';
import { base64UrlEncode, openOauthCookie } from '../src/crypto';
import { createGatewayDeployWorker } from '../src/index';
import { parseDeploySelection } from '../src/schema';
import {
  cookiePair,
  ENCRYPTION_KEY,
  env,
  FakeDeploySessionNamespace,
  NOW,
  selectionInput,
} from './fixtures';

const ACCOUNT_ID = 'a'.repeat(32);
const ZONE_ID = 'b'.repeat(32);
const TARGET_ID_HASH = `sha256:${'1'.repeat(64)}`;
const ACTION_KEY = base64UrlEncode(new Uint8Array(32).fill(9));
const EXISTING_GATEWAY = Object.freeze({
  schemaVersion: 1 as const,
  installationId: `acg-${'d'.repeat(24)}`,
  name: selectionInput.basics.gatewayName,
  managementHostname: selectionInput.basics.managementHostname,
  portalHostname: selectionInput.basics.portalHostname,
  workerName: 'ankka-gateway-example',
});

const preparedResponseSchema = v.strictObject({
  schemaVersion: v.literal(1),
  reviewUrl: v.string(),
  planId: v.string(),
});
const publicSessionSchema = v.looseObject({
  capabilities: v.looseObject({ uninstall: v.boolean() }),
  removal: v.looseObject({
    plan: v.looseObject({ planId: v.string(), planHash: v.string() }),
  }),
});
const startedResponseSchema = v.looseObject({
  authorizationUrl: v.string(),
  handoffUrl: v.string(),
});

function encodeHandoff(value: BoundaryValue): string {
  return base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)));
}

function mutationHeaders(cookie: string): HeadersInit {
  return {
    origin: PUBLIC_ORIGIN,
    'sec-fetch-site': 'same-origin',
    'content-type': 'application/json',
    cookie,
  };
}

interface SeededSession {
  readonly sessionCookie: string;
  readonly sessionId: string;
  readonly claim: {
    readonly schemaVersion: 3;
    readonly actionType: 'gateway_teardown';
    readonly actionId: string;
    readonly actionKey: string;
    readonly actorEmail: string;
    readonly accountId: string;
    readonly installationId: string;
    readonly gatewayName: string;
    readonly portalHostname: string;
    readonly workerName: string;
    readonly workersSubdomain: string;
    readonly managementOrigin: string;
    readonly expiresAt: number;
  };
}

async function seedExistingGatewaySession(
  worker: ReturnType<typeof createGatewayDeployWorker>,
  workerEnv: ReturnType<typeof env>,
  namespace: FakeDeploySessionNamespace,
  actionCharacter = 'A',
): Promise<SeededSession> {
  const created = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`), workerEnv);
  expect(created.status).toBe(200);
  const sessionCookie = cookiePair(created.headers.get('set-cookie') ?? '', SESSION_COOKIE);
  const sessionId = sessionCookie.slice(sessionCookie.indexOf('=') + 1);
  const state = namespace.states.get(sessionId);
  if (!state) throw new Error('test session was not created');
  const stored = v.parse(boundaryObjectSchema, state.storage.values.get('deploy-session-v1'));
  const expiresAt = v.parse(v.number(), stored.expiresAt);
  state.storage.values.set('deploy-session-v1', {
    ...stored,
    status: 'failed',
    updatedAt: NOW,
    selection: parseDeploySelection(selectionInput),
    plan: null,
    oauthAttempt: null,
    result: {
      code: 'existing_gateway_detected',
      completedAt: NOW,
      existingGateway: EXISTING_GATEWAY,
    },
  });
  state.storage.values.set('cloudflare-discovery-v1', {
    schemaVersion: 1,
    status: 'ready',
    updatedAt: NOW,
    expiresAt,
    oauthAttempt: {
      attemptId: `att_${'D'.repeat(32)}`,
      stateHash: 's'.repeat(43),
      verifierHash: 'v'.repeat(43),
      expiresAt: NOW + 100_000,
      usedAt: NOW,
    },
    result: {
      actor: { id: 'user-12345678', email: 'owner@example.com' },
      targets: [{
        targetIdHash: TARGET_ID_HASH,
        account: { id: ACCOUNT_ID, name: 'Primary account' },
        zone: { id: ZONE_ID, name: 'example.com', status: 'active' },
      }],
    },
    selectedTargetIdHash: TARGET_ID_HASH,
    failureCode: null,
    grantRevocation: 'confirmed',
  });
  return {
    sessionCookie,
    sessionId,
    claim: {
      schemaVersion: 3,
      actionType: 'gateway_teardown',
      actionId: `action_${actionCharacter.repeat(32)}`,
      actionKey: ACTION_KEY,
      actorEmail: 'owner@example.com',
      accountId: ACCOUNT_ID,
      installationId: EXISTING_GATEWAY.installationId,
      gatewayName: EXISTING_GATEWAY.name,
      portalHostname: EXISTING_GATEWAY.portalHostname,
      workerName: EXISTING_GATEWAY.workerName,
      workersSubdomain: 'customer-workers',
      managementOrigin: `https://${EXISTING_GATEWAY.managementHostname}`,
      expiresAt: NOW + 600_000,
    },
  };
}

async function submitHandoff(
  worker: ReturnType<typeof createGatewayDeployWorker>,
  workerEnv: ReturnType<typeof env>,
  seeded: SeededSession,
  claim: BoundaryValue = seeded.claim,
): Promise<Response> {
  return worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/management/authorize`, {
    method: 'POST',
    headers: mutationHeaders(seeded.sessionCookie),
    body: JSON.stringify({ handoff: encodeHandoff(claim) }),
  }), workerEnv);
}

describe('returning-customer management handoff', () => {
  it('parses schema 3 into a session-bound v6 review cookie and a secret-free public removal plan', async () => {
    const namespace = new FakeDeploySessionNamespace(() => NOW);
    const workerEnv = env(namespace);
    const worker = createGatewayDeployWorker({
      now: () => NOW,
      capabilityPolicy: { deploy: false, uninstall: true, events: false },
    });
    const seeded = await seedExistingGatewaySession(worker, workerEnv, namespace);

    const prepared = await submitHandoff(worker, workerEnv, seeded);
    expect(prepared.status).toBe(200);
    const preparedBody = v.parse(preparedResponseSchema, await prepared.json());
    expect(preparedBody).toEqual({
      schemaVersion: 1,
      reviewUrl: '/result',
      planId: expect.stringMatching(/^returning-uninstall-plan-[a-f0-9]{24}$/u),
    });
    const reviewCookie = cookiePair(prepared.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
    const review = await openOauthCookie(ENCRYPTION_KEY, reviewCookie.slice(reviewCookie.indexOf('=') + 1));
    expect(review).toEqual({
      schemaVersion: 6,
      purpose: 'gateway_teardown_review',
      sessionId: seeded.sessionId,
      expiresAt: seeded.claim.expiresAt,
      actionId: seeded.claim.actionId,
      actionKey: seeded.claim.actionKey,
      actorEmail: seeded.claim.actorEmail,
      accountId: seeded.claim.accountId,
      installationId: seeded.claim.installationId,
      gatewayName: seeded.claim.gatewayName,
      portalHostname: seeded.claim.portalHostname,
      workerName: seeded.claim.workerName,
      workersSubdomain: seeded.claim.workersSubdomain,
      managementOrigin: seeded.claim.managementOrigin,
    });

    const publicResponse = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: seeded.sessionCookie },
    }), workerEnv);
    const publicSession = v.parse(publicSessionSchema, await publicResponse.json());
    expect(publicSession.capabilities.uninstall).toBe(true);
    expect(publicSession.removal).toMatchObject({
      status: 'planned',
      recovery: null,
      canRetry: false,
      failure: null,
      receipt: null,
      plan: {
        planId: preparedBody.planId,
        writesPerformed: false,
        installationId: EXISTING_GATEWAY.installationId,
        release: null,
        operations: [
          { id: 'returning_teardown_1' },
          { id: 'returning_teardown_2' },
          { id: 'returning_teardown_3' },
          { id: 'returning_teardown_4' },
        ],
      },
    });
    expect(JSON.stringify(publicSession)).not.toMatch(
      /actionId|actionKey|accountId|stateHash|verifierHash|attemptId|workersSubdomain|cloudflareAccessToken|access_token|refresh_token|authorizationCode/iu,
    );
  });

  it('rejects widened or malformed schema-3 claims before creating teardown state', async () => {
    const namespace = new FakeDeploySessionNamespace(() => NOW);
    const workerEnv = env(namespace);
    const worker = createGatewayDeployWorker({
      now: () => NOW,
      capabilityPolicy: { deploy: false, uninstall: true, events: false },
    });
    const seeded = await seedExistingGatewaySession(worker, workerEnv, namespace);
    const malformed = [
      { ...seeded.claim, extra: true },
      { ...seeded.claim, actionType: 'runtime_update' },
      { ...seeded.claim, actorEmail: 'Owner@example.com' },
      { ...seeded.claim, accountId: 'not-an-account' },
      { ...seeded.claim, installationId: `acg-${'Z'.repeat(24)}` },
      { ...seeded.claim, portalHostname: 'MCP.example.com' },
      { ...seeded.claim, managementOrigin: 'https://manage.example.com/path' },
      { ...seeded.claim, expiresAt: NOW + 600_001 },
    ];

    for (const claim of malformed) {
      const response = await submitHandoff(worker, workerEnv, seeded, claim);
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ code: 'bad_request' });
    }
    const state = namespace.states.get(seeded.sessionId);
    expect(state?.storage.values.has('returning-uninstall-v1')).toBe(false);
  });

  it('binds a valid claim to the discovered actor, account, and exact detected gateway', async () => {
    const mismatches = [
      { actorEmail: 'other@example.com' },
      { accountId: 'f'.repeat(32) },
      { installationId: `acg-${'e'.repeat(24)}` },
      { gatewayName: 'Another Gateway' },
      { portalHostname: 'other.example.com' },
      { workerName: 'another-worker' },
      { managementOrigin: 'https://other.example.com' },
    ];

    for (const mismatch of mismatches) {
      const namespace = new FakeDeploySessionNamespace(() => NOW);
      const workerEnv = env(namespace);
      const worker = createGatewayDeployWorker({
        now: () => NOW,
        capabilityPolicy: { deploy: false, uninstall: true, events: false },
      });
      const seeded = await seedExistingGatewaySession(worker, workerEnv, namespace);
      const response = await submitHandoff(worker, workerEnv, seeded, { ...seeded.claim, ...mismatch });
      expect(response.status).toBe(409);
      expect(await response.json()).toEqual({ code: 'session_conflict' });
    }
  });

  it('requires the exact v6 review cookie and session before minting a v7 OAuth attempt', async () => {
    const namespace = new FakeDeploySessionNamespace(() => NOW);
    const workerEnv = env(namespace);
    const worker = createGatewayDeployWorker({
      now: () => NOW,
      capabilityPolicy: { deploy: false, uninstall: true, events: false },
    });
    const first = await seedExistingGatewaySession(worker, workerEnv, namespace, 'A');
    const second = await seedExistingGatewaySession(worker, workerEnv, namespace, 'B');
    const firstPrepared = await submitHandoff(worker, workerEnv, first);
    const secondPrepared = await submitHandoff(worker, workerEnv, second);
    expect(firstPrepared.status).toBe(200);
    expect(secondPrepared.status).toBe(200);
    const firstReview = cookiePair(firstPrepared.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
    const secondReview = cookiePair(secondPrepared.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
    const secondPlan = v.parse(preparedResponseSchema, await secondPrepared.json()).planId;
    const secondPublic = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: second.sessionCookie },
    }), workerEnv);
    const plan = v.parse(publicSessionSchema, await secondPublic.json()).removal.plan;
    expect(plan.planId).toBe(secondPlan);

    const crossed = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/returning-uninstall`, {
      method: 'POST',
      headers: mutationHeaders(`${second.sessionCookie}; ${firstReview}`),
      body: JSON.stringify({ planId: plan.planId, planHash: plan.planHash }),
    }), workerEnv);
    expect(crossed.status).toBe(409);
    expect(await crossed.json()).toEqual({ code: 'session_conflict' });

    const started = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/returning-uninstall`, {
      method: 'POST',
      headers: mutationHeaders(`${second.sessionCookie}; ${secondReview}`),
      body: JSON.stringify({ planId: plan.planId, planHash: plan.planHash }),
    }), workerEnv);
    expect(started.status).toBe(200);
    const startedBody = v.parse(startedResponseSchema, await started.json());
    expect(new URL(startedBody.authorizationUrl).origin).toBe('https://dash.cloudflare.com');
    expect(new URL(startedBody.handoffUrl).origin + new URL(startedBody.handoffUrl).pathname)
      .toBe(`${PUBLIC_ORIGIN}/oauth/handoff`);
    const attemptCookie = cookiePair(started.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
    const attempt = await openOauthCookie(ENCRYPTION_KEY, attemptCookie.slice(attemptCookie.indexOf('=') + 1));
    expect(attempt).toMatchObject({
      schemaVersion: 7,
      purpose: 'gateway_teardown',
      sessionId: second.sessionId,
      actionId: second.claim.actionId,
      installationId: EXISTING_GATEWAY.installationId,
    });
    if (attempt.schemaVersion !== 7) throw new Error('expected v7 teardown attempt');
    expect(new URL(startedBody.authorizationUrl).searchParams.get('state')).toBe(attempt.state);

    const replay = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/returning-uninstall`, {
      method: 'POST',
      headers: mutationHeaders(`${second.sessionCookie}; ${secondReview}`),
      body: JSON.stringify({ planId: plan.planId, planHash: plan.planHash }),
    }), workerEnv);
    expect(replay.status).toBe(409);
  });
});
import * as v from 'valibot';

import { boundaryObjectSchema, type BoundaryValue } from '../src/boundary';
