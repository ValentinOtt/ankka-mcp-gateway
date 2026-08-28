import { sha256 } from '../src/crypto';
import { GatewayDeploySession } from '../src/durable/gateway-deploy-session';
import { MAX_INSTALL_RECOVERY_RETENTION_MS } from '../src/install-journal';
import {
  FakeState,
  internalRequest,
  manifest,
  NOW,
  selectionInput,
} from './fixtures';

async function body(response: Response): Promise<Record<string, any>> {
  return response.json() as Promise<Record<string, any>>;
}

describe('GatewayDeploySession SQLite Durable Object state machine', () => {
  const csrf = 'c'.repeat(43);
  const stateValue = 's'.repeat(43);
  const verifier = 'v'.repeat(43);
  const attemptId = `att_${'a'.repeat(32)}`;

  async function prepared(planExpiresAt = NOW + 600_000) {
    const state = new FakeState();
    let currentTime = NOW;
    const object = new GatewayDeploySession(
      state as unknown as DurableObjectState,
      undefined,
      () => currentTime,
    );
    const csrfHash = await sha256(csrf);
    expect((await object.fetch(internalRequest('/initialize', 'POST', {
      csrfHash,
      createdAt: NOW,
      expiresAt: NOW + 1_800_000,
    }))).status).toBe(201);
    expect((await object.fetch(internalRequest('/selection', 'PUT', {
      csrfHash,
      selection: selectionInput,
      now: NOW + 1,
    }))).status).toBe(200);
    const planResponse = await object.fetch(internalRequest('/plan', 'POST', {
      csrfHash,
      releaseManifest: manifest,
      planExpiresAt,
      now: NOW + 2,
    }));
    const plan = (await body(planResponse)).session.plan;
    return { state, object, csrfHash, plan, setNow: (value: number) => { currentTime = value; } };
  }

  it('stores only canonical selection, plan, and state/verifier hashes', async () => {
    const { state, object, csrfHash, plan } = await prepared();
    const response = await object.fetch(internalRequest('/authorize', 'POST', {
      csrfHash,
      releaseManifest: manifest,
      approvedPlanId: plan.planId,
      approvedPlanHash: plan.planHash,
      attemptId,
      stateHash: await sha256(stateValue),
      verifierHash: await sha256(verifier),
      attemptExpiresAt: NOW + 500_000,
      now: NOW + 3,
    }));
    expect(response.status).toBe(200);
    const serialized = JSON.stringify([...state.storage.values.values()]);
    expect(serialized).not.toContain(stateValue);
    expect(serialized).not.toContain(verifier);
    expect(serialized).not.toMatch(/access[_-]?token|refresh[_-]?token|client[_-]?secret/iu);
    expect(serialized).toContain(await sha256(stateValue));
    expect(serialized).toContain(await sha256(verifier));
  });

  it('alarms anonymous sessions and removes their state at the fixed expiry', async () => {
    const state = new FakeState();
    let currentTime = NOW;
    const object = new GatewayDeploySession(
      state as unknown as DurableObjectState,
      undefined,
      () => currentTime,
    );
    await object.fetch(internalRequest('/initialize', 'POST', {
      csrfHash: await sha256(csrf),
      createdAt: 1,
      expiresAt: 2,
    }));
    expect(state.storage.alarmAt).toBe(NOW + 1_800_000);
    currentTime = NOW + 1_800_000;
    await object.alarm();
    expect(state.storage.values.size).toBe(0);
    expect(state.storage.alarmAt).toBeNull();
  });

  it('removes canonical selection PII when the session alarm expires', async () => {
    const { state, object, setNow } = await prepared();
    expect(JSON.stringify([...state.storage.values.values()])).toContain('owner@example.com');
    setNow(NOW + 1_800_000);
    await object.alarm();
    expect(JSON.stringify([...state.storage.values.values()])).not.toContain('owner@example.com');
    expect(state.storage.values.size).toBe(0);
    expect(state.storage.alarmAt).toBeNull();
  });

  it('purges malformed stored state instead of retaining or rescheduling it', async () => {
    const state = new FakeState();
    state.storage.values.set('deploy-session-v1', {
      schemaVersion: 1,
      malformedPii: 'owner@example.com',
    });
    state.storage.alarmAt = NOW;
    const object = new GatewayDeploySession(state as unknown as DurableObjectState);
    await object.alarm();
    expect(state.storage.values.size).toBe(0);
    expect(state.storage.alarmAt).toBeNull();
  });

  it('rederives the approved static plan and rejects a changed release', async () => {
    const { object, csrfHash, plan } = await prepared();
    const response = await object.fetch(internalRequest('/authorize', 'POST', {
      csrfHash,
      releaseManifest: {
        ...manifest,
        components: {
          ...manifest.components,
          worker: { ...manifest.components.worker, treeSha256: 'd'.repeat(64) },
        },
      },
      approvedPlanId: plan.planId,
      approvedPlanHash: plan.planHash,
      attemptId,
      stateHash: await sha256(stateValue),
      verifierHash: await sha256(verifier),
      attemptExpiresAt: NOW + 500_000,
      now: NOW + 3,
    }));
    expect(response.status).toBe(409);
    expect(await body(response)).toEqual({ error: { code: 'session_conflict' } });
  });

  it('consumes an OAuth state exactly once before any exchange', async () => {
    const { object, csrfHash, plan } = await prepared();
    await object.fetch(internalRequest('/authorize', 'POST', {
      csrfHash,
      releaseManifest: manifest,
      approvedPlanId: plan.planId,
      approvedPlanHash: plan.planHash,
      attemptId,
      stateHash: await sha256(stateValue),
      verifierHash: await sha256(verifier),
      attemptExpiresAt: NOW + 500_000,
      now: NOW + 3,
    }));
    const consume = {
      attemptId,
      stateHash: await sha256(stateValue),
      verifierHash: await sha256(verifier),
      now: NOW + 4,
    };
    const consumed = await object.fetch(internalRequest('/consume', 'POST', consume));
    expect(consumed.status).toBe(200);
    expect(await body(consumed)).toMatchObject({
      recoverUntil: NOW + 1_800_000 + MAX_INSTALL_RECOVERY_RETENTION_MS,
    });
    const replay = await object.fetch(internalRequest('/consume', 'POST', consume));
    expect(replay.status).toBe(400);
    expect(await body(replay)).toEqual({ error: { code: 'oauth_state_invalid' } });
  });

  it('caps authorization at the approved plan and accepts only the T-minus-one-second boundary', async () => {
    const planExpiresAt = NOW + 10_000;
    const preparedBeforeExpiry = await prepared(planExpiresAt);
    const tooLong = await preparedBeforeExpiry.object.fetch(internalRequest('/authorize', 'POST', {
      csrfHash: preparedBeforeExpiry.csrfHash,
      releaseManifest: manifest,
      approvedPlanId: preparedBeforeExpiry.plan.planId,
      approvedPlanHash: preparedBeforeExpiry.plan.planHash,
      attemptId,
      stateHash: await sha256(stateValue),
      verifierHash: await sha256(verifier),
      attemptExpiresAt: planExpiresAt + 1,
      now: NOW + 3,
    }));
    expect(tooLong.status).toBe(400);

    const accepted = await preparedBeforeExpiry.object.fetch(internalRequest('/authorize', 'POST', {
      csrfHash: preparedBeforeExpiry.csrfHash,
      releaseManifest: manifest,
      approvedPlanId: preparedBeforeExpiry.plan.planId,
      approvedPlanHash: preparedBeforeExpiry.plan.planHash,
      attemptId,
      stateHash: await sha256(stateValue),
      verifierHash: await sha256(verifier),
      attemptExpiresAt: planExpiresAt,
      now: NOW + 3,
    }));
    expect(accepted.status).toBe(200);
    preparedBeforeExpiry.setNow(planExpiresAt - 1_000);
    const tMinusOneSecond = await preparedBeforeExpiry.object.fetch(internalRequest('/consume', 'POST', {
      attemptId,
      stateHash: await sha256(stateValue),
      verifierHash: await sha256(verifier),
      now: planExpiresAt - 1_000,
    }));
    expect(tMinusOneSecond.status).toBe(200);

    const atExpiry = await prepared(planExpiresAt);
    await atExpiry.object.fetch(internalRequest('/authorize', 'POST', {
      csrfHash: atExpiry.csrfHash,
      releaseManifest: manifest,
      approvedPlanId: atExpiry.plan.planId,
      approvedPlanHash: atExpiry.plan.planHash,
      attemptId,
      stateHash: await sha256(stateValue),
      verifierHash: await sha256(verifier),
      attemptExpiresAt: planExpiresAt,
      now: NOW + 3,
    }));
    atExpiry.setNow(planExpiresAt);
    const rejected = await atExpiry.object.fetch(internalRequest('/consume', 'POST', {
      attemptId,
      stateHash: await sha256(stateValue),
      verifierHash: await sha256(verifier),
      now: planExpiresAt,
    }));
    expect(rejected.status).toBe(400);
    expect(await body(rejected)).toEqual({ error: { code: 'oauth_state_invalid' } });
  });

  it('rejects a forged CSRF value and an unrecognized completion code', async () => {
    const { object, csrfHash, plan } = await prepared();
    const forged = await object.fetch(internalRequest('/authorize', 'POST', {
      csrfHash: await sha256('x'.repeat(43)),
      releaseManifest: manifest,
      approvedPlanId: plan.planId,
      approvedPlanHash: plan.planHash,
      attemptId,
      stateHash: await sha256(stateValue),
      verifierHash: await sha256(verifier),
      attemptExpiresAt: NOW + 500_000,
      now: NOW + 3,
    }));
    expect(forged.status).toBe(403);

    await object.fetch(internalRequest('/authorize', 'POST', {
      csrfHash,
      releaseManifest: manifest,
      approvedPlanId: plan.planId,
      approvedPlanHash: plan.planHash,
      attemptId,
      stateHash: await sha256(stateValue),
      verifierHash: await sha256(verifier),
      attemptExpiresAt: NOW + 500_000,
      now: NOW + 3,
    }));
    await object.fetch(internalRequest('/consume', 'POST', {
      attemptId,
      stateHash: await sha256(stateValue),
      verifierHash: await sha256(verifier),
      now: NOW + 4,
    }));
    const invalid = await object.fetch(internalRequest('/complete', 'POST', {
      attemptId,
      code: 'surprise_provider_body',
      completedAt: NOW + 5,
      installationId: null,
      grantRevocation: null,
    }));
    expect(invalid.status).toBe(400);
    expect(await body(invalid)).toEqual({ error: { code: 'bad_request' } });

    const missingReceiptIdentity = await object.fetch(internalRequest('/complete', 'POST', {
      attemptId,
      code: 'install_complete',
      completedAt: NOW + 5,
      installationId: null,
      grantRevocation: 'confirmed',
    }));
    expect(missingReceiptIdentity.status).toBe(409);
    expect(await body(missingReceiptIdentity)).toEqual({ error: { code: 'session_conflict' } });
  });

  it('retains only secret-free discovery, binds selection to its opaque target, and returns the target internally', async () => {
    const state = new FakeState();
    let currentTime = NOW;
    const object = new GatewayDeploySession(
      state as unknown as DurableObjectState,
      undefined,
      () => currentTime,
    );
    const csrfHash = await sha256(csrf);
    await object.fetch(internalRequest('/initialize', 'POST', {
      csrfHash,
      createdAt: NOW,
      expiresAt: NOW + 1_800_000,
    }));
    currentTime = NOW + 1;
    expect((await object.fetch(internalRequest('/discover/authorize', 'POST', {
      csrfHash,
      attemptId,
      stateHash: await sha256(stateValue),
      verifierHash: await sha256(verifier),
      attemptExpiresAt: NOW + 500_000,
      now: currentTime,
    }))).status).toBe(200);
    currentTime = NOW + 2;
    expect((await object.fetch(internalRequest('/discover/consume', 'POST', {
      attemptId,
      stateHash: await sha256(stateValue),
      verifierHash: await sha256(verifier),
      now: currentTime,
    }))).status).toBe(200);
    const targetIdHash = `sha256:${'1'.repeat(64)}`;
    currentTime = NOW + 3;
    expect((await object.fetch(internalRequest('/discover/complete', 'POST', {
      attemptId,
      code: 'discovery_complete',
      result: {
        actor: { id: 'user-12345678', email: 'owner@example.com' },
        targets: [{
          targetIdHash,
          account: { id: 'a'.repeat(32), name: 'Primary account' },
          zone: { id: 'b'.repeat(32), name: 'example.com', status: 'active' },
        }],
      },
      grantRevocation: 'confirmed',
      completedAt: currentTime,
    }))).status).toBe(200);
    const publicResponse = await body(await object.fetch(internalRequest('/public', 'GET')));
    expect(publicResponse.discovery).toEqual({
      schemaVersion: 1,
      status: 'ready',
      actorEmail: 'owner@example.com',
      targets: [{ targetIdHash, accountName: 'Primary account', zoneName: 'example.com' }],
      selectedTargetIdHash: null,
      failureCode: null,
      grantRevocation: 'confirmed',
      updatedAt: new Date(currentTime).toISOString(),
    });
    expect(JSON.stringify(publicResponse.discovery)).not.toContain('a'.repeat(32));
    expect(JSON.stringify(publicResponse.discovery)).not.toContain('b'.repeat(32));

    currentTime = NOW + 4;
    expect((await object.fetch(internalRequest('/selection', 'PUT', {
      csrfHash,
      selection: selectionInput,
      targetIdHash,
      now: currentTime,
    }))).status).toBe(200);
    const planResponse = await object.fetch(internalRequest('/plan', 'POST', {
      csrfHash,
      releaseManifest: manifest,
      planExpiresAt: NOW + 600_000,
      now: currentTime,
    }));
    const plan = (await body(planResponse)).session.plan;
    currentTime = NOW + 5;
    await object.fetch(internalRequest('/authorize', 'POST', {
      csrfHash,
      releaseManifest: manifest,
      approvedPlanId: plan.planId,
      approvedPlanHash: plan.planHash,
      attemptId: `att_${'z'.repeat(32)}`,
      stateHash: await sha256('x'.repeat(43)),
      verifierHash: await sha256('y'.repeat(43)),
      attemptExpiresAt: NOW + 500_000,
      now: currentTime,
    }));
    currentTime = NOW + 6;
    const consumed = await body(await object.fetch(internalRequest('/consume', 'POST', {
      attemptId: `att_${'z'.repeat(32)}`,
      stateHash: await sha256('x'.repeat(43)),
      verifierHash: await sha256('y'.repeat(43)),
      now: currentTime,
    })));
    expect(consumed.discoveredTarget).toMatchObject({
      targetIdHash,
      account: { id: 'a'.repeat(32), name: 'Primary account' },
      zone: { id: 'b'.repeat(32), name: 'example.com', status: 'active' },
    });
    const serialized = JSON.stringify([...state.storage.values.values()]);
    expect(serialized).not.toContain(stateValue);
    expect(serialized).not.toContain(verifier);
    expect(serialized).not.toMatch(/access[_-]?token|refresh[_-]?token|client[_-]?secret/iu);
  });
});
