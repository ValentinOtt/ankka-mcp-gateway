import {
  CUSTOMER_BOOTSTRAP_OAUTH_TTL_MS,
  CUSTOMER_BOOTSTRAP_TTL_MS,
  createCustomerBootstrapRecoverySession,
  createCustomerBootstrapCapability,
  consumeCustomerBootstrapCapability,
  consumeCustomerBootstrapOauthCallback,
  initialCustomerBootstrapState,
  markCustomerBootstrapIncomplete,
  markCustomerBootstrapReady,
  publicCustomerBootstrapStatus,
  rejectCustomerBootstrapOauthStart,
  startCustomerBootstrapOauth,
  CustomerBootstrapStateError,
} from '../src/customer-bootstrap-state';

const INSTALL_ID = `acg-${'a'.repeat(24)}`;
const NOW = 1_800_000_000_000;

function deterministicRandom(): (length: number) => Uint8Array {
  let call = 0;
  return (length) => {
    call += 1;
    return new Uint8Array(length).fill(call);
  };
}

async function initialized() {
  const randomBytes = deterministicRandom();
  const capability = await createCustomerBootstrapCapability({ now: NOW, randomBytes });
  const initial = initialCustomerBootstrapState({
    installId: INSTALL_ID,
    bootstrapId: capability.bootstrapId,
    secretCommitment: capability.secretCommitment,
    expiresAt: capability.expiresAt,
  });
  return { capability, initial, randomBytes };
}

describe('customer bootstrap state', () => {
  it('stores a commitment, consumes the capability once, and never persists either raw secret', async () => {
    const { capability, initial, randomBytes } = await initialized();
    expect(JSON.stringify(initial)).not.toContain(capability.secret);
    const consumed = await consumeCustomerBootstrapCapability({
      current: initial,
      bootstrapId: capability.bootstrapId,
      secret: capability.secret,
      now: NOW + 1,
      randomBytes,
    });
    const persisted = JSON.stringify(consumed.state);
    expect(persisted).not.toContain(capability.secret);
    expect(persisted).not.toContain(consumed.sessionSecret);
    expect(consumed.state).toMatchObject({ status: 'INCOMPLETE', capabilityUnused: false });
    await expect(consumeCustomerBootstrapCapability({
      current: consumed.state,
      bootstrapId: capability.bootstrapId,
      secret: capability.secret,
      now: NOW + 2,
    })).rejects.toMatchObject({ code: 'consumed' });
  });

  it('generates PKCE without serializing its verifier, binds callback state, and reaches READY once', async () => {
    const { capability, initial, randomBytes } = await initialized();
    const session = await consumeCustomerBootstrapCapability({
      current: initial, bootstrapId: capability.bootstrapId, secret: capability.secret,
      now: NOW + 1, randomBytes,
    });
    const oauth = await startCustomerBootstrapOauth({
      current: session.state, sessionSecret: session.sessionSecret, now: NOW + 2, randomBytes,
    });
    expect(oauth.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(oauth.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(oauth.next.oauth).toMatchObject({ phase: 'authorizing' });
    expect(JSON.stringify(oauth.next)).not.toContain('"verifier"');
    expect(JSON.stringify(oauth.next)).not.toContain(oauth.verifier);
    await expect(consumeCustomerBootstrapOauthCallback({
      current: oauth.next,
      sessionSecret: session.sessionSecret,
      attemptId: oauth.attemptId,
      state: 'A'.repeat(43),
      now: NOW + 3,
    })).rejects.toBeInstanceOf(CustomerBootstrapStateError);
    const callback = await consumeCustomerBootstrapOauthCallback({
      current: oauth.next,
      sessionSecret: session.sessionSecret,
      attemptId: oauth.attemptId,
      state: oauth.state,
      now: NOW + 3,
    });
    expect(callback.next.status).toBe('CONVERGING');
    const ready = markCustomerBootstrapReady({
      current: callback.next, attemptId: callback.attemptId, now: NOW + 4,
    });
    expect(ready).toMatchObject({ status: 'READY', session: null, oauth: null, failureCode: null });
    expect(publicCustomerBootstrapStatus(ready)).toEqual({
      schemaVersion: 1, status: 'READY', canRetry: false,
    });
    await expect(startCustomerBootstrapOauth({
      current: ready, sessionSecret: session.sessionSecret, now: NOW + 5,
    })).rejects.toMatchObject({ code: 'final' });
  });

  it('returns partial failure to safe INCOMPLETE and starts a fresh authorization', async () => {
    const { capability, initial, randomBytes } = await initialized();
    const session = await consumeCustomerBootstrapCapability({
      current: initial, bootstrapId: capability.bootstrapId, secret: capability.secret,
      now: NOW + 1, randomBytes,
    });
    const first = await startCustomerBootstrapOauth({
      current: session.state, sessionSecret: session.sessionSecret, now: NOW + 2, randomBytes,
    });
    const callback = await consumeCustomerBootstrapOauthCallback({
      current: first.next, sessionSecret: session.sessionSecret, attemptId: first.attemptId,
      state: first.state, now: NOW + 3,
    });
    const incomplete = markCustomerBootstrapIncomplete({
      current: callback.next,
      attemptId: callback.attemptId,
      failureCode: 'provider_recovery_required',
    });
    expect(publicCustomerBootstrapStatus(incomplete)).toEqual({
      schemaVersion: 1, status: 'INCOMPLETE', canRetry: true,
    });
    const retry = await startCustomerBootstrapOauth({
      current: incomplete, sessionSecret: session.sessionSecret, now: NOW + 4, randomBytes,
    });
    expect(retry.attemptId).not.toBe(first.attemptId);
    expect(retry.state).not.toBe(first.state);
  });

  it('makes a failed relay start immediately retryable without reusing its PKCE attempt', async () => {
    const { capability, initial, randomBytes } = await initialized();
    const session = await consumeCustomerBootstrapCapability({
      current: initial, bootstrapId: capability.bootstrapId, secret: capability.secret,
      now: NOW + 1, randomBytes,
    });
    const first = await startCustomerBootstrapOauth({
      current: session.state, sessionSecret: session.sessionSecret, now: NOW + 2, randomBytes,
    });
    const rejected = rejectCustomerBootstrapOauthStart({
      current: first.next,
      attemptId: first.attemptId,
    });
    expect(rejected).toMatchObject({
      status: 'INCOMPLETE', oauth: null, failureCode: 'authorization_rejected',
    });
    const retry = await startCustomerBootstrapOauth({
      current: rejected, sessionSecret: session.sessionSecret, now: NOW + 3, randomBytes,
    });
    expect(retry.attemptId).not.toBe(first.attemptId);
  });

  it('recovers an expired CONVERGING lease only through fresh OAuth', async () => {
    const { capability, initial, randomBytes } = await initialized();
    const session = await consumeCustomerBootstrapCapability({
      current: initial, bootstrapId: capability.bootstrapId, secret: capability.secret,
      now: NOW + 1, randomBytes,
    });
    const first = await startCustomerBootstrapOauth({
      current: session.state, sessionSecret: session.sessionSecret, now: NOW + 2, randomBytes,
    });
    const callback = await consumeCustomerBootstrapOauthCallback({
      current: first.next, sessionSecret: session.sessionSecret, attemptId: first.attemptId,
      state: first.state, now: NOW + 3,
    });
    const retry = await startCustomerBootstrapOauth({
      current: callback.next,
      sessionSecret: session.sessionSecret,
      now: NOW + 2 + CUSTOMER_BOOTSTRAP_OAUTH_TTL_MS + 1,
      randomBytes,
    });
    expect(retry.next.status).toBe('INCOMPLETE');
    expect(retry.next.failureCode).toBeNull();
    expect(retry.attemptId).not.toBe(callback.attemptId);
  });

  it('rotates an expired install session without reviving the one-use capability', async () => {
    const { capability, initial, randomBytes } = await initialized();
    const session = await consumeCustomerBootstrapCapability({
      current: initial,
      bootstrapId: capability.bootstrapId,
      secret: capability.secret,
      now: NOW + 1,
      randomBytes,
    });
    const first = await startCustomerBootstrapOauth({
      current: session.state,
      sessionSecret: session.sessionSecret,
      now: NOW + 2,
      randomBytes,
    });
    await expect(createCustomerBootstrapRecoverySession({
      current: first.next,
      now: NOW + 3,
      randomBytes,
    })).rejects.toMatchObject({ code: 'conflict' });

    const recoveryAt = NOW + 2 + CUSTOMER_BOOTSTRAP_OAUTH_TTL_MS + 1;
    const recovered = await createCustomerBootstrapRecoverySession({
      current: first.next,
      now: recoveryAt,
      randomBytes,
    });
    expect(recovered.expiresAt).toBe(recoveryAt + CUSTOMER_BOOTSTRAP_TTL_MS);
    expect(recovered.state).toMatchObject({
      status: 'INCOMPLETE',
      capabilityUnused: false,
      oauth: null,
      failureCode: 'provider_recovery_required',
    });
    expect(recovered.sessionSecret).not.toBe(session.sessionSecret);
    expect(JSON.stringify(recovered.state)).not.toContain(recovered.sessionSecret);
    await expect(consumeCustomerBootstrapCapability({
      current: recovered.state,
      bootstrapId: capability.bootstrapId,
      secret: capability.secret,
      now: recoveryAt + 1,
    })).rejects.toMatchObject({ code: 'consumed' });
  });
});
