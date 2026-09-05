import { describe, expect, it } from 'vitest';

import {
  GATEWAY_ROOT_REMOVAL_STEPS,
  armGatewayRootRemoval,
  authorizeGatewayTeardownJob,
  consumeGatewayTeardownCallback,
  parseGatewayTeardownJob,
  settleGatewayTeardownAttempt,
  verifyGatewayRootRemoval,
  type GatewayTeardownJob,
} from '../src/gateway-teardown-job';

const NOW = 1_800_000_000_000;
const TTL = 600_000;
const attemptId = `attempt_${'a'.repeat(24)}`;
const nextAttemptId = `attempt_${'b'.repeat(24)}`;
const hashes = { stateHash: 's'.repeat(43), verifierHash: 'v'.repeat(43) };

// Transition fixtures are already-stored records. Signed import and resumed
// authority verification use a real installation in customer-stage2-converger.
function stored(): GatewayTeardownJob {
  return parseGatewayTeardownJob({
    schemaVersion: 1, revision: 1, handoff: 'signed-handoff-fixture',
    handoffSha256: `sha256:${'1'.repeat(64)}`,
    acceptedAt: NOW, updatedAt: NOW, phase: 'review', attempt: null,
    verifiedSteps: [], pendingStep: null, pendingAttemptId: null, revocation: 'not_attempted',
  });
}

function exchanged(job = stored(), id = attemptId, now = NOW): GatewayTeardownJob {
  const authorized = authorizeGatewayTeardownJob({ job, attemptId: id, ...hashes, now });
  return consumeGatewayTeardownCallback({ job: authorized, attemptId: id, ...hashes, now });
}

describe('hosted gateway teardown recovery journal', () => {
  it('consumes each callback once and refuses a different state, verifier, or attempt', () => {
    const job = authorizeGatewayTeardownJob({ job: stored(), attemptId, ...hashes, now: NOW });
    for (const changed of [{ stateHash: 'x'.repeat(43) }, { verifierHash: 'x'.repeat(43) }, { attemptId: nextAttemptId }]) {
      expect(() => consumeGatewayTeardownCallback({ job, attemptId, ...hashes, ...changed, now: NOW })).toThrow();
    }
    expect(() => consumeGatewayTeardownCallback({ job, attemptId, ...hashes, now: NOW + TTL })).toThrow();
    const consumed = consumeGatewayTeardownCallback({ job, attemptId, ...hashes, now: NOW });
    expect(() => consumeGatewayTeardownCallback({ job: consumed, attemptId, ...hashes, now: NOW })).toThrow();
    expect(() => authorizeGatewayTeardownJob({ job: consumed, attemptId: nextAttemptId, ...hashes, now: NOW })).toThrow();
    expect(consumed.revision).toBe(3);
    expect(Object.isFrozen(consumed.attempt)).toBe(true);
  });

  it.each(GATEWAY_ROOT_REMOVAL_STEPS)('resumes an uncertain %s without deleting earlier resources again', (failedStep) => {
    let job = exchanged();
    for (const step of GATEWAY_ROOT_REMOVAL_STEPS) {
      job = armGatewayRootRemoval({ job, attemptId, step, now: NOW });
      if (step === failedStep) break;
      job = verifyGatewayRootRemoval({ job, attemptId, step, now: NOW });
    }
    expect(() => armGatewayRootRemoval({ job, attemptId, step: failedStep, now: NOW })).toThrow();
    const progress = [...job.verifiedSteps];
    job = settleGatewayTeardownAttempt({ job, attemptId, revocation: 'confirmed', now: NOW + 1 });
    expect(job.phase).toBe('recovery_required');
    expect(job.pendingStep).toBe(failedStep);
    expect(() => authorizeGatewayTeardownJob({ job, attemptId, ...hashes, now: NOW + 2 })).toThrow();
    job = exchanged(job, nextAttemptId, NOW + 2);
    // Exact absence read-back resolves an earlier ambiguous send without
    // another mutation, even though the provider grant is now different.
    job = verifyGatewayRootRemoval({ job, attemptId: nextAttemptId, step: failedStep, now: NOW + 2 });
    expect(job.verifiedSteps).toEqual([...progress, failedStep]);
    for (const step of GATEWAY_ROOT_REMOVAL_STEPS.slice(job.verifiedSteps.length)) {
      job = armGatewayRootRemoval({ job, attemptId: nextAttemptId, step, now: NOW + 2 });
      job = verifyGatewayRootRemoval({ job, attemptId: nextAttemptId, step, now: NOW + 2 });
    }
    job = settleGatewayTeardownAttempt({ job, attemptId: nextAttemptId, revocation: 'confirmed', now: NOW + 3 });
    expect(job.phase).toBe('removed');
    expect(job.verifiedSteps).toEqual(GATEWAY_ROOT_REMOVAL_STEPS);
    expect(job.attempt).toBeNull();
    expect(() => authorizeGatewayTeardownJob({ job, attemptId, ...hashes, now: NOW + 4 })).toThrow();
  });

  it('requires a fresh attempt before re-arming a still-present resource', () => {
    let job = armGatewayRootRemoval({ job: exchanged(), attemptId, step: 'retire_namespace', now: NOW });
    job = settleGatewayTeardownAttempt({ job, attemptId, revocation: 'confirmed', now: NOW + 1 });
    job = exchanged(job, nextAttemptId, NOW + 2);
    job = armGatewayRootRemoval({ job, attemptId: nextAttemptId, step: 'retire_namespace', now: NOW + 2 });
    expect(job.pendingAttemptId).toBe(nextAttemptId);
    expect(() => armGatewayRootRemoval({ job, attemptId: nextAttemptId, step: 'retire_namespace', now: NOW + 2 })).toThrow();
  });

  it.each(['expired exchange', 'unconfirmed revocation'])('preserves %s as an explicit outcome after a later successful consent', (failure) => {
    let job = exchanged();
    if (failure === 'unconfirmed revocation') {
      job = settleGatewayTeardownAttempt({ job, attemptId, revocation: 'unconfirmed', now: NOW + 1 });
    }
    job = exchanged(job, nextAttemptId, NOW + TTL);
    for (const step of GATEWAY_ROOT_REMOVAL_STEPS) {
      job = armGatewayRootRemoval({ job, attemptId: nextAttemptId, step, now: NOW + TTL });
      job = verifyGatewayRootRemoval({ job, attemptId: nextAttemptId, step, now: NOW + TTL });
    }
    job = settleGatewayTeardownAttempt({ job, attemptId: nextAttemptId, revocation: 'confirmed', now: NOW + TTL });
    expect(job.phase).toBe('removed_revocation_unconfirmed');
    expect(job.revocation).toBe('unconfirmed');
  });

  it('replaces an expired unused consent without claiming an unrevoked grant exists', () => {
    const job = authorizeGatewayTeardownJob({ job: stored(), attemptId, ...hashes, now: NOW });
    const next = exchanged(job, nextAttemptId, NOW + TTL);
    expect(next.revocation).toBe('not_attempted');
    expect(() => armGatewayRootRemoval({ job: next, attemptId: nextAttemptId, step: 'worker', now: NOW + TTL })).toThrow();
    expect(() => armGatewayRootRemoval({ job: next, attemptId: nextAttemptId, step: 'retire_namespace', now: NOW + TTL * 2 })).toThrow();
  });

  it('rejects corrupted progress, forged terminal states, raw secrets, and time reversal', () => {
    for (const changed of [
      { verifiedSteps: ['worker'] }, { verifiedSteps: ['retire_namespace', 'retire_namespace'] },
      { pendingStep: 'retire_namespace' }, { phase: 'removed', revocation: 'confirmed' },
      { accessToken: 'must-not-persist' }, { verifier: 'must-not-persist' }, { updatedAt: NOW - 1 },
    ]) expect(() => parseGatewayTeardownJob({ ...stored(), ...changed })).toThrow();
    expect(() => authorizeGatewayTeardownJob({ job: stored(), attemptId, ...hashes, now: NOW - 1 })).toThrow();
  });
});
