import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { exactOperationScopes } from '../src/cloudflare-operation-authority';
import {
  CustomerBootstrapConvergenceDriver,
  CUSTOMER_BOOTSTRAP_CONVERGENCE_DEADLINE_MS,
  CUSTOMER_BOOTSTRAP_HANDOVER_ALARM_DELAY_MS,
} from '../src/customer-bootstrap-convergence-driver';
import { finalizeCustomerBootstrapHandover } from '../src/customer-bootstrap-handover';
import type { CustomerBootstrapStatePort } from '../src/customer-bootstrap-router';
import {
  consumeCustomerBootstrapCapability,
  consumeCustomerBootstrapOauthCallback,
  createCustomerBootstrapCapability,
  initialCustomerBootstrapState,
  startCustomerBootstrapOauth,
  type CustomerBootstrapState,
} from '../src/customer-bootstrap-state';
import {
  EphemeralCustomerCloudflareGrant,
  type CustomerCloudflareTransport,
} from '../src/customer-cloudflare-grant';
import { CustomerStage2ConvergerError, type CustomerStage2ConvergerResult } from
  '../src/customer-stage2-converger';

const NOW = 1_900_000_000_000;
const INSTALL_ID = `acg-${'b'.repeat(24)}`;
const CLIENT_ID = 'c'.repeat(32);
const ACCESS_TOKEN = `token_${'d'.repeat(32)}`;
const COMPLETE: CustomerStage2ConvergerResult = Object.freeze({
  verified: true,
  ownershipReceipt: 'complete',
  managementAccess: 'enforced',
  portal: 'converged',
  sourceSet: 'converged',
  finalRuntime: 'active-recovery-capable',
  workersDev: 'disabled',
});
const PAUSED: CustomerStage2ConvergerResult = {
  verified: false,
  paused: true,
  checkpoint: { action: 'gateway_resources', phase: 'submitted' },
};
const HANDED_OVER: CustomerStage2ConvergerResult = { verified: false, handedOver: true };

function deterministicRandom(): (length: number) => Uint8Array {
  let call = 0;
  return (length) => new Uint8Array(length).fill(++call);
}

function grant(): EphemeralCustomerCloudflareGrant {
  const scopes = exactOperationScopes('install');
  const value = new EphemeralCustomerCloudflareGrant(ACCESS_TOKEN, undefined, scopes, true, scopes);
  value.assertUsable();
  return value;
}

/** A CONVERGING state with its armed attempt, the way the callback leaves it. */
async function convergingState(): Promise<{ state: CustomerBootstrapState; attemptId: string }> {
  const randomBytes = deterministicRandom();
  const capability = await createCustomerBootstrapCapability({ now: NOW, randomBytes });
  const initial = initialCustomerBootstrapState({
    installId: INSTALL_ID,
    bootstrapId: capability.bootstrapId,
    secretCommitment: capability.secretCommitment,
    expiresAt: capability.expiresAt,
  });
  const session = await consumeCustomerBootstrapCapability({
    current: initial,
    bootstrapId: capability.bootstrapId,
    secret: capability.secret,
    now: NOW + 1,
    randomBytes,
  });
  const oauth = await startCustomerBootstrapOauth({
    current: session.state,
    sessionSecret: session.sessionSecret,
    now: NOW + 2,
    randomBytes,
  });
  const callback = await consumeCustomerBootstrapOauthCallback({
    current: oauth.next,
    sessionSecret: session.sessionSecret,
    attemptId: oauth.attemptId,
    state: oauth.state,
    now: NOW + 3,
  });
  return { state: callback.next, attemptId: callback.attemptId };
}

class MemoryState implements CustomerBootstrapStatePort {
  constructor(public stored: CustomerBootstrapState | undefined) {}

  async read(): Promise<CustomerBootstrapState | undefined> {
    return this.stored;
  }

  async compareAndSet(expectedRevision: number | null, state: CustomerBootstrapState): Promise<boolean> {
    if ((this.stored?.revision ?? null) !== expectedRevision) return false;
    this.stored = state;
    return true;
  }
}

function transportCounting(revocations: { count: number }): CustomerCloudflareTransport {
  return async (input) => {
    if (String(input).endsWith('/oauth2/revoke')) {
      revocations.count += 1;
      return Response.json({ revoked: true });
    }
    throw new Error('unexpected request');
  };
}

describe('customer bootstrap convergence driver', () => {
  beforeEach(() => { vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] }); });
  afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });

  it('runs one converger pass per scheduled invocation and settles READY after the last', async () => {
    const converging = await convergingState();
    const state = new MemoryState(converging.state);
    const revocations = { count: 0 };
    const passes: string[] = [];
    let scheduled = 0;
    const results = [PAUSED, PAUSED, COMPLETE];
    const driver = new CustomerBootstrapConvergenceDriver({
      state,
      transport: transportCounting(revocations),
      publicClientId: CLIENT_ID,
      converge: async (accessToken, attemptId) => {
        passes.push(`${accessToken === ACCESS_TOKEN ? 'token' : 'other'}:${attemptId}`);
        const next = results.shift();
        if (next === undefined) throw new Error('unexpected pass');
        return next;
      },
      now: () => NOW + 10,
      schedule: async () => { scheduled += 1; },
    });
    await driver.start({ attemptId: converging.attemptId, grant: grant() });
    expect(vi.getTimerCount()).toBe(1);
    expect(scheduled).toBe(1);
    expect(await driver.continue()).toBe('scheduled');
    // A delayed alarm must not leave the object eligible for idle hibernation
    // after ten seconds when no browser is polling the progress page.
    await vi.advanceTimersByTimeAsync(15_000);
    expect(vi.getTimerCount()).toBe(1);
    expect(await driver.continue()).toBe('scheduled');
    expect(state.stored?.status).toBe('CONVERGING');
    expect(revocations.count).toBe(0);
    expect(await driver.continue()).toBe('settled');
    expect(scheduled).toBe(3);
    expect(passes).toEqual(Array(3).fill(`token:${converging.attemptId}`));
    expect(state.stored).toMatchObject({ status: 'READY', oauth: null, session: null });
    expect(revocations.count).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
    // Nothing is left to run once the attempt has settled.
    expect(await driver.continue()).toBe('idle');
    expect(scheduled).toBe(3);
  });

  it('settles INCOMPLETE with grant_lost when a pass runs without the grant in memory', async () => {
    const converging = await convergingState();
    const state = new MemoryState(converging.state);
    let converged = false;
    const driver = new CustomerBootstrapConvergenceDriver({
      state,
      transport: async () => { throw new Error('no provider call expected'); },
      publicClientId: CLIENT_ID,
      converge: async () => { converged = true; return COMPLETE; },
      now: () => NOW + 10,
      schedule: async () => undefined,
    });
    expect(await driver.continue()).toBe('settled');
    expect(converged).toBe(false);
    expect(state.stored).toMatchObject({
      status: 'INCOMPLETE',
      oauth: null,
      failureCode: 'revocation_unconfirmed',
      failureReason: 'grant_lost',
    });
  });

  it('revokes and names the deadline instead of running an attempt that is too old', async () => {
    const converging = await convergingState();
    const state = new MemoryState(converging.state);
    const revocations = { count: 0 };
    let clock = NOW + 10;
    let converged = false;
    const driver = new CustomerBootstrapConvergenceDriver({
      state,
      transport: transportCounting(revocations),
      publicClientId: CLIENT_ID,
      converge: async () => { converged = true; return PAUSED; },
      now: () => clock,
      schedule: async () => undefined,
    });
    await driver.start({ attemptId: converging.attemptId, grant: grant() });
    clock += CUSTOMER_BOOTSTRAP_CONVERGENCE_DEADLINE_MS + 1;
    await vi.advanceTimersByTimeAsync(CUSTOMER_BOOTSTRAP_CONVERGENCE_DEADLINE_MS + 1);
    expect(vi.getTimerCount()).toBe(0);
    expect(await driver.continue()).toBe('settled');
    expect(converged).toBe(false);
    expect(revocations.count).toBe(1);
    expect(state.stored).toMatchObject({
      status: 'INCOMPLETE',
      failureCode: 'provider_recovery_required',
      failureReason: 'convergence_deadline',
    });
  });

  it('carries a converger failure through revocation into the status read', async () => {
    const converging = await convergingState();
    const state = new MemoryState(converging.state);
    const revocations = { count: 0 };
    const driver = new CustomerBootstrapConvergenceDriver({
      state,
      transport: transportCounting(revocations),
      publicClientId: CLIENT_ID,
      converge: async () => {
        throw new CustomerStage2ConvergerError('payload_recovery_required', 'verify_dns_record_absent');
      },
      now: () => NOW + 10,
      schedule: async () => undefined,
    });
    await driver.start({ attemptId: converging.attemptId, grant: grant() });
    expect(await driver.continue()).toBe('settled');
    expect(revocations.count).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
    expect(state.stored).toMatchObject({
      status: 'INCOMPLETE',
      failureCode: 'provider_recovery_required',
      failureReason: 'verify_dns_record_absent',
    });
  });

  it('hands over to the final runtime: finalizing state, delayed alarm, revoked grant, then READY', async () => {
    const converging = await convergingState();
    const state = new MemoryState(converging.state);
    const revocations = { count: 0 };
    const scheduled: number[] = [];
    const phasesSeen: string[] = [];
    const driver = new CustomerBootstrapConvergenceDriver({
      state,
      transport: transportCounting(revocations),
      publicClientId: CLIENT_ID,
      converge: async (_accessToken, _attemptId, handover) => {
        if (handover === undefined) throw new Error('handover hook missing');
        phasesSeen.push(state.stored?.oauth?.phase ?? 'none');
        await handover();
        phasesSeen.push(state.stored?.oauth?.phase ?? 'none');
        return HANDED_OVER;
      },
      now: () => NOW + 10,
      schedule: async (delayMs) => { scheduled.push(delayMs); },
    });
    await driver.start({ attemptId: converging.attemptId, grant: grant() });
    expect(await driver.continue()).toBe('settled');
    expect(phasesSeen).toEqual(['exchanging', 'finalizing']);
    expect(scheduled).toEqual([0, CUSTOMER_BOOTSTRAP_HANDOVER_ALARM_DELAY_MS]);
    expect(revocations.count).toBe(1);
    expect(vi.getTimerCount()).toBe(0);
    expect(state.stored).toMatchObject({ status: 'CONVERGING', oauth: { phase: 'finalizing' } });
    // Until the object restarts on the final runtime, this code only looks again later.
    expect(await driver.continue()).toBe('scheduled');
    expect(scheduled).toEqual([0, CUSTOMER_BOOTSTRAP_HANDOVER_ALARM_DELAY_MS, CUSTOMER_BOOTSTRAP_HANDOVER_ALARM_DELAY_MS]);
    expect(state.stored?.status).toBe('CONVERGING');
    // The final runtime's alarm closes the install; a second look changes nothing.
    expect(await finalizeCustomerBootstrapHandover(state, NOW + 20)).toBe('ready');
    expect(state.stored).toMatchObject({ status: 'READY', oauth: null, session: null, readyAt: NOW + 20 });
    expect(await finalizeCustomerBootstrapHandover(state, NOW + 21)).toBe('idle');
    expect(await driver.continue()).toBe('idle');
  });

  it('settles a failed upload after arming the handover as INCOMPLETE with its reason', async () => {
    const converging = await convergingState();
    const state = new MemoryState(converging.state);
    const revocations = { count: 0 };
    const driver = new CustomerBootstrapConvergenceDriver({
      state,
      transport: transportCounting(revocations),
      publicClientId: CLIENT_ID,
      converge: async (_accessToken, _attemptId, handover) => {
        if (handover === undefined) throw new Error('handover hook missing');
        await handover();
        throw new CustomerStage2ConvergerError('provider_mismatch', 'script_upload_rejected');
      },
      now: () => NOW + 10,
      schedule: async () => undefined,
    });
    await driver.start({ attemptId: converging.attemptId, grant: grant() });
    expect(await driver.continue()).toBe('settled');
    expect(revocations.count).toBe(1);
    expect(state.stored).toMatchObject({
      status: 'INCOMPLETE',
      oauth: null,
      failureCode: 'provider_recovery_required',
      failureReason: 'script_upload_rejected',
    });
    expect(await finalizeCustomerBootstrapHandover(state, NOW + 20)).toBe('idle');
  });

  it('stays idle when the durable state is not converging', async () => {
    const state = new MemoryState(undefined);
    const driver = new CustomerBootstrapConvergenceDriver({
      state,
      transport: async () => { throw new Error('no provider call expected'); },
      publicClientId: CLIENT_ID,
      converge: async () => COMPLETE,
      now: () => NOW,
      schedule: async () => undefined,
    });
    expect(await driver.continue()).toBe('idle');
  });
});
