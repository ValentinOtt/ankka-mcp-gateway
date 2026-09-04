import {
  consumeCustomerBootstrapOauthCallback,
  markCustomerBootstrapIncomplete,
  markCustomerBootstrapReady,
  type CustomerBootstrapState,
} from './customer-bootstrap-state';
import {
  CustomerCloudflareGrantError,
  exchangeCustomerCloudflareAuthorizationCode,
  verifyCustomerCloudflareGrantAccount,
  type CustomerCloudflareTransport,
  type EphemeralCustomerCloudflareGrant,
} from './customer-cloudflare-grant';
import { CustomerStage2ConvergerError, type CustomerStage2ConvergerResult } from './customer-stage2-converger';
import { CustomerBootstrapRequestError } from './customer-bootstrap-request';

export interface CustomerBootstrapConvergenceResult {
  readonly verified: true;
  readonly ownershipReceipt: 'complete';
  readonly managementAccess: 'enforced';
  readonly portal: 'converged';
  readonly sourceSet: 'converged';
  /** Final signed runtime remains able to finish or retry while state is not READY. */
  readonly finalRuntime: 'active-recovery-capable';
  readonly workersDev: 'disabled';
}

export type CustomerBootstrapCallbackFailureCode = 'authorization_rejected' | 'grant_invalid' |
  'provider_recovery_required' | 'revocation_unconfirmed';

export interface CustomerBootstrapCallbackResult {
  readonly status: 'READY' | 'INCOMPLETE';
  readonly state: CustomerBootstrapState;
  readonly failureReason?: string | null;
  readonly failureCode: null | CustomerBootstrapCallbackFailureCode;
}

export interface CustomerBootstrapCallbackIncomplete extends CustomerBootstrapCallbackResult {
  readonly status: 'INCOMPLETE';
  readonly failureReason: string | null;
  readonly failureCode: CustomerBootstrapCallbackFailureCode;
}

/** One converger pass: complete, or stopped at a checkpoint to continue in a later invocation. */
export type CustomerBootstrapConverge = (
  accessToken: string,
  attemptId: string,
) => Promise<CustomerStage2ConvergerResult>;

type PersistTransition = (
  expected: CustomerBootstrapState,
  next: CustomerBootstrapState,
) => Promise<void>;

/** Passes one attempt may take before it is treated as making no progress. */
export const CUSTOMER_BOOTSTRAP_CONVERGENCE_MAX_PASSES = 16;

function revocationFailureReason(error: Error): string {
  if (error instanceof CustomerCloudflareGrantError && error.detail !== null) return `revoke_${error.detail}`;
  return 'revoke_unknown';
}

/**
 * Names what stopped the callback without provider text: the converger's own
 * reason (which carries the payload's provider status and code), a grant
 * error's code and detail, or a request stage and outcome.
 */
function callbackFailureReason<Thrown>(error: Thrown): string | null {
  if (error instanceof CustomerStage2ConvergerError) return error.reason ?? `converge_${error.code}`;
  if (error instanceof CustomerCloudflareGrantError) {
    return error.detail === null ? `grant_${error.code}` : `grant_${error.code}_${error.detail}`;
  }
  if (error instanceof CustomerBootstrapRequestError) return `payload_request_${error.stage}_${error.outcome}`;
  return 'unexpected';
}

function callbackFailureCode<Thrown>(error: Thrown): 'grant_invalid' | 'provider_recovery_required' {
  return error instanceof CustomerCloudflareGrantError && [
    'invalid', 'token_exchange_failed', 'scope_mismatch', 'refresh_token_returned',
    'account_mismatch', 'account_ambiguous',
  ].includes(error.code)
    ? 'grant_invalid'
    : 'provider_recovery_required';
}

function convergenceComplete(
  result: CustomerStage2ConvergerResult,
): result is CustomerBootstrapConvergenceResult {
  return result.verified === true && Object.keys(result).length === 7 &&
    result.ownershipReceipt === 'complete' && result.managementAccess === 'enforced' &&
    result.portal === 'converged' && result.sourceSet === 'converged' &&
    result.finalRuntime === 'active-recovery-capable' && result.workersDev === 'disabled';
}

async function settleIncomplete(input: {
  readonly current: CustomerBootstrapState;
  readonly attemptId: string;
  readonly failureCode: CustomerBootstrapCallbackFailureCode;
  readonly failureReason: string | null;
  readonly persist: PersistTransition;
}): Promise<CustomerBootstrapCallbackIncomplete> {
  const incomplete = markCustomerBootstrapIncomplete({
    current: input.current,
    attemptId: input.attemptId,
    failureCode: input.failureCode,
    failureReason: input.failureReason,
  });
  await input.persist(input.current, incomplete);
  return Object.freeze({
    status: 'INCOMPLETE',
    state: incomplete,
    failureCode: input.failureCode,
    failureReason: incomplete.failureReason ?? null,
  });
}

export interface CustomerBootstrapCallbackBeginInput {
  readonly current: CustomerBootstrapState;
  readonly sessionSecret: string;
  readonly attemptId: string;
  readonly verifier: string;
  readonly oauthState: string;
  readonly code: string;
  readonly accountId: string;
  readonly publicClientId: string;
  readonly now: number;
  readonly transport: CustomerCloudflareTransport;
  readonly persist: PersistTransition;
}

export type CustomerBootstrapCallbackBegin =
  | Readonly<{
    status: 'CONVERGING';
    state: CustomerBootstrapState;
    attemptId: string;
    /** Lives only in the caller's memory; it is never written anywhere. */
    grant: EphemeralCustomerCloudflareGrant;
  }>
  | CustomerBootstrapCallbackIncomplete;

/**
 * Arms the durable attempt, exchanges the code directly with Cloudflare, and
 * checks that the grant sees exactly the handoff account. A grant that fails
 * any of that is revoked here; a usable grant is handed to the caller so the
 * provider work can run in as many invocations as the platform budget needs.
 */
export async function beginCustomerBootstrapCallback(
  input: CustomerBootstrapCallbackBeginInput,
): Promise<CustomerBootstrapCallbackBegin> {
  const callback = await consumeCustomerBootstrapOauthCallback({
    current: input.current,
    sessionSecret: input.sessionSecret,
    attemptId: input.attemptId,
    state: input.oauthState,
    now: input.now,
  });
  // Arm the durable state before token exchange or any provider mutation.
  await input.persist(input.current, callback.next);

  let grant: EphemeralCustomerCloudflareGrant | null = null;
  try {
    grant = await exchangeCustomerCloudflareAuthorizationCode({
      clientId: input.publicClientId,
      code: input.code,
      verifier: input.verifier,
      operation: 'install',
      transport: input.transport,
    });
    grant.assertUsable();
    await grant.withAccessToken(async (accessToken) => {
      await verifyCustomerCloudflareGrantAccount({
        accessToken,
        expectedAccountId: input.accountId,
        transport: input.transport,
      });
    });
    return Object.freeze({
      status: 'CONVERGING',
      state: callback.next,
      attemptId: callback.attemptId,
      grant,
    });
  } catch (error) {
    let failureCode: CustomerBootstrapCallbackFailureCode = callbackFailureCode(error);
    let failureReason = callbackFailureReason(error);
    if (grant !== null) {
      try {
        await grant.revoke({ clientId: input.publicClientId, transport: input.transport });
      } catch (revokeError) {
        failureCode = 'revocation_unconfirmed';
        failureReason ??= revocationFailureReason(
          revokeError instanceof Error ? revokeError : new Error('revoke_failed'),
        );
      } finally {
        grant.discard();
      }
    }
    return settleIncomplete({
      current: callback.next,
      attemptId: callback.attemptId,
      failureCode,
      failureReason,
      persist: input.persist,
    });
  }
}

export interface CustomerBootstrapContinueInput {
  readonly current: CustomerBootstrapState;
  readonly attemptId: string;
  readonly grant: EphemeralCustomerCloudflareGrant;
  readonly publicClientId: string;
  readonly now: number;
  readonly transport: CustomerCloudflareTransport;
  readonly persist: PersistTransition;
  readonly converge: CustomerBootstrapConverge;
}

export type CustomerBootstrapContinueResult =
  | Readonly<{
    status: 'CONVERGING';
    state: CustomerBootstrapState;
    failureCode: null;
    failureReason: null;
  }>
  | CustomerBootstrapCallbackResult;

/**
 * Runs one converger pass with the in-memory grant. A pass that stops at a
 * checkpoint leaves the state CONVERGING and the grant usable for the next
 * pass; a pass that completes or fails revokes and discards the grant and
 * settles READY or INCOMPLETE. The token reaches only the fixed converger.
 */
export async function continueCustomerBootstrapConvergence(
  input: CustomerBootstrapContinueInput,
): Promise<CustomerBootstrapContinueResult> {
  let failureCode: CustomerBootstrapCallbackFailureCode | null = null;
  let failureReason: string | null = null;
  let verified = false;
  let paused = false;
  try {
    await input.grant.withAccessToken(async (accessToken) => {
      const result = await input.converge(accessToken, input.attemptId);
      if (result.verified === false) {
        paused = true;
        return;
      }
      if (!convergenceComplete(result)) throw new CustomerCloudflareGrantError('provider_unavailable');
      verified = true;
    });
  } catch (error) {
    failureCode = callbackFailureCode(error);
    failureReason = callbackFailureReason(error);
  }
  if (paused && failureCode === null) {
    return Object.freeze({
      status: 'CONVERGING',
      state: input.current,
      failureCode: null,
      failureReason: null,
    });
  }
  try {
    await input.grant.revoke({ clientId: input.publicClientId, transport: input.transport });
  } catch (error) {
    failureCode = 'revocation_unconfirmed';
    failureReason ??= revocationFailureReason(error instanceof Error ? error : new Error('revoke_failed'));
  } finally {
    input.grant.discard();
  }
  if (verified && failureCode === null) {
    const ready = markCustomerBootstrapReady({
      current: input.current,
      attemptId: input.attemptId,
      now: input.now,
    });
    await input.persist(input.current, ready);
    return Object.freeze({ status: 'READY', state: ready, failureCode: null, failureReason: null });
  }
  return settleIncomplete({
    current: input.current,
    attemptId: input.attemptId,
    failureCode: failureCode ?? 'provider_recovery_required',
    failureReason,
    persist: input.persist,
  });
}

/**
 * Executes Stage 2 inside one invocation: begin, then converger passes until
 * the attempt settles. Only fits where no per-invocation provider budget
 * applies; the customer Worker instead spreads the passes over alarms.
 */
export async function executeCustomerBootstrapCallback(
  input: CustomerBootstrapCallbackBeginInput & { readonly converge: CustomerBootstrapConverge },
): Promise<CustomerBootstrapCallbackResult> {
  const begun = await beginCustomerBootstrapCallback(input);
  if (begun.status !== 'CONVERGING') return begun;
  for (let pass = 1; pass <= CUSTOMER_BOOTSTRAP_CONVERGENCE_MAX_PASSES; pass += 1) {
    const next = await continueCustomerBootstrapConvergence({
      current: begun.state,
      attemptId: begun.attemptId,
      grant: begun.grant,
      publicClientId: input.publicClientId,
      now: input.now,
      transport: input.transport,
      persist: input.persist,
      converge: input.converge,
    });
    if (next.status !== 'CONVERGING') return next;
  }
  const stopped = await continueCustomerBootstrapConvergence({
    current: begun.state,
    attemptId: begun.attemptId,
    grant: begun.grant,
    publicClientId: input.publicClientId,
    now: input.now,
    transport: input.transport,
    persist: input.persist,
    converge: async () => {
      throw new CustomerStage2ConvergerError('provider_mismatch', 'convergence_passes_exhausted');
    },
  });
  if (stopped.status === 'CONVERGING') throw new Error('convergence_passes_exhausted');
  return stopped;
}
