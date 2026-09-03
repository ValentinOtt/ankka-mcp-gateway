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

export interface CustomerBootstrapCallbackResult {
  readonly status: 'READY' | 'INCOMPLETE';
  readonly state: CustomerBootstrapState;
  readonly failureCode: null | 'authorization_rejected' | 'grant_invalid' |
    'provider_recovery_required' | 'revocation_unconfirmed';
}

function convergenceComplete(result: CustomerBootstrapConvergenceResult): boolean {
  return Object.keys(result).length === 7 && result.verified === true &&
    result.ownershipReceipt === 'complete' && result.managementAccess === 'enforced' &&
    result.portal === 'converged' && result.sourceSet === 'converged' &&
    result.finalRuntime === 'active-recovery-capable' && result.workersDev === 'disabled';
}

/**
 * Executes Stage 2 inside one customer-Worker invocation. The only callback
 * that receives the access token is the fixed reviewed converger supplied by
 * the customer Worker; state persistence receives secret-free records only.
 */
export async function executeCustomerBootstrapCallback(input: {
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
  readonly persist: (
    expected: CustomerBootstrapState,
    next: CustomerBootstrapState,
  ) => Promise<void>;
  readonly converge: (
    accessToken: string,
    attemptId: string,
  ) => Promise<CustomerBootstrapConvergenceResult>;
}): Promise<CustomerBootstrapCallbackResult> {
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
  let failureCode: 'grant_invalid' | 'provider_recovery_required' | 'revocation_unconfirmed' | null = null;
  let verified = false;
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
      const result = await input.converge(accessToken, callback.attemptId);
      if (!convergenceComplete(result)) throw new CustomerCloudflareGrantError('provider_unavailable');
      verified = true;
    });
  } catch (error) {
    failureCode = error instanceof CustomerCloudflareGrantError && [
      'invalid', 'token_exchange_failed', 'scope_mismatch', 'refresh_token_returned',
      'account_mismatch', 'account_ambiguous',
    ].includes(error.code)
      ? 'grant_invalid'
      : 'provider_recovery_required';
  } finally {
    if (grant !== null) {
      try {
        await grant.revoke({ clientId: input.publicClientId, transport: input.transport });
      } catch {
        failureCode = 'revocation_unconfirmed';
      } finally {
        grant.discard();
      }
    }
  }

  if (verified && failureCode === null) {
    const ready = markCustomerBootstrapReady({
      current: callback.next,
      attemptId: callback.attemptId,
      now: input.now,
    });
    await input.persist(callback.next, ready);
    return Object.freeze({ status: 'READY', state: ready, failureCode: null });
  }
  const incomplete = markCustomerBootstrapIncomplete({
    current: callback.next,
    attemptId: callback.attemptId,
    failureCode: failureCode ?? 'provider_recovery_required',
  });
  await input.persist(callback.next, incomplete);
  return Object.freeze({ status: 'INCOMPLETE', state: incomplete, failureCode: incomplete.failureCode });
}
