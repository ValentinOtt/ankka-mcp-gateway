import * as v from 'valibot';
import { boundaryObjectSchema } from './boundary';
import { OAUTH_EXCHANGE_URL } from './constants';
import { readBoundedText } from './http';

import { exactOperationScopes } from './cloudflare-operation-authority';
import { resolveSingleAuthorizedCloudflareAccount } from './customer-cloudflare-grant';
import type { GatewayTeardownJobPort } from './gateway-teardown-durable-state';
import type { GatewayTeardownTrust } from './gateway-teardown-handoff';
import { settleGatewayTeardownAttempt } from './gateway-teardown-job';
import { executeGatewayRootRemoval, GatewayTeardownProviderError } from './gateway-teardown-provider';
import { exchangeAuthorizationCode, type EphemeralCloudflareGrant, type CloudflareOauthConfig, type FetchTransport } from './oauth';
import type { VerifiedReleaseBundle } from './release';

/** A distinct fixed hosted operation; neither bootstrap cleanup nor its scopes change. */
export async function executeGatewayTeardownGrant(input: {
  readonly code: string; readonly verifier: string; readonly config: CloudflareOauthConfig;
  readonly transport: FetchTransport; readonly port: GatewayTeardownJobPort;
  readonly attemptId: string; readonly trust: GatewayTeardownTrust; readonly bundle: VerifiedReleaseBundle;
  readonly now: () => number; readonly wait?: (milliseconds: number) => Promise<void>;
}) {
  const current = await input.port.read();
  if (current?.phase !== 'exchanging' || current.attempt?.id !== input.attemptId || current.attempt.expiresAt <= input.now()) {
    throw new Error('teardown_callback_invalid');
  }
  let grant: EphemeralCloudflareGrant | null = null;
  let revocation: 'confirmed' | 'unconfirmed' = 'unconfirmed';
  let reason: string | null = null;
  let refreshTokenReturned = false;
  const inspectingTransport: FetchTransport = async (request, init) => {
    const response = await input.transport(request, init);
    const url = request instanceof Request ? request.url : request.toString();
    if (url === OAUTH_EXCHANGE_URL && response.ok) {
      try {
        const body = v.parse(boundaryObjectSchema, JSON.parse(await readBoundedText(response.clone(), 'oauth_exchange_failed', 128 * 1024)));
        refreshTokenReturned = v.is(v.pipe(v.string(), v.minLength(1)), body.refresh_token);
      } catch { /* The exchange parser owns malformed-response handling. */ }
    }
    return response;
  };
  try {
    grant = await exchangeAuthorizationCode({ ...input, transport: inspectingTransport });
    grant.assertUsable(exactOperationScopes('gateway-root-finalize'));
    if (refreshTokenReturned) throw new Error('teardown_grant_invalid');
    await grant.withAccessToken(async (accessToken) => {
      const accountId = await resolveSingleAuthorizedCloudflareAccount({ accessToken, transport: input.transport });
      await executeGatewayRootRemoval({ ...input, accessToken, authorizedAccountId: accountId });
    });
  } catch (error) {
    reason = error instanceof GatewayTeardownProviderError ? `${error.stage}_${error.code}` : 'finalization_failed';
  } finally {
    if (grant !== null) {
      try { await grant.revoke(input.transport, input.config); revocation = 'confirmed'; }
      catch { reason ??= 'revocation_unconfirmed'; }
      finally { grant.discard(); }
    }
  }
  const latest = await input.port.read();
  if (latest === null) throw new Error('teardown_job_missing');
  const job = settleGatewayTeardownAttempt({ job: latest, attemptId: input.attemptId, revocation, reason, now: input.now() });
  if (!await input.port.compareAndSet(latest.revision, job)) throw new Error('teardown_job_conflict');
  return { job, reason };
}
