import * as v from 'valibot';

import { boundaryObjectSchema } from './boundary';
import { exactOperationScopes } from './cloudflare-operation-authority';
import {
  buildAuthorizationUrl,
  exchangeAuthorizationCode,
  type CloudflareOauthConfig,
  type EphemeralCloudflareGrant,
  type FetchTransport,
} from './oauth';
import { OAUTH_EXCHANGE_URL } from './constants';
import {
  CustomerCloudflareGrantError,
  resolveSingleAuthorizedCloudflareAccount,
} from './customer-cloudflare-grant';
import { DeployError } from './errors';
import { readBoundedText } from './http';


export function buildHostedBootstrapAuthorizationUrl(input: {
  readonly kind?: 'bootstrap' | 'cleanup';
  readonly clientId: string;
  readonly state: string;
  readonly challenge: string;
}): string {
  return buildAuthorizationUrl({ ...input, scopes: exactOperationScopes(input.kind === 'cleanup' ? 'uninstall-finalize' : 'bootstrap') });
}

export interface HostedBootstrapExecutionResult<Deployment> {
  readonly accountId: string;
  /** Secret-free output of the fixed bootstrap executor. */
  readonly deployment: Deployment;
  readonly grantRevocation: 'confirmed';
}

/**
 * Owns the complete lifetime of the narrow hosted bootstrap grant. The token
 * is available only to the fixed deploy callback and is revoked before a value
 * is returned to the caller.
 */
const stagedProviderErrorSchema = v.object({
  stage: v.pipe(v.string(), v.regex(/^[a-z][a-z0-9_]{0,80}$/u)),
  outcome: v.pipe(v.string(), v.regex(/^[a-z][a-z0-9_]{0,32}$/u)),
});

/**
 * Secret-free diagnostic for a failed shell deployment: the provider stage
 * and outcome when the thrown error carries them, else the stable code.
 * Never provider text, ids, or tokens.
 */
function deployFailureReason<Thrown>(error: Thrown): string {
  const staged = v.safeParse(stagedProviderErrorSchema, error);
  if (staged.success) return `${staged.output.stage}_${staged.output.outcome}`;
  if (error instanceof DeployError) return error.reason ?? error.code;
  return 'bootstrap_deploy_failed';
}

/**
 * The account read runs before any deployment and throws a grant error, not a
 * DeployError. Left untranslated it reached the operator as the unclassified
 * "internal_error"; the ambiguous case is a real, actionable outcome (the
 * grant can see zero or several accounts) and deserves its own code. The
 * grant error's secret-free detail (HTTP status, numeric provider code,
 * account count) rides along in the reason so a refused read names itself.
 */
function accountReadError<Thrown>(error: Thrown): DeployError {
  if (!(error instanceof CustomerCloudflareGrantError)) {
    return new DeployError(502, 'oauth_exchange_failed', 'account_read_failed');
  }
  const reason = error.detail === null
    ? `account_read_${error.code}`
    : `account_read_${error.code}_${error.detail}`;
  if (error.code === 'account_ambiguous') return new DeployError(403, 'target_account_ambiguous', reason);
  return new DeployError(502, 'oauth_exchange_failed', reason);
}

export async function executeHostedBootstrapGrant<Deployment>(input: {
  readonly kind?: 'bootstrap' | 'cleanup';
  readonly code: string;
  readonly verifier: string;
  readonly config: CloudflareOauthConfig;
  readonly transport: FetchTransport;
  readonly deploy: (input: { readonly accessToken: string; readonly accountId: string }) => Promise<Deployment>;
}): Promise<HostedBootstrapExecutionResult<Deployment>> {
  let refreshTokenReturned = false;
  const inspectingTransport: FetchTransport = async (request, init) => {
    const response = await input.transport(request, init);
    const url = request instanceof Request
      ? request.url
      : request instanceof URL ? request.toString() : request;
    if (url === OAUTH_EXCHANGE_URL && response.ok) {
      try {
        const serialized = await readBoundedText(
          response.clone(), 'oauth_exchange_failed', 128 * 1024,
        );
        const parsed = v.safeParse(boundaryObjectSchema, JSON.parse(serialized));
        refreshTokenReturned = parsed.success &&
          v.is(v.pipe(v.string(), v.minLength(1)), parsed.output.refresh_token);
      } catch {
        // The normal exchange parser owns malformed-response classification.
      }
    }
    return response;
  };
  const grant: EphemeralCloudflareGrant = await exchangeAuthorizationCode({
    code: input.code,
    verifier: input.verifier,
    config: input.config,
    transport: inspectingTransport,
  });
  try {
    grant.assertUsable(exactOperationScopes(input.kind === 'cleanup' ? 'uninstall-finalize' : 'bootstrap'));
    if (refreshTokenReturned) throw new DeployError(403, 'oauth_grant_invalid');
    const result = await grant.withAccessToken(async (accessToken) => {
      let accountId: string;
      try {
        accountId = await resolveSingleAuthorizedCloudflareAccount({
          accessToken,
          transport: input.transport,
        });
      } catch (error) {
        throw accountReadError(error);
      }
      try {
        const deployment = await input.deploy({ accessToken, accountId });
        return Object.freeze({ accountId, deployment });
      } catch (error) {
        throw new DeployError(502, 'oauth_exchange_failed', deployFailureReason(error));
      }
    });
    return Object.freeze({ ...result, grantRevocation: 'confirmed' });
  } finally {
    try {
      await grant.revoke(input.transport, input.config);
    } finally {
      grant.discard();
    }
  }
}
