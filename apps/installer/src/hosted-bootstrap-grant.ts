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
import { OAUTH_TOKEN_URL } from './constants';
import { resolveSingleAuthorizedCloudflareAccount } from './customer-cloudflare-grant';
import { DeployError } from './errors';
import { readBoundedText } from './http';

const BOOTSTRAP_SCOPES = exactOperationScopes('bootstrap');

export function buildHostedBootstrapAuthorizationUrl(input: {
  readonly clientId: string;
  readonly state: string;
  readonly challenge: string;
}): string {
  return buildAuthorizationUrl({ ...input, scopes: BOOTSTRAP_SCOPES });
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
export async function executeHostedBootstrapGrant<Deployment>(input: {
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
    if (url === OAUTH_TOKEN_URL && response.ok) {
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
    grant.assertUsable(BOOTSTRAP_SCOPES);
    if (refreshTokenReturned) throw new DeployError(403, 'oauth_grant_invalid');
    const result = await grant.withAccessToken(async (accessToken) => {
      const accountId = await resolveSingleAuthorizedCloudflareAccount({
        accessToken,
        transport: input.transport,
      });
      try {
        const deployment = await input.deploy({ accessToken, accountId });
        return Object.freeze({ accountId, deployment });
      } catch {
        throw new DeployError(502, 'oauth_exchange_failed', 'bootstrap_deploy_failed');
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
