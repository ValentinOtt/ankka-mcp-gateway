import * as v from 'valibot';

import type { GatewayConfig } from './config.ts';
import { boundaryObjectSchema, type BoundaryValue } from './json.ts';

const SERVICE_TOKEN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CANARY_HOST_LABEL = /^ankka-canary(?:-[a-z0-9-]+)?$/;

/** Only the private operator input can carry this identifier, never config or receipts. */
export function canaryServiceTokenId(access: BoundaryValue): string | null {
  if (!v.is(boundaryObjectSchema, access)
    || !Object.hasOwn(access, 'canaryServiceTokenId')) return null;
  if (Object.keys(access).length !== 1
    || !v.is(v.string(), access.canaryServiceTokenId)
    || !SERVICE_TOKEN_ID.test(access.canaryServiceTokenId)) {
    throw new TypeError('canary service identity must be one exact service token ID');
  }
  return access.canaryServiceTokenId;
}

export function assertCanaryServiceIdentityConfig(config: GatewayConfig): void {
  const source = config.sources[0];
  if (config.gateway.name !== 'Ankka disposable canary'
    || !CANARY_HOST_LABEL.test(config.gateway.hostname.split('.')[0] ?? '')
    || config.gateway.codeMode !== 'off'
    || config.sources.length !== 1
    || source?.id !== 'synthetic-canary'
    || source.enabledTools.length !== 1
    || source.enabledTools[0] !== 'ankka_canary_status'
    || source.authentication.mode !== 'none'
    || source.authentication.onBehalfOfUser !== false
    || source.accessGroup !== undefined) {
    throw new TypeError('service identity is restricted to the disposable synthetic canary');
  }
}

export async function canaryServiceIdentityDigest(id: string): Promise<string> {
  if (!SERVICE_TOKEN_ID.test(id)) {
    throw new TypeError('canary service identity must be one exact service token ID');
  }
  // A single fixed key is already canonical JSON; the raw value never leaves this boundary.
  const bytes = new TextEncoder().encode(JSON.stringify({ canaryServiceTokenId: id }));
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return `sha256:${[...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

export function exactServiceTokenPolicyRule(rule: BoundaryValue): string | null {
  if (!v.is(boundaryObjectSchema, rule)
    || Object.keys(rule).length !== 1
    || !v.is(boundaryObjectSchema, rule.service_token)
    || Object.keys(rule.service_token).length !== 1
    || !v.is(v.string(), rule.service_token.token_id)
    || !SERVICE_TOKEN_ID.test(rule.service_token.token_id)) return null;
  return rule.service_token.token_id;
}

export async function serviceTokenPolicyMatchesDigest(
  policy: BoundaryValue,
  identitiesHash: string,
): Promise<boolean> {
  if (!v.is(boundaryObjectSchema, policy)
    || policy.decision !== 'non_identity'
    || !Array.isArray(policy.include) || policy.include.length !== 1
    || !Array.isArray(policy.exclude) || policy.exclude.length !== 0
    || !Array.isArray(policy.require) || policy.require.length !== 0) return false;
  const id = exactServiceTokenPolicyRule(policy.include[0]);
  return id !== null && await canaryServiceIdentityDigest(id) === identitiesHash;
}
