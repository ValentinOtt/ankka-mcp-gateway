import * as v from 'valibot';

import { boundaryValueSchema } from './boundary';
import { canonicalJson } from './canonical-json';
import { CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH } from './customer-install-paths';
import {
  exactOperationScopes,
  fixedCloudflareOperationAuthority,
  isCustomerCloudflareOperation,
  RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS,
  type CustomerCloudflareOperation,
} from './cloudflare-operation-authority';
import { base64UrlDecode, base64UrlEncode, constantTimeEqual } from './crypto';

export const CLOUDFLARE_CODE_RELAY_ORIGIN = 'https://auth.ankka.ai';
export const CLOUDFLARE_CODE_RELAY_CALLBACK = `${CLOUDFLARE_CODE_RELAY_ORIGIN}/oauth/callback`;
export const CLOUDFLARE_AUTHORIZE_ENDPOINT = 'https://dash.cloudflare.com/oauth2/auth';
export const CLOUDFLARE_CODE_RELAY_TTL_MS = 10 * 60 * 1_000;

const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const CLIENT_ID = /^[A-Za-z0-9_-]{16,128}$/u;
const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const INSTALLATION_ID = /^acg-[a-f0-9]{24}$/u;
const AUTHORIZATION_CODE = /^[A-Za-z0-9._~-]{8,4096}$/u;
const PROVIDER_ERROR = /^[A-Za-z_]{3,64}$/u;
const MAX_PROVIDER_ERROR_DESCRIPTION_LENGTH = 1_024;
const MAX_PROVIDER_ERROR_URI_LENGTH = 2_048;
const MAX_ECHOED_SCOPE_LENGTH = 1_024;
const SCOPE_ID = /^[a-z][a-z0-9-]*\.(?:read|write)$/u;

const relayStateSchema = v.strictObject({
  schemaVersion: v.literal(1),
  operation: v.picklist([
    'install', 'upgrade', 'rollback', 'source-add', 'source-update', 'source-remove', 'uninstall',
  ]),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  installId: v.pipe(v.string(), v.regex(INSTALLATION_ID)),
  gatewayCallback: v.pipe(v.string(), v.url()),
  gatewayState: v.pipe(v.string(), v.regex(TOKEN)),
  nonce: v.pipe(v.string(), v.regex(TOKEN)),
  expiresAt: v.pipe(v.number(), v.safeInteger()),
});

type RelayState = v.InferOutput<typeof relayStateSchema>;

export class CloudflareCodeRelayError extends Error {
  constructor(readonly code: 'invalid' | 'expired' | 'operation_disabled') {
    super(code);
    this.name = 'CloudflareCodeRelayError';
  }
}

function invalid(): never {
  throw new CloudflareCodeRelayError('invalid');
}

function validGatewayCallback(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.username === '' && url.password === '' && url.port === '' &&
      url.pathname === CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH && url.search === '' && url.hash === '' &&
      url.hostname === url.hostname.toLowerCase() && url.hostname.includes('.');
  } catch {
    return false;
  }
}

function relayKeyBytes(value: string): Uint8Array<ArrayBuffer> {
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(value);
  } catch {
    invalid();
  }
  if (bytes.byteLength !== 32) invalid();
  const copy = new Uint8Array(new ArrayBuffer(32));
  copy.set(bytes);
  return copy;
}

async function relayKey(value: string): Promise<CryptoKey> {
  const bytes = relayKeyBytes(value);
  try {
    return await crypto.subtle.importKey('raw', bytes, { name: 'HMAC', hash: 'SHA-256' }, false, [
      'sign', 'verify',
    ]);
  } finally {
    bytes.fill(0);
  }
}

async function signState(serialized: string, key: string): Promise<string> {
  const signature = await crypto.subtle.sign(
    'HMAC',
    await relayKey(key),
    new TextEncoder().encode(serialized),
  );
  return base64UrlEncode(new Uint8Array(signature));
}

async function sealState(state: RelayState, key: string): Promise<string> {
  const serialized = canonicalJson(state);
  const payload = base64UrlEncode(new TextEncoder().encode(serialized));
  return `${payload}.${await signState(payload, key)}`;
}

async function openState(value: string, key: string): Promise<RelayState> {
  const segments = value.split('.');
  const payload = segments.at(0);
  const signature = segments.at(1);
  if (segments.length !== 2 || payload === undefined || signature === undefined || !TOKEN.test(signature) ||
      payload.length > 4096 || !/^[A-Za-z0-9_-]+$/u.test(payload)) invalid();
  const expected = await signState(payload, key);
  if (!constantTimeEqual(expected, signature)) invalid();
  let decoded: unknown;
  let bytes: Uint8Array | undefined;
  try {
    bytes = base64UrlDecode(payload);
    decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    invalid();
  } finally {
    bytes?.fill(0);
  }
  const boundary = v.safeParse(boundaryValueSchema, decoded);
  const parsed = boundary.success ? v.safeParse(relayStateSchema, boundary.output) : null;
  if (!parsed?.success || canonicalJson(parsed.output) !== canonicalJson(decoded) ||
      !validGatewayCallback(parsed.output.gatewayCallback)) invalid();
  return Object.freeze(parsed.output);
}

export interface FixedRelayAuthorizationInput {
  /** Public PKCE-only client used by customer-owned Workers. */
  readonly clientId: string;
  /** Server-only state authentication key held by auth.ankka.ai. */
  readonly relayStateKey: string;
  /** Authenticated gateway identity; never copied from a browser scope string. */
  readonly gateway: {
    readonly accountId: string;
    readonly installId: string;
    readonly callback: string;
  };
  readonly operation: string;
  readonly gatewayState: string;
  readonly pkceChallenge: string;
  readonly nonce: string;
  readonly now: number;
  /** Internal output of the reviewed receipt verifier; never raw HTTP input. */
  readonly receiptResourceKinds?: readonly string[];
}

export interface FixedRelayAuthorization {
  readonly authorizationUrl: string;
  readonly expiresAt: number;
  readonly scopes: readonly string[];
}

/**
 * Builds a Cloudflare authorization from a fixed operation. There is no scope
 * parameter in this boundary, so a compromised Gateway cannot widen it.
 */
export async function buildFixedRelayAuthorization(
  input: FixedRelayAuthorizationInput,
): Promise<FixedRelayAuthorization> {
  const operation = input.operation;
  if (!CLIENT_ID.test(input.clientId) || !ACCOUNT_ID.test(input.gateway.accountId) ||
      !INSTALLATION_ID.test(input.gateway.installId) || !validGatewayCallback(input.gateway.callback) ||
      !TOKEN.test(input.gatewayState) || !TOKEN.test(input.pkceChallenge) || !TOKEN.test(input.nonce) ||
      !Number.isSafeInteger(input.now) || input.now < 0 ||
      !isCustomerCloudflareOperation(operation)) invalid();
  const receiptKindsResult = input.receiptResourceKinds === undefined
    ? null
    : v.safeParse(v.array(v.picklist(RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS)),
      input.receiptResourceKinds);
  if (receiptKindsResult !== null && (!receiptKindsResult.success ||
      receiptKindsResult.output.length < 1 ||
      receiptKindsResult.output.length > RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS.length ||
      new Set(receiptKindsResult.output).size !== receiptKindsResult.output.length)) invalid();
  const receiptResourceKinds = receiptKindsResult?.success === true
    ? receiptKindsResult.output
    : undefined;
  const authority = fixedCloudflareOperationAuthority(operation);
  if (!authority.enabled || authority.executor !== 'customer-gateway') {
    throw new CloudflareCodeRelayError('operation_disabled');
  }
  if (operation !== 'uninstall' && receiptResourceKinds !== undefined) invalid();
  const scopes = exactOperationScopes(operation, receiptResourceKinds);
  if (scopes.length === 0) invalid();
  const expiresAt = input.now + CLOUDFLARE_CODE_RELAY_TTL_MS;
  const state = await sealState({
    schemaVersion: 1,
    operation,
    accountId: input.gateway.accountId,
    installId: input.gateway.installId,
    gatewayCallback: input.gateway.callback,
    gatewayState: input.gatewayState,
    nonce: input.nonce,
    expiresAt,
  }, input.relayStateKey);
  const url = new URL(CLOUDFLARE_AUTHORIZE_ENDPOINT);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', input.clientId);
  url.searchParams.set('redirect_uri', CLOUDFLARE_CODE_RELAY_CALLBACK);
  url.searchParams.set('scope', scopes.join(' '));
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', input.pkceChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return Object.freeze({ authorizationUrl: url.toString(), expiresAt, scopes });
}

export interface RelayedCloudflareCode {
  readonly location: string;
  readonly operation: CustomerCloudflareOperation;
  readonly accountId: string;
  readonly installId: string;
}

export interface RelayedCloudflareError {
  readonly location: string;
  readonly operation: CustomerCloudflareOperation;
  readonly accountId: string;
  readonly installId: string;
}

/**
 * Validates relay state and returns a redirect carrying only the authorization
 * code and the Gateway's original state. This function has no token endpoint
 * transport and therefore cannot exchange or retain a Cloudflare grant.
 */
/**
 * Cloudflare echoes the granted scope set on the authorization response
 * (observed live 2026-08-23 on deploy.ankka.ai and again on the relay
 * qualification of 2026-09-03). The relay tolerates that echo only when every
 * echoed scope lies within the sealed operation's fixed ceiling; it never
 * forwards it. The customer Gateway still enforces the exact set at exchange.
 */
function echoedScopeWithinCeiling(echoedScope: string, operation: CustomerCloudflareOperation): boolean {
  if (echoedScope.length < 1 || echoedScope.length > MAX_ECHOED_SCOPE_LENGTH) return false;
  const scopes = echoedScope.split(/\s+/u).filter(Boolean);
  if (scopes.length === 0 || new Set(scopes).size !== scopes.length) return false;
  const ceiling = new Set<string>(operation === 'uninstall'
    ? exactOperationScopes('uninstall', RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS)
    : exactOperationScopes(operation));
  return scopes.every((scope) => SCOPE_ID.test(scope) && ceiling.has(scope));
}

export async function relayCloudflareAuthorizationCode(input: {
  readonly code: string;
  readonly state: string;
  readonly relayStateKey: string;
  readonly now: number;
  /** Provider-echoed scope string, if Cloudflare appended one; validated, never forwarded. */
  readonly echoedScope?: string | null;
}): Promise<RelayedCloudflareCode> {
  if (!AUTHORIZATION_CODE.test(input.code) || !Number.isSafeInteger(input.now) || input.now < 0) invalid();
  const state = await openState(input.state, input.relayStateKey);
  if (state.expiresAt <= input.now) throw new CloudflareCodeRelayError('expired');
  if (input.echoedScope !== undefined && input.echoedScope !== null &&
      !echoedScopeWithinCeiling(input.echoedScope, state.operation)) invalid();
  const location = new URL(state.gatewayCallback);
  location.searchParams.set('code', input.code);
  location.searchParams.set('state', state.gatewayState);
  return Object.freeze({
    location: location.toString(),
    operation: state.operation,
    accountId: state.accountId,
    installId: state.installId,
  });
}

/**
 * Converts every provider-side OAuth rejection into one fixed error and sends
 * it to the signed customer callback. Provider descriptions are never copied.
 */
export async function relayCloudflareAuthorizationError(input: {
  readonly error: string;
  readonly errorDescription: string | null;
  readonly errorUri: string | null;
  readonly state: string;
  readonly relayStateKey: string;
  readonly now: number;
}): Promise<RelayedCloudflareError> {
  if (!PROVIDER_ERROR.test(input.error) ||
      input.errorDescription !== null &&
        input.errorDescription.length > MAX_PROVIDER_ERROR_DESCRIPTION_LENGTH ||
      input.errorUri !== null && !validProviderErrorUri(input.errorUri) ||
      !Number.isSafeInteger(input.now) || input.now < 0) invalid();
  const state = await openState(input.state, input.relayStateKey);
  if (state.expiresAt <= input.now) throw new CloudflareCodeRelayError('expired');
  const location = new URL(state.gatewayCallback);
  location.searchParams.set('error', 'authorization_rejected');
  location.searchParams.set('state', state.gatewayState);
  return Object.freeze({
    location: location.toString(),
    operation: state.operation,
    accountId: state.accountId,
    installId: state.installId,
  });
}

function validProviderErrorUri(value: string): boolean {
  if (value.length < 1 || value.length > MAX_PROVIDER_ERROR_URI_LENGTH) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.username === '' && url.password === '';
  } catch {
    return false;
  }
}
