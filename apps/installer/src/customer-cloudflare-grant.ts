import * as v from 'valibot';

import { boundaryObjectSchema, boundaryValueSchema, type BoundaryValue } from './boundary';
import { CLOUDFLARE_API_ORIGIN, OAUTH_REVOKE_URL, OAUTH_EXCHANGE_URL } from './constants';
import { CLOUDFLARE_CODE_RELAY_CALLBACK } from './cloudflare-code-relay';
import {
  exactOperationScopes,
  isCustomerCloudflareOperation,
  RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS,
  type CustomerCloudflareOperation,
} from './cloudflare-operation-authority';
import { readBoundedText, withDeadline } from './http';

const CLIENT_ID = /^[A-Za-z0-9_-]{16,128}$/u;
const VERIFIER = /^[A-Za-z0-9_-]{43}$/u;
const CODE = /^[A-Za-z0-9._~-]{8,4096}$/u;
const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const MAX_PROVIDER_BYTES = 128 * 1024;

const accountEnvelopeSchema = v.looseObject({
  success: v.literal(true),
  errors: v.array(boundaryValueSchema),
  messages: v.array(boundaryValueSchema),
  result: v.array(v.looseObject({ id: v.pipe(v.string(), v.regex(ACCOUNT_ID)) })),
});
const zoneEnvelopeSchema = v.looseObject({
  success: v.literal(true),
  errors: v.array(boundaryValueSchema),
  messages: v.array(boundaryValueSchema),
  result: v.array(v.looseObject({
    id: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
    name: v.string(),
    status: v.literal('active'),
    account: v.looseObject({ id: v.pipe(v.string(), v.regex(ACCOUNT_ID)) }),
  })),
});

export type CustomerCloudflareGrantErrorCode =
  | 'invalid'
  | 'token_exchange_failed'
  | 'scope_mismatch'
  | 'refresh_token_returned'
  | 'account_mismatch'
  | 'account_ambiguous'
  | 'zone_mismatch'
  | 'zone_ambiguous'
  | 'provider_unavailable'
  | 'revoke_failed';

export class CustomerCloudflareGrantError extends Error {
  readonly userMessage: string | null;

  constructor(readonly code: CustomerCloudflareGrantErrorCode) {
    super(code);
    this.name = 'CustomerCloudflareGrantError';
    this.userMessage = code === 'account_ambiguous'
      ? 'Please authorize exactly one Cloudflare account.'
      : null;
  }
}

export type CustomerCloudflareTransport = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

function invalid(): never {
  throw new CustomerCloudflareGrantError('invalid');
}

function parseScopes(value: BoundaryValue): readonly string[] {
  const parsed = v.safeParse(v.pipe(v.string(), v.maxLength(8192)), value);
  if (!parsed.success) return Object.freeze([]);
  return Object.freeze([...new Set(parsed.output.split(/\s+/u).filter(Boolean))].sort());
}

function exactScopes(actual: readonly string[], expected: readonly string[]): boolean {
  const left = [...actual].sort();
  const right = [...expected].sort();
  return left.length === right.length && left.every((scope, index) => scope === right[index]);
}

function containsControlCharacter(value: string): boolean {
  return Array.from(value).some((character) => {
    const code = character.charCodeAt(0);
    return code <= 31 || code === 127;
  });
}

// Capture any bounded credential returned by a successful token response so
// it remains available for revocation even when its metadata is unacceptable.
function capturedCredential(value: BoundaryValue): string | undefined {
  const parsed = v.safeParse(v.pipe(v.string(), v.minLength(1), v.maxLength(8192)), value);
  return parsed.success ? parsed.output : undefined;
}

function validBearerCredential(value: string | undefined): value is string {
  return value !== undefined && value.length >= 16 && value.length <= 8192 &&
    !containsControlCharacter(value) && /^[A-Za-z0-9._~+/-]+=*$/u.test(value);
}

function validOperation(
  value: string,
): value is CustomerCloudflareOperation {
  return isCustomerCloudflareOperation(value);
}

async function responseJson(response: Response, failure: CustomerCloudflareGrantErrorCode): Promise<BoundaryValue> {
  let serialized: string;
  try {
    serialized = await readBoundedText(response, failure === 'revoke_failed' ? 'oauth_revoke_failed' : 'oauth_exchange_failed',
      MAX_PROVIDER_BYTES);
  } catch {
    throw new CustomerCloudflareGrantError(failure);
  }
  try {
    const parsed = v.safeParse(boundaryValueSchema, JSON.parse(serialized));
    if (!parsed.success) throw new Error('invalid');
    return parsed.output;
  } catch {
    throw new CustomerCloudflareGrantError(failure);
  }
}

export class EphemeralCustomerCloudflareGrant {
  #accessToken: string | undefined;
  #refreshToken: string | undefined;
  #usable = false;

  constructor(
    accessToken: string | undefined,
    refreshToken: string | undefined,
    readonly scopes: readonly string[],
    readonly metadataValid: boolean,
    readonly expectedScopes: readonly string[],
  ) {
    this.#accessToken = accessToken;
    this.#refreshToken = refreshToken;
  }

  assertUsable(): void {
    if (!this.metadataValid || this.#accessToken === undefined) {
      throw new CustomerCloudflareGrantError('token_exchange_failed');
    }
    if (this.#refreshToken !== undefined) {
      throw new CustomerCloudflareGrantError('refresh_token_returned');
    }
    if (!exactScopes(this.scopes, this.expectedScopes)) {
      throw new CustomerCloudflareGrantError('scope_mismatch');
    }
    this.#usable = true;
  }

  async withAccessToken<Value>(operation: (accessToken: string) => Promise<Value>): Promise<Value> {
    if (!this.#usable || this.#accessToken === undefined) invalid();
    return operation(this.#accessToken);
  }

  async revoke(input: {
    readonly clientId: string;
    readonly transport: CustomerCloudflareTransport;
  }): Promise<void> {
    if (!CLIENT_ID.test(input.clientId)) invalid();
    const tokens = [this.#accessToken, this.#refreshToken].filter(
      (token): token is string => token !== undefined,
    );
    let failed = false;
    for (const token of tokens) {
      try {
        await withDeadline(async (signal) => {
          const response = await input.transport(OAUTH_REVOKE_URL, {
            method: 'POST',
            headers: {
              accept: 'application/json',
              'content-type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({ token, client_id: input.clientId }),
            signal,
          });
          await readBoundedText(response, 'oauth_revoke_failed', 16 * 1024);
          if (!response.ok) throw new CustomerCloudflareGrantError('revoke_failed');
        }, 'oauth_revoke_failed');
      } catch {
        failed = true;
      }
    }
    if (failed) throw new CustomerCloudflareGrantError('revoke_failed');
  }

  discard(): void {
    this.#accessToken = undefined;
    this.#refreshToken = undefined;
    this.#usable = false;
  }

  toJSON(): never {
    invalid();
  }
}

/** Public-client PKCE exchange performed by the customer-owned Gateway. */
export async function exchangeCustomerCloudflareAuthorizationCode(input: {
  readonly clientId: string;
  readonly code: string;
  readonly verifier: string;
  readonly operation: string;
  readonly transport: CustomerCloudflareTransport;
  /** Internal output of the customer receipt verifier; never browser input. */
  readonly receiptResourceKinds?: readonly string[];
}): Promise<EphemeralCustomerCloudflareGrant> {
  const receiptKindsResult = input.receiptResourceKinds === undefined
    ? null
    : v.safeParse(v.array(v.picklist(RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS)),
      input.receiptResourceKinds);
  if (!CLIENT_ID.test(input.clientId) || !CODE.test(input.code) || !VERIFIER.test(input.verifier) ||
      !validOperation(input.operation) || (receiptKindsResult !== null &&
        (!receiptKindsResult.success || receiptKindsResult.output.length < 1 ||
         receiptKindsResult.output.length > RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS.length ||
         new Set(receiptKindsResult.output).size !== receiptKindsResult.output.length))) invalid();
  const receiptResourceKinds = receiptKindsResult?.success === true
    ? receiptKindsResult.output
    : undefined;
  if (input.operation !== 'uninstall' && receiptResourceKinds !== undefined) invalid();
  const expectedScopes = exactOperationScopes(input.operation, receiptResourceKinds);
  if (expectedScopes.length === 0) invalid();
  let response: Response;
  try {
    response = await withDeadline((signal) => input.transport(OAUTH_EXCHANGE_URL, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: input.clientId,
        code: input.code,
        redirect_uri: CLOUDFLARE_CODE_RELAY_CALLBACK,
        code_verifier: input.verifier,
      }),
      signal,
    }), 'oauth_exchange_failed');
  } catch {
    throw new CustomerCloudflareGrantError('token_exchange_failed');
  }
  const payload = await responseJson(response, 'token_exchange_failed');
  const object = v.safeParse(boundaryObjectSchema, payload);
  if (!response.ok || !object.success) {
    throw new CustomerCloudflareGrantError('token_exchange_failed');
  }
  const accessToken = capturedCredential(object.output.access_token);
  const refreshToken = capturedCredential(object.output.refresh_token);
  const tokenTypeResult = v.safeParse(v.string(), object.output.token_type);
  const tokenType = tokenTypeResult.success ? tokenTypeResult.output.toLowerCase() : '';
  return new EphemeralCustomerCloudflareGrant(
    accessToken,
    refreshToken,
    parseScopes(object.output.scope),
    tokenType === 'bearer' && validBearerCredential(accessToken),
    expectedScopes,
  );
}

/**
 * Binds the customer-side grant to the Stage 1 account without relying on
 * memberships, user-details, or account-settings authority. Any other fixed
 * operation scopes are irrelevant to this exact one-account assertion.
 */
export async function resolveSingleAuthorizedCloudflareAccount(input: {
  readonly accessToken: string;
  readonly transport: CustomerCloudflareTransport;
}): Promise<string> {
  if (!validBearerCredential(input.accessToken)) invalid();
  const url = new URL('/client/v4/accounts', CLOUDFLARE_API_ORIGIN);
  url.searchParams.set('page', '1');
  url.searchParams.set('per_page', '2');
  let response: Response;
  try {
    response = await withDeadline((signal) => input.transport(url, {
      method: 'GET',
      headers: { accept: 'application/json', authorization: `Bearer ${input.accessToken}` },
      signal,
    }), 'oauth_exchange_failed');
  } catch {
    throw new CustomerCloudflareGrantError('provider_unavailable');
  }
  const value = await responseJson(response, 'provider_unavailable');
  const parsed = v.safeParse(accountEnvelopeSchema, value);
  if (!response.ok || !parsed.success || parsed.output.errors.length !== 0 ||
      parsed.output.messages.length !== 0) {
    throw new CustomerCloudflareGrantError('provider_unavailable');
  }
  if (parsed.output.result.length !== 1) {
    throw new CustomerCloudflareGrantError('account_ambiguous');
  }
  const accountId = parsed.output.result[0]?.id;
  if (accountId === undefined) throw new CustomerCloudflareGrantError('provider_unavailable');
  return accountId;
}

export async function verifyCustomerCloudflareGrantAccount(input: {
  readonly accessToken: string;
  readonly expectedAccountId: string;
  readonly transport: CustomerCloudflareTransport;
}): Promise<void> {
  if (!ACCOUNT_ID.test(input.expectedAccountId)) invalid();
  const accountId = await resolveSingleAuthorizedCloudflareAccount({
    accessToken: input.accessToken,
    transport: input.transport,
  });
  if (accountId !== input.expectedAccountId) {
    throw new CustomerCloudflareGrantError('account_mismatch');
  }
}

/** Resolve one exact active zone without adding identity or membership scopes. */
export async function resolveAuthorizedCloudflareZone(input: {
  readonly accessToken: string;
  readonly accountId: string;
  readonly zoneName: string;
  readonly transport: CustomerCloudflareTransport;
}): Promise<Readonly<{ id: string; name: string; status: 'active' }>> {
  if (!validBearerCredential(input.accessToken) || !ACCOUNT_ID.test(input.accountId)) invalid();
  let expectedName: string;
  try {
    const url = new URL(`https://${input.zoneName}`);
    if (url.hostname !== input.zoneName || url.pathname !== '/' || url.search !== '' || url.hash !== '' ||
        url.username !== '' || url.password !== '' || url.port !== '') invalid();
    expectedName = url.hostname;
  } catch {
    invalid();
  }
  const url = new URL('/client/v4/zones', CLOUDFLARE_API_ORIGIN);
  url.searchParams.set('account.id', input.accountId);
  url.searchParams.set('name', expectedName);
  url.searchParams.set('status', 'active');
  url.searchParams.set('page', '1');
  url.searchParams.set('per_page', '2');
  let response: Response;
  try {
    response = await withDeadline((signal) => input.transport(url, {
      method: 'GET',
      headers: { accept: 'application/json', authorization: `Bearer ${input.accessToken}` },
      signal,
    }), 'oauth_exchange_failed');
  } catch {
    throw new CustomerCloudflareGrantError('provider_unavailable');
  }
  const value = await responseJson(response, 'provider_unavailable');
  const parsed = v.safeParse(zoneEnvelopeSchema, value);
  if (!response.ok || !parsed.success || parsed.output.errors.length !== 0 ||
      parsed.output.messages.length !== 0) {
    throw new CustomerCloudflareGrantError('provider_unavailable');
  }
  if (parsed.output.result.length > 1) throw new CustomerCloudflareGrantError('zone_ambiguous');
  const zone = parsed.output.result[0];
  if (zone === undefined || zone.account.id !== input.accountId || zone.name !== expectedName) {
    throw new CustomerCloudflareGrantError('zone_mismatch');
  }
  return Object.freeze({ id: zone.id, name: zone.name, status: 'active' });
}
