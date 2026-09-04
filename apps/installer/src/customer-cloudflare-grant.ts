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
import { DeployError } from './errors';
import { type BoundedRead, fetchBoundedText, readBoundedText, withDeadline } from './http';

const CLIENT_ID = /^[A-Za-z0-9_-]{16,128}$/u;
const VERIFIER = /^[A-Za-z0-9_-]{43}$/u;
const CODE = /^[A-Za-z0-9._~-]{8,4096}$/u;
const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const MAX_PROVIDER_BYTES = 128 * 1024;
const REVOKE_ATTEMPTS = 3;
const REVOKE_BACKOFF_MS = 300;

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
    // Any status parses; only an active zone is ever matched or returned.
    status: v.string(),
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

const GRANT_ERROR_DETAIL = /^[a-z][a-z0-9_]{0,80}$/u;

export class CustomerCloudflareGrantError extends Error {
  readonly userMessage: string | null;
  /**
   * Secret-free diagnostic naming which check failed, built only from HTTP
   * statuses, the provider's numeric error codes, and result counts. Never
   * provider text, ids, or tokens.
   */
  readonly detail: string | null;

  constructor(readonly code: CustomerCloudflareGrantErrorCode, detail: string | null = null) {
    super(code);
    this.name = 'CustomerCloudflareGrantError';
    this.userMessage = code === 'account_ambiguous'
      ? 'Please authorize exactly one Cloudflare account.'
      : null;
    this.detail = detail !== null && GRANT_ERROR_DETAIL.test(detail) ? detail : null;
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

function parseProviderJson(serialized: string): BoundaryValue {
  const parsed = v.safeParse(boundaryValueSchema, JSON.parse(serialized));
  if (!parsed.success) throw new Error('invalid');
  return parsed.output;
}

/** Names a failure inside the deadline without provider text: expiry, body read, or transport. */
function deadlineDetail<Thrown>(error: Thrown): string {
  if (error instanceof DeployError) {
    if (error.status === 504) return 'deadline_expired';
    if (error.reason === 'body_read_failed') return 'body_read_failed';
  }
  return 'transport_failed';
}

const providerErrorCodeSchema = v.object({
  errors: v.pipe(
    v.array(v.looseObject({
      code: v.optional(v.pipe(v.number(), v.integer(), v.minValue(0), v.maxValue(999_999))),
    })),
    v.minLength(1),
  ),
});

/** The provider's first numeric error code, or null. Numeric codes carry no secrets. */
function firstProviderErrorCode(value: BoundaryValue): number | null {
  const parsed = v.safeParse(providerErrorCodeSchema, value);
  if (!parsed.success) return null;
  return parsed.output.errors[0]?.code ?? null;
}

function httpStatusDetail(response: Response): string {
  const { status } = response;
  return Number.isInteger(status) && status >= 100 && status <= 599 ? `http_${status}` : 'http_unknown';
}

type EnvelopeParse =
  | v.SafeParseResult<typeof accountEnvelopeSchema>
  | v.SafeParseResult<typeof zoneEnvelopeSchema>;

/**
 * Names why a provider envelope was rejected: the HTTP status and numeric
 * provider code for a refused read, else which envelope rule failed.
 */
function envelopeDetail(response: Response, value: BoundaryValue, parsed: EnvelopeParse): string {
  const code = firstProviderErrorCode(value);
  const suffix = code === null ? '' : `_code_${code}`;
  if (!response.ok) return `${httpStatusDetail(response)}${suffix}`;
  if (!parsed.success) return `envelope_invalid${suffix}`;
  if (parsed.output.errors.length !== 0) return `errors_present${suffix}`;
  if (parsed.output.messages.length !== 0) return 'messages_present';
  return 'envelope_rejected';
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
    /** Test seam for the back-off between attempts; production sleeps. */
    readonly wait?: (milliseconds: number) => Promise<void>;
  }): Promise<void> {
    if (!CLIENT_ID.test(input.clientId)) invalid();
    const tokens = [this.#accessToken, this.#refreshToken].filter(
      (token): token is string => token !== undefined,
    );
    const wait = input.wait ?? ((milliseconds: number) =>
      new Promise<void>((resolve) => { setTimeout(resolve, milliseconds); }));
    let failed: string | null = null;
    for (const token of tokens) {
      let revoked = false;
      // A revocation that is refused once is retried briefly: an unconfirmed
      // revocation turns an otherwise finished install into INCOMPLETE. The
      // last refusal is kept as a detail: its HTTP status, or transport.
      let last = 'transport';
      for (let attempt = 1; attempt <= REVOKE_ATTEMPTS && !revoked; attempt += 1) {
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
            if (!response.ok) {
              last = `http_${response.status}`;
              throw new CustomerCloudflareGrantError('revoke_failed', last);
            }
          }, 'oauth_revoke_failed');
          revoked = true;
        } catch {
          if (attempt < REVOKE_ATTEMPTS) await wait(REVOKE_BACKOFF_MS * attempt);
        }
      }
      if (!revoked) failed = last;
    }
    if (failed !== null) throw new CustomerCloudflareGrantError('revoke_failed', failed);
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
  let read: BoundedRead;
  try {
    read = await fetchBoundedText(input.transport, OAUTH_EXCHANGE_URL, {
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
    }, 'oauth_exchange_failed', { maxBytes: MAX_PROVIDER_BYTES });
  } catch (error) {
    throw new CustomerCloudflareGrantError('token_exchange_failed', deadlineDetail(error));
  }
  const { response } = read;
  let payload: BoundaryValue;
  try {
    payload = parseProviderJson(read.text);
  } catch {
    throw new CustomerCloudflareGrantError('token_exchange_failed', `not_json_${httpStatusDetail(response)}`);
  }
  const object = v.safeParse(boundaryObjectSchema, payload);
  if (!response.ok || !object.success) {
    throw new CustomerCloudflareGrantError(
      'token_exchange_failed',
      response.ok ? 'envelope_invalid' : httpStatusDetail(response),
    );
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
  let read: BoundedRead;
  try {
    read = await fetchBoundedText(input.transport, url, {
      method: 'GET',
      headers: { accept: 'application/json', authorization: `Bearer ${input.accessToken}` },
    }, 'oauth_exchange_failed', { maxBytes: MAX_PROVIDER_BYTES });
  } catch (error) {
    throw new CustomerCloudflareGrantError('provider_unavailable', deadlineDetail(error));
  }
  const { response } = read;
  let value: BoundaryValue;
  try {
    value = parseProviderJson(read.text);
  } catch {
    throw new CustomerCloudflareGrantError('provider_unavailable', `not_json_${httpStatusDetail(response)}`);
  }
  const parsed = v.safeParse(accountEnvelopeSchema, value);
  if (!response.ok || !parsed.success || parsed.output.errors.length !== 0 ||
      parsed.output.messages.length !== 0) {
    throw new CustomerCloudflareGrantError('provider_unavailable', envelopeDetail(response, value, parsed));
  }
  if (parsed.output.result.length !== 1) {
    throw new CustomerCloudflareGrantError('account_ambiguous', `accounts_${parsed.output.result.length}`);
  }
  const accountId = parsed.output.result[0]?.id;
  if (accountId === undefined) {
    throw new CustomerCloudflareGrantError('provider_unavailable', 'account_id_missing');
  }
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

/** Operations whose grant the gateway binds to the account it was installed in. */
export type CustomerCloudflareGatewayOperation = 'source-add' | 'upgrade' | 'rollback';

const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;

const accountProbeEnvelopeSchema = v.looseObject({
  success: v.boolean(),
  errors: v.array(boundaryValueSchema),
});

/** One small read of the expected account that the operation's own scope covers. */
function accountProbePath(operation: CustomerCloudflareGatewayOperation, workerName: string): string {
  if (operation === 'source-add') return '/access/ai-controls/mcp/portals';
  return `/workers/workers/${encodeURIComponent(workerName)}`;
}

function accountProbeDetail(
  response: Response,
  value: BoundaryValue,
  parsed: v.SafeParseResult<typeof accountProbeEnvelopeSchema>,
): string {
  const code = firstProviderErrorCode(value);
  const suffix = code === null ? '' : `_code_${code}`;
  if (!response.ok) return `${httpStatusDetail(response)}${suffix}`;
  if (!parsed.success) return `envelope_invalid${suffix}`;
  if (!parsed.output.success) return `success_false${suffix}`;
  if (parsed.output.errors.length !== 0) return `errors_present${suffix}`;
  return 'envelope_rejected';
}

/**
 * Binds a gateway operation's grant to the installed account. The accounts
 * listing shows only accounts the grant can read, and an operation grant
 * carries no account-level read scope, so this reads one small resource of
 * the expected account under the operation's own scope: the MCP portals for
 * a source grant, the gateway Worker for a Workers grant. A refused read
 * means the consent authorized another account; any other failure names the
 * provider problem without its text.
 */
export async function verifyCustomerCloudflareGrantAccountAccess(input: {
  readonly accessToken: string;
  readonly expectedAccountId: string;
  readonly operation: CustomerCloudflareGatewayOperation;
  readonly workerName: string;
  readonly transport: CustomerCloudflareTransport;
}): Promise<void> {
  if (!validBearerCredential(input.accessToken) || !ACCOUNT_ID.test(input.expectedAccountId) ||
      !WORKER_NAME.test(input.workerName)) {
    invalid();
  }
  const url = new URL(
    `/client/v4/accounts/${input.expectedAccountId}${accountProbePath(input.operation, input.workerName)}`,
    CLOUDFLARE_API_ORIGIN,
  );
  let read: BoundedRead;
  try {
    read = await fetchBoundedText(input.transport, url, {
      method: 'GET',
      headers: { accept: 'application/json', authorization: `Bearer ${input.accessToken}` },
    }, 'oauth_exchange_failed', { maxBytes: MAX_PROVIDER_BYTES });
  } catch (error) {
    throw new CustomerCloudflareGrantError('provider_unavailable', deadlineDetail(error));
  }
  const { response } = read;
  let value: BoundaryValue;
  try {
    value = parseProviderJson(read.text);
  } catch {
    throw new CustomerCloudflareGrantError('provider_unavailable', `not_json_${httpStatusDetail(response)}`);
  }
  const parsed = v.safeParse(accountProbeEnvelopeSchema, value);
  if (response.status === 401 || response.status === 403 || response.status === 404) {
    throw new CustomerCloudflareGrantError('account_mismatch', accountProbeDetail(response, value, parsed));
  }
  if (!response.ok || !parsed.success || !parsed.output.success || parsed.output.errors.length !== 0) {
    throw new CustomerCloudflareGrantError('provider_unavailable', accountProbeDetail(response, value, parsed));
  }
}

type AuthorizedZone = v.InferOutput<typeof zoneEnvelopeSchema>['result'][number];

/** Bounds for the unfiltered listing that backs the filtered zone read. */
const ZONE_LIST_PAGE_SIZE = 20;
const ZONE_LIST_MAX_PAGES = 10;

async function readZonePage(input: {
  readonly accessToken: string;
  readonly transport: CustomerCloudflareTransport;
  readonly url: URL;
}): Promise<readonly AuthorizedZone[]> {
  let read: BoundedRead;
  try {
    read = await fetchBoundedText(input.transport, input.url, {
      method: 'GET',
      headers: { accept: 'application/json', authorization: `Bearer ${input.accessToken}` },
    }, 'oauth_exchange_failed', { maxBytes: MAX_PROVIDER_BYTES });
  } catch (error) {
    throw new CustomerCloudflareGrantError('provider_unavailable', deadlineDetail(error));
  }
  const { response } = read;
  let value: BoundaryValue;
  try {
    value = parseProviderJson(read.text);
  } catch {
    throw new CustomerCloudflareGrantError('provider_unavailable', `not_json_${httpStatusDetail(response)}`);
  }
  const parsed = v.safeParse(zoneEnvelopeSchema, value);
  if (!response.ok || !parsed.success || parsed.output.errors.length !== 0 ||
      parsed.output.messages.length !== 0) {
    throw new CustomerCloudflareGrantError('provider_unavailable', envelopeDetail(response, value, parsed));
  }
  return parsed.output.result;
}

/**
 * Resolve one exact active zone without adding identity or membership scopes.
 *
 * The filtered read (name, account, status) is asked first. A grant that
 * answers it with no zone is then listed in bounded pages and matched here,
 * because provider-side filters and grant-scoped listings have not always
 * agreed; the failure detail says how many zones the grant could see, so a
 * grant with no zone access reads differently from a filter that missed.
 */
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
  const common = { accessToken: input.accessToken, transport: input.transport };
  const filtered = new URL('/client/v4/zones', CLOUDFLARE_API_ORIGIN);
  filtered.searchParams.set('account.id', input.accountId);
  filtered.searchParams.set('name', expectedName);
  filtered.searchParams.set('status', 'active');
  filtered.searchParams.set('page', '1');
  filtered.searchParams.set('per_page', '2');
  const direct = await readZonePage({ ...common, url: filtered });
  if (direct.length > 1) {
    throw new CustomerCloudflareGrantError('zone_ambiguous', `zones_${direct.length}`);
  }
  const matches = (zone: AuthorizedZone): boolean =>
    zone.account.id === input.accountId && zone.name === expectedName && zone.status === 'active';
  const zone = direct[0];
  if (zone !== undefined) {
    if (!matches(zone)) {
      throw new CustomerCloudflareGrantError('zone_mismatch', zone.account.id !== input.accountId ? 'account'
        : zone.name !== expectedName ? 'name' : 'status');
    }
    return Object.freeze({ id: zone.id, name: zone.name, status: 'active' });
  }
  // The filter found nothing: list what the grant can see and match here.
  const found: AuthorizedZone[] = [];
  let visible = 0;
  for (let page = 1; page <= ZONE_LIST_MAX_PAGES; page += 1) {
    const listing = new URL('/client/v4/zones', CLOUDFLARE_API_ORIGIN);
    listing.searchParams.set('page', String(page));
    listing.searchParams.set('per_page', String(ZONE_LIST_PAGE_SIZE));
    const zones = await readZonePage({ ...common, url: listing });
    visible += zones.length;
    found.push(...zones.filter(matches));
    if (zones.length < ZONE_LIST_PAGE_SIZE) break;
  }
  if (found.length > 1) throw new CustomerCloudflareGrantError('zone_ambiguous', `zones_${found.length}`);
  const listed = found[0];
  if (listed === undefined) {
    throw new CustomerCloudflareGrantError('zone_mismatch', `zones_0_visible_${Math.min(visible, 999)}`);
  }
  return Object.freeze({ id: listed.id, name: listed.name, status: 'active' });
}
