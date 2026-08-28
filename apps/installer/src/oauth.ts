import {
  OAUTH_AUTHORIZE_URL,
  OAUTH_CALLBACK_URL,
  OAUTH_REVOKE_URL,
  OAUTH_TOKEN_URL,
  REQUIRED_OAUTH_SCOPES,
} from './constants';
import { DeployError } from './errors';
import { readBoundedText, withDeadline } from './http';

export type FetchTransport = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export interface CloudflareOauthConfig {
  clientId: string;
  clientSecret: string;
}

export function assertCloudflareOauthConfig(config: CloudflareOauthConfig): void {
  if (!/^[A-Za-z0-9_-]{16,128}$/u.test(config.clientId)) {
    throw new DeployError(500, 'oauth_exchange_failed', 'oauth_client_id_invalid');
  }
  if (
    config.clientSecret.length < 16 ||
    config.clientSecret.length > 512 ||
    /[:\u0000-\u001f\u007f]/u.test(config.clientSecret)
  ) {
    throw new DeployError(500, 'oauth_exchange_failed', 'oauth_client_secret_invalid');
  }
}

const STANDARD_OAUTH_ERRORS = new Set([
  'invalid_request', 'invalid_client', 'invalid_grant', 'unauthorized_client',
  'unsupported_grant_type', 'invalid_scope', 'server_error', 'temporarily_unavailable',
]);

/** Status class plus the standard RFC 6749 error code when present; never bodies. */
function tokenEndpointReason(status: number, serialized: string): string {
  let standard = '';
  try {
    const parsed = JSON.parse(serialized) as unknown;
    const value = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>).error
      : undefined;
    if (typeof value === 'string' && STANDARD_OAUTH_ERRORS.has(value)) standard = `_${value}`;
  } catch {
    standard = '';
  }
  return `token_endpoint_${status}${standard}`;
}

function basicAuthorization(config: CloudflareOauthConfig): string {
  assertCloudflareOauthConfig(config);
  return `Basic ${btoa(`${config.clientId}:${config.clientSecret}`)}`;
}

export function buildAuthorizationUrl(input: {
  clientId: string;
  state: string;
  challenge: string;
  scopes?: readonly string[];
}): string {
  if (
    !/^[A-Za-z0-9_-]{16,128}$/u.test(input.clientId) ||
    !/^[A-Za-z0-9_-]{43}$/u.test(input.state) ||
    !/^[A-Za-z0-9_-]{43}$/u.test(input.challenge)
  ) {
    throw new DeployError(500, 'oauth_grant_invalid');
  }
  const scopes = input.scopes ?? REQUIRED_OAUTH_SCOPES;
  if (scopes.length < 1 || scopes.length > 32 || scopes.some((scope) =>
    typeof scope !== 'string' || !/^[a-z][a-z0-9-]*\.(?:read|write)$/u.test(scope)
  ) || new Set(scopes).size !== scopes.length) {
    throw new DeployError(500, 'oauth_grant_invalid');
  }
  const url = new URL(OAUTH_AUTHORIZE_URL);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', input.clientId);
  url.searchParams.set('redirect_uri', OAUTH_CALLBACK_URL);
  url.searchParams.set('scope', scopes.join(' '));
  url.searchParams.set('state', input.state);
  url.searchParams.set('code_challenge', input.challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return url.toString();
}

function parseGrantedScopes(scope: unknown): readonly string[] {
  if (typeof scope !== 'string' || scope.length > 8192) return Object.freeze([]);
  const values = [...new Set(scope.split(/\s+/u).filter(Boolean))].sort();
  return Object.freeze(values);
}

export function assertExactGrantedScopes(
  scopes: readonly string[],
  expectedScopes: readonly string[] = REQUIRED_OAUTH_SCOPES,
): void {
  const values = [...scopes].sort();
  const expected = [...expectedScopes].sort();
  if (
    values.length !== expected.length ||
    values.some((value, index) => value !== expected[index])
  ) {
    throw new DeployError(403, 'oauth_grant_invalid');
  }
}

export class EphemeralCloudflareGrant {
  #accessToken: string | undefined;
  #refreshToken: string | undefined;
  #usable = false;
  readonly #metadataValid: boolean;
  readonly scopes: readonly string[];

  constructor(
    accessToken: string | undefined,
    refreshToken: string | undefined,
    scopes: readonly string[],
    metadataValid: boolean,
  ) {
    this.#accessToken = accessToken;
    this.#refreshToken = refreshToken;
    this.scopes = scopes;
    this.#metadataValid = metadataValid;
  }

  assertUsable(expectedScopes: readonly string[] = REQUIRED_OAUTH_SCOPES): void {
    if (!this.#metadataValid || !this.#accessToken) {
      throw new DeployError(
        502,
        'oauth_exchange_failed',
        this.#accessToken ? 'token_metadata_invalid' : 'token_access_token_missing',
      );
    }
    assertExactGrantedScopes(this.scopes, expectedScopes);
    this.#usable = true;
  }

  async withAccessToken<T>(operation: (accessToken: string) => Promise<T>): Promise<T> {
    if (!this.#usable || !this.#accessToken) throw new DeployError(500, 'oauth_grant_invalid');
    return operation(this.#accessToken);
  }

  async revoke(transport: FetchTransport, config: CloudflareOauthConfig): Promise<void> {
    const tokens = [this.#accessToken, this.#refreshToken].filter(
      (value): value is string => typeof value === 'string',
    );
    let failed = false;
    for (const token of tokens) {
      try {
        await withDeadline(async (signal) => {
          const body = new URLSearchParams({ token });
          const response = await transport(OAUTH_REVOKE_URL, {
            method: 'POST',
            headers: {
              authorization: basicAuthorization(config),
              'content-type': 'application/x-www-form-urlencoded',
              accept: 'application/json',
            },
            body,
            signal,
          });
          await readBoundedText(response, 'oauth_revoke_failed', 16 * 1024);
          if (!response.ok) throw new DeployError(502, 'oauth_revoke_failed');
        }, 'oauth_revoke_failed');
      } catch {
        // Attempt every returned credential even if revoking one failed.
        failed = true;
      }
    }
    if (failed) throw new DeployError(502, 'oauth_revoke_failed');
  }

  discard(): void {
    this.#accessToken = undefined;
    this.#refreshToken = undefined;
    this.#usable = false;
  }

  toJSON(): never {
    throw new DeployError(500, 'oauth_grant_invalid');
  }
}

function capturedCredential(value: unknown): string | undefined {
  return typeof value === 'string' && value.length >= 1 && value.length <= 8192
    ? value
    : undefined;
}

function validCredentialMetadata(value: unknown, required: boolean): boolean {
  if (value === undefined) return !required;
  return typeof value === 'string' &&
    value.length >= 16 &&
    value.length <= 8192 &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

export async function exchangeAuthorizationCode(input: {
  code: string;
  verifier: string;
  config: CloudflareOauthConfig;
  transport: FetchTransport;
}): Promise<EphemeralCloudflareGrant> {
  if (
    input.code.length < 8 ||
    input.code.length > 4096 ||
    /[\u0000-\u001f\u007f]/u.test(input.code) ||
    !/^[A-Za-z0-9_-]{43}$/u.test(input.verifier)
  ) {
    throw new DeployError(400, 'oauth_exchange_failed', 'exchange_input_invalid');
  }
  const authorization = basicAuthorization(input.config);
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: input.code,
    redirect_uri: OAUTH_CALLBACK_URL,
    code_verifier: input.verifier,
  });
  let payload: unknown;
  try {
    payload = await withDeadline(async (signal) => {
      let response: Response;
      try {
        response = await input.transport(OAUTH_TOKEN_URL, {
          method: 'POST',
          headers: {
            authorization,
            'content-type': 'application/x-www-form-urlencoded',
            accept: 'application/json',
          },
          body,
          signal,
        });
      } catch {
        throw new DeployError(502, 'oauth_exchange_failed', 'token_endpoint_unreachable');
      }
      const serialized = await readBoundedText(response, 'oauth_exchange_failed');
      if (!response.ok) {
        throw new DeployError(502, 'oauth_exchange_failed', tokenEndpointReason(response.status, serialized));
      }
      try {
        return JSON.parse(serialized) as unknown;
      } catch {
        throw new DeployError(502, 'oauth_exchange_failed', 'token_response_not_json');
      }
    }, 'oauth_exchange_failed');
  } catch (error) {
    if (error instanceof DeployError) {
      throw new DeployError(
        error.status,
        'oauth_exchange_failed',
        error.reason ?? (error.status === 504 ? 'token_endpoint_timeout' : 'token_response_unreadable'),
      );
    }
    throw new DeployError(502, 'oauth_exchange_failed', 'token_exchange_unknown');
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new DeployError(502, 'oauth_exchange_failed', 'token_response_not_object');
  }
  const token = payload as Record<string, unknown>;
  // Capture every bounded credential string from a successful token response
  // before validating any accompanying metadata. The callback therefore owns
  // a disposable revocation handle even when token_type, refresh metadata, or
  // the returned scope set is malformed.
  const accessToken = capturedCredential(token.access_token);
  const refreshToken = capturedCredential(token.refresh_token);
  const metadataValid =
    typeof token.token_type === 'string' && token.token_type.toLowerCase() === 'bearer' &&
    validCredentialMetadata(token.access_token, true) &&
    validCredentialMetadata(token.refresh_token, false);
  return new EphemeralCloudflareGrant(
    accessToken,
    refreshToken,
    parseGrantedScopes(token.scope),
    metadataValid,
  );
}
