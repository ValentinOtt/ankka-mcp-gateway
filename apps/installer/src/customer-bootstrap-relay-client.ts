import * as v from 'valibot';

import {
  CLOUDFLARE_AUTHORIZE_ENDPOINT,
  CLOUDFLARE_CODE_RELAY_CALLBACK,
  CLOUDFLARE_CODE_RELAY_ORIGIN,
} from './cloudflare-code-relay';
import { exactOperationScopes } from './cloudflare-operation-authority';
import { readBoundedText, withDeadline } from './http';
import type { CustomerBootstrapRelayStart } from './customer-bootstrap-router';
import type { CustomerCloudflareTransport } from './customer-cloudflare-grant';
import { CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH } from './customer-install-paths';

const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const CLIENT_ID = /^[A-Za-z0-9_-]{16,128}$/u;
const RELAY_TICKET = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/u;
const SEALED_RELAY_STATE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/u;
const MAX_RESPONSE_BYTES = 16 * 1024;
const EXPECTED_AUTHORIZATION_KEYS = Object.freeze([
  'response_type', 'client_id', 'redirect_uri', 'scope', 'state',
  'code_challenge', 'code_challenge_method',
] as const);

const responseSchema = v.strictObject({
  schemaVersion: v.literal(1),
  authorizationUrl: v.pipe(v.string(), v.url(), v.maxLength(12_000)),
});

function applicationJson(value: string | null): boolean {
  return value?.split(';', 1)[0]?.trim().toLowerCase() === 'application/json';
}

function validGatewayCallback(value: URL): boolean {
  return value.protocol === 'https:' && value.username === '' && value.password === '' &&
    value.port === '' && value.pathname === CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH && value.search === '' &&
    value.hash === '' && value.hostname === value.hostname.toLowerCase() && value.hostname.includes('.');
}

function validAuthorizationUrl(
  value: string,
  expectedClientId: string,
  expectedChallenge: string,
): boolean {
  try {
    const url = new URL(value);
    const authorizeEndpoint = new URL(CLOUDFLARE_AUTHORIZE_ENDPOINT);
    const actualKeys = [...url.searchParams.keys()];
    const state = url.searchParams.get('state') ?? '';
    return url.origin === authorizeEndpoint.origin && url.pathname === authorizeEndpoint.pathname &&
      url.username === '' && url.password === '' && url.port === '' && url.hash === '' &&
      actualKeys.length === EXPECTED_AUTHORIZATION_KEYS.length &&
      new Set(actualKeys).size === actualKeys.length &&
      EXPECTED_AUTHORIZATION_KEYS.every((key) => actualKeys.includes(key)) &&
      url.searchParams.get('response_type') === 'code' &&
      url.searchParams.get('client_id') === expectedClientId &&
      url.searchParams.get('redirect_uri') === CLOUDFLARE_CODE_RELAY_CALLBACK &&
      url.searchParams.get('scope') === exactOperationScopes('install').join(' ') &&
      url.searchParams.get('code_challenge') === expectedChallenge &&
      url.searchParams.get('code_challenge_method') === 'S256' &&
      state.length <= 8_192 && SEALED_RELAY_STATE.test(state);
  } catch {
    return false;
  }
}

/** Calls the code-only relay from the customer Worker; no Cloudflare token is involved. */
export async function beginCustomerBootstrapRelay(input: {
  readonly publicClientId: string;
  readonly relayTicket: string;
  readonly gatewayState: string;
  readonly pkceChallenge: string;
  readonly gatewayCallback: string;
  readonly transport: CustomerCloudflareTransport;
}): Promise<CustomerBootstrapRelayStart> {
  if (!CLIENT_ID.test(input.publicClientId) || input.relayTicket.length < 40 ||
      input.relayTicket.length > 4096 || !RELAY_TICKET.test(input.relayTicket) ||
      !TOKEN.test(input.gatewayState) || !TOKEN.test(input.pkceChallenge)) throw new Error('relay_rejected');
  let callback: URL;
  try {
    callback = new URL(input.gatewayCallback);
  } catch {
    throw new Error('relay_rejected');
  }
  if (!validGatewayCallback(callback)) throw new Error('relay_rejected');

  const response = await withDeadline((signal) => input.transport(
    `${CLOUDFLARE_CODE_RELAY_ORIGIN}/oauth/start/install`,
    {
      method: 'POST',
      headers: { accept: 'application/json', 'content-type': 'application/json' },
      body: JSON.stringify({
        relayTicket: input.relayTicket,
        gatewayState: input.gatewayState,
        pkceChallenge: input.pkceChallenge,
        gatewayCallback: callback.toString(),
      }),
      redirect: 'manual',
      signal,
    },
  ), 'oauth_exchange_failed');
  if (response.redirected || response.status !== 200 ||
      !applicationJson(response.headers.get('content-type'))) {
    await response.body?.cancel();
    throw new Error('relay_rejected');
  }
  let parsed: v.InferOutput<typeof responseSchema>;
  try {
    parsed = v.parse(responseSchema, JSON.parse(await readBoundedText(
      response,
      'oauth_exchange_failed',
      MAX_RESPONSE_BYTES,
    )));
  } catch {
    throw new Error('relay_rejected');
  }
  if (!validAuthorizationUrl(parsed.authorizationUrl, input.publicClientId, input.pkceChallenge)) {
    throw new Error('relay_rejected');
  }
  return Object.freeze({ authorizationUrl: parsed.authorizationUrl });
}
