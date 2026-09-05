import * as v from 'valibot';

import {
  buildFixedRelayAuthorization,
  CLOUDFLARE_CODE_RELAY_ORIGIN,
  CloudflareCodeRelayError,
  relayCloudflareAuthorizationCode,
  relayCloudflareAuthorizationError,
} from './cloudflare-code-relay';
import {
  verifyCloudflareGatewayRelayTicket,
  CloudflareGatewayRelayTicketError,
} from './cloudflare-gateway-relay-ticket';
import type { CustomerCloudflareOperation } from './cloudflare-operation-authority';

const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const MAX_BODY_BYTES = 8192;
const START_PATH = /^\/oauth\/start\/(install|upgrade|rollback|source-add|bigquery-add|source-update|source-remove|uninstall)$/u;

type RelayOperation = CustomerCloudflareOperation;

const startBodySchema = v.strictObject({
  relayTicket: v.pipe(v.string(), v.minLength(40), v.maxLength(4096)),
  gatewayState: v.pipe(v.string(), v.regex(TOKEN)),
  pkceChallenge: v.pipe(v.string(), v.regex(TOKEN)),
  gatewayCallback: v.pipe(v.string(), v.url()),
});

export interface CloudflareCodeRelayHttpConfig {
  readonly publicClientId: string;
  readonly relayStateKey: string;
  readonly relayTicketKey: string;
}

export interface CloudflareCodeRelayHttpDependencies {
  readonly now?: () => number;
}

type RelayHttpJson =
  | { readonly schemaVersion: 1; readonly authorizationUrl: string }
  | { readonly schemaVersion: 1; readonly error: 'not_found' | 'relay_rejected' };

function responseHeaders(contentType = 'application/json; charset=utf-8'): Headers {
  return new Headers({
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'content-type': contentType,
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  });
}

function json(value: RelayHttpJson, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: responseHeaders() });
}

function redirect(location: string): Response {
  const headers = responseHeaders('text/plain; charset=utf-8');
  headers.set('location', location);
  return new Response('Continue to your Ankka Gateway.', { status: 302, headers });
}

function notFound(): Response {
  return json({ schemaVersion: 1, error: 'not_found' }, 404);
}

function exactQuery(url: URL, keys: readonly string[]): boolean {
  const actual = [...url.searchParams.keys()];
  return actual.length === keys.length && new Set(actual).size === actual.length &&
    keys.every((key) => actual.includes(key));
}

function boundedErrorQuery(url: URL): boolean {
  const required = ['error', 'state'] as const;
  const allowed: ReadonlySet<string> = new Set([...required, 'error_description', 'error_uri']);
  const actual = [...url.searchParams.keys()];
  return actual.length >= required.length && actual.length <= allowed.size &&
    new Set(actual).size === actual.length &&
    required.every((key) => actual.includes(key)) && actual.every((key) => allowed.has(key));
}

function applicationJson(value: string | null): boolean {
  return value?.split(';', 1)[0]?.trim().toLowerCase() === 'application/json';
}

async function readStartBody(request: Request): Promise<v.InferOutput<typeof startBodySchema>> {
  if (!applicationJson(request.headers.get('content-type'))) {
    throw new CloudflareCodeRelayError('invalid');
  }
  const declared = request.headers.get('content-length');
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0 || length > MAX_BODY_BYTES) {
      throw new CloudflareCodeRelayError('invalid');
    }
  }
  const serialized = await request.text();
  if (serialized.length > MAX_BODY_BYTES) throw new CloudflareCodeRelayError('invalid');
  try {
    return v.parse(startBodySchema, JSON.parse(serialized));
  } catch {
    throw new CloudflareCodeRelayError('invalid');
  }
}

function operationFromPath(pathname: string): RelayOperation | null {
  const match = START_PATH.exec(pathname);
  const operation = match?.[1];
  return operation === 'install' || operation === 'upgrade' || operation === 'rollback' ||
    operation === 'source-add' || operation === 'bigquery-add' || operation === 'source-update' || operation === 'source-remove' ||
    operation === 'uninstall'
    ? operation
    : null;
}

/**
 * Minimal auth.ankka.ai HTTP surface. It can mint a fixed authorization URL
 * and relay an authorization code, but it has no token endpoint transport.
 */
export function createCloudflareCodeRelayHttpHandler(
  config: CloudflareCodeRelayHttpConfig,
  dependencies: CloudflareCodeRelayHttpDependencies = {},
): Readonly<{ fetch(request: Request): Promise<Response> }> {
  const now = dependencies.now ?? Date.now;
  return Object.freeze({
    async fetch(request: Request): Promise<Response> {
      let url: URL;
      try {
        url = new URL(request.url);
      } catch {
        return notFound();
      }
      if (url.origin !== CLOUDFLARE_CODE_RELAY_ORIGIN || url.username !== '' || url.password !== '' ||
          url.port !== '' || url.hash !== '') return notFound();

      try {
        const operation = operationFromPath(url.pathname);
        if (request.method === 'POST' && operation !== null && url.search === '') {
          const body = await readStartBody(request);
          const currentTime = now();
          const ticket = await verifyCloudflareGatewayRelayTicket({
            ticket: body.relayTicket,
            signingKey: config.relayTicketKey,
            expectedClientId: config.publicClientId,
            expectedOperation: operation,
            expectedGatewayCallback: body.gatewayCallback,
            now: currentTime,
          });
          const authorizationInput = {
            clientId: config.publicClientId,
            relayStateKey: config.relayStateKey,
            gateway: {
              accountId: ticket.accountId,
              installId: ticket.installId,
              callback: ticket.gatewayCallback,
            },
            operation,
            gatewayState: body.gatewayState,
            pkceChallenge: body.pkceChallenge,
            nonce: ticket.nonce,
            now: currentTime,
          };
          const authorization = await buildFixedRelayAuthorization(
            ticket.receiptResourceKinds === null
              ? authorizationInput
              : { ...authorizationInput, receiptResourceKinds: ticket.receiptResourceKinds },
          );
          return json({ schemaVersion: 1, authorizationUrl: authorization.authorizationUrl });
        }

        if (request.method === 'GET' && url.pathname === '/oauth/callback') {
          // Cloudflare may echo the granted scope on the code response; it is
          // checked against the sealed operation's ceiling and never forwarded.
          if (exactQuery(url, ['code', 'state']) || exactQuery(url, ['code', 'scope', 'state'])) {
            const code = url.searchParams.get('code');
            const state = url.searchParams.get('state');
            if (code === null || state === null) throw new CloudflareCodeRelayError('invalid');
            return redirect((await relayCloudflareAuthorizationCode({
              code,
              state,
              relayStateKey: config.relayStateKey,
              now: now(),
              echoedScope: url.searchParams.get('scope'),
            })).location);
          }
          if (boundedErrorQuery(url)) {
            const error = url.searchParams.get('error');
            const state = url.searchParams.get('state');
            if (error === null || state === null) throw new CloudflareCodeRelayError('invalid');
            return redirect((await relayCloudflareAuthorizationError({
              error,
              errorDescription: url.searchParams.get('error_description'),
              errorUri: url.searchParams.get('error_uri'),
              state,
              relayStateKey: config.relayStateKey,
              now: now(),
            })).location);
          }
          throw new CloudflareCodeRelayError('invalid');
        }
        return notFound();
      } catch (error) {
        const expired = error instanceof CloudflareCodeRelayError && error.code === 'expired' ||
          error instanceof CloudflareGatewayRelayTicketError && error.code === 'expired';
        return json({ schemaVersion: 1, error: 'relay_rejected' }, expired ? 410 : 400);
      }
    },
  });
}
