import * as v from 'valibot';

import {
  beginCustomerBootstrapCallback,
  type CustomerBootstrapCallbackFailureCode,
} from './customer-bootstrap-callback';
import {
  type CustomerBootstrapRelayStart,
  type CustomerBootstrapStatePort,
  validCustomerBootstrapRelayAuthorization,
} from './customer-bootstrap-router';
import {
  createCustomerBootstrapRecoverySession,
  parseCustomerBootstrapState,
  rejectCustomerBootstrapOauthCallback,
  rejectCustomerBootstrapOauthStart,
  startCustomerBootstrapOauth,
  CustomerBootstrapStateError,
  type BootstrapRandomBytes,
  type CustomerBootstrapState,
} from './customer-bootstrap-state';
import type {
  CustomerCloudflareTransport,
  EphemeralCustomerCloudflareGrant,
} from './customer-cloudflare-grant';
import {
  CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH,
  CUSTOMER_INSTALL_OAUTH_START_PATH,
} from './customer-install-paths';

const SESSION_COOKIE = '__Host-ankka_bootstrap_session';
const PKCE_COOKIE = '__Host-ankka_bootstrap_pkce';
const ATTEMPT_ID = /^attempt_[A-Za-z0-9_-]{24}$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const AUTHORIZATION_CODE = /^[A-Za-z0-9._~-]{8,4096}$/u;
const RELAY_TICKET = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/u;
const MAX_COOKIE_BYTES = 8 * 1024;

const configSchema = v.strictObject({
  accountId: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
  installId: v.pipe(v.string(), v.regex(/^acg-[a-f0-9]{24}$/u)),
  publicClientId: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{16,128}$/u)),
  managementOrigin: v.pipe(v.string(), v.url()),
});

export interface CustomerStage2RecoveryRouterConfig {
  readonly accountId: string;
  readonly installId: string;
  readonly publicClientId: string;
  readonly managementOrigin: string;
}

export interface CustomerStage2RecoveryRouterDependencies {
  readonly state: CustomerBootstrapStatePort;
  readonly transport: CustomerCloudflareTransport;
  readonly assertRecoverable: () => Promise<void>;
  readonly issueRelayTicket: () => Promise<{
    readonly relayTicket: string;
    readonly expiresAt: number;
  }>;
  readonly beginRelay: (input: {
    readonly gatewayState: string;
    readonly pkceChallenge: string;
    readonly gatewayCallback: string;
    readonly relayTicket: string;
  }) => Promise<CustomerBootstrapRelayStart>;
  /**
   * Takes the exchanged, account-checked grant into memory and arranges the
   * converger passes, one alarm each, the way the bootstrap shell does; the
   * final runtime lives under the same per-invocation budget.
   */
  readonly startConvergence: (input: {
    readonly attemptId: string;
    readonly grant: EphemeralCustomerCloudflareGrant;
  }) => Promise<void>;
  /** Renders the callback outcome for a browser; JSON when absent. */
  readonly callbackResponse?: (
    outcome: CustomerStage2RecoveryOutcome,
    cookies: readonly string[],
  ) => Response;
  readonly now?: () => number;
  readonly randomBytes?: BootstrapRandomBytes;
}

export interface CustomerStage2RecoveryOutcome {
  readonly status: 'READY' | 'INCOMPLETE' | 'CONVERGING';
  readonly failureCode: CustomerBootstrapCallbackFailureCode | null;
  readonly failureReason: string | null;
}

function headers(): Headers {
  return new Headers({
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'content-type': 'application/json; charset=utf-8',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  });
}

function json<Value>(value: Value, status = 200, cookies: readonly string[] = []): Response {
  const responseHeaders = headers();
  for (const cookie of cookies) responseHeaders.append('set-cookie', cookie);
  return new Response(JSON.stringify(value), { status, headers: responseHeaders });
}

function notFound(): Response {
  return json({ schemaVersion: 1, error: 'not_found' }, 404);
}

function sessionCookie(value: string, expiresAt: number, now: number): string {
  const maxAge = Math.max(1, Math.floor((expiresAt - now) / 1_000));
  return `${SESSION_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Lax`;
}

function pkceCookie(input: {
  readonly attemptId: string;
  readonly verifier: string;
  readonly expiresAt: number;
  readonly now: number;
}): string {
  const maxAge = Math.max(1, Math.floor((input.expiresAt - input.now) / 1_000));
  return `${PKCE_COOKIE}=${input.attemptId}.${input.expiresAt}.${input.verifier}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Lax`;
}

function clearCookie(name: string): string {
  return `${name}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax`;
}

function oneCookie(request: Request, name: string): string | null {
  const raw = request.headers.get('cookie');
  if (raw === null || raw.length > MAX_COOKIE_BYTES) return null;
  const matches = raw.split(';').map((entry) => entry.trim()).filter((entry) =>
    entry.startsWith(`${name}=`));
  return matches.length === 1 ? matches[0]?.slice(name.length + 1) ?? null : null;
}

function readSessionCookie(request: Request): string | null {
  const value = oneCookie(request, SESSION_COOKIE);
  return value !== null && TOKEN.test(value) ? value : null;
}

function readPkceCookie(request: Request, now: number): Readonly<{
  attemptId: string;
  verifier: string;
  expiresAt: number;
}> | null {
  const value = oneCookie(request, PKCE_COOKIE);
  const parts = value?.split('.') ?? [];
  if (parts.length !== 3) return null;
  const [attemptId = '', serializedExpiresAt = '', verifier = ''] = parts;
  if (!ATTEMPT_ID.test(attemptId) || !/^\d{1,16}$/u.test(serializedExpiresAt) ||
      !TOKEN.test(verifier)) return null;
  const expiresAt = Number(serializedExpiresAt);
  return Number.isSafeInteger(expiresAt) && expiresAt > now
    ? Object.freeze({ attemptId, verifier, expiresAt })
    : null;
}

function sameOriginJsonMutation(request: Request, expectedOrigin: string): boolean {
  const url = new URL(request.url);
  const fetchSite = request.headers.get('sec-fetch-site');
  return url.origin === expectedOrigin && request.headers.get('origin') === expectedOrigin &&
    (fetchSite === null || fetchSite === 'same-origin') &&
    request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() ===
      'application/json';
}

async function emptyJsonBody(request: Request): Promise<boolean> {
  const declared = request.headers.get('content-length');
  if (declared !== null && (!/^\d{1,4}$/u.test(declared) || Number(declared) > 64)) return false;
  const body = await request.text();
  if (body.length > 64) return false;
  try {
    return v.safeParse(v.strictObject({}), JSON.parse(body)).success;
  } catch {
    return false;
  }
}

/**
 * Access-protected install recovery. It can mint only a browser session and a
 * fixed install OAuth attempt; Cloudflare authority still requires customer
 * key possession, fresh consent, direct exchange, and immediate revocation.
 */
export function createCustomerStage2RecoveryRouter(
  rawConfig: CustomerStage2RecoveryRouterConfig,
  dependencies: CustomerStage2RecoveryRouterDependencies,
): Readonly<{ fetch(request: Request): Promise<Response> }> {
  const parsed = v.safeParse(configSchema, rawConfig);
  if (!parsed.success) throw new CustomerBootstrapStateError('invalid');
  const config = Object.freeze(parsed.output);
  const management = new URL(config.managementOrigin);
  if (management.protocol !== 'https:' || management.username !== '' || management.password !== '' ||
      management.port !== '' || management.pathname !== '/' || management.search !== '' ||
      management.hash !== '' || management.hostname !== management.hostname.toLowerCase() ||
      !management.hostname.includes('.')) throw new CustomerBootstrapStateError('invalid');
  const now = dependencies.now ?? Date.now;

  const readState = async (): Promise<CustomerBootstrapState> => {
    const stored = await dependencies.state.read();
    const current = parseCustomerBootstrapState(stored);
    if (current === null || current.installId !== config.installId || current.capabilityUnused) {
      throw new CustomerBootstrapStateError('conflict');
    }
    return current;
  };

  const persist = async (expected: CustomerBootstrapState, next: CustomerBootstrapState) => {
    if (next.revision !== expected.revision + 1 ||
        !await dependencies.state.compareAndSet(expected.revision, next)) {
      throw new CustomerBootstrapStateError('conflict');
    }
  };

  return Object.freeze({
    async fetch(request: Request): Promise<Response> {
      let url: URL;
      try {
        url = new URL(request.url);
      } catch {
        return notFound();
      }
      if (url.origin !== config.managementOrigin || url.username !== '' || url.password !== '' ||
          url.port !== '' || url.hash !== '') return notFound();
      const isCallback = request.method === 'GET' &&
        url.pathname === CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH;
      try {
        await dependencies.assertRecoverable();
        const current = await readState();
        if (current.status === 'READY') {
          return isCallback
            ? json({ schemaVersion: 1, error: 'not_found' }, 404, [
              clearCookie(PKCE_COOKIE), clearCookie(SESSION_COOKIE),
            ])
            : notFound();
        }

        if (request.method === 'POST' && url.pathname === CUSTOMER_INSTALL_OAUTH_START_PATH &&
            url.search === '') {
          if (!sameOriginJsonMutation(request, config.managementOrigin) ||
              !await emptyJsonBody(request)) {
            return json({ schemaVersion: 1, error: 'forbidden' }, 403);
          }
          const startedAt = now();
          const session = dependencies.randomBytes === undefined
            ? await createCustomerBootstrapRecoverySession({ current, now: startedAt })
            : await createCustomerBootstrapRecoverySession({
              current, now: startedAt, randomBytes: dependencies.randomBytes,
            });
          await persist(current, session.state);
          const started = dependencies.randomBytes === undefined
            ? await startCustomerBootstrapOauth({
              current: session.state, sessionSecret: session.sessionSecret, now: startedAt,
            })
            : await startCustomerBootstrapOauth({
              current: session.state,
              sessionSecret: session.sessionSecret,
              now: startedAt,
              randomBytes: dependencies.randomBytes,
            });
          await persist(session.state, started.next);
          try {
            const ticket = await dependencies.issueRelayTicket();
            if (!Number.isSafeInteger(ticket.expiresAt) || ticket.expiresAt <= startedAt ||
                ticket.relayTicket.length > 4_096 || !RELAY_TICKET.test(ticket.relayTicket)) {
              throw new Error('invalid');
            }
            const relay = await dependencies.beginRelay({
              relayTicket: ticket.relayTicket,
              gatewayState: started.state,
              pkceChallenge: started.challenge,
              gatewayCallback: `${config.managementOrigin}${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`,
            });
            if (!validCustomerBootstrapRelayAuthorization(
              relay,
              config.publicClientId,
              started.challenge,
            )) throw new Error('invalid');
            return json({ schemaVersion: 1, authorizationUrl: relay.authorizationUrl }, 200, [
              sessionCookie(session.sessionSecret, session.expiresAt, startedAt),
              pkceCookie({
                attemptId: started.attemptId,
                verifier: started.verifier,
                expiresAt: started.expiresAt,
                now: startedAt,
              }),
            ]);
          } catch {
            await persist(started.next, rejectCustomerBootstrapOauthStart({
              current: started.next,
              attemptId: started.attemptId,
            }));
            return json({ schemaVersion: 1, error: 'authorization_unavailable' }, 503, [
              clearCookie(PKCE_COOKIE), clearCookie(SESSION_COOKIE),
            ]);
          }
        }

        if (isCallback) {
          const callbackAt = now();
          const sessionSecret = readSessionCookie(request);
          const pkce = readPkceCookie(request, callbackAt);
          const code = url.searchParams.get('code') ?? '';
          const oauthState = url.searchParams.get('state') ?? '';
          const oauthError = url.searchParams.get('error');
          const matchingAttempt = pkce !== null && current.oauth?.attemptId === pkce.attemptId &&
            current.oauth.expiresAt === pkce.expiresAt;
          if (sessionSecret !== null && matchingAttempt && oauthError === 'authorization_rejected' &&
              code === '' && TOKEN.test(oauthState) && url.searchParams.size === 2) {
            const rejected = await rejectCustomerBootstrapOauthCallback({
              current,
              sessionSecret,
              attemptId: pkce.attemptId,
              state: oauthState,
              now: callbackAt,
            });
            await persist(current, rejected);
            return json({
              schemaVersion: 1,
              status: 'INCOMPLETE',
              failureCode: 'authorization_rejected',
            }, 200, [clearCookie(PKCE_COOKIE), clearCookie(SESSION_COOKIE)]);
          }
          if (sessionSecret === null || !matchingAttempt || oauthError !== null ||
              !AUTHORIZATION_CODE.test(code) || !TOKEN.test(oauthState) ||
              url.searchParams.size !== 2) {
            return json({ schemaVersion: 1, error: 'oauth_callback_rejected' }, 400, [
              clearCookie(PKCE_COOKIE), clearCookie(SESSION_COOKIE),
            ]);
          }
          const begun = await beginCustomerBootstrapCallback({
            current,
            sessionSecret,
            attemptId: pkce.attemptId,
            verifier: pkce.verifier,
            oauthState,
            code,
            accountId: config.accountId,
            publicClientId: config.publicClientId,
            now: callbackAt,
            transport: dependencies.transport,
            persist,
          });
          let outcome: CustomerStage2RecoveryOutcome;
          if (begun.status === 'CONVERGING') {
            await dependencies.startConvergence({ attemptId: begun.attemptId, grant: begun.grant });
            // The host may have run every pass inline; report the durable state.
            const stored = await dependencies.state.read();
            const settled = (stored === undefined || stored === null ? null : parseCustomerBootstrapState(stored))
              ?? begun.state;
            outcome = {
              status: settled.status,
              failureCode: settled.failureCode,
              failureReason: settled.failureReason ?? null,
            };
          } else {
            outcome = {
              status: begun.status,
              failureCode: begun.failureCode,
              failureReason: begun.failureReason,
            };
          }
          const cookies = [clearCookie(PKCE_COOKIE), clearCookie(SESSION_COOKIE)];
          return dependencies.callbackResponse?.(outcome, cookies) ??
            json({ schemaVersion: 1, status: outcome.status, failureCode: outcome.failureCode }, 200, cookies);
        }
        return notFound();
      } catch (error) {
        const status = error instanceof CustomerBootstrapStateError && error.code === 'expired'
          ? 410
          : 409;
        return json({ schemaVersion: 1, error: 'recovery_unavailable' }, status,
          isCallback ? [clearCookie(PKCE_COOKIE), clearCookie(SESSION_COOKIE)] : []);
      }
    },
  });
}
