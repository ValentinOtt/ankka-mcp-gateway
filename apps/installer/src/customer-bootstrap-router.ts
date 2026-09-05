import * as v from 'valibot';

import { boundaryObjectSchema } from './boundary';
import { parseDeploySelection, type DeploySelection } from './schema';
import type { CustomerWorkerSetupPublicState } from './customer-worker-setup';
import { DeployError } from './errors';

import { CLOUDFLARE_CODE_RELAY_CALLBACK } from './cloudflare-code-relay';
import {
  exactOperationScopes,
  type CustomerCloudflareOperation,
} from './cloudflare-operation-authority';
import {
  authenticatedSession,
  consumeCustomerBootstrapCapability,
  initialCustomerBootstrapState,
  parseCustomerBootstrapState,
  publicCustomerBootstrapStatus,
  rejectCustomerBootstrapOauthCallback,
  rejectCustomerBootstrapOauthStart,
  startCustomerBootstrapOauth,
  CustomerBootstrapStateError,
  type BootstrapRandomBytes,
  type CustomerBootstrapState,
} from './customer-bootstrap-state';
import {
  beginCustomerBootstrapCallback,
  type CustomerBootstrapCallbackFailureCode,
} from './customer-bootstrap-callback';
import type {
  CustomerCloudflareTransport,
  EphemeralCustomerCloudflareGrant,
} from './customer-cloudflare-grant';
import {
  CUSTOMER_INSTALL_CONTINUE_PATH,
  CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH,
  CUSTOMER_INSTALL_OAUTH_START_PATH,
  CUSTOMER_INSTALL_STATUS_PATH,
} from './customer-install-paths';

const SESSION_COOKIE = '__Host-ankka_bootstrap_session';
const PKCE_COOKIE = '__Host-ankka_bootstrap_pkce';
const ATTEMPT_ID = /^attempt_[A-Za-z0-9_-]{24}$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const AUTHORIZATION_CODE = /^[A-Za-z0-9._~-]{8,4096}$/u;
const MAX_BODY_BYTES = 128 * 1024;
const MAX_HANDOFF_BYTES = 60 * 1024;

export interface CustomerBootstrapStatePort {
  read(): Promise<CustomerBootstrapState | null | undefined>;
  /** Atomically writes only when the stored revision still matches. */
  compareAndSet(
    expectedRevision: number | null,
    state: CustomerBootstrapState,
  ): Promise<boolean>;
}

export interface CustomerBootstrapRelayStart {
  readonly authorizationUrl: string;
}

export interface CustomerBootstrapRouterDependencies {
  readonly acceptSetup?: (permit: string) => Promise<void>;
  readonly readSetup?: () => Promise<CustomerWorkerSetupPublicState>;
  readonly configureSetup?: (selection: DeploySelection) => Promise<CustomerWorkerSetupPublicState>;
  readonly now?: () => number;
  readonly randomBytes?: BootstrapRandomBytes;
  readonly state: CustomerBootstrapStatePort;
  readonly transport: CustomerCloudflareTransport;
  /**
   * Verifies and adopts the exact deploy-signed Worker/namespace handoff and
   * ownership certificate. It must be idempotent for byte-identical evidence.
   */
  readonly acceptHandoff: (input: {
    readonly serializedHandoff: string;
    readonly serializedPlan: string;
    readonly ownershipCertificate: string;
  }) => Promise<void>;
  /**
   * Proves possession of the customer-owned key to auth.ankka.ai and returns
   * one fresh, fixed install ticket. The ticket never enters durable state or
   * a browser cookie.
   */
  readonly issueRelayTicket: () => Promise<{
    readonly relayTicket: string;
    readonly expiresAt: number;
  }>;
  /**
   * Calls auth.ankka.ai with the Stage 1 signed gateway attestation. The input
   * deliberately has no operation or scope field: this route is always install.
   */
  readonly beginRelay: (input: {
    readonly gatewayState: string;
    readonly pkceChallenge: string;
    readonly gatewayCallback: string;
    readonly relayTicket: string;
  }) => Promise<CustomerBootstrapRelayStart>;
  /**
   * Takes the exchanged, account-checked grant into memory and arranges the
   * converger passes. It returns once the passes are arranged, or once they
   * have run when the host can run them inline.
   */
  readonly startConvergence: (input: {
    readonly attemptId: string;
    readonly grant: EphemeralCustomerCloudflareGrant;
  }) => Promise<void>;
  /** Renders the callback outcome for a browser; JSON when absent. */
  readonly callbackResponse?: (
    outcome: CustomerBootstrapCallbackOutcome,
    cookies: readonly string[],
  ) => Response;
}

export interface CustomerBootstrapCallbackOutcome {
  readonly status: 'READY' | 'INCOMPLETE' | 'CONVERGING';
  readonly failureCode: CustomerBootstrapCallbackFailureCode | null;
  readonly failureReason: string | null;
}

export interface CustomerBootstrapRouterConfig {
  readonly accountId: string;
  readonly installId: string;
  readonly bootstrapId: string;
  readonly secretCommitment: string;
  readonly capabilityExpiresAt: number;
  readonly publicClientId: string;
}

const configSchema = v.strictObject({
  accountId: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
  installId: v.pipe(v.string(), v.regex(/^acg-[a-f0-9]{24}$/u)),
  bootstrapId: v.pipe(v.string(), v.regex(/^boot_[A-Za-z0-9_-]{24}$/u)),
  secretCommitment: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  capabilityExpiresAt: v.pipe(v.number(), v.safeInteger()),
  publicClientId: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{16,128}$/u)),
});

function headers(contentType = 'application/json; charset=utf-8'): Headers {
  return new Headers({
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'content-type': contentType,
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  });
}

function json<Value>(
  value: Value,
  status = 200,
  cookies?: readonly string[],
): Response {
  const responseHeaders = headers();
  if (cookies !== undefined) {
    for (const cookie of cookies) {
      responseHeaders.append('set-cookie', cookie);
    }
  }
  return new Response(JSON.stringify(value), { status, headers: responseHeaders });
}

function notFound(): Response {
  return json({ schemaVersion: 1, error: 'not_found' }, 404);
}

function sessionCookie(value: string, expiresAt: number, now: number): string {
  const maxAge = Math.max(1, Math.floor((expiresAt - now) / 1000));
  return `${SESSION_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Lax`;
}

function pkceCookie(input: {
  readonly attemptId: string;
  readonly verifier: string;
  readonly expiresAt: number;
  readonly now: number;
}): string {
  const maxAge = Math.max(1, Math.floor((input.expiresAt - input.now) / 1000));
  const value = `${input.attemptId}.${input.expiresAt}.${input.verifier}`;
  return `${PKCE_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Lax`;
}

function clearPkceCookie(): string {
  return `${PKCE_COOKIE}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax`;
}

function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax`;
}

function readSessionCookie(request: Request): string | null {
  const raw = request.headers.get('cookie');
  if (raw === null || raw.length > 8192) return null;
  const values = raw.split(';').map((entry) => entry.trim()).filter((entry) =>
    entry.startsWith(`${SESSION_COOKIE}=`),
  );
  if (values.length !== 1) return null;
  const value = values[0]?.slice(SESSION_COOKIE.length + 1) ?? '';
  return TOKEN.test(value) ? value : null;
}

function readPkceCookie(request: Request, now: number): Readonly<{
  attemptId: string;
  verifier: string;
  expiresAt: number;
}> | null {
  const raw = request.headers.get('cookie');
  if (raw === null || raw.length > 8192 || !Number.isSafeInteger(now) || now < 0) return null;
  const values = raw.split(';').map((entry) => entry.trim()).filter((entry) =>
    entry.startsWith(`${PKCE_COOKIE}=`),
  );
  if (values.length !== 1) return null;
  const value = values[0]?.slice(PKCE_COOKIE.length + 1) ?? '';
  const parts = value.split('.');
  if (parts.length !== 3) return null;
  const [attemptId = '', serializedExpiresAt = '', verifier = ''] = parts;
  if (!ATTEMPT_ID.test(attemptId) || !/^\d{1,16}$/u.test(serializedExpiresAt) ||
      !TOKEN.test(verifier)) return null;
  const expiresAt = Number(serializedExpiresAt);
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= now) return null;
  return Object.freeze({ attemptId, verifier, expiresAt });
}

function sameOriginMutation(request: Request): boolean {
  const url = new URL(request.url);
  const origin = request.headers.get('origin');
  const fetchSite = request.headers.get('sec-fetch-site');
  return origin === url.origin && (fetchSite === null || fetchSite === 'same-origin') &&
    request.headers.get('content-type')?.toLowerCase().startsWith('application/json') === true;
}

async function smallJson<Schema extends v.GenericSchema>(
  request: Request,
  schema: Schema,
): Promise<v.InferOutput<Schema>> {
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) throw new Error('invalid');
  const serialized = await request.text();
  if (serialized.length > MAX_BODY_BYTES) throw new Error('invalid');
  return v.parse(schema, JSON.parse(serialized));
}

export function validCustomerBootstrapRelayAuthorization(
  value: CustomerBootstrapRelayStart,
  publicClientId: string,
  challenge: string,
  operation: CustomerCloudflareOperation = 'install',
): boolean {
  try {
    const url = new URL(value.authorizationUrl);
    const expectedScopes = exactOperationScopes(operation).join(' ');
    const expectedKeys = [
      'response_type', 'client_id', 'redirect_uri', 'scope', 'state',
      'code_challenge', 'code_challenge_method',
    ];
    const actualKeys = [...url.searchParams.keys()];
    const relayState = url.searchParams.get('state') ?? '';
    return url.origin === 'https://dash.cloudflare.com' && url.pathname === '/oauth2/auth' &&
      url.username === '' && url.password === '' && url.port === '' && url.hash === '' &&
      actualKeys.length === expectedKeys.length && new Set(actualKeys).size === actualKeys.length &&
      expectedKeys.every((key) => actualKeys.includes(key)) &&
      url.searchParams.get('response_type') === 'code' &&
      url.searchParams.get('client_id') === publicClientId &&
      url.searchParams.get('redirect_uri') === CLOUDFLARE_CODE_RELAY_CALLBACK &&
      url.searchParams.get('scope') === expectedScopes &&
      url.searchParams.get('code_challenge') === challenge &&
      url.searchParams.get('code_challenge_method') === 'S256' &&
      relayState.length <= 8192 && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/u.test(relayState);
  } catch {
    return false;
  }
}

export function createCustomerBootstrapRouter(
  rawConfig: CustomerBootstrapRouterConfig,
  dependencies: CustomerBootstrapRouterDependencies,
): Readonly<{ fetch(request: Request): Promise<Response> }> {
  const parsedConfig = v.safeParse(configSchema, rawConfig);
  if (!parsedConfig.success) throw new CustomerBootstrapStateError('invalid');
  const config = Object.freeze(parsedConfig.output);
  const now = dependencies.now ?? Date.now;

  const persistTransition = async (
    expected: CustomerBootstrapState,
    next: CustomerBootstrapState,
  ): Promise<void> => {
    if (next.revision !== expected.revision + 1 ||
        !await dependencies.state.compareAndSet(expected.revision, next)) {
      throw new CustomerBootstrapStateError('conflict');
    }
  };

  const readState = async (): Promise<CustomerBootstrapState> => {
    let stored = await dependencies.state.read();
    if (stored === undefined || stored === null) {
      const initial = initialCustomerBootstrapState({
        installId: config.installId,
        bootstrapId: config.bootstrapId,
        secretCommitment: config.secretCommitment,
        expiresAt: config.capabilityExpiresAt,
      });
      if (await dependencies.state.compareAndSet(null, initial)) return initial;
      stored = await dependencies.state.read();
    }
    const current = parseCustomerBootstrapState(stored);
    if (!current || current.installId !== config.installId || current.bootstrapId !== config.bootstrapId ||
        current.secretCommitment !== config.secretCommitment ||
        current.capabilityExpiresAt !== config.capabilityExpiresAt) {
      throw new CustomerBootstrapStateError('conflict');
    }
    return current;
  };

  return Object.freeze({
    async fetch(request: Request): Promise<Response> {
      let url: URL;
      try {
        url = new URL(request.url);
      } catch {
        return notFound();
      }
      if (url.protocol !== 'https:' || url.username !== '' || url.password !== '' || url.port !== '') {
        return notFound();
      }
      const isOauthCallback = request.method === 'GET' &&
        url.pathname === CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH;
      try {
        const current = await readState();
        if (request.method === 'GET' && url.pathname === CUSTOMER_INSTALL_STATUS_PATH) {
          return json(publicCustomerBootstrapStatus(current));
        }
        // READY is terminal. A clean release serves the final Gateway; this
        // restricted bootstrap version never reopens any setup endpoint.
        if (current.status === 'READY') {
          return isOauthCallback
            ? json(
              { schemaVersion: 1, error: 'not_found' },
              404,
              [clearPkceCookie(), clearSessionCookie()],
            )
            : notFound();
        }

        if (request.method === 'POST' && url.pathname === CUSTOMER_INSTALL_CONTINUE_PATH) {
          if (!sameOriginMutation(request)) return json({ schemaVersion: 1, error: 'forbidden' }, 403);
          const input = await smallJson(request, v.union([
            v.strictObject({
              bootstrapId: v.pipe(v.string(), v.regex(/^boot_[A-Za-z0-9_-]{24}$/u)),
              secret: v.pipe(v.string(), v.regex(TOKEN)),
              setupPermit: v.pipe(v.string(), v.minLength(1), v.maxLength(56 * 1024)),
            }),
            v.strictObject({
              bootstrapId: v.pipe(v.string(), v.regex(/^boot_[A-Za-z0-9_-]{24}$/u)),
              secret: v.pipe(v.string(), v.regex(TOKEN)),
              serializedHandoff: v.pipe(v.string(), v.minLength(1), v.maxLength(MAX_HANDOFF_BYTES)),
              serializedPlan: v.pipe(v.string(), v.minLength(1), v.maxLength(MAX_BODY_BYTES)),
              ownershipCertificate: v.pipe(v.string(), v.minLength(1), v.maxLength(MAX_HANDOFF_BYTES)),
            }),
          ]));
          const consumed = dependencies.randomBytes === undefined
            ? await consumeCustomerBootstrapCapability({
              current, bootstrapId: input.bootstrapId, secret: input.secret, now: now(),
            })
            : await consumeCustomerBootstrapCapability({
              current, bootstrapId: input.bootstrapId, secret: input.secret, now: now(),
              randomBytes: dependencies.randomBytes,
            });
          if ('setupPermit' in input) {
            if (dependencies.acceptSetup === undefined) throw new CustomerBootstrapStateError('invalid');
            await dependencies.acceptSetup(input.setupPermit);
          } else {
            await dependencies.acceptHandoff({
              serializedHandoff: input.serializedHandoff,
              serializedPlan: input.serializedPlan,
              ownershipCertificate: input.ownershipCertificate,
            });
          }
          await persistTransition(current, consumed.state);
          return json(
            { schemaVersion: 1, status: 'INCOMPLETE', next: CUSTOMER_INSTALL_OAUTH_START_PATH },
            200,
            [
              sessionCookie(consumed.sessionSecret, consumed.expiresAt, now()),
            ],
          );
        }

        if ((request.method === 'GET' && url.pathname === '/__ankka/install/setup') ||
            (request.method === 'POST' && url.pathname === '/__ankka/install/configuration')) {
          if (request.method === 'POST' && !sameOriginMutation(request)) return json({ error: 'forbidden' }, 403);
          const secret = readSessionCookie(request);
          if (secret === null) return json({ error: 'bootstrap_session_required' }, 403);
          await authenticatedSession(current, secret, now());
          if (current.oauth !== null || current.status !== 'INCOMPLETE') return json({ error: 'setup_locked' }, 409);
          if (request.method === 'GET' && dependencies.readSetup !== undefined) return json(await dependencies.readSetup());
          if (request.method === 'POST' && dependencies.configureSetup !== undefined) {
            return json(await dependencies.configureSetup(parseDeploySelection(await smallJson(request, boundaryObjectSchema))));
          }
          return notFound();
        }

        if (request.method === 'POST' && url.pathname === CUSTOMER_INSTALL_OAUTH_START_PATH) {
          if (!sameOriginMutation(request)) return json({ schemaVersion: 1, error: 'forbidden' }, 403);
          const sessionSecret = readSessionCookie(request);
          if (sessionSecret === null) return json({ schemaVersion: 1, error: 'bootstrap_session_required' }, 403);
          const startedAt = now();
          const started = dependencies.randomBytes === undefined
            ? await startCustomerBootstrapOauth({ current, sessionSecret, now: startedAt })
            : await startCustomerBootstrapOauth({
              current, sessionSecret, now: startedAt, randomBytes: dependencies.randomBytes,
            });
          await persistTransition(current, started.next);
          let relay: CustomerBootstrapRelayStart;
          try {
            const issued = await dependencies.issueRelayTicket();
            if (!Number.isSafeInteger(issued.expiresAt) || issued.expiresAt <= startedAt ||
                issued.relayTicket.length < 40 || issued.relayTicket.length > 4096 ||
                !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/u.test(issued.relayTicket)) {
              throw new Error('invalid');
            }
            relay = await dependencies.beginRelay({
              gatewayState: started.state,
              pkceChallenge: started.challenge,
              gatewayCallback: `${url.origin}${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`,
              relayTicket: issued.relayTicket,
            });
            if (!validCustomerBootstrapRelayAuthorization(
              relay,
              config.publicClientId,
              started.challenge,
            )) throw new Error('invalid');
          } catch {
            const rejected = rejectCustomerBootstrapOauthStart({
              current: started.next,
              attemptId: started.attemptId,
            });
            await persistTransition(started.next, rejected);
            return json(
              { schemaVersion: 1, error: 'authorization_unavailable' },
              503,
              [clearPkceCookie()],
            );
          }
          return json(
            { schemaVersion: 1, authorizationUrl: relay.authorizationUrl },
            200,
            [pkceCookie({
              attemptId: started.attemptId,
              verifier: started.verifier,
              expiresAt: started.expiresAt,
              now: startedAt,
            })],
          );
        }

        if (request.method === 'GET' && url.pathname === CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH) {
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
            await persistTransition(current, rejected);
            const cookies = [clearPkceCookie()];
            if (dependencies.callbackResponse !== undefined) {
              return dependencies.callbackResponse({
                status: 'INCOMPLETE', failureCode: 'authorization_rejected', failureReason: null,
              }, cookies);
            }
            return json({
              schemaVersion: 1,
              status: 'INCOMPLETE',
              failureCode: 'authorization_rejected',
            }, 200, cookies);
          }
          if (sessionSecret === null || !matchingAttempt || oauthError !== null ||
              !AUTHORIZATION_CODE.test(code) ||
              !TOKEN.test(oauthState) || url.searchParams.size !== 2) {
            return json(
              { schemaVersion: 1, error: 'oauth_callback_rejected' },
              400,
              [clearPkceCookie()],
            );
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
            persist: persistTransition,
          });
          let outcome: CustomerBootstrapCallbackOutcome;
          if (begun.status === 'CONVERGING') {
            await dependencies.startConvergence({ attemptId: begun.attemptId, grant: begun.grant });
            // The host may have run every pass inline; report what the
            // durable state says now rather than what began.
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
              failureReason: begun.failureReason ?? null,
            };
          }
          const cookies = outcome.status === 'READY'
            ? [clearPkceCookie(), clearSessionCookie()]
            : [clearPkceCookie()];
          return dependencies.callbackResponse?.(outcome, cookies) ??
            json({ schemaVersion: 1, ...outcome }, 200, cookies);
        }
        return notFound();
      } catch (error) {
        if (url.pathname === '/__ankka/install/configuration' && error instanceof DeployError &&
            error.code === 'bad_request' && error.status === 400) {
          return json({ error: 'invalid_configuration', reason: error.reason ?? 'selection_contract_invalid' }, 400);
        }
        const status = error instanceof CustomerBootstrapStateError && error.code === 'expired' ? 410 : 409;
        return json(
          { schemaVersion: 1, error: 'bootstrap_unavailable' },
          status,
          isOauthCallback ? [clearPkceCookie()] : undefined,
        );
      }
    },
  });
}
