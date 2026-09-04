import * as v from 'valibot';

import { canonicalJson } from './canonical-json';
import type { CustomerCloudflareOperation } from './cloudflare-operation-authority';
import {
  base64UrlDecode,
  constantTimeEqual,
  pkceChallenge,
  randomBase64Url,
  sha256,
} from './crypto';
import {
  type CustomerBootstrapRelayStart,
  validCustomerBootstrapRelayAuthorization,
} from './customer-bootstrap-router';
import {
  CustomerCloudflareGrantError,
  exchangeCustomerCloudflareAuthorizationCode,
  verifyCustomerCloudflareGrantAccount,
  type CustomerCloudflareTransport,
  type EphemeralCustomerCloudflareGrant,
} from './customer-cloudflare-grant';
import {
  CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH,
  CUSTOMER_OPERATION_OAUTH_START_PATH,
  CUSTOMER_OPERATION_ROOT_PATH,
} from './customer-install-paths';
import { operationSignature } from './customer-operation-secrets';
import type { CustomerRuntimeUpdateTarget } from './customer-runtime-update';

/**
 * Gateway-local authorization for a later operation.
 *
 * The dashboard prepares a source installation or a runtime update inside the
 * gateway and hands the browser a same-origin fragment carrying the one-time
 * action key. This router turns that handoff into a fresh Cloudflare consent
 * for exactly the operation's scopes, using the public client and callback
 * the ownership trust certified for the install, then runs the operation with
 * the request-local grant and revokes it. Nothing about the grant, the PKCE
 * verifier, or the action key is written to durable storage: the verifier and
 * the key ride in one HttpOnly cookie, the attempt record keeps only hashes,
 * identifiers, and expiries.
 */
export const CUSTOMER_OPERATION_COOKIE = '__Host-ankka_operation';
export const CUSTOMER_OPERATION_ATTEMPT_TTL_MS = 10 * 60 * 1_000;
/** A prepared action lives ten minutes on the gateway's clock; allow a little skew when reading it. */
const MAX_ACTION_LIFETIME_MS = 11 * 60 * 1_000;
const CLOCK_SKEW_MS = 30 * 1_000;

const ATTEMPT_ID = /^attempt_[A-Za-z0-9_-]{24}$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const ACTION_ID = /^action_[A-Za-z0-9_-]{32}$/u;
const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const AUTHORIZATION_CODE = /^[A-Za-z0-9._~-]{8,4096}$/u;
const RELAY_TICKET = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/u;
const HANDOFF = /^[A-Za-z0-9_-]{40,8192}$/u;
const EMAIL = /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const RELEASE = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const KEY_ID = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u;
const ARTIFACT_SHA256 = /^[a-f0-9]{64}$/u;
const PREFIXED_SHA256 = /^sha256:[a-f0-9]{64}$/u;
const VERSION_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const MAX_COOKIE_BYTES = 8 * 1024;
const MAX_BODY_BYTES = 16 * 1024;
const MAX_APPLY_RESPONSE_BYTES = 64 * 1024;

const configSchema = v.strictObject({
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  installId: v.pipe(v.string(), v.regex(/^acg-[a-f0-9]{24}$/u)),
  publicClientId: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{16,128}$/u)),
  managementOrigin: v.pipe(v.string(), v.url()),
  workerName: v.pipe(v.string(), v.regex(WORKER_NAME)),
  workersSubdomain: v.pipe(v.string(), v.regex(DNS_LABEL)),
  release: v.pipe(v.string(), v.regex(RELEASE)),
  artifactSha256: v.pipe(v.string(), v.regex(ARTIFACT_SHA256)),
});

/** The exact release identity the gateway wrote into a source handoff. */
const releaseIdentitySchema = v.strictObject({
  schemaVersion: v.literal(1),
  channel: v.picklist(['canary', 'stable']),
  controlPlaneOrigin: v.pipe(v.string(), v.url()),
  release: v.pipe(v.string(), v.regex(RELEASE)),
  keyId: v.pipe(v.string(), v.regex(KEY_ID)),
  publicKey: v.pipe(v.string(), v.regex(TOKEN)),
  artifactSha256: v.pipe(v.string(), v.regex(ARTIFACT_SHA256)),
});

const commonClaimEntries = {
  actionId: v.pipe(v.string(), v.regex(ACTION_ID)),
  actionKey: v.pipe(v.string(), v.regex(TOKEN)),
  actorEmail: v.pipe(v.string(), v.maxLength(256), v.regex(EMAIL)),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  controlPlaneOrigin: v.pipe(v.string(), v.url()),
  workerName: v.pipe(v.string(), v.regex(WORKER_NAME)),
  workersSubdomain: v.pipe(v.string(), v.regex(DNS_LABEL)),
  managementOrigin: v.pipe(v.string(), v.url()),
  expiresAt: v.pipe(v.number(), v.safeInteger()),
};

/** A source installation handoff, exactly as the gateway's prepare route builds it. */
const sourceActionClaimSchema = v.strictObject({
  schemaVersion: v.literal(1),
  ...commonClaimEntries,
  releaseIdentity: releaseIdentitySchema,
});

const runtimeVersionSchema = v.strictObject({
  release: v.pipe(v.string(), v.regex(RELEASE)),
  artifactSha256: v.pipe(v.string(), v.regex(PREFIXED_SHA256)),
  versionId: v.union([v.pipe(v.string(), v.regex(VERSION_ID)), v.null()]),
});

/** A runtime update handoff, exactly as the gateway's update prepare route builds it. */
const runtimeActionClaimSchema = v.strictObject({
  schemaVersion: v.literal(2),
  actionType: v.literal('runtime_update'),
  ...commonClaimEntries,
  operation: v.picklist(['update', 'rollback']),
  from: runtimeVersionSchema,
  to: runtimeVersionSchema,
});

const startBodySchema = v.strictObject({
  schemaVersion: v.literal(1),
  handoff: v.pipe(v.string(), v.regex(HANDOFF)),
});

const appliedSchema = v.strictObject({
  schemaVersion: v.literal(1),
  actionId: v.pipe(v.string(), v.regex(ACTION_ID)),
  status: v.literal('succeeded'),
});

const targetSchema = v.strictObject({
  release: v.pipe(v.string(), v.regex(RELEASE)),
  artifactSha256: v.pipe(v.string(), v.regex(PREFIXED_SHA256)),
});

export const customerOperationAttemptSchema = v.strictObject({
  schemaVersion: v.literal(1),
  attemptId: v.pipe(v.string(), v.regex(ATTEMPT_ID)),
  kind: v.picklist(['source', 'runtime']),
  operation: v.picklist(['source-add', 'upgrade', 'rollback']),
  actionId: v.pipe(v.string(), v.regex(ACTION_ID)),
  actorEmail: v.pipe(v.string(), v.maxLength(256), v.regex(EMAIL)),
  actionExpiresAt: v.pipe(v.number(), v.safeInteger()),
  /** Where a runtime update fetches the signed bundle; as the gateway named it in the handoff. */
  controlPlaneOrigin: v.pipe(v.string(), v.url()),
  /** The runtime release to reach; null for a source installation. */
  target: v.union([targetSchema, v.null()]),
  stateHash: v.pipe(v.string(), v.regex(TOKEN)),
  phase: v.picklist(['authorizing', 'exchanging']),
  expiresAt: v.pipe(v.number(), v.safeInteger()),
});

export type CustomerOperationAttempt = v.InferOutput<typeof customerOperationAttemptSchema>;
type SourceActionClaim = v.InferOutput<typeof sourceActionClaimSchema>;
type RuntimeActionClaim = v.InferOutput<typeof runtimeActionClaimSchema>;
type DecodedClaim =
  | { readonly kind: 'source'; readonly claim: SourceActionClaim }
  | { readonly kind: 'runtime'; readonly claim: RuntimeActionClaim };

/** One attempt per gateway, durable so the callback can refuse replays. */
export interface CustomerOperationAttemptPort {
  read(): Promise<CustomerOperationAttempt | null>;
  write(attempt: CustomerOperationAttempt): Promise<void>;
  clear(): Promise<void>;
}

/** What the gateway's own action routes report about a prepared action. */
export interface CustomerOperationActionView {
  readonly status: string;
  readonly expiresAt: number;
}

export type CustomerOperationResult = 'applied' | 'failed' | 'denied' | 'revocation_unconfirmed';

export interface CustomerOperationRuntimeUpdateInput {
  readonly accessToken: string;
  readonly actionId: string;
  readonly actionKey: string;
  readonly actorEmail: string;
  readonly actionExpiresAt: number;
  readonly controlPlaneOrigin: string;
  readonly operation: 'update' | 'rollback';
  readonly target: CustomerRuntimeUpdateTarget;
}

export interface CustomerOperationRouterConfig {
  readonly accountId: string;
  readonly installId: string;
  readonly publicClientId: string;
  readonly managementOrigin: string;
  readonly workerName: string;
  readonly workersSubdomain: string;
  readonly release: string;
  readonly artifactSha256: string;
}

export interface CustomerOperationRouterDependencies {
  readonly attempts: CustomerOperationAttemptPort;
  readonly transport: CustomerCloudflareTransport;
  /** Throws unless the install is complete and the ownership trust names the callback. */
  readonly assertOperational: () => Promise<void>;
  readonly readSourceAction: (actionId: string) => Promise<CustomerOperationActionView | null>;
  readonly readRuntimeAction: (actionId: string) => Promise<CustomerOperationActionView | null>;
  readonly issueRelayTicket: (operation: CustomerCloudflareOperation) => Promise<{
    readonly relayTicket: string;
    readonly expiresAt: number;
  }>;
  readonly beginRelay: (input: {
    readonly operation: CustomerCloudflareOperation;
    readonly gatewayState: string;
    readonly pkceChallenge: string;
    readonly gatewayCallback: string;
    readonly relayTicket: string;
  }) => Promise<CustomerBootstrapRelayStart>;
  /** Submits the signed claim to the gateway's own apply route, in process. */
  readonly applySourceAction: (input: {
    readonly body: string;
    readonly signature: string;
  }) => Promise<Response>;
  /** Runs the gateway's own update with the grant; it hands over before the upload. */
  readonly runRuntimeUpdate: (input: CustomerOperationRuntimeUpdateInput) => Promise<CustomerOperationResult>;
  readonly now?: () => number;
}

function headers(contentType = 'application/json; charset=utf-8'): Headers {
  return new Headers({
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'content-type': contentType,
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

function operationCookie(input: {
  readonly attemptId: string;
  readonly expiresAt: number;
  readonly verifier: string;
  readonly actionKey: string;
  readonly now: number;
}): string {
  const maxAge = Math.max(1, Math.floor((input.expiresAt - input.now) / 1_000));
  return `${CUSTOMER_OPERATION_COOKIE}=${input.attemptId}.${input.expiresAt}.${input.verifier}.${input.actionKey}; Path=/; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Lax`;
}

function clearCookie(): string {
  return `${CUSTOMER_OPERATION_COOKIE}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax`;
}

function oneCookie(request: Request): string | null {
  const raw = request.headers.get('cookie');
  if (raw === null || raw.length > MAX_COOKIE_BYTES) return null;
  const matches = raw.split(';').map((entry) => entry.trim()).filter((entry) =>
    entry.startsWith(`${CUSTOMER_OPERATION_COOKIE}=`));
  return matches.length === 1 ? matches[0]?.slice(CUSTOMER_OPERATION_COOKIE.length + 1) ?? null : null;
}

/** True when the browser carries an operation attempt, which claims the shared callback. */
export function customerOperationCookiePresent(request: Request): boolean {
  return oneCookie(request) !== null;
}

function readOperationCookie(request: Request, now: number): Readonly<{
  attemptId: string;
  expiresAt: number;
  verifier: string;
  actionKey: string;
}> | null {
  const parts = oneCookie(request)?.split('.') ?? [];
  if (parts.length !== 4) return null;
  const [attemptId = '', serializedExpiresAt = '', verifier = '', actionKey = ''] = parts;
  if (!ATTEMPT_ID.test(attemptId) || !/^\d{1,16}$/u.test(serializedExpiresAt) ||
      !TOKEN.test(verifier) || !TOKEN.test(actionKey)) return null;
  const expiresAt = Number(serializedExpiresAt);
  return Number.isSafeInteger(expiresAt) && expiresAt > now
    ? Object.freeze({ attemptId, expiresAt, verifier, actionKey })
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

async function startBody(request: Request): Promise<v.InferOutput<typeof startBodySchema> | null> {
  const declared = request.headers.get('content-length');
  if (declared !== null && (!/^\d{1,6}$/u.test(declared) || Number(declared) > MAX_BODY_BYTES)) return null;
  const body = await request.text();
  if (body.length > MAX_BODY_BYTES) return null;
  try {
    const parsed = v.safeParse(startBodySchema, JSON.parse(body));
    return parsed.success ? parsed.output : null;
  } catch {
    return null;
  }
}

function decodeClaim(handoff: string): DecodedClaim | null {
  let decoded: v.InferInput<typeof startBodySchema> | null;
  try {
    decoded = JSON.parse(new TextDecoder().decode(base64UrlDecode(handoff)));
  } catch {
    return null;
  }
  const source = v.safeParse(sourceActionClaimSchema, decoded);
  if (source.success) return { kind: 'source', claim: source.output };
  const runtime = v.safeParse(runtimeActionClaimSchema, decoded);
  if (runtime.success) return { kind: 'runtime', claim: runtime.output };
  return null;
}

function claimMatches(
  decoded: DecodedClaim,
  config: v.InferOutput<typeof configSchema>,
  now: number,
): boolean {
  const { claim } = decoded;
  const identity = decoded.kind === 'source'
    ? decoded.claim.releaseIdentity.release === config.release &&
      decoded.claim.releaseIdentity.artifactSha256 === config.artifactSha256
    : decoded.claim.from.release === config.release &&
      decoded.claim.from.artifactSha256 === `sha256:${config.artifactSha256}` &&
      decoded.claim.to.release !== decoded.claim.from.release;
  return identity && claim.accountId === config.accountId && claim.managementOrigin === config.managementOrigin &&
    claim.workerName === config.workerName && claim.workersSubdomain === config.workersSubdomain &&
    claim.expiresAt > now && claim.expiresAt <= now + MAX_ACTION_LIFETIME_MS + CLOCK_SKEW_MS;
}

function relayOperation(decoded: DecodedClaim): 'source-add' | 'upgrade' | 'rollback' {
  if (decoded.kind === 'source') return 'source-add';
  return decoded.claim.operation === 'rollback' ? 'rollback' : 'upgrade';
}

/** A fixed, bounded word naming why an operation stopped; never provider text. */
export type CustomerOperationReason = string;
const REASON = /^[a-z][a-z0-9_]{0,120}$/u;

interface OperationOutcome {
  readonly result: CustomerOperationResult;
  readonly reason: CustomerOperationReason | null;
}

const rejectionSchema = v.looseObject({ error: v.pipe(v.string(), v.regex(REASON)) });

async function appliedOutcome(response: Response, actionId: string): Promise<OperationOutcome> {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d{1,7}$/u.test(declared) || Number(declared) > MAX_APPLY_RESPONSE_BYTES)) {
    await response.body?.cancel();
    return { result: 'failed', reason: `apply_http_${response.status}` };
  }
  let text: string;
  try {
    text = await response.text();
  } catch {
    return { result: 'failed', reason: `apply_http_${response.status}_unreadable` };
  }
  if (text.length > MAX_APPLY_RESPONSE_BYTES) return { result: 'failed', reason: `apply_http_${response.status}` };
  let body: v.InferInput<typeof appliedSchema> | null;
  try {
    body = JSON.parse(text);
  } catch {
    body = null;
  }
  if (response.status !== 200) {
    const rejection = v.safeParse(rejectionSchema, body);
    return {
      result: 'failed',
      reason: rejection.success ? `apply_${rejection.output.error}` : `apply_http_${response.status}`,
    };
  }
  const parsed = v.safeParse(appliedSchema, body);
  return parsed.success && parsed.output.actionId === actionId
    ? { result: 'applied', reason: null }
    : { result: 'failed', reason: 'apply_response_invalid' };
}

function failureReason<Thrown>(error: Thrown): CustomerOperationReason {
  if (error instanceof CustomerCloudflareGrantError) {
    return error.detail === null ? `grant_${error.code}` : `grant_${error.code}_${error.detail}`;
  }
  return 'unexpected';
}

function operationPage(): Response {
  const nonce = crypto.randomUUID().replaceAll('-', '');
  const pageHeaders = headers('text/html; charset=utf-8');
  pageHeaders.set('content-security-policy', `default-src 'none'; script-src 'nonce-${nonce}'; connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`);
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="referrer" content="no-referrer"><title>Authorize in Cloudflare</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:42rem;margin:5rem auto;padding:0 1.25rem;color:#171713}button{font:inherit;padding:.75rem 1rem}a{color:inherit}</style><h1>Authorize this change in Cloudflare</h1><p id="message">Preparing a fresh, temporary Cloudflare approval for your gateway…</p><button id="retry" hidden>Try again</button><p><a href="/sources">Back to the dashboard</a></p><script nonce="${nonce}">(()=>{const message=document.querySelector('#message');const retry=document.querySelector('#retry');const handoff=location.hash.slice(1);history.replaceState(null,'',location.pathname);const run=async()=>{retry.hidden=true;try{if(!/^[A-Za-z0-9_-]{40,8192}$/.test(handoff))throw new Error();const response=await fetch('${CUSTOMER_OPERATION_OAUTH_START_PATH}',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({schemaVersion:1,handoff}),credentials:'same-origin',cache:'no-store'});const value=await response.json();if(!response.ok||typeof value.authorizationUrl!=='string')throw new Error();location.replace(value.authorizationUrl)}catch{message.textContent='This authorization link could not be started. Go back to the dashboard, check the action status, and authorize again.';retry.hidden=false}};retry.addEventListener('click',run);run()})();</script></html>`, {
    status: 200,
    headers: pageHeaders,
  });
}

function redirectToDashboard(
  managementOrigin: string,
  attempt: CustomerOperationAttempt,
  outcome: OperationOutcome,
  cookies: readonly string[],
): Response {
  const location = attempt.kind === 'source'
    ? new URL('/sources', managementOrigin)
    : new URL('/settings', managementOrigin);
  const parameter = attempt.kind === 'source' ? 'sourceAction' : 'runtimeAction';
  location.searchParams.set(parameter, attempt.actionId);
  location.searchParams.set(`${parameter}Result`, outcome.result);
  if (outcome.reason !== null && REASON.test(outcome.reason)) {
    location.searchParams.set(`${parameter}Reason`, outcome.reason);
  }
  const responseHeaders = headers();
  responseHeaders.set('location', location.toString());
  for (const cookie of cookies) responseHeaders.append('set-cookie', cookie);
  return new Response(null, { status: 303, headers: responseHeaders });
}

export function createCustomerOperationRouter(
  rawConfig: CustomerOperationRouterConfig,
  dependencies: CustomerOperationRouterDependencies,
): Readonly<{ fetch(request: Request): Promise<Response> }> {
  const parsed = v.safeParse(configSchema, rawConfig);
  if (!parsed.success) throw new Error('operation_config_invalid');
  const config = Object.freeze(parsed.output);
  const management = new URL(config.managementOrigin);
  if (management.protocol !== 'https:' || management.username !== '' || management.password !== '' ||
      management.port !== '' || management.pathname !== '/' || management.search !== '' ||
      management.hash !== '' || management.hostname !== management.hostname.toLowerCase() ||
      !management.hostname.includes('.')) throw new Error('operation_config_invalid');
  const now = dependencies.now ?? Date.now;
  const gatewayCallback = `${config.managementOrigin}${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`;

  const start = async (request: Request): Promise<Response> => {
    if (!sameOriginJsonMutation(request, config.managementOrigin)) {
      return json({ schemaVersion: 1, error: 'forbidden' }, 403);
    }
    const body = await startBody(request);
    const decoded = body === null ? null : decodeClaim(body.handoff);
    const startedAt = now();
    if (decoded === null || !claimMatches(decoded, config, startedAt)) {
      return json({ schemaVersion: 1, error: 'operation_invalid' }, 400);
    }
    const { claim } = decoded;
    const action = decoded.kind === 'source'
      ? await dependencies.readSourceAction(claim.actionId)
      : await dependencies.readRuntimeAction(claim.actionId);
    if (action === null || action.status !== 'authorization_required' || action.expiresAt !== claim.expiresAt) {
      return json({ schemaVersion: 1, error: 'operation_conflict' }, 409);
    }
    const existing = await dependencies.attempts.read();
    if (existing !== null && existing.expiresAt > startedAt && existing.actionId !== claim.actionId) {
      return json({ schemaVersion: 1, error: 'operation_pending' }, 409);
    }
    const operation = relayOperation(decoded);
    const verifier = randomBase64Url(32);
    const state = randomBase64Url(32);
    const attemptId = `attempt_${randomBase64Url(18)}`;
    const expiresAt = Math.min(claim.expiresAt, startedAt + CUSTOMER_OPERATION_ATTEMPT_TTL_MS);
    await dependencies.attempts.write({
      schemaVersion: 1,
      attemptId,
      kind: decoded.kind,
      operation,
      actionId: claim.actionId,
      actorEmail: claim.actorEmail,
      actionExpiresAt: claim.expiresAt,
      controlPlaneOrigin: new URL(claim.controlPlaneOrigin).origin,
      target: decoded.kind === 'runtime'
        ? { release: decoded.claim.to.release, artifactSha256: decoded.claim.to.artifactSha256 }
        : null,
      stateHash: await sha256(state),
      phase: 'authorizing',
      expiresAt,
    });
    try {
      const ticket = await dependencies.issueRelayTicket(operation);
      if (!Number.isSafeInteger(ticket.expiresAt) || ticket.expiresAt <= startedAt ||
          ticket.relayTicket.length > 4_096 || !RELAY_TICKET.test(ticket.relayTicket)) {
        throw new Error('invalid');
      }
      const challenge = await pkceChallenge(verifier);
      const relay = await dependencies.beginRelay({
        operation,
        relayTicket: ticket.relayTicket,
        gatewayState: state,
        pkceChallenge: challenge,
        gatewayCallback,
      });
      if (!validCustomerBootstrapRelayAuthorization(relay, config.publicClientId, challenge, operation)) {
        throw new Error('invalid');
      }
      return json({ schemaVersion: 1, authorizationUrl: relay.authorizationUrl }, 200, [
        operationCookie({ attemptId, expiresAt, verifier, actionKey: claim.actionKey, now: startedAt }),
      ]);
    } catch {
      await dependencies.attempts.clear();
      return json({ schemaVersion: 1, error: 'authorization_unavailable' }, 503, [clearCookie()]);
    }
  };

  const applySource = async (
    attempt: CustomerOperationAttempt,
    actionKey: string,
    accessToken: string,
    at: number,
  ): Promise<OperationOutcome> => {
    const body = canonicalJson({
      schemaVersion: 1,
      actionId: attempt.actionId,
      actionKey,
      actorEmail: attempt.actorEmail,
      accountId: config.accountId,
      issuedAt: at,
      expiresAt: attempt.actionExpiresAt,
      cloudflareAccessToken: accessToken,
    });
    const response = await dependencies.applySourceAction({
      body,
      signature: await operationSignature(actionKey, body),
    });
    return appliedOutcome(response, attempt.actionId);
  };

  const callback = async (request: Request, url: URL): Promise<Response> => {
    const callbackAt = now();
    const cookies = [clearCookie()];
    const cookie = readOperationCookie(request, callbackAt);
    const attempt = await dependencies.attempts.read();
    const oauthState = url.searchParams.get('state') ?? '';
    if (cookie === null || attempt === null || attempt.attemptId !== cookie.attemptId ||
        attempt.expiresAt !== cookie.expiresAt || attempt.expiresAt <= callbackAt ||
        attempt.phase !== 'authorizing' || !TOKEN.test(oauthState) ||
        !constantTimeEqual(await sha256(oauthState), attempt.stateHash)) {
      return json({ schemaVersion: 1, error: 'oauth_callback_rejected' }, 400, cookies);
    }
    const code = url.searchParams.get('code') ?? '';
    const oauthError = url.searchParams.get('error');
    if (oauthError === 'authorization_rejected' && code === '' && url.searchParams.size === 2) {
      await dependencies.attempts.clear();
      return redirectToDashboard(config.managementOrigin, attempt, { result: 'denied', reason: null }, cookies);
    }
    if (oauthError !== null || !AUTHORIZATION_CODE.test(code) || url.searchParams.size !== 2) {
      return json({ schemaVersion: 1, error: 'oauth_callback_rejected' }, 400, cookies);
    }
    // The attempt is spent before the exchange: a replayed callback cannot exchange twice.
    await dependencies.attempts.write({ ...attempt, phase: 'exchanging' });
    let grant: EphemeralCustomerCloudflareGrant | null = null;
    let outcome: OperationOutcome;
    try {
      grant = await exchangeCustomerCloudflareAuthorizationCode({
        clientId: config.publicClientId,
        code,
        verifier: cookie.verifier,
        operation: attempt.operation,
        transport: dependencies.transport,
      });
      grant.assertUsable();
      outcome = await grant.withAccessToken(async (accessToken): Promise<OperationOutcome> => {
        await verifyCustomerCloudflareGrantAccount({
          accessToken,
          expectedAccountId: config.accountId,
          transport: dependencies.transport,
        });
        if (attempt.kind === 'source') return applySource(attempt, cookie.actionKey, accessToken, callbackAt);
        if (attempt.target === null || attempt.operation === 'source-add') {
          return { result: 'failed', reason: 'attempt_invalid' };
        }
        const result = await dependencies.runRuntimeUpdate({
          accessToken,
          actionId: attempt.actionId,
          actionKey: cookie.actionKey,
          actorEmail: attempt.actorEmail,
          actionExpiresAt: attempt.actionExpiresAt,
          controlPlaneOrigin: attempt.controlPlaneOrigin,
          operation: attempt.operation === 'rollback' ? 'rollback' : 'update',
          target: attempt.target,
        });
        return { result, reason: result === 'applied' ? null : 'update_failed' };
      });
    } catch (error) {
      outcome = { result: 'failed', reason: failureReason(error) };
    }
    if (grant !== null) {
      try {
        await grant.revoke({ clientId: config.publicClientId, transport: dependencies.transport });
      } catch {
        if (outcome.result === 'applied') outcome = { result: 'revocation_unconfirmed', reason: null };
      }
      grant.discard();
    }
    // A runtime update may have replaced this Worker by now; storage writes can be refused.
    try {
      await dependencies.attempts.clear();
    } catch {
      // The attempt record expires on its own; the new version finishes the journal.
    }
    return redirectToDashboard(config.managementOrigin, attempt, outcome, cookies);
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
      const isCallback = request.method === 'GET' && url.pathname === CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH;
      try {
        await dependencies.assertOperational();
      } catch {
        return json({ schemaVersion: 1, error: 'operation_unavailable' }, 503, isCallback ? [clearCookie()] : []);
      }
      if (request.method === 'GET' && url.pathname === CUSTOMER_OPERATION_ROOT_PATH && url.search === '') {
        return operationPage();
      }
      if (request.method === 'POST' && url.pathname === CUSTOMER_OPERATION_OAUTH_START_PATH && url.search === '') {
        return start(request);
      }
      if (isCallback) return callback(request, url);
      return notFound();
    },
  });
}
