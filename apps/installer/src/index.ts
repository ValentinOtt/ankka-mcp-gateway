import * as v from 'valibot';

import {
  OAUTH_ATTEMPT_TTL_MS,
  OAUTH_CALLBACK_URL,
  PUBLIC_ORIGIN,
  SESSION_TTL_MS,
  DISCOVERY_OAUTH_SCOPES,
  REQUIRED_OAUTH_SCOPES,
} from './constants';
import {
  enforceAnonymousSessionRateLimit,
  enforceSessionReadRateLimit,
  enforceSessionMutationRateLimit,
  isAuthenticatedSessionId,
  mintAuthenticatedSessionId,
  type HostedAbuseControlPolicy,
} from './abuse-controls';
import {
  clearOauthCookie,
  clearSessionCookie,
  oauthCookie,
  readOauthCookie,
  readSessionId,
  sessionCookie,
} from './cookies';
import {
  openOauthCookie,
  base64UrlDecode,
  deriveCsrfToken,
  pkceChallenge,
  randomBase64Url,
  sealOauthCookie,
  sha256,
  type SealedOauthCookie,
} from './crypto';
import { GatewayDeploySession } from './durable/gateway-deploy-session';
import type {
  GatewayDeployEnv,
  GatewayDeploySessionStub,
} from './env';
import { DeployError, isDeployErrorCode, stableError, type DeployErrorCode } from './errors';
import {
  assertExactReleaseBundleIdentity,
  DisabledExactReleaseBundleProvider,
  exactReleaseBundleIdentitySchema,
  type ExactReleaseBundleIdentity,
  type ExactReleaseBundleProvider,
} from './exact-release-bundle';
import { deepFreezePlainData, isPlainDataTree } from './plain-data';
import {
  recordHostedInstallerAnalytics,
  type HostedInstallerAnalyticsOutcome,
  type HostedInstallerAnalyticsSink,
} from './hosted-installer-analytics';
import { DisabledInstallExecutor, type InstallExecutor } from './install-executor';
import { createInstallJournalPort } from './install-journal-port';
import {
  CustomerGatewayFreshPreflightError,
  type ExistingAnkkaGatewaySummary,
} from './cloudflare-gateway-fresh-preflight';
import {
  MAX_INSTALL_RECOVERY_RETENTION_MS,
  parsePublicInstallProgress,
  requireInstallJournal,
  type PublicInstallProgress,
} from './install-journal';
import {
  buildAuthorizationUrl,
  assertCloudflareOauthConfig,
  exchangeAuthorizationCode,
  type CloudflareOauthConfig,
  type EphemeralCloudflareGrant,
  type FetchTransport,
} from './oauth';
import {
  EnvironmentReleaseManifestProvider,
  type ReleaseBundleProvider,
  type VerifiedRelease,
  type VerifiedReleaseBundle,
} from './release';
import {
  buildStaticDeployPlan,
  parseDeploySelection,
  parseStaticDeployPlan,
  type DeploySelection,
  type StaticDeployPlan,
} from './schema';
import {
  resolveAuthorizedAccount,
  resolveAuthorizedTarget,
  type AuthorizedTargetResolutionInput,
} from './cloudflare-target';
import { relaySourceAction } from './source-action-relay';
import { buildPublicUpdateChannel } from './update-channel';
import { relayRuntimeUpdate } from './runtime-update-relay';
import {
  discoverCloudflareTargets,
  type CloudflareDiscoveryResult,
  type DiscoveredCloudflareTarget,
  type PublicCloudflareDiscovery,
} from './cloudflare-discovery';
import {
  DISABLED_INSTALLER_CAPABILITY_POLICY,
  installerSession,
  type InstallerCapabilityPolicy,
} from './installer-contract';
import {
  parsePublicDeployRecovery,
  parsePublicDeployResultRetention,
  type PublicDeployRecovery,
  type PublicDeployResultRetention,
  type PublicDeploySession,
} from './session';
import {
  parsePublicUninstallRecovery,
  parsePublicUninstallSession,
  type PublicUninstallRecovery,
  type PublicUninstallSession,
} from './uninstall-session';
import { createUninstallJournalPort } from './uninstall-journal-port';
import {
  DisabledUninstallExecutor,
  type UninstallExecutor,
} from './uninstall-executor';
import { buildStaticUninstallPlan } from './uninstall-plan';
import {
  parsePublicReturningUninstall,
  type PublicReturningUninstall,
} from './returning-uninstall-session';
import { parseReturningUninstallPlan } from './returning-uninstall-plan';
import {
  DisabledReturningUninstallExecutor,
  type ReturningUninstallExecutor,
} from './returning-uninstall-executor';
import { createReturningUninstallJournalPort } from './returning-uninstall-journal-port';

export { GatewayDeploySession };

export interface GatewayDeployExecutionContext {
  waitUntil(task: Promise<unknown>): void;
}

export interface InstallCallbackResponseInput {
  readonly request: Request;
  readonly env: GatewayDeployEnv;
  readonly context?: GatewayDeployExecutionContext;
  readonly execute: () => Promise<void>;
}

export type InstallCallbackResponse = (
  input: InstallCallbackResponseInput,
) => Promise<Response>;

export type ManagementCallbackResponse = InstallCallbackResponse;

export interface GatewayDeployWorkerDependencies {
  now?: () => number;
  abuseControlPolicy?: HostedAbuseControlPolicy;
  transport?: FetchTransport;
  releaseProvider?: ReleaseBundleProvider;
  exactReleaseProvider?: ExactReleaseBundleProvider;
  installExecutor?: InstallExecutor;
  uninstallExecutor?: UninstallExecutor;
  returningUninstallExecutor?: ReturningUninstallExecutor;
  capabilityPolicy?: InstallerCapabilityPolicy;
  installCallbackResponse?: InstallCallbackResponse;
  managementCallbackResponse?: ManagementCallbackResponse;
}

interface SessionContext {
  created: boolean;
  sessionId: string;
  csrfToken: string;
  stub: GatewayDeploySessionStub;
  publicSession: PublicDeploySession;
  installProgress: PublicInstallProgress | null;
  discovery: PublicCloudflareDiscovery;
  recovery: PublicDeployRecovery | null;
  uninstall: PublicUninstallSession | null;
  uninstallRecovery: PublicUninstallRecovery | null;
  returningUninstall: PublicReturningUninstall | null;
  sessionCookieMaxAgeSeconds: number | null;
}

const SECURITY_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  'cache-control': 'no-store',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'cross-origin-opener-policy': 'same-origin',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
});

function responseHeaders(contentType: string): Headers {
  const headers = new Headers(SECURITY_HEADERS);
  headers.set('content-type', contentType);
  return headers;
}

function json<Value>(value: Value, status = 200, cookies: readonly string[] = []): Response {
  const headers = responseHeaders('application/json; charset=utf-8');
  for (const cookie of cookies) headers.append('set-cookie', cookie);
  return new Response(JSON.stringify(value), { status, headers });
}

function errorResponse<ErrorInput>(error: ErrorInput, clearOauth = false): Response {
  const stable = stableError(error instanceof Error ? error : undefined);
  const response = json(
    stable.reason ? { code: stable.code, reason: stable.reason } : { code: stable.code },
    stable.status,
    clearOauth ? [clearOauthCookie()] : [],
  );
  if (stable.code === 'rate_limited') response.headers.set('retry-after', '60');
  return response;
}

function completionAnalyticsOutcome(
  code: string,
  successCode: string,
): HostedInstallerAnalyticsOutcome {
  if (code === successCode) return 'succeeded';
  if (code === 'oauth_denied') return 'denied';
  if (code === 'existing_gateway_detected') return 'existing_gateway';
  return 'failed';
}

function hostedInstallerAnalyticsSink(
  env: GatewayDeployEnv,
  request?: Request,
  sessionId?: string | null,
): HostedInstallerAnalyticsSink {
  const sink: HostedInstallerAnalyticsSink = {};
  if (env.HOSTED_INSTALLER_ANALYTICS !== undefined) {
    sink.dataset = env.HOSTED_INSTALLER_ANALYTICS;
  }
  if (env.HOSTED_INSTALLER_ANALYTICS_CHANNEL !== undefined) {
    sink.channel = env.HOSTED_INSTALLER_ANALYTICS_CHANNEL;
  }
  if (env.HOSTED_INSTALLER_ANALYTICS_RELEASE !== undefined) {
    sink.release = env.HOSTED_INSTALLER_ANALYTICS_RELEASE;
  }
  if (request !== undefined) {
    sink.session = analyticsSessionKey(sessionId ?? readSessionId(request));
    sink.country = analyticsCountry(request);
    sink.browser = analyticsBrowserFamily(request.headers.get('user-agent'));
    sink.referrer = analyticsReferrerHost(request);
  }
  return sink;
}

/**
 * Opaque per-session grouping key: a non-cryptographic digest of the session
 * identifier, so funnel rows group by session without carrying the session
 * credential itself.
 */
function analyticsSessionKey(sessionId: string | null): string {
  if (sessionId === null || sessionId === '') return 'none';
  let digest = 0xcbf29ce484222325n;
  for (let index = 0; index < sessionId.length; index += 1) {
    digest ^= BigInt(sessionId.charCodeAt(index));
    digest = (digest * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return digest.toString(16).padStart(16, '0');
}

function analyticsCountry(request: Request): string {
  const country = request.cf?.country;
  return v.is(v.string(), country) && /^[A-Z]{2}$/u.test(country) ? country : 'ZZ';
}

function analyticsBrowserFamily(userAgent: string | null): string {
  if (userAgent === null || userAgent === '') return 'none';
  if (/(?:firefox|fxios)\//iu.test(userAgent)) return 'firefox';
  if (/(?:chrome|chromium|crios|edg|opr)\//iu.test(userAgent)) return 'chromium';
  if (/safari\//iu.test(userAgent)) return 'safari';
  return 'other';
}

/**
 * External referrer hostname only: 'direct' without a Referer header, 'none'
 * for a same-host or unparseable value. Paths and queries are never read.
 */
function analyticsReferrerHost(request: Request): string {
  const referrer = request.headers.get('referer');
  if (referrer === null || referrer === '') return 'direct';
  try {
    const referrerHost = new URL(referrer).hostname.toLowerCase();
    if (referrerHost === new URL(request.url).hostname.toLowerCase()) return 'none';
    return /^[a-z0-9](?:[a-z0-9.-]{0,62})$/u.test(referrerHost) ? referrerHost : 'none';
  } catch {
    return 'none';
  }
}

async function internalCall<T>(stub: GatewayDeploySessionStub, path: string, init?: RequestInit): Promise<T> {
  const request = new Request(`https://gateway-deploy-session.invalid${path}`, init);
  const response = await stub.fetch(request);
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new DeployError(500, 'session_invalid');
  }
  if (!response.ok) {
    const code = internalErrorCode(body);
    throw new DeployError(response.status, code ?? 'session_invalid');
  }
  // SAFETY: This is a same-release private Durable Object RPC. Every caller
  // names the exact endpoint response contract, and public/untrusted nested
  // values are parsed by their domain parser immediately after this boundary.
  return body as T;
}

function internalErrorCode<Input>(input: Input): DeployErrorCode | null {
  const result = v.safeParse(v.object({
    error: v.optional(v.object({ code: v.optional(v.string()) })),
  }), input);
  const code = result.success ? result.output.error?.code : undefined;
  return isDeployErrorCode(code) ? code : null;
}

function sessionStub(env: GatewayDeployEnv, sessionId: string): GatewayDeploySessionStub {
  return env.GATEWAY_DEPLOY_SESSION.get(env.GATEWAY_DEPLOY_SESSION.idFromName(sessionId));
}

function persistentSessionCookieSeconds(): number {
  return Math.floor((SESSION_TTL_MS + MAX_INSTALL_RECOVERY_RETENTION_MS) / 1000);
}

function recoveryCookieSeconds(now: number, recoverUntil: number): number {
  return Math.max(1, Math.floor((recoverUntil - now) / 1000));
}

function randomUninstallCycleId(): string {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  return `uninstall-${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

async function readPublicSession(
  stub: GatewayDeploySessionStub,
  now: number,
): Promise<{
  session: PublicDeploySession;
  installProgress: PublicInstallProgress | null;
  discovery: PublicCloudflareDiscovery;
  recovery: PublicDeployRecovery | null;
  resultRetention: PublicDeployResultRetention | null;
  uninstall: PublicUninstallSession | null;
  uninstallRecovery: PublicUninstallRecovery | null;
  returningUninstall: PublicReturningUninstall | null;
}> {
  const body = await internalCall<{
    session: PublicDeploySession;
    installProgress: unknown;
    discovery: PublicCloudflareDiscovery;
    recovery: unknown;
    resultRetention: unknown;
    uninstall: unknown;
    uninstallRecovery: unknown;
    returningUninstall: unknown;
  }>(stub, '/public');
  const installProgress = parsePublicInstallProgress(body.installProgress);
  const recovery = parsePublicDeployRecovery(body.recovery);
  const resultRetention = parsePublicDeployResultRetention(body.resultRetention);
  const uninstall = await parsePublicUninstallSession(body.uninstall);
  const uninstallRecovery = parsePublicUninstallRecovery(body.uninstallRecovery);
  const returningUninstall = await parsePublicReturningUninstall(body.returningUninstall ?? null);
  if (recovery && (
    body.session.expiresAt > now ||
    recovery.recoverUntil <= now ||
    recovery.recoverUntil <= body.session.expiresAt ||
    recovery.recoverUntil > body.session.expiresAt + MAX_INSTALL_RECOVERY_RETENTION_MS
  )) throw new DeployError(500, 'session_invalid');
  if (resultRetention && (
    recovery !== null ||
    body.session.status !== 'succeeded' ||
    body.session.result?.code !== 'install_complete' ||
    body.session.expiresAt > now ||
    resultRetention.resultUntil <= now ||
    resultRetention.resultUntil <= body.session.expiresAt ||
    resultRetention.resultUntil > body.session.expiresAt + MAX_INSTALL_RECOVERY_RETENTION_MS
  )) throw new DeployError(500, 'session_invalid');
  if (uninstall && (
    body.session.status !== 'succeeded' || body.session.result?.code !== 'install_complete' ||
    body.session.result.installationId !== uninstall.plan.installationId ||
    uninstall.recoverUntil <= now || uninstall.recoverUntil > body.session.expiresAt + MAX_INSTALL_RECOVERY_RETENTION_MS ||
    (uninstall.status === 'removed' && uninstallRecovery !== null) ||
    (uninstallRecovery && uninstallRecovery.recoverUntil !== uninstall.recoverUntil)
  )) throw new DeployError(500, 'session_invalid');
  if (!uninstall && uninstallRecovery) throw new DeployError(500, 'session_invalid');
  if (returningUninstall && (
    body.session.status !== 'failed' || body.session.result?.code !== 'existing_gateway_detected' ||
    JSON.stringify(body.session.result.existingGateway) !== JSON.stringify(returningUninstall.plan.gateway) ||
    returningUninstall.recoverUntil <= returningUninstall.updatedAt ||
    returningUninstall.recoverUntil > body.session.expiresAt + MAX_INSTALL_RECOVERY_RETENTION_MS ||
    (returningUninstall.plan.expiresAt <= now &&
      returningUninstall.status !== 'removed' && returningUninstall.status !== 'failed')
  )) throw new DeployError(500, 'session_invalid');
  return {
    session: body.session,
    installProgress,
    discovery: body.discovery,
    recovery,
    resultRetention,
    uninstall,
    uninstallRecovery,
    returningUninstall,
  };
}

async function initializeSession(
  env: GatewayDeployEnv,
  sessionId: string,
  now: number,
): Promise<{ stub: GatewayDeploySessionStub; csrfToken: string; session: PublicDeploySession }> {
  const csrfToken = await deriveCsrfToken(env.DEPLOY_SESSION_ENCRYPTION_KEY, sessionId);
  const stub = sessionStub(env, sessionId);
  const initialized = await internalCall<{ session: PublicDeploySession }>(stub, '/initialize', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      csrfHash: await sha256(csrfToken),
      createdAt: now,
      expiresAt: now + SESSION_TTL_MS,
    }),
  });
  return { stub, csrfToken, session: initialized.session };
}

async function synchronizeSessionCsrf(stub: GatewayDeploySessionStub, csrfToken: string): Promise<void> {
  const synchronized = await internalCall<{ synchronized: true }>(stub, '/csrf/synchronize', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ csrfHash: await sha256(csrfToken) }),
  });
  if (synchronized.synchronized !== true) throw new DeployError(500, 'session_invalid');
}

async function sessionForGet(
  request: Request,
  env: GatewayDeployEnv,
  now: number,
  abuseControlPolicy: HostedAbuseControlPolicy,
  authenticatedExistingId: string | null,
): Promise<SessionContext> {
  const existingId = abuseControlPolicy === 'required'
    ? authenticatedExistingId
    : readSessionId(request);
  if (existingId) {
    const stub = sessionStub(env, existingId);
    try {
      const body = await readPublicSession(stub, now);
      const csrfToken = await deriveCsrfToken(env.DEPLOY_SESSION_ENCRYPTION_KEY, existingId);
      await synchronizeSessionCsrf(stub, csrfToken);
      if (body.session.expiresAt > now) {
        return {
          created: false,
          sessionId: existingId,
          csrfToken,
          stub,
          publicSession: body.session,
          installProgress: body.installProgress,
          discovery: body.discovery,
          recovery: null,
          uninstall: body.uninstall,
          uninstallRecovery: body.uninstallRecovery,
          returningUninstall: body.returningUninstall,
          sessionCookieMaxAgeSeconds: null,
        };
      }
      if (body.recovery) {
        return {
          created: false,
          sessionId: existingId,
          csrfToken,
          stub,
          publicSession: body.session,
          installProgress: body.installProgress,
          discovery: body.discovery,
          recovery: body.recovery,
          uninstall: body.uninstall,
          uninstallRecovery: body.uninstallRecovery,
          returningUninstall: body.returningUninstall,
          sessionCookieMaxAgeSeconds: recoveryCookieSeconds(now, body.recovery.recoverUntil),
        };
      }
      if (body.resultRetention) {
        return {
          created: false,
          sessionId: existingId,
          csrfToken,
          stub,
          publicSession: body.session,
          installProgress: body.installProgress,
          discovery: body.discovery,
          recovery: null,
          uninstall: body.uninstall,
          uninstallRecovery: body.uninstallRecovery,
          returningUninstall: body.returningUninstall,
          sessionCookieMaxAgeSeconds: recoveryCookieSeconds(now, body.resultRetention.resultUntil),
        };
      }
    } catch (error) {
      if (!(error instanceof DeployError) || error.code !== 'session_invalid') throw error;
    }
  }
  if (abuseControlPolicy === 'required') {
    await enforceAnonymousSessionRateLimit(request, env);
  }
  const sessionId = abuseControlPolicy === 'required'
    ? await mintAuthenticatedSessionId(env.DEPLOY_SESSION_ENCRYPTION_KEY)
    : randomBase64Url(32);
  const initialized = await initializeSession(env, sessionId, now);
  return {
    created: true,
    sessionId,
    csrfToken: initialized.csrfToken,
    stub: initialized.stub,
    publicSession: initialized.session,
    installProgress: null,
    discovery: {
      schemaVersion: 1, status: 'not_started', actorEmail: null, targets: [],
      selectedTargetIdHash: null, failureCode: null, grantRevocation: null, updatedAt: null,
    },
    recovery: null,
    uninstall: null,
    uninstallRecovery: null,
    returningUninstall: null,
    sessionCookieMaxAgeSeconds: persistentSessionCookieSeconds(),
  };
}

async function existingSession(
  request: Request,
  env: GatewayDeployEnv,
  now: number,
  allowRecovery = false,
): Promise<SessionContext> {
  const sessionId = readSessionId(request);
  if (!sessionId) throw new DeployError(401, 'session_invalid');
  const stub = sessionStub(env, sessionId);
  const body = await readPublicSession(stub, now);
  const returningRecovery = body.returningUninstall &&
    body.returningUninstall.status !== 'removed' && now < body.returningUninstall.recoverUntil;
  const recoveryDeadline = body.recovery?.recoverUntil ??
    (returningRecovery ? body.returningUninstall?.recoverUntil : undefined);
  if (body.session.expiresAt <= now && (!allowRecovery || (!body.recovery && !returningRecovery))) {
    throw new DeployError(410, 'session_expired');
  }
  return {
    created: false,
    sessionId,
    csrfToken: await deriveCsrfToken(env.DEPLOY_SESSION_ENCRYPTION_KEY, sessionId),
    stub,
    publicSession: body.session,
    installProgress: body.installProgress,
    discovery: body.discovery,
    recovery: body.recovery,
    uninstall: body.uninstall,
    uninstallRecovery: body.uninstallRecovery,
    returningUninstall: body.returningUninstall,
    sessionCookieMaxAgeSeconds: recoveryDeadline !== undefined
      ? recoveryCookieSeconds(now, recoveryDeadline)
      : null,
  };
}

async function retainedInstallationSession(
  request: Request,
  env: GatewayDeployEnv,
  now: number,
): Promise<SessionContext> {
  const sessionId = readSessionId(request);
  if (!sessionId) throw new DeployError(401, 'session_invalid');
  const stub = sessionStub(env, sessionId);
  const body = await readPublicSession(stub, now);
  if (body.session.status !== 'succeeded' || body.session.result?.code !== 'install_complete') {
    throw new DeployError(409, 'session_conflict');
  }
  const deadline = body.uninstall?.recoverUntil ?? body.resultRetention?.resultUntil ??
    body.session.expiresAt + MAX_INSTALL_RECOVERY_RETENTION_MS;
  if (!Number.isSafeInteger(deadline) || deadline <= now ||
    deadline > body.session.expiresAt + MAX_INSTALL_RECOVERY_RETENTION_MS) {
    throw new DeployError(410, 'session_expired');
  }
  return {
    created: false,
    sessionId,
    csrfToken: await deriveCsrfToken(env.DEPLOY_SESSION_ENCRYPTION_KEY, sessionId),
    stub,
    publicSession: body.session,
    installProgress: body.installProgress,
    discovery: body.discovery,
    recovery: null,
    uninstall: body.uninstall,
    uninstallRecovery: body.uninstallRecovery,
    returningUninstall: body.returningUninstall,
    sessionCookieMaxAgeSeconds: body.session.expiresAt <= now
      ? recoveryCookieSeconds(now, deadline)
      : null,
  };
}

function requireMutationBoundary(request: Request, requiresJson = true): void {
  if (request.headers.get('origin') !== PUBLIC_ORIGIN) throw new DeployError(403, 'origin_invalid');
  const fetchSite = request.headers.get('sec-fetch-site');
  if (fetchSite !== null && fetchSite !== 'same-origin') throw new DeployError(403, 'origin_invalid');
  if (requiresJson && !request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
    throw new DeployError(400, 'bad_request');
  }
}

async function readSelectionRequest(request: Request): Promise<DeploySelection> {
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > 16 * 1024) throw new DeployError(413, 'bad_request');
  let input: unknown;
  try {
    const text = await request.text();
    if (text.length > 16 * 1024) throw new DeployError(413, 'bad_request');
    input = JSON.parse(text);
  } catch (error) {
    if (error instanceof DeployError) throw error;
    throw new DeployError(400, 'bad_request');
  }
  return parseDeploySelection(input);
}

async function requireCsrf(request: Request): Promise<string> {
  const csrf = request.headers.get('x-csrf-token');
  if (!csrf || !/^[A-Za-z0-9_-]{43}$/u.test(csrf)) throw new DeployError(403, 'csrf_invalid');
  // The DO performs the authoritative constant-time hash comparison.
  return sha256(csrf);
}

function oauthConfig(env: GatewayDeployEnv): CloudflareOauthConfig {
  return {
    clientId: env.CLOUDFLARE_OAUTH_CLIENT_ID,
    clientSecret: env.CLOUDFLARE_OAUTH_CLIENT_SECRET,
  };
}

async function saveSelection(
  request: Request,
  env: GatewayDeployEnv,
  now: number,
  capabilityPolicy: InstallerCapabilityPolicy,
): Promise<Response> {
  requireMutationBoundary(request);
  const session = await existingSession(request, env, now);
  const firstConfiguration = session.publicSession.selection === null;
  const csrfHash = await requireCsrf(request);
  const selection = await readSelectionRequest(request);
  const targetIdHash = request.headers.get('x-cloudflare-target-hash');
  if (targetIdHash !== null && !/^sha256:[a-f0-9]{64}$/u.test(targetIdHash)) {
    throw new DeployError(400, 'bad_request');
  }
  const updated = await internalCall<{ session: PublicDeploySession }>(session.stub, '/selection', {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ csrfHash, selection, targetIdHash, now }),
  });
  if (firstConfiguration) {
    recordHostedInstallerAnalytics(
      hostedInstallerAnalyticsSink(env, request),
      'configuration_saved',
      'none',
      'fresh_install',
    );
  }
  return json(installerSession(updated.session, null, capabilityPolicy));
}

async function startCloudflareDiscovery(
  request: Request,
  env: GatewayDeployEnv,
  now: number,
): Promise<Response> {
  requireMutationBoundary(request);
  const session = await existingSession(request, env, now);
  const csrfHash = await requireCsrf(request);
  assertCloudflareOauthConfig(oauthConfig(env));
  const state = randomBase64Url(32);
  const verifier = randomBase64Url(32);
  const attemptId = `att_${randomBase64Url(24)}`;
  const expiresAt = Math.min(now + OAUTH_ATTEMPT_TTL_MS, session.publicSession.expiresAt);
  await internalCall<{ accepted: true }>(session.stub, '/discover/authorize', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      csrfHash,
      attemptId,
      stateHash: await sha256(state),
      verifierHash: await sha256(verifier),
      attemptExpiresAt: expiresAt,
      now,
    }),
  });
  const sealed = await sealOauthCookie(env.DEPLOY_SESSION_ENCRYPTION_KEY, {
    schemaVersion: 3,
    purpose: 'discover',
    sessionId: session.sessionId,
    attemptId,
    state,
    verifier,
    expiresAt,
  });
  const authorizationUrl = buildAuthorizationUrl({
    clientId: env.CLOUDFLARE_OAUTH_CLIENT_ID,
    state,
    challenge: await pkceChallenge(verifier),
    scopes: DISCOVERY_OAUTH_SCOPES,
  });
  recordHostedInstallerAnalytics(
    hostedInstallerAnalyticsSink(env, request),
    'discovery_authorization_created',
    'none',
    'none',
  );
  return json(
    { schemaVersion: 1, authorizationUrl, handoffUrl: oauthHandoffUrl(sealed) },
    200,
    [oauthCookie(sealed, Math.max(1, Math.floor((expiresAt - now) / 1000)))],
  );
}

async function previewPlan(
  request: Request,
  env: GatewayDeployEnv,
  releaseProvider: ReleaseBundleProvider,
  now: number,
  capabilityPolicy: InstallerCapabilityPolicy,
): Promise<Response> {
  requireMutationBoundary(request, false);
  const session = await existingSession(request, env, now, true);
  const firstPlan = session.publicSession.plan === null;
  const csrfHash = await requireCsrf(request);
  const release = await releaseProvider.loadVerifiedRelease(env);
  const planDeadline = session.recovery?.recoverUntil ?? session.publicSession.expiresAt;
  const updated = await internalCall<{ session: PublicDeploySession }>(
    session.stub,
    session.recovery ? '/install-journal/recovery-plan' : '/plan',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        csrfHash,
        releaseManifest: release.manifest,
        planExpiresAt: Math.min(now + OAUTH_ATTEMPT_TTL_MS, planDeadline),
        now,
      }),
    },
  );
  if (firstPlan) {
    recordHostedInstallerAnalytics(
      hostedInstallerAnalyticsSink(env, request),
      'install_plan_created',
      'none',
      'fresh_install',
    );
  }
  return json(installerSession(updated.session, session.recovery, capabilityPolicy));
}

async function readPlanApproval(
  request: Request,
  purpose: 'install' | 'uninstall' | 'returning-uninstall' = 'install',
): Promise<{ planId: string; planHash: string }> {
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > 2048) throw new DeployError(413, 'bad_request');
  let input: unknown;
  try {
    const text = await request.text();
    if (text.length > 2048) throw new DeployError(413, 'bad_request');
    input = JSON.parse(text);
  } catch (error) {
    if (error instanceof DeployError) throw error;
    throw new DeployError(400, 'bad_request');
  }
  if (!isPlainDataTree(input)) throw new DeployError(400, 'bad_request');
  const result = v.safeParse(v.strictObject({
    planId: v.string(),
    planHash: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  }), input);
  if (!result.success || !(purpose === 'install'
      ? /^plan-[a-f0-9]{24}$/u
      : purpose === 'uninstall'
        ? /^uninstall-plan-[a-f0-9]{24}$/u
        : /^returning-uninstall-plan-[a-f0-9]{24}$/u).test(result.output.planId)) {
    throw new DeployError(400, 'bad_request');
  }
  return result.output;
}

async function readUninstallPlanApproval(request: Request): Promise<{ planId: string; planHash: string }> {
  return readPlanApproval(request, 'uninstall');
}

async function readReturningUninstallPlanApproval(
  request: Request,
): Promise<{ planId: string; planHash: string }> {
  return readPlanApproval(request, 'returning-uninstall');
}

async function readOauthHandoff(request: Request): Promise<string> {
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > 8192) throw new DeployError(413, 'bad_request');
  let input: unknown;
  try {
    const text = await request.text();
    if (text.length > 8192) throw new DeployError(413, 'bad_request');
    input = JSON.parse(text);
  } catch (error) {
    if (error instanceof DeployError) throw error;
    throw new DeployError(400, 'bad_request');
  }
  if (!isPlainDataTree(input)) throw new DeployError(400, 'bad_request');
  const result = v.safeParse(handoffEnvelopeSchema, input);
  if (!result.success) throw new DeployError(400, 'bad_request');
  return result.output.handoff;
}

function oauthHandoffUrl(sealed: string): string {
  return `${PUBLIC_ORIGIN}/oauth/handoff#${sealed}`;
}

async function exchangeOauthHandoff(
  request: Request,
  env: GatewayDeployEnv,
  now: number,
): Promise<Response> {
  requireMutationBoundary(request);
  const handoff = await readOauthHandoff(request);
  const sealed = await openOauthCookie(env.DEPLOY_SESSION_ENCRYPTION_KEY, handoff);
  if (sealed.schemaVersion !== 3 || sealed.expiresAt <= now) {
    throw new DeployError(410, 'session_expired');
  }
  const state = await readPublicSession(sessionStub(env, sealed.sessionId), now);
  const deadline = sealed.purpose === 'install'
    ? state.recovery?.recoverUntil ?? state.session.expiresAt
    : sealed.purpose === 'discover'
      ? state.session.expiresAt
      : state.uninstall?.recoverUntil;
  const attemptIsCurrent = sealed.purpose === 'install'
    ? state.session.status === 'authorizing'
    : sealed.purpose === 'discover'
      ? state.discovery.status === 'authorizing'
      : state.session.status === 'succeeded' && state.uninstall?.status === 'authorizing';
  if (!attemptIsCurrent || !deadline || deadline <= now || sealed.expiresAt > deadline) {
    throw new DeployError(409, 'session_conflict');
  }
  const authorizationUrl = buildAuthorizationUrl({
    clientId: env.CLOUDFLARE_OAUTH_CLIENT_ID,
    state: sealed.state,
    challenge: await pkceChallenge(sealed.verifier),
    scopes: sealed.purpose === 'discover' ? DISCOVERY_OAUTH_SCOPES : REQUIRED_OAUTH_SCOPES,
  });
  const sessionMaxAgeSeconds = Math.max(1, Math.floor((deadline - now) / 1000));
  const oauthMaxAgeSeconds = Math.max(1, Math.floor((sealed.expiresAt - now) / 1000));
  return json(
    { schemaVersion: 1, authorizationUrl },
    200,
    [sessionCookie(sealed.sessionId, sessionMaxAgeSeconds), oauthCookie(handoff, oauthMaxAgeSeconds)],
  );
}

interface SourceManagementActionHandoff {
  readonly schemaVersion: 1;
  readonly actionId: string;
  readonly actionKey: string;
  readonly actorEmail: string;
  readonly accountId: string;
  readonly controlPlaneOrigin: string;
  readonly workerName: string;
  readonly workersSubdomain: string;
  readonly managementOrigin: string;
  readonly releaseIdentity: ExactReleaseBundleIdentity;
  readonly expiresAt: number;
}

interface RuntimeManagementActionHandoff {
  readonly schemaVersion: 2;
  readonly actionType: 'runtime_update';
  readonly actionId: string;
  readonly actionKey: string;
  readonly actorEmail: string;
  readonly accountId: string;
  readonly controlPlaneOrigin: string;
  readonly workerName: string;
  readonly workersSubdomain: string;
  readonly managementOrigin: string;
  readonly operation: 'update' | 'rollback';
  readonly from: { readonly release: string; readonly artifactSha256: string; readonly versionId: string | null };
  readonly to: { readonly release: string; readonly artifactSha256: string; readonly versionId: string | null };
  readonly expiresAt: number;
}

interface GatewayTeardownManagementActionHandoff {
  readonly schemaVersion: 3;
  readonly actionType: 'gateway_teardown';
  readonly actionId: string;
  readonly actionKey: string;
  readonly actorEmail: string;
  readonly accountId: string;
  readonly controlPlaneOrigin: string;
  readonly installationId: string;
  readonly gatewayName: string;
  readonly portalHostname: string;
  readonly workerName: string;
  readonly workersSubdomain: string;
  readonly managementOrigin: string;
  readonly expiresAt: number;
}

type ManagementActionHandoff = SourceManagementActionHandoff | RuntimeManagementActionHandoff |
  GatewayTeardownManagementActionHandoff;

function parseManagementOrigin(value: string): string | null {
  let url: URL;
  try { url = new URL(value); } catch { return null; }
  return url.protocol === 'https:' && url.username === '' && url.password === '' && url.port === '' &&
    url.pathname === '/' && url.search === '' && url.hash === '' ? url.origin : null;
}

function validGatewayName(value: string): boolean {
  return ![...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127 || '<>{}\\'.includes(character);
  });
}

const handoffEnvelopeSchema = v.strictObject({
  handoff: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{40,4096}$/u)),
});
const managementOriginSchema = v.pipe(v.string(), v.check((origin) => parseManagementOrigin(origin) !== null));
const managementActionSharedEntries = {
  actionId: v.pipe(v.string(), v.regex(/^action_[A-Za-z0-9_-]{32}$/u)),
  actionKey: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{43}$/u)),
  actorEmail: v.pipe(
    v.string(),
    v.regex(/^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u),
    v.check((email) => email === email.toLowerCase()),
  ),
  accountId: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
  controlPlaneOrigin: managementOriginSchema,
  workerName: v.pipe(v.string(), v.regex(/^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u)),
  workersSubdomain: v.pipe(v.string(), v.regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u)),
  managementOrigin: managementOriginSchema,
  expiresAt: v.pipe(v.number(), v.safeInteger()),
};
const runtimeVersionHandoffSchema = v.strictObject({
  release: v.pipe(v.string(), v.regex(/^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u)),
  artifactSha256: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  versionId: v.union([
    v.pipe(v.string(), v.regex(/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u)),
    v.null(),
  ]),
});
const sourceManagementActionHandoffSchema = v.strictObject({
  schemaVersion: v.literal(1),
  ...managementActionSharedEntries,
  releaseIdentity: exactReleaseBundleIdentitySchema,
});
const runtimeManagementActionHandoffSchema = v.strictObject({
  schemaVersion: v.literal(2),
  actionType: v.literal('runtime_update'),
  ...managementActionSharedEntries,
  operation: v.picklist(['update', 'rollback']),
  from: runtimeVersionHandoffSchema,
  to: runtimeVersionHandoffSchema,
});
const teardownManagementActionHandoffSchema = v.strictObject({
  schemaVersion: v.literal(3),
  actionType: v.literal('gateway_teardown'),
  ...managementActionSharedEntries,
  installationId: v.pipe(v.string(), v.regex(/^acg-[a-f0-9]{24}$/u)),
  gatewayName: v.pipe(v.string(), v.minLength(1), v.maxLength(128), v.check(validGatewayName)),
  portalHostname: v.pipe(v.string(), v.regex(
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/u,
  )),
});
const managementActionHandoffSchema = v.variant('schemaVersion', [
  sourceManagementActionHandoffSchema,
  runtimeManagementActionHandoffSchema,
  teardownManagementActionHandoffSchema,
]);

async function readManagementActionHandoff(request: Request, now: number): Promise<ManagementActionHandoff> {
  requireMutationBoundary(request);
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > 8192) throw new DeployError(413, 'bad_request');
  let envelopeInput: unknown;
  try {
    const serialized = await request.text();
    if (serialized.length > 8192) throw new DeployError(413, 'bad_request');
    envelopeInput = JSON.parse(serialized);
  } catch (error) {
    if (error instanceof DeployError) throw error;
    throw new DeployError(400, 'bad_request');
  }
  if (!isPlainDataTree(envelopeInput)) throw new DeployError(400, 'bad_request');
  const envelopeResult = v.safeParse(handoffEnvelopeSchema, envelopeInput);
  if (!envelopeResult.success) {
    throw new DeployError(400, 'bad_request');
  }
  let claimInput: unknown;
  try {
    const bytes = base64UrlDecode(envelopeResult.output.handoff);
    try { claimInput = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
    finally { bytes.fill(0); }
  } catch {
    throw new DeployError(400, 'bad_request');
  }
  if (!isPlainDataTree(claimInput)) throw new DeployError(400, 'bad_request');
  const claimResult = v.safeParse(managementActionHandoffSchema, claimInput);
  if (!claimResult.success) throw new DeployError(400, 'bad_request');
  const claim = claimResult.output;
  if (claim.controlPlaneOrigin !== PUBLIC_ORIGIN) throw new DeployError(400, 'bad_request');
  if (claim.schemaVersion === 1 && claim.releaseIdentity.controlPlaneOrigin !== claim.controlPlaneOrigin) {
    throw new DeployError(400, 'bad_request');
  }
  const managementOrigin = parseManagementOrigin(claim.managementOrigin);
  if (!managementOrigin || claim.expiresAt <= now || claim.expiresAt > now + OAUTH_ATTEMPT_TTL_MS) {
    throw new DeployError(400, 'bad_request');
  }
  return deepFreezePlainData({ ...claim, managementOrigin });
}

async function authorizeManagementAction(
  request: Request,
  env: GatewayDeployEnv,
  now: number,
): Promise<Response> {
  const claim = await readManagementActionHandoff(request, now);
  if (claim.schemaVersion === 3) {
    const session = await existingSession(request, env, now, true);
    const firstReturningRemovalPlan = session.returningUninstall === null;
    const existing = session.publicSession.result?.code === 'existing_gateway_detected'
      ? session.publicSession.result.existingGateway
      : null;
    const selected = session.discovery.targets.find(
      (target) => target.targetIdHash === session.discovery.selectedTargetIdHash,
    );
    if (!existing || session.publicSession.status !== 'failed' ||
      existing.installationId !== claim.installationId || existing.name !== claim.gatewayName ||
      existing.managementHostname !== new URL(claim.managementOrigin).hostname ||
      existing.portalHostname !== claim.portalHostname || existing.workerName !== claim.workerName ||
      session.discovery.actorEmail !== claim.actorEmail || !selected) {
      throw new DeployError(409, 'session_conflict');
    }
    const prepared = await internalCall<{ returningUninstall: PublicReturningUninstall }>(
      session.stub,
      '/returning-uninstall/plan',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          csrfHash: await sha256(session.csrfToken),
          action: {
            actionId: claim.actionId,
            actionKeyHash: await sha256(claim.actionKey),
            actorEmail: claim.actorEmail,
            accountId: claim.accountId,
            workerName: claim.workerName,
            workersSubdomain: claim.workersSubdomain,
            managementOrigin: claim.managementOrigin,
            expiresAt: claim.expiresAt,
          },
          planExpiresAt: claim.expiresAt,
          now,
        }),
      },
    );
    const sealed = await sealOauthCookie(env.DEPLOY_SESSION_ENCRYPTION_KEY, {
      schemaVersion: 6,
      purpose: 'gateway_teardown_review',
      sessionId: session.sessionId,
      expiresAt: claim.expiresAt,
      actionId: claim.actionId,
      actionKey: claim.actionKey,
      actorEmail: claim.actorEmail,
      accountId: claim.accountId,
      installationId: claim.installationId,
      gatewayName: claim.gatewayName,
      portalHostname: claim.portalHostname,
      workerName: claim.workerName,
      workersSubdomain: claim.workersSubdomain,
      managementOrigin: claim.managementOrigin,
    });
    if (firstReturningRemovalPlan) {
      recordHostedInstallerAnalytics(
        hostedInstallerAnalyticsSink(env, request),
        'removal_plan_created',
        'none',
        'returning_removal',
      );
    }
    return json(
      { schemaVersion: 1, reviewUrl: '/result', planId: prepared.returningUninstall.plan.planId },
      200,
      [oauthCookie(sealed, Math.max(1, Math.floor((claim.expiresAt - now) / 1000)))],
    );
  }
  assertCloudflareOauthConfig(oauthConfig(env));
  const state = randomBase64Url(32);
  const verifier = randomBase64Url(32);
  const sealed = await sealOauthCookie(env.DEPLOY_SESSION_ENCRYPTION_KEY, claim.schemaVersion === 2 ? {
    schemaVersion: 5,
    purpose: 'runtime_update',
    state,
    verifier,
    expiresAt: claim.expiresAt,
    actionId: claim.actionId,
    actionKey: claim.actionKey,
    actorEmail: claim.actorEmail,
    accountId: claim.accountId,
    workerName: claim.workerName,
    workersSubdomain: claim.workersSubdomain,
    managementOrigin: claim.managementOrigin,
    operation: claim.operation,
    from: claim.from,
    to: claim.to,
  } : {
    schemaVersion: 4,
    purpose: 'source_apply',
    state,
    verifier,
    expiresAt: claim.expiresAt,
    actionId: claim.actionId,
    actionKey: claim.actionKey,
    actorEmail: claim.actorEmail,
    accountId: claim.accountId,
    workerName: claim.workerName,
    workersSubdomain: claim.workersSubdomain,
    managementOrigin: claim.managementOrigin,
    releaseIdentity: claim.releaseIdentity,
  });
  const authorizationUrl = buildAuthorizationUrl({
    clientId: env.CLOUDFLARE_OAUTH_CLIENT_ID,
    state,
    challenge: await pkceChallenge(verifier),
  });
  return json(
    { schemaVersion: 1, authorizationUrl },
    200,
    [oauthCookie(sealed, Math.max(1, Math.floor((claim.expiresAt - now) / 1000)))],
  );
}

async function managementActionContext(request: Request, env: GatewayDeployEnv, now: number): Promise<Response> {
  const value = readOauthCookie(request);
  if (!value) throw new DeployError(404, 'session_invalid');
  const sealed = await openOauthCookie(env.DEPLOY_SESSION_ENCRYPTION_KEY, value);
  if (sealed.schemaVersion !== 9 || sealed.purpose !== 'management_action_result' || sealed.expiresAt <= now) {
    throw new DeployError(404, 'session_invalid');
  }
  const target = new URL(sealed.managementOrigin);
  target.searchParams.set(
    sealed.actionType === 'runtime_update' ? 'runtimeAction' : 'sourceAction',
    sealed.actionId,
  );
  return json(
    {
      schemaVersion: 1,
      actionId: sealed.actionId,
      managementUrl: target.toString(),
      expiresAt: new Date(sealed.expiresAt).toISOString(),
    },
    200,
    [clearOauthCookie()],
  );
}

function verifiedReleasePin(release: VerifiedRelease): Readonly<{
  verification: 'ed25519';
  keyId: string;
  release: string;
  artifactSha256: string;
}> {
  if (release.verification !== 'ed25519') throw new DeployError(503, 'release_invalid');
  return Object.freeze({
    verification: 'ed25519',
    keyId: release.keyId,
    release: release.manifest.release,
    artifactSha256: release.manifest.artifact.treeSha256,
  });
}

async function previewUninstallPlan(
  request: Request,
  env: GatewayDeployEnv,
  releaseProvider: ReleaseBundleProvider,
  now: number,
  capabilityPolicy: InstallerCapabilityPolicy,
): Promise<Response> {
  requireMutationBoundary(request, false);
  const session = await retainedInstallationSession(request, env, now);
  const firstRemovalPlan = session.uninstall === null;
  const csrfHash = await requireCsrf(request);
  const release = await releaseProvider.loadVerifiedRelease(env);
  const deadline = session.uninstall?.recoverUntil ??
    session.publicSession.expiresAt + MAX_INSTALL_RECOVERY_RETENTION_MS;
  const updated = await internalCall<{ uninstall: unknown }>(session.stub, '/uninstall/plan', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      csrfHash,
      releasePin: verifiedReleasePin(release),
      planExpiresAt: Math.min(now + OAUTH_ATTEMPT_TTL_MS, deadline),
      now,
    }),
  });
  const uninstall = await parsePublicUninstallSession(updated.uninstall);
  if (!uninstall) throw new DeployError(500, 'session_invalid');
  if (firstRemovalPlan) {
    recordHostedInstallerAnalytics(
      hostedInstallerAnalyticsSink(env, request),
      'removal_plan_created',
      'none',
      'same_session_removal',
    );
  }
  return json(installerSession(
    session.publicSession,
    null,
    capabilityPolicy,
    uninstall,
    session.uninstallRecovery,
  ));
}

async function startUninstall(
  request: Request,
  env: GatewayDeployEnv,
  releaseProvider: ReleaseBundleProvider,
  now: number,
  capabilityPolicy: InstallerCapabilityPolicy,
): Promise<Response> {
  requireMutationBoundary(request);
  if (!capabilityPolicy.uninstall) throw new DeployError(503, 'uninstall_mutations_disabled');
  const session = await retainedInstallationSession(request, env, now);
  const csrfHash = await requireCsrf(request);
  const approval = await readUninstallPlanApproval(request);
  const uninstall = session.uninstall;
  const approvedPlan = uninstall?.plan;
  if (!uninstall || !approvedPlan || approvedPlan.planId !== approval.planId ||
    approvedPlan.planHash !== approval.planHash || approvedPlan.expiresAt <= now) {
    throw new DeployError(409, 'session_conflict');
  }
  const release = await releaseProvider.loadVerifiedRelease(env);
  assertCloudflareOauthConfig(oauthConfig(env));
  const state = randomBase64Url(32);
  const verifier = randomBase64Url(32);
  const attemptId = `att_${randomBase64Url(24)}`;
  const expiresAt = Math.min(now + OAUTH_ATTEMPT_TTL_MS, approvedPlan.expiresAt, uninstall.recoverUntil);
  await internalCall<{ accepted: true }>(session.stub, '/uninstall/authorize', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      csrfHash,
      releasePin: verifiedReleasePin(release),
      approvedPlanId: approval.planId,
      approvedPlanHash: approval.planHash,
      attemptId,
      stateHash: await sha256(state),
      verifierHash: await sha256(verifier),
      attemptExpiresAt: expiresAt,
      now,
    }),
  });
  const sealed = await sealOauthCookie(env.DEPLOY_SESSION_ENCRYPTION_KEY, {
    schemaVersion: 3,
    purpose: 'uninstall',
    sessionId: session.sessionId,
    attemptId,
    state,
    verifier,
    expiresAt,
  });
  const authorizationUrl = buildAuthorizationUrl({
    clientId: env.CLOUDFLARE_OAUTH_CLIENT_ID,
    state,
    challenge: await pkceChallenge(verifier),
  });
  recordHostedInstallerAnalytics(
    hostedInstallerAnalyticsSink(env, request),
    'removal_authorization_created',
    'none',
    'same_session_removal',
  );
  return json(
    { schemaVersion: 1, authorizationUrl, handoffUrl: oauthHandoffUrl(sealed) },
    200,
    [oauthCookie(sealed, Math.max(1, Math.floor((expiresAt - now) / 1000)))],
  );
}

async function startReturningUninstall(
  request: Request,
  env: GatewayDeployEnv,
  now: number,
  capabilityPolicy: InstallerCapabilityPolicy,
): Promise<Response> {
  requireMutationBoundary(request);
  if (!capabilityPolicy.uninstall) throw new DeployError(503, 'uninstall_mutations_disabled');
  const session = await existingSession(request, env, now, true);
  const approval = await readReturningUninstallPlanApproval(request);
  const control = session.returningUninstall;
  const encryptedReview = readOauthCookie(request);
  if (!control || (control.status !== 'planned' && control.status !== 'failed') ||
    control.plan.planId !== approval.planId ||
    control.plan.planHash !== approval.planHash || control.plan.expiresAt <= now || !encryptedReview) {
    throw new DeployError(409, 'session_conflict');
  }
  const review = await openOauthCookie(env.DEPLOY_SESSION_ENCRYPTION_KEY, encryptedReview);
  if (review.schemaVersion !== 6 || review.purpose !== 'gateway_teardown_review' ||
    review.sessionId !== session.sessionId || review.expiresAt !== control.plan.expiresAt ||
    review.installationId !== control.plan.gateway.installationId ||
    review.gatewayName !== control.plan.gateway.name ||
    review.portalHostname !== control.plan.gateway.portalHostname ||
    review.workerName !== control.plan.gateway.workerName ||
    review.managementOrigin !== `https://${control.plan.gateway.managementHostname}`) {
    throw new DeployError(409, 'session_conflict');
  }
  assertCloudflareOauthConfig(oauthConfig(env));
  const state = randomBase64Url(32);
  const verifier = randomBase64Url(32);
  const attemptId = `att_${randomBase64Url(24)}`;
  const expiresAt = Math.min(now + OAUTH_ATTEMPT_TTL_MS, control.plan.expiresAt);
  await internalCall<{ accepted: true }>(session.stub, '/returning-uninstall/authorize', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      csrfHash: await sha256(session.csrfToken),
      approvedPlanId: approval.planId,
      approvedPlanHash: approval.planHash,
      attemptId,
      stateHash: await sha256(state),
      verifierHash: await sha256(verifier),
      attemptExpiresAt: expiresAt,
      now,
    }),
  });
  const sealed = await sealOauthCookie(env.DEPLOY_SESSION_ENCRYPTION_KEY, {
    ...review,
    schemaVersion: 7,
    purpose: 'gateway_teardown',
    attemptId,
    state,
    verifier,
    expiresAt,
  });
  const authorizationUrl = buildAuthorizationUrl({
    clientId: env.CLOUDFLARE_OAUTH_CLIENT_ID,
    state,
    challenge: await pkceChallenge(verifier),
  });
  recordHostedInstallerAnalytics(
    hostedInstallerAnalyticsSink(env, request),
    'removal_authorization_created',
    'none',
    'returning_removal',
  );
  return json(
    { schemaVersion: 1, authorizationUrl, handoffUrl: oauthHandoffUrl(sealed) },
    200,
    [oauthCookie(sealed, Math.max(1, Math.floor((expiresAt - now) / 1000)))],
  );
}

async function previewReturningUninstallRecoveryPlan(
  request: Request,
  env: GatewayDeployEnv,
  now: number,
  capabilityPolicy: InstallerCapabilityPolicy,
): Promise<Response> {
  requireMutationBoundary(request, false);
  if (!capabilityPolicy.uninstall) throw new DeployError(503, 'uninstall_mutations_disabled');
  const session = await existingSession(request, env, now, true);
  const control = session.returningUninstall;
  if (!control || control.status === 'removed' || control.recoverUntil <= now) {
    throw new DeployError(409, 'session_conflict');
  }
  const updated = await internalCall<{ returningUninstall: unknown }>(
    session.stub,
    '/returning-uninstall/recovery/plan',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        csrfHash: await requireCsrf(request),
        planExpiresAt: Math.min(now + OAUTH_ATTEMPT_TTL_MS, control.recoverUntil),
        now,
      }),
    },
  );
  const returningUninstall = await parsePublicReturningUninstall(updated.returningUninstall);
  if (!returningUninstall) throw new DeployError(500, 'session_invalid');
  return json(installerSession(
    session.publicSession,
    session.recovery,
    capabilityPolicy,
    session.uninstall,
    session.uninstallRecovery,
    session.installProgress,
    returningUninstall,
  ));
}

async function startReturningUninstallRecovery(
  request: Request,
  env: GatewayDeployEnv,
  now: number,
  capabilityPolicy: InstallerCapabilityPolicy,
): Promise<Response> {
  requireMutationBoundary(request);
  if (!capabilityPolicy.uninstall) throw new DeployError(503, 'uninstall_mutations_disabled');
  const session = await existingSession(request, env, now, true);
  const csrfHash = await requireCsrf(request);
  const approval = await readReturningUninstallPlanApproval(request);
  const control = session.returningUninstall;
  if (!control || control.status !== 'planned' || !session.discovery.actorEmail ||
    control.plan.planId !== approval.planId || control.plan.planHash !== approval.planHash ||
    control.plan.expiresAt <= now || control.recoverUntil <= now) {
    throw new DeployError(409, 'session_conflict');
  }
  assertCloudflareOauthConfig(oauthConfig(env));
  const state = randomBase64Url(32);
  const verifier = randomBase64Url(32);
  const attemptId = `att_${randomBase64Url(24)}`;
  const expiresAt = Math.min(now + OAUTH_ATTEMPT_TTL_MS, control.plan.expiresAt, control.recoverUntil);
  const authorized = await internalCall<{
    accepted: true;
    actorEmail: string;
    accountId: string;
    zoneId: string;
  }>(session.stub, '/returning-uninstall/recovery/authorize', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      csrfHash,
      approvedPlanId: approval.planId,
      approvedPlanHash: approval.planHash,
      attemptId,
      stateHash: await sha256(state),
      verifierHash: await sha256(verifier),
      attemptExpiresAt: expiresAt,
      now,
    }),
  });
  if (authorized.accepted !== true || authorized.actorEmail !== session.discovery.actorEmail ||
    !/^[a-f0-9]{32}$/u.test(authorized.accountId) || !/^[a-f0-9]{32}$/u.test(authorized.zoneId)) {
    throw new DeployError(500, 'session_invalid');
  }
  const sealed = await sealOauthCookie(env.DEPLOY_SESSION_ENCRYPTION_KEY, {
    schemaVersion: 8,
    purpose: 'gateway_teardown_recovery',
    sessionId: session.sessionId,
    attemptId,
    state,
    verifier,
    expiresAt,
    planId: control.plan.planId,
    planHash: control.plan.planHash,
    actorEmail: authorized.actorEmail,
    accountId: authorized.accountId,
    zoneId: authorized.zoneId,
    installationId: control.plan.gateway.installationId,
  });
  const authorizationUrl = buildAuthorizationUrl({
    clientId: env.CLOUDFLARE_OAUTH_CLIENT_ID,
    state,
    challenge: await pkceChallenge(verifier),
  });
  recordHostedInstallerAnalytics(
    hostedInstallerAnalyticsSink(env, request),
    'removal_authorization_created',
    'none',
    'returning_removal',
  );
  return json(
    { schemaVersion: 1, authorizationUrl, handoffUrl: oauthHandoffUrl(sealed) },
    200,
    [oauthCookie(sealed, Math.max(1, Math.floor((expiresAt - now) / 1000)))],
  );
}

async function startDeploy(
  request: Request,
  env: GatewayDeployEnv,
  releaseProvider: ReleaseBundleProvider,
  now: number,
): Promise<Response> {
  requireMutationBoundary(request);
  const session = await existingSession(request, env, now, true);
  const csrfHash = await requireCsrf(request);
  const approval = await readPlanApproval(request);
  const release: VerifiedRelease = await releaseProvider.loadVerifiedRelease(env);
  assertCloudflareOauthConfig(oauthConfig(env));
  const approvedPlan = session.publicSession.plan;
  if (
    !approvedPlan ||
    approvedPlan.planId !== approval.planId ||
    approvedPlan.planHash !== approval.planHash ||
    approvedPlan.expiresAt <= now
  ) throw new DeployError(409, 'session_conflict');
  parseStaticDeployPlan(approvedPlan);

  // Config, server-derived plan, and exact user approval all exist before an
  // OAuth state or PKCE verifier is minted.
  const state = randomBase64Url(32);
  const verifier = randomBase64Url(32);
  const attemptId = `att_${randomBase64Url(24)}`;
  const expiresAt = Math.min(
    now + OAUTH_ATTEMPT_TTL_MS,
    session.recovery?.recoverUntil ?? session.publicSession.expiresAt,
    approvedPlan.expiresAt,
  );
  await internalCall<{ accepted: true }>(session.stub, '/authorize', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      csrfHash,
      releaseManifest: release.manifest,
      approvedPlanId: approval.planId,
      approvedPlanHash: approval.planHash,
      attemptId,
      stateHash: await sha256(state),
      verifierHash: await sha256(verifier),
      attemptExpiresAt: expiresAt,
      now,
    }),
  });
  const sealed = await sealOauthCookie(env.DEPLOY_SESSION_ENCRYPTION_KEY, {
    schemaVersion: 3,
    purpose: 'install',
    sessionId: session.sessionId,
    attemptId,
    state,
    verifier,
    expiresAt,
  });
  const authorizationUrl = buildAuthorizationUrl({
    clientId: env.CLOUDFLARE_OAUTH_CLIENT_ID,
    state,
    challenge: await pkceChallenge(verifier),
  });
  recordHostedInstallerAnalytics(
    hostedInstallerAnalyticsSink(env, request),
    'install_authorization_created',
    'none',
    'fresh_install',
  );
  return json(
    { schemaVersion: 1, authorizationUrl, handoffUrl: oauthHandoffUrl(sealed) },
    200,
    [oauthCookie(sealed, Math.max(1, Math.floor((expiresAt - now) / 1000)))],
  );
}

function clearedSessionResponse(): Response {
  const headers = new Headers(SECURITY_HEADERS);
  headers.append('set-cookie', clearSessionCookie());
  headers.append('set-cookie', clearOauthCookie());
  return new Response(null, { status: 204, headers });
}

async function deleteSession(request: Request, env: GatewayDeployEnv): Promise<Response> {
  requireMutationBoundary(request, false);
  const csrfHash = await requireCsrf(request);
  const sessionId = readSessionId(request);
  if (!sessionId) return clearedSessionResponse();
  const response = await sessionStub(env, sessionId).fetch(new Request('https://gateway-deploy-session.invalid/destroy', {
    method: 'DELETE',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ csrfHash }),
  }));
  if (!response.ok) {
    let code: DeployErrorCode | null = null;
    try {
      code = internalErrorCode(await response.json());
    } catch {
      // Stable fallback only.
    }
    throw new DeployError(response.status, code ?? 'session_invalid');
  }
  return clearedSessionResponse();
}

function uniqueQuery(url: URL, name: string): string | null {
  const values = url.searchParams.getAll(name);
  if (values.length > 1) throw new DeployError(400, 'callback_invalid');
  return values[0] ?? null;
}

type ValidatedCallbackQuery =
  | { readonly state: string; readonly code: string; readonly denied: false }
  | { readonly state: string; readonly code: null; readonly denied: true };

function validateCallbackQuery(
  url: URL,
  expectedScopes: readonly string[],
): ValidatedCallbackQuery {
  const keys = [...url.searchParams.keys()];
  const state = uniqueQuery(url, 'state');
  const code = uniqueQuery(url, 'code');
  const oauthError = uniqueQuery(url, 'error');
  // Cloudflare echoes the granted scope set on the authorization response
  // (observed live 2026-08-23). It is accepted only when it is exactly the
  // required set; the token response remains the authoritative grant check.
  const echoedScope = uniqueQuery(url, 'scope');
  const allowed = code
    ? new Set(['code', 'scope', 'state'])
    : new Set(['error', 'error_description', 'error_uri', 'state']);
  if (
    keys.some((key) => !allowed.has(key)) ||
    !state || !/^[A-Za-z0-9_-]{43}$/u.test(state) ||
    Boolean(code) === Boolean(oauthError) ||
    (code !== null && (code.length < 8 || code.length > 4096)) ||
    (oauthError !== null && (oauthError.length < 1 || oauthError.length > 128)) ||
    (echoedScope !== null && !echoedScopeIsExact(echoedScope, expectedScopes))
  ) {
    throw new DeployError(400, 'callback_invalid');
  }
  if (oauthError !== null) return { state, code: null, denied: true };
  if (code === null) throw new DeployError(400, 'callback_invalid');
  return { state, code, denied: false };
}

function echoedScopeIsExact(value: string, expectedScopes: readonly string[]): boolean {
  if (value.length > 1024) return false;
  const values = [...new Set(value.split(/\s+/u).filter(Boolean))].sort();
  const expected = [...expectedScopes].sort();
  return values.length === expected.length &&
    values.every((scope, index) => scope === expected[index]);
}

function sanitizeReason(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9_]+/gu, '_').replace(/^_+|_+$/gu, '').replace(/^[^a-z]+/u, '').slice(0, 160);
}

/**
 * Secret-free failure reason: the error's class (DeployError code or the
 * thrown error's name) plus the last journaled install action and phase, so an
 * operator can see where a live run died without any provider body or token.
 */
async function installFailureReason<ErrorInput>(stub: GatewayDeploySessionStub, error: ErrorInput): Promise<string | null> {
  const stable = stableError(error instanceof Error ? error : undefined);
  const errorDetails = v.safeParse(v.object({
    code: v.optional(v.string()),
    stage: v.optional(v.string()),
  }), error);
  const detail = (field: 'code' | 'stage'): string => {
    const value = errorDetails.success ? errorDetails.output[field] : undefined;
    return value !== undefined && /^[a-z][a-z0-9_]{0,40}$/u.test(value) ? `_${value}` : '';
  };
  // Most specific first so a long reason never loses its useful part.
  const errorClass = error instanceof DeployError
    ? (stable.reason ?? stable.code)
    : `${detail('code').slice(1) || 'unclassified'}${detail('stage')}_${error instanceof Error && error.name ? error.name : 'error'}`;
  let stage = 'before_journal';
  try {
    // The endpoint answers {journal: {...}}; reading `actions` off the envelope
    // instead of the journal silently yielded `before_journal` for every
    // failure that had a journal, which hid the real stage on live runs.
    const response = await internalCall<{
      journal?: { actions?: Array<{ name?: string; phase?: string }> };
    }>(stub, '/install-journal', { method: 'GET' });
    const actions = response?.journal?.actions;
    const last = Array.isArray(actions) ? actions.at(-1) : undefined;
    if (last?.name !== undefined && last.phase !== undefined) {
      stage = `${last.name}_${last.phase}`;
    } else if (Array.isArray(actions)) {
      stage = 'journal_empty';
    } else {
      // A readable response without the reviewed journal shape is malformed,
      // not absent and not an unreadable provider response.
      stage = 'journal_malformed';
    }
  } catch (journalError) {
    stage = journalError instanceof DeployError && journalError.status === 404
      ? 'journal_absent'
      : 'journal_unreadable';
  }
  const reason = sanitizeReason(`${errorClass}_at_${stage}`);
  return reason.length > 0 ? reason : null;
}

async function completeAttempt(
  stub: GatewayDeploySessionStub,
  attemptId: string,
  code: 'install_complete' | DeployErrorCode,
  installationId: string | null,
  grantRevocation: 'confirmed' | 'unconfirmed' | null,
  completedAt: number,
  reason: string | null = null,
  existingGateway: ExistingAnkkaGatewaySummary | null = null,
): Promise<void> {
  const body = existingGateway === null
    ? { attemptId, code, installationId, grantRevocation, completedAt, reason }
    : { attemptId, code, installationId, grantRevocation, completedAt, reason, existingGateway };
  await internalCall(stub, '/complete', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function completeUninstallAttempt(
  stub: GatewayDeploySessionStub,
  attemptId: string,
  code: 'uninstall_complete' | DeployErrorCode,
  installationId: string | null,
  grantRevocation: 'confirmed' | 'unconfirmed' | null,
  completedAt: number,
  reason: string | null = null,
): Promise<void> {
  await internalCall(stub, '/uninstall/complete', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ attemptId, code, installationId, grantRevocation, completedAt, reason }),
  });
}

function resultRedirect(): Response {
  const headers = new Headers(SECURITY_HEADERS);
  headers.set('location', `${PUBLIC_ORIGIN}/result`);
  headers.append('set-cookie', clearOauthCookie());
  return new Response(null, { status: 303, headers });
}

async function returningResultRedirect(
  env: GatewayDeployEnv,
  sealed: Extract<SealedOauthCookie, { readonly schemaVersion: 7 }>,
  reviewExpiresAt: number,
  now: number,
  preserveReview: boolean,
): Promise<Response> {
  if (!preserveReview || reviewExpiresAt <= now) return resultRedirect();
  const review = await sealOauthCookie(env.DEPLOY_SESSION_ENCRYPTION_KEY, {
    schemaVersion: 6,
    purpose: 'gateway_teardown_review',
    sessionId: sealed.sessionId,
    expiresAt: reviewExpiresAt,
    actionId: sealed.actionId,
    actionKey: sealed.actionKey,
    actorEmail: sealed.actorEmail,
    accountId: sealed.accountId,
    installationId: sealed.installationId,
    gatewayName: sealed.gatewayName,
    portalHostname: sealed.portalHostname,
    workerName: sealed.workerName,
    workersSubdomain: sealed.workersSubdomain,
    managementOrigin: sealed.managementOrigin,
  });
  const headers = new Headers(SECURITY_HEADERS);
  headers.set('location', `${PUBLIC_ORIGIN}/result`);
  headers.append('set-cookie', oauthCookie(
    review,
    Math.max(1, Math.floor((reviewExpiresAt - now) / 1000)),
  ));
  return new Response(null, { status: 303, headers });
}

function withClearedOauthCookie(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.append('set-cookie', clearOauthCookie());
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function installerRedirect(): Response {
  const headers = new Headers(SECURITY_HEADERS);
  headers.set('location', `${PUBLIC_ORIGIN}/`);
  headers.append('set-cookie', clearOauthCookie());
  return new Response(null, { status: 303, headers });
}

async function withVerifiedManagementContext(
  response: Response,
  env: GatewayDeployEnv,
  sealed: Extract<SealedOauthCookie, { schemaVersion: 4 | 5 }>,
  now: number,
): Promise<Response> {
  const verified = await sealOauthCookie(env.DEPLOY_SESSION_ENCRYPTION_KEY, {
    schemaVersion: 9,
    purpose: 'management_action_result',
    actionType: sealed.schemaVersion === 5 ? 'runtime_update' : 'source_apply',
    actionId: sealed.actionId,
    managementOrigin: sealed.managementOrigin,
    expiresAt: sealed.expiresAt,
  });
  const headers = new Headers(response.headers);
  // The callback shell is not an authority source. Replace any cookie it may
  // carry with the one exact post-verification context cookie.
  headers.delete('set-cookie');
  headers.append('set-cookie', oauthCookie(
    verified,
    Math.max(1, Math.floor((sealed.expiresAt - now) / 1000)),
  ));
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function managementRedirect(
  sealed: Extract<SealedOauthCookie, { schemaVersion: 4 | 5 }>,
  result: 'finished',
): Response {
  const url = new URL(sealed.managementOrigin);
  const runtime = sealed.schemaVersion === 5;
  url.searchParams.set(runtime ? 'runtimeAction' : 'sourceAction', sealed.actionId);
  url.searchParams.set(runtime ? 'runtimeActionResult' : 'sourceActionResult', result);
  const headers = new Headers(SECURITY_HEADERS);
  headers.set('location', url.toString());
  headers.append('set-cookie', clearOauthCookie());
  return new Response(null, { status: 303, headers });
}

type SourceCallbackPhase =
  | 'source_release_verification'
  | 'source_grant_exchange'
  | 'source_account_authorization'
  | 'source_action_relay'
  | 'source_callback_shell';

function sourceCallbackError<ErrorInput>(error: ErrorInput, phase: SourceCallbackPhase): DeployError {
  const stable = stableError(error);
  // Request-local fixed vocabulary only; never derive diagnostics from the
  // handoff, grant, provider response, or thrown exception text.
  return new DeployError(stable.status, stable.code, stable.reason ?? phase);
}

async function sourceActionOauthCallback(
  request: Request,
  env: GatewayDeployEnv,
  transport: FetchTransport,
  exactReleaseProvider: ExactReleaseBundleProvider,
  now: number,
  callback: ValidatedCallbackQuery,
  sealed: Extract<SealedOauthCookie, { schemaVersion: 4 }>,
  managementCallbackResponse?: ManagementCallbackResponse,
  context?: GatewayDeployExecutionContext,
): Promise<Response> {
  if (sealed.purpose !== 'source_apply' || sealed.expiresAt <= now) {
    throw new DeployError(400, 'session_invalid');
  }
  if (callback.denied) return errorResponse(new DeployError(400, 'oauth_denied'), true);
  let phase: SourceCallbackPhase = 'source_release_verification';
  let execution: Promise<void> | null = null;
  const executeOnce = (): Promise<void> => {
    execution ??= (async () => {
      let grant: EphemeralCloudflareGrant | null = null;
      try {
        // Resolve the immutable historical release selected by the installed
        // Worker, never the mutable currently promoted channel head.
        const releaseBundle = await exactReleaseProvider.loadVerifiedReleaseBundleForIdentity(
          env,
          sealed.releaseIdentity,
        );
        assertExactReleaseBundleIdentity(releaseBundle, sealed.releaseIdentity);
        phase = 'source_grant_exchange';
        grant = await exchangeAuthorizationCode({
          code: callback.code,
          verifier: sealed.verifier,
          config: oauthConfig(env),
          transport,
        });
        grant.assertUsable();
        phase = 'source_account_authorization';
        await grant.withAccessToken(async (accessToken) => {
          await resolveAuthorizedAccount({
            accessToken,
            expectedActorEmail: sealed.actorEmail,
            expectedAccountId: sealed.accountId,
            transport,
          });
          phase = 'source_action_relay';
          await relaySourceAction({
            accessToken,
            accountId: sealed.accountId,
            workerName: sealed.workerName,
            workersSubdomain: sealed.workersSubdomain,
            managementOrigin: sealed.managementOrigin,
            actionId: sealed.actionId,
            actionKey: sealed.actionKey,
            actorEmail: sealed.actorEmail,
            expiresAt: sealed.expiresAt,
            releaseIdentity: sealed.releaseIdentity,
            releaseBundle,
            transport,
            now: () => now,
          });
        });
      } finally {
        if (grant) {
          try { await grant.revoke(transport, oauthConfig(env)); } catch { /* The action result remains customer-owned. */ }
          grant.discard();
        }
      }
    })();
    return execution;
  };
  try {
    await executeOnce();
  } catch (error) {
    return errorResponse(sourceCallbackError(error, phase), true);
  }
  if (managementCallbackResponse) {
    phase = 'source_callback_shell';
    try {
      const callbackInput: InstallCallbackResponseInput = context === undefined
        ? { request, env, execute: executeOnce }
        : { request, env, context, execute: executeOnce };
      return await withVerifiedManagementContext(
        await managementCallbackResponse(callbackInput), env, sealed, now,
      );
    } catch (error) {
      return errorResponse(sourceCallbackError(error, phase), true);
    }
  }
  return managementRedirect(sealed, 'finished');
}

async function runtimeUpdateOauthCallback(
  request: Request,
  env: GatewayDeployEnv,
  transport: FetchTransport,
  releaseProvider: ReleaseBundleProvider,
  now: number,
  callback: ValidatedCallbackQuery,
  sealed: Extract<SealedOauthCookie, { schemaVersion: 5 }>,
  managementCallbackResponse?: ManagementCallbackResponse,
  context?: GatewayDeployExecutionContext,
): Promise<Response> {
  if (sealed.purpose !== 'runtime_update' || sealed.expiresAt <= now) {
    throw new DeployError(400, 'session_invalid');
  }
  if (callback.denied) return errorResponse(new DeployError(400, 'oauth_denied'), true);
  let execution: Promise<void> | null = null;
  const executeOnce = (): Promise<void> => {
    execution ??= (async () => {
      let grant: EphemeralCloudflareGrant | null = null;
      try {
        const releaseBundle = await releaseProvider.loadVerifiedReleaseBundle(env);
        if (sealed.operation === 'update' && (
          releaseBundle.manifest.release !== sealed.to.release ||
          `sha256:${releaseBundle.manifest.artifact.treeSha256}` !== sealed.to.artifactSha256
        )) throw new DeployError(409, 'session_conflict');
        grant = await exchangeAuthorizationCode({
          code: callback.code,
          verifier: sealed.verifier,
          config: oauthConfig(env),
          transport,
        });
        grant.assertUsable();
        await grant.withAccessToken(async (accessToken) => {
          await resolveAuthorizedAccount({
            accessToken,
            expectedActorEmail: sealed.actorEmail,
            expectedAccountId: sealed.accountId,
            transport,
          });
          await relayRuntimeUpdate({
            accessToken,
            accountId: sealed.accountId,
            workerName: sealed.workerName,
            workersSubdomain: sealed.workersSubdomain,
            managementOrigin: sealed.managementOrigin,
            actionId: sealed.actionId,
            actionKey: sealed.actionKey,
            operation: sealed.operation,
            from: sealed.from,
            to: sealed.to,
            expiresAt: sealed.expiresAt,
            releaseBundle,
            transport,
            now: () => now,
          });
        });
      } finally {
        if (grant) {
          try { await grant.revoke(transport, oauthConfig(env)); } catch { /* Customer action records convergence. */ }
          grant.discard();
        }
      }
    })();
    return execution;
  };
  try {
    await executeOnce();
  } catch (error) {
    return errorResponse(error, true);
  }
  if (managementCallbackResponse) {
    try {
      const callbackInput: InstallCallbackResponseInput = context === undefined
        ? { request, env, execute: executeOnce }
        : { request, env, context, execute: executeOnce };
      return await withVerifiedManagementContext(
        await managementCallbackResponse(callbackInput), env, sealed, now,
      );
    } catch (error) {
      return errorResponse(error, true);
    }
  }
  return managementRedirect(sealed, 'finished');
}

async function completeDiscoveryAttempt(
  stub: GatewayDeploySessionStub,
  attemptId: string,
  code: 'discovery_complete' | DeployErrorCode,
  result: CloudflareDiscoveryResult | null,
  grantRevocation: 'confirmed' | 'unconfirmed' | null,
  completedAt: number,
): Promise<void> {
  await internalCall(stub, '/discover/complete', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ attemptId, code, result, grantRevocation, completedAt }),
  });
}

async function oauthCallback(
  request: Request,
  env: GatewayDeployEnv,
  transport: FetchTransport,
  releaseProvider: ReleaseBundleProvider,
  exactReleaseProvider: ExactReleaseBundleProvider,
  executor: InstallExecutor,
  uninstallExecutor: UninstallExecutor,
  returningUninstallExecutor: ReturningUninstallExecutor,
  now: number,
  installCallbackResponse?: InstallCallbackResponse,
  managementCallbackResponse?: ManagementCallbackResponse,
  context?: GatewayDeployExecutionContext,
): Promise<Response> {
  const sealedValue = readOauthCookie(request);
  if (!sealedValue) throw new DeployError(400, 'session_invalid');
  const sealed = await openOauthCookie(env.DEPLOY_SESSION_ENCRYPTION_KEY, sealedValue);
  const callback = validateCallbackQuery(
    new URL(request.url),
    sealed.purpose === 'discover' ? DISCOVERY_OAUTH_SCOPES : REQUIRED_OAUTH_SCOPES,
  );
  if ((sealed.schemaVersion === 3 || sealed.schemaVersion === 4 || sealed.schemaVersion === 5 ||
      sealed.schemaVersion === 7 || sealed.schemaVersion === 8) &&
      sealed.state !== callback.state) {
    throw new DeployError(400, 'callback_invalid');
  }
  if (sealed.schemaVersion === 4 && sealed.purpose === 'source_apply') {
    return sourceActionOauthCallback(
      request,
      env,
      transport,
      exactReleaseProvider,
      now,
      callback,
      sealed,
      managementCallbackResponse,
      context,
    );
  }
  if (sealed.schemaVersion === 5 && sealed.purpose === 'runtime_update') {
    return runtimeUpdateOauthCallback(
      request,
      env,
      transport,
      releaseProvider,
      now,
      callback,
      sealed,
      managementCallbackResponse,
      context,
    );
  }
  if (sealed.schemaVersion === 7 && sealed.purpose === 'gateway_teardown') {
    return returningUninstallOauthCallback(
      request,
      env,
      transport,
      exactReleaseProvider,
      returningUninstallExecutor,
      now,
      callback,
      sealed,
    );
  }
  if (sealed.schemaVersion === 8 && sealed.purpose === 'gateway_teardown_recovery') {
    return returningUninstallRecoveryOauthCallback(
      request,
      env,
      transport,
      exactReleaseProvider,
      returningUninstallExecutor,
      now,
      callback,
      sealed,
    );
  }
  if (sealed.purpose === 'uninstall') {
    return uninstallOauthCallback(
      request,
      env,
      transport,
      releaseProvider,
      uninstallExecutor,
      now,
      callback,
      sealed,
    );
  }
  if (sealed.purpose === 'discover') {
    return discoveryOauthCallback(request, env, transport, now, callback, sealed);
  }
  const session = await existingSession(request, env, now, true);
  if (sealed.purpose !== 'install' || sealed.sessionId !== session.sessionId || sealed.expiresAt <= now) {
    throw new DeployError(400, 'session_invalid');
  }
  const consumed = await internalCall<{
    selection: DeploySelection;
    plan: StaticDeployPlan;
    recoverUntil: number;
    discoveredTarget: DiscoveredCloudflareTarget | null;
  }>(
    session.stub,
    '/consume',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        attemptId: sealed.attemptId,
        stateHash: await sha256(callback.state),
        verifierHash: await sha256(sealed.verifier),
        now,
      }),
    },
  );
  const selection = parseDeploySelection(consumed.selection);
  const plan = parseStaticDeployPlan(consumed.plan);
  if (
    !Number.isSafeInteger(consumed.recoverUntil) ||
    consumed.recoverUntil <= now ||
    consumed.recoverUntil > session.publicSession.expiresAt + MAX_INSTALL_RECOVERY_RETENTION_MS
  ) throw new DeployError(500, 'session_invalid');
  if (callback.denied) {
    await completeAttempt(session.stub, sealed.attemptId, 'oauth_denied', null, null, now);
    recordHostedInstallerAnalytics(
      hostedInstallerAnalyticsSink(env, request),
      'install_completed',
      'denied',
      'fresh_install',
    );
    return resultRedirect();
  }

  const executeInstall = async (): Promise<void> => {
    let grant: EphemeralCloudflareGrant | null = null;
    let resultCode: 'install_complete' | DeployErrorCode = 'internal_error';
    let resultReason: string | null = null;
    let installationId: string | null = null;
    let existingGateway: ExistingAnkkaGatewaySummary | null = null;
    let grantRevocation: 'confirmed' | 'unconfirmed' | null = null;
    try {
      const releaseBundle: VerifiedReleaseBundle = await releaseProvider.loadVerifiedReleaseBundle(env);
      const reboundPlan = await buildStaticDeployPlan(selection, releaseBundle.manifest, plan.expiresAt);
      if (JSON.stringify(reboundPlan) !== JSON.stringify(plan)) {
        throw new DeployError(409, 'session_conflict');
      }
      grant = await exchangeAuthorizationCode({
        code: callback.code,
        verifier: sealed.verifier,
        config: oauthConfig(env),
        transport,
      });
      grant.assertUsable();
      const installed = await grant.withAccessToken(async (accessToken) => {
        const targetInput: AuthorizedTargetResolutionInput = {
          accessToken,
          typedZoneName: selection.basics.zoneName,
          expectedAdminEmail: selection.basics.adminEmail,
          transport,
        };
        if (consumed.discoveredTarget !== null) {
          targetInput.expectedAccountId = consumed.discoveredTarget.account.id;
          targetInput.expectedZoneId = consumed.discoveredTarget.zone.id;
        }
        const target = await resolveAuthorizedTarget(targetInput);
        return executor.execute({
          selection,
          plan,
          target,
          releaseBundle,
          accessToken,
          sessionId: session.sessionId,
          bootstrapNonceDerivationKey: env.BOOTSTRAP_NONCE_DERIVATION_KEY,
          attemptId: sealed.attemptId,
          recoverUntil: consumed.recoverUntil,
          journal: createInstallJournalPort({
            fetch: (internalRequest) => session.stub.fetch(internalRequest),
          }),
        });
      });
      if (!/^acg-[a-f0-9]{24}$/u.test(installed.installationId)) {
        throw new DeployError(500, 'internal_error');
      }
      resultCode = 'install_complete';
      installationId = installed.installationId;
    } catch (error) {
      if (error instanceof CustomerGatewayFreshPreflightError &&
        error.code === 'existing_gateway_detected' && error.existingGateway) {
        resultCode = 'existing_gateway_detected';
        existingGateway = error.existingGateway;
      } else {
        resultCode = stableError(error instanceof Error ? error : undefined).code;
      }
      resultReason = await installFailureReason(session.stub, error);
      installationId = null;
    } finally {
      if (grant) {
        try {
          await grant.revoke(transport, oauthConfig(env));
          if (resultCode === 'install_complete') grantRevocation = 'confirmed';
        } catch {
          if (resultCode === 'install_complete') {
            grantRevocation = 'unconfirmed';
          } else {
            resultCode = 'oauth_revoke_failed';
            resultReason = null;
            installationId = null;
            existingGateway = null;
          }
        } finally {
          grant.discard();
        }
      }
    }
    await completeAttempt(
      session.stub,
      sealed.attemptId,
      resultCode,
      installationId,
      grantRevocation,
      now,
      resultCode === 'install_complete' ? null : resultReason,
      existingGateway,
    );
    recordHostedInstallerAnalytics(
      hostedInstallerAnalyticsSink(env, request),
      'install_completed',
      completionAnalyticsOutcome(resultCode, 'install_complete'),
      'fresh_install',
    );
  };

  let execution: Promise<void> | null = null;
  const executeOnce = (): Promise<void> => {
    execution ??= executeInstall();
    return execution;
  };
  if (installCallbackResponse) {
    try {
      const callbackInput: InstallCallbackResponseInput = context === undefined
        ? { request, env, execute: executeOnce }
        : { request, env, context, execute: executeOnce };
      return withClearedOauthCookie(await installCallbackResponse(callbackInput));
    } catch {
      // A signed shell or stream construction failure must not strand the
      // consumed grant. Fall back to the original connected callback path.
      await executeOnce();
      return resultRedirect();
    }
  }
  await executeOnce();
  return resultRedirect();
}

async function discoveryOauthCallback(
  request: Request,
  env: GatewayDeployEnv,
  transport: FetchTransport,
  now: number,
  callback: ValidatedCallbackQuery,
  sealed: SealedOauthCookie,
): Promise<Response> {
  const session = await existingSession(request, env, now, true);
  if (sealed.purpose !== 'discover' || sealed.schemaVersion !== 3 ||
    sealed.sessionId !== session.sessionId || sealed.expiresAt <= now) {
    throw new DeployError(400, 'session_invalid');
  }
  await internalCall<{ accepted: true }>(session.stub, '/discover/consume', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      attemptId: sealed.attemptId,
      stateHash: await sha256(callback.state),
      verifierHash: await sha256(sealed.verifier),
      now,
    }),
  });
  if (callback.denied) {
    await completeDiscoveryAttempt(session.stub, sealed.attemptId, 'oauth_denied', null, null, now);
    recordHostedInstallerAnalytics(
      hostedInstallerAnalyticsSink(env, request),
      'discovery_completed',
      'denied',
      'none',
    );
    return installerRedirect();
  }

  let grant: EphemeralCloudflareGrant | null = null;
  let result: Awaited<ReturnType<typeof discoverCloudflareTargets>> | null = null;
  let resultCode: 'discovery_complete' | DeployErrorCode = 'internal_error';
  let grantRevocation: 'confirmed' | 'unconfirmed' | null = null;
  try {
    grant = await exchangeAuthorizationCode({
      code: callback.code,
      verifier: sealed.verifier,
      config: oauthConfig(env),
      transport,
    });
    grant.assertUsable(DISCOVERY_OAUTH_SCOPES);
    result = await grant.withAccessToken((accessToken) => discoverCloudflareTargets({
      accessToken,
      transport,
    }));
    resultCode = 'discovery_complete';
  } catch (error) {
    resultCode = stableError(error instanceof Error ? error : undefined).code;
    result = null;
  } finally {
    if (grant) {
      try {
        await grant.revoke(transport, oauthConfig(env));
        if (resultCode === 'discovery_complete') grantRevocation = 'confirmed';
      } catch {
        if (resultCode === 'discovery_complete') {
          grantRevocation = 'unconfirmed';
        } else {
          resultCode = 'oauth_revoke_failed';
          result = null;
        }
      } finally {
        grant.discard();
      }
    }
  }
  await completeDiscoveryAttempt(
    session.stub,
    sealed.attemptId,
    resultCode,
    resultCode === 'discovery_complete' ? result : null,
    resultCode === 'discovery_complete' ? grantRevocation : null,
    now,
  );
  recordHostedInstallerAnalytics(
    hostedInstallerAnalyticsSink(env, request),
    'discovery_completed',
    completionAnalyticsOutcome(resultCode, 'discovery_complete'),
    'none',
  );
  return installerRedirect();
}

async function uninstallOauthCallback(
  request: Request,
  env: GatewayDeployEnv,
  transport: FetchTransport,
  releaseProvider: ReleaseBundleProvider,
  executor: UninstallExecutor,
  now: number,
  callback: ValidatedCallbackQuery,
  sealed: SealedOauthCookie,
): Promise<Response> {
  const session = await retainedInstallationSession(request, env, now);
  if (sealed.purpose !== 'uninstall' || sealed.sessionId !== session.sessionId || sealed.expiresAt <= now) {
    throw new DeployError(400, 'session_invalid');
  }
  const consumed = await internalCall<{
    approvedAt: number;
    recoverUntil: number;
    installationId: string;
    plan: unknown;
  }>(session.stub, '/uninstall/consume', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      purpose: 'uninstall',
      attemptId: sealed.attemptId,
      stateHash: await sha256(callback.state),
      verifierHash: await sha256(sealed.verifier),
      now,
    }),
  });
  const plan = session.uninstall?.plan;
  if (!plan || JSON.stringify(consumed.plan) !== JSON.stringify(plan) ||
    consumed.installationId !== plan.installationId || !Number.isSafeInteger(consumed.approvedAt) ||
    consumed.approvedAt < now || consumed.approvedAt >= plan.expiresAt ||
    !Number.isSafeInteger(consumed.recoverUntil) ||
    consumed.recoverUntil !== session.uninstall?.recoverUntil || consumed.recoverUntil <= now) {
    throw new DeployError(500, 'session_invalid');
  }
  if (callback.denied) {
    await completeUninstallAttempt(session.stub, sealed.attemptId, 'oauth_denied', null, null, now);
    recordHostedInstallerAnalytics(
      hostedInstallerAnalyticsSink(env, request),
      'removal_completed',
      'denied',
      'same_session_removal',
    );
    return resultRedirect();
  }

  let grant: EphemeralCloudflareGrant | null = null;
  let resultCode: 'uninstall_complete' | DeployErrorCode = 'internal_error';
  let resultReason: string | null = null;
  let installationId: string | null = null;
  let grantRevocation: 'confirmed' | 'unconfirmed' | null = null;
  try {
    const releaseBundle = await releaseProvider.loadVerifiedReleaseBundle(env);
    const installJournalResponse = await internalCall<{ journal: unknown }>(
      session.stub,
      '/install-journal',
    );
    const installJournal = await requireInstallJournal(installJournalResponse.journal);
    const rebuiltPlan = await buildStaticUninstallPlan(installJournal, plan.createdAt, plan.expiresAt);
    if (JSON.stringify(rebuiltPlan) !== JSON.stringify(plan) ||
      JSON.stringify(verifiedReleasePin(releaseBundle)) !== JSON.stringify(installJournal.releasePin)) {
      throw new DeployError(409, 'session_conflict');
    }
    grant = await exchangeAuthorizationCode({
      code: callback.code,
      verifier: sealed.verifier,
      config: oauthConfig(env),
      transport,
    });
    grant.assertUsable();
    const removed = await grant.withAccessToken(async (accessToken) => {
      const target = await resolveAuthorizedTarget({
        accessToken,
        typedZoneName: installJournal.selection.basics.zoneName,
        expectedAdminEmail: installJournal.selection.basics.adminEmail,
        transport,
      });
      if (target.actor.id !== installJournal.target.actor.id ||
        target.actor.email !== installJournal.target.actor.email ||
        target.account.id !== installJournal.target.account.id ||
        target.account.name !== installJournal.target.account.name ||
        target.zone.id !== installJournal.target.zone.id ||
        target.zone.name !== installJournal.target.zone.name ||
        target.zone.status !== installJournal.target.zone.status) {
        throw new DeployError(403, 'oauth_grant_invalid');
      }
      const journal = createUninstallJournalPort({
        fetch: (internalRequest) => session.stub.fetch(internalRequest),
      });
      let uninstallCycleId = randomUninstallCycleId();
      try {
        uninstallCycleId = (await journal.read()).uninstallCycleId;
      } catch (error) {
        if (!(error instanceof DeployError) || error.status !== 404 || error.code !== 'session_invalid') {
          throw error;
        }
      }
      return executor.execute({
        installJournal,
        uninstallPlan: plan,
        target,
        releaseBundle,
        accessToken,
        uninstallNonceDerivationKey: env.BOOTSTRAP_NONCE_DERIVATION_KEY,
        attemptId: sealed.attemptId,
        approvedAt: consumed.approvedAt,
        recoverUntil: consumed.recoverUntil,
        uninstallCycleId,
        journal,
      });
    });
    if (removed.status !== 'removed' || removed.installationId !== plan.installationId ||
      !/^sha256:[a-f0-9]{64}$/u.test(removed.convergenceHash)) {
      throw new DeployError(500, 'internal_error');
    }
    resultCode = 'uninstall_complete';
    installationId = removed.installationId;
  } catch (error) {
    const stable = stableError(error instanceof Error ? error : undefined);
    resultCode = stable.code;
    resultReason = stable.reason;
    installationId = null;
  } finally {
    if (grant) {
      try {
        await grant.revoke(transport, oauthConfig(env));
        if (resultCode === 'uninstall_complete') grantRevocation = 'confirmed';
      } catch {
        if (resultCode === 'uninstall_complete') {
          grantRevocation = 'unconfirmed';
        } else {
          resultCode = 'oauth_revoke_failed';
          installationId = null;
        }
      } finally {
        grant.discard();
      }
    }
  }
  await completeUninstallAttempt(
    session.stub,
    sealed.attemptId,
    resultCode,
    installationId,
    grantRevocation,
    now,
    resultCode === 'uninstall_complete' ? null : resultReason,
  );
  recordHostedInstallerAnalytics(
    hostedInstallerAnalyticsSink(env, request),
    'removal_completed',
    completionAnalyticsOutcome(resultCode, 'uninstall_complete'),
    'same_session_removal',
  );
  return resultRedirect();
}

async function completeReturningUninstallAttempt(
  stub: GatewayDeploySessionStub,
  attemptId: string,
  code: 'returning_uninstall_complete' | DeployErrorCode,
  installationId: string | null,
  grantRevocation: 'confirmed' | 'unconfirmed' | null,
  completedAt: number,
  reason: string | null = null,
): Promise<void> {
  const body = reason === null
    ? { attemptId, code, completedAt, installationId, grantRevocation }
    : { attemptId, code, completedAt, installationId, grantRevocation, reason };
  await internalCall(stub, '/returning-uninstall/complete', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function returningUninstallRecoveryOauthCallback(
  request: Request,
  env: GatewayDeployEnv,
  transport: FetchTransport,
  exactReleaseProvider: ExactReleaseBundleProvider,
  executor: ReturningUninstallExecutor,
  now: number,
  callback: ValidatedCallbackQuery,
  sealed: Extract<SealedOauthCookie, { readonly schemaVersion: 8 }>,
): Promise<Response> {
  const session = await existingSession(request, env, now, true);
  if (sealed.sessionId !== session.sessionId || sealed.expiresAt <= now) {
    throw new DeployError(400, 'session_invalid');
  }
  const consumed = await internalCall<{
    approvedAt: number;
    recoverUntil: number;
    plan: unknown;
    actor: { id: string; email: string };
    discoveredTarget: DiscoveredCloudflareTarget;
  }>(session.stub, '/returning-uninstall/recovery/consume', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      attemptId: sealed.attemptId,
      stateHash: await sha256(callback.state),
      verifierHash: await sha256(sealed.verifier),
      now,
    }),
  });
  const plan = await parseReturningUninstallPlan(consumed.plan);
  const retained = session.returningUninstall?.plan;
  if (!retained || JSON.stringify(plan) !== JSON.stringify(retained) ||
    plan.planId !== sealed.planId || plan.planHash !== sealed.planHash ||
    plan.gateway.installationId !== sealed.installationId ||
    !Number.isSafeInteger(consumed.approvedAt) || consumed.approvedAt > now ||
    consumed.approvedAt < plan.createdAt || consumed.approvedAt >= plan.expiresAt ||
    !Number.isSafeInteger(consumed.recoverUntil) || consumed.recoverUntil <= plan.expiresAt ||
    consumed.recoverUntil <= now || consumed.actor.email !== sealed.actorEmail ||
    consumed.discoveredTarget.account.id !== sealed.accountId ||
    consumed.discoveredTarget.zone.id !== sealed.zoneId) {
    throw new DeployError(500, 'session_invalid');
  }
  if (callback.denied) {
    await completeReturningUninstallAttempt(
      session.stub, sealed.attemptId, 'oauth_denied', null, null, now,
    );
    recordHostedInstallerAnalytics(
      hostedInstallerAnalyticsSink(env, request),
      'removal_completed',
      'denied',
      'returning_removal',
    );
    return resultRedirect();
  }

  let grant: EphemeralCloudflareGrant | null = null;
  let resultCode: 'returning_uninstall_complete' | DeployErrorCode = 'internal_error';
  let resultReason: string | null = null;
  let installationId: string | null = null;
  let grantRevocation: 'confirmed' | 'unconfirmed' | null = null;
  try {
    grant = await exchangeAuthorizationCode({
      code: callback.code,
      verifier: sealed.verifier,
      config: oauthConfig(env),
      transport,
    });
    grant.assertUsable();
    const removed = await grant.withAccessToken(async (accessToken) => {
      const target = await resolveAuthorizedTarget({
        accessToken,
        typedZoneName: consumed.discoveredTarget.zone.name,
        expectedAdminEmail: sealed.actorEmail,
        transport,
      });
      if (target.actor.id !== consumed.actor.id || target.actor.email !== sealed.actorEmail ||
        target.account.id !== sealed.accountId || target.account.name !== consumed.discoveredTarget.account.name ||
        target.zone.id !== sealed.zoneId || target.zone.name !== consumed.discoveredTarget.zone.name ||
        target.zone.status !== 'active') {
        throw new DeployError(403, 'oauth_grant_invalid');
      }
      return executor.resume({
        plan,
        target,
        loadExactReleaseBundle: (identity) => (
          exactReleaseProvider.loadVerifiedReleaseBundleForIdentity(env, identity)
        ),
        accessToken,
        transport,
        attemptId: sealed.attemptId,
        approvedAt: consumed.approvedAt,
        recoverUntil: consumed.recoverUntil,
        journal: createReturningUninstallJournalPort({
          fetch: (internalRequest) => session.stub.fetch(internalRequest),
        }),
      });
    });
    if (removed.status !== 'removed' || removed.installationId !== sealed.installationId ||
      !/^sha256:[a-f0-9]{64}$/u.test(removed.convergenceHash)) {
      throw new DeployError(500, 'internal_error');
    }
    resultCode = 'returning_uninstall_complete';
    installationId = removed.installationId;
  } catch (error) {
    const stable = stableError(error instanceof Error ? error : undefined);
    resultCode = stable.code;
    resultReason = stable.reason;
  } finally {
    if (grant) {
      try {
        await grant.revoke(transport, oauthConfig(env));
        if (resultCode === 'returning_uninstall_complete') grantRevocation = 'confirmed';
      } catch {
        if (resultCode === 'returning_uninstall_complete') grantRevocation = 'unconfirmed';
        else resultCode = 'oauth_revoke_failed';
      } finally { grant.discard(); }
    }
  }
  await completeReturningUninstallAttempt(
    session.stub,
    sealed.attemptId,
    resultCode,
    resultCode === 'returning_uninstall_complete' ? installationId : null,
    resultCode === 'returning_uninstall_complete' ? grantRevocation : null,
    now,
    resultCode === 'returning_uninstall_complete' ? null : resultReason,
  );
  recordHostedInstallerAnalytics(
    hostedInstallerAnalyticsSink(env, request),
    'removal_completed',
    completionAnalyticsOutcome(resultCode, 'returning_uninstall_complete'),
    'returning_removal',
  );
  return resultRedirect();
}

async function returningUninstallOauthCallback(
  request: Request,
  env: GatewayDeployEnv,
  transport: FetchTransport,
  exactReleaseProvider: ExactReleaseBundleProvider,
  executor: ReturningUninstallExecutor,
  now: number,
  callback: ValidatedCallbackQuery,
  sealed: Extract<SealedOauthCookie, { readonly schemaVersion: 7 }>,
): Promise<Response> {
  const session = await existingSession(request, env, now, true);
  if (sealed.sessionId !== session.sessionId || sealed.expiresAt <= now) {
    throw new DeployError(400, 'session_invalid');
  }
  const consumed = await internalCall<{
    approvedAt: number;
    recoverUntil: number;
    plan: unknown;
    action: {
      actionId: string;
      actionKeyHash: string;
      actorEmail: string;
      accountId: string;
      workerName: string;
      workersSubdomain: string;
      managementOrigin: string;
      expiresAt: number;
    };
    actor: { id: string; email: string };
    discoveredTarget: DiscoveredCloudflareTarget;
  }>(session.stub, '/returning-uninstall/consume', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      attemptId: sealed.attemptId,
      stateHash: await sha256(callback.state),
      verifierHash: await sha256(sealed.verifier),
      actionKeyHash: await sha256(sealed.actionKey),
      now,
    }),
  });
  const plan = await parseReturningUninstallPlan(consumed.plan);
  const retained = session.returningUninstall?.plan;
  if (!retained || JSON.stringify(plan) !== JSON.stringify(retained) ||
    !Number.isSafeInteger(consumed.approvedAt) || consumed.approvedAt > now ||
    consumed.approvedAt < plan.createdAt || consumed.approvedAt >= plan.expiresAt ||
    !Number.isSafeInteger(consumed.recoverUntil) || consumed.recoverUntil <= plan.expiresAt ||
    consumed.recoverUntil <= now || consumed.action.actionId !== sealed.actionId ||
    consumed.action.actorEmail !== sealed.actorEmail || consumed.action.accountId !== sealed.accountId ||
    consumed.action.workerName !== sealed.workerName ||
    consumed.action.workersSubdomain !== sealed.workersSubdomain ||
    consumed.action.managementOrigin !== sealed.managementOrigin ||
    consumed.action.expiresAt !== sealed.expiresAt || consumed.actor.email !== sealed.actorEmail ||
    consumed.discoveredTarget.account.id !== sealed.accountId) {
    throw new DeployError(500, 'session_invalid');
  }
  if (callback.denied) {
    await completeReturningUninstallAttempt(
      session.stub, sealed.attemptId, 'oauth_denied', null, null, now,
    );
    recordHostedInstallerAnalytics(
      hostedInstallerAnalyticsSink(env, request),
      'removal_completed',
      'denied',
      'returning_removal',
    );
    return returningResultRedirect(env, sealed, plan.expiresAt, now, true);
  }

  let grant: EphemeralCloudflareGrant | null = null;
  let resultCode: 'returning_uninstall_complete' | DeployErrorCode = 'internal_error';
  let resultReason: string | null = null;
  let installationId: string | null = null;
  let grantRevocation: 'confirmed' | 'unconfirmed' | null = null;
  try {
    grant = await exchangeAuthorizationCode({
      code: callback.code,
      verifier: sealed.verifier,
      config: oauthConfig(env),
      transport,
    });
    grant.assertUsable();
    const removed = await grant.withAccessToken(async (accessToken) => {
      const target = await resolveAuthorizedTarget({
        accessToken,
        typedZoneName: consumed.discoveredTarget.zone.name,
        expectedAdminEmail: sealed.actorEmail,
        transport,
      });
      if (target.actor.id !== consumed.actor.id || target.actor.email !== consumed.actor.email ||
        target.account.id !== consumed.discoveredTarget.account.id ||
        target.account.name !== consumed.discoveredTarget.account.name ||
        target.zone.id !== consumed.discoveredTarget.zone.id ||
        target.zone.name !== consumed.discoveredTarget.zone.name || target.zone.status !== 'active') {
        throw new DeployError(403, 'oauth_grant_invalid');
      }
      return executor.execute({
        plan,
        target,
        loadExactReleaseBundle: (identity) => (
          exactReleaseProvider.loadVerifiedReleaseBundleForIdentity(env, identity)
        ),
        accessToken,
        transport,
        attemptId: sealed.attemptId,
        approvedAt: consumed.approvedAt,
        recoverUntil: consumed.recoverUntil,
        journal: createReturningUninstallJournalPort({
          fetch: (internalRequest) => session.stub.fetch(internalRequest),
        }),
        action: {
          actionId: sealed.actionId,
          actionKey: sealed.actionKey,
          actorEmail: sealed.actorEmail,
          accountId: sealed.accountId,
          installationId: sealed.installationId,
          workerName: sealed.workerName,
          workersSubdomain: sealed.workersSubdomain,
          managementOrigin: sealed.managementOrigin,
          expiresAt: sealed.expiresAt,
        },
      });
    });
    if (removed.status !== 'removed' || removed.installationId !== plan.gateway.installationId ||
      !/^sha256:[a-f0-9]{64}$/u.test(removed.convergenceHash)) {
      throw new DeployError(500, 'internal_error');
    }
    resultCode = 'returning_uninstall_complete';
    installationId = removed.installationId;
  } catch (error) {
    const stable = stableError(error instanceof Error ? error : undefined);
    resultCode = stable.code;
    resultReason = stable.reason;
  } finally {
    if (grant) {
      try {
        await grant.revoke(transport, oauthConfig(env));
        if (resultCode === 'returning_uninstall_complete') grantRevocation = 'confirmed';
      } catch {
        if (resultCode === 'returning_uninstall_complete') grantRevocation = 'unconfirmed';
        else resultCode = 'oauth_revoke_failed';
      } finally { grant.discard(); }
    }
  }
  await completeReturningUninstallAttempt(
    session.stub,
    sealed.attemptId,
    resultCode,
    resultCode === 'returning_uninstall_complete' ? installationId : null,
    resultCode === 'returning_uninstall_complete' ? grantRevocation : null,
    now,
    resultCode === 'returning_uninstall_complete' ? null : resultReason,
  );
  recordHostedInstallerAnalytics(
    hostedInstallerAnalyticsSink(env, request),
    'removal_completed',
    completionAnalyticsOutcome(resultCode, 'returning_uninstall_complete'),
    'returning_removal',
  );
  return returningResultRedirect(
    env,
    sealed,
    plan.expiresAt,
    now,
    resultCode !== 'returning_uninstall_complete',
  );
}

const HOME_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ankka MCP Gateway deploy</title></head><body><main><h1>Ankka MCP Gateway deploy service</h1><p>The hosted installer UI will be attached to this service after the zero-write OAuth scaffold is verified.</p></main></body></html>`;
const RESULT_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ankka MCP Gateway deployment result</title></head><body><main><h1>Deployment attempt finished</h1><p>Return to the installer to review the code-only result.</p></main></body></html>`;

export interface GatewayDeployWorker {
  fetch(
    request: Request,
    env: GatewayDeployEnv,
    context?: GatewayDeployExecutionContext,
  ): Promise<Response>;
}

function validatedCapabilityPolicy(
  input: InstallerCapabilityPolicy | undefined,
): Readonly<InstallerCapabilityPolicy> {
  if (input === undefined) return DISABLED_INSTALLER_CAPABILITY_POLICY;
  const result = v.safeParse(v.strictObject({
    deploy: v.boolean(),
    events: v.boolean(),
    uninstall: v.boolean(),
  }), input);
  if (!result.success) throw new DeployError(500, 'internal_error');
  return Object.freeze(result.output);
}

function validatedAbuseControlPolicy(
  input: HostedAbuseControlPolicy | undefined,
): HostedAbuseControlPolicy {
  if (input === undefined) return 'disabled';
  if (input !== 'disabled' && input !== 'required') {
    throw new DeployError(500, 'internal_error');
  }
  return input;
}

function stateChangingApiRequest(request: Request, url: URL): boolean {
  return url.pathname.startsWith('/api/') &&
    ['DELETE', 'PATCH', 'POST', 'PUT'].includes(request.method);
}

export function createGatewayDeployWorker(
  dependencies: GatewayDeployWorkerDependencies = {},
): GatewayDeployWorker {
  const now = dependencies.now ?? Date.now;
  const transport = dependencies.transport ?? ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init));
  const releaseProvider = dependencies.releaseProvider ?? new EnvironmentReleaseManifestProvider();
  const exactReleaseProvider = dependencies.exactReleaseProvider ?? new DisabledExactReleaseBundleProvider();
  const executor = dependencies.installExecutor ?? new DisabledInstallExecutor();
  const uninstallExecutor = dependencies.uninstallExecutor ?? new DisabledUninstallExecutor();
  const returningUninstallExecutor = dependencies.returningUninstallExecutor ??
    new DisabledReturningUninstallExecutor();
  const installCallbackResponse = dependencies.installCallbackResponse;
  const managementCallbackResponse = dependencies.managementCallbackResponse;
  const capabilityPolicy = validatedCapabilityPolicy(dependencies.capabilityPolicy);
  const abuseControlPolicy = validatedAbuseControlPolicy(dependencies.abuseControlPolicy);
  return {
    async fetch(request, env, executionContext): Promise<Response> {
      const url = new URL(request.url);
      try {
        const suppliedSessionId = readSessionId(request);
        let sessionAuthentication: Promise<boolean> | null = null;
        const authenticatedSessionId = async (): Promise<string | null> => {
          if (abuseControlPolicy !== 'required' || suppliedSessionId === null) {
            return suppliedSessionId;
          }
          sessionAuthentication ??= isAuthenticatedSessionId(
            env.DEPLOY_SESSION_ENCRYPTION_KEY,
            suppliedSessionId,
          );
          return await sessionAuthentication ? suppliedSessionId : null;
        };
        if (request.method === 'GET' && url.pathname === '/health') {
          return json({ ok: true, mutationsEnabled: capabilityPolicy.deploy || capabilityPolicy.uninstall });
        }
        if (request.method === 'GET' && /^\/api\/releases\/(?:canary|stable)$/u.test(url.pathname)) {
          const channel = buildPublicUpdateChannel(await releaseProvider.loadVerifiedReleaseBundle(env));
          if (url.pathname !== `/api/releases/${channel.channel}`) {
            return json({ code: 'release_unavailable' }, 404);
          }
          return json(channel);
        }
        if (abuseControlPolicy === 'required' && stateChangingApiRequest(request, url)) {
          requireMutationBoundary(request, false);
          const verifiedSessionId = await authenticatedSessionId();
          await enforceSessionMutationRateLimit(request, env, verifiedSessionId);
          if (
            suppliedSessionId !== null &&
            verifiedSessionId === null &&
            url.pathname !== '/api/oauth/handoff'
          ) throw new DeployError(401, 'session_invalid');
        }
        if (request.method === 'GET' && url.pathname === '/') {
          recordHostedInstallerAnalytics(
            hostedInstallerAnalyticsSink(env, request),
            'installer_page_viewed',
            'none',
            'none',
          );
          return new Response(HOME_HTML, { headers: responseHeaders('text/html; charset=utf-8') });
        }
        if (request.method === 'GET' && url.pathname === '/result') {
          return new Response(RESULT_HTML, { headers: responseHeaders('text/html; charset=utf-8') });
        }
        if (request.method === 'GET' && url.pathname === '/api/session') {
          const verifiedSessionId = await authenticatedSessionId();
          if (abuseControlPolicy === 'required' && verifiedSessionId !== null) {
            await enforceSessionReadRateLimit(env, verifiedSessionId);
          }
          const context = await sessionForGet(
            request,
            env,
            now(),
            abuseControlPolicy,
            verifiedSessionId,
          );
          if (context.created) {
            recordHostedInstallerAnalytics(
              hostedInstallerAnalyticsSink(env, request, context.sessionId),
              'installer_session_created',
              'none',
              'none',
            );
          }
          return json(
            {
              ...installerSession(
                context.publicSession,
                context.recovery,
                capabilityPolicy,
                context.uninstall,
                context.uninstallRecovery,
                context.installProgress,
                context.returningUninstall,
              ),
              csrf: context.csrfToken,
            },
            200,
            context.sessionCookieMaxAgeSeconds !== null
              ? [sessionCookie(context.sessionId, context.sessionCookieMaxAgeSeconds)]
              : [],
          );
        }
        if (request.method === 'GET' && url.pathname === '/api/discovery') {
          const verifiedSessionId = await authenticatedSessionId();
          if (abuseControlPolicy === 'required' && verifiedSessionId !== null) {
            await enforceSessionReadRateLimit(env, verifiedSessionId);
          }
          const context = await sessionForGet(
            request,
            env,
            now(),
            abuseControlPolicy,
            verifiedSessionId,
          );
          if (context.created) {
            recordHostedInstallerAnalytics(
              hostedInstallerAnalyticsSink(env, request, context.sessionId),
              'installer_session_created',
              'none',
              'none',
            );
          }
          return json(
            { ...context.discovery, csrf: context.csrfToken },
            200,
            context.sessionCookieMaxAgeSeconds !== null
              ? [sessionCookie(context.sessionId, context.sessionCookieMaxAgeSeconds)]
              : [],
          );
        }
        if (request.method === 'POST' && url.pathname === '/api/discovery') {
          return await startCloudflareDiscovery(request, env, now());
        }
        if (request.method === 'POST' && url.pathname === '/api/plan') {
          return await previewPlan(request, env, releaseProvider, now(), capabilityPolicy);
        }
        if (request.method === 'PUT' && url.pathname === '/api/selection') {
          return await saveSelection(request, env, now(), capabilityPolicy);
        }
        if (request.method === 'POST' && url.pathname === '/api/deploy') {
          return await startDeploy(request, env, releaseProvider, now());
        }
        if (request.method === 'POST' && url.pathname === '/api/oauth/handoff') {
          return await exchangeOauthHandoff(request, env, now());
        }
        if (request.method === 'POST' && url.pathname === '/api/management/authorize') {
          return await authorizeManagementAction(request, env, now());
        }
        if (request.method === 'GET' && url.pathname === '/api/management/context') {
          return await managementActionContext(request, env, now());
        }
        if (request.method === 'POST' && url.pathname === '/api/uninstall/plan') {
          return await previewUninstallPlan(request, env, releaseProvider, now(), capabilityPolicy);
        }
        if (request.method === 'POST' && url.pathname === '/api/uninstall') {
          return await startUninstall(request, env, releaseProvider, now(), capabilityPolicy);
        }
        if (request.method === 'POST' && url.pathname === '/api/returning-uninstall') {
          return await startReturningUninstall(request, env, now(), capabilityPolicy);
        }
        if (request.method === 'POST' && url.pathname === '/api/returning-uninstall/recovery/plan') {
          return await previewReturningUninstallRecoveryPlan(request, env, now(), capabilityPolicy);
        }
        if (request.method === 'POST' && url.pathname === '/api/returning-uninstall/recovery') {
          return await startReturningUninstallRecovery(request, env, now(), capabilityPolicy);
        }
        if (request.method === 'DELETE' && url.pathname === '/api/session') {
          return await deleteSession(request, env);
        }
        if (request.method === 'GET' && url.pathname === new URL(OAUTH_CALLBACK_URL).pathname) {
          return await oauthCallback(
            request,
            env,
            transport,
            releaseProvider,
            exactReleaseProvider,
            executor,
            uninstallExecutor,
            returningUninstallExecutor,
            now(),
            installCallbackResponse,
            managementCallbackResponse,
            executionContext,
          );
        }
        return errorResponse(new DeployError(404, 'bad_request'));
      } catch (error) {
        return errorResponse(error, url.pathname === new URL(OAUTH_CALLBACK_URL).pathname);
      }
    },
  };
}

export default createGatewayDeployWorker();
