import * as v from 'valibot';

import {
  enforceAnonymousSessionRateLimit,
  enforceSessionMutationRateLimit,
  enforceSessionReadRateLimit,
  isAuthenticatedSessionId,
  mintAuthenticatedSessionId,
  type AbuseControlEnv,
  type HostedAbuseControlPolicy,
} from './abuse-controls';
import { boundaryObjectSchema } from './boundary';
import { exactOperationScopes } from './cloudflare-operation-authority';
import { OAUTH_CALLBACK_URL, PUBLIC_ORIGIN, SESSION_COOKIE } from './constants';
import {
  bootstrapCookie,
  clearBootstrapCookie,
  parseCookies,
  readBootstrapCookie,
  sessionCookie,
} from './cookies';
import {
  constantTimeEqual,
  deriveCsrfToken,
  openHostedStage1Cookie,
  sealHostedStage1Cookie,
  type SealedBootstrapCookie,
} from './crypto';
import { CUSTOMER_BOOTSTRAP_TTL_MS, type BootstrapRandomBytes } from './customer-bootstrap-state';
import { DeployError, stableError, type DeployErrorCode } from './errors';
import { parseExactReleaseBundleIdentity } from './exact-release-bundle';
import { buildHostedBootstrapAuthorizationUrl } from './hosted-bootstrap-grant';
import {
  completeHostedStage1Handoff,
  createHostedStage1Secrets,
  provisionHostedStage1,
  type HostedStage1Provider,
} from './hosted-stage1-bootstrap';
import { executeHostedStage1Cleanup, type HostedStage1CleanupInput } from './hosted-stage1-cleanup';
import {
  HOSTED_STAGE1_SESSION_TTL_MS,
  matchHostedStage1Cookie,
  publicHostedStage1Session,
  type HostedStage1AuthorizationStart,
  type HostedStage1FailureCode,
  type HostedStage1PublicSession,
  type HostedStage1Session,
} from './hosted-stage1-session';
import type { CloudflareOauthConfig, FetchTransport } from './oauth';
import { importOwnershipIssuerKey, type OwnershipIssuerKey } from './ownership-issuer-key';
import {
  PinnedR2ReleaseBundleProvider,
  type PinnedR2Release,
  type R2ReleaseBundleProvider,
  type R2ReleaseReadBucket,
} from './r2-release-provider';
import type { VerifiedReleaseBundle } from './release';
import type { ReviewedGatewayDeployActivation } from './reviewed-activation';
import { buildStaticDeployPlan, parseDeploySelection } from './schema';
import { buildPublicUpdateChannel } from './update-channel';
import {
  buildSignedInstallerAssetResponse,
  createSignedInstallerAssetIndex,
  type SignedInstallerAssetIndex,
} from './signed-installer-assets';
import {
  TwoStageDeploySessionClient,
  type TwoStageDeploySessionNamespace,
} from './two-stage-deploy-session';
import { parseVerifiedReleaseBundle } from './verified-release-bundle';

/**
 * Clean hosted two-stage HTTP runtime for deploy.ankka.ai.
 *
 * It is independent of the legacy installer route graph. There is no
 * discovery grant, no generic provider proxy, and no browser-supplied
 * provider identifier. Every Cloudflare call happens inside the request that
 * owns the encrypted bootstrap cookie, and the Durable Object only records
 * secret-free commitments and read-back identities.
 */

const CALLBACK_PATH = new URL(OAUTH_CALLBACK_URL).pathname;
const BOOTSTRAP_SCOPES = exactOperationScopes('bootstrap');
const PLAN_TTL_MS = 30 * 60 * 1_000;
const PLAN_RENEWAL_MARGIN_MS = 60 * 1_000;
const HANDOFF_RETRY_MS = 3_000;
const MAX_JSON_BYTES = 16 * 1_024;
const SESSION_ID = /^[A-Za-z0-9_-]{43}$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;

/** Token-free public update descriptors read by installed Gateways' updaters. */
const RELEASE_DESCRIPTOR_ROUTES = Object.freeze(['/api/releases/canary', '/api/releases/stable'] as const);
/** One exact manifest path of the pinned bundle; matched by equality, never resolved. */
const RELEASE_FILE_ROUTE = /^\/api\/releases\/(canary|stable)\/files\/(payload\/[A-Za-z0-9][A-Za-z0-9._/-]{0,200})$/u;

/** The complete hosted route allowlist besides signed installer assets. */
export const TWO_STAGE_API_ROUTES = Object.freeze([
  '/health',
  ...RELEASE_DESCRIPTOR_ROUTES,
  '/api/session',
  '/api/selection',
  '/api/plan',
  '/api/bootstrap',
  '/api/bootstrap/handoff',
  '/api/cleanup',
  CALLBACK_PATH,
] as const);

const envSchema = v.object({
  CLOUDFLARE_OAUTH_CLIENT_ID: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{16,128}$/u)),
  CLOUDFLARE_OAUTH_CLIENT_SECRET: v.pipe(v.string(), v.minLength(16), v.maxLength(512)),
  CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{16,128}$/u)),
  DEPLOY_SESSION_ENCRYPTION_KEY: v.pipe(v.string(), v.minLength(32), v.maxLength(64)),
  CLOUDFLARE_OWNERSHIP_ISSUER_PRIVATE_KEY: v.pipe(v.string(), v.regex(TOKEN)),
  CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY: v.pipe(v.string(), v.regex(TOKEN)),
  CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID: v.pipe(v.string(), v.regex(/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u)),
});
const namespaceSchema = v.object({ idFromName: v.function(), get: v.function() });
const releaseBucketSchema = v.object({ get: v.function(), list: v.function() });
const activationSchema = v.union([
  v.strictObject({ enabled: v.literal(false), pin: v.null() }),
  v.strictObject({ enabled: v.literal(true), pin: v.object({}) }),
]);

export interface TwoStageDeployEnv extends AbuseControlEnv {
  TWO_STAGE_DEPLOY_SESSION: TwoStageDeploySessionNamespace;
  /** Private, read-only release bucket. Absent from the disabled config. */
  GATEWAY_RELEASE_BUCKET?: R2ReleaseReadBucket;
  CLOUDFLARE_OAUTH_CLIENT_ID: string;
  CLOUDFLARE_OAUTH_CLIENT_SECRET: string;
  CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID: string;
  CLOUDFLARE_OWNERSHIP_ISSUER_PRIVATE_KEY: string;
  CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY: string;
  CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID: string;
}

export interface TwoStageDeployWorker {
  fetch(request: Request, env: TwoStageDeployEnv): Promise<Response>;
}

/** Exact-root cleanup on a fresh Stage 1 grant; production uses `executeHostedStage1Cleanup`. */
export interface TwoStageCleanupExecutor {
  execute(input: {
    readonly code: string;
    readonly verifier: string;
    readonly oauth: CloudflareOauthConfig;
    readonly transport: FetchTransport;
    readonly session: HostedStage1Session;
    readonly bundle: VerifiedReleaseBundle;
    readonly customerOauthClientId: string;
    readonly issuerKeyId: string;
    readonly issuerPublicKey: string;
    readonly now: () => number;
  }): Promise<void>;
}

export interface TwoStageRuntimeDependencies {
  readonly now?: () => number;
  readonly randomBytes?: BootstrapRandomBytes;
  readonly transport?: FetchTransport;
  readonly abuseControlPolicy?: HostedAbuseControlPolicy;
  /** Test seam only; production constructs PinnedR2ReleaseBundleProvider. */
  readonly releaseBundleProvider?: R2ReleaseBundleProvider;
  /** Test seam only; production re-hashes all signed UI bytes. */
  readonly createInstallerAssets?: (bundle: VerifiedReleaseBundle) => Promise<SignedInstallerAssetIndex>;
  /** Test seam only; production uses the fixed reviewed provider primitives. */
  readonly stage1Provider?: HostedStage1Provider;
  readonly cleanupExecutor?: TwoStageCleanupExecutor;
}

export interface TwoStagePublicSessionResponse {
  readonly schemaVersion: 1;
  readonly now: number;
  readonly csrfToken: string;
  readonly session: HostedStage1PublicSession;
}

interface ReleaseSnapshot {
  readonly bundle: VerifiedReleaseBundle;
  readonly installerAssets: SignedInstallerAssetIndex;
}

interface RuntimeContext {
  readonly env: TwoStageDeployEnv;
  readonly config: v.InferOutput<typeof envSchema>;
  readonly now: number;
}

interface SessionHandle {
  readonly sessionId: string;
  readonly client: TwoStageDeploySessionClient;
}

/** Test seam carried only when a fake provider is injected. */
interface Stage1ProviderOverride {
  provider?: HostedStage1Provider;
}

interface CallbackQuery {
  readonly state: string;
  readonly code: string | null;
  readonly denied: boolean;
}

const JSON_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  'cache-control': 'no-store',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  'content-type': 'application/json; charset=utf-8',
  'cross-origin-opener-policy': 'same-origin',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
});

function json<Value>(value: Value, status = 200, cookies: readonly string[] = []): Response {
  const headers = new Headers(JSON_HEADERS);
  for (const cookie of cookies) headers.append('set-cookie', cookie);
  return new Response(JSON.stringify(value), { status, headers });
}

function errorResponse<Thrown>(error: Thrown, cookies: readonly string[] = []): Response {
  const stable = stableError(error);
  return json({ code: stable.code }, stable.status, cookies);
}

function redirectToResult(cookies: readonly string[]): Response {
  const headers = new Headers({
    'cache-control': 'no-store',
    location: `${PUBLIC_ORIGIN}/result`,
    'referrer-policy': 'no-referrer',
  });
  for (const cookie of cookies) headers.append('set-cookie', cookie);
  return new Response(null, { status: 303, headers });
}

function boundFetch(): FetchTransport {
  return (input, init) => fetch(input, init);
}

function releaseBucket(env: TwoStageDeployEnv): R2ReleaseReadBucket {
  const bucket = env.GATEWAY_RELEASE_BUCKET;
  if (bucket === undefined || !v.safeParse(releaseBucketSchema, bucket).success) {
    throw new DeployError(503, 'release_unavailable');
  }
  return bucket;
}

function assertExactBundlePin(bundle: VerifiedReleaseBundle, pin: PinnedR2Release): void {
  const parsed = parseVerifiedReleaseBundle(bundle);
  if (
    !Object.isFrozen(bundle) ||
    parsed.channel !== pin.channel ||
    parsed.keyId !== pin.keyId ||
    parsed.publicKey !== pin.publicKey ||
    parsed.manifest.controlPlaneOrigin !== pin.controlPlaneOrigin ||
    parsed.manifest.controlPlaneOrigin !== PUBLIC_ORIGIN ||
    parsed.manifest.release !== pin.release ||
    parsed.manifest.artifact.treeSha256 !== pin.artifactSha256
  ) throw new DeployError(503, 'release_invalid');
}

function createLazyReleaseSnapshot(
  pin: Readonly<PinnedR2Release>,
  provider: R2ReleaseBundleProvider,
  assetFactory: (bundle: VerifiedReleaseBundle) => Promise<SignedInstallerAssetIndex>,
): (env: TwoStageDeployEnv) => Promise<ReleaseSnapshot> {
  let successful: ReleaseSnapshot | null = null;
  let inFlight: Promise<ReleaseSnapshot> | null = null;
  const loadFresh = async (env: TwoStageDeployEnv): Promise<ReleaseSnapshot> => {
    const bundle = await provider.loadVerifiedReleaseBundle(releaseBucket(env));
    assertExactBundlePin(bundle, pin);
    const installerAssets = await assetFactory(bundle);
    if (!Object.isFrozen(installerAssets) || installerAssets.release !== pin.release ||
        installerAssets.artifactSha256 !== pin.artifactSha256) {
      throw new DeployError(503, 'release_invalid');
    }
    return Object.freeze({ bundle, installerAssets });
  };
  return async (env) => {
    if (successful) return successful;
    inFlight ??= loadFresh(env).then((snapshot) => {
      successful = snapshot;
      return snapshot;
    }).finally(() => {
      inFlight = null;
    });
    return inFlight;
  };
}

function uniqueQuery(url: URL, key: string): string | null {
  const values = url.searchParams.getAll(key);
  if (values.length > 1) throw new DeployError(400, 'callback_invalid');
  return values[0] ?? null;
}

function echoedScopeIsExact(value: string): boolean {
  if (value.length > 1_024) return false;
  const values = [...new Set(value.split(/\s+/u).filter(Boolean))].sort();
  const expected = [...BOOTSTRAP_SCOPES].sort();
  return values.length === expected.length && values.every((scope, index) => scope === expected[index]);
}

/** Accepts only `code`, `state`, the echoed exact scope, and the standard denial fields. */
function parseCallbackQuery(url: URL): CallbackQuery {
  const keys = [...url.searchParams.keys()];
  const state = uniqueQuery(url, 'state');
  const code = uniqueQuery(url, 'code');
  const oauthError = uniqueQuery(url, 'error');
  const echoedScope = uniqueQuery(url, 'scope');
  const allowed = code !== null
    ? new Set(['code', 'scope', 'state'])
    : new Set(['error', 'error_description', 'error_uri', 'state']);
  if (
    keys.some((key) => !allowed.has(key)) ||
    state === null || !TOKEN.test(state) ||
    (code === null) === (oauthError === null) ||
    (code !== null && (code.length < 8 || code.length > 4_096)) ||
    (oauthError !== null && (oauthError.length < 1 || oauthError.length > 128)) ||
    (echoedScope !== null && !echoedScopeIsExact(echoedScope))
  ) throw new DeployError(400, 'callback_invalid');
  if (oauthError !== null) return Object.freeze({ state, code: null, denied: true });
  if (code === null) throw new DeployError(400, 'callback_invalid');
  return Object.freeze({ state, code, denied: false });
}

function provisionFailureCode(error: DeployError): HostedStage1FailureCode {
  switch (error.code) {
    case 'oauth_denied':
      return 'authorization_rejected';
    case 'oauth_grant_invalid':
    case 'target_account_ambiguous':
      return 'grant_invalid';
    case 'oauth_revoke_failed':
      return 'revocation_unconfirmed';
    default:
      return 'provision_failed';
  }
}

async function readJsonBody<Schema extends v.GenericSchema>(
  request: Request,
  schema: Schema,
): Promise<v.InferOutput<Schema>> {
  if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
    throw new DeployError(400, 'bad_request');
  }
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_JSON_BYTES) throw new DeployError(413, 'bad_request');
  let decoded: unknown;
  try {
    const text = await request.text();
    if (text.length > MAX_JSON_BYTES) throw new DeployError(413, 'bad_request');
    decoded = JSON.parse(text);
  } catch (error) {
    if (error instanceof DeployError) throw error;
    throw new DeployError(400, 'bad_request');
  }
  const parsed = v.safeParse(schema, decoded);
  if (!parsed.success) throw new DeployError(400, 'bad_request');
  return parsed.output;
}

function bootstrapCookieFor(
  session: HostedStage1Session,
  start: HostedStage1AuthorizationStart,
  capability: Readonly<{
    secret: string; bootstrapNonce: string; ownershipWrapKey: string; bootstrapId: string; expiresAt: number;
  }> | null,
): SealedBootstrapCookie {
  if (session.plan === null) throw new DeployError(500, 'session_invalid');
  return Object.freeze({
    schemaVersion: 10,
    purpose: 'bootstrap',
    kind: start.kind,
    sessionId: session.sessionId,
    attemptId: start.attemptId,
    state: start.state,
    verifier: start.verifier,
    expiresAt: start.expiresAt,
    planId: session.plan.planId,
    planHash: session.plan.planHash,
    capability: capability === null ? null : Object.freeze({
      bootstrapId: capability.bootstrapId,
      capabilitySecret: capability.secret,
      capabilityExpiresAt: capability.expiresAt,
      bootstrapNonce: capability.bootstrapNonce,
      ownershipWrapKey: capability.ownershipWrapKey,
    }),
  });
}

function disabledResponse(request: Request): Response {
  let health = false;
  try {
    health = request.method === 'GET' && new URL(request.url).pathname === '/health';
  } catch {
    // Fixed unavailable response below.
  }
  return json(health ? { ok: true, mutationsEnabled: false } : { code: 'release_unavailable' }, health ? 200 : 503);
}

/** Zero-write shell: touches no binding and answers only health or unavailable. */
export function createDisabledTwoStageShell(): TwoStageDeployWorker {
  return Object.freeze({ fetch: async (request: Request): Promise<Response> => disabledResponse(request) });
}

/**
 * Build the hosted two-stage runtime around one exact code-pinned release.
 * The bundle and installer asset index are loaded lazily and then remain the
 * single immutable snapshot for this isolate.
 */
export function createTwoStageDeployRuntime(
  inputPin: PinnedR2Release,
  dependencies: TwoStageRuntimeDependencies = {},
): TwoStageDeployWorker {
  const pin = parseExactReleaseBundleIdentity(inputPin);
  const now = dependencies.now ?? Date.now;
  const transport = dependencies.transport ?? boundFetch();
  const policy: HostedAbuseControlPolicy = dependencies.abuseControlPolicy ?? 'required';
  const loadSnapshot = createLazyReleaseSnapshot(
    pin,
    dependencies.releaseBundleProvider ?? new PinnedR2ReleaseBundleProvider(pin),
    dependencies.createInstallerAssets ?? createSignedInstallerAssetIndex,
  );
  const cleanupExecutor: TwoStageCleanupExecutor = dependencies.cleanupExecutor ?? Object.freeze({
    execute: async (input: HostedStage1CleanupInput): Promise<void> => {
      await executeHostedStage1Cleanup(input);
    },
  });

  function context(env: TwoStageDeployEnv): RuntimeContext {
    const config = v.safeParse(envSchema, env);
    if (!config.success || !v.safeParse(namespaceSchema, env.TWO_STAGE_DEPLOY_SESSION).success) {
      throw new DeployError(500, 'internal_error', 'runtime_config_invalid');
    }
    const current = now();
    if (!Number.isSafeInteger(current) || current < 0) throw new DeployError(500, 'internal_error');
    return Object.freeze({ env, config: config.output, now: current });
  }

  function oauthConfig(context: RuntimeContext): CloudflareOauthConfig {
    return {
      clientId: context.config.CLOUDFLARE_OAUTH_CLIENT_ID,
      clientSecret: context.config.CLOUDFLARE_OAUTH_CLIENT_SECRET,
    };
  }

  async function issuerKey(context: RuntimeContext): Promise<OwnershipIssuerKey> {
    return importOwnershipIssuerKey({
      privateKeySeed: context.config.CLOUDFLARE_OWNERSHIP_ISSUER_PRIVATE_KEY,
      publicKey: context.config.CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY,
      keyId: context.config.CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID,
    });
  }

  function handle(context: RuntimeContext, sessionId: string): SessionHandle {
    const namespace = context.env.TWO_STAGE_DEPLOY_SESSION;
    return Object.freeze({
      sessionId,
      client: new TwoStageDeploySessionClient(namespace.get(namespace.idFromName(sessionId))),
    });
  }

  async function presentedSessionId(request: Request, context: RuntimeContext): Promise<string | null> {
    const value = parseCookies(request.headers.get('cookie')).get(SESSION_COOKIE) ?? null;
    if (value === null) return null;
    if (!SESSION_ID.test(value)) throw new DeployError(401, 'session_invalid');
    if (policy === 'required' &&
        !await isAuthenticatedSessionId(context.config.DEPLOY_SESSION_ENCRYPTION_KEY, value)) {
      throw new DeployError(401, 'session_invalid');
    }
    return value;
  }

  async function requireSession(request: Request, context: RuntimeContext): Promise<SessionHandle> {
    const sessionId = await presentedSessionId(request, context);
    if (sessionId === null) throw new DeployError(401, 'session_invalid');
    return handle(context, sessionId);
  }

  async function requireMutation(
    request: Request,
    context: RuntimeContext,
    session: SessionHandle,
  ): Promise<void> {
    if (request.headers.get('origin') !== PUBLIC_ORIGIN) throw new DeployError(403, 'origin_invalid');
    const fetchSite = request.headers.get('sec-fetch-site');
    if (fetchSite !== null && fetchSite !== 'same-origin') throw new DeployError(403, 'origin_invalid');
    const presented = request.headers.get('x-csrf-token');
    const expected = await deriveCsrfToken(context.config.DEPLOY_SESSION_ENCRYPTION_KEY, session.sessionId);
    if (presented === null || !TOKEN.test(presented) || !constantTimeEqual(presented, expected)) {
      throw new DeployError(403, 'csrf_invalid');
    }
    if (policy === 'required') await enforceSessionMutationRateLimit(request, context.env, session.sessionId);
  }

  async function publicResponse(
    context: RuntimeContext,
    session: SessionHandle,
    state: HostedStage1Session,
    cookies: readonly string[] = [],
  ): Promise<Response> {
    const body: TwoStagePublicSessionResponse = Object.freeze({
      schemaVersion: 1,
      now: context.now,
      csrfToken: await deriveCsrfToken(context.config.DEPLOY_SESSION_ENCRYPTION_KEY, session.sessionId),
      session: publicHostedStage1Session(state),
    });
    return json(body, 200, cookies);
  }

  async function freshSession(request: Request, context: RuntimeContext): Promise<Response> {
    if (policy === 'required') await enforceAnonymousSessionRateLimit(request, context.env);
    const sessionId = await mintAuthenticatedSessionId(context.config.DEPLOY_SESSION_ENCRYPTION_KEY);
    const session = handle(context, sessionId);
    const state = await session.client.initialize();
    return publicResponse(context, session, state, [
      sessionCookie(sessionId, Math.ceil(HOSTED_STAGE1_SESSION_TTL_MS / 1_000)),
    ]);
  }

  async function getSession(request: Request, context: RuntimeContext): Promise<Response> {
    const sessionId = await presentedSessionId(request, context);
    if (sessionId === null) return freshSession(request, context);
    if (policy === 'required') await enforceSessionReadRateLimit(context.env, sessionId);
    const session = handle(context, sessionId);
    const state = await session.client.read();
    if (state === null) return freshSession(request, context);
    if (state.phase !== 'cleanup_required' && state.expiresAt <= context.now) {
      return freshSession(request, context);
    }
    return publicResponse(context, session, state);
  }

  async function putSelection(request: Request, context: RuntimeContext): Promise<Response> {
    const session = await requireSession(request, context);
    await requireMutation(request, context, session);
    const selection = parseDeploySelection(await readJsonBody(request, boundaryObjectSchema));
    const state = await session.client.saveSelection(selection);
    return publicResponse(context, session, state);
  }

  async function freezePlanFor(
    context: RuntimeContext,
    session: SessionHandle,
    current: HostedStage1Session,
  ): Promise<HostedStage1Session> {
    if (current.selection === null) throw new DeployError(409, 'session_conflict', 'selection_missing');
    const snapshot = await loadSnapshot(context.env);
    const plan = await buildStaticDeployPlan(current.selection, snapshot.bundle.manifest, context.now + PLAN_TTL_MS);
    return session.client.freezePlan(plan);
  }

  async function postPlan(request: Request, context: RuntimeContext): Promise<Response> {
    const session = await requireSession(request, context);
    await requireMutation(request, context, session);
    const current = await session.client.read();
    if (current === null) throw new DeployError(404, 'session_invalid');
    return publicResponse(context, session, await freezePlanFor(context, session, current));
  }

  async function postBootstrap(request: Request, context: RuntimeContext): Promise<Response> {
    const session = await requireSession(request, context);
    await requireMutation(request, context, session);
    let current = await session.client.read();
    if (current === null) throw new DeployError(404, 'session_invalid');
    if (current.plan === null) throw new DeployError(409, 'session_conflict', 'plan_missing');
    if (current.plan.expiresAt < context.now + CUSTOMER_BOOTSTRAP_TTL_MS + PLAN_RENEWAL_MARGIN_MS) {
      current = await freezePlanFor(context, session, current);
    }
    const secrets = await createHostedStage1Secrets({ now: context.now, randomBytes: dependencies.randomBytes });
    const start = await session.client.authorizeBootstrap(secrets.capability);
    const sealed = await sealHostedStage1Cookie(
      context.config.DEPLOY_SESSION_ENCRYPTION_KEY,
      bootstrapCookieFor(start.next, start, {
        secret: secrets.capability.secret,
        bootstrapId: secrets.capability.bootstrapId,
        expiresAt: secrets.capability.expiresAt,
        bootstrapNonce: secrets.bootstrapNonce,
        ownershipWrapKey: secrets.ownershipWrapKey,
      }),
      context.now,
    );
    const authorizationUrl = buildHostedBootstrapAuthorizationUrl({
      clientId: context.config.CLOUDFLARE_OAUTH_CLIENT_ID,
      state: start.state,
      challenge: start.challenge,
    });
    return json({
      schemaVersion: 1,
      authorizationUrl,
      expiresAt: start.expiresAt,
      session: publicHostedStage1Session(start.next),
    }, 200, [bootstrapCookie(sealed, Math.ceil((start.expiresAt - context.now) / 1_000))]);
  }

  async function postCleanup(request: Request, context: RuntimeContext): Promise<Response> {
    const session = await requireSession(request, context);
    await requireMutation(request, context, session);
    const start = await session.client.authorizeCleanup();
    const sealed = await sealHostedStage1Cookie(
      context.config.DEPLOY_SESSION_ENCRYPTION_KEY,
      bootstrapCookieFor(start.next, start, null),
      context.now,
    );
    const authorizationUrl = buildHostedBootstrapAuthorizationUrl({
      clientId: context.config.CLOUDFLARE_OAUTH_CLIENT_ID,
      state: start.state,
      challenge: start.challenge,
    });
    return json({
      schemaVersion: 1,
      authorizationUrl,
      expiresAt: start.expiresAt,
      session: publicHostedStage1Session(start.next),
    }, 200, [bootstrapCookie(sealed, Math.ceil((start.expiresAt - context.now) / 1_000))]);
  }

  async function openCookie(request: Request, context: RuntimeContext): Promise<SealedBootstrapCookie> {
    const sealed = readBootstrapCookie(request);
    if (sealed === null) throw new DeployError(400, 'callback_invalid', 'bootstrap_cookie_missing');
    return openHostedStage1Cookie(context.config.DEPLOY_SESSION_ENCRYPTION_KEY, sealed, context.now);
  }

  async function oauthCallback(request: Request, context: RuntimeContext): Promise<Response> {
    const cleared = [clearBootstrapCookie()];
    const query = parseCallbackQuery(new URL(request.url));
    const cookie = await openCookie(request, context);
    if (!constantTimeEqual(query.state, cookie.state)) throw new DeployError(400, 'callback_invalid');
    const session = await requireSession(request, context);
    const current = await session.client.read();
    if (current === null) throw new DeployError(404, 'session_invalid');
    const match = await matchHostedStage1Cookie({ current, cookie, now: context.now });
    if (match.phase === 'provisioned') throw new DeployError(409, 'callback_invalid');
    const consumed = await session.client.consumeCallback({
      attemptId: match.attemptId,
      state: cookie.state,
      verifier: cookie.verifier,
    });
    if (query.denied || query.code === null) {
      await session.client.failAttempt({ attemptId: match.attemptId, code: 'authorization_rejected' });
      return redirectToResult(cleared);
    }
    if (cookie.kind === 'cleanup') {
      const snapshot = await loadSnapshot(context.env);
      try {
        await cleanupExecutor.execute({
          code: query.code,
          verifier: cookie.verifier,
          oauth: oauthConfig(context),
          transport,
          session: consumed,
          bundle: snapshot.bundle,
          customerOauthClientId: context.config.CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID,
          issuerKeyId: context.config.CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID,
          issuerPublicKey: context.config.CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY,
          now,
        });
      } catch {
        await session.client.failAttempt({ attemptId: match.attemptId, code: 'cleanup_failed' });
        return redirectToResult(cleared);
      }
      await session.client.completeCleanup(match.attemptId);
      return redirectToResult(cleared);
    }
    if (cookie.capability === null || consumed.plan === null) throw new DeployError(400, 'callback_invalid');
    const snapshot = await loadSnapshot(context.env);
    const issuer = await issuerKey(context);
    let provisionError: DeployError | null = null;
    const providerOverride: Stage1ProviderOverride = {};
    if (dependencies.stage1Provider !== undefined) providerOverride.provider = dependencies.stage1Provider;
    try {
      const provision = await provisionHostedStage1({
        code: query.code,
        verifier: cookie.verifier,
        oauth: oauthConfig(context),
        transport,
        bundle: snapshot.bundle,
        plan: consumed.plan,
        secrets: {
          capability: {
            bootstrapId: cookie.capability.bootstrapId,
            secret: cookie.capability.capabilitySecret,
            secretCommitment: `sha256:${await sha256HexOf(cookie.capability.capabilitySecret)}`,
            expiresAt: cookie.capability.capabilityExpiresAt,
          },
          bootstrapNonce: cookie.capability.bootstrapNonce,
          ownershipWrapKey: cookie.capability.ownershipWrapKey,
        },
        customerOauthClientId: context.config.CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID,
        issuerKeyId: issuer.keyId,
        issuerPublicKey: issuer.publicKey,
        issuerPrivateKey: issuer.privateKey,
        now,
        ...providerOverride,
      });
      await session.client.recordProvision({ attemptId: match.attemptId, provision });
    } catch (error) {
      provisionError = stableError(error);
    }
    if (provisionError !== null) {
      await session.client.failAttempt({
        attemptId: match.attemptId,
        code: provisionFailureCode(provisionError),
        reason: provisionError.reason ?? provisionError.code,
      });
      return redirectToResult(cleared);
    }
    // The cookie stays: it still holds the capability for the token-free handoff.
    return redirectToResult([]);
  }

  /**
   * Names the handoff step an unexpected error escaped from, so the operator
   * reads "handoff_<step>_<kind>" instead of a bare internal_error. Stable
   * DeployErrors pass through untouched.
   */
  async function handoffStep<T>(step: string, run: () => Promise<T>): Promise<T> {
    try {
      return await run();
    } catch (error) {
      if (error instanceof DeployError) throw error;
      const kind = error instanceof Error && error.name === 'ValiError' ? 'schema' : 'unexpected';
      throw new DeployError(500, 'internal_error', `handoff_${step}_${kind}`);
    }
  }

  async function getHandoff(request: Request, context: RuntimeContext): Promise<Response> {
    const cleared = [clearBootstrapCookie()];
    const session = await requireSession(request, context);
    if (policy === 'required') await enforceSessionReadRateLimit(context.env, session.sessionId);
    const cookie = await handoffStep('cookie', () => openCookie(request, context));
    const current = await handoffStep('session_read', () => session.client.read());
    if (current === null) throw new DeployError(404, 'session_invalid');
    const match = await handoffStep('cookie_match', () => matchHostedStage1Cookie({ current, cookie, now: context.now }));
    if (match.phase !== 'provisioned' || current.provision === null || current.plan === null ||
        cookie.capability === null) {
      throw new DeployError(409, 'session_conflict', 'handoff_not_provisioned');
    }
    const issuer = await handoffStep('issuer_key', () => issuerKey(context));
    const provision = current.provision;
    const plan = current.plan;
    const capability = cookie.capability;
    try {
      const handoff = await handoffStep('complete', () => completeHostedStage1Handoff({
        provision,
        plan,
        capabilitySecret: capability.capabilitySecret,
        customerOauthClientId: context.config.CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID,
        issuerKeyId: issuer.keyId,
        issuerPublicKey: issuer.publicKey,
        issuerPrivateKey: issuer.privateKey,
        transport,
        now,
      }));
      await handoffStep('mark', () => session.client.markHandedOff({
        bootstrapId: provision.bootstrapId,
        secretCommitment: provision.bootstrapSecretCommitment,
      }));
      return json({
        schemaVersion: 1,
        status: 'ready',
        handoffUrl: handoff.handoffUrl,
        bootstrapOrigin: handoff.bootstrapOrigin,
        expiresAt: handoff.expiresAt,
      }, 200, cleared);
    } catch (error) {
      const stable = stableError(error);
      if (stable.code === 'bootstrap_not_ready') {
        // The installer page keeps polling only on a body whose `code` says
        // so; without it the page read every not-ready poll as an internal
        // error and stopped, which every fresh shell's route propagation hit.
        return json({
          schemaVersion: 1,
          code: 'bootstrap_not_ready',
          status: 'not_ready',
          retryAfterMs: HANDOFF_RETRY_MS,
          expiresAt: provision.capabilityExpiresAt,
          reason: stable.reason,
        }, 503);
      }
      if (stable.code === 'bootstrap_failed') {
        await session.client.requireCleanup('handoff_rejected');
        return json(
          stable.reason === null ? { code: stable.code } : { code: stable.code, reason: stable.reason },
          stable.status,
          cleared,
        );
      }
      throw stable;
    }
  }

  async function route(request: Request, env: TwoStageDeployEnv): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    if (request.method === 'GET' && path === '/health') {
      return json({ ok: true, mutationsEnabled: true });
    }
    const isApi = TWO_STAGE_API_ROUTES.some((candidate) => candidate === path) || path === '/api' || path.startsWith('/api/');
    if (!isApi) {
      const snapshot = await loadSnapshot(env);
      return buildSignedInstallerAssetResponse(snapshot.installerAssets, request);
    }
    if (path !== CALLBACK_PATH && url.search !== '') throw new DeployError(404, 'bad_request');
    if (request.method === 'GET' && RELEASE_DESCRIPTOR_ROUTES.some((candidate) => candidate === path)) {
      // Served from the pinned bundle alone, before any binding besides the
      // bucket is read, so an installed Gateway can discover updates even
      // while the hosted install flow itself is unavailable.
      const channel = buildPublicUpdateChannel((await loadSnapshot(env)).bundle);
      if (path !== `/api/releases/${channel.channel}`) throw new DeployError(404, 'release_unavailable');
      return json(channel);
    }
    const releaseFile = RELEASE_FILE_ROUTE.exec(path);
    if (releaseFile !== null) {
      if (request.method !== 'GET') throw new DeployError(405, 'bad_request');
      // The pinned bundle's own bytes, for an installed Gateway that updates
      // itself: it fetched the signed manifest first and verifies every file
      // against it, so this route needs no session, grant, or other binding.
      const [, channelName = '', filePath = ''] = releaseFile;
      const snapshot = await loadSnapshot(env);
      const channel = buildPublicUpdateChannel(snapshot.bundle);
      const file = snapshot.bundle.payload.find((entry) => entry.path === filePath);
      if (channelName !== channel.channel || file === undefined) throw new DeployError(404, 'release_unavailable');
      return new Response(file.bytes, {
        headers: {
          'cache-control': 'no-store',
          'content-length': String(file.byteSize),
          'content-type': file.contentType,
          'x-content-type-options': 'nosniff',
        },
      });
    }
    const runtime = context(env);
    switch (`${request.method} ${path}`) {
      case 'GET /api/session':
        return getSession(request, runtime);
      case 'PUT /api/selection':
        return putSelection(request, runtime);
      case 'POST /api/plan':
        return postPlan(request, runtime);
      case 'POST /api/bootstrap':
        return postBootstrap(request, runtime);
      case 'POST /api/cleanup':
        return postCleanup(request, runtime);
      case `GET ${CALLBACK_PATH}`:
        return oauthCallback(request, runtime);
      case 'GET /api/bootstrap/handoff':
        return getHandoff(request, runtime);
      default:
        throw new DeployError(TWO_STAGE_API_ROUTES.some((candidate) => candidate === path) ? 405 : 404, 'bad_request');
    }
  }

  return Object.freeze({
    async fetch(request: Request, env: TwoStageDeployEnv): Promise<Response> {
      try {
        return await route(request, env);
      } catch (error) {
        const stable = stableError(error);
        // A malformed or expired cookie is cleared; a 409 replay after provisioning keeps it for the handoff.
        const clearsCookie = stable.status === 400 &&
          (stable.code === 'callback_invalid' || stable.code === 'session_expired');
        return errorResponse(stable, clearsCookie ? [clearBootstrapCookie()] : []);
      }
    },
  });
}

async function sha256HexOf(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
  return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Production-facing entrypoint factory. The disabled arm reads no dependency,
 * binding, or release and answers only health or unavailable.
 */
export function createTwoStageDeployEntrypoint(
  inputActivation: ReviewedGatewayDeployActivation,
  dependencies?: TwoStageRuntimeDependencies,
): TwoStageDeployWorker {
  const activation = v.safeParse(activationSchema, inputActivation);
  if (!activation.success) throw new DeployError(503, 'release_invalid');
  if (!activation.output.enabled) return createDisabledTwoStageShell();
  return createTwoStageDeployRuntime(parseExactReleaseBundleIdentity(activation.output.pin), dependencies);
}

export type { DeployErrorCode };
