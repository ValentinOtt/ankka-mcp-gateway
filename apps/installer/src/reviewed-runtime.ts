import { OAUTH_CALLBACK_URL, PUBLIC_ORIGIN } from './constants';
import type { GatewayDeployEnv } from './env';
import { DeployError, stableError } from './errors';
import type { ExactReleaseBundleIdentity } from './exact-release-bundle';
import {
  createGatewayDeployWorker,
  type GatewayDeployWorker,
  type GatewayDeployWorkerDependencies,
} from './index';
import type { InstallExecutionInput, InstallExecutor } from './install-executor';
import type { UninstallExecutionInput, UninstallExecutor } from './uninstall-executor';
import type { FetchTransport } from './oauth';
import {
  ExactR2ReleaseBundleProvider,
  PinnedR2ReleaseBundleProvider,
  type PinnedR2Release,
  type R2ExactReleaseBundleProvider,
  type R2ReleaseBundleProvider,
} from './r2-release-provider';
import {
  RELEASE_ENVELOPE_SCHEMA_VERSION,
  RELEASE_SIGNATURE_CONTEXT,
  type ReleaseBundleProvider,
  type VerifiedReleaseBundle,
} from './release';
import { canonicalJson } from './release-manifest';
import type { ReviewedGatewayDeployActivation } from './reviewed-activation';
import {
  createCloudflareReviewedInstallProviderAdapter,
  executeReviewedInstall,
  type ReviewedInstallExecutionInput,
  type ReviewedInstallExecutionResult,
  type ReviewedInstallProviderAdapter,
  type ReviewedInstallTransport,
} from './reviewed-install-executor';
import {
  createCloudflareReviewedUninstallProviderAdapter,
  executeReviewedUninstall,
  type ReviewedUninstallExecutionInput,
  type ReviewedUninstallProviderAdapter,
} from './reviewed-uninstall-executor';
import { ReviewedReturningUninstallExecutor } from './reviewed-returning-uninstall-executor';
import {
  buildSignedInstallerAssetResponse,
  createSignedInstallerAssetIndex,
  type SignedInstallerAssetIndex,
} from './signed-installer-assets';
import { streamingInstallCallbackResponse } from './streaming-callback';

const CALLBACK_PATH = new URL(OAUTH_CALLBACK_URL).pathname;
const PIN_KEYS = Object.freeze([
  'artifactSha256',
  'channel',
  'keyId',
  'publicKey',
  'release',
  'schemaVersion',
] as const);

export interface ReviewedGatewayDeployEnv extends GatewayDeployEnv {
  /** Private, read-only release bucket. It is absent from the disabled config. */
  GATEWAY_RELEASE_BUCKET?: R2Bucket;
}

export interface ReviewedGatewayDeployWorker {
  fetch(
    request: Request,
    env: ReviewedGatewayDeployEnv,
    context?: ExecutionContext,
  ): Promise<Response>;
}

interface ReviewedReleaseSnapshot {
  readonly bundle: VerifiedReleaseBundle;
  readonly installerAssets: SignedInstallerAssetIndex;
}

type ReviewedExecutor = (
  input: ReviewedInstallExecutionInput,
) => Promise<ReviewedInstallExecutionResult>;

type ReviewedUninstallExecutor = (
  input: ReviewedUninstallExecutionInput,
) => ReturnType<typeof executeReviewedUninstall>;

export type ReviewedRuntimeTransport = FetchTransport & ReviewedInstallTransport;

/** A receiver-independent wrapper around the global fetch. */
export function boundGlobalFetch(): (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> {
  return (input, init) => fetch(input, init);
}

export interface ReviewedRuntimeDependencies {
  readonly now?: () => number;
  readonly transport?: ReviewedRuntimeTransport;
  readonly timeoutMs?: number;
  readonly randomBytes?: (length: number) => Uint8Array;
  /** Test seam only; production constructs PinnedR2ReleaseBundleProvider. */
  readonly releaseBundleProvider?: R2ReleaseBundleProvider;
  /** Test seam only; production resolves historical releases from the same create-only bucket. */
  readonly exactReleaseBundleProvider?: R2ExactReleaseBundleProvider;
  /** Test seam only; production uses the stateless Cloudflare adapter. */
  readonly providerAdapter?: ReviewedInstallProviderAdapter;
  /** Test seam only; production uses the stateless reviewed uninstall adapter. */
  readonly uninstallProviderAdapter?: ReviewedUninstallProviderAdapter;
  /** Test seam proving execution remains owned by the connected callback request. */
  readonly execute?: ReviewedExecutor;
  /** Test seam proving uninstall execution remains awaited in the callback request. */
  readonly executeUninstall?: ReviewedUninstallExecutor;
  /** Test seam for cache behavior; production re-hashes all signed UI bytes. */
  readonly createInstallerAssets?: (
    bundle: VerifiedReleaseBundle,
  ) => Promise<SignedInstallerAssetIndex>;
}

export interface SynchronousReviewedExecutorDependencies {
  readonly providerAdapter: ReviewedInstallProviderAdapter;
  readonly transport: ReviewedRuntimeTransport;
  readonly execute: ReviewedExecutor;
  readonly timeoutMs?: number;
  readonly now?: () => number;
  readonly randomBytes?: (length: number) => Uint8Array;
}

export interface SynchronousReviewedUninstallExecutorDependencies {
  readonly providerAdapter: ReviewedUninstallProviderAdapter;
  readonly transport: ReviewedRuntimeTransport;
  readonly execute: ReviewedUninstallExecutor;
  readonly timeoutMs?: number;
  readonly now?: () => number;
  readonly randomBytes?: (length: number) => Uint8Array;
}

function invalid(): never {
  throw new DeployError(503, 'release_invalid');
}

function unavailable(): never {
  throw new DeployError(503, 'release_unavailable');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function exactPin(pin: PinnedR2Release): Readonly<PinnedR2Release> {
  // The provider constructor owns the complete format validation. Constructing
  // it here also validates pins when a test-only provider seam is injected.
  new PinnedR2ReleaseBundleProvider(pin);
  if (!isRecord(pin) || !exactKeys(pin, PIN_KEYS)) invalid();
  return Object.freeze({ ...pin });
}

function assertExactBundlePin(bundle: VerifiedReleaseBundle, pin: PinnedR2Release): void {
  if (
    !Object.isFrozen(bundle) ||
    bundle.verification !== 'ed25519' ||
    bundle.channel !== pin.channel ||
    bundle.keyId !== pin.keyId ||
    bundle.publicKey !== pin.publicKey ||
    !isRecord(bundle.envelope) ||
    !Object.isFrozen(bundle.envelope) ||
    !exactKeys(bundle.envelope as unknown as Record<string, unknown>, [
      'channel', 'keyId', 'manifest', 'schemaVersion', 'signature', 'signatureContext',
    ]) ||
    bundle.envelope.schemaVersion !== RELEASE_ENVELOPE_SCHEMA_VERSION ||
    bundle.envelope.channel !== pin.channel ||
    bundle.envelope.keyId !== pin.keyId ||
    bundle.envelope.manifest !== canonicalJson(bundle.manifest) ||
    !/^[A-Za-z0-9_-]{86}$/u.test(bundle.envelope.signature) ||
    bundle.envelope.signatureContext !== RELEASE_SIGNATURE_CONTEXT ||
    bundle.manifest.release !== pin.release ||
    bundle.manifest.artifact.treeSha256 !== pin.artifactSha256 ||
    !Array.isArray(bundle.payload) ||
    !Object.isFrozen(bundle.payload)
  ) invalid();
}

function assertExactAssetPin(index: SignedInstallerAssetIndex, pin: PinnedR2Release): void {
  if (
    !Object.isFrozen(index) ||
    index.release !== pin.release ||
    index.artifactSha256 !== pin.artifactSha256
  ) invalid();
}

function releaseBucket(env: ReviewedGatewayDeployEnv): R2Bucket {
  const bucket = env.GATEWAY_RELEASE_BUCKET;
  if (!bucket || typeof bucket.get !== 'function' || typeof bucket.list !== 'function') unavailable();
  return bucket;
}

function createLazyReleaseSnapshot(
  pin: Readonly<PinnedR2Release>,
  provider: R2ReleaseBundleProvider,
  assetFactory: (bundle: VerifiedReleaseBundle) => Promise<SignedInstallerAssetIndex>,
): {
  readonly load: (env: ReviewedGatewayDeployEnv) => Promise<ReviewedReleaseSnapshot>;
} {
  let successful: ReviewedReleaseSnapshot | null = null;
  let inFlight: Promise<ReviewedReleaseSnapshot> | null = null;

  const loadFresh = async (env: ReviewedGatewayDeployEnv): Promise<ReviewedReleaseSnapshot> => {
    const bundle = await provider.loadVerifiedReleaseBundle(releaseBucket(env));
    assertExactBundlePin(bundle, pin);
    const installerAssets = await assetFactory(bundle);
    assertExactBundlePin(bundle, pin);
    assertExactAssetPin(installerAssets, pin);
    return Object.freeze({ bundle, installerAssets });
  };

  return Object.freeze({
    async load(env: ReviewedGatewayDeployEnv): Promise<ReviewedReleaseSnapshot> {
      if (successful) {
        assertExactBundlePin(successful.bundle, pin);
        assertExactAssetPin(successful.installerAssets, pin);
        return successful;
      }
      if (!inFlight) {
        inFlight = loadFresh(env).then((snapshot) => {
          successful = snapshot;
          return snapshot;
        }).finally(() => {
          inFlight = null;
        });
      }
      return inFlight;
    },
  });
}

function protectedCorePath(pathname: string): boolean {
  return pathname === '/health' ||
    pathname === '/api' ||
    pathname.startsWith('/api/') ||
    pathname === CALLBACK_PATH;
}

function runtimeErrorResponse(error: unknown): Response {
  const stable = stableError(error);
  const headers = new Headers({
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    'content-type': 'application/json; charset=utf-8',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  });
  return new Response(JSON.stringify({ code: stable.code }), { status: stable.status, headers });
}

function disabledReviewedResponse(request: Request): Response {
  const headers = new Headers({
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    'content-type': 'application/json; charset=utf-8',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  });
  let health = false;
  try {
    health = request.method === 'GET' && new URL(request.url).pathname === '/health';
  } catch {
    // Fixed unavailable response below.
  }
  return new Response(JSON.stringify(health
    ? { ok: true, mutationsEnabled: false }
    : { code: 'release_unavailable' }), {
    status: health ? 200 : 503,
    headers,
  });
}

function createDisabledReviewedShell(): ReviewedGatewayDeployWorker {
  return Object.freeze({
    fetch: async (request: Request): Promise<Response> => disabledReviewedResponse(request),
  });
}

function disabledActivation(activation: ReviewedGatewayDeployActivation): boolean {
  const value: unknown = activation;
  if (!isRecord(value) || !exactKeys(value, ['enabled', 'pin'])) invalid();
  if (value.enabled === false && value.pin === null) return true;
  if (value.enabled !== true || !isRecord(value.pin)) invalid();
  return false;
}

/** Direct, awaited adapter: no queue, waitUntil, alarm, or credential capture. */
export function createSynchronousReviewedInstallExecutor(
  dependencies: SynchronousReviewedExecutorDependencies,
): InstallExecutor {
  return Object.freeze({
    execute: (input: InstallExecutionInput) => dependencies.execute({
      ...input,
      provider: dependencies.providerAdapter,
      transport: dependencies.transport,
      ...(dependencies.timeoutMs === undefined ? {} : { timeoutMs: dependencies.timeoutMs }),
      ...(dependencies.now === undefined ? {} : { now: dependencies.now }),
      ...(dependencies.randomBytes === undefined ? {} : { randomBytes: dependencies.randomBytes }),
    }),
  });
}

/** Direct, awaited uninstall adapter: no queue, waitUntil, alarm, or credential capture. */
export function createSynchronousReviewedUninstallExecutor(
  dependencies: SynchronousReviewedUninstallExecutorDependencies,
): UninstallExecutor {
  return Object.freeze({
    execute: (input: UninstallExecutionInput) => dependencies.execute({
      ...input,
      provider: dependencies.providerAdapter,
      transport: dependencies.transport,
      ...(dependencies.timeoutMs === undefined ? {} : { timeoutMs: dependencies.timeoutMs }),
      ...(dependencies.now === undefined ? {} : { now: dependencies.now }),
      ...(dependencies.randomBytes === undefined ? {} : { randomBytes: dependencies.randomBytes }),
    }),
  });
}

/**
 * Build the reviewed runtime around one exact code-pinned release. The release
 * and installer asset index are loaded lazily and, after the first successful
 * verification, remain the single immutable snapshot for this Worker isolate.
 */
export function createReviewedGatewayDeployRuntime(
  inputPin: PinnedR2Release,
  dependencies: ReviewedRuntimeDependencies = {},
): ReviewedGatewayDeployWorker {
  const pin = exactPin(inputPin);
  // Never hand out the bare global `fetch`: call sites invoke the transport
  // as a method (`input.transport(...)`), and workerd's `fetch` throws
  // "Illegal invocation" when called with a foreign receiver. Node ignores the
  // receiver, so only a live Worker exposes the difference.
  const transport = (dependencies.transport ?? boundGlobalFetch()) as ReviewedRuntimeTransport;
  const bundleProvider = dependencies.releaseBundleProvider ?? new PinnedR2ReleaseBundleProvider(pin);
  const exactBundleProvider = dependencies.exactReleaseBundleProvider ?? new ExactR2ReleaseBundleProvider();
  const assetFactory = dependencies.createInstallerAssets ?? createSignedInstallerAssetIndex;
  const snapshot = createLazyReleaseSnapshot(pin, bundleProvider, assetFactory);
  const providerAdapter = dependencies.providerAdapter ?? createCloudflareReviewedInstallProviderAdapter();
  const uninstallProviderAdapter = dependencies.uninstallProviderAdapter ??
    createCloudflareReviewedUninstallProviderAdapter();
  const execute = dependencies.execute ?? executeReviewedInstall;
  const executeUninstall = dependencies.executeUninstall ?? executeReviewedUninstall;

  const releaseProvider: ReleaseBundleProvider = Object.freeze({
    async loadVerifiedRelease(env: GatewayDeployEnv): Promise<VerifiedReleaseBundle> {
      return (await snapshot.load(env as ReviewedGatewayDeployEnv)).bundle;
    },
    async loadVerifiedReleaseBundle(env: GatewayDeployEnv): Promise<VerifiedReleaseBundle> {
      return (await snapshot.load(env as ReviewedGatewayDeployEnv)).bundle;
    },
  });
  const installExecutor = createSynchronousReviewedInstallExecutor({
    providerAdapter,
    transport,
    execute,
    ...(dependencies.timeoutMs === undefined ? {} : { timeoutMs: dependencies.timeoutMs }),
    ...(dependencies.now === undefined ? {} : { now: dependencies.now }),
    ...(dependencies.randomBytes === undefined ? {} : { randomBytes: dependencies.randomBytes }),
  });
  const uninstallExecutor = createSynchronousReviewedUninstallExecutor({
    providerAdapter: uninstallProviderAdapter,
    transport,
    execute: executeUninstall,
    ...(dependencies.timeoutMs === undefined ? {} : { timeoutMs: dependencies.timeoutMs }),
    ...(dependencies.now === undefined ? {} : { now: dependencies.now }),
    ...(dependencies.randomBytes === undefined ? {} : { randomBytes: dependencies.randomBytes }),
  });
  const coreDependencies: GatewayDeployWorkerDependencies = {
    abuseControlPolicy: 'required',
    releaseProvider,
    exactReleaseProvider: Object.freeze({
      loadVerifiedReleaseBundleForIdentity: (
        env: GatewayDeployEnv,
        identity: ExactReleaseBundleIdentity,
      ) => (
        exactBundleProvider.loadVerifiedReleaseBundleForIdentity(
          releaseBucket(env as ReviewedGatewayDeployEnv),
          identity,
        )
      ),
    }),
    installExecutor,
    uninstallExecutor,
    returningUninstallExecutor: new ReviewedReturningUninstallExecutor(),
    transport,
    capabilityPolicy: Object.freeze({ deploy: true, uninstall: true, events: false }),
    installCallbackResponse: async ({ env, context, execute }) => {
      const loaded = await snapshot.load(env as ReviewedGatewayDeployEnv);
      const shell = buildSignedInstallerAssetResponse(
        loaded.installerAssets,
        new Request(`${PUBLIC_ORIGIN}/result`),
      );
      return streamingInstallCallbackResponse(shell, execute, {
        ...(context === undefined ? {} : { context }),
      });
    },
    managementCallbackResponse: async ({ env, context, execute }) => {
      const loaded = await snapshot.load(env as ReviewedGatewayDeployEnv);
      const shell = buildSignedInstallerAssetResponse(
        loaded.installerAssets,
        new Request(`${PUBLIC_ORIGIN}/manage`),
      );
      return streamingInstallCallbackResponse(shell, execute, {
        ...(context === undefined ? {} : { context }),
      });
    },
    ...(dependencies.now === undefined ? {} : { now: dependencies.now }),
  };
  const core: GatewayDeployWorker = createGatewayDeployWorker(coreDependencies);

  return Object.freeze({
    async fetch(
      request: Request,
      env: ReviewedGatewayDeployEnv,
      context?: ExecutionContext,
    ): Promise<Response> {
      let pathname: string;
      try {
        pathname = new URL(request.url).pathname;
      } catch (error) {
        return runtimeErrorResponse(error);
      }
      if (protectedCorePath(pathname)) return core.fetch(request, env, context);
      try {
        const loaded = await snapshot.load(env);
        return buildSignedInstallerAssetResponse(loaded.installerAssets, request);
      } catch (error) {
        return runtimeErrorResponse(error);
      }
    },
  });
}

/**
 * Production-facing entrypoint factory. The disabled arm does not read runtime
 * dependencies, instantiate the reviewed adapter, or require an R2 binding.
 */
export function createReviewedGatewayDeployEntrypoint(
  activation: ReviewedGatewayDeployActivation,
  dependencies?: ReviewedRuntimeDependencies,
): ReviewedGatewayDeployWorker {
  if (disabledActivation(activation)) {
    return createDisabledReviewedShell();
  }
  if (activation.pin === null) invalid();
  return createReviewedGatewayDeployRuntime(activation.pin, dependencies);
}
