import * as v from 'valibot';

import { boundaryObjectSchema } from './boundary';
import { OAUTH_CALLBACK_URL, PUBLIC_ORIGIN } from './constants';
import type { GatewayDeployEnv } from './env';
import { DeployError, stableError } from './errors';
import {
  parseExactReleaseBundleIdentity,
  type ExactReleaseBundleIdentity,
} from './exact-release-bundle';
import {
  createGatewayDeployWorker,
  type GatewayDeployExecutionContext,
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
  type R2ReleaseReadBucket,
} from './r2-release-provider';
import type { ReleaseBundleProvider, VerifiedReleaseBundle } from './release';
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
import { parseVerifiedReleaseBundle } from './verified-release-bundle';

const CALLBACK_PATH = new URL(OAUTH_CALLBACK_URL).pathname;
const releaseBucketSchema = v.object({ get: v.function(), list: v.function() });
const reviewedActivationSchema = v.union([
  v.strictObject({ enabled: v.literal(false), pin: v.null() }),
  v.strictObject({ enabled: v.literal(true), pin: boundaryObjectSchema }),
]);

export interface ReviewedGatewayDeployEnv extends GatewayDeployEnv {
  /** Private, read-only release bucket. It is absent from the disabled config. */
  GATEWAY_RELEASE_BUCKET?: R2ReleaseReadBucket;
}

export interface ReviewedGatewayDeployWorker {
  fetch(
    request: Request,
    env: ReviewedGatewayDeployEnv,
    context?: GatewayDeployExecutionContext,
  ): Promise<Response>;
}

interface ReviewedReleaseSnapshot {
  readonly bundle: VerifiedReleaseBundle;
  readonly installerAssets: SignedInstallerAssetIndex;
}

interface LazyReleaseSnapshot {
  readonly load: (env: ReviewedGatewayDeployEnv) => Promise<ReviewedReleaseSnapshot>;
}

interface OptionalExecutionControls {
  now?: () => number;
  randomBytes?: (length: number) => Uint8Array;
  timeoutMs?: number;
}

type ReviewedExecutor = (
  input: ReviewedInstallExecutionInput,
) => Promise<ReviewedInstallExecutionResult>;

type ReviewedUninstallExecutor = (
  input: ReviewedUninstallExecutionInput,
) => ReturnType<typeof executeReviewedUninstall>;

export type ReviewedRuntimeTransport = FetchTransport & ReviewedInstallTransport;

/** A receiver-independent wrapper around the global fetch. */
export function boundGlobalFetch(): ReviewedRuntimeTransport {
  function transport(request: Request): Promise<Response>;
  function transport(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  function transport(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    return fetch(input, init);
  }
  return transport;
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

function exactPin(pin: PinnedR2Release): Readonly<PinnedR2Release> {
  return parseExactReleaseBundleIdentity(pin);
}

function assertExactBundlePin(bundle: VerifiedReleaseBundle, pin: PinnedR2Release): void {
  const parsed = parseVerifiedReleaseBundle(bundle);
  if (
    !Object.isFrozen(bundle) ||
    parsed.channel !== pin.channel ||
    parsed.keyId !== pin.keyId ||
    parsed.publicKey !== pin.publicKey ||
    !Object.isFrozen(bundle.envelope) ||
    parsed.manifest.release !== pin.release ||
    parsed.manifest.artifact.treeSha256 !== pin.artifactSha256 ||
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

function releaseBucket(env: ReviewedGatewayDeployEnv): R2ReleaseReadBucket {
  const bucket = env.GATEWAY_RELEASE_BUCKET;
  if (bucket === undefined || !v.safeParse(releaseBucketSchema, bucket).success) unavailable();
  return bucket;
}

function createLazyReleaseSnapshot(
  pin: Readonly<PinnedR2Release>,
  provider: R2ReleaseBundleProvider,
  assetFactory: (bundle: VerifiedReleaseBundle) => Promise<SignedInstallerAssetIndex>,
): LazyReleaseSnapshot {
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

function runtimeErrorResponse<ErrorValue>(error: ErrorValue): Response {
  const stable = stableError(error instanceof Error ? error : undefined);
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

function parseReviewedActivation<Input>(input: Input): ReviewedGatewayDeployActivation {
  const result = v.safeParse(reviewedActivationSchema, input);
  if (!result.success) invalid();
  if (!result.output.enabled) return Object.freeze({ enabled: false, pin: null });
  return Object.freeze({
    enabled: true,
    pin: parseExactReleaseBundleIdentity(result.output.pin),
  });
}

function optionalExecutionControls(
  dependencies: OptionalExecutionControls,
): OptionalExecutionControls {
  const controls: OptionalExecutionControls = {};
  if (dependencies.timeoutMs !== undefined) controls.timeoutMs = dependencies.timeoutMs;
  if (dependencies.now !== undefined) controls.now = dependencies.now;
  if (dependencies.randomBytes !== undefined) controls.randomBytes = dependencies.randomBytes;
  return controls;
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
      ...optionalExecutionControls(dependencies),
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
      ...optionalExecutionControls(dependencies),
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
  const transport = dependencies.transport ?? boundGlobalFetch();
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
      return (await snapshot.load(env)).bundle;
    },
    async loadVerifiedReleaseBundle(env: GatewayDeployEnv): Promise<VerifiedReleaseBundle> {
      return (await snapshot.load(env)).bundle;
    },
  });
  const installExecutor = createSynchronousReviewedInstallExecutor({
    providerAdapter,
    transport,
    execute,
    ...optionalExecutionControls(dependencies),
  });
  const uninstallExecutor = createSynchronousReviewedUninstallExecutor({
    providerAdapter: uninstallProviderAdapter,
    transport,
    execute: executeUninstall,
    ...optionalExecutionControls(dependencies),
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
          releaseBucket(env),
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
      const loaded = await snapshot.load(env);
      const shell = buildSignedInstallerAssetResponse(
        loaded.installerAssets,
        new Request(`${PUBLIC_ORIGIN}/result`),
      );
      return context === undefined
        ? streamingInstallCallbackResponse(shell, execute)
        : streamingInstallCallbackResponse(shell, execute, { context });
    },
    managementCallbackResponse: async ({ env, context, execute }) => {
      const loaded = await snapshot.load(env);
      const shell = buildSignedInstallerAssetResponse(
        loaded.installerAssets,
        new Request(`${PUBLIC_ORIGIN}/manage`),
      );
      return context === undefined
        ? streamingInstallCallbackResponse(shell, execute)
        : streamingInstallCallbackResponse(shell, execute, { context });
    },
    ...optionalExecutionControls(dependencies.now === undefined ? {} : { now: dependencies.now }),
  };
  const core: GatewayDeployWorker = createGatewayDeployWorker(coreDependencies);

  return Object.freeze({
    async fetch(
      request: Request,
      env: ReviewedGatewayDeployEnv,
      context?: GatewayDeployExecutionContext,
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
  inputActivation: ReviewedGatewayDeployActivation,
  dependencies?: ReviewedRuntimeDependencies,
): ReviewedGatewayDeployWorker {
  const activation = parseReviewedActivation(inputActivation);
  if (!activation.enabled) {
    return createDisabledReviewedShell();
  }
  return createReviewedGatewayDeployRuntime(activation.pin, dependencies);
}
