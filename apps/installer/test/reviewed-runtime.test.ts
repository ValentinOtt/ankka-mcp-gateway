import * as v from 'valibot';

import {
  OAUTH_COOKIE,
  PUBLIC_ORIGIN,
  REQUIRED_OAUTH_SCOPES,
  SESSION_COOKIE,
} from '../src/constants';
import { DeployError } from '../src/errors';
import { sealOauthCookie } from '../src/crypto';
import * as runtimeRelay from '../src/runtime-update-relay';
import type {
  PinnedR2Release,
  R2ReleaseBundleProvider,
  R2ReleaseReadBucket,
} from '../src/r2-release-provider';
import type { VerifiedReleaseBundle, VerifiedReleasePayloadBlob } from '../src/release';
import { REVIEWED_GATEWAY_DEPLOY_ACTIVATION } from '../src/reviewed-activation';
import {
  createReviewedGatewayDeployEntrypoint,
  createReviewedGatewayDeployRuntime,
  type ReviewedGatewayDeployEnv,
  type ReviewedRuntimeDependencies,
  type ReviewedRuntimeTransport,
} from '../src/reviewed-runtime';
import {
  APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
  canonicalJson,
  parseReleaseManifest,
  type ReleaseComponent,
  type ReleaseFileRecord,
} from '../src/release-manifest';
import { cookiePair, env, selectionInput } from './fixtures';

const encoder = new TextEncoder();

function deferred() {
  let resolve = (): void => undefined;
  const promise = new Promise<void>((next) => { resolve = next; });
  return { promise, resolve };
}

interface SourceFile {
  readonly bytes: Uint8Array;
  readonly record: ReleaseFileRecord;
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(input: Uint8Array | string): Promise<string> {
  const bytes = v.is(v.string(), input) ? encoder.encode(input) : input;
  const owned = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  owned.set(bytes);
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', owned)));
}

async function source(path: string, contentType: string, body: string): Promise<SourceFile> {
  const bytes = encoder.encode(body);
  return Object.freeze({
    bytes,
    record: Object.freeze({
      path,
      contentType,
      byteSize: bytes.byteLength,
      sha256: await sha256(bytes),
    }),
  });
}

async function component(files: readonly SourceFile[]): Promise<ReleaseComponent> {
  const records = Object.freeze(files.map((file) => file.record));
  return Object.freeze({
    byteSize: records.reduce((sum, file) => sum + file.byteSize, 0),
    fileCount: records.length,
    files: records,
    treeSha256: await sha256(canonicalJson(records)),
  });
}

async function signedSnapshotFixture(controlPlaneOrigin = PUBLIC_ORIGIN): Promise<{
  readonly bundle: VerifiedReleaseBundle;
  readonly pin: PinnedR2Release;
}> {
  const admin = [await source(
    'payload/admin/index.html',
    'text/html; charset=utf-8',
    '<!doctype html><main>private customer admin</main>',
  )];
  const installer = [
    await source(
      'payload/installer/assets/app-A1b2C3d4.js',
      'text/javascript; charset=utf-8',
      'globalThis.__reviewedSignedInstaller=true;',
    ),
    await source(
      'payload/installer/index.html',
      'text/html; charset=utf-8',
      '<!doctype html><body><!-- ankka-runtime-callback-state --><main>signed reviewed installer</main>' +
        '<script type="module" src="/assets/app-A1b2C3d4.js"></script></body>',
    ),
  ];
  const worker = [await source(
    'payload/worker/index.js',
    'application/javascript+module',
    `const CONTROL_PLANE_ORIGIN = '${controlPlaneOrigin}';\nexport default {fetch(){return new Response("customer worker")}};`,
  )];
  const workerCleanup = [await source(
    'payload/worker-cleanup/index.js',
    'application/javascript+module',
    'export class AdminState {}; export default {fetch(){return new Response("cleanup")}};',
  )];
  const workerRetirement = [await source(
    'payload/worker-retirement/index.js',
    'application/javascript+module',
    'export default {fetch(){return new Response(null,{status:410})}};',
  )];
  const all = Object.freeze([
    ...admin,
    ...installer,
    ...workerCleanup,
    ...workerRetirement,
    ...worker,
  ]);
  const manifest = parseReleaseManifest({
    artifact: {
      byteSize: all.reduce((sum, file) => sum + file.record.byteSize, 0),
      fileCount: all.length,
      treeSha256: await sha256(canonicalJson(all.map((file) => file.record))),
    },
    cloudflare: APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
    controlPlaneOrigin,
    components: {
      admin: await component(admin),
      installer: await component(installer),
      worker: await component(worker),
      workerCleanup: await component(workerCleanup),
      workerRetirement: await component(workerRetirement),
    },
    oauthScopeIds: REQUIRED_OAUTH_SCOPES,
    release: 'gateway-v1.2.3',
    schemaVersion: 1,
    sourceCommit: '0123456789abcdef0123456789abcdef01234567',
  });
  const payload = Object.freeze(all.map((file): VerifiedReleasePayloadBlob => {
    const owned = new Uint8Array(new ArrayBuffer(file.bytes.byteLength));
    owned.set(file.bytes);
    return Object.freeze({
      ...file.record,
      bytes: new Blob([owned], { type: file.record.contentType }),
    });
  }));
  const bundle: VerifiedReleaseBundle = Object.freeze({
    verification: 'ed25519',
    channel: 'canary',
    keyId: 'reviewed-test-key',
    envelope: Object.freeze({
      schemaVersion: 2, channel: 'canary', keyId: 'reviewed-test-key',
      manifest: canonicalJson(manifest), signature: 'A'.repeat(86),
      signatureContext: 'ankka-mcp-gateway-release-envelope-v2',
    }),
    manifest,
    payload,
    publicKey: 'A'.repeat(43),
  });
  return {
    bundle,
    pin: {
      schemaVersion: 1,
      channel: 'canary',
      controlPlaneOrigin: manifest.controlPlaneOrigin,
      release: manifest.release,
      keyId: bundle.keyId,
      publicKey: 'A'.repeat(43),
      artifactSha256: manifest.artifact.treeSha256,
    },
  };
}

function inertBucket(): R2ReleaseReadBucket {
  return {
    get: async () => null,
    list: async () => ({ objects: [], truncated: false }),
  };
}

function runtimeEnv(): ReviewedGatewayDeployEnv {
  const allow = { limit: async () => ({ success: true }) } satisfies RateLimit;
  return {
    ...env(),
    ANONYMOUS_SESSION_RATE_LIMIT: allow,
    SESSION_READ_RATE_LIMIT: allow,
    SESSION_MUTATION_RATE_LIMIT: allow,
    GATEWAY_RELEASE_BUCKET: inertBucket(),
  };
}

class SequencedProvider implements R2ReleaseBundleProvider {
  calls = 0;

  constructor(
    private readonly bundle: VerifiedReleaseBundle,
    private failures = 0,
  ) {}

  async loadVerifiedReleaseBundle(_bucket: R2ReleaseReadBucket): Promise<VerifiedReleaseBundle> {
    this.calls += 1;
    if (this.failures > 0) {
      this.failures -= 1;
      throw new DeployError(503, 'release_unavailable');
    }
    await Promise.resolve();
    return this.bundle;
  }
}

function runtimeDependencies(provider: R2ReleaseBundleProvider): ReviewedRuntimeDependencies {
  return { releaseBundleProvider: provider };
}

describe('reviewed runtime boundary', () => {
  it('keeps the reviewed entrypoint false/null and does not touch enabled dependencies', async () => {
    expect(REVIEWED_GATEWAY_DEPLOY_ACTIVATION).toEqual({ enabled: false, pin: null });
    expect(Object.keys(REVIEWED_GATEWAY_DEPLOY_ACTIVATION).sort()).toEqual(['enabled', 'pin']);
    expect(Object.isFrozen(REVIEWED_GATEWAY_DEPLOY_ACTIVATION)).toBe(true);

    let dependencyRead = false;
    const dependencies: ReviewedRuntimeDependencies = {
      get releaseBundleProvider(): R2ReleaseBundleProvider {
        dependencyRead = true;
        throw new Error('disabled activation read a runtime dependency');
      },
    };
    const worker = createReviewedGatewayDeployEntrypoint(
      REVIEWED_GATEWAY_DEPLOY_ACTIVATION,
      dependencies,
    );
    const poisonEnv = new Proxy(runtimeEnv(), {
      get() {
        throw new Error('disabled shell touched an environment binding');
      },
    });
    const response = await worker.fetch(new Request('https://deploy.ankka.ai/health'), poisonEnv);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true, mutationsEnabled: false });
    for (const path of ['/', '/api/session', '/oauth/callback?state=bad', '/result']) {
      const unavailable = await worker.fetch(
        new Request(`https://deploy.ankka.ai${path}`),
        poisonEnv,
      );
      expect(unavailable.status).toBe(503);
      expect(await unavailable.json()).toEqual({ code: 'release_unavailable' });
    }
    expect(dependencyRead).toBe(false);
  });

  it('loads lazily, retries failures, coalesces concurrency, then keeps one immutable snapshot', async () => {
    const fixture = await signedSnapshotFixture();
    const provider = new SequencedProvider(fixture.bundle, 1);
    const worker = createReviewedGatewayDeployRuntime(fixture.pin, runtimeDependencies(provider));
    const workerEnv = runtimeEnv();

    const health = await worker.fetch(new Request('https://deploy.ankka.ai/health'), workerEnv);
    expect(await health.json()).toEqual({ ok: true, mutationsEnabled: true });
    expect(provider.calls).toBe(0);

    const unavailable = await worker.fetch(new Request('https://deploy.ankka.ai/'), workerEnv);
    expect(unavailable.status).toBe(503);
    expect(await unavailable.json()).toEqual({ code: 'release_unavailable' });
    expect(provider.calls).toBe(1);

    const [home, gateway, review] = await Promise.all([
      worker.fetch(new Request('https://deploy.ankka.ai/'), workerEnv),
      worker.fetch(new Request('https://deploy.ankka.ai/gateway'), workerEnv),
      worker.fetch(new Request('https://deploy.ankka.ai/review'), workerEnv),
    ]);
    expect(provider.calls).toBe(2);
    expect(await home.text()).toContain('signed reviewed installer');
    expect(await gateway.text()).toContain('signed reviewed installer');
    expect(await review.text()).toContain('signed reviewed installer');

    const asset = await worker.fetch(
      new Request('https://deploy.ankka.ai/assets/app-A1b2C3d4.js'),
      workerEnv,
    );
    expect(asset.status).toBe(200);
    expect(asset.headers.get('cache-control')).toContain('immutable');
    expect(await asset.text()).toBe('globalThis.__reviewedSignedInstaller=true;');
    expect(provider.calls).toBe(2);
  });

  it('never routes protected health, API, or exact OAuth callback paths through signed assets', async () => {
    const fixture = await signedSnapshotFixture();
    const provider = new SequencedProvider(fixture.bundle);
    const worker = createReviewedGatewayDeployRuntime(fixture.pin, runtimeDependencies(provider));
    const workerEnv = runtimeEnv();

    const health = await worker.fetch(new Request('https://deploy.ankka.ai/health'), workerEnv);
    const session = await worker.fetch(new Request('https://deploy.ankka.ai/api/session', {
      headers: { 'cf-connecting-ip': '192.0.2.55' },
    }), workerEnv);
    const unknownApi = await worker.fetch(new Request('https://deploy.ankka.ai/api/not-real'), workerEnv);
    const callback = await worker.fetch(
      new Request('https://deploy.ankka.ai/oauth/callback?state=bad'),
      workerEnv,
    );

    expect(health.headers.get('content-type')).toContain('application/json');
    expect(session.headers.get('content-type')).toContain('application/json');
    expect(unknownApi.status).toBe(404);
    expect(unknownApi.headers.get('content-type')).toContain('application/json');
    expect(callback.status).toBe(400);
    expect(callback.headers.get('content-type')).toContain('application/json');
    expect(provider.calls).toBe(0);
  });

  it('fails closed without active abuse-control bindings while leaving release discovery independent', async () => {
    const fixture = await signedSnapshotFixture();
    const provider = new SequencedProvider(fixture.bundle);
    const worker = createReviewedGatewayDeployRuntime(fixture.pin, runtimeDependencies(provider));
    const activeEnv = runtimeEnv();
    const established = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { 'cf-connecting-ip': '192.0.2.55' },
    }), activeEnv);
    expect(established.status).toBe(200);
    const establishedPayload = v.parse(
      v.looseObject({ csrf: v.string() }),
      await established.json(),
    );
    const establishedCookie = cookiePair(established.headers.get('set-cookie') ?? '', SESSION_COOKIE);
    const { SESSION_MUTATION_RATE_LIMIT: _mutationBinding, ...missingMutationBinding } = activeEnv;
    const mutation = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/selection`, {
      method: 'PUT',
      headers: {
        cookie: establishedCookie,
        'content-type': 'application/json',
        origin: PUBLIC_ORIGIN,
        'sec-fetch-site': 'same-origin',
        'x-csrf-token': establishedPayload.csrf,
      },
      body: JSON.stringify(selectionInput),
    }), missingMutationBinding);
    expect(mutation.status).toBe(503);
    expect(await mutation.json()).toEqual({ code: 'abuse_controls_unavailable' });

    const { SESSION_READ_RATE_LIMIT: _readBinding, ...missingReadBinding } = activeEnv;
    const read = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: establishedCookie },
    }), missingReadBinding);
    expect(read.status).toBe(503);
    expect(await read.json()).toEqual({ code: 'abuse_controls_unavailable' });

    const {
      ANONYMOUS_SESSION_RATE_LIMIT: _anonymousBinding,
      SESSION_READ_RATE_LIMIT: _allReadBinding,
      SESSION_MUTATION_RATE_LIMIT: _allMutationBinding,
      ...missingBindings
    } = activeEnv;

    const session = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { 'cf-connecting-ip': '192.0.2.55' },
    }), missingBindings);
    expect(session.status).toBe(503);
    expect(await session.json()).toEqual({ code: 'abuse_controls_unavailable' });

    const release = await worker.fetch(
      new Request(`${PUBLIC_ORIGIN}/api/releases/canary`),
      missingBindings,
    );
    expect(release.status).toBe(200);
    expect(await release.json()).toMatchObject({
      channel: 'canary',
      release: { id: 'gateway-v1.2.3' },
    });
  });

  it('revalidates the exact pin before caching and never executes on a mismatched bundle', async () => {
    const fixture = await signedSnapshotFixture();
    const mismatched = Object.freeze({
      ...fixture.bundle,
      keyId: 'different-reviewed-key',
    });
    const provider = new SequencedProvider(mismatched);
    let executeCalls = 0;
    const worker = createReviewedGatewayDeployRuntime(fixture.pin, {
      releaseBundleProvider: provider,
      execute: async () => {
        executeCalls += 1;
        return { installationId: `acg-${'a'.repeat(24)}` };
      },
    });

    const first = await worker.fetch(new Request('https://deploy.ankka.ai/'), runtimeEnv());
    const second = await worker.fetch(new Request('https://deploy.ankka.ai/'), runtimeEnv());
    expect(first.status).toBe(503);
    expect(second.status).toBe(503);
    expect(await first.json()).toEqual({ code: 'release_invalid' });
    expect(provider.calls).toBe(2);
    expect(executeCalls).toBe(0);
  });

  it('refuses an internally consistent signed snapshot for another control-plane origin', async () => {
    const fixture = await signedSnapshotFixture('https://foreign-control.example');
    const provider = new SequencedProvider(fixture.bundle);
    const worker = createReviewedGatewayDeployRuntime(fixture.pin, runtimeDependencies(provider));

    const response = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/`), runtimeEnv());
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ code: 'release_invalid' });
    expect(provider.calls).toBe(1);
  });

  it('serves the signed installer immediately while reviewed execution owns the connected stream', async () => {
    const fixture = await signedSnapshotFixture();
    const provider = new SequencedProvider(fixture.bundle);
    let releaseExecutor = (): void => undefined;
    let markStarted = (): void => undefined;
    const executorGate = new Promise<void>((resolve) => {
      releaseExecutor = resolve;
    });
    const executorStarted = new Promise<void>((resolve) => {
      markStarted = resolve;
    });
    const transport: ReviewedRuntimeTransport = async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : input.toString());
      if (url.pathname === '/oauth2/token') {
        return new Response(JSON.stringify({
          access_token: 'reviewed-stream-access-token',
          refresh_token: 'reviewed-stream-refresh-token',
          token_type: 'bearer',
          scope: REQUIRED_OAUTH_SCOPES.join(' '),
        }));
      }
      if (url.pathname.endsWith('/user')) {
        return Response.json({ success: true, result: { id: 'user-12345678', email: 'owner@example.com' } });
      }
      if (url.pathname.endsWith('/accounts')) {
        return Response.json({ success: true, result: [{ id: 'a'.repeat(32), name: 'Disposable account' }] });
      }
      if (url.pathname.endsWith('/zones')) {
        return Response.json({
          success: true,
          result: [{
            id: 'b'.repeat(32),
            name: 'example.com',
            status: 'active',
            account: { id: 'a'.repeat(32) },
          }],
        });
      }
      if (url.pathname === '/oauth2/revoke') return Response.json({});
      return new Response(JSON.stringify({ url: url.toString(), method: init?.method }), { status: 404 });
    };
    const worker = createReviewedGatewayDeployRuntime(fixture.pin, {
      releaseBundleProvider: provider,
      transport,
      execute: async () => {
        markStarted();
        await executorGate;
        throw new DeployError(503, 'install_mutations_disabled');
      },
    });
    const workerEnv = runtimeEnv();
    const sessionResponse = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { 'cf-connecting-ip': '192.0.2.55' },
    }), workerEnv);
    const session = v.parse(v.looseObject({ csrf: v.string() }), await sessionResponse.json());
    const sessionCookie = cookiePair(sessionResponse.headers.get('set-cookie') ?? '', SESSION_COOKIE);
    const mutationHeaders = (json = true): Headers => {
      const headers = new Headers({
        origin: PUBLIC_ORIGIN,
        'sec-fetch-site': 'same-origin',
        'x-csrf-token': session.csrf,
        cookie: sessionCookie,
      });
      if (json) headers.set('content-type', 'application/json');
      return headers;
    };
    expect((await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/selection`, {
      method: 'PUT',
      headers: mutationHeaders(),
      body: JSON.stringify(selectionInput),
    }), workerEnv)).status).toBe(200);
    const planResponse = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/plan`, {
      method: 'POST', headers: mutationHeaders(false),
    }), workerEnv);
    const planPayload = v.parse(v.looseObject({
      plan: v.looseObject({ planId: v.string(), planHash: v.string() }),
    }), await planResponse.json());
    const deployResponse = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/deploy`, {
      method: 'POST',
      headers: mutationHeaders(),
      body: JSON.stringify({
        planId: planPayload.plan.planId,
        planHash: planPayload.plan.planHash,
      }),
    }), workerEnv);
    const deploy = v.parse(
      v.looseObject({ authorizationUrl: v.string() }),
      await deployResponse.json(),
    );
    const state = new URL(deploy.authorizationUrl).searchParams.get('state');
    const oauthCookie = cookiePair(deployResponse.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
    const waitUntilTasks: Promise<unknown>[] = [];
    const callback = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${state}`,
      { headers: { cookie: `${sessionCookie}; ${oauthCookie}` } },
    ), workerEnv, {
      waitUntil(task: Promise<unknown>) {
        waitUntilTasks.push(task);
      },
    });

    expect(callback.status).toBe(200);
    expect(callback.headers.get('content-type')).toContain('text/html');
    expect(callback.headers.has('content-length')).toBe(false);
    expect(callback.headers.get('set-cookie')).toContain('Max-Age=0');
    expect(waitUntilTasks).toHaveLength(1);
    const reader = callback.body?.getReader();
    const first = await reader?.read();
    expect(new TextDecoder().decode(first?.value)).toContain('signed reviewed installer');
    await executorStarted;

    const running = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: sessionCookie },
    }), workerEnv);
    expect(await running.json()).toMatchObject({ deployment: { status: 'running' } });
    releaseExecutor();
    expect((await reader?.read())?.done).toBe(true);
    await Promise.all(waitUntilTasks);
    const completed = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: sessionCookie },
    }), workerEnv);
    expect(await completed.json()).toMatchObject({
      deployment: { status: 'failed', failure: { code: 'install_mutations_disabled' } },
    });
  });

  it('wires the runtime-only pending stream to the signed shell and emits completion only after relay cleanup', async () => {
    const fixture = await signedSnapshotFixture();
    const provider = new SequencedProvider(fixture.bundle);
    const now = Date.UTC(2026, 7, 31, 1, 0, 0);
    const actionId = 'action_' + 'A'.repeat(32);
    const state = 'S'.repeat(43);
    const relayGate = deferred();
    const relayStarted = deferred();
    const revokeGate = deferred();
    const revokeStarted = deferred();
    const relay = vi.spyOn(runtimeRelay, 'relayRuntimeUpdate').mockImplementation(async () => {
      relayStarted.resolve();
      await relayGate.promise;
      return {
        schemaVersion: 1, actionId, operation: 'update', status: 'succeeded',
        managementUrl: 'https://manage.example.com/?runtimeAction=' + actionId,
      };
    });
    const calls = { exchanged: 0, revoked: 0 };
    const worker = createReviewedGatewayDeployRuntime(fixture.pin, {
      releaseBundleProvider: provider,
      now: () => now,
      transport: async (input) => {
        const url = new URL(input instanceof Request ? input.url : input.toString());
        if (url.pathname === '/oauth2/token') {
          calls.exchanged += 1;
          return Response.json({
            access_token: 'runtime-stream-private-token', token_type: 'Bearer', scope: REQUIRED_OAUTH_SCOPES.join(' '),
          });
        }
        if (url.pathname.endsWith('/user')) {
          return Response.json({ success: true, result: { id: 'synthetic-user', email: 'owner@example.com' } });
        }
        if (url.pathname.endsWith('/accounts')) {
          return Response.json({ success: true, result: [{ id: 'a'.repeat(32), name: 'Disposable account' }] });
        }
        if (url.pathname === '/oauth2/revoke') {
          calls.revoked += 1;
          revokeStarted.resolve();
          await revokeGate.promise;
          return Response.json({});
        }
        throw new Error('unexpected synthetic runtime transport');
      },
    });
    const workerEnv = runtimeEnv();
    const sealed = await sealOauthCookie(workerEnv.DEPLOY_SESSION_ENCRYPTION_KEY, {
      schemaVersion: 5, purpose: 'runtime_update', state, verifier: 'V'.repeat(43),
      expiresAt: now + 10 * 60_000, actionId, actionKey: 'K'.repeat(43),
      actorEmail: 'owner@example.com', accountId: 'a'.repeat(32), workerName: 'ankka-gateway-example',
      workersSubdomain: 'customer-workers', managementOrigin: 'https://manage.example.com', operation: 'update',
      from: { release: 'gateway-v0.9.0', artifactSha256: 'sha256:' + 'f'.repeat(64), versionId: null },
      to: {
        release: fixture.bundle.manifest.release,
        artifactSha256: 'sha256:' + fixture.bundle.manifest.artifact.treeSha256,
        versionId: null,
      },
    });
    const tasks: Promise<unknown>[] = [];
    try {
      const callback = await worker.fetch(new Request(
        `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${state}`,
        { headers: { cookie: OAUTH_COOKIE + '=' + sealed } },
      ), workerEnv, { waitUntil: (task) => { tasks.push(task); } });
      expect(callback.status).toBe(200);
      expect(callback.headers.get('content-type')).toContain('text/html');
      expect(callback.headers.get('set-cookie')).toContain(OAUTH_COOKIE + '=;');
      expect(callback.headers.get('location')).toBeNull();
      const reader = callback.body?.getReader();
      const first = new TextDecoder().decode((await reader?.read())?.value);
      expect(first).toContain('signed reviewed installer');
      expect(first).toContain('ankka-runtime-callback-pending');
      expect(first).not.toContain('ankka-runtime-callback-result');
      await relayStarted.promise;
      relayGate.resolve();
      await revokeStarted.promise;
      expect(calls).toEqual({ exchanged: 1, revoked: 1 });
      let receivedTerminal = false;
      const terminal = reader?.read().then((part) => { receivedTerminal = true; return part; });
      await Promise.resolve();
      expect(receivedTerminal).toBe(false);
      revokeGate.resolve();
      const body = new TextDecoder().decode((await terminal)?.value);
      expect(body).toContain('"status":"succeeded"');
      expect(body).toContain('"managementUrl":"https://manage.example.com/?runtimeAction=' + actionId + '"');
      expect(body).not.toContain('runtime-stream-private-token');
      expect((await reader?.read())?.done).toBe(true);
      expect(relay).toHaveBeenCalledTimes(1);
      expect(tasks).toHaveLength(1);
      await Promise.all(tasks);
    } finally {
      relayGate.resolve();
      revokeGate.resolve();
      relay.mockRestore();
    }
  });
});
