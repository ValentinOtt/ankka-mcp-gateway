import * as v from 'valibot';
import { describe, expect, it } from 'vitest';
import { boundaryObjectSchema, type BoundaryObject } from '../src/boundary';
import { relayRuntimeUpdate } from '../src/runtime-update-relay';
import { verifiedReleaseBundle } from './fixtures';
import { requestJson } from './boundary';
import { sourceActionRuntimeFixture } from './source-action-runtime-fixture';

const ACCOUNT_ID = 'a'.repeat(32);
const WORKER_ID = 'b'.repeat(32);
const WORKER_NAME = 'ankka-gateway-test';
const OLD_VERSION = '11111111-1111-4111-8111-111111111111';
const TARGET_VERSION = '22222222-2222-4222-8222-222222222222';
const INITIAL_DEPLOYMENT = '33333333-3333-4333-8333-333333333333';
const STAGE_DEPLOYMENT = '44444444-4444-4444-8444-444444444444';
const ACTIVE_DEPLOYMENT = '55555555-5555-4555-8555-555555555555';
const COMPENSATION_DEPLOYMENT = '66666666-6666-4666-8666-666666666666';
const ACTION_ID = `action_${'a'.repeat(32)}`;
const ACTION_KEY = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc';
const EXPIRES_AT = 1_800_000_600_000;
const ACCESS_TOKEN = 'cloudflare-access-token-value';
const ASSET_UPLOAD_JWT = 'synthetic-asset-upload-jwt-value';
const ASSET_COMPLETION_JWT = 'synthetic-asset-completion-jwt-value';
const commandSchema = v.object({ command: v.string() });
const assetManifestSchema = v.strictObject({
  manifest: v.record(v.string(), v.strictObject({ hash: v.string(), size: v.number() })),
});
const subdomainSchema = v.object({ enabled: v.boolean() });
const deploymentBodySchema = v.object({
  versions: v.array(v.object({ percentage: v.number(), version_id: v.string() })),
});

interface DeploymentTarget {
  readonly percentage: number;
  readonly version_id: string;
}

interface TransportFixture {
  readonly transport: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
  readonly deployments: Array<readonly DeploymentTarget[]>;
  readonly commands: string[];
  readonly subdomainStates: boolean[];
  readonly currentSubdomain: () => boolean;
}

function json<Result>(result: Result, status = 200): Response {
  return new Response(JSON.stringify({ success: status < 300, errors: [], messages: [], result }), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function bindings() {
  const values = {
    ADMIN_EMAILS: 'owner@example.com',
    ANKKA_GATEWAY_RELEASE: 'gateway-v1.1.0',
    ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${'1'.repeat(64)}`,
    ANKKA_MANAGEMENT_HOSTNAME: 'manage.example.com',
    ANKKA_UPDATE_CHANNEL: 'stable',
    ANKKA_UPDATE_KEY_ID: verifiedReleaseBundle.keyId,
    ANKKA_UPDATE_PUBLIC_KEY: verifiedReleaseBundle.publicKey,
    ANKKA_WORKERS_SUBDOMAIN: 'tenant',
    ANKKA_WORKER_NAME: WORKER_NAME,
    CF_ACCESS_AUD: 'access-audience-tag',
    CF_ACCESS_ISSUER: 'https://tenant.cloudflareaccess.com',
    CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID,
    CLOUDFLARE_ZONE_ID: 'c'.repeat(32),
    CLOUDFLARE_ZONE_NAME: 'example.com',
    ZERO_TRUST_READY: 'true',
  };
  return [
    { name: 'ADMIN_STATE', type: 'durable_object_namespace', class_name: 'AdminState' },
    { name: 'ASSETS', type: 'assets' },
    ...Object.entries(values).map(([name, text]) => ({ name, text, type: 'plain_text' })),
  ];
}

function transportFixture(options: Readonly<{
  probeFails?: boolean;
  initialSubdomain?: boolean;
  managementDomainService?: string;
  workerTags?: readonly string[];
}> = {}): TransportFixture {
  let active: readonly DeploymentTarget[] = [{ percentage: 100, version_id: OLD_VERSION }];
  let deploymentId = INITIAL_DEPLOYMENT;
  let deploymentWrites = 0;
  let subdomain = options.initialSubdomain ?? false;
  const deployments: Array<readonly DeploymentTarget[]> = [];
  const commands: string[] = [];
  const subdomainStates: boolean[] = [];
  return {
    deployments,
    commands,
    subdomainStates,
    currentSubdomain: () => subdomain,
    transport: async (input, init = {}) => {
      const url = new URL(input instanceof Request ? input.url : input.toString());
      const request = input instanceof Request ? input : new Request(url, init);
      if (url.hostname.endsWith('.workers.dev')) {
        if (request.method === 'HEAD') {
          return new Response(null, { status: 204, headers: { 'x-ankka-runtime-action': 'ready' } });
        }
        const body = await requestJson(request, commandSchema);
        commands.push(body.command);
        if (body.command === 'probe') {
          return options.probeFails
            ? json({ error: 'broken_candidate' }, 409)
            : new Response(null, { status: 204, headers: { 'x-ankka-runtime-action': 'ready' } });
        }
        return json({ accepted: true });
      }
      const path = url.pathname;
      if (path.endsWith(`/workers/scripts/${WORKER_NAME}/subdomain`)) {
        if (request.method === 'POST') {
          const body = await requestJson(request, subdomainSchema);
          subdomain = body.enabled;
          subdomainStates.push(subdomain);
        }
        return json({ enabled: subdomain, previews_enabled: false });
      }
      if (path.endsWith('/workers/subdomain')) {
        return json({ subdomain: 'tenant' });
      }
      if (path.endsWith('/workers/domains')) {
        return json([{
          environment: 'production',
          hostname: 'manage.example.com',
          service: options.managementDomainService ?? WORKER_NAME,
        }]);
      }
      if (path.endsWith(`/workers/workers/${WORKER_NAME}`)) {
        return json({
          id: WORKER_ID,
          name: WORKER_NAME,
          tags: options.workerTags ?? ['ankka-mcp-gateway'],
        });
      }
      if (path.endsWith(`/workers/workers/${WORKER_ID}/versions/${OLD_VERSION}`)) {
        return json({
          id: OLD_VERSION,
          main_module: 'index.js',
          compatibility_date: '2026-08-08',
          bindings: bindings(),
        });
      }
      if (path.endsWith(`/workers/scripts/${WORKER_NAME}/deployments`)) {
        if (request.method === 'POST') {
          const body = await requestJson(request, deploymentBodySchema);
          active = [...body.versions];
          deployments.push(active);
          deploymentWrites += 1;
          deploymentId = deploymentWrites === 1
            ? STAGE_DEPLOYMENT
            : options.probeFails ? COMPENSATION_DEPLOYMENT : ACTIVE_DEPLOYMENT;
          return json({ id: deploymentId });
        }
        return json({ deployments: [{ id: deploymentId, versions: active }] });
      }
      throw new Error(`unexpected request ${request.method} ${url}`);
    },
  };
}

function input(transport: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) {
  return {
    accessToken: ACCESS_TOKEN,
    accountId: ACCOUNT_ID,
    workerName: WORKER_NAME,
    workersSubdomain: 'tenant',
    managementOrigin: 'https://manage.example.com',
    actionId: ACTION_ID,
    actionKey: ACTION_KEY,
    operation: 'rollback' as const,
    from: { release: 'gateway-v1.1.0', artifactSha256: `sha256:${'1'.repeat(64)}`, versionId: OLD_VERSION },
    to: { release: 'gateway-v1.0.0', artifactSha256: `sha256:${'0'.repeat(64)}`, versionId: TARGET_VERSION },
    expiresAt: EXPIRES_AT,
    releaseBundle: verifiedReleaseBundle,
    transport,
    now: () => 1_800_000_000_000,
  };
}

async function updateTransportFixture(failure?: 'asset_session' | 'worker_version' | 'version_verify') {
  const runtime = await sourceActionRuntimeFixture({
    accountId: ACCOUNT_ID,
    actorEmail: 'owner@example.com',
    managementHostname: 'manage.example.com',
    workerId: WORKER_ID,
    workerName: WORKER_NAME,
    workersSubdomain: 'tenant',
  });
  const fixture = transportFixture();
  const events: string[] = [];
  const controls: Array<Readonly<{ body: BoundaryObject; versionOverride: string | null }>> = [];
  const oldBindings = {
    ...runtime.bindings,
    ANKKA_GATEWAY_RELEASE: 'gateway-v0.9.0',
    ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${'1'.repeat(64)}`,
  };
  const expectedVersion = runtime.versionResult(TARGET_VERSION);
  let assetHash = '';
  const rejected = () => new Response(JSON.stringify({
    success: false,
    errors: [{ code: 10000, message: `synthetic rejection ${ACCESS_TOKEN}` }],
    messages: [],
    result: null,
  }), { status: 403, headers: { 'content-type': 'application/json' } });
  const transport = async (input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
    const request = input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);
    if (url.hostname === `${WORKER_NAME}.tenant.workers.dev`) {
      expect(url.pathname).toBe('/__ankka/runtime-action');
      expect(request.headers.has('authorization')).toBe(false);
      if (request.method === 'POST') {
        const body = await requestJson(request.clone(), boundaryObjectSchema);
        controls.push({ body, versionOverride: request.headers.get('Cloudflare-Workers-Version-Overrides') });
        events.push(body.command === 'progress' ? `progress:${body.stage}` : `control:${body.command}`);
      }
      return fixture.transport(request);
    }
    expect(url.origin).toBe('https://api.cloudflare.com');
    expect(url.pathname.startsWith(`/client/v4/accounts/${ACCOUNT_ID}/workers/`)).toBe(true);
    expect(request.headers.get('authorization')).toBe(`Bearer ${
      url.pathname.endsWith('/workers/assets/upload') ? ASSET_UPLOAD_JWT : ACCESS_TOKEN
    }`);
    if (url.pathname.endsWith(`/versions/${OLD_VERSION}`)) {
      return json({
        ...runtime.versionResult(OLD_VERSION),
        bindings: [
          { name: 'ADMIN_STATE', type: 'durable_object_namespace', class_name: 'AdminState' },
          { name: 'ASSETS', type: 'assets' },
          ...Object.entries(oldBindings).map(([name, text]) => ({ name, text, type: 'plain_text' })),
        ],
      });
    }
    if (url.pathname.endsWith(`/workers/scripts/${WORKER_NAME}/assets-upload-session`)) {
      events.push('asset_session');
      expect(request.method).toBe('POST');
      const { manifest } = await requestJson(request, assetManifestSchema);
      expect(Object.keys(manifest)).toEqual(['/index.html']);
      const asset = manifest['/index.html'];
      if (asset === undefined) throw new TypeError('missing fixture asset');
      expect(asset.hash).toMatch(/^[a-f0-9]{32}$/u);
      expect(asset.size).toBe(new TextEncoder().encode('<!doctype html><title>Gateway</title>').byteLength);
      assetHash = asset.hash;
      return failure === 'asset_session' ? rejected() : json({ jwt: ASSET_UPLOAD_JWT, buckets: [[assetHash]] });
    }
    if (url.pathname.endsWith('/workers/assets/upload')) {
      events.push('asset_bucket');
      expect(request.method).toBe('POST');
      expect(url.search).toBe('?base64=true');
      const form = await request.formData();
      expect([...form.keys()]).toEqual([assetHash]);
      const asset = form.get(assetHash);
      if (!(asset instanceof Blob)) throw new TypeError('missing fixture upload');
      expect(atob(await asset.text())).toBe('<!doctype html><title>Gateway</title>');
      return json({ jwt: ASSET_COMPLETION_JWT }, 201);
    }
    if (url.pathname.endsWith(`/workers/workers/${WORKER_ID}/versions`)) {
      events.push('worker_version');
      expect(request.method).toBe('POST');
      const body = await requestJson(request, boundaryObjectSchema);
      expect(body).toEqual({
        annotations: expectedVersion.annotations,
        assets: {
          config: { not_found_handling: 'single-page-application', run_worker_first: ['/__ankka/*', '/api/*'] },
          jwt: ASSET_COMPLETION_JWT,
        },
        bindings: v.parse(v.array(v.looseObject({ name: v.string() })), expectedVersion.bindings)
          .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0),
        compatibility_date: expectedVersion.compatibility_date,
        compatibility_flags: [],
        exports: expectedVersion.exports,
        main_module: expectedVersion.main_module,
        modules: expectedVersion.modules,
      });
      return failure === 'worker_version' ? rejected() : json({ id: TARGET_VERSION }, 201);
    }
    if (url.pathname.endsWith(`/versions/${TARGET_VERSION}`)) {
      events.push('version_verify');
      expect(request.method).toBe('GET');
      expect(url.search).toBe('?include=modules');
      return json(failure === 'version_verify'
        ? runtime.versionResult(TARGET_VERSION, new TextEncoder().encode('unreviewed module bytes'))
        : expectedVersion);
    }
    if (url.pathname.endsWith('/deployments') && request.method === 'POST') events.push('deployment');
    return fixture.transport(request);
  };
  return {
    ...fixture,
    events,
    controls,
    relayInput: {
      ...input(transport),
      operation: 'update' as const,
      releaseBundle: runtime.bundle,
      from: { release: oldBindings.ANKKA_GATEWAY_RELEASE, artifactSha256: oldBindings.ANKKA_GATEWAY_RELEASE_SHA256, versionId: OLD_VERSION },
      to: { release: runtime.identity.release, artifactSha256: `sha256:${runtime.identity.artifactSha256}`, versionId: null },
    },
  };
}

describe('runtime update relay', () => {
  it('uploads and verifies a new update candidate before zero-traffic probe and activation', async () => {
    const fixture = await updateTransportFixture();
    const result = await relayRuntimeUpdate(fixture.relayInput);
    expect(result).toEqual({
      schemaVersion: 1,
      actionId: ACTION_ID,
      operation: 'update',
      status: 'succeeded',
      managementUrl: `https://manage.example.com/?runtimeAction=${ACTION_ID}`,
    });
    expect(fixture.events).toEqual([
      'control:begin', 'progress:current_verified', 'asset_session', 'asset_bucket',
      'progress:assets_uploaded', 'worker_version', 'version_verify', 'progress:candidate_created',
      'deployment', 'progress:candidate_staged', 'control:probe', 'progress:candidate_verified',
      'deployment', 'progress:activated', 'control:probe', 'progress:health_verified', 'control:complete',
    ]);
    expect(fixture.deployments).toEqual([
      [{ version_id: OLD_VERSION, percentage: 100 }, { version_id: TARGET_VERSION, percentage: 0 }],
      [{ version_id: TARGET_VERSION, percentage: 100 }],
    ]);
    const probes = fixture.controls.filter(({ body }) => body.command === 'probe');
    expect(probes.map(({ versionOverride }) => versionOverride)).toEqual([`${WORKER_NAME}="${TARGET_VERSION}"`, null]);
    for (const { body } of probes) {
      expect(body).toMatchObject({
        operation: 'update',
        targetRelease: fixture.relayInput.to.release,
        targetArtifactSha256: fixture.relayInput.to.artifactSha256,
      });
    }
    expect(fixture.controls.at(-1)?.body).toMatchObject({ command: 'complete', fromVersionId: OLD_VERSION, toVersionId: TARGET_VERSION });
    expect(fixture.subdomainStates).toEqual([true, false]);
    expect(fixture.currentSubdomain()).toBe(false);
    for (const credential of [ACCESS_TOKEN, ASSET_UPLOAD_JWT, ASSET_COMPLETION_JWT]) {
      expect(JSON.stringify(fixture.controls)).not.toContain(credential);
    }
  });

  it.each(['asset_session', 'worker_version'] as const)('leaves the old deployment active when update %s is rejected', async (stage) => {
    const fixture = await updateTransportFixture(stage);
    await expect(relayRuntimeUpdate(fixture.relayInput)).rejects.toMatchObject({
      code: 'provider_rejected', stage, outcome: 'rejected', canRetry: false, submissions: [],
    });
    expect(fixture.events.filter((event) => event === stage)).toHaveLength(1);
    expect(fixture.events).not.toContain('version_verify');
    if (stage === 'asset_session') {
      expect(fixture.events).not.toContain('asset_bucket');
      expect(fixture.events).not.toContain('worker_version');
    }
    expect(fixture.deployments).toEqual([]);
    expect(fixture.commands).not.toContain('probe');
    expect(fixture.commands).not.toContain('complete');
    expect(fixture.controls.at(-1)?.body).toMatchObject({
      command: 'fail', failureCode: 'runtime_action_failed', recoveryRequired: false,
    });
    expect(JSON.stringify(fixture.controls)).not.toContain(ACCESS_TOKEN);
    expect(fixture.subdomainStates).toEqual([true, false]);
    expect(fixture.currentSubdomain()).toBe(false);
  });

  it('does not stage an update version whose read-back module differs from the verified bundle', async () => {
    const fixture = await updateTransportFixture('version_verify');
    await expect(relayRuntimeUpdate(fixture.relayInput)).rejects.toMatchObject({
      code: 'provider_mismatch', stage: 'version_verify', outcome: 'submitted',
      submissions: [{ kind: 'version', versionId: TARGET_VERSION }],
    });
    expect(fixture.events.filter((event) => event === 'worker_version')).toHaveLength(1);
    expect(fixture.events.filter((event) => event === 'version_verify')).toHaveLength(1);
    expect(fixture.deployments).toEqual([]);
    expect(fixture.commands).not.toContain('probe');
    expect(fixture.commands).not.toContain('complete');
    expect(fixture.controls.at(-1)?.body).toMatchObject({ command: 'fail', recoveryRequired: false });
    expect(fixture.subdomainStates).toEqual([true, false]);
    expect(fixture.currentSubdomain()).toBe(false);
  });

  it('stages the rollback target at zero, probes it exactly, then activates it', async () => {
    const fixture = transportFixture();
    const result = await relayRuntimeUpdate(input(fixture.transport));
    expect(result.status).toBe('succeeded');
    expect(fixture.deployments).toEqual([
      [{ version_id: OLD_VERSION, percentage: 100 }, { version_id: TARGET_VERSION, percentage: 0 }],
      [{ version_id: TARGET_VERSION, percentage: 100 }],
    ]);
    expect(fixture.commands).toContain('complete');
    expect(fixture.subdomainStates).toEqual([true, false]);
  });

  it('restores the old version when the exact candidate probe fails', async () => {
    const fixture = transportFixture({ probeFails: true });
    await expect(relayRuntimeUpdate(input(fixture.transport))).rejects.toBeDefined();
    expect(fixture.deployments.at(-1)).toEqual([{ version_id: OLD_VERSION, percentage: 100 }]);
    expect(fixture.commands).toContain('fail');
    expect(fixture.subdomainStates).toEqual([true, false]);
  });

  it('does not mutate an unowned Worker before exact ownership verification', async () => {
    const fixture = transportFixture({ workerTags: ['customer-worker'] });
    await expect(relayRuntimeUpdate(input(fixture.transport))).rejects.toBeDefined();
    expect(fixture.subdomainStates).toEqual([]);
    expect(fixture.deployments).toEqual([]);
    expect(fixture.commands).toEqual([]);
  });

  it('rejects a release candidate signed for another control-plane origin before provider access', async () => {
    let providerCalls = 0;
    const base = input(async () => {
      providerCalls += 1;
      throw new Error('provider access must not be reached');
    });
    await expect(relayRuntimeUpdate({
      ...base,
      releaseBundle: Object.freeze({
        ...verifiedReleaseBundle,
        manifest: Object.freeze({
          ...verifiedReleaseBundle.manifest,
          controlPlaneOrigin: 'https://foreign-control.example',
        }),
      }),
    })).rejects.toMatchObject({ code: 'session_conflict' });
    expect(providerCalls).toBe(0);
  });

  it('does not expose a Worker when the claimed management domain belongs elsewhere', async () => {
    const fixture = transportFixture({ managementDomainService: 'another-worker' });
    await expect(relayRuntimeUpdate(input(fixture.transport))).rejects.toBeDefined();
    expect(fixture.subdomainStates).toEqual([]);
    expect(fixture.deployments).toEqual([]);
    expect(fixture.commands).toEqual([]);
  });

  it('preserves an already-enabled workers.dev route and performs no writes', async () => {
    const fixture = transportFixture({ initialSubdomain: true });
    await expect(relayRuntimeUpdate(input(fixture.transport))).rejects.toBeDefined();
    expect(fixture.currentSubdomain()).toBe(true);
    expect(fixture.subdomainStates).toEqual([]);
    expect(fixture.deployments).toEqual([]);
    expect(fixture.commands).toEqual([]);
  });
});
