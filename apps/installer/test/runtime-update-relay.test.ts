import * as v from 'valibot';
import { afterEach, describe, expect, it, vi } from 'vitest';
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

afterEach(() => vi.useRealTimers());

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

type ControlResponse = (request: Request) => Promise<Response | null>;

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
  currentBindings?: readonly BoundaryObject[];
  targetBindings?: readonly BoundaryObject[];
  controlResponse?: ControlResponse;
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
        const body = await requestJson(request.clone(), commandSchema);
        commands.push(body.command);
        const response = await options.controlResponse?.(request);
        if (response) return response;
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
          bindings: options.currentBindings ?? bindings(),
        });
      }
      if (path.endsWith(`/workers/workers/${WORKER_ID}/versions/${TARGET_VERSION}`)) {
        return json({
          id: TARGET_VERSION,
          main_module: 'index.js',
          compatibility_date: '2026-08-08',
          bindings: options.targetBindings ?? bindings().map((binding) => (
            binding.name === 'ANKKA_GATEWAY_RELEASE' ? { ...binding, text: 'gateway-v1.0.0' } :
            binding.name === 'ANKKA_GATEWAY_RELEASE_SHA256' ? { ...binding, text: `sha256:${'0'.repeat(64)}` } : binding
          )),
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

async function updateTransportFixture(
  failure?: 'asset_session' | 'worker_version' | 'version_verify',
  controlResponse?: ControlResponse,
  teamManagementBinding = false,
) {
  const runtimeInput = {
    accountId: ACCOUNT_ID,
    actorEmail: 'owner@example.com',
    managementHostname: 'manage.example.com',
    workerId: WORKER_ID,
    workerName: WORKER_NAME,
    workersSubdomain: 'tenant',
  };
  const runtime = await sourceActionRuntimeFixture(teamManagementBinding
    ? { ...runtimeInput, inheritTeamManagementFromVersion: OLD_VERSION } : runtimeInput);
  const fixture = transportFixture(controlResponse ? { controlResponse } : {});
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
          ...(teamManagementBinding ? [{ name: 'ANKKA_TEAM_MANAGEMENT_TOKEN', type: 'secret_text' }] : []),
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
          .map((binding) => binding.name === 'ANKKA_TEAM_MANAGEMENT_TOKEN'
            ? { name: binding.name, type: 'inherit', version_id: OLD_VERSION } : binding)
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

function holdProviderRequest(
  transport: TransportFixture['transport'],
  path: string,
  delayMs?: number,
) {
  let announce: ((request: Request) => void) | null = null;
  const arrived = new Promise<Request>((resolve) => { announce = resolve; });
  let calls = 0;
  return {
    arrived,
    callCount: () => calls,
    transport: (input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (new URL(request.url).pathname !== `/client/v4/accounts/${ACCOUNT_ID}${path}`) {
        return transport(request);
      }
      calls += 1;
      return new Promise<Response>((resolve, reject) => {
        const timer = delayMs === undefined ? undefined : setTimeout(() => resolve(transport(request)), delayMs);
        request.signal.addEventListener('abort', () => {
          if (timer !== undefined) clearTimeout(timer);
          reject(new Error(`synthetic aborted provider request ${ACCESS_TOKEN}`));
        }, { once: true });
        if (announce === null) throw new TypeError('missing request observer');
        announce(request);
      });
    },
  };
}

function caughtError<Thrown>(error: Thrown): Error {
  if (!(error instanceof Error)) throw new TypeError('unexpected relay rejection');
  return error;
}

function candidateResponse(response: (request: Request) => Promise<Response>): ControlResponse {
  return async (request) => {
    const body = await requestJson(request.clone(), commandSchema);
    return body.command === 'probe' && request.headers.has('Cloudflare-Workers-Version-Overrides')
      ? response(request) : null;
  };
}

function expectSafeControlError(error: Error, reason: string) {
  expect(error).toMatchObject({ status: 409, code: 'session_conflict', reason });
  for (const privateValue of [ACCESS_TOKEN, ASSET_UPLOAD_JWT, ASSET_COMPLETION_JWT, ACTION_KEY, 'synthetic-private-control']) {
    expect(String(error)).not.toContain(privateValue);
    expect(JSON.stringify(error)).not.toContain(privateValue);
  }
}

describe('customer-owned Team management binding', () => {
  const management = { name: 'ANKKA_TEAM_MANAGEMENT_TOKEN', type: 'secret_text' };

  it('preserves only the known secret from the exact active version during a code update', async () => {
    const fixture = await updateTransportFixture(undefined, undefined, true);
    await expect(relayRuntimeUpdate(fixture.relayInput)).resolves.toMatchObject({ status: 'succeeded' });
    expect(fixture.deployments.at(-1)).toEqual([{ version_id: TARGET_VERSION, percentage: 100 }]);
    expect(fixture.commands).toContain('complete');
    expect(fixture.subdomainStates).toEqual([true, false]);
  });

  it('does not stage a candidate when the provider drops the inherited secret', async () => {
    const fixture = await updateTransportFixture(undefined, undefined, true);
    const transport = async (requestInput: RequestInfo | URL, init?: RequestInit) => {
      const response = await fixture.relayInput.transport(requestInput, init);
      const url = new URL(requestInput instanceof Request ? requestInput.url : requestInput.toString());
      if (url.pathname.endsWith(`/versions/${TARGET_VERSION}`)) {
        const envelope = v.parse(v.object({ result: v.looseObject({ bindings: v.array(boundaryObjectSchema) }) }), await response.json());
        return json({
          ...envelope.result,
          bindings: envelope.result.bindings.filter((binding) => binding.name !== management.name),
        });
      }
      return response;
    };
    await expect(relayRuntimeUpdate({ ...fixture.relayInput, transport })).rejects.toThrow();
    expect(fixture.deployments).toEqual([]);
    expect(fixture.subdomainStates).toEqual([true, false]);
  });

  it.each([
    ['unknown secret', [...bindings(), { name: 'UNKNOWN_CREDENTIAL', type: 'secret_text' }]],
    ['plaintext management credential', [...bindings(), { ...management, type: 'plain_text', text: 'unsafe' }]],
    ['exposed secret value', [...bindings(), { ...management, text: 'unsafe' }]],
    ['duplicate binding', [...bindings(), management, management]],
    ['missing required binding', [...bindings().filter((binding) => binding.name !== 'ADMIN_EMAILS'), management]],
  ] as const)('rejects %s before any provider write', async (_label, currentBindings) => {
    const fixture = transportFixture({ currentBindings });
    await expect(relayRuntimeUpdate(input(fixture.transport))).rejects.toThrow();
    expect(fixture.deployments).toEqual([]);
    expect(fixture.subdomainStates).toEqual([]);
  });

  it.each(['current', 'target'] as const)('blocks rollback with a management secret on the %s version', async (side) => {
    const fixture = transportFixture(side === 'current'
      ? { currentBindings: [...bindings(), management] }
      : { targetBindings: [...bindings(), management] });
    await expect(relayRuntimeUpdate(input(fixture.transport))).rejects.toThrow();
    expect(fixture.deployments).toEqual([]);
    expect(fixture.subdomainStates).toEqual([]);
  });

  it('refuses to overwrite a concurrent customer secret rotation deployment', async () => {
    const fixture = await updateTransportFixture(undefined, undefined, true);
    let deploymentReads = 0;
    const transport = async (requestInput: RequestInfo | URL, init?: RequestInit) => {
      const request = requestInput instanceof Request ? requestInput : new Request(requestInput, init);
      if (new URL(request.url).pathname.endsWith('/deployments') && request.method === 'GET') {
        deploymentReads += 1;
        if (deploymentReads > 1) return json({ deployments: [{
          id: COMPENSATION_DEPLOYMENT, versions: [{ percentage: 100, version_id: TARGET_VERSION }],
        }] });
      }
      return fixture.relayInput.transport(request);
    };
    await expect(relayRuntimeUpdate({ ...fixture.relayInput, transport })).rejects.toThrow();
    expect(fixture.deployments).toEqual([]);
    expect(fixture.commands).not.toContain('complete');
  });

  it.each(['candidate_success', 'candidate_failure', 'active_failure', 'active_success'] as const)(
    'does not activate or compensate over a customer rotation during %s', async (moment) => {
      let rotated = false;
      const fixture = await updateTransportFixture(undefined, async (request) => {
        const body = await requestJson(request.clone(), commandSchema);
        const candidate = request.headers.has('Cloudflare-Workers-Version-Overrides');
        const activeProbe = moment === 'active_failure' || moment === 'active_success';
        if (body.command !== 'probe' || candidate === activeProbe) return null;
        rotated = true;
        return moment === 'candidate_success' || moment === 'active_success'
          ? new Response(null, { status: 204, headers: { 'x-ankka-runtime-action': 'ready' } })
          : Response.json({ schemaVersion: 1, error: 'runtime_action_conflict' }, { status: 409 });
      }, true);
      const transport = async (requestInput: RequestInfo | URL, init?: RequestInit) => {
        const request = requestInput instanceof Request ? requestInput : new Request(requestInput, init);
        if (rotated && new URL(request.url).pathname.endsWith('/deployments') && request.method === 'GET') {
          return json({ deployments: [{
            id: COMPENSATION_DEPLOYMENT,
            versions: [{ percentage: 100, version_id: COMPENSATION_DEPLOYMENT }],
          }] });
        }
        return fixture.relayInput.transport(request);
      };
      await expect(relayRuntimeUpdate({ ...fixture.relayInput, transport })).rejects.toThrow();
      expect(fixture.deployments).toHaveLength(moment === 'active_failure' || moment === 'active_success' ? 2 : 1);
      expect(fixture.deployments).not.toContainEqual([{ version_id: OLD_VERSION, percentage: 100 }]);
      expect(fixture.controls.at(-1)?.body).toMatchObject({
        command: 'fail', failureCode: 'runtime_action_recovery_required', recoveryRequired: true,
      });
      expect(fixture.subdomainStates).toEqual([true, false]);
      expect(fixture.commands).not.toContain('complete');
    },
  );

  it('leaves an unacknowledged activation for recovery instead of guessing compensation authority', async () => {
    const fixture = await updateTransportFixture(undefined, undefined, true);
    const transport = async (requestInput: RequestInfo | URL, init?: RequestInit) => {
      const request = requestInput instanceof Request ? requestInput : new Request(requestInput, init);
      if (new URL(request.url).pathname.endsWith('/deployments') && request.method === 'POST') {
        const body = await requestJson(request.clone(), deploymentBodySchema);
        if (body.versions.length === 1 && body.versions[0]?.version_id === TARGET_VERSION) {
          await fixture.relayInput.transport(request);
          return Response.json({ success: false }, { status: 503 });
        }
      }
      return fixture.relayInput.transport(request);
    };
    await expect(relayRuntimeUpdate({ ...fixture.relayInput, transport })).rejects.toThrow();
    expect(fixture.deployments).toHaveLength(2);
    expect(fixture.controls.at(-1)?.body).toMatchObject({ command: 'fail', recoveryRequired: true });
  });
});

describe('bounded runtime control diagnostics', () => {
  it.each([
    ['runtime_probe_version_mismatch', 'version_mismatch', 409],
    ['runtime_action_rejected', 'action_rejected', 400],
    ['runtime_action_conflict', 'action_conflict', 409],
    ['runtime_updates_unavailable', 'updates_unavailable', 503],
    ['team_action_conflict', 'team_conflict', 409],
  ] as const)('reports only the exact known candidate error %s', async (workerError, detail, status) => {
    const fixture = await updateTransportFixture(undefined, candidateResponse(async () => (
      new Response(JSON.stringify({ schemaVersion: 1, error: workerError }).padEnd(1_024, ' '), {
        status, headers: { 'content-type': 'application/json; charset=utf-8' },
      })
    )));
    const error = await relayRuntimeUpdate(fixture.relayInput).catch(caughtError);
    if (!(error instanceof Error)) throw new TypeError('expected control failure');
    expectSafeControlError(error, `runtime_candidate_probe_${detail}`);
    expect(fixture.deployments).toEqual([
      [{ version_id: OLD_VERSION, percentage: 100 }, { version_id: TARGET_VERSION, percentage: 0 }],
      [{ version_id: OLD_VERSION, percentage: 100 }],
    ]);
    expect(fixture.commands.filter((command) => command === 'probe')).toHaveLength(1);
    expect(fixture.commands).not.toContain('complete');
    expect(fixture.controls.at(-1)?.body).toMatchObject({ command: 'fail', recoveryRequired: false });
    expect(fixture.subdomainStates).toEqual([true, false]);
  });

  const knownBody = JSON.stringify({ schemaVersion: 1, error: 'runtime_probe_version_mismatch' });
  it.each([
    ['malformed JSON', () => new Response(`{synthetic-private-control:${ACCESS_TOKEN}`, { status: 409, headers: { 'content-type': 'application/json' } }), 'rejected'],
    ['extra private field', () => Response.json({ schemaVersion: 1, error: 'runtime_probe_version_mismatch', message: ACCESS_TOKEN }, { status: 409 }), 'rejected'],
    ['unknown error', () => Response.json({ schemaVersion: 1, error: 'synthetic-private-control' }, { status: 409 }), 'rejected'],
    ['wrong schema', () => Response.json({ schemaVersion: 2, error: 'runtime_probe_version_mismatch' }, { status: 409 }), 'rejected'],
    ['HTML body', () => new Response(`<p>${ACCESS_TOKEN}</p>`, { status: 503, headers: { 'content-type': 'text/html' } }), 'rejected'],
    ['missing content type', () => new Response(new TextEncoder().encode(knownBody), { status: 409 }), 'rejected'],
    ['oversize stream', () => new Response(knownBody.padEnd(1_025, ' '), { status: 409, headers: { 'content-type': 'application/json' } }), 'rejected'],
    ['oversize declared length', () => new Response(knownBody, { status: 409, headers: { 'content-type': 'application/json', 'content-length': '1025' } }), 'rejected'],
    ['success status with error body', () => Response.json({ schemaVersion: 1, error: 'runtime_probe_version_mismatch' }), 'rejected'],
    ['missing probe marker', () => new Response(null, { status: 204 }), 'rejected'],
    ['redirect', () => new Response(knownBody, { status: 302, headers: { 'content-type': 'application/json', location: `https://private.example/${ACCESS_TOKEN}` } }), 'redirect'],
  ] as const)('uses a fixed fallback for %s without echoing its body', async (_label, response, detail) => {
    const fixture = await updateTransportFixture(undefined, candidateResponse(async () => response()));
    const error = await relayRuntimeUpdate(fixture.relayInput).catch(caughtError);
    if (!(error instanceof Error)) throw new TypeError('expected control failure');
    expectSafeControlError(error, `runtime_candidate_probe_${detail}`);
    expect(fixture.deployments.at(-1)).toEqual([{ version_id: OLD_VERSION, percentage: 100 }]);
    expect(fixture.commands.filter((command) => command === 'probe')).toHaveLength(1);
    expect(fixture.commands).not.toContain('complete');
    expect(fixture.subdomainStates).toEqual([true, false]);
  });

  it.each(['begin', 'progress_candidate_staged', 'active_probe', 'complete'] as const)(
    'identifies the exact %s control phase without replaying it', async (phase) => {
      let rejectedCalls = 0;
      const fixture = await updateTransportFixture(undefined, async (request) => {
        const body = await requestJson(request.clone(), boundaryObjectSchema);
        const matches = phase === 'active_probe'
          ? body.command === 'probe' && !request.headers.has('Cloudflare-Workers-Version-Overrides')
          : phase === 'progress_candidate_staged'
            ? body.command === 'progress' && body.stage === 'candidate_staged'
            : body.command === phase;
        if (!matches) return null;
        rejectedCalls += 1;
        return Response.json({ schemaVersion: 1, error: 'runtime_action_conflict' }, { status: 409 });
      });
      const error = await relayRuntimeUpdate(fixture.relayInput).catch(caughtError);
      if (!(error instanceof Error)) throw new TypeError('expected control failure');
      expectSafeControlError(error, `runtime_${phase}_action_conflict`);
      expect(rejectedCalls).toBe(1);
      if (phase === 'begin') expect(fixture.deployments).toEqual([]);
      else expect(fixture.deployments.at(-1)).toEqual([{ version_id: OLD_VERSION, percentage: 100 }]);
      expect(fixture.commands.at(-1)).toBe('fail');
      expect(fixture.subdomainStates).toEqual([true, false]);
    },
  );

  it.each(['request', 'error body'] as const)('bounds a hung candidate %s at ten seconds and compensates once', async (kind) => {
    let announce: ((request: Request) => void) | null = null;
    const arrived = new Promise<Request>((resolve) => { announce = resolve; });
    let aborted = 0;
    const fixture = await updateTransportFixture(undefined, candidateResponse(async (request) => {
      if (announce === null) throw new TypeError('missing control observer');
      announce(request);
      if (kind === 'request') return new Promise<Response>((_resolve, reject) => {
        request.signal.addEventListener('abort', () => {
          aborted += 1;
          reject(new Error(ACCESS_TOKEN));
        }, { once: true });
      });
      return new Response(new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('{"schemaVersion":1,"error":'));
          // A real fetch response body errors when its request signal aborts.
          request.signal.addEventListener('abort', () => {
            aborted += 1;
            controller.error(new Error(ACCESS_TOKEN));
          }, { once: true });
        },
      }), { status: 409, headers: { 'content-type': 'application/json' } });
    }));
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const outcome = relayRuntimeUpdate(fixture.relayInput).catch(caughtError);
    const request = await arrived;
    await vi.advanceTimersByTimeAsync(9_999);
    expect(request.signal.aborted).toBe(false);
    expect(fixture.deployments).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    const error = await outcome;
    if (!(error instanceof Error)) throw new TypeError('expected control failure');
    expectSafeControlError(error, 'runtime_candidate_probe_timeout');
    expect(request.signal.aborted).toBe(true);
    expect(aborted).toBe(1);
    expect(fixture.commands.filter((command) => command === 'probe')).toHaveLength(1);
    expect(fixture.deployments).toHaveLength(2);
    expect(fixture.deployments.at(-1)).toEqual([{ version_id: OLD_VERSION, percentage: 100 }]);
    expect(fixture.commands).not.toContain('complete');
    expect(fixture.subdomainStates).toEqual([true, false]);
  });

  it('labels a failed control request without using the thrown message', async () => {
    const fixture = await updateTransportFixture(undefined, candidateResponse(async () => {
      throw new Error(`synthetic-private-control:${ACCESS_TOKEN}`);
    }));
    const error = await relayRuntimeUpdate(fixture.relayInput).catch(caughtError);
    if (!(error instanceof Error)) throw new TypeError('expected control failure');
    expectSafeControlError(error, 'runtime_candidate_probe_request_failed');
    expect(fixture.commands.filter((command) => command === 'probe')).toHaveLength(1);
    expect(fixture.subdomainStates).toEqual([true, false]);
  });

  it.each(['candidate_stage', 'candidate_stage_verify', 'candidate_activate', 'candidate_active_verify'] as const)(
    'labels the provider %s phase and preserves compensation', async (phase) => {
      const fixture = await updateTransportFixture();
      let rejected = 0;
      const transport: TransportFixture['transport'] = async (input, init) => {
        const request = input instanceof Request ? input : new Request(input, init);
        if (new URL(request.url).pathname.endsWith('/deployments') && rejected === 0) {
          const count = fixture.deployments.length;
          const matches = phase === 'candidate_stage' ? request.method === 'POST' && count === 0
            : phase === 'candidate_stage_verify' ? request.method === 'GET' && count === 1
              : phase === 'candidate_activate' ? request.method === 'POST' && count === 1
                : request.method === 'GET' && count === 2;
          if (matches) {
            rejected += 1;
            if (phase.endsWith('_verify')) return json({
              deployments: [{ id: INITIAL_DEPLOYMENT, versions: fixture.deployments.at(-1) }],
            });
            return Response.json({ success: false, error: ACCESS_TOKEN }, { status: 503 });
          }
        }
        return fixture.relayInput.transport(request);
      };
      const error = await relayRuntimeUpdate({ ...fixture.relayInput, transport }).catch(caughtError);
      if (!(error instanceof Error)) throw new TypeError('expected provider failure');
      expectSafeControlError(error, `runtime_${phase}`);
      expect(rejected).toBe(1);
      if (phase === 'candidate_stage') expect(fixture.deployments).toEqual([]);
      else expect(fixture.deployments.at(-1)).toEqual([{ version_id: OLD_VERSION, percentage: 100 }]);
      expect(fixture.commands).not.toContain('complete');
      expect(fixture.subdomainStates).toEqual([true, false]);
    },
  );

  it.each(['fail record', 'compensation', 'route disable'] as const)(
    'preserves the diagnostic boundary when %s also fails', async (cleanup) => {
      const fixture = await updateTransportFixture(undefined, async (request) => {
        const body = await requestJson(request.clone(), commandSchema);
        if (body.command === 'probe') return Response.json({ schemaVersion: 1, error: 'runtime_probe_version_mismatch' }, { status: 409 });
        if (body.command === 'fail' && cleanup === 'fail record') return Response.json({ schemaVersion: 1, error: 'runtime_action_conflict' }, { status: 409 });
        return null;
      });
      let rejected = 0;
      const transport: TransportFixture['transport'] = async (input, init) => {
        const request = input instanceof Request ? input : new Request(input, init);
        const path = new URL(request.url).pathname;
        const fails = cleanup === 'compensation'
          ? request.method === 'POST' && path.endsWith('/deployments') && fixture.deployments.length === 1
          : cleanup === 'route disable' && request.method === 'POST' && path.endsWith('/subdomain') &&
            (await requestJson(request.clone(), subdomainSchema)).enabled === false;
        if (fails) {
          rejected += 1;
          return Response.json({ success: false, error: ACCESS_TOKEN }, { status: 503 });
        }
        return fixture.relayInput.transport(request);
      };
      const error = await relayRuntimeUpdate({ ...fixture.relayInput, transport }).catch(caughtError);
      if (!(error instanceof Error)) throw new TypeError('expected control failure');
      expectSafeControlError(error, cleanup === 'route disable'
        ? 'runtime_route_disable_failed' : 'runtime_candidate_probe_version_mismatch');
      expect(rejected).toBe(cleanup === 'fail record' ? 0 : 1);
      expect(fixture.commands.filter((command) => command === 'probe')).toHaveLength(1);
      expect(fixture.commands.filter((command) => command === 'fail')).toHaveLength(1);
      expect(fixture.commands).not.toContain('complete');
      expect(fixture.controls.at(-1)?.body).toMatchObject({ command: 'fail', recoveryRequired: cleanup === 'compensation' });
      expect(fixture.currentSubdomain()).toBe(cleanup === 'route disable');
    },
  );
});

describe('runtime update relay', () => {
  it('allows a version POST taking fifteen seconds and then verifies, probes, and activates it', async () => {
    const fixture = await updateTransportFixture();
    const delayed = holdProviderRequest(
      fixture.relayInput.transport, `/workers/workers/${WORKER_ID}/versions`, 15_000,
    );
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const outcome = relayRuntimeUpdate({ ...fixture.relayInput, transport: delayed.transport })
      .catch(caughtError);
    const request = await delayed.arrived;
    expect(request.method).toBe('POST');
    await vi.advanceTimersByTimeAsync(14_999);
    expect(request.signal.aborted).toBe(false);
    expect(fixture.deployments).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    await expect(outcome).resolves.toMatchObject({ operation: 'update', status: 'succeeded' });
    expect(delayed.callCount()).toBe(1);
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
    expect(fixture.subdomainStates).toEqual([true, false]);
  });

  it('aborts one hung version POST at thirty seconds without deploying or retrying', async () => {
    const fixture = await updateTransportFixture();
    const held = holdProviderRequest(fixture.relayInput.transport, `/workers/workers/${WORKER_ID}/versions`);
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const outcome = relayRuntimeUpdate({ ...fixture.relayInput, transport: held.transport })
      .catch(caughtError);
    const request = await held.arrived;
    await vi.advanceTimersByTimeAsync(29_999);
    expect(request.signal.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(request.signal.aborted).toBe(true);
    const error = await outcome;
    expect(error).toMatchObject({
      code: 'provider_unknown', stage: 'worker_version', outcome: 'unknown', canRetry: false, submissions: [],
    });
    expect(String(error)).not.toContain(ACCESS_TOKEN);
    expect(JSON.stringify(error)).not.toContain(ACCESS_TOKEN);
    expect(held.callCount()).toBe(1);
    expect(fixture.events).not.toContain('version_verify');
    expect(fixture.deployments).toEqual([]);
    expect(fixture.commands).not.toContain('probe');
    expect(fixture.commands).not.toContain('complete');
    expect(fixture.controls.at(-1)?.body).toMatchObject({ command: 'fail', failureCode: 'runtime_action_failed' });
    expect(fixture.subdomainStates).toEqual([true, false]);
    expect(fixture.currentSubdomain()).toBe(false);
  });

  it.each([
    ['asset_session', `/workers/scripts/${WORKER_NAME}/assets-upload-session`],
    ['version_verify', `/workers/workers/${WORKER_ID}/versions/${TARGET_VERSION}`],
  ] as const)('keeps the %s deadline at ten seconds', async (stage, path) => {
    const fixture = await updateTransportFixture();
    const held = holdProviderRequest(fixture.relayInput.transport, path);
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const outcome = relayRuntimeUpdate({ ...fixture.relayInput, transport: held.transport })
      .catch(caughtError);
    const request = await held.arrived;
    await vi.advanceTimersByTimeAsync(9_999);
    expect(request.signal.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(request.signal.aborted).toBe(true);
    await expect(outcome).resolves.toMatchObject({
      code: 'provider_unknown', stage, canRetry: false,
      outcome: stage === 'version_verify' ? 'submitted' : 'unknown',
    });
    expect(held.callCount()).toBe(1);
    expect(fixture.deployments).toEqual([]);
    expect(fixture.commands).toContain('fail');
    expect(fixture.commands).not.toContain('probe');
    expect(fixture.commands).not.toContain('complete');
    expect(fixture.subdomainStates).toEqual([true, false]);
    expect(fixture.currentSubdomain()).toBe(false);
  });

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
