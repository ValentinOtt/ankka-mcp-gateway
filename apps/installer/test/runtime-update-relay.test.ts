import { describe, expect, it } from 'vitest';
import { relayRuntimeUpdate } from '../src/runtime-update-relay';
import { verifiedReleaseBundle } from './fixtures';

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

function json(result: unknown, status = 200): Response {
  return new Response(JSON.stringify({ success: status < 300, errors: [], messages: [], result }), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function bindings(): readonly unknown[] {
  const values: Record<string, string> = {
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
}> = {}): {
  transport: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
  deployments: Array<readonly unknown[]>;
  commands: string[];
  subdomainStates: boolean[];
  currentSubdomain: () => boolean;
} {
  let active = [{ percentage: 100, version_id: OLD_VERSION }];
  let deploymentId = INITIAL_DEPLOYMENT;
  let deploymentWrites = 0;
  let subdomain = options.initialSubdomain ?? false;
  const deployments: Array<readonly unknown[]> = [];
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
        const body = await request.json() as { command: string };
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
          const body = await request.json() as { enabled: boolean };
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
          const body = await request.json() as { versions: readonly unknown[] };
          active = [...body.versions] as typeof active;
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
    accessToken: 'cloudflare-access-token-value',
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

describe('runtime update relay', () => {
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
