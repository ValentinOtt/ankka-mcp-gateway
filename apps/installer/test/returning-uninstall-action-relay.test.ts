import * as v from 'valibot';
import { describe, expect, it } from 'vitest';

import { boundaryObjectSchema } from '../src/boundary';
import {
  applyReturningUninstallAction,
  relayReturningUninstallAction,
} from '../src/returning-uninstall-action-relay';
import { parseReturningUninstallImportedAuthority } from '../src/returning-uninstall-authority';
import { requestJson } from './boundary';
import { readyInstallationReceiptFixture } from './provider-neutral-installation-receipt-fixture';

const ACCOUNT_ID = 'a'.repeat(32);
const ACTION_ID = `action_${'A'.repeat(32)}`;
const ACTION_KEY = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc';
const ACCESS_TOKEN = 'returning-uninstall-access-token-value';
const INSTALLATION_ID = `acg-${'d'.repeat(24)}`;
const NOW = Date.UTC(2026, 7, 26, 0, 0, 0);
const REQUEST_ID = 'R'.repeat(22);
const WORKER_ID = 'b'.repeat(32);
const VERSION_ID = '11111111-1111-4111-8111-111111111111';
const DEPLOYMENT_ID = '22222222-2222-4222-8222-222222222222';
const subdomainMutationSchema = v.object({ enabled: v.boolean(), previews_enabled: v.boolean() });

interface AuthoritySourceFixture {
  readonly id: string;
  readonly label: string;
  readonly url: string;
  readonly authMode: 'none' | 'oauth';
  readonly enabledTools: readonly string[];
  readonly status: 'installed' | 'draft';
}

function envelope<Result>(result: Result, status = 200): Response {
  return new Response(JSON.stringify({ success: status >= 200 && status < 300, result }), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function runtimeBindings(overrides: Readonly<Record<string, string>> = {}) {
  const values = {
    ADMIN_EMAILS: 'admin@example.com',
    ANKKA_INSTALL_ID: INSTALLATION_ID,
    ANKKA_GATEWAY_RELEASE: 'gateway-v1.0.0',
    ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${'1'.repeat(64)}`,
    ANKKA_MANAGEMENT_HOSTNAME: 'manage.example.com',
    ANKKA_UPDATE_CHANNEL: 'canary',
    ANKKA_UPDATE_KEY_ID: 'release-test-v1',
    ANKKA_UPDATE_PUBLIC_KEY: 'A'.repeat(43),
    ANKKA_WORKERS_SUBDOMAIN: 'customer-workers',
    ANKKA_WORKER_NAME: 'ankka-gateway-example',
    CF_ACCESS_AUD: 'access-audience-tag',
    CF_ACCESS_ISSUER: 'https://customer.cloudflareaccess.com',
    CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID,
    CLOUDFLARE_ZONE_ID: 'c'.repeat(32),
    CLOUDFLARE_ZONE_NAME: 'example.com',
    ZERO_TRUST_READY: 'true',
    ...overrides,
  };
  return [
    { name: 'ADMIN_STATE', type: 'durable_object_namespace', class_name: 'AdminState' },
    { name: 'ASSETS', type: 'assets' },
    ...Object.entries(values).map(([name, text]) => ({ name, text, type: 'plain_text' })),
  ];
}

function runtimePreflightResponse(
  url: URL,
  options: Readonly<{
    bindingOverrides?: Readonly<Record<string, string>>;
    workerTags?: readonly string[];
  }> = {},
): Response | null {
  if (url.pathname.endsWith('/workers/subdomain')) return envelope({ subdomain: 'customer-workers' });
  if (url.pathname.endsWith('/workers/domains')) return envelope([{
    hostname: 'manage.example.com',
    service: 'ankka-gateway-example',
    environment: 'production',
  }]);
  if (url.pathname.endsWith('/workers/workers/ankka-gateway-example')) {
    return envelope({
      id: WORKER_ID,
      name: 'ankka-gateway-example',
      tags: options.workerTags ?? ['ankka-mcp-gateway'],
    });
  }
  if (url.pathname.endsWith('/workers/scripts/ankka-gateway-example/deployments')) {
    return envelope({ deployments: [{
      id: DEPLOYMENT_ID,
      versions: [{ percentage: 100, version_id: VERSION_ID }],
    }] });
  }
  if (url.pathname.endsWith(`/workers/workers/${WORKER_ID}/versions/${VERSION_ID}`)) {
    return envelope({
      id: VERSION_ID,
      main_module: 'index.js',
      compatibility_date: '2026-08-08',
      bindings: runtimeBindings(options.bindingOverrides),
    });
  }
  return null;
}

function input(transport: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) {
  return {
    actionId: ACTION_ID,
    actionKey: ACTION_KEY,
    actorEmail: 'admin@example.com',
    accountId: ACCOUNT_ID,
    installationId: INSTALLATION_ID,
    workerName: 'ankka-gateway-example',
    workersSubdomain: 'customer-workers',
    managementOrigin: 'https://manage.example.com',
    portalHostname: 'mcp.example.com',
    gatewayName: 'Example Gateway',
    expiresAt: NOW + 10 * 60 * 1000,
    accessToken: ACCESS_TOKEN,
    transport,
    now: () => NOW,
  } as const;
}

async function authorityEnvelope(
  runtimeOverrides: Readonly<Record<string, string>> = {},
  sources: readonly AuthoritySourceFixture[] = [],
) {
  const resourceKinds = [
    'portal', 'portal_access_application', 'portal_access_policy', 'dns_record',
  ] as const;
  const receipt = await readyInstallationReceiptFixture({
    installationId: INSTALLATION_ID,
    release: 'gateway-v0.9.0',
    desiredHash: `sha256:${'2'.repeat(64)}`,
    target: {
      accountId: ACCOUNT_ID,
      zoneId: 'c'.repeat(32),
      zoneName: 'example.com',
      hostname: 'mcp.example.com',
    },
    accessPolicy: {
      identityType: 'email',
      identityCount: 1,
      identitiesHash: `sha256:${'3'.repeat(64)}`,
    },
    resources: resourceKinds.map((kind, index) => {
      const key = `resource-${index}`;
      const base = {
        kind,
        key,
        desiredHash: `sha256:${String(index + 4).repeat(64)}`,
        marker: `acg:v1:${INSTALLATION_ID}:${key}`,
      };
      return kind === 'portal_access_policy'
        ? { ...base, identityHash: `sha256:${'8'.repeat(64)}` }
        : base;
    }),
  });
  const portal = receipt.resources[0];
  if (!portal || portal.kind !== 'portal') throw new TypeError('portal authority fixture');
  return {
    schemaVersion: 1,
    status: 'authorized',
    authority: {
      schemaVersion: 1,
      installationId: INSTALLATION_ID,
      root: { receipt },
      control: {
        schemaVersion: 1,
        installationId: INSTALLATION_ID,
        accountId: ACCOUNT_ID,
        audienceEmails: ['admin@example.com'],
        portal: {
          id: portal.provider.id,
          hostname: 'mcp.example.com',
          name: 'Example Gateway',
          marker: portal.marker,
        },
        sourceOwnership: [],
      },
      sources: { schemaVersion: 1, revision: 1, applyMode: 'oauth_per_action', sources },
      runtime: {
        release: 'gateway-v1.0.0',
        artifactSha256: `sha256:${'1'.repeat(64)}`,
        controlPlaneOrigin: 'https://deploy.ankka.ai',
        updateChannel: 'canary',
        updateKeyId: 'release-test-v1',
        updatePublicKey: 'A'.repeat(43),
        accountId: ACCOUNT_ID,
        zoneId: 'c'.repeat(32),
        zoneName: 'example.com',
        workerName: 'ankka-gateway-example',
        workersSubdomain: 'customer-workers',
        managementHostname: 'manage.example.com',
        ...runtimeOverrides,
      },
    },
    actionId: ACTION_ID,
  } as const;
}

async function authority(
  runtimeOverrides: Readonly<Record<string, string>> = {},
) {
  return await parseReturningUninstallImportedAuthority(
    await authorityEnvelope(runtimeOverrides),
    authorityExpectation(),
  );
}

function authorityExpectation() {
  return {
    actionId: ACTION_ID,
    actorEmail: 'admin@example.com',
    installationId: INSTALLATION_ID,
    accountId: ACCOUNT_ID,
    workerName: 'ankka-gateway-example',
    workersSubdomain: 'customer-workers',
    managementOrigin: 'https://manage.example.com',
    portalHostname: 'mcp.example.com',
    gatewayName: 'Example Gateway',
  } as const;
}

function largeDraftSources(sourceCount = 15) {
  return Array.from({ length: sourceCount }, (_source, sourceIndex) => ({
    id: `source-${String(sourceIndex).padStart(16, '0')}`,
    label: `Synthetic source ${String(sourceIndex).padStart(2, '0')}`,
    url: `https://source-${String(sourceIndex).padStart(2, '0')}.example.net/mcp`,
    authMode: 'none' as const,
    enabledTools: Array.from({ length: 500 }, (_tool, toolIndex) => (
      `tool_${String(sourceIndex).padStart(2, '0')}_${String(toolIndex).padStart(3, '0')}_`.padEnd(128, 'x')
    )),
    status: 'draft' as const,
  }));
}

describe('returning uninstall customer-action relay', () => {
  it('rejects an unrelated Worker before any route mutation or customer-control request', async () => {
    let providerWrites = 0;
    let customerCalls = 0;
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(requestInput, init);
      const url = new URL(request.url);
      if (url.origin !== 'https://api.cloudflare.com') {
        customerCalls += 1;
        throw new Error('customer route must not be reached');
      }
      expect(request.headers.get('authorization')).toBe(`Bearer ${ACCESS_TOKEN}`);
      expect(request.redirect).toBe('manual');
      const preflight = runtimePreflightResponse(url, { workerTags: ['customer-worker'] });
      if (preflight) return preflight;
      if (request.method === 'GET') return envelope({ enabled: false, previews_enabled: false });
      providerWrites += 1;
      throw new Error('provider write must not be reached');
    };

    await expect(relayReturningUninstallAction(input(transport)))
      .rejects.toMatchObject({ code: 'session_conflict' });
    expect(providerWrites).toBe(0);
    expect(customerCalls).toBe(0);
  });

  it('rejects an emulated Worker with binding drift before relaying the grant', async () => {
    let providerWrites = 0;
    let customerCalls = 0;
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(requestInput, init);
      const url = new URL(request.url);
      if (url.origin !== 'https://api.cloudflare.com') {
        customerCalls += 1;
        throw new Error('customer route must not be reached');
      }
      const preflight = runtimePreflightResponse(url, {
        bindingOverrides: { CLOUDFLARE_ACCOUNT_ID: 'e'.repeat(32) },
      });
      if (preflight) return preflight;
      if (request.method === 'GET') return envelope({ enabled: false, previews_enabled: false });
      providerWrites += 1;
      throw new Error('provider write must not be reached');
    };

    await expect(applyReturningUninstallAction(input(transport), REQUEST_ID, await authority(), async () => {
      throw new Error('post-ready proof must not be reached');
    }))
      .rejects.toMatchObject({ code: 'session_conflict' });
    expect(providerWrites).toBe(0);
    expect(customerCalls).toBe(0);
  });

  it('rejects live bindings that do not match the imported runtime authority before route mutation', async () => {
    let providerWrites = 0;
    let customerCalls = 0;
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(requestInput, init);
      const url = new URL(request.url);
      if (url.origin !== 'https://api.cloudflare.com') {
        customerCalls += 1;
        throw new Error('customer route must not be reached');
      }
      const preflight = runtimePreflightResponse(url);
      if (preflight) return preflight;
      if (request.method === 'GET') return envelope({ enabled: false, previews_enabled: false });
      providerWrites += 1;
      throw new Error('provider write must not be reached');
    };

    await expect(applyReturningUninstallAction(input(transport), REQUEST_ID, await authority({
      artifactSha256: `sha256:${'2'.repeat(64)}`,
    }), async () => {
      throw new Error('post-ready proof must not be reached');
    })).rejects.toMatchObject({ code: 'session_conflict' });
    expect(providerWrites).toBe(0);
    expect(customerCalls).toBe(0);
  });

  it('rejects returning-removal authority for another control-plane origin before route mutation', async () => {
    let providerWrites = 0;
    let customerCalls = 0;
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(requestInput, init);
      const url = new URL(request.url);
      if (url.origin !== 'https://api.cloudflare.com') {
        customerCalls += 1;
        throw new Error('customer route must not be reached');
      }
      const preflight = runtimePreflightResponse(url);
      if (preflight) return preflight;
      if (request.method === 'GET') return envelope({ enabled: false, previews_enabled: false });
      providerWrites += 1;
      throw new Error('provider write must not be reached');
    };

    await expect(applyReturningUninstallAction(
      input(transport),
      REQUEST_ID,
      await authority({ controlPlaneOrigin: 'https://foreign-control.example' }),
      async () => { throw new Error('post-ready proof must not be reached'); },
    )).rejects.toMatchObject({ code: 'session_conflict' });
    expect(providerWrites).toBe(0);
    expect(customerCalls).toBe(0);
  });

  it('imports a storage-valid large proof with 500 maximum-length tool names per source', async () => {
    const sources = largeDraftSources().map((source, index) => index === 0 ? {
      ...source,
      label: '<Operational source>',
      url: 'https://source-00.example.net/v1/mcp',
    } : source);
    const serializedAuthority = JSON.stringify(await authorityEnvelope({}, sources));
    const authorityBytes = new TextEncoder().encode(serializedAuthority).byteLength;
    expect(authorityBytes).toBeGreaterThan(256 * 1024);
    expect(authorityBytes).toBeLessThan(4 * 1024 * 1024);
    expect(new TextEncoder().encode(JSON.stringify({
      schemaVersion: 1,
      revision: 1,
      applyMode: 'oauth_per_action',
      sources,
    })).byteLength).toBeLessThanOrEqual(1024 * 1024);

    let enabled = false;
    const providerWrites: boolean[] = [];
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(requestInput, init);
      const url = new URL(request.url);
      if (url.origin === 'https://api.cloudflare.com') {
        const preflight = runtimePreflightResponse(url);
        if (preflight) return preflight;
        if (request.method === 'GET') return envelope({ enabled, previews_enabled: false });
        const body = await requestJson(request, subdomainMutationSchema);
        enabled = body.enabled;
        providerWrites.push(enabled);
        return envelope({ enabled, previews_enabled: false });
      }
      expect(url.href).toBe(
        'https://ankka-gateway-example.customer-workers.workers.dev/__ankka/teardown-action',
      );
      if (request.method === 'HEAD') {
        return new Response(null, { status: 204, headers: { 'x-ankka-teardown-action': 'ready' } });
      }
      const body = await requestJson(request, boundaryObjectSchema);
      expect(body).toMatchObject({ command: 'prove', actionId: ACTION_ID });
      return new Response(serializedAuthority, { headers: { 'content-type': 'application/json' } });
    };

    const result = await relayReturningUninstallAction(input(transport));
    expect(result.sources.sources).toHaveLength(15);
    expect(result.sources.sources.every((source) => source.enabledTools.length === 500)).toBe(true);
    expect(result.sources.sources[0]).toMatchObject({
      label: '<Operational source>',
      url: 'https://source-00.example.net/v1/mcp',
    });
    expect(result.sources.sources.at(-1)?.enabledTools.at(-1)).toHaveLength(128);
    expect(providerWrites).toEqual([true, false]);
    expect(enabled).toBe(false);
  });

  it('rejects an authority whose source journal exceeds the customer storage contract', async () => {
    const sources = largeDraftSources(32);
    const record = { schemaVersion: 1, revision: 1, applyMode: 'oauth_per_action', sources } as const;
    expect(new TextEncoder().encode(JSON.stringify(record)).byteLength).toBeGreaterThan(1024 * 1024);
    await expect(parseReturningUninstallImportedAuthority(
      await authorityEnvelope({}, sources),
      authorityExpectation(),
    )).rejects.toMatchObject({ code: 'session_conflict' });
  });

  it('cancels an over-limit authority proof and still closes workers.dev', async () => {
    let enabled = false;
    let proofBodyCancelled = false;
    const providerWrites: boolean[] = [];
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(requestInput, init);
      const url = new URL(request.url);
      if (url.origin === 'https://api.cloudflare.com') {
        const preflight = runtimePreflightResponse(url);
        if (preflight) return preflight;
        if (request.method === 'GET') return envelope({ enabled, previews_enabled: false });
        const body = await requestJson(request, subdomainMutationSchema);
        enabled = body.enabled;
        providerWrites.push(enabled);
        return envelope({ enabled, previews_enabled: false });
      }
      if (request.method === 'HEAD') {
        return new Response(null, { status: 204, headers: { 'x-ankka-teardown-action': 'ready' } });
      }
      return new Response(new ReadableStream({
        cancel() { proofBodyCancelled = true; },
      }), {
        headers: {
          'content-type': 'application/json',
          'content-length': String((4 * 1024 * 1024) + 1),
        },
      });
    };

    await expect(relayReturningUninstallAction(input(transport)))
      .rejects.toMatchObject({ code: 'session_conflict' });
    expect(proofBodyCancelled).toBe(true);
    expect(providerWrites).toEqual([true, false]);
    expect(enabled).toBe(false);
  });

  it('relays the grant once only after the receipt and current runtime match, then closes workers.dev', async () => {
    let enabled = false;
    let customerPosts = 0;
    const providerWrites: boolean[] = [];
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(requestInput, init);
      const url = new URL(request.url);
      if (url.origin === 'https://api.cloudflare.com') {
        expect(request.headers.get('authorization')).toBe(`Bearer ${ACCESS_TOKEN}`);
        expect(request.redirect).toBe('manual');
        const preflight = runtimePreflightResponse(url);
        if (preflight) return preflight;
        if (request.method === 'GET') return envelope({ enabled, previews_enabled: false });
        const body = await requestJson(request, subdomainMutationSchema);
        expect(body.previews_enabled).toBe(false);
        enabled = body.enabled;
        providerWrites.push(enabled);
        return envelope({ enabled, previews_enabled: false });
      }
      expect(url.href).toBe(
        'https://ankka-gateway-example.customer-workers.workers.dev/__ankka/teardown-action',
      );
      expect(request.redirect).toBe('manual');
      if (request.method === 'HEAD') {
        expect(enabled).toBe(true);
        return new Response(null, { status: 204, headers: { 'x-ankka-teardown-action': 'ready' } });
      }
      customerPosts += 1;
      expect(enabled).toBe(true);
      expect(request.headers.get('authorization')).toBeNull();
      expect(request.headers.get('cookie')).toBeNull();
      expect(request.headers.get('x-ankka-teardown-action-signature')).toMatch(/^sha256=[a-f0-9]{64}$/u);
      const body = await requestJson(request, boundaryObjectSchema);
      expect(body).toMatchObject({
        schemaVersion: 1,
        command: 'apply',
        actionId: ACTION_ID,
        requestId: REQUEST_ID,
        cloudflareAccessToken: ACCESS_TOKEN,
      });
      return new Response(JSON.stringify({
        schemaVersion: 1,
        actionId: ACTION_ID,
        status: 'gateway_removed',
        installationId: INSTALLATION_ID,
        removedResourceCount: 4,
      }), { headers: { 'content-type': 'application/json' } });
    };

    let postReadyProofs = 0;
    await expect(applyReturningUninstallAction(input(transport), REQUEST_ID, await authority(), async () => {
      expect(enabled).toBe(true);
      expect(customerPosts).toBe(0);
      postReadyProofs += 1;
    }))
      .resolves.toEqual({
        schemaVersion: 1,
        actionId: ACTION_ID,
        status: 'gateway_removed',
        installationId: INSTALLATION_ID,
        removedResourceCount: 4,
      });
    expect(customerPosts).toBe(1);
    expect(postReadyProofs).toBe(1);
    expect(providerWrites).toEqual([true, false]);
    expect(enabled).toBe(false);
  });

  it('closes workers.dev without forwarding the grant when the post-readiness runtime proof drifts', async () => {
    let enabled = false;
    let customerPosts = 0;
    const providerWrites: boolean[] = [];
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(requestInput, init);
      const url = new URL(request.url);
      if (url.origin === 'https://api.cloudflare.com') {
        const preflight = runtimePreflightResponse(url);
        if (preflight) return preflight;
        if (request.method === 'GET') return envelope({ enabled, previews_enabled: false });
        const body = await requestJson(request, subdomainMutationSchema);
        enabled = body.enabled;
        providerWrites.push(enabled);
        return envelope({ enabled, previews_enabled: false });
      }
      if (request.method === 'HEAD') {
        expect(enabled).toBe(true);
        return new Response(null, { status: 204, headers: { 'x-ankka-teardown-action': 'ready' } });
      }
      customerPosts += 1;
      throw new Error('token-bearing customer request must not be reached');
    };

    await expect(applyReturningUninstallAction(
      input(transport),
      REQUEST_ID,
      await authority(),
      async () => { throw new Error('active release changed'); },
    )).rejects.toThrow('active release changed');
    expect(customerPosts).toBe(0);
    expect(providerWrites).toEqual([true, false]);
    expect(enabled).toBe(false);
  });
});
