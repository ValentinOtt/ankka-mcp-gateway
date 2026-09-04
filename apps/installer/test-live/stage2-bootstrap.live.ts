import { readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as v from 'valibot';
import { afterAll, describe, expect, it } from 'vitest';

import { type BoundaryValue } from '../src/boundary';
import { base64UrlEncode } from '../src/crypto';
import {
  prepareCustomerBootstrapClaimFromPlan,
  submitCustomerBootstrapFromPlan,
} from '../src/customer-bootstrap-request';
import { customerPayloadEnvironment } from '../src/customer-payload-environment';
import { buildStaticDeployPlan, parseDeploySelection } from '../src/schema';
import type { ReleaseManifest, StaticDeployPlan } from '../src/schema';
import { PUBLIC_ORIGIN } from '../src/constants';

/**
 * Token-mode Stage 2 harness: the converger's real bootstrap request into the
 * shipped payload, in-process, against the real Cloudflare API of the test
 * account with an API token instead of the OAuth grant. Every provider call is
 * traced (method, path, status, duration; never tokens or bodies). Resources
 * the payload creates are removed afterwards from its own receipt.
 */
const env = (name: string): string => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
};
const TOKEN = env('ANKKA_LIVE_TOKEN');
const ACCOUNT_ID = env('ANKKA_LIVE_ACCOUNT_ID');
const ZONE_ID = env('ANKKA_LIVE_ZONE_ID');
const ZONE_NAME = env('ANKKA_LIVE_ZONE_NAME');
const PREFIX = process.env.ANKKA_LIVE_PREFIX ?? 'harness';
const GATEWAY_NAME = process.env.ANKKA_LIVE_GATEWAY_NAME ?? `Ankka ${PREFIX}`;
const ADMIN_EMAIL = env('ANKKA_LIVE_ADMIN_EMAIL');
const MANIFEST_PATH = env('ANKKA_LIVE_MANIFEST');
const PAYLOAD_SPECIFIER = process.env.ANKKA_LIVE_PAYLOAD ?? '../../../payload/worker/index.js';
const PAYLOAD_URL = pathToFileURL(isAbsolute(PAYLOAD_SPECIFIER)
  ? PAYLOAD_SPECIFIER
  : resolve(dirname(fileURLToPath(import.meta.url)), PAYLOAD_SPECIFIER)).href;
const KEEP = process.env.ANKKA_LIVE_KEEP === '1';

const target = Object.freeze({ accountId: ACCOUNT_ID, zoneId: ZONE_ID, zoneName: ZONE_NAME });
const NONCE = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
const KEY = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));

interface Trace { readonly method: string; readonly path: string; readonly status: number | string; readonly ms: number }
const trace: Trace[] = [];
const realFetch = globalThis.fetch;
// SAFETY: the wrapper forwards every call to the real fetch with the same
// Request and only records method, path, status and duration beside it.
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const request = new Request(input, init);
  const url = new URL(request.url);
  const started = performance.now();
  try {
    const response = await realFetch(request);
    trace.push({ method: request.method, path: `${url.host}${url.pathname}${url.search}`, status: response.status, ms: Math.round(performance.now() - started) });
    return response;
  } catch (error) {
    trace.push({ method: request.method, path: `${url.host}${url.pathname}`, status: `threw ${error instanceof Error ? error.name : 'unknown'}`, ms: Math.round(performance.now() - started) });
    throw error;
  }
}) as typeof fetch;

/** Durable Object storage stand-in: the payload only uses get and put. */
class MemoryStorage {
  readonly map = new Map<string, BoundaryValue>();
  async get(key: string): Promise<BoundaryValue | undefined> { return this.map.get(key); }
  async put(key: string, value: BoundaryValue): Promise<void> { this.map.set(key, structuredClone(value)); }
}

function stageOneEnvironment(plan: StaticDeployPlan) {
  const worker = plan.managementResources.find((resource) => resource.kind === 'management_worker');
  if (!worker) throw new TypeError('plan has no management worker');
  return Object.freeze({
    CLOUDFLARE_ACCOUNT_ID: target.accountId,
    ANKKA_INSTALL_ID: plan.managementOwnershipMarker,
    ANKKA_WORKER_NAME: worker.name,
    ANKKA_GATEWAY_RELEASE: plan.releaseId,
    ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${plan.releaseArtifactSha256}`,
    ANKKA_PLAN_ID: plan.planId,
    ANKKA_PLAN_HASH: plan.planHash,
    ANKKA_BOOTSTRAP_ID: `boot_${'a'.repeat(24)}`,
    ANKKA_BOOTSTRAP_SECRET_SHA256: `sha256:${'b'.repeat(64)}`,
    ANKKA_BOOTSTRAP_EXPIRES_AT: String(Date.now() + 3_600_000),
    ANKKA_BOOTSTRAP_CALLBACK: `https://${worker.name}.example.workers.dev/__ankka/install/oauth/callback`,
    ANKKA_INSTALLER_ORIGIN: PUBLIC_ORIGIN,
    ANKKA_MANAGEMENT_HOSTNAME: plan.gatewayConfiguration.managementHostname,
    ANKKA_UPDATE_CHANNEL: 'canary',
    ANKKA_UPDATE_KEY_ID: 'release-2026-09-dev1',
    ANKKA_UPDATE_PUBLIC_KEY: KEY,
    CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID: 'c'.repeat(32),
    CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY: KEY,
    CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID: 'issuer-2026-09',
    ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY: KEY,
    ANKKA_BOOTSTRAP_NONCE: NONCE,
  });
}

async function api(method: string, path: string): Promise<{ status: number; body: unknown }> {
  const response = await realFetch(`https://api.cloudflare.com/client/v4${path}`, {
    method,
    headers: { authorization: `Bearer ${TOKEN}`, accept: 'application/json' },
  });
  return { status: response.status, body: await response.json().catch(() => null) };
}

const recordedStateSchema = v.looseObject({
  resources: v.array(v.looseObject({
    kind: v.string(),
    provider: v.optional(v.nullable(v.looseObject({ id: v.optional(v.string()) }))),
  })),
});
const storage = new MemoryStorage();
const created: { kind: string; id: string }[] = [];

function printTrace(): void {
  console.log(`\n--- provider trace (${trace.length} calls) ---`);
  for (const entry of trace) console.log(`${String(entry.status).padEnd(6)} ${entry.ms.toString().padStart(5)}ms ${entry.method} ${entry.path}`);
}

describe('token-mode Stage 2 bootstrap against the test account', () => {
  afterAll(async () => {
    printTrace();
    if (KEEP) { console.log('ANKKA_LIVE_KEEP=1: leaving resources in place'); return; }
    // Remove what the payload recorded, most dependent first.
    const order = ['portal_access_policy', 'source_access_policy', 'portal_access_application', 'source_access_application', 'portal', 'mcp_server', 'dns_record'];
    for (const kind of order) {
      for (const resource of created.filter((entry) => entry.kind === kind)) {
        const path = kind === 'dns_record' ? `/zones/${ZONE_ID}/dns_records/${resource.id}`
          : kind === 'portal' ? `/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/portals/${resource.id}`
          : kind === 'mcp_server' ? `/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/servers/${resource.id}`
          : kind.endsWith('_application') ? `/accounts/${ACCOUNT_ID}/access/apps/${resource.id}`
          : null;
        if (path === null) continue; // policies go with their application
        const result = await api('DELETE', path);
        console.log(`cleanup ${kind} ${resource.id}: http ${result.status}`);
      }
    }
  });

  it('creates the gateway resources and verifies its own receipt', async () => {
    // SAFETY: the file is a manifest written by build-gateway-release-candidate;
    // buildStaticDeployPlan verifies its integrity before anything uses it.
    const manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf8')) as ReleaseManifest;
    const selection = parseDeploySelection({
      schemaVersion: 1,
      basics: {
        gatewayName: GATEWAY_NAME,
        zoneName: ZONE_NAME,
        adminEmail: ADMIN_EMAIL,
        additionalAdminEmails: [],
        managementHostname: `manage${PREFIX}.${ZONE_NAME}`,
        portalHostname: `mcp${PREFIX}.${ZONE_NAME}`,
      },
      firstSource: null,
    });
    const nowMs = Date.now();
    const plan = await buildStaticDeployPlan(selection, manifest, nowMs + 30 * 60_000);
    const environment = customerPayloadEnvironment(stageOneEnvironment(plan), target);
    const payload = await import(PAYLOAD_URL);
    console.log(`install ${plan.managementOwnershipMarker} portal mcp${PREFIX}.${ZONE_NAME} release ${plan.releaseId}`);

    const result = await submitCustomerBootstrapFromPlan({
      plan,
      target,
      accountWorkersSubdomain: { accountId: ACCOUNT_ID, subdomain: 'harness' },
      bootstrapNonce: NONCE,
      cloudflareAccessToken: TOKEN,
      transport: async (request: Request) => {
        const response: Response = await payload.processBootstrap(request, environment, storage);
        Object.defineProperty(response, 'url', { configurable: true, value: request.url });
        return response;
      },
      timeoutMs: 120_000,
      nowMs,
    });
    // Whatever happened, remember what the payload recorded so cleanup is exact.
    const stored = v.safeParse(recordedStateSchema, storage.map.get('ankka-mcp-gateway/uninstall-state/v1'));
    for (const resource of stored.success ? stored.output.resources : []) {
      if (resource.provider?.id) created.push({ kind: resource.kind, id: resource.provider.id });
    }
    console.log('bootstrap result:', JSON.stringify(result).slice(0, 400));
    console.log('recorded resources:', JSON.stringify(created));
    expect(result.status).toBe('ready');

    const claim = await prepareCustomerBootstrapClaimFromPlan({ plan, target, nowMs: Date.now() });
    const verdict = await payload.verifyBootstrapReceiptProviderStateWithReason(
      { ...claim, cloudflareAccessToken: TOKEN }, environment, storage, Date.now(),
    );
    console.log('receipt verification:', JSON.stringify(verdict));
    expect(verdict).toEqual({ verified: true, reason: null });
  });
});
