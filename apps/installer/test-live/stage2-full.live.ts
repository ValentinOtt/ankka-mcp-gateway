import { readFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as v from 'valibot';
import { afterAll, describe, expect, it } from 'vitest';

import { type BoundaryValue } from '../src/boundary';
import { canonicalJson } from '../src/canonical-json';
import { issueCloudflareGatewayOwnershipCertificate } from '../src/cloudflare-gateway-ownership-proof';
import { base64UrlEncode, sha256Hex } from '../src/crypto';
import { prepareCustomerBootstrapClaimFromPlan } from '../src/customer-bootstrap-request';
import {
  acceptCustomerGatewayOwnershipHandoff,
  initializeCustomerGatewayOwnershipState,
  type CustomerGatewayOwnershipStorage,
} from '../src/customer-gateway-ownership-state';
import { customerPayloadEnvironment } from '../src/customer-payload-environment';
import {
  CUSTOMER_STAGE2_CHUNK_CHECKPOINTS,
  convergeCustomerStage2,
  type CustomerStage2ConvergerResult,
} from '../src/customer-stage2-converger';
import type { CustomerStage2JournalPort } from '../src/customer-stage2-durable-state';
import type { CustomerStage2Journal } from '../src/customer-stage2-journal';
import {
  completeHostedStage1Handoff,
  createHostedStage1Secrets,
  expectedCustomerBootstrapBindings,
  provisionHostedStage1,
} from '../src/hosted-stage1-bootstrap';
import {
  PinnedR2ReleaseBundleProvider,
  type R2ReleaseReadBucket,
  type R2ReleaseReadObject,
} from '../src/r2-release-provider';
import { buildStaticDeployPlan, parseDeploySelection } from '../src/schema';
import type { StaticDeployPlan } from '../src/schema';
import { parseVerifiedReleaseBundle } from '../src/verified-release-bundle';

/**
 * Full token-mode Stage 2 harness. Hosted Stage 1 provisions the real shell
 * Worker in the test account and completes the handoff against it; then the
 * Stage 2 converger runs in this process against the real provider with the
 * shipped payload in-process. The only things faked are the two OAuth
 * endpoints, which hand back the API token as the grant, and the account
 * list, which names the test account. Every provider call is traced.
 */
const env = (name: string): string => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
};
const TOKEN = env('ANKKA_LIVE_TOKEN');
const ACCOUNT_ID = env('ANKKA_LIVE_ACCOUNT_ID');
const ZONE_NAME = env('ANKKA_LIVE_ZONE_NAME');
const ZONE_ID = env('ANKKA_LIVE_ZONE_ID');
const ADMIN_EMAIL = env('ANKKA_LIVE_ADMIN_EMAIL');
const PREFIX = process.env.ANKKA_LIVE_PREFIX ?? 'harness';
const GATEWAY_NAME = process.env.ANKKA_LIVE_GATEWAY_NAME ?? `Ankka ${PREFIX}`;
const PUBLISH_DIR = env('ANKKA_LIVE_PUBLISH_DIR');
const PIN_PATH = env('ANKKA_LIVE_PIN');
const KEEP = process.env.ANKKA_LIVE_KEEP === '1';
const PAYLOAD_SPECIFIER = process.env.ANKKA_LIVE_PAYLOAD ?? '../../../payload/worker/index.js';
const PAYLOAD_URL = pathToFileURL(isAbsolute(PAYLOAD_SPECIFIER)
  ? PAYLOAD_SPECIFIER
  : resolve(dirname(fileURLToPath(import.meta.url)), PAYLOAD_SPECIFIER)).href;

const CLIENT_ID = 'h'.repeat(32);
const ISSUER_KEY_ID = 'harness-issuer-v1';
const API = 'https://api.cloudflare.com/client/v4';

interface Trace { readonly method: string; readonly path: string; readonly status: number | string; readonly ms: number }
const trace: Trace[] = [];
const realFetch = globalThis.fetch;

async function traced(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const started = performance.now();
  try {
    const response = await realFetch(request);
    let status: number | string = response.status;
    if (!response.ok && url.hostname === 'api.cloudflare.com') {
      // The provider's error codes and messages, for the trace only.
      const body = await response.clone().text().catch(() => '');
      status = `${response.status} ${body.replace(/\s+/gu, ' ').slice(0, 400)}`;
    }
    trace.push({ method: request.method, path: `${url.host}${url.pathname}${url.search}`, status, ms: Math.round(performance.now() - started) });
    return response;
  } catch (error) {
    trace.push({ method: request.method, path: `${url.host}${url.pathname}`, status: `threw ${error instanceof Error ? error.name : 'unknown'}`, ms: Math.round(performance.now() - started) });
    throw error;
  }
}

/** The OAuth grant is the API token; the account list names the test account; all else is real. */
async function transport(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const request = new Request(input, init);
  const url = new URL(request.url);
  if (url.hostname === 'dash.cloudflare.com' && url.pathname === '/oauth2/token') {
    trace.push({ method: 'POST', path: 'dash.cloudflare.com/oauth2/token (token mode)', status: 200, ms: 0 });
    return Response.json({ access_token: TOKEN, token_type: 'bearer', scope: 'workers-scripts.write' });
  }
  if (url.hostname === 'dash.cloudflare.com' && url.pathname === '/oauth2/revoke') {
    trace.push({ method: 'POST', path: 'dash.cloudflare.com/oauth2/revoke (token mode)', status: 200, ms: 0 });
    return new Response(null, { status: 200 });
  }
  if (url.hostname === 'api.cloudflare.com' && url.pathname === '/client/v4/accounts' && request.method === 'GET') {
    trace.push({ method: 'GET', path: 'api.cloudflare.com/client/v4/accounts (token mode)', status: 200, ms: 0 });
    return Response.json({ success: true, errors: [], messages: [], result: [{ id: ACCOUNT_ID }] });
  }
  return traced(request);
}
// SAFETY: the payload reaches the provider through the global fetch; the
// wrapper forwards every call unchanged and only records it.
globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => traced(new Request(input, init))) as typeof fetch;

class MemoryOwnershipStorage implements CustomerGatewayOwnershipStorage {
  readonly values = new Map<string, unknown>();
  async get<Value = unknown>(key: string): Promise<Value | undefined> {
    // SAFETY: the storage contract lets the caller name the stored type; the map holds exactly what put() stored.
    return structuredClone(this.values.get(key)) as Value | undefined;
  }
  async put<Value>(key: string, value: Value): Promise<void> {
    this.values.set(key, structuredClone(value));
  }
}

class MemoryJournal implements CustomerStage2JournalPort {
  value: CustomerStage2Journal | null = null;
  async read(): Promise<CustomerStage2Journal | null> {
    return this.value === null ? null : structuredClone(this.value);
  }
  async compareAndSet(expectedRevision: number | null, state: CustomerStage2Journal): Promise<boolean> {
    if ((this.value?.revision ?? null) !== expectedRevision) return false;
    this.value = structuredClone(state);
    return true;
  }
}

class MemoryStorage {
  readonly map = new Map<string, BoundaryValue>();
  async get(key: string): Promise<BoundaryValue | undefined> { return this.map.get(key); }
  async put(key: string, value: BoundaryValue): Promise<void> { this.map.set(key, structuredClone(value)); }
}

const objectPlanSchema = v.looseObject({
  objects: v.array(v.looseObject({ key: v.string(), contentType: v.string(), byteSize: v.number() })),
});

/** The publish directory read the way the hosted runtime reads R2. */
function localBucket(): R2ReleaseReadBucket {
  const plan = v.parse(objectPlanSchema, JSON.parse(readFileSync(join(PUBLISH_DIR, 'r2-object-plan.json'), 'utf8')));
  const byKey = new Map(plan.objects.map((object) => [object.key, object]));
  return {
    async get(key: string): Promise<R2ReleaseReadObject | null> {
      const object = byKey.get(key);
      if (!object) return null;
      const bytes = readFileSync(join(PUBLISH_DIR, 'objects', key));
      return {
        key,
        size: bytes.byteLength,
        httpMetadata: { contentType: object.contentType },
        arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
      };
    },
    async list({ prefix }) {
      return { objects: plan.objects.filter((object) => object.key.startsWith(prefix)).map((object) => ({ key: object.key, size: object.byteSize })), truncated: false };
    },
  };
}

async function api(method: string, path: string): Promise<{ status: number; body: BoundaryValue | null }> {
  const response = await realFetch(`${API}${path}`, { method, headers: { authorization: `Bearer ${TOKEN}`, accept: 'application/json' } });
  return { status: response.status, body: await response.json().catch(() => null) };
}

const recordedStateSchema = v.looseObject({
  resources: v.array(v.looseObject({ kind: v.string(), provider: v.optional(v.nullable(v.looseObject({ id: v.optional(v.string()) }))) })),
});
const listSchema = v.looseObject({ result: v.array(v.looseObject({ id: v.string(), name: v.optional(v.string()), hostname: v.optional(v.string()), comment: v.optional(v.nullable(v.string())) })) });

const cleanup: { label: string; path: string }[] = [];
const payloadStorage = new MemoryStorage();
let plan: StaticDeployPlan | null = null;

function printTrace(): void {
  console.log(`\n--- provider trace (${trace.length} calls) ---`);
  for (const entry of trace) console.log(`${String(entry.status).padEnd(6)} ${entry.ms.toString().padStart(5)}ms ${entry.method} ${entry.path}`);
}

describe('token-mode Stage 1 + Stage 2 against the test account', () => {
  afterAll(async () => {
    printTrace();
    if (KEEP) { console.log('ANKKA_LIVE_KEEP=1: leaving resources in place'); return; }
    // Payload resources, from its own receipt.
    const stored = v.safeParse(recordedStateSchema, payloadStorage.map.get('ankka-mcp-gateway/uninstall-state/v1'));
    const order = ['portal_access_application', 'source_access_application', 'portal', 'mcp_server', 'dns_record'];
    for (const kind of order) {
      for (const resource of (stored.success ? stored.output.resources : []).filter((entry) => entry.kind === kind)) {
        const id = resource.provider?.id;
        if (!id) continue;
        const path = kind === 'dns_record' ? `/zones/${ZONE_ID}/dns_records/${id}`
          : kind === 'portal' ? `/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/portals/${id}`
          : kind === 'mcp_server' ? `/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/servers/${id}`
          : `/accounts/${ACCOUNT_ID}/access/apps/${id}`;
        cleanup.push({ label: kind, path });
      }
    }
    if (plan) {
      const marker = plan.managementOwnershipMarker;
      const apps = v.safeParse(listSchema, (await api('GET', `/accounts/${ACCOUNT_ID}/access/apps?per_page=100`)).body);
      for (const app of apps.success ? apps.output.result : []) {
        if ((app.name ?? '').includes(`[${marker}]`)) cleanup.push({ label: 'management app', path: `/accounts/${ACCOUNT_ID}/access/apps/${app.id}` });
      }
      const domains = v.safeParse(listSchema, (await api('GET', `/accounts/${ACCOUNT_ID}/workers/domains?hostname=${encodeURIComponent(plan.gatewayConfiguration.managementHostname)}`)).body);
      for (const domain of domains.success ? domains.output.result : []) cleanup.push({ label: 'custom domain', path: `/accounts/${ACCOUNT_ID}/workers/domains/${domain.id}` });
      const records = v.safeParse(listSchema, (await api('GET', `/zones/${ZONE_ID}/dns_records?per_page=100`)).body);
      for (const record of records.success ? records.output.result : []) {
        if ((record.comment ?? '').includes(marker)) cleanup.push({ label: 'dns by marker', path: `/zones/${ZONE_ID}/dns_records/${record.id}` });
      }
      const worker = plan.managementResources.find((resource) => resource.kind === 'management_worker');
      if (worker) cleanup.push({ label: 'worker', path: `/accounts/${ACCOUNT_ID}/workers/scripts/${worker.name}?force=true` });
    }
    const seen = new Set<string>();
    for (const item of cleanup) {
      if (seen.has(item.path)) continue;
      seen.add(item.path);
      const result = await api('DELETE', item.path);
      console.log(`cleanup ${item.label}: http ${result.status}`);
    }
  });

  it('provisions the shell, hands off, and converges Stage 2 to completion', async () => {
    const pin = JSON.parse(readFileSync(PIN_PATH, 'utf8'));
    const bundle = await PinnedR2ReleaseBundleProvider.fromCandidate(pin).loadVerifiedReleaseBundle(localBucket());
    const parsedRelease = parseVerifiedReleaseBundle(bundle);
    console.log(`release ${parsedRelease.manifest.release} verified from ${PUBLISH_DIR}`);

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
    const startedAt = Date.now();
    plan = await buildStaticDeployPlan(selection, parsedRelease.manifest, startedAt + 60 * 60_000);
    const workerName = plan.managementResources.find((resource) => resource.kind === 'management_worker')?.name;
    if (!workerName) throw new Error('plan has no management worker');
    console.log(`install ${plan.managementOwnershipMarker} worker ${workerName}`);

    // SAFETY: Ed25519 generateKey always yields a key pair; the union only exists for symmetric algorithms.
    const issuer = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair;
    const issuerPublicKey = base64UrlEncode(new Uint8Array(await crypto.subtle.exportKey('raw', issuer.publicKey)));
    const secrets = await createHostedStage1Secrets({ now: Date.now() });

    // Hosted Stage 1: the real shell Worker goes into the account.
    const provision = await provisionHostedStage1({
      code: `code_${'x'.repeat(32)}`,
      verifier: base64UrlEncode(crypto.getRandomValues(new Uint8Array(32))),
      oauth: { clientId: CLIENT_ID, clientSecret: 's'.repeat(32) },
      transport,
      bundle,
      plan,
      secrets,
      customerOauthClientId: CLIENT_ID,
      issuerKeyId: ISSUER_KEY_ID,
      issuerPublicKey,
      issuerPrivateKey: issuer.privateKey,
      now: Date.now,
    });
    console.log(`stage 1 provisioned: ${provision.deployment.workerName} version ${provision.deployment.versionId} (${provision.deployment.recovery}) at ${provision.bootstrapOrigin}`);

    // The hosted runtime polls this step while the new workers.dev hostname
    // propagates; do the same, for up to four minutes.
    const handoffStarted = Date.now();
    let handoff: Awaited<ReturnType<typeof completeHostedStage1Handoff>> | null = null;
    let attempts = 0;
    while (handoff === null) {
      attempts += 1;
      try {
        handoff = await completeHostedStage1Handoff({
          provision,
          plan,
          capabilitySecret: secrets.capability.secret,
          customerOauthClientId: CLIENT_ID,
          issuerKeyId: ISSUER_KEY_ID,
          issuerPublicKey,
          issuerPrivateKey: issuer.privateKey,
          transport,
          now: Date.now,
        });
      } catch (error) {
        const failure = v.safeParse(v.looseObject({ code: v.string() }), error);
        const notReady = failure.success && failure.output.code === 'bootstrap_not_ready';
        if (!notReady || Date.now() - handoffStarted > 240_000) throw error;
        await new Promise<void>((resolveWait) => { setTimeout(resolveWait, 3_000); });
      }
    }
    console.log(`readiness reached after ${attempts} attempt(s), ${Math.round((Date.now() - handoffStarted) / 1000)} s`);
    console.log(`stage 1 handoff ready: ${new URL(handoff.handoffUrl).origin}${new URL(handoff.handoffUrl).pathname} (fragment ${new URL(handoff.handoffUrl).hash.length} chars)`);

    // Stage 2, the shell's side, in this process: its own ownership key,
    // a certificate from the same issuer, the accepted handoff, then the
    // converger against the real provider.
    const storage = new MemoryOwnershipStorage();
    const customerKey = await initializeCustomerGatewayOwnershipState({ storage, wrappingKey: secrets.ownershipWrapKey });
    const gatewayCallback = `https://${plan.gatewayConfiguration.managementHostname}/__ankka/install/oauth/callback`;
    const ownershipCertificate = await issueCloudflareGatewayOwnershipCertificate({
      accountId: ACCOUNT_ID,
      installId: plan.managementOwnershipMarker,
      worker: { name: provision.deployment.workerName, providerId: provision.deployment.workerId },
      adminStateNamespaceId: provision.deployment.namespaceId,
      bootstrapCallback: provision.bootstrapCallback,
      gatewayCallback,
      publicClientId: CLIENT_ID,
      ownershipPublicKey: customerKey.publicKey,
      handoffSha256: `sha256:${await sha256Hex(provision.handoff)}`,
      issuedAt: Date.now(),
      keyId: ISSUER_KEY_ID,
    }, issuer.privateKey);
    await acceptCustomerGatewayOwnershipHandoff({
      storage,
      config: {
        accountId: ACCOUNT_ID,
        installId: plan.managementOwnershipMarker,
        workerName,
        plan: { id: plan.planId, hash: plan.planHash },
        release: { id: plan.releaseId, artifactSha256: plan.releaseArtifactSha256 },
        bootstrapSecretCommitment: secrets.capability.secretCommitment,
        bootstrapExpiresAt: secrets.capability.expiresAt,
        bootstrapCallback: provision.bootstrapCallback,
        gatewayCallback,
        publicClientId: CLIENT_ID,
        pinnedIssuerPublicKey: issuerPublicKey,
        issuerKeyId: ISSUER_KEY_ID,
      },
      serializedHandoff: provision.handoff,
      serializedPlan: canonicalJson(plan),
      ownershipCertificate,
      now: Date.now(),
    });
    const expectedBindings = expectedCustomerBootstrapBindings({
      accountId: ACCOUNT_ID,
      bootstrapCallback: provision.bootstrapCallback,
      customerOauthClientId: CLIENT_ID,
      issuerKeyId: ISSUER_KEY_ID,
      issuerPublicKey,
      plan,
      release: parsedRelease,
      capability: secrets.capability,
      workerName,
    });
    const shellEnvironment = Object.freeze({
      ...expectedBindings,
      ANKKA_BOOTSTRAP_NONCE: secrets.bootstrapNonce,
      ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY: secrets.ownershipWrapKey,
    });
    const finalRuntimeSource = readFileSync(join(PUBLISH_DIR, 'objects', `${pin.channel === 'canary' ? 'ankka-mcp-gateway/releases/canary' : 'ankka-mcp-gateway/releases/stable'}/${pin.release}/payload/worker/index.js`), 'utf8');
    const payload = await import(PAYLOAD_URL);
    const journal = new MemoryJournal();
    const attemptId = `attempt_${base64UrlEncode(crypto.getRandomValues(new Uint8Array(18)))}`;
    // The shell runs these same passes one alarm each; every pass must stay
    // inside the Workers Free budget of 50 subrequests per invocation, and
    // this is the only place the payload's own provider calls are counted.
    const passes: number[] = [];
    let result: CustomerStage2ConvergerResult;
    for (;;) {
      const callsBeforePass = trace.length;
      result = await convergeCustomerStage2({
        accessToken: TOKEN,
        attemptId,
        storage,
        journal,
        runtime: { updateChannel: bundle.channel, updateKeyId: bundle.keyId, updatePublicKey: bundle.publicKey },
        bootstrap: { nonce: secrets.bootstrapNonce, expectedBindings },
        finalRuntimeSource,
        payload: {
          bootstrap: (request, { target }) => payload.processBootstrap(request, customerPayloadEnvironment(shellEnvironment, target), payloadStorage),
          verifyReady: async ({ accessToken, plan: renewed, target }) => {
            const claim = await prepareCustomerBootstrapClaimFromPlan({ plan: renewed, target, nowMs: Date.now() });
            return payload.verifyBootstrapReceiptProviderStateWithReason(
              { ...claim, cloudflareAccessToken: accessToken }, customerPayloadEnvironment(shellEnvironment, target), payloadStorage, Date.now(),
            );
          },
        },
        transport,
        now: Date.now,
        checkpoints: CUSTOMER_STAGE2_CHUNK_CHECKPOINTS,
      }).catch((error: Error) => {
        const code = 'code' in error ? String(error.code) : '';
        const reason = 'reason' in error ? String(error.reason) : '';
        console.log(`converger failed: ${error.name} ${error.message} code=${code} reason=${reason}`);
        throw error;
      });
      passes.push(trace.length - callsBeforePass);
      const stop = result.verified ? 'complete' : `${result.checkpoint.action}:${result.checkpoint.phase}`;
      console.log(`converger pass ${passes.length}: ${passes[passes.length - 1]} provider calls, ${stop}`);
      if (result.verified || passes.length > 8) break;
    }
    console.log('converger result:', JSON.stringify(result));
    console.log(`converger provider calls: ${passes.reduce((sum, calls) => sum + calls, 0)} over ${passes.length} passes`);
    expect(result.verified).toBe(true);
    for (const calls of passes) expect(calls).toBeLessThanOrEqual(45);
  });
});
