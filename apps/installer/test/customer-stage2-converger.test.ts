import { buildBootstrapDeployPlan } from '../src/bootstrap-plan';
import * as v from 'valibot';
import { describe, expect, it } from 'vitest';

import { boundaryObjectSchema, type BoundaryObject, type BoundaryValue } from '../src/boundary';
import { canonicalJson } from '../src/canonical-json';
import { issueCloudflareBootstrapOwnershipHandoff, verifyCloudflareBootstrapOwnershipHandoff } from
  '../src/cloudflare-bootstrap-ownership-handoff';
import { issueCloudflareGatewayOwnershipCertificate } from
  '../src/cloudflare-gateway-ownership-proof';
import { sha256Hex, base64UrlEncode } from '../src/crypto';
import {
  deriveCustomerGatewayInstallationReceiptExpectation,
  prepareCustomerGatewayDesiredProjectionFromPlan,
  type CustomerBootstrapReadyResult,
} from '../src/customer-bootstrap-request';
import {
  acceptCustomerGatewayOwnershipHandoff,
  adoptCustomerGatewayOwnership,
  initializeCustomerGatewayOwnershipState,
  readCustomerGatewayOwnershipState,
  openCustomerGatewayOwnershipPrivateKey,
  type CustomerGatewayOwnershipStorage,
} from '../src/customer-gateway-ownership-state';
import {
  CUSTOMER_STAGE2_CHUNK_CHECKPOINTS,
  convergeCustomerStage2,
  type CustomerStage2BootstrapBindings,
  type CustomerStage2ConvergerInput,
  type CustomerStage2ConvergerResult,
} from '../src/customer-stage2-converger';
import type { CustomerCloudflareTransport } from '../src/customer-cloudflare-grant';
import type { CustomerStage2JournalPort } from '../src/customer-stage2-durable-state';
import {
  customerStage2Action,
  type CustomerStage2ActionName,
  type CustomerStage2Journal,
} from '../src/customer-stage2-journal';
import { buildStaticDeployPlan, parseDeploySelection, verifyStaticDeployPlanIntegrity, type StaticDeployPlan } from '../src/schema';
import {
  BOOTSTRAP_NONCE_KEY,
  CLIENT_ID,
  ENCRYPTION_KEY,
  manifest,
  NOW,
  selectionInput,
} from './fixtures';
import { createGatewayTeardownHandoff, verifyGatewayTeardownHandoff, GATEWAY_TEARDOWN_HANDOFF_TTL_MS } from '../src/gateway-teardown-handoff';
import { createGatewayTeardownJob, verifyGatewayTeardownJobAuthority } from '../src/gateway-teardown-job';
import { readyInstallationReceiptFixture } from './provider-neutral-installation-receipt-fixture';

const ACCOUNT_ID = '1'.repeat(32);
const ZONE_ID = '2'.repeat(32);
const WORKER_ID = '3'.repeat(32);
const NAMESPACE_ID = '4'.repeat(32);
const BOOTSTRAP_VERSION = '11111111-1111-4111-8111-111111111111';
const BOOTSTRAP_DEPLOYMENT = '22222222-2222-4222-8222-222222222222';
const FINAL_VERSION = '33333333-3333-4333-8333-333333333333';
const FINAL_DEPLOYMENT = '44444444-4444-4444-8444-444444444444';
const APPLICATION_ID = '55555555-5555-4555-8555-555555555555';
const POLICY_ID = '66666666-6666-4666-8666-666666666666';
const DOMAIN_ID = '7'.repeat(32);
const IDP_ID = '8'.repeat(32);
const ACCESS_AUD = 'ankka-access-audience-v1';
const ACCESS_TOKEN = `ephemeral_${'t'.repeat(48)}`;
const FINAL_SOURCE = [
  'export class AdminState { fetch() { return new Response("ready"); } }',
  'export default { fetch() { return new Response("ready"); } };',
  '',
].join('\n');
const OWNERSHIP_KEY_ID = 'ownership-key-v1';
const UPDATE_KEY_ID = 'release-key-v1';
const UPDATE_PUBLIC_KEY = 'A'.repeat(43);
const WORKERS_SUBDOMAIN = 'ankka-stage2-test';

function required<Value>(value: Value | undefined, name: string): Value {
  if (value === undefined) throw new TypeError(`missing ${name}`);
  return value;
}

const namedBindingSchema = v.looseObject({ name: v.string(), type: v.string() });

function object(value: BoundaryValue, name: string): BoundaryObject {
  const parsed = v.safeParse(boundaryObjectSchema, value);
  if (!parsed.success || Array.isArray(value)) throw new TypeError(`invalid ${name}`);
  return parsed.output;
}

function json(result: BoundaryValue, status = 200, resultInfo?: BoundaryObject): Response {
  const envelope = { success: status >= 200 && status < 300, errors: [], messages: [], result };
  return Response.json(
    resultInfo === undefined ? envelope : { ...envelope, result_info: resultInfo },
    { status },
  );
}

function page(url: URL, result: readonly BoundaryValue[], totalCount = result.length): Response {
  const pageNumber = Number(url.searchParams.get('page') ?? '1');
  const perPage = Number(url.searchParams.get('per_page') ?? '100');
  return json([...result], 200, {
    count: result.length,
    page: pageNumber,
    per_page: perPage,
    total_count: totalCount,
    total_pages: totalCount === 0 ? 0 : Math.ceil(totalCount / perPage),
  });
}

function sourceBase64(source: string): string {
  const bytes = new TextEncoder().encode(source);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

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
  readonly serializedWrites: string[] = [];
  private faulted = false;

  constructor(private readonly failSubmittedAction: CustomerStage2ActionName | null = null) {}

  async read(): Promise<CustomerStage2Journal | null> {
    return this.value === null ? null : structuredClone(this.value);
  }

  async compareAndSet(
    expectedRevision: number | null,
    state: CustomerStage2Journal,
  ): Promise<boolean> {
    const actualRevision = this.value?.revision ?? null;
    if (actualRevision !== expectedRevision) return false;
    const current = this.failSubmittedAction === null || this.value === null
      ? null
      : customerStage2Action(this.value, this.failSubmittedAction);
    const next = this.failSubmittedAction === null
      ? null
      : customerStage2Action(state, this.failSubmittedAction);
    if (!this.faulted && current?.phase === 'send_armed' && next?.phase === 'submitted') {
      this.faulted = true;
      return false;
    }
    this.value = structuredClone(state);
    this.serializedWrites.push(canonicalJson(state));
    return true;
  }
}

interface ProviderState {
  application: BoundaryObject | null;
  policy: BoundaryObject | null;
  domain: BoundaryObject | null;
  workersDevEnabled: boolean;
  finalActive: boolean;
  finalBindings: readonly BoundaryObject[] | null;
  appCreates: number;
  policyCreates: number;
  domainCreates: number;
  finalUploads: number;
  nonceDeletes: number;
}

function inheritedBinding(name: string): BoundaryObject {
  if (name === 'ADMIN_STATE') {
    return { name, type: 'durable_object_namespace', class_name: 'AdminState' };
  }
  if (name === 'ASSETS') return { name, type: 'assets' };
  if (name === 'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY') return { name, type: 'secret_text' };
  throw new TypeError(`unexpected inherited binding ${name}`);
}

function provider(plan: StaticDeployPlan) {
  const workerName = required(
    plan.managementResources.find((resource) => resource.kind === 'management_worker')?.name,
    'management Worker',
  );
  const state: ProviderState = {
    application: null,
    policy: null,
    domain: null,
    workersDevEnabled: true,
    finalActive: false,
    finalBindings: null,
    appCreates: 0,
    policyCreates: 0,
    domainCreates: 0,
    finalUploads: 0,
    nonceDeletes: 0,
  };
  const calls: string[] = [];

  const transport = async (input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
    const request = input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);
    calls.push(`${request.method} ${url.pathname}${url.search}`);
    expect(request.headers.get('authorization')).toBe(`Bearer ${ACCESS_TOKEN}`);

    if (url.pathname === '/client/v4/zones' && request.method === 'GET') {
      return json([{
        id: ZONE_ID,
        name: selectionInput.basics.zoneName,
        status: 'active',
        account: { id: ACCOUNT_ID },
      }]);
    }
    if (url.pathname === `/client/v4/accounts/${ACCOUNT_ID}/access/organizations`) {
      return json({ name: 'Ankka Test', auth_domain: 'ankka-test.cloudflareaccess.com' });
    }
    if (url.pathname === `/client/v4/accounts/${ACCOUNT_ID}/access/identity_providers`) {
      return page(url, [{ id: IDP_ID, name: '', type: 'cloudflare' }]);
    }
    if (url.pathname === `/client/v4/accounts/${ACCOUNT_ID}/workers/subdomain`) {
      return json({ subdomain: WORKERS_SUBDOMAIN });
    }

    const appsPath = `/client/v4/zones/${ZONE_ID}/access/apps`;
    if (url.pathname === appsPath && request.method === 'GET') {
      return page(url, state.application === null ? [] : [state.application]);
    }
    if (url.pathname === appsPath && request.method === 'POST') {
      state.appCreates += 1;
      const body = object(await request.json(), 'Access application body');
      state.application = { ...body, id: APPLICATION_ID, aud: ACCESS_AUD };
      return json({ id: APPLICATION_ID, aud: ACCESS_AUD }, 201);
    }
    if (url.pathname === `${appsPath}/${APPLICATION_ID}` && request.method === 'GET') {
      return json(required(state.application ?? undefined, 'Access application'));
    }

    const policiesPath = `${appsPath}/${APPLICATION_ID}/policies`;
    if (url.pathname === policiesPath && request.method === 'GET') {
      return page(url, state.policy === null ? [] : [state.policy]);
    }
    if (url.pathname === policiesPath && request.method === 'POST') {
      state.policyCreates += 1;
      const body = object(await request.json(), 'Access policy body');
      state.policy = { ...body, id: POLICY_ID };
      return json({ id: POLICY_ID }, 201);
    }
    if (url.pathname === `${policiesPath}/${POLICY_ID}` && request.method === 'GET') {
      return json(required(state.policy ?? undefined, 'Access policy'));
    }

    const domainsPath = `/client/v4/accounts/${ACCOUNT_ID}/workers/domains`;
    if (url.pathname === domainsPath && request.method === 'GET') {
      return page(url, state.domain === null ? [] : [state.domain]);
    }
    if (url.pathname === domainsPath && request.method === 'PUT') {
      state.domainCreates += 1;
      const body = object(await request.json(), 'custom domain body');
      state.domain = { ...body, id: DOMAIN_ID, environment: 'production' };
      return json({ id: DOMAIN_ID });
    }
    if (url.pathname === `${domainsPath}/${DOMAIN_ID}` && request.method === 'GET') {
      return json(required(state.domain ?? undefined, 'custom domain'));
    }

    if (url.pathname === `/client/v4/zones/${ZONE_ID}/workers/routes` && request.method === 'GET') {
      return page(url, []);
    }
    if (url.pathname === `/client/v4/zones/${ZONE_ID}/dns_records` && request.method === 'GET') {
      return page(url, [], 0);
    }
    if (url.pathname === `/client/v4/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/servers` &&
        request.method === 'GET') {
      return page(url, []);
    }
    if (url.pathname === `/client/v4/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/portals` &&
        request.method === 'GET') {
      return page(url, []);
    }

    if (url.pathname === `/client/v4/accounts/${ACCOUNT_ID}/workers/workers/${workerName}` &&
        request.method === 'GET') {
      return json({ id: WORKER_ID, name: workerName, tags: ['ankka-mcp-gateway'] });
    }
    if (url.pathname === `/client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${workerName}/deployments` &&
        request.method === 'GET') {
      return json({ deployments: [{
        id: state.finalActive ? FINAL_DEPLOYMENT : BOOTSTRAP_DEPLOYMENT,
        versions: [{
          version_id: state.finalActive ? FINAL_VERSION : BOOTSTRAP_VERSION,
          percentage: 100,
        }],
      }] });
    }
    if (url.pathname === `/client/v4/accounts/${ACCOUNT_ID}/workers/workers/${WORKER_ID}/versions/${FINAL_VERSION}` &&
        request.method === 'GET') {
      return json({
        id: FINAL_VERSION,
        main_module: 'index.js',
        compatibility_date: '2026-08-08',
        compatibility_flags: [],
        modules: [{
          name: 'index.js',
          content_type: 'application/javascript+module',
          content_base64: sourceBase64(FINAL_SOURCE),
        }],
        bindings: required(state.finalBindings ?? undefined, 'final bindings'),
        exports: { AdminState: { type: 'durable-object', storage: 'sqlite' } },
      });
    }
    if (request.method === 'DELETE' && url.pathname.endsWith('/secrets/ANKKA_BOOTSTRAP_NONCE')) {
      // Secrets survive uploads; the final runtime removes the nonce explicitly.
      state.nonceDeletes += 1;
      return json(null);
    }
    if (url.pathname === `/client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${workerName}` &&
        request.method === 'PUT') {
      expect(url.searchParams.get('bindings_inherit')).toBe('strict');
      state.finalUploads += 1;
      const form = await request.formData();
      const metadataPart = form.get('metadata');
      const sourcePart = form.get('index.js');
      if (!(metadataPart instanceof File) || !(sourcePart instanceof File)) {
        throw new TypeError('invalid final runtime upload');
      }
      expect(await sourcePart.text()).toBe(FINAL_SOURCE);
      const metadata = object(JSON.parse(await metadataPart.text()), 'upload metadata');
      const bindings = metadata.bindings;
      if (!Array.isArray(bindings)) throw new TypeError('invalid upload bindings');
      state.finalBindings = bindings.map((value) => {
        const binding = object(value, 'upload binding');
        const named = v.safeParse(namedBindingSchema, binding);
        if (!named.success) throw new TypeError('invalid upload binding fields');
        if (named.output.type === 'inherit') return inheritedBinding(named.output.name);
        return binding;
      });
      state.finalActive = true;
      return json({ id: FINAL_VERSION });
    }

    if (url.pathname === `/client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${workerName}/subdomain`) {
      if (request.method === 'GET') {
        return json({ enabled: state.workersDevEnabled, previews_enabled: false });
      }
      if (request.method === 'POST') {
        const body = object(await request.json(), 'workers.dev body');
        if (body.enabled !== false || body.previews_enabled !== false) {
          throw new TypeError('unexpected workers.dev mutation');
        }
        state.workersDevEnabled = false;
        return json({ enabled: false, previews_enabled: false });
      }
    }

    throw new Error(`unexpected Cloudflare request ${request.method} ${url}`);
  };

  return { calls, state, transport };
}

function bootstrapBindings(input: {
  readonly plan: StaticDeployPlan;
  readonly workerName: string;
  readonly publicKey: string;
  readonly bootstrapCallback: string;
  readonly expiresAt: number;
  readonly commitment: string;
}): CustomerStage2BootstrapBindings {
  return Object.freeze({
    ANKKA_BOOTSTRAP_CALLBACK: input.bootstrapCallback,
    ANKKA_BOOTSTRAP_EXPIRES_AT: String(input.expiresAt),
    ANKKA_BOOTSTRAP_ID: `boot_${'b'.repeat(24)}`,
    ANKKA_BOOTSTRAP_SECRET_SHA256: input.commitment,
    ANKKA_GATEWAY_RELEASE: input.plan.releaseId,
    ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${input.plan.releaseArtifactSha256}`,
    ANKKA_INSTALL_ID: input.plan.managementOwnershipMarker,
    ANKKA_INSTALLER_ORIGIN: 'https://deploy.ankka.ai',
    ANKKA_MANAGEMENT_HOSTNAME: input.plan.bootstrapIdentity === undefined ? input.plan.gatewayConfiguration.managementHostname : new URL(input.bootstrapCallback).hostname,
    ANKKA_PLAN_HASH: input.plan.bootstrapIdentity?.planHash ?? input.plan.planHash,
    ANKKA_PLAN_ID: input.plan.bootstrapIdentity?.planId ?? input.plan.planId,
    ANKKA_UPDATE_CHANNEL: 'stable',
    ANKKA_UPDATE_KEY_ID: UPDATE_KEY_ID,
    ANKKA_UPDATE_PUBLIC_KEY: UPDATE_PUBLIC_KEY,
    ANKKA_WORKER_NAME: input.workerName,
    CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID,
    CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID: CLIENT_ID,
    CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID: OWNERSHIP_KEY_ID,
    CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY: input.publicKey,
  });
}

async function fixture(fault: CustomerStage2ActionName | null = null, workerSetup = false) {
  const selection = parseDeploySelection(selectionInput);
  const bootstrap = await buildBootstrapDeployPlan(manifest, NOW + 60 * 60_000);
  const identity = workerSetup ? { planId: bootstrap.planId, planHash: bootstrap.planHash, workerName: bootstrap.workerName, installId: bootstrap.managementOwnershipMarker } : undefined;
  const plan = await buildStaticDeployPlan(selection, manifest, NOW + 60 * 60_000, identity);
  const workerName = required(
    plan.managementResources.find((resource) => resource.kind === 'management_worker')?.name,
    'management Worker',
  );
  const bootstrapCallback =
    `https://${workerName}.${WORKERS_SUBDOMAIN}.workers.dev/__ankka/install/oauth/callback`;
  const gatewayCallback =
    `https://${plan.gatewayConfiguration.managementHostname}/__ankka/install/oauth/callback`;
  const bootstrapExpiresAt = NOW + 5 * 60_000;
  const commitment = `sha256:${'9'.repeat(64)}`;
  const issuer = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const publicKey = base64UrlEncode(
    new Uint8Array(await crypto.subtle.exportKey('raw', issuer.publicKey)),
  );
  const storage = new MemoryOwnershipStorage();
  const customerKey = await initializeCustomerGatewayOwnershipState({
    storage,
    wrappingKey: ENCRYPTION_KEY,
  });
  const serializedHandoff = await issueCloudflareBootstrapOwnershipHandoff({
    accountId: ACCOUNT_ID,
    adminState: {
      binding: 'ADMIN_STATE',
      className: 'AdminState',
      namespaceId: NAMESPACE_ID,
      storage: 'sqlite',
      workerProviderId: WORKER_ID,
    },
    bootstrapSecret: { commitment, expiresAt: bootstrapExpiresAt },
    expiresAt: NOW + 6 * 60_000,
    installId: plan.managementOwnershipMarker,
    issuedAt: NOW,
    plan: { id: plan.planId, hash: plan.planHash },
    release: { id: plan.releaseId, artifactSha256: plan.releaseArtifactSha256 },
    worker: { name: workerName, providerId: WORKER_ID },
  }, issuer.privateKey);
  const ownershipCertificate = await issueCloudflareGatewayOwnershipCertificate({
    accountId: ACCOUNT_ID,
    installId: plan.managementOwnershipMarker,
    worker: { name: workerName, providerId: WORKER_ID },
    adminStateNamespaceId: NAMESPACE_ID,
    bootstrapCallback,
    gatewayCallback,
    publicClientId: CLIENT_ID,
    ownershipPublicKey: customerKey.publicKey,
    handoffSha256: `sha256:${await sha256Hex(serializedHandoff)}`,
    issuedAt: NOW + 1,
    keyId: OWNERSHIP_KEY_ID,
  }, issuer.privateKey);
  await acceptCustomerGatewayOwnershipHandoff({
    storage,
    config: {
      accountId: ACCOUNT_ID,
      installId: plan.managementOwnershipMarker,
      plan: { id: plan.bootstrapIdentity?.planId ?? plan.planId, hash: plan.bootstrapIdentity?.planHash ?? plan.planHash },
      workerName,
      release: { id: plan.releaseId, artifactSha256: plan.releaseArtifactSha256 },
      bootstrapSecretCommitment: commitment,
      bootstrapExpiresAt,
      bootstrapCallback,
      gatewayCallback,
      publicClientId: CLIENT_ID,
      pinnedIssuerPublicKey: publicKey,
      issuerKeyId: OWNERSHIP_KEY_ID,
    },
    serializedHandoff,
    serializedPlan: canonicalJson(plan),
    ownershipCertificate,
    now: NOW + 2,
  });
  const verifiedHandoff = await verifyCloudflareBootstrapOwnershipHandoff({
    now: NOW + 3,
    pinnedPublicKey: publicKey,
    serializedHandoff,
  });
  const statement = verifiedHandoff.statement;
  await adoptCustomerGatewayOwnership({
    storage,
    pinnedIssuerPublicKey: publicKey,
    activeVersionId: BOOTSTRAP_VERSION,
    now: NOW + 4,
    providerReadback: {
      schemaVersion: 2,
      purpose: 'cloudflare_bootstrap_ownership_provider_readback',
      accountId: ACCOUNT_ID,
      installId: statement.installId,
      worker: statement.worker,
      adminState: statement.adminState,
      bootstrapSecret: statement.bootstrapSecret,
      handoff: {
        issuedAt: statement.issuedAt,
        expiresAt: statement.expiresAt,
        nonce: statement.nonce,
      },
      plan: statement.plan,
      release: statement.release,
      observedAt: NOW + 3,
    },
  });

  const authorizedTarget = {
    actor: { id: 'actor_stage2_test', email: selection.basics.adminEmail },
    account: { id: ACCOUNT_ID, name: 'Ankka Test' },
    zone: { id: ZONE_ID, name: selection.basics.zoneName, status: 'active' as const },
  };
  const receiptExpectation = await deriveCustomerGatewayInstallationReceiptExpectation({
    selection,
    target: authorizedTarget,
    plan,
    release: { id: plan.releaseId, artifactSha256: plan.releaseArtifactSha256 },
  });
  const projection = await prepareCustomerGatewayDesiredProjectionFromPlan({
    plan,
    target: {
      accountId: ACCOUNT_ID,
      zoneId: ZONE_ID,
      zoneName: selection.basics.zoneName,
    },
  });
  const receipt = await readyInstallationReceiptFixture(receiptExpectation, 7);
  const ready: CustomerBootstrapReadyResult = Object.freeze({
    schemaVersion: 1,
    status: 'ready',
    installationId: receiptExpectation.installationId,
    approvedPlanId: plan.planId,
    configurationHash: projection.expected.configurationHash,
    desiredHash: receiptExpectation.desiredHash,
    settingsRevision: 1,
    release: {
      id: plan.releaseId,
      artifactSha256: `sha256:${plan.releaseArtifactSha256}`,
    },
    gateway: {
      hostname: plan.gatewayConfiguration.portalHostname,
      mcpUrl: `https://${plan.gatewayConfiguration.portalHostname}/mcp`,
    },
    receipt: { revision: 7, resourceCount: 7 as const, evidence: receipt },
    applyInvoked: true,
    resumed: false,
  });
  const cloudflare = provider(plan);
  const journal = new MemoryJournal(fault);
  let clock = NOW + 10;
  let payloadBootstrapCalls = 0;
  let payloadVerifyCalls = 0;
  const baseInput: Omit<CustomerStage2ConvergerInput, 'attemptId'> = {
    accessToken: ACCESS_TOKEN,
    storage,
    journal,
    runtime: {
      updateChannel: 'stable',
      updateKeyId: UPDATE_KEY_ID,
      updatePublicKey: UPDATE_PUBLIC_KEY,
    },
    bootstrap: {
      nonce: BOOTSTRAP_NONCE_KEY,
      expectedBindings: bootstrapBindings({
        plan,
        workerName,
        publicKey,
        bootstrapCallback,
        expiresAt: bootstrapExpiresAt,
        commitment,
      }),
    },
    finalRuntimeSource: FINAL_SOURCE,
    payload: {
      bootstrap: async (request, context) => {
        payloadBootstrapCalls += 1;
        expect(request.url).toBe(
          `https://${workerName}.${WORKERS_SUBDOMAIN}.workers.dev/__ankka/bootstrap`,
        );
        // The host completes the payload's environment from these.
        expect(context.target).toEqual({ accountId: ACCOUNT_ID, zoneId: ZONE_ID, zoneName: selection.basics.zoneName });
        expect(context.plan.planId).toBe(plan.planId);
        const response = Response.json(ready);
        Object.defineProperty(response, 'url', { configurable: true, value: request.url });
        return response;
      },
      verifyReady: async () => {
        payloadVerifyCalls += 1;
        return { verified: true, reason: null };
      },
    },
    transport: cloudflare.transport,
    now: () => clock++,
  };
  return {
    baseInput,
    cloudflare,
    journal,
    payloadBootstrapCalls: () => payloadBootstrapCalls,
    payloadVerifyCalls: () => payloadVerifyCalls,
  };
}

function withoutBootstrapRuntime(
  input: Omit<CustomerStage2ConvergerInput, 'attemptId'>,
): Omit<CustomerStage2ConvergerInput, 'attemptId'> {
  const { bootstrap: _bootstrap, finalRuntimeSource: _finalRuntimeSource, ...finalRuntime } = input;
  return finalRuntime;
}

describe('customer Stage 2 convergence', () => {
  it.each([false, true])('converges the fixed lifecycle and persists no OAuth secret material (Worker setup: %s)', async (workerSetup) => {
    const test = await fixture(null, workerSetup);
    await expect(convergeCustomerStage2({
      ...test.baseInput,
      attemptId: `attempt_${'a'.repeat(24)}`,
    })).resolves.toEqual({
      verified: true,
      ownershipReceipt: 'complete',
      managementAccess: 'enforced',
      portal: 'converged',
      sourceSet: 'converged',
      finalRuntime: 'active-recovery-capable',
      workersDev: 'disabled',
    });
    expect(test.journal.value?.completedAt).not.toBeNull();
    expect(test.cloudflare.state).toMatchObject({
      appCreates: 1,
      policyCreates: 1,
      domainCreates: 1,
      finalUploads: 1,
      workersDevEnabled: false,
      finalActive: true,
    });
    expect(test.payloadBootstrapCalls()).toBe(1);
    const durableBytes = test.journal.serializedWrites.join('\n');
    expect(durableBytes).not.toContain(ACCESS_TOKEN);
    expect(durableBytes).not.toContain(BOOTSTRAP_NONCE_KEY);
    expect(durableBytes).not.toMatch(/code_verifier|authorization_code|access_token|refresh_token/iu);
  });

  it('names the resource the payload could not re-verify', async () => {
    const test = await fixture();
    await expect(convergeCustomerStage2({
      ...test.baseInput,
      attemptId: `attempt_${'v'.repeat(24)}`,
      payload: {
        ...test.baseInput.payload,
        verifyReady: async () => ({ verified: false, reason: 'dns_record_absent' }),
      },
    })).rejects.toMatchObject({ code: 'payload_recovery_required', reason: 'verify_dns_record_absent' });
    // A verdict without a usable reason still names the step.
    await expect(convergeCustomerStage2({
      ...test.baseInput,
      attemptId: `attempt_${'w'.repeat(24)}`,
      payload: {
        ...test.baseInput.payload,
        verifyReady: async () => ({ verified: false, reason: 'Not A Reason' }),
      },
    })).rejects.toMatchObject({ code: 'payload_recovery_required', reason: 'verify_unknown' });
  });

  it('recovers an Access application created before its locator was journaled', async () => {
    const test = await fixture('management_access_application');
    await expect(convergeCustomerStage2({
      ...test.baseInput,
      attemptId: `attempt_${'b'.repeat(24)}`,
    })).rejects.toMatchObject({ code: 'journal_conflict' });
    expect(test.cloudflare.state.appCreates).toBe(1);
    expect(customerStage2Action(
      required(test.journal.value ?? undefined, 'journal'),
      'management_access_application',
    )?.phase).toBe('send_armed');

    await expect(convergeCustomerStage2({
      ...test.baseInput,
      attemptId: `attempt_${'c'.repeat(24)}`,
    })).resolves.toMatchObject({ verified: true });
    expect(test.cloudflare.state.appCreates).toBe(1);
    expect(test.cloudflare.state.policyCreates).toBe(1);
  });

  it('recovers an active final runtime without retaining or reusing bootstrap code', async () => {
    const test = await fixture('final_runtime');
    await expect(convergeCustomerStage2({
      ...test.baseInput,
      attemptId: `attempt_${'d'.repeat(24)}`,
    })).rejects.toMatchObject({ code: 'journal_conflict' });
    expect(test.cloudflare.state.finalUploads).toBe(1);
    expect(test.cloudflare.state.finalActive).toBe(true);
    expect(customerStage2Action(
      required(test.journal.value ?? undefined, 'journal'),
      'final_runtime',
    )?.phase).toBe('send_armed');

    await expect(convergeCustomerStage2({
      ...withoutBootstrapRuntime(test.baseInput),
      attemptId: `attempt_${'e'.repeat(24)}`,
    })).resolves.toMatchObject({ verified: true, finalRuntime: 'active-recovery-capable' });
    expect(test.cloudflare.state.finalUploads).toBe(1);
    expect(test.payloadBootstrapCalls()).toBe(1);
  });

  it('pauses at each fixed checkpoint and finishes on resume without repeating a mutation', async () => {
    const test = await fixture();
    const attemptId = `attempt_${'h'.repeat(24)}`;
    const counted = {
      calls: 0,
      transport: ((input, init) => {
        counted.calls += 1;
        return test.cloudflare.transport(input, init);
      }) satisfies CustomerCloudflareTransport,
    };
    const passes: { result: CustomerStage2ConvergerResult; calls: number }[] = [];
    for (let pass = 1; pass <= 8; pass += 1) {
      counted.calls = 0;
      const result = await convergeCustomerStage2({
        ...test.baseInput,
        attemptId,
        transport: counted.transport,
        checkpoints: CUSTOMER_STAGE2_CHUNK_CHECKPOINTS,
      });
      passes.push({ result, calls: counted.calls });
      if (result.verified) break;
    }
    expect(passes.map((pass) => (pass.result.verified
      ? 'complete'
      : 'paused' in pass.result
        ? `${pass.result.checkpoint.action}:${pass.result.checkpoint.phase}`
        : 'handed_over')))
      .toEqual([
        'management_admin_policy:verified',
        'gateway_resources:submitted',
        'management_custom_domain:verified',
        'complete',
      ]);
    // The lease stays with the attempt across passes; the journal completes once.
    expect(test.journal.value?.completedAt).not.toBeNull();
    expect(test.cloudflare.state).toMatchObject({
      appCreates: 1,
      policyCreates: 1,
      domainCreates: 1,
      finalUploads: 1,
      workersDevEnabled: false,
      finalActive: true,
    });
    expect(test.payloadBootstrapCalls()).toBe(1);
    // Each pass proves a resource at most once, so no pass approaches the
    // 50-subrequest budget of a Workers Free invocation; the payload's own
    // provider calls are counted by the live harness, not here.
    for (const pass of passes) expect(pass.calls).toBeLessThanOrEqual(30);
    const durableBytes = test.journal.serializedWrites.join('\n');
    expect(durableBytes).not.toContain(ACCESS_TOKEN);
  });

  it('hands the final runtime upload over when the caller cannot outlive it', async () => {
    const test = await fixture();
    const attemptId = `attempt_${'i'.repeat(24)}`;
    const observed: string[] = [];
    let writesWhenArmed = -1;
    const result = await convergeCustomerStage2({
      ...test.baseInput,
      attemptId,
      handover: async () => {
        observed.push(`handover uploads=${test.cloudflare.state.finalUploads} workersDev=${test.cloudflare.state.workersDevEnabled}`);
        writesWhenArmed = test.journal.serializedWrites.length;
      },
    });
    expect(result).toEqual({ verified: false, handedOver: true });
    // Everything that needs the journal happened first; the upload came after the hook.
    expect(observed).toEqual(['handover uploads=0 workersDev=false']);
    expect(test.cloudflare.state).toMatchObject({
      appCreates: 1,
      policyCreates: 1,
      domainCreates: 1,
      finalUploads: 1,
      nonceDeletes: 1,
      workersDevEnabled: false,
      finalActive: true,
    });
    const journal = required(test.journal.value ?? undefined, 'journal');
    expect(customerStage2Action(journal, 'workers_dev_disable')?.phase).toBe('verified');
    expect(customerStage2Action(journal, 'terminal_verify')?.phase).toBe('verified');
    expect(customerStage2Action(journal, 'final_runtime')?.phase).toBe('send_armed');
    expect(journal.completedAt).toBeNull();
    // No journal write after the handover: the object may already be restarting.
    expect(test.journal.serializedWrites).toHaveLength(writesWhenArmed);
  });

  it('re-proves every terminal resource on a completed journal without mutating again', async () => {
    const test = await fixture();
    await convergeCustomerStage2({
      ...test.baseInput,
      attemptId: `attempt_${'f'.repeat(24)}`,
    });
    const writes = test.journal.serializedWrites.length;
    const verifies = test.payloadVerifyCalls();
    await expect(convergeCustomerStage2({
      ...withoutBootstrapRuntime(test.baseInput),
      attemptId: `attempt_${'g'.repeat(24)}`,
    })).resolves.toMatchObject({ verified: true });
    expect(test.journal.serializedWrites).toHaveLength(writes);
    expect(test.payloadVerifyCalls()).toBeGreaterThan(verifies);
    expect(test.cloudflare.state).toMatchObject({
      appCreates: 1,
      policyCreates: 1,
      domainCreates: 1,
      finalUploads: 1,
    });
  });
});


describe('gateway teardown handoff from a real installation journal', () => {
  async function installed(handover = false) {
    const test = await fixture();
    const common = { ...test.baseInput, attemptId: `attempt_${'q'.repeat(24)}` };
    await convergeCustomerStage2(handover ? { ...common, handover: async () => undefined } : common);
    const owner = await readCustomerGatewayOwnershipState(test.baseInput.storage);
    if (owner.ownershipCertificate === null || owner.serializedPlan === null || owner.trust === null || test.journal.value === null) {
      throw new Error('installation fixture incomplete');
    }
    const journal = test.journal.value;
    const resources = v.parse(v.looseObject({ receiptChecksum: v.string() }),
      journal.actions.find((action) => action.name === 'gateway_resources')?.locator);
    const trust = {
      pinnedIssuerPublicKey: owner.trust.pinnedIssuerPublicKey,
      expectedKeyId: owner.trust.issuerKeyId, expectedPublicClientId: owner.trust.publicClientId,
    };
    return {
      input: {
        certificate: owner.ownershipCertificate,
        privateKey: await openCustomerGatewayOwnershipPrivateKey({ storage: test.baseInput.storage, wrappingKey: ENCRYPTION_KEY }),
        trust, plan: await verifyStaticDeployPlanIntegrity(JSON.parse(owner.serializedPlan)),
        journal, actionId: `action_${'r'.repeat(32)}`, nonce: 'A'.repeat(43),
        readyReceiptChecksum: resources.receiptChecksum, dependencyResourcesHash: `sha256:${'8'.repeat(64)}`,
        now: NOW + 1_000, customerGrantRevocation: 'confirmed' as const,
      },
      test,
    };
  }

  it.each([false, true])('certifies only the recorded management root, including a self-upload handover (%s)', async (handover) => {
    const { input } = await installed(handover);
    const encoded = await createGatewayTeardownHandoff(input);
    const verified = await verifyGatewayTeardownHandoff({ handoff: encoded, trust: input.trust, now: input.now });
    expect(verified.certificate.statement.worker.providerId).toBe(WORKER_ID);
    expect(verified.statement.management).toMatchObject({ applicationId: APPLICATION_ID, policyId: POLICY_ID, domainId: DOMAIN_ID });
    expect(verified.statement.customerGrantRevocation).toBe('confirmed');
    expect(encoded).not.toContain(ACCESS_TOKEN);
    expect(encoded).not.toContain(ENCRYPTION_KEY);
    await expect(verifyGatewayTeardownHandoff({ handoff: encoded, trust: input.trust,
      now: input.now + GATEWAY_TEARDOWN_HANDOFF_TTL_MS })).rejects.toThrow();
    const tampered = JSON.parse(encoded);
    const statement = JSON.parse(tampered.statement);
    statement.management.applicationId = 'foreign-application';
    tampered.statement = canonicalJson(statement);
    await expect(verifyGatewayTeardownHandoff({ handoff: canonicalJson(tampered), trust: input.trust, now: input.now })).rejects.toThrow();
  });

  it('refuses an unrelated receipt, incomplete management action, foreign root, or wrong signing key', async () => {
    const { input } = await installed();
    await expect(createGatewayTeardownHandoff({ ...input, readyReceiptChecksum: `sha256:${'0'.repeat(64)}` })).rejects.toThrow();
    await expect(createGatewayTeardownHandoff({ ...input, journal: { ...input.journal,
      identity: { ...input.journal.identity, workerId: '9'.repeat(32) } } })).rejects.toThrow();
    await expect(createGatewayTeardownHandoff({ ...input, journal: { ...input.journal,
      actions: input.journal.actions.filter((action) => action.name !== 'management_custom_domain') } })).rejects.toThrow();
    const foreign = await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify']);
    await expect(createGatewayTeardownHandoff({ ...input, privateKey: foreign.privateKey })).rejects.toThrow();
  });

  it('imports a fresh signed handoff and preserves its exact authority for recovery after expiry', async () => {
    const { input } = await installed();
    const handoff = await createGatewayTeardownHandoff(input);
    const release = { schemaVersion: 1 as const, channel: 'stable' as const, controlPlaneOrigin: 'https://deploy.ankka.ai',
      release: 'gateway-v0.1.1', artifactSha256: '1'.repeat(64), keyId: 'test', publicKey: 'A'.repeat(43) };
    const retirementModuleSha256 = '2'.repeat(64);
    const job = await createGatewayTeardownJob({ handoff, trust: input.trust, release, retirementModuleSha256, now: input.now });
    await expect(createGatewayTeardownJob({ handoff, trust: input.trust, release, retirementModuleSha256,
      now: input.now + GATEWAY_TEARDOWN_HANDOFF_TTL_MS })).rejects.toThrow();
    const recovered = { ...job, updatedAt: input.now + GATEWAY_TEARDOWN_HANDOFF_TTL_MS * 2 };
    const authority = await verifyGatewayTeardownJobAuthority({ job: recovered, trust: input.trust });
    expect(authority.certificate.statement.worker.providerId).toBe(WORKER_ID);
    expect(authority.statement.management.applicationId).toBe(APPLICATION_ID);
    await expect(verifyGatewayTeardownJobAuthority({ job: { ...recovered,
      handoffSha256: `sha256:${'0'.repeat(64)}` }, trust: input.trust })).rejects.toThrow();
    await expect(verifyGatewayTeardownJobAuthority({ job: { ...recovered,
      handoff: handoff.replace(APPLICATION_ID, 'foreign-application') }, trust: input.trust })).rejects.toThrow();
  });
});
