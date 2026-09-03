import { describe, expect, it } from 'vitest';

import type { BoundaryObject, BoundaryValue } from '../src/boundary';
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
  type CustomerGatewayOwnershipStorage,
} from '../src/customer-gateway-ownership-state';
import {
  convergeCustomerStage2,
  type CustomerStage2BootstrapBindings,
  type CustomerStage2ConvergerInput,
} from '../src/customer-stage2-converger';
import type { CustomerStage2JournalPort } from '../src/customer-stage2-durable-state';
import {
  customerStage2Action,
  type CustomerStage2ActionName,
  type CustomerStage2Journal,
} from '../src/customer-stage2-journal';
import { buildStaticDeployPlan, parseDeploySelection, type StaticDeployPlan } from '../src/schema';
import {
  BOOTSTRAP_NONCE_KEY,
  CLIENT_ID,
  ENCRYPTION_KEY,
  manifest,
  NOW,
  selectionInput,
} from './fixtures';
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

function object(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(`invalid ${name}`);
  }
  return value as Record<string, unknown>;
}

function json(result: BoundaryValue, status = 200, resultInfo?: BoundaryObject): Response {
  return Response.json({
    success: status >= 200 && status < 300,
    errors: [],
    messages: [],
    result,
    ...(resultInfo === undefined ? {} : { result_info: resultInfo }),
  }, { status });
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
      state.application = { ...body, id: APPLICATION_ID, aud: ACCESS_AUD } as BoundaryObject;
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
      state.policy = { ...body, id: POLICY_ID } as BoundaryObject;
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
      state.domain = { ...body, id: DOMAIN_ID, environment: 'production' } as BoundaryObject;
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
        const name = binding.name;
        const type = binding.type;
        if (typeof name !== 'string' || typeof type !== 'string') {
          throw new TypeError('invalid upload binding fields');
        }
        if (type === 'inherit') return inheritedBinding(name);
        return binding as BoundaryObject;
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
    ANKKA_MANAGEMENT_HOSTNAME: input.plan.gatewayConfiguration.managementHostname,
    ANKKA_PLAN_HASH: input.plan.planHash,
    ANKKA_PLAN_ID: input.plan.planId,
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

async function fixture(fault: CustomerStage2ActionName | null = null) {
  const selection = parseDeploySelection(selectionInput);
  const plan = await buildStaticDeployPlan(selection, manifest, NOW + 60 * 60_000);
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
      plan: { id: plan.planId, hash: plan.planHash },
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
      bootstrap: async (request) => {
        payloadBootstrapCalls += 1;
        expect(request.url).toBe(
          `https://${workerName}.${WORKERS_SUBDOMAIN}.workers.dev/__ankka/bootstrap`,
        );
        const response = Response.json(ready);
        Object.defineProperty(response, 'url', { configurable: true, value: request.url });
        return response;
      },
      verifyReady: async () => {
        payloadVerifyCalls += 1;
        return true;
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
  it('converges the fixed lifecycle and persists no OAuth secret material', async () => {
    const test = await fixture();
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
