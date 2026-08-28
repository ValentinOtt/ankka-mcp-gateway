import { describe, expect, it, vi } from 'vitest';

import {
  CustomerBootstrapRequestError,
  canonicalCustomerBootstrapJson,
  deriveCustomerGatewayInstallationReceiptExpectation,
  prepareCustomerGatewayDesiredProjection,
  prepareCustomerBootstrapClaim,
  submitCustomerBootstrap,
} from '../src/customer-bootstrap-request';
import type {
  AccountWorkersSubdomain,
  CustomerBootstrapReadyResult,
  PreparedCustomerBootstrapClaim,
  SubmitCustomerBootstrapInput,
} from '../src/customer-bootstrap-request';
import { base64UrlEncode } from '../src/crypto';
import { buildStaticDeployPlan, parseDeploySelection } from '../src/schema';
import type { StaticDeployPlan } from '../src/schema';
import type { AuthorizedTarget } from '../src/cloudflare-target';
import { manifest, NOW, selectionInput, verifiedRelease } from './fixtures';
import { readyInstallationReceiptFixture } from './provider-neutral-installation-receipt-fixture';

const TOKEN = 'ephemeral-cloudflare-oauth-grant-never-store';
const NONCE_BYTES = Uint8Array.from({ length: 32 }, (_, index) => index + 33);
const NONCE = base64UrlEncode(NONCE_BYTES);
const REQUEST_BYTES = Uint8Array.from({ length: 16 }, (_, index) => index + 1);
const ACCOUNT_WORKERS_SUBDOMAIN: AccountWorkersSubdomain = {
  accountId: '1'.repeat(32),
  subdomain: 'tenant',
};
const INTERNAL_PLAN = `plan-${'7'.repeat(24)}`;

// Golden evidence generated independently by the public provider-neutral
// planner in ankka-mcp-gateway for this exact selection and target.
const GOLDEN_INSTALLATION_ID = 'acg-361551cea347ce8d598c04f7';
const GOLDEN_DESIRED_HASH = 'sha256:51f2a522d9dc537459a36ac5d70af04c61556da0c9a3d2964b0b7b97f86de93b';
const GOLDEN_CONFIGURATION_HASH = 'sha256:adef4aee1b0500faf61c3d169c3ed0a0554ba0848e703ee3fa727fcd12a782cc';

const target: AuthorizedTarget = {
  actor: { id: 'actor_12345678', email: 'owner@example.com' },
  account: { id: '1'.repeat(32), name: 'Example account' },
  zone: { id: '2'.repeat(32), name: 'example.com', status: 'active' },
};

function deterministicRandom(length: number): Uint8Array {
  if (length !== 16) throw new Error('unexpected random request');
  return new Uint8Array(REQUEST_BYTES);
}

async function approvedPlan(expiresAt = NOW + 30 * 60_000): Promise<StaticDeployPlan> {
  return buildStaticDeployPlan(parseDeploySelection(selectionInput), manifest, expiresAt);
}

const APPROVED_PLAN = await approvedPlan();
const APPROVED_WORKER_NAME = APPROVED_PLAN.managementResources.find(
  (resource) => resource.kind === 'management_worker',
)?.name;
if (!APPROVED_WORKER_NAME) throw new TypeError('worker fixture');
const BOOTSTRAP_ORIGIN = `https://${APPROVED_WORKER_NAME}.tenant.workers.dev`;
const BOOTSTRAP_URL = `${BOOTSTRAP_ORIGIN}/__ankka/bootstrap`;

async function input(
  overrides: Partial<SubmitCustomerBootstrapInput> = {},
): Promise<SubmitCustomerBootstrapInput> {
  return {
    selection: parseDeploySelection(selectionInput),
    target,
    release: verifiedRelease,
    plan: await approvedPlan(),
    nowMs: NOW,
    randomBytes: deterministicRandom,
    accountWorkersSubdomain: ACCOUNT_WORKERS_SUBDOMAIN,
    bootstrapNonce: NONCE,
    cloudflareAccessToken: TOKEN,
    transport: async () => {
      throw new Error('transport not configured');
    },
    ...overrides,
  };
}

function response(
  body: unknown,
  status = 200,
  url = BOOTSTRAP_URL,
): Response {
  const value = new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
  Object.defineProperty(value, 'url', { configurable: true, value: url });
  return value;
}

async function ready(claim: PreparedCustomerBootstrapClaim): Promise<CustomerBootstrapReadyResult> {
  const expectation = await deriveCustomerGatewayInstallationReceiptExpectation({
    selection: parseDeploySelection(selectionInput),
    target,
    plan: APPROVED_PLAN,
    release: {
      id: claim.release.id,
      artifactSha256: claim.release.artifactSha256.slice('sha256:'.length),
    },
  });
  const evidence = await readyInstallationReceiptFixture(expectation, 8);
  return {
    schemaVersion: 1,
    status: 'ready',
    installationId: claim.expected.installationId,
    approvedPlanId: INTERNAL_PLAN,
    configurationHash: claim.expected.configurationHash,
    desiredHash: claim.expected.desiredHash,
    settingsRevision: 1,
    release: claim.release,
    gateway: {
      hostname: claim.settings.connect.hostname,
      mcpUrl: `https://${claim.settings.connect.hostname}/mcp`,
    },
    receipt: { revision: 8, resourceCount: 7, evidence },
    applyInvoked: true,
    resumed: false,
  };
}

async function hmac(rawBody: string, nonce = NONCE_BYTES): Promise<string> {
  const owned = new Uint8Array(new ArrayBuffer(nonce.byteLength));
  owned.set(nonce);
  const key = await crypto.subtle.importKey(
    'raw',
    owned,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const bytes = new Uint8Array(await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(rawBody),
  ));
  owned.fill(0);
  const result = `sha256=${[...bytes]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}`;
  bytes.fill(0);
  return result;
}

async function publicVerifierCompatible(request: Request): Promise<{
  claim: PreparedCustomerBootstrapClaim;
  rawBody: string;
  token: string;
}> {
  expect(request.method).toBe('POST');
  expect(request.url).toBe(BOOTSTRAP_URL);
  expect(request.redirect).toBe('manual');
  expect(request.credentials).toBe('omit');
  expect(request.referrer).toBe('about:client');
  expect(request.referrerPolicy).toBe('no-referrer');
  expect(request.headers.get('content-type')).toBe('application/json');
  expect(request.headers.get('authorization')).toBeNull();
  expect(request.headers.get('origin')).toBeNull();
  expect(request.headers.get('cookie')).toBeNull();
  expect(request.headers.get('referer')).toBeNull();
  expect([...request.headers.keys()].some((name) => name.startsWith('sec-fetch-'))).toBe(false);
  const rawBody = await request.text();
  expect(request.headers.get('x-ankka-bootstrap-signature')).toBe(await hmac(rawBody));
  const body = JSON.parse(rawBody) as Record<string, unknown>;
  expect(rawBody).toBe(canonicalCustomerBootstrapJson(body));
  expect(Object.keys(body).sort()).toEqual([
    'schemaVersion',
    'requestId',
    'issuedAt',
    'expiresAt',
    'settingsRevision',
    'settings',
    'target',
    'release',
    'expected',
    'cloudflareAccessToken',
  ].sort());
  expect(body.requestId).toMatch(/^[A-Za-z0-9_-]{22}$/u);
  expect(body.issuedAt).toBe(Math.floor(NOW / 1000));
  expect(body.expiresAt).toBe(Math.floor(NOW / 1000) + 300);
  expect((body.expiresAt as number) - (body.issuedAt as number)).toBeLessThanOrEqual(300);
  expect(body.cloudflareAccessToken).toBe(TOKEN);
  const { cloudflareAccessToken, ...claim } = body;
  return {
    claim: claim as unknown as PreparedCustomerBootstrapClaim,
    rawBody,
    token: cloudflareAccessToken as string,
  };
}

function expectError(
  error: unknown,
  code: CustomerBootstrapRequestError['code'],
  stage: CustomerBootstrapRequestError['stage'],
  outcome: CustomerBootstrapRequestError['outcome'],
): void {
  expect(error).toBeInstanceOf(CustomerBootstrapRequestError);
  expect(error).toMatchObject({ code, stage, outcome, canRetry: false });
  expect((error as Error).message).toBe(code);
}

describe('hosted customer bootstrap request', () => {
  it('builds the public verifier-compatible canonical claim and signs exact raw UTF-8 bytes', async () => {
    const requestId = base64UrlEncode(REQUEST_BYTES);
    const prepared = await prepareCustomerBootstrapClaim(await input());
    expect(prepared).toEqual({
      schemaVersion: 1,
      requestId,
      issuedAt: Math.floor(NOW / 1000),
      expiresAt: Math.floor(NOW / 1000) + 300,
      settingsRevision: 1,
      settings: {
        schemaVersion: 1,
        connect: {
          name: 'Example Gateway',
          hostname: 'mcp.example.com',
          codeMode: 'default_on',
        },
        access: {
          adminEmails: ['admin@example.com'],
          memberEmails: ['member@example.com', 'owner@example.com'],
        },
        sources: [{
          id: 'company-context',
          label: 'Company context',
          url: 'https://source.example.net/mcp',
          authentication: { mode: 'none', onBehalfOfUser: false },
          enabledTools: ['company_prepare', 'company_search'],
        }],
      },
      target: {
        accountId: '1'.repeat(32),
        zoneId: '2'.repeat(32),
        zoneName: 'example.com',
      },
      release: {
        id: 'gateway-v0.1.0',
        artifactSha256: `sha256:${'9'.repeat(64)}`,
      },
      expected: {
        configurationHash: GOLDEN_CONFIGURATION_HASH,
        installationId: GOLDEN_INSTALLATION_ID,
        desiredHash: GOLDEN_DESIRED_HASH,
      },
    });

    const transport = vi.fn(async (request: Request) => {
      const verified = await publicVerifierCompatible(request);
      expect(verified.claim).toEqual(prepared);
      const tampered = verified.rawBody.replace(TOKEN, `${TOKEN}-tampered`);
      expect(await hmac(tampered)).not.toBe(request.headers.get('x-ankka-bootstrap-signature'));
      return response(await ready(verified.claim));
    });
    const result = await submitCustomerBootstrap(await input({ transport }));
    expect(result).toEqual(await ready(prepared));
    expect(transport).toHaveBeenCalledOnce();
    expect(JSON.stringify(result)).not.toContain(TOKEN);
    expect(JSON.stringify(result)).not.toContain(NONCE);
  });

  it('prepares an empty Portal bootstrap without synthetic source resources', async () => {
    const selection = parseDeploySelection({ ...selectionInput, firstSource: null });
    const plan = await buildStaticDeployPlan(selection, manifest, NOW + 30 * 60_000);
    const preparedInput = await input({ selection, plan });
    const claim = await prepareCustomerBootstrapClaim(preparedInput);
    const projection = await prepareCustomerGatewayDesiredProjection(preparedInput);

    expect(claim.settings.sources).toEqual([]);
    expect(claim.settings.access).toEqual({
      adminEmails: ['admin@example.com'],
      memberEmails: ['owner@example.com'],
    });
    expect(projection.resourceKinds).toEqual([
      'portal',
      'portal_access_application',
      'portal_access_policy',
      'dns_record',
    ]);
    expect(projection.candidates.mcpServer).toBeNull();
    expect(projection.candidates.sourceAccessApplication).toBeNull();
    expect(projection.candidates.sourceAccessPolicy).toBeNull();
  });

  it('rejects stale claims and malformed request IDs before transport', async () => {
    const stalePlan = await approvedPlan(NOW - 1);
    const staleTransport = vi.fn();
    await expect(submitCustomerBootstrap(await input({
      plan: stalePlan,
      transport: staleTransport,
    }))).rejects.toSatisfy((error: unknown) => {
      expectError(error, 'request_expired', 'validate', 'not_sent');
      return true;
    });
    expect(staleTransport).not.toHaveBeenCalled();

    const invalidRandom = vi.fn(() => new Uint8Array(15));
    await expect(prepareCustomerBootstrapClaim(await input({
      randomBytes: invalidRandom,
    }))).rejects.toSatisfy((error: unknown) => {
      expectError(error, 'invalid_input', 'claim', 'not_sent');
      return true;
    });
  });

  it('fails closed when the approved plan, release, or response evidence hash differs', async () => {
    const basePlan = await approvedPlan();
    const changedPlan = { ...basePlan, planHash: `sha256:${'f'.repeat(64)}` };
    const noCall = vi.fn();
    await expect(submitCustomerBootstrap(await input({
      plan: changedPlan,
      transport: noCall,
    }))).rejects.toSatisfy((error: unknown) => {
      expectError(error, 'plan_mismatch', 'validate', 'not_sent');
      return true;
    });

    const otherRelease = {
      ...verifiedRelease,
      manifest: { ...structuredClone(manifest), release: 'gateway-v0.1.1' },
    };
    await expect(submitCustomerBootstrap(await input({
      release: otherRelease,
      transport: noCall,
    }))).rejects.toSatisfy((error: unknown) => {
      expectError(error, 'plan_mismatch', 'validate', 'not_sent');
      return true;
    });

    const mismatchedResponse = vi.fn(async (request: Request) => {
      const { claim } = await publicVerifierCompatible(request);
      return response({ ...await ready(claim), desiredHash: `sha256:${'0'.repeat(64)}` });
    });
    await expect(submitCustomerBootstrap(await input({
      transport: mismatchedResponse,
    }))).rejects.toSatisfy((error: unknown) => {
      expectError(error, 'response_invalid', 'response', 'unknown');
      return true;
    });
    expect(noCall).not.toHaveBeenCalled();
  });

  it('derives only the reviewed Worker on the authorized account subdomain and treats redirects as unknown', async () => {
    const noCall = vi.fn();
    for (const accountWorkersSubdomain of [
      BOOTSTRAP_ORIGIN,
      { accountId: '3'.repeat(32), subdomain: 'tenant' },
      { accountId: target.account.id, subdomain: 'other.tenant' },
      { accountId: target.account.id, subdomain: 'Tenant' },
      { accountId: target.account.id, subdomain: 'tenant:443' },
      { accountId: target.account.id, subdomain: 'tenant?next=1' },
      { accountId: target.account.id, subdomain: 'tenant', origin: BOOTSTRAP_ORIGIN },
    ]) {
      await expect(submitCustomerBootstrap(await input({
        accountWorkersSubdomain: accountWorkersSubdomain as AccountWorkersSubdomain,
        transport: noCall,
      }))).rejects.toSatisfy((error: unknown) => {
        expectError(error, 'origin_invalid', 'validate', 'not_sent');
        return true;
      });
    }
    expect(noCall).not.toHaveBeenCalled();

    let subdomainAccessorReads = 0;
    const accessorSubdomain = Object.defineProperties({}, {
      accountId: {
        enumerable: true,
        value: target.account.id,
      },
      subdomain: {
        enumerable: true,
        get: () => {
          subdomainAccessorReads += 1;
          return subdomainAccessorReads < 3 ? 'tenant' : 'attacker.example/collect?';
        },
      },
    });
    await expect(submitCustomerBootstrap(await input({
      accountWorkersSubdomain: accessorSubdomain as AccountWorkersSubdomain,
      transport: noCall,
    }))).rejects.toSatisfy((error: unknown) => {
      expectError(error, 'origin_invalid', 'validate', 'not_sent');
      return true;
    });
    expect(subdomainAccessorReads).toBe(0);
    expect(noCall).not.toHaveBeenCalled();

    const redirect = vi.fn(async () => new Response(null, {
      status: 307,
      headers: { location: 'https://attacker.example/collect' },
    }));
    await expect(submitCustomerBootstrap(await input({ transport: redirect })))
      .rejects.toSatisfy((error: unknown) => {
        expectError(error, 'outcome_unknown', 'response', 'unknown');
        return true;
      });

    const crossOrigin = vi.fn(async (request: Request) => {
      const { claim } = await publicVerifierCompatible(request);
      return response(await ready(claim), 200, 'https://attacker.example/result');
    });
    await expect(submitCustomerBootstrap(await input({ transport: crossOrigin })))
      .rejects.toSatisfy((error: unknown) => {
        expectError(error, 'outcome_unknown', 'response', 'unknown');
        return true;
      });
  });

  it('uses immutable target evidence and the rebuilt reviewed Worker for the token-bearing URL', async () => {
    const noCall = vi.fn();
    const accessorTarget = structuredClone(target);
    let accountIdAccessorReads = 0;
    Object.defineProperty(accessorTarget.account, 'id', {
      enumerable: true,
      get: () => {
        accountIdAccessorReads += 1;
        return accountIdAccessorReads < 3 ? target.account.id : '3'.repeat(32);
      },
    });
    await expect(submitCustomerBootstrap(await input({
      target: accessorTarget,
      transport: noCall,
    }))).rejects.toSatisfy((error: unknown) => {
      expectError(error, 'invalid_input', 'validate', 'not_sent');
      return true;
    });
    expect(accountIdAccessorReads).toBe(0);
    expect(noCall).not.toHaveBeenCalled();

    const plan = await approvedPlan();
    const reviewedResources = structuredClone(plan.managementResources);
    const switchedResources = structuredClone(plan.managementResources);
    const reviewedWorker = switchedResources.find(
      (resource) => resource.kind === 'management_worker',
    );
    if (!reviewedWorker) throw new Error('missing management worker fixture');
    reviewedWorker.name = 'attacker-worker';
    const accessorPlan = structuredClone(plan) as StaticDeployPlan;
    let resourceReads = 0;
    Object.defineProperty(accessorPlan, 'managementResources', {
      enumerable: true,
      get: () => {
        resourceReads += 1;
        return resourceReads <= 2 ? reviewedResources : switchedResources;
      },
    });
    const transport = vi.fn(async (request: Request) => {
      const { claim } = await publicVerifierCompatible(request);
      return response(await ready(claim));
    });
    await expect(submitCustomerBootstrap(await input({
      plan: accessorPlan,
      transport,
    }))).rejects.toSatisfy((error: unknown) => {
      expectError(error, 'plan_mismatch', 'validate', 'not_sent');
      return true;
    });
    expect(resourceReads).toBeGreaterThanOrEqual(2);
    expect(transport).not.toHaveBeenCalled();
  });

  it('accepts the safe ready response from a fresh completed-bootstrap recovery request', async () => {
    const freshRequestBytes = Uint8Array.from(
      { length: 16 },
      (_, index) => index + 61,
    );
    const transport = vi.fn(async (request: Request) => {
      const verified = await publicVerifierCompatible(request);
      expect(verified.claim.requestId).toBe(base64UrlEncode(freshRequestBytes));
      return response({
        ...await ready(verified.claim),
        applyInvoked: false,
        resumed: true,
      });
    });
    const result = await submitCustomerBootstrap(await input({
      randomBytes: (length) => {
        expect(length).toBe(16);
        return freshRequestBytes;
      },
      transport,
    }));
    expect(result).toEqual({
      ...await ready(await prepareCustomerBootstrapClaim(await input({
        randomBytes: () => freshRequestBytes,
      }))),
      applyInvoked: false,
      resumed: true,
    });
    expect(transport).toHaveBeenCalledOnce();
  });

  it('bounds time and response size and reports every post-submit uncertainty without retrying', async () => {
    const observed: { signal?: AbortSignal } = {};
    const hanging = vi.fn((request: Request) => {
      observed.signal = request.signal;
      return new Promise<Response>(() => undefined);
    });
    await expect(submitCustomerBootstrap(await input({
      transport: hanging,
      timeoutMs: 5,
    }))).rejects.toSatisfy((error: unknown) => {
      expectError(error, 'outcome_unknown', 'submit', 'unknown');
      return true;
    });
    expect(hanging).toHaveBeenCalledOnce();
    expect(observed.signal?.aborted).toBe(true);

    const oversized = vi.fn(async () => new Response('x'.repeat(64 * 1024 + 1), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));
    await expect(submitCustomerBootstrap(await input({ transport: oversized })))
      .rejects.toSatisfy((error: unknown) => {
        expectError(error, 'response_invalid', 'response', 'unknown');
        return true;
      });
    expect(oversized).toHaveBeenCalledOnce();
  });

  it('parses only safe recovery results and never offers an automatic retry', async () => {
    const transport = vi.fn(async () => response({
      schemaVersion: 1,
      error: 'bootstrap_recovery_required',
      retryable: true,
    }, 409));
    await expect(submitCustomerBootstrap(await input({ transport }))).resolves.toEqual({
      schemaVersion: 1,
      status: 'recovery_required',
      reason: 'bootstrap_recovery_required',
      canRetry: false,
    });
    expect(transport).toHaveBeenCalledOnce();

    const arbitrary = vi.fn(async () => response({
      schemaVersion: 1,
      error: `provider leaked ${TOKEN} ${NONCE}`,
      retryable: true,
    }, 409));
    await expect(submitCustomerBootstrap(await input({ transport: arbitrary })))
      .rejects.toSatisfy((error: unknown) => {
        expectError(error, 'bootstrap_rejected', 'response', 'rejected');
        expect(JSON.stringify(error)).not.toContain(TOKEN);
        expect(JSON.stringify(error)).not.toContain(NONCE);
        expect(String(error)).not.toContain(TOKEN);
        expect(String(error)).not.toContain(NONCE);
        return true;
      });
  });

  it('redacts thrown transport values and never sends the token as an authorization header', async () => {
    const transport = vi.fn(async (request: Request) => {
      expect(request.headers.get('authorization')).toBeNull();
      throw new Error(`network failed ${TOKEN} ${NONCE}`);
    });
    await expect(submitCustomerBootstrap(await input({ transport })))
      .rejects.toSatisfy((error: unknown) => {
        expectError(error, 'outcome_unknown', 'submit', 'unknown');
        const serialized = JSON.stringify(error);
        expect(serialized).not.toContain(TOKEN);
        expect(serialized).not.toContain(NONCE);
        expect(String(error)).not.toContain(TOKEN);
        expect(String(error)).not.toContain(NONCE);
        return true;
      });
    expect(transport).toHaveBeenCalledOnce();

    const badNonce = base64UrlEncode(new Uint8Array(31).fill(9));
    const noCall = vi.fn();
    await expect(submitCustomerBootstrap(await input({
      bootstrapNonce: badNonce,
      transport: noCall,
    }))).rejects.toSatisfy((error: unknown) => {
      expectError(error, 'invalid_input', 'validate', 'not_sent');
      return true;
    });
    expect(noCall).not.toHaveBeenCalled();
  });
});
