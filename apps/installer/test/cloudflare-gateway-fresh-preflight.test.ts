import { describe, expect, it, vi } from 'vitest';

import {
  CustomerGatewayFreshPreflightError,
  parseExistingAnkkaGatewaySummary,
  parseCustomerGatewayFreshPreflightAttestation,
  preflightFreshCustomerGateway,
  type CustomerGatewayFreshPreflightInput,
  type CustomerGatewayFreshPreflightTransport,
} from '../src/cloudflare-gateway-fresh-preflight';
import { prepareCustomerGatewayDesiredProjection } from '../src/customer-bootstrap-request';
import type { AuthorizedTarget } from '../src/cloudflare-target';
import { buildStaticDeployPlan, parseDeploySelection } from '../src/schema';
import { manifest, NOW, selectionInput, verifiedRelease } from './fixtures';

const ACCOUNT_ID = '1'.repeat(32);
const ZONE_ID = '2'.repeat(32);
const ACCESS_TOKEN = 'ephemeral_cloudflare_oauth_token_for_preflight';
const selection = parseDeploySelection(selectionInput);
const target: AuthorizedTarget = {
  actor: { id: 'actor_12345678', email: selection.basics.adminEmail },
  account: { id: ACCOUNT_ID, name: 'Example account' },
  zone: { id: ZONE_ID, name: selection.basics.zoneName, status: 'active' },
};
const plan = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
const projection = await prepareCustomerGatewayDesiredProjection({
  selection,
  target,
  release: verifiedRelease,
  plan,
  nowMs: NOW,
});

type ResponseFactory = (request: Request, index: number) => Response | Promise<Response>;
type PreflightRequest = Parameters<CustomerGatewayFreshPreflightTransport>[0];

interface RecordedTransport {
  readonly transport: CustomerGatewayFreshPreflightTransport;
  readonly requests: PreflightRequest[];
}

function successPage(
  result: readonly unknown[],
  page = 1,
  totalCount = result.length,
  extraInfo: Record<string, unknown> = {},
): Response {
  return Response.json({
    errors: [],
    messages: [],
    result,
    result_info: {
      count: result.length,
      page,
      per_page: 100,
      total_count: totalCount,
      ...extraInfo,
    },
    success: true,
  });
}

function recorded(factory: Response | ResponseFactory): RecordedTransport {
  const requests: PreflightRequest[] = [];
  return {
    requests,
    transport: async (request) => {
      const index = requests.length;
      requests.push(request.clone() as PreflightRequest);
      return factory instanceof Response ? factory.clone() : await factory(request, index);
    },
  };
}

function emptyProvider(overrides: Partial<Record<string, readonly unknown[]>> = {}): RecordedTransport {
  return recorded((request) => {
    const url = new URL(request.url);
    const result = overrides[url.pathname] ?? [];
    const filteredDns = url.pathname.endsWith('/dns_records');
    return successPage(result, 1, filteredDns ? 2_000 : result.length);
  });
}

function input(
  transport: CustomerGatewayFreshPreflightTransport,
  overrides: Partial<CustomerGatewayFreshPreflightInput> = {},
): CustomerGatewayFreshPreflightInput {
  return {
    selection,
    target,
    release: verifiedRelease,
    plan,
    nowMs: NOW,
    accessToken: ACCESS_TOKEN,
    transport,
    ...overrides,
  };
}

function expectPreflightError(
  error: unknown,
  code: CustomerGatewayFreshPreflightError['code'],
  stage: CustomerGatewayFreshPreflightError['stage'],
): boolean {
  expect(error).toBeInstanceOf(CustomerGatewayFreshPreflightError);
  expect(error).toMatchObject({ code, stage, canRetry: false });
  expect((error as Error).message).toBe(code);
  expect(JSON.stringify(error)).not.toContain(ACCESS_TOKEN);
  return true;
}

const SERVER_PATH = `/client/v4/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/servers`;
const APPS_PATH = `/client/v4/accounts/${ACCOUNT_ID}/access/apps`;
const PORTALS_PATH = `/client/v4/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/portals`;
const DNS_PATH = `/client/v4/zones/${ZONE_ID}/dns_records`;

interface ExistingGatewayResourceOverrides {
  readonly portalApplication?: Readonly<Record<string, unknown>>;
  readonly managementApplication?: Readonly<Record<string, unknown>>;
  readonly portal?: Readonly<Record<string, unknown>>;
  readonly dnsRecord?: Readonly<Record<string, unknown>>;
}

function existingGatewayProvider(
  overrides: ExistingGatewayResourceOverrides = {},
): RecordedTransport {
  return emptyProvider({
    [APPS_PATH]: [
      {
        id: 'a'.repeat(32),
        type: 'mcp_portal',
        name: projection.candidates.portalAccessApplication.name,
        domain: projection.candidates.portalAccessApplication.hostname,
        destinations: [{
          type: 'public',
          uri: projection.candidates.portalAccessApplication.hostname,
        }],
        ...overrides.portalApplication,
      },
      {
        id: 'b'.repeat(32),
        type: 'self_hosted',
        name: `${selection.basics.gatewayName} management [${plan.managementOwnershipMarker}]`,
        domain: selection.basics.managementHostname,
        ...overrides.managementApplication,
      },
    ],
    [PORTALS_PATH]: [{
      id: 'existing-portal',
      hostname: selection.basics.portalHostname,
      name: selection.basics.gatewayName,
      description: projection.candidates.portal.ownershipMarker,
      ...overrides.portal,
    }],
    [DNS_PATH]: [{
      id: 'c'.repeat(32),
      name: selection.basics.portalHostname,
      type: 'CNAME',
      content: 'gateway.agents.cloudflare.com',
      proxied: true,
      comment: `acg:v1:${projection.expected.installationId}:${projection.candidates.dnsRecord.key}`,
      ...overrides.dnsRecord,
    }],
  });
}

describe('private customer-gateway fresh preflight', () => {
  it('returns only a secret-free handoff summary for a coherent existing Ankka gateway', async () => {
    const provider = existingGatewayProvider();

    let detected: CustomerGatewayFreshPreflightError | null = null;
    try {
      await preflightFreshCustomerGateway(input(provider.transport));
    } catch (error) {
      detected = error as CustomerGatewayFreshPreflightError;
    }
    expect(detected).toBeInstanceOf(CustomerGatewayFreshPreflightError);
    expect(detected).toMatchObject({
      code: 'existing_gateway_detected',
      stage: 'portal_list',
      canRetry: false,
      existingGateway: {
        schemaVersion: 1,
        installationId: projection.expected.installationId,
        name: selection.basics.gatewayName,
        managementHostname: selection.basics.managementHostname,
        portalHostname: selection.basics.portalHostname,
        workerName: `ankka-gateway-example-gateway-${plan.managementOwnershipMarker}`,
      },
    });
    expect(parseExistingAnkkaGatewaySummary(detected?.existingGateway)).toEqual(detected?.existingGateway);
    const serialized = JSON.stringify(detected);
    expect(serialized).not.toContain(ACCESS_TOKEN);
    expect(serialized).not.toContain('existing-portal');
    expect(provider.requests).toHaveLength(4);
  });

  it.each([
    ['management hostname', {
      managementApplication: { domain: 'foreign.example.com' },
    }],
    ['malformed management ownership marker', {
      managementApplication: { name: `${selection.basics.gatewayName} management [foreign]` },
    }],
    ['Portal ownership marker', {
      portal: { description: `acg:v1:acg-${'f'.repeat(24)}:${projection.candidates.portal.key}` },
    }],
    ['Portal application domain', {
      portalApplication: { domain: 'foreign.example.com' },
    }],
    ['Portal application destination', {
      portalApplication: { destinations: [{ type: 'public', uri: 'foreign.example.com' }] },
    }],
    ['Portal application destination shape', {
      portalApplication: {
        destinations: [{
          type: 'public',
          uri: selection.basics.portalHostname,
          foreign: true,
        }],
      },
    }],
    ['DNS target', {
      dnsRecord: { content: 'foreign.example.com' },
    }],
    ['DNS proxy mode', {
      dnsRecord: { proxied: false },
    }],
    ['DNS ownership marker', {
      dnsRecord: { comment: `acg:v1:acg-${'f'.repeat(24)}:${projection.candidates.dnsRecord.key}` },
    }],
  ] satisfies readonly (readonly [string, ExistingGatewayResourceOverrides])[])(
    'does not adopt an otherwise coherent gateway with mismatched %s evidence',
    async (_label, overrides) => {
      const provider = existingGatewayProvider(overrides);
      await expect(preflightFreshCustomerGateway(input(provider.transport))).rejects.toSatisfy(
        (error: unknown) => expectPreflightError(error, 'fresh_collision', 'access_application_list'),
      );
      expect(provider.requests).toHaveLength(4);
    },
  );

  it('routes a coherent older release by its exact retained management marker', async () => {
    const retainedMarker = `acg-${'f'.repeat(24)}`;
    const provider = existingGatewayProvider({
      managementApplication: {
        name: `${selection.basics.gatewayName} management [${retainedMarker}]`,
      },
    });

    await expect(preflightFreshCustomerGateway(input(provider.transport))).rejects.toSatisfy(
      (error: unknown) => {
        expect(error).toBeInstanceOf(CustomerGatewayFreshPreflightError);
        expect(error).toMatchObject({
          code: 'existing_gateway_detected',
          existingGateway: {
            installationId: projection.expected.installationId,
            workerName: `ankka-gateway-example-gateway-${retainedMarker}`,
          },
        });
        return true;
      },
    );
    expect(provider.requests).toHaveLength(4);
  });

  it('reads every broad candidate set twice and returns a short exact secret-free attestation', async () => {
    const provider = emptyProvider();
    const attestation = await preflightFreshCustomerGateway(input(provider.transport));

    expect(provider.requests.map((request) => new URL(request.url).pathname)).toEqual([
      SERVER_PATH,
      APPS_PATH,
      PORTALS_PATH,
      DNS_PATH,
      SERVER_PATH,
      APPS_PATH,
      PORTALS_PATH,
      DNS_PATH,
    ]);
    for (const request of provider.requests) {
      expect(request.method).toBe('GET');
      expect(request.headers.get('authorization')).toBe(`Bearer ${ACCESS_TOKEN}`);
      expect(request.headers.get('accept')).toBe('application/json');
      // workerd refuses redirect:'error'; 'manual' plus explicit 3xx rejection below.
      expect(request.redirect).toBe('manual');
      expect(request.body).toBeNull();
    }
    const dnsUrl = new URL(provider.requests[3].url);
    expect(dnsUrl.searchParams.get('name.exact')).toBe(selection.basics.portalHostname);
    expect(dnsUrl.searchParams.get('match')).toBe('all');
    expect(dnsUrl.searchParams.get('page')).toBe('1');
    expect(dnsUrl.searchParams.get('per_page')).toBe('100');

    expect(attestation).toMatchObject({
      schemaVersion: 1,
      kind: 'customer_gateway_fresh_preflight',
      accountId: ACCOUNT_ID,
      zoneId: ZONE_ID,
      planId: plan.planId,
      planHash: plan.planHash,
      installationId: projection.expected.installationId,
      configurationHash: projection.expected.configurationHash,
      desiredHash: projection.expected.desiredHash,
      releaseId: plan.releaseId,
      releaseArtifactSha256: plan.releaseArtifactSha256,
      zeroCandidateKinds: [
        'mcp_server',
        'source_access_application',
        'source_access_policy',
        'portal',
        'portal_access_application',
        'portal_access_policy',
        'dns_record',
      ],
      checkedAt: NOW,
      expiresAt: NOW + 30_000,
    });
    expect(attestation.attestationHash).toMatch(/^sha256:[a-f0-9]{64}$/u);
    expect(Object.isFrozen(attestation)).toBe(true);
    expect(Object.isFrozen(attestation.zeroCandidateKinds)).toBe(true);
    const serialized = JSON.stringify(attestation);
    expect(serialized).not.toContain(ACCESS_TOKEN);
    expect(serialized.toLowerCase()).not.toMatch(/token|nonce|secret|jwt/u);

    const parsed = await parseCustomerGatewayFreshPreflightAttestation(JSON.parse(serialized));
    expect(parsed).toEqual(attestation);
    expect(parsed).not.toBe(attestation);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed?.zeroCandidateKinds)).toBe(true);
    await expect(parseCustomerGatewayFreshPreflightAttestation({
      ...attestation,
      desiredHash: `sha256:${'f'.repeat(64)}`,
    })).resolves.toBeNull();
    await expect(parseCustomerGatewayFreshPreflightAttestation({
      ...attestation,
      expiresAt: attestation.checkedAt + 60_001,
    })).resolves.toBeNull();
  });

  it('preflights an empty Portal without scanning for an initial MCP server', async () => {
    const portalSelection = parseDeploySelection({ ...selectionInput, firstSource: null });
    const portalPlan = await buildStaticDeployPlan(portalSelection, manifest, NOW + 600_000);
    const provider = emptyProvider();
    const attestation = await preflightFreshCustomerGateway(input(provider.transport, {
      selection: portalSelection,
      plan: portalPlan,
    }));

    expect(provider.requests.map((request) => new URL(request.url).pathname)).toEqual([
      APPS_PATH, PORTALS_PATH, DNS_PATH,
      APPS_PATH, PORTALS_PATH, DNS_PATH,
    ]);
    expect(attestation.zeroCandidateKinds).toEqual([
      'portal', 'portal_access_application', 'portal_access_policy', 'dns_record',
    ]);
    await expect(parseCustomerGatewayFreshPreflightAttestation(attestation)).resolves.toEqual(attestation);
  });

  it.each([
    ['deterministic MCP server ID', SERVER_PATH, {
      id: projection.candidates.mcpServer!.id,
      hostname: 'https://foreign.example.net/mcp',
      name: 'Foreign',
    }, 'mcp_server_list'],
    ['same MCP endpoint', SERVER_PATH, {
      id: 'foreign-server',
      hostname: projection.candidates.mcpServer!.endpoint,
      name: 'Foreign',
    }, 'mcp_server_list'],
    ['MCP ownership marker', SERVER_PATH, {
      id: 'foreign-server',
      hostname: 'https://foreign.example.net/mcp',
      name: 'Foreign',
      description: projection.candidates.mcpServer!.ownershipMarker,
    }, 'mcp_server_list'],
    ['source app server relation', APPS_PATH, {
      id: 'a'.repeat(32),
      type: 'mcp',
      name: 'Foreign',
      destinations: [{
        type: 'via_mcp_server_portal',
        mcp_server_id: projection.candidates.sourceAccessApplication!.serverId,
      }],
    }, 'access_application_list'],
    ['source app ownership marker', APPS_PATH, {
      id: 'a'.repeat(32),
      type: 'self_hosted',
      name: projection.candidates.sourceAccessApplication!.ownershipMarker,
    }, 'access_application_list'],
    ['deterministic portal ID', PORTALS_PATH, {
      id: projection.candidates.portal.id,
      hostname: 'foreign.example.com',
      name: 'Foreign',
    }, 'portal_list'],
    ['portal hostname', PORTALS_PATH, {
      id: 'foreign-portal',
      hostname: projection.candidates.portal.hostname,
      name: 'Foreign',
    }, 'portal_list'],
    ['portal name', PORTALS_PATH, {
      id: 'foreign-portal',
      hostname: 'foreign.example.com',
      name: projection.candidates.portal.name,
    }, 'portal_list'],
    ['portal ownership marker', PORTALS_PATH, {
      id: 'foreign-portal',
      hostname: 'foreign.example.com',
      name: 'Foreign',
      description: projection.candidates.portal.ownershipMarker,
    }, 'portal_list'],
    ['portal app name', APPS_PATH, {
      id: 'a'.repeat(32),
      type: 'self_hosted',
      name: projection.candidates.portalAccessApplication.name,
    }, 'access_application_list'],
    ['portal app domain', APPS_PATH, {
      id: 'a'.repeat(32),
      type: 'mcp_portal',
      name: 'Foreign',
      domain: projection.candidates.portalAccessApplication.hostname,
    }, 'access_application_list'],
    ['portal app destination', APPS_PATH, {
      id: 'a'.repeat(32),
      type: 'mcp_portal',
      name: 'Foreign',
      destinations: [{
        type: 'public',
        uri: projection.candidates.portalAccessApplication.hostname,
      }],
    }, 'access_application_list'],
    ['exact portal DNS', DNS_PATH, {
      id: 'b'.repeat(32),
      name: projection.candidates.dnsRecord.hostname,
      type: 'CNAME',
      content: 'foreign.example.com',
      proxied: true,
      comment: null,
    }, 'dns_record_list'],
  ] as const)(
    'fails closed on %s without reading policy children',
    async (_label, path, candidate, stage) => {
      const provider = emptyProvider({ [path]: [candidate] });
      await expect(preflightFreshCustomerGateway(input(provider.transport))).rejects.toSatisfy(
        (error: unknown) => expectPreflightError(error, 'fresh_collision', stage),
      );
      expect(provider.requests.some((request) =>
        new URL(request.url).pathname.includes('/policies'))).toBe(false);
    },
  );

  it('accepts the AI Controls envelope that omits errors and messages, and still rejects a populated errors array', async () => {
    // Live 2026-08-23: /access/ai-controls/mcp/* returns {result, result_info, success}
    // only; classic endpoints keep errors/messages. Both shapes are one contract.
    const aiControls = recorded((request) => {
      const url = new URL(request.url);
      const filteredDns = url.pathname.endsWith('/dns_records');
      if (url.pathname.includes('/ai-controls/')) {
        return Response.json({
          result: [],
          result_info: { count: 0, page: 1, per_page: 100, total_count: 0 },
          success: true,
        });
      }
      return successPage([], 1, filteredDns ? 2_000 : 0);
    });
    const attestation = await preflightFreshCustomerGateway(input(aiControls.transport));
    expect(attestation.kind).toBe('customer_gateway_fresh_preflight');
    expect(aiControls.requests).toHaveLength(8);

    const populatedErrors = recorded(Response.json({
      errors: [{ code: 1000, message: 'synthetic' }], messages: [], result: [],
      result_info: { count: 0, page: 1, per_page: 100, total_count: 0 }, success: true,
    }));
    await expect(preflightFreshCustomerGateway(input(populatedErrors.transport))).rejects.toSatisfy(
      (error: unknown) => expectPreflightError(error, 'provider_mismatch', 'mcp_server_list'),
    );
  });

  it('rejects a redirecting provider response as a read failure instead of following it', async () => {
    const redirecting = recorded(new Response(null, { status: 302, headers: { location: 'https://example.invalid/' } }));
    await expect(preflightFreshCustomerGateway(input(redirecting.transport))).rejects.toSatisfy(
      (error: unknown) => expectPreflightError(error, 'provider_unknown', 'mcp_server_list'),
    );
  });

  it('does not infer freshness from the first scan and rejects a late second-scan candidate', async () => {
    const provider = recorded((request, index) => {
      const path = new URL(request.url).pathname;
      if (index === 4 && path === SERVER_PATH) {
        return successPage([{
          id: projection.candidates.mcpServer!.id,
          hostname: projection.candidates.mcpServer!.endpoint,
          name: selection.firstSource!.name,
        }]);
      }
      return successPage([], 1, path === DNS_PATH ? 2_000 : 0);
    });
    await expect(preflightFreshCustomerGateway(input(provider.transport))).rejects.toSatisfy(
      (error: unknown) => expectPreflightError(error, 'fresh_collision', 'mcp_server_list'),
    );
    expect(provider.requests).toHaveLength(5);
  });

  it('fully paginates unfiltered lists and rejects duplicate IDs across pages', async () => {
    const firstPage = Array.from({ length: 100 }, (_, index) => ({
      id: `foreign-${index}`,
      hostname: `https://source-${index}.example.net/mcp`,
      name: `Foreign ${index}`,
    }));
    const provider = recorded((request) => {
      const url = new URL(request.url);
      if (url.pathname === SERVER_PATH) {
        const page = Number(url.searchParams.get('page'));
        return page === 1
          ? successPage(firstPage, 1, 101, { total_pages: 2 })
          : successPage([firstPage[0]], 2, 101, { total_pages: 2 });
      }
      return successPage([], 1, url.pathname === DNS_PATH ? 2_000 : 0);
    });
    await expect(preflightFreshCustomerGateway(input(provider.transport))).rejects.toSatisfy(
      (error: unknown) => expectPreflightError(error, 'provider_ambiguous', 'mcp_server_list'),
    );
    expect(provider.requests).toHaveLength(2);
  });

  it.each([
    ['unknown envelope field', {
      errors: [], messages: [], result: [], result_info: {
        count: 0, page: 1, per_page: 100, total_count: 0,
      }, success: true, extra: true,
    }],
    ['missing result_info', { errors: [], messages: [], result: [], success: true }],
    ['partial zero page', {
      errors: [], messages: [], result: [], result_info: {
        count: 0, page: 1, per_page: 100, total_count: 1,
      }, success: true,
    }],
    ['wrong page', {
      errors: [], messages: [], result: [], result_info: {
        count: 0, page: 2, per_page: 100, total_count: 0,
      }, success: true,
    }],
  ])('rejects %s instead of accepting a partial or unknown list', async (_label, body) => {
    const provider = recorded(Response.json(body));
    await expect(preflightFreshCustomerGateway(input(provider.transport))).rejects.toSatisfy(
      (error: unknown) => expectPreflightError(error, 'provider_mismatch', 'mcp_server_list'),
    );
  });

  it('bounds chunked provider bodies and timeouts without exposing the grant or body', async () => {
    let cancelled = false;
    const provider = recorded(() => new Response(new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(1024 * 1024 + 1));
      },
      cancel() {
        cancelled = true;
      },
    }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));
    await expect(preflightFreshCustomerGateway(input(provider.transport))).rejects.toSatisfy(
      (error: unknown) => expectPreflightError(error, 'provider_unknown', 'mcp_server_list'),
    );
    expect(cancelled).toBe(true);

    const never = recorded(async () => new Promise<Response>(() => undefined));
    await expect(preflightFreshCustomerGateway(input(never.transport, { timeoutMs: 1 })))
      .rejects.toSatisfy(
        (error: unknown) => expectPreflightError(error, 'provider_unknown', 'mcp_server_list'),
      );
  });

  it('rejects a reviewed-target mismatch before any provider read', async () => {
    const transport = vi.fn<CustomerGatewayFreshPreflightTransport>();
    await expect(preflightFreshCustomerGateway(input(transport, {
      target: {
        ...target,
        zone: { ...target.zone, name: 'foreign.example' },
      },
    }))).rejects.toSatisfy(
      (error: unknown) => expectPreflightError(error, 'invalid_input', 'validate'),
    );
    expect(transport).not.toHaveBeenCalled();
  });
});
