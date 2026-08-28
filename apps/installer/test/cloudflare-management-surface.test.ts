import {
  CloudflareManagementError,
  attachManagementCustomDomain,
  createManagementAccessApplication,
  createManagementAdminAllowPolicy,
  getAccountWorkersSubdomain,
  getZeroTrustOrganization,
  listAccessIdentityProviders,
  managementAccessApplicationName,
  managementAdminPolicyName,
  managementOwnershipMarker,
  preflightFreshManagementAccessApplication,
  preflightFreshManagementCustomDomain,
  prepareManagementAccessApplicationIntent,
  prepareManagementAdminPolicyIntent,
  prepareManagementCustomDomainIntent,
  recoverManagementAccessApplication,
  recoverManagementAdminAllowPolicy,
  recoverManagementCustomDomain,
  setWorkerBootstrapSubdomain,
  verifyManagementAccessApplicationGet,
  verifyManagementAccessApplicationList,
  verifyManagementAdminAllowPolicyGet,
  verifyManagementAdminAllowPolicyList,
  verifyManagementCustomDomainGet,
  verifyManagementCustomDomainList,
  verifyWorkerBootstrapSubdomain,
  type CloudflareManagementTransport,
} from '../src/cloudflare-management-surface';
import { buildStaticDeployPlan, parseDeploySelection } from '../src/schema';
import { manifest, NOW, selectionInput } from './fixtures';

const ACCOUNT_ID = 'a'.repeat(32);
const ZONE_ID = 'b'.repeat(32);
const APP_ID = 'f174e90a-fafe-4643-bbbc-4a0ed4fc8415';
const OTHER_APP_ID = 'e174e90a-fafe-4643-bbbc-4a0ed4fc8415';
const POLICY_ID = 'd174e90a-fafe-4643-bbbc-4a0ed4fc8415';
const OTHER_POLICY_ID = 'c174e90a-fafe-4643-bbbc-4a0ed4fc8415';
const DOMAIN_ID = 'd'.repeat(32);
const OTHER_DOMAIN_ID = 'e'.repeat(32);
const ROUTE_ID = 'f'.repeat(32);
const DNS_ID = '7'.repeat(32);
const AUD = 'access-audience-token-1234567890';
const ACCESS_TOKEN = 'oauth_access_token_for_management_test';
const IDP_ONE = '1'.repeat(32);
const IDP_TWO = '2'.repeat(32);
const PLAN = await buildStaticDeployPlan(
  parseDeploySelection(selectionInput),
  manifest,
  NOW + 600_000,
);
const ZONE_NAME = PLAN.gatewayConfiguration.zoneName;
const MANAGEMENT_HOSTNAME = PLAN.gatewayConfiguration.managementHostname;
const MANAGEMENT_MARKER = PLAN.managementOwnershipMarker;
const JOURNAL_MARKER = `ankka-mcp-gateway:${MANAGEMENT_MARKER}`;
const MANAGEMENT_APP_NAME = `Example Gateway management [${MANAGEMENT_MARKER}]`;
const MANAGEMENT_POLICY_NAME = `Example Gateway administrators [${MANAGEMENT_MARKER}]`;
const WORKER_NAME = PLAN.managementResources.find((resource) => resource.kind === 'management_worker')?.name;
if (!WORKER_NAME) throw new TypeError('worker fixture');

type ManagementRequest = Parameters<CloudflareManagementTransport>[0];
type ResponseFactory = (request: ManagementRequest) => Response | Promise<Response>;

interface RecordedTransport {
  readonly transport: CloudflareManagementTransport;
  readonly requests: ManagementRequest[];
}

function success(result: unknown, resultInfo?: unknown, status = 200): Response {
  return Response.json({
    errors: [],
    messages: [],
    result,
    ...(resultInfo === undefined ? {} : { result_info: resultInfo }),
    success: true,
  }, { status });
}

function page(
  result: readonly unknown[],
  pageNumber: number,
  totalCount: number,
  perPage: number,
  extra: Record<string, unknown> = {},
): Response {
  return success(result, {
    count: result.length,
    page: pageNumber,
    per_page: perPage,
    total_count: totalCount,
    ...extra,
  });
}

function failure(status = 400, message = 'provider rejected this request'): Response {
  return Response.json({
    errors: [{ code: 1000, message }],
    messages: [],
    result: null,
    success: false,
  }, { status });
}

function recorded(response: Response | ResponseFactory): RecordedTransport {
  const requests: ManagementRequest[] = [];
  return {
    requests,
    transport: async (request) => {
      requests.push(request.clone() as unknown as ManagementRequest);
      return typeof response === 'function' ? await response(request) : response.clone();
    },
  };
}

function sequenced(steps: readonly (Response | ResponseFactory)[]): RecordedTransport {
  let index = 0;
  return recorded(async (request) => {
    const step = steps[index];
    index += 1;
    if (!step) throw new Error('unexpected provider request');
    return typeof step === 'function' ? await step(request) : step.clone();
  });
}

function call(transport: CloudflareManagementTransport) {
  return { accessToken: ACCESS_TOKEN, transport };
}

function applicationSpec() {
  return {
    accountId: ACCOUNT_ID,
    allowedIdentityProviderIds: [IDP_ONE, IDP_TWO],
    plan: PLAN,
  } as const;
}

function exactApplication(id = APP_ID, aud = AUD): Record<string, unknown> {
  return {
    allow_authenticate_via_warp: false,
    allowed_idps: [IDP_ONE, IDP_TWO],
    app_launcher_visible: false,
    aud,
    auto_redirect_to_identity: false,
    domain: MANAGEMENT_HOSTNAME,
    id,
    name: managementAccessApplicationName(PLAN),
    session_duration: '24h',
    type: 'self_hosted',
  };
}

function policySpec() {
  return { accountId: ACCOUNT_ID, applicationId: APP_ID, plan: PLAN } as const;
}

function exactPolicy(id = POLICY_ID): Record<string, unknown> {
  return {
    approval_required: false,
    decision: 'allow',
    exclude: [],
    id,
    include: [
      { email: { email: 'admin@example.com' } },
      { email: { email: 'owner@example.com' } },
    ],
    isolation_required: false,
    name: managementAdminPolicyName(PLAN),
    precedence: 1,
    purpose_justification_required: false,
    require: [],
  };
}

function domainSpec() {
  return { accountId: ACCOUNT_ID, plan: PLAN, zoneId: ZONE_ID } as const;
}

function exactDomain(id = DOMAIN_ID): Record<string, unknown> {
  return {
    cert_id: '9fdf92c8-64c2-4a3d-b1af-e15304961145',
    environment: 'production',
    hostname: MANAGEMENT_HOSTNAME,
    id,
    service: WORKER_NAME,
    zone_id: ZONE_ID,
    zone_name: ZONE_NAME,
  };
}

function expectManagementError(
  error: unknown,
  expected: Pick<CloudflareManagementError, 'code' | 'stage' | 'outcome'>,
): boolean {
  expect(error).toBeInstanceOf(CloudflareManagementError);
  expect(error).toMatchObject({ ...expected, canRetry: false });
  expect((error as Error).message).toBe(expected.code);
  expect((error as Error).message).not.toContain(ACCESS_TOKEN);
  return true;
}

describe('Cloudflare management-surface prerequisite', () => {
  it('reads bounded organization and exact account Workers subdomain projections', async () => {
    const organization = recorded(success({
      auth_domain: 'acme.cloudflareaccess.com',
      custom_pages: { ignored: true },
      name: 'Acme',
    }));
    await expect(getZeroTrustOrganization({
      ...call(organization.transport),
      accountId: ACCOUNT_ID,
    })).resolves.toEqual({
      authDomain: 'acme.cloudflareaccess.com',
      issuer: 'https://acme.cloudflareaccess.com',
      name: 'Acme',
    });

    const subdomain = recorded(success({ subdomain: 'acme-workers' }));
    await expect(getAccountWorkersSubdomain({
      ...call(subdomain.transport),
      accountId: ACCOUNT_ID,
    })).resolves.toEqual({ accountId: ACCOUNT_ID, subdomain: 'acme-workers' });
    expect(subdomain.requests[0].method).toBe('GET');
    expect(subdomain.requests[0].url).toBe(
      `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/workers/subdomain`,
    );

    const malformed = recorded(success({ subdomain: 'acme-workers', unexpected: true }));
    await expect(getAccountWorkersSubdomain({
      ...call(malformed.transport),
      accountId: ACCOUNT_ID,
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'provider_mismatch',
      stage: 'account_worker_subdomain_get',
      outcome: 'rejected',
    }));
  });

  it('paginates list endpoints using total_count while tolerating optional metadata', async () => {
    const provider = recorded((request) => {
      const requested = Number(new URL(request.url).searchParams.get('page'));
      if (requested === 1) {
        return page([
          { id: IDP_TWO, name: 'One-time PIN', type: 'onetimepin' },
        ], 1, 2, 1_000, { provider_note: 'optional metadata' });
      }
      return page([
        { id: IDP_ONE, name: 'Google Workspace', read_only: true, type: 'google-apps' },
      ], 2, 2, 1_000);
    });
    await expect(listAccessIdentityProviders({
      ...call(provider.transport),
      accountId: ACCOUNT_ID,
    })).resolves.toEqual([
      { id: IDP_ONE, name: 'Google Workspace', readOnly: true, type: 'google-apps' },
      { id: IDP_TWO, name: 'One-time PIN', readOnly: false, type: 'onetimepin' },
    ]);
    expect(provider.requests).toHaveLength(2);
    expect(new URL(provider.requests[1].url).searchParams.get('page')).toBe('2');
  });

  it('accepts the account-default Cloudflare identity provider, which is listed with an empty name', async () => {
    // Live shape 2026-08-23: new Zero Trust organisations get type "cloudflare"
    // with name "" and extra uid/version/config fields.
    const provider = recorded(page([
      { id: IDP_ONE, type: 'cloudflare', uid: IDP_ONE, name: '', version: '1', config: {}, scim_config: {} },
    ], 1, 1, 1_000));
    await expect(listAccessIdentityProviders({
      ...call(provider.transport),
      accountId: ACCOUNT_ID,
    })).resolves.toEqual([{ id: IDP_ONE, name: '', readOnly: false, type: 'cloudflare' }]);

    const unnamedOther = recorded(page([{ id: IDP_ONE, type: 'onetimepin', name: '' }], 1, 1, 1_000));
    await expect(listAccessIdentityProviders({
      ...call(unnamedOther.transport),
      accountId: ACCOUNT_ID,
    })).rejects.toMatchObject({ code: 'provider_mismatch', stage: 'identity_provider_list' });
  });

  it('does not treat filtered-list total_count as the number of matching results', async () => {
    const provider = recorded(success([], {
      count: 0,
      page: 1,
      per_page: 100,
      total_count: 2_000,
      total_pages: 1,
    }));
    await expect(preflightFreshManagementAccessApplication({
      ...call(provider.transport),
      accountId: ACCOUNT_ID,
      plan: PLAN,
    })).resolves.toEqual({ clear: true });
    expect(provider.requests).toHaveLength(1);
  });

  it('fails closed on inconsistent pagination totals', async () => {
    const provider = recorded((request) => {
      const requested = Number(new URL(request.url).searchParams.get('page'));
      return requested === 1
        ? page([{ id: IDP_ONE, name: 'One', type: 'onetimepin' }], 1, 2, 1_000)
        : page([{ id: IDP_TWO, name: 'Two', type: 'onetimepin' }], 2, 3, 1_000);
    });
    await expect(listAccessIdentityProviders({
      ...call(provider.transport),
      accountId: ACCOUNT_ID,
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'provider_unknown',
      stage: 'identity_provider_list',
      outcome: 'unknown',
    }));
  });

  it('binds names, marker, and all journal intents to the exact reviewed plan', () => {
    expect(PLAN.planHash).toMatch(/^sha256:[a-f0-9]{64}$/u);
    expect(MANAGEMENT_MARKER).toMatch(/^acg-[a-f0-9]{24}$/u);
    expect(managementAccessApplicationName(PLAN)).toBe(MANAGEMENT_APP_NAME);
    expect(managementAdminPolicyName(PLAN)).toBe(MANAGEMENT_POLICY_NAME);
    expect(managementOwnershipMarker(PLAN)).toBe(JOURNAL_MARKER);

    const appIntent = prepareManagementAccessApplicationIntent(applicationSpec());
    expect(appIntent).toMatchObject({
      schemaVersion: 1,
      kind: 'management_access_application',
      planId: PLAN.planId,
      planHash: PLAN.planHash,
      ownershipMarker: JOURNAL_MARKER,
      request: { domain: MANAGEMENT_HOSTNAME, name: MANAGEMENT_APP_NAME },
    });
    expect(prepareManagementAdminPolicyIntent(policySpec())).toMatchObject({
      kind: 'management_admin_policy',
      planId: PLAN.planId,
      request: { name: MANAGEMENT_POLICY_NAME },
    });
    expect(prepareManagementCustomDomainIntent(domainSpec())).toMatchObject({
      kind: 'management_custom_domain',
      planId: PLAN.planId,
      request: { hostname: MANAGEMENT_HOSTNAME, service: WORKER_NAME },
    });
    expect(JSON.stringify([appIntent])).not.toContain(ACCESS_TOKEN);
  });

  it('rejects a noncanonical plan hash or drifted reviewed resource before provider I/O', async () => {
    let calls = 0;
    const transport: CloudflareManagementTransport = async () => {
      calls += 1;
      return success([]);
    };
    const rawHashPlan = { ...PLAN, planHash: PLAN.planHash.slice('sha256:'.length) };
    expect(() => prepareManagementAccessApplicationIntent({
      ...applicationSpec(),
      plan: rawHashPlan,
    })).toThrow();
    const driftedPlan = {
      ...PLAN,
      managementResources: PLAN.managementResources.map((resource) =>
        resource.kind === 'management_access_application'
          ? { ...resource, name: 'provider-only hidden name' }
          : resource),
    };
    await expect(preflightFreshManagementAccessApplication({
      ...call(transport),
      accountId: ACCOUNT_ID,
      plan: driftedPlan,
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'invalid_input',
      stage: 'management_app_baseline',
      outcome: 'not_sent',
    }));
    expect(calls).toBe(0);
  });

  it('proves exact paginated fresh baselines for Access app and custom domain', async () => {
    const app = recorded(page([], 1, 0, 100, { total_pages: 0 }));
    await expect(preflightFreshManagementAccessApplication({
      ...call(app.transport),
      accountId: ACCOUNT_ID,
      plan: PLAN,
    })).resolves.toEqual({ clear: true });
    const domain = sequenced([success([]), success([]), success([])]);
    await expect(preflightFreshManagementCustomDomain({
      ...call(domain.transport),
      ...domainSpec(),
    })).resolves.toEqual({ clear: true });
    expect(domain.requests).toHaveLength(3);
    expect(Object.fromEntries(new URL(domain.requests[0].url).searchParams)).toEqual({
      hostname: MANAGEMENT_HOSTNAME,
      page: '1',
      per_page: '100',
    });
    expect(new URL(domain.requests[1].url).pathname).toBe(`/client/v4/zones/${ZONE_ID}/dns_records`);
    expect(new URL(domain.requests[2].url).pathname).toBe(`/client/v4/zones/${ZONE_ID}/workers/routes`);
  });

  it('requires the persisted app intent, sends it exactly, and returns the exact locator', async () => {
    const spec = applicationSpec();
    const intent = prepareManagementAccessApplicationIntent(spec);
    const provider = recorded(success({ aud: AUD, id: APP_ID, ignored: 'verified later' }));
    await expect(createManagementAccessApplication({
      ...call(provider.transport),
      ...spec,
      intent,
    })).resolves.toEqual({ applicationId: APP_ID, aud: AUD });
    expect(provider.requests[0].method).toBe('POST');
    await expect(provider.requests[0].json()).resolves.toEqual(intent.request);

    let calls = 0;
    const altered = { ...intent, request: { ...intent.request, name: 'altered' } };
    await expect(createManagementAccessApplication({
      ...call(async () => { calls += 1; return success({}); }),
      ...spec,
      intent: altered,
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'invalid_input',
      stage: 'management_app_create',
      outcome: 'not_sent',
    }));
    expect(calls).toBe(0);
  });

  it('accepts the live 201 on Access application create and still treats other statuses as unknown', async () => {
    // Live 2026-08-23: POST /access/apps and POST …/policies answer 201.
    const spec = applicationSpec();
    const intent = prepareManagementAccessApplicationIntent(spec);
    const created = recorded(success({ aud: AUD, id: APP_ID }, undefined, 201));
    await expect(createManagementAccessApplication({
      ...call(created.transport),
      ...spec,
      intent,
    })).resolves.toEqual({ applicationId: APP_ID, aud: AUD });

    const unexpected = recorded(success({ aud: AUD, id: APP_ID }, undefined, 203));
    await expect(createManagementAccessApplication({
      ...call(unexpected.transport),
      ...spec,
      intent,
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'provider_unknown',
      stage: 'management_app_create',
      outcome: 'unknown',
    }));
  });

  it('recovers an outcome-unknown Access app only from one exact paginated match', async () => {
    const spec = applicationSpec();
    const intent = prepareManagementAccessApplicationIntent(spec);
    await expect(createManagementAccessApplication({
      ...call(async () => { throw new Error(`hidden ${ACCESS_TOKEN}`); }),
      ...spec,
      intent,
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'provider_unknown',
      stage: 'management_app_create',
      outcome: 'unknown',
    }));
    const recovered = recorded(success([exactApplication()]));
    await expect(recoverManagementAccessApplication({
      ...call(recovered.transport),
      ...spec,
      intent,
    })).resolves.toEqual({
      schemaVersion: 1,
      kind: 'management_access_application_recovery',
      planId: PLAN.planId,
      planHash: PLAN.planHash,
      ownershipMarker: JOURNAL_MARKER,
      locator: { applicationId: APP_ID, aud: AUD },
    });

    const ambiguous = recorded(success([exactApplication(), exactApplication(OTHER_APP_ID)]));
    await expect(recoverManagementAccessApplication({
      ...call(ambiguous.transport),
      ...spec,
      intent,
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'provider_ambiguous',
      stage: 'management_app_recover',
      outcome: 'rejected',
    }));
  });

  it('creates and outcome-recovers the admin policy from the exact persisted intent', async () => {
    const spec = policySpec();
    const intent = prepareManagementAdminPolicyIntent(spec);
    const create = recorded(success({ id: POLICY_ID, ignored: true }));
    await expect(createManagementAdminAllowPolicy({
      ...call(create.transport),
      ...spec,
      intent,
    })).resolves.toEqual({ policyId: POLICY_ID });
    await expect(create.requests[0].json()).resolves.toEqual(intent.request);

    const recover = recorded(success([exactPolicy()]));
    await expect(recoverManagementAdminAllowPolicy({
      ...call(recover.transport),
      ...spec,
      intent,
    })).resolves.toEqual({
      schemaVersion: 1,
      kind: 'management_admin_policy_recovery',
      planId: PLAN.planId,
      planHash: PLAN.planHash,
      ownershipMarker: JOURNAL_MARKER,
      locator: { policyId: POLICY_ID },
    });
    const foreign = recorded(success([exactPolicy(), exactPolicy(OTHER_POLICY_ID)]));
    await expect(recoverManagementAdminAllowPolicy({
      ...call(foreign.transport),
      ...spec,
      intent,
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'provider_ambiguous',
      stage: 'admin_policy_recover',
      outcome: 'rejected',
    }));
  });

  it('fails closed when recovery has no exact unique resource', async () => {
    const appSpec = applicationSpec();
    const appIntent = prepareManagementAccessApplicationIntent(appSpec);
    await expect(recoverManagementAccessApplication({
      ...call(recorded(success([])).transport),
      ...appSpec,
      intent: appIntent,
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'provider_unknown',
      stage: 'management_app_recover',
      outcome: 'unknown',
    }));
    await expect(recoverManagementAccessApplication({
      ...call(recorded(success([{ ...exactApplication(), name: 'foreign' }])).transport),
      ...appSpec,
      intent: appIntent,
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'provider_mismatch',
      stage: 'management_app_recover',
      outcome: 'rejected',
    }));

    const customSpec = domainSpec();
    await expect(recoverManagementCustomDomain({
      ...call(recorded(success([{ ...exactDomain(), service: 'foreign-worker' }])).transport),
      ...customSpec,
      intent: prepareManagementCustomDomainIntent(customSpec),
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'provider_mismatch',
      stage: 'management_domain_recover',
      outcome: 'rejected',
    }));
  });

  it('rejects altered policy/domain intents without any provider request', async () => {
    let calls = 0;
    const transport: CloudflareManagementTransport = async () => {
      calls += 1;
      return success({});
    };
    const policy = policySpec();
    const policyIntent = prepareManagementAdminPolicyIntent(policy);
    await expect(createManagementAdminAllowPolicy({
      ...call(transport),
      ...policy,
      intent: { ...policyIntent, applicationId: OTHER_APP_ID },
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'invalid_input',
      stage: 'admin_policy_create',
      outcome: 'not_sent',
    }));

    const domain = domainSpec();
    const domainIntent = prepareManagementCustomDomainIntent(domain);
    await expect(attachManagementCustomDomain({
      ...call(transport),
      ...domain,
      intent: { ...domainIntent, zoneId: '9'.repeat(32) },
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'invalid_input',
      stage: 'management_domain_attach',
      outcome: 'not_sent',
    }));
    expect(calls).toBe(0);
  });

  it('verifies exact Access app and policy locators by GET and paginated lists', async () => {
    const appSpec = applicationSpec();
    await expect(verifyManagementAccessApplicationGet({
      ...call(recorded(success(exactApplication())).transport),
      ...appSpec,
      applicationId: APP_ID,
      aud: AUD,
    })).resolves.toEqual({ applicationId: APP_ID, aud: AUD });
    await expect(verifyManagementAccessApplicationList({
      ...call(recorded(success([exactApplication()])).transport),
      ...appSpec,
      applicationId: APP_ID,
      aud: AUD,
    })).resolves.toEqual({ applicationId: APP_ID, aud: AUD });

    const spec = policySpec();
    await expect(verifyManagementAdminAllowPolicyGet({
      ...call(recorded(success(exactPolicy())).transport),
      ...spec,
      policyId: POLICY_ID,
    })).resolves.toEqual({ policyId: POLICY_ID });
    await expect(verifyManagementAdminAllowPolicyList({
      ...call(recorded(success([exactPolicy()])).transport),
      ...spec,
      policyId: POLICY_ID,
    })).resolves.toEqual({ policyId: POLICY_ID });
  });

  it('accepts the live policy shape that omits the false approval/isolation/justification flags and still rejects true', async () => {
    // Live 2026-08-23: the created admin policy carries no approval_required,
    // isolation_required, or purpose_justification_required keys when false.
    const spec = policySpec();
    const { approval_required: _a, isolation_required: _i, purpose_justification_required: _p, ...live } = exactPolicy();
    await expect(verifyManagementAdminAllowPolicyGet({
      ...call(recorded(success({ ...live, uid: POLICY_ID, reusable: false, created_at: 'x', updated_at: 'x' })).transport),
      ...spec,
      policyId: POLICY_ID,
    })).resolves.toEqual({ policyId: POLICY_ID });
    await expect(verifyManagementAdminAllowPolicyGet({
      ...call(recorded(success({ ...live, approval_required: true })).transport),
      ...spec,
      policyId: POLICY_ID,
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'late_drift',
      stage: 'admin_policy_get',
      outcome: 'rejected',
    }));
  });

  it('keeps per-script workers.dev preview URLs false and verifies both states', async () => {
    for (const enabled of [true, false]) {
      const set = recorded(success({ enabled, previews_enabled: false }));
      await expect(setWorkerBootstrapSubdomain({
        ...call(set.transport),
        accountId: ACCOUNT_ID,
        enabled,
        plan: PLAN,
      })).resolves.toEqual({ enabled, previewsEnabled: false });
      const get = recorded(success({ enabled, previews_enabled: false }));
      await expect(verifyWorkerBootstrapSubdomain({
        ...call(get.transport),
        accountId: ACCOUNT_ID,
        expectedEnabled: enabled,
        plan: PLAN,
      })).resolves.toEqual({ enabled, previewsEnabled: false });
    }
  });

  it('checks exact DNS and all Worker routes immediately before custom-domain PUT', async () => {
    const spec = domainSpec();
    const intent = prepareManagementCustomDomainIntent(spec);
    const provider = sequenced([
      success([]),
      success([]),
      success([{ id: ROUTE_ID, pattern: 'other.example.com/*', script: 'other-worker' }]),
      success([]),
      success([{ id: ROUTE_ID, pattern: 'other.example.com/*', script: 'other-worker' }]),
      success([]),
      success({ id: DOMAIN_ID }),
    ]);
    await expect(attachManagementCustomDomain({
      ...call(provider.transport),
      ...spec,
      intent,
    })).resolves.toEqual({ domainId: DOMAIN_ID });
    expect(provider.requests.map((request) => request.method)).toEqual([
      'GET', 'GET', 'GET', 'GET', 'GET', 'GET', 'PUT',
    ]);
    expect(new URL(provider.requests[0].url).pathname).toBe('/client/v4/accounts/' + ACCOUNT_ID + '/workers/domains');
    const dnsUrl = new URL(provider.requests[1].url);
    expect(dnsUrl.pathname).toBe(`/client/v4/zones/${ZONE_ID}/dns_records`);
    expect(dnsUrl.searchParams.get('name.exact')).toBe(MANAGEMENT_HOSTNAME);
    expect(new URL(provider.requests[2].url).pathname).toBe(`/client/v4/zones/${ZONE_ID}/workers/routes`);
    expect(new URL(provider.requests[5].url).pathname).toBe(`/client/v4/zones/${ZONE_ID}/dns_records`);
    await expect(provider.requests[6].json()).resolves.toEqual(intent.request);
  });

  it.each([
    ['DNS collision', success([{ id: DNS_ID, name: MANAGEMENT_HOSTNAME }]), null, 'dns_collision', 'management_domain_dns_collision'],
    ['overlapping exact route', success([]), success([{ id: ROUTE_ID, pattern: `${MANAGEMENT_HOSTNAME}/*`, script: WORKER_NAME }]), 'worker_route_collision', 'management_domain_route_collision'],
    ['overlapping wildcard route', success([]), success([{ id: ROUTE_ID, pattern: `*.${ZONE_NAME}/*`, script: 'other-worker' }]), 'worker_route_collision', 'management_domain_route_collision'],
    ['malformed route', success([]), success([{ id: ROUTE_ID, pattern: 'not a route', script: 'other-worker' }]), 'provider_mismatch', 'management_domain_route_collision'],
  ] as const)('performs no PUT on %s', async (_label, dns, routes, code, stage) => {
    const spec = domainSpec();
    const provider = sequenced(routes === null
      ? [success([]), dns]
      : [success([]), dns, routes]);
    await expect(attachManagementCustomDomain({
      ...call(provider.transport),
      ...spec,
      intent: prepareManagementCustomDomainIntent(spec),
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code,
      stage,
      outcome: 'rejected',
    }));
    expect(provider.requests.every((request) => request.method === 'GET')).toBe(true);
  });

  it('performs no custom-domain PUT when a collision appears during the terminal second proof', async () => {
    const spec = domainSpec();
    const intent = prepareManagementCustomDomainIntent(spec);
    const lateDomain = sequenced([
      success([]),
      success([]),
      success([]),
      success([exactDomain()]),
    ]);
    await expect(attachManagementCustomDomain({
      ...call(lateDomain.transport),
      ...spec,
      intent,
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'fresh_baseline_collision',
      stage: 'management_domain_baseline',
      outcome: 'rejected',
    }));
    expect(lateDomain.requests.every((request) => request.method === 'GET')).toBe(true);

    const lateDns = sequenced([
      success([]),
      success([]),
      success([]),
      success([]),
      success([]),
      success([{ id: DNS_ID, name: MANAGEMENT_HOSTNAME }]),
    ]);
    await expect(attachManagementCustomDomain({
      ...call(lateDns.transport),
      ...spec,
      intent,
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'dns_collision',
      stage: 'management_domain_dns_collision',
      outcome: 'rejected',
    }));
    expect(lateDns.requests.every((request) => request.method === 'GET')).toBe(true);
  });

  it('outcome-recovers a custom domain only from one exact relation', async () => {
    const spec = domainSpec();
    const intent = prepareManagementCustomDomainIntent(spec);
    const recovered = recorded(success([exactDomain()]));
    await expect(recoverManagementCustomDomain({
      ...call(recovered.transport),
      ...spec,
      intent,
    })).resolves.toEqual({
      schemaVersion: 1,
      kind: 'management_custom_domain_recovery',
      planId: PLAN.planId,
      planHash: PLAN.planHash,
      ownershipMarker: JOURNAL_MARKER,
      locator: { domainId: DOMAIN_ID },
    });
    const ambiguous = recorded(success([exactDomain(), exactDomain(OTHER_DOMAIN_ID)]));
    await expect(recoverManagementCustomDomain({
      ...call(ambiguous.transport),
      ...spec,
      intent,
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'provider_ambiguous',
      stage: 'management_domain_recover',
      outcome: 'rejected',
    }));
  });

  it('verifies the exact custom-domain locator by GET and list', async () => {
    const spec = domainSpec();
    await expect(verifyManagementCustomDomainGet({
      ...call(recorded(success(exactDomain())).transport),
      ...spec,
      domainId: DOMAIN_ID,
    })).resolves.toEqual({ domainId: DOMAIN_ID });
    await expect(verifyManagementCustomDomainList({
      ...call(recorded(success([exactDomain()])).transport),
      ...spec,
      domainId: DOMAIN_ID,
    })).resolves.toEqual({ domainId: DOMAIN_ID });
  });

  it('keeps unknown mutation outcomes body-free and never retries them', async () => {
    const spec = applicationSpec();
    let calls = 0;
    await expect(createManagementAccessApplication({
      ...call(async () => {
        calls += 1;
        return failure(502, `never expose ${ACCESS_TOKEN}`);
      }),
      ...spec,
      intent: prepareManagementAccessApplicationIntent(spec),
    })).rejects.toSatisfy((error: unknown) => expectManagementError(error, {
      code: 'provider_unknown',
      stage: 'management_app_create',
      outcome: 'unknown',
    }));
    expect(calls).toBe(1);
  });
});
