import { CLOUDFLARE_API_ORIGIN } from './constants';
import { parseStaticDeployPlan, type StaticDeployPlan } from './schema';

const ACCOUNT_ID_PATTERN = /^[a-f0-9]{32}$/u;
const ZONE_ID_PATTERN = ACCOUNT_ID_PATTERN;
const PLAN_HASH_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const WORKER_NAME_PATTERN = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const PROVIDER_ID_PATTERN = /^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$/u;
const ACCESS_AUD_PATTERN = /^[A-Za-z0-9._~-]{16,512}$/u;
const ACCESS_TOKEN_PATTERN = /^[A-Za-z0-9._~-]{20,8192}$/u;
const DNS_LABEL_PATTERN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$/u;
const EMAIL_PATTERN = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/u;

const MAX_RESPONSE_BYTES = 128 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const LIST_PAGE_SIZE = 100;
const IDP_PAGE_SIZE = 1_000;
const MAX_LIST_PAGES = 20;
const MAX_LIST_ITEMS = 2_000;
const ACCESS_SESSION_DURATION = '24h';
const OWNERSHIP_PREFIX = 'ankka-mcp-gateway';

const IDENTITY_PROVIDER_TYPES = new Set([
  'azureAD',
  'centrify',
  'cloudflare',
  'facebook',
  'github',
  'google',
  'google-apps',
  'linkedin',
  'oidc',
  'okta',
  'onelogin',
  'onetimepin',
  'pingone',
  'saml',
  'yandex',
]);

export type CloudflareManagementStage =
  | 'zero_trust_organization_get'
  | 'identity_provider_list'
  | 'account_worker_subdomain_get'
  | 'management_app_baseline'
  | 'management_app_create'
  | 'management_app_get'
  | 'management_app_list_verify'
  | 'management_app_recover'
  | 'admin_policy_create'
  | 'admin_policy_get'
  | 'admin_policy_list_verify'
  | 'admin_policy_recover'
  | 'worker_subdomain_set'
  | 'worker_subdomain_get'
  | 'management_domain_baseline'
  | 'management_domain_dns_collision'
  | 'management_domain_route_collision'
  | 'management_domain_attach'
  | 'management_domain_get'
  | 'management_domain_list_verify'
  | 'management_domain_recover';

export type CloudflareManagementOutcome = 'not_sent' | 'rejected' | 'unknown';

export type CloudflareManagementErrorCode =
  | 'invalid_input'
  | 'provider_rejected'
  | 'provider_unknown'
  | 'provider_mismatch'
  | 'provider_ambiguous'
  | 'fresh_baseline_collision'
  | 'identity_provider_unavailable'
  | 'dns_collision'
  | 'worker_route_collision'
  | 'foreign_policy'
  | 'late_drift';

/**
 * Stable, body-free error information. Provider response bodies, token values,
 * and transport exceptions are deliberately never exposed or retained.
 */
export class CloudflareManagementError extends Error {
  readonly code: CloudflareManagementErrorCode;
  readonly stage: CloudflareManagementStage;
  readonly outcome: CloudflareManagementOutcome;
  readonly canRetry: false;

  constructor(
    code: CloudflareManagementErrorCode,
    stage: CloudflareManagementStage,
    outcome: CloudflareManagementOutcome,
  ) {
    super(code);
    this.name = 'CloudflareManagementError';
    this.code = code;
    this.stage = stage;
    this.outcome = outcome;
    this.canRetry = false;
  }
}

export type CloudflareManagementTransport = (request: Request) => Promise<Response>;

export interface CloudflareManagementCall {
  readonly accessToken: string;
  readonly transport: CloudflareManagementTransport;
  readonly timeoutMs?: number;
}

export interface ZeroTrustOrganization {
  readonly name: string;
  readonly authDomain: string;
  readonly issuer: string;
}

export interface AccessIdentityProvider {
  readonly id: string;
  readonly name: string;
  readonly type: string;
  readonly readOnly: boolean;
}

export interface ManagementAccessApplicationLocator {
  readonly applicationId: string;
  readonly aud: string;
}

export interface ManagementAdminPolicyLocator {
  readonly policyId: string;
}

export interface WorkerSubdomainState {
  readonly enabled: boolean;
  readonly previewsEnabled: false;
}

export interface AccountWorkersSubdomain {
  readonly accountId: string;
  readonly subdomain: string;
}

export interface ManagementCustomDomainLocator {
  readonly domainId: string;
}

export interface ManagementAccessApplicationSpec {
  readonly accountId: string;
  readonly plan: StaticDeployPlan;
  readonly allowedIdentityProviderIds: readonly string[];
}

export interface ManagementAdminPolicySpec {
  readonly accountId: string;
  readonly applicationId: string;
  readonly plan: StaticDeployPlan;
}

export interface ManagementCustomDomainSpec {
  readonly accountId: string;
  readonly zoneId: string;
  readonly plan: StaticDeployPlan;
}

export interface ManagementAccessApplicationRequestSpec {
  readonly allow_authenticate_via_warp: false;
  readonly allowed_idps: readonly string[];
  readonly app_launcher_visible: false;
  readonly auto_redirect_to_identity: false;
  readonly domain: string;
  readonly name: string;
  readonly session_duration: '24h';
  readonly type: 'self_hosted';
}

export interface ManagementAdminPolicyRequestSpec {
  readonly approval_required: false;
  readonly decision: 'allow';
  readonly exclude: readonly [];
  readonly include: readonly { readonly email: { readonly email: string } }[];
  readonly isolation_required: false;
  readonly name: string;
  readonly precedence: 1;
  readonly purpose_justification_required: false;
  readonly require: readonly [];
}

export interface ManagementCustomDomainRequestSpec {
  readonly hostname: string;
  readonly service: string;
  readonly zone_id: string;
  readonly zone_name: string;
}

export interface ManagementAccessApplicationIntent {
  readonly schemaVersion: 1;
  readonly kind: 'management_access_application';
  readonly planId: string;
  readonly planHash: string;
  readonly ownershipMarker: string;
  readonly accountId: string;
  readonly request: ManagementAccessApplicationRequestSpec;
}

export interface ManagementAdminPolicyIntent {
  readonly schemaVersion: 1;
  readonly kind: 'management_admin_policy';
  readonly planId: string;
  readonly planHash: string;
  readonly ownershipMarker: string;
  readonly accountId: string;
  readonly applicationId: string;
  readonly request: ManagementAdminPolicyRequestSpec;
}

export interface ManagementCustomDomainIntent {
  readonly schemaVersion: 1;
  readonly kind: 'management_custom_domain';
  readonly planId: string;
  readonly planHash: string;
  readonly ownershipMarker: string;
  readonly accountId: string;
  readonly zoneId: string;
  readonly request: ManagementCustomDomainRequestSpec;
}

export interface ManagementAccessApplicationRecoveryRecord {
  readonly schemaVersion: 1;
  readonly kind: 'management_access_application_recovery';
  readonly planId: string;
  readonly planHash: string;
  readonly ownershipMarker: string;
  readonly locator: ManagementAccessApplicationLocator;
}

export interface ManagementAdminPolicyRecoveryRecord {
  readonly schemaVersion: 1;
  readonly kind: 'management_admin_policy_recovery';
  readonly planId: string;
  readonly planHash: string;
  readonly ownershipMarker: string;
  readonly locator: ManagementAdminPolicyLocator;
}

export interface ManagementCustomDomainRecoveryRecord {
  readonly schemaVersion: 1;
  readonly kind: 'management_custom_domain_recovery';
  readonly planId: string;
  readonly planHash: string;
  readonly ownershipMarker: string;
  readonly locator: ManagementCustomDomainLocator;
}

interface CloudflareEnvelope {
  readonly errors: null | readonly unknown[];
  readonly messages: null | readonly unknown[];
  readonly result: unknown;
  readonly success: boolean;
  readonly resultInfo?: unknown;
}

interface ProviderResponse {
  readonly status: number;
  readonly value: unknown;
}

interface ExpectedApplication {
  readonly accountId: string;
  readonly planId: string;
  readonly planHash: string;
  readonly applicationId: string;
  readonly aud: string;
  readonly domain: string;
  readonly name: string;
  readonly allowedIdentityProviderIds: readonly string[];
}

interface ExpectedPolicy {
  readonly accountId: string;
  readonly planId: string;
  readonly planHash: string;
  readonly applicationId: string;
  readonly policyId: string;
  readonly name: string;
  readonly adminEmails: readonly string[];
}

interface ExpectedDomain {
  readonly accountId: string;
  readonly planId: string;
  readonly planHash: string;
  readonly domainId: string;
  readonly hostname: string;
  readonly service: string;
  readonly zoneId: string;
  readonly zoneName: string;
}

function fail(
  code: CloudflareManagementErrorCode,
  stage: CloudflareManagementStage,
  outcome: CloudflareManagementOutcome,
): never {
  throw new CloudflareManagementError(code, stage, outcome);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function stableJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError('json');
}

function exactJson(left: unknown, right: unknown): boolean {
  try {
    return stableJson(left) === stableJson(right);
  } catch {
    return false;
  }
}

function isEmptyProviderList(value: unknown): value is null | readonly [] {
  return value === null || (Array.isArray(value) && value.length === 0);
}

function validProviderErrorList(value: unknown): boolean {
  if (!Array.isArray(value) || value.length === 0 || value.length > 16) return false;
  return value.every((entry) => {
    if (!isRecord(entry)) return false;
    const allowed = new Set(['code', 'documentation_url', 'message', 'source']);
    if (Object.keys(entry).some((key) => !allowed.has(key))) return false;
    return typeof entry.code === 'number' && Number.isSafeInteger(entry.code) &&
      typeof entry.message === 'string' && entry.message.length > 0 && entry.message.length <= 2_048;
  });
}

function parseEnvelope(value: unknown): CloudflareEnvelope | null {
  if (!isRecord(value)) return null;
  const allowed = new Set(['errors', 'messages', 'result', 'result_info', 'success']);
  if (
    Object.keys(value).some((key) => !allowed.has(key)) ||
    !Object.hasOwn(value, 'errors') ||
    !Object.hasOwn(value, 'messages') ||
    !Object.hasOwn(value, 'result') ||
    !Object.hasOwn(value, 'success') ||
    typeof value.success !== 'boolean' ||
    !(value.errors === null || Array.isArray(value.errors)) ||
    !(value.messages === null || Array.isArray(value.messages))
  ) return null;
  return {
    errors: value.errors,
    messages: value.messages,
    result: value.result,
    success: value.success,
    ...(Object.hasOwn(value, 'result_info') ? { resultInfo: value.result_info } : {}),
  };
}

function parseSuccessEnvelope(value: unknown): CloudflareEnvelope | null {
  const envelope = parseEnvelope(value);
  if (
    !envelope ||
    envelope.success !== true ||
    !isEmptyProviderList(envelope.errors) ||
    !isEmptyProviderList(envelope.messages)
  ) return null;
  return envelope;
}

interface ParsedListPage {
  readonly values: readonly unknown[];
  readonly page: number | null;
  readonly perPage: number | null;
  readonly totalCount: number | null;
  readonly totalPages: number | null;
}

function optionalPositiveInteger(value: unknown): number | null | undefined {
  if (value === undefined) return null;
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0
    ? value
    : undefined;
}

function optionalNonnegativeInteger(value: unknown): number | null | undefined {
  if (value === undefined) return null;
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
    ? value
    : undefined;
}

function parseListPage(envelope: CloudflareEnvelope, requestedPage: number): ParsedListPage | null {
  if (!Array.isArray(envelope.result)) return null;
  if (envelope.resultInfo === undefined) {
    return { values: envelope.result, page: null, perPage: null, totalCount: null, totalPages: null };
  }
  if (!isRecord(envelope.resultInfo)) return null;
  const info = envelope.resultInfo;
  const page = optionalPositiveInteger(info.page);
  const perPage = optionalPositiveInteger(info.per_page);
  const count = optionalNonnegativeInteger(info.count);
  const totalCount = optionalNonnegativeInteger(info.total_count);
  const totalPages = optionalNonnegativeInteger(info.total_pages);
  if (
    page === undefined ||
    perPage === undefined ||
    count === undefined ||
    totalCount === undefined ||
    totalPages === undefined ||
    (page !== null && page !== requestedPage) ||
    (count !== null && count !== envelope.result.length)
  ) return null;
  return { values: envelope.result, page, perPage, totalCount, totalPages };
}

function providerId(value: unknown): value is string {
  return typeof value === 'string' && PROVIDER_ID_PATTERN.test(value);
}

/**
 * Worker custom-domain ids are 40 lowercase hex characters, unlike every other
 * provider id in this surface (live 2026-08-23). Kept separate so the exact
 * 32-hex/UUID identity check still applies everywhere else.
 */
function customDomainId(value: unknown): value is string {
  return typeof value === 'string' && (PROVIDER_ID_PATTERN.test(value) || /^[a-f0-9]{40}$/u.test(value));
}

function accessAud(value: unknown): value is string {
  return typeof value === 'string' && ACCESS_AUD_PATTERN.test(value);
}

function validHostname(value: unknown): value is string {
  if (typeof value !== 'string' || value.length < 3 || value.length > 253 || value !== value.toLowerCase()) return false;
  const labels = value.split('.');
  return labels.length >= 2 && labels.every((label) => DNS_LABEL_PATTERN.test(label));
}

function validZoneRelation(hostname: string, zoneName: string): boolean {
  return validHostname(hostname) && validHostname(zoneName) && hostname !== zoneName && hostname.endsWith(`.${zoneName}`);
}

function validToken(value: unknown): value is string {
  return typeof value === 'string' && ACCESS_TOKEN_PATTERN.test(value);
}

function canonicalStrings(values: readonly string[]): readonly string[] | null {
  if (!Array.isArray(values) || values.length === 0 || values.length > 64) return null;
  const normalized = [...values];
  if (!normalized.every(providerId)) return null;
  normalized.sort();
  if (normalized.some((value, index) => index > 0 && value === normalized[index - 1])) return null;
  return Object.freeze(normalized);
}

function canonicalEmails(values: readonly string[]): readonly string[] | null {
  if (!Array.isArray(values) || values.length === 0 || values.length > 64) return null;
  const normalized = values.map((value) => typeof value === 'string' ? value.trim().toLowerCase() : '');
  if (normalized.some((value) => value.length > 254 || !EMAIL_PATTERN.test(value))) return null;
  normalized.sort();
  const unique = normalized.filter((value, index) => index === 0 || value !== normalized[index - 1]);
  return Object.freeze(unique);
}

function validatedTimeout(value: number | undefined): number | null {
  const timeout = value ?? DEFAULT_TIMEOUT_MS;
  return Number.isSafeInteger(timeout) && timeout >= 100 && timeout <= 60_000 ? timeout : null;
}

function commonInput(
  input: CloudflareManagementCall,
  stage: CloudflareManagementStage,
): { accessToken: string; transport: CloudflareManagementTransport; timeoutMs: number } {
  if (!isRecord(input) || !validToken(input.accessToken) || typeof input.transport !== 'function') {
    return fail('invalid_input', stage, 'not_sent');
  }
  const timeoutMs = validatedTimeout(input.timeoutMs);
  if (timeoutMs === null) return fail('invalid_input', stage, 'not_sent');
  return { accessToken: input.accessToken, transport: input.transport, timeoutMs };
}

function authHeaders(accessToken: string): Headers {
  return new Headers({ accept: 'application/json', authorization: `Bearer ${accessToken}` });
}

function jsonHeaders(accessToken: string): Headers {
  const headers = authHeaders(accessToken);
  headers.set('content-type', 'application/json');
  return headers;
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null) {
    const declared = Number(declaredLength);
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > MAX_RESPONSE_BYTES) {
      throw new TypeError('response');
    }
  }
  const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
  if (!contentType.startsWith('application/json') || !response.body) throw new TypeError('response');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new TypeError('response');
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return JSON.parse(text) as unknown;
  } catch {
    throw new TypeError('response');
  }
}

async function performRequest(
  call: ReturnType<typeof commonInput>,
  stage: CloudflareManagementStage,
  url: URL,
  init: RequestInit,
): Promise<ProviderResponse> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    // workerd rejects `redirect: 'error'` at construction; redirects are
    // rejected explicitly by status instead.
    const request = new Request(url, { ...init, redirect: 'manual', signal: controller.signal });
    const operation = (async () => {
      const response = await call.transport(request);
      if (response.redirected || response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
        throw new TypeError('redirect');
      }
      return { status: response.status, value: await readBoundedJson(response) };
    })();
    const deadline = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new TypeError('timeout'));
      }, call.timeoutMs);
    });
    return await Promise.race([operation, deadline]);
  } catch (error) {
    if (error instanceof CloudflareManagementError) throw error;
    return fail('provider_unknown', stage, 'unknown');
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    controller.abort();
  }
}

// Live Cloudflare contract (2026-08-23): Access application and policy
// creates answer 201; reads answer 200. A create site passes CREATED_STATUSES.
const CREATED_STATUSES: readonly number[] = Object.freeze([200, 201]);

function requireSuccess(
  response: ProviderResponse,
  stage: CloudflareManagementStage,
  expectedStatuses: readonly number[] = [200],
): CloudflareEnvelope {
  const success = parseSuccessEnvelope(response.value);
  if (expectedStatuses.includes(response.status) && success) return success;
  const envelope = parseEnvelope(response.value);
  if (
    response.status >= 400 &&
    response.status < 500 &&
    envelope?.success === false &&
    validProviderErrorList(envelope.errors) &&
    isEmptyProviderList(envelope.messages) &&
    envelope.result === null
  ) return fail('provider_rejected', stage, 'rejected');
  return fail('provider_unknown', stage, 'unknown');
}

function accountUrl(accountId: string, path: string): URL {
  return new URL(`/client/v4/accounts/${accountId}${path}`, CLOUDFLARE_API_ORIGIN);
}

function zoneUrl(zoneId: string, path: string): URL {
  return new URL(`/client/v4/zones/${zoneId}${path}`, CLOUDFLARE_API_ORIGIN);
}

async function collectPaginated(
  call: ReturnType<typeof commonInput>,
  stage: CloudflareManagementStage,
  perPage: number,
  urlForPage: (page: number, perPage: number) => URL,
  totalCountMatchesQuery = false,
): Promise<readonly unknown[]> {
  const values: unknown[] = [];
  let totalCount: number | null = null;
  let totalPages: number | null = null;
  for (let pageNumber = 1; pageNumber <= MAX_LIST_PAGES; pageNumber += 1) {
    const response = await performRequest(call, stage, urlForPage(pageNumber, perPage), {
      method: 'GET',
      headers: authHeaders(call.accessToken),
    });
    const page = parseListPage(requireSuccess(response, stage), pageNumber);
    if (!page) fail('provider_unknown', stage, 'unknown');
    if (page.perPage !== null && page.perPage > perPage) fail('provider_unknown', stage, 'unknown');
    // Cloudflare documents `total_count` as the count available without
    // search parameters on several filtered list APIs. It is therefore usable
    // for pagination only on endpoints where this call applies no filter.
    if (totalCountMatchesQuery && page.totalCount !== null) {
      if (page.totalCount > MAX_LIST_ITEMS) fail('provider_unknown', stage, 'unknown');
      if (totalCount !== null && page.totalCount !== totalCount) fail('provider_unknown', stage, 'unknown');
      totalCount = page.totalCount;
    }
    if (page.totalPages !== null) {
      if (
        page.totalPages > MAX_LIST_PAGES ||
        (totalPages !== null && page.totalPages !== totalPages)
      ) fail('provider_unknown', stage, 'unknown');
      totalPages = page.totalPages;
    }
    values.push(...page.values);
    if (values.length > MAX_LIST_ITEMS) fail('provider_unknown', stage, 'unknown');
    if (totalCount !== null && values.length > totalCount) fail('provider_unknown', stage, 'unknown');
    const effectivePerPage = page.perPage ?? perPage;
    if (page.values.length > effectivePerPage) fail('provider_unknown', stage, 'unknown');
    if (totalPages === 0 && values.length !== 0) fail('provider_unknown', stage, 'unknown');

    const reachedTotal = totalCount !== null && values.length === totalCount;
    const reachedPages = totalPages !== null && pageNumber >= totalPages;
    if (reachedTotal || reachedPages) {
      if (reachedTotal && totalPages !== null && pageNumber < totalPages) {
        fail('provider_unknown', stage, 'unknown');
      }
      if (totalCount !== null && values.length !== totalCount) fail('provider_unknown', stage, 'unknown');
      return Object.freeze(values);
    }
    if (page.values.length === 0) {
      if (totalCount === null && totalPages === null) return Object.freeze(values);
      fail('provider_unknown', stage, 'unknown');
    }
    if (totalCount === null && totalPages === null && page.values.length < effectivePerPage) {
      return Object.freeze(values);
    }
  }
  return fail('provider_unknown', stage, 'unknown');
}

interface ReviewedManagementProjection {
  readonly planId: string;
  readonly planHash: string;
  readonly gatewayName: string;
  readonly zoneName: string;
  readonly managementHostname: string;
  readonly ownershipMarker: string;
  readonly workerName: string;
  readonly applicationName: string;
  readonly policyName: string;
  readonly adminEmails: readonly string[];
}

function reviewedManagementProjection(
  plan: StaticDeployPlan,
  stage: CloudflareManagementStage,
): ReviewedManagementProjection {
  let parsed: StaticDeployPlan;
  try {
    parsed = parseStaticDeployPlan(plan);
  } catch {
    return fail('invalid_input', stage, 'not_sent');
  }
  if (!PLAN_HASH_PATTERN.test(parsed.planHash)) fail('invalid_input', stage, 'not_sent');
  const worker = parsed.managementResources.find((resource) => resource.kind === 'management_worker');
  const app = parsed.managementResources.find((resource) => resource.kind === 'management_access_application');
  const policy = parsed.managementResources.find((resource) => resource.kind === 'management_access_policy');
  const slug = parsed.gatewayConfiguration.gatewayName
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, '-')
    .replace(/^-+|-+$/gu, '')
    .slice(0, 20)
    .replace(/-$/u, '');
  const ownershipMarker = parsed.managementOwnershipMarker;
  const expectedWorkerName = `ankka-gateway-${slug}-${ownershipMarker}`;
  const expectedApplicationName = `${parsed.gatewayConfiguration.gatewayName} management [${ownershipMarker}]`;
  const expectedPolicyName = `${parsed.gatewayConfiguration.gatewayName} administrators [${ownershipMarker}]`;
  if (
    !worker || worker.key !== 'management-worker' || worker.name !== expectedWorkerName ||
    worker.hostname !== parsed.gatewayConfiguration.managementHostname ||
    !app || app.key !== 'management-access-app' || app.name !== expectedApplicationName ||
    app.hostname !== parsed.gatewayConfiguration.managementHostname ||
    !policy || policy.key !== 'management-access-policy' || policy.name !== expectedPolicyName ||
    policy.hostname !== parsed.gatewayConfiguration.managementHostname
  ) fail('invalid_input', stage, 'not_sent');
  return Object.freeze({
    planId: parsed.planId,
    planHash: parsed.planHash,
    gatewayName: parsed.gatewayConfiguration.gatewayName,
    zoneName: parsed.gatewayConfiguration.zoneName,
    managementHostname: parsed.gatewayConfiguration.managementHostname,
    ownershipMarker,
    workerName: worker.name,
    applicationName: app.name,
    policyName: policy.name,
    adminEmails: parsed.managementAdminEmails,
  });
}

export function managementOwnershipMarker(plan: StaticDeployPlan): string {
  const projection = reviewedManagementProjection(plan, 'management_app_create');
  if (!PLAN_HASH_PATTERN.test(projection.planHash)) {
    throw new CloudflareManagementError('invalid_input', 'management_app_create', 'not_sent');
  }
  return `${OWNERSHIP_PREFIX}:${projection.ownershipMarker}`;
}

export function managementAccessApplicationName(plan: StaticDeployPlan): string {
  return reviewedManagementProjection(plan, 'management_app_create').applicationName;
}

export function managementAdminPolicyName(plan: StaticDeployPlan): string {
  return reviewedManagementProjection(plan, 'admin_policy_create').policyName;
}

export async function getZeroTrustOrganization(
  input: CloudflareManagementCall & { readonly accountId: string },
): Promise<ZeroTrustOrganization> {
  const stage = 'zero_trust_organization_get';
  const call = commonInput(input, stage);
  if (!ACCOUNT_ID_PATTERN.test(input.accountId)) fail('invalid_input', stage, 'not_sent');
  const response = await performRequest(
    call,
    stage,
    accountUrl(input.accountId, '/access/organizations'),
    { method: 'GET', headers: authHeaders(call.accessToken) },
  );
  const result = requireSuccess(response, stage).result;
  if (!isRecord(result)) fail('provider_mismatch', stage, 'rejected');
  const authDomain = result.auth_domain;
  const name = result.name;
  if (
    typeof name !== 'string' ||
    name.length === 0 ||
    name.length > 256 ||
    !validHostname(authDomain) ||
    !authDomain.endsWith('.cloudflareaccess.com') ||
    authDomain === 'cloudflareaccess.com'
  ) fail('provider_mismatch', stage, 'rejected');
  return Object.freeze({ name, authDomain, issuer: `https://${authDomain}` });
}

export async function listAccessIdentityProviders(
  input: CloudflareManagementCall & { readonly accountId: string },
): Promise<readonly AccessIdentityProvider[]> {
  const stage = 'identity_provider_list';
  const call = commonInput(input, stage);
  if (!ACCOUNT_ID_PATTERN.test(input.accountId)) fail('invalid_input', stage, 'not_sent');
  const values = await collectPaginated(call, stage, IDP_PAGE_SIZE, (page, perPage) => {
    const url = accountUrl(input.accountId, '/access/identity_providers');
    url.searchParams.set('page', String(page));
    url.searchParams.set('per_page', String(perPage));
    return url;
  }, true);
  if (values.length === 0) fail('identity_provider_unavailable', stage, 'rejected');
  const seen = new Set<string>();
  const providers: AccessIdentityProvider[] = [];
  for (const value of values) {
    if (!isRecord(value)) fail('provider_mismatch', stage, 'rejected');
    const { id, name, type } = value;
    const readOnly = value.read_only ?? false;
    // The account-default Cloudflare identity provider (type "cloudflare") is
    // listed with an empty name (observed live 2026-08-23); every other type
    // carries one. An empty name is therefore accepted for that type only.
    if (
      !providerId(id) ||
      seen.has(id) ||
      typeof name !== 'string' ||
      (name.length === 0 && type !== 'cloudflare') ||
      name.length > 256 ||
      typeof type !== 'string' ||
      !IDENTITY_PROVIDER_TYPES.has(type) ||
      typeof readOnly !== 'boolean'
    ) fail(seen.has(String(id)) ? 'provider_ambiguous' : 'provider_mismatch', stage, 'rejected');
    seen.add(id);
    providers.push(Object.freeze({ id, name, type, readOnly }));
  }
  providers.sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0);
  return Object.freeze(providers);
}

export async function getAccountWorkersSubdomain(
  input: CloudflareManagementCall & { readonly accountId: string },
): Promise<AccountWorkersSubdomain> {
  const stage = 'account_worker_subdomain_get';
  const call = commonInput(input, stage);
  if (!ACCOUNT_ID_PATTERN.test(input.accountId)) fail('invalid_input', stage, 'not_sent');
  const response = await performRequest(
    call,
    stage,
    accountUrl(input.accountId, '/workers/subdomain'),
    { method: 'GET', headers: authHeaders(call.accessToken) },
  );
  const result = requireSuccess(response, stage).result;
  if (
    !isRecord(result) ||
    !exactKeys(result, ['subdomain']) ||
    typeof result.subdomain !== 'string' ||
    !DNS_LABEL_PATTERN.test(result.subdomain) ||
    result.subdomain.length > 63
  ) fail('provider_mismatch', stage, 'rejected');
  return Object.freeze({ accountId: input.accountId, subdomain: result.subdomain });
}

function validateApplicationSpec(
  input: ManagementAccessApplicationSpec,
  stage: CloudflareManagementStage,
): Omit<ExpectedApplication, 'applicationId' | 'aud'> {
  if (!ACCOUNT_ID_PATTERN.test(input.accountId)) fail('invalid_input', stage, 'not_sent');
  const plan = reviewedManagementProjection(input.plan, stage);
  if (!validZoneRelation(plan.managementHostname, plan.zoneName)) fail('invalid_input', stage, 'not_sent');
  const allowedIdentityProviderIds = canonicalStrings(input.allowedIdentityProviderIds);
  if (!allowedIdentityProviderIds || !exactJson(allowedIdentityProviderIds, input.allowedIdentityProviderIds)) {
    fail('invalid_input', stage, 'not_sent');
  }
  return {
    accountId: input.accountId,
    planId: plan.planId,
    planHash: plan.planHash,
    domain: plan.managementHostname,
    name: plan.applicationName,
    allowedIdentityProviderIds,
  };
}

function applicationsListUrl(accountId: string, hostname: string, page: number, perPage: number): URL {
  const url = accountUrl(accountId, '/access/apps');
  url.searchParams.set('domain', hostname);
  url.searchParams.set('page', String(page));
  url.searchParams.set('per_page', String(perPage));
  return url;
}

function exactApplication(value: unknown, expected: ExpectedApplication): boolean {
  if (!isRecord(value)) return false;
  if (
    value.id !== expected.applicationId ||
    value.aud !== expected.aud ||
    value.name !== expected.name ||
    value.type !== 'self_hosted' ||
    value.domain !== expected.domain ||
    value.session_duration !== ACCESS_SESSION_DURATION ||
    value.app_launcher_visible !== false ||
    value.auto_redirect_to_identity !== false ||
    value.allow_authenticate_via_warp !== false ||
    !Array.isArray(value.allowed_idps)
  ) return false;
  const ids = canonicalStrings(value.allowed_idps as string[]);
  return Boolean(
    ids &&
    ids.length === expected.allowedIdentityProviderIds.length &&
    ids.every((id, index) => id === expected.allowedIdentityProviderIds[index]),
  );
}

export async function preflightFreshManagementAccessApplication(
  input: CloudflareManagementCall & {
    readonly accountId: string;
    readonly plan: StaticDeployPlan;
  },
): Promise<{ readonly clear: true }> {
  const stage = 'management_app_baseline';
  const call = commonInput(input, stage);
  if (!ACCOUNT_ID_PATTERN.test(input.accountId)) fail('invalid_input', stage, 'not_sent');
  const plan = reviewedManagementProjection(input.plan, stage);
  if (!validZoneRelation(plan.managementHostname, plan.zoneName)) fail('invalid_input', stage, 'not_sent');
  const values = await collectPaginated(call, stage, LIST_PAGE_SIZE, (page, perPage) =>
    applicationsListUrl(input.accountId, plan.managementHostname, page, perPage));
  if (values.length > 1) fail('provider_ambiguous', stage, 'rejected');
  if (values.length === 1) {
    const value = values[0];
    if (!isRecord(value) || value.domain !== plan.managementHostname || !providerId(value.id)) {
      fail('provider_mismatch', stage, 'rejected');
    }
    fail('fresh_baseline_collision', stage, 'rejected');
  }
  return Object.freeze({ clear: true });
}

function applicationBody(
  expected: Omit<ExpectedApplication, 'applicationId' | 'aud'>,
): ManagementAccessApplicationRequestSpec {
  return Object.freeze({
    allow_authenticate_via_warp: false,
    allowed_idps: expected.allowedIdentityProviderIds,
    app_launcher_visible: false,
    auto_redirect_to_identity: false,
    domain: expected.domain,
    name: expected.name,
    session_duration: ACCESS_SESSION_DURATION,
    type: 'self_hosted',
  });
}

export function prepareManagementAccessApplicationIntent(
  input: ManagementAccessApplicationSpec,
): ManagementAccessApplicationIntent {
  const expected = validateApplicationSpec(input, 'management_app_create');
  return Object.freeze({
    schemaVersion: 1,
    kind: 'management_access_application',
    planId: expected.planId,
    planHash: expected.planHash,
    ownershipMarker: managementOwnershipMarker(input.plan),
    accountId: expected.accountId,
    request: applicationBody(expected),
  });
}

function requireApplicationIntent(
  input: ManagementAccessApplicationSpec & { readonly intent: ManagementAccessApplicationIntent },
  stage: CloudflareManagementStage,
): {
  readonly expected: Omit<ExpectedApplication, 'applicationId' | 'aud'>;
  readonly intent: ManagementAccessApplicationIntent;
} {
  const expected = validateApplicationSpec(input, stage);
  const canonical = prepareManagementAccessApplicationIntent(input);
  if (!isRecord(input.intent) || !exactJson(input.intent, canonical)) fail('invalid_input', stage, 'not_sent');
  return { expected, intent: canonical };
}

export async function createManagementAccessApplication(
  input: CloudflareManagementCall & ManagementAccessApplicationSpec & {
    readonly intent: ManagementAccessApplicationIntent;
  },
): Promise<ManagementAccessApplicationLocator> {
  const stage = 'management_app_create';
  const call = commonInput(input, stage);
  const { intent } = requireApplicationIntent(input, stage);
  const response = await performRequest(call, stage, accountUrl(input.accountId, '/access/apps'), {
    method: 'POST',
    headers: jsonHeaders(call.accessToken),
    body: JSON.stringify(intent.request),
  });
  const result = requireSuccess(response, stage, CREATED_STATUSES).result;
  if (!isRecord(result) || !providerId(result.id) || !accessAud(result.aud)) {
    fail('provider_unknown', stage, 'unknown');
  }
  return Object.freeze({ applicationId: result.id, aud: result.aud });
}

function expectedApplication(
  input: ManagementAccessApplicationSpec & ManagementAccessApplicationLocator,
  stage: CloudflareManagementStage,
): ExpectedApplication {
  const expected = validateApplicationSpec(input, stage);
  if (!providerId(input.applicationId) || !accessAud(input.aud)) fail('invalid_input', stage, 'not_sent');
  return { ...expected, applicationId: input.applicationId, aud: input.aud };
}

export async function verifyManagementAccessApplicationGet(
  input: CloudflareManagementCall & ManagementAccessApplicationSpec & ManagementAccessApplicationLocator,
): Promise<ManagementAccessApplicationLocator> {
  const stage = 'management_app_get';
  const call = commonInput(input, stage);
  const expected = expectedApplication(input, stage);
  const response = await performRequest(
    call,
    stage,
    accountUrl(input.accountId, `/access/apps/${encodeURIComponent(input.applicationId)}`),
    { method: 'GET', headers: authHeaders(call.accessToken) },
  );
  const result = requireSuccess(response, stage).result;
  if (!exactApplication(result, expected)) fail('late_drift', stage, 'rejected');
  return Object.freeze({ applicationId: expected.applicationId, aud: expected.aud });
}

export async function verifyManagementAccessApplicationList(
  input: CloudflareManagementCall & ManagementAccessApplicationSpec & ManagementAccessApplicationLocator,
): Promise<ManagementAccessApplicationLocator> {
  const stage = 'management_app_list_verify';
  const call = commonInput(input, stage);
  const expected = expectedApplication(input, stage);
  const values = await collectPaginated(call, stage, LIST_PAGE_SIZE, (page, perPage) =>
    applicationsListUrl(input.accountId, expected.domain, page, perPage));
  if (values.length > 1) fail('provider_ambiguous', stage, 'rejected');
  if (values.length !== 1 || !exactApplication(values[0], expected)) {
    fail('late_drift', stage, 'rejected');
  }
  return Object.freeze({ applicationId: expected.applicationId, aud: expected.aud });
}

export async function recoverManagementAccessApplication(
  input: CloudflareManagementCall & ManagementAccessApplicationSpec & {
    readonly intent: ManagementAccessApplicationIntent;
  },
): Promise<ManagementAccessApplicationRecoveryRecord> {
  const stage = 'management_app_recover';
  const call = commonInput(input, stage);
  const { expected } = requireApplicationIntent(input, stage);
  const values = await collectPaginated(call, stage, LIST_PAGE_SIZE, (page, perPage) =>
    applicationsListUrl(input.accountId, expected.domain, page, perPage));
  const matches: ManagementAccessApplicationLocator[] = [];
  for (const value of values) {
    if (!isRecord(value) || !providerId(value.id) || !accessAud(value.aud)) {
      fail('provider_mismatch', stage, 'rejected');
    }
    const candidate = { ...expected, applicationId: value.id, aud: value.aud };
    if (exactApplication(value, candidate)) {
      matches.push(Object.freeze({ applicationId: value.id, aud: value.aud }));
    }
  }
  if (matches.length > 1 || (matches.length === 1 && values.length !== 1)) {
    fail('provider_ambiguous', stage, 'rejected');
  }
  if (matches.length === 0) {
    if (values.length > 0) fail('provider_mismatch', stage, 'rejected');
    fail('provider_unknown', stage, 'unknown');
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: 'management_access_application_recovery',
    planId: input.intent.planId,
    planHash: input.intent.planHash,
    ownershipMarker: input.intent.ownershipMarker,
    locator: matches[0],
  });
}

function validatePolicySpec(
  input: ManagementAdminPolicySpec,
  stage: CloudflareManagementStage,
): Omit<ExpectedPolicy, 'policyId'> {
  if (
    !ACCOUNT_ID_PATTERN.test(input.accountId) ||
    !providerId(input.applicationId)
  ) fail('invalid_input', stage, 'not_sent');
  const plan = reviewedManagementProjection(input.plan, stage);
  const adminEmails = canonicalEmails(plan.adminEmails);
  if (!adminEmails || !exactJson(adminEmails, plan.adminEmails)) {
    fail('invalid_input', stage, 'not_sent');
  }
  return {
    accountId: input.accountId,
    planId: plan.planId,
    planHash: plan.planHash,
    applicationId: input.applicationId,
    name: plan.policyName,
    adminEmails,
  };
}

function policyBody(expected: Omit<ExpectedPolicy, 'policyId'>): ManagementAdminPolicyRequestSpec {
  return {
    approval_required: false,
    decision: 'allow',
    exclude: [],
    include: expected.adminEmails.map((email) => ({ email: { email } })),
    isolation_required: false,
    name: expected.name,
    precedence: 1,
    purpose_justification_required: false,
    require: [],
  };
}

function exactPolicy(value: unknown, expected: ExpectedPolicy): boolean {
  if (!isRecord(value)) return false;
  if (
    value.id !== expected.policyId ||
    value.name !== expected.name ||
    value.decision !== 'allow' ||
    value.precedence !== 1 ||
    // Live (2026-08-23): these flags are omitted from the policy when false.
    !(value.approval_required === false || value.approval_required === undefined) ||
    !(value.isolation_required === false || value.isolation_required === undefined) ||
    !(value.purpose_justification_required === false || value.purpose_justification_required === undefined) ||
    !Array.isArray(value.include) ||
    !Array.isArray(value.exclude) ||
    value.exclude.length !== 0 ||
    !Array.isArray(value.require) ||
    value.require.length !== 0 ||
    value.include.length !== expected.adminEmails.length
  ) return false;
  const emails: string[] = [];
  for (const rule of value.include) {
    if (!isRecord(rule) || !exactKeys(rule, ['email']) || !isRecord(rule.email) || !exactKeys(rule.email, ['email'])) {
      return false;
    }
    const email = rule.email.email;
    if (typeof email !== 'string') return false;
    emails.push(email);
  }
  emails.sort();
  return emails.every((email, index) => email === expected.adminEmails[index]);
}

export function prepareManagementAdminPolicyIntent(
  input: ManagementAdminPolicySpec,
): ManagementAdminPolicyIntent {
  const expected = validatePolicySpec(input, 'admin_policy_create');
  return Object.freeze({
    schemaVersion: 1,
    kind: 'management_admin_policy',
    planId: expected.planId,
    planHash: expected.planHash,
    ownershipMarker: managementOwnershipMarker(input.plan),
    accountId: expected.accountId,
    applicationId: expected.applicationId,
    request: Object.freeze(policyBody(expected)),
  });
}

function requirePolicyIntent(
  input: ManagementAdminPolicySpec & { readonly intent: ManagementAdminPolicyIntent },
  stage: CloudflareManagementStage,
): {
  readonly expected: Omit<ExpectedPolicy, 'policyId'>;
  readonly intent: ManagementAdminPolicyIntent;
} {
  const expected = validatePolicySpec(input, stage);
  const canonical = prepareManagementAdminPolicyIntent(input);
  if (!isRecord(input.intent) || !exactJson(input.intent, canonical)) fail('invalid_input', stage, 'not_sent');
  return { expected, intent: canonical };
}

export async function createManagementAdminAllowPolicy(
  input: CloudflareManagementCall & ManagementAdminPolicySpec & {
    readonly intent: ManagementAdminPolicyIntent;
  },
): Promise<ManagementAdminPolicyLocator> {
  const stage = 'admin_policy_create';
  const call = commonInput(input, stage);
  const { intent } = requirePolicyIntent(input, stage);
  const response = await performRequest(
    call,
    stage,
    accountUrl(input.accountId, `/access/apps/${encodeURIComponent(input.applicationId)}/policies`),
    {
      method: 'POST',
      headers: jsonHeaders(call.accessToken),
      body: JSON.stringify(intent.request),
    },
  );
  const result = requireSuccess(response, stage, CREATED_STATUSES).result;
  if (!isRecord(result) || !providerId(result.id)) fail('provider_unknown', stage, 'unknown');
  return Object.freeze({ policyId: result.id });
}

function expectedPolicy(
  input: ManagementAdminPolicySpec & ManagementAdminPolicyLocator,
  stage: CloudflareManagementStage,
): ExpectedPolicy {
  const expected = validatePolicySpec(input, stage);
  if (!providerId(input.policyId)) fail('invalid_input', stage, 'not_sent');
  return { ...expected, policyId: input.policyId };
}

export async function verifyManagementAdminAllowPolicyGet(
  input: CloudflareManagementCall & ManagementAdminPolicySpec & ManagementAdminPolicyLocator,
): Promise<ManagementAdminPolicyLocator> {
  const stage = 'admin_policy_get';
  const call = commonInput(input, stage);
  const expected = expectedPolicy(input, stage);
  const response = await performRequest(
    call,
    stage,
    accountUrl(
      input.accountId,
      `/access/apps/${encodeURIComponent(input.applicationId)}/policies/${encodeURIComponent(input.policyId)}`,
    ),
    { method: 'GET', headers: authHeaders(call.accessToken) },
  );
  if (!exactPolicy(requireSuccess(response, stage).result, expected)) fail('late_drift', stage, 'rejected');
  return Object.freeze({ policyId: expected.policyId });
}

export async function verifyManagementAdminAllowPolicyList(
  input: CloudflareManagementCall & ManagementAdminPolicySpec & ManagementAdminPolicyLocator,
): Promise<ManagementAdminPolicyLocator> {
  const stage = 'admin_policy_list_verify';
  const call = commonInput(input, stage);
  const expected = expectedPolicy(input, stage);
  const values = await collectPaginated(call, stage, LIST_PAGE_SIZE, (page, perPage) => {
    const url = accountUrl(input.accountId, `/access/apps/${encodeURIComponent(input.applicationId)}/policies`);
    url.searchParams.set('page', String(page));
    url.searchParams.set('per_page', String(perPage));
    return url;
  }, true);
  if (values.length > 1) fail('foreign_policy', stage, 'rejected');
  if (values.length !== 1 || !exactPolicy(values[0], expected)) {
    fail('late_drift', stage, 'rejected');
  }
  return Object.freeze({ policyId: expected.policyId });
}

export async function recoverManagementAdminAllowPolicy(
  input: CloudflareManagementCall & ManagementAdminPolicySpec & {
    readonly intent: ManagementAdminPolicyIntent;
  },
): Promise<ManagementAdminPolicyRecoveryRecord> {
  const stage = 'admin_policy_recover';
  const call = commonInput(input, stage);
  const { expected } = requirePolicyIntent(input, stage);
  const values = await collectPaginated(call, stage, LIST_PAGE_SIZE, (page, perPage) => {
    const url = accountUrl(input.accountId, `/access/apps/${encodeURIComponent(input.applicationId)}/policies`);
    url.searchParams.set('page', String(page));
    url.searchParams.set('per_page', String(perPage));
    return url;
  }, true);
  const matches: ManagementAdminPolicyLocator[] = [];
  for (const value of values) {
    if (!isRecord(value) || !providerId(value.id)) fail('provider_mismatch', stage, 'rejected');
    if (exactPolicy(value, { ...expected, policyId: value.id })) {
      matches.push(Object.freeze({ policyId: value.id }));
    }
  }
  if (matches.length > 1) fail('provider_ambiguous', stage, 'rejected');
  if (values.length > 1 || (values.length === 1 && matches.length === 0)) {
    fail('foreign_policy', stage, 'rejected');
  }
  if (matches.length === 0) fail('provider_unknown', stage, 'unknown');
  return Object.freeze({
    schemaVersion: 1,
    kind: 'management_admin_policy_recovery',
    planId: input.intent.planId,
    planHash: input.intent.planHash,
    ownershipMarker: input.intent.ownershipMarker,
    locator: matches[0],
  });
}

function validateWorkerSubdomainInput(
  input: CloudflareManagementCall & { readonly accountId: string; readonly plan: StaticDeployPlan },
  stage: CloudflareManagementStage,
): { readonly call: ReturnType<typeof commonInput>; readonly workerName: string } {
  const call = commonInput(input, stage);
  if (!ACCOUNT_ID_PATTERN.test(input.accountId)) {
    fail('invalid_input', stage, 'not_sent');
  }
  const plan = reviewedManagementProjection(input.plan, stage);
  if (!WORKER_NAME_PATTERN.test(plan.workerName)) fail('invalid_input', stage, 'not_sent');
  return { call, workerName: plan.workerName };
}

function parseSubdomainState(value: unknown): WorkerSubdomainState | null {
  if (!isRecord(value) || !exactKeys(value, ['enabled', 'previews_enabled'])) return null;
  if (typeof value.enabled !== 'boolean' || value.previews_enabled !== false) return null;
  return Object.freeze({ enabled: value.enabled, previewsEnabled: false });
}

/**
 * Explicit bootstrap-only toggle. Preview URLs are always disabled, and the
 * caller must make a separate verified `enabled: false` call after bootstrap.
 */
export async function setWorkerBootstrapSubdomain(
  input: CloudflareManagementCall & {
    readonly accountId: string;
    readonly plan: StaticDeployPlan;
    readonly enabled: boolean;
  },
): Promise<WorkerSubdomainState> {
  const stage = 'worker_subdomain_set';
  const { call, workerName } = validateWorkerSubdomainInput(input, stage);
  if (typeof input.enabled !== 'boolean') fail('invalid_input', stage, 'not_sent');
  const response = await performRequest(
    call,
    stage,
    accountUrl(input.accountId, `/workers/scripts/${encodeURIComponent(workerName)}/subdomain`),
    {
      method: 'POST',
      headers: jsonHeaders(call.accessToken),
      body: JSON.stringify({ enabled: input.enabled, previews_enabled: false }),
    },
  );
  const state = parseSubdomainState(requireSuccess(response, stage, CREATED_STATUSES).result);
  if (!state || state.enabled !== input.enabled) fail('provider_unknown', stage, 'unknown');
  return state;
}

export async function verifyWorkerBootstrapSubdomain(
  input: CloudflareManagementCall & {
    readonly accountId: string;
    readonly plan: StaticDeployPlan;
    readonly expectedEnabled: boolean;
  },
): Promise<WorkerSubdomainState> {
  const stage = 'worker_subdomain_get';
  const { call, workerName } = validateWorkerSubdomainInput(input, stage);
  if (typeof input.expectedEnabled !== 'boolean') fail('invalid_input', stage, 'not_sent');
  const response = await performRequest(
    call,
    stage,
    accountUrl(input.accountId, `/workers/scripts/${encodeURIComponent(workerName)}/subdomain`),
    { method: 'GET', headers: authHeaders(call.accessToken) },
  );
  const state = parseSubdomainState(requireSuccess(response, stage).result);
  if (!state || state.enabled !== input.expectedEnabled) fail('late_drift', stage, 'rejected');
  return state;
}

function validateDomainSpec(
  input: ManagementCustomDomainSpec,
  stage: CloudflareManagementStage,
): Omit<ExpectedDomain, 'domainId'> {
  if (!ACCOUNT_ID_PATTERN.test(input.accountId) || !ZONE_ID_PATTERN.test(input.zoneId)) {
    fail('invalid_input', stage, 'not_sent');
  }
  const plan = reviewedManagementProjection(input.plan, stage);
  if (
    !validZoneRelation(plan.managementHostname, plan.zoneName) ||
    !WORKER_NAME_PATTERN.test(plan.workerName)
  ) fail('invalid_input', stage, 'not_sent');
  return {
    accountId: input.accountId,
    planId: plan.planId,
    planHash: plan.planHash,
    hostname: plan.managementHostname,
    service: plan.workerName,
    zoneId: input.zoneId,
    zoneName: plan.zoneName,
  };
}

function domainsListUrl(accountId: string, hostname: string, page: number, perPage: number): URL {
  const url = accountUrl(accountId, '/workers/domains');
  url.searchParams.set('hostname', hostname);
  url.searchParams.set('page', String(page));
  url.searchParams.set('per_page', String(perPage));
  return url;
}

function exactDomain(value: unknown, expected: ExpectedDomain): boolean {
  if (!isRecord(value)) return false;
  return value.id === expected.domainId &&
    value.hostname === expected.hostname &&
    value.service === expected.service &&
    value.zone_id === expected.zoneId &&
    value.zone_name === expected.zoneName &&
    (value.environment === undefined || value.environment === 'production');
}

async function assertNoManagementCustomDomain(
  call: ReturnType<typeof commonInput>,
  expected: Omit<ExpectedDomain, 'domainId'>,
): Promise<void> {
  const stage = 'management_domain_baseline';
  const values = await collectPaginated(call, stage, LIST_PAGE_SIZE, (page, perPage) =>
    domainsListUrl(expected.accountId, expected.hostname, page, perPage));
  if (values.length > 1) fail('provider_ambiguous', stage, 'rejected');
  if (values.length === 1) {
    const value = values[0];
    if (!isRecord(value) || value.hostname !== expected.hostname || !providerId(value.id)) {
      fail('provider_mismatch', stage, 'rejected');
    }
    fail('fresh_baseline_collision', stage, 'rejected');
  }
}

export async function preflightFreshManagementCustomDomain(
  input: CloudflareManagementCall & ManagementCustomDomainSpec,
): Promise<{ readonly clear: true }> {
  const stage = 'management_domain_baseline';
  const call = commonInput(input, stage);
  const expected = validateDomainSpec(input, stage);
  await assertNoManagementCustomDomain(call, expected);
  await assertNoExactDnsCollision(call, expected);
  await assertNoOverlappingWorkerRoute(call, expected);
  return Object.freeze({ clear: true });
}

function domainBody(expected: Omit<ExpectedDomain, 'domainId'>): ManagementCustomDomainRequestSpec {
  return Object.freeze({
    hostname: expected.hostname,
    service: expected.service,
    zone_id: expected.zoneId,
    zone_name: expected.zoneName,
  });
}

export function prepareManagementCustomDomainIntent(
  input: ManagementCustomDomainSpec,
): ManagementCustomDomainIntent {
  const expected = validateDomainSpec(input, 'management_domain_attach');
  return Object.freeze({
    schemaVersion: 1,
    kind: 'management_custom_domain',
    planId: expected.planId,
    planHash: expected.planHash,
    ownershipMarker: managementOwnershipMarker(input.plan),
    accountId: expected.accountId,
    zoneId: expected.zoneId,
    request: domainBody(expected),
  });
}

function requireDomainIntent(
  input: ManagementCustomDomainSpec & { readonly intent: ManagementCustomDomainIntent },
  stage: CloudflareManagementStage,
): {
  readonly expected: Omit<ExpectedDomain, 'domainId'>;
  readonly intent: ManagementCustomDomainIntent;
} {
  const expected = validateDomainSpec(input, stage);
  const canonical = prepareManagementCustomDomainIntent(input);
  if (!isRecord(input.intent) || !exactJson(input.intent, canonical)) fail('invalid_input', stage, 'not_sent');
  return { expected, intent: canonical };
}

async function assertNoExactDnsCollision(
  call: ReturnType<typeof commonInput>,
  expected: Omit<ExpectedDomain, 'domainId'>,
): Promise<void> {
  const stage = 'management_domain_dns_collision';
  const values = await collectPaginated(call, stage, LIST_PAGE_SIZE, (page, perPage) => {
    const url = zoneUrl(expected.zoneId, '/dns_records');
    url.searchParams.set('name.exact', expected.hostname);
    url.searchParams.set('page', String(page));
    url.searchParams.set('per_page', String(perPage));
    return url;
  });
  for (const value of values) {
    if (!isRecord(value) || !providerId(value.id) || value.name !== expected.hostname) {
      fail('provider_mismatch', stage, 'rejected');
    }
  }
  if (values.length > 0) fail('dns_collision', stage, 'rejected');
}

function routeOverlapsHostname(pattern: unknown, hostname: string): boolean | null {
  if (
    typeof pattern !== 'string' ||
    pattern.length < 3 ||
    pattern.length > 512 ||
    pattern !== pattern.toLowerCase() ||
    /[\u0000-\u0020\u007f]/u.test(pattern)
  ) return null;
  const withoutScheme = pattern.replace(/^https?:\/\//u, '');
  const slash = withoutScheme.indexOf('/');
  if (slash <= 0 || slash === withoutScheme.length - 1) return null;
  const hostPattern = withoutScheme.slice(0, slash);
  if (/[\[\]@:?#]/u.test(hostPattern)) return null;
  if (!hostPattern.includes('*')) return validHostname(hostPattern) ? hostPattern === hostname : null;
  if (!hostPattern.startsWith('*') || hostPattern.slice(1).includes('*')) return null;
  const suffix = hostPattern.slice(1).replace(/^\./u, '');
  if (!validHostname(suffix)) return null;
  return hostname === suffix || hostname.endsWith(`.${suffix}`) || hostname.endsWith(suffix);
}

async function assertNoOverlappingWorkerRoute(
  call: ReturnType<typeof commonInput>,
  expected: Omit<ExpectedDomain, 'domainId'>,
): Promise<void> {
  const stage = 'management_domain_route_collision';
  const values = await collectPaginated(call, stage, LIST_PAGE_SIZE, (page, perPage) => {
    const url = zoneUrl(expected.zoneId, '/workers/routes');
    url.searchParams.set('page', String(page));
    url.searchParams.set('per_page', String(perPage));
    return url;
  }, true);
  for (const value of values) {
    if (
      !isRecord(value) ||
      !providerId(value.id) ||
      !Object.hasOwn(value, 'pattern') ||
      (Object.hasOwn(value, 'script') && value.script !== null && typeof value.script !== 'string')
    ) fail('provider_mismatch', stage, 'rejected');
    const overlap = routeOverlapsHostname(value.pattern, expected.hostname);
    if (overlap === null) fail('provider_mismatch', stage, 'rejected');
    if (overlap) fail('worker_route_collision', stage, 'rejected');
  }
}

/**
 * Terminal provider mutation for the management surface. Callers must invoke
 * this only after the Worker bootstrap and Access app/policy verifications;
 * this stage intentionally performs no orchestration or prerequisite writes.
 */
export async function attachManagementCustomDomain(
  input: CloudflareManagementCall & ManagementCustomDomainSpec & {
    readonly intent: ManagementCustomDomainIntent;
  },
): Promise<ManagementCustomDomainLocator> {
  const stage = 'management_domain_attach';
  const call = commonInput(input, stage);
  const { expected, intent } = requireDomainIntent(input, stage);
  // Two complete fresh-state proofs narrow ordinary drift during pagination.
  // The second round finishes with the exact DNS lookup immediately before PUT.
  await assertNoManagementCustomDomain(call, expected);
  await assertNoExactDnsCollision(call, expected);
  await assertNoOverlappingWorkerRoute(call, expected);
  await assertNoManagementCustomDomain(call, expected);
  await assertNoOverlappingWorkerRoute(call, expected);
  await assertNoExactDnsCollision(call, expected);
  const response = await performRequest(call, stage, accountUrl(input.accountId, '/workers/domains'), {
    method: 'PUT',
    headers: jsonHeaders(call.accessToken),
    body: JSON.stringify(intent.request),
  });
  const result = requireSuccess(response, stage, CREATED_STATUSES).result;
  if (!isRecord(result) || !customDomainId(result.id)) fail('provider_unknown', stage, 'unknown');
  return Object.freeze({ domainId: result.id });
}

function expectedDomain(
  input: ManagementCustomDomainSpec & ManagementCustomDomainLocator,
  stage: CloudflareManagementStage,
): ExpectedDomain {
  const expected = validateDomainSpec(input, stage);
  if (!customDomainId(input.domainId)) fail('invalid_input', stage, 'not_sent');
  return { ...expected, domainId: input.domainId };
}

export async function verifyManagementCustomDomainGet(
  input: CloudflareManagementCall & ManagementCustomDomainSpec & ManagementCustomDomainLocator,
): Promise<ManagementCustomDomainLocator> {
  const stage = 'management_domain_get';
  const call = commonInput(input, stage);
  const expected = expectedDomain(input, stage);
  const response = await performRequest(
    call,
    stage,
    accountUrl(input.accountId, `/workers/domains/${encodeURIComponent(input.domainId)}`),
    { method: 'GET', headers: authHeaders(call.accessToken) },
  );
  if (!exactDomain(requireSuccess(response, stage).result, expected)) fail('late_drift', stage, 'rejected');
  return Object.freeze({ domainId: expected.domainId });
}

export async function verifyManagementCustomDomainList(
  input: CloudflareManagementCall & ManagementCustomDomainSpec & ManagementCustomDomainLocator,
): Promise<ManagementCustomDomainLocator> {
  const stage = 'management_domain_list_verify';
  const call = commonInput(input, stage);
  const expected = expectedDomain(input, stage);
  const values = await collectPaginated(call, stage, LIST_PAGE_SIZE, (page, perPage) =>
    domainsListUrl(input.accountId, expected.hostname, page, perPage));
  if (values.length > 1) fail('provider_ambiguous', stage, 'rejected');
  if (values.length !== 1 || !exactDomain(values[0], expected)) fail('late_drift', stage, 'rejected');
  return Object.freeze({ domainId: expected.domainId });
}

export async function recoverManagementCustomDomain(
  input: CloudflareManagementCall & ManagementCustomDomainSpec & {
    readonly intent: ManagementCustomDomainIntent;
  },
): Promise<ManagementCustomDomainRecoveryRecord> {
  const stage = 'management_domain_recover';
  const call = commonInput(input, stage);
  const { expected } = requireDomainIntent(input, stage);
  const values = await collectPaginated(call, stage, LIST_PAGE_SIZE, (page, perPage) =>
    domainsListUrl(input.accountId, expected.hostname, page, perPage));
  const matches: ManagementCustomDomainLocator[] = [];
  for (const value of values) {
    if (!isRecord(value) || !providerId(value.id)) fail('provider_mismatch', stage, 'rejected');
    if (exactDomain(value, { ...expected, domainId: value.id })) {
      matches.push(Object.freeze({ domainId: value.id }));
    }
  }
  if (matches.length > 1 || (matches.length === 1 && values.length !== 1)) {
    fail('provider_ambiguous', stage, 'rejected');
  }
  if (matches.length === 0) {
    if (values.length > 0) fail('provider_mismatch', stage, 'rejected');
    fail('provider_unknown', stage, 'unknown');
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: 'management_custom_domain_recovery',
    planId: input.intent.planId,
    planHash: input.intent.planHash,
    ownershipMarker: input.intent.ownershipMarker,
    locator: matches[0],
  });
}
