import { CLOUDFLARE_API_ORIGIN } from './constants';
import { sha256Hex } from './crypto';
import {
  canonicalCustomerBootstrapJson,
  prepareCustomerGatewayDesiredProjection,
  type CustomerGatewayDesiredProjection,
  type PrepareCustomerBootstrapClaimInput,
} from './customer-bootstrap-request';
import { parseStaticDeployPlan, type GatewayResourceKind } from './schema';

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const ZONE_ID = ACCOUNT_ID;
const SAFE_PROVIDER_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u;
const ACCESS_TOKEN = /^[A-Za-z0-9._~-]{20,8192}$/u;
const PLAN_ID = /^plan-[a-f0-9]{24}$/u;
const INSTALLATION_ID = /^acg-[a-f0-9]{24}$/u;
const MANAGEMENT_OWNERSHIP_MARKER = INSTALLATION_ID;
const HASH = /^sha256:[a-f0-9]{64}$/u;
const BARE_HASH = /^[a-f0-9]{64}$/u;
const RELEASE_ID = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$/u;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const RESOURCE_KINDS = Object.freeze([
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
] as const satisfies readonly GatewayResourceKind[]);
const PORTAL_RESOURCE_KINDS = Object.freeze([
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
] as const satisfies readonly GatewayResourceKind[]);

const PAGE_SIZE = 100;
const MAX_LIST_PAGES = 20;
const MAX_LIST_ITEMS = 2_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 15_000;
const ATTESTATION_TTL_MS = 30_000;
const MAX_ATTESTATION_TTL_MS = 60_000;
const PORTAL_CNAME_TARGET = 'gateway.agents.cloudflare.com';

export type CustomerGatewayFreshPreflightStage =
  | 'validate'
  | 'mcp_server_list'
  | 'access_application_list'
  | 'portal_list'
  | 'dns_record_list'
  | 'attest';

export type CustomerGatewayFreshPreflightErrorCode =
  | 'invalid_input'
  | 'provider_rejected'
  | 'provider_unknown'
  | 'provider_mismatch'
  | 'provider_ambiguous'
  | 'existing_gateway_detected'
  | 'fresh_collision'
  | 'attestation_invalid';

/**
 * Secret-free provider evidence that the requested Portal hostname belongs to
 * a coherent Ankka deployment. Provider locators deliberately stay inside the
 * fresh OAuth callback; this summary is display and handoff routing data only.
 */
export interface ExistingAnkkaGatewaySummary {
  readonly schemaVersion: 1;
  readonly installationId: string;
  readonly name: string;
  readonly managementHostname: string;
  readonly portalHostname: string;
  readonly workerName: string;
}

export function parseExistingAnkkaGatewaySummary(value: unknown): ExistingAnkkaGatewaySummary | null {
  const input = isRecord(value) ? value : null;
  const managementHostname = normalizeHostname(input?.managementHostname);
  const portalHostname = normalizeHostname(input?.portalHostname);
  if (!input || !exactKeys(input, [
    'schemaVersion', 'installationId', 'name', 'managementHostname', 'portalHostname', 'workerName',
  ]) || input.schemaVersion !== 1 || typeof input.installationId !== 'string' ||
    !INSTALLATION_ID.test(input.installationId) || !safeText(input.name, 80) ||
    managementHostname === null || portalHostname === null ||
    managementHostname !== input.managementHostname || portalHostname !== input.portalHostname ||
    managementHostname === portalHostname || typeof input.workerName !== 'string' ||
    !/^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(input.workerName)) return null;
  return Object.freeze({
    schemaVersion: 1,
    installationId: input.installationId,
    name: input.name,
    managementHostname,
    portalHostname,
    workerName: input.workerName,
  });
}

/** Stable value-free error; provider bodies and credentials are never retained. */
export class CustomerGatewayFreshPreflightError extends Error {
  readonly code: CustomerGatewayFreshPreflightErrorCode;
  readonly stage: CustomerGatewayFreshPreflightStage;
  readonly canRetry = false;

  constructor(
    code: CustomerGatewayFreshPreflightErrorCode,
    stage: CustomerGatewayFreshPreflightStage,
    readonly existingGateway: ExistingAnkkaGatewaySummary | null = null,
  ) {
    super(code);
    this.name = 'CustomerGatewayFreshPreflightError';
    this.code = code;
    this.stage = stage;
  }
}

export type CustomerGatewayFreshPreflightTransport = (request: Request) => Promise<Response>;

export interface CustomerGatewayFreshPreflightInput extends PrepareCustomerBootstrapClaimInput {
  /** Ephemeral Cloudflare OAuth grant, passed for this call and never retained. */
  readonly accessToken: string;
  readonly transport: CustomerGatewayFreshPreflightTransport;
  readonly timeoutMs?: number;
}

export interface CustomerGatewayFreshPreflightAttestation {
  readonly schemaVersion: 1;
  readonly kind: 'customer_gateway_fresh_preflight';
  readonly accountId: string;
  readonly zoneId: string;
  readonly planId: string;
  readonly planHash: string;
  readonly installationId: string;
  readonly configurationHash: string;
  readonly desiredHash: string;
  readonly releaseId: string;
  /** Canonical aggregate release digest, without a `sha256:` prefix. */
  readonly releaseArtifactSha256: string;
  readonly zeroCandidateKinds: readonly GatewayResourceKind[];
  readonly checkedAt: number;
  readonly expiresAt: number;
  readonly attestationHash: string;
}

interface PreflightCall {
  readonly accessToken: string;
  readonly transport: CustomerGatewayFreshPreflightTransport;
  readonly timeoutMs: number;
}

interface ProviderPage {
  readonly values: readonly unknown[];
  readonly count: number;
  readonly page: number;
  readonly perPage: number;
  readonly totalCount: number | null;
  readonly totalPages: number | null;
}

interface ParsedMcpServer {
  readonly id: string;
  readonly endpoint: string;
  readonly description: string | null;
}

interface ParsedAccessApplication {
  readonly id: string;
  readonly type: string;
  readonly name: string;
  readonly domain: string | null;
  readonly destinations: readonly ParsedDestination[];
}

interface ParsedDestination {
  readonly type: string;
  readonly mcpServerId: string | null;
  readonly uri: string | null;
  readonly exactShape: boolean;
}

interface ParsedPortal {
  readonly id: string;
  readonly hostname: string;
  readonly name: string | null;
  readonly description: string | null;
}

interface ParsedDnsRecord {
  readonly id: string;
  readonly name: string;
  readonly type: string;
  readonly content: string;
  readonly proxied: boolean;
  readonly comment: string | null;
}

class ProviderReadFailure extends Error {}

function fail(
  code: CustomerGatewayFreshPreflightErrorCode,
  stage: CustomerGatewayFreshPreflightStage,
  existingGateway: ExistingAnkkaGatewaySummary | null = null,
): never {
  throw new CustomerGatewayFreshPreflightError(code, stage, existingGateway);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort(compareText);
  const sortedExpected = [...expected].sort(compareText);
  return actual.length === sortedExpected.length &&
    actual.every((key, index) => key === sortedExpected[index]);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function safeText(value: unknown, maxLength: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

function normalizeHostname(value: unknown): string | null {
  if (typeof value !== 'string' || value.length < 3 || value.length > 253) return null;
  const normalized = value.toLowerCase().replace(/\.$/u, '');
  const labels = normalized.split('.');
  if (labels.length < 2 || labels.some((label) => label.length > 63 || !DNS_LABEL.test(label))) {
    return null;
  }
  return normalized;
}

function normalizeHttpsEndpoint(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 2048) return null;
  try {
    const url = new URL(value);
    if (
      url.protocol !== 'https:' || url.username || url.password || url.port || url.hash ||
      normalizeHostname(url.hostname) === null
    ) return null;
    return url.toString();
  } catch {
    return null;
  }
}

function requireTimeout(value: unknown): number {
  const timeout = value === undefined ? DEFAULT_TIMEOUT_MS : value;
  if (!Number.isSafeInteger(timeout) || (timeout as number) < 1 || (timeout as number) > MAX_TIMEOUT_MS) {
    fail('invalid_input', 'validate');
  }
  return timeout as number;
}

function requireCall(input: CustomerGatewayFreshPreflightInput): PreflightCall {
  if (
    !isRecord(input) || typeof input.transport !== 'function' ||
    typeof input.accessToken !== 'string' || !ACCESS_TOKEN.test(input.accessToken)
  ) fail('invalid_input', 'validate');
  return Object.freeze({
    accessToken: input.accessToken,
    transport: input.transport,
    timeoutMs: requireTimeout(input.timeoutMs),
  });
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') throw new ProviderReadFailure();
  const declared = response.headers.get('content-length');
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0 || length > MAX_RESPONSE_BYTES) {
      throw new ProviderReadFailure();
    }
  }
  if (!response.body) throw new ProviderReadFailure();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        // Cancellation is best-effort; a hostile stream must not extend the
        // bounded read by returning a never-settling cancel promise.
        void reader.cancel().catch(() => undefined);
        throw new ProviderReadFailure();
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
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
    } finally {
      bytes.fill(0);
    }
  } catch (error) {
    if (error instanceof ProviderReadFailure) throw error;
    throw new ProviderReadFailure();
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

async function performListRequest(
  call: PreflightCall,
  stage: CustomerGatewayFreshPreflightStage,
  url: URL,
): Promise<unknown> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const request = new Request(url, {
      method: 'GET',
      headers: { accept: 'application/json', authorization: `Bearer ${call.accessToken}` },
      // workerd rejects `redirect: 'error'` at construction; a redirect is
      // instead rejected explicitly by status below.
      redirect: 'manual',
      signal: controller.signal,
    });
    const operation = (async () => {
      const response = await call.transport(request);
      if (
        !(response instanceof Response) || response.redirected || response.type === 'opaqueredirect' ||
        (response.status >= 300 && response.status < 400)
      ) {
        throw new ProviderReadFailure();
      }
      const value = await readBoundedJson(response);
      if (response.status === 200) return value;
      if (response.status >= 400 && response.status < 500 && isProviderRejection(value)) {
        fail('provider_rejected', stage);
      }
      fail('provider_unknown', stage);
    })();
    const deadline = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new ProviderReadFailure());
      }, call.timeoutMs);
    });
    return await Promise.race([operation, deadline]);
  } catch (error) {
    if (error instanceof CustomerGatewayFreshPreflightError) throw error;
    fail('provider_unknown', stage);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    controller.abort();
  }
}

/**
 * The AI Controls endpoints (`/access/ai-controls/mcp/*`) omit the classic v4
 * `errors` and `messages` keys on success (observed live 2026-08-23); the
 * classic endpoints include them. Both keys are therefore optional and are
 * validated only when present.
 */
function envelopeKeysAllowed(value: Record<string, unknown>, required: readonly string[]): boolean {
  const optional = new Set(['errors', 'messages']);
  const keys = Object.keys(value);
  return required.every((key) => keys.includes(key)) &&
    keys.every((key) => required.includes(key) || optional.has(key)) &&
    (!Object.hasOwn(value, 'messages') || Array.isArray(value.messages)) &&
    (!Object.hasOwn(value, 'errors') || Array.isArray(value.errors));
}

function isProviderRejection(value: unknown): boolean {
  if (!isRecord(value)) return false;
  const keys = Object.hasOwn(value, 'result_info')
    ? ['result', 'result_info', 'success']
    : ['result', 'success'];
  return envelopeKeysAllowed(value, keys) && value.success === false && value.result === null &&
    Array.isArray(value.errors) && value.errors.length > 0 &&
    value.errors.every((entry) => isRecord(entry));
}

function parseListPage(
  value: unknown,
  expectedPage: number,
  stage: CustomerGatewayFreshPreflightStage,
): ProviderPage {
  if (
    !isRecord(value) ||
    !envelopeKeysAllowed(value, ['result', 'result_info', 'success']) ||
    value.success !== true ||
    (Object.hasOwn(value, 'errors') && (value.errors as unknown[]).length !== 0) ||
    (Object.hasOwn(value, 'messages') && (value.messages as unknown[]).length !== 0) ||
    !Array.isArray(value.result) || !isRecord(value.result_info)
  ) fail('provider_mismatch', stage);
  const info = value.result_info;
  const allowedInfoKeys = new Set(['count', 'page', 'per_page', 'total_count', 'total_pages']);
  if (
    Object.keys(info).some((key) => !allowedInfoKeys.has(key)) ||
    !Object.hasOwn(info, 'count') || !Object.hasOwn(info, 'page') ||
    !Object.hasOwn(info, 'per_page') ||
    !Number.isSafeInteger(info.count) || info.count !== value.result.length ||
    !Number.isSafeInteger(info.page) || info.page !== expectedPage ||
    !Number.isSafeInteger(info.per_page) || info.per_page !== PAGE_SIZE
  ) fail('provider_mismatch', stage);
  const totalCount = Object.hasOwn(info, 'total_count') ? info.total_count : null;
  const totalPages = Object.hasOwn(info, 'total_pages') ? info.total_pages : null;
  if (
    (totalCount !== null && (!Number.isSafeInteger(totalCount) || (totalCount as number) < 0)) ||
    (totalPages !== null && (!Number.isSafeInteger(totalPages) || (totalPages as number) < 0))
  ) fail('provider_mismatch', stage);
  return Object.freeze({
    values: Object.freeze([...value.result]),
    count: info.count as number,
    page: info.page as number,
    perPage: info.per_page as number,
    totalCount: totalCount as number | null,
    totalPages: totalPages as number | null,
  });
}

async function collectPaginated(
  call: PreflightCall,
  stage: CustomerGatewayFreshPreflightStage,
  urlForPage: (page: number) => URL,
  totalCountMatchesQuery: boolean,
): Promise<readonly unknown[]> {
  const values: unknown[] = [];
  let expectedTotalCount: number | null = null;
  let expectedTotalPages: number | null = null;
  for (let pageNumber = 1; pageNumber <= MAX_LIST_PAGES; pageNumber += 1) {
    const raw = await performListRequest(call, stage, urlForPage(pageNumber));
    const page = parseListPage(raw, pageNumber, stage);
    if (page.values.length > PAGE_SIZE) fail('provider_mismatch', stage);
    if (totalCountMatchesQuery) {
      if (page.totalCount === null) fail('provider_mismatch', stage);
      if (page.totalCount > MAX_LIST_ITEMS) fail('provider_unknown', stage);
      if (expectedTotalCount !== null && expectedTotalCount !== page.totalCount) {
        fail('provider_ambiguous', stage);
      }
      expectedTotalCount = page.totalCount;
      if (page.totalPages !== null) {
        if (page.totalPages > MAX_LIST_PAGES) fail('provider_unknown', stage);
        if (expectedTotalPages !== null && expectedTotalPages !== page.totalPages) {
          fail('provider_ambiguous', stage);
        }
        expectedTotalPages = page.totalPages;
      }
    }
    values.push(...page.values);
    if (values.length > MAX_LIST_ITEMS) fail('provider_unknown', stage);

    if (totalCountMatchesQuery) {
      if (expectedTotalCount === null || values.length > expectedTotalCount) {
        fail('provider_mismatch', stage);
      }
      const expectedPages = expectedTotalCount === 0 ? 0 : Math.ceil(expectedTotalCount / PAGE_SIZE);
      if (
        expectedTotalPages !== null &&
        expectedTotalPages !== expectedPages &&
        !(expectedTotalCount === 0 && expectedTotalPages === 1)
      ) fail('provider_mismatch', stage);
      if (values.length === expectedTotalCount) {
        if (
          expectedTotalPages !== null && expectedTotalPages > 0 &&
          pageNumber < expectedTotalPages
        ) fail('provider_mismatch', stage);
        return Object.freeze(values);
      }
      if (page.values.length === 0) fail('provider_mismatch', stage);
      continue;
    }

    // Filtered Cloudflare list responses may report an unfiltered total_count.
    // Exhaust the exact filtered query by page fullness instead of trusting it.
    if (page.values.length < PAGE_SIZE) return Object.freeze(values);
  }
  return fail('provider_unknown', stage);
}

function accountListUrl(accountId: string, path: string, page: number): URL {
  const url = new URL(`/client/v4/accounts/${accountId}${path}`, CLOUDFLARE_API_ORIGIN);
  url.searchParams.set('page', String(page));
  url.searchParams.set('per_page', String(PAGE_SIZE));
  return url;
}

function dnsListUrl(zoneId: string, hostname: string, page: number): URL {
  const url = new URL(`/client/v4/zones/${zoneId}/dns_records`, CLOUDFLARE_API_ORIGIN);
  url.searchParams.set('name.exact', hostname);
  url.searchParams.set('match', 'all');
  url.searchParams.set('page', String(page));
  url.searchParams.set('per_page', String(PAGE_SIZE));
  return url;
}

function parseMcpServer(value: unknown): ParsedMcpServer | null {
  if (!isRecord(value) || typeof value.id !== 'string' || !SAFE_PROVIDER_ID.test(value.id)) {
    return null;
  }
  const endpoint = normalizeHttpsEndpoint(value.hostname);
  const description = value.description ?? null;
  if (
    endpoint === null ||
    (Object.hasOwn(value, 'name') && value.name !== null && !safeText(value.name, 350)) ||
    (description !== null && !safeText(description, 350))
  ) return null;
  return Object.freeze({ id: value.id, endpoint, description: description as string | null });
}

function parseDestination(value: unknown): ParsedDestination | null {
  if (!isRecord(value) || !safeText(value.type, 128)) return null;
  let mcpServerId: string | null = null;
  let uri: string | null = null;
  let exactShape = false;
  if (value.type === 'via_mcp_server_portal') {
    if (typeof value.mcp_server_id !== 'string' || !SAFE_PROVIDER_ID.test(value.mcp_server_id)) {
      return null;
    }
    mcpServerId = value.mcp_server_id;
    exactShape = exactKeys(value, ['type', 'mcp_server_id']);
  }
  if (value.type === 'public') {
    if (!safeText(value.uri, 2048)) return null;
    uri = value.uri;
    exactShape = exactKeys(value, ['type', 'uri']);
  }
  return Object.freeze({ type: value.type, mcpServerId, uri, exactShape });
}

function parseAccessApplication(value: unknown): ParsedAccessApplication | null {
  if (
    !isRecord(value) || typeof value.id !== 'string' || !SAFE_PROVIDER_ID.test(value.id) ||
    !safeText(value.type, 128) || !safeText(value.name, 350)
  ) return null;
  const domain = value.domain ?? null;
  if (domain !== null && !safeText(domain, 2048)) return null;
  const rawDestinations = value.destinations ?? [];
  if (!Array.isArray(rawDestinations) || rawDestinations.length > 64) return null;
  const destinations: ParsedDestination[] = [];
  for (const destination of rawDestinations) {
    const parsed = parseDestination(destination);
    if (!parsed) return null;
    destinations.push(parsed);
  }
  return Object.freeze({
    id: value.id,
    type: value.type,
    name: value.name,
    domain: domain as string | null,
    destinations: Object.freeze(destinations),
  });
}

function parsePortal(value: unknown): ParsedPortal | null {
  if (!isRecord(value) || typeof value.id !== 'string' || !SAFE_PROVIDER_ID.test(value.id)) {
    return null;
  }
  const hostname = normalizeHostname(value.hostname);
  const name = value.name ?? null;
  const description = value.description ?? null;
  if (
    hostname === null || (name !== null && !safeText(name, 350)) ||
    (description !== null && !safeText(description, 350))
  ) return null;
  return Object.freeze({
    id: value.id,
    hostname,
    name: name as string | null,
    description: description as string | null,
  });
}

function parseDnsRecord(value: unknown): ParsedDnsRecord | null {
  if (!isRecord(value) || typeof value.id !== 'string' || !SAFE_PROVIDER_ID.test(value.id)) {
    return null;
  }
  const name = normalizeHostname(value.name);
  const comment = value.comment ?? null;
  if (
    name === null || !safeText(value.type, 32) || !safeText(value.content, 2048) ||
    typeof value.proxied !== 'boolean' || (comment !== null && !safeText(comment, 350))
  ) return null;
  return Object.freeze({
    id: value.id,
    name,
    type: value.type,
    content: value.content,
    proxied: value.proxied,
    comment: comment as string | null,
  });
}

function parseUnique<T extends { readonly id: string }>(
  values: readonly unknown[],
  parser: (value: unknown) => T | null,
  stage: CustomerGatewayFreshPreflightStage,
): readonly T[] {
  const parsed: T[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const item = parser(value);
    if (!item) fail('provider_mismatch', stage);
    if (seen.has(item.id)) fail('provider_ambiguous', stage);
    seen.add(item.id);
    parsed.push(item);
  }
  return Object.freeze(parsed);
}

function managementOwnershipMarkerFromName(name: string, gatewayName: string): string | null {
  const prefix = `${gatewayName} management [`;
  if (!name.startsWith(prefix) || !name.endsWith(']')) return null;
  const marker = name.slice(prefix.length, -1);
  return MANAGEMENT_OWNERSHIP_MARKER.test(marker) ? marker : null;
}

async function assertZeroCandidates(
  call: PreflightCall,
  projection: CustomerGatewayDesiredProjection,
  managementHostname: string,
): Promise<void> {
  const accountId = projection.target.accountId;
  const zoneId = projection.target.zoneId;
  const mcpServer = projection.candidates.mcpServer;
  if (mcpServer !== null) {
    const servers = parseUnique(
      await collectPaginated(
        call,
        'mcp_server_list',
        (page) => accountListUrl(accountId, '/access/ai-controls/mcp/servers', page),
        true,
      ),
      parseMcpServer,
      'mcp_server_list',
    );
    const expectedEndpoint = normalizeHttpsEndpoint(mcpServer.endpoint);
    if (expectedEndpoint === null) fail('invalid_input', 'validate');
    if (servers.some((server) =>
      server.id === mcpServer.id ||
      server.endpoint === expectedEndpoint ||
      server.description === mcpServer.ownershipMarker)) {
      fail('fresh_collision', 'mcp_server_list');
    }
  }

  const applications = parseUnique(
    await collectPaginated(
      call,
      'access_application_list',
      (page) => accountListUrl(accountId, '/access/apps', page),
      true,
    ),
    parseAccessApplication,
    'access_application_list',
  );
  const sourceApplication = projection.candidates.sourceAccessApplication;
  const portalApplication = projection.candidates.portalAccessApplication;
  const portals = parseUnique(
    await collectPaginated(
      call,
      'portal_list',
      (page) => accountListUrl(accountId, '/access/ai-controls/mcp/portals', page),
      true,
    ),
    parsePortal,
    'portal_list',
  );
  const desiredPortal = projection.candidates.portal;
  const dnsRecords = parseUnique(
    await collectPaginated(
      call,
      'dns_record_list',
      (page) => dnsListUrl(zoneId, projection.candidates.dnsRecord.hostname, page),
      false,
    ),
    parseDnsRecord,
    'dns_record_list',
  );
  if (dnsRecords.some((record) => record.name !== projection.candidates.dnsRecord.hostname)) {
    fail('provider_mismatch', 'dns_record_list');
  }

  const matchingPortals = portals.filter((portal) =>
    portal.hostname === desiredPortal.hostname && portal.name === desiredPortal.name &&
    portal.description === desiredPortal.ownershipMarker);
  const portalApplications = applications.filter((application) =>
    application.name === portalApplication.name && application.type === 'mcp_portal' &&
    application.domain === portalApplication.hostname && application.destinations.length === 1 &&
    application.destinations[0]?.exactShape === true &&
    application.destinations[0].type === 'public' &&
    application.destinations[0].uri === portalApplication.hostname);
  const managementApplications = applications.filter((application) =>
    application.type === 'self_hosted' &&
    managementOwnershipMarkerFromName(application.name, desiredPortal.name) !== null &&
    application.domain === managementHostname && application.destinations.length === 0);
  const detectedManagementMarker = managementApplications.length === 1
    ? managementOwnershipMarkerFromName(managementApplications[0].name, desiredPortal.name)
    : null;
  const dnsOwnershipMarker = `acg:v1:${projection.expected.installationId}:${projection.candidates.dnsRecord.key}`;
  const matchingDnsRecords = dnsRecords.filter((record) =>
    record.name === projection.candidates.dnsRecord.hostname && record.type === 'CNAME' &&
    record.content === PORTAL_CNAME_TARGET && record.proxied === true &&
    record.comment === dnsOwnershipMarker);
  if (
    matchingPortals.length === 1 && portalApplications.length === 1 &&
    managementApplications.length === 1 && detectedManagementMarker !== null &&
    dnsRecords.length === 1 && matchingDnsRecords.length === 1
  ) {
    const gatewaySlug = desiredPortal.name.toLowerCase().replace(/[^a-z0-9]+/gu, '-')
      .replace(/^-+|-+$/gu, '').slice(0, 20).replace(/-$/u, '');
    if (gatewaySlug) {
      fail('existing_gateway_detected', 'portal_list', Object.freeze({
        schemaVersion: 1,
        installationId: projection.expected.installationId,
        name: desiredPortal.name,
        managementHostname,
        portalHostname: desiredPortal.hostname,
        workerName: `ankka-gateway-${gatewaySlug}-${detectedManagementMarker}`,
      }));
    }
  }

  if (applications.some((application) =>
    (sourceApplication !== null && (
      application.name === sourceApplication.ownershipMarker ||
      (application.type === 'mcp' && application.destinations.some((destination) =>
        destination.type === 'via_mcp_server_portal' &&
        destination.mcpServerId === sourceApplication.serverId
      ))
    )) ||
    application.name === portalApplication.name ||
    (application.type === 'mcp_portal' && (
      application.domain === portalApplication.hostname ||
      application.destinations.some((destination) =>
        destination.type === 'public' && destination.uri === portalApplication.hostname)
    )))) {
    fail('fresh_collision', 'access_application_list');
  }
  if (portals.some((portal) =>
    portal.id === desiredPortal.id || portal.hostname === desiredPortal.hostname ||
    portal.name === desiredPortal.name || portal.description === desiredPortal.ownershipMarker)) {
    fail('fresh_collision', 'portal_list');
  }
  if (dnsRecords.length !== 0) fail('fresh_collision', 'dns_record_list');
}

function attestationWithoutHash(value: CustomerGatewayFreshPreflightAttestation): Omit<
  CustomerGatewayFreshPreflightAttestation,
  'attestationHash'
> {
  const { attestationHash: _attestationHash, ...unsigned } = value;
  return unsigned;
}

async function attestationHash(value: unknown): Promise<string> {
  return `sha256:${await sha256Hex(canonicalCustomerBootstrapJson(value))}`;
}

/**
 * Read every broad customer-gateway candidate set twice and attest only an
 * exact fresh zero state. This function has no provider mutation method.
 */
export async function preflightFreshCustomerGateway(
  input: CustomerGatewayFreshPreflightInput,
): Promise<CustomerGatewayFreshPreflightAttestation> {
  const call = requireCall(input);
  let projection: CustomerGatewayDesiredProjection;
  let managementHostname: string;
  try {
    projection = await prepareCustomerGatewayDesiredProjection(input);
    const parsedPlan = parseStaticDeployPlan(input.plan);
    managementHostname = parsedPlan.gatewayConfiguration.managementHostname;
  } catch {
    fail('invalid_input', 'validate');
  }
  const expectedKinds = projection.candidates.mcpServer === null
    ? PORTAL_RESOURCE_KINDS
    : RESOURCE_KINDS;
  if (
    !ACCOUNT_ID.test(projection.target.accountId) || !ZONE_ID.test(projection.target.zoneId) ||
    projection.resourceKinds.length !== expectedKinds.length ||
    projection.resourceKinds.some((kind, index) => kind !== expectedKinds[index])
  ) fail('invalid_input', 'validate');

  // A complete second scan is the final provider operation. Success is never
  // inferred from the first scan or a pagination count alone.
  await assertZeroCandidates(call, projection, managementHostname);
  await assertZeroCandidates(call, projection, managementHostname);

  const checkedAt = input.nowMs ?? Date.now();
  if (!Number.isSafeInteger(checkedAt) || checkedAt < 0 || projection.plan.planId.length === 0) {
    fail('invalid_input', 'attest');
  }
  const expiresAt = Math.min(checkedAt + ATTESTATION_TTL_MS, projection.plan.expiresAt);
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= checkedAt) fail('invalid_input', 'attest');
  const unsigned = Object.freeze({
    schemaVersion: 1 as const,
    kind: 'customer_gateway_fresh_preflight' as const,
    accountId: projection.target.accountId,
    zoneId: projection.target.zoneId,
    planId: projection.plan.planId,
    planHash: projection.plan.planHash,
    installationId: projection.expected.installationId,
    configurationHash: projection.expected.configurationHash,
    desiredHash: projection.expected.desiredHash,
    releaseId: projection.release.id,
    releaseArtifactSha256: projection.release.artifactSha256,
    zeroCandidateKinds: projection.resourceKinds,
    checkedAt,
    expiresAt,
  });
  return Object.freeze({ ...unsigned, attestationHash: await attestationHash(unsigned) });
}

/** Pure, provider-I/O-free parser for journal persistence and cross-binding. */
export async function parseCustomerGatewayFreshPreflightAttestation(
  value: unknown,
): Promise<CustomerGatewayFreshPreflightAttestation | null> {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion',
    'kind',
    'accountId',
    'zoneId',
    'planId',
    'planHash',
    'installationId',
    'configurationHash',
    'desiredHash',
    'releaseId',
    'releaseArtifactSha256',
    'zeroCandidateKinds',
    'checkedAt',
    'expiresAt',
    'attestationHash',
  ])) return null;
  const candidateKinds = Array.isArray(value.zeroCandidateKinds)
    ? value.zeroCandidateKinds as GatewayResourceKind[]
    : [];
  const validCandidateKinds = [RESOURCE_KINDS, PORTAL_RESOURCE_KINDS].some((expected) =>
    candidateKinds.length === expected.length &&
    candidateKinds.every((kind, index) => kind === expected[index]));
  if (
    value.schemaVersion !== 1 || value.kind !== 'customer_gateway_fresh_preflight' ||
    typeof value.accountId !== 'string' || !ACCOUNT_ID.test(value.accountId) ||
    typeof value.zoneId !== 'string' || !ZONE_ID.test(value.zoneId) ||
    typeof value.planId !== 'string' || !PLAN_ID.test(value.planId) ||
    typeof value.planHash !== 'string' || !HASH.test(value.planHash) ||
    typeof value.installationId !== 'string' || !INSTALLATION_ID.test(value.installationId) ||
    typeof value.configurationHash !== 'string' || !HASH.test(value.configurationHash) ||
    typeof value.desiredHash !== 'string' || !HASH.test(value.desiredHash) ||
    typeof value.releaseId !== 'string' || !RELEASE_ID.test(value.releaseId) ||
    typeof value.releaseArtifactSha256 !== 'string' || !BARE_HASH.test(value.releaseArtifactSha256) ||
    !validCandidateKinds ||
    !Number.isSafeInteger(value.checkedAt) || (value.checkedAt as number) < 0 ||
    !Number.isSafeInteger(value.expiresAt) ||
    (value.expiresAt as number) <= (value.checkedAt as number) ||
    (value.expiresAt as number) - (value.checkedAt as number) > MAX_ATTESTATION_TTL_MS ||
    typeof value.attestationHash !== 'string' || !HASH.test(value.attestationHash)
  ) return null;
  const candidate: CustomerGatewayFreshPreflightAttestation = Object.freeze({
    schemaVersion: 1,
    kind: 'customer_gateway_fresh_preflight',
    accountId: value.accountId,
    zoneId: value.zoneId,
    planId: value.planId,
    planHash: value.planHash,
    installationId: value.installationId,
    configurationHash: value.configurationHash,
    desiredHash: value.desiredHash,
    releaseId: value.releaseId,
    releaseArtifactSha256: value.releaseArtifactSha256,
    zeroCandidateKinds: Object.freeze([...candidateKinds]),
    checkedAt: value.checkedAt as number,
    expiresAt: value.expiresAt as number,
    attestationHash: value.attestationHash,
  });
  if (await attestationHash(attestationWithoutHash(candidate)) !== candidate.attestationHash) {
    return null;
  }
  return candidate;
}
