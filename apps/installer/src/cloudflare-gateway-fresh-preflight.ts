import * as v from 'valibot';

import { boundaryValueSchema, type BoundaryValue } from './boundary';
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

function safeText(value: string, maxLength: number): boolean {
  return value.length > 0 && value.length <= maxLength && ![...value].some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint === undefined || codePoint <= 0x1f || codePoint === 0x7f;
  });
}

const nonnegativeIntegerSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const timeoutSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(1), v.maxValue(MAX_TIMEOUT_MS));
const providerIdSchema = v.pipe(v.string(), v.regex(SAFE_PROVIDER_ID));
const existingGatewaySchema = v.strictObject({
  schemaVersion: v.literal(1),
  installationId: v.pipe(v.string(), v.regex(INSTALLATION_ID)),
  name: v.pipe(v.string(), v.check((value) => safeText(value, 80))),
  managementHostname: v.string(),
  portalHostname: v.string(),
  workerName: v.pipe(v.string(), v.regex(/^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u)),
});
const providerEnvelopeSchema = v.strictObject({
  result: boundaryValueSchema,
  result_info: v.optional(boundaryValueSchema),
  success: v.boolean(),
  errors: v.optional(v.array(boundaryValueSchema)),
  messages: v.optional(v.array(boundaryValueSchema)),
});
const listPageSchema = v.strictObject({
  result: v.array(boundaryValueSchema),
  result_info: v.strictObject({
    count: nonnegativeIntegerSchema,
    page: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
    per_page: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
    total_count: v.optional(nonnegativeIntegerSchema),
    total_pages: v.optional(nonnegativeIntegerSchema),
  }),
  success: v.literal(true),
  errors: v.optional(v.array(boundaryValueSchema)),
  messages: v.optional(v.array(boundaryValueSchema)),
});
const mcpServerSchema = v.looseObject({
  id: providerIdSchema,
  hostname: v.string(),
  name: v.optional(v.nullable(v.string())),
  description: v.optional(v.nullable(v.string())),
});
const destinationContainerSchema = v.looseObject({ type: v.string() });
const viaMcpDestinationSchema = v.strictObject({
  type: v.literal('via_mcp_server_portal'),
  mcp_server_id: providerIdSchema,
});
const publicDestinationSchema = v.strictObject({ type: v.literal('public'), uri: v.string() });
const viaMcpDestinationFieldsSchema = v.looseObject({
  type: v.literal('via_mcp_server_portal'),
  mcp_server_id: providerIdSchema,
});
const publicDestinationFieldsSchema = v.looseObject({ type: v.literal('public'), uri: v.string() });
const accessApplicationSchema = v.looseObject({
  id: providerIdSchema,
  type: v.string(),
  name: v.string(),
  domain: v.optional(v.nullable(v.string())),
  destinations: v.optional(v.array(boundaryValueSchema)),
});
const portalSchema = v.looseObject({
  id: providerIdSchema,
  hostname: v.string(),
  name: v.optional(v.nullable(v.string())),
  description: v.optional(v.nullable(v.string())),
});
const dnsRecordSchema = v.looseObject({
  id: providerIdSchema,
  name: v.string(),
  type: v.string(),
  content: v.string(),
  proxied: v.boolean(),
  comment: v.optional(v.nullable(v.string())),
});
const attestationSchema = v.strictObject({
  schemaVersion: v.literal(1),
  kind: v.literal('customer_gateway_fresh_preflight'),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  zoneId: v.pipe(v.string(), v.regex(ZONE_ID)),
  planId: v.pipe(v.string(), v.regex(PLAN_ID)),
  planHash: v.pipe(v.string(), v.regex(HASH)),
  installationId: v.pipe(v.string(), v.regex(INSTALLATION_ID)),
  configurationHash: v.pipe(v.string(), v.regex(HASH)),
  desiredHash: v.pipe(v.string(), v.regex(HASH)),
  releaseId: v.pipe(v.string(), v.regex(RELEASE_ID)),
  releaseArtifactSha256: v.pipe(v.string(), v.regex(BARE_HASH)),
  zeroCandidateKinds: v.array(v.picklist(RESOURCE_KINDS)),
  checkedAt: nonnegativeIntegerSchema,
  expiresAt: nonnegativeIntegerSchema,
  attestationHash: v.pipe(v.string(), v.regex(HASH)),
});

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

export function parseExistingAnkkaGatewaySummary<Input>(value: Input): ExistingAnkkaGatewaySummary | null {
  const result = v.safeParse(existingGatewaySchema, value);
  if (!result.success) return null;
  const input = result.output;
  const managementHostname = normalizeHostname(input.managementHostname);
  const portalHostname = normalizeHostname(input.portalHostname);
  if (
    managementHostname === null || portalHostname === null ||
    managementHostname !== input.managementHostname || portalHostname !== input.portalHostname ||
    managementHostname === portalHostname) return null;
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

export interface CustomerGatewayFreshProjectionPreflightInput {
  /** Ephemeral customer-Worker grant, passed for this call and never retained. */
  readonly accessToken: string;
  readonly transport: CustomerGatewayFreshPreflightTransport;
  readonly timeoutMs?: number;
  readonly projection: CustomerGatewayDesiredProjection;
  readonly managementHostname: string;
  readonly nowMs?: number;
}

/** Optional call controls forwarded only when the caller supplied them. */
interface OptionalFreshPreflightControls {
  timeoutMs?: number;
  nowMs?: number;
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
  readonly values: readonly BoundaryValue[];
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
  readonly matchesReviewedContract: boolean;
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

function normalizeHostname(value: string): string | null {
  if (value.length < 3 || value.length > 253) return null;
  const normalized = value.toLowerCase().replace(/\.$/u, '');
  const labels = normalized.split('.');
  if (labels.length < 2 || labels.some((label) => label.length > 63 || !DNS_LABEL.test(label))) {
    return null;
  }
  return normalized;
}

function normalizeHttpsEndpoint(value: string): string | null {
  if (value.length > 2048) return null;
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

function requireTimeout<Value>(value: Value): number {
  const timeout = value === undefined ? DEFAULT_TIMEOUT_MS : value;
  const result = v.safeParse(timeoutSchema, timeout);
  if (!result.success) {
    fail('invalid_input', 'validate');
  }
  return result.output;
}

function requireCall(input: Pick<
  CustomerGatewayFreshPreflightInput,
  'accessToken' | 'transport' | 'timeoutMs'
>): PreflightCall {
  if (
    !v.is(v.function(), input.transport) || !ACCESS_TOKEN.test(input.accessToken)
  ) fail('invalid_input', 'validate');
  return Object.freeze({
    accessToken: input.accessToken,
    transport: input.transport,
    timeoutMs: requireTimeout(input.timeoutMs),
  });
}

async function readBoundedJson(response: Response): Promise<BoundaryValue> {
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
      const parsed = v.safeParse(
        boundaryValueSchema,
        JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)),
      );
      if (!parsed.success) throw new ProviderReadFailure();
      return parsed.output;
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
): Promise<BoundaryValue> {
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

function isProviderRejection(value: BoundaryValue): boolean {
  const result = v.safeParse(providerEnvelopeSchema, value);
  return result.success && result.output.success === false && result.output.result === null &&
    result.output.errors !== undefined && result.output.errors.length > 0 &&
    result.output.errors.every((entry) => v.is(v.looseObject({}), entry));
}

function parseListPage(
  value: BoundaryValue,
  expectedPage: number,
  stage: CustomerGatewayFreshPreflightStage,
): ProviderPage {
  const result = v.safeParse(listPageSchema, value);
  if (!result.success || (result.output.errors?.length ?? 0) !== 0 ||
      (result.output.messages?.length ?? 0) !== 0) fail('provider_mismatch', stage);
  const pageValues = result.output.result;
  const info = result.output.result_info;
  if (
    info.count !== pageValues.length || info.page !== expectedPage || info.per_page !== PAGE_SIZE
  ) fail('provider_mismatch', stage);
  const totalCount = info.total_count ?? null;
  const totalPages = info.total_pages ?? null;
  return Object.freeze({
    values: Object.freeze([...pageValues]),
    count: info.count,
    page: info.page,
    perPage: info.per_page,
    totalCount,
    totalPages,
  });
}

async function collectPaginated(
  call: PreflightCall,
  stage: CustomerGatewayFreshPreflightStage,
  urlForPage: (page: number) => URL,
  totalCountMatchesQuery: boolean,
): Promise<readonly BoundaryValue[]> {
  const values: BoundaryValue[] = [];
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

function zoneListUrl(zoneId: string, path: string, page: number): URL {
  const url = new URL(`/client/v4/zones/${zoneId}${path}`, CLOUDFLARE_API_ORIGIN);
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

function parseMcpServer(value: BoundaryValue): ParsedMcpServer | null {
  const result = v.safeParse(mcpServerSchema, value);
  if (!result.success) return null;
  const endpoint = normalizeHttpsEndpoint(result.output.hostname);
  const description = result.output.description ?? null;
  if (
    endpoint === null ||
    (result.output.name !== undefined && result.output.name !== null && !safeText(result.output.name, 350)) ||
    (description !== null && !safeText(description, 350))
  ) return null;
  return Object.freeze({ id: result.output.id, endpoint, description });
}

function parseDestination(value: BoundaryValue): ParsedDestination | null {
  const container = v.safeParse(destinationContainerSchema, value);
  if (!container.success || !safeText(container.output.type, 128)) return null;
  let mcpServerId: string | null = null;
  let uri: string | null = null;
  let matchesReviewedContract = false;
  if (container.output.type === 'via_mcp_server_portal') {
    const destination = v.safeParse(viaMcpDestinationFieldsSchema, value);
    if (!destination.success) return null;
    mcpServerId = destination.output.mcp_server_id;
    matchesReviewedContract = v.safeParse(viaMcpDestinationSchema, value).success;
  }
  if (container.output.type === 'public') {
    const destination = v.safeParse(publicDestinationFieldsSchema, value);
    if (!destination.success || !safeText(destination.output.uri, 2048)) return null;
    uri = destination.output.uri;
    matchesReviewedContract = v.safeParse(publicDestinationSchema, value).success;
  }
  return Object.freeze({ type: container.output.type, mcpServerId, uri, matchesReviewedContract });
}

function parseAccessApplication(value: BoundaryValue): ParsedAccessApplication | null {
  const result = v.safeParse(accessApplicationSchema, value);
  if (!result.success || !safeText(result.output.type, 128) || !safeText(result.output.name, 350)) return null;
  const domain = result.output.domain ?? null;
  if (domain !== null && !safeText(domain, 2048)) return null;
  const rawDestinations = result.output.destinations ?? [];
  if (rawDestinations.length > 64) return null;
  const destinations: ParsedDestination[] = [];
  for (const destination of rawDestinations) {
    const parsed = parseDestination(destination);
    if (!parsed) return null;
    destinations.push(parsed);
  }
  return Object.freeze({
    id: result.output.id,
    type: result.output.type,
    name: result.output.name,
    domain,
    destinations: Object.freeze(destinations),
  });
}

function parsePortal(value: BoundaryValue): ParsedPortal | null {
  const result = v.safeParse(portalSchema, value);
  if (!result.success) return null;
  const hostname = normalizeHostname(result.output.hostname);
  const name = result.output.name ?? null;
  const description = result.output.description ?? null;
  if (
    hostname === null || (name !== null && !safeText(name, 350)) ||
    (description !== null && !safeText(description, 350))
  ) return null;
  return Object.freeze({
    id: result.output.id,
    hostname,
    name,
    description,
  });
}

function parseDnsRecord(value: BoundaryValue): ParsedDnsRecord | null {
  const result = v.safeParse(dnsRecordSchema, value);
  if (!result.success) return null;
  const name = normalizeHostname(result.output.name);
  const comment = result.output.comment ?? null;
  if (
    name === null || !safeText(result.output.type, 32) || !safeText(result.output.content, 2048) ||
    (comment !== null && !safeText(comment, 350))
  ) return null;
  return Object.freeze({
    id: result.output.id,
    name,
    type: result.output.type,
    content: result.output.content,
    proxied: result.output.proxied,
    comment,
  });
}

function parseUnique<T extends { readonly id: string }>(
  values: readonly BoundaryValue[],
  parser: (value: BoundaryValue) => T | null,
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
      (page) => zoneListUrl(zoneId, '/access/apps', page),
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
    application.destinations[0]?.matchesReviewedContract === true &&
    application.destinations[0].type === 'public' &&
    application.destinations[0].uri === portalApplication.hostname);
  const managementApplications = applications.filter((application) =>
    application.type === 'self_hosted' &&
    managementOwnershipMarkerFromName(application.name, desiredPortal.name) !== null &&
    application.domain === managementHostname && application.destinations.length === 0);
  const managementApplication = managementApplications.length === 1
    ? managementApplications.at(0)
    : undefined;
  const detectedManagementMarker = managementApplication === undefined
    ? null
    : managementOwnershipMarkerFromName(managementApplication.name, desiredPortal.name);
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

async function attestationHash<Value>(value: Value): Promise<string> {
  return `sha256:${await sha256Hex(canonicalCustomerBootstrapJson(value))}`;
}

/**
 * Read every broad customer-gateway candidate set twice and attest only an
 * exact fresh zero state. This function has no provider mutation method.
 */
export async function preflightFreshCustomerGateway(
  input: CustomerGatewayFreshPreflightInput,
): Promise<CustomerGatewayFreshPreflightAttestation> {
  let projection: CustomerGatewayDesiredProjection;
  let managementHostname: string;
  try {
    projection = await prepareCustomerGatewayDesiredProjection(input);
    const parsedPlan = parseStaticDeployPlan(input.plan);
    managementHostname = parsedPlan.gatewayConfiguration.managementHostname;
  } catch {
    fail('invalid_input', 'validate');
  }
  const controls: OptionalFreshPreflightControls = {};
  if (input.timeoutMs !== undefined) controls.timeoutMs = input.timeoutMs;
  if (input.nowMs !== undefined) controls.nowMs = input.nowMs;
  return preflightFreshCustomerGatewayProjection({
    accessToken: input.accessToken,
    transport: input.transport,
    projection,
    managementHostname,
    ...controls,
  });
}

/**
 * Stage 2 variant for a projection rebuilt from the signed static plan inside
 * the customer Worker. It performs the same two complete provider scans as the
 * full release-input wrapper and has no mutation path.
 */
export async function preflightFreshCustomerGatewayProjection(
  input: CustomerGatewayFreshProjectionPreflightInput,
): Promise<CustomerGatewayFreshPreflightAttestation> {
  const call = requireCall(input);
  const projection = input.projection;
  const managementHostname = normalizeHostname(input.managementHostname);
  const expectedKinds = projection.candidates.mcpServer === null
    ? PORTAL_RESOURCE_KINDS
    : RESOURCE_KINDS;
  if (
    managementHostname === null || managementHostname !== input.managementHostname ||
    !ACCOUNT_ID.test(projection.target.accountId) || !ZONE_ID.test(projection.target.zoneId) ||
    projection.resourceKinds.length !== expectedKinds.length ||
    projection.resourceKinds.some((kind, index) => kind !== expectedKinds[index])
  ) fail('invalid_input', 'validate');

  // A complete second scan is the final provider operation. Success is never
  // inferred from the first scan or a pagination count alone.
  await assertZeroCandidates(call, projection, managementHostname);
  await assertZeroCandidates(call, projection, managementHostname);

  const checkedAt = input.nowMs ?? Date.now();
  if (!v.is(nonnegativeIntegerSchema, checkedAt) || projection.plan.planId.length === 0) {
    fail('invalid_input', 'attest');
  }
  const expiresAt = Math.min(checkedAt + ATTESTATION_TTL_MS, projection.plan.expiresAt);
  if (!v.is(nonnegativeIntegerSchema, expiresAt) || expiresAt <= checkedAt) fail('invalid_input', 'attest');
  const unsigned = Object.freeze({
    schemaVersion: 1,
    kind: 'customer_gateway_fresh_preflight',
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
export async function parseCustomerGatewayFreshPreflightAttestation<Input>(
  value: Input,
): Promise<CustomerGatewayFreshPreflightAttestation | null> {
  const parsed = v.safeParse(attestationSchema, value);
  if (!parsed.success) return null;
  const input = parsed.output;
  const candidateKinds = input.zeroCandidateKinds;
  const validCandidateKinds = [RESOURCE_KINDS, PORTAL_RESOURCE_KINDS].some((expected) =>
    candidateKinds.length === expected.length &&
    candidateKinds.every((kind, index) => kind === expected[index]));
  if (
    !validCandidateKinds ||
    input.expiresAt <= input.checkedAt ||
    input.expiresAt - input.checkedAt > MAX_ATTESTATION_TTL_MS
  ) return null;
  const candidate: CustomerGatewayFreshPreflightAttestation = Object.freeze({
    schemaVersion: 1,
    kind: 'customer_gateway_fresh_preflight',
    accountId: input.accountId,
    zoneId: input.zoneId,
    planId: input.planId,
    planHash: input.planHash,
    installationId: input.installationId,
    configurationHash: input.configurationHash,
    desiredHash: input.desiredHash,
    releaseId: input.releaseId,
    releaseArtifactSha256: input.releaseArtifactSha256,
    zeroCandidateKinds: Object.freeze([...candidateKinds]),
    checkedAt: input.checkedAt,
    expiresAt: input.expiresAt,
    attestationHash: input.attestationHash,
  });
  if (await attestationHash(attestationWithoutHash(candidate)) !== candidate.attestationHash) {
    return null;
  }
  return candidate;
}
