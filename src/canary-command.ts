import * as v from 'valibot';

import {
  createCloudflareClient,
  type CloudflareClientOptions,
  type CloudflareFetch,
} from './cloudflare-client.ts';
import {
  runCloudflareCanaryPreflight,
  type CloudflareCanaryPreflightReport,
  type CloudflarePreflightClient,
} from './canary-preflight.ts';
import type { BoundaryValue } from './json.ts';

const CLOUDFLARE_ID = /^[a-fA-F0-9]{32}$/;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const stringSchema = v.string();
const booleanSchema = v.boolean();
const functionSchema = v.function();
const renderedReportSchema = v.object({
  capabilities: v.array(v.object({ key: v.string(), status: v.string() })),
  diagnostics: v.array(v.object({
    capability: v.string(),
    codes: v.array(v.string()),
    httpStatus: v.number(),
  })),
  kind: v.literal('cloudflare_canary_preflight'),
  prerequisites: v.array(v.object({ key: v.string(), status: v.string() })),
  ready: v.boolean(),
});
const SAFE_RENDERED_STATUSES = new Set([
  'available',
  'denied',
  'failed',
  'not_found',
  'not_ready',
  'ready',
  'skipped',
  'unavailable',
]);
const SAFE_DIAGNOSTIC_CODES = new Set([
  'invalid_response',
  'network_error',
  'not_found',
  'pagination_limit',
  'request_failed',
  'hostname_outside_zone',
  'target_mismatch',
  'unexpected_error',
  'zone_inactive',
]);

const CAPABILITY_LABELS = new Map([
  ['zone.read', 'Active zone read'],
  ['access.identity_providers.read', 'Zero Trust identity-provider read'],
  ['mcp.servers.read', 'MCP server read'],
  ['mcp.portals.read', 'MCP Portal read'],
  ['access.applications.read', 'Access application read'],
  ['dns.records.read', 'DNS record read'],
]);

const PREREQUISITE_LABELS = new Map([
  ['selected_target_matches', 'Selected account and zone match'],
  ['zone_active', 'Active zone'],
  ['hostname_in_zone', 'Gateway hostname belongs to selected zone'],
  ['zero_trust_identity_provider', 'Zero Trust identity provider configured'],
]);

export interface CanaryPreflightInvocation {
  readonly accountId: string;
  readonly hostname: string;
  readonly json?: boolean;
  readonly zoneId: string;
}

type TokenReader = () => BoundaryValue | Promise<BoundaryValue>;
type ClientFactory = (options: CloudflareClientOptions) => CloudflarePreflightClient;

export interface CanaryPreflightDependencies {
  readonly clientFactory?: ClientFactory;
  readonly fetchImpl?: CloudflareFetch;
  readonly readToken?: TokenReader;
}

export interface CanaryPreflightCommandResult {
  readonly exitCode: 0 | 1;
  readonly output: string;
  readonly report: CloudflareCanaryPreflightReport;
}

type RenderedStatus = v.InferOutput<typeof renderedReportSchema>['capabilities'][number];

export class CanaryPreflightInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CanaryPreflightInputError';
  }
}

/**
 * Compose the CLI-facing preflight while keeping the token out of argv and all
 * returned values. A caller may inject a token closure and client factory for
 * tests or a future customer-owned runtime.
 */
const defaultCloudflareFetch: CloudflareFetch = async (url, init) =>
  globalThis.fetch(url, init);

export async function executeCanaryPreflightCommand(
  invocation: CanaryPreflightInvocation,
  dependencies: CanaryPreflightDependencies = {},
): Promise<CanaryPreflightCommandResult> {
  requireExactObject(
    invocation,
    ['accountId', 'zoneId', 'hostname', 'json'],
    'canary preflight invocation',
  );
  requireExactObject(
    dependencies,
    ['readToken', 'clientFactory', 'fetchImpl'],
    'canary preflight dependencies',
  );
  const { accountId, zoneId, json = false } = invocation;
  const hostname = validateHostname(invocation.hostname);
  validateCloudflareId(accountId, 'account');
  validateCloudflareId(zoneId, 'zone');
  if (!v.is(booleanSchema, json)) {
    throw new CanaryPreflightInputError('The canary preflight JSON option must be boolean.');
  }

  const readToken = dependencies.readToken ?? (() => process.env.CLOUDFLARE_API_TOKEN);
  const clientFactory = dependencies.clientFactory ?? createCloudflareClient;
  const fetchImpl = dependencies.fetchImpl ?? defaultCloudflareFetch;
  if (!v.safeParse(functionSchema, readToken).success
    || !v.safeParse(functionSchema, clientFactory).success) {
    throw new CanaryPreflightInputError('The canary preflight runtime is not configured.');
  }

  let token: BoundaryValue;
  try {
    token = await readToken();
  } catch {
    throw new CanaryPreflightInputError(
      'CLOUDFLARE_API_TOKEN could not be read from the customer-controlled environment.',
    );
  }
  if (!v.is(stringSchema, token) || token.length === 0 || hasControlCharacters(token)) {
    throw new CanaryPreflightInputError(
      'CLOUDFLARE_API_TOKEN is required in the customer-controlled environment.',
    );
  }

  let cloudflare: CloudflarePreflightClient;
  try {
    cloudflare = clientFactory({ token, accountId, zoneId, fetchImpl });
  } catch {
    throw new CanaryPreflightInputError('The Cloudflare preflight client could not be initialized.');
  } finally {
    token = undefined;
  }

  let report: CloudflareCanaryPreflightReport;
  try {
    report = await runCloudflareCanaryPreflight({
      cloudflare,
      accountId,
      zoneId,
      hostname,
    });
  } catch {
    throw new CanaryPreflightInputError(
      'Cloudflare canary preflight could not be completed safely.',
    );
  }
  return Object.freeze({
    report,
    output: json ? JSON.stringify(report, null, 2) : renderCanaryPreflight(report),
    exitCode: report.ready ? 0 : 1,
  });
}

export function renderCanaryPreflight(
  report: BoundaryValue | CloudflareCanaryPreflightReport,
): string {
  const parsed = v.safeParse(renderedReportSchema, report);
  if (!parsed.success) {
    throw new TypeError('report must be a Cloudflare canary preflight report');
  }
  const safeReport = parsed.output;
  const lines = [
    `Cloudflare canary preflight: ${safeReport.ready ? 'READY' : 'NOT READY'}`,
    '',
    'Prerequisites:',
    ...renderStatuses(safeReport.prerequisites, PREREQUISITE_LABELS),
    '',
    'Read capabilities:',
    ...renderStatuses(safeReport.capabilities, CAPABILITY_LABELS),
  ];
  if (safeReport.diagnostics.length > 0) {
    lines.push('', 'Sanitized diagnostics:');
    for (const diagnostic of safeReport.diagnostics) {
      const label = CAPABILITY_LABELS.get(diagnostic.capability) ?? 'Unknown read capability';
      const status =
        Number.isInteger(diagnostic.httpStatus) &&
        diagnostic.httpStatus >= 0 &&
        diagnostic.httpStatus <= 599
          ? diagnostic.httpStatus
          : 0;
      const codes = diagnostic.codes.filter(
        (code) => /^\d{1,10}$/.test(code) || SAFE_DIAGNOSTIC_CODES.has(code),
      );
      lines.push(`  - ${label}: HTTP ${status}; ${codes.length > 0 ? codes.join(',') : 'request_failed'}`);
    }
  }
  lines.push('', 'No Cloudflare resources were changed.');
  return lines.join('\n');
}

export function validateCloudflareId(value: string, label: string): void {
  const option = label === 'account' ? '--account-id' : label === 'zone' ? '--zone-id' : null;
  if (option === null) {
    throw new CanaryPreflightInputError('Cloudflare identifier type is unsupported.');
  }
  if (!v.is(stringSchema, value) || !CLOUDFLARE_ID.test(value)) {
    throw new CanaryPreflightInputError(
      `${option} must be an explicit 32-character Cloudflare identifier.`,
    );
  }
}

export function validateHostname(value: string): string {
  if (
    !v.is(stringSchema, value) ||
    value.length === 0 ||
    value.length > 253 ||
    value.endsWith('.') ||
    hasControlCharacters(value)
  ) {
    throw new CanaryPreflightInputError(
      '--hostname must be an explicit valid DNS hostname.',
    );
  }
  const normalized = value.toLowerCase();
  if (
    normalized.split('.').length < 2 ||
    normalized.split('.').some((part) => !DNS_LABEL.test(part))
  ) {
    throw new CanaryPreflightInputError(
      '--hostname must be an explicit valid DNS hostname.',
    );
  }
  return normalized;
}

function renderStatuses(
  items: readonly RenderedStatus[],
  labels: ReadonlyMap<string, string>,
): string[] {
  if (items.length === 0) return ['  - unavailable'];
  return items.map((item) => {
    const label = labels.get(item.key) ?? 'Unknown check';
    const status = SAFE_RENDERED_STATUSES.has(item.status) ? item.status : 'unavailable';
    return `  - ${label}: ${status}`;
  });
}

function requireExactObject(
  value: CanaryPreflightDependencies | CanaryPreflightInvocation,
  fields: readonly string[],
  label: string,
): void {
  if (!v.is(v.object({}), value)) {
    throw new CanaryPreflightInputError(`${label} must be an object.`);
  }
  if (Object.keys(value).some((key) => !fields.includes(key))) {
    throw new CanaryPreflightInputError(`${label} contains unsupported fields.`);
  }
}

function hasControlCharacters(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && (codePoint <= 31 || codePoint === 127);
  });
}
