import { createCloudflareClient } from './cloudflare-client.mjs';
import { runCloudflareCanaryPreflight } from './canary-preflight.mjs';

const CLOUDFLARE_ID = /^[a-fA-F0-9]{32}$/;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const SAFE_TOKEN = /^[^\u0000-\u001f\u007f]+$/;
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

const CAPABILITY_LABELS = Object.freeze({
  'zone.read': 'Active zone read',
  'access.identity_providers.read': 'Zero Trust identity-provider read',
  'mcp.servers.read': 'MCP server read',
  'mcp.portals.read': 'MCP Portal read',
  'access.applications.read': 'Access application read',
  'dns.records.read': 'DNS record read',
});

const PREREQUISITE_LABELS = Object.freeze({
  selected_target_matches: 'Selected account and zone match',
  zone_active: 'Active zone',
  hostname_in_zone: 'Gateway hostname belongs to selected zone',
  zero_trust_identity_provider: 'Zero Trust identity provider configured',
});

export class CanaryPreflightInputError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CanaryPreflightInputError';
  }
}

/**
 * Compose the CLI-facing preflight while keeping the token out of argv and all
 * returned values. A caller may inject a token closure and client factory for
 * tests or a future customer-owned runtime.
 */
export async function executeCanaryPreflightCommand(invocation = {}, dependencies = {}) {
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
  if (typeof json !== 'boolean') {
    throw new CanaryPreflightInputError('The canary preflight JSON option must be boolean.');
  }

  const readToken = dependencies.readToken ?? (() => process.env.CLOUDFLARE_API_TOKEN);
  const clientFactory = dependencies.clientFactory ?? createCloudflareClient;
  const fetchImpl = dependencies.fetchImpl ?? globalThis.fetch;
  if (typeof readToken !== 'function' || typeof clientFactory !== 'function') {
    throw new CanaryPreflightInputError('The canary preflight runtime is not configured.');
  }

  let token;
  try {
    token = await readToken();
  } catch {
    throw new CanaryPreflightInputError(
      'CLOUDFLARE_API_TOKEN could not be read from the customer-controlled environment.',
    );
  }
  if (typeof token !== 'string' || token.length === 0 || !SAFE_TOKEN.test(token)) {
    throw new CanaryPreflightInputError(
      'CLOUDFLARE_API_TOKEN is required in the customer-controlled environment.',
    );
  }

  let cloudflare;
  try {
    cloudflare = clientFactory({ token, accountId, zoneId, fetchImpl });
  } catch {
    throw new CanaryPreflightInputError('The Cloudflare preflight client could not be initialized.');
  } finally {
    token = undefined;
  }

  let report;
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

export function renderCanaryPreflight(report) {
  if (!isObject(report) || report.kind !== 'cloudflare_canary_preflight') {
    throw new TypeError('report must be a Cloudflare canary preflight report');
  }
  const lines = [
    `Cloudflare canary preflight: ${report.ready === true ? 'READY' : 'NOT READY'}`,
    '',
    'Prerequisites:',
    ...renderStatuses(report.prerequisites, PREREQUISITE_LABELS),
    '',
    'Read capabilities:',
    ...renderStatuses(report.capabilities, CAPABILITY_LABELS),
  ];
  if (Array.isArray(report.diagnostics) && report.diagnostics.length > 0) {
    lines.push('', 'Sanitized diagnostics:');
    for (const diagnostic of report.diagnostics) {
      const label = CAPABILITY_LABELS[diagnostic?.capability] ?? 'Unknown read capability';
      const status =
        Number.isInteger(diagnostic?.httpStatus) &&
        diagnostic.httpStatus >= 0 &&
        diagnostic.httpStatus <= 599
          ? diagnostic.httpStatus
          : 0;
      const codes = Array.isArray(diagnostic?.codes)
        ? diagnostic.codes.filter(
            (code) =>
              typeof code === 'string' &&
              (/^\d{1,10}$/.test(code) || SAFE_DIAGNOSTIC_CODES.has(code)),
          )
        : [];
      lines.push(`  - ${label}: HTTP ${status}; ${codes.length > 0 ? codes.join(',') : 'request_failed'}`);
    }
  }
  lines.push('', 'No Cloudflare resources were changed.');
  return lines.join('\n');
}

export function validateCloudflareId(value, label) {
  const option = label === 'account' ? '--account-id' : label === 'zone' ? '--zone-id' : null;
  if (option === null) {
    throw new CanaryPreflightInputError('Cloudflare identifier type is unsupported.');
  }
  if (typeof value !== 'string' || !CLOUDFLARE_ID.test(value)) {
    throw new CanaryPreflightInputError(
      `${option} must be an explicit 32-character Cloudflare identifier.`,
    );
  }
}

export function validateHostname(value) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 253 ||
    value.endsWith('.') ||
    /[\u0000-\u001f\u007f]/.test(value)
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

function renderStatuses(items, labels) {
  if (!Array.isArray(items) || items.length === 0) return ['  - unavailable'];
  return items.map((item) => {
    const label = labels[item?.key] ?? 'Unknown check';
    const status = SAFE_RENDERED_STATUSES.has(item?.status) ? item.status : 'unavailable';
    return `  - ${label}: ${status}`;
  });
}

function requireExactObject(value, fields, label) {
  if (!isObject(value)) throw new CanaryPreflightInputError(`${label} must be an object.`);
  if (Object.keys(value).some((key) => !fields.includes(key))) {
    throw new CanaryPreflightInputError(`${label} contains unsupported fields.`);
  }
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
