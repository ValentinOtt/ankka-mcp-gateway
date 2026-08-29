import * as v from 'valibot';

import {
  isAccessGroupName,
  MAX_ACCESS_GROUP_NAME_LENGTH,
} from './access-groups.ts';
import { jsonObjectSchema, type JsonObject, type JsonValue } from './json.ts';

const CODE_MODES = new Set(['off', 'opt_in', 'default_on', 'enforced']);
const AUTH_MODES = new Set(['none', 'bearer', 'oauth', 'headers']);
const SOURCE_ID = /^[a-z][a-z0-9-]{0,31}$/u;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const SECRET_KEY = /(?:api[_-]?key|credential|password|private[_-]?key|secret|token)/iu;
const SECRET_METADATA_KEYS = new Set(['credentialCustody']);
const SENSITIVE_QUERY_KEY = /(?:api[_-]?key|auth|credential|password|secret|signature|token)/iu;

export const MAX_ENABLED_TOOLS_PER_SOURCE = 500;

const gatewayConfigSchema = v.strictObject({
  $schema: v.optional(v.string()),
  schemaVersion: v.literal(1),
  gateway: v.strictObject({
    name: v.string(),
    hostname: v.string(),
    codeMode: v.picklist(['off', 'opt_in', 'default_on', 'enforced']),
  }),
  policy: v.strictObject({
    capabilityMode: v.literal('read_only'),
    credentialCustody: v.literal('customer'),
    telemetry: v.literal('off'),
  }),
  sources: v.array(v.strictObject({
    id: v.string(),
    label: v.string(),
    url: v.string(),
    authentication: v.strictObject({
      mode: v.picklist(['none', 'bearer', 'oauth', 'headers']),
      onBehalfOfUser: v.boolean(),
    }),
    accessGroup: v.optional(v.string()),
    enabledTools: v.array(v.string()),
  })),
});

export type GatewayConfig = v.InferOutput<typeof gatewayConfigSchema>;

export class GatewayConfigError extends TypeError {
  readonly errors: readonly string[];

  constructor(errors: readonly string[]) {
    super(`Invalid gateway configuration:\n- ${errors.join('\n- ')}`);
    this.name = 'GatewayConfigError';
    this.errors = errors;
  }
}

export function validateGatewayConfig(input: JsonValue): GatewayConfig {
  const errors: string[] = [];

  if (!isObject(input)) {
    throw new GatewayConfigError(['configuration must be a JSON object']);
  }

  findSecretFields(input, '$', errors);
  rejectUnknownKeys(input, '$', ['$schema', 'schemaVersion', 'gateway', 'policy', 'sources'], errors);

  if (input.schemaVersion !== 1) errors.push('schemaVersion must be 1');

  validateGateway(input.gateway, errors);
  validatePolicy(input.policy, errors);
  validateSources(input.sources, errors);

  if (errors.length > 0) throw new GatewayConfigError(errors);
  return v.parse(gatewayConfigSchema, input);
}

function validateGateway(gateway: JsonValue | undefined, errors: string[]): void {
  if (!isObject(gateway)) {
    errors.push('gateway must be an object');
    return;
  }
  rejectUnknownKeys(gateway, 'gateway', ['name', 'hostname', 'codeMode'], errors);
  requireText(gateway.name, 'gateway.name', 80, errors);
  if (!isHostname(gateway.hostname)) {
    errors.push('gateway.hostname must be a lowercase fully qualified hostname');
  }
  if (!isString(gateway.codeMode) || !CODE_MODES.has(gateway.codeMode)) {
    errors.push('gateway.codeMode is not supported');
  }
}

function validatePolicy(policy: JsonValue | undefined, errors: string[]): void {
  if (!isObject(policy)) {
    errors.push('policy must be an object');
    return;
  }
  rejectUnknownKeys(
    policy,
    'policy',
    ['capabilityMode', 'credentialCustody', 'telemetry'],
    errors,
  );
  if (policy.capabilityMode !== 'read_only') {
    errors.push('policy.capabilityMode must be read_only');
  }
  if (policy.credentialCustody !== 'customer') {
    errors.push('policy.credentialCustody must be customer');
  }
  if (policy.telemetry !== 'off') errors.push('policy.telemetry must be off');
}

function validateSources(sources: JsonValue | undefined, errors: string[]): void {
  if (!Array.isArray(sources) || sources.length === 0) {
    errors.push('sources must contain at least one source');
    return;
  }
  if (sources.length > 40) errors.push('sources cannot contain more than 40 entries');

  const ids = new Set<string>();
  sources.forEach((source, index) => {
    const path = `sources[${index}]`;
    if (!isObject(source)) {
      errors.push(`${path} must be an object`);
      return;
    }
    rejectUnknownKeys(
      source,
      path,
      ['id', 'label', 'url', 'authentication', 'accessGroup', 'enabledTools'],
      errors,
    );
    if (!isString(source.id) || !SOURCE_ID.test(source.id)) {
      errors.push(`${path}.id must use lowercase letters, numbers, and hyphens`);
    } else if (ids.has(source.id)) {
      errors.push(`${path}.id duplicates ${source.id}`);
    } else {
      ids.add(source.id);
    }
    requireText(source.label, `${path}.label`, 80, errors);
    if (source.accessGroup !== undefined && !isAccessGroupName(source.accessGroup)) {
      errors.push(
        `${path}.accessGroup must be an exact non-empty group name of at most `
          + `${MAX_ACCESS_GROUP_NAME_LENGTH} characters`,
      );
    }
    validateSourceUrl(source.url, `${path}.url`, errors);
    validateAuthentication(source.authentication, `${path}.authentication`, errors);
    validateTools(source.enabledTools, `${path}.enabledTools`, errors);
  });
}

function validateSourceUrl(value: JsonValue | undefined, path: string, errors: string[]): void {
  if (!isString(value)) {
    errors.push(`${path} must be a valid HTTPS URL`);
    return;
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    errors.push(`${path} must be a valid HTTPS URL`);
    return;
  }
  if (url.protocol !== 'https:' || url.username || url.password) {
    errors.push(`${path} must be HTTPS and contain no embedded credentials`);
  }
  if (!isHostname(url.hostname) || url.hostname.endsWith('.local')) {
    errors.push(`${path} must use a public fully qualified hostname`);
  }
  for (const key of url.searchParams.keys()) {
    if (SENSITIVE_QUERY_KEY.test(key)) {
      errors.push(`${path} must not contain credential-like query parameters`);
    }
  }
}

function validateAuthentication(
  authentication: JsonValue | undefined,
  path: string,
  errors: string[],
): void {
  if (!isObject(authentication)) {
    errors.push(`${path} must be an object`);
    return;
  }
  rejectUnknownKeys(authentication, path, ['mode', 'onBehalfOfUser'], errors);
  if (!isString(authentication.mode) || !AUTH_MODES.has(authentication.mode)) {
    errors.push(`${path}.mode is not supported`);
  }
  if (!v.is(v.boolean(), authentication.onBehalfOfUser)) {
    errors.push(`${path}.onBehalfOfUser must be a boolean`);
  } else if (authentication.mode === 'none' && authentication.onBehalfOfUser !== false) {
    errors.push(`${path}.onBehalfOfUser must be false when mode is none`);
  }
}

function validateTools(tools: JsonValue | undefined, path: string, errors: string[]): void {
  if (!Array.isArray(tools) || tools.length === 0) {
    errors.push(`${path} must contain at least one exact tool name`);
    return;
  }
  if (tools.length > MAX_ENABLED_TOOLS_PER_SOURCE) {
    errors.push(
      `${path} cannot contain more than ${MAX_ENABLED_TOOLS_PER_SOURCE} entries`,
    );
  }
  const seen = new Set<string>();
  tools.forEach((tool, index) => {
    if (!isString(tool) || tool.trim() === '' || tool.length > 128) {
      errors.push(`${path}[${index}] must be a non-empty tool name`);
    } else if (tool === '*') {
      errors.push(`${path}[${index}] must not be a wildcard`);
    } else if (seen.has(tool)) {
      errors.push(`${path}[${index}] duplicates ${tool}`);
    } else {
      seen.add(tool);
    }
  });
}

function findSecretFields(value: JsonValue, path: string, errors: string[]): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => findSecretFields(item, `${path}[${index}]`, errors));
    return;
  }
  if (!isObject(value)) return;
  for (const [key, child] of Object.entries(value)) {
    const childPath = `${path}.${key}`;
    if (SECRET_KEY.test(key) && !SECRET_METADATA_KEYS.has(key)) {
      errors.push(`${childPath} is a forbidden secret-bearing field`);
    }
    findSecretFields(child, childPath, errors);
  }
}

function isHostname(value: JsonValue | undefined): value is string {
  if (!isString(value) || value.length > 253 || value !== value.toLowerCase()) return false;
  if (isIpLiteral(value)) return false;
  const labels = value.split('.');
  return labels.length >= 2 && labels.every((label) => HOST_LABEL.test(label));
}

function isIpLiteral(value: string): boolean {
  if (value.includes(':') || value.startsWith('[') || value.endsWith(']')) return true;
  return /^(?:\d+\.)+\d+$/u.test(value);
}

function rejectUnknownKeys(
  value: JsonObject,
  path: string,
  allowedKeys: readonly string[],
  errors: string[],
): void {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) errors.push(`${path}.${key} is not supported`);
  }
}

function requireText(
  value: JsonValue | undefined,
  path: string,
  maxLength: number,
  errors: string[],
): void {
  if (!isString(value) || value.trim() === '' || value.length > maxLength) {
    errors.push(`${path} must be a non-empty string of at most ${maxLength} characters`);
  }
}

function isObject(value: JsonValue | undefined): value is JsonObject {
  return v.is(jsonObjectSchema, value);
}

function isString(value: JsonValue | undefined): value is string {
  return v.is(v.string(), value);
}
