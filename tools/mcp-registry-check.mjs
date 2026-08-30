import { createHash } from 'node:crypto';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import * as v from 'valibot';

export const OFFICIAL_REGISTRY_ORIGIN = 'https://registry.modelcontextprotocol.io';
export const OFFICIAL_REGISTRY_API_VERSION = 'v0.1';
export const SUPPORTED_SERVER_SCHEMA_REVISION = '2025-12-11';
export const SUPPORTED_SERVER_SCHEMA_URL =
  `https://static.modelcontextprotocol.io/schemas/${SUPPORTED_SERVER_SCHEMA_REVISION}/server.schema.json`;

const MAX_RESPONSE_BYTES = 1024 * 1024;
const REQUEST_TIMEOUT_MS = 10_000;
const MAX_REMOTES = 100;
const MAX_PACKAGES = 100;
const MAX_REMOTE_INPUTS = 100;
const MAX_CANONICAL_DEPTH = 64;
const MAX_CANONICAL_NODES = 50_000;
const SERVER_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,127})\/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,127})$/u;
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const BLOCKED_HOST_SUFFIXES = ['.internal', '.invalid', '.local', '.localhost', '.onion', '.test'];
const OBJECT_SCHEMA = v.object({});
const STRING_SCHEMA = v.string();
const BOOLEAN_SCHEMA = v.boolean();
const NUMBER_SCHEMA = v.number();
const FUNCTION_SCHEMA = v.function();
const REMOTE_FIELDS = new Set(['headers', 'type', 'url', 'variables']);
const INPUT_FIELDS = new Set([
  'choices',
  'default',
  'description',
  'format',
  'isRequired',
  'isSecret',
  'placeholder',
  'value',
]);
const KEY_VALUE_INPUT_FIELDS = new Set([...INPUT_FIELDS, 'name', 'variables']);

const USAGE = `Usage:
  node tools/mcp-registry-check.mjs \\
    --server <registry-server-name> \\
    --version <exact-version> \\
    [--expect-record-sha256 <sha256:digest>]

Fetches one exact record from the official MCP Registry and prints only a
bounded review summary. It never updates the source catalog.`;

export const MCP_REGISTRY_CHECK_CODES = Object.freeze([
  'argument_invalid',
  'registry_record_digest_mismatch',
  'registry_record_invalid',
  'registry_record_not_found',
  'registry_request_timeout',
  'registry_response_invalid',
  'registry_response_too_large',
  'registry_schema_unsupported',
  'registry_unavailable',
]);

const CODE_SET = new Set(MCP_REGISTRY_CHECK_CODES);

export class McpRegistryCheckError extends Error {
  constructor(code) {
    super('mcp_registry_check_failed');
    this.name = 'McpRegistryCheckError';
    this.code = CODE_SET.has(code) ? code : 'registry_response_invalid';
  }
}

function fail(code) {
  throw new McpRegistryCheckError(code);
}

function isRecord(value) {
  return v.is(OBJECT_SCHEMA, value) && !Array.isArray(value);
}

function isExactVersion(value) {
  return v.is(STRING_SCHEMA, value) && value.length > 0 && value.length <= 128 &&
    value.trim() === value && !['*', '.', '..', 'latest'].includes(value.toLowerCase()) &&
    !hasControlCharacter(value);
}

function isRegistryServerName(value) {
  return v.is(STRING_SCHEMA, value) && SERVER_NAME.test(value);
}

function isObservedAt(value) {
  if (!v.is(STRING_SCHEMA, value) || !/^\d{4}-\d{2}-\d{2}$/u.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(date.valueOf()) && date.toISOString().slice(0, 10) === value;
}

function isPhaseOneRemote(remote) {
  if (remote.type !== 'streamable-http' || remote.hasHeaders || remote.hasVariables ||
      remote.url.includes('{') || remote.url.includes('}')) return false;
  let url;
  try {
    url = new URL(remote.url);
  } catch {
    return false;
  }
  const hostname = url.hostname.toLowerCase();
  if (
    url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash ||
    url.pathname === '/' || url.hostname !== hostname || !isHostname(hostname) ||
    hostname === 'localhost' || BLOCKED_HOST_SUFFIXES.some((suffix) => hostname.endsWith(suffix))
  ) return false;
  return url.href === remote.url;
}

function isHostname(value) {
  if (value.length > 253 || /^(?:\d+\.)+\d+$/u.test(value)) return false;
  const labels = value.split('.');
  return labels.length >= 2 && labels.every((label) =>
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label));
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function hasControlCharacter(value) {
  return [...value].some((character) => {
    const point = character.codePointAt(0);
    return point <= 31 || point === 127;
  });
}

export function canonicalRegistryJson(value) {
  return canonicalJsonValue(value, { nodes: 0 }, 0);
}

function canonicalJsonValue(value, state, depth) {
  state.nodes += 1;
  if (depth > MAX_CANONICAL_DEPTH || state.nodes > MAX_CANONICAL_NODES) {
    fail('registry_record_invalid');
  }
  if (value === null || v.is(BOOLEAN_SCHEMA, value) || v.is(STRING_SCHEMA, value)) {
    return JSON.stringify(value);
  }
  if (v.is(NUMBER_SCHEMA, value)) {
    if (!Number.isFinite(value)) fail('registry_record_invalid');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJsonValue(entry, state, depth + 1)).join(',')}]`;
  }
  if (!isRecord(value)) fail('registry_record_invalid');
  return `{${Object.keys(value).sort(compareText).map((key) =>
    `${JSON.stringify(key)}:${canonicalJsonValue(value[key], state, depth + 1)}`).join(',')}}`;
}

function registryRecordSha256(server) {
  return `sha256:${createHash('sha256').update(canonicalRegistryJson(server), 'utf8').digest('hex')}`;
}

function hasValidInputProperties(input) {
  return (!Object.hasOwn(input, 'choices') || (
    Array.isArray(input.choices) && input.choices.every((choice) => v.is(STRING_SCHEMA, choice))
  )) &&
    (!Object.hasOwn(input, 'default') || v.is(STRING_SCHEMA, input.default)) &&
    (!Object.hasOwn(input, 'description') || v.is(STRING_SCHEMA, input.description)) &&
    (!Object.hasOwn(input, 'format') ||
      ['boolean', 'filepath', 'number', 'string'].includes(input.format)) &&
    (!Object.hasOwn(input, 'isRequired') || v.is(BOOLEAN_SCHEMA, input.isRequired)) &&
    (!Object.hasOwn(input, 'isSecret') || v.is(BOOLEAN_SCHEMA, input.isSecret)) &&
    (!Object.hasOwn(input, 'placeholder') || v.is(STRING_SCHEMA, input.placeholder)) &&
    (!Object.hasOwn(input, 'value') || v.is(STRING_SCHEMA, input.value));
}

function isInput(input) {
  return isRecord(input) && Object.keys(input).every((key) => INPUT_FIELDS.has(key)) &&
    hasValidInputProperties(input);
}

function isRemoteVariables(value) {
  return isRecord(value) && Object.keys(value).length <= MAX_REMOTE_INPUTS &&
    Object.values(value).every(isInput);
}

function isHeaderInput(value) {
  return isRecord(value) && Object.keys(value).every((key) => KEY_VALUE_INPUT_FIELDS.has(key)) &&
    v.is(STRING_SCHEMA, value.name) && hasValidInputProperties(value) &&
    (!Object.hasOwn(value, 'variables') || isRemoteVariables(value.variables));
}

function normalizeRemotes(value) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > MAX_REMOTES) fail('registry_record_invalid');
  const identities = new Set();
  const remotes = value.map((remote) => {
    if (!isRecord(remote) || !['streamable-http', 'sse'].includes(remote.type) ||
        !v.is(STRING_SCHEMA, remote.url) || remote.url.length === 0 ||
        remote.url.length > 2_048 || hasControlCharacter(remote.url) ||
        Object.keys(remote).some((key) => !REMOTE_FIELDS.has(key)) ||
        (Object.hasOwn(remote, 'headers') && (
          !Array.isArray(remote.headers) || remote.headers.length > MAX_REMOTE_INPUTS ||
          remote.headers.some((header) => !isHeaderInput(header))
        )) ||
        (Object.hasOwn(remote, 'variables') && !isRemoteVariables(remote.variables))) {
      fail('registry_record_invalid');
    }
    const normalized = {
      type: remote.type,
      url: remote.url,
      hasHeaders: Object.hasOwn(remote, 'headers'),
      hasVariables: Object.hasOwn(remote, 'variables'),
    };
    const identity = `${normalized.type}\u0000${normalized.url}`;
    if (identities.has(identity)) fail('registry_record_invalid');
    identities.add(identity);
    return { ...normalized, phaseOneCompatible: isPhaseOneRemote(normalized) };
  });
  return remotes.sort((left, right) =>
    compareText(`${left.type}\u0000${left.url}`, `${right.type}\u0000${right.url}`));
}

function packageCount(value) {
  if (value === undefined) return 0;
  if (!Array.isArray(value) || value.length > MAX_PACKAGES ||
      value.some((entry) => !isRecord(entry))) {
    fail('registry_record_invalid');
  }
  return value.length;
}

/**
 * Validate one exact Registry response and reduce it to public review fields.
 * Descriptions, publisher-authored metadata, arguments, and environment inputs
 * are intentionally omitted from output.
 */
export function inspectRegistryRecord(
  payload,
  {
    serverName,
    serverVersion,
    expectedRecordSha256,
    observedAt = new Date().toISOString().slice(0, 10),
  },
) {
  if (!isRegistryServerName(serverName) || !isExactVersion(serverVersion) ||
      (expectedRecordSha256 !== undefined && (
        !v.is(STRING_SCHEMA, expectedRecordSha256) || !SHA256.test(expectedRecordSha256)
      )) || !isObservedAt(observedAt)) {
    fail('argument_invalid');
  }
  if (!isRecord(payload) || !isRecord(payload.server) || !isRecord(payload._meta)) {
    fail('registry_record_invalid');
  }
  const server = payload.server;
  if (server.name !== serverName || server.version !== serverVersion) {
    fail('registry_record_invalid');
  }
  if (server.$schema !== SUPPORTED_SERVER_SCHEMA_URL) fail('registry_schema_unsupported');
  const packages = packageCount(server.packages);

  const official = payload._meta['io.modelcontextprotocol.registry/official'];
  if (!isRecord(official) || !['active', 'deprecated', 'deleted'].includes(official.status) ||
      !v.is(BOOLEAN_SCHEMA, official.isLatest)) {
    fail('registry_record_invalid');
  }

  const recordSha256 = registryRecordSha256(server);
  if (expectedRecordSha256 !== undefined && recordSha256 !== expectedRecordSha256) {
    fail('registry_record_digest_mismatch');
  }
  const remotes = normalizeRemotes(server.remotes);
  const phaseOneRemotes = remotes
    .filter((remote) => remote.phaseOneCompatible)
    .map((remote) => Object.freeze({ type: remote.type, url: remote.url }));
  return Object.freeze({
    schemaVersion: 1,
    registryOrigin: OFFICIAL_REGISTRY_ORIGIN,
    registryApiVersion: OFFICIAL_REGISTRY_API_VERSION,
    serverSchemaRevision: SUPPORTED_SERVER_SCHEMA_REVISION,
    serverName,
    serverVersion,
    status: official.status,
    isLatest: official.isLatest,
    observedAt,
    recordSha256,
    packageCount: packages,
    remoteCount: remotes.length,
    phaseOneCandidateCount: official.status === 'active'
      ? phaseOneRemotes.length
      : 0,
    phaseOneRemotes: Object.freeze(official.status === 'active' ? phaseOneRemotes : []),
  });
}

async function readBoundedJson(response) {
  const declared = response.headers.get('content-length');
  if (declared !== null && (
    !/^\d+$/u.test(declared) || !Number.isSafeInteger(Number(declared)) ||
    Number(declared) > MAX_RESPONSE_BYTES
  )) {
    await response.body?.cancel().catch(() => {});
    fail('registry_response_too_large');
  }
  if (!response.body) fail('registry_response_invalid');
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.byteLength > MAX_RESPONSE_BYTES - total) {
        await reader.cancel().catch(() => {});
        fail('registry_response_too_large');
      }
      if (value.byteLength > 0) {
        chunks.push(value.slice());
        total += value.byteLength;
      }
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    try {
      const serialized = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      return JSON.parse(serialized);
    } catch {
      fail('registry_response_invalid');
    } finally {
      bytes.fill(0);
    }
  } catch (error) {
    if (error instanceof McpRegistryCheckError) throw error;
    await reader.cancel().catch(() => {});
    fail('registry_response_invalid');
  } finally {
    for (const chunk of chunks) chunk.fill(0);
    try { reader.releaseLock(); } catch { /* The fixed error remains authoritative. */ }
  }
}

export async function checkOfficialRegistryRecord(
  serverName,
  serverVersion,
  { fetchImpl = globalThis.fetch, expectedRecordSha256, observedAt } = {},
) {
  if (!isRegistryServerName(serverName) || !isExactVersion(serverVersion) ||
      !v.is(FUNCTION_SCHEMA, fetchImpl)) {
    fail('argument_invalid');
  }
  const endpoint = `${OFFICIAL_REGISTRY_ORIGIN}/${OFFICIAL_REGISTRY_API_VERSION}/servers/${encodeURIComponent(serverName)}/versions/${encodeURIComponent(serverVersion)}`;
  let response;
  try {
    response = await fetchImpl(endpoint, {
      method: 'GET',
      redirect: 'error',
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    if (error?.name === 'AbortError' || error?.name === 'TimeoutError') {
      fail('registry_request_timeout');
    }
    fail('registry_unavailable');
  }
  if (!(response instanceof Response) || response.redirected) fail('registry_response_invalid');
  if (response.status === 404) {
    await response.body?.cancel().catch(() => {});
    fail('registry_record_not_found');
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => {});
    fail('registry_unavailable');
  }
  const contentType = (response.headers.get('content-type') ?? '').toLowerCase();
  if (!contentType.startsWith('application/json')) {
    await response.body?.cancel().catch(() => {});
    fail('registry_response_invalid');
  }
  const payload = await readBoundedJson(response);
  return inspectRegistryRecord(payload, {
    serverName,
    serverVersion,
    expectedRecordSha256,
    observedAt: observedAt ?? new Date().toISOString().slice(0, 10),
  });
}

function parseArguments(argv) {
  if (argv.length === 1 && ['--help', '-h'].includes(argv[0])) return { help: true };
  const output = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (value === undefined || Object.hasOwn(output, flag)) fail('argument_invalid');
    if (!['--server', '--version', '--expect-record-sha256'].includes(flag)) {
      fail('argument_invalid');
    }
    output[flag] = value;
  }
  if (!isRegistryServerName(output['--server']) || !isExactVersion(output['--version'])) {
    fail('argument_invalid');
  }
  if (output['--expect-record-sha256'] !== undefined &&
      !SHA256.test(output['--expect-record-sha256'])) {
    fail('argument_invalid');
  }
  return {
    help: false,
    serverName: output['--server'],
    serverVersion: output['--version'],
    expectedRecordSha256: output['--expect-record-sha256'],
  };
}

export async function main(argv = process.argv.slice(2)) {
  try {
    const args = parseArguments(argv);
    if (args.help) {
      process.stdout.write(`${USAGE}\n`);
      return 0;
    }
    const result = await checkOfficialRegistryRecord(args.serverName, args.serverVersion, {
      expectedRecordSha256: args.expectedRecordSha256,
    });
    process.stdout.write(`${canonicalRegistryJson(result)}\n`);
    return 0;
  } catch (error) {
    const code = error instanceof McpRegistryCheckError ? error.code : 'registry_response_invalid';
    process.stderr.write(`MCP Registry check failed: ${code}.\n`);
    return 1;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exitCode = await main();
}
