import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import * as v from 'valibot';
import { validateGatewayConfig } from '../src/config.ts';

const PROTOCOL_VERSION = '2026-07-28';
const CLIENT_NAME = 'ankka-live-source-catalogue-verifier';
const CLIENT_VERSION = '1.0.0';
const MAX_CONFIG_BYTES = 1024 * 1024;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAX_AGGREGATE_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_TOOL_COUNT = 500;
const MAX_PAGES = 20;
const MAX_CURSOR_LENGTH = 2_048;
const REQUEST_TIMEOUT_MS = 8_000;
const TOTAL_TIMEOUT_MS = 30_000;
const FUNCTION_SCHEMA = v.function();
const OBJECT_SCHEMA = v.object({});
const STRING_SCHEMA = v.string();

export const LIVE_SOURCE_CATALOGUE_CODES = Object.freeze([
  'ok',
  'argument_invalid',
  'config_read_failed',
  'config_too_large',
  'config_invalid',
  'source_not_found',
  'source_authentication_required',
  'source_authentication_unsupported',
  'source_unreachable',
  'source_request_timeout',
  'source_http_rejected',
  'source_response_too_large',
  'source_response_invalid',
  'source_tool_list_invalid',
  'catalogue_mismatch',
  'internal_failure',
]);

const CODE_SET = new Set(LIVE_SOURCE_CATALOGUE_CODES);

export class LiveSourceCatalogueError extends Error {
  constructor(code) {
    super('live_source_catalogue_failure');
    this.name = 'LiveSourceCatalogueError';
    this.code = CODE_SET.has(code) && code !== 'ok' ? code : 'internal_failure';
  }
}

function fail(code) {
  throw new LiveSourceCatalogueError(code);
}

function isRecord(value) {
  return v.is(OBJECT_SCHEMA, value) && !Array.isArray(value);
}

function hasControlCharacter(value) {
  return [...value].some((character) => {
    const point = character.codePointAt(0);
    return point <= 31 || point === 127;
  });
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function catalogueDigest(names) {
  return `sha256:${createHash('sha256').update(JSON.stringify(names), 'utf8').digest('hex')}`;
}

function modernRequestMeta() {
  return {
    'io.modelcontextprotocol/protocolVersion': PROTOCOL_VERSION,
    'io.modelcontextprotocol/clientInfo': {
      name: CLIENT_NAME,
      version: CLIENT_VERSION,
    },
    'io.modelcontextprotocol/clientCapabilities': {},
  };
}

async function readBoundedBody(response, remainingBytes) {
  const limit = Math.min(MAX_RESPONSE_BYTES, remainingBytes);
  const declared = response.headers.get('content-length');
  if (declared !== null && (
    !/^\d+$/u.test(declared)
    || !Number.isSafeInteger(Number(declared))
    || Number(declared) > limit
  )) {
    await response.body?.cancel().catch(() => {});
    fail('source_response_too_large');
  }
  if (!response.body) fail('source_response_invalid');
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.byteLength > limit - total) {
        await reader.cancel().catch(() => {});
        fail('source_response_too_large');
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
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } finally {
      bytes.fill(0);
    }
  } catch (error) {
    if (error instanceof LiveSourceCatalogueError) throw error;
    await reader.cancel().catch(() => {});
    fail('source_response_invalid');
  } finally {
    for (const chunk of chunks) chunk.fill(0);
    try { reader.releaseLock(); } catch { /* The fixed result remains authoritative. */ }
  }
}

function parseJsonRpcMessage(serialized, contentType, id) {
  const candidates = [];
  if (contentType.startsWith('application/json')) {
    try {
      candidates.push(JSON.parse(serialized));
    } catch {
      fail('source_response_invalid');
    }
  } else if (contentType.startsWith('text/event-stream')) {
    for (const event of serialized.split(/\r?\n\r?\n/u)) {
      const data = event.split(/\r?\n/u)
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice(5).trimStart())
        .join('\n');
      if (data.length === 0) continue;
      try {
        candidates.push(JSON.parse(data));
      } catch {
        fail('source_response_invalid');
      }
    }
  } else {
    fail('source_response_invalid');
  }
  const message = candidates.find((candidate) => (
    isRecord(candidate) && candidate.jsonrpc === '2.0' && candidate.id === id
  ));
  if (!message) fail('source_response_invalid');
  return message;
}

function parseToolPage(serialized, contentType, id, names, cursors) {
  const message = parseJsonRpcMessage(serialized, contentType, id);
  if (
    !isRecord(message.result)
    || Object.hasOwn(message, 'error')
    || !Array.isArray(message.result.tools)
  ) {
    fail('source_response_invalid');
  }

  for (const tool of message.result.tools) {
    if (
      !isRecord(tool)
      || !v.is(STRING_SCHEMA, tool.name)
      || tool.name.trim() === ''
      || tool.name.length > 128
      || names.has(tool.name)
      || names.size >= MAX_TOOL_COUNT
    ) {
      fail('source_tool_list_invalid');
    }
    names.add(tool.name);
  }

  if (!Object.hasOwn(message.result, 'nextCursor')) return undefined;
  const cursor = message.result.nextCursor;
  if (
    !v.is(STRING_SCHEMA, cursor)
    || cursor.length === 0
    || cursor.length > MAX_CURSOR_LENGTH
    || hasControlCharacter(cursor)
    || cursors.has(cursor)
  ) {
    fail('source_tool_list_invalid');
  }
  cursors.add(cursor);
  return cursor;
}

async function listLiveToolNames(endpoint, fetchImpl, oauthAccessToken) {
  const names = new Set();
  const cursors = new Set();
  const deadline = Date.now() + TOTAL_TIMEOUT_MS;
  let aggregateBytes = 0;
  let cursor;

  for (let page = 0; page < MAX_PAGES; page += 1) {
    const remainingTime = deadline - Date.now();
    if (remainingTime <= 0) fail('source_request_timeout');
    const id = page + 1;
    const params = {
      _meta: modernRequestMeta(),
    };
    if (cursor !== undefined) params.cursor = cursor;

    const headers = {
      Accept: 'application/json, text/event-stream',
      'Content-Type': 'application/json',
      'MCP-Protocol-Version': PROTOCOL_VERSION,
      'Mcp-Method': 'tools/list',
    };
    if (oauthAccessToken !== undefined) headers.authorization = `Bearer ${oauthAccessToken}`;

    let response;
    try {
      response = await fetchImpl(endpoint, {
        method: 'POST',
        redirect: 'error',
        headers,
        body: JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/list', params }),
        signal: AbortSignal.timeout(Math.min(REQUEST_TIMEOUT_MS, remainingTime)),
      });
    } catch (error) {
      if (error?.name === 'TimeoutError' || error?.name === 'AbortError') {
        fail('source_request_timeout');
      }
      fail('source_unreachable');
    }
    if (!(response instanceof Response) || response.redirected || !response.ok) {
      if (response instanceof Response) await response.body?.cancel().catch(() => {});
      fail('source_http_rejected');
    }

    let serialized;
    try {
      serialized = await readBoundedBody(
        response,
        MAX_AGGREGATE_RESPONSE_BYTES - aggregateBytes,
      );
    } catch (error) {
      if (error instanceof LiveSourceCatalogueError) throw error;
      fail('source_response_invalid');
    }
    aggregateBytes += Buffer.byteLength(serialized, 'utf8');
    cursor = parseToolPage(
      serialized,
      (response.headers.get('content-type') ?? '').toLowerCase(),
      id,
      names,
      cursors,
    );
    if (cursor === undefined) return [...names].sort(compareText);
  }
  fail('source_tool_list_invalid');
}

/**
 * Compare a live MCP source's exact tools/list names with one reviewed source
 * allowlist. The report contains counts and digests, not names.
 */
export async function verifyLiveSourceCatalogue(
  configInput,
  sourceId,
  { fetchImpl = globalThis.fetch, oauthAccessToken } = {},
) {
  let config;
  try {
    config = validateGatewayConfig(configInput);
  } catch {
    fail('config_invalid');
  }
  if (!v.is(FUNCTION_SCHEMA, fetchImpl) || !v.is(STRING_SCHEMA, sourceId) || sourceId.length === 0) {
    fail('argument_invalid');
  }
  const source = config.sources.find((candidate) => candidate.id === sourceId);
  if (!source) fail('source_not_found');
  if (!['none', 'oauth'].includes(source.authentication.mode)) {
    fail('source_authentication_unsupported');
  }
  if (
    oauthAccessToken !== undefined
    && (
      !v.is(STRING_SCHEMA, oauthAccessToken)
      || oauthAccessToken.length === 0
      || oauthAccessToken.length > 4_096
      || /[^\x21-\x7e]/u.test(oauthAccessToken)
    )
  ) {
    fail('argument_invalid');
  }
  if (source.authentication.mode === 'oauth' && oauthAccessToken === undefined) {
    fail('source_authentication_required');
  }
  if (source.authentication.mode === 'none' && oauthAccessToken !== undefined) {
    fail('argument_invalid');
  }

  const expected = [...source.enabledTools].sort(compareText);
  const actual = await listLiveToolNames(source.url, fetchImpl, oauthAccessToken);
  const report = Object.freeze({
    schemaVersion: 1,
    status: 'verified',
    expectedCount: expected.length,
    actualCount: actual.length,
    expectedSha256: catalogueDigest(expected),
    actualSha256: catalogueDigest(actual),
  });
  if (
    expected.length !== actual.length
    || expected.some((name, index) => name !== actual[index])
  ) {
    fail('catalogue_mismatch');
  }
  return report;
}

function parseArguments(argv) {
  if (argv.length === 1 && argv[0] === '--help') return { help: true };
  if (
    ![4, 5].includes(argv.length)
    || argv[0] !== '--config'
    || argv[2] !== '--source'
    || (argv.length === 5 && argv[4] !== '--oauth-token-stdin')
  ) {
    fail('argument_invalid');
  }
  if (argv[1].length === 0 || argv[2].length === 0 || argv[3].length === 0) {
    fail('argument_invalid');
  }
  return {
    help: false,
    configPath: argv[1],
    sourceId: argv[3],
    oauthTokenStdin: argv.length === 5,
  };
}

async function readOauthTokenFromStdin() {
  const chunks = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length;
    if (length > 4_098) fail('argument_invalid');
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/u, '');
  if (raw.length === 0 || raw.length > 4_096 || /[^\x21-\x7e]/u.test(raw)) {
    fail('argument_invalid');
  }
  return raw;
}

async function readConfig(configPath) {
  let serialized;
  try {
    serialized = await readFile(configPath);
  } catch {
    fail('config_read_failed');
  }
  if (serialized.byteLength > MAX_CONFIG_BYTES) fail('config_too_large');
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(serialized));
  } catch {
    fail('config_invalid');
  }
}

async function main() {
  const args = parseArguments(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(
      'Usage: node tools/verify-live-source-catalogue.mjs --config <gateway-config.json> --source <source-id> [--oauth-token-stdin]\n',
    );
    return;
  }
  const report = await verifyLiveSourceCatalogue(
    await readConfig(args.configPath),
    args.sourceId,
    args.oauthTokenStdin ? { oauthAccessToken: await readOauthTokenFromStdin() } : {},
  );
  process.stdout.write(`${JSON.stringify(report)}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    const code = error instanceof LiveSourceCatalogueError
      ? error.code
      : 'internal_failure';
    process.stderr.write(`Live source catalogue verification failed: ${code}.\n`);
    process.exitCode = 1;
  });
}
