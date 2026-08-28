/**
 * Live, read-only verification that Cloudflare still publishes every OAuth
 * scope required by the reviewed installer manifest.
 */
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import * as v from 'valibot';

export const REQUIRED_SCOPE_IDS = Object.freeze([
  'access-acct.write',
  'access.write',
  'account-settings.read',
  'dns.write',
  'mcp-portals.write',
  'memberships.read',
  'user-details.read',
  'workers-routes.read',
  'workers-scripts.write',
  'zone.read',
]);

const CATALOGUE_URL = 'https://api.cloudflare.com/client/v4/oauth/scopes';
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{20,256}$/u;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const TIMEOUT_MS = 10_000;
const FUNCTION_SCHEMA = v.function();
const OBJECT_SCHEMA = v.object({});
const STRING_SCHEMA = v.string();

export class OAuthScopeCatalogueError extends Error {
  constructor(code) {
    super(code);
    this.name = 'OAuthScopeCatalogueError';
    this.code = code;
  }
}

function fail(code = 'oauth_scope_catalogue_invalid') {
  throw new OAuthScopeCatalogueError(code);
}

function isRecord(value) {
  return v.is(OBJECT_SCHEMA, value) && !Array.isArray(value);
}

async function readBoundedResponse(response) {
  const declared = Number(response.headers?.get?.('content-length'));
  if (Number.isFinite(declared) && (declared < 0 || declared > MAX_RESPONSE_BYTES)) fail();
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_RESPONSE_BYTES) fail();
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    fail();
  } finally {
    bytes.fill(0);
  }
}

export async function verifyOAuthScopeCatalogue({ fetchImpl = fetch, readToken }) {
  if (!v.is(FUNCTION_SCHEMA, fetchImpl) || !v.is(FUNCTION_SCHEMA, readToken)) fail();
  let token;
  try {
    token = await readToken();
    if (!v.is(STRING_SCHEMA, token) || !TOKEN_PATTERN.test(token)) fail('oauth_scope_token_invalid');
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
    let response;
    try {
      response = await fetchImpl(CATALOGUE_URL, {
        method: 'GET',
        headers: {
          accept: 'application/json',
          authorization: `Bearer ${token}`,
        },
        redirect: 'error',
        signal: controller.signal,
      });
    } catch {
      fail('oauth_scope_catalogue_unavailable');
    } finally {
      clearTimeout(timeout);
    }
    if (!response || response.status !== 200) fail('oauth_scope_catalogue_unavailable');
    const body = await readBoundedResponse(response);
    if (!isRecord(body) || body.success !== true || !Array.isArray(body.result)) fail();
    const ids = body.result.map((entry) => isRecord(entry) ? entry.id : null);
    if (ids.some((id) => !v.is(STRING_SCHEMA, id)) || new Set(ids).size !== ids.length) fail();
    const available = new Set(ids);
    if (REQUIRED_SCOPE_IDS.some((scope) => !available.has(scope))) {
      fail('oauth_scope_catalogue_required_scope_missing');
    }
    return Object.freeze({
      catalogueScopeCount: ids.length,
      requiredScopeCount: REQUIRED_SCOPE_IDS.length,
      schemaVersion: 1,
      status: 'verified',
    });
  } finally {
    token = undefined;
  }
}

async function readTokenFromStdin(stream) {
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    const bytes = Buffer.from(chunk);
    size += bytes.byteLength;
    if (size > 512) fail('oauth_scope_token_invalid');
    chunks.push(bytes);
  }
  const joined = Buffer.concat(chunks);
  for (const chunk of chunks) chunk.fill(0);
  try {
    return joined.toString('utf8').trim();
  } finally {
    joined.fill(0);
  }
}

const HELP = 'Usage: <token-source> | node scripts/verify-oauth-scope-catalogue.mjs --api-token-stdin\n';

async function run(argv) {
  if (argv.length !== 1 || argv[0] !== '--api-token-stdin') {
    process.stderr.write(HELP);
    return 2;
  }
  try {
    const result = await verifyOAuthScopeCatalogue({
      readToken: () => readTokenFromStdin(process.stdin),
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return 0;
  } catch (error) {
    const code = error instanceof OAuthScopeCatalogueError
      ? error.code
      : 'oauth_scope_catalogue_internal_error';
    process.stderr.write(`OAuth scope catalogue verification failed: ${code}.\n`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  run(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}
