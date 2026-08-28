/**
 * Live, zero-authority OAuth-client credential preflight.
 *
 * Cloudflare authenticates the client before validating an authorization code.
 * A deliberately invalid code must therefore produce `invalid_grant` when the
 * client ID and secret match. `invalid_client` proves the deployed pair is
 * wrong. No grant can be issued by this request.
 *
 * The client secret is accepted only as bounded stdin. It is never accepted in
 * argv, the environment or a file, and no response description is surfaced.
 */
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import * as v from 'valibot';

const TOKEN_ENDPOINT = 'https://dash.cloudflare.com/oauth2/token';
const CALLBACK_URL = 'https://deploy.ankka.ai/oauth/callback';
const CLIENT_ID = /^[A-Za-z0-9_-]{16,128}$/u;
const MAX_SECRET_BYTES = 512;
const MAX_RESPONSE_BYTES = 16 * 1024;
const FUNCTION_SCHEMA = v.function();
const OBJECT_SCHEMA = v.object({});
const STRING_SCHEMA = v.string();

function hasControlCharacter(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 31 || code === 127) return true;
  }
  return false;
}

export class OauthClientPairPreflightError extends Error {
  constructor(code) {
    super(code);
    this.name = 'OauthClientPairPreflightError';
    this.code = code;
  }
}

function fail(code) {
  throw new OauthClientPairPreflightError(code);
}

async function boundedText(response) {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) fail('response_invalid');
  const reader = response.body?.getReader();
  if (!reader) return '';
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) fail('response_invalid');
      chunks.push(value);
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
  } finally {
    for (const chunk of chunks) chunk.fill(0);
    await reader.cancel().catch(() => {});
  }
}

function standardError(serialized) {
  try {
    const parsed = JSON.parse(serialized);
    return v.is(OBJECT_SCHEMA, parsed) && !Array.isArray(parsed) &&
      v.is(STRING_SCHEMA, parsed.error) ? parsed.error : null;
  } catch {
    return null;
  }
}

export async function verifyOauthClientPair({ clientId, readClientSecret, transport = fetch }) {
  if (!CLIENT_ID.test(clientId) || !v.is(FUNCTION_SCHEMA, readClientSecret) ||
      !v.is(FUNCTION_SCHEMA, transport)) {
    fail('input_invalid');
  }
  const clientSecret = await readClientSecret();
  if (!v.is(STRING_SCHEMA, clientSecret) || clientSecret.length < 16 || clientSecret.length > MAX_SECRET_BYTES ||
      clientSecret.includes(':') || hasControlCharacter(clientSecret)) fail('input_invalid');
  const authorizationBytes = Buffer.from(`${clientId}:${clientSecret}`, 'utf8');
  let response;
  try {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: 'ankka_oauth_client_pair_preflight_invalid_code',
      redirect_uri: CALLBACK_URL,
      code_verifier: 'A'.repeat(43),
    });
    response = await transport(TOKEN_ENDPOINT, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        authorization: `Basic ${authorizationBytes.toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body,
      redirect: 'manual',
    });
  } catch {
    fail('endpoint_unavailable');
  } finally {
    authorizationBytes.fill(0);
  }
  if (!(response instanceof Response) || response.redirected) fail('response_invalid');
  const serialized = await boundedText(response);
  const error = standardError(serialized);
  if (response.status === 400 && error === 'invalid_grant') {
    return Object.freeze({
      schemaVersion: 1,
      status: 'verified',
      clientId,
      tokenEndpoint: TOKEN_ENDPOINT,
      proof: 'authenticated_client_rejected_invalid_code',
    });
  }
  if (error === 'invalid_client' || response.status === 401) fail('client_credentials_mismatch');
  fail('response_inconclusive');
}

async function readSecretStdin(readable) {
  const chunks = [];
  let total = 0;
  try {
    for await (const chunk of readable) {
      const owned = Buffer.from(chunk);
      total += owned.byteLength;
      if (total > MAX_SECRET_BYTES + 1) {
        owned.fill(0);
        fail('input_invalid');
      }
      chunks.push(owned);
    }
    const bytes = Buffer.concat(chunks, total);
    try {
      const value = bytes.toString('utf8').replace(/\r?\n$/u, '');
      if (Buffer.byteLength(value, 'utf8') > MAX_SECRET_BYTES) fail('input_invalid');
      return value;
    } finally {
      bytes.fill(0);
    }
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

function parseArguments(argv) {
  if (argv.length === 1 && argv[0] === '--help') return { help: true };
  if (argv.length !== 3 || argv[0] !== '--client-id' || argv[2] !== '--client-secret-stdin' ||
      !CLIENT_ID.test(argv[1])) fail('input_invalid');
  return { help: false, clientId: argv[1] };
}

const HELP = `Usage: security find-generic-password -s <service> -w | node scripts/verify-oauth-client-pair.mjs \\\n  --client-id <client-id> --client-secret-stdin\n`;

export async function runOauthClientPairPreflightCli({ argv, stdin, stdout, stderr, transport = fetch }) {
  try {
    const options = parseArguments(argv);
    if (options.help) {
      stdout.write(HELP);
      return 0;
    }
    const result = await verifyOauthClientPair({
      clientId: options.clientId,
      readClientSecret: () => readSecretStdin(stdin),
      transport,
    });
    stdout.write(`${JSON.stringify(result)}\n`);
    return 0;
  } catch (error) {
    const code = error instanceof OauthClientPairPreflightError ? error.code : 'internal_error';
    stderr.write(`OAuth client credential preflight failed: ${code}.\n`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await runOauthClientPairPreflightCli({
    argv: process.argv.slice(2),
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
  });
}
