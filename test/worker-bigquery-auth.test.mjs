import assert from 'node:assert/strict';
import test from 'node:test';
import worker from '../payload/worker/index.js';
import { installReadyGateway } from './payload-lifecycle.mjs';

const ENDPOINT = 'https://bigquery.googleapis.com/mcp';
const BLOCK = 'source_google_shared_oauth_unsupported';
const SOURCE_KEY = 'ankka-mcp-gateway/management-sources/v1';
// Synthetic protocol data, not a copied provider response.
const TOOL_NAMES = [
  'list_dataset_ids', 'get_dataset_info', 'list_table_ids',
  'get_table_info', 'execute_sql_readonly', 'execute_sql',
];

async function fixture(run) {
  const { env } = await installReadyGateway();
  const keys = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify'],
  );
  const kid = 'synthetic-bigquery-access-key';
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const unsigned = `${encode({ alg: 'RS256', kid, typ: 'JWT' })}.${encode({
    iss: env.CF_ACCESS_ISSUER, aud: [env.CF_ACCESS_AUD], email: 'admin@example.com', nbf: now - 1, exp: now + 300,
  })}`;
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', keys.privateKey, new TextEncoder().encode(unsigned));
  const headers = {
    'cf-access-authenticated-user-email': 'admin@example.com',
    'cf-access-jwt-assertion': `${unsigned}.${Buffer.from(signature).toString('base64url')}`,
    origin: 'https://manage.example.com', 'content-type': 'application/json',
  };
  const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
  const originalFetch = globalThis.fetch;
  const calls = [];
  let responseMode = 'public';
  globalThis.fetch = async (request) => {
    if (request.url === `${env.CF_ACCESS_ISSUER}/cdn-cgi/access/certs`) {
      return Response.json({ keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] });
    }
    calls.push(request.url);
    assert.equal(request.headers.get('authorization'), null);
    assert.equal(request.headers.get('cookie'), null);
    const message = await request.json();
    assert.equal(message.method, 'tools/list', 'discovery must never execute a tool');
    if (responseMode === 'unreachable') throw new Error('synthetic-provider-sensitive-detail');
    if (responseMode === 'redirect') {
      return new Response(null, { status: 302, headers: { location: 'https://other.example.net/mcp' } });
    }
    if (responseMode === 'oauth') {
      return new Response('synthetic-provider-sensitive-detail', {
        status: 401,
        headers: { 'www-authenticate': 'Bearer resource_metadata="https://bigquery.googleapis.com/.well-known/oauth-protected-resource"' },
      });
    }
    return Response.json({ jsonrpc: '2.0', id: message.id, result: {
      tools: TOOL_NAMES.map((name) => ({ name, annotations: {
        readOnlyHint: name !== 'execute_sql', destructiveHint: name === 'execute_sql',
      } })),
    } });
  };
  const request = (path, method, body) => {
    const init = { method, headers };
    if (body !== undefined) init.body = JSON.stringify(body);
    return worker.fetch(new Request(`https://manage.example.com${path}`, init), env);
  };
  try {
    await run({ request, calls, storage: env.ADMIN_STATE.objects.get('v1:management').storage,
      mode(value) { responseMode = value; } });
  } finally { globalThis.fetch = originalFetch; }
}

test('BigQuery public discovery is OAuth protected and never approves its connection', async () => {
  await fixture(async ({ request, calls, storage }) => {
    const response = await request('/api/sources/discover', 'POST', { url: ENDPOINT });
    assert.equal(response.status, 200);
    const discovery = await response.json();
    assert.equal(discovery.authentication, 'oauth');
    assert.equal(discovery.status, 'authorization_required');
    assert.equal(discovery.connectionBlock, BLOCK);
    assert.deepEqual(discovery.tools.map((t) => t.name), TOOL_NAMES);
    assert.equal(discovery.tools.find((t) => t.name === 'execute_sql').defaultSelected, false);
    // The release-wide installation pause answers before the endpoint-specific
    // gate; when a release lifts the pause, the Google block must answer next.
    const managed = await (await request('/api/sources', 'GET')).json();
    const expectedRefusal = managed.installationEnabled === true
      ? { schemaVersion: 1, error: BLOCK }
      : { schemaVersion: 1, error: 'source_addition_paused', retryable: false };
    const before = structuredClone(storage.writes);
    const discoveredCalls = calls.length;
    for (const authMode of ['none', 'oauth']) {
      const saved = await request('/api/sources', 'PUT', {
        schemaVersion: 1, revision: 1,
        source: { label: 'GA4 example', url: ENDPOINT, authMode, enabledTools: ['execute_sql_readonly'] },
      });
      assert.equal(saved.status, 409);
      assert.deepEqual(await saved.json(), expectedRefusal);
    }
    assert.deepEqual(storage.writes, before, 'no draft or credential storage');
    assert.equal(calls.length, discoveredCalls, 'save rejection happens before upstream requests');
  });
});

test('BigQuery legacy drafts cannot start a Cloudflare authorization or provider mutation', async () => {
  await fixture(async ({ request, calls, storage }) => {
    for (const authMode of ['none', 'oauth']) {
      const source = { id: 'source-0123456789abcdef', label: 'GA4 example', url: ENDPOINT,
        authMode, onBehalfOfUser: false, enabledTools: ['execute_sql_readonly'], status: 'draft' };
      await storage.put(SOURCE_KEY, { schemaVersion: 1, revision: 1, applyMode: 'oauth_per_action', sources: [source] });
      const managed = await (await request('/api/sources', 'GET')).json();
      const expectedRefusal = managed.installationEnabled === true
        ? { schemaVersion: 1, error: BLOCK }
        : { schemaVersion: 1, error: 'source_addition_paused', retryable: false };
      const before = structuredClone(storage.writes);
      const response = await request('/api/source-actions', 'POST', {
        schemaVersion: 1, revision: 1, sourceId: source.id,
      });
      assert.equal(response.status, 409);
      assert.deepEqual(await response.json(), expectedRefusal);
      assert.deepEqual(storage.writes, before);
      assert.equal(calls.length, 0);
    }
  });
});

test('BigQuery discovery fails closed on failures, redirects and credential-bearing input', async () => {
  await fixture(async ({ request, mode, calls }) => {
    for (const failure of ['unreachable', 'redirect']) {
      mode(failure);
      const response = await request('/api/sources/discover', 'POST', { url: ENDPOINT });
      assert.equal(response.status, 502);
      const body = await response.json();
      assert.equal(body.authentication, undefined);
      assert.doesNotMatch(JSON.stringify(body), /synthetic-provider-sensitive-detail/);
    }
    mode('oauth');
    const response = await request('/api/sources/discover', 'POST', { url: ENDPOINT });
    assert.deepEqual(await response.json(), {
      schemaVersion: 1, status: 'authorization_required', endpoint: ENDPOINT,
      protocolVersion: '2026-07-28', authentication: 'oauth', tools: [], connectionBlock: BLOCK,
    });
    const before = calls.length;
    for (const input of [
      { url: `${ENDPOINT}?access_token=synthetic` },
      { url: 'https://synthetic:synthetic@bigquery.googleapis.com/mcp' },
      { url: ENDPOINT, headers: { authorization: 'synthetic' } },
      { url: ENDPOINT, clientSecret: 'synthetic' },
    ]) {
      assert.equal((await request('/api/sources/discover', 'POST', input)).status, 400);
    }
    assert.equal(calls.length, before);
  });
});

test('BigQuery classification is restricted to the reviewed exact endpoint', async () => {
  await fixture(async ({ request }) => {
    for (const url of ['https://bigquery.googleapis.com.example.net/mcp', 'https://other.example.net/mcp']) {
      const response = await request('/api/sources/discover', 'POST', { url });
      const discovery = await response.json();
      assert.equal(response.status, 200);
      assert.equal(discovery.authentication, 'none');
      assert.equal(discovery.connectionBlock, undefined);
    }
  });
});
