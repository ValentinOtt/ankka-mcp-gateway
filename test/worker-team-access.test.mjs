import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import test from 'node:test';

import worker, { AdminState, planTeamAccessChange } from '../payload/worker/index.js';
import { addHistoricalInstalledSource } from './historical-source-fixture.mjs';
import {
  ACCOUNT_ID,
  BOOTSTRAP_NONCE,
  canonicalJson,
  cloudflareProvider,
  installReadyGateway,
  portalOnlyClaim,
  prefixedSha256,
  withProviderFetch,
} from './payload-lifecycle.mjs';

// Exercise the real Worker against synthetic Cloudflare resource state. These
// tests verify native policy mutations, never just UI visibility. Live provider
// enforcement and session propagation remain separate two-identity acceptance.
const ADMIN = 'admin@example.com';
const OWNER = 'owner@example.com';
const MEMBER = 'member@example.com';
const NEW_PERSON = 'new-person@example.com';
const TEAM_KEY = 'ankka-mcp-gateway/team-access/v1';
const UPDATES_KEY = 'ankka-mcp-gateway/runtime-updates/v1';
const SOURCES_KEY = 'ankka-mcp-gateway/management-sources/v1';
const SOURCE_ACTIONS_KEY = 'ankka-mcp-gateway/source-actions/v1';
const MANAGEMENT_ORIGIN = 'https://manage.example.com';
const SYNTHETIC_GRANT = 'synthetic-legacy-installer-grant-never-store';
const SYNTHETIC_MANAGEMENT_TOKEN = 'synthetic-team-management-token-never-store';
const API_APPS = `/client/v4/accounts/${ACCOUNT_ID}/access/apps`;
const NEW_SOURCE_URL = 'https://catalog.example.net/mcp';

function envelope(result, status = 200) {
  return Response.json({ success: status >= 200 && status < 300, errors: [], messages: [], result }, { status });
}

// Extend the existing explicit resource fake locally: permission updates change
// only an existing policy below its existing application, never create a target.
function teamProvider() {
  let hook;
  const provider = cloudflareProvider({
    async onRequest(context) {
      const intercepted = await hook?.(context);
      if (intercepted instanceof Response) return intercepted;
      const { record, state } = context;
      if (record.method !== 'PUT' || !record.pathname.startsWith(`${API_APPS}/`)) return undefined;
      const [appId, segment, policyId, extra] = record.pathname.slice(API_APPS.length + 1).split('/');
      assert.equal(segment, 'policies');
      assert.equal(extra, undefined);
      const policies = state.policies.get(appId);
      const index = policies?.findIndex((policy) => policy.id === policyId) ?? -1;
      if (index < 0) return envelope(null, 404);
      policies[index] = { id: policyId, ...structuredClone(record.body) };
      return envelope(policies[index]);
    },
  });
  return {
    ...provider,
    hook(next) { hook = next; },
    puts() { return provider.requests.filter(({ method }) => method === 'PUT'); },
  };
}

async function fixture(run, claimInput) {
  const provider = teamProvider();
  const options = { provider };
  if (claimInput) options.claimInput = claimInput;
  const gateway = await installReadyGateway(options);
  gateway.env.ANKKA_TEAM_MANAGEMENT_TOKEN = SYNTHETIC_MANAGEMENT_TOKEN;
  // Real Durable Object instances retain their operation queue. The shared
  // sequential lifecycle fixture recreates instances; retain them here so
  // concurrent API regressions exercise the actual runtime serialization.
  const namespace = gateway.env.ADMIN_STATE;
  const instances = new Map();
  gateway.env.ADMIN_STATE = {
    ...namespace,
    get(name) {
      if (!instances.has(name)) {
        const entry = gateway.objects.get(name);
        assert.ok(entry);
        instances.set(name, new AdminState({ storage: entry.storage }, gateway.env));
      }
      return { fetch: (request) => instances.get(name).fetch(request) };
    },
  };
  const keys = await crypto.subtle.generateKey({
    name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256',
  }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
  const kid = 'synthetic-team-regression-key';
  async function headers(email = ADMIN) {
    const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const unsigned = `${encode({ alg: 'RS256', kid, typ: 'JWT' })}.${encode({
      iss: gateway.env.CF_ACCESS_ISSUER, aud: [gateway.env.CF_ACCESS_AUD],
      email, nbf: now - 1, exp: now + 300,
    })}`;
    const signed = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', keys.privateKey, new TextEncoder().encode(unsigned));
    return {
      'cf-access-authenticated-user-email': email,
      'cf-access-jwt-assertion': `${unsigned}.${Buffer.from(signed).toString('base64url')}`,
      'content-type': 'application/json', origin: MANAGEMENT_ORIGIN,
    };
  }
  async function api(path, { method = 'GET', body, email = ADMIN, extraHeaders = {} } = {}) {
    const init = {
      method, headers: { ...await headers(email), ...extraHeaders },
    };
    if (body !== undefined) init.body = canonicalJson(body);
    return worker.fetch(new Request(`${MANAGEMENT_ORIGIN}${path}`, init), gateway.env);
  }
  async function view() {
    const response = await api('/api/team');
    assert.equal(response.status, 200, await response.clone().text());
    return response.json();
  }
  // A draft exists only in the browser until one authenticated Save request.
  async function draft(input) { return { input }; }
  async function apply(prepared, overrides = {}, action = 'access') {
    if (prepared.input) return api('/api/team-actions', { method: 'POST', body: prepared.input });
    const { claim } = prepared;
    const input = {
      schemaVersion: 1, actionId: claim.actionId,
      actionKey: claim.actionKey, actorEmail: claim.actorEmail, accountId: claim.accountId,
      issuedAt: Date.now(), expiresAt: claim.expiresAt,
      cloudflareAccessToken: SYNTHETIC_GRANT,
    };
    if (action !== null) input.action = action;
    Object.assign(input, overrides);
    const body = canonicalJson(input);
    const signature = `sha256=${createHmac('sha256', Buffer.from(claim.actionKey, 'base64url')).update(body).digest('hex')}`;
    return worker.fetch(new Request('https://ankka-gateway-test.tenant.workers.dev/__ankka/source-action', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-ankka-source-action-signature': signature }, body,
    }), gateway.env);
  }
  async function teardown() {
    const response = await api('/api/teardown-actions', { method: 'POST', body: { schemaVersion: 1 } });
    assert.equal(response.status, 200, await response.clone().text());
    const prepared = await response.json();
    const claim = JSON.parse(Buffer.from(new URL(prepared.handoffUrl).hash.slice(1), 'base64url').toString('utf8'));
    return async (command, requestId) => {
      const input = {
        schemaVersion: 1, command, actionId: claim.actionId, actionKey: claim.actionKey,
        actorEmail: claim.actorEmail, accountId: claim.accountId, installationId: claim.installationId,
        issuedAt: Date.now(), expiresAt: claim.expiresAt,
      };
      if (requestId !== undefined) {
        input.requestId = requestId;
        input.cloudflareAccessToken = SYNTHETIC_GRANT;
      }
      const body = canonicalJson(input);
      const signature = `sha256=${createHmac('sha256', Buffer.from(claim.actionKey, 'base64url')).update(body).digest('hex')}`;
      return worker.fetch(new Request('https://ankka-gateway-test.tenant.workers.dev/__ankka/teardown-action', {
        method: 'POST', headers: { 'content-type': 'application/json', 'x-ankka-teardown-action-signature': signature }, body,
      }), gateway.env);
    };
  }
  const managementStorage = gateway.objects.get('v1:management').storage;
  const managementRequests = [];
  const network = async (request) => {
    if (request.headers.get('authorization') === `Bearer ${SYNTHETIC_MANAGEMENT_TOKEN}`) {
      const url = new URL(request.url);
      assert.equal(url.origin, 'https://api.cloudflare.com');
      assert.equal(request.redirect, 'manual');
      assert.match(url.pathname, new RegExp(`^/client/v4/accounts/${ACCOUNT_ID}/access/(apps(?:/[^/]+(?:/policies(?:/[^/]+)?)?)?|ai-controls/mcp/portals/[^/]+)$`, 'u'));
      assert.ok(request.method === 'GET' || request.method === 'PUT' && /\/policies\/[^/]+$/u.test(url.pathname));
      assert.equal(request.url.includes(SYNTHETIC_MANAGEMENT_TOKEN), false);
      assert.equal((await request.clone().text()).includes(SYNTHETIC_MANAGEMENT_TOKEN), false);
      managementRequests.push({ method: request.method, path: url.pathname });
    }
    if (request.url === `${gateway.env.CF_ACCESS_ISSUER}/cdn-cgi/access/certs`) {
      return Response.json({ keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] });
    }
    if (request.url === NEW_SOURCE_URL) {
      const message = await request.json();
      if (message.method === 'initialize') return Response.json({ jsonrpc: '2.0', id: message.id, result: {
        protocolVersion: '2026-07-28', capabilities: { tools: {} }, serverInfo: { name: 'Synthetic source', version: '1' },
      } });
      if (message.method === 'notifications/initialized') return new Response(null, { status: 202 });
      return Response.json({ jsonrpc: '2.0', id: message.id, result: { tools: [{
        name: 'company_lookup', description: 'Read synthetic reference records.', inputSchema: { type: 'object' },
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
      }] } });
    }
    return provider.fetch(request);
  };
  return withProviderFetch(network, () => run({ ...gateway, api, view, draft, apply, teardown,
    headers, managementStorage, managementRequests }));
}

function changedRequest(view) {
  return {
    schemaVersion: 1, expectedRevision: view.revision,
    members: [
      { email: ADMIN, sourceIds: [] },
      { email: OWNER, sourceIds: [] },
      { email: NEW_PERSON, sourceIds: [view.sources[0].id] },
    ],
  };
}

function app(gateway, type = 'mcp') {
  const result = [...gateway.provider.state.apps.values()].find((value) => value.type === type);
  assert.ok(result);
  return result;
}

function policy(gateway, type = 'mcp') {
  return gateway.provider.state.policies.get(app(gateway, type).id)[0];
}

function assertNoMutation(provider, baseline) {
  assert.deepEqual(provider.requests.slice(baseline).filter(({ method }) => method !== 'GET'), []);
}

async function prepareNewSource(gateway) {
  const current = await (await gateway.api('/api/sources')).json();
  const savedResponse = await gateway.api('/api/sources', { method: 'PUT', body: {
    schemaVersion: 1, revision: current.revision,
    source: { label: 'Additional source', url: NEW_SOURCE_URL, authMode: 'none', enabledTools: ['company_lookup'] },
  } });
  assert.equal(savedResponse.status, 200, await savedResponse.clone().text());
  const sources = await savedResponse.json();
  assert.equal(sources.installationEnabled, true);
  const source = sources.sources.find((candidate) => candidate.url === NEW_SOURCE_URL);
  return { source, sources, ...await authorizeNewSource(gateway, source.id, sources.revision) };
}

async function authorizeNewSource(gateway, sourceId, revision) {
  const response = await gateway.api('/api/source-actions', { method: 'POST', body: {
    schemaVersion: 1, revision, sourceId,
  } });
  assert.equal(response.status, 200, await response.clone().text());
  const prepared = await response.json();
  const claim = JSON.parse(Buffer.from(new URL(prepared.handoffUrl).hash.slice(1), 'base64url').toString('utf8'));
  return { claim };
}

// A previously issued, unexpired source-installation handoff can survive a
// runtime upgrade. Model that historical journal directly without enabling a
// current preparation route or altering any original resource/receipt authority.
async function historicalPreparedSource(gateway, status = 'authorization_required') {
  const current = gateway.managementStorage.snapshot(SOURCES_KEY);
  const source = { id: 'source-4444444444444444', label: 'Additional source', url: NEW_SOURCE_URL,
    authMode: 'none', onBehalfOfUser: false, enabledTools: ['company_lookup'], status: 'draft' };
  const sources = { ...current, revision: current.revision + 1, sources: [...current.sources, source] };
  const claim = { actionId: `action_${'L'.repeat(32)}`, actionKey: BOOTSTRAP_NONCE,
    actorEmail: ADMIN, accountId: ACCOUNT_ID, expiresAt: Date.now() + 600_000 };
  const action = { schemaVersion: 1, actionId: claim.actionId, sourceId: source.id,
    sourceRevision: sources.revision, actorEmail: ADMIN, issuedAt: Date.now(), expiresAt: claim.expiresAt,
    actionKeyHash: await prefixedSha256(claim.actionKey), sourceHash: await prefixedSha256({
      id: source.id, label: source.label, url: source.url, authMode: source.authMode,
      onBehalfOfUser: source.onBehalfOfUser, enabledTools: source.enabledTools,
    }), status: 'authorization_required', resources: [], pending: status === 'recovery_required'
      ? { kind: 'mcp_server', phase: 'send_armed', provider: null } : null,
    portalUpdate: null, failureCode: status === 'recovery_required' ? 'source_action_recovery_required' : null };
  await gateway.managementStorage.put(SOURCES_KEY, sources);
  if (status !== null) {
    await gateway.managementStorage.put(SOURCE_ACTIONS_KEY, { schemaVersion: 1, revision: 2, actions: [action] });
  }
  return { source, sources, claim, action };
}

// Reconstruct a v16 retained proposal with its original exact planner hash.
// This models stored migration state, not an available preparation endpoint.
async function historicalPreparedTeam(gateway, input) {
  const view = await gateway.view();
  const sources = gateway.managementStorage.snapshot(SOURCES_KEY);
  const control = gateway.managementStorage.snapshot('ankka-mcp-gateway/management-control/v1');
  const target = (applicationId, policyId) => ({ applicationId, policyId,
    policyName: gateway.provider.state.policies.get(applicationId).find(({ id }) => id === policyId).name });
  const portal = policy(gateway, 'mcp_portal');
  const plan = planTeamAccessChange(input, {
    revision: view.revision, adminEmails: view.adminEmails, currentMembers: view.members,
    sources: view.sources.map(({ status, ...source }) => ({ ...source, installed: status === 'installed' })),
    portalTarget: target(app(gateway, 'mcp_portal').id, portal.id),
    sourceTargets: control.sourceOwnership.map(({ sourceId, resources }) => ({ sourceId,
      ...target(resources[2].provider.parentId, resources[2].provider.id) })),
  });
  const claim = { actionId: `action_${'K'.repeat(32)}`, actionKey: BOOTSTRAP_NONCE,
    actorEmail: ADMIN, accountId: ACCOUNT_ID, expiresAt: Date.now() + 600_000 };
  const action = { schemaVersion: 1, actionId: claim.actionId, actorEmail: ADMIN,
    issuedAt: Date.now(), expiresAt: claim.expiresAt, actionKeyHash: await prefixedSha256(claim.actionKey),
    status: 'authorization_required', failureCode: null,
    request: { ...input, members: plan.nextState.members }, sourceRevision: sources.revision,
    planHash: await prefixedSha256({ plan, sourceRevision: sources.revision }), journal: [] };
  await gateway.managementStorage.put(TEAM_KEY, { ...gateway.managementStorage.snapshot(TEAM_KEY), pendingAction: action });
  return { claim, authorization: { actionId: action.actionId } };
}

async function runtimeAction(gateway, { operation = 'rollback', release = 'gateway-v0.0.9' } = {}) {
  const to = { release, artifactSha256: `sha256:${'8'.repeat(64)}`, versionId: '00000000-0000-4000-8000-000000000008' };
  await gateway.managementStorage.put(UPDATES_KEY, {
    schemaVersion: 1, revision: 1, actions: [],
    current: { release: gateway.env.ANKKA_GATEWAY_RELEASE,
      artifactSha256: gateway.env.ANKKA_GATEWAY_RELEASE_SHA256,
      versionId: '00000000-0000-4000-8000-000000000009' },
    previous: to,
  });
  const issuedAt = Date.now();
  const expiresAt = issuedAt + 600_000;
  const actionId = `action_${'R'.repeat(32)}`;
  const stub = gateway.env.ADMIN_STATE.get('v1:management');
  const prepare = () => stub.fetch(new Request('https://admin-state.invalid/runtime-updates', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: canonicalJson({ actionId, actionKeyHash, actorEmail: ADMIN, issuedAt, expiresAt, operation, to }),
  }));
  const actionKeyHash = await prefixedSha256(BOOTSTRAP_NONCE);
  const begin = () => {
    const body = canonicalJson({ schemaVersion: 1, command: 'begin', actionId, actionKey: BOOTSTRAP_NONCE,
      issuedAt: Date.now(), expiresAt, operation });
    const signature = `sha256=${createHmac('sha256', Buffer.from(BOOTSTRAP_NONCE, 'base64url')).update(body).digest('hex')}`;
    return stub.fetch(new Request('https://admin-state.invalid/runtime-updates/control', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-ankka-runtime-action-signature': signature }, body,
    }));
  };
  return { prepare, begin };
}

async function shortenedTeamDeadline(run) {
  const originalTimeout = AbortSignal.timeout;
  const requested = [];
  let guardTimer;
  const started = performance.now();
  AbortSignal.timeout = (milliseconds) => {
    assert.ok(milliseconds > 0 && milliseconds <= 60_000);
    requested.push(milliseconds);
    return originalTimeout.call(AbortSignal, 25);
  };
  try {
    const guard = new Promise((_resolve, reject) => {
      guardTimer = setTimeout(() => reject(new Error('Team operation did not respect its shortened deadline')), 1500);
    });
    const result = await Promise.race([run(), guard]);
    assert.equal(requested.length, 1);
    assert.ok(performance.now() - started < 1500);
    return { result, requested };
  } finally {
    clearTimeout(guardTimer);
    AbortSignal.timeout = originalTimeout;
  }
}

test('Team API requires matching administrator identity, same origin, exact schema and current revision', async () => fixture(async (gateway) => {
  const { api, env, provider } = gateway;
  const initial = await gateway.view();
  const input = changedRequest(initial);
  const baseline = provider.requests.length;
  const anonymous = await worker.fetch(new Request(`${MANAGEMENT_ORIGIN}/api/team-actions`, {
    method: 'POST', headers: { 'content-type': 'application/json', origin: MANAGEMENT_ORIGIN }, body: canonicalJson(input),
  }), env);
  assert.equal(anonymous.status, 401);
  assert.equal((await api('/api/team-actions', { method: 'POST', body: input, email: MEMBER })).status, 401);
  assert.equal((await api('/api/team-actions', {
    method: 'POST', body: input, extraHeaders: { 'cf-access-authenticated-user-email': OWNER },
  })).status, 401);
  assert.equal((await api('/api/team-actions', {
    method: 'POST', body: input, extraHeaders: { origin: 'https://foreign.example.com' },
  })).status, 403);
  for (const malformed of [
    { ...input, expectedRevision: initial.revision + 1 },
    { ...input, members: input.members.filter(({ email }) => email !== OWNER) },
    { ...input, members: [...input.members, { email: ' ADMIN@EXAMPLE.COM ', sourceIds: [] }] },
    { ...input, members: [{ email: ADMIN, sourceIds: ['uninstalled-source'] }, { email: OWNER, sourceIds: [] }] },
    { ...input, members: input.members.map((member) => ({ ...member, role: 'admin' })) },
    { ...input, cloudflareAccessToken: SYNTHETIC_GRANT },
  ]) {
    const response = await api('/api/team-actions', { method: 'POST', body: malformed });
    assert.ok([400, 409].includes(response.status), await response.clone().text());
    assert.doesNotMatch(await response.text(), /new-person@example\.com|synthetic-team-action-grant/u);
  }
  assertNoMutation(provider, baseline);
}));

test('Team applies only exact native source audiences and preserves original receipt, tools and shared source auth', async () => fixture(async (gateway) => {
  const initial = await gateway.view();
  assert.equal(initial.editingEnabled, true);
  const input = changedRequest(initial);
  const receiptBefore = canonicalJson(gateway.storage.snapshot());
  const portalBefore = canonicalJson(gateway.provider.state.portal);
  const prepared = await gateway.draft(input);
  const baseline = gateway.provider.requests.length;
  const response = await gateway.apply(prepared);
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal((await response.json()).action.status, 'succeeded');
  const next = await gateway.view();
  assert.equal(next.revision, initial.revision + 1);
  assert.deepEqual(next.members, [...input.members].sort((left, right) => left.email.localeCompare(right.email)));
  assert.equal(next.pendingAction.status, 'succeeded');
  assert.equal(next.proposedMembers, null);
  assert.equal(canonicalJson(gateway.storage.snapshot()), receiptBefore, 'original bootstrap receipt is immutable');
  assert.equal(canonicalJson(gateway.provider.state.portal), portalBefore, 'source tools and on_behalf are untouched');
  assert.deepEqual(policy(gateway).include, [{ email: { email: NEW_PERSON } }]);
  assert.equal(policy(gateway).decision, 'allow');
  assert.deepEqual(policy(gateway, 'mcp_portal').include.map(({ email }) => email.email), [ADMIN, NEW_PERSON, OWNER]);
  const mutations = gateway.provider.requests.slice(baseline).filter(({ method }) => method !== 'GET');
  assert.equal(mutations.length, 2);
  assert.ok(gateway.managementRequests.length > 2);
  assert.ok(mutations.every(({ method, pathname }) => method === 'PUT' && /^\/client\/v4\/accounts\/[1]{32}\/access\/apps\/[ab]{32}\/policies\/[mn]{32}$/u.test(pathname)));
  const saved = canonicalJson([...gateway.objects.values()].flatMap((entry) => entry.storage.writes));
  assert.equal(saved.includes(SYNTHETIC_MANAGEMENT_TOKEN), false);
  assert.equal(saved.includes(SYNTHETIC_GRANT), false);
  const stale = await gateway.api('/api/team-actions', { method: 'POST', body: input });
  assert.equal(stale.status, 409);
}));

test('missing customer management credential retains the proposal and never falls back to any installer or source credential', async () => fixture(async (gateway) => {
  delete gateway.env.ANKKA_TEAM_MANAGEMENT_TOKEN;
  const view = await gateway.view();
  assert.equal(view.managementCredentialConfigured, false);
  const input = changedRequest(view);
  const baseline = gateway.provider.requests.length;
  const result = await gateway.api('/api/team-actions', { method: 'POST', body: input });
  assert.equal(result.status, 409);
  assert.deepEqual(await result.json(), { schemaVersion: 1, error: 'team_management_credential_missing' });
  assert.equal(gateway.provider.requests.length, baseline);
  const retained = await gateway.view();
  assert.deepEqual(retained.proposedMembers, input.members.slice().sort((a, b) => a.email.localeCompare(b.email)));
  assert.equal(retained.pendingAction.canCancel, true);
  gateway.env.ANKKA_TEAM_MANAGEMENT_TOKEN = SYNTHETIC_MANAGEMENT_TOKEN;
  const recovered = await gateway.api('/api/team-actions', { method: 'POST', body: input });
  assert.equal(recovered.status, 200, await recovered.clone().text());
  assert.equal((await recovered.json()).action.actionId, retained.pendingAction.actionId);
}));

test('one local Save applies a multi-source batch and later revocation changes only the selected native audience', async () => fixture(async (gateway) => {
  const added = await addHistoricalInstalledSource(gateway);
  const initial = await gateway.view();
  const original = initial.sources.find(({ id }) => id !== added.source.id);
  assert.ok(original);
  const sourceState = canonicalJson(gateway.managementStorage.snapshot(SOURCES_KEY));
  const portalMappings = canonicalJson(gateway.provider.state.portal.servers);
  const input = { schemaVersion: 1, expectedRevision: initial.revision, members: [
    { email: ADMIN, sourceIds: [original.id] },
    { email: OWNER, sourceIds: [] },
    { email: NEW_PERSON, sourceIds: [added.source.id] },
  ] };
  const saved = await gateway.api('/api/team-actions', { method: 'POST', body: input });
  assert.equal(saved.status, 200, await saved.clone().text());
  assert.equal(gateway.provider.puts().length, 3);
  const additionalPolicy = () => gateway.provider.state.policies.get(added.resources[1].provider.id)[0];
  assert.deepEqual(additionalPolicy().include, [{ email: { email: NEW_PERSON } }]);
  const firstPolicy = canonicalJson(policy(gateway));
  const next = await gateway.view();
  const revoked = await gateway.api('/api/team-actions', { method: 'POST', body: {
    schemaVersion: 1, expectedRevision: next.revision,
    members: next.members.map((member) => member.email === NEW_PERSON ? { ...member, sourceIds: [] } : member),
  } });
  assert.equal(revoked.status, 200, await revoked.clone().text());
  assert.equal(gateway.provider.puts().length, 4);
  assert.equal(additionalPolicy().decision, 'deny');
  assert.deepEqual(additionalPolicy().include, [{ everyone: {} }]);
  assert.equal(canonicalJson(policy(gateway)), firstPolicy);
  assert.equal(canonicalJson(gateway.managementStorage.snapshot(SOURCES_KEY)), sourceState);
  assert.equal(canonicalJson(gateway.provider.state.portal.servers), portalMappings);
}));

test('malformed management credential fails safely without provider requests or reflected secret', async () => fixture(async (gateway) => {
  gateway.env.ANKKA_TEAM_MANAGEMENT_TOKEN = `${SYNTHETIC_MANAGEMENT_TOKEN}\n`;
  const input = changedRequest(await gateway.view());
  const baseline = gateway.provider.requests.length;
  const response = await gateway.api('/api/team-actions', { method: 'POST', body: input });
  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), { schemaVersion: 1, error: 'team_management_credential_invalid' });
  assert.equal(gateway.provider.requests.length, baseline);
  assert.equal(canonicalJson(gateway.managementStorage.writes).includes(SYNTHETIC_MANAGEMENT_TOKEN), false);
}));

for (const denied of ['applications', 'application', 'policies', 'portal', 'write']) {
  test(`revoked or insufficient credential at ${denied} fails closed and remains recoverable`, async () => fixture(async (gateway) => {
    const input = changedRequest(await gateway.view());
    let rejected = false;
    gateway.provider.hook(({ record }) => {
      const match = denied === 'applications' ? record.pathname === API_APPS
        : denied === 'application' ? record.pathname === `${API_APPS}/${app(gateway, 'mcp_portal').id}`
        : denied === 'policies' ? record.pathname.endsWith('/policies')
        : denied === 'portal' ? record.pathname.includes('/mcp/portals/')
        : record.method === 'PUT';
      if (!match) return undefined;
      rejected = true;
      return Response.json({ private: SYNTHETIC_MANAGEMENT_TOKEN }, { status: 403 });
    });
    const response = await gateway.api('/api/team-actions', { method: 'POST', body: input });
    assert.equal(response.status, 409);
    assert.deepEqual(await response.json(), { schemaVersion: 1, error: 'team_management_credential_invalid' });
    assert.equal(rejected, true);
    assert.equal(gateway.provider.puts().length, denied === 'write' ? 1 : 0);
    const retained = gateway.managementStorage.snapshot(TEAM_KEY);
    assert.equal(retained.revision, input.expectedRevision);
    assert.equal(retained.pendingAction.status, 'recovery_required');
    assert.equal(retained.teardownDisabled, denied === 'write');
    assert.equal(canonicalJson(gateway.managementStorage.writes).includes(SYNTHETIC_MANAGEMENT_TOKEN), false);
    gateway.provider.hook(undefined);
    const recovered = await gateway.api('/api/team-actions', { method: 'POST', body: input });
    assert.equal(recovered.status, 200, await recovered.clone().text());
  }));
}

test('an empty source audience becomes native deny-everyone without changing administrator ownership', async () => fixture(async (gateway) => {
  const initial = await gateway.view();
  const input = { schemaVersion: 1, expectedRevision: initial.revision,
    members: initial.members.map(({ email }) => ({ email, sourceIds: [] })) };
  const response = await gateway.apply(await gateway.draft(input));
  assert.equal(response.status, 200, await response.clone().text());
  assert.deepEqual(policy(gateway).include, [{ everyone: {} }]);
  assert.equal(policy(gateway).decision, 'deny');
  assert.deepEqual((await gateway.view()).adminEmails, [ADMIN, OWNER]);
  assert.equal(gateway.env.ADMIN_EMAILS, `${ADMIN},${OWNER}`);
}));

const POLICY_DRIFT_CASES = [
  ['extra Allow', (gateway) => gateway.provider.state.policies.get(app(gateway).id).push({ ...policy(gateway), id: 'x'.repeat(32) })],
  ['extra Bypass', (gateway) => gateway.provider.state.policies.get(app(gateway).id).push({ ...policy(gateway), id: 'x'.repeat(32), decision: 'bypass', include: [{ everyone: {} }] })],
  ['duplicate owned policy', (gateway) => gateway.provider.state.policies.get(app(gateway).id).push(structuredClone(policy(gateway)))],
  ['group selector', (gateway) => { policy(gateway).include = [{ group: { id: 'synthetic-group' } }]; }],
  ['allow everyone', (gateway) => { policy(gateway).include = [{ everyone: {} }]; }],
  ['wrong policy ID', (gateway) => { policy(gateway).id = 'x'.repeat(32); }],
  ['wrong policy UID', (gateway) => { policy(gateway).uid = 'x'.repeat(32); }],
  ['reusable policy', (gateway) => { policy(gateway).reusable = true; }],
  ['wrong policy marker', (gateway) => { policy(gateway).name = 'Unrelated policy'; }],
  ['wrong policy parent', (gateway) => { policy(gateway).app_id = 'x'.repeat(32); }],
  ['wrong policy account', (gateway) => { policy(gateway).account_id = '9'.repeat(32); }],
  ['unexpected MFA requirement', (gateway) => { policy(gateway).require = [{ auth_method: { auth_method: 'mfa' } }]; }],
  ['wrong application ID', (gateway) => { app(gateway).id = 'x'.repeat(32); }],
  ['wrong application marker', (gateway) => { app(gateway).name = 'Unrelated application'; }],
  ['wrong application account', (gateway) => { app(gateway).account_id = '9'.repeat(32); }],
  ['wrong source destination', (gateway) => { app(gateway).destinations[0].mcp_server_id = 'foreign-source'; }],
  ['wrong Portal destination', (gateway) => { app(gateway, 'mcp_portal').domain = 'foreign.example.com'; }],
  ['competing source application', (gateway) => {
    const extra = { ...structuredClone(app(gateway)), id: 'x'.repeat(32) };
    gateway.provider.state.apps.set(extra.id, extra);
    gateway.provider.state.policies.set(extra.id, [{ ...structuredClone(policy(gateway)), id: 'y'.repeat(32) }]);
  }],
];

for (const [name, drift] of POLICY_DRIFT_CASES) {
  test(`Team preflight rejects ${name} before any policy mutation`, async () => fixture(async (gateway) => {
    const input = changedRequest(await gateway.view());
    const prepared = await gateway.draft(input);
    drift(gateway);
    const baseline = gateway.provider.requests.length;
    const response = await gateway.apply(prepared);
    assert.ok(response.status >= 400, await response.clone().text());
    assertNoMutation(gateway.provider, baseline);
    assert.equal(gateway.storage.snapshot().checksum, gateway.readyReceipt.checksum);
  }));
}

test('complete application and policy listings reject duplicate provider list rows', async () => fixture(async (gateway) => {
  const prepared = await gateway.draft(changedRequest(await gateway.view()));
  gateway.provider.hook(({ record, state }) => record.method === 'GET' && record.pathname === API_APPS
    ? envelope([...state.apps.values(), structuredClone(app(gateway))]) : undefined);
  const baseline = gateway.provider.requests.length;
  const response = await gateway.apply(prepared);
  assert.ok(response.status >= 400, await response.clone().text());
  assertNoMutation(gateway.provider, baseline);
}));

test('application preflight follows pagination before accepting an apparently unique owned application', async () => fixture(async (gateway) => {
  const prepared = await gateway.draft(changedRequest(await gateway.view()));
  const visitedPages = [];
  gateway.provider.hook(({ record, state }) => {
    if (record.method !== 'GET' || record.pathname !== API_APPS) return undefined;
    const page = Number(new URLSearchParams(record.search).get('page'));
    visitedPages.push(page);
    if (page === 1) return envelope([
      ...state.apps.values(),
      ...Array.from({ length: 98 }, (_value, index) => ({
        id: `unrelated-app-${index}`, name: `Unrelated ${index}`, type: 'self_hosted',
        domain: `other-${index}.example.com`,
      })),
    ]);
    assert.equal(page, 2);
    return envelope([{ ...structuredClone(app(gateway)), id: 'x'.repeat(32) }]);
  });
  const baseline = gateway.provider.requests.length;
  const response = await gateway.apply(prepared);
  assert.equal(response.status, 409, await response.clone().text());
  assert.deepEqual(visitedPages, [1, 2]);
  assertNoMutation(gateway.provider, baseline);
}));

test('all legacy Team relays are retired, including valid and altered signed grants', async () => fixture(async (gateway) => {
  const prepared = await historicalPreparedTeam(gateway, changedRequest(await gateway.view()));
  const baseline = gateway.provider.requests.length;
  for (const override of [
    {}, { accountId: '9'.repeat(32) }, { actorEmail: MEMBER }, { actionKey: 'A'.repeat(43) },
    { action: 'install' }, { members: [{ email: NEW_PERSON, sourceIds: [] }] },
  ]) {
    const response = await gateway.apply(prepared, override);
    assert.ok(response.status >= 400, await response.clone().text());
  }
  assertNoMutation(gateway.provider, baseline);
}));

test('unknown provider write outcome is recovered from exact readback without repeating acknowledged PUTs', async () => fixture(async (gateway) => {
  const input = changedRequest(await gateway.view());
  const prepared = await gateway.draft(input);
  let lostPath;
  gateway.provider.hook(({ record, state }) => {
    if (record.method !== 'PUT' || !record.pathname.startsWith(`${API_APPS}/`) || lostPath) return undefined;
    lostPath = record.pathname;
    const [appId, , policyId] = record.pathname.slice(API_APPS.length + 1).split('/');
    state.policies.set(appId, [{ id: policyId, ...structuredClone(record.body) }]);
    throw new Error(`${SYNTHETIC_MANAGEMENT_TOKEN}: ${NEW_PERSON} synthetic private provider response`);
  });
  const logs = [];
  const originals = Object.fromEntries(['log', 'warn', 'error', 'info', 'debug'].map((key) => [key, console[key]]));
  let first;
  try {
    for (const key of Object.keys(originals)) console[key] = (...values) => { logs.push(values); };
    first = await gateway.apply(prepared);
  } finally {
    for (const [key, value] of Object.entries(originals)) console[key] = value;
  }
  assert.equal(first.status, 409, await first.clone().text());
  assert.doesNotMatch(await first.text(), /synthetic-(?:legacy-installer-grant|team-management-token)|new-person@example\.com|synthetic private/u);
  assert.deepEqual(logs, []);
  assert.ok(lostPath);
  assert.ok(gateway.managementStorage.snapshot(TEAM_KEY).pendingAction);
  assert.equal((await gateway.view()).revision, input.expectedRevision);
  gateway.provider.hook(undefined);
  const recovered = await gateway.apply(await gateway.draft(input));
  assert.equal(recovered.status, 200, await recovered.clone().text());
  assert.equal((await recovered.json()).action.status, 'succeeded');
  assert.equal(gateway.provider.puts().filter(({ pathname }) => pathname === lostPath).length, 1);
  assert.equal(gateway.provider.puts().length, 2);
  assert.equal((await gateway.view()).revision, input.expectedRevision + 1);
  assert.equal(gateway.managementStorage.snapshot(TEAM_KEY).pendingAction.status, 'succeeded');
  assert.equal(gateway.storage.snapshot().checksum, gateway.readyReceipt.checksum);
  assert.equal(canonicalJson(gateway.managementStorage.writes).includes(SYNTHETIC_MANAGEMENT_TOKEN), false);
}));

test('partial policy updates block conflicting changes and teardown until exact recovery finishes', async () => fixture(async (gateway) => {
  const input = changedRequest(await gateway.view());
  const prepared = await gateway.draft(input);
  let sends = 0;
  gateway.provider.hook(({ record }) => {
    if (record.method === 'PUT' && record.pathname.startsWith(`${API_APPS}/`) && ++sends === 2) {
      return envelope(null, 503);
    }
    return undefined;
  });
  const first = await gateway.apply(prepared);
  assert.equal(first.status, 409, await first.clone().text());
  const current = await gateway.view();
  assert.equal(current.revision, input.expectedRevision);
  assert.ok(current.pendingAction);
  const replacement = { ...input, members: input.members.map(({ email }) => ({ email, sourceIds: [] })) };
  const conflict = await gateway.api('/api/team-actions', { method: 'POST', body: replacement });
  assert.equal(conflict.status, 409);
  const teardown = await gateway.api('/api/teardown-actions', { method: 'POST', body: { schemaVersion: 1 } });
  assert.equal(teardown.status, 409);
  assert.equal(gateway.provider.deletes().length, 0);
  const firstPath = gateway.provider.puts()[0].pathname;
  gateway.provider.hook(undefined);
  const recovered = await gateway.apply(await gateway.draft(input));
  assert.equal(recovered.status, 200, await recovered.clone().text());
  assert.equal(gateway.provider.puts().filter(({ pathname }) => pathname === firstPath).length, 1);
  assert.equal((await gateway.view()).revision, input.expectedRevision + 1);
}));

test('recovery rejects a third-party audience instead of overwriting it as before or after', async () => fixture(async (gateway) => {
  const input = changedRequest(await gateway.view());
  const prepared = await gateway.draft(input);
  let lost = false;
  gateway.provider.hook(({ record, state }) => {
    if (record.method !== 'PUT' || !record.pathname.startsWith(`${API_APPS}/`) || lost) return undefined;
    lost = true;
    const [appId, , policyId] = record.pathname.slice(API_APPS.length + 1).split('/');
    state.policies.set(appId, [{ id: policyId, ...structuredClone(record.body), include: [{ email: { email: 'unrelated@example.com' } }] }]);
    throw new Error('synthetic unknown outcome');
  });
  assert.equal((await gateway.apply(prepared)).status, 409);
  gateway.provider.hook(undefined);
  const baseline = gateway.provider.requests.length;
  const recovered = await gateway.apply(await gateway.draft(input));
  assert.equal(recovered.status, 409, await recovered.clone().text());
  assertNoMutation(gateway.provider, baseline);
  assert.equal((await gateway.view()).revision, input.expectedRevision);
}));

test('pristine legacy teardown keeps its existing exact receipt-backed path', async () => fixture(async (gateway) => {
  const send = await gateway.teardown();
  const proof = await send('prove');
  assert.equal(proof.status, 200, await proof.clone().text());
  const authority = await proof.json();
  assert.equal(canonicalJson(authority.authority.root.receipt), canonicalJson(gateway.readyReceipt));
  const removed = await send('apply', 'T'.repeat(22));
  assert.equal(removed.status, 200, await removed.clone().text());
  assert.equal(gateway.provider.liveResourceCount(), 0);
}));

test('native Team changes block teardown handoff without broadening legacy ownership checks', async () => fixture(async (gateway) => {
  const originalReceipt = canonicalJson(gateway.readyReceipt);
  const applied = await gateway.apply(await gateway.draft(changedRequest(await gateway.view())));
  assert.equal(applied.status, 200, await applied.clone().text());
  const baseline = gateway.provider.requests.length;
  const prepared = await gateway.api('/api/teardown-actions', { method: 'POST', body: { schemaVersion: 1 } });
  assert.equal(prepared.status, 409, await prepared.clone().text());
  const result = await prepared.json();
  assert.equal(Object.hasOwn(result, 'handoffUrl'), false);
  assertNoMutation(gateway.provider, baseline);
  assert.equal(gateway.provider.deletes().length, 0);
  assert.equal(gateway.provider.liveResourceCount(), 7);
  assert.equal(canonicalJson(gateway.storage.snapshot()), originalReceipt);
}));

test('historical day-two ownership cannot alias another source application or policy parent during teardown', async () => fixture(async (gateway) => {
  await addHistoricalInstalledSource(gateway);
  await addHistoricalInstalledSource(gateway, { label: 'Other historical source', url: 'https://other.example.net/mcp' });
  const key = 'ankka-mcp-gateway/management-control/v1';
  const originalReceipt = canonicalJson(gateway.storage.snapshot());
  const control = gateway.managementStorage.snapshot(key);
  const [first, second] = control.sourceOwnership.slice(-2);
  second.resources[1].provider.id = first.resources[1].provider.id;
  second.resources[2].provider.parentId = first.resources[1].provider.id;
  await gateway.managementStorage.put(key, control);
  const baseline = gateway.provider.requests.length;
  const response = await gateway.api('/api/teardown-actions', { method: 'POST', body: { schemaVersion: 1 } });
  assert.equal(response.status, 409);
  assertNoMutation(gateway.provider, baseline);
  assert.equal(gateway.provider.deletes().length, 0);
  assert.equal(canonicalJson(gateway.storage.snapshot()), originalReceipt);
}));

test('historical day-two policy drift blocks every teardown deletion in the primary runtime', async () => fixture(async (gateway) => {
  const added = await addHistoricalInstalledSource(gateway);
  const send = await gateway.teardown();
  added.policy.include = [{ email: { email: 'unowned@example.com' } }];
  const proof = await send('prove');
  assert.equal(proof.status, 200, await proof.clone().text());
  const baseline = gateway.provider.requests.length;
  const result = await send('apply', 'Q'.repeat(22));
  assert.equal(result.status, 409);
  assertNoMutation(gateway.provider, baseline);
  assert.equal(gateway.provider.deletes().length, 0);
  assert.equal(gateway.provider.liveResourceCount(), 10);
}));

for (const drift of ['root Portal application alias', 'desired hash mismatch']) {
  test(`historical day-two ${drift} invalidates previously prepared primary teardown authority`, async () => fixture(async (gateway) => {
    const added = await addHistoricalInstalledSource(gateway);
    const send = await gateway.teardown();
    const valid = await send('prove');
    assert.equal(valid.status, 200, await valid.clone().text());
    const key = 'ankka-mcp-gateway/management-control/v1';
    const control = gateway.managementStorage.snapshot(key);
    const owned = control.sourceOwnership.find(({ sourceId }) => sourceId === added.source.id);
    if (drift === 'root Portal application alias') {
      const portalApplicationId = app(gateway, 'mcp_portal').id;
      owned.resources[1].provider.id = portalApplicationId;
      owned.resources[2].provider.parentId = portalApplicationId;
    } else {
      owned.resources[0].desiredHash = `sha256:${'0'.repeat(64)}`;
    }
    await gateway.managementStorage.put(key, control);
    const baseline = gateway.provider.requests.length;
    const proof = await send('prove');
    assert.equal(proof.status, 409);
    const result = await send('apply', 'Q'.repeat(22));
    assert.equal(result.status, 409);
    assertNoMutation(gateway.provider, baseline);
    assert.equal(gateway.provider.deletes().length, 0);
    assert.equal(gateway.provider.liveResourceCount(), 10);
  }));
}

test('pristine historical two-source additions retain exact primary-runtime teardown order without native Team state', async () => fixture(async (gateway) => {
  const first = await addHistoricalInstalledSource(gateway);
  const second = await addHistoricalInstalledSource(gateway, {
    label: 'Historical shared OAuth source', url: 'https://other.example.net/mcp', authMode: 'oauth',
  });
  assert.equal(gateway.managementStorage.snapshot(TEAM_KEY), undefined);
  assert.equal(gateway.provider.liveResourceCount(), 13);
  const send = await gateway.teardown();
  const proof = await send('prove');
  assert.equal(proof.status, 200, await proof.clone().text());
  const response = await send('apply', 'Q'.repeat(22));
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal((await response.json()).removedResourceCount, 13);
  assert.equal(gateway.provider.liveResourceCount(), 0);
  const expectedExtraIds = [first, second].sort((left, right) => right.source.id.localeCompare(left.source.id))
    .flatMap(({ resources }) => [...resources].reverse().map(({ provider }) => provider.id));
  assert.deepEqual(gateway.provider.deletes().slice(0, 6).map(({ pathname }) => pathname.split('/').at(-1)), expectedExtraIds);
}));

// New source provisioning has a distinct empty initial audience. It must not
// inherit the original receipt audience or change existing saved assignments.
for (const initialState of ['before first Team view', 'after Team view', 'after a no-op', 'after a Team mutation']) {
  test(`new source starts denied ${initialState} without changing existing grants or receipts`, async () => fixture(async (gateway) => {
    assert.equal(gateway.managementStorage.snapshot(TEAM_KEY), undefined);
    if (initialState !== 'before first Team view') {
      const team = await gateway.view();
      if (initialState === 'after a no-op' || initialState === 'after a Team mutation') {
        const input = initialState === 'after a no-op'
          ? { schemaVersion: 1, expectedRevision: team.revision, members: team.members }
          : changedRequest(team);
        const result = await gateway.apply(await gateway.draft(input));
        assert.equal(result.status, 200, await result.clone().text());
      }
    }
    const publicSources = await (await gateway.api('/api/sources')).json();
    assert.equal(publicSources.installationEnabled, true);
    assert.equal(Object.hasOwn(gateway.managementStorage.snapshot(SOURCES_KEY), 'installationEnabled'), false);
    const originalPolicies = new Map([...gateway.provider.state.policies].map(([id, policies]) => [id, canonicalJson(policies)]));
    const originalMappings = structuredClone(gateway.provider.state.portal.servers);
    const originalReceipt = canonicalJson(gateway.storage.snapshot());
    const originalTeam = gateway.managementStorage.snapshot(TEAM_KEY);
    const baseline = gateway.provider.requests.length;
    const prepared = await prepareNewSource(gateway);
    assertNoMutation(gateway.provider, baseline);
    assert.deepEqual(gateway.managementStorage.snapshot(TEAM_KEY), originalTeam, 'draft and review do not arm a floor');
    const applied = await gateway.apply(prepared, {}, null);
    assert.equal(applied.status, 200, await applied.clone().text());
    const team = await gateway.view();
    assert.equal(team.sources.find((source) => source.id === prepared.source.id).status, 'installed');
    assert.equal(team.members.some((member) => member.sourceIds.includes(prepared.source.id)), false);
    if (originalTeam) {
      assert.deepEqual(team.members, originalTeam.members);
      assert.equal(team.revision, originalTeam.revision);
    }
    const ownership = gateway.managementStorage.snapshot('ankka-mcp-gateway/management-control/v1')
      .sourceOwnership.find((entry) => entry.sourceId === prepared.source.id);
    const newPolicy = gateway.provider.state.policies.get(ownership.resources[1].provider.id);
    assert.equal(newPolicy.length, 1);
    assert.deepEqual(newPolicy[0].include, [{ everyone: {} }]);
    assert.equal(newPolicy[0].decision, 'deny');
    assert.equal(ownership.resources[2].identityHash, await prefixedSha256({ emails: [] }));
    const retainedTeam = gateway.managementStorage.snapshot(TEAM_KEY);
    assert.equal(retainedTeam.teardownDisabled, true);
    assert.equal(retainedTeam.minimumRuntimeRelease, gateway.env.ANKKA_GATEWAY_RELEASE);
    for (const [id, policies] of originalPolicies) assert.equal(canonicalJson(gateway.provider.state.policies.get(id)), policies);
    assert.deepEqual(gateway.provider.state.portal.servers.filter((mapping) => mapping.server_id !== ownership.resources[0].provider.id), originalMappings);
    assert.equal(canonicalJson(gateway.storage.snapshot()), originalReceipt);
    assert.equal(gateway.provider.liveResourceCount(), 10);
    const next = { schemaVersion: 1, expectedRevision: team.revision,
      members: team.members.map((member) => member.email === ADMIN
        ? { ...member, sourceIds: [...member.sourceIds, prepared.source.id] } : member) };
    const granted = await gateway.apply(await gateway.draft(next));
    assert.equal(granted.status, 200, await granted.clone().text());
    assert.deepEqual(gateway.provider.state.policies.get(ownership.resources[1].provider.id)[0].include,
      [{ email: { email: ADMIN } }]);
  }));
}

for (const status of ['authorization_required', 'recovery_required']) {
  test(`a legacy ${status} source handoff cannot resume an old Allow policy`, async () => fixture(async (gateway) => {
    const originalReceipt = canonicalJson(gateway.storage.snapshot());
    const prepared = await historicalPreparedSource(gateway, status);
    const originalPolicies = canonicalJson([...gateway.provider.state.policies]);
    const originalMappings = canonicalJson(gateway.provider.state.portal.servers);
    const baseline = gateway.provider.requests.length;
    const storageWrites = gateway.managementStorage.writes.length;
    const originalActions = gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY);
    const originalSources = gateway.managementStorage.snapshot(SOURCES_KEY);
    const renewal = await gateway.api('/api/source-actions', { method: 'POST', body: {
      schemaVersion: 1, revision: prepared.sources.revision, sourceId: prepared.source.id,
    } });
    assert.equal(renewal.status, 409);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const response = await gateway.apply(prepared, {}, null);
      assert.equal(response.status, 409);
      assert.equal((await response.json()).error, 'source_action_legacy_policy');
    }
    const wrongKey = await gateway.apply({ ...prepared, claim: { ...prepared.claim, actionKey: 'Z'.repeat(43) } }, {}, null);
    assert.equal(wrongKey.status, 400);
    assert.equal(gateway.provider.requests.length, baseline);
    assert.equal(gateway.managementStorage.writes.length, storageWrites);
    assert.deepEqual(gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY), originalActions);
    assert.deepEqual(gateway.managementStorage.snapshot(SOURCES_KEY), originalSources);
    assert.equal(canonicalJson([...gateway.provider.state.policies]), originalPolicies);
    assert.equal(canonicalJson(gateway.provider.state.portal.servers), originalMappings);
    assert.equal(canonicalJson(gateway.storage.snapshot()), originalReceipt);
    assert.equal(canonicalJson(gateway.managementStorage.writes).includes(SYNTHETIC_MANAGEMENT_TOKEN), false);
  }));
}

test('source installation preserves administrator and same-origin authorization', async () => fixture(async (gateway) => {
  const baseline = gateway.provider.requests.length;
  const sources = await (await gateway.api('/api/sources')).json();
  for (const path of ['/api/sources', '/api/source-actions']) {
    const method = path === '/api/sources' ? 'PUT' : 'POST';
    const body = { schemaVersion: 1, revision: sources.revision };
    const anonymous = await worker.fetch(new Request(`${MANAGEMENT_ORIGIN}${path}`, {
      method, headers: { 'content-type': 'application/json', origin: MANAGEMENT_ORIGIN }, body: canonicalJson(body),
    }), gateway.env);
    assert.equal(anonymous.status, 401);
    assert.equal((await gateway.api(path, { method, body, email: MEMBER })).status, 401);
    assert.equal((await gateway.api(path, { method, body, extraHeaders: { origin: 'https://other.example.com' } })).status, 403);
  }
  assert.equal(gateway.provider.requests.length, baseline);
}));

test('a fresh empty Portal can install its first source without implicitly granting it to anyone', async () => fixture(async (gateway) => {
  const prepared = await prepareNewSource(gateway);
  assert.equal(gateway.managementStorage.snapshot(TEAM_KEY), undefined);
  const response = await gateway.apply(prepared, {}, null);
  assert.equal(response.status, 200, await response.clone().text());
  const team = await gateway.view();
  assert.equal(team.sources.length, 1);
  assert.equal(team.members.every((member) => member.sourceIds.length === 0), true);
  assert.equal(gateway.provider.state.portal.servers[0].on_behalf, false);
  assert.equal(gateway.provider.state.portal.servers[0].default_disabled, true);
}, await portalOnlyClaim()));

for (const createdBeforeFailure of [false, true]) {
  test(`source create uncertainty preserves its journal and floor (provider committed: ${createdBeforeFailure})`, async () => fixture(async (gateway) => {
    const prepared = await prepareNewSource(gateway);
    const originalReceipt = canonicalJson(gateway.storage.snapshot());
    const originalMappings = structuredClone(gateway.provider.state.portal.servers);
    gateway.provider.hook(({ record, state }) => {
      if (record.method !== 'POST' || !record.pathname.endsWith('/mcp/servers')) return undefined;
      const team = gateway.managementStorage.snapshot(TEAM_KEY);
      assert.equal(team.teardownDisabled, true, 'floor must be durable before potential creation');
      assert.equal(team.minimumRuntimeRelease, gateway.env.ANKKA_GATEWAY_RELEASE);
      if (createdBeforeFailure) state.servers.set(record.body.id, { ...record.body, status: 'ready' });
      return envelope(null, 503);
    });
    const response = await gateway.apply(prepared, {}, null);
    assert.equal(response.status, 409);
    const retained = gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY).actions.at(-1);
    assert.equal(retained.status, 'recovery_required');
    assert.equal(retained.initialPolicyVersion, 2);
    assert.deepEqual(retained.pending, { kind: 'mcp_server', phase: 'send_armed', provider: null });
    const cancelled = await gateway.api(`/api/source-actions/${retained.actionId}`, { method: 'DELETE' });
    assert.equal(cancelled.status, 409);
    assert.deepEqual(gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY).actions.at(-1), retained);
    assert.deepEqual(gateway.provider.state.portal.servers, originalMappings);
    assert.equal(canonicalJson(gateway.storage.snapshot()), originalReceipt);
    gateway.provider.hook(undefined);
    const baseline = gateway.provider.requests.length;
    const renewed = await authorizeNewSource(gateway, prepared.source.id, prepared.sources.revision);
    const recovered = await gateway.apply(renewed, {}, null);
    assert.equal(recovered.status, 200, await recovered.clone().text());
    assert.equal(gateway.provider.requests.slice(baseline).filter((record) =>
      record.method === 'POST' && record.pathname.endsWith('/mcp/servers')).length, createdBeforeFailure ? 0 : 1);
    assert.equal((await gateway.view()).members.some((member) => member.sourceIds.includes(prepared.source.id)), false);
  }));
}

for (const committedBeforeInterruption of [false, true]) {
  test(`source finalization is all-or-nothing across ownership, installed status and journal (committed: ${committedBeforeInterruption})`, async () => fixture(async (gateway) => {
    const prepared = await prepareNewSource(gateway);
    const controlKey = 'ankka-mcp-gateway/management-control/v1';
    const originalControl = gateway.managementStorage.snapshot(controlKey);
    const originalSources = gateway.managementStorage.snapshot(SOURCES_KEY);
    const originalPut = gateway.managementStorage.put;
    let interrupted = false;
    gateway.managementStorage.put = async (key, value) => {
      if (Object.hasOwn(key, SOURCES_KEY)) {
        assert.deepEqual(Object.keys(key).sort(), [controlKey, SOURCES_KEY, SOURCE_ACTIONS_KEY].sort());
        const completed = key[SOURCE_ACTIONS_KEY].actions.find((action) => action.actionId === prepared.claim.actionId);
        assert.equal(completed.status, 'succeeded');
        assert.equal(key[SOURCES_KEY].sources.find((source) => source.id === prepared.source.id).status, 'installed');
        assert.deepEqual(key[controlKey].sourceOwnership.find((entry) => entry.sourceId === prepared.source.id).resources,
          completed.resources);
        interrupted = true;
        if (committedBeforeInterruption) await originalPut(key);
        throw new Error('synthetic local commit interruption');
      }
      return originalPut(key, value);
    };
    const response = await gateway.apply(prepared, {}, null);
    assert.equal(response.status, 503);
    assert.equal(interrupted, true);
    gateway.managementStorage.put = originalPut;
    const state = gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY);
    const action = state.actions.find((entry) => entry.actionId === prepared.claim.actionId);
    const baseline = gateway.provider.requests.length;
    if (committedBeforeInterruption) {
      assert.equal(action.status, 'succeeded');
      const refreshed = await gateway.api(`/api/source-actions/${action.actionId}`);
      assert.equal((await refreshed.json()).status, 'succeeded');
    } else {
      assert.deepEqual(gateway.managementStorage.snapshot(controlKey), originalControl);
      assert.deepEqual(gateway.managementStorage.snapshot(SOURCES_KEY), originalSources);
      assert.equal(action.status, 'applying');
      assert.equal(action.resources.length, 3);
      assert.equal(action.portalUpdate.phase, 'submitted');
      // A stopped applying request remains journaled. Once its old grant has
      // expired, a fresh authorization verifies provider state without replay.
      const now = Date.now();
      await gateway.managementStorage.put(SOURCE_ACTIONS_KEY, { ...state,
        actions: state.actions.map((entry) => entry.actionId === action.actionId
          ? { ...entry, issuedAt: now - 700_000, expiresAt: now - 100_000 } : entry) });
      const renewed = await authorizeNewSource(gateway, prepared.source.id, prepared.sources.revision);
      const recovered = await gateway.apply(renewed, {}, null);
      assert.equal(recovered.status, 200, await recovered.clone().text());
    }
    assertNoMutation(gateway.provider, baseline);
    const team = await gateway.view();
    assert.equal(team.sources.find((source) => source.id === prepared.source.id).status, 'installed');
    assert.equal(team.members.some((member) => member.sourceIds.includes(prepared.source.id)), false);
    assert.equal(gateway.managementStorage.snapshot(TEAM_KEY).teardownDisabled, true);
  }));
}

for (const decision of ['allow', 'bypass']) {
  test(`new source cannot be mapped when its native application has a competing ${decision} policy`, async () => fixture(async (gateway) => {
    const prepared = await prepareNewSource(gateway);
    const originalMappings = structuredClone(gateway.provider.state.portal.servers);
    gateway.provider.hook(({ record, state }) => {
      if (record.method !== 'GET' || !record.pathname.endsWith('/policies')) return undefined;
      const id = record.pathname.split('/').at(-2);
      const policies = state.policies.get(id);
      if (policies?.length === 1 && policies[0].decision === 'deny') {
        policies.push({ id: 'foreign-policy', name: 'Unrelated policy', decision, include: [{ everyone: {} }], exclude: [], require: [] });
      }
      return undefined;
    });
    const response = await gateway.apply(prepared, {}, null);
    assert.equal(response.status, 409);
    assert.deepEqual(gateway.provider.state.portal.servers, originalMappings);
    assert.equal(gateway.provider.puts().length, 0);
  }));
}

test('new source checks the exact Portal baseline before its first mapping PUT', async () => fixture(async (gateway) => {
  const prepared = await prepareNewSource(gateway);
  gateway.provider.state.portal.servers.push({ server_id: 'foreign-server', default_disabled: true,
    on_behalf: false, updated_tools: [{ name: 'foreign_read', enabled: true }] });
  const mappings = structuredClone(gateway.provider.state.portal.servers);
  const response = await gateway.apply(prepared, {}, null);
  assert.equal(response.status, 409);
  assert.equal((await response.json()).error, 'portal_drift');
  assert.equal(gateway.provider.puts().length, 0);
  assert.deepEqual(gateway.provider.state.portal.servers, mappings);
}));

test('stale source revisions stop provisioning before any mutation', async () => fixture(async (gateway) => {
  const prepared = await prepareNewSource(gateway);
  const saved = gateway.managementStorage.snapshot(SOURCES_KEY);
  await gateway.managementStorage.put(SOURCES_KEY, { ...saved, revision: saved.revision + 1 });
  const baseline = gateway.provider.requests.length;
  const response = await gateway.apply(prepared, {}, null);
  assert.equal(response.status, 409);
  assert.equal((await response.json()).error, 'source_action_conflict');
  assertNoMutation(gateway.provider, baseline);
  assert.equal(gateway.managementStorage.snapshot(TEAM_KEY), undefined);
}));

test('another prepared lifecycle action stops source provisioning before its first mutation', async () => fixture(async (gateway) => {
  const prepared = await prepareNewSource(gateway);
  await gateway.teardown();
  const baseline = gateway.provider.requests.length;
  const response = await gateway.apply(prepared, {}, null);
  assert.equal(response.status, 409);
  assert.equal((await response.json()).error, 'source_action_conflict');
  assertNoMutation(gateway.provider, baseline);
  assert.equal(gateway.managementStorage.snapshot(TEAM_KEY), undefined);
}));

for (const status of ['authorization_required', 'failed', 'recovery_required']) {
  test(`an expired other ${status} source journal is retained and blocks new preparation`, async () => fixture(async (gateway) => {
    const prepared = await prepareNewSource(gateway);
    const saved = gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY);
    const now = Date.now();
    const uncertain = { ...saved.actions[0], actionId: `action_${'X'.repeat(32)}`,
      sourceId: 'source-5555555555555555', issuedAt: now - 700_000, expiresAt: now - 100_000,
      status, pending: { kind: 'mcp_server', phase: 'send_armed', provider: null } };
    const retained = { ...saved, actions: [...saved.actions, uncertain] };
    await gateway.managementStorage.put(SOURCE_ACTIONS_KEY, retained);
    const baseline = gateway.provider.requests.length;
    const writes = gateway.managementStorage.writes.length;
    const response = await gateway.api('/api/source-actions', { method: 'POST', body: {
      schemaVersion: 1, revision: prepared.sources.revision, sourceId: prepared.source.id,
    } });
    assert.equal(response.status, 409);
    assert.deepEqual(gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY), retained);
    assert.equal(gateway.managementStorage.writes.length, writes);
    assertNoMutation(gateway.provider, baseline);
    assert.equal(gateway.managementStorage.snapshot(TEAM_KEY), undefined);
  }));
}

for (const [field, value] of [
  ['id', 'foreign-portal'], ['name', 'Unrelated Portal'], ['hostname', 'other.example.com'],
  ['description', 'foreign-marker'], ['code_mode', 'default_off'], ['secure_web_gateway', true],
  ['servers', null],
]) {
  test(`an empty Portal with malformed ${field} cannot be overwritten during first-source installation`, async () => fixture(async (gateway) => {
    const prepared = await prepareNewSource(gateway);
    gateway.provider.hook(({ record, state }) => record.method === 'GET' &&
      record.pathname.endsWith(`/mcp/portals/${state.portal.id}`)
      ? envelope({ ...state.portal, [field]: value }) : undefined);
    const response = await gateway.apply(prepared, {}, null);
    assert.equal(response.status, 409);
    assert.equal((await response.json()).error, 'portal_drift');
    assert.equal(gateway.provider.puts().length, 0);
    assert.equal(gateway.provider.state.portal.servers, undefined);
  }, await portalOnlyClaim()));
}

test('new receipt hashes cannot be relabeled as legacy authority to grant access', async () => fixture(async (gateway) => {
  const prepared = await prepareNewSource(gateway);
  const installed = await gateway.apply(prepared, {}, null);
  assert.equal(installed.status, 200);
  const team = await gateway.view();
  const controlKey = 'ankka-mcp-gateway/management-control/v1';
  const control = gateway.managementStorage.snapshot(controlKey);
  const ownership = control.sourceOwnership.find((entry) => entry.sourceId === prepared.source.id);
  ownership.resources[2].identityHash = await prefixedSha256({ emails: control.audienceEmails });
  await gateway.managementStorage.put(controlKey, control);
  const baseline = gateway.provider.requests.length;
  const response = await gateway.apply(await gateway.draft({ schemaVersion: 1, expectedRevision: team.revision,
    members: team.members.map((member) => member.email === ADMIN
      ? { ...member, sourceIds: [...member.sourceIds, prepared.source.id] } : member),
  }));
  assert.equal(response.status, 409);
  assert.equal(gateway.provider.requests.length, baseline);
}));

test('restoring Team from legacy and native source receipts never grants a new source or loses its compatibility floor', async () => fixture(async (gateway) => {
  const prepared = await prepareNewSource(gateway);
  const response = await gateway.apply(prepared, {}, null);
  assert.equal(response.status, 200);
  // Model a restored source/ownership snapshot with no saved Team record.
  await gateway.managementStorage.put(TEAM_KEY, undefined);
  const baseline = gateway.provider.requests.length;
  const team = await gateway.view();
  assert.equal(team.members.some((member) => member.sourceIds.includes(prepared.source.id)), false);
  const legacySource = team.sources.find((source) => source.id !== prepared.source.id);
  assert.ok(team.members.some((member) => member.sourceIds.includes(legacySource.id)));
  assert.equal(gateway.managementStorage.snapshot(TEAM_KEY).minimumRuntimeRelease, gateway.env.ANKKA_GATEWAY_RELEASE);
  assert.equal(gateway.managementStorage.snapshot(TEAM_KEY).teardownDisabled, true);
  assertNoMutation(gateway.provider, baseline);
}));

test('an unstarted old source handoff can be cancelled but an old armed journal remains untouched', async () => {
  for (const phase of ['authorization_required', 'recovery_required']) await fixture(async (gateway) => {
    const prepared = await historicalPreparedSource(gateway, phase);
    const before = gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY);
    const cancelled = await gateway.api(`/api/source-actions/${prepared.claim.actionId}`, { method: 'DELETE' });
    assert.equal(cancelled.status, phase === 'authorization_required' ? 200 : 409);
    if (phase === 'recovery_required') assert.deepEqual(gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY), before);
    else {
      const next = await authorizeNewSource(gateway, prepared.source.id, prepared.sources.revision);
      assert.notEqual(next.claim.actionId, prepared.claim.actionId);
      assert.equal(gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY).actions.at(-1).initialPolicyVersion, 2);
    }
  });
});

test('inspection, preparation and no-op application do not disable pristine teardown or create a rollback floor', async () => fixture(async (gateway) => {
  const initial = await gateway.view();
  const assertPristine = () => {
    const state = gateway.managementStorage.snapshot(TEAM_KEY);
    assert.equal(state.minimumRuntimeRelease, null);
    assert.equal(state.teardownDisabled, false);
  };
  assertPristine();
  const prepared = await gateway.draft({ schemaVersion: 1, expectedRevision: initial.revision, members: initial.members });
  assertPristine();
  const baseline = gateway.provider.requests.length;
  const response = await gateway.apply(prepared);
  assert.equal(response.status, 200, await response.clone().text());
  assertNoMutation(gateway.provider, baseline);
  assertPristine();
  const send = await gateway.teardown();
  const proof = await send('prove');
  assert.equal(proof.status, 200, await proof.clone().text());
}));

test('preflight failure before any PUT leaves teardown and rollback floor pristine', async () => fixture(async (gateway) => {
  const prepared = await gateway.draft(changedRequest(await gateway.view()));
  policy(gateway).include = [{ group: { id: 'synthetic-group' } }];
  const baseline = gateway.provider.requests.length;
  const response = await gateway.apply(prepared);
  assert.equal(response.status, 409, await response.clone().text());
  assertNoMutation(gateway.provider, baseline);
  const state = gateway.managementStorage.snapshot(TEAM_KEY);
  assert.equal(state.minimumRuntimeRelease, null);
  assert.equal(state.teardownDisabled, false);
}));

test('rollback floor and teardown exclusion are durable before the first native policy write is sent', async () => fixture(async (gateway) => {
  const prepared = await gateway.draft(changedRequest(await gateway.view()));
  let inspected = false;
  gateway.provider.hook(({ record }) => {
    if (record.method !== 'PUT' || !record.pathname.startsWith(`${API_APPS}/`)) return undefined;
    const state = gateway.managementStorage.snapshot(TEAM_KEY);
    assert.equal(state.minimumRuntimeRelease, gateway.env.ANKKA_GATEWAY_RELEASE);
    assert.equal(state.teardownDisabled, true);
    assert.ok(state.pendingAction.journal.some((entry) => entry.phase === 'send_armed'));
    inspected = true;
    return envelope(null, 503);
  });
  const response = await gateway.apply(prepared);
  assert.equal(response.status, 409, await response.clone().text());
  assert.equal(inspected, true);
  assert.equal(gateway.managementStorage.snapshot(TEAM_KEY).teardownDisabled, true);
}));

test('a previously authorized teardown cannot prove or execute after native permission exclusion is recorded', async () => fixture(async (gateway) => {
  const send = await gateway.teardown();
  await gateway.view();
  const originalReceipt = canonicalJson(gateway.readyReceipt);
  // Model a retained authorization presented after a separately durable native
  // mutation boundary. The exclusion must be enforced at execution, not just
  // by hiding or disabling the fresh handoff UI.
  await gateway.managementStorage.put(TEAM_KEY, {
    ...gateway.managementStorage.snapshot(TEAM_KEY),
    minimumRuntimeRelease: gateway.env.ANKKA_GATEWAY_RELEASE, teardownDisabled: true,
  });
  const baseline = gateway.provider.requests.length;
  for (const [command, requestId] of [['prove', undefined], ['apply', 'U'.repeat(22)]]) {
    const response = await send(command, requestId);
    assert.equal(response.status, 409, await response.clone().text());
  }
  assertNoMutation(gateway.provider, baseline);
  assert.equal(gateway.provider.deletes().length, 0);
  assert.equal(canonicalJson(gateway.storage.snapshot()), originalReceipt);
}));

test('concurrent Team saves serialize revision checks and never duplicate policy writes', async () => fixture(async (gateway) => {
  const input = changedRequest(await gateway.view());
  const conflicting = { ...input, members: input.members.map(({ email }) => ({ email, sourceIds: [] })) };
  const results = await Promise.all([
    gateway.api('/api/team-actions', { method: 'POST', body: input }),
    gateway.api('/api/team-actions', { method: 'POST', body: conflicting }),
  ]);
  assert.deepEqual(results.map((response) => response.status).sort(), [200, 409]);
  const saved = await results.find((response) => response.status === 200).json();
  assert.equal(saved.action.status, 'succeeded');
  assert.equal(Object.hasOwn(saved, 'handoffUrl'), false);
  const retried = await gateway.api('/api/team-actions', { method: 'POST', body: input });
  assert.equal(retried.status, 409);
  assert.equal(gateway.provider.puts().length, 2);
  assert.equal((await gateway.view()).revision, input.expectedRevision + 1);
}));

test('a newly added person receives no source permission without an explicit assignment', async () => fixture(async (gateway) => {
  const initial = await gateway.view();
  const originalSourcePolicy = canonicalJson(policy(gateway));
  const input = { schemaVersion: 1, expectedRevision: initial.revision,
    members: [...initial.members, { email: NEW_PERSON, sourceIds: [] }] };
  const response = await gateway.apply(await gateway.draft(input));
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal(canonicalJson(policy(gateway)), originalSourcePolicy);
  assert.deepEqual((await gateway.view()).members.find(({ email }) => email === NEW_PERSON).sourceIds, []);
  assert.equal(gateway.provider.puts().length, 1);
  assert.ok(policy(gateway, 'mcp_portal').include.some(({ email }) => email.email === NEW_PERSON));
}));

test('a successful PUT echo does not substitute for exact complete-policy readback', async () => fixture(async (gateway) => {
  const prepared = await gateway.draft(changedRequest(await gateway.view()));
  gateway.provider.hook(({ record }) => {
    if (record.method !== 'PUT' || !record.pathname.startsWith(`${API_APPS}/`)) return undefined;
    const policyId = record.pathname.split('/').at(-1);
    return envelope({ id: policyId, ...record.body });
  });
  const response = await gateway.apply(prepared);
  assert.equal(response.status, 409, await response.clone().text());
  assert.equal(gateway.provider.puts().length, 1);
  assert.equal(gateway.managementStorage.snapshot(TEAM_KEY).revision, 1);
}));

test('a competing Bypass introduced during a partial update stops remaining policy writes', async () => fixture(async (gateway) => {
  const input = changedRequest(await gateway.view());
  const prepared = await gateway.draft(input);
  let introduced = false;
  gateway.provider.hook(({ record, state }) => {
    if (introduced || record.method !== 'GET' || !record.pathname.endsWith('/policies') || gateway.provider.puts().length === 0) return undefined;
    const appId = record.pathname.split('/').at(-2);
    state.policies.get(appId).push({
      id: 'x'.repeat(32), name: 'Unrelated access', decision: 'bypass',
      include: [{ everyone: {} }], exclude: [], require: [],
    });
    introduced = true;
    return undefined;
  });
  const response = await gateway.apply(prepared);
  assert.equal(response.status, 409, await response.clone().text());
  assert.equal(introduced, true);
  assert.equal(gateway.provider.puts().length, 1);
  assert.equal((await gateway.view()).revision, input.expectedRevision);
  gateway.provider.hook(undefined);
  const baseline = gateway.provider.requests.length;
  const recovery = await gateway.apply(await gateway.draft(input));
  assert.equal(recovery.status, 409, await recovery.clone().text());
  assertNoMutation(gateway.provider, baseline);
}));

test('a storage interruption after provider success recovers the armed journal without repeating that policy write', async () => fixture(async (gateway) => {
  const input = changedRequest(await gateway.view());
  const prepared = await gateway.draft(input);
  const originalPut = gateway.managementStorage.put;
  let interrupted = false;
  gateway.managementStorage.put = async (key, value) => {
    if (!interrupted && key === TEAM_KEY && value.pendingAction?.journal.some((entry) => entry.phase === 'verified')) {
      interrupted = true;
      throw new Error(`${NEW_PERSON}: synthetic private storage failure`);
    }
    return originalPut(key, value);
  };
  const first = await gateway.apply(prepared);
  assert.ok(first.status >= 400, await first.clone().text());
  assert.doesNotMatch(await first.text(), /new-person@example\.com|synthetic private/u);
  assert.equal(interrupted, true);
  const firstPath = gateway.provider.puts()[0].pathname;
  gateway.managementStorage.put = originalPut;
  const recovered = await gateway.apply(await gateway.draft(input));
  assert.equal(recovered.status, 200, await recovered.clone().text());
  assert.equal(gateway.provider.puts().filter(({ pathname }) => pathname === firstPath).length, 1);
  assert.equal((await gateway.view()).revision, input.expectedRevision + 1);
}));

test('an unspent authorization can be cancelled but an armed policy journal cannot be discarded', async () => fixture(async (gateway) => {
  const input = changedRequest(await gateway.view());
  const first = await historicalPreparedTeam(gateway, input);
  const firstPath = `/api/team-actions/${first.authorization.actionId}`;
  const status = await gateway.api(firstPath);
  assert.equal((await status.json()).canCancel, true);
  const foreignActor = await gateway.api(firstPath, { method: 'DELETE', body: {}, email: OWNER });
  assert.equal(foreignActor.status, 409);
  const cancelled = await gateway.api(firstPath, { method: 'DELETE', body: {} });
  assert.equal(cancelled.status, 200, await cancelled.clone().text());
  assert.equal((await cancelled.json()).status, 'failed');
  const stale = await gateway.apply(first);
  assert.equal(stale.status, 410);
  assert.equal(gateway.provider.puts().length, 0);
  const second = await gateway.draft(input);
  gateway.provider.hook(({ record }) => record.method === 'PUT' ? envelope(null, 503) : undefined);
  const interrupted = await gateway.apply(second);
  assert.equal(interrupted.status, 409);
  const secondPath = `/api/team-actions/${(await gateway.view()).pendingAction.actionId}`;
  const pending = await gateway.api(secondPath);
  assert.equal((await pending.json()).canCancel, false);
  const before = canonicalJson(gateway.managementStorage.snapshot(TEAM_KEY));
  const rejected = await gateway.api(secondPath, { method: 'DELETE', body: {} });
  assert.equal(rejected.status, 409);
  assert.equal(canonicalJson(gateway.managementStorage.snapshot(TEAM_KEY)), before);
}));

test('matching policy UID and neutral non-reusable metadata do not prevent an exact permission update', async () => fixture(async (gateway) => {
  for (const policies of gateway.provider.state.policies.values()) {
    for (const value of policies) Object.assign(value, { uid: value.id, reusable: false, precedence: 1, account_id: ACCOUNT_ID });
  }
  const applied = await gateway.apply(await gateway.draft(changedRequest(await gateway.view())));
  assert.equal(applied.status, 200, await applied.clone().text());
  assert.equal(gateway.provider.puts().length, 2);
}));

test('a real native policy mutation prevents preparing rollback to a release below its durable floor', async () => fixture(async (gateway) => {
  const applied = await gateway.apply(await gateway.draft(changedRequest(await gateway.view())));
  assert.equal(applied.status, 200, await applied.clone().text());
  const rollback = await runtimeAction(gateway);
  const before = canonicalJson(gateway.managementStorage.snapshot(UPDATES_KEY));
  const result = await rollback.prepare();
  assert.equal(result.status, 409, await result.clone().text());
  assert.equal(canonicalJson(gateway.managementStorage.snapshot(UPDATES_KEY)), before);
}));

test('rollback authorized before a native mutation cannot begin below the subsequently recorded floor', async () => fixture(async (gateway) => {
  await gateway.view();
  const rollback = await runtimeAction(gateway);
  const prepared = await rollback.prepare();
  assert.equal(prepared.status, 200, await prepared.clone().text());
  await gateway.managementStorage.put(TEAM_KEY, {
    ...gateway.managementStorage.snapshot(TEAM_KEY),
    minimumRuntimeRelease: gateway.env.ANKKA_GATEWAY_RELEASE, teardownDisabled: true,
  });
  const before = canonicalJson(gateway.managementStorage.snapshot(UPDATES_KEY));
  const begun = await rollback.begin();
  assert.equal(begun.status, 409, await begun.clone().text());
  assert.equal(canonicalJson(gateway.managementStorage.snapshot(UPDATES_KEY)), before);
}));

test('the native permission floor still permits a valid newer runtime to prepare and begin', async () => fixture(async (gateway) => {
  const applied = await gateway.apply(await gateway.draft(changedRequest(await gateway.view())));
  assert.equal(applied.status, 200, await applied.clone().text());
  const update = await runtimeAction(gateway, { operation: 'update', release: 'gateway-v0.1.1' });
  const prepared = await update.prepare();
  assert.equal(prepared.status, 200, await prepared.clone().text());
  const begun = await update.begin();
  assert.equal(begun.status, 200, await begun.clone().text());
  assert.equal((await begun.json()).status, 'applying');
}));

test('local Team deadline aborts a hung provider fetch before any policy mutation', async () => fixture(async (gateway) => {
  const prepared = await gateway.draft(changedRequest(await gateway.view()));
  let sawAbort = false;
  gateway.provider.hook(({ request }) => new Promise((_resolve, reject) => {
    const abort = () => {
      sawAbort = true;
      reject(new Error(`${SYNTHETIC_MANAGEMENT_TOKEN}: ${NEW_PERSON} synthetic hung fetch`));
    };
    if (request.signal.aborted) abort();
    else request.signal.addEventListener('abort', abort, { once: true });
  }));
  const baseline = gateway.provider.requests.length;
  const { result, requested } = await shortenedTeamDeadline(() => gateway.apply(prepared));
  assert.deepEqual(requested, [60_000]);
  assert.equal(result.status, 409);
  assert.doesNotMatch(await result.text(), /synthetic-(?:legacy-installer-grant|team-management-token)|new-person@example\.com|synthetic hung/u);
  assert.equal(sawAbort, true);
  assertNoMutation(gateway.provider, baseline);
  assert.equal(gateway.provider.requests.length - baseline, 1);
  const state = gateway.managementStorage.snapshot(TEAM_KEY);
  assert.equal(state.pendingAction.status, 'recovery_required');
  assert.equal(state.pendingAction.journal.length, 0);
  assert.equal(state.teardownDisabled, false);
  assert.equal(canonicalJson(gateway.managementStorage.writes).includes(SYNTHETIC_MANAGEMENT_TOKEN), false);
}));

test('Team timeout cancels a hung PUT response body and recovers without blindly repeating the armed write', async () => fixture(async (gateway) => {
  const input = changedRequest(await gateway.view());
  const prepared = await gateway.draft(input);
  let cancelled = false;
  let armedPath;
  gateway.provider.hook(({ record, state }) => {
    if (record.method !== 'PUT' || !record.pathname.startsWith(`${API_APPS}/`)) return undefined;
    armedPath = record.pathname;
    const [appId, , policyId] = record.pathname.slice(API_APPS.length + 1).split('/');
    state.policies.set(appId, [{ id: policyId, ...structuredClone(record.body) }]);
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(`{"success":true,"private":"${SYNTHETIC_MANAGEMENT_TOKEN}","result":`));
      },
      cancel() { cancelled = true; },
    });
    return new Response(stream, { headers: { 'content-type': 'application/json' } });
  });
  const { result, requested } = await shortenedTeamDeadline(() => gateway.apply(prepared));
  assert.deepEqual(requested, [60_000]);
  assert.equal(result.status, 409);
  assert.doesNotMatch(await result.text(), /synthetic-(?:legacy-installer-grant|team-management-token)|new-person@example\.com/u);
  assert.equal(cancelled, true);
  assert.ok(armedPath);
  assert.equal(gateway.provider.puts().length, 1);
  assert.equal(gateway.provider.requests.at(-1).pathname, armedPath);
  const state = gateway.managementStorage.snapshot(TEAM_KEY);
  assert.equal(state.pendingAction.status, 'recovery_required');
  assert.equal(state.pendingAction.journal.at(-1).phase, 'send_armed');
  assert.equal(state.teardownDisabled, true);
  assert.equal(canonicalJson(gateway.managementStorage.writes).includes(SYNTHETIC_MANAGEMENT_TOKEN), false);
  gateway.provider.hook(undefined);
  const recovered = await gateway.apply(await gateway.draft(input));
  assert.equal(recovered.status, 200, await recovered.clone().text());
  assert.equal(gateway.provider.puts().filter(({ pathname }) => pathname === armedPath).length, 1);
  assert.equal(gateway.provider.puts().length, 2);
}));

test('partial Team recovery rejects source draft edits and installation without changing the reviewed source revision', async () => fixture(async (gateway) => {
  const historical = await historicalPreparedSource(gateway, null);
  const sources = historical.sources;
  const draft = historical.source;
  const draftInput = {
    schemaVersion: 1, revision: sources.revision,
    source: { label: 'Additional source', url: NEW_SOURCE_URL, authMode: 'none', enabledTools: ['company_lookup'] },
  };
  const input = changedRequest(await gateway.view());
  const prepared = await gateway.draft(input);
  let writes = 0;
  gateway.provider.hook(({ record }) => record.method === 'PUT' && ++writes === 2 ? envelope(null, 503) : undefined);
  const interrupted = await gateway.apply(prepared);
  assert.equal(interrupted.status, 409);
  assert.equal(gateway.managementStorage.snapshot(TEAM_KEY).pendingAction.status, 'recovery_required');
  const revisionBefore = canonicalJson(await (await gateway.api('/api/sources')).json());
  const edited = await gateway.api('/api/sources', { method: 'PUT', body: {
    ...draftInput, revision: sources.revision, source: { ...draftInput.source, label: 'Changed draft label' },
  } });
  assert.equal(edited.status, 409);
  assert.equal((await edited.json()).error, 'team_action_conflict');
  const install = await gateway.api('/api/source-actions', { method: 'POST', body: {
    schemaVersion: 1, revision: sources.revision, sourceId: draft.id,
  } });
  assert.equal(install.status, 409);
  const providerBaseline = gateway.provider.requests.length;
  const staleExecution = await gateway.apply(historical, {}, null);
  assert.equal(staleExecution.status, 409, await staleExecution.clone().text());
  assertNoMutation(gateway.provider, providerBaseline);
  assert.equal(canonicalJson(await (await gateway.api('/api/sources')).json()), revisionBefore);
  gateway.provider.hook(undefined);
  const recovered = await gateway.apply(await gateway.draft(input));
  assert.equal(recovered.status, 200, await recovered.clone().text());
  assert.equal((await gateway.view()).revision, input.expectedRevision + 1);
}));

test('Team transport accepts a bounded maximum-size roster and rejects a body above its 96 KiB ceiling', async () => fixture(async (gateway) => {
  const initial = await gateway.view();
  const sourceIds = Array.from({ length: 32 }, (_value, index) => `source-${String(index).padStart(25, '0')}`);
  const members = [ADMIN, OWNER, ...Array.from({ length: 49 }, (_value, index) => (
    `${`person-${index}`.padEnd(64, 'x')}@${'d'.repeat(185)}.com`
  ))].map((email) => ({ email, sourceIds }));
  const input = { schemaVersion: 1, expectedRevision: initial.revision, members };
  const inputBytes = Buffer.byteLength(canonicalJson(input));
  assert.ok(inputBytes > 32 * 1024 && inputBytes < 96 * 1024);
  const namespace = gateway.env.ADMIN_STATE;
  const received = [];
  // Stub only the public-route/DO transport seam. Actual identity, planner,
  // policy authorization and application tests elsewhere use the real DO.
  gateway.env.ADMIN_STATE = {
    ...namespace,
    get(name) {
      const original = namespace.get(name);
      return { async fetch(request) {
        if (name !== 'v1:management' || request.method !== 'POST' || new URL(request.url).pathname !== '/team-actions') {
          return original.fetch(request);
        }
        const wrapper = await request.json();
        received.push(wrapper.request);
        return Response.json({ schemaVersion: 1, error: 'synthetic_transport_inspected' }, { status: 400 });
      } };
    },
  };
  const accepted = await gateway.api('/api/team-actions', { method: 'POST', body: input });
  assert.equal(accepted.status, 400);
  assert.deepEqual(received, [input]);
  const oversized = { ...input, padding: '' };
  oversized.padding = 'x'.repeat(96 * 1024 + 1 - Buffer.byteLength(canonicalJson(oversized)));
  assert.equal(Buffer.byteLength(canonicalJson(oversized)), 96 * 1024 + 1);
  const rejected = await gateway.api('/api/team-actions', { method: 'POST', body: oversized });
  assert.equal(rejected.status, 400);
  assert.equal(received[1], null);
  assert.equal(gateway.provider.puts().length, 0);
}));

test('a later policy changed during the first PUT is re-read and never overwritten from stale preflight', async () => fixture(async (gateway) => {
  const prepared = await gateway.draft(changedRequest(await gateway.view()));
  let changed = false;
  gateway.provider.hook(({ record }) => {
    if (record.method === 'PUT' && !changed) {
      policy(gateway).include = [{ email: { email: 'unrelated@example.com' } }];
      changed = true;
    }
    return undefined;
  });
  const result = await gateway.apply(prepared);
  assert.equal(result.status, 409, await result.clone().text());
  assert.equal(changed, true);
  assert.equal(gateway.provider.puts().length, 1);
  assert.deepEqual(policy(gateway).include, [{ email: { email: 'unrelated@example.com' } }]);
  assert.equal(gateway.managementStorage.snapshot(TEAM_KEY).pendingAction.status, 'recovery_required');
}));

test('a retained v16 proposal resumes locally without discarding it or accepting its old handoff', async () => fixture(async (gateway) => {
  const input = changedRequest(await gateway.view());
  const legacy = await historicalPreparedTeam(gateway, input);
  const before = canonicalJson(gateway.managementStorage.snapshot(TEAM_KEY));
  const baseline = gateway.provider.requests.length;
  const stale = await gateway.apply(legacy);
  assert.equal(stale.status, 410);
  assertNoMutation(gateway.provider, baseline);
  assert.equal(canonicalJson(gateway.managementStorage.snapshot(TEAM_KEY)), before);
  const conflict = await gateway.api('/api/team-actions', { method: 'POST', body: {
    ...input, members: input.members.map(({ email }) => ({ email, sourceIds: [] })),
  } });
  assert.equal(conflict.status, 409);
  const applied = await gateway.api('/api/team-actions', { method: 'POST', body: input });
  assert.equal(applied.status, 200, await applied.clone().text());
  const result = await applied.json();
  assert.equal(result.action.actionId, legacy.claim.actionId);
  assert.equal(result.action.status, 'succeeded');
  assert.equal(Object.hasOwn(result, 'handoffUrl'), false);
  assert.equal(gateway.provider.puts().length, 2);
}));
