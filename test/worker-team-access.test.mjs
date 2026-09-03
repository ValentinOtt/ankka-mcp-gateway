import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import test from 'node:test';

import worker, { AdminState, planTeamAccessChange } from '../payload/worker/index.js';
import { addHistoricalInstalledSource } from './historical-source-fixture.mjs';
import {
  ACCOUNT_ID,
  BOOTSTRAP_NONCE,
  ZONE_ID,
  canonicalJson,
  cloudflareProvider,
  installReadyGateway,
  portalOnlyClaim,
  prefixedSha256,
  withProviderFetch,
} from './payload-lifecycle.mjs';

// Exercise the real Worker against synthetic Cloudflare resource state. V1
// keeps Team management read-only in the gateway; source and lifecycle tests
// continue to verify customer-owned resource and recovery invariants.
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
const API_APPS = `/client/v4/zones/${ZONE_ID}/access/apps`;
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
  let sourceRequestHook;
  const network = async (request) => {
    if (request.url === `${gateway.env.CF_ACCESS_ISSUER}/cdn-cgi/access/certs`) {
      return Response.json({ keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] });
    }
    if (request.url === NEW_SOURCE_URL) {
      await sourceRequestHook?.(request);
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
    headers, managementStorage,
    onSourceRequest(hook) { sourceRequestHook = hook; },
    reloadManagement() { instances.delete('v1:management'); },
  }));
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
  const valid = await api('/api/team-actions', { method: 'POST', body: input });
  assert.equal(valid.status, 409);
  assert.deepEqual(await valid.json(), { schemaVersion: 1, error: 'team_editing_managed_in_cloudflare' });
  assertNoMutation(provider, baseline);
}));

test('V1 Team state is read-only and never provisions or accepts a permanent management credential', async () => fixture(async (gateway) => {
  const view = await gateway.view();
  const before = canonicalJson(gateway.managementStorage.snapshot(TEAM_KEY));
  assert.equal(view.editingEnabled, false);
  assert.equal(view.editingDisabledReason, 'managed_in_cloudflare');
  assert.equal(view.managementCredentialConfigured, false);
  assert.equal(Object.hasOwn(gateway.env, 'ANKKA_TEAM_MANAGEMENT_TOKEN'), false);
  const baseline = gateway.provider.requests.length;
  const response = await gateway.api('/api/team-actions', {
    method: 'POST',
    body: changedRequest(view),
  });
  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), { schemaVersion: 1, error: 'team_editing_managed_in_cloudflare' });
  assertNoMutation(gateway.provider, baseline);
  assert.equal(canonicalJson(gateway.managementStorage.snapshot(TEAM_KEY)), before);
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
for (const initialState of ['before first Team view', 'after Team view']) {
  test(`new source starts denied ${initialState} without changing existing grants or receipts`, async () => fixture(async (gateway) => {
    assert.equal(gateway.managementStorage.snapshot(TEAM_KEY), undefined);
    if (initialState !== 'before first Team view') await gateway.view();
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
    const denied = await gateway.api('/api/team-actions', { method: 'POST', body: next });
    assert.equal(denied.status, 409);
    assert.deepEqual(await denied.json(), { schemaVersion: 1, error: 'team_editing_managed_in_cloudflare' });
    assert.deepEqual(gateway.provider.state.policies.get(ownership.resources[1].provider.id)[0].include,
      [{ everyone: {} }]);
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
    assert.equal(Object.hasOwn(gateway.env, 'ANKKA_TEAM_MANAGEMENT_TOKEN'), false);
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

test('slow consent is discoverable after reload and repeated Apply points to the same source action', async () => fixture(async (gateway) => {
  const prepared = await prepareNewSource(gateway);
  const retained = gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY);
  const baseline = gateway.provider.requests.length;
  let sourceRequests = 0;
  gateway.onSourceRequest(() => { sourceRequests += 1; });
  const pointer = { kind: 'source', actionId: prepared.claim.actionId, sourceId: prepared.source.id };
  for (let tab = 0; tab < 2; tab += 1) {
    gateway.reloadManagement();
    const response = await gateway.api('/api/source-actions');
    assert.equal(response.status, 200);
    const snapshot = await response.json();
    assert.deepEqual(snapshot.blockingAction, pointer);
    assert.equal(snapshot.actions.length, 1);
    const action = snapshot.actions[0];
    assert.equal(action.state, 'authorization_required');
    assert.equal(action.canCancel, true);
    assert.equal(action.issuedAt, new Date(retained.actions[0].issuedAt).toISOString());
    assert.equal(action.expiresAt, new Date(prepared.claim.expiresAt).toISOString());
    assert.doesNotMatch(canonicalJson(snapshot), /actionKey|actorEmail|accountId|provider|resources|sourceHash|cloudflareAccessToken|handoffUrl|catalog\.example/iu);
    const duplicate = await gateway.api('/api/source-actions', { method: 'POST', body: {
      schemaVersion: 1, revision: prepared.sources.revision, sourceId: prepared.source.id,
    } });
    assert.equal(duplicate.status, 409);
    assert.deepEqual(await duplicate.json(), { schemaVersion: 1, error: 'source_action_conflict',
      reason: 'source_pending', action: pointer });
  }
  assert.deepEqual(gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY), retained);
  assert.equal(sourceRequests, 0, 'duplicate preparation stops before remote discovery');
  assertNoMutation(gateway.provider, baseline);
  const otherAdmin = await (await gateway.api('/api/source-actions', { email: OWNER })).json();
  assert.equal(otherAdmin.actions[0].canCancel, false);
  assert.equal((await gateway.api(`/api/source-actions/${prepared.claim.actionId}`, { method: 'DELETE', email: OWNER })).status, 409);
  assert.equal((await gateway.api('/api/source-actions', { email: MEMBER })).status, 401);
  assert.equal((await worker.fetch(new Request(`${MANAGEMENT_ORIGIN}/api/source-actions`), gateway.env)).status, 401);
  assert.equal((await gateway.api('/api/source-actions', {
    extraHeaders: { 'cf-access-authenticated-user-email': OWNER },
  })).status, 401);
  assert.equal((await gateway.api(`/api/source-actions/${prepared.claim.actionId}`, {
    method: 'DELETE', extraHeaders: { origin: 'https://other.example.com' },
  })).status, 403);
  assert.equal((await gateway.api(`/api/source-actions/${prepared.claim.actionId}`, { method: 'DELETE' })).status, 200);
  assert.equal((await gateway.apply(prepared, {}, null)).status, 400, 'cancellation wins before execution claims');
  assertNoMutation(gateway.provider, baseline);
}));

test('an expired proven-unstarted source action requires owner cancellation before a fresh authorization', async () => fixture(async (gateway) => {
  const prepared = await prepareNewSource(gateway);
  const saved = gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY);
  const now = Date.now();
  await gateway.managementStorage.put(SOURCE_ACTIONS_KEY, { ...saved,
    actions: saved.actions.map((action) => ({ ...action, issuedAt: now - 700_000, expiresAt: now - 100_000 })) });
  const snapshot = await (await gateway.api('/api/source-actions')).json();
  assert.equal(snapshot.actions[0].state, 'authorization_expired');
  assert.equal(snapshot.actions[0].canCancel, true);
  assert.equal(snapshot.blockingAction.actionId, prepared.claim.actionId);
  const repeat = await gateway.api('/api/source-actions', { method: 'POST', body: {
    schemaVersion: 1, revision: prepared.sources.revision, sourceId: prepared.source.id,
  } });
  assert.equal(repeat.status, 409);
  assert.equal((await repeat.json()).reason, 'source_pending');
  const cancelled = await gateway.api(`/api/source-actions/${prepared.claim.actionId}`, { method: 'DELETE' });
  assert.equal(cancelled.status, 200);
  assert.equal((await cancelled.json()).status, 'failed');
  assert.equal((await (await gateway.api('/api/source-actions')).json()).blockingAction, null);
  const next = await authorizeNewSource(gateway, prepared.source.id, prepared.sources.revision);
  assert.notEqual(next.claim.actionId, prepared.claim.actionId);
  const baseline = gateway.provider.requests.length;
  assert.equal((await gateway.apply(prepared, {}, null)).status, 400, 'old callback cannot execute after cancellation');
  assertNoMutation(gateway.provider, baseline);
}));

test('expired armed, partial, failed-with-evidence and unknown execution states remain protected', async () => fixture(async (gateway) => {
  const prepared = await prepareNewSource(gateway);
  assert.equal((await gateway.apply(prepared, {}, null)).status, 200);
  const saved = gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY);
  const complete = saved.actions[0];
  const now = Date.now();
  const expired = { ...complete, issuedAt: now - 700_000, expiresAt: now - 100_000,
    resources: [], pending: null, portalUpdate: null };
  const cases = [
    { ...expired, status: 'authorization_required', pending: { kind: 'mcp_server', phase: 'send_armed', provider: null } },
    { ...expired, status: 'failed', pending: { kind: 'mcp_server', phase: 'submitted', provider: complete.resources[0].provider } },
    { ...expired, status: 'recovery_required', resources: complete.resources.slice(0, 1) },
    { ...expired, status: 'applying' },
    { ...expired, status: 'applying', resources: complete.resources,
      portalUpdate: { phase: 'submitted', desiredHash: `sha256:${'8'.repeat(64)}` } },
  ];
  for (const action of cases) {
    const retained = { ...saved, actions: [action] };
    await gateway.managementStorage.put(SOURCE_ACTIONS_KEY, retained);
    const before = gateway.managementStorage.writes.length;
    const baseline = gateway.provider.requests.length;
    const snapshot = await (await gateway.api('/api/source-actions')).json();
    assert.equal(snapshot.actions[0].state, 'recovery_required');
    assert.equal(snapshot.actions[0].canCancel, false);
    assert.equal(snapshot.blockingAction.actionId, action.actionId);
    for (const [path, options] of [
      [`/api/source-actions/${action.actionId}`, { method: 'DELETE' }],
      ['/api/source-actions', { method: 'POST', body: {
        schemaVersion: 1, revision: prepared.sources.revision, sourceId: prepared.source.id,
      } }],
    ]) {
      const response = await gateway.api(path, options);
      assert.equal(response.status, 409);
      assert.equal((await response.json()).reason, 'recovery_required');
    }
    assert.deepEqual(gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY), retained);
    assert.equal(gateway.managementStorage.writes.length, before);
    assertNoMutation(gateway.provider, baseline);
  }
}));

test('source execution claims before remote discovery, stays observable and wins a cancellation race safely', async () => fixture(async (gateway) => {
  const prepared = await prepareNewSource(gateway);
  let release;
  let entered;
  const held = new Promise((resolve) => { release = resolve; });
  const started = new Promise((resolve) => { entered = resolve; });
  gateway.onSourceRequest(async () => { entered(); await held; });
  const execution = gateway.apply(prepared, {}, null);
  await started;
  try {
    const snapshot = await (await gateway.api('/api/source-actions')).json();
    assert.equal(snapshot.actions[0].state, 'applying');
    assert.equal(snapshot.actions[0].canCancel, false);
    assert.equal((await gateway.api('/api/status')).status, 200);
    const during = await (await gateway.api('/api/sources')).json();
    assert.equal(during.sources.find((source) => source.id === prepared.source.id).status, 'draft');
    assert.equal((await (await gateway.api(`/api/source-actions/${prepared.claim.actionId}`)).json()).status, 'applying');
    const duplicate = await gateway.api('/api/source-actions', { method: 'POST', body: {
      schemaVersion: 1, revision: prepared.sources.revision, sourceId: prepared.source.id,
    } });
    assert.equal(duplicate.status, 409);
    assert.equal((await duplicate.json()).reason, 'source_pending');
    const cancellation = gateway.api(`/api/source-actions/${prepared.claim.actionId}`, { method: 'DELETE' });
    release();
    assert.equal((await execution).status, 200);
    assert.equal((await cancellation).status, 409);
    const completed = await (await gateway.api('/api/source-actions')).json();
    assert.equal(completed.actions[0].state, 'succeeded');
    assert.equal(completed.actions[0].canCancel, false);
    assert.equal(completed.blockingAction, null);
    const sources = await (await gateway.api('/api/sources')).json();
    assert.equal(sources.sources.find((source) => source.id === prepared.source.id).status, 'installed');
    assert.doesNotMatch(canonicalJson(gateway.managementStorage.writes), /synthetic-legacy-installer-grant-never-store|cloudflareAccessToken/iu);
  } finally { release(); }
}));

test('a stale source draft revision has its own conflict and creates no authorization', async () => fixture(async (gateway) => {
  const prepared = await prepareNewSource(gateway);
  assert.equal((await gateway.api(`/api/source-actions/${prepared.claim.actionId}`, { method: 'DELETE' })).status, 200);
  const saved = await gateway.api('/api/sources', { method: 'PUT', body: {
    schemaVersion: 1, revision: prepared.sources.revision,
    source: { label: 'Updated source label', url: NEW_SOURCE_URL, authMode: 'none', enabledTools: ['company_lookup'] },
  } });
  assert.equal(saved.status, 200);
  const retained = gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY);
  const stale = await gateway.api('/api/source-actions', { method: 'POST', body: {
    schemaVersion: 1, revision: prepared.sources.revision, sourceId: prepared.source.id,
  } });
  assert.equal(stale.status, 409);
  assert.deepEqual(await stale.json(), { schemaVersion: 1, error: 'source_action_conflict', reason: 'draft_changed' });
  assert.deepEqual(gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY), retained);
}));

test('invalid source journal state cannot be presented as idle or replaced', async () => fixture(async (gateway) => {
  const prepared = await prepareNewSource(gateway);
  const saved = gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY);
  const invalid = { ...saved, actions: [{ ...saved.actions[0], pending: { phase: 'unknown' } }] };
  await gateway.managementStorage.put(SOURCE_ACTIONS_KEY, invalid);
  const baseline = gateway.provider.requests.length;
  for (const options of [{}, { method: 'POST', body: {
    schemaVersion: 1, revision: prepared.sources.revision, sourceId: prepared.source.id,
  } }]) {
    const response = await gateway.api('/api/source-actions', options);
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { schemaVersion: 1, error: 'source_actions_unavailable' });
  }
  assert.deepEqual(gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY), invalid);
  assertNoMutation(gateway.provider, baseline);
}));

for (const kind of ['source', 'runtime', 'teardown', 'team']) {
  test(`source preparation identifies an unrelated ${kind} action`, async () => fixture(async (gateway) => {
    const prepared = await prepareNewSource(gateway);
    if (kind !== 'source') {
      assert.equal((await gateway.api(`/api/source-actions/${prepared.claim.actionId}`, { method: 'DELETE' })).status, 200);
      if (kind === 'runtime') assert.equal((await (await runtimeAction(gateway)).prepare()).status, 200);
      if (kind === 'teardown') await gateway.teardown();
      if (kind === 'team') await historicalPreparedTeam(gateway, changedRequest(await gateway.view()));
    }
    const response = await gateway.api('/api/source-actions', { method: 'POST', body: {
      schemaVersion: 1, revision: prepared.sources.revision, sourceId: 'source-5555555555555555',
    } });
    assert.equal(response.status, 409);
    const conflict = await response.json();
    assert.equal(conflict.reason, kind === 'source' ? 'source_pending' : 'lifecycle_pending');
    assert.equal(conflict.action.kind, kind);
    const snapshot = await (await gateway.api('/api/source-actions')).json();
    assert.deepEqual(snapshot.blockingAction, conflict.action);
  }));
}

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
    const renewal = await gateway.api('/api/source-actions', { method: 'POST', body: {
      schemaVersion: 1, revision: prepared.sources.revision, sourceId: prepared.source.id,
    } });
    assert.equal(renewal.status, 409);
    assert.equal((await renewal.json()).reason, 'recovery_required');
    assert.deepEqual(gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY).actions.at(-1), retained);
    assertNoMutation(gateway.provider, baseline);
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
      // Expiry does not establish whether the provider or final local commit
      // completed. Preserve the journal without minting a replacement action.
      const now = Date.now();
      await gateway.managementStorage.put(SOURCE_ACTIONS_KEY, { ...state,
        actions: state.actions.map((entry) => entry.actionId === action.actionId
          ? { ...entry, issuedAt: now - 700_000, expiresAt: now - 100_000 } : entry) });
      const retained = gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY);
      const renewal = await gateway.api('/api/source-actions', { method: 'POST', body: {
        schemaVersion: 1, revision: prepared.sources.revision, sourceId: prepared.source.id,
      } });
      assert.equal(renewal.status, 409);
      assert.equal((await renewal.json()).reason, 'recovery_required');
      assert.deepEqual(gateway.managementStorage.snapshot(SOURCE_ACTIONS_KEY), retained);
    }
    assertNoMutation(gateway.provider, baseline);
    const team = await gateway.view();
    assert.equal(team.sources.find((source) => source.id === prepared.source.id).status,
      committedBeforeInterruption ? 'installed' : 'draft');
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

test('an unstarted legacy Team proposal can be cancelled while an armed journal remains protected', async () => fixture(async (gateway) => {
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

  const second = await historicalPreparedTeam(gateway, input);
  const retained = gateway.managementStorage.snapshot(TEAM_KEY);
  retained.pendingAction.status = 'recovery_required';
  retained.pendingAction.failureCode = 'team_action_recovery_required';
  retained.pendingAction.journal = [{ policyId: 'm'.repeat(32), phase: 'send_armed' }];
  await gateway.managementStorage.put(TEAM_KEY, retained);
  const secondPath = `/api/team-actions/${second.authorization.actionId}`;
  const pending = await gateway.api(secondPath);
  assert.equal((await pending.json()).canCancel, false);
  const before = canonicalJson(gateway.managementStorage.snapshot(TEAM_KEY));
  const rejected = await gateway.api(secondPath, { method: 'DELETE', body: {} });
  assert.equal(rejected.status, 409);
  assert.equal(canonicalJson(gateway.managementStorage.snapshot(TEAM_KEY)), before);
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

test('a retained v16 proposal remains inspectable but cannot resume through the V1 gateway', async () => fixture(async (gateway) => {
  const input = changedRequest(await gateway.view());
  const legacy = await historicalPreparedTeam(gateway, input);
  const before = canonicalJson(gateway.managementStorage.snapshot(TEAM_KEY));
  const baseline = gateway.provider.requests.length;
  const stale = await gateway.apply(legacy);
  assert.equal(stale.status, 410);
  assertNoMutation(gateway.provider, baseline);
  assert.equal(canonicalJson(gateway.managementStorage.snapshot(TEAM_KEY)), before);
  const applied = await gateway.api('/api/team-actions', { method: 'POST', body: input });
  assert.equal(applied.status, 409);
  assert.deepEqual(await applied.json(), { schemaVersion: 1, error: 'team_editing_managed_in_cloudflare' });
  assert.equal(canonicalJson(gateway.managementStorage.snapshot(TEAM_KEY)), before);
  assert.equal(gateway.provider.puts().length, 0);
}));
