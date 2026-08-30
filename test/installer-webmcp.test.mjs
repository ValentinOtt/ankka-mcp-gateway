import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createContext, Script } from 'node:vm';
import { JSDOM } from 'jsdom';

const html = await readFile(new URL('../payload/installer/index.html', import.meta.url), 'utf8');
const asset = html.match(/<script src="(\/assets\/installer-[a-f0-9]{8}\.js)"><\/script>/u)?.[1];
assert.ok(asset, 'test the installer asset selected by its actual HTML');
const source = new Script(await readFile(new URL(`../payload/installer${asset}`, import.meta.url), 'utf8'));
const flush = () => new Promise((resolve) => setImmediate(resolve));
const targetIdHash = `sha256:${'a'.repeat(64)}`;
const planHash = `sha256:${'b'.repeat(64)}`;
const syntheticPrivate = 'SYNTHETIC_PRIVATE_VALUE_MUST_NOT_ESCAPE';
const handoff = `https://installer.example/oauth/handoff#${'A'.repeat(64)}`;
const expectedNames = [
  'begin_cloudflare_discovery', 'configure_gateway', 'create_review_plan',
  'get_installer_status', 'begin_authorization', 'create_removal_plan', 'begin_removal',
];

function sessionFixture() {
  return {
    schemaVersion: 1,
    csrf: 'synthetic-csrf',
    authorization: { status: 'anonymous' },
    capabilities: { selection: true, plan: true, deploy: true, uninstall: true, events: false, signedRelease: true },
    recovery: null,
    selection: {
      schemaVersion: 1,
      basics: {
        gatewayName: 'Example Gateway', zoneName: 'example.com', adminEmail: 'owner@example.com',
        additionalAdminEmails: [], managementHostname: 'manage.example.com', portalHostname: 'mcp.example.com',
      },
      firstSource: null,
    },
    plan: {
      planId: 'plan-synthetic', planHash, expiresAt: '2099-01-01T00:00:00.000Z',
      release: { version: 'gateway-v0.1.18' },
      resourceGroups: [{ label: 'Gateway', operations: ['Create reviewed runtime'] }],
      blockers: [],
    },
    deployment: null,
    removal: null,
  };
}

function removalFixture(planId = 'uninstall-plan-synthetic') {
  return {
    status: 'planned', canRetry: false, recovery: null,
    plan: {
      planId, planHash, expiresAt: '2099-01-01T00:00:00.000Z',
      providerNotice: 'Only reviewed resources are eligible.',
      operations: [{ label: 'Remove reviewed runtime' }],
    },
    failure: null, receipt: null,
  };
}

async function browser(t, options = {}) {
  const dom = new JSDOM(html, { url: 'https://installer.example/' });
  t.after(() => dom.window.close());
  const document = dom.window.document;
  const tools = new Map();
  const registered = [];
  const requests = [];
  const navigations = [];
  const logs = [];
  const timers = new Map();
  let nextTimer = 0;
  let failure = options.registrationFailure ?? null;
  const retained = {
    session: options.session ?? sessionFixture(),
    discovery: {
      schemaVersion: 1, status: 'ready', actorEmail: 'owner@example.com',
      targets: [{ targetIdHash, accountName: 'Example account', zoneName: 'example.com', extra: syntheticPrivate }],
      selectedTargetIdHash: targetIdHash, grantRevocation: 'confirmed', failureCode: null,
      extra: syntheticPrivate,
    },
  };
  const modelContext = {
    registerTool(tool, registrationOptions) {
      assert.deepEqual(Object.keys(registrationOptions), ['signal']);
      const { signal } = registrationOptions;
      registered.push(tool.name);
      if (failure && registered.length === failure.at) {
        const current = failure;
        failure = null;
        if (current.async) return Promise.reject(new Error(syntheticPrivate));
        throw new Error(syntheticPrivate);
      }
      if (signal.aborted) return Promise.reject(new Error('synthetic registration aborted'));
      assert.equal(tools.has(tool.name), false, 'no duplicate live registration');
      tools.set(tool.name, tool);
      signal.addEventListener('abort', () => tools.delete(tool.name), { once: true });
      return options.registrationPause?.(registered.length);
    },
  };
  if (!options.unsupported) Object.defineProperty(document, 'modelContext', { configurable: true, value: modelContext });
  const window = Object.assign(new EventTarget(), {
    location: { pathname: '/', hash: '', origin: 'https://installer.example', assign: (url) => navigations.push(url), replace: (url) => navigations.push(url) },
    history: { replaceState() {}, pushState() {} },
    scrollTo() {}, matchMedia: () => ({ matches: true }),
    setTimeout(callback) { timers.set(++nextTimer, callback); return nextTimer; },
    clearTimeout: (id) => timers.delete(id),
  });
  const context = createContext({
    window, document, URL, AbortController, structuredClone,
    console: { log: (...args) => logs.push(args), error: (...args) => logs.push(args) },
    fetch: async (url, init = {}) => {
      requests.push(structuredClone({ url, ...init }));
      const custom = await options.request?.(url, init, retained);
      if (custom !== undefined) return custom;
      if (url === '/api/session') return Response.json(retained.session);
      if (url === '/api/discovery' && (!init.method || init.method === 'GET')) return Response.json(retained.discovery);
      if (url === '/api/selection') {
        retained.session.selection = JSON.parse(init.body);
        return Response.json(retained.session);
      }
      if (url === '/api/plan' || url === '/api/uninstall/plan' || url === '/api/returning-uninstall/recovery/plan') {
        retained.session.removal ??= removalFixture();
        return Response.json(retained.session);
      }
      if (['/api/discovery', '/api/deploy', '/api/uninstall', '/api/returning-uninstall', '/api/returning-uninstall/recovery'].includes(url)) {
        return Response.json({ schemaVersion: 1, authorizationUrl: 'https://dash.cloudflare.com/oauth2/auth?synthetic=true', handoffUrl: handoff });
      }
      throw new Error('unexpected synthetic request');
    },
  });
  source.runInContext(context);
  await flush();
  requests.length = 0;
  return {
    document, window, context, tools, registered, requests, navigations, logs, retained,
    call: async (name, input = {}, executionOptions) => JSON.parse(await tools.get(name).execute(input, executionOptions)),
    dispatch: async (name) => { window.dispatchEvent(new Event(name)); await flush(); },
    enable: () => Object.defineProperty(document, 'modelContext', { configurable: true, value: modelContext }),
  };
}

test('registers exactly the seven existing tools with closed schemas and no cross-origin exposure', async (t) => {
  const current = await browser(t);
  assert.deepEqual([...current.tools.keys()], expectedNames);
  for (const tool of current.tools.values()) {
    assert.equal(tool.inputSchema.type, 'object');
    assert.equal(tool.inputSchema.additionalProperties, false);
  }
  assert.equal(current.tools.get('get_installer_status').annotations.readOnlyHint, true);
  await current.dispatch('focus');
  assert.equal(current.registered.length, 7);
  assert.deepEqual(current.navigations, []);
});

test('all tools validate arguments before shared handlers can perform requests', async (t) => {
  const current = await browser(t);
  for (const name of expectedNames) {
    for (const input of [null, [], 'not-an-object', { unexpected: syntheticPrivate }]) {
      const result = await current.call(name, input);
      assert.equal(result.ok, false);
      assert.equal(result.error.code, 'invalid_arguments');
      assert.ok(!JSON.stringify(result).includes(syntheticPrivate));
    }
  }
  const valid = { gatewayName: 'Example Gateway', targetIdHash, managementHostname: 'manage.example.com', portalHostname: 'mcp.example.com' };
  const sparseEmails = [];
  sparseEmails.length = 1;
  for (const change of [
    { gatewayName: '' }, { gatewayName: 'x'.repeat(81) }, { targetIdHash: 1 },
    { managementHostname: 'x'.repeat(254) }, { additionalAdminEmails: [null] },
    { additionalAdminEmails: ['same@example.com', 'same@example.com'] },
    { additionalAdminEmails: Array.from({ length: 20 }, (_, i) => `a${i}@example.com`) },
    { additionalAdminEmails: sparseEmails }, { additionalAdminEmails: ['x'.repeat(255)] },
  ]) assert.equal((await current.call('configure_gateway', { ...valid, ...change })).error.code, 'invalid_arguments');
  for (const name of ['begin_authorization', 'begin_removal']) {
    for (const input of [{}, { planHash: [] }, { planHash: 'x'.repeat(129) }]) {
      assert.equal((await current.call(name, input)).error.code, 'invalid_arguments');
    }
  }
  const accessor = {};
  Object.defineProperty(accessor, 'planHash', { enumerable: true, get() { throw new Error(syntheticPrivate); } });
  assert.equal((await current.call('begin_authorization', accessor)).error.code, 'invalid_arguments');
  assert.deepEqual(current.requests, []);
});

test('configuration uses the discovered actor/zone and exact existing same-origin CSRF endpoint', async (t) => {
  const current = await browser(t);
  const result = await current.call('configure_gateway', {
    gatewayName: 'Updated Gateway', targetIdHash, additionalAdminEmails: ['admin@example.com'],
    managementHostname: 'management.example.com', portalHostname: 'portal.example.com',
  });
  assert.equal(result.ok, true);
  assert.equal(result.result.administratorCount, 2);
  assert.deepEqual(current.requests.map(({ url, method }) => ({ url, method })), [{ url: '/api/selection', method: 'PUT' }]);
  const request = current.requests[0];
  assert.equal(request.credentials, 'same-origin');
  assert.equal(request.redirect, 'error');
  assert.equal(request.headers['x-csrf-token'], 'synthetic-csrf');
  assert.equal(request.headers['x-cloudflare-target-hash'], targetIdHash);
  assert.deepEqual(JSON.parse(request.body), {
    schemaVersion: 1,
    basics: { gatewayName: 'Updated Gateway', zoneName: 'example.com', adminEmail: 'owner@example.com', additionalAdminEmails: ['admin@example.com'], managementHostname: 'management.example.com', portalHostname: 'portal.example.com' },
    firstSource: null,
  });
});

test('disabled server-advertised capabilities cannot be bypassed with direct tool execution', async (t) => {
  const session = sessionFixture();
  session.capabilities = {};
  const current = await browser(t, { session });
  for (const [name, input] of [
    ['configure_gateway', { gatewayName: 'Example Gateway', targetIdHash, managementHostname: 'manage.example.com', portalHostname: 'mcp.example.com' }],
    ['create_review_plan', {}], ['begin_authorization', { planHash }],
    ['create_removal_plan', {}], ['begin_removal', { planHash }],
  ]) assert.equal((await current.call(name, input)).error.code, 'action_unavailable');
  assert.deepEqual(current.requests, []);
});

test('review returns exact retained plan, blockers, and a structured next step without writes', async (t) => {
  const session = sessionFixture();
  session.plan.blockers = [{ code: 'synthetic_warning', title: 'Review', detail: 'Read the plan.', severity: 'warning', privateField: syntheticPrivate }];
  const current = await browser(t, { session });
  const result = await current.call('create_review_plan');
  assert.equal(result.ok, true);
  assert.equal(result.result.planHash, planHash);
  assert.equal(result.result.writesPerformed, false);
  assert.deepEqual(result.result.continuation, { status: 'review_required', tool: 'begin_authorization', arguments: { planHash } });
  assert.deepEqual(result.result.blockers, [{ code: 'synthetic_warning', title: 'Review', detail: 'Read the plan.', severity: 'warning' }]);
  assert.deepEqual(current.requests, []);
});

test('authorization creates only the exact plan handoff and never opens or approves it', async (t) => {
  const current = await browser(t);
  assert.equal((await current.call('begin_authorization', { planHash: 'different' })).error.code, 'plan_hash_mismatch');
  assert.deepEqual(current.requests, []);
  const result = await current.call('begin_authorization', { planHash });
  assert.equal(result.result.status, 'user_authorization_required');
  assert.equal(result.result.authorizationUrl, handoff);
  assert.deepEqual(result.result.continuation, { status: 'user_authorization_required', tool: 'get_installer_status', requiresUserConsent: true });
  assert.deepEqual(current.requests.map(({ url }) => url), ['/api/deploy', '/api/session']);
  assert.deepEqual(JSON.parse(current.requests[0].body), { planId: 'plan-synthetic', planHash });
  assert.deepEqual(current.navigations, []);
});

test('discovery returns its bounded continuation, without source/provider credential intake', async (t) => {
  const current = await browser(t);
  const result = await current.call('begin_cloudflare_discovery');
  assert.equal(result.ok, true);
  assert.equal(result.result.authorizationUrl, handoff);
  assert.equal(result.result.continuation.requiresUserConsent, true);
  assert.deepEqual(current.requests.map(({ url }) => url), ['/api/discovery', '/api/discovery']);
  assert.equal(current.requests[0].body, '{}');
  assert.deepEqual(current.navigations, []);
});

test('the shared authorization validation rejects foreign handoffs without returning them', async (t) => {
  const current = await browser(t, { request: (url) => url === '/api/deploy' ? Response.json({
    schemaVersion: 1,
    authorizationUrl: 'https://dash.cloudflare.com/oauth2/auth',
    handoffUrl: `https://untrusted.example/oauth/handoff#${syntheticPrivate}`,
  }) : undefined });
  const result = await current.call('begin_authorization', { planHash });
  assert.equal(result.ok, false);
  assert.ok(!JSON.stringify(result).includes(syntheticPrivate));
  assert.ok(!JSON.stringify(result).includes('untrusted.example'));
  assert.deepEqual(current.navigations, []);
});

test('removal review reuses the existing handler for normal and returning recovery plans', async (t) => {
  const current = await browser(t);
  const first = await current.call('create_removal_plan');
  assert.equal(first.ok, true);
  assert.equal(first.result.writesPerformed, false);
  assert.deepEqual(current.requests.map(({ url }) => url), ['/api/uninstall/plan']);
  current.retained.session.removal = {
    ...removalFixture('returning-uninstall-plan-synthetic'),
    recovery: { status: 'recovery_required' },
  };
  await current.call('get_installer_status');
  current.requests.length = 0;
  assert.equal((await current.call('create_removal_plan')).ok, true);
  assert.deepEqual(current.requests.map(({ url }) => url), ['/api/returning-uninstall/recovery/plan']);
  assert.deepEqual(current.navigations, []);
});

for (const [name, planId, recovery, endpoint] of [
  ['session removal', 'uninstall-plan-synthetic', null, '/api/uninstall'],
  ['returning removal', 'returning-uninstall-plan-synthetic', null, '/api/returning-uninstall'],
  ['returning recovery', 'returning-uninstall-plan-synthetic', { status: 'recovery_required' }, '/api/returning-uninstall/recovery'],
]) {
  test(`${name} retains its exact supported authorization endpoint`, async (t) => {
    const session = sessionFixture();
    session.removal = { ...removalFixture(planId), recovery };
    const current = await browser(t, { session });
    assert.equal((await current.call('begin_removal', { planHash: 'different' })).error.code, 'removal_plan_hash_mismatch');
    assert.deepEqual(current.requests, []);
    const result = await current.call('begin_removal', { planHash });
    assert.equal(result.result.status, 'user_authorization_required');
    assert.deepEqual(current.requests.map(({ url }) => url), [endpoint, '/api/session']);
    assert.deepEqual(JSON.parse(current.requests[0].body), { planId, planHash });
    assert.deepEqual(current.navigations, []);
  });
}

test('status projects public fields, capabilities, and removal recovery without spreading hidden data', async (t) => {
  const session = sessionFixture();
  session.capabilities.secret = syntheticPrivate;
  session.recovery = { status: 'recovery_required', expiresAt: '2099-01-01', secret: syntheticPrivate };
  session.removal = {
    ...removalFixture(), status: 'failed', recovery: { status: 'recovery_required', expiresAt: '2099-01-01', secret: syntheticPrivate },
    failure: { code: 'session_conflict', title: 'Review required', detail: 'Use the retained result.', secret: syntheticPrivate },
  };
  const current = await browser(t, { session });
  const result = await current.call('get_installer_status');
  assert.equal(result.ok, true);
  assert.equal(result.result.recovery.status, 'recovery_required');
  assert.equal(result.result.removal.failure.code, 'session_conflict');
  assert.deepEqual(result.result.continuation, { status: 'review_required', tool: 'create_removal_plan' });
  assert.ok(!JSON.stringify(result).includes(syntheticPrivate));
  assert.ok(!JSON.stringify(result).includes('synthetic-csrf'));
  assert.ok(current.requests.every(({ method = 'GET' }) => method === 'GET'));
});

test('unconfirmed revocation reports manual action instead of suggesting another authorization', async (t) => {
  const current = await browser(t);
  current.retained.discovery.grantRevocation = 'unconfirmed';
  const result = await current.call('get_installer_status');
  assert.deepEqual(result.result.continuation, { status: 'manual_action_required', tool: null, reason: 'grant_revocation_unconfirmed' });
});

test('a succeeded installation remains actionable until its grant revocation is confirmed', async (t) => {
  const session = sessionFixture();
  session.deployment = {
    status: 'succeeded', operations: [], failure: null, canRetry: false,
    receipt: { managementUrl: 'https://manage.example.com/', portalUrl: 'https://mcp.example.com/mcp', grantRevocation: 'unconfirmed' },
  };
  const current = await browser(t, { session });
  const result = await current.call('get_installer_status');
  assert.equal(result.result.deployment.status, 'succeeded');
  assert.deepEqual(result.result.continuation, { status: 'manual_action_required', tool: null, reason: 'grant_revocation_unconfirmed' });
  current.retained.session.deployment.receipt.grantRevocation = 'confirmed';
  assert.deepEqual((await current.call('get_installer_status')).result.continuation, { status: 'complete', tool: null });
  assert.ok(current.requests.every(({ method = 'GET' }) => method === 'GET'));
});

test('a discovered account without zones points to rediscovery, not an unusable configuration', async (t) => {
  const current = await browser(t);
  current.retained.discovery.targets = [];
  const result = await current.call('get_installer_status');
  assert.deepEqual(result.result.continuation, { status: 'manual_action_required', tool: 'begin_cloudflare_discovery', reason: 'active_zone_required' });
});

for (const failure of ['throw', 'reject', 'api']) {
  test(`sanitizes ${failure} failures and releases the busy state`, async (t) => {
    const current = await browser(t, { request: (url) => {
      if (url !== '/api/deploy') return undefined;
      if (failure === 'throw') throw new Error(syntheticPrivate);
      if (failure === 'reject') return Promise.reject(new Error(syntheticPrivate));
      return Response.json({ code: syntheticPrivate, reason: syntheticPrivate }, { status: 500 });
    } });
    const result = await current.call('begin_authorization', { planHash });
    assert.equal(result.ok, false);
    assert.equal(result.error.code, 'internal_error');
    assert.equal(result.error.reason, null);
    assert.ok(!JSON.stringify(result).includes(syntheticPrivate));
    assert.ok(!current.document.getElementById('live-notice').textContent.includes(syntheticPrivate));
    assert.equal((await current.call('get_installer_status')).ok, true);
    assert.deepEqual(current.logs, []);
  });
}

for (const async of [false, true]) {
  test(`partial ${async ? 'async' : 'sync'} registration failure rolls back and can retry`, async (t) => {
    const current = await browser(t, { registrationFailure: { at: 3, async } });
    assert.equal(current.tools.size, 0);
    assert.ok(!current.document.getElementById('live-notice').textContent.includes(syntheticPrivate));
    await current.dispatch('focus');
    assert.deepEqual([...current.tools.keys()], expectedNames);
    assert.deepEqual(current.requests, []);
    assert.deepEqual(current.logs, []);
  });
}

test('concurrent registration is single-flight; pagehide cleanup blocks stale tool references', async (t) => {
  const paused = Promise.withResolvers();
  const current = await browser(t, { registrationPause: (count) => count === 1 ? paused.promise : undefined });
  await current.dispatch('focus');
  assert.equal(current.registered.length, 1);
  const stale = current.tools.get('begin_cloudflare_discovery');
  await current.dispatch('pagehide');
  assert.equal(current.tools.size, 0);
  assert.equal(JSON.parse(await stale.execute({})).error.code, 'page_inactive');
  assert.deepEqual(current.requests, []);
  // A BFCache restoration may arrive before the old async registration settles.
  await current.dispatch('pageshow');
  paused.resolve();
  await flush();
  assert.equal(JSON.parse(await stale.execute({})).error.code, 'page_inactive');
  assert.deepEqual(current.requests, []);
  assert.deepEqual([...current.tools.keys()], expectedNames);
});

test('unsupported browsers retain the UI and can register when support becomes available', async (t) => {
  const current = await browser(t, { unsupported: true });
  assert.equal(current.tools.size, 0);
  assert.equal(current.document.getElementById('discover-cloudflare').disabled, false);
  current.enable();
  await current.dispatch('focus');
  assert.deepEqual([...current.tools.keys()], expectedNames);
  assert.deepEqual(current.requests, []);
});

test('startup finishing after pagehide cannot leave tools on an inactive page', async (t) => {
  const session = Promise.withResolvers();
  const current = await browser(t, { request: (url) => url === '/api/session' ? session.promise : undefined });
  await current.dispatch('pagehide');
  session.resolve(Response.json(sessionFixture()));
  await flush();
  assert.equal(current.tools.size, 0);
  await current.dispatch('pageshow');
  assert.deepEqual([...current.tools.keys()], expectedNames);
});

test('abort before an action prevents requests; abort after submission does not claim rollback', async (t) => {
  const pending = Promise.withResolvers();
  const current = await browser(t, { request: (url) => url === '/api/deploy' ? pending.promise : undefined });
  const before = new AbortController();
  before.abort();
  assert.equal((await current.call('begin_authorization', { planHash }, { signal: before.signal })).error.code, 'action_cancelled');
  assert.deepEqual(current.requests, []);
  const after = new AbortController();
  const action = current.call('begin_authorization', { planHash }, { signal: after.signal });
  await flush();
  assert.equal(current.requests.length, 1);
  assert.equal((await current.call('begin_authorization', { planHash })).error.code, 'installer_busy');
  after.abort();
  pending.resolve(Response.json({ schemaVersion: 1, authorizationUrl: 'https://dash.cloudflare.com/oauth2/auth', handoffUrl: handoff }));
  const result = await action;
  assert.equal(result.ok, true);
  assert.equal(result.result.status, 'user_authorization_required');
  assert.equal(current.requests.filter(({ url }) => url === '/api/deploy').length, 1);
});
