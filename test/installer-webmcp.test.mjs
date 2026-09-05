import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createContext, Script } from 'node:vm';
import { JSDOM } from 'jsdom';

const html = await readFile(new URL('../payload/installer/index.html', import.meta.url), 'utf8');
const asset = html.match(/<script src="(\/assets\/installer-[a-f0-9]{8}\.js)"><\/script>/u)?.[1];
assert.ok(asset, 'test the installer asset selected by its actual HTML');
const source = new Script(await readFile(new URL(`../payload/installer${asset}`, import.meta.url), 'utf8'));
const flush = async () => {
  for (let index = 0; index < 4; index += 1) await new Promise((resolve) => setImmediate(resolve));
};
const NOW = 1_800_000_000_000;
const AUTHORIZATION_URL = 'https://dash.cloudflare.com/oauth2/auth?client_id=x&state=' + 'S'.repeat(43);
const HANDOFF_URL = `https://ankka-gateway-example-acg-${'a'.repeat(24)}.tenant.workers.dev/__ankka/install#${'A'.repeat(64)}`;
const READINESS_URL = new URL('__ankka/install/status', new URL(HANDOFF_URL).origin + '/').href;
const READY_STATUS = { schemaVersion: 1, role: 'customer-gateway-bootstrap', status: 'INCOMPLETE',
  installId: `acg-${'a'.repeat(24)}`, release: 'gateway-v1.2.3', ownershipPublicKey: 'k'.repeat(43), failure: null };
const syntheticPrivate = 'SYNTHETIC_PRIVATE_VALUE_MUST_NOT_ESCAPE';
const expectedNames = [
  'get_installer_status', 'prepare_deployment', 'begin_authorization', 'finish_secure_setup', 'begin_cleanup',
];

function sessionFixture(overrides = {}) {
  return {
    schemaVersion: 1,
    now: NOW,
    csrfToken: 'synthetic-csrf',
    session: {
      schemaVersion: 1,
      sessionId: `s1s_${'b'.repeat(24)}`,
      phase: 'draft',
      revision: 1,
      expiresAt: NOW + 3_600_000,
      selection: null,
      plan: null,
      attempt: null,
      provision: null,
      failure: null,
      cleanup: null,
      ...overrides,
    },
  };
}

const SELECTION = {
  schemaVersion: 1,
  basics: {
    gatewayName: 'Example Gateway', zoneName: 'example.com', adminEmail: 'owner@example.com',
    additionalAdminEmails: [], managementHostname: 'manage.example.com', portalHostname: 'mcp.example.com',
  },
  firstSource: null,
};
const PLAN = { planId: `plan-${'c'.repeat(24)}`, releaseId: 'gateway-v1.2.3', expiresAt: NOW + 1_800_000, managementHostname: 'manage.example.com', portalHostname: 'mcp.example.com' };
const PROVISION = {
  installId: `acg-${'a'.repeat(24)}`,
  workerName: `ankka-gateway-example-acg-${'a'.repeat(24)}`,
  bootstrapOrigin: `https://ankka-gateway-example-acg-${'a'.repeat(24)}.tenant.workers.dev/`,
  capabilityExpiresAt: NOW + 600_000,
};

async function browser(t, options = {}) {
  const dom = new JSDOM(html, { url: 'https://installer.example/' });
  t.after(() => dom.window.close());
  const document = dom.window.document;
  const tools = new Map();
  const registered = [];
  const requests = [];
  const navigations = [];
  const timers = new Map();
  let nextTimer = 0;
  let clock = NOW;
  class BrowserDate extends Date { static now() { return clock; } }
  let failure = options.registrationFailure ?? null;
  const retained = { response: options.session ?? sessionFixture() };
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
      return undefined;
    },
  };
  if (!options.unsupported) Object.defineProperty(document, 'modelContext', { configurable: true, value: modelContext });
  const window = Object.assign(new EventTarget(), {
    location: { pathname: options.pathname ?? '/', hash: '', origin: 'https://installer.example', assign: (url) => navigations.push(url), replace: (url) => navigations.push(url) },
    history: { replaceState() {}, pushState() {} },
    scrollTo() {}, matchMedia: () => ({ matches: true }),
    setTimeout(callback) { timers.set(++nextTimer, callback); return nextTimer; },
    clearTimeout: (id) => timers.delete(id),
  });
  const context = createContext({
    window, document, URL, AbortController, structuredClone, Number, Math, JSON, Object, Array, Date: BrowserDate, Error, Infinity, TextDecoder,
    fetch: async (url, init = {}) => {
      requests.push(structuredClone({ url, ...init }));
      const custom = await options.request?.(url, init, retained);
      if (custom !== undefined) return custom;
      if (url === '/api/session') return Response.json({ ...retained.response, now: clock });
      if (url === READINESS_URL) return Response.json(READY_STATUS);
      if (url === '/api/selection') {
        retained.response.session.selection = JSON.parse(init.body);
        return Response.json(retained.response);
      }
      if (url === '/api/plan') {
        retained.response.session.plan = PLAN;
        return Response.json(retained.response);
      }
      if (url === '/api/bootstrap') {
        retained.response.session.phase = 'authorizing';
        retained.response.session.attempt = { attemptId: `attempt_${'d'.repeat(24)}`, kind: 'bootstrap', expiresAt: NOW + 600_000 };
        return Response.json({ schemaVersion: 1, authorizationUrl: AUTHORIZATION_URL, expiresAt: NOW + 600_000, session: retained.response.session });
      }
      if (url === '/api/cleanup') {
        retained.response.session.attempt = { attemptId: `attempt_${'e'.repeat(24)}`, kind: 'cleanup', expiresAt: NOW + 600_000 };
        return Response.json({ schemaVersion: 1, authorizationUrl: AUTHORIZATION_URL, expiresAt: NOW + 600_000, session: retained.response.session });
      }
      if (url === '/api/bootstrap/handoff') {
        return Response.json({ schemaVersion: 1, status: 'ready', handoffUrl: HANDOFF_URL, bootstrapOrigin: PROVISION.bootstrapOrigin, expiresAt: NOW + 600_000 });
      }
      return Response.json({ code: 'bad_request' }, { status: 404 });
    },
  });
  source.runInContext(context);
  await flush();
  const runTimers = async () => {
    const pending = new Map(timers);
    timers.clear();
    for (const callback of pending.values()) await callback();
    await flush();
  };
  const invoke = async (name, input, callOptions) => {
    const tool = tools.get(name);
    assert.ok(tool, `tool ${name} is registered`);
    const result = await tool.execute(input, callOptions);
    await flush();
    return JSON.parse(result);
  };
  return { document, window, tools, registered, requests, navigations, timers, retained, invoke, runTimers, advance: (ms) => { clock += ms; } };
}

test('registers the five two-stage installer tools once with an abort signal and no duplicates', async (t) => {
  const b = await browser(t);
  assert.deepEqual(b.registered, expectedNames);
  assert.deepEqual([...b.tools.keys()], expectedNames);
  for (const tool of b.tools.values()) {
    assert.match(tool.description, /\S/u);
    assert.equal(tool.inputSchema.type, 'object');
    assert.equal(tool.inputSchema.additionalProperties, false);
    assert.ok([true, false].includes(tool.annotations.readOnlyHint));
  }
  b.window.dispatchEvent(new Event('focus'));
  await flush();
  assert.deepEqual(b.registered, expectedNames, 'a focus event does not re-register live tools');
  b.window.dispatchEvent(new Event('pagehide'));
  await flush();
  assert.equal(b.tools.size, 0, 'pagehide aborts every registration');
});

test('get_installer_status reflects the durable session without leaking anything but the public projection', async (t) => {
  const b = await browser(t, {
    session: sessionFixture({
      phase: 'provisioned', selection: SELECTION, plan: PLAN, provision: PROVISION, secret: syntheticPrivate,
    }),
  });
  const status = await b.invoke('get_installer_status', {});
  assert.equal(status.ok, true);
  assert.equal(status.status.phase, 'provisioned');
  assert.deepEqual(status.status.gateway, {
    gatewayName: 'Example Gateway', zoneName: 'example.com', managementHostname: 'manage.example.com',
    portalHostname: 'mcp.example.com', adminEmail: 'owner@example.com',
  });
  assert.deepEqual(status.status.plan, { planId: PLAN.planId, releaseId: 'gateway-v1.2.3', expiresAt: PLAN.expiresAt });
  assert.deepEqual(status.status.installed, {
    workerName: PROVISION.workerName, gatewayOrigin: PROVISION.bootstrapOrigin, handoffExpiresAt: PROVISION.capabilityExpiresAt,
  });
  assert.equal(JSON.stringify(status).includes(syntheticPrivate), false);
  assert.match(status.status.approvals.first, /temporary/iu);
  assert.match(status.status.approvals.second, /never held by Ankka/u);
});

test('prepare_deployment creates a bootstrap plan without collecting gateway details', async (t) => {
  const b = await browser(t);
  const rejected = await b.invoke('prepare_deployment', { gatewayName: 'Example Gateway' });
  assert.equal(rejected.error.code, 'invalid_arguments');
  const saved = await b.invoke('prepare_deployment', {});
  assert.equal(saved.ok, true);
  assert.equal(b.requests.some((request) => request.url === '/api/selection'), false);
  const plan = b.requests.find((request) => request.url === '/api/plan');
  assert.equal(plan.method, 'POST');
  assert.equal(plan.headers['x-csrf-token'], 'synthetic-csrf');
  assert.equal(plan.credentials, 'same-origin');
  assert.deepEqual(JSON.parse(plan.body), {});
  assert.equal(saved.status.plan.releaseId, 'gateway-v1.2.3');
});

test('begin_authorization prepares deployment and returns the Cloudflare link and never opens it itself', async (t) => {
  const unplanned = await browser(t);
  const prepared = await unplanned.invoke('begin_authorization', {});
  assert.equal(prepared.ok, true);
  assert.equal(unplanned.requests.some((request) => request.url === '/api/bootstrap'), true);

  const planned = await browser(t, { session: sessionFixture({ selection: SELECTION, plan: PLAN }) });
  const started = await planned.invoke('begin_authorization', {});
  assert.equal(started.ok, true);
  assert.equal(started.status, 'user_authorization_required');
  assert.equal(started.authorizationUrl, AUTHORIZATION_URL);
  assert.match(started.instruction, /finish_secure_setup/u);
  assert.deepEqual(planned.navigations, [], 'the agent tool hands the link back instead of navigating');
  assert.equal(planned.document.querySelector('[data-route="/deploy"]').hidden, false);
  assert.equal(planned.document.getElementById('authorization-link').getAttribute('href'), AUTHORIZATION_URL);

  const foreign = await browser(t, {
    session: sessionFixture({ selection: SELECTION, plan: PLAN }),
    request: (url) => url === '/api/bootstrap'
      ? Response.json({ schemaVersion: 1, authorizationUrl: 'https://evil.example/oauth2/auth', expiresAt: NOW + 1, session: sessionFixture().session })
      : undefined,
  });
  const blocked = await foreign.invoke('begin_authorization', {});
  assert.equal(blocked.ok, false);
  assert.equal(foreign.document.getElementById('authorization-link').hasAttribute('href'), false);
});

test('finish_secure_setup polls the token-free handoff and navigates this browser to the exact Gateway origin', async (t) => {
  const b = await browser(t, {
    pathname: '/result',
    session: sessionFixture({ phase: 'provisioned', selection: SELECTION, plan: PLAN, provision: PROVISION }),
  });
  assert.equal(b.document.querySelector('[data-route="/result"]').hidden, false);
  assert.equal(b.timers.size, 1, 'the result page schedules handoff polling on its own');
  const result = await b.invoke('finish_secure_setup', {});
  assert.equal(result.ok, true);
  assert.equal(result.status, 'checking');
  assert.equal(JSON.stringify(result).includes('__ankka/install'), false, 'the handoff is never returned to the caller');
  await b.runTimers();
  assert.deepEqual(b.navigations, [HANDOFF_URL]);
  const handoff = b.requests.find((request) => request.url === '/api/bootstrap/handoff');
  assert.equal(handoff.method, 'GET');
  assert.equal(Object.hasOwn(handoff.headers, 'x-csrf-token'), false);

  const wrongOrigin = await browser(t, {
    pathname: '/result',
    session: sessionFixture({ phase: 'provisioned', selection: SELECTION, plan: PLAN, provision: PROVISION }),
    request: (url) => url === '/api/bootstrap/handoff'
      ? Response.json({ schemaVersion: 1, status: 'ready', handoffUrl: `https://other.workers.dev/__ankka/install#${'A'.repeat(64)}`, bootstrapOrigin: PROVISION.bootstrapOrigin, expiresAt: NOW + 1 })
      : undefined,
  });
  await wrongOrigin.runTimers();
  assert.deepEqual(wrongOrigin.navigations, []);
  assert.equal(wrongOrigin.document.getElementById('live-notice').classList.contains('notice-error'), true);
  assert.equal(wrongOrigin.timers.size, 0, 'a rejected handoff stops polling instead of looping');

  const notReady = await browser(t, {
    pathname: '/result',
    session: sessionFixture({ phase: 'provisioned', selection: SELECTION, plan: PLAN, provision: PROVISION }),
    request: (url) => url === '/api/bootstrap/handoff'
      ? Response.json({ schemaVersion: 1, code: 'bootstrap_not_ready', status: 'not_ready', retryAfterMs: 3000 }, { status: 503 })
      : undefined,
  });
  await notReady.runTimers();
  assert.deepEqual(notReady.navigations, []);
  assert.equal(notReady.timers.size, 1, 'not-ready schedules another poll');

  const draft = await browser(t);
  const early = await draft.invoke('finish_secure_setup', {});
  assert.equal(early.error.code, 'action_unavailable');
});

test('begin_cleanup is offered only when the install must be removed and returns the removal approval link', async (t) => {
  const draft = await browser(t);
  const refused = await draft.invoke('begin_cleanup', {});
  assert.equal(refused.error.code, 'action_unavailable');
  assert.equal(draft.requests.some((request) => request.url === '/api/cleanup'), false);

  const b = await browser(t, {
    pathname: '/result',
    session: sessionFixture({
      phase: 'cleanup_required', selection: SELECTION, plan: PLAN, provision: PROVISION,
      cleanup: { reason: 'cookie_lost', requiredAt: NOW, completedAt: null },
    }),
  });
  assert.equal(b.document.getElementById('begin-cleanup').hidden, false);
  assert.match(b.document.getElementById('result-title').textContent, /Remove the incomplete install first/u);
  const started = await b.invoke('begin_cleanup', {});
  assert.equal(started.ok, true);
  assert.equal(started.status, 'user_authorization_required');
  assert.equal(started.authorizationUrl, AUTHORIZATION_URL);
  assert.equal(b.document.getElementById('cleanup-link').getAttribute('href'), AUTHORIZATION_URL);
  assert.deepEqual(b.navigations, []);
});

test('failed and handed-off sessions render a fresh-approval path and never expose the handoff', async (t) => {
  const failed = await browser(t, {
    pathname: '/result',
    session: sessionFixture({
      phase: 'failed', selection: SELECTION, plan: PLAN,
      failure: { code: 'authorization_rejected', attemptId: `attempt_${'d'.repeat(24)}`, at: NOW },
    }),
  });
  assert.match(failed.document.getElementById('result-intro').textContent, /declined/u);
  assert.equal(failed.document.getElementById('fresh-approval').hidden, false);
  failed.document.getElementById('fresh-approval').click();
  await flush();
  assert.deepEqual(failed.navigations, [AUTHORIZATION_URL], 'the human button opens the approval link');

  const handedOff = await browser(t, {
    pathname: '/result',
    session: sessionFixture({ phase: 'handed_off', selection: SELECTION, plan: PLAN, provision: PROVISION, handedOffAt: NOW }),
  });
  assert.match(handedOff.document.getElementById('result-title').textContent, /Setup continues on your Gateway/u);
  assert.equal(handedOff.document.getElementById('continue-gateway').getAttribute('href'), PROVISION.bootstrapOrigin);
  assert.equal(handedOff.timers.size, 0, 'no handoff polling after the capability was released');
});

test('failed setup shows its bounded diagnostic without claiming provider resources were removed', async (t) => {
  const b = await browser(t, {
    pathname: '/result',
    session: sessionFixture({
      phase: 'failed', selection: SELECTION, plan: PLAN,
      failure: { code: 'provision_failed', reason: 'script_upload_rejected', at: NOW },
    }),
  });
  const detail = b.document.getElementById('result-detail').textContent;
  assert.match(detail, /Reference: script_upload_rejected/u);
  assert.doesNotMatch(detail, /Nothing was left running/u);
  assert.match(detail, /incomplete gateway/u);
});

test('failed setup does not render malformed or unbounded diagnostic values', async (t) => {
  for (const reason of ['Bearer synthetic-secret', 'https://example.com/private', 'a'.repeat(161), { message: 'synthetic-private' }]) {
    const b = await browser(t, {
      pathname: '/result',
      session: sessionFixture({
        phase: 'failed', selection: SELECTION, plan: PLAN,
        failure: { code: 'provision_failed', reason, at: NOW },
      }),
    });
    assert.doesNotMatch(b.document.getElementById('result-detail').textContent, /Reference:|synthetic|https:|a{161}/u);
  }
});

test('starting another deployment replaces the session before opening a fresh approval', async (t) => {
  const b = await browser(t, {
    pathname: '/result',
    session: sessionFixture({ phase: 'handed_off', selection: SELECTION, plan: PLAN, provision: PROVISION }),
    request: (url, init, retained) => {
      if (url !== '/api/session/new') return undefined;
      assert.equal(init.method, 'POST');
      assert.equal(init.headers['x-csrf-token'], 'synthetic-csrf');
      retained.response = { ...sessionFixture(), csrfToken: 'fresh-csrf' };
      return Response.json(retained.response);
    },
  });
  b.document.getElementById('describe-again').click();
  await flush();
  assert.equal(b.document.querySelector('[data-route="/"]').hidden, false);
  assert.equal(b.retained.response.session.phase, 'draft');
  b.document.getElementById('gateway-form').dispatchEvent(new b.document.defaultView.Event('submit', { cancelable: true }));
  await flush();
  const start = b.requests.find((request) => request.url === '/api/bootstrap');
  assert.equal(start.headers['x-csrf-token'], 'fresh-csrf');
  assert.deepEqual(b.navigations, [AUTHORIZATION_URL]);
});

test('registration failures abort cleanly, unsupported browsers register nothing, and errors never leak', async (t) => {
  const failing = await browser(t, { registrationFailure: { at: 2, async: true } });
  assert.equal(failing.tools.size, 0);
  assert.equal(failing.document.getElementById('live-notice').textContent.includes(syntheticPrivate), false);
  const unsupported = await browser(t, { unsupported: true });
  assert.deepEqual(unsupported.registered, []);
  assert.equal(unsupported.document.querySelector('[data-route="/"]').hidden, false);
});


test('a browser TLS failure retains the handoff until the secure address answers', async (t) => {
  let reads = 0;
  const b = await browser(t, {
    pathname: '/result',
    session: sessionFixture({ phase: 'provisioned', plan: PLAN, provision: PROVISION }),
    request: (url) => {
      if (url === READINESS_URL && ++reads <= 2) throw new TypeError(syntheticPrivate);
    },
  });
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await b.runTimers();
    assert.deepEqual(b.navigations, []);
    assert.equal(b.requests.some(r => r.url === '/api/bootstrap/handoff'), false);
    assert.equal(b.document.getElementById('finish-setup').hidden, true);
    assert.match(b.document.getElementById('operation-detail').textContent, /secure connection/u);
    assert.equal(b.document.body.textContent.includes(syntheticPrivate), false);
    assert.equal(b.timers.size, 1);
  }
  await b.runTimers();
  assert.deepEqual(b.navigations, [HANDOFF_URL]);
  assert.equal(b.requests.filter(r => r.url === '/api/bootstrap/handoff').length, 1);
  for (const request of b.requests.filter(r => r.url === READINESS_URL)) {
    assert.equal(request.method, 'GET');
    assert.equal(request.mode, 'cors');
    assert.equal(request.credentials, 'omit');
    assert.equal(request.redirect, 'error');
    assert.equal(request.cache, 'no-store');
    assert.equal(request.referrerPolicy, 'no-referrer');
    assert.equal(request.headers, undefined);
    assert.equal(request.body, undefined);
    assert.equal(new URL(request.url).hash, '');
    assert.equal(new URL(request.url).search, '');
  }
});

test('browser readiness retries HTTP and malformed responses but rejects wrong identity and oversized bodies', async (t) => {
  for (const response of [
    () => new Response('still propagating', { status: 503 }),
    () => new Response('<html>not ready</html>'),
    () => new Response(null, { status: 302, headers: { location: 'https://other.example/' } }),
  ]) {
    const b = await browser(t, { pathname: '/result',
      session: sessionFixture({ phase: 'provisioned', plan: PLAN, provision: PROVISION }),
      request: url => url === READINESS_URL ? response() : undefined,
    });
    await b.runTimers();
    assert.equal(b.timers.size, 1);
    assert.equal(b.requests.some(r => r.url === '/api/bootstrap/handoff'), false);
    assert.deepEqual(b.navigations, []);
  }
  for (const response of [
    () => Response.json({ ...READY_STATUS, installId: `acg-${'f'.repeat(24)}` }),
    () => Response.json({ ...READY_STATUS, release: 'gateway-v9.9.9' }),
    () => Response.json({ ...READY_STATUS, status: 'READY' }),
    () => Response.json({ ...READY_STATUS, role: 'customer-gateway' }),
    () => new Response('x'.repeat(8193)),
  ]) {
    const b = await browser(t, { pathname: '/result',
      session: sessionFixture({ phase: 'provisioned', plan: PLAN, provision: PROVISION }),
      request: url => url === READINESS_URL ? response() : undefined,
    });
    await b.runTimers();
    assert.equal(b.timers.size, 0);
    assert.equal(b.requests.some(r => r.url === '/api/bootstrap/handoff'), false);
    assert.deepEqual(b.navigations, []);
    assert.equal(b.document.getElementById('live-notice').classList.contains('notice-error'), true);
  }
});

test('readiness expiry prevents endless retries and consuming an expired handoff', async (t) => {
  const b = await browser(t, { pathname: '/result',
    session: sessionFixture({ phase: 'provisioned', plan: PLAN, provision: PROVISION }),
    request: url => { if (url === READINESS_URL) throw new TypeError('network'); },
  });
  await b.runTimers();
  b.advance(600_001);
  await b.runTimers();
  assert.equal(b.timers.size, 0);
  assert.deepEqual(b.navigations, []);
  assert.equal(b.requests.some(r => r.url === '/api/bootstrap/handoff'), false);
  assert.match(b.document.getElementById('live-notice').textContent, /expired/u);
});

test('readiness validates the target before any external request', async (t) => {
  for (const bootstrapOrigin of [
    'https://other.example/', PROVISION.bootstrapOrigin + '?secret=synthetic',
    PROVISION.bootstrapOrigin.replace('https:', 'http:'),
    PROVISION.bootstrapOrigin.replace('.tenant.', '.other.tenant.'),
    PROVISION.bootstrapOrigin.replace('https://', 'https://user@'),
  ]) {
    const b = await browser(t, { pathname: '/result',
      session: sessionFixture({ phase: 'provisioned', plan: PLAN, provision: { ...PROVISION, bootstrapOrigin } }),
    });
    await b.runTimers();
    assert.equal(b.requests.some(r => r.url !== '/api/session'), false);
    assert.deepEqual(b.navigations, []);
    assert.equal(b.timers.size, 0);
  }
});

test('an in-flight browser check is single-flight and cancelled when the page leaves', async (t) => {
  let signal;
  const b = await browser(t, { pathname: '/result',
    session: sessionFixture({ phase: 'provisioned', plan: PLAN, provision: PROVISION }),
    request: (url, init) => {
      if (url !== READINESS_URL) return undefined;
      signal = init.signal;
      return new Promise((_, reject) => signal.addEventListener('abort', () => reject(new TypeError('aborted')), { once: true }));
    },
  });
  const pending = b.runTimers();
  await flush();
  assert.ok(signal);
  await b.invoke('finish_secure_setup', {});
  assert.equal(b.requests.filter(r => r.url === READINESS_URL).length, 1);
  b.window.dispatchEvent(new Event('pagehide'));
  await pending;
  assert.equal(signal.aborted, true);
  assert.equal(b.timers.size, 0);
  assert.equal(b.requests.some(r => r.url === '/api/bootstrap/handoff'), false);
  assert.deepEqual(b.navigations, []);
});

test('a browser connection timeout retries without releasing the handoff', async (t) => {
  let signal;
  const b = await browser(t, { pathname: '/result',
    session: sessionFixture({ phase: 'provisioned', plan: PLAN, provision: PROVISION }),
    request: (url, init) => {
      if (url !== READINESS_URL) return undefined;
      signal = init.signal;
      return new Promise((_, reject) => signal.addEventListener('abort', () => reject(new TypeError('timeout')), { once: true }));
    },
  });
  const pending = b.runTimers();
  await flush();
  await b.runTimers();
  await pending;
  assert.equal(signal.aborted, true);
  assert.equal(b.timers.size, 1);
  assert.equal(b.requests.some(r => r.url === '/api/bootstrap/handoff'), false);
  assert.deepEqual(b.navigations, []);
});
