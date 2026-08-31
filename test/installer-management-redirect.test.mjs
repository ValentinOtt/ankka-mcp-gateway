import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { Script } from 'node:vm';
import { JSDOM } from 'jsdom';

const html = await readFile(new URL('../payload/installer/index.html', import.meta.url), 'utf8');
const assetPath = html.match(/<script src="(\/assets\/installer-[a-f0-9]{8}\.js)"><\/script>/u)?.[1];
assert.ok(assetPath, 'exercise the exact installer asset referenced by the release HTML');
const script = new Script(await readFile(new URL(`../payload/installer${assetPath}`, import.meta.url), 'utf8'));
const managementUrl = 'https://manage.example.com/?runtimeAction=action_' + 'A'.repeat(32);
const contextPayload = { schemaVersion: 1, managementUrl };
const flush = () => new Promise((resolve) => setImmediate(resolve));

function browser(t, readyState = 'loading', {
  runtime = false, initialResult,
  pendingMarkup = '<template id="ankka-runtime-callback-pending"></template>',
} = {}) {
  const shell = runtime ? html.replace('<!-- ankka-runtime-callback-state -->',
    pendingMarkup) : html;
  const dom = new JSDOM(shell);
  t.after(() => dom.window.close());
  const document = dom.window.document;
  Object.defineProperty(document, 'readyState', { get: () => readyState });
  const appendResult = (payload, { raw = false, tag = 'template' } = {}) => {
    const marker = document.createElement(tag);
    marker.id = 'ankka-runtime-callback-result';
    (marker.content ?? marker).textContent = raw ? payload : JSON.stringify(payload);
    document.body.append(marker);
    return marker;
  };
  if (initialResult !== undefined) appendResult(initialResult);
  const requests = [];
  const navigations = [];
  const history = [];
  const timers = new Map();
  let nextTimer = 0;
  const context = Promise.withResolvers();
  // Control load independently of the context request. No real navigation,
  // network, OAuth callback, or timer is executed by this browser harness.
  const window = Object.assign(new EventTarget(), {
    location: {
      pathname: '/oauth/callback',
      hash: '',
      replace: (url) => navigations.push(url),
    },
    history: { replaceState: (_state, _title, url) => history.push(url) },
    setTimeout: (callback) => { timers.set(++nextTimer, callback); return nextTimer; },
    clearTimeout: (id) => timers.delete(id),
  });
  script.runInNewContext({
    window, document, URL,
    fetch: (url, options) => {
      requests.push(structuredClone({ url, ...options }));
      if (url === '/api/management/context') return context.promise;
      // Missing context must retain the ordinary session-error fallback.
      return Promise.resolve(Response.json({ code: 'session_invalid' }, { status: 404 }));
    },
  });
  return {
    requests, navigations, history, timers,
    document, appendResult,
    notice: document.getElementById('live-notice'),
    clickHome: () => {
      const event = new dom.window.MouseEvent('click', { bubbles: true, cancelable: true });
      document.querySelector('.brand').dispatchEvent(event);
      return event.defaultPrevented;
    },
    resolve: async (response = Response.json(contextPayload)) => { context.resolve(response); await flush(); },
    reject: async () => { context.reject(new Error('synthetic context network failure')); await flush(); },
    load: () => { readyState = 'complete'; window.dispatchEvent(new Event('load')); },
  };
}

function assertContextOnly(current) {
  assert.deepEqual(current.requests, [{
    url: '/api/management/context',
    headers: { accept: 'application/json' },
    credentials: 'same-origin',
    redirect: 'error',
  }]);
  assert.deepEqual(current.history, ['/manage']);
  assert.equal(current.timers.size, 0);
}

test('returns once when load fires while management context is pending', async (t) => {
  const current = browser(t);
  current.load();
  assert.deepEqual(current.navigations, []);
  await current.resolve();
  assert.deepEqual(current.navigations, [managementUrl]);
  current.load();
  assert.deepEqual(current.navigations, [managementUrl]);
  assertContextOnly(current);
});

test('waits for response completion when management context arrives before load', async (t) => {
  const current = browser(t, 'interactive');
  await current.resolve();
  assert.deepEqual(current.navigations, []);
  assert.match(current.notice.textContent, /Completing the approved gateway action/u);
  current.load();
  current.load();
  assert.deepEqual(current.navigations, [managementUrl]);
  assertContextOnly(current);
});

test('returns once if the document was already complete at startup', async (t) => {
  const current = browser(t, 'complete');
  await current.resolve();
  assert.deepEqual(current.navigations, [managementUrl]);
  current.load();
  assert.deepEqual(current.navigations, [managementUrl]);
  assertContextOnly(current);
});

const invalidContexts = [
  ['missing or expired context', () => Response.json({ code: 'session_invalid' }, { status: 404 })],
  ['invalid JSON', () => new Response('{')],
  ['missing URL', () => Response.json({ schemaVersion: 1 })],
  ['wrong schema', () => Response.json({ ...contextPayload, schemaVersion: 2 })],
  ...[
    'https://untrusted.example/',
    '/?runtimeAction=action_example',
    'http://untrusted.example/?runtimeAction=action_example',
    'javascript:alert(1)',
    'https://user@untrusted.example/?runtimeAction=action_example',
    'https://untrusted.example:8443/?runtimeAction=action_example',
    'https://untrusted.example/?runtimeAction=action_example#fragment',
    'https://untrusted.example/?runtimeAction=action_example&sourceAction=action_example',
  ].map((url) => [url, () => Response.json({ schemaVersion: 1, managementUrl: url })]),
];

for (const [name, response] of invalidContexts) {
  test(`does not redirect with ${name}`, async (t) => {
    const current = browser(t, 'complete');
    await current.resolve(response());
    current.load();
    assert.deepEqual(current.navigations, []);
    assert.deepEqual(current.history, ['/result']);
    assert.deepEqual(current.requests.map(({ url }) => url), ['/api/management/context', '/api/session']);
    assert.ok(current.requests.every(({ method = 'GET' }) => method === 'GET'));
    assert.match(current.notice.textContent, /Status refresh failed\. Reconnecting automatically/u);
    assert.equal(current.notice.classList.contains('notice-error'), true);
    assert.equal(current.timers.size, 1);
  });
}

test('a context network failure retains recovery without navigation or replay', async (t) => {
  const current = browser(t, 'complete');
  await current.reject();
  current.load();
  assert.deepEqual(current.navigations, []);
  assert.deepEqual(current.requests.map(({ url }) => url), ['/api/management/context']);
  assert.match(current.notice.textContent, /Status refresh failed\. Reconnecting automatically/u);
  assert.equal(current.timers.size, 1);
});

const runtimeSuccess = {
  schemaVersion: 1, kind: 'runtime_update', status: 'succeeded', managementUrl,
};
const runtimeFailure = {
  schemaVersion: 1, kind: 'runtime_update', status: 'failed', managementUrl,
  code: 'session_conflict', reason: 'runtime_active_probe_timeout',
};

function assertRuntimeOnly(current) {
  assert.deepEqual(current.requests, [], 'runtime callbacks never fetch an old install or result context');
  assert.deepEqual(current.history, ['/manage']);
  assert.equal(current.timers.size, 0, 'no automatic replay or polling of another operation');
}

test('runtime callback shows progress immediately without fetching context or a previous installation', (t) => {
  const current = browser(t, 'loading', { runtime: true });
  assertRuntimeOnly(current);
  assert.equal(current.document.querySelector('[data-route="/manage"]').hidden, false);
  assert.equal(current.document.querySelector('.step-indicators').hidden, true);
  assert.equal(current.document.getElementById('manage-action-title').textContent, 'Updating your gateway');
  assert.equal(current.document.getElementById('manage-action-stage').dataset.status, 'running');
  assert.match(current.document.getElementById('manage-action-stage-detail').textContent, /Keep this tab open/u);
  assert.equal(current.document.getElementById('manage-action-links').hidden, true);
  assert.ok([...current.document.querySelectorAll('button')].every((button) => button.disabled));
  assert.equal(current.clickHome(), true, 'installer navigation cannot accidentally interrupt cleanup');
  assert.deepEqual(current.navigations, []);
});

test('runtime callback returns once only after explicit success and the response has drained', (t) => {
  const current = browser(t, 'interactive', { runtime: true });
  current.appendResult(runtimeSuccess);
  assert.deepEqual(current.navigations, []);
  assert.equal(current.document.getElementById('manage-action-stage').dataset.status, 'running');
  current.load();
  current.load();
  assert.deepEqual(current.navigations, [managementUrl]);
  assert.equal(current.document.getElementById('manage-action-stage').dataset.status, 'succeeded');
  assert.equal(current.document.getElementById('manage-action-return').href, managementUrl);
  assertRuntimeOnly(current);
});

test('runtime callback handles a fully parsed result before the script starts', (t) => {
  const current = browser(t, 'complete', { runtime: true, initialResult: runtimeSuccess });
  assert.deepEqual(current.navigations, [managementUrl]);
  current.load();
  assert.deepEqual(current.navigations, [managementUrl]);
  assertRuntimeOnly(current);
});

test('runtime callback does not classify a partially parsed template before load', (t) => {
  const current = browser(t, 'interactive', { runtime: true });
  const marker = current.appendResult('{"schemaVersion":', { raw: true });
  assert.deepEqual(current.navigations, []);
  assert.equal(current.document.getElementById('manage-action-stage').dataset.status, 'running');
  marker.content.textContent = JSON.stringify(runtimeSuccess);
  current.load();
  assert.deepEqual(current.navigations, [managementUrl]);
  assertRuntimeOnly(current);
});

test('runtime callback failure stays visible and offers only a manual return to the exact action', (t) => {
  const current = browser(t, 'interactive', { runtime: true });
  current.appendResult(runtimeFailure);
  current.load();
  assert.deepEqual(current.navigations, []);
  assert.equal(current.document.getElementById('manage-action-title').textContent, 'Update needs attention');
  assert.equal(current.document.getElementById('manage-action-return').href, managementUrl);
  assert.equal(current.document.getElementById('manage-action-links').hidden, false);
  assert.match(current.notice.textContent, /session_conflict \/ runtime_active_probe_timeout/u);
  assertRuntimeOnly(current);
});

test('runtime callback accepts a sanitized failure without an optional diagnostic reason', (t) => {
  const current = browser(t, 'complete', { runtime: true, initialResult: { ...runtimeFailure, reason: null } });
  assert.deepEqual(current.navigations, []);
  assert.equal(current.notice.textContent, 'Diagnostic: session_conflict.');
  assertRuntimeOnly(current);
});

const invalidRuntimeResults = [
  ['missing result', () => {}],
  ['invalid JSON', (current) => current.appendResult('{', { raw: true })],
  ['empty template', (current) => current.appendResult('', { raw: true })],
  ['oversized result', (current) => current.appendResult(' '.repeat(4097), { raw: true })],
  ['null', (current) => current.appendResult(null)],
  ['extra fields', (current) => current.appendResult({ ...runtimeSuccess, extra: true })],
  ['wrong version', (current) => current.appendResult({ ...runtimeSuccess, schemaVersion: 2 })],
  ['wrong kind', (current) => current.appendResult({ ...runtimeSuccess, kind: 'source_apply' })],
  ['pending is not success', (current) => current.appendResult({ ...runtimeSuccess, status: 'pending' })],
  ['missing URL', (current) => {
    const { managementUrl: _url, ...rest } = runtimeSuccess;
    current.appendResult(rest);
  }],
  ['duplicate templates', (current) => { current.appendResult(runtimeSuccess); current.appendResult(runtimeSuccess); }],
  ['non-template node', (current) => current.appendResult(runtimeSuccess, { tag: 'div' })],
  ['failure missing code', (current) => {
    const { code: _code, ...rest } = runtimeFailure;
    current.appendResult(rest);
  }],
  ['unknown failure code', (current) => current.appendResult({ ...runtimeFailure, code: 'unreviewed_diagnostic' })],
  ['failure unsafe reason', (current) => current.appendResult({ ...runtimeFailure, reason: '<img src=x onerror=alert(1)>' })],
  ...[
    'https://manage.example.com/',
    '/?runtimeAction=action_' + 'A'.repeat(32),
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'https://manage.example.com/?runtimeAction=action_' + 'A'.repeat(31) + '%41',
    'https://manage.example.com/?%72untimeAction=action_' + 'A'.repeat(32),
    'https://manage.example.com/?runtimeAction=action_' + 'A'.repeat(32) + '%22%3E%3Cimg%20src=x%3E',
    'https://manage.example.com/\n?runtimeAction=action_' + 'A'.repeat(32),
    'http://manage.example.com/?runtimeAction=action_' + 'A'.repeat(32),
    'https://user@manage.example.com/?runtimeAction=action_' + 'A'.repeat(32),
    'https://manage.example.com:8443/?runtimeAction=action_' + 'A'.repeat(32),
    managementUrl + '#fragment',
    managementUrl + '&runtimeAction=action_' + 'A'.repeat(32),
    managementUrl + '&sourceAction=action_' + 'A'.repeat(32),
    managementUrl.replace('/?', '/settings?'),
    managementUrl.replace('runtimeAction', 'sourceAction'),
    managementUrl.slice(0, -1),
  ].map((value) => [`invalid destination ${value}`, (current) => current.appendResult({ ...runtimeSuccess, managementUrl: value })]),
];

for (const [name, append] of invalidRuntimeResults) {
  test(`runtime callback treats ${name} as unknown without redirect or replay`, (t) => {
    const current = browser(t, 'interactive', { runtime: true });
    append(current);
    current.load();
    assert.deepEqual(current.navigations, []);
    assert.equal(current.document.getElementById('manage-action-title').textContent, 'Update status unavailable');
    assert.match(current.notice.textContent, /without a verified result/u);
    assert.equal(current.document.getElementById('manage-action-links').hidden, true);
    assert.equal(current.document.getElementById('manage-action-return').hasAttribute('href'), false);
    assertRuntimeOnly(current);
    // An unrelated late DOM mutation cannot reverse the terminal unknown state.
    current.document.querySelectorAll('[id="ankka-runtime-callback-result"]').forEach((marker) => marker.remove());
    current.appendResult(runtimeSuccess);
    current.load();
    assert.deepEqual(current.navigations, []);
  });
}

for (const [name, pendingMarkup] of [
  ['duplicate pending markers', '<template id="ankka-runtime-callback-pending"></template>'.repeat(2)],
  ['non-template pending marker', '<div id="ankka-runtime-callback-pending"></div>'],
]) {
  test(`runtime callback rejects ${name} without falling back to another operation`, (t) => {
    const current = browser(t, 'complete', { runtime: true, pendingMarkup, initialResult: runtimeSuccess });
    assert.equal(current.document.getElementById('manage-action-title').textContent, 'Update status unavailable');
    assert.deepEqual(current.navigations, []);
    assertRuntimeOnly(current);
  });
}

test('a result marker without runtime pending state cannot override a legacy callback', async (t) => {
  const current = browser(t, 'complete', { initialResult: runtimeSuccess });
  assert.deepEqual(current.navigations, []);
  assert.equal(current.requests.length, 1);
  await current.resolve(Response.json({ schemaVersion: 1, managementUrl: managementUrl.replace('runtimeAction', 'sourceAction') }));
  assert.deepEqual(current.navigations, [managementUrl.replace('runtimeAction', 'sourceAction')]);
  assertContextOnly(current);
});
