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

function browser(t, readyState = 'loading') {
  const dom = new JSDOM(html);
  t.after(() => dom.window.close());
  const document = dom.window.document;
  Object.defineProperty(document, 'readyState', { get: () => readyState });
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
    notice: document.getElementById('live-notice'),
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
