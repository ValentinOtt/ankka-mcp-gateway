import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import worker, { AdminState } from '../fixtures/runtime-probe/worker.mjs';

const KEY = 'A'.repeat(43);
const KEY_HEADER = 'x-ankka-canary-key';
const OUTER = 'x-canary-outer-revision';
const INNER = 'x-canary-do-revision';
const OVERRIDE = 'synthetic-probe="22222222-2222-4222-8222-222222222222"';

function request(value, { key = KEY, path = '/control', headers = {} } = {}) {
  return new Request(`https://synthetic.example.com${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json', [KEY_HEADER]: key, ...headers },
    body: Object.prototype.toString.call(value) === '[object String]'
      ? value : JSON.stringify({ schemaVersion: 1, ...value }),
  });
}

function fixture() {
  const values = new Map();
  const calls = [];
  const headerSnapshots = [];
  let writes = 0;
  const env = { CANARY_KEY: KEY, CANARY_REVISION: 'old' };
  const storage = {
    async get(key) { return structuredClone(values.get(key)); },
    async put(key, value) { writes += 1; values.set(key, structuredClone(value)); },
  };
  const object = new AdminState({ storage }, env);
  const namespace = {
    idFromName(name) { assert.equal(name, 'v1:management'); return name; },
    get(id) {
      assert.equal(id, 'v1:management');
      return { async fetch(forwarded) {
        headerSnapshots.push(new Headers(forwarded.headers));
        calls.push({
          url: forwarded.url, method: forwarded.method,
          marker: forwarded.headers.get('x-ankka-runtime-probe-version'),
          override: forwarded.headers.get('Cloudflare-Workers-Version-Overrides'),
          key: forwarded.headers.get(KEY_HEADER),
        });
        return object.fetch(forwarded);
      } };
    },
  };
  return {
    env: { ...env, ADMIN_STATE: namespace }, object, storage, calls, headerSnapshots,
    writes: () => writes,
  };
}

async function staged(subject) {
  assert.equal((await worker.fetch(request({ command: 'begin' }), subject.env)).status, 200);
  for (const stage of ['current_verified', 'candidate_created', 'candidate_staged']) {
    assert.equal((await worker.fetch(request({ command: 'progress', stage }), subject.env)).status, 200);
  }
}

test('synthetic old and new outer revisions reach the same old DO through exact probe reconstruction', async () => {
  const subject = fixture();
  await staged(subject);
  assert.equal(subject.writes(), 4);
  for (const outerRevision of ['old', 'new']) {
    const response = await worker.fetch(request({ command: 'probe', targetRevision: outerRevision }, {
      headers: { 'Cloudflare-Workers-Version-Overrides': OVERRIDE },
    }), { ...subject.env, CANARY_REVISION: outerRevision });
    assert.equal(response.status, 204);
    assert.equal(response.headers.get('x-ankka-runtime-action'), 'ready');
    assert.equal(response.headers.get(OUTER), outerRevision);
    assert.equal(response.headers.get(INNER), 'old');
    assert.deepEqual(subject.calls.at(-1), {
      url: 'https://admin-state.invalid/runtime-updates/control', method: 'POST',
      marker: 'verified', override: OVERRIDE, key: KEY,
    });
  }
  assert.equal(subject.writes(), 4, 'both probes are read-only');
});

test('explicit strip-override diagnostic changes only that forwarded header and never synthetic state', async () => {
  const subject = fixture();
  await staged(subject);
  for (const outerRevision of ['old', 'new']) {
    for (const forwarding of [undefined, 'strip_override']) {
      const command = { command: 'probe', targetRevision: outerRevision };
      if (forwarding) command.forwarding = forwarding;
      const incoming = request(command, { headers: {
        'Cloudflare-Workers-Version-Overrides': OVERRIDE,
        'x-canary-preserve': 'synthetic-unchanged-value',
      } });
      const expectedHeaders = new Headers(incoming.headers);
      expectedHeaders.set('x-ankka-runtime-probe-version', 'verified');
      if (forwarding) expectedHeaders.delete('Cloudflare-Workers-Version-Overrides');
      const response = await worker.fetch(incoming, { ...subject.env, CANARY_REVISION: outerRevision });
      assert.equal(response.status, 204);
      assert.equal(response.headers.get(OUTER), outerRevision);
      assert.equal(response.headers.get(INNER), 'old');
      assert.deepEqual(Object.fromEntries(subject.headerSnapshots.at(-1)), Object.fromEntries(expectedHeaders));
      assert.equal(subject.calls.at(-1).key, KEY);
      assert.equal(subject.calls.at(-1).marker, 'verified');
      assert.equal(subject.calls.at(-1).override, forwarding ? null : OVERRIDE);
      assert.equal(incoming.headers.get('Cloudflare-Workers-Version-Overrides'), OVERRIDE, 'incoming headers are never mutated');
      assert.equal(subject.writes(), 4, 'diagnostic probes are read-only');
    }
  }
});

test('forwarding accepts only the explicit probe diagnostic enum and does not broaden other commands', async () => {
  const subject = fixture();
  const invalid = [
    ...['preserve_override', '', null, true, [], {}, 'strip_override '].map((forwarding) => ({
      command: 'probe', targetRevision: 'old', forwarding,
    })),
    { command: 'probe', targetRevision: 'old', forwarding: 'strip_override', extra: true },
    { command: 'begin', forwarding: 'strip_override' },
    { command: 'progress', stage: 'current_verified', forwarding: 'strip_override' },
  ];
  for (const command of invalid) {
    const response = await worker.fetch(request(command), subject.env);
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { schemaVersion: 1, error: 'invalid_command', stage: 'request_read' });
  }
  assert.equal(subject.calls.length, 0);
  assert.equal(subject.writes(), 0);
});

test('all public requests, including readiness, require the ephemeral gate before DO access', async () => {
  const subject = fixture();
  for (const key of ['', 'B'.repeat(43)]) {
    const response = await worker.fetch(request({ command: 'begin' }, { key }), subject.env);
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { schemaVersion: 1, error: 'unauthorized', stage: 'authorization' });
  }
  assert.equal((await worker.fetch(new Request('https://synthetic.example.com/ready'), subject.env)).status, 401);
  const ready = await worker.fetch(new Request('https://synthetic.example.com/ready', {
    headers: { [KEY_HEADER]: KEY },
  }), subject.env);
  assert.deepEqual(await ready.json(), { schemaVersion: 1, revision: 'old' });
  assert.equal(subject.calls.length, 0);
  assert.equal(subject.writes(), 0);
  assert.equal((await subject.object.fetch(request({ command: 'begin' }, {
    key: 'B'.repeat(43), path: '/runtime-updates/control',
  }))).status, 401);
});

test('rejects unknown fields, commands, destinations and bounded-body violations without state writes', async () => {
  const subject = fixture();
  const bodies = [
    '{', ' '.repeat(1025), { command: 'begin', destination: 'https://private.example.com/' },
    { command: 'delete' }, { command: 'progress', stage: 'unreviewed' },
    { command: 'probe', targetRevision: 'private-data' },
  ];
  for (const body of bodies) assert.equal((await worker.fetch(request(body), subject.env)).status, 400);
  assert.equal((await worker.fetch(request({ command: 'begin' }, {
    headers: { 'content-length': '1025' },
  }), subject.env)).status, 400);
  assert.equal((await worker.fetch(request({ command: 'begin' }, { path: '/elsewhere' }), subject.env)).status, 404);
  assert.equal(subject.calls.length, 0);
  assert.equal(subject.writes(), 0);
});

test('rejects sequence conflicts and wrong outer targets without changing synthetic state', async () => {
  const subject = fixture();
  assert.equal((await worker.fetch(request({ command: 'progress', stage: 'candidate_staged' }), subject.env)).status, 409);
  assert.equal((await worker.fetch(request({ command: 'probe', targetRevision: 'old' }), subject.env)).status, 409);
  await staged(subject);
  assert.equal((await worker.fetch(request({ command: 'begin' }), subject.env)).status, 409);
  const response = await worker.fetch(request({ command: 'probe', targetRevision: 'new' }), subject.env);
  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), { schemaVersion: 1, error: 'version_mismatch', stage: 'probe_target' });
  assert.equal(subject.writes(), 4);
});

test('accepts an exact 1KiB command but times out a stalled body before DO state access', async (context) => {
  const subject = fixture();
  const raw = JSON.stringify({ schemaVersion: 1, command: 'begin' }).padEnd(1024, ' ');
  assert.equal((await worker.fetch(request(raw), subject.env)).status, 200);
  const stalled = fixture();
  context.mock.timers.enable({ apis: ['setTimeout'] });
  let cancelled = false;
  const pending = new Request('https://synthetic.example.com/control', {
    method: 'POST', headers: { 'content-type': 'application/json', [KEY_HEADER]: KEY },
    body: new ReadableStream({ cancel() { cancelled = true; } }), duplex: 'half',
  });
  const result = worker.fetch(pending, stalled.env);
  context.mock.timers.tick(3_000);
  const response = await result;
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { schemaVersion: 1, error: 'invalid_command', stage: 'request_read' });
  await pending.body.cancel();
  assert.equal(cancelled, true);
  assert.equal(stalled.calls.length, 0);
  assert.equal(stalled.writes(), 0);
});

test('reports only fixed failing stages for binding, stub and response failures', async () => {
  const variants = [
    ['binding', undefined, 'unavailable'],
    ['stub_id', { idFromName() { throw new Error('private-secret'); }, get() {} }, 'exception'],
    ['stub_get', { idFromName() { return 'fixed'; }, get() { throw new Error('private-secret'); } }, 'exception'],
    ['stub_shape', { idFromName() { return 'fixed'; }, get() { return {}; } }, 'unavailable'],
    ['stub_fetch', { idFromName() { return 'fixed'; }, get() { return { fetch() { throw new Error('private-secret'); } }; } }, 'exception'],
    ['response_check', { idFromName() { return 'fixed'; }, get() { return { fetch() { return {}; } }; } }, 'invalid_response'],
  ];
  for (const [stage, namespace, error] of variants) {
    const response = await worker.fetch(request({ command: 'probe', targetRevision: 'new' }), {
      CANARY_KEY: KEY, CANARY_REVISION: 'new', ADMIN_STATE: namespace,
    });
    assert.equal(response.status, 503);
    const body = await response.text();
    assert.deepEqual(JSON.parse(body), { schemaVersion: 1, error, stage });
    assert.equal(response.headers.get(OUTER), 'new');
    assert.equal(response.headers.get(INNER), 'unknown');
    assert.ok(!body.includes('private-secret') && !body.includes(KEY));
  }
});

test('DO storage exceptions propagate to the fixed outer stub-fetch diagnostic', async () => {
  const subject = fixture();
  subject.storage.get = async () => { throw new Error('private-state'); };
  const response = await worker.fetch(request({ command: 'begin' }), subject.env);
  assert.deepEqual(await response.json(), { schemaVersion: 1, error: 'exception', stage: 'stub_fetch' });
  assert.equal(subject.writes(), 0);
});

test('fixture has no provider calls, logs, arbitrary namespace IDs or extra exported authority', async () => {
  const source = await readFile(new URL('../fixtures/runtime-probe/worker.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /console\.|api\.cloudflare\.com|CLOUDFLARE_API_TOKEN|\bidFromString\(|\bnewUniqueId\(|\bfetch\(['"`]/u);
  assert.deepEqual(Object.keys(await import('../fixtures/runtime-probe/worker.mjs')).sort(), ['AdminState', 'default']);
});
