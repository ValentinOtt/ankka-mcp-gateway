import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import worker, { AdminState } from '../fixtures/runtime-probe/worker.mjs';
import { main } from '../tools/runtime-probe-canary.mjs';
import { boundedText, cloudflareTransport, runRuntimeProbeCanary } from '../tools/runtime-probe/run.mjs';

const ACCOUNT = 'a'.repeat(32);
const WORKER = 'b'.repeat(32);
const NAMESPACE = 'c'.repeat(32);
const OLD = '11111111-1111-4111-8111-111111111111';
const NEW = '22222222-2222-4222-8222-222222222222';
const PRIVATE = 'synthetic-private-provider-detail';
const SOURCE = await readFile(new URL('../fixtures/runtime-probe/worker.mjs', import.meta.url), 'utf8');
const ok = (result) => ({ status: 200, success: true, result });
const absent = () => ({ status: 404, success: false });

// A tiny account adapter, not a second implementation of the fixture. Every
// Worker name, marker and gate key is observed from the real runner's requests.
function fixture({ before, after, probeResponse, eventThrows = false } = {}) {
  const calls = [];
  const probes = [];
  const events = [];
  const state = {
    name: null, marker: null, key: null, present: false, namespace: false,
    bindings: [], uploads: [], versions: [{ version_id: OLD, percentage: 100 }],
    enabled: false, values: new Map(), stateWrites: 0,
  };
  const base = `/accounts/${ACCOUNT}/workers`;
  let object;
  const namespace = {
    idFromName(name) { assert.equal(name, 'v1:management'); return name; },
    get(id) { assert.equal(id, 'v1:management'); return { fetch: (request) => object.fetch(request) }; },
  };
  async function handle(request) {
    const script = `${base}/scripts/${state.name}`;
    if (request.method === 'GET' && [
      `${base}/workers/${state.name}`, `${base}/workers/${WORKER}`,
    ].includes(request.path)) {
      return state.present ? ok({ id: WORKER, name: state.name, tags: [state.marker], references: {
        workers: [], domains: [], dispatch_namespace_outbounds: [], queues: [],
        durable_objects: state.namespace ? [{
          worker_id: WORKER, worker_name: state.name, namespace_id: NAMESPACE, namespace_name: `${state.name}_AdminState`,
        }] : [],
      } }) : absent();
    }
    if (request.method === 'GET' && request.path === `${base}/subdomain`) return ok({ subdomain: 'synthetic-canary' });
    if ((request.method === 'PUT' && request.path === script)
      || (request.method === 'POST' && request.path === `${script}/versions`)) {
      const form = await new Response(request.body, { headers: { 'content-type': request.contentType } }).formData();
      const metadata = JSON.parse(form.get('metadata'));
      const source = await form.get('index.js').text();
      state.uploads.push({ metadata, source, method: request.method });
      if (metadata.migrations?.deleted_classes) {
        assert.deepEqual(metadata.migrations, {
          old_tag: 'runtime-probe-v1', new_tag: 'runtime-probe-deleted-v2', deleted_classes: ['AdminState'],
        });
        assert.deepEqual(metadata.bindings, []);
        state.namespace = false;
        // Cloudflare retains existing secret bindings on an immediate upload,
        // even when its metadata requests bindings: []. Worker deletion removes it.
        state.bindings = [{ type: 'secret_text', name: 'CANARY_KEY' }];
      } else if (request.method === 'PUT') {
        assert.deepEqual(metadata.migrations, { new_tag: 'runtime-probe-v1', new_sqlite_classes: ['AdminState'] });
        state.present = true;
        state.namespace = true;
        state.marker = metadata.tags[0];
        state.key = metadata.bindings.find((binding) => binding.name === 'CANARY_KEY').text;
        state.bindings = metadata.bindings.map((binding) => binding.name === 'ADMIN_STATE'
          ? { ...binding, namespace_id: NAMESPACE, script_name: state.name }
          : binding.name === 'CANARY_KEY' ? { type: 'secret_text', name: 'CANARY_KEY' } : binding);
        object = new AdminState({ storage: {
          async get(key) { return structuredClone(state.values.get(key)); },
          async put(key, value) { state.stateWrites += 1; state.values.set(key, structuredClone(value)); },
        } }, { CANARY_KEY: state.key, CANARY_REVISION: 'old' });
      } else {
        assert.equal(metadata.migrations, undefined);
        assert.equal(metadata.tags, undefined);
        assert.equal(metadata.bindings.find((binding) => binding.name === 'CANARY_KEY').text, state.key);
      }
      return ok({ id: request.method === 'POST' ? NEW : OLD });
    }
    if (request.path === `${script}/settings` && request.method === 'GET') return ok({ bindings: structuredClone(state.bindings) });
    if (request.path === `${base}/durable_objects/namespaces` && request.method === 'GET') {
      assert.equal(request.query.per_page, 100);
      return ok(state.namespace ? [{ id: NAMESPACE, script: state.name, class: 'AdminState', use_sqlite: true }] : []);
    }
    if (request.path === `${script}/deployments`) {
      if (request.method === 'GET') return ok({ deployments: [{ versions: structuredClone(state.versions) }] });
      assert.equal(request.method, 'POST');
      assert.deepEqual(request.body, { strategy: 'percentage', versions: [
        { version_id: OLD, percentage: 100 }, { version_id: NEW, percentage: 0 },
      ] });
      state.versions = structuredClone(request.body.versions);
      return ok({});
    }
    if (request.path === `${script}/subdomain` && request.method === 'POST') {
      assert.equal(request.body.previews_enabled, false);
      state.enabled = request.body.enabled;
      return ok({});
    }
    if (request.path === `${base}/workers/${WORKER}` && request.method === 'DELETE') {
      assert.equal(state.namespace, false, 'the class must be retired before Worker deletion');
      assert.equal(state.enabled, false, 'the public address must be disabled before Worker deletion');
      assert.equal(request.query, undefined, 'no force-delete option');
      state.present = false;
      return ok({});
    }
    assert.fail('unexpected synthetic API request');
  }
  async function api(request) {
    if (state.name === null) {
      assert.equal(request.method, 'GET');
      const match = request.path.match(new RegExp(`^${base}/workers/(ankka-probe-[0-9a-f]{32})$`, 'u'));
      assert.ok(match, 'first call must resolve a newly generated name in the chosen account');
      state.name = match[1];
    }
    assert.ok(request.path.startsWith(`${base}/`));
    calls.push(request);
    const intercepted = await before?.({ request, state, calls });
    if (intercepted !== undefined) return intercepted;
    const response = await handle(request);
    return await after?.({ request, response, state, calls }) ?? response;
  }
  async function probe(url, init) {
    assert.equal(new URL(url).origin, `https://${state.name}.synthetic-canary.workers.dev`);
    assert.equal(init.redirect, 'manual');
    assert.ok(init.signal instanceof AbortSignal);
    const headers = new Headers(init.headers);
    assert.equal(headers.get('authorization'), null);
    assert.equal(headers.get('x-ankka-canary-key'), state.key);
    const override = headers.get('Cloudflare-Workers-Version-Overrides');
    if (override) assert.equal(override, `${state.name}="${NEW}"`);
    const command = init.body ? JSON.parse(init.body) : null;
    probes.push({ url, init, command });
    const intercepted = await probeResponse?.({ url, init, command, state, probes });
    if (intercepted !== undefined) return intercepted;
    return worker.fetch(new Request(url, init), {
      CANARY_KEY: state.key, CANARY_REVISION: override ? 'new' : 'old', ADMIN_STATE: namespace,
    });
  }
  const run = () => runRuntimeProbeCanary({
    accountId: ACCOUNT, fixtureSource: SOURCE, api, probe,
    wait: async () => {},
    onEvent(event) { events.push(event); if (eventThrows) throw new Error(PRIVATE); },
  });
  return { run, state, calls, probes, events };
}

const mutations = (subject) => subject.calls.filter((call) => call.method !== 'GET');
const retirement = (subject) => subject.state.uploads.filter((upload) => upload.metadata.migrations?.deleted_classes);
function assertPrivate(subject, result) {
  const published = JSON.stringify({ result, events: subject.events });
  assert.ok(!published.includes(PRIVATE));
  if (subject.state.key) assert.ok(!published.includes(subject.state.key));
}

test('CLI defaults to an offline plan and refuses caller-selected names or cleanup files', async (context) => {
  const outputs = [];
  context.mock.method(globalThis, 'fetch', () => { assert.fail('plan must be offline'); });
  const unreadable = new Proxy({}, { get() { assert.fail('plan must not read credentials'); } });
  for (const args of [[], ['--plan']]) {
    assert.equal(await main(args, unreadable, (value) => outputs.push(value)), 0);
    assert.equal(JSON.parse(outputs.at(-1)).mode, 'plan');
  }
  for (const args of [['--execute', '--name', 'existing-worker'], ['--cleanup', 'state.json'], ['--resume'], ['--unknown']]) {
    assert.equal(await main(args, unreadable, (value) => outputs.push(value)), 2);
  }
  for (const env of [{}, { CLOUDFLARE_API_TOKEN: 'synthetic-token' }, { CLOUDFLARE_ACCOUNT_ID: ACCOUNT }]) {
    assert.equal(await main(['--execute'], env, (value) => outputs.push(value)), 1);
  }
  assert.ok(!outputs.join('').includes('synthetic-token'));
});

test('invalid account or oversized fixture fails before API or probe calls', async () => {
  for (const input of [{ accountId: 'invalid', fixtureSource: SOURCE }, { accountId: ACCOUNT, fixtureSource: 'x'.repeat(65537) }]) {
    await assert.rejects(runRuntimeProbeCanary({ ...input,
      api() { assert.fail('invalid input must not reach provider'); },
      probe() { assert.fail('invalid input must not reach fixture'); },
    }));
  }
});

test('collision, unauthorized inventory and unknown preflight outcomes cause zero writes', async () => {
  for (const response of [ok({}), { status: 401, success: false }, { status: 500, success: false }, { status: 404, success: true }]) {
    const subject = fixture({ before: () => response });
    const result = await subject.run();
    assert.equal(result.failure, 'preflight');
    assert.equal(result.reason, 'name_not_absent');
    assert.equal(result.cleanup, 'not_needed');
    assert.equal(mutations(subject).length, 0);
    assert.equal(subject.probes.length, 0);
  }
});

test('real synthetic fixture stays old in the DO while a new outer is staged at zero percent, then all run-owned resources are removed', async () => {
  const subject = fixture();
  const result = await subject.run();
  assert.equal(result.passed, true);
  assert.equal(result.cleanup, 'verified_removed');
  assert.equal(result.failure, null);
  assert.deepEqual(result.observations.map(({ label, status, outer, durableObject, ready, passed }) => ({ label, status, outer, durableObject, ready, passed })), [
    { label: 'candidate_immediate', status: 204, outer: 'new', durableObject: 'old', ready: true, passed: true },
    { label: 'candidate_strip_override', status: 204, outer: 'new', durableObject: 'old', ready: true, passed: true },
    { label: 'old_baseline', status: 204, outer: 'old', durableObject: 'old', ready: true, passed: true },
    { label: 'candidate_after_ready', status: 204, outer: 'new', durableObject: 'old', ready: true, passed: true },
  ]);
  assert.equal(subject.state.stateWrites, 4, 'four probes add no synthetic state writes');
  assert.equal(subject.state.present, false);
  assert.equal(subject.state.namespace, false);
  assert.equal(subject.state.enabled, false);
  assert.equal(retirement(subject).length, 1);
  assert.equal(subject.state.uploads[0].source, SOURCE);
  assert.deepEqual(subject.state.uploads[0].metadata.observability, { enabled: false });
  assert.equal(subject.state.uploads[0].metadata.logpush, false);
  assert.match(subject.state.marker, /^runtime-probe:[0-9a-f]{32}$/u);
  assert.notEqual(subject.state.marker.slice(14), subject.state.name.slice(12));
  assert.match(subject.state.key, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(mutations(subject).filter((call) => call.path.endsWith('/deployments')).length, 1, 'never activate new at 100%');
  assert.equal(mutations(subject).filter((call) => call.method === 'DELETE').length, 1);
  assertPrivate(subject, result);
});

test('each invocation generates its own fresh Worker name and credentials', async () => {
  const left = fixture();
  const right = fixture();
  assert.equal((await left.run()).passed, true);
  assert.equal((await right.run()).passed, true);
  assert.notEqual(left.state.name, right.state.name);
  assert.notEqual(left.state.marker, right.state.marker);
  assert.notEqual(left.state.key, right.state.key);
});

test('empty reference lists and cosmetic namespace labels do not replace exact binding and resource-ID checks', async () => {
  for (const variant of ['empty', 'display_label']) {
    const subject = fixture({ after({ request, response }) {
      if (request.method !== 'GET' || !response.result?.references) return;
      const references = response.result.references.durable_objects;
      if (variant === 'empty') response.result.references.durable_objects = [];
      else if (references.length) references[0].namespace_name = 'cosmetic-namespace-label';
    } });
    assert.equal((await subject.run()).passed, true);
    assert.equal(retirement(subject).length, 1);
  }
});

test('incorrect or additional DO self-references stop before enabling the address or sending fixture requests', async () => {
  for (const change of ['worker_id', 'worker_name', 'namespace_id', 'duplicate', 'foreign']) {
    const subject = fixture({ after({ request, response }) {
      if (request.method !== 'GET' || !response.result?.references) return;
      const references = response.result.references.durable_objects;
      if (change === 'worker_id') references[0].worker_id = 'd'.repeat(32);
      if (change === 'worker_name') references[0].worker_name = 'other-worker';
      if (change === 'namespace_id') references[0].namespace_id = 'd'.repeat(32);
      if (change === 'duplicate') references.push({ ...references[0] });
      if (change === 'foreign') references.push({
        worker_id: 'd'.repeat(32), worker_name: 'other-worker',
        namespace_id: 'e'.repeat(32), namespace_name: 'other-worker_AdminState',
      });
    } });
    const result = await subject.run();
    assert.equal(result.failure, 'create', change);
    assert.equal(result.cleanup, 'resources_may_remain', change);
    assert.equal(subject.probes.length, 0, change);
    assert.equal(subject.state.stateWrites, 0, change);
    assert.equal(subject.calls.filter((call) => call.method === 'POST' && call.path.endsWith('/subdomain')).length, 0, change);
    assert.equal(retirement(subject).length, 0, change);
    assert.equal(subject.calls.filter((call) => call.method === 'DELETE').length, 0, change);
  }
});

test('even an exact self-reference must be absent after class retirement before Worker deletion', async () => {
  const subject = fixture({ after({ request, response, state }) {
    if (request.method === 'GET' && response.result?.references && retirement({ state }).length) {
      response.result.references.durable_objects = [{
        worker_id: WORKER, worker_name: state.name, namespace_id: NAMESPACE, namespace_name: `${state.name}_AdminState`,
      }];
    }
  } });
  const result = await subject.run();
  assert.equal(result.observations.length, 4);
  assert.equal(result.passed, false);
  assert.equal(result.cleanup, 'resources_may_remain');
  assert.equal(retirement(subject).length, 1);
  assert.equal(subject.calls.filter((call) => call.method === 'DELETE').length, 0);
});

test('class retirement may leave no bindings or only the original canary secret', async () => {
  const subject = fixture({ after({ request, response, state }) {
    if (request.path.endsWith('/settings') && retirement({ state }).length) response.result.bindings = [];
  } });
  const result = await subject.run();
  assert.equal(result.passed, true);
  assert.equal(result.cleanup, 'verified_removed');
  assert.equal(subject.calls.filter((call) => call.method === 'DELETE').length, 1);
});

test('unknown secrets, plaintext, mistyped or additional bindings after retirement prevent Worker deletion', async () => {
  for (const bindings of [
    [{ type: 'secret_text', name: 'UNKNOWN_SECRET' }],
    [{ type: 'plain_text', name: 'UNRELATED_VALUE', text: 'synthetic' }],
    [{ type: 'plain_text', name: 'CANARY_KEY', text: PRIVATE }],
    [{ type: 'secret_text', name: 'CANARY_KEY' }, { type: 'secret_text', name: 'ADDITIONAL_KEY' }],
  ]) {
    const subject = fixture({ after({ request, response, state }) {
      if (request.path.endsWith('/settings') && retirement({ state }).length) response.result.bindings = bindings;
    } });
    const result = await subject.run();
    assert.equal(result.observations.length, 4);
    assert.equal(retirement(subject).length, 1);
    assert.equal(result.passed, false);
    assert.equal(result.cleanup, 'resources_may_remain');
    assert.equal(result.cleanupReason, 'binding_changed');
    assert.equal(subject.calls.filter((call) => call.method === 'DELETE').length, 0);
    assert.equal(subject.state.present, true);
    assertPrivate(subject, result);
  }
});

test('cleanup refuses changed Worker identity, marker, references, binding or namespace ownership', async () => {
  for (const change of ['id', 'name', 'marker', 'reference', 'missing_reference', 'class', 'namespace_id', 'namespace_script', 'namespace_class', 'sqlite']) {
    let reachedProbe = false;
    const subject = fixture({
      probeResponse({ command }) { if (command?.command === 'probe') reachedProbe = true; },
      after({ request, response }) {
        if (!reachedProbe || request.method !== 'GET') return;
        if (request.path.includes('/workers/ankka-probe-')) {
          if (change === 'id') response.result.id = 'd'.repeat(32);
          if (change === 'name') response.result.name = 'other-worker';
          if (change === 'marker') response.result.tags = ['unrelated'];
          if (change === 'reference') response.result.references.workers = ['other-worker'];
          if (change === 'missing_reference') delete response.result.references.queues;
        }
        if (request.path.endsWith('/settings')) {
          if (change === 'class') response.result.bindings[0].class_name = 'ForeignState';
          if (change === 'namespace_id') response.result.bindings[0].namespace_id = 'd'.repeat(32);
        }
        if (request.path.endsWith('/namespaces')) {
          if (change === 'namespace_script') response.result[0].script = 'other-worker';
          if (change === 'namespace_class') response.result[0].class = 'ForeignState';
          if (change === 'sqlite') response.result[0].use_sqlite = false;
        }
      },
    });
    const result = await subject.run();
    assert.equal(reachedProbe, true, 'ownership drift is injected only after successful setup');
    assert.equal(result.observations.length, 4);
    assert.equal(result.passed, false, change);
    assert.equal(result.cleanup, 'resources_may_remain', change);
    assert.equal(retirement(subject).length, 0, change);
    assert.equal(mutations(subject).filter((call) => call.method === 'DELETE').length, 0, change);
    assertPrivate(subject, result);
  }
});

test('ownership is checked again after route disable and class retirement, before the next destructive step', async () => {
  for (const point of ['route_disabled', 'class_retired']) {
    let drift = false;
    const subject = fixture({ after({ request, response, state }) {
      if (point === 'route_disabled' && request.method === 'POST' && request.path.endsWith('/subdomain') && !request.body.enabled) drift = true;
      if (point === 'class_retired' && state.uploads.some((upload) => upload.metadata.migrations?.deleted_classes)) drift = true;
      if (drift && request.method === 'GET' && request.path.includes('/workers/ankka-probe-')) response.result.tags = ['foreign'];
    } });
    const result = await subject.run();
    assert.equal(result.cleanup, 'resources_may_remain');
    assert.equal(result.cleanupReason, 'ownership_changed');
    assert.equal(retirement(subject).length, point === 'route_disabled' ? 0 : 1);
    assert.equal(mutations(subject).filter((call) => call.method === 'DELETE').length, 0);
  }
});

test('unknown create, version or staging write outcomes are never retried; verified ownership still permits cleanup', async () => {
  for (const phase of ['create', 'version', 'stage']) {
    let interrupted = false;
    const subject = fixture({ after({ request }) {
      const matches = (phase === 'create' && request.method === 'PUT')
        || (phase === 'version' && request.path.endsWith('/versions') && request.method === 'POST')
        || (phase === 'stage' && request.path.endsWith('/deployments') && request.method === 'POST');
      if (matches && !interrupted) { interrupted = true; throw new Error(PRIVATE); }
    } });
    const result = await subject.run();
    assert.equal(result.failure, { create: 'create', version: 'upload_candidate', stage: 'stage_candidate' }[phase]);
    assert.equal(result.reason, 'transport_failed');
    assert.equal(result.cleanup, 'verified_removed');
    assert.equal(subject.state.uploads.filter((upload) => upload.metadata.migrations?.new_sqlite_classes).length, 1);
    assert.equal(subject.calls.filter((call) => call.method === 'POST' && call.path.endsWith('/versions')).length, phase === 'create' ? 0 : 1);
    assert.equal(subject.calls.filter((call) => call.method === 'POST' && call.path.endsWith('/deployments')).length, phase === 'stage' ? 1 : 0);
    assertPrivate(subject, result);
  }
});

test('failed cleanup never reports success, retries destructive calls or erases retained namespace evidence', async () => {
  for (const phase of ['disable', 'retire', 'namespace_remains', 'delete', 'worker_remains']) {
    const subject = fixture({
      before({ request, state }) {
        if (phase === 'disable' && request.path.endsWith('/subdomain') && request.body?.enabled === false) throw new Error(PRIVATE);
        if (phase === 'retire' && request.method === 'PUT' && state.uploads.length === 2) throw new Error(PRIVATE);
        if (phase === 'delete' && request.method === 'DELETE') throw new Error(PRIVATE);
      },
      after({ request, response, state }) {
        if (phase === 'namespace_remains' && retirement({ state }).length && request.path.endsWith('/namespaces')) {
          response.result = [{ id: NAMESPACE, script: state.name, class: 'AdminState', use_sqlite: true }];
        }
        if (phase === 'worker_remains' && request.method === 'GET' && request.path.endsWith(`/workers/${WORKER}`)) return ok({});
      },
    });
    const result = await subject.run();
    assert.equal(result.observations.length, 4, 'cleanup faults must follow successful probes');
    assert.equal(result.passed, false, phase);
    assert.equal(result.cleanup, 'resources_may_remain', phase);
    assert.equal(subject.calls.filter((call) => call.method === 'DELETE').length, ['delete', 'worker_remains'].includes(phase) ? 1 : 0, phase);
    assertPrivate(subject, result);
  }
});

test('successful strip diagnostic does not mask the observed default-forwarding failure', async () => {
  const subject = fixture({ probeResponse({ command }) {
    if (command?.command === 'probe' && command.targetRevision === 'new' && !command.forwarding) {
      return Response.json({ schemaVersion: 1, error: 'exception', stage: 'stub_fetch' }, {
        status: 503, headers: { 'x-canary-outer-revision': 'new', 'x-canary-do-revision': 'unknown' },
      });
    }
  } });
  const result = await subject.run();
  assert.deepEqual(result.observations.map((item) => item.passed), [false, true, true, false]);
  assert.equal(result.passed, false);
  assert.equal(result.cleanup, 'verified_removed');
  assert.equal(subject.state.stateWrites, 4);
  assertPrivate(subject, result);
});

test('fixed fixture failure labels survive without arbitrary exception, body or credential details', async () => {
  const subject = fixture({ probeResponse({ command }) {
    if (command?.command === 'probe' && command.targetRevision === 'new') {
      return Response.json({ schemaVersion: 1, error: 'exception', stage: 'stub_fetch' }, {
        status: 503, headers: { 'x-canary-outer-revision': 'new', 'x-canary-do-revision': 'unknown' },
      });
    }
  } });
  const result = await subject.run();
  assert.equal(result.passed, false);
  assert.equal(result.cleanup, 'verified_removed');
  for (const observation of [result.observations[0], result.observations[1], result.observations[3]]) {
    assert.equal(observation.error, 'exception');
    assert.equal(observation.stage, 'stub_fetch');
  }
  assert.equal(result.observations[2].passed, true);
  assertPrivate(subject, result);
});

test('private, malformed, oversized or thrown probe responses remain bounded and never echoed', async () => {
  for (const response of [
    () => Response.json({ schemaVersion: 1, error: PRIVATE, stage: PRIVATE }),
    () => new Response(`invalid ${PRIVATE}`, { status: 503 }),
    () => new Response(PRIVATE.repeat(100), { status: 503 }),
    () => { throw new Error(PRIVATE); },
  ]) {
    const subject = fixture({ probeResponse({ command }) { if (command?.command === 'probe') return response(); } });
    const result = await subject.run();
    assert.equal(result.passed, false);
    assert.equal(result.cleanup, 'verified_removed');
    assert.equal(result.observations.length, 4);
    assertPrivate(subject, result);
  }
});

test('only exact schema-one fixture errors contribute diagnostic labels', async () => {
  for (const body of [
    { error: 'exception', stage: 'stub_fetch' },
    { schemaVersion: 2, error: 'exception', stage: 'stub_fetch' },
    { schemaVersion: 1, error: 'exception', stage: 'stub_fetch', private: PRIVATE },
    { schemaVersion: 1, error: PRIVATE, stage: PRIVATE },
  ]) {
    const subject = fixture({ probeResponse({ command }) {
      if (command?.command === 'probe') return Response.json(body, { status: 503 });
    } });
    const result = await subject.run();
    assert.equal(result.cleanup, 'verified_removed');
    assert.equal(result.observations.length, 4);
    for (const observation of result.observations) {
      assert.equal(observation.error, null);
      assert.equal(observation.stage, null);
    }
    assertPrivate(subject, result);
  }
});

test('an early control failure retains fixed evidence, stops further mutations, and still cleans up', async () => {
  const subject = fixture({ probeResponse({ command }) {
    if (command?.command === 'begin') return Response.json({ schemaVersion: 1, error: 'exception', stage: 'stub_fetch' }, {
      status: 503, headers: { 'x-canary-outer-revision': 'old', 'x-canary-do-revision': 'unknown' },
    });
  } });
  const result = await subject.run();
  assert.equal(result.failure, 'seed');
  assert.equal(result.reason, 'control_failed');
  assert.deepEqual(result.controlFailure, {
    status: 503, outer: 'old', durableObject: 'unknown', ready: false, error: 'exception', stage: 'stub_fetch',
  });
  assert.equal(subject.probes.filter((probe) => probe.command?.command === 'begin').length, 1);
  assert.equal(subject.calls.filter((call) => call.method === 'POST' && call.path.endsWith('/versions')).length, 0);
  assert.equal(subject.calls.filter((call) => call.method === 'POST' && call.path.endsWith('/deployments')).length, 0);
  assert.equal(result.cleanup, 'verified_removed');
  assertPrivate(subject, result);
});

test('readiness redirects are never followed or sent the gate key and still trigger verified cleanup', async () => {
  for (const status of [302, 307]) {
    const destination = `https://untrusted.example/redirect-${status}`;
    const subject = fixture({ probeResponse() {
      return new Response(null, { status, headers: { location: destination } });
    } });
    const result = await subject.run();
    assert.equal(result.failure, 'seed');
    assert.equal(result.reason, 'readiness_unavailable');
    assert.equal(result.cleanup, 'verified_removed');
    assert.equal(subject.probes.length, 15, 'only bounded readiness checks are retried');
    for (const request of subject.probes) {
      assert.equal(new URL(request.url).origin, `https://${subject.state.name}.synthetic-canary.workers.dev`);
      assert.notEqual(request.url, destination);
      assert.equal(request.init.redirect, 'manual');
      assert.equal(request.init.method, 'GET');
      assert.equal(request.command, null);
    }
    assert.equal(subject.state.stateWrites, 0);
    assert.equal(subject.calls.filter((call) => call.method === 'POST' && call.path.endsWith('/versions')).length, 0);
    assert.equal(subject.calls.filter((call) => call.method === 'POST' && call.path.endsWith('/deployments')).length, 0);
    assertPrivate(subject, result);
  }
});

test('contradictory namespace pagination or an unbounded inventory cannot authorize cleanup', async () => {
  for (const variant of ['wrong_page', 'extra_pages', 'wrong_total', 'unbounded']) {
    const subject = fixture({ after({ request, response }) {
      if (!request.path.endsWith('/namespaces')) return;
      if (variant === 'wrong_page') response.result_info = { page: 2 };
      if (variant === 'extra_pages') response.result_info = { total_pages: 2 };
      if (variant === 'wrong_total') response.result_info = { total_count: 2 };
      if (variant === 'unbounded') response.result = Array.from({ length: 100 }, () => ({ ...response.result[0] }));
    } });
    const result = await subject.run();
    const expected = variant === 'unbounded' ? 'namespace_inventory_unbounded' : 'namespace_inventory_incomplete';
    assert.equal(result.failure, 'create');
    assert.equal(result.reason, expected);
    assert.equal(result.cleanup, 'resources_may_remain');
    assert.equal(result.cleanupReason, expected);
    assert.equal(retirement(subject).length, 0);
    assert.equal(mutations(subject).filter((call) => call.method === 'DELETE').length, 0);
    assert.equal(subject.calls.filter((call) => call.path.endsWith('/namespaces')).length, variant === 'unbounded' ? 40 : 2);
  }
});

test('throwing event consumers cannot skip owned cleanup', async () => {
  const subject = fixture({ eventThrows: true });
  const result = await subject.run();
  assert.equal(result.passed, true);
  assert.equal(result.cleanup, 'verified_removed');
  assertPrivate(subject, result);
});

test('Cloudflare transport keeps its token only on the fixed API origin and preserves provider status', async () => {
  const token = 'synthetic-operation-api-token';
  const requests = [];
  const api = cloudflareTransport(token, async (url, init) => {
    requests.push({ url, init });
    assert.equal(url.origin, 'https://api.cloudflare.com');
    assert.equal(new Headers(init.headers).get('authorization'), `Bearer ${token}`);
    assert.equal(new Headers(init.headers).get('x-ankka-canary-key'), null);
    assert.equal(init.redirect, 'error');
    assert.ok(init.signal instanceof AbortSignal);
    return Response.json({ success: false, errors: [{ message: PRIVATE }] }, { status: 403 });
  });
  const result = await api({ method: 'GET', path: `/accounts/${ACCOUNT}/workers/subdomain`, query: { page: 1 } });
  assert.equal(result.status, 403);
  assert.equal(result.success, false);
  assert.equal(requests.length, 1);
  assert.ok(!JSON.stringify(result).includes(PRIVATE));
  assert.throws(() => cloudflareTransport('invalid\ncredential'));
});

test('response bounds cancel a stream before consuming unbounded provider output', async () => {
  let cancelled = false;
  const response = new Response(new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(1025)); },
    cancel() { cancelled = true; },
  }));
  await assert.rejects(boundedText(response, 1024), { message: 'response_too_large' });
  assert.equal(cancelled, true);
});
