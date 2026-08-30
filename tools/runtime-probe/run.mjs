// Synthetic platform diagnostic, not an installer or a customer cleanup tool.
const ID = /^[0-9a-f]{32}$/u;
const VERSION = /^[0-9a-f-]{36}$/u;
const MIGRATION = 'runtime-probe-v1';
const CLEANUP_MIGRATION = 'runtime-probe-deleted-v2';
const CLEANUP_SOURCE = 'export default { fetch() { return new Response(null, { status: 404 }); } };';
const FIXTURE_ERRORS = ['unauthorized', 'unavailable', 'not_found', 'invalid_command', 'state_conflict', 'version_mismatch', 'invalid_response', 'exception'];
const FIXTURE_STAGES = ['authorization', 'environment', 'routing', 'request_content_type', 'binding', 'stub_id', 'stub_get', 'stub_shape', 'request_read', 'probe_target', 'probe_headers', 'probe_request', 'do_request', 'stub_fetch', 'response_check', 'do_request_read', 'do_probe', 'do_begin', 'do_progress'];

export const RUNTIME_PROBE_PLAN = Object.freeze([
  'Create one randomly named Worker and its own SQLite Durable Object namespace.',
  'Expose only authenticated synthetic fixture requests on its temporary workers.dev address.',
  'Seed fake state on old; upload new; stage old 100%, new 0%.',
  'Compare old and candidate probes; isolate forwarding of the version override header.',
  'Disable the temporary address; delete the synthetic class and all its data; delete the Worker.',
  'Verify Worker and namespace absence. Never modify an existing gateway.',
]);

class CanaryError extends Error {}
function fail(code) { throw new CanaryError(code); }
function randomHex(bytes) {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (byte) => byte.toString(16).padStart(2, '0')).join('');
}
function randomKey() {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

export async function boundedText(response, limit) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  let size = 0;
  const chunks = [];
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > limit) fail('response_too_large');
      chunks.push(next.value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const joined = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder().decode(joined);
}

// Credentials are used only by this adapter, never by the fixture or probe fetch.
export function cloudflareTransport(token, fetcher = fetch) {
  if (!token || /[\r\n]/u.test(token)) fail('credential_missing');
  return async (request) => {
    const url = new URL(`https://api.cloudflare.com/client/v4${request.path}`);
    for (const [key, value] of Object.entries(request.query ?? {})) url.searchParams.set(key, String(value));
    const headers = { authorization: `Bearer ${token}` };
    if (request.body !== undefined) headers['content-type'] = request.contentType ?? 'application/json';
    const response = await fetcher(url, {
      method: request.method, headers, redirect: 'error', signal: AbortSignal.timeout(60_000),
      body: request.body === undefined ? undefined : request.rawBody ? request.body : JSON.stringify(request.body),
    });
    const raw = await boundedText(response, 256 * 1024);
    const data = raw ? JSON.parse(raw) : {};
    return { status: response.status, success: response.ok && (data.success ?? true), result: data.result, result_info: data.result_info };
  };
}

/** All deletion authority is generated and checked within this invocation. No resume file or caller-supplied name. */
export async function runRuntimeProbeCanary({ accountId, fixtureSource, api, probe = fetch, onEvent = () => {}, wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) }) {
  if (!ID.test(accountId)) fail('account_invalid');
  if (!fixtureSource || fixtureSource.length > 64 * 1024) fail('fixture_invalid');
  const name = `ankka-probe-${randomHex(16)}`;
  const marker = `runtime-probe:${randomHex(16)}`;
  const key = randomKey();
  const base = `/accounts/${accountId}/workers`;
  const script = `${base}/scripts/${name}`;
  const worker = `${base}/workers/${name}`;
  let workerId;
  let namespaceId;
  let attemptedCreate = false;
  let cleanup = 'not_needed';
  let stage = 'preflight';
  let failure = null;
  let reason = null;
  let cleanupReason = null;
  let controlFailure = null;
  const observations = [];
  const event = (value) => { try { onEvent(value); } catch { /* Reporting cannot skip cleanup. */ } };
  const checked = async (request) => {
    const result = await api(request);
    if (!result.success) fail('provider_rejected');
    return result.result;
  };
  const detail = async () => checked({ method: 'GET', path: worker });
  const settings = async () => checked({ method: 'GET', path: `${script}/settings` });
  const namespaceList = async () => {
    const entries = [];
    for (let page = 1; page <= 20; page += 1) {
      const response = await api({ method: 'GET', path: `${base}/durable_objects/namespaces`, query: { page, per_page: 100 } });
      if (!response.success || !Array.isArray(response.result)) fail('namespace_inventory_unavailable');
      const info = response.result_info;
      if (info?.page !== undefined && info.page !== page) fail('namespace_inventory_incomplete');
      entries.push(...response.result);
      if (response.result.length < 100) {
        if ((info?.total_pages !== undefined && info.total_pages > page)
          || (info?.total_count !== undefined && info.total_count !== entries.length)) fail('namespace_inventory_incomplete');
        return entries;
      }
    }
    fail('namespace_inventory_unbounded');
  };
  const owned = async (withNamespace) => {
    const observed = await detail();
    if (observed.name !== name || !ID.test(observed.id) || (workerId && observed.id !== workerId)
      || !Array.isArray(observed.tags) || !observed.tags.includes(marker)
      || !observed.references || ['workers', 'domains', 'dispatch_namespace_outbounds', 'queues'].some((type) => !Array.isArray(observed.references[type]) || observed.references[type].length > 0)
      || !Array.isArray(observed.references.durable_objects)) fail('ownership_changed');
    workerId = observed.id;
    const config = await settings();
    const bindings = config.bindings ?? [];
    if (withNamespace) {
      const binding = bindings.find((item) => item.name === 'ADMIN_STATE');
      if (bindings.length !== 3 || !binding || binding.type !== 'durable_object_namespace' || binding.class_name !== 'AdminState'
        || !ID.test(binding.namespace_id) || (namespaceId && binding.namespace_id !== namespaceId)
        || (binding.script_name && binding.script_name !== name)
        || !bindings.some((item) => item.name === 'CANARY_KEY' && item.type === 'secret_text')
        || !bindings.some((item) => item.name === 'CANARY_REVISION' && item.type === 'plain_text')) fail('binding_changed');
      namespaceId = binding.namespace_id;
      // Live API includes the Worker's own binding despite describing "other Workers".
      // This one exact self-reference is not an external dependency.
      if (observed.references.durable_objects.length > 1 || observed.references.durable_objects.some((entry) =>
        entry.worker_id !== workerId || entry.worker_name !== name || entry.namespace_id !== namespaceId)) fail('ownership_changed');
      const namespaces = await namespaceList();
      const entry = namespaces.find((item) => item.id === namespaceId);
      if (!entry || entry.script !== name || entry.class !== 'AdminState' || entry.use_sqlite !== true) fail('namespace_changed');
    } else if (bindings.length > 1 || bindings.some((item) => item.name !== 'CANARY_KEY' || item.type !== 'secret_text')
      || observed.references.durable_objects.length !== 0) {
      fail('binding_changed');
    }
    // Immediate uploads may retain secret bindings. The sole permitted remainder
    // is this run's ephemeral gate; deleting the Worker below removes it too.
    return observed;
  };
  const upload = async (revision, initial = false, retiring = false) => {
    const metadata = {
      main_module: 'index.js', compatibility_date: '2026-08-08', compatibility_flags: [],
      bindings: retiring ? [] : [
        { type: 'durable_object_namespace', name: 'ADMIN_STATE', class_name: 'AdminState' },
        { type: 'plain_text', name: 'CANARY_REVISION', text: revision },
        { type: 'secret_text', name: 'CANARY_KEY', text: key },
      ],
    };
    if (initial || retiring) {
      metadata.tags = [marker];
      metadata.observability = { enabled: false };
      metadata.logpush = false;
      metadata.migrations = retiring
        ? { old_tag: MIGRATION, new_tag: CLEANUP_MIGRATION, deleted_classes: ['AdminState'] }
        : { new_tag: MIGRATION, new_sqlite_classes: ['AdminState'] };
    }
    const boundary = `probe-${randomHex(16)}`;
    const body = [
      `--${boundary}`, 'Content-Disposition: form-data; name="metadata"', 'Content-Type: application/json', '', JSON.stringify(metadata),
      `--${boundary}`, 'Content-Disposition: form-data; name="index.js"; filename="index.js"', 'Content-Type: application/javascript+module', '', retiring ? CLEANUP_SOURCE : fixtureSource,
      `--${boundary}--`, '',
    ].join('\r\n');
    return checked({ method: initial || retiring ? 'PUT' : 'POST', path: initial || retiring ? script : `${script}/versions`, body, contentType: `multipart/form-data; boundary=${boundary}`, rawBody: true });
  };
  const assertNamespaceAbsent = async () => {
    const entries = await namespaceList();
    if (entries.some((item) => item.id === namespaceId || item.script === name)) fail('namespace_remains');
  };
  try {
    const absent = await api({ method: 'GET', path: worker });
    if (absent.status !== 404 || absent.success) fail('name_not_absent');
    const subdomain = await checked({ method: 'GET', path: `${base}/subdomain` });
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(subdomain?.subdomain)) fail('subdomain_invalid');
    const url = `https://${name}.${subdomain.subdomain}.workers.dev`;
    stage = 'create';
    event({ stage, workerName: name });
    attemptedCreate = true;
    await upload('old', true);
    await owned(true);
    const deployments = await checked({ method: 'GET', path: `${script}/deployments` });
    const old = deployments?.deployments?.[0]?.versions?.[0]?.version_id;
    if (!VERSION.test(old) || deployments.deployments[0].versions.length !== 1 || deployments.deployments[0].versions[0].percentage !== 100) fail('old_deployment_invalid');
    await checked({ method: 'POST', path: `${script}/subdomain`, body: { enabled: true, previews_enabled: false } });
    const call = async (body, version) => {
      const headers = { 'x-ankka-canary-key': key, 'content-type': 'application/json' };
      if (version) headers['Cloudflare-Workers-Version-Overrides'] = `${name}="${version}"`;
      const response = await probe(`${url}${body ? '/control' : '/ready'}`, {
        method: body ? 'POST' : 'GET', headers, body: body ? JSON.stringify({ schemaVersion: 1, ...body }) : undefined,
        // Edge fetch implementations support manual, not redirect:"error".
        // Never follow a redirect carrying the ephemeral gate.
        redirect: 'manual', signal: AbortSignal.timeout(10_000),
      });
      const text = await boundedText(response, 1024);
      let data = null;
      try { data = text ? JSON.parse(text) : null; } catch { /* Only fixed fixture fields are accepted below. */ }
      const diagnostic = data?.schemaVersion === 1 && Object.keys(data).sort().join(',') === 'error,schemaVersion,stage';
      const revision = (value) => ['old', 'new'].includes(value) ? value : 'unknown';
      return {
        status: response.status,
        outer: revision(response.headers.get('x-canary-outer-revision') ?? data?.revision),
        durableObject: revision(response.headers.get('x-canary-do-revision')),
        ready: response.headers.get('x-ankka-runtime-action') === 'ready',
        error: diagnostic && FIXTURE_ERRORS.includes(data.error) ? data.error : null,
        stage: diagnostic && FIXTURE_STAGES.includes(data.stage) ? data.stage : null,
      };
    };
    const waitReady = async (revision, version) => {
      for (let attempt = 0; attempt < 15; attempt += 1) {
        try {
          const result = await call(null, version);
          if (result.status === 200 && result.outer === revision) return;
        } catch { /* Bounded readiness-only polling; no control mutation retries. */ }
        await wait(2000);
      }
      fail('readiness_unavailable');
    };
    const control = async (body) => {
      const result = await call(body);
      if (result.status !== 200 || result.outer !== 'old' || result.durableObject !== 'old') {
        controlFailure = result;
        fail('control_failed');
      }
    };
    stage = 'seed';
    await waitReady('old');
    await control({ command: 'begin' });
    await control({ command: 'progress', stage: 'current_verified' });
    stage = 'upload_candidate';
    const candidate = await upload('new');
    if (!VERSION.test(candidate?.id)) fail('candidate_invalid');
    await owned(true);
    await control({ command: 'progress', stage: 'candidate_created' });
    stage = 'stage_candidate';
    const versions = [{ version_id: old, percentage: 100 }, { version_id: candidate.id, percentage: 0 }];
    await checked({ method: 'POST', path: `${script}/deployments`, body: { strategy: 'percentage', versions } });
    const current = await checked({ method: 'GET', path: `${script}/deployments` });
    const active = current?.deployments?.[0]?.versions;
    if (!Array.isArray(active) || active.length !== 2 || !versions.every((expected) => active.some((entry) => entry.version_id === expected.version_id && entry.percentage === expected.percentage))) fail('stage_mismatch');
    await control({ command: 'progress', stage: 'candidate_staged' });
    stage = 'probe';
    const observe = async (label, targetRevision, version, forwarding) => {
      let result;
      try {
        const command = { command: 'probe', targetRevision };
        if (forwarding) command.forwarding = forwarding;
        result = await call(command, version);
      }
      catch { result = { status: 0, outer: 'unknown', durableObject: 'unknown', ready: false }; }
      const observation = { label, ...result, passed: result.status === 204 && result.ready && result.outer === targetRevision && result.durableObject === 'old' };
      observations.push(observation);
      event(observation);
    };
    await observe('candidate_immediate', 'new', candidate.id);
    await observe('candidate_strip_override', 'new', candidate.id, 'strip_override');
    await observe('old_baseline', 'old');
    await waitReady('new', candidate.id);
    await observe('candidate_after_ready', 'new', candidate.id);
  } catch (error) {
    // Never expose provider messages, request bodies, environment values, or exception text.
    failure = stage;
    reason = error instanceof CanaryError ? error.message : 'transport_failed';
  } finally {
    if (attemptedCreate) {
      cleanup = 'resources_may_remain';
      event({ stage: 'cleanup' });
      try {
        await owned(true);
        await checked({ method: 'POST', path: `${script}/subdomain`, body: { enabled: false, previews_enabled: false } });
        await owned(true);
        await upload('old', false, true);
        await assertNamespaceAbsent();
        await owned(false);
        // No force: provider must refuse unexpected references.
        await checked({ method: 'DELETE', path: `${base}/workers/${workerId}` });
        const removed = await api({ method: 'GET', path: `${base}/workers/${workerId}` });
        if (removed.status !== 404 || removed.success) fail('worker_remains');
        await assertNamespaceAbsent();
        cleanup = 'verified_removed';
      } catch (error) {
        cleanupReason = error instanceof CanaryError ? error.message : 'transport_failed';
      }
    }
  }
  return { schemaVersion: 1, workerName: name, passed: failure === null && observations.length === 4 && observations.every((item) => item.passed) && cleanup === 'verified_removed', failure, reason, controlFailure, observations, cleanup, cleanupReason };
}
