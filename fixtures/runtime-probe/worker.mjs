// Disposable, synthetic platform fixture. It has no gateway or provider access.
// Keep the probe's clone/header reconstruction/DO fetch order aligned with the
// public gateway Worker. Do not add retries or log request/exception contents.
const KEY_HEADER = 'x-ankka-canary-key';
const REVISION_HEADER = 'x-canary-outer-revision';
const DO_REVISION_HEADER = 'x-canary-do-revision';
const INTERNAL_PATH = '/runtime-updates/control';
const STATE_KEY = 'synthetic-runtime-probe';
const BODY_LIMIT = 1_024;
const READ_TIMEOUT_MS = 3_000;
const STAGES = ['authorized', 'current_verified', 'candidate_created', 'candidate_staged'];
const FUNCTION_SOURCE = Function.prototype.toString;

function isCallable(value) {
  try { FUNCTION_SOURCE.call(value); return true; } catch { return false; }
}

function isText(value) {
  return value !== null && value !== undefined && Object(value) !== value &&
    Object.prototype.toString.call(value) === '[object String]';
}

function revision(env) {
  return ['old', 'new'].includes(env?.CANARY_REVISION) ? env.CANARY_REVISION : 'unknown';
}

function authorized(request, env) {
  const expected = env?.CANARY_KEY;
  const supplied = request.headers.get(KEY_HEADER);
  if (!isText(expected) || !/^[A-Za-z0-9_-]{43}$/u.test(expected) ||
      supplied === null || !/^[A-Za-z0-9_-]{43}$/u.test(supplied)) return false;
  let mismatch = 0;
  for (let index = 0; index < 43; index += 1) {
    mismatch |= expected.charCodeAt(index) ^ supplied.charCodeAt(index);
  }
  return mismatch === 0;
}

function reply(status, value, outerRevision = 'unknown', doRevision = 'unknown') {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      'content-type': 'application/json', 'cache-control': 'no-store',
      [REVISION_HEADER]: outerRevision, [DO_REVISION_HEADER]: doRevision,
    },
  });
}

function failure(status, error, stage, outerRevision = 'unknown', doRevision = 'unknown') {
  return reply(status, { schemaVersion: 1, error, stage }, outerRevision, doRevision);
}

async function readBoundedText(request) {
  const declared = request.headers.get('content-length');
  if (declared !== null && (!Number.isSafeInteger(Number(declared)) ||
      Number(declared) < 0 || Number(declared) > BODY_LIMIT)) return null;
  if (!request.body) return null;
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  let timeout;
  const read = async () => {
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value.byteLength > BODY_LIMIT - total) return null;
        chunks.push(value.slice());
        total += value.byteLength;
      }
      if (total === 0) return null;
      const bytes = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
      finally { bytes.fill(0); }
    } catch { return null; }
  };
  try {
    return await Promise.race([
      read(),
      new Promise((resolve) => { timeout = setTimeout(() => resolve(null), READ_TIMEOUT_MS); }),
    ]);
  } finally {
    clearTimeout(timeout);
    void reader.cancel().catch(() => undefined);
    for (const chunk of chunks) chunk.fill(0);
  }
}

function parseCommand(raw) {
  let value;
  try { value = JSON.parse(raw); } catch { return null; }
  if (!value || Array.isArray(value) || value.schemaVersion !== 1) return null;
  const keys = Object.keys(value).sort().join(',');
  if (value.command === 'begin' && keys === 'command,schemaVersion') return value;
  if (value.command === 'progress' && keys === 'command,schemaVersion,stage' &&
      STAGES.slice(1).includes(value.stage)) return value;
  if (value.command === 'probe' && (keys === 'command,schemaVersion,targetRevision' ||
      (keys === 'command,forwarding,schemaVersion,targetRevision' && value.forwarding === 'strip_override')) &&
      ['old', 'new'].includes(value.targetRevision)) return value;
  return null;
}

export class AdminState {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.queue = Promise.resolve();
  }

  fetch(request) {
    const operation = async () => {
      const ownRevision = revision(this.env);
      const reject = (status, error, stage) => failure(status, error, stage, 'unknown', ownRevision);
      if (!authorized(request, this.env)) return reject(401, 'unauthorized', 'authorization');
      if (ownRevision === 'unknown') return reject(503, 'unavailable', 'environment');
      if (request.method !== 'POST' || new URL(request.url).pathname !== INTERNAL_PATH) {
        return reject(404, 'not_found', 'routing');
      }
      const input = parseCommand(await readBoundedText(request));
      if (!input) return reject(400, 'invalid_command', 'do_request_read');
      const state = await this.state.storage.get(STATE_KEY);
      if (input.command === 'probe') {
        if (state?.stage !== 'candidate_staged' ||
            request.headers.get('x-ankka-runtime-probe-version') !== 'verified') {
          return reject(409, 'state_conflict', 'do_probe');
        }
        return new Response(null, { status: 204, headers: {
          'cache-control': 'no-store', 'x-ankka-runtime-action': 'ready',
          [DO_REVISION_HEADER]: ownRevision,
        } });
      }
      if (input.command === 'begin') {
        if (state !== undefined) return reject(409, 'state_conflict', 'do_begin');
        await this.state.storage.put(STATE_KEY, { stage: 'authorized' });
      } else {
        if (!state || STAGES.indexOf(input.stage) !== STAGES.indexOf(state.stage) + 1) {
          return reject(409, 'state_conflict', 'do_progress');
        }
        await this.state.storage.put(STATE_KEY, { stage: input.stage });
      }
      return reply(200, { schemaVersion: 1, status: 'accepted' }, 'unknown', ownRevision);
    };
    const result = this.queue.then(operation, operation);
    this.queue = result.then(() => undefined, () => undefined);
    return result;
  }
}

export default {
  async fetch(request, env) {
    const ownRevision = revision(env);
    const reject = (status, error, stage) => failure(status, error, stage, ownRevision);
    if (!authorized(request, env)) return reject(401, 'unauthorized', 'authorization');
    if (ownRevision === 'unknown') return reject(503, 'unavailable', 'environment');
    const path = new URL(request.url).pathname;
    if (request.method === 'GET' && path === '/ready') {
      return reply(200, { schemaVersion: 1, revision: ownRevision }, ownRevision);
    }
    if (request.method !== 'POST' || path !== '/control') return reject(404, 'not_found', 'routing');
    if (request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/json') {
      return reject(400, 'invalid_command', 'request_content_type');
    }
    let stage = 'binding';
    try {
      if (!env.ADMIN_STATE || !isCallable(env.ADMIN_STATE.idFromName) ||
          !isCallable(env.ADMIN_STATE.get)) return reject(503, 'unavailable', stage);
      stage = 'stub_id';
      const id = env.ADMIN_STATE.idFromName('v1:management');
      stage = 'stub_get';
      const stub = env.ADMIN_STATE.get(id);
      stage = 'stub_shape';
      if (!stub || !isCallable(stub.fetch)) return reject(503, 'unavailable', stage);
      let internal = request;
      stage = 'request_read';
      const control = parseCommand(await readBoundedText(request.clone()));
      if (!control) return reject(400, 'invalid_command', stage);
      if (control.command === 'probe') {
        stage = 'probe_target';
        if (control.targetRevision !== ownRevision) return reject(409, 'version_mismatch', stage);
        stage = 'probe_headers';
        const headers = new Headers(request.headers);
        headers.set('x-ankka-runtime-probe-version', 'verified');
        // Explicit diagnostic variant only; the default preserves the live path.
        if (control.forwarding === 'strip_override') headers.delete('Cloudflare-Workers-Version-Overrides');
        stage = 'probe_request';
        internal = new Request(request, { headers });
      }
      stage = 'do_request';
      const forwarded = new Request(`https://admin-state.invalid${INTERNAL_PATH}`, internal);
      stage = 'stub_fetch';
      const response = await stub.fetch(forwarded);
      stage = 'response_check';
      if (!(response instanceof Response)) return reject(503, 'invalid_response', stage);
      const headers = new Headers(response.headers);
      headers.set(REVISION_HEADER, ownRevision);
      if (!['old', 'new'].includes(headers.get(DO_REVISION_HEADER))) headers.set(DO_REVISION_HEADER, 'unknown');
      return new Response(response.body, { status: response.status, headers });
    } catch { return reject(503, 'exception', stage); }
  },
};
