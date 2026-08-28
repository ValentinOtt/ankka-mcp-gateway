import { describe, expect, it } from 'vitest';
import * as v from 'valibot';

import { PUBLIC_ORIGIN, SESSION_COOKIE } from '../src/constants';
import type { GatewayDeployEnv } from '../src/env';
import { createGatewayDeployWorker } from '../src/index';
import {
  cookiePair,
  env,
  FakeDeploySessionNamespace,
  NOW,
  releaseProvider,
  selectionInput,
} from './fixtures';

class RecordingRateLimit implements RateLimit {
  readonly keys: string[] = [];
  outcomes: Array<boolean | Error | RateLimitOutcome> = [];
  defaultSuccess = true;

  async limit(options: RateLimitOptions): Promise<RateLimitOutcome> {
    this.keys.push(options.key);
    const outcome = this.outcomes.shift();
    if (outcome instanceof Error) throw outcome;
    if (v.is(v.boolean(), outcome)) return { success: outcome };
    return outcome ?? { success: this.defaultSuccess };
  }
}

class CountingNamespace extends FakeDeploySessionNamespace {
  getCalls = 0;
  readonly names: string[] = [];

  override get(id: DurableObjectId) {
    this.getCalls += 1;
    this.names.push(id.toString());
    return super.get(id);
  }
}

function protectedEnv(
  namespace: FakeDeploySessionNamespace = new CountingNamespace(),
  anonymous: RateLimit | null = new RecordingRateLimit(),
  mutation: RateLimit | null = new RecordingRateLimit(),
  read: RateLimit | null = new RecordingRateLimit(),
): GatewayDeployEnv {
  const workerEnv = { ...env(namespace) };
  if (anonymous !== null) Object.assign(workerEnv, { ANONYMOUS_SESSION_RATE_LIMIT: anonymous });
  if (read !== null) Object.assign(workerEnv, { SESSION_READ_RATE_LIMIT: read });
  if (mutation !== null) Object.assign(workerEnv, { SESSION_MUTATION_RATE_LIMIT: mutation });
  return workerEnv;
}

function edgeRequest(path: string, init: RequestInit = {}, address = '192.0.2.44'): Request {
  const headers = new Headers(init.headers);
  headers.set('cf-connecting-ip', address);
  return new Request(`${PUBLIC_ORIGIN}${path}`, { ...init, headers });
}

function activeWorker() {
  return createGatewayDeployWorker({
    abuseControlPolicy: 'required',
    now: () => NOW,
    releaseProvider,
  });
}

async function activeSession(
  worker: ReturnType<typeof activeWorker>,
  workerEnv: GatewayDeployEnv,
): Promise<{ cookie: string; csrf: string }> {
  const response = await worker.fetch(edgeRequest('/api/session'), workerEnv, undefined);
  expect(response.status).toBe(200);
  const payload = v.parse(v.looseObject({ csrf: v.string() }), await response.json());
  return {
    cookie: cookiePair(response.headers.get('set-cookie') ?? '', SESSION_COOKIE),
    csrf: payload.csrf,
  };
}

function mutationHeaders(session: { cookie: string; csrf: string }): HeadersInit {
  return {
    cookie: session.cookie,
    'content-type': 'application/json',
    origin: PUBLIC_ORIGIN,
    'sec-fetch-site': 'same-origin',
    'x-csrf-token': session.csrf,
  };
}

describe('hosted installer Worker-native abuse controls', () => {
  it('retains the anonymous creation limit before any Durable Object lookup', async () => {
    const namespace = new CountingNamespace();
    const anonymous = new RecordingRateLimit();
    anonymous.defaultSuccess = false;
    const address = '2001:db8::44';
    const response = await activeWorker().fetch(
      edgeRequest('/api/session', {}, address),
      protectedEnv(namespace, anonymous),
      undefined,
    );

    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBe('60');
    const body = await response.text();
    expect(JSON.parse(body)).toEqual({ code: 'rate_limited' });
    expect(namespace.getCalls).toBe(0);
    expect(namespace.states.size).toBe(0);
    expect(anonymous.keys).toHaveLength(1);
    expect(anonymous.keys[0]).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(JSON.stringify([...response.headers]) + body).not.toContain(address);
  });

  it.each(['/api/session', '/api/discovery'])(
    'rotates an unauthenticated format-valid cookie on %s through the anonymous limiter',
    async (path) => {
      const namespace = new CountingNamespace();
      const anonymous = new RecordingRateLimit();
      const mutation = new RecordingRateLimit();
      const read = new RecordingRateLimit();
      const workerEnv = protectedEnv(namespace, anonymous, mutation, read);
      const sprayedCookie = `${SESSION_COOKIE}=${'A'.repeat(43)}`;
      const address = '2001:db8::44';

      const response = await activeWorker().fetch(edgeRequest(path, {
        headers: { cookie: sprayedCookie },
      }, address), workerEnv, undefined);

      expect(response.status).toBe(200);
      expect(response.headers.get('retry-after')).toBeNull();
      const body = await response.text();
      expect(JSON.parse(body)).toHaveProperty('csrf');
      const rotatedCookie = cookiePair(response.headers.get('set-cookie') ?? '', SESSION_COOKIE);
      expect(rotatedCookie).not.toBe(sprayedCookie);
      expect(rotatedCookie.slice(rotatedCookie.indexOf('=') + 1)).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      expect(namespace.getCalls).toBe(1);
      expect(namespace.names).not.toContain('A'.repeat(43));
      expect(namespace.states.size).toBe(1);
      expect(anonymous.keys).toHaveLength(1);
      expect(read.keys).toHaveLength(0);
      expect(mutation.keys).toHaveLength(0);
      const exposed = JSON.stringify([...response.headers]) + body;
      expect(exposed).not.toContain(address);
    },
  );

  it.each(['/api/session', '/api/discovery'])(
    'returns 429 for an unauthenticated format-valid cookie on %s before any Durable Object lookup',
    async (path) => {
      const namespace = new CountingNamespace();
      const anonymous = new RecordingRateLimit();
      const mutation = new RecordingRateLimit();
      const read = new RecordingRateLimit();
      anonymous.defaultSuccess = false;
      const response = await activeWorker().fetch(edgeRequest(path, {
        headers: { cookie: `${SESSION_COOKIE}=${'A'.repeat(43)}` },
      }), protectedEnv(namespace, anonymous, mutation, read), undefined);

      expect(response.status).toBe(429);
      expect(response.headers.get('retry-after')).toBe('60');
      expect(await response.json()).toEqual({ code: 'rate_limited' });
      expect(namespace.getCalls).toBe(0);
      expect(namespace.states.size).toBe(0);
      expect(anonymous.keys).toHaveLength(1);
      expect(read.keys).toHaveLength(0);
      expect(mutation.keys).toHaveLength(0);
    },
  );

  it('authenticates and bounds existing session reads before each Durable Object lookup', async () => {
    const namespace = new CountingNamespace();
    const anonymous = new RecordingRateLimit();
    const mutation = new RecordingRateLimit();
    const read = new RecordingRateLimit();
    read.outcomes.push(true, false);
    const workerEnv = protectedEnv(namespace, anonymous, mutation, read);
    const worker = activeWorker();
    const session = await activeSession(worker, workerEnv);
    expect(session.cookie.slice(session.cookie.indexOf('=') + 1)).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    anonymous.defaultSuccess = false;
    mutation.defaultSuccess = false;

    const response = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: session.cookie },
    }), workerEnv, undefined);

    expect(response.status).toBe(200);
    expect(v.parse(v.looseObject({ csrf: v.string() }), await response.json()).csrf).toBe(session.csrf);
    const beforeLimitedRead = namespace.getCalls;
    const limited = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/discovery`, {
      headers: { cookie: session.cookie },
    }), workerEnv, undefined);
    expect(limited.status).toBe(429);
    expect(limited.headers.get('retry-after')).toBe('60');
    expect(await limited.json()).toEqual({ code: 'rate_limited' });
    expect(namespace.getCalls).toBe(beforeLimitedRead);
    expect(anonymous.keys).toHaveLength(1);
    expect(read.keys).toHaveLength(2);
    expect(read.keys[0]).toBe(read.keys[1]);
    expect(read.keys[0]).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(read.keys[0]).not.toBe(session.cookie.slice(session.cookie.indexOf('=') + 1));
    expect(JSON.stringify([...limited.headers])).not.toContain(read.keys[0]);
    expect(mutation.keys).toHaveLength(0);
  });

  it('applies a stable per-session mutation limit and returns no limiter identity', async () => {
    const anonymous = new RecordingRateLimit();
    const mutation = new RecordingRateLimit();
    mutation.outcomes.push(true, false);
    const workerEnv = protectedEnv(new CountingNamespace(), anonymous, mutation);
    const worker = activeWorker();
    const session = await activeSession(worker, workerEnv);

    const first = await worker.fetch(edgeRequest('/api/selection', {
      method: 'PUT',
      headers: mutationHeaders(session),
      body: JSON.stringify(selectionInput),
    }), workerEnv, undefined);
    expect(first.status).toBe(200);

    const limited = await worker.fetch(edgeRequest('/api/selection', {
      method: 'PUT',
      headers: mutationHeaders(session),
      body: JSON.stringify(selectionInput),
    }), workerEnv, undefined);
    expect(limited.status).toBe(429);
    expect(limited.headers.get('retry-after')).toBe('60');
    const body = await limited.text();
    expect(JSON.parse(body)).toEqual({ code: 'rate_limited' });
    expect(mutation.keys).toHaveLength(2);
    expect(mutation.keys[0]).toBe(mutation.keys[1]);
    expect(mutation.keys[0]).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(mutation.keys[0]).not.toBe(session.cookie.slice(session.cookie.indexOf('=') + 1));
    const visible = JSON.stringify([...limited.headers]) + body;
    expect(visible).not.toContain(mutation.keys[0]);
    expect(visible).not.toContain('192.0.2.44');
  });

  it('uses independent purpose-separated keys for creation, reads, and both mutation identities', async () => {
    const anonymous = new RecordingRateLimit();
    const mutation = new RecordingRateLimit();
    const read = new RecordingRateLimit();
    const workerEnv = protectedEnv(new CountingNamespace(), anonymous, mutation, read);
    const worker = activeWorker();
    const session = await activeSession(worker, workerEnv);

    const sessionRead = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: session.cookie },
    }), workerEnv, undefined);
    expect(sessionRead.status).toBe(200);

    const anonymousMutation = await worker.fetch(edgeRequest('/api/not-real', {
      method: 'POST',
      headers: { origin: PUBLIC_ORIGIN, 'content-type': 'application/json' },
      body: '{}',
    }), workerEnv, undefined);
    expect(anonymousMutation.status).toBe(404);

    const sessionMutation = await worker.fetch(edgeRequest('/api/not-real', {
      method: 'POST',
      headers: { cookie: session.cookie, origin: PUBLIC_ORIGIN, 'content-type': 'application/json' },
      body: '{}',
    }), workerEnv, undefined);
    expect(sessionMutation.status).toBe(404);

    expect(anonymous.keys).toHaveLength(1);
    expect(read.keys).toHaveLength(1);
    expect(mutation.keys).toHaveLength(2);
    expect(new Set([anonymous.keys[0], read.keys[0], ...mutation.keys]).size).toBe(4);
  });

  it('fails closed on missing and failed bindings with fixed secret-free responses', async () => {
    const missing = await activeWorker().fetch(
      edgeRequest('/api/session'),
      protectedEnv(new CountingNamespace(), null, new RecordingRateLimit()),
      undefined,
    );
    expect(missing.status).toBe(503);
    expect(await missing.json()).toEqual({ code: 'abuse_controls_unavailable' });

    const mutation = new RecordingRateLimit();
    const read = new RecordingRateLimit();
    const namespace = new CountingNamespace();
    const workerEnv = protectedEnv(namespace, new RecordingRateLimit(), mutation, read);
    const worker = activeWorker();
    const session = await activeSession(worker, workerEnv);

    const beforeMissingRead = namespace.getCalls;
    const missingReadEnv = { ...workerEnv };
    delete missingReadEnv.SESSION_READ_RATE_LIMIT;
    const missingRead = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: session.cookie },
    }), missingReadEnv, undefined);
    expect(missingRead.status).toBe(503);
    expect(await missingRead.json()).toEqual({ code: 'abuse_controls_unavailable' });
    expect(namespace.getCalls).toBe(beforeMissingRead);

    read.outcomes.push(new Error('read provider failure with private detail'));
    const beforeFailedRead = namespace.getCalls;
    const failedRead = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/discovery`, {
      headers: { cookie: session.cookie },
    }), workerEnv, undefined);
    expect(failedRead.status).toBe(503);
    const failedReadBody = await failedRead.text();
    expect(JSON.parse(failedReadBody)).toEqual({ code: 'abuse_controls_unavailable' });
    expect(failedReadBody).not.toContain('private detail');
    expect(namespace.getCalls).toBe(beforeFailedRead);

    mutation.outcomes.push(new Error('provider failure with private detail'));
    const failed = await worker.fetch(edgeRequest('/api/selection', {
      method: 'PUT', headers: mutationHeaders(session), body: JSON.stringify(selectionInput),
    }), workerEnv, undefined);
    expect(failed.status).toBe(503);
    const body = await failed.text();
    expect(JSON.parse(body)).toEqual({ code: 'abuse_controls_unavailable' });
    expect(body).not.toContain('private detail');
  });

  it('leaves management context, OAuth callback, and signed release discovery outside the bindings', async () => {
    const workerEnv = protectedEnv(new CountingNamespace(), null, null, null);
    const worker = activeWorker();
    const stable = await worker.fetch(
      new Request(`${PUBLIC_ORIGIN}/api/releases/stable`),
      workerEnv,
      undefined,
    );
    expect(stable.status).toBe(200);

    const callback = await worker.fetch(
      new Request(`${PUBLIC_ORIGIN}/oauth/callback?state=not-valid`),
      workerEnv,
      undefined,
    );
    expect(callback.status).toBe(400);
    expect(await callback.json()).not.toEqual({ code: 'abuse_controls_unavailable' });

    const context = await worker.fetch(
      new Request(`${PUBLIC_ORIGIN}/api/management/context`),
      workerEnv,
      undefined,
    );
    expect(context.status).toBe(404);
    expect(await context.json()).toEqual({ code: 'session_invalid' });
  });

  it('leaves management context semantics unchanged for an unrelated random session cookie', async () => {
    const namespace = new CountingNamespace();
    const read = new RecordingRateLimit();
    const workerEnv = protectedEnv(
      namespace,
      new RecordingRateLimit(),
      new RecordingRateLimit(),
      read,
    );
    const response = await activeWorker().fetch(new Request(`${PUBLIC_ORIGIN}/api/management/context`, {
      headers: { cookie: `${SESSION_COOKIE}=${'B'.repeat(43)}` },
    }), workerEnv, undefined);

    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ code: 'session_invalid' });
    expect(namespace.getCalls).toBe(0);
    expect(read.keys).toHaveLength(0);
  });

  it('leaves callback semantics unchanged for an unrelated random session cookie', async () => {
    const namespace = new CountingNamespace();
    const anonymous = new RecordingRateLimit();
    const mutation = new RecordingRateLimit();
    const read = new RecordingRateLimit();
    const workerEnv = protectedEnv(namespace, anonymous, mutation, read);
    const response = await activeWorker().fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?state=not-valid`,
      { headers: { cookie: `${SESSION_COOKIE}=${'C'.repeat(43)}` } },
    ), workerEnv, undefined);

    expect(response.status).toBe(400);
    expect(await response.json()).not.toEqual({ code: 'abuse_controls_unavailable' });
    expect(namespace.getCalls).toBe(0);
    expect(anonymous.keys).toHaveLength(0);
    expect(read.keys).toHaveLength(0);
    expect(mutation.keys).toHaveLength(0);
  });

  it('catches a malformed session cookie as a fixed error before limiter or namespace access', async () => {
    const namespace = new CountingNamespace();
    const anonymous = new RecordingRateLimit();
    const mutation = new RecordingRateLimit();
    const read = new RecordingRateLimit();
    const workerEnv = protectedEnv(namespace, anonymous, mutation, read);
    const response = await activeWorker().fetch(new Request(`${PUBLIC_ORIGIN}/api/session`, {
      headers: { cookie: `${SESSION_COOKIE}=not-a-valid-session-cookie!` },
    }), workerEnv, undefined);

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ code: 'session_invalid' });
    expect(namespace.getCalls).toBe(0);
    expect(anonymous.keys).toHaveLength(0);
    expect(read.keys).toHaveLength(0);
    expect(mutation.keys).toHaveLength(0);
  });
});
