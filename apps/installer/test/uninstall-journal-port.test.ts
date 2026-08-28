import * as v from 'valibot';

import { boundaryValueSchema, type BoundaryValue } from '../src/boundary';
import { DeployError } from '../src/errors';
import {
  createUninstallJournalPortWithDependencies,
  type InitializeUninstallJournalPortInput,
  type UninstallJournalFetcher,
  type UninstallJournalPort,
} from '../src/uninstall-journal-port';

const ATTEMPT = `att_${'a'.repeat(32)}`;
const NOW = Date.UTC(2026, 7, 23, 12, 0, 0);
const validWireJournalSchema = v.strictObject({
  schemaVersion: v.literal(1),
  fixture: v.literal('valid-uninstall-journal'),
});
type ValidWireJournal = v.InferOutput<typeof validWireJournalSchema>;
const VALID_WIRE_JOURNAL = Object.freeze({
  schemaVersion: 1,
  fixture: 'valid-uninstall-journal',
} satisfies ValidWireJournal);
const journalParser = vi.fn(async (value: BoundaryValue): Promise<ValidWireJournal> => {
  const result = v.safeParse(validWireJournalSchema, value);
  if (!result.success) throw new DeployError(500, 'session_invalid');
  return Object.freeze(result.output);
});

interface CapturedCall {
  readonly origin: string;
  readonly method: string;
  readonly path: string;
  readonly headers: Record<string, string>;
  readonly body: BoundaryValue | null;
}

interface ExpectedCall<Body> {
  readonly origin: string;
  readonly method: string;
  readonly path: string;
  readonly headers: Record<string, string>;
  readonly body: Body;
}

interface CyclicFixture {
  self?: CyclicFixture;
}

function json<Value>(value: Value, status = 200, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
  });
}

function successJournal(): Response {
  return json({ journal: VALID_WIRE_JOURNAL });
}

function createTestPort(fetcher: UninstallJournalFetcher): UninstallJournalPort<ValidWireJournal> {
  return createUninstallJournalPortWithDependencies(fetcher, { parseJournal: journalParser });
}

async function capturedBody(request: Request): Promise<BoundaryValue | null> {
  if (request.method === 'GET') return null;
  const result = v.safeParse(boundaryValueSchema, await request.json());
  if (!result.success) throw new Error('test captured a non-boundary request body');
  return result.output;
}

beforeEach(() => {
  journalParser.mockReset();
  journalParser.mockImplementation(async (value: BoundaryValue): Promise<ValidWireJournal> => {
    const result = v.safeParse(validWireJournalSchema, value);
    if (!result.success) throw new DeployError(500, 'session_invalid');
    return Object.freeze(result.output);
  });
});

describe('typed uninstall journal port', () => {
  it('uses only the fixed same-DO origin and exact route, method, and body contract', async () => {
    const calls: CapturedCall[] = [];
    const fetcher: UninstallJournalFetcher = {
      fetch: async (request) => {
        calls.push({
          origin: new URL(request.url).origin,
          method: request.method,
          path: new URL(request.url).pathname,
          headers: Object.fromEntries(request.headers.entries()),
          body: await capturedBody(request),
        });
        return new URL(request.url).pathname === '/uninstall-journal/preflight/discard'
          ? json({ discarded: true })
          : successJournal();
      },
    };
    const port = createTestPort(fetcher);
    const cas = { expectedRevision: 7, attemptId: ATTEMPT, now: NOW };
    const initialization: InitializeUninstallJournalPortInput = {
      initialization: {
        schemaVersion: 1,
        now: NOW,
        recoverUntil: NOW + 60_000,
        installJournal: { fixture: 'complete-install-journal' },
        uninstallPlan: { fixture: 'reviewed-uninstall-plan' },
        uninstallCycleId: `uninstall-${'b'.repeat(24)}`,
        bindingHash: `sha256:${'c'.repeat(64)}`,
        freshPreflight: { fixture: 'fresh-preflight' },
      },
      approval: {
        attemptId: ATTEMPT,
        approvedAt: NOW - 1,
        authorizedTarget: { account: { id: 'account' }, zone: { id: 'zone' } },
      },
    };
    const appendApproval = {
      ...cas,
      approvedAt: NOW - 1,
      authorizedTarget: { account: { id: 'account' }, zone: { id: 'zone' } },
      candidatePlan: { fixture: 'recovery-equivalent-uninstall-plan' },
    };
    const lease = { ...cas, leaseExpiresAt: NOW + 30_000 };
    const refresh = { ...cas, preflight: { fixture: 'refreshed-preflight' } };
    const managementPreflight = { ...cas, preflight: { fixture: 'management-preflight' } };
    const managementDeleteAttempt = {
      ...cas,
      action: 'management_custom_domain_delete' as const,
      prerequisites: { fixture: 'management-delete-prerequisites' },
      intent: { fixture: 'management-delete-intent' },
    };
    const managementDeleteRecovery = {
      ...cas,
      action: 'management_custom_domain_delete' as const,
      evidence: { fixture: 'management-delete-recovery-evidence' },
    };
    const prepare = {
      ...cas,
      action: 'cleanup_worker_version_create' as const,
      record: { schemaVersion: 1, kind: 'uninstall_worker_version_create' },
    };
    const recovery = {
      ...cas,
      action: 'cleanup_worker_version_create' as const,
      recovery: { schemaVersion: 1, kind: 'uninstall_worker_version_recovery' },
    };
    const transition = { ...cas, action: 'cleanup_worker_version_create' as const };
    const transitionWithValue = { ...transition, value: { kind: 'uninstall_worker_version' } };
    const customerCycle = { ...cas, semantic: { schemaVersion: 1, requestId: 'request-id' } };
    const workersDev = { ...cas, enabled: true };
    const workersDevSubmission = {
      ...workersDev,
      locator: { enabled: true, previewsEnabled: false },
    };
    const workersDevNotApplied = {
      ...workersDev,
      locator: { enabled: false, previewsEnabled: false },
    };
    const customerSubmission = { ...cas, locator: { status: 'removed' } };

    const results = [
      await port.initialize(initialization),
      await port.read(),
      await port.appendApproval(appendApproval),
      await port.acquireLease(lease),
      await port.releaseLease(cas),
      await port.refreshPreflight(refresh),
      await port.appendManagementPreflight(managementPreflight),
      await port.appendManagementDeleteAttempt(managementDeleteAttempt),
      await port.recordManagementDeleteRecovery(managementDeleteRecovery),
      await port.prepareAction(prepare),
      await port.replacePreparedAction(prepare),
      await port.attachWorkerVersionRecovery(recovery),
      await port.armAction(transition),
      await port.recordActionSubmitted(transitionWithValue),
      await port.verifyAction(transitionWithValue),
      await port.appendCustomerRemoveCycle(customerCycle),
      await port.replacePreparedCustomerRemoveCycle(customerCycle),
      await port.prepareCustomerWorkersDevDisable(cas),
      await port.replacePreparedCustomerWorkersDevDisable(cas),
      await port.armCustomerWorkersDev(workersDev),
      await port.recordCustomerWorkersDevSubmitted(workersDevSubmission),
      await port.verifyCustomerWorkersDev(workersDev),
      await port.recordCustomerWorkersDevNotApplied(workersDevNotApplied),
      await port.armCustomerRemoveRequest(cas),
      await port.recordCustomerRemoveRequestSubmitted(customerSubmission),
      await port.verifyCustomerRemoveRequest(cas),
    ];
    const discarded = await port.discardPreflight(cas);

    expect(results.every(Object.isFrozen)).toBe(true);
    expect(Object.isFrozen(discarded)).toBe(true);
    expect(discarded).toEqual({ discarded: true });
    expect(journalParser).toHaveBeenCalledTimes(results.length);
    expect(calls).toEqual([
      call('POST', '/uninstall-journal/initialize', initialization),
      call('GET', '/uninstall-journal', null),
      call('POST', '/uninstall-journal/approval/append', appendApproval),
      call('POST', '/uninstall-journal/lease/acquire', lease),
      call('POST', '/uninstall-journal/lease/release', cas),
      call('POST', '/uninstall-journal/preflight/refresh', refresh),
      call('POST', '/uninstall-journal/management-preflight/append', managementPreflight),
      call('POST', '/uninstall-journal/management-delete/attempt/append', managementDeleteAttempt),
      call('POST', '/uninstall-journal/management-delete/recovery', managementDeleteRecovery),
      call('POST', '/uninstall-journal/action/prepare', prepare),
      call('POST', '/uninstall-journal/action/replace', prepare),
      call('POST', '/uninstall-journal/action/version-recovery/attach', recovery),
      call('POST', '/uninstall-journal/action/arm', transition),
      call('POST', '/uninstall-journal/action/submitted', transitionWithValue),
      call('POST', '/uninstall-journal/action/verified', transitionWithValue),
      call('POST', '/uninstall-journal/customer-remove/cycle/append', customerCycle),
      call('POST', '/uninstall-journal/customer-remove/cycle/replace', customerCycle),
      call('POST', '/uninstall-journal/customer-remove/workers-dev/disable/prepare', cas),
      call('POST', '/uninstall-journal/customer-remove/workers-dev/disable/replace', cas),
      call('POST', '/uninstall-journal/customer-remove/workers-dev/arm', workersDev),
      call('POST', '/uninstall-journal/customer-remove/workers-dev/submitted', workersDevSubmission),
      call('POST', '/uninstall-journal/customer-remove/workers-dev/verified', workersDev),
      call('POST', '/uninstall-journal/customer-remove/workers-dev/not-applied', workersDevNotApplied),
      call('POST', '/uninstall-journal/customer-remove/request/arm', cas),
      call('POST', '/uninstall-journal/customer-remove/request/submitted', customerSubmission),
      call('POST', '/uninstall-journal/customer-remove/request/verified', cas),
      call('POST', '/uninstall-journal/preflight/discard', cas),
    ]);
  });

  it('rejects credential-shaped and unserializable request bodies before transport', async () => {
    let calls = 0;
    const port = createTestPort({
      fetch: async () => {
        calls += 1;
        return successJournal();
      },
    });

    await expect(port.prepareAction({
      expectedRevision: 0,
      attemptId: ATTEMPT,
      now: NOW,
      action: 'cleanup_worker_version_create',
      record: { nested: { cloudflareAccessToken: 'must-not-cross-port' } },
    })).rejects.toMatchObject({ status: 400, code: 'bad_request', message: 'bad_request' });

    await expect(port.appendManagementDeleteAttempt({
      expectedRevision: 0,
      attemptId: ATTEMPT,
      now: NOW,
      action: 'management_custom_domain_delete',
      prerequisites: { fixture: 'prerequisites' },
      intent: { nested: { cloudflareAccessToken: 'must-not-cross-management-attempt' } },
    })).rejects.toMatchObject({ status: 400, code: 'bad_request', message: 'bad_request' });

    await expect(port.recordManagementDeleteRecovery({
      expectedRevision: 0,
      attemptId: ATTEMPT,
      now: NOW,
      action: 'management_admin_policy_delete',
      evidence: { cloudflareAccessToken: 'must-not-cross-management-recovery' },
    })).rejects.toMatchObject({ status: 400, code: 'bad_request', message: 'bad_request' });

    await expect(port.replacePreparedCustomerRemoveCycle({
      expectedRevision: 0,
      attemptId: ATTEMPT,
      now: NOW,
      semantic: { nested: { clientSecret: 'must-not-cross-customer-replacement' } },
    })).rejects.toMatchObject({ status: 400, code: 'bad_request', message: 'bad_request' });

    await expect(port.recordCustomerWorkersDevNotApplied({
      expectedRevision: 0,
      attemptId: ATTEMPT,
      now: NOW,
      enabled: true,
      locator: { enabled: false, previewsEnabled: false, cloudflareAccessToken: 'must-not-cross-recovery' },
    })).rejects.toMatchObject({ status: 400, code: 'bad_request', message: 'bad_request' });

    const cyclic: CyclicFixture = {};
    cyclic.self = cyclic;
    await expect(port.refreshPreflight({
      expectedRevision: 0,
      attemptId: ATTEMPT,
      now: NOW,
      preflight: cyclic,
    })).rejects.toMatchObject({ status: 400, code: 'bad_request', message: 'bad_request' });

    await expect(port.appendCustomerRemoveCycle({
      expectedRevision: 0,
      attemptId: ATTEMPT,
      now: NOW,
      semantic: { unsafe: 1n },
    })).rejects.toMatchObject({ status: 400, code: 'bad_request', message: 'bad_request' });

    await expect(port.prepareAction({
      expectedRevision: 0,
      attemptId: ATTEMPT,
      now: NOW,
      action: 'cleanup_worker_version_create',
      record: {
        toJSON: () => ({ cloudflareAccessToken: 'must-not-cross-port-after-serialization' }),
      },
    })).rejects.toMatchObject({ status: 400, code: 'bad_request', message: 'bad_request' });
    expect(calls).toBe(0);
  });

  it('bounds streaming JSON and rejects malformed media, bytes, lengths, shapes, and journals', async () => {
    const overLimit = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(4 * 1024 * 1024));
        controller.enqueue(new Uint8Array([0x20]));
        controller.close();
      },
    });
    const brokenStream = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.error(new Error('provider transport detail must not escape'));
      },
    });
    const cases: Response[] = [
      new Response('not json', { headers: { 'content-type': 'text/plain' } }),
      new Response('{}', { headers: { 'content-type': 'application/json-evil' } }),
      new Response('{', { headers: { 'content-type': 'application/json' } }),
      new Response(new Uint8Array([0xff]), { headers: { 'content-type': 'application/json' } }),
      new Response(null, { status: 204, headers: { 'content-type': 'application/json' } }),
      json({}, 200, { 'content-length': String(4 * 1024 * 1024 + 1) }),
      json({}, 200, { 'content-length': '+2' }),
      json({}, 200, { 'content-length': '02' }),
      new Response(overLimit, { headers: { 'content-type': 'application/json' } }),
      new Response(brokenStream, { headers: { 'content-type': 'application/json' } }),
      json({}),
      json({ journal: VALID_WIRE_JOURNAL, extra: true }),
      json({ journal: { schemaVersion: 1, fixture: 'invalid' } }),
      json({ journal: VALID_WIRE_JOURNAL, cloudflareAccessToken: 'must-not-enter-port' }),
    ];

    for (const response of cases) {
      const port = createTestPort({ fetch: async () => response.clone() });
      await expect(port.read()).rejects.toMatchObject({
        status: 500,
        code: 'session_invalid',
        message: 'session_invalid',
      });
    }
  });

  it('accepts only exact stable error envelopes and never propagates transport or provider values', async () => {
    const cases: Array<{
      readonly response: Response;
      readonly expected: { readonly status: number; readonly code: string; readonly message: string };
    }> = [
      {
        response: json({ error: { code: 'session_conflict' } }, 409),
        expected: { status: 409, code: 'session_conflict', message: 'session_conflict' },
      },
      {
        response: json({ error: { code: 'provider-secret-message' } }, 502),
        expected: { status: 502, code: 'session_invalid', message: 'session_invalid' },
      },
      {
        response: json({ error: { code: 'session_conflict', detail: 'provider detail' } }, 409),
        expected: { status: 409, code: 'session_invalid', message: 'session_invalid' },
      },
      {
        response: json({ error: { code: 'session_conflict' }, extra: true }, 409),
        expected: { status: 409, code: 'session_invalid', message: 'session_invalid' },
      },
      {
        response: json({ error: { code: 'session_conflict' }, cloudflareAccessToken: 'secret' }, 409),
        expected: { status: 500, code: 'session_invalid', message: 'session_invalid' },
      },
    ];

    for (const testCase of cases) {
      const port = createTestPort({ fetch: async () => testCase.response.clone() });
      await expect(port.read()).rejects.toMatchObject(testCase.expected);
    }

    const port = createTestPort({
      fetch: async () => { throw new Error('provider response contained bearer value'); },
    });
    await expect(port.read()).rejects.toMatchObject({
      status: 500,
      code: 'session_invalid',
      message: 'session_invalid',
    });
  });

  it('requires the one exact preflight-discard acknowledgement on every successful status', async () => {
    const cas = { expectedRevision: 1, attemptId: ATTEMPT, now: NOW };
    const invalidBodies = [
      {},
      { discarded: false },
      { discarded: true, extra: true },
      { journal: VALID_WIRE_JOURNAL },
    ];
    for (const invalidBody of invalidBodies) {
      const port = createTestPort({ fetch: async () => json(invalidBody, 201) });
      await expect(port.discardPreflight(cas)).rejects.toMatchObject({
        status: 500,
        code: 'session_invalid',
      });
    }

    const statusError = createTestPort({
      fetch: async () => json({ error: { code: 'session_conflict' } }, 409),
    });
    await expect(statusError.discardPreflight(cas)).rejects.toMatchObject({
      status: 409,
      code: 'session_conflict',
    });
  });
});

function call<Body>(method: 'GET' | 'POST', path: string, body: Body): ExpectedCall<Body> {
  return {
    origin: 'https://gateway-deploy-session.internal',
    method,
    path,
    headers: method === 'GET' ? {} : { 'content-type': 'application/json' },
    body,
  };
}
