import type { AuthorizedTarget } from '../src/cloudflare-target';
import { deriveCustomerGatewayExpectedProjection } from '../src/customer-bootstrap-request';
import { sha256Hex } from '../src/crypto';
import {
  computeInstallJournalBindingHash,
  createInstallJournal,
  type CreateInstallJournalInput,
  type InstallJournal,
} from '../src/install-journal';
import {
  createInstallJournalPort,
  type InstallJournalFetcher,
} from '../src/install-journal-port';
import { buildStaticDeployPlan, parseDeploySelection } from '../src/schema';
import { manifest, NOW, selectionInput } from './fixtures';

const ATTEMPT = `att_${'a'.repeat(32)}`;
const TARGET: AuthorizedTarget = Object.freeze({
  actor: Object.freeze({ id: 'actor-test', email: 'owner@example.com' }),
  account: Object.freeze({ id: '1'.repeat(32), name: 'Example account' }),
  zone: Object.freeze({ id: '2'.repeat(32), name: 'example.com', status: 'active' }),
});

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (!isRecord(value)) throw new TypeError('canonical');
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

async function journalFixture(): Promise<{
  initialization: CreateInstallJournalInput;
  journal: InstallJournal;
}> {
  const selection = parseDeploySelection(selectionInput);
  const plan = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
  const projection = await deriveCustomerGatewayExpectedProjection({
    selection,
    target: TARGET,
    plan,
    release: { id: manifest.release, artifactSha256: manifest.artifact.treeSha256 },
  });
  const releasePin = {
    verification: 'ed25519' as const,
    keyId: 'test-key',
    release: manifest.release,
    artifactSha256: manifest.artifact.treeSha256,
  };
  const installationId = projection.expected.installationId;
  const bindingHash = await computeInstallJournalBindingHash({
    selection, plan, releasePin, target: TARGET, installationId,
  });
  const checkedAt = NOW + 4;
  const unsigned = {
    schemaVersion: 1 as const,
    kind: 'customer_gateway_fresh_preflight' as const,
    accountId: TARGET.account.id,
    zoneId: TARGET.zone.id,
    planId: plan.planId,
    planHash: plan.planHash,
    installationId,
    configurationHash: projection.expected.configurationHash,
    desiredHash: projection.expected.desiredHash,
    releaseId: manifest.release,
    releaseArtifactSha256: manifest.artifact.treeSha256,
    zeroCandidateKinds: projection.resourceKinds,
    checkedAt,
    expiresAt: checkedAt + 30_000,
  };
  const initialization: CreateInstallJournalInput = {
    schemaVersion: 1,
    now: NOW + 5,
    recoverUntil: NOW + 1_800_000 + 24 * 60 * 60 * 1_000,
    selection,
    plan,
    releasePin,
    target: TARGET,
    installationId,
    bindingHash,
    gatewayFreshPreflight: {
      ...unsigned,
      attestationHash: `sha256:${await sha256Hex(canonicalJson(unsigned))}`,
    },
  };
  return {
    initialization,
    journal: await createInstallJournal(
      initialization,
      selection,
      plan,
      NOW + 1_800_000,
      { attemptId: ATTEMPT, approvedAt: NOW + 3 },
    ),
  };
}

function json(value: unknown, status = 200, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
  });
}

describe('typed install journal port', () => {
  it('uses only the exact internal routes, methods, and bodies and reparses every returned journal', async () => {
    const fixture = await journalFixture();
    const calls: Array<{ method: string; path: string; body: unknown }> = [];
    const fetcher: InstallJournalFetcher = {
      fetch: async (request) => {
        calls.push({
          method: request.method,
          path: new URL(request.url).pathname,
          body: request.method === 'GET' ? null : await request.json(),
        });
        return json({ journal: fixture.journal });
      },
    };
    const port = createInstallJournalPort(fetcher);
    const cas = { expectedRevision: 0, attemptId: ATTEMPT, now: NOW + 6 };
    const transition = { ...cas, action: 'worker_create' as const };
    const results = [
      await port.initialize(fixture.initialization),
      await port.read(),
      await port.appendApproval(cas),
      await port.acquireLease({ ...cas, leaseExpiresAt: NOW + 10_000 }),
      await port.releaseLease(cas),
      await port.prepareAction({ ...transition, record: { schemaVersion: 1, kind: 'worker_create' } }),
      await port.armAction(transition),
      await port.recordSubmitted({ ...transition, locator: { kind: 'worker' } }),
      await port.verifyAction(transition),
      await port.appendCustomerBootstrapCycle({ ...cas, attempt: { requestId: 'r'.repeat(22) } }),
    ];
    expect(results.every(Object.isFrozen)).toBe(true);
    expect(calls).toEqual([
      { method: 'POST', path: '/install-journal/initialize', body: fixture.initialization },
      { method: 'GET', path: '/install-journal', body: null },
      { method: 'POST', path: '/install-journal/approval/append', body: cas },
      { method: 'POST', path: '/install-journal/lease/acquire', body: { ...cas, leaseExpiresAt: NOW + 10_000 } },
      { method: 'POST', path: '/install-journal/lease/release', body: cas },
      { method: 'POST', path: '/install-journal/action/prepare', body: { ...transition, record: { schemaVersion: 1, kind: 'worker_create' } } },
      { method: 'POST', path: '/install-journal/action/arm', body: transition },
      { method: 'POST', path: '/install-journal/action/submitted', body: { ...transition, locator: { kind: 'worker' } } },
      { method: 'POST', path: '/install-journal/action/verified', body: transition },
      { method: 'POST', path: '/install-journal/customer-bootstrap/attempt/append', body: { ...cas, attempt: { requestId: 'r'.repeat(22) } } },
    ]);
  });

  it('rejects credential-shaped inputs before transport', async () => {
    let calls = 0;
    const port = createInstallJournalPort({
      fetch: async () => {
        calls += 1;
        return json({});
      },
    });
    await expect(port.prepareAction({
      expectedRevision: 0,
      attemptId: ATTEMPT,
      now: NOW,
      action: 'worker_create',
      record: { cloudflareAccessToken: 'must-not-cross-port' },
    })).rejects.toMatchObject({
      status: 400,
      code: 'bad_request',
      reason: 'journal_body_rejected_at_record_cloudflareaccesstoken',
    });
    expect(calls).toBe(0);
  });

  it('bounds and exact-validates internal responses and preserves stable error codes', async () => {
    const fixture = await journalFixture();
    const cases: Array<{ response: Response; expected: { status: number; code: string } }> = [
      {
        response: new Response('not json', { headers: { 'content-type': 'text/plain' } }),
        expected: { status: 500, code: 'session_invalid' },
      },
      {
        response: new Response('{', { headers: { 'content-type': 'application/json' } }),
        expected: { status: 500, code: 'session_invalid' },
      },
      {
        response: json({}, 200, { 'content-length': String(4 * 1024 * 1024 + 1) }),
        expected: { status: 500, code: 'session_invalid' },
      },
      {
        response: json({ error: { code: 'session_conflict' } }, 409),
        expected: { status: 409, code: 'session_conflict' },
      },
      {
        response: json({ error: { code: 'provider-secret-message' } }, 502),
        expected: { status: 502, code: 'session_invalid' },
      },
      {
        response: json({ journal: fixture.journal, extra: true }),
        expected: { status: 500, code: 'session_invalid' },
      },
      {
        response: json({ journal: { ...fixture.journal, bindingHash: `sha256:${'0'.repeat(64)}` } }),
        expected: { status: 500, code: 'session_invalid' },
      },
    ];
    for (const testCase of cases) {
      const port = createInstallJournalPort({ fetch: async () => testCase.response.clone() });
      await expect(port.read()).rejects.toMatchObject(testCase.expected);
    }
  });
});
