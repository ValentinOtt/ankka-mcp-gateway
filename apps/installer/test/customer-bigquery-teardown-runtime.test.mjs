import { createHmac } from 'node:crypto';
import { AdminState } from '../../../payload/worker/index.js';
import { ACCOUNT_ID, ZONE_ID, canonicalJson, installReadyGateway, portalOnlyClaim, prefixedSha256, withProviderFetch } from '../../../test/payload-lifecycle.mjs';
import accessDeleteEvidence from '../../../test/fixtures/cloudflare-access-delete-accepted.json' with { type: 'json' };
import { createBigQuerySetup } from '../src/customer-bigquery-setup';
import { createBigQueryTeardown } from '../src/customer-bigquery-teardown';
import { fixture as bridgeFixture, grant } from './bigquery-teardown-fixture.mjs';

const ACTIONS = 'ankka-mcp-gateway/source-actions/v1';
const SOURCES = 'ankka-mcp-gateway/management-sources/v1';
const TEARDOWNS = 'ankka-mcp-gateway/teardown-actions/v1';
const origin = 'https://admin-state.invalid';

function acceptedAccessDelete(pathname) {
  const observed = accessDeleteEvidence[pathname.includes('/policies/') ? 'accessPolicy' : 'accessApplication'].delete;
  const body = structuredClone(observed.body);
  body.result.id = decodeURIComponent(pathname.split('/').at(-1));
  return Response.json(body, { status: observed.status });
}

async function fixture(run, { stopAfter, knownPending = false, portalPending = false, lostDelete = -1, count = 1 } = {}) {
  const gateway = await installReadyGateway({ claimInput: await portalOnlyClaim() });
  const portalApplicationId = gateway.readyReceipt.resources.find((resource) => resource.kind === 'portal_access_application').provider.id;
  const accessDeleteResponses = [];
  async function accessDeletionResponse(request, response) {
    const pathname = new URL(request.url).pathname;
    if (request.method !== 'DELETE' || !pathname.includes('/access/apps/') || response.status !== 200) return response;
    await response.body?.cancel();
    // The disposable live provider probe returned this 202 envelope for
    // Access policy and application DELETE, followed by GET 404.
    const accepted = acceptedAccessDelete(pathname);
    accessDeleteResponses.push({ status: accepted.status, kind: pathname.includes('/policies/') ? 'policy' : 'application' });
    return accepted;
  }
  const storage = gateway.objects.get('v1:management').storage;
  const context = { accountId: ACCOUNT_ID, zoneId: ZONE_ID, installationId: gateway.readyReceipt.installationId,
    accessIssuer: gateway.env.CF_ACCESS_ISSUER, zoneName: 'example.com' };
  const bridges = [];
  for (let index = 0; index < count; index++) bridges.push(await bridgeFixture({ fixtureContext: context, lostDelete, journalStorage: storage, index }));
  const bridge = bridges[0];
  const bridgeAbsences = new Map(bridges.map((item) => [item, new Set()]));
  const instances = new Map();
  const invocationStack = [];
  const invocationCounts = [];
  const network = async (request) => {
    if (invocationStack.length > 0) invocationStack.at(-1).count++;
    const url = new URL(request.url);
    const endpoint = bridges.find((item) => item.record.hostname === url.hostname);
    if (endpoint) {
      return new Response(null, { status: 401, headers: {
        'WWW-Authenticate': `Bearer resource_metadata="https://${endpoint.record.hostname}/.well-known/oauth-protected-resource"`,
      } });
    }
    if (url.pathname === `/client/v4/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/servers` && request.method === 'GET') {
      return Response.json({ success: true, result: [...gateway.provider.state.servers.values()] });
    }
    if (url.pathname === `/client/v4/accounts/${ACCOUNT_ID}/workers/domains`) {
      return Response.json({ success: true, result: bridges.flatMap((item) => item.provider.domain ? [item.provider.domain] : []) });
    }
    const target = bridges.find((item) => url.pathname.includes(`/workers/scripts/${item.record.workerName}`) ||
      url.pathname.endsWith(`/workers/domains/${item.record.domainId}`) || url.pathname.endsWith(`/access/apps/${item.record.application.id}`));
    if (target) {
      const confirmed = bridgeAbsences.get(target);
      if (request.method === 'DELETE' && url.pathname.endsWith(`/access/apps/${target.record.application.id}`)) {
        expect(confirmed).toEqual(new Set(['domain', 'worker']));
      }
      const response = await target.fetch(request.url, { method: request.method, headers: request.headers });
      if (request.method === 'GET' && response.status === 404) {
        if (url.pathname.endsWith(`/workers/domains/${target.record.domainId}`)) confirmed.add('domain');
        if (url.pathname.endsWith(`/workers/scripts/${target.record.workerName}/settings`)) confirmed.add('worker');
      }
      return accessDeletionResponse(request, response);
    }
    const response = await gateway.provider.fetch(request);
    return accessDeletionResponse(request, response);
  };
  gateway.env.ADMIN_STATE = { idFromName: (name) => name, get(name) {
    if (!instances.has(name)) {
      const state = { storage: gateway.objects.get(name).storage };
      instances.set(name, new AdminState(state, gateway.env,
        createBigQueryTeardown(context, { storage: state.storage, fetch: (input, init) => network(new Request(input, init)) })));
    }
    return { async fetch(request) {
      const invocation = { name, count: 0 };
      invocationStack.push(invocation);
      try { return await instances.get(name).fetch(request); }
      finally {
        invocationStack.pop(); invocationCounts.push(invocation);
        expect(invocation.count, name).toBeLessThanOrEqual(50);
      }
    } };
  } };
  const runtime = gateway.env.ADMIN_STATE.get('v1:management');
  const request = (path, body) => new Request(origin + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: canonicalJson(body) });
  const setup = createBigQuerySetup({ ...context, managementOrigin: 'https://manage.example.com', workerName: 'ankka-gateway-test',
    workersSubdomain: 'tenant', controlPlaneOrigin: 'https://deploy.ankka.ai',
    releaseIdentity: { schemaVersion: 1, channel: 'stable', controlPlaneOrigin: 'https://deploy.ankka.ai', release: gateway.env.ANKKA_GATEWAY_RELEASE,
      keyId: 'test-release-key', publicKey: 'A'.repeat(43), artifactSha256: '9'.repeat(64) },
  }, { storage, runtime: runtime.fetch, fetch: (input, init) => network(new Request(input, init)), runtimeSource: 'export default {}' });
  let claim;
  async function prepareBridge(item) {
    const prepared = await setup.prepare(request('/api/bigquery', { schemaVersion: 1, revision: storage.snapshot(SOURCES).revision,
      label: 'BigQuery', configuration: item.record.configuration, readOnlyConfirmed: true }), 'admin@example.com', false);
    expect(prepared.status).toBe(200);
    claim = JSON.parse(Buffer.from(new URL((await prepared.json()).handoffUrl).hash.slice(1), 'base64url').toString());
    const generated = await storage.get(item.key);
    await storage.put(item.key, { ...item.record, actionId: claim.actionId, sourceHash: generated.sourceHash });
  }
  async function signed(path, value, key, header) {
    const body = canonicalJson(value);
    return runtime.fetch(new Request(origin + path, { method: 'POST', headers: { 'content-type': 'application/json',
      [header]: `sha256=${createHmac('sha256', Buffer.from(key, 'base64url')).update(body).digest('hex')}` }, body }));
  }
  async function sourceCommand(path, extra = {}) {
    return signed('/source-actions/' + path, { schemaVersion: 1, actionId: claim.actionId, actionKey: claim.actionKey,
      actorEmail: claim.actorEmail, accountId: claim.accountId, issuedAt: Date.now(), expiresAt: claim.expiresAt,
      cloudflareAccessToken: grant.accessToken, ...extra }, claim.actionKey, 'x-ankka-source-action-signature');
  }
  let stop = true;
  gateway.provider.intercept(({ record }) => {
    const action = storage.snapshot(ACTIONS)?.actions[0];
    if (stop && record.method === 'GET' && action && ((stopAfter !== undefined && action.resources.length >= stopAfter) ||
        (knownPending && action.pending?.provider !== null && action.pending?.provider !== undefined) ||
        (portalPending && action.portalUpdate?.phase === 'submitted'))) {
      stop = false;
      return Response.json({ success: false, result: null }, { status: 403 });
    }
  });
  async function teardown(seed = 't') {
    let applyPasses = 0;
    const key = Buffer.alloc(32, seed.charCodeAt(0)).toString('base64url');
    const issuedAt = Date.now();
    const proposal = { schemaVersion: 1, actionId: `action_${seed.repeat(32)}`, actionKeyHash: await prefixedSha256(key),
      actorEmail: claim.actorEmail, installationId: context.installationId, issuedAt, expiresAt: issuedAt + 600_000 };
    const prepared = await runtime.fetch(request('/teardown-actions/prepare-current', proposal));
    return { prepared, applyPasses: () => applyPasses, async send(command, requestId = 'u'.repeat(22)) {
      const body = { schemaVersion: 1, command, actionId: proposal.actionId, actionKey: key, actorEmail: claim.actorEmail,
        accountId: ACCOUNT_ID, installationId: context.installationId, issuedAt: Date.now(), expiresAt: proposal.expiresAt };
      if (command === 'apply') Object.assign(body, { requestId, cloudflareAccessToken: grant.accessToken });
      const seen = new Set();
      for (let pass = 0; pass < 768; pass++) {
        if (command === 'apply') applyPasses++;
        const response = await signed(`/teardown-actions/${command}-current`, body, key, 'x-ankka-teardown-action-signature');
        const result = await response.clone().json();
        if (result.status !== 'removing') return response;
        expect(seen.has(result.progress)).toBe(false);
        seen.add(result.progress);
      }
      throw new Error('teardown made too many passes');
    } };
  }
  await withProviderFetch(network, async () => {
    let action;
    for (const item of bridges) {
      await prepareBridge(item);
    expect((await sourceCommand('bigquery', { bigqueryPhase: 'start' })).status).toBe(200);
    const applied = await sourceCommand('apply');
    action = storage.snapshot(ACTIONS).actions.find((candidate) => candidate.actionId === claim.actionId);
    const expected = stopAfter !== undefined && stopAfter < 3 ? 'failed' :
      stopAfter !== undefined || knownPending || portalPending ? 'recovery_required' : 'succeeded';
    expect(action.status, await applied.clone().text()).toBe(expected);
    if (action.status === 'succeeded') expect(applied.status).toBe(200);
    }
    await run({ ...gateway, storage, bridge, bridges, runtime, teardown, invocationCounts, sourceAction: action,
      portalApplicationId, accessDeleteResponses });
  });
}

describe('BigQuery cleanup in the gateway dependency-removal phase', () => {
  it('accepts observed Access DELETE 202 responses only after verifying every resource is absent', async () => fixture(async (test) => {
    const sourceApplication = [...test.provider.state.apps.values()].find((app) => app.type === 'mcp');
    const sourcePolicy = test.provider.state.policies.get(sourceApplication.id)[0];
    Object.assign(sourcePolicy, { decision: 'allow', include: [{ email: { email: 'admin@example.com' } }], exclude: [], require: [] });
    const foreignApplication = { id: 'unrelated-app', type: 'self_hosted', domain: 'unrelated.example.com', name: 'Unrelated' };
    const foreignPolicies = [{ id: 'unrelated-policy', name: 'Unrelated policy', decision: 'allow', include: [{ everyone: {} }] }];
    test.provider.state.apps.set(foreignApplication.id, structuredClone(foreignApplication));
    test.provider.state.policies.set(foreignApplication.id, structuredClone(foreignPolicies));
    const action = await test.teardown();
    expect(action.prepared.status).toBe(200);
    const response = await action.send('apply');
    expect(response.status, await response.clone().text()).toBe(200);
    expect(await response.json()).toMatchObject({ status: 'gateway_removed', removedResourceCount: 10 });
    expect(test.accessDeleteResponses).toHaveLength(5);
    expect(test.accessDeleteResponses.filter(({ kind }) => kind === 'policy')).toHaveLength(2);
    expect(test.accessDeleteResponses.every(({ status }) => status === 202)).toBe(true);
    expect(test.provider.liveResourceCount()).toBe(2);
    expect(test.provider.state.apps.get(foreignApplication.id)).toEqual(foreignApplication);
    expect(test.provider.state.policies.get(foreignApplication.id)).toEqual(foreignPolicies);
    expect(test.bridge.deletions).toEqual(['domain', 'settings', 'app']);
  }));
  it('requires confirmed absence after Access DELETE 202 and fresh consent before retrying a still-present policy', async () => fixture(async (test) => {
    test.provider.intercept(({ record }) => {
      if (record.method === 'DELETE' && record.pathname.includes(`/access/apps/${test.portalApplicationId}/policies/`)) {
        return acceptedAccessDelete(record.pathname);
      }
    });
    const first = await test.teardown();
    expect(first.prepared.status).toBe(200);
    const interrupted = await first.send('apply');
    expect(interrupted.status).toBe(409);
    expect(await interrupted.json()).toMatchObject({ failure: {
      phase: 'root_verify', resourceKind: 'portal_access_policy', category: 'absence_unconfirmed',
    } });
    const root = test.objects.get(`v1:${test.readyReceipt.installationId}`).storage.snapshot();
    expect(root.teardown.pending).toMatchObject({ phase: 'submitted' });
    expect(test.provider.state.policies.get(test.portalApplicationId)).toHaveLength(1);
    expect(test.bridge.deletions).toEqual([]);
    const before = test.provider.deletes().length;
    const repeated = await first.send('apply');
    expect(repeated.status).toBe(409);
    expect(test.provider.deletes()).toHaveLength(before);
    expect((await first.send('settle')).status).toBe(200);
    test.provider.intercept(undefined);
    const fresh = await test.teardown('v');
    expect(fresh.prepared.status).toBe(200);
    const response = await fresh.send('apply', 'w'.repeat(22));
    expect(response.status, await response.clone().text()).toBe(200);
    expect(test.provider.liveResourceCount()).toBe(0);
    expect(test.bridge.deletions).toEqual(['domain', 'settings', 'app']);
  }));
  it('resumes the v0.1.59 journal after two accepted Access deletions were classified as not applied', async () => fixture(async (test) => {
    const previous = await test.teardown();
    expect(previous.prepared.status).toBe(200);
    const proof = await previous.send('prove');
    expect(proof.status).toBe(200);
    const { authority } = await proof.json();
    const resources = [...authority.root.receipt.resources].reverse().concat(
      [...authority.control.sourceOwnership[0].resources].reverse(),
    );
    expect(resources.slice(0, 4).map((resource) => resource.kind)).toEqual([
      'dns_record', 'portal_access_policy', 'portal_access_application', 'portal',
    ]);
    const resourceKey = (resource) => `${resource.kind}\u0000${resource.provider.parentId ?? ''}\u0000${resource.provider.id}`;
    const resourcesHash = await prefixedSha256({ schemaVersion: 1, resources, control: authority.control,
      sources: authority.sources, policyMode: 'receipt_owned' });
    const rootStorage = test.objects.get(`v1:${test.readyReceipt.installationId}`).storage;
    // v0.1.59 durably called each 202 "not_applied" despite completed provider
    // deletion. The second consent recorded policy absence, then stopped at app.
    await rootStorage.put('ankka-mcp-gateway/uninstall-state/v1', {
      schemaVersion: 1, status: 'tearing_down', installationId: test.readyReceipt.installationId,
      receipt: authority.root.receipt, teardown: {
        schemaVersion: 1, installationId: test.readyReceipt.installationId, resourcesHash,
        status: 'applying', removedKeys: resources.slice(0, 2).map(resourceKey),
        pending: { key: resourceKey(resources[2]), requestId: 'u'.repeat(22), phase: 'not_applied' }, removedAt: null,
      },
    });
    test.provider.state.dns = null;
    test.provider.state.policies.delete(test.portalApplicationId);
    test.provider.state.apps.delete(test.portalApplicationId);
    expect(test.provider.state.portal).not.toBeNull();
    expect(test.provider.state.servers.size).toBe(1);
    expect(test.bridge.provider.app).not.toBeNull();
    expect((await previous.send('settle')).status).toBe(200);
    const fresh = await test.teardown('v');
    expect(fresh.prepared.status).toBe(200);
    const response = await fresh.send('apply', 'w'.repeat(22));
    expect(response.status, await response.clone().text()).toBe(200);
    expect(rootStorage.snapshot().teardown.resourcesHash).toBe(resourcesHash);
    expect(test.provider.liveResourceCount()).toBe(0);
    expect(test.bridge.deletions).toEqual(['domain', 'settings', 'app']);
  }));
  it('preserves the Portal and its Access app when an unrelated attached policy appears after preflight', async () => fixture(async (test) => {
    const foreignPolicy = { id: 'unrelated-policy', name: 'Unrelated policy', decision: 'allow', include: [{ everyone: {} }] };
    test.provider.intercept(({ record, state }) => {
      if (record.method === 'DELETE' && record.pathname.includes('/dns_records/')) {
        state.policies.get(test.portalApplicationId).push(structuredClone(foreignPolicy));
      }
    });
    const action = await test.teardown();
    expect(action.prepared.status).toBe(200);
    const response = await action.send('apply');
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ failure: {
      phase: 'root_remove', resourceKind: 'portal_access_application', category: 'ownership_mismatch',
    } });
    expect(test.provider.deletes()).toHaveLength(2);
    expect(test.provider.state.portal).not.toBeNull();
    expect(test.provider.state.apps.has(test.portalApplicationId)).toBe(true);
    expect(test.provider.state.policies.get(test.portalApplicationId)).toContainEqual(foreignPolicy);
    expect(test.bridge.deletions).toEqual([]);
  }));
  for (const count of [2, 32]) it(`removes ${count} bridges and their ordinary sources within each invocation budget`, async () => {
    await fixture(async (test) => {
      const action = await test.teardown();
      expect(action.prepared.status).toBe(200);
      const before = test.invocationCounts.length;
      const response = await action.send('apply');
      expect(response.status, await response.clone().text()).toBe(200);
      expect(await response.json()).toMatchObject({ status: 'gateway_removed', removedResourceCount: 4 + 6 * count });
      expect(test.provider.liveResourceCount()).toBe(0);
      for (const bridge of test.bridges) expect(bridge.deletions).toEqual(['domain', 'settings', 'app']);
      const invocations = test.invocationCounts.slice(before);
      expect(invocations.reduce((sum, value) => sum + value.count, 0)).toBeGreaterThan(50);
      expect(Math.max(...invocations.map((value) => value.count))).toBeLessThanOrEqual(40);
      expect(action.applyPasses()).toBeLessThanOrEqual(768);
      console.info('bounded teardown', { sources: count, callbackPasses: action.applyPasses(),
        maxExternalCalls: Math.max(...invocations.map((value) => value.count)) });
    }, { count });
  }, 60_000);
  for (const shared of [false, true]) it(`checks paginated foreign Portal mappings in bounded passes${shared ? ' and refuses a late shared source' : ''}`, async () => fixture(async (test) => {
    const serverId = [...test.provider.state.servers.keys()][0];
    const foreign = Array.from({ length: 205 }, (_, index) => ({ id: `foreign-${index}` }));
    const path = `/client/v4/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/portals`;
    test.provider.intercept(({ record, state }) => {
      if (record.method !== 'GET') return;
      if (record.pathname === path) {
        const page = Number(new URLSearchParams(record.search).get('page'));
        const all = [...(state.portal ? [state.portal] : []), ...foreign];
        return Response.json({ success: true, result: all.slice((page - 1) * 100, page * 100) });
      }
      const id = record.pathname.slice(path.length + 1);
      if (foreign.some((portal) => portal.id === id)) return Response.json({ success: true,
        result: { id, servers: shared && id === 'foreign-204' ? [{ server_id: serverId }] : [] } });
    });
    const action = await test.teardown();
    expect(action.prepared.status).toBe(200);
    const before = test.invocationCounts.length;
    const response = await action.send('apply');
    expect(response.status, await response.clone().text()).toBe(shared ? 409 : 200);
    if (shared) { expect(test.provider.deletes()).toEqual([]); expect(test.bridge.deletions).toEqual([]); }
    else expect(test.bridge.deletions).toEqual(['domain', 'settings', 'app']);
    expect(Math.max(...test.invocationCounts.slice(before).map((value) => value.count))).toBeLessThanOrEqual(40);
  }));
  for (const applied of [false, true]) for (let lostDelete = 0; lostDelete < 7; lostDelete++) {
    it(`recovers bounded ordinary-source deletion ${lostDelete + 1} after a ${applied ? 'completed' : 'unapplied'} lost response`, async () => fixture(async (test) => {
      let deletes = 0;
      test.provider.intercept(({ record, state }) => {
        if (record.method !== 'DELETE' || deletes++ !== lostDelete) return;
        if (applied) {
          const path = record.pathname, id = path.split('/').at(-1);
          if (path.includes('/dns_records/')) state.dns = null;
          else if (path.includes('/mcp/portals/')) state.portal = null;
          else if (path.includes('/mcp/servers/')) { state.servers.delete(id); state.server = null; }
          else if (path.includes('/policies/')) {
            const parent = path.split('/').at(-3);
            state.policies.set(parent, state.policies.get(parent).filter((policy) => policy.id !== id));
          } else { state.apps.delete(id); state.policies.delete(id); }
        }
        return Response.json({ success: false, result: null }, { status: 503 });
      });
      const first = await test.teardown();
      expect(first.prepared.status).toBe(200); expect((await first.send('apply')).status).toBe(409);
      expect(test.bridge.deletions).toEqual([]);
      if (!applied) {
        const before = test.provider.deletes().length;
        expect((await first.send('apply')).status).toBe(409);
        expect(test.provider.deletes()).toHaveLength(before);
      }
      expect((await first.send('settle')).status).toBe(200);
      test.provider.intercept(undefined);
      const fresh = await test.teardown('v');
      expect(fresh.prepared.status).toBe(200);
      const response = await fresh.send('apply', 'w'.repeat(22));
      expect(response.status, await response.clone().text()).toBe(200);
      expect(test.provider.liveResourceCount()).toBe(0);
      expect(test.provider.deletes()).toHaveLength(applied ? 7 : 8);
      expect(test.bridge.deletions).toEqual(['domain', 'settings', 'app']);
    }));
  }
  for (const stopAfter of [undefined, 0, 1, 2, 3]) it(`removes the bridge and ${stopAfter ?? 'all installed'} ordinary source receipts`, async () => {
    await fixture(async (test) => {
      const action = await test.teardown();
      expect(action.prepared.status, await action.prepared.clone().text()).toBe(200);
      const proof = await action.send('prove');
      expect(proof.status).toBe(200);
      expect((await proof.json()).receiptResourceKinds).toContain('worker');
      const applied = await action.send('apply');
      expect(applied.status, await applied.clone().text()).toBe(200);
      const completion = await applied.json();
      expect(completion.status).toBe('gateway_removed');
      expect(completion.removedResourceCount).toBe(7 + (stopAfter ?? 3));
      expect(test.provider.liveResourceCount()).toBe(0);
      expect(test.bridge.deletions).toEqual(['domain', 'settings', 'app']);
      expect(completion.dependencyResourcesHash).not.toBe(test.objects.get(`v1:${test.readyReceipt.installationId}`).storage.snapshot().teardown.resourcesHash);
      expect(JSON.stringify(test.storage.writes)).not.toContain(grant.accessToken);
    }, { stopAfter });
  });
  for (const mode of ['knownPending', 'portalPending']) it(`cleans an interrupted ${mode} without adopting a name`, async () => {
    await fixture(async (test) => {
      const action = await test.teardown();
      expect(action.prepared.status, await action.prepared.clone().text()).toBe(200);
      const applied = await action.send('apply');
      expect(applied.status, await applied.clone().text()).toBe(200);
      expect(test.provider.liveResourceCount()).toBe(0);
      expect(test.bridge.deletions).toHaveLength(3);
    }, { [mode]: true });
  });
  it('refuses a bridge conflict before removing ordinary dependencies', async () => fixture(async (test) => {
    test.bridge.provider.app.policies[0].include = [{ everyone: {} }];
    const action = await test.teardown();
    expect(action.prepared.status).toBe(200);
    expect((await action.send('apply')).status).toBe(409);
    expect(test.provider.deletes()).toEqual([]);
    expect(test.bridge.deletions).toEqual([]);
  }));
  it('rejects unsupported installed label/tool edits without changing receipts or stranding removal', async () => fixture(async (test) => {
    const before = test.storage.snapshot(SOURCES);
    const source = before.sources[0];
    for (const changed of [{ label: 'Changed label' }, { enabledTools: ['list_table_ids'] }]) {
      const response = await test.runtime.fetch(new Request(origin + '/sources', { method: 'PUT',
        headers: { 'content-type': 'application/json' }, body: canonicalJson({ schemaVersion: 1, revision: before.revision,
          source: { label: source.label, url: source.url, authMode: source.authMode, enabledTools: source.enabledTools, ...changed } }),
      }));
      expect(response.status).toBe(409);
      expect(test.storage.snapshot(SOURCES)).toEqual(before);
    }
    const action = await test.teardown();
    expect(action.prepared.status).toBe(200);
    expect((await action.send('apply')).status).toBe(200);
  }));
  it('withholds root-finalizer completion after interrupted bridge cleanup, then resumes with fresh consent', async () => fixture(async (test) => {
    const first = await test.teardown();
    expect(first.prepared.status).toBe(200);
    expect((await first.send('apply')).status).toBe(409);
    expect(test.provider.liveResourceCount()).toBe(0);
    expect(test.bridge.deletions).toEqual(['domain', 'settings']);
    expect(test.storage.snapshot(TEARDOWNS).actions[0].status).toBe('applying');
    expect((await first.send('settle')).status).toBe(200);
    expect(test.storage.snapshot(TEARDOWNS).actions[0].status).toBe('recovery_required');
    const fresh = await test.teardown('v');
    expect(fresh.prepared.status).toBe(200);
    const finished = await fresh.send('apply', 'w'.repeat(22));
    expect(finished.status, await finished.clone().text()).toBe(200);
    expect(test.bridge.deletions).toEqual(['domain', 'settings', 'app']);
  }, { lostDelete: 1 }));
  it('blocks a source create without a provider locator and leaves all resources intact', async () => fixture(async (test) => {
    const actions = test.storage.snapshot(ACTIONS);
    actions.actions[0].pending = { kind: 'mcp_server', phase: 'send_armed', provider: null };
    await test.storage.put(ACTIONS, actions);
    expect((await test.teardown()).prepared.status).toBe(409);
    expect(test.provider.deletes()).toEqual([]);
    expect(test.bridge.deletions).toEqual([]);
  }, { stopAfter: 0 }));
});
