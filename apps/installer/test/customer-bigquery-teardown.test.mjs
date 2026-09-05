import { fixture, grant, JOURNAL } from './bigquery-teardown-fixture.mjs';
const GRANT = grant.accessToken;

describe('receipt-bound BigQuery bridge removal', () => {
  it('fits both maximum catalogue scans and resource rechecks in each pass', async () => {
    const test = await fixture(); test.provider.cataloguePages = 10;
    await (await test.describe()).remove(grant, [test.serverId]);
    expect(test.requests.length).toBeGreaterThan(50);
    expect(Math.max(...test.invocationCounts)).toBeLessThanOrEqual(26);
    expect(test.deletions).toEqual(['domain', 'settings', 'app']);
  });
  it('bounds a catalogue that never reaches a verified final page without deleting', async () => {
    const test = await fixture(); test.provider.cataloguePages = 11;
    await expect((await test.describe()).remove(grant, [test.serverId])).rejects.toThrow();
    expect(test.requests.length).toBeLessThanOrEqual(10); expect(test.deletions).toEqual([]);
  });
  it('cannot reuse verification after source identity or receipt changes between passes', async () => {
    const test = await fixture();
    expect((await (await test.rawDescribe()).preflight(grant, [test.serverId])).complete).toBe(true);
    test.snapshot.sources.sources[0].label = 'Changed';
    await expect(test.rawDescribe()).rejects.toThrow();
    expect(test.deletions).toEqual([]);
    test.snapshot.sources.sources[0].label = 'BigQuery';
    test.values.set(test.key, { ...test.record, workerVersion: 'changed-version' });
    await expect((await test.describe()).remove(grant, [test.serverId])).rejects.toThrow();
    expect(test.deletions).toEqual([]);
  });
  it('keeps Access until the domain and secret-bearing Worker are absent, and proves completion again', async () => {
    const test = await fixture();
    const plan = await test.describe();
    expect(plan.receiptResourceKinds).toEqual(['worker_custom_domain', 'worker', 'access_application']);
    expect(await plan.remove(grant, [test.serverId])).toMatchObject({ removedResourceCount: 3 });
    expect(test.deletions).toEqual(['domain', 'settings', 'app']);
    expect(await (await test.describe()).remove({ ...grant, requestId: 'y'.repeat(22) }, [test.serverId])).toMatchObject({ removedResourceCount: 3 });
    expect(test.deletions).toHaveLength(3);
    expect(JSON.stringify(test.writes)).not.toContain(GRANT);
  });
  it('removes an exactly receipted interrupted application-only setup', async () => {
    const test = await fixture({ partial: true });
    const plan = await test.describe();
    expect(plan.receiptResourceKinds).toContain('worker');
    expect(await plan.remove(grant, [test.serverId])).toMatchObject({ removedResourceCount: 1 });
    expect(test.deletions).toEqual(['app']);
  });
  for (const applied of [true, false]) for (const lostDelete of [0, 1, 2]) {
    it(`recovers a ${applied ? 'completed' : 'unapplied'} ambiguous DELETE at step ${lostDelete + 1} with a new request`, async () => {
      const test = await fixture({ applied, lostDelete });
      await expect((await test.describe()).remove(grant, [test.serverId])).rejects.toThrow('lost response');
      expect(test.values.get(JOURNAL).pending).not.toBeNull();
      if (!applied) {
        const count = test.requests.length;
        await expect((await test.describe()).remove(grant, [test.serverId])).rejects.toThrow('unverified');
        expect(test.requests.slice(count).every((request) => request.method === 'GET')).toBe(true);
      }
      expect(await (await test.describe()).remove({ ...grant, requestId: 'z'.repeat(22) }, [test.serverId])).toMatchObject({ removedResourceCount: 3 });
      expect(test.deletions).toEqual(['domain', 'settings', 'app']);
    });
  }
  const driftCases = {
    'Worker version': (test) => { test.provider.deployments.deployments[0].versions[0].version_id = 'replacement'; },
    'Worker owner tag': (test) => { test.provider.settings.tags[1] = 'foreign'; },
    'Worker origin binding': (test) => { test.provider.settings.bindings.find((binding) => binding.name === 'PUBLIC_ORIGIN').text = 'https://foreign.example.com'; },
    'Worker public preview': (test) => { test.provider.subdomain.previews_enabled = true; },
    'Worker logging': (test) => { test.provider.settings.observability.enabled = true; },
    'Access audience': (test) => { test.provider.app.aud = '0'.repeat(64); },
    'Access additional hostname': (test) => { test.provider.app.destinations = [{ type: 'public', uri: 'foreign.example.com' }]; },
    'Access policy': (test) => { test.provider.app.policies[0].include = [{ everyone: {} }]; },
    'Access callback': (test) => { test.provider.app.oauth_configuration.dynamic_client_registration.allowed_uris.push('https://foreign.example.com/callback'); },
    'domain replacement': (test) => { test.provider.domain.service = 'foreign'; },
    'foreign MCP source': (test) => { test.provider.servers.push({ id: 'foreign', hostname: test.snapshot.sources.sources[0].url }); },
    'foreign domain': (test) => { test.provider.extraDomains.push({ ...test.provider.domain, id: 'foreign', hostname: 'foreign.example.com' }); },
    'missing protection': (test) => { test.provider.app = null; },
    'missing Worker': (test) => { test.provider.settings = null; },
  };
  for (const [name, mutate] of Object.entries(driftCases)) it(`refuses ${name} before any deletion`, async () => {
    const test = await fixture(); mutate(test);
    await expect((await test.describe()).remove(grant, [test.serverId])).rejects.toThrow();
    expect(test.deletions).toEqual([]);
    expect(test.writes).toEqual([]);
  });
  it('refuses unreceipted creates without looking up or adopting a matching name', async () => {
    const test = await fixture();
    test.values.set(test.key, { ...test.record, pending: 'worker' });
    await expect(test.describe()).rejects.toThrow('unverified');
    expect(test.requests).toEqual([]);
  });
  it('checks later catalogue pages before deleting a bridge', async () => {
    const test = await fixture();
    test.provider.serverPages = [test.provider.servers, [{ id: 'foreign', hostname: test.snapshot.sources.sources[0].url }]];
    await expect((await test.describe()).remove(grant, [test.serverId])).rejects.toThrow('unverified');
    expect(test.deletions).toEqual([]);
  });
  it('keeps an application-only receipt protected if an unreceipted Worker now exists', async () => {
    const test = await fixture({ partial: true });
    test.provider.settings = { unexpected: true };
    await expect((await test.describe()).remove(grant, [test.serverId])).rejects.toThrow('unverified');
    expect(test.deletions).toEqual([]);
  });
  it('cleans a started action with no resource writes without any Workers permission', async () => {
    const test = await fixture({ partial: true });
    test.values.set(test.key, { ...test.record, application: null });
    const plan = await test.describe();
    expect(plan.receiptResourceKinds).toEqual([]);
    expect(await plan.remove(grant, [])).toMatchObject({ removedResourceCount: 0 });
    expect(test.requests).toEqual([]);
  });
  it('reads past discarded unstarted drafts to find every retained bridge', async () => {
    const test = await fixture();
    for (let index = 0; index < 80; index++) {
      const sourceId = `source-${index.toString(16).padStart(16, '0')}`;
      test.values.set('ankka-mcp-gateway/bigquery-source/v1/' + sourceId,
        { ...test.record, sourceId, application: null, workerVersion: null, domainId: null, ready: false });
    }
    expect(await (await test.describe()).remove(grant, [test.serverId])).toMatchObject({ removedResourceCount: 3 });
  });
  it('refuses changed receipt authority and expired grants', async () => {
    const test = await fixture();
    test.expire();
    await expect((await test.describe()).remove(grant, [test.serverId])).rejects.toThrow('unverified');
    expect(test.requests).toEqual([]);
    test.snapshot.sources.sources[0].label = 'Changed';
    await expect(test.describe()).rejects.toThrow('unverified');
  });
  it('does not report completion if a removed Worker is recreated', async () => {
    const test = await fixture();
    const settings = structuredClone(test.provider.settings);
    await (await test.describe()).remove(grant, [test.serverId]);
    test.provider.settings = settings;
    await expect((await test.describe()).remove({ ...grant, requestId: 'z'.repeat(22) }, [test.serverId])).rejects.toThrow('unverified');
  });
});
