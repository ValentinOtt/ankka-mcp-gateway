import { discoverHostedAccountZones, ensureHostedWorkersSubdomain } from '../src/hosted-account-setup';
import type { BoundaryValue } from '../src/boundary';

const accountId = 'a'.repeat(32);
const zone = { id: 'b'.repeat(32), name: 'example.com', status: 'active', account: { id: accountId } };
const ok = (result: BoundaryValue) => Response.json({ success: true, errors: [], result });
const absent = () => Response.json({ success: false, errors: [{ code: 10007 }], result: null }, { status: 404 });

describe('account setup discovery', () => {
  it('restricts domain discovery to active zones in the authorized account', async () => {
    const result = await discoverHostedAccountZones({ accountId, accessToken: 'synthetic', transport: async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      expect(request.method).toBe('GET');
      expect(url.pathname).toBe('/client/v4/zones');
      expect(url.searchParams.get('account.id')).toBe(accountId);
      expect(url.searchParams.get('status')).toBe('active');
      return ok([zone]);
    } });
    expect(result).toEqual([{ id: zone.id, name: zone.name }]);
  });

  it('allows an empty account to reach the Worker setup page', async () => {
    await expect(discoverHostedAccountZones({ accountId, accessToken: 'synthetic', transport: async () => ok([]) })).resolves.toEqual([]);
  });

  it.each([
    { zones: [{ ...zone, account: { id: 'c'.repeat(32) } }] }, { zones: [{ ...zone, status: 'pending' }] }, { zones: [zone, zone] },
  ])('rejects a foreign, inactive, or duplicate domain list', async ({ zones }) => {
    await expect(discoverHostedAccountZones({ accountId, accessToken: 'synthetic', transport: async () => ok(zones) })).rejects.toThrow();
  });

  it('paginates without dropping eligible domains', async () => {
    const pages: number[] = [];
    const result = await discoverHostedAccountZones({ accountId, accessToken: 'synthetic', transport: async (input) => {
      const page = Number(new URL(String(input)).searchParams.get('page'));
      pages.push(page);
      return ok(page === 1 ? Array.from({ length: 50 }, (_, i) => ({ ...zone, id: i.toString(16).padStart(32, '0'), name: `zone-${i}.example.com` })) : [zone]);
    } });
    expect(pages).toEqual([1, 2]);
    expect(result).toHaveLength(51);
  });
});

describe('account Workers subdomain setup', () => {
  it('reuses an existing account subdomain with no mutations', async () => {
    const methods: string[] = [];
    const result = await ensureHostedWorkersSubdomain({ accountId, accessToken: 'synthetic', suggestedSubdomain: 'ankka-new', transport: async (input, init) => {
      methods.push(new Request(input, init).method);
      return ok({ subdomain: 'existing-team' });
    } });
    expect(result.subdomain).toBe('existing-team');
    expect(methods).toEqual(['GET']);
  });

  it('registers only after explicit absence and verifies the setting', async () => {
    let subdomain: string | null = null;
    const methods: string[] = [];
    const result = await ensureHostedWorkersSubdomain({ accountId, accessToken: 'synthetic', suggestedSubdomain: 'ankka-new', transport: async (input, init) => {
      const request = new Request(input, init);
      methods.push(request.method);
      if (request.method === 'PUT') {
        expect(await request.json()).toEqual({ subdomain: 'ankka-new' });
        subdomain = 'ankka-new';
      }
      return subdomain === null ? absent() : ok({ subdomain });
    } });
    expect(methods).toEqual(['GET', 'GET', 'PUT', 'GET']);
    expect(result.subdomain).toBe('ankka-new');
  });

  it('reuses a subdomain that appears before registration', async () => {
    let calls = 0;
    const result = await ensureHostedWorkersSubdomain({ accountId, accessToken: 'synthetic', suggestedSubdomain: 'ankka-new', transport: async (_input, init) => {
      expect(init?.method).toBe('GET');
      return ++calls === 1 ? absent() : ok({ subdomain: 'other-setup' });
    } });
    expect(result.subdomain).toBe('other-setup');
  });

  it.each([403, 500])('does not mistake HTTP %i for a missing subdomain', async (status) => {
    let calls = 0;
    await expect(ensureHostedWorkersSubdomain({ accountId, accessToken: 'synthetic', suggestedSubdomain: 'ankka-new', transport: async (_input, init) => {
      calls += 1;
      expect(init?.method).toBe('GET');
      return Response.json({ success: false, errors: [{ code: 10007 }], result: null }, { status });
    } })).rejects.toThrow();
    expect(calls).toBe(1);
  });
});
