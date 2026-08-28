import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CloudflareApiError,
  createCloudflareClient,
} from '../src/cloudflare-client.ts';

const TOKEN = 'test-only-sensitive-token';
const BASE = 'https://api.cloudflare.com/client/v4';

function success(result, { status = 200, resultInfo, headers } = {}) {
  return new Response(
    status === 204
      ? null
      : JSON.stringify({ success: true, errors: [], result, result_info: resultInfo }),
    { status, headers },
  );
}

function mockFetch(responses) {
  const calls = [];
  const queue = [...responses];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    const response = queue.shift();
    if (response instanceof Error) throw response;
    if (!response) throw new Error('Unexpected mocked request');
    return response;
  };
  return { calls, fetchImpl };
}

function client(fetchImpl, overrides = {}) {
  return createCloudflareClient({
    token: TOKEN,
    accountId: 'account/id',
    zoneId: 'zone id',
    fetchImpl,
    ...overrides,
  });
}

test('gets a zone with encoded path and exact safe request headers', async () => {
  const mock = mockFetch([success({ id: 'zone id', status: 'active' })]);
  const result = await client(mock.fetchImpl).getZone();

  assert.deepEqual(result, { id: 'zone id', status: 'active' });
  assert.equal(mock.calls[0].url, `${BASE}/zones/zone%20id`);
  assert.ok(mock.calls[0].init.signal instanceof AbortSignal);
  assert.deepEqual({ ...mock.calls[0].init, signal: undefined }, {
    method: 'GET',
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${TOKEN}`,
    },
    signal: undefined,
  });
});

test('aborts every request at the configured deadline and forwards an external abort', async () => {
  for (const mode of ['timeout', 'external']) {
    const controller = new AbortController();
    let receivedSignal;
    const fetchImpl = async (_url, init) => {
      receivedSignal = init.signal;
      return new Promise((_resolve, reject) => {
        init.signal.addEventListener('abort', () => reject(new Error('private abort detail')), { once: true });
      });
    };
    const options = {
      requestTimeoutMs: mode === 'timeout' ? 5 : 1_000,
    };
    if (mode === 'external') options.signal = controller.signal;
    const api = client(fetchImpl, options);
    if (mode === 'external') queueMicrotask(() => controller.abort());
    await assert.rejects(api.getZone(), (error) => {
      assert.ok(error instanceof CloudflareApiError);
      assert.deepEqual(error.codes, ['network_error']);
      return true;
    });
    assert.equal(receivedSignal.aborted, true);
  }
});

test('keeps the deadline active while a response body hangs', async () => {
  let receivedSignal;
  const fetchImpl = async (_url, init) => {
    receivedSignal = init.signal;
    return {
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () => new Promise(() => {}),
    };
  };
  await assert.rejects(
    client(fetchImpl, { requestTimeoutMs: 5 }).getZone(),
    (error) => error instanceof CloudflareApiError && error.codes.includes('invalid_response'),
  );
  assert.equal(receivedSignal.aborted, true);
});

test('uses current MCP server endpoints and verbs, including sync', async () => {
  const mock = mockFetch([
    success({ id: 'server/id' }),
    success({ id: 'server/id', name: 'updated' }),
    success({ status: 'waiting' }),
    success({ id: 'server/id' }),
  ]);
  const api = client(mock.fetchImpl);
  await api.createMcpServer({ name: 'created' });
  await api.updateMcpServer('server/id', { name: 'updated' });
  await api.syncMcpServer('server/id');
  await api.deleteMcpServer('server/id');

  const root = `${BASE}/accounts/account%2Fid/access/ai-controls/mcp/servers`;
  assert.deepEqual(
    mock.calls.map(({ url, init }) => [url, init.method, init.body]),
    [
      [root, 'POST', '{"name":"created"}'],
      [`${root}/server%2Fid`, 'PUT', '{"name":"updated"}'],
      [`${root}/server%2Fid/sync`, 'POST', undefined],
      [`${root}/server%2Fid`, 'DELETE', undefined],
    ],
  );
  assert.equal(mock.calls[0].init.headers['Content-Type'], 'application/json');
  assert.equal(mock.calls[3].init.headers['Content-Type'], undefined);
});

test('covers Portal, Access app, policy, identity-provider, and DNS paths', async () => {
  const mock = mockFetch(Array.from({ length: 16 }, () => success([])));
  const api = client(mock.fetchImpl);
  await api.listIdentityProviders();
  await api.createPortal({ name: 'portal' });
  await api.getPortal('portal/id');
  await api.updatePortal('portal/id', { name: 'portal-2' });
  await api.deletePortal('portal/id');
  await api.listAccessApps();
  await api.createAccessApp({ name: 'source-app', type: 'mcp', destinations: [] });
  await api.getAccessApp('app/id');
  await api.updateAccessApp('app/id', { name: 'app-2' });
  await api.deleteAccessApp('app/id');
  await api.createAppPolicy('app/id', { name: 'allow' });
  await api.getAppPolicy('app/id', 'policy/id');
  await api.updateAppPolicy('app/id', 'policy/id', { name: 'allow-2' });
  await api.deleteAppPolicy('app/id', 'policy/id');
  await api.createDnsRecord({ type: 'CNAME' });
  await api.updateDnsRecord('record/id', { type: 'CNAME' });

  assert.deepEqual(
    mock.calls.map(({ url, init }) => [new URL(url).pathname, init.method]),
    [
      ['/client/v4/accounts/account%2Fid/access/identity_providers', 'GET'],
      ['/client/v4/accounts/account%2Fid/access/ai-controls/mcp/portals', 'POST'],
      ['/client/v4/accounts/account%2Fid/access/ai-controls/mcp/portals/portal%2Fid', 'GET'],
      ['/client/v4/accounts/account%2Fid/access/ai-controls/mcp/portals/portal%2Fid', 'PUT'],
      ['/client/v4/accounts/account%2Fid/access/ai-controls/mcp/portals/portal%2Fid', 'DELETE'],
      ['/client/v4/accounts/account%2Fid/access/apps', 'GET'],
      ['/client/v4/accounts/account%2Fid/access/apps', 'POST'],
      ['/client/v4/accounts/account%2Fid/access/apps/app%2Fid', 'GET'],
      ['/client/v4/accounts/account%2Fid/access/apps/app%2Fid', 'PUT'],
      ['/client/v4/accounts/account%2Fid/access/apps/app%2Fid', 'DELETE'],
      ['/client/v4/accounts/account%2Fid/access/apps/app%2Fid/policies', 'POST'],
      ['/client/v4/accounts/account%2Fid/access/apps/app%2Fid/policies/policy%2Fid', 'GET'],
      ['/client/v4/accounts/account%2Fid/access/apps/app%2Fid/policies/policy%2Fid', 'PUT'],
      ['/client/v4/accounts/account%2Fid/access/apps/app%2Fid/policies/policy%2Fid', 'DELETE'],
      ['/client/v4/zones/zone%20id/dns_records', 'POST'],
      ['/client/v4/zones/zone%20id/dns_records/record%2Fid', 'PUT'],
    ],
  );
  assert.equal(new URL(mock.calls[0].url).search, '?page=1&per_page=100');
  assert.equal(new URL(mock.calls[5].url).search, '?page=1&per_page=100');
  assert.equal(mock.calls[6].init.body, '{"name":"source-app","type":"mcp","destinations":[]}');
});

test('covers the remaining list and read/delete resource paths', async () => {
  const mock = mockFetch(Array.from({ length: 8 }, () => success([])));
  const api = client(mock.fetchImpl);
  await api.listMcpServers();
  await api.getMcpServer('server');
  await api.listPortals();
  await api.listAppPolicies('app');
  await api.listDnsRecords();
  await api.getDnsRecord('record');
  await api.deleteDnsRecord('record');
  await api.getZone();

  assert.deepEqual(
    mock.calls.map(({ url, init }) => [new URL(url).pathname, init.method]),
    [
      ['/client/v4/accounts/account%2Fid/access/ai-controls/mcp/servers', 'GET'],
      ['/client/v4/accounts/account%2Fid/access/ai-controls/mcp/servers/server', 'GET'],
      ['/client/v4/accounts/account%2Fid/access/ai-controls/mcp/portals', 'GET'],
      ['/client/v4/accounts/account%2Fid/access/apps/app/policies', 'GET'],
      ['/client/v4/zones/zone%20id/dns_records', 'GET'],
      ['/client/v4/zones/zone%20id/dns_records/record', 'GET'],
      ['/client/v4/zones/zone%20id/dns_records/record', 'DELETE'],
      ['/client/v4/zones/zone%20id', 'GET'],
    ],
  );
});

test('paginates list results and encodes caller query values', async () => {
  const mock = mockFetch([
    success([{ id: 'one' }], { resultInfo: { page: 1, total_pages: 2 } }),
    success([{ id: 'two' }], { resultInfo: { page: 2, total_pages: 2 } }),
  ]);
  const result = await client(mock.fetchImpl).listDnsRecords({ name: 'mcp example.com' });

  assert.deepEqual(result, [{ id: 'one' }, { id: 'two' }]);
  assert.equal(
    new URL(mock.calls[0].url).search,
    '?name=mcp+example.com&page=1&per_page=100',
  );
  assert.equal(
    new URL(mock.calls[1].url).search,
    '?name=mcp+example.com&page=2&per_page=100',
  );
});

test('encodes an exact-name DNS preflight lookup without zone-wide enumeration', async () => {
  const mock = mockFetch([success([])]);

  await client(mock.fetchImpl).listDnsRecords({
    'name.exact': 'gateway.canary.example',
    match: 'all',
  });

  assert.equal(
    new URL(mock.calls[0].url).search,
    '?name.exact=gateway.canary.example&match=all&page=1&per_page=100',
  );
});

test('continues full pages when Cloudflare omits total_pages', async () => {
  const firstPage = Array.from({ length: 100 }, (_, index) => ({ id: `record-${index}` }));
  const mock = mockFetch([
    success(firstPage, { resultInfo: { page: 1, per_page: 100 } }),
    success([], { resultInfo: { page: 2, per_page: 100 } }),
  ]);

  const result = await client(mock.fetchImpl).listDnsRecords();

  assert.equal(result.length, 100);
  assert.equal(mock.calls.length, 2);
  assert.equal(new URL(mock.calls[1].url).search, '?page=2&per_page=100');
});

test('refuses pagination beyond the fixed safety cap', async () => {
  const mock = mockFetch([
    success([], { resultInfo: { page: 1, total_pages: 101 } }),
  ]);

  await assert.rejects(client(mock.fetchImpl).listMcpServers(), (error) => {
    assert.ok(error instanceof CloudflareApiError);
    assert.deepEqual(error.codes, ['pagination_limit']);
    assert.equal(mock.calls.length, 1);
    return true;
  });
});

test('explicit read methods return null for 404 without exposing the response', async () => {
  const mock = mockFetch([
    new Response('private upstream details', { status: 404 }),
    new Response('private upstream details', { status: 404 }),
    new Response('private upstream details', { status: 404 }),
  ]);
  const api = client(mock.fetchImpl);

  assert.equal(await api.getMcpServer('missing'), null);
  assert.equal(await api.getAppPolicy('app', 'missing'), null);
  assert.equal(await api.getDnsRecord('missing'), null);
});

test('API failures expose only operation, status, codes, and request id', async () => {
  const privateMessage = `bad request ${TOKEN} customer@example.com`;
  const mock = mockFetch([
    new Response(
      JSON.stringify({
        success: false,
        errors: [
          { code: 1001, message: privateMessage },
          { code: `${TOKEN} unsafe`, message: privateMessage },
        ],
        result: null,
      }),
      { status: 403, headers: { 'cf-ray': 'safe-ray-id' } },
    ),
  ]);

  await assert.rejects(
    client(mock.fetchImpl).createPortal({ name: 'portal' }),
    (error) => {
      assert.ok(error instanceof CloudflareApiError);
      assert.equal(error.operation, 'create_portal');
      assert.equal(error.status, 403);
      assert.deepEqual(error.codes, ['1001']);
      assert.equal(error.requestId, 'safe-ray-id');
      assert.doesNotMatch(error.message, new RegExp(TOKEN));
      assert.doesNotMatch(error.message, /customer@example\.com/);
      assert.doesNotMatch(error.stack, new RegExp(TOKEN));
      return true;
    },
  );
});

test('malformed and network errors are redacted into safe stable codes', async () => {
  const malformed = mockFetch([new Response(`${TOKEN} not json`, { status: 502 })]);
  await assert.rejects(
    client(malformed.fetchImpl).listPortals(),
    (error) => {
      assert.deepEqual(error.codes, ['invalid_response']);
      assert.equal(error.status, 502);
      assert.doesNotMatch(error.message, new RegExp(TOKEN));
      return true;
    },
  );

  const network = mockFetch([new Error(`socket failed ${TOKEN}`)]);
  await assert.rejects(
    client(network.fetchImpl).getZone(),
    (error) => {
      assert.deepEqual(error.codes, ['network_error']);
      assert.equal(error.status, 0);
      assert.doesNotMatch(error.message, new RegExp(TOKEN));
      return true;
    },
  );
});

test('validates construction and request bodies without echoing values', async () => {
  assert.throws(
    () => createCloudflareClient({ token: TOKEN, accountId: '', zoneId: 'zone' }),
    /accountId must be a non-empty identifier/,
  );
  assert.throws(
    () =>
      createCloudflareClient({
        token: TOKEN,
        accountId: 'account',
        zoneId: 'zone',
        baseUrl: 'http://api.example.test',
      }),
    /client options contain unsupported fields/,
  );
  assert.throws(
    () => createCloudflareClient({ token: TOKEN, accountId: 'account', zoneId: 'zone', requestTimeoutMs: 0 }),
    /requestTimeoutMs/,
  );

  const mock = mockFetch([]);
  await assert.rejects(client(mock.fetchImpl).createDnsRecord(TOKEN), (error) => {
    assert.match(error.message, /request body must be a JSON object/);
    assert.doesNotMatch(error.message, new RegExp(TOKEN));
    return true;
  });
});
