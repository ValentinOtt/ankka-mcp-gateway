import * as v from 'valibot';
import { generateKeyPairSync } from 'node:crypto';
import { boundaryObjectSchema, boundaryValueSchema, type BoundaryValue } from '../src/boundary';
import { bigQuerySourceNames, type BigQueryRecord } from '../src/customer-bigquery-contract';
import { deployBigQueryBridge } from '../src/customer-bigquery-deployment';

const GOOGLE_KEY = JSON.stringify({ type: 'service_account', project_id: 'query-project', private_key_id: 'a'.repeat(40),
  private_key: generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } }).privateKey,
  client_email: 'synthetic-reader@query-project.iam.gserviceaccount.com', token_uri: 'https://oauth2.googleapis.com/token' });
const CF_TOKEN = 'synthetic-operation-grant';
const context = { accountId: 'a'.repeat(32), zoneId: 'b'.repeat(32), installationId: `acg-${'c'.repeat(24)}`,
  accessIssuer: 'https://example.cloudflareaccess.com' };
const configuration = { queryProjectId: 'query-project', allowedDatasets: [{ projectId: 'data-project', datasetId: 'reporting' }] };
async function fixture(options: { collision?: boolean; lostUpload?: boolean; googleFailure?: boolean; changedVersion?: boolean; applicationStatus?: number } = {}) {
  const names = await bigQuerySourceNames(context.installationId, 'example.com', configuration);
  let record: BigQueryRecord = { schemaVersion: 1, sourceId: names.sourceId, actionId: `action_${'d'.repeat(32)}`,
    configuration, workerName: names.workerName, hostname: names.hostname, operatorEmail: 'admin@example.com',
    sourceHash: `sha256:${'e'.repeat(64)}`, application: null, workerVersion: null, domainId: null, pending: null, ready: false };
  let application: BoundaryValue = null;
  let settings: BoundaryValue = null;
  let domains: BoundaryValue[] = [];
  let uploadCount = 0;
  const writes: string[] = [];
  const requests: { url: string; method: string }[] = [];
  const begin = vi.fn(async () => {});
  const fetch: typeof globalThis.fetch = async (input, init) => {
    const url = String(input);
    const method = init?.method ?? 'GET';
    requests.push({ url, method });
    const headers = new Headers(init?.headers);
    if (url === 'https://oauth2.googleapis.com/token') {
      expect(init?.body).not.toContain(CF_TOKEN);
      return Response.json({ access_token: 'synthetic-google-access', token_type: 'Bearer', expires_in: 3600 });
    }
    if (url === 'https://bigquery.googleapis.com/mcp') {
      expect(headers.get('Authorization')).toBe('Bearer synthetic-google-access');
      expect(init?.body).toContain('SELECT 1 AS bridge_ok');
      expect(init?.body).not.toContain(CF_TOKEN);
      return Response.json({ result: { content: [{ type: 'text', text: JSON.stringify({ jobComplete: !options.googleFailure }) }] } });
    }
    const account = `https://api.cloudflare.com/client/v4/accounts/${context.accountId}`;
    const zone = `https://api.cloudflare.com/client/v4/zones/${context.zoneId}`;
    expect(url.startsWith(account + '/') || url.startsWith(zone + '/')).toBe(true);
    expect(headers.get('Authorization')).toBe(`Bearer ${CF_TOKEN}`);
    const path = url.slice((url.startsWith(zone + '/') ? zone : account).length);
    // Model the actual zone-access.write grant instead of an unrestricted
    // account token, so an account-path Access request cannot pass this fixture.
    if (path.startsWith('/access/apps') && !url.startsWith(zone + '/')) return new Response(null, { status: 403 });
    if (!path.startsWith('/access/apps')) expect(url.startsWith(account + '/')).toBe(true);
    let result: BoundaryValue = null;
    if (path?.startsWith('/access/apps?')) result = options.collision ? [{ name: 'foreign', domain: names.hostname }] : [];
    else if (path === '/access/apps' && method === 'POST') {
      if (options.applicationStatus) return Response.json({ errors: [{ message: 'private-provider-detail' }] }, { status: options.applicationStatus });
      const body = v.parse(boundaryObjectSchema, JSON.parse(v.parse(v.string(), init?.body)));
      application = { ...body, id: 'app-id', aud: 'f'.repeat(64) };
      result = application;
    } else if (path === '/access/apps/app-id') result = application;
    else if (path === `/workers/scripts/${names.workerName}/settings`) {
      if (settings === null) return new Response(null, { status: 404 });
      result = settings;
    } else if (path === `/workers/scripts/${names.workerName}` && method === 'PUT') {
      uploadCount++;
      expect(init?.body).toBeInstanceOf(FormData);
      if (!(init?.body instanceof FormData)) throw new Error('multipart expected');
      const metadata = init.body.get('metadata');
      if (!(metadata instanceof Blob)) throw new Error('metadata expected');
      const parsed = v.parse(v.object({ bindings: v.array(v.object({ name: v.string(), type: v.string(), text: v.string() })), tags: v.array(v.string()),
        logpush: v.boolean(), observability: v.object({ enabled: v.boolean() }) }), JSON.parse(await metadata.text()));
      expect(parsed.bindings.find((binding) => binding.name === 'PROVIDER_TOKEN')).toEqual({ name: 'PROVIDER_TOKEN', type: 'secret_text', text: GOOGLE_KEY });
      expect(parsed.bindings.find((binding) => binding.name === 'CONNECTOR_CONFIG_JSON')?.text).toContain('"allowQueries":true');
      settings = { ...parsed, bindings: parsed.bindings.map((binding) => binding.type === 'secret_text' ? { name: binding.name, type: binding.type } : binding) };
      if (options.lostUpload) throw new Error('synthetic lost upload acknowledgement');
      result = { id: names.workerName };
    } else if (path === `/workers/scripts/${names.workerName}/deployments`) {
      result = { deployments: [{ versions: [{ version_id: options.changedVersion && record.workerVersion !== null ? 'foreign-version' : 'version-id', percentage: 100 }] }] };
    } else if (path === `/workers/scripts/${names.workerName}/subdomain`) result = { enabled: false, previews_enabled: false };
    else if (path === '/workers/domains' && method === 'PUT') {
      const domain = v.parse(boundaryObjectSchema, JSON.parse(v.parse(v.string(), init?.body)));
      result = { ...domain, id: 'domain-id' }; domains = [result];
    } else if (path === '/workers/domains') result = domains;
    else throw new Error('unexpected synthetic request');
    expect(method === 'GET' || begin.mock.calls.length > 0).toBe(true);
    return Response.json({ success: true, result: v.parse(boundaryValueSchema, result) });
  };
  const port = { fetch, begin, assertActive: async () => {}, runtimeSource: 'export default { fetch() { return new Response("synthetic") } }',
    save: async (next: BigQueryRecord) => { writes.push(JSON.stringify(next)); record = structuredClone(next); } };
  return { run: () => deployBigQueryBridge(record, context, CF_TOKEN, GOOGLE_KEY, port), requests, writes, begin,
    record: () => record, uploads: () => uploadCount };
}

describe('gateway-owned BigQuery deployment', () => {
  it('checks Google first, uploads one secret to the exact child Worker, protects its domain, and retains only receipts', async () => {
    const test = await fixture();
    const result = await test.run();
    expect(result).toMatchObject({ ready: true, pending: null, application: { id: 'app-id' }, workerVersion: 'version-id', domainId: 'domain-id' });
    expect(test.requests.slice(0, 2).map((request) => request.url)).toEqual(['https://oauth2.googleapis.com/token', 'https://bigquery.googleapis.com/mcp']);
    expect(test.uploads()).toBe(1);
    expect(test.writes.join('\n')).not.toContain(GOOGLE_KEY);
    expect(test.writes.join('\n')).not.toContain(CF_TOKEN);
    await test.run();
    expect(test.uploads()).toBe(1);
    expect(test.requests.filter((request) => request.url === 'https://bigquery.googleapis.com/mcp')).toHaveLength(1);
  });
  it('refuses an unsuccessful Google preflight before any Cloudflare resource write', async () => {
    const test = await fixture({ googleFailure: true });
    await expect(test.run()).rejects.toThrow('bigquery_google_connection_failed');
    expect(test.begin).not.toHaveBeenCalled();
    expect(test.requests).toHaveLength(2);
    expect(test.writes).toEqual([]);
  });
  it('refuses an existing application at the chosen hostname', async () => {
    const test = await fixture({ collision: true });
    await expect(test.run()).rejects.toThrow('bigquery_resource_collision');
    expect(test.uploads()).toBe(0);
    expect(test.writes).toEqual([]);
  });
  it('keeps an unacknowledged upload uncertain and never adopts or uploads it again', async () => {
    const test = await fixture({ lostUpload: true });
    await expect(test.run()).rejects.toThrow('bigquery_deployment_failed');
    expect(test.record().pending).toBe('worker');
    expect(test.record().failure).toEqual({ stage: 'worker', httpStatus: null });
    const count = test.requests.length;
    await expect(test.run()).rejects.toThrow('bigquery_resource_uncertain');
    expect(test.requests).toHaveLength(count);
    expect(test.uploads()).toBe(1);
    expect(test.writes.join('\n')).not.toContain(GOOGLE_KEY);
  });
  it('retains only the stage and HTTP status after an Access refusal, without retrying an uncertain create', async () => {
    const test = await fixture({ applicationStatus: 403 });
    await expect(test.run()).rejects.toThrow('bigquery_deployment_failed');
    expect(test.record()).toMatchObject({ pending: 'application', application: null, workerVersion: null,
      failure: { stage: 'application', httpStatus: 403 } });
    expect(test.requests.at(-1)).toEqual({ method: 'POST', url: `https://api.cloudflare.com/client/v4/zones/${context.zoneId}/access/apps` });
    expect(test.uploads()).toBe(0);
    expect(test.writes.join('\n')).not.toContain('private-provider-detail');
    expect(test.writes.join('\n')).not.toContain(CF_TOKEN);
    expect(test.writes.join('\n')).not.toContain(GOOGLE_KEY);
    const count = test.requests.length;
    await expect(test.run()).rejects.toThrow('bigquery_resource_uncertain');
    expect(test.requests).toHaveLength(count);
  });
  it('refuses a Worker version changed outside the retained receipt', async () => {
    const test = await fixture({ changedVersion: true });
    await expect(test.run()).rejects.toThrow('bigquery_deployment_failed');
    expect(test.requests.some((request) => request.method === 'PUT' && request.url.endsWith('/workers/domains'))).toBe(false);
  });
});
