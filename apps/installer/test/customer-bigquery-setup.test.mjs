import { generateKeyPairSync } from 'node:crypto';
import { AdminState } from '../../../payload/worker/index.js';
import { installReadyGateway, ACCOUNT_ID, ZONE_ID, INSTALLATION_ID } from '../../../test/payload-lifecycle.mjs';
import { createBigQuerySetup } from '../src/customer-bigquery-setup';
import { bigQuerySourceNames } from '../src/customer-bigquery-contract';
import { base64UrlDecode } from '../src/crypto';

const body = { schemaVersion: 1, label: 'BigQuery analytics', configuration: {
  queryProjectId: 'query-project', allowedDatasets: [{ projectId: 'data-project', datasetId: 'reporting' }],
}, readOnlyConfirmed: true };
async function fixture() {
  const { env, objects } = await installReadyGateway();
  const storage = objects.get('v1:management').storage;
  const runtime = new AdminState({ storage }, env);
  const fetch = vi.fn(async () => { throw new Error('provider refused'); });
  const controller = createBigQuerySetup({ accountId: ACCOUNT_ID, zoneId: ZONE_ID, installationId: INSTALLATION_ID,
    accessIssuer: 'https://example.cloudflareaccess.com', zoneName: 'example.com', managementOrigin: 'https://manage.example.com',
    workerName: 'ankka-gateway', workersSubdomain: 'example', controlPlaneOrigin: 'https://deploy.ankka.ai',
    releaseIdentity: { schemaVersion: 1, channel: 'canary', controlPlaneOrigin: 'https://deploy.ankka.ai', release: 'gateway-v1.0.0',
      keyId: 'test-key', publicKey: 'p'.repeat(43), artifactSha256: 'a'.repeat(64) },
  }, { storage, runtime: (request) => runtime.fetch(request), fetch, runtimeSource: 'export default {}' });
  const sources = await (await runtime.fetch(new Request('https://admin-state.invalid/sources'))).json();
  const prepare = async () => controller.prepare(new Request('https://manage.example.com/api/bigquery', {
    method: 'POST', body: JSON.stringify({ ...body, revision: sources.revision }),
  }), 'admin@example.com', false);
  return { controller, storage, runtime, prepare, fetch };
}

describe('BigQuery setup with the production source-action state machine', () => {
  it('prepares the real source draft and same-origin handoff without a provider credential or grant', async () => {
    const test = await fixture();
    const prepared = await test.prepare();
    expect(prepared.status).toBe(200);
    const result = await prepared.json();
    const claim = JSON.parse(new TextDecoder().decode(base64UrlDecode(new URL(result.handoffUrl).hash.slice(1))));
    expect(claim).toMatchObject({ actionType: 'bigquery_setup', accountId: ACCOUNT_ID, releaseIdentity: { schemaVersion: 1, channel: 'canary' } });
    const current = await test.controller.readSourceAction(result.actionId);
    expect(current?.action.status).toBe('authorization_required');
    expect(current?.record).toMatchObject({ application: null, pending: null, ready: false });
    const stored = JSON.stringify(test.storage.writes);
    expect(stored).not.toContain(claim.actionKey);
    expect(test.fetch).not.toHaveBeenCalled();
    expect((await test.prepare()).status).toBe(409);
  });
  it('cancels and replaces an unstarted action when resuming; rejects a different operator', async () => {
    const test = await fixture();
    const first = await (await test.prepare()).json();
    const request = () => new Request('https://manage.example.com/api/bigquery/resume', {
      method: 'POST', body: JSON.stringify({ schemaVersion: 1, actionId: first.actionId }),
    });
    expect((await test.controller.prepare(request(), 'different@example.com', true)).status).toBe(409);
    const resumed = await test.controller.prepare(request(), 'admin@example.com', true);
    expect(resumed.status).toBe(200);
    expect((await resumed.json()).actionId).not.toBe(first.actionId);
    expect(test.fetch).not.toHaveBeenCalled();
  });
  it('retains a failed Google preflight as an unstarted action, without persisting the key', async () => {
    const test = await fixture();
    const prepared = await (await test.prepare()).json();
    const claim = JSON.parse(new TextDecoder().decode(base64UrlDecode(new URL(prepared.handoffUrl).hash.slice(1))));
    const response = await test.controller.run({ actionId: claim.actionId, actionKey: claim.actionKey,
      actorEmail: claim.actorEmail, accessToken: 'synthetic-cloudflare-operation-grant', actionExpiresAt: claim.expiresAt,
      serviceAccountJson: 'synthetic-invalid-google-key' });
    expect(response.status).toBe(409);
    expect((await test.controller.readSourceAction(claim.actionId))?.action.status).toBe('authorization_required');
    expect(JSON.stringify(test.storage.writes)).not.toContain('synthetic-invalid-google-key');
  });
  it('marks bridge provisioning as write evidence and only resumes its retained action', async () => {
    const test = await fixture();
    const prepared = await (await test.prepare()).json();
    const claim = JSON.parse(new TextDecoder().decode(base64UrlDecode(new URL(prepared.handoffUrl).hash.slice(1))));
    const current = await test.controller.readSourceAction(claim.actionId);
    test.fetch.mockImplementation(async (input) => {
      const url = String(input);
      if (url === 'https://oauth2.googleapis.com/token') return Response.json({ access_token: 'synthetic-google-access-token', token_type: 'Bearer', expires_in: 3600 });
      if (url === 'https://bigquery.googleapis.com/mcp') return Response.json({ result: { content: [{ type: 'text', text: '{"jobComplete":true}' }] } });
      if (url.includes('/access/apps?')) return Response.json({ success: true, result: [{ name: 'foreign', domain: current.record.hostname }] });
      throw new Error('unexpected synthetic destination');
    });
    const key = JSON.stringify({ type: 'service_account', project_id: 'query-project', private_key_id: 'a'.repeat(40),
      private_key: generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } }).privateKey,
      client_email: 'synthetic-reader@query-project.iam.gserviceaccount.com', token_uri: 'https://oauth2.googleapis.com/token' });
    const result = await test.controller.run({ actionId: claim.actionId, actionKey: claim.actionKey, actorEmail: claim.actorEmail,
      accessToken: 'synthetic-cloudflare-operation-grant', actionExpiresAt: claim.expiresAt, serviceAccountJson: key });
    expect(await result.json()).toEqual({ error: 'bigquery_resource_collision' });
    const snapshot = await (await test.runtime.fetch(new Request('https://admin-state.invalid/source-actions', { headers: { 'x-ankka-actor-email': claim.actorEmail } }))).json();
    expect(snapshot.actions[0]).toMatchObject({ state: 'recovery_required', failureCode: 'bigquery_setup_required', canCancel: false, canRenew: true });
    const resumed = await test.controller.prepare(new Request('https://manage.example.com/api/bigquery/resume', { method: 'POST',
      body: JSON.stringify({ schemaVersion: 1, actionId: claim.actionId }) }), claim.actorEmail, true);
    expect(resumed.status).toBe(200);
    expect((await resumed.json()).actionId).toBe(claim.actionId);
    expect(JSON.stringify(test.storage.writes)).not.toContain(JSON.parse(key).private_key);
  });
  it('normalizes dataset order so retries name the same bridge and source', async () => {
    const datasets = [...body.configuration.allowedDatasets, { projectId: 'other-project', datasetId: 'reports' }];
    const first = await bigQuerySourceNames(INSTALLATION_ID, 'example.com', { ...body.configuration, allowedDatasets: datasets });
    const second = await bigQuerySourceNames(INSTALLATION_ID, 'example.com', { ...body.configuration, allowedDatasets: datasets.reverse() });
    expect(second).toEqual(first);
  });
});
