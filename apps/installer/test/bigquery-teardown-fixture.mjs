import { createBigQueryTeardown } from '../src/customer-bigquery-teardown';
import { bigQueryHex, bigQuerySourceNames, BIGQUERY_SETUP_TOOLS } from '../src/customer-bigquery-contract';
import { canonicalJson } from '../src/canonical-json';

const context = { accountId: 'a'.repeat(32), zoneId: 'b'.repeat(32), installationId: `acg-${'c'.repeat(24)}`,
  zoneName: 'example.com', accessIssuer: 'https://example.cloudflareaccess.com' };
const GRANT = 'synthetic-uninstall-grant-never-store';
export const grant = { accessToken: GRANT, expiresAt: 20_000, requestId: 'x'.repeat(22) };
export const JOURNAL = 'ankka-mcp-gateway/bigquery-teardown/v1';

export async function fixture({ partial = false, lostDelete = -1, applied = true, fixtureContext = context, journalStorage } = {}) {
  const context = fixtureContext;
  const configuration = { queryProjectId: 'query-project', allowedDatasets: [{ projectId: 'data-project', datasetId: 'reporting' }] };
  const names = await bigQuerySourceNames(context.installationId, context.zoneName, configuration);
  const source = { id: names.sourceId, label: 'BigQuery', url: names.url, authMode: 'oauth', onBehalfOfUser: true,
    enabledTools: [...BIGQUERY_SETUP_TOOLS] };
  const record = { schemaVersion: 1, sourceId: source.id, actionId: `action_${'d'.repeat(32)}`, configuration,
    workerName: names.workerName, hostname: names.hostname, operatorEmail: 'admin@example.com',
    sourceHash: `sha256:${await bigQueryHex(canonicalJson(source))}`, application: { id: 'bridge-app', audience: 'f'.repeat(64) },
    workerVersion: partial ? null : 'bridge-version', domainId: partial ? null : 'bridge-domain', pending: null, ready: !partial };
  const action = { actionId: record.actionId, sourceId: source.id, sourceHash: record.sourceHash,
    actorEmail: record.operatorEmail, bigquerySetupStarted: true };
  const snapshot = { actions: [action], sources: { sources: [{ ...source, status: partial ? 'draft' : 'installed' }] } };
  const key = 'ankka-mcp-gateway/bigquery-source/v1/' + source.id;
  const values = new Map([[key, structuredClone(record)]]);
  const writes = [];
  const storage = { get: async (key) => structuredClone(values.get(key)),
    put: async (key, value) => { values.set(key, structuredClone(value)); writes.push(structuredClone(value)); },
    list: async ({ prefix, limit, startAfter = '' }) => new Map([...values].filter(([key]) => key.startsWith(prefix) && key > startAfter)
      .sort(([a], [b]) => a < b ? -1 : 1).slice(0, limit).map(([key, value]) => [key, structuredClone(value)])),
  };
  const digest = await bigQueryHex(canonicalJson({ installationId: context.installationId, prefix: 'mcp', logicalId: source.id }));
  const serverId = `mcp-${source.id.slice(0, 19).replace(/-+$/u, '')}-${digest.slice(0, 8)}`;
  const app = { id: 'bridge-app', aud: 'f'.repeat(64), name: `acg:v1:${context.installationId}:bigquery-${source.id}`,
    domain: names.hostname, type: 'self_hosted', oauth_configuration: { enabled: true,
      dynamic_client_registration: { enabled: true, allow_any_on_localhost: false, allow_any_on_loopback: false,
        allowed_uris: [`https://dash.cloudflare.com/${context.accountId}/one/access-controls/ai-controls/mcp-server/oauth-callback/${serverId}`] },
      grant: { access_token_lifetime: '15m', session_duration: '336h' } },
    policies: [{ decision: 'allow', include: [{ email: { email: 'admin@example.com' } }], exclude: [], require: [] }] };
  const variables = { CONNECTOR_PROVIDER: 'bigquery-mcp', CONNECTOR_CONFIG_JSON: JSON.stringify({ ...configuration, allowQueries: true }),
    PUBLIC_ORIGIN: `https://${names.hostname}`, ACCESS_TEAM_DOMAIN: new URL(context.accessIssuer).hostname, ACCESS_AUD: 'f'.repeat(64) };
  const settings = { logpush: false, observability: { enabled: false }, tags: ['ankka-mcp-gateway', context.installationId, source.id, `bigquery:${'9'.repeat(64)}`],
    bindings: [...Object.entries(variables).map(([name, text]) => ({ name, text, type: 'plain_text' })), { name: 'PROVIDER_TOKEN', type: 'secret_text' }] };
  const domain = { id: 'bridge-domain', hostname: names.hostname, service: names.workerName, zone_id: context.zoneId, environment: 'production' };
  const provider = { app, settings: partial ? null : settings, domain: partial ? null : domain,
    deployments: { deployments: [{ versions: [{ version_id: 'bridge-version', percentage: 100 }] }] },
    subdomain: { enabled: false, previews_enabled: false }, servers: [{ id: serverId, hostname: names.url }], extraDomains: [], serverPages: null };
  const requests = [];
  const deletions = [];
  let deletionCount = 0;
  let clock = 10_000;
  const fetch = async (input, init) => {
    const url = new URL(input);
    expect(url.origin).toBe('https://api.cloudflare.com');
    expect(url.pathname.startsWith(`/client/v4/accounts/${context.accountId}/`)).toBe(true);
    expect(new Headers(init.headers).get('Authorization')).toBe(`Bearer ${GRANT}`);
    const path = url.pathname.slice(`/client/v4/accounts/${context.accountId}`.length);
    const method = init.method;
    requests.push({ path, method });
    const property = path === '/workers/domains/bridge-domain' ? 'domain' :
      path === `/workers/scripts/${names.workerName}` ? 'settings' : path === '/access/apps/bridge-app' ? 'app' : null;
    if (method === 'DELETE') {
      expect(property).not.toBeNull();
      const journal = journalStorage ? await journalStorage.get(JOURNAL) : values.get(JOURNAL);
      expect(journal.pending).toMatchObject({ index: journal.removed });
      expect(provider.app).not.toBeNull();
      if (property === 'app') { expect(provider.domain).toBeNull(); expect(provider.settings).toBeNull(); }
      if (property === 'settings') expect(provider.domain).toBeNull();
      const lose = deletionCount++ === lostDelete;
      if (!lose || applied) { provider[property] = null; deletions.push(property); }
      if (lose) throw new Error('synthetic lost response');
      return Response.json({ success: true });
    }
    let result;
    if (path === '/access/ai-controls/mcp/servers') result = provider.servers;
    else if (path === '/workers/domains') result = [...(provider.domain ? [provider.domain] : []), ...provider.extraDomains];
    else if (path === `/workers/scripts/${names.workerName}/settings`) result = provider.settings;
    else if (path === `/workers/scripts/${names.workerName}/deployments`) result = provider.deployments;
    else if (path === `/workers/scripts/${names.workerName}/subdomain`) result = provider.subdomain;
    else if (property) result = provider[property];
    else throw new Error('unexpected synthetic destination');
    if (path === '/access/ai-controls/mcp/servers' && provider.serverPages !== null) {
      const page = Number(url.searchParams.get('page'));
      return Response.json({ success: true, result: provider.serverPages[page - 1], result_info: { page, total_pages: provider.serverPages.length } });
    }
    return result === null ? new Response(null, { status: 404 }) : Response.json({ success: true, result });
  };
  const manager = createBigQueryTeardown(context, { storage, fetch, now: () => clock });
  return { storage, fetch, describe: () => manager.describe(snapshot), snapshot, record, key, values, provider, requests, writes, deletions, serverId,
    expire: () => { clock = 30_000; } };
}
