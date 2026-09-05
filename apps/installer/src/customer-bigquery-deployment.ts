import * as v from 'valibot';
import { createGoogleAuthorization } from '../../read-only-connectors/src/google-auth';
import { boundaryValueSchema, type BoundaryValue } from './boundary';
import { canonicalJson } from './canonical-json';
import { bigQueryHex, readBigQueryText, type BigQueryRecord } from './customer-bigquery-contract';

declare const __ANKKA_BIGQUERY_RUNTIME_SOURCE__: string;
export function bigQuerySetupAvailable(): boolean {
  // This build-time constant is absent in an unbundled runtime; no external value is being narrowed.
  // oxlint-disable-next-line anti-slop/no-runtime-typeof
  return typeof __ANKKA_BIGQUERY_RUNTIME_SOURCE__ === 'string' && __ANKKA_BIGQUERY_RUNTIME_SOURCE__.length > 0;
}
const identifier = v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{1,128}$/u));
const applicationSchema = v.looseObject({ id: identifier, aud: v.pipe(v.string(), v.regex(/^[a-f0-9]{64}$/u)),
  name: v.string(), domain: v.string(), type: v.literal('self_hosted'),
  oauth_configuration: v.object({ enabled: v.literal(true), dynamic_client_registration: v.object({
    enabled: v.literal(true), allowed_uris: v.array(v.string()),
    allow_any_on_localhost: v.literal(false), allow_any_on_loopback: v.literal(false),
  }), grant: v.object({ access_token_lifetime: v.literal('15m'), session_duration: v.literal('336h') }) }),
  policies: v.array(v.looseObject({ decision: v.string(), include: v.array(v.unknown()), exclude: v.optional(v.array(v.unknown()), []), require: v.optional(v.array(v.unknown()), []) })),
});
const bindingsSchema = v.array(v.looseObject({ name: v.string(), type: v.string(), text: v.optional(v.string()) }));
const settingsSchema = v.looseObject({ bindings: bindingsSchema, tags: v.array(v.string()),
  logpush: v.optional(v.boolean()), observability: v.optional(v.looseObject({ enabled: v.boolean() })),
});
const domainSchema = v.looseObject({ id: identifier, hostname: v.string(), service: v.string(),
  zone_id: v.string(), environment: v.string() });
const deploymentSchema = v.looseObject({ deployments: v.array(v.looseObject({
  versions: v.array(v.strictObject({ version_id: identifier, percentage: v.number() })),
})) });
const envelopeSchema = v.looseObject({ success: v.literal(true), result: boundaryValueSchema });
const googleResult = v.object({ result: v.object({ isError: v.optional(v.boolean()),
  content: v.array(v.object({ type: v.literal('text'), text: v.string() })),
}) });
export interface BigQueryDeploymentContext {
  readonly accountId: string;
  readonly zoneId: string;
  readonly installationId: string;
  readonly accessIssuer: string;
}
export interface BigQueryDeploymentPort {
  readonly fetch: typeof globalThis.fetch;
  readonly save: (record: BigQueryRecord) => Promise<void>;
  readonly begin: () => Promise<void>;
  readonly assertActive: () => Promise<void>;
  /** Set only by a synthetic test; production receives the release's compiled module. */
  readonly runtimeSource?: string;
}

function failure(): never { throw new Error('bigquery_deployment_failed'); }

async function serverKey(installationId: string, sourceId: string): Promise<string> {
  const prefix = 'mcp';
  const digest = await bigQueryHex(canonicalJson({ installationId, prefix, logicalId: sourceId }));
  const hint = sourceId.slice(0, 32 - prefix.length - 10).replace(/-+$/u, '');
  return `${prefix}-${hint}-${digest.slice(0, 8)}`;
}

/** No Google credential leaves this gateway's request except the fixed Google exchange and its owned Worker upload. */
export async function deployBigQueryBridge(
  initial: BigQueryRecord, context: BigQueryDeploymentContext, accessToken: string,
  serviceAccountJson: string, port: BigQueryDeploymentPort,
): Promise<BigQueryRecord> {
  let record = initial;
  const base = `https://api.cloudflare.com/client/v4/accounts/${context.accountId}`;
  const workerPath = `/workers/scripts/${record.workerName}`;
  const callback = `https://dash.cloudflare.com/${context.accountId}/one/access-controls/ai-controls/mcp-server/oauth-callback/${await serverKey(context.installationId, record.sourceId)}`;
  const applicationName = `acg:v1:${context.installationId}:bigquery-${record.sourceId}`;
  const source = port.runtimeSource ?? (bigQuerySetupAvailable() ? __ANKKA_BIGQUERY_RUNTIME_SOURCE__ : '');
  if (source.length < 1 || new TextEncoder().encode(source).byteLength > 4 * 1024 * 1024 ||
      !/^[a-f0-9]{32}$/u.test(context.accountId) || !/^[a-f0-9]{32}$/u.test(context.zoneId) ||
      !/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/u.test(context.accessIssuer)) failure();
  const tags = ['ankka-mcp-gateway', context.installationId, record.sourceId, `bigquery:${await bigQueryHex(source)}`];
  async function api(path: string, method = 'GET', body?: string | FormData, allowAbsent = false): Promise<BoundaryValue> {
    await port.assertActive();
    const headers = new Headers({ Authorization: `Bearer ${accessToken}`, Accept: 'application/json' });
    if (body !== undefined && !(body instanceof FormData)) headers.set('Content-Type', 'application/json');
    const init: RequestInit = { method, headers, redirect: 'manual', signal: AbortSignal.timeout(15_000) };
    if (body !== undefined) init.body = body;
    const response = await port.fetch(base + path, init);
    if (allowAbsent && response.status === 404) { await response.body?.cancel(); return null; }
    if (!response.ok) { await response.body?.cancel(); failure(); }
    return v.parse(envelopeSchema, JSON.parse(await readBigQueryText(response.body, 256 * 1024))).result;
  }
  async function save(next: BigQueryRecord) { await port.assertActive(); await port.save(next); record = next; }
  async function arm(pending: BigQueryRecord['pending']) {
    if (record.pending !== null) throw new Error('bigquery_resource_uncertain');
    await save({ ...record, pending });
  }
  // A lost create response has no ownership receipt. Never adopt an object by its name alone.
  if (record.pending !== null) throw new Error('bigquery_resource_uncertain');
  await port.assertActive();
  if (record.workerVersion === null) {
    const authorize = createGoogleAuthorization(serviceAccountJson, 'bigquery');
    const googleHeaders = await authorize(port.fetch);
    const response = await port.fetch('https://bigquery.googleapis.com/mcp', {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(8_000),
      headers: { ...googleHeaders, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-06-18' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {
        name: 'execute_sql_readonly', arguments: { projectId: record.configuration.queryProjectId, query: 'SELECT 1 AS bridge_ok' },
      } }),
    });
    if (!response.ok) { await response.body?.cancel(); throw new Error('bigquery_google_connection_failed'); }
    const result = v.parse(googleResult, JSON.parse(await readBigQueryText(response.body, 512 * 1024))).result;
    const completed = v.safeParse(v.object({ jobComplete: v.literal(true), errors: v.optional(v.pipe(v.array(boundaryValueSchema), v.maxLength(0))) }), JSON.parse(result.content.map((part) => part.text).join('\n')));
    if (result.isError || !completed.success) throw new Error('bigquery_google_connection_failed');
  }
  await port.begin();
  const desiredApplication = { name: applicationName, type: 'self_hosted', domain: record.hostname,
    session_duration: '24h', app_launcher_visible: false,
    oauth_configuration: { enabled: true, dynamic_client_registration: { enabled: true,
      allow_any_on_localhost: false, allow_any_on_loopback: false, allowed_uris: [callback] },
      grant: { access_token_lifetime: '15m', session_duration: '336h' } },
    policies: [{ name: 'Gateway operator', decision: 'allow', include: [{ email: { email: record.operatorEmail } }], exclude: [], require: [] }],
  };
  if (record.application === null) {
    // Review the whole bounded listing before creating an Access application at this hostname.
    let complete = false;
    for (let page = 1; page <= 10; page++) {
      const apps = v.parse(v.array(v.looseObject({ name: v.string(), domain: v.optional(v.string()) })),
        await api(`/access/apps?per_page=100&page=${page}`));
      if (apps.some((app) => app.name === applicationName || app.domain === record.hostname)) throw new Error('bigquery_resource_collision');
      if (apps.length < 100) { complete = true; break; }
    }
    if (!complete) failure();
    await arm('application');
    const app = v.parse(v.looseObject({ id: identifier, aud: v.pipe(v.string(), v.regex(/^[a-f0-9]{64}$/u)) }),
      await api('/access/apps', 'POST', JSON.stringify(desiredApplication)));
    await save({ ...record, application: { id: app.id, audience: app.aud }, pending: null });
  }
  const application = record.application;
  if (application === null) failure();
  const observedApp = v.parse(applicationSchema, await api(`/access/apps/${application.id}`));
  if (observedApp.id !== application.id || observedApp.aud !== application.audience ||
      observedApp.name !== applicationName || observedApp.domain !== record.hostname ||
      canonicalJson(observedApp.oauth_configuration.dynamic_client_registration.allowed_uris) !== canonicalJson([callback]) ||
      observedApp.policies.length !== 1 || observedApp.policies[0]?.decision !== 'allow' ||
      canonicalJson(observedApp.policies[0].include) !== canonicalJson(desiredApplication.policies[0]?.include) ||
      observedApp.policies[0].exclude.length !== 0 || observedApp.policies[0].require.length !== 0) failure();
  const variables = { CONNECTOR_PROVIDER: 'bigquery-mcp',
    CONNECTOR_CONFIG_JSON: JSON.stringify({ ...record.configuration, allowQueries: true }),
    PUBLIC_ORIGIN: `https://${record.hostname}`, ACCESS_TEAM_DOMAIN: new URL(context.accessIssuer).hostname,
    ACCESS_AUD: application.audience };
  if (record.workerVersion === null) {
    if (await api(`${workerPath}/settings`, 'GET', undefined, true) !== null) throw new Error('bigquery_resource_collision');
    await arm('worker');
    const multipart = new FormData();
    multipart.set('metadata', new Blob([JSON.stringify({ main_module: 'index.js', compatibility_date: '2026-09-05',
      compatibility_flags: ['nodejs_compat'], tags, logpush: false, observability: { enabled: false },
      bindings: [...Object.entries(variables).map(([name, text]) => ({ name, type: 'plain_text', text })),
        { name: 'PROVIDER_TOKEN', type: 'secret_text', text: serviceAccountJson }],
    })], { type: 'application/json' }));
    multipart.set('index.js', new Blob([source], { type: 'application/javascript+module' }), 'index.js');
    await api(workerPath, 'PUT', multipart);
    const deployments = v.parse(deploymentSchema, await api(`${workerPath}/deployments`));
    const active = deployments.deployments[0];
    if (active?.versions.length !== 1 || active.versions[0]?.percentage !== 100) failure();
    await save({ ...record, workerVersion: active.versions[0].version_id, pending: null });
  }
  const currentDeployments = v.parse(deploymentSchema, await api(`${workerPath}/deployments`));
  const currentVersion = currentDeployments.deployments[0]?.versions;
  if (currentVersion?.length !== 1 || currentVersion[0]?.version_id !== record.workerVersion || currentVersion[0]?.percentage !== 100) failure();
  const settings = v.parse(settingsSchema, await api(`${workerPath}/settings`));
  if (settings.bindings.length !== Object.keys(variables).length + 1 || settings.logpush === true ||
      settings.observability?.enabled === true || canonicalJson([...settings.tags].sort()) !== canonicalJson([...tags].sort()) ||
      !Object.entries(variables).every(([name, text]) => settings.bindings.some((binding) => binding.name === name && binding.type === 'plain_text' && binding.text === text)) ||
      !settings.bindings.some((binding) => binding.name === 'PROVIDER_TOKEN' && binding.type === 'secret_text')) failure();
  await api(`${workerPath}/subdomain`, 'POST', JSON.stringify({ enabled: false, previews_enabled: false }));
  const disabled = v.parse(v.object({ enabled: v.literal(false), previews_enabled: v.literal(false) }), await api(`${workerPath}/subdomain`));
  if (disabled.enabled !== false) failure();
  if (record.domainId === null) {
    const domains = v.parse(v.array(domainSchema), await api('/workers/domains'));
    if (domains.some((domain) => domain.hostname === record.hostname)) throw new Error('bigquery_resource_collision');
    await arm('domain');
    const domain = v.parse(domainSchema, await api('/workers/domains', 'PUT', JSON.stringify({
      hostname: record.hostname, service: record.workerName, environment: 'production', zone_id: context.zoneId,
    })));
    if (domain.hostname !== record.hostname || domain.service !== record.workerName || domain.zone_id !== context.zoneId || domain.environment !== 'production') failure();
    await save({ ...record, domainId: domain.id, pending: null });
  }
  const domains = v.parse(v.array(domainSchema), await api('/workers/domains'));
  if (!domains.some((domain) => domain.id === record.domainId && domain.hostname === record.hostname &&
      domain.service === record.workerName && domain.zone_id === context.zoneId && domain.environment === 'production')) failure();
  await save({ ...record, ready: true });
  return record;
}
