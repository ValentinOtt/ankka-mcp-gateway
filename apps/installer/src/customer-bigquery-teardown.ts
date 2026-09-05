import * as v from 'valibot';
import { boundaryValueSchema } from './boundary';
import { canonicalJson } from './canonical-json';
import { BIGQUERY_SETUP_TOOLS, bigQueryHex, bigQueryRecordSchema, bigQuerySourceNames,
  readBigQueryText, type BigQueryRecord } from './customer-bigquery-contract';
import type { BigQueryDeploymentContext } from './customer-bigquery-deployment';

const PREFIX = 'ankka-mcp-gateway/bigquery-source/v1/';
const JOURNAL = 'ankka-mcp-gateway/bigquery-teardown/v1';
const PROGRESS = 'ankka-mcp-gateway/bigquery-teardown-progress/v1';
const id = v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{1,128}$/u));
const hash = v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u));
const requestId = v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{22}$/u));
const sourceSchema = v.object({ id: v.string(), label: v.string(), url: v.string(), authMode: v.string(),
  onBehalfOfUser: v.boolean(), enabledTools: v.array(v.string()), status: v.string() });
const snapshotSchema = v.object({ actions: v.array(v.object({ actionId: v.string(), sourceId: v.string(),
  sourceHash: hash, actorEmail: v.string(), bigquerySetupStarted: v.optional(v.literal(true)) })),
  sources: v.object({ sources: v.array(sourceSchema) }) });
const domainSchema = v.object({ id, hostname: v.string(), service: v.string(), zone_id: v.string(),
  environment: v.optional(v.literal('production'), 'production') });
const journalSchema = v.strictObject({ schemaVersion: v.literal(1), recordsHash: hash,
  removed: v.pipe(v.number(), v.safeInteger(), v.minValue(0)),
  pending: v.nullable(v.strictObject({ index: v.pipe(v.number(), v.safeInteger(), v.minValue(0)), requestId })),
});
type Journal = v.InferOutput<typeof journalSchema>;
const progressSchema = v.strictObject({ recordsHash: hash, requestId,
  phase: v.picklist(['preflight', 'remove', 'verify', 'complete']),
  checked: v.pipe(v.number(), v.safeInteger(), v.minValue(0)),
});
type Progress = v.InferOutput<typeof progressSchema>;
type Kind = 'worker_custom_domain' | 'worker' | 'access_application';
interface Resource { readonly record: BigQueryRecord; readonly kind: Kind; readonly path: string }
interface Grant { readonly accessToken: string; readonly expiresAt: number; readonly requestId: string }

function fail(): never { throw new Error('bigquery_teardown_unverified'); }
function same<Left, Right>(left: Left, right: Right) { return canonicalJson(left) === canonicalJson(right); }

/**
 * Only the compiled gateway supplies this constructor extension. It interprets
 * its own bridge receipts; an environment value or hosted claim cannot enable
 * cleanup in a runtime which does not understand them.
 */
export function createBigQueryTeardown(context: BigQueryDeploymentContext & { readonly zoneName: string }, port: {
  readonly storage: Pick<DurableObjectStorage, 'get' | 'put' | 'list'>;
  readonly fetch: typeof fetch;
  readonly now?: () => number;
}) {
  const now = port.now ?? Date.now;
  async function* storedRecords() {
    let startAfter: string | undefined;
    for (let page = 0; page < 16; page++) {
      const options: DurableObjectListOptions = { prefix: PREFIX, limit: 64 };
      if (startAfter !== undefined) options.startAfter = startAfter;
      const entries = await port.storage.list(options);
      for (const entry of entries) {
        if (startAfter !== undefined && entry[0] <= startAfter) fail();
        startAfter = entry[0];
        yield entry;
      }
      if (entries.size < 64) return;
    }
    fail();
  }
  async function describe<Input>(input: Input) {
    const snapshot = v.parse(snapshotSchema, input);
    const records: BigQueryRecord[] = [];
    const actionIds: string[] = [];
    for await (const [key, raw] of storedRecords()) {
      const record = v.parse(bigQueryRecordSchema, raw);
      const hasResources = record.application !== null || record.workerVersion !== null || record.domainId !== null;
      // Unknown creates have no receipt. A fresh grant cannot turn a matching
      // name into ownership; these require manual reconciliation in Cloudflare.
      if (key !== PREFIX + record.sourceId || record.pending !== null ||
          (record.workerVersion !== null && record.application === null) ||
          (record.domainId !== null && record.workerVersion === null) ||
          (record.ready && record.domainId === null)) fail();
      const action = snapshot.actions.find((entry) => entry.actionId === record.actionId && entry.sourceId === record.sourceId);
      const source = snapshot.sources.sources.find((entry) => entry.id === record.sourceId);
      // A discarded, definitely-unstarted draft has no provider resources.
      if (!hasResources && !record.ready && action?.bigquerySetupStarted !== true) continue;
      if (!source || (source.status !== 'installed' && !action) ||
          (action && (action.sourceHash !== record.sourceHash || action.actorEmail !== record.operatorEmail ||
            action.bigquerySetupStarted !== true))) fail();
      const names = await bigQuerySourceNames(context.installationId, context.zoneName, record.configuration);
      const { status: _status, ...sourceIdentity } = source;
      if (names.sourceId !== record.sourceId || names.workerName !== record.workerName || names.hostname !== record.hostname ||
          !same(names.configuration, record.configuration) || source.url !== names.url || source.authMode !== 'oauth' ||
          !same(source.enabledTools, BIGQUERY_SETUP_TOOLS) ||
          `sha256:${await bigQueryHex(canonicalJson(sourceIdentity))}` !== record.sourceHash) fail();
      records.push(record);
      if (records.length > 32) fail();
      if (action) actionIds.push(action.actionId);
    }
    if (snapshot.actions.some((action) => action.bigquerySetupStarted === true && !actionIds.includes(action.actionId))) fail();
    if (records.length === 0) return null;
    records.sort((a, b) => a.sourceId < b.sourceId ? -1 : 1);
    const resources: Resource[] = [];
    for (const record of records) {
      // Access remains until both the route and the Worker containing the key
      // have been removed and their absence has been read back.
      if (record.domainId !== null) resources.push({ record, kind: 'worker_custom_domain', path: `/workers/domains/${record.domainId}` });
      if (record.workerVersion !== null) resources.push({ record, kind: 'worker', path: `/workers/scripts/${record.workerName}` });
      if (record.application !== null) resources.push({ record, kind: 'access_application', path: `/access/apps/${record.application.id}` });
    }
    const recordsHash = `sha256:${await bigQueryHex(canonicalJson({ installationId: context.installationId, records }))}`;
    async function readJournal(): Promise<Journal> {
      const raw = await port.storage.get(JOURNAL);
      if (raw === undefined) return { schemaVersion: 1, recordsHash, removed: 0, pending: null };
      const journal = v.parse(journalSchema, raw);
      if (journal.recordsHash !== recordsHash || journal.removed > resources.length ||
          (journal.pending !== null && (journal.pending.index !== journal.removed || journal.removed === resources.length))) fail();
      return journal;
    }
    function active(grant: Grant) {
      if (grant.expiresAt <= now() || !v.is(requestId, grant.requestId)) fail();
    }
    async function apiResponse(path: string, grant: Grant, method = 'GET', allowAbsent = false) {
      active(grant);
      const response = await port.fetch(`https://api.cloudflare.com/client/v4/accounts/${context.accountId}${path}`, {
        method, redirect: 'manual', signal: AbortSignal.timeout(15_000),
        headers: { Authorization: `Bearer ${grant.accessToken}`, Accept: 'application/json' },
      });
      if (allowAbsent && response.status === 404) { await response.body?.cancel(); return null; }
      if (!response.ok) { await response.body?.cancel(); fail(); }
      return v.parse(v.object({ success: v.literal(true), result: v.optional(boundaryValueSchema),
        result_info: v.optional(v.object({ page: v.optional(v.number()), total_pages: v.optional(v.number()),
          per_page: v.optional(v.number()), total_count: v.optional(v.number()) })),
      }),
        JSON.parse(await readBigQueryText(response.body, 512 * 1024)));
    }
    async function api(path: string, grant: Grant, method = 'GET', allowAbsent = false) {
      const response = await apiResponse(path, grant, method, allowAbsent);
      return response === null ? null : response.result;
    }
    async function list(path: string, grant: Grant) {
      const results = [];
      for (let page = 1; page <= 10; page++) {
        const response = await apiResponse(`${path}?per_page=100&page=${page}`, grant);
        if (response === null) fail();
        const items = v.parse(v.pipe(v.array(boundaryValueSchema), v.maxLength(100)), response.result);
        results.push(...items);
        const info = response.result_info;
        if (info?.page !== undefined && info.page !== page) fail();
        if (info?.total_pages !== undefined) {
          if (page === 1 && items.length === 0 && info.total_pages === 0 && (info.total_count ?? 0) === 0) return results;
          if (!Number.isSafeInteger(info.total_pages) || info.total_pages < page || info.total_pages > 10) fail();
          if (info.total_pages === page) return results;
        } else if (items.length < 100) {
          if (info?.total_count !== undefined && info.total_count !== results.length) fail();
          return results;
        }
      }
      fail();
    }
    async function application(record: BigQueryRecord, grant: Grant) {
      if (record.application === null) fail();
      const raw = await api(`/access/apps/${record.application.id}`, grant, 'GET', true);
      if (raw === null) return false;
      const app = v.parse(v.object({ id, aud: v.string(), name: v.string(), domain: v.string(), type: v.literal('self_hosted'),
        destinations: v.optional(v.array(boundaryValueSchema), []), self_hosted_domains: v.optional(v.array(v.string()), []),
        oauth_configuration: v.object({ enabled: v.literal(true), dynamic_client_registration: v.object({
          enabled: v.literal(true), allowed_uris: v.array(v.string()), allow_any_on_localhost: v.literal(false), allow_any_on_loopback: v.literal(false),
        }), grant: v.object({ access_token_lifetime: v.literal('15m'), session_duration: v.literal('336h') }) }),
        policies: v.array(v.object({ decision: v.literal('allow'), include: v.array(boundaryValueSchema),
          exclude: v.optional(v.array(boundaryValueSchema), []), require: v.optional(v.array(boundaryValueSchema), []) })),
      }), raw);
      const digest = await bigQueryHex(canonicalJson({ installationId: context.installationId, prefix: 'mcp', logicalId: record.sourceId }));
      const serverKey = `mcp-${record.sourceId.slice(0, 19).replace(/-+$/u, '')}-${digest.slice(0, 8)}`;
      const callback = `https://dash.cloudflare.com/${context.accountId}/one/access-controls/ai-controls/mcp-server/oauth-callback/${serverKey}`;
      if (app.id !== record.application.id || app.aud !== record.application.audience || app.domain !== record.hostname ||
          app.name !== `acg:v1:${context.installationId}:bigquery-${record.sourceId}` ||
          !(app.destinations.length === 0 || same(app.destinations, [{ type: 'public', uri: record.hostname }])) ||
          !(app.self_hosted_domains.length === 0 || same(app.self_hosted_domains, [record.hostname])) ||
          !same(app.oauth_configuration.dynamic_client_registration.allowed_uris, [callback]) || app.policies.length !== 1 ||
          !same(app.policies[0]?.include, [{ email: { email: record.operatorEmail } }]) ||
          app.policies[0]?.exclude.length !== 0 || app.policies[0]?.require.length !== 0) fail();
      return true;
    }
    async function worker(record: BigQueryRecord, grant: Grant) {
      const path = `/workers/scripts/${record.workerName}`;
      const raw = await api(`${path}/settings`, grant, 'GET', true);
      if (raw === null) return false;
      const settings = v.parse(v.object({ bindings: v.array(v.object({ name: v.string(), type: v.string(), text: v.optional(v.string()) })),
        tags: v.array(v.string()), logpush: v.optional(v.boolean()), observability: v.optional(v.object({ enabled: v.boolean() })),
      }), raw);
      const expected = { CONNECTOR_PROVIDER: 'bigquery-mcp', CONNECTOR_CONFIG_JSON: JSON.stringify({ ...record.configuration, allowQueries: true }),
        PUBLIC_ORIGIN: `https://${record.hostname}`, ACCESS_TEAM_DOMAIN: new URL(context.accessIssuer).hostname, ACCESS_AUD: record.application?.audience };
      if (settings.bindings.length !== 6 || settings.logpush === true || settings.observability?.enabled === true ||
          !Object.entries(expected).every(([name, text]) => settings.bindings.some((binding) => binding.name === name && binding.type === 'plain_text' && binding.text === text)) ||
          !settings.bindings.some((binding) => binding.name === 'PROVIDER_TOKEN' && binding.type === 'secret_text' && binding.text === undefined) ||
          settings.tags.length !== 4 || !['ankka-mcp-gateway', context.installationId, record.sourceId].every((tag) => settings.tags.includes(tag)) ||
          settings.tags.filter((tag) => /^bigquery:[a-f0-9]{64}$/u.test(tag)).length !== 1) fail();
      const deployments = v.parse(v.object({ deployments: v.array(v.object({ versions: v.array(v.object({ version_id: id, percentage: v.number() })) })) }),
        await api(`${path}/deployments`, grant));
      const versions = deployments.deployments[0]?.versions;
      // Immutable version identity permits removal after a gateway upgrade,
      // without treating the new gateway's bundled bridge code as an old receipt.
      if (versions?.length !== 1 || versions[0]?.version_id !== record.workerVersion || versions[0]?.percentage !== 100) fail();
      v.parse(v.object({ enabled: v.literal(false), previews_enabled: v.literal(false) }), await api(`${path}/subdomain`, grant));
      return true;
    }
    async function read(resource: Resource, grant: Grant): Promise<boolean> {
      if (resource.kind === 'worker') return worker(resource.record, grant);
      if (resource.kind === 'access_application') return application(resource.record, grant);
      const raw = await api(resource.path, grant, 'GET', true);
      if (raw === null) return false;
      const domain = v.parse(domainSchema, raw);
      if (domain.id !== resource.record.domainId || domain.hostname !== resource.record.hostname ||
          domain.service !== resource.record.workerName || domain.zone_id !== context.zoneId) fail();
      return true;
    }
    async function unshared(grant: Grant, ownedServerIds: readonly string[]) {
      if (resources.length === 0) return;
      // The MCP catalogue is account-wide. An unowned server may refer to an
      // owned bridge even if it is attached to a different or no Portal.
      const seen = new Set<string>();
      const servers = v.parse(v.array(v.object({ id, hostname: v.string() })), await list('/access/ai-controls/mcp/servers', grant));
      for (const server of servers) {
        if (seen.has(server.id)) fail();
        seen.add(server.id);
        const hostname = new URL(server.hostname).hostname;
        if (records.some((record) => record.hostname === hostname) && !ownedServerIds.includes(server.id)) fail();
      }
      const domains = v.parse(v.array(domainSchema), await list('/workers/domains', grant));
      if (new Set(domains.map((domain) => domain.id)).size !== domains.length || domains.some((domain) =>
        records.some((record) => (domain.service === record.workerName || domain.hostname === record.hostname) &&
          (domain.id !== record.domainId || domain.service !== record.workerName || domain.hostname !== record.hostname || domain.zone_id !== context.zoneId)))) fail();
    }
    async function progress(grant: Grant): Promise<Progress> {
      active(grant);
      const raw = await port.storage.get(PROGRESS);
      if (raw === undefined) return { recordsHash, requestId: grant.requestId, phase: 'preflight', checked: 0 };
      const saved = v.parse(progressSchema, raw);
      if (saved.recordsHash !== recordsHash || saved.checked > records.length) fail();
      // A fresh consent proves the complete graph again, retaining only the
      // journaled deletion prefix and its one ambiguous boundary.
      return saved.requestId === grant.requestId ? saved :
        { recordsHash, requestId: grant.requestId, phase: 'preflight', checked: 0 };
    }
    async function saveProgress(next: Progress, journal: Journal) {
      await port.storage.put(PROGRESS, v.parse(progressSchema, next));
      return { complete: next.phase === 'complete', progress: `sha256:${await bigQueryHex(canonicalJson({ next, journal }))}`,
        recordsHash, removedResourceCount: resources.length };
    }
    async function checkRecord(record: BigQueryRecord, journal: Journal, grant: Grant) {
      // An application-only receipt proves that no Worker create was armed.
      // Refuse a later unreceipted Worker without adopting or deleting it.
      if (record.application !== null && record.workerVersion === null &&
          await api(`/workers/scripts/${record.workerName}/settings`, grant, 'GET', true) !== null) fail();
      for (let index = 0; index < resources.length; index++) {
        const resource = resources[index];
        if (!resource || resource.record.sourceId !== record.sourceId) continue;
        const present = await read(resource, grant);
        if (index < journal.removed ? present : (!present && journal.pending?.index !== index)) fail();
      }
    }
    async function preflight(grant: Grant, ownedServerIds: readonly string[]) {
      const journal = await readJournal();
      const current = await progress(grant);
      if (current.phase !== 'preflight') return { complete: true, progress: recordsHash };
      // At most 20 catalogue pages plus five resource reads in one pass.
      // The caller gives every pass its own Durable Object invocation.
      await unshared(grant, ownedServerIds);
      const record = records[current.checked];
      if (!record) fail();
      await checkRecord(record, journal, grant);
      const checked = current.checked + 1;
      const complete = checked === records.length;
      const result = await saveProgress({ ...current, checked, phase: complete ? 'remove' : 'preflight' }, journal);
      return { complete, progress: result.progress };
    }
    async function remove(grant: Grant, ownedServerIds: readonly string[]) {
      let journal = await readJournal();
      const current = await progress(grant);
      if (current.phase === 'preflight') fail();
      const save = async (next: Journal) => { await port.storage.put(JOURNAL, v.parse(journalSchema, next)); journal = next; };
      if (current.phase === 'complete') return saveProgress(current, journal);
      if (current.phase === 'remove' && journal.removed < resources.length) {
        const resource = resources[journal.removed];
        if (!resource) fail();
        // Recheck references immediately before each removal, including a
        // retry after an ambiguous DELETE. Never reuse the old callback grant.
        await unshared(grant, ownedServerIds);
        const present = await read(resource, grant);
        if (!present) {
          if (journal.pending?.index !== journal.removed) fail();
          await save({ ...journal, removed: journal.removed + 1, pending: null });
          return saveProgress(current, journal);
        }
        if (journal.pending?.requestId === grant.requestId) fail();
        // Removing protection requires a fresh proof that its Worker/key and
        // domain are absent, not just an earlier journal entry.
        if (resource.kind === 'access_application') {
          if (await api(`/workers/scripts/${resource.record.workerName}/settings`, grant, 'GET', true) !== null) fail();
          const domain = resources.find((entry) => entry.record.sourceId === resource.record.sourceId && entry.kind === 'worker_custom_domain');
          if (domain && await read(domain, grant)) fail();
        } else if (!await application(resource.record, grant)) fail();
        await save({ ...journal, pending: { index: journal.removed, requestId: grant.requestId } });
        await api(resource.path, grant, 'DELETE');
        if (await read(resource, grant)) fail();
        await save({ ...journal, removed: journal.removed + 1, pending: null });
        return saveProgress(current, journal);
      }
      // Completion requires every bridge's live absence. Verification itself
      // is bounded to one record per invocation, including after fresh consent.
      const checked = current.phase === 'remove' ? 0 : current.checked;
      const record = records[checked];
      if (!record) fail();
      await unshared(grant, ownedServerIds);
      await checkRecord(record, journal, grant);
      return saveProgress({ ...current, checked: checked + 1,
        phase: checked + 1 === records.length ? 'complete' : 'verify' }, journal);
    }
    // Even an application-only receipt requires the Workers family to prove
    // that the planned Worker is absent. A name without a version receipt
    // never authorizes deleting a Worker.
    const receiptResourceKinds = new Set(resources.map((resource) => resource.kind));
    if (resources.length > 0) receiptResourceKinds.add('worker');
    return { actionIds, recordsHash, receiptResourceKinds: [...receiptResourceKinds], preflight, remove };
  }
  return { describe, bounded: true };
}
