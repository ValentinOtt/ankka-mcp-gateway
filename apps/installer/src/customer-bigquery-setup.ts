import * as v from 'valibot';
import type { BoundaryObject } from './boundary';
import type { ExactReleaseBundleIdentity } from './exact-release-bundle';
import { canonicalJson } from './canonical-json';
import { base64UrlEncode, randomBase64Url } from './crypto';
import { operationSignature } from './customer-operation-secrets';
import { BIGQUERY_SETUP_TOOLS, bigQueryHex, bigQueryPrepareSchema, bigQueryRecordSchema,
  bigQueryResumeSchema, bigQuerySourceNames, readBigQueryText, type BigQueryRecord } from './customer-bigquery-contract';
import { deployBigQueryBridge, type BigQueryDeploymentContext } from './customer-bigquery-deployment';

const PREFIX = 'ankka-mcp-gateway/bigquery-source/v1/';
const sourceSchema = v.object({ id: v.string(), label: v.string(), url: v.string(),
  authMode: v.picklist(['none', 'oauth']), onBehalfOfUser: v.boolean(), enabledTools: v.array(v.string()),
  status: v.picklist(['installed', 'draft']) });
const sourcesSchema = v.object({ revision: v.number(), sources: v.array(sourceSchema) });
const actionSchema = v.object({ actionId: v.string(), sourceId: v.string(), status: v.string(), expiresAt: v.string() });
const snapshotSchema = v.object({ actions: v.array(v.object({ ...actionSchema.entries,
  canCancel: v.boolean(), canRenew: v.optional(v.boolean()), failureCode: v.nullable(v.string()),
})), blockingAction: v.nullable(v.object({ actionId: v.string(), kind: v.string() })) });

export interface BigQuerySetupContext extends BigQueryDeploymentContext {
  readonly zoneName: string;
  readonly managementOrigin: string;
  readonly workerName: string;
  readonly workersSubdomain: string;
  readonly controlPlaneOrigin: string;
  readonly releaseIdentity: ExactReleaseBundleIdentity;
}
export interface BigQuerySetupPort {
  readonly storage: Pick<DurableObjectStorage, 'get' | 'put' | 'list'>;
  readonly runtime: (request: Request) => Promise<Response>;
  readonly fetch: typeof globalThis.fetch;
  readonly runtimeSource?: string;
  readonly now?: () => number;
}
export interface BigQueryOperationInput {
  readonly actionId: string;
  readonly actionKey: string;
  readonly actorEmail: string;
  readonly accessToken: string;
  readonly actionExpiresAt: number;
  readonly serviceAccountJson: string;
}

function json(value: BoundaryObject, status = 200) {
  return Response.json(value, { status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
}
export function createBigQuerySetup(context: BigQuerySetupContext, port: BigQuerySetupPort) {
  const now = port.now ?? Date.now;
  async function runtime(path: string, method = 'GET', input?: BoundaryObject, actorEmail?: string) {
    const headers = new Headers({ 'Content-Type': 'application/json' });
    if (actorEmail !== undefined) headers.set('x-ankka-actor-email', actorEmail);
    const init: RequestInit = { method, headers };
    if (input !== undefined) init.body = canonicalJson(input);
    return port.runtime(new Request(`https://admin-state.invalid${path}`, init));
  }
  async function readRecord(sourceId: string) {
    const raw = await port.storage.get(PREFIX + sourceId);
    if (raw === undefined) return null;
    return v.parse(bigQueryRecordSchema, raw);
  }
  async function save(record: BigQueryRecord) {
    await port.storage.put(PREFIX + record.sourceId, v.parse(bigQueryRecordSchema, record));
  }
  async function readSourceAction(actionId: string) {
    const response = await runtime(`/source-actions/${actionId}`);
    if (response.status !== 200) return null;
    const action = v.parse(actionSchema, await response.json());
    const record = await readRecord(action.sourceId);
    return record?.actionId === actionId ? { action, record } : null;
  }
  async function prepare(request: Request, actorEmail: string, resume: boolean): Promise<Response> {
    const body: unknown = JSON.parse(await readBigQueryText(request.body));
    const sourceResponse = await runtime('/sources');
    if (!sourceResponse.ok) return sourceResponse;
    let sources = v.parse(sourcesSchema, await sourceResponse.json());
    const actionsResponse = await runtime('/source-actions', 'GET', undefined, actorEmail);
    if (!actionsResponse.ok) return actionsResponse;
    const snapshot = v.parse(snapshotSchema, await actionsResponse.json());
    let record: BigQueryRecord;
    let existingActionId: string | null = null;
    if (resume) {
      const input = v.parse(bigQueryResumeSchema, body);
      const existing = await readSourceAction(input.actionId);
      const current = snapshot.actions.find((action) => action.actionId === input.actionId);
      if (!existing || existing.record.operatorEmail !== actorEmail || !current || existing.record.pending !== null ||
          (snapshot.blockingAction !== null && snapshot.blockingAction.actionId !== input.actionId)) {
        return json({ error: 'bigquery_setup_conflict' }, 409);
      }
      record = existing.record;
      if (current.canCancel) {
        const cancelled = await runtime(`/source-actions/${input.actionId}`, 'DELETE', { actorEmail, now: now() });
        if (!cancelled.ok) return cancelled;
      } else if (current.status === 'failed' && record.application === null && record.workerVersion === null && record.domainId === null) {
        // A cancelled, definitely-unstarted setup can prepare a new action.
      } else {
        if (current.canRenew !== true) return json({ error: 'bigquery_setup_conflict' }, 409);
        existingActionId = input.actionId;
      }
    } else {
      const input = v.parse(bigQueryPrepareSchema, body);
      if (snapshot.blockingAction !== null || input.revision !== sources.revision) return json({ error: 'bigquery_setup_conflict' }, 409);
      const names = await bigQuerySourceNames(context.installationId, context.zoneName, input.configuration);
      const retained = await readRecord(names.sourceId);
      if (retained !== null && (retained.application !== null || retained.pending !== null)) return json({ error: 'bigquery_setup_conflict' }, 409);
      const saved = await runtime('/sources', 'PUT', { schemaVersion: 1, revision: sources.revision,
        source: { label: input.label, url: names.url, authMode: 'oauth', enabledTools: [...BIGQUERY_SETUP_TOOLS] } });
      if (!saved.ok) return saved;
      sources = v.parse(sourcesSchema, await saved.json());
      record = { schemaVersion: 1, sourceId: names.sourceId, actionId: `action_${randomBase64Url(24)}`,
        configuration: names.configuration, workerName: names.workerName, hostname: names.hostname,
        operatorEmail: actorEmail, sourceHash: `sha256:${'0'.repeat(64)}`,
        application: null, workerVersion: null, domainId: null, pending: null, ready: false };
    }
    const source = sources.sources.find((item) => item.id === record.sourceId);
    if (!source || source.status !== 'draft' || source.url !== `https://${record.hostname}/mcp`) return json({ error: 'bigquery_setup_conflict' }, 409);
    const sourceHash = `sha256:${await bigQueryHex(canonicalJson({ id: source.id, label: source.label,
      url: source.url, authMode: source.authMode, onBehalfOfUser: source.onBehalfOfUser, enabledTools: source.enabledTools }))}`;
    if (resume && sourceHash !== record.sourceHash) return json({ error: 'bigquery_setup_conflict' }, 409);
    const actionId = existingActionId ?? `action_${randomBase64Url(24)}`;
    const actionKey = randomBase64Url(32);
    const issuedAt = now();
    const expiresAt = issuedAt + 10 * 60 * 1_000;
    const path = existingActionId === null ? '/source-actions' : `/source-actions/${existingActionId}/renew`;
    await save({ ...record, actionId, sourceHash });
    const prepared = await runtime(path, 'POST', { schemaVersion: 1, actionId, sourceId: source.id,
      sourceRevision: sources.revision, actorEmail, issuedAt, expiresAt,
      actionKeyHash: `sha256:${await bigQueryHex(actionKey)}`, sourceHash });
    if (!prepared.ok) return prepared;
    const claim = { schemaVersion: 1, actionType: 'bigquery_setup', actionId, actionKey, actorEmail,
      accountId: context.accountId, controlPlaneOrigin: context.controlPlaneOrigin, workerName: context.workerName,
      workersSubdomain: context.workersSubdomain, managementOrigin: context.managementOrigin,
      releaseIdentity: context.releaseIdentity, expiresAt };
    return json({ schemaVersion: 1, actionId, sourceId: source.id, expiresAt: new Date(expiresAt).toISOString(),
      handoffUrl: `${context.managementOrigin}/__ankka/operation#${base64UrlEncode(new TextEncoder().encode(canonicalJson(claim)))}` });
  }
  async function run(input: BigQueryOperationInput): Promise<Response> {
    const current = await readSourceAction(input.actionId);
    if (!current || current.record.operatorEmail !== input.actorEmail || current.action.status !== 'authorization_required' ||
        Date.parse(current.action.expiresAt) !== input.actionExpiresAt || input.actionExpiresAt <= now()) {
      return json({ error: 'bigquery_setup_conflict' }, 409);
    }
    const baseClaim = { schemaVersion: 1, actionId: input.actionId, actionKey: input.actionKey,
      actorEmail: input.actorEmail, accountId: context.accountId, issuedAt: now(), expiresAt: input.actionExpiresAt,
      cloudflareAccessToken: input.accessToken };
    async function signed(path: string, value: BoundaryObject) {
      const body = canonicalJson(value);
      return port.runtime(new Request(`https://admin-state.invalid/source-actions/${path}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'x-ankka-source-action-signature': await operationSignature(input.actionKey, body) }, body,
      }));
    }
    const assertActive = async () => {
      const latest = await readSourceAction(input.actionId);
      if (!latest || input.actionExpiresAt <= now() || Date.parse(latest.action.expiresAt) !== input.actionExpiresAt ||
          !['authorization_required', 'applying'].includes(latest.action.status)) throw new Error('bigquery_setup_conflict');
    };
    let began = false;
    try {
      const deploymentPort = { fetch: port.fetch, save, assertActive, begin: async () => {
        const response = await signed('bigquery', { ...baseClaim, bigqueryPhase: 'start' });
        if (!response.ok) throw new Error('bigquery_setup_conflict');
        began = true;
      } };
      await deployBigQueryBridge(current.record, context, input.accessToken, input.serviceAccountJson,
        port.runtimeSource === undefined ? deploymentPort : { ...deploymentPort, runtimeSource: port.runtimeSource });
      await assertActive();
      return await signed('apply', baseClaim);
    } catch (error) {
      if (began) await signed('bigquery', { ...baseClaim, bigqueryPhase: 'failed' });
      const allowed = ['bigquery_resource_uncertain', 'bigquery_resource_collision', 'bigquery_google_connection_failed'];
      const code = error instanceof Error && allowed.includes(error.message) ? error.message : 'bigquery_setup_failed';
      return json({ error: code }, 409);
    }
  }
  async function list() {
    const entries = await port.storage.list({ prefix: PREFIX, limit: 32 });
    const setups = [...entries.values()].map((raw) => v.parse(bigQueryRecordSchema, raw)).map((record) => ({
      sourceId: record.sourceId, actionId: record.actionId, ready: record.ready,
      credentialRequired: record.workerVersion === null, recoveryRequired: record.pending !== null,
      pendingResource: record.pending, failure: record.failure ?? null,
    }));
    return json({ schemaVersion: 1, available: true, setups });
  }
  return { prepare, run, list, readSourceAction };
}
