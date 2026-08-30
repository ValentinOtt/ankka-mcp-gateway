import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { parseSourceSave, saveDraftSource } from '../payload/worker/index.js';
import { canonicalJson, prefixedSha256 } from './payload-lifecycle.mjs';

const SOURCES_KEY = 'ankka-mcp-gateway/management-sources/v1';
const CONTROL_KEY = 'ankka-mcp-gateway/management-control/v1';
const TEAM_KEY = 'ankka-mcp-gateway/team-access/v1';

async function resourceKey(prefix, installationId, logicalId) {
  const digest = (await prefixedSha256({ installationId, prefix, logicalId })).slice('sha256:'.length);
  const hint = logicalId.toLowerCase().replace(/[^a-z0-9-]+/gu, '-').replace(/^-+|-+$/gu, '');
  const hintLength = Math.max(0, 32 - prefix.length - 10);
  return hint && hintLength > 0
    ? `${prefix}-${hint.slice(0, hintLength)}-${digest.slice(0, 8)}`
    : `${prefix}-${digest.slice(0, 32 - prefix.length - 1)}`;
}

/**
 * Synthetic historical day-two snapshot, before native Team state existed.
 * Current source-installation routes remain paused: this creates no handoff and
 * calls no provider API. Original bootstrap receipt, IDs and ownership hashes
 * are not rewritten. The historical source owns its independently derived
 * three-resource graph and exact original shared email audience.
 */
export async function addHistoricalInstalledSource(gateway, {
  label = 'Approved catalogue',
  url = 'https://catalog.example.net/mcp',
  authMode = 'none',
  enabledTools = ['company_lookup'],
} = {}) {
  const storage = gateway.env.ADMIN_STATE.objects.get('v1:management').storage;
  assert.equal(storage.snapshot(TEAM_KEY), undefined, 'historical snapshot must predate native Team state');
  const originalReceipt = canonicalJson(gateway.storage.snapshot());
  const current = storage.snapshot(SOURCES_KEY);
  const control = storage.snapshot(CONTROL_KEY);
  const saved = await saveDraftSource(current, parseSourceSave({
    schemaVersion: 1, revision: current.revision, source: { label, url, authMode, enabledTools },
  }));
  assert.ok(saved);
  const source = { ...saved.sources.find((candidate) => candidate.url === url), status: 'installed' };
  const installationId = control.installationId;
  const [mcpKey, applicationKey, policyKey] = await Promise.all(
    ['mcp', 'source-app', 'source-access'].map((prefix) => resourceKey(prefix, installationId, source.id)),
  );
  const applicationId = createHash('sha256').update(`${source.id}:historical-application`).digest('hex').slice(0, 32);
  const policyId = createHash('sha256').update(`${source.id}:historical-policy`).digest('hex').slice(0, 32);
  const metadata = { manager: 'ankka-mcp-gateway', installationId };
  const identityHash = await prefixedSha256({ emails: control.audienceEmails });
  const specifications = [
    { kind: 'mcp_server', key: mcpKey, desired: {
      metadata, sourceId: source.id, name: source.label, endpoint: source.url,
      capabilityMode: 'read_only', secureWebGateway: false,
      toolPolicy: { defaultDisabled: true, allowedTools: source.enabledTools },
      authentication: { mode: source.authMode, onBehalfOfUser: false, credentialCustody: 'customer' },
    } },
    { kind: 'source_access_application', key: applicationKey, desired: {
      metadata, sourceResourceKey: mcpKey, applicationType: 'mcp',
    } },
    { kind: 'source_access_policy', key: policyKey, desired: {
      metadata, sourceApplicationResourceKey: applicationKey, defaultAction: 'deny',
      allow: { identitiesRef: 'access.allowedEmails', identityType: 'email',
        identityCount: control.audienceEmails.length, identitiesHash: identityHash },
    } },
  ];
  const providers = [{ id: mcpKey }, { id: applicationId }, { id: policyId, parentId: applicationId }];
  const resources = await Promise.all(specifications.map(async (specification, index) => {
    const resource = {
      kind: specification.kind, key: specification.key, provider: providers[index],
      desiredHash: await prefixedSha256({ schemaVersion: 1, ...specification }),
      marker: `acg:v1:${installationId}:${specification.key}`,
    };
    if (index === 2) resource.identityHash = identityHash;
    return resource;
  }));
  assert.equal(gateway.provider.state.servers.has(mcpKey), false);
  assert.equal(gateway.provider.state.apps.has(applicationId), false);
  const server = {
    id: mcpKey, name: source.label, hostname: source.url,
    auth_type: authMode === 'oauth' ? 'oauth' : 'unauthenticated', secure_web_gateway: false,
    description: resources[0].marker, status: 'ready',
    updated_tools: source.enabledTools.map((name) => ({ name, enabled: true })),
  };
  if (authMode === 'oauth') server.is_shared_oauth_callback_enabled = true;
  const application = { id: applicationId, name: resources[1].marker, type: 'mcp',
    destinations: [{ type: 'via_mcp_server_portal', mcp_server_id: mcpKey }] };
  const policy = { id: policyId, name: `${source.label} users [${resources[2].marker}]`,
    decision: 'allow', include: control.audienceEmails.map((email) => ({ email: { email } })),
    exclude: [], require: [] };
  gateway.provider.state.servers.set(server.id, server);
  gateway.provider.state.server ??= server;
  gateway.provider.state.apps.set(application.id, application);
  gateway.provider.state.policies.set(application.id, [policy]);
  const sourceOwnership = [...control.sourceOwnership, { sourceId: source.id, resources }];
  const sources = saved.sources.map((candidate) => candidate.id === source.id ? source : candidate);
  gateway.provider.state.portal.servers = [...sourceOwnership]
    .sort((left, right) => left.sourceId.localeCompare(right.sourceId))
    .map((entry) => {
      const owned = sources.find((candidate) => candidate.id === entry.sourceId);
      assert.ok(owned);
      return { server_id: entry.resources[0].provider.id, default_disabled: true,
        on_behalf: owned.onBehalfOfUser,
        updated_tools: owned.enabledTools.map((name) => ({ name, enabled: true })) };
    });
  await storage.put(CONTROL_KEY, { ...control, sourceOwnership });
  await storage.put(SOURCES_KEY, { ...saved, revision: saved.revision + 1, sources });
  assert.equal(storage.snapshot(TEAM_KEY), undefined);
  assert.equal(canonicalJson(gateway.storage.snapshot()), originalReceipt);
  return { source, server, application, policy, resources };
}
