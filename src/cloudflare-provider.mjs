import { createCloudflareClient } from './cloudflare-client.mjs';
import { readCloudflareObservedState } from './cloudflare-observed.mjs';
import { buildGatewayDesiredState } from './plan.mjs';
import {
  ownershipMarker,
  validateInstallationReceipt,
} from './receipt.mjs';

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const RESOURCE_KEY = /^[a-z][a-z0-9-]{0,31}$/;
const DESIRED_HASH = /^sha256:[0-9a-f]{64}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PORTAL_CNAME_TARGET = 'gateway.agents.cloudflare.com';
const POLICY_KINDS = new Set(['source_access_policy', 'portal_access_policy']);
const RESOURCE_KINDS = new Set([
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
]);
const ACTIONS = new Set(['create', 'update', 'delete']);
const CLOUDFLARE_MUTATION_METHODS = new Set([
  'createMcpServer', 'updateMcpServer', 'deleteMcpServer', 'syncMcpServer',
  'createPortal', 'updatePortal', 'deletePortal',
  'createAccessApp', 'updateAccessApp', 'deleteAccessApp',
  'createAppPolicy', 'updateAppPolicy', 'deleteAppPolicy',
  'createDnsRecord', 'updateDnsRecord', 'deleteDnsRecord',
]);
const SAFE_CODES = new Set([
  'invalid_input',
  'target_mismatch',
  'unsupported_change',
  'ownership_conflict',
  'resource_collision',
  'immutable_server_drift',
  'authenticated_server_update_blocked',
  'source_authorization_required',
  'access_app_missing',
  'access_app_ambiguous',
  'access_app_shape_unsupported',
  'access_identity_mismatch',
  'invalid_provider_response',
  'sync_failed',
  'sync_timeout',
  'provider_read_failed',
  'provider_write_failed',
]);
/** A value-free error suitable for installer output and receipt recovery. */
export class CloudflareGatewayProviderError extends Error {
  constructor(code, { mutationOutcome } = {}) {
    const safeCode = SAFE_CODES.has(code) ? code : 'provider_write_failed';
    super(`Cloudflare gateway provider failed: code=${safeCode}`);
    this.name = 'CloudflareGatewayProviderError';
    this.code = safeCode;
    if (mutationOutcome === 'not_submitted') {
      Object.defineProperty(this, 'mutationOutcome', {
        value: 'not_submitted',
        enumerable: true,
        writable: false,
        configurable: false,
      });
    }
  }
}

/**
 * Bind the provider-neutral reconciler to one explicit Cloudflare account and
 * zone. The token and fetch implementation stay inside the returned closure.
 */
export function createCloudflareGatewayProvider(options = {}) {
  if (!isObject(options)) throw new TypeError('provider options must be an object');
  rejectUnknownKeys(options, [
    'token',
    'accountId',
    'zoneId',
    'fetchImpl',
    'delayImpl',
    'discoveryAttempts',
    'discoveryIntervalMs',
    'requestTimeoutMs',
  ]);
  const {
    token,
    accountId,
    zoneId,
    fetchImpl = globalThis.fetch,
    delayImpl = defaultDelay,
    discoveryAttempts = 30,
    discoveryIntervalMs = 1_000,
    requestTimeoutMs = 30_000,
  } = options;
  requireId(accountId);
  requireId(zoneId);
  if (typeof delayImpl !== 'function') throw new TypeError('delayImpl must be a function');
  if (!Number.isInteger(discoveryAttempts) || discoveryAttempts < 1 || discoveryAttempts > 120) {
    throw new TypeError('discoveryAttempts must be an integer from 1 to 120');
  }
  if (!Number.isInteger(discoveryIntervalMs) || discoveryIntervalMs < 0 || discoveryIntervalMs > 10_000) {
    throw new TypeError('discoveryIntervalMs must be an integer from 0 to 10000');
  }

  const cloudflare = createCloudflareClient({
    token,
    accountId,
    zoneId,
    fetchImpl,
    requestTimeoutMs,
  });
  const polling = { delayImpl, attempts: discoveryAttempts, intervalMs: discoveryIntervalMs };

  const readObservedState = (input = {}) =>
    readCloudflareObservedState({ ...input, cloudflare });

  const applyChange = async (input = {}) => {
    const mutationAttempt = { submitted: false };
    const applyCloudflare = trackCloudflareMutationAttempt(cloudflare, mutationAttempt);
    try {
      const mutation = await normalizeMutationInput(input, { accountId, zoneId });
      const result = await dispatchMutation(applyCloudflare, polling, mutation);
      return normalizeApplyMutationResult(mutation.change, result);
    } catch (error) {
      const code = error instanceof CloudflareGatewayProviderError
        ? error.code
        : 'provider_write_failed';
      throw new CloudflareGatewayProviderError(code, {
        mutationOutcome: mutationAttempt.submitted ? undefined : 'not_submitted',
      });
    }
  };

  const inspectCanaryResidue = async (input = {}) => {
    try {
      const signal = normalizeAbortSignal(input?.signal);
      const residueCloudflare = signal
        ? createCloudflareClient({
          token,
          accountId,
          zoneId,
          fetchImpl,
          signal,
          requestTimeoutMs,
        })
        : cloudflare;
      return await inspectResidue(residueCloudflare, input, { accountId, zoneId });
    } catch (error) {
      if (error instanceof CloudflareGatewayProviderError) throw error;
      throw new CloudflareGatewayProviderError('provider_read_failed');
    }
  };

  const inspectPendingPortalCreateRollback = async (input = {}) => {
    try {
      const mutation = await normalizePendingPortalCreateRollbackInput(
        input,
        { accountId, zoneId },
      );
      const sample = await readPendingPortalCreateRollbackSample(cloudflare, mutation);
      assertNoPendingPortalAppCandidates(sample);
      if (sample.portal === null) {
        await provePendingPortalCreateRollbackQuiet(cloudflare, polling, mutation);
        return Object.freeze({ status: 'already_absent', portalKey: mutation.change.key });
      }
      assertPendingPortalCreateShape(sample.portal, mutation);
      return Object.freeze({ status: 'ready', portalKey: mutation.change.key });
    } catch (error) {
      if (error instanceof CloudflareGatewayProviderError) throw error;
      throw new CloudflareGatewayProviderError('provider_read_failed');
    }
  };

  const rollbackPendingPortalCreate = async (input = {}) => {
    try {
      const mutation = await normalizePendingPortalCreateRollbackInput(
        input,
        { accountId, zoneId },
      );
      const first = await readPendingPortalCreateRollbackSample(cloudflare, mutation);
      assertNoPendingPortalAppCandidates(first);
      if (first.portal === null) {
        await provePendingPortalCreateRollbackQuiet(cloudflare, polling, mutation);
        return Object.freeze({
          status: 'already_absent',
          portalKey: mutation.change.key,
          deleteRequest: 'not_needed',
        });
      }
      assertPendingPortalCreateShape(first.portal, mutation);

      await polling.delayImpl(polling.intervalMs);
      const second = await readPendingPortalCreateRollbackSample(cloudflare, mutation);
      assertNoPendingPortalAppCandidates(second);
      if (second.portal === null) {
        await provePendingPortalCreateRollbackQuiet(cloudflare, polling, mutation);
        return Object.freeze({
          status: 'already_absent',
          portalKey: mutation.change.key,
          deleteRequest: 'not_needed',
        });
      }
      assertPendingPortalCreateShape(second.portal, mutation);

      let deleteRequest = 'confirmed';
      try {
        await cloudflare.deletePortal(mutation.change.key);
      } catch {
        // A transport or response failure does not establish whether the exact
        // DELETE reached Cloudflare. Prove the postcondition before reporting
        // the outcome; the receipt remains pending outside this provider hook.
        deleteRequest = 'outcome_unknown';
      }
      await provePendingPortalCreateRollbackQuiet(cloudflare, polling, mutation);
      return Object.freeze({
        status: 'rolled_back',
        portalKey: mutation.change.key,
        deleteRequest,
      });
    } catch (error) {
      if (error instanceof CloudflareGatewayProviderError) throw error;
      throw new CloudflareGatewayProviderError('provider_write_failed');
    }
  };

  return Object.freeze({
    readObservedState,
    applyChange,
    inspectCanaryResidue,
    inspectPendingPortalCreateRollback,
    rollbackPendingPortalCreate,
  });
}

function normalizeApplyMutationResult(change, result) {
  const returnsCreatedLocator = change.action === 'create'
    && change.kind === 'portal_access_application';
  if (!returnsCreatedLocator) {
    if (result !== undefined) fail('invalid_provider_response');
    return Object.freeze({ status: 'submitted' });
  }
  if (!isObject(result)
    || Object.keys(result).sort().join(',') !== 'provider'
    || !isObject(result.provider)
    || Object.keys(result.provider).sort().join(',') !== 'id'
    || !safeId(result.provider.id)) fail('invalid_provider_response');
  return Object.freeze({
    status: 'submitted',
    provider: Object.freeze({ id: result.provider.id }),
  });
}

function trackCloudflareMutationAttempt(cloudflare, attempt) {
  return Object.freeze(Object.fromEntries(
    Object.entries(cloudflare).map(([name, method]) => [
      name,
      CLOUDFLARE_MUTATION_METHODS.has(name)
        ? (...args) => {
          attempt.submitted = true;
          return method(...args);
        }
        : method,
    ]),
  ));
}

async function normalizePendingPortalCreateRollbackInput(input, boundTarget) {
  const mutation = await normalizeMutationInput(input, boundTarget);
  if (mutation.change.action !== 'create'
    || mutation.change.kind !== 'portal'
    || mutation.receipt.pending?.type !== 'apply') fail('invalid_input');
  if (input.target?.zoneName !== mutation.receipt.target.zoneName) fail('target_mismatch');
  if (mutation.receipt.resources.some((resource) =>
    ['portal', 'portal_access_application', 'portal_access_policy', 'dns_record']
      .includes(resource.kind))) {
    fail('ownership_conflict');
  }

  let desiredState;
  try {
    desiredState = await buildGatewayDesiredState(mutation.config, {
      target: input.target,
      access: mutation.access,
    });
  } catch {
    fail('invalid_input');
  }
  const desiredPortal = desiredState.resources.find((resource) =>
    resource.kind === 'portal' && resource.key === mutation.change.key);
  if (desiredState.installationId !== mutation.receipt.installationId
    || desiredPortal?.desiredHash !== mutation.change.desiredHash
    || canonicalJson(desiredPortal?.desired) !== canonicalJson(mutation.change.desired)
    || canonicalJson(desiredState.accessPolicy) !== canonicalJson(mutation.receipt.accessPolicy)) {
    fail('invalid_input');
  }
  assertPendingPortalRollbackReceiptTopology(desiredState.resources, mutation.receipt);

  return {
    ...mutation,
    expectedPortal: normalizePortalDesired(mutation.change.desired, mutation.marker),
  };
}

function assertPendingPortalRollbackReceiptTopology(desiredResources, receipt) {
  const portalIndex = desiredResources.findIndex((resource) => resource.kind === 'portal');
  if (portalIndex < 0 || receipt.resources.length !== portalIndex) fail('invalid_input');
  const lowerDesired = desiredResources.slice(0, portalIndex);
  for (const desired of lowerDesired) {
    const matches = receipt.resources.filter((owned) =>
      owned.kind === desired.kind && owned.key === desired.key);
    if (
      matches.length !== 1 ||
      matches[0].desiredHash !== desired.desiredHash ||
      matches[0].marker !== ownershipMarker(receipt.installationId, desired.key)
    ) {
      fail('invalid_input');
    }
    const owned = matches[0];
    if (desired.kind === 'mcp_server' && owned.provider.id !== desired.key) {
      fail('invalid_input');
    }
    if (
      desired.kind === 'source_access_application' &&
      receipt.resources.filter((candidate) =>
        candidate.kind === 'mcp_server' &&
        candidate.key === desired.desired.sourceResourceKey &&
        candidate.provider.id === desired.desired.sourceResourceKey).length !== 1
    ) {
      fail('invalid_input');
    }
    if (desired.kind === 'source_access_policy') {
      const parents = receipt.resources.filter((candidate) =>
        candidate.kind === 'source_access_application' &&
        candidate.key === desired.desired.sourceApplicationResourceKey);
      if (
        parents.length !== 1 ||
        owned.provider.parentId !== parents[0].provider.id ||
        owned.identityHash !== desired.desired.allow.identitiesHash
      ) {
        fail('invalid_input');
      }
    }
  }
}

async function readPendingPortalCreateRollbackSample(cloudflare, mutation) {
  const portal = await exactRead(
    () => cloudflare.getPortal(mutation.change.key),
    mutation.change.key,
  );
  const apps = await cloudflare.listAccessApps();
  if (!Array.isArray(apps)) fail('invalid_provider_response');
  const appCandidates = apps
    .filter((app) => isPortalAppCandidate(app, mutation.config.gateway.hostname))
    .map(requireAppId);
  const dnsRecords = await cloudflare.listDnsRecords({
    'name.exact': mutation.config.gateway.hostname,
    match: 'all',
  });
  if (!Array.isArray(dnsRecords)) fail('invalid_provider_response');
  return { portal, appCandidates, dnsRecords };
}

function assertNoPendingPortalAppCandidates(sample) {
  if (sample.appCandidates.length > 0 || sample.dnsRecords.length > 0) {
    fail('ownership_conflict');
  }
}

function assertPendingPortalCreateShape(portal, mutation) {
  const expected = mutation.expectedPortal;
  if (!portalMatchesExpected(portal, mutation.change.key, expected)) {
    fail('ownership_conflict');
  }
}

function portalMatchesExpected(portal, portalId, expected) {
  return portal.id === portalId
    && portal.name === expected.name
    && portal.hostname === expected.hostname
    && portal.code_mode === expected.code_mode
    && portal.secure_web_gateway === expected.secure_web_gateway
    && portal.description === expected.description
    && samePortalServers(portal.servers, expected.servers);
}

function samePortalServers(liveServers, expectedServers) {
  if (!Array.isArray(liveServers) || liveServers.length !== expectedServers.length) return false;
  return expectedServers.every((expected) => {
    const matches = liveServers.filter((live) =>
      (live?.server_id ?? live?.id) === expected.server_id);
    if (matches.length !== 1) return false;
    const live = matches[0];
    return live.default_disabled === expected.default_disabled
      && live.on_behalf === expected.on_behalf
      && optionalPromptsAreEmpty(live.updated_prompts)
      && sameEnabledPortalTools(live.updated_tools, expected.updated_tools);
  });
}

function sameEnabledPortalTools(liveTools, expectedTools) {
  if (!Array.isArray(liveTools)) return false;
  const liveEnabled = [];
  for (const tool of liveTools) {
    if (!isObject(tool) || typeof tool.name !== 'string' || typeof tool.enabled !== 'boolean') {
      return false;
    }
    if (tool.enabled) liveEnabled.push(tool.name);
  }
  const expectedEnabled = expectedTools
    .filter((tool) => tool.enabled === true)
    .map((tool) => tool.name);
  return sameTextSet(liveEnabled, expectedEnabled);
}

function optionalPromptsAreEmpty(value) {
  return value === undefined || (Array.isArray(value) && value.length === 0);
}

function sameTextSet(left, right) {
  return left.length === right.length
    && new Set(left).size === left.length
    && [...left].sort(compareText).every(
      (value, index) => value === [...right].sort(compareText)[index],
    );
}

async function provePendingPortalCreateRollbackQuiet(cloudflare, polling, mutation) {
  let everySampleQuiet = true;
  for (let attempt = 0; attempt < polling.attempts; attempt += 1) {
    const sample = await readPendingPortalCreateRollbackSample(cloudflare, mutation);
    assertNoPendingPortalAppCandidates(sample);
    if (sample.portal !== null) {
      assertPendingPortalCreateShape(sample.portal, mutation);
      everySampleQuiet = false;
    }
    if (attempt + 1 < polling.attempts) await polling.delayImpl(polling.intervalMs);
  }
  if (!everySampleQuiet) fail('sync_timeout');
}

async function normalizeMutationInput(input, boundTarget) {
  if (!isObject(input)) fail('invalid_input');
  rejectMutationKeys(input, ['change', 'receipt', 'config', 'target', 'access']);
  const { change, config, target, access } = input;
  const receipt = await validateReceipt(input.receipt);
  assertTarget(target, boundTarget, receipt.target);
  if (!isObject(config) || !isObject(config.gateway) || config.gateway.hostname !== receipt.target.hostname) {
    fail('invalid_input');
  }
  if (!isObject(change) || !ACTIONS.has(change.action) || !RESOURCE_KINDS.has(change.kind)) {
    fail('unsupported_change');
  }
  if (typeof change.key !== 'string' || !RESOURCE_KEY.test(change.key)) fail('invalid_input');
  if (!receipt.pending
    || receipt.pending.action !== change.action
    || receipt.pending.kind !== change.kind
    || receipt.pending.key !== change.key) fail('invalid_input');
  if (change.action !== 'delete') {
    if (!DESIRED_HASH.test(change.desiredHash) || !isObject(change.desired)) fail('invalid_input');
    if (change.desiredHash !== receipt.pending.expectedDesiredHash) fail('invalid_input');
    const computedDesiredHash = await hashCanonical({
      schemaVersion: 1,
      kind: change.kind,
      key: change.key,
      desired: change.desired,
    });
    if (computedDesiredHash !== change.desiredHash) fail('invalid_input');
    assertDesiredMetadata(change.desired, receipt.installationId);
  }
  let ownedResource;
  if (change.action !== 'create') {
    assertProviderLocator(change.kind, change.provider);
    if ((change.kind === 'mcp_server' || change.kind === 'portal')
      && change.provider.id !== change.key) fail('ownership_conflict');
    ownedResource = receipt.resources.find((resource) =>
      resource.kind === change.kind
      && resource.key === change.key
      && sameLocator(resource.provider, change.provider));
    if (!ownedResource) fail('ownership_conflict');
  }
  return {
    change,
    receipt,
    config,
    target,
    access,
    ownedResource,
    marker: ownershipMarker(receipt.installationId, change.key),
  };
}

async function dispatchMutation(cloudflare, polling, mutation) {
  const { change } = mutation;
  if (change.kind === 'mcp_server') return mutateServer(cloudflare, polling, mutation);
  if (change.kind === 'source_access_application') {
    return mutateSourceAccessApplication(cloudflare, polling, mutation);
  }
  if (change.kind === 'portal') return mutatePortal(cloudflare, polling, mutation);
  if (change.kind === 'portal_access_application') {
    return mutatePortalAccessApplication(cloudflare, polling, mutation);
  }
  if (POLICY_KINDS.has(change.kind)) return mutatePolicy(cloudflare, polling, mutation);
  if (change.kind === 'dns_record') return mutateDns(cloudflare, mutation);
  fail('unsupported_change');
}

async function mutateServer(cloudflare, polling, mutation) {
  const { change, marker } = mutation;
  if (change.action === 'delete') {
    const live = await exactRead(() => cloudflare.getMcpServer(change.provider.id), change.provider.id);
    if (live === null) {
      await assertNoServerAccessApplications(cloudflare, change.provider.id);
      return;
    }
    assertMarker(live.description, marker);
    await assertNoServerAccessApplications(cloudflare, change.provider.id);
    const confirmed = await exactRead(
      () => cloudflare.getMcpServer(change.provider.id),
      change.provider.id,
    );
    if (confirmed === null) fail('ownership_conflict');
    assertMarker(confirmed.description, marker);
    await assertNoServerAccessApplications(cloudflare, change.provider.id);
    await cloudflare.deleteMcpServer(change.provider.id);
    return;
  }

  const expected = normalizeServerDesired(change.desired, marker);
  if (change.action === 'create') {
    if (await cloudflare.getMcpServer(change.key) !== null) fail('resource_collision');
    // The desired-state contract intentionally contains no upstream secret.
    // OAuth administrative authorization and static credentials are completed
    // in Cloudflare, not inferred or forwarded by this adapter.
    if (expected.auth_type !== 'unauthenticated') fail('source_authorization_required');
    await assertNoAccessAppBaseline(
      cloudflare,
      (app) => isExactServerApp(app, change.key),
    );
    await cloudflare.createMcpServer({
      id: change.key,
      auth_type: expected.auth_type,
      hostname: expected.hostname,
      name: expected.name,
      description: marker,
      secure_web_gateway: false,
      updated_prompts: [],
      updated_tools: expected.updated_tools,
    });
  } else {
    const live = await exactRead(() => cloudflare.getMcpServer(change.provider.id), change.provider.id);
    if (live === null) fail('ownership_conflict');
    assertMarker(live.description, marker);
    if (live.hostname !== expected.hostname || live.auth_type !== expected.auth_type) {
      fail('immutable_server_drift');
    }
    if (live.auth_type !== 'unauthenticated') fail('authenticated_server_update_blocked');
  }

  await cloudflare.syncMcpServer(change.key);
  await waitForServerSync(cloudflare, polling, change.key, expected.updated_tools);
  await cloudflare.updateMcpServer(change.key, {
    name: expected.name,
    description: marker,
    secure_web_gateway: false,
    updated_prompts: [],
    updated_tools: expected.updated_tools,
  });
}

async function mutateSourceAccessApplication(cloudflare, polling, mutation) {
  const { change, marker } = mutation;
  if (change.action === 'delete') {
    let app = await exactRead(
      () => cloudflare.getAccessApp(change.provider.id),
      change.provider.id,
    );
    if (app === null) return;
    await assertSourceAccessApplicationAuthority(cloudflare, mutation, app, marker, {
      allowMissingServer: true,
    });
    await assertAccessApplicationPoliciesEmpty(cloudflare, app);
    app = await exactRead(() => cloudflare.getAccessApp(change.provider.id), change.provider.id);
    if (app === null) fail('ownership_conflict');
    await assertSourceAccessApplicationAuthority(cloudflare, mutation, app, marker, {
      allowMissingServer: true,
    });
    await assertAccessApplicationPoliciesEmpty(cloudflare, app);
    await cloudflare.deleteAccessApp(change.provider.id);
    await waitForAccessAppAbsence(cloudflare, polling, change.provider.id);
    return;
  }

  const expected = normalizeSourceAccessApplicationDesired(change.desired);
  const server = await assertReceiptOwnedServer(cloudflare, mutation, expected.sourceResourceKey);
  if (change.action === 'update') {
    const live = await exactRead(
      () => cloudflare.getAccessApp(change.provider.id),
      change.provider.id,
    );
    if (live === null || !isExactSourceAccessApplication(live, server.provider.id, marker)) {
      fail('ownership_conflict');
    }
    await assertAccessApplicationPoliciesEmpty(cloudflare, live);
    return;
  }

  const apps = await cloudflare.listAccessApps();
  if (!Array.isArray(apps)) fail('invalid_provider_response');
  if (apps.some((app) => app?.name === marker || isExactServerApp(app, server.provider.id))) {
    fail('resource_collision');
  }
  const created = await cloudflare.createAccessApp({
    name: marker,
    type: 'mcp',
    destinations: [{
      type: 'via_mcp_server_portal',
      mcp_server_id: server.provider.id,
    }],
  });
  const createdId = requireAppId(created).id;
  const live = await exactRead(() => cloudflare.getAccessApp(createdId), createdId);
  if (live === null || !isExactSourceAccessApplication(live, server.provider.id, marker)) {
    fail('ownership_conflict');
  }
  await assertReceiptOwnedServer(cloudflare, mutation, expected.sourceResourceKey);
  await assertAccessApplicationPoliciesEmpty(cloudflare, live);
}

async function mutatePortal(cloudflare, polling, mutation) {
  const { change, marker } = mutation;
  if (change.action === 'delete') {
    assertPortalApplicationReceiptAbsent(mutation.receipt);
    const live = await exactRead(() => cloudflare.getPortal(change.provider.id), change.provider.id);
    if (live === null) {
      await assertNoPortalAccessApplications(cloudflare, mutation.config.gateway.hostname);
      return;
    }
    assertMarker(live.description, marker);
    if (live.hostname !== mutation.config.gateway.hostname) fail('ownership_conflict');
    await assertNoPortalAccessApplications(cloudflare, mutation.config.gateway.hostname);
    const confirmed = await exactRead(
      () => cloudflare.getPortal(change.provider.id),
      change.provider.id,
    );
    if (confirmed === null
      || confirmed.hostname !== mutation.config.gateway.hostname) fail('ownership_conflict');
    assertMarker(confirmed.description, marker);
    assertPortalApplicationReceiptAbsent(mutation.receipt);
    await assertNoPortalAccessApplications(cloudflare, mutation.config.gateway.hostname);
    await cloudflare.deletePortal(change.provider.id);
    return;
  }
  const expected = normalizePortalDesired(change.desired, marker);
  if (change.action === 'create') {
    if (await cloudflare.getPortal(change.key) !== null) fail('resource_collision');
    await assertNoAccessAppBaseline(
      cloudflare,
      (app) => isPortalAppCandidate(app, mutation.config.gateway.hostname),
    );
    await cloudflare.createPortal({ id: change.key, ...expected });
    return;
  }
  const live = await exactRead(() => cloudflare.getPortal(change.provider.id), change.provider.id);
  if (live === null) fail('ownership_conflict');
  assertMarker(live.description, marker);
  if (live.hostname !== mutation.config.gateway.hostname) fail('ownership_conflict');
  await cloudflare.updatePortal(change.provider.id, expected);
}

async function mutatePortalAccessApplication(cloudflare, polling, mutation) {
  const { change, marker } = mutation;
  if (change.action === 'delete') {
    let app = await exactRead(
      () => cloudflare.getAccessApp(change.provider.id),
      change.provider.id,
    );
    if (app === null) {
      await assertPortalAccessApplicationCandidateSet(
        cloudflare,
        mutation.config.gateway.hostname,
        mutation.config.gateway.name,
        change.provider.id,
        { allowAbsent: true },
      );
      return;
    }
    await assertPortalAccessApplicationAuthority(cloudflare, mutation, app, marker, {
      allowMissingPortal: true,
    });
    await assertPortalAccessApplicationCandidateSet(
      cloudflare,
      mutation.config.gateway.hostname,
      mutation.config.gateway.name,
      change.provider.id,
    );
    await assertAccessApplicationPoliciesEmpty(cloudflare, app);

    app = await exactRead(() => cloudflare.getAccessApp(change.provider.id), change.provider.id);
    if (app === null) fail('ownership_conflict');
    await assertPortalAccessApplicationAuthority(cloudflare, mutation, app, marker, {
      allowMissingPortal: true,
    });
    await assertPortalAccessApplicationCandidateSet(
      cloudflare,
      mutation.config.gateway.hostname,
      mutation.config.gateway.name,
      change.provider.id,
    );
    await assertAccessApplicationPoliciesEmpty(cloudflare, app);
    await cloudflare.deleteAccessApp(change.provider.id);
    await waitForAccessAppAbsence(cloudflare, polling, change.provider.id);
    return;
  }

  const expected = normalizePortalAccessApplicationDesired(change.desired);
  const expectedPortal = await expectedPortalForApplicationMutation(
    mutation,
    expected.portalResourceKey,
  );
  await assertReceiptOwnedPortal(cloudflare, mutation, expected.portalResourceKey, {
    expected: expectedPortal,
  });
  if (change.action === 'create') {
    await provePortalAccessApplicationBaselineQuiet(
      cloudflare,
      polling,
      expected.body.domain,
    );
    await assertReceiptOwnedPortal(cloudflare, mutation, expected.portalResourceKey, {
      expected: expectedPortal,
    });
    const apps = await cloudflare.listAccessApps();
    if (!Array.isArray(apps)) fail('invalid_provider_response');
    if (apps.some((app) => app?.name === expected.body.name
      || isPortalAppCandidate(app, expected.body.domain))) {
      fail('resource_collision');
    }
    const created = await cloudflare.createAccessApp(expected.body);
    const createdId = requireAppId(created).id;
    const live = await exactRead(() => cloudflare.getAccessApp(createdId), createdId);
    if (live === null || !portalAccessApplicationPrePolicyMatches(live, expected.body)) {
      fail('ownership_conflict');
    }
    // The exact POST result and exact GET are the last fallible operations
    // before returning the markerless app's provenance. Later list/parent/
    // policy checks happen only after the reconciler has atomically committed
    // this ID, so eventual consistency or a late same-shaped app cannot strand
    // or replace the application we just created.
    return Object.freeze({ provider: Object.freeze({ id: createdId }) });
  }

  let live = await exactRead(() => cloudflare.getAccessApp(change.provider.id), change.provider.id);
  if (live === null || live.name !== expected.body.name
    || !portalAccessApplicationShapeMatches(live, expected.body.domain)) {
    fail('ownership_conflict');
  }
  await assertPortalAccessApplicationCandidateSet(
    cloudflare,
    expected.body.domain,
    expected.body.name,
    change.provider.id,
  );
  await assertPortalAccessApplicationPolicyPhase(cloudflare, mutation, live);
  live = await exactRead(() => cloudflare.getAccessApp(change.provider.id), change.provider.id);
  if (live === null || live.name !== expected.body.name
    || !portalAccessApplicationShapeMatches(live, expected.body.domain)) {
    fail('ownership_conflict');
  }
  await assertReceiptOwnedPortal(cloudflare, mutation, expected.portalResourceKey, {
    expected: expectedPortal,
  });
  await assertPortalAccessApplicationPolicyPhase(cloudflare, mutation, live);
  await cloudflare.updateAccessApp(change.provider.id, expected.body);
}

async function mutatePolicy(cloudflare, polling, mutation) {
  const { change, marker } = mutation;
  if (change.action === 'delete') {
    const parent = await assertPolicyParent(cloudflare, mutation, change.provider.parentId);
    const policies = await cloudflare.listAppPolicies(change.provider.parentId);
    assertInlinePolicySet(parent, policies);
    const listed = assertExpectedPolicySet(policies, change.provider.id, marker, { allowAbsent: true });
    if (listed === null) return;
    const live = await exactRead(
      () => cloudflare.getAppPolicy(change.provider.parentId, change.provider.id),
      change.provider.id,
    );
    if (live === null) fail('ownership_conflict');
    assertMarker(live.name, marker);
    const confirmedParent = await assertPolicyParent(
      cloudflare,
      mutation,
      change.provider.parentId,
    );
    if (POLICY_KINDS.has(change.kind)) {
      const confirmedPolicies = await cloudflare.listAppPolicies(change.provider.parentId);
      assertExpectedPolicySet(confirmedPolicies, change.provider.id, marker);
      assertInlinePolicySet(confirmedParent, confirmedPolicies);
    }
    await cloudflare.deleteAppPolicy(change.provider.parentId, change.provider.id);
    return;
  }

  const body = await normalizePolicyDesired(change.desired, mutation.access, marker);
  const parentId = change.action === 'create'
    ? await findPolicyParent(cloudflare, polling, mutation)
    : change.provider.parentId;
  let parent = await assertPolicyParent(cloudflare, mutation, parentId);

  if (change.action === 'create') {
    if (!inlinePoliciesAreEmpty(parent)) fail('ownership_conflict');
    let policies = await cloudflare.listAppPolicies(parentId);
    if (!Array.isArray(policies)) fail('invalid_provider_response');
    assertEmptyPolicySet(policies, marker);
    parent = await assertPolicyParent(cloudflare, mutation, parentId);
    if (!inlinePoliciesAreEmpty(parent)) fail('ownership_conflict');
    policies = await cloudflare.listAppPolicies(parentId);
    if (!Array.isArray(policies)) fail('invalid_provider_response');
    assertEmptyPolicySet(policies, marker);
    await cloudflare.createAppPolicy(parentId, body);
    return;
  }

  const policies = await cloudflare.listAppPolicies(parentId);
  assertExpectedPolicySet(policies, change.provider.id, marker);
  assertInlinePolicySet(parent, policies);
  const live = await exactRead(
    () => cloudflare.getAppPolicy(parentId, change.provider.id),
    change.provider.id,
  );
  if (live === null) fail('ownership_conflict');
  assertMarker(live.name, marker);
  parent = await assertPolicyParent(cloudflare, mutation, parentId);
  if (POLICY_KINDS.has(change.kind)) {
    const confirmedPolicies = await cloudflare.listAppPolicies(parentId);
    assertExpectedPolicySet(confirmedPolicies, change.provider.id, marker);
    assertInlinePolicySet(parent, confirmedPolicies);
  }
  await cloudflare.updateAppPolicy(parentId, change.provider.id, body);
}

function assertInlinePolicySet(app, policies) {
  if (!inlinePoliciesMatchListedPolicies(app, policies)) fail('ownership_conflict');
}

function assertEmptyPolicySet(policies, marker) {
  if (!Array.isArray(policies)) fail('invalid_provider_response');
  if (policies.length === 0) return;
  if (policies.some((policy) => policy?.name !== marker)) fail('ownership_conflict');
  fail('resource_collision');
}

function assertExpectedPolicySet(policies, id, marker, { allowAbsent = false } = {}) {
  if (!Array.isArray(policies)) fail('invalid_provider_response');
  const expected = policies.filter((policy) => policy?.id === id && policy?.name === marker);
  const unexpected = policies.filter((policy) => policy?.id !== id || policy?.name !== marker);
  if (unexpected.length > 0 || expected.length > 1) fail('ownership_conflict');
  if (expected.length === 0) {
    if (allowAbsent && policies.length === 0) return null;
    fail('ownership_conflict');
  }
  return expected[0];
}

async function mutateDns(cloudflare, mutation) {
  const { change, marker, config } = mutation;
  if (change.action === 'delete') {
    const live = await exactRead(() => cloudflare.getDnsRecord(change.provider.id), change.provider.id);
    if (live === null) return;
    assertMarker(live.comment, marker);
    if (normalizeDns(live.name) !== config.gateway.hostname) fail('ownership_conflict');
    await cloudflare.deleteDnsRecord(change.provider.id);
    return;
  }
  const body = normalizeDnsDesired(change.desired, marker, config.gateway.hostname);
  if (change.action === 'create') {
    await assertDnsDependencies(cloudflare, mutation, change.desired.dependsOnResourceKey);
    const collisions = await cloudflare.listDnsRecords({
      'name.exact': config.gateway.hostname,
      match: 'all',
    });
    if (!Array.isArray(collisions)) fail('invalid_provider_response');
    if (collisions.length > 0) fail('resource_collision');
    await assertDnsDependencies(cloudflare, mutation, change.desired.dependsOnResourceKey);
    await cloudflare.createDnsRecord(body);
    return;
  }
  await assertDnsDependencies(cloudflare, mutation, change.desired.dependsOnResourceKey);
  const live = await exactRead(() => cloudflare.getDnsRecord(change.provider.id), change.provider.id);
  if (live === null) fail('ownership_conflict');
  assertMarker(live.comment, marker);
  if (normalizeDns(live.name) !== config.gateway.hostname) fail('ownership_conflict');
  await assertDnsDependencies(cloudflare, mutation, change.desired.dependsOnResourceKey);
  await cloudflare.updateDnsRecord(change.provider.id, body);
}

async function assertDnsDependencies(cloudflare, mutation, portalKey) {
  let desiredState;
  try {
    desiredState = await buildGatewayDesiredState(mutation.config, {
      target: mutation.target,
      access: mutation.access,
    });
  } catch {
    fail('invalid_input');
  }
  const desiredDns = desiredState.resources.find((resource) =>
    resource.kind === 'dns_record' && resource.key === mutation.change.key);
  const desiredPortal = desiredState.resources.find((resource) =>
    resource.kind === 'portal' && resource.key === portalKey);
  const desiredApplication = desiredState.resources.find((resource) =>
    resource.kind === 'portal_access_application'
      && resource.desired.portalResourceKey === portalKey);
  const desiredPolicy = desiredState.resources.find((resource) =>
    resource.kind === 'portal_access_policy'
      && resource.desired.portalApplicationResourceKey === desiredApplication?.key);
  if (desiredState.installationId !== mutation.receipt.installationId
    || desiredDns?.desiredHash !== mutation.change.desiredHash
    || canonicalJson(desiredDns?.desired) !== canonicalJson(mutation.change.desired)
    || !desiredPortal || !desiredApplication || !desiredPolicy) fail('invalid_input');

  const receiptPortal = exactReceiptResource(mutation.receipt, desiredPortal);
  const receiptApplication = exactReceiptResource(mutation.receipt, desiredApplication);
  const receiptPolicy = exactReceiptResource(mutation.receipt, desiredPolicy);
  if (receiptPortal.provider.id !== desiredPortal.key
    || receiptPolicy.provider.parentId !== receiptApplication.provider.id
    || receiptPolicy.identityHash !== desiredPolicy.desired.allow.identitiesHash) {
    fail('ownership_conflict');
  }

  const expectedPortal = normalizePortalDesired(
    desiredPortal.desired,
    ownershipMarker(mutation.receipt.installationId, desiredPortal.key),
  );
  await assertReceiptOwnedPortal(cloudflare, mutation, desiredPortal.key, {
    expected: expectedPortal,
  });

  const expectedApplication = normalizePortalAccessApplicationDesired(
    desiredApplication.desired,
  ).body;
  const application = await exactRead(
    () => cloudflare.getAccessApp(receiptApplication.provider.id),
    receiptApplication.provider.id,
  );
  if (application === null || !portalAccessApplicationMatches(application, expectedApplication)) {
    fail('ownership_conflict');
  }
  await assertPortalAccessApplicationCandidateSet(
    cloudflare,
    expectedApplication.domain,
    expectedApplication.name,
    receiptApplication.provider.id,
  );

  const policyMarker = ownershipMarker(mutation.receipt.installationId, desiredPolicy.key);
  const policies = await cloudflare.listAppPolicies(receiptApplication.provider.id);
  assertExpectedPolicySet(policies, receiptPolicy.provider.id, policyMarker);
  if (!inlinePoliciesMatchListedPolicies(application, policies)) fail('ownership_conflict');
  const policy = await exactRead(
    () => cloudflare.getAppPolicy(receiptApplication.provider.id, receiptPolicy.provider.id),
    receiptPolicy.provider.id,
  );
  const expectedPolicy = await normalizePolicyDesired(
    desiredPolicy.desired,
    mutation.access,
    policyMarker,
  );
  if (policy === null || !accessPolicyMatches(policy, expectedPolicy)) {
    fail('ownership_conflict');
  }
}

function exactReceiptResource(receipt, desired) {
  const matches = receipt.resources.filter((resource) =>
    resource.kind === desired.kind
      && resource.key === desired.key
      && resource.desiredHash === desired.desiredHash
      && resource.marker === ownershipMarker(receipt.installationId, desired.key));
  if (matches.length !== 1) fail('ownership_conflict');
  return matches[0];
}

function accessPolicyMatches(live, expected) {
  if (live.name !== expected.name || live.decision !== expected.decision
    || !Array.isArray(live.exclude) || live.exclude.length !== 0
    || !Array.isArray(live.require) || live.require.length !== 0
    || !Array.isArray(live.include) || live.include.length !== expected.include.length) {
    return false;
  }
  const liveEmails = live.include.map((rule) => rule?.email?.email);
  const expectedEmails = expected.include.map((rule) => rule.email.email);
  return liveEmails.every((email) => typeof email === 'string')
    && sameTextSet(liveEmails.map((email) => email.trim().toLowerCase()), expectedEmails);
}

function normalizeServerDesired(value, marker) {
  assertExactKeys(value, [
    'metadata', 'sourceId', 'name', 'endpoint', 'capabilityMode', 'secureWebGateway',
    'toolPolicy', 'authentication',
  ]);
  if (value.capabilityMode !== 'read_only' || value.secureWebGateway !== false) fail('invalid_input');
  if (typeof value.name !== 'string' || value.name.length < 1 || value.name.length > 350) fail('invalid_input');
  requireHttpsUrl(value.endpoint);
  if (!isObject(value.toolPolicy)) fail('invalid_input');
  assertExactKeys(value.toolPolicy, ['defaultDisabled', 'allowedTools']);
  if (value.toolPolicy.defaultDisabled !== true) fail('invalid_input');
  const tools = normalizeTools(value.toolPolicy.allowedTools);
  if (!isObject(value.authentication)) fail('invalid_input');
  assertExactKeys(value.authentication, ['mode', 'onBehalfOfUser', 'credentialCustody']);
  if (value.authentication.credentialCustody !== 'customer') fail('invalid_input');
  const authType = value.authentication.mode === 'none'
    ? 'unauthenticated'
    : value.authentication.mode === 'oauth'
      ? 'oauth'
      : value.authentication.mode === 'bearer' || value.authentication.mode === 'headers'
        ? 'bearer'
        : null;
  if (!authType) fail('invalid_input');
  return {
    auth_type: authType,
    hostname: value.endpoint,
    name: value.name,
    description: marker,
    updated_tools: tools.map((name) => ({ name, enabled: true })),
  };
}

function normalizeSourceAccessApplicationDesired(value) {
  assertExactKeys(value, ['metadata', 'sourceResourceKey', 'applicationType']);
  if (!RESOURCE_KEY.test(value.sourceResourceKey) || value.applicationType !== 'mcp') {
    fail('invalid_input');
  }
  return { sourceResourceKey: value.sourceResourceKey };
}

function normalizePortalAccessApplicationDesired(value) {
  assertExactKeys(value, [
    'metadata', 'portalResourceKey', 'name', 'hostname', 'applicationType',
    'destination', 'authentication',
  ]);
  if (!RESOURCE_KEY.test(value.portalResourceKey)
    || value.applicationType !== 'mcp_portal'
    || typeof value.name !== 'string'
    || value.name.length < 1) fail('invalid_input');
  requireHostname(value.hostname);
  if (!isObject(value.destination)) fail('invalid_input');
  assertExactKeys(value.destination, ['type', 'uri']);
  if (value.destination.type !== 'public' || value.destination.uri !== value.hostname) {
    fail('invalid_input');
  }
  if (value.name.length > 350 || /[\u0000-\u001f\u007f]/.test(value.name)) fail('invalid_input');
  return {
    portalResourceKey: value.portalResourceKey,
    body: {
      name: value.name,
      type: 'mcp_portal',
      domain: value.hostname,
      destinations: [{ type: 'public', uri: value.hostname }],
      oauth_configuration: normalizeManagedOauth(value.authentication),
    },
  };
}

function normalizePortalDesired(value, marker) {
  assertExactKeys(value, [
    'metadata', 'name', 'hostname', 'capabilityMode', 'codeMode',
    'secureWebGateway', 'sourceMappings',
  ]);
  if (value.capabilityMode !== 'read_only' || value.secureWebGateway !== false) fail('invalid_input');
  if (typeof value.name !== 'string' || value.name.length < 1 || value.name.length > 350) fail('invalid_input');
  requireHostname(value.hostname);
  if (!['off', 'opt_in', 'default_on', 'enforced'].includes(value.codeMode)) fail('invalid_input');
  if (!Array.isArray(value.sourceMappings) || value.sourceMappings.length === 0) fail('invalid_input');
  const seen = new Set();
  const servers = value.sourceMappings.map((mapping) => {
    if (!isObject(mapping)) fail('invalid_input');
    assertExactKeys(mapping, ['sourceResourceKey', 'defaultDisabled', 'allowedTools', 'onBehalfOfUser']);
    if (!RESOURCE_KEY.test(mapping.sourceResourceKey) || seen.has(mapping.sourceResourceKey)) fail('invalid_input');
    seen.add(mapping.sourceResourceKey);
    if (mapping.defaultDisabled !== true || typeof mapping.onBehalfOfUser !== 'boolean') fail('invalid_input');
    return {
      server_id: mapping.sourceResourceKey,
      default_disabled: true,
      on_behalf: mapping.onBehalfOfUser,
      updated_prompts: [],
      updated_tools: normalizeTools(mapping.allowedTools).map((name) => ({ name, enabled: true })),
    };
  });
  return {
    hostname: value.hostname,
    name: value.name,
    code_mode: value.codeMode,
    description: marker,
    secure_web_gateway: false,
    servers,
  };
}

async function normalizePolicyDesired(value, access, marker) {
  assertExactKeys(value, value.portalApplicationResourceKey === undefined
    ? ['metadata', 'sourceApplicationResourceKey', 'defaultAction', 'allow']
    : ['metadata', 'portalApplicationResourceKey', 'defaultAction', 'allow']);
  const parentKey = value.sourceApplicationResourceKey ?? value.portalApplicationResourceKey;
  if (!RESOURCE_KEY.test(parentKey) || value.defaultAction !== 'deny' || !isObject(value.allow)) {
    fail('invalid_input');
  }
  assertExactKeys(value.allow, ['identitiesRef', 'identityType', 'identityCount', 'identitiesHash']);
  if (value.allow.identitiesRef !== 'access.allowedEmails' || value.allow.identityType !== 'email') {
    fail('invalid_input');
  }
  const emails = normalizeEmails(access);
  if (emails.length !== value.allow.identityCount) fail('access_identity_mismatch');
  const hash = await hashCanonical({ emails });
  if (hash !== value.allow.identitiesHash) fail('access_identity_mismatch');
  return {
    name: marker,
    decision: 'allow',
    include: emails.map((email) => ({ email: { email } })),
    exclude: [],
    require: [],
  };
}

function normalizeDnsDesired(value, marker, hostname) {
  assertExactKeys(value, [
    'metadata', 'recordType', 'hostname', 'content', 'proxied', 'dependsOnResourceKey',
  ]);
  if (value.recordType !== 'CNAME'
    || value.hostname !== hostname
    || value.content !== PORTAL_CNAME_TARGET
    || value.proxied !== true
    || !RESOURCE_KEY.test(value.dependsOnResourceKey)) fail('invalid_input');
  return {
    type: 'CNAME',
    name: hostname,
    content: PORTAL_CNAME_TARGET,
    proxied: true,
    ttl: 1,
    comment: marker,
  };
}

async function findPolicyParent(cloudflare, polling, mutation) {
  void cloudflare;
  void polling;
  if (mutation.change.kind === 'source_access_policy') {
    const applicationKey = mutation.change.desired?.sourceApplicationResourceKey;
    const matches = mutation.receipt.resources.filter((resource) =>
      resource.kind === 'source_access_application' && resource.key === applicationKey);
    if (matches.length !== 1) fail('ownership_conflict');
    return matches[0].provider.id;
  }
  const applicationKey = mutation.change.desired?.portalApplicationResourceKey;
  const matches = mutation.receipt.resources.filter((resource) =>
    resource.kind === 'portal_access_application' && resource.key === applicationKey);
  if (matches.length !== 1) fail('ownership_conflict');
  return matches[0].provider.id;
}

async function assertPolicyParent(cloudflare, mutation, parentId) {
  const app = await exactRead(() => cloudflare.getAccessApp(parentId), parentId);
  if (app === null) fail('access_app_missing');
  if (mutation.change.kind === 'portal_access_policy') {
    const desiredApplicationKey = mutation.change.desired?.portalApplicationResourceKey;
    const receiptApplications = mutation.receipt.resources.filter((resource) =>
      resource.kind === 'portal_access_application'
      && (!desiredApplicationKey || resource.key === desiredApplicationKey)
      && resource.provider.id === parentId);
    if (receiptApplications.length !== 1) fail('ownership_conflict');
    await assertPortalAccessApplicationAuthority(
      cloudflare,
      mutation,
      app,
      ownershipMarker(mutation.receipt.installationId, receiptApplications[0].key),
      {
        allowMissingPortal: mutation.change.action === 'delete',
        requireDesired: true,
      },
    );
    return app;
  }
  const desiredApplicationKey = mutation.change.desired?.sourceApplicationResourceKey;
  const receiptApplications = mutation.receipt.resources.filter((resource) =>
    resource.kind === 'source_access_application'
    && (!desiredApplicationKey || resource.key === desiredApplicationKey)
    && resource.provider.id === parentId);
  if (receiptApplications.length !== 1) fail('ownership_conflict');
  await assertSourceAccessApplicationAuthority(
    cloudflare,
    mutation,
    app,
    ownershipMarker(mutation.receipt.installationId, receiptApplications[0].key),
    { allowMissingServer: mutation.change.action === 'delete' },
  );
  return app;
}

async function assertReceiptOwnedServer(cloudflare, mutation, serverKey) {
  const servers = mutation.receipt.resources.filter((resource) =>
    resource.kind === 'mcp_server'
    && resource.key === serverKey
    && resource.provider.id === serverKey);
  if (servers.length !== 1) fail('ownership_conflict');
  const server = servers[0];
  const live = await exactRead(
    () => cloudflare.getMcpServer(server.provider.id),
    server.provider.id,
  );
  if (live === null
    || live.description !== ownershipMarker(mutation.receipt.installationId, server.key)) {
    fail('ownership_conflict');
  }
  return server;
}

async function assertSourceAccessApplicationAuthority(
  cloudflare,
  mutation,
  app,
  marker,
  { allowMissingServer = false } = {},
) {
  if (app?.name !== marker || app?.type !== 'mcp' || !sourceAppHasNoDomain(app)
    || !Array.isArray(app.destinations)
    || app.destinations.length !== 1) fail('ownership_conflict');
  const destination = app.destinations[0];
  if (!isObject(destination)
    || Object.keys(destination).sort().join(',') !== 'mcp_server_id,type'
    || destination.type !== 'via_mcp_server_portal'
    || !safeId(destination.mcp_server_id)) {
    fail('ownership_conflict');
  }
  const servers = mutation.receipt.resources.filter((resource) =>
    resource.kind === 'mcp_server'
    && resource.provider.id === destination.mcp_server_id
    && resource.provider.id === resource.key);
  if (servers.length === 1) {
    const live = await exactRead(
      () => cloudflare.getMcpServer(servers[0].provider.id),
      servers[0].provider.id,
    );
    if (live === null) {
      if (allowMissingServer) return servers[0];
      fail('ownership_conflict');
    }
    if (live.description !== ownershipMarker(mutation.receipt.installationId, servers[0].key)) {
      fail('ownership_conflict');
    }
    return servers[0];
  }
  if (allowMissingServer && servers.length === 0) {
    const live = await exactRead(
      () => cloudflare.getMcpServer(destination.mcp_server_id),
      destination.mcp_server_id,
    );
    if (live === null) return null;
  }
  fail('ownership_conflict');
}

async function expectedPortalForApplicationMutation(mutation, portalKey) {
  let desiredState;
  try {
    desiredState = await buildGatewayDesiredState(mutation.config, {
      target: mutation.target,
      access: mutation.access,
    });
  } catch {
    fail('invalid_input');
  }
  const application = desiredState.resources.find((resource) =>
    resource.kind === 'portal_access_application' && resource.key === mutation.change.key);
  const portal = desiredState.resources.find((resource) =>
    resource.kind === 'portal' && resource.key === portalKey);
  if (desiredState.installationId !== mutation.receipt.installationId
    || application?.desiredHash !== mutation.change.desiredHash
    || canonicalJson(application?.desired) !== canonicalJson(mutation.change.desired)
    || !portal) fail('invalid_input');
  const receiptPortals = mutation.receipt.resources.filter((resource) =>
    resource.kind === 'portal'
      && resource.key === portal.key
      && resource.provider.id === portal.key
      && resource.desiredHash === portal.desiredHash
      && resource.marker === ownershipMarker(mutation.receipt.installationId, portal.key));
  if (receiptPortals.length !== 1) fail('invalid_input');
  return normalizePortalDesired(
    portal.desired,
    ownershipMarker(mutation.receipt.installationId, portal.key),
  );
}

async function assertReceiptOwnedPortal(
  cloudflare,
  mutation,
  portalKey,
  { allowMissing = false, expected } = {},
) {
  const portals = mutation.receipt.resources.filter((resource) =>
    resource.kind === 'portal'
    && resource.key === portalKey
    && resource.provider.id === resource.key);
  if (portals.length !== 1) fail('ownership_conflict');
  const portal = portals[0];
  const live = await exactRead(() => cloudflare.getPortal(portal.provider.id), portal.provider.id);
  if (live === null) {
    if (allowMissing) return portal;
    fail('ownership_conflict');
  }
  if (live.description !== ownershipMarker(mutation.receipt.installationId, portal.key)
    || live.hostname !== mutation.config.gateway.hostname) fail('ownership_conflict');
  if (expected && !portalMatchesExpected(live, portal.provider.id, expected)) {
    fail('ownership_conflict');
  }
  return portal;
}

async function assertPortalAccessApplicationAuthority(
  cloudflare,
  mutation,
  app,
  _marker,
  { allowMissingPortal = false, requireDesired = false } = {},
) {
  if (app?.name !== mutation.config.gateway.name
    || !portalAccessApplicationShapeMatches(app, mutation.config.gateway.hostname)
    || (requireDesired && !managedOauthMatches(
      app.oauth_configuration,
      expectedManagedOauthConfiguration(),
    ))) fail('ownership_conflict');
  const applications = mutation.receipt.resources.filter((resource) =>
    resource.kind === 'portal_access_application'
    && resource.provider.id === app.id);
  if (applications.length !== 1) fail('ownership_conflict');
  const portals = mutation.receipt.resources.filter((resource) => resource.kind === 'portal');
  if (portals.length !== 1) fail('ownership_conflict');
  await assertReceiptOwnedPortal(cloudflare, mutation, portals[0].key, {
    allowMissing: allowMissingPortal,
  });
  return applications[0];
}

async function assertPortalAccessApplicationCandidateSet(
  cloudflare,
  hostname,
  expectedName,
  expectedId,
  { allowAbsent = false } = {},
) {
  const apps = await cloudflare.listAccessApps();
  if (!Array.isArray(apps)) fail('invalid_provider_response');
  const matches = apps
    .filter((app) => app?.name === expectedName
      || isPortalAppCandidate(app, hostname))
    .map(requireAppId);
  if (allowAbsent) {
    if (matches.length !== 0) fail('ownership_conflict');
    return;
  }
  if (matches.length !== 1 || matches[0].id !== expectedId) fail('ownership_conflict');
}

function assertPortalApplicationReceiptAbsent(receipt) {
  if (receipt.resources.some((resource) => resource.kind === 'portal_access_application')) {
    fail('ownership_conflict');
  }
}

async function assertNoPortalAccessApplications(cloudflare, hostname) {
  const apps = await cloudflare.listAccessApps();
  if (!Array.isArray(apps)) fail('invalid_provider_response');
  if (apps.some((app) => isPortalAppCandidate(app, hostname))) fail('ownership_conflict');
}

async function provePortalAccessApplicationBaselineQuiet(cloudflare, polling, hostname) {
  for (let attempt = 0; attempt < polling.attempts; attempt += 1) {
    const apps = await cloudflare.listAccessApps();
    if (!Array.isArray(apps)) fail('invalid_provider_response');
    if (apps.some((app) => isPortalAppCandidate(app, hostname))) fail('resource_collision');
    if (attempt + 1 < polling.attempts) await polling.delayImpl(polling.intervalMs);
  }
}

async function assertAccessApplicationPoliciesEmpty(cloudflare, app) {
  const policies = await cloudflare.listAppPolicies(app.id);
  if (!Array.isArray(policies)) fail('invalid_provider_response');
  if (policies.length > 0
    || (Object.hasOwn(app, 'policies')
      && (!Array.isArray(app.policies) || app.policies.length > 0))) {
    fail('ownership_conflict');
  }
}

async function assertPortalAccessApplicationPolicyPhase(cloudflare, mutation, app) {
  const policies = await cloudflare.listAppPolicies(app.id);
  if (!Array.isArray(policies)) fail('invalid_provider_response');
  const ownedPolicies = mutation.receipt.resources.filter((resource) =>
    resource.kind === 'portal_access_policy'
      && resource.provider.parentId === app.id);
  if (ownedPolicies.length === 0) {
    if (policies.length > 0 || !inlinePoliciesAreEmpty(app)) fail('ownership_conflict');
    return;
  }
  if (ownedPolicies.length !== 1) fail('ownership_conflict');
  const ownedPolicy = ownedPolicies[0];
  const marker = ownershipMarker(mutation.receipt.installationId, ownedPolicy.key);
  if (ownedPolicy.marker !== marker) fail('ownership_conflict');
  assertExpectedPolicySet(policies, ownedPolicy.provider.id, marker);
  if (!inlinePoliciesMatchListedPolicies(app, policies)) fail('ownership_conflict');
}

async function assertNoAccessAppBaseline(cloudflare, predicate) {
  const apps = await cloudflare.listAccessApps();
  if (!Array.isArray(apps)) fail('invalid_provider_response');
  const matches = apps.filter(predicate).map(requireAppId);
  if (matches.length > 0) fail('resource_collision');
}

async function assertNoServerAccessApplications(cloudflare, serverId) {
  const apps = await cloudflare.listAccessApps();
  if (!Array.isArray(apps)) fail('invalid_provider_response');
  if (apps.some((app) => isExactServerApp(app, serverId))) fail('ownership_conflict');
}

function normalizeManagedOauth(value) {
  if (!isObject(value)) fail('invalid_input');
  assertExactKeys(value, ['mode', 'dynamicClientRegistration', 'grant']);
  if (value.mode !== 'managed_oauth'
    || !isObject(value.dynamicClientRegistration)
    || !isObject(value.grant)) fail('invalid_input');
  assertExactKeys(value.dynamicClientRegistration, [
    'enabled', 'allowAnyOnLocalhost', 'allowAnyOnLoopback',
  ]);
  assertExactKeys(value.grant, ['accessTokenLifetime', 'sessionDuration']);
  if (value.dynamicClientRegistration.enabled !== true
    || value.dynamicClientRegistration.allowAnyOnLocalhost !== true
    || value.dynamicClientRegistration.allowAnyOnLoopback !== true
    || value.grant.accessTokenLifetime !== '15m'
    || value.grant.sessionDuration !== '336h') fail('invalid_input');
  return {
    enabled: true,
    dynamic_client_registration: {
      enabled: true,
      allow_any_on_localhost: true,
      allow_any_on_loopback: true,
    },
    grant: { access_token_lifetime: '15m', session_duration: '336h' },
  };
}

function managedOauthMatches(live, desired) {
  return live?.enabled === desired.enabled
    && live?.dynamic_client_registration?.enabled === desired.dynamic_client_registration.enabled
    && live?.dynamic_client_registration?.allow_any_on_localhost === desired.dynamic_client_registration.allow_any_on_localhost
    && live?.dynamic_client_registration?.allow_any_on_loopback === desired.dynamic_client_registration.allow_any_on_loopback
    && live?.grant?.access_token_lifetime === desired.grant.access_token_lifetime
    && live?.grant?.session_duration === desired.grant.session_duration;
}

async function waitForServerSync(cloudflare, polling, serverId, expectedTools) {
  for (let attempt = 0; attempt < polling.attempts; attempt += 1) {
    const server = await exactRead(() => cloudflare.getMcpServer(serverId), serverId);
    if (server === null) fail('sync_failed');
    if (server.status === 'ready' && expectedToolsDiscovered(server.tools, expectedTools)) return;
    if (server.status === 'error') fail('sync_failed');
    if (attempt + 1 < polling.attempts) await polling.delayImpl(polling.intervalMs);
  }
  fail('sync_timeout');
}

async function waitForAccessAppAbsence(cloudflare, polling, appId) {
  if (!safeId(appId)) fail('ownership_conflict');
  for (let attempt = 0; attempt < polling.attempts; attempt += 1) {
    const app = await exactRead(() => cloudflare.getAccessApp(appId), appId);
    if (app === null) return;
    if (attempt + 1 < polling.attempts) await polling.delayImpl(polling.intervalMs);
  }
  fail('sync_timeout');
}

async function inspectResidue(cloudflare, input, boundTarget) {
  if (!isObject(input)) fail('invalid_input');
  rejectMutationKeys(input, ['config', 'target', 'receipt', 'signal']);
  const receipt = await validateReceipt(input.receipt);
  assertTarget(input.target, boundTarget, receipt.target);
  if (!isObject(input.config) || input.config?.gateway?.hostname !== receipt.target.hostname) {
    fail('invalid_input');
  }
  let ownedResourceCount = 0;
  const liveReceiptPortalApplicationIds = new Set();
  for (const resource of receipt.resources) {
    let live;
    if (resource.kind === 'mcp_server') live = await exactRead(() => cloudflare.getMcpServer(resource.provider.id), resource.provider.id);
    else if (resource.kind === 'source_access_application'
      || resource.kind === 'portal_access_application') {
      live = await exactRead(() => cloudflare.getAccessApp(resource.provider.id), resource.provider.id);
    }
    else if (resource.kind === 'portal') live = await exactRead(() => cloudflare.getPortal(resource.provider.id), resource.provider.id);
    else if (resource.kind === 'dns_record') live = await exactRead(() => cloudflare.getDnsRecord(resource.provider.id), resource.provider.id);
    else live = await exactRead(() => cloudflare.getAppPolicy(resource.provider.parentId, resource.provider.id), resource.provider.id);
    // Receipt locators are exact existence evidence. Shape and marker checks gate
    // mutations, but must not make live residue disappear from uninstall proof.
    if (live !== null) {
      ownedResourceCount += 1;
      if (resource.kind === 'portal_access_application') {
        liveReceiptPortalApplicationIds.add(resource.provider.id);
      }
    }
  }

  const apps = await cloudflare.listAccessApps();
  if (!Array.isArray(apps)) fail('invalid_provider_response');
  const countedBroadIds = new Set(liveReceiptPortalApplicationIds);
  for (const candidate of apps.filter((app) =>
    isPortalAppCandidate(app, input.config.gateway.hostname))) {
    const app = requireAppId(candidate);
    if (!countedBroadIds.has(app.id)) {
      countedBroadIds.add(app.id);
      ownedResourceCount += 1;
    }
  }
  return Object.freeze({ ownedResourceCount });
}

async function exactRead(reader, expectedId) {
  const value = await reader();
  if (value === null) return null;
  if (!isObject(value) || value.id !== expectedId) fail('invalid_provider_response');
  return value;
}

function isExactServerApp(app, serverId) {
  return safeId(serverId)
    && app?.type === 'mcp'
    && Array.isArray(app.destinations)
    && app.destinations.some((destination) =>
      destination?.type === 'via_mcp_server_portal'
      && destination.mcp_server_id === serverId);
}

function isExactSourceAccessApplication(app, serverId, marker) {
  if (app?.name !== marker || app?.type !== 'mcp' || !sourceAppHasNoDomain(app)
    || !Array.isArray(app.destinations) || app.destinations.length !== 1) return false;
  const destination = app.destinations[0];
  return isObject(destination)
    && Object.keys(destination).sort().join(',') === 'mcp_server_id,type'
    && destination.type === 'via_mcp_server_portal'
    && destination.mcp_server_id === serverId;
}

function sourceAppHasNoDomain(app) {
  return app?.domain === undefined || app.domain === null;
}

function portalAccessApplicationMatches(app, expected) {
  return app?.name === expected.name
    && portalAccessApplicationShapeMatches(app, expected.domain)
    && managedOauthMatches(app.oauth_configuration, expected.oauth_configuration);
}

function portalAccessApplicationPrePolicyMatches(app, expected) {
  return portalAccessApplicationMatches(app, expected)
    && inlinePoliciesAreEmpty(app);
}

function portalAccessApplicationShapeMatches(app, hostname) {
  if (app?.type !== 'mcp_portal' || app.domain !== hostname
    || !Array.isArray(app.destinations) || app.destinations.length !== 1) return false;
  const destination = app.destinations[0];
  return isObject(destination)
    && Object.keys(destination).sort().join(',') === 'type,uri'
    && destination.type === 'public'
    && destination.uri === hostname;
}

function inlinePoliciesAreEmpty(app) {
  return !Object.hasOwn(app, 'policies')
    || (Array.isArray(app.policies) && app.policies.length === 0);
}

function inlinePoliciesMatchListedPolicies(app, policies) {
  if (!Array.isArray(policies)) return false;
  if (!Object.hasOwn(app, 'policies')
    || (Array.isArray(app.policies) && app.policies.length === 0)) return true;
  if (!Array.isArray(app.policies) || app.policies.length !== policies.length) return false;

  const listedById = new Map();
  for (const policy of policies) {
    const id = safeId(policy?.id);
    if (!id || listedById.has(id)) return false;
    listedById.set(id, policy);
  }
  const seen = new Set();
  for (const inlinePolicy of app.policies) {
    const id = safeId(typeof inlinePolicy === 'string' ? inlinePolicy : inlinePolicy?.id);
    if (!id || seen.has(id) || !listedById.has(id)) return false;
    if (isObject(inlinePolicy)
      && Object.hasOwn(inlinePolicy, 'name')
      && inlinePolicy.name !== listedById.get(id)?.name) return false;
    seen.add(id);
  }
  return seen.size === listedById.size;
}

function expectedManagedOauthConfiguration() {
  return {
    enabled: true,
    dynamic_client_registration: {
      enabled: true,
      allow_any_on_localhost: true,
      allow_any_on_loopback: true,
    },
    grant: { access_token_lifetime: '15m', session_duration: '336h' },
  };
}

function isPortalAppCandidate(app, hostname) {
  return app?.type === 'mcp_portal' && (
    app.domain === hostname ||
    (Array.isArray(app.destinations) && app.destinations.some((destination) =>
      destination?.type === 'public' && destination.uri === hostname))
  );
}

function requireAppId(app) {
  if (!isObject(app) || !safeId(app.id)) fail('invalid_provider_response');
  return app;
}

async function validateReceipt(value) {
  try {
    return await validateInstallationReceipt(value);
  } catch {
    fail('invalid_input');
  }
}

function assertTarget(target, bound, receiptTarget) {
  if (!isObject(target)
    || target.accountId !== bound.accountId
    || target.zoneId !== bound.zoneId
    || receiptTarget.accountId !== bound.accountId
    || receiptTarget.zoneId !== bound.zoneId) fail('target_mismatch');
}

function assertDesiredMetadata(desired, installationId) {
  if (!isObject(desired.metadata)) fail('invalid_input');
  assertExactKeys(desired.metadata, ['manager', 'installationId']);
  if (desired.metadata.manager !== 'ankka-mcp-gateway'
    || desired.metadata.installationId !== installationId) fail('invalid_input');
}

function assertProviderLocator(kind, provider) {
  if (!isObject(provider) || !safeId(provider.id)) fail('invalid_input');
  const expected = POLICY_KINDS.has(kind) ? ['id', 'parentId'] : ['id'];
  assertExactKeys(provider, expected);
  if (POLICY_KINDS.has(kind) && !safeId(provider.parentId)) fail('invalid_input');
}

function assertMarker(actual, expected) {
  if (actual !== expected) fail('ownership_conflict');
}

function normalizeEmails(access) {
  if (!isObject(access) || !Array.isArray(access.allowedEmails)) fail('access_identity_mismatch');
  const values = [];
  for (const raw of access.allowedEmails) {
    if (typeof raw !== 'string') fail('access_identity_mismatch');
    const email = raw.trim().toLowerCase();
    if (email.length === 0 || email.length > 254 || !EMAIL.test(email)) fail('access_identity_mismatch');
    values.push(email);
  }
  return [...new Set(values)].sort(compareText);
}

function normalizeTools(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 500) fail('invalid_input');
  const tools = [];
  for (const tool of value) {
    if (typeof tool !== 'string' || tool.length === 0 || tool.length > 128 || tool === '*' || tools.includes(tool)) {
      fail('invalid_input');
    }
    tools.push(tool);
  }
  return [...tools].sort(compareText);
}

function expectedToolsDiscovered(tools, expectedTools) {
  if (!Array.isArray(tools)) return false;
  const names = [];
  for (const tool of tools) {
    if (!isObject(tool) || typeof tool.name !== 'string' || names.includes(tool.name)) return false;
    names.push(tool.name);
  }
  return expectedTools.every(({ name }) => names.includes(name));
}

function normalizeAbortSignal(value) {
  if (value === undefined) return null;
  if (!isObject(value)
    || typeof value.aborted !== 'boolean'
    || typeof value.addEventListener !== 'function'
    || typeof value.removeEventListener !== 'function') fail('invalid_input');
  return value;
}

function requireHttpsUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password) fail('invalid_input');
  } catch (error) {
    if (error instanceof CloudflareGatewayProviderError) throw error;
    fail('invalid_input');
  }
}

function requireHostname(value) {
  if (typeof value !== 'string' || value !== value.toLowerCase() || value.length > 253
    || value.split('.').length < 2
    || !value.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    fail('invalid_input');
  }
}

function requireId(value) {
  if (!safeId(value)) throw new TypeError('accountId and zoneId must be non-empty identifiers');
}

function safeId(value) {
  return typeof value === 'string' && SAFE_ID.test(value);
}

function normalizeDns(value) {
  return typeof value === 'string' ? value.toLowerCase().replace(/\.$/, '') : '';
}

function sameLocator(left, right) {
  return left?.id === right?.id && (left?.parentId ?? '') === (right?.parentId ?? '');
}

function rejectUnknownKeys(value, allowed) {
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    throw new TypeError('provider options contain unsupported fields');
  }
}

function rejectMutationKeys(value, allowed) {
  if (Object.keys(value).some((key) => !allowed.includes(key))) fail('invalid_input');
}

function assertExactKeys(value, expected) {
  if (!isObject(value)) fail('invalid_input');
  const actual = Object.keys(value).sort(compareText);
  const sortedExpected = [...expected].sort(compareText);
  if (actual.length !== sortedExpected.length
    || actual.some((key, index) => key !== sortedExpected[index])) fail('invalid_input');
}

async function hashCanonical(value) {
  const bytes = new TextEncoder().encode(canonicalJson(value));
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return `sha256:${[...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}`;
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isObject(value)) return `{${Object.keys(value).sort(compareText)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  fail('invalid_input');
}

function defaultDelay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function fail(code) {
  throw new CloudflareGatewayProviderError(code);
}
