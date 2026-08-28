import { buildGatewayDesiredState } from './plan.mjs';
import { ownershipMarker, validateInstallationReceipt } from './receipt.mjs';

const MANAGER = 'ankka-mcp-gateway';
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const POLICY_KINDS = new Set(['source_access_policy', 'portal_access_policy']);
const SAFE_ERROR_CODES = new Set([
  'invalid_input',
  'provider_read_failed',
  'invalid_provider_response',
  'zone_not_found',
  'zone_mismatch',
  'zone_account_mismatch',
]);

export class ObservedStateError extends Error {
  constructor(code) {
    const safeCode = SAFE_ERROR_CODES.has(code) ? code : 'provider_read_failed';
    super(`Cloudflare observed-state read failed: code=${safeCode}`);
    this.name = 'ObservedStateError';
    this.code = safeCode;
  }
}

/**
 * Read the small, canonical slice of Cloudflare state used by the planner.
 * Provider bodies are reduced immediately; ownership requires both a live
 * marker and a checksum-verified receipt (or its exact pending create intent).
 */
export async function readCloudflareObservedState({
  cloudflare,
  config,
  target,
  access,
  receipt,
} = {}) {
  requireReader(cloudflare);
  const selectedTarget = normalizeSelectedTarget(target);
  const zone = await providerRead(() => cloudflare.getZone());
  const verifiedTarget = verifyZone(zone, selectedTarget);
  const identityProviders = await providerRead(() => cloudflare.listIdentityProviders());
  if (!Array.isArray(identityProviders)) throw new ObservedStateError('invalid_provider_response');
  verifiedTarget.zeroTrustReady = identityProviders.length > 0;

  let desiredState;
  try {
    desiredState = await buildGatewayDesiredState(config, {
      target: verifiedTarget,
      access,
    });
  } catch {
    throw new ObservedStateError('invalid_input');
  }

  const diagnostics = [];
  const trustedReceipt = await readTrustedReceipt(receipt, desiredState.installationId, {
    accountId: verifiedTarget.accountId,
    zoneId: verifiedTarget.zoneId,
    zoneName: verifiedTarget.zoneName,
    hostname: config.gateway.hostname,
  }, diagnostics);
  const desiredByIdentity = new Map(
    desiredState.resources.map((resource) => [identity(resource.kind, resource.key), resource]),
  );
  const receiptResources = trustedReceipt?.resources ?? [];
  const resources = [];

  const serverReads = buildEntityReads('mcp_server', desiredState.resources, receiptResources);
  const portalReads = buildEntityReads('portal', desiredState.resources, receiptResources);
  const [serverResults, portalResults, dnsRecords, accessApps] = await Promise.all([
    readEntities(serverReads, (id) => cloudflare.getMcpServer(id)),
    readEntities(portalReads, (id) => cloudflare.getPortal(id)),
    providerRead(() => cloudflare.listDnsRecords({ 'name.exact': config.gateway.hostname, match: 'all' })),
    providerRead(() => cloudflare.listAccessApps()),
  ]);
  if (!Array.isArray(dnsRecords) || !Array.isArray(accessApps)) {
    throw new ObservedStateError('invalid_provider_response');
  }

  for (const result of serverResults) {
    if (result.live === null) continue;
    const desired = desiredByIdentity.get(identity('mcp_server', result.key));
    const pendingCreateCanRecover = desired
      ? pendingCreateMatches(trustedReceipt, desired)
        && serverMatches(result.live, desired)
      : false;
    pushObserved(resources, makeObserved({
      kind: 'mcp_server',
      key: result.key,
      locator: { id: result.id },
      marker: result.live.description,
      liveMatchesDesired: desired
        ? serverMatches(result.live, desired) || pendingCreateCanRecover
        : false,
      desired,
      receipt: trustedReceipt,
    }));
  }

  for (const result of portalResults) {
    if (result.live === null) continue;
    const desired = desiredByIdentity.get(identity('portal', result.key));
    const pendingCreateCanRecover = desired
      ? pendingCreateMatches(trustedReceipt, desired)
        && portalBaseMatches(result.live, desired)
      : false;
    pushObserved(resources, makeObserved({
      kind: 'portal',
      key: result.key,
      locator: { id: result.id },
      marker: result.live.description,
      liveMatchesDesired: desired
        ? portalBaseMatches(result.live, desired) || pendingCreateCanRecover
        : false,
      desired,
      receipt: trustedReceipt,
    }));
  }

  for (const desired of desiredState.resources.filter((resource) =>
    resource.kind === 'source_access_application')) {
    const marker = ownershipMarker(desiredState.installationId, desired.key);
    const serverId = desired.desired.sourceResourceKey;
    const candidates = accessApps
      .filter((app) => app?.name === marker || isServerApp(app, serverId))
      .map(requireObservedApp);
    const receiptResource = receiptResources.find((resource) =>
      resource.kind === desired.kind && resource.key === desired.key);
    if (receiptResource && !candidates.some((app) => app.id === receiptResource.provider.id)) {
      const exact = await providerRead(() => cloudflare.getAccessApp(receiptResource.provider.id));
      if (exact !== null) {
        exactReturnedId(exact, receiptResource.provider.id);
        candidates.push(requireObservedApp(exact));
      }
    }
    const candidateIds = new Set(candidates.map((candidate) => candidate.id));
    const pendingForDesired = pendingCreateMatches(trustedReceipt, desired);
    const seenApplicationIds = new Set();
    for (const candidate of candidates) {
      if (seenApplicationIds.has(candidate.id)) continue;
      seenApplicationIds.add(candidate.id);
      const live = await providerRead(() => cloudflare.getAccessApp(candidate.id));
      if (live === null || safeId(live?.id) !== candidate.id) {
        diagnostics.push({
          code: 'access_app_provenance_mismatch',
          kind: desired.kind,
          key: desired.key,
        });
        pushObserved(resources, {
          kind: desired.kind,
          key: desired.key,
          provider: { id: candidate.id },
          owner: {},
          desiredHash: '',
        });
        continue;
      }
      const baseMatches = sourceAccessApplicationBaseMatches(live, serverId, marker);
      let pendingBaseCanRecover = false;
      if (pendingForDesired && candidateIds.size === 1 && baseMatches
        && inlinePoliciesAreEmpty(live)) {
        const policies = await providerRead(() => cloudflare.listAppPolicies(candidate.id));
        if (!Array.isArray(policies)) throw new ObservedStateError('invalid_provider_response');
        pendingBaseCanRecover = policies.length === 0;
      }
      const exact = sourceAccessApplicationMatches(live, serverId, marker);
      pushObserved(resources, makeObserved({
        kind: desired.kind,
        key: desired.key,
        locator: { id: candidate.id },
        marker: exact ? live.name : undefined,
        liveMatchesDesired: exact || pendingBaseCanRecover,
        desired,
        receipt: trustedReceipt,
        pendingCreateProvenance: pendingBaseCanRecover,
      }));
    }
    if (seenApplicationIds.size > 1) {
      diagnostics.push({
        code: 'access_app_ambiguous',
        kind: desired.kind,
        key: desired.key,
        count: seenApplicationIds.size,
      });
    }
  }

  for (const desired of desiredState.resources.filter((resource) =>
    resource.kind === 'portal_access_application')) {
    const expectedName = desired.desired.name;
    const candidates = accessApps
      .filter((app) => app?.name === expectedName
        || isPortalAppCandidate(app, desired.desired.hostname))
      .map(requireObservedApp);
    const receiptResource = receiptResources.find((resource) =>
      resource.kind === desired.kind && resource.key === desired.key);
    if (receiptResource && !candidates.some((app) => app.id === receiptResource.provider.id)) {
      const exact = await providerRead(() => cloudflare.getAccessApp(receiptResource.provider.id));
      if (exact !== null) {
        exactReturnedId(exact, receiptResource.provider.id);
        candidates.push(requireObservedApp(exact));
      }
    }
    const seenApplicationIds = new Set();
    for (const candidate of candidates) {
      if (seenApplicationIds.has(candidate.id)) continue;
      seenApplicationIds.add(candidate.id);
      const live = await providerRead(() => cloudflare.getAccessApp(candidate.id));
      if (live === null || safeId(live?.id) !== candidate.id) {
        diagnostics.push({
          code: 'access_app_provenance_mismatch',
          kind: desired.kind,
          key: desired.key,
        });
        pushObserved(resources, {
          kind: desired.kind,
          key: desired.key,
          provider: { id: candidate.id },
          owner: {},
          desiredHash: '',
        });
        continue;
      }
      pushObserved(resources, makeObserved({
        kind: desired.kind,
        key: desired.key,
        locator: { id: candidate.id },
        liveMatchesDesired: portalAccessApplicationMatches(live, desired.desired),
        desired,
        receipt: trustedReceipt,
      }));
    }
    if (seenApplicationIds.size > 1) {
      diagnostics.push({
        code: 'access_app_ambiguous',
        kind: desired.kind,
        key: desired.key,
        count: seenApplicationIds.size,
      });
    }
  }

  const desiredDns = desiredState.resources.find((resource) => resource.kind === 'dns_record');
  const seenDnsIds = new Set();
  for (const record of dnsRecords) {
    const id = safeId(record?.id);
    if (!id) {
      diagnostics.push({ code: 'invalid_dns_record' });
      pushObserved(resources, {
        kind: 'dns_record',
        key: desiredDns.key,
        owner: {},
        desiredHash: '',
      });
      continue;
    }
    seenDnsIds.add(id);
    pushObserved(resources, makeObserved({
      kind: 'dns_record',
      key: desiredDns.key,
      locator: { id },
      marker: record.comment,
      liveMatchesDesired: dnsMatches(record, desiredDns),
      desired: desiredDns,
      receipt: trustedReceipt,
    }));
  }
  if (dnsRecords.length > 1) {
    diagnostics.push({ code: 'ambiguous_dns_record', kind: 'dns_record', key: desiredDns.key, count: dnsRecords.length });
  }

  for (const ownedDns of receiptResources.filter((resource) => resource.kind === 'dns_record')) {
    if (seenDnsIds.has(ownedDns.provider.id)) continue;
    const record = await providerRead(() => cloudflare.getDnsRecord(ownedDns.provider.id));
    if (record === null) continue;
    const id = exactReturnedId(record, ownedDns.provider.id);
    pushObserved(resources, makeObserved({
      kind: 'dns_record',
      key: ownedDns.key,
      locator: { id },
      marker: record.comment,
      liveMatchesDesired: desiredByIdentity.has(identity('dns_record', ownedDns.key))
        ? dnsMatches(record, desiredByIdentity.get(identity('dns_record', ownedDns.key)))
        : false,
      desired: desiredByIdentity.get(identity('dns_record', ownedDns.key)),
      receipt: trustedReceipt,
    }));
  }

  const allowedEmails = normalizeAllowedEmails(access);

  for (const desired of desiredState.resources.filter((resource) => POLICY_KINDS.has(resource.kind))) {
    const parentKey = desired.kind === 'source_access_policy'
      ? desired.desired.sourceApplicationResourceKey
      : desired.desired.portalApplicationResourceKey;
    const parentKind = desired.kind === 'source_access_policy'
      ? 'source_access_application'
      : 'portal_access_application';
    const liveParent = resources.find((resource) =>
      resource.kind === parentKind
      && resource.key === parentKey
      && resource.owner?.manager === MANAGER);
    if (!liveParent) continue;
    const app = await verifySingleAccessApp(
      cloudflare,
      [{ id: liveParent.provider.id }],
      desired.kind === 'source_access_policy'
        ? (candidate) => {
          const application = desiredByIdentity.get(identity('source_access_application', parentKey));
          return application
            ? sourceAccessApplicationMatches(
              candidate,
              application.desired.sourceResourceKey,
              ownershipMarker(desiredState.installationId, parentKey),
            )
            : false;
        }
        : (candidate) => {
          const application = desiredByIdentity.get(identity('portal_access_application', parentKey));
          return application
            ? portalAccessApplicationMatches(
              candidate,
              application.desired,
            )
            : false;
        },
      diagnostics,
      desired.kind,
      desired.key,
    );
    if (app === null) {
      pushObserved(resources, {
        kind: desired.kind,
        key: desired.key,
        owner: {},
        desiredHash: '',
      });
      continue;
    }
    const policies = await providerRead(() => cloudflare.listAppPolicies(app.id));
    if (!Array.isArray(policies)) throw new ObservedStateError('invalid_provider_response');
    const marker = ownershipMarker(desiredState.installationId, desired.key);
    const matches = policies.filter((policy) => policy?.name === marker);
    const unexpected = policies.filter((policy) => policy?.name !== marker);
    const inlinePolicyConflict = !inlinePoliciesMatchListedPolicies(app, policies);
    if (unexpected.length > 0 || inlinePolicyConflict) {
      diagnostics.push({
        code: 'unexpected_access_policy',
        kind: desired.kind,
        key: desired.key,
        count: unexpected.length + (inlinePolicyConflict ? 1 : 0),
      });
      resources.push({ kind: desired.kind, key: desired.key, owner: {}, desiredHash: '' });
    }
    if (matches.length > 1) {
      diagnostics.push({ code: 'access_policy_ambiguous', kind: desired.kind, key: desired.key, count: matches.length });
    }
    for (const policy of matches) {
      const id = safeId(policy?.id);
      if (!id) {
        diagnostics.push({ code: 'invalid_access_policy', kind: desired.kind, key: desired.key });
        pushObserved(resources, {
          kind: desired.kind,
          key: desired.key,
          owner: {},
          desiredHash: '',
        });
        continue;
      }
      pushObserved(resources, makeObserved({
        kind: desired.kind,
        key: desired.key,
        locator: { id, parentId: app.id },
        marker: policy.name,
        liveMatchesDesired: policyMatches(policy, allowedEmails),
        desired,
        receipt: trustedReceipt,
      }));
    }
  }

  for (const ownedApplication of receiptResources.filter((resource) =>
    resource.kind === 'source_access_application'
      || resource.kind === 'portal_access_application')) {
    const desired = desiredByIdentity.get(identity(ownedApplication.kind, ownedApplication.key));
    if (desired && hasLocator(resources, ownedApplication.kind, ownedApplication.key, ownedApplication.provider)) {
      continue;
    }
    const app = await providerRead(() => cloudflare.getAccessApp(ownedApplication.provider.id));
    if (app === null) continue;
    const id = exactReturnedId(app, ownedApplication.provider.id);
    const exact = ownedApplication.kind === 'source_access_application'
      ? sourceAccessApplicationReceiptMatches(
        app,
        ownedApplication,
        receiptResources,
        trustedReceipt.installationId,
      )
      : true;
    pushObserved(resources, makeObserved({
      kind: ownedApplication.kind,
      key: ownedApplication.key,
      locator: { id },
      marker: exact
        ? ownedApplication.kind === 'portal_access_application' ? undefined : app.name
        : undefined,
      liveMatchesDesired: desired
        ? ownedApplication.kind === 'source_access_application'
          ? sourceAccessApplicationMatches(
            app,
            desired.desired.sourceResourceKey,
            ownershipMarker(trustedReceipt.installationId, desired.key),
          )
          : portalAccessApplicationMatches(
            app,
            desired.desired,
          )
        : false,
      desired,
      receipt: trustedReceipt,
    }));
  }

  // Receipt locators are the installed inventory. Read stale policies directly
  // so prune and uninstall remain safe after configuration sources are removed.
  for (const ownedPolicy of receiptResources.filter((resource) => POLICY_KINDS.has(resource.kind))) {
    const desired = desiredByIdentity.get(identity(ownedPolicy.kind, ownedPolicy.key));
    if (desired && hasLocator(resources, ownedPolicy.kind, ownedPolicy.key, ownedPolicy.provider)) continue;
    const policy = await providerRead(() => cloudflare.getAppPolicy(
      ownedPolicy.provider.parentId,
      ownedPolicy.provider.id,
    ));
    if (policy === null) continue;
    const id = exactReturnedId(policy, ownedPolicy.provider.id);
    pushObserved(resources, makeObserved({
      kind: ownedPolicy.kind,
      key: ownedPolicy.key,
      locator: { id, parentId: ownedPolicy.provider.parentId },
      marker: policy.name,
      liveMatchesDesired: false,
      desired,
      receipt: trustedReceipt,
    }));
  }

  resources.sort(compareObserved);
  diagnostics.sort(compareDiagnostics);
  return { target: verifiedTarget, resources, diagnostics };
}

function requireReader(cloudflare) {
  const methods = [
    'getZone', 'listIdentityProviders', 'getMcpServer', 'getPortal',
    'listDnsRecords', 'getDnsRecord', 'listAccessApps', 'getAccessApp',
    'listAppPolicies', 'getAppPolicy',
  ];
  if (!cloudflare || methods.some((method) => typeof cloudflare[method] !== 'function')) {
    throw new ObservedStateError('invalid_input');
  }
}

function normalizeSelectedTarget(target) {
  if (!target || !safeId(target.accountId) || !safeId(target.zoneId)) {
    throw new ObservedStateError('invalid_input');
  }
  return { accountId: target.accountId, zoneId: target.zoneId };
}

function verifyZone(zone, target) {
  if (zone === null) throw new ObservedStateError('zone_not_found');
  if (!zone || typeof zone !== 'object') throw new ObservedStateError('invalid_provider_response');
  if (zone.id !== target.zoneId) throw new ObservedStateError('zone_mismatch');
  if (zone.account?.id !== target.accountId) throw new ObservedStateError('zone_account_mismatch');
  if (!validHostname(zone.name) || typeof zone.status !== 'string') {
    throw new ObservedStateError('invalid_provider_response');
  }
  return {
    accountId: target.accountId,
    zoneId: target.zoneId,
    zoneName: zone.name,
    zoneStatus: zone.status,
    zeroTrustReady: false,
  };
}

async function readTrustedReceipt(receipt, installationId, expectedTarget, diagnostics) {
  if (receipt === undefined || receipt === null) return null;
  try {
    const trusted = await validateInstallationReceipt(receipt, { expectedTarget });
    if (trusted.installationId !== installationId) throw new Error('installation mismatch');
    return trusted;
  } catch {
    diagnostics.push({ code: 'invalid_receipt' });
    return null;
  }
}

function buildEntityReads(kind, desiredResources, receiptResources) {
  const reads = [];
  for (const desired of desiredResources.filter((resource) => resource.kind === kind)) {
    reads.push({ key: desired.key, id: desired.key });
  }
  for (const resource of receiptResources.filter((resource) => resource.kind === kind)) {
    reads.push({ key: resource.key, id: resource.provider.id });
  }
  const seen = new Set();
  return reads.filter((read) => {
    const value = `${read.key}\u0000${read.id}`;
    if (seen.has(value)) return false;
    seen.add(value);
    return true;
  });
}

async function readEntities(reads, reader) {
  return Promise.all(reads.map(async ({ key, id }) => {
    const live = await providerRead(() => reader(id));
    if (live === null) return { key, id, live: null };
    return { key, id: exactReturnedId(live, id), live };
  }));
}

function exactReturnedId(live, expectedId) {
  const id = safeId(live?.id);
  if (!id || id !== expectedId) throw new ObservedStateError('invalid_provider_response');
  return id;
}

function makeObserved({
  kind,
  key,
  locator,
  marker,
  liveMatchesDesired,
  desired,
  receipt,
  pendingCreateProvenance = false,
}) {
  const expectedMarker = ownershipMarker(receipt?.installationId ?? desired?.desired?.metadata?.installationId ?? 'invalid', key);
  const markerMatches = marker === expectedMarker;
  const receiptResource = receipt?.resources.find((resource) =>
    resource.kind === kind && resource.key === key && sameLocator(resource.provider, locator));
  const pendingMatches = receipt?.pending?.type === 'apply'
    && receipt.pending.action === 'create'
    && receipt.pending.kind === kind
    && receipt.pending.key === key
    && desired
    && receipt.pending.expectedDesiredHash === desired.desiredHash;
  const markerlessPortalApplication = kind === 'portal_access_application';
  const pendingApplicationNeedsProvenance = markerlessPortalApplication
    || kind === 'source_access_application';
  const owned = markerlessPortalApplication
    ? Boolean(receiptResource)
    : markerMatches && Boolean(receiptResource
      || (pendingMatches && (!pendingApplicationNeedsProvenance || pendingCreateProvenance)));
  return {
    kind,
    key,
    provider: { ...locator },
    owner: owned ? { manager: MANAGER, installationId: receipt.installationId } : {},
    desiredHash: liveMatchesDesired ? desired?.desiredHash ?? '' : '',
  };
}

function serverMatches(live, desired) {
  const expected = desired.desired;
  return serverCreationIdentityMatches(live, desired)
    && live.name === expected.name
    && live.secure_web_gateway === expected.secureWebGateway
    && live.status === 'ready'
    && expectedToolsDiscovered(live.tools, expected.toolPolicy.allowedTools)
    && optionalPromptsAreEmpty(live.updated_prompts)
    && sameEnabledTools(live.updated_tools, expected.toolPolicy.allowedTools);
}

function serverCreationIdentityMatches(live, desired) {
  const expected = desired.desired;
  const authType = expected.authentication.mode === 'none'
    ? 'unauthenticated'
    : expected.authentication.mode === 'oauth'
      ? 'oauth'
      : 'bearer';
  return live.id === desired.key
    && live.hostname === expected.endpoint
    && live.auth_type === authType
    && live.description === ownershipMarker(expected.metadata.installationId, desired.key);
}

function expectedToolsDiscovered(tools, expected) {
  if (!Array.isArray(tools)) return false;
  const names = [];
  for (const tool of tools) {
    if (!tool || typeof tool.name !== 'string' || names.includes(tool.name)) return false;
    names.push(tool.name);
  }
  return expected.every((name) => names.includes(name));
}

function pendingCreateMatches(receipt, desired) {
  return receipt?.pending?.type === 'apply'
    && receipt.pending.action === 'create'
    && receipt.pending.kind === desired.kind
    && receipt.pending.key === desired.key
    && receipt.pending.expectedDesiredHash === desired.desiredHash;
}

function portalBaseMatches(live, desired) {
  const expected = desired.desired;
  if (live.id !== desired.key
    || live.name !== expected.name
    || live.hostname !== expected.hostname
    || live.code_mode !== expected.codeMode
    || live.secure_web_gateway !== expected.secureWebGateway
    || live.description !== ownershipMarker(expected.metadata.installationId, desired.key)) return false;
  if (!Array.isArray(live.servers) || live.servers.length !== expected.sourceMappings.length) return false;
  return expected.sourceMappings.every((mapping) => {
    const matches = live.servers.filter((server) => (server.server_id ?? server.id) === mapping.sourceResourceKey);
    if (matches.length !== 1) return false;
    const server = matches[0];
    return server.default_disabled === true
      && server.on_behalf === mapping.onBehalfOfUser
      && optionalPromptsAreEmpty(server.updated_prompts)
      && sameEnabledTools(server.updated_tools, mapping.allowedTools);
  });
}

function dnsMatches(live, desired) {
  const expected = desired.desired;
  return live.type === expected.recordType
    && normalizeDnsName(live.name) === normalizeDnsName(expected.hostname)
    && normalizeDnsName(live.content) === normalizeDnsName(expected.content)
    && live.proxied === expected.proxied
    && live.comment === ownershipMarker(expected.metadata.installationId, desired.key);
}

function policyMatches(policy, allowedEmails) {
  if (policy.decision !== 'allow') return false;
  if (!emptyRules(policy.exclude) || !emptyRules(policy.require)) return false;
  if (!Array.isArray(policy.include) || policy.include.length !== allowedEmails.length) return false;
  const liveEmails = [];
  for (const rule of policy.include) {
    const email = rule?.email?.email;
    if (typeof email !== 'string') return false;
    liveEmails.push(email.trim().toLowerCase());
  }
  return sameTextSet(liveEmails, allowedEmails);
}

function managedOauthMatches(app, expected) {
  const oauth = app.oauth_configuration;
  const registration = oauth?.dynamic_client_registration;
  const grant = oauth?.grant;
  return expected?.mode === 'managed_oauth'
    && oauth?.enabled === true
    && registration?.enabled === expected.dynamicClientRegistration?.enabled
    && registration.allow_any_on_localhost === expected.dynamicClientRegistration?.allowAnyOnLocalhost
    && registration.allow_any_on_loopback === expected.dynamicClientRegistration?.allowAnyOnLoopback
    && grant?.access_token_lifetime === expected.grant?.accessTokenLifetime
    && grant.session_duration === expected.grant?.sessionDuration;
}

function findServerApps(apps, serverId) {
  return apps
    .filter((app) => isServerApp(app, serverId))
    .map(requireObservedApp);
}

function isServerApp(app, serverId) {
  return app?.type === 'mcp'
    && Array.isArray(app.destinations)
    && app.destinations.some((destination) =>
      destination?.type === 'via_mcp_server_portal'
      && destination.mcp_server_id === serverId);
}

function sourceAccessApplicationMatches(app, serverId, marker) {
  return sourceAccessApplicationBaseMatches(app, serverId, marker);
}

function sourceAccessApplicationBaseMatches(app, serverId, marker) {
  if (app?.name !== marker || app?.type !== 'mcp' || !sourceAppHasNoDomain(app)
    || !Array.isArray(app.destinations) || app.destinations.length !== 1) return false;
  const destination = app.destinations[0];
  return isObject(destination)
    && Object.keys(destination).sort().join(',') === 'mcp_server_id,type'
    && destination.type === 'via_mcp_server_portal'
    && destination.mcp_server_id === serverId;
}

function sourceAccessApplicationReceiptMatches(app, owned, receiptResources, installationId) {
  if (app?.name !== ownershipMarker(installationId, owned.key)
    || app?.type !== 'mcp' || !sourceAppHasNoDomain(app)
    || !Array.isArray(app.destinations) || app.destinations.length !== 1) return false;
  const destination = app.destinations[0];
  return isObject(destination)
    && Object.keys(destination).sort().join(',') === 'mcp_server_id,type'
    && destination.type === 'via_mcp_server_portal'
    && receiptResources.some((resource) =>
      resource.kind === 'mcp_server'
      && resource.provider.id === destination.mcp_server_id);
}

function sourceAppHasNoDomain(app) {
  return app?.domain === undefined || app.domain === null;
}

function portalAccessApplicationBaseMatches(app, expected) {
  if (app?.name !== expected.name
    || expected.applicationType !== 'mcp_portal'
    || expected.destination?.type !== 'public'
    || expected.destination.uri !== expected.hostname
    || app?.type !== 'mcp_portal'
    || app.domain !== expected.hostname
    || !Array.isArray(app.destinations) || app.destinations.length !== 1) return false;
  const destination = app.destinations[0];
  return isObject(destination)
    && Object.keys(destination).sort().join(',') === 'type,uri'
    && destination.type === 'public'
    && destination.uri === expected.hostname;
}

function portalAccessApplicationMatches(app, expected) {
  return portalAccessApplicationBaseMatches(app, expected)
    && managedOauthMatches(app, expected.authentication);
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

function isPortalAppCandidate(app, hostname) {
  return app?.type === 'mcp_portal' && (
    app.domain === hostname ||
    (Array.isArray(app.destinations) && app.destinations.some((destination) =>
      destination?.type === 'public' && destination.uri === hostname))
  );
}

async function verifySingleAccessApp(
  cloudflare,
  candidates,
  predicate,
  diagnostics,
  kind,
  key,
) {
  if (candidates.length !== 1) return null;
  const candidate = candidates[0];
  const live = await providerRead(() => cloudflare.getAccessApp(candidate.id));
  if (live === null || safeId(live?.id) !== candidate.id || !predicate(live)) {
    diagnostics.push({ code: 'access_app_provenance_mismatch', kind, key });
    return null;
  }
  return { ...live, id: candidate.id };
}

function requireObservedApp(app) {
  const id = safeId(app?.id);
  if (!id) throw new ObservedStateError('invalid_provider_response');
  return { ...app, id };
}

function normalizeAllowedEmails(access) {
  const raw = Array.isArray(access?.allowedEmails) ? access.allowedEmails : [];
  return [...new Set(raw
    .filter((email) => typeof email === 'string')
    .map((email) => email.trim().toLowerCase())
    .filter((email) => email.length > 0 && email.length <= 254 && EMAIL.test(email)))]
    .sort(compareText);
}

function sameEnabledTools(tools, expected) {
  if (!Array.isArray(tools)) return false;
  const enabled = [];
  for (const tool of tools) {
    if (!tool || typeof tool.name !== 'string' || typeof tool.enabled !== 'boolean') return false;
    if (tool.enabled) enabled.push(tool.name);
  }
  return sameTextSet(enabled, expected);
}

function sameTextSet(left, right) {
  return left.length === right.length
    && [...new Set(left)].length === left.length
    && [...left].sort(compareText).every((value, index) => value === [...right].sort(compareText)[index]);
}

function emptyRules(value) {
  return value === undefined || (Array.isArray(value) && value.length === 0);
}

function optionalPromptsAreEmpty(value) {
  return value === undefined || (Array.isArray(value) && value.length === 0);
}

function sameLocator(left, right) {
  if (!left || !right || left.id !== right.id) return false;
  return (left.parentId ?? '') === (right.parentId ?? '');
}

function hasLocator(resources, kind, key, locator) {
  return resources.some((resource) => resource.kind === kind
    && resource.key === key
    && sameLocator(resource.provider, locator));
}

function pushObserved(resources, resource) {
  if (!hasLocator(resources, resource.kind, resource.key, resource.provider)) resources.push(resource);
}

function identity(kind, key) {
  return `${kind}\u0000${key}`;
}

function safeId(value) {
  return typeof value === 'string' && SAFE_ID.test(value) ? value : null;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validHostname(value) {
  if (typeof value !== 'string' || value !== value.toLowerCase() || value.length > 253) return false;
  return value.split('.').length > 1
    && value.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}

function normalizeDnsName(value) {
  return typeof value === 'string' ? value.toLowerCase().replace(/\.$/, '') : '';
}

async function providerRead(operation) {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof ObservedStateError) throw error;
    throw new ObservedStateError('provider_read_failed');
  }
}

function compareObserved(left, right) {
  return compareText(left.kind, right.kind)
    || compareText(left.key, right.key)
    || compareText(left.provider?.parentId ?? '', right.provider?.parentId ?? '')
    || compareText(left.provider?.id ?? '', right.provider?.id ?? '');
}

function compareDiagnostics(left, right) {
  return compareText(left.code, right.code)
    || compareText(left.kind ?? '', right.kind ?? '')
    || compareText(left.key ?? '', right.key ?? '');
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}
