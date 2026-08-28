import { validateGatewayConfig } from './config.mjs';

const MANAGER = 'ankka-mcp-gateway';
const HASH_PREFIX = 'sha256:';
const DEFAULT_RELEASE = 'development';
const PORTAL_CNAME_TARGET = 'gateway.agents.cloudflare.com';

export const GATEWAY_REQUIRED_CAPABILITIES = Object.freeze([
  'identity.discovery',
  'account.discovery',
  'zone.discovery',
  'mcp.server.read',
  'mcp.server.write',
  'mcp.server.sync',
  'mcp.portal.read',
  'mcp.portal.write',
  'access.application.read',
  'access.application.write',
  'access.policy.read',
  'access.policy.write',
  'dns.record.read',
  'dns.record.write',
]);

const RESOURCE_ORDER = new Map([
  ['mcp_server', 0],
  ['source_access_application', 1],
  ['source_access_policy', 2],
  ['portal', 3],
  ['portal_access_application', 4],
  ['portal_access_policy', 5],
  ['dns_record', 6],
]);

const RESOURCE_KINDS = new Set(RESOURCE_ORDER.keys());
const RESOURCE_KEY = /^[a-z][a-z0-9-]{0,31}$/;
const SAFE_OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const DESIRED_HASH = /^sha256:[0-9a-f]{64}$/;
const RELEASE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Calculate desired-versus-observed Cloudflare state without performing I/O.
 * Observed input is reduced to explicit, validated identifiers and is never
 * spread into plan output. The result omits raw member emails, but its stable
 * identity digest and other deployment metadata still belong to the customer.
 */
export async function buildGatewayPlan(config, observed, options = {}) {
  const release = normalizeRelease(options.release);
  const desiredState = await buildGatewayDesiredState(config, {
    target: isObject(observed) ? observed.target : undefined,
    access: options.access,
  });
  const { installationId, desiredHash, resources } = desiredState;
  const blockers = [...desiredState.blockers];

  const observedResources = normalizeObservedResources(observed);
  const { changes, uninstall } = reconcile(resources, observedResources, installationId);
  const conflictCount = changes.filter((change) => change.action === 'conflict').length;
  if (conflictCount > 0) {
    blockers.push({
      code: 'resource_conflicts',
      message: 'Resolve existing resource ownership conflicts before deployment.',
    });
  }
  const planId = await stablePlanId({
    schemaVersion: 1,
    installationId,
    desiredHash,
    release,
    requiredCapabilities: GATEWAY_REQUIRED_CAPABILITIES,
    blockers,
    changes,
    uninstall,
  });

  return {
    schemaVersion: 1,
    installationId,
    desiredHash,
    planId,
    release,
    requiredCapabilities: [...GATEWAY_REQUIRED_CAPABILITIES],
    blockers,
    changes,
    uninstall,
  };
}

/**
 * Build the provider-neutral desired resources without reading live state.
 * Raw access identities are consumed only to derive policy count/digests and
 * are never returned.
 */
export async function buildGatewayDesiredState(config, input = {}) {
  validateGatewayConfig(config);

  const target = normalizeTarget(input.target);
  const access = await normalizeAccess(input.access);
  const blockers = buildBlockers(config, target, access);
  const installationId = await stableInstallationId(config.gateway.hostname, target);
  const resources = await buildDesiredResources(config, access, installationId);
  const desiredHash = await hashCanonical({
    schemaVersion: 1,
    installationId,
    resources,
  });

  return {
    schemaVersion: 1,
    installationId,
    desiredHash,
    blockers,
    resources,
    accessPolicy: {
      identityType: 'email',
      identityCount: access.allowedEmails.length,
      identitiesHash: access.identitiesHash,
    },
  };
}

function normalizeRelease(value) {
  if (value === undefined) return DEFAULT_RELEASE;
  if (typeof value !== 'string' || !RELEASE.test(value)) {
    throw new TypeError('options.release must be a safe, non-empty release identifier');
  }
  return value;
}

function normalizeTarget(value) {
  const rawTarget = isObject(value) ? value : {};

  return {
    accountId: safeOpaqueId(rawTarget.accountId),
    zoneId: safeOpaqueId(rawTarget.zoneId),
    zoneName: normalizeHostname(rawTarget.zoneName),
    zoneStatus: typeof rawTarget.zoneStatus === 'string' ? rawTarget.zoneStatus : '',
    zeroTrustReady: rawTarget.zeroTrustReady === true,
  };
}

async function normalizeAccess(value) {
  const rawAccess = isObject(value) ? value : {};
  const unsupportedKeys = Object.keys(rawAccess).filter((key) => key !== 'allowedEmails');
  if (unsupportedKeys.length > 0) {
    throw new TypeError('access input contains unsupported fields');
  }

  const rawEmails = Array.isArray(rawAccess.allowedEmails) ? rawAccess.allowedEmails : [];
  const validEmails = [];
  let invalidEmailCount = 0;

  for (const value of rawEmails) {
    if (typeof value !== 'string') {
      invalidEmailCount += 1;
      continue;
    }
    const email = value.trim().toLowerCase();
    if (email.length === 0 || email.length > 254 || !EMAIL.test(email)) {
      invalidEmailCount += 1;
      continue;
    }
    validEmails.push(email);
  }

  const allowedEmails = [...new Set(validEmails)].sort(compareText);
  return {
    allowedEmails,
    identitiesHash: await hashCanonical({ emails: allowedEmails }),
    allowedEmailsProvided: Array.isArray(rawAccess.allowedEmails),
    invalidEmailCount,
  };
}

function buildBlockers(config, target, access) {
  const blockers = [];

  if (!target.accountId) {
    blockers.push({
      code: 'account_required',
      message: 'Select a Cloudflare account before deployment.',
    });
  }
  if (!target.zoneId || !target.zoneName) {
    blockers.push({
      code: 'active_zone_required',
      message: 'Select an active Cloudflare DNS zone before deployment.',
    });
  } else if (target.zoneStatus !== 'active') {
    blockers.push({
      code: 'zone_not_active',
      message: 'The selected Cloudflare DNS zone must be active.',
    });
  }
  if (target.zoneName && !hostnameBelongsToZone(config.gateway.hostname, target.zoneName)) {
    blockers.push({
      code: 'hostname_outside_zone',
      message: 'The gateway hostname must belong to the selected Cloudflare DNS zone.',
    });
  }
  if (!target.zeroTrustReady) {
    blockers.push({
      code: 'zero_trust_required',
      message: 'Complete Cloudflare Zero Trust setup before deployment.',
    });
  }
  if (!access.allowedEmailsProvided || access.allowedEmails.length === 0) {
    blockers.push({
      code: 'allowed_emails_required',
      message: 'Provide at least one valid email identity for the Access allow policy.',
    });
  }
  if (access.invalidEmailCount > 0) {
    blockers.push({
      code: 'invalid_allowed_emails',
      message: 'Every Access identity must be a valid email address.',
    });
  }

  return blockers;
}

async function stableInstallationId(hostname, target) {
  const digest = await hashHex({
    hostname,
    accountId: target.accountId ?? '',
    zoneId: target.zoneId ?? '',
  });
  return `acg-${digest.slice(0, 24)}`;
}

async function stablePlanId(value) {
  const digest = await hashHex(value);
  return `plan-${digest.slice(0, 24)}`;
}

async function buildDesiredResources(config, access, installationId) {
  const sources = [...config.sources]
    .map((source) => ({ ...source, enabledTools: [...source.enabledTools].sort(compareText) }))
    .sort((left, right) => compareText(left.id, right.id));
  const metadata = { manager: MANAGER, installationId };
  const emailAllowPolicy = {
    identitiesRef: 'access.allowedEmails',
    identityType: 'email',
    identityCount: access.allowedEmails.length,
    identitiesHash: access.identitiesHash,
  };
  const resourceSpecs = [];
  const sourceMappings = [];

  for (const source of sources) {
    const mcpKey = await stableResourceKey('mcp', installationId, source.id);
    const applicationKey = await stableResourceKey('source-app', installationId, source.id);
    const accessKey = await stableResourceKey('source-access', installationId, source.id);
    sourceMappings.push({
      sourceResourceKey: mcpKey,
      defaultDisabled: true,
      allowedTools: source.enabledTools,
      onBehalfOfUser: source.authentication.onBehalfOfUser,
    });

    resourceSpecs.push({
      kind: 'mcp_server',
      key: mcpKey,
      desired: {
        metadata,
        sourceId: source.id,
        name: source.label,
        endpoint: source.url,
        capabilityMode: 'read_only',
        secureWebGateway: false,
        toolPolicy: {
          defaultDisabled: true,
          allowedTools: source.enabledTools,
        },
        authentication: {
          mode: source.authentication.mode,
          onBehalfOfUser: source.authentication.onBehalfOfUser,
          credentialCustody: 'customer',
        },
      },
    });
    resourceSpecs.push({
      kind: 'source_access_application',
      key: applicationKey,
      desired: {
        metadata,
        sourceResourceKey: mcpKey,
        applicationType: 'mcp',
      },
    });
    resourceSpecs.push({
      kind: 'source_access_policy',
      key: accessKey,
      desired: {
        metadata,
        sourceApplicationResourceKey: applicationKey,
        defaultAction: 'deny',
        allow: emailAllowPolicy,
      },
    });
  }

  const portalKey = await stableResourceKey('portal', installationId, config.gateway.hostname);
  const portalApplicationKey = await stableResourceKey(
    'portal-app',
    installationId,
    config.gateway.hostname,
  );
  const portalAccessKey = await stableResourceKey(
    'portal-access',
    installationId,
    config.gateway.hostname,
  );
  const dnsKey = await stableResourceKey('dns', installationId, config.gateway.hostname);

  resourceSpecs.push({
    kind: 'portal',
    key: portalKey,
    desired: {
      metadata,
      name: config.gateway.name,
      hostname: config.gateway.hostname,
      capabilityMode: 'read_only',
      codeMode: config.gateway.codeMode,
      secureWebGateway: false,
      sourceMappings,
    },
  });
  resourceSpecs.push({
    kind: 'portal_access_application',
    key: portalApplicationKey,
    desired: {
      metadata,
      portalResourceKey: portalKey,
      name: config.gateway.name,
      hostname: config.gateway.hostname,
      applicationType: 'mcp_portal',
      destination: {
        type: 'public',
        uri: config.gateway.hostname,
      },
      authentication: {
        mode: 'managed_oauth',
        dynamicClientRegistration: {
          enabled: true,
          allowAnyOnLocalhost: true,
          allowAnyOnLoopback: true,
        },
        grant: {
          accessTokenLifetime: '15m',
          sessionDuration: '336h',
        },
      },
    },
  });
  resourceSpecs.push({
    kind: 'portal_access_policy',
    key: portalAccessKey,
    desired: {
      metadata,
      portalApplicationResourceKey: portalApplicationKey,
      defaultAction: 'deny',
      allow: emailAllowPolicy,
    },
  });
  resourceSpecs.push({
    kind: 'dns_record',
    key: dnsKey,
    desired: {
      metadata,
      recordType: 'CNAME',
      hostname: config.gateway.hostname,
      content: PORTAL_CNAME_TARGET,
      proxied: true,
      dependsOnResourceKey: portalKey,
    },
  });

  return Promise.all(
    resourceSpecs.map(async (resource) => ({
      ...resource,
      desiredHash: await hashCanonical({
        schemaVersion: 1,
        kind: resource.kind,
        key: resource.key,
        desired: resource.desired,
      }),
    })),
  );
}

async function stableResourceKey(prefix, installationId, logicalId) {
  const digest = await hashHex({ installationId, prefix, logicalId });
  const hint = logicalId
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  const hintLength = Math.max(0, 32 - prefix.length - 10);
  if (hint && hintLength > 0) {
    return `${prefix}-${hint.slice(0, hintLength)}-${digest.slice(0, 8)}`;
  }
  return `${prefix}-${digest.slice(0, 32 - prefix.length - 1)}`;
}

function normalizeObservedResources(observed) {
  const rawResources = isObject(observed) && Array.isArray(observed.resources)
    ? observed.resources
    : [];
  const resources = [];

  for (const raw of rawResources) {
    if (!isObject(raw) || !RESOURCE_KINDS.has(raw.kind) || !RESOURCE_KEY.test(raw.key)) {
      continue;
    }
    const owner = isObject(raw.owner) ? raw.owner : {};
    const provider = normalizeProviderLocator(raw.kind, raw.provider);
    resources.push({
      kind: raw.kind,
      key: raw.key,
      ...(provider ? { provider } : {}),
      ownerMatchesManager: owner.manager === MANAGER,
      ownerInstallationId:
        typeof owner.installationId === 'string' && RESOURCE_KEY.test(owner.installationId)
          ? owner.installationId
          : '',
      desiredHash:
        typeof raw.desiredHash === 'string' && DESIRED_HASH.test(raw.desiredHash)
          ? raw.desiredHash
          : '',
    });
  }

  return resources.sort(compareObservedResources);
}

function reconcile(desiredResources, observedResources, installationId) {
  const desiredIdentities = new Set(
    desiredResources.map((resource) => resourceIdentity(resource.kind, resource.key)),
  );
  const observedByIdentity = new Map();

  for (const resource of observedResources) {
    const identity = resourceIdentity(resource.kind, resource.key);
    const matches = observedByIdentity.get(identity) ?? [];
    matches.push(resource);
    observedByIdentity.set(identity, matches);
  }

  const changes = desiredResources.map((desired) => {
    const candidates = observedByIdentity.get(resourceIdentity(desired.kind, desired.key)) ?? [];
    if (candidates.length === 0) return desiredChange('create', desired);
    if (candidates.length > 1) {
      return desiredChange('conflict', desired, undefined, 'ambiguous_observed_resource');
    }

    const observed = candidates[0];
    if (!isOwned(observed, installationId)) {
      return desiredChange(
        'conflict',
        desired,
        observed.provider,
        'foreign_resource_collision',
      );
    }
    if (observed.desiredHash === desired.desiredHash) {
      return desiredChange(
        'noop',
        desired,
        observed.provider,
        undefined,
      );
    }
    return desiredChange(
      'update',
      desired,
      observed.provider,
      'owned_resource_drift',
    );
  });

  const staleByIdentity = new Map();
  for (const observed of observedResources) {
    const identity = resourceIdentity(observed.kind, observed.key);
    if (desiredIdentities.has(identity) || !isOwned(observed, installationId)) continue;
    const matches = staleByIdentity.get(identity) ?? [];
    matches.push(observed);
    staleByIdentity.set(identity, matches);
  }

  const staleChanges = [];
  for (const matches of staleByIdentity.values()) {
    const observed = matches[0];
    if (matches.length > 1) {
      staleChanges.push({
        action: 'conflict',
        kind: observed.kind,
        key: observed.key,
        reason: 'ambiguous_observed_resource',
      });
    } else {
      staleChanges.push({
        action: 'delete',
        kind: observed.kind,
        key: observed.key,
        ...(observed.provider ? { provider: observed.provider } : {}),
        reason: 'stale_owned_resource',
      });
    }
  }
  staleChanges.sort(compareReverseResourceOrder);
  changes.push(...staleChanges);

  const uninstall = observedResources
    .filter((resource) => isOwned(resource, installationId))
    .map((resource) => ({
      action: 'delete',
      kind: resource.kind,
      key: resource.key,
      ...(resource.provider ? { provider: resource.provider } : {}),
    }))
    .sort(compareReverseResourceOrder);

  return { changes, uninstall };
}

function desiredChange(action, resource, provider, reason) {
  return {
    action,
    kind: resource.kind,
    key: resource.key,
    desiredHash: resource.desiredHash,
    desired: resource.desired,
    ...(provider ? { provider } : {}),
    ...(reason ? { reason } : {}),
  };
}

function isOwned(resource, installationId) {
  return resource.ownerMatchesManager
    && resource.ownerInstallationId === installationId;
}

function resourceIdentity(kind, key) {
  return `${kind}\u0000${key}`;
}

function compareObservedResources(left, right) {
  return (
    resourceRank(left.kind) - resourceRank(right.kind) ||
    compareText(left.key, right.key) ||
    compareText(providerLocatorText(left.provider), providerLocatorText(right.provider))
  );
}

function compareReverseResourceOrder(left, right) {
  return (
    resourceRank(right.kind) - resourceRank(left.kind) ||
    compareText(left.key, right.key) ||
    compareText(providerLocatorText(left.provider), providerLocatorText(right.provider))
  );
}

function resourceRank(kind) {
  return RESOURCE_ORDER.get(kind) ?? -1;
}

function hostnameBelongsToZone(hostname, zoneName) {
  return hostname === zoneName || hostname.endsWith(`.${zoneName}`);
}

function normalizeHostname(value) {
  if (typeof value !== 'string' || value.length > 253 || value !== value.toLowerCase()) {
    return '';
  }
  const labels = value.split('.');
  if (labels.length < 2 || !labels.every((label) => HOST_LABEL.test(label))) return '';
  return value;
}

function safeOpaqueId(value) {
  return typeof value === 'string' && SAFE_OPAQUE_ID.test(value) ? value : null;
}

function normalizeProviderLocator(kind, value) {
  if (!isObject(value)) return null;
  const policy = kind === 'source_access_policy' || kind === 'portal_access_policy';
  const expectedKeys = policy ? ['id', 'parentId'] : ['id'];
  const actualKeys = Object.keys(value).sort(compareText);
  if (
    actualKeys.length !== expectedKeys.length ||
    !expectedKeys.every((key) => actualKeys.includes(key))
  ) {
    return null;
  }
  const id = safeOpaqueId(value.id);
  const parentId = policy ? safeOpaqueId(value.parentId) : null;
  if (!id || (policy && !parentId)) return null;
  return policy ? { id, parentId } : { id };
}

function providerLocatorText(value) {
  if (!isObject(value)) return '';
  return `${value.parentId ?? ''}\u0000${value.id ?? ''}`;
}

async function hashCanonical(value) {
  return `${HASH_PREFIX}${await hashHex(value)}`;
}

async function hashHex(value) {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto is required to build a gateway plan');
  }
  const bytes = new TextEncoder().encode(canonicalJson(value));
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Cannot hash a non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }
  if (isObject(value)) {
    return `{${Object.keys(value)
      .sort(compareText)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  throw new TypeError(`Cannot hash unsupported value type: ${typeof value}`);
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
