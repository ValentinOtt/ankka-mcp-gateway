import * as v from 'valibot';

import {
  accessGroupDigest,
  accessGroupsNamed,
  normalizeAccessGroups,
  type AccessGroupObservation,
} from './access-groups.ts';
import {
  assertCanaryServiceIdentityConfig,
  canaryServiceIdentityDigest,
  canaryServiceTokenId,
} from './canary-service-identity.ts';
import { validateGatewayConfig, type GatewayConfig } from './config.ts';
import {
  boundaryObjectSchema,
  type BoundaryObject,
  type BoundaryValue,
  type JsonObject,
  type JsonValue,
} from './json.ts';

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

const RESOURCE_ORDER = new Map<ResourceKind, number>([
  ['mcp_server', 0],
  ['source_access_application', 1],
  ['source_access_policy', 2],
  ['portal', 3],
  ['portal_access_application', 4],
  ['portal_access_policy', 5],
  ['dns_record', 6],
]);

const RESOURCE_KEY = /^[a-z][a-z0-9-]{0,31}$/;
const SAFE_OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const DESIRED_HASH = /^sha256:[0-9a-f]{64}$/;
const RELEASE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

const resourceKindSchema = v.picklist([
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
]);
const stringSchema = v.string();
const booleanSchema = v.boolean();
const numberSchema = v.number();

export type ResourceKind = v.InferOutput<typeof resourceKindSchema>;
type ChangeAction = 'conflict' | 'create' | 'delete' | 'noop' | 'update';

export interface GatewayPlanOptions {
  readonly access?: BoundaryValue;
  readonly release?: BoundaryValue;
}

export interface GatewayDesiredStateInput {
  readonly access?: BoundaryValue;
  readonly target?: BoundaryValue;
}

interface DeploymentTarget {
  readonly accountId: string | null;
  readonly zoneId: string | null;
  readonly zoneName: string;
  readonly zoneStatus: string;
  readonly zeroTrustReady: boolean;
}

interface NormalizedAccess {
  readonly accessGroups: readonly AccessGroupObservation[];
  readonly accessGroupsProvided: boolean;
  readonly allowedEmails: readonly string[];
  readonly allowedEmailsProvided: boolean;
  readonly canaryServiceIdentity: boolean;
  readonly identitiesHash: string;
  readonly invalidAccessGroupCount: number;
  readonly invalidEmailCount: number;
}

export type PlanBlocker = {
  readonly code: string;
  readonly message: string;
};

export type ProviderLocator = {
  readonly id: string;
  readonly parentId?: string;
};

export type DesiredResource = {
  readonly desired: JsonObject;
  readonly desiredHash: string;
  readonly key: string;
  readonly kind: ResourceKind;
};

type ResourceSpec = Omit<DesiredResource, 'desiredHash'>;

interface ObservedResource {
  readonly desiredHash: string;
  readonly key: string;
  readonly kind: ResourceKind;
  readonly ownerInstallationId: string;
  readonly ownerMatchesManager: boolean;
  readonly provider?: ProviderLocator;
}

export type PlanChange = {
  action: ChangeAction;
  desired?: JsonObject;
  desiredHash?: string;
  key: string;
  kind: ResourceKind;
  provider?: ProviderLocator;
  reason?: string;
};

interface Reconciliation {
  readonly changes: PlanChange[];
  readonly uninstall: PlanChange[];
}

export interface GatewayPlan {
  readonly blockers: readonly PlanBlocker[];
  readonly changes: readonly PlanChange[];
  readonly desiredHash: string;
  readonly installationId: string;
  readonly planId: string;
  readonly release: string;
  readonly requiredCapabilities: readonly string[];
  readonly schemaVersion: 1;
  readonly uninstall: readonly PlanChange[];
}

export interface GatewayDesiredState {
  readonly accessPolicy: {
    readonly identitiesHash: string;
    readonly identityCount: number;
    readonly identityType: 'email' | 'service_token';
  };
  readonly blockers: readonly PlanBlocker[];
  readonly desiredHash: string;
  readonly installationId: string;
  readonly resources: readonly DesiredResource[];
  readonly schemaVersion: 1;
}

/**
 * Calculate desired-versus-observed Cloudflare state without performing I/O.
 * Observed input is reduced to explicit, validated identifiers and is never
 * spread into plan output. The result omits raw member emails, but its stable
 * identity digest and other deployment metadata still belong to the customer.
 */
export async function buildGatewayPlan(
  config: JsonValue,
  observed: BoundaryValue,
  options: GatewayPlanOptions = {},
): Promise<GatewayPlan> {
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
export async function buildGatewayDesiredState(
  configInput: JsonValue,
  input: GatewayDesiredStateInput = {},
): Promise<GatewayDesiredState> {
  const config = validateGatewayConfig(configInput);

  const target = normalizeTarget(input.target);
  const access = await normalizeAccess(input.access);
  if (access.canaryServiceIdentity) assertCanaryServiceIdentityConfig(config);
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
      identityType: access.canaryServiceIdentity ? 'service_token' : 'email',
      identityCount: access.canaryServiceIdentity ? 1 : access.allowedEmails.length,
      identitiesHash: access.identitiesHash,
    },
  };
}

function normalizeRelease(value: BoundaryValue): string {
  if (value === undefined) return DEFAULT_RELEASE;
  if (!isString(value) || !RELEASE.test(value)) {
    throw new TypeError('options.release must be a safe, non-empty release identifier');
  }
  return value;
}

function normalizeTarget(value: BoundaryValue): DeploymentTarget {
  const rawTarget = isObject(value) ? value : {};

  return {
    accountId: safeOpaqueId(rawTarget.accountId),
    zoneId: safeOpaqueId(rawTarget.zoneId),
    zoneName: normalizeHostname(rawTarget.zoneName),
    zoneStatus: isString(rawTarget.zoneStatus) ? rawTarget.zoneStatus : '',
    zeroTrustReady: rawTarget.zeroTrustReady === true,
  };
}

async function normalizeAccess(value: BoundaryValue): Promise<NormalizedAccess> {
  const rawAccess = isObject(value) ? value : {};
  const unsupportedKeys = Object.keys(rawAccess)
    .filter((key) => key !== 'allowedEmails' && key !== 'groups' && key !== 'canaryServiceTokenId');
  if (unsupportedKeys.length > 0) {
    throw new TypeError('access input contains unsupported fields');
  }
  const normalizedGroups = normalizeAccessGroups(rawAccess);
  const serviceTokenId = canaryServiceTokenId(rawAccess);

  const rawEmails = Array.isArray(rawAccess.allowedEmails) ? rawAccess.allowedEmails : [];
  const validEmails: string[] = [];
  let invalidEmailCount = 0;

  for (const rawEmail of rawEmails) {
    if (!isString(rawEmail)) {
      invalidEmailCount += 1;
      continue;
    }
    const email = rawEmail.trim().toLowerCase();
    if (email.length === 0 || email.length > 254 || !EMAIL.test(email)) {
      invalidEmailCount += 1;
      continue;
    }
    validEmails.push(email);
  }

  const allowedEmails = [...new Set(validEmails)].sort(compareText);
  return {
    accessGroups: normalizedGroups.groups,
    accessGroupsProvided: normalizedGroups.provided,
    allowedEmails,
    canaryServiceIdentity: serviceTokenId !== null,
    identitiesHash: serviceTokenId === null
      ? await hashCanonical({ emails: allowedEmails })
      : await canaryServiceIdentityDigest(serviceTokenId),
    allowedEmailsProvided: Array.isArray(rawAccess.allowedEmails),
    invalidAccessGroupCount: normalizedGroups.invalidCount,
    invalidEmailCount,
  };
}

function buildBlockers(
  config: GatewayConfig,
  target: DeploymentTarget,
  access: NormalizedAccess,
): PlanBlocker[] {
  const blockers: PlanBlocker[] = [];

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
  if (!access.canaryServiceIdentity
    && (!access.allowedEmailsProvided || access.allowedEmails.length === 0)) {
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
  if (access.invalidAccessGroupCount > 0) {
    blockers.push({
      code: 'invalid_access_groups',
      message: 'Every Access group observation must contain only one safe ID and exact name.',
    });
  }
  for (const source of config.sources) {
    if (source.accessGroup === undefined) continue;
    const matches = accessGroupsNamed(access.accessGroups, source.accessGroup);
    if (!access.accessGroupsProvided || matches.length === 0) {
      blockers.push({
        code: 'source_access_group_missing',
        message: `Resolve one fresh Access group observation for source ${source.id}.`,
      });
    } else if (matches.length > 1) {
      blockers.push({
        code: 'source_access_group_ambiguous',
        message: `Resolve exactly one fresh Access group observation for source ${source.id}.`,
      });
    }
  }

  return blockers;
}

async function stableInstallationId(
  hostname: string,
  target: DeploymentTarget,
): Promise<string> {
  const digest = await hashHex({
    hostname,
    accountId: target.accountId ?? '',
    zoneId: target.zoneId ?? '',
  });
  return `acg-${digest.slice(0, 24)}`;
}

async function stablePlanId(value: JsonValue): Promise<string> {
  const digest = await hashHex(value);
  return `plan-${digest.slice(0, 24)}`;
}

async function buildDesiredResources(
  config: GatewayConfig,
  access: NormalizedAccess,
  installationId: string,
): Promise<DesiredResource[]> {
  const sources = [...config.sources]
    .map((source) => ({ ...source, enabledTools: [...source.enabledTools].sort(compareText) }))
    .sort((left, right) => compareText(left.id, right.id));
  const metadata = { manager: MANAGER, installationId };
  const defaultAllowPolicy: JsonObject = {
    identitiesRef: access.canaryServiceIdentity ? 'access.canaryServiceTokenId' : 'access.allowedEmails',
    identityType: access.canaryServiceIdentity ? 'service_token' : 'email',
    identityCount: access.canaryServiceIdentity ? 1 : access.allowedEmails.length,
    identitiesHash: access.identitiesHash,
  };
  const resourceSpecs: ResourceSpec[] = [];
  const sourceMappings: JsonObject[] = [];

  for (const source of sources) {
    const mcpKey = await stableResourceKey('mcp', installationId, source.id);
    const applicationKey = await stableResourceKey('source-app', installationId, source.id);
    const accessKey = await stableResourceKey('source-access', installationId, source.id);
    const sourceAllowPolicy = source.accessGroup === undefined
      ? defaultAllowPolicy
      : await groupAllowPolicy(source.accessGroup, access);
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
        allow: sourceAllowPolicy,
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
      allow: defaultAllowPolicy,
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

async function groupAllowPolicy(
  logicalName: string,
  access: NormalizedAccess,
): Promise<JsonObject> {
  const matches = accessGroupsNamed(access.accessGroups, logicalName);
  return {
    identitiesRef: 'access.groups',
    identityType: 'group',
    identityCount: matches.length,
    identitiesHash: await accessGroupDigest(matches),
  };
}

async function stableResourceKey(
  prefix: string,
  installationId: string,
  logicalId: string,
): Promise<string> {
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

function normalizeObservedResources(observed: BoundaryValue): ObservedResource[] {
  const rawResources = isObject(observed) && Array.isArray(observed.resources)
    ? observed.resources
    : [];
  const resources: ObservedResource[] = [];

  for (const raw of rawResources) {
    if (!isObject(raw) || !isResourceKind(raw.kind) || !isResourceKey(raw.key)) {
      continue;
    }
    const owner = isObject(raw.owner) ? raw.owner : {};
    const provider = normalizeProviderLocator(raw.kind, raw.provider);
    const resource: ObservedResource = {
      kind: raw.kind,
      key: raw.key,
      ownerMatchesManager: owner.manager === MANAGER,
      ownerInstallationId:
        isResourceKey(owner.installationId)
          ? owner.installationId
          : '',
      desiredHash:
        isString(raw.desiredHash) && DESIRED_HASH.test(raw.desiredHash)
          ? raw.desiredHash
          : '',
    };
    resources.push(provider ? { ...resource, provider } : resource);
  }

  return resources.sort(compareObservedResources);
}

function reconcile(
  desiredResources: readonly DesiredResource[],
  observedResources: readonly ObservedResource[],
  installationId: string,
): Reconciliation {
  const desiredIdentities = new Set(
    desiredResources.map((resource) => resourceIdentity(resource.kind, resource.key)),
  );
  const observedByIdentity = new Map<string, ObservedResource[]>();

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

    const observed = candidates.at(0);
    if (!observed) throw new Error('Observed resource reconciliation invariant failed');
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

  const staleByIdentity = new Map<string, ObservedResource[]>();
  for (const observed of observedResources) {
    const identity = resourceIdentity(observed.kind, observed.key);
    if (desiredIdentities.has(identity) || !isOwned(observed, installationId)) continue;
    const matches = staleByIdentity.get(identity) ?? [];
    matches.push(observed);
    staleByIdentity.set(identity, matches);
  }

  const staleChanges: PlanChange[] = [];
  for (const matches of staleByIdentity.values()) {
    const observed = matches.at(0);
    if (!observed) throw new Error('Stale resource reconciliation invariant failed');
    if (matches.length > 1) {
      staleChanges.push({
        action: 'conflict',
        kind: observed.kind,
        key: observed.key,
        reason: 'ambiguous_observed_resource',
      });
    } else {
      const change: PlanChange = {
        action: 'delete',
        kind: observed.kind,
        key: observed.key,
        reason: 'stale_owned_resource',
      };
      if (observed.provider) change.provider = observed.provider;
      staleChanges.push(change);
    }
  }
  staleChanges.sort(compareReverseResourceOrder);
  changes.push(...staleChanges);

  const uninstall = observedResources
    .filter((resource) => isOwned(resource, installationId))
    .map((resource) => {
      const change: PlanChange = {
        action: 'delete',
        kind: resource.kind,
        key: resource.key,
      };
      if (resource.provider) change.provider = resource.provider;
      return change;
    })
    .sort(compareReverseResourceOrder);

  return { changes, uninstall };
}

function desiredChange(
  action: ChangeAction,
  resource: DesiredResource,
  provider?: ProviderLocator,
  reason?: string,
): PlanChange {
  const change: PlanChange = {
    action,
    kind: resource.kind,
    key: resource.key,
    desiredHash: resource.desiredHash,
    desired: resource.desired,
  };
  if (provider) change.provider = provider;
  if (reason) change.reason = reason;
  return change;
}

function isOwned(resource: ObservedResource, installationId: string): boolean {
  return resource.ownerMatchesManager
    && resource.ownerInstallationId === installationId;
}

function resourceIdentity(kind: ResourceKind, key: string): string {
  return `${kind}\u0000${key}`;
}

function compareObservedResources(left: ObservedResource, right: ObservedResource): number {
  return (
    resourceRank(left.kind) - resourceRank(right.kind) ||
    compareText(left.key, right.key) ||
    compareText(providerLocatorText(left.provider), providerLocatorText(right.provider))
  );
}

function compareReverseResourceOrder(left: PlanChange, right: PlanChange): number {
  return (
    resourceRank(right.kind) - resourceRank(left.kind) ||
    compareText(left.key, right.key) ||
    compareText(providerLocatorText(left.provider), providerLocatorText(right.provider))
  );
}

function resourceRank(kind: ResourceKind): number {
  return RESOURCE_ORDER.get(kind) ?? -1;
}

function hostnameBelongsToZone(hostname: string, zoneName: string): boolean {
  return hostname === zoneName || hostname.endsWith(`.${zoneName}`);
}

function normalizeHostname(value: BoundaryValue): string {
  if (!isString(value) || value.length > 253 || value !== value.toLowerCase()) {
    return '';
  }
  const labels = value.split('.');
  if (labels.length < 2 || !labels.every((label) => HOST_LABEL.test(label))) return '';
  return value;
}

function safeOpaqueId(value: BoundaryValue): string | null {
  return isString(value) && SAFE_OPAQUE_ID.test(value) ? value : null;
}

function normalizeProviderLocator(
  kind: ResourceKind,
  value: BoundaryValue,
): ProviderLocator | null {
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
  if (parentId) return { id, parentId };
  return { id };
}

function providerLocatorText(value: ProviderLocator | undefined): string {
  if (!value) return '';
  return `${value.parentId ?? ''}\u0000${value.id ?? ''}`;
}

async function hashCanonical(value: JsonValue): Promise<string> {
  return `${HASH_PREFIX}${await hashHex(value)}`;
}

async function hashHex(value: JsonValue): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto is required to build a gateway plan');
  }
  const bytes = new TextEncoder().encode(canonicalJson(value));
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function canonicalJson(value: JsonValue): string {
  if (value === null || v.is(booleanSchema, value) || isString(value)) {
    return serializeJsonPrimitive(value);
  }
  if (v.is(numberSchema, value)) {
    if (!Number.isFinite(value)) throw new TypeError('Cannot hash a non-finite number');
    return serializeJsonPrimitive(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }
  if (isObject(value)) {
    return `{${Object.entries(value)
      .sort(([left], [right]) => compareText(left, right))
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`)
      .join(',')}}`;
  }
  throw new TypeError('Cannot hash unsupported JSON value');
}

function serializeJsonPrimitive(value: boolean | null | number | string): string {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) throw new TypeError('Cannot serialize JSON primitive');
  return serialized;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isObject(value: BoundaryValue): value is BoundaryObject {
  return v.is(boundaryObjectSchema, value);
}

function isString(value: BoundaryValue): value is string {
  return v.is(stringSchema, value);
}

function isResourceKind(value: BoundaryValue): value is ResourceKind {
  return v.is(resourceKindSchema, value);
}

function isResourceKey(value: BoundaryValue): value is string {
  return isString(value) && RESOURCE_KEY.test(value);
}
