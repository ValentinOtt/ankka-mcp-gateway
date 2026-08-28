import * as v from 'valibot';

import type { CloudflareQuery } from './cloudflare-client.ts';
import { validateGatewayConfig } from './config.ts';
import {
  boundaryObjectSchema,
  type BoundaryObject,
  type BoundaryValue,
  type JsonObject,
  type JsonValue,
} from './json.ts';
import {
  buildGatewayDesiredState,
  type DesiredResource,
  type GatewayDesiredState,
  type ResourceKind,
} from './plan.ts';
import {
  ownershipMarker,
  validateInstallationReceipt,
  type InstallationReceipt,
  type ReceiptProviderLocator,
  type ReceiptResource,
  type ReceiptTarget,
} from './receipt.ts';

const MANAGER = 'ankka-mcp-gateway';
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const stringSchema = v.string();
const booleanSchema = v.boolean();
const functionSchema = v.function();
const POLICY_KINDS = new Set<ResourceKind>(['source_access_policy', 'portal_access_policy']);
const SAFE_ERROR_CODES = new Set([
  'invalid_input',
  'provider_read_failed',
  'invalid_provider_response',
  'zone_not_found',
  'zone_mismatch',
  'zone_account_mismatch',
]);

export interface CloudflareObservedReader {
  getAccessApp(id: string): Promise<BoundaryValue>;
  getAppPolicy(parentId: string, id: string): Promise<BoundaryValue>;
  getDnsRecord(id: string): Promise<BoundaryValue>;
  getMcpServer(id: string): Promise<BoundaryValue>;
  getPortal(id: string): Promise<BoundaryValue>;
  getZone(): Promise<BoundaryValue>;
  listAccessApps(): Promise<BoundaryValue>;
  listAppPolicies(parentId: string): Promise<BoundaryValue>;
  listDnsRecords(query: CloudflareQuery): Promise<BoundaryValue>;
  listIdentityProviders(): Promise<BoundaryValue>;
}

export interface CloudflareObservedStateInput {
  readonly access?: BoundaryValue;
  readonly cloudflare: CloudflareObservedReader;
  readonly config: JsonValue;
  readonly receipt?: BoundaryValue;
  readonly target: BoundaryValue;
}

export type ObservedProviderLocator = {
  readonly id: string;
  readonly parentId?: string;
};

type ObservedOwner = {
  readonly installationId?: string;
  readonly manager?: string;
};

export type CloudflareObservedResource = {
  readonly desiredHash: string;
  readonly key: string;
  readonly kind: ResourceKind;
  readonly owner: ObservedOwner;
  readonly provider?: ObservedProviderLocator;
};

export type ObservedDiagnostic = {
  readonly code: string;
  readonly count?: number;
  readonly key?: string;
  readonly kind?: ResourceKind;
};

export type VerifiedCloudflareTarget = {
  accountId: string;
  zeroTrustReady: boolean;
  zoneId: string;
  zoneName: string;
  zoneStatus: string;
};

export interface CloudflareObservedState {
  readonly diagnostics: readonly ObservedDiagnostic[];
  readonly resources: readonly CloudflareObservedResource[];
  readonly target: VerifiedCloudflareTarget;
}

interface SelectedTarget {
  readonly accountId: string;
  readonly zoneId: string;
}

interface EntityRead {
  readonly id: string;
  readonly key: string;
}

interface EntityResult extends EntityRead {
  readonly live: BoundaryObject | null;
}

interface MakeObservedInput {
  readonly desired: DesiredResource | undefined;
  readonly key: string;
  readonly kind: ResourceKind;
  readonly liveMatchesDesired: boolean;
  readonly locator: ObservedProviderLocator;
  readonly marker?: BoundaryValue;
  readonly pendingCreateProvenance?: boolean;
  readonly receipt: InstallationReceipt | null;
}

type ObservedApp = BoundaryObject & { readonly id: string };

export class ObservedStateError extends Error {
  readonly code: string;

  constructor(code: string) {
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
  config: configInput,
  target,
  access,
  receipt,
}: CloudflareObservedStateInput): Promise<CloudflareObservedState> {
  requireReader(cloudflare);
  const config = validateGatewayConfig(configInput);
  const selectedTarget = normalizeSelectedTarget(target);
  const zone = await providerRead(() => cloudflare.getZone());
  const verifiedTarget = verifyZone(zone, selectedTarget);
  const identityProviders = await providerRead(() => cloudflare.listIdentityProviders());
  if (!Array.isArray(identityProviders)) throw new ObservedStateError('invalid_provider_response');
  verifiedTarget.zeroTrustReady = identityProviders.length > 0;

  let desiredState: GatewayDesiredState;
  try {
    desiredState = await buildGatewayDesiredState(configInput, {
      target: verifiedTarget,
      access,
    });
  } catch {
    throw new ObservedStateError('invalid_input');
  }

  const diagnostics: ObservedDiagnostic[] = [];
  const trustedReceipt = await readTrustedReceipt(receipt, desiredState.installationId, {
    accountId: verifiedTarget.accountId,
    zoneId: verifiedTarget.zoneId,
    zoneName: verifiedTarget.zoneName,
    hostname: config.gateway.hostname,
  }, diagnostics);
  const desiredByIdentity = new Map(
    desiredState.resources.map((resource) => [identity(resource.kind, resource.key), resource]),
  );
  const receiptResources: readonly ReceiptResource[] = trustedReceipt?.resources ?? [];
  const resources: CloudflareObservedResource[] = [];

  const serverReads = buildEntityReads('mcp_server', desiredState.resources, receiptResources);
  const portalReads = buildEntityReads('portal', desiredState.resources, receiptResources);
  const [serverResults, portalResults, dnsRecords, accessApps] = await Promise.all([
    readEntities(serverReads, (id: string) => cloudflare.getMcpServer(id)),
    readEntities(portalReads, (id: string) => cloudflare.getPortal(id)),
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
      .filter((app) => (isObject(app) && app.name === marker) || isServerApp(app, serverId))
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
    const seenApplicationIds = new Set<string>();
    for (const candidate of candidates) {
      if (seenApplicationIds.has(candidate.id)) continue;
      seenApplicationIds.add(candidate.id);
      const live = await providerRead(() => cloudflare.getAccessApp(candidate.id));
      if (!isObject(live) || safeId(live.id) !== candidate.id) {
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
      .filter((app) => (isObject(app) && app.name === expectedName)
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
    const seenApplicationIds = new Set<string>();
    for (const candidate of candidates) {
      if (seenApplicationIds.has(candidate.id)) continue;
      seenApplicationIds.add(candidate.id);
      const live = await providerRead(() => cloudflare.getAccessApp(candidate.id));
      if (!isObject(live) || safeId(live.id) !== candidate.id) {
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
  if (!desiredDns) throw new ObservedStateError('invalid_input');
  const seenDnsIds = new Set<string>();
  for (const record of dnsRecords) {
    const recordObject = isObject(record) ? record : null;
    const id = recordObject ? safeId(recordObject.id) : null;
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
      marker: recordObject?.comment,
      liveMatchesDesired: recordObject ? dnsMatches(recordObject, desiredDns) : false,
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
    if (!isObject(record)) continue;
    const id = exactReturnedId(record, ownedDns.provider.id);
    const currentDesiredDns = desiredByIdentity.get(identity('dns_record', ownedDns.key));
    pushObserved(resources, makeObserved({
      kind: 'dns_record',
      key: ownedDns.key,
      locator: { id },
      marker: record.comment,
      liveMatchesDesired: currentDesiredDns
        ? dnsMatches(record, currentDesiredDns)
        : false,
      desired: currentDesiredDns,
      receipt: trustedReceipt,
    }));
  }

  const allowedEmails = normalizeAllowedEmails(access);

  for (const desired of desiredState.resources.filter((resource) => POLICY_KINDS.has(resource.kind))) {
    const parentKey = desired.kind === 'source_access_policy'
      ? desired.desired.sourceApplicationResourceKey
      : desired.desired.portalApplicationResourceKey;
    if (!isString(parentKey)) throw new ObservedStateError('invalid_input');
    const parentKind = desired.kind === 'source_access_policy'
      ? 'source_access_application'
      : 'portal_access_application';
    const liveParent = resources.find((resource) =>
      resource.kind === parentKind
      && resource.key === parentKey
      && resource.owner?.manager === MANAGER);
    if (!liveParent?.provider) continue;
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
    const matches = policies.filter((policy) => isObject(policy) && policy.name === marker);
    const unexpected = policies.filter((policy) => !isObject(policy) || policy.name !== marker);
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
      if (!isObject(policy)) continue;
      const id = safeId(policy.id);
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
    if (!isObject(app) || !trustedReceipt) continue;
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
      ownedPolicy.provider.parentId ?? '',
      ownedPolicy.provider.id,
    ));
    if (!isObject(policy)) continue;
    const parentId = ownedPolicy.provider.parentId;
    if (!parentId) throw new ObservedStateError('invalid_receipt');
    const id = exactReturnedId(policy, ownedPolicy.provider.id);
    pushObserved(resources, makeObserved({
      kind: ownedPolicy.kind,
      key: ownedPolicy.key,
      locator: { id, parentId },
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

function requireReader(cloudflare: CloudflareObservedReader): void {
  const methods: readonly (keyof CloudflareObservedReader)[] = [
    'getZone', 'listIdentityProviders', 'getMcpServer', 'getPortal',
    'listDnsRecords', 'getDnsRecord', 'listAccessApps', 'getAccessApp',
    'listAppPolicies', 'getAppPolicy',
  ];
  if (!v.is(v.object({}), cloudflare)
    || methods.some((method) => !v.safeParse(functionSchema, cloudflare[method]).success)) {
    throw new ObservedStateError('invalid_input');
  }
}

function normalizeSelectedTarget(target: BoundaryValue): SelectedTarget {
  if (!isObject(target)) throw new ObservedStateError('invalid_input');
  const accountId = safeId(target.accountId);
  const zoneId = safeId(target.zoneId);
  if (!accountId || !zoneId) {
    throw new ObservedStateError('invalid_input');
  }
  return { accountId, zoneId };
}

function verifyZone(zone: BoundaryValue, target: SelectedTarget): VerifiedCloudflareTarget {
  if (zone === null) throw new ObservedStateError('zone_not_found');
  if (!isObject(zone)) throw new ObservedStateError('invalid_provider_response');
  if (zone.id !== target.zoneId) throw new ObservedStateError('zone_mismatch');
  if (!isObject(zone.account) || zone.account.id !== target.accountId) {
    throw new ObservedStateError('zone_account_mismatch');
  }
  if (!validHostname(zone.name) || !isString(zone.status)) {
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

async function readTrustedReceipt(
  receipt: BoundaryValue,
  installationId: string,
  expectedTarget: ReceiptTarget,
  diagnostics: ObservedDiagnostic[],
): Promise<InstallationReceipt | null> {
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

function buildEntityReads(
  kind: ResourceKind,
  desiredResources: readonly DesiredResource[],
  receiptResources: readonly ReceiptResource[],
): EntityRead[] {
  const reads: EntityRead[] = [];
  for (const desired of desiredResources.filter((resource) => resource.kind === kind)) {
    reads.push({ key: desired.key, id: desired.key });
  }
  for (const resource of receiptResources.filter((resource) => resource.kind === kind)) {
    reads.push({ key: resource.key, id: resource.provider.id });
  }
  const seen = new Set<string>();
  return reads.filter((read) => {
    const value = `${read.key}\u0000${read.id}`;
    if (seen.has(value)) return false;
    seen.add(value);
    return true;
  });
}

async function readEntities(
  reads: readonly EntityRead[],
  reader: (id: string) => Promise<BoundaryValue>,
): Promise<EntityResult[]> {
  return Promise.all(reads.map(async ({ key, id }) => {
    const live = await providerRead(() => reader(id));
    if (live === null) return { key, id, live: null };
    if (!isObject(live)) throw new ObservedStateError('invalid_provider_response');
    return { key, id: exactReturnedId(live, id), live };
  }));
}

function exactReturnedId(live: BoundaryValue, expectedId: string): string {
  const id = isObject(live) ? safeId(live.id) : null;
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
}: MakeObservedInput): CloudflareObservedResource {
  const expectedMarker = ownershipMarker(
    receipt?.installationId ?? desiredInstallationId(desired) ?? 'invalid',
    key,
  );
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
  const observed: CloudflareObservedResource = {
    kind,
    key,
    provider: { ...locator },
    owner: {},
    desiredHash: liveMatchesDesired ? desired?.desiredHash ?? '' : '',
  };
  if (owned && receipt) {
    return {
      ...observed,
      owner: { manager: MANAGER, installationId: receipt.installationId },
    };
  }
  return observed;
}

function desiredInstallationId(desired: DesiredResource | undefined): string | null {
  const metadata = desired && isObject(desired.desired.metadata)
    ? desired.desired.metadata
    : null;
  return metadata ? safeId(metadata.installationId) : null;
}

function serverMatches(live: BoundaryObject, desired: DesiredResource): boolean {
  const expected = desired.desired;
  const toolPolicy = isObject(expected.toolPolicy) ? expected.toolPolicy : null;
  const allowedTools = toolPolicy ? stringArray(toolPolicy.allowedTools) : null;
  if (!allowedTools) return false;
  return serverCreationIdentityMatches(live, desired)
    && live.name === expected.name
    && live.secure_web_gateway === expected.secureWebGateway
    && live.status === 'ready'
    && expectedToolsDiscovered(live.tools, allowedTools)
    && optionalPromptsAreEmpty(live.updated_prompts)
    && sameEnabledTools(live.updated_tools, allowedTools);
}

function serverCreationIdentityMatches(live: BoundaryObject, desired: DesiredResource): boolean {
  const expected = desired.desired;
  const authentication = isObject(expected.authentication) ? expected.authentication : null;
  const metadata = isObject(expected.metadata) ? expected.metadata : null;
  if (!authentication || !metadata || !isString(metadata.installationId)) return false;
  const authType = authentication.mode === 'none'
    ? 'unauthenticated'
    : authentication.mode === 'oauth'
      ? 'oauth'
      : 'bearer';
  return live.id === desired.key
    && live.hostname === expected.endpoint
    && live.auth_type === authType
    && live.description === ownershipMarker(metadata.installationId, desired.key);
}

function expectedToolsDiscovered(
  tools: BoundaryValue,
  expected: readonly string[],
): boolean {
  if (!Array.isArray(tools)) return false;
  const names: string[] = [];
  for (const tool of tools) {
    if (!isObject(tool) || !isString(tool.name) || names.includes(tool.name)) return false;
    names.push(tool.name);
  }
  return expected.every((name) => names.includes(name));
}

function pendingCreateMatches(
  receipt: InstallationReceipt | null,
  desired: DesiredResource,
): boolean {
  return receipt?.pending?.type === 'apply'
    && receipt.pending.action === 'create'
    && receipt.pending.kind === desired.kind
    && receipt.pending.key === desired.key
    && receipt.pending.expectedDesiredHash === desired.desiredHash;
}

function portalBaseMatches(live: BoundaryObject, desired: DesiredResource): boolean {
  const expected = desired.desired;
  const metadata = isObject(expected.metadata) ? expected.metadata : null;
  const mappings = Array.isArray(expected.sourceMappings) ? expected.sourceMappings : null;
  const liveServers = Array.isArray(live.servers) ? live.servers : null;
  if (!metadata || !isString(metadata.installationId) || !mappings) return false;
  if (live.id !== desired.key
    || live.name !== expected.name
    || live.hostname !== expected.hostname
    || live.code_mode !== expected.codeMode
    || live.secure_web_gateway !== expected.secureWebGateway
    || live.description !== ownershipMarker(metadata.installationId, desired.key)) return false;
  if (!liveServers || liveServers.length !== mappings.length) return false;
  return mappings.every((mapping) => {
    if (!isObject(mapping)) return false;
    const matches = liveServers.filter((server) => isObject(server)
      && (server.server_id ?? server.id) === mapping.sourceResourceKey);
    if (matches.length !== 1) return false;
    const server = matches.at(0);
    if (!server || !isObject(server)) return false;
    const allowedTools = stringArray(mapping.allowedTools);
    if (!allowedTools) return false;
    return server.default_disabled === true
      && server.on_behalf === mapping.onBehalfOfUser
      && optionalPromptsAreEmpty(server.updated_prompts)
      && sameEnabledTools(server.updated_tools, allowedTools);
  });
}

function dnsMatches(live: BoundaryObject, desired: DesiredResource): boolean {
  const expected = desired.desired;
  const metadata = isObject(expected.metadata) ? expected.metadata : null;
  if (!metadata || !isString(metadata.installationId)) return false;
  return live.type === expected.recordType
    && normalizeDnsName(live.name) === normalizeDnsName(expected.hostname)
    && normalizeDnsName(live.content) === normalizeDnsName(expected.content)
    && live.proxied === expected.proxied
    && live.comment === ownershipMarker(metadata.installationId, desired.key);
}

function policyMatches(policy: BoundaryValue, allowedEmails: readonly string[]): boolean {
  if (!isObject(policy)) return false;
  if (policy.decision !== 'allow') return false;
  if (!emptyRules(policy.exclude) || !emptyRules(policy.require)) return false;
  if (!Array.isArray(policy.include) || policy.include.length !== allowedEmails.length) return false;
  const liveEmails = [];
  for (const rule of policy.include) {
    const emailRule = isObject(rule) && isObject(rule.email) ? rule.email : null;
    const email = emailRule?.email;
    if (!isString(email)) return false;
    liveEmails.push(email.trim().toLowerCase());
  }
  return sameTextSet(liveEmails, allowedEmails);
}

function managedOauthMatches(app: BoundaryObject, expected: BoundaryValue): boolean {
  if (!isObject(expected)) return false;
  const oauth = app.oauth_configuration;
  const oauthObject = isObject(oauth) ? oauth : null;
  const registration = oauthObject && isObject(oauthObject.dynamic_client_registration)
    ? oauthObject.dynamic_client_registration
    : null;
  const grant = oauthObject && isObject(oauthObject.grant) ? oauthObject.grant : null;
  const expectedRegistration = isObject(expected.dynamicClientRegistration)
    ? expected.dynamicClientRegistration
    : null;
  const expectedGrant = isObject(expected.grant) ? expected.grant : null;
  return expected.mode === 'managed_oauth'
    && oauthObject?.enabled === true
    && registration?.enabled === expectedRegistration?.enabled
    && registration?.allow_any_on_localhost === expectedRegistration?.allowAnyOnLocalhost
    && registration?.allow_any_on_loopback === expectedRegistration?.allowAnyOnLoopback
    && grant?.access_token_lifetime === expectedGrant?.accessTokenLifetime
    && grant?.session_duration === expectedGrant?.sessionDuration;
}

function isServerApp(app: BoundaryValue, serverId: BoundaryValue): boolean {
  return isObject(app)
    && app.type === 'mcp'
    && Array.isArray(app.destinations)
    && app.destinations.some((destination) =>
      isObject(destination)
      && destination.type === 'via_mcp_server_portal'
      && destination.mcp_server_id === serverId);
}

function sourceAccessApplicationMatches(
  app: BoundaryObject,
  serverId: BoundaryValue,
  marker: string,
): boolean {
  return sourceAccessApplicationBaseMatches(app, serverId, marker);
}

function sourceAccessApplicationBaseMatches(
  app: BoundaryObject,
  serverId: BoundaryValue,
  marker: string,
): boolean {
  if (app.name !== marker || app.type !== 'mcp' || !sourceAppHasNoDomain(app)
    || !Array.isArray(app.destinations) || app.destinations.length !== 1) return false;
  const destination = app.destinations[0];
  return isObject(destination)
    && Object.keys(destination).sort().join(',') === 'mcp_server_id,type'
    && destination.type === 'via_mcp_server_portal'
    && destination.mcp_server_id === serverId;
}

function sourceAccessApplicationReceiptMatches(
  app: BoundaryObject,
  owned: ReceiptResource,
  receiptResources: readonly ReceiptResource[],
  installationId: string,
): boolean {
  if (app.name !== ownershipMarker(installationId, owned.key)
    || app.type !== 'mcp' || !sourceAppHasNoDomain(app)
    || !Array.isArray(app.destinations) || app.destinations.length !== 1) return false;
  const destination = app.destinations[0];
  return isObject(destination)
    && Object.keys(destination).sort().join(',') === 'mcp_server_id,type'
    && destination.type === 'via_mcp_server_portal'
    && receiptResources.some((resource) =>
      resource.kind === 'mcp_server'
      && resource.provider.id === destination.mcp_server_id);
}

function sourceAppHasNoDomain(app: BoundaryObject): boolean {
  return app.domain === undefined || app.domain === null;
}

function portalAccessApplicationBaseMatches(
  app: BoundaryObject,
  expected: JsonObject,
): boolean {
  const destinationSpec = isObject(expected.destination) ? expected.destination : null;
  if (app.name !== expected.name
    || expected.applicationType !== 'mcp_portal'
    || destinationSpec?.type !== 'public'
    || destinationSpec.uri !== expected.hostname
    || app.type !== 'mcp_portal'
    || app.domain !== expected.hostname
    || !Array.isArray(app.destinations) || app.destinations.length !== 1) return false;
  const destination = app.destinations[0];
  return isObject(destination)
    && Object.keys(destination).sort().join(',') === 'type,uri'
    && destination.type === 'public'
    && destination.uri === expected.hostname;
}

function portalAccessApplicationMatches(app: BoundaryObject, expected: JsonObject): boolean {
  return portalAccessApplicationBaseMatches(app, expected)
    && managedOauthMatches(app, expected.authentication);
}

function inlinePoliciesAreEmpty(app: BoundaryObject): boolean {
  return !Object.hasOwn(app, 'policies')
    || (Array.isArray(app.policies) && app.policies.length === 0);
}

function inlinePoliciesMatchListedPolicies(
  app: BoundaryObject,
  policies: BoundaryValue,
): boolean {
  if (!Array.isArray(policies)) return false;
  if (!Object.hasOwn(app, 'policies')
    || (Array.isArray(app.policies) && app.policies.length === 0)) return true;
  if (!Array.isArray(app.policies) || app.policies.length !== policies.length) return false;

  const listedById = new Map<string, BoundaryObject>();
  for (const policy of policies) {
    if (!isObject(policy)) return false;
    const id = safeId(policy.id);
    if (!id || listedById.has(id)) return false;
    listedById.set(id, policy);
  }
  const seen = new Set<string>();
  for (const inlinePolicy of app.policies) {
    const id = safeId(isString(inlinePolicy)
      ? inlinePolicy
      : isObject(inlinePolicy) ? inlinePolicy.id : undefined);
    if (!id || seen.has(id) || !listedById.has(id)) return false;
    if (isObject(inlinePolicy)
      && Object.hasOwn(inlinePolicy, 'name')
      && inlinePolicy.name !== listedById.get(id)?.name) return false;
    seen.add(id);
  }
  return seen.size === listedById.size;
}

function isPortalAppCandidate(app: BoundaryValue, hostname: BoundaryValue): boolean {
  return isObject(app) && app.type === 'mcp_portal' && (
    app.domain === hostname ||
    (Array.isArray(app.destinations) && app.destinations.some((destination) =>
      isObject(destination) && destination.type === 'public' && destination.uri === hostname))
  );
}

async function verifySingleAccessApp(
  cloudflare: CloudflareObservedReader,
  candidates: readonly ObservedApp[],
  predicate: (app: BoundaryObject) => boolean,
  diagnostics: ObservedDiagnostic[],
  kind: ResourceKind,
  key: string,
): Promise<ObservedApp | null> {
  if (candidates.length !== 1) return null;
  const candidate = candidates.at(0);
  if (!candidate) return null;
  const live = await providerRead(() => cloudflare.getAccessApp(candidate.id));
  if (!isObject(live) || safeId(live.id) !== candidate.id || !predicate(live)) {
    diagnostics.push({ code: 'access_app_provenance_mismatch', kind, key });
    return null;
  }
  return { ...live, id: candidate.id };
}

function requireObservedApp(app: BoundaryValue): ObservedApp {
  if (!isObject(app)) throw new ObservedStateError('invalid_provider_response');
  const id = safeId(app.id);
  if (!id) throw new ObservedStateError('invalid_provider_response');
  return { ...app, id };
}

function normalizeAllowedEmails(access: BoundaryValue): string[] {
  const raw = isObject(access) && Array.isArray(access.allowedEmails)
    ? access.allowedEmails
    : [];
  return [...new Set(raw
    .filter(isString)
    .map((email) => email.trim().toLowerCase())
    .filter((email) => email.length > 0 && email.length <= 254 && EMAIL.test(email)))]
    .sort(compareText);
}

function sameEnabledTools(tools: BoundaryValue, expected: readonly string[]): boolean {
  if (!Array.isArray(tools)) return false;
  const enabled: string[] = [];
  for (const tool of tools) {
    if (!isObject(tool) || !isString(tool.name) || !v.is(booleanSchema, tool.enabled)) return false;
    if (tool.enabled) enabled.push(tool.name);
  }
  return sameTextSet(enabled, expected);
}

function sameTextSet(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length
    && new Set(left).size === left.length
    && [...left].sort(compareText).every((value, index) => value === [...right].sort(compareText)[index]);
}

function emptyRules(value: BoundaryValue): boolean {
  return value === undefined || (Array.isArray(value) && value.length === 0);
}

function optionalPromptsAreEmpty(value: BoundaryValue): boolean {
  return value === undefined || (Array.isArray(value) && value.length === 0);
}

function sameLocator(
  left: ObservedProviderLocator | ReceiptProviderLocator | undefined,
  right: ObservedProviderLocator | ReceiptProviderLocator | undefined,
): boolean {
  if (!left || !right || left.id !== right.id) return false;
  return (left.parentId ?? '') === (right.parentId ?? '');
}

function hasLocator(
  resources: readonly CloudflareObservedResource[],
  kind: ResourceKind,
  key: string,
  locator: ObservedProviderLocator | ReceiptProviderLocator | undefined,
): boolean {
  return resources.some((resource) => resource.kind === kind
    && resource.key === key
    && sameLocator(resource.provider, locator));
}

function pushObserved(
  resources: CloudflareObservedResource[],
  resource: CloudflareObservedResource,
): void {
  if (!hasLocator(resources, resource.kind, resource.key, resource.provider)) resources.push(resource);
}

function identity(kind: ResourceKind, key: string): string {
  return `${kind}\u0000${key}`;
}

function safeId(value: BoundaryValue): string | null {
  return isString(value) && SAFE_ID.test(value) ? value : null;
}

function isObject(value: BoundaryValue): value is BoundaryObject {
  return v.is(boundaryObjectSchema, value);
}

function isString(value: BoundaryValue): value is string {
  return v.is(stringSchema, value);
}

function stringArray(value: BoundaryValue): string[] | null {
  if (!Array.isArray(value) || !value.every(isString)) return null;
  return [...value];
}

function validHostname(value: BoundaryValue): value is string {
  if (!isString(value) || value !== value.toLowerCase() || value.length > 253) return false;
  return value.split('.').length > 1
    && value.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}

function normalizeDnsName(value: BoundaryValue): string {
  return isString(value) ? value.toLowerCase().replace(/\.$/, '') : '';
}

async function providerRead(operation: () => Promise<BoundaryValue>): Promise<BoundaryValue> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof ObservedStateError) throw error;
    throw new ObservedStateError('provider_read_failed');
  }
}

function compareObserved(left: CloudflareObservedResource, right: CloudflareObservedResource): number {
  return compareText(left.kind, right.kind)
    || compareText(left.key, right.key)
    || compareText(left.provider?.parentId ?? '', right.provider?.parentId ?? '')
    || compareText(left.provider?.id ?? '', right.provider?.id ?? '');
}

function compareDiagnostics(left: ObservedDiagnostic, right: ObservedDiagnostic): number {
  return compareText(left.code, right.code)
    || compareText(left.kind ?? '', right.kind ?? '')
    || compareText(left.key ?? '', right.key ?? '');
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
