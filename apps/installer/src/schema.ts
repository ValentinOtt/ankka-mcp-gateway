import * as v from 'valibot';

import {
  boundaryObjectSchema,
  boundaryValueSchema,
  type BoundaryObject,
  type BoundaryValue,
} from './boundary';
import { REQUIRED_OAUTH_SCOPES, type RequiredOauthScope } from './constants';
import { sha256Hex } from './crypto';
import { DeployError } from './errors';
import type { ReleaseManifest } from './release-manifest';

export { parseReleaseManifest, type ReleaseManifest } from './release-manifest';

const GATEWAY_NAME_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9 -]{0,78}[A-Za-z0-9])?$/u;
const EMAIL_PATTERN = /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const RELEASE_PATTERN = /^gateway-v\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?$/u;
const COMMIT_PATTERN = /^[a-f0-9]{40}$/u;
const TOOL_NAME_PATTERN = /^[A-Za-z0-9_.:/-]{1,128}$/u;
const MAX_ENABLED_TOOLS_PER_SOURCE = 500;
const MANAGEMENT_OWNERSHIP_MARKER_PATTERN = /^acg-[a-f0-9]{24}$/u;
const NON_PUBLIC_SOURCE_SUFFIXES = Object.freeze([
  '.localhost',
  '.local',
  '.internal',
  '.lan',
  '.home',
  '.home.arpa',
  '.test',
  '.invalid',
  '.example',
  '.onion',
]);
const stringSchema = v.string();
const numberSchema = v.number();
const deploySelectionInputSchema = v.strictObject({
  basics: v.strictObject({
    additionalAdminEmails: v.array(stringSchema),
    adminEmail: stringSchema,
    gatewayName: stringSchema,
    managementHostname: stringSchema,
    portalHostname: stringSchema,
    zoneName: stringSchema,
  }),
  firstSource: v.nullable(v.strictObject({
    enabledTools: v.array(stringSchema),
    name: stringSchema,
    portalUserEmails: v.array(stringSchema),
    url: stringSchema,
  })),
  schemaVersion: v.literal(1),
});

function isRecord(value: BoundaryValue): value is BoundaryObject {
  return v.is(boundaryObjectSchema, value);
}

function scopesAreExact(input: readonly string[]): input is RequiredOauthScope[] {
  return Array.isArray(input) &&
    input.length === REQUIRED_OAUTH_SCOPES.length &&
    input.every((scope, index) => scope === REQUIRED_OAUTH_SCOPES[index]);
}

function normalizeDnsName(value: string, reason: string | null = null): string {
  const name = value.trim().toLowerCase();
  if (name.length < 3 || name.length > 253 || name.endsWith('.') || name.includes('..')) {
    throw new DeployError(400, 'bad_request', reason);
  }
  const labels = name.split('.');
  if (
    labels.length < 2 ||
    labels.some(
      (label) =>
        label.length < 1 ||
        label.length > 63 ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label),
    )
  ) {
    throw new DeployError(400, 'bad_request', reason);
  }
  return name;
}

function normalizeEmail(value: string, reason: string | null = null): string {
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !EMAIL_PATTERN.test(email)) {
    throw new DeployError(400, 'bad_request', reason);
  }
  return email;
}

function isPublicSourceHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  return normalized !== 'localhost' && normalized !== 'home.arpa' &&
    !NON_PUBLIC_SOURCE_SUFFIXES.some((suffix) => normalized.endsWith(suffix));
}

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && (codePoint < 32 || codePoint === 127);
  });
}

export interface DeploySelection {
  schemaVersion: 1;
  basics: {
    gatewayName: string;
    zoneName: string;
    adminEmail: string;
    additionalAdminEmails: readonly string[];
    managementHostname: string;
    portalHostname: string;
  };
  firstSource: {
    name: string;
    url: string;
    enabledTools: readonly string[];
    portalUserEmails: readonly string[];
  } | null;
}

export function parseDeploySelection<Input>(value: Input): DeploySelection {
  const parsed = v.safeParse(deploySelectionInputSchema, value);
  if (!parsed.success) {
    throw new DeployError(400, 'bad_request', 'selection_contract_invalid');
  }
  const input = parsed.output;
  const gatewayName = input.basics.gatewayName.trim().replace(/\s+/gu, ' ');
  if (!GATEWAY_NAME_PATTERN.test(gatewayName)) {
    throw new DeployError(400, 'bad_request', 'gateway_name_invalid');
  }
  const resourceSlug = gatewayName
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, '-')
    .replace(/^-+|-+$/gu, '')
    .slice(0, 40)
    .replace(/-$/u, '');
  if (resourceSlug.length < 2) throw new DeployError(400, 'bad_request', 'gateway_name_invalid');
  const adminEmail = normalizeEmail(input.basics.adminEmail, 'admin_email_invalid');
  const additionalAdminEmails = [...new Set(
    input.basics.additionalAdminEmails
      .map((email) => normalizeEmail(email, 'additional_admin_emails_invalid'))
      .filter((email) => email !== adminEmail),
  )].sort();
  const zoneName = normalizeDnsName(input.basics.zoneName, 'zone_name_invalid');
  const managementHostname = normalizeDnsName(
    input.basics.managementHostname,
    'management_hostname_invalid',
  );
  const portalHostname = normalizeDnsName(input.basics.portalHostname, 'portal_hostname_invalid');
  if (
    managementHostname === portalHostname ||
    !managementHostname.endsWith(`.${zoneName}`) ||
    !portalHostname.endsWith(`.${zoneName}`)
  ) {
    throw new DeployError(400, 'bad_request', 'gateway_hostnames_invalid');
  }
  if (input.firstSource === null) {
    return Object.freeze({
      schemaVersion: 1,
      basics: Object.freeze({
        gatewayName,
        zoneName,
        adminEmail,
        additionalAdminEmails: Object.freeze(additionalAdminEmails),
        managementHostname,
        portalHostname,
      }),
      firstSource: null,
    });
  }
  const sourceName = input.firstSource.name.trim().replace(/\s+/gu, ' ');
  if (sourceName.length < 2 || sourceName.length > 80 || containsControlCharacter(sourceName)) {
    throw new DeployError(400, 'bad_request', 'source_name_invalid');
  }
  if (input.firstSource.url.length > 2048) {
    throw new DeployError(400, 'bad_request', 'source_url_invalid');
  }
  let sourceUrl: URL;
  try {
    sourceUrl = new URL(input.firstSource.url);
  } catch {
    throw new DeployError(400, 'bad_request', 'source_url_invalid');
  }
  if (
    sourceUrl.protocol !== 'https:' || sourceUrl.username || sourceUrl.password || sourceUrl.port ||
    sourceUrl.hash || sourceUrl.search || sourceUrl.pathname === '/' ||
    /^\d{1,3}(?:\.\d{1,3}){3}$/u.test(sourceUrl.hostname) ||
    sourceUrl.hostname.includes(':') || !isPublicSourceHostname(sourceUrl.hostname)
  ) throw new DeployError(400, 'bad_request', 'source_url_invalid');
  normalizeDnsName(sourceUrl.hostname, 'source_url_invalid');
  if (
    input.firstSource.enabledTools.length < 1 ||
    input.firstSource.enabledTools.length > MAX_ENABLED_TOOLS_PER_SOURCE
  ) {
    throw new DeployError(400, 'bad_request', 'enabled_tools_invalid');
  }
  const enabledTools = [...new Set(input.firstSource.enabledTools.map((tool) => {
    const normalized = tool.trim();
    if (!TOOL_NAME_PATTERN.test(normalized)) {
      throw new DeployError(400, 'bad_request', 'enabled_tool_name_invalid');
    }
    return normalized;
  }))].sort();
  // OAuth actor (the person consenting), primary gateway admin, additional
  // admins, and portal users are distinct concepts. V1 requires the actor to
  // match adminEmail at callback; every admin is included in the Access audience.
  const portalUserEmails = [...new Set([
    adminEmail,
    ...additionalAdminEmails,
    ...input.firstSource.portalUserEmails
      .map((email) => normalizeEmail(email, 'portal_user_emails_invalid')),
  ])].sort();
  return Object.freeze({
    schemaVersion: 1,
    basics: Object.freeze({
      gatewayName,
      zoneName,
      adminEmail,
      additionalAdminEmails: Object.freeze(additionalAdminEmails),
      managementHostname,
      portalHostname,
    }),
    firstSource: Object.freeze({
      name: sourceName,
      url: sourceUrl.toString(),
      enabledTools: Object.freeze(enabledTools),
      portalUserEmails: Object.freeze(portalUserEmails),
    }),
  });
}

function selectionResourceSlug(selection: DeploySelection): string {
  return selection.basics.gatewayName
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, '-')
    .replace(/^-+|-+$/gu, '')
    .slice(0, 20)
    .replace(/-$/u, '');
}

export interface StaticDeployPlan {
  schemaVersion: 1;
  planId: string;
  planHash: string;
  expiresAt: number;
  releaseId: string;
  releaseArtifactSha256: string;
  sourceCommit: string;
  bootstrapWorkerSourceSha256: string;
  workerBundleSha256: string;
  dashboardAssetsSha256: string;
  managementOwnershipMarker: string;
  actorRole: 'deployment_authorizer';
  primaryAdminEmail: string;
  managementAdminEmails: readonly string[];
  portalAudienceEmails: readonly string[];
  gatewayConfiguration: {
    gatewayName: string;
    zoneName: string;
    managementHostname: string;
    portalHostname: string;
    capabilityMode: 'read_only';
    codeMode: 'default_on';
    firstSource: {
      name: string;
      url: string;
      enabledTools: readonly string[];
    } | null;
  };
  managementResources: readonly ManagementResource[];
  gatewayResources: readonly GatewayResource[];
  requiredScopes: readonly RequiredOauthScope[];
}

export type ManagementResourceKind =
  | 'management_worker'
  | 'management_durable_object'
  | 'management_assets'
  | 'management_access_application'
  | 'management_access_policy';

export type GatewayResourceKind =
  | 'mcp_server'
  | 'source_access_application'
  | 'source_access_policy'
  | 'portal'
  | 'portal_access_application'
  | 'portal_access_policy'
  | 'dns_record';

export interface ManagementResource {
  kind: ManagementResourceKind;
  key: string;
  name: string;
  hostname: string | null;
}

export interface GatewayResource {
  kind: GatewayResourceKind;
  key: string;
  name: string;
  hostname: string | null;
}

const managementResourceKindSchema = v.picklist([
  'management_worker',
  'management_durable_object',
  'management_assets',
  'management_access_application',
  'management_access_policy',
]);
const gatewayResourceKindSchema = v.picklist([
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
]);
const managementResourceSchema = v.strictObject({
  kind: managementResourceKindSchema,
  key: stringSchema,
  name: stringSchema,
  hostname: v.nullable(stringSchema),
});
const gatewayResourceSchema = v.strictObject({
  kind: gatewayResourceKindSchema,
  key: stringSchema,
  name: stringSchema,
  hostname: v.nullable(stringSchema),
});
const staticDeployPlanSchema = v.strictObject({
  schemaVersion: v.literal(1),
  releaseId: stringSchema,
  releaseArtifactSha256: stringSchema,
  sourceCommit: stringSchema,
  bootstrapWorkerSourceSha256: stringSchema,
  workerBundleSha256: stringSchema,
  dashboardAssetsSha256: stringSchema,
  managementOwnershipMarker: stringSchema,
  actorRole: v.literal('deployment_authorizer'),
  primaryAdminEmail: stringSchema,
  managementAdminEmails: v.array(stringSchema),
  portalAudienceEmails: v.array(stringSchema),
  gatewayConfiguration: v.strictObject({
    gatewayName: stringSchema,
    zoneName: stringSchema,
    managementHostname: stringSchema,
    portalHostname: stringSchema,
    capabilityMode: v.literal('read_only'),
    codeMode: v.literal('default_on'),
    firstSource: v.nullable(v.strictObject({
      name: stringSchema,
      url: stringSchema,
      enabledTools: v.array(stringSchema),
    })),
  }),
  managementResources: v.array(managementResourceSchema),
  gatewayResources: v.array(gatewayResourceSchema),
  requiredScopes: v.array(v.picklist(REQUIRED_OAUTH_SCOPES)),
  expiresAt: numberSchema,
  planId: stringSchema,
  planHash: stringSchema,
});

export async function buildStaticDeployPlan(
  selection: DeploySelection,
  manifest: ReleaseManifest,
  expiresAt: number,
): Promise<StaticDeployPlan> {
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0) throw new DeployError(500, 'release_invalid');
  const bootstrapWorkerSource = manifest.components.workerBootstrap.files.filter(
    (file) => file.path === 'payload/worker-bootstrap/index.js',
  );
  if (bootstrapWorkerSource.length !== 1) throw new DeployError(500, 'release_invalid');
  const bootstrapWorkerSourceSha256 = bootstrapWorkerSource[0]?.sha256;
  if (bootstrapWorkerSourceSha256 === undefined || !SHA256_PATTERN.test(bootstrapWorkerSourceSha256)) {
    throw new DeployError(500, 'release_invalid');
  }
  const slug = selectionResourceSlug(selection);
  const managementOwnershipDigest = await sha256Hex(JSON.stringify({
    schemaVersion: 1,
    releaseId: manifest.release,
    releaseArtifactSha256: manifest.artifact.treeSha256,
    sourceCommit: manifest.sourceCommit,
    selection,
  }));
  const managementOwnershipMarker = `acg-${managementOwnershipDigest.slice(0, 24)}`;
  const workerName = `ankka-gateway-${slug}-${managementOwnershipMarker}`;
  const managementAdminEmails = Object.freeze([
    selection.basics.adminEmail,
    ...selection.basics.additionalAdminEmails,
  ].sort());
  const managementResources: readonly ManagementResource[] = Object.freeze([
    { kind: 'management_worker', key: 'management-worker', name: workerName, hostname: selection.basics.managementHostname },
    { kind: 'management_durable_object', key: 'management-state', name: `${workerName}-state`, hostname: null },
    { kind: 'management_assets', key: 'management-assets', name: `${workerName}-assets`, hostname: selection.basics.managementHostname },
    { kind: 'management_access_application', key: 'management-access-app', name: `${selection.basics.gatewayName} management [${managementOwnershipMarker}]`, hostname: selection.basics.managementHostname },
    { kind: 'management_access_policy', key: 'management-access-policy', name: `${selection.basics.gatewayName} administrators [${managementOwnershipMarker}]`, hostname: selection.basics.managementHostname },
  ]);
  const sourceResources: readonly GatewayResource[] = selection.firstSource === null
    ? Object.freeze([])
    : Object.freeze([
      { kind: 'mcp_server', key: 'first-mcp-server', name: selection.firstSource.name, hostname: new URL(selection.firstSource.url).hostname },
      { kind: 'source_access_application', key: 'first-source-access-app', name: `${selection.firstSource.name} source`, hostname: new URL(selection.firstSource.url).hostname },
      { kind: 'source_access_policy', key: 'first-source-access-policy', name: `${selection.firstSource.name} users`, hostname: new URL(selection.firstSource.url).hostname },
    ]);
  const gatewayResources: readonly GatewayResource[] = Object.freeze([
    ...sourceResources,
    { kind: 'portal', key: 'mcp-portal', name: selection.basics.gatewayName, hostname: selection.basics.portalHostname },
    { kind: 'portal_access_application', key: 'portal-access-app', name: `${selection.basics.gatewayName} portal`, hostname: selection.basics.portalHostname },
    { kind: 'portal_access_policy', key: 'portal-access-policy', name: `${selection.basics.gatewayName} portal users`, hostname: selection.basics.portalHostname },
    { kind: 'dns_record', key: 'portal-dns', name: selection.basics.portalHostname, hostname: selection.basics.portalHostname },
  ]);
  const boundPlan = {
    schemaVersion: 1,
    releaseId: manifest.release,
    releaseArtifactSha256: manifest.artifact.treeSha256,
    sourceCommit: manifest.sourceCommit,
    bootstrapWorkerSourceSha256,
    workerBundleSha256: manifest.components.worker.treeSha256,
    dashboardAssetsSha256: manifest.components.admin.treeSha256,
    managementOwnershipMarker,
    actorRole: 'deployment_authorizer',
    primaryAdminEmail: selection.basics.adminEmail,
    managementAdminEmails,
    portalAudienceEmails: selection.firstSource?.portalUserEmails ?? managementAdminEmails,
    gatewayConfiguration: Object.freeze({
      gatewayName: selection.basics.gatewayName,
      zoneName: selection.basics.zoneName,
      managementHostname: selection.basics.managementHostname,
      portalHostname: selection.basics.portalHostname,
      capabilityMode: 'read_only',
      codeMode: 'default_on',
      firstSource: selection.firstSource === null ? null : Object.freeze({
        name: selection.firstSource.name,
        url: selection.firstSource.url,
        enabledTools: selection.firstSource.enabledTools,
      }),
    }),
    managementResources,
    gatewayResources,
    requiredScopes: REQUIRED_OAUTH_SCOPES,
  } as const;
  // Expiry authorizes one OAuth window; it is not desired state. Keeping it
  // outside this digest lets an exact partial install be re-authorized later
  // without changing ownership, plan identity, or any provider resource.
  const digest = await sha256Hex(JSON.stringify(boundPlan));
  return Object.freeze({
    ...boundPlan,
    expiresAt,
    planId: `plan-${digest.slice(0, 24)}`,
    planHash: `sha256:${digest}`,
  });
}

const MANAGEMENT_KINDS = new Set<ManagementResourceKind>([
  'management_worker',
  'management_durable_object',
  'management_assets',
  'management_access_application',
  'management_access_policy',
]);
const GATEWAY_KINDS = new Set<GatewayResourceKind>([
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
]);

function resourcesMatch(
  value: readonly (GatewayResource | ManagementResource)[],
  count: number,
  kinds: ReadonlySet<string>,
): boolean {
  return value.length === count && value.every((resource) =>
    kinds.has(resource.kind) &&
    /^[a-z][a-z0-9-]{0,63}$/u.test(resource.key) &&
    resource.name.length >= 1 &&
    resource.name.length <= 128) &&
    new Set(value.map((resource) => resource.kind)).size === count;
}

export function parseStaticDeployPlan<Input>(value: Input): StaticDeployPlan {
  const parsed = v.safeParse(staticDeployPlanSchema, value);
  if (!parsed.success) throw new DeployError(500, 'session_invalid');
  const input = parsed.output;
  if (
    !/^plan-[a-f0-9]{24}$/u.test(input.planId) ||
    !/^sha256:[a-f0-9]{64}$/u.test(input.planHash) ||
    !Number.isSafeInteger(input.expiresAt) || input.expiresAt <= 0 ||
    !RELEASE_PATTERN.test(input.releaseId) ||
    !SHA256_PATTERN.test(input.releaseArtifactSha256) ||
    !COMMIT_PATTERN.test(input.sourceCommit) ||
    !SHA256_PATTERN.test(input.bootstrapWorkerSourceSha256) ||
    !SHA256_PATTERN.test(input.workerBundleSha256) ||
    !SHA256_PATTERN.test(input.dashboardAssetsSha256) ||
    !MANAGEMENT_OWNERSHIP_MARKER_PATTERN.test(input.managementOwnershipMarker) ||
    normalizeEmail(input.primaryAdminEmail) !== input.primaryAdminEmail ||
    input.managementAdminEmails.some((email) => normalizeEmail(email) !== email) ||
    !input.managementAdminEmails.includes(input.primaryAdminEmail) ||
    new Set(input.managementAdminEmails).size !== input.managementAdminEmails.length ||
    input.portalAudienceEmails.some((email) => normalizeEmail(email) !== email) ||
    !input.portalAudienceEmails.includes(input.primaryAdminEmail) ||
    new Set(input.portalAudienceEmails).size !== input.portalAudienceEmails.length ||
    (input.gatewayConfiguration.firstSource !== null && (
      input.gatewayConfiguration.firstSource.enabledTools.length < 1
    )) ||
    !resourcesMatch(input.managementResources, 5, MANAGEMENT_KINDS) ||
    !resourcesMatch(
      input.gatewayResources,
      input.gatewayConfiguration.firstSource === null ? 4 : 7,
      GATEWAY_KINDS,
    ) ||
    !scopesAreExact(input.requiredScopes)
  ) throw new DeployError(500, 'session_invalid');
  try {
    const config = input.gatewayConfiguration;
    const canonical = parseDeploySelection({
      schemaVersion: 1,
      basics: {
        gatewayName: config.gatewayName,
        zoneName: config.zoneName,
        adminEmail: input.primaryAdminEmail,
        additionalAdminEmails: input.managementAdminEmails
          .filter((email) => email !== input.primaryAdminEmail),
        managementHostname: config.managementHostname,
        portalHostname: config.portalHostname,
      },
      firstSource: config.firstSource === null ? null : {
        name: config.firstSource.name,
        url: config.firstSource.url,
        enabledTools: config.firstSource.enabledTools,
        portalUserEmails: input.portalAudienceEmails,
      },
    });
    if (
      canonical.basics.gatewayName !== config.gatewayName ||
      canonical.basics.zoneName !== config.zoneName ||
      canonical.basics.managementHostname !== config.managementHostname ||
      canonical.basics.portalHostname !== config.portalHostname ||
      JSON.stringify(canonical.basics.additionalAdminEmails) !==
        JSON.stringify(input.managementAdminEmails.filter((email) => email !== input.primaryAdminEmail)) ||
      (canonical.firstSource === null
        ? config.firstSource !== null ||
          JSON.stringify(input.portalAudienceEmails) !== JSON.stringify(canonical.basics.additionalAdminEmails.length > 0
            ? [canonical.basics.adminEmail, ...canonical.basics.additionalAdminEmails].sort()
            : [canonical.basics.adminEmail])
        : config.firstSource === null ||
          canonical.firstSource.name !== config.firstSource.name ||
          canonical.firstSource.url !== config.firstSource.url ||
          JSON.stringify(canonical.firstSource.enabledTools) !==
            JSON.stringify(config.firstSource.enabledTools) ||
          JSON.stringify(canonical.firstSource.portalUserEmails) !== JSON.stringify(input.portalAudienceEmails))
    ) throw new DeployError(500, 'session_invalid');
    const marker = input.managementOwnershipMarker;
    const workerName = `ankka-gateway-${selectionResourceSlug(canonical)}-${marker}`;
    const expectedManagementResources: readonly ManagementResource[] = [
      { kind: 'management_worker', key: 'management-worker', name: workerName, hostname: canonical.basics.managementHostname },
      { kind: 'management_durable_object', key: 'management-state', name: `${workerName}-state`, hostname: null },
      { kind: 'management_assets', key: 'management-assets', name: `${workerName}-assets`, hostname: canonical.basics.managementHostname },
      { kind: 'management_access_application', key: 'management-access-app', name: `${canonical.basics.gatewayName} management [${marker}]`, hostname: canonical.basics.managementHostname },
      { kind: 'management_access_policy', key: 'management-access-policy', name: `${canonical.basics.gatewayName} administrators [${marker}]`, hostname: canonical.basics.managementHostname },
    ];
    const sourceResources: readonly GatewayResource[] = canonical.firstSource === null ? [] : [
      { kind: 'mcp_server', key: 'first-mcp-server', name: canonical.firstSource.name, hostname: new URL(canonical.firstSource.url).hostname },
      { kind: 'source_access_application', key: 'first-source-access-app', name: `${canonical.firstSource.name} source`, hostname: new URL(canonical.firstSource.url).hostname },
      { kind: 'source_access_policy', key: 'first-source-access-policy', name: `${canonical.firstSource.name} users`, hostname: new URL(canonical.firstSource.url).hostname },
    ];
    const expectedGatewayResources: readonly GatewayResource[] = [
      ...sourceResources,
      { kind: 'portal', key: 'mcp-portal', name: canonical.basics.gatewayName, hostname: canonical.basics.portalHostname },
      { kind: 'portal_access_application', key: 'portal-access-app', name: `${canonical.basics.gatewayName} portal`, hostname: canonical.basics.portalHostname },
      { kind: 'portal_access_policy', key: 'portal-access-policy', name: `${canonical.basics.gatewayName} portal users`, hostname: canonical.basics.portalHostname },
      { kind: 'dns_record', key: 'portal-dns', name: canonical.basics.portalHostname, hostname: canonical.basics.portalHostname },
    ];
    if (
      JSON.stringify(input.managementResources) !== JSON.stringify(expectedManagementResources) ||
      JSON.stringify(input.gatewayResources) !== JSON.stringify(expectedGatewayResources)
    ) throw new DeployError(500, 'session_invalid');
  } catch {
    throw new DeployError(500, 'session_invalid');
  }
  return Object.freeze(input);
}

/** Rebuild the customer-facing selection carried by an exact static plan. */
export function deploySelectionFromStaticPlan(plan: StaticDeployPlan): DeploySelection {
  const parsed = parseStaticDeployPlan(plan);
  const config = parsed.gatewayConfiguration;
  return parseDeploySelection({
    schemaVersion: 1,
    basics: {
      gatewayName: config.gatewayName,
      zoneName: config.zoneName,
      adminEmail: parsed.primaryAdminEmail,
      additionalAdminEmails: parsed.managementAdminEmails
        .filter((email) => email !== parsed.primaryAdminEmail),
      managementHostname: config.managementHostname,
      portalHostname: config.portalHostname,
    },
    firstSource: config.firstSource === null ? null : {
      name: config.firstSource.name,
      url: config.firstSource.url,
      enabledTools: config.firstSource.enabledTools,
      portalUserEmails: parsed.portalAudienceEmails,
    },
  });
}

/**
 * Recompute both static-plan commitments before the plan crosses into the
 * customer Worker. Expiry is deliberately excluded, matching plan renewal.
 */
export async function verifyStaticDeployPlanIntegrity<Input>(
  value: Input,
): Promise<StaticDeployPlan> {
  const plan = parseStaticDeployPlan(value);
  const selection = deploySelectionFromStaticPlan(plan);
  const ownershipDigest = await sha256Hex(JSON.stringify({
    schemaVersion: 1,
    releaseId: plan.releaseId,
    releaseArtifactSha256: plan.releaseArtifactSha256,
    sourceCommit: plan.sourceCommit,
    selection,
  }));
  if (plan.managementOwnershipMarker !== `acg-${ownershipDigest.slice(0, 24)}`) {
    throw new DeployError(500, 'session_invalid');
  }
  const boundPlan = {
    schemaVersion: 1,
    releaseId: plan.releaseId,
    releaseArtifactSha256: plan.releaseArtifactSha256,
    sourceCommit: plan.sourceCommit,
    bootstrapWorkerSourceSha256: plan.bootstrapWorkerSourceSha256,
    workerBundleSha256: plan.workerBundleSha256,
    dashboardAssetsSha256: plan.dashboardAssetsSha256,
    managementOwnershipMarker: plan.managementOwnershipMarker,
    actorRole: plan.actorRole,
    primaryAdminEmail: plan.primaryAdminEmail,
    managementAdminEmails: plan.managementAdminEmails,
    portalAudienceEmails: plan.portalAudienceEmails,
    gatewayConfiguration: plan.gatewayConfiguration,
    managementResources: plan.managementResources,
    gatewayResources: plan.gatewayResources,
    requiredScopes: plan.requiredScopes,
  };
  const digest = await sha256Hex(JSON.stringify(boundPlan));
  if (plan.planId !== `plan-${digest.slice(0, 24)}` || plan.planHash !== `sha256:${digest}`) {
    throw new DeployError(500, 'session_invalid');
  }
  return plan;
}

const FORBIDDEN_STORED_KEYS = new Set([
  'access_token',
  'accesstoken',
  'authorizationcode',
  'client_secret',
  'clientsecret',
  'codeverifier',
  'refresh_token',
  'refreshtoken',
  'verifier',
]);

// Defense in depth for credential-free durable state. Exact persisted schemas
// remain the primary boundary, but prefixed/camel-cased credential names must
// not bypass the legacy exact-name list (for example cloudflareAccessToken or
// bootstrapNonce). Hash-only evidence is deliberately allowed.
const FORBIDDEN_STORED_KEY_FRAGMENTS = Object.freeze([
  'accesstoken',
  'refreshtoken',
  'bearertoken',
  'oauthtoken',
  'authorizationcode',
  'clientsecret',
  'bootstrapnonce',
  'hmacsignature',
  'uploadjwt',
  'completionjwt',
  'assetjwt',
  'pkceverifier',
  'codeverifier',
]);

function forbiddenStoredKey(key: string): boolean {
  const normalized = key.toLowerCase().replaceAll('-', '').replaceAll('_', '');
  return FORBIDDEN_STORED_KEYS.has(key.toLowerCase()) ||
    FORBIDDEN_STORED_KEYS.has(normalized) ||
    FORBIDDEN_STORED_KEY_FRAGMENTS.some((fragment) => normalized.includes(fragment)) ||
    (normalized.endsWith('nonce') && !normalized.endsWith('noncehash')) ||
    (normalized.endsWith('signature') && !normalized.endsWith('signaturehash')) ||
    (normalized.endsWith('secret') && !normalized.endsWith('secrethash')) ||
    (normalized.endsWith('verifier') && !normalized.endsWith('verifierhash'));
}

function findForbiddenStoredKeyPath(value: BoundaryValue, path: string): string | null {
  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) {
      const found = findForbiddenStoredKeyPath(item, `${path}[${index}]`);
      if (found) return found;
    }
    return null;
  }
  if (!isRecord(value)) return null;
  for (const [key, item] of Object.entries(value)) {
    const here = path ? `${path}.${key}` : key;
    if (forbiddenStoredKey(key)) return here;
    const found = findForbiddenStoredKeyPath(item, here);
    if (found) return found;
  }
  return null;
}

/** Returns only the first rejected key path; values are never included. */
export function forbiddenStoredKeyPath<Value>(value: Value, path = ''): string | null {
  const parsed = v.safeParse(boundaryValueSchema, value);
  return parsed.success ? findForbiddenStoredKeyPath(parsed.output, path) : null;
}

export function assertSecretFree<Value>(value: Value): void {
  if (forbiddenStoredKeyPath(value)) throw new DeployError(500, 'session_invalid');
}
