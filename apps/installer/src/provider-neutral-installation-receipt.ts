import * as v from 'valibot';

import { canonicalJson } from './canonical-json';
import { sha256Hex } from './crypto';
import { deepFreezePlainData, isPlainDataTree } from './plain-data';
import type { GatewayResourceKind } from './schema';

const HASH = /^sha256:[0-9a-f]{64}$/u;
const INSTALLATION_ID = /^acg-[0-9a-f]{24}$/u;
const RELEASE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$/u;
const RESOURCE_KEY = /^[a-z][a-z0-9-]{0,31}$/u;
const SAFE_OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const RESOURCE_ORDER = Object.freeze([
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
] as const satisfies readonly GatewayResourceKind[]);
const PORTAL_RESOURCE_ORDER = Object.freeze([
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
] as const satisfies readonly GatewayResourceKind[]);
const POLICY_RESOURCE_KINDS = ['source_access_policy', 'portal_access_policy'] as const;
const NON_POLICY_RESOURCE_KINDS = [
  'mcp_server',
  'source_access_application',
  'portal',
  'portal_access_application',
  'dns_record',
] as const;

type ReceiptResourceKind = GatewayResourceKind;

function validHostname(value: string): boolean {
  if (
    value.length > 253 || value !== value.toLowerCase() || value.includes(':') ||
    /^(?:\d+\.)+\d+$/u.test(value)
  ) return false;
  const labels = value.split('.');
  return labels.length >= 2 && labels.every((label) => HOST_LABEL.test(label));
}

const hashSchema = v.pipe(v.string(), v.regex(HASH));
const installationIdSchema = v.pipe(v.string(), v.regex(INSTALLATION_ID));
const releaseSchema = v.pipe(v.string(), v.regex(RELEASE));
const resourceKeySchema = v.pipe(v.string(), v.regex(RESOURCE_KEY));
const safeOpaqueIdSchema = v.pipe(v.string(), v.regex(SAFE_OPAQUE_ID));
const hostnameSchema = v.pipe(v.string(), v.check(validHostname));
const safeNonnegativeIntegerSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const identityCountSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(1), v.maxValue(10_000));
const policyResourceKindSchema = v.picklist(POLICY_RESOURCE_KINDS);
const nonPolicyResourceKindSchema = v.picklist(NON_POLICY_RESOURCE_KINDS);
export const installationReceiptTargetSchema = v.strictObject({
  accountId: safeOpaqueIdSchema,
  zoneId: safeOpaqueIdSchema,
  zoneName: hostnameSchema,
  hostname: hostnameSchema,
});
export const installationReceiptAccessPolicySchema = v.strictObject({
  identityType: v.literal('email'),
  identityCount: identityCountSchema,
  identitiesHash: hashSchema,
});
const nonPolicyExpectationResourceSchema = v.strictObject({
  kind: nonPolicyResourceKindSchema,
  key: resourceKeySchema,
  desiredHash: hashSchema,
  marker: v.string(),
});
const policyExpectationResourceSchema = v.strictObject({
  kind: policyResourceKindSchema,
  key: resourceKeySchema,
  desiredHash: hashSchema,
  marker: v.string(),
  identityHash: hashSchema,
});
const expectationResourceSchema = v.union([
  nonPolicyExpectationResourceSchema,
  policyExpectationResourceSchema,
]);
const expectationSchema = v.strictObject({
  installationId: installationIdSchema,
  release: releaseSchema,
  desiredHash: hashSchema,
  target: installationReceiptTargetSchema,
  accessPolicy: installationReceiptAccessPolicySchema,
  resources: v.array(expectationResourceSchema),
});
const nonPolicyReceiptResourceSchema = v.strictObject({
  kind: nonPolicyResourceKindSchema,
  key: resourceKeySchema,
  provider: v.strictObject({ id: safeOpaqueIdSchema }),
  desiredHash: hashSchema,
  marker: v.string(),
});
const policyReceiptResourceSchema = v.strictObject({
  kind: policyResourceKindSchema,
  key: resourceKeySchema,
  provider: v.strictObject({ id: safeOpaqueIdSchema, parentId: safeOpaqueIdSchema }),
  desiredHash: hashSchema,
  marker: v.string(),
  identityHash: hashSchema,
});
const receiptResourceSchema = v.union([
  nonPolicyReceiptResourceSchema,
  policyReceiptResourceSchema,
]);
export const readyInstallationReceiptSchema = v.strictObject({
  schemaVersion: v.literal(1),
  manager: v.literal('ankka-mcp-gateway'),
  installationId: installationIdSchema,
  state: v.literal('ready'),
  revision: safeNonnegativeIntegerSchema,
  release: releaseSchema,
  target: installationReceiptTargetSchema,
  accessPolicy: installationReceiptAccessPolicySchema,
  desiredHash: hashSchema,
  resources: v.array(receiptResourceSchema),
  pending: v.null(),
  checksum: hashSchema,
});

type ParsedExpectationResource = v.InferOutput<typeof expectationResourceSchema>;
type ParsedReceiptResource = v.InferOutput<typeof receiptResourceSchema>;
type ParsedTarget = v.InferOutput<typeof installationReceiptTargetSchema>;
type ParsedAccessPolicy = v.InferOutput<typeof installationReceiptAccessPolicySchema>;

interface ReceiptProviderDraft {
  id: string;
  parentId?: string;
}

interface ReceiptResourceDraft {
  kind: ReceiptResourceKind;
  key: string;
  provider: ReceiptProviderDraft;
  desiredHash: string;
  marker: string;
  identityHash?: string;
}

export interface InstallationReceiptTarget {
  readonly accountId: string;
  readonly zoneId: string;
  readonly zoneName: string;
  readonly hostname: string;
}

export interface InstallationReceiptAccessPolicy {
  readonly identityType: 'email';
  readonly identityCount: number;
  readonly identitiesHash: string;
}

export interface InstallationReceiptResourceExpectation {
  readonly kind: ReceiptResourceKind;
  readonly key: string;
  readonly desiredHash: string;
  readonly marker: string;
  readonly identityHash?: string;
}

interface InstallationReceiptResourceExpectationDraft {
  kind: ReceiptResourceKind;
  key: string;
  desiredHash: string;
  marker: string;
  identityHash?: string;
}

export interface ReadyInstallationReceiptExpectation {
  readonly installationId: string;
  readonly release: string;
  readonly desiredHash: string;
  readonly target: InstallationReceiptTarget;
  readonly accessPolicy: InstallationReceiptAccessPolicy;
  readonly resources: readonly InstallationReceiptResourceExpectation[];
}

export interface InstallationReceiptResource {
  readonly kind: ReceiptResourceKind;
  readonly key: string;
  readonly provider: {
    readonly id: string;
    readonly parentId?: string;
  };
  readonly desiredHash: string;
  readonly marker: string;
  readonly identityHash?: string;
}

/** Exact, checksum-protected public ownership evidence retained in the private install journal. */
export interface ReadyInstallationReceipt {
  readonly schemaVersion: 1;
  readonly manager: 'ankka-mcp-gateway';
  readonly installationId: string;
  readonly state: 'ready';
  readonly revision: number;
  readonly release: string;
  readonly target: InstallationReceiptTarget;
  readonly accessPolicy: InstallationReceiptAccessPolicy;
  readonly desiredHash: string;
  readonly resources: readonly InstallationReceiptResource[];
  readonly pending: null;
  readonly checksum: string;
}

/**
 * Derive the exact expectation needed to authenticate a candidate ready receipt.
 * The returned values are not trusted until {@link parseReadyInstallationReceipt}
 * verifies the receipt checksum and semantic resource graph.
 */
export function readyInstallationReceiptExpectationFromCandidate<Input>(
  input: Input,
): ReadyInstallationReceiptExpectation | null {
  if (!isPlainDataTree(input)) return null;
  const result = v.safeParse(readyInstallationReceiptSchema, input);
  if (!result.success) return null;
  const receipt = result.output;
  const resources: InstallationReceiptResourceExpectation[] = receipt.resources.map((resource) => {
    const expectation: InstallationReceiptResourceExpectationDraft = {
      kind: resource.kind,
      key: resource.key,
      desiredHash: resource.desiredHash,
      marker: resource.marker,
    };
    if ('identityHash' in resource) expectation.identityHash = resource.identityHash;
    return expectation;
  });
  return deepFreezePlainData({
    installationId: receipt.installationId,
    release: receipt.release,
    desiredHash: receipt.desiredHash,
    target: receipt.target,
    accessPolicy: receipt.accessPolicy,
    resources,
  });
}

function canonicalResourceOrder(
  resources: readonly { readonly kind: ReceiptResourceKind }[],
): readonly GatewayResourceKind[] | null {
  return [RESOURCE_ORDER, PORTAL_RESOURCE_ORDER].find((candidate) => (
    candidate.length === resources.length &&
    candidate.every((kind, index) => kind === resources[index]?.kind)
  )) ?? null;
}

function sameTarget(value: ParsedTarget, expected: ParsedTarget): boolean {
  return (value.hostname === value.zoneName || value.hostname.endsWith(`.${value.zoneName}`)) &&
    value.accountId === expected.accountId && value.zoneId === expected.zoneId &&
    value.zoneName === expected.zoneName && value.hostname === expected.hostname;
}

function sameAccessPolicy(value: ParsedAccessPolicy, expected: ParsedAccessPolicy): boolean {
  return value.identityCount === expected.identityCount && value.identitiesHash === expected.identitiesHash;
}

function policyResource(kind: ReceiptResourceKind): boolean {
  return kind === 'source_access_policy' || kind === 'portal_access_policy';
}

function parseResource(
  value: ParsedReceiptResource,
  expected: ParsedExpectationResource,
  installationId: string,
): InstallationReceiptResource | null {
  const policy = policyResource(expected.kind);
  if (
    value.kind !== expected.kind || value.key !== expected.key ||
    value.desiredHash !== expected.desiredHash || value.marker !== expected.marker ||
    value.marker !== `acg:v1:${installationId}:${value.key}`
  ) return null;

  const actualParentId = 'parentId' in value.provider ? value.provider.parentId : undefined;
  const actualIdentityHash = 'identityHash' in value ? value.identityHash : undefined;
  const expectedIdentityHash = 'identityHash' in expected ? expected.identityHash : undefined;
  if (policy && (actualParentId === undefined || actualIdentityHash !== expectedIdentityHash)) return null;
  if (!policy && (actualParentId !== undefined || actualIdentityHash !== undefined)) return null;

  const provider: ReceiptProviderDraft = { id: value.provider.id };
  const resource: ReceiptResourceDraft = {
    kind: expected.kind,
    key: expected.key,
    provider,
    desiredHash: expected.desiredHash,
    marker: expected.marker,
  };
  if (policy) {
    if (actualParentId === undefined || expectedIdentityHash === undefined) return null;
    provider.parentId = actualParentId;
    resource.identityHash = expectedIdentityHash;
  }
  Object.freeze(provider);
  return Object.freeze(resource);
}

/** Parse only the exact ready receipt bound to the reviewed customer resource graph. */
export async function parseReadyInstallationReceipt<Input>(
  input: Input,
  expectedInput: ReadyInstallationReceiptExpectation,
): Promise<ReadyInstallationReceipt | null> {
  const expectedResult = v.safeParse(expectationSchema, expectedInput);
  const receiptResult = v.safeParse(readyInstallationReceiptSchema, input);
  if (!expectedResult.success || !receiptResult.success) return null;
  const expected = expectedResult.output;
  const receipt = receiptResult.output;
  const expectedOrder = canonicalResourceOrder(expected.resources);
  if (!expectedOrder || !expected.resources.every((resource) => (
    resource.marker === `acg:v1:${expected.installationId}:${resource.key}`
  ))) return null;
  if (
    receipt.installationId !== expected.installationId || receipt.release !== expected.release ||
    receipt.desiredHash !== expected.desiredHash || !sameTarget(receipt.target, expected.target) ||
    !sameAccessPolicy(receipt.accessPolicy, expected.accessPolicy) ||
    receipt.resources.length !== expected.resources.length ||
    !canonicalResourceOrder(receipt.resources)
  ) return null;

  const resources: InstallationReceiptResource[] = [];
  for (let index = 0; index < expected.resources.length; index += 1) {
    const rawResource = receipt.resources[index];
    const expectedResource = expected.resources[index];
    if (rawResource === undefined || expectedResource === undefined) return null;
    const resource = parseResource(rawResource, expectedResource, expected.installationId);
    if (!resource) return null;
    resources.push(resource);
  }

  const providerLocators = new Set<string>();
  const accessApplicationIds = new Set<string>();
  for (const resource of resources) {
    const locator = `${resource.kind}\u0000${resource.provider.parentId ?? ''}\u0000${resource.provider.id}`;
    if (providerLocators.has(locator)) return null;
    providerLocators.add(locator);
    if (resource.kind === 'source_access_application' || resource.kind === 'portal_access_application') {
      if (accessApplicationIds.has(resource.provider.id)) return null;
      accessApplicationIds.add(resource.provider.id);
    }
  }
  const sourceApplication = resources.find((resource) => resource.kind === 'source_access_application');
  const sourcePolicy = resources.find((resource) => resource.kind === 'source_access_policy');
  const portalApplication = resources.find((resource) => resource.kind === 'portal_access_application');
  const portalPolicy = resources.find((resource) => resource.kind === 'portal_access_policy');
  if ((sourceApplication && sourcePolicy?.provider.parentId !== sourceApplication.provider.id) ||
      (!sourceApplication && sourcePolicy) ||
      portalPolicy?.provider.parentId !== portalApplication?.provider.id) return null;

  const unsigned = {
    schemaVersion: 1,
    manager: 'ankka-mcp-gateway',
    installationId: expected.installationId,
    state: 'ready',
    revision: receipt.revision,
    release: expected.release,
    target: receipt.target,
    accessPolicy: receipt.accessPolicy,
    desiredHash: expected.desiredHash,
    resources: receipt.resources,
    pending: null,
  };
  let checksum: string;
  try {
    checksum = `sha256:${await sha256Hex(canonicalJson(unsigned))}`;
  } catch {
    return null;
  }
  if (checksum !== receipt.checksum) return null;

  return Object.freeze({
    schemaVersion: 1,
    manager: 'ankka-mcp-gateway',
    installationId: expected.installationId,
    state: 'ready',
    revision: receipt.revision,
    release: expected.release,
    target: Object.freeze({ ...expected.target }),
    accessPolicy: Object.freeze({ ...expected.accessPolicy }),
    desiredHash: expected.desiredHash,
    resources: Object.freeze(resources),
    pending: null,
    checksum,
  });
}
