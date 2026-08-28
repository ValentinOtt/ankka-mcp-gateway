import * as v from 'valibot';

import {
  boundaryObjectSchema,
  type BoundaryObject,
  type BoundaryValue,
  type JsonValue,
} from './json.ts';

const SCHEMA_VERSION = 1;
const MANAGER = 'ankka-mcp-gateway';
const HASH_PREFIX = 'sha256:';
const RESOURCE_KEY = /^[a-z][a-z0-9-]{0,31}$/;
const SAFE_OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const RELEASE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$/;
const HASH = /^sha256:[0-9a-f]{64}$/;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const stringSchema = v.string();
const numberSchema = v.number();
const booleanSchema = v.boolean();
const resourceKindSchema = v.picklist([
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
]);
const receiptStateSchema = v.picklist(['installing', 'ready', 'uninstalling', 'removed']);
const operationTypeSchema = v.picklist(['apply', 'uninstall']);
const actionSchema = v.picklist(['create', 'update', 'delete']);

export type ReceiptResourceKind = v.InferOutput<typeof resourceKindSchema>;
export type ReceiptState = v.InferOutput<typeof receiptStateSchema>;
export type ReceiptOperationType = v.InferOutput<typeof operationTypeSchema>;
export type ReceiptAction = v.InferOutput<typeof actionSchema>;

export type ReceiptTarget = {
  readonly accountId: string;
  readonly hostname: string;
  readonly zoneId: string;
  readonly zoneName: string;
};

export type ReceiptAccessPolicy = {
  readonly identitiesHash: string;
  readonly identityCount: number;
  readonly identityType: string;
};

export type ReceiptProviderLocator = {
  readonly id: string;
  readonly parentId?: string;
};

export type ReceiptResource = {
  readonly desiredHash: string;
  readonly identityHash?: string;
  readonly key: string;
  readonly kind: ReceiptResourceKind;
  readonly marker?: string;
  readonly provider: ReceiptProviderLocator;
};

export type ReceiptPendingAction = {
  readonly action: ReceiptAction;
  readonly expectedDesiredHash: string;
  readonly key: string;
  readonly kind: ReceiptResourceKind;
  readonly operationId: string;
  readonly planId: string;
  readonly pruneApprovalId?: string;
  readonly requestHash: string;
  readonly type: ReceiptOperationType;
};

type ReceiptUnsigned = {
  readonly accessPolicy: ReceiptAccessPolicy;
  readonly desiredHash: string;
  readonly installationId: string;
  readonly manager: typeof MANAGER;
  readonly pending: ReceiptPendingAction | null;
  readonly release: string;
  readonly resources: readonly ReceiptResource[];
  readonly revision: number;
  readonly schemaVersion: typeof SCHEMA_VERSION;
  readonly state: ReceiptState;
  readonly target: ReceiptTarget;
};

type ReceiptCandidate = ReceiptUnsigned & { readonly checksum?: string };

export type InstallationReceipt = ReceiptUnsigned & { readonly checksum: string };

type CommitResult = {
  identityHash?: string;
  marker?: string;
  provider?: ReceiptProviderLocator;
};

export type ReceiptValidationOptions = {
  readonly expectedTarget?: BoundaryValue;
};

const ACCESS_APPLICATION_KINDS = new Set<ReceiptResourceKind>([
  'source_access_application',
  'portal_access_application',
]);
const RESOURCE_ORDER = new Map<ReceiptResourceKind, number>([
  ['mcp_server', 0],
  ['source_access_application', 1],
  ['source_access_policy', 2],
  ['portal', 3],
  ['portal_access_application', 4],
  ['portal_access_policy', 5],
  ['dns_record', 6],
]);
const MAX_RESOURCES = 200;
const FORBIDDEN_FIELD = /(?:authorization|bearer|cookie|credential|password|private[_-]?key|secret|token|raw|payload|response[_-]?body|headers?|allowed[_-]?emails?|emails?|errors?)/i;
const EMAIL_VALUE = /(^|[^A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}($|[^A-Za-z0-9.-])/;
const BEARER_VALUE = /\bbearer\s+[A-Za-z0-9._~+/=-]+/i;
const PRIVATE_KEY_VALUE = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const JWT_VALUE = /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b/;

export class ReceiptValidationError extends TypeError {
  readonly errors: readonly string[];

  constructor(errors: readonly string[]) {
    super(`Invalid installation receipt:\n- ${errors.join('\n- ')}`);
    this.name = 'ReceiptValidationError';
    this.errors = [...errors];
  }
}

/** Return the compact marker written to Cloudflare resources that support it. */
export function ownershipMarker(installationId: string, key: string): string {
  const errors: string[] = [];
  validateResourceKey(installationId, 'installationId', errors);
  validateResourceKey(key, 'key', errors);
  if (errors.length > 0) throw new ReceiptValidationError(errors);
  return `acg:v1:${installationId}:${key}`;
}

/**
 * Compute the checksum of a receipt's canonical, checksum-free representation.
 * Object key order and resource array order do not affect this value.
 */
export async function receiptChecksum(receipt: BoundaryValue): Promise<string> {
  const normalized = normalizeReceipt(receipt, { checksumRequired: false });
  const { checksum: _checksum, ...unsigned } = normalized;
  return hashCanonical(unsigned);
}

/**
 * Allocate a non-secret, customer-owned installation receipt from a reviewed
 * plan. The caller persists the returned value through an injected store.
 */
export async function createInstallationReceipt(
  input: BoundaryValue = {},
): Promise<InstallationReceipt> {
  const errors: string[] = [];
  if (!isObject(input)) throw new ReceiptValidationError(['input must be an object']);
  rejectUnknownKeys(input, 'input', ['plan', 'target', 'accessPolicy', 'resources'], errors);
  const { plan, target, accessPolicy, resources = [] } = input;
  if (!isObject(plan)) errors.push('plan must be an object');
  if (!isObject(target)) errors.push('target must be an object');

  const inferredAccessPolicy = accessPolicy ?? inferAccessPolicy(plan);
  const candidate = {
    schemaVersion: SCHEMA_VERSION,
    manager: MANAGER,
    installationId: isObject(plan) ? plan.installationId : undefined,
    state: 'ready',
    revision: 0,
    release: isObject(plan) ? plan.release : undefined,
    target,
    accessPolicy: inferredAccessPolicy,
    desiredHash: isObject(plan) ? plan.desiredHash : undefined,
    resources,
    pending: null,
  };

  if (errors.length > 0) throw new ReceiptValidationError(errors);
  return sealReceipt(candidate);
}

/**
 * Advance receipt-level desired metadata after a newly approved plan. Existing
 * provider ownership remains untouched and the target cannot be retargeted.
 */
export async function updateInstallationReceipt(
  receipt: BoundaryValue,
  input: BoundaryValue = {},
): Promise<InstallationReceipt> {
  const current = await validateInstallationReceipt(receipt);
  if (current.state === 'removed') {
    throw new ReceiptValidationError(['removed receipts cannot be updated']);
  }
  if (current.pending !== null) {
    throw new ReceiptValidationError(['a receipt with a pending action cannot be updated']);
  }
  if (!isObject(input)) throw new ReceiptValidationError(['input must be an object']);
  const inputErrors: string[] = [];
  rejectUnknownKeys(input, 'input', ['plan', 'target', 'accessPolicy'], inputErrors);
  if (inputErrors.length > 0) throw new ReceiptValidationError(inputErrors);
  const { plan, target, accessPolicy } = input;
  if (!isObject(plan)) throw new ReceiptValidationError(['plan must be an object']);
  if (plan.installationId !== current.installationId) {
    throw new ReceiptValidationError(['plan installationId does not match the receipt']);
  }
  const expectedTarget = normalizeTarget(target, 'target');
  if (!sameTarget(current.target, expectedTarget)) {
    throw new ReceiptValidationError([
      'target does not match the account, zone, and hostname in the receipt',
    ]);
  }

  const nextAccessPolicy = accessPolicy ?? inferAccessPolicy(plan);
  const errors: string[] = [];
  const normalizedAccessPolicy = normalizeAccessPolicy(nextAccessPolicy, 'accessPolicy', errors);
  if (errors.length > 0) throw new ReceiptValidationError(unique(errors));
  if (!isString(plan.release) || !RELEASE.test(plan.release)) {
    errors.push('plan.release must be a safe identifier of at most 80 characters');
  }
  validateHash(plan.desiredHash, 'plan.desiredHash', errors);
  if (errors.length > 0) throw new ReceiptValidationError(unique(errors));

  if (
    current.release === plan.release &&
    current.desiredHash === plan.desiredHash &&
    sameAccessPolicy(current.accessPolicy, normalizedAccessPolicy)
  ) {
    return current;
  }

  return sealReceipt({
    ...withoutChecksum(current),
    revision: incrementRevision(current.revision),
    release: plan.release,
    accessPolicy: normalizedAccessPolicy,
    desiredHash: plan.desiredHash,
  });
}

/** Validate, checksum-verify, normalize, and copy an installation receipt. */
export async function validateInstallationReceipt(
  receipt: BoundaryValue,
  options: ReceiptValidationOptions = {},
): Promise<InstallationReceipt> {
  const optionErrors: string[] = [];
  if (!isObject(options)) {
    throw new ReceiptValidationError(['options must be an object']);
  }
  rejectUnknownKeys(options, 'options', ['expectedTarget'], optionErrors);
  if (optionErrors.length > 0) throw new ReceiptValidationError(optionErrors);
  const normalized = requireSealedReceipt(
    normalizeReceipt(receipt, { checksumRequired: true }),
  );
  const expectedChecksum = await receiptChecksum(normalized);
  if (normalized.checksum !== expectedChecksum) {
    throw new ReceiptValidationError(['checksum does not match the receipt contents']);
  }

  if (options.expectedTarget !== undefined) {
    const expected = normalizeTarget(options.expectedTarget, 'options.expectedTarget');
    if (!sameTarget(normalized.target, expected)) {
      throw new ReceiptValidationError([
        'target does not match the account, zone, and hostname selected for this operation',
      ]);
    }
  }

  return normalized;
}

/** Record one exact mutation intent before any remote write occurs. */
export async function beginReceiptAction(
  receipt: BoundaryValue,
  intent: BoundaryValue,
): Promise<InstallationReceipt> {
  const current = await validateInstallationReceipt(receipt);
  if (current.state === 'removed') {
    throw new ReceiptValidationError(['removed receipts cannot begin new actions']);
  }
  if (current.pending !== null) {
    throw new ReceiptValidationError(['a receipt action is already pending']);
  }

  const pending = normalizePending(intent, 'intent');
  const existingIndex = findResourceIndex(current.resources, pending.kind, pending.key);
  if (pending.type === 'uninstall' && pending.action !== 'delete') {
    throw new ReceiptValidationError(['uninstall actions must delete an owned resource']);
  }
  if (pending.action === 'create' && existingIndex !== -1) {
    throw new ReceiptValidationError(['create action targets an existing receipt resource']);
  }
  if (pending.action !== 'create' && existingIndex === -1) {
    throw new ReceiptValidationError([
      `${pending.action} action does not target a receipt-owned resource`,
    ]);
  }
  if (
    pending.action === 'delete' &&
    existingIndex !== -1 &&
    current.resources.at(existingIndex)?.desiredHash !== pending.expectedDesiredHash
  ) {
    throw new ReceiptValidationError([
      'delete action expectedDesiredHash does not match the owned receipt resource',
    ]);
  }

  return sealReceipt({
    ...withoutChecksum(current),
    state: pending.type === 'uninstall' ? 'uninstalling' : 'installing',
    revision: incrementRevision(current.revision),
    pending,
  });
}

/**
 * Commit the currently journaled action. Create/update upsert the exact owned
 * resource; delete removes it. No mutation can be committed without an intent.
 */
export async function commitReceiptAction(
  receipt: BoundaryValue,
  result: BoundaryValue = {},
): Promise<InstallationReceipt> {
  const current = await validateInstallationReceipt(receipt);
  if (current.pending === null) {
    throw new ReceiptValidationError(['there is no pending receipt action to commit']);
  }
  const pending = current.pending;
  const normalizedResult = normalizeCommitResult(result, pending, current.installationId);
  const resources = current.resources.map(copyResource);
  const existingIndex = findResourceIndex(resources, pending.kind, pending.key);

  if (pending.action === 'delete') {
    if (existingIndex === -1) {
      throw new ReceiptValidationError(['pending delete no longer has an owned receipt resource']);
    }
    resources.splice(existingIndex, 1);
  } else if (pending.action === 'create') {
    if (existingIndex !== -1) {
      throw new ReceiptValidationError(['pending create already has an owned receipt resource']);
    }
    if (!normalizedResult.provider) {
      throw new ReceiptValidationError(['create commit requires a provider locator']);
    }
    let resource: ReceiptResource = {
      kind: pending.kind,
      key: pending.key,
      provider: normalizedResult.provider,
      desiredHash: pending.expectedDesiredHash,
    };
    if (normalizedResult.marker) resource = { ...resource, marker: normalizedResult.marker };
    if (normalizedResult.identityHash) {
      resource = { ...resource, identityHash: normalizedResult.identityHash };
    }
    resources.push(resource);
  } else {
    if (existingIndex === -1) {
      throw new ReceiptValidationError(['pending update no longer has an owned receipt resource']);
    }
    const existing = resources.at(existingIndex);
    if (!existing) throw new Error('Receipt update resource invariant failed');
    if (
      normalizedResult.provider &&
      providerIdentity(pending.kind, normalizedResult.provider) !==
        providerIdentity(existing.kind, existing.provider)
    ) {
      throw new ReceiptValidationError(['an update cannot change the owned provider locator']);
    }
    let updated: ReceiptResource = {
      ...existing,
      desiredHash: pending.expectedDesiredHash,
    };
    if (normalizedResult.marker !== undefined) {
      updated = { ...updated, marker: normalizedResult.marker };
    }
    if (normalizedResult.identityHash !== undefined) {
      updated = { ...updated, identityHash: normalizedResult.identityHash };
    }
    resources[existingIndex] = updated;
  }

  assertUniqueResources(resources);
  return sealReceipt({
    ...withoutChecksum(current),
    state: pending.type === 'uninstall' ? 'uninstalling' : 'ready',
    revision: incrementRevision(current.revision),
    resources,
    pending: null,
  });
}

/** Clear a journaled action without claiming that its remote mutation succeeded. */
export async function clearReceiptAction(
  receipt: BoundaryValue,
  operationId?: BoundaryValue,
): Promise<InstallationReceipt> {
  const current = await validateInstallationReceipt(receipt);
  if (current.pending === null) return current;
  if (operationId !== undefined) {
    validateSafeOpaqueId(operationId, 'operationId');
    if (operationId !== current.pending.operationId) {
      throw new ReceiptValidationError(['operationId does not match the pending receipt action']);
    }
  }
  return sealReceipt({
    ...withoutChecksum(current),
    state: 'ready',
    revision: incrementRevision(current.revision),
    pending: null,
  });
}

/** Retain a final, checksum-protected tombstone once every owned resource is gone. */
export async function markReceiptRemoved(receipt: BoundaryValue): Promise<InstallationReceipt> {
  const current = await validateInstallationReceipt(receipt);
  if (current.state === 'removed') return current;
  if (current.pending !== null) {
    throw new ReceiptValidationError(['cannot remove a receipt while an action is pending']);
  }
  if (current.resources.length > 0) {
    throw new ReceiptValidationError(['cannot remove a receipt that still owns resources']);
  }
  return sealReceipt({
    ...withoutChecksum(current),
    state: 'removed',
    revision: incrementRevision(current.revision),
  });
}

async function sealReceipt(candidate: BoundaryValue): Promise<InstallationReceipt> {
  const normalized = normalizeReceipt(candidate, { checksumRequired: false });
  const { checksum: _checksum, ...unsigned } = normalized;
  const checksum = await hashCanonical(unsigned);
  return requireSealedReceipt(
    normalizeReceipt({ ...unsigned, checksum }, { checksumRequired: true }),
  );
}

function normalizeReceipt(
  input: BoundaryValue,
  { checksumRequired }: { readonly checksumRequired: boolean },
): ReceiptCandidate {
  const errors: string[] = [];
  if (!isObject(input)) throw new ReceiptValidationError(['receipt must be an object']);
  findForbiddenMaterial(input, '$', errors);
  rejectUnknownKeys(
    input,
    '$',
    [
      'schemaVersion',
      'manager',
      'installationId',
      'state',
      'revision',
      'release',
      'target',
      'accessPolicy',
      'desiredHash',
      'resources',
      'pending',
      'checksum',
    ],
    errors,
  );

  if (input.schemaVersion !== SCHEMA_VERSION) errors.push('schemaVersion must be 1');
  if (input.manager !== MANAGER) errors.push(`manager must be ${MANAGER}`);
  validateResourceKey(input.installationId, 'installationId', errors);
  if (!isReceiptState(input.state)) errors.push('state is not supported');
  if (!v.is(numberSchema, input.revision)
    || !Number.isSafeInteger(input.revision)
    || input.revision < 0) {
    errors.push('revision must be a non-negative safe integer');
  }
  if (!isString(input.release) || !RELEASE.test(input.release)) {
    errors.push('release must be a safe identifier of at most 80 characters');
  }
  validateHash(input.desiredHash, 'desiredHash', errors);

  const target = normalizeTargetForReceipt(input.target, 'target', errors);
  const accessPolicy = normalizeAccessPolicy(input.accessPolicy, 'accessPolicy', errors);
  const resources = normalizeResources(input.resources, errors);
  const pending = input.pending === null
    ? null
    : normalizePendingForReceipt(input.pending, 'pending', errors);

  if (checksumRequired) {
    validateHash(input.checksum, 'checksum', errors);
  } else if (input.checksum !== undefined) {
    validateHash(input.checksum, 'checksum', errors);
  }

  validateStateConsistency(input.state, pending, resources, errors);
  validatePendingOwnership(pending, resources, errors);
  for (const [index, resource] of resources.entries()) {
    if (
      resource.marker !== undefined &&
      isString(input.installationId) &&
      RESOURCE_KEY.test(input.installationId) &&
      RESOURCE_KEY.test(resource.key) &&
      resource.marker !== ownershipMarker(input.installationId, resource.key)
    ) {
      errors.push(`resources[${index}].marker is not the expected ownership marker`);
    }
  }
  if (target.zoneName && target.hostname && !hostnameBelongsToZone(target.hostname, target.zoneName)) {
    errors.push('target.hostname must belong to target.zoneName');
  }
  if (errors.length > 0) throw new ReceiptValidationError(unique(errors));

  const normalized: ReceiptCandidate = {
    schemaVersion: SCHEMA_VERSION,
    manager: MANAGER,
    installationId: isString(input.installationId) ? input.installationId : '',
    state: isReceiptState(input.state) ? input.state : 'ready',
    revision: v.is(numberSchema, input.revision) ? input.revision : 0,
    release: isString(input.release) ? input.release : '',
    target,
    accessPolicy,
    desiredHash: isString(input.desiredHash) ? input.desiredHash : '',
    resources,
    pending,
  };
  if (isString(input.checksum)) return { ...normalized, checksum: input.checksum };
  return normalized;
}

function requireSealedReceipt(candidate: ReceiptCandidate): InstallationReceipt {
  if (!candidate.checksum) {
    throw new ReceiptValidationError(['checksum must be a canonical SHA-256 digest']);
  }
  return { ...candidate, checksum: candidate.checksum };
}

function normalizeTargetForReceipt(
  input: BoundaryValue,
  path: string,
  errors: string[],
): ReceiptTarget {
  if (!isObject(input)) {
    errors.push(`${path} must be an object`);
    return { accountId: '', zoneId: '', zoneName: '', hostname: '' };
  }
  rejectUnknownKeys(input, path, ['accountId', 'zoneId', 'zoneName', 'hostname'], errors);
  validateOpaqueId(input.accountId, `${path}.accountId`, errors);
  validateOpaqueId(input.zoneId, `${path}.zoneId`, errors);
  validateHostname(input.zoneName, `${path}.zoneName`, errors);
  validateHostname(input.hostname, `${path}.hostname`, errors);
  return {
    accountId: isString(input.accountId) ? input.accountId : '',
    zoneId: isString(input.zoneId) ? input.zoneId : '',
    zoneName: isString(input.zoneName) ? input.zoneName : '',
    hostname: isString(input.hostname) ? input.hostname : '',
  };
}

function normalizeTarget(input: BoundaryValue, path: string): ReceiptTarget {
  const errors: string[] = [];
  const target = normalizeTargetForReceipt(input, path, errors);
  if (target.zoneName && target.hostname && !hostnameBelongsToZone(target.hostname, target.zoneName)) {
    errors.push(`${path}.hostname must belong to ${path}.zoneName`);
  }
  if (errors.length > 0) throw new ReceiptValidationError(unique(errors));
  return target;
}

function normalizeAccessPolicy(
  input: BoundaryValue,
  path: string,
  errors: string[],
): ReceiptAccessPolicy {
  if (!isObject(input)) {
    errors.push(`${path} must be an object`);
    return { identityType: '', identityCount: -1, identitiesHash: '' };
  }
  rejectUnknownKeys(input, path, ['identityType', 'identityCount', 'identitiesHash'], errors);
  if (input.identityType !== 'email') errors.push(`${path}.identityType must be email`);
  if (!v.is(numberSchema, input.identityCount)
    || !Number.isSafeInteger(input.identityCount)
    || input.identityCount < 1
    || input.identityCount > 10000) {
    errors.push(`${path}.identityCount must be an integer from 1 to 10000`);
  }
  validateHash(input.identitiesHash, `${path}.identitiesHash`, errors);
  return {
    identityType: isString(input.identityType) ? input.identityType : '',
    identityCount: v.is(numberSchema, input.identityCount) ? input.identityCount : -1,
    identitiesHash: isString(input.identitiesHash) ? input.identitiesHash : '',
  };
}

function normalizeResources(input: BoundaryValue, errors: string[]): ReceiptResource[] {
  if (!Array.isArray(input)) {
    errors.push('resources must be an array');
    return [];
  }
  if (input.length > MAX_RESOURCES) errors.push(`resources cannot exceed ${MAX_RESOURCES} entries`);
  const resources = input.map((resource, index) => normalizeResource(resource, `resources[${index}]`, errors));
  assertUniqueResources(resources, errors);
  return resources.sort(compareResources);
}

function normalizeResource(
  input: BoundaryValue,
  path: string,
  errors: string[],
): ReceiptResource {
  if (!isObject(input)) {
    errors.push(`${path} must be an object`);
    return { kind: 'mcp_server', key: '', provider: { id: '' }, desiredHash: '' };
  }
  rejectUnknownKeys(
    input,
    path,
    [
      'kind',
      'key',
      'provider',
      'desiredHash',
      'marker',
      'identityHash',
    ],
    errors,
  );
  if (!isResourceKind(input.kind)) errors.push(`${path}.kind is not supported`);
  const kind = isResourceKind(input.kind) ? input.kind : 'mcp_server';
  validateResourceKey(input.key, `${path}.key`, errors);
  const provider = normalizeProvider(input.provider, `${path}.provider`, errors, kind);
  validateHash(input.desiredHash, `${path}.desiredHash`, errors);
  if (input.marker !== undefined) {
    if (!isString(input.marker) || input.marker.length > 96) {
      errors.push(`${path}.marker must be a bounded ownership marker`);
    }
  }
  if (input.identityHash !== undefined) {
    validateHash(input.identityHash, `${path}.identityHash`, errors);
  }
  const resource: ReceiptResource = {
    kind,
    key: isString(input.key) ? input.key : '',
    provider,
    desiredHash: isString(input.desiredHash) ? input.desiredHash : '',
  };
  if (isString(input.marker) && isString(input.identityHash)) {
    return { ...resource, marker: input.marker, identityHash: input.identityHash };
  }
  if (isString(input.marker)) return { ...resource, marker: input.marker };
  if (isString(input.identityHash)) return { ...resource, identityHash: input.identityHash };
  return resource;
}

function normalizeProvider(
  input: BoundaryValue,
  path: string,
  errors: string[],
  kind: ReceiptResourceKind,
): ReceiptProviderLocator {
  if (!isObject(input)) {
    errors.push(`${path} must be an object`);
    return { id: '' };
  }
  const policy = kind === 'source_access_policy' || kind === 'portal_access_policy';
  rejectUnknownKeys(input, path, policy ? ['id', 'parentId'] : ['id'], errors);
  validateOpaqueId(input.id, `${path}.id`, errors);
  if (policy) validateOpaqueId(input.parentId, `${path}.parentId`, errors);
  const id = isString(input.id) ? input.id : '';
  if (policy) {
    return { id, parentId: isString(input.parentId) ? input.parentId : '' };
  }
  return { id };
}

function normalizePending(input: BoundaryValue, path: string): ReceiptPendingAction {
  const errors: string[] = [];
  findForbiddenMaterial(input, path, errors);
  const pending = normalizePendingForReceipt(input, path, errors);
  if (errors.length > 0) throw new ReceiptValidationError(unique(errors));
  if (!pending) throw new ReceiptValidationError([`${path} must be an object`]);
  return pending;
}

function normalizePendingForReceipt(
  input: BoundaryValue,
  path: string,
  errors: string[],
): ReceiptPendingAction | null {
  if (!isObject(input)) {
    errors.push(`${path} must be an object or null`);
    return null;
  }
  rejectUnknownKeys(
    input,
    path,
    [
      'operationId',
      'type',
      'planId',
      'action',
      'kind',
      'key',
      'expectedDesiredHash',
      'pruneApprovalId',
      'requestHash',
    ],
    errors,
  );
  validateOpaqueId(input.operationId, `${path}.operationId`, errors);
  if (!isOperationType(input.type)) errors.push(`${path}.type is not supported`);
  validateOpaqueId(input.planId, `${path}.planId`, errors);
  if (!isReceiptAction(input.action)) errors.push(`${path}.action is not supported`);
  if (!isResourceKind(input.kind)) errors.push(`${path}.kind is not supported`);
  validateResourceKey(input.key, `${path}.key`, errors);
  validateHash(input.expectedDesiredHash, `${path}.expectedDesiredHash`, errors);
  if (input.pruneApprovalId !== undefined) {
    validateOpaqueId(input.pruneApprovalId, `${path}.pruneApprovalId`, errors);
    if (input.type !== 'apply' || input.action !== 'delete') {
      errors.push(`${path}.pruneApprovalId is supported only for apply delete actions`);
    }
  }
  validateHash(input.requestHash, `${path}.requestHash`, errors);
  const pending: ReceiptPendingAction = {
    operationId: isString(input.operationId) ? input.operationId : '',
    type: isOperationType(input.type) ? input.type : 'apply',
    planId: isString(input.planId) ? input.planId : '',
    action: isReceiptAction(input.action) ? input.action : 'create',
    kind: isResourceKind(input.kind) ? input.kind : 'mcp_server',
    key: isString(input.key) ? input.key : '',
    expectedDesiredHash: isString(input.expectedDesiredHash) ? input.expectedDesiredHash : '',
    requestHash: isString(input.requestHash) ? input.requestHash : '',
  };
  if (isString(input.pruneApprovalId)) {
    return { ...pending, pruneApprovalId: input.pruneApprovalId };
  }
  return pending;
}

function normalizeCommitResult(
  input: BoundaryValue,
  pending: ReceiptPendingAction,
  installationId: string,
): CommitResult {
  const errors: string[] = [];
  if (!isObject(input)) throw new ReceiptValidationError(['result must be an object']);
  findForbiddenMaterial(input, 'result', errors);
  rejectUnknownKeys(
    input,
    'result',
    ['provider', 'desiredHash', 'marker', 'identityHash'],
    errors,
  );

  let provider: ReceiptProviderLocator | undefined;
  if (input.provider !== undefined) {
    provider = normalizeProvider(input.provider, 'result.provider', errors, pending.kind);
  }
  if (pending.action === 'create' && provider === undefined) {
    errors.push('result.provider is required when committing a create action');
  }
  if (pending.action === 'delete' && Object.keys(input).length > 0) {
    errors.push('a delete commit does not accept remote result fields');
  }
  if (input.desiredHash !== undefined) {
    validateHash(input.desiredHash, 'result.desiredHash', errors);
    if (input.desiredHash !== pending.expectedDesiredHash) {
      errors.push('result.desiredHash does not match the pending action');
    }
  }
  if (input.marker !== undefined) {
    const expectedMarker = ownershipMarker(installationId, pending.key);
    if (input.marker !== expectedMarker) errors.push('result.marker is not the expected ownership marker');
  }
  if (input.identityHash !== undefined) {
    validateHash(input.identityHash, 'result.identityHash', errors);
  }
  if (errors.length > 0) throw new ReceiptValidationError(unique(errors));
  const result: CommitResult = {};
  if (provider) result.provider = provider;
  if (isString(input.marker)) result.marker = input.marker;
  if (isString(input.identityHash)) result.identityHash = input.identityHash;
  return result;
}

function validateStateConsistency(
  state: BoundaryValue,
  pending: ReceiptPendingAction | null,
  resources: readonly ReceiptResource[],
  errors: string[],
): void {
  if (state === 'removed' && (pending !== null || resources.length > 0)) {
    errors.push('removed receipt must be a resource-free tombstone with no pending action');
  }
  if (state === 'ready' && pending !== null) {
    errors.push('ready receipt cannot contain a pending action');
  }
  if (pending?.type === 'apply' && state !== 'installing') {
    errors.push('apply pending action requires installing state');
  }
  if (pending?.type === 'uninstall' && state !== 'uninstalling') {
    errors.push('uninstall pending action requires uninstalling state');
  }
}

function validatePendingOwnership(
  pending: ReceiptPendingAction | null,
  resources: readonly ReceiptResource[],
  errors: string[],
): void {
  if (pending === null) return;
  const index = findResourceIndex(resources, pending.kind, pending.key);
  if (pending.type === 'uninstall' && pending.action !== 'delete') {
    errors.push('uninstall pending action must be delete');
  }
  if (pending.action === 'create' && index !== -1) {
    errors.push('pending create conflicts with an existing receipt resource');
  }
  if (pending.action !== 'create' && index === -1) {
    errors.push('pending update or delete must target a receipt resource');
  }
  if (
    pending.action === 'delete' &&
    index !== -1 &&
    pending.expectedDesiredHash !== resources.at(index)?.desiredHash
  ) {
    errors.push('pending delete hash must match the receipt resource');
  }
}

function assertUniqueResources(
  resources: readonly ReceiptResource[],
  errors?: string[],
): void {
  const localErrors = errors ?? [];
  const identities = new Set<string>();
  const providerLocators = new Set<string>();
  const accessApplicationIds = new Set<string>();
  for (const resource of resources) {
    const identity = `${resource.kind}\u0000${resource.key}`;
    if (identities.has(identity)) {
      localErrors.push(`resources duplicate ${resource.kind}/${resource.key}`);
    }
    identities.add(identity);

    const locator = providerIdentity(resource.kind, resource.provider);
    if (providerLocators.has(locator)) {
      localErrors.push(`resources duplicate a ${resource.kind} provider locator`);
    }
    providerLocators.add(locator);

    if (ACCESS_APPLICATION_KINDS.has(resource.kind)) {
      if (accessApplicationIds.has(resource.provider.id)) {
        localErrors.push('resources duplicate an Access application provider ID');
      }
      accessApplicationIds.add(resource.provider.id);
    }
  }
  for (const resource of resources) {
    if (resource.kind !== 'source_access_policy' && resource.kind !== 'portal_access_policy') {
      continue;
    }
    const parentKind = resource.kind === 'source_access_policy'
      ? 'source_access_application'
      : 'portal_access_application';
    const parents = resources.filter((candidate) => candidate.kind === parentKind);
    if (parents.length === 0) continue;
    const boundParentIds = parents.map((parent) => parent.provider.id);
    if (
      boundParentIds.length > 0 &&
      !boundParentIds.includes(resource.provider.parentId ?? '')
    ) {
      localErrors.push(`${resource.kind}/${resource.key} parentId does not match its parent binding`);
    }
  }
  if (errors === undefined && localErrors.length > 0) {
    throw new ReceiptValidationError(unique(localErrors));
  }
}

function inferAccessPolicy(plan: BoundaryValue): BoundaryValue {
  if (!isObject(plan)) return undefined;
  if (isObject(plan.accessPolicy)) {
    return {
      identityType: plan.accessPolicy.identityType,
      identityCount: plan.accessPolicy.identityCount,
      identitiesHash: plan.accessPolicy.identitiesHash,
    };
  }
  if (!Array.isArray(plan.changes)) return undefined;
  for (const change of plan.changes) {
    const allow = isObject(change) && isObject(change.desired) ? change.desired.allow : undefined;
    if (
      isObject(allow) &&
      allow.identityType === 'email' &&
      v.is(numberSchema, allow.identityCount) &&
      Number.isSafeInteger(allow.identityCount) &&
      isString(allow.identitiesHash)
    ) {
      return {
        identityType: allow.identityType,
        identityCount: allow.identityCount,
        identitiesHash: allow.identitiesHash,
      };
    }
  }
  return undefined;
}

function findForbiddenMaterial(value: BoundaryValue, path: string, errors: string[]): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => findForbiddenMaterial(item, `${path}[${index}]`, errors));
    return;
  }
  if (isObject(value)) {
    for (const [key, child] of Object.entries(value)) {
      const childPath = `${path}.${key}`;
      if (FORBIDDEN_FIELD.test(key)) {
        errors.push(`${childPath} is a forbidden sensitive field`);
      }
      findForbiddenMaterial(child, childPath, errors);
    }
    return;
  }
  if (!isString(value)) return;
  if (
    EMAIL_VALUE.test(value) ||
    BEARER_VALUE.test(value) ||
    PRIVATE_KEY_VALUE.test(value) ||
    JWT_VALUE.test(value)
  ) {
    errors.push(`${path} contains forbidden sensitive material`);
  }
}

function rejectUnknownKeys(
  value: BoundaryValue,
  path: string,
  allowedKeys: readonly string[],
  errors: string[],
): void {
  if (!isObject(value)) return;
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) errors.push(`${path}.${key} is not supported`);
  }
}

function validateResourceKey(value: BoundaryValue, path: string, errors: string[]): void {
  if (!isString(value) || !RESOURCE_KEY.test(value)) {
    errors.push(`${path} must use at most 32 lowercase letters, numbers, and hyphens`);
  }
}

function validateOpaqueId(value: BoundaryValue, path: string, errors: string[]): void {
  if (!isString(value) || !SAFE_OPAQUE_ID.test(value)) {
    errors.push(`${path} must be a bounded opaque identifier`);
  }
}

function validateSafeOpaqueId(value: BoundaryValue, path: string): void {
  const errors: string[] = [];
  validateOpaqueId(value, path, errors);
  if (errors.length > 0) throw new ReceiptValidationError(errors);
}

function validateHash(value: BoundaryValue, path: string, errors: string[]): void {
  if (!isString(value) || !HASH.test(value)) {
    errors.push(`${path} must be a canonical SHA-256 digest`);
  }
}

function validateHostname(value: BoundaryValue, path: string, errors: string[]): void {
  if (
    !isString(value) ||
    value.length > 253 ||
    value !== value.toLowerCase() ||
    value.includes(':') ||
    /^(?:\d+\.)+\d+$/.test(value)
  ) {
    errors.push(`${path} must be a lowercase fully qualified hostname`);
    return;
  }
  const labels = value.split('.');
  if (labels.length < 2 || !labels.every((label) => HOST_LABEL.test(label))) {
    errors.push(`${path} must be a lowercase fully qualified hostname`);
  }
}

function hostnameBelongsToZone(hostname: string, zoneName: string): boolean {
  return hostname === zoneName || hostname.endsWith(`.${zoneName}`);
}

function providerIdentity(
  kind: ReceiptResourceKind,
  provider: ReceiptProviderLocator | undefined,
): string {
  return `${kind}\u0000${provider?.parentId ?? ''}\u0000${provider?.id ?? ''}`;
}

function compareResources(left: ReceiptResource, right: ReceiptResource): number {
  return (
    (RESOURCE_ORDER.get(left.kind) ?? -1) - (RESOURCE_ORDER.get(right.kind) ?? -1) ||
    compareText(left.key, right.key) ||
    compareText(left.provider.parentId ?? '', right.provider.parentId ?? '') ||
    compareText(left.provider.id, right.provider.id)
  );
}

function findResourceIndex(
  resources: readonly ReceiptResource[],
  kind: ReceiptResourceKind,
  key: string,
): number {
  return resources.findIndex((resource) => resource.kind === kind && resource.key === key);
}

function sameTarget(left: ReceiptTarget, right: ReceiptTarget): boolean {
  return (
    left.accountId === right.accountId &&
    left.zoneId === right.zoneId &&
    left.zoneName === right.zoneName &&
    left.hostname === right.hostname
  );
}

function sameAccessPolicy(left: ReceiptAccessPolicy, right: ReceiptAccessPolicy): boolean {
  return (
    left.identityType === right.identityType &&
    left.identityCount === right.identityCount &&
    left.identitiesHash === right.identitiesHash
  );
}

function copyResource(resource: ReceiptResource): ReceiptResource {
  return {
    ...resource,
    provider: { ...resource.provider },
  };
}

function withoutChecksum(receipt: InstallationReceipt): ReceiptUnsigned {
  const { checksum: _checksum, ...unsigned } = receipt;
  return {
    ...unsigned,
    target: { ...unsigned.target },
    accessPolicy: { ...unsigned.accessPolicy },
    resources: unsigned.resources.map(copyResource),
    pending: unsigned.pending ? { ...unsigned.pending } : null,
  };
}

function incrementRevision(revision: number): number {
  if (!Number.isSafeInteger(revision) || revision >= Number.MAX_SAFE_INTEGER) {
    throw new ReceiptValidationError(['revision cannot be incremented safely']);
  }
  return revision + 1;
}

async function hashCanonical(value: JsonValue): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto is required to protect an installation receipt');
  }
  const bytes = new TextEncoder().encode(canonicalJson(value));
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return `${HASH_PREFIX}${[...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}`;
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
  throw new TypeError('Cannot hash an unsupported receipt value');
}

function serializeJsonPrimitive(value: boolean | null | number | string): string {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) throw new TypeError('Cannot serialize receipt primitive');
  return serialized;
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}

function isObject(value: BoundaryValue): value is BoundaryObject {
  return v.is(boundaryObjectSchema, value);
}

function isString(value: BoundaryValue): value is string {
  return v.is(stringSchema, value);
}

function isResourceKind(value: BoundaryValue): value is ReceiptResourceKind {
  return v.is(resourceKindSchema, value);
}

function isReceiptState(value: BoundaryValue): value is ReceiptState {
  return v.is(receiptStateSchema, value);
}

function isOperationType(value: BoundaryValue): value is ReceiptOperationType {
  return v.is(operationTypeSchema, value);
}

function isReceiptAction(value: BoundaryValue): value is ReceiptAction {
  return v.is(actionSchema, value);
}
