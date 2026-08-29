import * as v from 'valibot';

import {
  boundaryObjectSchema,
  type BoundaryObject,
  type BoundaryValue,
} from './json.ts';

const SAFE_PROVIDER_GROUP_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u;
const stringSchema = v.string();

export const MAX_ACCESS_GROUP_NAME_LENGTH = 128;

export interface AccessGroupObservation {
  readonly id: string;
  readonly name: string;
}

export interface NormalizedAccessGroups {
  readonly groups: readonly AccessGroupObservation[];
  readonly invalidCount: number;
  readonly provided: boolean;
}

/**
 * Reduce fresh, ephemeral provider observations to the exact fields needed for
 * logical-name resolution. Provider IDs must be globally unique. Distinct IDs
 * sharing one logical name are retained so that use of that name fails as an
 * ambiguous binding.
 */
export function normalizeAccessGroups(access: BoundaryValue): NormalizedAccessGroups {
  const rawAccess = isObject(access) ? access : {};
  if (!Array.isArray(rawAccess.groups)) {
    return { groups: [], invalidCount: 0, provided: false };
  }

  const candidates: AccessGroupObservation[] = [];
  let invalidCount = 0;
  for (const rawGroup of rawAccess.groups) {
    if (!isObject(rawGroup)
      || !hasExactKeys(rawGroup, ['id', 'name'])
      || !isSafeProviderGroupId(rawGroup.id)
      || !isAccessGroupName(rawGroup.name)) {
      invalidCount += 1;
      continue;
    }
    candidates.push({ id: rawGroup.id, name: rawGroup.name });
  }

  const idCounts = new Map<string, number>();
  for (const { id } of candidates) idCounts.set(id, (idCounts.get(id) ?? 0) + 1);
  const duplicateIds = new Set(
    [...idCounts.entries()]
      .filter(([, count]) => count > 1)
      .map(([id]) => id),
  );
  invalidCount += duplicateIds.size;
  const groups = candidates.filter(({ id }) => !duplicateIds.has(id));
  groups.sort((left, right) => compareText(left.name, right.name)
    || compareText(left.id, right.id));
  return { groups, invalidCount, provided: true };
}

export function isAccessGroupName(value: BoundaryValue): value is string {
  return v.is(stringSchema, value)
    && codePointLengthWithin(value, MAX_ACCESS_GROUP_NAME_LENGTH)
    && value === value.trim()
    && !hasControlCharacter(value);
}

export function accessGroupsNamed(
  groups: readonly AccessGroupObservation[],
  logicalName: string,
): AccessGroupObservation[] {
  return groups.filter((group) => group.name === logicalName);
}

export async function accessGroupDigest(
  groups: readonly AccessGroupObservation[],
): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto is required to resolve Access groups');
  }
  const normalized = [...groups]
    .map(({ id, name }) => ({ id, name }))
    .sort((left, right) => compareText(left.name, right.name) || compareText(left.id, right.id));
  const bytes = new TextEncoder().encode(JSON.stringify({ groups: normalized }));
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return `sha256:${[...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}`;
}

/** Resolve one provider ID from a digest without putting that ID in desired state. */
export async function resolveAccessGroupByDigest(
  access: BoundaryValue,
  identityCount: number,
  identitiesHash: string,
): Promise<AccessGroupObservation | null> {
  const normalized = normalizeAccessGroups(access);
  if (!normalized.provided || normalized.invalidCount > 0 || identityCount !== 1) return null;

  const candidates = await Promise.all(normalized.groups.map(async (group) => ({
    group,
    digest: await accessGroupDigest([group]),
  })));
  const matches = candidates
    .filter((candidate) => candidate.digest === identitiesHash)
    .map((candidate) => candidate.group);
  return matches.length === 1 ? matches[0] ?? null : null;
}

function isSafeProviderGroupId(value: BoundaryValue): value is string {
  return v.is(stringSchema, value) && SAFE_PROVIDER_GROUP_ID.test(value);
}

function hasExactKeys(value: BoundaryObject, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort(compareText);
  const sortedExpected = [...expected].sort(compareText);
  return actual.length === sortedExpected.length
    && actual.every((key, index) => key === sortedExpected[index]);
}

function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint !== undefined && (codePoint <= 31 || codePoint === 127)) return true;
  }
  return false;
}

function codePointLengthWithin(value: string, maximum: number): boolean {
  let length = 0;
  for (const _character of value) {
    length += 1;
    if (length > maximum) return false;
  }
  return length > 0;
}

function isObject(value: BoundaryValue): value is BoundaryObject {
  return v.is(boundaryObjectSchema, value);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
