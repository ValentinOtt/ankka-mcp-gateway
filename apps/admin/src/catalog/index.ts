import * as v from 'valibot'

const MAX_CATALOG_SOURCES = 100
const MAX_RECOMMENDED_TOOLS = 500
export const SUPPORTED_SERVER_SCHEMA_REVISION = '2025-12-11'
const CATALOG_REVISION = /^(\d{4})-(\d{2})-(\d{2})\.([1-9]\d{0,3})$/u
const STABLE_ID = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u
const TOOL_NAME = /^[A-Za-z0-9_.:/-]{1,128}$/u
const SHA256 = /^sha256:[0-9a-f]{64}$/u
const REGISTRY_SERVER_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,127})\/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,127})$/u
const FORBIDDEN_SECRET_KEY = /(?:authorization|client.?secret|credential|password|private.?key|secret|token)/iu
const BLOCKED_HOST_SUFFIXES = ['.internal', '.invalid', '.local', '.localhost', '.onion', '.test']

const stableIdSchema = v.pipe(
  v.string(),
  v.minLength(2),
  v.maxLength(64),
  v.regex(STABLE_ID),
)
const trimmedTextSchema = v.pipe(
  v.string(),
  v.minLength(1),
  v.maxLength(240),
  v.check((value) => value.trim() === value && !hasControlCharacter(value)),
)
const publicHttpsUrlSchema = v.pipe(
  v.string(),
  v.maxLength(2_048),
  v.check((value) => isPublicHttpsUrl(value, false)),
)
const remoteMcpUrlSchema = v.pipe(
  v.string(),
  v.maxLength(2_048),
  v.check((value) => isPublicHttpsUrl(value, true)),
)
const dateSchema = v.pipe(v.string(), v.check(isCalendarDate))
const digestSchema = v.pipe(v.string(), v.regex(SHA256))
const toolNameSchema = v.pipe(v.string(), v.regex(TOOL_NAME))
const exactVersionSchema = v.pipe(
  v.string(),
  v.minLength(1),
  v.maxLength(128),
  v.check((value) => value.trim() === value && !hasControlCharacter(value) &&
    !['*', '.', '..', 'latest'].includes(value.toLowerCase())),
)

const registryReferenceSchema = v.strictObject({
  serverName: v.pipe(v.string(), v.regex(REGISTRY_SERVER_NAME)),
  serverVersion: exactVersionSchema,
  serverSchemaRevision: v.literal(SUPPORTED_SERVER_SCHEMA_REVISION),
  recordSha256: digestSchema,
  status: v.literal('active'),
  observedAt: dateSchema,
})

const catalogImplementationSchema = v.strictObject({
  implementationId: stableIdSchema,
  implementationRevision: v.pipe(
    v.number(),
    v.integer(),
    v.minValue(1),
    v.maxValue(Number.MAX_SAFE_INTEGER),
  ),
  catalogProvenance: v.literal('official_registry'),
  kind: v.literal('native_mcp'),
  behaviorSha256: digestSchema,
  registry: registryReferenceSchema,
  deployment: v.strictObject({
    kind: v.literal('remote_mcp'),
    transport: v.literal('streamable_http'),
    url: remoteMcpUrlSchema,
  }),
  connection: v.strictObject({
    authMode: v.picklist(['none', 'oauth']),
    onBehalfOfUser: v.literal(false),
  }),
  recommendedTools: v.pipe(
    v.array(toolNameSchema),
    v.minLength(1),
    v.maxLength(MAX_RECOMMENDED_TOOLS),
  ),
})

const sourceCatalogSourceSchema = v.strictObject({
  sourceId: stableIdSchema,
  displayName: v.pipe(trimmedTextSchema, v.maxLength(80)),
  description: trimmedTextSchema,
  documentationUrl: publicHttpsUrlSchema,
  implementation: catalogImplementationSchema,
  publisher: v.strictObject({
    relationship: v.picklist(['provider', 'community']),
    evidence: v.pipe(v.array(publicHttpsUrlSchema), v.minLength(1), v.maxLength(10)),
  }),
  review: v.strictObject({
    status: v.literal('ankka_reviewed'),
    reviewedAt: dateSchema,
  }),
})

export const sourceCatalogSchema = v.strictObject({
  schemaVersion: v.literal(1),
  catalogRevision: v.pipe(v.string(), v.regex(CATALOG_REVISION), v.check(isCatalogRevision)),
  sources: v.pipe(v.array(sourceCatalogSourceSchema), v.maxLength(MAX_CATALOG_SOURCES)),
})

export type CatalogImplementation = v.InferOutput<typeof catalogImplementationSchema>
export type SourceCatalogSource = v.InferOutput<typeof sourceCatalogSourceSchema>
export type SourceCatalog = v.InferOutput<typeof sourceCatalogSchema>
export interface SourceCatalogInputObject {
  readonly [key: string]: SourceCatalogInput
}
export interface SourceCatalogInputArray extends ReadonlyArray<SourceCatalogInput> {}
export type SourceCatalogInput =
  SourceCatalogInputArray | SourceCatalogInputObject | boolean | null | number | string | undefined

export type SourceCatalogValidationCode =
  | 'catalog_behavior_digest_mismatch'
  | 'catalog_duplicate_implementation_id'
  | 'catalog_duplicate_source_id'
  | 'catalog_evidence_after_revision'
  | 'catalog_history_empty'
  | 'catalog_implementation_identity_changed'
  | 'catalog_implementation_revision_redundant'
  | 'catalog_implementation_revision_regressed'
  | 'catalog_implementation_revision_reused'
  | 'catalog_invalid'
  | 'catalog_registry_observation_not_refreshed'
  | 'catalog_registry_observation_regressed'
  | 'catalog_review_not_refreshed'
  | 'catalog_review_precedes_observation'
  | 'catalog_review_regressed'
  | 'catalog_revision_not_advanced'
  | 'catalog_secret_field'
  | 'catalog_unsorted'

export class SourceCatalogValidationError extends Error {
  readonly code: SourceCatalogValidationCode

  constructor(code: SourceCatalogValidationCode) {
    super(code)
    this.name = 'SourceCatalogValidationError'
    this.code = code
  }
}

export { SOURCE_CATALOG, SOURCE_CATALOG_HISTORY } from './manifest'

/** Parse the strict phase-one manifest without trusting stored behavior digests. */
export function parseSourceCatalog(input: SourceCatalogInput): SourceCatalog {
  if (hasForbiddenSecretKey(input)) {
    throw new SourceCatalogValidationError('catalog_secret_field')
  }

  const parsed = v.safeParse(sourceCatalogSchema, input)
  if (!parsed.success) throw new SourceCatalogValidationError('catalog_invalid')
  const revisionDate = catalogRevisionDate(parsed.output.catalogRevision)

  assertSortedUnique(
    parsed.output.sources.map((source) => source.sourceId),
    'catalog_duplicate_source_id',
  )
  assertSortedUnique(
    parsed.output.sources.map((source) => source.implementation.implementationId),
    'catalog_duplicate_implementation_id',
  )
  for (const source of parsed.output.sources) {
    assertSortedUnique(source.implementation.recommendedTools, 'catalog_invalid')
    assertSortedUnique(source.publisher.evidence, 'catalog_invalid')
    if (source.review.reviewedAt < source.implementation.registry.observedAt) {
      throw new SourceCatalogValidationError('catalog_review_precedes_observation')
    }
    if (source.review.reviewedAt > revisionDate ||
        source.implementation.registry.observedAt > revisionDate) {
      throw new SourceCatalogValidationError('catalog_evidence_after_revision')
    }
  }

  return parsed.output
}

/** Parse the manifest and recompute every immutable behavior digest. */
export async function parseVerifiedSourceCatalog(input: SourceCatalogInput): Promise<SourceCatalog> {
  const catalog = parseSourceCatalog(input)
  for (const source of catalog.sources) {
    const expected = await computeBehaviorSha256(source.implementation)
    if (expected !== source.implementation.behaviorSha256) {
      throw new SourceCatalogValidationError('catalog_behavior_digest_mismatch')
    }
  }
  return catalog
}

/**
 * Return the normalized fields whose change requires a new implementation
 * revision. Registry status/observation and review/presentation fields are
 * intentionally excluded.
 */
export function behaviorFields(implementation: CatalogImplementation) {
  return {
    catalogProvenance: implementation.catalogProvenance,
    kind: implementation.kind,
    registry: {
      serverName: implementation.registry.serverName,
      serverVersion: implementation.registry.serverVersion,
      serverSchemaRevision: implementation.registry.serverSchemaRevision,
      recordSha256: implementation.registry.recordSha256,
    },
    deployment: {
      kind: implementation.deployment.kind,
      transport: implementation.deployment.transport,
      url: implementation.deployment.url,
    },
    connection: {
      authMode: implementation.connection.authMode,
      onBehalfOfUser: implementation.connection.onBehalfOfUser,
    },
    recommendedTools: [...implementation.recommendedTools],
  }
}

export async function computeBehaviorSha256(
  implementation: CatalogImplementation,
): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(behaviorFields(implementation)))
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes)
  const hex = [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
  return `sha256:${hex}`
}

/**
 * Validate an authored catalog transition. Existing revision identities are
 * immutable; changed behavior must use a greater revision, while a greater
 * revision must describe changed behavior.
 */
export async function assertCatalogEvolution(
  previous: SourceCatalogInput,
  next: SourceCatalogInput,
): Promise<void> {
  const [before, after] = await Promise.all([
    parseVerifiedSourceCatalog(previous),
    parseVerifiedSourceCatalog(next),
  ])
  if (compareCatalogRevisions(after.catalogRevision, before.catalogRevision) <= 0) {
    throw new SourceCatalogValidationError('catalog_revision_not_advanced')
  }

  const previousSources = new Map(before.sources.map((source) => [source.sourceId, source]))
  const previousImplementationOwners = new Map(
    before.sources.map((source) => [source.implementation.implementationId, source.sourceId]),
  )
  for (const source of after.sources) {
    const previousOwner = previousImplementationOwners.get(source.implementation.implementationId)
    if (previousOwner !== undefined && previousOwner !== source.sourceId) {
      throw new SourceCatalogValidationError('catalog_implementation_identity_changed')
    }

    const oldSource = previousSources.get(source.sourceId)
    if (!oldSource) {
      const nextCatalogDate = catalogRevisionDate(after.catalogRevision)
      if (source.implementation.registry.observedAt !== nextCatalogDate) {
        throw new SourceCatalogValidationError('catalog_registry_observation_not_refreshed')
      }
      if (source.review.reviewedAt !== nextCatalogDate) {
        throw new SourceCatalogValidationError('catalog_review_not_refreshed')
      }
      continue
    }

    assertSourceEvolution(oldSource, source, catalogRevisionDate(after.catalogRevision), false)
  }
}

/** Verify every public baseline transition and the current production manifest. */
export async function assertCatalogHistory(
  history: readonly SourceCatalogInput[],
  current: SourceCatalogInput,
): Promise<void> {
  const first = history[0]
  if (first === undefined) throw new SourceCatalogValidationError('catalog_history_empty')
  const implementationOwners = new Map<string, string>()
  const previousImplementations = new Map<string, SourceCatalogSource>()
  let priorManifestIds = new Set<string>()
  for (const input of [...history, current]) {
    const catalog = await parseVerifiedSourceCatalog(input)
    const currentManifestIds = new Set<string>()
    for (const source of catalog.sources) {
      const implementationId = source.implementation.implementationId
      currentManifestIds.add(implementationId)
      const previousOwner = implementationOwners.get(implementationId)
      if (previousOwner !== undefined && previousOwner !== source.sourceId) {
        throw new SourceCatalogValidationError('catalog_implementation_identity_changed')
      }
      const historicalSource = previousImplementations.get(implementationId)
      if (historicalSource !== undefined && !priorManifestIds.has(implementationId)) {
        assertSourceEvolution(
          historicalSource,
          source,
          catalogRevisionDate(catalog.catalogRevision),
          true,
        )
      }
      implementationOwners.set(implementationId, source.sourceId)
      previousImplementations.set(implementationId, source)
    }
    priorManifestIds = currentManifestIds
  }
  for (let index = 1; index < history.length; index += 1) {
    await assertCatalogEvolution(history[index - 1], history[index])
  }
  await assertCatalogEvolution(history.at(-1), current)
}

function assertSourceEvolution(
  oldSource: SourceCatalogSource,
  source: SourceCatalogSource,
  nextCatalogDate: string,
  forceFreshReview: boolean,
): void {
  const oldImplementation = oldSource.implementation
  const newImplementation = source.implementation
  const behaviorChanged = JSON.stringify(behaviorFields(newImplementation)) !==
    JSON.stringify(behaviorFields(oldImplementation))
  const implementationChanged = newImplementation.implementationId !==
    oldImplementation.implementationId
  if (!implementationChanged) {
    if (newImplementation.implementationRevision < oldImplementation.implementationRevision) {
      throw new SourceCatalogValidationError('catalog_implementation_revision_regressed')
    }
    if (newImplementation.implementationRevision === oldImplementation.implementationRevision) {
      if (behaviorChanged) {
        throw new SourceCatalogValidationError('catalog_implementation_revision_reused')
      }
    } else if (!behaviorChanged) {
      throw new SourceCatalogValidationError('catalog_implementation_revision_redundant')
    }
  }

  const observationComparison = compareDates(
    newImplementation.registry.observedAt,
    oldImplementation.registry.observedAt,
  )
  if (observationComparison < 0) {
    throw new SourceCatalogValidationError('catalog_registry_observation_regressed')
  }
  const registryChanged = JSON.stringify(registryReviewFields(newImplementation)) !==
    JSON.stringify(registryReviewFields(oldImplementation))
  if ((registryChanged || observationComparison !== 0) &&
      newImplementation.registry.observedAt !== nextCatalogDate) {
    throw new SourceCatalogValidationError('catalog_registry_observation_not_refreshed')
  }

  const reviewComparison = compareDates(source.review.reviewedAt, oldSource.review.reviewedAt)
  if (reviewComparison < 0) {
    throw new SourceCatalogValidationError('catalog_review_regressed')
  }
  const publisherChanged = JSON.stringify(source.publisher) !== JSON.stringify(oldSource.publisher)
  const presentationChanged = JSON.stringify(sourcePresentationFields(source)) !==
    JSON.stringify(sourcePresentationFields(oldSource))
  if (
    (forceFreshReview || implementationChanged || behaviorChanged || registryChanged ||
      observationComparison !== 0 || publisherChanged || presentationChanged) &&
    source.review.reviewedAt !== nextCatalogDate
  ) {
    throw new SourceCatalogValidationError('catalog_review_not_refreshed')
  }
}

function sourcePresentationFields(source: SourceCatalogSource) {
  return {
    displayName: source.displayName,
    description: source.description,
    documentationUrl: source.documentationUrl,
  }
}

function registryReviewFields(implementation: CatalogImplementation) {
  return {
    serverName: implementation.registry.serverName,
    serverVersion: implementation.registry.serverVersion,
    serverSchemaRevision: implementation.registry.serverSchemaRevision,
    recordSha256: implementation.registry.recordSha256,
    status: implementation.registry.status,
  }
}

function assertSortedUnique(
  values: readonly string[],
  duplicateCode: SourceCatalogValidationCode,
): void {
  const sorted = [...new Set(values)].sort(compareText)
  if (sorted.length !== values.length) throw new SourceCatalogValidationError(duplicateCode)
  if (JSON.stringify(sorted) !== JSON.stringify(values)) {
    throw new SourceCatalogValidationError('catalog_unsorted')
  }
}

function compareCatalogRevisions(left: string, right: string): number {
  const leftParts = catalogRevisionParts(left)
  const rightParts = catalogRevisionParts(right)
  for (let index = 0; index < leftParts.length; index += 1) {
    const difference = (leftParts[index] ?? 0) - (rightParts[index] ?? 0)
    if (difference !== 0) return difference
  }
  return 0
}

function compareDates(left: string, right: string): number {
  return compareText(left, right)
}

function catalogRevisionParts(value: string): readonly number[] {
  const match = value.match(CATALOG_REVISION)
  if (!match) return []
  return match.slice(1).map(Number)
}

function catalogRevisionDate(value: string): string {
  return value.slice(0, 10)
}

function isCatalogRevision(value: string): boolean {
  const match = value.match(CATALOG_REVISION)
  return match !== null && isCalendarDate(`${match[1]}-${match[2]}-${match[3]}`)
}

function isCalendarDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(value)) return false
  const date = new Date(`${value}T00:00:00.000Z`)
  return Number.isFinite(date.valueOf()) && date.toISOString().slice(0, 10) === value
}

function isPublicHttpsUrl(value: string, requireNonRootPath: boolean): boolean {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return false
  }
  const hostname = url.hostname.toLowerCase()
  if (
    url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash ||
    url.hostname !== hostname || !isHostname(hostname) || hostname === 'localhost' ||
    BLOCKED_HOST_SUFFIXES.some((suffix) => hostname.endsWith(suffix)) ||
    (requireNonRootPath && url.pathname === '/')
  ) return false
  return url.href === value
}

function isHostname(value: string): boolean {
  if (value.length > 253 || /^(?:\d+\.)+\d+$/u.test(value)) return false
  const labels = value.split('.')
  return labels.length >= 2 && labels.every((label) =>
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))
}

function hasForbiddenSecretKey(value: SourceCatalogInput): boolean {
  if (Array.isArray(value)) return value.some(hasForbiddenSecretKey)
  if (value === null || value === undefined ||
    v.is(v.union([v.boolean(), v.number(), v.string()]), value)) return false
  return Object.entries(value).some(([key, child]) =>
    FORBIDDEN_SECRET_KEY.test(key) || hasForbiddenSecretKey(child))
}

function hasControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const code = character.charCodeAt(0)
    return code <= 31 || code === 127
  })
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}
