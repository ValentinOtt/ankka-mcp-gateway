import { describe, expect, it } from 'vitest'
import { SYNTHETIC_SOURCE_CATALOG } from './fixtures'
import {
  assertCatalogEvolution,
  assertCatalogHistory,
  computeBehaviorSha256,
  parseSourceCatalog,
  parseVerifiedSourceCatalog,
  SOURCE_CATALOG,
  SourceCatalogValidationError,
  type SourceCatalog,
  type SourceCatalogSource,
} from './index'

function syntheticCatalog(): SourceCatalog {
  return structuredClone(SYNTHETIC_SOURCE_CATALOG)
}

function onlySource(catalog: SourceCatalog): SourceCatalogSource {
  const source = catalog.sources[0]
  if (!source) throw new Error('synthetic catalog source missing')
  return source
}

type CatalogErrorCandidate = Error | null | undefined

function expectCatalogError(
  code: SourceCatalogValidationError['code'],
): (error: CatalogErrorCandidate) => boolean {
  return (error) => error instanceof SourceCatalogValidationError &&
    error.code === code && error.message === code
}

describe('source catalog contract', () => {
  it('parses production data and verifies the synthetic fixture', async () => {
    expect(parseSourceCatalog(SOURCE_CATALOG)).toEqual(SOURCE_CATALOG)
    await expect(parseVerifiedSourceCatalog(SYNTHETIC_SOURCE_CATALOG)).resolves.toEqual(
      SYNTHETIC_SOURCE_CATALOG,
    )
  })

  it('rejects unknown and secret-bearing fields without reflecting their values', () => {
    const unknown = Object.assign(syntheticCatalog(), { extra: true })
    expect(() => parseSourceCatalog(unknown)).toThrow(SourceCatalogValidationError)

    const secretBearing = Object.assign(syntheticCatalog(), { clientSecret: null })
    expect(() => parseSourceCatalog(secretBearing)).toThrowError(
      expect.objectContaining({ code: 'catalog_secret_field', message: 'catalog_secret_field' }),
    )
  })

  it.each([
    'http://mcp.example.com/mcp',
    'https://mcp.example.com/',
    'https://mcp.example.com/mcp?key=value',
    'https://mcp.example.local/mcp',
    'https://owner@mcp.example.com/mcp',
  ])('rejects an incompatible remote URL: %s', (url) => {
    const catalog = syntheticCatalog()
    onlySource(catalog).implementation.deployment.url = url
    expect(() => parseSourceCatalog(catalog)).toThrow(SourceCatalogValidationError)
  })

  it('accepts only sorted, unique, exact nonempty recommended tools', () => {
    for (const tools of [
      [],
      ['*'],
      ['reports.read', 'reports.read'],
      ['reports.read', 'properties.list'],
      ['reports read'],
    ]) {
      const catalog = syntheticCatalog()
      onlySource(catalog).implementation.recommendedTools = tools
      expect(() => parseSourceCatalog(catalog)).toThrow(SourceCatalogValidationError)
    }
  })

  it('requires stable unique source and implementation identities in deterministic order', () => {
    const duplicateSource = syntheticCatalog()
    duplicateSource.sources.push(structuredClone(onlySource(duplicateSource)))
    expect(() => parseSourceCatalog(duplicateSource)).toThrowError(
      expect.objectContaining({ code: 'catalog_duplicate_source_id' }),
    )

    const duplicateImplementation = syntheticCatalog()
    const second = structuredClone(onlySource(duplicateImplementation))
    second.sourceId = 'another-source'
    duplicateImplementation.sources.unshift(second)
    expect(() => parseSourceCatalog(duplicateImplementation)).toThrowError(
      expect.objectContaining({ code: 'catalog_duplicate_implementation_id' }),
    )

    const unsorted = syntheticCatalog()
    const earlier = structuredClone(onlySource(unsorted))
    earlier.sourceId = 'another-source'
    earlier.implementation.implementationId = 'another-source-registry'
    unsorted.sources.push(earlier)
    expect(() => parseSourceCatalog(unsorted)).toThrowError(
      expect.objectContaining({ code: 'catalog_unsorted' }),
    )

    const unsupportedSchema = syntheticCatalog()
    Reflect.set(
      onlySource(unsupportedSchema).implementation.registry,
      'serverSchemaRevision',
      '2099-01-01',
    )
    expect(() => parseSourceCatalog(unsupportedSchema)).toThrow(SourceCatalogValidationError)

    const unsafeVersion = syntheticCatalog()
    onlySource(unsafeVersion).implementation.registry.serverVersion = '..'
    expect(() => parseSourceCatalog(unsafeVersion)).toThrow(SourceCatalogValidationError)
  })

  it('hashes behavioral fields but excludes Registry observation metadata', async () => {
    const original = onlySource(syntheticCatalog()).implementation
    const observationUpdate = structuredClone(original)
    observationUpdate.registry.observedAt = '2026-08-30'
    expect(await computeBehaviorSha256(observationUpdate)).toBe(original.behaviorSha256)

    const behaviorUpdate = structuredClone(original)
    behaviorUpdate.connection.authMode = 'none'
    expect(await computeBehaviorSha256(behaviorUpdate)).not.toBe(original.behaviorSha256)
  })

  it('rejects a behavior digest that does not match the normalized implementation', async () => {
    const catalog = syntheticCatalog()
    onlySource(catalog).implementation.behaviorSha256 = `sha256:${'0'.repeat(64)}`
    await expect(parseVerifiedSourceCatalog(catalog)).rejects.toSatisfy(
      expectCatalogError('catalog_behavior_digest_mismatch'),
    )
  })

  it('allows presentation and observation refreshes without rewriting behavior', async () => {
    const next = syntheticCatalog()
    next.catalogRevision = '2026-08-30.1'
    const source = onlySource(next)
    source.description = 'Updated synthetic presentation text.'
    source.review.reviewedAt = '2026-08-30'
    source.implementation.registry.observedAt = '2026-08-30'
    await expect(assertCatalogEvolution(SYNTHETIC_SOURCE_CATALOG, next)).resolves.toBeUndefined()
  })

  it('requires a new implementation revision for a behavior change', async () => {
    const next = syntheticCatalog()
    next.catalogRevision = '2026-08-30.1'
    const implementation = onlySource(next).implementation
    implementation.recommendedTools.push('reports.summary')
    implementation.behaviorSha256 = await computeBehaviorSha256(implementation)
    await expect(assertCatalogEvolution(SYNTHETIC_SOURCE_CATALOG, next)).rejects.toSatisfy(
      expectCatalogError('catalog_implementation_revision_reused'),
    )

    implementation.implementationRevision = 2
    onlySource(next).review.reviewedAt = '2026-08-30'
    await expect(assertCatalogEvolution(SYNTHETIC_SOURCE_CATALOG, next)).resolves.toBeUndefined()
  })

  it('uses the advancing catalog revision for a same-day evidence review', async () => {
    const next = syntheticCatalog()
    next.catalogRevision = '2026-08-29.2'
    const implementation = onlySource(next).implementation
    implementation.registry.recordSha256 = `sha256:${'2'.repeat(64)}`
    implementation.implementationRevision = 2
    implementation.behaviorSha256 = await computeBehaviorSha256(implementation)

    await expect(assertCatalogEvolution(SYNTHETIC_SOURCE_CATALOG, next)).resolves.toBeUndefined()
  })

  it('requires new entries to be observed and reviewed in their catalog revision', async () => {
    const previous: SourceCatalog = {
      schemaVersion: 1,
      catalogRevision: '2026-08-28.1',
      sources: [],
    }
    const staleEntry = syntheticCatalog()
    onlySource(staleEntry).implementation.registry.observedAt = '2026-08-28'
    onlySource(staleEntry).review.reviewedAt = '2026-08-28'

    await expect(assertCatalogEvolution(previous, staleEntry)).rejects.toSatisfy(
      expectCatalogError('catalog_registry_observation_not_refreshed'),
    )
    await expect(
      assertCatalogEvolution(previous, SYNTHETIC_SOURCE_CATALOG),
    ).resolves.toBeUndefined()
  })

  it('requires a fresh review when publisher evidence changes', async () => {
    const next = syntheticCatalog()
    next.catalogRevision = '2026-08-30.1'
    onlySource(next).publisher.relationship = 'community'
    await expect(assertCatalogEvolution(SYNTHETIC_SOURCE_CATALOG, next)).rejects.toSatisfy(
      expectCatalogError('catalog_review_not_refreshed'),
    )

    onlySource(next).review.reviewedAt = '2026-08-30'
    await expect(assertCatalogEvolution(SYNTHETIC_SOURCE_CATALOG, next)).resolves.toBeUndefined()
  })

  it('requires Registry changes to carry a fresh observation and review', async () => {
    const next = syntheticCatalog()
    next.catalogRevision = '2026-08-30.1'
    const source = onlySource(next)
    source.implementation.registry.recordSha256 = `sha256:${'2'.repeat(64)}`
    source.implementation.implementationRevision = 2
    source.implementation.behaviorSha256 = await computeBehaviorSha256(source.implementation)
    source.review.reviewedAt = '2026-08-30'
    await expect(assertCatalogEvolution(SYNTHETIC_SOURCE_CATALOG, next)).rejects.toSatisfy(
      expectCatalogError('catalog_registry_observation_not_refreshed'),
    )

    source.implementation.registry.observedAt = '2026-08-30'
    await expect(assertCatalogEvolution(SYNTHETIC_SOURCE_CATALOG, next)).resolves.toBeUndefined()
  })

  it('rejects regressed observations and reviews older than their evidence', async () => {
    const regressed = syntheticCatalog()
    regressed.catalogRevision = '2026-08-30.1'
    onlySource(regressed).implementation.registry.observedAt = '2026-08-28'
    await expect(assertCatalogEvolution(SYNTHETIC_SOURCE_CATALOG, regressed)).rejects.toSatisfy(
      expectCatalogError('catalog_registry_observation_regressed'),
    )

    const staleReview = syntheticCatalog()
    onlySource(staleReview).implementation.registry.observedAt = '2026-08-30'
    expect(() => parseSourceCatalog(staleReview)).toThrowError(
      expect.objectContaining({ code: 'catalog_review_precedes_observation' }),
    )

    const futureEvidence = syntheticCatalog()
    futureEvidence.catalogRevision = '2026-08-29.2'
    onlySource(futureEvidence).implementation.registry.observedAt = '2026-08-30'
    onlySource(futureEvidence).review.reviewedAt = '2026-08-30'
    expect(() => parseSourceCatalog(futureEvidence)).toThrowError(
      expect.objectContaining({ code: 'catalog_evidence_after_revision' }),
    )
  })

  it('keeps deprecated lifecycle state out of v1 and permits reviewed removal', async () => {
    const unsupportedStatus = syntheticCatalog()
    Reflect.set(onlySource(unsupportedStatus).implementation.registry, 'status', 'deprecated')
    expect(() => parseSourceCatalog(unsupportedStatus)).toThrow(SourceCatalogValidationError)

    const removed = syntheticCatalog()
    removed.catalogRevision = '2026-08-30.1'
    removed.sources = []
    await expect(assertCatalogEvolution(SYNTHETIC_SOURCE_CATALOG, removed)).resolves.toBeUndefined()
  })

  it('rejects reassignment of a historical implementation after removal', async () => {
    const removed = syntheticCatalog()
    removed.catalogRevision = '2026-08-30.1'
    removed.sources = []

    const reassigned = syntheticCatalog()
    reassigned.catalogRevision = '2026-08-31.1'
    onlySource(reassigned).sourceId = 'other-analytics'
    onlySource(reassigned).review.reviewedAt = '2026-08-31'

    await expect(
      assertCatalogHistory([SYNTHETIC_SOURCE_CATALOG, removed], reassigned),
    ).rejects.toSatisfy(expectCatalogError('catalog_implementation_identity_changed'))
  })

  it('preserves immutable implementation revisions across removal and reintroduction', async () => {
    const removed = syntheticCatalog()
    removed.catalogRevision = '2026-08-30.1'
    removed.sources = []

    const reintroduced = syntheticCatalog()
    reintroduced.catalogRevision = '2026-08-31.1'
    const source = onlySource(reintroduced)
    source.implementation.deployment.url = 'https://mcp.example.com/v2/mcp'
    source.implementation.registry.observedAt = '2026-08-31'
    source.implementation.behaviorSha256 = await computeBehaviorSha256(source.implementation)
    source.review.reviewedAt = '2026-08-31'

    await expect(
      assertCatalogHistory([SYNTHETIC_SOURCE_CATALOG, removed], reintroduced),
    ).rejects.toSatisfy(expectCatalogError('catalog_implementation_revision_reused'))

    source.implementation.implementationRevision = 2
    await expect(
      assertCatalogHistory([SYNTHETIC_SOURCE_CATALOG, removed], reintroduced),
    ).resolves.toBeUndefined()
  })

  it('rejects meaningless revision bumps and non-advancing catalog revisions', async () => {
    const redundant = syntheticCatalog()
    redundant.catalogRevision = '2026-08-30.1'
    onlySource(redundant).implementation.implementationRevision = 2
    await expect(assertCatalogEvolution(SYNTHETIC_SOURCE_CATALOG, redundant)).rejects.toSatisfy(
      expectCatalogError('catalog_implementation_revision_redundant'),
    )

    await expect(assertCatalogEvolution(
      SYNTHETIC_SOURCE_CATALOG,
      SYNTHETIC_SOURCE_CATALOG,
    )).rejects.toSatisfy(expectCatalogError('catalog_revision_not_advanced'))
  })
})
