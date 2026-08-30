import type { SourceCatalog } from './index'

/**
 * Public catalog history is append-only. Before changing SOURCE_CATALOG after
 * a release, append its previous value here. Release-gated tests verify every
 * transition and the current manifest; old entries remain useful evidence
 * when a deprecated or deleted Registry server is removed from the picker.
 */
const EMPTY_CATALOG_BASELINE: SourceCatalog = {
  schemaVersion: 1,
  catalogRevision: '2026-08-28.1',
  sources: [],
}

export const SOURCE_CATALOG_HISTORY: readonly SourceCatalog[] = Object.freeze([
  EMPTY_CATALOG_BASELINE,
])

/** Reviewed production entries only. Synthetic data belongs in fixtures.ts. */
export const SOURCE_CATALOG: SourceCatalog = Object.freeze({
  schemaVersion: 1,
  catalogRevision: '2026-08-29.1',
  sources: [],
})
