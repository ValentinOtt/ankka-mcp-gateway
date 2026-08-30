import { describe, expect, it } from 'vitest'
import {
  assertCatalogHistory,
  parseVerifiedSourceCatalog,
  SOURCE_CATALOG,
  SOURCE_CATALOG_HISTORY,
} from './index'

describe('production source catalog release gate', () => {
  it('recomputes production behavior digests and verifies append-only evolution', async () => {
    await expect(parseVerifiedSourceCatalog(SOURCE_CATALOG)).resolves.toEqual(SOURCE_CATALOG)
    await expect(
      assertCatalogHistory(SOURCE_CATALOG_HISTORY, SOURCE_CATALOG),
    ).resolves.toBeUndefined()
  })
})
