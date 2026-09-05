import { describe, expect, it } from 'vitest'
import { parseBigQueryDatasets } from './BigQuerySetupForm'

describe('BigQuery dataset selection', () => {
  it.each(['', 'project.dataset.table', 'invalid/data', 'data-project.reporting\ndata-project.reporting', 'data-project.*'])('rejects ambiguous or wildcard dataset input %s', (value) => {
    expect(parseBigQueryDatasets(value)).toBeNull()
  })
  it('keeps explicitly chosen cross-project datasets', () => {
    expect(parseBigQueryDatasets(' data-project.reporting\nother-project.analytics_123 ')).toEqual([
      { projectId: 'data-project', datasetId: 'reporting' }, { projectId: 'other-project', datasetId: 'analytics_123' },
    ])
  })
})
