import type { SourceCatalog } from './index'

/** Public, synthetic data for tests and previews. Never ship it as a preset. */
export const SYNTHETIC_SOURCE_CATALOG = {
  schemaVersion: 1,
  catalogRevision: '2026-08-29.1',
  sources: [{
    sourceId: 'example-analytics',
    displayName: 'Example Analytics',
    description: 'Read reviewed synthetic reporting data.',
    documentationUrl: 'https://example.com/docs/mcp',
    implementation: {
      implementationId: 'example-analytics-registry',
      implementationRevision: 1,
      catalogProvenance: 'official_registry',
      kind: 'native_mcp',
      behaviorSha256: 'sha256:e15d2bf80bb097bf8f991881f7b4403a27cadb1b730e6eeb206be64a3ea7a119',
      registry: {
        serverName: 'com.example/analytics',
        serverVersion: '1.2.3',
        serverSchemaRevision: '2025-12-11',
        recordSha256: 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
        status: 'active',
        observedAt: '2026-08-29',
      },
      deployment: {
        kind: 'remote_mcp',
        transport: 'streamable_http',
        url: 'https://mcp.example.com/mcp',
      },
      connection: {
        authMode: 'oauth',
        onBehalfOfUser: false,
      },
      recommendedTools: ['properties.list', 'reports.read'],
    },
    publisher: {
      relationship: 'provider',
      evidence: ['https://example.com/docs/mcp'],
    },
    review: {
      status: 'ankka_reviewed',
      reviewedAt: '2026-08-29',
    },
  }],
} as const satisfies SourceCatalog
