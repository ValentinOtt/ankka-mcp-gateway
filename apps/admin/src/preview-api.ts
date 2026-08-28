import type {
  GatewayAdminApi,
  GatewayStatus,
  ManagedSources,
  PreparedAction,
  RuntimeAction,
  RuntimeOperation,
  RuntimeUpdate,
  SourceAction,
  SourceDiscovery,
  SourceDraftInput,
} from './api'

type PreviewScenario = 'empty' | 'ready' | 'update' | 'error'
const PREVIEW_STORAGE_KEY = 'ankka-gateway-ui-preview-scenario'
const ACTION_ID = `action_${'a'.repeat(32)}`
const HANDOFF = `https://deploy.ankka.ai/manage#${'a'.repeat(40)}`

const status: GatewayStatus = {
  schemaVersion: 1,
  status: 'ready',
  release: 'gateway-v0.1.12',
  gateway: {
    name: 'Example MCP Gateway',
    hostname: 'mcp.example.com',
    mcpUrl: 'https://mcp.example.com/mcp',
    capabilityMode: 'read_only',
    codeMode: 'default_on',
  },
  source: null,
  access: { administratorCount: 1, memberCount: 2 },
  updatedAt: '2026-08-27T12:00:00.000Z',
}

const installedSources: ManagedSources = {
  schemaVersion: 1,
  revision: 3,
  applyMode: 'oauth_per_action',
  sources: [
    {
      id: 'source-1111111111111111',
      label: 'Company knowledge',
      url: 'https://knowledge.example.com/mcp',
      authMode: 'oauth',
      enabledTools: ['fetch_document', 'search'],
      status: 'installed',
    },
    {
      id: 'source-2222222222222222',
      label: 'Product catalogue',
      url: 'https://catalogue.example.com/mcp',
      authMode: 'none',
      enabledTools: ['get_product', 'list_products'],
      status: 'draft',
    },
  ],
}

function scenarioFromLocation(): PreviewScenario {
  const requested = new URLSearchParams(window.location.search).get('preview')
  if (requested === 'empty' || requested === 'ready' || requested === 'update' || requested === 'error') {
    window.sessionStorage.setItem(PREVIEW_STORAGE_KEY, requested)
    return requested
  }
  const retained = window.sessionStorage.getItem(PREVIEW_STORAGE_KEY)
  return retained === 'empty' || retained === 'update' || retained === 'error' ? retained : 'ready'
}

function update(available: boolean): RuntimeUpdate {
  return {
    schemaVersion: 1,
    channel: 'stable',
    status: available ? 'available' : 'up_to_date',
    current: { release: 'gateway-v0.1.12', artifactSha256: '1'.repeat(64) },
    available: available ? {
      release: 'gateway-v0.1.13',
      artifactSha256: '2'.repeat(64),
      sourceCommit: '3'.repeat(40),
      classification: { kind: 'normal' },
      notes: ['Updates the signed management interface.', 'Preserves customer configuration and Durable Object state.'],
    } : null,
    rollback: { available: true, release: 'gateway-v0.1.11', artifactSha256: '4'.repeat(64), dataRollback: false },
  }
}

class PreviewGatewayAdminApi implements GatewayAdminApi {
  #sources: ManagedSources
  readonly #scenario: PreviewScenario

  constructor(scenario: PreviewScenario) {
    this.#scenario = scenario
    this.#sources = structuredClone(scenario === 'empty' ? { ...installedSources, revision: 1, sources: [] } : installedSources)
  }

  async getStatus(): Promise<GatewayStatus> {
    if (this.#scenario === 'error') throw new Error('Synthetic preview error: the gateway could not be reached.')
    return structuredClone(status)
  }

  async getSources(): Promise<ManagedSources> { return structuredClone(this.#sources) }
  async getUpdate(): Promise<RuntimeUpdate> { return update(this.#scenario === 'update') }

  async discoverSource(url: string): Promise<SourceDiscovery> {
    return {
      schemaVersion: 1,
      status: 'discovered',
      endpoint: url,
      protocolVersion: '2026-07-28',
      authentication: 'none',
      tools: [
        { name: 'search', title: 'Search', description: 'Search company knowledge.', readOnlyHint: true, destructiveHint: false, defaultSelected: true },
        { name: 'fetch_document', title: 'Fetch document', description: 'Retrieve one document by identifier.', readOnlyHint: true, destructiveHint: false, defaultSelected: true },
        { name: 'publish_document', title: 'Publish document', description: 'Publish a changed document.', destructiveHint: true, defaultSelected: false },
      ],
    }
  }

  async saveSourceDraft(_revision: number, source: SourceDraftInput): Promise<ManagedSources> {
    this.#sources = {
      ...this.#sources,
      revision: this.#sources.revision + 1,
      sources: [...this.#sources.sources, {
        id: `source-${(this.#sources.sources.length + 1).toString(16).padStart(16, '0')}`,
        ...structuredClone(source),
        status: 'draft',
      }],
    }
    return structuredClone(this.#sources)
  }

  async prepareSourceAction(_revision: number, _sourceId: string): Promise<PreparedAction> {
    return { schemaVersion: 1, actionId: ACTION_ID, status: 'authorization_required', expiresAt: new Date(Date.now() + 600_000).toISOString(), handoffUrl: HANDOFF }
  }

  async getSourceAction(_actionId: string): Promise<SourceAction> {
    return { schemaVersion: 1, actionId: ACTION_ID, sourceId: 'source-2222222222222222', status: 'succeeded', expiresAt: new Date(Date.now() + 600_000).toISOString(), failureCode: null }
  }

  async cancelSourceAction(actionId: string): Promise<SourceAction> { return this.getSourceAction(actionId) }

  async prepareRuntimeAction(operation: RuntimeOperation): Promise<PreparedAction & { operation: RuntimeOperation }> {
    return { schemaVersion: 1, actionId: ACTION_ID, operation, status: 'authorization_required', expiresAt: new Date(Date.now() + 600_000).toISOString(), handoffUrl: HANDOFF }
  }

  async getRuntimeAction(_actionId: string): Promise<RuntimeAction> {
    return {
      schemaVersion: 1,
      actionId: ACTION_ID,
      operation: 'update',
      status: 'succeeded',
      stage: 'activated',
      from: { release: 'gateway-v0.1.12', artifactSha256: '1'.repeat(64) },
      to: { release: 'gateway-v0.1.13', artifactSha256: '2'.repeat(64) },
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
      failureCode: null,
    }
  }

  async prepareTeardownAction(): Promise<PreparedAction> {
    return { schemaVersion: 1, actionId: ACTION_ID, status: 'authorization_required', expiresAt: new Date(Date.now() + 600_000).toISOString(), handoffUrl: HANDOFF }
  }

  async getTeardownAction(_actionId: string) {
    return { schemaVersion: 1 as const, actionId: ACTION_ID, status: 'applying' as const, expiresAt: new Date(Date.now() + 600_000).toISOString(), failureCode: null }
  }
}

export function createPreviewGatewayAdminApi(): GatewayAdminApi | undefined {
  return import.meta.env.DEV && import.meta.env.VITE_GATEWAY_UI_PREVIEW === '1'
    ? new PreviewGatewayAdminApi(scenarioFromLocation())
    : undefined
}
