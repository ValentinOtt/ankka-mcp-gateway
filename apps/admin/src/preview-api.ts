import { GatewayApiError } from './api'
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
  Team,
  TeamAction,
  TeamMember,
} from './api'

type PreviewScenario = 'empty' | 'ready' | 'update' | 'error' | 'team-recovery' | 'team-readonly' | 'team-lifecycle'
const PREVIEW_STORAGE_KEY = 'ankka-gateway-ui-preview-scenario'
const ACTION_ID = `action_${'a'.repeat(32)}`
const CONTROL_PLANE_ORIGIN = 'https://deploy.ankka.ai'
const HANDOFF = `${CONTROL_PLANE_ORIGIN}/manage#${'a'.repeat(40)}`

const status: GatewayStatus = {
  schemaVersion: 1,
  status: 'ready',
  controlPlaneOrigin: CONTROL_PLANE_ORIGIN,
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
  installationEnabled: false,
  sources: [
    {
      id: 'source-1111111111111111',
      label: 'Company knowledge',
      url: 'https://knowledge.example.com/mcp',
      authMode: 'oauth',
      onBehalfOfUser: false,
      enabledTools: ['fetch_document', 'search'],
      status: 'installed',
    },
    {
      id: 'source-2222222222222222',
      label: 'Product catalogue',
      url: 'https://catalogue.example.com/mcp',
      authMode: 'none',
      onBehalfOfUser: false,
      enabledTools: ['get_product', 'list_products'],
      status: 'draft',
    },
  ],
}

function scenarioFromLocation(): PreviewScenario {
  const requested = new URLSearchParams(window.location.search).get('preview')
  if (requested === 'empty' || requested === 'ready' || requested === 'update' || requested === 'error' || requested === 'team-recovery' || requested === 'team-readonly' || requested === 'team-lifecycle') {
    window.sessionStorage.setItem(PREVIEW_STORAGE_KEY, requested)
    return requested
  }
  const retained = window.sessionStorage.getItem(PREVIEW_STORAGE_KEY)
  return retained === 'empty' || retained === 'update' || retained === 'error' || retained === 'team-recovery' || retained === 'team-readonly' || retained === 'team-lifecycle' ? retained : 'ready'
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
      classification: {
        kind: 'normal',
        updaterProtocol: 2,
        changes: ['customer_worker_code', 'management_assets'],
        excludes: [
          'access_policies',
          'credentials',
          'dns',
          'durable_object_migrations',
          'mcp_portal_configuration',
          'sources',
          'tool_allowlists',
        ],
      },
      notes: ['Updates the signed management interface.', 'Preserves customer configuration and Durable Object state.'],
    } : null,
    rollback: { available: true, release: 'gateway-v0.1.11', artifactSha256: '4'.repeat(64), dataRollback: false },
  }
}

class PreviewGatewayAdminApi implements GatewayAdminApi {
  #sources: ManagedSources
  #team: Team
  readonly #scenario: PreviewScenario

  constructor(scenario: PreviewScenario) {
    this.#scenario = scenario
    this.#sources = structuredClone(scenario === 'empty' ? { ...installedSources, revision: 1, sources: [] } : installedSources)
    this.#team = {
      schemaVersion: 1,
      revision: 2,
      editingEnabled: scenario !== 'team-readonly' && scenario !== 'team-lifecycle',
      editingDisabledReason: scenario === 'team-readonly' ? 'release_review_required' : scenario === 'team-lifecycle' ? 'lifecycle_action_pending' : null,
      adminEmails: ['admin@example.com'],
      members: [
        { email: 'admin@example.com', sourceIds: scenario === 'empty' ? [] : ['source-1111111111111111'] },
        { email: 'analyst@example.com', sourceIds: [] },
      ],
      sources: this.#sources.sources.map(({ id, label, enabledTools, status: sourceStatus }) => ({ id, label, enabledTools, status: sourceStatus })),
      pendingAction: null,
      proposedMembers: null,
    }
    if (scenario === 'team-recovery') {
      this.#team.pendingAction = { schemaVersion: 1, actionId: ACTION_ID, status: 'recovery_required', expiresAt: new Date(Date.now() + 600_000).toISOString(), failureCode: 'team_action_recovery_required', canCancel: false }
      this.#team.proposedMembers = [
        { email: 'admin@example.com', sourceIds: ['source-1111111111111111'] },
        { email: 'analyst@example.com', sourceIds: ['source-1111111111111111'] },
      ]
    }
  }

  async getStatus(): Promise<GatewayStatus> {
    if (this.#scenario === 'error') throw new Error('Synthetic preview error: the gateway could not be reached.')
    return structuredClone(status)
  }

  async getSources(): Promise<ManagedSources> { return structuredClone(this.#sources) }
  async getTeam(): Promise<Team> {
    if (this.#scenario === 'error') throw new Error('Synthetic preview error: team access could not be loaded.')
    return structuredClone({ ...this.#team, sources: this.#sources.sources.map(({ id, label, enabledTools, status: sourceStatus }) => ({ id, label, enabledTools, status: sourceStatus })) })
  }

  async prepareTeamAction(expectedRevision: number, members: TeamMember[]): Promise<PreparedAction> {
    if (!this.#team.editingEnabled) throw new GatewayApiError(403, this.#team.editingDisabledReason === 'release_review_required' ? 'team_release_review_required' : 'team_action_conflict')
    if (expectedRevision !== this.#team.revision) throw new GatewayApiError(409, 'team_access_revision_conflict')
    const pending = this.#team.pendingAction
    const continuing = pending && ['authorization_required', 'applying', 'recovery_required'].includes(pending.status)
    if (continuing && (pending.status === 'applying' || JSON.stringify(members) !== JSON.stringify(this.#team.proposedMembers))) throw new GatewayApiError(409, 'team_action_conflict')
    const expiresAt = new Date(Date.now() + 600_000).toISOString()
    this.#team.proposedMembers = structuredClone(members)
    this.#team.pendingAction = { schemaVersion: 1, actionId: ACTION_ID, status: 'authorization_required', expiresAt, failureCode: null, canCancel: continuing ? pending.canCancel : true }
    return { schemaVersion: 1, actionId: ACTION_ID, status: 'authorization_required', expiresAt, handoffUrl: HANDOFF }
  }

  async getTeamAction(_actionId: string): Promise<TeamAction> {
    if (!this.#team.pendingAction || this.#team.pendingAction.actionId !== _actionId) throw new GatewayApiError(404, 'team_action_invalid')
    return structuredClone(this.#team.pendingAction)
  }

  async cancelTeamAction(actionId: string): Promise<TeamAction> {
    const pending = this.#team.pendingAction
    if (!pending || pending.actionId !== actionId || pending.status !== 'authorization_required' || pending.canCancel !== true) throw new GatewayApiError(409, 'team_action_conflict')
    this.#team.pendingAction = { ...pending, status: 'failed', failureCode: 'team_action_cancelled', canCancel: false }
    this.#team.proposedMembers = null
    return structuredClone(this.#team.pendingAction)
  }
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
    if (!this.#sources.installationEnabled) throw new GatewayApiError(409, 'source_addition_paused')
    this.#sources = {
      ...this.#sources,
      revision: this.#sources.revision + 1,
      sources: [...this.#sources.sources, {
        id: `source-${(this.#sources.sources.length + 1).toString(16).padStart(16, '0')}`,
        ...structuredClone(source),
        onBehalfOfUser: false,
        status: 'draft',
      }],
    }
    return structuredClone(this.#sources)
  }

  async prepareSourceAction(_revision: number, _sourceId: string): Promise<PreparedAction> {
    throw new GatewayApiError(409, 'source_addition_paused')
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

export function isGatewayUiPreview(): boolean {
  return import.meta.env.DEV && import.meta.env.VITE_GATEWAY_UI_PREVIEW === '1'
}

export function createPreviewGatewayAdminApi(): GatewayAdminApi | undefined {
  return isGatewayUiPreview()
    ? new PreviewGatewayAdminApi(scenarioFromLocation())
    : undefined
}
