import { GatewayApiError } from './api'
import type {
  GatewayAdminApi,
  GatewayStatus,
  ManagedSources,
  PreparedAction,
  RuntimeAction,
  RuntimeOperation,
  RuntimeUpdate,
  RuntimeVersion,
  SourceAction,
  SourceActions,
  SourceActionSummary,
  SourceDiscovery,
  SourceDraftInput,
  Team,
  TeamAction,
  TeamActionResult,
  TeamMember,
} from './api'

const PREVIEW_SCENARIOS = [
  'empty', 'ready', 'update', 'error', 'team-recovery', 'team-readonly', 'team-lifecycle', 'team-legacy', 'team-no-credential',
  'source-pending', 'source-applying', 'source-expired', 'source-recovery', 'source-completed', 'source-late-success', 'source-lifecycle',
] as const
type PreviewScenario = typeof PREVIEW_SCENARIOS[number]
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
  installationEnabled: true,
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
  if (isPreviewScenario(requested)) {
    window.sessionStorage.setItem(PREVIEW_STORAGE_KEY, requested)
    return requested
  }
  const retained = window.sessionStorage.getItem(PREVIEW_STORAGE_KEY)
  return isPreviewScenario(retained) ? retained : 'ready'
}

function isPreviewScenario(value: string | null): value is PreviewScenario {
  return PREVIEW_SCENARIOS.some((scenario) => scenario === value)
}

function legacySourceAction(action: SourceActionSummary): SourceAction {
  const { schemaVersion, actionId, sourceId, status: actionStatus, expiresAt, failureCode } = action
  return { schemaVersion, actionId, sourceId, status: actionStatus, expiresAt, failureCode }
}

function update(available: boolean): RuntimeUpdate {
  return {
    schemaVersion: 1,
    channel: 'stable',
    status: available ? 'available' : 'up_to_date',
    current: { release: 'gateway-v0.1.12', artifactSha256: `sha256:${'1'.repeat(64)}` },
    available: available ? {
      release: 'gateway-v0.1.13',
      artifactSha256: `sha256:${'2'.repeat(64)}`,
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
      notes: ['Updates the signed management interface.', 'Preserves your configuration and Durable Object state.'],
    } : null,
    rollback: { available: true, release: 'gateway-v0.1.11', artifactSha256: `sha256:${'4'.repeat(64)}`, dataRollback: false },
  }
}

class PreviewGatewayAdminApi implements GatewayAdminApi {
  #sources: ManagedSources
  #team: Team
  #sourceActions: SourceActionSummary[] = []
  readonly #scenario: PreviewScenario

  constructor(scenario: PreviewScenario) {
    this.#scenario = scenario
    this.#sources = structuredClone(scenario === 'empty' ? { ...installedSources, revision: 1, sources: [] } : installedSources)
    if (scenario.startsWith('source-') && scenario !== 'source-lifecycle') {
      const state = scenario === 'source-expired' ? 'authorization_expired' : scenario === 'source-recovery' ? 'recovery_required' :
        scenario === 'source-completed' ? 'succeeded' : scenario === 'source-applying' ? 'applying' : 'authorization_required'
      const expired = scenario === 'source-expired' || scenario === 'source-recovery'
      this.#sourceActions = [{
        schemaVersion: 1, actionId: ACTION_ID, sourceId: 'source-2222222222222222',
        issuedAt: new Date(Date.now() - (expired ? 660_000 : 60_000)).toISOString(),
        expiresAt: new Date(Date.now() + (expired ? -60_000 : 540_000)).toISOString(),
        status: state === 'authorization_expired' ? 'authorization_required' : state,
        state, canCancel: state === 'authorization_required' || state === 'authorization_expired',
        failureCode: state === 'recovery_required' ? 'source_action_recovery_required' : null,
      }]
      const completedSource = this.#sources.sources.find((source) => source.id === 'source-2222222222222222')
      if (state === 'succeeded' && completedSource) completedSource.status = 'installed'
    }
    this.#team = {
      schemaVersion: 1,
      revision: 2,
      editingEnabled: false,
      editingDisabledReason: scenario === 'team-lifecycle' ? 'lifecycle_action_pending' : 'managed_in_cloudflare',
      managementCredentialConfigured: false,
      adminEmails: ['admin@example.com'],
      members: [
        { email: 'admin@example.com', sourceIds: scenario === 'empty' ? [] : ['source-1111111111111111'] },
        { email: 'analyst@example.com', sourceIds: [] },
      ],
      sources: this.#sources.sources.map(({ id, label, enabledTools, status: sourceStatus }) => ({ id, label, enabledTools, status: sourceStatus })),
      pendingAction: null,
      proposedMembers: null,
    }
    if (scenario === 'team-recovery' || scenario === 'team-legacy') {
      this.#team.pendingAction = { schemaVersion: 1, actionId: ACTION_ID, status: scenario === 'team-recovery' ? 'recovery_required' : 'authorization_required', expiresAt: new Date(Date.now() + 600_000).toISOString(), failureCode: scenario === 'team-recovery' ? 'team_action_recovery_required' : null, canCancel: scenario === 'team-legacy' }
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

  async prepareTeamAction(expectedRevision: number, members: TeamMember[]): Promise<TeamActionResult> {
    if (!this.#team.editingEnabled) throw new GatewayApiError(403, this.#team.editingDisabledReason === 'managed_in_cloudflare'
      ? 'team_editing_managed_in_cloudflare'
      : this.#team.editingDisabledReason === 'release_review_required' ? 'team_release_review_required' : 'team_action_conflict')
    if (expectedRevision !== this.#team.revision) throw new GatewayApiError(409, 'team_access_revision_conflict')
    const pending = this.#team.pendingAction
    const continuing = pending && ['authorization_required', 'applying', 'recovery_required'].includes(pending.status)
    if (continuing && (pending.status === 'applying' || JSON.stringify(members) !== JSON.stringify(this.#team.proposedMembers))) throw new GatewayApiError(409, 'team_action_conflict')
    const expiresAt = new Date(Date.now() + 600_000).toISOString()
    const action: TeamActionResult['action'] = { schemaVersion: 1, actionId: ACTION_ID, status: 'succeeded', expiresAt, failureCode: null, canCancel: false }
    this.#team.members = structuredClone(members)
    this.#team.revision += 1
    this.#team.proposedMembers = null
    this.#team.pendingAction = action
    return { schemaVersion: 1, action: structuredClone(action) }
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

  async saveSourceDraft(revision: number, source: SourceDraftInput): Promise<ManagedSources> {
    if (!this.#sources.installationEnabled) throw new GatewayApiError(409, 'source_addition_paused')
    if (revision !== this.#sources.revision) throw new GatewayApiError(409, 'source_conflict')
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

  async prepareSourceAction(revision: number, sourceId: string): Promise<PreparedAction> {
    if (!this.#sources.installationEnabled) throw new GatewayApiError(409, 'source_addition_paused')
    if (revision !== this.#sources.revision || !this.#sources.sources.some((source) => source.id === sourceId && source.status === 'draft')) throw new GatewayApiError(409, 'source_action_conflict', { reason: 'draft_changed' })
    const { blockingAction, actions } = await this.getSourceActions()
    if (blockingAction) throw new GatewayApiError(409, 'source_action_conflict', {
      reason: blockingAction.kind !== 'source' ? 'lifecycle_pending' : actions.some((action) => action.actionId === blockingAction.actionId && action.state === 'recovery_required') ? 'recovery_required' : 'source_pending',
      action: blockingAction,
    })
    const action: SourceActionSummary = {
      schemaVersion: 1, actionId: `action_${(this.#sourceActions.length + 1).toString(16).padStart(32, '0')}`, sourceId,
      issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString(),
      status: 'authorization_required', state: 'authorization_required', failureCode: null, canCancel: true,
    }
    this.#sourceActions.push(action)
    return { schemaVersion: 1, actionId: action.actionId, status: 'authorization_required', expiresAt: action.expiresAt, handoffUrl: HANDOFF }
  }

  async getSourceActions(): Promise<SourceActions> {
    for (const action of this.#sourceActions) {
      if (action.state === 'authorization_required' && Date.now() >= Date.parse(action.expiresAt)) action.state = 'authorization_expired'
      if (action.state === 'applying' && Date.now() >= Date.parse(action.expiresAt)) action.state = 'recovery_required'
      if (this.#scenario === 'source-late-success' && action.state === 'authorization_required' && Date.now() >= Date.parse(action.issuedAt) + 75_000) {
        action.status = action.state = 'succeeded'
        action.canCancel = false
        const source = this.#sources.sources.find((candidate) => candidate.id === action.sourceId)
        if (source?.status === 'draft') { source.status = 'installed'; this.#sources.revision += 1 }
      }
    }
    const pending = this.#sourceActions.find((action) => action.state !== 'succeeded' && action.state !== 'failed')
    const teamAction = this.#team.pendingAction
    const blockingAction: SourceActions['blockingAction'] = pending ? { kind: 'source', actionId: pending.actionId, sourceId: pending.sourceId } :
      teamAction && !['succeeded', 'failed'].includes(teamAction.status) ? { kind: 'team', actionId: teamAction.actionId } :
      this.#scenario === 'source-lifecycle' ? { kind: 'runtime', actionId: ACTION_ID } : null
    return structuredClone({ schemaVersion: 1, actions: this.#sourceActions, blockingAction })
  }

  async getSourceAction(actionId: string): Promise<SourceAction> {
    const current = await this.getSourceActions()
    const action = current.actions.find((candidate) => candidate.actionId === actionId)
    if (!action) throw new GatewayApiError(404, 'source_action_not_found')
    return legacySourceAction(action)
  }

  async cancelSourceAction(actionId: string): Promise<SourceAction> {
    await this.getSourceActions()
    const action = this.#sourceActions.find((candidate) => candidate.actionId === actionId)
    if (!action) throw new GatewayApiError(404, 'source_action_not_found')
    if (!action.canCancel) throw new GatewayApiError(409, 'source_action_conflict', {
      reason: action.state === 'recovery_required' ? 'recovery_required' : 'source_pending',
      action: { kind: 'source', actionId, sourceId: action.sourceId },
    })
    action.status = action.state = 'failed'
    action.failureCode = 'source_action_denied'
    action.canCancel = false
    return legacySourceAction(action)
  }

  async prepareRuntimeAction(operation: RuntimeOperation, expectedTarget?: RuntimeVersion): Promise<PreparedAction & { operation: RuntimeOperation }> {
    const current = await this.getUpdate()
    const target = operation === 'update' ? current.available : current.rollback.available ? current.rollback : null
    if (expectedTarget && (!target || target.release !== expectedTarget.release || target.artifactSha256 !== expectedTarget.artifactSha256)) throw new GatewayApiError(409, 'runtime_action_conflict')
    return { schemaVersion: 1, actionId: ACTION_ID, operation, status: 'authorization_required', expiresAt: new Date(Date.now() + 600_000).toISOString(), handoffUrl: HANDOFF }
  }

  async getRuntimeAction(_actionId: string): Promise<RuntimeAction> {
    return {
      schemaVersion: 1,
      actionId: ACTION_ID,
      operation: 'update',
      status: 'succeeded',
      stage: 'activated',
      from: { release: 'gateway-v0.1.12', artifactSha256: `sha256:${'1'.repeat(64)}` },
      to: { release: 'gateway-v0.1.13', artifactSha256: `sha256:${'2'.repeat(64)}` },
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
