import { describe, expect, it, vi } from 'vitest'
import {
  GatewayApiError,
  type GatewayAdminApi,
  type GatewayStatus,
  type ManagedSources,
  type PreparedAction,
  type RuntimeAction,
  type RuntimeUpdate,
  type SourceAction,
  type SourceActions,
  type Team,
  type TeamAction,
  type TeamActionResult,
  type TeamMember,
  type TeardownAction,
} from './api'
import { createGatewayWebMcpTools, type WebMcpInput } from './webmcp'

const actionId = `action_${'a'.repeat(32)}`
const otherActionId = `action_${'b'.repeat(32)}`
const sourceId = 'source-1111111111111111'
const digest = `sha256:${'1'.repeat(64)}`
const previousDigest = `sha256:${'2'.repeat(64)}`
const nextDigest = `sha256:${'3'.repeat(64)}`
const expiresAt = '2030-01-01T00:10:00.000Z'
const syntheticSensitiveText = 'synthetic-sensitive-value-never-display'

const names = [
  'get_gateway_status', 'get_gateway_capabilities', 'list_mcp_sources',
  'discover_mcp_source', 'save_mcp_source_draft', 'apply_mcp_source',
  'get_mcp_source_action', 'cancel_mcp_source_action', 'get_gateway_team',
  'list_mcp_source_actions',
  'get_gateway_team_action', 'cancel_gateway_team_action',
  'check_gateway_update', 'review_gateway_update', 'apply_gateway_update',
  'rollback_gateway_update', 'get_gateway_runtime_action',
  'review_gateway_teardown', 'get_gateway_teardown_action',
]
const noInputNames = [
  'get_gateway_status', 'get_gateway_capabilities', 'list_mcp_sources',
  'list_mcp_source_actions',
  'get_gateway_team', 'check_gateway_update', 'review_gateway_update',
  'review_gateway_teardown',
]
const actionNames = [
  'get_mcp_source_action', 'cancel_mcp_source_action', 'get_gateway_team_action',
  'cancel_gateway_team_action', 'get_gateway_runtime_action',
  'get_gateway_teardown_action',
]
const members: TeamMember[] = [
  { email: 'operator@example.com', sourceIds: [sourceId] },
  { email: 'teammate@example.com', sourceIds: [] },
]
const sourceDraft = {
  label: 'Example source', url: 'https://source.example.com/mcp',
  authMode: 'none', enabledTools: ['search'],
}

function fixture(installationEnabled = true, onStateChange?: () => Promise<void>) {
  const status: GatewayStatus = {
    schemaVersion: 1, status: 'ready', controlPlaneOrigin: 'https://deploy.ankka.ai',
    release: 'gateway-v1.0.0',
    gateway: {
      name: 'Example Gateway', hostname: 'gateway.example.com',
      mcpUrl: 'https://portal.example.com/mcp', capabilityMode: 'read_only', codeMode: 'default_on',
    },
    source: null, access: { administratorCount: 1, memberCount: 1 },
    updatedAt: '2030-01-01T00:00:00.000Z',
  }
  const sources: ManagedSources = {
    schemaVersion: 1, revision: 4, applyMode: 'oauth_per_action', installationEnabled,
    sources: [{
      id: sourceId, label: 'Example source', url: 'https://source.example.com/mcp',
      authMode: 'none', onBehalfOfUser: false, enabledTools: ['search'], status: 'installed',
    }],
  }
  const team: Team = {
    schemaVersion: 1, revision: 7, editingEnabled: false, editingDisabledReason: 'managed_in_cloudflare',
    managementCredentialConfigured: false, members, adminEmails: ['operator@example.com'],
    sources: [{ id: sourceId, label: 'Example source', enabledTools: ['search'], status: 'installed' }],
    pendingAction: null, proposedMembers: null,
  }
  const teamAction: TeamAction = {
    schemaVersion: 1, actionId, status: 'authorization_required', expiresAt,
    failureCode: null, canCancel: true,
  }
  const teamResult: TeamActionResult = {
    schemaVersion: 1, action: { ...teamAction, status: 'succeeded', canCancel: false },
  }
  const prepared: PreparedAction = {
    schemaVersion: 1, actionId, status: 'authorization_required', expiresAt,
    handoffUrl: `${window.location.origin}/__ankka/operation#${'x'.repeat(40)}`,
  }
  const sourceAction: SourceAction = {
    schemaVersion: 1, actionId, sourceId, status: 'applying', expiresAt, failureCode: null,
  }
  const teardownAction: TeardownAction = {
    schemaVersion: 1, actionId, status: 'authorization_required', expiresAt, failureCode: null,
  }
  const update: RuntimeUpdate = {
    schemaVersion: 1, channel: 'canary', status: 'available',
    current: { release: 'gateway-v1.0.0', artifactSha256: digest },
    available: {
      release: 'gateway-v1.0.1', artifactSha256: nextDigest, sourceCommit: 'a'.repeat(40),
      classification: { kind: 'normal', updaterProtocol: 2, changes: ['Worker code'], excludes: ['source credentials'] },
      notes: ['Synthetic signed update'],
    },
    rollback: { available: true, release: 'gateway-v0.9.9', artifactSha256: previousDigest, dataRollback: false },
  }
  const runtimeAction: RuntimeAction = {
    schemaVersion: 1, actionId, operation: 'update', status: 'applying', stage: 'candidate_probe',
    from: { release: 'gateway-v1.0.0', artifactSha256: digest },
    to: { release: 'gateway-v1.0.1', artifactSha256: nextDigest }, expiresAt, failureCode: null,
  }
  const api = {
    getStatus: vi.fn(async () => status),
    getSources: vi.fn(async () => sources),
    getTeam: vi.fn(async () => team),
    prepareTeamAction: vi.fn(async (_revision: number, _members: TeamMember[]) => teamResult),
    getTeamAction: vi.fn(async (_actionId: string) => teamAction),
    cancelTeamAction: vi.fn(async (_actionId: string): Promise<TeamAction> => ({
      ...teamAction, status: 'failed', failureCode: 'team_action_cancelled', canCancel: false,
    })),
    getUpdate: vi.fn(async () => update),
    discoverSource: vi.fn<GatewayAdminApi['discoverSource']>(),
    saveSourceDraft: vi.fn<GatewayAdminApi['saveSourceDraft']>(async () => sources),
    prepareSourceAction: vi.fn<GatewayAdminApi['prepareSourceAction']>(async () => prepared),
    getSourceActions: vi.fn<GatewayAdminApi['getSourceActions']>(async () => ({ schemaVersion: 1, actions: [], blockingAction: null })),
    getSourceAction: vi.fn(async (_actionId: string) => sourceAction),
    cancelSourceAction: vi.fn<GatewayAdminApi['cancelSourceAction']>(async () => ({ ...sourceAction, status: 'failed' })),
    prepareRuntimeAction: vi.fn<GatewayAdminApi['prepareRuntimeAction']>(async (operation) => ({ ...prepared, operation })),
    getRuntimeAction: vi.fn(async (_actionId: string) => runtimeAction),
    prepareTeardownAction: vi.fn(async () => prepared),
    getTeardownAction: vi.fn(async (_actionId: string) => teardownAction),
  } satisfies GatewayAdminApi
  const tools = createGatewayWebMcpTools(api, installationEnabled, onStateChange)
  const tool = (name: string) => {
    const found = tools.find((candidate) => candidate.name === name)
    if (!found) throw new Error(`Missing synthetic tool: ${name}`)
    return found
  }
  const call = async (name: string, input: WebMcpInput = {}, signal?: AbortSignal) => JSON.parse(
    await tool(name).execute(input, signal ? { signal } : undefined),
  )
  return { api, tools, tool, call, status, sources, team, teamAction, teamResult, prepared, update, sourceAction, runtimeAction, teardownAction }
}

function expectNoApiCalls(api: ReturnType<typeof fixture>['api']) {
  for (const method of Object.values(api)) expect(method).not.toHaveBeenCalled()
}

describe('Gateway WebMCP tool contracts', () => {
  it('refreshes after a successful mutation exactly once without repeating the save', async () => {
    const refresh = vi.fn(async () => {})
    const { api, call, sources } = fixture(true, refresh)
    expect(await call('save_mcp_source_draft', sourceDraft)).toEqual({ ok: true, result: sources })
    expect(api.saveSourceDraft).toHaveBeenCalledTimes(1)
    expect(refresh).toHaveBeenCalledTimes(1)
  })

  it('refreshes after an uncertain mutation without retrying it or replacing its error', async () => {
    const refresh = vi.fn(async () => {})
    const { api, call } = fixture(true, refresh)
    api.saveSourceDraft.mockRejectedValue(new Error(syntheticSensitiveText))
    expect(await call('save_mcp_source_draft', sourceDraft)).toMatchObject({ ok: false, error: { code: 'request_failed' } })
    expect(api.saveSourceDraft).toHaveBeenCalledTimes(1)
    expect(refresh).toHaveBeenCalledTimes(1)
  })

  it('does not turn a successful mutation into failure when the separate UI refresh fails', async () => {
    const refresh = vi.fn(async () => { throw new Error(syntheticSensitiveText) })
    const { api, call, sources } = fixture(true, refresh)
    expect(await call('save_mcp_source_draft', sourceDraft)).toEqual({ ok: true, result: sources })
    expect(api.saveSourceDraft).toHaveBeenCalledTimes(1)
    expect(refresh).toHaveBeenCalledTimes(1)
  })

  it('returns the mutation result even when its observational refresh never settles', async () => {
    const refresh = vi.fn(() => new Promise<void>(() => {}))
    const { api, call, sources } = fixture(true, refresh)
    expect(await call('save_mcp_source_draft', sourceDraft)).toEqual({ ok: true, result: sources })
    expect(api.saveSourceDraft).toHaveBeenCalledTimes(1)
    expect(refresh).toHaveBeenCalledTimes(1)
  })

  it('does not refresh or call the API for invalid or already-cancelled mutation input', async () => {
    const refresh = vi.fn(async () => {})
    const { api, call } = fixture(true, refresh)
    expect(await call('save_mcp_source_draft', { token: syntheticSensitiveText })).toMatchObject({ ok: false, error: { code: 'webmcp_input_invalid' } })
    const controller = new AbortController()
    controller.abort()
    expect(await call('save_mcp_source_draft', sourceDraft, controller.signal)).toMatchObject({ ok: false, error: { code: 'webmcp_call_cancelled' } })
    expectNoApiCalls(api)
    expect(refresh).not.toHaveBeenCalled()
  })

  it('does not invalidate a human draft for read-only state or action inspection', async () => {
    const refresh = vi.fn(async () => {})
    const { api, call } = fixture(true, refresh)
    await call('get_gateway_team')
    expect(refresh).not.toHaveBeenCalled()
    await call('get_mcp_source_action', { actionId })
    expect(api.getSourceAction).toHaveBeenCalledExactlyOnceWith(actionId)
    expect(refresh).not.toHaveBeenCalled()
  })

  it('offers exactly nineteen non-generic tools when installation is enabled', () => {
    const { tools } = fixture()
    expect(tools.map((tool) => tool.name).sort()).toEqual([...names].sort())
    expect(new Set(tools.map((tool) => tool.name)).size).toBe(19)
    for (const tool of tools) {
      expect(tool.inputSchema.additionalProperties).toBe(false)
      for (const forbidden of ['token', 'headers', 'accountId', 'apiPath', 'actor', 'role', 'credential']) {
        expect(Object.keys(tool.inputSchema.properties)).not.toContain(forbidden)
      }
      expect(tool.description).not.toMatch(/\bcustomer[s]?\b/iu)
    }
  })

  it('does not label immediate writes or action preparation as read-only or idempotent', () => {
    const { tool } = fixture()
    for (const name of ['cancel_gateway_team_action', 'cancel_mcp_source_action', 'save_mcp_source_draft', 'apply_mcp_source', 'apply_gateway_update', 'rollback_gateway_update', 'review_gateway_teardown']) {
      expect(tool(name).annotations).toMatchObject({ readOnlyHint: false, idempotentHint: false })
    }
    for (const name of ['rollback_gateway_update', 'review_gateway_teardown']) {
      expect(tool(name).annotations.destructiveHint).toBe(true)
    }
    for (const name of ['get_gateway_status', 'get_gateway_capabilities', 'get_gateway_team', 'get_gateway_team_action', 'get_mcp_source_action', 'list_mcp_source_actions', 'get_gateway_runtime_action', 'get_gateway_teardown_action', 'review_gateway_update']) {
      expect(tool(name).annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false })
    }
  })

  it.each(noInputNames)('%s rejects unexpected arguments before any request', async (name) => {
    const { api, call } = fixture()
    const result = await call(name, { token: syntheticSensitiveText })
    expect(result).toMatchObject({ ok: false, error: { code: 'webmcp_input_invalid' } })
    expect(JSON.stringify(result)).not.toContain(syntheticSensitiveText)
    expectNoApiCalls(api)
  })

  it('reports compact current capabilities without exposing the roster or claiming health', async () => {
    const { api, call, team, sources } = fixture()
    api.getSources.mockResolvedValue({ ...sources, installationEnabled: false, revision: 19 })
    api.getTeam.mockResolvedValue({ ...team, revision: 21 })
    const result = await call('get_gateway_capabilities')
    expect(result).toMatchObject({ ok: true, result: {
      sourceInstallation: { available: false, reason: 'source_addition_paused', revision: 19 },
      team: {
        editingEnabled: false,
        editingDisabledReason: 'managed_in_cloudflare',
        management: 'cloudflare_dashboard',
        revision: 21,
        pendingAction: null,
      },
      runtimeActions: { authorization: 'fresh_cloudflare_oauth' },
      sourceAuthenticationManagement: { available: false },
      installedSourceAllowlistEditing: { available: false },
      dataCapabilityMode: 'read_only',
    } })
    expect(JSON.stringify(result)).not.toContain('operator@example.com')
    expect(JSON.stringify(result)).not.toContain('teammate@example.com')
    expect(api.prepareTeamAction).not.toHaveBeenCalled()
  })
})

describe('exact signed runtime target', () => {
  it.each([
    { name: 'apply_gateway_update', operation: 'update', release: 'gateway-v1.0.1', artifactSha256: nextDigest },
    { name: 'rollback_gateway_update', operation: 'rollback', release: 'gateway-v0.9.9', artifactSha256: previousDigest },
  ])('$name binds both reviewed values through expectedTarget', async ({ name, operation, release, artifactSha256 }) => {
    const { api, call, prepared } = fixture()
    expect(await call(name, { approvedRelease: release, approvedArtifactSha256: artifactSha256 })).toEqual({ ok: true, result: {
      status: 'user_authorization_required', authorizationUrl: prepared.handoffUrl, actionId, expiresAt,
    } })
    expect(api.prepareRuntimeAction).toHaveBeenCalledExactlyOnceWith(operation, { release, artifactSha256 })
  })

  it.each(['apply_gateway_update', 'rollback_gateway_update'])('%s requires a valid digest and rejects extra arguments', async (name) => {
    for (const input of [
      { approvedRelease: 'gateway-v1.0.1' },
      { approvedRelease: 'gateway-v1.0.1', approvedArtifactSha256: 'not-a-digest' },
      { approvedRelease: 'gateway-v1.0.1', approvedArtifactSha256: nextDigest, force: true },
      { approvedRelease: 'gateway-v01.0.1', approvedArtifactSha256: nextDigest },
    ]) {
      const { api, call } = fixture()
      expect(await call(name, input)).toMatchObject({ ok: false, error: { code: 'webmcp_input_invalid' } })
      expectNoApiCalls(api)
    }
  })

  it.each([
    { name: 'apply_gateway_update', release: 'gateway-v1.0.2', artifactSha256: nextDigest },
    { name: 'apply_gateway_update', release: 'gateway-v1.0.1', artifactSha256: digest },
    { name: 'rollback_gateway_update', release: 'gateway-v1.0.0', artifactSha256: previousDigest },
    { name: 'rollback_gateway_update', release: 'gateway-v0.9.9', artifactSha256: nextDigest },
  ])('rejects mismatched release or artifact for $name', async ({ name, release, artifactSha256 }) => {
    const { api, call } = fixture()
    expect(await call(name, { approvedRelease: release, approvedArtifactSha256: artifactSha256 })).toMatchObject({ ok: false, error: { code: 'runtime_action_conflict' } })
    expect(api.prepareRuntimeAction).not.toHaveBeenCalled()
    expect(api.getStatus).not.toHaveBeenCalled()
  })

  it.each(['up_to_date', 'newer_than_channel', 'unavailable'] as const)('does not prepare an update when its current status is %s', async (status) => {
    const { api, call, update } = fixture()
    api.getUpdate.mockResolvedValue({ ...update, status })
    expect(await call('apply_gateway_update', { approvedRelease: 'gateway-v1.0.1', approvedArtifactSha256: nextDigest })).toMatchObject({ ok: false, error: { code: 'runtime_action_conflict' } })
    expect(api.prepareRuntimeAction).not.toHaveBeenCalled()
  })

  it('does not prepare an unavailable rollback', async () => {
    const { api, call, update } = fixture()
    api.getUpdate.mockResolvedValue({ ...update, rollback: { available: false } })
    expect(await call('rollback_gateway_update', { approvedRelease: 'gateway-v0.9.9', approvedArtifactSha256: previousDigest })).toMatchObject({ ok: false, error: { code: 'runtime_action_conflict' } })
    expect(api.prepareRuntimeAction).not.toHaveBeenCalled()
  })

  it('preserves a server-side target conflict after the last read without retrying or replacing approval', async () => {
    const { api, call } = fixture()
    api.prepareRuntimeAction.mockRejectedValue(new GatewayApiError(409, 'runtime_action_conflict'))
    expect(await call('apply_gateway_update', { approvedRelease: 'gateway-v1.0.1', approvedArtifactSha256: nextDigest })).toMatchObject({ ok: false, error: { code: 'runtime_action_conflict' } })
    expect(api.prepareRuntimeAction).toHaveBeenCalledExactlyOnceWith('update', { release: 'gateway-v1.0.1', artifactSha256: nextDigest })
  })
})

describe('source pause and current state', () => {
  function recordedAction(state: SourceActions['actions'][number]['state'], canCancel = false): SourceActions {
    return { schemaVersion: 1, blockingAction: state === 'succeeded' || state === 'failed' ? null : { kind: 'source', actionId, sourceId }, actions: [{
      schemaVersion: 1, actionId, sourceId, issuedAt: '2030-01-01T00:00:00.000Z', expiresAt,
      status: state === 'authorization_expired' ? 'authorization_required' : state,
      state, canCancel, failureCode: state === 'recovery_required' ? 'source_action_recovery_required' : null,
    }] }
  }

  it('discovers pending actions without a saved handoff and exposes safe capabilities', async () => {
    const refresh = vi.fn(async () => {})
    const { api, call } = fixture(true, refresh)
    const snapshot = recordedAction('authorization_required', true)
    api.getSourceActions.mockResolvedValue(snapshot)
    expect(await call('list_mcp_source_actions')).toEqual({ ok: true, result: snapshot })
    expect(await call('get_gateway_capabilities')).toMatchObject({ ok: true, result: { sourceInstallation: {
      available: false, reason: 'source_action_conflict', blockingAction: snapshot.blockingAction, statusTool: 'list_mcp_source_actions',
    } } })
    expect(refresh).not.toHaveBeenCalled()
    expect(api.prepareSourceAction).not.toHaveBeenCalled()
  })

  it.each(['authorization_required', 'authorization_expired', 'applying', 'recovery_required'] as const)('does not prepare a second action while %s', async (state) => {
    const { api, call, sources } = fixture()
    api.getSources.mockResolvedValue({ ...sources, sources: sources.sources.map((source) => ({ ...source, status: 'draft' })) })
    const snapshot = recordedAction(state, state === 'authorization_required' || state === 'authorization_expired')
    api.getSourceActions.mockResolvedValue(snapshot)
    expect(await call('apply_mcp_source', { sourceId })).toMatchObject({ ok: false, error: {
      code: 'source_action_conflict', reason: state === 'recovery_required' ? 'recovery_required' : 'source_pending', action: snapshot.blockingAction,
    } })
    expect(api.prepareSourceAction).not.toHaveBeenCalled()
    expect(api.getStatus).not.toHaveBeenCalled()
  })

  it('returns Installed after late success without preparing another authorization', async () => {
    const { api, call } = fixture()
    expect(await call('apply_mcp_source', { sourceId })).toEqual({ ok: true, result: { status: 'installed', sourceId } })
    expect(api.prepareSourceAction).not.toHaveBeenCalled()
  })

  it.each(['runtime', 'teardown', 'team'] as const)('identifies an unrelated %s action without starting source consent', async (kind) => {
    const { api, call, sources } = fixture()
    api.getSources.mockResolvedValue({ ...sources, sources: sources.sources.map((source) => ({ ...source, status: 'draft' })) })
    api.getSourceActions.mockResolvedValue({ schemaVersion: 1, actions: [], blockingAction: { kind, actionId: otherActionId } })
    expect(await call('apply_mcp_source', { sourceId })).toMatchObject({ ok: false, error: {
      code: 'source_action_conflict', reason: 'lifecycle_pending', action: { kind, actionId: otherActionId },
    } })
    expect(api.prepareSourceAction).not.toHaveBeenCalled()
  })

  it('preserves a stale revision rejection after the status read, without retrying', async () => {
    const { api, call, sources } = fixture()
    api.getSources.mockResolvedValue({ ...sources, sources: sources.sources.map((source) => ({ ...source, status: 'draft' })) })
    api.prepareSourceAction.mockRejectedValue(new GatewayApiError(409, 'source_action_conflict', { reason: 'draft_changed' }))
    expect(await call('apply_mcp_source', { sourceId })).toMatchObject({ ok: false, error: {
      reason: 'draft_changed', message: expect.stringContaining('draft changed'),
    } })
    expect(api.prepareSourceAction).toHaveBeenCalledTimes(1)
  })

  it('cancels a proven-unstarted expired action only after the current server capability permits it', async () => {
    const { api, call } = fixture()
    api.getSourceActions.mockResolvedValue(recordedAction('authorization_expired', true))
    expect(await call('cancel_mcp_source_action', { actionId })).toMatchObject({ ok: true, result: { status: 'failed' } })
    expect(api.getSourceActions).toHaveBeenCalledTimes(1)
    expect(api.cancelSourceAction).toHaveBeenCalledExactlyOnceWith(actionId)
    expect(api.prepareSourceAction).not.toHaveBeenCalled()
  })

  it.each(['authorization_required', 'applying', 'recovery_required', 'succeeded'] as const)('does not cancel %s without server permission', async (state) => {
    const { api, call } = fixture()
    api.getSourceActions.mockResolvedValue(recordedAction(state))
    expect(await call('cancel_mcp_source_action', { actionId })).toMatchObject({ ok: false, error: { code: 'source_action_conflict' } })
    expect(api.cancelSourceAction).not.toHaveBeenCalled()
    expect(api.prepareSourceAction).not.toHaveBeenCalled()
  })

  it('discloses source grants and lifecycle restrictions before agent actions', () => {
    const { tool, api } = fixture()
    expect(tool('apply_mcp_source').description).toContain('denied to everyone')
    expect(tool('apply_mcp_source').description).toContain('explicit Team grant')
    expect(tool('apply_mcp_source').description).toContain('preparation alone does not')
    expect(tool('apply_mcp_source').description).toContain('disables automatic teardown')
    expect(tool('apply_mcp_source').description).toContain('blocks older-runtime rollback')
    expectNoApiCalls(api)
  })

  it('omits source writes when installation is disabled', () => {
    const { tools, api } = fixture(false)
    expect(tools.map((tool) => tool.name).sort()).toEqual(names.filter((name) => !['save_mcp_source_draft', 'apply_mcp_source'].includes(name)).sort())
    expectNoApiCalls(api)
  })

  it.each(['save_mcp_source_draft', 'apply_mcp_source'])('%s rechecks the pause at call time', async (name) => {
    const { api, call, sources } = fixture()
    api.getSources.mockResolvedValue({ ...sources, installationEnabled: false })
    expect(await call(name, name === 'apply_mcp_source' ? { sourceId } : sourceDraft)).toMatchObject({ ok: false, error: { code: 'source_addition_paused' } })
    expect(api.prepareSourceAction).not.toHaveBeenCalled()
    expect(api.saveSourceDraft).not.toHaveBeenCalled()
    expect(api.getStatus).not.toHaveBeenCalled()
  })

  it('uses the fresh source revision for a draft and never changes the live Portal directly', async () => {
    const { api, call, sources } = fixture()
    api.getSources.mockResolvedValue({ ...sources, revision: 12 })
    expect(await call('save_mcp_source_draft', sourceDraft)).toMatchObject({ ok: true })
    expect(api.saveSourceDraft).toHaveBeenCalledExactlyOnceWith(12, sourceDraft)
    expect(api.prepareSourceAction).not.toHaveBeenCalled()
  })

  it('uses the fresh source revision for an exact draft handoff', async () => {
    const { api, call, sources } = fixture()
    api.getSources.mockResolvedValue({ ...sources, revision: 13, sources: sources.sources.map((source) => ({ ...source, status: 'draft' })) })
    expect(await call('apply_mcp_source', { sourceId })).toMatchObject({ ok: true, result: { actionId } })
    expect(api.prepareSourceAction).toHaveBeenCalledExactlyOnceWith(13, sourceId)
  })

  it('rejects unknown source write arguments and duplicate tool names before requests', async () => {
    for (const input of [{ ...sourceDraft, token: syntheticSensitiveText }, { ...sourceDraft, enabledTools: ['search', 'search'] }]) {
      const { api, call } = fixture()
      expect(await call('save_mcp_source_draft', input)).toMatchObject({ ok: false, error: { code: 'webmcp_input_invalid' } })
      expectNoApiCalls(api)
    }
  })
})

describe('recorded actions and cancellation', () => {
  it.each(actionNames)('%s rejects malformed identifiers and extra arguments', async (name) => {
    for (const input of [{ actionId: '../other' }, { actionId: `action_${'a'.repeat(31)}` }, { actionId, token: syntheticSensitiveText }]) {
      const { api, call } = fixture()
      expect(await call(name, input)).toMatchObject({ ok: false, error: { code: 'webmcp_input_invalid' } })
      expectNoApiCalls(api)
    }
  })

  it.each([
    { name: 'get_gateway_team_action', method: 'getTeamAction' as const },
    { name: 'get_mcp_source_action', method: 'getSourceAction' as const },
    { name: 'get_gateway_runtime_action', method: 'getRuntimeAction' as const },
    { name: 'get_gateway_teardown_action', method: 'getTeardownAction' as const },
  ])('$name reads only its existing action', async ({ name, method }) => {
    const { api, call } = fixture()
    expect(await call(name, { actionId })).toMatchObject({ ok: true, result: { actionId } })
    expect(api[method]).toHaveBeenCalledExactlyOnceWith(actionId)
    for (const [apiName, fn] of Object.entries(api)) if (apiName !== method) expect(fn).not.toHaveBeenCalled()
  })

  it('cancels only the exact action explicitly marked cancelable and preserves canceled history', async () => {
    const { api, call } = fixture()
    expect(await call('cancel_gateway_team_action', { actionId })).toMatchObject({ ok: true, result: { actionId, status: 'failed', failureCode: 'team_action_cancelled' } })
    expect(api.getTeamAction).toHaveBeenCalledExactlyOnceWith(actionId)
    expect(api.cancelTeamAction).toHaveBeenCalledExactlyOnceWith(actionId)
    expect(api.prepareTeamAction).not.toHaveBeenCalled()
  })

  it.each([
    { status: 'applying' as const, canCancel: false },
    { status: 'recovery_required' as const, canCancel: false },
    { status: 'authorization_required' as const, canCancel: false },
    { actionId: otherActionId, canCancel: true },
  ])('does not cancel a noncancelable or mismatched Team action: %j', async (changes) => {
    const { api, call, teamAction } = fixture()
    api.getTeamAction.mockResolvedValue({ ...teamAction, ...changes })
    expect(await call('cancel_gateway_team_action', { actionId })).toMatchObject({ ok: false, error: { code: 'team_action_conflict' } })
    expect(api.cancelTeamAction).not.toHaveBeenCalled()
  })

  it('does not hide a cancellation conflict discovered by the server after a safe read', async () => {
    const { api, call } = fixture()
    api.cancelTeamAction.mockRejectedValue(new GatewayApiError(409, 'team_action_conflict'))
    expect(await call('cancel_gateway_team_action', { actionId })).toMatchObject({ ok: false, error: { code: 'team_action_conflict' } })
    expect(api.cancelTeamAction).toHaveBeenCalledTimes(1)
    expect(api.prepareTeamAction).not.toHaveBeenCalled()
  })

  it('uses only the normal source cancellation API and preserves server denial', async () => {
    const { api, call, sourceAction } = fixture()
    api.getSourceActions.mockResolvedValue({ schemaVersion: 1, actions: [{
      ...sourceAction, status: 'authorization_required', state: 'authorization_required',
      issuedAt: '2030-01-01T00:00:00.000Z', canCancel: true,
    }], blockingAction: { kind: 'source', actionId, sourceId } })
    api.cancelSourceAction.mockRejectedValue(new GatewayApiError(409, 'source_action_conflict'))
    expect(await call('cancel_mcp_source_action', { actionId })).toMatchObject({ ok: false, error: { code: 'source_action_conflict' } })
    expect(api.cancelSourceAction).toHaveBeenCalledExactlyOnceWith(actionId)
    expect(api.prepareSourceAction).not.toHaveBeenCalled()
  })
})

describe('safe errors and verified handoffs', () => {
  it.each(['unknown', 'synchronous', 'asynchronous', 'api-unknown', 'api-known'] as const)('sanitizes %s failures without exposing error text or input', async (kind) => {
    const { api, tool } = fixture()
    if (kind === 'unknown') api.getStatus.mockImplementation(() => { throw { detail: syntheticSensitiveText } })
    if (kind === 'synchronous') api.getStatus.mockImplementation(() => { throw new Error(syntheticSensitiveText) })
    if (kind === 'asynchronous') api.getStatus.mockRejectedValue(new Error(syntheticSensitiveText))
    if (kind === 'api-unknown') api.getStatus.mockRejectedValue(new GatewayApiError(500, syntheticSensitiveText))
    if (kind === 'api-known') {
      const error = new GatewayApiError(401, 'access_required')
      error.message = syntheticSensitiveText
      api.getStatus.mockRejectedValue(error)
    }
    const response = await tool('get_gateway_status').execute({})
    expect(response).not.toContain(syntheticSensitiveText)
    expect(JSON.parse(response)).toMatchObject({ ok: false, error: { code: kind === 'api-known' ? 'access_required' : 'request_failed' } })
  })

  it('does not leak synchronous validation issues, stack traces, or supplied arguments', async () => {
    const { api, tool } = fixture()
    const response = await tool('save_mcp_source_draft').execute({ ...sourceDraft, token: syntheticSensitiveText })
    expect(JSON.parse(response)).toMatchObject({ ok: false, error: { code: 'webmcp_input_invalid' } })
    expect(response).not.toContain(syntheticSensitiveText)
    expect(response).not.toContain('stack')
    expectNoApiCalls(api)
  })

  it.each([
    `https://other.example.com/__ankka/operation#${'x'.repeat(40)}`,
    `https://deploy.ankka.ai/__ankka/operation#${'x'.repeat(40)}`,
    `${window.location.origin}/other#${'x'.repeat(40)}`,
    `${window.location.origin}/manage#${'x'.repeat(40)}`,
    `${window.location.origin}/__ankka/operation?token=${syntheticSensitiveText}#${'x'.repeat(40)}`,
    `${window.location.protocol}//operator:${syntheticSensitiveText}@${window.location.host}/__ankka/operation#${'x'.repeat(40)}`,
    `${window.location.origin}/__ankka/operation#short`,
  ])('refuses an invalid handoff without exposing it: %s', async (handoffUrl) => {
    const { api, tool, prepared } = fixture()
    api.prepareTeardownAction.mockResolvedValue({ ...prepared, handoffUrl })
    const response = await tool('review_gateway_teardown').execute({})
    expect(JSON.parse(response)).toMatchObject({ ok: false, error: { code: 'webmcp_handoff_invalid' } })
    expect(response).not.toContain(handoffUrl)
    expect(response).not.toContain(syntheticSensitiveText)
    expect(api.prepareTeardownAction).toHaveBeenCalledTimes(1)
  })

  it('refuses a malformed returned action ID after preparation and reports an unknown outcome safely', async () => {
    const { api, call, prepared } = fixture()
    api.prepareTeardownAction.mockResolvedValue({ ...prepared, actionId: '../untrusted-action' })
    expect(await call('review_gateway_teardown')).toMatchObject({ ok: false, error: { code: 'webmcp_handoff_invalid', message: expect.stringContaining('recorded action') } })
    expect(api.prepareTeardownAction).toHaveBeenCalledTimes(1)
  })

  it('returns a validated teardown review handoff without claiming deletion', async () => {
    const { api, call, prepared } = fixture()
    expect(await call('review_gateway_teardown')).toEqual({ ok: true, result: {
      status: 'user_review_required', authorizationUrl: prepared.handoffUrl,
      actionId, expiresAt, instruction: expect.stringContaining('never request or handle their token'),
    } })
    expect(api.prepareTeardownAction).toHaveBeenCalledTimes(1)
    expect(api.getTeardownAction).not.toHaveBeenCalled()
  })
})

describe('browser cancellation is not durable rollback', () => {
  it('rejects every pre-aborted execution before validation or API access', async () => {
    const { api, tools } = fixture()
    const controller = new AbortController()
    controller.abort()
    for (const tool of tools) {
      expect(JSON.parse(await tool.execute({}, { signal: controller.signal }))).toMatchObject({ ok: false, error: { code: 'webmcp_call_cancelled' } })
    }
    expectNoApiCalls(api)
  })

  it('does not pretend an in-flight durable source-draft write was canceled when its browser call aborts', async () => {
    const { api, tool, sources } = fixture()
    const controller = new AbortController()
    let complete: (result: ManagedSources) => void = () => { throw new Error('Synthetic operation not started') }
    api.saveSourceDraft.mockImplementation(() => new Promise<ManagedSources>((resolve) => { complete = resolve }))
    const pending = tool('save_mcp_source_draft').execute(sourceDraft, { signal: controller.signal })
    await vi.waitFor(() => expect(api.saveSourceDraft).toHaveBeenCalledTimes(1))
    controller.abort()
    complete(sources)
    expect(JSON.parse(await pending)).toEqual({ ok: true, result: sources })
    expect(api.cancelSourceAction).not.toHaveBeenCalled()
    expect(api.saveSourceDraft).toHaveBeenCalledTimes(1)
  })
})
