import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { GatewayApiError, SOURCE_ADDITION_PAUSED_MESSAGE, type GatewayAdminApi, type GatewayStatus, type ManagedSources, type RuntimeUpdate, type SourceActions, type SourceActionSummary, type TeamActionResult } from './api'
import { GatewayProvider, useGateway } from './GatewayContext'

const status: GatewayStatus = {
  schemaVersion: 1,
  status: 'ready',
  controlPlaneOrigin: 'https://deploy.ankka.ai',
  release: 'gateway-v1.0.0',
  gateway: { name: 'Example Gateway', hostname: 'mcp.example.com', mcpUrl: 'https://mcp.example.com/mcp', capabilityMode: 'read_only', codeMode: 'default_on' },
  source: null,
  access: { administratorCount: 1, memberCount: 2 },
  updatedAt: '2026-08-27T12:00:00.000Z',
}
const sources: ManagedSources = { schemaVersion: 1, revision: 7, applyMode: 'oauth_per_action', installationEnabled: true, sources: [] }
const update: RuntimeUpdate = { schemaVersion: 1, channel: 'stable', status: 'up_to_date', current: { release: 'gateway-v1.0.0', artifactSha256: 'a'.repeat(64) }, available: null, rollback: { available: false } }
const emptyActions: SourceActions = { schemaVersion: 1, actions: [], blockingAction: null }
const pendingAction: SourceActionSummary = {
  schemaVersion: 1, actionId: `action_${'a'.repeat(32)}`, sourceId: 'source-1111111111111111',
  status: 'authorization_required', state: 'authorization_required',
  issuedAt: '2026-08-31T12:00:00.000Z', expiresAt: '2026-08-31T12:15:00.000Z', failureCode: null, canCancel: true,
}
const pendingActions: SourceActions = {
  schemaVersion: 1, actions: [pendingAction],
  blockingAction: { kind: 'source', actionId: pendingAction.actionId, sourceId: pendingAction.sourceId },
}
const installedSources: ManagedSources = {
  ...sources, revision: 8, sources: [{ id: pendingAction.sourceId, label: 'Knowledge', url: 'https://knowledge.example.com/mcp',
    authMode: 'none', onBehalfOfUser: false, enabledTools: ['search'], status: 'installed' }],
}

function api(overrides: Partial<GatewayAdminApi> = {}): GatewayAdminApi {
  return {
    getStatus: vi.fn(async () => status),
    getSources: vi.fn(async () => sources),
    getTeam: vi.fn(), prepareTeamAction: vi.fn(), getTeamAction: vi.fn(), cancelTeamAction: vi.fn(),
    getUpdate: vi.fn(async () => update),
    discoverSource: vi.fn(),
    saveSourceDraft: vi.fn(async () => ({ ...sources, revision: 8 })),
    prepareSourceAction: vi.fn(),
    getSourceActions: vi.fn(async () => emptyActions),
    getSourceAction: vi.fn(),
    cancelSourceAction: vi.fn(),
    prepareRuntimeAction: vi.fn(),
    getRuntimeAction: vi.fn(),
    prepareTeardownAction: vi.fn(),
    getTeardownAction: vi.fn(),
    ...overrides,
  }
}

function Probe() {
  const { hasLoaded, isLoading, status: current, sources: currentSources } = useGateway()
  return <div><span>{isLoading ? 'loading' : 'settled'}</span><span>{hasLoaded ? 'loaded' : 'not loaded'}</span><span>{current?.gateway.name ?? 'no gateway'}</span><span>{currentSources?.sources.length ?? 0} sources</span></div>
}

function SaveProbe() {
  const { saveSourceDraft, sources: current } = useGateway()
  return <div><span>{current?.revision ?? 'no revision'}</span><button type="button" onClick={() => void saveSourceDraft({ label: 'Knowledge', url: 'https://knowledge.example.com/mcp', authMode: 'none', enabledTools: ['search'] })}>Save</button></div>
}

function ExternalRefreshProbe() {
  const { refreshAfterExternalChange, error } = useGateway()
  return <div><button type="button" onClick={() => { void refreshAfterExternalChange() }}>External refresh</button><span>{error}</span></div>
}

function PausedSourceProbe() {
  const { saveSourceDraft, prepareSourceApply, sourceNotice, error, hasLoaded } = useGateway()
  return <div>
    <span>{hasLoaded ? 'ready' : 'loading'}</span><span>{sourceNotice?.message}</span><span>{error}</span>
    <button type="button" onClick={() => { void saveSourceDraft({ label: 'Knowledge', url: 'https://knowledge.example.com/mcp', authMode: 'none', enabledTools: ['search'] }).catch(() => {}) }}>Save blocked draft</button>
    <button type="button" onClick={() => { void prepareSourceApply('source-1111111111111111').catch(() => {}) }}>Prepare blocked source</button>
  </div>
}

function TeamSaveProbe() {
  const { prepareTeamAction } = useGateway()
  const [result, setResult] = useState('unsaved')
  return <div>
    <span>{result}</span>
    <button type="button" onClick={() => {
      void prepareTeamAction(7, [{ email: 'admin@example.com', sourceIds: [] }]).then((value) => setResult(value.action.status)).catch(() => setResult('failed'))
    }}>Save Team</button>
  </div>
}

function SourceActionsProbe() {
  const { sourceActions, sourceActionsError, isCheckingSourceActions, sourceActionsPollingPaused,
    refreshSourceActions, prepareSourceApply, cancelSourceApply, sources: currentSources, error } = useGateway()
  return <div>
    <span>{sourceActions?.blockingAction?.actionId ?? 'no blocker'}</span>
    <span>{sourceActions?.actions[0]?.state ?? 'no action'}</span>
    <span>{sourceActions?.actions[0]?.canCancel ? 'can cancel' : 'cannot cancel'}</span>
    <span>{isCheckingSourceActions ? 'checking' : 'not checking'}</span>
    <span>{sourceActionsPollingPaused ? 'polling paused' : 'polling active'}</span>
    <span>{currentSources?.sources[0]?.status ?? 'no installed source'}</span>
    <span>{sourceActionsError}</span><span>{error}</span>
    <button type="button" onClick={() => { void refreshSourceActions().catch(() => {}) }}>Check status</button>
    <button type="button" onClick={() => { void prepareSourceApply(pendingAction.sourceId).catch(() => {}) }}>Prepare source</button>
    <button type="button" onClick={() => { void cancelSourceApply(pendingAction.actionId).catch(() => {}) }}>Cancel authorization</button>
  </div>
}

describe('GatewayProvider', () => {
  afterEach(() => { cleanup(); vi.useRealTimers(); window.history.replaceState(null, '', '/') })
  it('hydrates the production status, source, and update contracts', async () => {
    const client = api()
    render(<GatewayProvider api={client}><Probe /></GatewayProvider>)
    expect(screen.getByText('loading')).toBeInTheDocument()
    expect(await screen.findByText('Example Gateway')).toBeInTheDocument()
    expect(screen.getByText('loaded')).toBeInTheDocument()
    expect(screen.getByText('0 sources')).toBeInTheDocument()
    expect(client.getStatus).toHaveBeenCalledTimes(1)
    expect(client.getSources).toHaveBeenCalledTimes(1)
    expect(client.getUpdate).toHaveBeenCalledTimes(1)
    expect(client.getSourceActions).toHaveBeenCalledTimes(1)
  })

  it('saves against the hydrated customer-owned source revision', async () => {
    const user = userEvent.setup()
    const saveSourceDraft = vi.fn(async () => ({ ...sources, revision: 8 }))
    render(<GatewayProvider api={api({ saveSourceDraft })}><SaveProbe /></GatewayProvider>)
    expect(await screen.findByText('7')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('8')).toBeInTheDocument()
    expect(saveSourceDraft).toHaveBeenCalledWith(7, expect.objectContaining({ label: 'Knowledge' }))
  })

  it('does not replace a newer saved source revision with an older delayed reload', async () => {
    const user = userEvent.setup()
    let resolveRead: (value: ManagedSources) => void = () => { throw new Error('Read not initialized') }
    const staleRead = new Promise<ManagedSources>((resolve) => { resolveRead = resolve })
    const getSources = vi.fn<GatewayAdminApi['getSources']>().mockResolvedValueOnce(sources).mockImplementationOnce(() => staleRead)
    const client = api({ getSources })
    render(<GatewayProvider api={client}><SaveProbe /><ExternalRefreshProbe /></GatewayProvider>)
    await screen.findByText('7')
    await user.click(screen.getByRole('button', { name: 'External refresh' }))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await screen.findByText('8')
    await act(async () => { resolveRead(sources) })
    expect(screen.getByText('8')).toBeVisible()
    expect(screen.queryByText('7')).not.toBeInTheDocument()
    expect(client.saveSourceDraft).toHaveBeenCalledTimes(1)
  })

  it('surfaces an observational refresh failure in the existing dashboard error state', async () => {
    const user = userEvent.setup()
    const client = api({ getSources: vi.fn<GatewayAdminApi['getSources']>().mockResolvedValueOnce(sources).mockRejectedValueOnce(new Error('Saved sources could not be refreshed.')) })
    render(<GatewayProvider api={client}><Probe /><ExternalRefreshProbe /></GatewayProvider>)
    await screen.findByText('loaded')
    await user.click(screen.getByRole('button', { name: 'External refresh' }))
    expect(await screen.findByText('Saved sources could not be refreshed.')).toBeVisible()
    expect(client.saveSourceDraft).not.toHaveBeenCalled()
  })

  it('saves Team locally without requiring a control-plane origin or hosted authorization', async () => {
    const user = userEvent.setup()
    const prepareTeamAction = vi.fn(async (): Promise<TeamActionResult> => ({ schemaVersion: 1, action: {
      schemaVersion: 1, actionId: `action_${'a'.repeat(32)}`, status: 'succeeded', expiresAt: '2030-01-01T00:00:00.000Z', failureCode: null, canCancel: false,
    } }))
    const client = api({ getStatus: vi.fn().mockRejectedValue(new Error('Status unavailable')), prepareTeamAction })
    render(<GatewayProvider api={client}><Probe /><TeamSaveProbe /></GatewayProvider>)
    await screen.findByText('settled')
    await user.click(screen.getByRole('button', { name: 'Save Team' }))
    expect(await screen.findByText('succeeded')).toBeInTheDocument()
    expect(prepareTeamAction).toHaveBeenCalledExactlyOnceWith(7, [{ email: 'admin@example.com', sourceIds: [] }])
    expect(client.getStatus).toHaveBeenCalledTimes(1)
    expect(client.prepareSourceAction).not.toHaveBeenCalled()
    expect(client.prepareRuntimeAction).not.toHaveBeenCalled()
  })

  it('blocks programmatic draft save and authorization before either API request when source addition is paused', async () => {
    const user = userEvent.setup()
    const client = api({ getSources: vi.fn(async () => ({ ...sources, installationEnabled: false })) })
    render(<GatewayProvider api={client}><PausedSourceProbe /></GatewayProvider>)
    await screen.findByText('ready')
    await user.click(screen.getByRole('button', { name: 'Save blocked draft' }))
    expect(await screen.findByText(SOURCE_ADDITION_PAUSED_MESSAGE)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Prepare blocked source' }))
    expect(client.saveSourceDraft).not.toHaveBeenCalled()
    expect(client.prepareSourceAction).not.toHaveBeenCalled()
  })

  it('explains the pause for a retained callback without telling people to authorize again', async () => {
    const actionId = `action_${'a'.repeat(32)}`
    window.history.replaceState(null, '', `/sources?sourceAction=${actionId}`)
    const client = api({
      getSources: vi.fn(async () => ({ ...sources, installationEnabled: false })),
      getSourceActions: vi.fn(async () => pendingActions),
    })
    render(<GatewayProvider api={client}><PausedSourceProbe /></GatewayProvider>)
    expect(await screen.findByText(SOURCE_ADDITION_PAUSED_MESSAGE)).toBeInTheDocument()
    expect(client.getSourceActions).toHaveBeenCalledTimes(1)
    expect(client.getSourceAction).not.toHaveBeenCalled()
    expect(client.prepareSourceAction).not.toHaveBeenCalled()
  })

  it('rediscovers slow consent without a callback URL after remount and rejects duplicate preparation', async () => {
    const client = api({ getSourceActions: vi.fn(async () => pendingActions) })
    const firstTab = render(<GatewayProvider api={client}><SourceActionsProbe /></GatewayProvider>)
    await screen.findByText('authorization_required')
    expect(screen.getByText(pendingAction.actionId)).toBeVisible()
    firstTab.unmount()
    render(<GatewayProvider api={client}><SourceActionsProbe /></GatewayProvider>)
    await screen.findByText('authorization_required')
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Prepare source' })) })
    expect(screen.getByText(/A source installation is already pending/)).toBeVisible()
    expect(client.prepareSourceAction).not.toHaveBeenCalled()
    expect(client.getSourceAction).not.toHaveBeenCalled()
    expect(client.getSourceActions).toHaveBeenCalledTimes(3)
  })

  it('discovers preparation in another tab when focus returns, and removes listeners on unmount', async () => {
    const getSourceActions = vi.fn<GatewayAdminApi['getSourceActions']>()
      .mockResolvedValueOnce(emptyActions).mockResolvedValue(pendingActions)
    const mounted = render(<GatewayProvider api={api({ getSourceActions })}><SourceActionsProbe /></GatewayProvider>)
    await screen.findByText('not checking')
    await act(async () => { window.dispatchEvent(new Event('focus')) })
    expect(screen.getByText('authorization_required')).toBeVisible()
    await act(async () => { document.dispatchEvent(new Event('visibilitychange')) })
    expect(getSourceActions).toHaveBeenCalledTimes(3)
    mounted.unmount()
    window.dispatchEvent(new Event('focus'))
    document.dispatchEvent(new Event('visibilitychange'))
    expect(getSourceActions).toHaveBeenCalledTimes(3)
  })

  it('bounds automatic status checks without rearming on each response, and keeps manual checks available', async () => {
    vi.useFakeTimers()
    const client = api({ getSourceActions: vi.fn(async () => ({ ...pendingActions })) })
    const mounted = render(<GatewayProvider api={client}><SourceActionsProbe /></GatewayProvider>)
    await act(async () => {})
    expect(client.getSourceActions).toHaveBeenCalledTimes(1)
    for (let index = 0; index < 60; index += 1) {
      await act(async () => { await vi.advanceTimersByTimeAsync(5_000) })
    }
    expect(client.getSourceActions).toHaveBeenCalledTimes(61)
    expect(screen.getByText('polling paused')).toBeVisible()
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000) })
    expect(client.getSourceActions).toHaveBeenCalledTimes(61)
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Check status' })) })
    expect(client.getSourceActions).toHaveBeenCalledTimes(62)
    expect(screen.getByText('polling paused')).toBeVisible()
    mounted.unmount()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('does not schedule another poll after an in-flight read completes following unmount', async () => {
    vi.useFakeTimers()
    let finishRead: (value: SourceActions) => void = () => { throw new Error('Read not initialized') }
    const delayedRead = new Promise<SourceActions>((resolve) => { finishRead = resolve })
    const getSourceActions = vi.fn<GatewayAdminApi['getSourceActions']>()
      .mockResolvedValueOnce(pendingActions).mockImplementationOnce(() => delayedRead)
    const mounted = render(<GatewayProvider api={api({ getSourceActions })}><SourceActionsProbe /></GatewayProvider>)
    await act(async () => {})
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000) })
    mounted.unmount()
    await act(async () => { finishRead(pendingActions); await vi.advanceTimersByTimeAsync(30_000) })
    expect(getSourceActions).toHaveBeenCalledTimes(2)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('reconciles late success into installed sources and stops polling', async () => {
    vi.useFakeTimers()
    const succeeded: SourceActions = { ...pendingActions, blockingAction: null, actions: [{ ...pendingAction, state: 'succeeded', status: 'succeeded', canCancel: false }] }
    const client = api({
      getSourceActions: vi.fn<GatewayAdminApi['getSourceActions']>()
        .mockResolvedValueOnce(pendingActions)
        .mockResolvedValueOnce({ ...pendingActions, actions: [{ ...pendingAction, state: 'applying', status: 'applying', canCancel: false }] })
        .mockResolvedValue(succeeded),
      getSources: vi.fn<GatewayAdminApi['getSources']>().mockResolvedValueOnce(sources).mockResolvedValue(installedSources),
    })
    render(<GatewayProvider api={client}><SourceActionsProbe /></GatewayProvider>)
    await act(async () => {})
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000) })
    expect(screen.getByText('applying')).toBeVisible()
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000) })
    expect(screen.getByText('succeeded')).toBeVisible()
    expect(screen.getByText('installed')).toBeVisible()
    expect(screen.getByText('no blocker')).toBeVisible()
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
    expect(client.getSourceActions).toHaveBeenCalledTimes(3)
    expect(client.getSources).toHaveBeenCalledTimes(2)
  })

  it('does not let an older delayed action read replace a newer observed completion', async () => {
    let finishRead: (value: SourceActions) => void = () => { throw new Error('Read not initialized') }
    const delayedRead = new Promise<SourceActions>((resolve) => { finishRead = resolve })
    const succeeded: SourceActions = { ...pendingActions, blockingAction: null, actions: [{ ...pendingAction, state: 'succeeded', status: 'succeeded', canCancel: false }] }
    const getSourceActions = vi.fn<GatewayAdminApi['getSourceActions']>()
      .mockResolvedValueOnce(pendingActions).mockImplementationOnce(() => delayedRead).mockResolvedValueOnce(succeeded)
    render(<GatewayProvider api={api({ getSourceActions })}><SourceActionsProbe /></GatewayProvider>)
    await screen.findByText('authorization_required')
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Check status' })) })
    await act(async () => { window.dispatchEvent(new Event('focus')) })
    expect(screen.getByText('succeeded')).toBeVisible()
    await act(async () => { finishRead(pendingActions) })
    expect(screen.getByText('succeeded')).toBeVisible()
    expect(screen.getByText('no blocker')).toBeVisible()
  })

  it.each([
    { state: 'authorization_expired' as const, status: 'authorization_required' as const, canCancel: true },
    { state: 'recovery_required' as const, status: 'applying' as const, canCancel: false },
    { state: 'recovery_required' as const, status: 'failed' as const, canCancel: false },
  ])('preserves server expiry and recovery decisions for $state / $status without automatic cancellation', async (decision) => {
    const client = api({ getSourceActions: vi.fn(async () => ({ ...pendingActions, actions: [{ ...pendingAction, ...decision, expiresAt: '2020-01-01T00:00:00.000Z' }] })) })
    render(<GatewayProvider api={client}><SourceActionsProbe /></GatewayProvider>)
    await screen.findByText(decision.state)
    expect(screen.getByText(pendingAction.actionId)).toBeVisible()
    expect(screen.getByText(decision.canCancel ? 'can cancel' : 'cannot cancel')).toBeVisible()
    expect(client.cancelSourceAction).not.toHaveBeenCalled()
    expect(client.prepareSourceAction).not.toHaveBeenCalled()
  })

  it('cancels only through the authenticated endpoint, refreshes its result, and does not start a new action', async () => {
    const client = api({
      getSourceActions: vi.fn<GatewayAdminApi['getSourceActions']>().mockResolvedValueOnce(pendingActions).mockResolvedValue(emptyActions),
      cancelSourceAction: vi.fn(async () => ({ ...pendingAction, status: 'failed' as const })),
    })
    render(<GatewayProvider api={client}><SourceActionsProbe /></GatewayProvider>)
    await screen.findByText('authorization_required')
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Cancel authorization' })) })
    expect(client.cancelSourceAction).toHaveBeenCalledExactlyOnceWith(pendingAction.actionId)
    expect(screen.getByText('no blocker')).toBeVisible()
    expect(client.prepareSourceAction).not.toHaveBeenCalled()
  })

  it('keeps the pending journal when cancellation races with execution, including a denied callback', async () => {
    window.history.replaceState(null, '', `/sources?sourceAction=${pendingAction.actionId}&sourceActionResult=denied`)
    const applying: SourceActions = { ...pendingActions, actions: [{ ...pendingAction, state: 'applying', status: 'applying', canCancel: false }] }
    const client = api({
      getSourceActions: vi.fn(async () => applying),
      cancelSourceAction: vi.fn().mockRejectedValue(new GatewayApiError(409, 'source_action_recovery_required')),
    })
    render(<GatewayProvider api={client}><SourceActionsProbe /></GatewayProvider>)
    await screen.findByText(/Source provisioning may have started/)
    expect(screen.getByText('applying')).toBeVisible()
    expect(screen.getByText(pendingAction.actionId)).toBeVisible()
    expect(client.cancelSourceAction).toHaveBeenCalledExactlyOnceWith(pendingAction.actionId)
    expect(client.prepareSourceAction).not.toHaveBeenCalled()
    expect(window.location.search).not.toContain('sourceActionResult')
  })

  it('refreshes collection state after preparation without storing the one-time handoff', async () => {
    const client = api({
      getSourceActions: vi.fn<GatewayAdminApi['getSourceActions']>().mockResolvedValueOnce(emptyActions).mockResolvedValueOnce(emptyActions).mockResolvedValue(pendingActions),
      prepareSourceAction: vi.fn(async () => ({ schemaVersion: 1 as const, actionId: pendingAction.actionId, status: 'authorization_required' as const,
        expiresAt: pendingAction.expiresAt, handoffUrl: `https://deploy.ankka.ai/manage#${'synthetic'.repeat(8)}` })),
    })
    render(<GatewayProvider api={client}><SourceActionsProbe /></GatewayProvider>)
    await screen.findByText('not checking')
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Prepare source' })) })
    expect(screen.getByText('authorization_required')).toBeVisible()
    expect(client.prepareSourceAction).toHaveBeenCalledExactlyOnceWith(7, pendingAction.sourceId)
    expect(client.getSourceActions).toHaveBeenCalledTimes(3)
    expect(window.location.hash).toBe('')
  })

  it('preserves the precise stale-draft error while refreshing sources and actions after a conflict', async () => {
    const client = api({
      getSources: vi.fn<GatewayAdminApi['getSources']>().mockResolvedValueOnce(sources).mockResolvedValue({ ...sources, revision: 9 }),
      prepareSourceAction: vi.fn().mockRejectedValue(new GatewayApiError(409, 'source_action_conflict', { reason: 'draft_changed' })),
    })
    render(<GatewayProvider api={client}><SourceActionsProbe /></GatewayProvider>)
    await screen.findByText('not checking')
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Prepare source' })) })
    expect(screen.getByText(/The saved source draft changed/)).toBeVisible()
    expect(client.getSources).toHaveBeenCalledTimes(2)
    expect(client.getSourceActions).toHaveBeenCalledTimes(3)
  })

  it('fails closed on unavailable status, retains a known blocker, and never displays a raw exception', async () => {
    const client = api({ getSourceActions: vi.fn<GatewayAdminApi['getSourceActions']>()
      .mockResolvedValueOnce(pendingActions).mockRejectedValue(new Error('synthetic-private-provider-error')) })
    render(<GatewayProvider api={client}><SourceActionsProbe /></GatewayProvider>)
    await screen.findByText('authorization_required')
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Check status' })) })
    expect(screen.getByText(/Source action status is temporarily unavailable/)).toBeVisible()
    expect(screen.getByText(pendingAction.actionId)).toBeVisible()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Prepare source' })) })
    expect(client.prepareSourceAction).not.toHaveBeenCalled()
    expect(screen.queryByText('synthetic-private-provider-error')).not.toBeInTheDocument()
  })

  it('discovers source actions after an external WebMCP change', async () => {
    const client = api({ getSourceActions: vi.fn<GatewayAdminApi['getSourceActions']>()
      .mockResolvedValueOnce(emptyActions).mockResolvedValue(pendingActions) })
    render(<GatewayProvider api={client}><SourceActionsProbe /><ExternalRefreshProbe /></GatewayProvider>)
    await screen.findByText('not checking')
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'External refresh' })) })
    expect(screen.getByText('authorization_required')).toBeVisible()
    expect(client.getSourceActions).toHaveBeenCalledTimes(2)
  })
})
