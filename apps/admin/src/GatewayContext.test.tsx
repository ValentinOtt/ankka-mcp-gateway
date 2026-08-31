import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { SOURCE_ADDITION_PAUSED_MESSAGE, type GatewayAdminApi, type GatewayStatus, type ManagedSources, type RuntimeUpdate, type SourceAction, type TeamActionResult } from './api'
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

function api(overrides: Partial<GatewayAdminApi> = {}): GatewayAdminApi {
  return {
    getStatus: vi.fn(async () => status),
    getSources: vi.fn(async () => sources),
    getTeam: vi.fn(), prepareTeamAction: vi.fn(), getTeamAction: vi.fn(), cancelTeamAction: vi.fn(),
    getUpdate: vi.fn(async () => update),
    discoverSource: vi.fn(),
    saveSourceDraft: vi.fn(async () => ({ ...sources, revision: 8 })),
    prepareSourceAction: vi.fn(),
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

describe('GatewayProvider', () => {
  afterEach(() => { cleanup(); window.history.replaceState(null, '', '/') })
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
      getSourceAction: vi.fn(async (): Promise<SourceAction> => ({ schemaVersion: 1, actionId, sourceId: 'source-1111111111111111', status: 'authorization_required', expiresAt: '2030-01-01T00:00:00.000Z', failureCode: null })),
    })
    render(<GatewayProvider api={client}><PausedSourceProbe /></GatewayProvider>)
    expect(await screen.findByText(SOURCE_ADDITION_PAUSED_MESSAGE)).toBeInTheDocument()
    expect(client.getSourceAction).toHaveBeenCalledTimes(1)
    expect(client.prepareSourceAction).not.toHaveBeenCalled()
  })
})
