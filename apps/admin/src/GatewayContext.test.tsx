import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import type { GatewayAdminApi, GatewayStatus, ManagedSources, RuntimeUpdate } from './api'
import { GatewayProvider, useGateway } from './GatewayContext'

const status: GatewayStatus = {
  schemaVersion: 1,
  status: 'ready',
  release: 'gateway-v1.0.0',
  gateway: { name: 'Example Gateway', hostname: 'mcp.example.com', mcpUrl: 'https://mcp.example.com/mcp', capabilityMode: 'read_only', codeMode: 'default_on' },
  source: null,
  access: { administratorCount: 1, memberCount: 2 },
  updatedAt: '2026-08-27T12:00:00.000Z',
}
const sources: ManagedSources = { schemaVersion: 1, revision: 7, applyMode: 'oauth_per_action', sources: [] }
const update: RuntimeUpdate = { schemaVersion: 1, channel: 'stable', status: 'up_to_date', current: { release: 'gateway-v1.0.0', artifactSha256: 'a'.repeat(64) }, available: null, rollback: { available: false } }

function api(overrides: Partial<GatewayAdminApi> = {}): GatewayAdminApi {
  return {
    getStatus: vi.fn(async () => status),
    getSources: vi.fn(async () => sources),
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

describe('GatewayProvider', () => {
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
})
