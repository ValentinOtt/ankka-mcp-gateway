import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import type { GatewayAdminApi, GatewayStatus, ManagedSources, RuntimeUpdate, SourceDiscovery } from '../api'
import { GatewayProvider } from '../GatewayContext'
import { SourcesPage } from './SourcesPage'

const status: GatewayStatus = {
  schemaVersion: 1, status: 'ready', release: 'gateway-v1.0.0',
  gateway: { name: 'Gateway', hostname: 'mcp.example.com', mcpUrl: 'https://mcp.example.com/mcp', capabilityMode: 'read_only', codeMode: 'default_on' },
  source: null, access: { administratorCount: 1, memberCount: 0 }, updatedAt: '2026-08-27T12:00:00.000Z',
}
const sources: ManagedSources = { schemaVersion: 1, revision: 4, applyMode: 'oauth_per_action', sources: [] }
const update: RuntimeUpdate = { schemaVersion: 1, channel: 'stable', status: 'up_to_date', current: { release: 'gateway-v1.0.0', artifactSha256: 'a'.repeat(64) }, available: null, rollback: { available: false } }

describe('SourcesPage', () => {
  it('discovers a catalogue and saves the reviewed exact allowlist', async () => {
    const user = userEvent.setup()
    const saveSourceDraft = vi.fn(async () => ({ ...sources, revision: 5 }))
    const api: GatewayAdminApi = {
      getStatus: vi.fn(async () => status),
      getSources: vi.fn(async () => sources),
      getUpdate: vi.fn(async () => update),
      discoverSource: vi.fn(async (url): Promise<SourceDiscovery> => ({
        schemaVersion: 1, status: 'discovered', endpoint: url, protocolVersion: '2026-07-28', authentication: 'none',
        tools: [{ name: 'search', title: 'Search', description: 'Search documents.', readOnlyHint: true, defaultSelected: true }],
      })),
      saveSourceDraft,
      prepareSourceAction: vi.fn(), getSourceAction: vi.fn(), cancelSourceAction: vi.fn(),
      prepareRuntimeAction: vi.fn(), getRuntimeAction: vi.fn(),
      prepareTeardownAction: vi.fn(), getTeardownAction: vi.fn(),
    }

    render(<GatewayProvider api={api}><SourcesPage /></GatewayProvider>)
    await screen.findByText('No sources yet')
    await user.click(screen.getByRole('button', { name: 'Add source' }))
    await user.type(screen.getByLabelText('Source name'), 'Company knowledge')
    await user.type(screen.getByLabelText('MCP URL'), 'https://knowledge.example.com/mcp')
    await user.click(screen.getByRole('button', { name: 'Inspect source' }))
    expect(await screen.findByText('Search documents.')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Save draft' }))

    expect(saveSourceDraft).toHaveBeenCalledWith(4, {
      label: 'Company knowledge',
      url: 'https://knowledge.example.com/mcp',
      authMode: 'none',
      enabledTools: ['search'],
    })
  })
})
