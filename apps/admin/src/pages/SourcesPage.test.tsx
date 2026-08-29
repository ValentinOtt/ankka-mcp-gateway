import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { GatewayAdminApi, GatewayStatus, ManagedSources, RuntimeUpdate, SourceDiscovery } from '../api'
import { GatewayProvider } from '../GatewayContext'
import { SourcesPage } from './SourcesPage'

const status: GatewayStatus = {
  schemaVersion: 1, status: 'ready', controlPlaneOrigin: 'https://deploy.ankka.ai', release: 'gateway-v1.0.0',
  gateway: { name: 'Gateway', hostname: 'mcp.example.com', mcpUrl: 'https://mcp.example.com/mcp', capabilityMode: 'read_only', codeMode: 'default_on' },
  source: null, access: { administratorCount: 1, memberCount: 0 }, updatedAt: '2026-08-27T12:00:00.000Z',
}
const sources: ManagedSources = { schemaVersion: 1, revision: 4, applyMode: 'oauth_per_action', sources: [] }
const update: RuntimeUpdate = { schemaVersion: 1, channel: 'stable', status: 'up_to_date', current: { release: 'gateway-v1.0.0', artifactSha256: 'a'.repeat(64) }, available: null, rollback: { available: false } }

describe('SourcesPage', () => {
  afterEach(cleanup)

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

  it.each([228, 224])('keeps a %i-tool catalogue filterable and supports bulk exact selection', async (toolCount) => {
    const user = userEvent.setup()
    const toolNames = Array.from(
      { length: toolCount },
      (_, index) => `catalogue_read_${String(index).padStart(3, '0')}`,
    )
    const saveSourceDraft = vi.fn(async (): Promise<ManagedSources> => ({
      ...sources,
      revision: 5,
      sources: [{
        id: 'source-0000000000000000',
        label: 'Large read API',
        url: 'https://catalogue-read.example.com/mcp',
        authMode: 'none',
        enabledTools: toolNames,
        status: 'draft',
      }],
    }))
    const api: GatewayAdminApi = {
      getStatus: vi.fn(async () => status),
      getSources: vi.fn(async () => sources),
      getUpdate: vi.fn(async () => update),
      discoverSource: vi.fn(async (url): Promise<SourceDiscovery> => ({
        schemaVersion: 1,
        status: 'discovered',
        endpoint: url,
        protocolVersion: '2026-07-28',
        authentication: 'none',
        tools: toolNames.map((name) => ({
          name,
          title: name.replaceAll('_', ' '),
          description: `Synthetic read operation ${name}.`,
          readOnlyHint: true,
          destructiveHint: false,
          defaultSelected: false,
        })),
      })),
      saveSourceDraft,
      prepareSourceAction: vi.fn(), getSourceAction: vi.fn(), cancelSourceAction: vi.fn(),
      prepareRuntimeAction: vi.fn(), getRuntimeAction: vi.fn(),
      prepareTeardownAction: vi.fn(), getTeardownAction: vi.fn(),
    }

    render(<GatewayProvider api={api}><SourcesPage /></GatewayProvider>)
    await screen.findByText('No sources yet')
    await user.click(screen.getByRole('button', { name: 'Add source' }))
    fireEvent.change(screen.getByLabelText('Source name'), { target: { value: 'Large read API' } })
    fireEvent.change(screen.getByLabelText('MCP URL'), {
      target: { value: 'https://catalogue-read.example.com/mcp' },
    })
    await user.click(screen.getByRole('button', { name: 'Inspect source' }))

    expect(await screen.findByText(`Showing ${toolCount} of ${toolCount} tools; 0 selected.`)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Filter tools'), {
      target: { value: `catalogue_read_${String(toolCount - 1).padStart(3, '0')}` },
    })
    expect(screen.getByText(`Showing 1 of ${toolCount} tools; 0 selected.`)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Select shown' }))
    expect(screen.getByText(`Showing 1 of ${toolCount} tools; 1 selected.`)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Clear shown' }))
    expect(screen.getByText(`Showing 1 of ${toolCount} tools; 0 selected.`)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Select shown' }))
    fireEvent.change(screen.getByLabelText('Filter tools'), { target: { value: '' } })
    await user.click(screen.getByRole('button', { name: 'Select shown' }))
    expect(screen.getByText(`Showing ${toolCount} of ${toolCount} tools; ${toolCount} selected.`)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Save draft' }))

    expect(saveSourceDraft).toHaveBeenCalledWith(4, {
      label: 'Large read API',
      url: 'https://catalogue-read.example.com/mcp',
      authMode: 'none',
      enabledTools: toolNames,
    })
    const installedSummary = await screen.findByText(`${toolCount} exact tools`)
    expect(installedSummary.closest('details')).not.toHaveAttribute('open')
  }, 15_000)
})
