import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { SOURCE_ADDITION_PAUSED_MESSAGE, type GatewayAdminApi, type GatewayStatus, type ManagedSources, type RuntimeUpdate, type SourceDiscovery } from '../api'
import { SYNTHETIC_SOURCE_CATALOG } from '../catalog/fixtures'
import { GatewayProvider } from '../GatewayContext'
import { SourcesPage } from './SourcesPage'

const status: GatewayStatus = {
  schemaVersion: 1, status: 'ready', controlPlaneOrigin: 'https://deploy.ankka.ai', release: 'gateway-v1.0.0',
  gateway: { name: 'Gateway', hostname: 'mcp.example.com', mcpUrl: 'https://mcp.example.com/mcp', capabilityMode: 'read_only', codeMode: 'default_on' },
  source: null, access: { administratorCount: 1, memberCount: 0 }, updatedAt: '2026-08-27T12:00:00.000Z',
}
const sources: ManagedSources = { schemaVersion: 1, revision: 4, applyMode: 'oauth_per_action', installationEnabled: true, sources: [] }
const update: RuntimeUpdate = { schemaVersion: 1, channel: 'stable', status: 'up_to_date', current: { release: 'gateway-v1.0.0', artifactSha256: 'a'.repeat(64) }, available: null, rollback: { available: false } }

describe('SourcesPage', () => {
  afterEach(cleanup)

  it.each([false, true])('disables source addition and draft application while retaining existing sources (empty=%s)', async (empty) => {
    const user = userEvent.setup()
    const current: ManagedSources = {
      ...sources, installationEnabled: false,
      sources: empty ? [] : [
        { id: 'source-1111111111111111', label: 'Installed knowledge', url: 'https://knowledge.example.com/mcp', authMode: 'oauth', onBehalfOfUser: false, enabledTools: ['search'], status: 'installed' },
        { id: 'source-2222222222222222', label: 'Retained draft', url: 'https://draft.example.com/mcp', authMode: 'none', onBehalfOfUser: false, enabledTools: ['get_product'], status: 'draft' },
      ],
    }
    const api: GatewayAdminApi = {
      getStatus: vi.fn(async () => status), getSources: vi.fn(async () => current), getUpdate: vi.fn(async () => update),
      getTeam: vi.fn(), prepareTeamAction: vi.fn(), getTeamAction: vi.fn(), cancelTeamAction: vi.fn(),
      discoverSource: vi.fn(), saveSourceDraft: vi.fn(), prepareSourceAction: vi.fn(), getSourceAction: vi.fn(), cancelSourceAction: vi.fn(),
      prepareRuntimeAction: vi.fn(), getRuntimeAction: vi.fn(), prepareTeardownAction: vi.fn(), getTeardownAction: vi.fn(),
    }
    render(<GatewayProvider api={api}><SourcesPage /></GatewayProvider>)
    expect(await screen.findByText(`${SOURCE_ADDITION_PAUSED_MESSAGE} Saved drafts are retained but cannot be applied.`)).toBeInTheDocument()
    const add = screen.getByRole('button', { name: 'Add source' })
    expect(add).toBeDisabled()
    await user.click(add)
    expect(screen.queryByRole('textbox', { name: 'MCP URL' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Authorize and apply' })).not.toBeInTheDocument()
    if (empty) {
      expect(screen.getByRole('button', { name: 'Add your first source' })).toBeDisabled()
    } else {
      expect(screen.getByText('Installed knowledge')).toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: 'Installed knowledge' }))
      expect(screen.getByText('Operator-connected OAuth')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Installation unavailable' })).toBeDisabled()
      expect(screen.getByText('search')).toBeVisible()
      expect(screen.getByText('Retained draft')).toBeInTheDocument()
    }
    expect(api.discoverSource).not.toHaveBeenCalled()
    expect(api.saveSourceDraft).not.toHaveBeenCalled()
    expect(api.prepareSourceAction).not.toHaveBeenCalled()
  })

  it('shows the protected BigQuery catalogue but blocks connection and keeps all tools unselected', async () => {
    const user = userEvent.setup()
    const saveSourceDraft = vi.fn()
    const api: GatewayAdminApi = {
      getStatus: vi.fn(async () => status),
      getTeam: vi.fn(), prepareTeamAction: vi.fn(), getTeamAction: vi.fn(), cancelTeamAction: vi.fn(), getSources: vi.fn(async () => sources), getUpdate: vi.fn(async () => update),
      discoverSource: vi.fn(async (url): Promise<SourceDiscovery> => ({
        schemaVersion: 1, status: 'authorization_required', endpoint: url, protocolVersion: '2026-07-28',
        authentication: 'oauth', connectionBlock: 'source_google_shared_oauth_unsupported',
        tools: [
          { name: 'execute_sql_readonly', description: 'Synthetic read query.', readOnlyHint: true, defaultSelected: true },
          { name: 'execute_sql', description: 'Synthetic write query.', destructiveHint: true, defaultSelected: false },
        ],
      })),
      saveSourceDraft, prepareSourceAction: vi.fn(), getSourceAction: vi.fn(), cancelSourceAction: vi.fn(),
      prepareRuntimeAction: vi.fn(), getRuntimeAction: vi.fn(), prepareTeardownAction: vi.fn(), getTeardownAction: vi.fn(),
    }
    render(<GatewayProvider api={api}><SourcesPage /></GatewayProvider>)
    await screen.findByText('No sources yet')
    expect(screen.getByText(/once source provisioning starts, automatic gateway removal/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Add source' }))
    expect(screen.getByText(/New sources start with nobody assigned/)).toBeInTheDocument()
    await user.type(screen.getByLabelText('Source name'), 'GA4 example')
    await user.type(screen.getByLabelText('MCP URL'), 'https://bigquery.googleapis.com/mcp')
    await user.click(screen.getByRole('button', { name: 'Inspect source' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('without an admin credential flow')
    expect(screen.getByText('OAuth protected')).toBeInTheDocument()
    expect(screen.queryByText('Public endpoint')).not.toBeInTheDocument()
    expect(screen.queryByText(/Connect this source as a gateway operator/u)).not.toBeInTheDocument()
    expect(screen.getByText('Synthetic read query.')).toBeInTheDocument()
    for (const checkbox of screen.getAllByRole('checkbox')) expect(checkbox).not.toBeChecked()
    await user.click(screen.getByRole('button', { name: 'Select shown' }))
    expect(screen.getByRole('button', { name: 'Save draft' })).toBeDisabled()
    const form = screen.getByRole('button', { name: 'Save draft' }).closest('form')
    if (!form) throw new Error('Expected source form')
    fireEvent.submit(form)
    expect(saveSourceDraft).not.toHaveBeenCalled()
    expect(api.prepareSourceAction).not.toHaveBeenCalled()
  })

  it('uses a reviewed catalog entry only as a seed for inspection and exact-tool review', async () => {
    const user = userEvent.setup()
    const preset = SYNTHETIC_SOURCE_CATALOG.sources[0]
    const saveSourceDraft = vi.fn(async () => ({ ...sources, revision: 5 }))
    const prepareSourceAction = vi.fn()
    const api: GatewayAdminApi = {
      getStatus: vi.fn(async () => status),
      getTeam: vi.fn(), prepareTeamAction: vi.fn(), getTeamAction: vi.fn(), cancelTeamAction: vi.fn(),
      getSources: vi.fn(async () => sources),
      getUpdate: vi.fn(async () => update),
      discoverSource: vi.fn(async (url): Promise<SourceDiscovery> => ({
        schemaVersion: 1,
        status: 'authorization_required',
        endpoint: url,
        protocolVersion: '2026-07-28',
        authentication: 'oauth',
        tools: [],
      })),
      saveSourceDraft,
      prepareSourceAction,
      getSourceAction: vi.fn(), cancelSourceAction: vi.fn(),
      prepareRuntimeAction: vi.fn(), getRuntimeAction: vi.fn(),
      prepareTeardownAction: vi.fn(), getTeardownAction: vi.fn(),
    }

    render(<GatewayProvider api={api}><SourcesPage catalog={SYNTHETIC_SOURCE_CATALOG} /></GatewayProvider>)
    await screen.findByText('No sources yet')
    await user.click(screen.getByRole('button', { name: 'Add source' }))

    await user.click(screen.getByRole('button', { name: 'Custom MCP URL' }))
    expect(screen.getByLabelText('MCP URL')).toHaveValue('')
    await user.click(screen.getByRole('button', { name: /Reviewed catalog/u }))
    expect(screen.queryByLabelText('MCP URL')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: `Select ${preset.displayName}` }))

    expect(screen.getByLabelText('Source name')).toHaveValue(preset.displayName)
    expect(screen.getByLabelText('MCP URL')).toHaveValue(preset.implementation.deployment.url)
    expect(screen.getByLabelText('MCP URL')).toHaveAttribute('readonly')
    expect(screen.getByLabelText('Catalog-recommended tools')).toHaveTextContent('properties.list')
    expect(screen.queryByRole('button', { name: 'Save draft' })).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Inspect source' }))
    expect(api.discoverSource).toHaveBeenCalledWith(preset.implementation.deployment.url)
    expect(await screen.findByLabelText('Exact tool names')).toHaveValue('properties.list\nreports.read')

    await user.click(screen.getByRole('button', { name: 'Save draft' }))
    expect(saveSourceDraft).toHaveBeenCalledWith(4, {
      label: preset.displayName,
      url: preset.implementation.deployment.url,
      authMode: 'oauth',
      enabledTools: ['properties.list', 'reports.read'],
    })
    expect(prepareSourceAction).not.toHaveBeenCalled()
  })

  it('rejects a catalog entry when live inspection finds different authentication', async () => {
    const user = userEvent.setup()
    const preset = SYNTHETIC_SOURCE_CATALOG.sources[0]
    const saveSourceDraft = vi.fn()
    const api: GatewayAdminApi = {
      getStatus: vi.fn(async () => status),
      getTeam: vi.fn(), prepareTeamAction: vi.fn(), getTeamAction: vi.fn(), cancelTeamAction: vi.fn(),
      getSources: vi.fn(async () => sources),
      getUpdate: vi.fn(async () => update),
      discoverSource: vi.fn(async (url): Promise<SourceDiscovery> => ({
        schemaVersion: 1,
        status: 'discovered',
        endpoint: url,
        protocolVersion: '2026-07-28',
        authentication: 'none',
        tools: [{ name: 'reports.read', defaultSelected: true }],
      })),
      saveSourceDraft,
      prepareSourceAction: vi.fn(), getSourceAction: vi.fn(), cancelSourceAction: vi.fn(),
      prepareRuntimeAction: vi.fn(), getRuntimeAction: vi.fn(),
      prepareTeardownAction: vi.fn(), getTeardownAction: vi.fn(),
    }

    render(<GatewayProvider api={api}><SourcesPage catalog={SYNTHETIC_SOURCE_CATALOG} /></GatewayProvider>)
    await screen.findByText('No sources yet')
    await user.click(screen.getByRole('button', { name: 'Add source' }))
    await user.click(screen.getByRole('button', { name: `Select ${preset.displayName}` }))
    await user.click(screen.getByRole('button', { name: 'Inspect source' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('authentication no longer matches')
    expect(screen.queryByRole('button', { name: 'Save draft' })).not.toBeInTheDocument()
    expect(saveSourceDraft).not.toHaveBeenCalled()
  })

  it('discovers a catalogue and saves the reviewed exact allowlist', async () => {
    const user = userEvent.setup()
    const saveSourceDraft = vi.fn(async () => ({ ...sources, revision: 5 }))
    const api: GatewayAdminApi = {
      getStatus: vi.fn(async () => status),
      getTeam: vi.fn(), prepareTeamAction: vi.fn(), getTeamAction: vi.fn(), cancelTeamAction: vi.fn(),
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

  it('clears a successful inspection when a retry fails', async () => {
    const user = userEvent.setup()
    let inspectionCount = 0
    const saveSourceDraft = vi.fn()
    const discoverSource = vi.fn(async (url): Promise<SourceDiscovery> => {
      inspectionCount += 1
      if (inspectionCount > 1) throw new Error('The source could not be reached.')
      return {
        schemaVersion: 1,
        status: 'discovered',
        endpoint: url,
        protocolVersion: '2026-07-28',
        authentication: 'none',
        tools: [{ name: 'search', title: 'Search', description: 'Search documents.', defaultSelected: true }],
      }
    })
    const api: GatewayAdminApi = {
      getStatus: vi.fn(async () => status),
      getTeam: vi.fn(), prepareTeamAction: vi.fn(), getTeamAction: vi.fn(), cancelTeamAction: vi.fn(),
      getSources: vi.fn(async () => sources),
      getUpdate: vi.fn(async () => update),
      discoverSource,
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
    expect(screen.getByRole('button', { name: 'Save draft' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Inspect source' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('could not be reached')
    expect(screen.queryByText('Search documents.')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save draft' })).not.toBeInTheDocument()
    expect(saveSourceDraft).not.toHaveBeenCalled()
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
        onBehalfOfUser: false,
        enabledTools: toolNames,
        status: 'draft',
      }],
    }))
    const api: GatewayAdminApi = {
      getStatus: vi.fn(async () => status),
      getTeam: vi.fn(), prepareTeamAction: vi.fn(), getTeamAction: vi.fn(), cancelTeamAction: vi.fn(),
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
    const savedSource = await screen.findByRole('button', { name: 'Large read API' })
    expect(savedSource).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText(`${toolCount} exact tools`)).not.toBeInTheDocument()
    await user.click(savedSource)
    expect(screen.getByText(`${toolCount} exact tools`)).toBeInTheDocument()
  }, 15_000)

  it('presents an OAuth-protected source as one operator connection', async () => {
    const user = userEvent.setup()
    const saveSourceDraft = vi.fn(async () => ({ ...sources, revision: 5 }))
    const api: GatewayAdminApi = {
      getStatus: vi.fn(async () => status),
      getTeam: vi.fn(), prepareTeamAction: vi.fn(), getTeamAction: vi.fn(), cancelTeamAction: vi.fn(),
      getSources: vi.fn(async () => sources),
      getUpdate: vi.fn(async () => update),
      discoverSource: vi.fn(async (url): Promise<SourceDiscovery> => ({
        schemaVersion: 1,
        status: 'authorization_required',
        endpoint: url,
        protocolVersion: '2026-07-28',
        authentication: 'oauth',
        tools: [],
      })),
      saveSourceDraft,
      prepareSourceAction: vi.fn(), getSourceAction: vi.fn(), cancelSourceAction: vi.fn(),
      prepareRuntimeAction: vi.fn(), getRuntimeAction: vi.fn(),
      prepareTeardownAction: vi.fn(), getTeardownAction: vi.fn(),
    }

    render(<GatewayProvider api={api}><SourcesPage /></GatewayProvider>)
    await screen.findByText('No sources yet')
    await user.click(screen.getByRole('button', { name: 'Add source' }))
    await user.type(screen.getByLabelText('Source name'), 'Protected read API')
    await user.type(screen.getByLabelText('MCP URL'), 'https://protected.example.com/mcp')
    await user.click(screen.getByRole('button', { name: 'Inspect source' }))
    expect(await screen.findByText(/Connect this source as a gateway operator/u)).toBeInTheDocument()
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    await user.type(screen.getByLabelText('Exact tool names'), 'company_read')
    await user.click(screen.getByRole('button', { name: 'Save draft' }))

    expect(saveSourceDraft).toHaveBeenCalledWith(4, {
      label: 'Protected read API',
      url: 'https://protected.example.com/mcp',
      authMode: 'oauth',
      enabledTools: ['company_read'],
    })
  })
})
