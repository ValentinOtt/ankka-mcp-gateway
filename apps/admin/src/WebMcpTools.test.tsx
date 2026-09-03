import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import { StrictMode } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { GatewayAdminApi, GatewayStatus, ManagedSources, RuntimeUpdate } from './api'
import { GatewayProvider } from './GatewayContext'
import { WebMcpTools, type WebMcpTool } from './WebMcpTools'
import { registerGatewayWebMcpTools, type WebMcpInput, type WebMcpModelContext } from './webmcp'
import { SourcesPage } from './pages/SourcesPage'

const status: GatewayStatus = {
  schemaVersion: 1,
  status: 'ready',
  controlPlaneOrigin: 'https://deploy.ankka.ai',
  release: 'gateway-v1.0.0',
  gateway: {
    name: 'Example Gateway',
    hostname: 'mcp.example.com',
    mcpUrl: 'https://mcp.example.com/mcp',
    capabilityMode: 'read_only',
    codeMode: 'default_on',
  },
  source: null,
  access: { administratorCount: 1, memberCount: 0 },
  updatedAt: '2026-08-27T12:00:00.000Z',
}
const sources: ManagedSources = {
  schemaVersion: 1,
  revision: 1,
  applyMode: 'oauth_per_action',
  installationEnabled: false,
  sources: [],
}
const update: RuntimeUpdate = {
  schemaVersion: 1,
  channel: 'stable',
  status: 'up_to_date',
  current: { release: 'gateway-v1.0.0', artifactSha256: `sha256:${'a'.repeat(64)}` },
  available: null,
  rollback: { available: false },
}

function fixtureApi(): GatewayAdminApi {
  return {
    getStatus: vi.fn(async () => status), getSources: vi.fn(async () => sources), getUpdate: vi.fn(async () => update),
    getTeam: vi.fn(), prepareTeamAction: vi.fn(), getTeamAction: vi.fn(), cancelTeamAction: vi.fn(),
    discoverSource: vi.fn(), saveSourceDraft: vi.fn(), prepareSourceAction: vi.fn(),
    getSourceActions: vi.fn<GatewayAdminApi['getSourceActions']>(async () => ({ schemaVersion: 1, actions: [], blockingAction: null })),
    getSourceAction: vi.fn(), cancelSourceAction: vi.fn(), prepareRuntimeAction: vi.fn(),
    getRuntimeAction: vi.fn(), prepareTeardownAction: vi.fn(), getTeardownAction: vi.fn(),
  }
}

function modelContextFixture() {
  const registered = new Map<string, WebMcpTool>()
  const signals: AbortSignal[] = []
  const modelContext: WebMcpModelContext = {
    registerTool: vi.fn(async (tool, options) => {
      const signal = options?.signal
      if (!signal || signal.aborted) return
      if (registered.has(tool.name)) throw new Error('duplicate registration')
      registered.set(tool.name, tool)
      signals.push(signal)
      signal.addEventListener('abort', () => { registered.delete(tool.name) }, { once: true })
    }),
  }
  return { registered, signals, modelContext }
}

async function executeTool(registered: Map<string, WebMcpTool>, name: string, input: WebMcpInput) {
  const tool = registered.get(name)
  if (!tool) throw new Error('Missing registered synthetic tool')
  let result = ''
  await act(async () => { result = await tool.execute(input) })
  return JSON.parse(result)
}

describe('WebMcpTools', () => {
  afterEach(() => { cleanup(); delete document.modelContext; window.history.replaceState(null, '', '/') })

  it.each([false, true])('shows a source saved through WebMCP without reloading the page (uncertain response: %s)', async (uncertain) => {
    let saved: ManagedSources = { ...sources, installationEnabled: true }
    const api = fixtureApi()
    api.getSources = vi.fn(async () => structuredClone(saved))
    api.saveSourceDraft = vi.fn(async (revision, draft) => {
      saved = { ...saved, revision: revision + 1, sources: [{ ...draft, id: 'source-1111111111111111', onBehalfOfUser: false, status: 'draft' }] }
      if (uncertain) throw new Error('Synthetic response lost after save')
      return structuredClone(saved)
    })
    const { registered, modelContext } = modelContextFixture()
    document.modelContext = modelContext
    render(<GatewayProvider api={api}><WebMcpTools /><SourcesPage /></GatewayProvider>)
    await screen.findByText('No sources yet')
    await waitFor(() => expect(registered.has('save_mcp_source_draft')).toBe(true))
    const result = await executeTool(registered, 'save_mcp_source_draft', {
      label: 'Saved by an agent', url: 'https://source.example.com/mcp', authMode: 'none', enabledTools: ['search'],
    })
    expect(result.ok).toBe(!uncertain)
    expect(await screen.findByText('Saved by an agent')).toBeVisible()
    expect(screen.queryByText('No sources yet')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Authorize and apply' })).toBeEnabled()
    expect(api.saveSourceDraft).toHaveBeenCalledTimes(1)
    expect(api.prepareSourceAction).not.toHaveBeenCalled()
  })

  it('registers teardown as a destructive review handoff without accepting credentials', async () => {
    const prepared = {
      schemaVersion: 1 as const,
      actionId: `action_${'a'.repeat(32)}`,
      status: 'authorization_required' as const,
      expiresAt: '2026-08-27T12:10:00.000Z',
      handoffUrl: `https://deploy.ankka.ai/manage#${'b'.repeat(40)}`,
    }
    const prepareTeardownAction = vi.fn(async () => prepared)
    const api: GatewayAdminApi = {
      getStatus: vi.fn(async () => status),
      getSources: vi.fn(async () => sources),
      getTeam: vi.fn(), prepareTeamAction: vi.fn(), getTeamAction: vi.fn(), cancelTeamAction: vi.fn(),
      getUpdate: vi.fn(async () => update),
      discoverSource: vi.fn(),
      saveSourceDraft: vi.fn(),
      prepareSourceAction: vi.fn(),
      getSourceAction: vi.fn(),
      getSourceActions: vi.fn<GatewayAdminApi['getSourceActions']>(async () => ({ schemaVersion: 1, actions: [], blockingAction: null })),
      cancelSourceAction: vi.fn(),
      prepareRuntimeAction: vi.fn(),
      getRuntimeAction: vi.fn(),
      prepareTeardownAction,
      getTeardownAction: vi.fn(),
    }
    const tools: WebMcpTool[] = []
    document.modelContext = {
      registerTool: vi.fn(async (tool) => { tools.push(tool) }),
    }

    render(<GatewayProvider api={api}><WebMcpTools /></GatewayProvider>)
    await waitFor(() => expect(tools.some((tool) => tool.name === 'review_gateway_teardown')).toBe(true))
    for (const tool of tools) expect(tool.description).not.toMatch(/\bcustomers?\b/iu)

    expect(tools.map((tool) => tool.name)).not.toContain('save_mcp_source_draft')
    expect(tools.map((tool) => tool.name)).not.toContain('apply_mcp_source')
    expect(tools.map((tool) => tool.name)).toContain('list_mcp_sources')
    expect(tools.map((tool) => tool.name)).toContain('discover_mcp_source')
    expect(api.saveSourceDraft).not.toHaveBeenCalled()
    expect(api.prepareSourceAction).not.toHaveBeenCalled()

    const tool = tools.find((candidate) => candidate.name === 'review_gateway_teardown')
    if (tool === undefined) throw new TypeError('teardown tool fixture missing')
    expect(tool.annotations).toMatchObject({
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    })
    const result = JSON.parse(await tool.execute({}))
    expect(result).toEqual({
      ok: true,
      result: {
        status: 'user_review_required',
        authorizationUrl: prepared.handoffUrl,
        actionId: prepared.actionId,
        expiresAt: prepared.expiresAt,
        instruction: expect.stringContaining('never request or handle their token'),
      },
    })
    expect(prepareTeardownAction).toHaveBeenCalledTimes(1)
  })

  it('keeps the ordinary UI usable when WebMCP is absent', async () => {
    const api = fixtureApi()
    const screen = render(<GatewayProvider api={api}><WebMcpTools /><p>Ordinary dashboard</p></GatewayProvider>)
    await waitFor(() => expect(api.getSources).toHaveBeenCalled())
    expect(screen.getByText('Ordinary dashboard')).toBeVisible()
  })

  it('registers exactly one live batch through StrictMode, page restoration, and remounting', async () => {
    const api = fixtureApi()
    const { registered, signals, modelContext } = modelContextFixture()
    document.modelContext = modelContext
    const mounted = render(<StrictMode><GatewayProvider api={api}><WebMcpTools /></GatewayProvider></StrictMode>)
    await waitFor(() => expect(registered.size).toBe(17))
    window.dispatchEvent(new Event('pagehide'))
    expect(registered.size).toBe(0)
    expect(signals.every((signal) => signal.aborted)).toBe(true)
    window.dispatchEvent(new Event('pageshow'))
    await waitFor(() => expect(registered.size).toBe(17))
    mounted.unmount()
    expect(registered.size).toBe(0)
    const remounted = render(<GatewayProvider api={api}><WebMcpTools /></GatewayProvider>)
    await waitFor(() => expect(registered.size).toBe(17))
    remounted.unmount()
    expect(registered.size).toBe(0)
  })

  it('removes a partially registered batch and can register it on the next attempt', async () => {
    const { registered, modelContext } = modelContextFixture()
    const tools: WebMcpTool[] = ['first', 'second'].map((name) => ({
      name, description: 'Synthetic read', inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      execute: async () => '{}',
    }))
    const register = modelContext.registerTool
    const broken: WebMcpModelContext = {
      registerTool: async (tool, options) => {
        if (tool.name === 'second') throw new Error('synthetic registration failure')
        await register(tool, options)
      },
    }
    const controller = new AbortController()
    await registerGatewayWebMcpTools(broken, tools, controller)
    expect(controller.signal.aborted).toBe(true)
    expect(registered.size).toBe(0)
    await registerGatewayWebMcpTools(modelContext, tools, new AbortController())
    expect([...registered.keys()]).toEqual(['first', 'second'])
  })
})
