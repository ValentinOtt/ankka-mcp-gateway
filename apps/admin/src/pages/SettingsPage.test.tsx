import { render, screen, waitFor } from '@testing-library/react'
import { RouterProvider } from '@tanstack/react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { GatewayAdminApi, GatewayStatus, ManagedSources, RuntimeUpdate } from '../api'
import { GatewayProvider } from '../GatewayContext'
import { router } from '../router'

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
  schemaVersion: 1, revision: 1, applyMode: 'oauth_per_action', installationEnabled: false, sources: [],
}
const update: RuntimeUpdate = {
  schemaVersion: 1,
  channel: 'stable',
  status: 'up_to_date',
  current: { release: 'gateway-v1.0.0', artifactSha256: `sha256:${'a'.repeat(64)}` },
  available: null,
  rollback: { available: false },
}

function api(): GatewayAdminApi {
  return {
    getStatus: vi.fn(async () => status),
    getSources: vi.fn(async () => sources),
    getTeam: vi.fn(), prepareTeamAction: vi.fn(), getTeamAction: vi.fn(), cancelTeamAction: vi.fn(),
    getUpdate: vi.fn(async () => update),
    discoverSource: vi.fn(),
    saveSourceDraft: vi.fn(),
    prepareSourceAction: vi.fn(),
    getSourceAction: vi.fn(),
    cancelSourceAction: vi.fn(),
    prepareRuntimeAction: vi.fn(),
    getRuntimeAction: vi.fn(),
    prepareTeardownAction: vi.fn(),
    getTeardownAction: vi.fn(),
  }
}

describe('SettingsPage danger zone', () => {
  const originalScrollIntoView = HTMLElement.prototype.scrollIntoView
  afterEach(() => {
    window.history.replaceState(null, '', '/')
    HTMLElement.prototype.scrollIntoView = originalScrollIntoView
  })

  it('focuses the receipt-authorized teardown section from the installer handoff', async () => {
    window.history.replaceState(null, '', '/?teardown=review')
    const scrollIntoView = vi.fn()
    HTMLElement.prototype.scrollIntoView = scrollIntoView

    render(<GatewayProvider api={api()}><RouterProvider router={router} /></GatewayProvider>)

    expect(await screen.findByRole('heading', { name: 'Settings' })).toBeInTheDocument()
    expect(router.state.location.pathname).toBe('/settings')
    const button = screen.getByRole('button', { name: 'Review teardown plan' })
    const section = button.closest('section')
    await waitFor(() => expect(section).toHaveFocus())
    expect(scrollIntoView).toHaveBeenCalledWith({ behavior: 'smooth', block: 'center' })
    expect(screen.getByText(/zero-write removal plan/u)).toBeInTheDocument()
  })
})
