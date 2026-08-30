import { createMemoryHistory, createRouter, RouterProvider } from '@tanstack/react-router'
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { GatewayProvider } from './GatewayContext'
import { createPreviewGatewayAdminApi } from './preview-api'
import { routeTree } from './router'

describe('gateway product language', () => {
  afterEach(() => {
    cleanup()
    vi.unstubAllEnvs()
    window.history.replaceState(null, '', '/')
    window.sessionStorage.removeItem('ankka-gateway-ui-preview-scenario')
  })

  it.each([
    ['/', 'Example MCP Gateway'],
    ['/sources', 'Sources'],
    ['/settings', 'Settings'],
  ])('addresses the team directly on %s', async (path, heading) => {
    vi.stubEnv('VITE_GATEWAY_UI_PREVIEW', '1')
    window.history.replaceState(null, '', '/?preview=update')
    const api = createPreviewGatewayAdminApi()
    if (!api) throw new TypeError('synthetic preview API is required')
    const router = createRouter({
      routeTree,
      history: createMemoryHistory({ initialEntries: [path] }),
    })

    const { container } = render(
      <GatewayProvider api={api}><RouterProvider router={router} /></GatewayProvider>,
    )

    expect(await screen.findByRole('heading', { name: heading, level: 1 })).toBeInTheDocument()
    expect(screen.getByText('Self-hosted')).toBeInTheDocument()
    expect(container.textContent).not.toMatch(/\bcustomers?\b/iu)
    if (path === '/') {
      expect(screen.getByText(/Your runtime, login settings, policies, DNS, credentials, and logs stay in your Cloudflare account/u))
        .toBeInTheDocument()
    }
    if (path === '/settings') {
      expect(screen.getByText('Preserves your configuration and Durable Object state.')).toBeInTheDocument()
    }
  })
})
