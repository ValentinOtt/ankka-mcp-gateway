import { createMemoryHistory, createRouter, RouterProvider } from '@tanstack/react-router'
import { cleanup, render, screen, within } from '@testing-library/react'
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
    ['/', 'Sources'],
    ['/sources', 'Sources'],
    ['/settings', 'Settings'],
  ])('addresses the team directly on %s', async (path, heading) => {
    vi.stubEnv('VITE_GATEWAY_UI_PREVIEW', '1')
    window.history.replaceState(null, '', '/?preview=update')
    const api = createPreviewGatewayAdminApi()
    if (!api) throw new TypeError('synthetic preview API is required')
    const router = createRouter({
      routeTree,
      history: createMemoryHistory({ initialEntries: [`${path}?preview=update`] }),
    })

    const { container } = render(
      <GatewayProvider api={api}><RouterProvider router={router} /></GatewayProvider>,
    )

    expect(await screen.findByRole('heading', { name: heading, level: 1 })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^(Refresh|Check again)$/u })).not.toBeInTheDocument()
    expect(within(screen.getByRole('complementary')).getByText('MCP Gateway')).toBeInTheDocument()
    const updateLink = within(screen.getByRole('complementary')).getByRole('link', { name: /Update available/ })
    expect(updateLink).toHaveAttribute('href', '/settings')
    const update = await api.getUpdate()
    if (!update.available) throw new TypeError('synthetic update is required')
    expect(updateLink).toHaveTextContent(update.available.release)
    expect(screen.queryByText('Self-hosted')).not.toBeInTheDocument()
    expect(container.textContent).not.toMatch(/\bcustomers?\b/iu)
    expect(screen.queryByRole('link', { name: 'Overview' })).not.toBeInTheDocument()
    if (path === '/' || path === '/sources') {
      expect(router.state.location.pathname).toBe('/sources')
      expect(new URLSearchParams(router.state.location.searchStr).get('preview')).toBe('update')
      expect(screen.getByRole('heading', { name: 'MCP Gateway' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Copy MCP URL' })).toBeInTheDocument()
      expect(screen.queryByText('Your account stays in control')).not.toBeInTheDocument()
    }
    if (path === '/settings') {
      expect(screen.getByText('Preserves your configuration and Durable Object state.')).toBeInTheDocument()
    }
  })

  it.each(['up_to_date', 'unavailable'] as const)('does not advertise an update in the sidebar when %s', async (updateStatus) => {
    vi.stubEnv('VITE_GATEWAY_UI_PREVIEW', '1')
    window.history.replaceState(null, '', '/?preview=ready')
    const api = createPreviewGatewayAdminApi()
    if (!api) throw new TypeError('synthetic preview API is required')
    vi.spyOn(api, 'getUpdate').mockResolvedValue({ ...await api.getUpdate(), status: updateStatus, available: null })
    const router = createRouter({
      routeTree,
      history: createMemoryHistory({ initialEntries: ['/sources'] }),
    })
    render(<GatewayProvider api={api}><RouterProvider router={router} /></GatewayProvider>)

    await screen.findByRole('heading', { name: 'Sources', level: 1 })
    expect(within(screen.getByRole('complementary')).queryByRole('link', { name: /Update available/ })).not.toBeInTheDocument()
  })
})
