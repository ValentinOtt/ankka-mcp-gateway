import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ManagedSource } from '../api'
import { SourceList } from './SourceList'

const sources: [ManagedSource, ManagedSource] = [
  { id: 'source-1111111111111111', label: 'Knowledge', url: 'https://knowledge.example.com/mcp', authMode: 'oauth', onBehalfOfUser: false, enabledTools: ['search', 'fetch_document'], status: 'installed' },
  { id: 'source-2222222222222222', label: 'Catalogue', url: 'https://catalogue.example.com/mcp', authMode: 'none', onBehalfOfUser: false, enabledTools: ['list_products'], status: 'draft' },
]

describe('SourceList', () => {
  afterEach(cleanup)

  it('filters installed sources and drafts without changing them', async () => {
    const user = userEvent.setup()
    const onAuthorize = vi.fn()
    render(<SourceList sources={sources} installationEnabled isBusy={false} onAuthorize={onAuthorize} />)
    const filters = within(screen.getByRole('group', { name: 'Filter sources' }))

    await user.click(filters.getByRole('button', { name: 'Installed' }))
    expect(filters.getByRole('button', { name: 'Installed' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('button', { name: 'Knowledge' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Catalogue' })).not.toBeInTheDocument()

    await user.click(filters.getByRole('button', { name: 'Drafts' }))
    expect(screen.queryByRole('button', { name: 'Knowledge' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Catalogue' })).toBeInTheDocument()

    await user.click(filters.getByRole('button', { name: 'All' }))
    expect(screen.getByRole('button', { name: 'Knowledge' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Catalogue' })).toBeInTheDocument()
    expect(onAuthorize).not.toHaveBeenCalled()
  })

  it('keeps details collapsed until the source is expanded with the keyboard', async () => {
    const user = userEvent.setup()
    render(<SourceList sources={sources} installationEnabled isBusy={false} onAuthorize={vi.fn()} />)
    const source = screen.getByRole('button', { name: 'Knowledge' })
    expect(source).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText(sources[0].url)).not.toBeInTheDocument()

    source.focus()
    await user.keyboard('{Enter}')
    expect(source).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText(sources[0].url)).toBeInTheDocument()
    expect(screen.getByText('Operator-connected OAuth')).toBeInTheDocument()
    expect(screen.getByText('2 exact tools')).toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: 'Knowledge allowed tools' })).getByText('search')).toBeInTheDocument()

    await user.keyboard('{Enter}')
    expect(source).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText(sources[0].url)).not.toBeInTheDocument()
  })

  it('preserves draft authorization and respects installation and busy restrictions', async () => {
    const user = userEvent.setup()
    const onAuthorize = vi.fn()
    const { rerender } = render(<SourceList sources={sources} installationEnabled isBusy={false} onAuthorize={onAuthorize} />)

    await user.click(screen.getByRole('button', { name: 'Authorize and apply' }))
    expect(onAuthorize).toHaveBeenCalledExactlyOnceWith(sources[1].id)

    rerender(<SourceList sources={sources} installationEnabled={false} isBusy={false} onAuthorize={onAuthorize} />)
    expect(screen.getByRole('button', { name: 'Installation unavailable' })).toBeDisabled()
    rerender(<SourceList sources={sources} installationEnabled isBusy onAuthorize={onAuthorize} />)
    expect(screen.getByRole('button', { name: /Authorize and apply/u })).toBeDisabled()
  })

  it('shows an empty filtered state without hiding the filters', async () => {
    const user = userEvent.setup()
    render(<SourceList sources={[sources[0]]} installationEnabled isBusy={false} onAuthorize={vi.fn()} />)
    await user.click(screen.getByRole('button', { name: 'Drafts' }))
    expect(screen.getByText('No drafts.')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'All' }))
    expect(screen.getByRole('button', { name: 'Knowledge' })).toBeInTheDocument()
  })

  it('searches names and URLs alongside the status filter', async () => {
    const user = userEvent.setup()
    const onAuthorize = vi.fn()
    render(<SourceList sources={sources} installationEnabled isBusy={false} onAuthorize={onAuthorize} />)
    const search = screen.getByRole('searchbox', { name: 'Search sources' })

    await user.type(search, 'KNOWLEDGE')
    expect(screen.getByRole('button', { name: 'Knowledge' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Catalogue' })).not.toBeInTheDocument()

    await user.clear(search)
    await user.type(search, 'catalogue.example.com')
    expect(screen.getByRole('button', { name: 'Catalogue' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Installed' }))
    expect(screen.getByText('No matching sources.')).toBeInTheDocument()

    await user.clear(search)
    expect(screen.getByRole('button', { name: 'Knowledge' })).toBeInTheDocument()
    expect(onAuthorize).not.toHaveBeenCalled()
  })
})
