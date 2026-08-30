import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { PageHeader } from './PageHeader'

describe('PageHeader', () => {
  afterEach(cleanup)

  it('renders a title and action without an empty description', () => {
    const { container } = render(<PageHeader title="Example gateway" action={<button>Refresh</button>} />)
    expect(screen.getByRole('heading', { level: 1, name: 'Example gateway' })).toBeVisible()
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeVisible()
    expect(container.querySelector('p')).toBeNull()
  })

  it('retains a supplied description', () => {
    render(<PageHeader title="Settings" description="Review the signed runtime." />)
    expect(screen.getByText('Review the signed runtime.')).toBeVisible()
  })
})
