import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'
import { NativeConnectorGuides } from './NativeConnectorGuides'
import { NATIVE_CONNECTOR_RECIPES } from '../connectors/native-recipes'

describe('provider setup guidance', () => {
  afterEach(cleanup)

  it('keeps guidance collapsed and separate from connection authority', async () => {
    const user = userEvent.setup()
    const { container } = render(<NativeConnectorGuides />)
    expect(container.querySelector('details')).not.toHaveAttribute('open')
    await user.click(screen.getByText('Provider setup guides'))
    expect(screen.getByLabelText('Choose a provider guide')).toHaveValue('linear')
    expect(screen.getByText('https://mcp.linear.app/mcp/readonly')).toBeVisible()
    expect(screen.getByText(/No source draft or tool permission is created/)).toBeVisible()
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
    expect(container.querySelector('input[type="password"]')).toBeNull()
    expect(container.querySelector('input[type="checkbox"]')).toBeNull()
  })

  it('shows exact prerequisites without filling a source draft or implying approval', async () => {
    const user = userEvent.setup()
    render(<NativeConnectorGuides />)
    await user.click(screen.getByText('Provider setup guides'))
    const picker = screen.getByLabelText('Choose a provider guide')
    expect(screen.getAllByRole('option')).toHaveLength(NATIVE_CONNECTOR_RECIPES.length)
    await user.selectOptions(picker, 'bigquery')
    expect(screen.getByLabelText('BigQuery setup guide')).toHaveTextContent('Manual setup needed')
    expect(screen.getByLabelText('BigQuery setup guide')).toHaveTextContent('unsupported shared manual-OAuth')
    expect(screen.queryByText('Ankka reviewed')).not.toBeInTheDocument()
    await user.selectOptions(picker, 'ahrefs')
    expect(screen.getByLabelText('Ahrefs setup guide')).toHaveTextContent('Provider permission required')
    expect(screen.getByLabelText('Ahrefs setup guide')).toHaveTextContent('Do not authenticate')
    for (const link of screen.getAllByRole('link')) {
      expect(link).toHaveAttribute('rel', 'noopener noreferrer')
      expect(link.getAttribute('href')).toMatch(/^https:\/\//)
    }
  })
})
