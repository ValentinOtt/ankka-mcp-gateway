import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { GatewayApiError, type GatewayAdminApi, type GatewayStatus, type ManagedSources, type TeamActionResult, type RuntimeUpdate, type Team, type TeamAction } from '../api'
import { GatewayProvider } from '../GatewayContext'
import { createPreviewGatewayAdminApi } from '../preview-api'
import { TeamPage } from './TeamPage'

const sourceId = 'source-1111111111111111'
const actionId = `action_${'a'.repeat(32)}`
const expiresAt = '2030-01-01T00:00:00.000Z'
const status: GatewayStatus = {
  schemaVersion: 1, status: 'ready', controlPlaneOrigin: 'https://deploy.ankka.ai', release: 'gateway-v1.0.0',
  gateway: { name: 'Example Gateway', hostname: 'mcp.example.com', mcpUrl: 'https://mcp.example.com/mcp', capabilityMode: 'read_only', codeMode: 'default_on' },
  source: null, access: { administratorCount: 1, memberCount: 1 }, updatedAt: '2026-08-27T12:00:00.000Z',
}
const sources: ManagedSources = { schemaVersion: 1, revision: 1, applyMode: 'oauth_per_action', installationEnabled: false, sources: [] }
const update: RuntimeUpdate = { schemaVersion: 1, channel: 'stable', status: 'up_to_date', current: null, available: null, rollback: { available: false } }
const team: Team = {
  schemaVersion: 1, revision: 7, editingEnabled: true, editingDisabledReason: null, managementCredentialConfigured: true,
  adminEmails: ['admin@example.com'],
  members: [{ email: 'admin@example.com', sourceIds: [] }, { email: 'analyst@example.com', sourceIds: [] }],
  sources: [
    { id: sourceId, label: 'Company knowledge', enabledTools: ['fetch_document', 'search'], status: 'installed' },
    { id: 'source-2222222222222222', label: 'Product catalogue', enabledTools: ['get_product'], status: 'draft' },
  ],
  pendingAction: null,
  proposedMembers: null,
}

function api(overrides: Partial<GatewayAdminApi> = {}): GatewayAdminApi {
  return {
    getStatus: vi.fn(async () => status), getSources: vi.fn(async () => sources), getUpdate: vi.fn(async () => update),
    getTeam: vi.fn(async () => structuredClone(team)), prepareTeamAction: vi.fn(), getTeamAction: vi.fn(), cancelTeamAction: vi.fn(),
    discoverSource: vi.fn(), saveSourceDraft: vi.fn(), prepareSourceAction: vi.fn(), getSourceAction: vi.fn(), cancelSourceAction: vi.fn(),
    prepareRuntimeAction: vi.fn(), getRuntimeAction: vi.fn(), prepareTeardownAction: vi.fn(), getTeardownAction: vi.fn(),
    ...overrides,
  }
}

function renderTeam(client = api()) {
  render(<GatewayProvider api={client}><TeamPage /></GatewayProvider>)
  return client
}

describe('TeamPage', () => {
  afterEach(() => { cleanup(); window.history.replaceState(null, '', '/'); vi.restoreAllMocks(); vi.unstubAllEnvs() })

  it('starts new people with no sources and keeps unsaved selections separate from saved access', async () => {
    const user = userEvent.setup()
    const client = renderTeam()
    await screen.findByRole('group', { name: 'admin@example.com' })
    expect(screen.queryByRole('button', { name: 'Remove admin@example.com' })).not.toBeInTheDocument()
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
    expect(screen.getByText(/Their roles are fixed/)).toBeInTheDocument()

    await user.type(screen.getByLabelText('Person’s email'), 'New.Person@Example.com')
    await user.click(screen.getByRole('button', { name: 'Add person' }))
    const newPerson = screen.getByRole('group', { name: 'new.person@example.com' })
    const checkbox = within(newPerson).getByRole('checkbox', { name: /Company knowledge/ })
    expect(checkbox).not.toBeChecked()
    expect(within(newPerson).queryByRole('checkbox', { name: /Product catalogue/ })).not.toBeInTheDocument()
    expect(screen.getByText('Unsaved changes')).toBeInTheDocument()

    await user.click(checkbox)
    expect(checkbox).toBeChecked()
    expect(within(screen.getByRole('list', { name: 'Saved team access' })).queryByText('new.person@example.com')).not.toBeInTheDocument()
    expect(client.prepareTeamAction).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: 'Discard unsaved changes' }))
    expect(screen.queryByRole('group', { name: 'new.person@example.com' })).not.toBeInTheDocument()
    expect(screen.getByText('No unsaved changes')).toBeInTheDocument()
  })

  it('edits administrator source access without changing roles and shares exact tools rather than per-person tools', async () => {
    const user = userEvent.setup()
    renderTeam()
    const administrator = await screen.findByRole('group', { name: 'admin@example.com' })
    await user.click(within(administrator).getByRole('checkbox', { name: /Company knowledge/ }))
    expect(within(administrator).getByRole('checkbox')).toBeChecked()
    expect(screen.getByText('Administrator · role unchanged')).toBeInTheDocument()
    await user.click(screen.getByText('Company knowledge · 2 tools'))
    const tools = screen.getByRole('list', { name: 'Company knowledge enabled tools' })
    expect(within(tools).getByText('fetch_document')).toBeInTheDocument()
    expect(within(tools).getByText('search')).toBeInTheDocument()
    expect(within(tools).queryByRole('checkbox')).not.toBeInTheDocument()
    expect(screen.getByText(/Existing cached sessions may remain valid/)).toBeInTheDocument()
    expect(screen.getByText('After the first permission-policy change, automatic teardown is unavailable until a compatible gateway release supports it.')).toBeInTheDocument()
  })

  it('keeps existing-source permission controls usable while source addition is paused', async () => {
    const user = userEvent.setup()
    const client = renderTeam()
    const administrator = await screen.findByRole('group', { name: 'admin@example.com' })
    expect(screen.getByText(/New-source installation is temporarily unavailable in this release/)).toBeInTheDocument()
    const source = within(administrator).getByRole('checkbox', { name: /Company knowledge/ })
    expect(source).toBeEnabled()
    await user.click(source)
    expect(source).toBeChecked()
    expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled()
    expect(screen.getByLabelText('Person’s email')).toBeEnabled()
    expect(client.prepareSourceAction).not.toHaveBeenCalled()
  })

  it('rejects a duplicate email without adding another person', async () => {
    const user = userEvent.setup()
    renderTeam()
    await screen.findByRole('group', { name: 'analyst@example.com' })
    await user.type(screen.getByLabelText('Person’s email'), 'ANALYST@example.com')
    await user.click(screen.getByRole('button', { name: 'Add person' }))
    expect(screen.getByRole('alert')).toHaveTextContent('This person is already in your team.')
    expect(screen.getAllByRole('group', { name: 'analyst@example.com' })).toHaveLength(1)
  })

  it('bounds the team at 51 people including administrators without limiting existing edits', async () => {
    const user = userEvent.setup()
    const members = [{ email: 'admin@example.com', sourceIds: [] }, ...Array.from({ length: 50 }, (_, index) => ({ email: `person${index}@example.com`, sourceIds: [] }))]
    renderTeam(api({ getTeam: vi.fn(async () => ({ ...team, members })) }))
    expect(await screen.findByText(/51 of 51 people, including administrators/)).toBeInTheDocument()
    expect(screen.getByLabelText('Person’s email')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Add person' })).toBeDisabled()
    const administrator = screen.getByRole('group', { name: 'admin@example.com' })
    expect(within(administrator).getByRole('checkbox')).toBeEnabled()
    await user.click(screen.getByRole('button', { name: 'Remove person0@example.com' }))
    expect(screen.getByLabelText('Person’s email')).toBeEnabled()
    expect(screen.getByText(/50 of 51 people, including administrators/)).toBeInTheDocument()
  })

  it('rejects an overlong local email part without preparing any change', async () => {
    const user = userEvent.setup()
    const client = renderTeam()
    await screen.findByRole('group', { name: 'admin@example.com' })
    await user.type(screen.getByLabelText('Person’s email'), `${'a'.repeat(65)}@example.com`)
    await user.click(screen.getByRole('button', { name: 'Add person' }))
    expect(screen.getByRole('alert')).toHaveTextContent('Enter a valid email address')
    expect(screen.getByText('No unsaved changes')).toBeInTheDocument()
    expect(client.prepareTeamAction).not.toHaveBeenCalled()
  })

  it('shows a newly installed source without implicitly assigning it to anyone', async () => {
    const client = renderTeam(api({ getTeam: vi.fn(async () => ({ ...team, sources: team.sources.map((source) => ({ ...source, status: 'installed' as const })) })) }))
    await screen.findByRole('group', { name: 'admin@example.com' })
    for (const checkbox of screen.getAllByRole('checkbox', { name: /Product catalogue/ })) expect(checkbox).not.toBeChecked()
    expect(screen.getByText(/New people start with no sources/)).toBeInTheDocument()
    expect(screen.getByText('No unsaved changes')).toBeInTheDocument()
    expect(client.prepareTeamAction).not.toHaveBeenCalled()
  })

  it('submits only the reviewed proposal and never optimistically changes saved access', async () => {
    const user = userEvent.setup()
    const prepareTeamAction = vi.fn(() => new Promise<never>(() => {}))
    renderTeam(api({ prepareTeamAction }))
    const person = await screen.findByRole('group', { name: 'analyst@example.com' })
    await user.click(within(person).getByRole('checkbox'))
    await user.dblClick(screen.getByRole('button', { name: 'Save' }))
    expect(prepareTeamAction).toHaveBeenCalledExactlyOnceWith(7, [
      { email: 'admin@example.com', sourceIds: [] },
      { email: 'analyst@example.com', sourceIds: [sourceId] },
    ])
    expect(within(screen.getByRole('list', { name: 'Saved team access' })).getAllByText('No source access')).toHaveLength(2)
    expect(screen.queryByText(/last recorded team access change was applied and verified/)).not.toBeInTheDocument()
  })

  it('keeps a recovery proposal read-only and resumes its exact recorded membership', async () => {
    const user = userEvent.setup()
    const proposedMembers = [{ email: 'admin@example.com', sourceIds: [sourceId] }]
    const pendingAction: TeamAction = { schemaVersion: 1, actionId, status: 'recovery_required', expiresAt, failureCode: 'team_recovery_required', canCancel: false }
    const prepareTeamAction = vi.fn(() => new Promise<never>(() => {}))
    renderTeam(api({ getTeam: vi.fn(async () => ({ ...team, pendingAction, proposedMembers })), prepareTeamAction }))
    expect(await screen.findByText(/Nothing was automatically restored/)).toBeInTheDocument()
    expect(screen.getByText('Recorded change')).toBeInTheDocument()
    expect(screen.queryByRole('group', { name: 'analyst@example.com' })).not.toBeInTheDocument()
    expect(within(screen.getByRole('group', { name: 'admin@example.com' })).getByRole('checkbox')).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Add person' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Resume recorded change' }))
    expect(prepareTeamAction).toHaveBeenCalledWith(7, proposedMembers)
    expect(within(screen.getByRole('list', { name: 'Saved team access' })).getByText('analyst@example.com')).toBeInTheDocument()
  })

  it('does not permit a recovery action when its recorded proposal cannot be retrieved', async () => {
    const pendingAction: TeamAction = { schemaVersion: 1, actionId, status: 'recovery_required', expiresAt, failureCode: null, canCancel: false }
    const client = renderTeam(api({ getTeam: vi.fn(async () => ({ ...team, pendingAction })) }))
    expect(await screen.findByText(/recorded proposal is unavailable/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Resume recorded change' })).toBeDisabled()
    expect(client.prepareTeamAction).not.toHaveBeenCalled()
  })

  it('loads verified state after a callback completes instead of treating the callback as proof', async () => {
    window.history.replaceState(null, '', `/team?accessAction=${actionId}&accessActionResult=complete`)
    const succeeded: TeamAction = { schemaVersion: 1, actionId, status: 'succeeded', expiresAt, failureCode: null, canCancel: false }
    const verified: Team = { ...team, revision: 8, pendingAction: succeeded, members: [{ email: 'admin@example.com', sourceIds: [] }, { email: 'analyst@example.com', sourceIds: [sourceId] }] }
    const getTeam = vi.fn().mockResolvedValueOnce(team).mockResolvedValue(verified)
    const getTeamAction = vi.fn(async () => succeeded)
    renderTeam(api({ getTeam, getTeamAction }))
    expect(await screen.findByText(/last recorded team access change was applied and verified/)).toBeInTheDocument()
    expect(screen.getByText('Revision 8')).toBeInTheDocument()
    expect(within(screen.getByRole('list', { name: 'Saved team access' })).getByText('Company knowledge')).toBeInTheDocument()
    expect(getTeamAction).toHaveBeenCalledWith(actionId)
    expect(window.location.search).not.toContain('accessActionResult')
    expect(window.location.search).not.toContain('accessAction=')
  })

  it('applies an entire batch with one local Save and reloads the verified roster without a hosted handoff', async () => {
    window.history.replaceState(null, '', '/team')
    const user = userEvent.setup()
    const secondSource = 'source-2222222222222222'
    const current = { ...team, sources: team.sources.map((source) => ({ ...source, status: 'installed' as const })) }
    const members = [
      { email: 'admin@example.com', sourceIds: [sourceId] },
      { email: 'analyst@example.com', sourceIds: [secondSource] },
      { email: 'new.person@example.com', sourceIds: [sourceId] },
    ]
    const succeeded: TeamActionResult['action'] = { schemaVersion: 1, action: 'access', actionId, status: 'succeeded', expiresAt, failureCode: null, canCancel: false }
    const getTeam = vi.fn().mockResolvedValueOnce(current).mockResolvedValue({ ...current, members, pendingAction: succeeded, revision: 8 })
    const client = renderTeam(api({ getTeam, prepareTeamAction: vi.fn(async (): Promise<TeamActionResult> => ({ schemaVersion: 1, action: succeeded })) }))
    const administrator = await screen.findByRole('group', { name: 'admin@example.com' })
    await user.click(within(administrator).getByRole('checkbox', { name: /Company knowledge/ }))
    await user.click(within(screen.getByRole('group', { name: 'analyst@example.com' })).getByRole('checkbox', { name: /Product catalogue/ }))
    await user.type(screen.getByLabelText('Person’s email'), 'New.Person@Example.com')
    await user.click(screen.getByRole('button', { name: 'Add person' }))
    await user.click(within(screen.getByRole('group', { name: 'new.person@example.com' })).getByRole('checkbox', { name: /Company knowledge/ }))
    expect(within(screen.getByRole('list', { name: 'Saved team access' })).getAllByText('No source access')).toHaveLength(2)
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Revision 8')).toBeInTheDocument()
    expect(screen.getByText(/last recorded team access change was applied and verified/)).toBeInTheDocument()
    expect(within(screen.getByRole('list', { name: 'Saved team access' })).getByText('new.person@example.com')).toBeInTheDocument()
    expect(screen.getByText('No unsaved changes')).toBeInTheDocument()
    expect(client.prepareTeamAction).toHaveBeenCalledExactlyOnceWith(7, members)
    expect(client.prepareSourceAction).not.toHaveBeenCalled()
    expect(client.getStatus).toHaveBeenCalledTimes(1)
    expect(getTeam).toHaveBeenCalledTimes(2)
    expect(window.location.pathname).toBe('/team')
    expect(window.location.search).toBe('')
  })

  it('blocks Save without a management credential and gives direct Worker-secret setup guidance', async () => {
    const user = userEvent.setup()
    const client = renderTeam(api({ getTeam: vi.fn(async () => ({ ...team, managementCredentialConfigured: false })) }))
    const person = await screen.findByRole('group', { name: 'analyst@example.com' })
    await user.click(within(person).getByRole('checkbox'))
    expect(screen.getByText(/Team saves need a dedicated Cloudflare management API token/)).toHaveTextContent('Settings → Variables and Secrets')
    expect(screen.getByText(/Team saves need a dedicated Cloudflare management API token/)).toHaveTextContent('can administer other applications and policies in the same account')
    expect(screen.getByRole('link', { name: 'Team credential setup guide' })).toHaveAttribute('href', 'https://github.com/ValentinOtt/ankka-mcp-gateway/blob/main/docs/TEAM_ACCESS.md')
    expect(screen.getByRole('link', { name: 'Team credential setup guide' })).toHaveAttribute('rel', 'noreferrer')
    expect(screen.getByText('ANKKA_TEAM_MANAGEMENT_TOKEN')).toBeInTheDocument()
    expect(screen.getByText(/Never paste the token into this dashboard or send it to Ankka/)).toBeInTheDocument()
    const save = screen.getByRole('button', { name: 'Save' })
    expect(save).toBeDisabled()
    await user.click(save)
    expect(client.prepareTeamAction).not.toHaveBeenCalled()
    expect(screen.queryByRole('button', { name: /Cloudflare/ })).not.toBeInTheDocument()
    expect(screen.queryByText(/last recorded team access change was applied and verified/)).not.toBeInTheDocument()
  })

  it('resumes an expired legacy proposal locally without requiring a hosted callback', async () => {
    const user = userEvent.setup()
    const proposedMembers = [{ email: 'admin@example.com', sourceIds: [sourceId] }]
    const pendingAction: TeamAction = { schemaVersion: 1, actionId, status: 'authorization_required', expiresAt: '2020-01-01T00:00:00.000Z', failureCode: null, canCancel: true }
    const succeeded: TeamActionResult['action'] = { ...pendingAction, status: 'succeeded', canCancel: false }
    const getTeam = vi.fn().mockResolvedValueOnce({ ...team, pendingAction, proposedMembers }).mockResolvedValue({ ...team, pendingAction: succeeded, proposedMembers: null, members: proposedMembers, revision: 8 })
    const client = renderTeam(api({ getTeam, prepareTeamAction: vi.fn(async (): Promise<TeamActionResult> => ({ schemaVersion: 1, action: succeeded })) }))
    expect(await screen.findByText(/Hosted authorization is no longer used/)).toBeInTheDocument()
    expect(within(screen.getByRole('group', { name: 'admin@example.com' })).getByRole('checkbox')).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Save recorded change' }))
    expect(await screen.findByText('Revision 8')).toBeInTheDocument()
    expect(client.prepareTeamAction).toHaveBeenCalledExactlyOnceWith(7, proposedMembers)
    expect(client.getTeamAction).not.toHaveBeenCalled()
    expect(window.location.search).toBe('')
  })

  it('gives revoked-credential guidance and retains an uncertain proposal for local recovery', async () => {
    const user = userEvent.setup()
    const proposedMembers = team.members.map((member) => ({ ...member, sourceIds: member.email === 'analyst@example.com' ? [sourceId] : [] }))
    const pendingAction: TeamAction = { schemaVersion: 1, actionId, status: 'recovery_required', expiresAt, failureCode: 'team_management_credential_invalid', canCancel: false }
    const getTeam = vi.fn().mockResolvedValueOnce(team).mockResolvedValue({ ...team, pendingAction, proposedMembers })
    const client = renderTeam(api({ getTeam, prepareTeamAction: vi.fn().mockRejectedValue(new GatewayApiError(409, 'team_management_credential_invalid')) }))
    await user.click(within(await screen.findByRole('group', { name: 'analyst@example.com' })).getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Check its expiry, account, and Access permissions')
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: /Cloudflare/ })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Refresh' }))
    expect(await screen.findByText(/Nothing was automatically restored/)).toHaveTextContent('replace ANKKA_TEAM_MANAGEMENT_TOKEN directly')
    expect(screen.getByRole('button', { name: 'Resume recorded change' })).toBeEnabled()
    expect(screen.queryByRole('button', { name: 'Cancel recorded change' })).not.toBeInTheDocument()
    expect(within(screen.getByRole('group', { name: 'analyst@example.com' })).getByRole('checkbox')).toBeChecked()
    expect(within(screen.getByRole('group', { name: 'analyst@example.com' })).getByRole('checkbox')).toBeDisabled()
    expect(within(screen.getByRole('list', { name: 'Saved team access' })).getAllByText('No source access')).toHaveLength(2)
    expect(client.prepareTeamAction).toHaveBeenCalledTimes(1)
  })

  it('locks uncertain preparation failures until refresh and never exposes raw exception details', async () => {
    const user = userEvent.setup()
    const prepareTeamAction = vi.fn().mockRejectedValue(new Error('private provider detail'))
    const client = renderTeam(api({ prepareTeamAction }))
    const person = await screen.findByRole('group', { name: 'analyst@example.com' })
    await user.click(within(person).getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('The team access request could not be confirmed')
    expect(screen.queryByText('private provider detail')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    expect(within(person).getByRole('checkbox')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeEnabled()
    await user.click(screen.getByRole('button', { name: 'Refresh' }))
    await waitFor(() => expect(within(person).getByRole('checkbox')).toBeEnabled())
    expect(within(person).getByRole('checkbox')).not.toBeChecked()
    expect(client.getTeam).toHaveBeenCalledTimes(2)
    expect(prepareTeamAction).toHaveBeenCalledTimes(1)
  })

  it('shows a revision conflict without silently retrying against a newer revision', async () => {
    const user = userEvent.setup()
    const prepareTeamAction = vi.fn().mockRejectedValue(new GatewayApiError(409, 'team_access_revision_conflict'))
    renderTeam(api({ prepareTeamAction }))
    const person = await screen.findByRole('group', { name: 'analyst@example.com' })
    await user.click(within(person).getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Team access changed in another tab')
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    expect(prepareTeamAction).toHaveBeenCalledTimes(1)
  })

  it('does not treat a success callback as proof when action status is unavailable', async () => {
    const user = userEvent.setup()
    window.history.replaceState(null, '', `/team?accessAction=${actionId}&accessActionResult=complete`)
    const client = renderTeam(api({ getTeamAction: vi.fn().mockRejectedValue(new Error('private provider detail')) }))
    expect(await screen.findByRole('alert')).toHaveTextContent('action status is unavailable')
    expect(screen.queryByText(/last recorded team access change was applied and verified/)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add person' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    expect(client.prepareTeamAction).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Refresh' }))
    await waitFor(() => expect(screen.getByLabelText('Person’s email')).toBeEnabled())
    expect(window.location.search).not.toContain('accessAction=')
    expect(client.getTeamAction).toHaveBeenCalledTimes(1)
  })

  it('only reports cancellation after the Worker confirms it and reloads the saved state', async () => {
    const user = userEvent.setup()
    const pendingAction: TeamAction = { schemaVersion: 1, actionId, status: 'authorization_required', expiresAt, failureCode: null, canCancel: true }
    const canceled: TeamAction = { ...pendingAction, status: 'failed', failureCode: 'team_action_cancelled', canCancel: false }
    const proposedMembers = [{ email: 'admin@example.com', sourceIds: [sourceId] }]
    const getTeam = vi.fn().mockResolvedValueOnce({ ...team, pendingAction, proposedMembers }).mockResolvedValue({ ...team, pendingAction: canceled })
    const client = renderTeam(api({ getTeam, getTeamAction: vi.fn(async () => pendingAction), cancelTeamAction: vi.fn(async () => canceled) }))
    await user.click(await screen.findByRole('button', { name: 'Cancel recorded change' }))
    expect(await screen.findByText('The recorded change was canceled before any access policy was changed.')).toBeInTheDocument()
    expect(client.cancelTeamAction).toHaveBeenCalledWith(actionId)
    expect(getTeam).toHaveBeenCalledTimes(2)
    expect(screen.getByLabelText('Person’s email')).toBeEnabled()
    expect(within(screen.getByRole('group', { name: 'admin@example.com' })).getByRole('checkbox')).not.toBeChecked()
  })

  it.each(['authorization_required', 'recovery_required'] as const)('retains a %s proposal without credentials and permits only Worker-approved cancellation', async (actionStatus) => {
    const user = userEvent.setup()
    const pendingAction: TeamAction = { schemaVersion: 1, actionId, status: actionStatus, expiresAt, failureCode: null, canCancel: true }
    const proposedMembers = [{ email: 'admin@example.com', sourceIds: [sourceId] }]
    const canceled: TeamAction = { ...pendingAction, status: 'failed', failureCode: 'team_action_cancelled', canCancel: false }
    const getTeam = vi.fn().mockResolvedValueOnce({ ...team, managementCredentialConfigured: false, pendingAction, proposedMembers }).mockResolvedValue({ ...team, managementCredentialConfigured: false, pendingAction: canceled })
    const client = renderTeam(api({ getTeam, cancelTeamAction: vi.fn(async () => canceled) }))
    expect(await screen.findByText('Recorded change')).toBeInTheDocument()
    const record = within(screen.getByRole('group', { name: 'admin@example.com' })).getByRole('checkbox')
    expect(record).toBeChecked()
    expect(record).toBeDisabled()
    expect(screen.getByRole('button', { name: actionStatus === 'recovery_required' ? 'Resume recorded change' : 'Save recorded change' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Cancel recorded change' }))
    expect(await screen.findByText('The recorded change was canceled before any access policy was changed.')).toBeInTheDocument()
    expect(client.cancelTeamAction).toHaveBeenCalledExactlyOnceWith(actionId)
    expect(client.prepareTeamAction).not.toHaveBeenCalled()
  })

  it.each(['authorization_required', 'applying', 'recovery_required'] as const)('does not offer cancellation for a non-cancellable %s action', async (actionStatus) => {
    const pendingAction: TeamAction = { schemaVersion: 1, actionId, status: actionStatus, expiresAt, failureCode: null, canCancel: false }
    const client = renderTeam(api({ getTeam: vi.fn(async () => ({ ...team, pendingAction, proposedMembers: team.members })), getTeamAction: vi.fn(async () => pendingAction) }))
    await screen.findByText('Recorded change')
    expect(screen.queryByRole('button', { name: 'Cancel recorded change' })).not.toBeInTheDocument()
    expect(client.cancelTeamAction).not.toHaveBeenCalled()
    for (const checkbox of screen.getAllByRole('checkbox')) expect(checkbox).toBeDisabled()
  })

  it('does not claim cancellation when the recorded action started applying before cancellation', async () => {
    const user = userEvent.setup()
    const pendingAction: TeamAction = { schemaVersion: 1, actionId, status: 'authorization_required', expiresAt, failureCode: null, canCancel: true }
    const client = renderTeam(api({
      getTeam: vi.fn(async () => ({ ...team, pendingAction, proposedMembers: team.members })),
      getTeamAction: vi.fn(async () => pendingAction),
      cancelTeamAction: vi.fn(async () => ({ ...pendingAction, status: 'applying' as const, canCancel: false })),
    }))
    await user.click(await screen.findByRole('button', { name: 'Cancel recorded change' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Cancellation could not be confirmed')
    expect(screen.queryByText('The recorded change was canceled before any access policy was changed.')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save recorded change' })).toBeDisabled()
    expect(client.cancelTeamAction).toHaveBeenCalledTimes(1)
  })

  it('pauses editing for a pending lifecycle action without hiding saved access and tools', async () => {
    const client = renderTeam(api({ getTeam: vi.fn(async () => ({ ...team, editingEnabled: false, editingDisabledReason: 'lifecycle_action_pending' as const })) }))
    expect(await screen.findByText(/Another source, update, or teardown action is in progress/)).toBeInTheDocument()
    expect(screen.getByRole('list', { name: 'Saved team access' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    expect(client.prepareTeamAction).not.toHaveBeenCalled()
  })

  it('keeps the real release-review capability disabled and never prepares a write', async () => {
    const user = userEvent.setup()
    const client = renderTeam(api({ getTeam: vi.fn(async () => ({ ...team, editingEnabled: false, editingDisabledReason: 'release_review_required' as const })) }))
    expect(await screen.findByText(/disabled until this gateway release is reviewed and approved/)).toBeInTheDocument()
    expect(screen.getByText(/Changes made directly in Cloudflare are not reflected here/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add person' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Remove analyst@example.com' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    for (const checkbox of screen.getAllByRole('checkbox')) expect(checkbox).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await user.click(screen.getByText('Company knowledge · 2 tools'))
    expect(screen.getByRole('list', { name: 'Company knowledge enabled tools' })).toBeInTheDocument()
    expect(client.prepareTeamAction).not.toHaveBeenCalled()
  })

  it('shows a safe unavailable state when team loading fails', async () => {
    const getTeam = vi.fn().mockRejectedValue(new Error('private provider detail'))
    renderTeam(api({ getTeam }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Team access could not be loaded.'))
    expect(screen.queryByText('private provider detail')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
  })

  it('keeps recovery resume disabled while the release is awaiting approval', async () => {
    const user = userEvent.setup()
    const pendingAction: TeamAction = { schemaVersion: 1, actionId, status: 'recovery_required', expiresAt, failureCode: null, canCancel: false }
    const client = renderTeam(api({ getTeam: vi.fn(async () => ({ ...team, editingEnabled: false, editingDisabledReason: 'release_review_required' as const, pendingAction, proposedMembers: team.members })) }))
    const resume = await screen.findByRole('button', { name: 'Resume recorded change' })
    expect(resume).toBeDisabled()
    await user.click(resume)
    expect(client.prepareTeamAction).not.toHaveBeenCalled()
  })

  it('explicitly labels the local synthetic preview and completes its simulated Save on this page', async () => {
    vi.stubEnv('VITE_GATEWAY_UI_PREVIEW', '1')
    window.history.replaceState(null, '', '/team?preview=ready')
    const user = userEvent.setup()
    const previewApi = createPreviewGatewayAdminApi()
    if (!previewApi) throw new Error('Expected preview API')
    renderTeam(previewApi)
    expect(screen.getByText(/Local preview — synthetic people; no Cloudflare changes/)).toBeInTheDocument()
    const person = await screen.findByRole('group', { name: 'analyst@example.com' })
    await user.click(within(person).getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/last recorded team access change was applied and verified/)).toBeInTheDocument()
    expect(window.location.pathname).toBe('/team')
    expect(screen.getByText('No unsaved changes')).toBeInTheDocument()
  })
})
