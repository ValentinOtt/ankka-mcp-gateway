import { afterEach, describe, expect, it, vi } from 'vitest'
import { createPreviewGatewayAdminApi } from './preview-api'

function previewApi() {
  const api = createPreviewGatewayAdminApi()
  if (!api) throw new Error('Expected the synthetic preview API')
  return api
}

describe('Team preview', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
    window.history.replaceState(null, '', '/')
    window.sessionStorage.removeItem('ankka-gateway-ui-preview-scenario')
  })

  it('offers an explicit read-only release-review scenario with synthetic people', async () => {
    vi.stubEnv('VITE_GATEWAY_UI_PREVIEW', '1')
    window.history.replaceState(null, '', '/team?preview=team-readonly')
    expect(await createPreviewGatewayAdminApi()?.getTeam()).toEqual(expect.objectContaining({
      editingEnabled: false,
      editingDisabledReason: 'release_review_required',
      adminEmails: ['admin@example.com'],
    }))
  })

  it('does not enable the preview API without its development flag', () => {
    vi.stubEnv('VITE_GATEWAY_UI_PREVIEW', '')
    expect(createPreviewGatewayAdminApi()).toBeUndefined()
  })

  it('previews source installation with nobody assigned and preserves existing Team grants', async () => {
    vi.stubEnv('VITE_GATEWAY_UI_PREVIEW', '1')
    window.history.replaceState(null, '', '/sources?preview=ready')
    const api = previewApi()
    const saved = await api.getSources()
    const team = await api.getTeam()
    expect(saved.installationEnabled).toBe(true)
    const drafted = await api.saveSourceDraft(saved.revision, { label: 'New draft', url: 'https://new.example.com/mcp', authMode: 'none', enabledTools: ['search'] })
    const source = drafted.sources.find((candidate) => candidate.url === 'https://new.example.com/mcp')
    if (!source) throw new Error('Expected saved preview source')
    const prepared = await api.prepareSourceAction(drafted.revision, source.id)
    expect(prepared.status).toBe('authorization_required')
    expect((await api.getSources()).sources.find((candidate) => candidate.id === source.id)?.status).toBe('draft')
    expect((await api.getSourceAction(prepared.actionId)).status).toBe('succeeded')
    expect((await api.getTeam()).members).toEqual(team.members)
    expect((await api.getTeam()).editingEnabled).toBe(true)
  })

  it('resumes only the exact locked recovery proposal through a local Save', async () => {
    vi.stubEnv('VITE_GATEWAY_UI_PREVIEW', '1')
    window.history.replaceState(null, '', '/team?preview=team-recovery')
    const api = previewApi()
    const saved = await api.getTeam()
    expect(saved.pendingAction?.canCancel).toBe(false)
    await expect(api.prepareTeamAction(saved.revision, saved.members)).rejects.toThrow()
    if (!saved.proposedMembers) throw new Error('Expected a recorded synthetic proposal')
    const prepared = await api.prepareTeamAction(saved.revision, saved.proposedMembers)
    expect(await api.getTeamAction(prepared.action.actionId)).toEqual(expect.objectContaining({ status: 'succeeded', canCancel: false }))
    await expect(api.cancelTeamAction(prepared.action.actionId)).rejects.toThrow()
    expect(await api.getTeam()).toEqual(expect.objectContaining({ members: saved.proposedMembers, proposedMembers: null, revision: saved.revision + 1 }))
  })

  it('simulates canceling an unstarted recorded change without changing saved permissions', async () => {
    vi.stubEnv('VITE_GATEWAY_UI_PREVIEW', '1')
    window.history.replaceState(null, '', '/team?preview=team-legacy')
    const api = previewApi()
    const saved = await api.getTeam()
    if (!saved.pendingAction) throw new Error('Expected a retained legacy proposal')
    expect(await api.getTeamAction(saved.pendingAction.actionId)).toEqual(expect.objectContaining({ canCancel: true }))
    expect(await api.cancelTeamAction(saved.pendingAction.actionId)).toEqual(expect.objectContaining({ status: 'failed', failureCode: 'team_action_cancelled', canCancel: false }))
    expect(await api.getTeam()).toEqual(expect.objectContaining({ members: saved.members, proposedMembers: null, revision: saved.revision }))
  })

  it('fails closed without the customer-local management credential', async () => {
    vi.stubEnv('VITE_GATEWAY_UI_PREVIEW', '1')
    window.history.replaceState(null, '', '/team?preview=team-no-credential')
    const api = previewApi()
    const saved = await api.getTeam()
    expect(saved.managementCredentialConfigured).toBe(false)
    await expect(api.prepareTeamAction(saved.revision, saved.members)).rejects.toEqual(expect.objectContaining({ code: 'team_management_credential_missing' }))
    expect(await api.getTeam()).toEqual(saved)
  })

  it('rejects attempts to write through release-gated and lifecycle-paused preview contracts', async () => {
    vi.stubEnv('VITE_GATEWAY_UI_PREVIEW', '1')
    for (const scenario of ['team-readonly', 'team-lifecycle']) {
      window.history.replaceState(null, '', `/team?preview=${scenario}`)
      const api = previewApi()
      const saved = await api.getTeam()
      expect(saved.editingEnabled).toBe(false)
      await expect(api.prepareTeamAction(saved.revision, saved.members)).rejects.toThrow()
      expect((await api.getTeam()).pendingAction).toBeNull()
    }
  })
})
