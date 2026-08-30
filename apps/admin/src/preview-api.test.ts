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

  it('keeps source addition paused in preview while preserving existing sources and Team editing', async () => {
    vi.stubEnv('VITE_GATEWAY_UI_PREVIEW', '1')
    window.history.replaceState(null, '', '/sources?preview=ready')
    const api = previewApi()
    const saved = await api.getSources()
    expect(saved.installationEnabled).toBe(false)
    await expect(api.prepareSourceAction(saved.revision, 'source-2222222222222222')).rejects.toEqual(expect.objectContaining({ code: 'source_addition_paused' }))
    await expect(api.saveSourceDraft(saved.revision, { label: 'New draft', url: 'https://new.example.com/mcp', authMode: 'none', enabledTools: ['search'] })).rejects.toEqual(expect.objectContaining({ code: 'source_addition_paused' }))
    expect(await api.getSources()).toEqual(saved)
    expect((await api.getTeam()).editingEnabled).toBe(true)
  })

  it('retains a locked recovery proposal through reauthorization and never offers cancellation', async () => {
    vi.stubEnv('VITE_GATEWAY_UI_PREVIEW', '1')
    window.history.replaceState(null, '', '/team?preview=team-recovery')
    const api = previewApi()
    const saved = await api.getTeam()
    expect(saved.pendingAction?.canCancel).toBe(false)
    await expect(api.prepareTeamAction(saved.revision, saved.members)).rejects.toThrow()
    if (!saved.proposedMembers) throw new Error('Expected a recorded synthetic proposal')
    const prepared = await api.prepareTeamAction(saved.revision, saved.proposedMembers)
    expect(await api.getTeamAction(prepared.actionId)).toEqual(expect.objectContaining({ status: 'authorization_required', canCancel: false }))
    await expect(api.cancelTeamAction(prepared.actionId)).rejects.toThrow()
    expect((await api.getTeam()).members).toEqual(saved.members)
  })

  it('simulates canceling an unstarted recorded change without changing saved permissions', async () => {
    vi.stubEnv('VITE_GATEWAY_UI_PREVIEW', '1')
    window.history.replaceState(null, '', '/team?preview=ready')
    const api = previewApi()
    const saved = await api.getTeam()
    const proposal = saved.members.map((member) => ({ ...member, sourceIds: [] }))
    const prepared = await api.prepareTeamAction(saved.revision, proposal)
    expect(await api.getTeamAction(prepared.actionId)).toEqual(expect.objectContaining({ canCancel: true }))
    expect(await api.cancelTeamAction(prepared.actionId)).toEqual(expect.objectContaining({ status: 'failed', failureCode: 'team_action_cancelled', canCancel: false }))
    expect(await api.getTeam()).toEqual(expect.objectContaining({ members: saved.members, proposedMembers: null, revision: saved.revision }))
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
