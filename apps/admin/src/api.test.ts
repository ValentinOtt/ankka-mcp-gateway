import { afterEach, describe, expect, it, vi } from 'vitest'
import { GatewayApiError, HttpGatewayAdminApi, validHandoffUrl } from './api'

describe('HttpGatewayAdminApi', () => {
  afterEach(() => { vi.unstubAllGlobals() })

  const readyStatus = {
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
    access: { administratorCount: 1, memberCount: 2 },
    updatedAt: '2026-08-29T00:00:00.000Z',
  } as const

  it('renews an exact source action through its same-origin endpoint', async () => {
    const actionId = `action_${'a'.repeat(32)}`
    const prepared = { schemaVersion: 1, actionId, status: 'authorization_required',
      expiresAt: '2030-01-01T00:00:00.000Z', handoffUrl: 'https://manage.example.com/__ankka/operation#synthetic' }
    const fetch = vi.fn(async () => Response.json(prepared))
    vi.stubGlobal('fetch', fetch)
    await expect(new HttpGatewayAdminApi().prepareSourceAction(4, 'source-test', actionId)).resolves.toEqual(prepared)
    expect(fetch).toHaveBeenCalledExactlyOnceWith(`/api/source-actions/${actionId}/renew`, expect.objectContaining({
      method: 'POST', body: JSON.stringify({ schemaVersion: 1, revision: 4, sourceId: 'source-test' }),
    }))
  })

  it('accepts the protected public BigQuery catalogue with nullable summaries and a fixed setup block', async () => {
    const discovery = {
      schemaVersion: 1, status: 'authorization_required', endpoint: 'https://bigquery.googleapis.com/mcp',
      protocolVersion: '2026-07-28', authentication: 'oauth',
      connectionBlock: 'source_google_shared_oauth_unsupported',
      tools: [{ name: 'execute_sql_readonly', title: null, description: null,
        readOnlyHint: true, destructiveHint: false, openWorldHint: null, defaultSelected: true }],
    }
    vi.stubGlobal('fetch', vi.fn(async () => Response.json(discovery)))
    await expect(new HttpGatewayAdminApi().discoverSource(discovery.endpoint)).resolves.toEqual(discovery)
  })

  it('renders only the fixed Google compatibility error, never provider details', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({
      error: 'source_google_shared_oauth_unsupported', detail: 'synthetic-sensitive-provider-response',
    }, { status: 409 })))
    await expect(new HttpGatewayAdminApi().saveSourceDraft(0, {
      label: 'GA4 example', url: 'https://bigquery.googleapis.com/mcp', authMode: 'oauth', enabledTools: ['execute_sql_readonly'],
    })).rejects.toEqual(expect.objectContaining({
      code: 'source_google_shared_oauth_unsupported',
      message: expect.stringContaining('without an admin credential flow'),
    }))
  })

  it('saves an exact sorted source draft through the production API', async () => {
    let capturedInit: RequestInit | undefined
    const fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      capturedInit = init
      return new Response(JSON.stringify({ schemaVersion: 1, revision: 8, applyMode: 'oauth_per_action', sources: [] }), {
        status: 200, headers: { 'content-type': 'application/json' },
      })
    })
    vi.stubGlobal('fetch', fetch)

    await new HttpGatewayAdminApi().saveSourceDraft(7, {
      label: 'Knowledge', url: 'https://knowledge.example.com/mcp', authMode: 'none',
      enabledTools: ['search', 'fetch', 'search'],
    })

    expect(fetch).toHaveBeenCalledWith('/api/sources', expect.objectContaining({
      method: 'PUT', credentials: 'same-origin', redirect: 'error',
    }))
    expect(JSON.parse(String(capturedInit?.body))).toEqual({
      schemaVersion: 1,
      revision: 7,
      source: {
        label: 'Knowledge', url: 'https://knowledge.example.com/mcp', authMode: 'none',
        enabledTools: ['fetch', 'search'],
      },
    })
  })

  it('turns fixed Worker error codes into safe local messages', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: 'source_conflict' }), {
      status: 409, headers: { 'content-type': 'application/json' },
    })))
    await expect(new HttpGatewayAdminApi().getSources()).rejects.toEqual(
      expect.objectContaining<Partial<GatewayApiError>>({ status: 409, code: 'source_conflict' }),
    )
  })

  it('discovers source actions without requiring a saved action identifier or authorization fragment', async () => {
    const actionId = `action_${'a'.repeat(32)}`
    const action = {
      schemaVersion: 1, actionId, sourceId: 'source-1111111111111111', status: 'authorization_required',
      issuedAt: '2030-01-01T00:00:00.000Z', expiresAt: '2030-01-01T00:10:00.000Z',
      state: 'authorization_expired', failureCode: null, canCancel: true,
    }
    const snapshot = { schemaVersion: 1, actions: [action], blockingAction: { kind: 'source', actionId, sourceId: action.sourceId } }
    const fetch = vi.fn(async () => Response.json(snapshot))
    vi.stubGlobal('fetch', fetch)
    expect(await new HttpGatewayAdminApi().getSourceActions()).toEqual(snapshot)
    expect(fetch).toHaveBeenCalledExactlyOnceWith('/api/source-actions', expect.objectContaining({ credentials: 'same-origin', redirect: 'error' }))
  })

  it('accepts only a credential-free Cloudflare server configuration link for connection pauses', async () => {
    const connectionUrl = `https://dash.cloudflare.com/${'1'.repeat(32)}/one/access-controls/ai-controls/mcp-server/edit/synthetic-source`
    const action = {
      schemaVersion: 1, actionId: `action_${'a'.repeat(32)}`, sourceId: 'source-1111111111111111',
      status: 'recovery_required', state: 'recovery_required', failureCode: 'source_connection_required',
      issuedAt: '2030-01-01T00:00:00.000Z', expiresAt: '2030-01-01T00:10:00.000Z',
      canCancel: false, canRenew: true, connectionUrl,
    }
    const snapshot = { schemaVersion: 1, actions: [action], blockingAction: null }
    vi.stubGlobal('fetch', vi.fn(async () => Response.json(snapshot)))
    expect(await new HttpGatewayAdminApi().getSourceActions()).toEqual(snapshot)
    for (const invalid of ['javascript:alert(1)', connectionUrl.replace('dash.cloudflare.com', 'other.example.com'),
      `${connectionUrl}?code=synthetic-private-code`, `${connectionUrl}#synthetic-private-fragment`]) {
      vi.stubGlobal('fetch', vi.fn(async () => Response.json({ ...snapshot, actions: [{ ...action, connectionUrl: invalid }] })))
      await expect(new HttpGatewayAdminApi().getSourceActions()).rejects.toThrow()
    }
  })

  it.each([
    ['draft_changed', 'saved source draft changed'],
    ['source_pending', 'source installation is already pending'],
    ['lifecycle_pending', 'Another gateway action is pending'],
    ['recovery_required', 'Source provisioning may have started'],
  ])('preserves the safe %s conflict reason and action pointer', async (reason, message) => {
    const action = { kind: reason === 'lifecycle_pending' ? 'runtime' : 'source', actionId: `action_${'a'.repeat(32)}` }
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({
      schemaVersion: 1, error: 'source_action_conflict', reason, action, detail: 'synthetic-provider-detail',
    }, { status: 409 })))
    const error = await new HttpGatewayAdminApi().prepareSourceAction(4, 'source-1111111111111111').catch((cause: unknown) => cause)
    expect(error).toMatchObject({ code: 'source_action_conflict', reason, action, message: expect.stringContaining(message) })
    expect(JSON.stringify(error)).not.toContain('synthetic-provider-detail')
  })

  it('drops unreviewed conflict reasons and credential-bearing action fields', async () => {
    for (const details of [
      { reason: 'synthetic-provider-detail' },
      { reason: 'source_pending', action: { kind: 'source', actionId: `action_${'a'.repeat(32)}`, handoffUrl: 'synthetic-private-fragment' } },
      { reason: 'source_pending', action: { kind: 'source', actionId: 'synthetic-private-fragment' } },
    ]) {
      vi.stubGlobal('fetch', vi.fn(async () => Response.json({ error: 'source_action_conflict', ...details }, { status: 409 })))
      const error = await new HttpGatewayAdminApi().prepareSourceAction(4, 'source-1111111111111111').catch((cause: unknown) => cause)
      expect(error).toMatchObject({ code: 'source_action_conflict', reason: undefined, action: undefined })
      expect(JSON.stringify(error)).not.toMatch(/synthetic-provider|synthetic-private/u)
    }
  })

  it('does not retain an arbitrary server error code in an exception', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ error: 'synthetic-sensitive-provider-error' }, { status: 503 })))
    const error = await new HttpGatewayAdminApi().getSourceActions().catch((cause: unknown) => cause)
    expect(error).toMatchObject({ code: 'request_failed', status: 503 })
    expect(JSON.stringify(error)).not.toContain('synthetic-sensitive')
  })

  it('fails closed when source-action discovery contains unknown fields or cancellation is not explicit', async () => {
    const action = {
      schemaVersion: 1, actionId: `action_${'a'.repeat(32)}`, sourceId: 'source-1111111111111111',
      status: 'authorization_required', issuedAt: '2030-01-01T00:00:00.000Z', expiresAt: '2030-01-01T00:10:00.000Z',
      state: 'authorization_required', canCancel: true, failureCode: null,
    }
    for (const invalid of [
      { ...action, handoffUrl: 'synthetic-sensitive-fragment' },
      { ...action, canCancel: undefined },
      { ...action, state: 'unreviewed' },
    ]) {
      vi.stubGlobal('fetch', vi.fn(async () => Response.json({ schemaVersion: 1, actions: [invalid], blockingAction: null })))
      const error = await new HttpGatewayAdminApi().getSourceActions().catch((cause: unknown) => cause)
      expect(error).toMatchObject({ code: 'response_invalid', status: 502 })
      expect(error).not.toHaveProperty('issues')
      expect(JSON.stringify(error)).not.toContain('synthetic-sensitive')
    }
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ schemaVersion: 1, actions: [{ ...action, failureCode: 'synthetic-sensitive-provider-response' }], blockingAction: null })))
    const snapshot = await new HttpGatewayAdminApi().getSourceActions()
    expect(snapshot.actions[0]?.failureCode).toBe('source_action_failed')
    expect(JSON.stringify(snapshot)).not.toContain('synthetic-sensitive')
  })

  it('preserves the legacy source status and cancellation response shape', async () => {
    const actionId = `action_${'a'.repeat(32)}`
    const action = { schemaVersion: 1, actionId, sourceId: 'source-1111111111111111', status: 'failed', expiresAt: '2030-01-01T00:10:00.000Z', failureCode: 'source_action_denied' }
    const fetch = vi.fn(async () => Response.json(action))
    vi.stubGlobal('fetch', fetch)
    const api = new HttpGatewayAdminApi()
    expect(await api.getSourceAction(actionId)).toEqual(action)
    expect(await api.cancelSourceAction(actionId)).toEqual(action)
    expect(fetch).toHaveBeenLastCalledWith(`/api/source-actions/${actionId}`, expect.objectContaining({ method: 'DELETE', body: '{}', credentials: 'same-origin', redirect: 'error' }))
  })

  it('sends the exact reviewed runtime target without changing legacy request shape', async () => {
    const action = {
      schemaVersion: 1, actionId: `action_${'a'.repeat(32)}`, status: 'authorization_required',
      expiresAt: '2030-01-01T00:00:00.000Z', handoffUrl: `${window.location.origin}/__ankka/operation#${'a'.repeat(40)}`, operation: 'update',
    }
    const fetch = vi.fn(async () => Response.json(action))
    vi.stubGlobal('fetch', fetch)
    const api = new HttpGatewayAdminApi()
    const expectedTarget = { release: 'gateway-v1.2.3', artifactSha256: `sha256:${'b'.repeat(64)}` }
    await api.prepareRuntimeAction('update', expectedTarget)
    expect(fetch).toHaveBeenLastCalledWith('/api/update-actions', expect.objectContaining({
      body: JSON.stringify({ schemaVersion: 1, operation: 'update', expectedTarget }),
      credentials: 'same-origin', redirect: 'error',
    }))
    await api.prepareRuntimeAction('update')
    expect(fetch).toHaveBeenLastCalledWith('/api/update-actions', expect.objectContaining({
      body: JSON.stringify({ schemaVersion: 1, operation: 'update' }),
    }))
  })

  it('requires explicit source-install availability and defaults an older response to disabled', async () => {
    const base = { schemaVersion: 1, revision: 4, applyMode: 'oauth_per_action', sources: [] }
    for (const installationEnabled of [undefined, false, true]) {
      vi.stubGlobal('fetch', vi.fn(async () => Response.json({ ...base, installationEnabled })))
      expect((await new HttpGatewayAdminApi().getSources()).installationEnabled).toBe(installationEnabled === true)
    }
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ ...base, installationEnabled: 'yes' })))
    await expect(new HttpGatewayAdminApi().getSources()).rejects.toThrow()
  })

  it('shows the fixed source-addition pause without exposing provider details or a handoff', async () => {
    const fetch = vi.fn(async () => Response.json({ error: 'source_addition_paused', retryable: false, detail: 'private provider response' }, { status: 409 }))
    vi.stubGlobal('fetch', fetch)
    const api = new HttpGatewayAdminApi()
    for (const request of [
      api.prepareSourceAction(4, 'source-1111111111111111'),
      api.saveSourceDraft(4, { label: 'Knowledge', url: 'https://knowledge.example.com/mcp', authMode: 'none', enabledTools: ['search'] }),
    ]) await expect(request).rejects.toEqual(expect.objectContaining({ code: 'source_addition_paused', message: 'New-source installation is temporarily unavailable in this release. Existing sources and team permissions remain available.' }))
  })

  it('saves the exact revision-bound Team batch through one same-origin POST without a handoff', async () => {
    const members = [{ email: 'teammate@example.com', sourceIds: ['source-1111111111111111'] }]
    const actionId = `action_${'a'.repeat(32)}`
    const expiresAt = '2030-01-01T00:00:00.000Z'
    const fetch = vi.fn()
      .mockResolvedValueOnce(Response.json({
        schemaVersion: 1, revision: 4, editingEnabled: true, editingDisabledReason: null, managementCredentialConfigured: true, members, adminEmails: ['admin@example.com'],
        sources: [{ id: 'source-1111111111111111', label: 'Knowledge', enabledTools: ['search'], status: 'installed' }],
        pendingAction: null, proposedMembers: null,
      }))
      .mockResolvedValueOnce(Response.json({ schemaVersion: 1, action: { schemaVersion: 1, action: 'access', actionId, status: 'succeeded', expiresAt, failureCode: null, canCancel: false } }))
      .mockResolvedValueOnce(Response.json({ schemaVersion: 1, actionId, status: 'recovery_required', expiresAt, failureCode: 'team_recovery_required' }))
    vi.stubGlobal('fetch', fetch)
    const api = new HttpGatewayAdminApi()

    expect(await api.getTeam()).toEqual(expect.objectContaining({ revision: 4, proposedMembers: null, managementCredentialConfigured: true }))
    expect(await api.prepareTeamAction(4, members)).toEqual({ schemaVersion: 1, action: { schemaVersion: 1, action: 'access', actionId, status: 'succeeded', expiresAt, failureCode: null, canCancel: false } })
    expect(await api.getTeamAction(actionId)).toEqual(expect.objectContaining({ status: 'recovery_required' }))
    expect(fetch).toHaveBeenNthCalledWith(1, '/api/team', expect.objectContaining({ credentials: 'same-origin', redirect: 'error' }))
    expect(fetch).toHaveBeenNthCalledWith(2, '/api/team-actions', expect.objectContaining({
      method: 'POST', credentials: 'same-origin', redirect: 'error',
      body: JSON.stringify({ schemaVersion: 1, expectedRevision: 4, members }),
    }))
    expect(fetch).toHaveBeenNthCalledWith(3, `/api/team-actions/${actionId}`, expect.objectContaining({ credentials: 'same-origin' }))
    expect(fetch).toHaveBeenCalledTimes(3)
    expect(fetch.mock.calls.every(([path]) => String(path).startsWith('/api/'))).toBe(true)
  })

  it('rejects legacy Team OAuth handoffs and unexpected fields from the local Save response', async () => {
    const actionId = `action_${'a'.repeat(32)}`
    const expiresAt = '2030-01-01T00:00:00.000Z'
    const action = { schemaVersion: 1, action: 'access', actionId, status: 'succeeded', expiresAt, failureCode: null, canCancel: false }
    const handoffUrl = `${window.location.origin}/__ankka/operation#${'a'.repeat(40)}`
    for (const payload of [
      { schemaVersion: 1, actionId, status: 'authorization_required', expiresAt, handoffUrl },
      { schemaVersion: 1, action: { ...action, status: 'authorization_required' } },
      { schemaVersion: 1, action, handoffUrl },
      { schemaVersion: 1, action: { ...action, token: 'synthetic-disallowed-field' } },
    ]) {
      const fetch = vi.fn(async () => Response.json(payload))
      vi.stubGlobal('fetch', fetch)
      await expect(new HttpGatewayAdminApi().prepareTeamAction(4, [])).rejects.toThrow()
      expect(fetch).toHaveBeenCalledExactlyOnceWith('/api/team-actions', expect.objectContaining({ redirect: 'error' }))
    }
  })

  it('does not expose raw team failure details', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ error: 'team_action_conflict', detail: 'provider private response' }, { status: 409 })))
    await expect(new HttpGatewayAdminApi().prepareTeamAction(1, [])).rejects.toEqual(expect.objectContaining({
      code: 'team_action_conflict', message: 'A team access change is already in progress. Refresh to review or resume it.',
    }))
  })

  it('defaults cancellation to denied when an older Team action omits explicit capability', async () => {
    const actionId = `action_${'a'.repeat(32)}`
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ schemaVersion: 1, actionId, status: 'authorization_required', expiresAt: '2030-01-01T00:00:00.000Z', failureCode: null })))
    expect(await new HttpGatewayAdminApi().getTeamAction(actionId)).toEqual(expect.objectContaining({ canCancel: false }))
  })

  it('accepts the exact runtime Team action projection in saved snapshots and action responses', async () => {
    const actionId = `action_${'a'.repeat(32)}`
    const expiresAt = '2030-01-01T00:00:00.000Z'
    const members = [{ email: 'admin@example.com', sourceIds: [] }]
    for (const [status, failureCode, canCancel] of [
      ['authorization_required', null, true],
      ['applying', null, false],
      ['recovery_required', 'team_policy_drift', false],
      ['succeeded', null, false],
      ['failed', 'team_action_cancelled', false],
    ] as const) {
      const pendingAction = { schemaVersion: 1, action: 'access', actionId, status, expiresAt, failureCode, canCancel }
      const proposedMembers = status === 'succeeded' || status === 'failed' ? null : members
      vi.stubGlobal('fetch', vi.fn()
        .mockResolvedValueOnce(Response.json({
          schemaVersion: 1, revision: 4, editingEnabled: true, editingDisabledReason: null, managementCredentialConfigured: true,
          members, adminEmails: ['admin@example.com'], sources: [], pendingAction, proposedMembers,
        }))
        .mockResolvedValueOnce(Response.json(pendingAction)))
      const api = new HttpGatewayAdminApi()
      expect((await api.getTeam()).pendingAction).toEqual(pendingAction)
      expect(await api.getTeamAction(actionId)).toEqual(pendingAction)
    }
  })

  it('rejects other action kinds and unreviewed fields in the strict Team action contract', async () => {
    const actionId = `action_${'a'.repeat(32)}`
    const action = { schemaVersion: 1, action: 'access', actionId, status: 'authorization_required', expiresAt: '2030-01-01T00:00:00.000Z', failureCode: null, canCancel: true }
    for (const extra of [{ action: 'install' }, { action: 'teardown' }, { unreviewedField: true }]) {
      vi.stubGlobal('fetch', vi.fn(async () => Response.json({ ...action, ...extra })))
      await expect(new HttpGatewayAdminApi().getTeamAction(actionId)).rejects.toThrow()
    }
  })

  it('cancels only the exact recorded Team action through a same-origin request', async () => {
    const actionId = `action_${'a'.repeat(32)}`
    const fetch = vi.fn(async () => Response.json({ schemaVersion: 1, action: 'access', actionId, status: 'failed', expiresAt: '2030-01-01T00:00:00.000Z', failureCode: 'team_action_cancelled', canCancel: false }))
    vi.stubGlobal('fetch', fetch)
    expect(await new HttpGatewayAdminApi().cancelTeamAction(actionId)).toEqual(expect.objectContaining({ status: 'failed', canCancel: false }))
    expect(fetch).toHaveBeenCalledWith(`/api/team-actions/${actionId}`, expect.objectContaining({ method: 'DELETE', credentials: 'same-origin', redirect: 'error', body: '{}' }))
  })

  it('accepts larger Team rosters while retaining field, source, and tool validation', async () => {
    const person = { email: 'teammate@example.com', sourceIds: [] }
    const source = { id: 'source-1111111111111111', label: 'Knowledge', enabledTools: ['search'], status: 'installed' }
    const validTeam = {
      schemaVersion: 1, revision: 4, editingEnabled: true, editingDisabledReason: null, managementCredentialConfigured: true,
      members: [person], adminEmails: ['admin@example.com'], sources: [source], pendingAction: null, proposedMembers: null,
    }
    const members = Array.from({ length: 100 }, (_, index) => ({ email: `user${index}@example.com`, sourceIds: [] }))
    const largeTeam = { ...validTeam, members, proposedMembers: members, adminEmails: members.map(({ email }) => email) }
    vi.stubGlobal('fetch', vi.fn(async () => Response.json(largeTeam)))
    expect(await new HttpGatewayAdminApi().getTeam()).toEqual(largeTeam)
    for (const invalid of [
      { members: [{ ...person, sourceIds: Array(33).fill(source.id) }] },
      { sources: Array(33).fill(source) },
      { sources: [{ ...source, enabledTools: Array(501).fill('search') }] },
      { members: [{ ...person, email: `${'a'.repeat(255)}@example.com` }] },
      { revision: 1.5 },
      { revision: -1 },
      { managementCredentialConfigured: undefined },
      { managementCredentialConfigured: 'yes' },
    ]) {
      vi.stubGlobal('fetch', vi.fn(async () => Response.json({ ...validTeam, ...invalid })))
      await expect(new HttpGatewayAdminApi().getTeam()).rejects.toThrow()
    }
  })

  it('maps native Team policy and lifecycle errors to fixed safe local explanations', async () => {
    for (const [code, explanation] of [
      ['team_access_revision_conflict', 'Team access changed in another tab'],
      ['team_action_recovery_required', 'Some access policies may already have changed'],
      ['team_policy_drift', 'Cloudflare access policies no longer match'],
      ['team_editing_managed_in_cloudflare', 'managed directly in Cloudflare'],
      ['team_management_credential_missing', 'legacy Team action cannot continue'],
      ['team_management_credential_invalid', 'legacy Team action cannot continue'],
      ['team_teardown_requires_compatible_release', 'Automatic removal is unavailable'],
    ] as const) {
      vi.stubGlobal('fetch', vi.fn(async () => Response.json({ error: code, detail: 'private provider detail' }, { status: 409 })))
      await expect(new HttpGatewayAdminApi().prepareTeamAction(1, [])).rejects.toEqual(expect.objectContaining({ code, message: expect.stringContaining(explanation) }))
    }
  })

  it('keeps teardown failures local and free of provider response text', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      error: 'teardown_action_conflict',
      detail: 'provider token and response text must not be rendered',
    }), {
      status: 409, headers: { 'content-type': 'application/json' },
    })))
    await expect(new HttpGatewayAdminApi().prepareTeardownAction()).rejects.toEqual(
      expect.objectContaining<Partial<GatewayApiError>>({
        status: 409,
        code: 'teardown_action_conflict',
        message: expect.not.stringContaining('provider token'),
      }),
    )
  })

  it('accepts only this gateway’s own operation handoff shape', () => {
    const expected = 'https://manage.example.com'
    expect(validHandoffUrl(`${expected}/__ankka/operation#${'a'.repeat(40)}`, expected)).toContain('/__ankka/operation#')
    expect(validHandoffUrl(`https://evil.example/__ankka/operation#${'a'.repeat(40)}`, expected)).toBeNull()
    expect(validHandoffUrl(`https://user:password@manage.example.com/__ankka/operation#${'a'.repeat(40)}`, expected)).toBeNull()
    expect(validHandoffUrl(`${expected}/__ankka/operation?token=secret`, expected)).toBeNull()
    // The retired hosted handoff is never navigated to, even from a trusted control plane.
    expect(validHandoffUrl(`${expected}/manage#${'a'.repeat(40)}`, expected)).toBeNull()
    expect(validHandoffUrl(`https://deploy.ankka.ai/__ankka/operation#${'a'.repeat(40)}`, expected)).toBeNull()
    expect(validHandoffUrl(`${expected}/__ankka/operation#${'a'.repeat(40)}`, `${expected}/path`)).toBeNull()
  })

  it('rejects a non-canonical control-plane origin in management status', async () => {
    for (const controlPlaneOrigin of [
      'http://deploy.ankka.ai',
      'https://deploy.ankka.ai/',
      'https://deploy.ankka.ai/path',
      'https://deploy.ankka.ai?view=status',
      'https://deploy.ankka.ai#status',
      'https://deploy.ankka.ai:443',
      'https://owner@deploy.ankka.ai',
    ]) {
      vi.stubGlobal('fetch', vi.fn(async () => Response.json({
        ...readyStatus,
        controlPlaneOrigin,
      })))
      await expect(new HttpGatewayAdminApi().getStatus()).rejects.toThrow()
      vi.unstubAllGlobals()
    }
  })
})
