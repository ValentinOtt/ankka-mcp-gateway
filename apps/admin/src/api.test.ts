import { afterEach, describe, expect, it, vi } from 'vitest'
import { GatewayApiError, HttpGatewayAdminApi, validHandoffUrl } from './api'

describe('HttpGatewayAdminApi', () => {
  afterEach(() => { vi.unstubAllGlobals() })

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

  it('accepts only the short-lived hosted management handoff shape', () => {
    expect(validHandoffUrl(`https://deploy.ankka.ai/manage#${'a'.repeat(40)}`)).toContain('/manage#')
    expect(validHandoffUrl(`https://evil.example/manage#${'a'.repeat(40)}`)).toBeNull()
    expect(validHandoffUrl(`https://user:password@deploy.ankka.ai/manage#${'a'.repeat(40)}`)).toBeNull()
    expect(validHandoffUrl('https://deploy.ankka.ai/manage?token=secret')).toBeNull()
  })
})
