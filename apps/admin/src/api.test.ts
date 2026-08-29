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
    const expected = 'https://canary-deploy.example.com'
    expect(validHandoffUrl(`${expected}/manage#${'a'.repeat(40)}`, expected)).toContain('/manage#')
    expect(validHandoffUrl(`https://evil.example/manage#${'a'.repeat(40)}`, expected)).toBeNull()
    expect(validHandoffUrl(`https://user:password@canary-deploy.example.com/manage#${'a'.repeat(40)}`, expected)).toBeNull()
    expect(validHandoffUrl(`${expected}/manage?token=secret`, expected)).toBeNull()
    expect(validHandoffUrl(`${expected}/manage#${'a'.repeat(40)}`, `${expected}/path`)).toBeNull()
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
