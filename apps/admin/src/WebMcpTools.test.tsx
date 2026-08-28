import { render, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { GatewayAdminApi, GatewayStatus, ManagedSources, RuntimeUpdate } from './api'
import { GatewayProvider } from './GatewayContext'
import { WebMcpTools } from './WebMcpTools'

const status: GatewayStatus = {
  schemaVersion: 1,
  status: 'ready',
  release: 'gateway-v1.0.0',
  gateway: {
    name: 'Example Gateway',
    hostname: 'mcp.example.com',
    mcpUrl: 'https://mcp.example.com/mcp',
    capabilityMode: 'read_only',
    codeMode: 'default_on',
  },
  source: null,
  access: { administratorCount: 1, memberCount: 0 },
  updatedAt: '2026-08-27T12:00:00.000Z',
}
const sources: ManagedSources = {
  schemaVersion: 1,
  revision: 1,
  applyMode: 'oauth_per_action',
  sources: [],
}
const update: RuntimeUpdate = {
  schemaVersion: 1,
  channel: 'stable',
  status: 'up_to_date',
  current: { release: 'gateway-v1.0.0', artifactSha256: `sha256:${'a'.repeat(64)}` },
  available: null,
  rollback: { available: false },
}

describe('WebMcpTools', () => {
  afterEach(() => { delete document.modelContext })

  it('registers teardown as a destructive review handoff without accepting credentials', async () => {
    const prepared = {
      schemaVersion: 1 as const,
      actionId: `action_${'a'.repeat(32)}`,
      status: 'authorization_required' as const,
      expiresAt: '2026-08-27T12:10:00.000Z',
      handoffUrl: `https://deploy.ankka.ai/manage#${'b'.repeat(40)}`,
    }
    const prepareTeardownAction = vi.fn(async () => prepared)
    const api: GatewayAdminApi = {
      getStatus: vi.fn(async () => status),
      getSources: vi.fn(async () => sources),
      getUpdate: vi.fn(async () => update),
      discoverSource: vi.fn(),
      saveSourceDraft: vi.fn(),
      prepareSourceAction: vi.fn(),
      getSourceAction: vi.fn(),
      cancelSourceAction: vi.fn(),
      prepareRuntimeAction: vi.fn(),
      getRuntimeAction: vi.fn(),
      prepareTeardownAction,
      getTeardownAction: vi.fn(),
    }
    const tools: Array<{
      name: string
      annotations: Record<string, boolean>
      execute(input: Record<string, unknown>): Promise<string>
    }> = []
    document.modelContext = {
      registerTool: vi.fn(async (tool) => { tools.push(tool) }),
    }

    render(<GatewayProvider api={api}><WebMcpTools /></GatewayProvider>)
    await waitFor(() => expect(tools.some((tool) => tool.name === 'review_gateway_teardown')).toBe(true))

    const tool = tools.find((candidate) => candidate.name === 'review_gateway_teardown')
    expect(tool?.annotations).toMatchObject({
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    })
    const result = JSON.parse(await tool!.execute({}))
    expect(result).toEqual({
      ok: true,
      result: {
        status: 'user_review_required',
        authorizationUrl: prepared.handoffUrl,
        actionId: prepared.actionId,
        expiresAt: prepared.expiresAt,
        instruction: expect.stringContaining('never request or handle their token'),
      },
    })
    expect(prepareTeardownAction).toHaveBeenCalledTimes(1)
  })
})
