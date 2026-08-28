export type SourceAuthMode = 'none' | 'oauth'
export type SourceStatus = 'installed' | 'draft'
export type RuntimeOperation = 'update' | 'rollback'
export type ActionStatus =
  | 'authorization_required'
  | 'applying'
  | 'succeeded'
  | 'failed'
  | 'recovery_required'

export interface GatewayStatus {
  schemaVersion: 1
  status: 'ready'
  release: string
  gateway: {
    name: string
    hostname: string
    mcpUrl: string
    capabilityMode: 'read_only'
    codeMode: 'default_on'
  }
  source: { label: string; endpoint: string; enabledTools: string[] } | null
  access: { administratorCount: number; memberCount: number }
  updatedAt: string
}

export interface ManagedSource {
  id: string
  label: string
  url: string
  authMode: SourceAuthMode
  enabledTools: string[]
  status: SourceStatus
}

export interface ManagedSources {
  schemaVersion: 1
  revision: number
  applyMode: 'oauth_per_action'
  sources: ManagedSource[]
}

export interface DiscoveredTool {
  name: string
  title?: string
  description?: string
  readOnlyHint?: boolean
  destructiveHint?: boolean
  openWorldHint?: boolean
  defaultSelected?: boolean
}

export interface SourceDiscovery {
  schemaVersion: 1
  status: 'discovered' | 'authorization_required'
  endpoint: string
  protocolVersion: string | null
  authentication: SourceAuthMode
  tools: DiscoveredTool[]
}

export interface SourceDraftInput {
  label: string
  url: string
  authMode: SourceAuthMode
  enabledTools: string[]
}

export interface PreparedAction {
  schemaVersion: 1
  actionId: string
  status: 'authorization_required'
  expiresAt: string
  handoffUrl: string
}

export interface SourceAction {
  schemaVersion: 1
  actionId: string
  sourceId: string
  status: ActionStatus
  expiresAt: string
  failureCode: string | null
}

export interface RuntimeVersion {
  release: string
  artifactSha256: string
}

export interface RuntimeUpdate {
  schemaVersion: 1
  channel: 'canary' | 'stable'
  status: 'available' | 'up_to_date' | 'newer_than_channel' | 'unavailable'
  current: RuntimeVersion | null
  available: (RuntimeVersion & {
    sourceCommit: string
    classification: { kind: string; [key: string]: unknown }
    notes: string[]
  }) | null
  rollback: { available: false } | ({ available: true; release: string; artifactSha256: string; dataRollback: false })
}

export interface RuntimeAction {
  schemaVersion: 1
  actionId: string
  operation: RuntimeOperation
  status: ActionStatus
  stage: string | null
  from: RuntimeVersion
  to: RuntimeVersion
  expiresAt: string
  failureCode: string | null
}

export interface TeardownAction {
  schemaVersion: 1
  actionId: string
  status: ActionStatus
  expiresAt: string
  failureCode: string | null
}

export interface GatewayAdminApi {
  getStatus(): Promise<GatewayStatus>
  getSources(): Promise<ManagedSources>
  getUpdate(): Promise<RuntimeUpdate>
  discoverSource(url: string): Promise<SourceDiscovery>
  saveSourceDraft(revision: number, source: SourceDraftInput): Promise<ManagedSources>
  prepareSourceAction(revision: number, sourceId: string): Promise<PreparedAction>
  getSourceAction(actionId: string): Promise<SourceAction>
  cancelSourceAction(actionId: string): Promise<SourceAction>
  prepareRuntimeAction(operation: RuntimeOperation): Promise<PreparedAction & { operation: RuntimeOperation }>
  getRuntimeAction(actionId: string): Promise<RuntimeAction>
  prepareTeardownAction(): Promise<PreparedAction>
  getTeardownAction(actionId: string): Promise<TeardownAction>
}

const ERROR_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  access_required: 'Your Cloudflare Access session is no longer active. Sign in again and refresh.',
  origin_required: 'Reload this management page before making changes.',
  source_action_conflict: 'This source already has an active authorization or changed in another tab.',
  source_action_invalid: 'The source action no longer matches the saved draft.',
  source_authentication_changed: 'The endpoint authentication mode changed. Inspect it again before saving.',
  source_authentication_unsupported: 'The endpoint did not return the standard MCP OAuth discovery challenge.',
  source_conflict: 'The source list changed in another tab. Refresh and try again.',
  source_invalid: 'The source draft was rejected. Review its endpoint and exact tool selection.',
  source_protocol_unsupported: 'The endpoint did not accept a supported MCP discovery protocol.',
  source_response_invalid: 'The endpoint returned an invalid or oversized MCP response.',
  source_tool_list_invalid: 'The endpoint returned an invalid or duplicate tool catalogue.',
  source_tools_changed: 'The tool catalogue changed. Inspect it again before saving.',
  source_unreachable: 'The MCP endpoint could not be reached within the discovery deadline.',
  source_url_invalid: 'Enter a public HTTPS MCP endpoint without credentials, query parameters, or a custom port.',
  runtime_action_conflict: 'Another runtime action is active or the installed version changed.',
  runtime_action_invalid: 'The runtime action is no longer valid.',
  runtime_update_not_available: 'The installed runtime already matches its release channel.',
  teardown_action_conflict: 'Another teardown action is active or the installed receipt could not be proven. Wait for the active action to expire before trying again.',
  teardown_action_invalid: 'The teardown request was rejected. Reload the management page before trying again.',
  teardown_actions_unavailable: 'Receipt-authorized teardown is not available from this gateway release.',
  update_channel_unavailable: 'The signed release channel is temporarily unavailable.',
})

export class GatewayApiError extends Error {
  readonly status: number
  readonly code: string

  constructor(status: number, code: string) {
    super(ERROR_MESSAGES[code] ?? 'The gateway request failed. Refresh and try again.')
    this.name = 'GatewayApiError'
    this.status = status
    this.code = code
  }
}

export function validHandoffUrl(value: string): string | null {
  try {
    const url = new URL(value)
    return url.origin === 'https://deploy.ankka.ai' && !url.username && !url.password && !url.port &&
      url.pathname === '/manage' &&
      url.search === '' && /^#[A-Za-z0-9_-]{40,4096}$/u.test(url.hash) ? url.href : null
  } catch {
    return null
  }
}

/** Typed same-origin boundary for the customer-resident management Worker. */
export class HttpGatewayAdminApi implements GatewayAdminApi {
  getStatus(): Promise<GatewayStatus> { return this.#request('/api/status') }
  getSources(): Promise<ManagedSources> { return this.#request('/api/sources') }
  getUpdate(): Promise<RuntimeUpdate> { return this.#request('/api/update') }

  discoverSource(url: string): Promise<SourceDiscovery> {
    return this.#request('/api/sources/discover', { method: 'POST', body: JSON.stringify({ url }) })
  }

  saveSourceDraft(revision: number, source: SourceDraftInput): Promise<ManagedSources> {
    return this.#request('/api/sources', {
      method: 'PUT',
      body: JSON.stringify({
        schemaVersion: 1,
        revision,
        source: { ...source, enabledTools: [...new Set(source.enabledTools)].sort() },
      }),
    })
  }

  prepareSourceAction(revision: number, sourceId: string): Promise<PreparedAction> {
    return this.#request('/api/source-actions', {
      method: 'POST', body: JSON.stringify({ schemaVersion: 1, revision, sourceId }),
    })
  }

  getSourceAction(actionId: string): Promise<SourceAction> {
    return this.#request(`/api/source-actions/${encodeURIComponent(actionId)}`)
  }

  cancelSourceAction(actionId: string): Promise<SourceAction> {
    return this.#request(`/api/source-actions/${encodeURIComponent(actionId)}`, {
      method: 'DELETE', body: '{}',
    })
  }

  prepareRuntimeAction(operation: RuntimeOperation): Promise<PreparedAction & { operation: RuntimeOperation }> {
    return this.#request('/api/update-actions', {
      method: 'POST', body: JSON.stringify({ schemaVersion: 1, operation }),
    })
  }

  getRuntimeAction(actionId: string): Promise<RuntimeAction> {
    return this.#request(`/api/update-actions/${encodeURIComponent(actionId)}`)
  }

  prepareTeardownAction(): Promise<PreparedAction> {
    return this.#request('/api/teardown-actions', {
      method: 'POST', body: JSON.stringify({ schemaVersion: 1 }),
    })
  }

  getTeardownAction(actionId: string): Promise<TeardownAction> {
    return this.#request(`/api/teardown-actions/${encodeURIComponent(actionId)}`)
  }

  async #request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await fetch(path, {
      ...init,
      credentials: 'same-origin',
      redirect: 'error',
      headers: {
        accept: 'application/json',
        ...(init.body === undefined ? {} : { 'content-type': 'application/json' }),
        ...init.headers,
      },
    })
    let payload: unknown = null
    try { payload = await response.json() } catch { /* The fixed local error is sufficient. */ }
    if (!response.ok) {
      const code = payload && typeof payload === 'object' && 'error' in payload &&
        typeof payload.error === 'string' ? payload.error : 'request_failed'
      throw new GatewayApiError(response.status, code)
    }
    return payload as T
  }
}
