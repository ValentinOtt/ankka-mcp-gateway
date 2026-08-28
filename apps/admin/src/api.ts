import * as v from 'valibot'

const sourceAuthModeSchema = v.picklist(['none', 'oauth'])
const sourceStatusSchema = v.picklist(['installed', 'draft'])
const runtimeOperationSchema = v.picklist(['update', 'rollback'])
const actionStatusSchema = v.picklist([
  'authorization_required',
  'applying',
  'succeeded',
  'failed',
  'recovery_required',
])
const runtimeVersionSchema = v.strictObject({
  release: v.string(),
  artifactSha256: v.string(),
})
const preparedActionSchema = v.strictObject({
  schemaVersion: v.literal(1),
  actionId: v.string(),
  status: v.literal('authorization_required'),
  expiresAt: v.string(),
  handoffUrl: v.string(),
})
const gatewayStatusSchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: v.literal('ready'),
  release: v.string(),
  gateway: v.strictObject({
    name: v.string(),
    hostname: v.string(),
    mcpUrl: v.string(),
    capabilityMode: v.literal('read_only'),
    codeMode: v.literal('default_on'),
  }),
  source: v.nullable(v.strictObject({
    label: v.string(),
    endpoint: v.string(),
    enabledTools: v.array(v.string()),
  })),
  access: v.strictObject({
    administratorCount: v.number(),
    memberCount: v.number(),
  }),
  updatedAt: v.string(),
})
const managedSourceSchema = v.strictObject({
  id: v.string(),
  label: v.string(),
  url: v.string(),
  authMode: sourceAuthModeSchema,
  enabledTools: v.array(v.string()),
  status: sourceStatusSchema,
})
const managedSourcesSchema = v.strictObject({
  schemaVersion: v.literal(1),
  revision: v.number(),
  applyMode: v.literal('oauth_per_action'),
  sources: v.array(managedSourceSchema),
})
const discoveredToolSchema = v.strictObject({
  name: v.string(),
  title: v.optional(v.string()),
  description: v.optional(v.string()),
  readOnlyHint: v.optional(v.boolean()),
  destructiveHint: v.optional(v.boolean()),
  openWorldHint: v.optional(v.boolean()),
  defaultSelected: v.optional(v.boolean()),
})
const sourceDiscoverySchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: v.picklist(['discovered', 'authorization_required']),
  endpoint: v.string(),
  protocolVersion: v.nullable(v.string()),
  authentication: sourceAuthModeSchema,
  tools: v.array(discoveredToolSchema),
})
const sourceActionSchema = v.strictObject({
  schemaVersion: v.literal(1),
  actionId: v.string(),
  sourceId: v.string(),
  status: actionStatusSchema,
  expiresAt: v.string(),
  failureCode: v.nullable(v.string()),
})
const runtimeUpdateSchema = v.strictObject({
  schemaVersion: v.literal(1),
  channel: v.picklist(['canary', 'stable']),
  status: v.picklist(['available', 'up_to_date', 'newer_than_channel', 'unavailable']),
  current: v.nullable(runtimeVersionSchema),
  available: v.nullable(v.strictObject({
    release: v.string(),
    artifactSha256: v.string(),
    sourceCommit: v.string(),
    classification: v.strictObject({
      kind: v.literal('normal'),
      updaterProtocol: v.literal(2),
      changes: v.array(v.string()),
      excludes: v.array(v.string()),
    }),
    notes: v.array(v.string()),
  })),
  rollback: v.union([
    v.strictObject({ available: v.literal(false) }),
    v.strictObject({
      available: v.literal(true),
      release: v.string(),
      artifactSha256: v.string(),
      dataRollback: v.literal(false),
    }),
  ]),
})
const runtimeActionSchema = v.strictObject({
  schemaVersion: v.literal(1),
  actionId: v.string(),
  operation: runtimeOperationSchema,
  status: actionStatusSchema,
  stage: v.nullable(v.string()),
  from: runtimeVersionSchema,
  to: runtimeVersionSchema,
  expiresAt: v.string(),
  failureCode: v.nullable(v.string()),
})
const teardownActionSchema = v.strictObject({
  schemaVersion: v.literal(1),
  actionId: v.string(),
  status: actionStatusSchema,
  expiresAt: v.string(),
  failureCode: v.nullable(v.string()),
})
const runtimePreparedActionSchema = v.strictObject({
  schemaVersion: v.literal(1),
  actionId: v.string(),
  status: v.literal('authorization_required'),
  expiresAt: v.string(),
  handoffUrl: v.string(),
  operation: runtimeOperationSchema,
})
const errorResponseSchema = v.object({ error: v.string() })

export type SourceAuthMode = v.InferOutput<typeof sourceAuthModeSchema>
export type SourceStatus = v.InferOutput<typeof sourceStatusSchema>
export type RuntimeOperation = v.InferOutput<typeof runtimeOperationSchema>
export type ActionStatus = v.InferOutput<typeof actionStatusSchema>
export type GatewayStatus = v.InferOutput<typeof gatewayStatusSchema>
export type ManagedSource = v.InferOutput<typeof managedSourceSchema>
export type ManagedSources = v.InferOutput<typeof managedSourcesSchema>
export type DiscoveredTool = v.InferOutput<typeof discoveredToolSchema>
export type SourceDiscovery = v.InferOutput<typeof sourceDiscoverySchema>

export interface SourceDraftInput {
  label: string
  url: string
  authMode: SourceAuthMode
  enabledTools: string[]
}

export type PreparedAction = v.InferOutput<typeof preparedActionSchema>
export type SourceAction = v.InferOutput<typeof sourceActionSchema>
export type RuntimeVersion = v.InferOutput<typeof runtimeVersionSchema>
export type RuntimeUpdate = v.InferOutput<typeof runtimeUpdateSchema>
export type RuntimeAction = v.InferOutput<typeof runtimeActionSchema>
export type TeardownAction = v.InferOutput<typeof teardownActionSchema>

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

const ERROR_MESSAGES = new Map([
  ['access_required', 'Your Cloudflare Access session is no longer active. Sign in again and refresh.'],
  ['origin_required', 'Reload this management page before making changes.'],
  ['source_action_conflict', 'This source already has an active authorization or changed in another tab.'],
  ['source_action_invalid', 'The source action no longer matches the saved draft.'],
  ['source_authentication_changed', 'The endpoint authentication mode changed. Inspect it again before saving.'],
  ['source_authentication_unsupported', 'The endpoint did not return the standard MCP OAuth discovery challenge.'],
  ['source_conflict', 'The source list changed in another tab. Refresh and try again.'],
  ['source_invalid', 'The source draft was rejected. Review its endpoint and exact tool selection.'],
  ['source_protocol_unsupported', 'The endpoint did not accept a supported MCP discovery protocol.'],
  ['source_response_invalid', 'The endpoint returned an invalid or oversized MCP response.'],
  ['source_tool_list_invalid', 'The endpoint returned an invalid or duplicate tool catalogue.'],
  ['source_tools_changed', 'The tool catalogue changed. Inspect it again before saving.'],
  ['source_unreachable', 'The MCP endpoint could not be reached within the discovery deadline.'],
  ['source_url_invalid', 'Enter a public HTTPS MCP endpoint without credentials, query parameters, or a custom port.'],
  ['runtime_action_conflict', 'Another runtime action is active or the installed version changed.'],
  ['runtime_action_invalid', 'The runtime action is no longer valid.'],
  ['runtime_update_not_available', 'The installed runtime already matches its release channel.'],
  ['teardown_action_conflict', 'Another teardown action is active or the installed receipt could not be proven. Wait for the active action to expire before trying again.'],
  ['teardown_action_invalid', 'The teardown request was rejected. Reload the management page before trying again.'],
  ['teardown_actions_unavailable', 'Receipt-authorized teardown is not available from this gateway release.'],
  ['update_channel_unavailable', 'The signed release channel is temporarily unavailable.'],
])

export class GatewayApiError extends Error {
  readonly status: number
  readonly code: string

  constructor(status: number, code: string) {
    super(ERROR_MESSAGES.get(code) ?? 'The gateway request failed. Refresh and try again.')
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
  getStatus(): Promise<GatewayStatus> { return this.#request('/api/status', gatewayStatusSchema) }
  getSources(): Promise<ManagedSources> { return this.#request('/api/sources', managedSourcesSchema) }
  getUpdate(): Promise<RuntimeUpdate> { return this.#request('/api/update', runtimeUpdateSchema) }

  discoverSource(url: string): Promise<SourceDiscovery> {
    return this.#request('/api/sources/discover', sourceDiscoverySchema, {
      method: 'POST', body: JSON.stringify({ url }),
    })
  }

  saveSourceDraft(revision: number, source: SourceDraftInput): Promise<ManagedSources> {
    return this.#request('/api/sources', managedSourcesSchema, {
      method: 'PUT',
      body: JSON.stringify({
        schemaVersion: 1,
        revision,
        source: { ...source, enabledTools: [...new Set(source.enabledTools)].sort() },
      }),
    })
  }

  prepareSourceAction(revision: number, sourceId: string): Promise<PreparedAction> {
    return this.#request('/api/source-actions', preparedActionSchema, {
      method: 'POST', body: JSON.stringify({ schemaVersion: 1, revision, sourceId }),
    })
  }

  getSourceAction(actionId: string): Promise<SourceAction> {
    return this.#request(`/api/source-actions/${encodeURIComponent(actionId)}`, sourceActionSchema)
  }

  cancelSourceAction(actionId: string): Promise<SourceAction> {
    return this.#request(`/api/source-actions/${encodeURIComponent(actionId)}`, sourceActionSchema, {
      method: 'DELETE', body: '{}',
    })
  }

  prepareRuntimeAction(operation: RuntimeOperation): Promise<PreparedAction & { operation: RuntimeOperation }> {
    return this.#request('/api/update-actions', runtimePreparedActionSchema, {
      method: 'POST', body: JSON.stringify({ schemaVersion: 1, operation }),
    })
  }

  getRuntimeAction(actionId: string): Promise<RuntimeAction> {
    return this.#request(`/api/update-actions/${encodeURIComponent(actionId)}`, runtimeActionSchema)
  }

  prepareTeardownAction(): Promise<PreparedAction> {
    return this.#request('/api/teardown-actions', preparedActionSchema, {
      method: 'POST', body: JSON.stringify({ schemaVersion: 1 }),
    })
  }

  getTeardownAction(actionId: string): Promise<TeardownAction> {
    return this.#request(`/api/teardown-actions/${encodeURIComponent(actionId)}`, teardownActionSchema)
  }

  async #request<TSchema extends v.GenericSchema>(
    path: string,
    schema: TSchema,
    init: RequestInit = {},
  ): Promise<v.InferOutput<TSchema>> {
    const requestInit: RequestInit = {
      ...init,
      credentials: 'same-origin',
      redirect: 'error',
      headers: {
        accept: 'application/json',
        ...init.headers,
      },
    }
    if (init.body !== undefined) {
      requestInit.headers = { ...requestInit.headers, 'content-type': 'application/json' }
    }
    const response = await fetch(path, requestInit)
    const payload = await response.json().catch(() => null)
    if (!response.ok) {
      const parsed = v.safeParse(errorResponseSchema, payload)
      const code = parsed.success ? parsed.output.error : 'request_failed'
      throw new GatewayApiError(response.status, code)
    }
    return v.parse(schema, payload)
  }
}
