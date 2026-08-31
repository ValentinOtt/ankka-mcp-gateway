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
const controlPlaneOriginSchema = v.pipe(
  v.string(),
  v.check(validControlPlaneOrigin),
)
const gatewayStatusSchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: v.literal('ready'),
  controlPlaneOrigin: controlPlaneOriginSchema,
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
  onBehalfOfUser: v.boolean(),
  enabledTools: v.array(v.string()),
  status: sourceStatusSchema,
})
const managedSourcesSchema = v.strictObject({
  schemaVersion: v.literal(1),
  revision: v.number(),
  applyMode: v.literal('oauth_per_action'),
  installationEnabled: v.optional(v.boolean(), false),
  sources: v.array(managedSourceSchema),
})
const discoveredToolSchema = v.strictObject({
  name: v.string(),
  title: v.nullish(v.string()),
  description: v.nullish(v.string()),
  readOnlyHint: v.nullish(v.boolean()),
  destructiveHint: v.nullish(v.boolean()),
  openWorldHint: v.nullish(v.boolean()),
  defaultSelected: v.optional(v.boolean()),
})
const sourceDiscoverySchema = v.strictObject({
  schemaVersion: v.literal(1),
  status: v.picklist(['discovered', 'authorization_required']),
  endpoint: v.string(),
  protocolVersion: v.nullable(v.string()),
  authentication: sourceAuthModeSchema,
  tools: v.array(discoveredToolSchema),
  connectionBlock: v.optional(v.literal('source_google_shared_oauth_unsupported')),
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
const teamActionSchema = v.strictObject({
  ...teardownActionSchema.entries,
  action: v.optional(v.literal('access')),
  canCancel: v.optional(v.boolean(), false),
})
const teamActionResultSchema = v.strictObject({
  schemaVersion: v.literal(1),
  action: v.strictObject({
    ...teamActionSchema.entries,
    status: v.picklist(['applying', 'succeeded', 'failed', 'recovery_required']),
  }),
})
export const TEAM_MAX_PEOPLE = 51
const TEAM_MAX_SOURCES = 32
const teamEmailSchema = v.pipe(v.string(), v.minLength(1), v.maxLength(254))
const teamSourceIdSchema = v.pipe(v.string(), v.regex(/^[a-z][a-z0-9-]{0,31}$/u))
const teamMemberSchema = v.strictObject({
  email: teamEmailSchema,
  sourceIds: v.pipe(v.array(teamSourceIdSchema), v.maxLength(TEAM_MAX_SOURCES)),
})
const teamMembersSchema = v.pipe(v.array(teamMemberSchema), v.maxLength(TEAM_MAX_PEOPLE))
const teamSchema = v.strictObject({
  schemaVersion: v.literal(1),
  revision: v.pipe(v.number(), v.integer(), v.minValue(0), v.maxValue(Number.MAX_SAFE_INTEGER - 1)),
  editingEnabled: v.boolean(),
  editingDisabledReason: v.nullable(v.picklist(['release_review_required', 'lifecycle_action_pending'])),
  managementCredentialConfigured: v.boolean(),
  members: teamMembersSchema,
  adminEmails: v.pipe(v.array(teamEmailSchema), v.minLength(1), v.maxLength(TEAM_MAX_PEOPLE)),
  sources: v.pipe(v.array(v.strictObject({
    id: teamSourceIdSchema,
    label: v.pipe(v.string(), v.minLength(1), v.maxLength(80)),
    enabledTools: v.pipe(v.array(v.pipe(v.string(), v.minLength(1), v.maxLength(128))), v.maxLength(500)),
    status: sourceStatusSchema,
  })), v.maxLength(TEAM_MAX_SOURCES)),
  pendingAction: v.nullable(teamActionSchema),
  proposedMembers: v.nullable(teamMembersSchema),
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
export type TeamMember = v.InferOutput<typeof teamMemberSchema>
export type Team = v.InferOutput<typeof teamSchema>
export type TeamAction = v.InferOutput<typeof teamActionSchema>
export type TeamActionResult = v.InferOutput<typeof teamActionResultSchema>

export interface GatewayAdminApi {
  getStatus(): Promise<GatewayStatus>
  getSources(): Promise<ManagedSources>
  getTeam(): Promise<Team>
  prepareTeamAction(expectedRevision: number, members: TeamMember[]): Promise<TeamActionResult>
  getTeamAction(actionId: string): Promise<TeamAction>
  cancelTeamAction(actionId: string): Promise<TeamAction>
  getUpdate(): Promise<RuntimeUpdate>
  discoverSource(url: string): Promise<SourceDiscovery>
  saveSourceDraft(revision: number, source: SourceDraftInput): Promise<ManagedSources>
  prepareSourceAction(revision: number, sourceId: string): Promise<PreparedAction>
  getSourceAction(actionId: string): Promise<SourceAction>
  cancelSourceAction(actionId: string): Promise<SourceAction>
  prepareRuntimeAction(operation: RuntimeOperation, expectedTarget?: RuntimeVersion): Promise<PreparedAction & { operation: RuntimeOperation }>
  getRuntimeAction(actionId: string): Promise<RuntimeAction>
  prepareTeardownAction(): Promise<PreparedAction>
  getTeardownAction(actionId: string): Promise<TeardownAction>
}

export const SOURCE_ADDITION_PAUSED_MESSAGE = 'New-source installation is temporarily unavailable in this release. Existing sources and team permissions remain available.'
export const GOOGLE_SHARED_OAUTH_BLOCK_MESSAGE = 'BigQuery requires a manually registered Google OAuth client. Cloudflare currently documents manual OAuth without an admin credential flow, so one operator connection for your team is not supported. No credentials have been requested. Keep Require user auth off; see the BigQuery setup guide.'

const ERROR_MESSAGES = new Map([
  ['webmcp_input_invalid', 'The tool arguments do not match the declared schema. Review the tool inputs before retrying.'],
  ['webmcp_call_cancelled', 'The call was canceled before the operation started.'],
  ['webmcp_handoff_invalid', 'The authorization handoff could not be verified. Check the recorded action before retrying.'],
  ['access_required', 'Your Cloudflare Access session is no longer active. Sign in again and refresh.'],
  ['origin_required', 'Reload this management page before making changes.'],
  ['team_conflict', 'Team access changed in another tab. Refresh before preparing another change.'],
  ['team_invalid', 'Review the email addresses and installed source selections before trying again.'],
  ['team_action_conflict', 'A team access change is already in progress. Refresh to review or resume it.'],
  ['team_action_invalid', 'The team access action could not be verified. Refresh before trying again.'],
  ['team_recovery_required', 'Some access policies may already have changed. Resume the recorded change before editing access again.'],
  ['team_access_revision_conflict', 'Team access changed in another tab. Refresh before preparing another change.'],
  ['team_access_invalid_request', 'Review the email addresses and installed source selections before trying again.'],
  ['team_access_admin_required', 'Gateway administrators must remain in your team. Their roles cannot be changed here.'],
  ['team_access_invalid_state', 'The saved access configuration could not be verified. Refresh before making changes.'],
  ['team_access_invalid_target', 'The owned access policies could not be verified. No new change can be prepared.'],
  ['team_action_recovery_required', 'Some access policies may already have changed. Resume the recorded change before editing access again.'],
  ['team_policy_drift', 'Cloudflare access policies no longer match the saved configuration. Review the Cloudflare policies before trying again. This page will not reset them automatically.'],
  ['team_release_review_required', 'Team access editing is not available in this gateway release.'],
  ['team_management_credential_missing', 'Add a dedicated Cloudflare management API token directly to your gateway Worker as the encrypted secret ANKKA_TEAM_MANAGEMENT_TOKEN, then refresh. Never paste the token into this dashboard or send it to Ankka.'],
  ['team_management_credential_invalid', 'Cloudflare rejected the gateway’s management credential. Check its expiry, account, and Access permissions, or replace ANKKA_TEAM_MANAGEMENT_TOKEN directly in your Worker’s secrets, then refresh and resume the recorded change. Do not send the token to Ankka.'],
  ['team_prepare_failed', 'The team access request could not be confirmed. Refresh to check whether a change was recorded before trying again.'],
  ['team_cancel_failed', 'Cancellation could not be confirmed. Refresh to check the recorded change before trying again.'],
  ['team_teardown_requires_compatible_release', 'Automatic removal is unavailable after source provisioning or team policy changes begin. A compatible removal release is required; do not discard the ownership or recovery records.'],
  ['source_action_conflict', 'Another gateway action is pending, or the source draft changed. Refresh to review the saved state.'],
  ['source_action_legacy_policy', 'This source authorization uses an older permission policy. Cancel it only if provisioning never started; otherwise retain its journal for reconciliation.'],
  ['source_action_invalid', 'The source action no longer matches the saved draft.'],
  ['source_addition_paused', SOURCE_ADDITION_PAUSED_MESSAGE],
  ['source_authentication_changed', 'The endpoint authentication mode changed. Inspect it again before saving.'],
  ['source_authentication_unsupported', 'The endpoint did not return the standard MCP OAuth discovery challenge.'],
  ['source_google_shared_oauth_unsupported', GOOGLE_SHARED_OAUTH_BLOCK_MESSAGE],
  ['source_capacity_exceeded', 'This source would exceed the gateway source-state capacity. Reduce its tool selection or remove another draft.'],
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

export function safeGatewayErrorCode(code: string): string {
  return ERROR_MESSAGES.has(code) ? code : 'request_failed'
}

function validControlPlaneOrigin(value: string): boolean {
  if (value.length === 0 || value.length > 2_048) return false
  try {
    const url = new URL(value)
    return url.protocol === 'https:' && url.origin === value && !url.username && !url.password &&
      !url.port && url.pathname === '/' && url.search === '' && url.hash === ''
  } catch {
    return false
  }
}

export function validHandoffUrl(value: string, expectedOrigin: string): string | null {
  if (!validControlPlaneOrigin(expectedOrigin)) return null
  try {
    const url = new URL(value)
    return url.origin === expectedOrigin && !url.username && !url.password && !url.port &&
      url.pathname === '/manage' &&
      url.search === '' && /^#[A-Za-z0-9_-]{40,4096}$/u.test(url.hash) ? url.href : null
  } catch {
    return null
  }
}

/** Typed same-origin boundary for the gateway management Worker. */
export class HttpGatewayAdminApi implements GatewayAdminApi {
  getStatus(): Promise<GatewayStatus> { return this.#request('/api/status', gatewayStatusSchema) }
  getSources(): Promise<ManagedSources> { return this.#request('/api/sources', managedSourcesSchema) }
  getTeam(): Promise<Team> { return this.#request('/api/team', teamSchema) }

  prepareTeamAction(expectedRevision: number, members: TeamMember[]): Promise<TeamActionResult> {
    return this.#request('/api/team-actions', teamActionResultSchema, {
      method: 'POST',
      body: JSON.stringify({ schemaVersion: 1, expectedRevision, members }),
    })
  }

  getTeamAction(actionId: string): Promise<TeamAction> {
    return this.#request(`/api/team-actions/${encodeURIComponent(actionId)}`, teamActionSchema)
  }

  cancelTeamAction(actionId: string): Promise<TeamAction> {
    return this.#request(`/api/team-actions/${encodeURIComponent(actionId)}`, teamActionSchema, {
      method: 'DELETE', body: '{}',
    })
  }
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

  prepareRuntimeAction(operation: RuntimeOperation, expectedTarget?: RuntimeVersion): Promise<PreparedAction & { operation: RuntimeOperation }> {
    return this.#request('/api/update-actions', runtimePreparedActionSchema, {
      method: 'POST', body: JSON.stringify({ schemaVersion: 1, operation, expectedTarget }),
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
