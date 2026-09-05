import * as v from 'valibot'

export type NativeRecipeStatus =
  | 'compatibility_pending'
  | 'manual_setup'
  | 'provider_permission_required'

export type NativeRecipeAuthentication =
  | 'oauth_dynamic_registration'
  | 'oauth_manual_client'
  | 'oauth_unverified'

/** Documentation-only setup data. This is not a SourceCatalogSource. */
export interface NativeConnectorRecipe {
  readonly id: string
  readonly displayName: string
  readonly description: string
  readonly status: NativeRecipeStatus
  readonly endpoint: string
  readonly authentication: NativeRecipeAuthentication
  readonly upstreamControls: readonly string[]
  readonly requiredScopes: readonly string[]
  readonly scopeNote: string
  readonly documentedReadTools: readonly string[]
  readonly blockers: readonly string[]
  readonly setupSteps: readonly string[]
  readonly evidenceUrls: readonly string[]
}

export const NATIVE_RECIPE_RESEARCH_DATE = '2026-08-30'
export const NATIVE_RECIPE_NOTICE = 'Setup guidance only. These connections have not passed the gateway canary or catalog release review. No source draft or tool permission is created.'
export const NATIVE_RECIPE_STATUS_LABELS: Readonly<Record<NativeRecipeStatus, string>> = Object.freeze({
  compatibility_pending: 'Compatibility pending',
  manual_setup: 'Manual setup needed',
  provider_permission_required: 'Provider permission required',
})

const CANARY_BLOCKER = 'Cloudflare operator-shared authentication, refresh, and read-only enforcement need a live canary.'
const CATALOG_BLOCKER = 'Catalog provenance and release review are still required.'
const MANUAL_AUTH_BLOCKER = 'The gateway does not support a manual OAuth client with the required shared operator connection.'
const EXACT_TOOLS_BLOCKER = 'Discover and review the exact tool names before creating an allowlist.'
const SAFE_ID = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u
const EXACT_TOOL = /^[A-Za-z0-9_.:/-]{1,128}$/u
const EXACT_SCOPE = /^[A-Za-z0-9._:/-]{1,240}$/u

const textSchema = v.pipe(
  v.string(), v.minLength(1), v.maxLength(600),
  v.check((value) => value.trim() === value && !hasControlCharacter(value)),
)
const urlSchema = v.pipe(v.string(), v.maxLength(2_048), v.check(isPublicSetupUrl))
const textListSchema = v.pipe(v.array(textSchema), v.minLength(1), v.maxLength(10))
const recipeSchema = v.strictObject({
  id: v.pipe(v.string(), v.maxLength(64), v.regex(SAFE_ID)),
  displayName: v.pipe(textSchema, v.maxLength(80)),
  description: textSchema,
  status: v.picklist(['compatibility_pending', 'manual_setup', 'provider_permission_required']),
  endpoint: urlSchema,
  authentication: v.picklist(['oauth_dynamic_registration', 'oauth_manual_client', 'oauth_unverified']),
  upstreamControls: textListSchema,
  requiredScopes: v.pipe(v.array(v.pipe(v.string(), v.regex(EXACT_SCOPE))), v.maxLength(20)),
  scopeNote: textSchema,
  documentedReadTools: v.pipe(v.array(v.pipe(v.string(), v.regex(EXACT_TOOL))), v.maxLength(30)),
  blockers: v.pipe(textListSchema, v.minLength(2)),
  setupSteps: textListSchema,
  evidenceUrls: v.pipe(v.array(urlSchema), v.minLength(1), v.maxLength(10)),
})
const recipesSchema = v.pipe(v.array(recipeSchema), v.minLength(1), v.maxLength(40))

export class NativeRecipeValidationError extends Error {
  constructor() {
    super('native_recipe_invalid')
    this.name = 'NativeRecipeValidationError'
  }
}

/** Validate authored data without network calls, credentials, or mutable state. */
export function parseNativeConnectorRecipes(
  input: readonly NativeConnectorRecipe[],
): readonly NativeConnectorRecipe[] {
  const parsed = v.safeParse(recipesSchema, input)
  if (!parsed.success) throw new NativeRecipeValidationError()
  if (!isSortedUnique(parsed.output.map((recipe) => recipe.id))) {
    throw new NativeRecipeValidationError()
  }
  for (const recipe of parsed.output) {
    if (!isSortedUnique(recipe.requiredScopes) ||
      !isSortedUnique(recipe.documentedReadTools) ||
      !isSortedUnique(recipe.evidenceUrls) ||
      !recipe.blockers.includes(CANARY_BLOCKER) ||
      !recipe.blockers.includes(CATALOG_BLOCKER) ||
      (recipe.authentication === 'oauth_manual_client' && recipe.status !== 'manual_setup')) {
      throw new NativeRecipeValidationError()
    }
  }
  return Object.freeze(parsed.output.map((recipe) => Object.freeze({
    ...recipe,
    upstreamControls: Object.freeze(recipe.upstreamControls),
    requiredScopes: Object.freeze(recipe.requiredScopes),
    documentedReadTools: Object.freeze(recipe.documentedReadTools),
    blockers: Object.freeze(recipe.blockers),
    setupSteps: Object.freeze(recipe.setupSteps),
    evidenceUrls: Object.freeze(recipe.evidenceUrls),
  })))
}

const authoredRecipes: readonly NativeConnectorRecipe[] = [
  {
    id: 'ahrefs', displayName: 'Ahrefs',
    description: 'SEO and competitive research through the provider-hosted MCP server.',
    status: 'provider_permission_required', endpoint: 'https://api.ahrefs.com/mcp/mcp',
    authentication: 'oauth_dynamic_registration',
    upstreamControls: ['Obtain provider confirmation that use through a self-hosted Cloudflare Portal is permitted.', 'Review the dedicated MCP grant and exact tools for read-only behavior.'],
    requiredScopes: [], scopeNote: 'No exact read-only scope contract has been established for this gateway.',
    documentedReadTools: [],
    blockers: ['Provider permission for gateway or bridge use must be resolved before an authenticated canary.', EXACT_TOOLS_BLOCKER, CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Do not authenticate or run a canary until Ahrefs confirms the proposed use is permitted.', 'After permission, review the exact authenticated tools and upstream authorization before enabling any tool.'],
    evidenceUrls: ['https://docs.ahrefs.com/en/mcp/docs/introduction', 'https://docs.ahrefs.com/en/mcp/docs/tool-categories'],
  },
  {
    id: 'airtable', displayName: 'Airtable',
    description: 'Read selected base schemas and records with a restricted provider grant.',
    status: 'compatibility_pending', endpoint: 'https://mcp.airtable.com/mcp',
    authentication: 'oauth_dynamic_registration',
    upstreamControls: ['Restrict the provider connection to the intended bases and only the documented read scopes.', 'Use a read-only Airtable identity where practical; exclude automation, form-submission, schema, and record writes.'],
    requiredScopes: ['data.recordComments:read', 'data.records:read', 'schema.bases:read', 'workspacesAndBases:read'],
    scopeNote: 'These are the provider-documented read-only scopes, not a claim that Cloudflare will request or receive only them.',
    documentedReadTools: ['get_table_schema', 'list_bases', 'list_records_for_table', 'list_tables_for_base'],
    blockers: ['Verify the actual OAuth grant excludes write scopes and includes only the intended bases.', CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Have your administrator review which bases the shared gateway identity may expose to your team.', 'Use only the read-only scope set during provider authorization; stop if the flow cannot produce that grant.', 'Discover the exact current tools and approve a small subset after the canary.'],
    evidenceUrls: ['https://airtable.com/developers/agents/mcp/getting-started', 'https://airtable.com/developers/agents/mcp/tools', 'https://support.airtable.com/articles/9897799762-using-the-airtable-mcp-server'],
  },
  {
    id: 'bigquery', displayName: 'BigQuery',
    description: 'Query approved datasets through Google’s hosted read-only SQL tool.',
    status: 'manual_setup', endpoint: 'https://bigquery.googleapis.com/mcp',
    authentication: 'oauth_manual_client',
    upstreamControls: ['Use a dedicated identity with dataset-scoped Data Viewer, query-project Job User, and MCP Tool User access.', 'Apply Google’s deny policy for non-read-only MCP tools; exclude execute_sql and inherited broad permissions.', 'Manage query spending in your Google account. Daily quotas are optional safeguards; a SQL LIMIT does not bound bytes scanned.'],
    requiredScopes: ['https://www.googleapis.com/auth/bigquery'],
    scopeNote: 'The required BigQuery scope is broad. Read-only IAM and provider tool enforcement are mandatory; do not invent a bigquery.readonly scope.',
    documentedReadTools: ['execute_sql_readonly', 'get_table_info', 'list_table_ids'],
    blockers: [MANUAL_AUTH_BLOCKER, 'The existing source_google_shared_oauth_unsupported gate remains in force even though public tools/list succeeds.', CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Do not create a Google client just to test the unsupported shared manual-OAuth topology.', 'First confirm supported Cloudflare admin authentication and refresh with a pre-registered Google client.', 'Then prepare scoped IAM and a small sandbox aggregate, and review its expected cost; keep all provider identifiers and credentials outside this repository.'],
    evidenceUrls: ['https://docs.cloud.google.com/bigquery/docs/reference/mcp', 'https://docs.cloud.google.com/bigquery/docs/use-bigquery-mcp', 'https://docs.cloud.google.com/mcp/authenticate-mcp', 'https://docs.cloud.google.com/mcp/control-mcp-use-iam'],
  },
  {
    id: 'confluence', displayName: 'Confluence',
    description: 'Read permitted knowledge pages through Atlassian Rovo MCP.',
    status: 'compatibility_pending', endpoint: 'https://mcp.atlassian.com/v1/mcp/authv2',
    authentication: 'oauth_unverified',
    upstreamControls: ['In Atlassian’s organization MCP Permissions tab, allow intended Confluence Read/Search permissions and block Write.', 'Review organization-wide effects before changing MCP permissions; other MCP clients may be affected.', 'Constrain the connecting identity to pages your gateway users may access.'],
    requiredScopes: [], scopeNote: 'No exact authv2 read-only OAuth scope set is asserted; the documented enforcement route is Atlassian’s MCP permission controls.',
    documentedReadTools: [],
    blockers: ['Verify authv2 automatic registration, organization permissions, and domain/IP access with Cloudflare.', EXACT_TOOLS_BLOCKER, CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Ask your Atlassian administrator to review the MCP Read/Write/Search controls and connected identity.', 'Do not enable automatic permission expansion for future additions.', 'Use the current authv2 endpoint; review Confluence-only exact tools after authentication.'],
    evidenceUrls: ['https://support.atlassian.com/atlassian-rovo-mcp-server/docs/getting-started-with-the-atlassian-remote-mcp-server/', 'https://support.atlassian.com/atlassian-rovo-mcp-server/docs/supported-tools/', 'https://support.atlassian.com/security-and-access-policies/docs/Configure-Atlassian-Rovo-MCP-server-permission/'],
  },
  {
    id: 'github', displayName: 'GitHub',
    description: 'Read repository contents, issues and pull requests through GitHub’s read-only endpoint.',
    status: 'manual_setup', endpoint: 'https://api.githubcopilot.com/mcp/readonly',
    authentication: 'oauth_manual_client',
    upstreamControls: ['Keep the provider /readonly endpoint; never fall back to the read-write base URL.', 'Restrict the GitHub app or source identity to the repositories and read permissions your team needs.'],
    requiredScopes: [], scopeNote: 'App permissions depend on the chosen GitHub App or OAuth App; no universal read-only OAuth scope is assumed.',
    documentedReadTools: ['get_file_contents', 'issue_read', 'pull_request_read'],
    blockers: [MANUAL_AUTH_BLOCKER, CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Review GitHub’s registered-app requirements with your organization administrator.', 'Wait for a supported shared manual-OAuth path before creating a gateway connection.', 'After qualification, choose only the exact repository, issue and pull-request read tools; do not add secret-scanning or mutation tools by default.'],
    evidenceUrls: ['https://github.com/github/github-mcp-server', 'https://github.com/github/github-mcp-server/blob/main/docs/host-integration.md', 'https://github.com/github/github-mcp-server/blob/main/docs/remote-server.md'],
  },
  {
    id: 'gitlab', displayName: 'GitLab',
    description: 'Read projects, issues, merge requests and pipelines from GitLab.com.',
    status: 'compatibility_pending', endpoint: 'https://gitlab.com/api/v4/mcp',
    authentication: 'oauth_dynamic_registration',
    upstreamControls: ['Establish a provider-side identity or grant that denies all mutations, not only protected-branch writes.', 'Enable native MCP only for the intended GitLab group and source identity.'],
    requiredScopes: [], scopeNote: 'A native MCP-specific read-only grant has not been established; ordinary project membership is insufficient proof.',
    documentedReadTools: ['get_commit', 'get_issue', 'get_merge_request', 'get_pipeline', 'get_repository_file', 'list_pipelines'],
    blockers: ['The native server includes writes and no complete read-only connection boundary has been verified.', CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Review GitLab MCP availability and group settings without enabling a broad identity.', 'Prove upstream mutation denial before connecting; use the exact native tool reference, not a community package’s tool list.'],
    evidenceUrls: ['https://docs.gitlab.com/user/model_context_protocol/mcp_server/', 'https://docs.gitlab.com/user/model_context_protocol/mcp_server_tools/'],
  },
  {
    id: 'google-drive', displayName: 'Google Drive',
    description: 'Search and read approved files through Google’s hosted Workspace MCP server.',
    status: 'manual_setup', endpoint: 'https://drivemcp.googleapis.com/mcp/v1',
    authentication: 'oauth_manual_client',
    upstreamControls: ['Use only drive.readonly for the file-reading use case; drive.file permits writes and is not a read-only substitute.', 'Restrict the connecting identity’s file access to material your gateway users may see.'],
    requiredScopes: ['https://www.googleapis.com/auth/drive.readonly'],
    scopeNote: 'The provider documents this read scope alongside write-capable alternatives; the actual restricted grant and refresh still need verification.',
    documentedReadTools: ['get_file_metadata', 'read_file_content', 'search_files'],
    blockers: [MANUAL_AUTH_BLOCKER, CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Review Google Workspace MCP availability and consent requirements.', 'Do not substitute a personal broad Drive grant for a team-approved read identity.', 'After the shared OAuth path is supported, verify only the requested file-read scope and exact read tools.'],
    evidenceUrls: ['https://developers.google.com/workspace/drive/api/guides/api-specific-auth', 'https://developers.google.com/workspace/guides/configure-mcp-servers'],
  },
  {
    id: 'google-sheets', displayName: 'Google Sheets',
    description: 'Read spreadsheet metadata and bounded cell ranges through Google’s hosted MCP server.',
    status: 'manual_setup', endpoint: 'https://sheetsmcp.googleapis.com/mcp/v1',
    authentication: 'oauth_manual_client',
    upstreamControls: ['Use spreadsheets.readonly and a source identity limited to approved spreadsheets.', 'Request bounded ranges; do not enable batch updates or write-capable Google scopes.'],
    requiredScopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
    scopeNote: 'Verify this least-privilege scope works for the chosen read tools; do not automatically add drive.file or spreadsheets write access.',
    documentedReadTools: ['get_spreadsheet', 'get_values'],
    blockers: [MANUAL_AUTH_BLOCKER, CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Review Google Workspace MCP setup and spreadsheet visibility for the shared source identity.', 'Wait for supported shared manual OAuth before registering a gateway connection.', 'Canary metadata and one small cell range, then review the exact two-tool allowlist.'],
    evidenceUrls: ['https://developers.google.com/workspace/guides/configure-mcp-servers'],
  },
  {
    id: 'gorgias', displayName: 'Gorgias',
    description: 'Prepare a minimal support-ticket read connection to the provider’s beta MCP server.',
    status: 'compatibility_pending', endpoint: 'https://mcp.gorgias.com/mcp',
    authentication: 'oauth_dynamic_registration',
    upstreamControls: ['Prove a granular read-only provider OAuth grant before connecting any support account.', 'Keep replies, ticket updates and helpdesk configuration changes unavailable upstream.'],
    requiredScopes: [], scopeNote: 'Granular scopes are advertised, but the exact minimal granted set through Cloudflare has not been proved.',
    documentedReadTools: [],
    blockers: ['Cloudflare’s actual requested and granted provider scopes remain unverified.', EXACT_TOOLS_BLOCKER, CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Finish the synthetic OAuth scope diagnostic before a real provider connection.', 'Use an approved isolated test identity; do not treat a production support account as an unattended canary.', 'Verify the complete authenticated tool catalogue and select only the required ticket reads.'],
    evidenceUrls: ['https://docs.gorgias.com/en-US/connect-your-ai-assistant-to-the-gorgias-mcp-6310546', 'https://updates.gorgias.com/publications/gorgias-mcp-is-now-in-open-beta'],
  },
  {
    id: 'hubspot', displayName: 'HubSpot',
    description: 'Read selected CRM objects and property definitions through HubSpot’s native server.',
    status: 'manual_setup', endpoint: 'https://mcp.hubspot.com/',
    authentication: 'oauth_manual_client',
    upstreamControls: ['Use installation permissions and a source identity that deny CRM, activity, and marketing mutations.', 'Verify the permissions chosen during installation; current MCP auth apps do not accept an arbitrary authored scope list.'],
    requiredScopes: [], scopeNote: 'HubSpot determines available scopes from tools and permissions selected during installation; do not reuse a private API app’s scope assumptions.',
    documentedReadTools: ['get_crm_objects', 'get_properties', 'get_user_details', 'search_crm_objects', 'search_owners', 'search_properties'],
    blockers: [MANUAL_AUTH_BLOCKER, 'Prove a genuinely read-only installation; the hosted server also supports writes.', CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Review the MCP auth app and PKCE flow with your HubSpot administrator.', 'Do not enter a client secret in Ankka or a repository file.', 'Once shared manual OAuth is supported, verify read-only installation permissions and exclude manage_crm_objects.'],
    evidenceUrls: ['https://developers.hubspot.com/docs/apps/developer-platform/build-apps/integrate-with-the-remote-hubspot-mcp-server'],
  },
  {
    id: 'intercom-eu', displayName: 'Intercom (EU)',
    description: 'Read support conversations and contacts from an EU-hosted Intercom workspace.',
    status: 'compatibility_pending', endpoint: 'https://mcp.eu.intercom.com/mcp',
    authentication: 'oauth_unverified',
    upstreamControls: ['Use a provider grant limited to conversation and contact reads; prove article-write permissions are absent.', 'Match the endpoint to the workspace region and never fall back to the US endpoint.'],
    requiredScopes: [], scopeNote: 'The exact read-only OAuth scope set and automatic-registration behavior need verification.',
    documentedReadTools: ['get_contact', 'get_conversation', 'search_contacts', 'search_conversations'],
    blockers: ['The server also exposes article creation and updates; read-only grant enforcement is not established.', CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Confirm that your workspace is EU-hosted.', 'Review a conversation/contact-only grant before any provider consent.', 'Discover exact tools and test denied write access without creating or modifying an article.'],
    evidenceUrls: ['https://developers.intercom.com/docs/guides/mcp'],
  },
  {
    id: 'intercom-us', displayName: 'Intercom (US)',
    description: 'Read support conversations and contacts from a US-hosted Intercom workspace.',
    status: 'compatibility_pending', endpoint: 'https://mcp.intercom.com/mcp',
    authentication: 'oauth_unverified',
    upstreamControls: ['Use a provider grant limited to conversation and contact reads; prove article-write permissions are absent.', 'Match the endpoint to the workspace region. AU-hosted workspaces are not documented as supported.'],
    requiredScopes: [], scopeNote: 'The exact read-only OAuth scope set and automatic-registration behavior need verification.',
    documentedReadTools: ['get_contact', 'get_conversation', 'search_contacts', 'search_conversations'],
    blockers: ['The server also exposes article creation and updates; read-only grant enforcement is not established.', CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Confirm that your workspace is US-hosted.', 'Review a conversation/contact-only grant before any provider consent.', 'Discover exact tools and test denied write access without creating or modifying an article.'],
    evidenceUrls: ['https://developers.intercom.com/docs/guides/mcp'],
  },
  {
    id: 'jira', displayName: 'Jira',
    description: 'Read issue and project context through Atlassian Rovo MCP.',
    status: 'compatibility_pending', endpoint: 'https://mcp.atlassian.com/v1/mcp/authv2',
    authentication: 'oauth_unverified',
    upstreamControls: ['In Atlassian’s organization MCP Permissions tab, allow intended Jira Read/Search permissions and block Write.', 'Review organization-wide effects before changing MCP permissions; other MCP clients may be affected.', 'Constrain the connecting identity to projects your gateway users may access.'],
    requiredScopes: [], scopeNote: 'No exact authv2 read-only OAuth scope set is asserted; the documented enforcement route is Atlassian’s MCP permission controls.',
    documentedReadTools: [],
    blockers: ['Verify authv2 automatic registration, organization permissions, and domain/IP access with Cloudflare.', EXACT_TOOLS_BLOCKER, CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Ask your Atlassian administrator to review MCP Read/Write/Search controls and the connected identity.', 'Do not enable automatic permission expansion for future additions.', 'Use the current authv2 endpoint; review Jira-only exact tools after authentication.'],
    evidenceUrls: ['https://support.atlassian.com/atlassian-rovo-mcp-server/docs/getting-started-with-the-atlassian-remote-mcp-server/', 'https://support.atlassian.com/atlassian-rovo-mcp-server/docs/supported-tools/', 'https://support.atlassian.com/security-and-access-policies/docs/Configure-Atlassian-Rovo-MCP-server-permission/'],
  },
  {
    id: 'linear', displayName: 'Linear',
    description: 'Read issues and projects through Linear’s dedicated read-only MCP endpoint.',
    status: 'compatibility_pending', endpoint: 'https://mcp.linear.app/mcp/readonly',
    authentication: 'oauth_dynamic_registration',
    upstreamControls: ['Keep the dedicated /mcp/readonly endpoint; never fall back to the read-write /mcp endpoint.', 'Verify the provider rejects write calls and the shared identity exposes only the intended workspace.'],
    requiredScopes: ['read'],
    scopeNote: 'Linear documents read as a read-only OAuth scope on its standard endpoint. Verify the dedicated read-only endpoint’s actual grant; metadata is not token evidence.',
    documentedReadTools: [],
    blockers: [EXACT_TOOLS_BLOCKER, CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Prepare an approved test workspace and limited source identity.', 'Use the dedicated read-only URL and confirm the requested and granted provider permissions.', 'Capture the exact authenticated tool list before proposing a small issue/project allowlist.'],
    evidenceUrls: ['https://linear.app/docs/mcp'],
  },
  {
    id: 'notion', displayName: 'Notion',
    description: 'Read pages and search knowledge through Notion’s hosted MCP service.',
    status: 'compatibility_pending', endpoint: 'https://mcp.notion.com/mcp',
    authentication: 'oauth_dynamic_registration',
    upstreamControls: ['Prove a hosted-MCP-specific read-only grant or identity before connecting.', 'Review connected-source search access as well as Notion page access; a separate API integration’s capabilities do not restrict the hosted MCP grant.'],
    requiredScopes: [], scopeNote: 'No explicit read-only scope or endpoint for the hosted MCP grant was established in this review.',
    documentedReadTools: ['notion-fetch', 'notion-search'],
    blockers: ['The hosted server can create and update content with the connecting user’s access.', CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Review a read-only identity or hosted grant with your workspace administrator.', 'Do not infer authorization from readOnlyHint or a two-tool client filter.', 'Verify page visibility, search reach and denied mutations before enabling the connection.'],
    evidenceUrls: ['https://developers.notion.com/guides/mcp/build-mcp-client', 'https://developers.notion.com/guides/mcp/mcp-supported-tools', 'https://developers.notion.com/guides/mcp/overview'],
  },
  {
    id: 'salesforce', displayName: 'Salesforce',
    description: 'Read schema and business records through Salesforce’s dedicated SObject Reads server.',
    status: 'manual_setup', endpoint: 'https://api.salesforce.com/platform/mcp/v1/platform/sobject-reads',
    authentication: 'oauth_manual_client',
    upstreamControls: ['Use only platform/sobject-reads, which the provider documents as unable to create, update or delete.', 'Use a dedicated identity with intended object, field and record visibility.'],
    requiredScopes: ['mcp_api', 'refresh_token'],
    scopeNote: 'The MCP scope is not itself read-only; the dedicated server and Salesforce permissions enforce the operation boundary.',
    documentedReadTools: [],
    blockers: [MANUAL_AUTH_BLOCKER, EXACT_TOOLS_BLOCKER, CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Review Salesforce edition availability, server activation and External Client App requirements.', 'Use the provider-documented sandbox server for qualification; do not silently switch the production endpoint to sandbox or vice versa.', 'Wait for shared manual OAuth support, then discover the exact SObject Reads tools with bounded queries.'],
    evidenceUrls: ['https://developer.salesforce.com/blogs/2026/04/salesforce-hosted-mcp-servers-are-now-generally-available', 'https://developer.salesforce.com/docs/platform/hosted-mcp-servers/references/reference/sobject-reads.html'],
  },
  {
    id: 'sentry', displayName: 'Sentry',
    description: 'Read error and performance context with an inspect-only provider MCP grant.',
    status: 'compatibility_pending', endpoint: 'https://mcp.sentry.dev/mcp',
    authentication: 'oauth_dynamic_registration',
    upstreamControls: ['Select only the inspect skill in Sentry MCP consent; do not approve triage, project-management, or Seer capabilities.', 'Verify provider grant filtering applies to direct tools and catalog execution.'],
    requiredScopes: [], scopeNote: 'inspect is a provider MCP skill, not an OAuth scope to invent. Current consent defaults select all active skills unless a preference exists.',
    documentedReadTools: [],
    blockers: ['Current wrapper executors can reach writes with broader grants; do not seed them before inspect-only enforcement is proved.', EXACT_TOOLS_BLOCKER, CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Explicitly select inspect only at provider consent; do not trust an old read-only default or a remembered browser preference.', 'Review current direct and catalog tool surfaces under that exact grant.', 'Prove denied write capabilities through both execution paths before enabling any executor.'],
    evidenceUrls: ['https://docs.sentry.io/product/sentry-mcp/', 'https://github.com/getsentry/sentry-mcp/blob/main/docs/architecture/overview.md', 'https://github.com/getsentry/sentry-mcp/blob/main/docs/specs/remembered-oauth-skills.md', 'https://github.com/getsentry/sentry-mcp/blob/main/docs/testing/remote.md'],
  },
  {
    id: 'slack', displayName: 'Slack',
    description: 'Read approved public-channel context with a restricted internal Slack app.',
    status: 'manual_setup', endpoint: 'https://mcp.slack.com/mcp',
    authentication: 'oauth_manual_client',
    upstreamControls: ['Use an internal or Marketplace-published Slack app; unlisted distributed apps are not supported.', 'For a public-channel starting point, grant only public search and history access; exclude chat, reaction, canvas, and conversation writes.', 'Do not expose one user’s private conversations through a team-shared source.'],
    requiredScopes: ['channels:history', 'search:read.public'],
    scopeNote: 'This is a minimal public-channel use case, not every Slack read tool. Add other read scopes only for an explicitly reviewed data category.',
    documentedReadTools: [],
    blockers: [MANUAL_AUTH_BLOCKER, 'Slack requires a registered confidential app and does not support DCR.', EXACT_TOOLS_BLOCKER, CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Review an internal app and approved public-channel data with your Slack administrator.', 'Wait for supported shared manual OAuth; keep client credentials out of Ankka.', 'Discover exact read tools for the chosen user scopes and verify refresh and visibility.'],
    evidenceUrls: ['https://docs.slack.dev/ai/slack-mcp-server/'],
  },
  {
    id: 'stripe', displayName: 'Stripe',
    description: 'Read account and payment data through Stripe’s provider-enforced GET tool.',
    status: 'compatibility_pending', endpoint: 'https://mcp.stripe.com/',
    authentication: 'oauth_unverified',
    upstreamControls: ['Prove the provider grant is read-only across the connection, not only within the selected GET tool.', 'Exclude stripe_api_write, report creation, feedback submission and analytics permissions from the initial read use case.'],
    requiredScopes: [], scopeNote: 'The exact OAuth read-only grant needs proof; a restricted API key would require a separately supported credential path.',
    documentedReadTools: ['get_stripe_account_info', 'stripe_api_details', 'stripe_api_read', 'stripe_api_search'],
    blockers: ['Verify automatic registration and an actual read-only OAuth consent grant; the hosted server also exposes writes.', CANARY_BLOCKER, CATALOG_BLOCKER],
    setupSteps: ['Review a sandbox account and read-only provider authorization before connecting.', 'Do not add Analytics, Financial Reports or Sigma write permissions merely because the workflow is analytical.', 'Verify current exact tools; Connect-platform account headers are outside this recipe.'],
    evidenceUrls: ['https://docs.stripe.com/data/analyze-with-ai', 'https://docs.stripe.com/mcp'],
  },
]

export const NATIVE_CONNECTOR_RECIPES = parseNativeConnectorRecipes(authoredRecipes)

export interface NativeRecipeResolution {
  readonly kind: 'setup_required'
  readonly recipe: NativeConnectorRecipe
  readonly sourceDraft: null
}

/** No recipe currently meets every connection gate; lookup never creates a draft. */
export function resolveNativeRecipe(id: string): NativeRecipeResolution | null {
  const recipe = NATIVE_CONNECTOR_RECIPES.find((candidate) => candidate.id === id)
  return recipe ? Object.freeze({ kind: 'setup_required', recipe, sourceDraft: null }) : null
}

/** Copyable instructions, intentionally not executable source configuration. */
export function formatNativeRecipeSetup(id: string): string | null {
  const resolved = resolveNativeRecipe(id)
  if (!resolved) return null
  const recipe = resolved.recipe
  return [
    `${recipe.displayName} — ${NATIVE_RECIPE_STATUS_LABELS[recipe.status]}`,
    NATIVE_RECIPE_NOTICE,
    `Research date: ${NATIVE_RECIPE_RESEARCH_DATE}`,
    `Provider endpoint: ${recipe.endpoint}`,
    `Authentication: ${recipe.authentication}`,
    '', 'Required upstream controls:',
    ...recipe.upstreamControls.map((control) => `- ${control}`),
    '', 'Scope requirements:',
    ...(recipe.requiredScopes.length ? recipe.requiredScopes.map((scope) => `- ${scope}`) : ['- No exact scope set established.']),
    recipe.scopeNote,
    '', 'Documented read-tool candidates (not enabled permissions):',
    ...(recipe.documentedReadTools.length ? recipe.documentedReadTools.map((tool) => `- ${tool}`) : ['- Exact tool discovery and review required.']),
    '', 'Remaining blockers:',
    ...recipe.blockers.map((blocker) => `- ${blocker}`),
    '', 'Setup steps:',
    ...recipe.setupSteps.map((step, index) => `${index + 1}. ${step}`),
    '', 'Provider evidence:',
    ...recipe.evidenceUrls.map((url) => `- ${url}`),
    '', 'Never put provider credentials in Ankka, chat, configuration examples, or repository files.',
  ].join('\n')
}

function isSortedUnique(values: readonly string[]): boolean {
  return values.every((value, index) => index === 0 || (values[index - 1] ?? '') < value)
}

function hasControlCharacter(value: string): boolean {
  return [...value].some((character) => character.charCodeAt(0) <= 31 || character.charCodeAt(0) === 127)
}

function isPublicSetupUrl(value: string): boolean {
  try {
    const url = new URL(value)
    const host = url.hostname
    const labels = host.split('.')
    return url.protocol === 'https:' && url.href === value &&
      !url.username && !url.password && !url.port && !url.search && !url.hash &&
      !value.includes('?') && !value.includes('#') && !/[{}%]/u.test(url.pathname) &&
      host.length <= 253 && labels.length >= 2 &&
      !/^(?:\d+\.)+\d+$/u.test(host) &&
      !['internal', 'invalid', 'local', 'localhost', 'onion', 'test'].includes(labels.at(-1) ?? '') &&
      labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))
  } catch {
    return false
  }
}
