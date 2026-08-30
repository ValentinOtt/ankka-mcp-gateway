# Provider-native connector feasibility

> Research reviewed 2026-08-30. This is implementation evidence, not a release
> approval or a claim that any provider has passed an authenticated Cloudflare
> canary. No provider account was connected and no provider data was read.

The highest-value shortcut is to reuse provider-run MCP servers, not maintain a
second API adapter for every business system. The useful distinction is between
an endpoint that exists, a provider-enforced read-only connection, and a
connection the gateway can actually establish. Those are three different facts.

This review covers GitHub, GitLab, Linear, Atlassian Jira and Confluence, Notion,
Slack, Sentry, HubSpot, Salesforce, Zendesk, Intercom, and Stripe. The originally
requested BigQuery, Search Console, Ahrefs, and Gorgias remain covered by
[the initial candidate review](SOURCE_CATALOG_CANDIDATES.md).

## Architecture fit

The current [catalog contract](SOURCE_CATALOG.md) accepts a fixed public HTTPS
Streamable HTTP endpoint, `none` or `oauth`, one operator connection
(`onBehalfOfUser: false`), and exact tools. It does not accept manual OAuth
clients, secret headers, bearer-token recipes, URL query configuration, or
per-user upstream credentials. The production manifest is still empty.

Every candidate below also needs pinned, provider-attributed Registry evidence
under that contract. This review does not establish Registry eligibility or
authorize a provenance-schema change. Provider documentation is sufficient to
write an honest setup guide, not sufficient to set `review.status` to
`ankka_reviewed`.

Do not convert every row into a selectable preset. A useful implementation can
show a setup guide and the exact missing prerequisite while keeping connection
creation disabled. Do not collect provider secrets at the hosted installer to
work around a missing Cloudflare authentication mode.

## Recommended implementation order

| Provider | Native remote | Actual upstream read-only route | Main remaining gap |
| --- | --- | --- | --- |
| Linear | Fixed HTTP endpoint | Dedicated `/readonly` endpoint; explicit read-only OAuth scope also documented | Exact tool discovery, Registry/provenance review, Cloudflare canary |
| Atlassian Jira / Confluence | Fixed HTTP endpoint | Organization MCP permissions can block Write, including per app | Administrator setup, authv2 compatibility, exact tools and canary |
| Sentry | Fixed HTTP endpoint | Provider MCP grant can select only the `inspect` skill | New consent defaults include writes; grant/tool verification and canary |
| GitHub | Fixed HTTP endpoint | Provider `/readonly` endpoint | Manually registered OAuth app or token, outside current source flow |
| Salesforce | Fixed HTTP endpoint | Dedicated `platform/sobject-reads` server | Manual External Client App and enabled Salesforce server |
| Slack | Fixed HTTP endpoint | User OAuth token with read-only scope set | No DCR; registered confidential app and supported app distribution |
| HubSpot | Fixed HTTP endpoint | Installation permissions and user permissions | Manual MCP auth app; current read-only consent combination unverified |
| Stripe | Fixed HTTP endpoint | Restricted read-only API key is possible; MCP read tool is GET-only | OAuth grant's read-only configuration needs proof; key mode unsupported |
| GitLab | Fixed endpoint on GitLab.com; instance-specific elsewhere | No MCP-specific read-only connection proved in this review | Token/identity operation boundary, then canary |
| Notion | Fixed HTTP endpoint | No explicit read-only MCP grant/endpoint proved here | MCP inherits user access; tool filtering alone insufficient |
| Intercom | Separate fixed US / EU endpoints | No read-only OAuth grant proved here | Article write tools exist; read-only permission proof |
| Zendesk | No first-party remote endpoint verified here | Not established | Separate Zendesk's MCP client from a provider-published MCP server |

This order is about compatibility effort, not a quantified popularity ranking.
An engineering/knowledge bundle can cover Linear, GitHub, Jira, Confluence,
Notion and Slack; a revenue/support bundle can cover Salesforce, HubSpot,
Stripe, Zendesk and Intercom. Shipping both bundles does not require owning all
their runtimes.

## Linear

- Endpoint: `https://mcp.linear.app/mcp/readonly` for this read-only product.
  `https://mcp.linear.app/mcp` is read-write by default. Do not silently fall back
  from the former to the latter.
- Authentication: the provider documents OAuth 2.1 with Dynamic Client
  Registration (DCR), plus optional direct bearer/API-key authentication.
- Read-only evidence: Linear documents that `/mcp/readonly` only exposes read
  tools. It separately documents that requesting only OAuth scope `read` on the
  standard endpoint gives a token that cannot call write APIs. A canary should
  verify the dedicated endpoint's write-call rejection and actual grant; an
  advertised read-only tool list is not itself the complete test.
- Exact seed: deliberately not filled from third-party tool lists. The provider
  setup page describes operations but does not publish a complete exact-name
  contract. Capture authenticated `tools/list` on the dedicated endpoint before
  selecting a small reviewed seed.
- Next implementation: fixed read-only URL, OAuth setup guidance, no API-key
  input, then approved-workspace canary and immutable catalog evidence.

Source: [Linear MCP documentation](https://linear.app/docs/mcp).

## Atlassian: Jira and Confluence

- Current recommended endpoint:
  `https://mcp.atlassian.com/v1/mcp/authv2`. The provider's current setup page
  still contains an older `/v1/mcp` quick-install link, but explicit client
  instructions use `authv2`; do not treat the two as interchangeable evidence.
- Authentication: provider-managed OAuth 2.1, with optional API-token mode.
  The public setup page does not by itself prove Cloudflare's automatic DCR
  flow against `authv2`. Domain allowlisting and existing IP controls may also
  apply. API-token mode is outside the current gateway contract.
- Read-only evidence: Atlassian's organization-level MCP **Permissions** tab
  controls Read, Write, and Search. Blocking Write prevents MCP creation and
  modification, with immediate enforcement and an access-denied response.
  Permissions can be set per app, including Jira versus Confluence.
- Important operator choice: these are organization MCP settings, not a
  gateway-local setting. A setup guide must explain that blocking Write can
  affect other MCP clients. Never change it automatically as a canary setup
  detail. Avoid enabling automatic future permissions.
- Exact seed: obtain the current `authv2` tool catalogue after read-only policy
  setup. The provider's supported-tools page did not return its tool body during
  this review, so no third-party list is promoted as an exact seed.
- Next implementation: separate Jira and Confluence business-source guidance
  may resolve to the same provider endpoint with different exact allowlists.
  Preserve the gateway's installed-source identity rules; do not pretend those
  are independent credentials or create duplicate connections automatically.

Sources: [current setup](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/getting-started-with-the-atlassian-remote-mcp-server/),
[provider-enforced MCP permissions](https://support.atlassian.com/security-and-access-policies/docs/Configure-Atlassian-Rovo-MCP-server-permission/),
[domain and authentication controls](https://support.atlassian.com/security-and-access-policies/docs/control-atlassian-rovo-mcp-server-settings/),
[supported-tools reference](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/supported-tools/).

## Sentry

- Endpoint: `https://mcp.sentry.dev/mcp`.
- Authentication: provider-run remote OAuth supports DCR and PKCE. Sentry's
  provider-maintained architecture describes separate MCP grants carrying
  approved skills and upstream Sentry tokens; the client does not receive the
  upstream token directly.
- Read-only route: explicitly choose **only `inspect`** in provider consent.
  The current provider testing guide calls this the minimal selection and
  requires write tools to be absent for read-only grants. Its architecture
  states that skill/capability filters apply both to directly exposed tools and
  catalog execution.
- Do not repeat stale advice: an older merged 2025 change described read-only
  as the default. The current remembered-consent specification instead selects
  all active approvable skills when there is no remembered choice. That can
  include `triage` and `project-management`, which enable writes. A remembered
  browser preference is not a gateway attestation of the new grant.
- Exact current wrapper names documented by the provider are
  `search_sentry_tools` and `execute_sentry_tool`. These are not inherently
  read-only: their allowed operations depend on the provider-side grant.
  Do not seed a generic executor until the canary proves the `inspect` boundary
  also holds for catalog execution. Older direct-tool lists are not proof of
  today's public `tools/list` surface.
- Next implementation: grant-specific instructions and a small live-verified
  tool seed; test direct and catalog attempts to call a write capability without
  carrying out a real mutation. Sentry's upstream OAuth permissions may be
  broader than the MCP skill grant, so name the actual provider MCP enforcement
  boundary accurately.

Sources: [Sentry MCP endpoint and setup](https://docs.sentry.io/product/sentry-mcp/),
[OAuth architecture](https://github.com/getsentry/sentry-mcp/blob/main/docs/cloudflare/oauth-architecture.md),
[current consent defaults](https://github.com/getsentry/sentry-mcp/blob/main/docs/specs/remembered-oauth-skills.md),
[provider testing guide](https://github.com/getsentry/sentry-mcp/blob/main/docs/testing/remote.md),
[catalog execution architecture](https://github.com/getsentry/sentry-mcp/blob/main/docs/architecture/overview.md).

## GitHub

- Read-only endpoint: `https://api.githubcopilot.com/mcp/readonly`.
  Provider-supported narrower examples include
  `https://api.githubcopilot.com/mcp/x/issues/readonly` and
  `https://api.githubcopilot.com/mcp/x/repos/readonly`.
- Authentication: GitHub's host integration guide requires an existing GitHub
  App or OAuth App, or a pre-generated access token. GitHub explicitly stated
  that DCR is unsupported; the current host guide still instructs integrators
  to register an app and handle its client secret. Do not infer automatic
  Cloudflare compatibility from the one-click VS Code experience.
- Read-only evidence: GitHub documents `/readonly` as a provider server mode
  enabling only read tools. Prefer this URL to relying on
  `X-MCP-Readonly`, since arbitrary request headers are not part of the gateway
  contract. GitHub App or fine-grained token read permissions are useful
  defense in depth if a supported secret-storage/auth path is later designed.
- Exact small seed candidates documented in the provider repository:
  `get_file_contents`, `issue_read`, `pull_request_read`. Their presence on the
  selected endpoint still needs live discovery; method arguments for grouped
  read tools must also be reviewed.
- Next implementation: prepare a secret-free manual-app setup guide; do not add
  client-secret fields to the catalog or route them through Ankka. Authentication
  topology is the blocker, not a missing GitHub API adapter.

Sources: [remote server modes](https://github.com/github/github-mcp-server/blob/main/docs/remote-server.md),
[host integration and OAuth](https://github.com/github/github-mcp-server/blob/main/docs/host-integration.md),
[provider tool documentation](https://github.com/github/github-mcp-server),
[provider DCR explanation](https://github.com/github/github-mcp-server/issues/1081).

## Salesforce

- Production read-only endpoint:
  `https://api.salesforce.com/platform/mcp/v1/platform/sobject-reads`.
- Sandbox/scratch endpoint:
  `https://api.salesforce.com/platform/mcp/v1/sandbox/platform/sobject-reads`.
- Authentication: enable the server in Salesforce and configure an External
  Client App with `mcp_api` and `refresh_token`, using OAuth and PKCE. Hosted
  MCP is documented for Enterprise Edition and above. This is a manual-client
  integration, not established DCR compatibility.
- Read-only evidence: Salesforce explicitly documents that `sobject-reads`
  cannot create, update, or delete data. Existing object permissions, field
  access, and sharing rules also apply. Prefer this dedicated server over the
  broader Headless 360, SObject All, or mutation endpoints.
- Tool contract: the reference describes schema discovery, SOQL, SOSL, current
  identity, recently viewed records, and relationship traversal. The rendered
  page did not preserve most exact tool headings; do not infer names from prose.
  Obtain the exact catalogue for the enabled Salesforce server before seeding.
- Next implementation: setup guidance can pin the two public environment
  endpoints; environment selection must be explicit. No Salesforce adapter is
  warranted merely because manual OAuth is not implemented yet.

Sources: [SObject Reads contract](https://developer.salesforce.com/docs/platform/hosted-mcp-servers/references/reference/sobject-reads.html),
[provider GA setup and security announcement](https://developer.salesforce.com/blogs/2026/04/salesforce-hosted-mcp-servers-are-now-generally-available).

## Slack

- Endpoint: `https://mcp.slack.com/mcp`, Streamable HTTP only.
- Authentication: **no DCR**. Slack requires a registered app with a fixed app
  identity and confidential OAuth client credentials. Only internal apps and
  Marketplace-published apps may use MCP; unlisted distributed apps are not a
  substitute. PKCE is supported.
- Provider authentication endpoints are
  `https://slack.com/oauth/v2_user/authorize` and
  `https://slack.com/api/oauth.v2.user.access`. Let a supported OAuth client use
  provider metadata rather than inventing a separate gateway token exchange.
- Read-only evidence: Slack publishes tool-to-user-scope mappings. Search uses
  `search:read.public`, `search:read.private`, `search:read.mpim`, and
  `search:read.im`; files can require `search:read.files` / `files:read`;
  message history uses the appropriate channel/group/DM `:history` scopes.
  Exclude `chat:write`, conversation-creation scopes, `reactions:write`, and
  `canvases:write`. Choose only the data categories actually needed.
- Exact seed: the reference's table uses descriptive labels, not a complete
  canonical MCP-name catalogue. Do not turn those labels into invented names.
- Next implementation: an internal-app setup recipe is credible for a
  self-hosted team gateway, but manual OAuth, permitted client identity, user
  grants, refresh and exact tools must be designed and verified first.

Source: [Slack MCP server contract](https://docs.slack.dev/ai/slack-mcp-server/).

## HubSpot

- Endpoint: `https://mcp.hubspot.com/`, Streamable HTTP.
- Authentication: create a HubSpot MCP auth app, configure its redirect URL,
  and use its client ID and secret with PKCE. This is a manual-client path.
- Permissions: current detailed documentation says the MCP app's scopes are
  determined by available tools and permissions chosen during installation,
  not an arbitrary scope list authored when creating the app. It now supports
  both CRM reads and mutations. Older landing-page wording about read-only
  scopes must not override the current integration guide.
- Exact bounded read seed candidates: `get_user_details`,
  `search_crm_objects`, `get_crm_objects`, `search_properties`,
  `get_properties`, `search_owners`. The provider describes each as reading
  data; exclude `manage_crm_objects`. Avoid prose tool labels containing spaces
  elsewhere on the page as presumed protocol names.
- Read-only blocker: prove the actual install grants and user permission
  combination deny every write category; do not assume listing only the six
  read tools restricts the token. Reinstallation is required for new scopes.
- Next implementation: secret-free manual-app setup guidance, then a consent
  and refresh design outside the hosted installer. Sensitive Data settings can
  also block activity and conversation objects, which should be surfaced as a
  provider limitation rather than treated as an empty CRM.

Source: [current remote HubSpot MCP integration guide](https://developers.hubspot.com/docs/apps/developer-platform/build-apps/integrate-with-the-remote-hubspot-mcp-server).

## Stripe

- Endpoint: `https://mcp.stripe.com`.
- Authentication: provider OAuth with revocable MCP sessions, or a restricted
  API key. The provider MCP page cites standards-based OAuth but does not
  explicitly settle all DCR and read-only scope details required for this
  gateway. An unauthenticated metadata probe and a canary should verify them.
- Current exact read seed candidates: `get_stripe_account_info`,
  `stripe_api_search`, `stripe_api_details`, `stripe_api_read`.
  Stripe explicitly limits `stripe_api_read` to API GET methods; exclude
  `stripe_api_write`, which supports POST/PATCH/PUT/DELETE. The server no longer
  should be assumed to expose only older resource-specific tools such as
  `list_customers`.
- Read-only blocker: GET-only execution is a useful server boundary for the
  selected tool, but does not prove the connection's authorization is read-only
  across other tools. Verify the OAuth consent grant or use a reviewed
  restricted-key path with only needed Read permissions. The current gateway
  accepts neither provider keys nor arbitrary headers.
- Do not include analytics/reporting tools in the initial read seed merely
  because their purpose is analytical. Stripe documents Analytics, Financial
  Reports, and Sigma write permissions for these POST-based operations; report
  creation is a separate capability decision.
- Connect-platform access requires a restricted key plus `Stripe-Account`;
  OAuth is not supported for that use case and it is outside this preset.

Sources: [current Stripe MCP contract and tool list](https://docs.stripe.com/mcp),
[analytics permission requirements](https://docs.stripe.com/data/analyze-with-ai),
[restricted API keys](https://docs.stripe.com/keys/restricted-api-keys).

## GitLab

- GitLab.com endpoint: `https://gitlab.com/api/v4/mcp`. Self-managed and
  Dedicated instances use their own `/api/v4/mcp`; those are not one fixed
  provider-hosted catalog URL.
- Authentication: GitLab documents OAuth 2.0 DCR and direct HTTP transport.
  The server must be enabled at the appropriate group or instance boundary;
  availability depends on deployment/version and related GitLab settings.
- Exact read seed candidates from the current tool reference: `get_issue`,
  `get_merge_request`, `get_repository_file`, `get_commit`, `list_pipelines`,
  `get_pipeline`, `get_pipeline_jobs`, `get_job`, `list_wiki_pages`.
- Read-only blocker: the same server includes `add_commit`, `create_issue`,
  `save_merge_request`, `accept_merge_request`, and pipeline mutations. This
  review did not prove a dedicated read-only endpoint or a read-only MCP OAuth
  scope. Ordinary project membership, a protected default branch, or a tool
  prefix does not establish a read-only identity; members can often still
  create issues or perform other mutations.
- Next implementation: verify a provider-side permission model that denies
  all mutations before connecting. Do not confuse the popular community
  GitLab MCP packages with GitLab's own remote service.

Sources: [GitLab native MCP setup](https://docs.gitlab.com/user/model_context_protocol/mcp_server/),
[GitLab native tool reference](https://docs.gitlab.com/user/model_context_protocol/mcp_server_tools/).

## Notion

- Endpoint: `https://mcp.notion.com/mcp`, Streamable HTTP. SSE exists only for
  older clients and is not the catalog target.
- Authentication: the provider client guide documents OAuth authorization
  code with PKCE, dynamic registration credentials, refresh handling, and
  optional Client ID Metadata Documents. That is promising structurally but
  is not a Cloudflare connection test.
- Exact read seed candidates: `notion-search` and `notion-fetch` from Notion's
  supported-tools reference. Search can include connected sources and its
  availability depends on the workspace's plan; fetching `self` includes
  current per-tool availability. Review data reach as well as write policy.
- Read-only blocker: the remote server can create and modify content with the
  connecting user's access. This review did not find an explicit remote MCP
  read-only endpoint or scope contract. Do not confuse Notion API integration
  capabilities or a custom Worker's `readOnlyHint` with authorization for the
  provider-run MCP connection.
- Next implementation: keep the native source held until an MCP-specific
  restricted grant or truly read-only identity is proved. Avoid a replacement
  API adapter unless that gap becomes a concrete product requirement.

Sources: [Notion MCP overview](https://developers.notion.com/guides/mcp/overview),
[client authentication guide](https://developers.notion.com/guides/mcp/build-mcp-client),
[supported tools](https://developers.notion.com/guides/mcp/mcp-supported-tools).

## Intercom

- US endpoint: `https://mcp.intercom.com/mcp`.
- EU endpoint: `https://mcp.eu.intercom.com/mcp`.
  The provider states AU-hosted workspaces are not yet supported. Region is an
  explicit setup choice, not an automatic fallback.
- Authentication: the provider describes browser OAuth and direct bearer API
  tokens. Its page does not explicitly enumerate DCR or granular OAuth scopes;
  verify current metadata and grant behavior before claiming compatibility.
- Exact read seed candidates: `search`, `fetch`, `search_conversations`,
  `get_conversation`, `search_contacts`, `get_contact`, `list_companies`,
  `get_company`, `list_articles`, `search_articles`, `get_article`.
  A small initial seed should select only needed categories, not all eleven.
- Read-only blocker: the current 13-tool server also includes `create_article`
  and `update_article`. The existence of conversation/contact reads does not
  mean its OAuth connection is read-only. A provider API-token Read permission
  recipe would still require a supported credential path and verification that
  the same restrictions apply through MCP.
- Next implementation: regional setup guidance and a tool policy draft;
  require actual read-only grants before a selectable native preset.

Source: [Intercom's current MCP contract](https://developers.intercom.com/docs/guides/mcp).

## Zendesk

No first-party, fixed remote MCP endpoint and read-only OAuth/tool contract was
verified in this review. Current Zendesk support documentation prominently
describes **Zendesk acting as an MCP client** in action flows. It mentions MCP
server use cases separately but that is not an endpoint contract. A Marketplace
listing named “MCP Server” is not proof that Zendesk publishes its runtime.

Do not invent `mcp.zendesk.com` or promote a community package as native. The
existing OAuth API supports a future narrow self-hosted adapter, but that needs
its own fixed-origin request policy, explicit read scopes, token lifecycle and
deployment/removal design. First confirm whether Zendesk has published a native
contract that removes that need.

Sources: [Zendesk's MCP client/action-flow documentation](https://support.zendesk.com/hc/en-us/articles/10497779528730-Connecting-to-MCP-servers-and-using-MCP-tools-in-action-flows),
[Zendesk OAuth refresh guidance](https://developer.zendesk.com/documentation/authentication/refresh-token/).

## Minimum qualification evidence

For each source that advances, retain only publishable, secret-free evidence:

1. Dated provider URL, endpoint, authentication mode and reviewed transport.
2. Exact Registry version/digest under the current contract, or a separately
   reviewed provenance extension; never a matching-name shortcut.
3. The actual Cloudflare registration and operator-shared OAuth behavior,
   including refresh and denied requests. Metadata is not a granted token.
4. An exact tool catalogue digest, selected read seed, and no automatic tool
   expansion. Grouped executor tools need operation-level authorization proof.
5. Proof of provider-enforced read-only access and a safe negative test of that
   boundary. No real production mutation is justified merely to test denial.
6. Approved canary account/resource ownership, cleanup/revocation and private
   receipts. No account IDs, tokens, raw provider data or consent URLs in git.

The research used provider documentation and provider-maintained repositories.
Raw fetched material is ignored maintenance data under `.firecrawl/native-*`;
this document is original analysis with links and protocol identifiers, not a
vendored implementation or a copied provider tool description catalogue.
