# B2B connector demand and implementation priorities

> Research checked on 2026-08-30. This is a prioritization record, not a list
> of released or authenticated integrations. A documented endpoint is not a
> passing gateway canary. No provider account was accessed for this research.

## Recommendation

Preserve the explicitly requested BigQuery, Search Console, Ahrefs, and Gorgias
work. In parallel, prioritize team knowledge and engineering context: Linear,
GitHub, Slack, Notion, Jira, Confluence, and Google Drive. Add CRM and support
coverage through Salesforce, HubSpot, Intercom, and Zendesk. Airtable, Google
Sheets, Google Analytics, Microsoft 365 files, and Snowflake are useful adjacent
sources, without making each one a separate bespoke integration platform.

This is an implementation shortlist, **not a measured ranking of individual
MCP providers**. The strongest near-term native candidate found in this review
is Linear's dedicated read-only endpoint. Salesforce also has a separately
documented read-only server, but needs a manually registered OAuth client.

For a solo developer, prefer a reviewed provider-native connection over a new
runtime. Where that is blocked, build a small, fixed read-only API adapter only
when it advances a concrete workflow. Share security primitives and tests, not
an arbitrary-URL, arbitrary-method credential proxy.

## Implemented from this review

The [self-hosted reader workspace](../apps/read-only-connectors/README.md) now
implements 19 ordinary read-only MCP tools across Notion, HubSpot, Zendesk,
Gorgias, Search Console, and Google Analytics 4. The Google readers use
deployment-owned service accounts; this does not unblock native BigQuery OAuth.
The dashboard also includes [19 native setup guides](NATIVE_CONNECTOR_SETUP.md).
These are locally tested implementations and documentary guides, not approved
production presets. The shortlist below records the research and remaining
provider-specific decisions; live authentication and lifecycle qualification
remain open.

## What the demand evidence actually supports

- **Direct product demand:** the four originally requested systems are the
  strongest evidence for this gateway's immediate audience. Broad market
  evidence should expand that list, not displace it.
- **Category-level survey:** Merge's 2026 survey landing page reports that
  more than 60% of respondents' companies plan MCP connections in categories
  including communications, CRM, knowledge management, and file storage. Its
  sample is hundreds of product managers and engineers at US companies with
  50+ employees already building agents. This measures reported intentions in
  a selected population, not installed connectors, market share, or solo-dev
  demand. Merge sells integration infrastructure, which is a relevant source
  limitation. [Survey and methodology](https://www.merge.dev/soai-2026)
- **Concrete developer request:** an OpenHands feature request specifically
  asks for easier OAuth connections to Slack and Notion, with Atlassian added
  in discussion. It demonstrates real setup friction and named demand; one
  issue is not a popularity ranking. [OpenHands request](https://github.com/openhands/agent-canvas/issues/2060)
- **Business-app adoption proxy:** Okta's 2025 report summary describes
  anonymized deployment data across thousands of its customers and the
  importance of collaboration and business-operation applications. This
  supports those categories as useful context sources, but does not measure
  MCP usage or the addressable market for this gateway. [Okta methodology and summary](https://www.okta.com/newsroom/articles/businesses-at-work-2025/)
- **Availability is not demand:** provider documentation, MCP Registry
  records, GitHub stars, and third-party “best MCP” lists can identify
  implementation candidates. They do not establish that teams want, use, or
  will pay for a particular connection. This review found no sufficiently
  comparable, primary provider-by-provider usage dataset to justify numeric
  popularity scores.

The resulting product hypothesis is that a useful bundle connects **team
knowledge + work tracking + CRM/support + business analytics**. It should be
tested against actual operator requests as the product gains users, without
adding telemetry to self-hosted gateways.

## Shortlist and attainable implementation

“Local work” below means code, synthetic tests, setup guidance, or reviewed
connection metadata that can be prepared without a provider login. It does not
mean a production catalog entry is approved. The source's authentication,
exact tool names, upstream read-only enforcement, provenance, and Cloudflare
topology still need verification.

| System | Why include it | Documented path and read-only boundary | Local work / remaining gate |
| --- | --- | --- | --- |
| **BigQuery** | Explicit priority; joins business analytics across systems. | Google-managed remote MCP; OAuth/IAM and tool-specific controls. | Retain the existing auth-classification protection and prepare a narrow reporting tool review. Manual OAuth and operator-shared Cloudflare compatibility remain blockers; do not replace IAM with SQL text heuristics. [Existing review](SOURCE_CATALOG_CANDIDATES.md#bigquery), [Google](https://docs.cloud.google.com/bigquery/docs/use-bigquery-mcp) |
| **Google Search Console** | Explicit priority; search-performance reporting. | Existing experimental self-hosted Code Mode adapter with fixed operations and `webmasters.readonly`. | Extend synthetic policy and lifecycle tests; operator-owned OAuth, provisioning/removal, and live verification remain necessary. Keep Portal Code Mode off for the nested Code Mode source. [Existing review](SOURCE_CATALOG_CANDIDATES.md#google-search-console), [Google authorization](https://developers.google.com/webmaster-tools/v1/how-tos/authorizing) |
| **Ahrefs** | Explicit priority; complements Search Console with SEO research. | Provider remote MCP with OAuth. Provider terms and exact authenticated tools need review. | Prepare endpoint/provenance evidence and bounded tool-review checks. Do not conduct an authenticated canary before permission for gateway/bridge use is resolved. [Existing review](SOURCE_CATALOG_CANDIDATES.md#ahrefs), [Ahrefs](https://docs.ahrefs.com/en/mcp/docs/introduction) |
| **Gorgias** | Explicit priority; support context for commerce teams. | Provider remote MCP includes reads and writes; granular provider scopes must be proved, not inferred from tool names. | Keep the synthetic OAuth-scope diagnostic and prepare a minimal ticket-read policy. Do not use a production support account as an unattended canary. [Existing review](SOURCE_CATALOG_CANDIDATES.md#gorgias), [Gorgias](https://docs.gorgias.com/en-US/connect-your-ai-assistant-to-the-gorgias-mcp-6310546) |
| **Linear** | Focused issue/project context; strong fit for small product teams. | `https://mcp.linear.app/mcp/readonly`; provider documents a read-only endpoint and OAuth 2.1 dynamic client registration. The alternative `read` OAuth scope also prevents write API access. | First native compatibility target: pin the read-only path, review exact tools, test discovery/classification, then verify real Cloudflare authentication and write rejection. The default `/mcp` is read-write. [Linear](https://linear.app/docs/mcp) |
| **GitHub** | Code, issues, PRs, and delivery context for the gateway's developer audience. | Provider remote supports `/mcp/readonly` and narrower `/mcp/x/{toolset}/readonly` paths. Host OAuth requires a registered GitHub/OAuth app; PATs are a separate option. | Prepare a small repository/issue/PR tool recommendation and read-only URL checks. Avoid secret-protection tools and workflow mutations. Verify auth and upstream rejection; do not add generic secret-header catalog recipes. [Remote configuration](https://github.com/github/github-mcp-server/blob/main/docs/remote-server.md), [authentication](https://github.com/github/github-mcp-server#remote-github-mcp-server) |
| **Slack** | Communications is a demand-supported category; a named developer request exists. | `https://mcp.slack.com/mcp`; documented per-tool read scopes. No dynamic client registration; confidential OAuth and an internal or Marketplace-published app are required. | Prepare a read-scope/tool mapping and setup recipe. Shared-operator auth must be resolved; do not silently share one person's private conversations with the team. [Slack](https://docs.slack.dev/ai/slack-mcp-server/) |
| **Notion** | Knowledge retrieval and the named developer demand above. | Hosted MCP uses OAuth and can update content. Separately, Notion API connections/PATs can enforce only the **Read content** capability. | Prefer proving hosted read-only identity access; otherwise a bounded self-hosted API adapter with page/data-source reads and capability-limited credentials is feasible. Do not assume the hosted grant inherits a separately configured API integration. The old provider open-source MCP server is no longer actively maintained. [Hosted MCP](https://developers.notion.com/guides/mcp/overview), [capabilities](https://developers.notion.com/reference/capabilities), [maintenance status](https://developers.notion.com/guides/mcp/get-started-with-mcp) |
| **Jira** | Issue/status context; named Atlassian demand and collaboration-category fit. | Atlassian Rovo MCP supports Jira and obeys provider permissions, but also offers mutations. | Prepare exact issue/project read tools and scoped API/identity guidance. A read tool list alone does not make an editor's grant read-only; domain/IP approval can also block authentication. [Tools](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/supported-tools/), [controls](https://support.atlassian.com/security-and-access-policies/docs/control-atlassian-rovo-mcp-server-settings/) |
| **Confluence** | Knowledge/documentation category; complements Jira without a second provider runtime. | Same Atlassian remote, with Confluence tools and provider authorization. | Prepare page/search reads as a distinct business-source recipe while sharing connection implementation. Verify page visibility and mutation denial; do not turn a shared administrator grant into organization-wide document access. [Atlassian tools](https://support.atlassian.com/atlassian-rovo-mcp-server/docs/supported-tools/) |
| **Salesforce** | CRM is a demand-supported category; broad cross-system account context. | `https://api.salesforce.com/platform/mcp/v1/platform/sobject-reads` cannot create/update/delete through that server. Requires org activation and an External Client App; OAuth uses `mcp_api` and refresh access. | Prepare the read-server recipe, exact schema/query tools, and bounded-query guidance. Manual OAuth/operator-shared topology and a sandbox canary remain gates. Do not choose `sobject-all`. [Read-only server](https://developer.salesforce.com/docs/platform/hosted-mcp-servers/references/reference/sobject-reads.html), [setup](https://developer.salesforce.com/docs/platform/hosted-mcp-servers/guide/setup-overview.html), [GA/auth overview](https://developer.salesforce.com/blogs/2026/04/salesforce-hosted-mcp-servers-are-now-generally-available) |
| **HubSpot** | CRM and marketing context with an approachable small-team audience. | `https://mcp.hubspot.com`; manual MCP auth app and PKCE. Current hosted server supports both reads and writes. Scopes depend on offered tools and installation permissions, not ordinary app-defined scopes. | Prepare a minimal CRM-read subset and test recipe. Prove a read-only installation/identity or use a separately scoped API adapter. Do not rely on older descriptions of the server as read-only; exclude management and feedback tools. [HubSpot](https://developers.hubspot.com/docs/apps/developer-platform/build-apps/integrate-with-the-remote-hubspot-mcp-server) |
| **Intercom** | Support conversations and account context; adjacent to the requested Gorgias workflow. | US and EU provider MCP endpoints are documented. Read conversations/contacts permissions exist, but Help Center article access requires combined read/write article permission; article mutations are present. | Prepare a conversations/contacts-only subset with region-specific endpoints. Prove that the grant omits article write authority; do not label the full server read-only. [Intercom](https://developers.intercom.com/docs/guides/mcp) |
| **Zendesk** | Support workflow adjacency; established ticketing API. | Zendesk OAuth supports `read` and resource-specific scopes. This review did not verify a provider-native remote MCP suitable for this flow. | A narrow ticket/user/organization read adapter is feasible with a fixed validated Zendesk tenant origin and read-only OAuth credential. Avoid unrestricted search/export and API-token assumptions; token lifecycle and real canary remain gates. [OAuth scopes](https://developer.zendesk.com/api-reference/ticketing/oauth/oauth_tokens/#scopes), [OAuth setup](https://support.zendesk.com/hc/en-us/articles/4408845965210-Using-OAuth-authentication-with-your-application) |
| **Google Drive** | File storage is a demand-supported category. | Google now documents `https://drivemcp.googleapis.com/mcp/v1`, with manual OAuth client setup and `drive.readonly` available. The server also has write tools. | Prefer this native path over a new Drive wrapper. Prepare exact metadata/search/content reads; verify read-scope enforcement, refresh, and Cloudflare auth. `drive.readonly` is a restricted scope; `drive.file` is not a read-only replacement. [Workspace setup](https://developers.google.com/workspace/guides/configure-mcp-servers), [Drive scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth) |
| **Google Sheets** | Natural companion to the requested analytics workflows; a product hypothesis, not measured provider demand. | `https://sheetsmcp.googleapis.com/mcp/v1`; Google documents read scopes and `get_values`/`get_spreadsheet`, alongside write tools. | Reuse the Google auth approach, with exact read tools and bounded ranges. Do not count a second endpoint as a second proven authentication integration. [Workspace setup and tools](https://developers.google.com/workspace/guides/configure-mcp-servers) |
| **Google Analytics** | Direct analytics complement to Search Console and BigQuery. | Google maintains an MCP implementation requiring `analytics.readonly` credentials; it is not automatically a compatible fixed remote source. | Reuse reviewed reporting operations, property boundaries, and synthetic tests if a self-hosted runtime is justified. Do not run its package inside the management Worker or invent a hosted endpoint. [Google guide](https://developers.google.com/analytics/devguides/MCP), [provider implementation](https://github.com/googleanalytics/google-analytics-mcp) |
| **Microsoft 365 files** | SharePoint/OneDrive cover the other major file/knowledge ecosystem. | Graph Selected permissions can restrict access to named resources; an explicit `read` resource role is required in addition to consent. Copilot Studio's SharePoint MCP tool listing is not proof of a generally usable gateway endpoint. | Prepare a selected-site/file read adapter or validate a native route before building one. Entra app setup, resource assignment, and tenant consent are real operator steps. Avoid broad tenant-wide permissions by default. [Selected permissions](https://learn.microsoft.com/en-us/graph/permissions-selected-overview), [SharePoint MCP context](https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-sharepoint-tools) |
| **Snowflake** | Warehouse/analytics adjacency; larger-team candidate after BigQuery. | Account-hosted managed MCP supports OAuth, custom tools, and SQL execution. Its SQL tool documents `read_only: true`; arbitrary procedures/agents are not automatically read-only. | Prepare a per-account recipe using a dedicated least-privileged role and fixed safe tools. Account-specific URL, OAuth integration, cost bounds, and provider-side configuration need verification; avoid implementing another general SQL parser. [Snowflake](https://docs.snowflake.com/en/user-guide/snowflake-cortex/cortex-agents-mcp) |
| **Airtable** | Lightweight operational data for small teams; adjacent to CRM/spreadsheet workflows. | `https://mcp.airtable.com/mcp`; provider documents read-only scopes: `data.records:read`, `schema.bases:read`, `data.recordComments:read`, `workspacesAndBases:read`. Provider base permissions also constrain writes. | Prepare a base/schema/record read recipe with selected bases, exact tools, and scope evidence. Prove OAuth compatibility or a narrowly reviewed token lifecycle; default editor access is not read-only. [Airtable](https://support.airtable.com/articles/9897799762-using-the-airtable-mcp-server) |

## Smallest useful delivery sequence

1. **Native read-only candidates:** advance Linear first; prepare GitHub,
   Salesforce, Airtable, and scoped Google Workspace recipes. Shared connection
   tests should cover authentication classification, fixed endpoint resolution,
   unknown tools, and no automatic tool expansion.
2. **The explicitly requested business workflows:** continue Search Console
   and BigQuery reporting work; keep Gorgias behind read-scope proof and Ahrefs
   behind the usage-permission check. Those blockers should not halt unrelated
   local integration work.
3. **Small API-backed readers where needed:** prioritize Notion, CRM, and
   support reads only when a native route cannot satisfy the current boundary.
   Use fixed provider origins, typed operations, bounded pages/results,
   explicit resources, sanitized errors, and credentials held only in your
   Cloudflare account. No arbitrary HTTP escape hatch is needed.
4. **Only then broaden:** Microsoft files and Snowflake need more operator
   configuration. Build reusable testable pieces now, but avoid provisioning
   machinery or enterprise policy frameworks without real users needing them.

## What counts as an integration result

Report three states separately:

- **Researched:** primary endpoint/auth/read-only evidence is recorded.
- **Locally implemented:** resolution or adapter behavior exists and synthetic
  positive/negative tests pass. This can be useful work even before login.
- **Live verified / release eligible:** the exact source works through the
  supported gateway topology, upstream writes are denied, refresh/recovery are
  exercised where applicable, and the catalog's provenance/release gates pass.

A green test using a synthetic OAuth server proves the fixture or client
behavior it exercised, not the scope or behavior of a real provider. Likewise,
the availability of a `/readonly` path is strong review evidence but still
needs an authenticated negative test before being represented as verified.
Keep production catalog claims aligned with those distinctions. A useful
overnight result can include many working local readers and reviewed recipes
without silently enabling unverified sources.

All text here is original synthesis with links to public sources; no upstream
code, schemas, branding assets, or private account data were transferred.
