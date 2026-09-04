# Google BigQuery authentication compatibility

Direct endpoint review: 2026-08-30. **Direct Google shared authentication remains
blocked.** Public discovery works, but Cloudflare's documented manual OAuth
path does not provide the shared operator credential this gateway requires.
During that review no Google client, credential, IAM policy, dataset, export, or
adapter was created. An isolated Cloudflare source was created for a live setup check; it
is not attached to a Portal and all six tool overrides are disabled. Existing
sources and Portal Code Mode were not changed.

The selected follow-up is an experimental
[bridge to Google's hosted MCP](../apps/read-only-connectors/BIGQUERY_MCP_EXPERIMENT.md)
running in your Cloudflare account. Direct client connectivity through that
bridge, Ankka source provisioning, and shared Portal access with a controlled
second identity are proven. Portal-wide session revocation is qualified;
selective disconnection is not promised. Claude Desktop has passed sign-in,
tool discovery, metadata reads, continued operation beyond the initial token
lifetime, and reconnection. Useful query cost controls and client qualification
of that query path still gate support; see the bridge's current evidence and support
gates. The direct-endpoint block below remains enforced.
The bridge uses a service-account secret in your Cloudflare account and
currently restricts SQL to a constant connectivity query.

## Compatibility result

The preferred upstream remains Google's hosted
`https://bigquery.googleapis.com/mcp`. Google supports neither dynamic client
registration nor OAuth Client ID Metadata Documents. A pre-registered client
is required for its browser OAuth flow. See [Google MCP authentication](https://docs.cloud.google.com/mcp/authenticate-mcp#oauth-client-id).

Cloudflare added [manual OAuth credentials](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/#configure-manual-oauth-credentials),
including encrypted client-secret storage. This does **not** establish support
for the required shared credential topology:

- The current Cloudflare OpenAPI contract for
  `GET /accounts/{account_id}/access/ai-controls/mcp/servers/{id}` describes
  `authentication_status` as: “Manual OAuth is user-managed and has no
  administrative authentication flow.” It includes a distinct `manual` status.
- Cloudflare documents manual-server capability capture during the first
  **user** authorization; background and manual synchronization do not refresh
  those capabilities. See [Portal known limitations](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/#known-limitations).
- Turning **Require user auth** off (`on_behalf: false`) uses the server's
  **admin credential**. A user's manual OAuth grant is not documented as
  becoming that shared credential. See [Portal configuration](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/#create-a-portal).

Therefore this topology is unsupported by the reviewed contract, rather than
proven impossible in every Cloudflare implementation. No authenticated manual
OAuth canary was possible without a new Google client and human consent.
Do not infer shared access from successful public `tools/list`, a manual client
configuration, or one user's successful upstream login.

The missing provider capability is: **obtain an admin Google grant with a
pre-registered client, retain and refresh it in Cloudflare, and use it for every
authorized Portal member while `on_behalf` remains false.** Cloudflare's
documented automatic-registration admin-token refresh is not proof of this
manual-client flow.

## Live Cloudflare setup attempt

A subsequent dashboard/API check confirmed the following without supplying a
Google credential or issuing a data query:

- Creating an isolated OAuth source succeeded. Its authentication status remains
  `required`, with zero discovered tools. The dashboard's six-tool count reflects
  the explicit disabled overrides, not authenticated discovery.
- The automatic-mode **Authenticate server** action did not produce an observed
  Google consent page. The capability-sync connector returned an ambiguous error
  with HTTP 200, so neither action proves a specific Google incompatibility.
  The detached source also has no associated Access application; its dashboard
  warns about that incomplete setup. No application or access policy was created.
- Selecting **Manual credentials** in the unsaved form exposes client ID and
  secret fields and removes **Authenticate server**. The scope help text refers
  to end users logging out and back into the Portal. This supports the documented
  per-user interpretation; it is not an authenticated test of shared access.
- **Discover OAuth endpoints** successfully populated Google's authorization,
  token, revocation and issuer fields. The displayed manual redirect URI is
  `https://oauth-callbacks.cloudflareaccess.com/cdn-cgi/access/outbound-oauth-callback`.
  No manual credentials or configuration were saved, and runtime redirect and
  token refresh behavior remain unverified.

This attempt reaches the explicit new-credential/human-consent gate. A
pre-registered Google client would permit further manual-flow testing, but is
not evidence that a shared operator grant is supported.

The [Agents authorization guide](https://developers.cloudflare.com/agents/model-context-protocol/protocol/authorization/)
describes implementing OAuth in a Worker, including a third-party provider such
as Google. That is a possible custom auth service, not proof of a managed Portal
configuration. The [SaaS-managed server section](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/secure-mcp-servers/#saas-managed-third-party-mcp-server)
requires the upstream service to accept a configurable OAuth/OIDC identity
provider. It does not establish that Google BigQuery accepts a Cloudflare-issued
token directly. Google's workload identity federation is another design to
evaluate; no compatible Portal token-exchange flow has been demonstrated here.

## Implemented protection

The management Worker recognizes the exact Google BigQuery MCP endpoint as
OAuth-protected even when its public catalogue succeeds. Discovery returns its
tool summaries and the fixed `source_google_shared_oauth_unsupported` block.
The dashboard shows the catalogue and block without selecting any tools or
offering a usable Save action. No secret input is added.

Saving, preparing an apply action, and executing an existing apply action all
recheck the boundary. Old BigQuery drafts cannot bypass it by claiming
`authMode: none`. Discovery still rejects credential-bearing URLs and unknown
request fields, does not follow redirects, executes no tools, and uses the
existing response-size and timeout budgets. Other endpoints retain their
existing discovery behavior. This is not a production catalog approval.

## Read-only identity and exact tools

Use a dedicated Google identity, not an owner, editor, or BigQuery administrator.
An administrator provisions permissions separately; the connecting identity
does not need permission to enable APIs or manage IAM.

| Role | Grant scope | Purpose |
| --- | --- | --- |
| `roles/mcp.toolUser` | Projects addressed by MCP calls: query project, and data project for metadata if different | `mcp.tools.call` |
| `roles/bigquery.jobUser` | Query/billing project only | `bigquery.jobs.create` |
| `roles/bigquery.dataViewer` | Intended GA4 dataset only | Read data and inspect table metadata |

Google documents these roles for [BigQuery MCP](https://docs.cloud.google.com/bigquery/docs/use-bigquery-mcp#required-roles).
Data Viewer can be scoped to a dataset, while Job User is granted on Resource
Manager resources. These are predefined roles, not a claim of an exact
three-permission identity: Data Viewer also includes export, snapshot and
routine permissions. Do not grant destination write permissions, connection
use, unrelated datasets, or inherited broad privileges. Audit effective access,
including group and project inheritance. See [BigQuery role definitions](https://docs.cloud.google.com/bigquery/docs/access-control).

The required OAuth scope is `https://www.googleapis.com/auth/bigquery`; it is
not read-only. Dataset-scoped IAM and Google's read-only tool enforcement are
essential. Do not substitute `bigquery.readonly` without provider support.

Live unauthenticated discovery returned exactly these six names. Argument keys
in the actual JSON schemas are **camelCase**, despite snake_case in some prose.

| Tool | Proposed initial exposure | Relevant arguments |
| --- | --- | --- |
| `list_dataset_ids` | Exclude; dataset is already known | `projectId`, `pageSize`, `pageToken` |
| `get_dataset_info` | Exclude unless metadata is needed | `projectId`, `datasetId` |
| `list_table_ids` | Include for finding daily export tables | `projectId`, `datasetId`, `pageSize`, `pageToken` |
| `get_table_info` | Include for verifying the export schema | `projectId`, `datasetId`, `tableId` |
| `execute_sql_readonly` | Include for bounded reads | `projectId`, `query`, `dryRun`, `labels` |
| `execute_sql` | Always exclude; permits writes | Never call |

This three-tool set is a reviewed proposal, not an installed allowlist.
Google's `execute_sql_readonly` rejects mutations, stored procedures and Python
UDFs. Also have the administrator apply the documented
[read-write MCP deny policy](https://docs.cloud.google.com/mcp/control-mcp-use-iam#deny_read-write_mcp_tool_use)
to the dedicated source identity and relevant query project. The denied
permission is `mcp.googleapis.com/tools.call`; the condition is
`api.getAttribute('mcp.googleapis.com/tool.isReadOnly', false) == false`.
Review its attachment and principal scope rather than copying a project-wide
all-principals policy into a working environment. Do not test this by attempting
a real production mutation.

## Rows, time and cost

Google documents a three-minute query timeout and a maximum 3,000 returned rows
for its hosted SQL tools. These are provider ceilings, not settings this change
enforces. The live read-only schema has `dryRun` but **no** `maximumBytesBilled`,
`maxResults`, configurable timeout, location, or query-parameter field. Unknown
arguments are not an enforcement mechanism. See [hosted limitations](https://docs.cloud.google.com/bigquery/docs/use-bigquery-mcp#limitations)
and [read-only tool schema](https://docs.cloud.google.com/bigquery/docs/reference/mcp/tools_list/execute_sql_readonly).

For a future canary, list at most 10 tables per page, inspect one known daily
table, dry-run a query limited to one completed export date, and execute only
after the byte estimate is within the operator's agreed budget. Aggregate in
BigQuery and use `LIMIT 20` for the product sample. A SQL limit bounds returned
rows; it does not bound bytes scanned. A dry run is an estimate, not a hard
budget at execution time. Do not retry a timed-out query automatically.

For on-demand billing, Google offers `QueryUsagePerDay` and
`QueryUsagePerUserPerDay` custom quotas. Configure a small approved quota on a
dedicated query project before a paid read; do not lower an existing production
project's quota without reviewing its other workloads. These are daily quotas,
not per-query `maximumBytesBilled`, and do not apply to capacity pricing.
See [custom query quotas](https://docs.cloud.google.com/bigquery/docs/custom-quotas).
Strict per-request cost/time/row policy remains a gap in the direct hosted path.

Do not log arguments, SQL, query results, OAuth codes, headers or provider error
bodies in application logs. Do not enable Model Armor payload logging or export
Portal request/response body fields. Google's own job history and audit records
are provider-managed data; do not copy them into this repository or Ankka.

## Smallest next step and alternative

First obtain Cloudflare confirmation or a supported update for **manual OAuth
with a shared admin credential**, including Google offline access and refresh.
No new Worker is justified if Cloudflare can supply this capability. A first
user authorization with Require user auth enabled does not satisfy this test.

If Cloudflare cannot support it, the smallest design to review is one
BigQuery-specific Worker in your Cloudflare account, with an operator-only
Google connection/refresh flow and a fixed three-tool upstream client to the
same Google-hosted MCP endpoint. It would accept no caller-provided destination
or credential headers, expose ordinary MCP tools so Portal Code Mode stays on,
and use a Portal-compatible shared credential. Google secrets would be stored
only in your account, independently from BLS and the installer grant. This
requires new credential provisioning and auth-service scope, so it is proposed,
**not implemented**. If hard per-query budgets are mandatory, review a direct
BigQuery API adapter instead, because an auth bridge alone cannot add missing
Google-hosted MCP controls.

**2026-08-30 update:** that direct-API alternative now exists as the
experimental `bigquery` reader in the
[read-only connector Worker](../apps/read-only-connectors/GOOGLE.md). It
mirrors the hosted read tools' names and arguments with a service-account
identity, a mandatory dry-run `SELECT` gate, and a per-query
`maximumBytesBilled` budget, closing the cost-control gap described below for
that path. It is a local experimental implementation behind the Worker's own
Cloudflare Access boundary — not a catalog preset and not a change to this
document's hosted-endpoint analysis or block.

## Setup requiring your action

Do not provision a client just to try the currently unsupported topology.
Once Cloudflare confirms support, these are the remaining setup steps:

1. Have your Google administrator prepare the dedicated identity, scoped roles,
   write-tool deny policy, and query budget above. Leave the existing GA4 export
   unchanged. Keep project/dataset IDs in your private operational configuration.
2. In [Google Auth Platform → Clients → Create client](https://console.cloud.google.com/auth/clients/create),
   select **Web application**. Configure the consent screen/audience for the
   dedicated identity. Register Cloudflare's displayed redirect URI. The current
   manual-client dashboard default is exactly:
   `https://oauth-callbacks.cloudflareaccess.com/cdn-cgi/access/outbound-oauth-callback`.
   This was also displayed in the isolated source's unsaved manual setup form;
   it is **not a verified runtime redirect**. Existing manual registrations retain their stored redirect;
   confirm the displayed and runtime values match before authorizing.
3. In Cloudflare **Zero Trust → Access controls → AI controls → MCP servers**,
   configure the BigQuery endpoint with **OAuth → Manual credentials**. Enter
   the client ID and secret directly in Cloudflare, never in chat, Ankka's
   installer, repository files, or command history. Use scope
   `https://www.googleapis.com/auth/bigquery` and token auth
   `client_secret_post`. Google endpoints are
   `https://accounts.google.com/o/oauth2/v2/auth` and
   `https://oauth2.googleapis.com/token`.
4. Complete the supported **admin** connection using the restricted Google
   identity. Keep **Require user auth off** and the existing Code Mode policy.
   Verify Cloudflare requests `access_type=offline` and can retain a refresh
   token; do not assume the manual endpoint fields add this automatically.
   Google's [web-server OAuth guide](https://developers.google.com/identity/protocols/oauth2/web-server#offline)
   explains offline access. Re-consent may be necessary. With the BigQuery scope,
   external consent apps in Testing receive refresh tokens that expire after
   seven days; review the [refresh-token expiration rules](https://developers.google.com/identity/protocols/oauth2#expiration).
5. Complete the acceptance checks below before removing the application block.

## Acceptance evidence and remaining gates

| Check | Result on 2026-08-30 |
| --- | --- |
| Public BigQuery `tools/list` | Passed live; six exact tools, no credentials |
| Edited Worker against live public Google discovery | Passed locally with synthetic management authentication; OAuth classification and setup block returned |
| Unauthenticated read-only metadata call | HTTP 401 with Bearer resource metadata; synthetic identifiers only |
| Gateway Code Mode discovery and BLS health | Passed through the actual Portal connector; BigQuery absent |
| Cloudflare isolated source setup | Created successfully; detached from Portal, all six tool overrides disabled, authentication required |
| Cloudflare manual endpoint discovery | Passed in unsaved dashboard form; no Google client or credential supplied |
| Cloudflare existing source state | BLS remains connected and shared; Portal still contains only BLS; Code Mode remains `default_on` |
| Local auth classification and setup block | Implemented with regression coverage |
| Google client and operator consent | Not provisioned; human action required |
| Google auth through Gateway | Blocked by the shared manual-auth topology |
| Google token refresh | Unverified gate; no Google credential obtained |
| Approved BigQuery tools in Gateway discovery | Blocked; not claimed from public discovery |
| Bounded real GA4 read | Not run |
| Compound BLS + GA4 sandbox join | Not run; no substitute connector used |
| Runtime code deployment | None; isolated Cloudflare configuration only |

Local validation passed: `npm run check:fast` and the full `npm run check`,
including the exact toolchain check, lint, types, builds, core and application
tests, public-boundary and public-history checks. The synthetic MCP listener
required local loopback permission. The Worker payload checksum was updated
for the reviewed source change. No generated release artifacts were published.

When unblocked, first confirm Gateway Code Mode exposes only the three approved
BigQuery tools in addition to unchanged BLS tools. Run the small GA4 read above.
For the compound test, obtain at most 20 aggregated GA4 `items.item_id` values
inside the sandbox, establish whether these correspond to a BLS external ID or
SKU (do not assume), and call the matching read tool with at most four
concurrent lookups. Join in sandbox memory. Return only sampled item count,
matched/unmatched counts, match percentage with its denominator, and aggregate
event quantities for matched/unmatched groups. Do not return item identifiers,
SQL or raw rows. A zero-match result needs an identifier-mapping investigation,
not a claimed successful join.

Repeat a bounded read after Google's original access token expires, without
another Google consent screen, and record only timing and pass/fail evidence.
Separately verify another already-authorized Gateway member can use the source
without a Google login. Check authentication failure behavior using a disposable
test credential/environment, not by revoking working BLS credentials or issuing
production writes. These remain release gates, not completed tests.
