# Native connector setup recipes

> Documentation-only setup contracts, researched 2026-08-30. None is a released
> preset or a live-qualified connection. The production Source Catalog and the
> existing BigQuery connection block are unchanged.

The dashboard's native setup data covers 19 provider/region choices. It records
the exact provider endpoint, documented read tools where available, upstream
controls, scope requirements, provider evidence and remaining setup blockers.
You can prepare the right provider settings without guessing an endpoint or
confusing a working OAuth login with a read-only connection.

These recipes create no source drafts, install no resources, request no
credentials and enable no tools. Provider credentials belong in your
Cloudflare account or a separately reviewed self-hosted source runtime, never
in Ankka's installer, chat, repository files, or copied configuration examples.

## What the status means

| Status | Meaning | Safe next step |
| --- | --- | --- |
| `compatibility_pending` | Provider evidence exists, but authentication, actual read-only grants, exact tools or the Cloudflare canary remains open | Review the listed provider controls and prepare an approved isolated test identity |
| `manual_setup` | A registered provider OAuth client is needed; the required operator-shared manual OAuth path is not supported by this gateway | Resolve that authentication topology before creating a client just for this connection |
| `provider_permission_required` | Provider permission for the proposed gateway use is still needed | Obtain that confirmation before an authenticated canary |

Every status also requires catalog provenance and release review. A provider's
read-only endpoint is strong evidence, not a claim that its connection has been
verified through Cloudflare. A documentary tool list is not `enabledTools`.

## Available recipes

| Recipe ID | Starting point | Provider-side requirement |
| --- | --- | --- |
| `airtable` | Native OAuth with DCR; exact base/schema/record read candidates | Restrict bases and grant only the documented read scopes; verify the actual grant |
| `linear` | Dedicated `/mcp/readonly` URL | Keep that endpoint, confirm the read-only grant and discover exact tools |
| `jira`, `confluence` | Current Atlassian `/v1/mcp/authv2` endpoint | Administrator blocks MCP Write while allowing intended Read/Search; review effects on other MCP clients |
| `sentry` | Provider MCP OAuth | Explicitly select only `inspect`; current defaults can include write skills; verify catalog execution too |
| `github` | Provider `/mcp/readonly` endpoint | Registered app and limited repository permissions; shared manual OAuth remains blocked |
| `salesforce` | Dedicated `platform/sobject-reads` server | Enable the server with an appropriate identity and External Client App; shared manual OAuth remains blocked |
| `google-drive` | `drivemcp.googleapis.com/mcp/v1` | Dedicated read identity and `drive.readonly`; do not substitute write-capable `drive.file` |
| `google-sheets` | `sheetsmcp.googleapis.com/mcp/v1` | Dedicated read identity, `spreadsheets.readonly`, bounded cell ranges |
| `bigquery` | Google-hosted read-only SQL tool | Scoped IAM and write-tool deny policy; query-cost safeguards are optional; existing direct shared OAuth block stays enforced |
| `slack` | Native public-channel read use case | Registered internal or Marketplace app; selected user read scopes; no broad private-conversation sharing |
| `hubspot` | Native CRM/property read candidates | MCP auth app with PKCE and proved read-only installation permissions |
| `notion` | Native search/fetch candidates | A hosted-MCP-specific read-only grant or identity; API integration capabilities are not interchangeable |
| `gitlab` | Native GitLab.com endpoint | Prove a grant or identity that cannot mutate issues, branches, merge requests or pipelines |
| `intercom-eu`, `intercom-us` | Region-specific native endpoints | Conversation/contact-only read authority; prove article writes are unavailable; never switch regions automatically |
| `stripe` | Current GET-only read tool and discovery tools | Actual read-only grant across the connection; no report, analytics, feedback or API writes by default |
| `gorgias` | Provider beta remote endpoint | Prove actual granular read-only scopes before connecting a real support account |
| `ahrefs` | Provider hosted remote endpoint | Obtain provider confirmation for gateway/bridge use before authenticating |

There is no native Zendesk recipe because no first-party remote endpoint was
verified. Search Console and Google Analytics are not assigned invented hosted
endpoints. A separately implemented API reader or deployed adapter has its own
credential and runtime lifecycle; it must not masquerade as a native recipe.
The [reader workspace](../apps/read-only-connectors/README.md) implements
API-backed providers separately from these native guides. The supported
[self-hosted BigQuery bridge](../apps/read-only-connectors/BIGQUERY_MCP_EXPERIMENT.md)
has its own manual deployment, Google IAM, and client qualification. The
dashboard's BigQuery guide links to it; connecting Google's endpoint directly
still has the shared-authentication block described above.

## Copyable setup contracts

The data and pure helpers live in
[`native-recipes.ts`](../apps/admin/src/connectors/native-recipes.ts):

```ts
resolveNativeRecipe('airtable')
// { kind: 'setup_required', recipe: ..., sourceDraft: null }

formatNativeRecipeSetup('airtable')
// Human-readable endpoint, controls, scope caveat, tool candidates,
// blockers, numbered setup steps and provider evidence links.
```

Unknown IDs return `null`; IDs are not normalized into another provider or
region. The resolver has no overrides for endpoint, authentication, scopes or
tools. Passing a readiness flag cannot turn a recipe into an approved source.

The formatter deliberately emits instructions rather than JSON that can be
submitted to source apply. Read-tool candidates are labelled as documentary
candidates and do not expand automatically when a provider adds tools. Empty
candidate lists mean that exact authenticated discovery is still required,
not that all tools should be allowed.

Validation rejects unknown fields, credentials/header recipes, query-bearing or
noncanonical URLs, local/IP destinations, duplicate IDs, wildcard tools,
ambiguous scopes, missing evidence and missing canary/release blockers. Parsed
records and their arrays are immutable. This is a small declarative setup
boundary, not a new authorization policy engine or a runtime provider registry.

## Before promoting any source

1. Confirm the exact provider endpoint and authentication path, including one
   shared operator grant and refresh where required. Do not silently switch to
   per-user upstream authentication.
2. Prove the upstream read-only boundary with an approved canary. A local test,
   `readOnlyHint`, endpoint suffix or scope advertised in metadata does not
   prove the actual grant. Do not attempt a real production mutation to test it.
3. Discover and review the exact live tool list, including the operation
   boundary inside any grouped executor. Approve the smallest useful set.
4. Record the provenance and immutable implementation revision required by the
   [Source Catalog contract](SOURCE_CATALOG.md). Do not fabricate Registry
   references or mark a recipe `ankka_reviewed`.
5. Preserve existing source state, deny-by-default tool mappings, private
   canary receipts and cleanup. A future catalog entry does not migrate an
   installed connection automatically.

The [native feasibility review](NATIVE_CONNECTOR_FEASIBILITY.md),
[demand research](CONNECTOR_DEMAND_RESEARCH.md) and
[BigQuery authentication review](BIGQUERY_GOOGLE_AUTH.md) explain the source
evidence and blockers. Primary citations also travel with every copyable recipe.
No provider source code or schema was vendored for these setup records.
