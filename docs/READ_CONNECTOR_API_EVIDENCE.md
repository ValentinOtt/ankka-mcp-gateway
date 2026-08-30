# API evidence: Notion, HubSpot, and Zendesk readers

Checked against public provider documentation on 2026-08-30. These are
experimental, self-hosted readers in `apps/read-only-connectors`, not released
Source Catalog presets. They have synthetic protocol/security coverage; no
provider account, provider OAuth flow, or production data was used in this
implementation.

## Shared deployment boundary

Each deployment selects one provider and a strict non-secret resource
configuration. The provider token is a separate Worker secret. You must obtain
that credential directly from the provider with only the read capabilities
below; do not send it through the hosted installer or place it in configuration,
logs, prompts, or a repository.

The readers author fixed request paths and parameters, then independently
validate the complete request plan before the shared executor sends it. They
do not accept a URL, HTTP method, authorization header, arbitrary search/filter
expression, or property-selection override from an MCP tool call. The shared
executor bounds request/response sizes and time, rejects redirects, and owns
the JSON headers. No attachment or pagination URL is followed automatically.

Opaque bearer tokens are **not automatically attested as read-only** by these
readers. They also do not implement OAuth consent or refresh. A provider-scoped
credential, authenticated write-denial test, supported gateway authentication
topology, and recovery/removal lifecycle remain release gates. The fixed
read-only adapter boundary does not justify granting it a broader credential.

## Notion

The implementation pins `Notion-Version: 2025-09-03`, the documented revision
introducing data-source IDs. It does not silently adopt the provider's newest
API revision. Page IDs and data-source IDs are distinct configuration lists;
only canonical lowercase hyphenated IDs are accepted. [Version contract](https://developers.notion.com/guides/get-started/upgrade-guide-2025-09-03)

| MCP tool | Fixed API operation | Bound |
| --- | --- | --- |
| `notion_get_page` | `GET /v1/pages/{page_id}` | Configured page ID; no query/body |
| `notion_list_page_blocks` | `GET /v1/blocks/{page_id}/children` | Configured page ID; 1–50 blocks per request |
| `notion_get_data_source` | `GET /v1/data_sources/{data_source_id}` | Configured data-source ID; no query/body |
| `notion_list_data_source_pages` | `POST /v1/data_sources/{data_source_id}/query` | Configured data source; 1–50 rows; pagination only |

Provider references: [page metadata](https://developers.notion.com/reference/retrieve-a-page),
[block children](https://developers.notion.com/reference/get-block-children),
[data-source metadata](https://developers.notion.com/reference/retrieve-a-data-source),
[data-source query](https://developers.notion.com/reference/query-a-data-source).
The POST query is an explicitly reviewed read, not permission to forward other
POST requests. Neither arbitrary filters/sorts nor workspace-wide search are
exposed.

Create a dedicated Notion connection or personal access token with only
**Read content**, and share only the intended content with it. Do not enable
Update content, Insert content, comment writes, or additional user access.
Notion documents that capabilities enforce the API endpoints a connection can
call. [Capability enforcement](https://developers.notion.com/reference/capabilities)

Configuration keys are `allowedPageIds` and `allowedDataSourceIds`; at least
one must be non-empty, each has at most 128 unique IDs. Access to a configured
data source intentionally includes its rows. The block reader returns only a
page's immediate children; it does not recursively infer authorization for
arbitrary nested block IDs or newly discovered page IDs. Opaque cursors are
bounded to 256 base64/URL-safe characters, with a default page size of 25.

## HubSpot

The implementation uses the documented CRM v3 contract. The provider currently
places those guides under its `legacy` documentation section; this is a pinned
read contract, not a claim that v3 is its newest API generation.

Only `contacts`, `companies`, and `deals` are supported. Configure
`objectProperties` with one or more of those keys, each mapping to 1–32 unique
property internal names. That both selects the exposed object families and
fixes the returned property selection for the deployment.

| MCP tool | Fixed API operation | Bound |
| --- | --- | --- |
| `hubspot_list_records` | `GET /crm/v3/objects/{type}` | 1–50 active records; numeric pagination cursor |
| `hubspot_get_record` | `GET /crm/v3/objects/{type}/{id}` | Numeric record ID; active records |
| `hubspot_batch_read_records` | `POST /crm/v3/objects/{type}/batch/read` | 1–25 unique numeric record IDs |

Provider references: [contacts](https://developers.hubspot.com/docs/api-reference/legacy/crm/objects/contacts/guide),
[companies](https://developers.hubspot.com/docs/api-reference/legacy/crm/objects/companies/guide),
[deals](https://developers.hubspot.com/docs/api-reference/legacy/crm/objects/deals/guide).
These guides document the read paths, property selection, batch reads, and
required object scopes.

Use a dedicated credential with only the selected families' scopes:
`crm.objects.contacts.read`, `crm.objects.companies.read`, and/or
`crm.objects.deals.read`. Do not add their write variants. Tickets, activities,
custom objects, associations, historical properties, archived-object queries,
and arbitrary CRM search are not implemented. In particular, the reader does
not invent a `crm.objects.tickets.read` scope or assume a legacy ticket grant
is read-only.

The result projector returns record IDs and only the configured properties,
even when an upstream response contains extra properties or associations.
For lists, only the next numeric cursor is retained; upstream pagination URLs
are dropped. This is a data-minimization boundary, not a replacement for
HubSpot account permissions. A configured object family permits reading any
record accessible to the credential in that family; it is not a record-level
allowlist.

## Zendesk

Configuration accepts one validated `subdomain` label, never a URL. The origin
is authored as `https://{subdomain}.zendesk.com`; public documentation/service
labels are rejected. `allowedOrganizationIds` and `allowedTicketIds` are
separate lists of at most 128 unique numeric IDs, with at least one resource
configured overall.

| MCP tool | Fixed API operation | Bound |
| --- | --- | --- |
| `zendesk_get_organization` | `GET /api/v2/organizations/{id}` | Explicit organization ID |
| `zendesk_list_organization_tickets` | `GET /api/v2/organizations/{id}/tickets` | Explicit organization; 1–50 tickets per page |
| `zendesk_get_ticket` | `GET /api/v2/tickets/{id}` | Explicit ticket ID |
| `zendesk_list_ticket_comments` | `GET /api/v2/tickets/{id}/comments` | Explicit ticket ID; 1–50 comments per page |

Provider references: [organizations](https://developer.zendesk.com/api-reference/ticketing/organizations/organizations/),
[tickets and organization ticket lists](https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/),
[ticket comments](https://developer.zendesk.com/api-reference/ticketing/tickets/ticket_comments/).

Register a dedicated Zendesk OAuth client and limit it to the necessary read
scopes, such as `tickets:read` and `organizations:read`; omit write and
impersonation. Zendesk documents `read` as access to GET operations and
resource-specific `resource:scope` grants. Prefer the resource-specific form
over account-wide `read`. Store the resulting token directly as a Worker
secret. [OAuth setup and scopes](https://support.zendesk.com/hc/en-us/articles/4408845965210-Using-OAuth-authentication-with-your-application),
[resource scope reference](https://developer.zendesk.com/api-reference/ticketing/oauth/oauth_tokens/#scopes)

Organization-scoped listing intentionally reveals tickets belonging to that
organization, including fields returned by Zendesk. It does not automatically
add those ticket IDs to the separate ticket-detail/comment allowlist. Pagination
uses only `page[size]` and an optional bounded `page[after]` cursor; side-loading,
inline-image expansion, tenant-wide ticket lists, exports, and free-form search
are unavailable. A supplied API token or administrator identity must not be
mistaken for an upstream read-only OAuth grant.

## Verification scope

`test/providers-business-readers.test.ts` exercises all 11 registered tools
through actual MCP request dispatch and tests exact request-plan acceptance,
method/path/resource escapes, extra query/body fields, pagination limits,
invalid deployment configuration, HubSpot response projection, and sanitized
exceptions. These synthetic tests do not prove live provider scope enforcement
or automatic token renewal. No upstream implementation code or schemas were
copied; source code and descriptions are original, with public contracts linked
above.
