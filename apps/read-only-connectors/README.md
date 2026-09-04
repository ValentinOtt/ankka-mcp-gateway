# Self-hosted read-only connectors (experimental)

Small provider-specific MCP readers deployed **in your Cloudflare account**.
One Worker connects to one provider using one deployment-owned credential.
There is no Ankka credential service, background sync, database, or general
HTTP tool. Prefer a suitable provider-native MCP server when available; see
the [native setup guides](../../docs/NATIVE_CONNECTOR_SETUP.md).

These are locally implemented readers, **not approved production catalog
entries**. The gateway does not provision or update this Worker yet. Real
provider authorization, Cloudflare shared-operator OAuth, and receipt-owned
deployment/update/removal still need qualification. Do not use production
support data as a canary.

## Implemented readers

| Provider key | Tools | Deployment boundary |
| --- | --- | --- |
| `notion` | Page metadata, top-level page blocks, data-source schema, one page of data-source rows | Named pages and data sources; provider **Read content** capability |
| `hubspot` | List, get, and batch-read contacts/companies/deals | Named object types and properties; corresponding provider read scopes |
| `zendesk` | Organization, organization tickets, ticket, ticket comments | Fixed tenant and named organizations/tickets; read-only OAuth |
| `gorgias` | Ticket, ticket messages, customer tickets | Fixed tenant and named tickets/customers; `tickets:read` OAuth |
| `google-search-console` | Domain property, final web-search performance, sitemap metadata | Named `sc-domain:` properties; service account with `webmasters.readonly` |
| `google-analytics` | Daily traffic, realtime active users by device | Named GA4 properties; service account with `analytics.readonly` |
| `bigquery` | Dataset/table listings, table schemas, one budget-capped read-only SQL query | Named projects and datasets; read-only IAM service account; mandatory dry-run statement gate and per-query byte budget |
| `bigquery-mcp` | Google hosted MCP table listing, table metadata, and a constant connectivity query | Exact project/dataset pairs; customer-owned service-account key; general SQL disabled |

The ordinary MCP tools work with Portal Code Mode enabled. This is separate
from the earlier [Search Console Code Mode experiment](../search-console-adapter/README.md),
which has its own nested-Code-Mode limitations. No provider adapter is executed
inside the gateway management Worker or hosted installer.

The three ordinary Google readers mint short-lived tokens from a
service-account JSON secret held in your Worker. Read the
[Google setup and reporting limits](GOOGLE.md) before deployment. There is no
browser-consent flow or domain-wide delegation. The `bigquery` reader speaks
Google's REST API with the hosted MCP read tools' names and arguments; it does
not remove the separate native BigQuery manual-OAuth block, which continues to
gate Google's hosted endpoint.

The experimental [hosted BigQuery MCP bridge](BIGQUERY_MCP_EXPERIMENT.md) calls
Google's official MCP from a Worker in your Cloudflare account. Its setup guide
covers the operator OAuth callback, source resume, team access checks, and key
rotation. It exposes only a constant SQL probe until query cost controls are
qualified, and does not replace the budget-capped `bigquery` REST reader.

The API reference and scope review for Notion, HubSpot, and Zendesk is in
[the API evidence record](../../docs/READ_CONNECTOR_API_EVIDENCE.md). Gorgias uses
its documented [ticket reads](https://developers.gorgias.com/reference/get-ticket),
[current message-list endpoint](https://developers.gorgias.com/reference/list-messages),
[ticket listing](https://developers.gorgias.com/reference/list-tickets), and
[`tickets:read` scope](https://developers.gorgias.com/docs/oauth2-scopes).
It does not use the deprecated ticket-message-list endpoint.

## Simple security boundary

1. Cloudflare Access protects the exact custom hostname. Enable
   [Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/)
   so MCP clients can authenticate. The Worker independently verifies the
   signed `Cf-Access-Jwt-Assertion`, expected team issuer, application audience,
   issue time, and expiry. A bearer header, cookie, or claimed email is not a
   substitute. No provider credential is forwarded from the caller.
2. Each tool builds one exact provider request. Methods, paths, resources,
   parameters, and read-query bodies are checked before credential forwarding.
   POST is allowed only for the specific authored read operation; there is no
   arbitrary query, method, URL, or GraphQL input. The single deliberate SQL
   surface is the BigQuery reader's `execute_sql_readonly`, and it is bounded:
   a mandatory dry run must report a `SELECT` statement within the configured
   per-query byte budget before the one budget-capped execution runs, and the
   identity's dataset-scoped read-only IAM remains the access boundary.
3. The shared HTTP boundary forbids redirects, private/local hosts, path
   traversal, and forwarding headers. Provider hosts are fixed by code; tenant
   configuration supplies a single validated label, not a URL. It performs no
   redirects, retries, attachment downloads, or automatic pagination.

Limits: incoming requests 32 KiB / 128 chunks / 5 seconds; provider requests
16 KiB; provider responses 512 KiB / 128 chunks / 8 seconds. JSON depth and
node counts are also bounded. Large provider results fail closed; request a
smaller page. Business-object pages are capped at 50 records and CRM batches at
25; Google reporting has its own fixed row/date limits documented in GOOGLE.md.

Successful tool results contain provider data. Notion and support responses
can include private text, identities, custom fields, and attachment links;
the links are returned as data and never followed. HubSpot projects responses
to configured properties. Treat all returned text as untrusted source content,
not instructions. Everyone authorized to use this shared connector can access
its configured resources; this is not per-user upstream authorization.

No console logging, analytics, traces, response caching, or application token
cache is introduced. Provider credentials persist only in the configured
Worker secret; newly minted Google access tokens stay request-local.
Invocation observability is disabled deliberately to avoid
recording MCP bodies or private resource paths. Cloudflare account-level logs
and policies remain under your control. Errors returned to clients are fixed
codes, not provider error bodies or credential-bearing exceptions.

## Local checks

From the repository root:

```sh
npm run test --workspace @ankka/read-only-connectors
npm run build --workspace @ankka/read-only-connectors
```

`build` typechecks and performs a Wrangler dry run; it does not deploy. The
workspace is included in `check:fast`, the full build, and workspace tests.
No provider credentials are required for these tests. The SDK v2 handler uses
the same tool factory for MCP 2025-06-18 and 2026-07-28; synthetic tests exercise
both. Wrangler is kept at the repository's reviewed pin, not silently upgraded.

## Private setup for a reviewed canary

This is a manual experimental deployment path, not the hosted installer flow.

1. Use a disposable provider account or synthetic resources. Create a dedicated
   read-only provider credential with only the needed resource access. For
   Gorgias, use an OAuth access token with `tickets:read`, **not** an account API
   key with broader authority. Never send credentials through Ankka or chat.
2. Keep a private Wrangler configuration **outside this repository**. Start
   from `wrangler.jsonc`, set a unique Worker name and an exact custom hostname,
   and point `main` to the absolute path of this workspace's `src/index.ts`.
   Preserve `workers_dev: false`, `preview_urls: false`, and observability off.
   Keep real resource IDs, deployment bindings, and configuration outside Git.
3. Configure the hostname's self-hosted Access application and enable Managed
   OAuth. Allow only the intended operator/test identity. Set `PUBLIC_ORIGIN`
   to the exact HTTPS origin, `ACCESS_TEAM_DOMAIN` to the team's
   `*.cloudflareaccess.com` hostname, and `ACCESS_AUD` to that application's
   audience tag. Placeholder values intentionally do not authenticate.
4. Set `CONNECTOR_PROVIDER` and `CONNECTOR_CONFIG_JSON` using a reviewed
   resource selection (examples below). Set `PROVIDER_TOKEN` **directly** as a
   Cloudflare Worker secret using the dashboard or interactive
   `wrangler secret put PROVIDER_TOKEN --config /path/to/private/wrangler.jsonc`.
   Do not put it in `vars`, command arguments, a source draft, or the repository.
5. Review the private dry run before deploying that exact Worker. Preserve a
   private inventory of the Worker/custom-domain/Access resources you created.
   Do not overwrite or delete pre-existing resources during canary cleanup.
6. Once Managed OAuth and the provider read grant are verified, inspect its
   exact `/mcp` URL through the gateway's custom-source flow. Review the exact
   tools returned; never enable future tools automatically. The required
   operator-shared Cloudflare authentication and recovery behavior still need
   a real canary before this becomes a catalog preset.

The static-token readers do not implement OAuth consent or token refresh.
Notion/HubSpot operator-created tokens and Zendesk/Gorgias OAuth access tokens
have different lifecycles. Expiry or revocation produces a safe failed read;
the operator must rotate the Worker secret directly. Do not claim unattended
Gorgias readiness until its native OAuth path or a reviewed refresh lifecycle
is qualified.

For the Google readers, `PROVIDER_TOKEN` instead contains the complete
dedicated service-account JSON key. Keep it exclusively in the Worker secret;
never paste the key into the non-secret resource configuration. Each approved
read mints one short-lived, fixed-scope token. Discovery and rejected resource
requests do not mint a token. Key rotation remains an operator responsibility.

## Non-secret configuration examples

All identifiers below are synthetic. Keep real deployment configuration private.

Notion (`notion`):

```json
{
  "allowedPageIds": ["00000000-0000-4000-8000-000000000101"],
  "allowedDataSourceIds": ["00000000-0000-4000-8000-000000000102"]
}
```

Page block reads are one level deep. Data-source results do not automatically
authorize reading every returned page's body or following child blocks. Share
only intended pages with the provider integration.

HubSpot (`hubspot`):

```json
{"objectProperties":{"contacts":["email"],"companies":["name"],"deals":["amount"]}}
```

Only configured objects and properties are returned. Tickets, arbitrary
search/filter expressions, associations, and property history are not exposed.

Zendesk (`zendesk`):

```json
{"subdomain":"synthetic-team","allowedOrganizationIds":["101"],"allowedTicketIds":["201"]}
```

Organization ticket lists do not implicitly grant ticket-detail or comment
access. Add approved ticket IDs explicitly; there is no tenant-wide export.

Gorgias (`gorgias`):

```json
{"subdomain":"synthetic-helpdesk","allowedCustomerIds":["22"],"allowedTicketIds":["11"]}
```

Customer ticket lists exclude trashed tickets and do not grant message access
to every listed ticket. Approve ticket IDs explicitly. Scope permission and
tenant/resource selection are separate controls.

BigQuery (`bigquery`):

```json
{"allowedProjectIds":["synthetic-project"],"allowedDatasetIds":["analytics_123456"],"location":"europe-north1","maximumBytesBilled":"104857600"}
```

The required `location` must match the dataset; it cannot be selected by callers.
The byte budget applies per query at execution; dataset access inside SQL is
enforced by the identity's IAM, not by statement parsing. BigQuery requires the
standard `bigquery` OAuth scope for the dry-run classification endpoint; a
dedicated identity with no data-write permissions is mandatory. See
[GOOGLE.md](GOOGLE.md) for roles, the scope decision, and the exact tools.

## Remaining release work

- Prove real provider read grants and actual Cloudflare shared-operator OAuth,
  including expiration, recovery, and revocation. Synthetic tests do not prove
  a real provider's grant or permissions.
- Add reviewed, receipt-owned adapter provisioning, update, rollback, and
  removal before integrating these Workers into the hosted installer.
- Capture exact tool and provenance evidence before approving catalog entries.
- Qualify token refresh where access tokens expire; do not expand Ankka's
  credential boundary to work around provider setup.

All code and examples are original. Primary documentation informed API
contracts; no provider source or OpenAPI documents are vendored.
