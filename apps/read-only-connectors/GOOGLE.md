# Google read-only providers

These are self-hosted ordinary MCP tools, not generated Code Mode tools and
not Google's hosted MCP service. Each deployment selects one provider and one
deployment-owned service-account credential. Implementation and synthetic tests are
available; a real-account setup and acceptance read are still required before
claiming a working connection.

## Setup in your accounts

Enable the Search Console API, Google Analytics Data API, or BigQuery API in
the service account's Google Cloud project. Use a dedicated service account with
access only to the properties or datasets this deployment should read. Google's
[service-account flow](https://developers.google.com/identity/protocols/oauth2/service-account)
describes key creation and signing; the
[GA4 service-account quickstart](https://developers.google.com/analytics/devguides/reporting/data/v1/quickstart?account_type=service#before_you_begin)
also requires granting the account access in Analytics.

For Search Console, add the service-account email under the intended domain
property's **Settings → Users and permissions**, starting with Restricted access.
Google documents Restricted access to Performance and reports; verify all
selected tools against the actual property before acceptance. Do not grant
ownership or domain-wide delegation just to make this connector work. See
[Search Console permissions](https://support.google.com/webmasters/answer/7687615).

For GA4, add the service-account email as a **Viewer** at the intended property's
**Property access management** level, not the account level. Account permissions
inherit into its properties; Cloud-project IAM access alone does not grant
Analytics-property access. See
[adding Analytics users](https://support.google.com/analytics/answer/9305788) and
[Analytics roles](https://support.google.com/analytics/answer/9305587).

For BigQuery, grant the service account `roles/bigquery.dataViewer` **on the
intended export dataset only** and `roles/bigquery.jobUser` on the query
project, nothing broader. This IAM boundary — not the connector — is what makes
the identity unable to write; audit effective access including group and
project inheritance. Do not grant dataset write roles, connection use, or
unrelated datasets. See
[BigQuery access control](https://docs.cloud.google.com/bigquery/docs/access-control)
and [dataset-level grants](https://docs.cloud.google.com/bigquery/docs/control-access-to-resources-iam).

Store the downloaded standard service-account JSON as your Worker's
`PROVIDER_TOKEN` secret directly in your Cloudflare account. Never put it
in `CONNECTOR_CONFIG_JSON`, source control, an installer request, a test fixture,
logs, or deployment output. This version accepts standard operator-managed
`*.iam.gserviceaccount.com` accounts with PKCS#8 RSA keys (2048–4096 bits), a
matching project, and Google's fixed token endpoint. User refresh-token JSON,
external-account/WIF credentials, delegated subjects, and alternate universes or
auth hosts are unsupported. Key rotation remains an operator responsibility.

The existing Cloudflare Access ingress remains mandatory. Access authenticates
the MCP caller; it does not replace Google's property permissions or the
provider's explicit read allowlist.

## Authorization boundary

| Deployment provider | Only requested OAuth scope |
| --- | --- |
| `google-search-console` | `https://www.googleapis.com/auth/webmasters.readonly` |
| `google-analytics` | `https://www.googleapis.com/auth/analytics.readonly` |
| `bigquery` | `https://www.googleapis.com/auth/bigquery` |

BigQuery's dry-run classification uses `jobs.insert`, which does **not** list
`cloud-platform.read-only` among its accepted scopes. The reader therefore
requests the standard `bigquery` scope, not `cloud-platform` or a combined scope.
That scope is not read-only: the dedicated identity's dataset-scoped IAM above
prevents data writes. The exact request allowlist additionally admits
`jobs.insert` only with `configuration.dryRun: true` and a query configuration;
load, copy, extract, and executing-job bodies are refused. See
[accepted scopes](https://docs.cloud.google.com/bigquery/docs/reference/rest/v2/jobs/insert).
Do not deploy with an existing owner/editor credential. Changing the scope
requires an explicit review of the deployment identity and its effective grants.

After the exact read plan passes its provider allowlist, the Worker signs an
RS256 assertion with the service-account email as `iss`, a five-minute lifetime,
the fixed scope above, and `https://oauth2.googleapis.com/token` as `aud`. It
never adds `sub`. One form-encoded POST contains only the JWT-bearer grant type
and signed assertion. The key itself is not transmitted. This follows Google's
[JWT and token-exchange contract](https://developers.google.com/identity/protocols/oauth2/service-account#httprest).

The authorization operation includes key import/signing, fetch, and streamed
response reading in one eight-second deadline. Secret input is capped at 16 KiB,
the outgoing form at 8 KiB, and token JSON at 16 KiB/32 chunks. Redirects,
non-JSON responses, wrong token types, unexpected returned scopes, and lifetimes
outside 1–3600 seconds fail closed. Tokens and imported keys are not cached.
Each approved REST request mints its own short-lived token. BigQuery query
execution performs two separately authorized requests: dry run, then execution.
Tool discovery and denied read plans mint no token. Errors expose
only fixed codes; neither provider errors nor credentials are logged.

## Search Console

Set `CONNECTOR_PROVIDER` to `google-search-console`. A synthetic configuration:

```json
{"allowedSites":["sc-domain:example.com"]}
```

Configure 1–25 unique, lowercase ASCII domain properties, including canonical
punycode where needed. URL-prefix properties such as `https://example.com/` are
deliberately unsupported here: their REST paths require encoded slashes, which
the shared outbound boundary rejects. The separate Search Console Code Mode
adapter has a different reviewed property-path boundary.

All three operations use the fixed origin `https://www.googleapis.com`:

| MCP tool | Exact approved REST operation |
| --- | --- |
| `gsc_get_site` | `GET /webmasters/v3/sites/{encodedDomainProperty}` |
| `gsc_search_performance` | `POST /webmasters/v3/sites/{encodedDomainProperty}/searchAnalytics/query` |
| `gsc_list_sitemaps` | `GET /webmasters/v3/sites/{encodedDomainProperty}/sitemaps` |

GET requests have no query parameters or body. Performance accepts an inclusive
date range of at most 93 days, one report dimension (`date`, `page`, `query`,
`country`, or `device`), and `rowLimit` from 1–250 (default 100). The authored body
always includes `type: "web"`, `dataState: "final"`, and `startRow: 0`; filters,
multiple dimensions, other search types, and pagination are not exposed. Dates
use Search Console's Pacific calendar. Google returns top rows, not a guaranteed
complete export, so results explicitly remain nonexhaustive and indicate when
the requested row cap was reached. See
[Search Analytics query](https://developers.google.com/webmaster-tools/v1/searchanalytics/query)
and [site retrieval](https://developers.google.com/webmaster-tools/v1/sites/get).

Successful responses are projected to the documented fields. Missing analytics
rows/keys become empty arrays. Site permissions normalize the four known
camelCase/UPPER_SNAKE_CASE aliases; unspecified values are rejected. The actual
JSON metadata names are
`firstIncompleteDate` and `firstIncompleteHour`, as shown in Google's
[published discovery schema](https://raw.githubusercontent.com/googleapis/google-api-go-client/main/searchconsole/v1/searchconsole-api.json).

Sitemap input JSON uses the singular `sitemap` array. Counts remain decimal
strings, preserving int64 precision; deprecated `contents[].indexed` is omitted.
Up to 1000 sitemap entries fit the structural limit, subject to the shared
512 KiB response limit. The connector does not retrieve sitemap contents,
attachment URLs, or any returned links. See
[sitemap listing](https://developers.google.com/webmaster-tools/v1/sitemaps/list)
and [sitemap fields](https://developers.google.com/webmaster-tools/v1/sitemaps).

## Google Analytics 4

Set `CONNECTOR_PROVIDER` to `google-analytics`. A synthetic configuration:

```json
{"allowedPropertyIds":["123456789"]}
```

Configure 1–25 unique numeric property IDs, not measurement IDs (`G-...`), URLs,
or account IDs. Both tools use `https://analyticsdata.googleapis.com`:

| MCP tool | Fixed report |
| --- | --- |
| `google_analytics_daily_traffic` | `POST /v1beta/properties/{id}:runReport`; dimension `date`; metrics `sessions`, `activeUsers`, `screenPageViews`; one inclusive date range of at most 93 days; limit 1–250, default 250. |
| `google_analytics_realtime_by_device` | `POST /v1beta/properties/{id}:runRealtimeReport`; dimension `deviceCategory`; metric `activeUsers`; minute range 29–0; limit 1–50, default 50. |

The wire `limit` is a decimal string, as required by Google's int64 JSON mapping.
Daily dates use the property's timezone. Realtime covers the last 30 minutes,
not the daily date range. These are fixed report templates: no caller-provided
dimensions, metrics, filters, expressions, ordering, pagination, batch reports,
SQL, Admin API operations, audiences, or configuration writes. See
[runReport](https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runReport),
[runRealtimeReport](https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runRealtimeReport),
and the distinct [realtime schema](https://developers.google.com/analytics/devguides/reporting/data/v1/realtime-api-schema).

Responses preserve exact expected dimension/metric headers, string metric
values, rows, and total `rowCount`. Daily responses also retain timezone,
thresholding, sampling, and data-loss metadata when provided. Unknown fields are
discarded; contradictory row counts or responses exceeding the requested limit
are rejected. Capped rows and Google's privacy/processing restrictions must not
be presented as a complete export. These calls consume your Google
API quotas; there are no retries or automatic page follow-ups. See
[report response fields](https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/RunReportResponse)
and [Data API quotas](https://developers.google.com/analytics/devguides/reporting/data/v1/quotas).

## BigQuery (GA4 export)

Set `CONNECTOR_PROVIDER` to `bigquery`. A synthetic configuration:

```json
{"allowedProjectIds":["synthetic-project"],"allowedDatasetIds":["analytics_123456"],"location":"europe-north1","maximumBytesBilled":"104857600"}
```

Configure 1–4 unique project IDs, 1–16 unique dataset IDs (a GA4 export
dataset is `analytics_<propertyId>`), a required query `location` matching the
dataset, and a per-query byte budget from 1 to 1 TiB as a decimal string.
Use the exact metadata location (for example `europe-north1`, `EU`, or `US`),
not an inferred default. The location is deployment-owned in both requests;
tool callers cannot override it. Existing experimental configurations without
`location` now fail closed and must be updated explicitly. The tool names and camelCase arguments mirror
Google's hosted BigQuery MCP read tools, so the same clients work against a
future native connection; the write-capable `execute_sql` tool is deliberately
never implemented. All five tools use `https://bigquery.googleapis.com`:

| MCP tool | Exact approved REST operation |
| --- | --- |
| `list_dataset_ids` | `GET /bigquery/v2/projects/{projectId}/datasets` with `maxResults` 1–50 and optional `pageToken`; listings are filtered to the configured dataset allowlist |
| `get_dataset_info` | `GET /bigquery/v2/projects/{projectId}/datasets/{datasetId}` |
| `list_table_ids` | `GET /bigquery/v2/projects/{projectId}/datasets/{datasetId}/tables` with `maxResults` 1–50 and optional `pageToken` |
| `get_table_info` | `GET /bigquery/v2/projects/{projectId}/datasets/{datasetId}/tables/{tableId}` |
| `execute_sql_readonly` | `POST /bigquery/v2/projects/{projectId}/jobs` with `configuration.dryRun: true`, then `POST /bigquery/v2/projects/{projectId}/queries` for bounded execution |

`execute_sql_readonly` accepts GoogleSQL text of at most 8 KiB **UTF-8 bytes** with
optional lowercase labels. Every call dry-runs first; execution proceeds only
when the returned Job reports `statistics.query.statementType: SELECT` and
`statistics.query.totalBytesProcessed` within the configured budget. Missing
classification, reported errors, DML, DDL, `SCRIPT`, and oversized scans are
refused before execution. `jobs.query` does not expose this classification and
is not used for preflight. The Worker generates a bounded job ID internally
and pins its project and location; no job-control arguments are caller-supplied.
The dry-run request does not execute the query or incur query charges. Setting
`dryRun: true` returns only the statement type, byte
estimate, and result schema. Execution always sends `maximumBytesBilled` (the
per-query billing bound the hosted MCP tools lack), a fixed 6.5-second `timeoutMs`, a
200-row `maxResults`, `jobCreationMode: JOB_CREATION_OPTIONAL`, and
`useLegacySql: false`. `timeoutMs` limits how long Google waits for results; it
does **not** cancel execution. An incomplete response or the separate bounded
HTTP deadline fails closed, but the query may continue within its byte budget.
There is no automatic retry or cancellation. Responses reporting provider
errors or DML statistics also fail closed; there is no result
pagination, and `rowsTruncated` marks incomplete result sets. Dataset scoping
inside SQL comes from the identity's IAM, not from parsing the statement.
Google-classified `SELECT` is not a universal side-effect check: remote functions
can invoke external services if the identity has connection access. Keep the
dedicated identity free of connection permissions and unrelated routine access;
do not substitute SQL parsing for IAM. A dry
run is an estimate; `maximumBytesBilled` is the enforcement at execution. See
[dry runs](https://docs.cloud.google.com/bigquery/docs/running-queries#dry-run),
[Job query statistics](https://docs.cloud.google.com/bigquery/docs/reference/rest/v2/Job#JobStatistics2),
[remote-function permissions](https://docs.cloud.google.com/bigquery/docs/remote-functions#use_a_remote_function_in_a_query),
[jobs.query](https://docs.cloud.google.com/bigquery/docs/reference/rest/v2/jobs/query),
[tables.get](https://docs.cloud.google.com/bigquery/docs/reference/rest/v2/tables/get),
and [datasets.list](https://docs.cloud.google.com/bigquery/docs/reference/rest/v2/datasets/list).

Result cells preserve BigQuery's string-encoded scalars and bounded nested
record/repeated wrappers; table schemas are projected to name, type, mode,
description, and nested fields within a fixed depth. Daily GA4 export tables
appear through `list_table_ids` as dated ids such as `events_20260830`;
partition decorators and wildcard table arguments are rejected. Queries consume
your BigQuery on-demand quota and billing; consider Google's custom query
quotas on the query project as an additional daily bound.

The dataset name is tied to the linked GA4 property, not to the export date.
Daily `events_YYYYMMDD` tables and temporary `events_intraday_YYYYMMDD` tables
change underneath it. Intraday is incomplete; daily exports accept late events
for several days and can be reprocessed later. Read metadata again after any
project/property migration rather than assuming identifiers or location are
permanent. See the [GA4 export schema](https://support.google.com/analytics/answer/7029846?hl=en)
and [export schedule](https://support.google.com/analytics/answer/9358801?hl=en#schedule).

For the first real-account canary, verify dataset/table metadata through this
Worker, then request a dry run of a narrowly date-filtered aggregate. Execute
only if the estimate fits the configured budget; a SQL `LIMIT` does not limit
bytes scanned. Confirm the exact five-tool list and denied unconfigured
resources before connecting the Access-protected source to your Portal with
shared operator OAuth (`on_behalf: false`). Source onboarding must use the
Gateway's reviewed default-deny flow, not a direct policy/receipt bypass.
Only then test a compact BLS + BigQuery Code Mode join, reporting join coverage
and keeping event-level rows out of the model response. Synthetic tests and
metadata reads through a different BigQuery client do not qualify this path.

## Validation and remaining acceptance

Synthetic tests cover signed assertions, fixed scopes/destinations, property
and request-shape rejection, bounded/stalled streams, token isolation, and
response projection. No Google credentials or live account API reads were used
to create these providers. Deployment-specific API enablement, property grants,
actual report availability, quota behavior, and an approved canary read
remain acceptance steps. All implementation is original; no Google client-library
source or sample code is vendored.
