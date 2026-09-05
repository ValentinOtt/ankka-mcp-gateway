# Google-hosted BigQuery MCP bridge

The bridge is supported as a manually deployed, self-hosted source with the
limits documented here. You manage its Worker, Access application, and Google
identity in your own accounts, then connect it through the gateway's custom
source flow. Automatic bridge provisioning and updates are not provided by the
hosted installer or Source Catalog. The original constant-query experiment
shipped in the `gateway-v0.1.46` canary; useful queries require this implementation
and explicit enablement. This document's published path is retained.
Run the existing connector Worker with `CONNECTOR_PROVIDER=bigquery-mcp` to
send approved read tool calls to Google's fixed `https://bigquery.googleapis.com/mcp`
endpoint. Google implements the BigQuery tools; this adapter only authenticates,
restricts requests, and unwraps bounded text tool results.

## Qualification status

The bridge passed `npm run check:fast`, including 65 bridge checks across
both supported client protocol versions. The repository's full CI release gate
is required before merge.

Useful-query qualification on 2026-09-05 passed with a dedicated read-only
Google identity and the deployed bridge:

- a dry run and one completed, five-row aggregate over an allowed table;
- an actual read of a verified existing excluded table rejected by Google IAM;
- no effective table-write permissions and Google's read-only tool rejecting
  harmless temporary DDL;
- exactly three tools retained after the deployed source was synchronized;
- the same aggregate through Claude Desktop beyond the initial 15-minute token
  lifetime, then a fresh execution after explicit disconnect and reconnect; and
- unauthenticated bridge requests still rejected with HTTP 401.

The dedicated identity's unnecessary query-project-wide Data Viewer grant was
removed; the intended dataset grant and query job permission remained. The
negative read was checked against an existing table and its actual permission
error, not inferred from a generic tool failure. The live probe below repeats
the runtime checks, while private client and deployment receipts record the
end-to-end evidence. This qualifies the documented small-result workflow;
other clients, long-running jobs, and automatic Worker lifecycle management
are not claimed by this evidence.

Live qualification passed on a separate Worker in the test Cloudflare account:

- Cloudflare Managed OAuth login with the existing test operator;
- exactly the three reviewed tools exposed;
- Google service-account authentication;
- the constant SQL query returned `1`;
- listing a page of tables and reading one table's metadata;
- unauthenticated requests rejected with HTTP 401; and
- public OAuth discovery served by the expected Cloudflare Access issuer.

Canary qualification also passed source installation through Ankka: the
action paused for operator authentication, then fresh consent resumed the
retained resources and attached the exact tool allowlist to the Portal. A
second identity signed in to the Portal using an email code and used the
shared operator connection without a Google login. Direct calls listed tables,
read metadata, and returned `1` from the constant query. Code Mode exposed
exactly the same three tools and also returned `1` from that query.

Removing the second identity from the source policy blocked a fresh client
authorization before an OAuth code or token was issued. Its existing Portal
grant still executed direct and Code Mode calls more than five minutes later,
including after successful token refreshes. This observation alone does not
establish a provider defect: Access policy edits and session revocation are
separate operations. A subsequent test explicitly revoked all sessions for the
Portal application: the existing token received HTTP 401 for direct and Code
Mode discovery and calls at the first check after 15 seconds, and its refresh
token was rejected with `invalid_grant` after 90 seconds. The source assignment
was restored and verified. This qualifies the tested Portal-wide procedure,
which also disconnects other team members. See
[Team access](../../docs/TEAM_ACCESS.md#revocation-qualification).
Deployment receipts and private test details remain outside this repository.

The live `tools/list` response confirmed the reviewed tool names and argument
names. A fresh public discovery probe on 2026-09-04 again found only
`projectId`, `query`, `dryRun`, and `labels` among the reviewed SQL fields.
Unlike the current documentation, its SQL input does not yet include
`timeoutMs` or `jobTimeoutMs`; sending those fields produced an invalid-argument
tool error. The bridge sends only the required project and query, plus optional
`dryRun`. Discovery also lacks `maximumBytesBilled`, `maxResults`, and `location`.
The bridge can now enable useful SQL explicitly with `allowQueries: true`.
A per-query byte ceiling is not a support requirement; query spending remains
under your Google account. See [query costs](#cost-limitation).

The Worker belongs in your Cloudflare account. Cloudflare Access with Managed
OAuth protects its exact hostname; the Worker verifies the signed Access JWT.
The dedicated service-account key stays in the Worker secret `PROVIDER_TOKEN`.
Ankka operates no intermediary service and receives no credentials or traffic.
Everyone admitted to this shared connector uses the same Google identity.

Synthetic configuration:

```json
{
  "queryProjectId": "synthetic-query-project",
  "allowQueries": false,
  "allowedDatasets": [
    { "projectId": "synthetic-data-project", "datasetId": "sample_dataset" }
  ]
}
```

The exact tools exposed are `list_table_ids`, `get_table_info`, and
`execute_sql_readonly`. The first two only accept configured project/dataset
pairs. The SQL tool accepts exactly `SELECT 1 AS bridge_ok` by default, preserving
existing installations. Set `allowQueries: true` after preparing the dedicated
identity's read-only IAM to enable GoogleSQL in the configured query project.
Queries are limited to 8 KiB UTF-8; `dryRun: true` requests an estimate without
execution. No write-capable tool, extra method, URL, incoming authorization
header, redirect, automatic pagination, or retry is forwarded.

Google's `execute_sql_readonly` enforces read-only statements. The
`allowedDatasets` list bounds metadata calls; it does not parse or restrict
SQL references. The service account's effective Google IAM must restrict SQL
to the intended datasets, with no write privileges, external connection use,
or unrelated routine access. A `SELECT` can invoke a remote function when its
identity has permission, so a tool name or SQL prefix is not that boundary.
See the [identity requirements](../../docs/BIGQUERY_GOOGLE_AUTH.md#read-only-identity-and-exact-tools).

The bridge returns only completed query results without provider errors.
Incomplete jobs fail with a fixed diagnostic; it does not poll or cancel them.
The bounded HTTP deadline limits waiting, not Google's execution or billing.
Inspect Google job history before retrying a failed query.

## Deploy in your Cloudflare account

Use a dedicated Google service account with the prerequisites below. Keep its
key in a private local file until it is uploaded directly to your Worker secret.
The service account belongs to your Google project; Ankka receives neither the
key nor the resulting access tokens. Do not use an exposed or shared test key.

1. Choose a bridge hostname in your Cloudflare zone. Create a self-hosted Access
   application for that exact hostname, enable Managed OAuth and dynamic client
   registration, and allow only the gateway operator to authenticate. Team
   members will use the Portal's shared connection, not direct bridge access.
2. Copy this workspace's `wrangler.jsonc` to a private directory outside Git.
   Set a unique Worker name, point `main` to the absolute path of
   `apps/read-only-connectors/src/index.ts`, and add an exact custom-domain route:
   `"routes": [{ "pattern": "bridge.example.com", "custom_domain": true }]`.
   Keep `workers_dev`, `preview_urls`, and observability disabled.
3. Set `CONNECTOR_PROVIDER` to `bigquery-mcp`. Set `CONNECTOR_CONFIG_JSON` to
   the serialized configuration above using your query project and exact
   project/dataset pairs. Set `PUBLIC_ORIGIN` to your bridge's HTTPS origin,
   `ACCESS_TEAM_DOMAIN` to your team's `*.cloudflareaccess.com` domain, and
   `ACCESS_AUD` to the Access application's audience tag. All real values stay
   in that private configuration.
4. From this workspace, run the pinned Wrangler dry run, then deploy that exact
   configuration in your Cloudflare account:

   ```sh
   npx wrangler deploy --dry-run --config /absolute/private/bridge/wrangler.jsonc
   npx wrangler deploy --config /absolute/private/bridge/wrangler.jsonc
   npx wrangler secret put PROVIDER_TOKEN --config /absolute/private/bridge/wrangler.jsonc
   ```

   Enter the service-account JSON through the secret prompt. Never place it in
   `vars`, command arguments, the source draft, or chat. Authenticated requests
   fail until the secret is configured. This manual deployment is independent
   of gateway installation and updates; keep your own resource inventory.
5. In the gateway's Sources page, add `https://bridge.example.com/mcp`, select
   the three exact tool names above, save the draft, and authorize installation.
   The source starts with nobody assigned. When the gateway shows **Connect
   your source**, open its recorded Cloudflare server.
6. Allow the exact operator OAuth callback for that server in the bridge's
   Access application under `oauth_configuration.dynamic_client_registration.allowed_uris`.
   Preserve existing settings and redirect entries. The callback uses the
   installed account and recorded server ID:
   `https://dash.cloudflare.com/<account-id>/one/access-controls/ai-controls/mcp-server/oauth-callback/<server-id>`.
   Do not allow arbitrary redirect hosts or a dashboard-wide wildcard.
7. Authenticate the server as the gateway operator. Keep **Require user auth**
   off. Wait for **Ready** and the three synced tools, then return to Sources
   and choose **Renew consent and resume**. The gateway verifies the retained
   resources and selected tools before attaching the source to the Portal.
8. In Cloudflare Access, assign intended people to the source's recorded policy
   and ensure they can enter the Portal. Keep the bridge application limited
   to its operator. Verify a client can call the constant query through the
   Portal without a Google login, then verify fresh-authorization denial after
   removing its source assignment. To invalidate existing clients, follow the
   [qualified Portal session-revocation procedure](../../docs/TEAM_ACCESS.md#qualified-procedure-for-existing-portal-sessions)
   and account for its effect on every team member connected to that Portal.
   A successful direct bridge login does not satisfy this Portal check.

## Rotate the Google key

Create a replacement key for the same dedicated service account. Update
`PROVIDER_TOKEN` in every Worker using the old key, verify a real authenticated
read, then disable the old Google key and remove it after confirming the
replacement works. Keep rotation receipts and key material outside this
repository. Gateway updates do not rotate or manage this separate Worker secret.

The existing request boundary limits provider JSON responses to 512 KiB and
eight seconds. Requests advertise both MCP media types; this first version
accepts only bounded JSON responses. SSE responses fail closed and need a
transport follow-up if observed live. Discovery and
initialization are supplied by our existing stateless MCP SDK. Google documents
direct `tools/call` requests; no upstream session is retained. Only the three
reviewed input schemas are authored here; new upstream tools are never enabled
automatically. Successful tool text is untrusted provider content.

## Google prerequisites and live qualification

Google documents the BigQuery OAuth scope for MCP. The shared identity needs
`roles/mcp.toolUser` and `roles/bigquery.jobUser` on the query project, and
`roles/bigquery.dataViewer` scoped to the intended dataset. Metadata calls may
also need MCP permission on the dataset's project. Verify the narrow grants
against Google's actual responses; never give the test identity Owner or Editor.
Enable the BigQuery API and ensure organization policies permit this MCP service.

1. Run local tests and the connector build with synthetic keys.
2. Run the opt-in live probe with a private service-account JSON file and
   private resource configuration, outside this repository. It prints only
   fixed outcomes, never Google tokens, provider bodies, SQL results, or IDs.
3. On a separate Access-protected test Worker, confirm that an unauthenticated
   call cannot reach Google and that a gateway operator can connect using
   Managed OAuth. Do not replace the existing reader or gateway deployment.
4. List one page of tables, read one table's schema, and run the constant query
   through the gateway. Only then claim end-to-end compatibility.
5. Verify key rotation directly in your Google and Cloudflare accounts.

The live probe simulates Access locally and calls Google for real; passing it
does not prove Cloudflare deployment, Managed OAuth, or portal authentication.
Private input config uses the JSON above and optionally `probeTableId` for the
metadata probe. Set `ANKKA_BIGQUERY_BRIDGE_LIVE=1`,
`ANKKA_BIGQUERY_BRIDGE_KEY_FILE` and `ANKKA_BIGQUERY_BRIDGE_CONFIG_FILE` in the
local environment, then run `npx vitest run --config vitest.live.config.ts`
from this workspace.

## Cost limitation

Google's hosted SQL MCP input currently has no `maximumBytesBilled` setting.
That is a documented cost-control limitation, not a release gate. Queries are
charged to your configured Google query project. Enable useful queries only
with costs appropriate for your workload and your team's access.

For on-demand billing, optional [custom daily quotas](https://docs.cloud.google.com/bigquery/docs/custom-quotas)
provide an additional safeguard. They are approximate and may be exceeded;
they are not a strict spending cap. Review other workloads before changing a
shared project's quotas. A separate query project can make ownership clearer.
A row limit, dry-run estimate, or shorter HTTP timeout is not an execution-time
byte ceiling. The bridge makes no such guarantee and never retries automatically.

If you specifically need a per-query byte ceiling, the separate
`CONNECTOR_PROVIDER=bigquery` REST reader supplies `maximumBytesBilled` at
execution. That remains an explicit alternative deployment, with its own
qualification; the hosted `bigquery-mcp` path never falls back to REST.

A local-runtime test against real Google on 2026-09-04 exercised that REST
alternative with a single-table event-count aggregate. A one-byte budget
rejected the query after dry run with no execution request. With a 100 MiB
ceiling, the estimate passed and one execution returned a nonempty aggregate
of at most five rows; reported billing stayed within the ceiling. Execution
carried the configured `maximumBytesBilled` value. Three dry-run requests and
one execution were observed. Access was simulated locally for this test; it
does not qualify a deployed REST Worker, its Portal integration, or denied
dataset IAM. No private identifiers or query results are retained here.

## Repeat public capability discovery

From `apps/read-only-connectors`, run:

```sh
ANKKA_BIGQUERY_MCP_DISCOVERY_LIVE=1 npx vitest run \
  --config vitest.live.config.ts test-live/bigquery-mcp-capabilities.live.ts \
  --silent=false --reporter=verbose
```

This opt-in probe sends one unauthenticated `tools/list` request to Google's
fixed endpoint. It executes no tools, reads no credential, follows no redirects,
and makes no retry or credential fallback. It uses the connector's existing
response-size and timeout bounds. Incomplete catalogues, duplicate tool names,
missing reviewed tools, or failed discovery produce fixed errors. Output
contains only reviewed field names and booleans; upstream descriptions and
errors are not printed. A field appearing in discovery requires a fresh
enforcement test before any runtime change. Discovery itself does not prove
that a query budget is enforced.

## Claude Desktop qualification

The current Claude Desktop custom-connector flow reached the Portal, signed
in the admitted member by email code, and returned the constant query result
through the Portal's Code Mode tools. The recorded tool response contained
`bridge_ok = 1`, `jobComplete: true`, and zero bytes processed and billed.
Code Mode discovery returned exactly the three reviewed tools; a one-table
listing and a table-schema read also passed in this client. A fresh constant
query succeeded without another sign-in more than 15 minutes after initial
authorization, beyond the configured access-token lifetime. This proves
continued client operation; the client's internal refresh-token exchange was
not inspected. Explicit disconnect and reconnect also passed: Claude showed
the disconnected state, completed consent for the same single source using
the existing Access session, and returned a new successful constant-query
result after the desktop handoff.

On 2026-09-05, the explicitly enabled hosted path passed a dry run and a
five-row event-count aggregate in this same client. The response reported a
completed job and the expected two-column schema. This new execution used an
existing connection more than 15 minutes after authorization. Explicit
disconnect, consent for the same single source, and reconnect then returned
another new completed aggregate. The observed executions reported zero bytes
processed and billed; these results demonstrate query compatibility, not a
fresh scan or a billing ceiling. The client's internal token exchange was not
inspected.

For this tested setup:

1. Add your Portal's `/mcp` URL to Claude. Select **Always required** for
   authentication and **No client ID — register one automatically** for the
   OAuth client. The tested path uses dynamic client registration, not Claude's
   client-metadata default. No additional credential header is needed.
2. On the Portal Access application, allow the exact public callback
   `https://claude.ai/api/mcp/auth_callback`. Preserve existing callback entries,
   admission policies, and token lifetimes. An older test installation lacked
   this entry: Claude failed with `invalid_request` / `provider_redirect` before
   Portal sign-in. Adding only that callback resolved the failure.
3. Choose **Connect** in Claude, complete Portal sign-in, select the intended
   source, and finish the browser handoff to Claude Desktop. The member signs
   into Cloudflare Access; the shared Google identity stays in the bridge.
4. Use the Portal tools in a new conversation. With Code Mode enabled, seeing
   Portal wrapper tools in Claude's settings is expected. Inspect the tools
   returned by Code Mode separately and verify the exact three-tool allowlist.
   Approve the reviewed discovery and query calls individually.

New-Portal callback defaults are already implemented in the gateway source.
The latest checked canary, `gateway-v0.1.48`, predates PR #114's additional
ChatGPT and Cursor defaults. Neither a source-code default nor Claude's passing
query proves those clients or changes an older Portal automatically.

## Enable and qualify useful queries

1. Give the dedicated Google identity read access only to the intended datasets
   and Job User on the query project. Remove inherited or project-wide data
   grants that widen this scope. Keep the exact three-tool Portal allowlist.
2. Set `allowQueries: true` in your private bridge configuration, then dry-run
   and deploy the reviewed Worker. Keep its existing secret and Access boundary.
3. Run a small aggregate over one completed date with `dryRun: true`, review
   the estimate, then execute it. Confirm denial for a known existing excluded
   dataset and confirm the identity cannot write. Use a disposable synthetic
   target or a harmless temporary-DDL rejection probe; never attempt a mutation
   of production data to test permissions.
4. Repeat the aggregate through your real client, including operation beyond
   its initial token lifetime and reconnection. Keep provider data and receipts
   private. The opt-in test below exercises the local runtime against real
   Google; it does not replace deployment and Portal checks.

```sh
ANKKA_BIGQUERY_QUERIES_LIVE=1 \
ANKKA_BIGQUERY_BRIDGE_KEY_FILE=/absolute/private/service-account.json \
ANKKA_BIGQUERY_QUERIES_CONFIG_FILE=/absolute/private/query-probe.json \
npx vitest run --config vitest.live.config.ts \
  test-live/bigquery-mcp-queries.live.ts --silent=false --reporter=verbose
```

Run from this workspace. The private probe file contains `queryProjectId`,
`allowedDatasets`, `probeQuery` (one read-only aggregate returning 1–20 rows),
and `deniedQuery` (a read against a verified existing excluded table). The test
performs one dry run, an excluded-read attempt, a temporary-DDL rejection
check, and one aggregate execution. It prints fixed outcomes, never SQL,
identifiers, results, or tokens.
An excluded-query error alone is not proof of IAM denial: verify the fixture's
existence and the actual permission-denied reason separately.

## Operate the self-hosted bridge

Keep a private inventory of the Worker, route, Access application, Google
identity, and deployed Worker version. The gateway manages the source's Portal
connection; the bridge Worker and its Google secret have their own lifecycle.

For an update, retain the previous Worker version and private configuration,
review the source change, run the pinned toolchain's checks and Wrangler dry
run, then deploy that exact version with the same configuration and secret.
Synchronize the recorded source in Cloudflare so the Portal receives the
current tool schemas; verify that only the three reviewed tools remain enabled.
Verify a real Portal query and unauthenticated denial. If qualification fails,
roll back the recorded Worker version with the same private configuration:

```sh
npx wrangler rollback <previous-version-id> --config /absolute/private/bridge/wrangler.jsonc
```

Verify the restored settings, synchronize the source, and repeat the constant
query. Keep the private deployment configuration aligned with that version.
Gateway updates do not silently enable `allowQueries` or update this separately
deployed Worker.

Use the [key rotation procedure](#rotate-the-google-key) for the Google secret.
For a removed team member, use the [qualified Portal-wide session revocation](../../docs/TEAM_ACCESS.md#qualified-procedure-for-existing-portal-sessions)
procedure, which disconnects everyone connected to that Portal. Source policy
removal alone does not immediately invalidate an existing Portal grant.

For removal, detach the source through the gateway's normal source workflow,
verify it is absent from Portal discovery, revoke any remaining direct bridge
sessions, then remove the recorded bridge resources. Disable a Google key only
after checking every Worker using it. Do not delete a shared identity, Access
application, route, or Google dataset as incidental cleanup.

## Evidence

- [Google MCP authentication](https://docs.cloud.google.com/mcp/authenticate-mcp)
- [BigQuery MCP setup, roles, scope, and direct calls](https://docs.cloud.google.com/bigquery/docs/use-bigquery-mcp)
- [List tables input](https://docs.cloud.google.com/bigquery/docs/reference/mcp/tools_list/list_table_ids)
- [Table metadata input](https://docs.cloud.google.com/bigquery/docs/reference/mcp/tools_list/get_table_info)
- [Read-only SQL input](https://docs.cloud.google.com/bigquery/docs/reference/mcp/tools_list/execute_sql_readonly)
- [Cloudflare Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/)

Reviewed 2026-09-05. All added implementation is original; no upstream source
or API descriptions are vendored. Existing dependency pins are unchanged.
