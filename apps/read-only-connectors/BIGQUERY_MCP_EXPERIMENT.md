# Google hosted BigQuery MCP bridge experiment

This is a tested prototype, not a supported catalog source or a release change.
Run the existing connector Worker with `CONNECTOR_PROVIDER=bigquery-mcp` to
send approved tool calls to Google's fixed `https://bigquery.googleapis.com/mcp`
endpoint. Google implements the BigQuery tools; this adapter only authenticates,
restricts requests, and unwraps bounded text tool results.

## Qualification status

The prototype passed `npm run check:fast`, including 31 bridge checks across
both supported client protocol versions. Integration must also pass the
repository's full CI release gate.

Live qualification passed on a separate Worker in the test Cloudflare account:

- Cloudflare Managed OAuth login with the existing test operator;
- exactly the three reviewed tools exposed;
- Google service-account authentication;
- the constant SQL query returned `1`;
- listing a page of tables and reading one table's metadata;
- unauthenticated requests rejected with HTTP 401; and
- public OAuth discovery served by the expected Cloudflare Access issuer.

No Google sign-in was required for the person using the direct bridge; the
Worker authenticated to Google. This does not prove the Portal's shared
operator flow. Deployment receipts and private test details remain outside
the public repository.

The live `tools/list` response confirmed the reviewed tool names and argument
names. Unlike the current documentation, its SQL input does not yet include
`timeoutMs` or `jobTimeoutMs`; sending those fields produced an invalid-argument
tool error. The prototype now sends only the required project and constant
query. The deployed client-to-Worker-to-Google path is proven. Adding this
source through Ankka's dashboard, shared-operator authentication in the
Cloudflare MCP portal, and use by a second team member remain unproven.
General SQL is still deliberately disabled; credential rotation and a query
cost-control decision remain necessary before production qualification.

The Worker belongs in your Cloudflare account. Cloudflare Access with Managed
OAuth protects its exact hostname; the Worker verifies the signed Access JWT.
The dedicated service-account key stays in the Worker secret `PROVIDER_TOKEN`.
Ankka operates no intermediary service and receives no credentials or traffic.
Everyone admitted to this shared connector uses the same Google identity.

Synthetic configuration:

```json
{
  "queryProjectId": "synthetic-query-project",
  "allowedDatasets": [
    { "projectId": "synthetic-data-project", "datasetId": "sample_dataset" }
  ]
}
```

The exact tools exposed are `list_table_ids`, `get_table_info`, and
`execute_sql_readonly`. The first two only accept configured project/dataset
pairs. The SQL tool accepts exactly `SELECT 1 AS bridge_ok` in the configured
query project. This deliberately tests authentication without scanning tables.
No data writes, arbitrary SQL, extra methods, URLs, incoming authorization
headers, redirects, automatic pagination, or retries are forwarded.

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
   Portal without a Google login, then revoke source access and verify denial.
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
5. Rotate the temporary test credential directly in the customer account.

The live probe simulates Access locally and calls Google for real; passing it
does not prove Cloudflare deployment, Managed OAuth, or portal authentication.
Private input config uses the JSON above and optionally `probeTableId` for the
metadata probe. Set `ANKKA_BIGQUERY_BRIDGE_LIVE=1`,
`ANKKA_BIGQUERY_BRIDGE_KEY_FILE` and `ANKKA_BIGQUERY_BRIDGE_CONFIG_FILE` in the
local environment, then run `npx vitest run --config vitest.live.config.ts`
from this workspace.

## Cost limitation

Google's hosted SQL MCP input currently has no `maximumBytesBilled` setting.
The documented job timeout is not a scan budget and was absent from the live
schema during this test. The current REST reader enforces the byte
budget; this experiment must not silently replace it for arbitrary queries.
Before expanding beyond the constant query, decide how the deployment will
enforce acceptable query costs and dataset-scoped read-only IAM.
[Custom daily quotas](https://docs.cloud.google.com/bigquery/docs/custom-quotas)
are useful additional safeguards, but Google documents that they are
approximate and can be exceeded. They are not a per-query byte ceiling.

## Evidence

- [Google MCP authentication](https://docs.cloud.google.com/mcp/authenticate-mcp)
- [BigQuery MCP setup, roles, scope, and direct calls](https://docs.cloud.google.com/bigquery/docs/use-bigquery-mcp)
- [List tables input](https://docs.cloud.google.com/bigquery/docs/reference/mcp/tools_list/list_table_ids)
- [Table metadata input](https://docs.cloud.google.com/bigquery/docs/reference/mcp/tools_list/get_table_info)
- [Read-only SQL input](https://docs.cloud.google.com/bigquery/docs/reference/mcp/tools_list/execute_sql_readonly)
- [Cloudflare Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/)

Reviewed 2026-09-04. All added implementation is original; no upstream source
or API descriptions are vendored. Existing dependency pins are unchanged.
