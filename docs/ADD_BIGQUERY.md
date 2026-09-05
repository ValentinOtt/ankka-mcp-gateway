# Add BigQuery

Open **Sources → Add BigQuery** in a gateway release that includes this flow.
The bridge, its Google credential, and the Cloudflare connection belong to your
Cloudflare account. The hosted Ankka installer does not receive the Google key.

## Prepare Google

Create a dedicated service account with a JSON key and enable the BigQuery API
and BigQuery MCP service in the projects used for queries and metadata.

- Grant `roles/bigquery.jobUser` in the query/billing project.
- Grant `roles/mcp.toolUser` in the query project and each data project used for
  table discovery.
- Grant `roles/bigquery.dataViewer` on the selected datasets. Review inherited
  permissions and avoid broader data access, write roles, and destination write
  permissions.

The [Google authentication guide](BIGQUERY_GOOGLE_AUTH.md)
explains the IAM and read-only MCP boundaries. The dataset list limits metadata
discovery; Google IAM controls what SQL can read. The setup confirmation is an
operator acknowledgement, not an automated audit of effective IAM.

## Connect

1. Choose **Add BigQuery**, name the source, enter its query project, and list
   datasets as `project.dataset`, one per line.
2. Confirm that the dedicated Google identity and JSON key are ready. Continue
   to the fresh Cloudflare approval for this operation.
3. Back on your gateway, choose the JSON key file and select **Deploy and
   connect BigQuery**. The gateway checks Google with `SELECT 1 AS bridge_ok`,
   creates a protected bridge Worker, writes its key as a Worker secret, and
   configures the exact OAuth callback automatically.
4. In the source status card, open the recorded source in Cloudflare and
   authenticate it as the gateway operator. Keep **Require user auth** off.
   Once Cloudflare reports **Ready**, return to Sources and select **Renew
   consent and resume** to verify and attach the source to the Portal.
5. Grant the intended audience access in Cloudflare. See [Team access](TEAM_ACCESS.md).
   Source installation starts with nobody assigned.

The selected tools are `execute_sql_readonly`, `get_table_info`, and
`list_table_ids`. Queries run in the chosen query project. There is no required
query cost ceiling; normal Google query billing and quotas apply.

## Permissions and credential handling

The initial BigQuery operation uses `bigquery-add`: `zone-access.write`,
`mcp-portals.write`, `workers-scripts.write`, and `workers-routes.read`. Ordinary
source installation retains its existing two scopes. The final connection
resume uses ordinary source consent once the bridge is ready.

The gateway exchanges the Cloudflare authorization code only after the
same-origin key upload. The grant remains in that callback's request memory,
is used for this operation, and is revoked/discarded afterward. The Google key
is never placed in a draft, cookie, Durable Object record, URL, or response. Its
only outbound destinations are the fixed Google authentication flow (a signed
assertion) and the exact child Worker's secret upload in the selected account.

Bridge code is embedded in the signed gateway release. The deployment disables
Worker logs, workers.dev, and previews before attaching its protected custom
domain. Managed OAuth allows only the recorded Cloudflare MCP server callback;
the bridge login policy admits the operator who prepared the action.

## Interrupted setup

Use **Continue BigQuery setup** for an unstarted attempt, or the recorded resume
action after a failed deployment. A fresh approval is required; saved resource
receipts identify what can be checked and resumed. A successful Worker upload
is not repeated and does not require another key upload when finishing the
source connection.

If a create request has an uncertain outcome, setup stops with its pending
receipt. Do not start another bridge with the same configuration or adopt a
resource based only on its name. Review the exact account resources before
reconciliation. An unknown create cannot be automatically resumed or removed;
keep the gateway's recovery state until the resources have been reconciled.
Rollback below the setup runtime remains blocked to preserve its receipts.

## Remove the gateway and its bridges

In a release with managed bridge removal, **Settings → Remove gateway** includes
BigQuery bridges in the first, gateway-hosted removal phase. The fresh approval
includes Workers permissions to verify each bridge's saved Worker version and
custom domain, including proving Worker absence for an application-only setup.
The gateway first verifies the full graph and refuses changed resources or a
bridge referenced by another MCP source.

Removal runs in bounded steps so multiple sources fit the
[Workers Free request limits](https://developers.cloudflare.com/workers/platform/limits/#subrequests).
The callback keeps its temporary grant only in memory and sends each signed
step to the same gateway. Saved progress contains no grant. Each fresh approval
rechecks the complete graph against its current receipts and configuration;
expired approval, an uncertain response, repeated progress, or an inventory
outside the bounded scan stops removal and withholds the final gateway handoff.

After removing the Portal and its owned sources, the gateway detaches each
bridge domain, deletes the Worker containing its Google key, and then removes
the bridge's Access application. Access stays in place until the Worker and
domain are confirmed absent. Only then can it issue the separate approval to
remove the gateway itself.

Known partial source receipts and interrupted Portal updates use the same
removal flow. An interrupted deletion keeps its exact receipt and progress;
return to Settings for fresh consent and resume. A lost create response without
a provider identity still requires manual reconciliation. Older releases that
cannot interpret bridge cleanup keep automatic gateway removal blocked.

Removing the bridge deletes its copy of the Google key. It does not revoke
the service-account key in Google; revoke that key there when you no longer need
it. Manually deployed bridges remain separate resources that you manage.

The manual deployment instructions remain available for older gateways. The
presence of **Add BigQuery** indicates that the installed release contains the
flow; main-branch documentation alone does not establish live availability.
