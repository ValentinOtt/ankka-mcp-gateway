# Self-service deployment

<a id="customer-self-service"></a>

Ankka MCP Gateway is designed to install into and operate from your Cloudflare
account. Your MCP Portal, management Worker, Access policies, logs, source
configuration, and upstream credentials remain under your control.

> **Availability:** stable and canary releases. [deploy.ankka.ai](https://deploy.ankka.ai)
> serves the stable release; signed [canary releases](https://github.com/ankka-ai/ankka-mcp-gateway/releases)
> are published for evaluation. Support is [best-effort](../SUPPORT.md), with no
> availability or response-time commitment. Review the exact release before
> authorizing changes to your account. If the installer reports that deployment
> is unavailable, do not bypass its activation checks.

The source installer's disabled default activation is separate from the reviewed
hosted build. Public source does not include live deployment authority or
signing keys. The [local UI preview](../README.md#run-locally) uses synthetic
data and cannot deploy a gateway.

## What you will need

Installation requires:

- a Cloudflare account with an active zone (up to 100 active zones in the hosted setup);
- Cloudflare Zero Trust configured for that account;
- permission to create Workers, Durable Objects, DNS, Access applications and
  policies, and MCP Portal resources;
- one hostname for the team's MCP Portal;
- a different hostname for the management dashboard; and
- the initial administrators, who also form the initial Portal audience.

The installer browser flow uses Cloudflare OAuth. Do not create an API token for Ankka,
paste a provider credential into the installer, or put credentials in a URL or
configuration file.

## Cloudflare permissions

The first approval selects exactly one account and requests:

- `workers-scripts.write`
- `zone.read`

Ankka discovers that account's active domains and deploys the initial Worker.
It reuses an existing account Workers subdomain. If none exists, it registers
a generated subdomain and verifies it. You do not need a placeholder Worker or
manual `workers.dev` setup. The account subdomain is shared by Workers and is
never included in gateway cleanup or removal.

The grant stays in the hosted callback's request memory and is revoked before
handoff to your Worker. Your Worker collects and reviews the gateway details,
then requests a fresh installation grant:

- `access-acct.read`
- `zone-access.write`
- `dns.write`
- `mcp-portals.write`
- `workers-routes.read`
- `workers-scripts.write`
- `zone.read`

The second grant is handled by your Worker. It rechecks the selected account,
zone, and hostname availability before creating the remaining resources.
Updates, rollback, and removal request only their operation's permissions;
adding domain discovery to initial setup does not widen those grants. The
[operation contract](../apps/installer/src/cloudflare-operation-authority.ts)
is authoritative.

If revocation cannot be confirmed, follow the installer's recovery instructions
and revoke the connection in Cloudflare Connected Applications. Compare each
consent screen with the operation you requested.

The Worker configuration flow and expanded first approval are implemented in
source. Their exact combined scope set and first-time account subdomain
registration still require a fresh live canary before production promotion;
older canary results do not qualify these changes.

V1 Team membership is managed directly in Cloudflare. Do not create or add a
Team-management API token to the gateway. Cloudflare does not support scoping
an API token to one reusable Access policy, so an account token would widen the
credential boundary instead of completing this flow. See
[Team access](TEAM_ACCESS.md).

## Installation flow

The public installer is designed to:

1. start at [deploy.ankka.ai](https://deploy.ankka.ai) without entering gateway details;
2. choose one Cloudflare account and approve initial Worker deployment and domain discovery;
3. revoke that grant and open the setup page in your own Worker;
4. choose a domain from the dropdown, gateway name, two hostnames, and administrators;
5. review the complete deployment plan and edit it if needed;
6. approve a fresh grant so your Worker can install and verify the remaining resources; and
7. open the MCP URL and management URL.

Each review sends the chosen configuration, signed by your Worker's ownership
key, to the hosted issuer to certify the exact final callback address. This
request contains no Cloudflare grant. The draft and signed response live in
your Worker; the initial domain list and deployment evidence remain in the
hosted session for its one-hour lifetime. The setup capability expires after
ten minutes. MCP source credentials never enter this flow.

Installation does not add an upstream MCP source. The default-deny onboarding
candidate restores a separate Sources workflow: discover and review the exact
read-only tools, save a draft, authorize installation, connect the upstream in
Cloudflare, and explicitly grant source access in Team. A new source initially
denies everyone. The published v19 runtime still pauses this workflow; use the
installed release's capability state and [qualification checklist](FIRST_SOURCE_ONBOARDING.md),
not main-branch documentation, to determine availability.

If discovery finds an existing or conflicting installation, the installer
stops instead of adopting or overwriting it.

Fresh-hostname checks are read-only and run in the second stage before final
Gateway resources are created. The initial Worker already exists at this point. If the requested hostname already has a DNS
record, that record is left untouched; start a new static plan with an unused
hostname, or intentionally retire the old hostname outside the installer.

After a write begins, exact journaled resources may remain for reviewed resume
or reconciliation and are not blindly auto-deleted. Continue through the
reviewed recovery flow and use its receipt-bound uninstall path for full
cleanup.

## Managing the gateway

Open the management URL and authenticate through your Cloudflare Access policy.

**Source onboarding is default-deny:** creating source resources is not an
access grant. The upstream connection and a reviewed Team assignment are
separate steps. Gateways still on the published v19 preview cannot add sources.

- **Sources** is the home page, with a copyable MCP Gateway URL and a searchable
  source list. Expand a source to inspect its selected tools. When the installed
  runtime enables installation, save and authorize a reviewed draft here.
  New sources start denied; old prepared installation links cannot silently
  acquire the new default-deny authorization profile.
- **Team** is read-only in V1. It shows the gateway's saved access snapshot and
  shared source tools; manage membership and source audiences directly in
  Cloudflare. Administrator rights remain fixed. See
  [Team access](TEAM_ACCESS.md) for the manual workflow and recovery limits.
- **Settings** checks the installed signed release channel, prepares an
  update or rollback, and contains the removal entry point in its danger zone.
  The sidebar footer shows the installed version and any available update. Older canary
  versions may label the update screen **Updates**; the current source keeps
  `/updates` as a redirect to `/settings`.

Updates, rollback, and removal require a new short-lived Cloudflare
authorization. Team writes are rejected in V1 and never fall back to hosted
OAuth or a standing Worker credential. Source installation uses a separate
short-lived installer authorization. Source draft saves do not request OAuth or
grant access. The complete secret-free source-state record is bounded to 1 MiB
of canonical UTF-8 JSON; a save that would cross the bound in its worst-case
installed projection is rejected before Durable Object storage is changed.

For a protected source, the Portal mapping sets **Require user auth** off. A
gateway operator connects the source once, the credential stays in your
Cloudflare account, and team members authenticate only to the
Gateway Portal. The current dashboard does not offer per-user upstream
authentication. Ankka does not receive the upstream token.

## Add BigQuery

Compatible releases provide **Sources → Add BigQuery**. Enter your query project
and datasets, approve Cloudflare, and upload a dedicated service-account JSON
key directly to your gateway. It deploys the protected bridge and configures
its callback before the operator connects the source and grants team access.
See the [complete flow and recovery instructions](ADD_BIGQUERY.md).

## Supported MCP sources

Source discovery supports Streamable HTTP responses as JSON or server-sent
events. It prefers MCP protocol `2026-07-28` and falls back to the compatible
`2025-06-18` initialize and session flow. Tool pagination is bounded, and the
Worker retains no upstream MCP session after discovery.

A protected source is normally recognized from the standard Bearer
`WWW-Authenticate` challenge with a public HTTPS `resource_metadata` URL.
The exact Google BigQuery MCP endpoint is also recognized as protected even
though its tool catalogue is public. Its shared operator connection is currently
blocked: Cloudflare's documented manual OAuth flow has no admin credential
flow. The dashboard shows the public tools and the reason for the block; it does
not accept Google secrets or offer per-user Google authentication as a fallback.
See [BigQuery Google authentication](BIGQUERY_GOOGLE_AUTH.md) for current
compatibility evidence, least-privilege setup, cost-control gaps and acceptance
gates.

Credential-bearing URLs, private-network endpoints, custom credential headers,
and manually supplied bearer tokens are rejected.

## Connecting an MCP client

Use the team-facing MCP Portal URL returned after installation. The client
must support the MCP transport exposed by Cloudflare and complete your
Cloudflare Access flow.

New installations configure these public, non-secret callbacks in the Portal's
Managed OAuth **Allowed redirect URIs** for dynamic client registration (DCR).
The provider documentation was reviewed on 2026-09-05.

| Client surface | Callback allowed during registration |
| --- | --- |
| Claude hosted connectors, including Claude Desktop | `https://claude.ai/api/mcp/auth_callback` |
| ChatGPT stable callback | `https://chatgpt.com/connector_platform_oauth_redirect` |
| ChatGPT callback specific to a connector | `https://chatgpt.com/connector/oauth/*` |
| Cursor web and Cursor Agents | `https://www.cursor.com/agents/mcp/oauth/callback` |

ChatGPT uses the stable callback for eligible authorization servers with issuer
identification and for older connections. Otherwise its callback contains a
connector-specific ID. The single wildcard above is limited to that documented
callback path; it does not allow other ChatGPT paths or hosts. Cloudflare uses
the pattern to admit registration; the client still registers its concrete
callback URI. See [ChatGPT's redirect URL documentation](https://developers.openai.com/plugins/build/auth#redirect-url)
and [Cloudflare's Managed OAuth settings](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/#managed-oauth-settings).

In Claude, use **Always required** authentication and automatic OAuth client
registration. In ChatGPT, use OAuth with DCR when configuring the connection.
For Cursor, add the Portal MCP URL and complete the offered OAuth login; these
defaults do not require manually supplied client credentials. Localhost and
loopback callbacks remain enabled for local clients, including Cursor Desktop's
`http://localhost:8787/callback`. See [Claude's callback documentation](https://claude.com/docs/connectors/building/authentication#callback-urls)
and [Cursor's callback documentation](https://cursor.com/docs/mcp#static-redirect-url).

Existing Portals keep their current callback settings; updating the gateway
Worker does not rewrite Access applications. To enable another client on an
older Portal, edit its **Managed OAuth → Allowed redirect URIs** in Cloudflare
and add the relevant entries above while preserving existing entries. For
ChatGPT, you can instead add only the exact callback shown in its connection
setup. The same setting accepts an additional client's documented HTTPS callback
without requiring an Ankka release. Keep custom entries as narrow as the client
allows. Portal access, source access, and upstream authentication still apply.

These are callback compatibility defaults, not proof of a client's identity or
an end-to-end client qualification. Local callback support is not restricted to
particular desktop products. CIMD support has not been established for the
managed Portal; these settings configure DCR only.

Only sources and exact tools approved by the operator are exposed. An MCP tool
name or description is not proof that the operation is safe; upstream
authorization remains authoritative.

Qualify the client and source together using the
[connection review checklist](README.md#before-sharing-a-gateway). A successful
catalogue discovery or local preview is not proof of live authentication,
execution, or compatibility with every MCP client.
Before marking Claude, ChatGPT, or Cursor as qualified for a release, test each
client against the same release candidate: complete registration and consent,
check the exact tools visible to the test member, execute a bounded read-only
canary call, then verify token refresh and reconnection. Team revocation remains
a separate release requirement; see [Team access](TEAM_ACCESS.md).

## Updates and rollback

Updates are never automatic. A gateway administrator reviews the signed
release and approves a new Cloudflare authorization.

An ordinary update changes Worker code and management assets, and records its
own action, installed release, and status in the existing Durable Object. It
preserves Portal configuration, Access, DNS, sources, credentials, ownership
receipts, and team data. Rollback restores a previous Worker version without
rolling back application data. See [Gateway updates and rollback](UPDATES.md)
for the temporary, authenticated action route used during the operation.

The V1 release contract does not include a Team-management secret. A reviewed
forward update can remove the retired preview binding by omitting it from the
new version; it never reads or inherits the value. Rollback is blocked when the
current or target version carries that legacy binding. Follow the
[retirement procedure](TEAM_UPGRADE.md), preserving source credentials,
application data, and any uncertain action journal.

After a Team policy write or new-profile source creation may have occurred,
rollback below the recorded runtime floor is blocked. Rolling back code would
not undo saved permissions, new ownership receipts, or Access policies.

## Removing a gateway

The original successful installer session can prepare a same-session removal
plan until the deadline shown by the installer. The initial session lasts 30
minutes; interrupted-operation recovery may be retained for at most 24
additional hours. An operator returning to an existing gateway starts with fresh, read-only
existing-gateway detection and then opens a receipt-bound handoff from the
gateway dashboard.

Both paths show the exact teardown plan and require a new Cloudflare
authorization before any deletion.

Automatic teardown is unavailable after a Team policy write or new-profile
source creation may have occurred, including for older prepared removal links.
The original ownership receipt is preserved; a later compatible release is
required to support this lifecycle state. Merely discovering a source, saving
its draft, or reviewing an action does not set the restriction. Review this
limitation before authorizing source installation.

Deletion authority comes from the checksum-valid receipt stored by the
gateway, not from a hostname, resource name, or provider identifier.
The flow removes only resources proven to belong to that installation and
stops on drift or ambiguity.

Cloudflare retains the Advanced Certificate after the management Custom Domain
is removed. That certificate is outside Ankka's OAuth scope and must be reviewed
or removed manually in Cloudflare.

Other unrelated Cloudflare resources and upstream provider accounts are not
removed. Provider-side credentials or OAuth clients configured outside the
gateway may need separate revocation.

If you created the retired preview Team token, revoke it separately in
Cloudflare and remove its Worker binding. Removing the binding does not revoke
the token or erase historical versions. Neither step clears restrictions caused
by a possibly applied legacy Team policy write.

## Experimental browser tools

When a browser provides `document.modelContext`, the installer and gateway
dashboard register WebMCP tools as a progressive enhancement. Browsers without
that API keep the normal interface.

Installer tools are `get_installer_status`, `prepare_deployment`,
`begin_authorization`, `finish_secure_setup`, and `begin_cleanup`.
`prepare_deployment` takes no gateway fields; configuration happens in your
Worker after the first approval.

Dashboard tools cover Gateway capabilities and status, sources, read-only Team
state and retained-action recovery, signed update review and handoffs, and
recorded action status. See [the complete WebMCP tool contract](WEBMCP.md) for
exact names, inputs, safe recovery, and browser-test instructions. No separate
management MCP connection is required.

The source draft/apply tools follow the installed runtime's capability state,
just like the dashboard. Published v19 gateways keep them paused; the default-deny
candidate restores them without granting source access automatically.

These tools call the same same-origin APIs as the visible interface. They add
no independent mutation authority. V1 exposes Team state read-only and leaves
membership changes in Cloudflare. Install/update/removal tools retain their
reviewed short-lived authorization handoffs. An agent must not request or
receive the user's token or substitute tool metadata for required consent.

## Troubleshooting safely

Keep any pending receipt or recovery record until provider state is understood.
Deleting recovery state can make a safe retry impossible.

Share only the fixed public error code and non-sensitive release information.
Never send OAuth codes, access tokens, cookies, private keys, account or
resource identifiers, raw provider responses, or credential-bearing
screenshots.

Report security issues through [private vulnerability reporting](../SECURITY.md).
