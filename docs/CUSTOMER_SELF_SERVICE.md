# Self-service deployment

<a id="customer-self-service"></a>

Ankka MCP Gateway is designed to install into and operate from your Cloudflare
account. Your MCP Portal, management Worker, Access policies, logs, source
configuration, and upstream credentials remain under your control.

> **Availability:** stable and canary releases. Signed [releases](https://github.com/ValentinOtt/ankka-mcp-gateway/releases)
> are available, with a hosted flow at [deploy.ankka.ai](https://deploy.ankka.ai).
> Review the exact release before authorizing changes to your account; support
> is best-effort under the [support policy](../SUPPORT.md), not a production
> SLA. If the installer reports that deployment is unavailable, do not bypass
> its activation checks.

The source installer's disabled default activation is separate from the reviewed
hosted build. Public source does not include live deployment authority or
signing keys. The [local UI preview](../README.md#run-locally) uses synthetic
data and cannot deploy a gateway.

## What you will need

Installation requires:

- a Cloudflare account with an active zone;
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

The first sign-in is read-only and requests exactly:

- `account-settings.read`
- `memberships.read`
- `user-details.read`
- `zone.read`

After discovery, the installer attempts bounded provider-side revocation and
always discards its local copy. Installation and installer-assisted updates,
rollback, and removal use a separate, short-lived grant requesting exactly:

- `access-acct.write`
- `access.write`
- `account-settings.read`
- `dns.write`
- `mcp-portals.write`
- `memberships.read`
- `user-details.read`
- `workers-routes.read`
- `workers-scripts.write`
- `zone.read`

If Cloudflare does not confirm discovery-grant revocation, the installer tells
you to revoke Ankka MCP Gateway in Cloudflare Connected Applications before
starting a mutation.

Compare Cloudflare's consent screen with these lists. Stop if a permission is
missing or unexpected; the installer also rejects any release that asks for a
different set.

Team permission saves use a distinct customer-owned Worker secret, never one of
these OAuth grants. The runtime token needs only account-scoped **Access: Apps
and Policies — Edit** and **MCP Portals — Read**, restricted to the gateway's
account. The Access permission permits broader account Access administration;
it is not isolated to this gateway's policies. Read the exact endpoint evidence,
direct Cloudflare provisioning, rotation/revocation, and migration steps in
[Team access](TEAM_ACCESS.md#customer-owned-management-credential) before
approving this standing authority.

## Installation flow

The public installer is designed to:

1. ask you to sign in with Cloudflare;
2. discover your eligible accounts and active zones without making changes;
3. collect the gateway name, two hostnames, and initial administrators;
4. show the complete secret-free deployment plan;
5. request a short-lived Cloudflare grant only after you approve that plan;
6. create and verify the gateway management surface and empty MCP Portal; and
7. return the MCP URL and management URL.

Installation does not add an upstream MCP source. Add the first source from the
gateway dashboard after the gateway is ready.

If discovery finds an existing or conflicting installation, the installer
stops instead of adopting or overwriting it.

Fresh-hostname checks are read-only and run before the installer creates its
journal or any Gateway resource. If the requested hostname already has a DNS
record, that record is left untouched; start a new static plan with an unused
hostname, or intentionally retire the old hostname outside the installer.

After a write begins, exact journaled resources may remain for reviewed resume
or reconciliation and are not blindly auto-deleted. Continue through the
reviewed recovery flow and use its receipt-bound uninstall path for full
cleanup.

## Managing the gateway

Open the management URL and authenticate through your Cloudflare Access policy.

**Native-permissions preview limitation:** this release is for gateways with
sources already installed. A fresh empty gateway cannot add its first source
through the dashboard or source-action API until a compatible release restores
source installation.

- **Overview** shows gateway status, the MCP URL, current release, audience,
  and source state.
- **Sources** shows existing sources and their selected tools. Adding a source
  is temporarily unavailable in the native-permissions release, including from
  previously prepared installation links. Existing connections are unchanged.
- **Team** manages who may connect and which existing sources each person can
  use. Administrator rights remain fixed; tool allowlists are shared per source.
  One Save sends the complete batch to your own Worker, which updates and
  verifies your Access policies without contacting Ankka or starting OAuth.
  See [Team access](TEAM_ACCESS.md) for verification and recovery limits.
- **Settings** checks the installed signed release channel, prepares an
  update or rollback, and contains the removal entry point. Older canary
  versions may label the update screen **Updates**; the current source keeps
  `/updates` as a redirect to `/settings`.

Updates, rollback, and removal require a new short-lived Cloudflare
authorization. Team saves require the separately provisioned
`ANKKA_TEAM_MANAGEMENT_TOKEN` Worker secret and fail closed with setup guidance
if it is missing or invalid; they never fall back to hosted OAuth. Source draft saves and installation actions are
refused while the source-installation pause is active. The complete secret-free source-state
record is bounded to 1 MiB of canonical UTF-8 JSON; a save that would cross the
bound in its worst-case installed projection is rejected before Durable Object
storage is changed.

For a protected source, the Portal mapping sets **Require user auth** off. A
gateway operator connects the source once, the credential stays in your
Cloudflare account, and team members authenticate only to the
Gateway Portal. The current dashboard does not offer per-user upstream
authentication. Ankka does not receive the upstream token.

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

Only sources and exact tools approved by the operator are exposed. An MCP tool
name or description is not proof that the operation is safe; upstream
authorization remains authoritative.

Qualify the client and source together using the
[connection review checklist](README.md#before-sharing-a-gateway). A successful
catalogue discovery or local preview is not proof of live authentication,
execution, or compatibility with every MCP client.

## Updates and rollback

Updates are never automatic. A gateway administrator reviews the signed
release and approves a new Cloudflare authorization.

An ordinary update persists only Worker code and management asset changes. It
preserves Portal configuration, Access, DNS, sources, credentials, and Durable
Object data. Rollback restores a previous Worker version without rolling back
data. See [Gateway updates and rollback](UPDATES.md) for the temporary,
authenticated action route used during the operation.

The customer-local Team release changes the optional secret-binding contract.
An installed v16 gateway requires a separately reviewed maintenance migration;
its normal code-only update cannot silently accept or provision that authority.
Compatible later forward updates preserve the secret by inheriting it from the
verified deployed version. Rollback is blocked when the current or target
version has the management secret. Follow the
[migration plan](TEAM_ACCESS.md#migration-from-the-v16-oauth-flow), preserving
pending proposals, source credentials, and Durable Object data.

After a Team policy write may have occurred, rollback to an older runtime is
blocked. Rolling back code would not undo saved permissions or Access policies.

## Removing a gateway

The original successful installer session can prepare a same-session removal
plan until the deadline shown by the installer. The initial session lasts 30
minutes; interrupted-operation recovery may be retained for at most 24
additional hours. An operator returning to an existing gateway starts with fresh, read-only
existing-gateway detection and then opens a receipt-bound handoff from the
gateway dashboard.

Both paths show the exact teardown plan and require a new Cloudflare
authorization before any deletion.

Automatic teardown is unavailable after a Team policy write may have occurred,
including for older prepared removal links. The original ownership receipt is
preserved; a later compatible release is required to support changed audiences.

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

The Team management API token is created outside the installer and must be
revoked separately in Cloudflare. Removing its Worker binding does not revoke
it or erase historical versions. Neither step clears the restrictions caused
by a possibly applied Team policy write.

## Experimental browser tools

When a browser provides `document.modelContext`, the installer and gateway
dashboard register WebMCP tools as a progressive enhancement. Browsers without
that API keep the normal interface.

Installer tools are `begin_cloudflare_discovery`, `configure_gateway`,
`create_review_plan`, `get_installer_status`, `begin_authorization`,
`create_removal_plan`, and `begin_removal`.

Dashboard tools are `list_mcp_sources`, `discover_mcp_source`,
`save_mcp_source_draft`, `apply_mcp_source`, `check_gateway_update`,
`review_gateway_update`, `apply_gateway_update`,
`rollback_gateway_update`, and `review_gateway_teardown`.

The source draft/apply tools obey the same temporary installation pause as the
dashboard and cannot add a source in this release.

These tools call the same same-origin APIs as the visible interface. They add
no independent mutation authority. A mutation tool can prepare a short-lived
handoff URL, but the user must review the action and approve Cloudflare consent;
an agent must not request, receive, or approve the user's token.

## Troubleshooting safely

Keep any pending receipt or recovery record until provider state is understood.
Deleting recovery state can make a safe retry impossible.

Share only the fixed public error code and non-sensitive release information.
Never send OAuth codes, access tokens, cookies, private keys, account or
resource identifiers, raw provider responses, or credential-bearing
screenshots.

Report security issues through [private vulnerability reporting](../SECURITY.md).
