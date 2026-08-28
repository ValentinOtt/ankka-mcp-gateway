# Customer self-service

Ankka MCP Gateway is designed to install into and operate from your Cloudflare
account. Your MCP Portal, management Worker, Access policies, logs, source
configuration, and upstream credentials remain under your control.

> **Availability:** customer self-service is not yet open for general use.
> `https://deploy.ankka.ai` may show an unavailable preview while the first
> signed public release is prepared. Do not use the current service for a
> production account.

## What you will need

When the public preview opens, installation will require:

- a Cloudflare account with an active zone;
- Cloudflare Zero Trust configured for that account;
- permission to create Workers, Durable Objects, DNS, Access applications and
  policies, and MCP Portal resources;
- one hostname for the employee MCP Portal;
- a different hostname for the management dashboard; and
- the initial administrators, who also form the initial Portal audience.

The browser flow uses Cloudflare OAuth. Do not create an API token for Ankka,
paste a provider credential into the installer, or put credentials in a URL or
configuration file.

## Cloudflare permissions

The first sign-in is read-only and requests exactly:

- `account-settings.read`
- `memberships.read`
- `user-details.read`
- `zone.read`

After discovery, the installer attempts bounded provider-side revocation and
always discards its local copy. Installation and every later Cloudflare
resource mutation use a separate, short-lived grant requesting exactly:

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

## Installation flow

In the current hosted browser flow, the public installer is designed to:

1. ask you to sign in with Cloudflare;
2. discover your eligible accounts and active zones without making changes;
3. collect the gateway name, two hostnames, and initial administrators;
4. show the complete secret-free deployment plan;
5. request a short-lived Cloudflare grant only after you approve that plan;
6. create and verify the customer management surface and an empty MCP Portal; and
7. return the MCP URL and management URL.

The browser flow does not add an upstream MCP source. The signed installation
contract also supports one explicitly reviewed initial source with an exact
tool allowlist, but the browser UI does not expose that option. Ordinary
self-service users add the first source from the customer dashboard after the
gateway is ready.

If discovery finds an existing or conflicting installation, the installer
stops instead of adopting or overwriting it.

## Managing the gateway

Open the management URL and authenticate through your Cloudflare Access policy.

- **Overview** shows gateway status, the MCP URL, current release, audience,
  source state, and the removal entry point.
- **Sources** discovers a public MCP catalogue or records a
  standards-compliant per-user OAuth source, saves an exact tool allowlist, and
  prepares an exact apply action for customer review.
- **Updates** checks the installed signed release channel and prepares an
  update or rollback.

Saving a source draft changes only customer-owned Durable Object state. Applying
a source, updating, rolling back, or removing the gateway requires a new
short-lived Cloudflare authorization.

Upstream per-user OAuth is handled by Cloudflare Portal. Ankka does not receive
those tokens.

## Supported MCP sources

Source discovery supports Streamable HTTP responses as JSON or server-sent
events. It prefers MCP protocol `2026-07-28` and falls back to the compatible
`2025-06-18` initialize and session flow. Tool pagination is bounded, and the
Worker retains no upstream MCP session after discovery.

A protected source is recognized only from the standard Bearer
`WWW-Authenticate` challenge with a public HTTPS `resource_metadata` URL.
Credential-bearing URLs, private-network endpoints, custom credential headers,
and manually supplied bearer tokens are rejected.

## Connecting an MCP client

Use the employee-facing MCP Portal URL returned after installation. The client
must support the MCP transport exposed by Cloudflare and complete the
customer's Cloudflare Access flow.

Only sources and exact tools approved by the customer are exposed. An MCP tool
name or description is not proof that the operation is safe; upstream
authorization remains authoritative.

## Updates and rollback

Updates are never automatic. A customer administrator reviews the signed
release and approves a new Cloudflare authorization.

An ordinary update persists only Worker code, management assets, and two
non-secret release-identity text bindings. It preserves Portal configuration,
Access, DNS, sources, credentials, resource and secret bindings, compatibility
settings, and Durable Object data. Rollback restores a previous Worker version
and its release identity without rolling back data. See
[Gateway updates and rollback](UPDATES.md) for the temporary, authenticated
action route used during the operation.

## Removing a gateway

The original successful installer session can prepare a same-session removal
plan until the deadline shown by the installer. The initial session lasts 30
minutes; interrupted-operation recovery may be retained for at most 24
additional hours. A returning customer instead starts with fresh, read-only
existing-gateway detection and then opens a receipt-bound handoff from the
customer dashboard.

Both paths show the exact teardown plan and require a new Cloudflare
authorization before any deletion.

Deletion authority comes from the checksum-valid receipt stored by the
customer gateway, not from a hostname, resource name, or provider identifier.
The flow removes only resources proven to belong to that installation and
stops on drift or ambiguity.

Cloudflare retains the Advanced Certificate after the management Custom Domain
is removed. That certificate is outside Ankka's OAuth scope and must be reviewed
or removed manually in Cloudflare.

Other unrelated Cloudflare resources and upstream provider accounts are not
removed. Provider-side credentials or OAuth clients configured outside the
gateway may need separate revocation.

## Experimental browser tools

When a browser provides `document.modelContext`, the installer and customer
dashboard register WebMCP tools as a progressive enhancement. Browsers without
that API keep the normal interface.

Installer tools are `begin_cloudflare_discovery`, `configure_gateway`,
`create_review_plan`, `get_installer_status`, `begin_authorization`,
`create_removal_plan`, and `begin_removal`.

Dashboard tools are `list_mcp_sources`, `discover_mcp_source`,
`save_mcp_source_draft`, `apply_mcp_source`, `check_gateway_update`,
`review_gateway_update`, `apply_gateway_update`,
`rollback_gateway_update`, and `review_gateway_teardown`.

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
