# Security model

This document describes the intended security boundary of Ankka MCP Gateway.
The project is a canary preview and is not a substitute for reviewing Cloudflare,
each upstream MCP server, and the exact signed release before deployment.

## Trust boundaries

The deployment trusts:

- the team's Cloudflare account and its administrators;
- Cloudflare Workers, Access, MCP Portal, DNS, and OAuth services;
- the exact signed gateway release; and
- each explicitly approved upstream MCP server.

Open source makes the gateway implementation inspectable. It does not
remove those external trusts.

An optional Ankka MCP source has no special access to other sources or their
credentials.

## Credentials

MCP source-provider credentials must remain in the team's Cloudflare
account. Ankka does not ask for, store, relay, or log them.

The hosted installer's Cloudflare OAuth grants are separate from MCP source
credentials. The first grant is read-only: it is bound to the authorizing actor,
discovery purpose, and expiry, and is used to discover eligible accounts and
zones before the operator selects a target.

A later mutation grant is created only after the user reviews an exact action.
It is additionally bound to the selected account and target and is used only
for the approved provider calls or one exact authenticated gateway Worker
action.

Both grant types are held only in request-local memory, are never written to
Durable Object state, logs, analytics, browser output, or support evidence, and
are subject to bounded revocation attempts before their local copies are
discarded.

Revocation is a provider operation and may be unconfirmed. Discarding a local
copy does not prove provider-side revocation.

Customer-local Team saves use a third, distinct credential:
`ANKKA_TEAM_MANAGEMENT_TOKEN`, a Cloudflare API token provisioned directly as a
Secret in the customer's gateway Worker. It is optional until the customer
explicitly approves standing management authority. It never transits Ankka or
the gateway browser API and must not enter Durable Object state, configuration
files, logs, telemetry, exceptions, deployment output, or support evidence.
Installer grants, source credentials, and inbound Access tokens cannot be used
for this purpose.

The current minimum is **Access: Apps and Policies — Edit/Write** and **MCP
Portals — Read**, scoped to the gateway's one account. Cloudflare does not
document per-policy API-token isolation for these account permissions: the
credential allows broader Access application and policy administration in that
account. Exact runtime ownership checks constrain this implementation, not a
stolen credential. Provisioning, rotation, revocation, endpoint evidence, and
remaining live validation are documented in [Team access](TEAM_ACCESS.md).
Deleting a Worker binding does not revoke its API token or remove the value from
historical versions; the customer must revoke the token in Cloudflare.

## Authorization

The initial source boundary is read-only with exact tool allowlists. Wildcards
are rejected. Tool names, descriptions, and source-authored annotations are
untrusted review aids; the upstream and Cloudflare policy must independently
enforce allowed operations.

Browser requests cannot select arbitrary Cloudflare accounts or provider
resources. The installer binds discovery, configuration, plan approval, OAuth
state, and execution to one expiring session and target. CSRF, OAuth state, and
PKCE are purpose-separated.

Every provider write is preceded by an intent record. A successful result
requires fresh read-back of the expected resource shape. Unknown outcomes
remain pending and are not replayed blindly.

## Gateway dashboard

<a id="customer-dashboard"></a>

The management dashboard runs in the team's Cloudflare account on a
hostname separate from the MCP Portal. Cloudflare Access protects the origin,
and the Worker independently verifies the Access JWT issuer, audience,
signature, expiry, verified email, and deployment administrator allowlist.
Cross-origin API requests are rejected.

The gateway Durable Object stores secret-free configuration, exact source
allowlists, action journals, release state, and ownership receipts. It must not
store Cloudflare OAuth grants or upstream tokens.

Team Save calls only the same-origin customer Worker, which uses its separate
management secret to verify the complete owned application/policy graph and
Portal mappings before and after exact policy writes. Fixed administrators,
same-origin/CSRF checks, revision checks, default-deny empty audiences, bounded
provider requests, and durable write intent remain required. Missing or invalid
credentials and provider drift fail closed without a hosted OAuth fallback.
An uncertain write retains its proposal and journal; it is not called a rollback.

Legacy Team authorization and callbacks are refused by the installer before
OAuth code exchange. The relay and new Worker also reject the old Team grant
submission. No temporary `workers.dev` route is needed for a Team save. Other
installer action callbacks retain their existing operation-scoped grant handling.

## Ownership, recovery, and removal

Resource names and provider IDs are not deletion authority. Removal requires a
checksum-valid installation receipt, an exact target match, fresh provider reads,
and expected ownership markers.

The receipt and journal preserve recovery authority after interruptions. A
missing, corrupt, conflicting, or ambiguous record stops automatic mutation.
Only receipt-owned resources are removed, in reverse dependency order.

## Software supply chain

The repository contains no private signing key, production deployment
credential, generated signed release, or release-publication authority.

Release tooling requires a clean public source commit, deterministic payload
inputs, a complete manifest, one exact HTTPS control-plane origin, and an
external Ed25519 signature. The origin is compiled into the gateway Worker
before hashing. The installer verifies the signed channel, key identity,
origin, manifest, deployment contract, and every payload digest before use;
requests and gateway configuration cannot redirect that authority.

See [Release integrity](RELEASING.md) for publication and signing-key lifecycle
requirements.

Normal updates are limited to Worker code and management assets. Changes to
permissions, bindings, migrations, compatibility settings, signing keys, or
provider resources require a separately designed and approved release path.

The customer-local Team release adds an explicitly optional secret contract.
The [reviewed bridge sequence](TEAM_UPGRADE.md) crosses the v16 contract boundary
using two normal signed updates, without out-of-band rewrites of durable release
records or provisioning the secret. Normal updater actions maintain their own
release records and status. Compatible subsequent forward updates preserve the
secret from the exact verified current Worker version without revealing its
value. Rollback is refused when the current or target version carries this secret. The original
teardown restrictions remain, including after token revocation or binding
deletion if any Team policy write may have occurred.

## Logs and telemetry

Secrets, raw provider responses, account or user identifiers, and free-form provider
errors must not appear in application logs, errors, analytics, tests, or
support output.

Self-hosted gateways send no telemetry to Ankka. Their routine Ankka
request is anonymous signed-release discovery and carries no account,
hostname, user, cookie, authorization, or referrer.

The optional Ankka-hosted installer has a separate session-scoped product
funnel: an opaque per-session key with coarse request context (country,
browser family, and the page-view referrer host), set without cookies and
without account or user identifiers, IP or raw user-agent storage, or any identifier
that outlives the installer session. Cloudflare separately adds Network Error
Logging headers to hosted-zone browser responses, and browsers may send the
resulting reliability reports to Cloudflare. The exact product fields,
destination, retention, exclusions, and user notice are public in
[Hosted installer analytics](HOSTED_INSTALLER_ANALYTICS.md). Neither mechanism
is installed in the gateway.

Cloudflare and upstream providers may retain their own operational data under
the team's configuration and their policies. The no-Ankka-telemetry
guarantee does not claim that those providers process no metadata.

## Known limitations

- Signed canary releases are available; there is no stable,
  production-supported release yet. Review the exact
  [release](https://github.com/ValentinOtt/ankka-mcp-gateway/releases), not only
  the current main-branch source.
- The default installer activation in the public source is disabled. A
  reviewed canary entrypoint uses an exact signed release pin and separately
  reviewed deployment configuration. Public source and the local UI preview
  do not confer live deployment or removal authority.
- Read-only tool policy depends on both gateway configuration and upstream
  enforcement.
- Worker rollback does not roll back Durable Object data.
- Provider APIs can return ambiguous outcomes; the system stops for recovery
  instead of claiming success.
