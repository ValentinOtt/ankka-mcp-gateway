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

V1 has no permanent Cloudflare management credential. Team membership and
source audiences are managed directly in Cloudflare; the gateway does not
accept a standing API token for Team policy writes. Installer OAuth grants,
source credentials, and inbound Access tokens cannot be repurposed for that
work.

Cloudflare support confirmed that account-owned and user-owned API tokens can
scope resources only at User, Account, or Zone level. **Access: Policies
Write** on one account therefore authorizes every Access policy in that account;
it cannot be restricted to one reusable Ankka policy. Per-policy Access Policy
Admin scoping belongs to the human/member IAM model, whose resource-scoped OAuth
path currently has a beta gap for individual policy API requests. See
[Team access](TEAM_ACCESS.md) for the V1 manual workflow and the two future
options that remain under consideration.

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

The Team page is read-only in V1. It can show the gateway's saved snapshot and
any retained legacy proposal, but changes made directly in Cloudflare are not
projected back into that snapshot. The Worker rejects new Team policy-write
requests and does not read a standing management credential. A definitely
unstarted legacy proposal may still be canceled through its existing guarded
path; uncertain writes retain their evidence for manual reconciliation rather
than being called a rollback.

The default-deny source-onboarding candidate creates each new source with one
exact deny-Everyone policy and verifies the complete policy list before Portal
attachment. No person, including an administrator, receives a new source
implicitly. Upstream operator authentication and a later Team grant are separate
steps. Existing receipt audiences remain immutable; only the exact historical
initial policy and the new empty-audience profile are recognized. Old prepared
source actions cannot silently become new-profile authorizations.

Legacy Team authorization and callbacks are refused by the installer before
OAuth code exchange. The relay and new Worker also reject the old Team grant
submission. Team management does not enable a temporary `workers.dev` route.
Other installer action callbacks retain their existing operation-scoped grant
handling.

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

The V1 signed release contract declares no Team-management secret. A forward
update may recognize the one retired preview binding only so it can omit that
binding from the new version; it never reads or inherits the value. Rollback
into or out of a version carrying the retired binding is refused. Anyone who
created the old API token must revoke it separately in Cloudflare because
removing a Worker binding does not revoke provider authority or erase historical
versions. See the preserved [retirement procedure](TEAM_UPGRADE.md).

The original teardown restrictions remain if a legacy Team policy write may
have occurred, even after token revocation or binding removal.
New-profile source creation uses the same conservative floor/removal safeguard
before its first provider mutation. Source discovery, draft saving, and action
review do not arm it. This restriction is disclosed before source authorization
and must be reviewed before release activation; it is not deletion authority.

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
- Automatic teardown is unavailable after a potentially applied Team policy
  write or new-profile source creation. Revoking a retired preview token or
  restoring the original roster does not clear the recorded restriction.
- Provider APIs can return ambiguous outcomes; the system stops for recovery
  instead of claiming success.
