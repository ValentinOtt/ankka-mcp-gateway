# Security model

This document describes the intended security boundary of Ankka MCP Gateway.
The project is pre-release and is not a substitute for reviewing Cloudflare,
each upstream MCP server, and the exact signed release before deployment.

## Trust boundaries

The deployment trusts:

- the customer's Cloudflare account and its administrators;
- Cloudflare Workers, Access, MCP Portal, DNS, and OAuth services;
- the exact signed gateway release; and
- each explicitly approved upstream MCP server.

Open source makes the customer-resident implementation inspectable. It does not
remove those external trusts.

An optional Ankka MCP source has no special access to other sources or their
credentials.

## Credentials

MCP source-provider credentials must remain in the customer's Cloudflare
account. Ankka does not ask for, store, relay, or log them.

The hosted installer's Cloudflare OAuth grants are separate from MCP source
credentials. The first grant is read-only: it is bound to the authorizing actor,
discovery purpose, and expiry, and is used to discover eligible accounts and
zones before the customer selects a target.

A later mutation grant is created only after the user reviews an exact action.
It is additionally bound to the selected account and target and is used only
for the approved provider calls or one exact authenticated customer Worker
action.

Both grant types are held only in request-local memory, are never written to
Durable Object state, logs, analytics, browser output, or support evidence, and
are subject to bounded revocation attempts before their local copies are
discarded.

Revocation is a provider operation and may be unconfirmed. Discarding a local
copy does not prove provider-side revocation.

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

## Customer dashboard

The management dashboard runs in the customer's Cloudflare account on a
hostname separate from the MCP Portal. Cloudflare Access protects the origin,
and the Worker independently verifies the Access JWT issuer, audience,
signature, expiry, verified email, and deployment administrator allowlist.
Cross-origin API requests are rejected.

The customer Durable Object stores secret-free configuration, exact source
allowlists, action journals, release state, and ownership receipts. It must not
store Cloudflare OAuth grants or upstream tokens.

## Ownership, recovery, and removal

Resource names and provider IDs are not deletion authority. Removal requires a
checksum-valid customer receipt, an exact target match, fresh provider reads,
and expected ownership markers.

The receipt and journal preserve recovery authority after interruptions. A
missing, corrupt, conflicting, or ambiguous record stops automatic mutation.
Only receipt-owned resources are removed, in reverse dependency order.

## Software supply chain

The repository contains no private signing key, production deployment
credential, generated signed release, or release-publication authority.

Release tooling requires a clean public source commit, deterministic payload
inputs, a complete manifest, one exact HTTPS control-plane origin, and an
external Ed25519 signature. The origin is compiled into the customer Worker
before hashing. The installer verifies the signed channel, key identity,
origin, manifest, deployment contract, and every payload digest before use;
requests and gateway configuration cannot redirect that authority.

See [Release integrity](RELEASING.md) for publication and signing-key lifecycle
requirements.

Normal updates are limited to Worker code and management assets. Changes to
permissions, bindings, migrations, compatibility settings, signing keys, or
provider resources require a separately designed and approved release path.

## Logs and telemetry

Secrets, raw provider responses, customer identifiers, and free-form provider
errors must not appear in application logs, errors, analytics, tests, or
support output.

Customer-deployed gateways send no telemetry to Ankka. Their routine Ankka
request is anonymous signed-release discovery and carries no account,
hostname, user, cookie, authorization, or referrer.

The optional Ankka-hosted installer has a separate session-scoped product
funnel: an opaque per-session key with coarse request context (country,
browser family, and the page-view referrer host), set without cookies and
without customer identifiers, IP or raw user-agent storage, or any identifier
that outlives the installer session. Cloudflare separately adds Network Error
Logging headers to hosted-zone browser responses, and browsers may send the
resulting reliability reports to Cloudflare. The exact product fields,
destination, retention, exclusions, and user notice are public in
[Hosted installer analytics](HOSTED_INSTALLER_ANALYTICS.md). Neither mechanism
is installed in the customer gateway.

Cloudflare and upstream providers may retain their own operational data under
the customer's configuration and their policies. The no-Ankka-telemetry
guarantee does not claim that those providers process no metadata.

## Known limitations

- The project has no production-supported release yet.
- The checked-in installer is deliberately unable to deploy or remove a
  gateway.
- Read-only tool policy depends on both gateway configuration and upstream
  enforcement.
- Worker rollback does not roll back Durable Object data.
- Provider APIs can return ambiguous outcomes; the system stops for recovery
  instead of claiming success.
