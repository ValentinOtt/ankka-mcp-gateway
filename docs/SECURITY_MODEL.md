# Security model

## Trust and credential boundary

The deployment trusts the customer's Cloudflare account, Cloudflare's managed
MCP and Access services, and each explicitly approved upstream. Open source
makes the customer-resident layer inspectable; it does not remove those trusts.

Ankka's hosted systems remain outside the provider-credential boundary. An
optional Ankka MCP upstream gains no access to other upstreams or their
credentials.

Required invariants:

- Public desired configuration, plans, receipts, fixtures, logs, tests, and
  telemetry contain no API tokens, bearer credentials, OAuth secrets, cookies,
  passwords, private keys, or raw employee identities. The customer-resident
  dashboard draft is the narrow identity exception described below.
- `CLOUDFLARE_API_TOKEN` and `ANKKA_CANARY_ALLOWED_EMAIL` are read only from the
  customer-controlled local environment for canary preview/run. They are never
  accepted as CLI arguments or persisted.
- Provider authorization is operation-scoped. The hosted callback holds the
  Cloudflare grant only in the connected invocation, forwards one HMAC-bound
  action to the customer Worker, verifies the temporary Worker route is closed,
  revokes the grant, and retains no credential.
- Sources use HTTPS and exact tool allowlists. Wildcards are rejected. A tool
  name or server-authored safety annotation is not authorization; the upstream
  and Cloudflare policy must also enforce the allowed operation.
- Customer-deployed gateway telemetry to Ankka is off. The signed release and
  live deployment contracts disable Workers metrics, dependency
  instrumentation, observability, Logpush, and tail consumers; payload code
  emits no Ankka analytics beacon or reporting header. Direct upstream URLs
  remain independently protected by the upstream's own authentication and
  authorization.

This customer-runtime invariant is distinct from Cloudflare platform metadata
on Ankka's hosted installer. Network Error Logging remains enabled for the
`ankka.ai` zone, and Cloudflare may inject `NEL`/`Report-To` after the hosted
Worker responds. That separately disclosed edge policy must not be copied into
customer Worker code, configured in a customer account, or treated as evidence
that customer traffic is reported to Ankka.

The active reviewed hosted installer also writes default product-funnel events
to one Analytics Engine dataset in Ankka's Cloudflare account. The server emits
only ten fixed milestone names plus the public release/channel and fixed
outcome/flow categories; it emits no visitor, session, request, customer,
provider-resource, credential, duration, or free-form field. The binding is
absent from the checked-in disabled shell, rollback shell, and every
customer-deployed Worker. Writes are drop-only and cannot affect a provider
operation. The exact schema, destination, three-month provider retention,
query semantics, and timing-correlation limitation are documented in
[Hosted installer analytics](HOSTED_INSTALLER_ANALYTICS.md).

The synthetic canary fixture contains one constant tool, no durable state, no
credentials or customer data, and no external calls. Its temporary Quick Tunnel
is disposable test infrastructure, not a production credential path.

## Customer dashboard boundary

The management dashboard is served from a customer-owned Worker on an origin
separate from the MCP Portal. Cloudflare Access protects that origin, and the
Worker independently verifies the JWT signature, issuer, audience, and email.
It does not trust the convenience identity header. A deployment-controlled
exact admin allowlist is checked after verification, and cross-origin API
requests are rejected.

The singleton Durable Object stores only customer-owned draft settings,
including the Portal-user audience. Its underlying V1 admin/member split exists
only for wire compatibility and is derived deterministically from the sorted
audience, never from the signed-in actor; it does not authorize the dashboard.
API routes are protected by the separate deployment-controlled dashboard admin
allowlist and responses are non-cacheable. Preview scope—account, zone, zone
name, and Zero Trust readiness—comes from deployment environment variables and
cannot be overridden by a browser request. Raw account and zone identifiers are
omitted from serialized plans and dashboard responses.

Dashboard V1 accepts public MCP sources or standards-compliant per-user OAuth
sources. It recognizes OAuth only from a Bearer `WWW-Authenticate` challenge
whose `resource_metadata` value is a public HTTPS URL. The source record stores
only the resulting authentication mode and exact tool allowlist. Cloudflare
Portal receives `on_behalf: true` and owns every user's upstream grant and
refresh token. The dashboard rejects submitted bearer values, custom credential
headers, pre-registered OAuth client secrets, wildcard tools, local or
IP-literal endpoints, and non-standard authentication.

Its live day-two mutation is an exact saved-source apply authorized through a
fresh Cloudflare OAuth action. The action key exists only in a URL fragment and
an encrypted short-lived installer cookie; the Durable Object stores its hash.
The Cloudflare OAuth grant exists only in request-local provider calls and must
never enter Durable Object state, logs, errors, telemetry, or API output.

Before the hosted callback exposes the exact customer Worker route, it verifies
the OAuth actor and account, the account's `workers.dev` subdomain, and that the
claimed management custom domain belongs to that Worker. It requires the route
to start disabled, always attempts and verifies a compensating disable after an
ambiguous enable, and accepts exactly one HMAC-authenticated action response.

## Plans, approvals, and receipts

Offline observed-state files are preview input only. Live mutation and deletion
authority comes from fresh provider reads plus the customer-owned receipt.

Before a canary write, the operator must review a fresh preview and supply both:

1. the exact lifecycle approval derived from the plan, fixture proof, receipt,
   and reverse cleanup;
2. the separate disposable-target confirmation bound to account, zone, and
   hostname.

Each remote mutation is journaled in the receipt before the request. A commit
requires the expected live marker, desired hash, and provider locator. A failed
or outcome-unknown create remains pending and is never replayed automatically.
Ordinary apply approval is not prune, uninstall, or partial-rollback authority.

The receipt and cleanup-recovery sidecar are checksum-protected, atomic local
files with owner-only mode `0600`. Their parent directory must also be
customer-controlled. Do not move, delete, edit, or publish a receipt while it
contains pending or cleanup authority.

## Locks and crash recovery

Mutation runs hold an exclusive lock directory with mode `0700` and one `0600`
metadata file. Lock metadata contains only bounded operational identifiers,
process ownership, PID, and creation time; it contains no secrets or receipt
body.

A lock is never broken because it is old. Recovery requires:

1. `lock inspect` on the exact receipt or cleanup store;
2. a `stale_candidate` result, never `live` or `ambiguous`;
3. the exact reported lock ID;
4. the explicit confirmation phrase printed by the CLI;
5. a second process and file-identity check immediately before removal.

Malformed, replaced, empty, live, or process-ambiguous locks remain for manual
investigation. Lock recovery removes only the lock, not the receipt or provider
resources.

## Seven-resource mutation boundary

The canary adapter is limited to this dependency order:

```text
mcp_server
  -> source_access_application
  -> source_access_policy
  -> portal
  -> portal_access_application
  -> portal_access_policy
  -> dns_record
```

Cleanup is the exact reverse: DNS, Portal policy, explicit Portal application,
Portal, source policy, explicit source application, then server. DNS can be
created only after both Access policy surfaces exist. Both the source `mcp`
application and Portal `mcp_portal` application are explicit receipt-owned
resources. The Portal policy parent must be the exact provider ID recorded for
the Portal application. Updates and deletes require receipt ownership plus a
fresh marker/shape check. Missing or duplicate dependencies fail closed.

After capability sync, the adapter must keep `default_disabled: true` and
reapply the exact tool allowlist. A tool name or prompt is never an
authorization boundary by itself.

### Pre-release receipt schema break

The abandoned six-resource prototype stored a Cloudflare-generated Portal
application ID on the `portal` receipt resource. That shape is not accepted by
the current receipt validator and cannot authorize apply, uninstall, adoption,
or migration. If the canary runner detects the removed
`portal.generatedAccessAppId` field, it returns the fixed
`legacy_manual_cleanup_required` error before any provider mutation. Detection
is diagnostic only; it does not establish ownership or validate the legacy
receipt as cleanup authority. An operator must inspect and clean such
pre-release state manually. No current seven-resource receipt is downgraded to
that schema.

## Logs and results

Errors identify a bounded stage and safe code; they never return Cloudflare or
upstream response bodies, authorization headers, selected target identifiers,
or raw emails. Human plan output omits upstream URLs and member identities.
Plan JSON includes deployment metadata and a deterministic identity digest, so
it remains customer-controlled and must not enter shared logs or telemetry.

An API-only lifecycle is deliberately non-successful. If no interactive tool
call traverses the employee-facing Portal, the result is
`verification_pending` and the CLI exits `3`, even when provider state,
idempotency, reverse cleanup, and residue checks otherwise pass.

## First live canary: legacy bare-Portal attempt and clean recovery

In the first disposable live run, the exact server, explicit source Access
application, and source policy were created and verified. The Portal API then
created the exact Portal, but Cloudflare did not expose the `mcp_portal` Access
application described by the
[MCP Portals documentation](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/).
The target otherwise had an active zone, Access organization/authentication
domain, and Cloudflare identity provider.

The verified finding is the missing generated application after API Portal
creation. Whether this is propagation, an API-versus-dashboard difference, or
another undocumented prerequisite is still an inference.

The lifecycle retained the pending Portal receipt, made no second Portal create,
created neither Portal policy nor DNS, and did not manually fabricate an Access
application.

The pending state was then removed without broadening ordinary authority. A
separate rollback approval bound the checksum-valid receipt, old and current
desired roots, pending intent, target, and fresh live evidence. The rollback
performed two full pre-delete Portal/app/DNS reads and proved bounded quiet
absence after the exact Portal deletion. A separate cleanup-only approval
deleted the source policy, explicit source Access application, and server in
reverse order. Fresh residue and plan reads confirmed all six resource kinds
in that historical model absent with no blockers or diagnostics. The receipt
tombstone and owner-only cleanup snapshot remain; the temporary Quick Tunnel
was stopped and the local Keychain copy of the short-lived token was deleted.
Cloudflare-side revocation or expiry still requires explicit operator
confirmation; deleting a local secret does not revoke the provider token.

Those facts describe recovery from the first live attempt, not current live
resources. They do not prove explicit Portal-app creation, Portal policy/DNS,
full idempotent re-apply, or an interactive Portal call. The repository is still
not production-ready.

## Dashboard reference and API-only second canary

A separately inspected dashboard-created reference showed a Portal followed by
an `mcp_portal` application whose name matched the Portal name, whose domain
matched the Portal hostname, and whose only destination was a public URI equal
to that hostname. An inline Allow policy was visible on the application. This
reference is evidence for a narrow desired shape; it is not mutation authority
and is not a successful API canary.

The implementation represents that application as an explicit
receipt-owned resource. Its exact provider ID is the only acceptable parent for
the Portal policy, and both resources must be removed before the Portal.

On 2026-08-23, the reviewed exact payload completed the seven-resource
lifecycle in a disposable account. It created and verified every resource in
dependency order, re-applied as a no-op, completed an authenticated employee
tool invocation through Access and Portal Code Mode, removed every resource in
reverse order from the stored receipt, and left zero independently observed
residue.

The hosted installer implementation now lives in `apps/installer`, but source
availability is not authority. Its checked-in install and uninstall activation
is compile-time disabled, the release pin and public-key registry are empty, and
the repository contains no OAuth secret, session key, signing private key,
release envelope, R2 credential, or generated release. Production remains
disabled until the separate hosted OAuth, signing, publication and removal
canary passes and an exact release is explicitly reviewed and pinned.
