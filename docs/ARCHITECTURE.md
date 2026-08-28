# Architecture

## Purpose and ownership

Ankka MCP Gateway presents one organization MCP endpoint while preserving
provider-native MCP servers and customer ownership of credentials.

```text
employee MCP clients
  -> Cloudflare Access
  -> Cloudflare MCP Server Portal
       -> optional Ankka company-context MCP
       -> provider-native MCP servers
       -> customer-approved MCP servers
```

The customer owns the Portal, hostname, Access applications and policies,
encrypted upstream credentials, DNS, request logs, and installation receipt in
its Cloudflare account and local environment. Ankka may operate an optional
company-context upstream and a future non-secret setup interface. Provider
credentials and proxied source results must not transit Ankka as a side effect
of deployment.

The repository is the public-source boundary for the customer-resident layer
and the optional hosted installer. It does not contain Ankka's broader product
control plane, credentials, private signing material, generated releases, or
production deployment authority.

## Execution surfaces

The current general product CLI is offline:

1. validate a secret-free configuration;
2. compare it with a credential-free observed snapshot;
3. emit a deterministic plan and non-authoritative uninstall preview.

The repository separately contains canary-only execution surfaces:

- a zero-write, target-bound Cloudflare preflight;
- a fixed synthetic MCP fixture for loopback plus a temporary Quick Tunnel;
- a live-capable Cloudflare mutation provider;
- an approval-bound lifecycle runner for a disposable account;
- lock inspection and explicit stale-lock recovery.

The repository contains one customer-resident administration application:

- the React/Vite/Tailwind/Kumo SPA in `apps/admin`, with Overview, Sources, and
  Updates;
- the reviewed primary Worker in `payload/worker`, serving the generated SPA
  and a same-origin JSON API;
- Cloudflare Access JWT validation and an exact deployment admin allowlist;
- a singleton Durable Object holding source drafts, action journals, and
  runtime version state; and
- browser-local WebMCP tools that use the same bounded APIs as the human UI.

The dashboard uses a distinct management origin; it cannot share the MCP
Portal hostname. The signed dashboard
accepts public MCP sources and standards-compliant OAuth sources with exact
tool allowlists. It recognizes OAuth only from the MCP protected-resource
`WWW-Authenticate` challenge and configures Cloudflare Portal for per-user
upstream authorization. The customer Worker applies one draft at a time through
a fresh, actor- and account-bound Cloudflare OAuth handoff, journals the three
source resources and full Portal mapping, and retains no Cloudflare grant or
upstream token. Manually entered names and upstream annotations do not
independently prove tool behavior, so upstream authorization remains part of
the boundary.

The saved access model is one Portal-user audience compiled identically into
the source and Portal Access policies. Dashboard administrators are not part of
that desired state: the management Access policy and exact deployment allowlist
remain the separate, immutable bootstrap boundary.

The repository additionally contains the hosted installer in `apps/installer`.
It implements session and CSRF handling, exact plan review, Cloudflare OAuth,
signed-release verification, installation journaling, customer bootstrap, and
retained-session plus returning-customer receipt-authorized removal. Its
checked-in activation is compile-time disabled and its release pin is empty;
source availability grants no deployment or signing authority. The customer
dashboard is the ongoing customer-owned administration path. Its WebMCP surface
lists and discovers sources, saves exact drafts, prepares the same one-time
OAuth apply handoff used by the human UI, and prepares a teardown handoff for
explicit user review.

## Seven-resource model

One synthetic-source lifecycle has exactly seven resources and a fixed
dependency order:

```text
1. mcp_server
2. source_access_application   # explicit Access app with type mcp
3. source_access_policy
4. portal
5. portal_access_application   # explicit Access app with type mcp_portal
6. portal_access_policy        # parent is the exact app from step 5
7. dns_record
```

Uninstall must use the exact reverse order:

```text
dns_record
  -> portal_access_policy
  -> portal_access_application
  -> portal
  -> source_access_policy
  -> source_access_application
  -> mcp_server
```

Both Access applications are created and owned explicitly rather than inferred
from a name or Cloudflare cascade. The Portal is created first; its
`mcp_portal` Access application is then created with the exact Portal name and
hostname, and the Portal policy is bound to that application's receipt-owned
provider ID. DNS is last so an incomplete authorization surface is never
published.

## Planning, ownership, and mutation

The planner derives stable resource keys, desired hashes, exact tool mappings,
and strict provider locators. Locators are routing information, not ownership
authority. Executable mutation requires all of:

- the exact freshly reviewed plan and approval;
- a checksum-valid customer receipt bound to account, zone, and hostname;
- the expected native ownership marker and live resource shape;
- a journaled request hash written before the remote operation;
- a fresh live read before update or deletion.

Receipt resources follow the seven-resource dependency order. The local store
writes atomically with mode `0600`. Mutations hold an exclusive owner-only lock;
the cleanup-recovery sidecar provides independent evidence for interrupted
reverse cleanup.

An unknown create outcome is not retried. The pending receipt remains the sole
recovery authority until a fresh read can prove adoption, approved rollback, or
continued ambiguity. Ordinary plan approval is not prune or rollback authority.

## Disposable canary lifecycle

The lifecycle is:

```text
inspect deterministic synthetic MCP
  -> zero-write target preflight
  -> preview exact seven-resource plan and reverse cleanup
  -> require lifecycle approval + disposable-target confirmation
  -> apply in dependency order
  -> verify provider state
  -> re-apply as no-op
  -> optionally call the tool through the employee-facing Portal
  -> uninstall in reverse order
  -> verify zero receipt-owned residue and no same-host conflicts
```

The synthetic MCP contains one constant read-only tool and no credentials,
customer data, clock values, or external calls. The first live fixture uses a
loopback listener and temporary Cloudflare Quick Tunnel; it is not the
production hosting design.

An API-only run cannot establish that an employee can authenticate and invoke
the tool through the Portal. Even after clean resource removal it reports
`verification_pending` and exits `3`. Only the interactive Portal call plus all
provider, idempotency, cleanup, and residue checks can produce success.

## First live canary: legacy bare-Portal finding and recovered state

The first disposable run successfully created and verified the server, explicit
source Access application, and source policy. The Portal API then returned and
fresh reads confirmed the exact Portal, but bounded discovery found no matching
`mcp_portal` Access application. The target had an active zone, Access
organization and authentication domain, and Cloudflare identity provider.

Cloudflare's
[MCP Portals documentation](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/)
describes automatic Access-application creation. The missing application is the
observed API-contract finding. It is only an inference that API creation differs
from dashboard creation or requires another undocumented condition; the code
must not assume either explanation.

Because the generated parent was absent, the Portal policy and DNS dependencies
were not created. The create was not replayed, and no substitute `mcp_portal`
application was constructed.

The partial state was removed through two distinct destructive approvals. The
Portal rollback bound the original receipt and pending intent to a fresh live
plan, performed two full Portal/app/DNS safety reads, deleted only the exact
Portal, and required bounded quiet absence before clearing the pending action.
A separate cleanup-only approval then removed the source policy, explicit
source Access application, and server in reverse dependency order. A fresh
residue inspection and live plan confirmed every one of the six resource kinds
in that historical model absent with no blockers or diagnostics. The receipt
tombstone and owner-only cleanup snapshot were retained; the Quick Tunnel was
stopped and the local Keychain copy of the short-lived test token was deleted.
Provider-side revocation or expiry remains an operator confirmation; deleting a
local secret does not revoke the Cloudflare token.

This is the completed cleanup of the first live attempt, not a description of
currently live resources. It proves only the legacy bare-Portal behavior and
its bounded recovery. Portal policy/DNS, full idempotent re-apply, and
interactive Portal invocation were not tested.

## Dashboard reference and API-only second-canary result

A separately inspected dashboard-created reference showed the Portal before an
associated `mcp_portal` Access application. The application name matched the
Portal name, its domain matched the Portal hostname, it contained exactly one
public destination whose URI was that hostname, and an inline Allow policy was
visible on it. This is reference evidence for the provider builders, not a
successful API-only installation and not evidence from the first canary.

The current implementation therefore models the Portal application as an
explicit receipt-owned resource between `portal` and `portal_access_policy`.
The policy remains a separate receipt resource: its parent locator must equal
the application's exact provider ID, and reverse cleanup removes the policy
and application before deleting the Portal.

On 2026-08-23, the second canary used a fresh, disjoint hostname and receipt and
proved the explicit API-only dependency chain end to end. It created the server,
source application, source policy, Portal, explicit Portal application, Portal
policy, and DNS in that order. The dashboard showed no broken-state banner.
Fresh API observations verified the exact installed state, Managed OAuth, both
exact Allow policies, DNS, server `Ready` status and tool discovery, and the
Portal's unauthenticated `401` OAuth-discovery response. The complete re-apply
was a no-op.

Cleanup then removed the seven resources in exact reverse order. A separate
residue observation counted zero, while the receipt tombstone and owner-only
seven-resource cleanup snapshot were retained as evidence. That run proved the
API-only resource lifecycle. A subsequent exact-payload lifecycle also
completed the authenticated employee tool invocation and zero-residue removal,
closing the customer-payload gate. It did not exercise the hosted installer,
OAuth consent, signing, or R2 publication.

## Remaining architecture work

1. Complete the reviewed hosted-installer OAuth, signed-publication and removal
   canary against the exact release bytes.
2. Pin and activate that exact release only after explicit review, without
   moving provider credential custody out of the customer's Cloudflare account.

Cloudflare OS remains an optional compatible client/runtime. Existing
MCP-compatible clients should connect to the same Portal URL.
