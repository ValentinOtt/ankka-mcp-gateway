# Cloudflare disposable-account canary

## Status and purpose

The mutation library and lifecycle are implemented locally. They exist to
characterize Cloudflare's live MCP Portal contracts before a production
installer is exposed. The first disposable run used the legacy bare-Portal
model: it reached Portal creation but found no generated Portal Access
application. Its partial state was subsequently rolled back and cleaned with
separate approvals. On 2026-08-23, a second run proved the explicit
seven-resource model through the API, including no-op reapply, reverse cleanup,
and zero residue. A later exact-payload lifecycle also completed an
authenticated employee-facing Portal tool invocation and independently proved
zero residue. That closes the customer-payload functional gate, not the
hosted-installer, OAuth, signed-publication, or production-exposure gates.

Use only a disposable account or isolated test target with:

- an active zone;
- an active Cloudflare Access organization and authentication domain;
- a configured Cloudflare identity provider;
- a short-lived least-privilege test token;
- no production sources, credentials, emails, or DNS names.

Never record real identifiers, tokens, raw provider responses, employee emails,
or approval values in commits, fixtures, screenshots, or shared logs.

## Synthetic MCP through Quick Tunnel

The live fixture is deterministic and credential-free. It exposes one constant
read-only tool and no external calls. Start it on loopback:

```sh
npm run canary:fixture:serve
```

In a second terminal, expose it temporarily:

```sh
cloudflared tunnel --url http://127.0.0.1:9610
```

Use the Quick Tunnel's HTTPS hostname plus `/mcp` as the synthetic endpoint.
Keep both processes running only for the canary. Stopping them is fixture
teardown; no Worker is deployed. See
[the fixture runbook](../fixtures/synthetic-mcp/README.md).

## Secret and local-state requirements

Populate these only through the trusted operator environment:

- `CLOUDFLARE_API_TOKEN`;
- `ANKKA_CANARY_ALLOWED_EMAIL` with one synthetic test identity.

They are not CLI flags and never belong in the receipt. Choose an explicit
local receipt path in an owner-controlled directory. The lifecycle receipt and
its `.cleanup-recovery` sidecar are atomic mode-`0600` files. Lock directories
are mode `0700` with mode-`0600` metadata.

Receipts from the abandoned pre-release generated-app prototype are an
intentional schema break. A receipt containing
`portal.generatedAccessAppId` is never migrated or used for automatic cleanup;
the runner stops with `legacy_manual_cleanup_required` before mutation. Treat
that error as a manual inspection and cleanup requirement, not as permission to
delete or recreate Cloudflare resources.

Never delete or edit a pending receipt. Inspect an interrupted lock with the
CLI before recovery; remove only a reported stale candidate using its exact lock
ID and the literal confirmation shown by `--help`. Live, ambiguous, replaced,
or malformed locks remain untouched.

## Preview and approval

Preview performs fixture inspection, target-bound read preflight, live planning,
and reverse-cleanup planning without writes:

```sh
node src/canary-lifecycle-cli.mjs preview \
  --account-id <account-id> \
  --zone-id <zone-id> \
  --hostname <gateway.test-zone.example> \
  --synthetic-mcp-url <quick-tunnel-url>/mcp \
  --receipt <owner-controlled-path>
```

Review the exact preview. A run requires both returned values:

```sh
node src/canary-lifecycle-cli.mjs run \
  --account-id <account-id> \
  --zone-id <zone-id> \
  --hostname <gateway.test-zone.example> \
  --synthetic-mcp-url <quick-tunnel-url>/mcp \
  --receipt <owner-controlled-path> \
  --approve <lifecycle-approval> \
  --confirm-disposable-target <target-confirmation>
```

Arguments remain visible to the trusted local shell and process table. The
token and email do not. The approvals are recomputed from fresh reads before
the first write.

## Exact lifecycle

Apply is allowed only in this order:

```text
MCP server
  -> explicit source mcp Access application
  -> source policy
  -> Portal
  -> explicit portal mcp_portal Access application
  -> Portal policy
  -> DNS
```

The runner then verifies provider state, proves a second apply is a no-op,
optionally performs an interactive tool call through the employee-facing
Portal, and cleans up in exact reverse order:

```text
DNS
  -> Portal policy
  -> explicit portal mcp_portal Access application
  -> Portal
  -> source policy
  -> explicit source mcp Access application
  -> MCP server
```

Every request is journaled before mutation. An outcome-unknown create remains
pending and is not replayed. DNS is never created before both Access
applications and policies exist. Cleanup uses the receipt and live markers,
not names alone.

If no interactive Portal call is supplied, a clean API-only lifecycle is still
partial: the result is `verification_pending` and exits `3`. Exit `0` requires
the interactive call, installed-state verification, idempotent re-apply,
reverse cleanup, and zero receipt-owned residue.

## First live result: legacy bare-Portal model

The first disposable run proved:

1. the synthetic Quick Tunnel MCP was valid;
2. the exact MCP server could be created, synced, and verified;
3. an explicit source Access application of type `mcp` could be created and
   bound to that server;
4. the exact source allow policy could be created;
5. the Portal API created and fresh reads confirmed the exact Portal.

The next dependency failed: bounded Access-app discovery returned no matching
application of type `mcp_portal`. The target had an active zone, active Access
organization/authentication domain, and Cloudflare identity provider.

**API-contract finding:** the Portal exists but its documented generated Access
application was absent during the bounded observation window.

**Inference still under test:** API-created Portals may behave differently from
dashboard-created Portals, may require another undocumented condition, or may
have a longer/variable propagation path. None is proven, so none is encoded as
a workaround.

Cloudflare's
[MCP Portals documentation](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/)
states that creating a Portal automatically creates an Access application.

## Fail-closed response and completed cleanup

The initial lifecycle correctly:

- retained the pending Portal receipt;
- did not replay the Portal create;
- did not create the Portal policy or DNS;
- did not manually create a substitute `mcp_portal` Access application;
- stopped before claiming the live exit gate.

The recovery then completed in two separately approved operations:

1. the Portal rollback bound the checksum-valid receipt and pending intent to a
   fresh plan, performed two full Portal/app/DNS safety reads, deleted only the
   exact pending Portal, and proved bounded quiet absence before clearing the
   pending action;
2. cleanup-only approval deleted the source policy, explicit source Access
   application, and MCP server in reverse dependency order.

A fresh residue pass and live plan then confirmed all six resource kinds in the
historical model absent with no blockers or diagnostics. The receipt tombstone
and owner-only cleanup snapshot were retained. The Quick Tunnel was stopped,
and the short-lived API token was deleted from the local Keychain.
Cloudflare-side revocation or expiry still requires explicit operator
confirmation; local deletion is not token revocation.

This is the outcome of the first live attempt and its recovery, not a list of
currently live resources. The attempt still did not prove Portal policy/DNS,
full idempotent re-apply, or an interactive employee-facing Portal call because
the documented `mcp_portal` application never appeared.

## Dashboard reference evidence and second API-only result

A separately inspected dashboard-created reference showed the Portal before an
associated `mcp_portal` Access application. The application name matched the
Portal name, its domain matched the Portal hostname, and it had exactly one
public destination whose URI was that hostname. An inline Allow policy was
visible on the application. This is useful shape and ordering evidence, but it
was not created by the first canary and was not itself an API-only lifecycle
proof.

The second canary used a fresh, disjoint receipt and hostname on 2026-08-23. It
created and receipt-owned resources in the exact order server, source `mcp`
Access application, source Allow policy, Portal, explicit `mcp_portal` Access
application, Portal Allow policy, and DNS. During the installed-state hold, the
dashboard showed no broken-state banner. API reads verified the exact resource
state, Managed OAuth, both exact Allow policies, DNS, server `Ready` status and
tool discovery. An unauthenticated Portal request returned `401` with OAuth
discovery metadata. A complete second apply produced no mutations.

The approved cleanup then removed DNS, Portal policy, explicit Portal
application, Portal, source policy, source application, and server. An
independent post-cleanup observation counted zero residue. The receipt tombstone
and owner-only seven-resource cleanup snapshot were retained.

This proved the API-only lifecycle. A subsequent exact-payload lifecycle used a
fresh installation, completed an authenticated employee-facing tool call
through Access and Portal Code Mode, removed the seven resources from the real
stored receipt, and independently verified zero residue. That later run closed
the customer-payload functional gate; it did not exercise the hosted installer,
OAuth consent, signing, or R2 publication.

## Remaining exit gates

- [x] Secret-free deterministic fixture and Quick Tunnel path.
- [x] Seven-resource desired-state, receipt, and lifecycle implementation with
  focused local tests.
- [x] Live server, explicit source Access application, and source policy.
- [x] Live Portal API creation.
- [x] Approval-bound rollback of the pending partial Portal.
- [x] Separately approved cleanup of the remaining receipt-owned resources and
  a fresh zero-residue/no-blocker/no-diagnostic proof.
- [x] First-run Quick Tunnel teardown and deletion of that run's local
  short-lived-token copy.
- [ ] Confirm Cloudflare-side revocation or expiry of the short-lived test
  token.
- [x] Create and verify the explicit receipt-owned `mcp_portal` Access
  application in a second disposable canary.
- [x] Bind Portal policy to that application's exact provider ID and create DNS.
- [x] One interactive employee-facing Portal tool call in the subsequent exact
  payload lifecycle.
- [x] Idempotent second full apply, exact seven-resource reverse cleanup,
  independent zero-residue proof, and retained receipt evidence.
- [ ] Delete the current second-canary token from the local Keychain and confirm
  provider-side revocation or expiry.
- [ ] Live `GET /oauth/scopes` validation and customer OAuth client cleanup.

The exact customer-payload lifecycle gate has passed once. The hosted installer,
OAuth consent, signed publication, production mutation path and deploy button
remain blocked until their separate reviewed canary passes.

## Primary references

- [Cloudflare MCP Portals](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/)
- [Cloudflare MCP API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/ai_controls/subresources/mcp/)
- [Cloudflare Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/)
- [Cloudflare Access application policies](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/subresources/policies/)
- [Cloudflare DNS records API](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/)
- [Cloudflare OAuth scope catalogue](https://developers.cloudflare.com/api/resources/iam/subresources/oauth_scopes/methods/list/)
