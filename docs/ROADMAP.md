# Roadmap

The repository contains both the customer-owned runtime and hosted-installer
source and is approaching its first public release. Enabling deployment still
follows the complete reviewed canary; implementation or repository visibility
alone is not the gate.

## 0. Public-ready boundary

- [x] Separate repository and Apache-2.0 license.
- [x] Customer ownership and credential-custody model.
- [x] Secret-free configuration schema and deterministic offline CLI.
- [x] Public-boundary check, synthetic fixtures, and provenance ledger.
- [x] Transfer the hosted installer source without credentials, signing
  material, or deployment authority.
- [x] Add checks for publishable files, reachable blobs, commit/tag metadata,
  forbidden output and high-confidence credential formats.
- [ ] Publish from a sanitized history root with no private canary locators.

## 1. Disposable-account canary

Implemented locally:

- [x] Target-bound, zero-write Cloudflare preflight.
- [x] Checksum-protected receipt, intent journal, owner-only persistence, and
  fail-closed lock recovery.
- [x] Seven-resource desired-state, receipt, and lifecycle implementation in
  the exact order: server, explicit source `mcp` Access application, source
  policy, Portal, explicit receipt-owned `mcp_portal` Access application,
  Portal policy, DNS.
- [x] Approval-bound preview/run lifecycle, idempotency check, reverse-order
  cleanup, and residue inspection.
- [x] Deterministic MCP fixture using a local listener and temporary Quick
  Tunnel.
- [x] API-only partial result exits `3` until an interactive Portal tool call is
  verified.

First live canary: legacy bare-Portal progress:

- [x] Synthetic upstream verification.
- [x] Server, explicit source Access application, and source policy creation.
- [x] Exact Portal API creation.
- [x] Recover the pending Portal through a dedicated, separately
  approved partial rollback.
- [x] Use a separate cleanup-only approval to delete the remaining source
  policy, explicit app, and server; retain the receipt tombstone and owner-only
  cleanup snapshot; confirm all six resource kinds in that historical model
  absent with no blockers, diagnostics, or residue.
- [x] Stop the first run's Quick Tunnel and delete that run's local Keychain
  copy of the short-lived installer token.
- [ ] Confirm Cloudflare-side token revocation or expiry; local deletion alone
  is not provider revocation.

Second live canary: explicit seven-resource model:

A separately inspected dashboard-created reference showed the Portal before an
`mcp_portal` Access application whose name matched the Portal, whose domain and
single public destination URI matched the hostname, and which exposed an inline
Allow policy. This remains shape evidence, distinct from both live canaries.

- [x] Use a fresh, disjoint receipt and hostname on 2026-08-23.
- [x] Create and verify the explicit receipt-owned `mcp_portal` Access
  application after the Portal.
- [x] Bind Portal policy to that application's exact provider ID and create DNS
  last.
- [x] Verify one interactive employee-facing Portal tool call.
- [x] Verify exact API state, Managed OAuth, both exact Allow policies, DNS, server
  `Ready`/tool discovery, and the unauthenticated `401` OAuth discovery path;
  confirm in the dashboard that no broken-state banner is present.
- [x] Verify a complete second apply is a no-op.
- [x] Uninstall all seven resources in exact reverse order and independently
  verify zero residue.
- [x] Retain the receipt tombstone and owner-only seven-resource cleanup
  snapshot.
- [ ] Delete the second-canary token still saved in the local Keychain and
  confirm provider revocation or expiry.

The first live run stopped at the historical generated `mcp_portal` Access-app
dependency and created no Portal policy or DNS. The partial state was
subsequently rolled back and cleaned to zero provider residue. Those items
describe that completed first attempt, not current live resources. Dashboard
reference evidence informed the explicit-app design but remains separate from
the second canary. That second API-only run proved the complete seven-resource
apply, Portal policy/DNS, no-op re-apply, reverse cleanup, and independent zero
residue. A subsequent exact-payload run completed the employee-facing tool
invocation and zero-residue removal. This closes the customer-payload half; it
does not by itself establish hosted-installer production readiness or
repeatability.

## 2. One-click onboarding

- [x] Single customer-resident React/Kumo dashboard with Overview, Sources,
  Updates, bounded live MCP discovery, exact customer-owned drafts, and
  equivalent WebMCP tools; deterministic builds feed the signed release.
- [x] Agent-native day-two source apply with an actor-bound one-time OAuth
  handoff, customer-resident mutation journal, recovery, and uninstall cleanup.
- [x] Standards-compliant per-user upstream MCP OAuth through the customer
  Cloudflare Portal, with no Ankka token custody.
- [x] Strict deployment-target-bound, zero-write dashboard preview.
- [ ] Fetch and validate the live Cloudflare OAuth scope catalogue.
- [x] Browser-based customer authorization implementation with short-lived
  least privilege, retained behind compile-time-disabled activation.
- [x] Worker-compatible checksum receipt store and approval-bound apply,
  status, retained-session uninstall, and returning-customer receipt-handoff
  implementation.
- [x] Scope V1 to public MCP sources and standards-compliant per-user OAuth;
  static bearer and pre-registered OAuth-client setup is explicitly post-preview
  and must remain customer-direct without exposing secrets to Ankka.
- [x] Hosted setup wizard and Cloudflare deploy-button implementation, disabled
  in checked-in source and activated only in generated builds from an exact
  signed release pin.
- [x] Exercise a signed hosted OAuth installation in a private canary.
- [x] Signed normal-update discovery, explicit OAuth apply, progress, and
  code-only rollback UX.
- [ ] Run the real updater-capable N → N+1, broken-candidate compensation,
  rollback, and post-update uninstall promotion canary in a disposable account.
- [ ] Optional handoff of narrowly scoped, non-secret health state to Ankka.

The checked-in implementation remains fail-closed. Generated private-canary
builds have exercised the mutation path. MCP source-provider credentials must
never transit or be retained by Ankka. The distinct operation-scoped Cloudflare
installer grant exists only in connected-callback memory and may be forwarded
once to the exact HMAC-authenticated customer Worker for the reviewed action;
it is never persisted, logged, sent elsewhere, or reused.

## 3. Public preview

- [x] Fresh-account installation and removal documentation.
- [ ] Repeatable complete canary on a clean target.
- [x] Deterministic production dependency/license inventory, SHA-pinned CI
  actions, checksum verification, and source-bound production-only SBOM tooling.
- [ ] Attach and checksum-verify the exact SBOM on the first sanitized public
  release.
- [x] Private vulnerability-reporting contract; enable and verify the host
  feature as part of public cutover.
- [ ] Make the combined customer-runtime and installer-source repository public.

Independent security review and a stable support policy remain mandatory before
stable promotion, but do not turn an explicitly unsupported preview into a
self-certified production release.

Write-capable company tools are outside these phases. They require a separate
capability, authorization, and audit design.

## 4. Post-preview source authentication

- [ ] Design customer-controlled static bearer and pre-registered OAuth-client
  setup performed directly in Cloudflare, with no secret transiting Ankka or
  entering configuration, logs, errors, telemetry, or support evidence.

This is not a V1 public-preview gate. Until that design is reviewed, the
runtime rejects those authentication modes rather than accepting an unsafe
credential-forwarding shortcut.
