# Changelog

Notable public product and repository changes are recorded here.

## Unreleased

- Prepare the initial public preview source for Ankka MCP Gateway.
- Add secret-free configuration validation and deterministic offline planning.
- Add the customer-owned Cloudflare runtime and management dashboard.
- Add the optional fail-closed hosted installer and operation-scoped OAuth
  flow.
- Add signed release, update, rollback, recovery, and receipt-owned removal
  contracts.
- Add exact read-only source allowlists and synthetic end-to-end fixtures.
- Raise repository-local contracts to a 500-tool bound and add a reproducible
  228-tool OpenAPI fixture, supplemental 251-tool workload and hostile-name
  coverage, simulated management lifecycle coverage, and searchable dashboard
  review.
- Add deterministic GET-only OpenAPI allowlist generation with check mode and
  an optional exact reviewed manifest for individually bound non-GET reads and
  wrapper-local synthetic tools; no method-wide non-GET switch is accepted.
- Add a signed, exact control-plane-origin contract and an unsupported
  first-party Cloudflare dogfood runbook covering two create-only releases,
  install, update, rollback, recovery, receipt-bound removal, and exact cleanup;
  live qualification remains pending.
- Document customer-owned audit logging with a minimal source-Worker fallback,
  large-source Code Mode qualification with an exact live-catalogue gate,
  per-source Access groups, a bounded live canary, and the post-preview
  governance roadmap.
- Document the customer credential boundary, no-telemetry runtime, and
  identifier-free hosted-installer analytics.
- Add public-source, license, history, and clean-build checks.
- Scope the public-history check to the publishable surface (checked-out
  history, origin refs, and tags) so private-history remotes in a working
  clone no longer fail the gate.
- Build each app once per `npm run check` and add `npm run check:fast` for
  local iteration.
- Warn on local toolchain drift instead of failing every npm command;
  continuous integration still enforces the exact pinned toolchain.
- Group Dependabot version updates into weekly combined pull requests
  (non-major npm updates together; action updates together).
- Extend hosted-installer analytics to a session-scoped funnel (schema v2):
  a page-view event plus an opaque per-session key, country, browser family,
  and page-view referrer host on every event — still with no cookies, no IP
  or raw user-agent storage, and no identifier that outlives the session.
  Self-hosted deployments continue to send nothing.
