# Changelog

All notable changes will be recorded in this file. The project will use
Semantic Versioning once its first deployable preview is released.

## Unreleased

- Establish **Ankka MCP Gateway** as the canonical product name and
  `ankka-mcp-gateway` as its pre-release receipt, storage, Worker-tag, release,
  schema, package, and SBOM identity.
- Move the hosted MCP Gateway installer source into this release-candidate
  repository as `apps/installer`, while keeping credentials, signing authority,
  generated releases, and production deployment authority external.
- Establish the customer-owned product, security, and licensing boundary.
- Add a secret-free versioned gateway configuration contract and validator.
- Add a deterministic, offline Cloudflare resource planner with prerequisite
  blockers, exact tool mappings, ownership-aware reconciliation, and a
  non-authoritative uninstall preview.
- Add human and JSON `plan` CLI output with synthetic examples and regression
  coverage for collisions, redaction, and stable IDs.
- Separate process-local Access identities from observed state and add strict,
  kind-specific provider locators.
- Add a fixed-origin, fetch-injected Cloudflare REST client and credential-
  scrubbing observed-state reader.
- Add checksum-protected installation receipts, atomic local persistence, and
  approval-bound apply, recovery, prune, status, and uninstall orchestration.
- Bind prune to a separate exact approval and add journaled repair for missing
  receipt-owned resources without discarding stale uninstall authority.
- Add inspectable, fail-closed receipt locks with explicit stale-lock recovery.
- Add an identifier-free, zero-write Cloudflare canary preflight with explicit
  target binding and exact-hostname DNS reads.
- Add a minimal public-readiness CI check.
- Add customer-verified signed runtime updates with exact candidate probing,
  one-version code rollback, fresh per-action Cloudflare OAuth, customer-owned
  progress state, dashboard controls, and equivalent WebMCP tools.
- Add a reviewed GitHub Release mirror that tags the exact source commit and
  publishes the signed envelope, sanitized public verification evidence and a
  source-bound CycloneDX SBOM only after immutable R2 publication succeeds.
- Simplify hosted onboarding to create an empty MCP Portal, move source setup
  into the customer portal, and show one animated live deployment stage.
- Add clean-install CI, pinned GitHub Actions, public-only CodeQL, Dependabot,
  and checks over every reachable Git history blob.
- Add a fixed-output live preflight for Cloudflare's OAuth scope catalogue and
  bind its required IDs to the reviewed runtime manifest.
- Bind release signatures to an exact publication channel with the versioned
  release-envelope protocol, reject legacy and cross-channel replay, and mirror
  the exact source-bound production SBOM with every GitHub Release.
- Add crash-safe returning-customer teardown with durable recovery authority,
  strict receipt ownership, reverse dependency ordering, replay rejection, and
  a bounded recovery window.
- Retire unsafe broad mutation entrypoints, keep checked-in deployments
  fail-closed, and require exact Cloudflare Access protection for private
  installer canaries.
- Bound authenticated session polling before Durable Object lookup with a
  purpose-separated, fail-closed Worker-native rate limit.
- Keep Cloudflare Network Error Logging on for the Ankka-owned hosted zone and
  add a documented, default, identifier-free hosted-installer funnel in a
  dedicated Analytics Engine dataset, while preserving the tested
  no-Ankka-telemetry boundary for every customer-deployed gateway variant.
- Pin the Node/npm/Wrangler toolchain, generate deterministic third-party
  notices, and verify public source, history, license, and release boundaries in
  CI.
