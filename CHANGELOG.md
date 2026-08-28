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
