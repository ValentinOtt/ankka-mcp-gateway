# Changelog

Notable public product and repository changes are recorded here.

## Unreleased

- State stable-channel availability in the entry-point documentation: the
  README status banner, docs index, self-service availability notice, and
  security-model limitations now describe stable and canary channels under
  the support policy instead of a canary-only preview.
- Correct the release-verification note: published canary releases already
  carry the signing key identity and sanitized verification record, so the
  complete verification check applies to them today.
- Add an opt-in, disposable two-version Worker/Durable Object probe with
  synthetic state, bounded diagnostics, and verified cleanup. It is a platform
  diagnostic, not a gateway release or source-connection acceptance test.
- Add a minimal best-effort support policy: only the newest release of each
  channel receives fixes, no backports, canary as the evaluation channel, and
  stable as a maintainer recommendation rather than an SLA.
- Add documentation-only native provider setup guides to the Sources dashboard,
  with explicit compatibility, read-only grant, and release prerequisites.
  These guides do not create source drafts or approve catalog entries.
- Add an experimental self-hosted MCP v2 reader runtime with fixed provider
  operations, Cloudflare Access JWT validation, bounded outbound reads, and
  credentials held only in the deployment account. Initial API readers cover
  Notion, HubSpot, Zendesk, Gorgias, Search Console domain properties, and GA4;
  live provider and lifecycle qualification remain separate release gates.
- Add an experimental BigQuery reader to that runtime, mirroring the hosted
  BigQuery MCP read tools over Google's REST API with a read-only
  service-account identity, a mandatory dry-run SELECT gate, and a per-query
  maximumBytesBilled budget. The native hosted-endpoint manual-OAuth block is
  unchanged.
- Prepare the initial public preview source for Ankka MCP Gateway.
- Add secret-free configuration validation and deterministic offline planning.
- Add the self-hosted Cloudflare runtime and management dashboard.
- Add the optional fail-closed hosted installer and operation-scoped OAuth
  flow.
- Add signed release, update, rollback, recovery, and receipt-owned removal
  contracts.
- Add exact read-only source allowlists and synthetic end-to-end fixtures.
- Keep the Portal as the single employee authentication layer: newly added
  OAuth-protected sources are connected once by a gateway operator and mapped
  with `on_behalf: false`, while legacy source records remain readable for safe
  lifecycle handling.
- Raise repository-local contracts to a 500-tool bound and add a reproducible
  228-tool OpenAPI fixture, supplemental 224-tool workload and hostile-name
  coverage, simulated management lifecycle coverage, and searchable dashboard
  review.
- Add deterministic GET-only OpenAPI allowlist generation with check mode and
  an optional exact reviewed manifest for individually bound non-GET reads and
  wrapper-local synthetic tools; no method-wide non-GET switch is accepted.
- Add a signed, exact control-plane-origin contract and an unsupported
  first-party Cloudflare dogfood runbook covering two create-only releases,
  install, update, rollback, recovery, receipt-bound removal, and exact cleanup;
  live qualification remains pending.
- Document operator-owned audit logging with a minimal source-Worker fallback,
  large-source Code Mode qualification with an exact live-catalogue gate,
  per-source Access groups, a bounded live canary, and the post-preview
  governance roadmap.
- Document the source-credential custody boundary, no-telemetry runtime, and
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
