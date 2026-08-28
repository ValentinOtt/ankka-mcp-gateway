# First public release checklist

This is the launch ledger for Ankka MCP Gateway. A checked box means the
specific evidence exists; source completeness or a successful earlier canary
does not waive a later gate.

Use the ordered [public-preview cutover](PUBLIC_CUTOVER.md) for external state
changes and rollback. Use [release signing-key operations](SIGNING_KEY_OPERATIONS.md)
for seed custody, backup, loss, compromise, and rotation; this checklist never
authorizes a secret-handling shortcut.

## Evidence already established

- [x] Exact customer payload installed seven receipt-owned resources, converged
  idempotently, served a real employee read-only tool call, uninstalled in
  reverse order, and independently verified zero residue.
- [x] Hosted onboarding exercised Cloudflare discovery OAuth, plan review,
  install OAuth, signed create-only R2 publication, generated canary activation,
  live progress, and a completed customer-owned installation.
- [x] `gateway-v0.1.11` has an immutable private-repository prerelease mirror
  containing only its signed envelope and sanitized verification record. It is
  historical evidence, not a public-release artifact.
- [x] Fresh-install management status and update-channel defects found by that
  run are regression-covered on the current release branch.
- [x] `npm run check` includes publishable-file, reachable-blob, commit-message,
  tag-message, forbidden-output, and high-confidence credential checks.
- [ ] Run those checks against the exact final sanitized root and every ref that
  will be published, and retain the result before pushing or exposing that root.

`gateway-v0.1.11` used a deliberately discarded signing key. It is historical
canary evidence, not updater-capable N and not a stable release candidate.
The later private `gateway-v0.1.12` canary used the legacy schema-1 envelope
that did not cryptographically bind its channel. Its immutable bytes are also
historical evidence only: retire/reinstall that disposable gateway and create
a fresh schema-2, updater-protocol-2 N rather than promoting or reusing it.

## Pre-publication source gates

- [x] Remove private canary locators from the current documentation.
- [ ] Choose a new sanitized history root (or a separate public repository),
  remove all old public refs and source archives, and repeat the exact-locator
  audit before changing repository visibility.
- [ ] Materialize the exact sanitized source on `main`, then complete a green
  clean-install CI run and `npm run check` before making the repository public.
  An intentionally skipped CodeQL job while the repository is private is not a
  CodeQL pass.
- [x] Pin every GitHub Action by reviewed commit SHA. On 2026-08-27 the checked-in
  checkout v7, setup-node v7 and CodeQL v4 SHAs were verified against the
  official GitHub refs.
- [ ] Generate the deterministic CycloneDX SBOM from the exact clean release
  source and lockfile before publication, and retain its checksum for the
  immutable public preview release.
- [x] Keep the checked-in CodeQL workflow public-only with the minimal explicit
  permissions it needs: `contents: read` and `security-events: write`. Review
  its source before publication; do not make paid private-repository GHAS a
  launch prerequisite.

The actual CodeQL analysis is deliberately deferred until the sanitized root is
public. A private-repository skip is expected, carries no security evidence, and
must never be used to authorize stable promotion.

## Retained-key release chain

- [x] Approve retained Ed25519 key `release-2026-08-v1` under local Keychain
  custody. On 2026-08-28 an independently encrypted, operator-controlled
  Bitwarden EU backup was restored through a memory-only verifier; it derived
  public key `X4LMKPjoHbKE0qRGq1uPMxQM8Fj_TG4JJYCC91UObWU`, the restored bytes
  were zeroed, and the one-use vault session was logged out. No private seed or
  vault-item locator is retained as evidence.
- [ ] Build, review, sign and create-only publish updater-capable N from the
  exact sanitized source commit; mirror it as an immutable GitHub prerelease.
- [ ] Exercise the reviewed installer pinned to N only in an approved isolated
  canary environment, then install N into a clean disposable account and make a
  real employee tool call. Keep `deploy.ankka.ai` on its no-Access disabled
  shell throughout this pre-activation proof.
- [ ] Publish N+1 under the same key and prove signed anonymous discovery,
  explicit OAuth update, 0% exact-version probe, 100% activation and a second
  real employee tool call.
- [ ] Prove an intentionally broken candidate compensates to the prior version,
  then prove a healthy update and explicit rollback without rolling back Durable
  Object data.
- [ ] Use the original installer session to remove the updated installation and
  independently verify zero receipt-owned residue.
- [ ] On a second disposable installation, start from a fresh hosted installer
  session, prove zero-write existing-gateway detection, round-trip the
  Access-verified dashboard handoff in the same browser, complete returning
  teardown, and independently verify zero Ankka-managed residue.

## Exposure and promotion

- [x] Implement Worker-native, telemetry-free limits for anonymous session
  creation, authenticated session polling, and state-changing hosted-installer
  API calls; generated active canary configs contain the three fixed bindings
  and active runtime failures are fail-closed.
- [ ] Prove all three rate limits and missing-binding failure on isolated live
  canaries, including exact 429/503 bodies, existing-session reads, callback
  completion, and anonymous signed release discovery.
- [ ] After the isolated retained-key promotion, rollback and uninstall run,
  reverify the OAuth scope catalogue and existing live client-secret pair, and
  confirm the already permanently Public Ankka-owned client still has verified
  `deploy.ankka.ai`, the exact live callback, and the exact ten scopes. Never
  move that callback or substitute the separate isolated-only client.
- [x] Re-read every account- and zone-level Logpush job and prove none can
  capture `deploy.ankka.ai`; retain only the secret-free result. On 2026-08-28
  the complete account inventory contained no jobs and the hosted zone's plan
  exposed no zone Logpush job configuration. The live disabled Worker's logs
  and traces were separately confirmed off; that Worker setting was not used
  as a substitute for the job inventory.
- [x] Confirm Cloudflare Network Error Logging remains enabled for the hosted
  zone. On 2026-08-28 the installer root, callback error, and both release
  channels returned one consistent valid Cloudflare policy. The public record
  documents the provider-owned destination, report fields, seven-day browser
  policy lifetime, request-lifetime IP handling, unspecified derived-data
  retention, and explicit residual-metadata acceptance; no report token or
  provider resource identifier was retained.
- [x] Implement the default hosted-installer funnel as server-authored writes
  to the dedicated `ankka_installer_funnel_v1` Analytics Engine dataset. The
  schema has ten fixed events, public release/channel, fixed outcome/flow, and
  count only; it has no browser ingestion endpoint or identifier dimension and
  sink failure cannot affect installation.
- [ ] Prove the active reviewed deployment has the exact Analytics Engine
  binding and pin-derived labels, the rollback shell has neither, and a live
  query returns only the documented columns/allowlists. Retain the secret-free
  query/result and confirm three-month provider retention; use
  `_sample_interval`-weighted counts.
- [x] Keep the signed customer Worker contract telemetry-off: metrics,
  dependency instrumentation, and observability are disabled for every variant;
  direct upload requires Logpush off and no tail consumers; payload tests reject
  Ankka analytics beacons and application-set `NEL`/`Report-To` headers.
- [ ] With the live host still on the disabled shell, complete a fresh paginated
  Access-app read and require zero whole-host, path-specific, wildcard, or
  destination selector capable of covering `deploy.ankka.ai`. Prove cookie-free
  requests reach the fixed disabled shell without an Access redirect. Do not
  create a temporary private Access gate on the live host; the private Access
  tooling is reserved for separately isolated canaries.
- [ ] Activate the exact reviewed build only after the no-Access disabled-shell
  preflight passes, then immediately run `scripts/edge-gate/verify-public.mjs`
  with the exact reviewed release pin and retained public key. Require zero
  Access applications capable of
  covering the host, exact `mutationsEnabled: true`, a `200` installer root
  whose bytes match the signed manifest, application-reachable callback and
  both release paths, a valid channel-bound Ed25519 descriptor on the active
  channel and no Access redirect.
  Hosted Cloudflare `NEL`/`Report-To` headers are allowed and are not readiness
  evidence. Its session probe must remain `HEAD`, not a state-minting GET.
- [ ] Record the public rollback drill: stop new invitations, finish or
  journal-recover every in-flight receipt-owned action, reconcile provider
  state, deploy the exact disabled shell, and re-prove zero Access coverage.
  Never create or recreate Access on `deploy.ankka.ai` as part of rollback.
- [ ] Test the public wizard from an unrelated fresh Cloudflare account and
  confirm credentials never appear in URLs, retained state, logs or evidence.
- [ ] Publish or expose the sanitized repository only after every
  pre-publication source gate above is green and the final GitHub visibility
  warning has been reviewed.
- [ ] Immediately after the repository is public, manually dispatch CodeQL on
  the exact public `main` commit and require the JavaScript/TypeScript analysis
  to pass. Skipped, queued, cancelled, or failed is not a pass.
- [ ] Re-run the boundary, reachable-history, metadata, forbidden-output, and
  credential checks against the refs actually visible on the public host.
- [ ] After publication, verify private vulnerability reporting, dependency
  alerts, secret scanning/push protection, and CodeQL alerts using the security
  features available to the public repository. Do not treat paid private GHAS
  as a prerequisite for the pre-publication gates.
- [ ] Attach the precomputed CycloneDX SBOM to the first immutable public
  preview release and verify its checksum.
- [ ] Keep the public launch and its releases labeled preview/prerelease, and do
  not promote the stable signed channel, until CodeQL has passed on the exact
  public source commit, an independent security review is complete, and a
  stable support policy is documented in `SECURITY.md`.
- [ ] Only after those preview blockers and every other promotion gate are
  closed, publish the first stable immutable GitHub release from the exact
  reviewed source commit, mark it non-prerelease/Latest, and promote the
  matching signed channel after human review.

Activation, signing and stable promotion remain human-reviewed operations.
