# Changelog

Notable public product and repository changes are recorded here.

## Unreleased

- Wait for the browser to reach a new workers.dev address securely before
  releasing the one-time setup handoff. The installer retries temporary TLS
  and connection failures on its progress page, verifies the expected Worker,
  and continues automatically once ready without requiring a manual reload.

- Allow the first Cloudflare approval to deploy gateway setup without a custom
  domain. Accounts with no active domains see a guide on their setup Worker,
  with example addresses and links to Cloudflare. Final gateway configuration
  still requires an active domain from the approved account.

- Support the Google-hosted BigQuery MCP bridge as a manually deployed,
  self-hosted source. Explicit `allowQueries: true` enables bounded read-only
  SQL with Google IAM controlling data access; existing deployments keep the
  constant connectivity probe. Query-byte ceilings are optional. Qualify useful
  aggregates, excluded-table denial, read-only enforcement, and Claude Desktop
  session continuity and reconnection. Link the setup guide from the dashboard
  and document bridge updates, rotation, and removal.

- Connect Settings to automated removal with two temporary Cloudflare approvals.
  The gateway verifies and removes its receipt-owned Portal and source resources;
  a signed handoff lets the hosted finalizer remove management resources, storage,
  and the Worker. Both phases retain progress for fresh-consent recovery after an
  interrupted request. Foreign dependencies stop deletion and unresolved grant
  revocation remains visible. Disposable live qualification is still required.

- Fetch an approved update or rollback release by its exact version and artifact
  digest, so moving the release channel no longer makes rollback unavailable.
  Serve retained signed releases from the existing bucket without a session or
  grant; keep the reviewed channel, origin, and signing key fixed and preserve
  runtime compatibility checks. Missing or invalid bytes stop before upload.

- Add an opt-in, credential-free BigQuery MCP capability probe with bounded
  discovery and fixed diagnostics. Record the hosted query-cost limitation and
  distinguish fresh authorization, refreshed grants, and Portal-wide revocation.
  Record Claude Desktop connectivity, session lifetime, and reconnection checks,
  plus a separate real-Google REST query-budget test. That initial qualification
  kept general hosted SQL disabled.

- Add ChatGPT and Cursor web OAuth callback defaults to newly created Portals
  alongside Claude. ChatGPT's variable callback is limited to its documented
  connector OAuth path. Keep local callbacks, existing Portal settings, and
  receipt hashes compatible; document manual additions and client qualification.

- Update the transitive `qs` dependency from 6.15.3 to 6.16.0 to resolve two
  upstream parsing and denial-of-service advisories. Existing dependency ranges
  and toolchain pins are unchanged.

- Accept Cloudflare One-time PIN providers with the empty name returned by the
  dashboard, so adding email-code login does not block installation. Document
  the Portal login-method prerequisite for team members outside the Cloudflare
  account; Portal and source allow rules remain separate requirements.

- Allow Claude's exact hosted OAuth callback when creating a Gateway Portal,
  including through the installer. Local MCP clients retain localhost and
  loopback support. Existing Portal settings and installation receipt hashes
  remain unchanged; older Portals can add the callback in Cloudflare.
- Recognize the runtime's complete source-installation receipt after a
  successful apply. The return notice now agrees with the verified action
  status instead of reporting `apply_response_invalid`; incomplete or
  mismatched receipts remain rejected.
- Add an initial experimental self-hosted bridge to Google's hosted BigQuery MCP.
  It exposes dataset-scoped table listing and metadata plus the exact constant
  query `SELECT 1 AS bridge_ok`. General SQL was initially disabled pending
  qualification; the existing budget-capped REST reader is unchanged. The setup
  guide covers direct secret configuration, the operator callback, and Portal checks.
- Pause source installation before Portal attachment when Cloudflare still
  needs operator authentication, tool synchronization, or a missing selected
  tool. The dashboard links to the recorded server and explains the next step.
  A completed connection check permits immediate fresh-consent renewal with
  the same receipts; uncertain writes still wait for the old approval to expire.
- Send identical `id` and `server_id` values in portal server mappings to
  accommodate Cloudflare's differing guide and API schema. Retained receipt
  hashes remain unchanged. Provider failures can name a field from a fixed
  validation vocabulary without returning or retaining provider message text.
- Let the initiating administrator renew an expired source installation with
  fresh Cloudflare consent. Renewal rotates the action key, retains the same
  journal and receipts, and resumes through the existing ownership checks.
  Unacknowledged Access application creation, legacy policy profiles, changed
  drafts, and conflicting lifecycle work remain blocked.
- Authorize source installations on the gateway itself. The dashboard's
  "Authorize and apply" handoff now opens the gateway's own
  `/__ankka/operation` page, which asks Cloudflare for a one-time `source-add`
  grant (Access applications and MCP portals only) through the public OAuth
  client and callback certified at install, applies the prepared action in
  place, and revokes the grant. The retired hosted `/manage` page is no
  longer navigated to, so source installs work again on two-stage gateways.
- Update the gateway from the gateway itself. A runtime update handoff opens
  the same operation page, asks for a one-time `upgrade` grant (Workers
  scripts only), downloads the pinned release from the control plane's new
  `/api/releases/<channel>/files/<path>` route, verifies every file against
  the signed manifest with the update key the install was made with, uploads
  the new version with the existing secrets inherited, and lets the new
  version's alarm finish the journal with a `finalize` command that proves
  the target release by its own bindings. Rollback and teardown handoffs are
  not yet served by this route.
- Name why a gateway-local operation stopped: the dashboard return carries a
  bounded reason word (grant, apply, or update stage) next to the result.
- Bind an operation grant to the installed account by reading one of that
  account's resources under the grant's own scope (the MCP portals for a
  source grant, the gateway Worker for an update) instead of listing
  accounts, which an operation grant cannot see. The first gateway-local
  source authorization had stopped with `grant_account_ambiguous_accounts_0`.
- Let the runtime-update journal follow a release the Worker received outside
  an action (an operator-run update or a Cloudflare-side rollback): once no
  action is in flight, the recorded current release becomes the rollback
  reference and the running release is current, so the next update no longer
  stops with `runtime_action_conflict`.
- Read a source's Access application back by id after creating it. Cloudflare
  stores an MCP-type application (no hostname of its own) with the account,
  and the zone listing never shows it, so the gateway created the application
  and then failed to see it, leaving the first real source installation in
  recovery-required after its MCP server and application existed. A baseline
  without a known id still consults the listings, the account listing
  included where the grant can read it; the writes stay on the zone paths
  the grant covers, and the portal application and both policies keep their
  listings so a competing policy is still seen.
- Clear a gateway-local operation's attempt record before a runtime update
  uploads the new version. The replaced version could not clear it afterwards,
  so every other operation on that gateway answered `operation_pending` for
  up to ten minutes after an update.
- Name the provider step that stopped a source installation. The apply
  route's rejection now carries the resource kind, the step, the outcome, the
  HTTP status and Cloudflare's numeric code (never provider text), and the
  dashboard's return reason repeats it, so a stalled installation says which
  call failed instead of only "recovery required".
- Retire the legacy hosted installer runtime, its Durable Object, journals,
  executors, management handoffs, and analytics sink. The two-stage runtime
  shipped in gateway-v0.1.21 is the only hosted mutation path.
- The hosted installer records no analytics; the former funnel documentation
  is removed and the architecture and security-model notes now say so.
- Repository references point at `ankka-ai/ankka-mcp-gateway`.

## gateway-v0.1.16 (canary)

- Keep the exact candidate-version override on the external update probe, but
  remove it before forwarding the authenticated probe to the retained Durable
  Object. Release, artifact, signature, expiry, and saved-action checks remain
  required; probe success still requires an explicit ready response.
- Preserve the v0.1.15 dashboard and existing-source-only Team permissions.
  New-source creation, including onboarding an empty gateway, remains paused.
  Administrators stay fixed, source write tools remain disabled, and armed Team
  changes still block automatic teardown and rollback to older releases.

## Unreleased

- Restore source onboarding with an exact deny-Everyone initial policy and no
  implicit Team assignments. Operator connection and a later explicit Team
  grant remain separate steps. Legacy source actions cannot bypass the new
  profile; new-profile creation conservatively disables automatic teardown
  and older-runtime rollback before its first provider mutation. Deployment
  and live shared-auth/permission qualification remain required.
- Show the runtime-update loader immediately after OAuth authorization, emit
  a terminal result only after execution and grant cleanup, and retry only an
  exact active-version propagation mismatch within a shared ten-second bound.
  Missing or malformed completion never means success or starts another update.
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
