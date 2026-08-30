# Team access: native source audiences

Status: implementation candidate, not yet deployed or live-qualified. The
Worker includes native permission preparation, policy updates, verification,
and recovery. Do not treat local tests as proof of Cloudflare enforcement.
This release deliberately pauses adding sources to an installed Gateway. Its
native permissions apply only to existing sources. Release and live acceptance
checks below remain required; this document does not assert a deployment.

**Existing-source preview only:** a fresh empty Gateway has no supported path
to add its first source in this release. Do not use it for new-source onboarding
or publish getting-started instructions that promise that workflow. Existing
installed sources continue to work while their team permissions are managed.

The read-only view reports saved installation configuration, not a fresh
Cloudflare policy read. It uses the runtime administrator list separately from
the saved source audience. Changes made directly in Cloudflare are not reflected
in this view.

## Try the local preview

Run `VITE_GATEWAY_UI_PREVIEW=1 npm run dev:admin`, then open `/team`.
The preview uses synthetic identities only and never follows the permission
authorization link to the real installer. Use `/team?preview=team-readonly` to
inspect the release-gated state and `/team?preview=team-recovery` to inspect a
recorded partial change. Production requests cannot enable editing with an
environment variable or request field.

## Remaining release gates

- Verify the temporary source-installation pause at the dashboard, authenticated
  API, Durable Object, and previously prepared signed source-action entrypoints.
  No request field or environment variable can lift this release restriction.
- Keep automatic teardown disabled once a native policy write may have
  happened. The original ownership receipt is immutable; this release does
  not reinterpret its original audience as deletion authority.
- Preserve the currently published installer fixes, review the Worker payload,
  and update its release checksum through the normal release gate. Unrelated
  unfinished dashboard or connector changes are not part of this release.
- Pass the full repository checks and the two-person live acceptance checks
  below before enabling permission editing. No live permissions are changed by
  this draft.

The native-permissions slice manages who may connect to your Gateway
and which installed MCP sources each person may use. It projects exact email
audiences into Cloudflare Access. It does not introduce roles, a policy language,
or per-person upstream credentials. The following rules describe the required
projection for existing sources.

## Scope

- Runtime gateway administrators remain administrators and must remain in the
  team. This interface cannot transfer ownership or change administrator rights.
- Each person explicitly receives zero or more installed sources. Joining the
  team does not grant all sources. Adding a source is temporarily unavailable:
  neither a new draft nor an old prepared installation can create it. A future
  release must establish default-deny creation before restoring this workflow.
- Tools are an exact **shared source allowlist**, not per-person tool settings.
  Every person granted a source receives that same selected toolset.
- An empty source audience becomes `decision: "deny"` with
  `include: [{"everyone": {}}]`. It never becomes an empty Allow rule or an
  Allow-everyone rule.
- The current limits are 51 people, 32 sources, and 500 selected tools per
  source. This preserves the runtime's existing bounds.

Source Access policies apply to the human Portal identity independently of
`on_behalf: false`. The Portal may continue using its stored operator credential;
the source credential is not an administrator identity for this dashboard.
Sources must remain protected against direct URL access outside the Portal.

## Pure module contract

`src/team-access.js` reexports the pure functions from the shipped Worker, so
the runtime and unit tests use one canonical implementation. These functions
perform no network, storage, credential handling, or logging. They export:

- `normalizeTeamAccessRequest(value, {revision, adminEmails, sources})`: validates
  `{schemaVersion: 1, expectedRevision, members: [{email, sourceIds}]}`. It copies,
  normalizes, sorts, and deeply freezes the result, rejecting unknown fields,
  duplicate identities or assignments, missing administrators, and stale revisions.
- `teamPolicy(emails, name)`: produces the exact writable email-Allow or
  deny-Everyone policy body.
- `teamPolicyMatches(observed, expected, policyId)`: checks a provider response
  against an owned policy ID and exact audience. It accepts neutral provider
  metadata but refuses groups, extra selectors, exclusions, requirements,
  non-default authorization settings, and unfamiliar fields. Expected precedence,
  if supplied, must match.
- `planTeamAccessChange(value, context)`: uses the same request context plus
  `currentMembers`, `portalTarget`, and `sourceTargets` to derive deterministic
  before/after policies. Targets contain `applicationId`, `policyId`, and
  `policyName`; source targets also contain `sourceId`. Every installed source
  must have exactly one distinct target. The result contains `nextState`, all
  target `policies` for complete preflight, changed `policyChanges`, and count-only
  `summary`. Both policy lists use stable Portal-then-source-ID ordering. A valid
  request advances the revision by one; a no-op has no policy writes.

Each source capability is exactly `{id, label, enabledTools, installed}`.
Provider IDs are customer-side execution inputs and never belong in public
fixtures with real values, logs, or installer analytics.

The module is not the authorization or mutation entrypoint. Integration must
authenticate a runtime administrator, read the latest stored revision, verify
every owned application and its **complete single-policy list**, match the
expected before policy, and perform scoped updates. A known policy ID alone
cannot prove there are no competing Allow or Bypass policies. Group-based or
otherwise unfamiliar existing policies require review rather than automatic
conversion. Mutable team state must remain separate from the original deployment
receipt and its immutable audience. Lifecycle compatibility must be reviewed
before activation. This slice refuses automatic teardown after a policy write
may have occurred, including previously prepared teardown handoffs. It does
not broaden destructive lifecycle authority. Do not claim that the pure
module itself persists or applies changes.

## Recovery and lifecycle limits

The Worker records the exact proposed roster and a per-policy write intent in
your Durable Object before sending a policy update. A failed or uncertain
request retains that proposal for fresh readback and recovery; it does not
claim that Cloudflare rolled changes back. Only a definitely unstarted action
can be canceled. Grants remain request-local and the roster is not included in
the hosted installer's handoff.

Automatic teardown becomes unavailable after the first policy write is armed.
It stays unavailable until a later compatible release explicitly supports the
changed audience. Rollback to older runtimes is also refused after that point;
rolling back Worker code would not roll back Durable Object data or Access
policies. Simply viewing Team or applying a no-op does not set this restriction.

The source-installation pause does not rewrite stored drafts, pending source
actions, existing policies, credentials, tool allowlists, or ownership receipts.
Read/status and safe cancellation remain available. Previously interrupted
source installations may need a later compatible release to resume; this
release does not discard their recovery records or claim they were rolled back.

## Revocation and acceptance

Access policy edits are not a promise of immediate session termination.
Managed OAuth rechecks policy when refreshing access tokens. Application-token
revocation affects every person in that application; user revocation affects
that person's applications across the account. These are not interchangeable
with a narrowly scoped person/source removal.

Before releasing native permission editing, verify with two synthetic identities:

1. Gateway entry and per-source membership produce the expected effective
   source and tool lists.
2. A denied source cannot be invoked by its exact tool name, including from
   Code Mode. Hiding a list entry alone is not sufficient.
3. Removing access denies new and already-connected sessions within the
   documented/tested propagation window; report that window honestly.
4. An existing source with nobody assigned denies everyone. Adding a source,
   including through an old signed handoff, is refused without provider writes.
   Existing shared tool allowlists and `on_behalf: false` remain unchanged.
5. Conflicting revisions, extra policies, groups, and unrecognized provider
   settings fail closed without overwriting Cloudflare configuration.

This work does not activate BLS write authority or change its approval gate.

References: [MCP Portal policies and tool controls](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/),
[Access policies](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/),
[managed OAuth refresh behavior](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/),
[Access session revocation](https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/).
