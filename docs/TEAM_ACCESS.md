# Team access: native source audiences

Status: implementation candidate, not yet deployed or live-qualified. The
Worker includes customer-local permission saves, policy updates, verification,
and recovery. Do not treat local tests as proof of Cloudflare enforcement.
The default-deny onboarding candidate restores adding sources without granting
them to existing team members. Release and live acceptance checks below remain
required; this document does not assert a deployment. Published v19 gateways
still pause new-source installation until a compatible signed update is applied.

**New sources start denied:** resource installation does not grant anyone source
access. Complete the upstream operator connection in Cloudflare, then explicitly
assign the installed source in Team. See [first-source qualification](FIRST_SOURCE_ONBOARDING.md).

An administrator edits the complete roster and source assignments, then clicks
**Save** once. The dashboard sends the batch to its own Worker; the Worker
updates and verifies the receipt-owned Cloudflare Access policies. Team saves
do not contact `deploy.ankka.ai`, request installer OAuth, or enable a temporary
`workers.dev` route. Cloudflare continues enforcing access at the Portal and
source boundary.

The read-only view reports saved installation configuration, not a fresh
Cloudflare policy read. It uses the runtime administrator list separately from
the saved source audience. Changes made directly in Cloudflare are not reflected
in this view.

## Try the local preview

Run `VITE_GATEWAY_UI_PREVIEW=1 npm run dev:admin`, then open `/team`.
The preview uses synthetic identities only and never changes Cloudflare.
Use `/team?preview=team-readonly` to inspect the unavailable state and
`/team?preview=team-recovery` to inspect a
recorded partial change. Production requests cannot enable editing with an
environment variable or request field.

## Remaining release gates

- Verify default-deny source creation at the dashboard, authenticated API,
  Durable Object, and signed source-action entrypoints. Old source actions
  cannot silently acquire the new authorization profile.
- Keep automatic teardown disabled once a native policy write or new-profile
  source creation may have happened. The original ownership receipt is immutable;
  this release does not reinterpret its original audience as deletion authority.
- Preserve the currently published installer fixes, review the Worker payload,
  and update its release checksum through the normal release gate. Unrelated
  unfinished dashboard or connector changes are not part of this release.
- Pass the full repository checks and the two-person live acceptance checks
  below before enabling permission editing. No live permissions are changed by
  this draft.
- Review and approve the new standing credential separately. A normal update
  cannot create it. Follow the migration steps below before provisioning it.

The native-permissions slice manages who may connect to your Gateway
and which installed MCP sources each person may use. It projects exact email
audiences into Cloudflare Access. It does not introduce roles, a policy language,
or per-person upstream credentials. The following rules describe the required
projection for existing sources.

## Scope

- Runtime gateway administrators remain administrators and must remain in the
  team. This interface cannot transfer ownership or change administrator rights.
- Each person explicitly receives zero or more installed sources. Joining the
  team does not grant all sources. Newly installed sources start with no
  assignments, including for administrators. An explicit Team save is needed
  after installation; first opening Team cannot add implicit grants.
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

## Customer-owned management credential

The optional Worker secret is named `ANKKA_TEAM_MANAGEMENT_TOKEN`. It must be a
distinct Cloudflare API token created by your administrator for this purpose.
Never use an installer OAuth grant, a source credential, or an inbound Access
token. An Access login authenticates the administrator; it is not authority to
write Cloudflare policies.

The minimum documented permissions for the current implementation, reviewed
against Cloudflare's API reference on 2026-08-30, are:

| Account permission | Required calls |
| --- | --- |
| **Access: Apps and Policies — Edit** (API name **Write**) | List Access applications, read each owned application, list its complete policy set, and update its exact owned policy. Write also authorizes those reads; a separate Read grant is unnecessary. |
| **MCP Portals — Read** | Read the exact Portal and its configured source mappings before and after policy changes. Portal Write is unnecessary. |

Restrict both account permissions to **one specific account: your gateway's
account**. No Workers, DNS, account-settings, memberships, user-details,
source-OAuth, token-management, or session-revocation permission is needed by
Team execution. The administrator's separate ability to configure a Worker
secret is not permission to add to this runtime token.

Cloudflare documents token resource scopes at the account, zone, and user level;
it does not document per-Access-policy isolation for this permission. Treat this
token as broader authority to administer Access applications and policies in
the selected account, including unrelated applications. The Worker's exact
receipt and policy checks narrow its use in this implementation; they do not
narrow what a stolen token could do. Do not create the token unless you accept
that standing authority. The documented minimum still requires live validation;
do not silently add broader permissions if a provider call fails.

Sources: [policy update](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/subresources/policies/methods/update/),
[application list](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/list/),
[application detail](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/get/),
[complete policy list](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/subresources/policies/methods/list/),
[Portal detail](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/ai_controls/subresources/mcp/subresources/portals/methods/read/),
[permission groups](https://developers.cloudflare.com/fundamentals/api/reference/permissions/),
[token resource scopes](https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/).

### Provision, rotate, and revoke directly in Cloudflare

Perform these steps yourself in Cloudflare after approving the compatible
release and standing authority. Do not give the token to Ankka, an assistant,
the installer, a support ticket, or the gateway dashboard.

1. In Cloudflare's API Tokens page, create a custom API token with only the two
   permissions above and only the gateway's account. Choose an appropriate
   expiry and keep any recovery copy in your own secret manager. Do not use a
   Global API key or place the value in a repository, shell argument, URL,
   environment file, screenshot, or deployment output.
2. In **Workers & Pages**, select the exact gateway Worker, then **Settings →
   Variables and Secrets → Add**. Choose **Secret**, name it
   `ANKKA_TEAM_MANAGEMENT_TOKEN`, and paste the value directly into Cloudflare.
   Select **Deploy**. This changes the Worker version and is a separate,
   explicitly approved customer operation.
3. Reopen Team. Its configuration status does not prove that the token is valid;
   Save performs the required provider verification. A missing, expired, revoked,
   or under-permissioned token stops the operation and retains recovery state.
   There is no fallback to hosted OAuth.
4. To rotate, create a replacement with the same minimum permissions, replace
   this one Secret in Cloudflare, verify the deployed secret binding and a
   reviewed Team operation, then revoke the old token in Cloudflare. If exposure
   is suspected, revoke first and accept a temporary Team editing outage. Never
   restore an older Worker version to restore a token.
5. To disable standing management authority, revoke/delete the token in
   Cloudflare's API Tokens page and remove this Secret from the Worker. Removing
   only the binding does not revoke the token or erase it from historical Worker
   versions. Revocation stops further Team writes; it does not undo already saved
   policies, terminate Portal sessions, or clear an uncertain operation.

The gateway returns only fixed status and error codes, never the credential or
raw provider errors. Do not use token-printing diagnostic commands or share raw
provider responses. See Cloudflare's [token creation](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)
and [Worker secret instructions](https://developers.cloudflare.com/workers/configuration/secrets/).

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
can be canceled. The management credential remains in the Worker environment
and request-local execution; neither it nor the roster is sent to Ankka.

Automatic teardown becomes unavailable after the first policy write or
new-profile source creation is armed.
It stays unavailable until a later compatible release explicitly supports the
changed audience. Rollback to older runtimes is also refused after that point;
rolling back Worker code would not roll back Durable Object data or Access
policies. Simply viewing Team or applying a no-op does not set this restriction.

Default-deny onboarding does not rewrite existing policies, credentials, tool
allowlists, or ownership receipts. Existing legacy source actions cannot be
replayed as new-profile actions. Read/status and safe cancellation remain
available where the server permits them. An interrupted legacy installation
with a pending or possibly applied write requires reviewed recovery; this
release does not discard its journal or claim it was rolled back.

Source creation still uses its own short-lived installer OAuth flow. Team saves
continue to use only the customer-local credential. New-profile source creation
raises the same conservative runtime floor and teardown restriction before its
first provider mutation; discovery, draft saves, and action review do not do so.

## Migration from the v16 OAuth flow

`gateway-v0.1.16` does not have this credential contract. Its code-only updater
cannot silently add a secret, and its exact release-contract validation does
not accept this changed binding contract. A retained Team proposal also blocks
ordinary lifecycle operations. Do not bypass those checks or delete pending
state to make an update proceed.

Follow the [signed bridge upgrade procedure](TEAM_UPGRADE.md): apply an
explicitly approved legacy-contract bridge through the ordinary updater, then
apply the customer-local Team release through that same updater. The bridge
recognizes exactly the legacy and reviewed optional-secret contracts; it does
not provision a credential or activate customer-local Team saves. Both actual
update completions preserve the existing Durable Object and maintain its
release bookkeeping. Do not replace this sequence with a direct Worker deploy,
delete `ankka-mcp-gateway/runtime-updates/v1`, or rewrite its `current` tuple.

Before the first update, verify the installed bytes, current policies, and
pending proposal's journal. Only the administrator's explicit normal
cancellation may resolve a provably unstarted proposal for this procedure.
Cancellation retains the action; it is not deletion or a lifecycle bypass.
An armed, partial, or uncertain proposal blocks this upgrade path and must be
reconciled through its existing recovery flow. A browser-blocked callback does
not prove that nothing changed.

After both updates, verify their installed artifacts, completed action records,
public status, unchanged source configuration, and disabled temporary routes.
Team must fail closed while the credential is absent. Provision the separate
secret only after approving its standing authority, then review and re-enter
any canceled proposal. Never replay an old OAuth link.

The customer-local release's hosted installer rejects new and already-issued
legacy Team OAuth handoffs before exchanging a code; the relay and new Worker
reject legacy Team grant submissions too. No old installer grant is retained or
converted into the new secret. Existing installer grants from other actions
keep their bounded revocation and discard behavior. This release also includes the separately
reviewed [updater redirect fix](UPDATER_REDIRECT_FIX.md).

After migration, compatible forward code updates preserve the optional secret
without reading its value or provisioning it. Rollback is refused when either
the current or target version carries this secret, so it cannot resurrect old
authority. Existing exact-binding teardown restrictions remain; deleting the
secret or revoking the token does not restore automatic teardown after an armed
Team write. Any removal or broader migration needs its own review.

Do not rotate or remove the secret, or change Worker deployments directly,
while an update is running. The updater rechecks the deployment before staging
and activation and after its final health probe, and refuses automatic
compensation over an observed unrelated
deployment. The provider deployment calls used here have no atomic
compare-and-swap guard: a change between the last read and write can still race.
Coordinate these customer operations and review uncertain outcomes before retrying.

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
4. An existing source with nobody assigned denies everyone. A newly installed
   source also starts denied, before Portal attachment and before any Team read.
   Old signed handoffs cannot bypass this profile. Verify one-time operator
   authentication while the native audience is empty, then an explicit Team
   grant. Existing shared allowlists and `on_behalf: false` remain unchanged.
5. Conflicting revisions, extra policies, groups, and unrecognized provider
   settings fail closed without overwriting Cloudflare configuration.
6. One Save applies the whole batch using only the customer dashboard and
   Cloudflare API. Record sanitized network evidence that no Team-save request
   reaches Ankka and no temporary `workers.dev` route is enabled.
7. Missing/revoked credentials and partial provider failures retain the exact
   proposal and safe recovery journal without exposing secrets. Compatible
   updates preserve the secret; unreviewed rollback and teardown remain blocked.

This work does not activate BLS write authority or change its approval gate.

References: [MCP Portal policies and tool controls](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/),
[Access policies](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/),
[managed OAuth refresh behavior](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/),
[Access session revocation](https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/).
