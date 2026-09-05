# Pending source installations

This describes the source-action status and recovery contract. It is not a
deployment claim or authorization to recover an existing live action.

The Sources page reads the retained action journal from the authenticated
customer gateway. Reloading, opening another tab, and returning from consent
do not require a saved authorization URL. A source installation and a gateway
update are separate actions; a completed update does not establish the result
of a later source installation.

| Displayed state | Meaning and available next step |
| --- | --- |
| Waiting for Cloudflare | The existing authorization is pending. Complete consent in its original tab, or cancel if the server permits it. |
| Applying and verifying | The gateway has claimed execution. Wait and check status; cancellation is unavailable. |
| Installation completed | The journal records verified completion. The page refreshes installed sources. This does not itself grant member access or verify upstream authentication. |
| Authorization expired before work began | The retained journal proves execution did not start. Its initiating administrator can cancel, then start a fresh authorization from the saved draft. |
| Authorization closed | The attempt has ended without retained write evidence. Review the saved draft before a new authorization. |
| Recovery required | The journal is retained. After the previous approval expires, its initiating administrator can renew consent when the gateway can safely reconcile the recorded resources. Otherwise review ownership in Cloudflare. |
| Connect your source | Authenticate the recorded server in Cloudflare. Keep Require user auth off, then renew consent after its status becomes Ready. |
| Sync source tools | Sync capabilities in Cloudflare and resolve any connection error before renewing consent. |
| Review source tools | The synced catalogue lacks a selected tool. Restore the reviewed tools upstream before resuming; the saved selection is never broadened. |

The page checks a blocking action every five seconds for at most 60 automatic
checks. It then leaves the status and **Check status** control visible. A manual
check or returning to the tab reads current state without replaying consent.
Pausing checks does not cancel execution. Status-read failures keep Apply
disabled until status can be read again.

## Authenticated protocol

`GET /api/source-actions` returns only safe summaries and an optional blocking
action pointer. Each summary includes the existing action ID, source ID,
recorded status, expiry and fixed failure code, plus its issue time, derived
display state and actor-specific `canCancel` and `canRenew`. Older responses may
omit `canRenew`, which clients treat as unavailable. The pointer identifies a source,
runtime, teardown or Team action without exposing the initiating identity,
Cloudflare resource identifiers, authorization URL, action key or grant.
An intentional connection pause also includes an optional `connectionUrl` to
the recorded server's configuration page on `dash.cloudflare.com`. This link
contains the installed account and server identifiers, but no OAuth state,
credential, or permission to administer the server. Cloudflare authenticates
the operator independently. Clients validate the exact dashboard URL shape.
Collection reads are available during execution; mutations remain serialized.
The existing by-ID GET and DELETE response shapes remain unchanged.

Source preparation retains the existing `source_action_conflict` error code and
adds a bounded reason when known: `draft_changed`, `source_pending`,
`lifecycle_pending`, or `recovery_required`. A safe action pointer accompanies
action conflicts. Older clients can continue to use the original error code;
new clients can distinguish revision conflicts from an action that needs review.
WebMCP exposes the same collection and cancellation checks.

Cancellation is a separate authenticated, same-origin mutation. The server
rechecks the initiating administrator, execution status and all retained write
evidence when processing it. It also permits cancellation after expiry when
execution provably never started. If execution wins the race, cancellation
cannot erase it. If cancellation wins, the old callback cannot start execution.
The user must separately authorize any replacement attempt.

Expiry never clears an armed write, resource receipt, Portal update or uncertain
execution. An absent resource in the Cloudflare dashboard does not prove that a
request was never armed or sent. Credentials remain request-local under the existing
one-action contract.

## Renewing a recorded installation

**Renew consent and resume** posts to
`/api/source-actions/<actionId>/renew` with the saved source ID and revision.
The gateway requires the initiating administrator, a same-origin request, an
expired approval, the current default-deny source profile, an unchanged source,
and no other blocking lifecycle action. The serialized check preserves the
action ID, source hash, resource receipts, pending write and Portal desired hash.
It issues a new action key and ten-minute approval window; the old key cannot
be used again. Only the key hash and a renewal timestamp are saved. The runtime
compatibility floor advances before saving the renewed journal.

An intentional connection pause can renew immediately: all three source
receipts must be retained, with no pending resource or Portal write. The
executor first verifies the Portal baseline, then reads the server's
authentication status and synced catalogue. It pauses before Portal attachment
if authentication is required, synchronization is incomplete, or an exact
selected tool is missing. These fixed failure codes use the existing retained
`recovery_required` journal status; only their displayed guidance differs.
Unknown outcomes and other recovery failures still wait for approval expiry.
Renewal does not authenticate the upstream or retain its credentials.

The browser completes a fresh `source-add` consent through the same gateway
operation page. The executor verifies every retained resource, reconciles a
recorded pending write, and accepts only the recorded Portal baseline or exact
desired mapping before continuing. It never grants Team access as part of
recovery. Concurrent renewals cannot create two valid approval windows, and
cancellation still cannot erase retained write evidence.

A source Access application whose creation was armed but returned no provider
ID remains blocked. Cloudflare stores these applications at account level,
while the operation grant's zone listing can omit them. That listing cannot
prove absence, so renewal must not create a second application. Legacy source
policy profiles and drift also require separate review. Denying or abandoning
a renewed consent retains the journal; check status after its approval expires
to renew again when eligible.

## Authorization on the gateway

Preparing a source installation returns a handoff to the gateway's own
`/__ankka/operation` page on the management origin, with the one-time action
key in the URL fragment. That page posts the fragment to the gateway, which
checks the claim against its own identity and the retained action, records
one attempt (identifiers, a state hash, and expiries only), and starts a
Cloudflare consent for exactly the `source-add` scopes through the public
OAuth client and callback that the ownership trust certified at install. The
PKCE verifier and the action key travel only in one HttpOnly cookie.

On the callback the gateway exchanges the code itself, confirms the grant
reaches the installed account by reading that account's MCP portals (an
operation grant cannot list accounts), submits the HMAC-signed apply claim to its own action route in
process, revokes the grant, and sends the browser back to
`/sources?sourceAction=<id>&sourceActionResult=<result>`. The result is
`applied`, `denied` (consent refused; the page cancels the untouched action),
`failed` (the gateway refused or could not finish the apply; read the action
status), or `revocation_unconfirmed` (installed, but the temporary grant could
not be confirmed revoked), with a bounded `sourceActionReason` word (a grant
error, the apply route's error code, or an update stage) when the gateway can
name what stopped it. No control-plane page, token, or callback is involved;
Ankka's hosted installer never sees the grant. Runtime updates and rollbacks
use the same route with their respective `upgrade` and `rollback` operations;
both request Workers Scripts Write. Rollback selects the exact retained release
(see [Updates](UPDATES.md)). Gateway removal starts at
`/__ankka/operation/teardown` and uses two separate approvals: receipt-owned
dependencies first, then the management resources and Worker. See
[removal limits](CUSTOMER_SELF_SERVICE.md#removing-a-gateway).

## Operational limits and release review

Uncertain ownership and drift remain blocked for separate review. Renewal adds
no automatic cleanup or permanent management credentials. It does not change
source allowlists, default-deny installation,
Team permissions or the separation between administrators and approved members.
While Team editing is deferred, manage the approved members' shared read-only
access directly in Cloudflare under a separate operational authorization.

Before releasing, run the full pinned-toolchain `npm run check` on the integrated
candidate, then use the existing reviewed release process. Resolve overlapping
dashboard or lifecycle changes by retaining both their checks and this source
journal boundary. Signing, publication, deployment, live policy changes and
live action recovery require their own authorization. Local tests and synthetic
previews are not evidence that a customer's pending action has recovered.
