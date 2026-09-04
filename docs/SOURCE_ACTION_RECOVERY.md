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
| Recovery required | Execution or provisioning may be incomplete, uncertain, or still finishing. Keep the journal and review status before separately authorized recovery. |

The page checks a blocking action every five seconds for at most 60 automatic
checks. It then leaves the status and **Check status** control visible. A manual
check or returning to the tab reads current state without replaying consent.
Pausing checks does not cancel execution. Status-read failures keep Apply
disabled until status can be read again.

## Authenticated protocol

`GET /api/source-actions` returns only safe summaries and an optional blocking
action pointer. Each summary includes the existing action ID, source ID,
recorded status, expiry and fixed failure code, plus its issue time, derived
display state and actor-specific `canCancel`. The pointer identifies a source,
runtime, teardown or Team action without exposing the initiating identity,
Cloudflare resource identifiers, authorization URL, action key or grant.
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
request was never armed or sent. There is no Resume feature that reconstructs
an action key or OAuth grant. Credentials remain request-local under the existing
one-action contract.

## Authorization on the gateway

Preparing a source installation returns a handoff to the gateway's own
`/__ankka/operation` page on the management origin, with the one-time action
key in the URL fragment. That page posts the fragment to the gateway, which
checks the claim against its own identity and the retained action, records
one attempt (identifiers, a state hash, and expiries only), and starts a
Cloudflare consent for exactly the `source-add` scopes through the public
OAuth client and callback that the ownership trust certified at install. The
PKCE verifier and the action key travel only in one HttpOnly cookie.

On the callback the gateway exchanges the code itself, checks the grant's
account, submits the HMAC-signed apply claim to its own action route in
process, revokes the grant, and sends the browser back to
`/sources?sourceAction=<id>&sourceActionResult=<result>`. The result is
`applied`, `denied` (consent refused; the page cancels the untouched action),
`failed` (the gateway refused or could not finish the apply; read the action
status), or `revocation_unconfirmed` (installed, but the temporary grant could
not be confirmed revoked), with a bounded `sourceActionReason` word (a grant
error, the apply route's error code, or an update stage) when the gateway can
name what stopped it. No control-plane page, token, or callback is involved;
Ankka's hosted installer never sees the grant. Runtime updates take the same
route with an `upgrade` grant (see [Updates](UPDATES.md)); rollback and
teardown handoffs are not yet served by it.

## Operational limits and release review

Uncertain actions remain blocked for separately reviewed recovery; this change
does not add provider reconciliation, automatic cleanup, or permanent management
credentials. It does not change source allowlists, default-deny installation,
Team permissions or the separation between administrators and approved members.
While Team editing is deferred, manage the approved members' shared read-only
access directly in Cloudflare under a separate operational authorization.

Before releasing, run the full pinned-toolchain `npm run check` on the integrated
candidate, then use the existing reviewed release process. Resolve overlapping
dashboard or lifecycle changes by retaining both their checks and this source
journal boundary. Signing, publication, deployment, live policy changes and
live action recovery require their own authorization. Local tests and synthetic
previews are not evidence that a customer's pending action has recovered.
