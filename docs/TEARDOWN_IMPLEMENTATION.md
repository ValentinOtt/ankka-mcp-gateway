# Automated teardown implementation

Automated teardown is required for the first stable release. This document
tracks the replacement for the retired hosted management flow. It describes
the implemented flow and the live qualification still required before release.

## Implemented boundaries

The current teardown executor has separate internal prepare, proof, and apply
routes. Its action record binds the `receipt_owned` policy interpretation.
Existing hosted teardown handoffs retain their original restrictions and cannot
select the new interpretation.

The executor rederives the immutable installation and source receipts before
using their provider locators. An Access policy can have a different email
assignment, including the supported deny-everyone state, while retaining its
exact marked name and recorded parent. Receipt hashes are never rewritten to
make live policy changes appear original. Applications with an unrecorded
policy, changed destinations, renamed resources, and servers used by another
Portal stop teardown before deletion. The complete graph is checked first;
application policies and server sharing are checked again before the relevant
delete. These reads cannot provide an atomic lock against simultaneous manual
changes in Cloudflare.

New removals delete the Portal before its Access policy and application, and
finish the Portal graph before deleting source servers. The Portal's Access
application and all of its policy children are checked again immediately
before deleting the Portal, because that deletion may also remove its Access
resources. This avoids leaving a Portal whose Access application is missing
and avoids depending on mappings that Cloudflare may remove when a server
disappears. Each deletion is armed durably first. A lost response is
resolved by reading the exact resource on a new authorization; proven absence
advances the journal without another delete. Unfinished source or runtime work
blocks preparation. A current teardown action blocks runtime updates, and the
existing source lifecycle checks block source changes. Compatibility floors
remain unchanged.

The optional root-journal field `removalOrder: "portal_first"` pins this order
for new removals. An existing journal without the field retains its original
resource order, graph hash, and deletion prefix; upgrading code does not
reinterpret earlier deletion receipts. This preserves journal compatibility,
but does not establish that a legacy removal blocked by provider behavior can
finish. No legacy receipt is rewritten to claim the new order.

Fresh consent rechecks the complete graph. Missing Portal Access resources
are accepted as a possible cascade only for the new order, after the exact
owned Portal's deletion was durably armed or recorded complete, and after a
fresh read confirms that Portal is still absent. A missing Access resource
before this boundary remains a conflict. Changed identities, destinations,
ownership markers, policies, and unowned dependencies still block removal.

Managed BigQuery bridge removal follows the Portal and source graph. It
detaches the owned custom domain, deletes the credential-bearing Worker, and
then removes its Access application. Deleting Access protection requires fresh
direct proof that both the Worker and its recorded custom domain are absent;
earlier journal entries alone do not authorize that deletion.

A distinct signed handoff binds the ownership certificate, removal action,
ready-receipt checksum, dependency-graph hash, and the management resource
locators recorded during installation. Its signer requires the adopted gateway
key and the verified installation journal. Import checks the pinned ownership
issuer, signature, purpose, exact management hostname, and ten-minute expiry.
The handoff contains neither an OAuth grant nor a signing key.

The hosted removal job model consumes each OAuth callback once and records a
fixed prefix of root-removal steps. An uncertain send stays pending until a
fresh consent permits exact read-back; the same attempt cannot send it again.
The accepted handoff is reverified at its original import time, allowing an
existing job to resume after the handoff's import window closes. A new job
cannot import an expired handoff. An interrupted token exchange or unconfirmed
revocation remains an explicit warning even if a later consent finishes removal.
The hosted job is stored in a separate SQLite Durable Object with atomic revision checks. Its original handoff, release identity, retirement module digest, and verified progress cannot be replaced or rewound.

## Browser and provider flow

Settings keeps the public `POST /api/teardown-actions` contract and returns a
fragment handoff to `/__ankka/operation/teardown` on the gateway itself. This
review page requires an explicit action before starting Cloudflare consent.
The certified final runtime selects the current internal executor; neither a
browser flag nor an old hosted handoff can select it.

The gateway derives the uninstall scopes from checksum-verified resource kinds.
Its callback atomically consumes a durable attempt before exchanging the code,
probes the expected account using that grant, and executes dependency removal.
Only the installation object's completed removal result supplies the original
receipt checksum and dependency-graph digest used in the signed handoff. The
current grant must be revoked before that handoff is signed. A rejected or
interrupted attempt retains the deletion boundary and permits fresh consent.
A declined consent releases lifecycle locks only when the installation object
proves that removal has not started. Unknown or partial removal stays locked.
An earlier unconfirmed revocation remains in the signed handoff even when a
later grant was revoked successfully.

Management Access and the management custom domain remain available during
this first phase. The hosted `/teardown` page imports the signed handoff into a
durable job before offering its own fresh consent. It exposes progress and a
downloadable signed recovery receipt. Reimporting the exact saved receipt can
resume an existing job after its ten-minute import window or the browser cookie
has expired. A fresh signed handoff for the same certificate, locators, and
completed dependency graph can reopen that same job; it cannot change authority
or erase progress. No new job accepts an expired handoff.

The distinct `gateway-root-finalize` operation requests `workers-scripts.write`
and `zone-access.write`. The old Workers-only `uninstall-finalize` and bootstrap
cleanup authorities retain their original scopes. The finalizer verifies the
exact Worker identity and namespace, recorded management application and policy,
and foreign Worker bindings, domains, and policies before the first mutation.
It accepts supported changes to the owned administrator email policy while
refusing additional policies or destinations.

The fixed root order is signed namespace retirement, management custom domain,
management policy, management Access application, and Worker. Retirement uploads
only the exact signed retirement module from the accepted job's pinned release,
with no bindings and a deleted `AdminState` export. The deployed version's module
and configuration are verified before treating namespace retirement as complete.
The job pins the original release so an installer promotion cannot silently
change recovery code. Each destructive boundary is persisted before the request;
only verified provider absence advances progress. Unknown responses require a
fresh consent and read-back, including after the gateway no longer runs. There
is no force-delete option or browser-provided resource list.

OAuth grants stay in callback-local memory and are revoked and discarded on
success and failure. State, PKCE verifier, and the gateway action key cross the
redirect only in separate encrypted HttpOnly cookies; durable attempts contain
hashes and expiry times. Customer and hosted cookies use distinct encryption
contexts. Provider bodies and credentials are never included in public errors.
Hosted removal jobs retain secret-free authority and progress for recovery;
no expiry alarm deletes them while removal may still need to resume.

## Bounded failure diagnostics

The gateway callback keeps the existing `recovery_required` result and adds a
fixed diagnostic to the current customer-local removal attempt. The recovery
page displays it as `phase / resourceKind / category`. These three fields are
strict allowlists defined in
[`customer-teardown-failure.ts`](../apps/installer/src/customer-teardown-failure.ts).
They distinguish authorization, account verification, root and bridge
preflight/removal/verification, revocation, settlement, and handoff failures.
Categories distinguish provider authorization or availability failures,
rejected or invalid responses, ownership mismatches, unconfirmed absence,
interruption, expiry, and bounded-progress limits.

Diagnostics contain no credentials, account or resource identifiers,
hostnames, URLs, provider bodies, raw exception messages, or free-form fields.
They add no logging, telemetry, or transmission to Ankka. They remain in the
gateway's Cloudflare Durable Object with the current removal attempt; a new
consent replaces that attempt and clears its prior diagnostic. Final removal
retires the gateway's state. Diagnostics do not change deletion authority or
the requirement to revoke and discard the callback-local grant.

## Local verification

Tests exercise the gateway payload with synthetic provider state, including
changed source membership, foreign dependencies, complete removal, immediate
fresh consent, and lost responses at every dependency deletion. Gateway callback
tests cover receipt-derived scopes, rejected grants, callback concurrency,
expiry, revocation, and signing only after verified completion. Hosted tests use
real SQLite, recreated Durable Objects, complete fixed-root removal, failed
revocation, rejected authority, and each uncertain provider mutation.

Additional synthetic cases model a Portal whose read/delete requests are
rejected after its Access application disappears, and a Portal deletion that
cascades to its owned Access application and policy. The original order
returns HTTP 409 in this regression harness; the new order completes. Lost
Portal-delete responses before and after the deletion takes effect, recovery
with fresh consent, and a foreign policy introduced before Portal deletion are
covered. These fixtures model plausible provider behavior; they are not
captured Cloudflare responses and do not confirm the production root cause.

## Qualification still required

**Automatic removal qualification: FAILED, pending a successful live rerun.**

The reported `v0.1.59` test, source commit
`7714761028163101c78d984ff4cc2a3bf9ee74fe`, completed Add BigQuery,
fresh-client authentication, tool discovery, read-only queries, and Code Mode.
After changing the owned source policy to admit the gateway operator, removal
returned `recovery_required`; fresh consent and supported resume returned the
same result. Before manual cleanup, the Portal remained and Cloudflare
reported its Access application missing. The source registration, bridge
Worker, and gateway Worker remained, and the second phase had not started.
Manual cleanup subsequently succeeded and resource absence was verified.

The exact failing provider request, HTTP status, and internal stage were not
captured. The deployment's state and journal are no longer available. The
root cause remains unconfirmed, and no actual partial-deletion response schema
has been captured. Cloudflare documents
[automatic Portal Access application creation and Portal deletion](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/),
but does not specify the Portal API's behavior after that application is
deleted. Passing synthetic tests does not satisfy live qualification.

Use fresh disposable installations for this bounded checklist. No active
shared gateway is a disposable test fixture. Keep all private locators,
receipts, and provider evidence outside this public repository.

1. Record the tested installer and gateway release identities. Run generated
   artifacts containing the candidate fix together, including the separate
   hosted finalizer. Retain an independent baseline inventory for the owned
   resources and selected unrelated control resources.
2. Complete Add BigQuery, source authentication, Portal attachment, and the
   operator's supported source-policy membership change while retaining its
   identity and ownership marker. Confirm fresh-client discovery, read-only
   queries, and Code Mode before removal.
3. Complete both automatic removal phases with the displayed operation-scoped
   approvals. Capture the fixed failure diagnostic if any request fails;
   capture only sanitized response shape and bounded status evidence needed
   to establish the actual provider behavior. Do not publish raw responses.
4. Repeat on another fresh installation with an interrupted deletion and fresh
   consent. Verify that retained receipts resolve the uncertain operation,
   already confirmed deletions are not resent, and both phases finish.
   Include interruptions at Portal deletion and bridge domain/Worker deletion.
5. During bridge cleanup, independently verify that Access protection remains
   until its exact custom domain and credential-bearing Worker are confirmed
   absent. Recreated or changed resources must block further deletion.
6. Independently verify absence of every owned Portal, source registration,
   Access application and policy, DNS record, bridge Worker and custom domain,
   management custom domain and Access resources, gateway Worker, and retired
   gateway namespace. Verify that unrelated control resources remain intact.
   Removing the bridge's Google key copy does not revoke the original key in
   Google; manage that key separately.
7. Run `npm run check:fast` and require the full CI `check` gate to pass. Record
   the live outcome separately from automated test results; retain FAILED
   status until full automatic removal and interrupted recovery both pass.
