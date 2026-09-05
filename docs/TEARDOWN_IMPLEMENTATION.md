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

The removal order deletes the Portal graph before its source servers. Within
the Portal graph, the order remains DNS record, Access policy, Access
application, and Portal. This avoids depending on mappings that Cloudflare may
remove when a server disappears. Each deletion is armed durably first. A lost response is
resolved by reading the exact resource on a new authorization; proven absence
advances the journal without another delete. Unfinished source or runtime work
blocks preparation. A current teardown action blocks runtime updates, and the
existing source lifecycle checks block source changes. Compatibility floors
remain unchanged.

A successful Access `DELETE` can return HTTP `202 Accepted`. This records a
submitted deletion, not confirmed removal. The executor advances only after
reading the exact owned resource and confirming absence. If absence cannot be
confirmed, it retains the pending deletion and requires fresh consent; that
same callback cannot send the deletion again. A fresh consent rechecks the
complete graph and resolves the pending operation from its recorded locator.
The resource order, graph hashes, and existing journal format remain unchanged.
No deletion prefix is rewritten and no new cascade exception changes the
ownership checks.

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

The
[`cloudflare-access-delete-accepted.json`](../test/fixtures/cloudflare-access-delete-accepted.json)
fixture records observed HTTP statuses and a synthetic version of the Access
deletion envelope. Regression coverage models HTTP 202 followed by exact
absence, an accepted deletion whose absence remains unconfirmed, and recovery
with fresh consent. The original runtime treated HTTP 202 as a rejected
provider request even when Cloudflare had completed the deletion.

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
captured. The deployment's state and journal are no longer available, so its
precise failure cannot be conclusively reconstructed.

On 2026-09-05, a separate live API probe created two fresh disposable empty
Portals with the installer's Access application shape and a deny-everyone
policy. It exercised both deletion orders without a source registration,
Google key, DNS record, or Worker:

- Access policy deletion returned HTTP 202 with `success: true`, empty
  `errors` and `messages`, and `result: { id }`; the exact policy read then
  returned HTTP 404. Access application deletion behaved the same way.
- After both Access resources were deleted, the Portal remained listed and
  its detail read returned HTTP 200. Its identity, marker, hostname, Code Mode,
  secure-web-gateway setting, and empty server list were unchanged. Portal
  deletion returned HTTP 200 and its exact read then returned HTTP 404.
- Deleting the other Portal first returned HTTP 200 and left its Access
  application and policy present. No automatic Access creation or deletion
  cascade was observed through the Portal API in these probes; the Access
  resources were created and removed explicitly.
- Every created Portal, application, and policy was independently verified
  absent by exact reads and relevant inventories after cleanup. The
  preexisting Portal and Access inventories remained unchanged.

This confirms a provider-status handling defect: the original runtime accepted
only HTTP 200, 201, or 204 and rejected a successful Access deletion returning
202. Stopping after policy deletion on one consent and application deletion on
the next is consistent with the reported state. It remains an explanation of
the historical report, not a recovered trace of that installation. The narrow
probe does not qualify managed BigQuery removal, the browser callback, or the
hosted finalizer, and does not establish every Portal's partial-state behavior.

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
   Include an accepted Access deletion whose response or absence confirmation
   is interrupted, and interruptions at bridge domain/Worker deletion.
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
