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

The current removal order deletes the Portal graph before its source servers.
This avoids depending on a Portal mapping that Cloudflare may remove when a
server disappears. Each deletion is armed durably first. A lost response is
resolved by reading the exact resource on a new authorization; proven absence
advances the journal without another delete. Unfinished source or runtime work
blocks preparation. A current teardown action blocks runtime updates, and the
existing source lifecycle checks block source changes. Compatibility floors
remain unchanged.

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

## Local verification

Tests exercise the gateway payload with synthetic provider state, including
changed source membership, foreign dependencies, complete removal, immediate
fresh consent, and lost responses at every dependency deletion. Gateway callback
tests cover receipt-derived scopes, rejected grants, callback concurrency,
expiry, revocation, and signing only after verified completion. Hosted tests use
real SQLite, recreated Durable Objects, complete fixed-root removal, failed
revocation, rejected authority, and each uncertain provider mutation.

## Qualification still required

- Generated installer and gateway artifacts running the complete flow together.
- A disposable live installation with a source and changed membership, complete
  removal with independent absence verification, and an interrupted run resumed
  with fresh consent. No active shared gateway is a disposable test fixture.
