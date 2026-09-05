# Automated teardown implementation

Automated teardown is required for the first stable release. This document
tracks the replacement for the retired hosted management flow. It describes
implementation work, not a supported removal procedure.

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
This state model does not yet have a hosted storage or HTTP entry point.

## Remaining integration

The dashboard and operation router must use the new internal executor only
when the complete finalization flow is available. Until then, the current
routes have no public HTTP entry point and the existing dashboard behavior
has not been enabled by this work.

The gateway-local callback must request the uninstall scopes derived from its
verified receipts, execute dependent-resource removal, and confirm revocation
before signing the handoff. An unsuccessful attempt must retain its receipts
and require a fresh authorization. A complete removal receipt must be obtained
from the installation object; a prepared action is not evidence of absence.

Management Access and the management custom domain remain available during
this phase, so the operator can return after an interrupted attempt. The hosted
finalizer will import the signed handoff into a separate durable removal job
before obtaining its own fresh grant. It must remove only the recorded
management policy, Access application, custom domain, Worker, and namespace.
Keeping management available requires a distinct reviewed finalization
operation covering Workers and zone Access. The old Workers-only bootstrap
cleanup and `uninstall-finalize` authorities must not be silently widened.

The finalizer must prove the exact Worker identity and namespace, recorded
management application and policy, and absence of foreign dependencies before
its first mutation. It must upload only the signed retirement module to retire
the namespace, persist each destructive boundary before sending it, and prove
absence before reporting success. A retained hosted job must support a fresh
consent after an interrupted retirement or Worker deletion, including when the
customer gateway no longer runs. Provider grants remain request-local and are
revoked and discarded on every path.

The hosted storage adapter must retain the original accepted handoff and import
time, enforce revision-checked writes, and prevent a browser from supplying or
rewinding either value. It must persist every job transition before the next
provider call. The provider executor must verify absence before advancing a
pending step; the pure state model is not provider evidence.

## Qualification still required

- Gateway-local uninstall consent, receipt-derived scopes, account mismatch,
  rejection, replay, expiry, revocation failure, and safe return to management.
- Hosted finalizer import, one-time callback, fixed root authority, foreign
  policy/domain/namespace refusal, and every ambiguous mutation boundary.
- Generated installer and gateway artifacts running the complete flow together.
- A disposable live installation with a source and changed membership, complete
  removal with independent absence verification, and an interrupted run resumed
  with fresh consent. No active shared gateway is a disposable test fixture.
