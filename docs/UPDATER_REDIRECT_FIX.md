# Updater return after callback completion

The installer could remain on its management progress banner after a completed
update because its asynchronous management-context request finished after the
window's `load` event. Registering a listener at that point never navigated.
This is separate from Chrome's `ERR_BLOCKED_BY_CLIENT` behavior.

Source management callbacks retain the existing load/already-complete return
behavior. Runtime update callbacks now show a pending loader immediately and
return automatically only when the complete document contains one valid
explicit success result. Load or EOF alone never establishes success.

## Completion and authority

The reviewed [`runtimeUpdateOauthCallback()`](../apps/installer/src/index.ts)
streams its verified pending shell before the memoized `executeOnce()`
operation finishes. The early response clears the OAuth cookie; it does not
issue verified result context. Only after execution and cleanup—including the
grant revocation attempt and discard—does the
[stream](../apps/installer/src/streaming-callback.ts) append an escaped terminal
result.

That result contains only a public status, bounded diagnostic, and validated
management URL. The grant remains in request-local memory; neither it nor the
action key or authorization code enters the HTML.

The runtime loader makes no management-context or installation-status
requests. It validates the terminal result after document completion. Failure
offers a manual return link; a missing or malformed result remains unknown,
without navigation or replay. Source callbacks retain their existing
verified-context and recovery behavior. Existing authorization checks and
Team-save behavior are unchanged.

## Local verification

The browser regression suite (`test/installer-management-redirect.test.mjs`, retired with the two-stage installer cutover on 2026-09-03 because deploy.ankka.ai no longer serves `/manage`)
executes the complete JavaScript asset referenced by the release HTML, with
controlled load events, context responses, and terminal templates. It covers
immediate progress, fragmented templates, already-complete documents,
once-only success navigation, manual-only failure, malformed or missing
results, and unchanged source callbacks.

The [callback lifecycle suite](../apps/installer/test/management-callback-errors.test.ts)
holds execution and grant cleanup separately: the pending shell arrives early,
but no terminal result escapes before cleanup finishes. Repeated execution
callbacks reuse the same operation, sensitive values never enter the result,
and source callbacks retain their existing response path. All fixtures are
synthetic; these tests do not run a customer update.

## Required delivery path

The [candidate builder](../apps/installer/scripts/build-gateway-release-candidate.mjs)
copies committed `payload/installer` files. The
[reviewed hosted runtime](../apps/installer/src/reviewed-runtime.ts) serves its
management shell and assets from one verified, isolate-cached R2 snapshot,
selected by its exact pin to a signed release. A hosted Worker rebuild retaining
the old pin still serves the old installer asset.

Follow the existing [release integrity contract](RELEASING.md), with separate
explicit approval for signing, publication, deployment, and activation:

1. Integrate this fix through a passing PR and build a new full candidate from
   a clean public commit using the pinned toolchain. Choose an unused release
   identifier. Keep generated output outside the repository.
2. Externally sign and publish the new immutable release through the reviewed
   create-only publisher, then mirror it through the existing GitHub Release
   workflow. Preserve the existing channel, canonical origin, and signing-key identity.
   Never overwrite or reuse any published `gateway-v0.1.16` object.
3. Generate a new reviewed hosted artifact from the new exact pin and verified
   publication receipt; review and validate it before approved deployment and
   activation. JS filename, HTML reference, manifest hashes, and pin must agree.
4. Coordinate activation with pending approvals. The same hosted snapshot
   supplies the public update descriptor, so this also promotes that release
   for discovery. An older approved update target fails closed on a changed
   release identity before grant exchange. Do not replay callbacks to recover.
   Installed gateways remain unchanged until a separately approved update.
5. After activation, anonymously fetch query-free `/manage`, its referenced
   JS, and `/api/releases/<active-channel>` without credentials. Compare the
   HTML/JS bytes and signed descriptor to the new manifest and pin. HTML is
   `no-store`; hash-named assets are immutable. Already-open pages retain old
   code, so use a fresh page to verify the activated deployment.
6. Only with explicit approval, perform one fresh end-to-end update and verify
   one return to the validated Gateway URL. Independently check the Gateway's
   authenticated Updates result, exact installed release, and disabled
   temporary routes. Do not treat the installer banner as proof of success.

This patch prepares source and offline regression coverage only. It does not
sign, publish, deploy, activate, or perform live update verification.
