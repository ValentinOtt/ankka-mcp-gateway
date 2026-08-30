# Updater return after callback completion

The installer could remain on its management progress banner after a completed
update because its asynchronous management-context request finished after the
window's `load` event. Registering a listener at that point never navigated.
This is separate from Chrome's `ERR_BLOCKED_BY_CLIENT` behavior.

The installer now returns to the validated management-context URL immediately
when `document.readyState` is `complete`; otherwise it registers a one-time
`load` listener. These mutually exclusive branches execute synchronously, so
they neither miss a subsequent load event nor navigate twice.

## Completion and authority

No server execution or validation behavior changes. In
[`runtimeUpdateOauthCallback()`](../apps/installer/src/index.ts), the callback
awaits the memoized `executeOnce()` operation, including the runtime relay and
the grant revocation attempt and discard, before constructing the management
shell or issuing verified result context. The
[streaming response](../apps/installer/src/streaming-callback.ts) awaits that
same promise before closing. Waiting for document completion preserves this
response boundary; the progress banner does not establish action success.

The browser still obtains its target only from `/api/management/context` and
uses the existing URL validator. The server still validates the management
origin, release identity, authenticated relay, and action result. No callback
query, grant, cookie, or credential is read or persisted by the browser fix.
Missing, expired, malformed, and unavailable context retain the existing
result/session recovery behavior. Team saves and `accessAction` validation are
outside this change.

## Local verification

The [browser regression suite](../test/installer-management-redirect.test.mjs)
executes the complete JavaScript asset referenced by the release HTML, with
controlled load events and context responses. Against the preceding asset,
two of its 16 cases fail: load during the pending request and a document that
is already complete. With the fix, all 16 pass. Context before load still
waits; duplicate events navigate once; invalid or unavailable context never
redirects; successful return performs only one context GET and no action POST.

The [callback lifecycle suite](../apps/installer/test/management-callback-errors.test.ts)
also holds the relay and grant cleanup separately, covering action success and
failure with both successful and failed revocation. It asserts that no shell
escapes before cleanup, repeated execution callbacks reuse the same operation,
and current failures remain bounded instead of displaying an earlier success.
All fixtures are synthetic; this verification does not run a customer update.

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
