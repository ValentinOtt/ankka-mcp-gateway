# Gateway updates and rollback

Gateway updates are operator-initiated and signed. They are deliberately
narrower than a general Cloudflare configuration deployment.

## What an ordinary update can change

An ordinary update changes:

- gateway Worker code; and
- gateway management assets.

The updater also records its action, installed release, rollback reference, and
public status in the existing Durable Object. This normal bookkeeping does not
replace application data, ownership receipts, saved audiences, or recovery
history. It is not a Durable Object migration or an out-of-band state rewrite.

It must not change:

- Access applications or policies;
- DNS or MCP Portal configuration;
- sources or tool allowlists;
- credentials;
- Cloudflare bindings or compatibility settings;
- the signing trust root; or
- application data, ownership receipts, saved audiences, or Durable Object
  migrations.

During the approved operation, the updater temporarily enables the existing
gateway Worker's `workers.dev` subdomain for a bounded, authenticated action
route. It disables and verifies that route before completion. The installer
reports unconfirmed route cleanup as a failure rather than success.

Changes outside this boundary require a separately designed and
operator-approved migration or a fresh installation.

The V1 release contract has no Team-management secret. A forward update may
recognize the retired preview binding only to omit it from the candidate; the
value is never read or inherited. Rollback into or out of a version carrying
that binding is refused. See the [retirement procedure](TEAM_UPGRADE.md).

## Release trust

Each installation receives a fixed release channel, an Ed25519 public key, and
one signed canonical HTTPS control-plane origin compiled into its Worker. The
gateway Worker fetches only that origin and channel's public descriptor and
verifies the signed channel, key identity, origin, manifest, deployment
contract, and payload digests. An update signed for a different origin fails
closed even when its signature is otherwise valid.

Release discovery is anonymous and sends no deployment account, hostname, user,
cookie, authorization, or referrer. A channel outage does not prevent source
management or an already available rollback.

Publishing a release does not install it. A gateway administrator must review
the release and approve a fresh, operation-scoped Cloudflare authorization.

## Update sequence

An update starts in the gateway dashboard and runs on the gateway itself:

1. The dashboard prepares the update and hands the browser to the gateway's
   own `/__ankka/operation` page, which asks Cloudflare for a one-time
   `upgrade` grant (Workers scripts write only) through the public OAuth
   client and callback certified at install.
2. The gateway reads its active Worker version and current bindings, then
   fetches the pinned release descriptor and every manifest file from the
   control plane's `/api/releases/<channel>/files/<path>` route and verifies
   the signature and every digest with the update key it was installed with.
3. It uploads the new management assets, records a handover (the action, the
   target, and the action key sealed under the ownership wrap key), arms its
   own alarm, and uploads the new Worker version with the existing secrets
   and object namespace inherited. The upload activates at once and replaces
   the version that ran the update.
4. The grant is revoked and the browser returns to Settings, which polls the
   action. The new version's alarm finds itself running the target release
   and completes the journal with `finalize`; if the old version still runs
   after five minutes, it marks the action as needing recovery instead.

Gateway traffic is not gradually split between versions, and no candidate is
probed before activation: the bytes are the signed release the hosted
installer would deploy for a fresh install, verified on the gateway before
the upload. The grant remains request-local and is never persisted. The new
version's Cloudflare version id is not recorded, because the version that
could learn it no longer runs by then.

Anything that fails before the upload fails the action in the journal with
the stage and cause as its code and leaves the running version untouched.
An upload whose outcome is unknown is left to the handover: the alarm either
proves the new release or reports recovery-required.

## Rollback

A successful update retains the previous Cloudflare version. Rollback is a new
operator-approved action with a fresh Cloudflare authorization. Through the
gateway's own route it succeeds only while the control plane still pins the
release being rolled back to; otherwise it stops with `release_unavailable`
before any upload. Serving exact earlier releases is still open.

The only persisted rollback changes are Worker code and management assets. It
does not roll back Durable Object data, sources, Access, DNS, Portal
configuration, or credentials. Releases must therefore remain compatible with
retained gateway state.

The original installation receipt remains the ownership authority for later
removal, even after updates.

Customer-local Team writes and default-deny source creation can establish a
minimum compatible runtime before their first provider mutation. An older
runtime cannot be restored below that recorded floor, and automatic teardown
remains unavailable. A merely prepared source action or saved draft does not
set the restriction. The optional Team-management secret also blocks rollback
when present on the current or target version. See [Team access](TEAM_ACCESS.md)
and [first-source qualification](FIRST_SOURCE_ONBOARDING.md); a normal code
update does not provision credentials, grant source access, or clear these
lifecycle restrictions.
