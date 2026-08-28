# Gateway updates and rollback

The gateway has a customer-initiated software update path for signed normal
releases. It is deliberately narrower than a general configuration manager:
an update may replace only the customer Worker code and management assets. It
does not change Access, DNS, the MCP Portal, sources, tool allowlists,
credentials, or Durable Object migrations.

## Why this design

The update coordinator is the already installed customer Worker. It checks one
fixed anonymous release-channel URL, verifies the release signature against the
public key installed with the gateway, records approval and progress in the
customer's Durable Object, and sends the user to a fresh Cloudflare OAuth
consent flow only after an exact release has been reviewed.

This keeps the existing custody boundary:

- no long-lived Cloudflare credential is added;
- no provider credential or upstream OAuth token is stored by Ankka;
- release discovery sends no account, hostname, user, cookie, or referrer;
- the hosted callback holds the operation-scoped Cloudflare grant only in the
  connected invocation, revokes it, and discards it;
- the original install receipt remains immutable;
- update and rollback history stays in the customer's Durable Object.

The fixed release request is software discovery, not an analytics event. Tests
bind it to the exact installed channel and prove it carries no account,
hostname, user, cookie, authorization, or referrer. The customer Worker has no
separate Ankka event endpoint; its signed deployment contract keeps metrics,
instrumentation, and observability disabled. Cloudflare may add hosted-zone
`NEL`/`Report-To` headers to the release response, but a server-side Worker
fetch neither configures customer reporting nor sends a browser NEL report.

An update is not a remote script fetched and executed by the dashboard. The
hosted release endpoint exposes a descriptor derived from the same exact
signed release bundle used by installation. Updater protocol 2 verifies an
Ed25519 signature over a domain-separated schema-2 statement binding the exact
canonical manifest, installed `canary` or `stable` channel, key ID and literal
signature context. It then validates the complete canonical manifest, exact
OAuth scope set, every component record, and the entire Cloudflare deployment
contract before it will describe a release as normal.

## Trust root and release channel

New installations receive three public, non-secret bindings:

```text
ANKKA_UPDATE_CHANNEL=stable
ANKKA_UPDATE_KEY_ID=<reviewed Ed25519 key ID>
ANKKA_UPDATE_PUBLIC_KEY=<reviewed raw Ed25519 public key>
```

Production installations use `stable`; reviewed disposable installations use
`canary`. The value is installed with the signing trust root and cannot be
chosen by a browser request. The Worker reads only:

```text
GET https://deploy.ankka.ai/api/releases/<installed stable-or-canary channel>
```

The public hosted installer has no Ankka Access application, so both exact
machine-to-machine release paths must reach the application directly. An
optional, separately isolated private canary may instead use exact Bypass
applications for only `/api/releases/canary` and `/api/releases/stable`; it
must not bypass `/api/releases`, `/api`, or the whole host. In either posture,
the inactive channel may return an application-level `404`, while an Access
redirect is always a failed edge configuration because an installed gateway
neither holds nor sends an Access identity.

The endpoint is derived from the installer's exact pinned and signature-verified
release bundle. A host pinned to one channel returns 404 for the other, so a
canary deployment cannot silently become the stable feed. It does not select a
release from a tenant or browser input.
The installed key is the trust root: every ordinary stable release must use the
same reviewed signing key. A key rotation is not a normal update and requires a
separate migration flow and review.

The channel is part of the signed bytes, not only the R2 key or public endpoint.
Copying an otherwise valid canary envelope into the stable prefix therefore
fails signature verification. Schema-1 envelopes that signed only manifest
bytes are rejected by the signer, publishers, installer and customer Worker.

The channel endpoint is intentionally not a rollout switch by itself. Publishing
and pinning a release makes it discoverable, but the customer must still review
and approve an update and authorize a fresh operation-scoped Cloudflare grant.

## Activation sequence

Cloudflare version overrides apply only to versions present in the active
deployment. The updater therefore uses this sequence:

1. Re-read the management Worker, active deployment, exact current version,
   bindings, account, Worker name, workers.dev subdomain, release, artifact
   digest, and installed signing key.
2. Upload the signed management assets and create the candidate Worker version.
3. Create and verify a deployment containing the current version at 100% and
   the candidate at 0%.
4. Send an exact-version health probe with
   `Cloudflare-Workers-Version-Overrides` to the 0% candidate.
5. Only after that probe succeeds, activate the candidate at 100%.
6. Probe the normally routed active version and commit the customer update
   record.
7. Disable the temporary workers.dev route used for the one-time
   HMAC-authenticated control channel.

No customer traffic is gradually split. This avoids mixed behavior across
versions and avoids pretending that Worker-code rollback also rolls back
Durable Object data or versioned static assets.

If any step fails after staging, the coordinator restores the prior version at
100% and verifies that deployment. If compensation cannot be verified, the
customer record becomes `recovery_required`; it never reports success from an
unknown provider outcome.

## Rollback

A successful update records the previous Cloudflare version ID in customer
state. Rollback is a new, explicit action with a fresh Cloudflare OAuth grant.
It stages the currently active version at 100% and the recorded previous
version at 0%, probes that exact previous version, activates it at 100%, and
health-checks it.

Rollback changes Worker code and assets only. It does **not** roll back Durable
Object data. Normal releases must therefore be backward-compatible with the
retained customer state. If a release requires a Durable Object migration,
binding change, compatibility-date change, scope change, signing-key rotation,
or any provider-resource mutation, it must be classified and shipped as a
separate migration rather than through this path.

## Human and agent flows

The management dashboard exposes Check, Review, Update, and Rollback controls.
When WebMCP is available it registers equivalent tools:

- `check_gateway_update`
- `review_gateway_update`
- `apply_gateway_update`
- `rollback_gateway_update`

Read tools perform no provider writes. Apply and rollback tools return a
short-lived authorization link for the user; an agent must relay that link and
must not approve Cloudflare consent on the user's behalf or request a token.
The same customer-owned journal drives progress in both the visible page and
the agent tool flow.

If the stable channel is unavailable, the rest of the management dashboard
continues to work. A previously recorded rollback remains visible and does not
depend on successful release discovery.

## Compatibility boundary

The updater bindings and customer runtime ledger are introduced by an
updater-capable release. A gateway installed before that release cannot safely
self-adopt this protocol because it does not yet possess the signing trust root
or the control implementation. Moving a pre-updater gateway onto the first
updater-capable release requires a separately reviewed migration or reinstall.
The normal lifecycle begins with updater-capable N and is proven by updating it
to N+1.

The private `gateway-v0.1.12` canary predates this channel-bound envelope and
updater protocol 2. Its immutable schema-1 bytes remain historical canary
evidence only: they must not be re-signed in place, promoted, or treated as N.
Retire that disposable installation and reinstall a freshly built and signed
schema-2 N before running the N to N+1 promotion proof. There is intentionally
no compatibility fallback that accepts schema-1 update descriptors.

Returning uninstall does not follow the mutable release channel. The installed
customer Worker exports its validated release ID, aggregate artifact digest,
channel, key ID, and public verification key inside the one-time, receipt-bound
teardown authority. The hosted executor uses those values only to address the
exact create-only R2 prefix, then re-verifies the schema-2 channel-bound
signature, exact object set, and every payload digest. If those historical
bytes are absent or disagree, removal fails closed; it never falls forward to
N+1. It also derives the exact clean-version semantic commitment from those
bytes and all expected plaintext bindings, requires read-back of every exact
module byte, then verifies the active Cloudflare version and sole 100%
deployment before any teardown mutation. Worker tags and imported mutable
bindings are not accepted as standalone release proof. Because the Versions
API exposes asset configuration but no immutable static-asset manifest or
content digest, active asset content is explicitly non-authoritative here.

## Promotion gate

Do not promote the first updater-capable release, or any change to the update
protocol, from canary until a real disposable customer account proves all of
the following with exact signed bytes:

1. install updater-capable N and make a real employee MCP tool call;
2. discover and approve signed N+1;
3. verify the 100% N / 0% N+1 deployment and exact-version N+1 probe;
4. activate N+1 and repeat the employee MCP tool call;
5. inject a broken candidate and prove verified compensation to N+1;
6. update to another healthy release, then explicitly roll back and repeat the
   employee MCP tool call;
7. uninstall after an update using the immutable original install receipt and
   the exact verified cleanup/retirement payload identified by the installed
   release, even after the channel advances again; and
8. independently prove zero receipt-owned residue.

Signing, publication, canary deployment, activation, and stable promotion stay
human-reviewed operations. No private signing key, generated release output,
Cloudflare account ID, or deployment credential belongs in this repository.
The deliberately broken step uses the source-bound
`build-reviewed-fault-injection-candidate.mjs` path documented in the reviewed
canary runbook. Its signer-enforced channel is `canary`, its target version must
be strictly newer than the healthy base and unpublished, and the injected
exact-version probe failure is the only payload change. It is never a stable or
GitHub release.
