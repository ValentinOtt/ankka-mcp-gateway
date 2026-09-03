# Team access in V1

V1 manages Team membership directly in Cloudflare. The gateway Team page is
read-only: it can show the access snapshot saved with the installation and any
retained legacy action, but it does not write Access policies.

This keeps the credential boundary simple:

- no permanent Cloudflare management credential is provisioned or required;
- installer and later-operation OAuth grants remain temporary and
  operation-scoped;
- source-provider credentials remain in your Cloudflare account; and
- changing Team membership does not send a token, policy, or roster to Ankka.

## Why V1 does not use an API token

Cloudflare support confirmed that both account-owned (`cfat_...`) and user-owned
API tokens can select resources only at User, Account, or Zone level. An API
token with **Access: Policies Write** for one account can therefore update every
Access policy in that account. It cannot be restricted to the reusable policy
owned by one Ankka installation.

Per-policy **Cloudflare Access Policy Admin** scoping exists in Cloudflare's
human/member IAM model. Cloudflare also confirmed that this resource-scoped
role is still beta for OAuth: individual policy API requests can currently be
evaluated differently from the resource-scoped list endpoints. That provider
gap explains the qualified `403`; widening the grant or substituting an
account-wide token would not preserve the intended isolation.

The V1 decision is therefore to keep the editor disabled instead of presenting
account-wide authority as policy-scoped.

<a id="customer-owned-management-credential"></a>

## No V1 Team credential

Do not create an API token for the gateway Team page and do not add a Team
management secret to the Worker. The normal release contract does not declare,
inherit, or consume one. Adding an undeclared secret manually does not enable
Team editing.

The management dashboard authenticates administrators through Cloudflare
Access, but that browser session is not authority for the Worker to rewrite
Access policies. V1 does not fall back to a hosted Team OAuth flow.

## Manage membership in Cloudflare

Use the Cloudflare dashboard to change the reusable Access policies protecting
the Ankka Portal and installed source applications. Keep the following
boundaries intact:

1. Confirm you are in the exact account that owns the gateway.
2. Identify the receipt-owned Ankka Access applications and reusable policies;
   do not select resources by a similar display name alone.
3. Preserve the fixed gateway administrators and review each source audience
   explicitly. Joining the team must not imply access to every source.
4. Keep an unassigned source default-deny. Do not replace an empty audience with
   an Allow-everyone or Bypass policy.
5. Do not change the Portal's shared tool allowlists or upstream authentication
   while performing a membership-only change.
6. Verify one intended identity and one denied identity with harmless read-only
   calls. Hiding a tool from a list is not enforcement proof.

The gateway's saved Team snapshot is not a live Cloudflare policy read. Changes
made in Cloudflare may not appear on the Team page, so Cloudflare remains the
source of truth for V1 membership.

<a id="recovery-and-lifecycle-limits"></a>

## Legacy preview recovery

Earlier preview source included an optional standing Team credential and local
policy-write path. That path is retired; the V1 Worker rejects new Team writes.

If you tested the old preview:

1. Revoke the old Team API token in Cloudflare. Removing a Worker secret does
   not revoke the token.
2. Remove the legacy Team-management secret binding from the active Worker.
   Historical Worker versions may still contain the old binding, so revocation
   is the authoritative removal of provider access.
3. Apply only a reviewed forward release whose contract omits the binding. The
   updater may recognize the legacy binding to remove it, but never reads or
   inherits its value.
4. Do not roll back into or out of a version carrying the retired binding.
5. If a retained action shows an armed, partial, or uncertain policy write,
   compare its journal with the actual Cloudflare policies and reconcile it
   manually. Do not delete the journal or claim that revocation rolled the
   policy back.

A definitely unstarted retained proposal can still use the existing guarded
cancel path. Any action with possible provider writes continues to block
automatic teardown and incompatible rollback until a separately reviewed
recovery path exists.

## Future Team editor options

A future editor has two realistic paths under Cloudflare's current model:

1. Revisit resource-scoped member OAuth if Cloudflare fixes the beta gap for
   individual reusable-policy API requests. The canary must prove positive and
   negative access for the exact policy and every endpoint used.
2. Offer an explicit enterprise opt-in account token with **Access: Policies
   Write**, guarded by exact application-level ownership checks while clearly
   accepting that Cloudflare itself does not isolate the token to Ankka
   policies.

The second option must not become the default. It would be account-wide standing
authority, not an exact-policy credential, even if the Worker promises to touch
only receipt-owned resources.

<a id="revocation-and-acceptance"></a>

## Session and acceptance limits

An Access policy change is not a promise that every existing session terminates
immediately. Test a fresh session and an already-connected session over a
bounded observation window, and report the delay observed. Application-token
revocation and user revocation have broader effects and are not substitutes for
a narrowly reviewed person/source policy change.

Keep real identities, account and policy IDs, source results, authorization
URLs, and credentials out of repository fixtures and support evidence.
