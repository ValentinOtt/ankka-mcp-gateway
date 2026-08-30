# Upgrade from hosted Team authorization

Status: reviewed upgrade procedure for the customer-local Team candidate, not
evidence of a published release or completed installation. Each release and
customer update still requires its normal approval and verification.

The upgrade uses two ordinary signed updates: the existing runtime to a
compatibility bridge, then the bridge to the customer-local Team runtime.
Neither update creates a credential or changes an Access policy. The dedicated
management credential is provisioned separately in your Cloudflare account.

## Why a bridge is needed

`gateway-v0.1.16` accepts only its exact signed Cloudflare deployment contract.
The customer-local Team contract additionally describes the optional
`ANKKA_TEAM_MANAGEMENT_TOKEN` secret. The old runtime correctly refuses that
unrecognized contract, even when no secret has been provisioned.

The bridge retains the exact legacy contract in its own signed manifest. Its
runtime recognizes only two complete contracts: the legacy contract and the
reviewed contract with this one optional secret. It does not accept arbitrary
bindings, change signed manifest contents, provision secrets, or activate
customer-local Team saves. The same signature, origin, artifact, update-action,
and lifecycle checks remain mandatory.

Using the normal updater for both hops updates the runtime release record and
public status through genuine completed actions. There is no maintenance
endpoint, direct Durable Object rewrite, fabricated success, or automatic reset
of stored release metadata. Deploying the final Worker directly is not this
procedure and can strand its release bookkeeping at the previous version.

## Before either update

1. Verify the installed release, exact Worker bytes, current bindings, and sole
   active deployment. Confirm that temporary `workers.dev` and preview routes
   are disabled. Keep the original receipt, source configuration, shared
   authentication, and tool allowlists unchanged.
2. Inspect pending Team and runtime actions. An expired or browser-blocked
   OAuth callback does not establish that no provider write occurred. Compare
   the saved action and its journal with the actual owned Access policies.
3. If a Team proposal is demonstrably unstarted, obtain the administrator's
   explicit approval to use **Cancel recorded change**. The normal cancellation
   retains the action as canceled; do not delete its storage or alter its
   journal. Keep the intended assignments available to review again after the
   upgrade, in customer-controlled storage, never in this repository.
4. If any write is armed, partial, or uncertain, stop this upgrade path and
   reconcile the existing operation. Do not cancel it, bypass the lifecycle
   check, or reset saved state. Resolve any pending runtime update too.

## Publish and apply the bridge

Build the bridge from a clean, reviewed public commit through the pinned release
tooling. Its signed manifest must retain the byte-exact legacy Cloudflare
contract. Verify that the actual v16 signature/manifest verifier accepts it.
Use a new, unused release identifier and the established signing-key identity,
origin, and channel. Do not overwrite existing release objects.

Publish and activate a legacy-compatible hosted installer pinned to that exact
bridge. This is distinct from publishing the later Team release: a hosted
loader accepting only the new contract cannot load a legacy bridge pin.
Verify the anonymous descriptor, signature, installer HTML, and referenced
hashed asset against the approved release. Do not change the pin during an
in-progress update.

The administrator approves one fresh normal update. After completion, verify:

- the active Worker bytes and aggregate artifact digest match the signed bridge;
- its durable update record and public status identify the bridge;
- the recorded action is completed, not merely authorized or staged;
- existing policies, receipts, source credentials, and tool selections are
  unchanged; and
- temporary routes are disabled.

The bridge includes the updater's post-success redirect correction. Independently
verify the installed state even if the browser returns successfully.

## Publish and apply customer-local Team

Only after the bridge update is verified, activate the compatible hosted
installer pinned to the separately signed Team release. The Team release's
manifest describes the optional management secret; its upload does not supply
one. The bridge validates that exact new contract and the normal updater stages,
probes, activates, and records the second update.

Verify the second completed action, exact active release and artifact, public
status, preserved source configuration, and disabled temporary routes again.
Opening Team without a management credential must fail closed for writes and
show the missing setup, not silently fall back to hosted OAuth.

## Provision authority and verify permissions

Provision the distinct secret directly in Cloudflare only after approving its
standing authority and the compatible deployment. Follow
[Team credential setup](TEAM_ACCESS.md#customer-owned-management-credential).
Do not paste it into an assistant, the Gateway dashboard, or the installer.
Do not use an installer grant, a source-provider credential, or a human Access
token as the management credential.

Re-enter and review any previously canceled proposal, then save one batch.
Confirm that only the receipt-owned policies changed, the exact shared tool
allowlists and `on_behalf: false` were preserved, and no Team-save request went
through Ankka or a temporary Worker route.

Complete the [two-person acceptance checks](TEAM_ACCESS.md#revocation-and-acceptance)
with actual direct tool calls and Code Mode. Report observed session/revocation
propagation; a changed policy or hidden tool list alone is not enforcement proof.

An administrator remains an administrator. No BLS write capability is enabled.
Source addition, including first-source onboarding for an empty Gateway, remains
unavailable in this release. Automatic teardown and older-runtime rollback stay
blocked once a Team policy write is armed. Do not rotate the credential or make
an unrelated deployment while an update is in progress.
