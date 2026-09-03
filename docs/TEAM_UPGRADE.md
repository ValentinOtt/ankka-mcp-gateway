# Retiring the Team-credential preview

Status: compatibility and cleanup guidance for an earlier canary preview. V1
does not ship a customer-local Team policy editor or require a permanent
Cloudflare management credential.

The former two-update bridge introduced an optional standing Team secret. That
contract is no longer a release target. Do not publish, provision, or reactivate
it as part of a V1 installation.

## Forward-update boundary

The V1 signed release contract contains only the bootstrap secret required by
the existing deployment lifecycle. It does not declare a Team-management
binding.

The updater may accept the exact retired binding on the currently active
preview version for one purpose: omit it from a reviewed forward candidate. It
does not read, copy, inherit, rotate, or expose the secret value. Candidate
readback fails if Cloudflare returns that binding on the new version.

Rollback is refused when either the current or target version carries the
retired binding. This prevents a normal code rollback from restoring standing
authority in the active Worker.

## Customer cleanup

If your team created the old credential:

1. Revoke the API token in Cloudflare. This is the step that removes provider
   authority.
2. Remove the retired Team-management secret from the active Worker.
3. Review historical Worker versions according to your Cloudflare retention
   policy; deleting the active binding alone does not erase old versions.
4. Apply a reviewed forward release and verify that its exact binding list does
   not contain the retired secret.

Do not put a credential value in a repository, command argument, URL, log,
screenshot, support ticket, or migration record. A forward update cannot revoke
the separate API token on your behalf.

## Retained action state

Keep existing Team proposals and journals until their provider outcome is
known. A definitely unstarted proposal may be canceled through its guarded
existing endpoint. An armed, partial, or uncertain action requires comparison
with the actual Cloudflare policies and manual reconciliation; token revocation
does not prove that an earlier write was rolled back.

The original lifecycle floor remains conservative after a possible Team write.
Do not delete Durable Object records, rewrite release bookkeeping, or weaken
receipt checks to make an update, rollback, or teardown proceed.

See [Team access](TEAM_ACCESS.md) for the V1 manual workflow and future editor
options.
