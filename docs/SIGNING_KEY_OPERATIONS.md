# Release signing-key operations

The release signing key is the trust root for updater-capable gateway installs.
It is deliberately separate from R2 and GitHub publication authority: a signer
cannot publish, and a publisher cannot create a valid release. Source code and
CI never receive the private seed.

## Initial custody

Before signing updater-capable N, record explicit approval for one Ed25519 seed
and a stable key ID. Generate the 32-byte seed directly into the operator's
local Keychain without putting it in a file, command argument, environment
variable, terminal output, shell history, clipboard, test fixture, or release
evidence. Derive and record only the raw public key and key ID.

The primary Keychain item is not a backup. Before first publication, create one
independently recoverable encrypted backup in a user-controlled secret store or
offline encrypted medium. Do not put it in Ankka application storage, the
repository, CI, Cloudflare Worker secrets, R2, a GitHub secret, or a support
system. Record the custodian and storage class, not the seed or a locator that
grants access.

Verify the backup once by restoring it into a memory-only process, deriving the
public key, comparing that public key with the reviewed trust root, and zeroing
the restored bytes. A successful backup test is required evidence; the backup
contents are not.

## Ordinary use

- Read the seed from Keychain into the signer through bounded stdin only.
- Require the explicit reviewed public key and key ID on every signing call;
  the signer must reject a mismatch.
- Keep signing and create-only publication as separate approvals and operator
  sessions.
- Sign only a clean candidate tied to one exact public source commit and
  channel. Never edit a signed output or reuse a partial output directory.
- Do not attach the seed, Keychain output, shell transcript, or signing process
  diagnostics to a release or audit record.

## Loss without suspected compromise

Stop signing and promotion. Do not create a replacement key under the old key
ID and do not change the published public key in place. Verify the recorded
public key before attempting the independently tested backup.

If the backup restores the same public key, return it to approved Keychain
custody and repeat the memory-only verification before signing. If no verified
copy remains, existing installations cannot safely accept releases under a new
trust root. Keep the channel frozen, keep the installer fail-closed for new
updates, and design an explicit customer-visible migration or reinstallation;
do not call an unsigned key swap a rotation.

## Suspected compromise

Treat uncertainty as compromise:

1. stop signing, publication, installer activation, and channel promotion;
2. revoke or rotate R2, GitHub, CI, and Cloudflare publication credentials even
   though they are separate from the signing key;
3. stop issuing installer links, safely resolve every in-flight receipt-owned
   action, deploy the disabled shell, and verify through a complete Access-app
   read plus cookie-free probes that no Access selector covers the public host;
4. preserve secret-free release, channel, and access evidence;
5. identify the last known-good signed release and notify affected preview
   users through the chosen private/public incident channels; and
6. design and independently review a new trust-root migration before asking a
   customer installation to accept it.

Deleting a release, changing a channel pointer, or generating a new key does
not prove that a copied seed is no longer usable. Never silently reuse a key ID.

## Planned rotation and retirement

The current updater protocol pins one key and does not define unattended key
rotation. Planned rotation is therefore a product/protocol change requiring a
separately signed migration design, downgrade and replay analysis, customer
consent semantics, rollback behavior, and an independent review. Until that
exists, use one retained preview key and treat its retirement as ending the
update lineage for installations that trust it.
