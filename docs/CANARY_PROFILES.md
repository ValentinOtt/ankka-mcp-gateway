# Local canary profiles

Local canary profiles remove repeated target arguments from the disposable
Cloudflare lifecycle canary. They are intentionally a small operator
convenience, not an account pool, scheduler, secret store, or remote operations
service.

The profile directory belongs to the Ankka operator and must remain outside
this public repository. Profiles may contain real Ankka-owned test account and
resource identifiers. They must never contain account or user identifiers,
credentials, OAuth grants, access-token values, allowed-user email addresses,
approval IDs, or receipt contents.

## One-time directory setup

The default directory is `~/.config/ankka-canary`. Set
`ANKKA_CANARY_DIRECTORY` to an absolute path to use another external directory.
Create the profile directory once with owner-only permissions:

```sh
export ANKKA_CANARY_DIRECTORY="/absolute/private/path/ankka-canary"
mkdir -p "$ANKKA_CANARY_DIRECTORY/profiles"
chmod 700 "$ANKKA_CANARY_DIRECTORY" "$ANKKA_CANARY_DIRECTORY/profiles"
```

Create `$ANKKA_CANARY_DIRECTORY/profiles/cloudflare-lifecycle.json` with this
exact shape, replacing the placeholders only with an Ankka-owned disposable
target and synthetic fixture:

```json
{
  "schemaVersion": 1,
  "kind": "ankka-cloudflare-disposable-canary-profile",
  "profileId": "cloudflare-lifecycle",
  "accountId": "00000000000000000000000000000000",
  "zoneId": "11111111111111111111111111111111",
  "hostname": "ankka-canary-lifecycle.canary.example.com",
  "syntheticMcpUrl": "https://synthetic-canary.example.net/mcp"
}
```

Then restrict the file:

```sh
chmod 600 "$ANKKA_CANARY_DIRECTORY/profiles/cloudflare-lifecycle.json"
```

The loader rejects unknown fields, unsafe profile names, permissive files or
directories, symlinks, files larger than 4 KiB, and any profile stored inside
this repository. The embedded `profileId` must match the filename. The CLI
derives the receipt path as
`receipts/cloudflare-lifecycle.receipt.json`; a profile cannot select another
receipt path.

## Running the lifecycle

Profiles without `authentication` keep the existing email-policy behavior.
Keep their two protected runtime values in the local environment or the
operator's existing secure credential facility:

```sh
export CLOUDFLARE_API_TOKEN
export ANKKA_CANARY_ALLOWED_EMAIL
```

For unattended authenticated testing, add `"authentication": "service_token"`
to a **new** profile. Keep the machine credentials separate from the management
API token, in the operator's existing credential facility (for example macOS
Keychain), and inject them only into the local process environment:

```sh
export CLOUDFLARE_API_TOKEN
export ANKKA_CANARY_SERVICE_TOKEN_ID
export CF_ACCESS_CLIENT_ID
export CF_ACCESS_CLIENT_SECRET
```

`ANKKA_CANARY_SERVICE_TOKEN_ID` is the service token's resource ID, not its
client ID. None of these values belongs in a profile, command-line argument,
log, or Git. Missing or malformed machine credentials stop the command before
provider construction; there is no fallback to email or unauthenticated mode.

Create one dedicated Access service token in the canary account, with a finite
duration. Creating or renewing it requires `Access: Service Tokens Write`
(**Account → Access: Service Tokens → Edit** in the dashboard) on the operator's
management grant. Capture the client secret directly into the credential
facility: Cloudflare returns it only at creation. The reusable service token
is operator-owned setup, not a disposable lifecycle resource. Reuse it across
runs; renew or rotate before expiry. See Cloudflare's
[service-token documentation](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/).

The machine lifecycle uses one exact Service Auth identity on both the Portal
and source applications, with no email policy or any-valid-token selector. It
still creates and removes exactly seven receipt-owned resources. The raw token
resource ID is consumed only in process; plans and receipts retain its digest.
Changing identities within an existing receipt fails closed: clean up using
the original identity first, then enroll a fresh profile.

This support is restricted to the fixed single synthetic source, its one
read-only tool, and a canary hostname. It does not add a general machine-access
configuration surface to deployed gateways. Cloudflare enforces the actual
authorization; the canary name and tool hints are not security boundaries.

Before cleanup, the command authenticates directly to the exact Portal `/mcp`
URL, lists its tools, invokes only the constant synthetic health tool with
empty arguments, and validates the complete expected result. Credentials are
never followed across a redirect or sent upstream by the verifier. The check
uses the stateless MCP transport and leaves Code Mode off. The separate
`canary:live` Code Mode checker remains a different test.

A successful machine result reports `authentication: "service_token"`,
`portalToolCallVerified: true`, and `interactiveVerification: "not_run"`.
It proves machine access, tool discovery/call, idempotent apply, and cleanup,
**not human OAuth login or upstream consent**. Run a separate interactive
check when changing those authentication paths. Machine verification failure
still enters receipt-owned cleanup and cannot produce a successful result.

Preview remains read-only:

```sh
npm run canary:lifecycle -- preview --profile cloudflare-lifecycle
```

Run performs one fresh preview and passes its structured lifecycle and target
confirmation IDs directly into the existing run path:

```sh
npm run canary:lifecycle -- run --profile cloudflare-lifecycle
```

The existing runner then rereads Cloudflare state and independently recomputes
both approval IDs before its first mutation. Drift, an unexpected target, an
unsafe plan, an existing lock, or mismatched receipt ownership still stops the
run. Approval IDs are neither written to the profile nor persisted for reuse.

Profile run performs only one preview/run pair. If the preview discovers a
receipt-owned partial installation or a pending Portal-create rollback, that
bounded recovery runs once and exits. Invoke the same command again to obtain a
new preview; the CLI does not add an automatic recovery loop.

## Local receipt and lock recovery

Receipts remain checksum-protected owner-only files managed by the existing
file receipt store. The profile command creates only its `receipts/` directory,
with mode `0700`, immediately before a mutating run.

Inspect locks without providing the derived receipt path or reading any
Cloudflare secret:

```sh
npm run canary:lifecycle -- lock inspect --profile cloudflare-lifecycle --store receipt
npm run canary:lifecycle -- lock inspect --profile cloudflare-lifecycle --store cleanup
```

Stale locks are never removed automatically. Use the exact lock ID returned by
inspection and the explicit confirmation printed by `--help` when recovery is
actually required.

Treat one profile as one enrolled target and receipt history. If the account,
zone, hostname, or synthetic endpoint changes, finish or recover the existing
lifecycle first and create a new profile ID. Do not overwrite or delete a
receipt to make a changed target pass.

This local profile mechanism covers only the hard-coded synthetic Cloudflare
disposable lifecycle. It does not qualify Google Search Console OAuth or turn
the experimental Search Console adapter into a production catalog preset.
