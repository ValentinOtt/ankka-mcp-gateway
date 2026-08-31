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

The [reviewed Team upgrade](TEAM_UPGRADE.md) uses a signed compatibility bridge
before the customer-local Team release. Recognizing the exact optional-secret
contract does not create or change a secret binding. The management credential
is a separate administrator-approved setup step in Cloudflare; neither update
provisions it.

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

The updater:

1. reads the currently active Worker version and deployment;
2. uploads the verified candidate;
3. stages the candidate at 0% beside the current version at 100%;
4. probes the exact candidate version;
5. activates the candidate at 100% only after the probe succeeds;
6. probes the active version through normal routing and re-verifies the deployment; and
7. records the result in the team's Durable Object.

Gateway traffic is not gradually split between versions.

Only an exact HTTP 409 `runtime_probe_version_mismatch` from the normal-routing
active probe is retried, with 250 ms pauses inside one total 10-second deadline.
Candidate probes, other errors, and provider mutations are not retried by this
check.

The connected callback displays a pending loader while the approved operation
runs. An explicit terminal result is emitted only after execution,
temporary-route cleanup, and the grant revocation attempt and discard. The
grant remains request-local and is never persisted. Automatic return requires
a valid success result and a complete document; EOF alone is not success.

If staging or activation fails, the updater attempts to restore and verify the
previous version. An unverified provider outcome becomes recovery-required
instead of success.

## Rollback

A successful update retains the previous Cloudflare version. Rollback is a new
operator-approved action with a fresh Cloudflare authorization.

The only persisted rollback changes are Worker code and management assets. It
does not roll back Durable Object data, sources, Access, DNS, Portal
configuration, or credentials. Releases must therefore remain compatible with
retained gateway state.

The original installation receipt remains the ownership authority for later
removal, even after updates.
