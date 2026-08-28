# Gateway updates and rollback

Gateway updates are customer-initiated and signed. They are deliberately
narrower than a general Cloudflare configuration deployment.

## What an ordinary update can change

The only persisted changes from an ordinary update are:

- customer Worker code;
- customer management assets; and
- the non-secret `ANKKA_GATEWAY_RELEASE` and
  `ANKKA_GATEWAY_RELEASE_SHA256` text bindings that identify the installed
  release.

It must not change:

- Access applications or policies;
- DNS or MCP Portal configuration;
- sources or tool allowlists;
- credentials;
- resource or secret bindings, other plain-text bindings, or compatibility
  settings;
- the signing trust root; or
- Durable Object data or migrations.

During the approved operation, the updater temporarily enables the existing
customer Worker's `workers.dev` subdomain for a bounded, authenticated action
route. It disables and verifies that route before completion. An unconfirmed
cleanup result becomes recovery-required rather than success.

Changes outside this boundary require a separately designed and
customer-approved migration or a fresh installation.

## Release trust

Each installation receives a fixed release channel and an Ed25519 public key.
The customer Worker fetches only that channel's public descriptor and verifies
the signed channel, key identity, manifest, deployment contract, and payload
digests.

Release discovery is anonymous and sends no customer account, hostname, user,
cookie, authorization, or referrer. A channel outage does not prevent source
management or an already available rollback.

Publishing a release does not install it. A customer administrator must review
the release and approve a fresh, operation-scoped Cloudflare authorization.

## Update sequence

The updater:

1. reads the currently active Worker version and deployment;
2. uploads the verified candidate;
3. stages the candidate at 0% beside the current version at 100%;
4. probes the exact candidate version;
5. activates the candidate at 100% only after the probe succeeds; and
6. records the result in the customer's Durable Object.

Customer traffic is not gradually split between versions.

If staging or activation fails, the updater attempts to restore and verify the
previous version. An unverified provider outcome becomes recovery-required
instead of success.

## Rollback

A successful update retains the previous Cloudflare version. Rollback is a new
customer-approved action with a fresh Cloudflare authorization.

The only persisted rollback changes are Worker code, management assets, and the
two non-secret release-identity text bindings. It does not roll back Durable
Object data, sources, Access, DNS, Portal configuration, credentials, resource
or secret bindings, other plain-text bindings, or compatibility settings.
Releases must therefore remain compatible with retained customer state.

The original installation receipt remains the ownership authority for later
removal, even after updates.
