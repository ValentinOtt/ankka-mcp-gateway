# Hosted installer

`apps/installer` contains the optional Cloudflare Worker behind Ankka's
hosted gateway installation flow.

## Status

The checked-in build is intentionally fail-closed:

- install and removal executors are disabled at compile time;
- the approved release pin and public-key registry are empty;
- no environment variable can enable mutations;
- the checked-in Wrangler configuration has no production route;
- `workers.dev`, preview URLs, application logs, and traces are disabled; and
- there is no package deploy script.

A deployable build requires a separately maintainer-approved source commit,
signed release pin, generated configuration, credentials, and explicit
deployment approval. Those artifacts and authorities are not stored in this
repository.

## Responsibilities

The installer implements:

- Cloudflare OAuth discovery and operation-specific authorization;
- secret-free gateway configuration and plan review;
- signed release verification;
- bounded installation, progress, recovery, and removal coordination; and
- fixed session-scoped hosted analytics.

Your management Worker, Durable Object, MCP Portal, Access policies,
DNS, logs, and upstream credentials remain in your Cloudflare account.

MCP source-provider credentials never enter the installer. The separate
Cloudflare deployment grant is request-local, is used only for the
operator-approved operation, is subject to a bounded revocation attempt, and
is then discarded locally.

See:

- [Self-service deployment](../../docs/CUSTOMER_SELF_SERVICE.md)
- [Architecture](../../docs/ARCHITECTURE.md)
- [Security model](../../docs/SECURITY_MODEL.md)

## Local development

Run these commands from the repository root:

```sh
npm ci
npm run dev:ui
npm run test --workspace @ankka/gateway-installer
npm run build --workspace @ankka/gateway-installer
```

`npm run dev:ui` is the safest interface workflow: it uses synthetic data,
does not contact Cloudflare, and needs no credentials.

The package build type-checks the Worker and performs a Wrangler dry run with
`wrangler.reviewed-disabled.toml`. It does not deploy.

Secret names and safe placeholders for local Worker development are listed in
`.dev.vars.example`. Never commit `.dev.vars` or copy real values into test
fixtures, logs, terminal transcripts, or documentation.

## Release tooling

The scripts under `apps/installer/scripts` build, verify, sign, and publish
create-only release artifacts from a clean public commit. They are maintainer
tools, not a supported end-user CLI; active commands document their accepted
arguments in source and reject incomplete input, while retired entrypoints fail
closed without reading credentials.

Signing keys, publication credentials, generated candidates, signed envelopes,
and deployment configuration remain outside the repository. Running a builder
or dry run does not grant deployment authority.

See [Release integrity](../../docs/RELEASING.md) for the public supply-chain
contract.
