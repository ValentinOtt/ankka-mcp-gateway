# Contributing

Thank you for helping improve Ankka MCP Gateway. This is public source, so every
commit, fixture, comment, screenshot, and test output must be safe to publish.

## Set up the project

Development is pinned to Node.js `22.23.2` and npm `10.9.8`. The `.nvmrc`,
`packageManager`, and `devEngines` fields are the source of truth; use any
Node manager that reads `.nvmrc` (nvm, fnm, mise). A drifted local toolchain
warns on npm commands and fails `npm run check`; continuous integration
enforces the exact versions on every pull request.

```sh
nvm install   # or: fnm install / mise install
nvm use
npm ci
npm run check
```

Use `npm ci` for normal setup and verification. Use `npm install` only when
intentionally changing dependencies, and commit the manifest and lockfile
changes together.

While iterating, `npm run check:fast` runs the lint, typecheck, public
boundary, and unit-test subset in well under a minute. `npm run check` is the
full release gate and matches what continuous integration runs.

For local interface work, run:

```sh
npm run dev:ui
```

The local studio uses synthetic data and does not contact Cloudflare.

## JavaScript and TypeScript boundary

Application and library source is TypeScript. The JavaScript under `payload/`
is intentional: those files are dependency-free, single-module release inputs
whose exact bytes are hashed and signed before gateway deployment. Compiling
them from TypeScript during release would introduce a second, toolchain-shaped
artifact between the reviewed source and the signed payload.

Standalone Node.js release utilities and tests use `.mjs` when they need to run
directly without producing checked-in build output. New reusable runtime logic
belongs in TypeScript unless it must be part of an exact signed payload.

## Public history boundary

The history gate treats commit `4ba4c065aa67a761287bd74fc56f4911f7e558b3`
as the last already-published branding baseline. Only retired gateway naming in
that commit and its ancestors is grandfathered. Every other content, path,
generated-output, and structural check still covers all reachable history, and
every other commit receives the complete policy.

## Product language

Use "you" and "your team" in the dashboard, installer, and getting-started
copy. Use "users" for people connecting to the gateway and "gateway operators"
or "administrators" for the people managing it. Describe ownership as
"self-hosted" or "in your Cloudflare account", without implying a commercial
relationship with Ankka.

Copy changes must not rename serialized fields, configuration values, routes,
or existing document paths. Those are compatibility contracts, not labels.

## Contribution expectations

- Keep changes within the documented gateway-runtime and hosted-installer
  product boundary.
- Exact tool allowlists are mandatory.
- Any move beyond read-only sources requires a separate capability,
  authorization, and audit design.
- Never add credentials, private data, private hostnames, provider resource
  identifiers, private repository history, or generated release output.
- Use synthetic values in tests, examples, screenshots, and bug reports.
- Keep dependencies small and justify new production packages.
- Update tests and the smallest relevant public document when behavior changes.
- Record transferred or vendored material in [ORIGINS.md](ORIGINS.md) and
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Before opening a pull request, run `npm run check` from a clean checkout and
describe any effect on credential custody, authorization, telemetry, updates,
rollback, or removal.

Use the repository's issue forms for bug reports and feature proposals. Keep
all reports synthetic and follow [the code of conduct](CODE_OF_CONDUCT.md).
Contributions are made under this repository's Apache-2.0 license; there is no
separate CLA or DCO process at this time.

For security reports, follow [SECURITY.md](SECURITY.md) instead of opening a
public issue.
