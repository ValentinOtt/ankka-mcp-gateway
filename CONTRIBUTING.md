# Contributing

Thank you for helping improve Ankka MCP Gateway. This is public source, so every
commit, fixture, comment, screenshot, and test output must be safe to publish.

## Set up the project

Development uses exactly Node.js `22.23.2` and npm `10.9.8`. The `.nvmrc`,
`packageManager`, and `devEngines` fields are the source of truth.

```sh
nvm install
nvm use
npm ci
npm run check
```

Use `npm ci` for normal setup and verification. Use `npm install` only when
intentionally changing dependencies, and commit the manifest and lockfile
changes together.

For local interface work, run:

```sh
npm run dev:ui
```

The local studio uses synthetic data and does not contact Cloudflare.

## Contribution expectations

- Keep changes within the documented customer-runtime and hosted-installer
  product boundary.
- Exact tool allowlists are mandatory.
- Any move beyond read-only sources requires a separate capability,
  authorization, and audit design.
- Never add credentials, customer data, private hostnames, provider resource
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
