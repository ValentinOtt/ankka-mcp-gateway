# Contributing

The repository is prepared and maintained as public source. Every contribution,
fixture, comment, and revision must be safe to publish even while preview
deployment gates are still being validated.

## Contributor toolchain

Development, verification, and release tooling use exactly Node.js `22.23.2`
and npm `10.9.8`. The `.nvmrc`, `packageManager`, and `devEngines` fields are
the machine-readable source of truth. The broader `engines.node` range is only
the runtime compatibility floor; it does not relax the contributor pin.

From a clean checkout, install and select the pinned Node release (which ships
the required npm version), then reproduce the lockfile installation without
rewriting it:

```sh
nvm install
nvm use
npm ci
npm run check
```

Use `npm ci` for clean verification, CI, release review, and ordinary local
setup. Use `npm install` only when intentionally changing dependencies, and
include the resulting `package.json` and `package-lock.json` changes together.

1. Do not copy files or Git history from a private repository without explicit
   ownership and license review.
2. Use synthetic organizations, hostnames, resource IDs, and provider payloads.
3. Never add secrets or customer data, including in tests and screenshots.
4. Keep the read-only and customer-credential-custody invariants intact.
5. Run `npm run check` with the pinned toolchain before opening a pull request.

For transferred or vendored material, update `ORIGINS.md` and
`THIRD_PARTY_NOTICES.md` in the same change.
