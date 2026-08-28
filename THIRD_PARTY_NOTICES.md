# Third-party notices

Except for the anti-slop plugin identified below, third-party dependencies are
consumed as published npm packages recorded exactly in `package-lock.json`.
The customer dashboard dependencies include:

- React and React DOM — Meta Platforms, Inc. and contributors, MIT License;
- Cloudflare Kumo — Cloudflare, Inc. and contributors, MIT License;
- TanStack Router — TanStack contributors, MIT License;
- Phosphor Icons for React — Phosphor Icons contributors, MIT License;
- Tailwind CSS — Tailwind Labs, Inc., MIT License;
- Valibot — Fabian Hiller, MIT License;
- Vite and Vitest — their respective contributors, MIT License; and
- TypeScript — Microsoft Corporation, Apache License 2.0.

Their transitive dependencies and development-only test/build packages remain
subject to their own licenses as identified by the package metadata and
lockfile. No dependency license grants rights to a third-party trademark.

The vendored anti-slop Oxlint plugin under `tools/oxlint/anti-slop/` is
Copyright (c) 2026 Dillon Mulroy and licensed under the MIT License. Its full
license text is retained in `tools/oxlint/anti-slop/LICENSE`. Oxlint and
`@oxlint/plugins` are development-only npm dependencies under their licenses
and versions recorded in `package-lock.json`.

The release builder generates `payload/admin/LICENSE.txt` and
`payload/admin/THIRD_PARTY_LICENSES.txt` from the exact clean source commit and
production dependency graph. The latter contains the complete root-level
license and notice files shipped by every production npm package, with package
version and registry origin. Both files are covered by the signed artifact
digest. The release publisher attaches the same files to its GitHub Release.

Cloudflare products and names referenced in the documentation are owned by
Cloudflare, Inc. No Cloudflare source code is included in this repository.
