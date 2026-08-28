# Third-party notices

This repository does not vendor third-party source code. The customer dashboard
uses published npm packages recorded exactly in `package-lock.json`, including:

- React and React DOM — Meta Platforms, Inc. and contributors, MIT License;
- Cloudflare Kumo — Cloudflare, Inc. and contributors, MIT License;
- TanStack Router — TanStack contributors, MIT License;
- Phosphor Icons for React — Phosphor Icons contributors, MIT License;
- Tailwind CSS — Tailwind Labs, Inc., MIT License;
- Vite and Vitest — their respective contributors, MIT License; and
- TypeScript — Microsoft Corporation, Apache License 2.0.

Their transitive dependencies and development-only test/build packages remain
subject to their own licenses as identified by the package metadata and
lockfile. No dependency license grants rights to a third-party trademark.

Every signed customer release generates `payload/admin/LICENSE.txt` and
`payload/admin/THIRD_PARTY_LICENSES.txt` from the exact clean source commit and
production dependency graph. The latter contains the complete root-level
license and notice files shipped by every production npm package, with package
version and registry origin. Both files are covered by the signed artifact
digest and are also attached to the immutable GitHub Release mirror.

Cloudflare products and names referenced in the documentation are owned by
Cloudflare, Inc. No Cloudflare source code is included in this repository.
