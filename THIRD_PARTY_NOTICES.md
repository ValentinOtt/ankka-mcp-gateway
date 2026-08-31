# Third-party notices

Except for the anti-slop plugin identified below, third-party dependencies are
consumed as published npm packages recorded exactly in `package-lock.json`.
The gateway dashboard and experimental adapter dependencies include:

- React and React DOM — Meta Platforms, Inc. and contributors, MIT License;
- Cloudflare Kumo — Cloudflare, Inc. and contributors, MIT License;
- Cloudflare Code Mode and Agents SDK — Cloudflare, Inc. and contributors,
  MIT License;
- Model Context Protocol TypeScript SDK — Anthropic, PBC and contributors,
  MIT License;
- TanStack Router — TanStack contributors, MIT License;
- Phosphor Icons for React — Phosphor Icons contributors, MIT License;
- Tailwind CSS — Tailwind Labs, Inc., MIT License;
- Valibot — Fabian Hiller, MIT License;
- Zod — Colin McDonnell and contributors, MIT License;
- jose — Filip Skokan and contributors, MIT License;
- Vite and Vitest — their respective contributors, MIT License; and
- TypeScript — Microsoft Corporation, Apache License 2.0.

The experimental Google Search Console adapter consumes the Cloudflare Code
Mode package, Cloudflare Agents SDK, Model Context Protocol TypeScript SDK, and
Zod at the exact versions recorded in `package-lock.json`. These packages are
not vendored. Google product and API names in that adapter and its documentation
identify compatibility only; no Google source code or API description is
included verbatim.

The experimental `apps/read-only-connectors` Worker consumes the v2 Model
Context Protocol server SDK, jose, and Zod as published npm packages. Its
provider readers and Access verification are original implementations based
on the primary documentation linked in its README and evidence record. No
provider schemas, examples, or source code are vendored. Provider names identify
compatibility, not an affiliation or endorsement.

The `@cfworker/json-schema@4.1.1` npm tarball declares the MIT License but does
not include its license file. A reviewed copy from the exact upstream source
revision is retained under `third_party/licenses/` and included by the release
license generator. Platform-specific esbuild and Rolldown binding packages use
the license file from the same-version parent package when their npm tarballs
omit a duplicate.

Their transitive dependencies and development-only test/build packages remain
subject to their own licenses as identified by the package metadata and
lockfile. No dependency license grants rights to a third-party trademark.

The Ankka favicon is maintainer-supplied brand artwork, included by request for
the gateway dashboard and hosted installer. No separate asset license or general
trademark license was supplied; its provenance and permitted use are recorded
in `ORIGINS.md`.

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
