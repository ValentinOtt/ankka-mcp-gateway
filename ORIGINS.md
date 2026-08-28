# Source origins

This repository started with a fresh Git history. Its initial files were written
for this repository and were not copied from the private Ankka codebase.

Record any future transfer or vendoring here with:

- source repository and path;
- source revision;
- copyright owner and license;
- approval to publish or relicense;
- review date and material modifications.

## Customer gateway release payloads

The primary, cleanup, and declarative-retirement Worker modules plus the
installer browser assets under `payload/` were written for this public
repository. The customer dashboard is authored once in `apps/admin` and its
generated assets are mapped to `payload/admin` only in a release candidate.
Their public wire and release-layout compatibility was cross-checked on
2026-08-23 against Ankka's private installer interfaces for session and plan
projections, customer bootstrap and uninstall requests, provider-neutral
seven-resource receipts, and signed Worker variants. No customer data,
provider credential, generated release, or third-party implementation is
vendored here. The hand-authored installer shell under `payload/installer`
uses only the operating system font stack and contains no copied font or
third-party UI asset. Generated dashboard assets come only from the locked npm
dependency graph and carry the generated license bundle described below.

## Customer dashboard stack

The `apps/admin` application was implemented in this public repository on
2026-08-27 using the same public technology choices as Cloudflare's open-source
Cloudflare OS project: React, TypeScript, Vite, Tailwind CSS, Cloudflare Kumo,
Phosphor icons, and TanStack Router. No Cloudflare OS application source,
Cloudflare product implementation, private asset, or generated output was
copied or vendored. Direct dependencies are consumed from their published npm
packages under the licenses recorded in `THIRD_PARTY_NOTICES.md`.

## Hosted installer

`apps/installer` was transferred on 2026-08-24 from the private Ankka repository,
path `apps/gateway-deploy`, at source revision
`08cad68e52f1730f9b3f7fcd203b1c9da5e0b466`. The repository owner explicitly
approved publishing and relicensing this implementation under this repository's
Apache-2.0 license. The transfer includes the Worker implementation, protocol
contracts, tests, secret-free release tooling, and reviewed canary documentation.
It excludes private Git history, credentials, signing material, generated
release output, and Cloudflare account or resource identifiers.

## Ankka brand alignment

The Ankka wordmark path and the public/app visual token references used by the
gateway installer and management interfaces were transferred on 2026-08-26
from the private Ankka repository at source revision
`0032d759a6f7fbcd897d449e1b0aee5dd8d014b2`. The reviewed source paths were
`apps/landing-page/src/components/Wordmark.astro`,
`apps/landing-page/src/styles/brand.css`,
`apps/landing-page/src/styles/home.css`, `apps/shared/styles/brand-tokens.css`,
and `DESIGN.md`. The repository owner approved using the first-party brand
asset and design language in this public Apache-2.0 repository. No font files,
customer theme values, private product implementation, or generated build
output were copied; the interfaces keep resilient operating-system font
fallbacks and locally implemented layouts.
