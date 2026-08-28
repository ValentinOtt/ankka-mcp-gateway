# Source origins

This repository has a fresh public history. This file records the origin and
publication rights of material that was transferred or vendored rather than
written directly in this repository.

Future entries must identify the source, copyright owner, license, publication
approval, review date, and material modifications. Do not include private
repository revisions or internal paths.

## Anti-slop Oxlint plugin

The source under `tools/oxlint/anti-slop/` was copied on 2026-08-28 from the
public `dmmulroy/anti-slop` repository at revision
`6d538555cb151d4121ed51a27db81890eacf8ae9`. It is licensed under the MIT
License, Copyright (c) 2026 Dillon Mulroy. The upstream rule tests were not
copied. The required license is retained at
`tools/oxlint/anti-slop/LICENSE`.

## Hosted installer

The implementation under `apps/installer/` was transferred from Ankka's
private product codebase on 2026-08-24. The copyright owner approved publishing
and relicensing it under Apache-2.0 for this repository.

The public version was adapted to the documented customer-owned Cloudflare
boundary. It excludes private history, credentials, signing material, generated
release output, customer data, and Cloudflare account or resource identifiers.

## Brand assets

The Ankka wordmark and visual-token references were transferred from Ankka's
private product codebase on 2026-08-26. The copyright owner approved their use
in this Apache-2.0 repository.

No private product implementation, font files, customer theme values, or
generated build output were transferred.

## Other repository code

Material not listed above was written for this public repository. Published npm
dependencies are not vendored; their licenses are described in
`THIRD_PARTY_NOTICES.md` and the lockfile.
