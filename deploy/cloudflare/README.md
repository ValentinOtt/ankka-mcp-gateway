# Cloudflare deployment

Cloudflare is the first deployment target for Ankka MCP Gateway.

The deployment account owns the management Worker, Durable Object, MCP Portal,
Access policies, DNS, logs, and upstream credentials. The management origin
must be different from the employee-facing MCP Portal hostname.

## Checked-in state

The hosted installer configuration in `apps/installer` is deliberately
non-deploying: it has no production route, no signed release pin, and no enabled
mutation executor. The repository does not provide a general `deploy` script.

Supported gateway releases will be generated from a clean public commit,
signed outside the repository, and deployed only through a separately
maintainer-approved installer build. Do not treat source files, local digests,
or Wrangler dry-run output as release or deployment authority.

The repository does contain an isolated installer generator and a bounded,
development-only self-deploy path for a consenting first party. Release
generation compiles one exact HTTPS control-plane origin into the gateway
Worker and binds it through the signed manifest, release pin, publication
receipt, installer, update discovery, and all returning management handoffs.
It is not request- or configuration-selectable.

That path is unsupported and has not been live-qualified. It requires a clean
public commit, a local development signature, team-controlled Cloudflare
resources, two create-only releases, lifecycle drills, receipt-bound removal,
and exact cleanup. It does not provide a general deploy script or production
signing authority. Follow the complete
[first-party Cloudflare dogfood runbook](FIRST_PARTY_DOGFOOD.md); do not deploy
from partial commands or generated source alone.

## Local verification

Run from the repository root:

```sh
npm ci
npm run dev:ui
npm run check
```

The UI studio uses synthetic data and makes no Cloudflare requests.

Never commit Cloudflare account, zone, or resource identifiers; API tokens;
OAuth secrets; Terraform state; private signing material; or generated
deployment output.
