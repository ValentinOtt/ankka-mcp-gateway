# Cloudflare deployment

Cloudflare is the first deployment target for Ankka MCP Gateway.

The customer account owns the management Worker, Durable Object, MCP Portal,
Access policies, DNS, logs, and upstream credentials. The management origin
must be different from the employee-facing MCP Portal hostname.

## Checked-in state

The hosted installer configuration in `apps/installer` is deliberately
non-deploying: it has no production route, no signed release pin, and no enabled
mutation executor. The repository does not provide a general `deploy` script.

Customer releases are generated from a clean public commit, signed outside the
repository, and deployed only through a separately maintainer-approved
installer build. Do not treat source files, local digests, or Wrangler dry-run
output as release or deployment authority.

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
