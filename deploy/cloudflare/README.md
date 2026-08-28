# Cloudflare deployment

Cloudflare is the first deployment target for Ankka MCP Gateway. The installed
management Worker, Durable Object, Access policy, DNS, MCP Portal, upstream
credentials, and logs belong to the customer account.

## Source and release shape

There is one customer dashboard source: `apps/admin`. It uses React,
TypeScript, Vite, Tailwind CSS, Cloudflare Kumo, Phosphor icons, and TanStack
Router. `npm run build:admin` writes ignored production assets to
`apps/admin/dist`.

The offline release-candidate builder verifies a clean public commit, rebuilds
that dashboard, and maps its generated files into the signed component path
`payload/admin`. The other four signed component sources remain under
`payload/`: installer, primary Worker, cleanup Worker, and retirement Worker.
Generated dashboard assets and signed release directories are never committed.

The primary customer Worker is the reviewed dependency-free module in
`payload/worker/index.js`. It serves the compiled SPA through its `ASSETS`
binding, routes `/api/*` through the Worker first, independently validates the
Cloudflare Access JWT and exact administrator allowlist, and serializes
customer-owned state in one Durable Object.

## Local development

From the repository root:

```sh
npm ci
npm run dev:ui
```

The UI studio starts the customer dashboard at `http://127.0.0.1:5730` and the
hosted installer at `http://127.0.0.1:5731`, both with synthetic data. It never
contacts Cloudflare and needs no credentials.

Run the full build and verification suite before committing:

```sh
npm run check
```

## Customer-owned topology

The management Worker needs its own origin, such as
`access-admin.example.com`. It cannot share the MCP Portal hostname, whose DNS
CNAME points at Cloudflare's MCP gateway.

Cloudflare Access protects the management origin. The Worker also verifies the
JWT issuer, audience, signature, verified email, and deployment administrator
allowlist before returning an admin API response. Alternate Worker routes and
preview URLs are disabled in a release.

Source and runtime mutations require a new operation-scoped Cloudflare OAuth
grant after explicit review. The grant remains in the connected hosted
callback, is never returned to the dashboard Worker, and is revoked after the
bounded action. Upstream user grants stay in the customer Cloudflare Portal.

Do not place account IDs, zone IDs, resource IDs, tokens, Terraform state,
private signing material, or generated deployment output in this repository.
