# Live harnesses

Real Cloudflare calls against a dedicated test account. Never part of
`npm run check`; run one explicitly from `apps/installer`:

```
ANKKA_LIVE_TOKEN=<api token, read from a keychain into this process only> \
ANKKA_LIVE_ACCOUNT_ID=<account id> ANKKA_LIVE_ZONE_ID=<zone id> \
ANKKA_LIVE_ZONE_NAME=<zone> ANKKA_LIVE_ADMIN_EMAIL=<admin email> \
ANKKA_LIVE_PREFIX=harness1 ANKKA_LIVE_MANIFEST=<candidate manifest.json> \
npx vitest run --config vitest.live.config.ts
```

`stage2-bootstrap.live.ts` builds a real plan for `mcp<prefix>.<zone>`, runs
the Stage 2 converger's bootstrap request into the shipped payload in-process
with the API token instead of the OAuth grant, verifies the receipt the way
the converger does, traces every provider call (method, path, status,
duration; never tokens or bodies) and removes what the payload recorded.

Optional: `ANKKA_LIVE_PAYLOAD=<path>` runs a different payload module (for
example an instrumented copy); `ANKKA_LIVE_KEEP=1` leaves the created
resources in place. The token needs the zone's DNS edit permission besides
Access, AI controls and Workers edit rights.
