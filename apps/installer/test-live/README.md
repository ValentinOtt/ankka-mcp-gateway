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

`stage2-full.live.ts` runs the whole install path in token mode: hosted
Stage 1 provisions the real shell Worker from a local publish directory
(read the way the hosted runtime reads R2, signature and all), completes the
handoff against it with the same readiness poll, then the Stage 2 converger
runs in this process against the real provider with the shipped payload
in-process, using an issuer key generated for the run. Only the two OAuth
endpoints and the account list are answered locally, so the API token stands
in for the grant. Needs `ANKKA_LIVE_PUBLISH_DIR` (the signer's publish
directory) and `ANKKA_LIVE_PIN` (its pin.json) beside the variables above.
The converger runs with the shell's checkpoints, one pass per call the way
the shell runs one pass per Durable Object alarm, and the harness prints and
bounds the provider calls of every pass: a Workers Free account allows 50
subrequests per invocation, and this is the only place the payload's own
provider calls are counted. Cleanup removes the payload's recorded
resources, the management application, the custom domain, marker-tagged
DNS records and the Worker. It does not cover the OAuth grant itself; that
still needs a consent.
