# auth.ankka.ai relay topology qualification

**Status:** COMPLETE (2026-09-03). Offline proof, live approval path, live
decline path, and teardown all done; see "Live result" below. Open item for
activation review: the operator-browser 403 on the final hop.

## Live result (2026-09-03)

Disposable topology: the real `auth-entrypoint.ts` bundled with the relay
origin rewritten to `auth-qual.ankka.ai` (custom domain on the Ankka zone),
and a disposable Gateway Worker holding a sealed ownership key with a
certificate from a qualification-only issuer key, reachable on both a
`workers.dev` host (bootstrap callback) and `gateway-qual.ankka.ai` (gateway
callback). Both Workers ran in the Ankka account, so the run qualifies the
public-HTTPS transport but not cross-account isolation. A disposable public
PKCE client with the single relay redirect URI and the exact seven install
scopes was created in the dashboard for the run.

- Challenge → proof → ticket → start over public HTTPS: passed on the first
  attempt with the real relay clients; three relay calls, all on the
  `v1:install` shard, no token or verifier in any request.
- Authorization URL: fixed public client id, relay redirect URI, exact seven
  scopes, S256, sealed state.
- Approval path: PASSED. Cloudflare returned the browser to the relay, the
  relay forwarded only `code` and the Gateway's state to
  `gateway-qual.ankka.ai/__ankka/install/oauth/callback`; the Gateway recorded
  `stateMatched: true`, `codeReceived: true`, `extraKeys: []`, and consumed the
  state once. No code was stored.
- Defect found live: Cloudflare appends an echoed `scope` parameter to the
  code response. The relay's callback accepted exactly `code` and `state` and
  answered 400 `relay_rejected` on the first approval. Fixed the same day:
  the relay now accepts `code`, `state`, and an optional `scope`, validates
  every echoed scope against the sealed operation's fixed ceiling, and still
  forwards only `code` and `state`. Offline test added; the fixed relay was
  redeployed and the approval path then passed.
- Decline path: PASSED. The operator pressed Cancel on Cloudflare's consent
  screen; Cloudflare redirected to the relay with `error=access_denied`, and
  the relay forwarded exactly `error=authorization_rejected` plus the
  Gateway's state to the certified callback (the description was not
  forwarded). The Gateway recorded `stateMatched: true`, `codeReceived: false`,
  `error: "authorization_rejected"`, `extraKeys: []`, and consumed the state
  once.
- Client-side observation, not a relay finding: the operator's Chrome
  profile received an empty-bodied HTTP 403 on the final hop to
  `gateway-qual.ankka.ai` for both an approval and the denial, before the
  Gateway Worker ran (its Durable Object had no record). The identical URLs
  answered 200 from curl and from a separate Chromium on the same Mac, and
  the Gateway has no 403 path, so the block sits between that browser
  profile and the zone edge (profile cookies/extensions, Chrome secure DNS
  with Tailscale, or a client-signal rule). The Gateway records above were
  produced by replaying the exact relay-forwarded URLs. Worth checking in
  Cloudflare Security → Events before any production activation, since a
  real installer must not lose a customer's browser on that hop.
- Relay-callback replay and shard emptiness: covered offline only.
- Teardown (2026-09-03): both Workers deleted with their Durable Objects;
  both custom domains gone (hosts unresolvable); the `workers.dev` host
  answers 404; local qualification secrets overwritten and removed; the
  disposable OAuth client deleted by the operator in the dashboard. Nothing
  from this qualification remains in the account.
**Scope:** the production boundary *customer Gateway (any Cloudflare account) →
public HTTPS → `https://auth.ankka.ai`*, using the real `auth-entrypoint.ts`
and the real production relay clients. This replaces the same-account Service
Binding transport used by the earlier live ownership canary.

Nothing in this document activates a production route or mutates the real
OAuth client. The live run uses disposable resources only.

## What is already proven offline

`apps/installer/test/two-stage-relay-topology.test.ts` drives the production
code end to end with only two stand-ins: the SQLite storage behind the relay's
challenge Durable Object, and the browser hop through dash.cloudflare.com.

- The customer side (`requestCustomerGatewayRelayTicket`,
  `beginCustomerBootstrapRelay`) reaches the relay only through absolute
  `https://auth.ankka.ai/...` URLs, with no authorization header, no cookie,
  and no verifier, capability secret, session secret, scope, or token in any
  request body.
- The relay is `createCloudflareAuthWorker` plus the real
  `CloudflareGatewayOwnershipChallenge` class: challenge → proof → ticket for
  the fixed `install` operation, sharded to `v1:install`, single-use consume.
- `/oauth/start/install` mints the exact authorization: fixed public client id,
  `redirect_uri = https://auth.ankka.ai/oauth/callback`, the exact seven-scope
  install ceiling, S256 challenge, HMAC-sealed state.
- `/oauth/callback` relays only `code` and the Gateway's own state to the
  certified `https://<management>/__ankka/install/oauth/callback`; denials are
  forwarded as one fixed error with no provider description; tampered state,
  duplicate or extra query keys, and expired state never redirect.
- The customer state consumes its callback exactly once before any exchange.
- Every relay response is `no-store`, `no-referrer`, `nosniff`, CSP
  `default-src 'none'`, with no CORS header and no cookie.
- Any origin other than the fixed public one (a `workers.dev` alias, `http`,
  or a port) is refused with 503.
- The relay source set contains no token endpoint, client secret, access or
  refresh token handling, or console logging, and `wrangler.auth.toml` declares
  exactly one route (`auth.ankka.ai` as a Custom Domain, restored by the
  activation review on 2026-09-03) and no bucket, session key, or client
  secret.

**Defect found and fixed on 2026-09-03:** the relay's challenge Durable Object
(`cloudflare-gateway-ownership-challenge-durable-state.ts`) accepted only the
later operations, so the real `auth.ankka.ai` would have rejected every Stage 2
`install` ticket with `ownership_proof_rejected`. The earlier live canary used a
disposable relay and exercised only `upgrade`, which is why it passed. The store
now accepts the full fixed operation catalogue. Any relay Durable Object created
before this fix carries the old table `CHECK` and must be recreated, not
migrated in place.

## Live run (needs an operator)

Everything below needs Cloudflare credentials, an OAuth client, and a human
completing consent, so it is not automated here. Use disposable names and tear
everything down at the end.

### Preconditions

- A disposable hostname on an Ankka-controlled zone for the relay, for example
  `auth-qual.<zone>`. Do not use `auth.ankka.ai`.
- A **separate** Cloudflare account acting as the customer account, with one
  active zone and a hostname for the Gateway management page.
- A disposable public (PKCE-only) Cloudflare OAuth client whose only redirect
  URI is `https://<relay-host>/oauth/callback`. Do not edit the production
  client.
- A fresh Ed25519 issuer key pair for the qualification only (seed as a Worker
  secret on deploy side, public key on both sides), and fresh HMAC keys
  (`CLOUDFLARE_RELAY_STATE_KEY`, `CLOUDFLARE_RELAY_TICKET_KEY`).

Because `cloudflare-code-relay.ts` pins `https://auth.ankka.ai`, the relay
Worker must be built once with that origin replaced by the disposable relay
host, and the customer-side canary with the same replacement. Keep that build
out of the repository; it is qualification tooling, not a release.

### Steps

1. Deploy the relay from a copy of `apps/installer/wrangler.auth.toml` that
   adds one `custom_domain` route for the disposable host and the
   `GATEWAY_OWNERSHIP_CHALLENGE` binding/migration. Provision the five
   bindings as Worker secrets or vars. Confirm `GET /health` returns
   `{ ok: true, role: 'cloudflare-code-relay', tokenExchange: false }` with
   `cache-control: no-store` and `referrer-policy: no-referrer`, and that the
   `workers.dev` alias of the Worker answers 503.
2. In the customer account, deploy a disposable Gateway that holds a sealed
   ownership key and a certificate issued by the qualification issuer key for
   its exact account id, Worker name and id, namespace id, and callbacks
   (`scripts/live-ownership-proof-gateway-worker.mjs` is the closest starting
   point; change its transport to `fetch` against the public relay host and
   its operation to `install`).
3. From the customer Gateway, request an `install` relay ticket and start the
   relay; open the returned dashboard URL in a browser as the customer account
   user; select exactly one account; approve. Expect the browser to land on
   the Gateway's `/__ankka/install/oauth/callback` with only `code` and the
   Gateway's state.
4. Repeat step 3 and decline consent. Expect the Gateway callback to receive
   only `error` and `state`.
5. Replay the relay callback URL from step 3. Expect no redirect.
6. Confirm on the relay: no Workers logs or traces are enabled, and the
   `GATEWAY_OWNERSHIP_CHALLENGE` shard for `v1:install` holds no row after the
   ticket was issued.
7. Tear down: delete the customer Gateway and its namespace, the relay Worker
   and its Durable Object, the disposable route, the disposable OAuth client,
   and the qualification keys. Verify each is absent.

### Record the outcome

Append the results (pass/fail per step, dates, and any provider drift) to
`docs/CLOUDFLARE_TWO_STAGE_INSTALL.md` under the canary evidence, without
account ids, resource ids, or secrets. A failing step blocks activation; it
never justifies widening scopes or adding a token path to the relay.
