# Synthetic runtime probe canary

Use this opt-in diagnostic to investigate a new Worker version calling an old
Durable Object through the gateway's request-clone/header-reconstruction pattern.
It creates a disposable Worker and its own SQLite Durable Object in your
Cloudflare account. It never targets an existing gateway or uses business data.

This is **not a release gate**: it does not deploy the signed gateway artifact,
exercise OAuth or Access policies, test source connections, or prove that a real
gateway update will succeed.

## Run

Use the repository's pinned Node/npm toolchain. Review the no-network plan first:

```sh
npm run canary:runtime-probe -- --plan
```

For a live run, securely inject these environment variables into your shell:

| Variable | Required value |
| --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | `<target-account-id>` |
| `CLOUDFLARE_API_TOKEN` | `<account-scoped-api-token>` |

Do not put credentials in commands, source files, committed fixtures, or shell
traces. Then explicitly start the cloud mutations:

```sh
npm run canary:runtime-probe -- --execute
```

The account must already have a `workers.dev` subdomain. Use a dedicated token
scoped to that account with Workers Scripts Edit/Write permission and the read
access needed for Worker details, settings, deployments, the account subdomain,
and Durable Object namespace inventory. No DNS, Access, MCP-provider, or logging
permissions are needed. Account-level Workers authority is broader than this
runner's randomly named resources; review the account before execution and revoke
the token when finished. See Cloudflare's [API token permissions](https://developers.cloudflare.com/fundamentals/api/reference/permissions/).

The runner accepts only `--plan` or `--execute`; it does not accept a Worker name,
namespace ID, gateway URL, cleanup file, or resume command. Each execution creates
a fresh `ankka-probe-…` name. Allow it to finish: stopping the process can prevent
cleanup. Requests and inventory scans are bounded, but network failures can make
the run take several minutes. Normal Cloudflare usage limits and charges apply.

## What the observations mean

The runner seeds fake state on `old`, uploads `new`, and verifies a deployment
split of old 100% / new 0%. Only authenticated requests using a fresh canary key
can reach the fixture; the Cloudflare API token is never sent to it. The fixture
has no provider calls or application logging.

| Observation | Expected outer Worker | Expected Durable Object |
| --- | --- | --- |
| `candidate_immediate` | `new`, via version override | `old` |
| `candidate_strip_override` | `new`, removing only the override before DO dispatch | `old` |
| `old_baseline` | `old`, without override | `old` |
| `candidate_after_ready` | `new`, after bounded readiness polling | `old` |

The strip variant isolates header forwarding inside the synthetic fixture; it
does not change gateway code, remove authentication, or turn an earlier failure
into a pass. A comparison is meaningful only when both candidate requests
actually report outer revision `new`.

Successful probes return HTTP 204 and the fixture's readiness marker without
changing the fake state. Cloudflare documents that [version overrides can take a
few seconds to propagate](https://developers.cloudflare.com/workers/versions-and-deployments/version-overrides/).
The old DO expectation follows its [deployment-version assignment](https://developers.cloudflare.com/workers/versions-and-deployments/gradual-deployments/with-durable-objects/).

A live synthetic run on 2026-08-30 reproduced HTTP 503 at `stub_fetch` on both
candidate probes that preserved the override. The diagnostic strip probe reached
the same old DO from the new outer Worker and returned 204, as did the old
baseline. Cleanup was independently verified by the runner. This isolates the
forwarded-header failure in the synthetic path; it does not certify a gateway
fix or reveal Cloudflare's internal reason for rejecting the call. The overall
canary correctly remained failed. Keep that result until the original path
passes; do not change the success criterion to accept only the diagnostic variant.

Readiness confirms one request reached `new`, not that propagation has completed
everywhere. The immediate result is retained even if the later probe succeeds. It is not
retried into a pass; only readiness GETs are polled. An immediate failure therefore
keeps the overall result failed. Each observation contains bounded status/revision
fields and, when recognized, fixed error/stage labels—not response bodies or
exception text. Status `0` means no usable probe response was obtained.

Exit status 0 requires all four observations to pass **and** cleanup to be
verified. Inspect `observations`, `failure`/`reason`, `controlFailure`, and
`cleanup`/`cleanupReason` separately; a failed probe can still have clean removal.

## Cleanup and interruptions

After any attempted creation, the runner attempts cleanup in `finally`. It checks
the generated ownership marker, immutable Worker ID, exact bindings and namespace,
and absence of other resource references. It then disables the temporary address,
deploys a class-deletion migration without the class or Durable Object binding, verifies
namespace absence, and deletes the Worker by immutable ID without `force`.
Cloudflare may retain the ephemeral gate secret during the retirement upload;
only that exact secret binding is allowed to remain until Worker deletion.
`verified_removed` requires a Worker-not-found readback and another namespace
absence check. A [class-deletion migration permanently removes its objects and
stored data](https://developers.cloudflare.com/durable-objects/reference/durable-object-class-migrations-legacy/).

`resources_may_remain`, missing final output, or interruption is **not** successful
cleanup. Keep the emitted exact `workerName` privately outside the repository and
stop for manual review of that exact resource in Cloudflare. Check ownership,
bindings, references, and namespace identity before separately authorizing any
removal; do not delete by prefix or use forced deletion. The name is a locator,
not deletion authority. There is deliberately no automated cleanup/resume path,
and rerunning the command creates a new canary rather than repairing the old one.
