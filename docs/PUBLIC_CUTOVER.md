# Public preview cutover

This runbook orders the first public preview so every intermediate state is
fail-closed. It does not turn source availability into deployment authority:
signing material, publication credentials, OAuth consent, and Cloudflare
deployment authority remain outside this repository.

The cutover is staged rather than atomic. A failed stage stops before the next
one. Do not compensate by skipping a check or widening a policy.

## 1. Owner decisions

Record these decisions before changing an external system:

- the final GitHub owner and repository name;
- the private-history archive name and confirmation that it stays private;
- the public `main` governance policy below;
- the monitored private security/conduct contact;
- any operator identities and non-live hostname/account used for an optional
  isolated private canary;
- retained signing-key custody, backup, loss, and compromise handling;
- explicit approval to keep zone-wide Network Error Logging enabled for the
  hosted installer, including the residual Cloudflare request and callback
  metadata described below; and
- explicit approval for default identifier-free hosted-installer funnel
  analytics under the exact public schema, destination, and retention in
  `HOSTED_INSTALLER_ANALYTICS.md`;
- acknowledgement that the live OAuth client is already permanently **Public**
  and its verified live callback must not be moved for an isolated proof.

Each signing, create-only R2 publication, deployment, live-host Access
preflight, activation, repository visibility change, and stable promotion
remains a separate reviewed action. A prior decision does not silently approve
a later one. The approved public-cutover posture does not create a temporary
Access gate on `deploy.ankka.ai`.

## 2. Create a clean GitHub destination

Do not change the existing multi-ref repository to public. Preserve it under a
different name, keep it private, and create a new empty repository for the
public source. Do not use GitHub's import, template, mirror, or fork features;
they can copy history or relationships that are outside the sanitized root.

Before the first push, the local publication candidate must have exactly:

- one root commit;
- one local ref, `refs/heads/main`;
- no tags, remotes, tracked or reachable symlinks, gitlinks, generated release
  output, or dirty publishable files; and
- a green `npm ci`, `npm run check`, `git fsck --full --strict`, deterministic
  SBOM generation, and second byte-identical SBOM generation under the pinned
  Node/npm toolchain.

Create the destination as **private**, push only `main`, and wait for the real
GitHub CI job to pass. Then prove from a new clean clone and from the host API:

- the default branch is `main`;
- only `HEAD` and `refs/heads/main` are advertised;
- there are no pull requests, tags, Releases, Actions artifacts from an older
  repository, Packages, Pages deployment, or imported source archive; and
- the downloadable source archive contains only the one sanitized root.

A new repository makes these negative checks meaningful. Deleting visible
branches from the old repository would not prove that pull-request refs,
release assets, workflow logs, caches, or historical source archives are gone.

## 3. Protect or stage protection for `main`

After the first `CI` workflow has emitted its successful `check` job, check the
selected owner's plan before relying on private-repository rules. GitHub Free
supports branch and tag rulesets for public repositories; private enforcement
requires a plan that includes private-repository rules. If the destination's
private plan supports them, apply the active rulesets now. Otherwise record the
host-confirmed limitation and stage the exact settings for immediate application
after the visibility change in section 5. Do not accept contributions, merge a
change, create a release, or advertise the repository during that bounded
transition.

The active `main` ruleset must:

- require a pull request before merge;
- require the exact successful `check` status emitted by `.github/workflows/ci.yml`
  (select it from GitHub; do not type a guessed context);
- require resolved review conversations and linear history;
- block force pushes and branch deletion; and
- configure no always-allowed bypass. Any emergency bypass must be deliberate,
  time-bounded when the host supports that, and recorded before use.

For a single-maintainer preview, zero required approvals is acceptable until a
second maintainer exists; CI and the pull-request boundary still apply. Raise
the approval count when another active reviewer can satisfy it. Protect
`gateway-v*` tags from update or deletion, while allowing reviewed release
creation, and enable immutable Releases before publishing the first preview
artifact.

Before publication, enable dependency alerts and the least-privilege Actions
policy available to the private destination. Set the default workflow token to
read-only and prevent Actions from creating or approving pull requests. If the
private plan cannot express the final selected-actions policy, stage an exact
post-public allowlist for the three reviewed action SHAs in the checked-in
workflows; do not use a broad publisher wildcard as a substitute. Do not treat
public-only security controls as failed pre-publication gates: on GitHub.com,
free secret scanning, repository push protection, and private vulnerability
reporting become available only after this user-owned repository is public.
Enable and verify those controls immediately after the visibility change in
section 5. These settings supplement the source scanners; they do not replace
them.

## 4. Complete the promotion proof away from the live host

Keep `deploy.ankka.ai` without an Access application and on the exact disabled
shell while provider writes are being proven. Do not activate the live host or
temporarily put the old private-canary Access contract in front of it. Run
fault-injection, rate-limit, retained-key update/rollback, installation, and
removal proofs only on disposable customer resources and explicitly isolated
canary environments. The optional private Access contract in the installer
runbook may protect such an isolated canary, but it is not part of this live
cutover. In order:

1. establish the retained signing key and its independently recoverable backup;
2. build, sign, and create-only publish updater-capable N from the exact clean
   source commit;
3. apply/read back any optional isolated-canary protection, deploy the exact
   target-bound disabled shell, and use the redacted verifier's disabled mode
   to prove its callback/release exclusions. After activation, use active mode
   to prove the callback's exact missing-session rejection and application
   release responses. The schema-2 target parser must reject the live hostname,
   production Worker, and live OAuth client. Prove the live-host Logpush
   exclusion, and record the live hosted-zone `NEL`/`Report-To` policy and its
   approved residual metadata boundary;
4. exercise the reviewed active installer pinned to N only in the approved
   isolated proof environment;
5. prove anonymous-session, authenticated-session-read, and mutation rate
   limits, plus missing-binding failure, on isolated canaries;
6. complete install, employee tool call, N to N+1 update, deliberately broken
   candidate compensation, healthy rollback, same-session removal, returning
   removal, and independent zero-residue checks; and
7. verify the separate isolated-only OAuth callback, exact scopes,
   client-secret pair, and Private-client behavior without recording
   credentials or personal data. Do not modify the existing Public live client.

Any failure leaves the live disabled shell in place. Do not create or restore
Access on `deploy.ankka.ai`. If an isolated customer installation exists,
finish its receipt-authorized cleanup first when that remains safe; disabling
an installer does not remove customer resources.

## 5. Publish source before opening the installer

With `deploy.ankka.ai` still on the no-Access disabled shell:

1. review GitHub's visibility warning and change only the clean destination to
   public;
2. if private-plan limits deferred the `main` and `gateway-v*` rulesets, apply
   them immediately and verify they are active before accepting contributions,
   merging changes, or creating a release;
3. enable and verify private vulnerability reporting, secret scanning, and
   repository push protection; reverify dependency alerts; restrict Actions to
   the exact reviewed action SHAs in the checked-in workflows; keep the default
   workflow token read-only and pull-request approval disabled;
4. verify the security and conduct private-report links work, the dedicated
   detail-free fallback issue form is offered, Issues are enabled, and the
   `bug` and `enhancement` labels referenced by the public forms exist;
5. dispatch CodeQL on the exact public `main` commit and require a real pass;
6. re-run the current-tree and reachable-history scanners against a fresh clone
   of every advertised ref;
7. verify the security features and `main`/tag rules from an unprivileged view;
8. create a draft preview release targeting the exact reviewed commit, attach
   every precomputed asset including the CycloneDX SBOM, and verify the draft's
   target tag plus every local checksum before publication;
9. publish that draft as an immutable prerelease, never as Latest, then
   redownload and checksum every asset and verify the immutable attestation; and
10. verify that no private-history redirect, source archive, release, package,
   Pages site, or Actions artifact became associated with the clean repository.

If any public-host check fails, make the clean repository private again if the
host permits it, remove no evidence, and investigate. Never substitute a force
push for a fresh sanitized destination.

## 6. Open customer self-service

Only after the isolated promotion proof and public-source checks pass:

1. reverify the existing permanently Public live client's exact callback,
   verified domain, client-secret pair, and scopes; do not replace it with the
   separate isolated-only client or attempt a visibility transition;
2. prove the client metadata is available to an unrelated Cloudflare account
   without approving a provider write;
3. while the disabled shell is still serving, perform a complete paginated
   Access-app read and prove that no whole-host, path-specific, wildcard, or
   destination selector can cover `deploy.ankka.ai`; then prove cookie-free
   requests reach the exact disabled shell without an Access redirect;
4. deploy the exact reviewed active build as the separate activation action,
   then immediately run the full public-mode Access, signed-release, and
   behavior verifier;
5. prove the anonymous wizard, session-read bound, callback, signed release
   channel, and fixed 429/503 responses from a clean client; and
6. complete one unrelated-account install, real read-only tool call, and
   receipt-bound removal with independent zero-residue verification.

The post-activation public verifier must fail if the active Worker is disabled,
signed release discovery is unavailable, an Access application still covers
any installer
surface, or an application-level request is redirected to Access. Cloudflare's
hosted-zone `NEL`/`Report-To` headers are permitted and are neither success nor
failure evidence; their separately approved platform-metadata contract remains
in force. The pre-activation Access read and disabled-shell probes are separate
evidence; neither alone authorizes activation. Merely observing that no
whole-host Allow application exists is not success evidence.

Keeping Network Error Logging on for the Ankka-owned installer does not widen
the customer-runtime contract. Every signed customer Worker variant must still
pin `sendMetrics: false`, disabled dependency instrumentation and disabled
observability. Worker creation and read-back must still prove `logpush: false`
and an empty tail-consumer list. The customer payload must emit no Ankka
analytics beacon or `NEL`/`Report-To` response header. Cloudflare may apply a
customer's own zone-level reporting policy after the Worker responds; that is
customer/Cloudflare platform behavior and must not report to Ankka.

The reviewed active hosted build separately binds the fixed
`ankka_installer_funnel_v1` Analytics Engine dataset. Before public exposure,
prove its generated release/channel labels equal the embedded signed pin, query
one bounded time window, and reject any column or value outside the documented
event/outcome/flow allowlists. Use `_sample_interval`-weighted counts. The
rollback shell and all customer Worker variants must have no such binding. A
missing or failing analytics sink is expected to drop data and must not change
installer behavior.

## 7. Public-cutover rollback

If public exposure fails after activation:

1. stop inviting new sessions or issuing new installer links and identify every
   callback or receipt-owned mutation already in flight;
2. let each known in-flight operation reach a durable terminal result, or use
   its existing journal and receipt authority to recover and reconcile provider
   state; do not discard pending authority to make rollback faster;
3. independently verify the resulting customer resources and record any
   separately approved manual recovery that remains necessary;
4. deploy and verify the exact disabled installer shell; and
5. repeat the complete Access-app read and cookie-free probes, requiring zero
   Access coverage, `mutationsEnabled: false`, and the fixed disabled responses.

Do not create or recreate an Access application on `deploy.ankka.ai` during
rollback. OAuth **Public** promotion is permanent; the no-Access disabled shell
is the live fail-closed posture. Deploying it does not remove customer
resources, which is why receipt-owned work is finished or reconciled first.

The first public launch remains a preview. Do not promote the stable channel or
publish a non-prerelease/Latest release until CodeQL, an independent security
review, and a stable support policy have all passed.
