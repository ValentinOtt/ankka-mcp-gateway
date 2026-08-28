#!/usr/bin/env node

/**
 * Retired live-host Access mutator.
 *
 * Public cutover requires deploy.ankka.ai to have no Ankka Access
 * application. This entrypoint intentionally cannot read credentials or make
 * network calls. Use apply-isolated-access.mjs with an exact, separately
 * reviewed non-live target file for an optional private canary.
 */

process.stderr.write(
  'Retired: this command cannot modify Access on the live installer host. ' +
  'Use the exact isolated-canary tooling for a reviewed non-live target.\n',
);
process.exitCode = 1;
