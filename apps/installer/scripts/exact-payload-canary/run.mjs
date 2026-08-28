#!/usr/bin/env node

/**
 * Retired operator entrypoint.
 *
 * This historical harness accepted editable Worker names and local state as
 * deletion authority. Its completed disposable-account result remains useful
 * evidence, but the executable is not a safe public mutation workflow.
 */

process.stderr.write(
  'Retired: the exact-payload canary was a completed one-off probe, not a receipt-bound operator workflow. ' +
  'Use the approval-bound canary lifecycle or reviewed hosted-installer runbook.\n',
);
process.exitCode = 1;
