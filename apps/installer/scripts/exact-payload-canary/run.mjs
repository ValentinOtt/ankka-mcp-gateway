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
  'Use the receipt-bound installer design documented in docs/ARCHITECTURE.md.\n',
);
process.exitCode = 1;
