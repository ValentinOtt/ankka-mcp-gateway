#!/usr/bin/env node

/**
 * Retired operator entrypoint.
 *
 * The historical probe discovered useful provider-contract facts, but its
 * account-wide name/marker sweep was not bound to one reviewed receipt. A
 * copied command or mistaken account selection could therefore delete an
 * unrelated gateway. Live mutation now belongs exclusively to the
 * approval-bound, receipt-owned canary and installer flows.
 */

process.stderr.write(
  'Retired: this live-contract probe was not bound to one exact reviewed receipt. ' +
  'Use the receipt-bound installer design documented in docs/ARCHITECTURE.md.\n',
);
process.exitCode = 1;
