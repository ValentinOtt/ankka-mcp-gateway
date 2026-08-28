#!/usr/bin/env node

/**
 * Retired verifier entrypoint.
 *
 * A matching zone rule is not evidence of protection for a Workers Custom
 * Domain. Keeping the old verifier would allow an ineffective configuration
 * to look release-ready, so it fails closed and points at the Access proof.
 */

process.stderr.write(
  'Retired: zone WAF and rate-limit verification is inapplicable to this Workers Custom Domain. ' +
  'Use scripts/edge-gate/verify-access.mjs.\n',
);
process.exitCode = 1;
