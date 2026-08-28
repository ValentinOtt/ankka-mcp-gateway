#!/usr/bin/env node

/**
 * Retired operator entrypoint.
 *
 * Zone WAF and rate-limit phases do not protect the installer's Workers
 * Custom Domain. The former implementation could replace whole live phase
 * entrypoints, so leaving it executable would turn obsolete guidance into a
 * production footgun. Cloudflare Access is the reviewed control.
 */

process.stderr.write(
  'Retired: zone WAF and rate-limit rules do not protect this Workers Custom Domain. ' +
  'Use scripts/edge-gate/apply-access.mjs and verify-access.mjs.\n',
);
process.exitCode = 1;
