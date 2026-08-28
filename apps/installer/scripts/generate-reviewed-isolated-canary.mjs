#!/usr/bin/env node

/** Fail-closed CLI that can generate or validate only schema-2 isolated output. */

import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

import {
  runReviewedCanaryGeneratorCli,
  validateGeneratedReviewedIsolatedCanaryDirectory,
} from './generate-reviewed-canary.mjs';

const HELP = `Usage:\n` +
  `  node scripts/generate-reviewed-isolated-canary.mjs \\\n` +
  `    --pin <exact-secret-free-pin.json> \\\n` +
  `    --publication-result <exact-publication-receipt.json> \\\n` +
  `    --isolated-target <exact-outside-repository-target.json> \\\n` +
  `    --output-dir <new-directory>\n` +
  `  node scripts/generate-reviewed-isolated-canary.mjs \\\n` +
  `    --validate-output-dir <schema-2-isolated-directory>\n`;

export async function runReviewedIsolatedCanaryGeneratorCli({ argv, stderr, stdout }) {
  if (Array.isArray(argv) && argv.length === 1 && argv[0] === '--help') {
    stdout.write(HELP);
    return 0;
  }
  if (
    Array.isArray(argv) &&
    argv.length === 2 &&
    argv[0] === '--validate-output-dir' &&
    !argv[1].startsWith('--')
  ) {
    try {
      await validateGeneratedReviewedIsolatedCanaryDirectory(argv[1]);
      stdout.write('Reviewed isolated canary artifacts are exact and secret-free.\n');
      return 0;
    } catch {
      stderr.write('Reviewed isolated canary validation failed. No deploy or live call was attempted.\n');
      return 1;
    }
  }
  if (!Array.isArray(argv) || argv.filter((entry) => entry === '--isolated-target').length !== 1) {
    stderr.write('Reviewed isolated canary generation requires one exact isolated target.\n');
    return 1;
  }
  return runReviewedCanaryGeneratorCli({ argv, stderr, stdout });
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = await runReviewedIsolatedCanaryGeneratorCli({
    argv: process.argv.slice(2),
    stderr: process.stderr,
    stdout: process.stdout,
  });
}
