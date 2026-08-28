import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
    // Cryptographic state-machine tests and real Git/Wrangler subprocesses
    // contend heavily on small CI runners, so file-level parallelism is slower
    // and can starve otherwise bounded scenarios.
    maxWorkers: 1,
    // The largest journal-validation scenarios take 20–30 seconds on a warm
    // developer machine. Keep a generous but finite ceiling for cold runners.
    testTimeout: 60_000,
  },
});
