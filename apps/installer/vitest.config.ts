import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
    // Several suites intentionally exercise real Git and Wrangler subprocesses.
    // Capping file workers prevents those subprocesses from starving one another
    // on small CI runners while retaining parallel coverage.
    maxWorkers: 2,
    testTimeout: 10_000,
  },
});
