import { defineConfig } from 'vitest/config';

// Opt-in, private test account only. Never part of ordinary checks.
export default defineConfig({
  test: { include: ['test-live/**/*.live.ts'], environment: 'node', maxWorkers: 1, testTimeout: 60000 },
});
