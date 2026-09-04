import { defineConfig } from 'vitest/config';

// Live harnesses run real Cloudflare calls against the test account. They are
// never part of `npm run check`; run them explicitly with
// `npx vitest run --config vitest.live.config.ts` and the ANKKA_LIVE_* env.
export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
    include: ['test-live/**/*.live.ts'],
    maxWorkers: 1,
    testTimeout: 600_000,
    hookTimeout: 600_000,
  },
});
