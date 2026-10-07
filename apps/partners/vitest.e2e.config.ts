import { defineConfig } from "vitest/config";

// The Playwright suite: a real Chromium, the built bundle served under its real `_headers`, a virtual WebAuthn authenticator and the real
// partner-session handler behind a fake database. Kept out of the default `vitest run` (config in vitest.config.ts excludes test/e2e/**) because
// it builds the bundle and launches a browser; `pnpm test` runs both.
export default defineConfig({
  test: {
    include: ["test/e2e/**/*.e2e.test.ts"],
    testTimeout: 60_000,
    hookTimeout: 120_000,
    fileParallelism: false,
  },
});
