import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globalSetup: ["./test/global-setup.mjs"],
    testTimeout: 30_000,
    hookTimeout: 120_000,
  },
});
