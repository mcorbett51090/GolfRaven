import { defineConfig } from "vitest/config";

export default defineConfig({
  define: { __GR_PARTNERS_API_BASE__: JSON.stringify("https://api.example.test/functions/v1") },
  test: {
    include: ["test/**/*.test.ts"],
    exclude: ["test/e2e/**", "node_modules/**"],
    testTimeout: 30_000,
    hookTimeout: 120_000,
  },
});
