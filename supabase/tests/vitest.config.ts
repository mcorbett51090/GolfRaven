// supabase/tests/vitest.config.ts
//
// Test-only Vite/Vitest config for supabase/tests/unit/**. NOT read by
// Deno at runtime and NOT scanned by tools/service-role-lint (that lint
// only ever walks supabase/functions/**, per its own index.ts) — this
// file exists purely so `vitest` (run from a workspace package that
// already depends on zod/@noble/hashes/tz-lookup, e.g. packages/rules)
// can resolve the SAME bare specifiers
// supabase/functions/_shared/scoring/vendor/*.js import, which Deno
// resolves at runtime through supabase/functions/deno.json's import map
// instead. `supabase/` is deliberately NOT a registered pnpm workspace
// package (see AGENTS.md's storage-tier contract; this repo's package
// boundaries are apps/*, packages/*, tools/* only), so these bare
// specifiers have no node_modules ancestry of their own to resolve
// against — this alias table is the test-time equivalent of Deno's
// import map, pointed at the exact same pinned versions
// tools/service-role-lint/pinned-import-targets.json names.
// Deliberately NOT `import { defineConfig } from "vitest/config"` —
// supabase/ has no node_modules ancestry of its own (see this file's own
// header), so even that import can't resolve when Vite's config loader
// reads this file directly. `defineConfig` is only an identity helper for
// type inference; a plain default-exported object works identically.
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

function resolveFrom(pkgDir: string, specifier: string): string {
  return require.resolve(specifier, { paths: [pkgDir] });
}

const RULES_PKG = new URL("../../packages/rules", import.meta.url).pathname;
const CATALOG_PKG = new URL("../../packages/catalog", import.meta.url).pathname;

export default {
  root: new URL(".", import.meta.url).pathname,
  resolve: {
    alias: {
      zod: resolveFrom(RULES_PKG, "zod"),
      "@noble/hashes/utils.js": resolveFrom(RULES_PKG, "@noble/hashes/utils.js"),
      "@noble/hashes/sha2.js": resolveFrom(RULES_PKG, "@noble/hashes/sha2.js"),
      "tz-lookup": resolveFrom(CATALOG_PKG, "tz-lookup"),
    },
  },
  test: {
    include: ["unit/**/*.test.ts"],
  },
};
