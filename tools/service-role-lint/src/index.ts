// tools/service-role-lint/src/index.ts
// Directory-walking entry point: lints every .ts/.tsx/.js/.jsx/.mts/.cts/
// .mjs/.cjs file under supabase/functions/** (build plan §4.7.1a; the
// extension list widened per B5, gate round 2 — Deno/Node ESM code
// commonly ships as .mts/.mjs, and a bypass file just needs an extension
// the walker skips).

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { lintSource, type LintResult } from "./lint.js";

const SOURCE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"]);

// ⛔ FIX (M3, post-P3a gate): "Stop excluding dist and __fixtures__ under
// supabase/functions except the lint's own fixtures dir, matched
// exactly." The old EXCLUDED_DIRS matched by BASENAME anywhere in the
// tree — a directory literally named `dist` or `__fixtures__` ANYWHERE
// under supabase/functions (not just the lint's own top-level one) was
// silently skipped, a real bypass: privileged code hidden in
// `supabase/functions/some-fn/dist/` (a plausible real build-output
// path, not even an attack) or `supabase/functions/some-fn/__fixtures__/`
// was never linted at all. Only `node_modules` (legitimate: vendored
// third-party code, never product code) is still excluded by basename.
// The lint's OWN fixtures directory is excluded by its EXACT resolved
// path — `<functionsRoot>/__fixtures__` — not by name, so a
// differently-located `__fixtures__` is linted like anything else.
const EXCLUDED_BASENAMES = new Set(["node_modules"]);

function listFiles(root: string): string[] {
  const out: string[] = [];
  const ownFixturesDir = resolve(root, "__fixtures__");
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const st = statSync(full);
      if (st.isDirectory()) {
        if (EXCLUDED_BASENAMES.has(entry)) continue;
        if (resolve(full) === ownFixturesDir) continue;
        walk(full);
      } else if (SOURCE_EXTENSIONS.has(entry.slice(entry.lastIndexOf(".")))) {
        out.push(full);
      }
    }
  };
  walk(root);
  return out;
}

// M3(4) (post-P3a re-gate): "resolve deno.json/import_map.json aliases
// and check what they point to." A Supabase Edge Function's import map
// can live at the function's own directory (`supabase/functions/<fn>/
// deno.json` or `import_map.json`) or be shared at the functions root
// (`supabase/functions/deno.json` / `import_map.json`) — both shapes are
// real: per-function config is the Supabase CLI default when scaffolding
// a function, a shared root one is common when several functions share
// the same aliases. Both are read and merged (per-function entries win
// on a key collision) rather than picking one location and missing an
// alias declared in the other.
//
// deno.json nests the map under a top-level `imports` key; import_map.json
// (the bare JSON import-map format) IS that object at the top level —
// both are read the same way here since deno.json's `imports` field uses
// the identical {specifier: target} shape.
function readImportMapFile(path: string): Record<string, string> {
  if (!existsSync(path)) return {};
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    const imports = typeof parsed === "object" && parsed !== null && typeof parsed.imports === "object" && parsed.imports !== null ? parsed.imports : parsed;
    const out: Record<string, string> = {};
    if (typeof imports === "object" && imports !== null) {
      for (const [k, v] of Object.entries(imports)) {
        if (typeof v === "string") out[k] = v;
      }
    }
    return out;
  } catch {
    // A malformed deno.json/import_map.json is a separate problem (JSON
    // validity is caught elsewhere in CI); the lint fails safe here by
    // resolving no aliases from it rather than crashing the whole run.
    return {};
  }
}

const importMapCache = new Map<string, Record<string, string>>();

function resolveImportMapForDir(dir: string, functionsRoot: string): Record<string, string> {
  const cached = importMapCache.get(dir);
  if (cached) return cached;
  const rootMap: Record<string, string> = {
    ...readImportMapFile(join(functionsRoot, "deno.json")),
    ...readImportMapFile(join(functionsRoot, "import_map.json")),
  };
  const localMap: Record<string, string> =
    resolve(dir) === resolve(functionsRoot)
      ? {}
      : { ...readImportMapFile(join(dir, "deno.json")), ...readImportMapFile(join(dir, "import_map.json")) };
  const merged = { ...rootMap, ...localMap };
  importMapCache.set(dir, merged);
  return merged;
}

export function lintDirectory(functionsRoot: string): LintResult[] {
  importMapCache.clear();
  const results: LintResult[] = [];
  for (const file of listFiles(functionsRoot)) {
    const source = readFileSync(file, "utf8");
    const relPath = relative(functionsRoot, file);
    const importMap = resolveImportMapForDir(dirname(file), functionsRoot);
    const findings = lintSource(source, file, { importMap });
    if (findings.length > 0) {
      results.push({ filePath: relPath, findings });
    }
  }
  return results;
}

export { lintSource } from "./lint.js";
export type { Finding, LintOptions, LintResult, RuleId } from "./lint.js";
