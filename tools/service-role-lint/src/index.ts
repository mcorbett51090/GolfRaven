// tools/service-role-lint/src/index.ts
// Directory-walking entry point: lints every .ts/.tsx/.js/.jsx/.mts/.cts/
// .mjs/.cjs file under supabase/functions/** (build plan §4.7.1a; the
// extension list widened per B5, gate round 2 — Deno/Node ESM code
// commonly ships as .mts/.mjs, and a bypass file just needs an extension
// the walker skips).

import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { buildConfigIndex, deriveRepoRoot } from "./config.js";
import { lintSource, type Finding, type LintResult } from "./lint.js";

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

// ⛔ FIX (follow-up, post-P3a re-gate round 2): "the lint walker must
// track visited real paths. A symlink loop should produce a clear
// finding (or be skipped), never a stack crash." Same fix as config.ts's
// own directory walker, applied here too — this is the walker that finds
// SOURCE files, and a symlink loop under supabase/functions would crash
// it exactly the same way.
function listFiles(root: string): { files: string[]; findings: LintResult[] } {
  const out: string[] = [];
  const problems: LintResult[] = [];
  const ownFixturesDir = resolve(root, "__fixtures__");
  const visitedRealPaths = new Set<string>();
  try {
    visitedRealPaths.add(realpathSync(root));
  } catch {
    // root itself unreadable/missing surfaces via readdirSync below.
  }
  const walk = (dir: string) => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (EXCLUDED_BASENAMES.has(entry)) continue;
        if (resolve(full) === ownFixturesDir) continue;
        let real: string;
        try {
          real = realpathSync(full);
        } catch {
          continue;
        }
        if (visitedRealPaths.has(real)) {
          const finding: Finding = {
            rule: "banned-import-specifier",
            message: `directory "${relative(root, full)}" resolves to an already-visited real path (a symlink loop or an alias of a directory already walked) -- not walked again`,
            line: 0,
            column: 0,
          };
          problems.push({ filePath: relative(root, full), findings: [finding] });
          continue;
        }
        visitedRealPaths.add(real);
        walk(full);
      } else if (SOURCE_EXTENSIONS.has(entry.slice(entry.lastIndexOf(".")))) {
        out.push(full);
      }
    }
  };
  walk(root);
  return { files: out, findings: problems };
}

// ⛔ FIX (M2 BLOCKING, post-P3a re-gate): "a pinned allow-list of ...
// exact target strings, kept as a committed fixture file compared by the
// lint, so adding a dependency is a reviewed diff." Read once, relative
// to this PACKAGE's own root (not the linted supabase/functions root, and
// not baked into the compiled dist/ output) so it works identically
// whether this runs from src/ (vitest/ts-node) or dist/ (the built CLI) —
// both sit exactly one directory below the package root.
const PINNED_IMPORT_TARGETS_PATH = resolve(import.meta.dirname, "..", "pinned-import-targets.json");

function loadPinnedImportTargets(): string[] {
  try {
    const parsed: unknown = JSON.parse(readFileSync(PINNED_IMPORT_TARGETS_PATH, "utf8"));
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === "string") : [];
  } catch {
    // Missing/malformed file fails CLOSED — an empty allow-list, not an
    // unchecked one; every bare specifier then fails to resolve, which is
    // the safe direction for this list to fail in.
    return [];
  }
}

// ⛔ REWRITE (M2 BLOCKING, post-P3a re-gate): the old root+local
// two-level merge is GONE, replaced entirely by tools/service-role-lint/
// src/config.ts's directory-walking ConfigIndex — see that module's own
// header comment for the confirmed bypasses (n1-n4, then R1-R5 + the
// lockfile, round 2) this closes.
//
// `repoRoot` (round 2, requirement 7): optional — when the caller omits
// it (every existing caller in this codebase's own tests), it is derived
// via config.ts's own `deriveRepoRoot` (walks up from functionsRoot
// looking for `.git`). The real CLI (below) always lets this default
// apply; a test that needs a SPECIFIC repoRoot (e.g. a synthetic /tmp
// tree simulating an ancestor config) passes one explicitly.
export function lintDirectory(functionsRoot: string, repoRoot?: string): LintResult[] {
  const root = resolve(functionsRoot);
  const pinnedImportTargets = new Set(loadPinnedImportTargets());
  const configIndex = buildConfigIndex(root, pinnedImportTargets, repoRoot ?? deriveRepoRoot(root));
  const results: LintResult[] = [...configIndex.results];
  const { files, findings: walkFindings } = listFiles(root);
  results.push(...walkFindings);
  for (const file of files) {
    const source = readFileSync(file, "utf8");
    const relPath = relative(root, file);
    const importMap = configIndex.resolveFor(file);
    const findings = lintSource(source, file, { importMap, functionsRoot: root, pinnedImportTargets: [...pinnedImportTargets] });
    if (findings.length > 0) {
      results.push({ filePath: relPath, findings });
    }
  }
  return results;
}

export { buildConfigIndex, deriveRepoRoot } from "./config.js";
export { lintSource } from "./lint.js";
export type { Finding, LintOptions, LintResult, RuleId } from "./lint.js";
