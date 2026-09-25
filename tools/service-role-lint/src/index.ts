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
// was never linted at all.
//
// ⛔ FIX (MEDIUM-2, post-P3a re-gate round 3): "importing from
// __fixtures__ bypasses the lint." The lint's OWN fixtures directory used
// to be excluded here by its exact resolved path
// (`<functionsRoot>/__fixtures__`) — closing the "differently-located
// __fixtures__" gap the M3 fix above already named, but leaving a
// DIFFERENT, real one open: a genuine function under supabase/functions
// could `import` a RELATIVE path INTO that excluded directory
// (`../__fixtures__/bad/g1-pinned-build-esm-sh.ts`), and since the lint
// never walked/read anything under __fixtures__ at all, it never saw —
// and never flagged — the file the import actually pulled in, while Deno
// would happily run it at deploy time. The fix is not a smarter
// exclusion: the lint's own fixtures no longer live anywhere under
// supabase/functions at all (moved to tools/service-role-lint/test/
// fixtures/**, this round) — nothing under supabase/functions is EVER
// excluded here now, closing this class of gap structurally rather than
// by carving out one more special case.
//
// ⛔ FIX (BLOCKING, post-P3a re-gate round 4): "node_modules is still
// excluded from the lint, but a function can import from it." The
// remaining `node_modules` basename exclusion (this round's OWN prior
// text above claimed it was "legitimate: vendored third-party code,
// never product code" -- wrong, exactly the same shape of bug M3/
// MEDIUM-2 already fixed for `dist`/`__fixtures__`) was a THIRD live
// bypass: `supabase/functions/some-fn/node_modules/x/admin.ts` (or a
// top-level `supabase/functions/node_modules/y/a.ts`) reading the
// service-role key was never walked, never read, never flagged --
// confirmed repro this round (N1, N2). Deno Edge Functions have no
// legitimate reason to ship a node_modules tree at all (no npm install
// step in the deploy path), so there is no "legitimate vendored code"
// case this exclusion was ever protecting -- removed entirely, same as
// `dist`/`__fixtures__` before it. Nothing under a linted functions root
// is excluded by basename any more (the check below is GONE; see the
// node_modules-presence finding inside listFiles's own walk instead).

// ⛔ FIX (follow-up, post-P3a re-gate round 2): "the lint walker must
// track visited real paths. A symlink loop should produce a clear
// finding (or be skipped), never a stack crash." Same fix as config.ts's
// own directory walker, applied here too — this is the walker that finds
// SOURCE files, and a symlink loop under supabase/functions would crash
// it exactly the same way.
function listFiles(root: string): { files: string[]; findings: LintResult[] } {
  const out: string[] = [];
  const problems: LintResult[] = [];
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
        // ⛔ FIX (BLOCKING, post-P3a re-gate round 4): the mere presence
        // of a `node_modules` directory ANYWHERE under the linted
        // functions root is itself a finding -- a Deno Edge Function
        // deploy has no npm-install step, so there is no legitimate
        // reason for one to exist here at all; this catches a
        // force-added vendored tree even if some future change re-adds a
        // name-based exclusion (this one, or a new one, would silently
        // reopen the N1/N2 bypass). Reported, but NOT skipped -- the walk
        // continues into it below, same as any other directory, so a
        // privileged file living inside it is still discovered and
        // flagged on its own content too (that is the actual N1/N2 fix;
        // this finding is belt-and-braces on top of it).
        if (entry === "node_modules") {
          const finding: Finding = {
            rule: "vendored-dependency-tree",
            message: `directory "${relative(root, full)}" is a node_modules tree -- Deno Edge Functions have no npm-install step and should never ship one; its mere presence is flagged regardless of contents (a force-added vendored tree, or a hiding place for privileged code, either way)`,
            line: 0,
            column: 0,
          };
          problems.push({ filePath: relative(root, full), findings: [finding] });
        }
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
