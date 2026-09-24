// tools/service-role-lint/src/config.ts
//
// ⛔ REWRITE (M2 BLOCKING, post-P3a re-gate): "the lint's import-map model
// diverges from what Deno actually loads." The reviewer confirmed four
// live bypasses against real Deno 2.5.2 while the OLD model (merge
// root-level deno.json + import_map.json with local-directory overrides,
// checked only at the function's own top directory) passed clean:
//   n1: a `scopes` key in the root deno.json -- never inspected at all.
//   n2: deno.json AND import_map.json both present in one directory --
//       the old code merged them with import_map.json spread SECOND (so
//       it silently WON on any key collision); real Deno uses deno.json
//       exclusively when both exist and never even reads import_map.json.
//   n3: a per-function `fn/deno.json` importing from `fn/lib/x.ts` (two
//       directory levels below functionsRoot) -- the old resolver only
//       ever checked `dirname(file)` merged with the ROOT, never the
//       INTERMEDIATE `fn/` level, so a two-level-deep standard Supabase
//       function layout silently fell through to the root config (or no
//       config at all).
//   n4: `deno.jsonc` -- never read at all; the old code only ever opened
//       exactly "deno.json" and "import_map.json" by literal name.
//
// This module is the fix: a from-scratch directory-walking config
// resolver that (1) finds and independently validates EVERY config file
// under supabase/functions, regardless of whether any source file
// currently imports through it; (2) fails a directory outright if more
// than one of deno.json/deno.jsonc/import_map.json is present in it
// (Deno's own precedence between them is real, but this lint refuses to
// silently pick a winner for the reviewer -- ambiguity is itself the
// finding); (3) allow-lists top-level config keys (imports,
// compilerOptions, lint, fmt, tasks) rather than deny-listing dangerous
// ones, so `scopes`, `importMap`, `links`, `workspace`, `patch`, `vendor`,
// and anything Deno adds later are ALL rejected by construction, not by
// enumeration; (4) resolves a given source file's effective import map by
// walking UP from its own directory to functionsRoot and using the
// NEAREST directory that has a (single, valid) config file -- exactly
// Deno's own directory-walk resolution, not a two-level root+local merge;
// (5) checks every `imports` TARGET against the committed
// pinned-import-targets.json allow-list at validation time, independent
// of whether anything currently imports it.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import type { Finding, LintResult } from "./lint.js";

/** The three config file shapes Deno recognises, in the order this module checks for them. */
const CONFIG_FILENAMES = ["deno.json", "deno.jsonc", "import_map.json"] as const;

// M2's own text, verbatim: "Default to an allow-list of known-safe
// top-level keys: imports, compilerOptions, lint, fmt, tasks. Anything
// else fails." Applied uniformly to all three file shapes -- an
// import_map.json's only legitimate top-level key under the WHATWG
// import-maps format is "imports" itself (plus the now-explicitly-banned
// "scopes"), which this same allow-list already covers without a second,
// format-specific list to keep in sync.
const ALLOWED_TOP_LEVEL_KEYS = new Set(["imports", "compilerOptions", "lint", "fmt", "tasks"]);

const EXCLUDED_BASENAMES = new Set(["node_modules"]);

/**
 * Strip `//` and `/* ... *‍/` comments from JSONC text, respecting string
 * literals (a comment-marker sequence INSIDE a JSON string is left
 * untouched). Trailing commas are NOT stripped -- a jsonc file relying on
 * them fails JSON.parse afterward and surfaces as a parse-error finding,
 * same as any other malformed config (fail closed, not fail silent).
 */
export function stripJsonComments(text: string): string {
  let out = "";
  let i = 0;
  let inString = false;
  while (i < text.length) {
    const c = text[i]!;
    const c2 = text[i + 1];
    if (inString) {
      out += c;
      if (c === "\\" && i + 1 < text.length) {
        out += text[i + 1];
        i += 2;
        continue;
      }
      if (c === '"') inString = false;
      i++;
      continue;
    }
    if (c === '"') {
      inString = true;
      out += c;
      i++;
      continue;
    }
    if (c === "/" && c2 === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && c2 === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

interface ConfigProblem {
  filePath: string; // absolute
  finding: Finding;
}

function configProblem(filePath: string, message: string): ConfigProblem {
  return { filePath, finding: { rule: "banned-import-specifier", message, line: 0, column: 0 } };
}

interface DirConfigResult {
  /** undefined = no valid map at this exact directory (either nothing present, or present-but-invalid/ambiguous). */
  importMap: Record<string, string> | undefined;
  /** true = a config file (or more than one) IS present here, so the caller must STOP walking up even though importMap may be undefined (Deno would resolve here, ambiguously or invalidly -- never silently fall through to an ancestor). */
  stopHere: boolean;
  problems: ConfigProblem[];
}

function validateSingleConfigFile(filePath: string, pinnedImportTargets: Set<string>): DirConfigResult {
  const problems: ConfigProblem[] = [];
  const raw = readFileSync(filePath, "utf8");
  const isJsonc = filePath.endsWith(".jsonc");
  let parsed: unknown;
  try {
    parsed = JSON.parse(isJsonc ? stripJsonComments(raw) : raw);
  } catch (err) {
    problems.push(configProblem(filePath, `failed to parse as JSON${isJsonc ? "C" : ""}: ${(err as Error).message}`));
    return { importMap: undefined, stopHere: true, problems };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    problems.push(configProblem(filePath, "does not contain a JSON object at the top level"));
    return { importMap: undefined, stopHere: true, problems };
  }
  const obj = parsed as Record<string, unknown>;

  // Requirement (M2): "Reject these outright: a scopes key; an importMap
  // key; any other resolution-affecting key ... Default to an allow-list
  // ... Anything else fails." One allow-list check covers every named
  // key (scopes, importMap, links, workspace, patch, vendor) AND anything
  // not yet named, by construction.
  for (const key of Object.keys(obj)) {
    if (!ALLOWED_TOP_LEVEL_KEYS.has(key)) {
      problems.push(
        configProblem(
          filePath,
          `disallowed top-level key "${key}" -- only ${[...ALLOWED_TOP_LEVEL_KEYS].join(", ")} are allowed (a resolution-affecting key like "scopes"/"importMap"/"links"/"workspace"/"patch"/"vendor", or any other key not on this allow-list, is rejected outright)`,
        ),
      );
    }
  }

  const importsRaw = obj.imports;
  const importMap: Record<string, string> = {};
  if (importsRaw !== undefined) {
    if (typeof importsRaw !== "object" || importsRaw === null || Array.isArray(importsRaw)) {
      problems.push(configProblem(filePath, `"imports" is not a JSON object`));
    } else {
      for (const [k, v] of Object.entries(importsRaw as Record<string, unknown>)) {
        if (typeof v !== "string") {
          problems.push(configProblem(filePath, `imports["${k}"] is not a string`));
          continue;
        }
        importMap[k] = v;
        // Requirement (M2): "Every imports target must be in
        // pinned-import-targets.json" -- validated here, at the config
        // file itself, independent of whether any source file currently
        // imports through this key at all (an unused-but-planted entry
        // is exactly the shape a reviewer needs to see flagged).
        if (v.startsWith("./") || v.startsWith("../")) {
          continue; // a relative-path target is checked for root-escape by lint.ts's own per-specifier pass, not here (this module has no notion of "which file" a relative target should resolve against until something actually imports it)
        }
        const upper = v.toUpperCase();
        if (upper.includes("@SUPABASE/") || upper.includes("SUPABASE-JS")) {
          problems.push(configProblem(filePath, `imports["${k}"] = "${v}" contains '@supabase/' or 'supabase-js'`));
        } else if (!pinnedImportTargets.has(v)) {
          problems.push(configProblem(filePath, `imports["${k}"] = "${v}" is not on the committed pinned-import-targets allow-list -- add it there as its own reviewed diff`));
        }
      }
    }
  }

  return { importMap, stopHere: true, problems };
}

/** All findings + effective-config-per-directory for one functionsRoot, computed once and reused across every linted file. */
export interface ConfigIndex {
  /** Config-file-level findings (bad keys, unpinned targets, ambiguous directories, …), grouped by file, ready to merge into lintDirectory's own LintResult[]. */
  results: LintResult[];
  /** Resolve the effective import map for a file at `filePath` (absolute). */
  resolveFor(filePath: string): Record<string, string>;
}

function listDirectories(root: string): string[] {
  const out: string[] = [resolve(root)];
  const ownFixturesDir = resolve(root, "__fixtures__");
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
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
        out.push(resolve(full));
        walk(full);
      }
    }
  };
  walk(root);
  return out;
}

/**
 * Build a ConfigIndex for `functionsRoot`: walks the WHOLE tree once,
 * finds and validates every deno.json/deno.jsonc/import_map.json
 * (regardless of whether anything imports through it -- requirement M2:
 * "Validate every config file ... regardless of importers"), and caches
 * each directory's own (possibly-undefined, possibly-ambiguous) result so
 * `resolveFor` only ever does an in-memory walk up the cache, never a
 * repeated filesystem read.
 */
export function buildConfigIndex(functionsRoot: string, pinnedImportTargets: Set<string>): ConfigIndex {
  const root = resolve(functionsRoot);
  const perDir = new Map<string, DirConfigResult>();
  const allProblems: ConfigProblem[] = [];

  for (const dir of listDirectories(root)) {
    const present = CONFIG_FILENAMES.map((name) => join(dir, name)).filter((p) => existsSync(p));
    if (present.length === 0) {
      perDir.set(dir, { importMap: undefined, stopHere: false, problems: [] });
      continue;
    }
    if (present.length > 1) {
      // Requirement (M2): "Fail if more than one of deno.json,
      // deno.jsonc and import_map.json exists at the same directory
      // level." Real Deno DOES have a defined precedence between these
      // (deno.json wins over import_map.json, n2) -- this lint
      // deliberately refuses to silently rely on that precedence for the
      // reviewer: an ambiguous directory is a finding, full stop, and
      // resolves to an EMPTY map (fail closed) rather than guessing which
      // file Deno would actually pick.
      const names = present.map((p) => relative(dir, p)).join(", ");
      const problems = present.map((p) => configProblem(p, `more than one config file present in this directory (${names}) -- ambiguous; keep only one (Deno has its own precedence between them, but this lint does not rely on it)`));
      perDir.set(dir, { importMap: undefined, stopHere: true, problems });
      allProblems.push(...problems);
      continue;
    }
    const result = validateSingleConfigFile(present[0]!, pinnedImportTargets);
    perDir.set(dir, result);
    allProblems.push(...result.problems);
  }

  const resolvedCache = new Map<string, Record<string, string>>();

  function resolveFor(filePath: string): Record<string, string> {
    let dir = resolve(dirname(filePath));
    const cached = resolvedCache.get(dir);
    if (cached) return cached;

    const chain: string[] = [];
    let cursor = dir;
    let result: Record<string, string> = {};
    for (;;) {
      chain.push(cursor);
      const own = perDir.get(cursor);
      if (own) {
        if (own.importMap !== undefined) {
          result = own.importMap;
          break;
        }
        if (own.stopHere) {
          // present but ambiguous/invalid at this exact level -- Deno
          // would resolve HERE (validly or not), never skip past it to
          // an ancestor; this lint fails closed with an empty map.
          result = {};
          break;
        }
      }
      if (cursor === root) {
        result = {};
        break;
      }
      const parent = dirname(cursor);
      if (parent === cursor) {
        result = {};
        break; // filesystem root guard
      }
      cursor = parent;
    }
    for (const d of chain) resolvedCache.set(d, result);
    return result;
  }

  const byFile = new Map<string, Finding[]>();
  for (const p of allProblems) {
    const relPath = relative(functionsRoot, p.filePath);
    const list = byFile.get(relPath) ?? [];
    list.push(p.finding);
    byFile.set(relPath, list);
  }
  const results: LintResult[] = [...byFile.entries()].map(([filePath, findings]) => ({ filePath, findings }));

  return { results, resolveFor };
}
