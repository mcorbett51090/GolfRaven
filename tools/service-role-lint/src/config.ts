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
// ⛔ FURTHER REWRITE (BLOCKING, post-P3a re-gate round 2): "config-level
// remaps and lockfile redirects." A SECOND round confirmed five more live
// bypasses even after the first rewrite closed n1-n4:
//   R1: a KEY inside the REVIEWED supabase/functions/deno.json that is
//       itself a relative path ("./fn/lib/x.ts") remapping a specific
//       in-tree import to an escaping relative TARGET
//       ("../../outside/admin.ts") -- the old model validated every
//       target's PIN status but never validated the KEY's own shape, and
//       skipped validating a relative TARGET entirely (deferring to
//       lint.ts's per-specifier escape check, which only ever runs for a
//       specifier some source file actually writes -- an unused-but-
//       planted remap entry was invisible to it, same class of gap n1-n4
//       closed for `imports` targets generally).
//   R2: a repo-ROOT `{"workspace": [...], "imports": {...}}` applies its
//       own remap to a workspace MEMBER (supabase/functions) -- entirely
//       outside the directory-walk-up chain the old model ever looked at
//       (it started walking FROM functionsRoot, never considered
//       anything ABOVE it).
//   R3/R5: a `repo/deno.json` / `supabase/deno.json` ABOVE functionsRoot
//       remaps a path INSIDE it -- same root cause as R2: nothing above
//       functionsRoot was ever in scope.
//   Lockfile: a `deno.lock` next to a config, with a `"redirects"` table
//       swapping a pinned target's URL for an attacker's -- deno.lock was
//       never read at all.
//
// This module closes all of the above. The full model, current as of
// this round:
//   (1) find and independently validate EVERY deno.json/deno.jsonc/
//       import_map.json under functionsRoot, regardless of whether any
//       source file currently imports through it;
//   (2) fail a directory outright if more than one of those three is
//       present in it (ambiguity is itself the finding, not silently
//       resolved by replicating Deno's own precedence);
//   (3) allow-list top-level config keys (imports, compilerOptions, lint,
//       fmt, tasks) rather than deny-list dangerous ones, so scopes,
//       importMap, links, workspace, patch, vendor, and anything Deno
//       adds later are ALL rejected by construction;
//   (4) every import-map KEY must be a bare specifier -- a key starting
//       with "./"/"../"/"/", or containing ":", is rejected outright
//       (closes R1's own remap vector, independent of what its target
//       is);
//   (5) every import-map TARGET must be an EXACT string on the committed
//       pinned-import-targets.json allow-list -- a relative or
//       absolute-path target is banned outright, no exceptions (in-tree
//       code is imported by a relative specifier directly in source,
//       never routed through the map at all);
//   (6) resolve a given source file's effective import map by walking UP
//       from its own directory to functionsRoot and using the NEAREST
//       directory that has a single, valid config file -- Deno's own
//       directory-walk resolution, not a two-level root+local merge;
//   (7) walk from functionsRoot's PARENT up to repoRoot (inclusive) and
//       flag the mere PRESENCE of any deno.json/deno.jsonc/
//       import_map.json/deno.lock found there -- closes R2/R3/R5
//       structurally: this lint does not attempt to resolve or "safely
//       merge" an ancestor config, it refuses to allow one to exist at
//       all in the reviewed tree;
//   (8) validate every deno.lock found anywhere under functionsRoot: a
//       non-empty "redirects" table is banned outright; every "remote"
//       key must itself be an exact pinned target (the conservative,
//       statically-decidable subset of "pinned target or a URL under a
//       pinned target's exact module graph" — see validateLockFile's own
//       note); "workspace" must carry no "imports"/"importMap" override;
//       no top-level key besides version/remote/specifiers/redirects/
//       workspace is allowed.
//
// Follow-up (post-P3a re-gate round 2): the directory walker tracks
// REAL (symlink-resolved) paths visited, so a symlink loop produces one
// clear finding and stops recursing there, instead of a stack overflow.

import { existsSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import type { Finding, LintResult } from "./lint.js";

/** The three config file shapes Deno recognises, in the order this module checks for them. */
const CONFIG_FILENAMES = ["deno.json", "deno.jsonc", "import_map.json"] as const;
const LOCK_FILENAME = "deno.lock";
/** Checked during the ANCESTOR scan (requirement 7) -- config files AND the lockfile, since either can affect resolution inside functionsRoot. */
const ANCESTOR_CHECK_FILENAMES = [...CONFIG_FILENAMES, LOCK_FILENAME] as const;

// M2's own text, verbatim: "Default to an allow-list of known-safe
// top-level keys: imports, compilerOptions, lint, fmt, tasks. Anything
// else fails." Applied uniformly to all three file shapes -- an
// import_map.json's only legitimate top-level key under the WHATWG
// import-maps format is "imports" itself (plus the now-explicitly-banned
// "scopes"), which this same allow-list already covers without a second,
// format-specific list to keep in sync.
const ALLOWED_TOP_LEVEL_KEYS = new Set(["imports", "compilerOptions", "lint", "fmt", "tasks"]);

/** deno.lock's own allowed top-level keys (round 2, "Lockfile" requirement). */
const LOCK_ALLOWED_TOP_LEVEL_KEYS = new Set(["version", "remote", "specifiers", "redirects", "workspace"]);

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

// ⛔ FIX (BLOCKING round 2, R1): "import-map keys must be bare
// specifiers. Reject any key that starts with './', '../' or '/', or
// contains ':'." A relative/absolute-path-shaped or scheme-qualified KEY
// can remap a SPECIFIC in-tree or scheme-based import to an arbitrary
// target, independent of whether the map's other entries look clean.
function isValidImportMapKey(key: string): boolean {
  if (key.startsWith("./") || key.startsWith("../") || key.startsWith("/")) return false;
  if (key.includes(":")) return false;
  return true;
}

// ⛔ FIX (BLOCKING round 2, R1/R3/R5): "import-map targets must be exact
// strings in pinned-import-targets.json. Ban relative targets entirely;
// in-tree code is imported by relative path directly, never via the
// map." Unconditional now -- the PRIOR version skipped validating a
// relative target altogether ("checked for root-escape by lint.ts's own
// per-specifier pass" -- which only ever runs for a specifier some
// source file actually WRITES; an unused-but-planted remap entry was
// invisible to it).
function isRelativeOrAbsoluteTarget(target: string): boolean {
  return target.startsWith("./") || target.startsWith("../") || target.startsWith("/");
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
        // Requirement (round 2, R1): keys must be bare specifiers. An
        // invalid key is excluded from the returned map entirely (fails
        // closed -- nothing can resolve THROUGH it), independent of the
        // finding being reported.
        if (!isValidImportMapKey(k)) {
          problems.push(
            configProblem(
              filePath,
              `imports key "${k}" is not a bare specifier -- a key starting with "./"/"../"/"/ ", or containing ":", can remap a relative or scheme-qualified import to an unreviewed target (R1, post-P3a re-gate round 2)`,
            ),
          );
          continue;
        }
        importMap[k] = v;
        // Requirement (M2, tightened round 2): "Every imports target
        // must be in pinned-import-targets.json ... Ban relative targets
        // entirely." Validated here, at the config file itself,
        // independent of whether any source file currently imports
        // through this key at all (an unused-but-planted entry is
        // exactly the shape a reviewer needs to see flagged).
        if (isRelativeOrAbsoluteTarget(v)) {
          problems.push(
            configProblem(
              filePath,
              `imports["${k}"] = "${v}" is a relative/absolute-path target -- banned outright (round 2, R1/R3/R5): in-tree code is imported by a relative specifier directly in source, never routed through the import map`,
            ),
          );
          continue;
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

// ⛔ FIX (BLOCKING round 2, "Lockfile"): deno.lock validation. Every
// key in "remote" must be "a pinned target or a URL under a pinned
// target's exact module graph" per the decision text -- deciding the
// latter statically (parsing an arbitrary remote URL's own module graph
// shape) is not reliably possible from the lockfile alone, so this
// module takes the conservative branch the decision itself offers: "If
// that's hard to decide statically, require remote keys ⊆ the pinned
// list." A remote key that is a sub-path of a pinned target's own host
// (e.g. a transitive dependency esm.sh serves under the same request)
// will therefore also need pinning explicitly -- stricter than the
// module-graph-aware alternative, deliberately, since silently trusting
// "looks like a subpath of a pinned host" is exactly the shape of
// reasoning that let host-trust (M2's own original bypass) through.
function containsKeyDeep(value: unknown, keyName: string): boolean {
  if (value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some((v) => containsKeyDeep(v, keyName));
  const obj = value as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(obj, keyName)) return true;
  return Object.values(obj).some((v) => containsKeyDeep(v, keyName));
}

function validateLockFile(filePath: string, pinnedImportTargets: Set<string>): ConfigProblem[] {
  const problems: ConfigProblem[] = [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(filePath, "utf8"));
  } catch (err) {
    problems.push(configProblem(filePath, `failed to parse deno.lock as JSON: ${(err as Error).message}`));
    return problems;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    problems.push(configProblem(filePath, "deno.lock does not contain a JSON object at the top level"));
    return problems;
  }
  const obj = parsed as Record<string, unknown>;

  for (const key of Object.keys(obj)) {
    if (!LOCK_ALLOWED_TOP_LEVEL_KEYS.has(key)) {
      problems.push(
        configProblem(filePath, `deno.lock has a disallowed top-level key "${key}" -- only ${[...LOCK_ALLOWED_TOP_LEVEL_KEYS].join(", ")} are allowed`),
      );
    }
  }

  // "allowed only if redirects is absent or empty" -- a non-empty
  // redirects table is exactly the confirmed live bypass: it swaps a
  // pinned target's resolved URL for arbitrary code at fetch time,
  // entirely independent of what deno.json itself says.
  const redirects = obj.redirects;
  if (redirects !== undefined) {
    const isEmptyObject = typeof redirects === "object" && redirects !== null && !Array.isArray(redirects) && Object.keys(redirects as object).length === 0;
    if (!isEmptyObject) {
      problems.push(configProblem(filePath, `deno.lock has a non-empty "redirects" table -- a redirect can swap a pinned target's resolved URL for arbitrary code and is banned outright`));
    }
  }

  const remote = obj.remote;
  if (remote !== undefined) {
    if (typeof remote !== "object" || remote === null || Array.isArray(remote)) {
      problems.push(configProblem(filePath, `deno.lock "remote" is not a JSON object`));
    } else {
      for (const key of Object.keys(remote as Record<string, unknown>)) {
        if (!pinnedImportTargets.has(key)) {
          problems.push(
            configProblem(
              filePath,
              `deno.lock "remote" key "${key}" is not on the committed pinned-import-targets allow-list (every remote entry must itself be an exact pinned target -- see this module's own note on deciding "under a pinned target's module graph" statically)`,
            ),
          );
        }
      }
    }
  }

  // "workspace (with no imports overrides)" -- a shallow recursive scan
  // for either key name anywhere inside the value, since this project's
  // deno.lock has no legitimate reason to carry either.
  const workspace = obj.workspace;
  if (workspace !== undefined && (containsKeyDeep(workspace, "imports") || containsKeyDeep(workspace, "importMap"))) {
    problems.push(configProblem(filePath, `deno.lock "workspace" contains an "imports"/"importMap" override -- not allowed; import-map entries must live only in the reviewed deno.json itself`));
  }

  return problems;
}

/** All findings + effective-config-per-directory for one functionsRoot, computed once and reused across every linted file. */
export interface ConfigIndex {
  /** Config-file-level findings (bad keys, unpinned targets, ambiguous directories, ancestor configs, lockfile problems, symlink loops, …), grouped by file, ready to merge into lintDirectory's own LintResult[]. */
  results: LintResult[];
  /** Resolve the effective import map for a file at `filePath` (absolute). */
  resolveFor(filePath: string): Record<string, string>;
}

// ⛔ FIX (follow-up, post-P3a re-gate round 2): "the lint walker must
// track visited real paths. A symlink loop should produce a clear
// finding (or be skipped), never a stack crash." Each directory's
// REALPATH (symlinks resolved) is recorded before recursing into it; a
// directory whose realpath was already visited is reported once and NOT
// walked again, instead of recursing forever.
function listDirectories(root: string): { dirs: string[]; problems: ConfigProblem[] } {
  const out: string[] = [resolve(root)];
  const problems: ConfigProblem[] = [];
  const ownFixturesDir = resolve(root, "__fixtures__");
  const visitedRealPaths = new Set<string>();
  try {
    visitedRealPaths.add(realpathSync(root));
  } catch {
    // root itself unreadable/missing is a separate, pre-existing failure
    // mode (the caller's readdirSync below will surface it); nothing more
    // to do here.
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
      if (!st.isDirectory()) continue;
      if (EXCLUDED_BASENAMES.has(entry)) continue;
      if (resolve(full) === ownFixturesDir) continue;
      let real: string;
      try {
        real = realpathSync(full);
      } catch {
        continue;
      }
      if (visitedRealPaths.has(real)) {
        problems.push(
          configProblem(full, `directory "${relative(root, full)}" resolves to an already-visited real path (a symlink loop or an alias of a directory already walked) -- not walked again`),
        );
        continue;
      }
      visitedRealPaths.add(real);
      out.push(resolve(full));
      walk(full);
    }
  };
  walk(root);
  return { dirs: out, problems };
}

// ⛔ FIX (BLOCKING round 2, requirement 7): "Configs above the functions
// root. Walk from functionsRoot up to the repo root ... Any deno.json,
// deno.jsonc, import_map.json or deno.lock found above functionsRoot is
// a finding." Closes R2/R3/R5 structurally: this lint does not attempt
// to read, merge or "safely" resolve an ancestor config -- its mere
// presence anywhere between functionsRoot's own parent and repoRoot is
// itself the finding, since Deno's own directory-walk resolution means
// ANY of them could affect resolution inside functionsRoot regardless of
// content.
function scanAncestors(functionsRoot: string, repoRoot: string): ConfigProblem[] {
  const problems: ConfigProblem[] = [];
  const root = resolve(functionsRoot);
  const repo = resolve(repoRoot);
  if (root === repo) return problems; // functionsRoot IS the repo root -- nothing above it to scan

  let dir = dirname(root);
  for (;;) {
    for (const name of ANCESTOR_CHECK_FILENAMES) {
      const p = join(dir, name);
      if (existsSync(p)) {
        problems.push(
          configProblem(
            p,
            `a ${name} file exists ABOVE the functions root -- disallowed regardless of content (round 2, R2/R3/R5): Deno resolves configs by walking up from the linted file, so anything above functionsRoot can affect resolution inside it`,
          ),
        );
      }
    }
    if (dir === repo) break;
    const parent = dirname(dir);
    if (parent === dir) break; // filesystem root guard -- repoRoot was never actually an ancestor of functionsRoot
    dir = parent;
  }
  return problems;
}

/**
 * ⛔ FIX (BLOCKING round 2, requirement 7): "the lint takes an explicit
 * repoRoot option, so tests can build /tmp trees, and the CLI derives the
 * root." Walks up from `startDir` looking for a directory containing
 * `.git` (a file for a worktree, a directory for a normal checkout --
 * existence alone is checked either way). Falls back to `startDir` itself
 * (no ancestor ever scanned) if none is found by the filesystem root --
 * fail-safe in the sense that it never THROWS, but note this fallback
 * means no ancestor-config protection at all in that case; a real repo
 * checkout always has `.git` somewhere above `supabase/functions`.
 */
export function deriveRepoRoot(startDir: string): string {
  let dir = resolve(startDir);
  for (;;) {
    if (existsSync(join(dir, ".git"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) return resolve(startDir);
    dir = parent;
  }
}

/**
 * Build a ConfigIndex for `functionsRoot`: walks the WHOLE tree once,
 * finds and validates every deno.json/deno.jsonc/import_map.json/
 * deno.lock (regardless of whether anything imports through it --
 * requirement M2: "Validate every config file ... regardless of
 * importers"), scans from functionsRoot up to `repoRoot` for a
 * disallowed ancestor config/lockfile, and caches each directory's own
 * (possibly-undefined, possibly-ambiguous) result so `resolveFor` only
 * ever does an in-memory walk up the cache, never a repeated filesystem
 * read.
 */
export function buildConfigIndex(functionsRoot: string, pinnedImportTargets: Set<string>, repoRoot: string): ConfigIndex {
  const root = resolve(functionsRoot);
  const perDir = new Map<string, DirConfigResult>();
  const allProblems: ConfigProblem[] = [];

  const { dirs, problems: walkProblems } = listDirectories(root);
  allProblems.push(...walkProblems);

  for (const dir of dirs) {
    const present = CONFIG_FILENAMES.map((name) => join(dir, name)).filter((p) => existsSync(p));
    if (present.length === 0) {
      perDir.set(dir, { importMap: undefined, stopHere: false, problems: [] });
    } else if (present.length > 1) {
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
    } else {
      const result = validateSingleConfigFile(present[0]!, pinnedImportTargets);
      perDir.set(dir, result);
      allProblems.push(...result.problems);
    }

    const lockPath = join(dir, LOCK_FILENAME);
    if (existsSync(lockPath)) {
      const lockProblems = validateLockFile(lockPath, pinnedImportTargets);
      allProblems.push(...lockProblems);
    }
  }

  allProblems.push(...scanAncestors(root, repoRoot));

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
    const relPath = relative(root, p.filePath);
    const list = byFile.get(relPath) ?? [];
    list.push(p.finding);
    byFile.set(relPath, list);
  }
  const results: LintResult[] = [...byFile.entries()].map(([filePath, findings]) => ({ filePath, findings }));

  return { results, resolveFor };
}
