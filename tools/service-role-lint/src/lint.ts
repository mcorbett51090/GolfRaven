// tools/service-role-lint/src/lint.ts
//
// AST-based check over the TS/JS in supabase/functions/** (build plan
// §4.7.1a, docs/golf-trails/02-build-plan.md:1197-1205).
//
// ⛔ REWRITE (MEDIUM 3, post-P3a re-gate): the previous version banned a
// growing list of individual SYNTACTIC SHAPES for reading Deno.env/
// process.env (a deny-list of bypasses). Every round of hardening added
// more shapes to the list, and every round left new ones open — the
// re-gate named twelve that still passed: `(Deno as any).env.get`, a
// function returning `Deno.env`, `Reflect.get(Deno, "env")`,
// `Deno["env"]`, `.call`, nested destructuring, spread, `(0,
// Deno.env.get)`, `eval`, an import-map alias "supabase",
// `@supabase/postgrest-js`, `(self as any).Deno`. A deny-list of shapes
// is structurally the wrong tool here: there is no bound on how many
// shapes JS/TS syntax offers to reach the SAME two global bindings.
//
// This version inverts the model to an ALLOW-list: ANY reference to the
// identifier `Deno` or `process` (or the indirection points `globalThis`/
// `self`/`window`) is an error, with EXACTLY ONE syntactic exception —
// `Deno.env.get("<literal>")` where the literal is on a small public
// allow-list. Nothing else about Deno/process is ever legitimate outside
// `_shared/privileged.ts`, so nothing else needs a name to be banned by;
// nothing needs enumerating, and a new syntactic bypass shape has no
// surface to land on — nSyntax that isn't the one sanctioned shape is,
// structurally, a reference to a banned identifier, full stop.
//
// The five requirements this rewrite implements (post-P3a re-gate,
// MEDIUM 3):
//   (1) any reference to `Deno`/`process` is an error unless it is
//       EXACTLY `Deno.env.get("<literal>")` with the literal on the
//       public allow-list; `globalThis`/`self`/`window` (indirection
//       points to reach them) are banned outright, unconditionally.
//   (2) any string literal or template chunk containing SERVICE_ROLE or
//       DB_URL (case-insensitive) is an error, everywhere in the file —
//       independent of (1), so a secret substring inside a completely
//       different call shape (not even touching Deno) is still caught.
//   (3) every `@supabase/*` specifier (the whole scope, not a fixed list
//       of package names under it) and every Postgres driver specifier is
//       banned, after normalising versioned/CDN/registry-prefixed forms.
//   (4) deno.json / import_map.json aliases are resolved (by the caller,
//       via the optional `importMap` parameter — see index.ts) and
//       checked against the same banned-specifier logic.
//   (5) `eval(...)`, `new Function(...)`, and `Function(...)` are banned
//       outright — an indirect way to run string-built code that could
//       itself reach Deno/process without ever naming them syntactically
//       in a form this (or any static) analysis could otherwise see.
//
// The exemption for `supabase/functions/_shared/privileged.ts` is an
// EXACT path-segment match, not an `endsWith` string check — a file named
// e.g. `evil_shared/privileged.ts` must NOT be exempted just because the
// string "_shared/privileged.ts" is a suffix of its path.
//
// Uses a real parser (@typescript-eslint/typescript-estree, pinned)
// rather than a method-name grep, per the plan's own explicit
// requirement.

import { AST_NODE_TYPES, parse, type TSESTree } from "@typescript-eslint/typescript-estree";

export type RuleId =
  | "service-role-construction"
  | "privileged-call-outside-withOwnership"
  | "banned-import-specifier"
  | "banned-global-reference"
  | "non-literal-env-access"
  | "literal-secret-env-var"
  | "secret-substring-in-literal"
  | "globalthis-access"
  | "withownership-shadowed"
  | "reexport-of-privileged-symbol"
  | "raw-fetch-with-secret"
  | "dynamic-code-execution"
  | "parse-error";

export interface Finding {
  rule: RuleId;
  message: string;
  line: number;
  column: number;
}

export interface LintResult {
  filePath: string;
  findings: Finding[];
}

/** Resolved import-map aliases (bare specifier -> target), per requirement (4). */
export interface LintOptions {
  importMap?: Record<string, string>;
  /**
   * Absolute path of the supabase/functions root, for the relative-import
   * escape check (post-P3a re-gate M1, g5). index.ts's directory walker
   * always supplies this; a standalone `lintSource(source, path)` call
   * (e.g. in a unit test) may omit it, which simply skips that one check.
   */
  functionsRoot?: string;
  /**
   * ⛔ FIX (M2 BLOCKING, post-P3a re-gate): "the lint trusts hosts and
   * registries, not modules ... switch to an explicit module allow-list;
   * drop host trust entirely ... a pinned allow-list of exact target
   * strings, kept as a committed fixture file." The exact set of
   * import-map TARGET strings a bare specifier is ever allowed to resolve
   * to — index.ts reads this from the committed
   * tools/service-role-lint/pinned-import-targets.json and always
   * supplies it for a real directory-walk run; a standalone
   * `lintSource(source, path)` call that omits it simply has an empty
   * allow-list (every bare specifier fails to resolve, fail-closed, not
   * fail-open).
   */
  pinnedImportTargets?: string[];
}

/** The one exact file allowed to do any of this (build plan line 1189). */
const EXEMPT_SEGMENTS = ["supabase", "functions", "_shared", "privileged.ts"];

/** Env var name substrings that mark a client/URL as privileged (case-insensitive). */
const SECRET_ENV_MARKERS = ["SERVICE_ROLE", "DB_URL"];

// Requirement (1): "a small allow-list of public vars" — the ONLY literal
// keys `Deno.env.get(...)` may ever read outside privileged.ts.
const PUBLIC_ENV_VAR_ALLOWLIST = new Set(["SUPABASE_URL", "SUPABASE_ANON_KEY", "ENVIRONMENT", "NODE_ENV", "DENO_ENV"]);

// Requirement (1): the two identifiers that are NEVER legitimate outside
// privileged.ts, except through the one sanctioned shape.
const BANNED_GLOBAL_IDENTIFIERS = new Set(["Deno", "process"]);
// Indirection points that can be used to REACH Deno/process (or anything
// else global) without naming them as a bare identifier reference —
// banned unconditionally, regardless of what they're used for.
const INDIRECTION_IDENTIFIERS = new Set(["globalThis", "self", "window"]);
// ⛔ FIX (post-P3a re-gate M1, g4): Worker/SharedWorker construct and run
// arbitrary source (including a `data:`/`blob:` URL — see
// isDataOrBlobSpecifier below), with no import specifier and no static
// call shape this lint's other rules would otherwise see. Banned
// unconditionally, no exemption — there is no legitimate reason for
// supabase/functions product code to construct one.
const BANNED_UNCONDITIONAL_IDENTIFIERS = new Set(["Worker", "SharedWorker"]);

function mentionsSecretSubstring(text: string): boolean {
  const upper = text.toUpperCase();
  return SECRET_ENV_MARKERS.some((m) => upper.includes(m));
}

function isPublicEnvVar(name: string): boolean {
  return PUBLIC_ENV_VAR_ALLOWLIST.has(name);
}

// Requirement (3): "versioned or URL specifiers ... match by normalised
// package name, not an anchored regex." normalizePackageSpecifier strips
// a CDN/registry host prefix, a `npm:`/`jsr:` scheme, and a trailing
// `@<version>`, so the same banned-name/scope check catches every
// dressed-up form of the same package.
const KNOWN_REGISTRY_HOST_PREFIXES = [
  "esm.sh/",
  "cdn.skypack.dev/",
  "cdn.jsdelivr.net/npm/",
  "unpkg.com/",
  "deno.land/x/",
  "jsr.io/",
];

function normalizePackageSpecifier(spec: string): string {
  let s = spec.replace(/^https?:\/\//, "");
  for (const prefix of KNOWN_REGISTRY_HOST_PREFIXES) {
    if (s.startsWith(prefix)) {
      s = s.slice(prefix.length);
      break;
    }
  }
  // esm.sh pinned-build tag, e.g. "esm.sh/v135/@supabase/supabase-js@2" —
  // confirmed this round as a real bypass (post-P3a re-gate M1, case g1):
  // without stripping this, the FIRST path segment after the host prefix
  // becomes "v135", not the package name.
  s = s.replace(/^v\d+\//, "");
  s = s.replace(/^npm:/, "").replace(/^jsr:/, "");
  // Strip a trailing "@<version>" — but not a LEADING "@scope" (atIdx must
  // be > 0 so "@supabase/supabase-js" itself is untouched when there is no
  // version suffix at all).
  const atIdx = s.lastIndexOf("@");
  if (atIdx > 0) s = s.slice(0, atIdx);
  // Strip a trailing sub-path (e.g. a deno.land/x style "pkg/mod.ts").
  const slashIdx = s.indexOf("/", s.startsWith("@") ? s.indexOf("/") + 1 : 0);
  const pkgName = slashIdx > 0 && !s.startsWith("@supabase/") ? s.slice(0, slashIdx) : s;
  return pkgName.toLowerCase();
}

// Requirement (3): every Postgres driver, by normalised bare package
// name — NOT scoped to @supabase (that whole scope is banned separately,
// below, so a new @supabase/* package needs no addition here).
const BANNED_DRIVER_PACKAGE_NAMES = new Set([
  "pg",
  "postgres",
  "postgres.js",
  "postgresjs",
  "pg-promise",
  "pg-native",
  "@db/postgres",
  "@neondatabase/serverless",
]);

function isBannedSpecifier(spec: string): boolean {
  const normalized = normalizePackageSpecifier(spec);
  // Requirement (3): the WHOLE @supabase/* scope, not a fixed list of
  // package names under it — closes the `@supabase/postgrest-js` gap (and
  // any other @supabase/* package named later) in one rule instead of
  // enumerating packages one at a time.
  if (normalized.startsWith("@supabase/")) return true;
  if (BANNED_DRIVER_PACKAGE_NAMES.has(normalized)) return true;
  return normalized.endsWith("supabase-js");
}

// ⛔ FIX (M2 BLOCKING, post-P3a re-gate): "switch to an explicit MODULE
// allow-list; drop host trust entirely." The prior version resolved a
// PREFIX key ending in "/" (the standard import-map "packages within a
// scope" shape) as well as an exact key — that prefix-resolution path was
// itself a confirmed bypass this round: an import-map entry like
// `"lib/": "../../../outside/"` let `import "lib/admin.ts"` walk outside
// supabase/functions through the SAME mechanism meant for legitimate
// scoped packages. M2's decision is explicit: "bare specifiers that are
// EXACT KEYS in a reviewed import map" — prefix/scope resolution is gone
// entirely, not just made stricter. A specifier that doesn't literally
// equal an import-map key resolves to nothing and falls through to "not
// an exact key" below, regardless of what prefix keys exist.
function resolveImportMapAlias(spec: string, importMap: Record<string, string> | undefined): string | undefined {
  if (!importMap) return undefined;
  if (Object.prototype.hasOwnProperty.call(importMap, spec)) return importMap[spec];
  return undefined;
}

// ⛔ FIX (post-P3a re-gate M1): "reject any specifier containing
// `@supabase/` or `supabase-js` anywhere in the raw string." Independent
// of, and evaluated BEFORE, normalizePackageSpecifier — g1
// (esm.sh/v135/@supabase/supabase-js@2.45.0/dist/module/index.js), g2a
// (ga.jspm.io/npm:@supabase/supabase-js@...), and g2b
// (esm.sh/*@supabase/supabase-js@2) all confirmed empirically this round
// that normalization has edge cases (a pinned-build "vNNN/" segment, an
// npm: scheme embedded after an unrecognized host, a "*" external-deps
// marker) that can shift which path segment gets taken as "the package
// name". A raw substring match has no such edge case: the banned text is
// either present in the specifier or it is not, regardless of what
// surrounds it.
function containsSupabaseSubstring(spec: string): boolean {
  const upper = spec.toUpperCase();
  return upper.includes("@SUPABASE/") || upper.includes("SUPABASE-JS");
}

// ⛔ FIX (M2 BLOCKING, post-P3a re-gate): "the lint trusts hosts and
// registries, not modules." The PRIOR model (a HOST allow-list for any
// http(s):// specifier) still let straight through every one of this
// round's confirmed repros that used an ALLOW-LISTED host with an
// unreviewed package: `https://esm.sh/gh/attacker/...`,
// `https://cdn.jsdelivr.net/gh/attacker/...`,
// `https://deno.land/x/attacker_admin@v1/mod.ts`,
// `https://esm.sh/attacker-admin-client@1` — esm.sh/cdn.jsdelivr.net/
// deno.land were all on that allow-list, so trusting the HOST said
// nothing about whether THIS specific module had ever been reviewed.
// M2's decision: host trust is dropped entirely. ANY specifier that is
// itself a literal `http(s):`/`npm:`/`jsr:`/`file:` scheme, or an
// absolute filesystem path, is banned OUTRIGHT — unconditionally, no
// host/package-name exception — because a specifier written directly in
// the source was never routed through import-map review at all. The
// ONLY way a non-relative import is ever legitimate is as a bare
// specifier that is an EXACT KEY in a reviewed import map whose TARGET is
// on the pinned allow-list (isBannedSpecifierOrAlias, below) — so a real
// dependency still gets imported, just never as a raw literal specifier
// in application code.
function isDirectRawSpecifier(spec: string): boolean {
  return /^(https?|npm|jsr|file):/i.test(spec) || spec.startsWith("/");
}

// ⛔ FIX (post-P3a re-gate M1, g4): `data:`/`blob:` specifiers can smuggle
// arbitrary source (a Worker, a dynamic import) with no importable file
// on disk or a real remote host to review at all.
function isDataOrBlobSpecifier(spec: string): boolean {
  const trimmed = spec.trim();
  return /^(data|blob):/i.test(trimmed);
}

/**
 * ⛔ FIX (post-P3a re-gate M1, g5): "resolve relative imports and fail if
 * they escape supabase/functions." Node's `path.resolve`-equivalent,
 * hand-rolled (no filesystem access from lint.ts itself — index.ts is the
 * only place with `node:fs`/`node:path`, so this stays a pure string
 * operation lintSource can run standalone/in tests too): resolves a
 * relative specifier against the linted file's own directory and checks
 * the result still starts with functionsRoot. `functionsRoot` is optional
 * (a plain `lintSource(source, path)` call with no root configured simply
 * skips this specific check, same as before) — index.ts always supplies
 * it for a real directory-walk run.
 */
function resolvesOutsideFunctionsRoot(spec: string, filePath: string, functionsRoot: string | undefined): boolean {
  if (!functionsRoot) return false;
  if (!spec.startsWith("./") && !spec.startsWith("../")) return false;
  const fileDirSegments = filePath.split(/[\\/]/).filter(Boolean);
  fileDirSegments.pop(); // drop the file's own basename, keep its directory
  const rootSegments = functionsRoot.split(/[\\/]/).filter(Boolean);
  const specSegments = spec.split("/").filter((s) => s.length > 0 && s !== ".");
  const resolved = [...fileDirSegments];
  for (const seg of specSegments) {
    if (seg === "..") {
      if (resolved.length === 0) return true; // walked off the filesystem root itself
      resolved.pop();
    } else {
      resolved.push(seg);
    }
  }
  if (resolved.length < rootSegments.length) return true;
  for (let i = 0; i < rootSegments.length; i++) {
    if (resolved[i] !== rootSegments[i]) return true;
  }
  return false;
}

// ⛔ REWRITE (M2 BLOCKING, post-P3a re-gate): explicit MODULE allow-list,
// host trust dropped entirely (this migration's own decision, verbatim):
// "Only two kinds of import are allowed: relative imports that resolve
// inside supabase/functions (after realpath); bare specifiers that are
// exact keys in a reviewed import map ... whose targets are exact,
// pinned, versioned URLs, or npm:/jsr: with exact versions ... a pinned
// allow-list of those exact target strings, kept as a committed fixture
// file compared by the lint, so adding a dependency is a reviewed diff."
function isBannedSpecifierOrAlias(
  spec: string,
  importMap: Record<string, string> | undefined,
  pinnedImportTargets: Set<string>,
  filePath: string,
  functionsRoot: string | undefined,
): { banned: boolean; reason?: string; resolvedVia?: string } {
  // Kind 1: a relative import. The ONLY non-import-map path that's ever
  // legitimate, and only if it stays inside supabase/functions.
  if (spec.startsWith("./") || spec.startsWith("../")) {
    if (resolvesOutsideFunctionsRoot(spec, filePath, functionsRoot)) {
      return { banned: true, reason: "relative import resolves outside supabase/functions" };
    }
    return { banned: false };
  }

  if (containsSupabaseSubstring(spec)) return { banned: true, reason: "contains '@supabase/' or 'supabase-js'" };
  if (isDataOrBlobSpecifier(spec)) return { banned: true, reason: "data:/blob: specifier" };
  // Every direct URL/npm:/jsr:/file: import, and every absolute path, is
  // banned OUTRIGHT — unconditionally, independent of host or package
  // name — because it was never routed through a reviewed import map at
  // all (also closes `gh/` passthrough paths on an otherwise-trusted
  // host, e.g. esm.sh/gh/attacker/..., which a host-only allow-list let
  // straight through).
  if (isDirectRawSpecifier(spec)) {
    return {
      banned: true,
      reason: "a direct URL/npm:/jsr:/file:/absolute-path specifier outside a reviewed import map -- only an exact import-map key whose target is on the pinned allow-list is permitted",
    };
  }

  // Kind 2: a bare specifier. The ONLY remaining legitimate path: an
  // EXACT key in the reviewed import map (resolveImportMapAlias no
  // longer does prefix/scope resolution at all -- see its own note),
  // whose target is itself clean AND appears verbatim on the committed
  // pinned-target allow-list.
  const resolved = resolveImportMapAlias(spec, importMap);
  if (resolved === undefined) {
    return {
      banned: true,
      reason: "not a relative import and not an exact key in a reviewed import map (supabase/functions/deno.json or import_map.json)",
    };
  }
  if (containsSupabaseSubstring(resolved)) {
    return { banned: true, reason: "alias resolves to a specifier containing '@supabase/' or 'supabase-js'", resolvedVia: resolved };
  }
  if (isBannedSpecifier(resolved)) return { banned: true, reason: "alias resolves to a banned Supabase/Postgres-driver package", resolvedVia: resolved };
  if (resolved.startsWith("./") || resolved.startsWith("../")) {
    // A relative-path TARGET (e.g. a locally vendored shim) is checked
    // for the same root-escape, M2's own text: "run the escape check on
    // the resolved import-map target too."
    if (resolvesOutsideFunctionsRoot(resolved, filePath, functionsRoot)) {
      return { banned: true, reason: "alias resolves to a relative path outside supabase/functions", resolvedVia: resolved };
    }
    return { banned: false };
  }
  if (resolved.endsWith("/")) {
    // M2's own text: "a prefix mapping (trailing '/') onto a remote host
    // fails." A scope/prefix-SHAPED target can never be a single "exact,
    // pinned, versioned" string by construction, independent of whether
    // it happens to collide with a pinned entry.
    return { banned: true, reason: "alias target is a prefix mapping (trailing '/'), not a single exact pinned target", resolvedVia: resolved };
  }
  if (!pinnedImportTargets.has(resolved)) {
    return {
      banned: true,
      reason: `alias target "${resolved}" is not on the committed pinned-import-targets allow-list -- add it there as its own reviewed diff`,
      resolvedVia: resolved,
    };
  }
  return { banned: false };
}

function isAllowedFile(filePath: string): boolean {
  const segments = filePath.split(/[\\/]/).filter(Boolean);
  if (segments.length < EXEMPT_SEGMENTS.length) return false;
  const tail = segments.slice(-EXEMPT_SEGMENTS.length);
  return tail.every((seg, i) => seg === EXEMPT_SEGMENTS[i]);
}

// ⛔ FIX (M2 BLOCKING, post-P3a re-gate): a computed member-access KEY
// built from an expression, rather than named as a literal/identifier —
// see the pass below that uses this. Deliberately narrow to the shapes
// the requirement names (binary `+` concatenation, a template literal
// with at least one interpolated expression, `.concat()`/`.join()`,
// `String.fromCharCode()`) so an ordinary `arr[i]` / `obj[key]` (an
// Identifier property) or `obj["literal"]` (a plain string Literal
// property — already covered by the dedicated `.constructor` check
// above where that literal IS "constructor") is never flagged.
function isStringBuildingExpression(node: TSESTree.Node): boolean {
  if (node.type === AST_NODE_TYPES.BinaryExpression && node.operator === "+") return true;
  if (node.type === AST_NODE_TYPES.TemplateLiteral && node.expressions.length > 0) return true;
  if (node.type === AST_NODE_TYPES.CallExpression) {
    const callee = node.callee;
    if (callee.type === AST_NODE_TYPES.MemberExpression && !callee.computed && callee.property.type === AST_NODE_TYPES.Identifier) {
      if (callee.property.name === "concat" || callee.property.name === "join") return true;
      if (
        callee.property.name === "fromCharCode" &&
        callee.object.type === AST_NODE_TYPES.Identifier &&
        callee.object.name === "String"
      ) {
        return true;
      }
    }
  }
  return false;
}

function nodeLoc(node: TSESTree.Node): { line: number; column: number } {
  return { line: node.loc?.start.line ?? 0, column: node.loc?.start.column ?? 0 };
}

/** Minimal generic AST walker (typescript-estree nodes are plain objects). */
function walk(node: TSESTree.Node | null | undefined, visit: (n: TSESTree.Node) => void): void {
  if (!node || typeof node !== "object") return;
  visit(node);
  for (const key of Object.keys(node)) {
    if (key === "parent" || key === "loc" || key === "range") continue;
    const value = (node as unknown as Record<string, unknown>)[key];
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item && typeof item === "object" && "type" in item) {
          walk(item as TSESTree.Node, visit);
        }
      }
    } else if (value && typeof value === "object" && "type" in (value as object)) {
      walk(value as TSESTree.Node, visit);
    }
  }
}

function isCreateClientCallee(callee: TSESTree.Expression, createClientLocalNames: Set<string>, namespaceImportNames: Set<string>): boolean {
  if (callee.type === AST_NODE_TYPES.Identifier) {
    return createClientLocalNames.has(callee.name);
  }
  if (callee.type === AST_NODE_TYPES.MemberExpression && callee.property.type === AST_NODE_TYPES.Identifier) {
    if (callee.object.type === AST_NODE_TYPES.Identifier && namespaceImportNames.has(callee.object.name)) {
      return callee.property.name === "createClient";
    }
  }
  return false;
}

// The EXACT sanctioned shape from requirement (1): a CallExpression whose
// callee is precisely `Deno.env.get` (both MemberExpressions
// non-computed, the innermost object a bare Identifier named "Deno") —
// nothing else matches, by construction: `Deno["env"].get(...)`,
// `Deno.env["get"](...)`, `(Deno as any).env.get(...)`, `x.env.get(...)`
// for any x other than the literal Deno identifier, `Deno.env.get.call(...)`
// (an extra MemberExpression hop), a destructured/aliased/spread/
// sequence-expression call — all fail this check by simply not matching
// the shape, with no per-bypass special-casing needed.
function isExactDenoEnvGetCall(node: TSESTree.Node): node is TSESTree.CallExpression {
  if (node.type !== AST_NODE_TYPES.CallExpression) return false;
  const callee = node.callee;
  if (callee.type !== AST_NODE_TYPES.MemberExpression) return false;
  if (callee.computed) return false;
  if (callee.property.type !== AST_NODE_TYPES.Identifier || callee.property.name !== "get") return false;
  const inner = callee.object;
  if (inner.type !== AST_NODE_TYPES.MemberExpression) return false;
  if (inner.computed) return false;
  if (inner.property.type !== AST_NODE_TYPES.Identifier || inner.property.name !== "env") return false;
  if (inner.object.type !== AST_NODE_TYPES.Identifier || inner.object.name !== "Deno") return false;
  return true;
}

export function lintSource(source: string, filePath: string, options: LintOptions = {}): Finding[] {
  const findings: Finding[] = [];
  if (isAllowedFile(filePath)) {
    return findings; // privileged.ts is the sanctioned construction site.
  }

  let ast: TSESTree.Program;
  try {
    ast = parse(source, { loc: true, range: true, jsx: false });
  } catch (err) {
    return [{ rule: "parse-error", message: `failed to parse ${filePath}: ${(err as Error).message}`, line: 0, column: 0 }];
  }

  // ---------------------------------------------------------------------
  // Pass 0: identifiers declared by an AMBIENT `declare` statement (e.g.
  // `declare const Deno: {...}` — every fixture in this suite uses this
  // purely so a Node-based parser can parse the file without a real Deno
  // type-definition on hand; it has zero runtime effect and real
  // production code never carries one, since Deno's own ambient types
  // come from the runtime itself). These are TYPE positions, not
  // references, so they are excluded from Pass 1's "any reference to
  // Deno/process" scan by object identity.
  // ---------------------------------------------------------------------
  const declaredAmbientIds = new Set<TSESTree.Node>();
  walk(ast, (node) => {
    if (
      node.type === AST_NODE_TYPES.VariableDeclaration &&
      node.declare &&
      node.declarations.length > 0
    ) {
      for (const decl of node.declarations) {
        if (decl.id.type === AST_NODE_TYPES.Identifier) declaredAmbientIds.add(decl.id as unknown as TSESTree.Node);
      }
    }
  });

  // ---------------------------------------------------------------------
  // Pass 1 (requirement 1): any reference to Deno/process/globalThis/
  // self/window, allow-listing EXACTLY `Deno.env.get("<public literal>")`.
  // ---------------------------------------------------------------------
  // First, find every exact-shape `Deno.env.get(...)` call and classify
  // it: sanctioned (literal, on the allow-list) or not. Either way, the
  // call's OWN callee subtree (the `Deno`/`env`/`get` identifiers) is
  // "handled" here with a specific, actionable message — the generic
  // scan below skips node objects already handled, so a bad key gets ONE
  // clear finding (not a generic one plus a duplicate).
  const handledNodes = new Set<TSESTree.Node>();
  walk(ast, (node) => {
    if (!isExactDenoEnvGetCall(node)) return;
    const call = node;
    handledNodes.add(call.callee as unknown as TSESTree.Node);
    const callee = call.callee as TSESTree.MemberExpression;
    handledNodes.add(callee.object as unknown as TSESTree.Node); // the `Deno.env` MemberExpression
    handledNodes.add((callee.object as TSESTree.MemberExpression).object as unknown as TSESTree.Node); // the `Deno` Identifier
    const arg = call.arguments[0];
    const literalKey = call.arguments.length === 1 && arg && arg.type === AST_NODE_TYPES.Literal && typeof arg.value === "string" ? arg.value : undefined;
    const loc = nodeLoc(call);
    if (literalKey === undefined) {
      findings.push({
        rule: "non-literal-env-access",
        message: "Deno.env.get(...) with a non-literal, computed, or spread argument — cannot verify it is on the public allow-list",
        ...loc,
      });
    } else if (!isPublicEnvVar(literalKey)) {
      findings.push({
        rule: "literal-secret-env-var",
        message: `Deno.env.get("${literalKey}") reads a key not on the public env-var allow-list (SERVICE_ROLE/DB_URL-shaped or otherwise unlisted secret)`,
        ...loc,
      });
    }
    // else: sanctioned — no finding.
  });

  // Generic scan: ANY remaining reference to Deno/process (not already
  // handled above, not an ambient `declare` id) is banned outright —
  // this is what makes every OTHER syntactic shape (aliasing, bracket
  // access, `.call`, `Reflect.get`, nested destructuring, spread, a
  // sequence-expression callee, a function that merely returns
  // `Deno.env`, `(Deno as any)...`, and any shape not yet invented) fail
  // without needing its own rule: it is, structurally, a reference to a
  // banned identifier that isn't the one sanctioned call shape.
  // globalThis/self/window are banned unconditionally (requirement 1:
  // "globalThis/self/window access to them" fails) — this also catches
  // `(self as any).Deno`/`window.process` etc without special-casing,
  // since `self`/`window` themselves are always findings.
  walk(ast, (node) => {
    if (node.type !== AST_NODE_TYPES.Identifier) return;
    if (handledNodes.has(node)) return;
    if (declaredAmbientIds.has(node)) return;
    if (BANNED_GLOBAL_IDENTIFIERS.has(node.name)) {
      const loc = nodeLoc(node);
      findings.push({
        rule: "banned-global-reference",
        message: `reference to "${node.name}" outside supabase/functions/_shared/privileged.ts — only the exact call Deno.env.get("<public-allow-listed literal>") is permitted`,
        ...loc,
      });
    } else if (INDIRECTION_IDENTIFIERS.has(node.name)) {
      const loc = nodeLoc(node);
      findings.push({
        rule: "globalthis-access",
        message: `reference to "${node.name}" outside supabase/functions/_shared/privileged.ts — can be used to reach Deno/process (or stash a privileged client) outside the normal import graph`,
        ...loc,
      });
    } else if (BANNED_UNCONDITIONAL_IDENTIFIERS.has(node.name)) {
      const loc = nodeLoc(node);
      findings.push({
        rule: "dynamic-code-execution",
        message: `reference to "${node.name}" outside supabase/functions/_shared/privileged.ts — constructs and runs arbitrary source with no static import specifier to audit`,
        ...loc,
      });
    }
  });

  // ⛔ FIX (post-P3a re-gate M1, g3): `.constructor` member access is the
  // universal gateway to the Function constructor without ever calling
  // something literally named `eval`/`Function`/`new Function` — e.g.
  // `(() => {}).constructor` IS the Function constructor, then invoked
  // through a local variable the eval/Function-name check (below) never
  // sees. Banned as a bare member access, unconditionally: there is no
  // legitimate reason for supabase/functions product code to read
  // `.constructor` off anything.
  walk(ast, (node) => {
    if (
      node.type === AST_NODE_TYPES.MemberExpression &&
      ((!node.computed && node.property.type === AST_NODE_TYPES.Identifier && node.property.name === "constructor") ||
        (node.computed && node.property.type === AST_NODE_TYPES.Literal && node.property.value === "constructor"))
    ) {
      const loc = nodeLoc(node);
      findings.push({
        rule: "dynamic-code-execution",
        message: ".constructor member access outside supabase/functions/_shared/privileged.ts — the universal gateway to the Function constructor, bypassing any eval()/Function()-name check",
        ...loc,
      });
    }
  });

  // ⛔ FIX (post-P3a re-gate M1, g4): a `data:`/`blob:` STRING LITERAL
  // anywhere — the concatenation site in `new Worker("data:..." +
  // encodeURIComponent(src))` is itself a plain Literal with this prefix,
  // independent of whatever it is eventually passed to (Worker, a dynamic
  // import, fetch, …).
  walk(ast, (node) => {
    if (node.type === AST_NODE_TYPES.Literal && typeof node.value === "string" && isDataOrBlobSpecifier(node.value)) {
      const loc = nodeLoc(node);
      findings.push({
        rule: "dynamic-code-execution",
        message: `data:/blob: string literal "${node.value}" outside supabase/functions/_shared/privileged.ts — can smuggle arbitrary source with no importable file or reviewable host`,
        ...loc,
      });
    }
  });

  // ⛔ FIX (M2 BLOCKING, post-P3a re-gate): "flag computed member access
  // whose key is a string-building expression (a binary +, a template
  // literal with expressions, .concat, .join, String.fromCharCode, etc).
  // Do NOT flag ordinary arr[i] / obj[key]." Confirmed bypass:
  // `(() => {})["constr" + "uctor"]` — the EXISTING `.constructor` check
  // above only matches a bare identifier property or a plain STRING
  // LITERAL computed key (`obj["constructor"]`); a computed key built at
  // parse-time from an expression (any expression, not just the literal
  // string "constructor" — the whole POINT of this gadget class is that
  // the resulting property name is never a static string this or any
  // other rule could grep for) was invisible to it. This is
  // content-agnostic by design: it flags the SHAPE (a computed access
  // whose key is built, not named), not any particular resulting string,
  // which is what makes it resistant to the next renamed variant.
  walk(ast, (node) => {
    if (node.type !== AST_NODE_TYPES.MemberExpression || !node.computed) return;
    if (!isStringBuildingExpression(node.property)) return;
    const loc = nodeLoc(node);
    findings.push({
      rule: "dynamic-code-execution",
      message:
        "computed member access whose key is built from an expression (concatenation/template/.concat()/.join()/String.fromCharCode()) outside supabase/functions/_shared/privileged.ts — the resulting property name is never a static string, which is exactly how a `.constructor`-style gadget hides from a name-based check",
      ...loc,
    });
  });

  // ⛔ FIX (M2 BLOCKING, post-P3a re-gate): "Also flag
  // Object.getOwnPropertyDescriptor(s), Reflect.get/getOwnPropertyDescriptor
  // and Object.getPrototypeOf calls whose key argument is not a string
  // literal." Confirmed bypass:
  // `Object.getOwnPropertyDescriptor(Object.getPrototypeOf(() => {}),
  // "constr" + "uctor").value` — walks the prototype chain and reads a
  // property descriptor's VALUE without ever writing a `.constructor` (or
  // `["constructor"]`) member-access token anywhere in the source, so
  // neither the bare-member-access check above nor the computed-key
  // check just above (its key argument here is a plain CALL argument, not
  // a MemberExpression property) ever sees it. `Object.getPrototypeOf` is
  // flagged unconditionally (it takes no "key" argument at all, and
  // walking to a prototype is itself the first step of this exact
  // gadget); the others are flagged only when their key argument is
  // anything other than a literal string, since a literal key is
  // statically readable by a human reviewer the same way a plain
  // `.propName` access is.
  walk(ast, (node) => {
    if (node.type !== AST_NODE_TYPES.CallExpression) return;
    const callee = node.callee;
    if (callee.type !== AST_NODE_TYPES.MemberExpression || callee.computed) return;
    if (callee.object.type !== AST_NODE_TYPES.Identifier || callee.property.type !== AST_NODE_TYPES.Identifier) return;
    const objectName = callee.object.name;
    const methodName = callee.property.name;
    const isStringLiteralArg = (n: TSESTree.Node | undefined): boolean => !!n && n.type === AST_NODE_TYPES.Literal && typeof n.value === "string";

    let flagged = false;
    let why = "";
    if (objectName === "Object" && methodName === "getPrototypeOf") {
      flagged = true;
      why = "Object.getPrototypeOf(...) walks the prototype chain -- the first step of the same gadget that reaches Function via .constructor";
    } else if (objectName === "Object" && (methodName === "getOwnPropertyDescriptor" || methodName === "getOwnPropertyDescriptors")) {
      if (!isStringLiteralArg(node.arguments[1])) {
        flagged = true;
        why = "Object.getOwnPropertyDescriptor(s)(...) with a non-literal (or absent) key reads an arbitrary property descriptor, including .constructor, without a static property name to review";
      }
    } else if (objectName === "Reflect" && (methodName === "get" || methodName === "getOwnPropertyDescriptor")) {
      if (!isStringLiteralArg(node.arguments[1])) {
        flagged = true;
        why = `Reflect.${methodName}(...) with a non-literal key reads an arbitrary property, including .constructor, without a static property name to review`;
      }
    }
    if (flagged) {
      const loc = nodeLoc(node);
      findings.push({
        rule: "dynamic-code-execution",
        message: `${why} — outside supabase/functions/_shared/privileged.ts`,
        ...loc,
      });
    }
  });

  // ---------------------------------------------------------------------
  // Pass 2 (requirement 2): any string literal OR template chunk
  // containing SERVICE_ROLE or DB_URL is an error, everywhere in the
  // file — independent of Pass 1, so a secret substring surfacing through
  // a completely different mechanism (not even touching Deno/process
  // syntactically — e.g. a hand-written comment-adjacent literal, a
  // hardcoded fallback, a string built into a config object) is still
  // caught.
  // ---------------------------------------------------------------------
  walk(ast, (node) => {
    if (node.type === AST_NODE_TYPES.Literal && typeof node.value === "string" && mentionsSecretSubstring(node.value)) {
      const loc = nodeLoc(node);
      findings.push({
        rule: "secret-substring-in-literal",
        message: `string literal "${node.value}" contains SERVICE_ROLE or DB_URL`,
        ...loc,
      });
    }
    if (node.type === AST_NODE_TYPES.TemplateElement) {
      const raw = node.value.raw;
      if (raw && mentionsSecretSubstring(raw)) {
        const loc = nodeLoc(node);
        findings.push({
          rule: "secret-substring-in-literal",
          message: `template literal chunk "${raw}" contains SERVICE_ROLE or DB_URL`,
          ...loc,
        });
      }
    }
  });

  // ---------------------------------------------------------------------
  // Pass 3: import/re-export/dynamic-import/require bookkeeping, and the
  // banned-specifier check (requirements 3 + 4).
  // ---------------------------------------------------------------------
  const createClientLocalNames = new Set<string>(); // e.g. `createClient`, or an alias of it
  const supabaseClientLocalNames = new Set<string>(); // `SupabaseClient` class import, aliased or not
  const namespaceImportNames = new Set<string>(); // `import * as x from "<supabase-js>"`

  const pinnedImportTargetsSet = new Set(options.pinnedImportTargets ?? []);

  function reportBannedSpecifier(node: TSESTree.Node, spec: string, kind: "import" | "dynamic import" | "require" | "re-export"): void {
    const { banned, reason, resolvedVia } = isBannedSpecifierOrAlias(spec, options.importMap, pinnedImportTargetsSet, filePath, options.functionsRoot);
    if (!banned) return;
    const loc = nodeLoc(node);
    const viaNote = resolvedVia ? ` (alias resolves via deno.json/import_map.json to "${resolvedVia}")` : "";
    const reasonNote = reason ? ` — ${reason}` : " (Supabase client scope or raw Postgres driver)";
    findings.push({
      rule: kind === "re-export" ? "reexport-of-privileged-symbol" : "banned-import-specifier",
      message: `${kind} of a banned specifier "${spec}"${viaNote}${reasonNote} outside supabase/functions/_shared/privileged.ts`,
      ...loc,
    });
  }

  walk(ast, (node) => {
    if (node.type === AST_NODE_TYPES.ImportDeclaration) {
      const spec = node.source.value;
      if (typeof spec === "string") {
        reportBannedSpecifier(node, spec, "import");
        for (const spec2 of node.specifiers) {
          if (spec2.type === AST_NODE_TYPES.ImportSpecifier) {
            const importedName = spec2.imported.type === AST_NODE_TYPES.Identifier ? spec2.imported.name : String(spec2.imported.value);
            if (importedName === "createClient") createClientLocalNames.add(spec2.local.name);
            if (importedName === "SupabaseClient") supabaseClientLocalNames.add(spec2.local.name);
          } else if (spec2.type === AST_NODE_TYPES.ImportDefaultSpecifier) {
            // `import postgres from "postgres"` — the default export IS
            // the client-constructing function; treat the local binding
            // itself as a createClient-equivalent name.
            createClientLocalNames.add(spec2.local.name);
          } else if (spec2.type === AST_NODE_TYPES.ImportNamespaceSpecifier) {
            namespaceImportNames.add(spec2.local.name);
          }
        }
      }
    }

    // Re-exports: `export { createClient } from "<banned>"` / `export * from "<banned>"`.
    if (
      (node.type === AST_NODE_TYPES.ExportNamedDeclaration || node.type === AST_NODE_TYPES.ExportAllDeclaration) &&
      node.source &&
      typeof node.source.value === "string"
    ) {
      reportBannedSpecifier(node, node.source.value, "re-export");
    }

    // Dynamic import(): `import("@supabase/supabase-js")`, `import("npm:pg")`.
    if (node.type === AST_NODE_TYPES.ImportExpression) {
      const arg = node.source;
      if (arg.type === AST_NODE_TYPES.Literal && typeof arg.value === "string") {
        reportBannedSpecifier(node, arg.value, "dynamic import");
      } else {
        // A dynamic import whose specifier isn't even a literal is
        // inherently unauditable by this static check — flag it too.
        const loc = nodeLoc(node);
        findings.push({
          rule: "banned-import-specifier",
          message: "dynamic import() with a non-literal specifier — cannot verify it isn't a Supabase/Postgres client; flagged outside supabase/functions/_shared/privileged.ts",
          ...loc,
        });
      }
    }

    // require("pg") / require("@supabase/supabase-js") (CJS interop).
    if (node.type === AST_NODE_TYPES.CallExpression && node.callee.type === AST_NODE_TYPES.Identifier && node.callee.name === "require") {
      const arg = node.arguments[0];
      if (arg && arg.type === AST_NODE_TYPES.Literal && typeof arg.value === "string") {
        reportBannedSpecifier(node, arg.value, "require");
      }
    }

    // A local withOwnership shadowing the real helper (function decl, or
    // any variable/const bound to that name).
    if (
      (node.type === AST_NODE_TYPES.FunctionDeclaration && node.id?.name === "withOwnership") ||
      (node.type === AST_NODE_TYPES.VariableDeclarator && node.id.type === AST_NODE_TYPES.Identifier && node.id.name === "withOwnership")
    ) {
      const loc = nodeLoc(node);
      findings.push({
        rule: "withownership-shadowed",
        message: "a local declaration named withOwnership shadows the real helper from supabase/functions/_shared/privileged.ts",
        ...loc,
      });
    }
  });

  // ---------------------------------------------------------------------
  // Pass 4: service-role client construction (createClient / new
  // SupabaseClient), with alias-taint propagated transitively.
  // ---------------------------------------------------------------------
  const serviceRoleIdentifiers = new Set<string>();
  const withOwnershipCallbackRanges: Array<[number, number]> = [];

  walk(ast, (node) => {
    if (node.type === AST_NODE_TYPES.CallExpression && isCreateClientCallee(node.callee, createClientLocalNames, namespaceImportNames)) {
      const usesServiceRole = node.arguments.some((arg) => {
        let found = false;
        walk(arg, (n) => {
          if (found) return;
          if (n.type === AST_NODE_TYPES.Literal && typeof n.value === "string" && mentionsSecretSubstring(n.value)) found = true;
          if (n.type === AST_NODE_TYPES.Identifier && mentionsSecretSubstring(n.name)) found = true;
        });
        return found;
      });
      if (usesServiceRole) {
        const loc = nodeLoc(node);
        findings.push({
          rule: "service-role-construction",
          message: "createClient(...) with a service-role key/env-var is constructed outside supabase/functions/_shared/privileged.ts",
          ...loc,
        });
      }
    }

    if (
      node.type === AST_NODE_TYPES.NewExpression &&
      node.callee.type === AST_NODE_TYPES.Identifier &&
      supabaseClientLocalNames.has(node.callee.name)
    ) {
      const loc = nodeLoc(node);
      findings.push({
        rule: "service-role-construction",
        message: "new SupabaseClient(...) constructed outside supabase/functions/_shared/privileged.ts",
        ...loc,
      });
    }

    if (
      node.type === AST_NODE_TYPES.VariableDeclarator &&
      node.id.type === AST_NODE_TYPES.Identifier &&
      node.init &&
      ((node.init.type === AST_NODE_TYPES.CallExpression &&
        isCreateClientCallee(node.init.callee, createClientLocalNames, namespaceImportNames)) ||
        (node.init.type === AST_NODE_TYPES.NewExpression &&
          node.init.callee.type === AST_NODE_TYPES.Identifier &&
          supabaseClientLocalNames.has(node.init.callee.name)))
    ) {
      serviceRoleIdentifiers.add(node.id.name);
    }

    if (
      node.type === AST_NODE_TYPES.CallExpression &&
      node.callee.type === AST_NODE_TYPES.Identifier &&
      node.callee.name === "withOwnership"
    ) {
      const cb = node.arguments[1];
      if (
        cb &&
        (cb.type === AST_NODE_TYPES.ArrowFunctionExpression || cb.type === AST_NODE_TYPES.FunctionExpression) &&
        cb.range
      ) {
        withOwnershipCallbackRanges.push([cb.range[0], cb.range[1]]);
      }
    }
  });

  // Alias propagation: `const alias = client;` taints `alias` too, for any
  // identifier already known to hold a service-role client. Also used to
  // track a secret-env-value identifier (`const key = Deno.env.get(...)`,
  // when that read wasn't allow-listed) for Pass 6's raw-fetch check.
  // Fixed-point over a few passes (handles chained aliasing: a -> b -> c).
  const secretEnvValueIdentifiers = new Set<string>();
  walk(ast, (node) => {
    if (
      node.type === AST_NODE_TYPES.VariableDeclarator &&
      node.id.type === AST_NODE_TYPES.Identifier &&
      node.init &&
      isExactDenoEnvGetCall(node.init)
    ) {
      const call = node.init;
      const arg = call.arguments[0];
      const literalKey = call.arguments.length === 1 && arg && arg.type === AST_NODE_TYPES.Literal && typeof arg.value === "string" ? arg.value : undefined;
      if (literalKey === undefined || !isPublicEnvVar(literalKey)) {
        secretEnvValueIdentifiers.add(node.id.name);
      }
    }
  });
  for (let pass = 0; pass < 5; pass++) {
    let added = false;
    walk(ast, (node) => {
      if (
        node.type === AST_NODE_TYPES.VariableDeclarator &&
        node.id.type === AST_NODE_TYPES.Identifier &&
        node.init &&
        node.init.type === AST_NODE_TYPES.Identifier &&
        serviceRoleIdentifiers.has(node.init.name) &&
        !serviceRoleIdentifiers.has(node.id.name)
      ) {
        serviceRoleIdentifiers.add(node.id.name);
        added = true;
      }
      if (
        node.type === AST_NODE_TYPES.AssignmentExpression &&
        node.left.type === AST_NODE_TYPES.Identifier &&
        node.right.type === AST_NODE_TYPES.Identifier &&
        serviceRoleIdentifiers.has(node.right.name) &&
        !serviceRoleIdentifiers.has(node.left.name)
      ) {
        serviceRoleIdentifiers.add(node.left.name);
        added = true;
      }
      if (
        node.type === AST_NODE_TYPES.VariableDeclarator &&
        node.id.type === AST_NODE_TYPES.Identifier &&
        node.init &&
        node.init.type === AST_NODE_TYPES.Identifier &&
        secretEnvValueIdentifiers.has(node.init.name) &&
        !secretEnvValueIdentifiers.has(node.id.name)
      ) {
        secretEnvValueIdentifiers.add(node.id.name);
        added = true;
      }
      if (
        node.type === AST_NODE_TYPES.AssignmentExpression &&
        node.left.type === AST_NODE_TYPES.Identifier &&
        node.right.type === AST_NODE_TYPES.Identifier &&
        secretEnvValueIdentifiers.has(node.right.name) &&
        !secretEnvValueIdentifiers.has(node.left.name)
      ) {
        secretEnvValueIdentifiers.add(node.left.name);
        added = true;
      }
    });
    if (!added) break;
  }

  const insideWithOwnership = (node: TSESTree.Node): boolean => {
    if (!node.range) return false;
    return withOwnershipCallbackRanges.some(([start, end]) => node.range![0] >= start && node.range![1] <= end);
  };

  // ---------------------------------------------------------------------
  // Pass 5: any call on a privileged (service-role) handle outside a
  // withOwnership callback.
  // ---------------------------------------------------------------------
  walk(ast, (node) => {
    if (node.type !== AST_NODE_TYPES.CallExpression) return;
    if (node.callee.type !== AST_NODE_TYPES.MemberExpression) return;

    const callee = node.callee;
    const methodName = callee.property.type === AST_NODE_TYPES.Identifier ? callee.property.name : undefined;

    let base: TSESTree.Node = callee.object;
    for (;;) {
      if (base.type === AST_NODE_TYPES.MemberExpression) {
        base = base.object;
        continue;
      }
      if (base.type === AST_NODE_TYPES.CallExpression && base.callee.type === AST_NODE_TYPES.MemberExpression) {
        base = base.callee.object;
        continue;
      }
      break;
    }
    if (base.type !== AST_NODE_TYPES.Identifier || !serviceRoleIdentifiers.has(base.name)) return;

    const isPrivilegedMethod =
      methodName === "from" ||
      methodName === "rpc" ||
      methodName === "upload" ||
      methodName === "remove" ||
      methodName === "update" ||
      methodName === "upsert" ||
      methodName === "insert" ||
      methodName === "delete" ||
      methodName === "select";

    if (isPrivilegedMethod && !insideWithOwnership(node)) {
      const loc = nodeLoc(node);
      findings.push({
        rule: "privileged-call-outside-withOwnership",
        message: `.${methodName}(...) called on service-role client "${base.name}" outside a withOwnership() callback`,
        ...loc,
      });
    }
  });

  // ---------------------------------------------------------------------
  // Pass 6 (requirement 2, continued): a raw fetch() carrying a
  // secret-env value read straight from env — no createClient/
  // SupabaseClient construction at all, so Pass 4 never sees it.
  // ---------------------------------------------------------------------
  walk(ast, (node) => {
    if (
      !(node.type === AST_NODE_TYPES.CallExpression && node.callee.type === AST_NODE_TYPES.Identifier && node.callee.name === "fetch")
    ) {
      return;
    }
    let usesSecret = false;
    for (const arg of node.arguments) {
      walk(arg, (n) => {
        if (usesSecret) return;
        if (n.type === AST_NODE_TYPES.Identifier && secretEnvValueIdentifiers.has(n.name)) {
          usesSecret = true;
          return;
        }
        if (isExactDenoEnvGetCall(n)) {
          const a = n.arguments[0];
          const literalKey = a && a.type === AST_NODE_TYPES.Literal && typeof a.value === "string" ? a.value : undefined;
          if (literalKey === undefined || !isPublicEnvVar(literalKey)) usesSecret = true;
        }
      });
      if (usesSecret) break;
    }
    if (usesSecret) {
      const loc = nodeLoc(node);
      findings.push({
        rule: "raw-fetch-with-secret",
        message: "fetch(...) call references a service-role/secret env value directly — build privileged HTTP calls through supabase/functions/_shared/privileged.ts instead",
        ...loc,
      });
    }
  });

  // ---------------------------------------------------------------------
  // Pass 7 (requirement 5): eval(...), new Function(...), Function(...).
  // ---------------------------------------------------------------------
  walk(ast, (node) => {
    if (node.type === AST_NODE_TYPES.CallExpression && node.callee.type === AST_NODE_TYPES.Identifier) {
      if (node.callee.name === "eval") {
        const loc = nodeLoc(node);
        findings.push({ rule: "dynamic-code-execution", message: "eval(...) — dynamically executed code cannot be statically audited for a privileged reference", ...loc });
      } else if (node.callee.name === "Function") {
        const loc = nodeLoc(node);
        findings.push({ rule: "dynamic-code-execution", message: "Function(...) constructor call — dynamically executed code cannot be statically audited for a privileged reference", ...loc });
      }
    }
    if (node.type === AST_NODE_TYPES.NewExpression && node.callee.type === AST_NODE_TYPES.Identifier && node.callee.name === "Function") {
      const loc = nodeLoc(node);
      findings.push({ rule: "dynamic-code-execution", message: "new Function(...) — dynamically executed code cannot be statically audited for a privileged reference", ...loc });
    }
  });

  return findings;
}
