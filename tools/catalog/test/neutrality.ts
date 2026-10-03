/**
 * Holds `src/manifest-core.ts` to its platform-neutral contract — it is shared
 * with the mobile app (Metro / Hermes), so it may import nothing but `zod` and
 * may not reach a Node global — using a REAL parser/bundler, not a lexer.
 *
 * History: the first version of this guard was a hand-rolled token lexer. A
 * lexer cannot tell a regex from a division without a parse (`if (x) /`/.test(y);`
 * vs `(a) / b`), so a regex after `)` made it swallow a following real
 * `import fs from "node:fs"`; and it only knew the spellings it listed
 * (`globalThis.Buffer`, `module.require("node:crypto")` and
 * `eval("req" + "uire")` all walked through). It is gone. Two layers replace it,
 * and each catches what the other cannot:
 *
 * 1. BUNDLE (esbuild's JS API, `platform: "neutral"`, only the allowed
 *    specifiers `external`). esbuild really parses the source, so:
 *      - an import of anything else is either unresolvable (the build errors:
 *        every `node:*` builtin, every bare Node builtin, an uninstalled
 *        package) or is resolved and BUNDLED, which the metafile reveals (an
 *        input outside `src/`);
 *      - every import edge in the metafile must be a static `import-statement`
 *        to an allowed specifier or to another file inside `src/` — `require()`
 *        and `import()` edges are refused;
 *      - a dynamic `import(expr)` / `require(expr)` whose argument is computed
 *        has NO metafile edge at all, so the dynamic-import feature is declared
 *        unsupported: esbuild must then lower it to its `__require` helper, whose
 *        presence in the output is the tell;
 *      - the Node-global / dynamic-code escape hatches (`Buffer`, `process`,
 *        `require`, `module`, `exports`, `__dirname`, `__filename`, `global`,
 *        `globalThis`, `self`, `window`, `eval`, `Function`) are `define`d to a
 *        sentinel string. `define` rewrites only FREE references (a local named
 *        `Buffer`, or `x.process`, is left alone), wherever they occur — so
 *        `globalThis.Buffer`, `module.require(...)` and `eval(...)` all leave the
 *        sentinel in the output. The only "text" check left is a substring search
 *        for that sentinel and for `__require`, both tool-generated.
 *      - `.constructor(...)`: the sentinel only sees the NAMES `eval` / `Function`,
 *        and string-as-code does not need to name either — `(() => {}).constructor("…")()`,
 *        `[].constructor.constructor("…")()` and the AsyncFunction / GeneratorFunction
 *        constructors reached via `Object.getPrototypeOf(async function () {}).constructor`
 *        all reach `Function` without it. The first version of this rule refused only a
 *        constructor that is IMMEDIATELY CALLED, and the PR #30 gate walked nine spellings
 *        through it with the constructor passed as a VALUE (`(0, fn.constructor)(…)`, a
 *        ternary / `||` callee, `[fn.constructor][0](…)`, `({ f: fn.constructor }).f(…)`, a
 *        default parameter, `(await fn.constructor)(…)`, a plain alias, `class X extends
 *        fn.constructor {}`, `Object.getOwnPropertyDescriptor(proto, "constructor").value(…)`).
 *        A call-shape can always be hidden behind one more expression, so the rule is no
 *        longer about calls: it refuses the READ. In esbuild's printed output (a text search,
 *        but over the printer's one canonical spelling: comments gone, whitespace normal,
 *        `x["constructor"]`, `x["construct" + "or"]` and `x?.["constructor"]` all folded or
 *        printed as a plain shape) it refuses:
 *          a. any `.constructor` / `?.constructor` member access, whatever follows it;
 *          b. any `"constructor"` / `'constructor'` / `` `constructor` `` string literal (the key
 *             argument of `Reflect.get`, `getOwnPropertyDescriptor`, a `["constructor"]` access, a
 *             `{ "constructor": F }` pattern, a `const k = "constructor"` later used as `x[k]`),
 *             except the ONE narrow allowance in `ALLOWED_CONSTRUCTOR_LITERALS`;
 *          c. an unquoted `constructor` as a key in an object pattern / literal or as a
 *             shorthand (`{ constructor: F }`, `{ a, constructor }`, `{ constructor = d }`) —
 *             the destructuring READ, which has neither a `.` nor a string;
 *          d. the key-ENUMERATING reflection APIs (`getOwnPropertyNames`,
 *             `getOwnPropertyDescriptors`, `ownKeys`): they hand back the non-enumerable
 *             key `"constructor"` at runtime without the text ever appearing in the source.
 *        A class or object-literal METHOD named `constructor` (a definition, not a read) is not
 *        refused. The real `manifest-core.ts` output has no such read, so there is no false
 *        positive there (its only `"constructor"` is the string in the key-blocklist `Set`, the
 *        allowance). The rule's false-positive sources all fail closed (a visible violation,
 *        never a miss): `x.constructor.name` and `x.constructor === Object` (refused by design:
 *        the real code needs neither), a STRING that contains the text `.constructor`, and a
 *        local variable that is itself named `constructor`.
 * 2. TYPES (the TypeScript checker with `lib: es2022` and NO `@types/node`).
 *    esbuild erases types, so `import type { X } from "node:buffer"` and a
 *    `Buffer` annotation vanish from the bundle; the checker cannot resolve
 *    either. This is the one thing layer 1 cannot see.
 *
 * Residual (honest):
 *  - The bundler resolves modules the way Node does, so a specifier that resolves
 *    to an installed package is caught by the "inputs outside `src/`" rule, not by name.
 *  - `import.meta` is deliberately allowed.
 *  - Reaching `Function` (and so evaluating a string as code) does NOT need the
 *    names `eval` / `Function`, so the sentinel alone does not close it; the
 *    `constructor` rules above close every spelling in which the key is a LITERAL (or a
 *    literal the bundler folds) at build time — including the destructured, passed-as-a-value,
 *    aliased, extended and `Reflect.get` / `Reflect.apply` forms — and the key-enumerating
 *    reflection APIs. What remains is a key that is NOT a literal at build time:
 *      * a key ASSEMBLED at runtime from parts the bundler does not fold: a template with a
 *        substitution (`` `constr${"uctor"}` ``), `"constr".concat("uctor")`, `["con", "structor"].join("")`,
 *        `String.fromCharCode(…)`, `atob(…)`, a function's return value;
 *      * a key that is DATA (`Reflect.get(fn, input.k)`, `x[k]` with `k` read from a parameter);
 *      * a key taken from the allowed blocklist `Set` itself (`[...BLOCKLIST][1]`).
 *    No static check closes a runtime-assembled key; what keeps those out is that a module must
 *    import nothing, reach no global, and be reviewed. Also not seen: string-as-code through a
 *    host API the type layer does not know (the type layer, with no DOM and no Node types, does
 *    reject `setTimeout("…")`). All pinned as known gaps in `manifest-core-neutral.test.ts`.
 */
import { execFile } from "node:child_process";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { build, type BuildFailure, type Metafile } from "esbuild";

const run = promisify(execFile);

/** `tools/catalog`. */
export const CATALOG_ROOT = fileURLToPath(new URL("..", import.meta.url));

/** Free identifiers that give a module a way out of platform neutrality. */
export const FORBIDDEN_FREE_IDENTIFIERS = [
  "Buffer",
  "process",
  "require",
  "module",
  "exports",
  "__dirname",
  "__filename",
  "global",
  "globalThis",
  "self",
  "window",
  "eval",
  "Function",
] as const;

const SENTINEL = "@@GR_FORBIDDEN:";
const SENTINEL_RE = /@@GR_FORBIDDEN:(\w+)@@/g;

export interface BundleReport {
  /** esbuild's own errors (an unresolvable import is one). */
  errors: string[];
  warnings: string[];
  /** Metafile input paths, relative to `tools/catalog`, `/`-separated. */
  inputs: string[];
  /** Every import edge of every input. */
  imports: { from: string; path: string; kind: string; external: boolean }[];
  /** The bundle's text (for the sentinel / helper search only). */
  output: string;
}

/** `loader: "css"` exists so a non-JS import edge (`@import`, `url()`) can be produced from stdin, which is
 * exempt from the "outside `src/`" rule; the type layer is only for `ts` sources. */
export type NeutralitySource = { file: string } | { text: string; loader?: "ts" | "css" };

/** Bundles one source for the `neutral` platform and reports what it found. */
export async function bundleNeutral(source: NeutralitySource, allowed: readonly string[]): Promise<BundleReport> {
  const define = Object.fromEntries(FORBIDDEN_FREE_IDENTIFIERS.map((n) => [n, JSON.stringify(`${SENTINEL}${n}@@`)]));
  try {
    const res = await build({
      ...("file" in source
        ? { entryPoints: [source.file] }
        : { stdin: { contents: source.text, loader: source.loader ?? ("ts" as const), resolveDir: join(CATALOG_ROOT, "src"), sourcefile: "fixture.ts" } }),
      absWorkingDir: CATALOG_ROOT,
      bundle: true,
      write: false,
      metafile: true,
      platform: "neutral",
      format: "esm",
      logLevel: "silent",
      external: [...allowed],
      define,
      // Any dynamic `import()` must be LOWERED (to `__require`), which makes a computed one visible.
      supported: { "dynamic-import": false },
    });
    return report(res.metafile, res.outputFiles[0]?.text ?? "", res.warnings.map((w) => w.text));
  } catch (err) {
    const f = err as Partial<BuildFailure>;
    if (!Array.isArray(f.errors)) throw err;
    return { errors: f.errors.map((e) => e.text), warnings: [], inputs: [], imports: [], output: "" };
  }
}

function report(meta: Metafile, output: string, warnings: string[]): BundleReport {
  const imports: BundleReport["imports"] = [];
  for (const [from, input] of Object.entries(meta.inputs)) {
    for (const i of input.imports) imports.push({ from, path: i.path, kind: i.kind, external: i.external === true });
  }
  return { errors: [], warnings, inputs: Object.keys(meta.inputs).map((p) => p.split(sep).join("/")), imports, output };
}

/**
 * The ONLY `"constructor"` string the bundled output may contain: the key blocklist of `manifest-core.ts`
 * (`FORBIDDEN_KEYS`), whose every use is a `.has(key)` REFUSAL. Matched as exact printed text, so adding, removing or
 * reordering an element fails closed and forces this line to be revisited. It is removed from the output before the
 * `constructor` rules run. Residual: any code that READS a key out of that Set and uses it as a property key
 * (`[...FORBIDDEN_KEYS][1]`) is not seen; a Set literal is indistinguishable, in text, from a blocklist.
 */
export const ALLOWED_CONSTRUCTOR_LITERALS: readonly { text: string; reason: string }[] = [
  { text: 'new Set(["__proto__", "constructor", "prototype"])', reason: "manifest-core.ts FORBIDDEN_KEYS: the strict-JSON parser REFUSES these three object keys" },
];

/** A `constructor` member READ: `x.constructor`, `x?.constructor`, `x\n.constructor`. */
const CONSTRUCTOR_MEMBER_RE = /\.\s*constructor(?![\w$])/;
/** A `"constructor"` / `'constructor'` / `` `constructor` `` string literal (a computed key, a `Reflect.get` / `getOwnPropertyDescriptor` argument, a quoted pattern key). */
const CONSTRUCTOR_STRING_RE = /(["'`])constructor\1/;
/** An UNQUOTED `constructor` object-pattern / object-literal key or shorthand: `{ constructor: F }`, `{ a, constructor }`, `{ constructor = d }`. A method definition `constructor(…) {` is followed by `(` and is not matched. */
const CONSTRUCTOR_KEY_RE = /[{,]\s*constructor\s*[:,}=]/;
/** Reflection that lists an object's own keys, the non-enumerable `"constructor"` among them, without the text appearing. */
const KEY_ENUMERATION_RE = /\b(?:getOwnPropertyNames|getOwnPropertyDescriptors|ownKeys)\b/;

/** The `constructor` / key-enumeration rules over esbuild's printed output (the allowance removed first). */
function constructorViolations(output: string): string[] {
  let text = output;
  for (const a of ALLOWED_CONSTRUCTOR_LITERALS) text = text.split(a.text).join("");
  const out: string[] = [];
  const why = "it reaches Function / AsyncFunction, so it evaluates a string as code without naming eval or Function";
  if (CONSTRUCTOR_MEMBER_RE.test(text)) out.push(`a .constructor member access (${why}; refused whether or not it is called)`);
  if (CONSTRUCTOR_STRING_RE.test(text)) out.push(`a "constructor" string literal (a computed key reaches the same constructor; only the manifest-core key blocklist Set is allowed)`);
  if (CONSTRUCTOR_KEY_RE.test(text)) out.push(`an unquoted constructor object-pattern / shorthand key (a destructuring read of the constructor: ${why})`);
  if (KEY_ENUMERATION_RE.test(text)) out.push(`a key-enumerating reflection API (getOwnPropertyNames / getOwnPropertyDescriptors / ownKeys return the non-enumerable "constructor" key at runtime)`);
  return out;
}

/** Every reason the bundle says the source is not neutral, or `[]`. */
export function bundleViolations(r: BundleReport, allowed: readonly string[]): string[] {
  const out: string[] = [];
  for (const e of r.errors) out.push(`build error: ${e}`);
  for (const w of r.warnings) out.push(`build warning: ${w}`);
  for (const p of r.inputs) {
    if (p !== "<stdin>" && !p.startsWith("src/")) out.push(`bundled a module from outside src/: ${p}`);
  }
  for (const i of r.imports) {
    if (i.external) {
      if (i.kind !== "import-statement") out.push(`${i.kind} of "${i.path}" (only static imports are allowed)`);
      else if (!allowed.includes(i.path)) out.push(`import of "${i.path}" (only ${allowed.map((s) => `"${s}"`).join(", ")} is allowed)`);
    } else if (i.kind !== "import-statement") {
      out.push(`${i.kind} of "${i.path}" (only static imports are allowed)`);
    }
  }
  for (const m of new Set([...r.output.matchAll(SENTINEL_RE)].map((x) => x[1]!))) out.push(`free identifier ${m} (a Node global or dynamic-code escape)`);
  out.push(...constructorViolations(r.output));
  if (/\b__require\b/.test(r.output)) out.push("a dynamic import() / require() the bundler could not resolve statically (its __require helper was emitted)");
  return out;
}

/** Layer 1 for one source. */
export async function neutralityViolations(source: NeutralitySource, allowed: readonly string[]): Promise<string[]> {
  return bundleViolations(await bundleNeutral(source, allowed), allowed);
}

/**
 * Layer 2: type-checks each file with `lib: es2022` and NO ambient Node types.
 * Resolves to, per label, the checker's diagnostics for that file (only files
 * that have some are present; a diagnostic that names no checked file is filed
 * under `"*"` so a checker that could not even load a file never reads as a
 * pass). One checker process for the lot.
 * `{ file }` entries are checked in place (so their relative imports resolve);
 * `{ text }` entries are written to a private temp directory first.
 */
export async function typeViolations(sources: Record<string, NeutralitySource>): Promise<Record<string, string[]>> {
  const dir = await mkdtemp(join(tmpdir(), "gr-neutral-"));
  try {
    await symlink(join(CATALOG_ROOT, "node_modules"), join(dir, "node_modules"));
    const paths = new Map<string, string>(); // checked path -> label
    for (const [label, s] of Object.entries(sources)) {
      let p: string;
      if ("file" in s) p = s.file;
      else {
        p = join(dir, `${label.replace(/[^a-z0-9]+/gi, "-")}.ts`);
        await writeFile(p, s.text);
      }
      paths.set(p, label);
    }
    const tsc = join(CATALOG_ROOT, "node_modules", ".bin", "tsc");
    const args = ["--ignoreConfig", "--noEmit", "--pretty", "false", "--target", "es2022", "--lib", "es2022", "--types", "", "--module", "esnext", "--moduleResolution", "bundler", "--strict", "--skipLibCheck", ...paths.keys()];
    let stdout: string;
    try {
      stdout = (await run(tsc, args, { cwd: dir, maxBuffer: 16 * 1024 * 1024 })).stdout;
    } catch (err) {
      const e = err as { code?: number; stdout?: string };
      if (typeof e.stdout !== "string" || (e.code !== 1 && e.code !== 2)) throw err; // 1/2 = diagnostics; anything else is the checker failing to run
      stdout = e.stdout;
    }
    const result: Record<string, string[]> = {};
    for (const line of stdout.split("\n")) {
      if (!/error TS\d+/.test(line)) continue;
      let label = "*";
      for (const [p, l] of paths) if (line.startsWith(`${relative(dir, p)}(`) || line.startsWith(`${p}(`)) label = l;
      (result[label] ??= []).push(line);
    }
    return result;
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
