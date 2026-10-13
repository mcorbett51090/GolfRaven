// supabase/tests/unit/privileged-sql-contract.test.ts
//
// The Edge <-> database CALL contract of `supabase/functions/_shared/privileged.ts`. Every privileged lane reaches the database through SQL written in tagged template literals there
// (`trx\`select o_status from private.partner_stock_move_for_partner(${a}::text, ...)\``). Nothing else ties that text to the migrations: the pgTAP matrix calls the SQL functions directly, and
// the Edge unit suites hand the handlers a MOCKED port, so a migration that renames a function, adds a required argument, changes an argument's type or drops a returned column leaves every
// suite green and fails only at runtime, as an uncaught 500, in the one lane that calls it. (Only the lanes with a real-stack integration test would see it; nine partner lanes have none.)
//
// This file replays the migrations in order (CREATE [OR REPLACE] FUNCTION and DROP FUNCTION, overloads included), tokenises privileged.ts so only SQL INSIDE a template literal counts
// (comments and ordinary strings do not), and requires every `private.*` / `app.*` function call there to
//   1. name a function some migration defines and none later dropped (a rename or a typo is a "no such function" at runtime),
//   2. pass an argument count the current signature accepts (defaults make trailing arguments optional),
//   3. cast each argument it casts to a type the parameter accepts (the same type, or an implicit widening such as int -> bigint), and
//   4. select only `o_*` columns the function RETURNS (a column the function no longer returns is "column does not exist").
// It is the precise sibling of partner-resolve-statuses.test.ts, which pins the status VOCABULARY of the resolve definers; that class (a status the SQL learned and the Edge did not) was
// design 115's 500. At the time of writing every call site passes (design 123 records the measured baseline).
//
// What it does NOT see: an argument it does not cast (the bound value's type is then whatever the driver sends), the ORDER of same-typed arguments (two `::text` arguments swapped), and SQL
// built from strings rather than templates (privileged.ts has none; a cell below fails if another Edge file starts calling the database this way, because this pin would no longer be the whole picture).

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Migrations: the CURRENT set of function signatures after replaying every file in order.
// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

interface Sig {
  schema: string;
  name: string;
  /** Identity (IN / INOUT / VARIADIC) parameter types, normalised, in order. */
  types: string[];
  /** How many of those carry a DEFAULT (PostgreSQL requires them to be the trailing ones). */
  defaults: number;
  /** Names a SELECT may read (RETURNS TABLE columns or OUT parameters); null when the function returns a scalar or a composite whose columns this parser cannot see. */
  outs: string[] | null;
  file: string;
}

const SYNONYMS: Record<string, string> = {
  integer: "int",
  int4: "int",
  int8: "bigint",
  int2: "smallint",
  boolean: "bool",
  "timestamp with time zone": "timestamptz",
  "timestamp without time zone": "timestamp",
  "double precision": "float8",
  real: "float4",
  "character varying": "text",
  varchar: "text",
  character: "text",
  char: "text",
};

/** `app.partner_role` -> `partner_role`, `numeric(12,2)` -> `numeric`, `INTEGER` -> `int`, `text []` -> `text[]`. */
export function normType(raw: string): string {
  let t = raw.trim().toLowerCase().replace(/\s+/g, " ");
  t = t.replace(/\s*\[\s*\]/g, "[]");
  t = t.replace(/\([^)]*\)/g, "");
  t = t.replace(/\b(?:app|public|pg_catalog|private|extensions)\./g, "");
  const array = t.endsWith("[]");
  const base = array ? t.slice(0, -2) : t;
  return (SYNONYMS[base] ?? base) + (array ? "[]" : "");
}

/** Split on top-level commas (not inside (), [], {} or quotes). */
export function splitTop(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  let quote = "";
  for (const ch of s) {
    if (quote) {
      cur += ch;
      if (ch === quote) quote = "";
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth += 1;
    else if (ch === ")" || ch === "]" || ch === "}") depth -= 1;
    if (ch === "," && depth === 0) {
      out.push(cur);
      cur = "";
    } else cur += ch;
  }
  if (cur.trim() !== "") out.push(cur);
  return out;
}

/** Index of the `)` matching the `(` at `open` (quote-aware), or -1. */
function matchParen(s: string, open: number): number {
  let depth = 0;
  let quote = "";
  for (let i = open; i < s.length; i += 1) {
    const ch = s[i]!;
    if (quote) {
      if (ch === quote) quote = "";
      continue;
    }
    if (ch === "'" || ch === '"') quote = ch;
    else if (ch === "(") depth += 1;
    else if (ch === ")") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

const stripSqlComments = (sql: string): string =>
  sql.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/--[^\n]*/g, " ");

interface ParsedParam {
  mode: "in" | "out";
  name: string | null;
  type: string;
  hasDefault: boolean;
}

/** One parameter of a CREATE FUNCTION header (`[IN|OUT|INOUT|VARIADIC] name type [DEFAULT x | = x]`). */
function parseParam(raw: string): ParsedParam {
  let p = raw.trim();
  let mode: "in" | "out" = "in";
  const m = /^(IN\s+OUT|INOUT|IN|OUT|VARIADIC)\s+/i.exec(p);
  if (m) {
    if (/^OUT$/i.test(m[1]!.trim())) mode = "out";
    p = p.slice(m[0].length);
  }
  let hasDefault = false;
  const d = /\s+DEFAULT\s+|\s+=\s+/i.exec(p);
  if (d) {
    hasDefault = true;
    p = p.slice(0, d.index);
  }
  const named = /^([a-z_][a-z_0-9]*)\s+(.+)$/i.exec(p.trim());
  return named
    ? {
        mode,
        name: named[1]!.toLowerCase(),
        type: normType(named[2]!),
        hasDefault,
      }
    : { mode, name: null, type: normType(p), hasDefault };
}

const keyOf = (s: { schema: string; name: string }): string =>
  `${s.schema}.${s.name}`;
const identity = (s: Sig): string => `${keyOf(s)}(${s.types.join(",")})`;

export function replayMigrations(
  files: ReadonlyArray<{ name: string; sql: string }>,
): Map<string, Sig[]> {
  const out = new Map<string, Sig[]>();
  const put = (sig: Sig): void => {
    const list = out.get(keyOf(sig)) ?? [];
    const at = list.findIndex((s) => identity(s) === identity(sig));
    if (at >= 0) list[at] = sig;
    else list.push(sig);
    out.set(keyOf(sig), list);
  };
  for (const { name: file, sql: raw } of [...files].sort((a, b) =>
    a.name.localeCompare(b.name),
  )) {
    const sql = stripSqlComments(raw);
    const events: Array<{ at: number; run: () => void }> = [];
    for (const m of sql.matchAll(
      /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_0-9]+)\.([a-z_0-9]+)\s*\(/gi,
    )) {
      const open = m.index! + m[0].length - 1;
      const close = matchParen(sql, open);
      if (close < 0)
        throw new Error(
          `${file}: unbalanced parameter list of ${m[1]}.${m[2]}`,
        );
      const params = splitTop(sql.slice(open + 1, close)).map(parseParam);
      const ins = params.filter((p) => p.mode === "in");
      const outs: string[] = params
        .filter((p) => p.mode === "out")
        .map((p) => p.name ?? "");
      const ret = /^\s*RETURNS\s+TABLE\s*\(/i.exec(
        sql.slice(close + 1, close + 200),
      );
      let tableOuts: string[] | null = null;
      if (ret) {
        const tOpen = close + 1 + ret[0].length - 1;
        const tClose = matchParen(sql, tOpen);
        if (tClose < 0)
          throw new Error(
            `${file}: unbalanced RETURNS TABLE of ${m[1]}.${m[2]}`,
          );
        tableOuts = splitTop(sql.slice(tOpen + 1, tClose)).map((c) =>
          c.trim().split(/\s+/)[0]!.toLowerCase(),
        );
      }
      const sig: Sig = {
        schema: m[1]!.toLowerCase(),
        name: m[2]!.toLowerCase(),
        types: ins.map((p) => p.type),
        defaults: ins.filter((p) => p.hasDefault).length,
        outs: tableOuts ?? (outs.length > 0 ? outs : null),
        file,
      };
      events.push({ at: m.index!, run: () => put(sig) });
    }
    for (const m of sql.matchAll(
      /DROP\s+FUNCTION\s+(?:IF\s+EXISTS\s+)?([^;]+);/gi,
    )) {
      const body = m[1]!.replace(/\s+(?:CASCADE|RESTRICT)\s*$/i, "");
      events.push({
        at: m.index!,
        run: () => {
          for (const part of splitTop(body)) {
            const d =
              /^\s*([a-z_0-9]+)\.([a-z_0-9]+)\s*(?:\(([\s\S]*)\))?\s*$/i.exec(
                part,
              );
            if (!d) continue;
            const key = `${d[1]!.toLowerCase()}.${d[2]!.toLowerCase()}`;
            const list = out.get(key) ?? [];
            if (d[3] === undefined) {
              if (list.length === 1) out.delete(key);
              continue;
            }
            // A DROP's argument list may or may not carry parameter names (`(p_a text)` / `(text)`), and an unnamed multi-word type looks like a named one: try both readings.
            const items = splitTop(d[3]).filter((x) => x.trim() !== "");
            const readings = [
              items.map((x) => parseParam(x).type),
              items.map((x) =>
                normType(x.replace(/^\s*(?:IN\s+|VARIADIC\s+)?/i, "")),
              ),
            ];
            const keep = list.filter(
              (s) => !readings.some((r) => r.join(",") === s.types.join(",")),
            );
            if (keep.length === 0) out.delete(key);
            else out.set(key, keep);
          }
        },
      });
    }
    for (const e of events.sort((a, b) => a.at - b.at)) e.run();
  }
  return out;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// privileged.ts: the SQL inside template literals.
// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

interface Template {
  line: number;
  /** The template's text with every `${...}` replaced by a single `§` placeholder. */
  text: string;
}

export function sqlTemplates(src: string): Template[] {
  const lineStarts = [0];
  for (let i = 0; i < src.length; i += 1)
    if (src[i] === "\n") lineStarts.push(i + 1);
  const lineAt = (idx: number): number => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid]! <= idx) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
  const skipLineComment = (i: number): number => {
    const nl = src.indexOf("\n", i);
    return nl < 0 ? src.length : nl;
  };
  const skipBlockComment = (i: number): number => {
    const end = src.indexOf("*/", i + 2);
    return end < 0 ? src.length : end + 2;
  };
  const skipString = (i: number): number => {
    const q = src[i]!;
    let j = i + 1;
    while (j < src.length && src[j] !== q) j += src[j] === "\\" ? 2 : 1;
    return j + 1;
  };
  /** Does a `/` at this point open a regular-expression literal (rather than divide)? Decided by the previous significant token. */
  const opensRegex = (prev: string, word: string): boolean =>
    prev === "" ||
    "([{},;=:!&|?+-*%<>~^".includes(prev) ||
    (prev === "a" &&
      /^(?:return|typeof|case|void|delete|throw|in|of|new|else|do|instanceof|yield|await)$/.test(
        word,
      ));
  /** Skip a regular-expression literal starting at its opening slash (flags included); a slash that turns out not to close on its line is a division. */
  const skipRegex = (i: number): number => {
    let j = i + 1;
    let inClass = false;
    while (j < src.length) {
      const c = src[j]!;
      if (c === "\\") j += 2;
      else if (c === "\n") return i + 1;
      else {
        if (c === "[") inClass = true;
        else if (c === "]") inClass = false;
        else if (c === "/" && !inClass) {
          j += 1;
          while (j < src.length && /[a-z]/i.test(src[j]!)) j += 1;
          return j;
        }
        j += 1;
      }
    }
    return i + 1;
  };
  const out: Template[] = [];
  /** Scan a template body starting just after its opening backtick; returns the index after the closing one. */
  const scanTemplate = (i: number, sink: { text: string }): number => {
    let j = i;
    while (j < src.length) {
      const c = src[j]!;
      if (c === "\\") {
        j += 2;
      } else if (c === "`") {
        return j + 1;
      } else if (c === "$" && src[j + 1] === "{") {
        sink.text += "§";
        j = scanCode(j + 2, true);
      } else {
        sink.text += c;
        j += 1;
      }
    }
    throw new Error("unterminated template literal");
  };
  /**
   * Scan code from `start`: to the end of the file, or (inside a `${ ... }`) to its matching brace. Comments, strings and regex literals are skipped; a template literal met in
   * top-level code is collected, and one met inside a `${ ... }` is skipped (its text belongs to no SQL statement of its own).
   */
  function scanCode(start: number, inExpr: boolean): number {
    let depth = 1;
    let j = start;
    let prev = ""; // the last significant character of code ("a" for an identifier or number)
    let word = "";
    while (j < src.length) {
      const c = src[j]!;
      const n = src[j + 1];
      if (c === "/" && n === "/") j = skipLineComment(j);
      else if (c === "/" && n === "*") j = skipBlockComment(j);
      else if (c === "'" || c === '"') {
        j = skipString(j);
        prev = '"';
      } else if (c === "`") {
        const sink = { text: "" };
        const at = j;
        j = scanTemplate(j + 1, sink);
        if (!inExpr) out.push({ line: lineAt(at), text: sink.text });
        prev = "`";
      } else if (c === "/" && opensRegex(prev, word)) {
        j = skipRegex(j);
        prev = "/";
        word = "";
      } else if (/\s/.test(c)) {
        j += 1;
      } else if (/[A-Za-z_$0-9]/.test(c)) {
        let k = j;
        while (k < src.length && /[A-Za-z_$0-9]/.test(src[k]!)) k += 1;
        word = src.slice(j, k);
        prev = "a";
        j = k;
      } else {
        if (inExpr && c === "{") depth += 1;
        else if (inExpr && c === "}") {
          depth -= 1;
          if (depth === 0) return j + 1;
        }
        prev = c;
        word = "";
        j += 1;
      }
    }
    if (inExpr) throw new Error("unterminated ${...} expression");
    return j;
  }
  scanCode(0, false);
  return out;
}

interface CallSite {
  line: number;
  schema: string;
  name: string;
  /** One entry per top-level argument: its trailing `::type` cast, normalised, or null when it carries none. */
  argTypes: Array<string | null>;
  /** The `o_*` columns of the SELECT list this call feeds (`select <list> from private.fn(...)`), or null when it is not the FROM source of one. */
  columns: string[] | null;
}

export function callSites(templates: ReadonlyArray<Template>): CallSite[] {
  const sites: CallSite[] = [];
  for (const { line, text } of templates) {
    for (const m of text.matchAll(/\b(private|app)\.([a-z_0-9]+)\s*\(/gi)) {
      const before = text.slice(0, m.index!);
      if (/\binto\s*$/i.test(before)) continue; // `insert into app.table (cols)` is a column list, not a call
      const open = m.index! + m[0].length - 1;
      const close = matchParen(text, open);
      if (close < 0)
        throw new Error(
          `privileged.ts:${line}: unbalanced call to ${m[1]}.${m[2]}`,
        );
      const argTypes = splitTop(text.slice(open + 1, close))
        .filter((a) => a.trim() !== "")
        .map((a) => {
          const c = /::\s*([a-z_][a-z_0-9.]*(?:\s*\[\s*\])?)\s*$/i.exec(
            a.trim(),
          );
          return c ? normType(c[1]!) : null;
        });
      let columns: string[] | null = null;
      const sel = [...before.matchAll(/\bselect\b/gi)].pop();
      if (sel) {
        const between = before.slice(sel.index! + sel[0].length);
        const from = /\bfrom\s*$/i.exec(between);
        if (from && !/[;]/.test(between)) {
          const list = between
            .slice(0, from.index)
            .replace(/\bas\s+[a-z_0-9]+/gi, " ") // an alias names an OUTPUT column, not one the function returns
            .replace(/::[a-z_0-9]+(?:\s*\[\s*\])?/gi, " ");
          columns = [...list.matchAll(/\bo_[a-z_0-9]+\b/gi)].map((c) =>
            c[0].toLowerCase(),
          );
        }
      }
      sites.push({
        line,
        schema: m[1]!.toLowerCase(),
        name: m[2]!.toLowerCase(),
        argTypes,
        columns,
      });
    }
  }
  return sites;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// The check.
// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

/** Implicit casts PostgreSQL applies when resolving a function call (the argument type on the left may be passed where the parameter type on the right is declared). */
const WIDENS: Record<string, readonly string[]> = {
  smallint: ["int", "bigint", "numeric", "float4", "float8"],
  int: ["bigint", "numeric", "float4", "float8"],
  bigint: ["numeric", "float4", "float8"],
  numeric: ["float4", "float8"],
  float4: ["float8"],
  date: ["timestamp", "timestamptz"],
  timestamp: ["timestamptz"],
};

const accepts = (param: string, arg: string): boolean =>
  param === arg ||
  param.startsWith("any") ||
  (WIDENS[arg]?.includes(param) ?? false);

export function checkCalls(
  sites: ReadonlyArray<CallSite>,
  sigs: ReadonlyMap<string, Sig[]>,
  where = "privileged.ts",
): string[] {
  const problems: string[] = [];
  for (const s of sites) {
    const id = `${where}:${s.line} ${s.schema}.${s.name}`;
    const all = sigs.get(`${s.schema}.${s.name}`);
    if (!all || all.length === 0) {
      problems.push(
        `${id}: no migration defines this function (renamed, dropped or mistyped)`,
      );
      continue;
    }
    const n = s.argTypes.length;
    const byArity = all.filter(
      (g) => g.types.length - g.defaults <= n && n <= g.types.length,
    );
    if (byArity.length === 0) {
      problems.push(
        `${id}: called with ${n} argument(s) but the current signature(s) take ${all
          .map((g) => `${g.types.length - g.defaults}..${g.types.length}`)
          .join(" or ")} (${all.map((g) => g.file).join(", ")})`,
      );
      continue;
    }
    const byType = byArity.filter((g) =>
      s.argTypes.every((t, i) => t === null || accepts(g.types[i]!, t)),
    );
    if (byType.length === 0) {
      const g = byArity[0]!;
      const bad = s.argTypes
        .map((t, i) =>
          t !== null && !accepts(g.types[i]!, t)
            ? `#${i + 1} cast ::${t} for ${g.types[i]}`
            : "",
        )
        .filter(Boolean);
      problems.push(
        `${id}: argument type mismatch against ${g.file}: ${bad.join("; ")}`,
      );
      continue;
    }
    if (s.columns !== null && s.columns.length > 0) {
      const ok = byType.some(
        (g) => g.outs !== null && s.columns!.every((c) => g.outs!.includes(c)),
      );
      if (!ok) {
        const g = byType[0]!;
        problems.push(
          `${id}: selects ${JSON.stringify(s.columns.filter((c) => !g.outs?.includes(c)))} but ${g.file} returns ${JSON.stringify(g.outs)}`,
        );
      }
    }
  }
  return problems;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// The parsers this pin stands on (synthetic fixtures; the real tree is below).
// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

const f = (name: string, sql: string) => ({ name, sql });
const one = (m: Map<string, Sig[]>, key: string): Sig[] => m.get(key) ?? [];

describe("replaying migrations into the current signatures", () => {
  it("takes the later definition of the same identity, keeps overloads, and ignores a CREATE inside a comment", () => {
    const sigs = replayMigrations([
      f(
        "0002_b.sql",
        "CREATE OR REPLACE FUNCTION private.a(p_x text, p_n integer DEFAULT 3) RETURNS TABLE (o_status text, o_n int) AS $$ BEGIN END $$;",
      ),
      f(
        "0001_a.sql",
        "-- CREATE FUNCTION private.ghost(p_x text) RETURNS void\n/* CREATE FUNCTION private.ghost2(p_x text) */\nCREATE FUNCTION private.a(p_x text, p_n integer) RETURNS TABLE (o_old text) AS $$ BEGIN END $$;\nCREATE FUNCTION private.a(p_y uuid) RETURNS void AS $$ BEGIN END $$;",
      ),
    ]); // the input order must not matter
    const a = one(sigs, "private.a");
    expect(a.map((s) => s.types.join(",")).sort()).toEqual([
      "text,int",
      "uuid",
    ]);
    const twoArg = a.find((s) => s.types.length === 2)!;
    expect(twoArg.defaults).toBe(1);
    expect(twoArg.outs).toEqual(["o_status", "o_n"]);
    expect(twoArg.file).toBe("0002_b.sql");
    expect(sigs.has("private.ghost")).toBe(false);
    expect(sigs.has("private.ghost2")).toBe(false);
  });

  it("removes exactly the dropped overload (named or unnamed argument list), and a function dropped with no list when it is the only one", () => {
    const sigs = replayMigrations([
      f(
        "0001.sql",
        "CREATE FUNCTION private.f(p_a text) RETURNS void AS $$ $$;\nCREATE FUNCTION private.f(p_a text, p_b timestamp with time zone) RETURNS void AS $$ $$;\nCREATE FUNCTION private.g(p_a text) RETURNS void AS $$ $$;\nCREATE FUNCTION private.h(p_a text) RETURNS void AS $$ $$;",
      ),
      f(
        "0002.sql",
        "DROP FUNCTION IF EXISTS private.f(text, timestamptz);\nDROP FUNCTION private.g(p_a text) CASCADE;\nDROP FUNCTION private.h;",
      ),
    ]);
    expect(one(sigs, "private.f").map((s) => s.types.join(","))).toEqual([
      "text",
    ]);
    expect(sigs.has("private.g")).toBe(false);
    expect(sigs.has("private.h")).toBe(false);
  });

  it("reads OUT parameters as the columns a SELECT may name, and a scalar function as having none", () => {
    const sigs = replayMigrations([
      f(
        "0001.sql",
        "CREATE FUNCTION private.o(p_a text, OUT o_x text, OUT o_y int) AS $$ $$;\nCREATE FUNCTION private.s(p_a text) RETURNS boolean AS $$ $$;",
      ),
    ]);
    expect(one(sigs, "private.o")[0]!.types).toEqual(["text"]);
    expect(one(sigs, "private.o")[0]!.outs).toEqual(["o_x", "o_y"]);
    expect(one(sigs, "private.s")[0]!.outs).toBeNull();
  });

  it("normalises parameter types the way a cast spells them", () => {
    expect(normType("INTEGER")).toBe("int");
    expect(normType("app.partner_role")).toBe("partner_role");
    expect(normType("numeric(12, 2)")).toBe("numeric");
    expect(normType("text []")).toBe("text[]");
    expect(normType("timestamp with time zone")).toBe("timestamptz");
    expect(normType("character varying(40)")).toBe("text");
  });
});

describe("reading SQL out of privileged.ts", () => {
  it("sees a call inside a template and none in a comment, a string or a ${...} expression, and keeps line numbers", () => {
    const src = [
      "// select private.in_comment(1)",
      "const a = 'select private.in_string(1)';",
      "/* trx`select private.in_block(1)` */",
      "const r = await trx`select o_s from private.real_one(${x}::uuid, ${y})`;",
      "const q = await trx`select ${ok ? `private.nested_template(1)` : 'z'}::text`;",
    ].join("\n");
    const sites = callSites(sqlTemplates(src));
    expect(sites.map((s) => `${s.line}:${s.name}`)).toEqual(["4:real_one"]);
    expect(sites[0]!.argTypes).toEqual(["uuid", null]);
    expect(sites[0]!.columns).toEqual(["o_s"]);
  });

  it("does not take `insert into app.table (cols)` for a call, and reads a scalar call as feeding no column list", () => {
    const sites = callSites(
      sqlTemplates(
        "const a = trx`insert into app.t (a, b) values (1, 2)`; const b = trx`select private.scalar_fn(${a}::int) as n`;",
      ),
    );
    expect(sites.map((s) => s.name)).toEqual(["scalar_fn"]);
    expect(sites[0]!.columns).toBeNull();
  });

  it("does not treat an output alias as a column the function must return, and ignores casts in the select list", () => {
    const sites = callSites(
      sqlTemplates(
        "const a = trx`select o_amount::text as o_amount_text, o_when::int as o_when from private.fn(${a}::text)`;",
      ),
    );
    expect(sites[0]!.columns).toEqual(["o_amount", "o_when"]);
  });

  it("is not thrown by a regular-expression literal that holds a quote or a backtick (settlement-handler.ts has them), and reads a division as a division", () => {
    const src = [
      "const a = /[\"'`]/g.test(v) ? 1 : 2;",
      'const b = x.replace(/"/g, \'""\');',
      "const t = (v) => /`/.test(v);",
      "const q1 = (a + b) / trx`select private.after_paren(1)` / 2;",
      "const q2 = total / trx`select private.after_identifier(1)` / 2;",
      "const r = await trx`select o_s from private.after_regexes(${x}::text)`;",
    ].join("\n");
    expect(
      callSites(sqlTemplates(src)).map((s) => `${s.line}:${s.name}`),
    ).toEqual(["4:after_paren", "5:after_identifier", "6:after_regexes"]);
  });

  it("throws on an unterminated template instead of seeing nothing", () => {
    expect(() => sqlTemplates("const a = trx`select 1")).toThrow(
      /unterminated/,
    );
  });
});

describe("checking a call against the current signatures", () => {
  const sigs = replayMigrations([
    f(
      "0001.sql",
      "CREATE FUNCTION private.fn(p_a text, p_n bigint, p_d date DEFAULT NULL) RETURNS TABLE (o_status text, o_n int) AS $$ $$;",
    ),
  ]);
  const run = (sql: string) =>
    checkCalls(callSites(sqlTemplates(`const x = trx\`${sql}\`;`)), sigs);

  it("passes a call that matches (an implicit widening and an optional trailing argument included)", () => {
    expect(
      run("select o_status, o_n from private.fn(${a}::text, ${n}::int)"),
    ).toEqual([]);
    expect(
      run(
        "select o_status from private.fn(${a}::text, ${n}::bigint, ${d}::date)",
      ),
    ).toEqual([]);
    expect(run("select o_status from private.fn(${a}, ${n})")).toEqual([]); // uncast arguments are not judged
  });

  it("fails a function no migration defines (a rename or a typo)", () => {
    expect(
      run("select o_status from private.fn_renamed(${a}::text, ${n}::bigint)"),
    ).toEqual([
      expect.stringMatching(
        /private\.fn_renamed: no migration defines this function/,
      ),
    ]);
  });

  it("fails too few and too many arguments", () => {
    expect(run("select o_status from private.fn(${a}::text)")).toEqual([
      expect.stringMatching(
        /called with 1 argument\(s\) but the current signature\(s\) take 2\.\.3/,
      ),
    ]);
    expect(
      run(
        "select o_status from private.fn(${a}::text, ${n}::bigint, ${d}::date, ${e}::text)",
      ),
    ).toEqual([expect.stringMatching(/called with 4 argument\(s\)/)]);
  });

  it("fails a cast the parameter does not accept, but not a narrowing the database would not make either way", () => {
    expect(
      run("select o_status from private.fn(${a}::uuid, ${n}::bigint)"),
    ).toEqual([
      expect.stringMatching(/argument type mismatch.*#1 cast ::uuid for text/),
    ]);
    expect(
      run("select o_status from private.fn(${a}::text, ${n}::numeric)"),
    ).toEqual([expect.stringMatching(/#2 cast ::numeric for bigint/)]);
  });

  it("fails a selected column the function does not return", () => {
    expect(
      run("select o_status, o_gone from private.fn(${a}::text, ${n}::bigint)"),
    ).toEqual([
      expect.stringMatching(
        /selects \["o_gone"\] but 0001\.sql returns \["o_status","o_n"\]/,
      ),
    ]);
  });

  it("with no migrations at all, every call is reported rather than passed", () => {
    const none = checkCalls(
      callSites(sqlTemplates("const x = trx`select private.a(1)`;")),
      new Map(),
    );
    expect(none).toHaveLength(1);
  });
});

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// What edge_partner may NAME (design 129). Calling a `private.*` function is not the only thing a template does: a `::app.partner_role` cast, or a table, resolves a name in schema `app`, which needs USAGE on it.
// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

/** The roles every migration grants USAGE (or ALL) on a schema to, lower-cased, comments removed; `public` is kept as a role name. A REVOKE is deliberately not subtracted: a grant that a later REVOKE undoes is still a reason to re-read the rule below. */
export function schemaUsageGrants(
  files: ReadonlyArray<{ name: string; sql: string }>,
): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const { sql } of files) {
    const text = sql.replace(/--[^\n]*/g, " ");
    for (const m of text.matchAll(
      /\bGRANT\s+([^;]*?)\s+ON\s+SCHEMA\s+([^;]*?)\s+TO\s+([^;]*?)\s*(?:WITH\s+GRANT\s+OPTION\s*)?;/gis,
    )) {
      if (!/\b(USAGE|ALL)\b/i.test(m[1]!)) continue;
      const roles = m[3]!
        .split(",")
        .map((r) => r.trim().replace(/^"|"$/g, "").toLowerCase())
        .filter((r) => r !== "");
      for (const schema of m[2]!
        .split(",")
        .map((x) => x.trim().toLowerCase())
        .filter((x) => x !== "")) {
        const set = out.get(schema) ?? new Set<string>();
        for (const r of roles) set.add(r);
        out.set(schema, set);
      }
    }
  }
  return out;
}

/** Templates that call a `private.*partner*` function (the partner lanes run as edge_partner or edge_partner_minter; so does the bucket hit `private.hit_partner_rate_limit`) and ALSO name something in schema `app` themselves: a `::app.<type>` cast, a table, a function. Comments are ignored. */
export function appNamesInPartnerCalls(
  templates: ReadonlyArray<Template>,
): Array<{ line: number; names: string[] }> {
  const out: Array<{ line: number; names: string[] }> = [];
  for (const { line, text } of templates) {
    const bare = text.replace(/--[^\n]*/g, " ");
    if (!/\bprivate\.[a-z_0-9]*partner[a-z_0-9]*\s*\(/i.test(bare)) continue;
    const names = [...bare.matchAll(/\bapp\.[a-z_][a-z_0-9]*/gi)].map((m) =>
      m[0].toLowerCase(),
    );
    if (names.length > 0) out.push({ line, names });
  }
  return out;
}

describe("reading schema grants and the names a partner template uses", () => {
  const files = (sql: string) => [{ name: "0001.sql", sql }];
  it("reads a multi-line grant, several schemas, ALL, PUBLIC and WITH GRANT OPTION, and ignores a comment and a non-USAGE grant", () => {
    const g = schemaUsageGrants(
      files(`
        -- GRANT USAGE ON SCHEMA app TO edge_partner;
        GRANT USAGE ON SCHEMA app, private TO
          role_a, "Role_B";
        GRANT ALL ON SCHEMA extra TO PUBLIC WITH GRANT OPTION;
        GRANT CREATE ON SCHEMA only_create TO role_c;
      `),
    );
    expect([...(g.get("app") ?? [])].sort()).toEqual(["role_a", "role_b"]);
    expect([...(g.get("private") ?? [])].sort()).toEqual(["role_a", "role_b"]);
    expect([...(g.get("extra") ?? [])]).toEqual(["public"]);
    expect(g.has("only_create")).toBe(false);
  });

  const names = (sql: string) =>
    appNamesInPartnerCalls(sqlTemplates(`const x = trx\`${sql}\`;`));
  it("flags an app type cast and an app table in a template that calls a private.partner_* function", () => {
    expect(
      names(
        "select o_status from private.partner_invite_create_for_partner(${a}::uuid, ${r}::app.partner_role)",
      ),
    ).toEqual([{ line: 1, names: ["app.partner_role"] }]);
    expect(
      names(
        "select 1 from app.partner_member m, private.partner_x_for_partner(${a}::uuid)",
      ),
    ).toEqual([{ line: 1, names: ["app.partner_member"] }]);
  });
  it("passes an untyped argument, a comment that mentions app., and a template that calls no partner function", () => {
    expect(
      names(
        "select o_status from private.partner_invite_create_for_partner(${a}::uuid, ${r}, ${e}::text)",
      ),
    ).toEqual([]);
    expect(
      names(
        "-- the app.partner_role type is not named here\nselect 1 from private.partner_x(${a}::uuid)",
      ),
    ).toEqual([]);
    expect(
      names(
        "select ${a}::app.ledger_status from private.hit_system_rate_limit(${k})",
      ),
    ).toEqual([]);
    // the bucket hit of the partner lane is named for the partner but not prefixed by it, and runs as edge_partner too
    expect(
      names(
        "select private.hit_partner_rate_limit(${k}, ${w}::interval, ${m}::int), ${a}::app.ledger_status",
      ),
    ).toEqual([{ line: 1, names: ["app.ledger_status"] }]);
  });
});

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// The real tree.
// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

const here = dirname(fileURLToPath(import.meta.url));
const supabaseDir = join(here, "..", "..");
const migrations = readdirSync(join(supabaseDir, "migrations"))
  .filter((n) => /^\d{4}_.*\.sql$/.test(n))
  .map((name) => ({
    name,
    sql: readFileSync(join(supabaseDir, "migrations", name), "utf8"),
  }));
const privilegedPath = join(
  supabaseDir,
  "functions",
  "_shared",
  "privileged.ts",
);
const current = replayMigrations(migrations);
const templates = sqlTemplates(readFileSync(privilegedPath, "utf8"));
const sites = callSites(templates);

describe("privileged.ts against the migrations", () => {
  it("replays the whole migration history and sees a realistic number of functions (a parser that silently saw nothing would pass everything)", () => {
    expect(migrations.length).toBeGreaterThan(100);
    expect(current.size).toBeGreaterThan(300);
    // 0062 created this function with 7 arguments; 0063 dropped that signature and created the 8-argument one: exactly one is current.
    expect(
      one(current, "private.partner_offers_redeem_apply_offline").map(
        (s) => s.types.length,
      ),
    ).toEqual([8]);
  });

  it("finds a realistic number of SQL call sites in privileged.ts", () => {
    expect(templates.length).toBeGreaterThan(200);
    expect(sites.length).toBeGreaterThan(150);
    expect(
      new Set(sites.map((s) => `${s.schema}.${s.name}`)).size,
    ).toBeGreaterThan(100);
    expect(
      sites.filter((s) => s.columns !== null && s.columns.length > 0).length,
    ).toBeGreaterThan(70);
  });

  it("every call names a defined function, with a signature-compatible argument list and only columns the function returns", () => {
    expect(checkCalls(sites, current)).toEqual([]);
  });

  it("is the whole picture: no other Edge source file calls a private/app function from SQL (service-role-lint confines privileged calls to privileged.ts)", () => {
    const strays: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir)) {
        const p = join(dir, entry);
        if (statSync(p).isDirectory()) walk(p);
        else if (/\.ts$/.test(entry) && p !== privilegedPath) {
          try {
            const found = callSites(sqlTemplates(readFileSync(p, "utf8")));
            if (found.length > 0)
              strays.push(
                `${relative(supabaseDir, p)}: ${found.map((s) => s.name).join(", ")}`,
              );
          } catch (e) {
            strays.push(
              `${relative(supabaseDir, p)}: could not be tokenised (${(e as Error).message})`,
            );
          }
        }
      }
    };
    walk(join(supabaseDir, "functions"));
    expect(strays).toEqual([]);
  });
});

describe("what edge_partner may name, against the real tree", () => {
  it("premise: no migration grants USAGE on schema app to edge_partner, edge_partner_minter or PUBLIC (0047), and the parser does see the grants that exist", () => {
    const usage = schemaUsageGrants(migrations);
    const app = usage.get("app") ?? new Set<string>();
    for (const role of ["edge_partner", "edge_partner_minter", "public"])
      expect(app.has(role), `${role} was granted USAGE on schema app`).toBe(
        false,
      );
    // controls: the same parser finds the USAGE edge_partner DOES hold (private) and one the player lane holds on app (0030)
    expect(usage.get("private")?.has("edge_partner")).toBe(true);
    expect(usage.get("private")?.has("edge_partner_minter")).toBe(true);
    expect(app.has("edge_actor")).toBe(true);
  });

  it("rule: no template that calls a private.partner_* function names anything in schema app (edge_partner would answer 42501 permission denied for schema app, which the Edge maps to a 403)", () => {
    expect(appNamesInPartnerCalls(templates)).toEqual([]);
  });
});
