// supabase/tests/unit/function-inventory-check-parity.test.ts
//
// P5.1a S1.1a (0047): the edge-role checks exist TWICE. tools/db/verify-function-inventory.mjs runs each one against the live schema (CI's gate and
// tools/db/test.sh), and supabase/tests/matrix/10_function_inventory.sql embeds the same SQL as `pg_temp.edge_check_N()` so each check can be proved to FAIL on
// a planted fixture (a check that has never been seen to fail proves nothing). Two copies of one fact drift: a clause added to the .mjs and not to the matrix
// leaves the must-fail fixtures proving a weaker check than the one that gates the build. This test pins that the two copies are the SAME SQL, modulo
// whitespace, for every check the matrix embeds. The one sanctioned difference is check 14's kind-exception list: the .mjs substitutes the fixture
// (supabase/tests/fixtures/partner_kind_readers.txt) for the literal `ARRAY['private.actor_uid()']` at run time, and the matrix keeps the literal default, so the
// literal must be the fixture's own first entry for the matrix cell to mean what the build checks.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = join(import.meta.dirname, "..", "..", "..");
const mjs = readFileSync(join(ROOT, "tools", "db", "verify-function-inventory.mjs"), "utf8");
const matrix = readFileSync(join(ROOT, "supabase", "tests", "matrix", "10_function_inventory.sql"), "utf8");
const kindFixture = readFileSync(join(ROOT, "supabase", "tests", "fixtures", "partner_kind_readers.txt"), "utf8");
const sessionClassFixture = readFileSync(join(ROOT, "supabase", "tests", "fixtures", "partner_session_class_functions.txt"), "utf8");

const squash = (s: string) => s.replace(/\s+/g, " ").trim();

/** `[N, "label", \`SQL\`],` entries of the .mjs `edgeChecks` array, JS-unescaped the way the template literal is evaluated. */
function mjsChecks(): Map<number, string> {
  const out = new Map<number, string>();
  for (const m of mjs.matchAll(/\n {2}\[(\d+), "([^"]*)", `([\s\S]*?)`\],(?=\n)/g)) {
    out.set(Number(m[1]), m[3]!.replaceAll("\\\\", "\\"));
  }
  return out;
}

/** `CREATE FUNCTION pg_temp.edge_check_N() ... SELECT array_agg(v ORDER BY v) FROM ( <BODY> ) AS t(v)` in the matrix file. */
function matrixChecks(): Map<number, string> {
  const out = new Map<number, string>();
  for (const m of matrix.matchAll(/CREATE FUNCTION pg_temp\.edge_check_(\d+)\(\) RETURNS text\[\] LANGUAGE sql AS \$f\$\n([\s\S]*?)\n\$f\$;\n/g)) {
    const inner = m[2]!.match(/^\s*SELECT array_agg\(v ORDER BY v\) FROM \(\n([\s\S]*)\n\s*\) AS t\(v\)\s*$/);
    if (inner) out.set(Number(m[1]), inner[1]!);
  }
  return out;
}

describe("edge-role checks: the .mjs and the matrix 10 copies are one SQL", () => {
  const a = mjsChecks();
  const b = matrixChecks();
  it("both files are parsed (the extraction itself is not silently empty)", () => {
    expect([...a.keys()].sort((x, y) => x - y)).toEqual(expect.arrayContaining([9, 10, 11, 12, 13, 14, 15]));
    expect([...b.keys()].sort((x, y) => x - y)).toEqual(expect.arrayContaining([9, 10, 11, 12, 13, 14, 15]));
  });
  for (const n of [9, 10, 11, 12, 13, 14, 15]) {
    it(`check ${n}: identical SQL in verify-function-inventory.mjs and 10_function_inventory.sql`, () => {
      expect(a.has(n), `the .mjs has no check ${n}`).toBe(true);
      expect(b.has(n), `matrix 10 embeds no check ${n}`).toBe(true);
      expect(squash(b.get(n)!)).toBe(squash(a.get(n)!));
    });
  }
  /** The SQL text between `/* marker *\/` and `/* end_marker *\/`, and the quoted strings inside its ARRAY[...] (a quote is doubled inside a string). */
  function inlineList(sql: string, marker: string): string[] {
    const m = sql.match(new RegExp(`/\\* ${marker} \\*/(.*?)/\\* end_${marker} \\*/`, "s"));
    expect(m, `check 14 carries no /* ${marker} */ ... /* end_${marker} */ block`).not.toBeNull();
    return [...m![1]!.matchAll(/'((?:[^']|'')*)'/g)].map((x) => x[1]!.replaceAll("''", "'")).sort();
  }
  const fixtureEntries = (text: string) => text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).sort();
  it("check 14: the inline lists in the check's SQL (the matrix twin's defaults) ARE the checked-in fixtures, entry for entry", () => {
    expect(inlineList(a.get(14)!, "kind_readers")).toEqual(fixtureEntries(kindFixture));
    expect(inlineList(a.get(14)!, "session_class_functions")).toEqual(fixtureEntries(sessionClassFixture));
    expect(inlineList(b.get(14)!, "kind_readers")).toEqual(fixtureEntries(kindFixture));
    expect(inlineList(b.get(14)!, "session_class_functions")).toEqual(fixtureEntries(sessionClassFixture));
  });
  it("check 14: the .mjs substitutes both fixtures between exactly these markers (a drifted marker would make the run-time replace a silent no-op, leaving the default list in force)", () => {
    for (const marker of ["kind_readers", "session_class_functions"]) {
      expect(mjs, `${marker}: the .mjs does not substitute this marker`).toContain(`"${marker}"`);
      expect(a.get(14)!.split(`/* ${marker} */`).length - 1, `${marker} must open exactly once in check 14`).toBe(1);
      expect(a.get(14)!.split(`/* end_${marker} */`).length - 1, `${marker} must close exactly once in check 14`).toBe(1);
    }
  });
});
