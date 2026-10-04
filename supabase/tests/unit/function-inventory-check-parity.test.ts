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
    expect([...a.keys()].sort((x, y) => x - y)).toEqual(expect.arrayContaining([9, 10, 11, 12, 13, 14]));
    expect([...b.keys()].sort((x, y) => x - y)).toEqual(expect.arrayContaining([9, 10, 11, 12, 13, 14]));
  });
  for (const n of [9, 10, 11, 12, 13, 14]) {
    it(`check ${n}: identical SQL in verify-function-inventory.mjs and 10_function_inventory.sql`, () => {
      expect(a.has(n), `the .mjs has no check ${n}`).toBe(true);
      expect(b.has(n), `matrix 10 embeds no check ${n}`).toBe(true);
      expect(squash(b.get(n)!)).toBe(squash(a.get(n)!));
    });
  }
  it("check 14: the literal default kind-exception list is the fixture's own entry (the matrix cell and the build check the same list)", () => {
    const entries = kindFixture.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    expect(entries).toEqual(["private.actor_uid()"]);
    expect(a.get(14)!).toContain("ARRAY['private.actor_uid()']");
  });
  it("check 14: the .mjs's substitution constant IS that literal (a drifted constant would make the run-time replace a silent no-op, leaving the default list in force)", () => {
    const m = mjs.match(/const PARTNER_KIND_DEFAULT = "([^"]*)";/);
    expect(m, "PARTNER_KIND_DEFAULT is not declared as a plain string constant").not.toBeNull();
    expect(m![1]).toBe("ARRAY['private.actor_uid()']");
    expect(a.get(14)!.split(m![1]!).length - 1, "the constant must occur exactly once in check 14's SQL").toBe(1);
  });
});
