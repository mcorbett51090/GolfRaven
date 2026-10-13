// supabase/tests/unit/facility-programme-off-roster-parity.test.ts
//
// P5 section 140 (0110): the roster rule exists in FOUR places that must stay one rule, and a fifth fact (the pinned pre-image) must stay true.
//   1. the definer: the EXISTS in migration 0110 (private.partner_facility_programme_upsert_for_partner);
//   2. the owner's query: tools/db/facility-programme-off-roster.sql (run once at the first deploy to list the rows written before the fix);
//   3. the same query inside matrix 88 (which runs it against the definer, row by row);
//   4. the same query in the design log (section 140), where the owner reads it;
//   5. the md5 pinned in 0110 must be the md5 of the 0059 function source, and the new body must be that source plus the listed edit and nothing else.
// A change to one copy that is not made to the others turns the owner's list into a lie about the rule the editor enforces; this test is what makes that a build failure.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = join(import.meta.dirname, "..", "..", "..");
const read = (...p: string[]) => readFileSync(join(ROOT, ...p), "utf8");
const tool = read("tools", "db", "facility-programme-off-roster.sql");
const matrix = read("supabase", "tests", "matrix", "88_partner_facility_programme_roster.sql");
const mig = read("supabase", "migrations", "0110_partner_facility_programme_roster.sql");
const mig0059 = read("supabase", "migrations", "0059_partner_programme_sponsors.sql");
const design = read("docs", "security", "partner-auth-design.md");

const squash = (s: string) => s.replace(/\s+/g, " ").trim();
const BEGIN = "-- BEGIN off-roster query";
const END = "-- END off-roster query";

/** The text between the BEGIN and END marker comments; asserts exactly one pair. */
function marked(text: string, where: string): string {
  expect(text.split(BEGIN).length - 1, `${where}: exactly one "${BEGIN}"`).toBe(1);
  expect(text.split(END).length - 1, `${where}: exactly one "${END}"`).toBe(1);
  const a = text.indexOf(BEGIN) + BEGIN.length;
  const b = text.indexOf(END);
  expect(b, `${where}: END after BEGIN`).toBeGreaterThan(a);
  return text.slice(a, b);
}

describe("section 140: the off-roster query and the editor's check are one rule", () => {
  const q = squash(marked(tool, "tools/db/facility-programme-off-roster.sql"));

  it("the query is not empty and is a read-only SELECT", () => {
    expect(q.startsWith("SELECT fp.trail_id, fp.facility_id")).toBe(true);
    expect(/\b(insert|update|delete|truncate|alter|drop|create|grant)\b/i.test(q)).toBe(false);
  });

  it("matrix 88 runs the same text", () => {
    expect(squash(marked(matrix, "matrix 88"))).toBe(q);
  });

  it("the design log (section 140) prints the same text", () => {
    expect(squash(marked(design, "partner-auth-design.md"))).toBe(q);
  });

  it("the definer's EXISTS is the query's, with the row's columns replaced by the call's arguments", () => {
    const fromQuery = /NOT EXISTS \(\s*(SELECT 1[\s\S]*?)\s*\)\s*ORDER BY/.exec(marked(tool, "tool"));
    expect(fromQuery, "the query has a NOT EXISTS ( SELECT 1 ... ) ORDER BY").not.toBeNull();
    const expected = squash(fromQuery![1]!.replaceAll("fp.trail_id", "p_trail_id").replaceAll("fp.facility_id", "p_facility_id"));
    // the function body written in the CREATE OR REPLACE (the last one in the file), not the listed-edit copy
    const body = mig.slice(mig.lastIndexOf("CREATE OR REPLACE FUNCTION private.partner_facility_programme_upsert_for_partner("));
    const fromFn = /IF NOT EXISTS \(\s*(SELECT 1\s+FROM app\.catalog_roster_member[\s\S]*?)\s*\)\s*THEN\s*RAISE EXCEPTION 'partner_facility_programme_upsert_for_partner: the facility must be on the current roster/.exec(body);
    expect(fromFn, "the definer has IF NOT EXISTS ( SELECT 1 ... ) THEN RAISE EXCEPTION ...roster").not.toBeNull();
    expect(squash(fromFn![1]!.replaceAll("pg_catalog.", ""))).toBe(expected);
  });
});

describe("section 140: 0110 is the 0059 function plus the one listed edit, and changes no data", () => {
  // prosrc of the 0059 definer: the text between the dollar quotes of its CREATE FUNCTION, verbatim
  const m59 = /CREATE FUNCTION private\.partner_facility_programme_upsert_for_partner\([\s\S]*?\nAS \$\$([\s\S]*?)\$\$;/.exec(mig0059);
  const src59 = m59 ? m59[1]! : "";

  it("the md5 pinned in 0110 is the md5 of the 0059 function source", () => {
    expect(m59, "0059 defines the function").not.toBeNull();
    const pinned = /md5\(r\.old_src\) <> '([0-9a-f]{32})'/.exec(mig);
    expect(pinned, "0110 pins an md5 before any DDL").not.toBeNull();
    expect(createHash("md5").update(src59).digest("hex")).toBe(pinned![1]);
    // the pin and the message agree (the message repeats the expected hash)
    expect(mig.includes(`expected ${pinned![1]}`)).toBe(true);
  });

  it("the pin is checked BEFORE the first statement that changes the database", () => {
    const pre = mig.indexOf("md5(r.old_src) <> '");
    for (const ddl of ["GRANT SELECT (", "CREATE POLICY", "CREATE OR REPLACE FUNCTION private.partner_facility_programme_upsert_for_partner(", "SET ROLE private_definer", "COMMENT ON FUNCTION"]) {
      const at = mig.indexOf(ddl);
      expect(at, `${ddl} is in the migration`).toBeGreaterThan(-1);
      expect(at, `${ddl} comes after the pre-DDL check`).toBeGreaterThan(pre);
    }
  });

  it("the new body is the 0059 body with the listed edit applied, and nothing else", () => {
    const edit = /\$o1\$([\s\S]*?)\$o1\$,\s*\$n1\$([\s\S]*?)\$n1\$\)/.exec(mig);
    expect(edit, "the listed edit").not.toBeNull();
    const [, oldFrag, newFrag] = edit!;
    expect(src59.split(oldFrag!).length - 1, "the old fragment occurs exactly once in the 0059 source").toBe(1);
    const expected = src59.replace(oldFrag!, () => newFrag!);
    const create = /CREATE OR REPLACE FUNCTION private\.partner_facility_programme_upsert_for_partner\([\s\S]*?\nAS \$\$([\s\S]*?)\$\$;/.exec(mig);
    expect(create, "0110 redefines the function").not.toBeNull();
    expect(create![1]).toBe(expected);
  });

  it("the redefinition has 0059's signature, return shape, language, SECURITY DEFINER and search_path, and no volatility or leakproof clause", () => {
    const head = (t: string, kw: string) => {
      const m = new RegExp(`${kw} FUNCTION private\\.partner_facility_programme_upsert_for_partner\\(([\\s\\S]*?)\\nAS \\$\\$`).exec(t);
      expect(m, `${kw} header`).not.toBeNull();
      return squash(m![1]!);
    };
    const h59 = head(mig0059, "CREATE");
    const h110 = head(mig, "CREATE OR REPLACE");
    expect(h110).toBe(h59);
    expect(h110.endsWith("RETURNS TABLE (o_status text) LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''")).toBe(true);
    expect(/\b(STABLE|IMMUTABLE|LEAKPROOF|PARALLEL|STRICT|SECURITY INVOKER|COST|ROWS)\b/i.test(h110)).toBe(false);
  });

  it("outside function bodies the migration never writes to app.facility_programme (existing rows are untouched)", () => {
    const stripped = mig
      .replace(/\$([A-Za-z0-9_]*)\$[\s\S]*?\$\1\$/g, " ") // every dollar-quoted body / fragment / DO block
      .replace(/--[^\n]*/g, " ");
    expect(/\b(insert\s+into|update|delete\s+from|truncate(\s+table)?|alter\s+table)\s+(only\s+)?app\.facility_programme\b/i.test(stripped)).toBe(false);
    // and the DO blocks hold no write to it either
    const doBlocks = [...mig.matchAll(/DO \$([A-Za-z0-9_]+)\$([\s\S]*?)\$\1\$/g)].map((m) => m[2]!.replace(/'(?:[^']|'')*'/g, "''")).join("\n"); // string literals dropped: the checks MENTION the write
    expect(/\b(insert\s+into|update|delete\s+from|truncate)\s+(only\s+)?app\.facility_programme\b/i.test(doBlocks)).toBe(false);
  });

  it("the migration touches only the one function, the four reads and their registry rows (no other function is redefined)", () => {
    const creates = [...mig.matchAll(/CREATE (?:OR REPLACE )?FUNCTION ([a-z_.0-9]+)\(/gi)].map((m) => m[1]);
    expect(creates.sort()).toEqual(["pg_temp.r110_edit", "private.partner_facility_programme_upsert_for_partner"]);
    const grants = [...mig.matchAll(/^GRANT SELECT \(([^)]*)\) ON (app\.[a-z_]+) TO ([a-z_]+);/gim)].map((m) => `${m[2]}:${m[3]}`);
    expect(grants.sort()).toEqual(["app.catalog_course:private_definer", "app.catalog_hole:private_definer", "app.catalog_roster_member:private_definer", "app.catalog_roster_version:private_definer"]);
    expect(/GRANT\s+(ALL|INSERT|UPDATE|DELETE)\b[^;]*ON\s+app\.catalog/i.test(mig)).toBe(false);
    expect(/\bTO\s+(PUBLIC|authenticated|anon|edge_[a-z_]+|service_role)\b/i.test(mig.replace(/--[^\n]*/g, " ").replace(/\$([A-Za-z0-9_]*)\$[\s\S]*?\$\1\$/g, " "))).toBe(false);
  });
});
