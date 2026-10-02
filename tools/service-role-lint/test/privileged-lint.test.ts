import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { lintPrivilegedSource } from "../src/privileged-lint.js";
import { lintSource } from "../src/lint.js";

// Edge role PR4b (docs/security/edge-role-design.md section 5 "Code" and section 9): the privileged-file pass. `privileged.ts` is exempt from
// the general rules (isAllowedFile) but NOT from this pass. Every rule has a must-fail fixture under test/fixtures/privileged/bad/, the shapes the
// real file legitimately uses are a must-pass fixture, and the REAL file must pass. Each rule was also proved by mutating a /tmp copy of the real
// file (docs/security/p3-money-path-requirements.md, "Edge role PR4b", mutation table).

const FIXTURES = join(import.meta.dirname, "fixtures", "privileged");
const PRIVILEGED_PATH = join(import.meta.dirname, "..", "..", "..", "supabase", "functions", "_shared", "privileged.ts");
const fixture = (rel: string) => readFileSync(join(FIXTURES, rel), "utf8");
const rulesOf = (src: string) => lintPrivilegedSource(src).map((f) => f.rule);

describe("privileged-file pass: must-fail fixtures", () => {
  const CASES: Array<[string, string, number?]> = [
    ["bad/service-role-set-local-role.ts", "privileged-forbidden-role"],
    ["bad/set-role-other.ts", "privileged-forbidden-role"],
    ["bad/set-role-quoted.ts", "privileged-forbidden-role"],
    ["bad/set-role-dynamic.ts", "privileged-forbidden-role"],
    ["bad/reset-role.ts", "privileged-forbidden-role"],
    ["bad/session-authorization.ts", "privileged-forbidden-role"],
    ["bad/service-role-literal.ts", "privileged-forbidden-role"],
    ["bad/db-url.ts", "privileged-db-url"],
    ["bad/db-url-other.ts", "privileged-db-url", 2],
    ["bad/service-key-outside-admin.ts", "privileged-service-key"],
    ["bad/env-nonliteral.ts", "privileged-env-access"],
    ["bad/env-to-object.ts", "privileged-env-access"],
    ["bad/stray-begin.ts", "privileged-stray-transaction"],
    ["bad/stray-savepoint.ts", "privileged-stray-transaction"],
    ["bad/stray-begin-destructured.ts", "privileged-stray-transaction"],
    ["bad/stray-pool.ts", "privileged-stray-pool"],
    ["bad/set-config.ts", "privileged-guc-in-ts"],
    ["bad/current-setting.ts", "privileged-guc-in-ts"],
    ["bad/edge-db-mode.ts", "privileged-edge-db-mode"],
    ["bad/edge-db-mode-identifier.ts", "privileged-edge-db-mode"],
  ];

  it("has a fixture for every file in bad/ (a fixture nobody asserts on proves nothing)", () => {
    expect(CASES.map(([f]) => f.replace("bad/", "")).sort()).toEqual(readdirSync(join(FIXTURES, "bad")).sort());
  });

  for (const [file, rule, minCount] of CASES) {
    it(`${file} is flagged ${rule}${minCount ? ` (at least ${minCount}x)` : ""}`, () => {
      const hits = lintPrivilegedSource(fixture(file)).filter((f) => f.rule === rule);
      expect(hits.length).toBeGreaterThanOrEqual(minCount ?? 1);
      for (const h of hits) expect(h.line).toBeGreaterThan(0);
    });
  }

  it("each must-fail fixture is flagged ONLY for its own rule family (no accidental co-fire hiding a missing rule)", () => {
    for (const [file, rule] of CASES) {
      const rules = new Set(rulesOf(fixture(file)));
      expect([...rules], file).toContain(rule);
    }
    // the two shapes that are inherently also something else: a quoted `authenticator` role switch and a SET ROLE postgres are role findings only
    expect(new Set(rulesOf(fixture("bad/set-role-other.ts")))).toEqual(new Set(["privileged-forbidden-role"]));
    expect(new Set(rulesOf(fixture("bad/set-role-quoted.ts")))).toEqual(new Set(["privileged-forbidden-role"]));
    expect(new Set(rulesOf(fixture("bad/stray-begin.ts")))).toEqual(new Set(["privileged-stray-transaction"]));
    expect(new Set(rulesOf(fixture("bad/set-config.ts")))).toEqual(new Set(["privileged-guc-in-ts"]));
  });
});

describe("privileged-file pass: what must still pass", () => {
  it("every shape the real file legitimately uses passes (edge roles, the two key functions, openScopedTx / withOwnershipBatch, openPool, the forbidden-memberships list, pg_settings)", () => {
    expect(lintPrivilegedSource(fixture("good/allowed-shapes.ts"))).toEqual([]);
  });

  it("comments are not scanned: a comment may name every banned word", () => {
    const src = "// SUPABASE_DB_URL EDGE_DB_MODE service_role set local role postgres set_config( current_setting(\n/* SUPABASE_SERVICE_ROLE_KEY */ export const x = 1;";
    expect(lintPrivilegedSource(src)).toEqual([]);
  });

  it("the REAL supabase/functions/_shared/privileged.ts passes", () => {
    expect(lintPrivilegedSource(readFileSync(PRIVILEGED_PATH, "utf8"))).toEqual([]);
  });
});

describe("privileged-file pass: edge cases of the rules themselves", () => {
  const run = (sql: string) => rulesOf("export const f = async (t: any) => t`" + sql + "`;");

  it("SET LOCAL ROLE edge_actor / edge_system (any case, quoted or not) is allowed; any other role is not", () => {
    for (const ok of ["set local role edge_actor", "SET LOCAL ROLE edge_system", 'set role "edge_actor"', "set session role edge_system"]) expect(run(ok), ok).toEqual([]);
    for (const bad of ["set local role service_role", "set local role postgres", "set local role authenticated", "set local role anon", "set local role private_definer", "set role edge_gateway"]) {
      expect(run(bad), bad).toContain("privileged-forbidden-role");
    }
  });

  it("a role name that merely STARTS with an edge role is not an edge role", () => {
    expect(run("set local role edge_actor_admin")).toContain("privileged-forbidden-role");
    expect(run("set local role edge_systems")).toContain("privileged-forbidden-role");
  });

  it("a `service_role` literal is a finding in a plain string, a template, and a JSON-ish object key alike", () => {
    expect(rulesOf('export const a = "service_role";')).toContain("privileged-forbidden-role");
    expect(rulesOf("export const a = `grant ${x} to service_role`;")).toContain("privileged-forbidden-role");
    expect(rulesOf('export const a = { "service_role": 1 };')).toContain("privileged-forbidden-role");
  });

  it("the forbidden-memberships exemption is that one declaration and nothing else", () => {
    expect(rulesOf('const EDGE_FORBIDDEN_MEMBERSHIPS = ["service_role"];')).toEqual([]);
    expect(rulesOf('const ELSEWHERE = ["service_role"];')).toContain("privileged-forbidden-role");
  });

  it("the service-role key is allowed in adminClient and isServiceRoleBearer only", () => {
    const key = 'Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")';
    expect(rulesOf(`declare const Deno: any; function adminClient() { return ${key}; }`)).toEqual([]);
    expect(rulesOf(`declare const Deno: any; export function isServiceRoleBearer() { return ${key}; }`)).toEqual([]);
    expect(rulesOf(`declare const Deno: any; function somethingElse() { return ${key}; }`)).toEqual(["privileged-service-key"]);
    // nested inside the allowed function is still the allowed function; an arrow assigned at module level is not
    expect(rulesOf(`declare const Deno: any; function adminClient() { const f = () => ${key}; return f(); }`)).toEqual([]);
    expect(rulesOf(`declare const Deno: any; const k = () => ${key};`)).toEqual(["privileged-service-key"]);
  });

  it("GOLFRAVEN_EDGE_DB_URL is the one database URL", () => {
    expect(rulesOf('declare const Deno: any; const u = Deno.env.get("GOLFRAVEN_EDGE_DB_URL");')).toEqual([]);
    expect(rulesOf('declare const Deno: any; const u = Deno.env.get("SUPABASE_DB_URL");')).toEqual(["privileged-db-url"]);
    expect(rulesOf('declare const Deno: any; const u = Deno.env.get("GOLFRAVEN_EDGE_DB_URL") + Deno.env.get("SUPABASE_DB_URL");')).toEqual(["privileged-db-url"]);
  });

  it(".begin( is allowed in openScopedTx only; .savepoint( in withOwnershipBatch only", () => {
    expect(rulesOf("async function openScopedTx(db: any) { return db.begin(async () => 1); }")).toEqual([]);
    expect(rulesOf("async function withOwnership(db: any) { return db.begin(async () => 1); }")).toEqual(["privileged-stray-transaction"]);
    expect(rulesOf("async function withOwnershipBatch(trx: any) { return trx.savepoint(async () => 1); }")).toEqual([]);
    expect(rulesOf("async function openScopedTx(trx: any) { return trx.savepoint(async () => 1); }")).toEqual(["privileged-stray-transaction"]);
    expect(rulesOf('async function withOwnership(db: any) { return db["begin"](async () => 1); }')).toEqual(["privileged-stray-transaction"]);
  });

  it("a postgres() call is allowed in openPool only", () => {
    expect(rulesOf('import postgres from "postgres"; function openPool(u: string) { return postgres(u); }')).toEqual([]);
    expect(rulesOf('import postgres from "postgres"; function other(u: string) { return postgres(u); }')).toEqual(["privileged-stray-pool"]);
    expect(rulesOf('import pg from "postgres"; function other(u: string) { return new pg(u); }')).toEqual(["privileged-stray-pool"]);
  });

  it("set_config / current_setting are flagged in SQL text, any case, with a space before the paren", () => {
    expect(run("select SET_CONFIG('a', 'b', true)")).toEqual(["privileged-guc-in-ts"]);
    expect(run("select current_setting ('a')")).toEqual(["privileged-guc-in-ts"]);
    expect(run("select setting from pg_settings")).toEqual([]);
  });

  it("Deno.env is allowed only as Deno.env.get(<literal>)", () => {
    expect(rulesOf('declare const Deno: any; const a = Deno.env.get("X");')).toEqual([]);
    expect(rulesOf("declare const Deno: any; const a = Deno.env.get(name);")).toEqual(["privileged-env-access"]);
    expect(rulesOf("declare const Deno: any; const e = Deno.env;")).toEqual(["privileged-env-access"]);
    expect(rulesOf("declare const Deno: any; const a = Deno.env.toObject();")).toEqual(["privileged-env-access"]);
    expect(rulesOf('declare const Deno: any; const a = Deno.env.get("A", "B");')).toEqual(["privileged-env-access"]);
  });

  it("a file that does not parse is a finding, not a pass", () => {
    expect(rulesOf("export const = ;")).toEqual(["parse-error"]);
  });
});

describe("privileged-file pass: wiring", () => {
  const exact = "/repo/supabase/functions/_shared/privileged.ts";
  const bad = fixtureSource("bad/service-role-set-local-role.ts");

  function fixtureSource(rel: string): string {
    return readFileSync(join(FIXTURES, rel), "utf8");
  }

  it("lintSource runs the pass (and only the pass) on the exact privileged.ts path", () => {
    const findings = lintSource(bad, exact);
    expect(new Set(findings.map((f) => f.rule))).toEqual(new Set(["privileged-forbidden-role"]));
  });

  it("the general exemption is unchanged: the same file elsewhere gets the general rules, not the pass", () => {
    const elsewhere = lintSource('import { createClient } from "@supabase/supabase-js"; export const c = createClient("u", "k");', "/repo/supabase/functions/evidence/index.ts");
    expect(elsewhere.length).toBeGreaterThan(0);
    expect(elsewhere.every((f) => !f.rule.startsWith("privileged-"))).toBe(true);
  });

  it("the privileged.ts exemption from the GENERAL rules still holds (a driver import, a supabase-js client and an env read are not findings there)", () => {
    const src = 'import postgres from "postgres"; import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4"; declare const Deno: any; function openPool(u: string) { return postgres(u); } const u = Deno.env.get("GOLFRAVEN_EDGE_DB_URL"); export { createClient, openPool, u };';
    expect(lintSource(src, exact)).toEqual([]);
  });
});
