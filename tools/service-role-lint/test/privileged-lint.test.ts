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
    // edge role PR4c, LOW-1: the shapes the first version of the pass missed
    ["bad/deno-destructured-env.ts", "privileged-env-access"],
    ["bad/globalthis-deno-env.ts", "privileged-global-access"],
    ["bad/globalthis-bracket.ts", "privileged-global-access"],
    ["bad/eval-call.ts", "privileged-global-access"],
    ["bad/dynamic-import.ts", "privileged-global-access"],
    ["bad/driver-alias.ts", "privileged-stray-pool"],
    ["bad/driver-passed-as-argument.ts", "privileged-stray-pool"],
    ["bad/open-pool-url-arg.ts", "privileged-stray-pool"],
    ["bad/open-pool-param.ts", "privileged-stray-pool"],
    ["bad/open-pool-other-url.ts", "privileged-stray-pool"],
    ["bad/computed-member-concat.ts", "privileged-computed-member"],
    ["bad/computed-member-variable.ts", "privileged-computed-member"],
    ["bad/computed-destructure.ts", "privileged-computed-member"],
    ["bad/unsafe-concat-set-role.ts", "privileged-unsafe-sql"],
    ["bad/unsafe-nonliteral.ts", "privileged-unsafe-sql"],
    ["bad/unsafe-alias.ts", "privileged-unsafe-sql"],
    ["bad/unsafe-destructured.ts", "privileged-unsafe-sql"],
    // PR #34 gate LOW-1: the shapes the second version of the pass missed
    ["bad/driver-import-url.ts", "privileged-driver-import"],
    ["bad/driver-import-twice.ts", "privileged-driver-import"],
    ["bad/driver-reexport.ts", "privileged-driver-import"],
    ["bad/create-require.ts", "privileged-driver-import"],
    ["bad/deno-current-target.ts", "privileged-global-access"],
    ["bad/deno-this-member.ts", "privileged-global-access"],
    ["bad/deno-destructure-key.ts", "privileged-global-access"],
    ["bad/sql-file.ts", "privileged-unsafe-sql"],
    // edge role PR #35 (migration 0041): the minter scope
    ["bad/mint-role-outside.ts", "privileged-mint-scope"],
    ["bad/mint-role-literal.ts", "privileged-mint-scope"],
    ["bad/mint-kind-outside.ts", "privileged-mint-scope"],
    ["bad/mint-kind-computed.ts", "privileged-mint-scope"],
    ["bad/mint-scoped-alias.ts", "privileged-mint-scope"],
    // partner auth S1.2 (PA-13): the partner minter kind and role have the same scope, each with its own caller
    ["bad/mint-partner-kind-outside.ts", "privileged-mint-scope"],
    ["bad/mint-partner-kind-wrong-caller.ts", "privileged-mint-scope"],
    ["bad/mint-partner-role-outside.ts", "privileged-mint-scope"],
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
    // PR4c: the new rules each stand alone on their own fixture
    for (const f of ["deno-destructured-env", "globalthis-deno-env", "driver-alias", "open-pool-url-arg", "open-pool-param", "open-pool-other-url", "computed-member-variable", "computed-destructure", "unsafe-nonliteral", "unsafe-alias", "unsafe-destructured", "eval-call", "dynamic-import"]) {
      expect(rulesOf(fixture(`bad/${f}.ts`)).length, f).toBeGreaterThan(0);
    }
    expect(new Set(rulesOf(fixture("bad/deno-destructured-env.ts")))).toEqual(new Set(["privileged-env-access"]));
    expect(new Set(rulesOf(fixture("bad/driver-alias.ts")))).toEqual(new Set(["privileged-stray-pool"]));
    expect(new Set(rulesOf(fixture("bad/open-pool-url-arg.ts")))).toEqual(new Set(["privileged-stray-pool"]));
    expect(new Set(rulesOf(fixture("bad/computed-member-variable.ts")))).toEqual(new Set(["privileged-computed-member"]));
    expect(new Set(rulesOf(fixture("bad/unsafe-nonliteral.ts")))).toEqual(new Set(["privileged-unsafe-sql"]));
  });

  it("each openPool / driver fixture is flagged by exactly ONE finding, so a mutation of just that rule cannot be masked by a neighbouring one", () => {
    for (const f of ["open-pool-url-arg", "open-pool-param", "open-pool-other-url", "driver-alias", "deno-destructured-env", "computed-member-variable", "computed-destructure", "unsafe-nonliteral", "unsafe-alias", "unsafe-destructured", "eval-call", "dynamic-import", "driver-import-url", "driver-import-twice", "driver-reexport", "deno-current-target", "deno-this-member", "deno-destructure-key", "sql-file", "mint-role-outside", "mint-role-literal", "mint-kind-outside", "mint-kind-computed", "mint-scoped-alias", "mint-partner-kind-outside", "mint-partner-kind-wrong-caller", "mint-partner-role-outside"]) {
      expect(lintPrivilegedSource(fixture(`bad/${f}.ts`)), f).toHaveLength(1);
    }
  });

  it("`globalThis[\"Deno\"]` is two findings by design (the global object outside the allow-list, and the member named Deno); create-require is several of one rule", () => {
    expect(new Set(rulesOf(fixture("bad/globalthis-bracket.ts")))).toEqual(new Set(["privileged-global-access"]));
    expect(lintPrivilegedSource(fixture("bad/globalthis-bracket.ts"))).toHaveLength(2);
    expect(new Set(rulesOf(fixture("bad/create-require.ts")))).toEqual(new Set(["privileged-driver-import"]));
  });

  it("the two shapes that are inherently two findings say so: a concatenated SET ROLE is an unsafe-sql finding AND a forbidden-role finding on the folded text; db[\"be\" + \"gin\"] is a computed member AND a stray begin", () => {
    expect(new Set(rulesOf(fixture("bad/unsafe-concat-set-role.ts")))).toEqual(new Set(["privileged-unsafe-sql", "privileged-forbidden-role"]));
    expect(new Set(rulesOf(fixture("bad/computed-member-concat.ts")))).toEqual(new Set(["privileged-computed-member", "privileged-stray-transaction"]));
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

describe("privileged-file pass: PR #34 LOW-1 shapes and the minter scope (edge cases)", () => {
  it("exactly one driver import, by the specifier `postgres`; any other specifier that names the driver is a finding (static, re-export, require, dynamic import)", () => {
    expect(rulesOf('import postgres from "postgres"; export const n = 1;')).toEqual([]);
    expect(rulesOf('import pg3 from "https://deno.land/x/postgresjs@v3.4.5/mod.js"; export const n = 1;')).toEqual(["privileged-driver-import"]);
    expect(rulesOf('import pg3 from "npm:postgres@3.4.5"; export const n = 1;')).toEqual(["privileged-driver-import"]);
    expect(rulesOf('import * as pg3 from "jsr:@x/postgres"; export const n = 1;')).toEqual(["privileged-driver-import"]);
    expect(rulesOf('export * from "https://deno.land/x/postgresjs@v3.4.5/mod.js";')).toEqual(["privileged-driver-import"]);
    expect(rulesOf('import postgres from "postgres"; import again from "postgres";')).toEqual(["privileged-driver-import"]);
    expect(rulesOf('declare const require: any; export const p = require("postgres");')).toEqual(["privileged-driver-import"]);
    expect(rulesOf('declare const require: any; export const p = require(name);')).toEqual(["privileged-driver-import"]);
    expect(rulesOf('export const p = import("https://deno.land/x/postgresjs@v3.4.5/mod.js");')).toContain("privileged-global-access");
    // a TYPE-only import is erased at run time: not a handle
    expect(rulesOf('import postgres from "postgres"; import type { Sql } from "https://deno.land/x/postgresjs@v3.4.5/mod.js"; export type S = Sql;')).toEqual([]);
    // an unrelated import that merely mentions nothing of the kind
    expect(rulesOf('import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4"; export const c = createClient;')).toEqual([]);
  });

  it("createRequire and node:module are findings in every shape", () => {
    expect(rulesOf('import { createRequire } from "node:module"; export const r = 1;')).toContain("privileged-driver-import");
    expect(rulesOf('import * as m from "node:module"; export const r = m.createRequire("file:///x")("postgres");')).toContain("privileged-driver-import");
    expect(rulesOf('export const r = (x: any) => x.createRequire(import.meta.url)("postgres");')).toEqual(["privileged-driver-import"]);
  });

  it("a member named `Deno` is a finding wherever it appears: x.Deno, x?.Deno, x[\"Deno\"], this.Deno, e.currentTarget.Deno, a destructure key", () => {
    for (const bad of ["x.Deno", "x?.Deno", 'x["Deno"]', "x.currentTarget.Deno.env", "x.y.z.Deno"]) {
      expect(rulesOf(`export const f = (x: any) => ${bad};`), bad).toContain("privileged-global-access");
    }
    expect(rulesOf("export function f(this: any) { return this.Deno; }")).toEqual(["privileged-global-access"]);
    expect(rulesOf('export const f = (x: any) => { const { "Deno": d } = x; return d; };')).toEqual(["privileged-global-access"]);
    // a property merely CONTAINING the word is not it
    expect(rulesOf("export const f = (x: any) => x.DenoVersion + x.deno;")).toEqual([]);
  });

  it(".file( and a destructured `file` are findings; .files / .filename are not", () => {
    expect(rulesOf('export const q = (t: any) => t.file("a.sql");')).toEqual(["privileged-unsafe-sql"]);
    expect(rulesOf('export const q = (t: any) => t["file"]("a.sql");')).toEqual(["privileged-unsafe-sql"]);
    expect(rulesOf("export const q = (t: any) => { const { file } = t; return file; };")).toEqual(["privileged-unsafe-sql"]);
    expect(rulesOf("export const q = (t: any) => t.files + t.filename;")).toEqual([]);
  });

  it("the minter role is named only inside openScopedTx; the kind only inside openScopedTx and signinEmailProofs; every kind is a literal; openScopedTx is never aliased", () => {
    const tag = "declare const t: any;";
    expect(rulesOf(`${tag} async function openScopedTx(kind: string) { await t\`set local role edge_signin_minter\`; }`)).toEqual([]);
    expect(rulesOf(`${tag} async function somethingElse() { await t\`set local role edge_signin_minter\`; }`)).toEqual(["privileged-mint-scope"]);
    expect(rulesOf('export const R = "EDGE_SIGNIN_MINTER";')).toEqual(["privileged-mint-scope"]);
    expect(rulesOf('declare function openScopedTx(k: string): void; function signinEmailProofs() { openScopedTx("signin_mint"); }')).toEqual([]);
    expect(rulesOf('declare function openScopedTx(k: string): void; function signinEmailProof() { openScopedTx("signin_mint"); }')).toEqual(["privileged-mint-scope"]);
    expect(rulesOf('declare function openScopedTx(k: string): void; export const k = "signin_" + "mint";')).toEqual(["privileged-mint-scope"]);
    expect(rulesOf("declare function openScopedTx(k: string): void; export const x = (k: string) => openScopedTx(k);")).toEqual(["privileged-mint-scope"]);
    expect(rulesOf('declare function openScopedTx(k: string): void; export const x = [openScopedTx];')).toEqual(["privileged-mint-scope"]);
    // a role that merely STARTS with the minter's name is not the minter, and is not an allowed role
    expect(rulesOf(`${tag} async function openScopedTx() { await t\`set local role edge_signin_minter_x\`; }`)).toContain("privileged-forbidden-role");
    // the three ordinary kinds are unaffected
    expect(rulesOf('declare function openScopedTx(k: string): void; export const a = () => openScopedTx("actor"); export const b = () => openScopedTx("system");')).toEqual([]);
  });

  it("partner auth S1.2 (PA-13): the partner minter role and kind have the SAME scope as the sign-in minter's, each kind with its OWN caller; edge_partner is an ordinary lane role", () => {
    const tag = "declare const t: any;";
    const open = "declare function openScopedTx(k: string): void;";
    // the minter role: only inside openScopedTx
    expect(rulesOf(`${tag} async function openScopedTx(kind: string) { await t\`set local role edge_partner_minter\`; }`)).toEqual([]);
    expect(rulesOf(`${tag} async function withPartnerMint() { await t\`set local role edge_partner_minter\`; }`)).toEqual(["privileged-mint-scope"]);
    expect(rulesOf('export const R = "EDGE_PARTNER_MINTER";')).toEqual(["privileged-mint-scope"]);
    // the kind: only inside openScopedTx and withPartnerMint
    expect(rulesOf(`${open} async function withPartnerMint() { await openScopedTx("partner_mint"); }`)).toEqual([]);
    expect(rulesOf(`${open} async function withPartnerMints() { await openScopedTx("partner_mint"); }`)).toEqual(["privileged-mint-scope"]);
    expect(rulesOf(`${open} async function signinEmailProofs() { await openScopedTx("partner_mint"); }`)).toEqual(["privileged-mint-scope"]);
    expect(rulesOf(`${open} async function withPartnerMint() { await openScopedTx("signin_mint"); }`)).toEqual(["privileged-mint-scope"]);
    expect(rulesOf(`${open} export const k = "partner_" + "mint";`)).toEqual(["privileged-mint-scope"]);
    // the lane role is NOT a minter: any function may use the partner KIND (a bound partner transaction); only the literal rule applies
    expect(rulesOf(`${open} export const a = () => openScopedTx("partner");`)).toEqual([]);
    expect(rulesOf(`${tag} async function openScopedTx() { await t\`set local role edge_partner\`; }`)).toEqual([]);
    // a role that merely STARTS with the lane's name is not the lane
    expect(rulesOf(`${tag} async function openScopedTx() { await t\`set local role edge_partner_x\`; }`)).toContain("privileged-forbidden-role");
    expect(rulesOf(`${tag} async function openScopedTx() { await t\`set local role edge_partners\`; }`)).toContain("privileged-forbidden-role");
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

  const OPEN_POOL = 'declare const Deno: any; import postgres from "postgres"; function openPool() { const u = Deno.env.get("GOLFRAVEN_EDGE_DB_URL"); return postgres(u); }';

  it("a postgres() call is allowed in openPool only, and only with the constant read from GOLFRAVEN_EDGE_DB_URL inside it", () => {
    expect(rulesOf(OPEN_POOL)).toEqual([]);
    expect(rulesOf('declare const Deno: any; import postgres from "postgres"; function other() { const u = Deno.env.get("GOLFRAVEN_EDGE_DB_URL"); return postgres(u); }')).toEqual(["privileged-stray-pool"]);
    expect(rulesOf('import pg from "postgres"; function other(u: string) { return new pg(u); }')).toEqual(["privileged-stray-pool"]);
    // inside openPool, but handed something else
    expect(rulesOf('import postgres from "postgres"; function openPool() { return postgres("postgres://u@h/db"); }')).toEqual(["privileged-stray-pool"]);
    expect(rulesOf('declare const Deno: any; import postgres from "postgres"; function openPool() { const u = Deno.env.get("OTHER_URL"); return postgres(u); }')).toEqual(["privileged-stray-pool"]);
    expect(rulesOf('declare const Deno: any; import postgres from "postgres"; function openPool() { let u = Deno.env.get("GOLFRAVEN_EDGE_DB_URL"); return postgres(u); }')).toEqual(["privileged-stray-pool"]);
    expect(rulesOf('import postgres from "postgres"; function openPool() { return postgres(); }')).toEqual(["privileged-stray-pool"]);
  });

  it("openPool takes no parameter and no call of it passes an argument (LOW-1 a)", () => {
    expect(rulesOf(`${OPEN_POOL} export const p = openPool();`)).toEqual([]);
    expect(rulesOf(`${OPEN_POOL} export const p = (anyUrl: string) => openPool(anyUrl as never);`)).toEqual(["privileged-stray-pool"]);
    expect(rulesOf(`${OPEN_POOL} export const p = openPool(...args);`)).toEqual(["privileged-stray-pool"]);
    expect(rulesOf('import postgres from "postgres"; function openPool(url: string) { return postgres(url); }')).toContain("privileged-stray-pool");
    expect(rulesOf('import postgres from "postgres"; function openPool(url = "x") { return postgres(url); }')).toContain("privileged-stray-pool");
  });

  it("any reference to the driver that is not a call is a finding (LOW-1 c); import bindings and type positions are not references", () => {
    const imp = 'import postgres from "postgres";';
    expect(rulesOf(`${imp} const pg = postgres; export const p = pg("u");`)).toEqual(["privileged-stray-pool"]);
    expect(rulesOf(`${imp} export const list = [postgres];`)).toEqual(["privileged-stray-pool"]);
    expect(rulesOf(`${imp} export const o = { postgres };`)).toEqual(["privileged-stray-pool"]);
    expect(rulesOf(`${imp} export const o = { driver: postgres };`)).toEqual(["privileged-stray-pool"]);
    expect(rulesOf(`${imp} export { postgres };`)).toEqual(["privileged-stray-pool"]);
    expect(rulesOf(`${imp} export const f = (postgres as any);`)).toEqual(["privileged-stray-pool"]);
    expect(rulesOf(`${imp} export const f = (x: any) => x(postgres);`)).toEqual(["privileged-stray-pool"]);
    expect(rulesOf('import * as pgns from "postgres"; export const f = pgns.default("u");')).toEqual(["privileged-stray-pool"]);
    // erased at run time: not references
    expect(rulesOf(`${imp} export type A = ReturnType<typeof postgres>; export type B = postgres.TransactionSql; export const c = (d: ReturnType<typeof postgres>) => d;`)).toEqual([]);
    // a member merely NAMED postgres is not the driver
    expect(rulesOf(`${imp} export const n = (o: any) => o.postgres + { postgres: 1 }.postgres;`)).toEqual([]);
  });

  it("any reference to Deno other than Deno.env.get(<literal>) is a finding (LOW-1 b): destructuring, aliasing, computed names", () => {
    expect(rulesOf('declare const Deno: any; const { env } = Deno; export const v = env.get("A" + k);')).toEqual(["privileged-env-access"]);
    expect(rulesOf("declare const Deno: any; const d = Deno; export const v = d.env.get(k);")).toEqual(["privileged-env-access"]);
    expect(rulesOf('declare const Deno: any; export const v = Deno["env"].get("A");')).toEqual(["privileged-env-access"]);
    expect(rulesOf('declare const Deno: any; export const v = (Deno as any).env.get("A");')).toEqual(["privileged-env-access"]);
    expect(rulesOf('declare const Deno: any; export const v = [Deno].map((d) => d.env.get("A"));')).toEqual(["privileged-env-access"]);
    expect(rulesOf('declare const Deno: any; export const v = Deno.readTextFileSync("/etc/passwd");')).toEqual(["privileged-env-access"]);
    expect(rulesOf('declare const Deno: any; export const v = { Deno };')).toEqual(["privileged-env-access"]);
    // shapes that stay allowed
    expect(rulesOf('declare const Deno: any; export const v = Deno.env.get("A") ?? "";')).toEqual([]);
    // (PR #34: a member NAMED Deno is a finding wherever it is, an object literal's included; and the second is globalThis outside the allow-list: `as`)
    expect(rulesOf('export const v = { Deno: 1 }.Deno + (globalThis as any).addEventListener;')).toEqual(["privileged-global-access", "privileged-global-access"]);
    expect(rulesOf("export type D = typeof Deno;")).toEqual([]);
  });

  it("globalThis / self / window / eval / Function / import() are findings except globalThis.addEventListener (LOW-1 b)", () => {
    for (const bad of ['globalThis.Deno.env.get(k)', 'globalThis["Deno"]', 'self.Deno', 'window.Deno', 'eval("1")', 'new Function("return 1")', 'Function("return 1")', 'globalThis', 'globalThis[k]', 'import("x")', 'globalThis.addEventListener.bind(globalThis)']) {
      expect(rulesOf(`export const v = ${bad};`), bad).toContain("privileged-global-access");
    }
    expect(rulesOf('export const a = typeof globalThis.addEventListener === "function"; if (a) globalThis.addEventListener("error", () => 1);')).toEqual([]);
    // a type named Function, and a member named eval, are not the code builders
    expect(rulesOf("export type F = Function; export const m = { eval: 1 }.eval;")).toEqual([]);
  });

  it("a computed member access with a non-literal key is a finding (LOW-1 d); a literal key, a number and a hole-less template are not", () => {
    expect(rulesOf('export const a = (db: any) => db["be" + "gin"];')).toContain("privileged-computed-member");
    expect(rulesOf("export const a = (db: any, k: string) => db[k];")).toEqual(["privileged-computed-member"]);
    expect(rulesOf("export const a = (db: any, k: string) => db[`x${k}`];")).toEqual(["privileged-computed-member"]);
    expect(rulesOf("export const a = (db: any, i: number) => db[i + 1];")).toEqual(["privileged-computed-member"]);
    expect(rulesOf("export const a = (db: any, k: string) => db?.[k];")).toEqual(["privileged-computed-member"]);
    expect(rulesOf("export const a = (db: any, k: string) => { const { [k]: v } = db; return v; };")).toEqual(["privileged-computed-member"]);
    expect(rulesOf('export const a = (rows: any[], r: any) => [rows[0], rows[12], r["n"], r[`n`]];')).toEqual([]);
    // the template form is a literal, and a literal key spelling `begin` is still the stray-transaction rule's business
    expect(rulesOf("async function w(db: any) { return db[`begin`](async () => 1); }")).toEqual(["privileged-stray-transaction"]);
  });

  it(".unsafe( takes one string literal and nothing else (LOW-1 e)", () => {
    expect(rulesOf('export const a = (t: any) => t.unsafe("select 1");')).toEqual([]);
    expect(rulesOf("export const a = (t: any) => t.unsafe(`select 1`);")).toEqual([]);
    expect(rulesOf("export const a = (t: any, s: string) => t.unsafe(s);")).toEqual(["privileged-unsafe-sql"]);
    expect(rulesOf("export const a = (t: any, s: string) => t.unsafe(`select ${s}`);")).toEqual(["privileged-unsafe-sql"]);
    expect(rulesOf('export const a = (t: any) => t.unsafe("select " + "1");')).toEqual(["privileged-unsafe-sql"]);
    expect(rulesOf("export const a = (t: any) => t.unsafe();")).toEqual(["privileged-unsafe-sql"]);
    expect(rulesOf('export const a = (t: any) => t["unsafe"](x);')).toEqual(["privileged-unsafe-sql"]);
    // a built member name is read as the name it spells (and is a computed-member finding on its own account), so the literal-argument form passes the unsafe rule and the other does not
    expect(rulesOf('export const a = (t: any) => t["un" + "safe"]("select 1");')).toEqual(["privileged-computed-member"]);
    expect(rulesOf('export const a = (t: any, s: string) => t["un" + "safe"](s);')).toEqual(["privileged-computed-member", "privileged-unsafe-sql"]);
    expect(rulesOf("export const a = (t: any) => { const { unsafe } = t; return unsafe; };")).toEqual(["privileged-unsafe-sql"]);
    expect(rulesOf('export const a = (t: any) => { const u = t.unsafe; return u("select 1"); };')).toEqual(["privileged-unsafe-sql"]);
  });

  it("a SET ROLE spelled across two literals is read as the one string it forms (the concatenation is folded)", () => {
    expect(rulesOf('export const a = "SET LOCAL " + "ROLE postgres";')).toEqual(["privileged-forbidden-role"]);
    expect(rulesOf('export const a = "SET LOCAL " + "ROLE " + "edge_actor";')).toEqual([]);
    expect(new Set(rulesOf('export const a = "SUPABASE_" + "DB_URL";'))).toEqual(new Set(["privileged-db-url"]));
    expect(rulesOf('export const a = "SUPABASE_" + "DB" + "_URL";')).toContain("privileged-db-url"); // neither piece names it alone: only the folded text does
    expect(rulesOf('export const a = "SET LOCAL " + "ROLE " + `service_` + "role";')).toContain("privileged-forbidden-role");
    // one finding for the chain, not one per `+`
    expect(rulesOf('export const a = "SET LOCAL " + "ROLE " + "postgres" + ";";')).toEqual(["privileged-forbidden-role"]);
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
    const src = 'import postgres from "postgres"; import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4"; declare const Deno: any; function openPool() { const u = Deno.env.get("GOLFRAVEN_EDGE_DB_URL"); return postgres(u); } const u = Deno.env.get("GOLFRAVEN_EDGE_DB_URL"); export { createClient, openPool, u };';
    expect(lintSource(src, exact)).toEqual([]);
  });
});
