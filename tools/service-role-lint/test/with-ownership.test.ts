import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// build plan §4.7.1a (docs/golf-trails/02-build-plan.md:1189-1196).
//
// ⛔ REWRITE (P3c gate round 2, item 5: "withOwnership ignores the actor
// ... rewrite with-ownership.test.ts to assert the correct shape. It
// currently pins the bug."). The PRIOR version of this file (still
// correct for the pre-P3c-gate-round-2 shape) asserted
// `withOwnership<T>(_actor: Actor, op: Op<T>): Promise<T> { return
// op(buildRepo()); }` — an UNDERSCORE-prefixed, unused `actor` parameter
// and a zero-argument `buildRepo()` — which was ITSELF the bug the gate
// found: every Repo method took an explicit `userId` argument instead,
// so nothing stopped a caller from passing a DIFFERENT user's id than
// the authenticated actor. That shape is gone. `withOwnership` now runs
// the whole callback inside ONE real transaction (item 2: "writes
// silently lost") and `buildRepo(trx, actor)` CLOSES OVER `actor.uid`
// once, so no Repo method takes a user-identity parameter at all
// (types.ts's own header explains this in full). This file still reads
// privileged.ts's SOURCE TEXT rather than importing it as a module —
// unchanged reason: it constructs a real service-role Postgres
// connection and a real Supabase Auth client via `https://`/bare-
// specifier imports Deno resolves natively at runtime (confirmed
// reachable this session via `deno eval`/`deno check`/`deno test`; see
// privileged.ts's own header comment), which plain Node/vitest's ESM
// loader cannot import at all ("Only URLs with a scheme in: file and
// data are supported"). The REAL functional behaviour (transaction
// atomicity, actor scoping, advisory locks, real grants) is now also
// exercised for real — supabase/tests/integration/repo.deno.test.ts and
// handlers.deno.test.ts (P3c gate round 2, item 0), which run this EXACT
// file under Deno against a real Postgres cluster; this file stays
// scoped to "is this still the one construction site, with the right
// actor-scoped shape", the same invariant
// tools/service-role-lint/src/lint.ts enforces mechanically over the
// whole supabase/functions tree (`node tools/service-role-lint/dist/
// cli.js supabase/functions` is clean — see tools/db/test.sh's own
// "service-role lint" step).
const PRIVILEGED_TS = readFileSync(join(import.meta.dirname, "..", "..", "..", "supabase", "functions", "_shared", "privileged.ts"), "utf8");
// The same text without comments, for the "this word appears nowhere in the code" pins (the file's own comments name the deleted things).
const PRIVILEGED_CODE = PRIVILEGED_TS.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

// ⛔ UPDATED (edge role PR4b): the `service_role` / `legacy` shape these pins used to describe is gone. There is ONE transaction opener
// (`openScopedTx`, as edge_actor / edge_system), and `withOwnership`, `withOwnershipBatch`, `withDelegatedActor` and `withSystemCatalogImport`
// are thin callers of it. The pins below say that; the structural bans (no service_role, no stray `.begin(`, ...) are the privileged-file lint
// pass's (privileged-lint.ts, test/privileged-lint.test.ts).
describe("privileged.ts — withOwnership is genuinely implemented (P3c), as one transaction opened by openScopedTx (PR4b)", () => {
  it("exports withOwnership and getActorFromRequest", () => {
    expect(PRIVILEGED_TS).toMatch(/export (?:async )?function withOwnership/);
    expect(PRIVILEGED_TS).toMatch(/export async function getActorFromRequest/);
  });

  it("no longer throws unconditionally — the B6 stub's 'fails closed' RAISE is gone", () => {
    expect(PRIVILEGED_TS).not.toMatch(/withOwnership\(\) is not implemented yet/);
  });

  // ⛔ FIX (item 2): the whole callback runs inside ONE real transaction, not a bare `op(buildRepo())` call against autocommitting statements.
  it("withOwnership runs its callback inside ONE real transaction (openScopedTx -> db.begin), not bare autocommitting statements", () => {
    expect(PRIVILEGED_TS).toMatch(/export async function withOwnership<T>\(actor: Actor, op: Op<T>\): Promise<T> \{/);
    expect(PRIVILEGED_TS).toMatch(/return await openScopedTx\("actor", userBind\(actor\.uid\), \(trx\) => op\(buildRepo\(trx, actor\)\)\);/);
    expect(PRIVILEGED_TS).toMatch(/return await \(db\.begin\(async \(trx: TxSql\) => \{/);
    // and there is exactly ONE db.begin( in the file
    expect((PRIVILEGED_CODE.match(/\.begin\(/g) ?? []).length).toBe(1);
  });

  // ⛔ NEW (P3c gate PASS follow-up 13, "503 after a successful commit"): every transaction must give the database a deadline well under http.ts's
  // own 15s request timeout, so a slow statement/lock wait fails INSIDE the transaction (rolling it back) rather than the HTTP layer timing out while
  // the write keeps running and later commits behind the client's back. ⛔ UPDATED (PR4b): openScopedTx is now the ONLY site that sets them, which is
  // what makes "every transaction has the deadlines" true by construction.
  it("openScopedTx is the one place statement_timeout and lock_timeout are set (so every transaction has them)", () => {
    expect((PRIVILEGED_TS.match(/set local statement_timeout = '10s'/g) ?? []).length).toBe(1);
    expect((PRIVILEGED_TS.match(/set local lock_timeout = '5s'/g) ?? []).length).toBe(1);
    expect((PRIVILEGED_TS.match(/set local transaction_timeout = '12s'/g) ?? []).length).toBe(1);
  });

  it("withOwnership, withOwnershipBatch and withSystemCatalogImport map a statement/lock-timeout SQLSTATE to Errors.serviceUnavailable(), not an opaque 500", () => {
    expect(PRIVILEGED_TS).toMatch(/function mapPgTimeoutError\(err: unknown\): unknown \{/);
    expect(PRIVILEGED_TS).toMatch(/PG_TIMEOUT_SQLSTATES = new Set\(\["57014", "55P03"\]\)/);
    expect(PRIVILEGED_TS).toMatch(/throw mapPgTimeoutError\(err\);/);
  });

  // ⛔ FIX (item 5, the bug this file used to PIN): `actor` is a real, USED parameter — never `_actor` — and `buildRepo` takes it explicitly, closing
  // over `actor.uid` for every Repo method built from it. ⛔ UPDATED (PR4b): buildRepo no longer takes a mode.
  it("withOwnership (and withOwnershipBatch) pass the REAL actor into buildRepo(trx, actor) — never a zero-arg buildRepo(), never an unused _actor, never a mode", () => {
    expect(PRIVILEGED_TS).toMatch(/buildRepo\(trx, actor\)/);
    expect(PRIVILEGED_TS).toMatch(/buildRepo\(sp, actor\)/);
    expect(PRIVILEGED_TS).not.toMatch(/buildRepo\([a-z]+, actor, "/);
    expect(PRIVILEGED_TS).not.toMatch(/function withOwnership[^)]*\(_actor: Actor/);
    expect(PRIVILEGED_TS).not.toMatch(/function buildRepo\(\): Repo \{/);
    expect(PRIVILEGED_TS).not.toMatch(/buildRepo\(db, (trx|sp), actor\)/);
  });

  // ⛔ FIX ("Conditions on the BYPASSRLS design", required, kept in its edge form): the role is activated explicitly, every transaction, with a hard
  // assertion that it worked, and it is an edge role (never service_role: the privileged-file lint pass fails on that literal).
  it("openScopedTx activates an edge role explicitly (SET LOCAL ROLE) and asserts current_user before running anything", () => {
    expect(PRIVILEGED_TS).toMatch(/await trx`set local role edge_actor`;/);
    expect(PRIVILEGED_TS).toMatch(/await trx`set local role edge_system`;/);
    expect(PRIVILEGED_TS).toMatch(/if \(c\?\.u !== role\) throw new Error\(`openScopedTx: expected current_user/);
    expect(PRIVILEGED_TS).not.toMatch(/set local role service_role/);
  });

  it("buildRepo takes the REAL transaction handle and the actor (no unused db param), and returns a Repo", () => {
    expect(PRIVILEGED_TS).toMatch(/function buildRepo\(trx: TxSql, actor: Actor\): Repo \{/);
    // Closes over `actor.uid` once — every Repo method built from this function reads `uid` from closure, not a per-call parameter.
    expect(PRIVILEGED_TS).toMatch(/function buildRepo\(trx: TxSql, actor: Actor\): Repo \{\s*const uid = actor\.uid;/);
    expect(PRIVILEGED_TS).not.toMatch(/function buildRepo\(db: ReturnType<typeof postgres>/);
  });

  it("still never returns the raw supabase-js/postgres client to a caller — only a narrow Repo object", () => {
    expect(PRIVILEGED_TS).toMatch(/function buildRepo\(trx: TxSql, actor: Actor\): Repo \{/);
  });

  it("the legacy path is gone: no mode switch, no service_role pool, no SUPABASE_DB_URL read, no nil-uid system actor", () => {
    expect(PRIVILEGED_CODE).not.toMatch(/getDbMode|DbMode|EDGE_DB_MODE/);
    expect(PRIVILEGED_CODE).not.toMatch(/SUPABASE_DB_URL/);
    expect(PRIVILEGED_CODE).not.toMatch(/SIGNIN_SYSTEM_ACTOR/);
    expect(PRIVILEGED_CODE).not.toMatch(/function sql\(\)/);
  });
});
