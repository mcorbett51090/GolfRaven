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

describe("privileged.ts — withOwnership is genuinely implemented (P3c), not the old fail-closed stub", () => {
  it("exports withOwnership and getActorFromRequest", () => {
    expect(PRIVILEGED_TS).toMatch(/export (?:async )?function withOwnership/);
    expect(PRIVILEGED_TS).toMatch(/export async function getActorFromRequest/);
  });

  it("no longer throws unconditionally — the B6 stub's 'fails closed' RAISE is gone", () => {
    expect(PRIVILEGED_TS).not.toMatch(/withOwnership\(\) is not implemented yet/);
  });

  // ⛔ FIX (item 2): the whole callback runs inside ONE real transaction
  // (`db.begin(...)`), not a bare `op(buildRepo())` call against
  // autocommitting statements.
  it("withOwnership runs its callback inside a real db.begin() transaction, not bare autocommitting statements", () => {
    expect(PRIVILEGED_TS).toMatch(/export async function withOwnership<T>\(actor: Actor, op: Op<T>\): Promise<T> \{/);
    expect(PRIVILEGED_TS).toMatch(/const db = sql\(\);/);
    // ⛔ FIX (follow-up 13): wrapped in try/await so a timeout SQLSTATE
    // can be mapped to a 503 before it escapes this function — the call
    // itself is unchanged (still one real db.begin() transaction).
    expect(PRIVILEGED_TS).toMatch(/return await \(db\.begin\(async \(trx: TxSql\) => \{/);
  });

  // ⛔ NEW (P3c gate PASS follow-up 13, "503 after a successful commit"):
  // both withOwnership and withOwnershipBatch must give the database a
  // deadline well under http.ts's own 15s request timeout, so a slow
  // statement/lock wait fails INSIDE the transaction (rolling it back)
  // rather than the HTTP layer timing out while the write keeps running
  // and later commits behind the client's back.
  it("withOwnership and withOwnershipBatch both set statement_timeout and lock_timeout below the 15s HTTP request race", () => {
    const statementTimeoutCount = (PRIVILEGED_TS.match(/set local statement_timeout = '10s'/g) ?? []).length;
    const lockTimeoutCount = (PRIVILEGED_TS.match(/set local lock_timeout = '5s'/g) ?? []).length;
    expect(statementTimeoutCount).toBe(2); // withOwnership + withOwnershipBatch
    expect(lockTimeoutCount).toBe(2);
  });

  it("withOwnership and withOwnershipBatch map a statement/lock-timeout SQLSTATE to Errors.serviceUnavailable(), not an opaque 500", () => {
    expect(PRIVILEGED_TS).toMatch(/function mapPgTimeoutError\(err: unknown\): unknown \{/);
    expect(PRIVILEGED_TS).toMatch(/PG_TIMEOUT_SQLSTATES = new Set\(\["57014", "55P03"\]\)/);
    expect(PRIVILEGED_TS).toMatch(/throw mapPgTimeoutError\(err\);/);
  });

  // ⛔ FIX (item 5, the bug this file used to PIN): `actor` is a real,
  // USED parameter — never `_actor` — and `buildRepo` takes it
  // explicitly, closing over `actor.uid` for every Repo method built
  // from it. The old shape (`buildRepo()`, zero args) is asserted ABSENT
  // below, not merely "not required".
  //
  // ⛔ FIX (P3c gate PASS follow-up 14, nit): `buildRepo`'s own `db`
  // parameter was unused (every Repo method queries through `trx`, never
  // `db`) and has been removed — `buildRepo(trx, actor)`/
  // `buildRepo(sp, actor)`, not `buildRepo(db, trx, actor)`/
  // `buildRepo(db, sp, actor)`. This assertion is updated to match, not
  // merely relaxed: the two-arg call sites are asserted PRESENT and the
  // old three-arg shape is asserted ABSENT, so this test would fail
  // again if the dead parameter were reintroduced.
  it("withOwnership (and withOwnershipBatch) pass the REAL actor into buildRepo(trx, actor) — never a zero-arg buildRepo(), never an unused _actor, never a reintroduced unused db param", () => {
    expect(PRIVILEGED_TS).toMatch(/const repo = buildRepo\(trx, actor\);/);
    expect(PRIVILEGED_TS).toMatch(/const repo = buildRepo\(sp, actor\);/);
    expect(PRIVILEGED_TS).not.toMatch(/function withOwnership[^)]*\(_actor: Actor/);
    expect(PRIVILEGED_TS).not.toMatch(/function buildRepo\(\): Repo \{/);
    expect(PRIVILEGED_TS).not.toMatch(/buildRepo\(db, (trx|sp), actor\)/);
  });

  // ⛔ FIX ("Conditions on the BYPASSRLS design", required): the
  // connecting role is not assumed to already BE service_role — activated
  // explicitly, every transaction, with a hard assertion that it worked.
  it("withOwnership activates service_role explicitly (SET LOCAL ROLE) and asserts current_user before building a Repo", () => {
    expect(PRIVILEGED_TS).toMatch(/await trx`set local role service_role`;/);
    expect(PRIVILEGED_TS).toMatch(/if \(check\[0\]\?\.u !== "service_role"\)/);
  });

  it("buildRepo takes the REAL transaction handle and the actor (no unused db param), and returns a Repo", () => {
    expect(PRIVILEGED_TS).toMatch(/function buildRepo\(trx: TxSql, actor: Actor\): Repo \{/);
    // Closes over `actor.uid` once — every Repo method built from this
    // function reads `uid` from closure, not a per-call parameter.
    expect(PRIVILEGED_TS).toMatch(/function buildRepo\(trx: TxSql, actor: Actor\): Repo \{\s*const uid = actor\.uid;/);
    expect(PRIVILEGED_TS).not.toMatch(/function buildRepo\(db: ReturnType<typeof postgres>/);
  });

  it("still never returns the raw supabase-js/postgres client to a caller — only a narrow Repo object", () => {
    // buildRepo(...)'s return type is `Repo` (types.ts) everywhere this
    // file constructs one; `deno check` (this session) confirms it
    // type-checks against that interface, which has no method returning
    // a client.
    expect(PRIVILEGED_TS).toMatch(/function buildRepo\(trx: TxSql, actor: Actor\): Repo \{/);
  });
});
