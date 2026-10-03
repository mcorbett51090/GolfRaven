// supabase/tests/integration/edge-role.deno.test.ts
//
// Edge role PR2 (follow-up 6, design §6): the pieces of `privileged.ts` that exist only because of the
// NOBYPASSRLS `edge_gateway` login, proved against the REAL cluster tools/db/test.sh builds:
//   - the startup self-check refuses a connection that is not a plain `edge_gateway` (a BYPASSRLS / superuser URL,
//     a login that is not `edge_gateway`, a membership of `service_role`), fails CLOSED (a plain Error: a 500),
//     and never caches a failure;
//   - `openScopedTx` really scopes: a deliberately UNSCOPED raw query inside it returns 0 foreign rows, a forgotten
//     bind fails closed, and a bind that bound somebody else fails closed BEFORE the operation runs;
//   - the `edge_system` kind is `edge_system` and can read no personal data;
//   - `EDGE_DB_MODE` is gone (edge role PR4b): there is one mode, and nothing reads that variable any more.
//
// The edge connection string is built by _helpers.ts from PGHOST / PGPORT / PGDATABASE and the provisioned
// `edge_gateway` login (the harness cluster's auth is `trust`; no password literal exists anywhere in the repo).

import { assert, assertEquals, assertRejects } from "https://deno.land/std@0.224.0/assert/mod.ts";
import postgres from "https://deno.land/x/postgresjs@v3.4.5/mod.js";
import { adminSql, createTestUser, ensureServiceRole, freshUuid, makeActor } from "./_helpers.ts";
import {
  assertEdgeConnectionSafe,
  hitRateLimitForActor,
  openScopedTx,
  resetPrivilegedConnectionsForTests,
  setEdgeSelfCheckScheduleForTests,
  userBind,
  withOwnership,
} from "../../functions/_shared/privileged.ts";
import { HttpError } from "../../functions/_shared/http.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };

const PGHOST = Deno.env.get("PGHOST")!;
const PGPORT = Number(Deno.env.get("PGPORT"));
const PGUSER = Deno.env.get("PGUSER")!;
const PGDATABASE = Deno.env.get("PGDATABASE")!;
const GOOD_EDGE_URL = Deno.env.get("GOLFRAVEN_EDGE_DB_URL")!;

/** One test, with the connections (and the self-check schedule) reset afterwards: a test here points `GOLFRAVEN_EDGE_DB_URL` at other
 * logins and shrinks the self-check interval, and none of that may leak into a later test or file. */
function edgeTest(name: string, fn: () => void | Promise<void>): void {
  Deno.test(name, DT, async () => {
    try {
      await fn();
    } finally {
      await resetPrivilegedConnectionsForTests();
    }
  });
}

async function withEdgeUrl<T>(url: string, fn: () => Promise<T>): Promise<T> {
  await resetPrivilegedConnectionsForTests();
  Deno.env.set("GOLFRAVEN_EDGE_DB_URL", url);
  try {
    return await fn();
  } finally {
    Deno.env.set("GOLFRAVEN_EDGE_DB_URL", GOOD_EDGE_URL);
    await resetPrivilegedConnectionsForTests();
  }
}

/** A raw connection as the harness role (`postgres` under HARNESS_MODE=superuser, `migration_owner` under restricted). */
function rawHarness() {
  return postgres({ host: PGHOST, port: PGPORT, username: PGUSER, database: PGDATABASE, max: 1, prepare: false });
}

async function withFreshUserWithDevice(label: string): Promise<{ uid: string; deviceId: string }> {
  const uid = freshUuid();
  await createTestUser(uid, `edge-${label}-${uid.slice(0, 8)}`);
  await ensureServiceRole();
  const deviceId = freshUuid();
  await adminSql()`insert into app.device (id, user_id, platform) values (${deviceId}, ${uid}, 'ios')`;
  return { uid, deviceId };
}

edgeTest("self-check: a connection that is not edge_gateway (the harness role: a superuser, or at least not the edge login) is REFUSED, as a plain Error, and the refusal is not cached", async () => {
  const harnessUrl = `postgres:///${PGDATABASE}`; // host-less: PGHOST/PGPORT/PGUSER from the environment = the harness role
  await withEdgeUrl(harnessUrl, async () => {
    const actor = makeActor(freshUuid());
    for (let attempt = 0; attempt < 2; attempt++) {
      const err = await assertRejects(() => withOwnership(actor, async () => "must never run")) as Error;
      assert(!(err instanceof HttpError), "an unacceptable connection is a server fault (500), never an HttpError the client could act on");
      assert(String(err.message).includes("the edge database connection is not acceptable"), err.message);
      assert(String(err.message).includes("session_user is"), err.message);
    }
    // every other entry point fails closed the same way
    await assertRejects(() => hitRateLimitForActor(actor, "edge-role-selfcheck", 60, 5), Error, "not acceptable");
    await assertRejects(() => openScopedTx("system", { expectedUid: null }, async () => 1), Error, "not acceptable");
  });
});

Deno.test("self-check: the harness role's own flags are reported (a SUPERUSER / BYPASSRLS connection says so)", DT, async () => {
  const raw = rawHarness();
  try {
    const me = await raw`select rolsuper, rolbypassrls from pg_roles where rolname = session_user`;
    const privileged = Boolean(me[0]?.rolsuper || me[0]?.rolbypassrls);
    if (!privileged) return; // restricted harness mode: the role is neither; the previous test already covers "not edge_gateway"
    const err = await assertRejects(() => assertEdgeConnectionSafe(raw)) as Error;
    assert(err.message.includes("SUPERUSER or BYPASSRLS"), err.message);
  } finally {
    await raw.end({ timeout: 1 });
  }
});

edgeTest("self-check (0041): edge_signin_minter is part of edge_gateway's membership closure and the check ACCEPTS it; the minter made BYPASSRLS is refused by the self-check AND by the signin_mint transaction's own role assertion (needs a superuser harness; reverted afterwards)", async () => {
  const raw = rawHarness();
  try {
    // the closure the self-check walks (the same recursive query), read as the harness role: exactly the four roles of the model
    const closure = (await raw`
      with recursive clo(oid) as (
        select oid from pg_catalog.pg_roles where rolname = 'edge_gateway'
        union
        select m.roleid from pg_catalog.pg_auth_members m join clo c on m.member = c.oid
      )
      select array_agg(r.rolname::text order by r.rolname::text) as names from clo join pg_catalog.pg_roles r on r.oid = clo.oid`)[0]!.names as string[];
    assertEquals(closure, ["edge_actor", "edge_gateway", "edge_signin_minter", "edge_system"], "edge_gateway reaches exactly the three roles it may SET into (and nothing a membership could smuggle in)");
    // accepted: a transaction of the new kind opens and runs as the minter, behind the same self-check gate
    await withEdgeUrl(GOOD_EDGE_URL, async () => {
      assertEquals(await openScopedTx("signin_mint", { expectedUid: null }, async (trx) => (await trx`select current_user::text as u`)[0]!.u), "edge_signin_minter");
    });
    const me = await raw`select rolsuper from pg_roles where rolname = session_user`;
    if (!me[0]?.rolsuper) {
      console.log("edge-role minter self-check mutation cell: skipped (the harness role is not a superuser; HARNESS_MODE=superuser runs it)");
      return;
    }
    try {
      // (1) the gate: a fresh connection walks the closure, which now holds a BYPASSRLS role
      await raw.unsafe("alter role edge_signin_minter bypassrls");
      await withEdgeUrl(GOOD_EDGE_URL, async () => {
        const err = await assertRejects(() => openScopedTx("signin_mint", { expectedUid: null }, async () => "must never run")) as Error;
        assert(err.message.includes("a role in its membership closure is SUPERUSER or BYPASSRLS"), err.message);
      });
      await raw.unsafe("alter role edge_signin_minter nobypassrls");
      // (2) the per-transaction assertion on its own: the gate has already trusted the connection (inside its interval), then the role changes
      await withEdgeUrl(GOOD_EDGE_URL, async () => {
        assertEquals(await openScopedTx("signin_mint", { expectedUid: null }, async () => "first"), "first");
        await raw.unsafe("alter role edge_signin_minter bypassrls");
        const err = await assertRejects(() => openScopedTx("signin_mint", { expectedUid: null }, async () => "must never run")) as Error;
        assert(err.message.includes("role 'edge_signin_minter' is SUPERUSER or BYPASSRLS"), err.message);
      });
    } finally {
      await raw.unsafe("alter role edge_signin_minter nobypassrls");
    }
    await withEdgeUrl(GOOD_EDGE_URL, async () => {
      assertEquals(await openScopedTx("signin_mint", { expectedUid: null }, async (trx) => (await trx`select current_user::text as u`)[0]!.u), "edge_signin_minter", "recovered after the fixture was reverted");
    });
  } finally {
    await raw.end({ timeout: 1 });
  }
});

edgeTest("self-check: edge_gateway made BYPASSRLS, or a member of service_role / authenticated, is REFUSED (needs a superuser harness; reverted afterwards)", async () => {
  const raw = rawHarness();
  try {
    const me = await raw`select rolsuper from pg_roles where rolname = session_user`;
    if (!me[0]?.rolsuper) {
      console.log("edge-role self-check mutation cells: skipped (the harness role is not a superuser; HARNESS_MODE=superuser runs them)");
      return;
    }
    // Baseline: the clean connection passes.
    await withEdgeUrl(GOOD_EDGE_URL, async () => {
      assertEquals(await withOwnership(makeActor((await withFreshUserWithDevice("baseline")).uid), async () => "ok"), "ok");
    });
    const cases: Array<{ name: string; apply: string; revert: string; expect: string }> = [
      { name: "BYPASSRLS", apply: "alter role edge_gateway bypassrls", revert: "alter role edge_gateway nobypassrls", expect: "SUPERUSER or BYPASSRLS" },
      { name: "SUPERUSER", apply: "alter role edge_gateway superuser", revert: "alter role edge_gateway nosuperuser", expect: "SUPERUSER or BYPASSRLS" },
      { name: "member of service_role", apply: "grant service_role to edge_gateway", revert: "revoke service_role from edge_gateway", expect: "member of service_role" },
      { name: "member of authenticated", apply: "grant authenticated to edge_gateway", revert: "revoke authenticated from edge_gateway", expect: "member of authenticated" },
    ];
    for (const c of cases) {
      await raw.unsafe(c.apply);
      try {
        await withEdgeUrl(GOOD_EDGE_URL, async () => {
          const err = await assertRejects(() => withOwnership(makeActor(freshUuid()), async () => "must never run")) as Error;
          assert(err.message.includes(c.expect), `${c.name}: ${err.message}`);
        });
      } finally {
        await raw.unsafe(c.revert);
      }
    }
    // A refusal is not CACHED: on ONE pool (no reset in between), the same connection that was refused passes as soon as
    // the misconfiguration is undone, and is refused again if it comes back.
    await resetPrivilegedConnectionsForTests();
    await raw.unsafe("grant service_role to edge_gateway");
    try {
      const sticky = makeActor((await withFreshUserWithDevice("sticky")).uid);
      await assertRejects(() => withOwnership(sticky, async () => "must never run"), Error, "member of service_role");
      await raw.unsafe("revoke service_role from edge_gateway");
      assertEquals(await withOwnership(sticky, async () => "ok"), "ok", "the failure was not remembered");
      await raw.unsafe("grant service_role to edge_gateway");
      // ...but a SUCCESS is remembered until the schedule's interval runs out (PR3: 5 minutes / 1000 transactions in production, so a
      // test that finishes in milliseconds sees it remembered); the periodic re-check itself is proved in the next test.
      assertEquals(await withOwnership(sticky, async () => "ok"), "ok");
    } finally {
      await raw.unsafe("revoke service_role from edge_gateway");
      await resetPrivilegedConnectionsForTests();
    }
    // The PER-TRANSACTION assertion (the self-check ran once, long ago, and passed): if edge_actor itself ever became
    // BYPASSRLS, the next transaction refuses before running anything.
    await resetPrivilegedConnectionsForTests();
    try {
      const pooled = makeActor((await withFreshUserWithDevice("pertx")).uid);
      assertEquals(await withOwnership(pooled, async () => "ok"), "ok"); // the self-check passes and is remembered
      await raw.unsafe("alter role edge_actor bypassrls");
      const err = await assertRejects(() => withOwnership(pooled, async () => "must never run")) as Error;
      assert(err.message.includes("is SUPERUSER or BYPASSRLS"), err.message);
      assert(err.message.includes("'edge_actor'"), err.message);
    } finally {
      await raw.unsafe("alter role edge_actor nobypassrls");
      await resetPrivilegedConnectionsForTests();
    }
    // ...and the clean connection passes again (nothing was left behind, nothing was cached).
    await withEdgeUrl(GOOD_EDGE_URL, async () => {
      assertEquals(await withOwnership(makeActor((await withFreshUserWithDevice("after")).uid), async () => "ok"), "ok");
    });
  } finally {
    await raw.end({ timeout: 1 });
  }
});

edgeTest("PR3 periodic self-check: a change made AFTER the first success (BYPASSRLS, a forbidden membership) is refused once the interval or the call budget runs out, a refusal is never remembered, and recovery is seen at once (needs a superuser harness; reverted afterwards)", async () => {
  const raw = rawHarness();
  try {
    const me = await raw`select rolsuper from pg_roles where rolname = session_user`;
    if (!me[0]?.rolsuper) {
      console.log("edge-role periodic self-check cells: skipped (the harness role is not a superuser; HARNESS_MODE=superuser runs them)");
      return;
    }
    const user = makeActor((await withFreshUserWithDevice("periodic")).uid);
    const ok = () => withOwnership(user, async () => "ok");

    // --- the INTERVAL ---
    await resetPrivilegedConnectionsForTests();
    let now = 1_000_000;
    const checks = setEdgeSelfCheckScheduleForTests({ intervalMs: 60_000, everyNCalls: 0, now: () => now });
    try {
      assertEquals(await ok(), "ok");
      assertEquals(checks(), 1, "the first transaction ran the self-check");
      await raw.unsafe("alter role edge_gateway bypassrls"); // an operator's change AFTER the first success
      assertEquals(await ok(), "ok", "inside the interval the earlier success is trusted (the documented window)");
      assertEquals(checks(), 1, "...and costs no round trip");
      now += 60_000;
      const err = await assertRejects(() => withOwnership(user, async () => "must never run")) as Error;
      assert(err.message.includes("the edge database connection is not acceptable"), err.message);
      assert(err.message.includes("SUPERUSER or BYPASSRLS"), err.message);
      assert(!(err instanceof HttpError), "a server fault (500), never an HttpError the client could act on");
      assertEquals(checks(), 2, "once the interval elapsed the next transaction re-checked");
      // a refusal is not remembered, and the earlier success is withdrawn: the NEXT call checks again and is refused again
      await assertRejects(() => withOwnership(user, async () => "must never run"), Error, "SUPERUSER or BYPASSRLS");
      assertEquals(checks(), 3);
      // every entry point is behind the same gate
      await assertRejects(() => hitRateLimitForActor(user, "edge-role-periodic", 60, 5), Error, "not acceptable");
      await assertRejects(() => openScopedTx("system", { expectedUid: null }, async () => 1), Error, "not acceptable");
      await raw.unsafe("alter role edge_gateway nobypassrls");
      assertEquals(await ok(), "ok", "recovery is seen at once: the refusal was not cached");
      // a forbidden membership, the other thing the check asserts
      await raw.unsafe("grant service_role to edge_gateway");
      now += 60_000;
      await assertRejects(() => withOwnership(user, async () => "must never run"), Error, "member of service_role");
      await raw.unsafe("revoke service_role from edge_gateway");
      assertEquals(await ok(), "ok");
    } finally {
      await raw.unsafe("alter role edge_gateway nobypassrls");
      await raw.unsafe("revoke service_role from edge_gateway").catch(() => {});
      await resetPrivilegedConnectionsForTests();
    }

    // --- the CALL BUDGET (the interval is an hour: only the count can fire) ---
    now = 5_000_000;
    const budgetChecks = setEdgeSelfCheckScheduleForTests({ intervalMs: 3_600_000, everyNCalls: 3, now: () => now });
    try {
      assertEquals(await ok(), "ok"); // check #1
      assertEquals(await ok(), "ok");
      assertEquals(await ok(), "ok");
      assertEquals(await ok(), "ok"); // the third cheap pass
      assertEquals(budgetChecks(), 1);
      await raw.unsafe("alter role edge_gateway bypassrls");
      await assertRejects(() => withOwnership(user, async () => "must never run"), Error, "SUPERUSER or BYPASSRLS");
      assertEquals(budgetChecks(), 2, "the call budget re-checked inside the interval");
    } finally {
      await raw.unsafe("alter role edge_gateway nobypassrls");
      await resetPrivilegedConnectionsForTests();
    }
    // nothing was left behind
    await withEdgeUrl(GOOD_EDGE_URL, async () => {
      assertEquals(await withOwnership(makeActor((await withFreshUserWithDevice("periodic-after")).uid), async () => "ok"), "ok");
    });
  } finally {
    await raw.end({ timeout: 1 });
  }
});

edgeTest("openScopedTx: a deliberately UNSCOPED raw query returns only the bound actor's rows -- 0 foreign rows (FORCE RLS is now the backstop, not the Repo's WHERE clause)", async () => {
  await resetPrivilegedConnectionsForTests();
  const a = await withFreshUserWithDevice("scope-a");
  const b = await withFreshUserWithDevice("scope-b");
  const total = Number((await adminSql()`select count(*)::int as n from app.device`)[0]!.n);
  assert(total >= 2, "control: the table holds other users' devices (and B's)");

  const asA = await openScopedTx("actor", userBind(a.uid), async (trx) => ({
    // NO `where user_id = ...` anywhere: exactly what a Repo method that forgot its ownership filter would run.
    unscoped: Number((await trx`select count(*)::int as n from app.device`)[0]!.n),
    foreign: Number((await trx`select count(*)::int as n from app.device where user_id = ${b.uid}`)[0]!.n),
    foreignById: Number((await trx`select count(*)::int as n from app.device where id = ${b.deviceId}`)[0]!.n),
    own: Number((await trx`select count(*)::int as n from app.device where id = ${a.deviceId}`)[0]!.n),
    actor: (await trx`select private.actor_uid()::text as a`)[0]!.a as string,
    role: (await trx`select current_user::text as u`)[0]!.u as string,
  }));
  assertEquals(asA.foreign, 0, "A sees none of B's devices");
  assertEquals(asA.foreignById, 0, "...not even by primary key");
  assertEquals(asA.own, 1, "control: A sees its own");
  assertEquals(asA.unscoped, 1, "the unscoped count is exactly A's one device, out of every device in the table");
  assert(asA.unscoped < total);
  assertEquals(asA.actor, a.uid);
  assertEquals(asA.role, "edge_actor");

  // the same silence on a write: an unscoped UPDATE touches 0 foreign rows
  const updated = await openScopedTx("actor", userBind(a.uid), async (trx) => {
    const rows = await trx`update app.device set last_seen = now() returning id`;
    return rows.map((r) => r.id as string);
  });
  assertEquals(updated, [a.deviceId], "an UNSCOPED update changes only the bound actor's own device");

  // ...and B, bound, sees B's and not A's
  const asB = await openScopedTx("actor", userBind(b.uid), async (trx) => (await trx`select id from app.device`).map((r) => r.id as string));
  assertEquals(asB, [b.deviceId]);
});

edgeTest("openScopedTx: a FORGOTTEN bind fails closed -- the operation never runs", async () => {
  const a = await withFreshUserWithDevice("nobind");
  let ran = false;
  const err = await assertRejects(() => openScopedTx("actor", { expectedUid: a.uid }, async () => { ran = true; return 1; })) as Error;
  assert(err.message.includes("the bound actor is 'null'"), err.message);
  assertEquals(ran, false);
});

edgeTest("openScopedTx: a bind that bound the WRONG uid fails closed, before the operation runs", async () => {
  const a = await withFreshUserWithDevice("mismatch-a");
  const b = await withFreshUserWithDevice("mismatch-b");
  let ran = false;
  // The caller means B; the bind step (a bug, or a forged value) bound A. The post-bind assertion compares the
  // database's own answer with the identity the caller meant.
  const err = await assertRejects(() =>
    openScopedTx("actor", { expectedUid: b.uid, run: (trx) => trx`select private.bind_actor(${a.uid}::uuid)` }, async () => { ran = true; return 1; })
  ) as Error;
  assert(err.message.includes(`expected '${b.uid}'`), err.message);
  assert(err.message.includes(`'${a.uid}'`), err.message);
  assertEquals(ran, false, "the operation must not have run as the wrong actor");
  // the system kind has no actor to assert, and no expectation either
  assertEquals(await openScopedTx("system", { expectedUid: null }, async (trx) => (await trx`select current_user::text as u`)[0]!.u), "edge_system");
});

edgeTest("openScopedTx: a binding does not leak into the next transaction on the same pooled connection", async () => {
  const a = await withFreshUserWithDevice("leak-a");
  await openScopedTx("actor", userBind(a.uid), async (trx) => (await trx`select count(*)::int as n from app.device`)[0]!.n);
  // Same pool, probably the same physical connection: a transaction that binds NOTHING must see nothing. (Forged by
  // handing openScopedTx an expectation the unbound transaction cannot meet, then reading the raw state it left.)
  let seen: number | null = null;
  await assertRejects(() =>
    openScopedTx("actor", { expectedUid: a.uid }, async (trx) => { seen = Number((await trx`select count(*)::int as n from app.device`)[0]!.n); return 1; })
  );
  assertEquals(seen, null, "the unbound transaction was refused before it could read anything");
});

edgeTest("openScopedTx('system'): runs as edge_system and can read no personal data", async () => {
  await withFreshUserWithDevice("system-reads");
  await assertRejects(
    () => openScopedTx("system", { expectedUid: null }, async (trx) => await trx`select count(*)::int as n from app.device`),
    Error,
    "permission denied for table device",
  );
  // control: it CAN read the public catalog it imports
  const n = await openScopedTx("system", { expectedUid: null }, async (trx) => Number((await trx`select count(*)::int as n from app.catalog_version`)[0]!.n));
  assert(n >= 1);
});

edgeTest("edge mode: withOwnership for a uid that is not in auth.users is refused (bind_actor), never run unbound", async () => {
  let ran = false;
  const err = await assertRejects(() => withOwnership(makeActor(freshUuid()), async () => { ran = true; return 1; })) as Error;
  assert(String(err.message).includes("bind_actor: no such user"), err.message);
  assertEquals(ran, false);
});

edgeTest("edge mode: a rate-limit hit uses the bare key (the database adds the <uid>: prefix) and counts per actor", async () => {
  const a = await withFreshUserWithDevice("rl-a");
  const b = await withFreshUserWithDevice("rl-b");
  const key = `edge-role-rl-${freshUuid().slice(0, 8)}`;
  const r1 = await hitRateLimitForActor(makeActor(a.uid), key, 3600, 2);
  assertEquals(r1, { ok: true, count: 1 });
  assertEquals((await hitRateLimitForActor(makeActor(a.uid), key, 3600, 2)).ok, true);
  const r3 = await hitRateLimitForActor(makeActor(a.uid), key, 3600, 2);
  assertEquals(r3.ok, false, "the over-cap hit is reported, not raised");
  assertEquals((await hitRateLimitForActor(makeActor(b.uid), key, 3600, 2)).count, 1, "B has its own bucket for the same key");
  await ensureServiceRole();
  const stored = await adminSql()`select bucket_key from private.rate_limit_bucket where bucket_key = ${a.uid + ":" + key}`;
  assertEquals(stored.length, 1, "the bucket is stored under <uid>:<key>");
});

// R2 ruling (edge role PR4b): `play.held_review` is NOT one-way for edge_actor, because the scorer legitimately lifts a hold. This cell pins the
// legitimate path (the real Repo, as edge_actor): a play scored held, then re-scored with the attested contribution it lacked, is un-held through
// `play.upsertFromScore`. If a later change makes the column one-way for edge_actor, this cell fails first and the re-score has to be given a definer.
edgeTest("R2 ruling: the scorer lifts a hold through the real Repo as edge_actor (play.upsertFromScore: held true, then re-scored un-held)", async () => {
  const { uid } = await withFreshUserWithDevice("r2");
  const actor = makeActor(uid);
  const score = (heldReview: boolean) =>
    withOwnership(actor, (repo) =>
      repo.play.upsertFromScore({
        courseId: "crs_x1", facilityId: "fac_x", playDate: "2026-09-20", courseDisambiguatedBy: null,
        scoreBadge: 0.6, scoreMonetary: 0.9, hardSignal: true, presenceSignal: true, money: true, heldReview,
        policyVersion: "v1", inputDigest: "r".repeat(64), evidenceIds: [],
      }),
    );
  const held = await score(true);
  await ensureServiceRole();
  const heldOf = async () => (await adminSql()`select held_review from app.play where id = ${held.id}`)[0]!.held_review as boolean;
  assertEquals(await heldOf(), true);
  const lifted = await score(false);
  assertEquals(lifted.id, held.id, "the same play row was re-scored");
  assertEquals(await heldOf(), false, "the scorer lifted the hold: held_review true -> false as edge_actor (the ruling: this stays inside R6)");
});
