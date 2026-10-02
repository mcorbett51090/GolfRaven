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
//   - `EDGE_DB_MODE` accepts only `legacy` / `edge`.
//
// This file forces `EDGE_DB_MODE=edge` itself (privileged.ts reads it on every call), so it exercises the edge path
// in BOTH passes of tools/db/test-deno-integration.sh. Every other file in this directory runs the suite as the pass's
// own mode. The edge connection string is built by _helpers.ts from PGHOST / PGPORT / PGDATABASE and the provisioned
// `edge_gateway` login (the harness cluster's auth is `trust`; no password literal exists anywhere in the repo).

import { assert, assertEquals, assertRejects } from "https://deno.land/std@0.224.0/assert/mod.ts";
import postgres from "https://deno.land/x/postgresjs@v3.4.5/mod.js";
import { adminSql, createTestUser, ensureServiceRole, freshUuid, makeActor } from "./_helpers.ts";
import {
  assertEdgeConnectionSafe,
  getDbMode,
  hitRateLimitForActor,
  openScopedTx,
  resetPrivilegedConnectionsForTests,
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

/**
 * Run one test with EDGE_DB_MODE=edge and put the previous value back afterwards. `Deno.env` is process-wide, so a file
 * that left the mode at `edge` would silently turn every LATER test file of a `legacy` pass into an edge-mode run (and
 * make the two passes of tools/db/test-deno-integration.sh the same pass) -- the restore is the point of this wrapper.
 */
function edgeTest(name: string, fn: () => void | Promise<void>): void {
  Deno.test(name, DT, async () => {
    const before = Deno.env.get("EDGE_DB_MODE");
    Deno.env.set("EDGE_DB_MODE", "edge");
    try {
      await fn();
    } finally {
      if (before === undefined) Deno.env.delete("EDGE_DB_MODE");
      else Deno.env.set("EDGE_DB_MODE", before);
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

Deno.test("EDGE_DB_MODE: only legacy / edge are accepted (unset = legacy); anything else is a configuration error, never a silent default", DT, () => {
  const before = Deno.env.get("EDGE_DB_MODE");
  try {
    Deno.env.delete("EDGE_DB_MODE");
    assertEquals(getDbMode(), "legacy");
    Deno.env.set("EDGE_DB_MODE", "legacy");
    assertEquals(getDbMode(), "legacy");
    Deno.env.set("EDGE_DB_MODE", "edge");
    assertEquals(getDbMode(), "edge");
    for (const bad of ["EDGE", "service_role", "true", "1", " edge"]) {
      Deno.env.set("EDGE_DB_MODE", bad);
      let threw = false;
      try {
        getDbMode();
      } catch (e) {
        threw = true;
        assert(String((e as Error).message).includes("EDGE_DB_MODE must be 'legacy' or 'edge'"));
      }
      assert(threw, `'${bad}' must be refused`);
    }
  } finally {
    if (before === undefined) Deno.env.delete("EDGE_DB_MODE");
    else Deno.env.set("EDGE_DB_MODE", before);
  }
});

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
      // ...but a SUCCESS is remembered for the pool's life (one check per pool, on its first use): this is the documented cost.
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
  assertEquals(stored.length, 1, "the bucket is stored under <uid>:<key>, the exact key legacy mode builds");
});
