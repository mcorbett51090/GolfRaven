// supabase/tests/integration/edge-system-path.deno.test.ts
//
// Edge role PR3 (follow-up 6, step 3 of 4): the SYSTEM path of `import-catalog` runs as `edge_system` and acts for a user only through the
// DELEGATE binders. Proved against the REAL cluster tools/db/test.sh builds. (PR4b: edge is the only mode; the `legacy` pool and its control
// cell are gone, the rest of the cells are unchanged.)
//
//   A. `import-catalog` needs ONE connection string: the whole pipeline (signing-key read, import, both drains, both purges, the rate limit)
//      runs with SUPABASE_DB_URL UNSET, and again with it pointing at an unusable host (nothing reads it any more; the lint also fails the
//      build on any read of it in privileged.ts).
//   B. A delegated transaction binds exactly the owner of the row it names, only while the row's precondition holds, and an unscoped query
//      inside it sees 0 foreign rows. The drain and the rescore are proved to open their per-row transactions with that delegate and that
//      owner (a probe re-opens the identical delegated transaction and reads what the database says).
//   C. The purges run as `edge_system` (revoke the definer's EXECUTE from edge_system and the purge stops working; needs a superuser harness).

import { assert, assertEquals, assertNotEquals, assertRejects } from "https://deno.land/std@0.224.0/assert/mod.ts";
import postgres from "https://deno.land/x/postgresjs@v3.4.5/mod.js";
import { adminSql, createTestUser, ensureServiceRole, freshUuid, rawCount } from "./_helpers.ts";
import {
  delegateBind,
  hitSystemRateLimit,
  openScopedTx,
  resetPrivilegedConnectionsForTests,
  userBind,
  withDelegatedActor,
  withOwnership,
  withSystemCatalogImport,
} from "../../functions/_shared/privileged.ts";
import { drainQueuedCatalog } from "../../functions/_shared/catalog/drain-orchestrator.ts";
import { drainRescoreBacklog } from "../../functions/_shared/catalog/rescore-orchestrator.ts";
import { makeDrainReadRepo } from "../../functions/_shared/catalog/drain-read-repo.ts";
import type { Actor, DelegateRef, WithDelegatedActorFn } from "../../functions/_shared/types.ts";
import { closeStaleBacklog, facilityShard, freshSiteVersion, giveCoursePolygon, ids, mint, newPublisher, newUser, seedDwellAndScore, todayChicago, uniqueCourses } from "./_publisher.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
const NO_GRACE = { sweepDelaySeconds: 0 };
const PGHOST = Deno.env.get("PGHOST")!;
const PGPORT = Number(Deno.env.get("PGPORT"));
const PGUSER = Deno.env.get("PGUSER")!;
const PGDATABASE = Deno.env.get("PGDATABASE")!;
const FAC_Y = "fac_y";
const CRS_Y1 = "crs_y1";
const TODAY_CHICAGO = todayChicago();

/** One test; the connections are reset afterwards, exactly as edge-role.deno.test.ts does. */
function edgeTest(name: string, fn: () => void | Promise<void>): void {
  Deno.test(name, DT, async () => {
    try {
      await fn();
    } finally {
      await resetPrivilegedConnectionsForTests();
    }
  });
}

/** Runs `fn` with SUPABASE_DB_URL (which no code reads any more) unset (`null`) or set to `url`, then restores it. */
async function withLegacyUrl<T>(url: string | null, fn: () => Promise<T>): Promise<T> {
  const before = Deno.env.get("SUPABASE_DB_URL");
  await resetPrivilegedConnectionsForTests();
  if (url === null) Deno.env.delete("SUPABASE_DB_URL");
  else Deno.env.set("SUPABASE_DB_URL", url);
  try {
    return await fn();
  } finally {
    if (before === undefined) Deno.env.delete("SUPABASE_DB_URL");
    else Deno.env.set("SUPABASE_DB_URL", before);
    await resetPrivilegedConnectionsForTests();
  }
}

const UNUSABLE_LEGACY_URL = "postgres://legacy_pool_must_not_be_used:x@legacy-pool-must-not-be-used.invalid:5432/none";

function rawHarness() {
  return postgres({ host: PGHOST, port: PGPORT, username: PGUSER, database: PGDATABASE, max: 1, prepare: false });
}

async function isSuperuserHarness(): Promise<boolean> {
  const raw = rawHarness();
  try {
    const me = await raw`select rolsuper from pg_roles where rolname = session_user`;
    return Boolean(me[0]?.rolsuper);
  } finally {
    await raw.end({ timeout: 1 });
  }
}

/** A `queued_catalog` evidence row of `uid`, inserted as the harness does (the claimed ids are deliberately unresolvable: these rows are bound, not drained). */
async function seedQueued(uid: string, opts: { facilityId?: string; courseId?: string | null; claimedVersion?: string } = {}): Promise<{ evidenceId: string; deviceId: string }> {
  await ensureServiceRole();
  const deviceId = freshUuid();
  await adminSql()`insert into app.device (id, user_id, platform) values (${deviceId}, ${uid}, 'ios')`;
  const claimedVersion = opts.claimedVersion ?? "20260101-0000000";
  const facilityId = opts.facilityId ?? "fac_pr3_not_in_the_ledger";
  const queuedInput = { source: "self_report", deviceId, facilityId, ...(opts.courseId ? { courseId: opts.courseId } : {}), localDate: TODAY_CHICAGO, catalogVersion: claimedVersion };
  const rows = await adminSql()`
    insert into app.evidence (user_id, source, source_ref, input_hash, status, device_id, claimed_facility_id, claimed_course_id, claimed_catalog_version, queued_input, local_date)
    values (${uid}, 'self_report', ${"pr3-" + freshUuid()}, ${"p".repeat(64)}, 'queued_catalog', ${deviceId}, ${facilityId}, ${opts.courseId ?? null}, ${claimedVersion}, ${adminSql().json(queuedInput)}, ${TODAY_CHICAGO})
    returning id`;
  return { evidenceId: rows[0]!.id as string, deviceId };
}

async function newPlainUser(label: string): Promise<Actor> {
  const uid = freshUuid();
  await createTestUser(uid, `pr3-${label}-${uid.slice(0, 8)}`);
  return { uid, role: "authenticated" };
}

/** What the database says inside the delegated transaction `openScopedTx("delegate", delegateBind(ref, expectedUid))` opens, read UNSCOPED (no `where user_id = ...`). */
async function probeDelegate(ref: DelegateRef, expectedUid: string) {
  return await openScopedTx("delegate", delegateBind(ref, expectedUid), async (trx) => {
    const one = async (q: Promise<postgres.RowList<postgres.Row[]>>) => Number((await q)[0]!.n);
    return {
      actor: (await trx`select private.actor_uid()::text as a`)[0]!.a as string,
      role: (await trx`select current_user::text as u`)[0]!.u as string,
      evidence: await one(trx`select count(*)::int as n from app.evidence`),
      plays: await one(trx`select count(*)::int as n from app.play`),
      devices: await one(trx`select count(*)::int as n from app.device`),
    };
  });
}

/** `withDelegatedActor` (the PUBLIC entry point the drains are handed), called with exactly the arguments a drain passes, opens a transaction that is
 * bound as a SYSTEM DELEGATE: the account-export definer refuses it (42501). A transaction bound through `bind_actor` would not be refused, so this is
 * what tells "bound through the delegate binder" from "bound as the user" for the transaction the drain really gets. Read-only: nothing is changed. */
async function assertIsDelegateKind(delegate: DelegateRef, actor: Actor) {
  const err = (await assertRejects(() => withDelegatedActor(delegate, actor, (repo) => repo.me.exportMyData()))) as { code?: string; message: string };
  assertEquals(err.code, "42501");
  assert(err.message.includes("a system delegate may not export an account"), err.message);
}

// ============================================================================
// A. import-catalog needs ONE connection string
// ============================================================================

async function wholeSystemPath(label: string) {
  await closeStaleBacklog();
  const i = ids();
  const pub = await newPublisher();
  const v1 = await freshSiteVersion("20260901");
  const v2 = await freshSiteVersion("20260925");

  // the signing-key read the entrypoint does before any write transaction, as edge_system
  const key = await withSystemCatalogImport((repo) => repo.catalog.getSigningKey((pub as unknown as { kid: string }).kid));
  assertNotEquals(key, null, "the importer repo read the signing key as edge_system");

  // import v1 (ledger, facility, course, version row): the importer repo as edge_system
  await pub.publish(v1, {
    "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "stub", transitions: mint(v1) } } },
    "facilities/us.json": facilityShard(i, "unverified", [{ id: i.k, name: "PR3 K", holes: 18 }]),
  });
  await giveCoursePolygon(i.k);
  const user = await newUser(label);
  const scored = await seedDwellAndScore(user, i.fac, i.k, "unverified", { withCoords: true });
  assert(scored.play.scoreBadge < 0.5, "a stub-era dwell scores below the badge bar");
  assertEquals(await uniqueCourses(user), 0);

  // import v2: the promotion queues a re-score backlog row
  const o2 = await pub.publish(v2, {
    "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "verified", transitions: [...mint(v1), { type: "verified", catalogVersion: v2 }] } } },
    "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "PR3 K", holes: 18 }]),
  });
  assertEquals(o2.promotedCourses, 1);

  // a queued row the drain will resolve (fac_y is verified in the seed), claiming the version that is now current
  const queuedUser = await newPlainUser(`${label}-queued`);
  const currentVersion = (await adminSql()`select site_version from app.catalog_version order by site_version desc nulls last, version desc limit 1`)[0]!.site_version as string;
  const q = await seedQueued(queuedUser.uid, { facilityId: FAC_Y, courseId: CRS_Y1, claimedVersion: currentVersion });

  // the two drains, exactly as import-catalog/index.ts wires them
  const drainRepo = makeDrainReadRepo(withSystemCatalogImport);
  const drained = await drainQueuedCatalog(drainRepo, withDelegatedActor, 200);
  assert(drained.resolved >= 1, `the queued row was drained: ${JSON.stringify(drained)}`);
  assertEquals((await adminSql()`select status from app.evidence where id = ${q.evidenceId}`)[0]!.status, "accepted");
  let completed = 0;
  let purged = 0;
  for (let pass = 0; pass < 8 && completed === 0; pass++) {
    const r = await drainRescoreBacklog(drainRepo, withDelegatedActor, 50, undefined, NO_GRACE);
    completed += r.coursesCompleted;
    purged += r.coordsPurged + r.tombstonesPurged;
    assertEquals(r.failures, 0);
  }
  assertEquals(completed, 1, "the backlog row closed");
  assertEquals(await uniqueCourses(user), 1, "the promoted play was re-scored through the delegate");
  assert(purged >= 0);

  // and the coarse rate limit the entrypoint puts in front of it
  const rl = await hitSystemRateLimit(`pr3-${label}-${freshUuid()}`, 60, 5);
  assertEquals(rl.ok, true);
}

edgeTest("PR3: import-catalog's WHOLE system path (key read, import, queued drain, rescore drain, both purges, rate limit) runs with SUPABASE_DB_URL UNSET", async () => {
  await withLegacyUrl(null, () => wholeSystemPath("unset"));
});

edgeTest("PR3: ...and with SUPABASE_DB_URL pointing at an unusable host (nothing may read it: a read would fail here)", async () => {
  await withLegacyUrl(UNUSABLE_LEGACY_URL, () => wholeSystemPath("invalid"));
});

edgeTest("PR3: with the EDGE URL missing every database call fails closed (one connection string is required, not zero)", async () => {
  const before = Deno.env.get("GOLFRAVEN_EDGE_DB_URL");
  await resetPrivilegedConnectionsForTests();
  Deno.env.delete("GOLFRAVEN_EDGE_DB_URL");
  try {
    await assertRejects(() => withSystemCatalogImport((repo) => repo.catalog.currentVersion()), Error, "GOLFRAVEN_EDGE_DB_URL");
  } finally {
    if (before !== undefined) Deno.env.set("GOLFRAVEN_EDGE_DB_URL", before);
    await resetPrivilegedConnectionsForTests();
  }
});

// ============================================================================
// B. delegated transactions
// ============================================================================

edgeTest("PR3: a delegate binds ONLY the owner of the evidence row it names; an UNSCOPED query inside it sees 0 foreign rows (and the raw submission, which the system list omits)", async () => {
  const a = await newPlainUser("del-a");
  const b = await newPlainUser("del-b");
  const ea = await seedQueued(a.uid);
  const eb = await seedQueued(b.uid);

  const seen = await openScopedTx("delegate", delegateBind({ kind: "queued_evidence", evidenceId: ea.evidenceId }, a.uid), async (trx) => ({
    actor: (await trx`select private.actor_uid()::text as a`)[0]!.a as string,
    role: (await trx`select current_user::text as u`)[0]!.u as string,
    // NO `where user_id = ...` anywhere: what a Repo method that forgot its ownership filter would run
    evidence: Number((await trx`select count(*)::int as n from app.evidence`)[0]!.n),
    devices: Number((await trx`select count(*)::int as n from app.device`)[0]!.n),
    foreign: Number((await trx`select count(*)::int as n from app.evidence where user_id = ${b.uid}`)[0]!.n),
    foreignById: Number((await trx`select count(*)::int as n from app.evidence where id = ${eb.evidenceId}`)[0]!.n),
    foreignDevice: Number((await trx`select count(*)::int as n from app.device where id = ${eb.deviceId}`)[0]!.n),
    ownInput: (await trx`select queued_input from app.evidence where id = ${ea.evidenceId}`)[0]?.queued_input as { deviceId?: string } | undefined,
    foreignInput: (await trx`select queued_input from app.evidence where id = ${eb.evidenceId}`).length,
  }));
  assertEquals(seen.actor, a.uid, "the delegate bound the row's owner");
  assertEquals(seen.role, "edge_actor", "and the work runs as edge_actor, not edge_system");
  assertEquals(seen.evidence, 1, "an unscoped count sees exactly the owner's one evidence row, out of every row in the table");
  assertEquals(seen.devices, 1);
  assertEquals(seen.foreign, 0, "0 foreign rows");
  assertEquals(seen.foreignById, 0, "...not even by primary key");
  assertEquals(seen.foreignDevice, 0);
  assertEquals(seen.ownInput?.deviceId, ea.deviceId, "the owner's raw submission is readable inside the owner's transaction");
  assertEquals(seen.foreignInput, 0, "another user's raw submission is not");

  // the Repo method the drain uses reads it too, and only as the owner
  const viaRepo = await withDelegatedActor({ kind: "queued_evidence", evidenceId: ea.evidenceId }, a, (repo) => repo.evidence.readQueuedInput(ea.evidenceId));
  assertEquals((viaRepo?.queuedInput as { deviceId?: string }).deviceId, ea.deviceId);
  const crossRead = await withDelegatedActor({ kind: "queued_evidence", evidenceId: ea.evidenceId }, a, (repo) => repo.evidence.readQueuedInput(eb.evidenceId));
  assertEquals(crossRead, null, "A's delegated transaction cannot read B's queued_input by id");
});

edgeTest("PR3: a delegate-bound transaction is a SYSTEM DELEGATE, not a user: it cannot export the account (the user-bound control can)", async () => {
  const a = await newPlainUser("kind-a");
  const ea = await seedQueued(a.uid);
  const ref: DelegateRef = { kind: "queued_evidence", evidenceId: ea.evidenceId };
  const err = (await assertRejects(() => openScopedTx("delegate", delegateBind(ref, a.uid), (trx) => trx`select private.export_my_data_for_actor()`))) as { code?: string; message: string };
  assertEquals(err.code, "42501");
  assert(err.message.includes("a system delegate may not export an account"), err.message);
  // the same call in a user-bound transaction works (so the refusal above is about the binding kind, nothing else)
  const exported = await openScopedTx("actor", userBind(a.uid), async (trx) => (await trx`select private.export_my_data_for_actor() as j`)[0]!.j);
  assertNotEquals(exported, null);
  // and through the Repo: a delegated transaction cannot export either
  await assertRejects(() => withDelegatedActor(ref, a, (repo) => repo.me.exportMyData()), Error, "a system delegate may not export an account");
});

edgeTest("PR3: a delegate for evidence that is NOT queued_catalog (resolved, terminal, or nonexistent) is refused before any work runs", async () => {
  const a = await newPlainUser("pre-a");
  const ea = await seedQueued(a.uid);
  await ensureServiceRole();
  await adminSql()`update app.evidence set status = 'needs_attention' where id = ${ea.evidenceId}`;
  let ran = false;
  for (const evidenceId of [ea.evidenceId, freshUuid()]) {
    const err = (await assertRejects(() => withDelegatedActor({ kind: "queued_evidence", evidenceId }, a, async () => { ran = true; return 1; }))) as { code?: string; message: string };
    assertEquals(err.code, "P0002");
    assert(err.message.includes("no queued_catalog evidence row"), err.message);
  }
  assertEquals(ran, false, "the operation never ran");
});

edgeTest("PR3: a delegate cannot be used to act as someone ELSE: naming A's row but expecting B fails closed, before the operation runs", async () => {
  const a = await newPlainUser("who-a");
  const b = await newPlainUser("who-b");
  const ea = await seedQueued(a.uid);
  let ran = false;
  const err = (await assertRejects(() => withDelegatedActor({ kind: "queued_evidence", evidenceId: ea.evidenceId }, b, async () => { ran = true; return 1; }))) as Error;
  assert(err.message.includes(`the bound actor is '${a.uid}', expected '${b.uid}'`), err.message);
  assertEquals(ran, false);
});

async function rescoreWorld(label: string) {
  await closeStaleBacklog();
  const i = ids();
  const k2 = i.mk("crs", "0000K2");
  const pub = await newPublisher();
  const v1 = await freshSiteVersion("20260901");
  await pub.publish(v1, {
    "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "verified", transitions: mint(v1) }, [k2]: { id: k2, status: "verified", transitions: mint(v1) } } },
    "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "PR3 K", holes: 18 }, { id: k2, name: "PR3 K2", holes: 18 }]),
  });
  const a = await newUser(`${label}-a`);
  const b = await newUser(`${label}-b`);
  const play = (actor: Actor, courseId: string) =>
    withOwnership(actor, (repo) =>
      repo.play.upsertFromScore({ courseId, facilityId: i.fac, playDate: todayChicago(), courseDisambiguatedBy: null, scoreBadge: 0, scoreMonetary: 0, hardSignal: false, presenceSignal: false, money: false, heldReview: false, policyVersion: "1", inputDigest: "d".repeat(64), evidenceIds: [] }),
    );
  const playA = (await play(a, i.k)).id;
  const playB = (await play(b, i.k)).id;
  const playAOther = (await play(a, k2)).id;
  await ensureServiceRole();
  const backlog = await adminSql()`insert into app.catalog_rescore_backlog (course_id, reason, catalog_version) values (${i.k}, 'promotion', (select max(version) from app.catalog_version)) returning id`;
  return { i, k2, a, b, playA, playB, playAOther, backlogId: Number(backlog[0]!.id) };
}

edgeTest("PR3: a rescore delegate binds the PLAY's owner only, and only while the backlog row is open and the play is at its course; an unscoped query sees 0 foreign plays", async () => {
  const w = await rescoreWorld("resc");
  // valid: A's play at the backlog row's course
  const seen = await probeDelegate({ kind: "rescore", backlogId: w.backlogId, playId: w.playA }, w.a.uid);
  assertEquals(seen.actor, w.a.uid);
  assertEquals(seen.role, "edge_actor");
  assertEquals(seen.plays, 2, "A's two plays (at K and at K2), not B's, whatever the table holds");
  const total = Number((await adminSql()`select count(*)::int as n from app.play`)[0]!.n);
  assert(total > seen.plays, "control: the table holds other users' plays (B's among them)");
  // B's play binds B
  const seenB = await probeDelegate({ kind: "rescore", backlogId: w.backlogId, playId: w.playB }, w.b.uid);
  assertEquals(seenB.actor, w.b.uid);
  assertEquals(seenB.plays, 1);

  // naming B's play while expecting A: refused, nothing runs
  let ran = false;
  const wrong = (await assertRejects(() => withDelegatedActor({ kind: "rescore", backlogId: w.backlogId, playId: w.playB }, w.a, async () => { ran = true; return 1; }))) as Error;
  assert(wrong.message.includes(`the bound actor is '${w.b.uid}', expected '${w.a.uid}'`), wrong.message);

  // a play at ANOTHER course than the backlog row's: refused by the database
  const otherCourse = (await assertRejects(() => withDelegatedActor({ kind: "rescore", backlogId: w.backlogId, playId: w.playAOther }, w.a, async () => { ran = true; return 1; }))) as { code?: string; message: string };
  assertEquals(otherCourse.code, "P0002");
  assert(otherCourse.message.includes("not at the backlog row's course"), otherCourse.message);

  // a CLOSED backlog row: refused
  await ensureServiceRole();
  await adminSql()`update app.catalog_rescore_backlog set done_at = now() where id = ${w.backlogId}`;
  const closed = (await assertRejects(() => withDelegatedActor({ kind: "rescore", backlogId: w.backlogId, playId: w.playA }, w.a, async () => { ran = true; return 1; }))) as { code?: string; message: string };
  assertEquals(closed.code, "P0002");
  assert(closed.message.includes("no open rescore backlog row"), closed.message);
  // a nonexistent backlog row: refused
  await assertRejects(() => withDelegatedActor({ kind: "rescore", backlogId: 2147483000, playId: w.playA }, w.a, async () => { ran = true; return 1; }), Error, "no open rescore backlog row");
  assertEquals(ran, false, "no refused delegate ever ran its operation");
});

edgeTest("PR3: the REAL queued drain opens every per-row transaction with the delegate for THAT evidence row and its OWNER; a probe of each identical transaction sees only that owner's rows", async () => {
  const a = await newPlainUser("dq-a");
  const b = await newPlainUser("dq-b");
  const currentVersion = (await adminSql()`select site_version from app.catalog_version order by site_version desc nulls last, version desc limit 1`)[0]!.site_version as string;
  const ea = await seedQueued(a.uid, { facilityId: FAC_Y, courseId: CRS_Y1, claimedVersion: currentVersion });
  const eb = await seedQueued(b.uid, { facilityId: FAC_Y, courseId: CRS_Y1, claimedVersion: currentVersion });
  const owner = new Map([[ea.evidenceId, a.uid], [eb.evidenceId, b.uid]]);

  const calls: Array<{ delegate: DelegateRef; uid: string }> = [];
  const probes: Array<{ evidenceId: string; seen: Awaited<ReturnType<typeof probeDelegate>> }> = [];
  const probing: WithDelegatedActorFn = async (delegate, actor, op) => {
    calls.push({ delegate, uid: actor.uid });
    if (delegate.kind === "queued_evidence" && owner.has(delegate.evidenceId)) {
      probes.push({ evidenceId: delegate.evidenceId, seen: await probeDelegate(delegate, actor.uid) });
      await assertIsDelegateKind(delegate, actor);
    }
    return withDelegatedActor(delegate, actor, op);
  };
  const drainRepo = makeDrainReadRepo(withSystemCatalogImport);
  const result = await drainQueuedCatalog(drainRepo, probing, 500);
  assert(result.resolved >= 2, `both rows resolved: ${JSON.stringify(result)}`);

  for (const [evidenceId, uid] of owner) {
    const call = calls.find((c) => c.delegate.kind === "queued_evidence" && c.delegate.evidenceId === evidenceId);
    assert(call, `the drain opened a delegated transaction for ${evidenceId}`);
    assertEquals(call!.uid, uid, "...expecting the row's own owner");
  }
  assertEquals(probes.length, 2);
  for (const p of probes) {
    assertEquals(p.seen.actor, owner.get(p.evidenceId), "the delegate bound the row's owner");
    assertEquals(p.seen.role, "edge_actor");
    assertEquals(p.seen.evidence, 1, "an unscoped read inside the drain's transaction sees only the owner's one evidence row");
    assertEquals(p.seen.devices, 1);
  }
  assertEquals((await adminSql()`select status from app.evidence where id = ${ea.evidenceId}`)[0]!.status, "accepted");
  assertEquals((await adminSql()`select status from app.evidence where id = ${eb.evidenceId}`)[0]!.status, "accepted");
});

edgeTest("PR3: the REAL rescore drain opens every per-play transaction with the delegate for THAT backlog row and play, and the PLAY's owner", async () => {
  const w = await rescoreWorld("drs");
  const calls: Array<{ delegate: DelegateRef; uid: string }> = [];
  const probes: Array<{ uid: string; seen: Awaited<ReturnType<typeof probeDelegate>> }> = [];
  const probing: WithDelegatedActorFn = async (delegate, actor, op) => {
    calls.push({ delegate, uid: actor.uid });
    probes.push({ uid: actor.uid, seen: await probeDelegate(delegate, actor.uid) });
    await assertIsDelegateKind(delegate, actor);
    return withDelegatedActor(delegate, actor, op);
  };
  const drainRepo = makeDrainReadRepo(withSystemCatalogImport);
  let completed = 0;
  for (let pass = 0; pass < 8 && completed === 0; pass++) completed += (await drainRescoreBacklog(drainRepo, probing, 50, undefined, NO_GRACE)).coursesCompleted;
  assertEquals(completed, 1);
  const expected = new Map([[w.playA, w.a.uid], [w.playB, w.b.uid]]);
  const named = new Set<string>();
  for (const c of calls) {
    assertEquals(c.delegate.kind, "rescore");
    if (c.delegate.kind !== "rescore") continue;
    assertEquals(c.delegate.backlogId, w.backlogId);
    assertEquals(c.uid, expected.get(c.delegate.playId), "the expected actor is the play's owner");
    named.add(c.delegate.playId);
  }
  assert(named.has(w.playA) && named.has(w.playB), "both plays at the course were visited");
  assert(!named.has(w.playAOther), "a play at another course was never visited");
  for (const p of probes) {
    assertEquals(p.seen.actor, p.uid);
    assertEquals(p.seen.role, "edge_actor");
    assert(p.seen.plays <= 2, `an unscoped read sees only the owner's own plays, got ${p.seen.plays}`);
  }
});

// ============================================================================
// C. the purges run as edge_system
// ============================================================================

async function seedAgedFixCoords(): Promise<{ evidenceId: string }> {
  const i = ids();
  const pub = await newPublisher();
  const v1 = await freshSiteVersion("20260901");
  await pub.publish(v1, {
    "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "stub", transitions: mint(v1) } } },
    "facilities/us.json": facilityShard(i, "unverified", [{ id: i.k, name: "PR3 purge K", holes: 18 }]),
  });
  await giveCoursePolygon(i.k);
  const user = await newUser("purge");
  await seedDwellAndScore(user, i.fac, i.k, "unverified", { withCoords: true });
  await ensureServiceRole();
  const ev = await adminSql()`select id from app.evidence where user_id = ${user.uid} and integrity ? 'fixCoords' limit 1`;
  const evidenceId = ev[0]!.id as string;
  await adminSql()`update app.evidence set created_at = now() - interval '31 days' where id = ${evidenceId}`;
  return { evidenceId };
}

async function seedExpiredTombstone(): Promise<string> {
  await ensureServiceRole();
  const user = await newPlainUser("tomb");
  const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(freshUuid())))].map((x) => x.toString(16).padStart(2, "0")).join("");
  await adminSql()`
    insert into app.install_link_account (install_link_hash, account_pseudonym, account_pseudonym_hmac_id, first_seen_at)
    select ${hash}, a.pseudonym, a.key_id, now() - interval '25 months' from private.account_pseudonyms(${user.uid}::uuid) a where a.preferred`;
  return hash;
}

edgeTest("PR3: the fix-coordinate purge and the install-link tombstone purge run through the edge_system definers (they work; and with EXECUTE revoked from edge_system they stop)", async () => {
  const { evidenceId } = await seedAgedFixCoords();
  const tomb = await seedExpiredTombstone();
  const coordsOf = async () => (await adminSql()`select integrity ? 'fixCoords' as has from app.evidence where id = ${evidenceId}`)[0]!.has as boolean;
  assertEquals(await coordsOf(), true, "control: the aged row carries raw fix coordinates");

  if (await isSuperuserHarness()) {
    // The sharp proof that the purge is edge_system's: take the definer's EXECUTE away from edge_system and the purge cannot run in edge mode.
    const raw = rawHarness();
    try {
      await raw.unsafe("revoke execute on function private.purge_fix_coords(int, int) from edge_system");
      await raw.unsafe("revoke execute on function private.purge_install_link_tombstones(int) from edge_system");
      try {
        await assertRejects(() => withSystemCatalogImport((repo) => repo.rescoreBacklog.purgeFixCoords(30, 5000)), Error, "permission denied for function purge_fix_coords");
        await assertRejects(() => withSystemCatalogImport((repo) => repo.rescoreBacklog.purgeInstallLinkTombstones(5000)), Error, "permission denied for function purge_install_link_tombstones");
        assertEquals(await coordsOf(), true, "nothing was purged while edge_system lacked EXECUTE");
      } finally {
        await raw.unsafe("grant execute on function private.purge_fix_coords(int, int) to edge_system");
        await raw.unsafe("grant execute on function private.purge_install_link_tombstones(int) to edge_system");
      }
    } finally {
      await raw.end({ timeout: 1 });
    }
  } else {
    console.log("PR3 purge EXECUTE-revoke cells: skipped (the harness role is not a superuser; HARNESS_MODE=superuser runs them)");
  }

  const nCoords = await withSystemCatalogImport((repo) => repo.rescoreBacklog.purgeFixCoords(30, 5000));
  assert(nCoords >= 1, `the fix-coordinate purge removed the aged row's coordinates (${nCoords})`);
  assertEquals(await coordsOf(), false);
  const nTombs = await withSystemCatalogImport((repo) => repo.rescoreBacklog.purgeInstallLinkTombstones(5000));
  assert(nTombs >= 1, `the tombstone purge removed the expired row (${nTombs})`);
  assertEquals(await rawCount(`select count(*)::int as n from app.install_link_account where install_link_hash = '${tomb}'`), 0);
});

edgeTest("PR3: the retention bounds are the database's: a fix-coordinate purge asking for 90 days, or for 0, is refused (22023), not obeyed", async () => {
  for (const days of [0, 6, 31, 90]) {
    const err = (await assertRejects(() => withSystemCatalogImport((repo) => repo.rescoreBacklog.purgeFixCoords(days, 100)))) as { code?: string };
    assertEquals(err.code, "22023", `retention ${days}`);
  }
});

// ============================================================================
// D. PR3 gate P1 (edge role PR4b): concurrent drains do not double-process a queued row
// ============================================================================
// `Repo#evidence.readQueuedInput` is the first statement of the drain's per-row transaction and takes `for update skip locked` on the evidence
// row. These cells are TWO real sessions (two pooled connections of the real privileged.ts): session A holds the row's transaction open; session B,
// a second drain, must skip the row instead of re-deriving it.

/** Opens session A: a delegated transaction that reads (and so locks) the queued row, then waits for `release()` before it commits. */
async function holdQueuedRow(ref: DelegateRef & { kind: "queued_evidence" }, actor: Actor) {
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let locked!: () => void;
  const lockedSignal = new Promise<void>((r) => (locked = r));
  const done = withDelegatedActor(ref, actor, async (repo) => {
    const first = await repo.evidence.readQueuedInput(ref.evidenceId);
    locked();
    await gate;
    return first;
  });
  // a failure of A must surface, not hang the test
  const settled = done.then((v) => v, (e) => { locked(); throw e; });
  await lockedSignal;
  return { release, done: settled };
}

edgeTest("PR4b P1: while one drain holds a queued row, a second drain's re-read gets NO row (skip locked), immediately; once the first commits the row is readable again", async () => {
  const a = await newPlainUser("lock-a");
  const ea = await seedQueued(a.uid);
  const ref = { kind: "queued_evidence", evidenceId: ea.evidenceId } as const;
  const held = await holdQueuedRow(ref, a);
  try {
    // control: the row IS still queued while A holds it, so the empty answer below is the lock's doing, not a state change
    const status = (await adminSql()`select status from app.evidence where id = ${ea.evidenceId}`)[0]!.status;
    assertEquals(status, "queued_catalog", "control: the row is still queued while A holds it");
    const t0 = Date.now();
    const b = await withDelegatedActor(ref, a, (repo) => repo.evidence.readQueuedInput(ea.evidenceId));
    const ms = Date.now() - t0;
    assertEquals(b, null, "B skipped the row A holds");
    assert(ms < 3000, `B did not wait for A (took ${ms} ms; the lock timeout is 5 s)`);
  } finally {
    held.release();
  }
  const first = await held.done;
  assertEquals((first?.queuedInput as { deviceId?: string }).deviceId, ea.deviceId, "A read the row");
  const after = await withDelegatedActor(ref, a, (repo) => repo.evidence.readQueuedInput(ea.evidenceId));
  assertEquals((after?.queuedInput as { deviceId?: string }).deviceId, ea.deviceId, "the lock ended with A's transaction: the row is readable again");
});

edgeTest("PR4b P1: a second REAL drain over a row another drain holds does not re-derive it (no resolve attempt, no error), and picks it up once the first is done", async () => {
  await closeStaleBacklog();
  const queuedUser = await newPlainUser("lock-drain");
  const currentVersion = (await adminSql()`select site_version from app.catalog_version order by site_version desc nulls last, version desc limit 1`)[0]!.site_version as string;
  const q = await seedQueued(queuedUser.uid, { facilityId: FAC_Y, courseId: CRS_Y1, claimedVersion: currentVersion });
  const ref = { kind: "queued_evidence", evidenceId: q.evidenceId } as const;
  const drainRepo = makeDrainReadRepo(withSystemCatalogImport);

  // a spy over withDelegatedActor that records what the drain does with THIS row
  const reads: unknown[] = [];
  let resolveAttempts = 0;
  const spy: WithDelegatedActorFn = (delegate, actor, op) =>
    withDelegatedActor(delegate, actor, (repo) => {
      if (delegate.kind === "queued_evidence" && delegate.evidenceId === q.evidenceId) {
        const realRead = repo.evidence.readQueuedInput.bind(repo.evidence);
        repo.evidence.readQueuedInput = async (id) => {
          const r = await realRead(id);
          reads.push(r);
          return r;
        };
        const realResolve = repo.evidence.resolveQueuedRow.bind(repo.evidence);
        repo.evidence.resolveQueuedRow = (...args) => {
          resolveAttempts += 1;
          return realResolve(...args);
        };
      }
      return op(repo);
    });

  const held = await holdQueuedRow(ref, queuedUser);
  let during;
  try {
    during = await drainQueuedCatalog(drainRepo, spy, 200);
  } finally {
    held.release();
  }
  await held.done;
  assertEquals(reads, [null], "the second drain's re-read of the held row returned no row");
  assertEquals(resolveAttempts, 0, "the second drain did not re-derive (resolve) the row A holds");
  assertEquals(during.errored, 0, `no row errored (a blocked second drain would have hit the 5 s lock timeout): ${JSON.stringify(during)}`);
  assertEquals((await adminSql()`select status from app.evidence where id = ${q.evidenceId}`)[0]!.status, "queued_catalog", "nothing was resolved while A held the row");

  // A is done: the next drain pass resolves the row, exactly once
  reads.length = 0;
  resolveAttempts = 0;
  const later = await drainQueuedCatalog(drainRepo, spy, 200);
  assert(later.resolved >= 1, `the row is drained once the first session is done: ${JSON.stringify(later)}`);
  assertEquals(reads.length, 1);
  assertEquals(resolveAttempts, 1);
  assertEquals((await adminSql()`select status from app.evidence where id = ${q.evidenceId}`)[0]!.status, "accepted");
});
