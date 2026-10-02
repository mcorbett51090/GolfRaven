// supabase/tests/integration/catalog-minimisation.deno.test.ts
//
// P3e round 3 gate, against REAL Postgres through the REAL handlers/importer:
//   HIGH   (§8.6 minimisation): raw fix coordinates (`integrity.fixCoords`) are
//          stored ONLY while a re-pick can happen, and cleared by each trigger
//          (re-pick used — covered in catalog-promotion.deno.test.ts; the
//          backlog row done; the fixed retention window); the export reflects it.
//   MEDIUM (A2-01 / §4.2): a blocked split label never leaves a split-ambiguous
//          play uncapped; `uniqueCourses` counts a facility-date's split plays once.
//   LOW    (keyset): a straggler (a long transaction that commits after the
//          cursor passed its timestamp) is picked up by the closing sweep.
import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { withDelegatedActor, withOwnership, withSystemCatalogImport } from "../../functions/_shared/privileged.ts";
import { drainRescoreBacklog } from "../../functions/_shared/catalog/rescore-orchestrator.ts";
import { makeDrainReadRepo } from "../../functions/_shared/catalog/drain-read-repo.ts";
import { handleEvidenceIntake } from "../../functions/_shared/evidence/handler.ts";
import { handleMeExport } from "../../functions/_shared/me/export-handler.ts";
import { adminSql, ensureServiceRole, freshUuid, rawCount } from "./_helpers.ts";
import { closeStaleBacklog, facilityShard, freshSiteVersion, giveCoursePolygon, ids, mint, newPublisher, newUser, playScore, seedDwellAndScore, seedDwellInRepo, todayChicago, uniqueCourses, type Actor } from "./_publisher.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
const drainRepo = makeDrainReadRepo(withSystemCatalogImport);
const NO_GRACE = { sweepDelaySeconds: 0 };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function currentSiteVersion(): Promise<string> {
  await ensureServiceRole();
  const rows = await adminSql()`select site_version from app.catalog_version where site_version is not null order by site_version desc, version desc limit 1`;
  return rows[0]!.site_version as string;
}

/** A real LIVE check-in through the handler (the path that decides whether to store coordinates). */
async function liveCheckin(actor: Actor, facilityId: string, courseId: string | undefined) {
  const catalogVersion = await currentSiteVersion();
  const r = await withOwnership(actor, (repo) =>
    handleEvidenceIntake(
      { source: "foreground_checkin", deviceId: freshUuid(), facilityId, ...(courseId ? { courseId } : {}), localDate: todayChicago(), catalogVersion, fix: { fixId: `fix_${freshUuid().slice(0, 12)}`, lat: 36.1467, lng: -86.7816, accuracyMeters: 10, capturedAt: Date.now(), simulated: false, foreground: true, fromApp: true } },
      repo,
    ),
  );
  assertEquals(r.status, "accepted");
  return (r as { evidenceId: string }).evidenceId;
}

const coordsOf = async (evidenceId: string) => {
  await ensureServiceRole();
  const rows = await adminSql()`select integrity from app.evidence where id = ${evidenceId}`;
  return (rows[0]!.integrity as Record<string, unknown>).fixCoords ?? null;
};

Deno.test("§8.6: a VERIFIED course stores no coordinates, a STUB course stores them, a row with no course never does — and the export reflects it", DT, async () => {
  const i = ids();
  const pub = await newPublisher();
  const v1 = await freshSiteVersion("20260901");
  const verifiedCourse = i.mk("crs", "0000VV");
  await pub.publish(v1, {
    "id-ledger.json": { entries: {
      [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) },
      [i.k]: { id: i.k, status: "stub", transitions: mint(v1) },
      [verifiedCourse]: { id: verifiedCourse, status: "verified", transitions: mint(v1) },
    } },
    "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "Stub K", holes: 18 }, { id: verifiedCourse, name: "Verified V", holes: 18 }]),
  });
  const user = await newUser("store");
  const stubEv = await liveCheckin(user, i.fac, i.k);
  const verifiedEv = await liveCheckin(user, i.fac, verifiedCourse);
  const noCourseEv = await liveCheckin(user, i.fac, undefined);

  assertEquals(await coordsOf(verifiedEv), null, "a verified, never-split course stores NO raw coordinates");
  assertEquals(await coordsOf(noCourseEv), null, "a row with no course never stores coordinates");
  const stored = (await coordsOf(stubEv)) as Record<string, { lat: number; lng: number }>;
  assert(stored !== null, "a stub course stores them (only stubs split)");
  assertEquals(Object.values(stored)[0], { lat: 36.1467, lng: -86.7816 });

  // The export is the owner's own rows: it carries coordinates for the stub row only.
  const exp = await withOwnership(user, (repo) => handleMeExport(repo, user.uid));
  const rows = exp.data.evidence as Array<{ id: string; integrity: Record<string, unknown> }>;
  assertEquals(rows.find((r) => r.id === verifiedEv)!.integrity.fixCoords, undefined, "export: verified-course row has no coordinates");
  assertEquals(rows.find((r) => r.id === noCourseEv)!.integrity.fixCoords, undefined);
  assert(rows.find((r) => r.id === stubEv)!.integrity.fixCoords !== undefined, "export: the stub row still carries them (until a trigger clears them)");
});

Deno.test("§8.6 trigger (b): coordinates are kept while the course's rescore backlog row is OPEN and cleared once it is DONE (the course is then neither a stub nor in a split family)", DT, async () => {
  await closeStaleBacklog();
  const i = ids();
  const pub = await newPublisher();
  const v1 = await freshSiteVersion("20260901");
  const v2 = await freshSiteVersion("20260925");
  await pub.publish(v1, {
    "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "stub", transitions: mint(v1) } } },
    "facilities/us.json": facilityShard(i, "unverified", [{ id: i.k, name: "Promo K", holes: 18 }]),
  });
  await giveCoursePolygon(i.k);
  const users = [await newUser("b1"), await newUser("b2"), await newUser("b3")];
  const evs: string[] = [];
  for (const u of users) evs.push(await liveCheckin(u, i.fac, i.k));
  for (const e of evs) assert((await coordsOf(e)) !== null, "stub course: coordinates stored at intake");

  await pub.publish(v2, {
    "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "verified", transitions: [...mint(v1), { type: "verified", catalogVersion: v2 }] } } },
    "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "Promo K", holes: 18 }]),
  });
  // K is promoted (no longer a stub) but its backlog row is OPEN: coordinates stay.
  const open = await drainRescoreBacklog(drainRepo, withDelegatedActor, 1);
  assertEquals(open.coursesCompleted, 0);
  for (const e of evs) assert((await coordsOf(e)) !== null, "backlog row still open -> coordinates retained");

  // Work the backlog to completion (no straggler grace in the test).
  let completed = 0;
  let purged = 0;
  for (let pass = 0; pass < 10 && completed === 0; pass++) {
    const r = await drainRescoreBacklog(drainRepo, withDelegatedActor, 50, undefined, NO_GRACE);
    completed += r.coursesCompleted;
    purged += r.coordsPurged;
  }
  assertEquals(completed, 1);
  // The pass that closed the row purged in the same run (the purge runs after the loop).
  for (const e of evs) assertEquals(await coordsOf(e), null, "backlog done, course promoted -> coordinates cleared");
  assert(purged >= 3, `the purge reported what it cleared (${purged})`);

  // ...and the export reflects that.
  const exp = await withOwnership(users[0]!, (repo) => handleMeExport(repo, users[0]!.uid));
  const rows = exp.data.evidence as Array<{ id: string; integrity: Record<string, unknown> }>;
  assertEquals(rows.find((r) => r.id === evs[0])!.integrity.fixCoords, undefined);
});

Deno.test("§8.6 trigger (c): after the fixed retention window the coordinates go even while the course is still a stub; a newer row keeps them", DT, async () => {
  await closeStaleBacklog();
  const i = ids();
  const pub = await newPublisher();
  const v1 = await freshSiteVersion("20260901");
  await pub.publish(v1, {
    "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "stub", transitions: mint(v1) } } },
    "facilities/us.json": facilityShard(i, "unverified", [{ id: i.k, name: "Stub K", holes: 18 }]),
  });
  const old = await newUser("w-old");
  const fresh = await newUser("w-new");
  const oldEv = await liveCheckin(old, i.fac, i.k);
  const freshEv = await liveCheckin(fresh, i.fac, i.k);
  await ensureServiceRole();
  await adminSql()`update app.evidence set created_at = now() - interval '29 days' where id = ${oldEv}`;
  const inside = await drainRescoreBacklog(drainRepo, withDelegatedActor, 50, undefined, NO_GRACE);
  assert((await coordsOf(oldEv)) !== null, `29 days: still inside the window (${JSON.stringify(inside)})`);
  await adminSql()`update app.evidence set created_at = now() - interval '31 days' where id = ${oldEv}`;
  const after = await drainRescoreBacklog(drainRepo, withDelegatedActor, 50, undefined, NO_GRACE);
  assert(after.coordsPurged >= 1);
  assertEquals(await coordsOf(oldEv), null, "31 days: past the retention window -> cleared");
  assert((await coordsOf(freshEv)) !== null, "a row inside the window keeps its coordinates (the course is still a stub)");

  // A row without coordinates fails closed at re-pick (cannot_rederive), never a silent re-derive from nothing.
  assertEquals(await rawCount(`select count(*)::int as n from app.evidence where id = '${oldEv}' and integrity ? 'fixCoords'`), 0);
});

Deno.test("A2-01 / §4.2 (MEDIUM): two courses of one facility both split — the second split play's label is blocked, yet BOTH are capped (score_monetary 0, money false) and uniqueCourses counts the facility-date once", DT, async () => {
  await closeStaleBacklog();
  const i = ids();
  const pub = await newPublisher();
  const k2 = i.mk("crs", "00000Q");
  const s2 = i.mk("crs", "00000R");
  const v1 = await freshSiteVersion("20260901");
  const v2 = await freshSiteVersion("20260925");
  const ledger1 = {
    [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) },
    [i.k]: { id: i.k, status: "verified", transitions: mint(v1) },
    [k2]: { id: k2, status: "verified", transitions: mint(v1) },
  };
  await pub.publish(v1, { "id-ledger.json": { entries: ledger1 }, "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "K", holes: 18 }, { id: k2, name: "K2", holes: 18 }]) });
  await giveCoursePolygon(i.k);
  await giveCoursePolygon(k2);

  const actor = await newUser("probe");
  // One user, one date, two plays at one facility via different courseIds — each money-true.
  const a = await seedDwellAndScore(actor, i.fac, i.k, "play-verified", { vendor: true, withCoords: false });
  const b = await seedDwellAndScore(actor, i.fac, k2, "play-verified", { vendor: true, withCoords: false });
  assertEquals([a.play.money, b.play.money], [true, true]);
  assertEquals(await uniqueCourses(actor), 2, "before any split the two courses are two courses");

  // v2: BOTH courses split.
  await pub.publish(v2, {
    "id-ledger.json": { entries: {
      ...ledger1,
      [i.k]: { id: i.k, status: "verified", transitions: [...mint(v1), { type: "split", catalogVersion: v2, siblingIds: [i.s] }] },
      [k2]: { id: k2, status: "verified", transitions: [...mint(v1), { type: "split", catalogVersion: v2, siblingIds: [s2] }] },
      [i.s]: { id: i.s, status: "verified", transitions: mint(v2) },
      [s2]: { id: s2, status: "verified", transitions: mint(v2) },
    } },
    "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "K", holes: 9 }, { id: i.s, name: "S", holes: 9 }, { id: k2, name: "K2", holes: 9 }, { id: s2, name: "S2", holes: 9 }]),
  });
  await drainRescoreBacklog(drainRepo, withDelegatedActor, 50, undefined, NO_GRACE);

  const pa = (await playScore(actor.uid, i.k))!;
  const pb = (await playScore(actor.uid, k2))!;
  const labels = [pa.pick, pb.pick].sort();
  assertEquals(labels, [null, "user"], "exactly ONE label could be written (the one-user-pick-per-facility-date index), the other was blocked");
  for (const p of [pa, pb]) {
    assertEquals(p.monetary, 0, "a split play contributes 0 to score_monetary whether or not its label could be stored");
    assertEquals(p.money, false);
  }
  assertEquals(await uniqueCourses(actor), 1, "the facility-date's split plays count ONCE");
});

Deno.test("keyset straggler (LOW): a play whose transaction STARTED before the cursor's timestamp but commits after the drain passed it is picked up by the closing sweep (grace + rewound cursor)", DT, async () => {
  await closeStaleBacklog();
  const i = ids();
  const pub = await newPublisher();
  const v1 = await freshSiteVersion("20260901");
  const v2 = await freshSiteVersion("20260925");
  await pub.publish(v1, {
    "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "stub", transitions: mint(v1) } } },
    "facilities/us.json": facilityShard(i, "unverified", [{ id: i.k, name: "Promo K", holes: 18 }]),
  });
  await giveCoursePolygon(i.k);

  // The straggler: a transaction that starts NOW (so its created_at = now()), inserts its
  // play + evidence, and stays open while the rest of the scenario runs.
  const late = await newUser("straggler");
  const inserted = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const straggler = withOwnership(late, async (repo) => {
    await seedDwellInRepo(repo, i.fac, i.k, "unverified", { withCoords: false });
    inserted.resolve();
    await release.promise;
  });
  await inserted.promise;
  await sleep(50);

  // Two ordinary plays created AFTER the straggler's transaction started (later created_at).
  const early = [await newUser("s1"), await newUser("s2")];
  for (const u of early) await seedDwellAndScore(u, i.fac, i.k, "unverified", { withCoords: false });
  await pub.publish(v2, {
    "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "verified", transitions: [...mint(v1), { type: "verified", catalogVersion: v2 }] } } },
    "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "Promo K", holes: 18 }]),
  });

  // Drain with a 2 s grace: the (committed) plays are re-scored and the cursor passes the
  // straggler's timestamp; the row is NOT closed (it records finished_at and waits out the grace).
  const first = await drainRescoreBacklog(drainRepo, withDelegatedActor, 50, undefined, { sweepDelaySeconds: 2 });
  assertEquals(first.playsProcessed, 2);
  assertEquals(first.coursesCompleted, 0, "a short page does not close the course");
  assertEquals(await rawCount(`select count(*)::int as n from app.catalog_rescore_backlog where course_id = '${i.k}' and done_at is null and finished_at is not null`), 1);

  // The straggler commits only now.
  release.resolve();
  await straggler;
  assertEquals((await playScore(late.uid, i.k))!.status, "provisional", "committed, but never re-scored: it sits at the stub-era score");
  assertEquals(await uniqueCourses(late), 0);

  // After the grace, the sweep rewinds the cursor and reaches it.
  await sleep(2200);
  let completed = 0;
  for (let pass = 0; pass < 6 && completed === 0; pass++) completed += (await drainRescoreBacklog(drainRepo, withDelegatedActor, 50, undefined, { sweepDelaySeconds: 2 })).coursesCompleted;
  assertEquals(completed, 1);
  assertEquals((await playScore(late.uid, i.k))!.status, "confirmed", "the straggler was swept and re-scored at the promoted tier");
  assertEquals(await uniqueCourses(late), 1);
});
