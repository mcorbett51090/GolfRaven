// supabase/tests/integration/catalog-promotion.deno.test.ts
//
// P3e round 3, R2 (AT 18) and R3 (holes, rosters) against REAL Postgres,
// through the REAL import pipeline, the REAL bounded re-score drain and the
// REAL live scoring path (`finalizeScoringForKey`, `handleEvidenceIntake`):
//   - a play at a STUB course is accepted but counts toward nothing;
//   - after the ledger promotes the course (stub -> verified, same id),
//     the next drain pass re-scores the affected plays and `uniqueCourses`
//     rises by EXACTLY 1 — an idempotent replay of the import (or of the
//     drain) never doubles it;
//   - the re-score is bounded per pass (backlog + keyset cursor);
//   - a split counts the kept course once, as a `user` pick; a re-pick
//     MOVES the play (never double counts);
//   - the re-score is safe against a concurrent live submission;
//   - R3: holes, hole details and roster versions/members are persisted.
//
// The evidence rows are seeded through `Repo#evidence.insertIdempotent` with
// DERIVED fixes (`deriveFix`) exactly as live intake would have stored them
// (a dwell needs two live-token fixes ~2 h apart, which a unit-speed test
// cannot issue through real challenge/token TTLs), then scored by the SAME
// `finalizeScoringForKey` the live tail uses.
import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { withDelegatedActor, withOwnership, withSystemCatalogImport } from "../../functions/_shared/privileged.ts";
import { drainRescoreBacklog } from "../../functions/_shared/catalog/rescore-orchestrator.ts";
import { makeDrainReadRepo } from "../../functions/_shared/catalog/drain-read-repo.ts";
import { finalizeScoringForKey, handleEvidenceIntake, repickUserPlay } from "../../functions/_shared/evidence/handler.ts";
import { adminSql, createTestUser, ensureServiceRole, freshUuid, rawCount } from "./_helpers.ts";
import { closeStaleBacklog, facilityShard, freshSiteVersion, giveCoursePolygon, ids, mint, newPublisher, newUser, playScore, seedDwellAndScore, todayChicago, uniqueCourses } from "./_publisher.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
const drainRepo = makeDrainReadRepo(withSystemCatalogImport);
/** No straggler grace (tests only): the finish mark, the sweep start and the sweep itself happen within one run. */
const NO_GRACE = { sweepDelaySeconds: 0 };

Deno.test("AT 18: a play at a STUB is accepted but counts toward nothing; after promotion the bounded drain re-scores it and uniqueCourses rises by exactly 1 (replays never double)", DT, async () => {
  await closeStaleBacklog();
  const i = ids();
  const pub = await newPublisher();
  const v1 = await freshSiteVersion("20260901");
  const v2 = await freshSiteVersion("20260925");

  // v1: facility verified, COURSE a stub (its facility shard says "unverified").
  await pub.publish(v1, {
    "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "stub", transitions: mint(v1) } } },
    "facilities/us.json": facilityShard(i, "unverified", [{ id: i.k, name: "Promo K", holes: 18 }]),
  });
  await giveCoursePolygon(i.k);

  // Three players with a (stub-era) play each — user A is the one we watch closely.
  const users = [await newUser("a"), await newUser("b"), await newUser("c")];
  for (const u of users) {
    const scored = await seedDwellAndScore(u, i.fac, i.k, "unverified");
    assert(scored.play.scoreBadge < 0.5, `a stub-era dwell must score below the badge bar, got ${scored.play.scoreBadge}`);
  }
  for (const u of users) assertEquals(await uniqueCourses(u), 0, "a play at a stub counts toward nothing");
  assertEquals((await playScore(users[0]!.uid, i.k))!.status, "provisional");
  assertEquals(await rawCount(`select count(*)::int as n from app.evidence where user_id = '${users[0]!.uid}' and status = 'accepted'`), 1, "the stub play's evidence is ACCEPTED");

  // v2: the SAME course id is promoted (verified transition), facility play-verified.
  const o2 = await pub.publish(v2, {
    "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "verified", transitions: [...mint(v1), { type: "verified", catalogVersion: v2 }] } } },
    "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "Promo K", holes: 18 }]),
  });
  assertEquals(o2.promotedCourses, 1);
  assertEquals(await rawCount(`select count(*)::int as n from app.catalog_rescore_backlog where course_id = '${i.k}' and reason = 'promotion' and done_at is null`), 1);
  // The IMPORT only queued work: nothing was re-scored inside its transaction.
  for (const u of users) assertEquals(await uniqueCourses(u), 0);

  // Bounded pass: at most 2 plays, so the 3-play backlog is NOT finished.
  const pass1 = await drainRescoreBacklog(drainRepo, withDelegatedActor, 2);
  assertEquals(pass1.playsProcessed, 2);
  assertEquals(pass1.coursesCompleted, 0);
  assertEquals(await rawCount(`select count(*)::int as n from app.catalog_rescore_backlog where course_id = '${i.k}' and done_at is null`), 1, "the backlog row stays open with a cursor");
  // Later passes (no straggler grace in the test): the last play, then the
  // closing sweep (cursor rewound by the overlap), then the row closes.
  let completed = 0;
  for (let pass = 0; pass < 8 && completed === 0; pass++) completed += (await drainRescoreBacklog(drainRepo, withDelegatedActor, 2, undefined, NO_GRACE)).coursesCompleted;
  assertEquals(completed, 1, "the backlog row closes after its sweep");

  for (const u of users) {
    assertEquals(await uniqueCourses(u), 1, "uniqueCourses rose by EXACTLY 1");
    const p = (await playScore(u.uid, i.k))!;
    assert(p.badge >= 0.5, `promoted play must reach the badge bar, got ${p.badge}`);
    assertEquals(p.status, "confirmed");
  }

  // Idempotency: replaying the import is an early exit that re-queues nothing,
  // and re-draining does nothing.
  const replay = await pub.publish(v2, {
    "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "verified", transitions: [...mint(v1), { type: "verified", catalogVersion: v2 }] } } },
    "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "Promo K", holes: 18 }]),
  });
  assertEquals(replay.alreadyImported, true);
  assertEquals(await rawCount(`select count(*)::int as n from app.catalog_rescore_backlog where course_id = '${i.k}'`), 1);
  const idle = await drainRescoreBacklog(drainRepo, withDelegatedActor, 50);
  assertEquals(idle.playsProcessed, 0);
  for (const u of users) assertEquals(await uniqueCourses(u), 1, "an idempotent replay must not double the count");
});

Deno.test("AT 18 (split): the kept course counts once as a USER pick (score_monetary 0, money false); a re-pick MOVES the play, re-derived, exactly once, audited (never double counts)", DT, async () => {
  await closeStaleBacklog();
  const i = ids();
  const pub = await newPublisher();
  const v1 = await freshSiteVersion("20260901");
  const v2 = await freshSiteVersion("20260925");
  const ledger1 = { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "verified", transitions: mint(v1) } };
  await pub.publish(v1, { "id-ledger.json": { entries: ledger1 }, "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "Promo K", holes: 9 }]) });
  await giveCoursePolygon(i.k);

  const actor = await newUser("split");
  const scored = await seedDwellAndScore(actor, i.fac, i.k, "play-verified", { vendor: true, holes: 9 });
  assert(scored.play.scoreBadge >= 0.5);
  assertEquals(scored.play.money, true, "the fixture is money-true while it is NOT a user pick");
  assert(scored.play.scoreMonetary >= 0.85);
  assertEquals(await uniqueCourses(actor), 1);
  assertEquals((await playScore(actor.uid, i.k))!.pick, null);

  // v2: K splits; S is the new, verified sibling (an 18-hole course, no polygon yet).
  const o2 = await pub.publish(v2, {
    "id-ledger.json": { entries: {
      ...ledger1,
      [i.k]: { id: i.k, status: "verified", transitions: [...mint(v1), { type: "split", catalogVersion: v2, siblingIds: [i.s] }] },
      [i.s]: { id: i.s, status: "verified", transitions: mint(v2) },
    } },
    "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "Promo K", holes: 9 }, { id: i.s, name: "Promo S", holes: 18 }]),
  });
  assertEquals(o2.splitCourses, 1);
  assertEquals(await rawCount(`select count(*)::int as n from app.catalog_id_ledger where id = '${i.s}' and split_from = '${i.k}'`), 1);

  await drainRescoreBacklog(drainRepo, withDelegatedActor, 50);
  const afterSplit = (await playScore(actor.uid, i.k))!;
  assertEquals(afterSplit.pick, "user", "the existing play becomes a user pick of the KEPT course");
  // NEW-4 (A2-01): the label is not enough — the play was RE-SCORED with the cap.
  assertEquals(afterSplit.monetary, 0, "a user pick contributes 0 to score_monetary");
  assertEquals(afterSplit.money, false, "...so a fixture that was money-true is money-false once it is a user pick");
  assertEquals(await uniqueCourses(actor), 1, "the kept course counts once");

  // §4.2: ANY unlabelled play at a split-family course is a user pick and capped — not just the labelled one.
  const other = await newUser("split-control");
  const ctrl = await seedDwellAndScore(other, i.fac, i.s, "play-verified", { vendor: true });
  assertEquals(ctrl.play.money, false, "a play at a split sibling is a user pick: capped even though no label was ever written for this player");
  assertEquals(ctrl.play.scoreMonetary, 0);

  // Re-pick K -> S: the SAME play row moves, evidence follows (RE-DERIVED against S), still exactly 1.
  // S has no polygon: the stored fixes must be re-matched, not carried over from K.
  const moved = await withOwnership(actor, (repo) => repickUserPlay(repo, { facilityId: i.fac, playDate: todayChicago(), fromCourseId: i.k, toCourseId: i.s }));
  assertEquals(moved, { ok: true });
  assertEquals(await playScore(actor.uid, i.k), null, "nothing left at the kept course for that date");
  const atS = (await playScore(actor.uid, i.s))!;
  assertEquals(atS.id, afterSplit.id, "the SAME play row moved");
  assertEquals(atS.pick, "user");
  assertEquals(atS.monetary, 0);
  assertEquals(await rawCount(`select count(*)::int as n from app.play where user_id = '${actor.uid}'`), 1);
  assertEquals(await rawCount(`select count(*)::int as n from app.evidence where user_id = '${actor.uid}' and course_id = '${i.s}'`), 2, "the evidence (dwell + vendor round) moved with it");
  await ensureServiceRole();
  // §8.6 trigger (a): the single re-pick is used, so the raw coordinates are cleared with it.
  assertEquals(await rawCount(`select count(*)::int as n from app.evidence where user_id = '${actor.uid}' and integrity ? 'fixCoords'`), 0, "re-pick used -> coordinates cleared");
  const ev = await adminSql()`select summary from app.evidence where user_id = ${actor.uid} and source = 'foreground_dwell'`;
  const sum = ev[0]!.summary as { checkinFix: { geometryKind: string; insideBuffer: boolean }; holes: number };
  assertEquals(sum.checkinFix.geometryKind, "radius", "re-matched against S (no polygon), not K's");
  assertEquals(sum.checkinFix.insideBuffer, false);
  assertEquals(sum.holes, 18, "the 9-hole dwell moved to an 18-hole sibling gets the 18-hole bar");
  assertEquals(await uniqueCourses(actor), 1, "S's re-derived (radius, outside) play is still a user pick capped at 0.50 — it still counts once at S, and never double (K has nothing left)");

  // The re-pick is audited, and exactly ONE is allowed: back again is refused.
  assertEquals(await rawCount(`select count(*)::int as n from app.audit_log where actor_user_id = '${actor.uid}' and action = 'play.repick' and subject_id = '${afterSplit.id}'`), 1);
  const back = await withOwnership(actor, (repo) => repickUserPlay(repo, { facilityId: i.fac, playDate: todayChicago(), fromCourseId: i.s, toCourseId: i.k }));
  assertEquals(back, { ok: false, reason: "already_repicked" });
  const refused = await withOwnership(actor, (repo) => repickUserPlay(repo, { facilityId: i.fac, playDate: todayChicago(), fromCourseId: i.s, toCourseId: "crs_y1" }));
  assertEquals(refused, { ok: false, reason: "not_same_split_family" });
  // A geometry-resolved (non-user) play is not the player's to move.
  const notUser = await withOwnership(other, (repo) => repickUserPlay(repo, { facilityId: i.fac, playDate: todayChicago(), fromCourseId: i.s, toCourseId: i.k }));
  assertEquals(notUser, { ok: false, reason: "not_user_pick" });
});

Deno.test("AT 18 (concurrency): the promotion re-score racing a LIVE submission for the same play ends consistent — one play, no deadlock, same score as a final re-run", DT, async () => {
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
  const actor = await newUser("race");
  await seedDwellAndScore(actor, i.fac, i.k, "unverified");
  await pub.publish(v2, {
    "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "verified", transitions: [...mint(v1), { type: "verified", catalogVersion: v2 }] } } },
    "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "Promo K", holes: 18 }]),
  });

  await ensureServiceRole();
  const cur = await adminSql()`select site_version from app.catalog_version order by site_version desc nulls last, version desc limit 1`;
  const catalogVersion = cur[0]!.site_version as string;

  const live = withOwnership(actor, (repo) =>
    handleEvidenceIntake({ source: "self_report", deviceId: freshUuid(), facilityId: i.fac, courseId: i.k, localDate: todayChicago(), catalogVersion }, repo),
  );
  const drain = drainRescoreBacklog(drainRepo, withDelegatedActor, 50);
  const [liveResult, drained] = await Promise.all([live, drain]);
  assertEquals(liveResult.status, "accepted");
  assertEquals(drained.failures, 0);

  assertEquals(await rawCount(`select count(*)::int as n from app.play where user_id = '${actor.uid}' and course_id = '${i.k}'`), 1);
  const settled = (await playScore(actor.uid, i.k))!;
  // A final, serialized re-score over the same stored rows is a fixed point.
  await withOwnership(actor, (repo) => finalizeScoringForKey(repo, i.fac, i.k, todayChicago()));
  const again = (await playScore(actor.uid, i.k))!;
  assertEquals(again.badge, settled.badge, "the raced result equals a clean re-score");
  assert(again.badge >= 0.5);
  assertEquals(await uniqueCourses(actor), 1);
});

Deno.test("R3: holes, hole details and roster versions/members are imported (and a re-import is a no-op)", DT, async () => {
  const i = ids();
  const pub = await newPublisher();
  const v1 = await freshSiteVersion("20260901");
  const v2 = await freshSiteVersion("20260925");
  const trail = (members2: unknown[]) => [{ id: i.trl, slug: `promo-trail-${i.salt.toLowerCase()}`, name: "Promo Trail", rosterVersions: [
    { version: 1, effectiveFrom: "2026-01-01", completionUnit: "course", markerUnit: "facility", completionRule: { kind: "all" }, markerRule: { kind: "all" }, members: [{ unit: "course", courseId: i.k, stopOrder: 0 }, { unit: "facility", facilityId: i.fac }, { unit: "hole", holeId: i.hol1, courseId: i.k }] },
    { version: 2, effectiveFrom: "2026-03-01", completionUnit: "course", markerUnit: "facility", completionRule: { kind: "n-of-m", n: 1, ruleSource: { url: "https://example.test/rule", retrieved: "2026-02-01" } }, markerRule: { kind: "all" }, trackingStartsOn: "2026-03-15", members: members2 },
  ] }];
  const ledger = { entries: {
    [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "verified", transitions: mint(v1) },
    [i.hol1]: { id: i.hol1, transitions: mint(v1) }, [i.hol2]: { id: i.hol2, transitions: mint(v1) }, [i.trl]: { id: i.trl, transitions: mint(v1) },
  } };
  const shards = (members2: unknown[]) => ({
    "id-ledger.json": ledger,
    "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "Promo K", holes: 9, holesDetail: [{ id: i.hol1, number: 1 }, { id: i.hol2, number: 2 }] }]),
    "trails.json": trail(members2),
  });
  const o = await pub.publish(v1, shards([{ unit: "facility", facilityId: i.fac }]));
  assertEquals(o.holesApplied, 2);
  assertEquals(o.rosterVersionsApplied, 2);

  await ensureServiceRole();
  const course = await adminSql()`select holes from app.catalog_course where id = ${i.k}`;
  assertEquals(Number(course[0]!.holes), 9);
  assertEquals(await rawCount(`select count(*)::int as n from app.catalog_hole where course_id = '${i.k}'`), 2);
  // (A real user: the actor is BOUND, and `private.bind_actor` refuses a uid that is not in auth.users.)
  const reader = freshUuid();
  await createTestUser(reader, "r3-reader");
  assertEquals(await withOwnership({ uid: reader, role: "authenticated" }, (repo) => repo.catalog.courseHoleCount(i.k)), 2, "catalog_hole rows win");

  const rv = await adminSql()`select version, completion_rule, completion_rule_n, completion_rule_source, tracking_starts_on from app.catalog_roster_version where trail_id = ${i.trl} order by version`;
  assertEquals(rv.length, 2);
  assertEquals(rv[1]!.completion_rule, "n_of_m");
  assertEquals(Number(rv[1]!.completion_rule_n), 1);
  assertEquals(rv[1]!.completion_rule_source, "https://example.test/rule");
  const members = await adminSql()`select roster_version, unit, course_id, facility_id, hole_id, removed_on from app.catalog_roster_member where trail_id = ${i.trl} order by roster_version, unit`;
  assertEquals(members.length, 4); // v1: course + facility + hole; v2: facility
  const v1Course = members.find((m) => m.roster_version === 1 && m.unit === "course")!;
  assert(v1Course.removed_on !== null, "v1's course stop was dropped in v2 -> removed_on is derived");
  assertEquals(members.find((m) => m.roster_version === 1 && m.unit === "facility")!.removed_on, null);
  const v1Hole = members.find((m) => m.roster_version === 1 && m.unit === "hole")!;
  assertEquals(v1Hole.hole_id, i.hol1);
  assertEquals(v1Hole.course_id, i.k);

  // A later release re-publishing the same roster versions changes nothing.
  const o2 = await pub.publish(v2, shards([{ unit: "facility", facilityId: i.fac }]));
  assert(o2.ok);
  assertEquals(await rawCount(`select count(*)::int as n from app.catalog_roster_member where trail_id = '${i.trl}'`), 4);
  assertEquals(await rawCount(`select count(*)::int as n from app.catalog_roster_version where trail_id = '${i.trl}'`), 2);
});

Deno.test("R3: an imported course with an UNKNOWN hole count never gets the 9-hole dwell bar (fails closed to 18)", DT, async () => {
  const i = ids();
  const pub = await newPublisher();
  const v1 = await freshSiteVersion("20260901");
  await pub.publish(v1, {
    "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "verified", transitions: mint(v1) } } },
    "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "No Holes Known" }]), // neither holes nor holesDetail
  });
  const reader = freshUuid();
  await createTestUser(reader, "r3-reader-2");
  const n = await withOwnership({ uid: reader, role: "authenticated" }, (repo) => repo.catalog.courseHoleCount(i.k));
  assertEquals(n, 0);
  const { dwellHolesFromCount } = await import("../../functions/_shared/evidence/handler.ts");
  assertEquals(dwellHolesFromCount(n), 18);
});

Deno.test("backlog keyset (LOW): a play created MID-DRAIN whose random uuid sorts BEFORE the cursor is still reached (a stable (created_at, id) keyset, not bare uuid order)", DT, async () => {
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
  const users = [await newUser("k1"), await newUser("k2"), await newUser("k3")];
  for (const u of users) await seedDwellAndScore(u, i.fac, i.k, "unverified");
  await pub.publish(v2, {
    "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "verified", transitions: [...mint(v1), { type: "verified", catalogVersion: v2 }] } } },
    "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "Promo K", holes: 18 }]),
  });

  const pass1 = await drainRescoreBacklog(drainRepo, withDelegatedActor, 2);
  assertEquals(pass1.playsProcessed, 2);

  // A new play lands while the drain is mid-course, and its id is the
  // SMALLEST possible uuid — i.e. behind any cursor under bare id ordering.
  const late = await newUser("k-late");
  await withOwnership(late, (repo) =>
    repo.play.upsertFromScore({ courseId: i.k, facilityId: i.fac, playDate: todayChicago(), courseDisambiguatedBy: null, scoreBadge: 0, scoreMonetary: 0, hardSignal: false, presenceSignal: false, money: false, heldReview: false, policyVersion: "1", inputDigest: "d".repeat(64), evidenceIds: [] }),
  );
  await ensureServiceRole();
  await adminSql()`update app.play set id = '00000000-0000-4000-8000-0000000000aa' where user_id = ${late.uid} and course_id = ${i.k}`;

  // Count which players the drain actually re-scored.
  const seen = new Set<string>();
  const spy: typeof withDelegatedActor = (delegate, actor, op) => {
    seen.add(actor.uid);
    return withDelegatedActor(delegate, actor, op);
  };
  const pass2 = await drainRescoreBacklog(drainRepo, spy, 50, undefined, NO_GRACE);
  assertEquals(pass2.failures, 0);
  assert(seen.has(late.uid), "the late play (id behind the cursor) was reached");
  assertEquals(pass2.coursesCompleted, 1);
});

Deno.test("M6 (interop): a ledger transition naming an ARBITRARY catalogVersion string does not reject the import — it falls back to the importing version", DT, async () => {
  const i = ids();
  const pub = await newPublisher();
  const v1 = await freshSiteVersion("20260901");
  const arbitrary = "not a site version at all / 2026";
  const o = await pub.publish(v1, {
    "id-ledger.json": { entries: {
      [i.fac]: { id: i.fac, status: "verified", transitions: [{ type: "minted", catalogVersion: arbitrary }, { type: "verified", catalogVersion: arbitrary }] },
    } },
  });
  assert(o.ok);
  const importing = await adminSql()`select version from app.catalog_version where site_version = ${v1}`;
  const row = await adminSql()`select first_catalog_version, verified_in_version from app.catalog_id_ledger where id = ${i.fac}`;
  assertEquals(row[0]!.first_catalog_version, importing[0]!.version);
  assertEquals(row[0]!.verified_in_version, importing[0]!.version);
});

Deno.test("split_from conflicts fail closed (LOW): a later ledger naming a DIFFERENT kept course for an already-split sibling is rejected whole, and the stored lineage is untouched", DT, async () => {
  const i = ids();
  const pub = await newPublisher();
  const k2 = i.mk("crs", "00000Q");
  const v1 = await freshSiteVersion("20260901");
  const v2 = await freshSiteVersion("20260925");
  const base = {
    [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) },
    [i.k]: { id: i.k, status: "verified", transitions: [...mint(v1), { type: "split", catalogVersion: v1, siblingIds: [i.s] }] },
    [k2]: { id: k2, status: "verified", transitions: mint(v1) },
    [i.s]: { id: i.s, status: "verified", transitions: mint(v1) },
  };
  const first = await pub.publish(v1, { "id-ledger.json": { entries: base } });
  assert(first.ok);
  assertEquals(await rawCount(`select count(*)::int as n from app.catalog_id_ledger where id = '${i.s}' and split_from = '${i.k}'`), 1);

  // v2: k2 now claims S as ITS split sibling (and K no longer does).
  let rejected: unknown = null;
  try {
    await pub.publish(v2, {
      "id-ledger.json": { entries: {
        ...base,
        [i.k]: { id: i.k, status: "verified", transitions: mint(v1) },
        [k2]: { id: k2, status: "verified", transitions: [...mint(v1), { type: "split", catalogVersion: v2, siblingIds: [i.s] }] },
      } },
    });
  } catch (err) {
    rejected = err;
  }
  assert(rejected !== null, "the conflicting ledger must be rejected");
  assert(String((rejected as Error).message).includes(i.s), `the reason must name the conflicting sibling: ${(rejected as Error).message}`);
  assertEquals(await rawCount(`select count(*)::int as n from app.catalog_id_ledger where id = '${i.s}' and split_from = '${i.k}'`), 1, "the stored lineage is unchanged");
});
