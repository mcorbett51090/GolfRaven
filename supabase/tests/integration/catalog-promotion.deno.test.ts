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
import { withOwnership, withSystemCatalogImport } from "../../functions/_shared/privileged.ts";
import { fetchAndVerifyArtifact, applyImportPlanAtomically, type FetchBytes } from "../../functions/_shared/catalog/import-handler.ts";
import { drainRescoreBacklog } from "../../functions/_shared/catalog/rescore-orchestrator.ts";
import { makeDrainReadRepo } from "../../functions/_shared/catalog/drain-read-repo.ts";
import { canonicalStringify, MANIFEST_DOMAIN, VERSIONS_DOMAIN } from "../../functions/_shared/catalog/manifest-artifact.ts";
import { bytesToBase64Url } from "../../functions/_shared/catalog/signature.ts";
import { finalizeScoringForKey, handleEvidenceIntake, repickUserPlay } from "../../functions/_shared/evidence/handler.ts";
import { deriveFix } from "../../functions/_shared/evidence/derive-fix.ts";
import { adminSql, createTestUser, ensureServiceRole, freshUuid, insertSigningKeyWithKey, rawCount } from "./_helpers.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };
const BASE_URL = "https://golfraven.example/catalog/v1";
const ALLOWED_HOSTS = ["golfraven.example"];
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const drainRepo = makeDrainReadRepo(withSystemCatalogImport);

function todayChicago(): string {
  return new Intl.DateTimeFormat("en-CA", { timeZone: "America/Chicago", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
}

/** Unique ids per test run (the cluster is shared with every other test file). */
function ids() {
  const salt = [...crypto.getRandomValues(new Uint8Array(20))].map((b) => CROCKFORD[b % 32]).join("");
  const mk = (prefix: string, n: string) => `${prefix}_${salt}${n}`; // 20 + 6 = 26
  return {
    fac: mk("fac", "000001"),
    k: mk("crs", "00000K"),
    s: mk("crs", "00000S"),
    trl: mk("trl", "000001"),
    hol1: mk("hol", "000001"),
    hol2: mk("hol", "000002"),
    mk,
    salt,
  };
}

async function generateKeypair() {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = await crypto.subtle.exportKey("raw", kp.publicKey);
  return { privateKey: kp.privateKey, publicKeyB64Url: bytesToBase64Url(new Uint8Array(raw)) };
}
async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", bytes.slice().buffer);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function signStd(privateKey: CryptoKey, text: string): Promise<string> {
  const sig = await crypto.subtle.sign("Ed25519", privateKey, new TextEncoder().encode(text));
  let bin = "";
  for (const b of new Uint8Array(sig)) bin += String.fromCharCode(b);
  return btoa(bin);
}
const jsonBytes = (v: unknown) => new TextEncoder().encode(canonicalStringify(v));

class Publisher {
  private history: { version: string; publishedAt: string; kid: string; sha256: string }[] = [];
  constructor(private privateKey: CryptoKey, private kid: string) {}

  /** Signs + imports one release (real two-phase pipeline). */
  async publish(version: string, shardFiles: Record<string, unknown>) {
    if (!this.history.some((h) => h.version === version)) this.history.push({ version, publishedAt: new Date().toISOString(), kid: this.kid, sha256: "a".repeat(63) + String(this.history.length) });
    const bytesByPath = new Map<string, Uint8Array>();
    for (const [path, value] of Object.entries(shardFiles)) bytesByPath.set(path, jsonBytes(value));
    const shards = [];
    for (const [path, bytes] of bytesByPath) shards.push({ path, sha256: await sha256Hex(bytes), bytes: bytes.length });
    const manifestBytes = jsonBytes({ contractVersion: 1, catalogVersion: version, minAppVersion: "1.0.0", kid: this.kid, revokedKids: [], generatedAt: new Date().toISOString(), shards });
    const mStmt = { catalogVersion: version, contractVersion: 1, kid: this.kid, manifestSha: await sha256Hex(manifestBytes) };
    const manifestSigBytes = jsonBytes({ ...mStmt, sig: await signStd(this.privateKey, MANIFEST_DOMAIN + canonicalStringify(mStmt)) });
    const versionsBytes = jsonBytes(this.history);
    const vStmt = { kid: this.kid, versionsSha: await sha256Hex(versionsBytes) };
    const versionsSigBytes = jsonBytes({ ...vStmt, sig: await signStd(this.privateKey, VERSIONS_DOMAIN + canonicalStringify(vStmt)) });
    const fetchBytes: FetchBytes = async (url: string) => {
      if (url.endsWith("/manifest.json")) return manifestBytes;
      if (url.endsWith("/manifest.sig.json")) return manifestSigBytes;
      if (url.endsWith("/versions.json")) return versionsBytes;
      if (url.endsWith("/versions.sig.json")) return versionsSigBytes;
      for (const [p, b] of bytesByPath) if (url.endsWith(`/${p}`)) return b;
      throw new Error(`unexpected url ${url}`);
    };
    const getKey = async (kid: string) => {
      await ensureServiceRole();
      const rows = await adminSql()`select kid, public_key_b64url, revoked_at from app.catalog_signing_key where kid = ${kid}`;
      const r = rows[0];
      return r ? { kid: r.kid as string, publicKeyB64Url: r.public_key_b64url as string, revokedAt: r.revoked_at ? (r.revoked_at as Date).toISOString() : null } : null;
    };
    const plan = await fetchAndVerifyArtifact({ artifactBaseUrl: BASE_URL, allowedHosts: ALLOWED_HOSTS }, fetchBytes, getKey);
    assert(plan.ok, `plan rejected: ${JSON.stringify(plan)}`);
    const outcome = await applyImportPlanAtomically(plan, withSystemCatalogImport);
    assert(outcome.ok, `import rejected: ${outcome.reason}`);
    return outcome;
  }
}

async function newPublisher() {
  const { privateKey, publicKeyB64Url } = await generateKeypair();
  const kid = `kid-promo-${freshUuid()}`;
  await insertSigningKeyWithKey(kid, publicKeyB64Url, null);
  return new Publisher(privateKey, kid);
}

const mint = (v: string) => [{ type: "minted", catalogVersion: v }];
const facilityShard = (i: ReturnType<typeof ids>, status: string, courses: unknown[]) => [
  { id: i.fac, slug: `promo-${i.salt.toLowerCase()}`, region: "US-TN", tz: "America/Chicago", name: "Promo Facility", verification: { status }, courses },
];

/** Gives an imported course a real polygon (the artifact carries none) so
 * the (derived-fix) tier is the ONLY thing standing between the stub-era
 * score and the promoted one. */
async function giveCoursePolygon(courseId: string) {
  await ensureServiceRole();
  const d = 0.001;
  await adminSql()`
    update app.catalog_course set geometry_kind = 'polygon',
      boundary = ST_SetSRID(ST_MakePolygon(ST_MakeLine(ARRAY[
        ST_MakePoint(${-86.7816 - d}, ${36.1467 - d}), ST_MakePoint(${-86.7816 + d}, ${36.1467 - d}),
        ST_MakePoint(${-86.7816 + d}, ${36.1467 + d}), ST_MakePoint(${-86.7816 - d}, ${36.1467 + d}),
        ST_MakePoint(${-86.7816 - d}, ${36.1467 - d})])), 4326)
    where id = ${courseId}`;
}

type Actor = { uid: string; role: "authenticated" };
async function newUser(label: string): Promise<Actor> {
  const uid = freshUuid();
  await createTestUser(uid, `promo-${label}-${uid.slice(0, 8)}`);
  return { uid, role: "authenticated" };
}

/** A dwell round (2 h apart, both fixes live+attested, inside a polygon) the
 * way live intake would have stored it, with the course's tier AS OF NOW. */
async function seedDwellAndScore(actor: Actor, facilityId: string, courseId: string, tier: "unverified" | "play-verified") {
  const localDate = todayChicago();
  const noonUtcMs = Date.parse(`${localDate}T17:00:00Z`); // 12:00 Chicago (CDT/CST both keep this on the same local day)
  const mk = (fixId: string, capturedAt: number) =>
    deriveFix({
      fix: { fixId, accuracyMeters: 10, capturedAt, simulated: false, foreground: true, fromApp: true },
      resolvedFacilityId: facilityId,
      localDate,
      match: { verificationTier: tier, geometryKind: "polygon", insideBuffer: true },
      consumedToken: { attestationGrade: "attested", challengeKind: "live" },
    });
  return withOwnership(actor, async (repo) => {
    const device = await repo.device.ensureOwn(null, "ios");
    const sourceRef = `dwell-${freshUuid()}`;
    await repo.evidence.insertIdempotent({
      kind: "resolved", sourceRef, inputHash: `hash-${sourceRef}`, source: "foreground_dwell", facilityId, courseId,
      startedAt: null, endedAt: null, localDate,
      summary: { localDate, checkinFix: mk(`in${freshUuid().slice(0, 8)}`, noonUtcMs), checkoutFix: mk(`out${freshUuid().slice(0, 8)}`, noonUtcMs + 120 * 60_000), apartMinutes: 120, holes: 18 },
      integrity: {}, cosignal: {}, attestationGrade: "attested", matcherVersion: null, catalogVersion: null, status: "accepted", deviceId: device.id,
    });
    return finalizeScoringForKey(repo, facilityId, courseId, localDate);
  });
}

const playScore = async (uid: string, courseId: string) => {
  await ensureServiceRole();
  const rows = await adminSql()`select score_badge, status, course_disambiguated_by, id from app.play where user_id = ${uid} and course_id = ${courseId}`;
  return rows[0] ? { badge: Number(rows[0].score_badge), status: rows[0].status as string, pick: rows[0].course_disambiguated_by as string | null, id: rows[0].id as string } : null;
};
const uniqueCourses = (actor: Actor) => withOwnership(actor, (repo) => repo.play.uniqueCourseCount());

Deno.test("AT 18: a play at a STUB is accepted but counts toward nothing; after promotion the bounded drain re-scores it and uniqueCourses rises by exactly 1 (replays never double)", DT, async () => {
  const i = ids();
  const pub = await newPublisher();
  const v1 = `20260901-${i.salt.slice(0, 7).toLowerCase().replace(/[^0-9a-f]/g, "0")}`;
  const v2 = `20260925-${i.salt.slice(7, 14).toLowerCase().replace(/[^0-9a-f]/g, "1")}`;

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
  const pass1 = await drainRescoreBacklog(drainRepo, withOwnership, 2);
  assertEquals(pass1.playsProcessed, 2);
  assertEquals(pass1.coursesCompleted, 0);
  assertEquals(await rawCount(`select count(*)::int as n from app.catalog_rescore_backlog where course_id = '${i.k}' and done_at is null`), 1, "the backlog row stays open with a cursor");
  const pass2 = await drainRescoreBacklog(drainRepo, withOwnership, 2);
  assertEquals(pass2.playsProcessed, 1);
  assertEquals(pass2.coursesCompleted, 1);

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
  const idle = await drainRescoreBacklog(drainRepo, withOwnership, 50);
  assertEquals(idle.playsProcessed, 0);
  for (const u of users) assertEquals(await uniqueCourses(u), 1, "an idempotent replay must not double the count");
});

Deno.test("AT 18 (split): the kept course counts once as a USER pick; a re-pick MOVES the play (never double counts)", DT, async () => {
  const i = ids();
  const pub = await newPublisher();
  const v1 = `20260901-${i.salt.slice(0, 7).toLowerCase().replace(/[^0-9a-f]/g, "2")}`;
  const v2 = `20260925-${i.salt.slice(7, 14).toLowerCase().replace(/[^0-9a-f]/g, "3")}`;
  const ledger1 = { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "verified", transitions: mint(v1) } };
  await pub.publish(v1, { "id-ledger.json": { entries: ledger1 }, "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "Promo K", holes: 18 }]) });
  await giveCoursePolygon(i.k);

  const actor = await newUser("split");
  const scored = await seedDwellAndScore(actor, i.fac, i.k, "play-verified");
  assert(scored.play.scoreBadge >= 0.5);
  assertEquals(await uniqueCourses(actor), 1);
  assertEquals((await playScore(actor.uid, i.k))!.pick, null);

  // v2: K splits; S is the new, verified sibling.
  const o2 = await pub.publish(v2, {
    "id-ledger.json": { entries: {
      ...ledger1,
      [i.k]: { id: i.k, status: "verified", transitions: [...mint(v1), { type: "split", catalogVersion: v2, siblingIds: [i.s] }] },
      [i.s]: { id: i.s, status: "verified", transitions: mint(v2) },
    } },
    "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "Promo K", holes: 9 }, { id: i.s, name: "Promo S", holes: 9 }]),
  });
  assertEquals(o2.splitCourses, 1);
  await giveCoursePolygon(i.s);
  assertEquals(await rawCount(`select count(*)::int as n from app.catalog_id_ledger where id = '${i.s}' and split_from = '${i.k}'`), 1);

  await drainRescoreBacklog(drainRepo, withOwnership, 50);
  const afterSplit = (await playScore(actor.uid, i.k))!;
  assertEquals(afterSplit.pick, "user", "the existing play becomes a user pick of the KEPT course");
  assertEquals(await uniqueCourses(actor), 1, "the kept course counts once");

  // Re-pick K -> S: the SAME play row moves, evidence follows, still exactly 1.
  const moved = await withOwnership(actor, (repo) => repickUserPlay(repo, { facilityId: i.fac, playDate: todayChicago(), fromCourseId: i.k, toCourseId: i.s }));
  assertEquals(moved, { ok: true });
  assertEquals(await playScore(actor.uid, i.k), null, "nothing left at the kept course for that date");
  const atS = (await playScore(actor.uid, i.s))!;
  assertEquals(atS.id, afterSplit.id, "the SAME play row moved");
  assertEquals(atS.pick, "user");
  assertEquals(await rawCount(`select count(*)::int as n from app.play where user_id = '${actor.uid}'`), 1);
  assertEquals(await rawCount(`select count(*)::int as n from app.evidence where user_id = '${actor.uid}' and course_id = '${i.s}'`), 1, "the evidence moved with it");
  assertEquals(await uniqueCourses(actor), 1, "a re-pick never double counts");

  // And back again, still 1; a course outside the split family is refused.
  const back = await withOwnership(actor, (repo) => repickUserPlay(repo, { facilityId: i.fac, playDate: todayChicago(), fromCourseId: i.s, toCourseId: i.k }));
  assertEquals(back, { ok: true });
  assertEquals(await uniqueCourses(actor), 1);
  const refused = await withOwnership(actor, (repo) => repickUserPlay(repo, { facilityId: i.fac, playDate: todayChicago(), fromCourseId: i.k, toCourseId: "crs_y1" }));
  assertEquals(refused, { ok: false, reason: "not_same_split_family" });
});

Deno.test("AT 18 (concurrency): the promotion re-score racing a LIVE submission for the same play ends consistent — one play, no deadlock, same score as a final re-run", DT, async () => {
  const i = ids();
  const pub = await newPublisher();
  const v1 = `20260901-${i.salt.slice(0, 7).toLowerCase().replace(/[^0-9a-f]/g, "4")}`;
  const v2 = `20260925-${i.salt.slice(7, 14).toLowerCase().replace(/[^0-9a-f]/g, "5")}`;
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
  const drain = drainRescoreBacklog(drainRepo, withOwnership, 50);
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
  const v1 = `20260901-${i.salt.slice(0, 7).toLowerCase().replace(/[^0-9a-f]/g, "6")}`;
  const v2 = `20260925-${i.salt.slice(7, 14).toLowerCase().replace(/[^0-9a-f]/g, "7")}`;
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
  assertEquals(await withOwnership({ uid: freshUuid(), role: "authenticated" }, (repo) => repo.catalog.courseHoleCount(i.k)), 2, "catalog_hole rows win");

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
  const v1 = `20260901-${i.salt.slice(0, 7).toLowerCase().replace(/[^0-9a-f]/g, "8")}`;
  await pub.publish(v1, {
    "id-ledger.json": { entries: { [i.fac]: { id: i.fac, status: "verified", transitions: mint(v1) }, [i.k]: { id: i.k, status: "verified", transitions: mint(v1) } } },
    "facilities/us.json": facilityShard(i, "play-verified", [{ id: i.k, name: "No Holes Known" }]), // neither holes nor holesDetail
  });
  const n = await withOwnership({ uid: freshUuid(), role: "authenticated" }, (repo) => repo.catalog.courseHoleCount(i.k));
  assertEquals(n, 0);
  const { dwellHolesFromCount } = await import("../../functions/_shared/evidence/handler.ts");
  assertEquals(dwellHolesFromCount(n), 18);
});
