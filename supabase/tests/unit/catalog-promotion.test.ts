// supabase/tests/unit/catalog-promotion.test.ts
//
// P3e round 3 — AT 18 (promotion / split re-score backlog) at the unit
// level, plus R3 (holes, rosters) parsing and import wiring, against the
// in-memory fakes. The REAL SQL (unnest upserts, keyset cursor, the
// uniqueCourses query) is proven against Postgres in
// integration/catalog-promotion.deno.test.ts.
import { describe, expect, it } from "vitest";
import { drainRescoreBacklog, type WithOwnershipFn } from "../../functions/_shared/catalog/rescore-orchestrator.js";
import { applyImportPlan, fetchAndVerifyArtifact } from "../../functions/_shared/catalog/import-handler.js";
import { parseFacilitiesShard, parseTrailsShard } from "../../functions/_shared/catalog/directory-artifact.js";
import { dwellHolesFromCount, handleEvidenceIntake, repickUserPlay } from "../../functions/_shared/evidence/handler.js";
import { makeFakeRepo, makeFakeState, FAKE_DEVICE_ID } from "./fake-repo.js";
import { makeFakeImporterRepo, makeFakeImporterState } from "./fake-importer-repo.js";
import { buildSignedArtifact, generateKeypair, jsonBytes } from "./catalog-artifact-fixtures.js";
import type { Actor, Repo } from "../../functions/_shared/types.js";

const NOW = new Date("2026-09-25T00:00:00.000Z");
const C = "01ARZ3NDEKTSV4RRFFQ69G5F"; // + 2 chars => 26
const id = (prefix: string, suffix: string) => `${prefix}_${C}${suffix}`;
const FAC = id("fac", "A1");
const CRS_K = id("crs", "A1");
const CRS_S = id("crs", "A2");
const HOL1 = id("hol", "A1");
const HOL2 = id("hol", "A2");
const TRL = id("trl", "A1");

describe("R3 — holes", () => {
  it("only a known count of exactly 9 earns the 9-hole dwell bar; unknown/odd counts take the stricter 18", () => {
    expect(dwellHolesFromCount(9)).toBe(9);
    expect(dwellHolesFromCount(18)).toBe(18);
    expect(dwellHolesFromCount(0)).toBe(18); // unknown — never lowers the bar
    expect(dwellHolesFromCount(12)).toBe(18); // used to fall into the 9-hole bucket
    expect(dwellHolesFromCount(27)).toBe(18);
  });

  it("parses Course.holes and Course.holesDetail", () => {
    const r = parseFacilitiesShard([
      { id: FAC, slug: "f", region: "US-TN", tz: "America/Chicago", name: "F", verification: { status: "play-verified" }, courses: [{ id: CRS_K, name: "K", holes: 9, holesDetail: [{ id: HOL1, number: 1 }, { id: HOL2, number: 2 }] }] },
    ]);
    expect(r.ok).toBe(true);
    if (!r.ok) throw new Error("unreachable");
    expect(r.value[0]!.courses[0]!.holes).toBe(9);
    expect(r.value[0]!.courses[0]!.holesDetail.map((h) => h.number)).toEqual([1, 2]);
  });

  it("rejects a malformed hole id / number", () => {
    const bad = (h: unknown) => parseFacilitiesShard([{ id: FAC, slug: "f", region: "US-TN", tz: "x", verification: { status: "unverified" }, courses: [{ id: CRS_K, holesDetail: [h] }] }]).ok;
    expect(bad({ id: "crs_" + C + "ZZ", number: 1 })).toBe(false);
    expect(bad({ id: HOL1, number: 0 })).toBe(false);
    expect(bad({ id: HOL1, number: 37 })).toBe(false);
  });
});

describe("R3 — rosters", () => {
  const rv = (version: number, members: unknown[], extra: Record<string, unknown> = {}) => ({
    version, effectiveFrom: `2026-0${version}-01`, completionUnit: "course", markerUnit: "facility",
    completionRule: { kind: "all" }, markerRule: { kind: "all" }, members, ...extra,
  });

  it("parses every member shape and n-of-m rules", () => {
    const r = parseTrailsShard([
      { id: TRL, slug: "t", name: "T", rosterVersions: [rv(1, [{ unit: "course", courseId: CRS_K, stopOrder: 0 }, { unit: "course", anyOf: [CRS_K, CRS_S] }, { unit: "facility", facilityId: FAC }, { unit: "hole", holeId: HOL1, courseId: CRS_K }], { completionRule: { kind: "n-of-m", n: 3, ruleSource: { url: "https://example.test/rule", retrieved: "2026-01-01" } }, trackingStartsOn: "2026-02-01" })] },
    ]);
    expect(r.ok).toBe(true);
    if (!r.ok) throw new Error("unreachable");
    const v = r.value[0]!.rosterVersions[0]!;
    expect(v.members).toHaveLength(4);
    expect(v.completionRule).toEqual({ kind: "n_of_m", n: 3, source: "https://example.test/rule" });
    expect(v.trackingStartsOn).toBe("2026-02-01");
  });

  it("rejects an n-of-m rule with no ruleSource, and an empty member list", () => {
    expect(parseTrailsShard([{ id: TRL, slug: "t", name: "T", rosterVersions: [rv(1, [{ unit: "facility", facilityId: FAC }], { completionRule: { kind: "n-of-m", n: 2 } })] }]).ok).toBe(false);
    expect(parseTrailsShard([{ id: TRL, slug: "t", name: "T", rosterVersions: [rv(1, [])] }]).ok).toBe(false);
  });
});

async function importArtifact(state: ReturnType<typeof makeFakeImporterState>, opts: { version: string; history: string[]; ledger: Record<string, unknown>; facilities?: unknown[]; trails?: unknown[]; priv: CryptoKey; kid: string }) {
  const shards = [{ path: "id-ledger.json", bytes: jsonBytes({ entries: opts.ledger }) }];
  if (opts.facilities) shards.push({ path: "facilities/us.json", bytes: jsonBytes(opts.facilities) });
  if (opts.trails) shards.push({ path: "trails.json", bytes: jsonBytes(opts.trails) });
  const art = await buildSignedArtifact({
    privateKey: opts.priv, kid: opts.kid, contractVersion: 1, catalogVersion: opts.version, minAppVersion: "1.0.0", revokedKids: [], generatedAt: NOW.toISOString(),
    versionHistory: opts.history.map((v, i) => ({ version: v, publishedAt: NOW.toISOString(), kid: opts.kid, sha256: String(i).repeat(64) })), shards,
  });
  const repo = makeFakeImporterRepo(state);
  const fetchBytes = async (url: string) => {
    if (url.endsWith("/manifest.json")) return art.manifestBytes;
    if (url.endsWith("/manifest.sig.json")) return art.manifestSigBytes;
    if (url.endsWith("/versions.json")) return art.versionsBytes;
    if (url.endsWith("/versions.sig.json")) return art.versionsSigBytes;
    for (const [p, b] of art.shardsByPath) if (url.endsWith(`/${p}`)) return b;
    throw new Error(url);
  };
  const plan = await fetchAndVerifyArtifact({ artifactBaseUrl: "https://golfraven.example/catalog/v1", allowedHosts: ["golfraven.example"] }, fetchBytes, (k) => repo.catalog.getSigningKey(k), undefined, NOW);
  if (!plan.ok) throw new Error(plan.reason);
  return applyImportPlan(plan, repo);
}

describe("AT 18 — import queues the work (never does it inline)", () => {
  async function setup() {
    const { privateKey, publicKeyB64Url } = await generateKeypair();
    const state = makeFakeImporterState(NOW);
    state.signingKeys.set("k", { kid: "k", publicKeyB64Url, revokedAt: null });
    return { state, priv: privateKey };
  }
  const v1 = "20260901-1111111";
  const v2 = "20260925-2222222";
  const fac = (status: string) => [{ id: FAC, slug: "f", region: "US-TN", tz: "America/Chicago", name: "F", verification: { status }, courses: [{ id: CRS_K, name: "K", holes: 18, holesDetail: [{ id: HOL1, number: 1 }] }] }];
  const mint = (v: string) => [{ type: "minted", catalogVersion: v }];

  it("a stub -> verified ledger transition on an EXISTING course enqueues exactly one promotion row; a replay of the import enqueues nothing more", async () => {
    const { state, priv } = await setup();
    const ledger1 = { [FAC]: { id: FAC, status: "verified", transitions: mint(v1) }, [CRS_K]: { id: CRS_K, status: "stub", transitions: mint(v1) }, [HOL1]: { id: HOL1, transitions: mint(v1) } };
    const o1 = await importArtifact(state, { version: v1, history: [v1], ledger: ledger1, facilities: fac("unverified"), priv, kid: "k" });
    expect(o1.ok).toBe(true);
    expect(state.backlog).toHaveLength(0); // minted as a stub: nothing to promote yet
    expect(state.holes.get(HOL1)!.courseId).toBe(CRS_K);
    expect(state.courses.get(CRS_K)!.holes).toBe(18);

    const ledger2 = { ...ledger1, [CRS_K]: { id: CRS_K, status: "verified", transitions: [...mint(v1), { type: "verified", catalogVersion: v2 }] } };
    const o2 = await importArtifact(state, { version: v2, history: [v1, v2], ledger: ledger2, facilities: fac("play-verified"), priv, kid: "k" });
    expect(o2.ok).toBe(true);
    if (!o2.ok) throw new Error("unreachable");
    expect(o2.promotedCourses).toBe(1);
    expect(state.backlog.map((b) => [b.courseId, b.reason])).toEqual([[CRS_K, "promotion"]]);
    expect(state.courses.get(CRS_K)!.verificationStatus).toBe("play-verified");

    const again = await importArtifact(state, { version: v2, history: [v1, v2], ledger: ledger2, facilities: fac("play-verified"), priv, kid: "k" });
    expect(again.ok).toBe(true);
    expect(state.backlog).toHaveLength(1);
  });

  it("a split transition naming a NEW sibling enqueues the KEPT course once and records split_from on the sibling", async () => {
    const { state, priv } = await setup();
    const l1 = { [FAC]: { id: FAC, status: "verified", transitions: mint(v1) }, [CRS_K]: { id: CRS_K, status: "verified", transitions: mint(v1) } };
    await importArtifact(state, { version: v1, history: [v1], ledger: l1, facilities: fac("play-verified"), priv, kid: "k" });
    const l2 = {
      ...l1,
      [CRS_K]: { id: CRS_K, status: "verified", transitions: [...mint(v1), { type: "split", catalogVersion: v2, siblingIds: [CRS_S] }] },
      [CRS_S]: { id: CRS_S, status: "verified", transitions: mint(v2) },
    };
    const o = await importArtifact(state, { version: v2, history: [v1, v2], ledger: l2, priv, kid: "k" });
    expect(o.ok).toBe(true);
    expect(state.backlog.map((b) => [b.courseId, b.reason])).toEqual([[CRS_K, "split"]]);
    expect(state.ledger.get(CRS_S)!.splitFrom).toBe(CRS_K);
  });

  it("persists roster versions and derives removed_on when a later version drops a stop", async () => {
    const { state, priv } = await setup();
    const ledger = { [FAC]: { id: FAC, status: "verified", transitions: mint(v1) }, [CRS_K]: { id: CRS_K, status: "verified", transitions: mint(v1) }, [HOL1]: { id: HOL1, transitions: mint(v1) } };
    const trail = [{ id: TRL, slug: "t", name: "T", rosterVersions: [
      { version: 1, effectiveFrom: "2026-01-01", completionUnit: "course", markerUnit: "facility", completionRule: { kind: "all" }, markerRule: { kind: "all" }, members: [{ unit: "course", courseId: CRS_K }, { unit: "facility", facilityId: FAC }] },
      { version: 2, effectiveFrom: "2026-03-01", completionUnit: "course", markerUnit: "facility", completionRule: { kind: "all" }, markerRule: { kind: "all" }, members: [{ unit: "facility", facilityId: FAC }] },
    ] }];
    const o = await importArtifact(state, { version: v1, history: [v1], ledger: { ...ledger, [TRL]: { id: TRL, transitions: mint(v1) } }, facilities: fac("play-verified"), trails: trail, priv, kid: "k" });
    expect(o.ok).toBe(true);
    if (!o.ok) throw new Error("unreachable");
    expect(o.rosterVersionsApplied).toBe(2);
    const v1m = state.rosters.find((r) => r.version === 1)!.members;
    expect(v1m.find((m) => m.unit === "course")!.removedOn).toBe("2026-03-01"); // dropped in v2
    expect(v1m.find((m) => m.unit === "facility")!.removedOn).toBeNull(); // kept
    expect(state.rosters.find((r) => r.version === 2)!.members.every((m) => m.removedOn === null)).toBe(true);
  });
});

describe("AT 18 — the bounded re-score drain", () => {
  function setup(nPlays: number) {
    const state = makeFakeState();
    const importer = makeFakeImporterState(NOW);
    const withOwnership: WithOwnershipFn = async (actor: Actor, op: (repo: Repo) => Promise<unknown>) => op(makeFakeRepo(state, actor.uid)) as never;
    return { state, importer, withOwnership, nPlays };
  }
  async function seedPlays(state: ReturnType<typeof makeFakeState>, importer: ReturnType<typeof makeFakeImporterState>, n: number) {
    // one self_report play per date at crs_x1 (state.now = 2026-06-01)
    for (let i = 0; i < n; i++) {
      const d = `2026-05-${String(31 - i).padStart(2, "0")}`;
      const repo = makeFakeRepo(state, "user-a");
      const r = await handleEvidenceIntake({ source: "self_report", deviceId: FAKE_DEVICE_ID, facilityId: "fac_x", courseId: "crs_x1", localDate: d, catalogVersion: "20260520-a000001" }, repo);
      if (r.status !== "accepted") throw new Error("unreachable");
      importer.plays.push({ playId: r.play.id, userId: "user-a", facilityId: "fac_x", courseId: "crs_x1", playDate: d });
    }
    importer.plays.sort((a, b) => (a.playId < b.playId ? -1 : 1));
  }

  it("works at most `maxPlays` per pass, advances the cursor, and completes the course on the last page — then is a no-op", async () => {
    const { state, importer, withOwnership } = setup(5);
    await seedPlays(state, importer, 5);
    importer.backlog.push({ id: 1, courseId: "crs_x1", reason: "promotion", cursor: null, catalogVersionInt: 2, done: false });
    const repo = makeFakeImporterRepo(importer);

    const p1 = await drainRescoreBacklog(repo, withOwnership, 2);
    expect(p1).toMatchObject({ playsProcessed: 2, coursesCompleted: 0, failures: 0 });
    expect(importer.backlog[0]!.cursor?.playId).toBe(importer.plays[1]!.playId);
    const p2 = await drainRescoreBacklog(repo, withOwnership, 2);
    expect(p2.playsProcessed).toBe(2);
    const p3 = await drainRescoreBacklog(repo, withOwnership, 2);
    expect(p3).toMatchObject({ playsProcessed: 1, coursesCompleted: 1 });
    expect(importer.backlog[0]!.done).toBe(true);
    const p4 = await drainRescoreBacklog(repo, withOwnership, 2);
    expect(p4).toMatchObject({ backlogRows: 0, playsProcessed: 0 });
  });

  it("a failing play stops its course for this pass WITHOUT advancing past it (retried, never skipped)", async () => {
    const { state, importer } = setup(3);
    await seedPlays(state, importer, 3);
    importer.backlog.push({ id: 1, courseId: "crs_x1", reason: "promotion", cursor: null, catalogVersionInt: 2, done: false });
    let calls = 0;
    const flaky: WithOwnershipFn = async (actor, op) => {
      calls += 1;
      if (calls === 2) throw new Error("simulated transaction failure");
      return op(makeFakeRepo(state, actor.uid)) as never;
    };
    const r = await drainRescoreBacklog(makeFakeImporterRepo(importer), flaky, 10);
    expect(r).toMatchObject({ playsProcessed: 1, failures: 1, coursesCompleted: 0 });
    expect(importer.backlog[0]).toMatchObject({ cursor: { playId: importer.plays[0]!.playId }, done: false });
  });

  it("promotion rewrites the stored fix tier before re-scoring (the stub-era tier is what made the old score low)", async () => {
    const { state, importer, withOwnership } = setup(1);
    await seedPlays(state, importer, 1);
    const ev = [...state.evidence.values()][0]!;
    (ev.summary as Record<string, unknown>).fix = { verificationTier: "unverified" };
    state.courseTier.set("crs_x1", "play-verified");
    importer.backlog.push({ id: 1, courseId: "crs_x1", reason: "promotion", cursor: null, catalogVersionInt: 2, done: false });
    await drainRescoreBacklog(makeFakeImporterRepo(importer), withOwnership, 10);
    expect(((ev.summary as Record<string, unknown>).fix as Record<string, unknown>).verificationTier).toBe("play-verified");
  });

  it("a split backlog row labels the kept course's play a user pick (once per facility+date)", async () => {
    const { state, importer, withOwnership } = setup(1);
    await seedPlays(state, importer, 1);
    importer.backlog.push({ id: 1, courseId: "crs_x1", reason: "split", cursor: null, catalogVersionInt: 2, done: false });
    await drainRescoreBacklog(makeFakeImporterRepo(importer), withOwnership, 10);
    expect([...state.plays.values()][0]!.courseDisambiguatedBy).toBe("user");
  });
});

// ---------------------------------------------------------------------------
// A money-capable dwell round, stored the way live intake stores it (derived
// fixes + raw coordinates in integrity.fixCoords), then scored through the
// real finalizeScoringForKey.
// ---------------------------------------------------------------------------
import { finalizeScoringForKey, labelSplitPlayAsUserPick } from "../../functions/_shared/evidence/handler.js";
import { deriveFix } from "../../functions/_shared/evidence/derive-fix.js";

const LOCAL_DATE = "2026-05-31";
const NOON_MS = Date.parse("2026-05-31T17:00:00Z");

async function seedDwell(state: ReturnType<typeof makeFakeState>, uid: string, courseId: string, opts: { holes?: 9 | 18; withCoords?: boolean; apartMinutes?: number; vendor?: boolean } = {}) {
  const repo = makeFakeRepo(state, uid);
  const mk = (fixId: string, at: number) => deriveFix({ fix: { fixId, accuracyMeters: 10, capturedAt: at, simulated: false, foreground: true, fromApp: true }, resolvedFacilityId: "fac_x", localDate: LOCAL_DATE, match: { verificationTier: "play-verified", geometryKind: "polygon", insideBuffer: true }, consumedToken: { attestationGrade: "attested", challengeKind: "live" } });
  const sourceRef = `dwell-${state.nextId++}`;
  await repo.evidence.insertIdempotent({
    kind: "resolved", sourceRef, inputHash: `hash-${sourceRef}`, source: "foreground_dwell", facilityId: "fac_x", courseId, startedAt: null, endedAt: null, localDate: LOCAL_DATE,
    summary: { localDate: LOCAL_DATE, checkinFix: mk("fix_in", NOON_MS), checkoutFix: mk("fix_out", NOON_MS + (opts.apartMinutes ?? 180) * 60_000), apartMinutes: opts.apartMinutes ?? 180, holes: opts.holes ?? 18 },
    integrity: opts.withCoords === false ? {} : { fixCoords: { fix_in: { lat: 36.1467, lng: -86.7816 }, fix_out: { lat: 36.1468, lng: -86.7817 } } },
    cosignal: {}, attestationGrade: "attested", matcherVersion: null, catalogVersion: null, status: "accepted", deviceId: FAKE_DEVICE_ID,
  });
  if (opts.vendor) {
    // A mapped, sensor-provenance vendor round (weight 0.85, money-eligible)
    // beside the attested polygon dwell's presence fix: the combination that
    // makes this play money-TRUE when it is NOT a user pick.
    const ref = `vendor-${state.nextId++}`;
    await repo.evidence.insertIdempotent({
      kind: "resolved", sourceRef: ref, inputHash: `hash-${ref}`, source: "arccos" as never, facilityId: "fac_x", courseId, startedAt: null, endedAt: null, localDate: LOCAL_DATE,
      summary: { localDate: LOCAL_DATE, vendorCourseMapped: true, sensorProvenance: true },
      integrity: {}, cosignal: {}, attestationGrade: "unattestable", matcherVersion: null, catalogVersion: null, status: "accepted", deviceId: FAKE_DEVICE_ID,
    });
  }
  return finalizeScoringForKey(repo, "fac_x", courseId, LOCAL_DATE);
}

describe("NEW-4 (A2-01): a user pick contributes 0 to score_monetary on EVERY scoring path", () => {
  it("a polygon-attested, play-verified dwell is money-true as a geometry play, and money-false / score_monetary 0 once the play is a user pick (label -> re-score)", async () => {
    const state = makeFakeState();
    const before = await seedDwell(state, "user-a", "crs_x1", { vendor: true });
    expect(before.play.money).toBe(true); // the precondition: this fixture WOULD be money-true
    expect(before.play.scoreMonetary).toBeGreaterThanOrEqual(0.85);

    const repo = makeFakeRepo(state, "user-a");
    await labelSplitPlayAsUserPick(repo, { playId: before.play.id, facilityId: "fac_x", courseId: "crs_x1", playDate: LOCAL_DATE });
    const play = [...state.plays.values()][0]!;
    expect(play.courseDisambiguatedBy).toBe("user");
    expect(play.money).toBe(false);
    expect(play.scoreMonetary).toBe(0);
    // ...and a plain re-finalize (the promotion path, a batch retry) keeps it capped.
    const again = await finalizeScoringForKey(repo, "fac_x", "crs_x1", LOCAL_DATE);
    expect(again.play).toMatchObject({ money: false, scoreMonetary: 0 });
  });

  it("a NEW live submission landing on an already-user-picked play is scored with the cap too", async () => {
    const state = makeFakeState();
    const first = await seedDwell(state, "user-a", "crs_x1", { vendor: true });
    expect(first.play.money).toBe(true);
    const repo = makeFakeRepo(state, "user-a");
    await labelSplitPlayAsUserPick(repo, { playId: first.play.id, facilityId: "fac_x", courseId: "crs_x1", playDate: LOCAL_DATE });
    const r = await handleEvidenceIntake({ source: "foreground_checkin", deviceId: FAKE_DEVICE_ID, facilityId: "fac_x", courseId: "crs_x1", localDate: LOCAL_DATE, catalogVersion: "20260520-a000001", fix: { fixId: "fix_live", lat: 36.1467, lng: -86.7816, accuracyMeters: 10, capturedAt: NOON_MS, simulated: false, foreground: true, fromApp: true } }, repo);
    if (r.status !== "accepted") throw new Error("unreachable");
    expect(r.play.money).toBe(false);
    expect(r.play.scoreMonetary).toBe(0);
  });
});

describe("AT 18 — re-pick: fully re-derived, user plays only, exactly once, audited", () => {
  function splitWorld() {
    const state = makeFakeState();
    state.ledger.set("crs_s", { id: "crs_s", kind: "course", status: "verified", verifiedInVersion: 1, splitFrom: "crs_x1", tombstonedAt: null, mergedInto: null, firstCatalogVersion: 1 });
    state.courseFacility.set("crs_s", "fac_x");
    state.ledger.set("crs_other", { id: "crs_other", kind: "course", status: "verified", verifiedInVersion: 1, splitFrom: null, tombstonedAt: null, mergedInto: null, firstCatalogVersion: 1 });
    return state;
  }
  const args = { facilityId: "fac_x", playDate: LOCAL_DATE, fromCourseId: "crs_x1", toCourseId: "crs_s" };

  it("refuses a non-user pick, then (as a user pick) moves the play + evidence once; a second re-pick is refused; outside the family is refused", async () => {
    const state = splitWorld();
    const first = await seedDwell(state, "user-a", "crs_x1");
    const repo = makeFakeRepo(state, "user-a");
    expect(await repickUserPlay(repo, { ...args, toCourseId: "crs_other" })).toEqual({ ok: false, reason: "not_same_split_family" });
    expect(await repickUserPlay(repo, args)).toEqual({ ok: false, reason: "not_user_pick" }); // a geometry resolution is not the player's to move
    await labelSplitPlayAsUserPick(repo, { playId: first.play.id, facilityId: "fac_x", courseId: "crs_x1", playDate: LOCAL_DATE });
    expect(await repickUserPlay(repo, args)).toEqual({ ok: true });
    expect(state.plays.size).toBe(1); // moved, not duplicated
    expect([...state.plays.values()][0]).toMatchObject({ courseId: "crs_s", courseDisambiguatedBy: "user", money: false, scoreMonetary: 0 });
    // back again: refused — exactly ONE re-pick per play.
    expect(await repickUserPlay(repo, { ...args, fromCourseId: "crs_s", toCourseId: "crs_x1" })).toEqual({ ok: false, reason: "already_repicked" });
    expect(await repickUserPlay(repo, args)).toEqual({ ok: false, reason: "no_such_play" });
  });

  it("re-runs the matcher against the TARGET course from the stored raw coordinates (tier/geometry/insideBuffer), not the old course's", async () => {
    const state = splitWorld();
    // At the target the same coordinates are OUTSIDE its (radius, unverified) geometry.
    state.matches.set("crs_s", { verificationTier: "unverified", geometryKind: "radius", insideBuffer: false });
    const first = await seedDwell(state, "user-a", "crs_x1");
    const repo = makeFakeRepo(state, "user-a");
    await labelSplitPlayAsUserPick(repo, { playId: first.play.id, facilityId: "fac_x", courseId: "crs_x1", playDate: LOCAL_DATE });
    expect(await repickUserPlay(repo, args)).toEqual({ ok: true });
    const ev = [...state.evidence.values()][0]!;
    const summary = ev.summary as { checkinFix: Record<string, unknown>; checkoutFix: Record<string, unknown> };
    expect(summary.checkinFix).toMatchObject({ verificationTier: "unverified", geometryKind: "radius", insideBuffer: false });
    expect(summary.checkoutFix).toMatchObject({ verificationTier: "unverified", geometryKind: "radius", insideBuffer: false });
    expect(ev.courseId).toBe("crs_s");
  });

  it("recomputes the dwell round bar for the target: a 9-hole dwell moved to an 18-hole sibling gets the 18-hole bar", async () => {
    const state = splitWorld();
    state.courseHoles.set("crs_x1", 9);
    state.courseHoles.set("crs_s", 18);
    const first = await seedDwell(state, "user-a", "crs_x1", { holes: 9, apartMinutes: 100 });
    const repo = makeFakeRepo(state, "user-a");
    await labelSplitPlayAsUserPick(repo, { playId: first.play.id, facilityId: "fac_x", courseId: "crs_x1", playDate: LOCAL_DATE });
    expect(await repickUserPlay(repo, args)).toEqual({ ok: true });
    const ev = [...state.evidence.values()][0]!;
    expect((ev.summary as Record<string, unknown>).holes).toBe(18);
    // ...and a move the other way (a different world) would give 9.
  });

  it("fails closed (cannot_rederive, nothing moves) when a fix's raw coordinates were never stored", async () => {
    const state = splitWorld();
    const first = await seedDwell(state, "user-a", "crs_x1", { withCoords: false });
    const repo = makeFakeRepo(state, "user-a");
    await labelSplitPlayAsUserPick(repo, { playId: first.play.id, facilityId: "fac_x", courseId: "crs_x1", playDate: LOCAL_DATE });
    expect(await repickUserPlay(repo, args)).toEqual({ ok: false, reason: "cannot_rederive" });
    expect([...state.plays.values()][0]!.courseId).toBe("crs_x1");
    expect([...state.evidence.values()][0]!.courseId).toBe("crs_x1");
  });
});
