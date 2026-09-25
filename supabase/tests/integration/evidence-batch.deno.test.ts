// supabase/tests/integration/evidence-batch.deno.test.ts
//
// P3c gate round 3, blocking MEDIUM 4 ("Batch: one failing item aborts
// the whole transaction") and the batch-mode half of blocking HIGH 1+2
// ("replay handling... single and batch"). Also P3d should-fix 1 ("score
// each play once per batch, after all items for that play").
//
// ⛔ REWRITE (P3d should-fix 1): this file used to hand-duplicate
// evidence-batch/index.ts's own two-phase orchestration in a local
// `runBatch` helper, because that orchestration lived INLINE in the
// `serve(...)` callback and had nothing importable to call directly. It
// is now extracted into `_shared/evidence/batch-handler.ts#
// handleEvidenceBatchIntake` (the SAME "pure, DI'd" shape every other
// endpoint in this round already uses) — every test below calls THAT
// function directly, so this suite exercises the actual production
// orchestration (including the should-fix 1 grouping/deferral logic),
// never a parallel reimplementation that could silently drift from it.
import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { createTestUser, createCourseWithPolygonAtFacX, freshUuid, makeActor, rawCount, FAC_X, CRS_X1 } from "./_helpers.ts";
import { hitRateLimitForActor, withOwnership } from "../../functions/_shared/privileged.ts";
import { handleEvidenceBatchIntake, RATE_LIMIT_PER_USER_DAY } from "../../functions/_shared/evidence/batch-handler.ts";
import { handleEvidenceIntake, type EvidenceIntakeResult } from "../../functions/_shared/evidence/handler.ts";
import { handleChallengeRequest } from "../../functions/_shared/checkin/challenge-handler.ts";
import { handleTokenRequest } from "../../functions/_shared/checkin/token-handler.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };

const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const digestHex = async (bytes: Uint8Array) => {
  const digest = await crypto.subtle.digest("SHA-256", bytes.slice().buffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
};

async function withFreshUser(label: string) {
  const uid = freshUuid();
  await createTestUser(uid, `batch-${label}-${uid.slice(0, 8)}`);
  return makeActor(uid);
}

function checkinBody(overrides: Record<string, unknown> = {}) {
  return {
    source: "foreground_checkin",
    deviceId: freshUuid(),
    facilityId: FAC_X,
    courseId: CRS_X1,
    localDate: "2026-06-01",
    catalogVersion: 1,
    fix: {
      fixId: `fix_${freshUuid()}`,
      lat: 36.1467,
      lng: -86.7816,
      accuracyMeters: 10,
      capturedAt: Date.parse("2026-06-01T12:00:00.000Z"),
      simulated: false,
      foreground: true,
      fromApp: true,
    },
    ...overrides,
  };
}

Deno.test("P3c gate round 3, blocking MEDIUM 4: one bad item among good ones — earlier AND later items still commit, only the bad one is reported failed", DT, async () => {
  const actor = await withFreshUser("bad-item");
  const items: unknown[] = [
    checkinBody(),
    { source: "foreground_checkin", deviceId: freshUuid() }, // structurally invalid: no facilityId/localDate/catalogVersion/fix
    checkinBody(),
  ];
  const { results } = await handleEvidenceBatchIntake(actor, items);

  assertEquals(results.length, 3);
  assertEquals(results[0].ok, true, "item 0 (good) must commit");
  assertEquals(results[1].ok, false, "item 1 (structurally invalid) must fail");
  assertEquals(results[2].ok, true, "item 2 (good) must STILL commit even though item 1 failed — a per-item savepoint, not a whole-batch rollback (P3c gate round 3, blocking MEDIUM 4)");

  if (results[0].ok) assertEquals((results[0].result as EvidenceIntakeResult).status, "accepted");
  if (results[2].ok) assertEquals((results[2].result as EvidenceIntakeResult).status, "accepted");
  if (!results[1].ok) assert(results[1].error !== undefined, "item 1's failure must carry a real error shape, not an opaque batch-wide abort");
});

Deno.test("P3c gate round 3, blocking MEDIUM 4: items after the per-user daily cap is reached are reported rate_limited, earlier items still commit", DT, async () => {
  const actor = await withFreshUser("cap-cross");
  // Pre-exhaust the REAL `evidence-batch:user` bucket (RATE_LIMIT_PER_USER_DAY
  // = 2,000) to 3 below its cap, directly — exercises the EXACT same
  // bucket key production code hits (batch-handler.ts's own hardcoded
  // literal, actor-scoped), without needing a 2,000+-item batch just to
  // reach it for real. `actor` is freshly minted (withFreshUser), so this
  // bucket starts at 0 and no other test can share or perturb it.
  for (let i = 0; i < RATE_LIMIT_PER_USER_DAY - 3; i++) {
    const r = await hitRateLimitForActor(actor, "evidence-batch:user", 86400, RATE_LIMIT_PER_USER_DAY);
    assert(r.ok, `pre-exhaustion hit ${i} should still be ok (below the real cap)`);
  }

  const items = Array.from({ length: 5 }, () => checkinBody());
  const { results } = await handleEvidenceBatchIntake(actor, items);

  const okCount = results.filter((r) => r.ok).length;
  assertEquals(okCount, 3, `expected exactly 3 items to succeed before the REAL ${RATE_LIMIT_PER_USER_DAY}/day cap — got ${okCount}`);
  for (let i = 3; i < items.length; i++) {
    assertEquals(results[i].ok, false, `item ${i} (past the cap) must be rejected`);
    assert(results[i].error?.code === "rate_limited", `item ${i} should be rate_limited, got ${JSON.stringify(results[i].error)}`);
  }
});

Deno.test("P3c gate round 3, blocking HIGH 1+2 (batch mode): an identical item submitted TWICE in one batch returns the SAME response for both — the second is a replay, not a double-score or a conflict", DT, async () => {
  const actor = await withFreshUser("batch-replay-plain");
  const body = checkinBody();
  const items = [body, body];
  const { results } = await handleEvidenceBatchIntake(actor, items);

  assertEquals(results[0].ok, true);
  assertEquals(results[1].ok, true);
  if (results[0].ok && results[1].ok) {
    const first = results[0].result as EvidenceIntakeResult;
    const second = results[1].result as EvidenceIntakeResult;
    assertEquals(first.status, "accepted");
    assertEquals(second.status, "accepted");
    if (first.status === "accepted" && second.status === "accepted") {
      assertEquals(second.evidenceId, first.evidenceId);
      assertEquals(second.replay, true, "the second (identical) item, in the SAME batch, must be reported as a replay");
    }
  }
});

Deno.test("P3c gate round 3, blocking HIGH 2 (batch mode): an identical TOKEN-BEARING item submitted TWICE in one batch returns the same success for both, without a double-consume error", DT, async () => {
  const actor = await withFreshUser("batch-token-replay");
  const courseId = `crs_batchreplay_${freshUuid().slice(0, 8)}`;
  await createCourseWithPolygonAtFacX(courseId);
  const deviceId = freshUuid();

  const challenges = await withOwnership(actor, (repo) => handleChallengeRequest({ deviceId, facilityId: FAC_X }, repo, randomBytes, digestHex));
  const token = await withOwnership(actor, (repo) =>
    handleTokenRequest({ challengeId: challenges[0].id, nonce: challenges[0].nonce, hardwareSupportsAttestation: false }, repo, digestHex),
  );
  const todayInFacilityTz = new Intl.DateTimeFormat("en-CA", { timeZone: "America/Chicago", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
  const body = checkinBody({
    deviceId,
    courseId,
    localDate: todayInFacilityTz,
    fix: { ...checkinBody().fix as object, checkinTokenJti: token.jti, capturedAt: Date.now() },
  });
  const items = [body, body];

  const { results } = await handleEvidenceBatchIntake(actor, items);

  assertEquals(results[0].ok, true, results[0].ok ? "" : JSON.stringify(results[0].error));
  assertEquals(results[1].ok, true, results[1].ok ? "" : JSON.stringify(results[1].error));
  if (results[0].ok && results[1].ok) {
    const first = results[0].result as EvidenceIntakeResult;
    const second = results[1].result as EvidenceIntakeResult;
    assertEquals(first.status, "accepted");
    assertEquals(second.status, "accepted");
    if (first.status === "accepted" && second.status === "accepted") {
      assertEquals(first.play.presenceSignal, true, "the FIRST (genuinely new) item must be a real co-signal");
      assertEquals(second.play.presenceSignal, true, "the SECOND (replayed) item must report the SAME outcome, not a fresh token-less rescore");
      assertEquals(second.evidenceId, first.evidenceId);
      assertEquals(second.replay, true);
    }
  }
});

// ─────────────────────────────────────────────────────────────────────────
// P3d should-fix 1: "score each play once per batch, after all items for
// that play, instead of once per item."
// ─────────────────────────────────────────────────────────────────────────
Deno.test("P3d should-fix 1: three items for the SAME play in one batch share ONE play id, and ALL THREE evidence rows are linked to it", DT, async () => {
  const actor = await withFreshUser("same-play-batch");
  const courseId = `crs_sameplay_${freshUuid().slice(0, 8)}`;
  await createCourseWithPolygonAtFacX(courseId);
  const localDate = "2026-06-05";
  const items = Array.from({ length: 3 }, () =>
    checkinBody({
      courseId,
      localDate,
      deviceId: freshUuid(),
      fix: { ...checkinBody().fix as object, fixId: `fix_${freshUuid()}`, capturedAt: Date.parse(`${localDate}T12:00:00.000Z`) },
    }),
  );

  const { results } = await handleEvidenceBatchIntake(actor, items);

  assertEquals(results.length, 3);
  const playIds = new Set<string>();
  const evidenceIds: string[] = [];
  for (const r of results) {
    assert(r.ok, `every item should succeed, got ${JSON.stringify(r.error)}`);
    const value = r.result as EvidenceIntakeResult;
    assertEquals(value.status, "accepted");
    if (value.status === "accepted") {
      playIds.add(value.play.id);
      evidenceIds.push(value.evidenceId);
    }
  }
  assertEquals(playIds.size, 1, "all three items must report the SAME play id — one shared play, not three separate ones");
  assertEquals(new Set(evidenceIds).size, 3, "each item must still have its OWN distinct evidence id");

  const linked = await rawCount(`select count(*)::int as n from app.play_evidence where evidence_id in ('${evidenceIds.join("','")}')`);
  assertEquals(linked, 3, "all three evidence rows must be linked to the (single, shared) play — proving the one scoring pass folded in every group member, not just the last one");
});

Deno.test("P3d should-fix 1: a group of size 1 (the common case) behaves exactly as an un-batched submission — unaffected by the grouping logic", DT, async () => {
  const actor = await withFreshUser("singleton-group");
  const items = [checkinBody()];
  const { results } = await handleEvidenceBatchIntake(actor, items);
  assertEquals(results.length, 1);
  assert(results[0].ok);
  const value = results[0].result as EvidenceIntakeResult;
  assertEquals(value.status, "accepted");
});

Deno.test("P3d should-fix 1: two DIFFERENT plays in one batch are scored independently, each into its own play", DT, async () => {
  const actor = await withFreshUser("two-plays-batch");
  const courseA = `crs_twoplaysA_${freshUuid().slice(0, 8)}`;
  const courseB = `crs_twoplaysB_${freshUuid().slice(0, 8)}`;
  await createCourseWithPolygonAtFacX(courseA);
  await createCourseWithPolygonAtFacX(courseB);
  const items = [
    checkinBody({ courseId: courseA, localDate: "2026-06-06", deviceId: freshUuid(), fix: { ...checkinBody().fix as object, fixId: `fix_${freshUuid()}`, capturedAt: Date.parse("2026-06-06T12:00:00.000Z") } }),
    checkinBody({ courseId: courseB, localDate: "2026-06-06", deviceId: freshUuid(), fix: { ...checkinBody().fix as object, fixId: `fix_${freshUuid()}`, capturedAt: Date.parse("2026-06-06T12:00:00.000Z") } }),
  ];
  const { results } = await handleEvidenceBatchIntake(actor, items);
  assert(results[0].ok && results[1].ok);
  const a = results[0].result as EvidenceIntakeResult;
  const b = results[1].result as EvidenceIntakeResult;
  assertEquals(a.status, "accepted");
  assertEquals(b.status, "accepted");
  if (a.status === "accepted" && b.status === "accepted") {
    assert(a.play.id !== b.play.id, "two different courses on the same date must produce two DIFFERENT plays, not be folded into one group");
  }
});

// ─────────────────────────────────────────────────────────────────────────
// P3d gate round 3, S2 (MEDIUM): "Batch phase A commits, then phase B
// (finalizeScoringForKey) fails or never runs → evidence is accepted with
// no app.play. A later retry through the live endpoint returns 500
// because the non-batch buildReplayResult finds no play row. Fix: when
// the play row is missing, the replay path calls the idempotent
// finalizeScoringForKey instead of throwing."
// ─────────────────────────────────────────────────────────────────────────
Deno.test("P3d gate round 3, S2: a live (non-batch) retry after a phase-A-only commit (evidence stored, no play yet) finalizes instead of 500ing", DT, async () => {
  const actor = await withFreshUser("phase-a-only-retry");
  const courseId = `crs_phaseaonly_${freshUuid().slice(0, 8)}`;
  await createCourseWithPolygonAtFacX(courseId);
  const body = checkinBody({ courseId, localDate: "2026-06-01" });

  // Simulate exactly the state an INTERRUPTED batch leaves behind: phase
  // A (per-item insert, deferScoring true) committed; phase B
  // (finalizeScoringForKey) never ran at all. Calling handleEvidenceIntake
  // directly with the SAME options evidence-batch/index.ts's own phase 2a
  // uses, and stopping there, reproduces this without needing to actually
  // kill a batch mid-flight.
  const deferred = await withOwnership(actor, (repo) => handleEvidenceIntake(body, repo, { deferScoring: true, batchMode: true }));
  assertEquals(deferred.status, "deferred");

  const beforePlays = await rawCount(`select count(*)::int as n from app.play where course_id = '${courseId}'`);
  assertEquals(beforePlays, 0, "precondition: no app.play row yet — phase A committed, phase B never ran");

  // The live retry: the client resubmits the SAME item through the
  // ordinary, non-batch POST /v1/evidence path (no deferScoring/batchMode
  // options) — findExisting matches the already-stored row by input_hash,
  // buildReplayResult finds no play row, and (this fix) finalizes now via
  // finalizeScoringForKey instead of throwing Errors.internal().
  const retried = await withOwnership(actor, (repo) => handleEvidenceIntake(body, repo));
  assertEquals(retried.status, "accepted", `expected the live retry to succeed (200), got ${JSON.stringify(retried)}`);
  if (retried.status === "accepted") {
    assert(retried.replay, "the retry is reported as a replay of the already-stored evidence row, not a fresh insert");
    assert(retried.play.id.length > 0, "a real play id is returned, not the empty-string facility-level placeholder");
  }

  const afterPlays = await rawCount(`select count(*)::int as n from app.play where course_id = '${courseId}'`);
  assertEquals(afterPlays, 1, "the live retry created exactly one app.play row for the group that was left unscored");
});
