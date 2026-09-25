// supabase/tests/integration/evidence-batch.deno.test.ts
//
// P3c gate round 3, blocking MEDIUM 4 ("Batch: one failing item aborts
// the whole transaction") and the batch-mode half of blocking HIGH 1+2
// ("replay handling... single and batch"). Exercises
// `privileged.ts#withOwnershipBatch` directly — the same real-transaction
// -plus-per-item-savepoint mechanism `evidence-batch/index.ts`'s own
// `Deno.serve` handler calls, without needing to stand up an actual HTTP
// server (this suite's established pattern throughout — see
// handlers.deno.test.ts's own header).
import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { createTestUser, createCourseWithPolygonAtFacX, freshUuid, makeActor, FAC_X, CRS_X1 } from "./_helpers.ts";
import { withOwnership, withOwnershipBatch } from "../../functions/_shared/privileged.ts";
import { handleEvidenceIntake, type EvidenceIntakeResult } from "../../functions/_shared/evidence/handler.ts";
import { handleChallengeRequest } from "../../functions/_shared/checkin/challenge-handler.ts";
import { handleTokenRequest } from "../../functions/_shared/checkin/token-handler.ts";
import { Errors, HttpError } from "../../functions/_shared/http.ts";
import type { Repo } from "../../functions/_shared/types.ts";

const DT = { sanitizeOps: false, sanitizeResources: false };

const RATE_LIMIT_PER_USER_DAY = 2000; // mirrors evidence-batch/index.ts's own constant

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

/** The SAME shape `evidence-batch/index.ts` itself passes to
 * `withOwnershipBatch` — rate-limit FIRST (its own separate transaction,
 * P3c gate round 3 blocking MEDIUM 3), then the real handler. Factored
 * out so every test below exercises the ACTUAL call shape, not a
 * simplified stand-in. */
function batchPerItem(items: unknown[], bucketKey: string, cap = RATE_LIMIT_PER_USER_DAY) {
  return async (repo: Repo, i: number): Promise<EvidenceIntakeResult> => {
    const rateLimit = await repo.rateLimit.hit(bucketKey, 86400, cap);
    if (!rateLimit.ok) throw Errors.tooManyRequests("evidence-batch daily rate limit exceeded");
    return handleEvidenceIntake(items[i], repo, { skipLiveRateLimit: true });
  };
}

Deno.test("P3c gate round 3, blocking MEDIUM 4: one bad item among good ones — earlier AND later items still commit, only the bad one is reported failed", DT, async () => {
  const actor = await withFreshUser("bad-item");
  const items: unknown[] = [
    checkinBody(),
    { source: "foreground_checkin", deviceId: freshUuid() }, // structurally invalid: no facilityId/localDate/catalogVersion/fix
    checkinBody(),
  ];
  const outcomes = await withOwnershipBatch(actor, items.length, batchPerItem(items, `bad-item-${freshUuid()}`));

  assertEquals(outcomes.length, 3);
  assertEquals(outcomes[0].ok, true, "item 0 (good) must commit");
  assertEquals(outcomes[1].ok, false, "item 1 (structurally invalid) must fail");
  assertEquals(outcomes[2].ok, true, "item 2 (good) must STILL commit even though item 1 failed — a per-item savepoint, not a whole-batch rollback (P3c gate round 3, blocking MEDIUM 4)");

  if (outcomes[0].ok) assertEquals((outcomes[0].value as EvidenceIntakeResult).status, "accepted");
  if (outcomes[2].ok) assertEquals((outcomes[2].value as EvidenceIntakeResult).status, "accepted");
  if (!outcomes[1].ok) assert(outcomes[1].error instanceof HttpError, "item 1's failure must be a real HttpError (bad_request), not an opaque batch-wide abort");
});

Deno.test("P3c gate round 3, blocking MEDIUM 4: items after the per-user daily cap is reached are reported rate_limited, earlier items still commit", DT, async () => {
  const actor = await withFreshUser("cap-cross");
  const CAP = 3; // small cap, purely for a fast test — exercises the SAME code path as the real 2,000/day cap
  const items = Array.from({ length: 5 }, () => checkinBody());
  const bucketKey = `cap-cross-${freshUuid()}`;

  const outcomes = await withOwnershipBatch(actor, items.length, batchPerItem(items, bucketKey, CAP));

  const okCount = outcomes.filter((o) => o.ok).length;
  assertEquals(okCount, CAP, `expected exactly ${CAP} items to succeed before the cap — got ${okCount}`);
  for (let i = CAP; i < items.length; i++) {
    assertEquals(outcomes[i].ok, false, `item ${i} (past the cap) must be rejected`);
    const outcome = outcomes[i];
    if (!outcome.ok) {
      assert(outcome.error instanceof HttpError && outcome.error.code === "rate_limited", `item ${i} should be rate_limited, got ${JSON.stringify(outcome.error)}`);
    }
  }
});

Deno.test("P3c gate round 3, blocking HIGH 1+2 (batch mode): an identical item submitted TWICE in one batch returns the SAME response for both — the second is a replay, not a double-score or a conflict", DT, async () => {
  const actor = await withFreshUser("batch-replay-plain");
  const body = checkinBody();
  const items = [body, body];
  const outcomes = await withOwnershipBatch(actor, items.length, batchPerItem(items, `batch-replay-plain-${freshUuid()}`));

  assertEquals(outcomes[0].ok, true);
  assertEquals(outcomes[1].ok, true);
  if (outcomes[0].ok && outcomes[1].ok) {
    const first = outcomes[0].value as EvidenceIntakeResult;
    const second = outcomes[1].value as EvidenceIntakeResult;
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

  const outcomes = await withOwnershipBatch(actor, items.length, batchPerItem(items, `batch-token-replay-${freshUuid()}`));

  assertEquals(outcomes[0].ok, true, outcomes[0].ok ? "" : String((outcomes[0] as { error: unknown }).error));
  assertEquals(outcomes[1].ok, true, outcomes[1].ok ? "" : String((outcomes[1] as { error: unknown }).error));
  if (outcomes[0].ok && outcomes[1].ok) {
    const first = outcomes[0].value as EvidenceIntakeResult;
    const second = outcomes[1].value as EvidenceIntakeResult;
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
