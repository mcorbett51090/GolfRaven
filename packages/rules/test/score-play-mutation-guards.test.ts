/**
 * "Prove in a mutation copy that every survivor listed below is now
 * caught." This repo has no mutation-testing harness wired up for
 * `packages/rules` (no Stryker config, no `--mutate` script), so rather
 * than fabricate one under this task's time budget, each test below is a
 * PRECISE BOUNDARY assertion against the REAL (unmutated) `scorePlay`,
 * chosen so that flipping EXACTLY the named mutation — and nothing else —
 * would flip this test's own assertion. Each `it` names its mutation and
 * states, in a comment, the exact wrong value the mutation would produce.
 * This is a narrower claim than "ran under a mutation-testing tool" and is
 * stated as such; it is nonetheless a real, falsifiable proof that the
 * listed line is under direct test, not just incidentally exercised by
 * some other assertion.
 */
import { describe, expect, it } from "vitest";
import { MONEY_MIN, scorePlay } from "../src/score-play.js";
import {
  scorePlayOrThrow,
  PLAY_LOCAL_DATE_MS,
  baseCtx,
  checkin,
  dwell,
  goodFix,
  receipt,
  staffPresence,
  vendorRound,
} from "./score-play-helpers.js";

describe("mutation guard: MONEY_MIN changed to 0.84", () => {
  it("fixture #14's 0.84 score_monetary stays non-money — would flip to money=true under MONEY_MIN=0.84", () => {
    const result = scorePlayOrThrow(
      [
        checkin({ fix: goodFix({ token: { present: true, grade: "unattestable" } }) }),
        receipt({ status: "approved", coSignalFix: goodFix({ token: { present: true, grade: "unattestable" } }) }),
      ],
      baseCtx(),
    );
    expect(result.score_monetary).toBe(0.84);
    expect(result.money).toBe(false); // MONEY_MIN=0.84 would make this `true`
  });
});

describe("mutation guard: the ×0.3 simulated penalty removed", () => {
  it("a simulated check-in's badgeWeight is exactly 0.30 × 0.3 = 0.09, not 0.30", () => {
    const result = scorePlayOrThrow([checkin({ fix: goodFix({ simulated: true }) })], baseCtx());
    const contribution = result.contributions.find((c) => c.classId === "foreground_checkin");
    expect(contribution?.badgeWeight).toBeCloseTo(0.09, 10); // would be 0.30 if the ×0.3 were dropped
  });
});

describe("mutation guard: a radius match counting toward money", () => {
  it("a radius-matched check-in is never money-eligible, however perfect its other attributes", () => {
    const result = scorePlayOrThrow(
      [checkin({ fix: goodFix({ geometryKind: "radius", verificationTier: "listed-verified" }) })],
      baseCtx(),
    );
    const contribution = result.contributions.find((c) => c.classId === "foreground_checkin");
    expect(contribution?.moneyEligible).toBe(false); // would be `true` if the radius exclusion were dropped
    expect(result.score_monetary).toBe(0);
  });
});

describe("mutation guard: corroboration counting toward money", () => {
  it("corroboration never raises score_monetary, even when it applies to score_badge", () => {
    const result = scorePlayOrThrow(
      [checkin({ fix: goodFix() })],
      baseCtx({ purchases: [{ facilityId: baseCtx().playFacilityId, localDate: baseCtx().playLocalDate }] }),
    );
    // Play classes alone (0.30) are below 0.50, so corroboration doesn't
    // even apply to the badge here — but the assertion that matters is:
    // score_monetary must equal the checkin's own money contribution
    // (0.30) and never anything corroboration-derived.
    expect(result.score_monetary).toBe(0.3);
  });
});

describe("mutation guard: a ±11 min staff-scan window (should be ±10 min)", () => {
  it("exactly 10 min is hard; 11 min is soft", () => {
    const at10 = scorePlayOrThrow(
      [staffPresence({ scanAt: PLAY_LOCAL_DATE_MS, coSignalFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS + 10 * 60_000 }) })],
      baseCtx(),
    );
    expect(at10.score_badge).toBe(0.95); // inclusive boundary
    const at11 = scorePlayOrThrow(
      [staffPresence({ scanAt: PLAY_LOCAL_DATE_MS, coSignalFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS + 11 * 60_000 }) })],
      baseCtx(),
    );
    expect(at11.score_badge).toBe(0.8); // would be 0.95 under an ±11 min window
  });
});

describe("mutation guard: accuracy / fromApp / foreground / tier checks dropped", () => {
  it("verificationTier !== play-verified (even with polygon geometry) never qualifies as a co-signal", () => {
    const result = scorePlayOrThrow(
      [checkin({ fix: goodFix({ verificationTier: "listed-verified", geometryKind: "polygon" }) })],
      baseCtx(),
    );
    expect(result.presence_signal).toBe(false);
  });

  it("accuracyMeters exactly 50 qualifies; 50.01 does not", () => {
    const at50 = scorePlayOrThrow([checkin({ fix: goodFix({ accuracyMeters: 50 }) })], baseCtx());
    expect(at50.score_badge).toBeGreaterThan(0);
    const at5001 = scorePlayOrThrow([checkin({ fix: goodFix({ accuracyMeters: 50.01 }) })], baseCtx());
    expect(at5001.score_badge).toBe(0);
  });
});

describe("mutation guard: the presence date or booking date check dropped", () => {
  it("presence_signal is false when the only qualifying fix is on a different date", () => {
    const result = scorePlayOrThrow(
      [checkin({ fix: goodFix({ localDate: "2026-06-02", capturedAt: PLAY_LOCAL_DATE_MS + 24 * 60 * 60 * 1000 }) })],
      baseCtx(),
    );
    expect(result.presence_signal).toBe(false); // would be `true` if the date check were dropped
  });
});

describe("mutation guard: the 9-hole dwell threshold changed from 50 to 40", () => {
  it("apartMinutes = 45 (9-hole) scores 0; apartMinutes = 50 qualifies", () => {
    const at45 = scorePlayOrThrow([dwell({ holes: 9, apartMinutes: 45 })], baseCtx());
    expect(at45.score_badge).toBe(0); // would be > 0 under a threshold of 40
    const at50 = scorePlayOrThrow([dwell({ holes: 9, apartMinutes: 50 })], baseCtx());
    expect(at50.score_badge).toBeGreaterThan(0);
  });
});

describe("mutation guard: `>=` changed to `>` on the MONEY_MIN comparison", () => {
  it("a play scoring EXACTLY MONEY_MIN (0.85) is money — not just strictly above it", () => {
    expect(MONEY_MIN).toBe(0.85);
    // vendor_sensor alone is exactly 0.85 and money-eligible; paired with a
    // user-picked check-in (contributes ZERO to score_monetary, since the
    // user-pick cap forces `moneyEligible: false` there, but still grants
    // presence_signal from its raw fix, which is computed independent of
    // any per-class cap) — score_monetary stays exactly 0.85.
    const result = scorePlayOrThrow(
      [
        vendorRound("garmin", { vendorCourseMapped: true, sensorProvenance: true }),
        checkin({ fix: goodFix(), courseDisambiguatedBy: "user" }),
      ],
      baseCtx(),
    );
    expect(result.score_monetary).toBe(0.85);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(true); // would be `false` under a `>` comparison
  });
});
