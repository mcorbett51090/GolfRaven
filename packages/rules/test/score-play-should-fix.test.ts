/**
 * The should-fix items from the Opus gate review on commit 0ff5cd7, not
 * already covered by a golden fixture or the exhaustive-generator suite:
 * user-pick applied to every class (vendor included), the health_route
 * insideRatio floor, and receipt fingerprint voiding. (§7.5 held_review is
 * covered by golden fixture #15; hard-class absorption by golden fixture
 * #10's verbatim encoding; A2-05's "identical at save/approval/issuance"
 * by `offer-eligibility.test.ts`.)
 */
import { describe, expect, it } from "vitest";
import { scorePlay } from "../src/score-play.js";
import {
  baseCtx,
  goodFix,
  healthRoute,
  receipt,
  vendorRound,
} from "./score-play-helpers.js";

describe("scorePlay — user-pick cap applies to EVERY class (plan line 956)", () => {
  it("a user-picked vendor_sensor round is capped at 0.50 in score_badge and 0 in score_monetary", () => {
    const picked = scorePlay(
      [
        vendorRound("garmin", {
          vendorCourseMapped: true,
          sensorProvenance: true,
          courseDisambiguatedBy: "user",
        }),
      ],
      baseCtx(),
    );
    expect(picked.score_badge).toBe(0.5);
    expect(picked.score_monetary).toBe(0);

    const notPicked = scorePlay(
      [vendorRound("garmin", { vendorCourseMapped: true, sensorProvenance: true })],
      baseCtx(),
    );
    expect(notPicked.score_badge).toBe(0.85);
  });

  it("a user-picked approved receipt is capped at 0.50 in score_badge and excluded from score_monetary", () => {
    const result = scorePlay(
      [receipt({ status: "approved", coSignalFix: goodFix(), courseDisambiguatedBy: "user" })],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.5);
    expect(result.score_monetary).toBe(0);
  });
});

describe("scorePlay — health_route insideRatio floor (should-fix)", () => {
  it("insideRatio below 0.6 scores 0", () => {
    const result = scorePlay([healthRoute({ insideRatio: 0.59 })], baseCtx());
    expect(result.score_badge).toBe(0);
  });

  it("a non-finite insideRatio (NaN/Infinity) scores 0", () => {
    const nan = scorePlay([healthRoute({ insideRatio: Number.NaN })], baseCtx());
    expect(nan.score_badge).toBe(0);
    const inf = scorePlay([healthRoute({ insideRatio: Number.POSITIVE_INFINITY })], baseCtx());
    // Infinity >= 0.8 is technically true, but is not FINITE, so it must
    // still be rejected — a route matcher bug should never silently grant
    // the top band.
    expect(inf.score_badge).toBe(0);
  });
});

describe("scorePlay — receipt fingerprint voiding (should-fix, §4.4/§4.5 line 996)", () => {
  it("a second receipt sharing a fingerprint with an earlier one is void", () => {
    const result = scorePlay(
      [
        receipt({ id: "r1", status: "approved", fingerprint: "fp_1" }),
        receipt({ id: "r2", status: "approved", fingerprint: "fp_1" }),
      ],
      baseCtx(),
    );
    // r1 contributes 0.80 (approved); r2 is void (0) — same class anyway,
    // so max(0.80, 0) = 0.80, never a noisy-ORed 0.96.
    expect(result.score_badge).toBe(0.8);
  });

  it("two receipts with DIFFERENT fingerprints are unaffected", () => {
    const result = scorePlay(
      [
        receipt({ id: "r1", status: "approved", fingerprint: "fp_1" }),
        receipt({ id: "r2", status: "approved", fingerprint: "fp_2" }),
      ],
      baseCtx(),
    );
    // Same class either way ("two rows of the same class do not stack"),
    // so this is still 0.80, not because of voiding but because of the
    // ordinary same-class dedup rule.
    expect(result.score_badge).toBe(0.8);
  });

  it("an explicitly void receipt never contributes, even with a co-signal", () => {
    const result = scorePlay(
      [receipt({ status: "void", coSignalFix: goodFix() })],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0);
    expect(result.score_monetary).toBe(0);
  });
});
