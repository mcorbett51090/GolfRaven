/**
 * S2a (player lane of the course QR) — pins what the scorer does with the
 * `foreground_checkin` evidence row that `marker-scan` writes.
 *
 * The scan's fix is matched by `matchFacilityFix` (a geometry match against
 * the facility's play-verified polygon), so the row the scan writes carries
 * a fix that satisfies `isQualityCoSignalFix` at FACILITY level. It is
 * presence-qualifying and money-eligible (`foreground_checkin` 0.3 weight
 * plus whatever the round contributes), exactly as plan §9.2 sanctions. It
 * is facility-level evidence: the row carries no course anchor, so it
 * counts for a round on ANY course of the same facility on the same date.
 * This is the opposite of the evidence endpoint's own check-in, which does
 * no geometry match and so never qualifies (see the design doc's departure
 * 4 and its correction).
 */
import { describe, expect, it } from "vitest";
import {
  baseCtx,
  checkin,
  goodFix,
  vendorRound,
  scorePlayOrThrow,
} from "./score-play-helpers.js";

const OTHER_COURSE = "course_other_nine";

function garminRound() {
  return vendorRound("garmin", {
    courseId: OTHER_COURSE,
    vendorCourseMapped: true,
    sensorProvenance: true,
  });
}

describe("marker-scan presence: facility-level, money-eligible", () => {
  it("a marker-scan fix plus a round on another course of the same facility, same date, gives money", () => {
    const result = scorePlayOrThrow(
      [
        // What marker-scan writes: a facility-level foreground_checkin row
        // (no courseId) carrying a quality fix.
        checkin({ fix: goodFix() }),
        // The round: a Garmin sensor round (0.85 on its own, but no presence
        // fact: golden #7) anchored to the OTHER course of the
        // same facility, same local date.
        garminRound(),
      ],
      baseCtx({ playCourseId: OTHER_COURSE }),
    );
    expect(result.presence_signal).toBe(true);
    expect(result.score_monetary).toBeGreaterThanOrEqual(0.85);
    expect(result.money).toBe(true);
  });

  it("the same round without the marker-scan fix has no presence and no money", () => {
    const result = scorePlayOrThrow(
      [garminRound()],
      baseCtx({ playCourseId: OTHER_COURSE }),
    );
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("a marker-scan fix on another DATE gives no presence for this play", () => {
    const result = scorePlayOrThrow(
      [
        checkin({
          fix: goodFix({ localDate: "2026-05-31" }),
          localDate: "2026-05-31",
        }),
        garminRound(),
      ],
      baseCtx({ playCourseId: OTHER_COURSE }),
    );
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("a check-in with NO geometry match (the evidence endpoint's own) is not presence-qualifying", () => {
    const result = scorePlayOrThrow(
      [
        checkin({
          fix: goodFix({ geometryKind: "radius", insideBuffer: false }),
        }),
        garminRound(),
      ],
      baseCtx({ playCourseId: OTHER_COURSE }),
    );
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("a marker-scan fix at a DIFFERENT facility gives no presence", () => {
    const result = scorePlayOrThrow(
      [
        checkin({ fix: goodFix({ facilityId: "fac_elsewhere" }) }),
        garminRound(),
      ],
      baseCtx({ playCourseId: OTHER_COURSE }),
    );
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });
});
