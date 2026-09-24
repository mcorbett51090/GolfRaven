/**
 * Fifth gate, H3: "There is no course anchor." `ScorePlayContext.playCourseId`
 * (`internal/classify.js`) — a row carrying its OWN `courseId` that
 * disagrees with the play's contributes 0; a facility-level row with no
 * `courseId` at all stays allowed. The gate's own required test: "2 plays
 * at a 36-hole facility and the same staff row whose courseId is one
 * course: only the matching play earns money."
 */
import { describe, expect, it } from "vitest";
import { classifyEvidenceRow } from "../src/internal/classify.js";
import { scorePlay, type Evidence, type ScorePlayContext } from "../src/score-play.js";
import { PLAY_FACILITY_ID, PLAY_LOCAL_DATE, PLAY_LOCAL_DATE_MS, goodFix } from "./score-play-helpers.js";

const COURSE_A = "course_front9";
const COURSE_B = "course_back9";

function ctxFor(playCourseId: string): ScorePlayContext {
  return { playFacilityId: PLAY_FACILITY_ID, playLocalDate: PLAY_LOCAL_DATE, playCourseId };
}

function staffRowAt(courseId: string): Evidence {
  return {
    id: "staff_1",
    facilityId: PLAY_FACILITY_ID,
    localDate: PLAY_LOCAL_DATE,
    courseId,
    source: "staff_presence",
    scanAt: PLAY_LOCAL_DATE_MS,
    coSignalFix: goodFix(),
  };
}

describe("H3: the gate's own required scenario — 2 plays at a 36-hole facility, one staff row, only the matching play earns money", () => {
  it("the SAME evidence row, scored against each play's own ctx.playCourseId, only pays out for the matching course", () => {
    const row = staffRowAt(COURSE_A);

    const playA = scorePlay([row], ctxFor(COURSE_A));
    const playB = scorePlay([row], ctxFor(COURSE_B));

    expect(playA.money).toBe(true);
    expect(playA.score_badge).toBe(0.95);

    expect(playB.money).toBe(false);
    expect(playB.score_badge).toBe(0);
    expect(playB.contributions.every((c) => !c.hard)).toBe(true);
  });
});

describe("H3: classifyEvidenceRow's own course anchor (defence in depth)", () => {
  it("a row with courseId=B contributes 0 against ctx.playCourseId=A", () => {
    const row = staffRowAt(COURSE_B);
    const c = classifyEvidenceRow(row, ctxFor(COURSE_A));
    expect(c.hard).toBe(false);
    expect(c.badgeWeight).toBe(0);
    expect(c.moneyEligible).toBe(false);
  });

  it("a row with courseId=A contributes fully against ctx.playCourseId=A", () => {
    const row = staffRowAt(COURSE_A);
    const c = classifyEvidenceRow(row, ctxFor(COURSE_A));
    expect(c.hard).toBe(true);
    expect(c.badgeWeight).toBe(0.95);
  });

  it("a facility-level row with NO courseId at all stays allowed regardless of ctx.playCourseId", () => {
    const row: Evidence = {
      id: "staff_2",
      facilityId: PLAY_FACILITY_ID,
      localDate: PLAY_LOCAL_DATE,
      // no courseId
      source: "staff_presence",
      scanAt: PLAY_LOCAL_DATE_MS,
      coSignalFix: goodFix(),
    };
    const c = classifyEvidenceRow(row, ctxFor(COURSE_A));
    expect(c.hard).toBe(true);
  });

  it("ctx.playCourseId undefined disables the check entirely (single-course facility / no course resolution wired yet)", () => {
    const row = staffRowAt(COURSE_B);
    const c = classifyEvidenceRow(row, { playFacilityId: PLAY_FACILITY_ID, playLocalDate: PLAY_LOCAL_DATE });
    expect(c.hard).toBe(true);
  });
});
