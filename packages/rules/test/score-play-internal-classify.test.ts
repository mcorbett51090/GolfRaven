/**
 * P3b fourth re-gate on commit 68d9139, blocking finding 1:
 * `classifyEvidenceRow` (formerly `classify`, exported directly from
 * `score-play.ts`) is no longer part of `@golfraven/rules`'s public
 * surface — it lives in `src/internal/classify.ts`, which `score-play.ts`
 * imports but never re-exports. This file:
 *   (a) proves the public package surface does NOT expose it;
 *   (b) unit-tests the classifier's own defence-in-depth row-level
 *       facility/date anchors DIRECTLY (bypassing `scorePlay`'s top-level
 *       filter entirely, by calling `classifyEvidenceRow` from its real
 *       import path) — for EVERY class the gate's failing examples named
 *       (`staff_presence`, vendor) plus the three this repo already had
 *       (booking, receipt, `foreground_checkin`), each constructed so the
 *       FIX stays genuinely on-date/on-facility and ONLY the ROW disagrees
 *       — isolating the row-level anchor specifically (a fix that is ALSO
 *       off-date/off-facility would let the fix-level check catch it
 *       first, proving nothing about the row-level one);
 *   (c) proves each of the three row-date anchors (booking, receipt,
 *       `foreground_checkin`) by applying its mutation for real.
 */
import { describe, expect, it } from "vitest";
import * as packageIndex from "../src/index.js";
import { classifyEvidenceRow } from "../src/internal/classify.js";
import type { Evidence } from "../src/score-play.js";
import {
  PLAY_FACILITY_ID,
  PLAY_LOCAL_DATE,
  baseCtx,
  booking,
  checkin,
  goodFix,
  staffPresence,
  vendorRound,
} from "./score-play-helpers.js";

const OFF_DATE = "2026-05-31";
const OTHER_FACILITY = "fac_other";

describe("public surface: classifyEvidenceRow (and its old name, classify) is NOT exported", () => {
  it("@golfraven/rules's package entry point has no 'classify' or 'classifyEvidenceRow' key", () => {
    expect("classify" in packageIndex).toBe(false);
    expect("classifyEvidenceRow" in packageIndex).toBe(false);
  });

  it("score-play.ts's own module has no 'classify' or 'classifyEvidenceRow' key either", async () => {
    const scorePlayModule = await import("../src/score-play.js");
    expect("classify" in scorePlayModule).toBe(false);
    expect("classifyEvidenceRow" in scorePlayModule).toBe(false);
  });
});

describe("defence in depth: classifyEvidenceRow checks the ROW's own facility/date directly, not just its fix's", () => {
  it("staff_presence at a DIFFERENT facility, with an otherwise-perfect same-facility fix, is never hard (gate's own failing case)", () => {
    // The fix itself reports the PLAY's facility (goodFix()'s default) —
    // only the ROW claims a different one. If this were reachable only
    // via the fix's own facility check, it would wrongly pass.
    const row = staffPresence({ facilityId: OTHER_FACILITY, localDate: PLAY_LOCAL_DATE, coSignalFix: goodFix() });
    const contribution = classifyEvidenceRow(row, baseCtx());
    expect(contribution.hard).toBe(false);
    expect(contribution.moneyEligible).toBe(false);
    expect(contribution.badgeWeight).toBe(0);
  });

  it("staff_presence on a DIFFERENT date, with an otherwise-perfect same-date fix, is never hard", () => {
    const row = staffPresence({ facilityId: PLAY_FACILITY_ID, localDate: OFF_DATE, coSignalFix: goodFix() });
    const contribution = classifyEvidenceRow(row, baseCtx());
    expect(contribution.hard).toBe(false);
    expect(contribution.badgeWeight).toBe(0);
  });

  it("a vendor round at a DIFFERENT facility is never money-eligible (gate's own failing case)", () => {
    const row = vendorRound("garmin", {
      facilityId: OTHER_FACILITY,
      localDate: PLAY_LOCAL_DATE,
      vendorCourseMapped: true,
      sensorProvenance: true,
    });
    const contribution = classifyEvidenceRow(row, baseCtx());
    expect(contribution.moneyEligible).toBe(false);
    expect(contribution.badgeWeight).toBe(0);
  });

  it("a vendor round on a DIFFERENT date is never money-eligible", () => {
    const row = vendorRound("garmin", {
      facilityId: PLAY_FACILITY_ID,
      localDate: OFF_DATE,
      vendorCourseMapped: true,
      sensorProvenance: true,
    });
    const contribution = classifyEvidenceRow(row, baseCtx());
    expect(contribution.moneyEligible).toBe(false);
  });

  it("a booking row on a DIFFERENT date, with an otherwise-perfect same-date presence fix, stays booking_alone at weight 0 (row rejected)", () => {
    const row = booking({ localDate: OFF_DATE, presenceFix: goodFix() }); // the fix itself IS on-date/on-facility
    const contribution = classifyEvidenceRow(row, baseCtx());
    expect(contribution.classId).toBe("booking_alone");
    expect(contribution.hard).toBe(false);
    expect(contribution.badgeWeight).toBe(0);
    expect(contribution.moneyEligible).toBe(false);
  });

  it("a receipt row on a DIFFERENT date, with an otherwise-perfect same-date co-signal, is never money-eligible", () => {
    const row: Evidence = {
      id: "r_row_off",
      facilityId: PLAY_FACILITY_ID,
      localDate: OFF_DATE,
      source: "receipt_green_fee",
      status: "approved",
      coSignalFix: goodFix(), // on-date, on-facility
    };
    const contribution = classifyEvidenceRow(row, baseCtx());
    expect(contribution.moneyEligible).toBe(false);
    expect(contribution.badgeWeight).toBe(0);
  });

  it("a foreground_checkin row on a DIFFERENT date, with an otherwise-perfect same-date fix, scores 0", () => {
    const row = checkin({ localDate: OFF_DATE, fix: goodFix() }); // the fix itself IS on-date/on-facility
    const contribution = classifyEvidenceRow(row, baseCtx());
    expect(contribution.badgeWeight).toBe(0);
  });
});
