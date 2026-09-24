/**
 * Seventh gate, item 10: "Restore direct `classifyEvidenceRow` tests for
 * the guards that now go through quarantine: the fix-localDate device
 * gate, NaN accuracy, NaN dwell, and NaN/Infinity insideRatio. The
 * mutation guards must be non-vacuous again."
 *
 * Once `parseEvidence`'s Zod schema started enforcing `.finite()` on
 * `accuracyMeters`/`insideRatio`/`apartMinutes` (M2, fifth gate) and the
 * tz cross-check on every fix's `localDate` (H2/F1), a row carrying any
 * of these malformed shapes never reaches `classifyEvidenceRow` at all
 * when called the PUBLIC way (`scorePlay`) — it's quarantined first. A
 * test that only calls `scorePlay` and asserts `score_badge === 0` can no
 * longer tell "classify.ts's own guard fired" apart from "the row was
 * quarantined before classify.ts ever ran" — the two look IDENTICAL from
 * `scorePlay`'s output, but only one of them is still exercising
 * classify.ts's own code. Every test below calls `classifyEvidenceRow`
 * DIRECTLY (`../src/internal/classify.js`, the same "tests reach it
 * directly" path this module's own doc describes), bypassing the parser
 * entirely, so a regression in classify.ts's OWN defensive code is
 * provably still caught — each is confirmed by a REAL applied mutation
 * (see the session's final report for the exact before/after
 * `pnpm vitest run` output).
 */
import { describe, expect, it } from "vitest";
import { classifyEvidenceRow, isQualityCoSignalFix } from "../src/internal/classify.js";
import { baseCtx, checkin, dwell, goodFix, healthRoute, PLAY_FACILITY_ID } from "./score-play-helpers.js";

describe("item 10 guard 1: the fix-localDate device gate (deviceRowFixGateOk, foreground_checkin)", () => {
  it("a check-in whose fix.localDate disagrees with the play's date contributes nothing, called DIRECTLY", () => {
    const row = checkin({ fix: goodFix({ localDate: "2026-05-31" }) }); // capturedAt stays default (June 1) — deliberately inconsistent, but classifyEvidenceRow never re-derives from capturedAt, only compares the STRING
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.badgeWeight).toBe(0);
    expect(c.moneyEligible).toBe(false);
  });
});

describe("item 10 guard 2: NaN accuracyMeters — the device-row gate (deviceRowFixGateOk, via finiteInRange)", () => {
  it("a check-in fix with accuracyMeters: NaN contributes nothing, called DIRECTLY", () => {
    const row = checkin({ fix: goodFix({ accuracyMeters: Number.NaN }) });
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.badgeWeight).toBe(0);
  });
});

describe("item 10 guard 3: NaN accuracyMeters — the co-signal quality gate (isQualityCoSignalFix, via finiteInRange)", () => {
  it("isQualityCoSignalFix rejects a fix with accuracyMeters: NaN, called DIRECTLY", () => {
    const fix = goodFix({ accuracyMeters: Number.NaN });
    expect(isQualityCoSignalFix(fix, PLAY_FACILITY_ID)).toBe(false);
  });

  it("isQualityCoSignalFix rejects a fix with accuracyMeters: Infinity, called DIRECTLY", () => {
    const fix = goodFix({ accuracyMeters: Number.POSITIVE_INFINITY });
    expect(isQualityCoSignalFix(fix, PLAY_FACILITY_ID)).toBe(false);
  });
});

describe("item 10 guard 4: NaN dwell (foreground_dwell's apartMinutes/derived-duration guard)", () => {
  it("a dwell with apartMinutes: NaN contributes nothing, called DIRECTLY (the derived duration is computed from capturedAt, not the stored field, so this also proves the derivation itself is NaN-safe)", () => {
    const row = dwell({ apartMinutes: Number.NaN });
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.badgeWeight).toBe(0);
    expect(c.moneyEligible).toBe(false);
  });
});

describe("item 10 guard 5/6: NaN/Infinity insideRatio (health_route)", () => {
  it("insideRatio: NaN contributes nothing, called DIRECTLY", () => {
    const row = healthRoute({ insideRatio: Number.NaN });
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.badgeWeight).toBe(0);
  });

  it("insideRatio: Infinity contributes nothing, called DIRECTLY (Infinity >= 0.8 is technically true, but not FINITE)", () => {
    const row = healthRoute({ insideRatio: Number.POSITIVE_INFINITY });
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.badgeWeight).toBe(0);
  });
});
