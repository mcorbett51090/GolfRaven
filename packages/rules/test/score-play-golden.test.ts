/**
 * §4.5's 16 money golden fixtures (lines 1058-1080), asserted VERBATIM: the
 * plan's own table is "Columns 4-7 are assertions (set in v3, unchanged in
 * v4), which the P3 tests encode exactly (G2-04)." Column 3 (v1's single
 * score) is historical illustration only and is not asserted.
 *
 * Each `it` cites its row number and quotes the "Combination" column so a
 * diff against the plan is a one-line lookup.
 */
import { describe, expect, it } from "vitest";
import { scorePlay } from "../src/score-play.js";
import {
  PLAY_FACILITY_ID,
  PLAY_LOCAL_DATE,
  PLAY_LOCAL_DATE_MS,
  baseCtx,
  booking,
  checkin,
  connectIq,
  dwell,
  fileImport,
  ghin,
  goodFix,
  healthRoute,
  receipt,
  staffPresence,
  tokenState,
  vendorRound,
} from "./score-play-helpers.js";

describe("scorePlay — §4.5 money golden fixtures (P3 AT(4))", () => {
  it("#1: Approved receipt (no co-signal) + forged GPX file_import", () => {
    const result = scorePlay(
      [receipt({ status: "approved" }), fileImport({ matchedRoute: true })],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.88);
    expect(result.score_monetary).toBe(0.0);
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("#2: Relayed staff scan without co-signal + forged GPX", () => {
    const result = scorePlay(
      [staffPresence({}), fileImport({ matchedRoute: true })],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.88);
    expect(result.score_monetary).toBe(0.0);
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("#3: Staff scan without co-signal + Health route + dwell", () => {
    const result = scorePlay(
      [
        staffPresence({}),
        healthRoute({ insideRatio: 0.85 }),
        dwell({ apartMinutes: 95, holes: 18 }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.96);
    expect(result.score_monetary).toBe(0.5);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(false);
  });

  it("#4: P7 booking alone + its own prepay receipt (no co-signal): a correlated pair", () => {
    const result = scorePlay(
      [
        booking({ correlationId: "pair4" }),
        receipt({ status: "approved", correlationId: "pair4" }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.8); // max, not noisy-OR
    expect(result.score_monetary).toBe(0.7);
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("#5: Health route + Connect IQ trace + file import (device-only)", () => {
    const result = scorePlay(
      [
        healthRoute({ insideRatio: 0.9 }),
        connectIq({ variant: "route" }),
        fileImport({ matchedRoute: true }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.8); // device-GPS cap
    expect(result.score_monetary).toBe(0.0);
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("#6: P8 GHIN-posted round alone", () => {
    const result = scorePlay([ghin({})], baseCtx());
    expect(result.score_badge).toBe(0.4);
    expect(result.score_monetary).toBe(0.0);
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("#7: P8 Garmin sensor round alone, no app fix — no presence fact", () => {
    const result = scorePlay(
      [vendorRound("garmin", { vendorCourseMapped: true, sensorProvenance: true })],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.85);
    expect(result.score_monetary).toBe(0.85);
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false); // no presence fact, despite score >= MONEY_MIN
  });

  it("#8: Marker scratch code + its same-date co-signal check-in — corroboration cannot cross 0.50", () => {
    const result = scorePlay([checkin({ fix: goodFix() })], baseCtx({ purchases: [{ facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE }] }));
    expect(result.score_badge).toBe(0.3);
    expect(result.score_monetary).toBe(0.3);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(false);
  });

  it("#9: Approved receipt + co-signal from the QR session (no separate check-in)", () => {
    const result = scorePlay(
      [
        receipt({ status: "approved", coSignalFix: goodFix() }),
        checkin({ fix: goodFix() }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.86);
    expect(result.score_monetary).toBe(0.86);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(true);
  });

  it("#10: P7 booking + dwell on the booking date — resolves to the hard class only", () => {
    const result = scorePlay([booking({ presenceFix: goodFix() })], baseCtx());
    expect(result.score_badge).toBe(0.9);
    expect(result.score_monetary).toBe(0.9);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(true);
  });

  it("#11: Offline-code staff scan + a prefetched-challenge fix 6 min later", () => {
    const result = scorePlay(
      [
        staffPresence({
          scanAt: PLAY_LOCAL_DATE_MS,
          coSignalFix: goodFix({ challenge: "prefetched", capturedAt: PLAY_LOCAL_DATE_MS + 6 * 60_000 }),
        }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.95);
    expect(result.score_monetary).toBe(0.95);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(true);
  });

  it("#12: Offline-code staff scan, no fix within ±10 min", () => {
    const result = scorePlay([staffPresence({})], baseCtx());
    expect(result.score_badge).toBe(0.8);
    expect(result.score_monetary).toBe(0.0);
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("#13: Check-in whose attestation failed + approved receipt", () => {
    const result = scorePlay(
      [
        checkin({ fix: goodFix({ token: tokenState("failed") }) }),
        receipt({ status: "approved" }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.8);
    expect(result.score_monetary).toBe(0.0);
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("#14: `unattestable` check-in (0.30 × 0.6) + approved receipt — below 0.85", () => {
    const result = scorePlay(
      [
        checkin({ fix: goodFix({ token: tokenState("unattestable") }) }),
        receipt({ status: "approved", coSignalFix: goodFix({ token: tokenState("unattestable") }) }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.84);
    expect(result.score_monetary).toBe(0.84);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(false);
  });

  it("#15: Staff scan + `unattestable` co-signal — hard class, routed to held_review", () => {
    const result = scorePlay(
      [staffPresence({ coSignalFix: goodFix({ token: tokenState("unattestable") }) })],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.95);
    expect(result.score_monetary).toBe(0.95);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(true); // held_review is a downstream routing concern, out of scorePlay's scope
  });

  it("#16: 36-hole site, shared polygon, dwell, course-unit trail, user pick", () => {
    const result = scorePlay(
      [dwell({ courseDisambiguatedBy: "user", apartMinutes: 95, holes: 18 })],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.5);
    expect(result.score_monetary).toBe(0.0);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(false);
  });
});
