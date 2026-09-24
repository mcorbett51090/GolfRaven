/**
 * §10 P3 AT(4) / §4.5's money-invariant property tests, over the
 * EXHAUSTIVE (not sampled) class × fix-attribute space named in the plan
 * (lines 976-983):
 *
 *   ≈16 class variants
 *   × grade {attested, unattestable, failed}, plus the two no-token
 *     inputs (5)
 *   × challenge {live, prefetched, none} (3)
 *   × {simulated, not} (2)
 *   × position {inside, the 50 m edge, outside, radius circle} (4)
 *   × time {same date, ±1 day across a tz boundary, the ±10 min edge} (3)
 *
 * = 16 × 5 × 3 × 2 × 4 × 3 = 5,760 generated cases, each asserted against
 * all three properties. Not every axis is meaningful for every class (e.g.
 * `ghin` carries no fix at all, so `grade`/`challenge`/`position`/`time`
 * are no-ops for it) — the full cross product is still iterated per the
 * task's "enumerate it fully; don't sample" instruction; a no-op axis just
 * means several of the 360 combinations for that class collapse to
 * identical evidence, which is harmless (the properties must still hold on
 * every one of them).
 */
import { describe, expect, it } from "vitest";
import {
  scorePlay,
  type ChallengeKind,
  type Evidence,
  type TokenState,
} from "../src/score-play.js";
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
  healthRoute,
  healthWorkout,
  receipt,
  selfReport,
  staffPresence,
  vendorRound,
} from "./score-play-helpers.js";
import { oracle } from "./score-play-oracle.js";
import type { AppFix } from "../src/score-play.js";

const GRADES = [
  "attested",
  "unattestable",
  "failed",
  "no_token_capable",
  "no_token_incapable",
] as const;
type GradeAxis = (typeof GRADES)[number];
const CHALLENGES: ChallengeKind[] = ["live", "prefetched", "none"];
const SIMULATED = [false, true];
const POSITIONS = ["inside", "edge", "outside", "radius"] as const;
type PositionAxis = (typeof POSITIONS)[number];
const TIMES = ["same", "tz_boundary", "minute_edge"] as const;
type TimeAxis = (typeof TIMES)[number];

function tokenFor(grade: GradeAxis): TokenState {
  switch (grade) {
    case "attested":
    case "unattestable":
    case "failed":
      return { present: true, grade };
    case "no_token_capable":
      return { present: false, hardwareSupportsAttestation: true }; // -> grades `failed` (G3-08)
    case "no_token_incapable":
      return { present: false, hardwareSupportsAttestation: false }; // -> grades `unattestable` (G3-08)
  }
}

/** Builds one `AppFix` for a given point in the 5-axis space. `position`
 * governs geometry (`inside`/`edge` are both within the polygon+50m
 * buffer — the buffer is inclusive at its boundary, §7.4's own `<=`
 * convention; `outside` fails containment; `radius` is matched to a
 * radius-fallback circle instead of a polygon, which §4.5 states can never
 * be a co-signal regardless of any other attribute). `time` governs
 * `localDate`/`capturedAt`: `same` sits inside every window this suite
 * exercises; `tz_boundary` moves the fix to the ADJACENT calendar date
 * (breaks every date-based window: presence_signal, receipt/booking
 * same-date co-signal, and — being 24h away — the ±10 min window too);
 * `minute_edge` stays on the same calendar date but sits exactly at the
 * ±10 min boundary (inclusive, per staff-scan window's own "±10 min"
 * wording).
 */
function buildFix(
  grade: GradeAxis,
  challenge: ChallengeKind,
  simulated: boolean,
  position: PositionAxis,
  time: TimeAxis,
): AppFix {
  const geometryKind = position === "radius" ? "radius" : "polygon";
  const insideBuffer =
    position === "inside" || position === "edge" || position === "radius";
  const accuracyMeters = position === "edge" ? 50 : 10;
  const verificationTier =
    position === "radius" ? "listed-verified" : "play-verified";
  let localDate = PLAY_LOCAL_DATE;
  let capturedAt = PLAY_LOCAL_DATE_MS;
  if (time === "tz_boundary") {
    localDate = "2026-06-02"; // the day after PLAY_LOCAL_DATE
    capturedAt = PLAY_LOCAL_DATE_MS + 24 * 60 * 60 * 1000;
  } else if (time === "minute_edge") {
    capturedAt = PLAY_LOCAL_DATE_MS + 10 * 60 * 1000; // exactly the ±10 min boundary
  }
  return {
    fromApp: true,
    simulated,
    foreground: true,
    challenge,
    token: tokenFor(grade),
    verificationTier,
    geometryKind,
    insideBuffer,
    accuracyMeters,
    capturedAt,
    localDate,
  };
}

interface GeneratedCase {
  classId: string;
  grade: GradeAxis;
  challenge: ChallengeKind;
  simulated: boolean;
  position: PositionAxis;
  time: TimeAxis;
  evidence: Evidence[];
  purchases?: { facilityId: string; localDate: string }[];
  /** True iff every row in `evidence` belongs to the device-GPS group by
   * construction — used for the "device-only score_monetary < 0.85"
   * property, which only applies to a device-only evidence set. */
  deviceOnly: boolean;
}

function buildCase(
  classId: string,
  grade: GradeAxis,
  challenge: ChallengeKind,
  simulated: boolean,
  position: PositionAxis,
  time: TimeAxis,
): GeneratedCase {
  const fix = buildFix(grade, challenge, simulated, position, time);
  const geometryKindFromPosition = position === "radius" ? "radius" : "polygon";
  const base = { classId, grade, challenge, simulated, position, time };

  switch (classId) {
    case "staff_presence_hard":
      return {
        ...base,
        evidence: [staffPresence({ coSignalFix: fix })],
        deviceOnly: false,
      };
    case "staff_presence_soft":
      return { ...base, evidence: [staffPresence({})], deviceOnly: false };
    case "vendor_sensor":
      return {
        ...base,
        evidence: [
          vendorRound("garmin", {
            vendorCourseMapped: true,
            sensorProvenance: true,
          }),
        ],
        deviceOnly: false,
      };
    case "self_posted":
      return { ...base, evidence: [ghin({})], deviceOnly: false };
    case "booking_hard":
      return {
        ...base,
        evidence: [booking({ presenceFix: fix })],
        deviceOnly: false,
      };
    case "booking_alone":
      return { ...base, evidence: [booking({})], deviceOnly: false };
    case "receipt_green_fee":
      return {
        ...base,
        evidence: [receipt({ status: "approved", coSignalFix: fix })],
        deviceOnly: false,
      };
    case "health_route":
      return {
        ...base,
        evidence: [
          healthRoute({
            simulated,
            geometryKind: geometryKindFromPosition,
            insideRatio:
              position === "inside" || position === "edge" ? 0.9 : 0.65,
          }),
        ],
        deviceOnly: true,
      };
    case "connect_iq_route":
      return {
        ...base,
        evidence: [
          connectIq({
            variant: "route",
            simulated,
            insidePolygon: position === "inside" || position === "edge",
            k4bPassed: true,
            durationMinutes: 95,
          }),
        ],
        deviceOnly: true,
      };
    case "connect_iq_checkin":
      return {
        ...base,
        evidence: [connectIq({ variant: "checkin", simulated })],
        deviceOnly: true,
      };
    case "foreground_dwell": {
      const checkoutFix: AppFix = {
        ...fix,
        capturedAt: fix.capturedAt + 95 * 60_000,
      };
      return {
        ...base,
        evidence: [
          dwell({ checkinFix: fix, checkoutFix, apartMinutes: 95, holes: 18 }),
        ],
        deviceOnly: true,
      };
    }
    case "file_import":
      return {
        ...base,
        evidence: [
          fileImport({
            matchedRoute: true,
            geometryKind: geometryKindFromPosition,
          }),
        ],
        deviceOnly: true,
      };
    case "foreground_checkin":
      return { ...base, evidence: [checkin({ fix })], deviceOnly: true };
    case "health_workout":
      return { ...base, evidence: [healthWorkout({})], deviceOnly: false };
    case "self_report":
      return { ...base, evidence: [selfReport({})], deviceOnly: false };
    case "purchase_corroboration":
      return {
        ...base,
        evidence: [],
        purchases: [
          {
            facilityId: PLAY_FACILITY_ID,
            localDate: time === "tz_boundary" ? "2026-06-02" : PLAY_LOCAL_DATE,
          },
        ],
        deviceOnly: false,
      };
    default:
      throw new Error(`unknown classId ${classId}`);
  }
}

const CLASS_IDS = [
  "staff_presence_hard",
  "staff_presence_soft",
  "vendor_sensor",
  "self_posted",
  "booking_hard",
  "booking_alone",
  "receipt_green_fee",
  "health_route",
  "connect_iq_route",
  "connect_iq_checkin",
  "foreground_dwell",
  "file_import",
  "foreground_checkin",
  "health_workout",
  "self_report",
  "purchase_corroboration",
];

function* generate(): Generator<GeneratedCase> {
  for (const classId of CLASS_IDS) {
    for (const grade of GRADES) {
      for (const challenge of CHALLENGES) {
        for (const simulated of SIMULATED) {
          for (const position of POSITIONS) {
            for (const time of TIMES) {
              yield buildCase(
                classId,
                grade,
                challenge,
                simulated,
                position,
                time,
              );
            }
          }
        }
      }
    }
  }
}

describe("scorePlay — §10 P3 AT(4) exhaustive money-invariant properties", () => {
  const cases = [...generate()];

  it("enumerates the full 16 × 5 × 3 × 2 × 4 × 3 = 5,760-case space", () => {
    expect(cases.length).toBe(16 * 5 * 3 * 2 * 4 * 3);
    expect(cases.length).toBe(5760);
  });

  it("money(E) ⇒ oracle(E), for every generated case (§10 P3 AT(4))", () => {
    const violations: string[] = [];
    for (const c of cases) {
      const ctx = baseCtx(c.purchases ? { purchases: c.purchases } : {});
      const result = scorePlay(c.evidence, ctx);
      if (result.money && !oracle(c.evidence, ctx)) {
        violations.push(
          `${c.classId} grade=${c.grade} challenge=${c.challenge} simulated=${c.simulated} position=${c.position} time=${c.time}`,
        );
      }
    }
    expect(violations).toEqual([]);
  });

  it("device-only ⇒ score_monetary < MONEY_MIN, for every generated case", () => {
    const violations: string[] = [];
    for (const c of cases) {
      if (!c.deviceOnly) continue;
      const ctx = baseCtx(c.purchases ? { purchases: c.purchases } : {});
      const result = scorePlay(c.evidence, ctx);
      if (result.score_monetary >= 0.85) {
        violations.push(
          `${c.classId}/${c.grade}/${c.challenge}/${c.simulated}/${c.position}/${c.time}`,
        );
      }
    }
    expect(violations).toEqual([]);
  });

  it("a class label without a qualifying fix ⇒ ¬money, for every generated case", () => {
    const violations: string[] = [];
    for (const c of cases) {
      const ctx = baseCtx(c.purchases ? { purchases: c.purchases } : {});
      if (oracle(c.evidence, ctx)) continue; // this case DOES carry a qualifying fix — not in scope for this property
      const result = scorePlay(c.evidence, ctx);
      if (result.money) {
        violations.push(
          `${c.classId}/${c.grade}/${c.challenge}/${c.simulated}/${c.position}/${c.time}`,
        );
      }
    }
    expect(violations).toEqual([]);
  });
});
