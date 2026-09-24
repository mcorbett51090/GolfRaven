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
 *   × time {same date, ±1 day across a tz boundary, the ±10 min edge,
 *     ±10 min + 1 ms (just OUTSIDE the window, test-adequacy item)} (4)
 *
 * = 16 × 5 × 3 × 2 × 4 × 4 = 7,680 generated cases, each asserted against
 * properties 1 (money⇒oracle) and 2 (device-only score_monetary < 0.85).
 * Not every axis is meaningful for every class (e.g. `ghin` carries no fix
 * at all, so `grade`/`challenge`/`position`/`time` are no-ops for it) — the
 * full cross product is still iterated per "enumerate it fully; don't
 * sample"; a no-op axis just means several combinations for that class
 * collapse to identical evidence, which is harmless.
 *
 * Property 3 ("a class label without a qualifying fix ⇒ ¬money") is
 * DELIBERATELY not computed as this generator's contrapositive (that would
 * just be property 1 read backwards, over the same fix-bearing evidence) —
 * see the dedicated "class label, no fix at all" block below, which
 * asserts `money === false` directly for the seven class shapes that
 * structurally carry no `AppFix` at all (as opposed to a low-quality one).
 *
 * `geometryKind`/`verificationTier` are decoupled per-fix (a `radius`-kind
 * fix at an otherwise `play-verified` facility must still fail on
 * `geometryKind` alone) — see `buildFix`.
 */
import { describe, expect, it } from "vitest";
import {
  type ChallengeKind,
  type Evidence,
  type TokenState,
} from "../src/score-play.js";
import {
  scorePlayOrThrow,
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
const TIMES = ["same", "tz_boundary", "minute_edge", "minute_edge_plus_1ms"] as const;
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
let nextGenFixId = 0;

function buildFix(
  grade: GradeAxis,
  challenge: ChallengeKind,
  simulated: boolean,
  position: PositionAxis,
  time: TimeAxis,
): AppFix {
  // Decoupled (test-adequacy item): `geometryKind`/`insideBuffer` come from
  // `position`; `verificationTier` is fixed at `play-verified` REGARDLESS
  // of geometry kind — a `radius`-kind fix at an otherwise play-verified
  // facility must still fail the co-signal gate on `geometryKind` alone,
  // proving the two checks are independent or `deriveGroups`/`classify`
  // would wrongly pass a radius fix whose facility happens to be verified.
  const geometryKind = position === "radius" ? "radius" : "polygon";
  const insideBuffer =
    position === "inside" || position === "edge" || position === "radius";
  const accuracyMeters = position === "edge" ? 50 : 10;
  const verificationTier = "play-verified";
  let localDate = PLAY_LOCAL_DATE;
  let capturedAt = PLAY_LOCAL_DATE_MS;
  if (time === "tz_boundary") {
    localDate = "2026-06-02"; // the day after PLAY_LOCAL_DATE
    capturedAt = PLAY_LOCAL_DATE_MS + 24 * 60 * 60 * 1000;
  } else if (time === "minute_edge") {
    capturedAt = PLAY_LOCAL_DATE_MS + 10 * 60 * 1000; // exactly the ±10 min boundary (inclusive)
  } else if (time === "minute_edge_plus_1ms") {
    capturedAt = PLAY_LOCAL_DATE_MS + 10 * 60 * 1000 + 1; // one ms OUTSIDE the window
  }
  nextGenFixId += 1;
  return {
    fixId: `gen_fix_${nextGenFixId}`,
    facilityId: PLAY_FACILITY_ID,
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
      // A distinct `fixId` from the check-in fix — they are two DIFFERENT
      // physical captures (open/close), never the same fix reused.
      const checkoutFix: AppFix = {
        ...fix,
        fixId: `${fix.fixId}_close`,
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

  it("enumerates the full 16 × 5 × 3 × 2 × 4 × 4 = 7,680-case space", () => {
    expect(cases.length).toBe(16 * 5 * 3 * 2 * 4 * 4);
    expect(cases.length).toBe(7680);
  });

  it("money(E) ⇒ oracle(E), for every generated case (§10 P3 AT(4))", () => {
    const violations: string[] = [];
    for (const c of cases) {
      const ctx = baseCtx(c.purchases ? { purchases: c.purchases } : {});
      const result = scorePlayOrThrow(c.evidence, ctx);
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
      const result = scorePlayOrThrow(c.evidence, ctx);
      if (result.score_monetary >= 0.85) {
        violations.push(`${c.classId}/${c.grade}/${c.challenge}/${c.simulated}/${c.position}/${c.time}`);
      }
    }
    expect(violations).toEqual([]);
  });

  // Retained as a secondary cross-check (the contrapositive of property 1
  // over the SAME fix-bearing generator), but the primary, literal reading
  // of "a class label without a qualifying fix ⇒ ¬money" lives in the
  // "class label, no fix at all" block below — this one alone would be
  // indistinguishable from property 1 (test-adequacy: "make property 3
  // genuinely different from property 1").
  it("[contrapositive cross-check] no oracle-qualifying fix anywhere in the case ⇒ ¬money", () => {
    const violations: string[] = [];
    for (const c of cases) {
      const ctx = baseCtx(c.purchases ? { purchases: c.purchases } : {});
      if (oracle(c.evidence, ctx)) continue;
      const result = scorePlayOrThrow(c.evidence, ctx);
      if (result.money) {
        violations.push(`${c.classId}/${c.grade}/${c.challenge}/${c.simulated}/${c.position}/${c.time}`);
      }
    }
    expect(violations).toEqual([]);
  });
});

/* ------------------------------------------------------------------ */
/* Property 3, literally: a class label present with NO fix at all      */
/* ------------------------------------------------------------------ */

describe("scorePlay — a class label present with NO fix at all ⇒ ¬money (property 3, literal)", () => {
  // Every one of these classes/variants structurally carries ZERO
  // `AppFix` objects — not a poor-quality one, none at all — yet several
  // of them (`vendor_sensor`, `booking_alone`, an approved receipt with no
  // `coSignalFix`) still reach a `score_monetary >= MONEY_MIN` on weight
  // alone (fixture #7 is exactly this). `money` must still be `false` in
  // every case, because `presence_signal` is computed only from fixes.
  const noFixCases: { label: string; evidence: Evidence[] }[] = [
    { label: "vendor_sensor alone (fixture #7 shape)", evidence: [vendorRound("garmin", { vendorCourseMapped: true, sensorProvenance: true })] },
    { label: "ghin alone", evidence: [ghin({})] },
    { label: "booking_alone (no presenceFix field at all)", evidence: [booking({})] },
    { label: "staff_presence_soft (no coSignalFix field at all)", evidence: [staffPresence({})] },
    { label: "approved receipt, no coSignalFix field at all", evidence: [receipt({ status: "approved" })] },
    { label: "health_workout alone", evidence: [healthWorkout({})] },
    { label: "self_report alone", evidence: [selfReport({})] },
  ];

  for (const { label, evidence } of noFixCases) {
    it(`${label} ⇒ money === false`, () => {
      const result = scorePlayOrThrow(evidence, baseCtx());
      expect(result.presence_signal).toBe(false);
      expect(result.money).toBe(false);
    });
  }
});

/* ------------------------------------------------------------------ */
/* Blocking findings 3 & 4 — targeted regressions                       */
/* ------------------------------------------------------------------ */

describe("scorePlay — facility and date anchoring (blocking findings 3, 4)", () => {
  it("finding 3: staff_presence with a co-signal at a DIFFERENT facility ⇒ no money", () => {
    const otherFacility = "fac_other";
    const result = scorePlayOrThrow(
      [
        staffPresence({
          facilityId: otherFacility,
          coSignalFix: goodFix({ facilityId: otherFacility }),
        }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0);
    expect(result.score_monetary).toBe(0);
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("finding 3: a co-signal fix whose OWN facilityId disagrees with the row's facility is never a co-signal", () => {
    // The row is at the play's facility, but the embedded fix claims a
    // DIFFERENT facility — must not be trusted either way.
    const result = scorePlayOrThrow([staffPresence({ coSignalFix: goodFix({ facilityId: "fac_other" }) })], baseCtx());
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("finding 4: a booking plus a fix on D+1, with a separate check-in on D ⇒ 0.79, no money", () => {
    const result = scorePlayOrThrow(
      [
        booking({ presenceFix: goodFix({ localDate: "2026-06-02", capturedAt: PLAY_LOCAL_DATE_MS + 24 * 60 * 60 * 1000 }) }),
        checkin({ fix: goodFix() }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.79);
    expect(result.score_monetary).toBe(0.79);
    expect(result.money).toBe(false);
  });
});

/* ------------------------------------------------------------------ */
/* Test adequacy: fromApp / foreground / accuracy > 50 / NaN            */
/* ------------------------------------------------------------------ */

describe("scorePlay — device-row fix-quality gate (finding 2 / test adequacy)", () => {
  it("fromApp: false on a check-in's fix ⇒ excluded entirely (weight 0, no money)", () => {
    const result = scorePlayOrThrow([checkin({ fix: goodFix({ fromApp: false }) })], baseCtx());
    expect(result.score_badge).toBe(0);
    expect(result.money).toBe(false);
  });

  it("foreground: false on a check-in's fix ⇒ excluded entirely", () => {
    const result = scorePlayOrThrow([checkin({ fix: goodFix({ foreground: false }) })], baseCtx());
    expect(result.score_badge).toBe(0);
    expect(result.money).toBe(false);
  });

  it("accuracyMeters > 50 on a check-in's fix ⇒ excluded entirely", () => {
    const result = scorePlayOrThrow([checkin({ fix: goodFix({ accuracyMeters: 51 }) })], baseCtx());
    expect(result.score_badge).toBe(0);
    expect(result.money).toBe(false);
  });

  it("accuracyMeters negative or NaN ⇒ never qualifies", () => {
    const neg = scorePlayOrThrow([checkin({ fix: goodFix({ accuracyMeters: -1 }) })], baseCtx());
    expect(neg.score_badge).toBe(0);
    const nan = scorePlayOrThrow([checkin({ fix: goodFix({ accuracyMeters: Number.NaN }) })], baseCtx());
    expect(nan.score_badge).toBe(0);
  });

  it("a dwell with a `none` challenge on either fix is fully ineligible, not ×0.6 (plan line 1000)", () => {
    const result = scorePlayOrThrow(
      [dwell({ checkinFix: goodFix({ challenge: "none" }), checkoutFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS + 95 * 60_000 }) })],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0);
  });

  it("foreground_dwell apartMinutes = NaN ⇒ never qualifies (the !(x >= threshold) fix)", () => {
    const result = scorePlayOrThrow([dwell({ apartMinutes: Number.NaN })], baseCtx());
    expect(result.score_badge).toBe(0);
  });
});

/* ------------------------------------------------------------------ */
/* Test adequacy: multi-row pairs across the device-only classes        */
/* ------------------------------------------------------------------ */

describe("scorePlay — device-only class pairs never reach MONEY_MIN (noisy-OR cap)", () => {
  const deviceOnlyBuilders: { label: string; build: () => Evidence }[] = [
    { label: "health_route", build: () => healthRoute({ insideRatio: 0.95 }) },
    { label: "connect_iq_route", build: () => connectIq({ variant: "route" }) },
    { label: "connect_iq_checkin", build: () => connectIq({ variant: "checkin" }) },
    { label: "foreground_dwell", build: () => dwell({}) },
    { label: "file_import", build: () => fileImport({ matchedRoute: true }) },
    { label: "foreground_checkin", build: () => checkin({}) },
  ];

  for (let a = 0; a < deviceOnlyBuilders.length; a += 1) {
    for (let b = a + 1; b < deviceOnlyBuilders.length; b += 1) {
      const A = deviceOnlyBuilders[a]!;
      const B = deviceOnlyBuilders[b]!;
      it(`${A.label} + ${B.label} ⇒ score_monetary < 0.85`, () => {
        const result = scorePlayOrThrow([A.build(), B.build()], baseCtx());
        expect(result.score_monetary).toBeLessThan(0.85);
        expect(result.money).toBe(false);
      });
    }
  }
});

/* ------------------------------------------------------------------ */
/* Test adequacy (third re-gate): vendor/sensor + device-row two-row     */
/* sets — the exact PAIR SHAPE finding 2 (b95bbfc third re-gate) was     */
/* found in: a money-eligible-but-presence-less class (vendor_sensor)    */
/* combined with a presence-only device row whose fix varies, including  */
/* a user-picked variant. Held at grade × position (10 = 5×2 combos,     */
/* userPicked × 2), challenge/simulated/time fixed at their "good"       */
/* value — the single-row generator above already exhausts THOSE axes    */
/* independently; this block's whole point is the CROSS-CLASS pairing,   */
/* not re-covering axes the single-row space already covers.             */
/* ------------------------------------------------------------------ */

describe("scorePlay — vendor + device-row two-row sets (money(E) ⇒ oracle(E), including user-picked)", () => {
  for (const grade of GRADES) {
    for (const position of POSITIONS) {
      for (const userPicked of [false, true]) {
        it(`garmin + checkin(grade=${grade}, position=${position}, userPicked=${userPicked})`, () => {
          const fix = buildFix(grade, "live", false, position, "same");
          const evidence: Evidence[] = [
            vendorRound("garmin", { vendorCourseMapped: true, sensorProvenance: true }),
            checkin({ ...(userPicked ? { courseDisambiguatedBy: "user" as const } : {}), fix }),
          ];
          const ctx = baseCtx();
          const result = scorePlayOrThrow(evidence, ctx);
          if (result.money) {
            expect(oracle(evidence, ctx)).toBe(true);
          }
        });
      }
    }
  }
});
