/**
 * Shared construction helpers for the `scorePlay` test suite (golden
 * fixtures, the exhaustive generator, and the oracle) — kept in its own,
 * non-`.test.ts` file so the oracle (`score-play-oracle.ts`) can share the
 * exact same `Evidence`/`AppFix` construction as the generator without
 * importing a `.test.ts` file.
 */
import {
  scorePlay,
  type AppFix,
  type ChallengeKind,
  type Evidence,
  type ScorePlayContext,
  type ScorePlayOutcome,
  type ScorePlayResult,
  type TokenState,
} from "../src/score-play.js";

export const PLAY_FACILITY_ID = "fac_test";
export const PLAY_LOCAL_DATE = "2026-06-01";
export const PLAY_LOCAL_DATE_MS = Date.parse("2026-06-01T12:00:00.000Z");
export const PLAY_COURSE_ID = "course_test";
/** F1 (sixth gate): a REAL IANA Area/Location timezone — Iceland observes
 * NO daylight saving and sits at UTC+0 year-round, so every existing
 * fixture's UTC-epoch arithmetic (`PLAY_LOCAL_DATE_MS` and friends) stays
 * numerically consistent under this tz with zero changes, while still
 * exercising the REAL `facilityTz` validator (this is not a magic
 * "UTC"-equivalent bypass string — it's a genuine, `Intl.supportedValuesOf`
 * -listed zone). */
export const PLAY_FACILITY_TZ = "Atlantic/Reykjavik";

export function baseCtx(
  overrides: Partial<ScorePlayContext> = {},
): ScorePlayContext {
  return {
    playFacilityId: PLAY_FACILITY_ID,
    playLocalDate: PLAY_LOCAL_DATE,
    playCourseId: PLAY_COURSE_ID,
    facilityTz: PLAY_FACILITY_TZ,
    ...overrides,
  };
}

/** Test-only convenience: unwraps a SUCCESSFUL `scorePlay` outcome,
 * throwing (with every reason) if it was instead a parse failure. The vast
 * majority of this suite's fixtures are meant to parse cleanly and score —
 * a test that specifically wants to exercise a parse FAILURE calls the
 * real `scorePlay` directly and checks `.ok` itself (see
 * `parse-evidence.test.ts`/`score-play-h1-allowlist.test.ts`), rather than
 * using this wrapper. */
export function scorePlayOrThrow(evidence: Evidence[], ctx: ScorePlayContext): ScorePlayResult {
  const result: ScorePlayOutcome = scorePlay(evidence, ctx);
  if (!result.ok) {
    throw new Error(`scorePlay unexpectedly failed to parse: ${result.reasons.join("; ")}`);
  }
  return result;
}

let nextFixId = 0;

/** A fix that satisfies the §4.5 co-signal quality gate in full: from our
 * app, non-simulated, foreground, against a live challenge, `attested`,
 * at the play's own facility, inside a play-verified facility's
 * polygon+50m buffer, captured on the play's own facility-local date.
 * `fixId` defaults to a fresh, unique id every call — pass one explicitly
 * (or reuse a fix object) when a test needs two rows to provably reuse the
 * SAME physical fix (finding 1(b)). Every golden fixture below starts from
 * this and overrides only what the fixture needs to differ. */
export function goodFix(overrides: Partial<AppFix> = {}): AppFix {
  nextFixId += 1;
  return {
    fixId: `fix_${nextFixId}`,
    facilityId: PLAY_FACILITY_ID,
    fromApp: true,
    simulated: false,
    foreground: true,
    challenge: "live",
    token: { present: true, grade: "attested" },
    verificationTier: "play-verified",
    geometryKind: "polygon",
    insideBuffer: true,
    accuracyMeters: 10,
    capturedAt: PLAY_LOCAL_DATE_MS,
    localDate: PLAY_LOCAL_DATE,
    ...overrides,
  };
}

export function tokenState(
  grade: "attested" | "unattestable" | "failed",
): TokenState {
  return { present: true, grade };
}

export function noToken(hardwareSupportsAttestation: boolean): TokenState {
  return { present: false, hardwareSupportsAttestation };
}

let nextId = 0;
/** A fresh evidence-row (or fix) id, unique within a test run (readable,
 * stable ordering — not used for anything semantic). */
export function evId(label: string): string {
  nextId += 1;
  return `${label}_${nextId}`;
}

interface EvidenceCommon {
  id?: string;
  facilityId?: string;
  localDate?: string;
  courseId?: string;
  courseDisambiguatedBy?: Evidence["courseDisambiguatedBy"];
  correlationId?: string;
}

function common(
  label: string,
  overrides: EvidenceCommon = {},
): Required<Pick<Evidence, "id" | "facilityId" | "localDate">> &
  Pick<Evidence, "courseId" | "courseDisambiguatedBy" | "correlationId"> {
  return {
    id: overrides.id ?? evId(label),
    facilityId: overrides.facilityId ?? PLAY_FACILITY_ID,
    localDate: overrides.localDate ?? PLAY_LOCAL_DATE,
    ...(overrides.courseId !== undefined
      ? { courseId: overrides.courseId }
      : {}),
    ...(overrides.courseDisambiguatedBy !== undefined
      ? { courseDisambiguatedBy: overrides.courseDisambiguatedBy }
      : {}),
    ...(overrides.correlationId !== undefined
      ? { correlationId: overrides.correlationId }
      : {}),
  };
}

export function staffPresence(
  opts: EvidenceCommon & { scanAt?: number; coSignalFix?: AppFix },
): Evidence {
  return {
    ...common("staff", opts),
    source: "staff_presence",
    scanAt: opts.scanAt ?? PLAY_LOCAL_DATE_MS,
    ...(opts.coSignalFix !== undefined
      ? { coSignalFix: opts.coSignalFix }
      : {}),
  };
}

export function vendorRound(
  source: "arccos" | "garmin",
  opts: EvidenceCommon & {
    vendorCourseMapped: boolean;
    sensorProvenance: boolean;
  },
): Evidence {
  return {
    ...common(source, opts),
    source,
    vendorCourseMapped: opts.vendorCourseMapped,
    sensorProvenance: opts.sensorProvenance,
  };
}

export function ghin(opts: EvidenceCommon = {}): Evidence {
  return { ...common("ghin", opts), source: "ghin" };
}

export function booking(
  opts: EvidenceCommon & { presenceFix?: AppFix; paymentRef?: string },
): Evidence {
  return {
    ...common("booking", opts),
    source: "booking",
    ...(opts.presenceFix !== undefined
      ? { presenceFix: opts.presenceFix }
      : {}),
    ...(opts.paymentRef !== undefined ? { paymentRef: opts.paymentRef } : {}),
  };
}

export function receipt(
  opts: EvidenceCommon & {
    status: "approved" | "pending" | "void";
    coSignalFix?: AppFix;
    paymentRef?: string;
    fingerprint?: string;
  },
): Evidence {
  return {
    ...common("receipt", opts),
    source: "receipt_green_fee",
    status: opts.status,
    ...(opts.coSignalFix !== undefined
      ? { coSignalFix: opts.coSignalFix }
      : {}),
    ...(opts.paymentRef !== undefined ? { paymentRef: opts.paymentRef } : {}),
    ...(opts.fingerprint !== undefined
      ? { fingerprint: opts.fingerprint }
      : {}),
  };
}

export function healthRoute(
  opts: EvidenceCommon & {
    sourceAllowListed?: boolean;
    insideRatio?: number;
    simulated?: boolean;
    geometryKind?: "polygon" | "radius";
    startedAt?: number;
  },
): Evidence {
  return {
    ...common("health_route", opts),
    source: "health_route",
    sourceAllowListed: opts.sourceAllowListed ?? true,
    insideRatio: opts.insideRatio ?? 0.9,
    simulated: opts.simulated ?? false,
    geometryKind: opts.geometryKind ?? "polygon",
    ...(opts.startedAt !== undefined ? { startedAt: opts.startedAt } : {}),
  };
}

export function connectIq(
  opts: EvidenceCommon & {
    variant: "route" | "checkin";
    k4bPassed?: boolean;
    insidePolygon?: boolean;
    durationMinutes?: number;
    simulated?: boolean;
  },
): Evidence {
  return {
    ...common("connect_iq", opts),
    source: "connect_iq",
    variant: opts.variant,
    k4bPassed: opts.k4bPassed ?? true,
    insidePolygon: opts.insidePolygon ?? true,
    durationMinutes: opts.durationMinutes ?? 95,
    simulated: opts.simulated ?? false,
  };
}

export function dwell(
  opts: EvidenceCommon & {
    checkinFix?: AppFix;
    checkoutFix?: AppFix;
    apartMinutes?: number;
    holes?: 9 | 18;
  },
): Evidence {
  const holes = opts.holes ?? 18;
  const apart = opts.apartMinutes ?? (holes === 9 ? 55 : 95);
  return {
    ...common("dwell", opts),
    source: "foreground_dwell",
    checkinFix: opts.checkinFix ?? goodFix(),
    checkoutFix:
      opts.checkoutFix ??
      goodFix({ capturedAt: PLAY_LOCAL_DATE_MS + apart * 60_000 }),
    apartMinutes: apart,
    holes,
  };
}

export function fileImport(
  opts: EvidenceCommon & {
    matchedRoute: boolean;
    geometryKind?: "polygon" | "radius";
    startedAt?: number;
  },
): Evidence {
  return {
    ...common("file_import", opts),
    source: "file_import",
    matchedRoute: opts.matchedRoute,
    ...(opts.geometryKind !== undefined
      ? { geometryKind: opts.geometryKind }
      : {}),
    ...(opts.startedAt !== undefined ? { startedAt: opts.startedAt } : {}),
  };
}

export function checkin(opts: EvidenceCommon & { fix?: AppFix }): Evidence {
  return {
    ...common("checkin", opts),
    source: "foreground_checkin",
    fix: opts.fix ?? goodFix(),
  };
}

export function healthWorkout(opts: EvidenceCommon = {}): Evidence {
  return { ...common("health_workout", opts), source: "health_workout" };
}

export function selfReport(opts: EvidenceCommon = {}): Evidence {
  return { ...common("self_report", opts), source: "self_report" };
}

export const CHALLENGES: ChallengeKind[] = ["live", "prefetched", "none"];
