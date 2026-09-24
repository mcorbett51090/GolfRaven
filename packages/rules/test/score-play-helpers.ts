/**
 * Shared construction helpers for the `scorePlay` test suite (golden
 * fixtures, the exhaustive generator, and the oracle) — kept in its own,
 * non-`.test.ts` file so the oracle (`score-play-oracle.ts`) can share the
 * exact same `Evidence`/`AppFix` construction as the generator without
 * importing a `.test.ts` file.
 */
import type {
  AppFix,
  ChallengeKind,
  Evidence,
  ScorePlayContext,
  TokenState,
} from "../src/score-play.js";

export const PLAY_FACILITY_ID = "fac_test";
export const PLAY_LOCAL_DATE = "2026-06-01";
export const PLAY_LOCAL_DATE_MS = Date.parse("2026-06-01T12:00:00.000Z");

export function baseCtx(
  overrides: Partial<ScorePlayContext> = {},
): ScorePlayContext {
  return {
    playFacilityId: PLAY_FACILITY_ID,
    playLocalDate: PLAY_LOCAL_DATE,
    ...overrides,
  };
}

/** A fix that satisfies the §4.5 co-signal quality gate in full: from our
 * app, non-simulated, foreground, against a live challenge, `attested`,
 * inside a play-verified facility's polygon+50m buffer, captured on the
 * play's own facility-local date. Every golden fixture below starts from
 * this and overrides only what the fixture needs to differ. */
export function goodFix(overrides: Partial<AppFix> = {}): AppFix {
  return {
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
/** A fresh evidence-row id, unique within a test run (readable, stable
 * ordering — not used for anything semantic). */
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
  opts: EvidenceCommon & { presenceFix?: AppFix },
): Evidence {
  return {
    ...common("booking", opts),
    source: "booking",
    ...(opts.presenceFix !== undefined
      ? { presenceFix: opts.presenceFix }
      : {}),
  };
}

export function receipt(
  opts: EvidenceCommon & {
    status: "approved" | "pending";
    coSignalFix?: AppFix;
  },
): Evidence {
  return {
    ...common("receipt", opts),
    source: "receipt_green_fee",
    status: opts.status,
    ...(opts.coSignalFix !== undefined
      ? { coSignalFix: opts.coSignalFix }
      : {}),
  };
}

export function healthRoute(
  opts: EvidenceCommon & {
    sourceAllowListed?: boolean;
    insideRatio?: number;
    simulated?: boolean;
    geometryKind?: "polygon" | "radius";
  },
): Evidence {
  return {
    ...common("health_route", opts),
    source: "health_route",
    sourceAllowListed: opts.sourceAllowListed ?? true,
    insideRatio: opts.insideRatio ?? 0.9,
    simulated: opts.simulated ?? false,
    geometryKind: opts.geometryKind ?? "polygon",
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
  },
): Evidence {
  return {
    ...common("file_import", opts),
    source: "file_import",
    matchedRoute: opts.matchedRoute,
    ...(opts.geometryKind !== undefined
      ? { geometryKind: opts.geometryKind }
      : {}),
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
