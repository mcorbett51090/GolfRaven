/**
 * Android Health Connect reader for the P0-X1 spike (build plan §10 P0,
 * row X1: "Android = a minimal Health Connect reader built in the P0
 * skeleton (0.5 pw, reused by P4)").
 *
 * This is the ANDROID SIDE of X1's harness. iOS uses Apple Health's own
 * `export.xml` export, no code needed (build plan §10 P0, row X1). This
 * file requests read permission for `ExerciseSession`, reads sessions in
 * the last N days, filters to `exerciseType === GOLF`, and shapes them
 * (via `shape.ts`) into the JSON the X1 memo quotes.
 *
 * ⚠️ NOT DEVICE-TESTED. Nothing in this file has run on a real Android
 * device or emulator with Health Connect installed — see
 * `apps/mobile/README.md` "Not device-tested" for exactly why and what
 * running it for real requires. Every claim below about what the Health
 * Connect API returns is `[unverified — training knowledge / library type
 * surface only]` until that run happens.
 */
import {
  getSdkStatus,
  initialize,
  readRecords,
  requestPermission,
  SdkAvailabilityStatus,
} from "react-native-health-connect";
import type { RawExerciseSessionRecord } from "./types.js";
import { shapeGolfSessions } from "./shape.js";
import type { GolfSessionReadResult } from "./types.js";

export type { GolfSessionReadResult, GolfSessionSummary } from "./types.js";
export { shapeGolfSessions, EXERCISE_TYPE_GOLF } from "./shape.js";

/** Thrown when Health Connect itself isn't usable on this device (not
 * installed, or the installed provider is too old). The X1 harness
 * treats this the same as "Android pass didn't run" (build plan §10 P0,
 * row X1's "not run — treated as fail" precedent for K4b applies here
 * too, by the same logic). */
export class HealthConnectUnavailableError extends Error {
  constructor(public readonly status: number) {
    super(`Health Connect is not available on this device (status ${status})`);
    this.name = "HealthConnectUnavailableError";
  }
}

/**
 * Confirms Health Connect is available and initialized. Call this once
 * before `requestGolfReadPermission` / `readGolfSessions`.
 *
 * @throws {HealthConnectUnavailableError} if the SDK isn't available.
 */
export async function ensureHealthConnectReady(): Promise<void> {
  const status = await getSdkStatus();
  if (status !== SdkAvailabilityStatus.SDK_AVAILABLE) {
    throw new HealthConnectUnavailableError(status);
  }
  await initialize();
}

/**
 * Requests read permission for `ExerciseSession`.
 *
 * Health Connect's route data is a separate case: reading the GPS points
 * of an existing session's route needs its own per-record consent flow
 * (`requestExerciseRoute(recordId)` in `react-native-health-connect`),
 * which the platform gates at the time you actually try to read the
 * route rather than as a permission you can request up front — there is
 * no static "read ExerciseRoute" permission object in this library's
 * types (only a write one, used for writing routes, not reading them).
 * `readGolfSessions` below reads whatever route data comes back attached
 * to each session record as-is (see `shape.ts`'s
 * `routePresent`/`routeRequiresConsent` split) rather than chasing that
 * consent automatically. `[unverified — training knowledge on the
 * Android platform permission model; confirmed only from this library's
 * shipped .d.ts, not from a real device]`
 */
export async function requestGolfReadPermission(): Promise<void> {
  await requestPermission([{ accessType: "read", recordType: "ExerciseSession" }]);
}

/**
 * Reads every `ExerciseSession` of type golf in the last `windowDays`
 * days and shapes them for the X1 memo. Call `ensureHealthConnectReady`
 * and `requestGolfReadPermission` first.
 */
export async function readGolfSessions(windowDays = 30): Promise<GolfSessionReadResult> {
  const now = new Date();
  const start = new Date(now.getTime() - windowDays * 24 * 60 * 60 * 1000);

  const { records } = await readRecords("ExerciseSession", {
    timeRangeFilter: {
      operator: "between",
      startTime: start.toISOString(),
      endTime: now.toISOString(),
    },
    ascendingOrder: false,
  });

  // The library's ExerciseSessionRecordResult is a structural superset of
  // RawExerciseSessionRecord (see types.ts), so this is a safe narrowing
  // cast, not an unsound one — every field shape.ts reads is present.
  return shapeGolfSessions(records as unknown as RawExerciseSessionRecord[], windowDays, now);
}

/**
 * Runs the full X1 Android pass: ready-check, permission request, read,
 * shape — and returns the result already serialized as the JSON the X1
 * memo quotes (build plan §10 P0, row X1: "exports them as JSON for the
 * X1 memo").
 */
export async function runX1HealthConnectCheck(windowDays = 30): Promise<string> {
  await ensureHealthConnectReady();
  await requestGolfReadPermission();
  const result = await readGolfSessions(windowDays);
  return JSON.stringify(result, null, 2);
}
