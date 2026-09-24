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
  requestExerciseRoute,
  requestPermission,
  SdkAvailabilityStatus,
} from "react-native-health-connect";
import type { RawExerciseSessionRecord, RouteFollowUpResult } from "./types.js";
import { shapeGolfSessions, shapeRouteFollowUp } from "./shape.js";
import type { GolfSessionReadResult } from "./types.js";

export type {
  GolfSessionReadResult,
  GolfSessionSummary,
  RouteFollowUpResult,
} from "./types.js";
export {
  shapeGolfSessions,
  shapeRouteFollowUp,
  EXERCISE_TYPE_GOLF,
} from "./shape.js";

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

/** Thrown when the user denies (or the manifest fails to declare) the
 * `read ExerciseSession` permission. `requestPermission`'s returned
 * granted-permissions list is the only reliable signal here (Android
 * does not otherwise surface a denial as an error) — see gate review S3:
 * previously this return value was ignored, so a silent no-grant would
 * fall through into `readRecords` and fail there with a less legible
 * error, or (worse) silently return no data. */
export class HealthConnectPermissionDeniedError extends Error {
  constructor() {
    super("Health Connect did not grant read access to ExerciseSession");
    this.name = "HealthConnectPermissionDeniedError";
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
  const granted = await requestPermission([
    { accessType: "read", recordType: "ExerciseSession" },
  ]);
  const hasExerciseRead = granted.some(
    (permission) =>
      permission.accessType === "read" &&
      permission.recordType === "ExerciseSession",
  );
  if (!hasExerciseRead) {
    throw new HealthConnectPermissionDeniedError();
  }
}

/**
 * Reads every `ExerciseSession` of type golf in the last `windowDays`
 * days and shapes them for the X1 memo. Call `ensureHealthConnectReady`
 * and `requestGolfReadPermission` first.
 */
export async function readGolfSessions(
  windowDays = 30,
): Promise<GolfSessionReadResult> {
  const now = new Date();
  const start = new Date(now.getTime() - windowDays * 24 * 60 * 60 * 1000);

  // readRecords paginates (a `pageToken` comes back whenever there are more
  // records than fit in one page). At X1's real scale (a handful of rounds
  // within `windowDays`) a single page is almost certainly enough, but
  // ignoring `pageToken` entirely would silently drop sessions on any device
  // with a longer Health Connect history — see gate review N5.
  const allRecords: RawExerciseSessionRecord[] = [];
  let pageToken: string | undefined;
  do {
    const { records, pageToken: nextPageToken } = await readRecords(
      "ExerciseSession",
      {
        timeRangeFilter: {
          operator: "between",
          startTime: start.toISOString(),
          endTime: now.toISOString(),
        },
        ascendingOrder: false,
        pageToken,
      },
    );
    // The library's ExerciseSessionRecordResult is a structural superset of
    // RawExerciseSessionRecord (see types.ts), so this is a safe narrowing
    // cast, not an unsound one — every field shape.ts reads is present.
    allRecords.push(...(records as unknown as RawExerciseSessionRecord[]));
    pageToken = nextPageToken;
  } while (pageToken);

  return shapeGolfSessions(allRecords, windowDays, now);
}

/**
 * CONSENT_REQUIRED follow-up read (decision 0001, Addendum D, R6): a
 * session Health Connect reported via `readGolfSessions` as
 * `routeRequiresConsent: true` counts as "route present" only if this
 * follow-up call to `requestExerciseRoute(recordId)` — the library's
 * per-record route-read consent flow, distinct from the up-front
 * `ExerciseSession` read permission requested by
 * `requestGolfReadPermission` — returns at least one point. Call this
 * (per session that came back with `routeRequiresConsent: true`) after
 * the device has had the chance to prompt for that per-record consent;
 * whether the platform actually surfaces that prompt here, versus
 * throwing or returning an empty array outright, is itself part of what
 * X1's real device run is meant to find out `[unverified — training
 * knowledge and this library's shipped .d.ts only, not a real device]`.
 *
 * @param recordId the `ExerciseSession` record id
 *   (`GolfSessionSummary.recordId`) to request the route for.
 */
export async function fetchConsentRequiredRouteFollowUp(
  recordId: string,
): Promise<RouteFollowUpResult> {
  const points = await requestExerciseRoute(recordId);
  return shapeRouteFollowUp(points);
}

/**
 * Runs the full X1 Android pass: ready-check, permission request, read,
 * shape — and returns the result already serialized as the JSON the X1
 * memo quotes (build plan §10 P0, row X1: "exports them as JSON for the
 * X1 memo").
 */
export async function runX1HealthConnectCheck(
  windowDays = 30,
): Promise<string> {
  await ensureHealthConnectReady();
  await requestGolfReadPermission();
  const result = await readGolfSessions(windowDays);
  return JSON.stringify(result, null, 2);
}
