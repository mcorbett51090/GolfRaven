/**
 * Pure shaping logic for the P0-X1 Health Connect reader — no native
 * calls, so it is unit-testable without a device or emulator (see
 * `test/health-connect.test.ts`). `reader.ts` is the thin native-calling
 * wrapper around this.
 */
import type {
  GolfSessionReadResult,
  GolfSessionSummary,
  RawExerciseSessionRecord,
} from "./types.js";

/** Health Connect `ExerciseType.GOLF` (from `react-native-health-connect`'s
 * `constants.ts`), duplicated here as a literal so `shape.ts` stays free
 * of any import from the native package (see `types.ts`). */
export const EXERCISE_TYPE_GOLF = 32;

/** `ExerciseRouteResultType.DATA` / `.CONSENT_REQUIRED`, duplicated for
 * the same reason. */
const EXERCISE_ROUTE_RESULT_DATA = 0;
const EXERCISE_ROUTE_RESULT_CONSENT_REQUIRED = 2;

function shapeOneSession(record: RawExerciseSessionRecord): GolfSessionSummary {
  const route = record.exerciseRoute;
  const routePresent = Boolean(
    route && route.type === EXERCISE_ROUTE_RESULT_DATA && route.route.length > 0,
  );
  const routeRequiresConsent = Boolean(
    route && route.type === EXERCISE_ROUTE_RESULT_CONSENT_REQUIRED,
  );
  const routePointCount = routePresent && route ? route.route.length : 0;

  return {
    recordId: record.metadata?.id ?? "",
    start: record.startTime,
    end: record.endTime,
    dataOrigin: record.metadata?.dataOrigin ?? "unknown",
    routePresent,
    routePointCount,
    routeRequiresConsent,
  };
}

/**
 * Filters raw `ExerciseSession` records down to golf sessions and shapes
 * them for the X1 memo.
 *
 * @param records every `ExerciseSession` record Health Connect returned
 *   for the read window (already time-filtered by the caller).
 * @param windowDays how many days back the caller's read window covered
 *   (recorded on the result so the memo doesn't have to be told twice).
 * @param now injectable for tests; defaults to the real current time.
 */
export function shapeGolfSessions(
  records: readonly RawExerciseSessionRecord[],
  windowDays: number,
  now: Date = new Date(),
): GolfSessionReadResult {
  const sessions = records
    .filter((record) => record.exerciseType === EXERCISE_TYPE_GOLF)
    .map(shapeOneSession);

  return {
    generatedAt: now.toISOString(),
    windowDays,
    sessionCount: sessions.length,
    sessions,
  };
}
