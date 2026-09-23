/**
 * Types for the P0-X1 Android Health Connect reader.
 *
 * X1 (build plan §10 P0) needs, per golf exercise session in the last N
 * days: start, end, dataOrigin (the source app's package name), and
 * whether a route is present plus its point count — enough to fill in the
 * X1 memo's per-source verdict (build plan §10 P0, row X1: "The memo
 * records a verdict per source").
 */

/** One golf `ExerciseSession` record, shaped for the X1 memo. */
export interface GolfSessionSummary {
  /** Health Connect record id (metadata.id). Empty string if the record
   * carried no id, which the API allows but this reader has not observed
   * in practice `[unverified — no device testing yet]`. */
  recordId: string;
  /** ISO 8601 session start time, as Health Connect returns it. */
  start: string;
  /** ISO 8601 session end time, as Health Connect returns it. */
  end: string;
  /** The source app's package name (metadata.dataOrigin), e.g.
   * "com.garmin.android.apps.connectmobile". This is exactly the signal
   * the §7.3 lane-5 source allow-list keys on. */
  dataOrigin: string;
  /** True only when Health Connect returned actual route points
   * (`ExerciseRouteResultType.DATA`). False for "no route recorded" and
   * for "route exists but needs a separate per-record consent grant"
   * (`CONSENT_REQUIRED`) — the latter is recorded separately in
   * `routeRequiresConsent` so a real device run can tell the two apart. */
  routePresent: boolean;
  /** Number of GPS points in the route, when `routePresent` is true.
   * Always 0 otherwise. */
  routePointCount: number;
  /** True when Health Connect reports the route needs its own consent
   * grant before points can be read (`ExerciseRouteResultType.
   * CONSENT_REQUIRED` — see `requestExerciseRoute()` in
   * `react-native-health-connect`'s README). This reader does not chase
   * that consent automatically; it only records that it would be
   * needed, which is itself useful evidence for the X1 memo. */
  routeRequiresConsent: boolean;
}

/** The full result written out as the X1 memo's evidence JSON. */
export interface GolfSessionReadResult {
  /** ISO 8601 timestamp of when this read ran. */
  generatedAt: string;
  /** How many days back the read window covered. */
  windowDays: number;
  /** `golfSessions.length`, kept alongside for a quick memo glance. */
  sessionCount: number;
  /** Every `ExerciseSession` record in the window whose `exerciseType`
   * was `ExerciseType.GOLF` (32). */
  sessions: GolfSessionSummary[];
}

/**
 * The minimal shape this module reads off a Health Connect
 * `ExerciseSessionRecordResult` (from `react-native-health-connect`).
 * Declared locally, narrowed to only the fields `shapeGolfSessions` uses,
 * so the pure shaping logic can be unit-tested with plain object literals
 * instead of importing (and mocking) the native module.
 */
/**
 * Result of the CONSENT_REQUIRED follow-up read (decision 0001, Addendum
 * D, R6): a session reported as `CONSENT_REQUIRED` counts as "route
 * present" only if a follow-up `requestExerciseRoute(recordId)` call
 * returns at least one point.
 */
export interface RouteFollowUpResult {
  /** True only if the follow-up read returned ≥ 1 point. */
  routePresent: boolean;
  /** Number of points the follow-up read returned. 0 when `routePresent`
   * is false. */
  routePointCount: number;
}

/**
 * The minimal shape this module reads off a
 * `requestExerciseRoute(recordId)` result (`Location[]` in
 * `react-native-health-connect`'s types). Declared locally, narrowed to
 * only the fields used, for the same reason as `RawExerciseSessionRecord`
 * below — keeps `shape.ts` free of any import from
 * `react-native-health-connect`.
 */
export interface RawExerciseRoutePoint {
  latitude: number;
  longitude: number;
  time: string;
}

export interface RawExerciseSessionRecord {
  metadata?: {
    id?: string;
    dataOrigin?: string;
  };
  startTime: string;
  endTime: string;
  exerciseType: number;
  exerciseRoute?: {
    /** `ExerciseRouteResultType`: 0 = DATA, 1 = NO_DATA, 2 =
     * CONSENT_REQUIRED. Typed as `number` here (not the library's enum)
     * so this file has zero import-time dependency on
     * `react-native-health-connect`. */
    type?: number;
    route: Array<{ latitude: number; longitude: number; time: string }>;
  };
}
