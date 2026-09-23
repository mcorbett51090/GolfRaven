import { describe, expect, it } from "vitest";
import {
  EXERCISE_TYPE_GOLF,
  shapeGolfSessions,
  shapeRouteFollowUp,
} from "../src/health-connect/shape.js";
import type { RawExerciseRoutePoint, RawExerciseSessionRecord } from "../src/health-connect/types.js";

// This file imports only the pure shaping logic (shape.ts), never
// reader.ts or the package's index.ts — those import
// "react-native-health-connect", which assumes a React Native runtime
// and cannot be exercised under plain Node/vitest. See README.md
// "Not device-tested".

const NOW = new Date("2026-09-23T12:00:00.000Z");

function golfRecord(overrides: Partial<RawExerciseSessionRecord> = {}): RawExerciseSessionRecord {
  return {
    metadata: { id: "rec-1", dataOrigin: "com.garmin.android.apps.connectmobile" },
    startTime: "2026-09-20T14:00:00.000Z",
    endTime: "2026-09-20T18:00:00.000Z",
    exerciseType: EXERCISE_TYPE_GOLF,
    ...overrides,
  };
}

describe("shapeGolfSessions", () => {
  it("drops non-golf sessions", () => {
    const running: RawExerciseSessionRecord = {
      ...golfRecord(),
      exerciseType: 56, // ExerciseType.RUNNING, per react-native-health-connect's constants.ts
    };
    const result = shapeGolfSessions([running], 30, NOW);
    expect(result.sessionCount).toBe(0);
    expect(result.sessions).toEqual([]);
  });

  it("shapes a golf session with no route", () => {
    const result = shapeGolfSessions([golfRecord()], 30, NOW);
    expect(result.sessionCount).toBe(1);
    expect(result.sessions[0]).toMatchObject({
      recordId: "rec-1",
      start: "2026-09-20T14:00:00.000Z",
      end: "2026-09-20T18:00:00.000Z",
      dataOrigin: "com.garmin.android.apps.connectmobile",
      routePresent: false,
      routePointCount: 0,
      routeRequiresConsent: false,
    });
  });

  it("counts route points when a route is present (type DATA)", () => {
    const record = golfRecord({
      exerciseRoute: {
        type: 0, // ExerciseRouteResultType.DATA
        route: [
          { latitude: 35.0, longitude: -86.0, time: "2026-09-20T14:01:00.000Z" },
          { latitude: 35.001, longitude: -86.001, time: "2026-09-20T14:02:00.000Z" },
          { latitude: 35.002, longitude: -86.002, time: "2026-09-20T14:03:00.000Z" },
        ],
      },
    });
    const result = shapeGolfSessions([record], 30, NOW);
    expect(result.sessions[0]?.routePresent).toBe(true);
    expect(result.sessions[0]?.routePointCount).toBe(3);
    expect(result.sessions[0]?.routeRequiresConsent).toBe(false);
  });

  it("flags routeRequiresConsent without counting points (type CONSENT_REQUIRED)", () => {
    const record = golfRecord({
      exerciseRoute: {
        type: 2, // ExerciseRouteResultType.CONSENT_REQUIRED
        route: [],
      },
    });
    const result = shapeGolfSessions([record], 30, NOW);
    expect(result.sessions[0]?.routePresent).toBe(false);
    expect(result.sessions[0]?.routePointCount).toBe(0);
    expect(result.sessions[0]?.routeRequiresConsent).toBe(true);
  });

  it("falls back to 'unknown' dataOrigin and '' recordId when metadata is missing", () => {
    const record: RawExerciseSessionRecord = {
      startTime: "2026-09-20T14:00:00.000Z",
      endTime: "2026-09-20T18:00:00.000Z",
      exerciseType: EXERCISE_TYPE_GOLF,
    };
    const result = shapeGolfSessions([record], 30, NOW);
    expect(result.sessions[0]).toMatchObject({ recordId: "", dataOrigin: "unknown" });
  });

  it("records generatedAt and windowDays on the result", () => {
    const result = shapeGolfSessions([golfRecord()], 14, NOW);
    expect(result.generatedAt).toBe(NOW.toISOString());
    expect(result.windowDays).toBe(14);
  });
});

// CONSENT_REQUIRED follow-up read (decision 0001, Addendum D, R6): a
// session reported as CONSENT_REQUIRED counts as "route present" only if
// the follow-up requestExerciseRoute(recordId) call returns ≥ 1 point.
describe("shapeRouteFollowUp", () => {
  it("reports route-not-present for an empty follow-up read", () => {
    const result = shapeRouteFollowUp([]);
    expect(result).toEqual({ routePresent: false, routePointCount: 0 });
  });

  it("reports route-present with the point count when points come back", () => {
    const points: RawExerciseRoutePoint[] = [
      { latitude: 35.0, longitude: -86.0, time: "2026-09-20T14:01:00.000Z" },
      { latitude: 35.001, longitude: -86.001, time: "2026-09-20T14:02:00.000Z" },
    ];
    const result = shapeRouteFollowUp(points);
    expect(result).toEqual({ routePresent: true, routePointCount: 2 });
  });
});
