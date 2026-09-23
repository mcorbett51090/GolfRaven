import { describe, expect, it } from "vitest";
import { computeX1Verdict, type AndroidGolfSessionReadResult, type SourceMap } from "../src/x1-verdict.js";
import type { X1IosExportResult, X1IosWorkoutRecord } from "../src/x1-ios-export.js";

function iosWorkout(overrides: Partial<X1IosWorkoutRecord>): X1IosWorkoutRecord {
  return {
    sourceName: "Garmin Connect",
    sourceVersion: null,
    device: null,
    workoutActivityType: "HKWorkoutActivityTypeGolf",
    startDate: "2026-09-20 09:00:00 -0400",
    endDate: "2026-09-20 13:00:00 -0400",
    hasWorkoutRoute: true,
    routeFileReferencePath: "/workout-routes/x.gpx",
    routeFileExists: true,
    routeTrackpointCount: 10,
    routePresent: true,
    verdict: "pass",
    ...overrides,
  };
}

function iosResult(workouts: X1IosWorkoutRecord[]): X1IosExportResult {
  return {
    generatedAt: new Date().toISOString(),
    exportDir: "/fake",
    since: null,
    totalWorkoutElementsSeen: workouts.length,
    golfWorkoutCount: workouts.length,
    workouts,
    warnings: [],
  };
}

function androidResult(
  sessions: AndroidGolfSessionReadResult["sessions"],
): AndroidGolfSessionReadResult {
  return { generatedAt: new Date().toISOString(), windowDays: 7, sessionCount: sessions.length, sessions };
}

const BASE_SOURCE_MAP: SourceMap = {
  garmin: {
    iosSourceNames: ["Garmin Connect"],
    androidDataOrigins: ["com.garmin.android.apps.connectmobile"],
  },
  appleWatch: { iosSourceNames: ["Matt's Apple Watch"] },
  phoneApp: {
    iosSourceNames: ["18Birdies"],
    androidDataOrigins: ["com.eighteenbirdies.android"],
    appUsed: "18Birdies",
  },
};

describe("x1-verdict: source-level verdicts and the 2-of-3 bar", () => {
  it("passes when all 3 sources write golf workouts with routes on iOS", () => {
    const ios = iosResult([
      iosWorkout({ sourceName: "Garmin Connect" }),
      iosWorkout({ sourceName: "Matt's Apple Watch" }),
      iosWorkout({ sourceName: "18Birdies" }),
    ]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP });
    expect(result.perSource.garmin.passesOnAnyOS).toBe(true);
    expect(result.perSource.appleWatch.passesOnAnyOS).toBe(true);
    expect(result.perSource.phoneApp.passesOnAnyOS).toBe(true);
    expect(result.sourcesPassingCount).toBe(3);
    expect(result.overallVerdict).toBe("pass");
    expect(result.garminWrittenStatementTriggeredByX1).toBe(false);
  });

  it("BOUNDARY: exactly 2 of 3 sources passing is a pass", () => {
    const ios = iosResult([
      iosWorkout({ sourceName: "Garmin Connect", routePresent: false, verdict: "fail" }), // Garmin fails
      iosWorkout({ sourceName: "Matt's Apple Watch" }),
      iosWorkout({ sourceName: "18Birdies" }),
    ]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP });
    expect(result.sourcesPassingCount).toBe(2);
    expect(result.overallVerdict).toBe("pass");
    // Garmin specifically failed -> K4 written statement triggers even though X1 passes overall.
    expect(result.garminWrittenStatementTriggeredByX1).toBe(true);
  });

  it("BOUNDARY: exactly 1 of 3 sources passing is a kill", () => {
    const ios = iosResult([
      iosWorkout({ sourceName: "Garmin Connect", routePresent: false, verdict: "fail" }),
      iosWorkout({ sourceName: "Matt's Apple Watch", routePresent: false, verdict: "fail" }),
      iosWorkout({ sourceName: "18Birdies" }),
    ]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP });
    expect(result.sourcesPassingCount).toBe(1);
    expect(result.overallVerdict).toBe("kill");
  });

  it("a source with no matching data at all is fail-not-written", () => {
    const ios = iosResult([iosWorkout({ sourceName: "18Birdies" })]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP });
    expect(result.perSource.garmin.ios).toBe("fail-not-written");
    expect(result.perSource.garmin.android).toBe("fail-not-written");
    expect(result.perSource.garmin.passesOnAnyOS).toBe(false);
  });

  it("a source that passes on Android but not iOS still passesOnAnyOS", () => {
    const ios = iosResult([
      iosWorkout({ sourceName: "Matt's Apple Watch" }),
      iosWorkout({ sourceName: "18Birdies" }),
    ]);
    const android = androidResult([
      {
        recordId: "r1",
        start: "2026-09-21T09:00:00Z",
        end: "2026-09-21T13:00:00Z",
        dataOrigin: "com.garmin.android.apps.connectmobile",
        routePresent: true,
        routePointCount: 50,
        routeRequiresConsent: false,
      },
    ]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP });
    expect(result.perSource.garmin.ios).toBe("fail-not-written");
    expect(result.perSource.garmin.android).toBe("pass");
    expect(result.perSource.garmin.passesOnAnyOS).toBe(true);
  });

  it("Apple Watch is not-applicable on Android and its passesOnAnyOS depends only on iOS", () => {
    const ios = iosResult([iosWorkout({ sourceName: "Matt's Apple Watch", routePresent: false, verdict: "fail" })]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP });
    expect(result.perSource.appleWatch.android).toBe("not-applicable");
    expect(result.perSource.appleWatch.passesOnAnyOS).toBe(false);
  });
});

describe("x1-verdict: decision 0001 Addendum D R6 — CONSENT_REQUIRED follow-up", () => {
  it("a CONSENT_REQUIRED session with a follow-up read of >= 1 point counts as route present", () => {
    const ios = iosResult([]);
    const android = androidResult([
      {
        recordId: "consent-1",
        start: "2026-09-21T09:00:00Z",
        end: "2026-09-21T13:00:00Z",
        dataOrigin: "com.garmin.android.apps.connectmobile",
        routePresent: false,
        routePointCount: 0,
        routeRequiresConsent: true,
      },
    ]);
    const result = computeX1Verdict({
      ios,
      android,
      sourceMap: BASE_SOURCE_MAP,
      androidRouteFollowUps: { "consent-1": { routePresent: true, routePointCount: 1 } },
    });
    expect(result.perSource.garmin.android).toBe("pass");
  });

  it("a CONSENT_REQUIRED session with a follow-up read of 0 points does NOT count as route present", () => {
    const ios = iosResult([]);
    const android = androidResult([
      {
        recordId: "consent-2",
        start: "2026-09-21T09:00:00Z",
        end: "2026-09-21T13:00:00Z",
        dataOrigin: "com.garmin.android.apps.connectmobile",
        routePresent: false,
        routePointCount: 0,
        routeRequiresConsent: true,
      },
    ]);
    const result = computeX1Verdict({
      ios,
      android,
      sourceMap: BASE_SOURCE_MAP,
      androidRouteFollowUps: { "consent-2": { routePresent: false, routePointCount: 0 } },
    });
    expect(result.perSource.garmin.android).toBe("fail-no-route");
  });

  it("a CONSENT_REQUIRED session with NO follow-up read at all defaults to not present", () => {
    const ios = iosResult([]);
    const android = androidResult([
      {
        recordId: "consent-3",
        start: "2026-09-21T09:00:00Z",
        end: "2026-09-21T13:00:00Z",
        dataOrigin: "com.garmin.android.apps.connectmobile",
        routePresent: false,
        routePointCount: 0,
        routeRequiresConsent: true,
      },
    ]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP });
    expect(result.perSource.garmin.android).toBe("fail-no-route");
  });
});

describe("x1-verdict: decision 0001 Addendum D R6 — the phone-app source and the Hole19 swap", () => {
  it("18Birdies as appUsed needs no swap log and works normally", () => {
    const ios = iosResult([iosWorkout({ sourceName: "18Birdies" })]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP });
    expect(result.perSource.phoneApp.ios).toBe("pass");
  });

  it("Hole19 as appUsed WITH the pre-round swap logged is valid and uses Hole19 data", () => {
    const sourceMap: SourceMap = {
      ...BASE_SOURCE_MAP,
      phoneApp: {
        iosSourceNames: ["Hole19"],
        androidDataOrigins: ["com.hole19golf.android"],
        appUsed: "Hole19",
        hole19SwapLoggedBeforeRound: true,
      },
    };
    const ios = iosResult([iosWorkout({ sourceName: "Hole19" })]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap });
    expect(result.perSource.phoneApp.appUsed).toBe("Hole19");
    expect(result.perSource.phoneApp.ios).toBe("pass");
  });

  it("Hole19 as appUsed WITHOUT the pre-round swap log throws (literal R6 violation)", () => {
    const sourceMap: SourceMap = {
      ...BASE_SOURCE_MAP,
      phoneApp: {
        iosSourceNames: ["Hole19"],
        androidDataOrigins: ["com.hole19golf.android"],
        appUsed: "Hole19",
        hole19SwapLoggedBeforeRound: false,
      },
    };
    const ios = iosResult([iosWorkout({ sourceName: "Hole19" })]);
    const android = androidResult([]);
    expect(() => computeX1Verdict({ ios, android, sourceMap })).toThrow(/hole19SwapLoggedBeforeRound/);
  });

  it("Hole19 as appUsed with hole19SwapLoggedBeforeRound omitted also throws", () => {
    const sourceMap: SourceMap = {
      ...BASE_SOURCE_MAP,
      phoneApp: {
        iosSourceNames: ["Hole19"],
        androidDataOrigins: ["com.hole19golf.android"],
        appUsed: "Hole19",
      },
    };
    const ios = iosResult([iosWorkout({ sourceName: "Hole19" })]);
    const android = androidResult([]);
    expect(() => computeX1Verdict({ ios, android, sourceMap })).toThrow();
  });

  it("extra/supplementary apps present in the data but not in the source map are ignored", () => {
    const ios = iosResult([
      iosWorkout({ sourceName: "18Birdies" }),
      iosWorkout({ sourceName: "TheGrint", routePresent: true, verdict: "pass" }), // supplementary, not configured
    ]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP });
    // TheGrint data doesn't appear anywhere in perSource — only phoneApp (18Birdies) does.
    expect(result.perSource.phoneApp.appUsed).toBe("18Birdies");
    expect(JSON.stringify(result.perSource)).not.toContain("TheGrint");
  });
});
