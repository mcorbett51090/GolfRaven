import { describe, expect, it } from "vitest";
import {
  computeOverallFromBoundResults,
  computeX1Verdict,
  type AndroidGolfSessionReadResult,
  type SourceMap,
  type X1VerdictInput,
} from "../src/x1-verdict.js";
import type { X1IosWorkoutRecord } from "../src/x1-ios-export.js";
import type { RoundWindow } from "../src/round-windows.js";

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
    testRound: false,
    ...overrides,
  };
}

/** Round-2 Opus-gate correction (post-67bdb27): `computeX1Verdict` has no
 * "eligible"/trust concept any more — it cannot verify anything (no
 * filesystem/git access), so `recordedVerdicts` is always computed purely
 * from data. These helpers reflect that: no `recorded`/`os` stamp param on
 * `iosResult` at all (it would mean nothing); `androidResult`'s `os` is
 * REQUIRED (a basic shape field the real Android reader output must carry
 * — see the module doc) but likewise carries no eligibility weight. */
function iosResult(workouts: X1IosWorkoutRecord[]): X1VerdictInput["ios"] {
  return {
    generatedAt: new Date().toISOString(),
    exportDir: "/fake",
    since: null,
    roundWindows: ROUND_WINDOWS,
    totalWorkoutElementsSeen: workouts.length,
    golfWorkoutCount: workouts.length,
    workouts,
    sourceSummaries: [],
    exportDate: "2026-09-20 09:00:00 -0400",
    exportSha256: "e".repeat(64),
    warnings: [],
  };
}

function androidResult(
  sessions: AndroidGolfSessionReadResult["sessions"],
  os: "ios" | "android" = "android",
): X1VerdictInput["android"] {
  return {
    generatedAt: new Date().toISOString(),
    windowDays: 7,
    sessionCount: sessions.length,
    sessions,
    os,
  };
}

/** Covers both the iOS fixture workouts ("2026-09-20 09:00:00 -0400" =
 * 13:00 UTC) and the Android fixture sessions ("2026-09-21T09:00:00Z"). */
const ROUND_WINDOWS: RoundWindow[] = [{ startIso: "2026-09-20T00:00:00Z", endIso: "2026-09-22T00:00:00Z" }];

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

describe("x1-verdict: source-level verdicts and the 2-of-3-on-one-OS bar (decision 0001 Addendum F)", () => {
  it("passes when all 3 sources write golf workouts with routes on iOS", () => {
    const ios = iosResult([
      iosWorkout({ sourceName: "Garmin Connect" }),
      iosWorkout({ sourceName: "Matt's Apple Watch" }),
      iosWorkout({ sourceName: "18Birdies" }),
    ]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
    expect(result.perSource.garmin.passesOnAnyOS).toBe(true);
    expect(result.perSource.appleWatch.passesOnAnyOS).toBe(true);
    expect(result.perSource.phoneApp.passesOnAnyOS).toBe(true);
    expect(result.sourcesPassingByOs).toEqual({ ios: 3, android: 0 });
    expect(result.overallVerdict).toBe("pass");
    expect(result.garminWrittenStatementTriggeredByX1).toBe(false);
  });

  it("BOUNDARY: exactly 2 of 3 sources passing on the SAME OS is a pass", () => {
    const ios = iosResult([
      iosWorkout({ sourceName: "Garmin Connect", routePresent: false, verdict: "fail" }), // Garmin fails
      iosWorkout({ sourceName: "Matt's Apple Watch" }),
      iosWorkout({ sourceName: "18Birdies" }),
    ]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
    expect(result.sourcesPassingByOs).toEqual({ ios: 2, android: 0 });
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
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
    expect(result.sourcesPassingByOs).toEqual({ ios: 1, android: 0 });
    expect(result.overallVerdict).toBe("kill");
  });

  it("gate finding B-6: sources passing on DIFFERENT OSes do NOT combine — this is a KILL, not a pass", () => {
    // Decision 0001 Addendum F's own example: Apple Watch routes only on
    // iOS, Garmin routes only on Android. Under the old ('any OS') reading
    // this was a pass (2 of 3 pass somewhere); Addendum F pins the reading
    // that predicts what a user actually gets — a kill, since no ONE OS has
    // 2 of 3 passing.
    const ios = iosResult([
      iosWorkout({ sourceName: "Matt's Apple Watch" }), // Apple Watch passes on iOS only
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
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
    expect(result.perSource.appleWatch.passesOnAnyOS).toBe(true);
    expect(result.perSource.garmin.passesOnAnyOS).toBe(true);
    expect(result.sourcesPassingByOs).toEqual({ ios: 1, android: 1 });
    expect(result.overallVerdict).toBe("kill");
  });

  it("a source with no matching data at all is fail-not-written", () => {
    const ios = iosResult([iosWorkout({ sourceName: "18Birdies" })]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
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
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
    expect(result.perSource.garmin.ios).toBe("fail-not-written");
    expect(result.perSource.garmin.android).toBe("pass");
    expect(result.perSource.garmin.passesOnAnyOS).toBe(true);
  });

  it("Apple Watch is not-applicable on Android and its passesOnAnyOS depends only on iOS", () => {
    const ios = iosResult([iosWorkout({ sourceName: "Matt's Apple Watch", routePresent: false, verdict: "fail" })]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
    expect(result.perSource.appleWatch.android).toBe("not-applicable");
    expect(result.perSource.appleWatch.passesOnAnyOS).toBe(false);
  });
});

describe("x1-verdict: round windows are labels, not a filter (decision 0005, superseding Addendum F)", () => {
  it("does NOT throw when roundWindows is empty — an unlogged window is a normal state now", () => {
    const ios = iosResult([iosWorkout({ sourceName: "Garmin Connect" })]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: [] });
    expect(result.perSource.garmin.ios).toBe("pass");
  });

  it("does NOT throw when roundWindows is omitted entirely", () => {
    const ios = iosResult([iosWorkout({ sourceName: "Garmin Connect" })]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP });
    expect(result.perSource.garmin.ios).toBe("pass");
  });

  it("a historical iOS workout OUTSIDE every window still counts toward the verdict (decision 0005)", () => {
    // Under the old Addendum F rule this workout would have been excluded
    // and the source would read fail-not-written; decision 0005 counts it.
    const ios = iosResult([iosWorkout({ sourceName: "Garmin Connect", startDate: "2020-01-01 09:00:00 -0400" })]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
    expect(result.perSource.garmin.ios).toBe("pass");
    // Tagged as NOT a test round — it falls outside the logged window.
    const entry = result.countedEntries.garmin.find((e) => e.os === "ios");
    expect(entry?.testRound).toBe(false);
  });

  it("a historical Android session OUTSIDE every window still counts toward the verdict", () => {
    const ios = iosResult([]);
    const android = androidResult([
      {
        recordId: "old",
        start: "2020-01-01T09:00:00Z",
        end: "2020-01-01T13:00:00Z",
        dataOrigin: "com.garmin.android.apps.connectmobile",
        routePresent: true,
        routePointCount: 50,
        routeRequiresConsent: false,
      },
    ]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
    expect(result.perSource.garmin.android).toBe("pass");
    const entry = result.countedEntries.garmin.find((e) => e.os === "android");
    expect(entry?.testRound).toBe(false);
  });

  it("a workout INSIDE a logged window is tagged testRound: true", () => {
    const ios = iosResult([iosWorkout({ sourceName: "Garmin Connect", startDate: "2026-09-20 09:00:00 -0400" })]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
    const entry = result.countedEntries.garmin.find((e) => e.os === "ios");
    expect(entry?.testRound).toBe(true);
  });

  it("newestCountedWorkoutDateBySource reports the newest start date per source per OS", () => {
    const ios = iosResult([
      iosWorkout({ sourceName: "Garmin Connect", startDate: "2020-01-01 09:00:00 -0400" }),
      iosWorkout({ sourceName: "Garmin Connect", startDate: "2026-09-20 09:00:00 -0400" }),
    ]);
    const android = androidResult([
      {
        recordId: "r1",
        start: "2021-05-01T09:00:00Z",
        end: "2021-05-01T13:00:00Z",
        dataOrigin: "com.garmin.android.apps.connectmobile",
        routePresent: true,
        routePointCount: 50,
        routeRequiresConsent: false,
      },
    ]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
    expect(result.newestCountedWorkoutDateBySource.garmin.ios).toBe("2026-09-20 09:00:00 -0400");
    expect(result.newestCountedWorkoutDateBySource.garmin.android).toBe("2021-05-01T09:00:00Z");
    expect(result.newestCountedWorkoutDateBySource.appleWatch).toEqual({ ios: null, android: null });
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
      roundWindows: ROUND_WINDOWS,
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
      roundWindows: ROUND_WINDOWS,
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
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
    expect(result.perSource.garmin.android).toBe("fail-no-route");
  });
});

describe("x1-verdict: decision 0001 Addendum D R6 — the phone-app source and the Hole19 swap", () => {
  it("18Birdies as appUsed needs no swap log and works normally", () => {
    const ios = iosResult([iosWorkout({ sourceName: "18Birdies" })]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
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
    const result = computeX1Verdict({ ios, android, sourceMap, roundWindows: ROUND_WINDOWS });
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
    expect(() => computeX1Verdict({ ios, android, sourceMap, roundWindows: ROUND_WINDOWS })).toThrow(
      /hole19SwapLoggedBeforeRound/,
    );
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
    expect(() => computeX1Verdict({ ios, android, sourceMap, roundWindows: ROUND_WINDOWS })).toThrow();
  });

  it("extra/supplementary apps present in the data but not in the source map are ignored", () => {
    const ios = iosResult([
      iosWorkout({ sourceName: "18Birdies" }),
      iosWorkout({ sourceName: "TheGrint", routePresent: true, verdict: "pass" }), // supplementary, not configured
    ]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
    // TheGrint data doesn't appear anywhere in perSource — only phoneApp (18Birdies) does.
    expect(result.perSource.phoneApp.appUsed).toBe("18Birdies");
    expect(JSON.stringify(result.perSource)).not.toContain("TheGrint");
  });

  it("gate finding B-9: a source list leaking the OTHER app's identifier throws", () => {
    const sourceMap: SourceMap = {
      ...BASE_SOURCE_MAP,
      phoneApp: {
        iosSourceNames: ["18Birdies", "Hole19"], // leaks the other app's name
        androidDataOrigins: ["com.eighteenbirdies.android"],
        appUsed: "18Birdies",
      },
    };
    const ios = iosResult([iosWorkout({ sourceName: "18Birdies" })]);
    const android = androidResult([]);
    expect(() => computeX1Verdict({ ios, android, sourceMap, roundWindows: ROUND_WINDOWS })).toThrow(/OTHER app/);
  });
});

const THREE_PASSING_IOS_WORKOUTS = [
  iosWorkout({ sourceName: "Garmin Connect" }),
  iosWorkout({ sourceName: "Matt's Apple Watch" }),
  iosWorkout({ sourceName: "18Birdies" }),
];

function twoOfThreePassingAndroidSessions(): AndroidGolfSessionReadResult["sessions"] {
  return [
    {
      recordId: "a",
      start: "2026-09-21T09:00:00Z",
      end: "2026-09-21T13:00:00Z",
      dataOrigin: "com.garmin.android.apps.connectmobile",
      routePresent: true,
      routePointCount: 5,
      routeRequiresConsent: false,
    },
    {
      recordId: "b",
      start: "2026-09-21T09:00:00Z",
      end: "2026-09-21T13:00:00Z",
      dataOrigin: "com.eighteenbirdies.android",
      routePresent: true,
      routePointCount: 5,
      routeRequiresConsent: false,
    },
  ];
}

describe("x1-verdict: recordedVerdicts is purely data-driven — stamps are IGNORED entirely (round-2 Opus-gate correction, post-67bdb27, reflects x1probe2.mjs)", () => {
  it("recordedVerdicts and overallVerdict are the SAME regardless of any recorded/os field the inputs carry", () => {
    // The exact shape of x1probe2.mjs's 3 scenarios: identical underlying
    // data, only the (now-irrelevant) recorded/os stamps differ.
    const iosData = [
      iosWorkout({ sourceName: "Garmin Connect", startDate: "2019-05-01 10:00:00 +0000", routePresent: true, verdict: "pass" }),
      iosWorkout({ sourceName: "Garmin Connect", startDate: "2026-09-20 10:00:00 +0000", routePresent: false, verdict: "fail" }),
    ];
    const androidData = twoOfThreePassingAndroidSessions();

    const scenarios: Array<[string, X1VerdictInput["ios"], X1VerdictInput["android"]]> = [
      ["no stamps at all", iosResult(iosData), androidResult(androidData)],
      [
        "hand-stamped recorded:true on both (as JSON someone could edit by hand)",
        { ...iosResult(iosData), recorded: true, os: "ios" } as X1VerdictInput["ios"],
        { ...androidResult(androidData), recorded: true } as X1VerdictInput["android"],
      ],
      [
        "hand-stamped recorded:true, no os field",
        { ...iosResult(iosData), recorded: true } as X1VerdictInput["ios"],
        androidResult(androidData),
      ],
    ];

    const results = scenarios.map(([, ios, android]) =>
      computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS }),
    );
    // All 3 must agree — proving the stamps have ZERO effect.
    for (const r of results) {
      expect(r.recordedVerdicts.ios.verdict).toBe(results[0]!.recordedVerdicts.ios.verdict);
      expect(r.recordedVerdicts.android.verdict).toBe(results[0]!.recordedVerdicts.android.verdict);
      expect(r.overallVerdict).toBe(results[0]!.overallVerdict);
    }
    // And the actual values are purely data-driven: garmin passes on iOS
    // (the old 2019 workout has a route), garmin+phoneApp pass on Android.
    expect(results[0]!.recordedVerdicts.ios.verdict).toBe("kill"); // only garmin (1/3) on iOS
    expect(results[0]!.recordedVerdicts.android.verdict).toBe("pass"); // 2/3 on Android
    expect(results[0]!.overallVerdict).toBe("pass");
  });

  it("recordedVerdicts has no eligible/ineligibleReason field — verdict is always populated", () => {
    const ios = iosResult(THREE_PASSING_IOS_WORKOUTS);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
    expect(result.recordedVerdicts.ios).not.toHaveProperty("eligible");
    expect(result.recordedVerdicts.ios).not.toHaveProperty("ineligibleReason");
    expect(result.recordedVerdicts.ios.verdict).toBe("pass");
    expect(result.recordedVerdicts.android.verdict).toBe("kill");
  });

  it("recordedVerdicts[os].sourcesPassing mirrors sourcesPassingByOs[os]", () => {
    const ios = iosResult(THREE_PASSING_IOS_WORKOUTS);
    const android = androidResult(twoOfThreePassingAndroidSessions());
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
    expect(result.recordedVerdicts.ios.sourcesPassing).toBe(result.sourcesPassingByOs.ios);
    expect(result.recordedVerdicts.android.sourcesPassing).toBe(result.sourcesPassingByOs.android);
  });
});

describe("x1-verdict: newest-date excludes route-less workouts (should-fix, Opus gate post-d0de4b8)", () => {
  it("newestCountedWorkoutDateBySource only considers route-present entries; a NEWER route-less workout does not pull it forward", () => {
    const ios = iosResult([
      iosWorkout({
        sourceName: "Garmin Connect",
        startDate: "2026-09-20 09:00:00 -0400",
        routePresent: true,
        verdict: "pass",
      }),
      iosWorkout({
        sourceName: "Garmin Connect",
        startDate: "2026-09-22 09:00:00 -0400",
        routePresent: false,
        verdict: "fail",
        hasWorkoutRoute: false,
      }),
    ]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
    expect(result.newestCountedWorkoutDateBySource.garmin.ios).toBe("2026-09-20 09:00:00 -0400");
    expect(result.newestRouteLessWorkoutDateBySource.garmin.ios).toBe("2026-09-22 09:00:00 -0400");
  });

  it("a source with only route-less workouts has a null newestCountedWorkoutDate but a populated newestRouteLessWorkoutDate", () => {
    const ios = iosResult([
      iosWorkout({
        sourceName: "18Birdies",
        startDate: "2026-09-20 09:00:00 -0400",
        routePresent: false,
        verdict: "fail",
        hasWorkoutRoute: false,
      }),
    ]);
    const android = androidResult([]);
    const result = computeX1Verdict({ ios, android, sourceMap: BASE_SOURCE_MAP, roundWindows: ROUND_WINDOWS });
    expect(result.newestCountedWorkoutDateBySource.phoneApp.ios).toBeNull();
    expect(result.newestRouteLessWorkoutDateBySource.phoneApp.ios).toBe("2026-09-20 09:00:00 -0400");
  });
});

// Round-3 Opus-gate correction (post-8e5a29b): `assertIosWorkoutDataNotTampered`
// and its tests are gone — x1-verdict no longer reads a separate `--ios`
// JSON to distrust. `--ios-export <dir>` is always parsed fresh, in the
// same call that verifies its hash, so there is nothing left to tamper
// with independently of the bound file itself. See x1-verdict.ts's module
// doc and `tools/p0/README.md` for the simplified mechanism.

describe("computeOverallFromBoundResults (round-3 Opus-gate correction, post-8e5a29b) — 'the overall result is a pass if any bound OS recomputes to a pass'", () => {
  it("pass when the only bound OS recomputed to pass", () => {
    expect(computeOverallFromBoundResults({ ios: "pass" })).toBe("pass");
  });

  it("kill when the only bound OS recomputed to kill", () => {
    expect(computeOverallFromBoundResults({ ios: "kill" })).toBe("kill");
  });

  it("iOS bound as kill and Android bound as pass -> overall pass, only when both bound files verify (i.e. both are present in boundResults)", () => {
    expect(computeOverallFromBoundResults({ ios: "kill", android: "pass" })).toBe("pass");
  });

  it("kill when both bound OSes recomputed to kill", () => {
    expect(computeOverallFromBoundResults({ ios: "kill", android: "kill" })).toBe("kill");
  });

  it("pass when both bound OSes recomputed to pass", () => {
    expect(computeOverallFromBoundResults({ ios: "pass", android: "pass" })).toBe("pass");
  });
});
