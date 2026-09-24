#!/usr/bin/env node
/**
 * `x1-verdict` — computes the X1 (=K4a) pass/kill verdict (build plan §10
 * P0; `docs/p0/X1.md`) from recorded per-source results: `x1-ios-export`'s
 * JSON output, and the Android Health Connect reader's JSON output
 * (`apps/mobile/src/health-connect/` — its `GolfSessionReadResult` /
 * `GolfSessionSummary` shape, duplicated here as a minimal input type so
 * this package does not depend on `@golfraven/mobile`, a React Native app).
 *
 * Applies, literally, not reinterpreted:
 * - The X1 pass bar (`docs/p0/X1.md`): ≥ 2 of 3 sources write golf workouts
 *   **with routes** on ≥ 1 OS.
 * - Decision 0001, Addendum D, R6: on Android, a `CONSENT_REQUIRED` session
 *   counts as "route present" only if a follow-up `requestExerciseRoute`
 *   read for that session returned ≥ 1 point. The phone-app source is
 *   18Birdies unless a Hole19 swap was logged before the round (this tool
 *   validates that the config asserts a pre-round log, not merely that a
 *   swap happened).
 * - A2-14: a verdict **per source**, so a Garmin fail stays visible even
 *   when X1 passes overall.
 *
 * "Extra apps are supplementary, never the source verdict" (R6): this tool
 * only looks at workouts/sessions whose identifying name is listed in the
 * caller's source map. Anything else in the input data is ignored for
 * verdict purposes (not reported as a source).
 *
 * **Decision 0005 (2026-09-24)** changes two things here:
 * - **Round windows are labels, not a filter.** Every counted golf
 *   workout/session — historical or not — now feeds the verdict; a logged
 *   `docs/p0/X1.md` round window only tags a matching entry `testRound:
 *   true` in `countedEntries` below. `computeX1Verdict` no longer refuses
 *   when no window is logged, and no longer excludes anything by date.
 * - **The recorded-export rule** (see `recorded-export.ts`) replaces the
 *   round-window refusal as the CLI's gate: `--os ios|android` names which
 *   OS's `docs/p0/X1.md` "## Recorded export" date this run is standing on;
 *   a blank date refuses unless `--informational` is passed, in which case
 *   the output is marked `recorded: false` with a loud banner. The verdict
 *   itself always combines both OSes' input data, as before — `--os` only
 *   decides which OS's recorded-export date gates this particular run.
 */
import { readFile, realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import type { X1IosExportResult, X1IosWorkoutRecord } from "./x1-ios-export.js";
import {
  isWithinRoundWindow,
  readLoggedRoundWindows,
  type RoundWindow,
} from "./round-windows.js";
import {
  assertRecordedExportDateLogged,
  informationalBanner,
  readRecordedExportDates,
  type X1Os,
} from "./recorded-export.js";

/** Minimal shape of the Android Health Connect reader's per-session record
 * (`apps/mobile/src/health-connect/types.ts` `GolfSessionSummary`),
 * duplicated here — see module doc for why. Field names and meanings must
 * stay in sync with that file by hand. */
export interface AndroidGolfSessionSummary {
  recordId: string;
  start: string;
  end: string;
  dataOrigin: string;
  routePresent: boolean;
  routePointCount: number;
  routeRequiresConsent: boolean;
}

/** Minimal shape of the reader's full result
 * (`GolfSessionReadResult`). */
export interface AndroidGolfSessionReadResult {
  generatedAt: string;
  windowDays: number;
  sessionCount: number;
  sessions: AndroidGolfSessionSummary[];
}

/** A CONSENT_REQUIRED follow-up read result, keyed by `recordId`
 * (mirrors the reader's `RouteFollowUpResult`, produced by
 * `requestExerciseRoute(recordId)` per decision 0001 Addendum D R6). */
export interface AndroidRouteFollowUp {
  routePresent: boolean;
  routePointCount: number;
}

export interface SourceMap {
  garmin: {
    iosSourceNames: string[];
    androidDataOrigins: string[];
  };
  appleWatch: {
    iosSourceNames: string[];
  };
  phoneApp: {
    iosSourceNames: string[];
    androidDataOrigins: string[];
    /** Which app was actually used for the round. */
    appUsed: "18Birdies" | "Hole19";
    /** Whether the Hole19 substitution (if `appUsed === "Hole19"`) was
     * logged in `docs/p0/X1.md`'s Log **before** the round, per decision
     * 0001 Addendum D R6 and X1.md method step 7. Ignored when
     * `appUsed === "18Birdies"`. */
    hole19SwapLoggedBeforeRound?: boolean;
  };
}

export type SourceOsVerdict =
  "pass" | "fail-no-route" | "fail-not-written" | "not-applicable";

export interface SourceVerdict {
  ios: SourceOsVerdict;
  android: SourceOsVerdict;
  passesOnAnyOS: boolean;
}

export interface PhoneAppSourceVerdict extends SourceVerdict {
  appUsed: "18Birdies" | "Hole19";
}

/** Decision 0005 "Every counted workout is listed with its date and
 * source ... the source version and device when the export records
 * them": one entry per counted iOS workout / Android session matched to a
 * source. `sourceVersion`/`device` are iOS-only — the Android reader's
 * `GolfSessionSummary` (`apps/mobile/src/health-connect/types.ts`) does not
 * carry them `[unverified — this package only has the minimal duplicated
 * shape; see the module doc]`. */
export interface X1CountedEntry {
  os: "ios" | "android";
  start: string | null;
  sourceBundleId: string | null;
  sourceVersion: string | null;
  device: string | null;
  routePresent: boolean;
  /** Decision 0005: true when `start` falls inside a logged
   * `docs/p0/X1.md` round window (60-minute slack) — a LABEL only; it does
   * not affect whether this entry is counted. */
  testRound: boolean;
}

export interface X1NewestDateByOs {
  ios: string | null;
  android: string | null;
}

export interface X1VerdictResult {
  generatedAt: string;
  perSource: {
    garmin: SourceVerdict;
    appleWatch: SourceVerdict;
    phoneApp: PhoneAppSourceVerdict;
  };
  /** Gate finding B-6: how many of the 3 sources pass ON EACH OS
   * independently — the bar is "≥ 2 of 3 sources pass on ONE OS", not "≥ 2
   * of 3 pass somewhere, possibly on different OSes" (decision 0001
   * Addendum F: "Sources that pass on different operating systems do not
   * combine"). Emitted alongside the verdict so both readings stay visible. */
  sourcesPassingByOs: { ios: number; android: number };
  overallVerdict: "pass" | "kill";
  /** Whether X1's half of the K4 written-statement trigger fires
   * (`docs/p0/K4.md`: "if K4b fails, or if X1's Garmin source specifically
   * fails ... a written statement ... must go to the owner before P1").
   * This tool has no K4b data, so it can only assess the X1 side; K4b
   * failing independently also triggers the statement and is not
   * reflected here. */
  garminWrittenStatementTriggeredByX1: boolean;
  /** Decision 0005: every counted workout/session matched to one of the 3
   * sources, listed with its date, source id, and (iOS only) version and
   * device — the per-workout listing. */
  countedEntries: {
    garmin: X1CountedEntry[];
    appleWatch: X1CountedEntry[];
    phoneApp: X1CountedEntry[];
  };
  /** Decision 0005: "The memo shows, per source, the newest counted
   * workout's date" — per source, per OS. */
  newestCountedWorkoutDateBySource: {
    garmin: X1NewestDateByOs;
    appleWatch: X1NewestDateByOs;
    phoneApp: X1NewestDateByOs;
  };
  warnings: string[];
}

export interface X1VerdictInput {
  ios: X1IosExportResult;
  android: AndroidGolfSessionReadResult;
  /** Follow-up reads for any Android session with `routeRequiresConsent`,
   * keyed by `recordId`. A session in that state with no entry here is
   * treated as "not present" (R6's default when the follow-up wasn't run
   * or returned nothing). */
  androidRouteFollowUps?: Record<string, AndroidRouteFollowUp>;
  sourceMap: SourceMap;
  /** Decision 0005: the logged round window(s) from docs/p0/X1.md's "##
   * Round windows" section, used ONLY to tag matching entries `testRound:
   * true` in `countedEntries` — never to exclude anything. Optional; an
   * empty/omitted list is a normal state (every entry is then tagged
   * `testRound: false`), not a refusal. */
  roundWindows?: RoundWindow[];
}

function iosVerdictFor(
  workouts: X1IosWorkoutRecord[],
  sourceNames: string[],
  warnings: string[],
  sourceLabel: string,
): SourceOsVerdict {
  const matches = workouts.filter((w) => sourceNames.includes(w.sourceName));
  if (matches.length === 0) {
    warnings.push(
      `${sourceLabel}: no matching iOS workout found (sourceName in [${sourceNames.join(", ")}]).`,
    );
    return "fail-not-written";
  }
  const anyRoute = matches.some((w) => w.routePresent);
  return anyRoute ? "pass" : "fail-no-route";
}

function androidVerdictFor(
  sessions: AndroidGolfSessionSummary[],
  dataOrigins: string[],
  followUps: Record<string, AndroidRouteFollowUp>,
  warnings: string[],
  sourceLabel: string,
): SourceOsVerdict {
  const matches = sessions.filter((s) => dataOrigins.includes(s.dataOrigin));
  if (matches.length === 0) {
    warnings.push(
      `${sourceLabel}: no matching Android session found (dataOrigin in [${dataOrigins.join(", ")}]).`,
    );
    return "fail-not-written";
  }
  const anyRoute = matches.some((s) => {
    if (s.routePresent) return true;
    if (s.routeRequiresConsent) {
      // Decision 0001, Addendum D, R6: CONSENT_REQUIRED counts as
      // "route present" only via a follow-up read returning ≥ 1 point.
      const followUp = followUps[s.recordId];
      return Boolean(
        followUp && followUp.routePresent && followUp.routePointCount >= 1,
      );
    }
    return false;
  });
  return anyRoute ? "pass" : "fail-no-route";
}

/** Gate finding B-9: R6 says extra apps are "supplementary, never the
 * source verdict" — so a source-map that lists the OTHER phone app's own
 * identifiers under `phoneApp` (e.g. a Hole19 dataOrigin/sourceName while
 * `appUsed` is still "18Birdies") would let that other app's data quietly
 * become the source verdict, exactly what R6 forbids. Case-insensitive
 * substring check against each app's own name — this is a config-hygiene
 * guard, not a full identifier registry. */
const OTHER_APP_HINT: Record<"18Birdies" | "Hole19", string> = {
  "18Birdies": "hole19",
  Hole19: "18birdies",
};

function containsOtherAppHint(names: string[], hint: string): boolean {
  return names.some((n) => n.toLowerCase().includes(hint));
}

/** Decision 0005: the counted-workout listing, iOS side — one entry per
 * matching workout, tagged `testRound` from the (label-only) round
 * windows. */
function iosCountedEntries(
  workouts: X1IosWorkoutRecord[],
  sourceNames: string[],
  roundWindows: RoundWindow[],
): X1CountedEntry[] {
  return workouts
    .filter((w) => sourceNames.includes(w.sourceName))
    .map((w) => ({
      os: "ios",
      start: w.startDate,
      sourceBundleId: w.sourceName || null,
      sourceVersion: w.sourceVersion,
      device: w.device,
      routePresent: w.routePresent,
      testRound: isWithinRoundWindow(w.startDate, roundWindows),
    }));
}

/** Decision 0005: the counted-workout listing, Android side. The
 * duplicated `GolfSessionSummary` shape has no source version/device
 * fields, so those are always `null` here. */
function androidCountedEntries(
  sessions: AndroidGolfSessionSummary[],
  dataOrigins: string[],
  roundWindows: RoundWindow[],
): X1CountedEntry[] {
  return sessions
    .filter((s) => dataOrigins.includes(s.dataOrigin))
    .map((s) => ({
      os: "android",
      start: s.start,
      sourceBundleId: s.dataOrigin || null,
      sourceVersion: null,
      device: null,
      routePresent: s.routePresent,
      testRound: isWithinRoundWindow(s.start, roundWindows),
    }));
}

/** Newest (by `Date.parse`) `start` among `entries`, or `null` if none
 * parse. An entry with a missing/unparseable `start` is skipped, not
 * treated as "newest". */
function newestStart(entries: X1CountedEntry[]): string | null {
  let newest: string | null = null;
  let newestTime = -Infinity;
  for (const e of entries) {
    if (!e.start) continue;
    const t = Date.parse(e.start);
    if (!Number.isNaN(t) && t > newestTime) {
      newestTime = t;
      newest = e.start;
    }
  }
  return newest;
}

export function computeX1Verdict(input: X1VerdictInput): X1VerdictResult {
  // Decision 0005: round windows are labels, not a filter — no refusal on
  // an empty/missing list, and no exclusion of anything by date.
  const roundWindows = input.roundWindows ?? [];

  const warnings: string[] = [...input.ios.warnings];
  const followUps = input.androidRouteFollowUps ?? {};

  // R6: the phone-app source is 18Birdies unless the Hole19 swap was
  // logged before the round. If appUsed is Hole19 without that log, this
  // is a literal violation of R6 — fail loudly rather than silently
  // crediting Hole19 data as the source verdict.
  const phoneApp = input.sourceMap.phoneApp;
  if (
    phoneApp.appUsed === "Hole19" &&
    phoneApp.hole19SwapLoggedBeforeRound !== true
  ) {
    throw new Error(
      "sourceMap.phoneApp.appUsed is 'Hole19' but hole19SwapLoggedBeforeRound is not true. " +
        "Decision 0001 Addendum D R6: Hole19 replaces 18Birdies as the phone-app source only when the " +
        "swap was logged in docs/p0/X1.md's Log before the round. Fix the config or set " +
        "hole19SwapLoggedBeforeRound: true if that log entry genuinely predates the round.",
    );
  }

  // B-9: reject a source list that leaks the OTHER app's own identifiers.
  const otherAppHint = OTHER_APP_HINT[phoneApp.appUsed];
  if (
    containsOtherAppHint(phoneApp.iosSourceNames, otherAppHint) ||
    containsOtherAppHint(phoneApp.androidDataOrigins, otherAppHint)
  ) {
    throw new Error(
      `sourceMap.phoneApp lists an identifier that looks like the OTHER app ("${otherAppHint}") while ` +
        `appUsed is "${phoneApp.appUsed}" — R6: extra apps are supplementary, never the source verdict. ` +
        "Remove that identifier from phoneApp's source lists (list it under a separate, non-verdict entry " +
        "if it needs recording at all).",
    );
  }

  // Decision 0005: every workout/session counts — no round-window
  // exclusion. `input.ios.workouts` / `input.android.sessions` are used
  // directly (previously `iosWorkoutsInWindow` / `androidSessionsInWindow`
  // were filtered by the window first).
  const garminIos = iosVerdictFor(
    input.ios.workouts,
    input.sourceMap.garmin.iosSourceNames,
    warnings,
    "Garmin (iOS)",
  );
  const garminAndroid = androidVerdictFor(
    input.android.sessions,
    input.sourceMap.garmin.androidDataOrigins,
    followUps,
    warnings,
    "Garmin (Android)",
  );

  const appleWatchIos = iosVerdictFor(
    input.ios.workouts,
    input.sourceMap.appleWatch.iosSourceNames,
    warnings,
    "Apple Watch (iOS)",
  );
  // No Apple Watch on Android (device-protocol.md §4 results table).
  const appleWatchAndroid: SourceOsVerdict = "not-applicable";

  const phoneAppIos = iosVerdictFor(
    input.ios.workouts,
    input.sourceMap.phoneApp.iosSourceNames,
    warnings,
    `Phone app ${phoneApp.appUsed} (iOS)`,
  );
  const phoneAppAndroid = androidVerdictFor(
    input.android.sessions,
    input.sourceMap.phoneApp.androidDataOrigins,
    followUps,
    warnings,
    `Phone app ${phoneApp.appUsed} (Android)`,
  );

  // Decision 0005: the per-workout listing + newest-date-per-source, built
  // from the SAME (unfiltered) input arrays as the verdicts above.
  const countedEntries = {
    garmin: [
      ...iosCountedEntries(input.ios.workouts, input.sourceMap.garmin.iosSourceNames, roundWindows),
      ...androidCountedEntries(input.android.sessions, input.sourceMap.garmin.androidDataOrigins, roundWindows),
    ],
    appleWatch: iosCountedEntries(input.ios.workouts, input.sourceMap.appleWatch.iosSourceNames, roundWindows),
    phoneApp: [
      ...iosCountedEntries(input.ios.workouts, input.sourceMap.phoneApp.iosSourceNames, roundWindows),
      ...androidCountedEntries(input.android.sessions, input.sourceMap.phoneApp.androidDataOrigins, roundWindows),
    ],
  };
  const iosOf = (entries: X1CountedEntry[]) => entries.filter((e) => e.os === "ios");
  const androidOf = (entries: X1CountedEntry[]) => entries.filter((e) => e.os === "android");
  const newestCountedWorkoutDateBySource = {
    garmin: {
      ios: newestStart(iosOf(countedEntries.garmin)),
      android: newestStart(androidOf(countedEntries.garmin)),
    },
    appleWatch: {
      ios: newestStart(iosOf(countedEntries.appleWatch)),
      android: null,
    },
    phoneApp: {
      ios: newestStart(iosOf(countedEntries.phoneApp)),
      android: newestStart(androidOf(countedEntries.phoneApp)),
    },
  };

  const garmin: SourceVerdict = {
    ios: garminIos,
    android: garminAndroid,
    passesOnAnyOS: garminIos === "pass" || garminAndroid === "pass",
  };
  const appleWatch: SourceVerdict = {
    ios: appleWatchIos,
    android: appleWatchAndroid,
    passesOnAnyOS: appleWatchIos === "pass",
  };
  const phoneAppVerdict: PhoneAppSourceVerdict = {
    appUsed: phoneApp.appUsed,
    ios: phoneAppIos,
    android: phoneAppAndroid,
    passesOnAnyOS: phoneAppIos === "pass" || phoneAppAndroid === "pass",
  };

  // Gate finding B-6 / decision 0001 Addendum F "X1 'on ≥ 1 OS'": the bar
  // is ≥ 2 of 3 sources passing on ONE operating system — sources that pass
  // on DIFFERENT OSes do not combine. So count passes PER OS, never a
  // per-source "passes anywhere" tally.
  const sourcesPassingByOs = {
    ios: [garmin.ios, appleWatch.ios, phoneAppVerdict.ios].filter(
      (v) => v === "pass",
    ).length,
    android: [
      garmin.android,
      appleWatch.android,
      phoneAppVerdict.android,
    ].filter((v) => v === "pass").length,
  };
  const overallVerdict: "pass" | "kill" =
    sourcesPassingByOs.ios >= 2 || sourcesPassingByOs.android >= 2
      ? "pass"
      : "kill";

  // docs/p0/K4.md: "if ... X1's Garmin source specifically fails (even
  // while X1 passes overall on the other two sources)" the written
  // statement is required — i.e. Garmin not passing on any tested OS. This
  // is a per-source ("any OS") question, distinct from the per-OS 2-of-3
  // combination bar above, so `passesOnAnyOS` is kept for it.
  const garminWrittenStatementTriggeredByX1 = !garmin.passesOnAnyOS;

  return {
    generatedAt: new Date().toISOString(),
    perSource: { garmin, appleWatch, phoneApp: phoneAppVerdict },
    sourcesPassingByOs,
    overallVerdict,
    garminWrittenStatementTriggeredByX1,
    countedEntries,
    newestCountedWorkoutDateBySource,
    warnings,
  };
}

export function renderVerdictMarkdown(result: X1VerdictResult): string {
  const lines: string[] = [];
  lines.push("| Source | iOS | Android | Passes on ≥ 1 OS? |");
  lines.push("|---|---|---|---|");
  lines.push(
    `| Garmin watch + Connect Mobile | ${result.perSource.garmin.ios} | ${result.perSource.garmin.android} | ${result.perSource.garmin.passesOnAnyOS ? "Yes" : "No"} |`,
  );
  lines.push(
    `| Apple Watch Workout | ${result.perSource.appleWatch.ios} | ${result.perSource.appleWatch.android} | ${result.perSource.appleWatch.passesOnAnyOS ? "Yes" : "No"} |`,
  );
  lines.push(
    `| Phone app (${result.perSource.phoneApp.appUsed}) | ${result.perSource.phoneApp.ios} | ${result.perSource.phoneApp.android} | ${result.perSource.phoneApp.passesOnAnyOS ? "Yes" : "No"} |`,
  );
  lines.push("");
  lines.push(
    `**Sources passing per OS: iOS ${result.sourcesPassingByOs.ios} of 3, Android ${result.sourcesPassingByOs.android} of 3** ` +
      "(decision 0001 Addendum F: sources passing on different OSes do not combine).",
  );
  lines.push(
    `**X1 overall verdict: ${result.overallVerdict.toUpperCase()}** (bar: ≥ 2 of 3 on ONE OS).`,
  );
  lines.push(
    `**K4 Garmin written statement triggered by X1: ${result.garminWrittenStatementTriggeredByX1 ? "YES" : "no"}** (K4b failing independently also triggers it; not assessed by this tool).`,
  );

  // Decision 0005: newest counted workout date, per source per OS.
  lines.push("");
  lines.push("## Newest counted workout date, per source");
  lines.push("| Source | Newest iOS date | Newest Android date |");
  lines.push("|---|---|---|");
  for (const [label, key] of [
    ["Garmin watch + Connect Mobile", "garmin"],
    ["Apple Watch Workout", "appleWatch"],
    [`Phone app (${result.perSource.phoneApp.appUsed})`, "phoneApp"],
  ] as const) {
    const d = result.newestCountedWorkoutDateBySource[key];
    lines.push(`| ${label} | ${d.ios ?? "(none)"} | ${d.android ?? "(none)"} |`);
  }

  // Decision 0005 "every counted workout is listed" — the per-workout
  // listing, one row per counted entry across all 3 sources.
  lines.push("");
  lines.push("## Counted workouts/sessions");
  lines.push("| Source | OS | Start | Source id | Source version | Device | Route present? | Test round? |");
  lines.push("|---|---|---|---|---|---|---|---|");
  const allEntries: [string, X1CountedEntry][] = [
    ...result.countedEntries.garmin.map((e): [string, X1CountedEntry] => ["Garmin watch + Connect Mobile", e]),
    ...result.countedEntries.appleWatch.map((e): [string, X1CountedEntry] => ["Apple Watch Workout", e]),
    ...result.countedEntries.phoneApp.map((e): [string, X1CountedEntry] => [
      `Phone app (${result.perSource.phoneApp.appUsed})`,
      e,
    ]),
  ];
  if (allEntries.length === 0) {
    lines.push("| _(none)_ | — | — | — | — | — | — | — |");
  } else {
    for (const [label, e] of allEntries) {
      lines.push(
        `| ${label} | ${e.os === "ios" ? "iOS" : "Android"} | ${e.start ?? "(unknown)"} | ${e.sourceBundleId ?? "(none)"} | ${e.sourceVersion ?? "(none)"} | ${e.device ?? "(none)"} | ${e.routePresent ? "Yes" : "No"} | ${e.testRound ? "Yes" : "No"} |`,
      );
    }
  }
  return lines.join("\n");
}

interface CliArgs {
  iosPath: string;
  androidPath: string;
  followUpsPath?: string;
  sourceMapPath: string;
  outPrefix: string;
  os: X1Os;
  informational: boolean;
}

function parseArgs(argv: string[]): CliArgs {
  const opts: Record<string, string> = {};
  const flags = new Set<string>();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--informational") {
      flags.add("informational");
      continue;
    }
    if (arg && arg.startsWith("--")) {
      opts[arg.slice(2)] = argv[i + 1] ?? "";
      i += 1;
    }
  }
  const {
    ios,
    android,
    "follow-ups": followUps,
    "source-map": sourceMap,
    out,
    os,
  } = opts;
  if (!ios || !android || !sourceMap || !os) {
    throw new Error(
      "Usage: node dist/x1-verdict.js --ios <x1-ios-export.json> --android <health-connect-reader.json> " +
        "--source-map <source-map.json> --os ios|android [--follow-ups <follow-ups.json>] " +
        "[--informational] [--out <prefix>]",
    );
  }
  if (os !== "ios" && os !== "android") {
    throw new Error(`--os must be "ios" or "android", got "${os}".`);
  }
  return {
    iosPath: ios,
    androidPath: android,
    sourceMapPath: sourceMap,
    outPrefix: out || "x1-verdict-result",
    os,
    informational: flags.has("informational"),
    ...(followUps ? { followUpsPath: followUps } : {}),
  };
}

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  const ios = JSON.parse(
    await readFile(args.iosPath, "utf8"),
  ) as X1IosExportResult;
  const android = JSON.parse(
    await readFile(args.androidPath, "utf8"),
  ) as AndroidGolfSessionReadResult;
  const sourceMap = JSON.parse(
    await readFile(args.sourceMapPath, "utf8"),
  ) as SourceMap;
  const androidRouteFollowUps = args.followUpsPath
    ? (JSON.parse(await readFile(args.followUpsPath, "utf8")) as Record<
        string,
        AndroidRouteFollowUp
      >)
    : undefined;
  const roundWindows = await readLoggedRoundWindows();
  const { dates: recordedExportDates, source } = await readRecordedExportDates();
  if (!args.informational) {
    assertRecordedExportDateLogged(recordedExportDates, args.os);
  }
  const recorded = !args.informational;

  const result = computeX1Verdict({
    ios,
    android,
    sourceMap,
    roundWindows,
    ...(androidRouteFollowUps ? { androidRouteFollowUps } : {}),
  });
  const banner = recorded ? "" : `${informationalBanner(args.os)}\n\n`;
  const md = banner + renderVerdictMarkdown(result);
  const output = { ...result, os: args.os, recorded, source };

  const { writeFile } = await import("node:fs/promises");
  await writeFile(
    `${args.outPrefix}.json`,
    `${JSON.stringify(output, null, 2)}\n`,
    "utf8",
  );
  await writeFile(`${args.outPrefix}.md`, `${md}\n`, "utf8");
  process.stdout.write(`${md}\n`);
}

/** Gate finding B-11 (the N7 symlink bug, again): real-path comparison —
 * see x1-ios-export.ts's identical fix for why the naive comparison this
 * replaced silently never ran `main` (exiting 0) through a symlink. */
async function isMainModule(): Promise<boolean> {
  if (!process.argv[1]) return false;
  try {
    const [herePath, argvPath] = await Promise.all([
      realpath(fileURLToPath(import.meta.url)),
      realpath(process.argv[1]),
    ]);
    return herePath === argvPath;
  } catch {
    return false;
  }
}

if (await isMainModule()) {
  main(process.argv.slice(2)).catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`x1-verdict: ${message}\n`);
    process.exitCode = 1;
  });
}
