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
 *   round-window refusal as the CLI's gate.
 *
 * **Opus-gate correction (post-d0de4b8, superseding the two paragraphs
 * above about how "recorded" combines across OSes):** the original fix let
 * a recorded run for one OS silently borrow the OTHER OS's raw data to
 * decide `overallVerdict` — an `--os ios` run backed by an `ios` JSON
 * stamped `recorded: false` could still report an overall PASS purely from
 * `android`'s (unstamped, unverified) sessions. That is now closed:
 *
 * - **A recorded verdict is per OS, decided from that OS's data alone.**
 *   `computeX1Verdict` computes `recordedVerdicts.ios` / `.android`
 *   independently, each `eligible` only when that OS's own input object
 *   carries `recorded === true` and (if it states one) a matching `os`
 *   field — i.e. it is itself the JSON a recorded `x1-ios-export`/Android
 *   reader run produced, not an `--informational` one or the wrong OS's
 *   file. An ineligible OS's data still appears in the informational
 *   sections below (`perSource`, `sourcesPassingByOs`, `countedEntries`)
 *   — clearly separate, and NEVER folded into `recordedVerdicts` or
 *   `overallVerdict`.
 * - **`overallVerdict`** ("pass" | "kill" | "not-recorded") is now derived
 *   ONLY from `recordedVerdicts`: "pass" if either eligible OS's own
 *   verdict is "pass" (Addendum F's ≥ 2-of-3-on-one-OS bar, applied WITHIN
 *   that OS's data only); "kill" if at least one OS is eligible and none
 *   passed; "not-recorded" if NEITHER OS is eligible — there is then no
 *   trustworthy recorded result to report at all, which is what the old
 *   code got wrong (it would still compute a "pass"/"kill" from raw,
 *   unstamped data).
 * - **The CLI still takes `--os ios|android`,** naming which OS this run
 *   claims to produce THE recorded result for, and now additionally
 *   REFUSES (throws, before writing any output) when
 *   `recordedVerdicts[--os].eligible` is false — i.e., when the input JSON
 *   for that OS is not itself stamped `recorded: true` for that OS.
 *   `--informational` skips this refusal entirely (and skips the
 *   export-date/SHA-256 binding below).
 * - **The recorded run is also bound to one specific export** (its own
 *   correction, not a d0de4b8 regression): Apple's `<ExportDate>` /
 *   the Android reader's `generatedAt` must match the calendar date logged
 *   in `docs/p0/X1.md`, and its SHA-256 is bound there on the first
 *   recorded run and checked on every later one — see `recorded-export.ts`
 *   and `x1-ios-export.ts`'s module doc for the mechanism.
 */
import { createHash } from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import type { X1IosExportResult, X1IosWorkoutRecord } from "./x1-ios-export.js";
import {
  isWithinRoundWindow,
  readLoggedRoundWindows,
  type RoundWindow,
} from "./round-windows.js";
import {
  assertExportDateMatches,
  assertRecordedExportDateLogged,
  bindExportHash,
  extractCalendarDate,
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

/** Opus-gate correction (post-d0de4b8): one OS's slice of the recorded
 * verdict. `eligible` is true only when that OS's own input object is
 * itself stamped `recorded: true` (and, if it states one, `os` matching
 * this OS) — i.e. it is the JSON a RECORDED run of that OS's export tool
 * produced. When `eligible` is false, `verdict` is `null` and
 * `ineligibleReason` says why (never silently defaulted to a verdict). */
export interface X1RecordedOsResult {
  eligible: boolean;
  ineligibleReason: string | null;
  /** How many of the 3 sources passed on this OS — meaningful only when
   * `eligible`; still populated (mirrors `sourcesPassingByOs`) when not,
   * for visibility, but MUST NOT be read as a recorded count. */
  sourcesPassing: number;
  verdict: "pass" | "kill" | null;
}

export interface X1VerdictResult {
  generatedAt: string;
  /** INFORMATIONAL ONLY (Opus-gate correction, post-d0de4b8) — computed
   * from BOTH inputs' raw data regardless of their `recorded`/`os` stamps.
   * Never used to decide `recordedVerdicts` or `overallVerdict`; see those
   * fields for the actual recorded result. Kept for visibility (decision
   * 0005 §1's "a separately labelled informational section"). */
  perSource: {
    garmin: SourceVerdict;
    appleWatch: SourceVerdict;
    phoneApp: PhoneAppSourceVerdict;
  };
  /** INFORMATIONAL ONLY — see `perSource` above. Gate finding B-6: how many
   * of the 3 sources pass ON EACH OS independently — the bar is "≥ 2 of 3
   * sources pass on ONE OS", not "≥ 2 of 3 pass somewhere, possibly on
   * different OSes" (decision 0001 Addendum F). */
  sourcesPassingByOs: { ios: number; android: number };
  /** Opus-gate correction (post-d0de4b8): the per-OS recorded verdict,
   * decided from EACH OS's own data alone — never combined across OSes.
   * See the module doc. */
  recordedVerdicts: { ios: X1RecordedOsResult; android: X1RecordedOsResult };
  /** "pass" if either eligible OS's `recordedVerdicts` entry is "pass";
   * "kill" if at least one OS is eligible and none passed; "not-recorded"
   * if NEITHER OS is eligible — there is then no trustworthy recorded
   * result at all. Derived ONLY from `recordedVerdicts`, never from the
   * informational `sourcesPassingByOs` above (that was the leak). */
  overallVerdict: "pass" | "kill" | "not-recorded";
  /** Whether X1's half of the K4 written-statement trigger fires
   * (`docs/p0/K4.md`: "if K4b fails, or if X1's Garmin source specifically
   * fails ... a written statement ... must go to the owner before P1").
   * This tool has no K4b data, so it can only assess the X1 side; K4b
   * failing independently also triggers the statement and is not
   * reflected here. INFORMATIONAL (built from `perSource.garmin`, same
   * caveat as above). */
  garminWrittenStatementTriggeredByX1: boolean;
  /** INFORMATIONAL — every counted workout/session matched to one of the 3
   * sources, listed with its date, source id, and (iOS only) version and
   * device — the per-workout listing (decision 0005). */
  countedEntries: {
    garmin: X1CountedEntry[];
    appleWatch: X1CountedEntry[];
    phoneApp: X1CountedEntry[];
  };
  /** Decision 0005: "The memo shows, per source, the newest counted
   * workout's date" — per source, per OS. Should-fix (Opus gate,
   * post-d0de4b8): covers only entries that count toward the verdict
   * (route present); a route-less entry's date is tracked separately in
   * `newestRouteLessWorkoutDateBySource`, never conflated with this one. */
  newestCountedWorkoutDateBySource: {
    garmin: X1NewestDateByOs;
    appleWatch: X1NewestDateByOs;
    phoneApp: X1NewestDateByOs;
  };
  /** Should-fix (Opus gate, post-d0de4b8): the newest counted workout
   * WITHOUT a route, per source per OS — visible, but never counted as
   * the verdict-bearing "newest counted workout date" above. */
  newestRouteLessWorkoutDateBySource: {
    garmin: X1NewestDateByOs;
    appleWatch: X1NewestDateByOs;
    phoneApp: X1NewestDateByOs;
  };
  warnings: string[];
}

export interface X1VerdictInput {
  /** Opus-gate correction (post-d0de4b8): the `recorded`/`os` fields are
   * whatever a recorded `x1-ios-export` run stamped into its JSON output
   * (optional here so plain/synthetic `X1IosExportResult` data — e.g. an
   * informational combined view, or a test fixture — still type-checks;
   * `computeX1Verdict` treats a missing/false `recorded` as "not eligible
   * for a recorded verdict on this OS", never as a permissive default). */
  ios: X1IosExportResult & Partial<{ os: X1Os; recorded: boolean }>;
  /** Opus-gate correction (post-d0de4b8): same stamp convention as `ios`
   * above — the apps/mobile Health Connect reader itself doesn't produce
   * these fields (that package is out of this repo's lane), so whoever
   * prepares a RECORDED Android run's input JSON stamps `recorded: true,
   * os: "android"` onto it by hand or with a small wrapper, mirroring what
   * `x1-ios-export --os ios` does automatically. */
  android: AndroidGolfSessionReadResult & Partial<{ os: X1Os; recorded: boolean }>;
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
  // Should-fix (Opus gate, post-d0de4b8): "newest counted workout date"
  // covers only entries that count TOWARD THE VERDICT — golf, allow-listed
  // source (both already true of everything in `countedEntries`), AND
  // route present. A route-less entry's date is tracked separately below,
  // never allowed to pull the verdict-bearing date forward.
  const withRoute = (entries: X1CountedEntry[]) => entries.filter((e) => e.routePresent);
  const withoutRoute = (entries: X1CountedEntry[]) => entries.filter((e) => !e.routePresent);
  const newestCountedWorkoutDateBySource = {
    garmin: {
      ios: newestStart(withRoute(iosOf(countedEntries.garmin))),
      android: newestStart(withRoute(androidOf(countedEntries.garmin))),
    },
    appleWatch: {
      ios: newestStart(withRoute(iosOf(countedEntries.appleWatch))),
      android: null,
    },
    phoneApp: {
      ios: newestStart(withRoute(iosOf(countedEntries.phoneApp))),
      android: newestStart(withRoute(androidOf(countedEntries.phoneApp))),
    },
  };
  const newestRouteLessWorkoutDateBySource = {
    garmin: {
      ios: newestStart(withoutRoute(iosOf(countedEntries.garmin))),
      android: newestStart(withoutRoute(androidOf(countedEntries.garmin))),
    },
    appleWatch: {
      ios: newestStart(withoutRoute(iosOf(countedEntries.appleWatch))),
      android: null,
    },
    phoneApp: {
      ios: newestStart(withoutRoute(iosOf(countedEntries.phoneApp))),
      android: newestStart(withoutRoute(androidOf(countedEntries.phoneApp))),
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
  // Opus-gate correction (post-d0de4b8): per-OS recorded eligibility,
  // decided ONLY from that OS's own input object's `recorded`/`os` stamp —
  // never from the other OS's data, and never from whether the DATA looks
  // good. An input not stamped `recorded: true` (or stamped for a
  // different OS) is ineligible, full stop; see the module doc.
  const osEligibility = (
    stampedRecorded: boolean | undefined,
    stampedOs: X1Os | undefined,
    expectedOs: X1Os,
  ): { eligible: boolean; reason: string | null } => {
    if (stampedRecorded !== true) {
      return {
        eligible: false,
        reason: `input.${expectedOs}.recorded is ${JSON.stringify(stampedRecorded)}, not true — this OS's ` +
          "data was not itself produced by a recorded run.",
      };
    }
    if (stampedOs !== undefined && stampedOs !== expectedOs) {
      return {
        eligible: false,
        reason: `input.${expectedOs}.os is "${stampedOs}", not "${expectedOs}" — this OS's data was produced ` +
          "for a different OS.",
      };
    }
    return { eligible: true, reason: null };
  };

  const iosElig = osEligibility(input.ios.recorded, input.ios.os, "ios");
  const androidElig = osEligibility(input.android.recorded, input.android.os, "android");

  const recordedVerdicts: X1VerdictResult["recordedVerdicts"] = {
    ios: {
      eligible: iosElig.eligible,
      ineligibleReason: iosElig.reason,
      sourcesPassing: sourcesPassingByOs.ios,
      verdict: iosElig.eligible ? (sourcesPassingByOs.ios >= 2 ? "pass" : "kill") : null,
    },
    android: {
      eligible: androidElig.eligible,
      ineligibleReason: androidElig.reason,
      sourcesPassing: sourcesPassingByOs.android,
      verdict: androidElig.eligible ? (sourcesPassingByOs.android >= 2 ? "pass" : "kill") : null,
    },
  };

  // "the overall is a pass if any recorded OS passes" — derived ONLY from
  // recordedVerdicts, never from the informational sourcesPassingByOs
  // above. "not-recorded" (neither OS eligible) is a distinct state from
  // "kill" (at least one OS's OWN recorded data was examined and failed
  // the bar) — the old code conflated these, which was the leak.
  const overallVerdict: "pass" | "kill" | "not-recorded" =
    recordedVerdicts.ios.verdict === "pass" || recordedVerdicts.android.verdict === "pass"
      ? "pass"
      : recordedVerdicts.ios.verdict === "kill" || recordedVerdicts.android.verdict === "kill"
        ? "kill"
        : "not-recorded";

  // docs/p0/K4.md: "if ... X1's Garmin source specifically fails (even
  // while X1 passes overall on the other two sources)" the written
  // statement is required — i.e. Garmin not passing on any tested OS. This
  // is a per-source ("any OS") question, distinct from the per-OS 2-of-3
  // combination bar above, so `passesOnAnyOS` is kept for it.
  // INFORMATIONAL, same caveat as `perSource` (see the module doc).
  const garminWrittenStatementTriggeredByX1 = !garmin.passesOnAnyOS;

  return {
    generatedAt: new Date().toISOString(),
    perSource: { garmin, appleWatch, phoneApp: phoneAppVerdict },
    sourcesPassingByOs,
    recordedVerdicts,
    overallVerdict,
    garminWrittenStatementTriggeredByX1,
    countedEntries,
    newestCountedWorkoutDateBySource,
    newestRouteLessWorkoutDateBySource,
    warnings,
  };
}

export function renderVerdictMarkdown(result: X1VerdictResult): string {
  const lines: string[] = [];

  // Opus-gate correction (post-d0de4b8): the recorded verdict, per OS,
  // leads — this is the actual answer, decided from each OS's own data
  // alone. Everything after "## Informational" is cross-reference only.
  lines.push("## Recorded verdict, per OS");
  for (const [label, os] of [
    ["iOS", "ios"],
    ["Android", "android"],
  ] as const) {
    const r = result.recordedVerdicts[os];
    const state = r.eligible ? (r.verdict === "pass" ? "PASS" : "KILL") : "NOT RECORDED";
    lines.push(`**X1 recorded on ${label}: ${state}**${r.eligible ? "" : ` — ${r.ineligibleReason}`}`);
  }
  lines.push("");
  lines.push(
    `**X1 overall verdict: ${result.overallVerdict.toUpperCase()}** ` +
      "(pass if either recorded OS passes; kill if a recorded OS was examined and failed the ≥ 2-of-3 bar; " +
      "not-recorded if neither OS's input is itself stamped as a recorded run).",
  );
  lines.push(
    `**K4 Garmin written statement triggered by X1: ${result.garminWrittenStatementTriggeredByX1 ? "YES" : "no"}** (K4b failing independently also triggers it; not assessed by this tool; informational, see below).`,
  );

  lines.push("");
  lines.push("## Informational (NOT the recorded result — see \"Recorded verdict\" above)");
  lines.push(
    "Everything below is computed from BOTH inputs' raw data regardless of their `recorded`/`os` stamps — " +
      "cross-OS reference only, never folded into the recorded verdict above.",
  );
  lines.push("");
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
    `Sources passing per OS (informational): iOS ${result.sourcesPassingByOs.ios} of 3, Android ${result.sourcesPassingByOs.android} of 3 ` +
      "(decision 0001 Addendum F: sources passing on different OSes do not combine).",
  );

  // Decision 0005: newest counted workout date, per source per OS.
  lines.push("");
  lines.push("### Newest counted workout date, per source (route present only)");
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

  lines.push("");
  lines.push("### Newest workout WITHOUT a route, per source (does not count toward the verdict)");
  lines.push("| Source | Newest iOS date | Newest Android date |");
  lines.push("|---|---|---|");
  for (const [label, key] of [
    ["Garmin watch + Connect Mobile", "garmin"],
    ["Apple Watch Workout", "appleWatch"],
    [`Phone app (${result.perSource.phoneApp.appUsed})`, "phoneApp"],
  ] as const) {
    const d = result.newestRouteLessWorkoutDateBySource[key];
    lines.push(`| ${label} | ${d.ios ?? "(none)"} | ${d.android ?? "(none)"} |`);
  }

  // Decision 0005 "every counted workout is listed" — the per-workout
  // listing, one row per counted entry across all 3 sources.
  lines.push("");
  lines.push("### Counted workouts/sessions");
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

function sha256Of(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  const { resolve } = await import("node:path");

  // Opus-gate correction (post-d0de4b8), point 3's third bullet: stamp
  // EVERY input file's path + SHA-256 into the output provenance, not just
  // docs/p0/X1.md.
  const iosRaw = await readFile(args.iosPath, "utf8");
  const ios = JSON.parse(iosRaw) as X1VerdictInput["ios"];
  const androidRaw = await readFile(args.androidPath, "utf8");
  const android = JSON.parse(androidRaw) as X1VerdictInput["android"];
  const sourceMapRaw = await readFile(args.sourceMapPath, "utf8");
  const sourceMap = JSON.parse(sourceMapRaw) as SourceMap;
  let followUpsRaw: string | undefined;
  const androidRouteFollowUps = args.followUpsPath
    ? (JSON.parse((followUpsRaw = await readFile(args.followUpsPath, "utf8"))) as Record<
        string,
        AndroidRouteFollowUp
      >)
    : undefined;

  const roundWindows = await readLoggedRoundWindows();
  const { dates: recordedExportDates, source: x1DocSource } = await readRecordedExportDates();
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

  if (recorded) {
    // Point 2: refuse a recorded run when the OS this run claims (--os)
    // isn't itself eligible — its input JSON wasn't recorded, or was
    // produced for a different OS. Checked from computeX1Verdict's own
    // eligibility determination, not re-derived here.
    const osResult = result.recordedVerdicts[args.os];
    if (!osResult.eligible) {
      throw new Error(
        `Refusing a recorded run for --os ${args.os}: ${osResult.ineligibleReason} Pass --informational to ` +
          "run anyway (the output is then marked informational, never the recorded P0 result).",
      );
    }

    // Point 3: bind the recorded run to one specific export — Apple's
    // ExportDate (iOS) or the Android reader's generatedAt (Android) must
    // match docs/p0/X1.md's logged date, and its SHA-256 is bound there on
    // the first recorded run and checked on every later one. iOS is
    // RE-VERIFIED here from the ios JSON's own embedded exportDate/
    // exportSha256 (written by a recorded x1-ios-export run) — this tool
    // never has direct access to export.xml itself, so it trusts those
    // embedded fields the same way it re-checks round windows itself
    // instead of trusting x1-ios-export's own filtering (gate finding B-7
    // philosophy) — a mismatch there still catches a stale/hand-edited
    // ios.json.
    if (args.os === "ios") {
      if (ios.exportDate === undefined || ios.exportDate === null) {
        throw new Error(
          "The --ios JSON has no exportDate — refusing a recorded run: decision 0005 requires binding the " +
            "recorded run to one specific export, and there is nothing to compare against docs/p0/X1.md's " +
            "logged date. Re-run x1-ios-export (not --informational) to produce a properly-stamped file, or " +
            "pass --informational here to run anyway.",
        );
      }
      const exportCalendarDate = extractCalendarDate(ios.exportDate);
      assertExportDateMatches(recordedExportDates, "ios", exportCalendarDate);
      await bindExportHash(x1DocSource.path, recordedExportDates, "ios", ios.exportSha256);
    } else {
      const androidCalendarDate = extractCalendarDate(android.generatedAt);
      assertExportDateMatches(recordedExportDates, "android", androidCalendarDate);
      await bindExportHash(x1DocSource.path, recordedExportDates, "android", sha256Of(androidRaw));
    }
  }

  const banner = recorded ? "" : `${informationalBanner(args.os)}\n\n`;
  const md = banner + renderVerdictMarkdown(result);

  const provenance = {
    x1Doc: x1DocSource,
    iosJson: { path: resolve(args.iosPath), sha256: sha256Of(iosRaw) },
    androidJson: { path: resolve(args.androidPath), sha256: sha256Of(androidRaw) },
    sourceMapJson: { path: resolve(args.sourceMapPath), sha256: sha256Of(sourceMapRaw) },
    followUpsJson:
      args.followUpsPath && followUpsRaw !== undefined
        ? { path: resolve(args.followUpsPath), sha256: sha256Of(followUpsRaw) }
        : null,
    // As recorded in the --ios JSON itself (x1-verdict has no direct
    // access to export.xml — see the ios-side rebind above).
    exportXml:
      ios.exportSha256 !== undefined
        ? { path: `${ios.exportDir}/export.xml`, sha256: ios.exportSha256 }
        : null,
  };
  const output = { ...result, os: args.os, recorded, provenance };

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
