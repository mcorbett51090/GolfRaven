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
 * **Round-1 Opus-gate correction (post-d0de4b8):** closed a leak where a
 * recorded run for one OS could silently borrow the OTHER OS's raw data to
 * decide the overall verdict.
 *
 * **Round-2 Opus-gate correction (post-67bdb27), superseding round 1's own
 * fix:** round 1's fix still trusted a `recorded`/`os` field INSIDE the
 * `--ios`/`--android` JSON itself to decide eligibility — a hand-editable
 * claim, not a verified one. That trust is gone: `computeX1Verdict` (this
 * pure function) has no "eligible" concept at all — it has no filesystem
 * access, so it can't verify anything, and doesn't try.
 * `recordedVerdicts.ios` / `.android` are unconditionally computed FROM
 * DATA ALONE (`sourcesPassingByOs` restated per OS). Whether either is
 * actually the recorded result belongs entirely to the CLI.
 *
 * **Round-3 Opus-gate correction (post-8e5a29b), simplifying round 2's
 * mechanism — no stored `result:` line, no separate `--ios <json>` to
 * distrust, no git-log tampering scan:**
 *
 * - **No stored result. A recorded run RECOMPUTES every bound OS's
 *   verdict, every time, from that OS's bound file.** `x1-verdict` takes
 *   `--ios-export <dir>` (the raw Apple Health export directory — not a
 *   pre-computed `x1-ios-export` JSON) and/or `--android <json>` (the
 *   reader's raw output). For each one supplied, on a recorded run: verify
 *   its UTC date and SHA-256 against `docs/p0/X1.md` (binding them on the
 *   first run), THEN recompute that OS's pass/kill straight from the
 *   verified data. There is no separate "claimed" JSON to disagree with
 *   any more — this eliminates round 2's whole `assertIosWorkoutDataNotTampered`
 *   tamper-detection path, because there's nothing left to tamper with
 *   independently of the bound file itself.
 * - **A recorded run needs the bound input of every OS that already has a
 *   bound hash.** If `docs/p0/X1.md` shows an OS as bound but its input
 *   wasn't supplied this run, that's refused — the overall result is never
 *   guessed from a partial picture.
 * - **The overall result is computed in-process, this call, from however
 *   many OSes were recomputed** — "pass" if any of them came back "pass".
 *   Nothing is ever read back from a markdown line.
 * - **No informational runs on real data while an OS is unbound** (whether
 *   its date is blank or logged) **— fixtures only**, and **the first-bind
 *   trust limit**: whatever file binds an OS first is trusted as that
 *   device's genuine output; there's no way to verify it further. Local
 *   git history CAN be rewritten (a rebase/amend) without detection — the
 *   actual protection is committing AND PUSHING `docs/p0/X1.md`
 *   immediately after binding (decision 0001 Addendum F's own K2
 *   precedent). See `recorded-export.ts`'s module doc for all of this.
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
  assertBoundInputProvided,
  assertExportDateMatches,
  assertInformationalInputAllowed,
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

/** Round-2 Opus-gate correction (post-67bdb27): one OS's own verdict,
 * computed UNCONDITIONALLY from that OS's data alone (`sourcesPassingByOs`
 * restated per OS) — no "eligible"/trust concept here at all, because a
 * pure function with no filesystem/git access cannot verify anything.
 * Whether this verdict IS the recorded X1 result for that OS is decided
 * entirely by the CLI (`main()`), from real hash-binding — never from
 * this object, and never from any `recorded`/`os` field an input claims. */
export interface X1RecordedOsResult {
  sourcesPassing: number;
  verdict: "pass" | "kill";
}

export interface X1VerdictResult {
  generatedAt: string;
  /** INFORMATIONAL (round-2 Opus-gate correction, post-67bdb27) — computed
   * from BOTH inputs' raw data. This function has no way to know which OS
   * (if either) a caller intends as "the recorded run" — that decision,
   * and the verification behind it, belongs entirely to the CLI. See the
   * module doc. */
  perSource: {
    garmin: SourceVerdict;
    appleWatch: SourceVerdict;
    phoneApp: PhoneAppSourceVerdict;
  };
  /** INFORMATIONAL — see `perSource` above. Gate finding B-6: how many
   * of the 3 sources pass ON EACH OS independently — the bar is "≥ 2 of 3
   * sources pass on ONE OS", not "≥ 2 of 3 pass somewhere, possibly on
   * different OSes" (decision 0001 Addendum F). */
  sourcesPassingByOs: { ios: number; android: number };
  /** INFORMATIONAL (round-2 Opus-gate correction) — `sourcesPassingByOs`
   * restated as a per-OS pass/kill verdict, unconditionally, ignoring any
   * `recorded`/`os` field on the inputs entirely. NOT the recorded result
   * — see the module doc and `main()`'s `recordedOverall`/git-verified
   * per-OS binding for that. */
  recordedVerdicts: { ios: X1RecordedOsResult; android: X1RecordedOsResult };
  /** INFORMATIONAL (round-2 Opus-gate correction) — "pass" if either OS's
   * `recordedVerdicts` entry is "pass" (Addendum F's bar, applied within
   * each OS's own data); "kill" otherwise. Computed from THIS call's two
   * inputs only — never confused with the CLI's `recordedOverall`, which
   * combines two SEPARATE, independently-verified runs read back from
   * `docs/p0/X1.md`. */
  overallVerdict: "pass" | "kill";
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
  ios: X1IosExportResult;
  /** `os` is REQUIRED here — "The Android reader output must carry os and
   * generatedAt." This is a basic shape/operator-error guard (e.g. catching
   * the iOS export.xml directory's own data accidentally passed as
   * `--android`), checked unconditionally by the CLI — it is NOT a trust
   * mechanism, and never makes this OS's data "recorded" (that requires
   * real, independently-verified hash binding; see the module doc).
   * Round-3 Opus-gate correction (post-8e5a29b): the apps/mobile Health
   * Connect reader itself now emits `os: "android"` (and `generatedAt`) as
   * part of its own real output — the bound file is that untouched output,
   * never hand-annotated. */
  android: AndroidGolfSessionReadResult & { os: X1Os };
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
  // Round-2 Opus-gate correction (post-67bdb27): purely DATA-DRIVEN, no
  // "eligible"/trust concept — this pure function has no filesystem/git
  // access to verify anything, so it doesn't pretend to. Any `recorded`/
  // `os` field an input might carry is not read here at all. Whether
  // either of these is actually the recorded X1 result for its OS is
  // decided entirely by the CLI (`main()`), from real, independently
  // verified hash binding — see the module doc.
  const recordedVerdicts: X1VerdictResult["recordedVerdicts"] = {
    ios: { sourcesPassing: sourcesPassingByOs.ios, verdict: sourcesPassingByOs.ios >= 2 ? "pass" : "kill" },
    android: {
      sourcesPassing: sourcesPassingByOs.android,
      verdict: sourcesPassingByOs.android >= 2 ? "pass" : "kill",
    },
  };

  // INFORMATIONAL (this call's two inputs only) — "pass if either OS's own
  // verdict is pass" (Addendum F's bar, applied within each OS's data).
  const overallVerdict: "pass" | "kill" =
    recordedVerdicts.ios.verdict === "pass" || recordedVerdicts.android.verdict === "pass" ? "pass" : "kill";

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
  // Round-2 Opus-gate correction (post-67bdb27): this WHOLE render is now
  // purely informational — the recorded verdict (per OS, git-verified) is
  // CLI-only state that `main()` renders separately, above this, and
  // reads back from docs/p0/X1.md rather than from anything in `result`.
  lines.push(
    "> **INFORMATIONAL — computed from BOTH inputs' raw data.** Not the recorded X1 result; see the " +
      '"Recorded verdict" section above this one (added by the CLI, from git-verified per-OS state in ' +
      "docs/p0/X1.md — never from this function's output).",
  );
  lines.push("");
  lines.push(
    `Per-OS verdict from this call's data alone: iOS ${result.recordedVerdicts.ios.verdict.toUpperCase()} ` +
      `(${result.recordedVerdicts.ios.sourcesPassing}/3), Android ${result.recordedVerdicts.android.verdict.toUpperCase()} ` +
      `(${result.recordedVerdicts.android.sourcesPassing}/3). Combined (informational): ` +
      `${result.overallVerdict.toUpperCase()}.`,
  );
  lines.push(
    `K4 Garmin written statement triggered by X1 (informational): ${result.garminWrittenStatementTriggeredByX1 ? "YES" : "no"} (K4b failing independently also triggers it; not assessed by this tool).`,
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
  iosExportDir: string | undefined;
  androidPath: string | undefined;
  followUpsPath?: string;
  sourceMapPath: string;
  outPrefix: string;
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
    "ios-export": iosExportDir,
    android: androidPath,
    "follow-ups": followUps,
    "source-map": sourceMap,
    out,
  } = opts;
  if (!sourceMap || (!iosExportDir && !androidPath)) {
    throw new Error(
      "Usage: node dist/x1-verdict.js [--ios-export <apple_health_export-dir>] [--android <health-connect-reader.json>] " +
        "--source-map <source-map.json> [--follow-ups <follow-ups.json>] [--informational] [--out <prefix>] " +
        "(at least one of --ios-export / --android is required)",
    );
  }
  return {
    iosExportDir: iosExportDir || undefined,
    androidPath: androidPath || undefined,
    sourceMapPath: sourceMap,
    outPrefix: out || "x1-verdict-result",
    informational: flags.has("informational"),
    ...(followUps ? { followUpsPath: followUps } : {}),
  };
}

function sha256Of(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

function osLabel(os: X1Os): string {
  return os === "ios" ? "iOS" : "Android";
}

/**
 * Round-3 Opus-gate correction (post-8e5a29b): "The overall result is a
 * pass if any bound OS recomputes to a pass" — combines whatever this run
 * actually recomputed (never read back from a markdown line). `boundResults`
 * holds 0, 1, or 2 entries (`main()` refuses a recorded run with 0 before
 * this is ever called).
 */
export function computeOverallFromBoundResults(boundResults: Partial<Record<X1Os, "pass" | "kill">>): "pass" | "kill" {
  return Object.values(boundResults).includes("pass") ? "pass" : "kill";
}

const EMPTY_IOS: X1IosExportResult = {
  generatedAt: new Date(0).toISOString(),
  exportDir: "",
  since: null,
  roundWindows: [],
  totalWorkoutElementsSeen: 0,
  golfWorkoutCount: 0,
  workouts: [],
  sourceSummaries: [],
  exportDate: null,
  exportSha256: "",
  warnings: [],
};

const EMPTY_ANDROID: X1VerdictInput["android"] = {
  generatedAt: new Date(0).toISOString(),
  windowDays: 0,
  sessionCount: 0,
  sessions: [],
  os: "android",
};

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  const { resolve, join } = await import("node:path");
  const { runX1IosExport } = await import("./x1-ios-export.js");

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
  const recorded = !args.informational;

  // Round-3 Opus-gate correction (post-8e5a29b): no `--os` flag any more —
  // each OS is processed if (and only if) its input flag was supplied.
  // `iosData`/`androidData` feed the INFORMATIONAL combined view below,
  // regardless of recorded/informational; `boundResults` holds only what
  // was actually verified-and-recomputed THIS run, for a recorded run.
  let iosData: X1IosExportResult | null = null;
  let androidData: X1VerdictInput["android"] | null = null;
  let androidRaw: string | null = null;
  const boundResults: Partial<Record<X1Os, "pass" | "kill">> = {};
  let iosBoundThisRun = false;
  let androidBoundThisRun = false;
  let exportXmlProvenance: { path: string; sha256: string } | null = null;

  if (args.iosExportDir) {
    if (!recorded) {
      // No informational runs on real data while iOS is unbound (whether
      // its UTC date is blank or logged) — fixtures only.
      assertInformationalInputAllowed(recordedExportDates, "ios", args.iosExportDir);
    }
    const freshIos = await runX1IosExport(args.iosExportDir, { roundWindows });
    iosData = freshIos;
    exportXmlProvenance = { path: join(args.iosExportDir, "export.xml"), sha256: freshIos.exportSha256 };

    if (recorded) {
      assertRecordedExportDateLogged(recordedExportDates, "ios");
      if (freshIos.exportDate === null) {
        throw new Error(
          `export.xml at ${join(args.iosExportDir, "export.xml")} has no <ExportDate> element — refusing a ` +
            "recorded run: decision 0005 requires binding to one specific export, and there is nothing to " +
            "compare against docs/p0/X1.md's logged UTC date. Pass --informational to run anyway.",
        );
      }
      // Re-hash export.xml and check it against the bound SHA-256, THEN
      // (only once that's confirmed) use its re-parsed workouts.
      assertExportDateMatches(recordedExportDates, "ios", extractCalendarDate(freshIos.exportDate));
      const { written } = await bindExportHash(x1DocSource.path, "ios", freshIos.exportSha256);
      iosBoundThisRun = written;
      const r = computeX1Verdict({ ios: freshIos, android: EMPTY_ANDROID, sourceMap, roundWindows });
      boundResults.ios = r.recordedVerdicts.ios.verdict;
    }
  } else if (recorded) {
    // iOS is bound but its input wasn't supplied — refusing rather than
    // guessing the overall result from a partial picture.
    assertBoundInputProvided(recordedExportDates, "ios", false);
  }

  if (args.androidPath) {
    // Basic shape validation runs FIRST, regardless of recorded/
    // informational — a structurally wrong file is refused before any
    // trust-related check even considers it.
    androidRaw = await readFile(args.androidPath, "utf8");
    const androidParsed = JSON.parse(androidRaw) as X1VerdictInput["android"];
    if (androidParsed.os !== "android") {
      throw new Error(
        `--android's JSON has os = ${JSON.stringify(androidParsed.os)}, not "android" — this doesn't look ` +
          "like the Android Health Connect reader's output (wrong file passed to --android?).",
      );
    }
    if (!androidParsed.generatedAt) {
      throw new Error(
        "--android's JSON has no generatedAt — this doesn't look like the Android Health Connect reader's " +
          "output (wrong file passed to --android?).",
      );
    }
    if (!recorded) {
      assertInformationalInputAllowed(recordedExportDates, "android", args.androidPath);
    }
    androidData = androidParsed;

    if (recorded) {
      assertRecordedExportDateLogged(recordedExportDates, "android");
      // Re-hash the reader-output JSON and check it against the bound
      // SHA-256, THEN (only once that's confirmed) use its parsed sessions.
      assertExportDateMatches(recordedExportDates, "android", extractCalendarDate(androidParsed.generatedAt));
      const { written } = await bindExportHash(x1DocSource.path, "android", sha256Of(androidRaw));
      androidBoundThisRun = written;
      const r = computeX1Verdict({ ios: EMPTY_IOS, android: androidParsed, sourceMap, roundWindows });
      boundResults.android = r.recordedVerdicts.android.verdict;
    }
  } else if (recorded) {
    assertBoundInputProvided(recordedExportDates, "android", false);
  }

  if (recorded && Object.keys(boundResults).length === 0) {
    throw new Error(
      "Nothing to record: no OS has both a logged UTC date and its input supplied this run. Log a UTC date " +
        'in docs/p0/X1.md\'s "## Recorded export" section for the OS you\'re binding, and pass its ' +
        "--ios-export/--android input.",
    );
  }

  // INFORMATIONAL combined view (perSource/sourcesPassingByOs/countedEntries/
  // etc.) — always computed, from whichever real data was supplied (an
  // omitted OS renders as an empty placeholder, informationally harmless).
  const result = computeX1Verdict({
    ios: iosData ?? EMPTY_IOS,
    android: androidData ?? EMPTY_ANDROID,
    sourceMap,
    roundWindows,
    ...(androidRouteFollowUps ? { androidRouteFollowUps } : {}),
  });

  let recordedSection = "";
  if (recorded) {
    const lines: string[] = ["## Recorded verdict, per OS", ""];
    for (const os of ["ios", "android"] as const) {
      const r = boundResults[os];
      lines.push(
        r !== undefined
          ? `**X1 recorded on ${osLabel(os)}: ${r.toUpperCase()}** (recomputed fresh from the bound file this run).`
          : `**X1 recorded on ${osLabel(os)}: not attempted this run** (no bound hash, and no input supplied).`,
      );
    }
    const overall = computeOverallFromBoundResults(boundResults);
    lines.push("");
    lines.push(
      `**X1 overall recorded result: ${overall.toUpperCase()}** (pass if any bound OS recomputes to a pass).`,
    );
    if (iosBoundThisRun || androidBoundThisRun) {
      lines.push("");
      lines.push("This run bound new state into docs/p0/X1.md — **commit and push docs/p0/X1.md now**.");
    }
    recordedSection = `${lines.join("\n")}\n\n`;
  }
  const banner = recorded
    ? ""
    : "> **INFORMATIONAL — NOT THE RECORDED X1 RESULT.**\n" +
      "> Decision 0005: this run never binds or verifies anything against docs/p0/X1.md; it never replaces " +
      "the recorded result and is not the P0 verdict.\n\n";
  const md = recordedSection + banner + renderVerdictMarkdown(result);

  const provenance = {
    x1Doc: x1DocSource,
    exportXml: exportXmlProvenance,
    androidJson:
      args.androidPath && androidRaw !== null
        ? { path: resolve(args.androidPath), sha256: sha256Of(androidRaw) }
        : null,
    sourceMapJson: { path: resolve(args.sourceMapPath), sha256: sha256Of(sourceMapRaw) },
    followUpsJson:
      args.followUpsPath && followUpsRaw !== undefined
        ? { path: resolve(args.followUpsPath), sha256: sha256Of(followUpsRaw) }
        : null,
  };
  const recordedOverall: "pass" | "kill" | null = recorded ? computeOverallFromBoundResults(boundResults) : null;
  const output = { ...result, recorded, boundResults, recordedOverall, provenance };

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
