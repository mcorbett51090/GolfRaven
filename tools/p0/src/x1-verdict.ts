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
 */
import { readFile, realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import type { X1IosExportResult, X1IosWorkoutRecord } from "./x1-ios-export.js";
import {
  isWithinRoundWindow,
  readLoggedRoundWindows,
  type RoundWindow,
} from "./round-windows.js";

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
  /** Decision 0001 Addendum F: the logged round window(s) from
   * docs/p0/X1.md's "## Round windows" section — REQUIRED, and enforced
   * here independently of whatever filtering `x1-ios-export` already did,
   * so a stale/unfiltered `ios` JSON can't silently widen the verdict
   * (gate finding B-7). A workout/session whose start time falls outside
   * every window (±60 min) is excluded before any per-source verdict is
   * computed. Empty (no window logged) is a refusal, not a permissive
   * default. */
  roundWindows: RoundWindow[];
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

export function computeX1Verdict(input: X1VerdictInput): X1VerdictResult {
  // Decision 0001 Addendum F: refuse outright with no logged round window
  // — never silently compute a verdict from every workout/session on the
  // device.
  if (!input.roundWindows || input.roundWindows.length === 0) {
    throw new Error(
      "computeX1Verdict requires at least one round window (decision 0001 Addendum F) — refusing to compute " +
        'a verdict with no round window logged in docs/p0/X1.md\'s "## Round windows" section.',
    );
  }

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

  // Gate finding B-7: enforce the round window HERE too, independently of
  // whatever filtering x1-ios-export already did to its JSON — a stale or
  // hand-edited export.json must not widen the verdict.
  const iosWorkoutsInWindow = input.ios.workouts.filter((w) =>
    isWithinRoundWindow(w.startDate, input.roundWindows),
  );
  const androidSessionsInWindow = input.android.sessions.filter((s) =>
    isWithinRoundWindow(s.start, input.roundWindows),
  );
  // Gate finding F-N5: this filter can silently drop older/out-of-window
  // records with no trace — count what it dropped so a suspiciously-large
  // drop (e.g. every workout, from a mis-logged window) is visible.
  const iosDropped = input.ios.workouts.length - iosWorkoutsInWindow.length;
  const androidDropped =
    input.android.sessions.length - androidSessionsInWindow.length;
  if (iosDropped > 0) {
    warnings.push(
      `${iosDropped} iOS workout(s) fell outside the logged round window(s) and were excluded.`,
    );
  }
  if (androidDropped > 0) {
    warnings.push(
      `${androidDropped} Android session(s) fell outside the logged round window(s) and were excluded.`,
    );
  }

  const garminIos = iosVerdictFor(
    iosWorkoutsInWindow,
    input.sourceMap.garmin.iosSourceNames,
    warnings,
    "Garmin (iOS)",
  );
  const garminAndroid = androidVerdictFor(
    androidSessionsInWindow,
    input.sourceMap.garmin.androidDataOrigins,
    followUps,
    warnings,
    "Garmin (Android)",
  );

  const appleWatchIos = iosVerdictFor(
    iosWorkoutsInWindow,
    input.sourceMap.appleWatch.iosSourceNames,
    warnings,
    "Apple Watch (iOS)",
  );
  // No Apple Watch on Android (device-protocol.md §4 results table).
  const appleWatchAndroid: SourceOsVerdict = "not-applicable";

  const phoneAppIos = iosVerdictFor(
    iosWorkoutsInWindow,
    input.sourceMap.phoneApp.iosSourceNames,
    warnings,
    `Phone app ${phoneApp.appUsed} (iOS)`,
  );
  const phoneAppAndroid = androidVerdictFor(
    androidSessionsInWindow,
    input.sourceMap.phoneApp.androidDataOrigins,
    followUps,
    warnings,
    `Phone app ${phoneApp.appUsed} (Android)`,
  );

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
  return lines.join("\n");
}

interface CliArgs {
  iosPath: string;
  androidPath: string;
  followUpsPath?: string;
  sourceMapPath: string;
  outPrefix: string;
}

function parseArgs(argv: string[]): CliArgs {
  const opts: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
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
  } = opts;
  if (!ios || !android || !sourceMap) {
    throw new Error(
      "Usage: node dist/x1-verdict.js --ios <x1-ios-export.json> --android <health-connect-reader.json> " +
        "--source-map <source-map.json> [--follow-ups <follow-ups.json>] [--out <prefix>]",
    );
  }
  return {
    iosPath: ios,
    androidPath: android,
    sourceMapPath: sourceMap,
    outPrefix: out || "x1-verdict-result",
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

  const result = computeX1Verdict({
    ios,
    android,
    sourceMap,
    roundWindows,
    ...(androidRouteFollowUps ? { androidRouteFollowUps } : {}),
  });
  const { writeFile } = await import("node:fs/promises");
  await writeFile(
    `${args.outPrefix}.json`,
    `${JSON.stringify(result, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    `${args.outPrefix}.md`,
    `${renderVerdictMarkdown(result)}\n`,
    "utf8",
  );
  process.stdout.write(`${renderVerdictMarkdown(result)}\n`);
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
