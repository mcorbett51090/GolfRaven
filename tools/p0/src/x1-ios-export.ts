#!/usr/bin/env node
/**
 * `x1-ios-export` — X1 (build plan §10 P0) iOS harness (G-P0-06):
 * stream-parses an unzipped Apple Health `apple_health_export/` directory
 * and reports every `HKWorkoutActivityTypeGolf` workout it finds, per
 * source, with route (`HKWorkoutRoute` / GPX) evidence.
 *
 * Usage: node dist/x1-ios-export.js <path-to-unzipped-apple_health_export-dir> --os ios
 *   [--since YYYY-MM-DD] [--informational] [--out <prefix>]
 *
 * **Decision 0005 (2026-09-24):** every golf workout counts, whenever it
 * was played — a logged round window (`docs/p0/X1.md` "## Round windows")
 * only TAGS a workout `testRound: true` when its start time falls inside
 * one (60-minute slack); it no longer excludes anything, and this tool no
 * longer refuses to run when no window is logged. In its place, decision
 * 0005's **recorded-export rule** governs what counts as the P0 verdict:
 * `docs/p0/X1.md`'s "## Recorded export" section holds, per OS, the date
 * Matt logged BEFORE reading that OS's export. `--os ios` (the only value
 * this tool accepts — it only ever reads an Apple Health export) checks
 * that date; a blank date refuses (throws) unless `--informational` is
 * passed, in which case the run proceeds and the output is stamped
 * `recorded: false` with a loud banner in the markdown.
 *
 * See `tools/p0/README.md` for what this feeds and exact commands, and
 * `src/health-export-xml.ts` for the `[unverified — training knowledge]`
 * export.xml shape this relies on and the loud-failure contract.
 */
import { mkdir, realpath, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  countGpxTrackpoints,
  GOLF_ACTIVITY_TYPE,
  parseHealthExportXml,
  type RawIosWorkout,
} from "./health-export-xml.js";
import {
  isWithinRoundWindow,
  readLoggedRoundWindows,
  type RoundWindow,
} from "./round-windows.js";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  assertDocCommitted,
  assertExportDateMatches,
  assertInformationalInputAllowed,
  assertRecordedExportDateLogged,
  bindExportHash,
  extractCalendarDate,
  informationalBanner,
  readRecordedExportDates,
  type X1Os,
} from "./recorded-export.js";
import { resolveX1DocPath } from "./round-windows.js";

export interface X1IosWorkoutRecord {
  sourceName: string;
  sourceVersion: string | null;
  device: string | null;
  workoutActivityType: string;
  startDate: string | null;
  endDate: string | null;
  hasWorkoutRoute: boolean;
  routeFileReferencePath: string | null;
  routeFileExists: boolean;
  routeTrackpointCount: number;
  /** `hasWorkoutRoute && routeFileExists && routeTrackpointCount > 0` — an
   * empty GPX (0 trackpoints) does not count as "route present", matching
   * the ≥ 1 point bar decision 0001 Addendum D R6 applies on the Android
   * side, for consistency. */
  routePresent: boolean;
  /** Per-row verdict: this source, on iOS, wrote a golf workout with a
   * route. The cross-source 2-of-3 bar is `x1-verdict`'s job, not this
   * tool's — this is just "written AND route present" for this one row. */
  verdict: "pass" | "fail";
  /** Decision 0005: true when `startDate` falls inside a logged
   * `docs/p0/X1.md` round window (60-minute slack) — a LABEL only. It does
   * not affect `verdict` or whether this workout is counted: every golf
   * workout counts, whenever it was played. */
  testRound: boolean;
}

/** Decision 0005 "Every counted workout is listed with its date and
 * source. ... The memo shows, per source, the newest counted workout's
 * date.": one row per distinct `sourceName` among the counted workouts.
 * Should-fix (Opus gate, post-d0de4b8): "newest counted workout date"
 * covers only workouts that count TOWARD THE VERDICT — golf (already
 * filtered to only golf workouts by the time this runs) with a route
 * present — so `newestStartDate` only considers `verdict === "pass"`
 * workouts; a route-less workout's date is tracked separately in
 * `newestStartDateWithoutRoute`, never conflated with the verdict-bearing
 * one. */
export interface X1IosSourceSummary {
  sourceName: string;
  count: number;
  /** The most recent (by parsed `startDate`) counted workout WITH A ROUTE
   * for this source, or `null` if none had a route (or none parsed). */
  newestStartDate: string | null;
  /** The most recent counted workout WITHOUT a route for this source, or
   * `null` if every workout of this source had a route (or none parsed). */
  newestStartDateWithoutRoute: string | null;
}

export interface X1IosExportResult {
  generatedAt: string;
  exportDir: string;
  since: string | null;
  /** Decision 0005: the logged round window(s) this run tagged `testRound`
   * against — recorded for auditability. May be empty (no window logged is
   * now a normal, not a refused, state). */
  roundWindows: RoundWindow[];
  totalWorkoutElementsSeen: number;
  golfWorkoutCount: number;
  workouts: X1IosWorkoutRecord[];
  /** Decision 0005: per-source counted-workout summary, including the
   * newest counted workout's date per source. */
  sourceSummaries: X1IosSourceSummary[];
  /** Opus-gate correction (post-d0de4b8): the raw `<ExportDate value="...">`
   * from `export.xml` (`[unverified — training knowledge]`, same footing as
   * `health-export-xml.ts`'s other export.xml-shape assumptions), or `null`
   * if the file has none. Compared to `docs/p0/X1.md`'s logged
   * recorded-export date for a recorded run (decision 0005 "Bind the
   * recorded run to one specific export"). */
  exportDate: string | null;
  /** Opus-gate correction (post-d0de4b8): SHA-256 of `export.xml`'s raw
   * bytes, bound into `docs/p0/X1.md` on the first recorded run and
   * checked against on every later one (decision 0005). */
  exportSha256: string;
  warnings: string[];
}

function toRecord(
  raw: RawIosWorkout,
  routeFileExists: boolean,
  routeTrackpointCount: number,
  testRound: boolean,
): X1IosWorkoutRecord {
  const routePresent =
    raw.hasWorkoutRoute && routeFileExists && routeTrackpointCount > 0;
  return {
    sourceName: raw.sourceName,
    sourceVersion: raw.sourceVersion,
    device: raw.device,
    workoutActivityType: raw.workoutActivityType,
    startDate: raw.startDate,
    endDate: raw.endDate,
    hasWorkoutRoute: raw.hasWorkoutRoute,
    routeFileReferencePath: raw.routeFileReferencePath,
    routeFileExists,
    routeTrackpointCount,
    routePresent,
    verdict: routePresent ? "pass" : "fail",
    testRound,
  };
}

/** Newest (by `Date.parse`) `startDate` among `list`, or `null` if none
 * parse. A workout with a missing/unparseable `startDate` is skipped, not
 * treated as "newest". */
function newestOf(list: X1IosWorkoutRecord[]): string | null {
  let newest: string | null = null;
  let newestTime = -Infinity;
  for (const w of list) {
    if (!w.startDate) continue;
    const t = Date.parse(w.startDate);
    if (!Number.isNaN(t) && t > newestTime) {
      newestTime = t;
      newest = w.startDate;
    }
  }
  return newest;
}

/** Decision 0005: groups counted workouts by `sourceName` and finds each
 * source's newest WITH-A-ROUTE `startDate` and newest WITHOUT-A-ROUTE
 * `startDate` separately (should-fix, Opus gate post-d0de4b8: the
 * verdict-bearing "newest counted workout date" must never be silently
 * pulled forward by a route-less workout). Sorted by `sourceName` for
 * stable output. */
export function computeSourceSummaries(
  workouts: X1IosWorkoutRecord[],
): X1IosSourceSummary[] {
  const bySource = new Map<string, X1IosWorkoutRecord[]>();
  for (const w of workouts) {
    const key = w.sourceName || "(unknown)";
    const list = bySource.get(key);
    if (list) {
      list.push(w);
    } else {
      bySource.set(key, [w]);
    }
  }
  const summaries: X1IosSourceSummary[] = [];
  for (const [sourceName, list] of bySource) {
    summaries.push({
      sourceName,
      count: list.length,
      newestStartDate: newestOf(list.filter((w) => w.routePresent)),
      newestStartDateWithoutRoute: newestOf(
        list.filter((w) => !w.routePresent),
      ),
    });
  }
  return summaries.sort((a, b) => a.sourceName.localeCompare(b.sourceName));
}

/** Streams `filePath` and returns the lowercase-hex SHA-256 of its raw
 * bytes — used to bind a recorded run to one specific `export.xml`
 * (decision 0005, Opus-gate correction post-d0de4b8). Read as raw bytes
 * (no `encoding` option), not the decoded-text stream `parseHealthExportXml`
 * uses, so the hash matches the file exactly as it sits on disk. */
export function hashFile(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(filePath);
    stream.on("data", (chunk) => hash.update(chunk as Buffer));
    stream.on("end", () => resolve(hash.digest("hex")));
    stream.on("error", (err) => reject(err));
  });
}

/** Resolves an export.xml `FileReference path` (e.g.
 * `/workout-routes/route_2026-09-20_5.32pm.gpx` or a path already rooted at
 * the export dir) to a real path under `exportDir` [unverified — training
 * knowledge on the exact path format export.xml writes]. */
function resolveRoutePath(exportDir: string, referencePath: string): string {
  const cleaned = referencePath.replace(/^\/+/, "");
  return path.join(exportDir, cleaned);
}

export async function runX1IosExport(
  exportDir: string,
  opts: { since?: string; roundWindows?: RoundWindow[] },
): Promise<X1IosExportResult> {
  // Decision 0005: round windows are labels, not a filter — no refusal and
  // no exclusion on an empty/missing list. `roundWindows` defaults to []
  // (every workout is then tagged testRound: false).
  const roundWindows = opts.roundWindows ?? [];

  const xmlPath = path.join(exportDir, "export.xml");
  if (!existsSync(exportDir)) {
    throw new Error(`Export directory not found: ${exportDir}`);
  }
  if (!existsSync(xmlPath)) {
    throw new Error(
      `export.xml not found under ${exportDir} — pass the unzipped apple_health_export ` +
        `directory (it should directly contain export.xml and workout-routes/).`,
    );
  }

  const sinceDate = opts.since ? new Date(`${opts.since}T00:00:00`) : null;
  if (opts.since && Number.isNaN(sinceDate?.getTime())) {
    throw new Error(
      `--since value is not a valid date: ${opts.since} (expected YYYY-MM-DD)`,
    );
  }

  // Gate finding F-N7: the real CLI opts into the workout-routes/
  // unreferenced-GPX-file check; synthetic test fixtures do not (see
  // health-export-xml.ts's ParseHealthExportXmlOptions doc).
  const parsed = await parseHealthExportXml(xmlPath, {
    checkUnreferencedGpxFiles: true,
  });
  const warnings: string[] = [];

  const golf = parsed.workouts.filter(
    (w) => w.workoutActivityType === GOLF_ACTIVITY_TYPE,
  );

  const sinceFiltered = golf.filter((w) => {
    if (!sinceDate) return true;
    if (!w.startDate) {
      warnings.push(
        `A golf workout (source "${w.sourceName}") has no startDate; --since cannot filter it, so it is included.`,
      );
      return true;
    }
    const start = new Date(w.startDate);
    if (Number.isNaN(start.getTime())) {
      warnings.push(
        `A golf workout (source "${w.sourceName}") has an unparseable startDate "${w.startDate}"; included since --since cannot filter it.`,
      );
      return true;
    }
    return start.getTime() >= sinceDate.getTime();
  });

  // Decision 0005: every workout in sinceFiltered counts — no round-window
  // exclusion. A logged window only TAGS a matching workout testRound:
  // true (below); it never removes anything.
  const workouts: X1IosWorkoutRecord[] = [];
  for (const w of sinceFiltered) {
    let routeFileExists = false;
    let routeTrackpointCount = 0;
    if (w.hasWorkoutRoute && w.routeFileReferencePath) {
      const resolved = resolveRoutePath(exportDir, w.routeFileReferencePath);
      const counted = await countGpxTrackpoints(resolved);
      routeFileExists = counted.exists;
      routeTrackpointCount = counted.count;
      if (!routeFileExists) {
        warnings.push(
          `Workout (source "${w.sourceName}", start ${w.startDate ?? "unknown"}) references a ` +
            `WorkoutRoute file "${w.routeFileReferencePath}" that does not exist under ${exportDir}.`,
        );
      } else if (routeTrackpointCount === 0) {
        warnings.push(
          `Workout (source "${w.sourceName}", start ${w.startDate ?? "unknown"})'s route file has 0 trackpoints.`,
        );
      }
    } else if (w.hasWorkoutRoute && !w.routeFileReferencePath) {
      warnings.push(
        `Workout (source "${w.sourceName}", start ${w.startDate ?? "unknown"}) has a WorkoutRoute ` +
          `element but no FileReference path attribute.`,
      );
    }
    const testRound = isWithinRoundWindow(w.startDate, roundWindows);
    workouts.push(
      toRecord(w, routeFileExists, routeTrackpointCount, testRound),
    );
  }

  if (golf.length === 0) {
    warnings.push(
      `No HKWorkoutActivityTypeGolf workouts found among ${parsed.totalWorkoutElementsSeen} <Workout> ` +
        `element(s) seen in export.xml. This is treated as a legitimate zero-golf-workouts result, not ` +
        `a shape error (see health-export-xml.ts) — double-check this is the right export before relying on it.`,
    );
  }

  const exportSha256 = await hashFile(xmlPath);

  return {
    generatedAt: new Date().toISOString(),
    exportDir,
    since: opts.since ?? null,
    roundWindows,
    totalWorkoutElementsSeen: parsed.totalWorkoutElementsSeen,
    golfWorkoutCount: workouts.length,
    workouts,
    sourceSummaries: computeSourceSummaries(workouts),
    exportDate: parsed.exportDate,
    exportSha256,
    warnings,
  };
}

/** Markdown table matching the X1 memo's results table columns (per source)
 * — see `docs/owner/x1-k4b-device-protocol.md` §4. OS is always "iOS" here;
 * the CONSENT_REQUIRED + follow-up-read column is Android-only (decision
 * 0001, Addendum D, R6) so it always reads "N/A (iOS)" in this tool's
 * output. "Source id" uses `sourceName` — export.xml does not appear to
 * expose `HKSource.bundleIdentifier` directly `[unverified — training
 * knowledge]`; `x1-verdict`'s source-map config matches on `sourceName` for
 * the same reason (see its README section).
 *
 * Decision 0005 "Every counted workout is listed with its date and
 * source ... the source version and device when the export records
 * them": this is already ONE ROW PER WORKOUT (not per source), so adding
 * Start date / Source version / Device / Test round columns makes it the
 * per-workout listing decision 0005 requires. */
export function renderMarkdownTable(result: X1IosExportResult): string {
  const header =
    "| Source | OS | Start date | Test round? | Workout/exercise written? | Route present? | CONSENT_REQUIRED + follow-up read | Source id (bundleIdentifier/dataOrigin) | Source version | Device | Verdict |\n" +
    "|---|---|---|---|---|---|---|---|---|---|---|";
  if (result.workouts.length === 0) {
    return `${header}\n| _(no golf workouts found)_ | iOS | — | — | — | — | N/A (iOS) | — | — | — | — |`;
  }
  const rows = result.workouts.map((w) => {
    const written = "Yes";
    const route = w.routePresent ? "Yes" : "No";
    const testRound = w.testRound ? "Yes" : "No";
    return `| ${w.sourceName || "(unknown)"} | iOS | ${w.startDate ?? "(unknown)"} | ${testRound} | ${written} | ${route} | N/A (iOS) | ${w.sourceName || "(unknown)"} | ${w.sourceVersion ?? "(none)"} | ${w.device ?? "(none)"} | ${w.verdict} |`;
  });
  return [header, ...rows].join("\n");
}

/** Decision 0005: "The memo shows, per source, the newest counted
 * workout's date." */
export function renderSourceSummaryMarkdown(result: X1IosExportResult): string {
  const header =
    "| Source | Counted workouts | Newest counted workout date (with route) | Newest workout without a route |\n" +
    "|---|---|---|---|";
  if (result.sourceSummaries.length === 0) {
    return `${header}\n| _(none)_ | 0 | — | — |`;
  }
  const rows = result.sourceSummaries.map(
    (s) =>
      `| ${s.sourceName} | ${s.count} | ${s.newestStartDate ?? "(none)"} | ${s.newestStartDateWithoutRoute ?? "(none)"} |`,
  );
  return [header, ...rows].join("\n");
}

export interface X1IosExportCliArgs {
  exportDir: string;
  since?: string;
  outPrefix: string;
  os: X1Os;
  informational: boolean;
}

function parseArgs(argv: string[]): X1IosExportCliArgs {
  const positional: string[] = [];
  let since: string | undefined;
  let outPrefix = "x1-ios-export-result";
  let os: string | undefined;
  let informational = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--since") {
      since = argv[++i];
    } else if (arg === "--out") {
      outPrefix = argv[++i] ?? outPrefix;
    } else if (arg === "--os") {
      os = argv[++i];
    } else if (arg === "--informational") {
      informational = true;
    } else if (arg && !arg.startsWith("--")) {
      positional.push(arg);
    }
  }
  const exportDir = positional[0];
  if (!exportDir || !os) {
    throw new Error(
      "Usage: node dist/x1-ios-export.js <path-to-unzipped-apple_health_export-dir> --os ios " +
        "[--since YYYY-MM-DD] [--informational] [--out <prefix>]",
    );
  }
  if (os !== "ios" && os !== "android") {
    throw new Error(`--os must be "ios" or "android", got "${os}".`);
  }
  if (os !== "ios") {
    // This tool only ever reads an Apple Health export.xml — it cannot
    // produce an Android result. Accepting the flag (per decision 0005:
    // "The CLIs take --os ios|android") and validating it here, rather
    // than silently ignoring the value, is what makes that requirement
    // meaningful for a tool that is inherently single-OS.
    throw new Error(
      `x1-ios-export only produces iOS results (it reads an Apple Health export.xml) — pass --os ios, not ` +
        `--os ${os}. The Android pass uses the Health Connect reader in apps/mobile, not this tool.`,
    );
  }
  if (since !== undefined && !informational) {
    // Decision 0005: "No recency limit." --since is a recency limit chosen
    // at run time, which the decision forbids for a recorded run — it's
    // only available on an --informational dry run.
    throw new Error(
      '--since is refused on a recorded run (decision 0005: "No recency limit" — an old round counts the ' +
        "same as a new one). Pass --informational if you genuinely want a date-limited, non-recorded dry run.",
    );
  }

  return {
    exportDir,
    outPrefix,
    os,
    informational,
    ...(since !== undefined ? { since } : {}),
  };
}

/**
 * The CLI's actual body, factored out of `main()` so it can be exercised
 * directly against a temp git repo in tests (round-4 Opus-gate correction,
 * post-4279773) — **there is no `--x1-doc` CLI flag** (decision 0005's own
 * "no override flag" rule, same philosophy as the K2 CLI's no-`--k2-doc`
 * rule: a recorded tool that WRITES a binding must never be pointable at
 * anywhere other than the repo's own `docs/p0/X1.md`). `main()` always
 * calls this with `resolveX1DocPath()`; only tests call it directly with a
 * different path.
 */
export async function runX1IosExportCli(
  args: X1IosExportCliArgs,
  x1DocPath: string,
): Promise<void> {
  const roundWindows = await readLoggedRoundWindows();
  const { dates: recordedExportDates, source } =
    await readRecordedExportDates(x1DocPath);
  const recorded = !args.informational;
  if (recorded) {
    // Round-4 Opus-gate correction (post-4279773): a recorded run only
    // ever trusts a COMMITTED docs/p0/X1.md — checked before anything else
    // reads/relies on its logged dates or hashes.
    await assertDocCommitted(source.path);
    assertRecordedExportDateLogged(recordedExportDates, args.os);
  } else {
    // Round-3 Opus-gate correction: --informational on real (non-fixture)
    // data is refused while iOS is unbound (whether its UTC date is blank
    // or logged) — only a synthetic fixture path is allowed in that window.
    assertInformationalInputAllowed(
      recordedExportDates,
      args.os,
      args.exportDir,
    );
  }

  const result = await runX1IosExport(args.exportDir, {
    roundWindows,
    ...(args.since !== undefined ? { since: args.since } : {}),
  });

  // Decision 0005 "Bind the recorded run to one specific export": a
  // recorded run is refused if export.xml has no ExportDate at all
  // (nothing to bind against), if that UTC date doesn't match what's
  // logged, or if its SHA-256 doesn't match what was already bound there.
  // --informational skips all of this — it is never checked or bound.
  // Round-3 Opus-gate correction: the first-bind trust limit — whatever
  // file is bound first is trusted as the device's genuine output; there
  // is no independent ground truth to verify it against. The protection
  // against a rewritten LOCAL history (rebase/amend, not detected by
  // anything here) is committing AND PUSHING docs/p0/X1.md right away,
  // the same as decision 0001 Addendum F requires for K2.
  let boundThisRun = false;
  if (recorded) {
    if (result.exportDate === null) {
      throw new Error(
        "export.xml has no <ExportDate> element — refusing a recorded run: decision 0005 requires binding " +
          "the recorded run to one specific export, and there is nothing to compare against docs/p0/X1.md's " +
          "logged date. Pass --informational to run anyway.",
      );
    }
    const exportCalendarDate = extractCalendarDate(result.exportDate);
    assertExportDateMatches(recordedExportDates, args.os, exportCalendarDate);
    const { written } = await bindExportHash(
      source.path,
      args.os,
      result.exportSha256,
    );
    boundThisRun = written;
  }

  // Round-4 Opus-gate correction (post-4279773), "a binding run binds and
  // prints no verdict": the run that performs the FIRST bind for iOS stops
  // here — it never computes or prints a verdict/per-source detail, and
  // never writes a result file, from a binding that hasn't even been
  // pushed yet. A later run, once docs/p0/X1.md is committed and pushed,
  // re-verifies the (now-matching) hash and produces the actual result.
  if (boundThisRun) {
    process.stdout.write(
      "x1-ios-export: bound a new SHA-256 for iOS into docs/p0/X1.md.\n" +
        "bound: commit and push docs/p0/X1.md, then re-run.\n",
    );
    return;
  }

  const banner = recorded ? "" : `${informationalBanner(args.os)}\n\n`;
  const md =
    banner +
    renderMarkdownTable(result) +
    "\n\n### Newest counted workout date, per source\n\n" +
    renderSourceSummaryMarkdown(result);
  const output = { ...result, os: args.os, recorded, source };

  const outDir = path.dirname(path.resolve(args.outPrefix));
  await mkdir(outDir, { recursive: true });
  const jsonPath = `${args.outPrefix}.json`;
  const mdPath = `${args.outPrefix}.md`;
  await writeFile(jsonPath, `${JSON.stringify(output, null, 2)}\n`, "utf8");
  await writeFile(mdPath, `${md}\n`, "utf8");

  process.stdout.write(
    `x1-ios-export: ${result.golfWorkoutCount} golf workout(s) found (of ${result.totalWorkoutElementsSeen} total <Workout> elements). ` +
      `recorded=${recorded}\n` +
      `Wrote ${jsonPath} and ${mdPath}.\n`,
  );
  if (result.warnings.length > 0) {
    process.stderr.write(
      `Warnings:\n${result.warnings.map((w) => `  - ${w}`).join("\n")}\n`,
    );
  }
}

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  await runX1IosExportCli(args, resolveX1DocPath());
}

/** Gate finding B-11 (the N7 symlink bug, again): real-path comparison, not
 * a raw `process.argv[1]` vs. `import.meta.url` comparison that silently
 * never matches (and so never runs `main`, exiting 0) when invoked through
 * a symlinked checkout path. */
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
    process.stderr.write(`x1-ios-export: ${message}\n`);
    process.exitCode = 1;
  });
}
