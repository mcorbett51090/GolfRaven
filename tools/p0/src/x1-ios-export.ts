#!/usr/bin/env node
/**
 * `x1-ios-export` — X1 (build plan §10 P0) iOS harness (G-P0-06):
 * stream-parses an unzipped Apple Health `apple_health_export/` directory
 * and reports every `HKWorkoutActivityTypeGolf` workout it finds, per
 * source, with route (`HKWorkoutRoute` / GPX) evidence.
 *
 * Usage: node dist/x1-ios-export.js <path-to-unzipped-apple_health_export-dir> [--since YYYY-MM-DD] [--out <prefix>]
 *
 * See `tools/p0/README.md` for what this feeds and exact commands, and
 * `src/health-export-xml.ts` for the `[unverified — training knowledge]`
 * export.xml shape this relies on and the loud-failure contract.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  countGpxTrackpoints,
  GOLF_ACTIVITY_TYPE,
  parseHealthExportXml,
  type RawIosWorkout,
} from "./health-export-xml.js";

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
}

export interface X1IosExportResult {
  generatedAt: string;
  exportDir: string;
  since: string | null;
  totalWorkoutElementsSeen: number;
  golfWorkoutCount: number;
  workouts: X1IosWorkoutRecord[];
  warnings: string[];
}

function toRecord(
  raw: RawIosWorkout,
  routeFileExists: boolean,
  routeTrackpointCount: number,
): X1IosWorkoutRecord {
  const routePresent = raw.hasWorkoutRoute && routeFileExists && routeTrackpointCount > 0;
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
  };
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
  opts: { since?: string } = {},
): Promise<X1IosExportResult> {
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
    throw new Error(`--since value is not a valid date: ${opts.since} (expected YYYY-MM-DD)`);
  }

  const parsed = await parseHealthExportXml(xmlPath);
  const warnings: string[] = [];

  const golf = parsed.workouts.filter((w) => w.workoutActivityType === GOLF_ACTIVITY_TYPE);

  const filtered = golf.filter((w) => {
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

  const workouts: X1IosWorkoutRecord[] = [];
  for (const w of filtered) {
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
    workouts.push(toRecord(w, routeFileExists, routeTrackpointCount));
  }

  if (golf.length === 0) {
    warnings.push(
      `No HKWorkoutActivityTypeGolf workouts found among ${parsed.totalWorkoutElementsSeen} <Workout> ` +
        `element(s) seen in export.xml. This is treated as a legitimate zero-golf-workouts result, not ` +
        `a shape error (see health-export-xml.ts) — double-check this is the right export before relying on it.`,
    );
  }

  return {
    generatedAt: new Date().toISOString(),
    exportDir,
    since: opts.since ?? null,
    totalWorkoutElementsSeen: parsed.totalWorkoutElementsSeen,
    golfWorkoutCount: workouts.length,
    workouts,
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
 * the same reason (see its README section). */
export function renderMarkdownTable(result: X1IosExportResult): string {
  const header =
    "| Source | OS | Workout/exercise written? | Route present? | CONSENT_REQUIRED + follow-up read | Source id (bundleIdentifier/dataOrigin) | Verdict |\n" +
    "|---|---|---|---|---|---|---|";
  if (result.workouts.length === 0) {
    return `${header}\n| _(no golf workouts found)_ | iOS | — | — | N/A (iOS) | — | — |`;
  }
  const rows = result.workouts.map((w) => {
    const written = "Yes";
    const route = w.routePresent ? "Yes" : "No";
    return `| ${w.sourceName || "(unknown)"} | iOS | ${written} | ${route} | N/A (iOS) | ${w.sourceName || "(unknown)"} | ${w.verdict} |`;
  });
  return [header, ...rows].join("\n");
}

interface CliArgs {
  exportDir: string;
  since?: string;
  outPrefix: string;
}

function parseArgs(argv: string[]): CliArgs {
  const positional: string[] = [];
  let since: string | undefined;
  let outPrefix = "x1-ios-export-result";
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--since") {
      since = argv[++i];
    } else if (arg === "--out") {
      outPrefix = argv[++i] ?? outPrefix;
    } else if (arg && !arg.startsWith("--")) {
      positional.push(arg);
    }
  }
  const exportDir = positional[0];
  if (!exportDir) {
    throw new Error(
      "Usage: node dist/x1-ios-export.js <path-to-unzipped-apple_health_export-dir> [--since YYYY-MM-DD] [--out <prefix>]",
    );
  }
  return { exportDir, outPrefix, ...(since !== undefined ? { since } : {}) };
}

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  const result = await runX1IosExport(args.exportDir, args.since !== undefined ? { since: args.since } : {});
  const md = renderMarkdownTable(result);

  const outDir = path.dirname(path.resolve(args.outPrefix));
  await mkdir(outDir, { recursive: true });
  const jsonPath = `${args.outPrefix}.json`;
  const mdPath = `${args.outPrefix}.md`;
  await writeFile(jsonPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
  await writeFile(mdPath, `${md}\n`, "utf8");

  process.stdout.write(
    `x1-ios-export: ${result.golfWorkoutCount} golf workout(s) found (of ${result.totalWorkoutElementsSeen} total <Workout> elements).\n` +
      `Wrote ${jsonPath} and ${mdPath}.\n`,
  );
  if (result.warnings.length > 0) {
    process.stderr.write(`Warnings:\n${result.warnings.map((w) => `  - ${w}`).join("\n")}\n`);
  }
}

const isMain =
  process.argv[1] !== undefined &&
  pathToFileURL(process.argv[1]).href === import.meta.url;

if (isMain) {
  main(process.argv.slice(2)).catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`x1-ios-export: ${message}\n`);
    process.exitCode = 1;
  });
}
