import { describe, expect, it } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  runX1IosExport,
  renderMarkdownTable,
  renderSourceSummaryMarkdown,
} from "../src/x1-ios-export.js";
import {
  HealthExportShapeError,
  countGpxTrackpoints,
} from "../src/health-export-xml.js";
import type { RoundWindow } from "../src/round-windows.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(__dirname, "fixtures");

/** The good fixture's export.xml lives directly under FIXTURES, and its
 * WorkoutRoute FileReference paths are "/workout-routes/...", resolved
 * relative to the export dir — so FIXTURES itself is "the export dir". */
const GOOD_EXPORT_DIR = FIXTURES;

/** Tags every 2026-09-15..09-21 golf workout `testRound: true` — the
 * 2026-08-01 Garmin workout falls outside it and is tagged `testRound:
 * false`, but (decision 0005) still counts toward the result; nothing is
 * excluded by this list any more. */
const GOOD_ROUND_WINDOWS: RoundWindow[] = [
  { startIso: "2026-09-15T00:00:00Z", endIso: "2026-09-21T00:00:00Z" },
];

/** Just the 2026-09-20 cluster (Garmin/Apple Watch/18Birdies), UTC. */
const TIGHT_ROUND_WINDOWS: RoundWindow[] = [
  { startIso: "2026-09-20T12:00:00Z", endIso: "2026-09-20T14:00:00Z" },
];

describe("x1-ios-export: parsing a well-formed export.xml", () => {
  it("finds ALL golf workouts, regardless of round window, and filters out non-golf ones (decision 0005)", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, {
      roundWindows: GOOD_ROUND_WINDOWS,
    });
    expect(result.totalWorkoutElementsSeen).toBe(6); // 5 golf + 1 running
    // Decision 0005: the 2026-08-01 Garmin workout (outside every window) STILL counts.
    expect(result.golfWorkoutCount).toBe(5);
    const sources = result.workouts.map((w) => w.sourceName).sort();
    expect(sources).toEqual([
      "18Birdies",
      "Garmin Connect",
      "Garmin Connect",
      "Hole19",
      "Matt's Apple Watch",
    ]);
  });

  it("reports route present with a positive trackpoint count for the Garmin workout", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, {
      roundWindows: GOOD_ROUND_WINDOWS,
    });
    const garminRecent = result.workouts.find(
      (w) =>
        w.sourceName === "Garmin Connect" &&
        w.startDate?.startsWith("2026-09-20"),
    );
    expect(garminRecent).toBeDefined();
    expect(garminRecent!.hasWorkoutRoute).toBe(true);
    expect(garminRecent!.routeFileExists).toBe(true);
    expect(garminRecent!.routeTrackpointCount).toBe(2);
    expect(garminRecent!.routePresent).toBe(true);
    expect(garminRecent!.verdict).toBe("pass");
  });

  it("reports route NOT present when the workout has no WorkoutRoute at all (Apple Watch)", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, {
      roundWindows: GOOD_ROUND_WINDOWS,
    });
    const appleWatch = result.workouts.find(
      (w) => w.sourceName === "Matt's Apple Watch",
    );
    expect(appleWatch).toBeDefined();
    expect(appleWatch!.hasWorkoutRoute).toBe(false);
    expect(appleWatch!.routePresent).toBe(false);
    expect(appleWatch!.verdict).toBe("fail");
  });

  it("reports route NOT present when the referenced GPX file is missing on disk (18Birdies)", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, {
      roundWindows: GOOD_ROUND_WINDOWS,
    });
    const birdies = result.workouts.find((w) => w.sourceName === "18Birdies");
    expect(birdies).toBeDefined();
    expect(birdies!.hasWorkoutRoute).toBe(true);
    expect(birdies!.routeFileExists).toBe(false);
    expect(birdies!.routePresent).toBe(false);
    expect(birdies!.verdict).toBe("fail");
    expect(result.warnings.some((w) => w.includes("does not exist"))).toBe(
      true,
    );
  });

  it("reports route NOT present when the GPX file exists but has 0 trackpoints (Hole19)", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, {
      roundWindows: GOOD_ROUND_WINDOWS,
    });
    const hole19 = result.workouts.find((w) => w.sourceName === "Hole19");
    expect(hole19).toBeDefined();
    expect(hole19!.routeFileExists).toBe(true);
    expect(hole19!.routeTrackpointCount).toBe(0);
    expect(hole19!.routePresent).toBe(false);
    expect(hole19!.verdict).toBe("fail");
  });

  it("--since filters out workouts before the cutoff date, on top of the round-window filter", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, {
      since: "2026-09-01",
      roundWindows: GOOD_ROUND_WINDOWS,
    });
    const garminStarts = result.workouts
      .filter((w) => w.sourceName === "Garmin Connect")
      .map((w) => w.startDate);
    expect(garminStarts).toEqual(["2026-09-20 09:00:00 -0400"]);
    expect(result.golfWorkoutCount).toBe(4);
  });

  it("renders a markdown table with the memo's columns, including Test round?", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, {
      roundWindows: GOOD_ROUND_WINDOWS,
    });
    const md = renderMarkdownTable(result);
    expect(md).toContain(
      "| Source | OS | Start date | Test round? | Workout/exercise written? | Route present? |",
    );
    expect(md).toContain("CONSENT_REQUIRED + follow-up read");
    expect(md).toContain("N/A (iOS)");
    // The recent (2026-09-20) Garmin workout is inside GOOD_ROUND_WINDOWS -> testRound Yes.
    expect(md).toMatch(/\| Garmin Connect \| iOS \| 2026-09-20[^|]*\| Yes \| Yes \| Yes \|/);
  });

  it("renders the per-source newest-counted-workout-date table", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, {
      roundWindows: GOOD_ROUND_WINDOWS,
    });
    const md = renderSourceSummaryMarkdown(result);
    expect(md).toContain(
      "| Source | Counted workouts | Newest counted workout date (with route) | Newest workout without a route |",
    );
    const garminRow = md.split("\n").find((l) => l.startsWith("| Garmin Connect"));
    expect(garminRow).toBeDefined();
    expect(garminRow).toContain("2026-09-20");
  });
});

describe("x1-ios-export: exportDate/exportSha256 binding (Opus-gate correction, post-d0de4b8)", () => {
  it("parses the ExportDate from the fixture export.xml", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, { roundWindows: GOOD_ROUND_WINDOWS });
    expect(result.exportDate).toBe("2026-09-21 09:00:00 -0400");
  });

  it("computes a SHA-256 of export.xml", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, { roundWindows: GOOD_ROUND_WINDOWS });
    expect(result.exportSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("computeSourceSummaries: newestStartDate only considers route-present workouts", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, { roundWindows: GOOD_ROUND_WINDOWS });
    const garmin = result.sourceSummaries.find((s) => s.sourceName === "Garmin Connect");
    expect(garmin).toBeDefined();
    // The 2026-09-20 Garmin workout has a route (2 trackpoints); the older
    // 2026-08-01 one has none — so it must not win "newest WITH a route".
    expect(garmin!.newestStartDate).toBe("2026-09-20 09:00:00 -0400");
    expect(garmin!.newestStartDateWithoutRoute).toBe("2026-08-01 09:00:00 -0400");
    const appleWatch = result.sourceSummaries.find((s) => s.sourceName === "Matt's Apple Watch");
    expect(appleWatch).toBeDefined();
    // Apple Watch's only workout has no route at all.
    expect(appleWatch!.newestStartDate).toBeNull();
    expect(appleWatch!.newestStartDateWithoutRoute).toBe("2026-09-20 09:01:00 -0400");
  });
});

describe("x1-ios-export: round windows are labels, not a filter (decision 0005, superseding Addendum F)", () => {
  it("does NOT throw when roundWindows is empty — every workout still counts, tagged testRound: false", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, { roundWindows: [] });
    expect(result.golfWorkoutCount).toBe(5);
    expect(result.workouts.every((w) => w.testRound === false)).toBe(true);
  });

  it("does NOT throw when roundWindows is omitted entirely", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, {});
    expect(result.golfWorkoutCount).toBe(5);
  });

  it("a historical workout (the 2026-08-01 Garmin one, outside every window) counts, tagged testRound: false", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, {
      roundWindows: TIGHT_ROUND_WINDOWS,
    });
    // Decision 0005: nothing is excluded by date. All 5 golf workouts count.
    expect(result.golfWorkoutCount).toBe(5);
    const old = result.workouts.find((w) => w.startDate?.startsWith("2026-08-01"));
    expect(old).toBeDefined();
    expect(old!.testRound).toBe(false);
    const hole19 = result.workouts.find((w) => w.sourceName === "Hole19");
    expect(hole19).toBeDefined();
    expect(hole19!.testRound).toBe(false);
  });

  it("a workout INSIDE the logged window is tagged testRound: true", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, {
      roundWindows: TIGHT_ROUND_WINDOWS,
    });
    const garminRecent = result.workouts.find(
      (w) => w.sourceName === "Garmin Connect" && w.startDate?.startsWith("2026-09-20"),
    );
    expect(garminRecent).toBeDefined();
    expect(garminRecent!.testRound).toBe(true);
  });

  it("a workout starting 59 minutes before the window (within the 60-min slack) is tagged testRound: true", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, {
      // Garmin's 2026-09-20 workout starts at 13:00:00Z; a window starting
      // 13:59:00Z is 59 minutes later — within the ±60 min slack.
      roundWindows: [
        { startIso: "2026-09-20T13:59:00Z", endIso: "2026-09-20T14:30:00Z" },
      ],
    });
    const w = result.workouts.find(
      (w) => w.sourceName === "Garmin Connect" && w.startDate?.startsWith("2026-09-20"),
    );
    expect(w).toBeDefined();
    expect(w!.testRound).toBe(true);
  });

  it("a workout starting 61 minutes before the window (outside the 60-min slack) is tagged testRound: false, but still counts", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, {
      roundWindows: [
        { startIso: "2026-09-20T14:01:00Z", endIso: "2026-09-20T14:30:00Z" },
      ],
    });
    const w = result.workouts.find(
      (w) => w.sourceName === "Garmin Connect" && w.startDate?.startsWith("2026-09-20"),
    );
    expect(w).toBeDefined();
    expect(w!.testRound).toBe(false);
  });
});

describe("x1-ios-export: loud failures on shape mismatches", () => {
  it("throws HealthExportShapeError for a wrong root element (not silently empty)", async () => {
    const { parseHealthExportXml } =
      await import("../src/health-export-xml.js");
    await expect(
      parseHealthExportXml(path.join(FIXTURES, "export-bad-root.xml")),
    ).rejects.toBeInstanceOf(HealthExportShapeError);
  });

  it("throws HealthExportShapeError when Workout elements exist but none carry workoutActivityType", async () => {
    const { parseHealthExportXml } =
      await import("../src/health-export-xml.js");
    await expect(
      parseHealthExportXml(path.join(FIXTURES, "export-bad-workout-shape.xml")),
    ).rejects.toBeInstanceOf(HealthExportShapeError);
  });

  it("does NOT fail when there are simply zero golf workouts (legitimate empty result)", async () => {
    const { parseHealthExportXml } =
      await import("../src/health-export-xml.js");
    const result = await parseHealthExportXml(
      path.join(FIXTURES, "export-no-golf.xml"),
    );
    expect(result.totalWorkoutElementsSeen).toBe(1);
    expect(
      result.workouts.filter(
        (w) => w.workoutActivityType === "HKWorkoutActivityTypeGolf",
      ),
    ).toHaveLength(0);
  });

  it("throws HealthExportShapeError for a <WorkoutRoute> that is a SIBLING of <Workout>, not nested (gate finding B-8)", async () => {
    const { parseHealthExportXml } =
      await import("../src/health-export-xml.js");
    await expect(
      parseHealthExportXml(
        path.join(FIXTURES, "export-sibling-workout-route.xml"),
      ),
    ).rejects.toMatchObject({
      name: "HealthExportShapeError",
      message: expect.stringContaining("sibling"),
    });
  });

  it("fails loudly when export.xml is missing entirely", async () => {
    await expect(
      runX1IosExport(path.join(FIXTURES, "does-not-exist"), {
        roundWindows: GOOD_ROUND_WINDOWS,
      }),
    ).rejects.toThrow(/not found/);
  });

  it("does NOT check for unreferenced GPX files by default — checkUnreferencedGpxFiles is opt-in (gate finding F-N7)", async () => {
    // export-no-golf.xml shares FIXTURES/workout-routes/ with other
    // fixtures' referenced GPX files, none of which IT references — this
    // must NOT throw unless the caller opts in.
    const { parseHealthExportXml } =
      await import("../src/health-export-xml.js");
    const result = await parseHealthExportXml(
      path.join(FIXTURES, "export-no-golf.xml"),
    );
    expect(result.totalWorkoutElementsSeen).toBe(1);
  });
});

describe("gate finding F-N7: a GPX file in workout-routes/ that no <Workout> references at all", () => {
  it("throws, opted in, when a .gpx file in workout-routes/ is not referenced by any workout", async () => {
    const { parseHealthExportXml, HealthExportShapeError: ShapeErr } =
      await import("../src/health-export-xml.js");
    const { mkdtempSync, writeFileSync, mkdirSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const dir = mkdtempSync(path.join(tmpdir(), "golfraven-x1-fn7-"));
    mkdirSync(path.join(dir, "workout-routes"));
    writeFileSync(
      path.join(dir, "export.xml"),
      `<?xml version="1.0" encoding="UTF-8"?>
<HealthData locale="en_US">
  <Workout workoutActivityType="HKWorkoutActivityTypeGolf" sourceName="Garmin Connect"
    startDate="2026-09-20 09:00:00 -0400" endDate="2026-09-20 13:00:00 -0400">
    <WorkoutRoute sourceName="Garmin Connect">
      <FileReference path="/workout-routes/referenced.gpx"/>
    </WorkoutRoute>
  </Workout>
</HealthData>`,
    );
    writeFileSync(
      path.join(dir, "workout-routes", "referenced.gpx"),
      "<gpx></gpx>",
    );
    writeFileSync(
      path.join(dir, "workout-routes", "orphan.gpx"),
      "<gpx></gpx>",
    );

    const promise = parseHealthExportXml(path.join(dir, "export.xml"), {
      checkUnreferencedGpxFiles: true,
    });
    await expect(promise).rejects.toBeInstanceOf(ShapeErr);
    await expect(promise).rejects.toThrow(/orphan\.gpx/);
  });

  it("does NOT throw, opted in, when every .gpx file in workout-routes/ is referenced", async () => {
    const { parseHealthExportXml } =
      await import("../src/health-export-xml.js");
    const { mkdtempSync, writeFileSync, mkdirSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const dir = mkdtempSync(path.join(tmpdir(), "golfraven-x1-fn7-ok-"));
    mkdirSync(path.join(dir, "workout-routes"));
    writeFileSync(
      path.join(dir, "export.xml"),
      `<?xml version="1.0" encoding="UTF-8"?>
<HealthData locale="en_US">
  <Workout workoutActivityType="HKWorkoutActivityTypeGolf" sourceName="Garmin Connect"
    startDate="2026-09-20 09:00:00 -0400" endDate="2026-09-20 13:00:00 -0400">
    <WorkoutRoute sourceName="Garmin Connect">
      <FileReference path="/workout-routes/referenced.gpx"/>
    </WorkoutRoute>
  </Workout>
</HealthData>`,
    );
    writeFileSync(
      path.join(dir, "workout-routes", "referenced.gpx"),
      "<gpx></gpx>",
    );

    const result = await parseHealthExportXml(path.join(dir, "export.xml"), {
      checkUnreferencedGpxFiles: true,
    });
    expect(result.workouts).toHaveLength(1);
  });
});

describe("countGpxTrackpoints", () => {
  it("returns exists:false for a missing file", async () => {
    const result = await countGpxTrackpoints(
      path.join(FIXTURES, "workout-routes", "nope.gpx"),
    );
    expect(result).toEqual({ exists: false, count: 0 });
  });

  it("counts trkpt elements in the fixture GPX", async () => {
    const result = await countGpxTrackpoints(
      path.join(FIXTURES, "workout-routes", "route_garmin_2026-09-20.gpx"),
    );
    expect(result).toEqual({ exists: true, count: 2 });
  });

  it("returns 0 for an empty GPX", async () => {
    const result = await countGpxTrackpoints(
      path.join(FIXTURES, "workout-routes", "route_hole19_empty.gpx"),
    );
    expect(result).toEqual({ exists: true, count: 0 });
  });
});
