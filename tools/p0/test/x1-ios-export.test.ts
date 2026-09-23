import { describe, expect, it } from "vitest";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runX1IosExport, renderMarkdownTable } from "../src/x1-ios-export.js";
import { HealthExportShapeError, countGpxTrackpoints } from "../src/health-export-xml.js";
import type { RoundWindow } from "../src/round-windows.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(__dirname, "fixtures");

/** The good fixture's export.xml lives directly under FIXTURES, and its
 * WorkoutRoute FileReference paths are "/workout-routes/...", resolved
 * relative to the export dir — so FIXTURES itself is "the export dir". */
const GOOD_EXPORT_DIR = FIXTURES;

/** Covers every golf workout in export.xml EXCEPT the 2026-08-01 Garmin one
 * (decision 0001 Addendum F round-window filtering — gate finding B-7),
 * so these tests reproduce the pre-Addendum-F fixture behavior except for
 * that one, deliberately-excluded old workout. */
const GOOD_ROUND_WINDOWS: RoundWindow[] = [{ startIso: "2026-09-15T00:00:00Z", endIso: "2026-09-21T00:00:00Z" }];

/** Just the 2026-09-20 cluster (Garmin/Apple Watch/18Birdies), UTC. */
const TIGHT_ROUND_WINDOWS: RoundWindow[] = [{ startIso: "2026-09-20T12:00:00Z", endIso: "2026-09-20T14:00:00Z" }];

describe("x1-ios-export: parsing a well-formed export.xml", () => {
  it("finds all golf workouts within the round window and filters out non-golf ones", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, { roundWindows: GOOD_ROUND_WINDOWS });
    expect(result.totalWorkoutElementsSeen).toBe(6); // 5 golf + 1 running (unaffected by window filter)
    expect(result.golfWorkoutCount).toBe(4); // the 2026-08-01 Garmin workout is outside every window
    const sources = result.workouts.map((w) => w.sourceName).sort();
    expect(sources).toEqual(["18Birdies", "Garmin Connect", "Hole19", "Matt's Apple Watch"]);
  });

  it("reports route present with a positive trackpoint count for the Garmin workout", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, { roundWindows: GOOD_ROUND_WINDOWS });
    const garminRecent = result.workouts.find(
      (w) => w.sourceName === "Garmin Connect" && w.startDate?.startsWith("2026-09-20"),
    );
    expect(garminRecent).toBeDefined();
    expect(garminRecent!.hasWorkoutRoute).toBe(true);
    expect(garminRecent!.routeFileExists).toBe(true);
    expect(garminRecent!.routeTrackpointCount).toBe(2);
    expect(garminRecent!.routePresent).toBe(true);
    expect(garminRecent!.verdict).toBe("pass");
  });

  it("reports route NOT present when the workout has no WorkoutRoute at all (Apple Watch)", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, { roundWindows: GOOD_ROUND_WINDOWS });
    const appleWatch = result.workouts.find((w) => w.sourceName === "Matt's Apple Watch");
    expect(appleWatch).toBeDefined();
    expect(appleWatch!.hasWorkoutRoute).toBe(false);
    expect(appleWatch!.routePresent).toBe(false);
    expect(appleWatch!.verdict).toBe("fail");
  });

  it("reports route NOT present when the referenced GPX file is missing on disk (18Birdies)", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, { roundWindows: GOOD_ROUND_WINDOWS });
    const birdies = result.workouts.find((w) => w.sourceName === "18Birdies");
    expect(birdies).toBeDefined();
    expect(birdies!.hasWorkoutRoute).toBe(true);
    expect(birdies!.routeFileExists).toBe(false);
    expect(birdies!.routePresent).toBe(false);
    expect(birdies!.verdict).toBe("fail");
    expect(result.warnings.some((w) => w.includes("does not exist"))).toBe(true);
  });

  it("reports route NOT present when the GPX file exists but has 0 trackpoints (Hole19)", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, { roundWindows: GOOD_ROUND_WINDOWS });
    const hole19 = result.workouts.find((w) => w.sourceName === "Hole19");
    expect(hole19).toBeDefined();
    expect(hole19!.routeFileExists).toBe(true);
    expect(hole19!.routeTrackpointCount).toBe(0);
    expect(hole19!.routePresent).toBe(false);
    expect(hole19!.verdict).toBe("fail");
  });

  it("--since filters out workouts before the cutoff date, on top of the round-window filter", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, { since: "2026-09-01", roundWindows: GOOD_ROUND_WINDOWS });
    const garminStarts = result.workouts.filter((w) => w.sourceName === "Garmin Connect").map((w) => w.startDate);
    expect(garminStarts).toEqual(["2026-09-20 09:00:00 -0400"]);
    expect(result.golfWorkoutCount).toBe(4);
  });

  it("renders a markdown table with the memo's columns", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, { roundWindows: GOOD_ROUND_WINDOWS });
    const md = renderMarkdownTable(result);
    expect(md).toContain("| Source | OS | Workout/exercise written? | Route present? |");
    expect(md).toContain("CONSENT_REQUIRED + follow-up read");
    expect(md).toContain("| Garmin Connect | iOS | Yes | Yes |");
    expect(md).toContain("N/A (iOS)");
  });
});

describe("x1-ios-export: round window (decision 0001 Addendum F, gate finding B-7)", () => {
  it("refuses (throws) when roundWindows is empty — never runs unwindowed", async () => {
    await expect(runX1IosExport(GOOD_EXPORT_DIR, { roundWindows: [] })).rejects.toThrow(/round window/);
  });

  it("excludes a workout outside every logged window, with a warning naming how many", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, { roundWindows: TIGHT_ROUND_WINDOWS });
    // Only the 2026-09-20 cluster (3 workouts) is inside TIGHT_ROUND_WINDOWS;
    // the 2026-08-01 Garmin workout and the 2026-09-15 Hole19 workout are not.
    expect(result.golfWorkoutCount).toBe(3);
    expect(result.workouts.some((w) => w.sourceName === "Hole19")).toBe(false);
    expect(result.warnings.some((w) => w.includes("excluded") && w.includes("round window"))).toBe(true);
  });

  it("a workout starting 59 minutes before the window (within the 60-min slack) still counts", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, {
      // Garmin's 2026-09-20 workout starts at 13:00:00Z; a window starting
      // 13:59:00Z is 59 minutes later — within the ±60 min slack.
      roundWindows: [{ startIso: "2026-09-20T13:59:00Z", endIso: "2026-09-20T14:30:00Z" }],
    });
    expect(result.workouts.some((w) => w.sourceName === "Garmin Connect" && w.startDate?.startsWith("2026-09-20"))).toBe(
      true,
    );
  });

  it("a workout starting 61 minutes before the window (outside the 60-min slack) does not count", async () => {
    const result = await runX1IosExport(GOOD_EXPORT_DIR, {
      roundWindows: [{ startIso: "2026-09-20T14:01:00Z", endIso: "2026-09-20T14:30:00Z" }],
    });
    expect(result.workouts.some((w) => w.sourceName === "Garmin Connect" && w.startDate?.startsWith("2026-09-20"))).toBe(
      false,
    );
  });
});

describe("x1-ios-export: loud failures on shape mismatches", () => {
  it("throws HealthExportShapeError for a wrong root element (not silently empty)", async () => {
    const { parseHealthExportXml } = await import("../src/health-export-xml.js");
    await expect(parseHealthExportXml(path.join(FIXTURES, "export-bad-root.xml"))).rejects.toBeInstanceOf(
      HealthExportShapeError,
    );
  });

  it("throws HealthExportShapeError when Workout elements exist but none carry workoutActivityType", async () => {
    const { parseHealthExportXml } = await import("../src/health-export-xml.js");
    await expect(
      parseHealthExportXml(path.join(FIXTURES, "export-bad-workout-shape.xml")),
    ).rejects.toBeInstanceOf(HealthExportShapeError);
  });

  it("does NOT fail when there are simply zero golf workouts (legitimate empty result)", async () => {
    const { parseHealthExportXml } = await import("../src/health-export-xml.js");
    const result = await parseHealthExportXml(path.join(FIXTURES, "export-no-golf.xml"));
    expect(result.totalWorkoutElementsSeen).toBe(1);
    expect(result.workouts.filter((w) => w.workoutActivityType === "HKWorkoutActivityTypeGolf")).toHaveLength(0);
  });

  it("throws HealthExportShapeError for a <WorkoutRoute> that is a SIBLING of <Workout>, not nested (gate finding B-8)", async () => {
    const { parseHealthExportXml } = await import("../src/health-export-xml.js");
    await expect(
      parseHealthExportXml(path.join(FIXTURES, "export-sibling-workout-route.xml")),
    ).rejects.toMatchObject({ name: "HealthExportShapeError", message: expect.stringContaining("sibling") });
  });

  it("fails loudly when export.xml is missing entirely", async () => {
    await expect(
      runX1IosExport(path.join(FIXTURES, "does-not-exist"), { roundWindows: GOOD_ROUND_WINDOWS }),
    ).rejects.toThrow(/not found/);
  });
});

describe("countGpxTrackpoints", () => {
  it("returns exists:false for a missing file", async () => {
    const result = await countGpxTrackpoints(path.join(FIXTURES, "workout-routes", "nope.gpx"));
    expect(result).toEqual({ exists: false, count: 0 });
  });

  it("counts trkpt elements in the fixture GPX", async () => {
    const result = await countGpxTrackpoints(path.join(FIXTURES, "workout-routes", "route_garmin_2026-09-20.gpx"));
    expect(result).toEqual({ exists: true, count: 2 });
  });

  it("returns 0 for an empty GPX", async () => {
    const result = await countGpxTrackpoints(path.join(FIXTURES, "workout-routes", "route_hole19_empty.gpx"));
    expect(result).toEqual({ exists: true, count: 0 });
  });
});
