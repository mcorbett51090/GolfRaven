/**
 * Streaming parser for Apple Health's `export.xml` (X1, build plan §10 P0;
 * `docs/p0/X1.md` step 3; `docs/owner/x1-k4b-device-protocol.md` §2d).
 *
 * `export.xml` from "Settings → Health → profile icon → Export All Health
 * Data" can be hundreds of MB (one file holding a user's entire Health
 * history), so this reads it as a stream via `sax` (a small, dependency-free
 * streaming XML parser — see `tools/p0/README.md` for why a dependency was
 * used at all) rather than loading it into memory or a DOM.
 *
 * ## `[unverified — training knowledge]` — the export.xml shape this relies on
 *
 * Apple does not publish a schema for `export.xml`. Everything below about
 * its exact element/attribute names is training knowledge, not a checked
 * source, and `docs/p0/X1.md` / the device protocol flag the same fields
 * the same way. This module's contract with that uncertainty is: **fail
 * loudly** (throw, never silently return an empty result) when what it
 * finds doesn't match what it expects, per two checks —
 *
 * 1. **Root element.** The whole file is expected to be wrapped in a single
 *    `<HealthData>` root element `[unverified — training knowledge]`. If the
 *    first element sax sees has any other tag name, this throws
 *    `HealthExportShapeError` immediately (the stream is destroyed without
 *    reading the rest of a possibly huge file).
 * 2. **Workout element shape.** Each workout is expected to be a `<Workout
 *    workoutActivityType="..." sourceName="..." sourceVersion="..."
 *    device="..." creationDate="..." startDate="..." endDate="..."
 *    duration="..." durationUnit="...">` element `[unverified — training
 *    knowledge on the exact attribute set, esp. `device` being an inline
 *    attribute rather than a nested element]`. If `<Workout>` elements are
 *    present but **none** of them carry a `workoutActivityType` attribute,
 *    that means the shape has changed from what this parser expects, so it
 *    throws rather than silently reporting zero golf workouts. Zero
 *    `<Workout>` elements in the whole file is treated as a legitimate
 *    (if unhelpful) "no workouts recorded" result, not a shape error.
 * 3. **A GPS route, when present, is expected as a nested `<WorkoutRoute
 *    sourceName="..." ...>` child of `<Workout>`, itself containing a
 *    `<FileReference path="/workout-routes/route_....gpx"/>` child**
 *    `[unverified — training knowledge]`. This is the least-certain part of
 *    the shape (community write-ups disagree on whether `WorkoutRoute` is
 *    nested inside `Workout` or a sibling correlated by timestamp) — it is
 *    exactly what the synthetic fixtures in `tools/p0/test/fixtures/` encode
 *    and what the tests pin down, so Matt's real export.xml is the first
 *    real-world check of this assumption (see README "Known risk"). Gate
 *    finding B-8: because this is the LEAST certain part of the shape, a
 *    `<WorkoutRoute>` seen as a SIBLING of `<Workout>` (not nested inside
 *    one) is exactly the case most likely for a real export to hit — and
 *    the nested-only reader used to ignore it entirely, silently reporting
 *    `routePresent: false` for every workout with no warning at all (a
 *    silent false X1 kill). Any such sibling `<WorkoutRoute>` now throws
 *    `HealthExportShapeError` instead.
 *
 * `workoutActivityType === "HKWorkoutActivityTypeGolf"` is the exact string
 * this filters on, per the same unverified-training-knowledge naming
 * convention X1.md itself quotes.
 */
import { createReadStream, existsSync } from "node:fs";
import sax from "sax";

export const GOLF_ACTIVITY_TYPE = "HKWorkoutActivityTypeGolf";

export class HealthExportShapeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HealthExportShapeError";
  }
}

export interface RawIosWorkout {
  workoutActivityType: string;
  sourceName: string;
  sourceVersion: string | null;
  device: string | null;
  creationDate: string | null;
  startDate: string | null;
  endDate: string | null;
  duration: string | null;
  durationUnit: string | null;
  hasWorkoutRoute: boolean;
  routeFileReferencePath: string | null;
}

export interface ParseHealthExportResult {
  rootTag: string;
  totalWorkoutElementsSeen: number;
  workouts: RawIosWorkout[];
}

/**
 * Streams `xmlPath` and returns every `<Workout>` element found, with a
 * loud failure (see module doc) instead of a silent empty result when the
 * file's shape doesn't match what this parser expects.
 */
export function parseHealthExportXml(xmlPath: string): Promise<ParseHealthExportResult> {
  if (!existsSync(xmlPath)) {
    return Promise.reject(new Error(`export.xml not found at ${xmlPath}`));
  }

  return new Promise((resolve, reject) => {
    const parser = sax.createStream(true /* strict */, { trim: false });
    const stream = createReadStream(xmlPath, { encoding: "utf8" });

    let settled = false;
    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      parser.removeAllListeners();
      stream.destroy();
      reject(err);
    };
    const succeed = (result: ParseHealthExportResult) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    let rootTag: string | null = null;
    let totalWorkoutElementsSeen = 0;
    let totalWorkoutElementsWithActivityType = 0;
    const workouts: RawIosWorkout[] = [];

    // Nesting state: while inside a <Workout>, and while inside that
    // Workout's <WorkoutRoute>, we look for a <FileReference path="...">.
    let depth = 0;
    let currentWorkout: RawIosWorkout | null = null;
    let insideWorkoutRoute = false;
    // Gate finding B-8: a <WorkoutRoute> seen while NOT inside a <Workout>
    // (a sibling, not a nested child) — counted so the whole parse can fail
    // loudly instead of silently reporting zero routes.
    let siblingWorkoutRouteCount = 0;

    parser.on("opentag", (node: { name: string; attributes: Record<string, string> }) => {
      depth += 1;
      if (rootTag === null) {
        rootTag = node.name;
        if (rootTag !== "HealthData") {
          fail(
            new HealthExportShapeError(
              `Unexpected root element <${rootTag}> in export.xml — expected <HealthData> ` +
                `[unverified — training knowledge]. This export.xml does not look like an Apple ` +
                `Health export, or Apple's format has changed; refusing to report a possibly-empty ` +
                `result silently.`,
            ),
          );
        }
        return;
      }

      if (node.name === "Workout") {
        totalWorkoutElementsSeen += 1;
        const a = node.attributes;
        if (a.workoutActivityType) {
          totalWorkoutElementsWithActivityType += 1;
        }
        currentWorkout = {
          workoutActivityType: a.workoutActivityType ?? "",
          sourceName: a.sourceName ?? "",
          sourceVersion: a.sourceVersion ?? null,
          device: a.device ?? null,
          creationDate: a.creationDate ?? null,
          startDate: a.startDate ?? null,
          endDate: a.endDate ?? null,
          duration: a.duration ?? null,
          durationUnit: a.durationUnit ?? null,
          hasWorkoutRoute: false,
          routeFileReferencePath: null,
        };
        insideWorkoutRoute = false;
        return;
      }

      if (node.name === "WorkoutRoute") {
        if (currentWorkout) {
          insideWorkoutRoute = true;
          currentWorkout.hasWorkoutRoute = true;
        } else {
          // B-8: a <WorkoutRoute> outside any <Workout> — the sibling shape
          // this reader does not (and, per the module doc, cannot safely)
          // support. Counted now; the parse fails loudly once complete
          // (see the closetag handler) rather than mid-stream, so the
          // error message can report how many were seen.
          siblingWorkoutRouteCount += 1;
        }
        return;
      }

      if (node.name === "FileReference" && insideWorkoutRoute && currentWorkout) {
        if (node.attributes.path) {
          currentWorkout.routeFileReferencePath = node.attributes.path;
        }
        return;
      }
    });

    parser.on("closetag", (name: string) => {
      depth -= 1;
      if (name === "WorkoutRoute") {
        insideWorkoutRoute = false;
      }
      if (name === "Workout" && currentWorkout) {
        workouts.push(currentWorkout);
        currentWorkout = null;
      }
      if (depth === 0 && rootTag !== null) {
        // Closed the root element — parsing is complete.
        if (totalWorkoutElementsSeen > 0 && totalWorkoutElementsWithActivityType === 0) {
          fail(
            new HealthExportShapeError(
              `Found ${totalWorkoutElementsSeen} <Workout> element(s) in export.xml, but none carry ` +
                `a workoutActivityType attribute — the Workout element shape has changed from what ` +
                `this tool expects [unverified — training knowledge]. Refusing to silently report ` +
                `zero golf workouts; update health-export-xml.ts to match the real shape.`,
            ),
          );
          return;
        }
        if (siblingWorkoutRouteCount > 0) {
          fail(
            new HealthExportShapeError(
              `Found ${siblingWorkoutRouteCount} <WorkoutRoute> element(s) that are NOT nested inside a ` +
                `<Workout> element (a sibling, not a child) — gate finding B-8. This reader only supports ` +
                `the nested shape [unverified — training knowledge], so it cannot correlate a sibling route ` +
                `to its workout; refusing to silently report every workout as routePresent: false. Update ` +
                `health-export-xml.ts to match the real shape once Matt's real export.xml confirms it.`,
            ),
          );
          return;
        }
        succeed({ rootTag, totalWorkoutElementsSeen, workouts });
      }
    });

    parser.on("error", (err: Error) => {
      fail(new Error(`export.xml is not well-formed XML: ${err.message}`));
    });

    stream.on("error", (err: Error) => {
      fail(new Error(`Failed to read ${xmlPath}: ${err.message}`));
    });

    stream.pipe(parser);
  });
}

/**
 * Counts `<trkpt` occurrences in a GPX file by streaming it in fixed-size
 * chunks with a small overlap (so a match isn't missed when it straddles a
 * chunk boundary) — a plain substring count, not a full XML parse, which is
 * enough for "how many trackpoints does this route have" and keeps this
 * cheap on a large file. Returns `{ exists: false, count: 0 }` if the file
 * is missing (the caller uses this to distinguish "route file missing" from
 * "route file present but empty").
 */
export function countGpxTrackpoints(
  gpxPath: string,
): Promise<{ exists: boolean; count: number }> {
  if (!existsSync(gpxPath)) {
    return Promise.resolve({ exists: false, count: 0 });
  }

  const NEEDLE = "<trkpt";
  return new Promise((resolve, reject) => {
    const stream = createReadStream(gpxPath, { encoding: "utf8" });
    let count = 0;
    let tail = "";

    stream.on("data", (chunk: string) => {
      const combined = tail + chunk;
      let idx = 0;
      while ((idx = combined.indexOf(NEEDLE, idx)) !== -1) {
        count += 1;
        idx += NEEDLE.length;
      }
      tail = combined.slice(Math.max(0, combined.length - (NEEDLE.length - 1)));
    });
    stream.on("end", () => resolve({ exists: true, count }));
    stream.on("error", (err) => reject(new Error(`Failed to read ${gpxPath}: ${err.message}`)));
  });
}
