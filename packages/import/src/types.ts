/**
 * `@golfraven/import` public types (build plan §7.3 lane 2, §7.4).
 *
 * A parser turns file bytes into a normalized `ImportedRound`. Parsing is
 * pure: bytes in, a result out, no filesystem or network access, so the
 * same code runs on device (Expo) and in tests. `toMatcherInput` then
 * adapts an `ImportedRound` into `@golfraven/matching`'s `MatchRouteInput`.
 */

export type ImportFormat = "fit" | "gpx" | "csv";

/** One recorded location fix, already in the matcher's coordinate
 * convention (`lat`, `lon`). */
export interface ImportedFix {
  lat: number;
  lon: number;
  /** Epoch milliseconds. */
  timestamp: number;
  /** Horizontal accuracy in meters, when the source file states one. */
  accuracyMeters?: number;
}

/** One hole's recorded strokes, when the source file carries a real
 * per-hole scorecard (e.g. a future Garmin S62 scorecard FIT). The minimal
 * CSV scorecard format (build plan §7.3 lane 2) carries only a round total,
 * not per-hole strokes — see `ImportedRound.totalScore` for that shape. */
export interface ImportedScoreHole {
  hole: number;
  strokes: number;
  par?: number;
}

/**
 * The normalized shape every parser (`parseFitFile`, `parseGpxFile`,
 * `parseCsvFile`) returns on success.
 *
 * Exactly one of the time shapes is populated when the round is dated at
 * all: `startedAt`/`endedAt` (a route or a file with real timestamps), or
 * `localDate` (a scorecard-only file with no timestamps, build plan A2-17
 * "`local_date` for date-only evidence"). Both may be absent for a file
 * that carries neither — see each parser's doc comment for when that
 * happens; callers should treat that as an unusable round and surface the
 * `warnings`.
 */
export interface ImportedRound {
  source: "file_import";
  format: ImportFormat;
  /** A device or creator string pulled from the file's own metadata, when
   * present (FIT `file_id.manufacturer`/`product_name`, GPX `creator`). */
  device?: string;
  /** Epoch milliseconds of the earliest fix, when the file carries
   * timestamps. */
  startedAt?: number;
  /** Epoch milliseconds of the latest fix, when the file carries
   * timestamps. */
  endedAt?: number;
  /** Facility-local calendar date, `YYYY-MM-DD`, for a file with no
   * timestamps at all (build plan §4.1 `tz`, A2-17). Never set at the same
   * time as `startedAt`/`endedAt`. */
  localDate?: string;
  /** Sorted ascending by `timestamp`. An empty array means the file
   * carries no usable route — the round can still be badge evidence via
   * `local_date` (build plan §4.5 `file_import` 0.10 row), just never a
   * `matchRoute()` candidate. */
  fixes: ImportedFix[];
  /** A course name pulled from the file's own golf data, when present
   * (FIT `sport.name`, or a CSV/GPX course field) — a hint for typeahead,
   * never authoritative (matching still decides the course id). */
  courseNameHint?: string;
  /** Hole count, when the file states one. */
  holes?: number;
  /** Per-hole strokes, only when the source file actually carries
   * per-hole data. */
  scores?: ImportedScoreHole[];
  /** A round-total score, for formats that carry only a single number
   * (the minimal CSV scorecard format: `date,course,holes,score`). Kept
   * distinct from `scores` so a caller never has to guess whether a
   * single-entry `scores` array means "one hole played" or "the total". */
  totalScore?: number;
  /** Non-fatal issues found while parsing — a truncated fix count, a
   * dropped invalid fix, an unrecognized FIT message number, a course
   * name that looked ambiguous, etc. Never thrown; always surfaced so the
   * app/reviewer can see what was silently adjusted. */
  warnings: string[];
}

export interface ImportSuccess {
  ok: true;
  round: ImportedRound;
}

export interface ImportFailure {
  ok: false;
  /** A human-readable reason the file was refused outright (corrupt,
   * truncated past recovery, not the claimed format, ambiguous CSV
   * layout, an XML file that isn't GPX, oversized input, etc.). */
  error: string;
}

export type ImportResult = ImportSuccess | ImportFailure;
