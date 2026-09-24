/**
 * A single dispatch entry point over the three format-specific parsers,
 * carrying an `AbortSignal` through to the ones that can act on it
 * (build plan §7.3 lane 2 security follow-up).
 *
 * **Where the real safety boundary is.** This package bounds what it
 * can: input size (`MAX_INPUT_BYTES`/`MAX_FIT_INPUT_BYTES`), FIT message/
 * field counts (`fit-prescan.ts`), and — here — a cooperative abort
 * check at each parser's natural checkpoints. None of that is a
 * substitute for running the parse off the main thread with a hard
 * timeout: a synchronous CPU-bound loop in JS can only be interrupted
 * between iterations it chooses to check at, never truly preempted, and
 * `fit-file-parser`'s own decode (once the prescan has let a file
 * through) isn't abortable at all from the outside. **The app is
 * expected to call this from a worker and enforce a wall-clock timeout
 * around the call** (e.g. `Promise.race` against a timer that terminates
 * the worker) — that outer boundary is what actually guarantees a stuck
 * parse can't hang the UI thread; `signal` support here is a fast,
 * cooperative early-exit for the common case, not a replacement for it.
 */
import type { ImportedRound, ImportFormat, ImportResult } from "./types.js";
import { parseFitFile, type ParseFitOptions } from "./parse-fit.js";
import { parseGpxFile, type ParseGpxOptions } from "./parse-gpx.js";
import { parseCsvFile } from "./parse-csv.js";

export interface ParseRoundOptions {
  format: ImportFormat;
  /** The facility's IANA timezone (build plan §4.1 `tz`) — passed
   * through to `parseFitFile`/`parseGpxFile` for their routeless
   * `localDate` fallback. Ignored for `csv` (the scorecard format's
   * `date` column is already an explicit local date; the fixes format
   * has no file-level date to convert). */
  tz?: string;
  /** Honored by the FIT path (checked between prescan messages and
   * before/after the decode) and checked once up front for GPX/CSV,
   * whose own parse loops are cheap enough after the size cap that a
   * mid-parse check adds little — see this module's doc comment for the
   * honest limit of what a synchronous abort check can guarantee. */
  signal?: AbortSignal;
}

/** Dispatches to the parser for `options.format`. */
export async function parseRound(
  bytes: Uint8Array,
  options: ParseRoundOptions,
): Promise<ImportResult> {
  if (options.signal?.aborted) return { ok: false, error: "aborted" };

  switch (options.format) {
    case "fit": {
      const fitOptions: ParseFitOptions = {
        ...(options.tz !== undefined ? { tz: options.tz } : {}),
        ...(options.signal !== undefined ? { signal: options.signal } : {}),
      };
      return parseFitFile(bytes, fitOptions);
    }
    case "gpx": {
      const gpxOptions: ParseGpxOptions =
        options.tz !== undefined ? { tz: options.tz } : {};
      return parseGpxFile(bytes, gpxOptions);
    }
    case "csv":
      return parseCsvFile(bytes);
    default: {
      const _exhaustive: never = options.format;
      return {
        ok: false,
        error: `unknown import format "${String(_exhaustive)}"`,
      };
    }
  }
}

export type { ImportedRound };
