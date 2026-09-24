/**
 * `@golfraven/import` — on-device file import for a played round
 * (build plan §7.3 lane 2, "Import a round (FIT/GPX/CSV), parsed on
 * device"). Each parser turns raw file bytes into a normalized
 * `ImportedRound`; `toMatcherInput` adapts that into
 * `@golfraven/matching`'s `matchRoute()` input; `correlationKey` gives
 * the `health_route` ↔ `file_import` correlation bucket (build plan
 * §4.5). Every parser is pure: bytes in, a result out, no filesystem or
 * network access.
 */

export { parseFitFile } from "./parse-fit.js";
export { parseGpxFile } from "./parse-gpx.js";
export { parseCsvFile } from "./parse-csv.js";

export { toMatcherInput } from "./to-matcher-input.js";
export type { ToMatcherInputOptions } from "./to-matcher-input.js";

export { correlationKey } from "./correlation.js";

export { MAX_INPUT_BYTES, MAX_FIXES } from "./safety.js";

export type {
  ImportFormat,
  ImportedFix,
  ImportedScoreHole,
  ImportedRound,
  ImportResult,
  ImportSuccess,
  ImportFailure,
} from "./types.js";
