/**
 * Shared safety limits applied by every parser (build plan §7.3 lane 2
 * "Safety", hardened after the Opus security gate found unbounded memory
 * and CPU on a crafted FIT file — see `fit-prescan.ts` for the FIT-
 * specific walker this module's limits feed).
 */

/** Input size cap for every format (FIT, GPX, CSV alike). A file over
 * this is refused outright before any parsing work happens.
 *
 * Originally 20 MB for GPX/CSV and a separate, lower 5 MB for FIT (after
 * a 19 MB crafted FIT file was shown to reach 2–3.4 GB peak RSS and 30 s
 * wall time in `fit-file-parser`). Round 2 of the security gate asked
 * for one 5 MB cap across all three formats — a real golf round's GPX or
 * CSV export is also well under 1 MB (a multi-hour, 1 Hz GPS track), so
 * there was no real-file reason for GPX/CSV to be allowed 4× more room
 * than FIT, and the format-specific hardening below it
 * (`fit-prescan.ts`'s message/field-count walk, `csv-rows.ts`'s row cap)
 * is what actually bounds a small-but-densely-packed hostile file within
 * whatever this cap allows through — this cap is just the cheap first
 * refusal, for every format equally. */
export const MAX_INPUT_BYTES = 5 * 1024 * 1024; // 5 MB

/** Alias for `MAX_INPUT_BYTES`, kept for call sites that name the format
 * explicitly (`parse-fit.ts`) — same value, not a separate cap. */
export const MAX_FIT_INPUT_BYTES = MAX_INPUT_BYTES;

/** CSV row cap, checked *during* tokenization (`csv-rows.ts`), not after
 * — a 19.9 MB file of ~9.9 million tiny empty rows took 17.8 s to
 * tokenize even though every individual field was small and the file
 * was under the 20 MB size cap; millions of row/array allocations was
 * the actual cost, and stopping early is what bounds it. Set an order of
 * magnitude above `MAX_FIXES` so a legitimately dense multi-day CSV
 * export is never the thing that hits this. */
export const MAX_CSV_ROWS = 500_000;

/** Fix count cap. A file with more raw fixes than this is truncated (kept
 * first, dropped rest, sorted afterwards) with a warning — downsampling
 * for matching is `@golfraven/matching`'s `simplifyToMaxPoints`, not this
 * package's job; this cap exists only to bound memory/CPU on a hostile or
 * absurd input. */
export const MAX_FIXES = 200_000;

/** At most this many warnings are ever returned; beyond it a single
 * "N more" entry replaces the rest, so a crafted file that would
 * otherwise generate one warning per row/record/fix can't turn the
 * `warnings` array itself into an unbounded-memory vector. */
export const MAX_WARNINGS = 50;

/** Every echoed value inside a warning or an `ImportFailure.error` —
 * a raw field, a header, a course name, an error detail — is truncated
 * to this many characters before being embedded in the message, so a
 * crafted multi-megabyte field can't blow up the size of the result
 * itself (a value that would otherwise be echoed back in full). */
export const MAX_ECHO_CHARS = 64;

/** The cap on a sanitized free-text field (course name, device/creator
 * string) kept in `ImportedRound` itself — distinct from `MAX_ECHO_CHARS`
 * (which bounds a *diagnostic* echo, not stored output). 120 characters
 * comfortably fits any real course or device name. */
export const MAX_TEXT_FIELD_CHARS = 120;

export function checkInputSize(byteLength: number, cap: number = MAX_INPUT_BYTES): string | undefined {
  if (byteLength > cap) {
    return `input is ${byteLength} bytes, over the ${cap}-byte cap`;
  }
  return undefined;
}

/** True for a finite, in-range latitude. */
export function isValidLat(lat: number): boolean {
  return Number.isFinite(lat) && lat >= -90 && lat <= 90;
}

/** True for a finite, in-range longitude. */
export function isValidLon(lon: number): boolean {
  return Number.isFinite(lon) && lon >= -180 && lon <= 180;
}

/** True for a finite epoch-millisecond timestamp. Doesn't bound the range
 * (a device clock can be wrong; matching decides what to do with that) —
 * only rejects `NaN`/`Infinity`, which a JSON or XML round trip can
 * produce from a malformed source. */
export function isValidTimestamp(ts: number): boolean {
  return Number.isFinite(ts);
}

// A plain decimal number: optional sign, digits, optional fractional
// part. Deliberately excludes scientific notation, hex (`0x..`), leading
// `+`, and (critically) the empty string — `Number("")` is `0`, which
// would otherwise silently turn a missing coordinate into "null island".
const DECIMAL_RE = /^-?\d+(?:\.\d+)?$/;

/** Parses a coordinate/accuracy field with a strict decimal-only grammar
 * before ever calling `Number()`, so an empty string, `"0x10"`, `"1e1"`,
 * or whitespace-only input can never be silently coerced into `0`.
 * Returns `undefined` for anything that doesn't match. */
export function parseStrictDecimal(raw: string): number | undefined {
  const trimmed = raw.trim();
  if (!DECIMAL_RE.test(trimmed)) return undefined;
  const n = Number(trimmed);
  return Number.isFinite(n) ? n : undefined;
}

/** An accuracy of 0 or less isn't a meaningful horizontal-accuracy value
 * (real GPS accuracy is a strictly positive radius) — treat it as absent
 * rather than as "perfectly accurate", which a hostile or buggy source
 * could otherwise use to make a fix look better than any real fix ever
 * could. */
export function sanitizeAccuracy(raw: number | undefined): number | undefined {
  if (raw === undefined || !Number.isFinite(raw) || raw <= 0) return undefined;
  return raw;
}

/** Strips control characters (C0/C1, including newlines/tabs) and caps
 * length for a free-text field pulled from a file (a course name, a
 * device/creator string). This is a safety cap on what this package
 * stores/returns, not a full sanitizer for any particular downstream
 * sink — a spreadsheet export, for instance, still needs its own
 * formula-injection guard (leading `=`/`+`/`-`/`@`) at the point it
 * writes a CSV/XLSX cell; that's the exporter's job, not this parser's,
 * since the right guard depends on the destination format. */
export function sanitizeText(raw: string, maxLen: number = MAX_TEXT_FIELD_CHARS): string {
  // eslint-disable-next-line no-control-regex
  const stripped = raw.replace(/[\u0000-\u001f\u007f-\u009f]/g, "").trim();
  return stripped.length > maxLen ? stripped.slice(0, maxLen) : stripped;
}

/** Truncates a value before it's embedded in a warning or error message. */
export function truncateEcho(value: string, max: number = MAX_ECHO_CHARS): string {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

/** Caps a warnings list at `MAX_WARNINGS`, appending a single "N more"
 * summary entry instead of the rest, and truncates every entry (they may
 * already contain a truncated echo from the caller, but this is the
 * final backstop). */
export function finalizeWarnings(warnings: string[]): string[] {
  const truncated = warnings.map((w) => truncateEcho(w, MAX_ECHO_CHARS * 4));
  if (truncated.length <= MAX_WARNINGS) return truncated;
  const kept = truncated.slice(0, MAX_WARNINGS);
  kept.push(`…${truncated.length - MAX_WARNINGS} more warning(s) omitted`);
  return kept;
}

/** Truncates an `ImportFailure.error` string. */
export function finalizeError(error: string): string {
  return truncateEcho(error, MAX_ECHO_CHARS);
}

export interface FixLike {
  lat: number;
  lon: number;
  timestamp: number;
}

/**
 * Applies the fix-count cap and sorts ascending by timestamp. Invalid
 * (non-finite or out-of-range) fixes must already have been dropped by
 * the caller — this only caps count and orders what's left, and reports
 * what it did via the returned warnings.
 */
export function capAndSortFixes<T extends FixLike>(fixes: T[]): { fixes: T[]; warnings: string[] } {
  const warnings: string[] = [];
  let capped = fixes;
  if (fixes.length > MAX_FIXES) {
    capped = fixes.slice(0, MAX_FIXES);
    warnings.push(
      `fix count ${fixes.length} exceeded the ${MAX_FIXES} cap; truncated to the first ${MAX_FIXES} — downsampling for matching is left to the matcher`,
    );
  }
  const sorted = capped
    .map((item, index) => ({ item, index }))
    .sort((a, b) => a.item.timestamp - b.item.timestamp || a.index - b.index)
    .map((entry) => entry.item);
  return { fixes: sorted, warnings };
}
