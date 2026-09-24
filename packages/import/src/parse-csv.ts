/**
 * The minimal CSV import format (build plan §7.3 lane 2). Exactly one of
 * two header shapes, matched exactly and case-insensitively — an
 * unrecognized or mixed header is refused rather than guessed at:
 *
 *  - `timestamp,lat,lon` or `timestamp,lat,lon,accuracy` — a fix trace.
 *    `timestamp` must be a strict ISO 8601 date-time with `Z` or a
 *    numeric UTC offset (`timestamps.ts` — naive times, US-style dates,
 *    and bare epoch numbers are all refused, not guessed at);
 *    `lat`/`lon`/`accuracy` are decimal degrees/meters, validated with a
 *    decimal-only regex before `Number()` (`safety.ts`'s
 *    `parseStrictDecimal` — an empty string or `"0x10"` never silently
 *    becomes `0`).
 *  - `date,course,holes,score` — a scorecard row with no route.
 *    `date` must be a real `YYYY-MM-DD` calendar date (facility-local,
 *    per build plan §4.1 `tz` — this package has no facility to resolve a
 *    timezone against, so it takes the date exactly as written); `holes`
 *    a positive integer up to 36 (covers 9, 18, and a 27-hole
 *    composite); `score` a positive integer. Only the first data row is
 *    used; a file is one round.
 *
 * RFC 4180 quoting throughout (`csv-rows.ts`).
 */
import type { ImportedFix, ImportedRound, ImportResult } from "./types.js";
import { parseCsvRows } from "./csv-rows.js";
import {
  checkInputSize,
  capAndSortFixes,
  isValidLat,
  isValidLon,
  parseStrictDecimal,
  sanitizeAccuracy,
  sanitizeText,
  finalizeWarnings,
  finalizeError,
  truncateEcho,
  MAX_INPUT_BYTES,
  MAX_CSV_ROWS,
} from "./safety.js";
import { parseStrictTimestamp } from "./timestamps.js";

const FIXES_HEADER_3 = ["timestamp", "lat", "lon"];
const FIXES_HEADER_4 = ["timestamp", "lat", "lon", "accuracy"];
const SCORECARD_HEADER = ["date", "course", "holes", "score"];
const MAX_HOLES = 36;

function normalizeHeader(row: string[]): string[] {
  return row.map((cell) => cell.trim().toLowerCase());
}

function headerEquals(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

function isRealCalendarDate(dateStr: string): boolean {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateStr);
  if (!m) return false;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  if (month < 1 || month > 12 || day < 1 || day > 31) return false;
  const dt = new Date(Date.UTC(year, month - 1, day));
  return dt.getUTCFullYear() === year && dt.getUTCMonth() === month - 1 && dt.getUTCDate() === day;
}

function isPositiveInteger(n: number): boolean {
  return Number.isInteger(n) && n > 0;
}

function parseFixesCsv(rows: string[][], rowsTruncated: boolean): ImportResult {
  const hasAccuracy = normalizeHeader(rows[0]!).length === 4;
  const warnings: string[] = [];
  const fixes: ImportedFix[] = [];
  if (rowsTruncated) {
    warnings.push(`CSV had over ${MAX_CSV_ROWS} rows; stopped reading after the cap`);
  }

  for (let i = 1; i < rows.length; i++) {
    const row = rows[i]!;
    const rowNum = i + 1; // 1-based, header is row 1
    if (row.length < 3 || (hasAccuracy && row.length < 4)) {
      warnings.push(`row ${rowNum}: too few columns, skipped`);
      continue;
    }
    const parsedTime = parseStrictTimestamp(row[0]!);
    const lat = parseStrictDecimal(row[1]!);
    const lon = parseStrictDecimal(row[2]!);
    const accuracyRaw = hasAccuracy ? row[3]?.trim() : undefined;
    const accuracyParsed =
      accuracyRaw !== undefined && accuracyRaw.length > 0 ? parseStrictDecimal(accuracyRaw) : undefined;

    if (parsedTime === undefined) {
      warnings.push(`row ${rowNum}: timestamp "${truncateEcho(row[0]!)}" isn't a strict ISO 8601 Z/offset time, skipped`);
      continue;
    }
    if (lat === undefined || lon === undefined || !isValidLat(lat) || !isValidLon(lon)) {
      warnings.push(`row ${rowNum}: invalid lat/lon, skipped`);
      continue;
    }
    if (accuracyRaw !== undefined && accuracyRaw.length > 0 && accuracyParsed === undefined) {
      warnings.push(`row ${rowNum}: invalid accuracy "${truncateEcho(accuracyRaw)}", ignored for this row`);
    }
    const accuracyMeters = sanitizeAccuracy(accuracyParsed);
    fixes.push({
      lat,
      lon,
      timestamp: parsedTime.ms,
      ...(accuracyMeters !== undefined ? { accuracyMeters } : {}),
    });
  }

  const { fixes: sortedFixes, warnings: capWarnings } = capAndSortFixes(fixes);
  warnings.push(...capWarnings);

  const round: ImportedRound = {
    source: "file_import",
    format: "csv",
    fixes: sortedFixes,
    warnings: [],
  };
  if (sortedFixes.length > 0) {
    // Routed: real timestamps only, never a derived date (A2-17).
    round.startedAt = sortedFixes[0]!.timestamp;
    round.endedAt = sortedFixes[sortedFixes.length - 1]!.timestamp;
  } else {
    // Routeless: the fixes-format header has no separate date field to
    // fall back to, so there's genuinely nothing to derive `localDate`
    // from — leave it undefined and say so.
    warnings.push("no valid fixes and no separate date field to fall back to; local date left undefined");
  }
  round.warnings = finalizeWarnings(warnings);
  return { ok: true, round };
}

function parseScorecardCsv(rows: string[][]): ImportResult {
  if (rows.length < 2) {
    return { ok: false, error: "CSV scorecard header found but no data row" };
  }
  const warnings: string[] = [];
  if (rows.length > 2) {
    warnings.push(`${rows.length - 2} extra scorecard row(s) ignored; a CSV file is one round`);
  }
  const row = rows[1]!;
  if (row.length < 4) {
    return { ok: false, error: "scorecard row has fewer than 4 columns" };
  }
  const [dateRaw, courseRaw, holesRaw, scoreRaw] = row;
  const date = dateRaw!.trim();
  if (!isRealCalendarDate(date)) {
    return { ok: false, error: finalizeError(`scorecard date "${date}" is not a real YYYY-MM-DD calendar date`) };
  }
  const holesParsed = parseStrictDecimal(holesRaw!.trim());
  if (holesParsed === undefined || !isPositiveInteger(holesParsed) || holesParsed > MAX_HOLES) {
    return {
      ok: false,
      error: finalizeError(`scorecard holes "${holesRaw}" must be a positive integer up to ${MAX_HOLES}`),
    };
  }
  const scoreParsed = parseStrictDecimal(scoreRaw!.trim());
  if (scoreParsed === undefined || !isPositiveInteger(scoreParsed)) {
    return { ok: false, error: finalizeError(`scorecard score "${scoreRaw}" must be a positive integer`) };
  }
  const courseNameHint = sanitizeText(courseRaw!.trim());

  const round: ImportedRound = {
    source: "file_import",
    format: "csv",
    fixes: [],
    localDate: date,
    holes: holesParsed,
    totalScore: scoreParsed,
    warnings: finalizeWarnings(warnings),
    ...(courseNameHint.length > 0 ? { courseNameHint } : {}),
  };
  return { ok: true, round };
}

/** Parses the minimal CSV import format from raw file bytes (UTF-8). Pure:
 * no filesystem or network access. */
export function parseCsvFile(bytes: Uint8Array): ImportResult {
  const sizeError = checkInputSize(bytes.byteLength, MAX_INPUT_BYTES);
  if (sizeError) return { ok: false, error: finalizeError(sizeError) };

  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const { rows: rawRows, truncated } = parseCsvRows(text, MAX_CSV_ROWS);
  const rows = rawRows.filter((r) => !(r.length === 1 && r[0]!.trim() === ""));
  if (rows.length === 0) {
    return { ok: false, error: "CSV file has no rows" };
  }
  const header = normalizeHeader(rows[0]!);

  if (headerEquals(header, FIXES_HEADER_3) || headerEquals(header, FIXES_HEADER_4)) {
    return parseFixesCsv(rows, truncated);
  }
  if (headerEquals(header, SCORECARD_HEADER)) {
    return parseScorecardCsv(rows);
  }
  return {
    ok: false,
    error: finalizeError(
      `unrecognized CSV header "${rows[0]!.join(",")}" — expected ` +
        `"timestamp,lat,lon[,accuracy]" or "date,course,holes,score"`,
    ),
  };
}
