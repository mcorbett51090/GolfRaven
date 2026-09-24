/**
 * The minimal CSV import format (build plan §7.3 lane 2). Exactly one of
 * two header shapes, matched exactly and case-insensitively — an
 * unrecognized or mixed header is refused rather than guessed at:
 *
 *  - `timestamp,lat,lon` or `timestamp,lat,lon,accuracy` — a fix trace.
 *    `timestamp` is either a bare integer (epoch milliseconds) or an
 *    ISO 8601 date-time string; `lat`/`lon`/`accuracy` are decimal
 *    degrees/meters.
 *  - `date,course,holes,score` — a scorecard row with no route.
 *    `date` is `YYYY-MM-DD` (facility-local, per build plan §4.1 `tz` —
 *    this package has no facility to resolve a timezone against, so it
 *    takes the date exactly as written). Only the first data row is used;
 *    a file is one round.
 *
 * RFC 4180 quoting throughout (`csv-rows.ts`).
 */
import type { ImportedFix, ImportedRound, ImportResult } from "./types.js";
import { parseCsvRows } from "./csv-rows.js";
import { checkInputSize, capAndSortFixes, isValidLat, isValidLon, isValidTimestamp } from "./safety.js";

const FIXES_HEADER_3 = ["timestamp", "lat", "lon"];
const FIXES_HEADER_4 = ["timestamp", "lat", "lon", "accuracy"];
const SCORECARD_HEADER = ["date", "course", "holes", "score"];
const LOCAL_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function normalizeHeader(row: string[]): string[] {
  return row.map((cell) => cell.trim().toLowerCase());
}

function headerEquals(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

function parseTimestampCell(raw: string): number | undefined {
  const trimmed = raw.trim();
  if (trimmed.length === 0) return undefined;
  if (/^-?\d+$/.test(trimmed)) {
    const n = Number(trimmed);
    return Number.isFinite(n) ? n : undefined;
  }
  const parsed = Date.parse(trimmed);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function parseFixesCsv(rows: string[][]): ImportResult {
  const hasAccuracy = normalizeHeader(rows[0]!).length === 4;
  const warnings: string[] = [];
  const fixes: ImportedFix[] = [];

  for (let i = 1; i < rows.length; i++) {
    const row = rows[i]!;
    const rowNum = i + 1; // 1-based, header is row 1
    if (row.length < 3 || (hasAccuracy && row.length < 4)) {
      warnings.push(`row ${rowNum}: too few columns, skipped`);
      continue;
    }
    const timestamp = parseTimestampCell(row[0]!);
    const lat = Number(row[1]!.trim());
    const lon = Number(row[2]!.trim());
    const accuracyRaw = hasAccuracy ? row[3]?.trim() : undefined;
    const accuracyMeters =
      accuracyRaw !== undefined && accuracyRaw.length > 0 ? Number(accuracyRaw) : undefined;

    if (timestamp === undefined || !isValidTimestamp(timestamp)) {
      warnings.push(`row ${rowNum}: unparseable timestamp "${row[0]}", skipped`);
      continue;
    }
    if (!isValidLat(lat) || !isValidLon(lon)) {
      warnings.push(`row ${rowNum}: invalid lat/lon, skipped`);
      continue;
    }
    if (accuracyRaw !== undefined && accuracyRaw.length > 0 && !Number.isFinite(accuracyMeters)) {
      warnings.push(`row ${rowNum}: invalid accuracy, ignored for this row`);
    }
    fixes.push({
      lat,
      lon,
      timestamp,
      ...(accuracyMeters !== undefined && Number.isFinite(accuracyMeters) ? { accuracyMeters } : {}),
    });
  }

  const { fixes: sortedFixes, warnings: capWarnings } = capAndSortFixes(fixes);
  warnings.push(...capWarnings);

  const round: ImportedRound = {
    source: "file_import",
    format: "csv",
    fixes: sortedFixes,
    warnings,
    ...(sortedFixes.length > 0
      ? { startedAt: sortedFixes[0]!.timestamp, endedAt: sortedFixes[sortedFixes.length - 1]!.timestamp }
      : {}),
  };
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
  if (!LOCAL_DATE_RE.test(date)) {
    return { ok: false, error: `scorecard date "${date}" is not YYYY-MM-DD` };
  }
  const holes = Number(holesRaw!.trim());
  const score = Number(scoreRaw!.trim());
  if (!Number.isFinite(holes) || holes <= 0) {
    return { ok: false, error: `scorecard holes "${holesRaw}" is not a positive number` };
  }
  if (!Number.isFinite(score) || score <= 0) {
    return { ok: false, error: `scorecard score "${scoreRaw}" is not a positive number` };
  }
  const courseNameHint = courseRaw!.trim();

  const round: ImportedRound = {
    source: "file_import",
    format: "csv",
    fixes: [],
    localDate: date,
    holes,
    totalScore: score,
    warnings,
    ...(courseNameHint.length > 0 ? { courseNameHint } : {}),
  };
  return { ok: true, round };
}

/** Parses the minimal CSV import format from raw file bytes (UTF-8). Pure:
 * no filesystem or network access. */
export function parseCsvFile(bytes: Uint8Array): ImportResult {
  const sizeError = checkInputSize(bytes.byteLength);
  if (sizeError) return { ok: false, error: sizeError };

  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const rows = parseCsvRows(text).filter((r) => !(r.length === 1 && r[0]!.trim() === ""));
  if (rows.length === 0) {
    return { ok: false, error: "CSV file has no rows" };
  }
  const header = normalizeHeader(rows[0]!);

  if (headerEquals(header, FIXES_HEADER_3) || headerEquals(header, FIXES_HEADER_4)) {
    return parseFixesCsv(rows);
  }
  if (headerEquals(header, SCORECARD_HEADER)) {
    return parseScorecardCsv(rows);
  }
  return {
    ok: false,
    error:
      `unrecognized CSV header "${rows[0]!.join(",")}" — expected ` +
      `"timestamp,lat,lon[,accuracy]" or "date,course,holes,score"`,
  };
}
