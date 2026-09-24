/**
 * `docs/p0/X1.md`'s "## Recorded export" section (decision 0005
 * "Integrity rules": "The first export read is the recorded one. Matt logs
 * the export's date in `docs/p0/X1.md` before it is read. A later export
 * can be read for information, but it never replaces the recorded result.
 * ... The same rule applies separately to each OS.").
 *
 * One line per OS — iOS and Android — holding that OS's recorded export's
 * date as `YYYY-MM-DD`, blank until Matt logs it. `x1-ios-export` and
 * `x1-verdict` both read this (their `--os` flag says which OS's date to
 * check) and refuse to produce a RECORDED result for an OS whose date is
 * blank; `--informational` runs anyway, and the output is marked
 * `recorded: false` with a loud banner (never the recorded P0 result).
 */
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolveX1DocPath } from "./round-windows.js";

export type X1Os = "ios" | "android";

export interface RecordedExportDates {
  ios: string | null;
  android: string | null;
}

/** Provenance stamp for a tool's output — same shape/purpose as
 * `k1-verdict.ts`'s `source` object: the exact file read and its
 * SHA-256, so an output can be checked against exactly what was read. */
export interface X1DocSource {
  path: string;
  sha256: string;
}

const HEADING_RE = /^#{1,6}\s*(.+?)\s*$/;
const RECORDED_EXPORT_HEADING_RE = /^recorded export\b/i;
const ROW_RE = /^[-*]\s*(iOS|Android)\s*:\s*(.*)$/i;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function headingText(line: string): string | null {
  const m = HEADING_RE.exec(line.trim());
  return m ? m[1]! : null;
}

/** Real ISO calendar date check — same technique as `round-windows.ts` /
 * `k1-verdict.ts`'s `isRealCalendarDate` (rejects e.g. "2026-13-45"). */
function isRealCalendarDate(value: string): boolean {
  if (!DATE_RE.test(value)) return false;
  const d = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === value;
}

/**
 * Parses the "## Recorded export" section into `{ ios, android }` dates
 * (`null` = blank, not yet logged). Requires exactly one `- iOS: ...` and
 * one `- Android: ...` line (case-insensitive OS name, `-`/`*` bullet,
 * blank value allowed) between the heading and the next heading (or end of
 * file). Throws — loudly, never silently defaulting to blank — when: the
 * heading is missing; either OS's line is missing; an OS's line appears
 * more than once; or a non-blank value is not a real "YYYY-MM-DD" date.
 */
export function parseRecordedExportDates(markdown: string): RecordedExportDates {
  const lines = markdown.split("\n");
  const startIdx = lines.findIndex((l) => {
    const text = headingText(l);
    return text !== null && RECORDED_EXPORT_HEADING_RE.test(text);
  });
  if (startIdx === -1) {
    throw new Error(
      'docs/p0/X1.md is missing its "## Recorded export" heading — cannot determine the recorded-export ' +
        "date(s) (decision 0005).",
    );
  }
  let bodyEnd = lines.length;
  for (let i = startIdx + 1; i < lines.length; i += 1) {
    if (headingText(lines[i]!) !== null) {
      bodyEnd = i;
      break;
    }
  }

  const dates: RecordedExportDates = { ios: null, android: null };
  const seen = new Set<X1Os>();
  for (let i = startIdx + 1; i < bodyEnd; i += 1) {
    const line = lines[i]!.trim();
    const m = ROW_RE.exec(line);
    if (!m) continue;
    const osLabel = m[1]!;
    const os = osLabel.toLowerCase() as X1Os;
    if (seen.has(os)) {
      throw new Error(
        `docs/p0/X1.md "## Recorded export" has more than one "${osLabel}:" line — keep exactly one per OS.`,
      );
    }
    seen.add(os);
    const raw = m[2]!.trim();
    if (raw === "") {
      dates[os] = null;
      continue;
    }
    if (!isRealCalendarDate(raw)) {
      throw new Error(
        `docs/p0/X1.md "## Recorded export" has a malformed date "${raw}" on the "${osLabel}:" line — ` +
          'expected a real calendar date in strict "YYYY-MM-DD" form, or blank (not yet logged).',
      );
    }
    dates[os] = raw;
  }
  if (!seen.has("ios")) {
    throw new Error('docs/p0/X1.md "## Recorded export" is missing its "iOS:" line.');
  }
  if (!seen.has("android")) {
    throw new Error('docs/p0/X1.md "## Recorded export" is missing its "Android:" line.');
  }
  return dates;
}

/**
 * Reads and parses the repo's own `docs/p0/X1.md` "## Recorded export"
 * section, alongside a provenance stamp (path + SHA-256 of the file read),
 * mirroring `k1-verdict.ts`'s source-stamping pattern.
 */
export async function readRecordedExportDates(
  x1DocPath: string = resolveX1DocPath(),
): Promise<{ dates: RecordedExportDates; source: X1DocSource }> {
  const raw = await readFile(x1DocPath, "utf8");
  const dates = parseRecordedExportDates(raw);
  const sha256 = createHash("sha256").update(raw).digest("hex");
  return { dates, source: { path: x1DocPath, sha256 } };
}

/**
 * Decision 0005 "Recorded-export rule": refuses (throws) when the caller is
 * about to produce a RECORDED (non-`--informational`) result for `os` and
 * that OS's recorded-export date is blank. Callers never call this when
 * `--informational` was passed — that path always runs, and the caller
 * marks its own output `recorded: false` instead.
 */
export function assertRecordedExportDateLogged(dates: RecordedExportDates, os: X1Os): void {
  if (dates[os] === null) {
    const osLabel = os === "ios" ? "iOS" : "Android";
    throw new Error(
      `docs/p0/X1.md "## Recorded export" has no logged date for ${osLabel} — refusing to produce the ` +
        `RECORDED X1 result for ${osLabel} (decision 0005). Log the export's date there before reading it, ` +
        "or pass --informational to run anyway (the output is then marked informational, never the recorded " +
        "P0 result).",
    );
  }
}

/** Loud markdown banner for an `--informational` run — decision 0005:
 * "the output then carries a loud 'INFORMATIONAL — NOT THE RECORDED X1
 * RESULT' banner". */
export function informationalBanner(os: X1Os): string {
  const osLabel = os === "ios" ? "iOS" : "Android";
  return (
    `> **INFORMATIONAL — NOT THE RECORDED X1 RESULT** (--informational, ${osLabel}).\n` +
    "> Decision 0005: the first export read for each OS, with its date logged in docs/p0/X1.md's " +
    '"## Recorded export" section BEFORE it is read, is the recorded one. This run either has no such ' +
    "date logged, or was explicitly requested as informational — either way, it never replaces the " +
    "recorded result and is not the P0 verdict."
  );
}
