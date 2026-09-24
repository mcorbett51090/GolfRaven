/**
 * `docs/p0/X1.md`'s "## Recorded export" section (decision 0005
 * "Integrity rules": "The first export read is the recorded one. Matt logs
 * the export's date in `docs/p0/X1.md` before it is read. A later export
 * can be read for information, but it never replaces the recorded result.
 * ... The same rule applies separately to each OS.").
 *
 * One line per OS — iOS and Android — holding that OS's recorded export's
 * date as `YYYY-MM-DD`, blank until Matt logs it, plus (after the first
 * recorded run) a `sha256:<hex>` suffix on the same line binding that date
 * to one specific export file (Opus-gate correction, post-d0de4b8):
 * `- iOS: 2026-09-20 sha256:abcd...`. `x1-ios-export` and `x1-verdict` both
 * read this (their `--os` flag says which OS's date/hash to check) and
 * refuse to produce a RECORDED result for an OS whose date is blank, whose
 * export's own date (Apple's `ExportDate` / the Android reader's
 * `generatedAt`) doesn't match the logged date, or whose export's SHA-256
 * doesn't match what was already bound there; `--informational` runs
 * anyway, and the output is marked `recorded: false` with a loud banner
 * (never the recorded P0 result, and never subject to any of these checks).
 */
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolveX1DocPath } from "./round-windows.js";

export type X1Os = "ios" | "android";

/** One OS's recorded-export line: `date` is `YYYY-MM-DD` or `null` (blank,
 * not yet logged); `sha256` is the 64-hex-char hash bound to that date, or
 * `null` before the first recorded run has bound one. */
export interface RecordedExportEntry {
  date: string | null;
  sha256: string | null;
}

export interface RecordedExportDates {
  ios: RecordedExportEntry;
  android: RecordedExportEntry;
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
/** A bullet's value: blank, a bare date, or a date + bound hash. The hash
 * is always lowercase hex (Node's `crypto` digest("hex") output). */
const VALUE_RE = /^(\d{4}-\d{2}-\d{2})(?:\s+sha256:([0-9a-f]{64}))?$/;

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

function parseValue(raw: string, osLabel: string): RecordedExportEntry {
  if (raw === "") return { date: null, sha256: null };
  const m = VALUE_RE.exec(raw);
  if (!m) {
    throw new Error(
      `docs/p0/X1.md "## Recorded export" has a malformed value "${raw}" on the "${osLabel}:" line — expected ` +
        'blank, "YYYY-MM-DD", or "YYYY-MM-DD sha256:<64 lowercase hex chars>".',
    );
  }
  const date = m[1]!;
  if (!isRealCalendarDate(date)) {
    throw new Error(
      `docs/p0/X1.md "## Recorded export" has a malformed date "${date}" on the "${osLabel}:" line — ` +
        'expected a real calendar date in strict "YYYY-MM-DD" form, or blank (not yet logged).',
    );
  }
  return { date, sha256: m[2] ?? null };
}

/**
 * Parses the "## Recorded export" section into `{ ios, android }` entries.
 * Requires exactly one `- iOS: ...` and one `- Android: ...` line
 * (case-insensitive OS name, `-`/`*` bullet, blank value allowed) between
 * the heading and the next heading (or end of file). Throws — loudly,
 * never silently defaulting to blank — when: the heading is missing;
 * either OS's line is missing; an OS's line appears more than once; or a
 * non-blank value doesn't match the blank/date/date+hash shape.
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

  const dates: RecordedExportDates = {
    ios: { date: null, sha256: null },
    android: { date: null, sha256: null },
  };
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
    dates[os] = parseValue(m[2]!.trim(), osLabel);
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
  if (dates[os].date === null) {
    const osLabel = os === "ios" ? "iOS" : "Android";
    throw new Error(
      `docs/p0/X1.md "## Recorded export" has no logged date for ${osLabel} — refusing to produce the ` +
        `RECORDED X1 result for ${osLabel} (decision 0005). Log the export's date there before reading it, ` +
        "or pass --informational to run anyway (the output is then marked informational, never the recorded " +
        "P0 result).",
    );
  }
}

/** Extracts a `YYYY-MM-DD` UTC calendar date out of any string `Date` can
 * parse (Apple's `ExportDate` value, e.g. "2026-09-21 09:00:00 -0400", or
 * the Android reader's ISO `generatedAt`). Throws on an unparseable
 * string, never silently returning an arbitrary date. */
export function extractCalendarDate(raw: string): string {
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) {
    throw new Error(`Cannot parse "${raw}" as a date to extract its calendar date from.`);
  }
  return d.toISOString().slice(0, 10);
}

/**
 * Opus-gate correction (post-d0de4b8), decision 0005 "Bind the recorded run
 * to one specific export": refuses (throws) when `exportCalendarDate`
 * (Apple's `ExportDate` for iOS, the Android reader's `generatedAt` for
 * Android) is not the SAME calendar date as the one logged in
 * `docs/p0/X1.md` for `os`. Callers run this only for a recorded
 * (non-informational) run, after `assertRecordedExportDateLogged` has
 * already confirmed a date is logged.
 */
export function assertExportDateMatches(
  dates: RecordedExportDates,
  os: X1Os,
  exportCalendarDate: string,
): void {
  const logged = dates[os].date;
  if (logged !== null && logged !== exportCalendarDate) {
    const osLabel = os === "ios" ? "iOS" : "Android";
    throw new Error(
      `The ${osLabel} export's date (${exportCalendarDate}) does not match the date logged in docs/p0/X1.md's ` +
        `"## Recorded export" section for ${osLabel} (${logged}) — decision 0005: refusing a recorded run ` +
        "against a different export than the one whose date was logged before it was read.",
    );
  }
}

/**
 * Opus-gate correction (post-d0de4b8): binds a recorded run's export to a
 * SHA-256, closing the "which export, exactly" gap a date alone leaves
 * open. On the first recorded run for `os` (no hash logged yet), writes
 * `actualSha256` into `docs/p0/X1.md` next to the already-logged date and
 * returns `{written: true}`. On every later recorded run, compares
 * `actualSha256` against what's already bound there and THROWS on a
 * mismatch — "Afterwards, refuse a recorded run whose export hash
 * differs." Returns `{written: false}` when it already matched.
 */
export async function bindExportHash(
  x1DocPath: string,
  dates: RecordedExportDates,
  os: X1Os,
  actualSha256: string,
): Promise<{ written: boolean }> {
  const osLabel = os === "ios" ? "iOS" : "Android";
  const logged = dates[os].sha256;
  if (logged === null) {
    await writeRecordedExportHash(x1DocPath, os, actualSha256);
    return { written: true };
  }
  if (logged !== actualSha256) {
    throw new Error(
      `The ${osLabel} export's SHA-256 (${actualSha256}) does not match the hash already recorded in ` +
        `docs/p0/X1.md's "## Recorded export" section for ${osLabel} (${logged}) — decision 0005: refusing a ` +
        "recorded run against a different export than the one first bound there. (--informational runs are " +
        "never checked or bound.)",
    );
  }
  return { written: false };
}

/** Rewrites `os`'s "## Recorded export" bullet line in `x1DocPath`,
 * appending/replacing its `sha256:<hex>` suffix while preserving the
 * already-logged date. Throws if the section/line isn't there — this is
 * only ever called right after `parseRecordedExportDates` confirmed both
 * exist, so that would mean the file changed underneath the run. */
async function writeRecordedExportHash(
  x1DocPath: string,
  os: X1Os,
  sha256: string,
): Promise<void> {
  const raw = await readFile(x1DocPath, "utf8");
  const lines = raw.split("\n");
  const osLabel = os === "ios" ? "iOS" : "Android";
  const startIdx = lines.findIndex((l) => {
    const text = headingText(l);
    return text !== null && RECORDED_EXPORT_HEADING_RE.test(text);
  });
  if (startIdx === -1) {
    throw new Error('docs/p0/X1.md is missing its "## Recorded export" heading — cannot write its hash.');
  }
  let bodyEnd = lines.length;
  for (let i = startIdx + 1; i < lines.length; i += 1) {
    if (headingText(lines[i]!) !== null) {
      bodyEnd = i;
      break;
    }
  }
  let lineIdx = -1;
  let dateOnly = "";
  for (let i = startIdx + 1; i < bodyEnd; i += 1) {
    const m = ROW_RE.exec(lines[i]!.trim());
    if (m && m[1]!.toLowerCase() === os) {
      lineIdx = i;
      const raw2 = m[2]!.trim();
      const valueMatch = VALUE_RE.exec(raw2);
      dateOnly = valueMatch ? valueMatch[1]! : raw2;
      break;
    }
  }
  if (lineIdx === -1) {
    throw new Error(`docs/p0/X1.md "## Recorded export" is missing its "${osLabel}:" line — cannot write its hash.`);
  }
  lines[lineIdx] = `- ${osLabel}: ${dateOnly} sha256:${sha256}`;
  await writeFile(x1DocPath, lines.join("\n"), "utf8");
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
