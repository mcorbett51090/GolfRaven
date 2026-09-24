/**
 * `docs/p0/X1.md`'s "## Recorded export" section (decision 0005
 * "Integrity rules": "The first export read is the recorded one. Matt logs
 * the export's date in `docs/p0/X1.md` before it is read. A later export
 * can be read for information, but it never replaces the recorded result.
 * ... The same rule applies separately to each OS.").
 *
 * One line per OS — iOS and Android — holding that OS's recorded export's
 * UTC date as `YYYY-MM-DD`, blank until Matt logs it, plus, once bound: a
 * `sha256:<hex>` suffix binding that date to one specific export file —
 * e.g. `- iOS: 2026-09-20 sha256:abcd...`.
 *
 * **Round-3 Opus-gate correction (post-8e5a29b), simplifying round 2's
 * design:** round 2 ALSO stored each OS's computed pass/kill as
 * `result:pass|kill` on this same line, read back later to combine both
 * OSes' results. That's gone — storing a *result* invites exactly the
 * failure mode decision 0005 exists to prevent (a stale or hand-typed
 * result line silently standing in for a real recomputation). This file
 * now stores ONLY what a result is bound to (a UTC date + a SHA-256),
 * never a result itself:
 *
 * - **No result is ever read back from a markdown line.** A recorded
 *   `x1-verdict` run RECOMPUTES every bound OS's result, every time, from
 *   that OS's bound file — re-hashed and re-parsed fresh, in the same
 *   process, never from a cached or written value. See `x1-verdict.ts`'s
 *   module doc for the recompute-and-combine mechanism.
 * - **No informational runs on real data while an OS is unbound.** While
 *   an OS has no bound `sha256:` (whether its date is blank or logged),
 *   `--informational` is refused for that OS unless its input path
 *   resolves under `tools/p0/test/fixtures/` — see
 *   `assertInformationalInputAllowed`.
 * - **The first-bind trust limit.** Whatever file is bound first for an
 *   OS is trusted as that device's genuine output — there is no way to
 *   verify a device's export against some independent ground truth. This
 *   is why `docs/p0/X1.md` should be committed AND PUSHED immediately
 *   after binding, the same as decision 0001 Addendum F requires for K2's
 *   exclusion dating: rewritten LOCAL history (a rebase or amend) is not
 *   detected by anything in this module — a pushed copy on GitHub is the
 *   actual protection. `bindExportHash`'s caller prints "commit and push
 *   docs/p0/X1.md now" after the first bind.
 */
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { resolveX1DocPath } from "./round-windows.js";

export type X1Os = "ios" | "android";

function osLabelOf(os: X1Os): string {
  return os === "ios" ? "iOS" : "Android";
}

/** One OS's recorded-export line. `date` (`YYYY-MM-DD`, a UTC calendar
 * date) and `sha256` are `null` until logged/bound. There is no stored
 * result any more — see the module doc. */
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
/** A bullet's value: blank, or a UTC date optionally followed by a bound
 * hash. The hash is always lowercase hex (Node's `crypto` digest("hex")
 * output). No `result:` suffix any more — see the module doc. */
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
        'blank, or "YYYY-MM-DD" (a UTC date) optionally followed by " sha256:<64 lowercase hex chars>".',
    );
  }
  const date = m[1]!;
  if (!isRealCalendarDate(date)) {
    throw new Error(
      `docs/p0/X1.md "## Recorded export" has a malformed UTC date "${date}" on the "${osLabel}:" line — ` +
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
 * non-blank value doesn't match the blank/date[/hash] shape.
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
 * that OS's recorded-export UTC date is blank. Callers never call this
 * when `--informational` was passed — see `assertInformationalInputAllowed`
 * for what gates that path instead.
 */
export function assertRecordedExportDateLogged(dates: RecordedExportDates, os: X1Os): void {
  if (dates[os].date === null) {
    const osLabel = osLabelOf(os);
    throw new Error(
      `docs/p0/X1.md "## Recorded export" has no logged UTC date for ${osLabel} — refusing to produce the ` +
        `RECORDED X1 result for ${osLabel} (decision 0005). Log the export's UTC date there before reading ` +
        "it, or pass --informational to run anyway (the output is then marked informational, never the " +
        "recorded P0 result).",
    );
  }
}

/** Repo-relative path to `tools/p0/test/fixtures`, resolved from THIS
 * module's own location (same technique as `round-windows.ts`'s
 * `resolveX1DocPath` — works identically from `src/` or `dist/`). */
export function resolveFixturesDir(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.join(here, "..", "test", "fixtures");
}

/** True when `candidatePath` resolves to `tools/p0/test/fixtures` itself,
 * or somewhere under it. */
export function isUnderFixturesDir(candidatePath: string): boolean {
  const fixturesDir = path.resolve(resolveFixturesDir());
  const resolved = path.resolve(candidatePath);
  return resolved === fixturesDir || resolved.startsWith(fixturesDir + path.sep);
}

/**
 * Round-3 Opus-gate correction (post-8e5a29b), "No informational runs on
 * real data while an OS is unbound": while `os` has no bound `sha256:`
 * (whether its UTC date is blank or logged), `--informational` is refused
 * for it UNLESS `inputPath` resolves under `tools/p0/test/fixtures/` — a
 * quiet informational preview of real data is exactly what an unbound OS
 * must not allow, whether or not a date happens to be logged yet. Once
 * `os` IS bound, informational runs against any path are allowed again
 * (decision 0005: "a later export can be read for information"). Callers
 * call this ONLY on the `--informational` path, once per input actually
 * supplied for that OS.
 */
export function assertInformationalInputAllowed(
  dates: RecordedExportDates,
  os: X1Os,
  inputPath: string,
): void {
  if (dates[os].sha256 !== null) return; // bound — any path is fine informationally.
  if (!isUnderFixturesDir(inputPath)) {
    const osLabel = osLabelOf(os);
    throw new Error(
      `Refusing --informational on real data for ${osLabel} (${inputPath}) while ${osLabel} has no bound ` +
        "SHA-256 yet (decision 0005: no informational runs on real data while an OS is unbound). Use a " +
        `synthetic fixture under tools/p0/test/fixtures/ for a dry run, or bind ${osLabel} first with a ` +
        "recorded run.",
    );
  }
}

/**
 * Round-3 Opus-gate correction (post-8e5a29b): refuses (throws) when `os`
 * is already bound (has a SHA-256 recorded) but its input wasn't supplied
 * this run (`inputProvided: false`) — decision 0005 needs every bound OS's
 * input recomputed, every time; the overall result is never guessed from a
 * partial picture. A no-op when `os` isn't bound (nothing to recompute) or
 * when its input WAS supplied.
 */
export function assertBoundInputProvided(dates: RecordedExportDates, os: X1Os, inputProvided: boolean): void {
  if (!inputProvided && dates[os].sha256 !== null) {
    const osLabel = osLabelOf(os);
    throw new Error(
      `docs/p0/X1.md shows ${osLabel} as already bound (a SHA-256 is recorded), but its input was not ` +
        "supplied this run — refusing a recorded run: decision 0005 needs every bound OS's input recomputed, " +
        "every time.",
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
    throw new Error(`Cannot parse "${raw}" as a date to extract its UTC calendar date from.`);
  }
  return d.toISOString().slice(0, 10);
}

/**
 * Decision 0005 "Bind the recorded run to one specific export": refuses
 * (throws) when `exportCalendarDate` — computed FRESH by the caller from
 * the real source, never trusted from a JSON field — is not the same UTC
 * calendar date as the one logged in `docs/p0/X1.md` for `os`. Called only
 * for a recorded (non-informational) run, after `assertRecordedExportDateLogged`.
 */
export function assertExportDateMatches(
  dates: RecordedExportDates,
  os: X1Os,
  exportCalendarDate: string,
): void {
  const logged = dates[os].date;
  if (logged !== null && logged !== exportCalendarDate) {
    const osLabel = osLabelOf(os);
    throw new Error(
      `The ${osLabel} export's UTC date (${exportCalendarDate}) does not match the UTC date logged in ` +
        `docs/p0/X1.md's "## Recorded export" section for ${osLabel} (${logged}) — decision 0005: refusing a ` +
        "recorded run against a different export than the one whose date was logged before it was read.",
    );
  }
}

/**
 * Binds a recorded run's export to a SHA-256, closing the "which export,
 * exactly" gap a date alone leaves open. `actualSha256` must be computed
 * FRESH by the caller from the real source (never trusted from a JSON
 * field — see the module doc). Re-reads `docs/p0/X1.md` itself (never
 * trusts a possibly-stale `dates` the caller read earlier) so a hash bound
 * by a concurrent/earlier step in the same run is never clobbered. On the
 * first recorded run for `os` (no hash bound yet), writes `actualSha256`
 * and returns `{written: true}` — the caller should then tell the operator
 * to commit AND PUSH `docs/p0/X1.md` immediately (see the module doc's
 * "first-bind trust limit"). On every later recorded run, compares
 * `actualSha256` against what's already bound and THROWS on a mismatch.
 * Returns `{written: false}` when it already matched.
 */
export async function bindExportHash(
  x1DocPath: string,
  os: X1Os,
  actualSha256: string,
): Promise<{ written: boolean }> {
  const osLabel = osLabelOf(os);
  const { dates } = await readRecordedExportDates(x1DocPath);
  const logged = dates[os].sha256;
  if (logged === null) {
    await updateRecordedExportEntry(x1DocPath, os, actualSha256);
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

/** Rewrites `os`'s "## Recorded export" bullet line in `x1DocPath` to
 * append its `sha256:<hex>` suffix, preserving the already-logged date.
 * Throws if the section/line isn't there, or if no UTC date is logged yet
 * (a hash can only ever be bound to an already-logged date) — this is
 * only ever called right after a fresh read confirmed the date exists, so
 * either case means the file changed underneath the run. */
async function updateRecordedExportEntry(x1DocPath: string, os: X1Os, sha256: string): Promise<void> {
  const raw = await readFile(x1DocPath, "utf8");
  const lines = raw.split("\n");
  const osLabel = osLabelOf(os);
  const startIdx = lines.findIndex((l) => {
    const text = headingText(l);
    return text !== null && RECORDED_EXPORT_HEADING_RE.test(text);
  });
  if (startIdx === -1) {
    throw new Error('docs/p0/X1.md is missing its "## Recorded export" heading — cannot write to it.');
  }
  let bodyEnd = lines.length;
  for (let i = startIdx + 1; i < lines.length; i += 1) {
    if (headingText(lines[i]!) !== null) {
      bodyEnd = i;
      break;
    }
  }
  let lineIdx = -1;
  let current: RecordedExportEntry = { date: null, sha256: null };
  for (let i = startIdx + 1; i < bodyEnd; i += 1) {
    const m = ROW_RE.exec(lines[i]!.trim());
    if (m && m[1]!.toLowerCase() === os) {
      lineIdx = i;
      current = parseValue(m[2]!.trim(), osLabel);
      break;
    }
  }
  if (lineIdx === -1) {
    throw new Error(`docs/p0/X1.md "## Recorded export" is missing its "${osLabel}:" line — cannot write to it.`);
  }
  if (current.date === null) {
    throw new Error(`docs/p0/X1.md "## Recorded export" has no UTC date logged for ${osLabel} — cannot bind to it.`);
  }
  lines[lineIdx] = `- ${osLabel}: ${current.date} sha256:${sha256}`;
  await writeFile(x1DocPath, lines.join("\n"), "utf8");
}

/** Loud markdown banner for an `--informational` run — decision 0005:
 * "the output then carries a loud 'INFORMATIONAL — NOT THE RECORDED X1
 * RESULT' banner". */
export function informationalBanner(os: X1Os): string {
  const osLabel = osLabelOf(os);
  return (
    `> **INFORMATIONAL — NOT THE RECORDED X1 RESULT** (--informational, ${osLabel}).\n` +
    "> Decision 0005: the first export read for each OS, with its UTC date logged in docs/p0/X1.md's " +
    '"## Recorded export" section BEFORE it is read, is the recorded one. This run either has no such ' +
    "date logged, or was explicitly requested as informational — either way, it never replaces the " +
    "recorded result and is not the P0 verdict."
  );
}
