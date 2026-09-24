/**
 * `docs/p0/X1.md`'s "## Recorded export" section (decision 0005
 * "Integrity rules": "The first export read is the recorded one. Matt logs
 * the export's date in `docs/p0/X1.md` before it is read. A later export
 * can be read for information, but it never replaces the recorded result.
 * ... The same rule applies separately to each OS.").
 *
 * One line per OS — iOS and Android — holding that OS's recorded export's
 * UTC date as `YYYY-MM-DD`, blank until Matt logs it, plus, once bound:
 * a `sha256:<hex>` suffix (the export's hash) and a `result:pass|kill`
 * suffix (that OS's own recorded X1 verdict) — e.g.
 * `- iOS: 2026-09-20 sha256:abcd... result:kill`.
 *
 * **Round-2 Opus-gate correction (post-67bdb27), superseding round 1's
 * design:** round 1 let `x1-verdict` treat an input as "recorded" whenever
 * its OWN `recorded`/`os` JSON fields said so — a hand-editable claim, not
 * a verified one. That's gone. Trust now flows ONLY through this file,
 * verified independently by whichever tool is binding a run (never by
 * reading a `recorded`/`exportSha256` field out of someone else's JSON):
 *
 * - **Per-OS, never combined in one call.** `x1-ios-export --os ios` binds
 *   iOS's date+hash here; `x1-verdict --os android` binds Android's. Each
 *   tool computes its OWN os's calendar date and SHA-256 FRESH from the
 *   real source (export.xml for iOS, the reader's output JSON's raw bytes
 *   for Android) — never from a self-reported field.
 * - **The recorded X1 result is also written here, per OS**, as
 *   `result:pass|kill` — `x1-verdict --os <os>` computes it from that OS's
 *   OWN data alone and writes it once, refusing to silently overwrite a
 *   different value later. The overall X1 result then reads BOTH OSes'
 *   `result:` fields from this file (never from a single call's two
 *   inputs) — pass if either is "pass".
 * - **No informational peeking before binding.** Once a date is logged but
 *   before its hash is bound, `--informational` is refused too — that gap
 *   is exactly the window a not-yet-committed "recorded" run could be
 *   quietly previewed and then walked back from.
 * - **Git-history + working-tree integrity**, in the spirit of decision
 *   0001 Addendum F's own precedent (`git log -S` for K2's exclusion
 *   dates — this uses `-G` instead, see `assertHashHistoryIntact`'s doc
 *   for why `-S` alone would miss a value SWAP): before binding, the tool
 *   checks this file is fully committed (not just staged/dirty), scans
 *   full git history for the OS's hash ever changing after being set, and
 *   refuses in a shallow clone (that scan needs full history).
 */
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { resolveX1DocPath } from "./round-windows.js";

const execFileAsync = promisify(execFile);

export type X1Os = "ios" | "android";
export type X1RecordedResult = "pass" | "kill";

function osLabelOf(os: X1Os): string {
  return os === "ios" ? "iOS" : "Android";
}

/** One OS's recorded-export line. `date` (`YYYY-MM-DD`, a UTC calendar
 * date) and `sha256` are `null` until logged/bound; `result` is `null`
 * until `x1-verdict` has computed and written that OS's own recorded X1
 * verdict. */
export interface RecordedExportEntry {
  date: string | null;
  sha256: string | null;
  result: X1RecordedResult | null;
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
 * hash and/or a recorded result, in that order. The hash is always
 * lowercase hex (Node's `crypto` digest("hex") output). */
const VALUE_RE =
  /^(\d{4}-\d{2}-\d{2})(?:\s+sha256:([0-9a-f]{64}))?(?:\s+result:(pass|kill))?$/;

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
  if (raw === "") return { date: null, sha256: null, result: null };
  const m = VALUE_RE.exec(raw);
  if (!m) {
    throw new Error(
      `docs/p0/X1.md "## Recorded export" has a malformed value "${raw}" on the "${osLabel}:" line — expected ` +
        'blank, or "YYYY-MM-DD" (a UTC date) optionally followed by " sha256:<64 lowercase hex chars>" and/or ' +
        '" result:pass" / " result:kill".',
    );
  }
  const date = m[1]!;
  if (!isRealCalendarDate(date)) {
    throw new Error(
      `docs/p0/X1.md "## Recorded export" has a malformed UTC date "${date}" on the "${osLabel}:" line — ` +
        'expected a real calendar date in strict "YYYY-MM-DD" form, or blank (not yet logged).',
    );
  }
  return { date, sha256: m[2] ?? null, result: (m[3] as X1RecordedResult | undefined) ?? null };
}

/**
 * Parses the "## Recorded export" section into `{ ios, android }` entries.
 * Requires exactly one `- iOS: ...` and one `- Android: ...` line
 * (case-insensitive OS name, `-`/`*` bullet, blank value allowed) between
 * the heading and the next heading (or end of file). Throws — loudly,
 * never silently defaulting to blank — when: the heading is missing;
 * either OS's line is missing; an OS's line appears more than once; or a
 * non-blank value doesn't match the blank/date[/hash][/result] shape.
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
    ios: { date: null, sha256: null, result: null },
    android: { date: null, sha256: null, result: null },
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
 * when `--informational` was passed — see `assertNoInformationalPeeking`
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

/**
 * Round-2 Opus-gate correction (post-67bdb27), "No informational peeking
 * before binding": refuses `--informational` too when `os`'s UTC date is
 * logged but its SHA-256 isn't bound yet — the window between logging the
 * date and committing to a specific export is exactly what a quiet
 * informational preview would defeat. Once the hash IS bound, later
 * informational runs (against other exports) are fine again; while no date
 * is logged at all, informational runs are fine too (there's nothing yet
 * to peek at). Callers call this ONLY on the `--informational` path.
 */
export function assertNoInformationalPeeking(dates: RecordedExportDates, os: X1Os): void {
  if (dates[os].date !== null && dates[os].sha256 === null) {
    const osLabel = osLabelOf(os);
    throw new Error(
      `docs/p0/X1.md has a ${osLabel} recorded-export UTC date logged but no SHA-256 bound yet — refusing ` +
        "--informational in this window (decision 0005: no informational peeking before binding). Either run " +
        "the recorded (non-informational) command to bind it, or use a synthetic test fixture instead of the " +
        "real export for a dry run in this window.",
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
 * and returns `{written: true}`. On every later recorded run, compares
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
    await updateRecordedExportEntry(x1DocPath, os, { sha256: actualSha256 });
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

/**
 * Writes `os`'s own recorded X1 verdict (`"pass"` or `"kill"`, computed by
 * the caller from that OS's data alone) into `docs/p0/X1.md`, so a LATER
 * run — for the OTHER OS, or a re-run of this one — can read it back
 * without ever needing both OSes' input data in one call (round-2
 * Opus-gate correction: "Record each per-OS recorded result ... so the two
 * runs combine without trusting a hand stamp"). Re-reads the file itself
 * (see `bindExportHash`'s doc for why). Refuses if a DIFFERENT result is
 * already recorded there — the recorded result, once set, never silently
 * changes. Returns `{written: false}` when it already matched.
 */
export async function writeRecordedResult(
  x1DocPath: string,
  os: X1Os,
  result: X1RecordedResult,
): Promise<{ written: boolean }> {
  const osLabel = osLabelOf(os);
  const { dates } = await readRecordedExportDates(x1DocPath);
  const logged = dates[os].result;
  if (logged === null) {
    await updateRecordedExportEntry(x1DocPath, os, { result });
    return { written: true };
  }
  if (logged !== result) {
    throw new Error(
      `docs/p0/X1.md already records ${osLabel}'s X1 result as "${logged}", but this run computed "${result}" ` +
        "— refusing to silently change a recorded result. If the underlying data genuinely changed, that " +
        "needs an owner decision, not an automatic overwrite.",
    );
  }
  return { written: false };
}

/**
 * Combines both OSes' durably-recorded results (never a single call's two
 * inputs — see the module doc) into the overall X1 result: `"pass"` if
 * either OS's own recorded result is `"pass"`; `"kill"` if both OSes have
 * a recorded result and neither is `"pass"`; `"pending"` if at least one
 * OS has no recorded result yet.
 */
export function computeOverallX1Result(dates: RecordedExportDates): X1RecordedResult | "pending" {
  if (dates.ios.result === "pass" || dates.android.result === "pass") return "pass";
  if (dates.ios.result !== null && dates.android.result !== null) return "kill";
  return "pending";
}

/** Rewrites `os`'s "## Recorded export" bullet line in `x1DocPath`,
 * merging `patch` into whatever's already on that line (never dropping an
 * already-set `sha256`/`result` when writing the other). Throws if the
 * section/line isn't there, or if no UTC date is logged yet (a hash/result
 * can only ever be bound to an already-logged date) — this is only ever
 * called right after a fresh read confirmed the date exists, so either
 * case means the file changed underneath the run. */
async function updateRecordedExportEntry(
  x1DocPath: string,
  os: X1Os,
  patch: { sha256?: string; result?: X1RecordedResult },
): Promise<void> {
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
  let current: RecordedExportEntry = { date: null, sha256: null, result: null };
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
  const merged: RecordedExportEntry = {
    date: current.date,
    sha256: patch.sha256 ?? current.sha256,
    result: patch.result ?? current.result,
  };
  const parts = [merged.date];
  if (merged.sha256) parts.push(`sha256:${merged.sha256}`);
  if (merged.result) parts.push(`result:${merged.result}`);
  lines[lineIdx] = `- ${osLabel}: ${parts.join(" ")}`;
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

// ---------------------------------------------------------------------
// Git integrity (round-2 Opus-gate correction, post-67bdb27, should-fix 3)
// ---------------------------------------------------------------------

async function runGit(args: string[], cwd: string): Promise<string> {
  const { stdout } = await execFileAsync("git", args, { cwd, maxBuffer: 64 * 1024 * 1024 });
  return stdout;
}

/** Decision 0001 Addendum F's own precedent ("The count refuses to run in
 * a shallow clone", K2 exclusion dating): `assertHashHistoryIntact` below
 * needs full history to be meaningful, so a shallow clone is refused
 * before any binding happens. */
export async function assertNotShallowClone(x1DocPath: string): Promise<void> {
  const dir = path.dirname(x1DocPath);
  let out: string;
  try {
    out = (await runGit(["rev-parse", "--is-shallow-repository"], dir)).trim();
  } catch (err) {
    throw new Error(
      `Could not determine whether this checkout is a shallow git clone (${err instanceof Error ? err.message : String(err)}) ` +
        "— refusing a recorded run: decision 0005's hash-history integrity check needs a real, full git repo.",
    );
  }
  if (out === "true") {
    throw new Error(
      "This checkout is a shallow git clone — refusing a recorded run: decision 0005's hash-history " +
        "integrity check (git log -S) needs full history. Un-shallow the clone (git fetch --unshallow) first.",
    );
  }
}

/** Refuses a recorded run when `docs/p0/X1.md` has uncommitted changes —
 * decision 0005: a hash/result that isn't committed can't be trusted as
 * the shared, auditable record the rest of this mechanism assumes it is.
 * The FIRST bind for an OS is the one exception in spirit (it necessarily
 * leaves the file dirty right after writing) — but that's handled by
 * calling this check BEFORE any write in a given run, never after; the
 * caller prints "commit docs/p0/X1.md now" once it has written something. */
export async function assertX1DocCommitted(x1DocPath: string): Promise<void> {
  const dir = path.dirname(x1DocPath);
  let out: string;
  try {
    out = await runGit(["status", "--porcelain", "--", x1DocPath], dir);
  } catch (err) {
    throw new Error(
      `Could not check docs/p0/X1.md's git status (${err instanceof Error ? err.message : String(err)}) — ` +
        "refusing a recorded run: decision 0005 requires the hash/result lines to be a committed, auditable " +
        "record.",
    );
  }
  if (out.trim() !== "") {
    throw new Error(
      "docs/p0/X1.md has uncommitted changes — refusing a recorded run: decision 0005 requires the hash/" +
        "result lines to be committed before they can be trusted as the shared record. Commit docs/p0/X1.md " +
        "(or discard the changes) first.",
    );
  }
}

/**
 * Should-fix 3, "Hash-line integrity": scans the FULL git history of
 * `x1DocPath` (`git log --reverse -S"sha256:"`, the same `-S` technique
 * decision 0001 Addendum F uses for K2's exclusion dating) for `os`'s bound
 * SHA-256 ever changing after first being set, or being removed entirely.
 * Refuses (throws) if so — a hash that changes after the fact is exactly
 * what this binding exists to catch. A commit whose historical content is
 * unreadable or fails to parse as a "## Recorded export" section is
 * skipped (it predates the section, or is otherwise not comparable), never
 * treated as evidence of tampering on its own.
 */
export async function assertHashHistoryIntact(x1DocPath: string, os: X1Os): Promise<void> {
  const osLabel = osLabelOf(os);
  const dir = path.dirname(x1DocPath);
  let repoRoot: string;
  try {
    repoRoot = (await runGit(["rev-parse", "--show-toplevel"], dir)).trim();
  } catch (err) {
    throw new Error(
      `Could not find this checkout's git root (${err instanceof Error ? err.message : String(err)}) — ` +
        "refusing a recorded run: decision 0005's hash-history integrity check needs a real git repo.",
    );
  }
  const relPath = path.relative(repoRoot, x1DocPath).split(path.sep).join("/");
  let logOut: string;
  try {
    // `-G` (matches any commit whose diff ADDS OR REMOVES a line matching
    // the regex), not `-S` (which only fires on a CHANGE IN OCCURRENCE
    // COUNT of a literal string): the substring "sha256:" itself is
    // present, unchanged, before and after a value swap, so `-S"sha256:"`
    // would silently miss exactly the tampering this check exists to
    // catch. `-G` matches because the WHOLE line (including the hex
    // value) differs, so it shows as one line removed + one line added.
    logOut = await runGit(
      ["log", "--format=%H", "--reverse", "-G", "sha256:[0-9a-f]{64}", "--", relPath],
      repoRoot,
    );
  } catch (err) {
    throw new Error(
      `Could not read docs/p0/X1.md's git history (${err instanceof Error ? err.message : String(err)}) — ` +
        "refusing a recorded run: decision 0005's hash-history integrity check needs full history.",
    );
  }
  const commits = logOut.split("\n").map((l) => l.trim()).filter(Boolean);
  let firstSeenHash: string | null = null;
  for (const commit of commits) {
    let content: string;
    try {
      content = await runGit(["show", `${commit}:${relPath}`], repoRoot);
    } catch {
      continue; // file didn't exist at that commit — not comparable.
    }
    let historical: RecordedExportDates;
    try {
      historical = parseRecordedExportDates(content);
    } catch {
      continue; // predates the "## Recorded export" section, or malformed at that point — not comparable.
    }
    const hash = historical[os].sha256;
    if (hash === null) continue;
    if (firstSeenHash === null) {
      firstSeenHash = hash;
    } else if (hash !== firstSeenHash) {
      throw new Error(
        `docs/p0/X1.md's bound SHA-256 for ${osLabel} has changed across git history (commit ${commit} shows ` +
          `"${hash}", but it was first bound as "${firstSeenHash}") — refusing a recorded run: decision 0005's ` +
          "hash binding must never change once set. A genuine re-bind needs an owner decision, not a silent " +
          "overwrite.",
      );
    }
  }
  if (firstSeenHash === null) return; // never bound in history — nothing to check yet.

  const { dates: current } = await readRecordedExportDates(x1DocPath);
  const currentHash = current[os].sha256;
  if (currentHash === null) {
    throw new Error(
      `docs/p0/X1.md's bound SHA-256 for ${osLabel} was previously set (${firstSeenHash}) but is now blank — ` +
        "refusing a recorded run: it looks like the hash was removed. A genuine re-bind needs an owner " +
        "decision, not a silent removal.",
    );
  }
  if (currentHash !== firstSeenHash) {
    throw new Error(
      `docs/p0/X1.md's bound SHA-256 for ${osLabel} (${currentHash}) does not match what git history shows it ` +
        `was first bound as (${firstSeenHash}) — refusing a recorded run: decision 0005's hash binding must ` +
        "never change once set.",
    );
  }
}

/** Convenience wrapper: runs all three git-integrity checks above, in the
 * order that fails fastest/cheapest first. Callers use this right before
 * binding a hash for a recorded run. */
export async function assertGitIntegrity(x1DocPath: string, os: X1Os): Promise<void> {
  await assertNotShallowClone(x1DocPath);
  await assertX1DocCommitted(x1DocPath);
  await assertHashHistoryIntact(x1DocPath, os);
}
