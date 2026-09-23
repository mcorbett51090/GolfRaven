/**
 * `docs/p0/X1.md`'s "Round windows" section (decision 0001 Addendum F: "X1
 * round window"): before the export is read, Matt logs the UTC start/end
 * time of each test round there. Only a workout/session whose start time
 * falls inside a logged window, with 60 minutes of slack either side,
 * counts — "Older workouts on the device are ignored." Both `x1-ios-export`
 * and `x1-verdict` (gate findings B-6/B-7) honor this, and both refuse to
 * run at all if no window is logged, rather than silently treating every
 * workout on the device as in-round.
 */
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export interface RoundWindow {
  /** ISO-8601 UTC timestamp, as logged (e.g. "2026-09-20T13:00:00Z"). */
  startIso: string;
  endIso: string;
}

const HEADING_RE = /^#{1,6}\s*(.+?)\s*$/;
const ROUND_WINDOWS_HEADING_RE = /^round windows\b/i;

// Broad — catches anything SHAPED like an attempted "<START> to <END>"
// window entry (a `YYYY-MM-DDT...` token, a `to`/dash separator, another
// such token), so it can be validated strictly below and rejected with a
// clear, pointed error rather than silently ignored (gate finding F-S6).
// The token class deliberately admits a non-`Z` offset (e.g. `-04:00`) so
// that shape is caught and rejected explicitly too, instead of just
// failing to match and vanishing.
const CANDIDATE_TOKEN = "\\d{4}-\\d{2}-\\d{2}T[\\d:+.Z-]+";
const CANDIDATE_WINDOW_RE = new RegExp(
  `(${CANDIDATE_TOKEN})\\s*(?:to|-|–|—)\\s*(${CANDIDATE_TOKEN})`,
);

// Strict — a valid UTC timestamp, `YYYY-MM-DDThh:mm[:ss]Z`, hour 00-23,
// minute/second 00-59. No other offset form is accepted: decision 0001
// Addendum F says the window is logged "in UTC" (gate finding F-S6).
const STRICT_TIMESTAMP_RE =
  /^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?Z$/;

const MAX_WINDOW_HOURS = 8;

function headingText(line: string): string | null {
  const m = HEADING_RE.exec(line.trim());
  return m ? m[1]! : null;
}

/**
 * Validates one captured timestamp token strictly (format, then calendar
 * round-trip, the same technique `config.ts`'s `checkK2GateClosesAt` uses
 * for `K2_GATE_CLOSES_AT`) and returns the parsed `Date`. Throws a clear,
 * line-quoting error on anything else — an invalid hour/minute/second, a
 * non-`Z` offset, or a calendar date that doesn't exist (e.g. day 31 of a
 * 30-day month, which `Date` silently rolls forward instead of rejecting).
 */
function parseStrictTimestamp(token: string, line: string): Date {
  if (!STRICT_TIMESTAMP_RE.test(token)) {
    throw new Error(
      `docs/p0/X1.md "## Round windows" has a malformed timestamp "${token}" in the line "${line.trim()}" — ` +
        'round window bounds must be UTC, strict "YYYY-MM-DDThh:mm:ssZ" (hour 00-23, minute/second 00-59; no ' +
        "other offset is accepted — decision 0001 Addendum F logs the window in UTC).",
    );
  }
  const normalized = /:\d{2}:\d{2}Z$/.test(token)
    ? token
    : `${token.slice(0, -1)}:00Z`;
  const d = new Date(normalized);
  if (
    Number.isNaN(d.getTime()) ||
    d.toISOString().replace(".000Z", "Z") !== normalized
  ) {
    throw new Error(
      `docs/p0/X1.md "## Round windows" has a timestamp "${token}" that is not a valid calendar date/time, ` +
        `in the line "${line.trim()}".`,
    );
  }
  return d;
}

/**
 * Parses `docs/p0/X1.md`'s "## Round windows" section into a list of
 * `{startIso, endIso}` windows — one per matching bullet/line of the form
 * `<START> to <END>` (also accepts a bare `-`/en/em dash as the separator).
 * A blank/placeholder section (no line shaped like a window attempt)
 * returns `[]` — that is the normal pre-round state, not a parse error;
 * refusing to RUN on an empty result is the caller's job
 * (`readLoggedRoundWindows`), not this pure parser's.
 *
 * Gate finding F-S6: a line that IS shaped like a window attempt — it has
 * two `YYYY-MM-DDT...`-looking tokens joined by `to`/a dash — is validated
 * strictly and THROWN on, rather than silently producing a window that
 * later matches nothing: an invalid hour/minute/second, a non-`Z` offset,
 * a non-existent calendar date, `end <= start`, or a window longer than 8
 * hours (a round of golf; anything longer signals a typo, not a long
 * round) are all rejected here, loudly, before any workout is filtered.
 */
export function parseRoundWindows(markdown: string): RoundWindow[] {
  const lines = markdown.split("\n");
  const startIdx = lines.findIndex((l) => {
    const text = headingText(l);
    return text !== null && ROUND_WINDOWS_HEADING_RE.test(text);
  });
  if (startIdx === -1) {
    throw new Error(
      'docs/p0/X1.md is missing its "## Round windows" heading — cannot determine the logged round window(s) ' +
        "(decision 0001 Addendum F).",
    );
  }
  let bodyEnd = lines.length;
  for (let i = startIdx + 1; i < lines.length; i += 1) {
    if (headingText(lines[i]!) !== null) {
      bodyEnd = i;
      break;
    }
  }
  const windows: RoundWindow[] = [];
  for (let i = startIdx + 1; i < bodyEnd; i += 1) {
    const line = lines[i]!;
    // Gate finding F-N5: refuse a SECOND window on one line, loudly,
    // rather than silently reading only the first (the old `.exec`-once
    // behavior).
    const allMatchesOnLine = [
      ...line.matchAll(new RegExp(CANDIDATE_WINDOW_RE, "g")),
    ];
    if (allMatchesOnLine.length > 1) {
      throw new Error(
        `docs/p0/X1.md "## Round windows" has more than one window on a single line: "${line.trim()}" — ` +
          "put each round window on its own line.",
      );
    }
    const m = CANDIDATE_WINDOW_RE.exec(line);
    if (!m) continue;
    const start = parseStrictTimestamp(m[1]!, line);
    const end = parseStrictTimestamp(m[2]!, line);
    if (end.getTime() <= start.getTime()) {
      throw new Error(
        `docs/p0/X1.md "## Round windows" has a window whose end is not after its start, in the line ` +
          `"${line.trim()}" — a round window must have end > start.`,
      );
    }
    const hours = (end.getTime() - start.getTime()) / (60 * 60 * 1000);
    if (hours > MAX_WINDOW_HOURS) {
      throw new Error(
        `docs/p0/X1.md "## Round windows" has a window longer than ${MAX_WINDOW_HOURS} hours (${hours.toFixed(2)}h), ` +
          `in the line "${line.trim()}" — that is longer than a round of golf and almost certainly a typo.`,
      );
    }
    windows.push({ startIso: m[1]!, endIso: m[2]! });
  }
  return windows;
}

const SLACK_MINUTES = 60;

/**
 * Decision 0001 Addendum F: true when `startIsoOrNull` falls inside ANY of
 * `windows`, with 60 minutes of slack either side. A missing/unparseable
 * start time never matches (it cannot be shown to be IN the round, so per
 * the addendum's "only workouts whose start time falls inside ... count"
 * it does not count — this is stricter than the old `--since` filter,
 * which generously included anything it couldn't parse).
 */
export function isWithinRoundWindow(
  startIsoOrNull: string | null,
  windows: RoundWindow[],
): boolean {
  if (!startIsoOrNull) return false;
  const t = Date.parse(startIsoOrNull);
  if (Number.isNaN(t)) return false;
  const slackMs = SLACK_MINUTES * 60_000;
  return windows.some((w) => {
    const s = Date.parse(w.startIso);
    const e = Date.parse(w.endIso);
    if (Number.isNaN(s) || Number.isNaN(e)) return false;
    return t >= s - slackMs && t <= e + slackMs;
  });
}

/** Repo-relative path to `docs/p0/X1.md`, resolved from THIS module's own
 * location (works identically whether this runs from `src/` — vitest/
 * ts-node — or `dist/`, since both sit exactly one level under `tools/p0`). */
export function resolveX1DocPath(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.join(here, "..", "..", "..");
  return path.join(repoRoot, "docs", "p0", "X1.md");
}

/**
 * Reads and parses the repo's own `docs/p0/X1.md` for its logged round
 * window(s), and REFUSES (throws) if none are logged — decision 0001
 * Addendum F: "refuse if no window is logged," never silently run
 * unwindowed against every workout the device happens to hold.
 */
export async function readLoggedRoundWindows(
  x1DocPath: string = resolveX1DocPath(),
): Promise<RoundWindow[]> {
  const markdown = await readFile(x1DocPath, "utf8");
  const windows = parseRoundWindows(markdown);
  if (windows.length === 0) {
    throw new Error(
      `No round window is logged in ${x1DocPath}'s "## Round windows" section — decision 0001 Addendum F: ` +
        "Matt logs the UTC start/end time of each test round there BEFORE the export is read. Refusing to run.",
    );
  }
  return windows;
}
