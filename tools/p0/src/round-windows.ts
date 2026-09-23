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
const WINDOW_LINE_RE =
  /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?Z)\s*(?:to|-|–|—)\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?Z)/;

function headingText(line: string): string | null {
  const m = HEADING_RE.exec(line.trim());
  return m ? m[1]! : null;
}

/**
 * Parses `docs/p0/X1.md`'s "## Round windows" section into a list of
 * `{startIso, endIso}` windows — one per matching bullet/line of the form
 * `<START> to <END>` (also accepts a bare `-`/en/em dash as the separator).
 * A blank/placeholder section (no matching lines) returns `[]` — that is
 * the normal pre-round state, not a parse error; refusing to RUN on an
 * empty result is the caller's job (`readLoggedRoundWindows`), not this
 * pure parser's.
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
    const m = WINDOW_LINE_RE.exec(lines[i]!);
    if (m) windows.push({ startIso: m[1]!, endIso: m[2]! });
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
export function isWithinRoundWindow(startIsoOrNull: string | null, windows: RoundWindow[]): boolean {
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
export async function readLoggedRoundWindows(x1DocPath: string = resolveX1DocPath()): Promise<RoundWindow[]> {
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
