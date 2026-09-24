/**
 * `docs/p0/K3.md`'s two input tables (Search Console clicks + read date,
 * Keyword Planner ranges) plus the SWC property id memo. Both tables and
 * the property-id field were fixed 2026-09-24, before any K3 read — see
 * the note committed directly above each table in that file. Decision
 * 0001, Addendum I (2026-09-24) added the Search Console table's "Read
 * date" cell and removed the Keyword Planner table's "Point value" column
 * — a point value is now entered as `lower = upper`, while the table was
 * still empty.
 *
 * Structural strictness lives here (a missing/extra month, an off-list or
 * missing keyword term, a malformed number, a half-filled range, a lower
 * bound above the upper bound, a Read date recorded more than once, or a
 * table row separated from its table by a blank line): all THROW. Whether
 * a *present-but-blank* value should refuse a run is a business rule about
 * the whole log, not a per-cell parse question, so that refusal lives in
 * `k3-verdict.ts` instead — see its module doc.
 */
import { readFile } from "node:fs/promises";
import path from "node:path";
import { repoRoot } from "./run-dir.js";

/** Decision 0001, Addendum D, R4: the three fixed Search Console months. */
export const K3_SEARCH_CONSOLE_MONTHS = [
  "2026-07",
  "2026-08",
  "2026-09",
] as const;

/** Decision 0001, Addendum B (closed list) — exact casing as pre-registered. */
export const K3_KEYWORD_TERMS = [
  "golf trail",
  "golf trails",
  "robert trent jones golf trail",
  "tennessee golf trail",
  "vancouver island golf trail",
  "oklahoma golf trail",
] as const;

export interface K3SearchConsoleRow {
  month: (typeof K3_SEARCH_CONSOLE_MONTHS)[number];
  clicks: number | null;
}

export interface K3KeywordRow {
  term: (typeof K3_KEYWORD_TERMS)[number];
  lowerBound: number | null;
  upperBound: number | null;
}

export interface K3Log {
  propertyId: string;
  searchConsole: K3SearchConsoleRow[];
  /** Decision 0001, Addendum I: the date the Search Console export was
   * actually read, recorded once (on any one of the three month rows) —
   * `null` when not yet recorded. */
  readDate: string | null;
  keywords: K3KeywordRow[];
}

const HEADING_RE = /^#{1,6}\s*(.+?)\s*$/;
const SEPARATOR_ROW_RE = /^\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/;
const PLACEHOLDER_LINE_RE = /^_\(.*\)_$/;
const NON_NEGATIVE_INT_RE = /^\d+$/;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function headingText(line: string): string | null {
  const m = HEADING_RE.exec(line.trim());
  return m ? m[1]! : null;
}

function splitRow(line: string): string[] {
  const trimmed = line.trim();
  const inner = trimmed.replace(/^\|/, "").replace(/\|$/, "");
  return inner.split("|").map((c) => c.trim());
}

function findHeadingIndex(
  lines: string[],
  matches: (text: string) => boolean,
): number {
  return lines.findIndex((l) => {
    const text = headingText(l);
    return text !== null && matches(text);
  });
}

function findTableStart(lines: string[], fromIdx: number): number {
  for (let i = fromIdx + 1; i < lines.length; i += 1) {
    const line = lines[i]!;
    if (headingText(line) !== null) break;
    if (line.trim().startsWith("|")) return i;
  }
  return -1;
}

/** Decision 0001, Addendum I ("Log integrity": every row is read; a row
 * that cannot be read is an error, never skipped): once the contiguous
 * table ends, keep scanning forward — stopping only at the next heading —
 * and throw if any further line starts with "|". */
function assertNoStrayRowsAfterTable(
  lines: string[],
  fromIdx: number,
  label: string,
): void {
  for (let i = fromIdx; i < lines.length; i += 1) {
    const line = lines[i]!;
    if (headingText(line) !== null) return;
    if (line.trim().startsWith("|")) {
      throw new Error(
        `${label} has a table row separated from the table by a blank line (or other content): ` +
          `"${line.trim()}" — rows must be contiguous with the table; move it back in (decision 0001, ` +
          'Addendum I: "Log integrity" — a row that cannot be read is an error, never skipped).',
      );
    }
  }
}

function parseNonNegativeIntOrNull(
  raw: string,
  context: string,
): number | null {
  const cell = raw.trim();
  if (cell === "") return null;
  if (!NON_NEGATIVE_INT_RE.test(cell)) {
    throw new Error(
      `${context}: malformed number "${cell}" — expected a non-negative integer or a blank cell.`,
    );
  }
  return Number.parseInt(cell, 10);
}

function parseIsoDateOrNull(raw: string, context: string): string | null {
  const cell = raw.trim();
  if (cell === "") return null;
  if (!ISO_DATE_RE.test(cell)) {
    throw new Error(
      `${context}: malformed date "${cell}" — expected ISO "YYYY-MM-DD" or a blank cell.`,
    );
  }
  const d = new Date(`${cell}T00:00:00Z`);
  if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== cell) {
    throw new Error(`${context}: "${cell}" is not a valid calendar date.`);
  }
  return cell;
}

function parsePropertyId(markdown: string, lines: string[]): string {
  const idx = findHeadingIndex(lines, (t) =>
    /^SWC Search Console property\b/i.test(t),
  );
  if (idx === -1) {
    throw new Error(
      'docs/p0/K3.md is missing its "## SWC Search Console property" heading.',
    );
  }
  let bodyEnd = lines.length;
  for (let i = idx + 1; i < lines.length; i += 1) {
    if (headingText(lines[i]!) !== null) {
      bodyEnd = i;
      break;
    }
  }
  // The placeholder text may wrap across more than one markdown line (the
  // real docs/p0/K3.md's does) — join first, then test the WHOLE joined
  // body against the placeholder pattern, rather than testing line by line
  // (which would never match either half of a wrapped placeholder).
  const bodyLines = lines
    .slice(idx + 1, bodyEnd)
    .map((l) => l.trim())
    .filter((l) => l !== "");
  const joined = bodyLines.join(" ").trim();
  return PLACEHOLDER_LINE_RE.test(joined) ? "" : joined;
}

function parseSearchConsoleTable(lines: string[]): {
  rows: K3SearchConsoleRow[];
  readDate: string | null;
} {
  const idx = findHeadingIndex(lines, (t) => /^Search Console read\b/i.test(t));
  if (idx === -1) {
    throw new Error(
      'docs/p0/K3.md is missing its "## Search Console read" heading.',
    );
  }
  const tableStart = findTableStart(lines, idx);
  if (tableStart === -1) {
    throw new Error(
      'docs/p0/K3.md "## Search Console read" has no markdown table under its heading.',
    );
  }
  const header = splitRow(lines[tableStart]!);
  const expected = ["Month", "Total organic clicks", "Read date"];
  if (
    header.length !== expected.length ||
    !header.every((c, i) => c === expected[i])
  ) {
    throw new Error(
      `docs/p0/K3.md "## Search Console read" table has an unexpected column layout.\n` +
        `Expected: ${expected.join(" | ")}\nFound:    ${header.join(" | ")}`,
    );
  }
  let dataStart = tableStart + 1;
  if (
    dataStart < lines.length &&
    SEPARATOR_ROW_RE.test(lines[dataStart]!.trim())
  )
    dataStart += 1;
  const byMonth = new Map<string, number | null>();
  const readDateEntries: { month: string; date: string }[] = [];
  let i = dataStart;
  while (i < lines.length && lines[i]!.trim().startsWith("|")) {
    const line = lines[i]!;
    const cells = splitRow(line);
    if (cells.length !== 3) {
      throw new Error(
        `docs/p0/K3.md Search Console row "${line.trim()}" has ${cells.length} cells, expected 3.`,
      );
    }
    const [monthRaw, clicksRaw, readDateRaw] = cells as [
      string,
      string,
      string,
    ];
    if (!(K3_SEARCH_CONSOLE_MONTHS as readonly string[]).includes(monthRaw)) {
      throw new Error(
        `docs/p0/K3.md Search Console table has an unexpected month "${monthRaw}" — the fixed months ` +
          `(decision 0001, Addendum D, R4) are exactly: ${K3_SEARCH_CONSOLE_MONTHS.join(", ")}.`,
      );
    }
    if (byMonth.has(monthRaw)) {
      throw new Error(
        `docs/p0/K3.md Search Console table has a duplicate row for "${monthRaw}".`,
      );
    }
    byMonth.set(
      monthRaw,
      parseNonNegativeIntOrNull(
        clicksRaw,
        `Search Console ${monthRaw}: Total organic clicks`,
      ),
    );
    const readDate = parseIsoDateOrNull(
      readDateRaw,
      `Search Console ${monthRaw}: Read date`,
    );
    if (readDate !== null)
      readDateEntries.push({ month: monthRaw, date: readDate });
    i += 1;
  }
  assertNoStrayRowsAfterTable(
    lines,
    i,
    'docs/p0/K3.md "## Search Console read"',
  );
  for (const month of K3_SEARCH_CONSOLE_MONTHS) {
    if (!byMonth.has(month)) {
      throw new Error(
        `docs/p0/K3.md Search Console table is missing the required month "${month}".`,
      );
    }
  }
  if (readDateEntries.length > 1) {
    throw new Error(
      `docs/p0/K3.md Search Console table has a "Read date" recorded on more than one row ` +
        `(${readDateEntries.map((e) => `${e.month}: ${e.date}`).join(", ")}) — record it once, on any single row.`,
    );
  }
  const rows = K3_SEARCH_CONSOLE_MONTHS.map((month) => ({
    month,
    clicks: byMonth.get(month)!,
  }));
  return { rows, readDate: readDateEntries[0]?.date ?? null };
}

function parseKeywordTable(lines: string[]): K3KeywordRow[] {
  const idx = findHeadingIndex(lines, (t) =>
    /^Keyword Planner read\b/i.test(t),
  );
  if (idx === -1) {
    throw new Error(
      'docs/p0/K3.md is missing its "## Keyword Planner read" heading.',
    );
  }
  const tableStart = findTableStart(lines, idx);
  if (tableStart === -1) {
    throw new Error(
      'docs/p0/K3.md "## Keyword Planner read" has no markdown table under its heading.',
    );
  }
  const header = splitRow(lines[tableStart]!);
  const expected = ["Term", "Lower bound", "Upper bound"];
  if (
    header.length !== expected.length ||
    !header.every((c, i) => c === expected[i])
  ) {
    throw new Error(
      `docs/p0/K3.md "## Keyword Planner read" table has an unexpected column layout.\n` +
        `Expected: ${expected.join(" | ")}\nFound:    ${header.join(" | ")}`,
    );
  }
  let dataStart = tableStart + 1;
  if (
    dataStart < lines.length &&
    SEPARATOR_ROW_RE.test(lines[dataStart]!.trim())
  )
    dataStart += 1;
  const byTerm = new Map<string, K3KeywordRow>();
  let i = dataStart;
  while (i < lines.length && lines[i]!.trim().startsWith("|")) {
    const line = lines[i]!;
    const cells = splitRow(line);
    if (cells.length !== 3) {
      throw new Error(
        `docs/p0/K3.md Keyword Planner row "${line.trim()}" has ${cells.length} cells, expected 3.`,
      );
    }
    const [termRaw, lowerRaw, upperRaw] = cells as [string, string, string];
    const termNormalized = termRaw.trim().toLowerCase();
    if (!(K3_KEYWORD_TERMS as readonly string[]).includes(termNormalized)) {
      throw new Error(
        `docs/p0/K3.md Keyword Planner table has an off-list term "${termRaw}" — the closed 6-term list ` +
          `(decision 0001, Addendum B) is exactly: ${K3_KEYWORD_TERMS.join(", ")}.`,
      );
    }
    if (byTerm.has(termNormalized)) {
      throw new Error(
        `docs/p0/K3.md Keyword Planner table has a duplicate row for "${termRaw}".`,
      );
    }
    const lowerBound = parseNonNegativeIntOrNull(
      lowerRaw,
      `Keyword "${termRaw}": Lower bound`,
    );
    const upperBound = parseNonNegativeIntOrNull(
      upperRaw,
      `Keyword "${termRaw}": Upper bound`,
    );
    if ((lowerBound === null) !== (upperBound === null)) {
      throw new Error(
        `docs/p0/K3.md Keyword Planner row "${termRaw}" has only one of Lower bound / Upper bound filled in — ` +
          "a range needs both bounds (a point value is entered as lower = upper, decision 0001 Addendum I).",
      );
    }
    if (lowerBound !== null && upperBound !== null && lowerBound > upperBound) {
      throw new Error(
        `docs/p0/K3.md Keyword Planner row "${termRaw}" has Lower bound (${lowerBound}) greater than Upper ` +
          `bound (${upperBound}) — a range's lower bound must not exceed its upper bound.`,
      );
    }
    byTerm.set(termNormalized, {
      term: termNormalized as (typeof K3_KEYWORD_TERMS)[number],
      lowerBound,
      upperBound,
    });
    i += 1;
  }
  assertNoStrayRowsAfterTable(
    lines,
    i,
    'docs/p0/K3.md "## Keyword Planner read"',
  );
  for (const term of K3_KEYWORD_TERMS) {
    if (!byTerm.has(term)) {
      throw new Error(
        `docs/p0/K3.md Keyword Planner table is missing the required term "${term}".`,
      );
    }
  }
  return K3_KEYWORD_TERMS.map((term) => byTerm.get(term)!);
}

/** Parses `docs/p0/K3.md`'s property-id memo and its two fixed input
 * tables. Structural errors (missing heading/table, unexpected column
 * layout, off-list/missing/duplicate row, malformed number, half-filled
 * range, lower bound above upper bound, a Read date recorded more than
 * once, or a table row separated from its table by a blank line) all
 * throw. A blank property id, a blank cell inside either table, or no
 * recorded Read date is returned as `""`/`null` — NOT an error here (see
 * module doc); `k3-verdict.ts` decides whether that blank refuses the
 * run. */
export function parseK3Log(markdown: string): K3Log {
  const lines = markdown.split("\n");
  const propertyId = parsePropertyId(markdown, lines);
  const { rows: searchConsole, readDate } = parseSearchConsoleTable(lines);
  const keywords = parseKeywordTable(lines);
  return { propertyId, searchConsole, readDate, keywords };
}

export function resolveK3DocPath(): string {
  return path.join(repoRoot(), "docs", "p0", "K3.md");
}

/** Reads and parses the repo's own `docs/p0/K3.md`. No override flag —
 * same philosophy as `round-windows.ts`'s `readLoggedRoundWindows` and
 * `k1-log.ts`'s `readK1Log`. */
export async function readK3Log(
  k3DocPath: string = resolveK3DocPath(),
): Promise<K3Log> {
  const markdown = await readFile(k3DocPath, "utf8");
  return parseK3Log(markdown);
}
