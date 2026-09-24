/**
 * `docs/partners/k1-outreach.md` §(g)'s K1 tracking table — the SINGLE K1
 * log (decision 0001, Addendum D, R2: "The single K1 log is the tracking
 * table in `docs/partners/k1-outreach.md` §(g)"). The table's columns were
 * restructured 2026-09-24, before any outreach, precisely so `k1-verdict`
 * can read every input as its own column rather than parsing free text —
 * see the note committed directly above the table in that file. The
 * "Sponsor conversation date" column was added 2026-09-24 too (decision
 * 0001, Addendum I), while the table was still empty.
 *
 * Strict, loud-failure parsing: an unknown operator name, a malformed
 * date, an unexpected column, a malformed Y/N cell, a sponsor row whose
 * target matches a known operator name, or a table row separated from the
 * table by a blank line all THROW. A blank cell means "not yet" and is
 * never an error — the whole point of reading a table that is genuinely
 * empty pre-outreach. "Hammock Coast" is accepted as an alias of
 * "Hammock Coast Golf Trail" (decision 0001, Addendum I; R2 names it
 * "Hammock Coast", the table's own row has always read "Hammock Coast Golf
 * Trail") and canonicalized to the latter before any matching happens.
 */
import { readFile } from "node:fs/promises";
import path from "node:path";
import { repoRoot } from "./run-dir.js";

export type K1RowType =
  | "Operator (slate)"
  | "Operator (reserve)"
  | "Operator (co-op reserve)"
  | "Sponsor";

export const K1_KNOWN_TYPES: readonly K1RowType[] = [
  "Operator (slate)",
  "Operator (reserve)",
  "Operator (co-op reserve)",
  "Sponsor",
];

/** The 5 named operators (decision 0001, Addendum D, R2) plus Oklahoma
 * Golf Trail, the conditional 6th row kept for swap readiness only. */
export const K1_KNOWN_OPERATOR_NAMES = [
  "Tennessee Golf Trail",
  "Vancouver Island Golf Trail",
  "Robert Trent Jones Golf Trail",
  "Hammock Coast Golf Trail",
  "Canadian Rockies Golf Consortium",
  "Oklahoma Golf Trail",
] as const;

/** decision 0001, Addendum I: accept both spellings for a Target cell,
 * canonicalized to the table's own row name before any matching. */
const OPERATOR_ALIASES: Readonly<Record<string, string>> = {
  "Hammock Coast": "Hammock Coast Golf Trail",
};

function canonicalizeTarget(raw: string): string {
  return OPERATOR_ALIASES[raw] ?? raw;
}

/** The 3 pilot-slate trails Oklahoma Golf Trail can replace via the X2
 * swap rule (decision 0001, Addendum D, R2 / K1.md METHOD step 1). */
export const K1_SLATE_TRAIL_NAMES = [
  "Tennessee Golf Trail",
  "Vancouver Island Golf Trail",
  "Robert Trent Jones Golf Trail",
] as const;

/** The base 5 named operators (decision 0001, Addendum D, R2), before any
 * Oklahoma swap is applied. */
export const K1_BASE_FIVE_NAMES = [
  "Tennessee Golf Trail",
  "Vancouver Island Golf Trail",
  "Robert Trent Jones Golf Trail",
  "Hammock Coast Golf Trail",
  "Canadian Rockies Golf Consortium",
] as const;

export interface K1Row {
  target: string;
  type: K1RowType;
  contactedDate: string | null;
  callAcceptedDate: string | null;
  loiDate: string | null;
  feeWillingness: "Y" | "N" | null;
  /** Blank on every row except "Oklahoma Golf Trail". Non-blank there
   * names the slate trail OK's swap replaces (K1.md METHOD step 1). */
  okSwapReplaces: string | null;
  sponsorDecisionMakerNamed: "Y" | "N" | null;
  sponsorBudgetStated: "Y" | "N" | null;
  sponsorAttributionInterest: "Y" | "N" | null;
  /** Decision 0001, Addendum I: a qualified sponsor conversation also
   * needs a recorded date, checked against the same 2026-11-30 full-gate
   * cutoff as the LOIs. */
  sponsorConversationDate: string | null;
  notes: string;
}

const EXPECTED_HEADERS = [
  "Target",
  "Type",
  "Contacted date",
  "Call accepted date",
  "LOI date",
  "Fee willingness (Y/N)",
  "OK swap replaces",
  "Sponsor: decision-maker named (Y/N)",
  "Sponsor: budget range stated (Y/N)",
  "Sponsor: attribution interest (Y/N)",
  "Sponsor conversation date",
  "Notes",
];

const HEADING_RE = /^#{1,6}\s*(.+?)\s*$/;
// No trailing \b: "(g)" is immediately followed by a space, and \b never
// matches between two non-word characters (")" and " "), so a boundary
// assertion there would never match anything.
const G_HEADING_RE = /^\(g\)/;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const SEPARATOR_ROW_RE = /^\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/;

function headingText(line: string): string | null {
  const m = HEADING_RE.exec(line.trim());
  return m ? m[1]! : null;
}

function splitRow(line: string): string[] {
  const trimmed = line.trim();
  const inner = trimmed.replace(/^\|/, "").replace(/\|$/, "");
  return inner.split("|").map((c) => c.trim());
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

function parseYNOrNull(raw: string, context: string): "Y" | "N" | null {
  const cell = raw.trim();
  if (cell === "") return null;
  if (cell === "Y" || cell === "N") return cell;
  throw new Error(
    `${context}: malformed value "${cell}" — expected "Y", "N", or a blank cell.`,
  );
}

/** Decision 0001, Addendum I ("Log integrity": every row is read; a row
 * that cannot be read is an error, never skipped): once the contiguous
 * table ends, keep scanning forward — stopping only at the next heading —
 * and throw if any further line starts with "|". A pipe row separated from
 * the table by a blank line (or anything else) is a data-loss bug in the
 * document, not a legitimate end of table. */
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

/**
 * Parses `docs/partners/k1-outreach.md`'s "## (g)" table into strict
 * `K1Row[]`. Throws on: a missing "(g)" heading or table, a header row
 * that doesn't match the fixed column list exactly (gate: "an unexpected
 * column"), a row with the wrong cell count, an unrecognized `Type`, an
 * operator-type row whose `Target` isn't one of the 6 known operator names
 * (gate: "an unknown operator name"), a sponsor row whose `Target` matches
 * a known operator name, a malformed date or Y/N cell, an `okSwapReplaces`
 * value set on any row other than "Oklahoma Golf Trail", an
 * `okSwapReplaces` value that isn't one of the 3 slate trail names, a
 * missing required operator row, a duplicate operator row, or a table row
 * separated from the table by a blank line.
 */
export function parseK1Table(markdown: string): K1Row[] {
  const lines = markdown.split("\n");
  const headingIdx = lines.findIndex((l) => {
    const text = headingText(l);
    return text !== null && G_HEADING_RE.test(text);
  });
  if (headingIdx === -1) {
    throw new Error(
      'docs/partners/k1-outreach.md is missing its "## (g)" heading — cannot find the K1 tracking table.',
    );
  }
  let tableStart = -1;
  for (let i = headingIdx + 1; i < lines.length; i += 1) {
    const line = lines[i]!;
    if (headingText(line) !== null) break;
    if (line.trim().startsWith("|")) {
      tableStart = i;
      break;
    }
  }
  if (tableStart === -1) {
    throw new Error(
      "docs/partners/k1-outreach.md §(g) has no markdown table under its heading.",
    );
  }
  const headerCells = splitRow(lines[tableStart]!);
  if (
    headerCells.length !== EXPECTED_HEADERS.length ||
    !headerCells.every((c, i) => c === EXPECTED_HEADERS[i])
  ) {
    throw new Error(
      `docs/partners/k1-outreach.md §(g) has an unexpected column layout.\n` +
        `Expected: ${EXPECTED_HEADERS.join(" | ")}\n` +
        `Found:    ${headerCells.join(" | ")}`,
    );
  }
  let dataStart = tableStart + 1;
  if (
    dataStart < lines.length &&
    SEPARATOR_ROW_RE.test(lines[dataStart]!.trim())
  ) {
    dataStart += 1;
  }
  const rows: K1Row[] = [];
  let i = dataStart;
  while (i < lines.length && lines[i]!.trim().startsWith("|")) {
    const line = lines[i]!;
    const cells = splitRow(line);
    if (cells.length !== EXPECTED_HEADERS.length) {
      throw new Error(
        `docs/partners/k1-outreach.md §(g) row "${line.trim()}" has ${cells.length} cells, expected ${EXPECTED_HEADERS.length}.`,
      );
    }
    const [
      targetRaw,
      typeRaw,
      contactedRaw,
      callAcceptedRaw,
      loiDateRaw,
      feeRaw,
      okSwapRaw,
      dmRaw,
      budgetRaw,
      attributionRaw,
      sponsorConversationRaw,
      notes,
    ] = cells as [
      string,
      string,
      string,
      string,
      string,
      string,
      string,
      string,
      string,
      string,
      string,
      string,
    ];
    const target = canonicalizeTarget(targetRaw);
    if (target === "") {
      throw new Error(
        `docs/partners/k1-outreach.md §(g) has a row with a blank Target.`,
      );
    }
    if (!K1_KNOWN_TYPES.includes(typeRaw as K1RowType)) {
      throw new Error(
        `docs/partners/k1-outreach.md §(g) row "${target}" has an unrecognized Type "${typeRaw}" — ` +
          `expected one of: ${K1_KNOWN_TYPES.join(", ")}.`,
      );
    }
    const type = typeRaw as K1RowType;
    const isOperatorType = type !== "Sponsor";
    if (
      isOperatorType &&
      !K1_KNOWN_OPERATOR_NAMES.includes(
        target as (typeof K1_KNOWN_OPERATOR_NAMES)[number],
      )
    ) {
      throw new Error(
        `docs/partners/k1-outreach.md §(g) has an unknown operator name "${target}" — ` +
          `expected one of the 5 named operators (decision 0001, Addendum D, R2) or "Oklahoma Golf Trail": ` +
          `${K1_KNOWN_OPERATOR_NAMES.join(", ")}.`,
      );
    }
    if (
      !isOperatorType &&
      K1_KNOWN_OPERATOR_NAMES.includes(
        target as (typeof K1_KNOWN_OPERATOR_NAMES)[number],
      )
    ) {
      throw new Error(
        `docs/partners/k1-outreach.md §(g) has a Sponsor row named "${target}", which matches a known ` +
          "operator name — sponsor and operator rows must use distinct names.",
      );
    }
    const contactedDate = parseIsoDateOrNull(
      contactedRaw,
      `${target}: Contacted date`,
    );
    const callAcceptedDate = parseIsoDateOrNull(
      callAcceptedRaw,
      `${target}: Call accepted date`,
    );
    const loiDate = parseIsoDateOrNull(loiDateRaw, `${target}: LOI date`);
    const feeWillingness = parseYNOrNull(feeRaw, `${target}: Fee willingness`);
    const okSwapCell = okSwapRaw.trim();
    let okSwapReplaces: string | null = null;
    if (okSwapCell !== "") {
      if (target !== "Oklahoma Golf Trail") {
        throw new Error(
          `docs/partners/k1-outreach.md §(g) row "${target}" has a non-blank "OK swap replaces" value ` +
            `("${okSwapCell}"), but that column only applies to the "Oklahoma Golf Trail" row.`,
        );
      }
      if (
        !K1_SLATE_TRAIL_NAMES.includes(
          okSwapCell as (typeof K1_SLATE_TRAIL_NAMES)[number],
        )
      ) {
        throw new Error(
          `docs/partners/k1-outreach.md §(g) "Oklahoma Golf Trail"'s "OK swap replaces" value "${okSwapCell}" ` +
            `is not one of the 3 slate trail names: ${K1_SLATE_TRAIL_NAMES.join(", ")}.`,
        );
      }
      okSwapReplaces = okSwapCell;
    }
    const sponsorDecisionMakerNamed = parseYNOrNull(
      dmRaw,
      `${target}: Sponsor decision-maker named`,
    );
    const sponsorBudgetStated = parseYNOrNull(
      budgetRaw,
      `${target}: Sponsor budget range stated`,
    );
    const sponsorAttributionInterest = parseYNOrNull(
      attributionRaw,
      `${target}: Sponsor attribution interest`,
    );
    const sponsorConversationDate = parseIsoDateOrNull(
      sponsorConversationRaw,
      `${target}: Sponsor conversation date`,
    );
    rows.push({
      target,
      type,
      contactedDate,
      callAcceptedDate,
      loiDate,
      feeWillingness,
      okSwapReplaces,
      sponsorDecisionMakerNamed,
      sponsorBudgetStated,
      sponsorAttributionInterest,
      sponsorConversationDate,
      notes,
    });
    i += 1;
  }
  assertNoStrayRowsAfterTable(lines, i, "docs/partners/k1-outreach.md §(g)");
  const seen = new Set<string>();
  for (const row of rows) {
    if (row.type === "Sponsor") continue;
    if (seen.has(row.target)) {
      throw new Error(
        `docs/partners/k1-outreach.md §(g) has a duplicate operator row for "${row.target}" — this also ` +
          "catches logging the same operator under both its name and its alias (decision 0001, Addendum I: " +
          '"Name alias" — logging it under both names is an error).',
      );
    }
    seen.add(row.target);
  }
  for (const name of K1_KNOWN_OPERATOR_NAMES) {
    if (!seen.has(name)) {
      throw new Error(
        `docs/partners/k1-outreach.md §(g) is missing the required operator row "${name}".`,
      );
    }
  }
  return rows;
}

/** Repo-relative path to `docs/partners/k1-outreach.md`. */
export function resolveK1LogPath(): string {
  return path.join(repoRoot(), "docs", "partners", "k1-outreach.md");
}

/** Reads and parses the repo's own K1 log. No override flag — same
 * philosophy as `round-windows.ts`'s `readLoggedRoundWindows`: the K1 log
 * lives at exactly one pre-registered path. */
export async function readK1Log(
  k1LogPath: string = resolveK1LogPath(),
): Promise<K1Row[]> {
  const markdown = await readFile(k1LogPath, "utf8");
  return parseK1Table(markdown);
}
