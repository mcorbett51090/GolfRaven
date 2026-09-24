#!/usr/bin/env node
/**
 * `k3-verdict` — the K3 SEO-signal pass/kill verdict (build plan §10 P0;
 * `docs/p0/K3.md`) from the two fixed input tables in that file:
 *
 * - **Search Console**: median of the three fixed-month organic-click
 *   totals (decision 0001, Addendum A), compared to **M = 1,000**. Refuses
 *   to run if the SWC property id memo is blank, doesn't look like a real
 *   Search Console property (decision 0001, Addendum I "Search Console
 *   property id" — must read `sc-domain:<host>`, an `https://` or an
 *   `http://` URL-prefix property, never e.g. "TBD"), if any of the three
 *   months' clicks is blank, or if the read date is blank, not a real
 *   calendar date, later than today, or earlier than **2026-10-01**
 *   (decision 0001, Addendum I "the read date is real"). A blank month is
 *   "not read yet," and silently treating it as 0 clicks would be exactly
 *   the "silently count zero" the loud-failure contract forbids, so a
 *   partial read refuses rather than computing a wrong median. `today` is
 *   a parameter, never read from the system clock internally, so callers
 *   (tests, the CLI) control it explicitly.
 * - **Keyword Planner**: sum of the six closed-list terms' lower bounds,
 *   compared to **≥ 5,000**, applying decision 0001 Addendum D R5's
 *   "identical range counted once" rule EXACTLY as stated — two terms
 *   sharing the identical (lower, upper) range contribute that lower
 *   bound only once to the sum. A point value is entered as
 *   `lower = upper` (decision 0001, Addendum I — the table has no
 *   separate "Point value" column), so R5's dedup applies to a shared
 *   point value exactly as it does to a shared range. Refuses to run if
 *   any of the six terms has no range recorded at all.
 */
import {
  readK3Log,
  resolveK3DocPath,
  K3_KEYWORD_TERMS,
  type K3Log,
} from "./k3-log.js";

/** Decision 0001, Addendum A (default) / K3.md Pass bar. */
export const K3_SEARCH_CONSOLE_BAR = 1000;
/** Decision 0001, Addendum B / O7. */
export const K3_KEYWORD_BAR = 5000;
/** Decision 0001, Addendum I: a read before this date would lock in a
 * partial September 2026. */
export const K3_MIN_READ_DATE = "2026-10-01";
/** Decision 0001, Addendum I ("Search Console property id"): the property
 * id must be a domain property (`sc-domain:<host>`) or a URL-prefix
 * property (`https://…` or `http://…`), not a placeholder like "TBD". */
const PROPERTY_ID_RE = /^(sc-domain:\S+|https?:\/\/\S+)$/i;

const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/** Decision 0001, Addendum I ("the read date is real"): a real ISO
 * calendar date — not just digit-shaped (rejects e.g. "2026-13-45"). */
function isRealCalendarDate(value: string): boolean {
  if (!ISO_DATE_RE.test(value)) return false;
  const d = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === value;
}

export const K3_CONSEQUENCE_BOTH_MISS =
  "Both miss → the directory is scoped as a partner-facing asset, not a growth engine, and operator " +
  "co-marketing becomes the primary channel (SP10).";
export const K3_CONSEQUENCE_DISAGREE =
  "They disagree → the directory is a growth engine on probation, re-read 6 months after M1 from the " +
  "GolfRaven site's own Search Console.";
export const K3_CONSEQUENCE_UNIVERSAL =
  "P1 proceeds in every case: the catalog is the app's substrate.";

export type K3CombinedBranch = "both-miss" | "disagree" | "both-pass";

export interface K3KeywordContribution {
  term: string;
  lowerBound: number;
  upperBound: number;
  value: number;
  /** The other term(s) that shared this identical (lower, upper) range
   * and so did NOT contribute separately (R5's dedup). Empty otherwise. */
  dedupedWith: string[];
}

export interface K3VerdictResult {
  generatedAt: string;
  propertyId: string;
  searchConsole: {
    readDate: string;
    monthlyTotals: { month: string; clicks: number }[];
    median: number;
    bar: number;
    pass: boolean;
  };
  keyword: {
    contributions: K3KeywordContribution[];
    combinedVolume: number;
    bar: number;
    pass: boolean;
  };
  combinedBranch: K3CombinedBranch;
  consequenceText: string;
  universalNote: string;
}

function median3(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[1]!;
}

export function computeK3Verdict(log: K3Log, today: string): K3VerdictResult {
  if (!isRealCalendarDate(today)) {
    throw new Error(
      `computeK3Verdict: malformed today "${today}" — not a real ISO "YYYY-MM-DD" calendar date.`,
    );
  }

  const propertyId = log.propertyId.trim();
  if (propertyId === "") {
    throw new Error(
      "computeK3Verdict requires a recorded SWC Search Console property id (K3.md METHOD step 1) — " +
        'refusing to run with docs/p0/K3.md\'s "## SWC Search Console property" section still blank.',
    );
  }
  if (!PROPERTY_ID_RE.test(propertyId)) {
    throw new Error(
      `computeK3Verdict: the recorded property id "${propertyId}" doesn't look like a Search Console ` +
        'property — expected "sc-domain:<host>", an "https://" or an "http://" URL-prefix property ' +
        '(decision 0001, Addendum I: "Search Console property id"). A placeholder like "TBD" is refused.',
    );
  }

  if (log.readDate === null) {
    throw new Error(
      "computeK3Verdict requires a recorded Search Console read date (decision 0001, Addendum I: " +
        '"the read date is real") — refusing to run with docs/p0/K3.md\'s "## Search Console read" ' +
        "table's Read date still blank.",
    );
  }
  if (!isRealCalendarDate(log.readDate)) {
    throw new Error(
      `computeK3Verdict: the recorded read date "${log.readDate}" is not a real calendar date (decision ` +
        '0001, Addendum I: "the read date is real").',
    );
  }
  if (log.readDate > today) {
    throw new Error(
      `computeK3Verdict: the recorded read date "${log.readDate}" is later than today (${today}) — refusing ` +
        'a read dated in the future (decision 0001, Addendum I: "the read date is real").',
    );
  }
  if (log.readDate < K3_MIN_READ_DATE) {
    throw new Error(
      `computeK3Verdict: the recorded read date "${log.readDate}" is before ${K3_MIN_READ_DATE} (decision ` +
        "0001, Addendum I) — a read that early would lock in a partial September 2026; refusing to run.",
    );
  }

  const missingMonths = log.searchConsole
    .filter((r) => r.clicks === null)
    .map((r) => r.month);
  if (missingMonths.length > 0) {
    throw new Error(
      `computeK3Verdict requires all three fixed months' organic-click totals — missing: ` +
        `${missingMonths.join(", ")}. Refusing rather than silently treating a blank cell as 0 clicks.`,
    );
  }
  const monthlyTotals = log.searchConsole.map((r) => ({
    month: r.month,
    clicks: r.clicks!,
  }));
  const median = median3(monthlyTotals.map((r) => r.clicks));
  const searchConsolePass = median >= K3_SEARCH_CONSOLE_BAR;

  const missingTerms = log.keywords
    .filter((r) => r.lowerBound === null)
    .map((r) => r.term);
  if (missingTerms.length > 0) {
    throw new Error(
      `computeK3Verdict requires a range (lower + upper bound) for all six closed-list terms — missing: ` +
        `${missingTerms.join(", ")}. Refusing rather than silently treating a blank cell as 0 volume.`,
    );
  }

  // Decision 0001, Addendum D, R5 (as restated by Addendum I): "if two of
  // the six terms return the identical range, count that range once" —
  // applied literally to every term, including a degenerate range
  // (lower === upper) that represents a point value.
  const rangeGroups = new Map<
    string,
    { lower: number; upper: number; terms: string[] }
  >();
  for (const row of log.keywords) {
    const key = `${row.lowerBound}-${row.upperBound}`;
    const existing = rangeGroups.get(key);
    if (existing) {
      existing.terms.push(row.term);
    } else {
      rangeGroups.set(key, {
        lower: row.lowerBound!,
        upper: row.upperBound!,
        terms: [row.term],
      });
    }
  }
  const contributions: K3KeywordContribution[] = [];
  let combinedVolume = 0;
  for (const { lower, upper, terms } of rangeGroups.values()) {
    combinedVolume += lower;
    for (const term of terms) {
      contributions.push({
        term,
        lowerBound: lower,
        upperBound: upper,
        value: lower,
        dedupedWith: terms.filter((t) => t !== term),
      });
    }
  }
  contributions.sort(
    (a, b) =>
      K3_KEYWORD_TERMS.indexOf(a.term as (typeof K3_KEYWORD_TERMS)[number]) -
      K3_KEYWORD_TERMS.indexOf(b.term as (typeof K3_KEYWORD_TERMS)[number]),
  );
  const keywordPass = combinedVolume >= K3_KEYWORD_BAR;

  const bothMiss = !searchConsolePass && !keywordPass;
  const bothPass = searchConsolePass && keywordPass;
  const combinedBranch: K3CombinedBranch = bothMiss
    ? "both-miss"
    : bothPass
      ? "both-pass"
      : "disagree";
  const consequenceText =
    combinedBranch === "both-miss"
      ? K3_CONSEQUENCE_BOTH_MISS
      : combinedBranch === "disagree"
        ? K3_CONSEQUENCE_DISAGREE
        : K3_CONSEQUENCE_UNIVERSAL;

  return {
    generatedAt: new Date().toISOString(),
    propertyId,
    searchConsole: {
      readDate: log.readDate,
      monthlyTotals,
      median,
      bar: K3_SEARCH_CONSOLE_BAR,
      pass: searchConsolePass,
    },
    keyword: {
      contributions,
      combinedVolume,
      bar: K3_KEYWORD_BAR,
      pass: keywordPass,
    },
    combinedBranch,
    consequenceText,
    universalNote: K3_CONSEQUENCE_UNIVERSAL,
  };
}

export function renderK3VerdictMarkdown(result: K3VerdictResult): string {
  const lines: string[] = [];
  lines.push(`**SWC property:** ${result.propertyId}`);
  lines.push(`**Read date:** ${result.searchConsole.readDate}`);
  lines.push("");
  lines.push("## Search Console");
  lines.push("| Month | Organic clicks |");
  lines.push("|---|---|");
  for (const r of result.searchConsole.monthlyTotals)
    lines.push(`| ${r.month} | ${r.clicks} |`);
  lines.push("");
  lines.push(
    `Median: **${result.searchConsole.median}** vs bar ≥ ${result.searchConsole.bar} — ` +
      `**${result.searchConsole.pass ? "PASS" : "MISS"}**.`,
  );
  lines.push("");
  lines.push("## Keyword Planner");
  lines.push("| Term | Lower | Upper | Value | Deduped with |");
  lines.push("|---|---|---|---|---|");
  for (const c of result.keyword.contributions) {
    lines.push(
      `| ${c.term} | ${c.lowerBound} | ${c.upperBound} | ${c.value} | ${c.dedupedWith.join(", ") || "—"} |`,
    );
  }
  lines.push("");
  lines.push(
    `Combined volume: **${result.keyword.combinedVolume}** vs bar ≥ ${result.keyword.bar} — ` +
      `**${result.keyword.pass ? "PASS" : "MISS"}**.`,
  );
  lines.push("");
  lines.push(`**Combined branch: ${result.combinedBranch}**`);
  lines.push(`> ${result.consequenceText}`);
  if (result.combinedBranch !== "both-pass") {
    lines.push(`> ${result.universalNote}`);
  }
  return lines.join("\n");
}

interface CliArgs {
  outPrefix: string;
  /** `--memo <path>`: a copy of K3.md to read instead of the repo's
   * `docs/p0/K3.md`. For tests only — the recorded K3 verdict is always
   * computed from the repo's own memo (the default). */
  memoPath: string | undefined;
}

function parseArgs(argv: string[]): CliArgs {
  const opts: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg && arg.startsWith("--")) {
      opts[arg.slice(2)] = argv[i + 1] ?? "";
      i += 1;
    }
  }
  return {
    outPrefix: opts.out || "k3-verdict-result",
    memoPath: opts.memo || undefined,
  };
}

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  const log = await readK3Log(args.memoPath);
  // Provenance (gate round 3): every output records which file it was computed
  // from, with its SHA-256, and says loudly when that is not the repo's own
  // K3 memo — so a --log/--memo run can never pass for the recorded verdict.
  const { readFile: readSource } = await import("node:fs/promises");
  const { createHash } = await import("node:crypto");
  const { resolve: resolvePath } = await import("node:path");
  const repoPath = resolvePath(resolveK3DocPath());
  const sourcePath = resolvePath(args.memoPath ?? repoPath);
  const source = {
    path: sourcePath,
    sha256: createHash("sha256")
      .update(await readSource(sourcePath))
      .digest("hex"),
    isRepoLog: sourcePath === repoPath,
  };
  const banner = source.isRepoLog
    ? ""
    : `> **NOT THE RECORDED K3 MEMO.** Computed from \`${sourcePath}\`, not the repo's own K3 memo. This output is not a P0 verdict.\n\n`;
  const today = new Date().toISOString().slice(0, 10);
  const result = computeK3Verdict(log, today);
  const { writeFile } = await import("node:fs/promises");
  await writeFile(
    `${args.outPrefix}.json`,
    `${JSON.stringify({ ...result, source }, null, 2)}\n`,
    "utf8",
  );
  const md = banner + renderK3VerdictMarkdown(result);
  await writeFile(`${args.outPrefix}.md`, `${md}\n`, "utf8");
  process.stdout.write(`${md}\n`);
}

async function isMainModule(): Promise<boolean> {
  if (!process.argv[1]) return false;
  try {
    const { realpath } = await import("node:fs/promises");
    const { fileURLToPath } = await import("node:url");
    const [herePath, argvPath] = await Promise.all([
      realpath(fileURLToPath(import.meta.url)),
      realpath(process.argv[1]),
    ]);
    return herePath === argvPath;
  } catch {
    return false;
  }
}

if (await isMainModule()) {
  main(process.argv.slice(2)).catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`k3-verdict: ${message}\n`);
    process.exitCode = 1;
  });
}
