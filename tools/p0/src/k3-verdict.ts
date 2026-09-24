#!/usr/bin/env node
/**
 * `k3-verdict` — the K3 SEO-signal pass/kill verdict (build plan §10 P0;
 * `docs/p0/K3.md`) from the two fixed input tables in that file:
 *
 * - **Search Console**: median of the three fixed-month organic-click
 *   totals (decision 0001, Addendum A), compared to **M = 1,000**. Refuses
 *   to run if the SWC property id memo is blank (K3.md METHOD step 1), OR
 *   if any of the three months' clicks is blank — a blank month is "not
 *   read yet," and silently treating it as 0 clicks would be exactly the
 *   "silently count zero" the loud-failure contract forbids, so a partial
 *   read refuses rather than computing a wrong median. This generalizes
 *   the task's explicit "refuse to run when a pre-registered input is
 *   blank" instruction from the property id (the one case named
 *   explicitly) to the clicks themselves, for the same reason.
 * - **Keyword Planner**: sum of the six closed-list terms' lower bounds,
 *   compared to **≥ 5,000**, applying decision 0001 Addendum D R5's
 *   "identical range counted once" rule EXACTLY as stated — two terms
 *   sharing the identical (lower, upper) range contribute that lower
 *   bound only once to the sum; a point-value term is not a "range" under
 *   R5's wording and is never deduplicated against anything. Refuses to
 *   run if any of the six terms has neither a range nor a point value
 *   recorded, for the same "never silently count zero" reason as above.
 */
import { readK3Log, K3_KEYWORD_TERMS, type K3Log } from "./k3-log.js";

/** Decision 0001, Addendum A (default) / K3.md Pass bar. */
export const K3_SEARCH_CONSOLE_BAR = 1000;
/** Decision 0001, Addendum B / O7. */
export const K3_KEYWORD_BAR = 5000;

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
  kind: "range" | "point";
  value: number;
  /** For a range term, the other term(s) that shared its identical range
   * and so did NOT contribute separately (R5's dedup). Empty otherwise. */
  dedupedWith: string[];
}

export interface K3VerdictResult {
  generatedAt: string;
  propertyId: string;
  searchConsole: {
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

export function computeK3Verdict(log: K3Log): K3VerdictResult {
  const propertyId = log.propertyId.trim();
  if (propertyId === "") {
    throw new Error(
      "computeK3Verdict requires a recorded SWC Search Console property id (K3.md METHOD step 1) — " +
        'refusing to run with docs/p0/K3.md\'s "## SWC Search Console property" section still blank.',
    );
  }

  const missingMonths = log.searchConsole.filter((r) => r.clicks === null).map((r) => r.month);
  if (missingMonths.length > 0) {
    throw new Error(
      `computeK3Verdict requires all three fixed months' organic-click totals — missing: ` +
        `${missingMonths.join(", ")}. Refusing rather than silently treating a blank cell as 0 clicks.`,
    );
  }
  const monthlyTotals = log.searchConsole.map((r) => ({ month: r.month, clicks: r.clicks! }));
  const median = median3(monthlyTotals.map((r) => r.clicks));
  const searchConsolePass = median >= K3_SEARCH_CONSOLE_BAR;

  const missingTerms = log.keywords
    .filter((r) => r.pointValue === null && r.lowerBound === null)
    .map((r) => r.term);
  if (missingTerms.length > 0) {
    throw new Error(
      `computeK3Verdict requires a volume (range or point value) for all six closed-list terms — missing: ` +
        `${missingTerms.join(", ")}. Refusing rather than silently treating a blank cell as 0 volume.`,
    );
  }

  // Decision 0001, Addendum D, R5: "if two of the six terms return the
  // identical range, count that range once." Group range terms by their
  // exact (lower, upper) pair; a point-value term is never grouped.
  const rangeGroups = new Map<string, { value: number; terms: string[] }>();
  const contributions: K3KeywordContribution[] = [];
  for (const row of log.keywords) {
    if (row.pointValue !== null) {
      contributions.push({ term: row.term, kind: "point", value: row.pointValue, dedupedWith: [] });
      continue;
    }
    const key = `${row.lowerBound}-${row.upperBound}`;
    const existing = rangeGroups.get(key);
    if (existing) {
      existing.terms.push(row.term);
    } else {
      rangeGroups.set(key, { value: row.lowerBound!, terms: [row.term] });
    }
  }
  for (const { value, terms } of rangeGroups.values()) {
    for (const term of terms) {
      const dedupedWith = terms.filter((t) => t !== term);
      contributions.push({ term, kind: "range", value, dedupedWith });
    }
  }
  // Restore K3_KEYWORD_TERMS order for a stable, readable output.
  contributions.sort(
    (a, b) => K3_KEYWORD_TERMS.indexOf(a.term as (typeof K3_KEYWORD_TERMS)[number]) -
      K3_KEYWORD_TERMS.indexOf(b.term as (typeof K3_KEYWORD_TERMS)[number]),
  );

  let combinedVolume = 0;
  for (const { value } of rangeGroups.values()) combinedVolume += value;
  for (const row of log.keywords) {
    if (row.pointValue !== null) combinedVolume += row.pointValue;
  }
  const keywordPass = combinedVolume >= K3_KEYWORD_BAR;

  const bothMiss = !searchConsolePass && !keywordPass;
  const bothPass = searchConsolePass && keywordPass;
  const combinedBranch: K3CombinedBranch = bothMiss ? "both-miss" : bothPass ? "both-pass" : "disagree";
  const consequenceText =
    combinedBranch === "both-miss"
      ? K3_CONSEQUENCE_BOTH_MISS
      : combinedBranch === "disagree"
        ? K3_CONSEQUENCE_DISAGREE
        : K3_CONSEQUENCE_UNIVERSAL;

  return {
    generatedAt: new Date().toISOString(),
    propertyId,
    searchConsole: { monthlyTotals, median, bar: K3_SEARCH_CONSOLE_BAR, pass: searchConsolePass },
    keyword: { contributions, combinedVolume, bar: K3_KEYWORD_BAR, pass: keywordPass },
    combinedBranch,
    consequenceText,
    universalNote: K3_CONSEQUENCE_UNIVERSAL,
  };
}

export function renderK3VerdictMarkdown(result: K3VerdictResult): string {
  const lines: string[] = [];
  lines.push(`**SWC property:** ${result.propertyId}`);
  lines.push("");
  lines.push("## Search Console");
  lines.push("| Month | Organic clicks |");
  lines.push("|---|---|");
  for (const r of result.searchConsole.monthlyTotals) lines.push(`| ${r.month} | ${r.clicks} |`);
  lines.push("");
  lines.push(
    `Median: **${result.searchConsole.median}** vs bar ≥ ${result.searchConsole.bar} — ` +
      `**${result.searchConsole.pass ? "PASS" : "MISS"}**.`,
  );
  lines.push("");
  lines.push("## Keyword Planner");
  lines.push("| Term | Kind | Value | Deduped with |");
  lines.push("|---|---|---|---|");
  for (const c of result.keyword.contributions) {
    lines.push(`| ${c.term} | ${c.kind} | ${c.value} | ${c.dedupedWith.join(", ") || "—"} |`);
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
  return { outPrefix: opts.out || "k3-verdict-result" };
}

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  const log = await readK3Log();
  const result = computeK3Verdict(log);
  const { writeFile } = await import("node:fs/promises");
  await writeFile(`${args.outPrefix}.json`, `${JSON.stringify(result, null, 2)}\n`, "utf8");
  const md = renderK3VerdictMarkdown(result);
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
