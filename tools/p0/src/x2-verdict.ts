#!/usr/bin/env node
/**
 * `x2-verdict` — the X2 pass/kill verdict (build plan §10 P0; `docs/p0/
 * X2.md`) from `x2-fetch`'s stored evidence plus a human-written
 * confirmation file. Implements decision 0001 Addendum G's "X2 'confirmed
 * from a direct fetch'" literally, not reinterpreted: a trail counts as
 * confirmed only when its roster, `completionUnit` and season window are
 * ALL backed by quotes that appear VERBATIM (after whitespace collapsing)
 * in the text of the evidence file cited by each fact's `evidenceSha`, and
 * every roster entry's name also appears in the evidence text it cites. X2
 * passes when ≥ 2 of the 3 slate trails are confirmed (X2.md's pass bar,
 * unchanged).
 *
 * A confirmation file's `evidenceSha` that does not match ANY evidence
 * `x2-fetch` actually produced is a hard REFUSAL (non-zero exit) — it is
 * never silently treated as "quote not found," since that would make a
 * fabricated SHA look identical to a real but failed verification.
 */
import { readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { collapseWhitespace } from "./text-extract.js";
import type { X2FetchManifest } from "./x2-fetch.js";

export interface X2ConfirmationRosterEntry {
  name: string;
  quote: string;
  evidenceSha: string;
}
export interface X2ConfirmationFact {
  value: string;
  quote: string;
  evidenceSha: string;
}
export interface X2TrailConfirmation {
  roster: X2ConfirmationRosterEntry[];
  completionUnit: X2ConfirmationFact;
  season: X2ConfirmationFact;
}
/** trail name -> that trail's confirmation entry. */
export type X2ConfirmationFile = Record<string, X2TrailConfirmation>;

export const X2_SLATE_TRAILS = ["TN", "VI", "RTJ"] as const;
export const X2_PASS_BAR_CONFIRMED = 2;

/**
 * Evidence text, keyed by SHA-256. `null` means the evidence EXISTS
 * (`x2-fetch` produced it) but has no extracted text (a PDF, marked
 * `"manual"` per Addendum G's "do not pretend"), so any quote citing it
 * fails the verbatim check. An ABSENT key means no evidence with that SHA
 * exists at all — the refusal case (see `computeX2Verdict`).
 */
export type EvidenceTextMap = Map<string, string | null>;

/** Builds the evidence text map from an `x2-fetch` manifest, reading each
 * `"fetched"` entry's `textFile` (when it has one) via the injected
 * `readText`. Injected so tests can supply an in-memory map instead of real
 * files, and so the CLI can point it at the real evidence dir. */
export async function buildEvidenceTextMap(
  manifest: X2FetchManifest,
  readText: (relPath: string) => Promise<string>,
): Promise<EvidenceTextMap> {
  const map: EvidenceTextMap = new Map();
  for (const entries of Object.values(manifest.trails)) {
    for (const e of entries) {
      if (e.status !== "fetched" || !e.sha256) continue;
      map.set(e.sha256, e.textFile ? await readText(e.textFile) : null);
    }
  }
  return map;
}

export interface X2TrailVerdict {
  confirmed: boolean;
  reasons: string[];
}
export interface X2VerdictResult {
  generatedAt: string;
  perTrail: Record<string, X2TrailVerdict>;
  confirmedCount: number;
  passBar: number;
  overallVerdict: "pass" | "kill";
}

/** Checks one `{quote, evidenceSha}` fact against the evidence map, pushing
 * a reason on failure. THROWS (refuses the whole run) when `evidenceSha`
 * matches no evidence at all — see module doc. Returns whether the quote
 * was found verbatim (after whitespace collapsing). */
function checkQuote(
  fact: { quote: string; evidenceSha: string },
  evidence: EvidenceTextMap,
  label: string,
  reasons: string[],
): boolean {
  if (!evidence.has(fact.evidenceSha)) {
    throw new Error(
      `${label} cites evidenceSha "${fact.evidenceSha}" which does not match any evidence x2-fetch produced — ` +
        "refusing to run (decision 0001 Addendum G: a cited evidence SHA must exist).",
    );
  }
  const text = evidence.get(fact.evidenceSha) ?? null;
  if (text === null) {
    reasons.push(
      `${label}: evidence ${fact.evidenceSha.slice(0, 12)}... has no extracted text (manual PDF extraction — ` +
        `Addendum G "do not pretend") — the quote cannot be verified.`,
    );
    return false;
  }
  const collapsedQuote = collapseWhitespace(fact.quote);
  if (!collapsedQuote) {
    reasons.push(`${label}: quote is empty.`);
    return false;
  }
  if (!collapseWhitespace(text).includes(collapsedQuote)) {
    reasons.push(
      `${label}: quote does not appear verbatim (after whitespace collapsing) in evidence ` +
        `${fact.evidenceSha.slice(0, 12)}....`,
    );
    return false;
  }
  return true;
}

function checkRosterEntryName(
  entry: X2ConfirmationRosterEntry,
  evidence: EvidenceTextMap,
  reasons: string[],
): boolean {
  // Existence of entry.evidenceSha in `evidence` is guaranteed by the
  // caller having already run checkQuote for this same entry, which throws
  // before this is reached if the SHA is unknown.
  const text = evidence.get(entry.evidenceSha) ?? null;
  if (text === null) return false; // already reasoned about by checkQuote
  const found = collapseWhitespace(text).includes(
    collapseWhitespace(entry.name),
  );
  if (!found) {
    reasons.push(
      `Roster entry "${entry.name}": name does not appear in evidence ${entry.evidenceSha.slice(0, 12)}....`,
    );
  }
  return found;
}

/** Decision 0001 Addendum G, applied literally. `slateTrails` defaults to
 * the pilot slate (TN/VI/RTJ); pass it explicitly to evaluate a swapped-in
 * reserve trail instead. */
export function computeX2Verdict(
  confirmation: X2ConfirmationFile,
  evidence: EvidenceTextMap,
  slateTrails: readonly string[] = X2_SLATE_TRAILS,
): X2VerdictResult {
  const perTrail: Record<string, X2TrailVerdict> = {};
  for (const trail of slateTrails) {
    const reasons: string[] = [];
    const trailConfirmation = confirmation[trail];
    if (!trailConfirmation) {
      perTrail[trail] = {
        confirmed: false,
        reasons: [`No confirmation entry for trail "${trail}".`],
      };
      continue;
    }

    let ok = true;

    if (!trailConfirmation.roster || trailConfirmation.roster.length === 0) {
      reasons.push("Roster is empty or missing.");
      ok = false;
    } else {
      for (const rosterEntry of trailConfirmation.roster) {
        const quoteOk = checkQuote(
          rosterEntry,
          evidence,
          `Roster entry "${rosterEntry.name}"`,
          reasons,
        );
        const nameOk = checkRosterEntryName(rosterEntry, evidence, reasons);
        if (!quoteOk || !nameOk) ok = false;
      }
    }

    if (!trailConfirmation.completionUnit) {
      reasons.push("completionUnit is missing.");
      ok = false;
    } else if (
      !checkQuote(
        trailConfirmation.completionUnit,
        evidence,
        "completionUnit",
        reasons,
      )
    ) {
      ok = false;
    }

    if (!trailConfirmation.season) {
      reasons.push("season is missing.");
      ok = false;
    } else if (
      !checkQuote(trailConfirmation.season, evidence, "season", reasons)
    ) {
      ok = false;
    }

    perTrail[trail] = { confirmed: ok, reasons };
  }

  const confirmedCount = Object.values(perTrail).filter(
    (t) => t.confirmed,
  ).length;
  return {
    generatedAt: new Date().toISOString(),
    perTrail,
    confirmedCount,
    passBar: X2_PASS_BAR_CONFIRMED,
    overallVerdict:
      confirmedCount >= X2_PASS_BAR_CONFIRMED ? "pass" : "kill",
  };
}

export function renderX2VerdictMarkdown(result: X2VerdictResult): string {
  const lines: string[] = [];
  lines.push("| Trail | Confirmed? | Reasons |");
  lines.push("|---|---|---|");
  for (const [trail, v] of Object.entries(result.perTrail)) {
    lines.push(
      `| ${trail} | ${v.confirmed ? "Yes" : "No"} | ${v.reasons.length > 0 ? v.reasons.join("<br>") : "—"} |`,
    );
  }
  lines.push("");
  lines.push(
    `**X2 overall verdict: ${result.overallVerdict.toUpperCase()}** (${result.confirmedCount} of ${Object.keys(result.perTrail).length} confirmed, bar: ≥ ${result.passBar}).`,
  );
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseFlags(argv: string[]): Record<string, string> {
  const flags: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg && arg.startsWith("--")) {
      flags[arg.slice(2)] = argv[i + 1] ?? "";
      i += 1;
    }
  }
  return flags;
}

async function main(argv: string[]): Promise<void> {
  const flags = parseFlags(argv);
  const evidenceDir = flags["evidence-dir"];
  const confirmationPath = flags.confirmation;
  if (!evidenceDir || !confirmationPath) {
    throw new Error(
      "Usage: node dist/x2-verdict.js --evidence-dir <dir> --confirmation <file.json> [--out <prefix>]",
    );
  }
  const manifest = JSON.parse(
    await readFile(path.join(evidenceDir, "manifest.json"), "utf8"),
  ) as X2FetchManifest;
  const confirmation = JSON.parse(
    await readFile(confirmationPath, "utf8"),
  ) as X2ConfirmationFile;
  const evidence = await buildEvidenceTextMap(manifest, (rel) =>
    readFile(path.join(evidenceDir, rel), "utf8"),
  );
  const result = computeX2Verdict(confirmation, evidence);
  const outPrefix = flags.out || "x2-verdict-result";
  await writeFile(
    `${outPrefix}.json`,
    `${JSON.stringify(result, null, 2)}\n`,
    "utf8",
  );
  const md = renderX2VerdictMarkdown(result);
  await writeFile(`${outPrefix}.md`, `${md}\n`, "utf8");
  process.stdout.write(`${md}\n`);
}

async function isMainModule(): Promise<boolean> {
  if (!process.argv[1]) return false;
  try {
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
    process.stderr.write(`x2-verdict: ${message}\n`);
    process.exitCode = 1;
  });
}
