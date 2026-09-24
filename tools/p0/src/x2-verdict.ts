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
 * Gate findings S1/S2, both about what counts as "the evidence" a fact can
 * cite:
 *
 *  - S1: the SHA-256 is RECOMPUTED from the stored raw bytes, and the text
 *    is RE-DERIVED from those same bytes with the identical extractor
 *    `x2-fetch` used (`evidence-extract.ts`) — never trusting the stored
 *    `text/<sha>.txt` convenience copy or the manifest's own `sha256`
 *    field, either of which is just a file anyone could edit.
 *  - S2: the evidence map is built PER TRAIL from `manifest.trails[trail]`
 *    only, and an entry whose final URL (after redirects) lands on a
 *    different host than the URL that trail's own config fetched is
 *    EXCLUDED from that trail's evidence — a same-trail same-host page is
 *    "official"; a foreign host, or another trail's evidence, is not.
 *
 * A confirmation file's `evidenceSha` that does not match evidence
 * belonging to that trail — whether because it matches NOTHING x2-fetch
 * produced, or because it matches only a DIFFERENT trail's evidence, or a
 * foreign-host redirect this trail's own evidence excludes — is a hard
 * REFUSAL (non-zero exit), never silently treated as "quote not found,"
 * since that would make a fabricated/borrowed SHA look identical to a real
 * but failed verification.
 *
 * Gate finding S5: a trail left unconfirmed while one of its sources FAILED
 * or was BLOCKED is flagged distinctly (`hasFailedSource`) and drives a
 * non-zero exit — a trail reading as a genuine KILL must not be
 * indistinguishable from one whose only rules page never loaded.
 */
import { createHash } from "node:crypto";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { collapseWhitespace } from "./text-extract.js";
import { extractEvidenceText } from "./evidence-extract.js";
import { SLATE_TRAILS } from "./slate.js";
import type { X2FetchManifest } from "./x2-fetch.js";
import { assertOutsideRepoUnlessExplicit, defaultOutsideRepoDir } from "./run-dir.js";

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

export const X2_SLATE_TRAILS = SLATE_TRAILS;
export const X2_PASS_BAR_CONFIRMED = 2;

/** One trail's own evidence — never merged with another trail's. `text ===
 * null` means the evidence EXISTS but has no extracted text (should not
 * happen for HTML/PDF with a working extractor, but can for an opaque
 * binary), so any quote citing it fails the verbatim check. */
export type TrailEvidenceMap = Map<string, { text: string | null }>;

export interface FailedSource {
  url: string;
  blocked: boolean;
  error: string;
}

export interface TrailEvidence {
  bySha: TrailEvidenceMap;
  failedSources: FailedSource[];
}

/** trail name -> that trail's own evidence (gate S2: never a flat/merged map). */
export type EvidenceByTrail = Record<string, TrailEvidence>;

/**
 * Same-site rule for X2 evidence: a host matches its configured host exactly,
 * or when the two differ only by a leading "www." (e.g. golfvancouverisland.ca
 * redirecting to www.golfvancouverisland.ca). Nothing broader: a different
 * registrable domain, or any other subdomain, is never the trail's official source.
 */
export function sameConfiguredHost(configured: string, final: string): boolean {
  const strip = (h: string) => (h.startsWith("www.") ? h.slice(4) : h);
  return configured === final || strip(configured) === strip(final);
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/**
 * Builds the per-trail evidence map from an `x2-fetch` manifest (gate S2),
 * recomputing each entry's SHA-256 from its RAW BYTES and re-deriving its
 * text with the same extractor `x2-fetch` used (gate S1/S3), via the
 * injected `readRaw` (real files for the CLI, in-memory for tests). Refuses
 * (throws) when a raw file's recomputed SHA-256 does not match the
 * manifest's recorded one — the raw bytes are the source of truth, never
 * the manifest or the stored text copy.
 */
export async function buildEvidenceByTrail(
  manifest: X2FetchManifest,
  readRaw: (relPath: string) => Promise<Buffer>,
): Promise<EvidenceByTrail> {
  const byTrail: EvidenceByTrail = {};
  for (const [trail, entries] of Object.entries(manifest.trails)) {
    const bySha: TrailEvidenceMap = new Map();
    const failedSources: FailedSource[] = [];
    for (const e of entries) {
      if (e.status !== "fetched" || !e.sha256 || !e.rawFile) {
        if (e.status === "failed") {
          failedSources.push({
            url: e.url,
            blocked: e.blocked,
            error: e.error ?? "failed (no error recorded)",
          });
        }
        continue;
      }
      const raw = await readRaw(e.rawFile);
      const recomputedSha = createHash("sha256").update(raw).digest("hex");
      if (recomputedSha !== e.sha256) {
        throw new Error(
          `Evidence raw file "${e.rawFile}" for trail "${trail}" recomputes to SHA-256 ${recomputedSha}, which ` +
            `does not match the manifest's recorded ${e.sha256} — refusing (gate finding S1: the raw bytes, ` +
            "recomputed at verdict time, are the only source of truth).",
        );
      }
      // Gate S2: only count this evidence for ITS trail when the final URL
      // (after redirects) is still on the same host that trail's own
      // config asked for.
      const configuredHost = hostOf(e.url);
      const finalHost = e.finalUrl ? hostOf(e.finalUrl) : configuredHost;
      if (!configuredHost || !finalHost || !sameConfiguredHost(configuredHost, finalHost)) {
        // Excluded — not this trail's official evidence. Reported, never dropped silently.
        failedSources.push({
          url: e.url,
          blocked: false,
          error: `redirected off the configured host (${configuredHost ?? "?"} -> ${finalHost ?? "?"}); excluded as evidence`,
        });
        continue;
      }
      const { text } = await extractEvidenceText(raw, e.contentType, e.url);
      bySha.set(recomputedSha, { text });
    }
    byTrail[trail] = { bySha, failedSources };
  }
  return byTrail;
}

/** Gate finding S8: the verdict output echoes exactly what was checked —
 * every fact's value/quote/evidenceSha and the roster size — so a reviewer
 * can see WHY a trail confirmed (or didn't) without re-opening the
 * confirmation file, and can spot a suspiciously short roster at a glance
 * next to X2.md's own research counts. */
export interface X2TrailVerdict {
  confirmed: boolean;
  reasons: string[];
  /** Gate S5: true when at least one of this trail's configured sources
   * failed or was blocked — distinguishes "genuinely unconfirmed" from
   * "unconfirmed because its evidence never loaded." */
  hasFailedSource: boolean;
  rosterSize: number;
  facts: {
    roster: X2ConfirmationRosterEntry[];
    completionUnit: X2ConfirmationFact | null;
    season: X2ConfirmationFact | null;
  };
}
export interface X2VerdictResult {
  generatedAt: string;
  perTrail: Record<string, X2TrailVerdict>;
  confirmedCount: number;
  passBar: number;
  overallVerdict: "pass" | "kill";
  /** Gate S5: true when any trail is unconfirmed while one of its sources
   * failed/was blocked — the CLI exits non-zero in that case. */
  anyUnconfirmedWithFailedSource: boolean;
}

/** Checks one `{quote, evidenceSha}` fact against THIS TRAIL's own evidence
 * map, pushing a reason on failure. THROWS (refuses the whole run) when
 * `evidenceSha` is not in this trail's own evidence — whether because it
 * doesn't exist anywhere, belongs to a different trail, or was excluded as
 * a foreign-host redirect (gate S1/S2). Returns whether the quote was found
 * verbatim (after whitespace collapsing). */
function checkQuote(
  fact: { quote: string; evidenceSha: string },
  trail: string,
  evidence: TrailEvidenceMap,
  label: string,
  reasons: string[],
): boolean {
  const entry = evidence.get(fact.evidenceSha);
  if (!entry) {
    throw new Error(
      `${label} (trail "${trail}") cites evidenceSha "${fact.evidenceSha}" which is not "${trail}"'s own ` +
        "confirmed evidence — it either does not match any evidence x2-fetch produced, belongs to a " +
        "DIFFERENT trail, or was excluded as a foreign-host redirect. Refusing to run (decision 0001 " +
        "Addendum G plus gate findings S1/S2: a cited evidence SHA must exist, be recomputed from its own " +
        "raw bytes, and belong to the trail citing it).",
    );
  }
  const text = entry.text;
  if (text === null) {
    reasons.push(
      `${label}: evidence ${fact.evidenceSha.slice(0, 12)}... has no extracted text — the quote cannot be verified.`,
    );
    return false;
  }
  const collapsedQuote = collapseWhitespace(fact.quote);
  if (!collapsedQuote || collapsedQuote.length < 12) {
    reasons.push(`${label}: quote is empty or shorter than 12 characters (gate finding N8).`);
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
  trail: string,
  evidence: TrailEvidenceMap,
  reasons: string[],
): boolean {
  // Existence of entry.evidenceSha in `evidence` is guaranteed by the
  // caller having already run checkQuote for this same entry, which throws
  // before this is reached if the SHA is unknown to this trail.
  const text = evidence.get(entry.evidenceSha)?.text ?? null;
  if (text === null) return false; // already reasoned about by checkQuote
  if (!entry.name || collapseWhitespace(entry.name).length === 0) {
    reasons.push(`Roster entry has an empty name (gate finding N8).`);
    return false;
  }
  const found = collapseWhitespace(text).includes(collapseWhitespace(entry.name));
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
  evidenceByTrail: EvidenceByTrail,
  slateTrails: readonly string[] = X2_SLATE_TRAILS,
): X2VerdictResult {
  const perTrail: Record<string, X2TrailVerdict> = {};
  for (const trail of slateTrails) {
    const reasons: string[] = [];
    const trailEvidence: TrailEvidence = evidenceByTrail[trail] ?? {
      bySha: new Map(),
      failedSources: [],
    };
    const trailConfirmation = confirmation[trail];

    let ok = Boolean(trailConfirmation);
    if (!trailConfirmation) {
      reasons.push(`No confirmation entry for trail "${trail}".`);
    } else {
      if (!trailConfirmation.roster || trailConfirmation.roster.length === 0) {
        reasons.push("Roster is empty or missing.");
        ok = false;
      } else {
        for (const rosterEntry of trailConfirmation.roster) {
          const quoteOk = checkQuote(
            rosterEntry,
            trail,
            trailEvidence.bySha,
            `Roster entry "${rosterEntry.name}"`,
            reasons,
          );
          const nameOk = checkRosterEntryName(rosterEntry, trail, trailEvidence.bySha, reasons);
          if (!quoteOk || !nameOk) ok = false;
        }
      }

      if (!trailConfirmation.completionUnit) {
        reasons.push("completionUnit is missing.");
        ok = false;
      } else if (
        !checkQuote(trailConfirmation.completionUnit, trail, trailEvidence.bySha, "completionUnit", reasons)
      ) {
        ok = false;
      }

      if (!trailConfirmation.season) {
        reasons.push("season is missing.");
        ok = false;
      } else if (!checkQuote(trailConfirmation.season, trail, trailEvidence.bySha, "season", reasons)) {
        ok = false;
      }
    }

    // Gate S5: every failed/blocked source is reported in the verdict
    // output too, not only in x2-fetch's own summary.
    for (const f of trailEvidence.failedSources) {
      reasons.push(
        `Source ${f.blocked ? "BLOCKED" : "failed"} and contributed no evidence: ${f.url} — ${f.error}`,
      );
    }

    perTrail[trail] = {
      confirmed: ok,
      reasons,
      hasFailedSource: trailEvidence.failedSources.length > 0,
      rosterSize: trailConfirmation?.roster?.length ?? 0,
      facts: {
        roster: trailConfirmation?.roster ?? [],
        completionUnit: trailConfirmation?.completionUnit ?? null,
        season: trailConfirmation?.season ?? null,
      },
    };
  }

  const confirmedCount = Object.values(perTrail).filter((t) => t.confirmed).length;
  const anyUnconfirmedWithFailedSource = Object.values(perTrail).some(
    (t) => !t.confirmed && t.hasFailedSource,
  );
  return {
    generatedAt: new Date().toISOString(),
    perTrail,
    confirmedCount,
    passBar: X2_PASS_BAR_CONFIRMED,
    overallVerdict: confirmedCount >= X2_PASS_BAR_CONFIRMED ? "pass" : "kill",
    anyUnconfirmedWithFailedSource,
  };
}

export function renderX2VerdictMarkdown(result: X2VerdictResult): string {
  const lines: string[] = [];
  lines.push("| Trail | Confirmed? | Roster size | Reasons |");
  lines.push("|---|---|---|---|");
  for (const [trail, v] of Object.entries(result.perTrail)) {
    lines.push(
      `| ${trail} | ${v.confirmed ? "Yes" : "No"} | ${v.rosterSize} | ${v.reasons.length > 0 ? v.reasons.join("<br>") : "—"} |`,
    );
  }
  lines.push("");
  for (const [trail, v] of Object.entries(result.perTrail)) {
    if (!v.confirmed && v.facts.roster.length === 0 && !v.facts.completionUnit && !v.facts.season) continue;
    lines.push(`**${trail} facts checked** (gate S8):`);
    for (const r of v.facts.roster) {
      lines.push(`- roster: "${r.name}" — quote: "${r.quote}" (evidence ${r.evidenceSha.slice(0, 12)}...)`);
    }
    if (v.facts.completionUnit) {
      lines.push(
        `- completionUnit: "${v.facts.completionUnit.value}" — quote: "${v.facts.completionUnit.quote}" (evidence ${v.facts.completionUnit.evidenceSha.slice(0, 12)}...)`,
      );
    }
    if (v.facts.season) {
      lines.push(
        `- season: "${v.facts.season.value}" — quote: "${v.facts.season.quote}" (evidence ${v.facts.season.evidenceSha.slice(0, 12)}...)`,
      );
    }
    lines.push("");
  }
  lines.push("");
  lines.push(
    `**X2 overall verdict: ${result.overallVerdict.toUpperCase()}** (${result.confirmedCount} of ${Object.keys(result.perTrail).length} confirmed, bar: ≥ ${result.passBar}).`,
  );
  if (result.anyUnconfirmedWithFailedSource) {
    lines.push("");
    lines.push(
      "**Refusing a clean pass/kill read:** at least one unconfirmed trail had a failed/blocked source " +
        "(see its Reasons above) — re-run once that source is reachable before treating this as final (gate S5).",
    );
  }
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
  const evidenceByTrail = await buildEvidenceByTrail(manifest, (rel) =>
    readFile(path.join(evidenceDir, rel)),
  );
  const result = computeX2Verdict(confirmation, evidenceByTrail);
  const outExplicit = Boolean(flags.out);
  const outPrefix = flags.out || path.join(defaultOutsideRepoDir("x2-verdict-result"), "result");
  assertOutsideRepoUnlessExplicit(path.dirname(outPrefix), outExplicit);
  await mkdir(path.dirname(outPrefix), { recursive: true });
  await writeFile(
    `${outPrefix}.json`,
    `${JSON.stringify(result, null, 2)}\n`,
    "utf8",
  );
  const md = renderX2VerdictMarkdown(result);
  await writeFile(`${outPrefix}.md`, `${md}\n`, "utf8");
  process.stdout.write(`${md}\n`);
  if (result.anyUnconfirmedWithFailedSource) {
    process.exitCode = 1;
  }
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
