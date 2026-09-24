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
import type { X2FetchManifest, X2Method } from "./x2-fetch.js";
import { defaultLedgerPath, loadLedger, type RecordedLedger } from "./x2-recorded-ledger.js";
import {
  assertOutsideRepoUnlessExplicit,
  defaultOutsideRepoDir,
} from "./run-dir.js";

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
 * binary), so any quote citing it fails the verbatim check. `method`
 * (decision 0001 Addendum J(a)) is carried straight through from the
 * `x2-fetch` manifest entry that produced this evidence, into the
 * verdict's own output (see `X2TrailVerdict.facts`) — never re-derived or
 * guessed, EXCEPT for a legacy manifest entry with no `method` field at
 * all (from before this field existed), which defaults to `"direct"` —
 * `methodDefaulted` records that this happened, so the verdict output can
 * say so rather than silently presenting a guess as fact. `recorded`
 * (Addendum J correction's first-capture-wins rule) is also carried
 * through, defaulting to `true` for a legacy entry with no such field (it
 * was the only capture that existed, so it was implicitly the recorded
 * one). */
export type TrailEvidenceMap = Map<
  string,
  {
    text: string | null;
    method: X2Method;
    methodDefaulted: boolean;
    recorded: boolean;
  }
>;

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
  opts: {
    /** Gate finding 2c: when given, `recorded` is decided by whether this
     * entry's SHA-256 is present in the LEDGER for its method — not by
     * the manifest entry's own (potentially stale or hand-edited)
     * `recorded` field. When omitted (the default, and the only option
     * available to legacy callers), `recorded` falls back to the
     * manifest entry's own field, as before. */
    ledger?: RecordedLedger;
  } = {},
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

      // Gate finding: a legacy manifest entry (from before `method`
      // existed) has no `method` field at runtime, whatever the TS type
      // claims — default it to "direct" (the only route that existed back
      // then) and remember that a default was applied, rather than
      // silently trusting `undefined` or crashing on it.
      const rawMethod = (e as { method?: unknown }).method;
      const methodDefaulted = !(
        rawMethod === "direct" ||
        rawMethod === "rendered" ||
        rawMethod === "owner-saved"
      );
      const method: X2Method = methodDefaulted
        ? "direct"
        : (rawMethod as X2Method);

      // Gate finding: cross-check method against httpStatus — an
      // "owner-saved" entry must carry the literal httpStatus "owner-saved"
      // (there was no real HTTP exchange), and a "direct"/"rendered" entry
      // must carry a NUMERIC httpStatus (a real HTTP exchange happened).
      // A mismatch means a corrupted or hand-edited manifest — refused
      // outright, the same hard-integrity style as gate S1's SHA check,
      // never silently trusted.
      if (
        method === "owner-saved"
          ? e.httpStatus !== "owner-saved"
          : typeof e.httpStatus !== "number"
      ) {
        throw new Error(
          `Evidence entry for trail "${trail}", url "${e.url}" has method "${method}" but httpStatus ` +
            `${JSON.stringify(e.httpStatus)} — these are inconsistent ("owner-saved" must pair with the ` +
            'literal httpStatus "owner-saved"; "direct"/"rendered" must pair with a numeric httpStatus). ' +
            "Refusing rather than trusting a manifest entry that contradicts itself.",
        );
      }

      // Addendum J correction's first-capture-wins rule. Gate finding 2c:
      // when a LEDGER is supplied, it is authoritative — this entry is
      // recorded only if its (recomputed) SHA is registered in the
      // ledger for its own method, full stop, regardless of what the
      // manifest entry's own `recorded` field claims. Without a ledger
      // (legacy callers), fall back to the manifest field, defaulting a
      // missing one to recorded (it was the only capture that existed).
      const recorded = opts.ledger
        ? opts.ledger.entries.some((le) => le.method === method && le.sha256 === recomputedSha)
        : (e as { recorded?: unknown }).recorded !== false;

      // Gate S2: only count this evidence for ITS trail when the final URL
      // (after redirects) is still on the same host that trail's own
      // config asked for.
      const configuredHost = hostOf(e.url);
      const finalHost = e.finalUrl ? hostOf(e.finalUrl) : configuredHost;
      if (
        !configuredHost ||
        !finalHost ||
        !sameConfiguredHost(configuredHost, finalHost)
      ) {
        // Excluded — not this trail's official evidence. Reported, never dropped silently.
        failedSources.push({
          url: e.url,
          blocked: false,
          error: `redirected off the configured host (${configuredHost ?? "?"} -> ${finalHost ?? "?"}); excluded as evidence`,
        });
        continue;
      }
      const { text } = await extractEvidenceText(raw, e.contentType, e.url);
      // Decision 0001 Addendum J: `method` is carried straight through from
      // the manifest entry, not re-derived (except the legacy default
      // above) — `x2-fetch`/`x2-ingest` are the only places that ever
      // genuinely decide it.
      //
      // Should-fix: same-SHA collision. Two entries for this trail CAN
      // share a SHA-256 (byte-identical content captured twice — e.g. an
      // `--additional` re-capture that happens to match the original
      // verbatim). A plain `Map.set` would let whichever entry is
      // iterated LAST silently overwrite the other, which could turn a
      // genuinely recorded capture into a non-recorded one (or vice
      // versa) depending on array order alone. Resolved by keying on
      // (sha, recorded) in effect: a `recorded: true` entry for a given
      // SHA is never overwritten by a `recorded: false` one for the SAME
      // sha — if ANY capture with this content was ever the recorded
      // one, citing this SHA reflects that, regardless of iteration order.
      const existingForSha = bySha.get(recomputedSha);
      if (!existingForSha || !existingForSha.recorded || recorded) {
        bySha.set(recomputedSha, { text, method, methodDefaulted, recorded });
      }
    }
    byTrail[trail] = { bySha, failedSources };
  }
  return byTrail;
}

/** Decision 0001 Addendum J: a fact's output echo, WITH the `method` of the
 * evidence its `evidenceSha` cites carried straight through — `null` only
 * when the trail has no confirmation entry for this fact at all (so there
 * is no evidenceSha to look a method up for); every fact that actually
 * cites evidence has already had that evidenceSha validated by `checkQuote`
 * before this is built, so the method lookup always succeeds. */
export interface X2FactOutput extends X2ConfirmationFact {
  method: X2Method;
}
export interface X2RosterEntryOutput extends X2ConfirmationRosterEntry {
  method: X2Method;
}

/** Gate finding S8: the verdict output echoes exactly what was checked —
 * every fact's value/quote/evidenceSha/method and the roster size — so a
 * reviewer can see WHY a trail confirmed (or didn't) without re-opening the
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
    roster: X2RosterEntryOutput[];
    completionUnit: X2FactOutput | null;
    season: X2FactOutput | null;
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
  if (!entry.recorded) {
    throw new Error(
      `${label} (trail "${trail}") cites evidenceSha "${fact.evidenceSha}", which is a NON-RECORDED capture ` +
        "(Addendum J correction's first-capture-wins rule: a later capture of the same URL, ingested with " +
        "--additional, is stored as real evidence but is never the one a confirmation may cite). Refusing " +
        "to run — cite the recorded capture's SHA instead.",
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
    reasons.push(
      `${label}: quote is empty or shorter than 12 characters (gate finding N8).`,
    );
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

/** Decision 0001 Addendum J: looks up the `method` of the evidence a fact
 * cites, for echoing in the verdict output (`X2TrailVerdict.facts`). Only
 * ever called for a fact that `checkQuote` has already run over — which
 * throws (refuses the whole run) if `evidenceSha` is not present in this
 * trail's own evidence — so the lookup below is safe by construction; the
 * thrown error here is unreachable in practice and exists only so a future
 * change that stops calling this after `checkQuote` fails loudly instead of
 * silently mislabeling a method. Gate finding: when the cited evidence's
 * `method` was DEFAULTED (a legacy manifest entry from before this field
 * existed), that is recorded into `reasons` — informational, not a
 * failure, but never silent, so a reader can see a value was assumed
 * rather than read from the manifest. */
function factMethod(
  evidence: TrailEvidenceMap,
  evidenceSha: string,
  label: string,
  reasons: string[],
): X2Method {
  const entry = evidence.get(evidenceSha);
  if (!entry) {
    throw new Error(
      `internal: evidenceSha "${evidenceSha}" missing from this trail's evidence while building the facts ` +
        "output — this should be unreachable, since checkQuote already validates evidenceSha first.",
    );
  }
  if (entry.methodDefaulted) {
    reasons.push(
      `${label}: evidence ${evidenceSha.slice(0, 12)}... has no \`method\` field (legacy manifest) — ` +
        'defaulted to "direct".',
    );
  }
  return entry.method;
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
          const nameOk = checkRosterEntryName(
            rosterEntry,
            trail,
            trailEvidence.bySha,
            reasons,
          );
          if (!quoteOk || !nameOk) ok = false;
        }
      }

      if (!trailConfirmation.completionUnit) {
        reasons.push("completionUnit is missing.");
        ok = false;
      } else if (
        !checkQuote(
          trailConfirmation.completionUnit,
          trail,
          trailEvidence.bySha,
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
        !checkQuote(
          trailConfirmation.season,
          trail,
          trailEvidence.bySha,
          "season",
          reasons,
        )
      ) {
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
        roster: (trailConfirmation?.roster ?? []).map((r) => ({
          ...r,
          method: factMethod(
            trailEvidence.bySha,
            r.evidenceSha,
            `Roster entry "${r.name}"`,
            reasons,
          ),
        })),
        completionUnit: trailConfirmation?.completionUnit
          ? {
              ...trailConfirmation.completionUnit,
              method: factMethod(
                trailEvidence.bySha,
                trailConfirmation.completionUnit.evidenceSha,
                "completionUnit",
                reasons,
              ),
            }
          : null,
        season: trailConfirmation?.season
          ? {
              ...trailConfirmation.season,
              method: factMethod(
                trailEvidence.bySha,
                trailConfirmation.season.evidenceSha,
                "season",
                reasons,
              ),
            }
          : null,
      },
    };
  }

  const confirmedCount = Object.values(perTrail).filter(
    (t) => t.confirmed,
  ).length;
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
    if (
      !v.confirmed &&
      v.facts.roster.length === 0 &&
      !v.facts.completionUnit &&
      !v.facts.season
    )
      continue;
    lines.push(`**${trail} facts checked** (gate S8):`);
    for (const r of v.facts.roster) {
      lines.push(
        `- roster: "${r.name}" — quote: "${r.quote}" (evidence ${r.evidenceSha.slice(0, 12)}..., method: ${r.method})`,
      );
    }
    if (v.facts.completionUnit) {
      lines.push(
        `- completionUnit: "${v.facts.completionUnit.value}" — quote: "${v.facts.completionUnit.quote}" (evidence ${v.facts.completionUnit.evidenceSha.slice(0, 12)}..., method: ${v.facts.completionUnit.method})`,
      );
    }
    if (v.facts.season) {
      lines.push(
        `- season: "${v.facts.season.value}" — quote: "${v.facts.season.quote}" (evidence ${v.facts.season.evidenceSha.slice(0, 12)}..., method: ${v.facts.season.method})`,
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
      "Usage: node dist/x2-verdict.js --evidence-dir <dir> --confirmation <file.json> [--out <prefix>] " +
        "[--ledger <path>]",
    );
  }
  const manifest = JSON.parse(
    await readFile(path.join(evidenceDir, "manifest.json"), "utf8"),
  ) as X2FetchManifest;
  const confirmation = JSON.parse(
    await readFile(confirmationPath, "utf8"),
  ) as X2ConfirmationFile;
  // Gate finding 2c: when a ledger path is given (default:
  // `<evidence-dir>/recorded-ledger.json`, same default `x2-fetch`/
  // `x2-ingest` use — pass `--ledger` explicitly when the recorded
  // captures for this trail set live in a SHARED ledger outside this one
  // evidence dir), it is authoritative for `recorded`, not each entry's
  // own field.
  const ledgerPath = flags.ledger || defaultLedgerPath(evidenceDir);
  const ledger = await loadLedger(ledgerPath);
  const evidenceByTrail = await buildEvidenceByTrail(
    manifest,
    (rel) => readFile(path.join(evidenceDir, rel)),
    { ledger },
  );
  const result = computeX2Verdict(confirmation, evidenceByTrail);
  const outExplicit = Boolean(flags.out);
  const outPrefix =
    flags.out ||
    path.join(defaultOutsideRepoDir("x2-verdict-result"), "result");
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
