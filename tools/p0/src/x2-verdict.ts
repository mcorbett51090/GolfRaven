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
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { collapseWhitespace } from "./text-extract.js";
import { extractEvidenceText } from "./evidence-extract.js";
import { SLATE_TRAILS } from "./slate.js";
import type { X2FetchManifest, X2Method } from "./x2-fetch.js";
import {
  loadLedger,
  normalizeUrlForFirstCapture,
  type RecordedLedger,
} from "./x2-recorded-ledger.js";
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

/**
 * Gate finding 4: the owner-saved rule was not enforced. Every fact whose
 * evidence has `method: "owner-saved"` rests on the owner's WORD alone —
 * nothing about ingestion verifies the bytes ever touched the stated URL
 * (the Addendum J correction's own point). Such a fact is
 * "owner-attested, uncorroborated" by default and does NOT count toward
 * confirmation UNLESS ONE of these is supplied, keyed by the SAME
 * `evidenceSha` the fact cites:
 *
 *  - `{ type: "wayback", snapshotUrl, snapshotSha256, snapshotText }` — a
 *    web.archive.org snapshot of the SAME stated URL. `snapshotText` is
 *    the text a human (or a future live-render helper) actually extracted
 *    from that snapshot — `x2-verdict` checks the SAME quote against it,
 *    with the SAME verbatim-after-whitespace-collapsing rule.
 *  - `{ type: "acceptance", id, acceptedBy: "Matt", date }` — Matt's own
 *    dated, written acceptance that this specific owner-attested fact
 *    counts without a Wayback snapshot (the Addendum J correction's own
 *    escape hatch for a page that was never archived).
 *
 * Gate finding 3 (re-gate): the OLD `wayback` shape carried its own
 * `snapshotText` inline — free text a human (or a compromised agent)
 * typed directly into this JSON file, never checked against anything
 * real. `x2-verdict` trusted it verbatim, which is a forgery hole exactly
 * the size of "type the quote you want to win into a text field." Fixed
 * by removing `snapshotText` from the file schema entirely: a `wayback`
 * record now cites ONLY `snapshotUrl` + `snapshotSha256` (+ `rawFile`,
 * where the bytes those hashed to are actually stored) — bytes that
 * `x2-corroborate-wayback.ts` ACTUALLY FETCHED from web.archive.org
 * itself, never hand-typed. `computeX2Verdict` never reads `snapshotText`
 * from the file at all any more; it takes an already-RESOLVED corroboration
 * (`X2ResolvedCorroboration`, below) that the CLI builds by re-reading and
 * re-verifying those stored bytes BEFORE this function ever runs — this
 * function stays a pure, synchronous function (no network, no filesystem),
 * it just no longer trusts a free-text field as its input.
 *
 * Gate finding 3 (re-gate): an `acceptance` record now also carries an
 * `id` — the CLI's resolution pass greps `docs/p0/X2.md`'s own `## Log`
 * section for a row naming BOTH this `id` and `date`, so "Matt accepted
 * this" is not just a claim inside a corroboration JSON file nobody else
 * ever has to write anywhere else — it has to also show up in the one
 * place this project's own decision trail already lives, checkable by
 * anyone reading X2.md, not just by trusting the corroboration file.
 */
export interface X2WaybackCorroboration {
  type: "wayback";
  /** The `https://web.archive.org/web/<14-digit timestamp>/<url>` this
   * came from — for a human to click and independently check. */
  snapshotUrl: string;
  /** SHA-256 `x2-corroborate-wayback.ts` computed over the bytes it
   * actually fetched — the thing `x2-verdict` re-verifies. */
  snapshotSha256: string;
  /** Path (relative to the evidence dir `x2-verdict --evidence-dir`
   * reads) to the raw bytes stored at `snapshotSha256`. */
  rawFile: string;
}
export interface X2AcceptanceCorroboration {
  type: "acceptance";
  /** A short, stable identifier for this specific acceptance — the same
   * string the CLI greps for, alongside `date`, in `docs/p0/X2.md`'s
   * `## Log` section (e.g. `"TN-completionUnit-2026-09-24"`). */
  id: string;
  /** Must be the literal string `"Matt"` — checked exactly, not just
   * truthy (gate finding 3, re-gate: any other value refuses). */
  acceptedBy: string;
  /** `YYYY-MM-DD`. */
  date: string;
}
export type X2CorroborationRecord = X2WaybackCorroboration | X2AcceptanceCorroboration;
/** trail name -> evidenceSha -> its corroboration record, if any. */
export type X2CorroborationFile = Record<string, Record<string, X2CorroborationRecord>>;

/**
 * The corroboration data ACTUALLY TRUSTED, after the CLI's own
 * verification pass — never derived from the raw `X2CorroborationFile`
 * directly. Keyed by `"<trail>:<evidenceSha>"` (matching how
 * `computeX2Verdict` already looks a fact's corroboration record up).
 */
export interface ResolvedCorroborationEntry {
  /** `wayback` records only: `false` when the stored raw bytes' recomputed
   * SHA-256 did not match `snapshotSha256` (tampered/missing evidence) —
   * `waybackText` is only meaningful when this is `true`. */
  waybackVerified?: boolean;
  /** `wayback` records only: text re-derived from the VERIFIED raw bytes,
   * with the SAME extractor every other evidence route uses. `null` when
   * extraction found no text, or verification failed. */
  waybackText?: string | null;
  /** `acceptance` records only: `true` only when a row naming both this
   * record's `id` and `date` was found in `docs/p0/X2.md`'s `## Log`
   * section. */
  acceptanceLogged?: boolean;
}
export type X2ResolvedCorroboration = Map<string, ResolvedCorroborationEntry>;

/** The key `X2ResolvedCorroboration` is keyed by, for one fact. */
export function corroborationResolutionKey(trail: string, evidenceSha: string): string {
  return `${trail}:${evidenceSha}`;
}

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
    /** Gate finding 2c (re-gate): REQUIRED — `recorded` is decided by
     * whether this entry's (SHA-256, method, normalised URL) triple is
     * registered in the LEDGER, never by the manifest entry's own
     * (potentially stale or hand-edited) `recorded` field. The legacy
     * "trust the manifest's own field when no ledger is given" fallback
     * was REMOVED — that fallback was itself a bypass of finding 2c
     * (any caller that omitted a ledger silently got the exact
     * hard-coded-`recorded:true` trust the ledger exists to replace). */
    ledger: RecordedLedger;
    /** Gate finding, should-fix (re-gate): the rendered route was adopted
     * (Addendum J(a)(i), and its own correction) for VI's specific
     * static-HTML-has-no-body-text problem — it was never part of Matt's
     * choice for any other trail. Defaults to `["VI"]`; a `"rendered"`
     * entry for a trail NOT on this list refuses the whole run outright
     * (the same hard-integrity style as the SHA/method checks below),
     * rather than silently accepting rendered evidence for a trail whose
     * owner never chose that route. */
    renderedAllowedTrails?: readonly string[];
  },
): Promise<EvidenceByTrail> {
  const renderedAllowedTrails = opts.renderedAllowedTrails ?? ["VI"];
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

      // Gate finding, should-fix (re-gate): the rendered route is
      // per-trail-opted-into, not blanket-available — see this
      // parameter's own doc above.
      if (method === "rendered" && !renderedAllowedTrails.includes(trail)) {
        throw new Error(
          `Evidence entry for trail "${trail}", url "${e.url}" has method "rendered", but "${trail}" is not ` +
            `on the rendered-route allow-list (${renderedAllowedTrails.join(", ") || "(none)"}) — the ` +
            "rendered route was adopted for VI's own static-HTML-has-no-body-text problem, never as a " +
            "blanket option for every trail; refusing rather than silently accepting rendered evidence a " +
            "trail's owner never chose (should-fix, re-gate).",
        );
      }

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

      // Addendum J correction's first-capture-wins rule. The ledger is
      // authoritative — this entry is recorded only if a ledger row
      // matches it on ALL THREE of method, (recomputed) SHA, AND
      // normalised URL, regardless of what the manifest entry's own
      // `recorded` field claims. Gate finding 2b (re-gate): matching on
      // method+SHA alone was found exploitable — a hand-edited ledger row
      // with the RIGHT sha256/method but a bogus/unrelated
      // `normalizedUrl` (one that was never actually checked) would
      // still match and wrongly mark a non-recorded capture as recorded.
      // Requiring the manifest entry's OWN normalised URL to equal the
      // ledger row's `normalizedUrl` closes that: a ledger row can only
      // vouch for the exact URL it claims to be about.
      const entryNormalizedUrl = (() => {
        try {
          return normalizeUrlForFirstCapture(e.url);
        } catch {
          return null;
        }
      })();
      const recorded = opts.ledger.entries.some(
        (le) =>
          le.method === method &&
          le.sha256 === recomputedSha &&
          le.normalizedUrl === entryNormalizedUrl,
      );

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
/** Gate finding 4: names the corroboration record backing an owner-saved
 * fact (or its absence) in the output — never left implicit. `null` for a
 * `direct`/`rendered` fact, where corroboration does not apply. */
export interface X2FactOutput extends X2ConfirmationFact {
  method: X2Method;
  corroboration: string | null;
}
export interface X2RosterEntryOutput extends X2ConfirmationRosterEntry {
  method: X2Method;
  corroboration: string | null;
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

/**
 * Gate finding 4: an owner-saved fact does not count toward confirmation
 * unless corroborated (or Matt has accepted it uncorroborated, in
 * writing). Only ever called for a fact whose `checkQuote` already
 * succeeded, so `evidence.get(evidenceSha)` is guaranteed to exist. A
 * `direct`/`rendered` fact needs no corroboration and always passes here
 * with a `null` summary (nothing to name).
 */
function checkOwnerSavedCorroboration(
  trail: string,
  evidenceSha: string,
  quote: string,
  evidence: TrailEvidenceMap,
  trailCorroboration: Record<string, X2CorroborationRecord>,
  resolved: X2ResolvedCorroboration,
  label: string,
  reasons: string[],
): { ok: boolean; summary: string | null } {
  const entry = evidence.get(evidenceSha);
  const method = entry?.method;
  if (method !== "owner-saved") {
    return { ok: true, summary: null };
  }
  const record = trailCorroboration[evidenceSha];
  if (!record) {
    reasons.push(
      `${label}: owner-attested, UNCORROBORATED (evidence ${evidenceSha.slice(0, 12)}... is an owner-saved ` +
        "capture with no corroboration record supplied — a Wayback snapshot or Matt's dated acceptance is " +
        "required for an owner-saved fact to count; Addendum J correction).",
    );
    return { ok: false, summary: "owner-attested, uncorroborated" };
  }
  const resolution = resolved.get(corroborationResolutionKey(trail, evidenceSha));
  if (record.type === "acceptance") {
    // Gate finding 3 (re-gate): `acceptedBy` must be EXACTLY "Matt", and
    // the record's `id`+`date` must show up in docs/p0/X2.md's own Log —
    // never just trusted because the JSON file says so.
    if (record.acceptedBy !== "Matt") {
      reasons.push(
        `${label}: owner-attested, acceptance record rejected — acceptedBy must be exactly "Matt", got ` +
          `${JSON.stringify(record.acceptedBy)} (gate finding 3, re-gate).`,
      );
      return { ok: false, summary: "owner-attested, acceptance record rejected (acceptedBy is not Matt)" };
    }
    if (!resolution?.acceptanceLogged) {
      reasons.push(
        `${label}: owner-attested, acceptance record cited (id "${record.id}", ${record.date}) but no row ` +
          'naming both was found in docs/p0/X2.md\'s "## Log" section — an acceptance not logged where this ' +
          "project's own decision trail lives does not count (gate finding 3, re-gate).",
      );
      return {
        ok: false,
        summary: `owner-attested, acceptance NOT FOUND in X2.md's Log (id "${record.id}")`,
      };
    }
    const summary = `owner-attested, accepted by Matt on ${record.date} (logged in X2.md, id "${record.id}")`;
    reasons.push(`${label}: ${summary}.`);
    return { ok: true, summary };
  }
  // record.type === "wayback" — gate finding 3 (re-gate): the record
  // cites only a SHA now; `resolution.waybackText` is what the CLI's own
  // re-verification pass derived from the REAL fetched bytes, never
  // free text from the file itself.
  if (!resolution?.waybackVerified) {
    reasons.push(
      `${label}: owner-attested, Wayback corroboration record cited (${record.snapshotUrl}) but its stored ` +
        `evidence (sha256 ${record.snapshotSha256.slice(0, 12)}...) could not be verified — the raw bytes at ` +
        "its rawFile did not recompute to the cited SHA, or could not be read — corroboration fails (gate " +
        "finding 3, re-gate).",
    );
    return { ok: false, summary: `owner-attested, Wayback corroboration UNVERIFIABLE (${record.snapshotUrl})` };
  }
  const collapsedQuote = collapseWhitespace(quote);
  const snapshotText = resolution.waybackText ?? "";
  const foundInSnapshot = collapseWhitespace(snapshotText).includes(collapsedQuote);
  if (!foundInSnapshot) {
    reasons.push(
      `${label}: owner-attested, corroboration record cited (Wayback snapshot ${record.snapshotUrl}) but the ` +
        "quote does NOT appear verbatim in the snapshot's own (re-derived) text — corroboration fails, this " +
        "fact does not count.",
    );
    return { ok: false, summary: `owner-attested, Wayback corroboration FAILED (${record.snapshotUrl})` };
  }
  const summary = `owner-attested, corroborated by Wayback snapshot ${record.snapshotUrl} (sha256 ${record.snapshotSha256.slice(0, 12)}...)`;
  reasons.push(`${label}: ${summary}.`);
  return { ok: true, summary };
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
 * reserve trail instead. `corroboration` (gate finding 4, default `{}` —
 * an empty one, under which EVERY owner-saved fact is uncorroborated and
 * so cannot confirm a trail on its own) supplies the Wayback-snapshot or
 * Matt's-acceptance records an owner-saved fact needs to count. */
export function computeX2Verdict(
  confirmation: X2ConfirmationFile,
  evidenceByTrail: EvidenceByTrail,
  slateTrails: readonly string[] = X2_SLATE_TRAILS,
  corroboration: X2CorroborationFile = {},
  /** Gate finding 3 (re-gate): pre-resolved, pre-verified corroboration
   * data — see `X2ResolvedCorroboration`'s own doc. This function stays
   * pure/synchronous; resolving a `wayback` record's real text (reading
   * files, recomputing a SHA) and an `acceptance` record's X2.md-logged
   * status (reading `docs/p0/X2.md`) both happen BEFORE this is called,
   * never inside it. Omitted (the default) means every corroboration
   * record resolves to "unverified" — the SAFE default: an owner-saved
   * fact citing a corroboration record that was never actually verified
   * does NOT count, rather than silently passing. */
  resolvedCorroboration: X2ResolvedCorroboration = new Map(),
): X2VerdictResult {
  const perTrail: Record<string, X2TrailVerdict> = {};
  for (const trail of slateTrails) {
    const reasons: string[] = [];
    const trailEvidence: TrailEvidence = evidenceByTrail[trail] ?? {
      bySha: new Map(),
      failedSources: [],
    };
    const trailConfirmation = confirmation[trail];
    const trailCorroboration = corroboration[trail] ?? {};

    // Gate finding 4: corroboration summaries are computed ONCE per fact,
    // here, and reused both for the confirmed/not decision below AND for
    // the `facts` output — never re-derived (and never re-reasoned-about,
    // which would duplicate `reasons` entries).
    const rosterCorroboration = new Map<string, string | null>();
    let completionUnitCorroboration: string | null = null;
    let seasonCorroboration: string | null = null;

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
          let corroborationOk = true;
          if (quoteOk) {
            const result = checkOwnerSavedCorroboration(
              trail,
              rosterEntry.evidenceSha,
              rosterEntry.quote,
              trailEvidence.bySha,
              trailCorroboration,
              resolvedCorroboration,
              `Roster entry "${rosterEntry.name}"`,
              reasons,
            );
            corroborationOk = result.ok;
            rosterCorroboration.set(rosterEntry.name, result.summary);
          }
          if (!quoteOk || !nameOk || !corroborationOk) ok = false;
        }
      }

      if (!trailConfirmation.completionUnit) {
        reasons.push("completionUnit is missing.");
        ok = false;
      } else {
        const quoteOk = checkQuote(
          trailConfirmation.completionUnit,
          trail,
          trailEvidence.bySha,
          "completionUnit",
          reasons,
        );
        let corroborationOk = true;
        if (quoteOk) {
          const result = checkOwnerSavedCorroboration(
            trail,
            trailConfirmation.completionUnit.evidenceSha,
            trailConfirmation.completionUnit.quote,
            trailEvidence.bySha,
            trailCorroboration,
            resolvedCorroboration,
            "completionUnit",
            reasons,
          );
          corroborationOk = result.ok;
          completionUnitCorroboration = result.summary;
        }
        if (!quoteOk || !corroborationOk) ok = false;
      }

      if (!trailConfirmation.season) {
        reasons.push("season is missing.");
        ok = false;
      } else {
        const quoteOk = checkQuote(
          trailConfirmation.season,
          trail,
          trailEvidence.bySha,
          "season",
          reasons,
        );
        let corroborationOk = true;
        if (quoteOk) {
          const result = checkOwnerSavedCorroboration(
            trail,
            trailConfirmation.season.evidenceSha,
            trailConfirmation.season.quote,
            trailEvidence.bySha,
            trailCorroboration,
            resolvedCorroboration,
            "season",
            reasons,
          );
          corroborationOk = result.ok;
          seasonCorroboration = result.summary;
        }
        if (!quoteOk || !corroborationOk) ok = false;
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
          corroboration: rosterCorroboration.get(r.name) ?? null,
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
              corroboration: completionUnitCorroboration,
            }
          : null,
        season: trailConfirmation?.season
          ? {
              ...trailConfirmation.season,
              corroboration: seasonCorroboration,
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
        `- roster: "${r.name}" — quote: "${r.quote}" (evidence ${r.evidenceSha.slice(0, 12)}..., method: ${r.method}${r.corroboration ? `, corroboration: ${r.corroboration}` : ""})`,
      );
    }
    if (v.facts.completionUnit) {
      lines.push(
        `- completionUnit: "${v.facts.completionUnit.value}" — quote: "${v.facts.completionUnit.quote}" (evidence ${v.facts.completionUnit.evidenceSha.slice(0, 12)}..., method: ${v.facts.completionUnit.method}${v.facts.completionUnit.corroboration ? `, corroboration: ${v.facts.completionUnit.corroboration}` : ""})`,
      );
    }
    if (v.facts.season) {
      lines.push(
        `- season: "${v.facts.season.value}" — quote: "${v.facts.season.quote}" (evidence ${v.facts.season.evidenceSha.slice(0, 12)}..., method: ${v.facts.season.method}${v.facts.season.corroboration ? `, corroboration: ${v.facts.season.corroboration}` : ""})`,
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

/**
 * Gate finding 3 (re-gate): the verification pass that makes a
 * `X2CorroborationFile` trustworthy — run ONCE, before `computeX2Verdict`,
 * never inside it (keeping that function pure/synchronous). For every
 * `wayback` record, re-reads the raw bytes its `rawFile` names (via the
 * SAME `readRaw` the caller already has for trail evidence — a wayback
 * record's bytes live in the same evidence dir), recomputes the SHA-256,
 * and — only if it matches `snapshotSha256` — re-derives the text with
 * the SAME extractor every other evidence route uses. For every
 * `acceptance` record, checks `x2MdLogText` (the text of `docs/p0/X2.md`'s
 * own `## Log` section — the caller reads the file once and passes its
 * text in, so this function itself does no I/O either) for a line naming
 * both the record's `id` and `date`. Never throws on a per-record
 * failure — a record that fails resolution just resolves to
 * "unverified"/"not logged", which `checkOwnerSavedCorroboration` then
 * correctly refuses to count.
 */
export async function resolveCorroboration(
  corroboration: X2CorroborationFile,
  readRaw: (relPath: string) => Promise<Buffer>,
  x2MdLogText: string | null,
): Promise<X2ResolvedCorroboration> {
  const resolved: X2ResolvedCorroboration = new Map();
  for (const [trail, trailRecords] of Object.entries(corroboration)) {
    for (const [evidenceSha, record] of Object.entries(trailRecords)) {
      const key = corroborationResolutionKey(trail, evidenceSha);
      if (record.type === "wayback") {
        try {
          const raw = await readRaw(record.rawFile);
          const recomputed = createHash("sha256").update(raw).digest("hex");
          if (recomputed !== record.snapshotSha256) {
            resolved.set(key, { waybackVerified: false });
            continue;
          }
          const { text } = await extractEvidenceText(raw, "text/html", record.snapshotUrl);
          resolved.set(key, { waybackVerified: true, waybackText: text });
        } catch {
          resolved.set(key, { waybackVerified: false });
        }
      } else {
        // record.type === "acceptance"
        const logged =
          x2MdLogText !== null &&
          x2MdLogText
            .split("\n")
            .some((line) => line.includes(record.id) && line.includes(record.date));
        resolved.set(key, { acceptanceLogged: logged });
      }
    }
  }
  return resolved;
}

/** Gate finding 3 (re-gate): extracts just the `## Log` section's text
 * from a full `docs/p0/X2.md` read — an acceptance record must be logged
 * THERE specifically, not merely anywhere in the file (a stray mention of
 * an id/date elsewhere in the document must not count). Returns the
 * WHOLE file's text if no `## Log` heading is found, rather than silently
 * treating "no Log section" as "nothing is logged" — a missing section
 * is itself a shape worth surfacing as a search-scope difference, not
 * hidden behind an empty-string match-nothing result. */
export function extractX2MdLogSection(x2MdText: string): string {
  const m = /^## Log\b[\s\S]*/m.exec(x2MdText);
  return m ? m[0] : x2MdText;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const execFileAsync = promisify(execFile);

export interface LedgerGitCheck {
  /** `git hash-object <ledgerPath>` — the blob hash the ledger's CURRENT
   * on-disk content would have if committed as-is, printed regardless of
   * clean/dirty so a reader can always see exactly which ledger content
   * produced this verdict. `null` only when `git` itself is unavailable
   * (not installed / not on PATH). */
  blobHash: string | null;
  /** True only when `git diff --quiet -- <ledgerPath>` reports no
   * uncommitted changes AND the file is not untracked/staged — i.e. the
   * ledger's on-disk content is EXACTLY what git history already has, so
   * this verdict is reproducible from the committed record alone. */
  clean: boolean;
  /** Human-readable reason for `clean: false`, or a plain "clean"
   * confirmation. */
  detail: string;
}

/**
 * Gate finding 2d: `docs/p0/x2-recorded-ledger.json` is the CANONICAL
 * ledger — living in the repo means every edit to it shows in `git log`,
 * unlike a `/tmp` file nobody else can audit. This checks that the ledger
 * a verdict run is ABOUT TO USE is exactly what git already has on record
 * (no uncommitted edit could have snuck in a bogus entry between commit
 * and this run), and reports the blob hash so the verdict output names
 * EXACTLY which ledger content it read — never "trust me," always
 * checkable against `git show <blobHash>` or `git log -p -- <path>`.
 * Never throws: a git failure (not a repo, git missing, path outside any
 * repo) comes back as `clean: false` with the reason in `detail` — the
 * caller decides whether that refuses the run or only marks it UNOFFICIAL
 * (this repo's own house style per `recorded-export.ts`'s `runGit`: a
 * git-check failure is never silently treated as "assume clean").
 */
export async function checkLedgerAgainstGit(ledgerPath: string): Promise<LedgerGitCheck> {
  const cwd = path.dirname(path.resolve(ledgerPath));
  let blobHash: string | null = null;
  try {
    const { stdout } = await execFileAsync("git", ["hash-object", ledgerPath]);
    blobHash = stdout.trim();
  } catch {
    blobHash = null;
  }
  try {
    // Exit 0 = no diff between working tree and index for this path.
    await execFileAsync("git", ["diff", "--quiet", "--", ledgerPath], { cwd });
  } catch (err) {
    const code = (err as { code?: number }).code;
    if (code === 1) {
      return {
        blobHash,
        clean: false,
        detail: `"${ledgerPath}" has uncommitted changes against the index (git diff is non-empty).`,
      };
    }
    return {
      blobHash,
      clean: false,
      detail:
        `could not verify "${ledgerPath}" is clean in git: ` +
        `${err instanceof Error ? err.message : String(err)}`,
    };
  }
  // `git diff` alone says nothing about an UNTRACKED file (never added at
  // all) — that would wrongly read as "clean". `git status --porcelain`
  // catches that too (an untracked file shows as `??`).
  try {
    const { stdout } = await execFileAsync(
      "git",
      ["status", "--porcelain", "--", ledgerPath],
      { cwd },
    );
    if (stdout.trim().length > 0) {
      return {
        blobHash,
        clean: false,
        detail: `"${ledgerPath}" is untracked or has staged-but-uncommitted changes (git status: "${stdout.trim()}").`,
      };
    }
  } catch (err) {
    return {
      blobHash,
      clean: false,
      detail:
        `could not verify "${ledgerPath}"'s git status: ` +
        `${err instanceof Error ? err.message : String(err)}`,
    };
  }
  return { blobHash, clean: true, detail: "clean — no uncommitted changes." };
}

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

/** Repo-relative path to `docs/p0/X2.md` — resolved from THIS module's own
 * location the same way `x2-fetch.ts`'s `resolveDefaultX2ConfigPath`
 * resolves `config/x2-sources.json` (works from `src/` via vitest and
 * from `dist/`, since both sit exactly one level under `tools/p0`, itself
 * two levels under the repo root). */
export function resolveDefaultX2MdPath(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const pkgRoot = path.join(here, ".."); // tools/p0
  const repoRoot = path.join(pkgRoot, "..", "..");
  return path.join(repoRoot, "docs", "p0", "X2.md");
}

async function main(argv: string[]): Promise<void> {
  // `--allow-dirty-ledger` is a bare boolean toggle (no value) — stripped
  // before `parseFlags` runs, same reasoning as `--render` in
  // `x2-fetch.ts`.
  const allowDirtyLedger = argv.includes("--allow-dirty-ledger");
  const flags = parseFlags(argv.filter((a) => a !== "--allow-dirty-ledger"));
  const evidenceDir = flags["evidence-dir"];
  const confirmationPath = flags.confirmation;
  if (!evidenceDir || !confirmationPath || !flags.ledger) {
    throw new Error(
      "Usage: node dist/x2-verdict.js --evidence-dir <dir> --confirmation <file.json> --ledger <path> " +
        "[--out <prefix>] [--corroboration <file.json>] [--x2-log <path to docs/p0/X2.md>] " +
        "[--allow-dirty-ledger] — `--ledger` is REQUIRED (gate finding 2c, re-gate): the per-directory " +
        "default ledger was removed. The canonical ledger is `docs/p0/x2-recorded-ledger.json` (gate " +
        "finding 2d). `--x2-log` defaults to this checkout's own docs/p0/X2.md (gate finding 3, re-gate: " +
        "an `acceptance` corroboration record must be logged there).",
    );
  }
  const manifest = JSON.parse(
    await readFile(path.join(evidenceDir, "manifest.json"), "utf8"),
  ) as X2FetchManifest;
  const confirmation = JSON.parse(
    await readFile(confirmationPath, "utf8"),
  ) as X2ConfirmationFile;
  const ledgerPath = flags.ledger;
  // Gate finding 2d: the ledger must be exactly what git already has on
  // record — an uncommitted (or untracked) edit could otherwise slip a
  // bogus entry into a verdict run with no trace in `git log`. A dirty or
  // unverifiable ledger REFUSES the run outright unless
  // `--allow-dirty-ledger` is passed, in which case the run proceeds but
  // the output is marked UNOFFICIAL — never silently treated as if the
  // ledger were the committed, auditable one.
  const ledgerGitCheck = await checkLedgerAgainstGit(ledgerPath);
  if (!ledgerGitCheck.clean && !allowDirtyLedger) {
    throw new Error(
      `Refusing: the ledger "${ledgerPath}" is not clean in git — ${ledgerGitCheck.detail} Pass ` +
        "--allow-dirty-ledger to proceed anyway; the output will be marked UNOFFICIAL, and this is never " +
        "the recommended path for a result meant to stand as the recorded verdict.",
    );
  }
  const ledgerOfficial = ledgerGitCheck.clean;
  const ledger = await loadLedger(ledgerPath);
  const evidenceByTrail = await buildEvidenceByTrail(
    manifest,
    (rel) => readFile(path.join(evidenceDir, rel)),
    { ledger },
  );
  // Gate finding 4: an optional corroboration file, keyed trail -> evidence
  // sha256 -> corroboration record, backs every owner-saved fact. Missing
  // flag -> `{}`, which `computeX2Verdict` treats as "no corroboration
  // supplied for anything" (every owner-saved fact fails as uncorroborated,
  // per the gate's rule — not silently skipped).
  const corroboration: X2CorroborationFile = flags.corroboration
    ? (JSON.parse(await readFile(flags.corroboration, "utf8")) as X2CorroborationFile)
    : {};
  // Gate finding 3 (re-gate): resolve (verify) that corroboration file
  // BEFORE computeX2Verdict ever sees it — re-reading `wayback` evidence
  // from THIS evidence dir (a `wayback` record's `rawFile` is relative to
  // it, same as any trail evidence) and checking `acceptance` records
  // against `docs/p0/X2.md`'s own Log section. A missing/unreadable
  // X2.md is not a hard refusal (an --evidence-dir far from a golfraven
  // checkout is a legitimate use), but every `acceptance` record then
  // resolves to "not logged" — the safe default.
  const x2MdPath = flags["x2-log"] || resolveDefaultX2MdPath();
  let x2MdLogText: string | null = null;
  try {
    x2MdLogText = extractX2MdLogSection(await readFile(x2MdPath, "utf8"));
  } catch {
    x2MdLogText = null;
  }
  const resolvedCorroboration = await resolveCorroboration(
    corroboration,
    (rel) => readFile(path.join(evidenceDir, rel)),
    x2MdLogText,
  );
  const result = computeX2Verdict(
    confirmation,
    evidenceByTrail,
    X2_SLATE_TRAILS,
    corroboration,
    resolvedCorroboration,
  );
  const outExplicit = Boolean(flags.out);
  const outPrefix =
    flags.out ||
    path.join(defaultOutsideRepoDir("x2-verdict-result"), "result");
  assertOutsideRepoUnlessExplicit(path.dirname(outPrefix), outExplicit);
  await mkdir(path.dirname(outPrefix), { recursive: true });
  // Gate finding 2d: the ledger's git blob hash and clean/UNOFFICIAL
  // status are written alongside the verdict itself — a reader of the
  // JSON result never has to separately go find and re-hash the ledger to
  // know exactly which version of it produced this verdict.
  const resultWithLedgerInfo = {
    ...result,
    ledger: {
      path: ledgerPath,
      blobHash: ledgerGitCheck.blobHash,
      official: ledgerOfficial,
      detail: ledgerGitCheck.detail,
    },
  };
  await writeFile(
    `${outPrefix}.json`,
    `${JSON.stringify(resultWithLedgerInfo, null, 2)}\n`,
    "utf8",
  );
  const ledgerHeader =
    `Ledger: ${ledgerPath} (blob ${ledgerGitCheck.blobHash ?? "unavailable — git not found"}) — ` +
    `${ledgerOfficial ? "OFFICIAL (clean in git)" : `**UNOFFICIAL** (${ledgerGitCheck.detail})`}\n\n`;
  const md = ledgerHeader + renderX2VerdictMarkdown(result);
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
