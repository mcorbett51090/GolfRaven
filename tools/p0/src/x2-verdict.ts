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
import { statSync } from "node:fs";
import { access, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
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
  daysBetween,
  parseWaybackUrl,
  waybackTimestampToDate,
  WAYBACK_TIMESTAMP_TOLERANCE_DAYS,
} from "./x2-corroborate-wayback.js";
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
 *
 * Gate finding 2 (re-gate, Addendum J re-gate at 1f6729d — "forged
 * acceptance"): the free-text `id` above could be ANY string an agent
 * chose, matched against X2.md by a loose "line contains both this id and
 * this date" substring test — an agent could write BOTH the corroboration
 * record AND a plausible-looking Log line naming its own made-up `id`,
 * and the old check would pass. Fixed two ways:
 *
 *  1. **Structured row.** `id` is REMOVED; an `acceptance` record now
 *     carries `fact` (a controlled identifier: `"completionUnit"`,
 *     `"season"`, or `"roster:<name>"`) instead. The ONLY row that counts
 *     is one matching, EXACTLY (after trimming), `ACCEPT <trail> <fact>
 *     <full evidenceSha256> <YYYY-MM-DD> Matt` — found ONLY inside X2.md's
 *     `## Log` section (bounded at the next `## ` heading,
 *     `findAcceptRowLine`) — and the record's own `fact` is cross-checked
 *     against the fact actually being resolved (`checkOwnerSavedCorroboration`'s
 *     `factId` parameter), so a record cannot borrow a DIFFERENT fact's
 *     accepted row.
 *  2. **Git binding.** Matching text in X2.md is not enough on its own —
 *     an agent can edit files. `git blame` (`blameAcceptRow`) finds the
 *     commit that introduced the matched row's line, and the row counts
 *     only when that commit is reachable from `origin/main` (i.e.
 *     genuinely pushed, not merely sitting in a local working tree or an
 *     unshared branch/stash). The commit hash, author, author date, and
 *     `%G?` signature status are all carried into the resolved
 *     corroboration entry and printed in the verdict output.
 *
 * **Honest limit, stated plainly (also in `docs/p0/X2.md` and this
 * package's README):** every agent working in this environment acts with
 * Matt's own GitHub credentials. No technical check run from inside this
 * environment can distinguish a commit Matt made from one an agent made
 * while impersonating his identity — `git blame`'s author field and even
 * `%G?` (unless Matt's key/token signs commits, which this environment's
 * credentials do not) cannot prove authorship in that adversarial sense.
 * The git-binding check above raises the bar from "a string exists in a
 * file" to "a commit reachable from the shared, pushed history says so,"
 * which is real and auditable, but it is NOT identity verification. The
 * REAL control is procedural, not technical: **agents must never write an
 * `ACCEPT` row themselves — only Matt adds one, by hand.** This tool's
 * job is to make that row's provenance checkable and visible (hash,
 * author, date, signature status) so a human reviewing a verdict — or
 * reviewing `git log` — can audit it, not to somehow prove identity a
 * shared-credential environment structurally cannot prove.
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
  /** Gate finding 2 (re-gate): which fact this record backs — a
   * controlled identifier, not free text: `"completionUnit"`, `"season"`,
   * or `"roster:<name>"` for a roster entry (matching the roster entry's
   * own `name`, verbatim). Must equal both the `<fact>` token of the
   * matched X2.md Log row AND the `factId` the caller is actually
   * resolving this record against — a record cannot borrow a different
   * fact's accepted row. */
  fact: string;
  /** Must be the literal string `"Matt"` — checked exactly, not just
   * truthy (gate finding 3, re-gate: any other value refuses). */
  acceptedBy: string;
  /** `YYYY-MM-DD` — must equal the matched Log row's own date exactly. */
  date: string;
}
export type X2CorroborationRecord = X2WaybackCorroboration | X2AcceptanceCorroboration;
/** trail name -> evidenceSha -> its corroboration record(s), if any.
 * Gate finding 2 (re-gate): a LIST, not a single record — one owner-saved
 * capture can legitimately back several DIFFERENT facts (a roster name, a
 * completionUnit, a season, each read off the same saved page), and each
 * needs its OWN acceptance, specific to that fact (see
 * `X2AcceptanceCorroboration.fact`'s own doc) — a single blanket
 * acceptance covering "whatever gets cited against this SHA, now or
 * later" is exactly the forgery shape finding 2 closes. A `wayback`
 * record, by contrast, corroborates the EVIDENCE itself (an independent
 * re-fetch of the whole page) and so is not fact-specific — realistically
 * at most one per SHA, but the list shape accommodates it uniformly. */
export type X2CorroborationFile = Record<string, Record<string, X2CorroborationRecord[]>>;

/**
 * The corroboration data ACTUALLY TRUSTED, after the CLI's own
 * verification pass — never derived from the raw `X2CorroborationFile`
 * directly. Keyed by `"<trail>:<evidenceSha>"` (matching how
 * `computeX2Verdict` already looks a fact's corroboration record up).
 */
/** Gate finding 2 (re-gate): the git provenance of the X2.md Log line that
 * backs an `acceptance` corroboration record — printed in the verdict
 * output so a human can audit it (see this file's own "Honest limit"
 * doc above `X2AcceptanceCorroboration`; this is NOT identity proof). */
export interface AcceptRowGitProvenance {
  /** Full 40-char commit hash that `git blame` says introduced the
   * matched Log line. */
  commit: string;
  author: string;
  /** ISO-8601 author date (`git show --format=%aI`). */
  authorDate: string;
  /** `%G?` — one of `G`/`B`/`U`/`X`/`Y`/`R`/`E`/`N` (git's own codes;
   * `N` means "no signature"), printed as-is, never interpreted as proof
   * of identity. */
  signatureStatus: string;
  /** Gate finding (third re-gate, "trust root is the caller's repo plus
   * local refs"): `true` only when `git merge-base --is-ancestor <commit>
   * refs/x2-verdict/verified-main` succeeds, where that ref was just
   * FRESHLY FETCHED (this same run, never read stale) from the pinned
   * canonical URL (`GOLFRAVEN_CANONICAL_REPO_URL`) — never the editable
   * local `origin` remote, which a caller can point anywhere or forge
   * with a bare `git update-ref`. This proves the commit is reachable
   * from GENUINE GitHub `main`, not merely from some local ref of the
   * same name. See this module's own "Honest limit" doc: this still does
   * not prove WHO made the commit (agents hold Matt's own credentials,
   * and even an API-made commit is GitHub-signed, so `signatureStatus`
   * proves nothing about identity either) — the value is that a forgery
   * now has to land in the SHARED, PUBLIC GitHub history, where Matt can
   * see it, not merely in a throwaway local repo. */
  reachableFromVerifiedMain: boolean;
}

export interface ResolvedCorroborationEntry {
  /** `wayback` records only: `true` only once EVERY re-validation rule
   * (gate finding 3, second re-gate) has passed: URL form, embedded-URL
   * normalisation match, ±90-day timestamp tolerance, `rawFile` shape +
   * containment, SHA differs from the owner-saved fact's own SHA, ledger
   * registration under method `wayback`, AND the raw bytes recompute to
   * `snapshotSha256`. `waybackText` is only meaningful when this is
   * `true`. */
  waybackVerified?: boolean;
  /** `wayback` records only: text re-derived from the VERIFIED raw bytes,
   * with the SAME extractor every other evidence route uses. `null` when
   * extraction found no text, or verification failed. */
  waybackText?: string | null;
  /** `wayback` records only: which rule failed (or a plain confirmation),
   * for the verdict output/reasons — never left implicit. */
  waybackDetail?: string;
  /** `acceptance` records only: `true` only when a matching structured
   * `ACCEPT` row was found in `docs/p0/X2.md`'s `## Log` section, that
   * row is VISIBLE prose (not inside a fenced code block, an HTML
   * comment, or an indented code block — gate finding, third re-gate,
   * fix (c)), `docs/p0/X2.md` itself is the toolkit's own canonical file
   * (fix (a)), the commit that introduced the row is reachable from a
   * FRESHLY FETCHED `refs/x2-verdict/verified-main` (fix (b)), and the
   * acceptance date is on/after the evidence's own `ownerSavedDate` and
   * no more than 1 day after the commit's own date (should-fix). */
  acceptanceLogged?: boolean;
  /** `acceptance` records only: the git provenance of the matched row,
   * when one was found (regardless of whether it was reachable from
   * `refs/x2-verdict/verified-main` — printed either way so a reader can
   * see why). */
  acceptanceProvenance?: AcceptRowGitProvenance | null;
  /** `acceptance` records only: why `acceptanceLogged` is `false`, or a
   * plain confirmation — never left implicit. */
  acceptanceDetail?: string;
}
export type X2ResolvedCorroboration = Map<string, ResolvedCorroborationEntry>;

/** The key `X2ResolvedCorroboration` is keyed by. Gate finding 2 (re-gate):
 * `disambiguator` is an `acceptance` record's own `fact` — REQUIRED for
 * those, since several acceptance records can now share one (trail,
 * evidenceSha) pair (see `X2CorroborationFile`'s own doc), one per fact.
 * Omitted for a `wayback` record, which corroborates the evidence as a
 * whole rather than one specific fact. */
export function corroborationResolutionKey(
  trail: string,
  evidenceSha: string,
  disambiguator?: string,
): string {
  return disambiguator === undefined ? `${trail}:${evidenceSha}` : `${trail}:${evidenceSha}:${disambiguator}`;
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
    /** Gate finding 3 (second re-gate): the manifest entry's own stated
     * URL and (owner-saved entries only) `ownerSavedDate` — carried
     * through so a Wayback corroboration record can be re-validated
     * against THIS fact's own claims (its stated URL, its own recorded
     * date) at verdict time, never against the corroboration record's own
     * say-so. `ownerSavedDate` is `null` for a non-owner-saved entry, or
     * a legacy owner-saved entry that predates the field. */
    url: string;
    ownerSavedDate: string | null;
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
        bySha.set(recomputedSha, {
          text,
          method,
          methodDefaulted,
          recorded,
          url: e.url,
          ownerSavedDate: e.ownerSavedDate ?? null,
        });
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
  trailCorroboration: Record<string, X2CorroborationRecord[]>,
  resolved: X2ResolvedCorroboration,
  label: string,
  reasons: string[],
  /** Gate finding 2 (re-gate): the controlled fact identifier THIS call
   * site is checking — `"completionUnit"`, `"season"`, or
   * `"roster:<name>"`. An acceptance record's own `fact` must equal this
   * exactly, or it is rejected outright: a record backing a DIFFERENT
   * fact (even a genuinely logged, git-reachable one) must never count
   * for this one. */
  factId: string,
): { ok: boolean; summary: string | null } {
  const entry = evidence.get(evidenceSha);
  const method = entry?.method;
  if (method !== "owner-saved") {
    return { ok: true, summary: null };
  }
  const records = trailCorroboration[evidenceSha];
  if (!records || records.length === 0) {
    reasons.push(
      `${label}: owner-attested, UNCORROBORATED (evidence ${evidenceSha.slice(0, 12)}... is an owner-saved ` +
        "capture with no corroboration record supplied — a Wayback snapshot or Matt's dated acceptance is " +
        "required for an owner-saved fact to count; Addendum J correction).",
    );
    return { ok: false, summary: "owner-attested, uncorroborated" };
  }
  // Gate finding 2 (re-gate): several acceptance records can share this
  // (trail, evidenceSha) pair, one per fact — a `wayback` record (which
  // corroborates the whole evidence, not one fact) applies regardless of
  // `factId`; an `acceptance` record applies ONLY when its own `fact`
  // equals this call site's `factId`.
  const record: X2CorroborationRecord | undefined =
    records.find((r) => r.type === "wayback") ?? records.find((r) => r.type === "acceptance" && r.fact === factId);
  if (!record) {
    reasons.push(
      `${label}: owner-attested, UNCORROBORATED FOR THIS FACT (evidence ${evidenceSha.slice(0, 12)}... has ` +
        `${records.length} corroboration record(s), but none is a Wayback snapshot or an acceptance whose ` +
        `fact matches ${JSON.stringify(factId)} — an acceptance for a DIFFERENT fact never backs this one ` +
        "(gate finding 2, re-gate).",
    );
    return { ok: false, summary: "owner-attested, uncorroborated for this fact" };
  }
  const resolution =
    record.type === "wayback"
      ? resolved.get(corroborationResolutionKey(trail, evidenceSha))
      : resolved.get(corroborationResolutionKey(trail, evidenceSha, record.fact));
  if (record.type === "acceptance") {
    // Gate finding 3 (re-gate): `acceptedBy` must be EXACTLY "Matt".
    if (record.acceptedBy !== "Matt") {
      reasons.push(
        `${label}: owner-attested, acceptance record rejected — acceptedBy must be exactly "Matt", got ` +
          `${JSON.stringify(record.acceptedBy)} (gate finding 3, re-gate).`,
      );
      return { ok: false, summary: "owner-attested, acceptance record rejected (acceptedBy is not Matt)" };
    }
    // Gate finding 2 (re-gate, "forged acceptance"): the record must cite
    // the SAME fact this call site is actually checking — a record for
    // "season" can never back "completionUnit", even if it is otherwise
    // valid and logged.
    if (record.fact !== factId) {
      reasons.push(
        `${label}: owner-attested, acceptance record rejected — its fact (${JSON.stringify(record.fact)}) does ` +
          `not match this fact (${JSON.stringify(factId)}) (gate finding 2, re-gate: an acceptance for one ` +
          "fact must never back a different one).",
      );
      return { ok: false, summary: "owner-attested, acceptance record rejected (fact mismatch)" };
    }
    if (!resolution?.acceptanceLogged) {
      reasons.push(
        `${label}: owner-attested, acceptance record cited (fact "${record.fact}", ${record.date}) but no ` +
          `structured "ACCEPT ${trail} ${record.fact} ${evidenceSha} ${record.date} Matt" row, on a commit ` +
          'reachable from origin/main, was found in docs/p0/X2.md\'s "## Log" section' +
          `${resolution?.acceptanceDetail ? ` (${resolution.acceptanceDetail})` : ""} — an acceptance not ` +
          "logged and pushed where this project's own decision trail lives does not count (gate finding 2, " +
          "re-gate).",
      );
      return {
        ok: false,
        summary: `owner-attested, acceptance NOT FOUND/NOT PUSHED in X2.md's Log (fact "${record.fact}")`,
      };
    }
    const prov = resolution.acceptanceProvenance;
    const provSummary = prov
      ? `commit ${prov.commit.slice(0, 12)}... by ${prov.author}, ${prov.authorDate}, sig:${prov.signatureStatus}`
      : "commit unavailable";
    const summary = `owner-attested, accepted by Matt on ${record.date} (X2.md Log row, ${provSummary})`;
    reasons.push(`${label}: ${summary}.`);
    return { ok: true, summary };
  }
  // record.type === "wayback" — gate finding 3 (second re-gate): the
  // resolution pass has ALREADY re-validated every rule (URL form,
  // embedded-URL match, timestamp tolerance, rawFile shape/containment,
  // SHA differs from the owner-saved fact's own SHA, ledger registration)
  // before ever setting `waybackVerified: true` — this function only acts
  // on that verdict, it never re-derives the rules itself.
  if (!resolution?.waybackVerified) {
    reasons.push(
      `${label}: owner-attested, Wayback corroboration record cited (${record.snapshotUrl}) but failed ` +
        `re-validation${resolution?.waybackDetail ? `: ${resolution.waybackDetail}` : ""} — corroboration fails ` +
        "(gate finding 3, re-gate).",
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
              `roster:${rosterEntry.name}`,
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
            "completionUnit",
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
            "season",
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

// ---------------------------------------------------------------------------
// Trust root (gate finding, third re-gate: "trust root is the caller's repo
// plus local refs")
//
// Round 4's fix pinned the LEDGER's canonical path via `git rev-parse
// --show-toplevel` run FROM THE LEDGER'S OWN DIRECTORY, and pinned
// `ACCEPT` row provenance to the LOCAL, editable ref `origin/main`. A
// caller who points `--ledger`/`--x2-log` at a throwaway scratch repo
// trivially satisfies "is this the toplevel of SOME repo" for that
// repo, and `origin/main` (or even a `refs/remotes/origin/main` with no
// `origin` remote configured at all) is just a ref anyone with write
// access to that repo can set with a bare `git update-ref` — no push,
// no review, no GitHub visibility required. A scratch repo committing a
// forged `ACCEPT` row "as Matt," then `git update-ref refs/remotes/
// origin/main HEAD`, made every check in this file report OFFICIAL /
// reachable / confirmed.
//
// The fix has three parts, all below: (a) pin the trust root to the
// TOOLKIT'S OWN checkout, resolved from `import.meta.url` — never from
// any caller-supplied path; (b) stop trusting local refs at all — fetch
// `main` fresh, every run, from the hard-coded canonical GitHub URL,
// into a ref this tool owns and always deletes-then-refetches; (c) only
// count a VISIBLE `ACCEPT` row — one that is not hidden inside a fenced
// code block, an HTML comment, or an indented code block.
// ---------------------------------------------------------------------------

/**
 * The canonical GolfRaven repository — GitHub is case-insensitive, and
 * this is the moved-to spelling. HARD-CODED, never read from the local,
 * editable `origin` remote: a caller can point `origin` at anything, or
 * forge a same-named local ref outright, and a check that trusted either
 * would trust whatever the caller set up, not GitHub's own shared
 * history. (Confirmed reachable from this environment directly —
 * `git ls-remote https://github.com/mcorbett51090/GolfRaven
 * refs/heads/main` returns a real SHA — this is a public repo.)
 */
export const GOLFRAVEN_CANONICAL_REPO_URL = "https://github.com/mcorbett51090/GolfRaven";

/** The toolkit's OWN checkout root — resolved from `import.meta.url`
 * (THIS module's own on-disk location), never from a caller-supplied
 * path. This is the ONE source of truth for "the real golfraven
 * checkout"; works from `src/` under vitest and from the built `dist/`
 * (both sit THREE levels under the repo root: repo root -> tools -> p0
 * -> {src,dist}), the same technique `resolveDefaultX2MdPath` already
 * used for its own default. */
export function resolveToolkitRepoRoot(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.join(here, "..", "..", ".."); // tools/p0/{src,dist} -> tools/p0 -> tools -> repo root
}

/** The ONE absolute path an OFFICIAL run's `--ledger` must resolve to
 * (gate finding, third re-gate, fix (a)). */
export function canonicalLedgerAbsPath(): string {
  return path.join(resolveToolkitRepoRoot(), ...CANONICAL_LEDGER_REPO_RELATIVE_PATH.split("/"));
}

/** The ONE absolute path an OFFICIAL run's `--x2-log` must resolve to
 * (gate finding, third re-gate, fix (a)) — the same value
 * `resolveDefaultX2MdPath` computes as its own default, named
 * separately here because this is now a TRUST boundary, not merely a
 * convenience default. */
export function canonicalX2MdAbsPath(): string {
  return resolveDefaultX2MdPath();
}

/** `realpath(candidate) === realpath(canonical)`, resolving symlinks on
 * both sides (gate finding, third re-gate, fix (a): "require
 * `realpath(--ledger)` to equal ..."). `false`, never throws, when
 * either path does not exist or cannot be resolved — a caller pointing
 * at a nonexistent file is "not canonical," not a crash. */
async function isCanonicalPath(candidate: string, canonical: string): Promise<boolean> {
  try {
    const [realCandidate, realCanonical] = await Promise.all([
      realpath(candidate),
      realpath(canonical),
    ]);
    return realCandidate === realCanonical;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Addendum J re-gate round 6 ("verification trusts the toolkit checkout's
// own local git state"): round 5's `fetchVerifiedMainRef` fetched into a
// ref INSIDE the toolkit's own checkout, with `process.env` inherited
// wholesale. Three exploits confirmed TN from a local, unsigned "Matt"
// commit: (I) `git config url.<fake>.insteadOf <real URL>` — local,
// global, SYSTEM config, or the GIT_CONFIG_COUNT/KEY/VALUE env-var
// channel, which needs no config file at all — silently redirects the
// "real main" fetch to an attacker's own repo; (R) `git replace <real>
// <forged>` makes every git command that reads the real commit
// transparently read the forged one instead (blame, merge-base
// --is-ancestor — everything), unless GIT_NO_REPLACE_OBJECTS=1; (G) a
// `.git/info/grafts` line rewrites a commit's parent history, making a
// forged commit an ancestor of "real main". GIT_DIR/GIT_WORK_TREE in the
// caller's env, and a `.git/hooks` script (e.g. `reference-transaction`),
// are the same class: local state a caller controls, silently trusted.
//
// Fix: every GitHub-verification git command below runs inside a
// disposable, freshly-created, BARE repo (`mkdtemp` + `git init --bare`,
// removed on exit) under an EXPLICITLY CONSTRUCTED, minimal environment
// — never `{...process.env}` — with HOME and GIT_DIR both pinned to that
// same disposable directory, GIT_NO_REPLACE_OBJECTS=1,
// GIT_CONFIG_NOSYSTEM=1, GIT_CONFIG_GLOBAL=/dev/null, and per-command
// `-c core.hooksPath=/dev/null -c protocol.file.allow=never -c
// protocol.ext.allow=never`. A `git ls-remote --get-url` canary (which
// resolves git's own config-rewriting logic WITHOUT a network
// connection) catches `insteadOf` redirection before any fetch happens;
// full history (no `--depth`) is fetched and a shallow result refused;
// `info/grafts` and `refs/replace/*` in the fresh temp repo are refused
// outright as belt-and-braces even though a brand-new repo cannot
// acquire either on its own. Reachability drops out for free: blame runs
// directly against `refs/heads/main` inside this repo, so whatever
// commit it finds is by construction already part of that ref's own
// history — there is no separate `merge-base --is-ancestor` step to
// subvert. Content authority also moves to GitHub: both the ledger blob
// and X2.md's own text are read with `git show <ref>:<path>` INSIDE the
// disposable repo, never from the local working tree — the local files
// are used only to confirm `--ledger`/`--x2-log` POINT at this toolkit's
// own canonical path (fix (a), unchanged), never for their CONTENT. This
// also neutralises a symlinked-docs/p0 trick: a local symlink no longer
// matters for what is actually trusted.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Addendum J re-gate round 7 ("an agent that controls the verdict
// process's runtime environment still gets OFFICIAL with a forged
// acceptance"): round 6's fix scrubbed process.env for the git commands
// it built, but still (a) resolved the LITERAL STRING "git" through
// PATH — a fake `git` shim placed earlier on PATH (or PATH itself
// rewritten) is silently trusted, since `execFileAsync("git", …)` does a
// PATH lookup every time; (b) passed the caller's own PATH straight
// through the "allowed" list into the child's env; and (c) never
// considered that round 6's fix runs INSIDE the same Node process the
// caller launched — `NODE_OPTIONS="--require evil.cjs"`, `LD_PRELOAD`,
// or any other mechanism that injects code into that process can patch
// `child_process.execFile` itself before a single line of this module's
// own code runs, making every "scrubbed" git invocation transparently
// go through attacker code regardless of what env/args this module
// constructs for it.
//
// Fix, three parts: (1) `resolveGitBinary` resolves an ABSOLUTE path
// (never the bare string "git", never PATH-dependent) and requires it be
// owned by root and not group-/world-writable, refusing otherwise —
// `main()` never overrides the candidate paths; a `gitBinary` override is
// a TEST-ONLY seam. (2) the child's own PATH is fixed to
// `/usr/bin:/bin`, never the caller's — closes both a shim placed
// elsewhere on PATH and PATH itself being rewritten. (3) `detectRuntimeTamper`
// looks for evidence the ORIGINAL process shows signs of the specific,
// NAIVE injection shapes this checks for.
//
// ⛔ Eighth re-gate correction (round 8) — READ THIS BEFORE TRUSTING
// `detectRuntimeTamper`'s OWN doc, which round 7 overstated: this check
// is a TRIPWIRE FOR NAIVE, NON-SELF-HIDING INJECTION ONLY. It is NOT a
// security boundary and CANNOT be made into one from inside this
// process. The reason is structural, not a bug to patch: `NODE_OPTIONS`
// preload code (`--require`, etc.) runs BEFORE a single line of this
// module's own code — including before `detectRuntimeTamper` itself ever
// executes. Round 8's gate fixture proved this directly: `evil.cjs` was
// extended with `delete process.env.NODE_OPTIONS; process.execArgv.length
// = 0;` at its very top — by the time `detectRuntimeTamper` runs, the
// evidence it looks for has already been erased BY THE SAME INJECTED CODE
// that patched `child_process.execFile`, and the verdict came back
// OFFICIAL with TN confirmed. No check added to THIS module can close
// this: any in-process check reads `process.env`/`process.execArgv` no
// earlier than the attacker's own preload code did, so a preload
// sophisticated enough to hide its OWN tracks always wins the race. The
// checks below remain as defense in depth against a NAIVE attempt (one
// that patches `execFile` but doesn't bother erasing NODE_OPTIONS/
// execArgv afterward) — they still refuse `LD_PRELOAD`/an `LD_*`-prefixed
// variable/`GIT_EXEC_PATH`/`DYLD_*` being set at all, a `NODE_OPTIONS`
// token outside a narrow benign allow-list (round 8: switched from a
// dangerous-flag denylist to an allow-list — see `isNodeOptionAllowed`'s
// own doc for why), or `process.execArgv` being non-empty. The REAL
// control for this class is procedural: this tool must run from a
// process an agent has not already compromised, which this module cannot
// verify about itself. See `docs/p0/X2.md`'s own Scope statement
// (eighth re-gate, round 8) for the corrected, honest "defends
// against"/residual split — this comment is the source of truth for the
// code; that file is the source of truth for what an operator should
// believe the tool actually does.
//
// `detectRuntimeTamper` is INJECTED (`env`/`execArgv` parameters), never
// reading `process.env`/`process.execArgv` itself — `verifyAgainstGitHub`
// passes the REAL ones by default and `main()` never overrides that; the
// injection exists ONLY so unit tests can (a) exercise a clean baseline
// unaffected by vitest's OWN ambient `execArgv` (vitest's worker process
// carries a non-empty `execArgv` including its own `--require
// suppress-warnings.cjs`, confirmed this session — every test not
// specifically exercising this check passes an explicit clean override,
// the seam `main()` never uses) and (b) attribute a specific vector
// precisely, rather than "some ambient noise tripped it."
// ---------------------------------------------------------------------------

/** Absolute paths `resolveGitBinary` tries, in order — never the bare
 * string `"git"`, which would resolve through the (spoofable) PATH. */
const GIT_BINARY_CANDIDATES = ["/usr/bin/git", "/bin/git"] as const;

/** The fixed PATH every child git process gets (hardening (b), round 7)
 * — the caller's own PATH is NEVER passed through, closing both "a fake
 * git shim earlier on PATH" and "PATH itself rewritten". */
const FIXED_CHILD_PATH = "/usr/bin:/bin";

export interface GitBinaryResolution {
  ok: boolean;
  /** Absolute path to a verified `git` binary, or `null` on failure. */
  path: string | null;
  detail: string;
}

/**
 * Round 7 hardening (1): resolves `git` to an ABSOLUTE path (trying
 * `/usr/bin/git`, then `/bin/git`) and requires — via `fs.statSync`,
 * never trusting a caller-controlled PATH lookup — that it be owned by
 * root (`uid === 0`) and not group- or world-writable (mode bits `022`).
 * A candidate that EXISTS but fails either check is a hard refusal, not
 * a silent fall-through to the next candidate: a tampered binary sitting
 * at the well-known path is itself exactly the attack this closes, and
 * quietly trying somewhere else an attacker may equally control buys
 * nothing. `gitBinaryOverride` is a TEST-ONLY seam (the shipped CLI's
 * `main()` never passes it) that REPLACES the candidate list with the
 * one given path — the same ownership/writability checks still run
 * against it, never bypassed. This lets a test do either: point at
 * whatever `git` the test environment actually trusts (its own real
 * `/usr/bin/git` may not exist, e.g. under a container with `git` only
 * at `/opt/.../git`), and see it validate fine; or point at a
 * deliberately bad file (wrong uid, or group/world-writable) and see it
 * genuinely refused — proving the check itself works, not merely that
 * the seam exists.
 */
export function resolveGitBinary(gitBinaryOverride?: string): GitBinaryResolution {
  // TEST-ONLY seam: REPLACES the candidate list with the single
  // overridden path — it does NOT bypass the ownership/writability
  // checks below. This is deliberate: a test needs to prove BOTH that a
  // trustworthy override validates fine (the test environment's real
  // `git` may not live at `/usr/bin/git`) AND that a deliberately bad
  // one (non-root-owned, or group/world-writable) is genuinely refused
  // — a seam that unconditionally returned `ok: true` could never
  // exercise the second case at all.
  const candidates = gitBinaryOverride !== undefined ? [gitBinaryOverride] : GIT_BINARY_CANDIDATES;
  for (const candidate of candidates) {
    let st: ReturnType<typeof statSync>;
    try {
      st = statSync(candidate);
    } catch {
      continue; // doesn't exist here — try the next candidate (none, under the override).
    }
    if ((st.mode & 0o022) !== 0) {
      return {
        ok: false,
        path: null,
        detail: `refusing: "${candidate}" is group- or world-writable (mode ${(st.mode & 0o777).toString(8)}) ` +
          "— will not trust a git binary that could be tampered with after this check (round 7 hardening).",
      };
    }
    if (st.uid !== 0) {
      return {
        ok: false,
        path: null,
        detail: `refusing: "${candidate}" exists but is not owned by root (uid ${st.uid}) — will not trust ` +
          "a git binary an unprivileged (or attacker) process could have written (round 7 hardening).",
      };
    }
    return { ok: true, path: candidate, detail: `resolved to "${candidate}" (root-owned, not group/world-writable).` };
  }
  return {
    ok: false,
    path: null,
    detail:
      `refusing: neither ${candidates.join(" nor ")} exists — never falling back to a PATH-resolved "git" ` +
      "(round 7 hardening).",
  };
}

/** Environment variables whose mere PRESENCE in the process's original
 * environment is grounds for refusal — none of these has a legitimate
 * reason to be set for this CLI, and each is a known code-injection or
 * binary-substitution vector for a *nix process. Checked against the
 * ORIGINAL environment (never the scrubbed child env, which never
 * carries these anyway) because the risk is that ALREADY-RUNNING
 * PROCESS, not merely the child git commands. `GIT_EXEC_PATH` is a fixed
 * name; `LD_*` (round 8 follow-up: was a fixed two-name list —
 * `LD_PRELOAD`/`LD_LIBRARY_PATH` — the gate's own round-8 probe used
 * `LD_AUDIT` to load native code, which that list missed entirely) and
 * `DYLD_*` (macOS's dynamic-linker family — `DYLD_INSERT_LIBRARIES` is
 * the LD_PRELOAD equivalent) are both PREFIXES now, not fixed names. */
const RUNTIME_TAMPER_BLANKET_VARS = ["GIT_EXEC_PATH"] as const;
const RUNTIME_TAMPER_PREFIXES = ["LD_", "DYLD_"] as const;

/**
 * Round 8: `NODE_OPTIONS` is checked with an ALLOW-LIST of known-benign
 * flags, never a denylist of known-dangerous ones — round 7's denylist
 * (`--require`/`-r`/`--loader`/`--experimental-loader`/`--import`) missed
 * every other Node flag capable of doing something this tool should
 * refuse on (`--inspect*` opens a debugger port; `--env-file` reads
 * arbitrary attacker-chosen config into `process.env`; `--conditions`
 * changes package resolution; `--openssl-config`/`--use-openssl-ca`
 * changes TLS trust; `--preserve-symlinks*` changes module resolution;
 * any `--experimental-*` flag is by definition not vetted for this use).
 * A denylist can only ever be a list of what somebody already thought
 * of; an allow-list refuses everything not explicitly vetted, including
 * flags nobody has named an attack for yet. Every OTHER, non-flag token
 * (a bare value following a space-separated flag, e.g. the `8192` in
 * `--stack-size 8192`) is passed through untouched — it is not itself a
 * vector, and rejecting it would make legitimate space-separated flags
 * unusable. This environment's own ordinary shell sets a benign
 * `--max-old-space-size=8192` NODE_OPTIONS (confirmed this session),
 * which the allow-list below is built to pass. */
const NODE_OPTIONS_ALLOWED_EXACT = new Set<string>([
  "--no-warnings",
  "--enable-source-maps",
  "--trace-warnings",
]);
/** A token is allowed if its flag name (before any `=value`) is exactly
 * one of `NODE_OPTIONS_ALLOWED_EXACT`, OR starts with one of these
 * prefixes — covers `--max-old-space-size`, `--max-semi-space-size`, any
 * OTHER `--max-*` memory-limit flag, `--stack-size`, and
 * `--unhandled-rejections=<any value>`. */
const NODE_OPTIONS_ALLOWED_PREFIXES = ["--max-", "--stack-size", "--unhandled-rejections"] as const;

/** Splits a NODE_OPTIONS string into tokens the way Node itself does:
 * whitespace-separated, with single- or double-quoted spans kept intact
 * (so a quoted value containing a space is one token, quote characters
 * stripped). Good enough for THIS module's purpose — identifying flag
 * NAMES to check against the allow-list — without depending on Node's
 * own (unexported) parser. An unterminated quote simply consumes to the
 * end of the string as part of that token, which is a safe (more
 * restrictive, not less) default. */
export function tokenizeNodeOptions(nodeOptions: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  const n = nodeOptions.length;
  while (i < n) {
    while (i < n && /\s/.test(nodeOptions[i] ?? "")) i += 1;
    if (i >= n) break;
    let token = "";
    let quote: string | null = null;
    while (i < n) {
      const c = nodeOptions[i] ?? "";
      if (quote) {
        if (c === quote) {
          quote = null;
          i += 1;
          continue;
        }
        token += c;
        i += 1;
        continue;
      }
      if (c === '"' || c === "'") {
        quote = c;
        i += 1;
        continue;
      }
      if (/\s/.test(c)) break;
      token += c;
      i += 1;
    }
    tokens.push(token);
  }
  return tokens;
}

/** `true` when `token` is either not a flag at all (doesn't start with
 * `-` — a bare value following a space-separated flag, always passed
 * through) or a flag on the allow-list above. Everything else — every
 * flag NOT explicitly vetted, named or not — is refused. */
export function isNodeOptionTokenAllowed(token: string): boolean {
  if (!token.startsWith("-")) return true; // a value, not a flag — not itself a vector
  const eqIdx = token.indexOf("=");
  const flagName = eqIdx === -1 ? token : token.slice(0, eqIdx);
  if (NODE_OPTIONS_ALLOWED_EXACT.has(flagName)) return true;
  return NODE_OPTIONS_ALLOWED_PREFIXES.some((prefix) => flagName.startsWith(prefix));
}

export interface RuntimeTamperCheck {
  tampered: boolean;
  detail: string;
}

/**
 * ⛔ Round 8 correction — read this section's own banner comment above
 * FIRST: this is a TRIPWIRE FOR NAIVE, NON-SELF-HIDING INJECTION ONLY,
 * not a security boundary. It looks for evidence the VERDICT PROCESS
 * ITSELF — not merely the git commands it spawns — may already be
 * running attacker-injected code, which would make any "scrubbed
 * environment" this module builds for its own child processes
 * meaningless (the injected code runs inside THIS process and can patch
 * `child_process.execFile` before this module's own code ever executes).
 * A preload sophisticated enough to ALSO erase the very env vars/execArgv
 * this function reads (round 8's own gate fixture does exactly that,
 * confirmed this round) defeats it completely and unavoidably — see the
 * banner comment for why no in-process fix exists. INJECTED, never
 * reading `process.env`/`process.execArgv` directly — see the banner
 * comment for why (the test-only seam is `verifyAgainstGitHub`'s
 * `runtimeEnv`/`runtimeExecArgv` options; `main()` never overrides them,
 * so the live CLI always checks the REAL ones — for whatever that is
 * worth against a naive attempt).
 */
export function detectRuntimeTamper(env: NodeJS.ProcessEnv, execArgv: readonly string[]): RuntimeTamperCheck {
  for (const key of RUNTIME_TAMPER_BLANKET_VARS) {
    if (env[key] !== undefined) {
      return {
        tampered: true,
        detail: `refusing: ${key} is set in the verdict process's own environment — this can substitute or ` +
          "inject code into any binary this process (or a child it spawns) loads, making a \"scrubbed git " +
          "environment\" meaningless (tripwire only — see this module's own round 8 correction).",
      };
    }
  }
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) continue;
    const matchedPrefix = RUNTIME_TAMPER_PREFIXES.find((prefix) => key.startsWith(prefix));
    if (matchedPrefix) {
      return {
        tampered: true,
        detail:
          `refusing: ${key} is set in the verdict process's own environment — the ${matchedPrefix}* family can ` +
          "inject code into this process (LD_PRELOAD/LD_AUDIT and their macOS DYLD_* equivalents) the same way " +
          "on Linux/macOS (tripwire only — see this module's own round 8 correction).",
      };
    }
  }
  const nodeOptions = env.NODE_OPTIONS;
  if (nodeOptions !== undefined) {
    // No allow-listed flag ever needs quoting or escaping, and this tokenizer's
    // quote handling is not guaranteed to match Node's own NODE_OPTIONS parser
    // (round-9 re-gate). Refuse any quote or backslash outright so the two
    // parsers can never disagree about what the tokens are.
    if (/['"\\]/.test(nodeOptions)) {
      return {
        tampered: true,
        detail:
          `refusing: NODE_OPTIONS ("${nodeOptions}") contains a quote or backslash; none of the allow-listed ` +
          "flags needs one, so this tool refuses rather than guess how Node will tokenize it (tripwire only).",
      };
    }
    const tokens = tokenizeNodeOptions(nodeOptions);
    const badToken = tokens.find((t) => !isNodeOptionTokenAllowed(t));
    if (badToken !== undefined) {
      return {
        tampered: true,
        detail:
          `refusing: NODE_OPTIONS ("${nodeOptions}") carries "${badToken}", which is not on this tool's narrow ` +
          "allow-list of known-benign flags (--max-*/--stack-size/--unhandled-rejections/--no-warnings/" +
          "--enable-source-maps/--trace-warnings) — refusing by default rather than denylisting only the " +
          "flags already known to be dangerous (tripwire only — see this module's own round 8 correction).",
      };
    }
  }
  if (execArgv.length > 0) {
    return {
      tampered: true,
      detail:
        `refusing: process.execArgv is non-empty (${JSON.stringify(execArgv)}) — a plain "node <script>.js" ` +
        "invocation has an empty execArgv; flags passed directly to the node invocation itself (e.g. " +
        "--require=evil.cjs, or -e/--eval) are the same code-injection class as NODE_OPTIONS (tripwire only " +
        "— see this module's own round 8 correction).",
    };
  }
  return { tampered: false, detail: "no runtime-tamper indicators found (naive-injection tripwire only)." };
}

/** Per-command `-c` flags every disposable-repo git invocation carries:
 * no hooks (`core.hooksPath=/dev/null` — defeats a `.git/hooks/
 * reference-transaction` or similar running arbitrary code), no `file://`
 * or `ext::` transports (defeats a redirect to a local path or an
 * arbitrary shelled-out "remote helper") EXCEPT under the test-only seam
 * (`opts.repoUrl` in `verifyAgainstGitHub`), which needs `file://` to
 * point at a local bare repo standing in for GitHub with zero real
 * network access. `protocol.ext.allow` stays `never` unconditionally —
 * no seam ever needs it. */
function gitSafeConfigArgs(allowFileProtocol: boolean): string[] {
  return [
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    `protocol.file.allow=${allowFileProtocol ? "always" : "never"}`,
    "-c",
    "protocol.ext.allow=never",
  ];
}

/** Builds the EXPLICIT, minimal environment every disposable-repo git
 * command runs under — constructed from an empty object, never
 * `{...process.env}`. `HOME` and `GIT_DIR` are both pinned to `tmpDir`
 * (the disposable bare repo itself), so no ambient `~/.gitconfig`, and
 * no caller-set `GIT_DIR`/`GIT_WORK_TREE`, can point these commands at
 * anything else. `GIT_NO_REPLACE_OBJECTS=1` defeats exploit R;
 * `GIT_CONFIG_NOSYSTEM=1` + `GIT_CONFIG_GLOBAL=/dev/null` defeat
 * SYSTEM/global `insteadOf` redirection (exploit I). Round 7 hardening
 * (2): `PATH` is now the FIXED `FIXED_CHILD_PATH`, never taken from
 * `process.env` — a fake `git`, or any other shim, placed earlier on the
 * CALLER's own PATH can no longer reach these commands regardless of
 * what `resolveGitBinary` itself resolves (defense in depth: this env's
 * PATH is irrelevant once the binary is invoked by absolute path, but a
 * git subprocess or hook — even under `core.hooksPath=/dev/null` — could
 * still shell out to another PATH-resolved tool otherwise). */
const GIT_ENV_ALLOWLIST = [
  "HTTPS_PROXY",
  "https_proxy",
  "HTTP_PROXY",
  "http_proxy",
  "NO_PROXY",
  "no_proxy",
  "GIT_SSL_CAINFO",
  "SSL_CERT_FILE",
  "NODE_EXTRA_CA_CERTS",
] as const;

function scrubbedGitEnv(tmpDir: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of GIT_ENV_ALLOWLIST) {
    const v = process.env[key];
    if (v !== undefined) env[key] = v;
  }
  env.PATH = FIXED_CHILD_PATH;
  env.HOME = tmpDir;
  env.GIT_DIR = tmpDir;
  env.GIT_NO_REPLACE_OBJECTS = "1";
  env.GIT_CONFIG_NOSYSTEM = "1";
  env.GIT_CONFIG_GLOBAL = "/dev/null";
  return env;
}

async function runDisposableGit(
  gitBinary: string,
  tmpDir: string,
  allowFileProtocol: boolean,
  args: string[],
): Promise<{ stdout: string }> {
  const { stdout } = await execFileAsync(gitBinary, [...gitSafeConfigArgs(allowFileProtocol), ...args], {
    cwd: tmpDir,
    env: scrubbedGitEnv(tmpDir),
  });
  return { stdout };
}

/** The result of a `verifyAgainstGitHub` run — everything downstream
 * (`checkLedgerAgainstGit`, `resolveAcceptanceRecord`, `resolveWaybackRecord`
 * via `ledgerOfficial`) reads GitHub's own state ONLY through this
 * object, never by running its own git commands against the caller's
 * environment. `cleanup()` removes the disposable temp repo — callers
 * MUST call it (`main()` does so in a `finally`). */
export interface GitHubVerification {
  ok: boolean;
  /** Human-readable reason for `ok: false`, or a plain confirmation. */
  detail: string;
  /** `git rev-parse refs/heads/main:docs/p0/x2-recorded-ledger.json`,
   * read inside the disposable repo — `null` when verification failed or
   * GitHub main does not yet have that path. */
  ledgerBlobHash: string | null;
  /** Same, for `docs/p0/X2.md`. */
  x2MdBlobHash: string | null;
  /** `git show refs/heads/main:docs/p0/X2.md`'s own text, read inside
   * the disposable repo — the AUTHORITATIVE source for ACCEPT-row
   * matching (never the local working tree — see this section's own
   * banner comment). `null` when verification failed or the path does
   * not exist on GitHub main. */
  x2MdText: string | null;
  /** Blames `docs/p0/X2.md` at `lineNumber` directly against
   * `refs/heads/main` INSIDE the disposable repo. Because the blame
   * target IS that ref, whatever commit it finds is by construction
   * already part of that ref's own history — `reachableFromVerifiedMain`
   * is therefore always `true` when `ok` is `true` here; there is no
   * separate ancestor check left to subvert (round 6's own
   * simplification). */
  blameX2MdLine: (
    lineNumber: number,
  ) => Promise<{ ok: true; provenance: AcceptRowGitProvenance } | { ok: false; detail: string }>;
  /** Removes the disposable temp repo. Safe to call more than once;
   * never throws. */
  cleanup: () => Promise<void>;
}

function failedGitHubVerification(detail: string, tmpDir: string | null): GitHubVerification {
  return {
    ok: false,
    detail,
    ledgerBlobHash: null,
    x2MdBlobHash: null,
    x2MdText: null,
    blameX2MdLine: async () => ({
      ok: false,
      detail: "GitHub verification did not succeed this run — nothing is trusted.",
    }),
    cleanup: async () => {
      if (tmpDir) await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    },
  };
}

/**
 * Gate finding (fourth re-gate, Addendum J round 6; hardened seventh
 * re-gate): the ONLY function in this module that touches the network,
 * and the ONLY place any GitHub-verification git command ever runs —
 * always at a resolved, root-owned absolute path (round 7), always
 * inside a fresh disposable bare repo, always under `scrubbedGitEnv`
 * (round 7: a FIXED child PATH, never the caller's). See this section's
 * own banner comment for the full rationale and the exploits
 * (I/R/G/GIT_DIR/hooks/PATH/NODE_OPTIONS/LD_PRELOAD) this closes. Never
 * throws: any failure (runtime tamper, an untrusted git binary, a
 * redirected fetch canary, `sslVerify` disabled, a shallow result, a
 * `grafts`/`replace` finding, a network error) comes back as
 * `{ok: false}` — the caller then treats the run as UNOFFICIAL, never
 * OFFICIAL.
 *
 * `opts.repoUrl` and `opts.gitBinary` are TEST-ONLY seams: `main()`
 * NEVER passes either (no CLI flag reaches this function's own
 * arguments), so the only way to point this at something other than the
 * real, pinned GitHub URL and a resolved system `git` — and the only way
 * `protocol.file.allow` is ever relaxed — is to call this directly from
 * test code, never through the shipped CLI. `opts.runtimeEnv`/
 * `opts.runtimeExecArgv` are a SEPARATE test-only seam for
 * `detectRuntimeTamper` alone (see this section's own banner comment for
 * why it needs one) — default to the REAL `process.env`/`process.execArgv`,
 * which `main()` always gets.
 */
export async function verifyAgainstGitHub(
  opts: {
    repoUrl?: string;
    gitBinary?: string;
    runtimeEnv?: NodeJS.ProcessEnv;
    runtimeExecArgv?: readonly string[];
  } = {},
): Promise<GitHubVerification> {
  const repoUrl = opts.repoUrl ?? GOLFRAVEN_CANONICAL_REPO_URL;
  const allowFileProtocol = opts.repoUrl !== undefined;
  const runtimeEnv = opts.runtimeEnv ?? process.env;
  const runtimeExecArgv = opts.runtimeExecArgv ?? process.execArgv;

  // Round 7 hardening (3), checked FIRST: if the VERDICT PROCESS ITSELF
  // shows signs of runtime tampering, nothing else this function does
  // can be trusted — injected code can patch child_process.execFile
  // before any of the checks below ever run.
  const tamper = detectRuntimeTamper(runtimeEnv, runtimeExecArgv);
  if (tamper.tampered) {
    return failedGitHubVerification(tamper.detail, null);
  }

  // Checked BEFORE even creating the temp dir: an original environment
  // that has already disabled TLS verification for git makes any fetch
  // below untrustworthy regardless of what the disposable repo does.
  if (runtimeEnv.GIT_SSL_NO_VERIFY !== undefined) {
    return failedGitHubVerification(
      "refusing: GIT_SSL_NO_VERIFY is set in this process's own environment — a fetch under a disabled-TLS-" +
        "verification environment cannot be trusted as genuinely from GitHub (fourth re-gate).",
      null,
    );
  }

  // Round 7 hardening (1): resolve git to a verified, root-owned,
  // non-writable ABSOLUTE path — never the bare string "git", which a
  // fake shim earlier on PATH (or a rewritten PATH) would silently
  // satisfy via `execFileAsync`'s own PATH lookup.
  const gitResolution = resolveGitBinary(opts.gitBinary);
  if (!gitResolution.ok || !gitResolution.path) {
    return failedGitHubVerification(gitResolution.detail, null);
  }
  const gitBinary = gitResolution.path;

  let tmpDir: string | null = null;
  try {
    tmpDir = await mkdtemp(path.join(os.tmpdir(), "x2-verdict-verify-"));
    await execFileAsync(gitBinary, ["init", "--quiet", "--bare", tmpDir], {
      env: scrubbedGitEnv(tmpDir),
    });

    // Step 3: `git ls-remote --get-url` resolves git's OWN config
    // rewriting logic (insteadOf, local/global/SYSTEM config, and the
    // GIT_CONFIG_COUNT/KEY_n/VALUE_n env-var channel) WITHOUT making a
    // network connection — the canary that catches exploit I before any
    // fetch happens. `scrubbedGitEnv` has already dropped every
    // GIT_CONFIG_* variable from the caller's own env and pointed
    // GIT_CONFIG_GLOBAL at /dev/null with GIT_CONFIG_NOSYSTEM=1, so this
    // check is really asserting those took effect, belt-and-braces.
    const { stdout: resolvedUrl } = await runDisposableGit(gitBinary, tmpDir, allowFileProtocol, [
      "ls-remote",
      "--get-url",
      repoUrl,
    ]);
    if (resolvedUrl.trim() !== repoUrl) {
      return failedGitHubVerification(
        `refusing: "git ls-remote --get-url ${repoUrl}" resolved to "${resolvedUrl.trim()}" instead of the ` +
          "URL itself — this means some config is rewriting the URL (insteadOf, via local/global/SYSTEM " +
          "config or GIT_CONFIG_COUNT/KEY/VALUE env vars) even inside the scrubbed environment (fourth " +
          "re-gate, exploit I).",
        tmpDir,
      );
    }

    // Refuse if the ORIGINAL environment's git config resolves
    // http.sslVerify to false — a caller-set `-c http.sslVerify=false`
    // (or GIT_SSL_NO_VERIFY, checked above) means TLS was not actually
    // verified for whatever proxy/MITM sits between here and GitHub.
    // Deliberately uses the ORIGINAL (unscrubbed) environment — this is
    // asking "does the ambient config disable verification," not asking
    // the disposable repo's own (scrubbed, GIT_CONFIG_GLOBAL=/dev/null)
    // config — but still through the resolved, trusted absolute path.
    try {
      const { stdout } = await execFileAsync(gitBinary, ["config", "--get", "http.sslVerify"]);
      if (stdout.trim() === "false") {
        return failedGitHubVerification(
          "refusing: this environment's own git config resolves http.sslVerify to false — a fetch under " +
            "disabled TLS verification cannot be trusted as genuinely from GitHub (fourth re-gate).",
          tmpDir,
        );
      }
    } catch {
      // No such config key set anywhere — the normal, expected case
      // (verification defaults to on); nothing to refuse.
    }

    // Step 4: fetch `main` with FULL history (no --depth) into the
    // disposable repo's own refs/heads/main.
    try {
      await runDisposableGit(gitBinary, tmpDir, allowFileProtocol, [
        "fetch",
        "--no-tags",
        repoUrl,
        "+refs/heads/main:refs/heads/main",
      ]);
    } catch (err) {
      return failedGitHubVerification(
        `fetching main from ${repoUrl} failed: ${err instanceof Error ? err.message : String(err)}`,
        tmpDir,
      );
    }

    // Refuse a shallow result outright — a shallow boundary commit can
    // misrepresent ancestor-reachability.
    try {
      const { stdout } = await runDisposableGit(gitBinary, tmpDir, allowFileProtocol, [
        "rev-parse",
        "--is-shallow-repository",
      ]);
      if (stdout.trim() === "true") {
        return failedGitHubVerification(
          "refusing: the fetched repository is shallow (--is-shallow-repository) — a shallow boundary commit " +
            "can misrepresent ancestor-reachability (fourth re-gate).",
          tmpDir,
        );
      }
    } catch (err) {
      return failedGitHubVerification(
        `could not check --is-shallow-repository: ${err instanceof Error ? err.message : String(err)}`,
        tmpDir,
      );
    }

    // Belt-and-braces (this is a brand-new disposable repo, so neither
    // should be reachable at all — but check anyway, cheaply, in case a
    // future change to this function ever reuses a repo or a git
    // implementation detail smuggles one in).
    try {
      await access(path.join(tmpDir, "info", "grafts"));
      return failedGitHubVerification(
        "refusing: the disposable verification repo has an info/grafts file (belt-and-braces — this should " +
          "be unreachable in a fresh repo; fourth re-gate, exploit G).",
        tmpDir,
      );
    } catch {
      // Expected: no grafts file.
    }
    try {
      const { stdout } = await runDisposableGit(gitBinary, tmpDir, allowFileProtocol, ["for-each-ref", "refs/replace/"]);
      if (stdout.trim().length > 0) {
        return failedGitHubVerification(
          "refusing: the disposable verification repo has refs/replace/* entries (belt-and-braces — should " +
            "be unreachable in a fresh repo with GIT_NO_REPLACE_OBJECTS=1; fourth re-gate, exploit R).",
          tmpDir,
        );
      }
    } catch (err) {
      return failedGitHubVerification(
        `could not list refs/replace/: ${err instanceof Error ? err.message : String(err)}`,
        tmpDir,
      );
    }

    // Step 5: read the ledger and X2.md CONTENT straight from
    // refs/heads/main's own tree — never the local working tree.
    let ledgerBlobHash: string | null = null;
    try {
      const { stdout } = await runDisposableGit(gitBinary, tmpDir, allowFileProtocol, [
        "rev-parse",
        `refs/heads/main:${CANONICAL_LEDGER_REPO_RELATIVE_PATH}`,
      ]);
      ledgerBlobHash = stdout.trim();
    } catch {
      ledgerBlobHash = null; // GitHub main simply doesn't have this path yet.
    }
    let x2MdBlobHash: string | null = null;
    let x2MdText: string | null = null;
    try {
      const { stdout } = await runDisposableGit(gitBinary, tmpDir, allowFileProtocol, [
        "rev-parse",
        `refs/heads/main:${CANONICAL_X2MD_REPO_RELATIVE_PATH}`,
      ]);
      x2MdBlobHash = stdout.trim();
      const { stdout: text } = await runDisposableGit(gitBinary, tmpDir, allowFileProtocol, [
        "show",
        `refs/heads/main:${CANONICAL_X2MD_REPO_RELATIVE_PATH}`,
      ]);
      x2MdText = text;
    } catch {
      x2MdBlobHash = null;
      x2MdText = null;
    }

    const finalTmpDir = tmpDir;
    const blameX2MdLine = async (
      lineNumber: number,
    ): Promise<{ ok: true; provenance: AcceptRowGitProvenance } | { ok: false; detail: string }> => {
      let sha: string;
      try {
        const { stdout } = await runDisposableGit(gitBinary, finalTmpDir, allowFileProtocol, [
          "blame",
          "-L",
          `${lineNumber},${lineNumber}`,
          "--porcelain",
          "refs/heads/main",
          "--",
          CANONICAL_X2MD_REPO_RELATIVE_PATH,
        ]);
        const firstLine = stdout.split("\n")[0] ?? "";
        const candidate = firstLine.split(" ")[0] ?? "";
        if (!/^[0-9a-f]{40}$/.test(candidate)) {
          return {
            ok: false,
            detail: `git blame did not return a commit hash for line ${lineNumber} of GitHub main's own docs/p0/X2.md (got: ${JSON.stringify(firstLine)}).`,
          };
        }
        sha = candidate;
      } catch (err) {
        return { ok: false, detail: `git blame failed: ${err instanceof Error ? err.message : String(err)}` };
      }
      let author = "";
      let authorDate = "";
      let signatureStatus = "";
      try {
        const { stdout } = await runDisposableGit(gitBinary, finalTmpDir, allowFileProtocol, [
          "show",
          "-s",
          "--format=%an%x1f%aI%x1f%G?",
          sha,
        ]);
        const [an, aI, gStatus] = stdout.trim().split("\x1f");
        author = an ?? "";
        authorDate = aI ?? "";
        signatureStatus = gStatus ?? "";
      } catch (err) {
        return {
          ok: false,
          detail: `git show failed for commit ${sha}: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
      // Reachability is TRUE BY CONSTRUCTION: this blame ran directly
      // against refs/heads/main, so whatever commit it found is already
      // part of that ref's own history — no separate merge-base
      // --is-ancestor step exists to subvert (round 6's simplification;
      // see this section's own banner comment).
      return {
        ok: true,
        provenance: { commit: sha, author, authorDate, signatureStatus, reachableFromVerifiedMain: true },
      };
    };

    return {
      ok: true,
      detail: `verified against GitHub main (${repoUrl}), disposable repo + scrubbed environment.`,
      ledgerBlobHash,
      x2MdBlobHash,
      x2MdText,
      blameX2MdLine,
      cleanup: async () => {
        await rm(finalTmpDir, { recursive: true, force: true }).catch(() => {});
      },
    };
  } catch (err) {
    return failedGitHubVerification(
      `unexpected error verifying against GitHub: ${err instanceof Error ? err.message : String(err)}`,
      tmpDir,
    );
  }
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
export interface ResolveCorroborationOptions {
  /** This trail's own evidence (as `buildEvidenceByTrail` already
   * produced it) — needed to look up an owner-saved fact's stated URL
   * and `ownerSavedDate` for Wayback re-validation (gate finding 3,
   * second re-gate), and to confirm a corroboration record is actually
   * attached to an owner-saved fact in the first place. */
  evidenceByTrail: EvidenceByTrail;
  /** Reads a file's raw bytes, relative to `evidenceDir` — same
   * dependency-injection principle as everywhere else in this tool
   * family (real files for the CLI, in-memory for tests). */
  readRaw: (relPath: string) => Promise<Buffer>;
  /** The evidence directory `rawFile` paths are relative to — needed to
   * resolve a `wayback` record's `rawFile` and refuse any path escape
   * (gate finding 3, second re-gate). */
  evidenceDir: string;
  /** The canonical recorded-captures ledger — a `wayback` record must be
   * registered in it under method `"wayback"` (gate finding 3, second
   * re-gate) for its corroboration to count at all; `x2-corroborate-
   * wayback` is the only tool that writes such an entry. */
  ledger: RecordedLedger;
  /** Gate finding, should-fix (fourth re-gate): whether THIS RUN's ledger
   * itself resolved OFFICIAL (`checkLedgerAgainstGit(...).clean`) —
   * threaded through from `main()`. A Wayback corroboration can only be
   * trusted when the ledger registering it is itself verified against
   * GitHub main (see `resolveWaybackRecord`'s own gate). */
  ledgerOfficial: boolean;
  /** Local `docs/p0/X2.md` — used ONLY to confirm `--x2-log` points at
   * the toolkit's own canonical file (fix (a), below); its CONTENT is
   * never trusted — `acceptance` records are matched against
   * `githubVerification.x2MdText` instead (GitHub main's own text, gate
   * finding fourth re-gate). `null` when the local file could not be
   * read at all — every `acceptance` record then resolves to "not
   * logged," the safe default. */
  x2Md: { fullText: string; path: string } | null;
  /** TEST-ONLY seam (gate finding, third re-gate, fix (a)) — `main()`
   * never overrides this; defaults to `canonicalX2MdAbsPath()`. An
   * `acceptance` record's `x2Md.path` must resolve (`realpath`) to
   * EXACTLY this for `acceptanceLogged` to ever be `true` — no matter
   * how well-formed its content looks, an `ACCEPT` row is only ever
   * trusted from the toolkit's own canonical X2.md. Exists so tests can
   * exercise the canonical-path-match logic against an isolated scratch
   * fixture. */
  canonicalX2MdPath?: string;
  /** Gate finding, fourth re-gate: the pre-computed `GitHubVerification`
   * this call (or `checkLedgerAgainstGit`) reads GitHub main's own
   * content and blame through — `main()` computes this ONCE per run
   * (`verifyAgainstGitHub()`) and threads it through everywhere; a test
   * builds its own (real, against a local bare repo via `repoUrl`, or a
   * hand-built fake). `null` only when verification was never run at
   * all (distinct from `ok: false`, which is a verification that ran and
   * failed) — every `acceptance` record then refuses outright. */
  githubVerification: GitHubVerification | null;
}

async function resolveWaybackRecord(
  trail: string,
  evidenceSha: string,
  record: X2WaybackCorroboration,
  opts: ResolveCorroborationOptions,
): Promise<ResolvedCorroborationEntry> {
  // Should-fix (fourth re-gate): a Wayback corroboration can only be
  // trusted when THIS RUN's own ledger is OFFICIAL (verified against
  // GitHub main) — round 5's exploit A3 (a self-authored `method:
  // "wayback"` ledger row plus local ref forgery) still reported
  // `waybackVerified: true` under an UNOFFICIAL ledger header, because
  // this function only ever checked the ledger's CONTENT (does it have a
  // matching row?), never whether that ledger was itself trustworthy.
  if (!opts.ledgerOfficial) {
    return {
      waybackVerified: false,
      waybackDetail:
        "this run's ledger is not OFFICIAL (verified against GitHub main) — a Wayback corroboration can " +
        "only be trusted when the ledger registering it is (should-fix, fourth re-gate).",
    };
  }
  // Gate finding 3 (second re-gate): the verdict RE-VALIDATES every rule
  // itself — never trusts that a record shaped like a wayback record was
  // actually produced by `x2-corroborate-wayback`.
  const ownerEntry = opts.evidenceByTrail[trail]?.bySha.get(evidenceSha);
  if (!ownerEntry || ownerEntry.method !== "owner-saved") {
    return {
      waybackVerified: false,
      waybackDetail:
        "this record's evidenceSha is not an owner-saved fact in this trail's own evidence — a Wayback " +
        "record can only corroborate an owner-saved fact.",
    };
  }
  const parsed = parseWaybackUrl(record.snapshotUrl);
  if (!parsed) {
    return {
      waybackVerified: false,
      waybackDetail:
        `snapshotUrl "${record.snapshotUrl}" is not in the required ` +
        '"https://web.archive.org/web/<14-digit timestamp>/<url>" form.',
    };
  }
  let embeddedNormalized: string;
  try {
    embeddedNormalized = normalizeUrlForFirstCapture(parsed.embeddedUrl);
  } catch {
    return {
      waybackVerified: false,
      waybackDetail: `the archive URL's embedded URL "${parsed.embeddedUrl}" is not a valid URL.`,
    };
  }
  let statedNormalized: string;
  try {
    statedNormalized = normalizeUrlForFirstCapture(ownerEntry.url);
  } catch {
    return {
      waybackVerified: false,
      waybackDetail: `the owner-saved fact's own stated URL "${ownerEntry.url}" is not a valid URL.`,
    };
  }
  if (embeddedNormalized !== statedNormalized) {
    return {
      waybackVerified: false,
      waybackDetail:
        `the archive URL's embedded URL ("${parsed.embeddedUrl}", normalises to "${embeddedNormalized}") does ` +
        `not match the owner-saved fact's own stated URL ("${ownerEntry.url}", normalises to ` +
        `"${statedNormalized}") — a snapshot of a DIFFERENT page can never corroborate this fact.`,
    };
  }
  if (!ownerEntry.ownerSavedDate) {
    return {
      waybackVerified: false,
      waybackDetail:
        "the owner-saved fact has no ownerSavedDate recorded — the ±90-day tolerance cannot be checked.",
    };
  }
  let snapshotDate: Date;
  try {
    snapshotDate = waybackTimestampToDate(parsed.timestamp);
  } catch {
    return {
      waybackVerified: false,
      waybackDetail: `snapshot timestamp "${parsed.timestamp}" is not a real calendar date/time.`,
    };
  }
  const [y, mo, d] = ownerEntry.ownerSavedDate.split("-").map(Number);
  if (
    y === undefined ||
    mo === undefined ||
    d === undefined ||
    Number.isNaN(y) ||
    Number.isNaN(mo) ||
    Number.isNaN(d)
  ) {
    return {
      waybackVerified: false,
      waybackDetail: `the owner-saved fact's ownerSavedDate "${ownerEntry.ownerSavedDate}" is not YYYY-MM-DD.`,
    };
  }
  const ownerSavedDateObj = new Date(Date.UTC(y, mo - 1, d));
  const gapDays = daysBetween(snapshotDate, ownerSavedDateObj);
  if (gapDays > WAYBACK_TIMESTAMP_TOLERANCE_DAYS) {
    return {
      waybackVerified: false,
      waybackDetail:
        `the snapshot's timestamp (${parsed.timestamp}) is ${gapDays.toFixed(1)} days from the owner-saved ` +
        `fact's own ownerSavedDate (${ownerEntry.ownerSavedDate}) — outside the ` +
        `${WAYBACK_TIMESTAMP_TOLERANCE_DAYS}-day tolerance.`,
    };
  }
  // Gate finding 3 (second re-gate): `rawFile` must resolve, INSIDE the
  // evidence dir, to exactly `raw/<snapshotSha256>.<ext>` — refuses a
  // path-escape attempt (e.g. `../../outside.html`) outright, since that
  // shape can never match this regex at all.
  const normalizedRawFile = record.rawFile.split(path.sep).join("/");
  const rawFileMatch = /^raw\/([0-9a-f]{64})\.[A-Za-z0-9]+$/.exec(normalizedRawFile);
  if (!rawFileMatch || rawFileMatch[1] !== record.snapshotSha256) {
    return {
      waybackVerified: false,
      waybackDetail:
        `rawFile "${record.rawFile}" is not in the required "raw/<snapshotSha256>.<ext>" shape (or its ` +
        "embedded hash does not match snapshotSha256) — refusing rather than trusting an arbitrary path.",
    };
  }
  const resolvedDir = path.resolve(opts.evidenceDir);
  const resolvedRaw = path.resolve(opts.evidenceDir, record.rawFile);
  if (resolvedRaw !== path.join(resolvedDir, ...normalizedRawFile.split("/"))) {
    return {
      waybackVerified: false,
      waybackDetail: `rawFile "${record.rawFile}" resolves outside the evidence directory — refusing (path escape).`,
    };
  }
  // Gate finding 3 (second re-gate): the snapshot's own SHA must DIFFER
  // from the owner-saved fact's own SHA — an identical SHA means the
  // "corroboration" is just the owner-saved bytes relabelled as their own
  // independent check, never a genuine second, independent capture.
  if (record.snapshotSha256 === evidenceSha) {
    return {
      waybackVerified: false,
      waybackDetail:
        "the snapshot's SHA-256 is IDENTICAL to the owner-saved fact's own SHA — a genuine, independent " +
        "Wayback snapshot is a distinct capture of the page, never byte-identical to the owner's own save.",
    };
  }
  // Gate finding 3 (second re-gate): the snapshot must be registered in
  // the canonical ledger under method "wayback" — `x2-corroborate-
  // wayback` is the only tool that writes such an entry, so its presence
  // is evidence this record was produced by that tool's real fetch
  // pipeline, not hand-crafted.
  const ledgerHasWayback = opts.ledger.entries.some(
    (le) =>
      le.method === "wayback" &&
      le.sha256 === record.snapshotSha256 &&
      le.normalizedUrl === embeddedNormalized,
  );
  if (!ledgerHasWayback) {
    return {
      waybackVerified: false,
      waybackDetail:
        `no ledger entry registers this snapshot (sha256 ${record.snapshotSha256.slice(0, 12)}..., url ` +
        `"${embeddedNormalized}") under method "wayback" — a Wayback corroboration must come from x2-` +
        "corroborate-wayback (which registers the ledger entry itself), never a hand-crafted record.",
    };
  }
  try {
    const raw = await opts.readRaw(record.rawFile);
    const recomputed = createHash("sha256").update(raw).digest("hex");
    if (recomputed !== record.snapshotSha256) {
      return {
        waybackVerified: false,
        waybackDetail: "the raw bytes at rawFile do not recompute to the cited snapshotSha256.",
      };
    }
    const { text } = await extractEvidenceText(raw, "text/html", record.snapshotUrl);
    return { waybackVerified: true, waybackText: text, waybackDetail: "verified." };
  } catch (err) {
    return {
      waybackVerified: false,
      waybackDetail: `could not read/verify rawFile: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/** `YYYY-MM-DD` -> a UTC-midnight `Date`, or `null` if not a real
 * calendar date — used by both should-fix date rules below. */
function parseYmdStrict(s: string): Date | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  if (!m) return null;
  const [, yStr, moStr, dStr] = m;
  const y = Number(yStr);
  const mo = Number(moStr);
  const d = Number(dStr);
  const date = new Date(Date.UTC(y, mo - 1, d));
  if (date.getUTCFullYear() !== y || date.getUTCMonth() !== mo - 1 || date.getUTCDate() !== d) return null;
  return date;
}

async function resolveAcceptanceRecord(
  trail: string,
  evidenceSha: string,
  record: X2AcceptanceCorroboration,
  opts: ResolveCorroborationOptions,
): Promise<ResolvedCorroborationEntry> {
  // Gate finding, fourth re-gate: no verified GitHub state at all —
  // never OFFICIAL. Distinguished from a verification that ran and
  // failed, purely for a clearer message.
  if (!opts.githubVerification) {
    return { acceptanceLogged: false, acceptanceDetail: "GitHub verification was never run this call." };
  }
  if (!opts.githubVerification.ok) {
    return {
      acceptanceLogged: false,
      acceptanceDetail: `GitHub verification did not succeed this run: ${opts.githubVerification.detail}`,
    };
  }
  if (!opts.x2Md) {
    return { acceptanceLogged: false, acceptanceDetail: "docs/p0/X2.md could not be read locally." };
  }
  // Gate finding, third re-gate, fix (a): an `ACCEPT` row is only ever
  // trusted when `--x2-log` POINTS at the TOOLKIT'S OWN canonical X2.md
  // — never from a `--x2-log` pointed at a scratch/forged copy
  // elsewhere. This is now purely a path check: the row's CONTENT is
  // read from `githubVerification.x2MdText` (GitHub main's own text),
  // never from `opts.x2Md.fullText` (gate finding, fourth re-gate — this
  // also neutralises a symlinked-docs/p0 trick, since the local file's
  // content no longer matters for what is trusted).
  const expectedX2MdPath = opts.canonicalX2MdPath ?? canonicalX2MdAbsPath();
  const x2MdIsCanonical = await isCanonicalPath(opts.x2Md.path, expectedX2MdPath);
  if (!x2MdIsCanonical) {
    return {
      acceptanceLogged: false,
      acceptanceDetail:
        `"${opts.x2Md.path}" is not this toolkit's own canonical docs/p0/X2.md (resolved: ` +
        `"${expectedX2MdPath}") — an acceptance is only ever trusted from there (gate finding, third ` +
        "re-gate, fix (a)).",
    };
  }
  // Gate finding, third re-gate, fix (c) / should-fix (fourth re-gate):
  // only a VISIBLE row counts — `findAcceptRowLine` skips fenced code
  // blocks, HTML comments (including multi-line), indented code blocks,
  // and (fourth re-gate) any line inside a raw HTML block or carrying a
  // `hidden`/`style` attribute. Matched against GitHub main's OWN text.
  const githubText = opts.githubVerification.x2MdText ?? "";
  const match = findAcceptRowLine(githubText, trail, record.fact, evidenceSha, record.date);
  if (!match) {
    return {
      acceptanceLogged: false,
      acceptanceDetail:
        `no VISIBLE line reading exactly "${acceptRowLiteral(trail, record.fact, evidenceSha, record.date)}" ` +
        'was found in GitHub main\'s own "## Log" section (a row hidden inside a fenced code block, an HTML ' +
        "comment/block, or an indented code block does not count).",
    };
  }
  // Gate finding, fourth re-gate: blame runs directly against
  // `refs/heads/main` inside the disposable, scrubbed-environment repo —
  // the matched commit is reachable from GitHub main BY CONSTRUCTION
  // (see `GitHubVerification.blameX2MdLine`'s own doc), so there is no
  // separate ancestor check left here.
  const blame = await opts.githubVerification.blameX2MdLine(match.lineNumber);
  if (!blame.ok) {
    return { acceptanceLogged: false, acceptanceDetail: blame.detail };
  }
  // Should-fix: the acceptance date must be on/after the evidence's own
  // ownerSavedDate (an acceptance cannot predate the thing it accepts)
  // and no more than 1 day after the commit that introduced the row (a
  // forged future-dated acceptance, or a row whose commit postdates its
  // own claimed date by more than a day, is suspicious rather than
  // simply trusted).
  const recordDate = parseYmdStrict(record.date);
  if (!recordDate) {
    return {
      acceptanceLogged: false,
      acceptanceProvenance: blame.provenance,
      acceptanceDetail: `acceptance date "${record.date}" is not a real YYYY-MM-DD calendar date.`,
    };
  }
  const ownerSavedDateRaw = opts.evidenceByTrail[trail]?.bySha.get(evidenceSha)?.ownerSavedDate ?? null;
  if (ownerSavedDateRaw) {
    const ownerSavedDate = parseYmdStrict(ownerSavedDateRaw);
    if (ownerSavedDate && recordDate.getTime() < ownerSavedDate.getTime()) {
      return {
        acceptanceLogged: false,
        acceptanceProvenance: blame.provenance,
        acceptanceDetail:
          `acceptance date ${record.date} is BEFORE the evidence's own ownerSavedDate ${ownerSavedDateRaw} — ` +
          "an acceptance cannot predate the evidence it accepts (should-fix, third re-gate).",
      };
    }
  }
  const commitDate = new Date(blame.provenance.authorDate);
  if (!Number.isNaN(commitDate.getTime())) {
    const commitDatePlusOneDay = new Date(commitDate.getTime() + 24 * 60 * 60 * 1000);
    if (recordDate.getTime() > commitDatePlusOneDay.getTime()) {
      return {
        acceptanceLogged: false,
        acceptanceProvenance: blame.provenance,
        acceptanceDetail:
          `acceptance date ${record.date} is more than 1 day after the commit date (${blame.provenance.authorDate}) ` +
          "that introduced this Log row (should-fix, third re-gate).",
      };
    }
  }
  return {
    acceptanceLogged: true,
    acceptanceProvenance: blame.provenance,
    acceptanceDetail: `logged in GitHub main's own X2.md Log section (commit ${blame.provenance.commit}).`,
  };
}

/**
 * Gate finding 3 (re-gate)/finding 2 (re-gate): the verification pass
 * that makes a `X2CorroborationFile` trustworthy — run ONCE, before
 * `computeX2Verdict`, never inside it (keeping that function pure/
 * synchronous). See `resolveWaybackRecord`/`resolveAcceptanceRecord` for
 * the per-type rules. Never throws on a per-record failure — a record
 * that fails resolution just resolves to "unverified"/"not logged", which
 * `checkOwnerSavedCorroboration` then correctly refuses to count.
 */
export async function resolveCorroboration(
  corroboration: X2CorroborationFile,
  opts: ResolveCorroborationOptions,
): Promise<X2ResolvedCorroboration> {
  const resolved: X2ResolvedCorroboration = new Map();
  for (const [trail, trailRecords] of Object.entries(corroboration)) {
    for (const [evidenceSha, records] of Object.entries(trailRecords)) {
      for (const record of records) {
        if (record.type === "wayback") {
          const key = corroborationResolutionKey(trail, evidenceSha);
          resolved.set(key, await resolveWaybackRecord(trail, evidenceSha, record, opts));
        } else {
          // Gate finding 2 (re-gate): keyed by (trail, evidenceSha,
          // record.fact) — several acceptance records can share one
          // (trail, evidenceSha) pair, one per fact.
          const key = corroborationResolutionKey(trail, evidenceSha, record.fact);
          resolved.set(key, await resolveAcceptanceRecord(trail, evidenceSha, record, opts));
        }
      }
    }
  }
  return resolved;
}

/** Gate finding 3 (re-gate)/finding 2 (re-gate): extracts just the
 * `## Log` section's text from a full `docs/p0/X2.md` read — bounded at
 * the NEXT top-level `## ` heading (should-fix, second re-gate: the old
 * version matched to end-of-file unconditionally, which happened to be
 * right only because Log was always the last section in practice — a
 * section added after Log would have been silently swept in too).
 * Returns the WHOLE file's text if no `## Log` heading is found, rather
 * than silently treating "no Log section" as "nothing is logged" — a
 * missing section is itself a shape worth surfacing as a search-scope
 * difference, not hidden behind an empty-string match-nothing result. */
export function extractX2MdLogSection(x2MdText: string): string {
  const startMatch = /^## Log\b/m.exec(x2MdText);
  if (!startMatch) return x2MdText;
  const start = startMatch.index;
  const afterHeading = start + startMatch[0].length;
  const rest = x2MdText.slice(afterHeading);
  const nextHeadingMatch = /\n## /.exec(rest);
  const end = nextHeadingMatch ? afterHeading + nextHeadingMatch.index + 1 : x2MdText.length;
  return x2MdText.slice(start, end);
}

/** Gate finding 2 (re-gate): the exact literal Log row an `acceptance`
 * corroboration record must be backed by — see `X2AcceptanceCorroboration`'s
 * own doc for the full rationale. */
export function acceptRowLiteral(trail: string, fact: string, evidenceSha: string, date: string): string {
  return `ACCEPT ${trail} ${fact} ${evidenceSha} ${date} Matt`;
}

/** One matched `ACCEPT …` row, with its 1-based line number IN THE FULL
 * FILE (not just the Log section) — handed straight to `git blame`. */
export interface AcceptRowMatch {
  lineNumber: number;
  line: string;
}

/** CommonMark's own list of block-level tag names (the "type 6" HTML
 * block condition) — a line starting (after up to 3 leading spaces) with
 * `<` or `</` followed by one of these, then a space/tab/`>`/`/>`/EOL,
 * opens a raw HTML block that swallows every following line up to (not
 * including) the next blank line. Should-fix, fourth re-gate: "treat
 * `<details>`, any line inside a raw HTML block ... as hidden." */
const HTML_BLOCK_TAG_NAMES =
  "address|article|aside|base|basefont|blockquote|body|button|canvas|caption|center|col|colgroup|dd|" +
  "details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h1|h2|h3|h4|h5|" +
  "h6|head|header|hr|html|iframe|legend|li|link|main|menu|menuitem|nav|noframes|ol|optgroup|option|p|" +
  "param|section|summary|table|tbody|td|template|textarea|tfoot|th|thead|title|tr|track|ul";
const HTML_BLOCK_OPEN_RE = new RegExp(`^ {0,3}</?(${HTML_BLOCK_TAG_NAMES})(?:[ \\t>]|/>|$)`, "i");

/** Round 7 follow-up: `<details>` gets its OWN, stricter tracking —
 * hidden from its opening tag all the way to its OWN closing
 * `</details>`, even across blank lines, unlike every other HTML block
 * above (which CommonMark ends at the next blank line). GitHub's own
 * renderer keeps a `<details>` section collapsed across internal blank
 * lines/paragraph breaks, so ending the hidden-tracking at the first
 * blank line (the generic rule) would let a forged row placed after
 * such a blank line — but still visually inside the collapsed section
 * on GitHub — read as "visible" here. */
const DETAILS_OPEN_RE = /^ {0,3}<details(?:[ \t>]|\/>|$)/i;
const DETAILS_CLOSE_RE = /<\/details\s*>/i;

/** Should-fix, fourth re-gate: a `hidden` or `style` HTML attribute
 * anywhere on a line marks JUST THAT LINE invisible, independent of the
 * block-level state above (a one-line `<span hidden>ACCEPT ...</span>`
 * or a `style="display:none"` row is never inside a "block" by the
 * CommonMark rule above, but is exactly the hidden-row shape the gate
 * asked to close). Matches a `<tag ... hidden ...>` or `<tag ...
 * style=...>` anywhere on the line, case-insensitive. */
const HTML_HIDDEN_ATTR_RE = /<[a-zA-Z][^>]*[\s"'](?:hidden\b|style\s*=)/i;

/** Gate finding, third re-gate, fix (c) / should-fix, fourth re-gate:
 * marks each line of `text` as VISIBLE prose (`true`) or not. A line is
 * NOT visible when it is inside a fenced code block (``` ` ``` or `~~~`,
 * any length ≥ 3, closed only by a matching-or-longer fence of the SAME
 * character — the fence lines themselves are also not visible, they're
 * syntax, not content), inside an HTML comment (`<!-- ... -->`, tracked
 * across as many lines as it takes to find the closing `-->` — a comment
 * opened and closed on one line hides only that line), an indented code
 * block (4+ leading spaces, or a leading tab), inside a raw HTML block
 * (should-fix, fourth re-gate: CommonMark's own block-level-tag rule,
 * `HTML_BLOCK_OPEN_RE` — e.g. `<details>`, ended only by the next blank
 * line, never by a matching close tag, matching CommonMark's own type-6
 * "ends at blank line" rule and erring toward hiding MORE), or carries a
 * `hidden`/`style` HTML attribute on that line specifically
 * (`HTML_HIDDEN_ATTR_RE`, independent of block state). Computed over the
 * WHOLE text, never just a bounded section, so state that opens before
 * the section in question and closes after it is still tracked
 * correctly.
 *
 * Deliberately errs toward treating MORE as hidden, never less: a
 * genuine row mis-classified as hidden merely fails to register (an
 * inconvenience — unindent it, or move it out of the fence/comment/HTML
 * block); a HIDDEN, forged row mis-classified as visible would be the
 * dangerous direction, and is exactly what this closes (a gate review
 * found `ACCEPT` rows sitting inside an HTML comment, and inside a
 * fenced code block, both silently counted as logged before this
 * existed; the fourth re-gate added `<details>`/raw-HTML-block/
 * `hidden`/`style` to the same list). */
export function computeMarkdownLineVisibility(text: string): boolean[] {
  const lines = text.split("\n");
  const visible: boolean[] = new Array(lines.length).fill(true);
  let fenceChar: string | null = null;
  let fenceLen = 0;
  let inComment = false;
  let inHtmlBlock = false;
  let inDetailsBlock = false;
  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i] ?? "";
    const trimmed = raw.trim();

    if (inDetailsBlock) {
      // Round 7 follow-up: stays hidden across blank lines — only its
      // OWN closing </details> ends it (see DETAILS_OPEN_RE's own doc).
      visible[i] = false;
      if (DETAILS_CLOSE_RE.test(raw)) inDetailsBlock = false;
      continue;
    }

    if (inHtmlBlock) {
      // CommonMark type-6 HTML blocks end at the next BLANK line — the
      // blank line itself is outside the block.
      if (trimmed.length === 0) {
        inHtmlBlock = false;
        // Fall through: a blank line is ordinary prose (still subject
        // to the other checks below, none of which a blank line can
        // ever match).
      } else {
        visible[i] = false;
        continue;
      }
    }

    if (inComment) {
      visible[i] = false;
      if (trimmed.includes("-->")) inComment = false;
      continue;
    }

    if (fenceChar) {
      visible[i] = false; // hidden, including the closing fence line itself
      const closeMatch = /^(`{3,}|~{3,})\s*$/.exec(trimmed);
      if (closeMatch && closeMatch[1] && closeMatch[1][0] === fenceChar && closeMatch[1].length >= fenceLen) {
        fenceChar = null;
        fenceLen = 0;
      }
      continue;
    }

    const openMatch = /^(`{3,}|~{3,})/.exec(trimmed);
    if (openMatch && openMatch[1]) {
      fenceChar = openMatch[1][0] ?? null;
      fenceLen = openMatch[1].length;
      visible[i] = false; // the opening fence line itself
      continue;
    }

    const commentOpen = trimmed.indexOf("<!--");
    if (commentOpen !== -1) {
      const commentCloseOnSameLine = trimmed.indexOf("-->", commentOpen + 4);
      visible[i] = false;
      if (commentCloseOnSameLine === -1) inComment = true;
      continue;
    }

    if (/^( {4,}|\t)/.test(raw)) {
      visible[i] = false;
      continue;
    }

    // Round 7 follow-up: <details> opens here and stays hidden until
    // its OWN closing tag, even across blank lines — checked BEFORE the
    // generic HTML-block rule below, since <details> is also a member
    // of HTML_BLOCK_TAG_NAMES and needs the stricter tracking instead.
    if (DETAILS_OPEN_RE.test(raw)) {
      visible[i] = false;
      if (!DETAILS_CLOSE_RE.test(raw)) inDetailsBlock = true; // else opened+closed on one line
      continue;
    }

    // Should-fix, fourth re-gate: any OTHER raw HTML block (`<div>`,
    // `<table>`, etc.) opens here and swallows this line plus every
    // following line up to the next blank line (CommonMark's own rule
    // — <details> is deliberately stricter, see above).
    if (HTML_BLOCK_OPEN_RE.test(raw)) {
      inHtmlBlock = true;
      visible[i] = false;
      continue;
    }

    // Should-fix, fourth re-gate: a `hidden`/`style` attribute hides
    // just this one line, independent of any block state.
    if (HTML_HIDDEN_ATTR_RE.test(raw)) {
      visible[i] = false;
      continue;
    }

    visible[i] = true;
  }
  return visible;
}

/** Finds `acceptRowLiteral(trail, fact, evidenceSha, date)` as an EXACT,
 * trimmed-equal, VISIBLE line — never a substring/loose match, and
 * never a line inside a fenced code block/HTML comment/indented code
 * block (`computeMarkdownLineVisibility`, gate finding third re-gate,
 * fix (c)) — ONLY inside `x2MdFullText`'s `## Log` section, bounded the
 * same way `extractX2MdLogSection` now is (at the next top-level `## `
 * heading). The heading search itself also only considers VISIBLE
 * lines, so a fake `## Log`/`## ` heading hidden inside a comment or
 * fence can't shift where the real section is taken to start or end. */
export function findAcceptRowLine(
  x2MdFullText: string,
  trail: string,
  fact: string,
  evidenceSha: string,
  date: string,
): AcceptRowMatch | null {
  const lines = x2MdFullText.split("\n");
  const visible = computeMarkdownLineVisibility(x2MdFullText);
  let logStart = -1;
  let logEnd = lines.length;
  for (let i = 0; i < lines.length; i += 1) {
    if (!visible[i]) continue;
    if (logStart === -1 && /^## Log\b/.test(lines[i] ?? "")) {
      logStart = i;
      continue;
    }
    if (logStart !== -1 && i > logStart && /^## /.test(lines[i] ?? "")) {
      logEnd = i;
      break;
    }
  }
  if (logStart === -1) return null;
  const wanted = acceptRowLiteral(trail, fact, evidenceSha, date);
  for (let i = logStart; i < logEnd; i += 1) {
    if (!visible[i]) continue;
    if ((lines[i] ?? "").trim() === wanted) {
      return { lineNumber: i + 1, line: lines[i] ?? "" };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const execFileAsync = promisify(execFile);

/** Repo-relative path (from a repo's toplevel) the canonical ledger must
 * live at — gate finding 4 (re-gate). */
export const CANONICAL_LEDGER_REPO_RELATIVE_PATH = "docs/p0/x2-recorded-ledger.json";

/** Repo-relative path (from a repo's toplevel) the canonical X2.md must
 * live at — gate finding, fourth re-gate: the same repo-relative path
 * `verifyAgainstGitHub` reads directly from GitHub's real `main`. */
export const CANONICAL_X2MD_REPO_RELATIVE_PATH = "docs/p0/X2.md";

export interface LedgerGitCheck {
  /** `git hash-object <ledgerPath>` — the blob hash the ledger's CURRENT
   * on-disk content would have if committed as-is, printed regardless of
   * clean/dirty so a reader can always see exactly which ledger content
   * produced this verdict. `null` only when `git` itself is unavailable
   * (not installed / not on PATH). */
  blobHash: string | null;
  /** True only once EVERY hard requirement passes: the path resolves
   * (`realpath`) to the TOOLKIT'S OWN canonical
   * `docs/p0/x2-recorded-ledger.json` (gate finding, third re-gate, fix
   * (a) — never a caller-supplied path's own repo toplevel), the file
   * is tracked cleanly (no uncommitted/untracked changes, no
   * assume-unchanged/skip-worktree flag), AND its content is
   * byte-identical to what a FRESHLY FETCHED `GOLFRAVEN_VERIFIED_MAIN_REF`
   * already has at that path (gate finding, third re-gate, fix (b) —
   * fetched from the pinned GitHub URL this same run, never the
   * editable local `origin` remote) — `verifiedMainUnavailable` is a
   * DELIBERATE exception: a ledger never yet on GitHub main (or a fetch
   * that itself failed) is not "dirty" in the same sense, so it fails
   * `clean` here but does not hard-refuse the CLI on its own (see
   * `main()`). */
  clean: boolean;
  /** Human-readable reason for `clean: false`, or a plain "clean"
   * confirmation. */
  detail: string;
  /** Gate finding, third re-gate, fix (a): `realpath(ledgerPath)` equals
   * `realpath(canonicalLedgerAbsPath())` — the TOOLKIT'S OWN checkout,
   * resolved from `import.meta.url`, never from `git rev-parse
   * --show-toplevel` run from the ledger's own (potentially
   * caller-controlled, e.g. a scratch repo's) directory. */
  pathIsCanonical: boolean;
  /** Gate finding, third re-gate, fix (b): `git hash-object <ledgerPath>`
   * equals `git rev-parse <verified-main ref>:docs/p0/x2-recorded-ledger.json`,
   * where that ref was FRESHLY FETCHED, this same run, from the pinned
   * canonical GitHub URL — proves the ledger's content is actually on
   * GitHub's real `main`, not merely committed to some local/forged ref
   * of a similar name. */
  verifiedAgainstGithub: boolean;
  /** Gate finding, third re-gate, fix (b): true when the freshly-fetched
   * verified-main ref has no such path at all yet (a brand-new ledger),
   * OR the fetch itself failed this run (network failure, unreachable
   * host — "must give UNOFFICIAL, never OFFICIAL") — the specific,
   * NON-hard-refusing case: mark UNOFFICIAL and say why, rather than
   * treat it as ordinary dirtiness. */
  verifiedMainUnavailable: boolean;
  /** Gate finding 4: `git ls-files -v -- <ledgerPath>` showed the
   * lowercase `h` (assume-unchanged) or `S` (skip-worktree) flag — a way
   * to hide a local edit from `git diff`/`git status` entirely. Always a
   * hard refusal in `main()`, never bypassable via `--allow-dirty-ledger`
   * (bypassing the very check that exists to defeat this bypass would
   * defeat the point). */
  hiddenByGitFlag: boolean;
  /** Gate finding 4: the most recent commit that touched the ledger
   * (`git log -1 -- <path>`), printed so a reader never has to separately
   * run `git log` to audit it. `null` when unavailable. */
  lastCommit: { hash: string; author: string; date: string } | null;
}

/**
 * Gate finding 2d/4/third re-gate: `docs/p0/x2-recorded-ledger.json` is
 * the CANONICAL ledger. This checks that the ledger a verdict run is
 * ABOUT TO USE is: at the TOOLKIT'S OWN canonical path (fix (a) — never
 * merely "some repo's own toplevel + the same relative path," which a
 * caller-controlled scratch repo trivially satisfies for itself);
 * tracked cleanly by git (no uncommitted/untracked/hidden-by-flag edit
 * could have snuck in a bogus entry); and byte-identical to what a
 * FRESHLY FETCHED `GOLFRAVEN_VERIFIED_MAIN_REF` already has there (fix
 * (b) — fetched from the pinned GitHub URL, this same run, never the
 * editable local `origin` remote a caller can point anywhere or forge
 * outright with `git update-ref`). Reports the blob hash and the last
 * commit that touched the file, so the verdict output names EXACTLY
 * which ledger content it read and who last changed it — never "trust
 * me," always checkable against `git show <blobHash>` or `git log -p --
 * <path>`. Never throws: any git failure comes back as `clean: false`
 * with the reason in `detail` — the caller (`main()`) decides whether
 * that hard-refuses the run or only marks it UNOFFICIAL (this repo's own
 * house style per `recorded-export.ts`'s `runGit`: a git-check failure is
 * never silently treated as "assume clean").
 *
 * `verification` (gate finding, fourth re-gate) is a PRE-COMPUTED
 * `GitHubVerification` — the caller (`main()`) runs `verifyAgainstGitHub()`
 * ONCE per invocation and passes the same object everywhere; this
 * function itself never touches the network or spawns a verification
 * git command of its own — it only reads `verification`'s already-
 * fetched `ledgerBlobHash`. A test builds its own (real, against a local
 * bare repo via `verifyAgainstGitHub({repoUrl})`, or a hand-built fake).
 */
export interface CheckLedgerAgainstGitOptions {
  /** TEST-ONLY seam — `main()` never overrides this; defaults to
   * `canonicalLedgerAbsPath()` (gate finding, third re-gate, fix (a)).
   * Exists so tests can exercise the canonical-path-match logic against
   * an isolated scratch fixture, without writing into (or reading from)
   * this toolkit's own real checkout. */
  canonicalPath?: string;
  /** TEST-ONLY seam (round 7 hardening) — `main()` never overrides this;
   * passed straight through to `resolveGitBinary`. See that function's
   * own doc for why a test needs it (the test environment's trusted
   * `git` may not live at `/usr/bin/git`). */
  gitBinary?: string;
}

export async function checkLedgerAgainstGit(
  ledgerPath: string,
  verification: GitHubVerification,
  opts: CheckLedgerAgainstGitOptions = {},
): Promise<LedgerGitCheck> {
  const canonicalPath = opts.canonicalPath ?? canonicalLedgerAbsPath();
  const resolvedLedgerPath = path.resolve(ledgerPath);
  const cwd = path.dirname(resolvedLedgerPath);
  const notCanonical = (detail: string): LedgerGitCheck => ({
    blobHash,
    clean: false,
    detail,
    pathIsCanonical: false,
    verifiedAgainstGithub: false,
    verifiedMainUnavailable: false,
    hiddenByGitFlag: false,
    lastCommit: null,
  });

  // Round 7 hardening: these LOCAL git checks (hash-object/diff/status/
  // ls-files/log) are just as spoofable by a fake "git" on PATH as the
  // GitHub-verification commands are — a forged `git hash-object` could
  // report a blob hash matching what's genuinely on GitHub while the
  // real local file differs. Same fix: a resolved, root-owned absolute
  // path, never the bare string "git", with the child's PATH fixed
  // (never the caller's own).
  const gitResolution = resolveGitBinary(opts.gitBinary);
  if (!gitResolution.ok || !gitResolution.path) {
    return {
      blobHash: null,
      clean: false,
      detail: `could not resolve a trusted git binary for local checks: ${gitResolution.detail}`,
      pathIsCanonical: false,
      verifiedAgainstGithub: false,
      verifiedMainUnavailable: false,
      hiddenByGitFlag: false,
      lastCommit: null,
    };
  }
  const gitBinary = gitResolution.path;
  const localGitEnv: NodeJS.ProcessEnv = { ...process.env, PATH: FIXED_CHILD_PATH };

  let blobHash: string | null = null;
  try {
    const { stdout } = await execFileAsync(gitBinary, ["hash-object", ledgerPath], { env: localGitEnv });
    blobHash = stdout.trim();
  } catch {
    blobHash = null;
  }

  // Gate finding, third re-gate, fix (a): the ledger path must resolve
  // (realpath) to EXACTLY the TOOLKIT'S OWN canonical
  // docs/p0/x2-recorded-ledger.json — a caller pointing --ledger at some
  // OTHER file (right name, wrong directory; a /tmp copy; a scratch
  // repo's own docs/p0/x2-recorded-ledger.json, which used to pass this
  // check by construction) is refused outright, never silently treated
  // as if it were the canonical record.
  if (!(await isCanonicalPath(ledgerPath, canonicalPath))) {
    return notCanonical(
      `"${resolvedLedgerPath}" is not the canonical ledger path — expected exactly "${canonicalPath}" ` +
        "(gate finding, third re-gate, fix (a): pinned to this toolkit's OWN checkout, never derived from " +
        "the ledger's own directory).",
    );
  }

  // Local cleanliness (unchanged in substance from the first re-gate):
  // `git diff --quiet` catches an uncommitted edit against the index;
  // `git status --porcelain` also catches a file that was never `git
  // add`ed at all (an untracked file has no index entry for `git diff`
  // to compare against).
  try {
    await execFileAsync(gitBinary, ["diff", "--quiet", "--", ledgerPath], { cwd, env: localGitEnv });
  } catch (err) {
    const code = (err as { code?: number }).code;
    return {
      blobHash,
      clean: false,
      detail:
        code === 1
          ? `"${ledgerPath}" has uncommitted changes against the index (git diff is non-empty).`
          : `could not verify "${ledgerPath}" is clean in git: ${err instanceof Error ? err.message : String(err)}`,
      pathIsCanonical: true,
      verifiedAgainstGithub: false,
      verifiedMainUnavailable: false,
      hiddenByGitFlag: false,
      lastCommit: null,
    };
  }
  try {
    const { stdout } = await execFileAsync(gitBinary, ["status", "--porcelain", "--", ledgerPath], { cwd, env: localGitEnv });
    if (stdout.trim().length > 0) {
      return {
        blobHash,
        clean: false,
        detail: `"${ledgerPath}" is untracked or has staged-but-uncommitted changes (git status: "${stdout.trim()}").`,
        pathIsCanonical: true,
        verifiedAgainstGithub: false,
        verifiedMainUnavailable: false,
        hiddenByGitFlag: false,
        lastCommit: null,
      };
    }
  } catch (err) {
    return {
      blobHash,
      clean: false,
      detail: `could not verify "${ledgerPath}"'s git status: ${err instanceof Error ? err.message : String(err)}`,
      pathIsCanonical: true,
      verifiedAgainstGithub: false,
      verifiedMainUnavailable: false,
      hiddenByGitFlag: false,
      lastCommit: null,
    };
  }

  // Gate finding 4: `git ls-files -v` — an `h` (assume-unchanged) or `S`
  // (skip-worktree) flag makes git itself HIDE a local edit from both
  // `git diff` and `git status`, i.e. exactly the checks just above —
  // always refused, regardless of --allow-dirty-ledger (see `main()`).
  try {
    const { stdout } = await execFileAsync(gitBinary, ["ls-files", "-v", "--", ledgerPath], { cwd, env: localGitEnv });
    const line = stdout.trim();
    if (line && /^[hS] /.test(line)) {
      return {
        blobHash,
        clean: false,
        detail:
          `"${ledgerPath}" is marked assume-unchanged or skip-worktree in git (git ls-files -v: ` +
          `"${line}") — either flag can hide a local edit from git diff/status entirely; refusing ` +
          "regardless of --allow-dirty-ledger (gate finding 4, re-gate).",
        pathIsCanonical: true,
        verifiedAgainstGithub: false,
        verifiedMainUnavailable: false,
        hiddenByGitFlag: true,
        lastCommit: null,
      };
    }
  } catch {
    // `git ls-files` failing outright is covered by the untracked-file
    // check above already having run (and passed) — nothing further to
    // do here; the diff/status checks are the primary defense.
  }

  // Gate finding 4: the last commit that touched the ledger — printed
  // whenever available, regardless of the outcome below.
  let lastCommit: { hash: string; author: string; date: string } | null = null;
  try {
    const { stdout } = await execFileAsync(
      gitBinary,
      ["log", "-1", "--format=%H%x1f%an%x1f%aI", "--", ledgerPath],
      { cwd, env: localGitEnv },
    );
    const [hash, author, date] = stdout.trim().split("\x1f");
    if (hash) lastCommit = { hash, author: author ?? "", date: date ?? "" };
  } catch {
    lastCommit = null;
  }

  // Gate finding, fourth re-gate: proves the ledger's content is
  // actually on GitHub's real `main` — reads `verification.ledgerBlobHash`,
  // computed ONCE per run by `verifyAgainstGitHub()` inside a disposable,
  // scrubbed-environment repo (see that function's own doc). A
  // verification that did not succeed at all, or a fresh main with no
  // such path yet, is UNOFFICIAL, never a hard refusal — and network
  // failure specifically must never read as OFFICIAL.
  if (!verification.ok) {
    return {
      blobHash,
      clean: false,
      detail:
        `GitHub verification did not succeed this run: ${verification.detail} — marking UNOFFICIAL rather ` +
        "than refusing (gate finding, fourth re-gate: a failed verification must give UNOFFICIAL, never " +
        "OFFICIAL).",
      pathIsCanonical: true,
      verifiedAgainstGithub: false,
      verifiedMainUnavailable: true,
      hiddenByGitFlag: false,
      lastCommit,
    };
  }
  if (verification.ledgerBlobHash === null) {
    return {
      blobHash,
      clean: false,
      detail:
        `GitHub main does not yet have "${CANONICAL_LEDGER_REPO_RELATIVE_PATH}" — marking UNOFFICIAL rather ` +
        "than refusing (a brand-new ledger not yet on GitHub main is not the same as a dirty one).",
      pathIsCanonical: true,
      verifiedAgainstGithub: false,
      verifiedMainUnavailable: true,
      hiddenByGitFlag: false,
      lastCommit,
    };
  }
  if (blobHash === null || verification.ledgerBlobHash !== blobHash) {
    return {
      blobHash,
      clean: false,
      detail:
        `the ledger's content (blob ${blobHash ?? "unavailable"}) does not match what GitHub's real main ` +
        `already has at "${CANONICAL_LEDGER_REPO_RELATIVE_PATH}" (blob ${verification.ledgerBlobHash}) — ` +
        "locally diverged from GitHub's own main; pass --allow-dirty-ledger to proceed anyway (result " +
        "marked UNOFFICIAL) (gate finding, third re-gate).",
      pathIsCanonical: true,
      verifiedAgainstGithub: false,
      verifiedMainUnavailable: false,
      hiddenByGitFlag: false,
      lastCommit,
    };
  }

  return {
    blobHash,
    clean: true,
    detail: `clean — committed, verified against GitHub's real main (${GOLFRAVEN_CANONICAL_REPO_URL}, disposable repo + scrubbed environment), canonical path, no hidden-edit flags.`,
    pathIsCanonical: true,
    verifiedAgainstGithub: true,
    verifiedMainUnavailable: false,
    hiddenByGitFlag: false,
    lastCommit,
  };
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
        "an `acceptance` corroboration record must be logged there). Neither flag can produce an OFFICIAL " +
        "result, or a counted acceptance, from anywhere but THIS toolkit's own canonical checkout, verified " +
        `against ${GOLFRAVEN_CANONICAL_REPO_URL}'s real main — pointing either at a copy elsewhere is a ` +
        "legitimate way to dry-run against fixtures, but the output is always UNOFFICIAL (gate finding, " +
        "third re-gate).",
    );
  }
  const manifest = JSON.parse(
    await readFile(path.join(evidenceDir, "manifest.json"), "utf8"),
  ) as X2FetchManifest;
  const confirmation = JSON.parse(
    await readFile(confirmationPath, "utf8"),
  ) as X2ConfirmationFile;
  const ledgerPath = flags.ledger;
  // Gate finding, fourth re-gate: verify against GitHub's real main
  // EXACTLY ONCE per invocation, inside a disposable, scrubbed-environment
  // repo (see `verifyAgainstGitHub`'s own doc, and this module's "Addendum
  // J re-gate round 6" banner comment above it) — the caller's own
  // process.env, GIT_DIR, local git config/replace-objects/grafts/hooks
  // never reach it. The result is threaded through everywhere downstream
  // (`checkLedgerAgainstGit`, `resolveCorroboration`) rather than each
  // call re-deriving it — one verification, one truth, this run.
  const githubVerification = await verifyAgainstGitHub();
  try {
    // Gate finding 2d/4/third+fourth re-gate: the ledger must be at the
    // TOOLKIT'S OWN canonical path (fix (a)), tracked cleanly by git (no
    // uncommitted/untracked/hidden-by-flag edit), and its content must
    // match GitHub's real main (fix (b), now via `githubVerification`).
    // Only ONE case is ALWAYS a hard refusal, regardless of
    // --allow-dirty-ledger: a `git ls-files` assume-unchanged/skip-worktree
    // flag (it exists specifically to hide a local edit from the very
    // diff/status checks --allow-dirty-ledger is meant to override —
    // bypassing the flag-check too would defeat the point of having it at
    // all). A wrong ledger path, or a ledger simply not yet on GitHub main
    // (including a failed verification), is NOT a hard-refusing case —
    // both proceed automatically, marked UNOFFICIAL, without needing the
    // flag. Everything else dirty (a local uncommitted edit, or content
    // that DIVERGED from what GitHub main has) still requires the flag.
    const ledgerGitCheck = await checkLedgerAgainstGit(ledgerPath, githubVerification);
    if (ledgerGitCheck.hiddenByGitFlag) {
      throw new Error(
        `Refusing: the ledger "${ledgerPath}" — ${ledgerGitCheck.detail} This is never bypassable via ` +
          "--allow-dirty-ledger (gate finding 4, re-gate): the flag exists specifically to hide a local edit " +
          "from the checks --allow-dirty-ledger is meant to override.",
      );
    }
    const ledgerNeedsAllowFlag =
      !ledgerGitCheck.clean && ledgerGitCheck.pathIsCanonical && !ledgerGitCheck.verifiedMainUnavailable;
    if (ledgerNeedsAllowFlag && !allowDirtyLedger) {
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
    // Gate finding 3/2 (both re-gate)/fourth re-gate: resolve (verify)
    // that corroboration file BEFORE computeX2Verdict ever sees it —
    // re-reading `wayback` evidence from THIS evidence dir and
    // re-validating every one of its rules against the owner-saved fact's
    // OWN claims and the canonical ledger; checking `acceptance` records
    // against a structured row in GitHub main's own X2.md Log section AND
    // its git provenance (via `githubVerification`). A missing/unreadable
    // local X2.md is not a hard refusal (an --evidence-dir far from a
    // golfraven checkout is a legitimate use), but every `acceptance`
    // record then resolves to "not logged" — the safe default.
    const x2MdPath = flags["x2-log"] || resolveDefaultX2MdPath();
    let x2Md: { fullText: string; path: string } | null = null;
    try {
      x2Md = { fullText: await readFile(x2MdPath, "utf8"), path: x2MdPath };
    } catch {
      x2Md = null;
    }
    const resolvedCorroboration = await resolveCorroboration(corroboration, {
      evidenceByTrail,
      readRaw: (rel) => readFile(path.join(evidenceDir, rel)),
      evidenceDir,
      ledger,
      ledgerOfficial,
      x2Md,
      githubVerification,
    });
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
        pathIsCanonical: ledgerGitCheck.pathIsCanonical,
        verifiedAgainstGithub: ledgerGitCheck.verifiedAgainstGithub,
      },
      githubVerification: { ok: githubVerification.ok, detail: githubVerification.detail },
    };
    await writeFile(
      `${outPrefix}.json`,
      `${JSON.stringify(resultWithLedgerInfo, null, 2)}\n`,
      "utf8",
    );
    const ledgerHeader =
      `Ledger: ${ledgerPath} (blob ${ledgerGitCheck.blobHash ?? "unavailable — git not found"}) — ` +
      `${ledgerOfficial ? `OFFICIAL (verified against ${GOLFRAVEN_CANONICAL_REPO_URL}'s real main)` : `**UNOFFICIAL** (${ledgerGitCheck.detail})`}\n\n`;
    const md = ledgerHeader + renderX2VerdictMarkdown(result);
    await writeFile(`${outPrefix}.md`, `${md}\n`, "utf8");
    process.stdout.write(`${md}\n`);
    if (result.anyUnconfirmedWithFailedSource) {
      process.exitCode = 1;
    }
  } finally {
    await githubVerification.cleanup();
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
