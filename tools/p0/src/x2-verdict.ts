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

/** The local ref a fresh fetch from `GOLFRAVEN_CANONICAL_REPO_URL` writes
 * `main` to (`fetchVerifiedMainRef`). Deliberately its OWN namespace —
 * not `refs/remotes/origin/main`, an ordinary remote-tracking ref anyone
 * with write access to a checkout can set with a bare `git update-ref`
 * — so nothing else's normal git usage collides with or shadows it, and
 * a forged leftover ref from a prior run is always deleted before this
 * tool ever reads it again (`fetchVerifiedMainRef` deletes first, then
 * fetches, every time it runs). */
export const GOLFRAVEN_VERIFIED_MAIN_REF = "refs/x2-verdict/verified-main";

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

export interface VerifiedMainFetchResult {
  ok: boolean;
  detail: string;
}

/**
 * Gate finding, third re-gate, fix (b): the ONLY function in this module
 * that touches the network. Deletes `GOLFRAVEN_VERIFIED_MAIN_REF` FIRST —
 * a stale ref from a prior run, or one a caller forged directly with
 * `git update-ref`, must never be read without a fresh fetch in THIS
 * same run — then fetches `main` from the pinned canonical URL into
 * that ref. Never throws: a network failure, an unreachable host, or
 * any other fetch error comes back as `{ok: false}` — the caller
 * (`main()`) then treats the run as UNOFFICIAL, never OFFICIAL, and
 * every downstream comparison against this ref naturally fails closed
 * too (having just been deleted, an absent ref makes `git rev-parse`/
 * `git merge-base --is-ancestor` against it fail with an ordinary
 * "unknown revision" error — the SAME code path already used for "this
 * ref doesn't have that content yet," no special-casing required).
 *
 * `repoUrl`/`refName` are a TEST-ONLY seam: `main()` NEVER passes them
 * (no CLI flag exposes this — `--ledger`/`--x2-log`/etc. cannot reach
 * this function's own arguments), so the only way to point this at
 * something other than the real, pinned GitHub URL is to call it
 * directly from test code, never through the shipped CLI.
 */
export async function fetchVerifiedMainRef(
  cwd: string,
  opts: { repoUrl?: string; refName?: string } = {},
): Promise<VerifiedMainFetchResult> {
  const repoUrl = opts.repoUrl ?? GOLFRAVEN_CANONICAL_REPO_URL;
  const refName = opts.refName ?? GOLFRAVEN_VERIFIED_MAIN_REF;
  try {
    await execFileAsync("git", ["update-ref", "-d", refName], { cwd });
  } catch {
    // Fine if it didn't exist yet — deletion is best-effort, the point
    // is only that nothing stale survives past this point.
  }
  try {
    await execFileAsync("git", ["fetch", "--no-tags", repoUrl, `+refs/heads/main:${refName}`], { cwd });
  } catch (err) {
    return {
      ok: false,
      detail: `fetching verified main from ${repoUrl} failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  return { ok: true, detail: `fetched ${refName} from ${repoUrl}` };
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
  /** `docs/p0/X2.md`'s FULL text (not just the Log section — a matched
   * row's line number is handed to `git blame` against the real, on-disk
   * file) plus the path it was read from. `null` when the file could not
   * be read — every `acceptance` record then resolves to "not logged",
   * the safe default (gate finding 2, re-gate). */
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
  /** TEST-ONLY seam (gate finding, third re-gate, fix (b)) — `main()`
   * never overrides this; defaults to `GOLFRAVEN_VERIFIED_MAIN_REF`.
   * Passed straight through to `blameAcceptRow`'s own reachability
   * check, so a test can point it at a ref it created locally (no
   * network) instead of the real fetched ref. */
  verifiedMainRefName?: string;
}

async function resolveWaybackRecord(
  trail: string,
  evidenceSha: string,
  record: X2WaybackCorroboration,
  opts: ResolveCorroborationOptions,
): Promise<ResolvedCorroborationEntry> {
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
  if (!opts.x2Md) {
    return { acceptanceLogged: false, acceptanceDetail: "docs/p0/X2.md could not be read." };
  }
  // Gate finding, third re-gate, fix (a): an `ACCEPT` row is only ever
  // trusted from the TOOLKIT'S OWN canonical X2.md — never from a
  // `--x2-log` pointed at a scratch/forged copy elsewhere, no matter how
  // well-formed its content looks. This is a hard requirement, not a
  // label: there is no legitimate reason for a real acceptance to live
  // anywhere else.
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
  // Gate finding, third re-gate, fix (c): only a VISIBLE row counts —
  // `findAcceptRowLine` itself now skips fenced code blocks, HTML
  // comments (including multi-line), and indented code blocks.
  const match = findAcceptRowLine(opts.x2Md.fullText, trail, record.fact, evidenceSha, record.date);
  if (!match) {
    return {
      acceptanceLogged: false,
      acceptanceDetail:
        `no VISIBLE line reading exactly "${acceptRowLiteral(trail, record.fact, evidenceSha, record.date)}" ` +
        'was found in the "## Log" section (a row hidden inside a fenced code block, an HTML comment, or an ' +
        "indented code block does not count).",
    };
  }
  // Gate finding, third re-gate, fix (b): reachability is checked
  // against `GOLFRAVEN_VERIFIED_MAIN_REF`, which the CALLER (`main()`)
  // is responsible for having freshly fetched, THIS SAME RUN, from the
  // pinned GitHub URL before ever reaching here — never the editable
  // local `origin/main`.
  const blame = await blameAcceptRow(
    opts.x2Md.path,
    match.lineNumber,
    opts.verifiedMainRefName ?? GOLFRAVEN_VERIFIED_MAIN_REF,
  );
  if (!blame.ok) {
    return { acceptanceLogged: false, acceptanceDetail: blame.detail };
  }
  if (!blame.provenance.reachableFromVerifiedMain) {
    return {
      acceptanceLogged: false,
      acceptanceProvenance: blame.provenance,
      acceptanceDetail:
        `commit ${blame.provenance.commit} (git blame's answer for who introduced this Log row) is not ` +
        `reachable from a freshly-fetched ${GOLFRAVEN_VERIFIED_MAIN_REF} (${GOLFRAVEN_CANONICAL_REPO_URL}) — ` +
        "not yet on GitHub's own main, or the fetch itself failed this run.",
    };
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
    acceptanceDetail: `logged in X2.md's Log section, on a commit reachable from a freshly-fetched ${GOLFRAVEN_VERIFIED_MAIN_REF}.`,
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

/** Gate finding, third re-gate, fix (c): marks each line of `text` as
 * VISIBLE prose (`true`) or not. A line is NOT visible when it is inside
 * a fenced code block (``` ` ``` or `~~~`, any length ≥ 3, closed only
 * by a matching-or-longer fence of the SAME character — the fence lines
 * themselves are also not visible, they're syntax, not content), inside
 * an HTML comment (`<!-- ... -->`, tracked across as many lines as it
 * takes to find the closing `-->` — a comment opened and closed on one
 * line hides only that line), or an indented code block (4+ leading
 * spaces, or a leading tab). Computed over the WHOLE text, never just a
 * bounded section, so state that opens before the section in question
 * and closes after it is still tracked correctly.
 *
 * Deliberately errs toward treating MORE as hidden, never less: a
 * genuine row mis-classified as hidden merely fails to register (an
 * inconvenience — unindent it, or move it out of the fence/comment); a
 * HIDDEN, forged row mis-classified as visible would be the dangerous
 * direction, and is exactly what this closes (a gate review found
 * `ACCEPT` rows sitting inside an HTML comment, and inside a fenced
 * code block, both silently counted as logged before this existed). */
export function computeMarkdownLineVisibility(text: string): boolean[] {
  const lines = text.split("\n");
  const visible: boolean[] = new Array(lines.length).fill(true);
  let fenceChar: string | null = null;
  let fenceLen = 0;
  let inComment = false;
  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i] ?? "";
    const trimmed = raw.trim();

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

/** Gate finding 2 (re-gate)/gate finding, third re-gate, fix (b): finds
 * the commit that introduced the given line of `x2MdPath` (`git blame
 * --porcelain`), then requires it reachable from `refName` — by
 * default `GOLFRAVEN_VERIFIED_MAIN_REF`, which the CALLER is
 * responsible for having freshly fetched (`fetchVerifiedMainRef`) in
 * THIS SAME RUN before ever calling this function; never the editable
 * local `origin/main`, which a caller can point anywhere or forge
 * outright with `git update-ref`. Never throws; a git failure of any
 * kind (including the ref simply not existing, e.g. because the fetch
 * failed or was never run) comes back as `{ok: false, detail}` or
 * `reachableFromVerifiedMain: false`, the same house style as
 * `checkLedgerAgainstGit`. Author/date/signature come from `git show`;
 * see `AcceptRowGitProvenance`'s own doc for what this can and cannot
 * prove. `refName` is a TEST-ONLY seam — `main()`/`resolveAcceptanceRecord`
 * never override it. */
export async function blameAcceptRow(
  x2MdPath: string,
  lineNumber: number,
  refName: string = GOLFRAVEN_VERIFIED_MAIN_REF,
): Promise<{ ok: true; provenance: AcceptRowGitProvenance } | { ok: false; detail: string }> {
  const cwd = path.dirname(path.resolve(x2MdPath));
  let sha: string;
  try {
    const { stdout } = await execFileAsync(
      "git",
      ["blame", "-L", `${lineNumber},${lineNumber}`, "--porcelain", "--", x2MdPath],
      { cwd },
    );
    const firstLine = stdout.split("\n")[0] ?? "";
    const candidate = firstLine.split(" ")[0] ?? "";
    if (!/^[0-9a-f]{40}$/.test(candidate)) {
      return {
        ok: false,
        detail: `git blame did not return a commit hash for line ${lineNumber} of "${x2MdPath}" (got: ${JSON.stringify(firstLine)}).`,
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
    const { stdout } = await execFileAsync(
      "git",
      ["show", "-s", "--format=%an%x1f%aI%x1f%G?", sha],
      { cwd },
    );
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
  let reachableFromVerifiedMain = false;
  try {
    await execFileAsync("git", ["merge-base", "--is-ancestor", sha, refName], { cwd });
    reachableFromVerifiedMain = true;
  } catch {
    reachableFromVerifiedMain = false;
  }
  return {
    ok: true,
    provenance: { commit: sha, author, authorDate, signatureStatus, reachableFromVerifiedMain },
  };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const execFileAsync = promisify(execFile);

/** Repo-relative path (from a repo's toplevel) the canonical ledger must
 * live at — gate finding 4 (re-gate). */
export const CANONICAL_LEDGER_REPO_RELATIVE_PATH = "docs/p0/x2-recorded-ledger.json";

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
 * `refName` is a TEST-ONLY seam (defaults to `GOLFRAVEN_VERIFIED_MAIN_REF`)
 * — `main()` never overrides it; the caller is responsible for having
 * fetched that ref FRESH, this same run, before calling this function
 * (`fetchVerifiedMainRef`) — this function itself does no fetching, so a
 * ref that was never fetched (or whose fetch failed and was deleted)
 * simply doesn't exist, and every git command against it fails closed
 * into `verifiedMainUnavailable: true`.
 */
export interface CheckLedgerAgainstGitOptions {
  /** TEST-ONLY seam — `main()` never overrides this; defaults to
   * `GOLFRAVEN_VERIFIED_MAIN_REF`. The caller is responsible for having
   * fetched this ref FRESH, this same run, before calling this function. */
  refName?: string;
  /** TEST-ONLY seam — `main()` never overrides this; defaults to
   * `canonicalLedgerAbsPath()` (gate finding, third re-gate, fix (a)).
   * Exists so tests can exercise the canonical-path-match logic against
   * an isolated scratch fixture, without writing into (or reading from)
   * this toolkit's own real checkout. */
  canonicalPath?: string;
}

export async function checkLedgerAgainstGit(
  ledgerPath: string,
  opts: CheckLedgerAgainstGitOptions = {},
): Promise<LedgerGitCheck> {
  const refName = opts.refName ?? GOLFRAVEN_VERIFIED_MAIN_REF;
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
  let blobHash: string | null = null;
  try {
    const { stdout } = await execFileAsync("git", ["hash-object", ledgerPath]);
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
    await execFileAsync("git", ["diff", "--quiet", "--", ledgerPath], { cwd });
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
    const { stdout } = await execFileAsync("git", ["status", "--porcelain", "--", ledgerPath], { cwd });
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
    const { stdout } = await execFileAsync("git", ["ls-files", "-v", "--", ledgerPath], { cwd });
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
      "git",
      ["log", "-1", "--format=%H%x1f%an%x1f%aI", "--", ledgerPath],
      { cwd },
    );
    const [hash, author, date] = stdout.trim().split("\x1f");
    if (hash) lastCommit = { hash, author: author ?? "", date: date ?? "" };
  } catch {
    lastCommit = null;
  }

  // Gate finding, third re-gate, fix (b): proves the ledger's content is
  // actually on GitHub's real `main` — `git rev-parse <verified-main
  // ref>:<path>` reads the blob that FRESHLY FETCHED ref has at that
  // path right now. The ref not existing at all (fetch never ran, or
  // failed and was deleted) fails this the SAME way as "doesn't have
  // this path yet" — both are UNOFFICIAL, never a hard refusal, and
  // network failure specifically must never read as OFFICIAL.
  try {
    const { stdout } = await execFileAsync(
      "git",
      ["rev-parse", `${refName}:${CANONICAL_LEDGER_REPO_RELATIVE_PATH}`],
      { cwd },
    );
    const verifiedBlobHash = stdout.trim();
    if (blobHash === null || verifiedBlobHash !== blobHash) {
      return {
        blobHash,
        clean: false,
        detail:
          `the ledger's content (blob ${blobHash ?? "unavailable"}) does not match what a freshly-fetched ` +
          `${refName} already has at "${CANONICAL_LEDGER_REPO_RELATIVE_PATH}" (blob ${verifiedBlobHash}) — ` +
          "locally diverged from GitHub's own main; pass --allow-dirty-ledger to proceed anyway (result " +
          "marked UNOFFICIAL) (gate finding, third re-gate).",
        pathIsCanonical: true,
        verifiedAgainstGithub: false,
        verifiedMainUnavailable: false,
        hiddenByGitFlag: false,
        lastCommit,
      };
    }
  } catch {
    return {
      blobHash,
      clean: false,
      detail:
        `${refName} does not yet have "${CANONICAL_LEDGER_REPO_RELATIVE_PATH}" (or the ref itself is absent — ` +
        "the fetch from GitHub either was never run or failed this run) — marking UNOFFICIAL rather than " +
        "refusing (gate finding, third re-gate: a network/fetch failure must give UNOFFICIAL, never OFFICIAL).",
      pathIsCanonical: true,
      verifiedAgainstGithub: false,
      verifiedMainUnavailable: true,
      hiddenByGitFlag: false,
      lastCommit,
    };
  }

  return {
    blobHash,
    clean: true,
    detail: `clean — committed, verified against a freshly-fetched ${refName} (${GOLFRAVEN_CANONICAL_REPO_URL}), canonical path, no hidden-edit flags.`,
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
  // Gate finding, third re-gate, fix (b): fetch `main` fresh from the
  // pinned canonical GitHub URL, ONCE, before any check that compares
  // against it — deleting any leftover/forged ref first. Runs in the
  // TOOLKIT'S OWN checkout (never a caller-supplied path's directory),
  // so `checkLedgerAgainstGit`/`blameAcceptRow` only ever see this fresh
  // ref when THEY are also looking inside that same canonical checkout
  // (i.e. exactly the case where `--ledger`/`--x2-log` are canonical) —
  // a run against a scratch/foreign repo never has this ref at all,
  // regardless of what that scratch repo's own local refs claim.
  // Network failure here is never silently ignored: it surfaces as
  // `verifiedMainUnavailable`/an unreachable-commit result below, which
  // → UNOFFICIAL, never OFFICIAL.
  const verifiedMainFetch = await fetchVerifiedMainRef(resolveToolkitRepoRoot());
  // Gate finding 2d/4/third re-gate: the ledger must be at the
  // TOOLKIT'S OWN canonical path (fix (a)), tracked cleanly by git (no
  // uncommitted/untracked/hidden-by-flag edit), and its content must
  // match a freshly-fetched GitHub main (fix (b)). Only ONE case is
  // ALWAYS a hard refusal, regardless of --allow-dirty-ledger: a `git
  // ls-files` assume-unchanged/skip-worktree flag (it exists
  // specifically to hide a local edit from the very diff/status checks
  // --allow-dirty-ledger is meant to override — bypassing the flag-check
  // too would defeat the point of having it at all). A wrong ledger path,
  // or a ledger simply not yet on GitHub main (including a failed
  // fetch), is NOT a hard-refusing case — both proceed automatically,
  // marked UNOFFICIAL, without needing the flag ("for an official run,
  // require realpath(--ledger) to equal <canonical path> — anything else
  // is UNOFFICIAL"). Everything else dirty (a local uncommitted edit, or
  // content that DIVERGED from what GitHub main has) still requires the
  // flag.
  const ledgerGitCheck = await checkLedgerAgainstGit(ledgerPath);
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
  // Gate finding 3/2 (both re-gate): resolve (verify) that corroboration
  // file BEFORE computeX2Verdict ever sees it — re-reading `wayback`
  // evidence from THIS evidence dir and re-validating every one of its
  // rules against the owner-saved fact's OWN claims and the canonical
  // ledger; checking `acceptance` records against a structured row in
  // `docs/p0/X2.md`'s own Log section AND its git provenance. A
  // missing/unreadable X2.md is not a hard refusal (an --evidence-dir far
  // from a golfraven checkout is a legitimate use), but every
  // `acceptance` record then resolves to "not logged" — the safe
  // default.
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
    x2Md,
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
      verifiedMainFetch,
    },
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
