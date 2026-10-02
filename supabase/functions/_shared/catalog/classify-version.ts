// supabase/functions/_shared/catalog/classify-version.ts
//
// Pure catalog-skew classification (build plan §3.3, P3 AT 8 / AT 15 /
// G3-10; docs/security/p3-money-path-requirements.md). Given the
// submitted `catalogVersion` and the server's own catalog_version rows,
// decides whether the submission's catalog claim is acceptable, stale, or
// forged — BEFORE any id lookup happens. No I/O: every catalog_version
// row this needs is passed in already fetched (by the caller,
// privileged.ts's Repo), so this is unit-testable with plain fixtures.
//
// ⛔ REWRITE (P3e round 2 gate, H1: "Intake takes an internal int as
// catalogVersion and verifies manifestSig over a payload the P1 signer
// never produces. Change the intake contract to the site version string
// (yyyymmdd-gitsha7), resolved via catalog_version.site_version.").
// `declaredVersion`/`currentVersion` are now the SITE's own
// `yyyymmdd-gitsha7` strings (`tools/catalog/src/manifest.ts`'s
// `CatalogVersionSchema`), ordered by `compareCatalogVersions` (date
// -primary, sha-suffix tiebreak — the SAME function `manifest-artifact.ts`
// exports, a direct port of `tools/catalog/src/manifest.ts`'s own). Two
// arithmetic checks that used to be plain integer subtraction now use two
// DIFFERENT, more precise sources instead of one int diff:
//   - "N releases behind" (AT 8: "5 releases... old") still needs a
//     PUBLISH-ORDER count, which a date-ordered string alone cannot give
//     (two versions cut the same week are still "1 release apart," not
//     "0 days apart") — so this still compares the two rows' own internal
//     `app.catalog_version.version` ints (`currentInternalVersion` /
//     `declaredVersionRow.internalVersion`), which import-handler.ts
//     assigns in strict publish order. This is the SAME field
//     `import-handler.ts`/`privileged.ts#ImporterRepo` already maintain
//     for idempotency — reused here, not a second source of truth.
//   - "far future" is now literally the build plan's own rule (§3.3(i):
//     "the version's date prefix is no later than now + 1 day"), read
//     directly off the declared version's OWN yyyymmdd date prefix — no
//     release-count heuristic needed at all, and it works even for a
//     version the server has never seen (no `declaredVersionRow`),
//     unlike the old int-diff check, which needed BOTH ints to exist.
//
// ⛔ STUB, still clearly marked (unchanged reasoning, restated): a
// `manifestSig` only verifies against a REGISTERED, non-revoked
// `app.catalog_signing_key` row — in an environment with none registered,
// every "newer, unsigned-yet" claim still fails closed to `forged`. What
// IS new this round: `import-handler.ts` now provisions real keys via a
// real import, so this path is REACHABLE once a real catalog has been
// imported — no longer a permanent stub, just conditional on a key
// actually being on file.

import { compareCatalogVersions } from "./manifest-artifact.ts";

export type CatalogVersionClassification =
  | { kind: "current_or_within_window"; resolvedVersion: string }
  | { kind: "stale" }
  | { kind: "forged" };

export interface CatalogVersionClassifyInput {
  /** The `catalogVersion` the submission claims — a site version string
   * (yyyymmdd-gitsha7). Request-shape.ts already rejects anything not
   * shaped that way before this function is ever called, but this
   * function re-checks defensively (a fixture/test caller may not have
   * gone through that layer). */
  declaredVersion: string;
  /** The server's own most-recently-imported site version (the
   * `site_version` of the row with the highest `version` int), or null
   * if none exist yet. */
  currentVersion: string | null;
  /** The app.catalog_version row for `declaredVersion`, if the server has
   * ever imported that exact site version (null otherwise). `kidRevoked`:
   * should-fix (P3c gate round 2, AT 15): "a revoked kid returns 422
   * catalog_stale". `internalVersion`: that row's own `version` int, used
   * ONLY for the "N releases behind" count against `currentInternalVersion`
   * — never compared to or conflated with any site version string. */
  declaredVersionRow: { publishedAt: string; kidRevoked: boolean; internalVersion: number } | null;
  /** The current row's own internal `version` int — null iff
   * `currentVersion` is null. */
  currentInternalVersion: number | null;
  now: Date;
  /** §3.3 / §4.4: "published_at drives the 30-day acceptance window." */
  maxAgeDays?: number;
  /** AT 8: "version 5 releases... old" — a PUBLISH-ORDER count (see this
   * module's own header), not a date difference. */
  maxVersionsBehind?: number;
  /** Build plan §3.3(i): "the version's date prefix is no later than now
   * + 1 day." Read directly off `declaredVersion`'s own yyyymmdd prefix —
   * see this module's header for why this replaced the old release-count
   * -ahead heuristic. */
  maxFutureDays?: number;
}

const DEFAULT_MAX_AGE_DAYS = 30;
const DEFAULT_MAX_VERSIONS_BEHIND = 5;
const DEFAULT_MAX_FUTURE_DAYS = 1;

const SITE_VERSION_RE = /^(\d{4})(\d{2})(\d{2})-[0-9a-f]{7}$/;

/** The UTC midnight `Date` a `yyyymmdd-gitsha7` string's own date prefix
 * names, or `null` if the string isn't shaped that way at all (a
 * malformed `declaredVersion` reaching this far is itself grounds for
 * "forged" — see the caller). */
function dateOf(siteVersion: string): Date | null {
  const m = SITE_VERSION_RE.exec(siteVersion);
  if (!m) return null;
  const [, y, mo, d] = m;
  return new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d)));
}

export function classifyCatalogVersion(input: CatalogVersionClassifyInput): CatalogVersionClassification {
  const maxAgeDays = input.maxAgeDays ?? DEFAULT_MAX_AGE_DAYS;
  const maxVersionsBehind = input.maxVersionsBehind ?? DEFAULT_MAX_VERSIONS_BEHIND;
  const maxFutureDays = input.maxFutureDays ?? DEFAULT_MAX_FUTURE_DAYS;

  const declaredDate = dateOf(input.declaredVersion);
  if (!declaredDate) {
    return { kind: "forged" };
  }

  const current = input.currentVersion;

  // No catalog imported at all yet: nothing can be "current or within
  // window" — fail closed rather than guessing.
  if (current === null) {
    return { kind: "stale" };
  }

  const cmp = compareCatalogVersions(input.declaredVersion, current);

  if (cmp > 0) {
    // Newer than what the server has imported. Build plan §3.3(i): a
    // date prefix more than maxFutureDays ahead of "now" is forged,
    // independent of any signature question.
    if (declaredDate.getTime() - input.now.getTime() > maxFutureDays * 24 * 60 * 60 * 1000) {
      return { kind: "forged" };
    }
    // Every other "newer" claim needs a verified manifestSig to become a
    // 202-queued outcome (AT 8). That verification is the caller's job
    // (classifyCatalogSubmission below) — from THIS function's point of
    // view alone, an unverified "newer" claim is never accepted, so it
    // reports "forged" as the default; the caller upgrades it to
    // "current_or_within_window" only after a real verified signature.
    return { kind: "forged" };
  }

  // AT 15: "a revoked-kid version gets 422 catalog_stale" — checked for
  // ANY version the server has a row for (current OR within-window),
  // independent of the normal skew arithmetic: a revoked signing key
  // means the release is no longer trusted, full stop.
  if (input.declaredVersionRow?.kidRevoked) {
    return { kind: "stale" };
  }

  if (cmp === 0) {
    return { kind: "current_or_within_window", resolvedVersion: input.declaredVersion };
  }

  // declaredVersion < current: within the skew window only if BOTH the
  // PUBLISH-ORDER gap and the row's own age are inside bounds, and the
  // row is one the server actually knows about.
  if (!input.declaredVersionRow || input.currentInternalVersion === null) {
    return { kind: "stale" };
  }
  if (input.currentInternalVersion - input.declaredVersionRow.internalVersion > maxVersionsBehind) {
    return { kind: "stale" };
  }
  const ageMs = input.now.getTime() - Date.parse(input.declaredVersionRow.publishedAt);
  if (!Number.isFinite(ageMs) || ageMs > maxAgeDays * 24 * 60 * 60 * 1000 || ageMs < 0) {
    return { kind: "stale" };
  }
  return { kind: "current_or_within_window", resolvedVersion: input.declaredVersion };
}

/** The AT 8 / G3-10 outer decision, folding in the signature check for a
 * "newer" claim. Kept separate from `classifyCatalogVersion` above so the
 * pure version-window arithmetic stays trivially testable without a
 * signature fixture, while this function is what the handler actually
 * calls. */
export interface ManifestSigClaim {
  kid: string;
  /** STANDARD (padded) base64 — the real P1 artifact signature format
   * (see signature.ts's own `base64ToBytes`/`verifyArtifactSignature`
   * note); this is NOT the base64url `fixId` uses. */
  signature: string;
  /** The exact bytes the signature covers — the caller (handler.ts)
   * builds this as the REAL P1 domain-tagged canonical-JSON statement
   * (`manifest-artifact.ts#MANIFEST_DOMAIN` + `canonicalStringify`), so
   * the verifier never has to guess a canonicalization and a real
   * `manifest.sig.json` value verifies here unmodified. */
  payload: string;
}

export type CatalogSubmissionOutcome =
  | { kind: "ok"; resolvedVersion: string }
  | { kind: "stale" }
  | { kind: "forged" };

export async function classifyCatalogSubmission(
  input: CatalogVersionClassifyInput & { manifestSig?: ManifestSigClaim },
  verifySignature: (claim: ManifestSigClaim) => Promise<boolean>,
): Promise<CatalogSubmissionOutcome> {
  const base = classifyCatalogVersion(input);
  if (base.kind === "current_or_within_window") {
    return { kind: "ok", resolvedVersion: base.resolvedVersion };
  }
  if (base.kind === "stale") {
    return { kind: "stale" };
  }
  // base.kind === "forged": the only path back from "forged" to "ok" is a
  // genuinely-newer (not far-future) claim carrying a manifestSig that
  // verifies against a REGISTERED, non-revoked key.
  const declaredDate = dateOf(input.declaredVersion);
  if (!declaredDate) return { kind: "forged" };
  const current = input.currentVersion;
  const cmp = current === null ? 1 : compareCatalogVersions(input.declaredVersion, current);
  const maxFutureDays = input.maxFutureDays ?? DEFAULT_MAX_FUTURE_DAYS;
  const isNewerNotFarFuture = cmp > 0 && declaredDate.getTime() - input.now.getTime() <= maxFutureDays * 24 * 60 * 60 * 1000;
  if (isNewerNotFarFuture && input.manifestSig) {
    const verified = await verifySignature(input.manifestSig);
    if (verified) {
      return { kind: "ok", resolvedVersion: input.declaredVersion };
    }
  }
  return { kind: "forged" };
}
