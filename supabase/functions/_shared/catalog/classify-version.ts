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
// ⛔ STUB, clearly marked (task instruction: "stub only what truly needs
// the not-yet-built importer, and mark each such stub clearly"):
// verifying a `manifestSig` requires the §4.8 Ed25519 keyset/kid registry
// AND the import pipeline that actually publishes signed catalog
// releases — neither exists yet (import-catalog is explicitly out of
// this round's scope, and no `catalog_signing_key` data is seeded in this
// environment). `verifySignatureFn` below IS a real, unit-tested Ed25519
// verifier (supabase/functions/_shared/catalog/signature.ts) — the
// MECHANISM is implemented, not faked — but with no keys ever registered
// in `app.catalog_signing_key` (a new, empty-by-default table this
// round's migration adds), every verification attempt fails closed by
// construction, which is exactly the safe default G3-10 asks for ("a
// newer [version] without a verifying manifestSig gets 422
// catalog_forged"). The one AT 8/G3-10 outcome this necessarily defers is
// "a validly signed newer version triggers an import" — there is no
// import pipeline to trigger in this round, so that half stays untested
// beyond the unit-level signature-verification path itself.

export type CatalogVersionClassification =
  | { kind: "current_or_within_window"; resolvedVersion: number }
  | { kind: "stale" }
  | { kind: "forged" };

export interface CatalogVersionClassifyInput {
  /** The `catalogVersion` the submission claims. */
  declaredVersion: number;
  /** The server's own most-recently-imported version (max app.
   * catalog_version.version), or null if none exist yet. */
  currentVersion: number | null;
  /** The app.catalog_version row for `declaredVersion`, if the server has
   * ever imported that exact version (null otherwise). */
  declaredVersionRow: { publishedAt: string } | null;
  now: Date;
  /** §3.3 / §4.4: "published_at drives the 30-day acceptance window." */
  maxAgeDays?: number;
  /** AT 8: "version 5 releases... old". */
  maxVersionsBehind?: number;
  /** A version more than this far ahead of `currentVersion` is treated as
   * far-future regardless of signature (G3-10: "a far-future
   * catalogVersion... gets 422 catalog_forged"), never merely "unverified
   * -sig forged" — kept generous (well above maxVersionsBehind) since a
   * legitimate release cadence and this far-future guard are different
   * concerns. */
  farFutureVersionsAhead?: number;
}

const DEFAULT_MAX_AGE_DAYS = 30;
const DEFAULT_MAX_VERSIONS_BEHIND = 5;
const DEFAULT_FAR_FUTURE_VERSIONS_AHEAD = 25;

export function classifyCatalogVersion(input: CatalogVersionClassifyInput): CatalogVersionClassification {
  const maxAgeDays = input.maxAgeDays ?? DEFAULT_MAX_AGE_DAYS;
  const maxVersionsBehind = input.maxVersionsBehind ?? DEFAULT_MAX_VERSIONS_BEHIND;
  const farFutureAhead = input.farFutureVersionsAhead ?? DEFAULT_FAR_FUTURE_VERSIONS_AHEAD;

  if (!Number.isInteger(input.declaredVersion) || input.declaredVersion < 0) {
    return { kind: "forged" };
  }

  const current = input.currentVersion;

  // No catalog imported at all yet: nothing can be "current or within
  // window" — fail closed rather than guessing.
  if (current === null) {
    return { kind: "stale" };
  }

  if (input.declaredVersion > current) {
    // Newer than what the server has imported. G3-10: far-future (well
    // beyond a plausible next release) is always forged, independent of
    // any signature question.
    if (input.declaredVersion - current > farFutureAhead) {
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

  if (input.declaredVersion === current) {
    return { kind: "current_or_within_window", resolvedVersion: input.declaredVersion };
  }

  // declaredVersion < current: within the skew window only if BOTH the
  // version-count gap and the row's own age are inside bounds, and the
  // row is one the server actually knows about.
  if (current - input.declaredVersion > maxVersionsBehind) {
    return { kind: "stale" };
  }
  if (!input.declaredVersionRow) {
    return { kind: "stale" };
  }
  const ageMs = input.now.getTime() - Date.parse(input.declaredVersionRow.publishedAt);
  if (!Number.isFinite(ageMs) || ageMs > maxAgeDays * 24 * 60 * 60 * 1000 || ageMs < 0) {
    return { kind: "stale" };
  }
  return { kind: "current_or_within_window", resolvedVersion: input.declaredVersion };
}

/** The AT 8 / G3-10 outer decision, folding in the (stubbed-fail-closed)
 * signature check for a "newer" claim. Kept separate from
 * `classifyCatalogVersion` above so the pure version-window arithmetic
 * stays trivially testable without a signature fixture, while this
 * function is what the handler actually calls. */
export interface ManifestSigClaim {
  kid: string;
  signatureB64Url: string;
  /** The exact bytes the signature covers — the caller (handler.ts)
   * builds this canonically (e.g. `${declaredVersion}`) so the verifier
   * never has to guess a canonicalization. */
  payload: string;
}

export type CatalogSubmissionOutcome =
  | { kind: "ok"; resolvedVersion: number }
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
  // verifies against a REGISTERED, non-revoked key — see this module's
  // own header for why that never happens in an environment with no keys
  // registered.
  const current = input.currentVersion ?? -1;
  const farFutureAhead = input.farFutureVersionsAhead ?? DEFAULT_FAR_FUTURE_VERSIONS_AHEAD;
  const isNewerNotFarFuture = input.declaredVersion > current && input.declaredVersion - current <= farFutureAhead;
  if (isNewerNotFarFuture && input.manifestSig) {
    const verified = await verifySignature(input.manifestSig);
    if (verified) {
      return { kind: "ok", resolvedVersion: input.declaredVersion };
    }
  }
  return { kind: "forged" };
}
