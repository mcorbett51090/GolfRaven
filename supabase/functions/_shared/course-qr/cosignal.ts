// supabase/functions/_shared/course-qr/cosignal.ts
//
// P5.1a S2a: does a scan's fix QUALIFY as a co-signal (build plan §4.5 "Co-signal", §4.6(q))? "A foreground, non-simulated fix taken against a server challenge, inside the
// polygon + 50 m of a `play-verified` facility", whose attestation did not grade `failed`. The scorer already owns this definition (packages/rules `isQualityCoSignalFix`, the
// predicate `presence_signal` itself uses); this is its twin over the server-derived `DerivedFix`, kept in lock-step by a drift test that runs BOTH over a grid of fixes
// (supabase/tests/unit/course-qr-cosignal.test.ts). It exists, instead of importing the scorer's, because that function is package-internal and the vendored scoring tree
// exposes only `scorePlay` / `parseScorePlayInput` (generate-bundle.sh): re-exporting an internal through the vendor is a wider change than this slice should make.
//
// A fix that does not qualify is simply not a co-signal (a `pending` purchase, no evidence row). A `failed` grade is not a refusal either: the check-in token already
// opened `fraud_signal(attestation_failed)` when it graded the attestation, and "a `failed` verdict removes the fix's co-signal status, so nothing is earned on it" (§7.5).

import type { DerivedFix } from "../evidence/derive-fix.ts";

/** The co-signal accuracy ceiling in metres: packages/rules `ACCURACY_METERS_MAX`. */
export const COSIGNAL_ACCURACY_METERS_MAX = 50;

export type CoSignalGrade = "attested" | "unattestable";

/** `attested` or `unattestable` when `fix` qualifies as a co-signal at `facilityId`; `null` otherwise (including a `failed` grade). */
export function coSignalGrade(fix: DerivedFix, facilityId: string): CoSignalGrade | null {
  if (fix.facilityId !== facilityId) return null;
  if (fix.fromApp !== true || fix.simulated !== false || fix.foreground !== true) return null;
  if (fix.challenge !== "live" && fix.challenge !== "prefetched") return null;
  if (!Number.isFinite(fix.accuracyMeters) || fix.accuracyMeters < 0 || fix.accuracyMeters > COSIGNAL_ACCURACY_METERS_MAX) return null;
  if (fix.geometryKind !== "polygon" || fix.verificationTier !== "play-verified" || fix.insideBuffer !== true) return null;
  // the grade: a token the server issued (`present`) carries its own; a fix with no token has `challenge: "none"` and was refused above
  if (!fix.token.present) return null;
  return fix.token.grade === "attested" || fix.token.grade === "unattestable" ? fix.token.grade : null;
}
