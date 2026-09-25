// supabase/functions/_shared/evidence/derive-fix.ts
//
// Turns a CLIENT-SUBMITTED `FixSubmission` (request-shape.ts — lat/lng,
// accuracy, timestamps, and the fix's own quality flags) into the
// server-derived `AppFix` shape `packages/rules`' bundled `scorePlay`
// expects (score-play.ts's own TRUST TABLE doc), by looking up:
//
//   - `verificationTier` / `geometryKind` / `insideBuffer` — REAL PostGIS
//     containment (Repo#catalog.matchFix; not a stub — see types.ts's
//     own doc), when the evidence row carries a `courseId`. Facility
//     -level evidence (no `courseId` — the H3 residual rule, always
//     allowed) has no course geometry to check against, so these default
//     conservatively (unverified/radius/false — never a co-signal, never
//     inflates a score).
//   - `challenge` / `token` — from the checkin-token session the fix ties
//     itself to via `checkinTokenJti`
//     (`Repo#checkinToken.consumeForFix` — evidence/handler.ts calls this
//     BEFORE calling `deriveFix`, since consuming is a write with its own
//     ownership/window/device checks; this module just formats whatever
//     that call already decided). No token reference at all, or the
//     consume call itself returning null (already consumed, expired,
//     wrong device, or outside the challenge window — P3c gate round 2,
//     item 4) -> `challenge: "none"`, `token: {present: false, ...}`
//     (G3-08's own "no token" grading rule, applied the same way
//     checkin-token itself applies it — see checkin/token-handler.ts).
//
// Pure: takes everything through parameters, no I/O of its own.

export interface MatchResult {
  verificationTier: "unverified" | "listed-verified" | "play-verified";
  geometryKind: "polygon" | "radius";
  insideBuffer: boolean;
}

const DEFAULT_MATCH: MatchResult = { verificationTier: "unverified", geometryKind: "radius", insideBuffer: false };

export interface ConsumedToken {
  attestationGrade: "attested" | "unattestable" | "failed";
  challengeKind: "live" | "prefetched";
}

export interface DerivedFix {
  fixId: string;
  facilityId: string;
  fromApp: boolean;
  simulated: boolean;
  foreground: boolean;
  challenge: "live" | "prefetched" | "none";
  token: { present: true; grade: "attested" | "unattestable" | "failed" } | { present: false; hardwareSupportsAttestation: boolean };
  verificationTier: "unverified" | "listed-verified" | "play-verified";
  geometryKind: "polygon" | "radius";
  insideBuffer: boolean;
  accuracyMeters: number;
  capturedAt: number;
  localDate: string;
}

export interface FixQuality {
  fixId: string;
  accuracyMeters: number;
  capturedAt: number;
  simulated: boolean;
  foreground: boolean;
  fromApp: boolean;
}

export interface DeriveFixInput {
  fix: FixQuality;
  /** The evidence row's own (already-resolved) facility id — every fix in
   * a submission is anchored to the evidence row's facility, never a
   * per-fix client claim. */
  resolvedFacilityId: string;
  /** localDate the evidence row itself is anchored to (server-cross
   * -checked against capturedAt by the bundled parser downstream — this
   * module just carries it through). */
  localDate: string;
  /** null when the evidence row has no course anchor at all (H3 residual:
   * facility-level evidence, always allowed) OR the course id doesn't
   * resolve. */
  match: MatchResult | null;
  /** null when the fix carried no `checkinTokenJti`, or the atomic
   * consume call already rejected it (see this module's own header). */
  consumedToken: ConsumedToken | null;
}

export function deriveFix(input: DeriveFixInput): DerivedFix {
  const match = input.match ?? DEFAULT_MATCH;
  const challenge: "live" | "prefetched" | "none" = input.consumedToken ? input.consumedToken.challengeKind : "none";
  const token: DerivedFix["token"] = input.consumedToken
    ? { present: true, grade: input.consumedToken.attestationGrade }
    : { present: false, hardwareSupportsAttestation: false };

  return {
    fixId: input.fix.fixId,
    facilityId: input.resolvedFacilityId,
    fromApp: input.fix.fromApp,
    simulated: input.fix.simulated,
    foreground: input.fix.foreground,
    challenge,
    token,
    verificationTier: match.verificationTier,
    geometryKind: match.geometryKind,
    insideBuffer: match.insideBuffer,
    accuracyMeters: input.fix.accuracyMeters,
    capturedAt: input.fix.capturedAt,
    localDate: input.localDate,
  };
}
