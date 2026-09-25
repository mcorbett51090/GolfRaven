// supabase/functions/_shared/types.ts
//
// Shared, dependency-free types: the authenticated `Actor` (build plan
// §4.7.1a: "It loads the target row by id and asserts row.user_id =
// actor.uid") and the `Repo` narrow-repository-object interface
// `withOwnership()` (supabase/functions/_shared/privileged.ts) hands to
// its callback. Pure types only — zero runtime imports, zero Deno/Node
// globals — so both privileged.ts (the real implementation) and every
// pure handler module (supabase/functions/_shared/evidence/handler.ts,
// .../checkin/*.ts) can import this file without pulling in anything a
// unit test (supabase/tests/unit/*.test.ts, which never touches a live
// Supabase project) would need to fake beyond a plain object literal.

export type ActorRole = "authenticated" | "staff" | "manager" | "operator" | "admin";

/** The caller, resolved from their own JWT by
 * `privileged.ts#getActorFromRequest` — NEVER from a client-sent user id
 * (security doc §1: "token.grade... Server verification"; build plan
 * §4.7 "Roles and facilities never come from user_metadata"). `role` is
 * carried for forward compatibility with the partner routes this round
 * doesn't implement (partner-attest, etc.) — every route in THIS round
 * only ever checks `uid`, since none of P3c's endpoints are partner
 * -scoped. */
export interface Actor {
  uid: string;
  role: ActorRole;
}

export interface LedgerRow {
  id: string;
  kind: string;
  status: "stub" | "verified";
  verifiedInVersion: number | null;
  splitFrom: string | null;
  tombstonedAt: string | null;
  mergedInto: string | null;
  firstCatalogVersion: number;
}

export interface CatalogVersionRow {
  version: number;
  publishedAt: string; // ISO 8601
  contractVersion: string;
  sha256: string;
  kid: string;
}

export interface SigningKeyRow {
  kid: string;
  publicKeyB64Url: string;
  revokedAt: string | null;
}

/** A single stored `app.evidence` row, as read back for scoring — the
 * shape `scorePlay`'s `Evidence` union expects, PLUS the bookkeeping
 * columns (`id`/`status`) the handler itself needs. `summary`/`integrity`/
 * `cosignal` are the raw jsonb payloads `app.evidence` stores (§4.4
 * line 833); the handler reassembles the typed `Evidence` row the bundled
 * scorer expects from these before calling it. */
export interface StoredEvidenceRow {
  id: string;
  source: string;
  facilityId: string;
  courseId: string | null;
  localDate: string;
  attestationGrade: "attested" | "unattestable" | "failed";
  summary: Record<string, unknown>;
  integrity: Record<string, unknown>;
  cosignal: Record<string, unknown>;
}

export interface NewEvidenceRow {
  sourceRef: string;
  source: string;
  facilityId: string;
  courseId: string | null;
  startedAt: string | null;
  endedAt: string | null;
  localDate: string;
  summary: Record<string, unknown>;
  integrity: Record<string, unknown>;
  cosignal: Record<string, unknown>;
  attestationGrade: "attested" | "unattestable" | "failed";
  matcherVersion: string | null;
  catalogVersion: number | null;
  status: "accepted" | "queued_catalog" | "needs_attention" | "flagged" | "rejected";
  deviceId: string | null;
}

export interface InsertEvidenceResult {
  id: string;
  wasNew: boolean;
  status: string;
}

export interface UpsertPlayInput {
  courseId: string;
  facilityId: string;
  playDate: string;
  courseDisambiguatedBy: "geometry" | "staff" | "user" | null;
  scoreBadge: number;
  scoreMonetary: number;
  hardSignal: boolean;
  presenceSignal: boolean;
  money: boolean;
  heldReview: boolean;
  policyVersion: string;
  inputDigest: string;
  evidenceIds: string[];
}

export interface UpsertPlayResult {
  id: string;
  created: boolean;
}

export interface RateLimitResult {
  ok: boolean;
  count: number;
  retryAfterSeconds?: number;
}

/** The narrow repository object `withOwnership()` hands to its callback
 * (build plan §4.7.1a: "named methods over fixed tables... never the
 * supabase-js client"). Every method is already scoped to the `actor`
 * that produced it (privileged.ts stamps `actor.uid` into every write
 * itself — a caller of this interface cannot pass a different user id in,
 * because none of these methods TAKE one). */
export interface Repo {
  now(): Date;

  /** `private.hit_rate_limit` (build plan §4.7 item 8). Resolves to
   * `{ok: true, count}` under the limit, `{ok: false, count}` with the
   * exception caught server-side (never throws `P0429` up to the
   * caller — the handler decides how to respond). */
  hitRateLimit(bucketKey: string, windowSeconds: number, max: number): Promise<RateLimitResult>;

  currentCatalogVersion(): Promise<CatalogVersionRow | null>;
  catalogVersionRow(version: number): Promise<CatalogVersionRow | null>;
  /** Resolves a catalog id THROUGH its merge closure (tombstoned ->
   * merged_into, followed to the survivor) itself — callers never walk
   * the chain by hand. Returns the row the id ULTIMATELY resolves to
   * (already the survivor if the input was tombstoned), or null if the id
   * (or, after following merges, its survivor) is not in the ledger at
   * all. */
  resolveLedgerId(id: string): Promise<LedgerRow | null>;
  facilityTz(facilityId: string): Promise<string | null>;
  courseFacilityId(courseId: string): Promise<string | null>;
  /** Real PostGIS point-in-polygon (or, for a `listed-verified` course
   * with no polygon, point-in-radius) containment check against the
   * course's own catalog geometry — build plan §4.2/§4.5 ("inside the
   * facility's polygon + 50m"; "matched to a radius-fallback circle...
   * capped at 0.50"). NOT a stub: `app.catalog_course` already carries
   * `boundary geometry`/`radius_center`/`radius_m` plus a GiST index
   * (0002_catalog_tables.sql), so this runs `ST_DWithin` server-side —
   * see privileged.ts's implementation. Returns null if the course id
   * doesn't exist. */
  matchFix(courseId: string, lat: number, lng: number): Promise<{
    verificationTier: "unverified" | "listed-verified" | "play-verified";
    geometryKind: "polygon" | "radius";
    insideBuffer: boolean;
  } | null>;
  signingKey(kid: string): Promise<SigningKeyRow | null>;

  countOpenQueuedEvidence(userId: string): Promise<number>;
  insertEvidenceIdempotent(userId: string, row: NewEvidenceRow): Promise<InsertEvidenceResult>;
  listEvidenceForPlay(userId: string, facilityId: string, courseId: string, localDate: string): Promise<StoredEvidenceRow[]>;
  upsertPlayFromScore(userId: string, input: UpsertPlayInput): Promise<UpsertPlayResult>;
  insertFraudSignal(userId: string, kind: string, detail: Record<string, unknown>): Promise<void>;

  ensureOwnDevice(userId: string, deviceId: string | null, platform: "ios" | "android" | null): Promise<{ id: string }>;

  insertChallenge(input: {
    userId: string | null;
    staffUserId: string | null;
    deviceId: string;
    facilityId: string | null;
    nonceHash: string;
    expiresAt: string;
  }): Promise<{ id: string }>;
  countOpenPrefetchedChallenges(deviceId: string): Promise<number>;
  getOwnChallenge(challengeId: string, userId: string): Promise<
    | {
        id: string;
        deviceId: string;
        facilityId: string | null;
        expiresAt: string;
        usedAt: string | null;
      }
    | null
  >;
  /** Atomic single-use consumption: `UPDATE ... SET used_at = now() WHERE
   * id = $1 AND used_at IS NULL RETURNING id`. Returns `true` iff THIS
   * call was the one that consumed it (false if already used, racing or
   * not). */
  consumeChallenge(challengeId: string): Promise<boolean>;

  insertCheckinToken(input: {
    challengeId: string;
    userId: string;
    deviceId: string;
    facilityId: string | null;
    attestationGrade: "attested" | "unattestable" | "failed";
    challengeKind: "live" | "prefetched";
    expiresAt: string;
  }): Promise<{ jti: string; expiresAt: string }>;
  getCheckinToken(jti: string): Promise<
    | {
        jti: string;
        userId: string;
        deviceId: string;
        facilityId: string | null;
        attestationGrade: "attested" | "unattestable" | "failed";
        challengeKind: "live" | "prefetched";
        challengeId: string;
        expiresAt: string;
      }
    | null
  >;
}
