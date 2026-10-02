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
//
// ⛔ REWRITE (P3c gate round 2, item 5: "withOwnership ignores the
// actor"). The prior shape took `userId` as an explicit parameter on
// almost every method — meaning nothing stopped a caller (a bug in
// handler.ts, or a future one) from passing a DIFFERENT user's id than
// `actor.uid` and having it silently honoured; `privileged.ts`'s real
// implementation never even READ `actor` at all. Every method below now
// takes NO user-identity parameter — `privileged.ts#buildRepo(trx,
// actor)` closes over `actor.uid` once and every query is parameterized
// with THAT closed-over value, so passing a different user's id is no
// longer a thing a caller CAN do, not merely a thing it's not supposed
// to do. Grouped into narrow, per-resource objects (§4.7.1a: "named
// methods over fixed tables") rather than one flat 20-method interface.

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

export interface MatchResult {
  verificationTier: "unverified" | "listed-verified" | "play-verified";
  geometryKind: "polygon" | "radius";
  insideBuffer: boolean;
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
  /** P3c gate round 3, blocking HIGH 1+2: SHA-256 hex of the entire
   * parsed, validated client submission (handler.ts's own
   * `computeInputHash`) — stored once at insert, compared on every later
   * request that resolves to the same (user, source, source_ref) BEFORE
   * any side effect. See the 0019 migration's own column comment. */
  inputHash: string;
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
  deviceId: string;
}

export interface InsertEvidenceResult {
  id: string;
  wasNew: boolean;
  status: string;
  inputHash: string;
}

/** What `Repo#evidence.findExisting` returns — just enough for
 * `handler.ts`'s replay-vs-conflict decision (P3c gate round 3, blocking
 * HIGH 1+2) without pulling in the full scoring-relevant shape
 * `StoredEvidenceRow` carries; the replay path re-fetches through
 * `listForPlay` (unchanged) once it knows a match is safe to build from
 * already-persisted rows only. */
export interface ExistingEvidenceRow {
  id: string;
  status: string;
  inputHash: string;
  facilityId: string;
  courseId: string | null;
  localDate: string;
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
  /** Only ids that actually CONTRIBUTED to the scorer's result (build
   * plan P3c gate round 2, item 1: "link only rows that weren't
   * excluded") — never every row that happened to be in the candidate
   * set. */
  evidenceIds: string[];
}

export interface UpsertPlayResult {
  id: string;
  created: boolean;
}

/** P3c gate round 4, blocking MEDIUM ("replays skip every rate limit" —
 * fix item "make the replay path read-only"): what `Repo#play.getForDate`
 * reads back, unscored, from an already-persisted `app.play` row — the
 * exact fields `evidence/handler.ts#buildReplayResult` needs to answer a
 * replay without re-running `scorePlay`/`upsertFromScore` at all. */
export interface StoredPlayRow {
  id: string;
  scoreBadge: number;
  scoreMonetary: number;
  presenceSignal: boolean;
  money: boolean;
  heldReview: boolean;
}

export interface RateLimitResult {
  ok: boolean;
  count: number;
  retryAfterSeconds?: number;
}

/** What `private.delete_my_data` itself returns (0015, unchanged by
 * P3d) — the two fields `me-delete`'s response surfaces to the caller.
 * `Repo#me.deleteMyData` parses this out of the function's own `jsonb`
 * result (`{"user_id": ..., "deleted_at": ...}`, 0015's own
 * `jsonb_build_object` call). */
export interface DeleteMyDataResult {
  userId: string;
  deletedAt: string;
}

/** P3d, `GET /v1/me/export`: the raw `jsonb` `private.export_my_data`
 * returns — one key per personal table (as `private.pii_retention_policy`
 * classifies it), each value the caller's own rows as a JSON array. Kept
 * as `Record<string, unknown>` rather than a fully-typed shape on
 * purpose: the export function's OWN job (see its migration's header) is
 * to stay in lockstep with `private.pii_retention_policy` as tables are
 * added, and a hand-maintained TS type for its output would be exactly
 * the kind of second source of truth that guarantee exists to avoid. */
export type ExportMyDataResult = Record<string, unknown>;

export interface ChallengeRow {
  id: string;
  deviceId: string;
  facilityId: string | null;
  nonceHash: string;
  kind: "live" | "prefetched";
  expiresAt: string;
  usedAt: string | null;
}

/** The outcome of atomically consuming a checkin-token FOR ONE FIX (P3c
 * gate round 2, item 4): the single UPDATE that marks it consumed also
 * enforces — in the SAME statement, so there is no read-then-check race —
 * ownership (the token's own `user_id`, already implied by
 * `checkinToken.consumeForFix` being actor-scoped), the submitting
 * device matching the token's own `device_id`, and the fix's own
 * `capturedAt` falling inside `[issued_at, expires_at]`. A `null` result
 * means ANY of those failed (already consumed, expired, wrong device, or
 * outside the window) — the caller never learns WHICH, by design: a
 * fix that isn't a valid co-signal is simply not one, not a distinct
 * error to leak probing information through. */
export interface ConsumedCheckinToken {
  facilityId: string | null;
  attestationGrade: "attested" | "unattestable" | "failed";
  challengeKind: "live" | "prefetched";
}

/** The narrow repository object `withOwnership()` hands to its callback
 * (build plan §4.7.1a: "named methods over fixed tables... never the
 * supabase-js client"). Every method is already scoped to the `actor`
 * that produced it — see this file's own header for why no method takes
 * a user-identity parameter any more. */
export interface Repo {
  now(): Date;

  // ⛔ REMOVED (P3c gate round 4, blocking HIGH: "5 concurrent requests
  // deadlock the pool"). There is deliberately NO `rateLimit` member on
  // `Repo` any more — a Repo method is only ever reachable from inside
  // an already-open `withOwnership`/`withOwnershipBatch` transaction,
  // which already holds one of the pool's limited connections; a method
  // that opened a SECOND one from there (round 3's own `rateLimit.hit`)
  // is exactly what deadlocked the pool under real concurrency. Every
  // rate-limit hit now goes through `privileged.ts#hitRateLimitForActor`
  // directly, called BEFORE the transaction opens — see that function's
  // own doc for the full reasoning. This is a structural removal, not a
  // deprecation: nothing on `Repo` should ever open its own connection.

  catalog: {
    currentVersion(): Promise<CatalogVersionRow | null>;
    versionRow(version: number): Promise<CatalogVersionRow | null>;
    /** Resolves a catalog id THROUGH its merge closure (tombstoned ->
     * merged_into, followed to the survivor) itself — callers never walk
     * the chain by hand. Returns the row the id ULTIMATELY resolves to
     * (already the survivor if the input was tombstoned), or null if the
     * id (or, after following merges, its survivor) is not in the ledger
     * at all. */
    resolveLedgerId(id: string): Promise<LedgerRow | null>;
    facilityTz(facilityId: string): Promise<string | null>;
    courseFacilityId(courseId: string): Promise<string | null>;
    /** The course's own catalog hole count (P3c gate round 2, item 6:
     * "derive holes for foreground_dwell from the catalog, not the
     * client"). 0 when no `app.catalog_hole` rows are on record for it. */
    courseHoleCount(courseId: string): Promise<number>;
    /** Real PostGIS point-in-polygon (or, for a `listed-verified` course
     * with no polygon, point-in-radius) containment check against the
     * course's own catalog geometry — build plan §4.2/§4.5 ("inside the
     * facility's polygon + 50m"; "matched to a radius-fallback circle...
     * capped at 0.50"). NOT a stub: `app.catalog_course` already carries
     * `boundary geometry`/`radius_center`/`radius_m` plus a GiST index
     * (0002_catalog_tables.sql), so this runs `ST_DWithin` server-side —
     * see privileged.ts's implementation. Returns null if the course id
     * doesn't exist. */
    matchFix(courseId: string, lat: number, lng: number): Promise<MatchResult | null>;
    signingKey(kid: string): Promise<SigningKeyRow | null>;
  };

  evidence: {
    countOpenQueued(): Promise<number>;
    insertIdempotent(row: NewEvidenceRow): Promise<InsertEvidenceResult>;
    /** Filters on the evidence row's own REAL `local_date` column (P3c
     * gate round 2, item 1) — never a jsonb `summary->>'localDate'` read,
     * and never a fail-open `coalesce(..., $queriedDate)` that would make
     * every prior row match every date queried. Capped at
     * `ABSOLUTE_ROW_CAP` (packages/rules' own DoS bound). */
    listForPlay(facilityId: string, courseId: string, localDate: string): Promise<StoredEvidenceRow[]>;
    /** P3c gate round 3, blocking HIGH 1+2: looks up an existing row by
     * the actor-scoped (source, source_ref) BEFORE any side effect —
     * `handler.ts` calls this first, unconditionally, so a replay (same
     * identity) is detected before a token is consumed, a fraud signal
     * fires, a rate-limit bucket is hit, or a device row is created.
     * `null` means genuinely new. */
    findExisting(source: string, sourceRef: string): Promise<ExistingEvidenceRow | null>;
  };

  play: {
    upsertFromScore(input: UpsertPlayInput): Promise<UpsertPlayResult>;
    /** P3c gate round 4, blocking MEDIUM: a plain, unscored read of the
     * already-persisted play row for (courseId, playDate) — no advisory
     * lock, no write. Used by a replay's own response reconstruction,
     * which must never re-score or re-upsert. `null` if no play row
     * exists yet for this (user, courseId, playDate) — either a batch's
     * own deferred-scoring window, or (P3d gate round 3, S2) a live
     * retry of a course-anchored replay whose group was left unscored by
     * an interrupted batch; see `buildReplayResult`'s own doc for both
     * shapes. */
    getForDate(courseId: string, playDate: string): Promise<StoredPlayRow | null>;
  };

  fraudSignal: {
    /** P3d gate round 3, S2: idempotent when `detail.playId` is a string
     * — a second `insert` call with the SAME `kind` and the SAME
     * `detail.playId` is a silent no-op (no duplicate row), so a
     * `finalizeScoringForKey` retry (either an interrupted batch's own
     * follow-up finalize, or `buildReplayResult`'s new live-retry path)
     * never raises a second `quarantined_evidence_row` signal for a play
     * that already has one. `detail` with no `playId` (e.g. the
     * `clock_skew` kind, keyed on `fixIds` instead) is never deduped —
     * always inserts, unchanged from before. */
    insert(kind: string, detail: Record<string, unknown>): Promise<void>;
  };

  device: {
    /** Looks up a device WITHOUT creating one — P3c gate round 2, item 7
     * ("don't create device rows on rejected requests"): the caller
     * checks the device cap against this BEFORE ever calling `ensureOwn`,
     * so a request that will be rejected for being over the per-user
     * device cap never creates the row it's about to reject. */
    findOwn(deviceId: string): Promise<{ id: string } | null>;
    ensureOwn(deviceId: string | null, platform: "ios" | "android" | null): Promise<{ id: string }>;
    /** How many `app.device` rows this actor already owns — P3c gate
     * round 2, item 7 ("cap the number of devices per user"). */
    countForUser(): Promise<number>;
  };

  challenge: {
    /** ⛔ FIX (P3c gate round 4): `staffUserId` removed — dead weight,
     * since staff/partner-attest issuance is out of this round's scope
     * and no real call site ever passed anything but `null`. Every
     * challenge this round is issued to the authenticated actor
     * themselves. */
    insert(input: { deviceId: string; facilityId: string | null; nonceHash: string; kind: "live" | "prefetched"; expiresAt: string }): Promise<{ id: string; expiresAt: string }>;
    countOpenPrefetched(deviceId: string): Promise<number>;
    /** Actor-scoped: only ever returns a row this actor OR the matching
     * staff account owns. */
    getOwn(challengeId: string): Promise<ChallengeRow | null>;
    /** Atomic single-use consumption, now REQUIRING the presented nonce
     * to hash-match the stored one (should-fix, P3c gate round 2:
     * "checkin-token must require the challenge nonce and compare its
     * hash") — `UPDATE ... WHERE id = $1 AND nonce_hash = $2 AND used_at
     * IS NULL RETURNING id`. Returns `true` iff THIS call was the one
     * that consumed it. */
    consume(challengeId: string, nonceHash: string): Promise<boolean>;
  };

  checkinToken: {
    insert(input: { challengeId: string; deviceId: string; facilityId: string | null; attestationGrade: "attested" | "unattestable" | "failed"; challengeKind: "live" | "prefetched"; expiresAt: string }): Promise<{ jti: string; expiresAt: string }>;
    /** Atomically consumes the token FOR ONE FIX — see
     * `ConsumedCheckinToken`'s own doc for exactly what one call enforces
     * in a single statement. */
    consumeForFix(jti: string, submittingDeviceId: string, capturedAtMs: number): Promise<ConsumedCheckinToken | null>;
  };

  /** P3d: `DELETE /v1/me` and `GET /v1/me/export` (build plan §4.7.1a
   * inventory: "me-export, me-delete... ). Both call the SAME
   * `private.pii_retention_policy`-driven registry (0014/0021) — see
   * `_shared/me/delete-handler.ts`/`export-handler.ts`'s own header for
   * how that keeps the two from drifting apart. */
  me: {
    /** Every provider row the caller has an OAuth-style grant under,
     * read BEFORE `deleteMyData()` removes the rows (the P4/P8
     * revocation seam — `_shared/me/provider-revocation.ts` — needs the
     * provider names to call a real revocation endpoint against, once
     * one exists; this round it only logs the seam). Distinct plain
     * reads, not routed through `private.export_my_data` — the delete
     * path must not depend on the export function's own shape. */
    listSigninProviders(): Promise<string[]>;
    listConnectorProviders(): Promise<string[]>;
    /** Calls `private.delete_my_data(actor.uid)` (0015) through the
     * established privileged path — never reimplemented here (task
     * instruction). Idempotent: calling it again after the caller's
     * personal rows are already gone is a documented no-op (0015's own
     * generic pass affects 0 rows; nothing raises) — see
     * `delete-handler.ts`'s own doc for the full idempotency argument. */
    deleteMyData(): Promise<DeleteMyDataResult>;
    /** Calls `private.export_my_data(actor.uid)` (0021) — the read-only
     * twin of `deleteMyData()` above, driven by the exact same registry
     * row set so the two "which tables count as personal" answers can
     * never drift apart (see 0021's own header). */
    exportMyData(): Promise<ExportMyDataResult>;
  };

  /** P3d: `POST /v1/me/push-token` (build plan line 832: "replaced on
   * reinstall, deleted by DELETE /v1/me"). `app.push_token`'s own PK is
   * `(user_id, device_id)` (0003) — a device is capped at one token, and
   * the device itself is capped at `MAX_DEVICES_PER_USER` (the SAME
   * accepted-follow-up constant `evidence/handler.ts`/`challenge-
   * handler.ts` already use, per push-token-handler.ts's own doc), so
   * "cap the number of tokens per user" is enforced by construction
   * through the device cap this repo method's caller already checks —
   * `countForUser` exists so the handler can still surface a clear count
   * without a second raw query. */
  pushToken: {
    /** Registers or replaces the token for OWN `deviceId` — `ON CONFLICT
     * (user_id, device_id) DO UPDATE`, so a reinstall (same device id,
     * new Expo token) naturally overwrites the prior row rather than
     * leaving a stale duplicate (build plan line 832: "replaced on
     * reinstall"). Does NOT create the device row — the caller resolves/
     * caps `deviceId` through `device.findOwn`/`ensureOwn` first, the
     * same ordering `evidence/handler.ts` already uses. */
    upsert(deviceId: string, expoToken: string): Promise<{ deviceId: string; updatedAt: string }>;
    countForUser(): Promise<number>;
  };
}
