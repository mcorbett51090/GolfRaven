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

import type { AttestKeyRepo, RewardsRepo } from "./rewards/types.ts";
import type { SigninRepo } from "./signin/types.ts";

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
  /** P3e round 2 gate, H1: the site's own `yyyymmdd-gitsha7` version
   * string (`tools/catalog/src/manifest.ts`'s `CatalogVersionSchema`) —
   * `null` only for a pre-import-catalog fixture row that predates this
   * column (see 0023_catalog_import.sql's own comment). Every row a real
   * import writes always carries one. */
  siteVersion: string | null;
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
export type RepickRefusal = "not_same_split_family" | "no_such_play" | "target_play_exists" | "not_user_pick" | "already_repicked" | "cannot_rederive";

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

/** P3e round 2 gate, B3: a discriminated union, not one flat shape with
 * every field optional — matching `app.evidence`'s own
 * `evidence_queued_claim_shape` CHECK constraint (0024_evidence_queued_claims.sql):
 * a `resolved` row (status `accepted`) always carries a real
 * `facilityId`/`courseId?`/`catalogVersion?`; a `queued` row (status
 * `queued_catalog`) NEVER does — it carries the unconstrained
 * `claimedFacilityId`/`claimedCourseId?`/`claimedCatalogVersion` plus the
 * full `queuedInput` (the validated submission, re-derived at drain time —
 * B2) instead. The type system now makes "an accepted row with a claimed_*
 * field" or "a queued row with a resolved facilityId" impossible to
 * construct, not merely disallowed by convention. */
export type NewEvidenceRow =
  | {
      kind: "resolved";
      sourceRef: string;
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
      /** The RESOLVED internal `app.catalog_version.version` int (the DB
       * column's own FK target — unchanged by H1's wire-contract change,
       * which is about what the CLIENT submits, not this internal
       * bookkeeping value) — `null` only for a row scored before any
       * catalog was ever imported. The caller resolves the client's own
       * site-version string to this int via
       * `Repo#catalog.versionRowBySiteVersion` before calling this. */
      catalogVersion: number | null;
      status: "accepted";
      deviceId: string;
    }
  | {
      kind: "queued";
      sourceRef: string;
      inputHash: string;
      source: string;
      claimedFacilityId: string;
      claimedCourseId: string | null;
      claimedCatalogVersion: string;
      localDate: string;
      /** The FULL validated submission (request-shape.ts's own parsed
       * shape) — re-read at drain time to re-run real intake derivation
       * (B2), never merely a status flip. */
      queuedInput: Record<string, unknown>;
      deviceId: string;
      status: "queued_catalog";
    };

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
  // ⛔ WIDENED (P3e round 2 gate, B3): a `queued_catalog` row now has NO
  // resolved facilityId at all (only a `claimed*` one — see
  // `NewEvidenceRow`'s own `kind: "queued"` branch) — `null` here,
  // exactly like `courseId` already allowed. Safe: `buildReplayResult`
  // (evidence/handler.ts) returns unconditionally at its own
  // `status === "queued_catalog"` check, before it ever reads
  // `existing.facilityId` — every OTHER caller still supplies a real,
  // resolved facility id.
  facilityId: string | null;
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

/** The token an already-consumed challenge produced (`app.checkin_token` is UNIQUE(challenge_id): one token per challenge). Read by
 * `checkin-token` to make a repeat redemption idempotent. */
export interface IssuedCheckinTokenRow {
  jti: string;
  expiresAt: string;
  attestationGrade: "attested" | "unattestable" | "failed";
  /** Set once a fix consumed the token (`consumeForFix`): a consumed token is no longer a valid session. */
  consumedAt: string | null;
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
    /** P3e round 2 gate, H1: resolves a CLIENT-SUBMITTED site version
     * string (`yyyymmdd-gitsha7`) against `app.catalog_version.site_version`
     * — the lookup evidence intake actually needs now that the wire
     * contract carries the site string, not the internal int. */
    versionRowBySiteVersion(siteVersion: string): Promise<CatalogVersionRow | null>;
    /** Release-order rank of a site version: how many imported versions have a `site_version` at or before it (so the gap between two ranks is the number of RELEASES between them — never the internal `version` int, which is import order and diverges after a rollback republish). `null` when it has no `site_version` (pre-import-catalog fixtures). */
    releaseRank(siteVersion: string): Promise<number | null>;
    /** Resolves a catalog id THROUGH its merge closure (tombstoned ->
     * merged_into, followed to the survivor) itself — callers never walk
     * the chain by hand. Returns the row the id ULTIMATELY resolves to
     * (already the survivor if the input was tombstoned), or null if the
     * id (or, after following merges, its survivor) is not in the ledger
     * at all. */
    resolveLedgerId(id: string): Promise<LedgerRow | null>;
    /**
     * §8.6: may a play at this course still be RE-PICKED (so its raw fix
     * coordinates are worth keeping)? True only when the course is a ledger
     * `stub` (G3-01: only stubs split), or already in a split family (it has a
     * `split_from`, or is the kept course of one), or has an open rescore
     * backlog row. A verified, never-split course: false — nothing can move
     * its play, so coordinates are never stored.
     */
    repickEligible(courseId: string): Promise<boolean>;
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
    /** AT 18 (promotion): rewrites `verificationTier` inside the stored
     * derived fixes (`summary.fix/checkinFix/checkoutFix`) of the actor's
     * ACCEPTED evidence at (courseId, localDate) to the course's CURRENT
     * `verification_status` — the tier was frozen at ingest time from
     * the then-stub course. Returns the number of rows rewritten. */
    refreshFixTiers(courseId: string, localDate: string): Promise<number>;
    /** P3e round 2 gate, B2/B3: promotes a `queued_catalog` row (`id`) to
     * `accepted` IN PLACE (same row, same id — never a fresh insert) with
     * REAL, freshly re-derived facility/course/summary/attestation data —
     * clears `claimed_facility_id`/`claimed_course_id`/
     * `claimed_catalog_version`/`queued_input` at the same time (the
     * `evidence_queued_claim_shape` CHECK only allows those to be
     * non-null while `status = 'queued_catalog'`). Guarded
     * `WHERE status = 'queued_catalog'` — a no-op if the row has already
     * moved on (a concurrent resolution, or an operator manually
     * resolved it) since the caller read it. */
    resolveQueuedRow(
      id: string,
      resolved: { facilityId: string; courseId: string | null; summary: Record<string, unknown>; integrity: Record<string, unknown>; attestationGrade: "attested" | "unattestable" | "failed"; catalogVersion: number | null },
    ): Promise<void>;
    /** P3e round 2 gate, B2/M1: a queued row that will never resolve —
     * flips `status` to `needs_attention` (age-based, build plan §3.3:
     * "without a review_item") or `unknown_id` (M1: "an id still absent
     * after an import that covers its claimed version") — never scored,
     * never linked to a play. `claimed_*`/`queued_input` are DELIBERATELY
     * left in place (unlike `resolveQueuedRow`) — they are the only
     * record of what the row ever claimed, and the CHECK constraint does
     * not require clearing them outside `queued_catalog`. */
    markQueuedTerminal(id: string, status: "needs_attention" | "unknown_id"): Promise<void>;
    /** The row's own device id, needed by drain-time re-derivation
     * (`redrainQueuedEvidenceRow`) to re-check a fix's checkin-token
     * against the SAME submitting device the original live request used —
     * `null` if the row (or its device) is somehow gone. */
    deviceIdFor(id: string): Promise<string | null>;
    /**
     * Edge role PR3: the raw submission (`app.evidence.queued_input`) of a still-`queued_catalog` row of THIS actor, read
     * INSIDE the per-row transaction the drain opens as the row's owner. The system list (`private.list_queued_catalog`)
     * deliberately omits it (raw coordinates leave the owner's transaction only to the owner), so the drain never has it
     * until it is bound to the owner. Returns `null` if the row is no longer `queued_catalog` (a concurrent drain resolved it) or
     * is not this actor's; otherwise `{ queuedInput }`, whose value is whatever is stored (re-validated by the caller, so a NULL
     * or malformed one still ends the row terminally rather than leaving it queued forever).
     */
    readQueuedInput(id: string): Promise<{ queuedInput: unknown } | null>;
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
    /** AT 18: how many DISTINCT courses (resolved through the ledger's
     * `mergedInto` closure) this actor has a QUALIFYING play at — the
     * server-side `uniqueCourses`, mirroring packages/rules'
     * `playQualifies` (`score_badge >= 0.50 OR money`, at a `verified`
     * ledger course, not void/disputed). A stub course counts toward
     * nothing; a split's kept course counts once. */
    uniqueCourseCount(): Promise<number>;
    /** AT 18 (split): marks the play a `user` pick of its own course iff
     * it has no disambiguation yet and no OTHER user pick exists for the
     * same (facility, date) (the partial unique index). Returns whether
     * it was marked. */
    markUserPick(playId: string): Promise<boolean>;
    /** A2-01 / §4.2: how the play at (course, date) is disambiguated.
     *  - `stored` is the recorded `course_disambiguated_by` (null when there is
     *    no play yet or no label) — the ONLY value ever written back.
     *  - `effective` is what the SCORER must be told. It equals `stored`, except
     *    that a play with no label at a course in a split family (the kept
     *    course or any sibling) is a `user` pick — "a split play is always a
     *    user pick and never money" — even when the DB label could not be set
     *    (the one-user-pick-per-facility-date index blocked it). Without this a
     *    second split play at the same facility and date was left uncapped.
     * The scorer caps a `user` pick (0 to `score_monetary`) ONLY when every
     * scored evidence row carries the label, so every scoring path reads this
     * first (plain SELECT, no lock). */
    disambiguation(courseId: string, playDate: string): Promise<{ stored: "geometry" | "staff" | "user" | null; effective: "geometry" | "staff" | "user" | null }>;
    /**
     * Takes the per-(user, course, date) scoring advisory lock (the SAME key
     * `upsertFromScore` takes, held to commit) BEFORE the caller reads the
     * play's evidence. Without it two scorers (a live submission and the
     * promotion re-score) each read the evidence set, score, and only then
     * serialize at `upsertFromScore` — the later writer can overwrite with a
     * score computed from a stale evidence set (found by the promotion-vs-live
     * race test, restricted harness run). Taking the lock first means the
     * later scorer's reads run AFTER the earlier one committed (READ
     * COMMITTED sees its rows).
     */
    lockForScoring(courseId: string, playDate: string): Promise<void>;
    /** AT 18 (re-pick) step 1 — takes the advisory locks of BOTH plays (the
     * same key family as `upsertFromScore`, stable order) and checks every
     * precondition: same split family, a play exists at `fromCourseId`, it
     * is a `user` pick, it has NOT been re-picked before (exactly ONE
     * re-pick, recorded in `app.audit_log`), and no other play occupies the
     * target. Returns `ok:false` with a reason instead of throwing. */
    repickPrepare(args: { facilityId: string; playDate: string; fromCourseId: string; toCourseId: string }): Promise<{ ok: true; playId: string } | { ok: false; reason: RepickRefusal }>;
    /** AT 18 (re-pick) step 2 — moves the play (and its evidence rows, each
     * with its RE-DERIVED `summary`/`integrity` — supplied by the handler
     * after re-running the matcher against the target course) to
     * `toCourseId`, keeps it a `user` pick, and writes the audit row. Must
     * follow a successful `repickPrepare` in the SAME transaction. */
    repickApply(args: { facilityId: string; playDate: string; fromCourseId: string; toCourseId: string; playId: string; rederived: { evidenceId: string; summary: Record<string, unknown> }[] }): Promise<void>;
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

  /** P3f: `POST /v1/rewards/{id}/activate` (build plan §7.5, A2-08) — the
   * reward-activation reads and writes, defined in ./rewards/types.ts. */
  rewards: RewardsRepo;

  /** App Attest key registration (`POST /v1/devices/attest-key`, P3f follow-up F2) — defined in
   * ./rewards/types.ts. */
  attestKey: AttestKeyRepo;

  /** O12: `me-signin-methods` and the provider-grant revocation (build plan §3.4, §7.8) — defined in ./signin/types.ts. */
  signin: SigninRepo;

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
    /** 0042: sets this OWN device's platform iff it is still unknown (NULL) — the first platform-bearing use wins — and returns the platform on
     * record afterwards, so the caller can refuse a mismatch. `null` for a device that is not the actor's own. Never changes a set platform.
     * `ensureOwn(id, null)` (the challenge and evidence endpoints, which carry no platform) leaves the platform unknown. */
    claimPlatform(deviceId: string, platform: "ios" | "android"): Promise<"ios" | "android" | null>;
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
    /** The actor's own token for a CONSUMED challenge, or `null` (none was issued, or it is not this actor's). */
    findByChallenge(challengeId: string): Promise<IssuedCheckinTokenRow | null>;
    /** Has this actor ever been issued a token graded `attested` on this device? (The Android half of the "this device has shown it can
     * attest" evidence the no-attestation grading rule uses; the iOS half is a registered key, `Repo#rewards.deviceAttestState`.) */
    hasAttestedOnDevice(deviceId: string): Promise<boolean>;
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

// ============================================================================
// P3e: `import-catalog` (build plan §3.3) — a SEPARATE, actor-FREE
// repository interface, not a member of `Repo` above. `Repo` is
// deliberately per-user (`buildRepo(trx, actor)` closes over `actor.uid`
// once — see this file's own header); `import-catalog` is a system
// operation with no user at all (no `auth.users` row, no JWT — see
// `_shared/catalog/webhook-auth.ts`'s own header for why that is the
// "explicit system-actor path rather than faking a user" the task asks
// for). Giving it a SEPARATE interface, rather than bolting write methods
// onto the shared, actor-scoped `Repo`, keeps every OTHER caller's own
// type surface (evidence/checkin/me) exactly as narrow as it already is.
// ============================================================================

export interface ImporterCurrentVersionRow {
  version: number;
  siteVersion: string | null;
}

export interface ImporterSigningKeyRow {
  kid: string;
  publicKeyB64Url: string;
  revokedAt: string | null;
}

export interface ImportVersionInput {
  siteVersion: string;
  contractVersion: string;
  sha256: string;
  kid: string;
  publishedAt: string;
}

export interface ImportVersionResult {
  version: number;
  wasNew: boolean;
}

export interface LedgerBaseRow {
  id: string;
  kind: string;
  firstCatalogVersionInt: number;
}

export interface LedgerStateRow {
  id: string;
  status: "stub" | "verified";
  tombstoned: boolean;
  mergedInto: string | null;
  verifiedInVersionInt: number | null;
  /** AT 18: sibling ids a `split` transition of THIS (kept) entry names. */
  splitSiblings: string[];
}

/** One `Trail.rosterVersions[]` entry, ready to persist (R3). */
export interface RosterVersionInput {
  trailId: string;
  version: number;
  effectiveFrom: string; // ISO date
  completionUnit: "course" | "facility" | "hole";
  markerUnit: "course" | "facility" | "hole";
  completionRule: { kind: "all" | "n_of_m"; n: number | null; source: string | null };
  markerRule: { kind: "all" | "n_of_m"; n: number | null; source: string | null };
  trackingStartsOn: string | null;
  members: Array<{ unit: "course" | "facility" | "hole"; courseId: string | null; anyOfCourseIds: string[] | null; facilityId: string | null; holeId: string | null; stopOrder: number | null; removedOn: string | null }>;
}

/** AT 18 rescore backlog row (migration 0026). */
export interface RescoreBacklogRow {
  id: number;
  courseId: string;
  reason: "promotion" | "split";
  /** Stable keyset position: (play created_at as Postgres text, play id). */
  cursor: RescoreCursor | null;
  /** Set once a page first came back short — the start of the straggler grace. */
  finishedAt: string | null;
  /** True once the closing straggler sweep (cursor rewound by the overlap) has begun. */
  swept: boolean;
  /** `finishedAt` is at least `sweepDelaySeconds` old (computed by the database clock). */
  sweepReady: boolean;
}

export interface RescoreCursor {
  createdAt: string;
  playId: string;
}

export interface RescorePlayRef {
  playId: string;
  userId: string;
  facilityId: string;
  courseId: string;
  playDate: string;
  /** The play's `created_at` as Postgres text (microsecond-exact, round-trips into the cursor). */
  createdAt: string;
}

export interface ImporterLedgerRow {
  id: string;
  kind: string;
  status: "stub" | "verified";
  mergedInto: string | null;
}

export interface QueuedEvidenceRow {
  id: string;
  userId: string;
  /** P3e round 2 gate, B3: the CLAIMED (unresolved) ids — `facility_id`/
   * `course_id` are always NULL on a queued row now (see
   * `evidence_queued_claim_shape`, 0024_evidence_queued_claims.sql). */
  claimedFacilityId: string;
  claimedCourseId: string | null;
  /** P3e round 2 gate, H1/M1: the site version STRING the row was queued
   * under — compared against the importer's own current site version to
   * tell "the covering import hasn't run yet, still legitimately queued"
   * apart from "it ran, and this id still doesn't exist" (M1's terminal
   * `unknown_id`). */
  claimedCatalogVersion: string;
  // Edge role PR3: NO `queuedInput` here. The system list never carries the raw submission (`private.list_queued_catalog`
  // omits it); the drain re-reads it as the row's OWNER, inside the per-row transaction (`Repo#evidence.readQueuedInput`).
  createdAt: string; // ISO 8601
}

/**
 * Edge role PR3: which row a delegated transaction acts on. A delegate is the system path's way of acting as ONE user for ONE
 * unit of work, and the database binds it only while the unit's precondition holds (migration 0030):
 *   queued_evidence  `private.bind_delegate_for_queued_evidence(evidenceId)`: valid only while that evidence row is `queued_catalog`;
 *   rescore          `private.bind_delegate_for_rescore(backlogId, playId)`: valid only while the backlog row is open and the play
 *                    is at that backlog row's course.
 * The owner it binds is the row's, never a value the caller supplies; the caller's `Actor` is what it EXPECTS, and a mismatch fails
 * closed before any work runs.
 */
export type DelegateRef = { kind: "queued_evidence"; evidenceId: string } | { kind: "rescore"; backlogId: number; playId: string };

/**
 * Edge role PR4b (E5): one retention class the independent retention purge (`retention-purge`) runs. Each class is a bounded definer
 * that `edge_system` may EXECUTE; `privileged.ts#retentionPurgeSteps` builds one step per class and the pure handler
 * (`_shared/retention/purge-handler.ts`) runs them, so the handler never sees a connection.
 */
export interface RetentionStep {
  name: "fix_coords" | "install_link_tombstones" | "signin_email_proofs" | "signin_revocation_queue" | "consumed_nonce" | "rate_limit_buckets";
  /** The most rows one batch removes (the definer's own `limit`, or its own constant bound); `null` = one unbatched pass (the definer has no row bound; no step is unbatched since 0040). The runner
   * repeats a batched step while a batch comes back FULL, up to its own per-run cap, so a backlog drains faster than one batch per run. */
  batchLimit: number | null;
  /** ONE batch in its own short `edge_system` transaction. Returns the rows removed, or `null` when another run holds this step's lock right
   * now (the batch was skipped, not failed: that run is doing the same work). */
  runBatch(): Promise<number | null>;
}

/** The shape `privileged.ts#withDelegatedActor` has: a transaction that binds the owner through the delegate binder and then acts as `edge_actor`. */
export type WithDelegatedActorFn = <T>(delegate: DelegateRef, actor: Actor, op: (repo: Repo) => Promise<T>) => Promise<T>;

/** The narrow repository object `privileged.ts#withSystemCatalogImport()`
 * hands to its callback — the importer's own counterpart to `Repo`. */
export interface ImporterRepo {
  now(): Date;

  catalog: {
    /** Every already-imported `(site_version -> version)` pair — used to
     * resolve a ledger entry's own `transitions[].catalogVersion` string
     * to the internal int FK `app.catalog_id_ledger.first_catalog_version`/
     * `verified_in_version` requires. */
    listSiteVersions(): Promise<Array<{ siteVersion: string; version: number }>>;
    currentVersion(): Promise<ImporterCurrentVersionRow | null>;
    /** Idempotent, keyed by `(site_version, sha256)` (task instruction:
     * "make the import idempotent, keyed by version and sha") — a
     * re-import of an already-seen `(siteVersion, sha256)` pair returns
     * the SAME row, `wasNew: false`, and writes nothing. A genuinely new
     * `siteVersion` is assigned the next `version` int under an advisory
     * lock (never a `GENERATED` identity column — see
     * 0023_catalog_import.sql's own comment for why: two pre-existing
     * fixture helpers insert an explicit `version` with no `site_version`
     * at all, and an identity column would reject that). A `siteVersion`
     * that already exists with a DIFFERENT `sha256` is a real conflict
     * (append-only violation / a forged replay of an old version number
     * with new content) — rejected, never silently overwritten. */
    importVersion(input: ImportVersionInput): Promise<ImportVersionResult>;
    getSigningKey(kid: string): Promise<ImporterSigningKeyRow | null>;
    /** M3: records every kid a verified manifest's revokedKids[] names
     * (append-only, app.catalog_kid_revocation — migration 0025). */
    recordRevokedKids(kids: string[], catalogVersion: string): Promise<void>;
    /** Pass 1 of the two-pass ledger apply (import-handler.ts's own doc):
     * `ON CONFLICT (id) DO NOTHING` inserts, so every id referenced by
     * ANY entry's own `mergedInto` exists before pass 2 sets it (the
     * column's own FK — 0002_catalog_tables.sql). Idempotent by
     * construction. */
    ensureLedgerIdsExist(rows: LedgerBaseRow[]): Promise<void>;
    /** Pass 2: applies status/tombstoned/mergedInto/verifiedInVersion —
     * every id referenced already exists (pass 1 already ran). Append-only
     * in EFFECT (never clears an already-`verified` status back to `stub`,
     * never un-tombstones — see import-handler.ts's own doc for exactly
     * what it will and won't overwrite). */
    applyLedgerState(rows: LedgerStateRow[]): Promise<void>;
    /** M3: a human-readable conflict description if any incoming entry
     * conflicts with already-stored ledger state (different merged_into,
     * or a tombstone reversal), else null. Set-based. */
    findLedgerConflict(rows: LedgerStateRow[]): Promise<string | null>;
    /** Resolves a catalog id through its merge closure — a system-scoped
     * duplicate of `Repo#catalog.resolveLedgerId`'s own SQL (privileged.ts),
     * kept SEPARATE rather than shared, per this file's own header on why
     * `ImporterRepo` doesn't reuse `Repo` machinery. */
    resolveLedgerId(id: string): Promise<ImporterLedgerRow | null>;
    // ⛔ NEW (P3e round 2 gate, H2/H3): the REAL directory shards
    // (`facilities/<region>.json`, `trails.json`, `designers.json` —
    // `_shared/catalog/directory-artifact.ts`'s own header names exactly
    // which fields are read and why geometry/roster-membership are
    // still out of scope). Every one is a SET-BASED upsert (H3: "replace
    // per-row writes with set-based upserts") — one round trip per
    // call, not one per row.
    upsertTrails(rows: { id: string; slug: string; name: string; catalogVersionInt: number }[]): Promise<void>;
    upsertDesigners(rows: { id: string; name: string; catalogVersionInt: number }[]): Promise<void>;
    upsertFacilities(rows: { id: string; slug: string; region: string; tz: string; name: string; verificationStatus: string; catalogVersionInt: number }[]): Promise<void>;
    upsertHoles(rows: { id: string; courseId: string; number: number; catalogVersionInt: number }[]): Promise<void>;
    /** R3: persists roster versions + members (set-based). A roster version is immutable per (trail, version): an already-stored one is left untouched (its members are only written alongside a NEWLY inserted version row). */
    upsertRosters(rows: RosterVersionInput[]): Promise<void>;
    /** AT 18, BEFORE applyLedgerState: the COURSE ids whose stored ledger status is `stub` and whose incoming entry is `verified`. */
    findStubPromotions(rows: LedgerStateRow[]): Promise<string[]>;
    /** AT 18, after ensureLedgerIdsExist: records `split_from` on every sibling still lacking one; returns the KEPT ids that gained at least one NEW sibling. */
    applySplits(rows: LedgerStateRow[]): Promise<string[]>;
    /** AT 18: queue course ids for re-scoring (idempotent per (course, reason, catalog version)). */
    enqueueRescore(courseIds: string[], reason: "promotion" | "split", catalogVersionInt: number): Promise<void>;
    upsertCourses(rows: { id: string; facilityId: string; designerId: string | null; name: string; holes: number | null; verificationStatus: string; closed: boolean; catalogVersionInt: number }[]): Promise<void>;
  };

  /** AT 18: the re-score backlog (migration 0026) — bounded work per run. */
  rescoreBacklog: {
    listOpen(limit: number, sweepDelaySeconds: number): Promise<RescoreBacklogRow[]>;
    /** A page came back short: records `finished_at` (once) and the cursor; the row stays open. */
    markFinished(id: number, cursor: RescoreCursor | null): Promise<void>;
    /** After the straggler grace: rewinds the cursor by `overlapSeconds` (database clock arithmetic on the stored timestamp, microsecond-exact) and starts the closing sweep. Returns the new cursor. */
    beginSweep(id: number, cursor: RescoreCursor | null, overlapSeconds: number): Promise<RescoreCursor | null>;
    /**
     * §8.6 minimisation: set-based purge of `integrity.fixCoords` from evidence
     * rows that can no longer be re-picked — course not a ledger stub / not in a
     * split family / no open backlog row for it, OR older than `retentionDays`.
     * At most `limit` rows per call. Returns the number of rows cleared.
     */
    purgeFixCoords(retentionDays: number, limit: number): Promise<number>;
    /**
     * F19 retention (owner decision 2026-10-02): the install-link fraud tombstone `app.install_link_account` is kept 24 months
     * from `first_seen_at` (mirroring `receipt_fingerprint`). Deletes at most `maxRows` expired rows, oldest first, through
     * `private.purge_install_link_tombstones`; the 24 months are the database's, not this call's. Returns the rows deleted.
     */
    purgeInstallLinkTombstones(maxRows: number): Promise<number>;
    /** Set-based keyset page of plays at `courseId` strictly after `after`, ordered by (created_at, id). */
    nextPlays(courseId: string, after: RescoreCursor | null, limit: number): Promise<RescorePlayRef[]>;
    advance(id: number, cursor: RescoreCursor | null, done: boolean): Promise<void>;
  };

  queuedCatalog: {
    /** Every open (`status = 'queued_catalog'`) evidence row, oldest
     * first, bounded — draining processes a bounded batch per run rather
     * than an unbounded table scan. Cross-user by design (this IS the
     * system-scoped importer repo) — the caller (drain-orchestrator.ts)
     * opens a PER-ROW, actor-scoped `Repo` transaction (via an injected
     * `withDelegatedActor`-shaped function, PR3) for the actual re-derivation/
     * status-write, one row's own `userId` at a time — see that module's
     * own header for why promotion moved off `ImporterRepo` entirely
     * (P3e round 2 gate, B2). */
    listOpen(limit: number): Promise<QueuedEvidenceRow[]>;
    /** The importer's own current site version string (duplicate of
     * `catalog.currentVersion()?.siteVersion` — exposed here directly so
     * drain-orchestrator.ts doesn't need a second call) — M1: compared
     * against a queued row's own `claimedCatalogVersion` to tell "not yet
     * imported" apart from "the covering import already ran." */
    currentSiteVersion(): Promise<string | null>;
  };
}

export interface CatalogImportEnvConfig {
  artifactBaseUrl: string;
  allowedHosts: string[];
  webhookHmacSecret: string;
}
