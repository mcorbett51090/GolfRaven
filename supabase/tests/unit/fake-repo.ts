// supabase/tests/unit/fake-repo.ts
//
// A minimal, fully in-memory implementation of
// supabase/functions/_shared/types.ts's `Repo` interface, for unit-testing
// evidence/handler.ts and checkin/*.ts WITHOUT a live Supabase project
// (task instruction: "handler logic in pure, dependency-injected modules
// unit-testable without a live Supabase"). Not exhaustive — only what the
// handlers under test actually call — but real enough to exercise
// idempotency, catalog-skew classification and scoring end to end.
//
// ⛔ REWRITE (P3c gate round 2, item 5: "withOwnership ignores the actor" —
// types.ts's own rewrite). `makeFakeRepo` now takes an `actorUid` and
// closes over it exactly the way `privileged.ts#buildRepo(trx, actor)`
// does — every method below is scoped to THAT uid, with no method taking a
// user-identity parameter of its own, matching the real `Repo` shape this
// file fakes. Every test that used to pass `userId` as an explicit
// argument into a fake-repo method now scopes it by calling
// `makeFakeRepo(state, "user-a")` instead.
import type {
  CatalogVersionRow,
  ChallengeRow,
  ConsumedCheckinToken,
  DeleteMyDataResult,
  ExistingEvidenceRow,
  ExportMyDataResult,
  InsertEvidenceResult,
  LedgerRow,
  MatchResult,
  NewEvidenceRow,
  RateLimitResult,
  Repo,
  SigningKeyRow,
  StoredEvidenceRow,
  StoredPlayRow,
  UpsertPlayInput,
  UpsertPlayResult,
} from "../../functions/_shared/types.js";
import { makeFakeAttestKeyRepo } from "./fake-attest-key-repo.ts";
import { makeFakeRewardsRepo } from "./fake-rewards-repo.ts";
import { deleteSigninRows, makeFakeSigninRepo } from "./fake-signin-repo.ts";

const ABSOLUTE_ROW_CAP = 10_000; // mirrors packages/rules' own constant (score-play.ts) — see privileged.ts's own re-import of the SAME vendored value; hardcoded here rather than imported so this fake has zero dependency on the vendor tree's own layout.

// ⛔ FIX (P3e round 2 gate, B3): `NewEvidenceRow` is now a discriminated
// UNION (types.ts) — `interface X extends A | B` is not valid TS, so this
// moves to a type-alias intersection, which distributes over the union
// correctly.
type FakeEvidenceRow = NewEvidenceRow & {
  id: string;
  userId: string;
};

interface FakePlayRow extends UpsertPlayInput {
  id: string;
  userId: string;
}

interface FakeDeviceRow {
  id: string;
  userId: string;
}

interface FakeChallengeRow {
  id: string;
  // ⛔ FIX (P3c gate round 4): `staffUserId` removed from the real
  // `challenge.insert` input — dead weight, since staff/partner-attest
  // issuance is out of this round's scope and no real call site ever
  // passed anything but null. `userId`/`staffUserId` stay on this
  // INTERNAL fake-state row shape (always `uid`/`null` respectively now)
  // to mirror `app.checkin_challenge`'s own CHECK constraint (0005:
  // exactly one of user_id/staff_user_id set) without narrowing the
  // fixture's own shape.
  userId: string | null;
  staffUserId: string | null;
  deviceId: string;
  facilityId: string | null;
  nonceHash: string;
  kind: "live" | "prefetched";
  expiresAt: string;
  usedAt: string | null;
}

interface FakeCheckinTokenRow {
  jti: string;
  userId: string;
  deviceId: string;
  facilityId: string | null;
  attestationGrade: "attested" | "unattestable" | "failed";
  challengeKind: "live" | "prefetched";
  challengeId: string;
  expiresAt: string;
  issuedAt: string;
  consumedAt: string | null;
}

interface FakePushTokenRow {
  userId: string;
  deviceId: string;
  expoToken: string;
  updatedAt: string;
}

export interface FakeState {
  now: Date;
  rateLimits: Map<string, number>;
  catalogVersions: Map<number, CatalogVersionRow>;
  ledger: Map<string, LedgerRow>;
  facilityTz: Map<string, string>;
  courseFacility: Map<string, string>;
  courseHoles: Map<string, number>;
  matches: Map<string, MatchResult>;
  signingKeys: Map<string, SigningKeyRow>;
  evidence: Map<string, FakeEvidenceRow>;
  plays: Map<string, FakePlayRow>;
  playEvidence: Array<{ playId: string; evidenceId: string }>;
  fraudSignals: Array<{ kind: string; detail: Record<string, unknown> }>;
  devices: Map<string, FakeDeviceRow>;
  challenges: Map<string, FakeChallengeRow>;
  checkinTokens: Map<string, FakeCheckinTokenRow>;
  // P3d: DELETE /v1/me, GET /v1/me/export, POST /v1/me/push-token.
  signinProviders: Map<string, string[]>; // userId -> providers
  connectorProviders: Map<string, string[]>; // userId -> providers
  deletedUsers: Set<string>;
  pushTokens: Map<string, FakePushTokenRow>; // `${userId}:${deviceId}` -> row
  nextId: number;
  // ⛔ NEW (P3e round 2 gate, B2/M1): `NewEvidenceRow` genuinely has no
  // `createdAt` field (real Postgres defaults `app.evidence.created_at`;
  // the app never supplies it) — but `ImporterRepo.queuedCatalog.listOpen`'s
  // own `QueuedEvidenceRow.createdAt` needs a real, test-controllable
  // value for the age-based `needs_attention` decision
  // (drain-orchestrator.test.ts's own "old, still-unresolved row" case).
  // A side-table keyed by evidence id, set by `insertIdempotent` (to
  // `state.now` at insert time) and overridable via
  // `setEvidenceCreatedAt` below — never part of `FakeEvidenceRow` itself.
  evidenceCreatedAt: Map<string, string>;
  /** AT 18: course id -> current verification_status, for refreshFixTiers. */
  courseTier: Map<string, "unverified" | "listed-verified" | "play-verified">;
  /** Play ids that already used their one re-pick (the real one is an audit_log row). */
  repicks: Set<string>;
}

export function makeFakeState(overrides: Partial<FakeState> = {}): FakeState {
  return {
    now: new Date("2026-06-01T12:00:00.000Z"),
    rateLimits: new Map(),
    // ⛔ FIX (P3e round 2 gate, H1): every row now carries the site's own
    // `yyyymmdd-gitsha7` string too — `evidence-handler.test.ts`'s own
    // `checkinBody()` default `catalogVersion` is this EXACT string, so
    // every test that doesn't care about skew semantics keeps working
    // unmodified.
    catalogVersions: new Map([[1, { version: 1, siteVersion: "20260520-a000001", publishedAt: "2026-05-20T00:00:00.000Z", contractVersion: "v1", sha256: "x", kid: "k1" }]]),
    ledger: new Map([
      ["fac_x", { id: "fac_x", kind: "facility", status: "verified", verifiedInVersion: 1, splitFrom: null, tombstonedAt: null, mergedInto: null, firstCatalogVersion: 1 }],
      ["crs_x1", { id: "crs_x1", kind: "course", status: "verified", verifiedInVersion: 1, splitFrom: null, tombstonedAt: null, mergedInto: null, firstCatalogVersion: 1 }],
    ]),
    facilityTz: new Map([["fac_x", "America/Chicago"]]),
    courseFacility: new Map([["crs_x1", "fac_x"]]),
    courseHoles: new Map([["crs_x1", 18]]),
    matches: new Map(),
    signingKeys: new Map(),
    evidence: new Map(),
    plays: new Map(),
    playEvidence: [],
    fraudSignals: [],
    devices: new Map([["11111111-1111-4111-8111-111111111111", { id: "11111111-1111-4111-8111-111111111111", userId: "user-a" }]]),
    challenges: new Map(),
    checkinTokens: new Map(),
    signinProviders: new Map(),
    connectorProviders: new Map(),
    deletedUsers: new Set(),
    pushTokens: new Map(),
    nextId: 1,
    evidenceCreatedAt: new Map(),
    courseTier: new Map(),
    repicks: new Set(),
    ...overrides,
  };
}

/** Test-only override for a queued row's simulated `created_at` — see
 * `FakeState.evidenceCreatedAt`'s own doc for why this lives outside
 * `NewEvidenceRow` entirely. */
export function setEvidenceCreatedAt(state: FakeState, id: string, iso: string): void {
  state.evidenceCreatedAt.set(id, iso);
}

/** The default device fixture's id — tests reference this instead of
 * hardcoding the UUID literal in every submission body (request-shape.ts's
 * P3c gate round 2 fix: "validate deviceId as a UUID"). */
export const FAKE_DEVICE_ID = "11111111-1111-4111-8111-111111111111";

/** P3c gate round 4, blocking HIGH ("5 concurrent requests deadlock the
 * pool"): mirrors `privileged.ts#hitRateLimitForActor`'s own signature
 * and behavior, standalone — NOT a `Repo` method any more (see types.ts's
 * own note: `Repo` has no `rateLimit` member at all now, structurally,
 * so nothing can call a rate-limit hit from inside an already-open
 * transaction). Unit tests that exercise the pre-transaction rate-limit
 * precheck (`evidence/handler.ts#planEvidenceRateLimitChecks` and its
 * checks) call this directly, the same way a real Edge Function
 * entrypoint calls `hitRateLimitForActor` before ever opening
 * `withOwnership`. */
export async function fakeHitRateLimitForActor(state: FakeState, actorUid: string, bucketKey: string, _windowSeconds: number, max: number): Promise<RateLimitResult> {
  const key = `${actorUid}:${bucketKey}`;
  const count = (state.rateLimits.get(key) ?? 0) + 1;
  state.rateLimits.set(key, count);
  if (count > max) return { ok: false, count, retryAfterSeconds: 3600 };
  return { ok: true, count };
}

export function makeFakeRepo(state: FakeState, actorUid: string): Repo {
  const uid = actorUid;
  const freshId = (prefix: string) => `${prefix}_${state.nextId++}`;

  return {
    now: () => state.now,

    catalog: {
      async currentVersion(): Promise<CatalogVersionRow | null> {
        // Mirrors the real `order by site_version desc nulls last, version desc`.
        let max: CatalogVersionRow | null = null;
        const better = (a: CatalogVersionRow, b: CatalogVersionRow): boolean => {
          if (a.siteVersion !== null && b.siteVersion !== null && a.siteVersion !== b.siteVersion) return a.siteVersion > b.siteVersion;
          if ((a.siteVersion === null) !== (b.siteVersion === null)) return a.siteVersion !== null;
          return a.version > b.version;
        };
        for (const row of state.catalogVersions.values()) {
          if (!max || better(row, max)) max = row;
        }
        return max;
      },
      async versionRow(version: number): Promise<CatalogVersionRow | null> {
        return state.catalogVersions.get(version) ?? null;
      },
      // ⛔ NEW (P3e round 2 gate, H1): evidence intake now resolves the
      // client's own submitted SITE version string, not the internal int.
      async versionRowBySiteVersion(siteVersion: string): Promise<CatalogVersionRow | null> {
        for (const row of state.catalogVersions.values()) {
          if (row.siteVersion === siteVersion) return row;
        }
        return null;
      },
      async repickEligible(courseId: string): Promise<boolean> {
        const l = state.ledger.get(courseId);
        if (!l) return false;
        return l.status === "stub" || l.splitFrom !== null || [...state.ledger.values()].some((o) => o.splitFrom === courseId);
      },
      async releaseRank(siteVersion: string): Promise<number | null> {
        let n = 0;
        for (const row of state.catalogVersions.values()) if (row.siteVersion !== null && row.siteVersion !== undefined && row.siteVersion <= siteVersion) n += 1;
        return n > 0 ? n : null;
      },
      async resolveLedgerId(id: string): Promise<LedgerRow | null> {
        let current = id;
        for (let hop = 0; hop < 10; hop++) {
          const row = state.ledger.get(current);
          if (!row) return null;
          if (row.mergedInto && row.mergedInto !== current) {
            current = row.mergedInto;
            continue;
          }
          return row;
        }
        return null;
      },
      async facilityTz(facilityId: string) {
        return state.facilityTz.get(facilityId) ?? null;
      },
      async courseFacilityId(courseId: string) {
        return state.courseFacility.get(courseId) ?? null;
      },
      async courseHoleCount(courseId: string) {
        return state.courseHoles.get(courseId) ?? 0;
      },
      async matchFix(courseId: string, lat: number, lng: number) {
        const key = `${courseId}:${lat}:${lng}`;
        return state.matches.get(key) ?? state.matches.get(courseId) ?? null;
      },
      async signingKey(kid: string) {
        return state.signingKeys.get(kid) ?? null;
      },
    },

    evidence: {
      async countOpenQueued(): Promise<number> {
        let n = 0;
        for (const row of state.evidence.values()) {
          if (row.userId === uid && row.status === "queued_catalog") n++;
        }
        return n;
      },
      async insertIdempotent(row: NewEvidenceRow): Promise<InsertEvidenceResult> {
        for (const existing of state.evidence.values()) {
          if (existing.userId === uid && existing.source === row.source && existing.sourceRef === row.sourceRef) {
            return { id: existing.id, wasNew: false, status: existing.status, inputHash: existing.inputHash };
          }
        }
        const id = freshId("ev");
        state.evidence.set(id, { ...row, id, userId: uid });
        state.evidenceCreatedAt.set(id, state.now.toISOString());
        return { id, wasNew: true, status: row.status, inputHash: row.inputHash };
      },
      // ⛔ P3c gate round 3, blocking HIGH 1+2 ("replay handling"): mirrors
      // privileged.ts#evidence.findExisting's own (user, source,
      // source_ref) lookup — evidence/handler.ts calls this BEFORE any
      // side effect, so the fake must support it for every unit test that
      // exercises `handleEvidenceIntake` at all (every one of them, since
      // it is now the FIRST repo call the handler makes).
      // AT 18: the fake has no course verification registry — a test that
      // needs a tier change sets `state.courseTier` (see FakeState).
      async refreshFixTiers(courseId: string, localDate: string): Promise<number> {
        const tier = state.courseTier.get(courseId);
        if (!tier) return 0;
        let n = 0;
        for (const row of state.evidence.values()) {
          if (row.userId !== uid || row.kind !== "resolved" || row.courseId !== courseId || row.localDate !== localDate || row.status !== "accepted") continue;
          for (const k of ["fix", "checkinFix", "checkoutFix"]) {
            const f = (row.summary as Record<string, unknown>)[k];
            if (f && typeof f === "object") (f as Record<string, unknown>).verificationTier = tier;
          }
          n += 1;
        }
        return n;
      },
      async findExisting(source: string, sourceRef: string): Promise<ExistingEvidenceRow | null> {
        for (const row of state.evidence.values()) {
          if (row.userId === uid && row.source === source && row.sourceRef === sourceRef) {
            // P3e round 2 gate, B3: a `queued` row's facility_id/course_id
            // columns are ALWAYS NULL now (the claimed_* columns carry the
            // unresolved claim instead) — mirrors the real DB row shape.
            return {
              id: row.id,
              status: row.status,
              inputHash: row.inputHash,
              facilityId: row.kind === "resolved" ? row.facilityId : null,
              courseId: row.kind === "resolved" ? row.courseId : null,
              localDate: row.localDate,
            };
          }
        }
        return null;
      },
      async listForPlay(facilityId: string, courseId: string, localDate: string): Promise<StoredEvidenceRow[]> {
        // ⛔ FIX (P3c gate round 2, item 1): filters on the row's own REAL
        // `localDate` field (a NewEvidenceRow property since types.ts's
        // rewrite), never a jsonb-summary read, and never a fail-open
        // coalesce onto the QUERIED date — a row from a different date
        // simply never matches. A facility-level row (courseId: null)
        // matches ANY course queried at that facility+date (the H3
        // residual rule this same test suite's "second course on the same
        // day" case covers), never only the SPECIFIC course it happened
        // to be submitted alongside.
        const out: StoredEvidenceRow[] = [];
        for (const row of state.evidence.values()) {
          if (row.userId !== uid || row.status !== "accepted") continue;
          if (row.facilityId !== facilityId) continue;
          if (row.courseId !== null && row.courseId !== courseId) continue;
          if (row.localDate !== localDate) continue;
          out.push({
            id: row.id,
            source: row.source,
            facilityId: row.facilityId,
            courseId: row.courseId,
            localDate: row.localDate,
            attestationGrade: row.attestationGrade,
            summary: row.summary,
            integrity: row.integrity,
            cosignal: row.cosignal,
          });
          if (out.length >= ABSOLUTE_ROW_CAP) break;
        }
        return out;
      },
      // ⛔ NEW (P3e round 2 gate, B2/B3) — mirrors privileged.ts's own
      // real SQL exactly: a partial UPDATE (facility_id/course_id/
      // summary/integrity/attestation_grade/catalog_version + status ->
      // 'accepted', claimed_*/queued_input cleared), NEVER a fresh row —
      // every OTHER field (cosignal, matcherVersion, source, sourceRef,
      // inputHash, deviceId, localDate, startedAt, endedAt) stays exactly
      // what it already was. Guarded on `status === 'queued_catalog'`,
      // same as the real `WHERE ... and status = 'queued_catalog'`.
      async resolveQueuedRow(
        id: string,
        resolved: { facilityId: string; courseId: string | null; summary: Record<string, unknown>; integrity: Record<string, unknown>; attestationGrade: "attested" | "unattestable" | "failed"; catalogVersion: number | null },
      ): Promise<void> {
        const row = state.evidence.get(id);
        if (!row || row.userId !== uid || row.status !== "queued_catalog" || row.kind !== "queued") return;
        const resolvedRow: FakeEvidenceRow = {
          id: row.id,
          userId: row.userId,
          kind: "resolved",
          sourceRef: row.sourceRef,
          inputHash: row.inputHash,
          source: row.source,
          facilityId: resolved.facilityId,
          courseId: resolved.courseId,
          startedAt: null,
          endedAt: null,
          localDate: row.localDate,
          summary: resolved.summary,
          integrity: resolved.integrity,
          cosignal: {},
          attestationGrade: resolved.attestationGrade,
          matcherVersion: null,
          catalogVersion: resolved.catalogVersion,
          status: "accepted",
          deviceId: row.deviceId,
        };
        state.evidence.set(id, resolvedRow);
      },
      // ⛔ NEW (P3e round 2 gate, B2/M1): flips status only — claimed_*/
      // queued_input stay in place in THIS fake (the real SQL clears them with the
      // status change; asserted against real Postgres), guarded the same way.
      async markQueuedTerminal(id: string, terminalStatus: "needs_attention" | "unknown_id"): Promise<void> {
        const row = state.evidence.get(id);
        if (!row || row.userId !== uid || row.status !== "queued_catalog") return;
        (row as { status: string }).status = terminalStatus;
      },
      async deviceIdFor(id: string): Promise<string | null> {
        const row = state.evidence.get(id);
        if (!row || row.userId !== uid) return null;
        return row.deviceId ?? null;
      },
      // Edge role PR3: the drain re-reads the raw submission as the row's owner (same status + ownership guards as the real SQL).
      async readQueuedInput(id: string): Promise<{ queuedInput: unknown } | null> {
        const row = state.evidence.get(id);
        if (!row || row.userId !== uid || row.status !== "queued_catalog" || row.kind !== "queued") return null;
        return { queuedInput: row.queuedInput };
      },
    },

    play: {
      async upsertFromScore(input: UpsertPlayInput): Promise<UpsertPlayResult> {
        const key = `${uid}:${input.courseId}:${input.playDate}`;
        const existing = state.plays.get(key);
        const id = existing?.id ?? freshId("play");
        // Mirrors the real ON CONFLICT DO UPDATE, which never touches
        // course_disambiguated_by (a re-pick / split label must survive a re-score).
        state.plays.set(key, { ...input, courseDisambiguatedBy: existing?.courseDisambiguatedBy ?? input.courseDisambiguatedBy, id, userId: uid });
        for (const evidenceId of input.evidenceIds) {
          if (!state.playEvidence.some((pe) => pe.playId === id && pe.evidenceId === evidenceId)) {
            state.playEvidence.push({ playId: id, evidenceId });
          }
        }
        return { id, created: !existing };
      },
      async getForDate(courseId: string, playDate: string): Promise<StoredPlayRow | null> {
        const key = `${uid}:${courseId}:${playDate}`;
        const row = state.plays.get(key);
        if (!row) return null;
        return { id: row.id, scoreBadge: row.scoreBadge, scoreMonetary: row.scoreMonetary, presenceSignal: row.presenceSignal, money: row.money, heldReview: row.heldReview };
      },
      // AT 18 — in-memory twins of privileged.ts's SQL (the REAL SQL is
      // proven against Postgres by import-catalog / catalog-promotion
      // .deno.test.ts; these exist so handler-level unit tests can run).
      async uniqueCourseCount(): Promise<number> {
        const resolved = new Set<string>();
        for (const p of state.plays.values()) {
          if (p.userId !== uid) continue;
          if (!(p.scoreBadge >= 0.5 || p.money)) continue;
          if (state.ledger.get(p.courseId)?.status !== "verified") continue;
          let cur = p.courseId;
          for (let i = 0; i < 10; i++) {
            const m = state.ledger.get(cur)?.mergedInto;
            if (!m || m === cur) break;
            cur = m;
          }
          resolved.add(cur);
        }
        return resolved.size;
      },
      async markUserPick(playId: string): Promise<boolean> {
        const play = [...state.plays.values()].find((p) => p.id === playId && p.userId === uid);
        if (!play || play.courseDisambiguatedBy !== null) return false;
        const clash = [...state.plays.values()].some((o) => o.userId === uid && o.facilityId === play.facilityId && o.playDate === play.playDate && o.courseDisambiguatedBy === "user" && o.id !== play.id);
        if (clash) return false;
        play.courseDisambiguatedBy = "user";
        return true;
      },
      async lockForScoring(_courseId: string, _playDate: string): Promise<void> {},
      async disambiguation(courseId: string, playDate: string) {
        const stored = state.plays.get(`${uid}:${courseId}:${playDate}`)?.courseDisambiguatedBy ?? null;
        const l = state.ledger.get(courseId);
        const family = Boolean(l && (l.splitFrom !== null || [...state.ledger.values()].some((o) => o.splitFrom === courseId)));
        return { stored, effective: stored ?? (family ? ("user" as const) : null) };
      },
      async repickPrepare(args: { facilityId: string; playDate: string; fromCourseId: string; toCourseId: string }) {
        const fromKey = `${uid}:${args.fromCourseId}:${args.playDate}`;
        const play = state.plays.get(fromKey);
        const fromLedger = state.ledger.get(args.fromCourseId);
        const toLedger = state.ledger.get(args.toCourseId);
        const sameFamily = Boolean(fromLedger && toLedger && args.fromCourseId !== args.toCourseId && (toLedger.splitFrom === args.fromCourseId || fromLedger.splitFrom === args.toCourseId || (fromLedger.splitFrom && fromLedger.splitFrom === toLedger.splitFrom)));
        if (!sameFamily) return { ok: false as const, reason: "not_same_split_family" as const };
        if (!play) return { ok: false as const, reason: "no_such_play" as const };
        if (play.courseDisambiguatedBy !== "user") return { ok: false as const, reason: "not_user_pick" as const };
        if (state.repicks.has(play.id)) return { ok: false as const, reason: "already_repicked" as const };
        const clash = [...state.plays.values()].some((o) => o.userId === uid && o.facilityId === args.facilityId && o.playDate === args.playDate && o.id !== play.id && (o.courseId === args.toCourseId || o.courseDisambiguatedBy === "user"));
        if (clash) return { ok: false as const, reason: "target_play_exists" as const };
        return { ok: true as const, playId: play.id };
      },
      async repickApply(args: { facilityId: string; playDate: string; fromCourseId: string; toCourseId: string; playId: string; rederived: { evidenceId: string; summary: Record<string, unknown> }[] }) {
        const fromKey = `${uid}:${args.fromCourseId}:${args.playDate}`;
        const play = state.plays.get(fromKey);
        if (!play) return;
        for (const r of args.rederived) {
          const ev = state.evidence.get(r.evidenceId);
          if (ev && ev.userId === uid) ev.summary = r.summary;
        }
        state.plays.delete(fromKey);
        play.courseId = args.toCourseId;
        play.courseDisambiguatedBy = "user";
        state.plays.set(`${uid}:${args.toCourseId}:${args.playDate}`, play);
        for (const ev of state.evidence.values()) {
          if (ev.userId === uid && ev.kind === "resolved" && ev.courseId === args.fromCourseId && ev.localDate === args.playDate) ev.courseId = args.toCourseId;
        }
        state.repicks.add(args.playId);
      },
    },

    fraudSignal: {
      async insert(kind: string, detail: Record<string, unknown>) {
        state.fraudSignals.push({ kind, detail });
      },
    },

    // P3f: rewards-activate (supabase/tests/unit/fake-rewards-repo.ts).
    rewards: makeFakeRewardsRepo(state, uid),
    // O12: me-signin-methods / provider-grant revocation (supabase/tests/unit/fake-signin-repo.ts).
    signin: makeFakeSigninRepo(state, uid),

    // App Attest key registration (supabase/tests/unit/fake-attest-key-repo.ts).
    attestKey: makeFakeAttestKeyRepo(state, uid),

    device: {
      async findOwn(deviceId: string) {
        const row = state.devices.get(deviceId);
        if (!row || row.userId !== uid) return null;
        return { id: row.id };
      },
      async ensureOwn(deviceId: string | null, _platform: "ios" | "android" | null) {
        if (deviceId) {
          const existing = state.devices.get(deviceId);
          if (existing && existing.userId === uid) return { id: existing.id };
        }
        const id = deviceId ?? freshId("dev");
        state.devices.set(id, { id, userId: uid });
        return { id };
      },
      async countForUser(): Promise<number> {
        let n = 0;
        for (const row of state.devices.values()) if (row.userId === uid) n++;
        return n;
      },
    },

    challenge: {
      async insert(input) {
        const id = freshId("chal");
        // ⛔ FIX (P3c gate round 4): staffUserId removed from the real
        // input shape — every challenge is issued to the authenticated
        // actor themselves now, always.
        state.challenges.set(id, {
          id,
          userId: uid,
          staffUserId: null,
          deviceId: input.deviceId,
          facilityId: input.facilityId,
          nonceHash: input.nonceHash,
          kind: input.kind,
          expiresAt: input.expiresAt,
          usedAt: null,
        });
        return { id, expiresAt: input.expiresAt };
      },
      async countOpenPrefetched(deviceId: string): Promise<number> {
        let n = 0;
        for (const row of state.challenges.values()) {
          if (row.deviceId === deviceId && row.userId === uid && row.kind === "prefetched" && row.usedAt === null && Date.parse(row.expiresAt) > state.now.getTime()) n++;
        }
        return n;
      },
      async getOwn(challengeId: string): Promise<ChallengeRow | null> {
        const row = state.challenges.get(challengeId);
        if (!row || row.userId !== uid) return null;
        return { id: row.id, deviceId: row.deviceId, facilityId: row.facilityId, nonceHash: row.nonceHash, kind: row.kind, expiresAt: row.expiresAt, usedAt: row.usedAt };
      },
      async consume(challengeId: string, nonceHash: string): Promise<boolean> {
        const row = state.challenges.get(challengeId);
        if (!row || row.userId !== uid || row.nonceHash !== nonceHash || row.usedAt !== null) return false;
        row.usedAt = state.now.toISOString();
        return true;
      },
    },

    checkinToken: {
      async insert(input) {
        const jti = freshId("jti");
        state.checkinTokens.set(jti, {
          jti,
          userId: uid,
          deviceId: input.deviceId,
          facilityId: input.facilityId,
          attestationGrade: input.attestationGrade,
          challengeKind: input.challengeKind,
          challengeId: input.challengeId,
          expiresAt: input.expiresAt,
          issuedAt: state.now.toISOString(),
          consumedAt: null,
        });
        return { jti, expiresAt: input.expiresAt };
      },
      async consumeForFix(jti: string, submittingDeviceId: string, capturedAtMs: number): Promise<ConsumedCheckinToken | null> {
        // ⛔ FIX (P3c gate round 2, item 4): mirrors privileged.ts's own
        // single atomic UPDATE's WHERE clause — ownership, single-use,
        // device match AND the issued_at <= capturedAt <= expires_at
        // window clamp, all checked together so a fake test can never
        // observe an intermediate state a real transaction wouldn't allow.
        const row = state.checkinTokens.get(jti);
        if (!row) return null;
        if (row.userId !== uid) return null;
        if (row.deviceId !== submittingDeviceId) return null;
        if (row.consumedAt !== null) return null;
        const expiresAtMs = Date.parse(row.expiresAt);
        const issuedAtMs = Date.parse(row.issuedAt);
        if (!(expiresAtMs > state.now.getTime())) return null;
        if (!(issuedAtMs <= capturedAtMs && capturedAtMs <= expiresAtMs)) return null;
        row.consumedAt = state.now.toISOString();
        return { facilityId: row.facilityId, attestationGrade: row.attestationGrade, challengeKind: row.challengeKind };
      },
    },

    // P3d: DELETE /v1/me, GET /v1/me/export.
    me: {
      async listSigninProviders(): Promise<string[]> {
        return [...(state.signinProviders.get(uid) ?? [])];
      },
      async listConnectorProviders(): Promise<string[]> {
        return [...(state.connectorProviders.get(uid) ?? [])];
      },
      async deleteMyData(): Promise<DeleteMyDataResult> {
        // Idempotent, same as the real private.delete_my_data (0015): a
        // second call for an already-deleted user removes nothing more
        // (every map delete below is a no-op if the row is already gone)
        // and still returns success, never throwing.
        for (const [id, row] of state.evidence) if (row.userId === uid) state.evidence.delete(id);
        for (const key of [...state.plays.keys()]) if (key.startsWith(`${uid}:`)) state.plays.delete(key);
        for (const [id, row] of state.devices) if (row.userId === uid) state.devices.delete(id);
        for (const [id, row] of state.challenges) if (row.userId === uid) state.challenges.delete(id);
        for (const [jti, row] of state.checkinTokens) if (row.userId === uid) state.checkinTokens.delete(jti);
        for (const key of [...state.pushTokens.keys()]) if (key.startsWith(`${uid}:`)) state.pushTokens.delete(key);
        state.signinProviders.delete(uid);
        deleteSigninRows(state, uid);
        state.connectorProviders.delete(uid);
        state.deletedUsers.add(uid);
        return { userId: uid, deletedAt: state.now.toISOString() };
      },
      async exportMyData(): Promise<ExportMyDataResult> {
        return {
          evidence: [...state.evidence.values()].filter((r) => r.userId === uid),
          play: [...state.plays.values()].filter((r) => r.userId === uid),
          device: [...state.devices.values()].filter((r) => r.userId === uid),
          push_token: [...state.pushTokens.values()].filter((r) => r.userId === uid),
        };
      },
    },

    // P3d: POST /v1/me/push-token.
    pushToken: {
      async upsert(deviceId: string, expoToken: string) {
        const key = `${uid}:${deviceId}`;
        const updatedAt = state.now.toISOString();
        state.pushTokens.set(key, { userId: uid, deviceId, expoToken, updatedAt });
        return { deviceId, updatedAt };
      },
      async countForUser(): Promise<number> {
        let n = 0;
        for (const row of state.pushTokens.values()) if (row.userId === uid) n++;
        return n;
      },
    },
  };
}
