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
  InsertEvidenceResult,
  LedgerRow,
  MatchResult,
  NewEvidenceRow,
  RateLimitResult,
  Repo,
  SigningKeyRow,
  StoredEvidenceRow,
  UpsertPlayInput,
  UpsertPlayResult,
} from "../../functions/_shared/types.js";

const ABSOLUTE_ROW_CAP = 10_000; // mirrors packages/rules' own constant (score-play.ts) — see privileged.ts's own re-import of the SAME vendored value; hardcoded here rather than imported so this fake has zero dependency on the vendor tree's own layout.

interface FakeEvidenceRow extends NewEvidenceRow {
  id: string;
  userId: string;
}

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
  /** null for a staff-issued challenge (input.staffUserId set) — mirrors
   * privileged.ts's own `user_id = input.staffUserId ? null : uid`. */
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
  nextId: number;
}

export function makeFakeState(overrides: Partial<FakeState> = {}): FakeState {
  return {
    now: new Date("2026-06-01T12:00:00.000Z"),
    rateLimits: new Map(),
    catalogVersions: new Map([[1, { version: 1, publishedAt: "2026-05-20T00:00:00.000Z", contractVersion: "v1", sha256: "x", kid: "k1" }]]),
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
    nextId: 1,
    ...overrides,
  };
}

/** The default device fixture's id — tests reference this instead of
 * hardcoding the UUID literal in every submission body (request-shape.ts's
 * P3c gate round 2 fix: "validate deviceId as a UUID"). */
export const FAKE_DEVICE_ID = "11111111-1111-4111-8111-111111111111";

export function makeFakeRepo(state: FakeState, actorUid: string): Repo {
  const uid = actorUid;
  const freshId = (prefix: string) => `${prefix}_${state.nextId++}`;

  return {
    now: () => state.now,

    rateLimit: {
      async hit(bucketKey: string, _windowSeconds: number, max: number): Promise<RateLimitResult> {
        const key = `${uid}:${bucketKey}`;
        const count = (state.rateLimits.get(key) ?? 0) + 1;
        state.rateLimits.set(key, count);
        if (count > max) return { ok: false, count, retryAfterSeconds: 3600 };
        return { ok: true, count };
      },
    },

    catalog: {
      async currentVersion(): Promise<CatalogVersionRow | null> {
        let max: CatalogVersionRow | null = null;
        for (const row of state.catalogVersions.values()) {
          if (!max || row.version > max.version) max = row;
        }
        return max;
      },
      async versionRow(version: number): Promise<CatalogVersionRow | null> {
        return state.catalogVersions.get(version) ?? null;
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
            return { id: existing.id, wasNew: false, status: existing.status };
          }
        }
        const id = freshId("ev");
        state.evidence.set(id, { ...row, id, userId: uid });
        return { id, wasNew: true, status: row.status };
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
    },

    play: {
      async upsertFromScore(input: UpsertPlayInput): Promise<UpsertPlayResult> {
        const key = `${uid}:${input.courseId}:${input.playDate}`;
        const existing = state.plays.get(key);
        const id = existing?.id ?? freshId("play");
        state.plays.set(key, { ...input, id, userId: uid });
        for (const evidenceId of input.evidenceIds) {
          if (!state.playEvidence.some((pe) => pe.playId === id && pe.evidenceId === evidenceId)) {
            state.playEvidence.push({ playId: id, evidenceId });
          }
        }
        return { id, created: !existing };
      },
    },

    fraudSignal: {
      async insert(kind: string, detail: Record<string, unknown>) {
        state.fraudSignals.push({ kind, detail });
      },
    },

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
        state.challenges.set(id, {
          id,
          userId: input.staffUserId ? null : uid,
          staffUserId: input.staffUserId,
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
  };
}
