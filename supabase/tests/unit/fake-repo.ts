// supabase/tests/unit/fake-repo.ts
//
// A minimal, fully in-memory implementation of
// supabase/functions/_shared/types.ts's `Repo` interface, for unit-testing
// evidence/handler.ts and checkin/*.ts WITHOUT a live Supabase project
// (task instruction: "handler logic in pure, dependency-injected modules
// unit-testable without a live Supabase"). Not exhaustive — only what the
// handlers under test actually call — but real enough to exercise
// idempotency, catalog-skew classification and scoring end to end.
import type {
  CatalogVersionRow,
  InsertEvidenceResult,
  LedgerRow,
  NewEvidenceRow,
  RateLimitResult,
  Repo,
  SigningKeyRow,
  StoredEvidenceRow,
  UpsertPlayInput,
  UpsertPlayResult,
} from "../../functions/_shared/types.js";

export interface FakeState {
  now: Date;
  rateLimits: Map<string, number>;
  catalogVersions: Map<number, CatalogVersionRow>;
  ledger: Map<string, LedgerRow>;
  facilityTz: Map<string, string>;
  courseFacility: Map<string, string>;
  matches: Map<string, { verificationTier: "unverified" | "listed-verified" | "play-verified"; geometryKind: "polygon" | "radius"; insideBuffer: boolean }>;
  signingKeys: Map<string, SigningKeyRow>;
  evidence: Map<string, NewEvidenceRow & { id: string; userId: string }>;
  plays: Map<string, UpsertPlayInput & { id: string; userId: string }>;
  playEvidence: Array<{ playId: string; evidenceId: string }>;
  fraudSignals: Array<{ userId: string; kind: string; detail: Record<string, unknown> }>;
  devices: Map<string, { id: string; userId: string }>;
  challenges: Map<string, { userId: string | null; staffUserId: string | null; deviceId: string; facilityId: string | null; expiresAt: string; usedAt: string | null }>;
  checkinTokens: Map<string, { jti: string; userId: string; deviceId: string; facilityId: string | null; attestationGrade: "attested" | "unattestable" | "failed"; challengeKind: "live" | "prefetched"; challengeId: string; expiresAt: string }>;
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
    matches: new Map(),
    signingKeys: new Map(),
    evidence: new Map(),
    plays: new Map(),
    playEvidence: [],
    fraudSignals: [],
    devices: new Map([["dev_1", { id: "dev_1", userId: "user-a" }]]),
    challenges: new Map(),
    checkinTokens: new Map(),
    nextId: 1,
    ...overrides,
  };
}

export function makeFakeRepo(state: FakeState): Repo {
  const freshId = (prefix: string) => `${prefix}_${state.nextId++}`;

  return {
    now: () => state.now,

    async hitRateLimit(bucketKey, _windowSeconds, max): Promise<RateLimitResult> {
      const count = (state.rateLimits.get(bucketKey) ?? 0) + 1;
      state.rateLimits.set(bucketKey, count);
      if (count > max) return { ok: false, count, retryAfterSeconds: 3600 };
      return { ok: true, count };
    },

    async currentCatalogVersion(): Promise<CatalogVersionRow | null> {
      let max: CatalogVersionRow | null = null;
      for (const row of state.catalogVersions.values()) {
        if (!max || row.version > max.version) max = row;
      }
      return max;
    },
    async catalogVersionRow(version: number): Promise<CatalogVersionRow | null> {
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
    async matchFix(courseId: string, lat: number, lng: number) {
      const key = `${courseId}:${lat}:${lng}`;
      return state.matches.get(key) ?? state.matches.get(courseId) ?? null;
    },
    async signingKey(kid: string) {
      return state.signingKeys.get(kid) ?? null;
    },

    async countOpenQueuedEvidence(userId: string) {
      let n = 0;
      for (const row of state.evidence.values()) {
        if (row.userId === userId && row.status === "queued_catalog") n++;
      }
      return n;
    },
    async insertEvidenceIdempotent(userId: string, row: NewEvidenceRow): Promise<InsertEvidenceResult> {
      for (const existing of state.evidence.values()) {
        if (existing.userId === userId && existing.source === row.source && existing.sourceRef === row.sourceRef) {
          return { id: existing.id, wasNew: false, status: existing.status };
        }
      }
      const id = freshId("ev");
      state.evidence.set(id, { ...row, id, userId });
      return { id, wasNew: true, status: row.status };
    },
    async listEvidenceForPlay(userId: string, facilityId: string, courseId: string, localDate: string): Promise<StoredEvidenceRow[]> {
      const out: StoredEvidenceRow[] = [];
      for (const row of state.evidence.values()) {
        if (row.userId !== userId || row.facilityId !== facilityId || row.status !== "accepted") continue;
        if (row.courseId !== null && row.courseId !== courseId) continue;
        out.push({
          id: row.id,
          source: row.source,
          facilityId: row.facilityId,
          courseId: row.courseId,
          localDate: (row.summary as Record<string, unknown>).localDate as string ?? localDate,
          attestationGrade: row.attestationGrade,
          summary: row.summary,
          integrity: row.integrity,
          cosignal: row.cosignal,
        });
      }
      return out;
    },
    async upsertPlayFromScore(userId: string, input: UpsertPlayInput): Promise<UpsertPlayResult> {
      const key = `${userId}:${input.courseId}:${input.playDate}`;
      const existing = state.plays.get(key);
      const id = existing?.id ?? freshId("play");
      state.plays.set(key, { ...input, id, userId });
      for (const evidenceId of input.evidenceIds) {
        if (!state.playEvidence.some((pe) => pe.playId === id && pe.evidenceId === evidenceId)) {
          state.playEvidence.push({ playId: id, evidenceId });
        }
      }
      return { id, created: !existing };
    },
    async insertFraudSignal(userId: string, kind: string, detail: Record<string, unknown>) {
      state.fraudSignals.push({ userId, kind, detail });
    },

    async ensureOwnDevice(userId: string, deviceId: string | null) {
      if (deviceId) {
        const existing = state.devices.get(deviceId);
        if (existing && existing.userId === userId) return { id: existing.id };
      }
      const id = freshId("dev");
      state.devices.set(id, { id, userId });
      return { id };
    },

    async insertChallenge(input) {
      const id = freshId("chal");
      state.challenges.set(id, { ...input, usedAt: null });
      return { id };
    },
    async countOpenPrefetchedChallenges(deviceId: string) {
      let n = 0;
      for (const row of state.challenges.values()) {
        if (row.deviceId === deviceId && row.usedAt === null && Date.parse(row.expiresAt) > state.now.getTime()) n++;
      }
      return n;
    },
    async getOwnChallenge(challengeId: string, userId: string) {
      const row = state.challenges.get(challengeId);
      if (!row || row.userId !== userId) return null;
      return { id: challengeId, deviceId: row.deviceId, facilityId: row.facilityId, expiresAt: row.expiresAt, usedAt: row.usedAt };
    },
    async consumeChallenge(challengeId: string) {
      const row = state.challenges.get(challengeId);
      if (!row || row.usedAt !== null) return false;
      row.usedAt = state.now.toISOString();
      return true;
    },

    async insertCheckinToken(input) {
      const jti = freshId("jti");
      state.checkinTokens.set(jti, { jti, ...input });
      return { jti, expiresAt: input.expiresAt };
    },
    async getCheckinToken(jti: string) {
      return state.checkinTokens.get(jti) ?? null;
    },
  };
}
