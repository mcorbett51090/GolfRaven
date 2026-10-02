// supabase/tests/unit/fake-importer-repo.ts
//
// A minimal, fully in-memory implementation of
// supabase/functions/_shared/types.ts's `ImporterRepo` interface, for
// unit-testing import-handler.ts / drain-orchestrator.ts WITHOUT a live
// Supabase project — same rationale and shape as fake-repo.ts's own
// header, for the SEPARATE, actor-free importer interface
// (privileged.ts's own P3e section explains why it's separate from
// `Repo`).
//
// ⛔ REWRITE (P3e round 2 gate, B2/B3/H2/H3): `queuedCatalog` no longer
// has `promoteToAccepted`/`markNeedsAttention` at all (a promotion now
// re-runs real intake derivation through the ACTOR-scoped `Repo`, via
// `drain-orchestrator.ts` — see that module's own header) — replaced by
// `currentSiteVersion()` (M1). `listOpen` now returns the full claim
// shape (`claimedFacilityId`/`claimedCourseId`/`claimedCatalogVersion`/
// `queuedInput`), matching `app.evidence`'s new B3 columns. `catalog`
// gained four SET-BASED directory upserts (H2/H3).
import type {
  ImporterCurrentVersionRow,
  ImporterLedgerRow,
  ImporterRepo,
  ImporterSigningKeyRow,
  ImportVersionInput,
  ImportVersionResult,
  LedgerBaseRow,
  LedgerStateRow,
  QueuedEvidenceRow,
  RescoreBacklogRow,
  RescorePlayRef,
  RescoreCursor,
  RosterVersionInput,
} from "../../functions/_shared/types.js";

export interface FakeLedgerRow {
  id: string;
  kind: string;
  status: "stub" | "verified";
  mergedInto: string | null;
  tombstonedAt: string | null;
  firstCatalogVersion: number;
  verifiedInVersion: number | null;
  splitFrom: string | null;
}

export interface FakeCatalogVersionRow {
  version: number;
  siteVersion: string | null;
  contractVersion: string;
  sha256: string;
  kid: string;
  publishedAt: string;
}

export interface FakeFacilityRow {
  id: string;
  slug: string;
  region: string;
  tz: string;
  name: string;
  verificationStatus: string;
  catalogVersionInt: number;
}

export interface FakeCourseRow {
  id: string;
  facilityId: string;
  designerId: string | null;
  name: string;
  holes: number | null;
  verificationStatus: string;
  closed: boolean;
  catalogVersionInt: number;
}

export interface FakeTrailRow {
  id: string;
  slug: string;
  name: string;
  catalogVersionInt: number;
}

export interface FakeHoleRow {
  id: string;
  courseId: string;
  number: number;
  catalogVersionInt: number;
}

export interface FakeBacklogRow extends Omit<RescoreBacklogRow, "finishedAt" | "swept" | "sweepReady"> {
  catalogVersionInt: number;
  done: boolean;
  finishedAt?: string | null;
  swept?: boolean;
  /** Tests: force the straggler grace to have (not) elapsed; undefined = elapsed. */
  graceElapsed?: boolean;
}

/** Test fixture for the re-score backlog's play listing (AT 18). */
export interface FakePlayRef extends Omit<RescorePlayRef, "createdAt"> {
  createdAt?: string;
}

export interface FakeDesignerRow {
  id: string;
  name: string;
  catalogVersionInt: number;
}

/** Mirrors `app.evidence`'s own `queued_catalog` row shape post-B3 — the
 * CLAIMED (unresolved) ids plus the raw `queuedInput`, never a resolved
 * facility/course/catalogVersion. */
export interface FakeQueuedRow {
  id: string;
  userId: string;
  claimedFacilityId: string;
  claimedCourseId: string | null;
  claimedCatalogVersion: string;
  queuedInput: unknown;
  createdAt: string;
  status: "queued_catalog" | "accepted" | "needs_attention" | "unknown_id";
}

export interface FakeImporterState {
  versions: FakeCatalogVersionRow[];
  ledger: Map<string, FakeLedgerRow>;
  signingKeys: Map<string, { kid: string; publicKeyB64Url: string; revokedAt: string | null }>;
  facilities: Map<string, FakeFacilityRow>;
  courses: Map<string, FakeCourseRow>;
  trails: Map<string, FakeTrailRow>;
  designers: Map<string, FakeDesignerRow>;
  holes: Map<string, FakeHoleRow>;
  rosters: RosterVersionInput[];
  backlog: FakeBacklogRow[];
  plays: FakePlayRef[];
  revokedKids: Map<string, string>;
  queued: FakeQueuedRow[];
  now: Date;
}

export function makeFakeImporterState(now: Date): FakeImporterState {
  return {
    versions: [],
    ledger: new Map(),
    signingKeys: new Map(),
    facilities: new Map(),
    courses: new Map(),
    trails: new Map(),
    designers: new Map(),
    holes: new Map(),
    rosters: [],
    backlog: [],
    plays: [],
    revokedKids: new Map(),
    queued: [],
    now,
  };
}

/** The same "prefer the non-null site_version, fall back to the version
 * int" ordering privileged.ts's own `currentVersion()`/`currentSiteVersion()`
 * use (P3e round 2 gate, LOW: "don't let rollback move the current
 * version") — every real row here always carries a `siteVersion` (the
 * fake never seeds a null one), so in practice this reduces to ordering
 * by `siteVersion` directly, but the shape is kept identical to the real
 * implementation rather than simplified away. */
function currentVersionRow(state: FakeImporterState): FakeCatalogVersionRow | null {
  let best: FakeCatalogVersionRow | null = null;
  for (const v of state.versions) {
    if (!best) {
      best = v;
      continue;
    }
    if (v.siteVersion !== null && (best.siteVersion === null || v.siteVersion > best.siteVersion)) {
      best = v;
    } else if (v.siteVersion === null && best.siteVersion === null && v.version > best.version) {
      best = v;
    }
  }
  return best;
}

export function makeFakeImporterRepo(state: FakeImporterState): ImporterRepo {
  return {
    now(): Date {
      return state.now;
    },
    catalog: {
      async listSiteVersions() {
        return state.versions.filter((v) => v.siteVersion !== null).map((v) => ({ siteVersion: v.siteVersion!, version: v.version }));
      },
      async currentVersion(): Promise<ImporterCurrentVersionRow | null> {
        const max = currentVersionRow(state);
        return max ? { version: max.version, siteVersion: max.siteVersion } : null;
      },
      async importVersion(input: ImportVersionInput): Promise<ImportVersionResult> {
        const existing = state.versions.find((v) => v.siteVersion === input.siteVersion);
        if (existing) {
          if (existing.sha256 !== input.sha256) throw new Error("importVersion: append-only violation (fake)");
          return { version: existing.version, wasNew: false };
        }
        const nextVersion = state.versions.length === 0 ? 1 : Math.max(...state.versions.map((v) => v.version)) + 1;
        state.versions.push({ version: nextVersion, siteVersion: input.siteVersion, contractVersion: input.contractVersion, sha256: input.sha256, kid: input.kid, publishedAt: input.publishedAt });
        return { version: nextVersion, wasNew: true };
      },
      async getSigningKey(kid: string): Promise<ImporterSigningKeyRow | null> {
        const k = state.signingKeys.get(kid);
        if (!k) return null;
        return { ...k, revokedAt: k.revokedAt ?? (state.revokedKids.has(kid) ? state.now.toISOString() : null) };
      },
      async recordRevokedKids(kids: string[], catalogVersion: string): Promise<void> {
        for (const kid of kids) if (!state.revokedKids.has(kid)) state.revokedKids.set(kid, catalogVersion);
      },
      async ensureLedgerIdsExist(rows: LedgerBaseRow[]): Promise<void> {
        for (const row of rows) {
          if (!state.ledger.has(row.id)) {
            state.ledger.set(row.id, { id: row.id, kind: row.kind, status: "stub", mergedInto: null, tombstonedAt: null, firstCatalogVersion: row.firstCatalogVersionInt, verifiedInVersion: null, splitFrom: null });
          }
        }
      },
      async applyLedgerState(rows: LedgerStateRow[]): Promise<void> {
        for (const row of rows) {
          const existing = state.ledger.get(row.id);
          if (!existing) throw new Error(`applyLedgerState: id "${row.id}" does not exist (fake) — ensureLedgerIdsExist must run first`);
          existing.status = existing.status === "verified" || row.status === "verified" ? "verified" : "stub";
          existing.verifiedInVersion = Math.max(existing.verifiedInVersion ?? 0, row.verifiedInVersionInt ?? 0) || null;
          existing.tombstonedAt = row.tombstoned ? (existing.tombstonedAt ?? state.now.toISOString()) : existing.tombstonedAt;
          existing.mergedInto = existing.mergedInto ?? row.mergedInto;
        }
      },
      async findLedgerConflict(rows: LedgerStateRow[]): Promise<string | null> {
        for (const row of rows) {
          const stored = state.ledger.get(row.id);
          if (!stored) continue;
          if (stored.mergedInto !== null && stored.mergedInto !== row.mergedInto) {
            return `id-ledger.json: entry "${row.id}" claims mergedInto ${row.mergedInto ? `"${row.mergedInto}"` : "none"}, but is already on file merged into "${stored.mergedInto}" — refusing to silently keep either write`;
          }
          if (stored.tombstonedAt !== null && !row.tombstoned) {
            return `id-ledger.json: entry "${row.id}" is already tombstoned on file, but this import claims it is not tombstoned — refusing a tombstone reversal`;
          }
        }
        // split_from conflicts (mirrors privileged.ts): two kept courses
        // claiming one sibling in a single ledger, or a stored lineage that
        // disagrees with the incoming one.
        const claimed = new Map<string, string>();
        for (const row of rows) {
          for (const sib of row.splitSiblings) {
            const prior = claimed.get(sib);
            if (prior !== undefined && prior !== row.id) return `id-ledger.json: split sibling "${sib}" is claimed by both "${prior}" and "${row.id}" in one ledger — refusing to pick one`;
            claimed.set(sib, row.id);
          }
        }
        for (const [sib, kept] of claimed) {
          const stored = state.ledger.get(sib);
          if (stored && stored.splitFrom !== null && stored.splitFrom !== undefined && stored.splitFrom !== kept) {
            return `id-ledger.json: split sibling "${sib}" is already on file as split from "${stored.splitFrom}", but this import claims a different kept course — refusing to silently keep either write`;
          }
        }
        return null;
      },
      async resolveLedgerId(id: string): Promise<ImporterLedgerRow | null> {
        let currentId = id;
        for (let hop = 0; hop < 10; hop++) {
          const r = state.ledger.get(currentId);
          if (!r) return null;
          if (r.mergedInto && r.mergedInto !== currentId) {
            currentId = r.mergedInto;
            continue;
          }
          return { id: r.id, kind: r.kind, status: r.status, mergedInto: r.mergedInto };
        }
        return null;
      },
      // ⛔ NEW (P3e round 2 gate, H2/H3): set-based in spirit (one call per
      // shard, never per row) even though this fake's own storage is a
      // plain Map — the real privileged.ts implementation is what H3's
      // "one round trip, not one per row" claim is actually about.
      async upsertTrails(rows): Promise<void> {
        for (const row of rows) state.trails.set(row.id, { ...row });
      },
      async upsertDesigners(rows): Promise<void> {
        for (const row of rows) state.designers.set(row.id, { ...row });
      },
      async upsertFacilities(rows): Promise<void> {
        for (const row of rows) state.facilities.set(row.id, { ...row });
      },
      async upsertHoles(rows): Promise<void> {
        for (const row of rows) state.holes.set(row.id, { ...row });
      },
      async upsertRosters(rows: RosterVersionInput[]): Promise<void> {
        for (const row of rows) {
          if (!state.rosters.some((r) => r.trailId === row.trailId && r.version === row.version)) state.rosters.push(structuredClone(row));
        }
      },
      async findStubPromotions(rows: LedgerStateRow[]): Promise<string[]> {
        return rows.filter((r) => {
          const stored = state.ledger.get(r.id);
          return stored && stored.kind === "course" && stored.status === "stub" && r.status === "verified";
        }).map((r) => r.id);
      },
      async applySplits(rows: LedgerStateRow[]): Promise<string[]> {
        const kept = new Set<string>();
        for (const r of rows) {
          for (const sib of r.splitSiblings) {
            const stored = state.ledger.get(sib);
            if (stored && stored.splitFrom === null) {
              stored.splitFrom = r.id;
              kept.add(r.id);
            }
          }
        }
        return [...kept];
      },
      async enqueueRescore(courseIds: string[], reason: "promotion" | "split", catalogVersionInt: number): Promise<void> {
        for (const courseId of courseIds) {
          if (!state.backlog.some((b) => b.courseId === courseId && b.reason === reason && b.catalogVersionInt === catalogVersionInt)) {
            state.backlog.push({ id: state.backlog.length + 1, courseId, reason, cursor: null, catalogVersionInt, done: false });
          }
        }
      },
      async upsertCourses(rows): Promise<void> {
        for (const row of rows) state.courses.set(row.id, { ...row });
      },
    },
    rescoreBacklog: {
      async listOpen(limit: number, _sweepDelaySeconds: number): Promise<RescoreBacklogRow[]> {
        return state.backlog
          .filter((b) => !b.done)
          .slice(0, limit)
          .map((b) => ({ id: b.id, courseId: b.courseId, reason: b.reason, cursor: b.cursor, finishedAt: b.finishedAt ?? null, swept: b.swept ?? false, sweepReady: b.finishedAt != null && (b.graceElapsed ?? true) }));
      },
      async markFinished(id: number, cursor: RescoreCursor | null): Promise<void> {
        const b = state.backlog.find((x) => x.id === id);
        if (b) {
          b.cursor = cursor;
          b.finishedAt = b.finishedAt ?? "now";
        }
      },
      async beginSweep(id: number, cursor: RescoreCursor | null, _overlapSeconds: number): Promise<RescoreCursor | null> {
        const b = state.backlog.find((x) => x.id === id);
        if (b) b.swept = true;
        return cursor; // the fake has no timestamps to rewind; it keeps the cursor
      },
      async purgeFixCoords(_retentionDays: number, _limit: number): Promise<number> {
        return 0; // the real set-based SQL is proven against Postgres
      },
      async nextPlays(courseId: string, after: RescoreCursor | null, limit: number): Promise<RescorePlayRef[]> {
        return state.plays
          .filter((p) => p.courseId === courseId && (after === null || p.playId > after.playId))
          .sort((a, b) => (a.playId < b.playId ? -1 : 1))
          .slice(0, limit)
          .map((p) => ({ ...p, createdAt: p.createdAt ?? "" }));
      },
      async advance(id: number, cursor: RescoreCursor | null, done: boolean): Promise<void> {
        const b = state.backlog.find((x) => x.id === id);
        if (b) {
          b.cursor = cursor;
          b.done = done;
        }
      },
    },
    queuedCatalog: {
      async listOpen(limit: number): Promise<QueuedEvidenceRow[]> {
        return state.queued
          .filter((q) => q.status === "queued_catalog")
          .sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt))
          .slice(0, limit)
          .map((q) => ({
            id: q.id,
            userId: q.userId,
            claimedFacilityId: q.claimedFacilityId,
            claimedCourseId: q.claimedCourseId,
            claimedCatalogVersion: q.claimedCatalogVersion,
            queuedInput: q.queuedInput,
            createdAt: q.createdAt,
          }));
      },
      // ⛔ NEW (M1): "the importer's own current site version string...
      // exposed here directly so drain-orchestrator.ts doesn't need a
      // second call."
      async currentSiteVersion(): Promise<string | null> {
        const max = currentVersionRow(state);
        return max?.siteVersion ?? null;
      },
    },
  };
}
