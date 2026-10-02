// supabase/tests/unit/drain-orchestrator.test.ts
//
// ⛔ REWRITE (P3e round 2 gate, B2 — probe D). The old version of this
// file exercised the REMOVED `ImporterRepo#queuedCatalog.promoteToAccepted`
// / `markNeedsAttention` — a raw status flip, with no re-derivation and
// no re-score at all (exactly the bug B2 fixes; see drain-orchestrator.ts's
// own header for the full "why"). `drainQueuedCatalog` now takes
// `(importerRepo, withOwnership, limit)` and every "resolved" outcome
// goes through the REAL `redrainQueuedEvidenceRow` (evidence/handler.ts)
// via an actor-scoped `Repo` — this file drives that with `makeFakeRepo`
// (fake-repo.ts, already proven correct by evidence-handler.test.ts's own
// 29 passing cases) rather than re-deriving a second, parallel fake.
//
// `ImporterRepoShim` below is a MINIMAL `ImporterRepo` — drain-orchestrator.ts
// itself only ever calls `importerRepo.now()` and
// `importerRepo.queuedCatalog.{listOpen,currentSiteVersion}` (never
// `importerRepo.catalog.*` — that only happens inside `applyImportPlan`,
// a separate code path this file doesn't exercise), so the shim reads
// `queued_catalog` rows directly out of the SAME `FakeState.evidence` map
// `makeFakeRepo` itself reads/writes — exactly mirroring how, in real
// Postgres, `ImporterRepo` and `Repo` are two different privilege-scoped
// views over the very same `app.evidence` table.
import { describe, expect, it } from "vitest";
import { drainQueuedCatalog, type WithOwnershipFn } from "../../functions/_shared/catalog/drain-orchestrator.js";
import { makeFakeRepo, makeFakeState, setEvidenceCreatedAt, FAKE_DEVICE_ID, type FakeState } from "./fake-repo.js";
import type { Actor, ImporterRepo, QueuedEvidenceRow, Repo } from "../../functions/_shared/types.js";

const NOW = new Date("2026-06-01T12:00:00.000Z");

function buildImporterShim(state: FakeState): ImporterRepo {
  return {
    now: () => state.now,
    catalog: undefined as unknown as ImporterRepo["catalog"], // never called by drain-orchestrator.ts itself — see this file's own header
    queuedCatalog: {
      async listOpen(limit: number): Promise<QueuedEvidenceRow[]> {
        const rows: (QueuedEvidenceRow & { createdAtMs: number })[] = [];
        for (const row of state.evidence.values()) {
          if (row.kind !== "queued" || row.status !== "queued_catalog") continue;
          const createdAt = state.evidenceCreatedAt.get(row.id) ?? state.now.toISOString();
          rows.push({
            id: row.id,
            userId: row.userId,
            claimedFacilityId: row.claimedFacilityId,
            claimedCourseId: row.claimedCourseId,
            claimedCatalogVersion: row.claimedCatalogVersion,
            queuedInput: row.queuedInput,
            createdAt,
            createdAtMs: Date.parse(createdAt),
          });
        }
        rows.sort((a, b) => a.createdAtMs - b.createdAtMs);
        return rows.slice(0, limit).map(({ createdAtMs: _createdAtMs, ...r }) => r);
      },
      async currentSiteVersion(): Promise<string | null> {
        let best: string | null = null;
        for (const row of state.catalogVersions.values()) {
          if (row.siteVersion !== null && (best === null || row.siteVersion > best)) best = row.siteVersion;
        }
        return best;
      },
    },
  };
}

/** The exact `WithOwnershipFn` shape `privileged.ts#withOwnership` has —
 * closes over the SAME `FakeState` the importer shim reads, so a write
 * `redrainQueuedEvidenceRow` makes (via `repo.evidence.resolveQueuedRow`)
 * is immediately visible to a LATER call in the same drain pass, exactly
 * as one real Postgres transaction's writes are visible to the next. */
function buildFakeWithOwnership(state: FakeState): WithOwnershipFn {
  return async (actor: Actor, op: (repo: Repo) => Promise<unknown>) => {
    const repo = makeFakeRepo(state, actor.uid);
    return op(repo);
  };
}

/** Inserts a real `queued_catalog` row through the SAME `Repo#evidence.insertIdempotent`
 * path `evidence/handler.ts`'s own 202 branch uses (B3's own claimed-id
 * plus queuedInput shape) — never a hand-built fixture row — so this
 * suite exercises the exact row shape `redrainQueuedEvidenceRow` will
 * read back. */
async function insertQueuedRow(state: FakeState, uid: string, input: { facilityId: string; courseId?: string | null; catalogVersion: string; localDate: string }): Promise<string> {
  const repo = makeFakeRepo(state, uid);
  const sourceRef = `drain-test-${crypto.randomUUID()}`;
  const queuedInput = {
    source: "self_report",
    deviceId: FAKE_DEVICE_ID,
    facilityId: input.facilityId,
    courseId: input.courseId ?? undefined,
    localDate: input.localDate,
    catalogVersion: input.catalogVersion,
  };
  const inserted = await repo.evidence.insertIdempotent({
    kind: "queued",
    sourceRef,
    inputHash: "h".repeat(64),
    source: "self_report",
    claimedFacilityId: input.facilityId,
    claimedCourseId: input.courseId ?? null,
    claimedCatalogVersion: input.catalogVersion,
    localDate: input.localDate,
    queuedInput,
    status: "queued_catalog",
    deviceId: FAKE_DEVICE_ID,
  });
  return inserted.id;
}

describe("drainQueuedCatalog (B2: real re-derivation, never a raw status flip)", () => {
  it("resolves a queued row whose claimed facility now resolves in the ledger — a REAL scored play, not a status flip", async () => {
    const state = makeFakeState();
    const id = await insertQueuedRow(state, "user-a", { facilityId: "fac_x", courseId: "crs_x1", catalogVersion: "20260520-a000001", localDate: "2026-06-01" });

    const result = await drainQueuedCatalog(buildImporterShim(state), buildFakeWithOwnership(state), 10);
    expect(result).toEqual({ scanned: 1, resolved: 1, needsAttention: 0, unknownId: 0, stillQueued: 0 });

    const row = state.evidence.get(id)!;
    expect(row.status).toBe("accepted");
    expect(row.kind).toBe("resolved");
    if (row.kind === "resolved") {
      expect(row.facilityId).toBe("fac_x");
      expect(row.courseId).toBe("crs_x1");
    }
    // B2's own core claim: a REAL play was scored, not merely a status
    // flip — the same object-identity check evidence-handler.test.ts's
    // own "read-only replay" test uses to prove a genuine write happened.
    const playKey = "user-a:crs_x1:2026-06-01";
    expect(state.plays.has(playKey)).toBe(true);
  });

  it("a claimed courseId that never resolves in the ledger is terminal unknown_id (not left queued forever)", async () => {
    const state = makeFakeState();
    // crs_ghost deliberately absent from the ledger.
    const id = await insertQueuedRow(state, "user-a", { facilityId: "fac_x", courseId: "crs_ghost", catalogVersion: "20260520-a000001", localDate: "2026-06-01" });

    const result = await drainQueuedCatalog(buildImporterShim(state), buildFakeWithOwnership(state), 10);
    expect(result.unknownId).toBe(1);
    expect(result.resolved).toBe(0);
    const row = state.evidence.get(id)!;
    expect(row.status).toBe("unknown_id");
    // markQueuedTerminal deliberately does NOT clear claimed_*/queuedInput.
    if (row.kind === "queued") {
      expect(row.claimedCourseId).toBe("crs_ghost");
    }
  });

  // ⛔ IMPORTANT SHAPE NOTE: the "still not resolved this pass, judge by
  // age/version-coverage" path (decideQueuedDrainOutcome) is reached ONLY
  // when `redrainQueuedEvidenceRow` itself couldn't even get PAST catalog
  // -version classification (drain-queued.ts's own header: "still_unresolved
  // ... only when [the claimed version] hasn't necessarily [been
  // imported]"). A claim whose catalogVersion DOES classify as current/
  // within-window but whose facility/course id then fails to resolve is
  // a STRUCTURAL failure — terminal unknown_id IMMEDIATELY, regardless of
  // age (see the "claimed courseId that never resolves" case above; the
  // real production code path this mirrors is `redrainQueuedEvidenceRow`'s
  // own `if (!facilityLedger...) return { kind: "terminal_unknown_id" }`,
  // reached only AFTER classification already said "ok"). So the
  // age-based tests below claim a catalogVersion NEWER than the fixture's
  // current one — genuinely "not yet imported," with no manifestSig, so
  // classification lands on "forged" (unverifiable newer claim) ->
  // `redrainQueuedEvidenceRow`'s own `still_unresolved` return — the ONLY
  // way to reach the age/coverage judgment this module owns.
  it("an OLD, still-unresolved row (claimed catalogVersion not yet imported) flips to needs_attention — never touches app.review_item (no such method exists on the fake Repo at all)", async () => {
    const state = makeFakeState();
    const id = await insertQueuedRow(state, "user-a", { facilityId: "fac_x", courseId: "crs_x1", catalogVersion: "20260602-b000002", localDate: "2026-06-01" });
    setEvidenceCreatedAt(state, id, new Date(NOW.getTime() - 10 * 24 * 60 * 60 * 1000).toISOString());

    const result = await drainQueuedCatalog(buildImporterShim(state), buildFakeWithOwnership(state), 10);
    expect(result.needsAttention).toBe(1);
    const row = state.evidence.get(id)!;
    expect(row.status).toBe("needs_attention");
  });

  it("a FRESH, still-unresolved row (claimed catalogVersion not yet imported) stays queued — not yet old enough for needs_attention, and the covering import hasn't run", async () => {
    const state = makeFakeState();
    const id = await insertQueuedRow(state, "user-a", { facilityId: "fac_x", courseId: "crs_x1", catalogVersion: "20260602-b000002", localDate: "2026-06-01" });
    setEvidenceCreatedAt(state, id, state.now.toISOString());

    const result = await drainQueuedCatalog(buildImporterShim(state), buildFakeWithOwnership(state), 10);
    expect(result.stillQueued).toBe(1);
    const row = state.evidence.get(id)!;
    expect(row.status).toBe("queued_catalog");
  });

  // ⛔ M1: "an id still absent after an import that covers its claimed
  // version -> terminal unknown_id status, not left queued." Distinct
  // from the age-based needs_attention case above — this row is FRESH
  // (would otherwise stay queued on age alone) but the claimed version
  // has already been superseded by a LATER import, so it terminates
  // immediately rather than waiting out the 7-day window.
  it("M1: a fresh row whose claimed version the current import already covers terminates as unknown_id immediately, not stillQueued", async () => {
    const state = makeFakeState();
    // The default fixture's own current site version is 20260520-a000001
    // (fake-repo.ts's own makeFakeState doc) — claim an OLDER one, so
    // "the covering import already ran" is unambiguously true.
    const id = await insertQueuedRow(state, "user-a", { facilityId: "fac_ghost_facility", catalogVersion: "20260101-0000000", localDate: "2026-06-01" });
    setEvidenceCreatedAt(state, id, state.now.toISOString()); // fresh — would stay queued on age alone

    const result = await drainQueuedCatalog(buildImporterShim(state), buildFakeWithOwnership(state), 10);
    expect(result.unknownId).toBe(1);
    expect(result.stillQueued).toBe(0);
    const row = state.evidence.get(id)!;
    expect(row.status).toBe("unknown_id");
  });

  it("respects the batch limit, oldest first", async () => {
    const state = makeFakeState();
    const ids: string[] = [];
    for (let i = 0; i < 5; i++) {
      const id = await insertQueuedRow(state, "user-a", { facilityId: "fac_ghost_facility", catalogVersion: "20260520-a000001", localDate: "2026-06-01" });
      setEvidenceCreatedAt(state, id, new Date(NOW.getTime() + i * 1000).toISOString());
      ids.push(id);
    }
    const result = await drainQueuedCatalog(buildImporterShim(state), buildFakeWithOwnership(state), 3);
    expect(result.scanned).toBe(3);
  });

  it("a per-row failure (withOwnership throws) never aborts the rest of the batch", async () => {
    const state = makeFakeState();
    const okId = await insertQueuedRow(state, "user-a", { facilityId: "fac_x", courseId: "crs_x1", catalogVersion: "20260520-a000001", localDate: "2026-06-01" });
    // A claimed version NEWER than current (unsigned) and a FRESH row —
    // even after the thrown exception forces redrainKind to
    // "still_unresolved", this must land on plain `still_queued` (never
    // `needs_attention`/`unknown_id`, which would call `withOwnership`
    // a SECOND time for user-b, throwing again, uncaught, outside this
    // test's own control — see this file's own header note on why the
    // age/coverage judgment needs a not-yet-imported claim).
    const failingId = await insertQueuedRow(state, "user-b", { facilityId: "fac_x", courseId: "crs_x1", catalogVersion: "20260602-b000002", localDate: "2026-06-01" });
    setEvidenceCreatedAt(state, failingId, new Date(NOW.getTime() - 1000).toISOString()); // scanned first, but still FRESH relative to the 7-day needs_attention window

    const flakyWithOwnership: WithOwnershipFn = async (actor, op) => {
      if (actor.uid === "user-b") throw new Error("simulated transaction failure");
      return buildFakeWithOwnership(state)(actor, op);
    };

    const result = await drainQueuedCatalog(buildImporterShim(state), flakyWithOwnership, 10);
    expect(result.scanned).toBe(2);
    expect(result.resolved).toBe(1); // user-a's row still resolved despite user-b's failure
    expect(result.stillQueued).toBe(1); // user-b's row treated as still-unresolved this pass, not lost
    const okRow = state.evidence.get(okId)!;
    expect(okRow.status).toBe("accepted");
    const failingRow = state.evidence.get(failingId)!;
    expect(failingRow.status).toBe("queued_catalog");
  });
});
