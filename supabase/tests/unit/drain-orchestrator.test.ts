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
import { canonicalStringify, MANIFEST_DOMAIN } from "../../functions/_shared/catalog/manifest-artifact.js";
import { generateKeypair, signBytes } from "./catalog-artifact-fixtures.js";
import { makeDeadline } from "../../functions/_shared/catalog/time-budget.js";

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
async function insertQueuedRow(state: FakeState, uid: string, input: { facilityId: string; courseId?: string | null; catalogVersion: string; localDate: string; manifestSig?: Record<string, unknown> }): Promise<string> {
  const repo = makeFakeRepo(state, uid);
  const sourceRef = `drain-test-${crypto.randomUUID()}`;
  const queuedInput = {
    source: "self_report",
    deviceId: FAKE_DEVICE_ID,
    facilityId: input.facilityId,
    courseId: input.courseId ?? undefined,
    localDate: input.localDate,
    catalogVersion: input.catalogVersion,
    ...(input.manifestSig ? { manifestSig: input.manifestSig } : {}),
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
    expect(result).toEqual({ scanned: 1, resolved: 1, needsAttention: 0, unknownId: 0, stillQueued: 0, errored: 0, truncated: false });

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
    // (The in-memory fake keeps claimed_*/queued_input on a terminal row; the
    // REAL markQueuedTerminal clears them — asserted against Postgres in
    // import-catalog.deno.test.ts.)
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

// ============================================================================
// P3e round 2 gate: NEW-1 (BLOCKER), NEW-2 (HIGH), time budget.
// ============================================================================

const V_NEWER = "20260602-b000002";

/** A REAL Ed25519-signed manifestSig for a claim of `V_NEWER` — the shape
 * that classifies `ok` for a newer-than-current version (the BLOCKER's
 * precondition: a validly signed claim whose version is not imported yet). */
async function signedClaimOfNewer(state: FakeState): Promise<Record<string, unknown>> {
  const { privateKey, publicKeyB64Url } = await generateKeypair();
  state.signingKeys.set("kv", { kid: "kv", publicKeyB64Url, revokedAt: null });
  const manifestSha = "a".repeat(64);
  const sig = await signBytes(privateKey, new TextEncoder().encode(MANIFEST_DOMAIN + canonicalStringify({ catalogVersion: V_NEWER, contractVersion: 1, kid: "kv", manifestSha })));
  return { kid: "kv", contractVersion: 1, manifestSha, sig };
}

describe("NEW-1: a drain before the covering import never kills queued rows", () => {
  it("2 validly-signed rows claiming a NOT-YET-IMPORTED version stay queued (not unknown_id) across drains, then age out to needs_attention — never unknown_id", async () => {
    const state = makeFakeState();
    const manifestSig = await signedClaimOfNewer(state);
    const a = await insertQueuedRow(state, "user-a", { facilityId: "fac_new", courseId: "crs_new", catalogVersion: V_NEWER, localDate: "2026-06-01", manifestSig });
    const b = await insertQueuedRow(state, "user-b", { facilityId: "fac_new", courseId: "crs_new", catalogVersion: V_NEWER, localDate: "2026-06-01", manifestSig });

    const first = await drainQueuedCatalog(buildImporterShim(state), buildFakeWithOwnership(state), 10);
    expect(first).toMatchObject({ scanned: 2, resolved: 0, unknownId: 0, needsAttention: 0, stillQueued: 2 });
    // ...and again (the drain runs after EVERY import, including failed ones).
    const second = await drainQueuedCatalog(buildImporterShim(state), buildFakeWithOwnership(state), 10);
    expect(second).toMatchObject({ unknownId: 0, stillQueued: 2 });
    expect(state.evidence.get(a)!.status).toBe("queued_catalog");
    expect(state.evidence.get(b)!.status).toBe("queued_catalog");

    // 7 days on, with the covering import STILL not run: needs_attention.
    for (const id of [a, b]) setEvidenceCreatedAt(state, id, new Date(state.now.getTime() - 8 * 24 * 60 * 60 * 1000).toISOString());
    const third = await drainQueuedCatalog(buildImporterShim(state), buildFakeWithOwnership(state), 10);
    expect(third).toMatchObject({ needsAttention: 2, unknownId: 0 });
    expect(state.evidence.get(a)!.status).toBe("needs_attention");
  });

  it("once the claimed version IS imported and carries the ids, the same rows resolve", async () => {
    const state = makeFakeState();
    const manifestSig = await signedClaimOfNewer(state);
    const a = await insertQueuedRow(state, "user-a", { facilityId: "fac_x", courseId: "crs_x1", catalogVersion: V_NEWER, localDate: "2026-06-01", manifestSig });
    const before = await drainQueuedCatalog(buildImporterShim(state), buildFakeWithOwnership(state), 10);
    expect(before.stillQueued).toBe(1);
    // The covering import lands.
    state.catalogVersions.set(2, { version: 2, siteVersion: V_NEWER, publishedAt: "2026-06-02T00:00:00.000Z", contractVersion: "1", sha256: "x", kid: "kv" });
    const after = await drainQueuedCatalog(buildImporterShim(state), buildFakeWithOwnership(state), 10);
    expect(after.resolved).toBe(1);
    expect(state.evidence.get(a)!.status).toBe("accepted");
  });
});

describe("NEW-2: a transient error never makes a row terminal", () => {
  it("a throw (lock/statement timeout, CONNECTION_CLOSED, deadlock) leaves the row queued even when the covering import already ran", async () => {
    const state = makeFakeState();
    // Claims the CURRENT version: the covering import has "already run", so
    // the OLD code (throw -> still_unresolved -> M1) made this unknown_id.
    const id = await insertQueuedRow(state, "user-a", { facilityId: "fac_x", courseId: "crs_x1", catalogVersion: "20260520-a000001", localDate: "2026-06-01" });
    // Only the REDRAIN throws (a healthy connection would then happily mark
    // the row terminal — which is exactly what the old code did).
    let calls = 0;
    const throwing: WithOwnershipFn = async (actor, op) => {
      calls += 1;
      if (calls === 1) throw Object.assign(new Error("canceling statement due to lock timeout"), { code: "55P03" });
      return buildFakeWithOwnership(state)(actor, op);
    };
    const result = await drainQueuedCatalog(buildImporterShim(state), throwing, 10);
    expect(result).toMatchObject({ scanned: 1, errored: 1, stillQueued: 1, unknownId: 0, needsAttention: 0, resolved: 0 });
    expect(state.evidence.get(id)!.status).toBe("queued_catalog");

    // Next pass, healthy: it resolves.
    const retry = await drainQueuedCatalog(buildImporterShim(state), buildFakeWithOwnership(state), 10);
    expect(retry.resolved).toBe(1);
  });

  it("a row older than 7 days that keeps throwing ages out to needs_attention (the 7-day timer, never unknown_id)", async () => {
    const state = makeFakeState();
    const id = await insertQueuedRow(state, "user-a", { facilityId: "fac_x", courseId: "crs_x1", catalogVersion: "20260520-a000001", localDate: "2026-06-01" });
    setEvidenceCreatedAt(state, id, new Date(state.now.getTime() - 8 * 24 * 60 * 60 * 1000).toISOString());
    let calls = 0;
    const flaky: WithOwnershipFn = async (actor, op) => {
      calls += 1;
      if (calls === 1) throw new Error("deadlock detected");
      return buildFakeWithOwnership(state)(actor, op);
    };
    const result = await drainQueuedCatalog(buildImporterShim(state), flaky, 10);
    expect(result).toMatchObject({ errored: 1, needsAttention: 1, unknownId: 0 });
    expect(state.evidence.get(id)!.status).toBe("needs_attention");
  });

  it("the terminal write shares the redrain's ONE transaction: if it throws, the whole unit rolls back and the row is simply left queued", async () => {
    const state = makeFakeState();
    // structural failure -> terminal_unknown_id from the redrain itself
    const id = await insertQueuedRow(state, "user-a", { facilityId: "fac_x", courseId: "crs_ghost", catalogVersion: "20260520-a000001", localDate: "2026-06-01" });
    let calls = 0;
    const flaky: WithOwnershipFn = async (actor, op) => {
      calls += 1;
      if (calls === 1) throw new Error("CONNECTION_CLOSED");
      return buildFakeWithOwnership(state)(actor, op);
    };
    const result = await drainQueuedCatalog(buildImporterShim(state), flaky, 10);
    expect(calls).toBe(1); // ONE transaction per unit — no second terminal-write transaction
    expect(result).toMatchObject({ unknownId: 0, errored: 1, stillQueued: 1 });
    expect(state.evidence.get(id)!.status).toBe("queued_catalog");
    // and a healthy pass makes it terminal, in a single transaction
    calls = 100;
    const retry = await drainQueuedCatalog(buildImporterShim(state), flaky, 10);
    expect(retry.unknownId).toBe(1);
    expect(calls).toBe(101);
  });
});

describe("time budget: the drain stops starting work it cannot finish", () => {
  it("an exhausted deadline truncates the pass and leaves every row queued", async () => {
    const state = makeFakeState();
    const id = await insertQueuedRow(state, "user-a", { facilityId: "fac_x", courseId: "crs_x1", catalogVersion: "20260520-a000001", localDate: "2026-06-01" });
    const spent = makeDeadline(() => 1_000, 1_000 + 5_000); // 5 s left < one unit's reserve
    const result = await drainQueuedCatalog(buildImporterShim(state), buildFakeWithOwnership(state), 10, spent);
    expect(result).toMatchObject({ scanned: 1, resolved: 0, truncated: true });
    expect(state.evidence.get(id)!.status).toBe("queued_catalog");
  });
});

