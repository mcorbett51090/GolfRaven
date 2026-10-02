// supabase/functions/_shared/catalog/drain-orchestrator.ts
//
// The I/O half of `queued_catalog` draining — for each open row, opens a
// PER-ROW, actor-scoped transaction (via an injected `withOwnership`
// -shaped function — this module stays privileged.ts-free, matching
// evidence/handler.ts's own dependency-injection discipline) and calls
// `evidence/handler.ts#redrainQueuedEvidenceRow`, the REAL re-derivation
// entry point (P3e round 2 gate, B2). `decideQueuedDrainOutcome`
// (drain-queued.ts, pure) then decides what a "still not resolved" result
// means (still queued / aged out / terminal — M1).
//
// ⛔ REWRITE (P3e round 2 gate, B2 — probe D). The OLD version of this
// file called a system-scoped `ImporterRepo#queuedCatalog.promoteToAccepted`
// — a raw `UPDATE ... SET status = 'accepted'` with NO re-derivation and
// NO re-score at all. That is exactly what "draining launders rows" means:
// a promoted row's own `summary` jsonb was still the ORIGINAL queue-time
// placeholder (`{queuedForCatalogVersion: ...}`), never replaced with real
// derived fix data, so the NEXT time anything tried to score a play that
// included it, the scorer's own quarantine logic rejected the malformed
// shape and raised a `fraud_signal` — the row was "promoted" and yet
// never actually scored. Every promotion now goes through
// `redrainQueuedEvidenceRow`, which re-runs the REAL pipeline (tombstone
// rewrite, facility/course pairing, localDate, the matcher, `scorePlay`)
// before ever touching `status`.

import { decideQueuedDrainOutcome } from "./drain-queued.ts";
import { redrainQueuedEvidenceRow } from "../evidence/handler.ts";
import { compareCatalogVersions } from "./manifest-artifact.ts";
import type { Actor, ImporterRepo, Repo } from "../types.ts";

export interface DrainQueuedCatalogResult {
  scanned: number;
  resolved: number;
  needsAttention: number;
  unknownId: number;
  stillQueued: number;
}

const DEFAULT_BATCH_LIMIT = 500;

/** `withOwnership` is injected (the exact shape
 * `privileged.ts#withOwnership` already has) rather than imported
 * directly — this module runs pure derivation/decision logic over
 * whatever transaction wrapper the caller (`import-catalog/index.ts`)
 * supplies, the same DI discipline `evidence/handler.ts`'s own
 * `planEvidenceRateLimitChecks`/`handleEvidenceIntake` already use for
 * their own injected dependencies. */
export type WithOwnershipFn = <T>(actor: Actor, op: (repo: Repo) => Promise<T>) => Promise<T>;

/** Drains up to `limit` open `queued_catalog` rows, oldest first, each in
 * its OWN per-user transaction (so one row's failure — a thrown error
 * inside `redrainQueuedEvidenceRow`, or the transaction's own timeout —
 * never aborts every other row's chance to drain this pass). `now` and
 * `currentSiteVersion` are read ONCE, up front, from `importerRepo`
 * (system-scoped, cross-user) — every row this pass judges against the
 * SAME snapshot of "what has been imported," so draining 500 rows over
 * several seconds can't have row #1 and row #500 judged against subtly
 * different "current" states. */
export async function drainQueuedCatalog(importerRepo: ImporterRepo, withOwnership: WithOwnershipFn, limit: number = DEFAULT_BATCH_LIMIT): Promise<DrainQueuedCatalogResult> {
  const rows = await importerRepo.queuedCatalog.listOpen(limit);
  const currentSiteVersion = await importerRepo.queuedCatalog.currentSiteVersion();
  const now = importerRepo.now();

  const result: DrainQueuedCatalogResult = { scanned: rows.length, resolved: 0, needsAttention: 0, unknownId: 0, stillQueued: 0 };

  for (const row of rows) {
    const actor: Actor = { uid: row.userId, role: "authenticated" };
    let redrainKind: "resolved" | "still_unresolved" | "terminal_unknown_id";
    try {
      redrainKind = await withOwnership(actor, async (repo) => {
        const outcome = await redrainQueuedEvidenceRow(repo, row.id, row.queuedInput, new Date(row.createdAt));
        return outcome.kind === "resolved" || outcome.kind === "terminal_unknown_id" ? outcome.kind : "still_unresolved";
      });
    } catch (err) {
      // A per-row failure (a transaction timeout, an unexpected
      // exception inside redrainQueuedEvidenceRow) never aborts the
      // whole batch — logged, treated as "still unresolved this pass,"
      // and picked up again on a LATER drain run rather than losing the
      // row's own chance to resolve on a future pass.
      console.error(`drainQueuedCatalog: row ${row.id} failed to redrain`, err);
      redrainKind = "still_unresolved";
    }

    if (redrainKind === "resolved") {
      result.resolved += 1;
      continue;
    }
    if (redrainKind === "terminal_unknown_id") {
      // redrainQueuedEvidenceRow found a STRUCTURAL failure (forged
      // pairing, a bad local date, ...) — terminal regardless of age or
      // import coverage. Applied via the SAME per-row actor-scoped
      // transaction shape as a resolution (markQueuedTerminal), not the
      // system-scoped repo (B2's own "no more system-scoped promotion"
      // reasoning applies here identically).
      await withOwnership(actor, (repo) => repo.evidence.markQueuedTerminal(row.id, "unknown_id"));
      result.unknownId += 1;
      continue;
    }

    // redrainKind === "still_unresolved": the M1 age/version-coverage
    // judgment (drain-queued.ts, pure).
    const coveringImportAlreadyRan = currentSiteVersion !== null && compareCatalogVersions(currentSiteVersion, row.claimedCatalogVersion) >= 0;
    const decision = decideQueuedDrainOutcome({ redrainKind: "still_unresolved", createdAt: new Date(row.createdAt), now, coveringImportAlreadyRan });
    switch (decision.kind) {
      case "terminal_unknown_id":
        await withOwnership(actor, (repo) => repo.evidence.markQueuedTerminal(row.id, "unknown_id"));
        result.unknownId += 1;
        break;
      case "needs_attention":
        await withOwnership(actor, (repo) => repo.evidence.markQueuedTerminal(row.id, "needs_attention"));
        result.needsAttention += 1;
        break;
      default:
        result.stillQueued += 1;
        break;
    }
  }
  return result;
}
