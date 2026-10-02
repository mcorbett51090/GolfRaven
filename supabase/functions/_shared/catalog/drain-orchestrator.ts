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
import type { Deadline } from "./time-budget.ts";
import type { Actor, ImporterRepo, Repo } from "../types.ts";

export interface DrainQueuedCatalogResult {
  scanned: number;
  resolved: number;
  needsAttention: number;
  unknownId: number;
  stillQueued: number;
  /** Rows whose pass threw (transient infra error) — left queued. */
  errored: number;
  /** True when the time budget ended the pass before every scanned row was visited (the rest stay queued for the next run). */
  truncated: boolean;
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
export async function drainQueuedCatalog(importerRepo: ImporterRepo, withOwnership: WithOwnershipFn, limit: number = DEFAULT_BATCH_LIMIT, deadline?: Deadline): Promise<DrainQueuedCatalogResult> {
  const rows = await importerRepo.queuedCatalog.listOpen(limit);
  const currentSiteVersion = await importerRepo.queuedCatalog.currentSiteVersion();
  const now = importerRepo.now();

  const result: DrainQueuedCatalogResult = { scanned: rows.length, resolved: 0, needsAttention: 0, unknownId: 0, stillQueued: 0, errored: 0, truncated: false };

  for (const row of rows) {
    // Time-boxed (time-budget.ts): never START a per-user transaction the
    // remaining budget cannot finish; the rest stay queued for the next run.
    if (deadline && !deadline.canStartUnit()) {
      result.truncated = true;
      break;
    }
    const actor: Actor = { uid: row.userId, role: "authenticated" };
    const createdAt = new Date(row.createdAt);
    const aged = now.getTime() - createdAt.getTime() >= MAX_AGE_MS;
    // ⛔ ONE transaction per unit (round 3 gate, LOW): the redrain AND the
    // terminal write (needs_attention / unknown_id) happen in the SAME
    // per-user transaction, so a unit is bounded by one 12 s transaction —
    // never redrain (12 s) + a second terminal-write transaction (12 s)
    // overrunning the unit reserve.
    let outcomeKind: "resolved" | "unknown_id" | "needs_attention" | "still_queued";
    try {
      outcomeKind = await withOwnership(actor, async (repo): Promise<"resolved" | "unknown_id" | "needs_attention" | "still_queued"> => {
        const outcome = await redrainQueuedEvidenceRow(repo, row.id, row.queuedInput, createdAt);
        if (outcome.kind === "resolved") return "resolved";
        if (outcome.kind === "terminal_unknown_id") {
          // redrainQueuedEvidenceRow found a STRUCTURAL failure (forged
          // pairing, a bad local date, ...) — terminal regardless of age or
          // import coverage.
          await repo.evidence.markQueuedTerminal(row.id, "unknown_id");
          return "unknown_id";
        }
        // still_unresolved: the M1 age/version-coverage judgment
        // (drain-queued.ts, pure). A claimed version that has not been
        // imported at all (NEW-1) is never "covered", whatever the current
        // import is.
        const claimedVersionImported = outcome.claimedVersionImported !== false;
        const coveringImportAlreadyRan = claimedVersionImported && currentSiteVersion !== null && compareCatalogVersions(currentSiteVersion, row.claimedCatalogVersion) >= 0;
        const decision = decideQueuedDrainOutcome({ redrainKind: "still_unresolved", createdAt, now, coveringImportAlreadyRan });
        if (decision.kind === "terminal_unknown_id") {
          await repo.evidence.markQueuedTerminal(row.id, "unknown_id");
          return "unknown_id";
        }
        if (decision.kind === "needs_attention") {
          await repo.evidence.markQueuedTerminal(row.id, "needs_attention");
          return "needs_attention";
        }
        return "still_queued";
      });
    } catch (err) {
      // ⛔ FIX (P3e round 2 gate, NEW-2): a THROW (lock/statement timeout,
      // `CONNECTION_CLOSED`/503, deadlock, ...) is a statement about the
      // infrastructure, never about the row. It used to be folded into
      // "still unresolved" — which, once a covering import had run, the M1
      // rule turned into a PERMANENT `unknown_id`. A throw now leaves the
      // row exactly as it was for the next pass; only an explicit
      // `terminal_unknown_id` from the redrain itself, or the row's own
      // 7-day age (-> `needs_attention`, never `unknown_id`), may end it.
      console.error(`drainQueuedCatalog: row ${row.id} failed to redrain (left queued for the next pass)`, err);
      result.errored += 1;
      if (aged) {
        try {
          await withOwnership(actor, (repo) => repo.evidence.markQueuedTerminal(row.id, "needs_attention"));
          result.needsAttention += 1;
        } catch (err2) {
          console.error(`drainQueuedCatalog: row ${row.id} could not be aged out either (left queued)`, err2);
          result.stillQueued += 1;
        }
      } else {
        result.stillQueued += 1;
      }
      continue;
    }

    switch (outcomeKind) {
      case "resolved":
        result.resolved += 1;
        break;
      case "unknown_id":
        result.unknownId += 1;
        break;
      case "needs_attention":
        result.needsAttention += 1;
        break;
      default:
        result.stillQueued += 1;
        break;
    }
  }
  return result;
}

const MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
