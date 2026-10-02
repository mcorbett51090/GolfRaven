// supabase/functions/_shared/catalog/drain-queued.ts
//
// Pure decision logic for `queued_catalog` draining (build plan §3.3, P3
// AT 8 / AT 15 / G3-10; P3e round 2 gate B2/M1). Given the OUTCOME of a
// real re-derivation attempt (`evidence/handler.ts#redrainQueuedEvidenceRow`
// — which has ALREADY tried to resolve the row for real, through the
// same code path live intake uses) plus the row's own age and claimed
// version, decides what a "still not resolved this pass" result actually
// means: legitimately still queued, aged out to `needs_attention`
// (age-based, no review_item), or terminally `unknown_id` (M1: "an id
// still absent after an import that covers its claimed version").
//
// ⛔ REWRITE (P3e round 2 gate, B2: "never promote without re-running
// intake"). The OLD version of this module decided "resolved" purely
// from "do the claimed ids exist in the ledger now?" and left the
// CALLER (drain-orchestrator.ts, at the time) to flip `app.evidence.status`
// to `accepted` directly, with no re-score at all — exactly the
// "draining launders rows" bug the gate's own probe D reproduced (a
// promoted row was later quarantined as a `fraud_signal`, because its
// `summary` was still the OLD queue-time placeholder, never replaced with
// real derived fix data). That responsibility has moved entirely to
// `redrainQueuedEvidenceRow`, which performs a REAL derivation-and-score
// attempt before this module is ever consulted — this module's only job
// now is the "what to do about a row that STILL isn't resolved" decision.

export type QueuedDrainOutcome =
  | { kind: "resolved" } // redrainQueuedEvidenceRow already applied this — informational only
  | { kind: "needs_attention" } // > 7 days unresolved, and the covering import hasn't necessarily run — no review_item (build plan §3.3)
  | { kind: "terminal_unknown_id" } // M1: the covering import already ran and the id still doesn't exist — OR redrainQueuedEvidenceRow itself found a structural failure (forged pairing, bad local date, ...)
  | { kind: "still_queued" }; // not yet resolved, not yet aged out, and the covering import hasn't run yet — legitimately still pending

export interface DrainQueuedInput {
  /** The outcome `redrainQueuedEvidenceRow` already reached for this row
   * THIS pass — "resolved" and "terminal_unknown_id" are already final;
   * only "still_unresolved" needs this module's own age/version-coverage
   * judgment. */
  redrainKind: "resolved" | "still_unresolved" | "terminal_unknown_id";
  createdAt: Date;
  now: Date;
  /** M1: the covering import "already ran" iff the importer's own
   * current site version is at or past the row's own claimed version —
   * `compareCatalogVersions(currentSiteVersion, claimedCatalogVersion) >= 0`
   * (the caller does this comparison — see manifest-artifact.ts's own
   * `compareCatalogVersions` — and passes the boolean result here, so
   * this module stays free of any site-version-string parsing of its
   * own). `null` currentSiteVersion (nothing imported at all yet) is
   * never "already ran". */
  coveringImportAlreadyRan: boolean;
  /** Default 7 — build plan §3.3 / AT 15: "unresolved after 7 days". */
  maxAgeDays?: number;
}

const DEFAULT_MAX_AGE_DAYS = 7;

export function decideQueuedDrainOutcome(input: DrainQueuedInput): QueuedDrainOutcome {
  if (input.redrainKind === "resolved") return { kind: "resolved" };
  if (input.redrainKind === "terminal_unknown_id") return { kind: "terminal_unknown_id" };

  // redrainKind === "still_unresolved" from here on.
  if (input.coveringImportAlreadyRan) {
    // M1: the import that should have brought this id in already ran,
    // and it still isn't there — never left to linger on the 7-day
    // timer, which exists for the OTHER case (the import legitimately
    // hasn't happened yet).
    return { kind: "terminal_unknown_id" };
  }

  const maxAgeDays = input.maxAgeDays ?? DEFAULT_MAX_AGE_DAYS;
  const ageMs = input.now.getTime() - input.createdAt.getTime();
  if (ageMs >= maxAgeDays * 24 * 60 * 60 * 1000) return { kind: "needs_attention" };
  return { kind: "still_queued" };
}
