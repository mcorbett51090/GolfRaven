// supabase/functions/_shared/catalog/time-budget.ts
//
// Explicit per-PHASE deadlines for `import-catalog` (P3e round 2 gate,
// MEDIUM "time budget"). The endpoint used to inherit http.ts's single
// 15 s race, which had to cover sequential 15 s artifact fetches, a 12 s
// import transaction, the queued drain AND the re-score — so a full-
// directory run answered 503 while work kept going unobserved.
//
// DESIGN (each phase has its OWN bound; the total is a backstop, not the
// mechanism):
//
//   fetch phase      <= FETCH_PHASE_MS (30 s) total across ALL artifact fetches
//                    (each fetch additionally capped at PER_FETCH_MS and
//                    never allowed past the phase deadline);
//   import write     one transaction, bounded by privileged.ts's own
//                    `transaction_timeout` (12 s) — unchanged;
//   drain + rescore  TIME-BOXED by whatever budget remains: a new row /
//                    play is only STARTED while at least UNIT_RESERVE_MS
//                    remain (one unit is one short per-user transaction,
//                    itself capped at 12 s), the remainder is split
//                    between the two drains, and whatever is left over
//                    simply stays queued / stays in the backlog (cursor
//                    persisted) for the NEXT run.
//
// The response is therefore always TRUTHFUL: it reports what each phase
// actually did and a `truncated` flag, instead of a 503 that hides work
// still in flight. TOTAL_BUDGET_MS is also the http.ts race for this
// function, so the 503 backstop can only fire if a single phase blows
// through its own bound.
//
// `[unverified — training knowledge]`: the hosting platform's own
// wall-clock ceiling for an Edge Function request. 100 s is chosen to sit
// comfortably under the documented-at-the-time ceilings, but confirm it
// against the deployed project's plan before relying on the margin; every
// number here is one constant to change.

export const TOTAL_BUDGET_MS = 100_000;
// 30 s (was 40): with the 26 s unit reserve, a fetch phase + a 12 s import write
// must still leave the drain half of the budget at least one full unit (42 s used
// at worst -> 58 s left -> a 29 s drain slice >= 26 s).
export const FETCH_PHASE_MS = 30_000;
export const PER_FETCH_MS = 15_000;
/** One drain/rescore unit is normally ONE per-user transaction (<= 12 s) — the
 * queued drain writes a terminal state inside the same transaction as the
 * redrain. The one exception is a row whose redrain transaction THREW and
 * which is past its 7-day age: ageing it out is a second transaction, so a
 * unit can take two (12 s + 12 s). The reserve covers both plus margin. */
export const UNIT_RESERVE_MS = 26_000;

export interface Deadline {
  /** Epoch ms. */
  at: number;
  remainingMs(): number;
  /** True while a NEW unit of work (<= UNIT_RESERVE_MS) may still be started. */
  canStartUnit(): boolean;
}

export function makeDeadline(nowMs: () => number, atMs: number): Deadline {
  return {
    at: atMs,
    remainingMs: () => atMs - nowMs(),
    canStartUnit: () => atMs - nowMs() >= UNIT_RESERVE_MS,
  };
}

export interface ImportBudget {
  startedAt: number;
  /** Phase 1 deadline (network + crypto). */
  fetch: Deadline;
  /** The whole-request deadline. */
  total: Deadline;
  /** Called after the import finishes: splits what is left between the queued drain (first half) and the re-score (the rest). */
  splitRemaining(): { drain: Deadline; rescore: Deadline };
}

export function makeImportBudget(nowMs: () => number): ImportBudget {
  const startedAt = nowMs();
  const totalAt = startedAt + TOTAL_BUDGET_MS;
  return {
    startedAt,
    fetch: makeDeadline(nowMs, startedAt + FETCH_PHASE_MS),
    total: makeDeadline(nowMs, totalAt),
    splitRemaining() {
      const now = nowMs();
      const usable = Math.max(0, totalAt - now);
      return { drain: makeDeadline(nowMs, now + Math.floor(usable / 2)), rescore: makeDeadline(nowMs, totalAt) };
    },
  };
}
