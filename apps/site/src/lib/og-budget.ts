/**
 * og-budget.ts — the §5.2 "Automatic fallback" rule, implemented for
 * real (Opus gate should-fix, OG cards: "Implement the §5.2
 * budget-projected fallback, not just a simulate flag").
 *
 * §5.2's exact text: *"before rendering, the build projects the missing-
 * card render time; if it exceeds the remaining budget, cards beyond the
 * budget ship with the per-trail template card ... and are queued for the
 * next release. The build never fails on OG volume."*
 *
 * This module is the projector: a running total of time actually spent
 * rendering FRESH (cache-miss) cards THIS build, an estimate of the next
 * card's render time (seeded from SWC's own measured baseline — "857 OG
 * PNGs ≈ 2m37s", `swc-analysis.md §1.2`, ≈ 183ms/card — and refined from
 * this build's own real measurements as it goes, so a slower/faster host
 * self-corrects instead of trusting a fixed guess), and a budget
 * (`GOLFRAVEN_OG_BUDGET_MS`, default a generous 10 minutes — well under
 * the ≤ 12 min WARM BUILD gate `verify-budget.mjs` enforces separately,
 * leaving headroom for everything else `astro build` does in the same
 * warm-build window).
 *
 * Module-level (process-lifetime) state is intentional: `astro build`
 * renders every static/API route in ONE Node process for this repo's
 * build (no worker-pool config), so a plain in-memory counter is a
 * faithful per-build tracker without needing a lockfile/IPC.
 */

const SWC_BASELINE_MS_PER_CARD = ((2 * 60 + 37) * 1000) / 857; // ≈ 183ms

let spentMs = 0;
let renderedCount = 0;
let queuedCount = 0;

function budgetMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = Number(env.GOLFRAVEN_OG_BUDGET_MS);
  return Number.isFinite(raw) && raw > 0 ? raw : 10 * 60 * 1000;
}

function estimatedNextCardMs(): number {
  return renderedCount > 0 ? spentMs / renderedCount : SWC_BASELINE_MS_PER_CARD;
}

/** Call BEFORE rendering a fresh (cache-miss) card. `true` = render the
 * full per-course card; `false` = the projected time would exceed the
 * remaining budget — ship the per-trail template card instead, and this
 * card is implicitly "queued for the next release" (the very next build
 * that has cache budget left retries it, since it's still uncached). */
export function shouldRenderFresh(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  const projected = spentMs + estimatedNextCardMs();
  if (projected > budgetMs(env)) {
    queuedCount++;
    return false;
  }
  return true;
}

/** Call AFTER a fresh render completes, with its measured wall-clock
 * time — refines the running per-card estimate for the rest of THIS
 * build. */
export function recordRenderTime(ms: number): void {
  spentMs += ms;
  renderedCount++;
}

/** For tests and the build's own end-of-run log line — never mutated by
 * a reader. */
export function ogBudgetStats() {
  return {
    spentMs,
    renderedCount,
    queuedCount,
    estimatedNextCardMs: estimatedNextCardMs(),
  };
}

/** Test-only: resets module state between test cases (this module's
 * whole POINT is process-lifetime state, which a test suite running many
 * cases in one process needs to reset explicitly rather than accidentally
 * share). */
export function resetOgBudgetForTests(): void {
  spentMs = 0;
  renderedCount = 0;
  queuedCount = 0;
}

export { SWC_BASELINE_MS_PER_CARD };
