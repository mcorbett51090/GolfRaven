// supabase/functions/evidence-batch/index.ts
//
// POST /v1/evidence/batch (build plan §4.7.1a inventory: "evidence-batch";
// §4.7 item 8: "Historic import... 2,000 items/user/day, separate from
// the live cap; items are scored with event-time velocity only" — the
// event-time-velocity-only nuance is a scorer/DB-side refinement out of
// this round's scope; every item here goes through the SAME
// `handleEvidenceIntake` core as a single POST /v1/evidence call).
//
// Runs each item through the pure handler independently and catches a
// per-item failure (security doc §3: "Catch scorer exceptions per play,
// so one bad row cannot block a re-score batch") — one bad item in a
// batch never fails the other 1,999.
//
// P3c gate round 2, should-fix "batch limits":
//   - the 2,000/user/day cap is now counted PER ITEM (one
//     `repo.rateLimit.hit` call per item, not once per whole request) —
//     a batch that would cross the daily cap partway through stops
//     there, with every remaining item reported as rate_limited in the
//     results array, rather than either silently under-counting (one
//     hit for the whole request) or aborting the entire batch.
//   - each item explicitly skips the LIVE 60/h bucket
//     (`skipLiveRateLimit`) — historic/batch import must not compete
//     with real-time submissions for the same budget.
//   - MAX_BATCH_ITEMS_PER_REQUEST is lowered from 2000 to 100: chosen to
//     fit a reasonable wall-clock budget given each item runs roughly a
//     dozen sequential round trips inside ONE transaction (P3c gate
//     round 2, item 2) — 2,000 items in one request/transaction would
//     both hold that transaction open for an unreasonable time and make
//     one bad item's rollback undo far more work than necessary. A
//     client importing a full 2,000-item/day history sends it across
//     multiple requests.
//
// ⛔ FIX (P3c gate round 3, blocking MEDIUM 4: "one failing item aborts
// the whole transaction"). With the daily count at 1999, a 2-item batch
// used to return 500 and keep 0 rows, forever — `withOwnership` runs the
// ENTIRE callback in one `db.begin()`, and once ANY statement inside it
// errors, Postgres marks the WHOLE transaction aborted — every earlier
// item's already-written rows are lost along with the failing one, not
// merely the failing item's own. This calls `withOwnershipBatch`
// (privileged.ts): each item runs inside its OWN `trx.savepoint(...)` of
// that same outer transaction, so a failing item's writes roll back to
// JUST that item's own savepoint — every earlier item's work stays
// committed to the outer transaction, and later items still run.
//
// ⛔ FIX (P3c gate round 4, blocking HIGH: "5 concurrent requests
// deadlock the pool"). Round 3's own per-item `repo.rateLimit.hit` call
// (inside `withOwnershipBatch`'s per-item closure) had the SAME
// deadlock shape as evidence/handler.ts's own: it opened a SECOND
// pooled connection from inside a callback that already holds ONE (the
// whole batch's own outer transaction). Rate-limiting is now a
// SEPARATE, PRE-TRANSACTION phase (phase 1 below) — every item's rate
// -limit check(s) are hit via `hitRateLimitForActor`, in order, BEFORE
// `withOwnershipBatch` is even called, preserving the original "one hit
// per item slot, even a structurally-invalid one" semantics (should-fix,
// P3c gate round 2: "batch limits") without ever holding two pooled
// connections for the same request at once. Only items that pass phase
// 1 proceed into phase 2's transactional work (savepoint-isolated, as
// before); items decided in phase 1 (rate_limited or bad_request) never
// touch the transaction at all.

import { getActorFromRequest, hitRateLimitForActor, withOwnershipBatch } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, readJsonBody, Errors, HttpError, MAX_BODY_BYTES } from "../_shared/http.ts";
import { handleEvidenceIntake, planEvidenceRateLimitChecks } from "../_shared/evidence/handler.ts";
import { serve } from "std/http/server";

const MAX_BATCH_ITEMS_PER_REQUEST = 100;
const RATE_LIMIT_PER_USER_DAY = 2000;

interface ItemResult {
  index: number;
  ok: boolean;
  result?: unknown;
  error?: { code: string; message: string };
}

function toErrorResult(index: number, err: unknown): ItemResult {
  if (err instanceof HttpError) return { index, ok: false, error: { code: err.code, message: err.message } };
  console.error(`evidence-batch: item ${index} failed unexpectedly`, err);
  return { index, ok: false, error: { code: "internal_error", message: "internal error" } };
}

serve((req) => handleRequest(async () => {
  if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");

  const actor = await getActorFromRequest(req);
  if (!actor) return Errors.unauthorized().toResponse();

  const body = await readJsonBody(req);
  if (typeof body !== "object" || body === null || !Array.isArray((body as Record<string, unknown>).items)) {
    return Errors.badRequest('body must be {"items": [...]}').toResponse();
  }
  const items = (body as { items: unknown[] }).items;
  if (items.length === 0) return Errors.badRequest("items must be non-empty").toResponse();
  if (items.length > MAX_BATCH_ITEMS_PER_REQUEST) {
    return Errors.badRequest(`items must be at most ${MAX_BATCH_ITEMS_PER_REQUEST} per request`).toResponse();
  }

  // ---- Phase 1: pre-transaction rate limiting, for EVERY item, in
  // order — no transaction open at all yet. ----
  const results: ItemResult[] = new Array(items.length);
  const readyIndices: number[] = [];
  for (let i = 0; i < items.length; i++) {
    // The daily batch cap is hit FIRST, unconditionally, per item slot —
    // even a structurally-invalid item still consumes one unit of it
    // (matches the pre-round-4 behavior: the cap was always checked
    // before the item's own content was ever examined).
    const batchRateLimit = await hitRateLimitForActor(actor, `evidence-batch:user`, 86400, RATE_LIMIT_PER_USER_DAY);
    if (!batchRateLimit.ok) {
      results[i] = { index: i, ok: false, error: { code: "rate_limited", message: "evidence-batch daily rate limit exceeded" } };
      continue;
    }
    let planned: ReturnType<typeof planEvidenceRateLimitChecks>;
    try {
      planned = planEvidenceRateLimitChecks(items[i], { skipLiveRateLimit: true });
    } catch (err) {
      results[i] = toErrorResult(i, err);
      continue;
    }
    let deviceRateLimitOk = true;
    for (const check of planned.checks) {
      const r = await hitRateLimitForActor(actor, check.bucketKey, check.windowSeconds, check.max);
      if (!r.ok) {
        deviceRateLimitOk = false;
        break;
      }
    }
    if (!deviceRateLimitOk) {
      results[i] = { index: i, ok: false, error: { code: "rate_limited", message: "evidence rate limit exceeded for this device" } };
      continue;
    }
    readyIndices.push(i);
  }

  // ---- Phase 2: transactional work, ONLY for items that passed phase 1
  // — one outer transaction, one savepoint per ready item (P3c gate
  // round 3, blocking MEDIUM 4). ----
  if (readyIndices.length > 0) {
    const outcomes = await withOwnershipBatch(actor, readyIndices.length, async (repo, j) => {
      const i = readyIndices[j];
      return handleEvidenceIntake(items[i], repo);
    });
    for (let j = 0; j < readyIndices.length; j++) {
      const i = readyIndices[j];
      const outcome = outcomes[j];
      results[i] = outcome.ok ? { index: i, ok: true, result: outcome.value } : toErrorResult(i, outcome.error);
    }
  }

  return okResponse(200, { results, maxBodyBytes: MAX_BODY_BYTES });
}));
