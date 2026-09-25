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
// errors (the 2nd item's rate-limit RAISE, pre-round-3; or any later
// per-item failure in general), Postgres marks the WHOLE transaction
// aborted — every earlier item's already-written rows are lost along
// with the failing one, not merely the failing item's own. This now
// calls `withOwnershipBatch` (privileged.ts) instead: each item runs
// inside its OWN `trx.savepoint(...)` of that same outer transaction, so
// a failing item's writes roll back to JUST that item's own savepoint —
// every earlier item's work stays committed to the outer transaction,
// and later items still run. Items after the daily cap is reached are
// still reported `rate_limited` (`repo.rateLimit.hit`, per-item, now
// itself immune to any of this by running in its own separate
// transaction — P3c gate round 3, blocking MEDIUM 3, privileged.ts).

import { getActorFromRequest, withOwnershipBatch } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, readJsonBody, Errors, HttpError, MAX_BODY_BYTES } from "../_shared/http.ts";
import { handleEvidenceIntake } from "../_shared/evidence/handler.ts";
import { serve } from "std/http/server";

const MAX_BATCH_ITEMS_PER_REQUEST = 100;
const RATE_LIMIT_PER_USER_DAY = 2000;

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

  const outcomes = await withOwnershipBatch(actor, items.length, async (repo, i) => {
    // Rate-limit check FIRST, before this item's own savepoint-wrapped
    // work — a cap-crossing item is rejected as rate_limited without
    // ever attempting its (pointless, since it will be discarded) writes.
    // `repo.rateLimit.hit` commits in its own separate transaction
    // regardless (privileged.ts), so this counts unconditionally, even
    // though it runs from inside this item's own savepoint scope.
    const rateLimit = await repo.rateLimit.hit(`evidence-batch:user`, 86400, RATE_LIMIT_PER_USER_DAY);
    if (!rateLimit.ok) {
      throw Errors.tooManyRequests("evidence-batch daily rate limit exceeded");
    }
    return handleEvidenceIntake(items[i], repo, { skipLiveRateLimit: true });
  });

  const results = outcomes.map((outcome, i) => {
    if (outcome.ok) return { index: i, ok: true, result: outcome.value };
    const err = outcome.error;
    if (err instanceof HttpError) {
      return { index: i, ok: false, error: { code: err.code, message: err.message } };
    }
    console.error(`evidence-batch: item ${i} failed unexpectedly`, err);
    return { index: i, ok: false, error: { code: "internal_error", message: "internal error" } };
  });

  return okResponse(200, { results, maxBodyBytes: MAX_BODY_BYTES });
}));
