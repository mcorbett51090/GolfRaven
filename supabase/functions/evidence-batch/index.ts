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

import { getActorFromRequest, withOwnership } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, readJsonBody, Errors, HttpError, MAX_BODY_BYTES } from "../_shared/http.ts";
import { handleEvidenceIntake } from "../_shared/evidence/handler.ts";
import { serve } from "std/http/server";

// build plan §4.7 item 8's "2,000 items/user/day" is a PER-DAY rate limit
// across every /v1/evidence/batch call that day (enforced below via
// Repo#hitRateLimit), not a per-request cap — a single request's item
// count is bounded far more tightly by the 64KB body cap already (P3 AT
// 8), so MAX_BATCH_ITEMS_PER_REQUEST here is a generous, purely
// structural sanity bound (never expected to bind before the body cap
// does).
const MAX_BATCH_ITEMS_PER_REQUEST = 2000;
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

  const results = await withOwnership(actor, async (repo) => {
    const rateLimit = await repo.hitRateLimit(`evidence-batch:user:${actor.uid}`, 86400, RATE_LIMIT_PER_USER_DAY);
    if (!rateLimit.ok) throw Errors.tooManyRequests("evidence-batch daily rate limit exceeded", rateLimit.retryAfterSeconds);

    const out: Array<{ index: number; ok: boolean; result?: unknown; error?: { code: string; message: string } }> = [];
    for (let i = 0; i < items.length; i++) {
      try {
        const result = await handleEvidenceIntake(actor.uid, items[i], repo);
        out.push({ index: i, ok: true, result });
      } catch (err) {
        if (err instanceof HttpError) {
          out.push({ index: i, ok: false, error: { code: err.code, message: err.message } });
        } else {
          console.error(`evidence-batch: item ${i} failed unexpectedly`, err);
          out.push({ index: i, ok: false, error: { code: "internal_error", message: "internal error" } });
        }
      }
    }
    return out;
  });

  return okResponse(200, { results, maxBodyBytes: MAX_BODY_BYTES });
}));
