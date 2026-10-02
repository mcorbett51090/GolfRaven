// supabase/functions/evidence-batch/index.ts
//
// POST /v1/evidence/batch (build plan §4.7.1a inventory: "evidence-batch").
// Thin entrypoint — every real decision lives in
// _shared/evidence/batch-handler.ts (P3d should-fix 1: extracted so it
// can be exercised directly by an integration test, the same "pure,
// DI'd" shape every other endpoint in this round already uses); this
// file only wires the HTTP request into it: verify the JWT, cap the body
// and item count, call the shared handler, wrap the response.

import { getActorFromRequest } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, readJsonBody, Errors, MAX_BODY_BYTES } from "../_shared/http.ts";
import { handleEvidenceBatchIntake, MAX_BATCH_ITEMS_PER_REQUEST } from "../_shared/evidence/batch-handler.ts";
import { serve } from "std/http/server";

serve((req) =>
  handleRequest(async () => {
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

    const { results } = await handleEvidenceBatchIntake(actor, items);
    return okResponse(200, { results, maxBodyBytes: MAX_BODY_BYTES });
  }),
);
