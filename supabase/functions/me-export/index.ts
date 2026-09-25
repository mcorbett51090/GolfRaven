// supabase/functions/me-export/index.ts
//
// GET /v1/me/export (build plan §4.7.1a inventory: "me-export"). Thin
// entrypoint over _shared/me/export-handler.ts.

import { getActorFromRequest, hitRateLimitForActor, withOwnership } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, Errors } from "../_shared/http.ts";
import { EXPORT_SIZE_BOUND_BYTES, handleMeExport } from "../_shared/me/export-handler.ts";
import { serve } from "std/http/server";

// `[inference]` — no plan-stated number (see me-delete/index.ts's own
// note on the same gap). A data-access request is not something a
// legitimate caller does often; this cap exists to bound abuse, not to
// constrain normal use.
const RATE_LIMIT_PER_USER_DAY = 10;

serve((req) =>
  handleRequest(async () => {
    if (req.method !== "GET") return errorResponse(405, "method_not_allowed", "GET only");

    const actor = await getActorFromRequest(req);
    if (!actor) return Errors.unauthorized().toResponse();

    const rateLimit = await hitRateLimitForActor(actor, "me-export:user", 86_400, RATE_LIMIT_PER_USER_DAY);
    if (!rateLimit.ok) return Errors.tooManyRequests("me-export rate limit exceeded", rateLimit.retryAfterSeconds).toResponse();

    const result = await withOwnership(actor, (repo) => handleMeExport(repo, actor.uid));

    const byteLength = new TextEncoder().encode(JSON.stringify({ data: result })).byteLength;
    if (byteLength > EXPORT_SIZE_BOUND_BYTES) {
      // Documented bound exceeded — see export-handler.ts's own doc on
      // EXPORT_SIZE_BOUND_BYTES for why this is logged, not truncated or
      // refused (a privacy access request should not be refused for
      // being large, and a silently truncated export would be worse than
      // an oversized one).
      console.error(`me-export: response for an actor exceeds the documented ${EXPORT_SIZE_BOUND_BYTES}-byte size bound (actual ${byteLength} bytes)`);
    }
    return okResponse(200, result);
  }),
);
