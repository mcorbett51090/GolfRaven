// supabase/functions/evidence/index.ts
//
// POST /v1/evidence (build plan §4.7.1a inventory: "evidence"). Thin Deno
// entrypoint — every real decision lives in
// supabase/functions/_shared/evidence/handler.ts (pure, unit-tested); this
// file only wires the HTTP request into it: verify the JWT, cap the body,
// call withOwnership, map the result to a status code.

import { getActorFromRequest, withOwnership } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, readJsonBody, Errors } from "../_shared/http.ts";
import { handleEvidenceIntake } from "../_shared/evidence/handler.ts";
import { serve } from "std/http/server";

serve((req) => handleRequest(async () => {
  if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");

  const actor = await getActorFromRequest(req);
  if (!actor) return Errors.unauthorized().toResponse();

  const body = await readJsonBody(req);
  const result = await withOwnership(actor, (repo) => handleEvidenceIntake(body, repo));
  return okResponse(result.status === "queued_catalog" ? 202 : 200, result);
}));
