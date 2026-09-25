// supabase/functions/checkin-token/index.ts
//
// The `checkin-token` Edge Function (build plan §4.7.1a: "moved out of
// the RPC allowlist because it must verify attestation, sign, and record
// a jti" — see _shared/checkin/token-handler.ts's own header for what is
// and isn't real this round). Thin entrypoint.

import { getActorFromRequest, withOwnership } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, readJsonBody, Errors } from "../_shared/http.ts";
import { handleTokenRequest, type TokenRequest } from "../_shared/checkin/token-handler.ts";
import { serve } from "std/http/server";

function isTokenRequest(v: unknown): v is TokenRequest {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return typeof o.challengeId === "string" && o.challengeId.length > 0 && typeof o.hardwareSupportsAttestation === "boolean";
}

serve((req) => handleRequest(async () => {
  if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");

  const actor = await getActorFromRequest(req);
  if (!actor) return Errors.unauthorized().toResponse();

  const body = await readJsonBody(req);
  if (!isTokenRequest(body)) throw Errors.badRequest('body must be {"challengeId": string, "hardwareSupportsAttestation": boolean}');

  const token = await withOwnership(actor, (repo) => handleTokenRequest(actor.uid, body, repo));
  return okResponse(201, token);
}));
