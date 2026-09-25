// supabase/functions/checkin-token/index.ts
//
// The `checkin-token` Edge Function (build plan §4.7.1a: "moved out of
// the RPC allowlist because it must verify attestation, sign, and record
// a jti" — see _shared/checkin/token-handler.ts's own header for what is
// and isn't real this round). Thin entrypoint.

import { getActorFromRequest, hitRateLimitForActor, withOwnership } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, readJsonBody, Errors } from "../_shared/http.ts";
import { handleTokenRequest, RATE_LIMIT_PER_USER_HOUR, type TokenRequest } from "../_shared/checkin/token-handler.ts";
import { serve } from "std/http/server";

function isTokenRequest(v: unknown): v is TokenRequest {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.challengeId === "string" &&
    o.challengeId.length > 0 &&
    typeof o.nonce === "string" &&
    o.nonce.length > 0 &&
    typeof o.hardwareSupportsAttestation === "boolean"
  );
}

async function digestHex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes.slice().buffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

serve((req) => handleRequest(async () => {
  if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");

  const actor = await getActorFromRequest(req);
  if (!actor) return Errors.unauthorized().toResponse();

  const body = await readJsonBody(req);
  if (!isTokenRequest(body)) throw Errors.badRequest('body must be {"challengeId": string, "nonce": string, "hardwareSupportsAttestation": boolean}');

  // ⛔ P3c gate round 4, blocking HIGH ("5 concurrent requests deadlock
  // the pool"): hit BEFORE withOwnership opens — see privileged.ts#
  // hitRateLimitForActor's own doc.
  const rateLimit = await hitRateLimitForActor(actor, "checkin-token:user", 3600, RATE_LIMIT_PER_USER_HOUR);
  if (!rateLimit.ok) return Errors.tooManyRequests("checkin-token rate limit exceeded", rateLimit.retryAfterSeconds).toResponse();

  const token = await withOwnership(actor, (repo) => handleTokenRequest(body, repo, digestHex));
  return okResponse(201, token);
}));
