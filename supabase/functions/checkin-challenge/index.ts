// supabase/functions/checkin-challenge/index.ts
//
// POST /v1/checkin/challenge, including prefetch (build plan §4.7.1a
// inventory: "checkin-challenge"). Thin entrypoint over
// _shared/checkin/challenge-handler.ts.

import { getActorFromRequest, withOwnership } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, readJsonBody, Errors } from "../_shared/http.ts";
import { handleChallengeRequest, type ChallengeRequest } from "../_shared/checkin/challenge-handler.ts";
import { serve } from "std/http/server";

function isChallengeRequest(v: unknown): v is ChallengeRequest {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  if (typeof o.deviceId !== "string" || o.deviceId.length === 0) return false;
  if (o.facilityId !== undefined && typeof o.facilityId !== "string") return false;
  if (o.prefetchCount !== undefined && (typeof o.prefetchCount !== "number" || !Number.isInteger(o.prefetchCount))) return false;
  return true;
}

serve((req) => handleRequest(async () => {
  if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");

  const actor = await getActorFromRequest(req);
  if (!actor) return Errors.unauthorized().toResponse();

  const body = await readJsonBody(req);
  if (!isChallengeRequest(body)) throw Errors.badRequest('body must be {"deviceId": string, "facilityId"?: string, "prefetchCount"?: number}');

  const challenges = await withOwnership(actor, (repo) =>
    handleChallengeRequest(
      actor.uid,
      body,
      repo,
      (n) => crypto.getRandomValues(new Uint8Array(n)),
      async (bytes) => {
        const digest = await crypto.subtle.digest("SHA-256", bytes.slice().buffer);
        return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
      },
    ),
  );
  return okResponse(201, { challenges });
}));
