// supabase/functions/me-offline-seed/index.ts
//
// POST /v1/me/offline-seed (build plan §7.6 "Offline staff path (G-P1-07)": the 6-digit TOTP's per-(account, device) seed, "provisioned by the server while
// online and held in the secure store"). Thin entrypoint over _shared/me/offline-seed-handler.ts. Actor-scoped: the caller can read, and rotate, the seed of
// THEIR OWN device only (another account's device, or none, is a 404; the device must already be registered: this endpoint never creates one).
//
// The response carries a SECRET, so it is `cache-control: no-store`, and nothing here (or in the handler) logs it. Request: {"deviceId": uuid, "rotate"?:
// boolean}; strict: any other key is a 400. Response: {"data": {"seed", "stepSeconds": 600, "digits": 6, "algorithm": "SHA256", "seedVersion", "issuedAt"}}.

import { getActorFromRequest, hitRateLimitForActor, withOwnership } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, readJsonBody, Errors } from "../_shared/http.ts";
import { handleOfflineSeedRequest, parseOfflineSeedRequest } from "../_shared/me/offline-seed-handler.ts";
import {
  OFFLINE_SEED_REVEAL_BUCKET,
  OFFLINE_SEED_REVEAL_PER_HOUR,
  OFFLINE_SEED_ROTATE_BUCKET,
  OFFLINE_SEED_ROTATE_PER_HOUR,
} from "../_shared/offline-code/params.ts";
import { serve } from "std/http/server";

serve((req) =>
  handleRequest(async () => {
    if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");

    const actor = await getActorFromRequest(req);
    if (!actor) return Errors.unauthorized().toResponse();

    const body = parseOfflineSeedRequest(await readJsonBody(req));

    // ⛔ Same ordering every other write endpoint uses (P3c gate round 4, blocking HIGH): hit BEFORE withOwnership opens (a rate-limit hit inside the
    // request transaction would hold a second pooled connection). Every call is a seed reveal and is limited; a rotation is limited again, much harder.
    const reveal = await hitRateLimitForActor(actor, OFFLINE_SEED_REVEAL_BUCKET, 3_600, OFFLINE_SEED_REVEAL_PER_HOUR);
    if (!reveal.ok) return Errors.tooManyRequests("me-offline-seed rate limit exceeded", reveal.retryAfterSeconds).toResponse();
    if (body.rotate === true) {
      const rotate = await hitRateLimitForActor(actor, OFFLINE_SEED_ROTATE_BUCKET, 3_600, OFFLINE_SEED_ROTATE_PER_HOUR);
      if (!rotate.ok) return Errors.tooManyRequests("me-offline-seed rotation rate limit exceeded", rotate.retryAfterSeconds).toResponse();
    }

    const result = await withOwnership(actor, (repo) => handleOfflineSeedRequest(body, repo));
    return okResponse(200, result, { "cache-control": "no-store" });
  }),
);
