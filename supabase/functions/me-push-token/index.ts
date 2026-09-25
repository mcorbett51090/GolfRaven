// supabase/functions/me-push-token/index.ts
//
// POST /v1/me/push-token (build plan §4.7.1a inventory: "me-push-token";
// line 832). Thin entrypoint over _shared/me/push-token-handler.ts.

import { getActorFromRequest, hitRateLimitForActor, withOwnership } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, readJsonBody, Errors } from "../_shared/http.ts";
import { handlePushTokenRequest, type PushTokenRequest } from "../_shared/me/push-token-handler.ts";
import { serve } from "std/http/server";

// Same UUID pattern request-shape.ts already pins deviceId to
// (P3c gate round 2, item 7's own fix — "validate deviceId as a UUID").
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

function isPushTokenRequest(v: unknown): v is PushTokenRequest {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  if (typeof o.deviceId !== "string" || !UUID_RE.test(o.deviceId)) return false;
  if (typeof o.expoToken !== "string" || o.expoToken.length === 0) return false;
  if (o.platform !== undefined && o.platform !== "ios" && o.platform !== "android") return false;
  return true;
}

// `[inference]` — no plan-stated number. A device typically registers a
// push token once per app launch/reinstall, not in a tight loop; this
// bounds abuse while comfortably covering that real usage shape.
const RATE_LIMIT_PER_USER_HOUR = 30;

serve((req) =>
  handleRequest(async () => {
    if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");

    const actor = await getActorFromRequest(req);
    if (!actor) return Errors.unauthorized().toResponse();

    const body = await readJsonBody(req);
    if (!isPushTokenRequest(body)) {
      throw Errors.badRequest('body must be {"deviceId": string (UUID), "expoToken": string, "platform"?: "ios" | "android"}');
    }

    // ⛔ Same ordering every other write endpoint in this round already
    // uses (P3c gate round 4, blocking HIGH): hit BEFORE withOwnership
    // opens.
    const rateLimit = await hitRateLimitForActor(actor, "me-push-token:user", 3_600, RATE_LIMIT_PER_USER_HOUR);
    if (!rateLimit.ok) return Errors.tooManyRequests("me-push-token rate limit exceeded", rateLimit.retryAfterSeconds).toResponse();

    const result = await withOwnership(actor, (repo) => handlePushTokenRequest(body, repo));
    return okResponse(200, result);
  }),
);
