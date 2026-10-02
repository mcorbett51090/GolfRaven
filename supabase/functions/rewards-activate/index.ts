// supabase/functions/rewards-activate/index.ts
//
// POST /v1/rewards/{id}/activate (build plan §4.7.1a inventory:
// "rewards-activate"; §7.5; A2-08). Thin Deno entrypoint — every decision
// lives in supabase/functions/_shared/rewards/ (pure, unit-tested): this file
// only wires the HTTP request into it: verify the JWT, name the reward from the
// URL, validate the body, apply the two rate limits BEFORE any transaction,
// then run the handler inside withOwnership.
//
// ⚠ Vendor verification is built but NOT exercised against Apple or Google
// (no credentials, no network route in the build environment — see
// docs/security/p3-money-path-requirements.md, "P3f"). With no vendor
// configuration the ports below are `null` and any request carrying that
// platform's attestation material fails closed with a 503; nothing is ever
// treated as clean.

import { getActorFromRequest, hitRateLimitForActor, loadRewardsAttestationConfig, withOwnership } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, readJsonBody, Errors } from "../_shared/http.ts";
import { enforceActivationRateLimits, handleActivation } from "../_shared/rewards/activate-handler.ts";
import { extractRewardId, parseActivationBody } from "../_shared/rewards/request-shape.ts";
import { verifyP256WebCrypto } from "../_shared/rewards/app-attest.ts";
import { buildAttestationPorts } from "../_shared/rewards/production-ports.ts";
import { platformVendorHttp } from "../_shared/rewards/vendor-http.ts";
import { serve } from "std/http/server";

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.slice().buffer));
}

// Built once per cold start from the environment (privileged.ts reads it — this
// file may not touch the environment itself). `null` platforms fail closed.
const ports = buildAttestationPorts(loadRewardsAttestationConfig(), platformVendorHttp(), { sha256, verifyP256: verifyP256WebCrypto });

serve((req) =>
  handleRequest(async () => {
    if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");

    const actor = await getActorFromRequest(req);
    if (!actor) return Errors.unauthorized().toResponse();

    // The reward id is named ONLY by the URL. An unparseable path is the same
    // 404 as an id that is not the caller's own.
    const rewardId = extractRewardId(new URL(req.url).pathname);
    if (!rewardId) return Errors.notFound("no such reward").toResponse();

    const parsed = parseActivationBody(await readJsonBody(req));
    if (!parsed.ok) throw Errors.badRequest("invalid activation request", parsed.issues);
    const body = parsed.value;

    // ⛔ P3c gate round 4: rate-limit hits happen BEFORE withOwnership opens,
    // never from inside the transaction (privileged.ts#hitRateLimitForActor's
    // own doc). 10/user/h and 20/device/day (§4.7 item 8).
    const limit = await enforceActivationRateLimits((bucketKey, windowSeconds, max) => hitRateLimitForActor(actor, bucketKey, windowSeconds, max), body.deviceId);
    if (!limit.ok) return Errors.tooManyRequests("rewards-activate rate limit exceeded", limit.retryAfterSeconds).toResponse();

    const result = await withOwnership(actor, (repo) => handleActivation(rewardId, body, repo, { ports, sha256 }));
    return okResponse(200, result);
  }),
);
