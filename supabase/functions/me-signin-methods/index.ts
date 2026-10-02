// supabase/functions/me-signin-methods/index.ts
//
// GET  /v1/me/signin-methods   list the caller's sign-in methods
// POST /v1/me/signin-methods   { action: "link" | "unlink", ... }   (build plan §4.7.1a inventory: "me-signin-methods";
//                              §3.4 account-linking rules; O12). Thin entrypoint: the rules live in
//                              _shared/signin/methods-handler.ts (pure, unit-tested), the wire shape in request-shape.ts.
//
// ⚠ Apple verification, the token exchange and the OTP proof are built but NOT exercised against Apple or a real Supabase Auth (no
// credentials and no route in the build environment): with the four GR_APPLE_* values unset, `apple` below is null and every Apple
// operation answers 503 `provider_not_configured`; nothing is ever treated as verified.

import { getActorFromRequest, hitRateLimitForActor, loadAppleSiwaConfig, signinOtpFailuresFor, signinRevocationDb, supabaseEmailOtpVerifier, withOwnership } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, readJsonBody, Errors } from "../_shared/http.ts";
import { buildSigninPorts, platformFetch } from "../_shared/signin/production.ts";
import { handleLinkProvider, handleListMethods, handleUnlinkProvider, type SigninDeps } from "../_shared/signin/methods-handler.ts";
import { parseSigninBody } from "../_shared/signin/request-shape.ts";
import { SIGNIN_LINKING_PER_USER_PER_HOUR } from "../_shared/signin/types.ts";
import type { Actor } from "../_shared/types.ts";
import { serve } from "std/http/server";

// Built once per cold start from the environment (privileged.ts reads it — this file may not touch the environment itself).
const ports = buildSigninPorts(loadAppleSiwaConfig(), { fetch: platformFetch, nowMs: () => Date.now() });
const log = (event: Record<string, unknown>) => console.log(JSON.stringify(event));

function depsFor(actor: Actor): SigninDeps {
  return {
    withRepo: (op) => withOwnership(actor, (repo) => op(repo.signin)),
    otpFailures: signinOtpFailuresFor(actor),
    apple: ports.apple,
    emailOtp: supabaseEmailOtpVerifier,
    revocation: { db: signinRevocationDb, apple: ports.apple, google: ports.google, log },
    log,
  };
}

serve((req) =>
  handleRequest(async () => {
    if (req.method !== "GET" && req.method !== "POST") return errorResponse(405, "method_not_allowed", "GET or POST only");

    const actor = await getActorFromRequest(req);
    if (!actor) return Errors.unauthorized().toResponse();
    const deps = depsFor(actor);

    if (req.method === "GET") return okResponse(200, await handleListMethods(deps));

    const parsed = parseSigninBody(await readJsonBody(req));
    if (!parsed.ok) throw Errors.badRequest("invalid sign-in methods request", parsed.issues);
    const body = parsed.value;

    // ⛔ P3c gate round 4: the rate-limit hit happens BEFORE withOwnership opens, never from inside a transaction
    // (privileged.ts#hitRateLimitForActor's own doc). §4.7 item 8: sign-in linking is 10/user/h. (The second limit, 5 FAILED OTP
    // proofs per target email per hour, is counted inside the handler, on its own committed transaction.)
    const limit = await hitRateLimitForActor(actor, "me-signin-methods:user", 3_600, SIGNIN_LINKING_PER_USER_PER_HOUR);
    if (!limit.ok) return Errors.tooManyRequests("me-signin-methods rate limit exceeded", limit.retryAfterSeconds).toResponse();

    if (body.action === "link") return okResponse(200, await handleLinkProvider(body, actor.uid, deps));
    return okResponse(200, await handleUnlinkProvider(body, deps));
  }),
);
