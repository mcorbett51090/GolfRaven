// supabase/functions/me-delete/index.ts
//
// DELETE /v1/me (build plan §4.7.1a inventory: "me-delete"; AT 6). Thin
// entrypoint over _shared/me/delete-handler.ts — see that file's own
// header for what private.delete_my_data already covers and what this
// round adds (the provider-revocation seam).

import { deleteAuthUser, getActorFromRequest, hitRateLimitForActor, withOwnership } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, Errors } from "../_shared/http.ts";
import { handleMeDelete } from "../_shared/me/delete-handler.ts";
import { serve } from "std/http/server";

// `[inference]` — no plan-stated number for this endpoint specifically
// (§4.7 item 8's table lists evidence/redemption/attest/challenge/
// receipt/activation/queued-catalog/hand-over/sign-in-linking/course-QR
// limits, but not me-delete or me-export). Account deletion is a
// one-shot, irreversible-in-effect action (a "retry after partial
// failure" is the ONLY legitimate reason to call this more than once in
// a short window per this round's own idempotency design — see
// delete-handler.ts's own doc) — a low daily cap is generous headroom
// for that retry case while still bounding abuse (a bug or a malicious
// caller hammering this endpoint against someone else's still-valid
// session).
const RATE_LIMIT_PER_USER_DAY = 5;

serve((req) =>
  handleRequest(async () => {
    if (req.method !== "DELETE") return errorResponse(405, "method_not_allowed", "DELETE only");

    const actor = await getActorFromRequest(req);
    if (!actor) return Errors.unauthorized().toResponse();

    // ⛔ Same ordering every other write endpoint in this round already
    // uses (P3c gate round 4, blocking HIGH — privileged.ts#
    // hitRateLimitForActor's own doc): hit BEFORE withOwnership opens.
    const rateLimit = await hitRateLimitForActor(actor, "me-delete:user", 86_400, RATE_LIMIT_PER_USER_DAY);
    if (!rateLimit.ok) return Errors.tooManyRequests("me-delete rate limit exceeded", rateLimit.retryAfterSeconds).toResponse();

    const result = await withOwnership(actor, (repo) => handleMeDelete(repo));

    // Auth-user deletion (task instruction: "Delete the Supabase Auth
    // user: use the Auth admin API from the allow-listed privileged
    // module only") runs AFTER the DB transaction above has committed —
    // it is an HTTP call to Supabase Auth, not a Postgres statement, so
    // it cannot participate in that transaction. See deleteAuthUser's
    // own doc (privileged.ts) for why this ordering is deliberate (the
    // privacy-bearing DB rows are gone even if THIS call has to be
    // retried) and for its own idempotency on a retry.
    const authResult = await deleteAuthUser(actor.uid);

    return okResponse(200, {
      userId: result.userId,
      deletedAt: result.deletedAt,
      authUserDeleted: authResult.deleted,
      authUserAlreadyGone: authResult.alreadyGone,
      signinProvidersRevoked: result.signinProvidersRevoked,
      connectorsRevoked: result.connectorsRevoked,
    });
  }),
);
