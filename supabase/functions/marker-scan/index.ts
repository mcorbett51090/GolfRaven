// supabase/functions/marker-scan/index.ts
//
// POST /v1/marker-scan (build plan §3.3 "Course QR (O5), the reverse direction", §4.6(q), §7.6 "Offline marker purchase (G2-03)", §9.2; P5.1a S2a). Thin entrypoint over
// _shared/course-qr/scan-handler.ts. Actor-scoped: the buyer is the verified caller, never a client-sent id. The request is a SCAN (a rotating token, or the printed QR and today's
// PIN, with a challenge-bound presence fix) or a CO-SIGNAL (only the fix, completing the player's own pending purchase): see _shared/course-qr/request-shape.ts.
//
// ORDER (the same one every write endpoint uses, P3c gate round 4): the strict body parse, then the per-user daily limit via `hitRateLimitForActor` BEFORE `withOwnership` opens (a
// hit from inside the transaction would hold a second pooled connection), then the handler inside ONE `withOwnership` transaction. The handler returns a `refused` outcome for the
// two refusals that must COMMIT (a wrong PIN counts; a forged QR writes a fraud_signal); every other refusal is thrown, which rolls the transaction back (so the check-in token the
// request consumed is not spent by a refused scan).
//
// Verification only on the attestation side: this function consumes the check-in token `checkin-token` already graded (App Attest / Play Integrity verification is checkin-token's); it
// never imports a rewards module. Nothing here reads the environment or a key: the Ed25519 PUBLIC keys come from the database (app.course_qr_key), the PIN pepper never leaves it.

import { getActorFromRequest, hitRateLimitForActor, withOwnership } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, readJsonBody, Errors } from "../_shared/http.ts";
import { handleMarkerScan } from "../_shared/course-qr/scan-handler.ts";
import { parseMarkerScanBody } from "../_shared/course-qr/request-shape.ts";
import { MARKER_SCAN_BUCKET, MARKER_SCAN_PER_USER_DAY, MARKER_SCAN_WINDOW_SECONDS } from "../_shared/course-qr/params.ts";
import { serve } from "std/http/server";

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.slice().buffer));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

serve((req) =>
  handleRequest(async () => {
    if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");

    const actor = await getActorFromRequest(req);
    if (!actor) return Errors.unauthorized().toResponse();

    // Strict: unknown keys are refused at the top level, inside `qr` and inside `fix`.
    const parsed = parseMarkerScanBody(await readJsonBody(req));
    if (!parsed.ok) throw Errors.badRequest("invalid marker-scan request", { issues: parsed.issues });

    // "20 scans/user/day" (plan §4.7.8). Every request counts, a refused or replayed one included.
    const limit = await hitRateLimitForActor(actor, MARKER_SCAN_BUCKET, MARKER_SCAN_WINDOW_SECONDS, MARKER_SCAN_PER_USER_DAY);
    if (!limit.ok) return Errors.tooManyRequests("marker-scan rate limit exceeded", limit.retryAfterSeconds).toResponse();

    const outcome = await withOwnership(actor, (repo) => handleMarkerScan(parsed.value, repo, { sha256Hex }));
    // a committed refusal (a counted wrong PIN, a recorded forgery): answered AFTER the transaction committed
    if (outcome.kind === "refused") return outcome.error.toResponse();
    return okResponse(outcome.status, outcome.body, { "cache-control": "no-store" });
  }),
);
