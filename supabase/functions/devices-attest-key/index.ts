// supabase/functions/devices-attest-key/index.ts
//
// POST /v1/devices/attest-key — App Attest KEY REGISTRATION (build plan §7.5; follow-up F2 of the P3f
// section of docs/security/p3-money-path-requirements.md). Thin Deno entrypoint — every decision lives in
// supabase/functions/_shared/rewards/ (pure, unit-tested): this file only wires the HTTP request into it:
// verify the JWT, validate the body, apply the two rate limits BEFORE any transaction, then run the handler
// inside withOwnership.
//
// ⚠ Verification is built but NOT exercised against a real attestation from an iPhone (no device, Apple account
// or network route in the build environment; see the security doc). With no Apple configuration the verifier is
// `null` and the endpoint answers 503 before reading or writing anything; nothing is ever registered unverified.
// The verifier's trust anchor is Apple's App Attestation Root CA PINNED IN CODE — privileged.ts's
// `loadAttestKeyVerifierConfig` is the only place that sets it, and no variable or request field can change it.

import { getActorFromRequest, hitRateLimitForActor, loadAttestKeyVerifierConfig, withOwnership } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, readJsonBody, Errors } from "../_shared/http.ts";
import { createAttestationVerifier } from "../_shared/rewards/app-attest-registration.ts";
import { enforceAttestKeyRateLimits, handleAttestKey } from "../_shared/rewards/attest-key-handler.ts";
import { parseAttestKeyBody } from "../_shared/rewards/attest-key-request.ts";
import { serve } from "std/http/server";

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.slice().buffer));
}

// Built once per cold start from the environment (privileged.ts reads it — this file may not touch the
// environment itself). `null` = unconfigured: every request fails closed with 503.
const config = loadAttestKeyVerifierConfig();
const verifier = config ? createAttestationVerifier(config, { sha256 }) : null;

serve((req) =>
  handleRequest(async () => {
    if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");

    const actor = await getActorFromRequest(req);
    if (!actor) return Errors.unauthorized().toResponse();

    // Fail closed BEFORE the rate limits (they write rows) and the body: an unconfigured deployment can do nothing.
    if (!verifier) return errorResponse(503, "attestation_not_configured", "App Attest key registration is not available on this deployment");

    const parsed = parseAttestKeyBody(await readJsonBody(req));
    if (!parsed.ok) throw Errors.badRequest("invalid attest-key request", parsed.issues);
    const body = parsed.value;

    // ⛔ P3c gate round 4: rate-limit hits happen BEFORE withOwnership opens, never from inside the transaction.
    const limit = await enforceAttestKeyRateLimits((bucketKey, windowSeconds, max) => hitRateLimitForActor(actor, bucketKey, windowSeconds, max), body.deviceId);
    if (!limit.ok) return Errors.tooManyRequests("devices-attest-key rate limit exceeded", limit.retryAfterSeconds).toResponse();

    // A verification failure is RETURNED (not thrown) so the transaction commits with the challenge consumed: a
    // challenge is spent by a failed attempt. See attest-key-handler.ts.
    const outcome = await withOwnership(actor, (repo) => handleAttestKey(body, repo, { verifier, sha256 }));
    return outcome.ok ? okResponse(outcome.status, outcome.body) : errorResponse(outcome.status, outcome.code, outcome.message);
  }),
);
