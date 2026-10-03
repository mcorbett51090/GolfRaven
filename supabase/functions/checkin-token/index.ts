// supabase/functions/checkin-token/index.ts
//
// The `checkin-token` Edge Function (build plan §4.7.1a: "moved out
// of the RPC allowlist because it must verify attestation, sign, and
// record a jti"; §4.5 G3-08). Thin entrypoint: verify the JWT, validate the
// body strictly, apply the per-user rate limit BEFORE any transaction, then run
// the handler inside withOwnership. Every decision — including how a presented
// App Attest assertion / Play Integrity token is graded — lives in
// _shared/checkin/token-handler.ts (pure, unit-tested).
//
// ⚠ Vendor verification is built but NOT exercised against Apple or Google (no
// credentials, no network route in the build environment — see
// docs/security/p3-money-path-requirements.md). With no configuration for a
// platform its port below is `null`, and a request carrying THAT platform's
// attestation fails closed with a 503; a request carrying no attestation is
// graded exactly as before (G3-08 "no token"). Nothing is ever treated as clean,
// and no vendor error is ever graded `failed`.
//
// Verification only: this function wires _shared/rewards/verification-ports.ts,
// never production-ports.ts (which carries the DeviceCheck persistent-bit
// adapter). The earning side reads and sets no persistent bit (§7.5, A2-08;
// rewards-isolation.test.ts).

import { getActorFromRequest, hitRateLimitForActor, loadCheckinAttestationConfig, withOwnership } from "../_shared/privileged.ts";
import { errorResponse, handleRequest, okResponse, readJsonBody, Errors } from "../_shared/http.ts";
import { handleTokenRequest, RATE_LIMIT_PER_USER_HOUR } from "../_shared/checkin/token-handler.ts";
import { parseTokenBody } from "../_shared/checkin/token-request-shape.ts";
import { verifyP256WebCrypto } from "../_shared/rewards/app-attest.ts";
import { buildVerificationPorts } from "../_shared/rewards/verification-ports.ts";
import { platformVendorHttp } from "../_shared/rewards/vendor-http.ts";
import { serve } from "std/http/server";

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.slice().buffer));
}

async function digestHex(bytes: Uint8Array): Promise<string> {
  return [...(await sha256(bytes))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Built once per cold start from the environment (privileged.ts reads it — this
// file may not touch the environment itself). A `null` platform fails closed.
const ports = buildVerificationPorts(loadCheckinAttestationConfig(), platformVendorHttp(), { sha256, verifyP256: verifyP256WebCrypto });

serve((req) => handleRequest(async () => {
  if (req.method !== "POST") return errorResponse(405, "method_not_allowed", "POST only");

  const actor = await getActorFromRequest(req);
  if (!actor) return Errors.unauthorized().toResponse();

  // Strict: unknown keys are refused, at the top level and inside the attestation block.
  const parsed = parseTokenBody(await readJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid checkin-token request", parsed.issues);
  const body = parsed.value;

  // ⛔ P3c gate round 4, blocking HIGH ("5 concurrent requests deadlock
  // the pool"): hit BEFORE withOwnership opens — see privileged.ts#
  // hitRateLimitForActor's own doc.
  const rateLimit = await hitRateLimitForActor(actor, "checkin-token:user", 3600, RATE_LIMIT_PER_USER_HOUR);
  if (!rateLimit.ok) return Errors.tooManyRequests("checkin-token rate limit exceeded", rateLimit.retryAfterSeconds).toResponse();

  const token = await withOwnership(actor, (repo) => handleTokenRequest(body, repo, digestHex, { userId: actor.uid, ports, sha256 }));
  return okResponse(201, token);
}));
