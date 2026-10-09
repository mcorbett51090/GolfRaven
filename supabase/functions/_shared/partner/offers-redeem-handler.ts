// supabase/functions/_shared/partner/offers-redeem-handler.ts
//
// The `partner-offers-redeem` handler (docs/security/partner-auth-design.md 4.5, 6.3, 12, 32; P5.1b, the Edge half of migration 0060): issued-offer queue and staff_scan redeem.
// Pure and unit-testable like entitlements-handler.ts: the database (`PartnerDb`) is a PORT (`ports.ts`); this file reads no environment, opens no connection, imports no library and writes no log line (PA-11).
//
// ROUTES (relative to the function; `GET queue` is `/partner-offers-redeem/queue`):
//   GET  queue    ?facilityId=                                              class A0 (staff or manager of the facility): issued offer codes at the facility, by player handle
//   POST redeem   { facilityId, offerCodeId, method, credential }           class A1: method staff_scan (credential = the player's check-in token jti). offline_code is refused here and in the database.
// Every route is a session route. Scope, class, self-redeem, replay, budget consume, the attestation and the cold-start cap are the DATABASE's.
//
// THE ORDER, for every request: (1) the Origin check; (2) OPTIONS with no port touched; (3) route and method; (4) the bearer; (5) exact JSON media type and strict body (POST) or strict query (GET);
// (6) the per-member bucket; (7) the work.
//
// STATUSES (every one commits): ok 201; not_found and no_facility 404; not_issued, expired, wrong_facility, token_invalid, wrong_player, budget_short 422; replayed 409; cold_start_cap 429.
// token_invalid and wrong_player are ONE answer on the wire (code token_invalid). A missing scope or PIN grant is 42501 and a 403; a self-redeem or a malformed argument is 22023 and a 422.

import { Errors } from "../http.ts";
import { decideOrigin, preflightResponse } from "./cors.ts";
import { bearerHash, type Decision, mapPartnerError, matchRoute, methodRefusal, rateLimited, routeOfFunction, type RouteSpec } from "./handler-kit.ts";
import { partnerError, partnerOk, readPartnerJsonBody, runPartnerHandler, unauthenticated } from "./http.ts";
import { parseOfferRedeemBody, parseOffersQueueQuery } from "./offers-redeem-shape.ts";
import type { OfferQueueRow, OfferRedeemResult, PartnerDb } from "./ports.ts";

export const PARTNER_OFFERS_REDEEM_FUNCTION = "partner-offers-redeem";
/** A per-member bucket over every queue read and redeem. `[inference]`: 240 an hour matches partner-entitlements. */
export const OFFERS_REDEEM_PER_MEMBER_PER_HOUR = 240;
export const OFFERS_REDEEM_BUCKET = "partner-offers-redeem:member";

export interface PartnerOffersRedeemDeps {
  readonly db: PartnerDb;
  readonly allowedOrigin: string | null;
  readonly timeoutMs?: number;
}

const ROUTES: readonly RouteSpec[] = [
  { name: "queue", path: "queue", methods: ["GET"], session: true },
  { name: "redeem", path: "redeem", methods: ["POST"], session: true },
];

export async function handlePartnerOffersRedeemRequest(req: Request, deps: PartnerOffersRedeemDeps): Promise<Response> {
  const decision = decideOrigin(req.headers, deps.allowedOrigin);
  if (decision.kind === "refused") return partnerError({ kind: "none" }, 403, "forbidden", "origin not allowed");
  if (req.method === "OPTIONS") return preflightResponse(decision);

  return await runPartnerHandler(
    decision,
    async () => {
      try {
        const matched = matchRoute(ROUTES, routeOfFunction(req.url, PARTNER_OFFERS_REDEEM_FUNCTION));
        if (matched === null) return partnerError(decision, 404, "not_found", "not found");
        const refusal = methodRefusal(decision, matched, req.method);
        if (refusal !== null) return refusal;
        const tokenHash = await bearerHash(req.headers);
        if (tokenHash === null) return unauthenticated(decision);

        switch (matched.spec.name) {
          case "queue":
            return await handleQueue(req, deps, decision, tokenHash);
          case "redeem":
            return await handleRedeem(req, deps, decision, tokenHash);
          default:
            return partnerError(decision, 404, "not_found", "not found");
        }
      } catch (err) {
        return mapPartnerError(decision, err);
      }
    },
    deps.timeoutMs,
  );
}

async function memberLimit(deps: PartnerOffersRedeemDeps, decision: Decision, tokenHash: string): Promise<Response | null> {
  const limit = await deps.db.hitRateLimit(tokenHash, OFFERS_REDEEM_BUCKET, 3600, OFFERS_REDEEM_PER_MEMBER_PER_HOUR);
  return limit.ok ? null : rateLimited(decision, "too many requests", limit.retryAfterSeconds);
}

function queueRowBody(r: OfferQueueRow): Record<string, unknown> {
  return {
    offerCodeId: r.offerCodeId,
    offerId: r.offerId,
    playerHandle: r.playerHandle,
    expiresAt: r.expiresAt,
    faceValue: r.faceValue,
  };
}

function redeemResponse(decision: Decision, r: OfferRedeemResult): Response {
  switch (r.status) {
    case "ok":
      return partnerOk(decision, 201, { attestationId: r.attestationId });
    case "not_found":
    case "no_facility":
      return partnerError(decision, 404, "not_found", "not found");
    case "not_issued":
      return partnerError(decision, 422, "not_issued", "this offer code cannot be redeemed");
    case "expired":
      return partnerError(decision, 422, "expired", "this offer code has expired");
    case "wrong_facility":
      return partnerError(decision, 422, "wrong_facility", "this offer code is owed at another facility");
    case "token_invalid":
    case "wrong_player":
      return partnerError(decision, 422, "token_invalid", "this token cannot be used here");
    case "replayed":
      return partnerError(decision, 409, "replayed", "this token has already been used");
    case "budget_short":
      return partnerError(decision, 422, "budget_short", "the offer has no remaining budget");
    case "cold_start_cap":
      return rateLimited(decision, "a new member's daily limit has been reached", 3600);
    default:
      return partnerError(decision, 422, "invalid_request", "the request cannot be applied");
  }
}

async function handleQueue(req: Request, deps: PartnerOffersRedeemDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseOffersQueueQuery(req.url);
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const rows = await deps.db.withOffersRedeem(tokenHash, (s) => s.offersQueue(parsed.value.facilityId));
  return partnerOk(decision, 200, { offerCodes: rows.map(queueRowBody) });
}

async function handleRedeem(req: Request, deps: PartnerOffersRedeemDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseOfferRedeemBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const { facilityId, offerCodeId, method, credential } = parsed.value;
  const result = await deps.db.withOffersRedeem(tokenHash, (s) => s.redeemOffer(facilityId, offerCodeId, method, credential));
  return redeemResponse(decision, result);
}
