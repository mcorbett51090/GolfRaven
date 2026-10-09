// supabase/functions/_shared/partner/entitlements-handler.ts
//
// The `partner-entitlements` handler (docs/security/partner-auth-design.md 4.5, 6.3, 12, 12.1, 28; slice S5, the Edge half of migration 0058): collect queue, hand-over token mint, redeem, voucher. Pure and
// unit-testable like attest-handler.ts: the database (`PartnerDb`) is a PORT (`ports.ts`); this file reads no environment, opens no connection, imports no library and writes no log line (PA-11).
//
// ROUTES (relative to the function; `GET collect` is `/partner-entitlements/collect`):
//   GET  collect          ?facilityId=                                          class A0 (staff or manager of the facility): the redeemable and owed-here special-marker entitlements, by player handle
//   POST handover/mint    { facilityId, entitlementId }                         class A1: the EDGE generates 32 random bytes (`gr_ho_...`), passes the database ONLY the SHA-256, and returns the plaintext
//                                                                               to the caller ONCE (201). A 15 minute single-use token; it is never stored, logged or returned again.
//   POST redeem           { facilityId, entitlementId, method, credential }     class A1: method staff_scan (credential = the player's check-in token jti) or hand_over_token (credential = the plaintext
//                                                                               the player was shown; the Edge hashes it, so the database never sees the plaintext). offline_code is not accepted.
//   POST voucher          { facilityId, entitlementId }                         class A1: redeemable becomes owed at this facility (the out-of-stock path)
// Every route is a session route. Scope, class, the self-redeem rule, the replay rule, the stock lock (the race for the last unit), the attestation and the cold-start cap are the DATABASE's.
//
// THE ORDER, for every request: (1) the Origin check; (2) OPTIONS with no port touched; (3) route and method; (4) the bearer; (5) exact JSON media type and strict body (POST) or strict query (GET);
// (6) the per-member bucket; (7) the work.
//
// STATUSES (every one commits, so a refusal is a returned value and not a rollback): mint ok 201; redeem ok 201; voucher ok 200; not_found and no_facility 404; not_redeemable, wrong_facility, token_invalid,
// wrong_player, no_stock_row, no_programme and token_exists 422; replayed 409; out_of_stock 409 (a state conflict: nothing changed, the caller vouchers instead); cold_start_cap 429. token_invalid and wrong_player
// are ONE answer on the wire (code token_invalid), as in partner-attest, so nothing says which check failed. A missing scope or PIN grant is 42501 and a 403; a self-redeem or a malformed argument is 22023 and a 422.

import { Errors } from "../http.ts";
import { decideOrigin, preflightResponse } from "./cors.ts";
import { type EntitlementRef, parseCollectQuery, parseEntitlementRefBody, parseRedeemBody } from "./entitlements-shape.ts";
import { bearerHash, type Decision, mapPartnerError, matchRoute, methodRefusal, rateLimited, routeOfFunction, type RouteSpec } from "./handler-kit.ts";
import { partnerError, partnerOk, readPartnerJsonBody, runPartnerHandler, unauthenticated } from "./http.ts";
import type { EntitlementQueueRow, HandoverMintResult, PartnerDb, RedeemResult, VoucherResult } from "./ports.ts";
import { newPartnerHandoverToken, sha256Hex } from "./token.ts";

export const PARTNER_ENTITLEMENTS_FUNCTION = "partner-entitlements";
/** A per-member bucket over every collect read, mint, redeem and voucher. `[inference]`: 240 an hour is about one a minute across a long shift. */
export const ENTITLEMENTS_PER_MEMBER_PER_HOUR = 240;
export const ENTITLEMENTS_BUCKET = "partner-entitlements:member";

export interface PartnerEntitlementsDeps {
  readonly db: PartnerDb;
  readonly allowedOrigin: string | null;
  readonly timeoutMs?: number;
}

const ROUTES: readonly RouteSpec[] = [
  { name: "collect", path: "collect", methods: ["GET"], session: true },
  { name: "handover-mint", path: "handover/mint", methods: ["POST"], session: true },
  { name: "redeem", path: "redeem", methods: ["POST"], session: true },
  { name: "voucher", path: "voucher", methods: ["POST"], session: true },
];

export async function handlePartnerEntitlementsRequest(req: Request, deps: PartnerEntitlementsDeps): Promise<Response> {
  const decision = decideOrigin(req.headers, deps.allowedOrigin);
  if (decision.kind === "refused") return partnerError({ kind: "none" }, 403, "forbidden", "origin not allowed");
  if (req.method === "OPTIONS") return preflightResponse(decision);

  return await runPartnerHandler(
    decision,
    async () => {
      try {
        const matched = matchRoute(ROUTES, routeOfFunction(req.url, PARTNER_ENTITLEMENTS_FUNCTION));
        if (matched === null) return partnerError(decision, 404, "not_found", "not found");
        const refusal = methodRefusal(decision, matched, req.method);
        if (refusal !== null) return refusal;
        const tokenHash = await bearerHash(req.headers);
        if (tokenHash === null) return unauthenticated(decision);

        switch (matched.spec.name) {
          case "collect":
            return await handleCollect(req, deps, decision, tokenHash);
          case "handover-mint":
            return await handleMint(req, deps, decision, tokenHash);
          case "redeem":
            return await handleRedeem(req, deps, decision, tokenHash);
          case "voucher":
            return await handleVoucher(req, deps, decision, tokenHash);
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

async function memberLimit(deps: PartnerEntitlementsDeps, decision: Decision, tokenHash: string): Promise<Response | null> {
  const limit = await deps.db.hitRateLimit(tokenHash, ENTITLEMENTS_BUCKET, 3600, ENTITLEMENTS_PER_MEMBER_PER_HOUR);
  return limit.ok ? null : rateLimited(decision, "too many requests", limit.retryAfterSeconds);
}

function queueRowBody(r: EntitlementQueueRow): Record<string, unknown> {
  return { entitlementId: r.entitlementId, trailId: r.trailId, state: r.state, playerHandle: r.playerHandle, activatedAt: r.activatedAt, voucherIssuedAt: r.voucherIssuedAt };
}

/** Refusals the three writes share: the entitlement or facility is not there (404), it cannot be acted on (422). */
function refusalOf(decision: Decision, status: string): Response | null {
  switch (status) {
    case "not_found":
    case "no_facility":
      return partnerError(decision, 404, "not_found", "not found");
    case "not_redeemable":
      return partnerError(decision, 422, "not_redeemable", "this entitlement cannot be handed over");
    case "wrong_facility":
      return partnerError(decision, 422, "wrong_facility", "this entitlement is owed at another facility");
    case "no_stock_row":
      return partnerError(decision, 422, "no_stock_row", "this facility holds no stock row for that trail");
    default:
      return null;
  }
}

function mintResponse(decision: Decision, r: HandoverMintResult, token: string): Response {
  if (r.status === "ok") return partnerOk(decision, 201, { token, expiresAt: r.expiresAt });
  if (r.status === "token_exists") return partnerError(decision, 422, "token_exists", "the token could not be issued: try again");
  return refusalOf(decision, r.status) ?? partnerError(decision, 422, "invalid_request", "the request cannot be applied");
}

function redeemResponse(decision: Decision, r: RedeemResult): Response {
  switch (r.status) {
    case "ok":
      return partnerOk(decision, 201, { attestationId: r.attestationId, movement: r.movement, availability: r.availability });
    case "replayed":
      return partnerError(decision, 409, "replayed", "this token has already been used");
    case "out_of_stock":
      return partnerError(decision, 409, "out_of_stock", "the facility has none left: issue a voucher instead");
    case "token_invalid":
    case "wrong_player":
      return partnerError(decision, 422, "token_invalid", "this token cannot be used here");
    case "no_programme":
      return partnerError(decision, 422, "no_programme", "this facility has no marker programme");
    case "cold_start_cap":
      return rateLimited(decision, "a new member's daily limit has been reached", 3600);
    default:
      return refusalOf(decision, r.status) ?? partnerError(decision, 422, "invalid_request", "the request cannot be applied");
  }
}

function voucherResponse(decision: Decision, r: VoucherResult): Response {
  if (r.status === "ok") return partnerOk(decision, 200, { voucherIssuedAt: r.voucherIssuedAt });
  return refusalOf(decision, r.status) ?? partnerError(decision, 422, "invalid_request", "the request cannot be applied");
}

async function handleCollect(req: Request, deps: PartnerEntitlementsDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseCollectQuery(req.url);
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const rows = await deps.db.withEntitlements(tokenHash, (s) => s.collectQueue(parsed.value.facilityId));
  return partnerOk(decision, 200, { entitlements: rows.map(queueRowBody) });
}

async function readRef(req: Request): Promise<EntitlementRef> {
  const parsed = parseEntitlementRefBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  return parsed.value;
}

async function handleMint(req: Request, deps: PartnerEntitlementsDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const { facilityId, entitlementId } = await readRef(req);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  // generated here, after every refusal that needs no database: the plaintext leaves this function only in a 201 body, and only its hash is handed to the port
  const minted = await newPartnerHandoverToken();
  const result = await deps.db.withEntitlements(tokenHash, (s) => s.mintHandover(facilityId, entitlementId, minted.hash));
  return mintResponse(decision, result, minted.token);
}

async function handleRedeem(req: Request, deps: PartnerEntitlementsDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseRedeemBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const { facilityId, entitlementId, method, credential } = parsed.value;
  const dbCredential = method === "hand_over_token" ? await sha256Hex(credential) : credential;
  const result = await deps.db.withEntitlements(tokenHash, (s) => s.redeem(facilityId, entitlementId, method, dbCredential));
  return redeemResponse(decision, result);
}

async function handleVoucher(req: Request, deps: PartnerEntitlementsDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const { facilityId, entitlementId } = await readRef(req);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const result = await deps.db.withEntitlements(tokenHash, (s) => s.voucher(facilityId, entitlementId));
  return voucherResponse(decision, result);
}
