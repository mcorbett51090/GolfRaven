// supabase/functions/_shared/partner/offers-handler.ts
//
// The `offers-admin` handler (docs/security/partner-auth-design.md 4.5, 6.3, 12, 30; slice S6, the Edge half of migration 0059). Pure and unit-testable like stock-handler.ts: the database
// (`PartnerDb`) is a PORT (`ports.ts`); this file reads no environment, opens no connection and writes no log line (PA-11). Eligibility is validated with `validateOfferEligibility` (AT(14)) before any
// database write.
//
// ROUTES (relative to the function; `GET offers` is `/offers-admin/offers`):
//   GET  offers           ?trailId=     class A0: full offer list
//   POST offers           { ... }       class A3: draft upsert (eligibility validated here first)
//   POST offers/approve   { id }        class A3: admin draft → live
//   POST offers/end       { id }        class A3: live → ended
// Every route is a session route. Scope, class, funder rules and the returned statuses are the DATABASE's (except eligibility, which is AT(14) here).
//
// THE ORDER, for every request: (1) the Origin check; (2) OPTIONS with no port touched; (3) route and method; (4) the bearer; (5) exact JSON media type and strict body (POST) or strict query (GET);
// (6) the per-member bucket; (7) eligibility (upsert only); (8) the work.
//
// STATUSES (every one commits): ok 200; not_found, not_draft, not_live and bad_funder 422; invalid eligibility 422; a missing scope is 42501 and a 403; a malformed argument the shape let through is 22023 and a 422.

import { Errors } from "../http.ts";
import { decideOrigin, preflightResponse } from "./cors.ts";
import { bearerHash, type Decision, mapPartnerError, matchRoute, methodRefusal, rateLimited, routeOfFunction, type RouteSpec } from "./handler-kit.ts";
import { partnerError, partnerOk, readPartnerJsonBody, runPartnerHandler, unauthenticated } from "./http.ts";
import { validateOfferEligibility } from "./offer-eligibility.ts";
import { parseOfferIdBody, parseOffersQuery, parseOfferUpsertBody } from "./offers-shape.ts";
import type { OfferAdminRow, OfferApproveStatus, OfferEndStatus, OfferUpsertResult, PartnerDb } from "./ports.ts";

export const PARTNER_OFFERS_FUNCTION = "offers-admin";
/** A per-member bucket over every offer read and write. `[inference]`: 240 an hour matches stock-admin. */
export const OFFERS_PER_MEMBER_PER_HOUR = 240;
export const OFFERS_BUCKET = "offers-admin:member";

export interface PartnerOffersAdminDeps {
  readonly db: PartnerDb;
  readonly allowedOrigin: string | null;
  readonly timeoutMs?: number;
}

const ROUTES: readonly RouteSpec[] = [
  // GET and POST share one path: matchRoute picks the first path match, then methodRefusal checks the method list.
  { name: "offers", path: "offers", methods: ["GET", "POST"], session: true },
  { name: "offers-approve", path: "offers/approve", methods: ["POST"], session: true },
  { name: "offers-end", path: "offers/end", methods: ["POST"], session: true },
];

export async function handlePartnerOffersAdminRequest(req: Request, deps: PartnerOffersAdminDeps): Promise<Response> {
  const decision = decideOrigin(req.headers, deps.allowedOrigin);
  if (decision.kind === "refused") return partnerError({ kind: "none" }, 403, "forbidden", "origin not allowed");
  if (req.method === "OPTIONS") return preflightResponse(decision);

  return await runPartnerHandler(
    decision,
    async () => {
      try {
        const matched = matchRoute(ROUTES, routeOfFunction(req.url, PARTNER_OFFERS_FUNCTION));
        if (matched === null) return partnerError(decision, 404, "not_found", "not found");
        const refusal = methodRefusal(decision, matched, req.method);
        if (refusal !== null) return refusal;
        const tokenHash = await bearerHash(req.headers);
        if (tokenHash === null) return unauthenticated(decision);

        switch (matched.spec.name) {
          case "offers":
            return req.method === "GET"
              ? await handleOffersList(req, deps, decision, tokenHash)
              : await handleOfferUpsert(req, deps, decision, tokenHash);
          case "offers-approve":
            return await handleOfferApprove(req, deps, decision, tokenHash);
          case "offers-end":
            return await handleOfferEnd(req, deps, decision, tokenHash);
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

async function memberLimit(deps: PartnerOffersAdminDeps, decision: Decision, tokenHash: string): Promise<Response | null> {
  const limit = await deps.db.hitRateLimit(tokenHash, OFFERS_BUCKET, 3600, OFFERS_PER_MEMBER_PER_HOUR);
  return limit.ok ? null : rateLimited(decision, "too many requests", limit.retryAfterSeconds);
}

function offerBody(r: OfferAdminRow): Record<string, unknown> {
  return {
    id: r.id,
    termsId: r.termsId,
    trailId: r.trailId,
    facilityId: r.facilityId,
    eligibility: r.eligibility,
    funder: r.funder,
    sponsorshipId: r.sponsorshipId,
    budgetCap: r.budgetCap,
    budgetUsed: r.budgetUsed,
    budgetReserved: r.budgetReserved,
    maxRedemptions: r.maxRedemptions,
    faceValue: r.faceValue,
    validFrom: r.validFrom,
    validTo: r.validTo,
    status: r.status,
  };
}

function upsertResponse(decision: Decision, r: OfferUpsertResult): Response {
  switch (r.status) {
    case "ok":
      return partnerOk(decision, 200, { id: r.id });
    case "not_found":
      return partnerError(decision, 422, "not_found", "offer not found");
    case "not_draft":
      return partnerError(decision, 422, "not_draft", "only a draft offer may be edited");
    case "bad_funder":
      return partnerError(decision, 422, "bad_funder", "funder and sponsorship do not match");
  }
}

function approveResponse(decision: Decision, status: OfferApproveStatus): Response {
  switch (status) {
    case "ok":
      return partnerOk(decision, 200, { ok: true });
    case "not_found":
      return partnerError(decision, 422, "not_found", "offer not found");
    case "not_draft":
      return partnerError(decision, 422, "not_draft", "only a draft offer may be approved");
  }
}

function endResponse(decision: Decision, status: OfferEndStatus): Response {
  switch (status) {
    case "ok":
      return partnerOk(decision, 200, { ok: true });
    case "not_found":
      return partnerError(decision, 422, "not_found", "offer not found");
    case "not_live":
      return partnerError(decision, 422, "not_live", "only a live offer may be ended");
  }
}

async function handleOffersList(req: Request, deps: PartnerOffersAdminDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseOffersQuery(req.url);
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const rows = await deps.db.withOffersAdmin(tokenHash, (o) => o.listOffers(parsed.value.trailId));
  return partnerOk(decision, 200, { offers: rows.map(offerBody) });
}

async function handleOfferUpsert(req: Request, deps: PartnerOffersAdminDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseOfferUpsertBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const eligibility = validateOfferEligibility(parsed.value.eligibility);
  if (!eligibility.valid) {
    return partnerError(decision, 422, "invalid_eligibility", "eligibility failed validation");
  }
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const v = parsed.value;
  const result = await deps.db.withOffersAdmin(tokenHash, (o) =>
    o.upsertOffer(
      v.id,
      v.trailId,
      v.facilityId,
      eligibility.rule,
      v.funder,
      v.sponsorshipId,
      v.budgetCap,
      v.maxRedemptions,
      v.faceValue,
      v.validFrom,
      v.validTo,
    ),
  );
  return upsertResponse(decision, result);
}

async function handleOfferApprove(req: Request, deps: PartnerOffersAdminDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseOfferIdBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const status = await deps.db.withOffersAdmin(tokenHash, (o) => o.approveOffer(parsed.value.id));
  return approveResponse(decision, status);
}

async function handleOfferEnd(req: Request, deps: PartnerOffersAdminDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseOfferIdBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const status = await deps.db.withOffersAdmin(tokenHash, (o) => o.endOffer(parsed.value.id));
  return endResponse(decision, status);
}
