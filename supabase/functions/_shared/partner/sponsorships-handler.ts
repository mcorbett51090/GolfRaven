// supabase/functions/_shared/partner/sponsorships-handler.ts
//
// The `sponsorships-admin` handler (docs/security/partner-auth-design.md 4.5, 6.3, 12, 30; slice S6, the Edge half of migration 0059). Pure and unit-testable like stock-handler.ts: the database
// (`PartnerDb`) is a PORT (`ports.ts`); this file reads no environment, opens no connection, imports no library and writes no log line (PA-11).
//
// ROUTES (relative to the function; `GET sponsorships` is `/sponsorships-admin/sponsorships`):
//   GET  sponsorships           ?trailId=     class A0
//   POST sponsorships           { ... }       class A3: draft upsert
//   POST sponsorships/approve   { id }        class A3: draft → live (AT(20) stock_short → 422)
// Every route is a session route. Scope, class, sponsor-org kind and the returned statuses are the DATABASE's.
//
// THE ORDER, for every request: (1) the Origin check; (2) OPTIONS with no port touched; (3) route and method; (4) the bearer; (5) exact JSON media type and strict body (POST) or strict query (GET);
// (6) the per-member bucket; (7) the work.
//
// STATUSES (every one commits): ok 200; not_found, not_draft, bad_sponsor and stock_short 422; a missing scope is 42501 and a 403; a malformed argument the shape let through is 22023 and a 422.

import { Errors } from "../http.ts";
import { decideOrigin, preflightResponse } from "./cors.ts";
import { bearerHash, type Decision, mapPartnerError, matchRoute, methodRefusal, rateLimited, routeOfFunction, type RouteSpec } from "./handler-kit.ts";
import { partnerError, partnerOk, readPartnerJsonBody, runPartnerHandler, unauthenticated } from "./http.ts";
import type { PartnerDb, SponsorshipApproveStatus, SponsorshipRow, SponsorshipUpsertResult } from "./ports.ts";
import { parseSponsorshipIdBody, parseSponsorshipsQuery, parseSponsorshipUpsertBody } from "./sponsorships-shape.ts";

export const PARTNER_SPONSORSHIPS_FUNCTION = "sponsorships-admin";
/** A per-member bucket over every sponsorship read and write. `[inference]`: 240 an hour matches stock-admin. */
export const SPONSORSHIPS_PER_MEMBER_PER_HOUR = 240;
export const SPONSORSHIPS_BUCKET = "sponsorships-admin:member";

export interface PartnerSponsorshipsDeps {
  readonly db: PartnerDb;
  readonly allowedOrigin: string | null;
  readonly timeoutMs?: number;
}

const ROUTES: readonly RouteSpec[] = [
  // GET and POST share one path: matchRoute picks the first path match, then methodRefusal checks the method list.
  { name: "sponsorships", path: "sponsorships", methods: ["GET", "POST"], session: true },
  { name: "sponsorships-approve", path: "sponsorships/approve", methods: ["POST"], session: true },
];

export async function handlePartnerSponsorshipsRequest(req: Request, deps: PartnerSponsorshipsDeps): Promise<Response> {
  const decision = decideOrigin(req.headers, deps.allowedOrigin);
  if (decision.kind === "refused") return partnerError({ kind: "none" }, 403, "forbidden", "origin not allowed");
  if (req.method === "OPTIONS") return preflightResponse(decision);

  return await runPartnerHandler(
    decision,
    async () => {
      try {
        const matched = matchRoute(ROUTES, routeOfFunction(req.url, PARTNER_SPONSORSHIPS_FUNCTION));
        if (matched === null) return partnerError(decision, 404, "not_found", "not found");
        const refusal = methodRefusal(decision, matched, req.method);
        if (refusal !== null) return refusal;
        const tokenHash = await bearerHash(req.headers);
        if (tokenHash === null) return unauthenticated(decision);

        switch (matched.spec.name) {
          case "sponsorships":
            return req.method === "GET"
              ? await handleSponsorshipsList(req, deps, decision, tokenHash)
              : await handleSponsorshipUpsert(req, deps, decision, tokenHash);
          case "sponsorships-approve":
            return await handleSponsorshipApprove(req, deps, decision, tokenHash);
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

async function memberLimit(deps: PartnerSponsorshipsDeps, decision: Decision, tokenHash: string): Promise<Response | null> {
  const limit = await deps.db.hitRateLimit(tokenHash, SPONSORSHIPS_BUCKET, 3600, SPONSORSHIPS_PER_MEMBER_PER_HOUR);
  return limit.ok ? null : rateLimited(decision, "too many requests", limit.retryAfterSeconds);
}

function sponsorshipBody(r: SponsorshipRow): Record<string, unknown> {
  return {
    id: r.id,
    sponsorOrgId: r.sponsorOrgId,
    trailId: r.trailId,
    category: r.category,
    scope: r.scope,
    attributionName: r.attributionName,
    attributionAsset: r.attributionAsset,
    placementFee: r.placementFee,
    startsOn: r.startsOn,
    endsOn: r.endsOn,
    operatorApprovedAt: r.operatorApprovedAt,
    status: r.status,
  };
}

function upsertResponse(decision: Decision, r: SponsorshipUpsertResult): Response {
  switch (r.status) {
    case "ok":
      return partnerOk(decision, 200, { id: r.id });
    case "not_found":
      return partnerError(decision, 422, "not_found", "sponsorship not found");
    case "not_draft":
      return partnerError(decision, 422, "not_draft", "only a draft sponsorship may be edited");
    case "bad_sponsor":
      return partnerError(decision, 422, "bad_sponsor", "sponsor organisation must be kind sponsor");
  }
}

function approveResponse(decision: Decision, status: SponsorshipApproveStatus): Response {
  switch (status) {
    case "ok":
      return partnerOk(decision, 200, { ok: true });
    case "not_found":
      return partnerError(decision, 422, "not_found", "sponsorship not found");
    case "not_draft":
      return partnerError(decision, 422, "not_draft", "only a draft sponsorship may be approved");
    case "stock_short":
      return partnerError(decision, 422, "stock_short", "every special-marker facility must hold stock before this sponsorship goes live");
  }
}

async function handleSponsorshipsList(req: Request, deps: PartnerSponsorshipsDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseSponsorshipsQuery(req.url);
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const rows = await deps.db.withSponsorships(tokenHash, (s) => s.listSponsorships(parsed.value.trailId));
  return partnerOk(decision, 200, { sponsorships: rows.map(sponsorshipBody) });
}

async function handleSponsorshipUpsert(req: Request, deps: PartnerSponsorshipsDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseSponsorshipUpsertBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const v = parsed.value;
  const result = await deps.db.withSponsorships(tokenHash, (s) =>
    s.upsertSponsorship(
      v.id,
      v.sponsorOrgId,
      v.trailId,
      v.category,
      v.scope,
      v.attributionName,
      v.attributionAsset,
      v.placementFee,
      v.startsOn,
      v.endsOn,
    ),
  );
  return upsertResponse(decision, result);
}

async function handleSponsorshipApprove(req: Request, deps: PartnerSponsorshipsDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseSponsorshipIdBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const status = await deps.db.withSponsorships(tokenHash, (s) => s.approveSponsorship(parsed.value.id));
  return approveResponse(decision, status);
}
