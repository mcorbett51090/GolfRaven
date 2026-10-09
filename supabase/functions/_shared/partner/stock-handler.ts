// supabase/functions/_shared/partner/stock-handler.ts
//
// The `stock-admin` handler (docs/security/partner-auth-design.md 4.5, 6.3, 12, 28; slice S5, the Edge half of migration 0058). Pure and unit-testable like attest-handler.ts: the database (`PartnerDb`) is a PORT
// (`ports.ts`); this file reads no environment, opens no connection, imports no library and writes no log line (PA-11).
//
// ROUTES (relative to the function; `GET stock` is `/stock-admin/stock`):
//   GET  stock          ?facilityId=                                 class A0 (staff or manager of the facility): the facility's stock rows with the projected availability
//   POST stock/move     { facilityId, trailId, kind, qty, note? }    class A1 (one PIN per action): one stock movement (delivered, transfer_in, transfer_out, count_adjustment, damaged)
// Every route is a session route. Scope, class, the row lock, the never-below-zero rule, the movement row and the availability projection are the DATABASE's. A facility with no stock row for the trail is
// the status `no_stock_row`: the Edge never creates a row (rows come from the catalog import).
//
// THE ORDER, for every request: (1) the Origin check; (2) OPTIONS with no port touched; (3) route and method; (4) the bearer; (5) exact JSON media type and strict body (POST) or strict query (GET);
// (6) the per-member bucket; (7) the work.
//
// STATUSES (every one commits): ok 200; no_stock_row, short and over_cap 422; a missing scope or PIN grant is 42501 and a 403; a malformed argument the shape let through is 22023 and a 422.

import { Errors } from "../http.ts";
import { decideOrigin, preflightResponse } from "./cors.ts";
import { bearerHash, type Decision, mapPartnerError, matchRoute, methodRefusal, rateLimited, routeOfFunction, type RouteSpec } from "./handler-kit.ts";
import { partnerError, partnerOk, readPartnerJsonBody, runPartnerHandler, unauthenticated } from "./http.ts";
import type { PartnerDb, StockMoveResult, StockRow } from "./ports.ts";
import { parseStockMoveBody, parseStockQuery } from "./stock-shape.ts";

export const PARTNER_STOCK_FUNCTION = "stock-admin";
/** A per-member bucket over every stock read and movement. `[inference]`: 240 an hour is about one a minute across a long shift. */
export const STOCK_PER_MEMBER_PER_HOUR = 240;
export const STOCK_BUCKET = "stock-admin:member";

export interface PartnerStockDeps {
  readonly db: PartnerDb;
  readonly allowedOrigin: string | null;
  readonly timeoutMs?: number;
}

const ROUTES: readonly RouteSpec[] = [
  { name: "stock", path: "stock", methods: ["GET"], session: true },
  { name: "stock-move", path: "stock/move", methods: ["POST"], session: true },
];

export async function handlePartnerStockRequest(req: Request, deps: PartnerStockDeps): Promise<Response> {
  const decision = decideOrigin(req.headers, deps.allowedOrigin);
  if (decision.kind === "refused") return partnerError({ kind: "none" }, 403, "forbidden", "origin not allowed");
  if (req.method === "OPTIONS") return preflightResponse(decision);

  return await runPartnerHandler(
    decision,
    async () => {
      try {
        const matched = matchRoute(ROUTES, routeOfFunction(req.url, PARTNER_STOCK_FUNCTION));
        if (matched === null) return partnerError(decision, 404, "not_found", "not found");
        const refusal = methodRefusal(decision, matched, req.method);
        if (refusal !== null) return refusal;
        const tokenHash = await bearerHash(req.headers);
        if (tokenHash === null) return unauthenticated(decision);

        switch (matched.spec.name) {
          case "stock":
            return await handleStockRead(req, deps, decision, tokenHash);
          case "stock-move":
            return await handleStockMove(req, deps, decision, tokenHash);
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

async function memberLimit(deps: PartnerStockDeps, decision: Decision, tokenHash: string): Promise<Response | null> {
  const limit = await deps.db.hitRateLimit(tokenHash, STOCK_BUCKET, 3600, STOCK_PER_MEMBER_PER_HOUR);
  return limit.ok ? null : rateLimited(decision, "too many requests", limit.retryAfterSeconds);
}

function stockRowBody(r: StockRow): Record<string, unknown> {
  return { trailId: r.trailId, onHand: r.onHand, lowThreshold: r.lowThreshold, status: r.status, lastCountedAt: r.lastCountedAt };
}

function moveResponse(decision: Decision, r: StockMoveResult): Response {
  switch (r.status) {
    case "ok":
      return partnerOk(decision, 200, { onHand: r.onHand, availability: r.availability });
    case "no_stock_row":
      return partnerError(decision, 422, "no_stock_row", "this facility holds no stock row for that trail");
    case "short":
      return partnerError(decision, 422, "short", "the facility does not hold that many");
    case "over_cap":
      return partnerError(decision, 422, "over_cap", "that would take the stock over its limit");
  }
}

async function handleStockRead(req: Request, deps: PartnerStockDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseStockQuery(req.url);
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const rows = await deps.db.withStock(tokenHash, (s) => s.stockRead(parsed.value.facilityId));
  return partnerOk(decision, 200, { stock: rows.map(stockRowBody) });
}

async function handleStockMove(req: Request, deps: PartnerStockDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseStockMoveBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const { facilityId, trailId, kind, qty, note } = parsed.value;
  const result = await deps.db.withStock(tokenHash, (s) => s.stockMove(facilityId, trailId, kind, qty, note));
  return moveResponse(decision, result);
}
