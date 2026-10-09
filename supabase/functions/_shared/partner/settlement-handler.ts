// supabase/functions/_shared/partner/settlement-handler.ts
//
// The `settlement-export` handler (docs/security/partner-auth-design.md 4.5, 6.3, 12, 32; AT(17), AT(20); P5.1b, the Edge half of migration 0060). Pure and unit-testable: the database and the
// exports storage bucket are PORTS (`ports.ts`); this file reads no environment, opens no connection, imports no library and writes no log line (PA-11).
//
// ROUTES:
//   POST export   { trailId, month }   class A3 (operator of the trail or admin): settlement lines for the month → CSV uploaded under `exports/`, a time-limited signed URL returned
// Every route is a session route. Scope, class (TOTP), sponsorship attribution and the line aggregates are the DATABASE's. The signed URL and the 7-day object lifecycle are AT(17).
//
// THE ORDER: (1) Origin; (2) OPTIONS; (3) route and method; (4) bearer; (5) exact JSON + strict body; (6) per-member bucket; (7) the definer; (8) on status ok, build CSV, upload, sign.
//
// STATUSES: ok 200 with { path, signedUrl, expiresAt, lines }; empty 404 (no redemptions that month); 42501 → 403; 22023 → 422.

import { Errors } from "../http.ts";
import { decideOrigin, preflightResponse } from "./cors.ts";
import { bearerHash, type Decision, mapPartnerError, matchRoute, methodRefusal, rateLimited, routeOfFunction, type RouteSpec } from "./handler-kit.ts";
import { partnerError, partnerOk, readPartnerJsonBody, runPartnerHandler, unauthenticated } from "./http.ts";
import type { ExportsStoragePort, PartnerDb, SettlementExportResult, SettlementLine } from "./ports.ts";
import { parseSettlementExportBody } from "./settlement-shape.ts";

export const SETTLEMENT_EXPORT_FUNCTION = "settlement-export";
/** A per-member bucket over settlement exports. `[inference]`: 60 an hour — an operator export is infrequent. */
export const SETTLEMENT_PER_MEMBER_PER_HOUR = 60;
export const SETTLEMENT_BUCKET = "settlement-export:member";
/** AT(17): signed URL lifetime matches the 7-day exports retention. */
export const SETTLEMENT_SIGNED_URL_SECONDS = 7 * 24 * 60 * 60;

export interface SettlementExportDeps {
  readonly db: PartnerDb;
  readonly storage: ExportsStoragePort;
  readonly allowedOrigin: string | null;
  readonly timeoutMs?: number;
  /** Injected clock for the signed-URL expiresAt (tests); defaults to Date.now. */
  readonly nowMs?: () => number;
  /** Injected id for the object path (tests); defaults to crypto.randomUUID. */
  readonly newId?: () => string;
}

const ROUTES: readonly RouteSpec[] = [
  { name: "export", path: "export", methods: ["POST"], session: true },
];

export async function handleSettlementExportRequest(req: Request, deps: SettlementExportDeps): Promise<Response> {
  const decision = decideOrigin(req.headers, deps.allowedOrigin);
  if (decision.kind === "refused") return partnerError({ kind: "none" }, 403, "forbidden", "origin not allowed");
  if (req.method === "OPTIONS") return preflightResponse(decision);

  return await runPartnerHandler(
    decision,
    async () => {
      try {
        const matched = matchRoute(ROUTES, routeOfFunction(req.url, SETTLEMENT_EXPORT_FUNCTION));
        if (matched === null) return partnerError(decision, 404, "not_found", "not found");
        const refusal = methodRefusal(decision, matched, req.method);
        if (refusal !== null) return refusal;
        const tokenHash = await bearerHash(req.headers);
        if (tokenHash === null) return unauthenticated(decision);
        return await handleExport(req, deps, decision, tokenHash);
      } catch (err) {
        return mapPartnerError(decision, err);
      }
    },
    deps.timeoutMs,
  );
}

function lineBody(r: SettlementLine): Record<string, unknown> {
  return {
    facilityId: r.facilityId,
    month: r.month,
    funder: r.funder,
    sponsorshipId: r.sponsorshipId,
    redemptions: r.redemptions,
    offlineCount: r.offlineCount,
    unconfirmedCount: r.unconfirmedCount,
    faceValueTotal: r.faceValueTotal,
  };
}

/** CSV with a header row; sponsorship_id empty when null (AT(20) attribution column is always present). */
export function settlementCsv(lines: readonly SettlementLine[]): string {
  const header = "facility_id,month,funder,sponsorship_id,redemptions,offline_count,unconfirmed_count,face_value_total";
  const rows = lines.map((l) =>
    [
      csvCell(l.facilityId),
      csvCell(l.month),
      csvCell(l.funder),
      csvCell(l.sponsorshipId ?? ""),
      String(l.redemptions),
      String(l.offlineCount),
      String(l.unconfirmedCount),
      String(l.faceValueTotal),
    ].join(",")
  );
  return [header, ...rows].join("\n") + "\n";
}

function csvCell(v: string): string {
  if (/[",\n\r]/.test(v)) return `"${v.replace(/"/g, '""')}"`;
  return v;
}

async function handleExport(req: Request, deps: SettlementExportDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseSettlementExportBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limit = await deps.db.hitRateLimit(tokenHash, SETTLEMENT_BUCKET, 3600, SETTLEMENT_PER_MEMBER_PER_HOUR);
  if (!limit.ok) return rateLimited(decision, "too many requests", limit.retryAfterSeconds);

  const result: SettlementExportResult = await deps.db.withSettlementExport(tokenHash, (s) => s.settlementExport(parsed.value.trailId, parsed.value.month));
  if (result.status === "empty") {
    return partnerError(decision, 404, "empty", "no redemptions for that trail and month");
  }

  const id = (deps.newId ?? (() => crypto.randomUUID()))();
  const path = `settlement/${parsed.value.trailId}/${parsed.value.month}/${id}.csv`;
  const body = new TextEncoder().encode(settlementCsv(result.lines));
  const put = await deps.storage.putSigned(path, body, "text/csv", SETTLEMENT_SIGNED_URL_SECONDS);
  return partnerOk(decision, 200, {
    path: put.path,
    signedUrl: put.signedUrl,
    expiresAt: put.expiresAt,
    lines: result.lines.map(lineBody),
  });
}
