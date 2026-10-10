// supabase/functions/_shared/partner/attest-handler.ts
//
// The `partner-attest` handler (docs/security/partner-auth-design.md 4.5, 6.5, 6.7, 12, 26; slice S3, the Edge half of migration 0056). Pure and unit-testable like members-handler.ts: the database
// (`PartnerDb`) is a PORT (`ports.ts`); this file reads no environment, opens no connection, imports no library and writes no log line (PA-11).
//
// ROUTES (relative to the function; `POST attest` is `/partner-attest/attest`):
//   POST attest           { facilityId, kind, token }          class A1 (one PIN per action): the ONLINE path. The player is the owner of the check-in token.
//   POST attest/offline   { facilityId, kind, handle, code }   class A1: the offline code, VERIFIED AND RECORDED IN THE DATABASE (X9, money doc step 3). The Edge never holds a seed or an expected code.
//   GET  shift-log        ?facilityId=                         class A0 (staff or manager of the facility): the old api.staff_shift_log, now that D12 has revoked PostgREST.
//   GET  staff-activity   ?facilityId=&days=                   class A0 (manager or operator of the facility; staff cannot).
// Every route is a session route. Scope, class, the self-attest rule, the replay rule, the same-device rule, the cold-start cap and the failure counters are the DATABASE's.
//
// THE ORDER, for every request: (1) the Origin check, before routing and for every method; (2) `OPTIONS` is answered here, with no port touched; (3) the route and the method (404 / 405); (4) the bearer:
// exactly `gr_ps_` + 43 characters, else the ONE 401 with no port touched; (5) the exact JSON media type (415) and the strict body (400) or the strict query (400); (6) the per-member bucket; (7) the work.
//
// STATUSES (every one commits, so the failure counters survive; PA-14 / money doc step 2): ok 201; token_invalid and verification_failed 422 (one answer for every way a token or a code can be wrong, so
// nothing says WHICH); replayed 409 (the 409 of AT(13)); rate_limited and cold_start_cap 429; no_programme 422; no_facility 404. A self-attest is 22023 in the database and a 422 here (AT(16)); a missing scope or PIN
// grant is 42501 and a 403.

import { Errors } from "../http.ts";
import { decideOrigin, preflightResponse } from "./cors.ts";
import { bearerHash, type Decision, mapPartnerError, matchRoute, methodRefusal, rateLimited, routeOfFunction, type RouteSpec } from "./handler-kit.ts";
import { parseOfflineAttestBody, parseOnlineAttestBody, parseShiftLogQuery, parseStaffActivityQuery } from "./attest-shape.ts";
import { partnerError, partnerOk, readPartnerJsonBody, runPartnerHandler, unauthenticated } from "./http.ts";
import type { AttestResult, PartnerDb, ShiftLogRow, StaffActivityRow } from "./ports.ts";

export const PARTNER_ATTEST_FUNCTION = "partner-attest";
/** A per-member bucket over every attest and read: a counter the database does not keep (the offline failure counters and the cold-start cap are the database's). `[inference]`: 240 an hour is about one a minute across a long shift. */
export const ATTEST_PER_MEMBER_PER_HOUR = 240;
export const ATTEST_BUCKET = "partner-attest:member";

export interface PartnerAttestDeps {
  readonly db: PartnerDb;
  /** The one allowed origin (privileged.ts#loadPartnerCorsOrigin), or null when none is configured. */
  readonly allowedOrigin: string | null;
  readonly timeoutMs?: number;
}

const ROUTES: readonly RouteSpec[] = [
  { name: "attest", path: "attest", methods: ["POST"], session: true },
  { name: "attest-offline", path: "attest/offline", methods: ["POST"], session: true },
  { name: "shift-log", path: "shift-log", methods: ["GET"], session: true },
  { name: "staff-activity", path: "staff-activity", methods: ["GET"], session: true },
];

export async function handlePartnerAttestRequest(req: Request, deps: PartnerAttestDeps): Promise<Response> {
  const decision = decideOrigin(req.headers, deps.allowedOrigin);
  if (decision.kind === "refused") return partnerError({ kind: "none" }, 403, "forbidden", "origin not allowed");
  if (req.method === "OPTIONS") return preflightResponse(decision);

  return await runPartnerHandler(
    decision,
    async () => {
      try {
        const matched = matchRoute(ROUTES, routeOfFunction(req.url, PARTNER_ATTEST_FUNCTION));
        if (matched === null) return partnerError(decision, 404, "not_found", "not found");
        const refusal = methodRefusal(decision, matched, req.method);
        if (refusal !== null) return refusal;
        const tokenHash = await bearerHash(req.headers);
        if (tokenHash === null) return unauthenticated(decision);

        switch (matched.spec.name) {
          case "attest":
            return await handleOnline(req, deps, decision, tokenHash);
          case "attest-offline":
            return await handleOffline(req, deps, decision, tokenHash);
          case "shift-log":
            return await handleShiftLog(req, deps, decision, tokenHash);
          case "staff-activity":
            return await handleStaffActivity(req, deps, decision, tokenHash);
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

async function memberLimit(deps: PartnerAttestDeps, decision: Decision, tokenHash: string): Promise<Response | null> {
  const limit = await deps.db.hitRateLimit(tokenHash, ATTEST_BUCKET, 3600, ATTEST_PER_MEMBER_PER_HOUR);
  return limit.ok ? null : rateLimited(decision, "too many requests", limit.retryAfterSeconds);
}

/** An attest result as its response. Nothing here names a seed, an expected code, a device or which check failed. */
function attestResponse(decision: Decision, r: AttestResult): Response {
  switch (r.status) {
    case "ok":
      return partnerOk(decision, 201, { attestationId: r.attestationId, held: r.held });
    case "replayed":
      return partnerError(decision, 409, "replayed", "this token or code has already been used");
    case "token_invalid":
      return partnerError(decision, 422, "token_invalid", "this token cannot be used here");
    case "verification_failed":
      return partnerError(decision, 422, "verification_failed", "the code was not accepted");
    case "rate_limited":
      return rateLimited(decision, "too many failed attempts: try again later", 3600);
    case "cold_start_cap":
      return rateLimited(decision, "a new member's daily limit has been reached", 3600);
    case "no_programme":
      return partnerError(decision, 422, "no_programme", "this facility has no marker programme");
    case "no_facility":
      return partnerError(decision, 404, "not_found", "not found");
  }
}

async function handleOnline(req: Request, deps: PartnerAttestDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseOnlineAttestBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const { facilityId, kind, token } = parsed.value;
  const result = await deps.db.withAttest(tokenHash, (s) => s.attest(facilityId, kind, token));
  return attestResponse(decision, result);
}

async function handleOffline(req: Request, deps: PartnerAttestDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseOfflineAttestBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const { facilityId, kind, handle, code } = parsed.value;
  const result = await deps.db.withAttest(tokenHash, (s) => s.offlineAttest(facilityId, kind, handle, code));
  return attestResponse(decision, result);
}

function shiftLogBody(r: ShiftLogRow): Record<string, unknown> {
  return { id: r.id, facilityId: r.facilityId, createdAt: r.createdAt, kind: r.kind, playerHandle: r.playerHandle, staffHandle: r.staffHandle };
}

function staffActivityBody(r: StaffActivityRow): Record<string, unknown> {
  return { staffUserId: r.staffUserId, facilityId: r.facilityId, day: r.day, attests: r.attests, activations: r.activations, anomalies: r.anomalies };
}

async function handleShiftLog(req: Request, deps: PartnerAttestDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseShiftLogQuery(req.url);
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const rows = await deps.db.withAttest(tokenHash, (s) => s.shiftLog(parsed.value.facilityId));
  return partnerOk(decision, 200, { entries: rows.map(shiftLogBody) });
}

async function handleStaffActivity(req: Request, deps: PartnerAttestDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseStaffActivityQuery(req.url);
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const { facilityId, days } = parsed.value;
  const rows = await deps.db.withAttest(tokenHash, (s) => s.staffActivity(facilityId, days));
  return partnerOk(decision, 200, { activity: rows.map(staffActivityBody) });
}
