// supabase/functions/_shared/partner/programme-handler.ts
//
// The `programme-config` handler (docs/security/partner-auth-design.md 4.5, 6.3, 12, 30; slice S6, the Edge half of migration 0059). Pure and unit-testable like stock-handler.ts: the database
// (`PartnerDb`) is a PORT (`ports.ts`); this file reads no environment, opens no connection, imports no library and writes no log line (PA-11).
//
// ROUTES (relative to the function; `GET programme` is `/programme-config/programme`):
//   GET  programme              ?trailId=              class A0: trail read + facility list
//   POST programme/trail        { ... }                class A3: trail_programme upsert
//   POST programme/facility     { ... }                class A3: facility_programme upsert
//   GET  rollups/operator       ?trailId=              class A0
//   GET  rollups/sponsor        ?sponsorshipId=        class A0
// Every route is a session route. Scope, class and the returned statuses are the DATABASE's.
//
// THE ORDER, for every request: (1) the Origin check; (2) OPTIONS with no port touched; (3) route and method; (4) the bearer; (5) exact JSON media type and strict body (POST) or strict query (GET);
// (6) the per-member bucket; (7) the work.
//
// STATUSES (every one commits): ok 200; not_found and no_trail 422; a missing scope is 42501 and a 403; a malformed argument the shape let through is 22023 and a 422.

import { Errors } from "../http.ts";
import { decideOrigin, preflightResponse } from "./cors.ts";
import { bearerHash, type Decision, mapPartnerError, matchRoute, methodRefusal, rateLimited, routeOfFunction, type RouteSpec } from "./handler-kit.ts";
import { partnerError, partnerOk, readPartnerJsonBody, runPartnerHandler, unauthenticated } from "./http.ts";
import type {
  FacilityProgrammeRow,
  FacilityProgrammeUpsertStatus,
  OperatorRollupRow,
  PartnerDb,
  SponsorRollupRow,
  TrailProgrammeRow,
  TrailProgrammeUpsertStatus,
} from "./ports.ts";
import {
  parseFacilityProgrammeUpsertBody,
  parseSponsorshipQuery,
  parseTrailProgrammeUpsertBody,
  parseTrailQuery,
} from "./programme-shape.ts";

export const PARTNER_PROGRAMME_FUNCTION = "programme-config";
/** A per-member bucket over every programme read and write. `[inference]`: 240 an hour matches stock-admin. */
export const PROGRAMME_PER_MEMBER_PER_HOUR = 240;
export const PROGRAMME_BUCKET = "programme-config:member";

export interface PartnerProgrammeDeps {
  readonly db: PartnerDb;
  readonly allowedOrigin: string | null;
  readonly timeoutMs?: number;
}

const ROUTES: readonly RouteSpec[] = [
  { name: "programme", path: "programme", methods: ["GET"], session: true },
  { name: "programme-trail", path: "programme/trail", methods: ["POST"], session: true },
  { name: "programme-facility", path: "programme/facility", methods: ["POST"], session: true },
  { name: "rollups-operator", path: "rollups/operator", methods: ["GET"], session: true },
  { name: "rollups-sponsor", path: "rollups/sponsor", methods: ["GET"], session: true },
];

export async function handlePartnerProgrammeRequest(req: Request, deps: PartnerProgrammeDeps): Promise<Response> {
  const decision = decideOrigin(req.headers, deps.allowedOrigin);
  if (decision.kind === "refused") return partnerError({ kind: "none" }, 403, "forbidden", "origin not allowed");
  if (req.method === "OPTIONS") return preflightResponse(decision);

  return await runPartnerHandler(
    decision,
    async () => {
      try {
        const matched = matchRoute(ROUTES, routeOfFunction(req.url, PARTNER_PROGRAMME_FUNCTION));
        if (matched === null) return partnerError(decision, 404, "not_found", "not found");
        const refusal = methodRefusal(decision, matched, req.method);
        if (refusal !== null) return refusal;
        const tokenHash = await bearerHash(req.headers);
        if (tokenHash === null) return unauthenticated(decision);

        switch (matched.spec.name) {
          case "programme":
            return await handleProgrammeRead(req, deps, decision, tokenHash);
          case "programme-trail":
            return await handleTrailUpsert(req, deps, decision, tokenHash);
          case "programme-facility":
            return await handleFacilityUpsert(req, deps, decision, tokenHash);
          case "rollups-operator":
            return await handleOperatorRollup(req, deps, decision, tokenHash);
          case "rollups-sponsor":
            return await handleSponsorRollup(req, deps, decision, tokenHash);
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

async function memberLimit(deps: PartnerProgrammeDeps, decision: Decision, tokenHash: string): Promise<Response | null> {
  const limit = await deps.db.hitRateLimit(tokenHash, PROGRAMME_BUCKET, 3600, PROGRAMME_PER_MEMBER_PER_HOUR);
  return limit.ok ? null : rateLimited(decision, "too many requests", limit.retryAfterSeconds);
}

function trailBody(r: TrailProgrammeRow): Record<string, unknown> {
  return {
    trailId: r.trailId,
    status: r.programmeStatus,
    markerSource: r.markerSource,
    markerRequiresCompletion: r.markerRequiresCompletion,
    specialMarkerFundedBy: r.specialMarkerFundedBy,
    specialMarkerLowThreshold: r.specialMarkerLowThreshold,
    webPlayerFlow: r.webPlayerFlow,
    specialMarkerSku: r.specialMarkerSku,
    specialMarkerSponsorshipId: r.specialMarkerSponsorshipId,
    feeModel: r.feeModel,
    feeAmount: r.feeAmount,
    startsOn: r.startsOn,
    endsOn: r.endsOn,
  };
}

function facilityBody(r: FacilityProgrammeRow): Record<string, unknown> {
  return {
    facilityId: r.facilityId,
    participation: r.participation,
    stocksMarkers: r.stocksMarkers,
    holdsSpecialMarker: r.holdsSpecialMarker,
    connectivity: r.connectivity,
    staffNetwork: r.staffNetwork,
    wifiNote: r.wifiNote,
    qrMode: r.qrMode,
    pinEpoch: r.pinEpoch,
  };
}

function operatorRollupBody(r: OperatorRollupRow): Record<string, unknown> {
  return { trailId: r.trailId, month: r.month, metric: r.metric, value: r.value, cohortN: r.cohortN };
}

function sponsorRollupBody(r: SponsorRollupRow): Record<string, unknown> {
  return { sponsorshipId: r.sponsorshipId, month: r.month, metric: r.metric, value: r.value, cohortN: r.cohortN };
}

function upsertStatusResponse(decision: Decision, status: TrailProgrammeUpsertStatus | FacilityProgrammeUpsertStatus): Response {
  switch (status) {
    case "ok":
      return partnerOk(decision, 200, { ok: true });
    case "not_found":
      return partnerError(decision, 422, "not_found", "trail not found");
    case "no_trail":
      return partnerError(decision, 422, "no_trail", "trail programme must exist before a facility programme");
  }
}

async function handleProgrammeRead(req: Request, deps: PartnerProgrammeDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseTrailQuery(req.url);
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const trailId = parsed.value.trailId;
  const { trail, facilities } = await deps.db.withProgramme(tokenHash, async (p) => {
    const t = await p.trailRead(trailId);
    if (t.status !== "ok") return { trail: t, facilities: [] as FacilityProgrammeRow[] };
    const f = await p.facilityList(trailId);
    return { trail: t, facilities: f };
  });
  if (trail.status !== "ok") return partnerError(decision, 422, "not_found", "trail programme not found");
  return partnerOk(decision, 200, { trail: trailBody(trail), facilities: facilities.map(facilityBody) });
}

async function handleTrailUpsert(req: Request, deps: PartnerProgrammeDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseTrailProgrammeUpsertBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const v = parsed.value;
  const status = await deps.db.withProgramme(tokenHash, (p) =>
    p.trailUpsert(
      v.trailId,
      v.status,
      v.markerSource,
      v.markerRequiresCompletion,
      v.specialMarkerFundedBy,
      v.specialMarkerLowThreshold,
      v.webPlayerFlow,
      v.specialMarkerSku,
      v.specialMarkerSponsorshipId,
      v.feeModel,
      v.feeAmount,
      v.startsOn,
      v.endsOn,
    ),
  );
  return upsertStatusResponse(decision, status);
}

async function handleFacilityUpsert(req: Request, deps: PartnerProgrammeDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseFacilityProgrammeUpsertBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const v = parsed.value;
  const status = await deps.db.withProgramme(tokenHash, (p) =>
    p.facilityUpsert(
      v.trailId,
      v.facilityId,
      v.participation,
      v.stocksMarkers,
      v.holdsSpecialMarker,
      v.connectivity,
      v.staffNetwork,
      v.wifiNote,
      v.qrMode,
    ),
  );
  return upsertStatusResponse(decision, status);
}

async function handleOperatorRollup(req: Request, deps: PartnerProgrammeDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseTrailQuery(req.url);
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const rows = await deps.db.withProgramme(tokenHash, (p) => p.operatorRollup(parsed.value.trailId));
  return partnerOk(decision, 200, { rollups: rows.map(operatorRollupBody) });
}

async function handleSponsorRollup(req: Request, deps: PartnerProgrammeDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseSponsorshipQuery(req.url);
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limited = await memberLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const rows = await deps.db.withProgramme(tokenHash, (p) => p.sponsorRollup(parsed.value.sponsorshipId));
  return partnerOk(decision, 200, { rollups: rows.map(sponsorRollupBody) });
}
