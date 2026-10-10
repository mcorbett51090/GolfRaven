// supabase/functions/_shared/partner/offers-shape.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shapes of `offers-admin` (docs/security/partner-auth-design.md 12, 30; slice S6, the Edge half of migration 0059), in the style of
// stock-shape.ts: unknown keys REJECTED, every value checked for its exact shape before any port is touched. Pure: no environment, no database, no logging.
//
//   GET  offers           ?trailId=
//   POST offers           { id?, trailId, facilityId, eligibility, funder, sponsorshipId?, budgetCap, maxRedemptions?, faceValue, validFrom, validTo }
//   POST offers/approve   { id }
//   POST offers/end       { id }
//
// Eligibility is checked for SHAPE only here (a JSON value). The Edge-local `validateOfferEligibility` (AT(14) schema gate) runs in the handler before the database is opened.

import { parseFacilityId, parseReadQuery } from "./attest-shape.ts";
import { parseUuid } from "./invites-shape.ts";
import { type ParseIssue, type ParseResult, plain, unknownKeys } from "./session-shape.ts";

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const FUNDERS = new Set(["course", "operator", "sponsor"]);

function parseTrailId(v: unknown): string | null {
  return parseFacilityId(v);
}

function parseIsoDate(v: unknown): string | null {
  return typeof v === "string" && DATE_RE.test(v) ? v : null;
}

export function parseOffersQuery(url: string): ParseResult<{ readonly trailId: string }> {
  const q = parseReadQuery(url, new Set(["trailId"]));
  if (!q.ok) return q;
  const trailId = parseTrailId(q.value.get("trailId"));
  if (trailId === null) return { ok: false, issues: [{ path: "trailId", message: "must be a trail id" }] };
  return { ok: true, value: { trailId } };
}

export interface OfferUpsertBody {
  readonly id: string | null;
  readonly trailId: string;
  readonly facilityId: string;
  readonly eligibility: unknown;
  readonly funder: string;
  readonly sponsorshipId: string | null;
  readonly budgetCap: number;
  readonly maxRedemptions: number | null;
  readonly faceValue: number;
  readonly validFrom: string;
  readonly validTo: string;
}

export function parseOfferUpsertBody(raw: unknown): ParseResult<OfferUpsertBody> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(
    raw,
    new Set([
      "id",
      "trailId",
      "facilityId",
      "eligibility",
      "funder",
      "sponsorshipId",
      "budgetCap",
      "maxRedemptions",
      "faceValue",
      "validFrom",
      "validTo",
    ]),
    "",
    issues,
  );
  let id: string | null = null;
  let idOk = true;
  if (raw.id !== undefined && raw.id !== null) {
    const u = parseUuid(raw.id);
    if (u === null) idOk = false;
    else id = u;
  }
  const trailId = parseTrailId(raw.trailId);
  const facilityId = parseFacilityId(raw.facilityId);
  const eligibility = raw.eligibility;
  const eligibilityOk = eligibility !== undefined && eligibility !== null && typeof eligibility === "object";
  const funder = typeof raw.funder === "string" && FUNDERS.has(raw.funder) ? raw.funder : null;
  let sponsorshipId: string | null = null;
  let sponsorshipOk = true;
  if (raw.sponsorshipId !== undefined && raw.sponsorshipId !== null) {
    const u = parseUuid(raw.sponsorshipId);
    if (u === null) sponsorshipOk = false;
    else sponsorshipId = u;
  }
  const budgetCap = typeof raw.budgetCap === "number" && Number.isFinite(raw.budgetCap) && raw.budgetCap >= 0 ? raw.budgetCap : null;
  const faceValue = typeof raw.faceValue === "number" && Number.isFinite(raw.faceValue) && raw.faceValue >= 0 ? raw.faceValue : null;
  let maxRedemptions: number | null = null;
  let maxOk = true;
  if (raw.maxRedemptions !== undefined && raw.maxRedemptions !== null) {
    if (typeof raw.maxRedemptions === "number" && Number.isSafeInteger(raw.maxRedemptions) && raw.maxRedemptions >= 0) {
      maxRedemptions = raw.maxRedemptions;
    } else maxOk = false;
  }
  const validFrom = parseIsoDate(raw.validFrom);
  const validTo = parseIsoDate(raw.validTo);

  if (!idOk) issues.push({ path: "id", message: "must be a uuid or null" });
  if (trailId === null) issues.push({ path: "trailId", message: "must be a trail id" });
  if (facilityId === null) issues.push({ path: "facilityId", message: "must be a facility id" });
  if (!eligibilityOk) issues.push({ path: "eligibility", message: "must be a JSON object" });
  if (funder === null) issues.push({ path: "funder", message: "must be course, operator or sponsor" });
  if (!sponsorshipOk) issues.push({ path: "sponsorshipId", message: "must be a uuid or null" });
  if (budgetCap === null) issues.push({ path: "budgetCap", message: "must be a non-negative number" });
  if (faceValue === null) issues.push({ path: "faceValue", message: "must be a non-negative number" });
  if (!maxOk) issues.push({ path: "maxRedemptions", message: "must be a non-negative whole number or null" });
  if (validFrom === null) issues.push({ path: "validFrom", message: "must be a YYYY-MM-DD date" });
  if (validTo === null) issues.push({ path: "validTo", message: "must be a YYYY-MM-DD date" });
  else if (validFrom !== null && validTo < validFrom) issues.push({ path: "validTo", message: "must be on or after validFrom" });

  if (
    issues.length > 0 || trailId === null || facilityId === null || !eligibilityOk || funder === null ||
    budgetCap === null || faceValue === null || validFrom === null || validTo === null
  ) {
    return { ok: false, issues };
  }
  return {
    ok: true,
    value: { id, trailId, facilityId, eligibility, funder, sponsorshipId, budgetCap, maxRedemptions, faceValue, validFrom, validTo },
  };
}

export function parseOfferIdBody(raw: unknown): ParseResult<{ readonly id: string }> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["id"]), "", issues);
  const id = parseUuid(raw.id);
  if (id === null) issues.push({ path: "id", message: "must be a uuid" });
  if (issues.length > 0 || id === null) return { ok: false, issues };
  return { ok: true, value: { id } };
}
