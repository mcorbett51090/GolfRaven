// supabase/functions/_shared/partner/offers-redeem-shape.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shapes of `partner-offers-redeem` (docs/security/partner-auth-design.md 12, 32; P5.1b, the Edge half of migration 0060).
// Unknown keys REJECTED. Pure: no environment, no database, no logging.
//
//   GET  queue   ?facilityId=
//   POST redeem { facilityId, offerCodeId, method, credential }
//                 method staff_scan: credential is the player's check-in token jti (a uuid)
//
// `offline_code` is not a method of this slice: it is refused here (400), and the database refuses it too (22023).

import { parseFacilityId, parseReadQuery } from "./attest-shape.ts";
import { parseUuid } from "./invites-shape.ts";
import { OFFER_REDEEM_METHODS, type OfferRedeemMethod } from "./ports.ts";
import { type ParseIssue, type ParseResult, plain, unknownKeys } from "./session-shape.ts";

export function parseOffersQueueQuery(url: string): ParseResult<{ readonly facilityId: string }> {
  const q = parseReadQuery(url, new Set(["facilityId"]));
  if (!q.ok) return q;
  const facilityId = parseFacilityId(q.value.get("facilityId"));
  if (facilityId === null) return { ok: false, issues: [{ path: "facilityId", message: "must be a facility id" }] };
  return { ok: true, value: { facilityId } };
}

export interface OfferRedeemBody {
  readonly facilityId: string;
  readonly offerCodeId: string;
  readonly method: OfferRedeemMethod;
  readonly credential: string;
}

export function parseOfferRedeemBody(raw: unknown): ParseResult<OfferRedeemBody> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["facilityId", "offerCodeId", "method", "credential"]), "", issues);
  const facilityId = parseFacilityId(raw.facilityId);
  const offerCodeId = parseUuid(raw.offerCodeId);
  const method = typeof raw.method === "string" && (OFFER_REDEEM_METHODS as readonly string[]).includes(raw.method)
    ? (raw.method as OfferRedeemMethod)
    : null;
  if (facilityId === null) issues.push({ path: "facilityId", message: "must be a facility id" });
  if (offerCodeId === null) issues.push({ path: "offerCodeId", message: "must be a uuid" });
  let credential: string | null = null;
  if (method === null) issues.push({ path: "method", message: "must be staff_scan" });
  else {
    credential = parseUuid(raw.credential);
    if (credential === null) issues.push({ path: "credential", message: "must be the check-in token id (a uuid)" });
  }
  if (issues.length > 0 || facilityId === null || offerCodeId === null || method === null || credential === null) {
    return { ok: false, issues };
  }
  return { ok: true, value: { facilityId, offerCodeId, method, credential } };
}
