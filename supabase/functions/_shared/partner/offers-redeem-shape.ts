// supabase/functions/_shared/partner/offers-redeem-shape.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shapes of `partner-offers-redeem` (docs/security/partner-auth-design.md 12, 32, 35; P5.1b + 0062 offline).
// Unknown keys REJECTED. Pure: no environment, no database, no logging.
//
//   GET  queue            ?facilityId=
//   POST redeem           { facilityId, offerCodeId, method, credential }
//                           method staff_scan: credential is the player's check-in token jti (a uuid)
//   POST redeem/offline   { facilityId, offerCodeId, handle, code, nameConfirmed }
//                           six digits verified in the database; nameConfirmed must be the boolean true (profile-card check)

import { parseFacilityId, parseReadQuery } from "./attest-shape.ts";
import { parseUuid } from "./invites-shape.ts";
import { OFFER_REDEEM_METHODS, type OfferRedeemMethod } from "./ports.ts";
import { type ParseIssue, type ParseResult, plain, unknownKeys } from "./session-shape.ts";

/** A player handle (app.profile.handle's own CHECK). */
const HANDLE_RE = /^[a-z0-9_]{3,20}$/;
const CODE_RE = /^[0-9]{6}$/;

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

export interface OfferRedeemOfflineBody {
  readonly facilityId: string;
  readonly offerCodeId: string;
  readonly handle: string;
  readonly code: string;
  readonly nameConfirmed: boolean;
}

export function parseOfferRedeemOfflineBody(raw: unknown): ParseResult<OfferRedeemOfflineBody> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["facilityId", "offerCodeId", "handle", "code", "nameConfirmed"]), "", issues);
  const facilityId = parseFacilityId(raw.facilityId);
  const offerCodeId = parseUuid(raw.offerCodeId);
  const handle = typeof raw.handle === "string" && HANDLE_RE.test(raw.handle.trim().toLowerCase())
    ? raw.handle.trim().toLowerCase()
    : null;
  const code = typeof raw.code === "string" && CODE_RE.test(raw.code) ? raw.code : null;
  if (facilityId === null) issues.push({ path: "facilityId", message: "must be a facility id" });
  if (offerCodeId === null) issues.push({ path: "offerCodeId", message: "must be a uuid" });
  if (handle === null) issues.push({ path: "handle", message: "must be a player handle" });
  if (code === null) issues.push({ path: "code", message: "must be six digits" });
  if (raw.nameConfirmed !== true) issues.push({ path: "nameConfirmed", message: "must be true" });
  if (issues.length > 0 || facilityId === null || offerCodeId === null || handle === null || code === null) {
    return { ok: false, issues };
  }
  return { ok: true, value: { facilityId, offerCodeId, handle, code, nameConfirmed: true } };
}
