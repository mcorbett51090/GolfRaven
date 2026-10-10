// supabase/functions/_shared/partner/entitlements-shape.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shapes of `partner-entitlements` (docs/security/partner-auth-design.md 12, 28; slice S5, the Edge half of migration 0058), in the style of
// attest-shape.ts: unknown keys REJECTED, every value checked for its exact shape before any port is touched. Pure: no environment, no database, no logging.
//
//   GET  collect          ?facilityId=
//   POST handover/mint    { facilityId, entitlementId }
//   POST redeem           { facilityId, entitlementId, method, credential }
//                           method staff_scan:      credential is the player's check-in token jti (a uuid)
//                           method hand_over_token: credential is the hand-over token the player was shown (`gr_ho_` + 43 characters); the handler hashes it, the database only ever sees the hash
//   POST voucher          { facilityId, entitlementId }
//
// `offline_code` is not a method of this slice: it is refused here (400), and the database refuses it too (22023).

import { parseFacilityId, parseReadQuery } from "./attest-shape.ts";
import { parseUuid } from "./invites-shape.ts";
import { REDEEM_METHODS, type RedeemMethod } from "./ports.ts";
import { type ParseIssue, type ParseResult, plain, unknownKeys } from "./session-shape.ts";
import { PARTNER_HANDOVER_TOKEN_RE } from "./token.ts";

export function parseCollectQuery(url: string): ParseResult<{ readonly facilityId: string }> {
  const q = parseReadQuery(url, new Set(["facilityId"]));
  if (!q.ok) return q;
  const facilityId = parseFacilityId(q.value.get("facilityId"));
  if (facilityId === null) return { ok: false, issues: [{ path: "facilityId", message: "must be a facility id" }] };
  return { ok: true, value: { facilityId } };
}

export interface EntitlementRef {
  readonly facilityId: string;
  readonly entitlementId: string;
}

/** POST handover/mint and POST voucher: `{ facilityId, entitlementId }` and nothing else. */
export function parseEntitlementRefBody(raw: unknown): ParseResult<EntitlementRef> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["facilityId", "entitlementId"]), "", issues);
  const facilityId = parseFacilityId(raw.facilityId);
  const entitlementId = parseUuid(raw.entitlementId);
  if (facilityId === null) issues.push({ path: "facilityId", message: "must be a facility id" });
  if (entitlementId === null) issues.push({ path: "entitlementId", message: "must be a uuid" });
  if (issues.length > 0 || facilityId === null || entitlementId === null) return { ok: false, issues };
  return { ok: true, value: { facilityId, entitlementId } };
}

export interface RedeemBody extends EntitlementRef {
  readonly method: RedeemMethod;
  /** As the client sent it, lower-cased for a uuid: the jti for staff_scan, the hand-over token PLAINTEXT for hand_over_token. */
  readonly credential: string;
}

export function parseRedeemBody(raw: unknown): ParseResult<RedeemBody> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["facilityId", "entitlementId", "method", "credential"]), "", issues);
  const facilityId = parseFacilityId(raw.facilityId);
  const entitlementId = parseUuid(raw.entitlementId);
  const method = typeof raw.method === "string" && (REDEEM_METHODS as readonly string[]).includes(raw.method) ? (raw.method as RedeemMethod) : null;
  if (facilityId === null) issues.push({ path: "facilityId", message: "must be a facility id" });
  if (entitlementId === null) issues.push({ path: "entitlementId", message: "must be a uuid" });
  let credential: string | null = null;
  if (method === null) issues.push({ path: "method", message: "must be staff_scan or hand_over_token" });
  else if (method === "staff_scan") {
    credential = parseUuid(raw.credential);
    if (credential === null) issues.push({ path: "credential", message: "must be the check-in token id (a uuid)" });
  } else {
    credential = typeof raw.credential === "string" && PARTNER_HANDOVER_TOKEN_RE.test(raw.credential) ? raw.credential : null;
    if (credential === null) issues.push({ path: "credential", message: "must be a hand-over token" });
  }
  if (issues.length > 0 || facilityId === null || entitlementId === null || method === null || credential === null) return { ok: false, issues };
  return { ok: true, value: { facilityId, entitlementId, method, credential } };
}
