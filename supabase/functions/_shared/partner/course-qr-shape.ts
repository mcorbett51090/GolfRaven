// supabase/functions/_shared/partner/course-qr-shape.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shapes of `course-qr` and `qr-print` (docs/security/partner-auth-design.md 4.2, 6.3, S2b; migration 0055), in the style of session-shape.ts: unknown
// keys REJECTED. Pure: no environment, no database, no logging.
//
//   GET  course-qr/pin?facilityId=<id>           today's PIN (class A0)
//   POST course-qr/pin/rotate    { facilityId }  "Rotate PIN" (class A2)
//   POST course-qr/tokens        { facilityId }  "Marker sold": mint a rotating token (class A1)
//   POST course-qr/tokens/refresh { facilityId, nonceHash }   the sale screen's 30 s heartbeat for ONE token this person's own mint created (class A0_KEEPALIVE)
//   GET  qr-print?facilityId=<id>                the registered printed QR (class A0, operator or admin)
//   POST qr-print                { facilityId }  sign and register the printed QR (class A3)
//
//   facilityId  the CATALOG id of the facility (`fac_...`): 1 to 128 characters of `A-Z a-z 0-9 _ . : -`, the same set the token's `fac` claim allows (format.ts), so an id that could not be put in a token is not accepted.
//   nonceHash   64 lower-case hex characters: hex(SHA-256(the 16 raw nonce bytes)) of the token the screen is showing.

import { type ParseIssue, type ParseResult, plain, unknownKeys } from "./session-shape.ts";

const FACILITY_ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
const NONCE_HASH_RE = /^[0-9a-f]{64}$/;

export function parseFacilityId(raw: unknown): string | null {
  return typeof raw === "string" && FACILITY_ID_RE.test(raw) ? raw : null;
}

export function parseNonceHash(raw: unknown): string | null {
  return typeof raw === "string" && NONCE_HASH_RE.test(raw) ? raw : null;
}

/** `{ facilityId }`: pin/rotate, tokens, and the qr-print POST. */
export function parseFacilityBody(raw: unknown): ParseResult<{ readonly facilityId: string }> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["facilityId"]), "", issues);
  const facilityId = parseFacilityId(raw.facilityId);
  if (facilityId === null) issues.push({ path: "facilityId", message: "must be a facility id" });
  if (issues.length > 0 || facilityId === null) return { ok: false, issues };
  return { ok: true, value: { facilityId } };
}

/** `{ facilityId, nonceHash }`: the token refresh. */
export function parseRefreshBody(raw: unknown): ParseResult<{ readonly facilityId: string; readonly nonceHash: string }> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["facilityId", "nonceHash"]), "", issues);
  const facilityId = parseFacilityId(raw.facilityId);
  if (facilityId === null) issues.push({ path: "facilityId", message: "must be a facility id" });
  const nonceHash = parseNonceHash(raw.nonceHash);
  if (nonceHash === null) issues.push({ path: "nonceHash", message: "must be 64 lower-case hex characters" });
  if (issues.length > 0 || facilityId === null || nonceHash === null) return { ok: false, issues };
  return { ok: true, value: { facilityId, nonceHash } };
}

/** A GET whose only query parameter is `facilityId`, given once. */
export function parseFacilityQuery(url: URL): ParseResult<{ readonly facilityId: string }> {
  const issues: ParseIssue[] = [];
  for (const k of new Set(url.searchParams.keys())) if (k !== "facilityId") issues.push({ path: k, message: "unknown query parameter" });
  const all = url.searchParams.getAll("facilityId");
  if (all.length !== 1) issues.push({ path: "facilityId", message: all.length === 0 ? "required" : "given more than once" });
  const facilityId = all.length === 1 ? parseFacilityId(all[0]) : null;
  if (all.length === 1 && facilityId === null) issues.push({ path: "facilityId", message: "must be a facility id" });
  if (issues.length > 0 || facilityId === null) return { ok: false, issues };
  return { ok: true, value: { facilityId } };
}
