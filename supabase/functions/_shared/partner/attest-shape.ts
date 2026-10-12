// supabase/functions/_shared/partner/attest-shape.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shapes of `partner-attest` (docs/security/partner-auth-design.md 26; slice S3, the Edge half of migration 0056), in the style of
// members-shape.ts: unknown keys REJECTED, every value checked for its exact shape before any port is touched. Pure: no environment, no database, no logging.
//
//   POST attest           { facilityId, kind, token }          the ONLINE path: `token` is the player's check-in token jti (a uuid); the player is the token's owner, never named here
//   POST attest/offline   { facilityId, kind, handle, code }   the offline code: the player's handle and the six digits the player's app showed
//   GET  shift-log        ?facilityId=
//   GET  staff-activity   ?facilityId=&days=                   days 1 to 90 (default 7)
//
// The six digits are validated for SHAPE only. They are never compared here: the verification is a definer's, so the Edge never holds a seed or an expected code (money doc, step 3).

import { parseUuid } from "./invites-shape.ts";
import { ATTEST_KINDS, type AttestKind } from "./ports.ts";
import { type ParseIssue, type ParseResult, plain, unknownKeys } from "./session-shape.ts";

/** A catalog facility id: letters, digits, `_`, `.`, `-`; 1 to 80 characters. */
const FACILITY_RE = /^[A-Za-z0-9_.-]{1,80}$/;
/** A player handle (app.profile.handle's own CHECK). */
const HANDLE_RE = /^[a-z0-9_]{3,20}$/;
const CODE_RE = /^[0-9]{6}$/;

export function parseFacilityId(v: unknown): string | null {
  return typeof v === "string" && FACILITY_RE.test(v) ? v : null;
}

function parseKind(v: unknown): AttestKind | null {
  return typeof v === "string" && (ATTEST_KINDS as readonly string[]).includes(v) ? (v as AttestKind) : null;
}

export interface OnlineAttestBody {
  readonly facilityId: string;
  readonly kind: AttestKind;
  readonly token: string;
}

export function parseOnlineAttestBody(raw: unknown): ParseResult<OnlineAttestBody> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["facilityId", "kind", "token"]), "", issues);
  const facilityId = parseFacilityId(raw.facilityId);
  const kind = parseKind(raw.kind);
  const token = parseUuid(raw.token);
  if (facilityId === null) issues.push({ path: "facilityId", message: "must be a facility id" });
  if (kind === null) issues.push({ path: "kind", message: "must be presence or marker_purchase" });
  if (token === null) issues.push({ path: "token", message: "must be a uuid" });
  if (issues.length > 0 || facilityId === null || kind === null || token === null) return { ok: false, issues };
  return { ok: true, value: { facilityId, kind, token } };
}

export interface OfflineAttestBody {
  readonly facilityId: string;
  readonly kind: AttestKind;
  readonly handle: string;
  readonly code: string;
}

export function parseOfflineAttestBody(raw: unknown): ParseResult<OfflineAttestBody> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["facilityId", "kind", "handle", "code"]), "", issues);
  const facilityId = parseFacilityId(raw.facilityId);
  const kind = parseKind(raw.kind);
  // a handle is lower-case by its own CHECK; a typed one is trimmed and lower-cased before it is judged (the staff member types what the player reads out)
  const handle = typeof raw.handle === "string" && HANDLE_RE.test(raw.handle.trim().toLowerCase()) ? raw.handle.trim().toLowerCase() : null;
  const code = typeof raw.code === "string" && CODE_RE.test(raw.code) ? raw.code : null;
  if (facilityId === null) issues.push({ path: "facilityId", message: "must be a facility id" });
  if (kind === null) issues.push({ path: "kind", message: "must be presence or marker_purchase" });
  if (handle === null) issues.push({ path: "handle", message: "must be a player handle" });
  if (code === null) issues.push({ path: "code", message: "must be six digits" });
  if (issues.length > 0 || facilityId === null || kind === null || handle === null || code === null) return { ok: false, issues };
  return { ok: true, value: { facilityId, kind, handle, code } };
}

/** The query of a GET: only the named keys, each at most once. */
export function parseReadQuery(url: string, allowed: ReadonlySet<string>): ParseResult<URLSearchParams> {
  const params = new URL(url).searchParams;
  const issues: ParseIssue[] = [];
  for (const k of new Set(params.keys())) {
    if (!allowed.has(k)) issues.push({ path: k, message: "unknown query parameter" });
    else if (params.getAll(k).length > 1) issues.push({ path: k, message: "must appear once" });
  }
  if (issues.length > 0) return { ok: false, issues };
  return { ok: true, value: params };
}

export function parseShiftLogQuery(url: string): ParseResult<{ readonly facilityId: string }> {
  const q = parseReadQuery(url, new Set(["facilityId"]));
  if (!q.ok) return q;
  const facilityId = parseFacilityId(q.value.get("facilityId"));
  if (facilityId === null) return { ok: false, issues: [{ path: "facilityId", message: "must be a facility id" }] };
  return { ok: true, value: { facilityId } };
}

export function parseStaffActivityQuery(url: string): ParseResult<{ readonly facilityId: string; readonly days: number }> {
  const q = parseReadQuery(url, new Set(["facilityId", "days"]));
  if (!q.ok) return q;
  const issues: ParseIssue[] = [];
  const facilityId = parseFacilityId(q.value.get("facilityId"));
  if (facilityId === null) issues.push({ path: "facilityId", message: "must be a facility id" });
  const rawDays = q.value.get("days");
  let days = 7;
  if (rawDays !== null) {
    if (!/^[0-9]{1,2}$/.test(rawDays) || Number(rawDays) < 1 || Number(rawDays) > 90) issues.push({ path: "days", message: "must be a whole number of days from 1 to 90" });
    else days = Number(rawDays);
  }
  if (issues.length > 0 || facilityId === null) return { ok: false, issues };
  return { ok: true, value: { facilityId, days } };
}
