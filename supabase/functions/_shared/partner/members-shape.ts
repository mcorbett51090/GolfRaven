// supabase/functions/_shared/partner/members-shape.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shapes of `partner-members` (docs/security/partner-auth-design.md 4.5, 6.5; slice S1.5), in the style of session-shape.ts: unknown keys
// REJECTED. The ids in a path (`members/{id}`, `orgs/{id}`, `credentials/{id}`) are matched by the router, which accepts a uuid and nothing else. Pure: no environment, no database, no logging.
//
//   POST members/{id}/revoke              { orgId }                  ONE membership of the person
//   POST members/{id}/recover             {}
//   POST members/{id}/pin-reset           {}
//   POST members/{id}/totp-reset          {}
//   POST orgs/{id}/sessions/revoke-all    { createdAfter? }          an ISO instant: every credential of the covered members created after it is revoked as well
//   POST admin/enrolments                 { userId }                 another admin
//   POST credentials/options              {}
//   POST credentials                      { challengeToken, credential }   (registration-shape.ts)
//   PATCH credentials/{id}                { note }                  display-only; null/"" clears; at most 40 characters
//   GET  credentials                      ?userId?                  own (absent), or a person under the 6.5 reach rule
//   GET  members                          ?orgId?                   active roster in manager/operator facility scope

import { parseUuid } from "./invites-shape.ts";
import { type ParseIssue, type ParseResult, plain, unknownKeys } from "./session-shape.ts";

const ISO_INSTANT_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,3})?Z$/;

export function parseMemberRevokeBody(raw: unknown): ParseResult<{ readonly orgId: string }> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["orgId"]), "", issues);
  const orgId = parseUuid(raw.orgId);
  if (orgId === null) issues.push({ path: "orgId", message: "must be a uuid" });
  if (issues.length > 0 || orgId === null) return { ok: false, issues };
  return { ok: true, value: { orgId } };
}

/** `{ createdAfter? }`: absent or null means sessions only; otherwise a UTC instant (`2030-01-01T12:00:00Z`, optional milliseconds) that is a real date. */
export function parseRevokeAllBody(raw: unknown): ParseResult<{ readonly createdAfter: string | null }> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["createdAfter"]), "", issues);
  let createdAfter: string | null = null;
  if (raw.createdAfter !== undefined && raw.createdAfter !== null) {
    const t = typeof raw.createdAfter === "string" && ISO_INSTANT_RE.test(raw.createdAfter) ? new Date(raw.createdAfter) : null;
    // a date that does not exist (2030-02-30) is rolled forward by Date, not refused: the instant must read back as the same date and time
    if (t === null || Number.isNaN(t.getTime()) || t.toISOString().slice(0, 19) !== (raw.createdAfter as string).slice(0, 19)) issues.push({ path: "createdAfter", message: "must be a UTC instant such as 2030-01-01T12:00:00Z" });
    else createdAfter = t.toISOString();
  }
  if (issues.length > 0) return { ok: false, issues };
  return { ok: true, value: { createdAfter } };
}

export function parseAdminEnrolmentBody(raw: unknown): ParseResult<{ readonly userId: string }> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["userId"]), "", issues);
  const userId = parseUuid(raw.userId);
  if (userId === null) issues.push({ path: "userId", message: "must be a uuid" });
  if (issues.length > 0 || userId === null) return { ok: false, issues };
  return { ok: true, value: { userId } };
}

/** GET members: the query string may hold `orgId` (uuid) and nothing else. Absent → every in-scope org. */
export function parseMemberListQuery(url: URL): ParseResult<{ readonly orgId: string | null }> {
  const issues: ParseIssue[] = [];
  for (const k of new Set(url.searchParams.keys())) if (k !== "orgId") issues.push({ path: k, message: "unknown query parameter" });
  const all = url.searchParams.getAll("orgId");
  let orgId: string | null = null;
  if (all.length > 1) issues.push({ path: "orgId", message: "given more than once" });
  else if (all.length === 1) {
    orgId = parseUuid(all[0]);
    if (orgId === null) issues.push({ path: "orgId", message: "must be a uuid" });
  }
  return issues.length > 0 ? { ok: false, issues } : { ok: true, value: { orgId } };
}

/** GET credentials: the query string may hold `userId` (uuid) and nothing else. Absent → the signed-in person. */
export function parseCredentialListQuery(url: URL): ParseResult<{ readonly userId: string | null }> {
  const issues: ParseIssue[] = [];
  for (const k of new Set(url.searchParams.keys())) if (k !== "userId") issues.push({ path: k, message: "unknown query parameter" });
  const all = url.searchParams.getAll("userId");
  let userId: string | null = null;
  if (all.length > 1) issues.push({ path: "userId", message: "given more than once" });
  else if (all.length === 1) {
    userId = parseUuid(all[0]);
    if (userId === null) issues.push({ path: "userId", message: "must be a uuid" });
  }
  return issues.length > 0 ? { ok: false, issues } : { ok: true, value: { userId } };
}

/** `{ note }`: string (trimmed; at most 40) or null/"" to clear. Unknown keys refused. */
export function parseCredentialNoteBody(raw: unknown): ParseResult<{ readonly note: string | null }> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["note"]), "", issues);
  if (!("note" in raw)) {
    issues.push({ path: "note", message: "required" });
    return { ok: false, issues };
  }
  if (raw.note === null) {
    if (issues.length > 0) return { ok: false, issues };
    return { ok: true, value: { note: null } };
  }
  if (typeof raw.note !== "string") {
    issues.push({ path: "note", message: "must be a string or null" });
    return { ok: false, issues };
  }
  const trimmed = raw.note.trim();
  if (trimmed.length > 40) {
    issues.push({ path: "note", message: "at most 40 characters" });
    return { ok: false, issues };
  }
  if (issues.length > 0) return { ok: false, issues };
  return { ok: true, value: { note: trimmed.length === 0 ? null : trimmed } };
}
