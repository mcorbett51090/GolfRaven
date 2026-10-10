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
