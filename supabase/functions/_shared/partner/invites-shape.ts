// supabase/functions/_shared/partner/invites-shape.ts
//
// Strict, hand-rolled validation of the CLIENT-SUBMITTED wire shapes of `partner-invites` (docs/security/partner-auth-design.md 4.5, 6.1; slice S1.5), in the style of session-shape.ts: no schema
// library, unknown keys REJECTED. Pure: no environment, no database, no logging.
//
//   POST invites                                { orgId, role, email }                 role: staff | manager | operator (sponsor invites are disabled); email: what the database accepts (3 to 254 characters, no whitespace, one @)
//   GET  invites                                ?orgId=<uuid>                          (the only query parameter, optional)
//   POST invites/accept/start                   { token }                              token: `gr_inv_` + 43 base64url characters
//   POST invites/accept/verify                  { token, code }                        code: the emailed one-time code, 6 to 10 digits
//   POST invites/accept                         { token }                              (branch E, a session)
//   POST enrolments/accept/start | verify       the same shapes with an `gr_enr_` token
//   POST credentials                            { userId, refKind, refId, challengeToken, credential }   what `accept/verify` returned, and the create ceremony (registration-shape.ts)

import { parseRegistration, type ParsedRegistration } from "./registration-shape.ts";
import { type ChallengeToken, type ParseIssue, type ParseResult, parseChallengeToken, plain, unknownKeys } from "./session-shape.ts";
import type { InviteRole, RegisterRefKind } from "./ports.ts";
import { PARTNER_ENROLMENT_TOKEN_RE, PARTNER_INVITE_TOKEN_RE } from "./token.ts";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CODE_RE = /^[0-9]{6,10}$/;
const INVITE_ROLES: ReadonlySet<string> = new Set(["staff", "manager", "operator"]);

/** A uuid in any case, lower-cased, or null. */
export function parseUuid(raw: unknown): string | null {
  return typeof raw === "string" && UUID_RE.test(raw) ? raw.toLowerCase() : null;
}

/** The address as the database will normalise it (lower(btrim)), or null for one the database would refuse (22023). */
export function normaliseEmail(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const v = raw.trim().toLowerCase();
  return v.length >= 3 && v.length <= 254 && !/\s/.test(v) && /^[^@]+@[^@]+$/.test(v) ? v : null;
}

export interface InviteCreateRequest {
  readonly orgId: string;
  readonly role: InviteRole;
  readonly email: string;
}

export function parseInviteCreateBody(raw: unknown): ParseResult<InviteCreateRequest> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["orgId", "role", "email"]), "", issues);
  const orgId = parseUuid(raw.orgId);
  if (orgId === null) issues.push({ path: "orgId", message: "must be a uuid" });
  if (typeof raw.role !== "string" || !INVITE_ROLES.has(raw.role)) issues.push({ path: "role", message: "must be staff, manager or operator" });
  const email = normaliseEmail(raw.email);
  if (email === null) issues.push({ path: "email", message: "must be an email address" });
  if (issues.length > 0 || orgId === null || email === null) return { ok: false, issues };
  return { ok: true, value: { orgId, role: raw.role as InviteRole, email } };
}

/** GET invites: the query string may hold `orgId` and nothing else. */
export function parseInviteListQuery(url: URL): ParseResult<{ readonly orgId: string | null }> {
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

export type TokenKind = "invite" | "enrolment";
const TOKEN_RE: Readonly<Record<TokenKind, RegExp>> = { invite: PARTNER_INVITE_TOKEN_RE, enrolment: PARTNER_ENROLMENT_TOKEN_RE };

/** `{ token }`: accept/start, and branch E. */
export function parseTokenBody(raw: unknown, kind: TokenKind): ParseResult<{ readonly token: string }> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["token"]), "", issues);
  if (typeof raw.token !== "string" || !TOKEN_RE[kind].test(raw.token)) issues.push({ path: "token", message: "malformed" });
  if (issues.length > 0) return { ok: false, issues };
  return { ok: true, value: { token: raw.token as string } };
}

/** `{ token, code }`: accept/verify. */
export function parseAcceptVerifyBody(raw: unknown, kind: TokenKind): ParseResult<{ readonly token: string; readonly code: string }> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["token", "code"]), "", issues);
  if (typeof raw.token !== "string" || !TOKEN_RE[kind].test(raw.token)) issues.push({ path: "token", message: "malformed" });
  if (typeof raw.code !== "string" || !CODE_RE.test(raw.code)) issues.push({ path: "code", message: "must be 6 to 10 digits" });
  if (issues.length > 0) return { ok: false, issues };
  return { ok: true, value: { token: raw.token as string, code: raw.code as string } };
}

export interface EnrolCredentialRequest {
  readonly userId: string;
  readonly refKind: RegisterRefKind;
  readonly refId: string;
  readonly token: ChallengeToken;
  readonly registration: ParsedRegistration;
}

/** POST credentials in enrolment mode. `refKind` is the wire word (`invite` or `enrolment`); the challenge is bound to all three of userId, refKind and refId, so a body that lies about them fails in the database. */
export function parseEnrolCredentialBody(raw: unknown): ParseResult<EnrolCredentialRequest> {
  if (!plain(raw)) return { ok: false, issues: [{ path: "", message: "expected a JSON object" }] };
  const issues: ParseIssue[] = [];
  unknownKeys(raw, new Set(["userId", "refKind", "refId", "challengeToken", "credential"]), "", issues);
  const userId = parseUuid(raw.userId);
  if (userId === null) issues.push({ path: "userId", message: "must be a uuid" });
  const refKind: RegisterRefKind | null = raw.refKind === "invite" ? 1 : raw.refKind === "enrolment" ? 2 : null;
  if (refKind === null) issues.push({ path: "refKind", message: "must be invite or enrolment" });
  const refId = parseUuid(raw.refId);
  if (refId === null) issues.push({ path: "refId", message: "must be a uuid" });
  const token = parseChallengeToken(raw.challengeToken);
  if (token === null) issues.push({ path: "challengeToken", message: "malformed" });
  const registration = parseRegistration(raw.credential, issues);
  if (issues.length > 0 || userId === null || refKind === null || refId === null || token === null || registration === null) return { ok: false, issues };
  return { ok: true, value: { userId, refKind, refId, token, registration } };
}
