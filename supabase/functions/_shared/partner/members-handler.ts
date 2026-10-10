// supabase/functions/_shared/partner/members-handler.ts
//
// The `partner-members` handler (docs/security/partner-auth-design.md 4.5, 6.4, 6.5, 8, 22.4; slice S1.5, the Edge half of migration 0054). Pure and unit-testable like session-handler.ts: the database
// (`PartnerDb`) and the WebAuthn wrapper (`RegistrationVerifier`) are PORTS (`ports.ts`); this file reads no environment, opens no connection, imports no library and writes no log line (PA-11).
// EVERY route here is a session route: the reach rule (6.5), the class (A0 / A2 / A3) and the scope are the database's, decided inside the `_for_partner` definer; a person outside the actor's reach is a 42501
// (a 403), never a returned status the caller could use to map who exists.
//
// ROUTES (relative to the function; `POST members/{id}/revoke` is `/partner-members/members/{id}/revoke`):
//   POST members/{id}/revoke             { orgId }: revoke ONE membership (class A2)
//   POST members/{id}/recover            {}: revoke every credential and session of the person, set the PIN to must_change, issue a 24 h `gr_enr_` recovery token (class A2). The token is returned ONCE, to the manager
//   POST members/{id}/pin-reset          {}: clear the lock and every failure counter, set must_change (class A2)
//   POST members/{id}/totp-reset         {}: reset an operator's or admin's TOTP under the reach rule (class A3)
//   POST orgs/{id}/sessions/revoke-all   { createdAfter? }: the stolen-iPad button (class A2)
//   POST admin/enrolments                { userId }: an admin issues an enrolment token for ANOTHER admin (class A3). Returned once
//   GET  credentials                     the signed-in person's own credentials (class A0)
//   POST credentials/options             {}: create options for a SECOND credential (class A2 + reauth)
//   POST credentials                     { challengeToken, credential }: register a second credential (class A2 + reauth)
//   DELETE credentials/{id}              revoke a credential, one's own included (class A2); another person's under the reach rule
//
// THE ORDER, for every request: (1) the Origin check, before routing and for every method; (2) `OPTIONS` is answered here, with no port touched; (3) the route and the method (404 / 405); (4) the bearer:
// exactly `gr_ps_` + 43 characters, else the ONE 401 with no port touched; (5) the exact JSON media type (415) and the strict body (400); (6) the work.
//
// COMMIT ON EVERY STATUS (PA-14): a refusal the database returns commits with the rest of its transaction; the response is built AFTER the transaction. A 42501 (outside reach or scope) and 22023 (a malformed
// argument, such as acting on oneself) throw: nothing was written.

import { Errors } from "../http.ts";
import { decideOrigin, preflightResponse } from "./cors.ts";
import {
  assertSameOrigin,
  bearerHash,
  type Decision,
  emptyBody,
  mapPartnerError,
  matchRoute,
  methodRefusal,
  rateLimited,
  registrationRefusal,
  routeOfFunction,
  type RouteSpec,
} from "./handler-kit.ts";
import { partnerError, partnerOk, readPartnerJsonBody, runPartnerHandler, unauthenticated } from "./http.ts";
import { parseAdminEnrolmentBody, parseMemberRevokeBody, parseRevokeAllBody } from "./members-shape.ts";
import { type CredentialView, type PartnerDb, PartnerNotConfigured, type RegistrationVerifier } from "./ports.ts";
import { parseSecondCredentialBody } from "./registration-shape.ts";
import { formatChallengeToken } from "./session-handler.ts";
import { uuidToBytes } from "./session-shape.ts";
import type { NewSessionToken } from "./token.ts";

export const PARTNER_MEMBERS_FUNCTION = "partner-members";
/** Design 8: credential add and revoke are 10 attempts per member per hour (a hard, member-keyed bucket, hit in its own short transaction). */
export const CREDENTIAL_PER_MEMBER_PER_HOUR = 10;
export const CREDENTIAL_BUCKET = "partner-credential:member";

export interface PartnerMembersDeps {
  readonly db: PartnerDb;
  /** The one allowed origin (privileged.ts#loadPartnerCorsOrigin), or null when none is configured. It is also the origin of the enrolment link. */
  readonly allowedOrigin: string | null;
  readonly registration: RegistrationVerifier;
  readonly nowMs: () => number;
  /** A fresh `gr_enr_` token: the recovery and admin enrolment tokens. */
  readonly newEnrolmentToken: () => Promise<NewSessionToken>;
  readonly timeoutMs?: number;
}

const ROUTES: readonly RouteSpec[] = [
  { name: "member-revoke", path: "members/{id}/revoke", methods: ["POST"], session: true },
  { name: "member-recover", path: "members/{id}/recover", methods: ["POST"], session: true },
  { name: "member-pin-reset", path: "members/{id}/pin-reset", methods: ["POST"], session: true },
  { name: "member-totp-reset", path: "members/{id}/totp-reset", methods: ["POST"], session: true },
  { name: "org-revoke-all", path: "orgs/{id}/sessions/revoke-all", methods: ["POST"], session: true },
  { name: "admin-enrolments", path: "admin/enrolments", methods: ["POST"], session: true },
  { name: "credential-options", path: "credentials/options", methods: ["POST"], session: true },
  { name: "credentials", path: "credentials", methods: ["GET", "POST"], session: true },
  { name: "credential", path: "credentials/{id}", methods: ["DELETE"], session: true },
];

export async function handlePartnerMembersRequest(req: Request, deps: PartnerMembersDeps): Promise<Response> {
  // (1) the Origin check, before routing, for every method
  const decision = decideOrigin(req.headers, deps.allowedOrigin);
  if (decision.kind === "refused") return partnerError({ kind: "none" }, 403, "forbidden", "origin not allowed");
  // (2) the preflight: answered here, nothing else is touched (PA-10: no database connection)
  if (req.method === "OPTIONS") return preflightResponse(decision);

  return await runPartnerHandler(
    decision,
    async () => {
      try {
        // (3) the route and the method
        const matched = matchRoute(ROUTES, routeOfFunction(req.url, PARTNER_MEMBERS_FUNCTION));
        if (matched === null) return partnerError(decision, 404, "not_found", "not found");
        const refusal = methodRefusal(decision, matched, req.method);
        if (refusal !== null) return refusal;

        // (4) every route is a session route: anything but a gr_ps_ bearer is the one 401, and no port is touched
        const tokenHash = await bearerHash(req.headers);
        if (tokenHash === null) return unauthenticated(decision);
        const id = matched.ids[0] ?? "";

        switch (matched.spec.name) {
          case "member-revoke":
            return await handleMemberRevoke(req, deps, decision, tokenHash, id);
          case "member-recover":
            return await handleRecover(req, deps, decision, tokenHash, id);
          case "member-pin-reset": {
            await emptyBody(req);
            const status = await deps.db.withMembers(tokenHash, (s) => s.pinReset(id));
            return status === "ok" ? partnerOk(decision, 200, { reset: true }) : partnerError(decision, 409, "pin_not_set", "this person has no PIN");
          }
          case "member-totp-reset": {
            await emptyBody(req);
            const r = await deps.db.withMembers(tokenHash, (s) => s.totpReset(id));
            return r.status === "ok" ? partnerOk(decision, 200, { reset: true }) : partnerError(decision, 409, "totp_not_set", "this person has no TOTP");
          }
          case "org-revoke-all":
            return await handleRevokeAll(req, deps, decision, tokenHash, id);
          case "admin-enrolments":
            return await handleAdminEnrolment(req, deps, decision, tokenHash);
          case "credential-options":
            return await handleCredentialOptions(req, deps, decision, tokenHash);
          case "credentials":
            return req.method === "POST" ? await handleCredentialRegister(req, deps, decision, tokenHash) : await handleCredentialList(deps, decision, tokenHash);
          case "credential":
            return await handleCredentialRevoke(deps, decision, tokenHash, id);
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

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

async function handleMemberRevoke(req: Request, deps: PartnerMembersDeps, decision: Decision, tokenHash: string, targetUserId: string): Promise<Response> {
  const parsed = parseMemberRevokeBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const status = await deps.db.withMembers(tokenHash, (s) => s.memberRevoke(targetUserId, parsed.value.orgId));
  return status === "ok" ? partnerOk(decision, 200, { revoked: true }) : partnerError(decision, 404, "not_found", "not found");
}

/** The enrolment link: the token rides in the fragment, which no server ever receives. The origin is checked BEFORE the definer runs, so a missing configuration never leaves a recovery done and no way to deliver it. */
function enrolOrigin(deps: PartnerMembersDeps): string {
  if (deps.allowedOrigin === null) throw new PartnerNotConfigured();
  return deps.allowedOrigin;
}

async function handleRecover(req: Request, deps: PartnerMembersDeps, decision: Decision, tokenHash: string, targetUserId: string): Promise<Response> {
  await emptyBody(req);
  const origin = enrolOrigin(deps);
  const fresh = await deps.newEnrolmentToken();
  const r = await deps.db.withMembers(tokenHash, (s) => s.memberRecover(targetUserId, fresh.hash));
  if (r.status !== "ok") return partnerError(decision, 409, "no_email", "this person has no email address to recover to");
  return partnerOk(decision, 201, { tokenId: r.tokenId, expiresAt: r.expiresAt, token: fresh.token, enrolUrl: `${origin}/enrol#${fresh.token}` });
}

async function handleRevokeAll(req: Request, deps: PartnerMembersDeps, decision: Decision, tokenHash: string, orgId: string): Promise<Response> {
  const parsed = parseRevokeAllBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const r = await deps.db.withMembers(tokenHash, (s) => s.orgSessionsRevokeAll(orgId, parsed.value.createdAfter));
  if (r.status !== "ok") return partnerError(decision, 404, "not_found", "not found");
  return partnerOk(decision, 200, { revokedSessions: r.sessions, revokedCredentials: r.credentials });
}

async function handleAdminEnrolment(req: Request, deps: PartnerMembersDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseAdminEnrolmentBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const origin = enrolOrigin(deps);
  const fresh = await deps.newEnrolmentToken();
  const r = await deps.db.withMembers(tokenHash, (s) => s.adminEnrolmentIssue(parsed.value.userId, fresh.hash));
  return partnerOk(decision, 201, { tokenId: r.tokenId, expiresAt: r.expiresAt, token: fresh.token, enrolUrl: `${origin}/enrol#${fresh.token}` });
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Credentials of a signed-in person
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

function credentialBody(c: CredentialView): Record<string, unknown> {
  return {
    id: c.id,
    label: c.label,
    note: c.note,
    createdAt: c.createdAt,
    lastUsedAt: c.lastUsedAt,
    revokedAt: c.revokedAt,
    backupEligible: c.backupEligible,
    backupState: c.backupState,
  };
}

async function handleCredentialList(deps: PartnerMembersDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const credentials = await deps.db.withMembers(tokenHash, (s) => s.credentialList());
  return partnerOk(decision, 200, { credentials: credentials.map(credentialBody) });
}

async function credentialLimit(deps: PartnerMembersDeps, decision: Decision, tokenHash: string): Promise<Response | null> {
  const limit = await deps.db.hitRateLimit(tokenHash, CREDENTIAL_BUCKET, 3600, CREDENTIAL_PER_MEMBER_PER_HOUR);
  return limit.ok ? null : rateLimited(decision, "too many credential changes", limit.retryAfterSeconds);
}

async function handleCredentialOptions(req: Request, deps: PartnerMembersDeps, decision: Decision, tokenHash: string): Promise<Response> {
  await emptyBody(req);
  const limited = await credentialLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const out = await deps.db.withMembers(tokenHash, async (s) => {
    const r = await s.credentialOptions();
    if (r.status !== "ok") return r;
    assertSameOrigin(deps.allowedOrigin, r.rp);
    return { ...r, subject: await s.credentialSubject() };
  });
  if (out.status !== "ok") return partnerError(decision, 409, "too_many", "this person already holds the most credentials allowed");
  const userHandle = uuidToBytes(out.subject.userId);
  if (userHandle === null) throw new Error("the signed-in person id is not a uuid");
  const options = await deps.registration.options({
    rp: out.rp,
    userHandle,
    userName: out.subject.email ?? out.subject.userId,
    challenge: out.challenge.nonce,
    excludeCredentialIds: out.excludeCredentialIds,
  });
  return partnerOk(decision, 200, { options, challengeToken: formatChallengeToken(out.challenge), expiresAt: new Date(out.challenge.exp * 1000).toISOString() });
}

async function handleCredentialRegister(req: Request, deps: PartnerMembersDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseSecondCredentialBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const { token, registration } = parsed.value;
  const limited = await credentialLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  if (token.exp * 1000 <= deps.nowMs()) return registrationRefusal(decision, "expired");
  // the relying party is the minter's to read (edge_partner cannot), in its own short transaction; the ceremony is verified with NO transaction open, and only then does the A2 definer run (its PIN grant is short-lived)
  const rp = await deps.db.withMint((m) => m.rpConfig());
  assertSameOrigin(deps.allowedOrigin, rp);
  const verified = await deps.registration.verify({ rp, response: registration.json, expectedChallenge: token.nonce });
  if (!verified.ok) return registrationRefusal(decision, "refused");
  const r = await deps.db.withMembers(tokenHash, (s) =>
    s.credentialRegister({
      nonce: token.nonce,
      exp: token.exp,
      mac: token.mac,
      attestationObject: registration.attestationObject,
      clientDataJson: registration.clientDataJson,
      credentialId: verified.credentialId,
      publicKey: verified.publicKey,
      transports: verified.transports,
    }),
  );
  if (r.status !== "ok" || r.credentialId === null) return registrationRefusal(decision, r.status);
  return partnerOk(decision, 201, { credentialId: r.credentialId });
}

async function handleCredentialRevoke(deps: PartnerMembersDeps, decision: Decision, tokenHash: string, credentialId: string): Promise<Response> {
  const limited = await credentialLimit(deps, decision, tokenHash);
  if (limited !== null) return limited;
  const status = await deps.db.withMembers(tokenHash, (s) => s.credentialRevoke(credentialId));
  switch (status) {
    case "ok":
      return partnerOk(decision, 200, { revoked: true });
    case "not_found":
      return partnerError(decision, 404, "not_found", "not found");
    default:
      return partnerError(decision, 409, "already_revoked", "this credential has already been revoked");
  }
}
