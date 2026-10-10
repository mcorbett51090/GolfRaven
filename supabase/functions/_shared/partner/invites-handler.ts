// supabase/functions/_shared/partner/invites-handler.ts
//
// The `partner-invites` handler (docs/security/partner-auth-design.md 4.5, 6.1, 8, 22.4; slice S1.5, the Edge half of migration 0054). Pure and unit-testable like session-handler.ts: the database
// (`PartnerDb`), the WebAuthn wrapper (`RegistrationVerifier`) and the two email-OTP ports are PORTS (`ports.ts`); this file reads no environment, opens no connection, imports no library and writes no
// log line (PA-11).
//
// ROUTES (relative to the function; `POST invites` is `/partner-invites/invites`):
//   POST invites                   { orgId, role, email }: create an invite (class A2). Returns the `gr_inv_` token ONCE, with the link; only its SHA-256 reaches the database
//   GET  invites                   ?orgId: the invites the actor's scope covers (class A0)
//   DELETE invites/{id}            revoke an unaccepted invite (class A2)
//   POST invites/accept/start      { token }: mails a one-time code to the address ON the invite (never a typed one). A CONSTANT body whatever the token is: neither an invite-existence nor an email oracle
//   POST invites/accept/verify     { token, code }: verifyOtp (anon key), THEN private.partner_invite_accept, and only AFTER it returns the GoTrue session is closed (in a `finally`). Branch N: the register challenge
//   POST invites/accept            { token }: branch E (a session, class A2): an existing member with a credential joins another org
//   POST enrolments/accept/start   { token }: the same, for a recovery or admin enrolment token (`gr_enr_`); the code goes to the person's own address
//   POST enrolments/accept/verify  { token, code }: private.partner_enrolment_token_accept
//   POST credentials               { userId, refKind, refId, challengeToken, credential }: the FIRST credential (no bearer): the wrapper verifies the create ceremony, then private.partner_credential_register_first,
//                                  which stores it and mints the person's first session in the same transaction. The `gr_ps_` token comes back exactly once, in a 201
//
// THE ORDER, for every request: (1) the Origin check, before routing and for every method (a foreign Origin is a 403 whatever CORS does); (2) `OPTIONS` is answered here, with no port touched; (3) the route
// and the method (404 / 405); (4) for a session route, the bearer: exactly `gr_ps_` + 43 characters, else the ONE 401 with no port touched; (5) the exact JSON media type (415) and the strict body (400); (6) the work.
//
// COMMIT ON EVERY STATUS (PA-14): a refusal the database makes (a mismatch, a locked invite, `existing_member_sign_in`, `recover_required`) is a RETURNED row, so the transaction commits and the attempt count
// commits with it; the response is built AFTER the transaction. Only a malformed argument, a deploy fault or an unexpected error throws (and rolls back).
//
// NO ORACLE BEFORE THE MAILBOX IS PROVEN. `accept/start` answers one constant body. `accept/verify` answers ONE 403 for: an unknown or dead token, a wrong or expired code, a rate-limited token, a GoTrue session
// the database does not accept, and every database refusal (a mismatch, a lock, a stale session). Only two states are told apart, and only the owner of the invited mailbox (the code was just proved) can reach
// them: `existing_member_sign_in` and `recover_required`, both 409.

import { Errors } from "../http.ts";
import { decideOrigin, preflightResponse } from "./cors.ts";
import {
  assertSameOrigin,
  bearerHash,
  type Decision,
  mapPartnerError,
  matchRoute,
  methodRefusal,
  rateLimited,
  registrationRefusal,
  routeOfFunction,
  type RouteSpec,
} from "./handler-kit.ts";
import { partnerError, partnerOk, readPartnerJsonBody, runPartnerHandler, unauthenticated } from "./http.ts";
import {
  parseAcceptVerifyBody,
  parseEnrolCredentialBody,
  parseInviteCreateBody,
  parseInviteListQuery,
  parseTokenBody,
  type TokenKind,
} from "./invites-shape.ts";
import {
  type ChallengeIssue,
  type EmailOtpPort,
  type InviteView,
  PartnerNotConfigured,
  type PartnerDb,
  type RegistrationVerifier,
  type RpConfig,
} from "./ports.ts";
import { formatChallengeToken } from "./session-handler.ts";
import { uuidToBytes } from "./session-shape.ts";
import { type NewSessionToken, sha256Hex } from "./token.ts";

export const PARTNER_INVITES_FUNCTION = "partner-invites";
/** Design 8: 20 invites a day per inviter (a hard, member-keyed bucket) and 3 a day per invitee address (a system bucket keyed on the address's hash). */
export const INVITE_CREATE_PER_MEMBER_PER_DAY = 20;
export const INVITE_CREATE_BUCKET = "partner-invite-create:member";
export const INVITE_CREATE_PER_EMAIL_PER_DAY = 3;
/** Design 8: 3 code sends and 10 code attempts per token per hour (system buckets keyed on the token's hash; hit only for a token that EXISTS, so an attacker cannot grow the table with made-up tokens). */
export const ACCEPT_START_PER_TOKEN_PER_HOUR = 3;
export const ACCEPT_VERIFY_PER_TOKEN_PER_HOUR = 10;

export interface PartnerInvitesDeps {
  readonly db: PartnerDb;
  /** The one allowed origin (privileged.ts#loadPartnerCorsOrigin), or null when none is configured. It is also the origin of the invite link. */
  readonly allowedOrigin: string | null;
  readonly registration: RegistrationVerifier;
  /** The email OTP of an INVITE: the invitee has no account yet, so GoTrue may create it (the invite, which names the address, is the authority). */
  readonly inviteOtp: EmailOtpPort;
  /** The email OTP of an enrolment token: the person's account exists. */
  readonly enrolmentOtp: EmailOtpPort;
  readonly nowMs: () => number;
  readonly newSessionToken: () => Promise<NewSessionToken>;
  readonly newInviteToken: () => Promise<NewSessionToken>;
  readonly timeoutMs?: number;
}

const ROUTES: readonly RouteSpec[] = [
  { name: "invites", path: "invites", methods: ["GET", "POST"], session: true },
  { name: "invite", path: "invites/{id}", methods: ["DELETE"], session: true },
  { name: "invite-accept-start", path: "invites/accept/start", methods: ["POST"], session: false },
  { name: "invite-accept-verify", path: "invites/accept/verify", methods: ["POST"], session: false },
  { name: "invite-accept", path: "invites/accept", methods: ["POST"], session: true },
  { name: "enrolment-accept-start", path: "enrolments/accept/start", methods: ["POST"], session: false },
  { name: "enrolment-accept-verify", path: "enrolments/accept/verify", methods: ["POST"], session: false },
  { name: "credentials", path: "credentials", methods: ["POST"], session: false },
];

export async function handlePartnerInvitesRequest(req: Request, deps: PartnerInvitesDeps): Promise<Response> {
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
        const matched = matchRoute(ROUTES, routeOfFunction(req.url, PARTNER_INVITES_FUNCTION));
        if (matched === null) return partnerError(decision, 404, "not_found", "not found");
        const refusal = methodRefusal(decision, matched, req.method);
        if (refusal !== null) return refusal;

        // (4) a session route needs a gr_ps_ bearer: anything else is the one 401, and no port is touched
        let tokenHash = "";
        if (matched.spec.session) {
          const h = await bearerHash(req.headers);
          if (h === null) return unauthenticated(decision);
          tokenHash = h;
        }

        switch (matched.spec.name) {
          case "invites":
            return req.method === "POST" ? await handleInviteCreate(req, deps, decision, tokenHash) : await handleInviteList(req, deps, decision, tokenHash);
          case "invite": {
            const status = await deps.db.withInvites(tokenHash, (s) => s.inviteRevoke(matched.ids[0]!));
            switch (status) {
              case "ok":
                return partnerOk(decision, 200, { revoked: true });
              case "not_found":
                return partnerError(decision, 404, "not_found", "not found");
              case "already_accepted":
                return partnerError(decision, 409, "invite_accepted", "this invite has already been accepted");
              default:
                return partnerError(decision, 409, "invite_revoked", "this invite has already been revoked");
            }
          }
          case "invite-accept-start":
            return await handleAcceptStart(req, deps, decision, "invite");
          case "invite-accept-verify":
            return await handleAcceptVerify(req, deps, decision, "invite");
          case "invite-accept":
            return await handleBranchE(req, deps, decision, tokenHash);
          case "enrolment-accept-start":
            return await handleAcceptStart(req, deps, decision, "enrolment");
          case "enrolment-accept-verify":
            return await handleAcceptVerify(req, deps, decision, "enrolment");
          case "credentials":
            return await handleRegisterFirst(req, deps, decision);
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
// The session routes: create, list (revoke is inline above), branch E
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

function inviteBody(v: InviteView): Record<string, unknown> {
  return {
    id: v.id,
    orgId: v.orgId,
    role: v.role,
    facilityId: v.facilityId,
    inviteeEmail: v.inviteeEmail,
    invitedBy: v.invitedBy,
    createdAt: v.createdAt,
    expiresAt: v.expiresAt,
    acceptedAt: v.acceptedAt,
    revokedAt: v.revokedAt,
    attempts: v.attempts,
  };
}

async function handleInviteCreate(req: Request, deps: PartnerInvitesDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseInviteCreateBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  if (deps.allowedOrigin === null) throw new PartnerNotConfigured();
  const { orgId, role, email } = parsed.value;
  // design 8: each hit is its OWN short transaction, committed before the request transaction opens
  const member = await deps.db.hitRateLimit(tokenHash, INVITE_CREATE_BUCKET, 86_400, INVITE_CREATE_PER_MEMBER_PER_DAY);
  if (!member.ok) return rateLimited(decision, "too many invites today", member.retryAfterSeconds);
  const mailbox = await deps.db.hitSystemRateLimit(`partner-invite-email:${await sha256Hex(email)}`, 86_400, INVITE_CREATE_PER_EMAIL_PER_DAY);
  if (!mailbox.ok) return rateLimited(decision, "too many invites to this address today", mailbox.retryAfterSeconds);

  const fresh = await deps.newInviteToken();
  const r = await deps.db.withInvites(tokenHash, (s) => s.inviteCreate(orgId, role, email, fresh.hash));
  if (r.status === "already_member") return partnerError(decision, 409, "already_member", "that person is already a member of this organisation");
  // the token leaves this function exactly once, here, in the body of the response; the link carries it in the FRAGMENT, which no server ever receives
  return partnerOk(decision, 201, { inviteId: r.inviteId, expiresAt: r.expiresAt, token: fresh.token, inviteUrl: `${deps.allowedOrigin}/invite#${fresh.token}` });
}

async function handleInviteList(req: Request, deps: PartnerInvitesDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseInviteListQuery(new URL(req.url));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const invites = await deps.db.withInvites(tokenHash, (s) => s.inviteList(parsed.value.orgId));
  return partnerOk(decision, 200, { invites: invites.map(inviteBody) });
}

async function handleBranchE(req: Request, deps: PartnerInvitesDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseTokenBody(await readPartnerJsonBody(req), "invite");
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const inviteHash = await sha256Hex(parsed.value.token);
  const r = await deps.db.withInvites(tokenHash, (s) => s.inviteAcceptMember(inviteHash));
  switch (r.status) {
    case "ok":
      return partnerOk(decision, 200, { orgId: r.orgId, role: r.role });
    case "already_member":
      return partnerError(decision, 409, "already_member", "you are already a member of this organisation");
    default:
      // not found, locked, a different mailbox (a forwarded link), an unconfirmed address: one answer, and the attempt count has committed
      return partnerError(decision, 403, "invite_refused", "that invite was not accepted");
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Accepting a token with no session: accept/start, accept/verify (invites and enrolment tokens)
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

/** The ONE answer of accept/start: it does not say whether the token exists, whether a code was sent, or whether a limit was reached. */
const REQUESTED_BODY = Object.freeze({ requested: true });

function acceptRefused(decision: Decision): Response {
  return partnerError(decision, 403, "accept_refused", "that code or link was not accepted");
}

function emailOf(deps: PartnerInvitesDeps, kind: TokenKind, hash: string): Promise<string | null> {
  return deps.db.withInviteMint((m) => (kind === "invite" ? m.inviteEmailForToken(hash) : m.enrolmentEmailForToken(hash)));
}

async function handleAcceptStart(req: Request, deps: PartnerInvitesDeps, decision: Decision, kind: TokenKind): Promise<Response> {
  const parsed = parseTokenBody(await readPartnerJsonBody(req), kind);
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const hash = await sha256Hex(parsed.value.token);
  const email = await emailOf(deps, kind, hash);
  const constant = partnerOk(decision, 200, REQUESTED_BODY);
  if (email === null) return constant;
  const limit = await deps.db.hitSystemRateLimit(`partner-${kind}-start:${hash}`, 3600, ACCEPT_START_PER_TOKEN_PER_HOUR);
  if (!limit.ok) return constant;
  try {
    await (kind === "invite" ? deps.inviteOtp : deps.enrolmentOtp).send(email);
  } catch {
    // a mailer failure is told to nobody: a 500 here would say the token exists
  }
  return constant;
}

/** What an accept definer produced, in one shape for both kinds. */
interface Accepted {
  readonly userId: string;
  readonly challenge: ChallengeIssue;
  readonly ref: { readonly kind: TokenKind; readonly id: string };
  readonly detail: Readonly<Record<string, unknown>>;
}
interface AcceptOutcome {
  readonly status: string;
  readonly rp: RpConfig;
  readonly accepted: Accepted | null;
}

async function handleAcceptVerify(req: Request, deps: PartnerInvitesDeps, decision: Decision, kind: TokenKind): Promise<Response> {
  const parsed = parseAcceptVerifyBody(await readPartnerJsonBody(req), kind);
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const hash = await sha256Hex(parsed.value.token);
  const email = await emailOf(deps, kind, hash);
  if (email === null) return acceptRefused(decision);
  const limit = await deps.db.hitSystemRateLimit(`partner-${kind}-verify:${hash}`, 3600, ACCEPT_VERIFY_PER_TOKEN_PER_HOUR);
  if (!limit.ok) return acceptRefused(decision);
  // the vendor is called with NO database transaction open
  const proven = await (kind === "invite" ? deps.inviteOtp : deps.enrolmentOtp).verify(email, parsed.value.code);
  if (!proven.ok) return acceptRefused(decision);

  let outcome: AcceptOutcome;
  try {
    if (proven.sessionId === null) return acceptRefused(decision);
    const gotrueSessionId = proven.sessionId;
    // ONE transaction as edge_partner_minter. Every refusal is a RETURNED row: it commits whatever it holds (the attempt count).
    outcome = await deps.db.withInviteMint(async (m): Promise<AcceptOutcome> => {
      const rp = await m.rpConfig();
      assertSameOrigin(deps.allowedOrigin, rp);
      if (kind === "invite") {
        const r = await m.inviteAccept(hash, proven.userId, gotrueSessionId);
        const a = r.accepted;
        return { status: r.status, rp, accepted: a === null ? null : { userId: a.userId, challenge: a.challenge, ref: { kind, id: a.inviteId }, detail: { orgId: a.orgId, role: a.role } } };
      }
      const r = await m.enrolmentAccept(hash, proven.userId, gotrueSessionId);
      const a = r.accepted;
      return { status: r.status, rp, accepted: a === null ? null : { userId: a.userId, challenge: a.challenge, ref: { kind, id: a.tokenId }, detail: { purpose: a.purpose } } };
    });
  } finally {
    // AFTER the definer has returned (the freshness check needs the session alive), on every path
    await proven.closeSession();
  }

  const a = outcome.accepted;
  if (outcome.status !== "ok" || a === null) {
    // only the owner of the mailbox reaches these two: the code was just proved
    if (outcome.status === "existing_member_sign_in") return partnerError(decision, 409, "existing_member_sign_in", "you already have a passkey: sign in with it");
    if (outcome.status === "recover_required") return partnerError(decision, 409, "recover_required", "ask a manager to recover your account");
    return acceptRefused(decision);
  }
  const userHandle = uuidToBytes(a.userId);
  if (userHandle === null) throw new Error("the accepted person id is not a uuid");
  const options = await deps.registration.options({ rp: outcome.rp, userHandle, userName: email, challenge: a.challenge.nonce, excludeCredentialIds: [] });
  return partnerOk(decision, 200, {
    options,
    challengeToken: formatChallengeToken(a.challenge),
    expiresAt: new Date(a.challenge.exp * 1000).toISOString(),
    userId: a.userId,
    refKind: a.ref.kind,
    refId: a.ref.id,
    ...a.detail,
  });
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// POST credentials, enrolment mode: the first credential, and the first session
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

async function handleRegisterFirst(req: Request, deps: PartnerInvitesDeps, decision: Decision): Promise<Response> {
  const parsed = parseEnrolCredentialBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const { userId, refKind, refId, token, registration } = parsed.value;
  // the Edge refuses an expired challenge itself; the database re-checks the HMAC (which binds the person, the acceptance and its time) and the expiry
  if (token.exp * 1000 <= deps.nowMs()) return registrationRefusal(decision, "expired");
  const fresh = await deps.newSessionToken();

  const outcome = await deps.db.withInviteMint(async (m) => {
    const rp = await m.rpConfig();
    assertSameOrigin(deps.allowedOrigin, rp);
    // the S0 wrapper FIRST: format none, no cross-origin, the exact origin and RP ID, UV, the challenge, the id inside the authenticator data
    const verified = await deps.registration.verify({ rp, response: registration.json, expectedChallenge: token.nonce });
    if (!verified.ok) return null;
    return await m.registerFirst({
      sessionTokenHash: fresh.hash,
      userId,
      refKind,
      refId,
      nonce: token.nonce,
      exp: token.exp,
      mac: token.mac,
      attestationObject: registration.attestationObject,
      clientDataJson: registration.clientDataJson,
      credentialId: verified.credentialId,
      publicKey: verified.publicKey,
      transports: verified.transports,
    });
  });

  if (outcome === null) return registrationRefusal(decision, "refused");
  if (outcome.status !== "ok" || outcome.aal === null || outcome.expiresAt === null || outcome.enrolmentUntil === null) return registrationRefusal(decision, outcome.status);
  // the session token leaves this function exactly once, here, in the body of the response
  return partnerOk(decision, 201, { token: fresh.token, expiresAt: outcome.expiresAt, aal: outcome.aal, enrolmentUntil: outcome.enrolmentUntil });
}
