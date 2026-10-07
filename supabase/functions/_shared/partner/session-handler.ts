// supabase/functions/_shared/partner/session-handler.ts
//
// The `partner-session` handler (docs/security/partner-auth-design.md 4.2, 4.5, 4.6, 6.2, 8; slice S1.2). Pure and unit-testable: the database (`PartnerDb`) and the WebAuthn wrapper
// (`AssertionVerifier`) are PORTS (`ports.ts`); this file reads no environment, opens no connection, imports no library and writes no log line (PA-11).
//
// ROUTES (relative to the function; `POST options` is `/partner-session/options`):
//   POST options          a stateless sign-in challenge (private.partner_challenge_issue_sign_in): { options, challengeToken, expiresAt }
//   POST verify           { challengeToken, credential, pop_jkt? }: verify with the S0 wrapper FIRST, then private.partner_session_mint, COMMIT on every status; one uniform 401 for every refusal;
//                         the opaque `gr_ps_` token comes back exactly once, in a 201
//   GET  session          who am I (class PEEK: it never extends the idle timer)
//   POST sign-out         revokes the presented session
//   POST lock             clears every step-up grant now (the session stays live)
//   POST reauth/options   a reauth challenge bound to the session
//   POST reauth           { challengeToken, credential }: a fresh passkey assertion by a credential of THE SESSION'S person (PA-27) sets reauth_until
//   GET  pin              the PBKDF2 inputs (salt, iterations) the browser derives the PIN key with, or `unset` / `must_change` / `locked` (S1.3)
//   POST step-up/pin      { derived }: the browser-derived key (never the PIN); on `ok` the session holds a single-use PIN grant (60 s). `wrong`, `locked` and `retry_after` are RETURNED statuses: the counter commits
//   POST pin/set          { derived, salt, iterations }: the first PIN, or the replacement after a reset; only inside an enrolment window or after an email proof (403 otherwise)
//   POST pin/change       { currentDerived, derived, salt, iterations }: replace a live PIN (needs the current one)
//   POST otp-proof/start  {}: mails a one-time code to the member's OWN address (3 a member an hour)
//   POST otp-proof/verify { code }: proves the mailbox through GoTrue (anon key) and records the proof on the session (5 attempts a member an hour); the GoTrue session is closed AFTER the proof is recorded
//
// THE ORDER, for every request: (1) the Origin check, before routing and for every method (a foreign Origin is a 403 whatever CORS does); (2) `OPTIONS` is answered here, with no port touched;
// (3) the route and method (404 / 405); (4) for a session route, the bearer: exactly `gr_ps_` + 43 characters, else the ONE 401 with no port touched (a Supabase JWT, any other bearer and no
// bearer are all refused here and never forwarded anywhere); (5) the exact JSON media type (415) and the strict body (400); (6) the work.
//
// COMMIT ON EVERY STATUS (17.8): a refusal the database makes (a signature the Edge passed, a counter regression, a replay, a limit) is a RETURNED value, so the transaction commits and the alarm
// rows, the burned nonce and the failure counter commit with it; the response is built AFTER the transaction. Only a malformed argument, a deploy fault or an unexpected error throws (and rolls back).
//
// PROOF OF POSSESSION is reserved and NOT built (N7): the `pop_jkt` body field is accepted and dropped, and the `X-GR-PoP` header is never read.

import { Errors } from "../http.ts";
import { decideOrigin, preflightResponse } from "./cors.ts";
import { partnerError, partnerOk, readPartnerJsonBody, runPartnerHandler, unauthenticated } from "./http.ts";
import {
  type AssertionVerifier,
  type ChallengeIssue,
  type EmailOtpPort,
  type PartnerDb,
  type PinWriteResult,
  PartnerAuthorityRefused,
  PartnerConflict,
  PartnerNotConfigured,
  PartnerSessionRefused,
  type RpConfig,
} from "./ports.ts";
import {
  parseEmptyBody,
  parseOtpVerifyBody,
  parsePinChangeBody,
  parsePinSetBody,
  parsePinVerifyBody,
  parseReauthBody,
  parseVerifyBody,
  uuidToBytes,
  type VerifyRequest,
} from "./session-shape.ts";
import { type NewSessionToken, partnerTokenFromHeader, sha256Hex, toB64u } from "./token.ts";

export const PARTNER_SESSION_FUNCTION = "partner-session";
/** Design 8: reauth is 10 attempts per member per hour (a hard, member-keyed bucket). */
export const REAUTH_PER_MEMBER_PER_HOUR = 10;
export const REAUTH_BUCKET = "partner-reauth:member";
/** Design 8: the email OTP of the proof is 3 sends and 5 verification attempts per member per hour (hard, member-keyed buckets, each hit in its own short transaction that commits). */
export const OTP_SEND_PER_MEMBER_PER_HOUR = 3;
export const OTP_SEND_BUCKET = "partner-otp-send:member";
export const OTP_VERIFY_PER_MEMBER_PER_HOUR = 5;
export const OTP_VERIFY_BUCKET = "partner-otp-verify:member";

export interface PartnerSessionDeps {
  readonly db: PartnerDb;
  /** The one allowed origin (privileged.ts#loadPartnerCorsOrigin), or null when none is configured (every request that carries an Origin is then refused). */
  readonly allowedOrigin: string | null;
  readonly webauthn: AssertionVerifier;
  /** The email OTP of the step-up proof (GoTrue, anon key). */
  readonly otp: EmailOtpPort;
  readonly nowMs: () => number;
  readonly newSessionToken: () => Promise<NewSessionToken>;
  readonly timeoutMs?: number;
}

const ROUTE_METHODS: Readonly<Record<string, "GET" | "POST">> = {
  options: "POST",
  verify: "POST",
  session: "GET",
  "sign-out": "POST",
  lock: "POST",
  "reauth/options": "POST",
  reauth: "POST",
  pin: "GET",
  "step-up/pin": "POST",
  "pin/set": "POST",
  "pin/change": "POST",
  "otp-proof/start": "POST",
  "otp-proof/verify": "POST",
};

/** The route of a request URL: the path after the function name (`/partner-session/verify`, `/functions/v1/partner-session/verify`) or, with no function name in the path, the whole path. */
export function routeOf(url: string): string {
  const parts = new URL(url).pathname.split("/").filter((p) => p.length > 0);
  const i = parts.lastIndexOf(PARTNER_SESSION_FUNCTION);
  return (i >= 0 ? parts.slice(i + 1) : parts).join("/");
}

/** `<nonce>.<exp>.<mac>`: the token POST options returns and the client sends back. */
export function formatChallengeToken(c: ChallengeIssue): string {
  return `${toB64u(c.nonce)}.${c.exp}.${toB64u(c.mac)}`;
}

function assertSameOrigin(deps: PartnerSessionDeps, rp: RpConfig): void {
  // the environment's origin (what CORS allows) and the database's (what WebAuthn is checked against) are two copies of one fact: when they disagree the lane is misconfigured, and it fails closed
  if (deps.allowedOrigin === null || rp.origin !== deps.allowedOrigin) throw new PartnerNotConfigured();
}

type Refusal = { readonly kind: "refused" };
const REFUSED: Refusal = { kind: "refused" };

export async function handlePartnerSessionRequest(req: Request, deps: PartnerSessionDeps): Promise<Response> {
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
        const route = routeOf(req.url);
        const want = ROUTE_METHODS[route];
        if (want === undefined) return partnerError(decision, 404, "not_found", "not found");
        if (req.method !== want) return partnerError(decision, 405, "method_not_allowed", `${want} only`, { allow: want });

        // (4) a session route needs a gr_ps_ bearer: anything else is the one 401, and no port is touched
        let tokenHash: string | null = null;
        if (route !== "options" && route !== "verify") {
          const token = partnerTokenFromHeader(req.headers.get("authorization"));
          if (token === null) return unauthenticated(decision);
          tokenHash = await sha256Hex(token);
        }

        switch (route) {
          case "options":
            return await handleOptions(req, deps, decision);
          case "verify":
            return await handleVerify(req, deps, decision);
          case "session":
            return partnerOk(decision, 200, await deps.db.withSession(tokenHash!, (s) => s.whoami()));
          case "sign-out": {
            await emptyBody(req);
            await deps.db.withSession(tokenHash!, (s) => s.signOut());
            return partnerOk(decision, 200, { signedOut: true });
          }
          case "lock": {
            await emptyBody(req);
            await deps.db.withSession(tokenHash!, (s) => s.lock());
            return partnerOk(decision, 200, { locked: true });
          }
          case "reauth/options":
            return await handleReauthOptions(req, deps, decision, tokenHash!);
          case "reauth":
            return await handleReauth(req, deps, decision, tokenHash!);
          case "pin":
            return await handlePinParams(deps, decision, tokenHash!);
          case "step-up/pin":
            return await handlePinVerify(req, deps, decision, tokenHash!);
          case "pin/set":
            return await handlePinSet(req, deps, decision, tokenHash!);
          case "pin/change":
            return await handlePinChange(req, deps, decision, tokenHash!);
          case "otp-proof/start":
            return await handleOtpStart(req, deps, decision, tokenHash!);
          default:
            return await handleOtpVerify(req, deps, decision, tokenHash!);
        }
      } catch (err) {
        if (err instanceof PartnerSessionRefused) return unauthenticated(decision);
        if (err instanceof PartnerAuthorityRefused) return partnerError(decision, 403, "forbidden", "forbidden");
        if (err instanceof PartnerConflict) return partnerError(decision, 409, "conflict", "conflict");
        if (err instanceof PartnerNotConfigured) return partnerError(decision, 503, "service_unavailable", "partner sign-in is not available");
        throw err;
      }
    },
    deps.timeoutMs,
  );
}

/** A route that takes no field: its body must be exactly `{}` (and the media type exactly JSON). */
async function emptyBody(req: Request): Promise<void> {
  const parsed = parseEmptyBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
}

type Decision = ReturnType<typeof decideOrigin>;

async function handleOptions(req: Request, deps: PartnerSessionDeps, decision: Decision): Promise<Response> {
  await emptyBody(req);
  const { rp, ch } = await deps.db.withMint(async (m) => {
    const rp = await m.rpConfig();
    assertSameOrigin(deps, rp);
    return { rp, ch: await m.issueChallenge() };
  });
  const options = await deps.webauthn.options(rp, ch.nonce);
  return partnerOk(decision, 200, { options, challengeToken: formatChallengeToken(ch), expiresAt: new Date(ch.exp * 1000).toISOString() });
}

async function handleVerify(req: Request, deps: PartnerSessionDeps, decision: Decision): Promise<Response> {
  const parsed = parseVerifyBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const body: VerifyRequest = parsed.value;
  // the Edge refuses an expired challenge itself; the database re-checks the HMAC and the expiry
  if (body.token.exp * 1000 <= deps.nowMs()) return unauthenticated(decision);
  const fresh = await deps.newSessionToken();
  const { assertion, token } = body;

  // ONE transaction as edge_partner_minter. Every refusal below is a RETURNED value: the transaction commits whatever it holds (the failure counter, the burned nonce, the alarm rows).
  const outcome = await deps.db.withMint(async (m): Promise<Refusal | { readonly kind: "minted"; readonly aal: number; readonly expiresAt: string }> => {
    const rp = await m.rpConfig();
    assertSameOrigin(deps, rp);
    const looked = await m.lookupCredential(assertion.credentialId);
    if (looked.status !== "ok") return REFUSED; // unknown, revoked and cooldown are one answer
    const userHandle = uuidToBytes(looked.credential.userId);
    if (userHandle === null) throw new Error("the stored person id is not a uuid");
    // the S0 wrapper FIRST: the signature, the exact origin and RP ID, UV, the user handle, the counter
    const verified = await deps.webauthn.verify({
      rp,
      response: assertion.json,
      expectedChallenge: token.nonce,
      credential: { id: assertion.json.id, publicKey: looked.credential.publicKey, signCount: looked.credential.signCount },
      expectedUserHandle: userHandle,
    });
    if (!verified.ok && !verified.counterOnly) {
      // a refused verification is a guess: it counts against the credential (design 8), and the count commits with this refusal
      await m.recordFailure(assertion.credentialId);
      return REFUSED;
    }
    // `counterOnly`: the signature is genuine and only the counter did not advance. It goes to the mint anyway, which writes the audit_log and alarm rows (PA-12) and answers counter_regression
    const minted = await m.mint({
      tokenHash: fresh.hash,
      credentialId: assertion.credentialId,
      nonce: token.nonce,
      exp: token.exp,
      mac: token.mac,
      authenticatorData: assertion.authenticatorData,
      clientDataJson: assertion.clientDataJson,
      signature: assertion.signature,
    });
    if (minted.status !== "ok" || minted.aal === null || minted.expiresAt === null) return REFUSED;
    return { kind: "minted", aal: minted.aal, expiresAt: minted.expiresAt };
  });

  if (outcome.kind === "refused") return unauthenticated(decision);
  // the token leaves this function exactly once, here, in the body of the response
  return partnerOk(decision, 201, { token: fresh.token, expiresAt: outcome.expiresAt, aal: outcome.aal });
}

async function handleReauthOptions(req: Request, deps: PartnerSessionDeps, decision: Decision, tokenHash: string): Promise<Response> {
  await emptyBody(req);
  const ch = await deps.db.withSession(tokenHash, async (s) => {
    const c = await s.reauthOptions();
    assertSameOrigin(deps, c.rp);
    return c;
  });
  const options = await deps.webauthn.options(ch.rp, ch.nonce);
  return partnerOk(decision, 200, { options, challengeToken: formatChallengeToken(ch), expiresAt: new Date(ch.exp * 1000).toISOString() });
}

async function handleReauth(req: Request, deps: PartnerSessionDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseReauthBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const { assertion, token } = parsed.value;
  // design 8: 10 reauth attempts per member per hour, a hard member-keyed bucket, hit in its OWN short transaction before the request transaction opens (and committed)
  const limit = await deps.db.hitRateLimit(tokenHash, REAUTH_BUCKET, 3600, REAUTH_PER_MEMBER_PER_HOUR);
  if (!limit.ok) return partnerError(decision, 429, "rate_limited", "too many reauthentication attempts", { "retry-after": String(limit.retryAfterSeconds) });
  if (token.exp * 1000 <= deps.nowMs()) return reauthRefused(decision);

  const outcome = await deps.db.withSession(tokenHash, async (s): Promise<Refusal | { readonly kind: "ok"; readonly reauthUntil: string }> => {
    // PA-27: only a live credential of THIS SESSION'S person is found; a coworker's own passkey is not
    const c = await s.reauthCredential(assertion.credentialId);
    if (c === null) return REFUSED;
    assertSameOrigin(deps, c.rp);
    const userHandle = uuidToBytes(c.userId);
    if (userHandle === null) throw new Error("the stored person id is not a uuid");
    const verified = await deps.webauthn.verify({
      rp: c.rp,
      response: assertion.json,
      expectedChallenge: token.nonce,
      credential: { id: assertion.json.id, publicKey: c.publicKey, signCount: c.signCount },
      expectedUserHandle: userHandle,
    });
    if (!verified.ok && !verified.counterOnly) return REFUSED;
    const r = await s.reauth({
      credentialId: assertion.credentialId,
      nonce: token.nonce,
      exp: token.exp,
      mac: token.mac,
      authenticatorData: assertion.authenticatorData,
      clientDataJson: assertion.clientDataJson,
      signature: assertion.signature,
    });
    if (r.status !== "ok" || r.reauthUntil === null) return REFUSED;
    return { kind: "ok", reauthUntil: r.reauthUntil };
  });
  if (outcome.kind === "refused") return reauthRefused(decision);
  return partnerOk(decision, 200, { reauthUntil: outcome.reauthUntil });
}

/** Every reauth refusal is this ONE 403 (a 401 would tell the client its SESSION is dead): a wrong person's passkey, a wrong origin, a replay, an expired challenge ... are indistinguishable. */
function reauthRefused(decision: Decision): Response {
  return partnerError(decision, 403, "reauth_refused", "reauthentication failed");
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// The step-up PIN (S1.3, design 6.3). The request bodies carry the BROWSER-DERIVED key (32 bytes, base64url), never the PIN: the Edge validates length and encoding (session-shape.ts) and nothing else.
// A refusal the database makes (`wrong`, `locked`, `retry_after`, ...) is a RETURNED status, so the transaction COMMITS and the failure counter with it (the 0020 lesson); the response is built AFTER it.
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

async function handlePinParams(deps: PartnerSessionDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const p = await deps.db.withSession(tokenHash, (s) => s.pinParams());
  if (p.state !== "ok") return partnerOk(decision, 200, { state: p.state });
  return partnerOk(decision, 200, { state: "ok", salt: toB64u(p.salt), iterations: p.iterations, retryAfterSeconds: p.retryAfterSeconds });
}

async function handlePinVerify(req: Request, deps: PartnerSessionDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parsePinVerifyBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const r = await deps.db.withSession(tokenHash, (s) => s.pinVerify(parsed.value.derived));
  switch (r.status) {
    case "ok":
      return partnerOk(decision, 200, { grantExpiresAt: r.grantUntil });
    case "wrong":
      return partnerError(decision, 403, "pin_wrong", "that PIN is not correct");
    case "retry_after":
      return partnerError(decision, 429, "pin_backoff", "too many attempts: wait before trying again", { "retry-after": String(Math.max(1, r.retryAfterSeconds)) });
    case "locked":
      return partnerError(decision, 403, "pin_locked", "this PIN is locked: ask a manager to reset it");
    case "unset":
      return partnerError(decision, 409, "pin_not_set", "no PIN is set");
    default:
      return partnerError(decision, 409, "pin_must_change", "set a new PIN");
  }
}

function pinWriteResponse(decision: Decision, r: PinWriteResult, okBody: unknown): Response {
  switch (r.status) {
    case "ok":
      return partnerOk(decision, 200, okBody);
    case "already_set":
      return partnerError(decision, 409, "pin_already_set", "a PIN is already set: change it instead");
    case "no_pin":
    case "unset":
      return partnerError(decision, 409, "pin_not_set", "no PIN is set");
    case "must_change":
      return partnerError(decision, 409, "pin_must_change", "set a new PIN");
    case "wrong":
      return partnerError(decision, 403, "pin_wrong", "that PIN is not correct");
    case "retry_after":
      return partnerError(decision, 429, "pin_backoff", "too many attempts: wait before trying again", { "retry-after": String(Math.max(1, r.retryAfterSeconds)) });
    default:
      return partnerError(decision, 403, "pin_locked", "this PIN is locked: ask a manager to reset it");
  }
}

async function handlePinSet(req: Request, deps: PartnerSessionDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parsePinSetBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const r = await deps.db.withSession(tokenHash, (s) => s.pinSet(parsed.value));
  return pinWriteResponse(decision, r, { set: true });
}

async function handlePinChange(req: Request, deps: PartnerSessionDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parsePinChangeBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const r = await deps.db.withSession(tokenHash, (s) => s.pinChange(parsed.value));
  return pinWriteResponse(decision, r, { changed: true });
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// The email proof (6.1, 6.3). A GoTrue call is NEVER made while a database transaction is open: the member's address is read in one transaction, the vendor is called with none open, and the proof is
// recorded in a second one. The GoTrue session verifyOtp creates is closed AFTER the proof is recorded, on every path (the order E19 uses). Every refusal of the code is the one 403.
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

async function handleOtpStart(req: Request, deps: PartnerSessionDeps, decision: Decision, tokenHash: string): Promise<Response> {
  await emptyBody(req);
  const limit = await deps.db.hitRateLimit(tokenHash, OTP_SEND_BUCKET, 3600, OTP_SEND_PER_MEMBER_PER_HOUR);
  if (!limit.ok) return partnerError(decision, 429, "rate_limited", "too many codes requested", { "retry-after": String(limit.retryAfterSeconds) });
  const email = await deps.db.withSession(tokenHash, (s) => s.otpTarget());
  if (email === null) return partnerError(decision, 409, "otp_unavailable", "this account has no email address to send a code to");
  await deps.otp.send(email);
  return partnerOk(decision, 200, { sent: true });
}

async function handleOtpVerify(req: Request, deps: PartnerSessionDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseOtpVerifyBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limit = await deps.db.hitRateLimit(tokenHash, OTP_VERIFY_BUCKET, 3600, OTP_VERIFY_PER_MEMBER_PER_HOUR);
  if (!limit.ok) return partnerError(decision, 429, "rate_limited", "too many attempts", { "retry-after": String(limit.retryAfterSeconds) });
  const email = await deps.db.withSession(tokenHash, (s) => s.otpTarget());
  if (email === null) return otpRefused(decision);
  const proven = await deps.otp.verify(email, parsed.value.code);
  if (!proven.ok) return otpRefused(decision);
  try {
    if (proven.sessionId === null) return otpRefused(decision);
    const sessionId = proven.sessionId;
    let r: { readonly status: "ok" | "refused"; readonly otpProofUntil: string | null };
    try {
      r = await deps.db.withSession(tokenHash, (s) => s.otpProof(sessionId));
    } catch (err) {
      // the UNIQUE index: this GoTrue session already proved another proof (one GoTrue session proves at most one)
      if (err instanceof PartnerConflict) return otpRefused(decision);
      throw err;
    }
    if (r.status !== "ok" || r.otpProofUntil === null) return otpRefused(decision);
    return partnerOk(decision, 200, { otpProofUntil: r.otpProofUntil });
  } finally {
    await proven.closeSession();
  }
}

/** Every refusal of the emailed code (wrong, expired, no session to bind, a stale or reused GoTrue session) is this ONE 403. */
function otpRefused(decision: Decision): Response {
  return partnerError(decision, 403, "otp_refused", "that code was not accepted");
}
