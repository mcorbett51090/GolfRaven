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
  type PartnerDb,
  PartnerAuthorityRefused,
  PartnerNotConfigured,
  PartnerSessionRefused,
  type RpConfig,
} from "./ports.ts";
import { parseEmptyBody, parseReauthBody, parseVerifyBody, uuidToBytes, type VerifyRequest } from "./session-shape.ts";
import { type NewSessionToken, partnerTokenFromHeader, sha256Hex, toB64u } from "./token.ts";

export const PARTNER_SESSION_FUNCTION = "partner-session";
/** Design 8: reauth is 10 attempts per member per hour (a hard, member-keyed bucket). */
export const REAUTH_PER_MEMBER_PER_HOUR = 10;
export const REAUTH_BUCKET = "partner-reauth:member";

export interface PartnerSessionDeps {
  readonly db: PartnerDb;
  /** The one allowed origin (privileged.ts#loadPartnerCorsOrigin), or null when none is configured (every request that carries an Origin is then refused). */
  readonly allowedOrigin: string | null;
  readonly webauthn: AssertionVerifier;
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
          default:
            return await handleReauth(req, deps, decision, tokenHash!);
        }
      } catch (err) {
        if (err instanceof PartnerSessionRefused) return unauthenticated(decision);
        if (err instanceof PartnerAuthorityRefused) return partnerError(decision, 403, "forbidden", "forbidden");
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
