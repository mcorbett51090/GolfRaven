// supabase/functions/_shared/partner/course-qr-handler.ts
//
// The `course-qr` handler: the STAFF lane of the course QR (docs/security/partner-auth-design.md 4.2, 6.3, 8, S2b; the Edge half of migration 0055). Pure and unit-testable like members-handler.ts: the database
// (`CourseQrDb`) is a PORT (`ports.ts`); this file reads no environment, opens no connection and writes no log line (PA-11). Every route is a SESSION route (`Authorization: Bearer gr_ps_...`): the class (A0 /
// A0_KEEPALIVE / A1 / A2) and the facility scope are the database's, decided inside the `_for_partner` definer; staff at X asking for Y is a 403, never a returned status the caller could map.
//
// ROUTES (relative to the function; `GET pin` is `/course-qr/pin`):
//   GET  pin?facilityId=             today's PIN: private.course_pin_derive for the facility-local date and the epoch live now, through the database ONLY (nothing here derives a PIN) (class A0)
//   POST pin/rotate    { facilityId } "Rotate PIN": pin_epoch + 1 (class A2: a PIN in the last 30 s and a passkey in the last 5 minutes)
//   POST tokens        { facilityId } "Marker sold": mint a rotating token (class A1: CONSUMES the single-use PIN grant), 60 a member an hour
//   POST tokens/refresh { facilityId, nonceHash }  the sale screen's 30 s heartbeat for a token THIS person's own mint created (class A0_KEEPALIVE: it never advances last_seen_at, creates no token and no authority)
//
// THE MINT, step by step (the order is the security argument):
//   (1) the member's 60-an-hour bucket (its own short transaction, before the request transaction: the pool-deadlock rule) -- 429 over the cap;
//   (2) 16 random bytes, and their SHA-256 as the nonce hash the database stores (never the nonce);
//   (3) ONE bound transaction: the A1 definer consumes the PIN grant, INSERTs the token row and releases the Vault signing key WITH it; the token is signed and verified under the registered public key INSIDE the
//       transaction, so a failure of any step (no programme, a key that does not match, a throw) ROLLS BACK the row and gives the PIN grant back;
//   (4) the token goes to the client ONCE. The seed is a local of step (3): it is not in the response, not in a header, not in an error and not in a log (there is no log line).
//
// THE ORDER, for every request: (1) the Origin check, before routing and for every method; (2) `OPTIONS` is answered here, with no port touched; (3) the route and the method (404 / 405); (4) the bearer: exactly
// `gr_ps_` + 43 characters, else the ONE 401 with no port touched; (5) the exact JSON media type (415) and the strict body (400) / the strict query (400); (6) the work.

import { Errors } from "../http.ts";
import { decideOrigin, preflightResponse } from "./cors.ts";
import { CourseQrKeyMismatch, signRotatingToken } from "./course-qr-signer.ts";
import { parseFacilityBody, parseFacilityQuery, parseRefreshBody } from "./course-qr-shape.ts";
import { bearerHash, type Decision, mapPartnerError, matchRoute, methodRefusal, rateLimited, routeOfFunction, type RouteSpec } from "./handler-kit.ts";
import { partnerError, partnerOk, readPartnerJsonBody, runPartnerHandler, unauthenticated } from "./http.ts";
import { type CourseQrDb, PartnerNotConfigured } from "./ports.ts";
import { toHex } from "./token.ts";

export const COURSE_QR_FUNCTION = "course-qr";

/** Plan 4.7.8 / design 8: "course-qr token issue 60/staff/h". Every request that reaches the limiter counts, a refused one included. */
export const MINT_BUCKET = "course-qr:mint:member";
export const MINT_PER_MEMBER_PER_HOUR = 60;
/** Rotating the PIN is rare and A2-gated; this only bounds a loop. */
export const ROTATE_BUCKET = "course-qr:rotate:member";
export const ROTATE_PER_MEMBER_PER_HOUR = 10;
/** The sale screen's heartbeat is every 30 s (120 an hour per open screen); the cap leaves room for several tills and only bounds a runaway client. */
export const REFRESH_BUCKET = "course-qr:refresh:member";
export const REFRESH_PER_MEMBER_PER_HOUR = 1000;

export interface CourseQrDeps {
  readonly db: CourseQrDb;
  /** The one allowed origin (privileged.ts#loadPartnerCorsOrigin), or null when none is configured. */
  readonly allowedOrigin: string | null;
  /** `https://golfraven.<tld>` (privileged.ts#loadCourseQrLinkOrigin): the universal-link origin of a token, or null (then the response carries no link; the token is the same). */
  readonly linkOrigin: string | null;
  /** 16 fresh random bytes (the token's 128-bit nonce). */
  readonly randomNonce: () => Uint8Array;
  readonly timeoutMs?: number;
}

const ROUTES: readonly RouteSpec[] = [
  { name: "pin", path: "pin", methods: ["GET"], session: true },
  { name: "pin-rotate", path: "pin/rotate", methods: ["POST"], session: true },
  { name: "tokens", path: "tokens", methods: ["POST"], session: true },
  { name: "tokens-refresh", path: "tokens/refresh", methods: ["POST"], session: true },
];

/** A returned status that must NOT commit: thrown inside the transaction callback so the PIN grant the A1 definer consumed is given back, then answered outside it. */
class MintRefused extends Error {
  constructor(readonly status: "no_programme") {
    super("mint_refused");
    this.name = "MintRefused";
  }
}

/** `app.course_qr_token.nonce_hash`: lower-case hex SHA-256 of the 16 raw nonce bytes (format.ts `nonceHashHex`). */
async function nonceHash(nonce: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", nonce.slice().buffer)));
}

function toIso(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

export async function handleCourseQrRequest(req: Request, deps: CourseQrDeps): Promise<Response> {
  const decision = decideOrigin(req.headers, deps.allowedOrigin);
  if (decision.kind === "refused") return partnerError({ kind: "none" }, 403, "forbidden", "origin not allowed");
  if (req.method === "OPTIONS") return preflightResponse(decision);

  return await runPartnerHandler(
    decision,
    async () => {
      try {
        const matched = matchRoute(ROUTES, routeOfFunction(req.url, COURSE_QR_FUNCTION));
        if (matched === null) return partnerError(decision, 404, "not_found", "not found");
        const refusal = methodRefusal(decision, matched, req.method);
        if (refusal !== null) return refusal;

        const tokenHash = await bearerHash(req.headers);
        if (tokenHash === null) return unauthenticated(decision);

        switch (matched.spec.name) {
          case "pin":
            return await handlePin(req, deps, decision, tokenHash);
          case "pin-rotate":
            return await handleRotate(req, deps, decision, tokenHash);
          case "tokens":
            return await handleMint(req, deps, decision, tokenHash);
          case "tokens-refresh":
            return await handleRefresh(req, deps, decision, tokenHash);
          default:
            return partnerError(decision, 404, "not_found", "not found");
        }
      } catch (err) {
        if (err instanceof CourseQrKeyMismatch) return mapPartnerError(decision, new PartnerNotConfigured());
        return mapPartnerError(decision, err);
      }
    },
    deps.timeoutMs,
  );
}

async function handlePin(req: Request, deps: CourseQrDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseFacilityQuery(new URL(req.url));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const r = await deps.db.withCourseQr(tokenHash, (s) => s.pinShow(parsed.value.facilityId));
  if (r.status === "no_facility") return partnerError(decision, 404, "not_found", "not found");
  if (r.status === "no_programme") return partnerError(decision, 409, "no_programme", "this facility has no active printed-QR programme");
  return partnerOk(decision, 200, { facilityId: parsed.value.facilityId, pin: r.dailyPin, localDate: r.localDate, validUntil: r.validUntil, pinEpoch: r.pinEpoch });
}

async function handleRotate(req: Request, deps: CourseQrDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseFacilityBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limit = await deps.db.hitRateLimit(tokenHash, ROTATE_BUCKET, 3600, ROTATE_PER_MEMBER_PER_HOUR);
  if (!limit.ok) return rateLimited(decision, "too many PIN rotations", limit.retryAfterSeconds);
  const r = await deps.db.withCourseQr(tokenHash, (s) => s.pinRotate(parsed.value.facilityId));
  if (r.status !== "ok") return partnerError(decision, 409, "no_programme", "this facility has no active programme");
  return partnerOk(decision, 200, { facilityId: parsed.value.facilityId, pinEpoch: r.pinEpoch });
}

async function handleMint(req: Request, deps: CourseQrDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseFacilityBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const { facilityId } = parsed.value;
  const limit = await deps.db.hitRateLimit(tokenHash, MINT_BUCKET, 3600, MINT_PER_MEMBER_PER_HOUR);
  if (!limit.ok) return rateLimited(decision, "too many tokens", limit.retryAfterSeconds);

  const nonce = deps.randomNonce();
  const nonceHashHex = await nonceHash(nonce);
  let minted: { readonly token: string; readonly kid: string; readonly issuedAt: number; readonly expiresAt: number };
  try {
    minted = await deps.db.withCourseQr(tokenHash, async (s) => {
      const m = await s.mint(facilityId, nonceHashHex);
      if (m.status !== "ok") throw new MintRefused(m.status);
      const token = await signRotatingToken({ kid: m.kid, facilityId, iat: m.issuedAt, nonce, seed: m.signingKey, publicKey: m.publicKey });
      return { token, kid: m.kid, issuedAt: m.issuedAt, expiresAt: m.expiresAt };
    });
  } catch (err) {
    if (err instanceof MintRefused) return partnerError(decision, 409, "no_programme", "this facility cannot sell a marker with a rotating QR");
    throw err;
  }
  return partnerOk(decision, 201, {
    facilityId,
    token: minted.token,
    link: deps.linkOrigin === null ? null : `${deps.linkOrigin}/q/m#${minted.token}`,
    nonceHash: nonceHashHex,
    kid: minted.kid,
    issuedAt: toIso(minted.issuedAt),
    expiresAt: toIso(minted.expiresAt),
  });
}

async function handleRefresh(req: Request, deps: CourseQrDeps, decision: Decision, tokenHash: string): Promise<Response> {
  const parsed = parseRefreshBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
  const limit = await deps.db.hitRateLimit(tokenHash, REFRESH_BUCKET, 3600, REFRESH_PER_MEMBER_PER_HOUR);
  if (!limit.ok) return rateLimited(decision, "too many refreshes", limit.retryAfterSeconds);
  const r = await deps.db.withCourseQr(tokenHash, (s) => s.refresh(parsed.value.facilityId, parsed.value.nonceHash));
  return partnerOk(decision, 200, { state: r.state, secondsLeft: r.secondsLeft });
}
