// supabase/functions/_shared/partner/handler-kit.ts
//
// What the `partner-invites` and `partner-members` handlers (slice S1.5) share, so each reads as its own route table and nothing else. Pure: no environment, no database, no clock, no logging (PA-11).
//
//   * `routeOfFunction`: the path after the function's name.
//   * `matchRoute`: a route table with `{id}` segments (a uuid and nothing else; any other shape is no route at all, a 404 before anything is touched).
//   * `encodedPathRefusal`: §20.12 / §99 — a raw path that still carries `%2F`, `%5C` or `%2E` is 400 before the route table runs.
//   * `mapPartnerError`: the ONE place a port error becomes a response (401 / 403 / 409 / 422 / 503), identical to the session handler's.
//   * `emptyBody`, `assertSameOrigin`, `bearerHash`: the session-handler steps, unchanged.
//   * `registrationRefusal`: the status map of a refused create ceremony (`partner_credential_register_first` and the second-credential wrapper).

import { Errors } from "../http.ts";
import type { OriginDecision } from "./cors.ts";
import { partnerError, readPartnerJsonBody, unauthenticated } from "./http.ts";
import { PartnerAuthorityRefused, PartnerConflict, PartnerInvalidArgument, PartnerNotConfigured, PartnerSessionRefused, type RpConfig } from "./ports.ts";
import { parseEmptyBody } from "./session-shape.ts";
import { partnerTokenFromHeader, sha256Hex } from "./token.ts";

export type Decision = OriginDecision;

const UUID_SEGMENT = "([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})";

export interface RouteSpec {
  readonly name: string;
  /** `invites/{id}` style, `{id}` standing for ONE uuid segment. */
  readonly path: string;
  readonly methods: readonly string[];
  readonly session: boolean;
}

export interface MatchedRoute {
  readonly spec: RouteSpec;
  /** The uuids of the `{id}` segments, lower-cased, in order. */
  readonly ids: readonly string[];
}

const compiled = new WeakMap<RouteSpec, RegExp>();
function regexOf(spec: RouteSpec): RegExp {
  let re = compiled.get(spec);
  if (re === undefined) {
    re = new RegExp("^" + spec.path.split("/").map((seg) => (seg === "{id}" ? UUID_SEGMENT : seg.replace(/[.*+?^$()|[\]\\]/g, "\\$&"))).join("/") + "$");
    compiled.set(spec, re);
  }
  return re;
}

/** The route of a request URL: the path after the function name (`/partner-invites/invites`, `/functions/v1/partner-invites/invites`) or, with no function name in the path, the whole path. */
export function routeOfFunction(url: string, functionName: string): string {
  const parts = new URL(url).pathname.split("/").filter((p) => p.length > 0);
  const i = parts.lastIndexOf(functionName);
  return (i >= 0 ? parts.slice(i + 1) : parts).join("/");
}

/**
 * Pathname of an absolute (or path-only) URL string without percent-decoding and without query/hash.
 * Used so `%2F` / `%5C` / `%2E` that the runtime left in `req.url` are still visible (WHATWG `pathname` keeps `%2F`/`%5C` but may normalise `%2E` segments).
 */
export function rawPathname(url: string): string {
  const scheme = url.indexOf("://");
  if (scheme < 0) {
    const end = url.search(/[?#]/);
    return end < 0 ? url : url.slice(0, end);
  }
  const pathStart = url.indexOf("/", scheme + 3);
  if (pathStart < 0) return "";
  let cut = url.length;
  const q = url.indexOf("?", pathStart);
  const h = url.indexOf("#", pathStart);
  if (q >= 0) cut = Math.min(cut, q);
  if (h >= 0) cut = Math.min(cut, h);
  return url.slice(pathStart, cut);
}

/** True when the raw path still contains an encoded slash, backslash or dot (`%2F` / `%5C` / `%2E`, any hex case). */
export function rawPathHasEncodedSegments(url: string): boolean {
  return /%(?:2[fFeE]|5[cC])/.test(rawPathname(url));
}

/** §20.12 optional hardening: refuse encoded path segments with 400 before the closed route map runs. */
export function encodedPathRefusal(decision: Decision, url: string): Response | null {
  if (!rawPathHasEncodedSegments(url)) return null;
  return partnerError(decision, 400, "bad_request", "encoded path segments are not allowed");
}

export function matchRoute(table: readonly RouteSpec[], route: string): MatchedRoute | null {
  for (const spec of table) {
    const m = regexOf(spec).exec(route);
    if (m !== null) return { spec, ids: m.slice(1).map((x) => x.toLowerCase()) };
  }
  return null;
}

/** The 405 (with `Allow`) when the route does not take this method, or null when it does. */
export function methodRefusal(decision: Decision, matched: MatchedRoute, method: string): Response | null {
  if (matched.spec.methods.includes(method)) return null;
  const allow = matched.spec.methods.join(", ");
  return partnerError(decision, 405, "method_not_allowed", `${allow} only`, { allow });
}

/** The sha256 of the `gr_ps_` bearer, or null for anything else (a Supabase JWT, no header, a malformed token): the caller answers the ONE 401 with no port touched. */
export async function bearerHash(headers: Headers): Promise<string | null> {
  const token = partnerTokenFromHeader(headers.get("authorization"));
  return token === null ? null : await sha256Hex(token);
}

/** A route that takes no field: its body must be exactly `{}` (and the media type exactly JSON). */
export async function emptyBody(req: Request): Promise<void> {
  const parsed = parseEmptyBody(await readPartnerJsonBody(req));
  if (!parsed.ok) throw Errors.badRequest("invalid request", parsed.issues);
}

/** The environment's origin (what CORS allows) and the database's (what WebAuthn is checked against) are two copies of one fact: when they disagree the lane is misconfigured and fails closed. */
export function assertSameOrigin(allowedOrigin: string | null, rp: RpConfig): void {
  if (allowedOrigin === null || rp.origin !== allowedOrigin) throw new PartnerNotConfigured();
}

/** A port error as its response; any other error is re-thrown (the runner answers a constant 500 and the transaction has rolled back). */
export function mapPartnerError(decision: Decision, err: unknown): Response {
  if (err instanceof PartnerSessionRefused) return unauthenticated(decision);
  if (err instanceof PartnerAuthorityRefused) return partnerError(decision, 403, "forbidden", "forbidden");
  if (err instanceof PartnerConflict) return partnerError(decision, 409, "conflict", "conflict");
  if (err instanceof PartnerInvalidArgument) return partnerError(decision, 422, "invalid_request", "the request cannot be applied");
  if (err instanceof PartnerNotConfigured) return partnerError(decision, 503, "service_unavailable", "partner service is not available");
  throw err;
}

export function rateLimited(decision: Decision, message: string, retryAfterSeconds: number): Response {
  return partnerError(decision, 429, "rate_limited", message, { "retry-after": String(Math.max(1, retryAfterSeconds)) });
}

/** What a member who is still inside the cold-start window is told when the daily cap is reached (plan 8.3, AT(15); design 26.1 / 28.2: "429 `cold_start_cap`").
 * Still a 429 with the same `Retry-After` as every other cap, but with its OWN `code`: the portal keys its explanation on it (`attest.coldStart`,
 * `handover.coldStart`, `offerRedeem.coldStart`), and under the generic `rate_limited` code it could only say "try again in an hour", which is wrong for a rolling
 * 24 hour cap. The cap is the caller's own, so naming it tells them nothing about anyone else. `partner-edge-pwa-error-contract.test.ts` runs this response through
 * the portal's own message mapper. */
export const COLD_START_RETRY_AFTER_SECONDS = 3600;
export function coldStartCapped(decision: Decision): Response {
  return partnerError(decision, 429, "cold_start_cap", "a new member's daily limit has been reached", { "retry-after": String(COLD_START_RETRY_AFTER_SECONDS) });
}

/** Design §8 / §70: alert-only 1,200/h any-partner-call soft-cap. Never a 429; does not replace hard per-route caps. */
export const MEMBER_ANY_CALL_BUCKET = "partner-any-call";
export const MEMBER_ANY_CALL_PER_HOUR = 1200;

type RaiseMemberRateAlarmTx = { raiseMemberRateAlarm(detail: unknown): Promise<void> };

/** Minimal port surface for `alertMemberAnyCall` (PartnerDb.withSession or CourseQrDb.withCourseQr). */
export type MemberAnyCallDb = {
  hitRateLimit(
    tokenHash: string,
    bucket: string,
    windowSeconds: number,
    max: number,
  ): Promise<{ readonly ok: boolean; readonly retryAfterSeconds: number }>;
  withSession?<T>(tokenHash: string, op: (s: RaiseMemberRateAlarmTx) => Promise<T>): Promise<T>;
  withCourseQr?<T>(tokenHash: string, op: (s: RaiseMemberRateAlarmTx) => Promise<T>): Promise<T>;
};

/**
 * Soft-cap every authenticated partner call (0083 / §70): hit `partner-any-call` at 1,200/h; when over, raise
 * `rate_member` via a bound session. Never returns 429; writer errors are swallowed. Call once per HTTP request
 * immediately after a successful bearer hash.
 */
export async function alertMemberAnyCall(db: MemberAnyCallDb, tokenHash: string): Promise<void> {
  const lim = await db.hitRateLimit(tokenHash, MEMBER_ANY_CALL_BUCKET, 3600, MEMBER_ANY_CALL_PER_HOUR);
  if (lim.ok) return;
  try {
    const raise = (s: RaiseMemberRateAlarmTx) => s.raiseMemberRateAlarm({ stage: "partner-any-call" });
    if (typeof db.withSession === "function") {
      await db.withSession(tokenHash, raise);
    } else if (typeof db.withCourseQr === "function") {
      await db.withCourseQr(tokenHash, raise);
    }
  } catch {
    // alert-only: a writer fault must not refuse the request
  }
}

/**
 * A create ceremony the database refused, by its status. The enrolling person (an OTP-proved mailbox owner, or a signed-in member) is the only caller that can reach these, so they may be told apart a little:
 * an expired acceptance or challenge is a 410 (start again), a state conflict is a 409 (it names itself), and everything else (a challenge that does not belong, a malformed ceremony) is one 403.
 */
export function registrationRefusal(decision: Decision, status: string): Response {
  switch (status) {
    case "expired":
    case "accept_expired":
      return partnerError(decision, 410, "expired", "this enrolment has expired: start again");
    case "credential_exists":
    case "other_membership":
    case "already_registered":
    case "credential_in_use":
    case "too_many":
      return partnerError(decision, 409, status, "the credential cannot be added in this state");
    default:
      return partnerError(decision, 403, "registration_refused", "that registration was not accepted");
  }
}
