/**
 * The partner API client (docs/security/partner-auth-design.md 4.5, 4.6, 18).
 *
 * THE TOKEN. The opaque `gr_ps_` bearer lives in ONE closure variable (`token`, below) and nowhere else: it is not
 * returned to callers, not written to any storage API (localStorage, sessionStorage, IndexedDB, a cookie, Cache Storage,
 * a service worker), not put in a URL, not logged, and not placed in an error. This module imports no storage API and
 * the source scan in `test/source-scan.test.ts` keeps it that way. A reload therefore loses it, by design: the next
 * session needs a fresh passkey tap (4.6).
 *
 * EVERY REQUEST sends exactly `Content-Type: application/json` (the server refuses any other media type with 415, and a
 * request with a `text/plain` look-alike is the cross-site "simple request" the server's check exists to stop), carries
 * `credentials: "omit"` (no cookie is ever sent or accepted: there is no ambient credential to ride), refuses redirects,
 * is never cached and sends no referrer. The session routes add `Authorization: Bearer <token>`.
 *
 * The reserved proof-of-possession header `X-GR-PoP` (N7) is not sent: the server ignores it today.
 *
 * ERRORS are `PartnerApiError` values with a closed `kind` (see errors.ts). A 401 on an authenticated call means the
 * session is dead: the token is wiped here, before the caller sees the error, and listeners are told.
 *
 * PRE-SESSION ROUTES (S1.5): `acceptStart` / `acceptVerify` (invite or enrolment token, no bearer) and `registerFirst` (the first credential, which OPENS the
 * first session: its token is adopted exactly as `verify`'s is, by `adoptSession`, including the cancel handling) are beside `signInOptions`. The step-up routes
 * (`pin`, `step-up/pin`, `pin/set`, ...) are session routes and go through `call()`; their typed wrappers are `session-routes.ts`.
 *
 * ENDING A SESSION IS IMMEDIATE (threat model: a shared shop iPad). `signOut()` and `lock()` copy the token into a local, wipe
 * it and tell the listeners (the screen goes to sign-in) BEFORE a byte is sent, then send with the copy and drop the copy as
 * soon as `fetch` has been called, so a request that never answers neither keeps the screen up nor keeps the token in memory.
 * Every request carries a timeout (REQUEST_TIMEOUT_MS), and a wipe aborts every authenticated request still in flight.
 * `lock()` REVOKES the session (it is a sign-out with the "locked" wording): a copied-out token is dead at once, not at its idle
 * expiry (design 20.4).
 *
 * THE BEARER GOES ONLY TO PARTNER FUNCTIONS: `call()` refuses any function name that is not in `partner-functions.json`, the
 * same list the build turns into the CSP's `connect-src` entries.
 */

import { kindForStatus, parseRetryAfter, PartnerApiError } from "./errors";
import PARTNER_FUNCTION_LIST from "./partner-functions.json";
import type { AssertionJson, ChallengeResponse, EnrolmentChallenge, FirstSessionGrant, ReauthResult, RegistrationJson, SessionGrant, WhoAmI } from "./types";

export const SESSION_FUNCTION = "partner-session";
/** The function that serves the pre-session invite and enrolment routes (and the first credential). */
export const INVITES_FUNCTION = "partner-invites";
/** Which kind of one-time token the person holds: an invite link (`gr_inv_`, a new member) or an enrolment token (`gr_enr_`, a recovery or an admin enrolment). */
export type EnrolmentKind = "invite" | "enrolment";
/** The partner functions this page may talk to (and may send the bearer to). One list, read by the client here and by scripts/lib/csp.mjs for `connect-src`. */
export const PARTNER_FUNCTIONS: readonly string[] = PARTNER_FUNCTION_LIST;
/** Every request is cut off after this long (a request that never answers must not pin a screen or a token). */
export const REQUEST_TIMEOUT_MS = 15_000;
const TOKEN_PREFIX = "gr_ps_";
/**
 * `gr_ps_` + 43 base64url characters: the shape the server issues (token.ts) and accepts. Checked WITHOUT a regular expression on purpose: V8 keeps the input
 * of the last successful regexp match alive in the realm (`regexp_last_match_info`), so `TOKEN_RE.test(token)` leaves a copy of a live token in the heap, out of
 * reach of every wipe, until some later regexp happens to overwrite it. (Found by the Playwright heap check on a cancelled or failed sign-in, where none did.)
 */
function isIssuedToken(v: string): boolean {
  if (v.length !== TOKEN_PREFIX.length + 43 || !v.startsWith(TOKEN_PREFIX)) return false;
  for (let i = TOKEN_PREFIX.length; i < v.length; i += 1) {
    const c = v.charCodeAt(i);
    const ok = (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 45 || c === 95;
    if (!ok) return false;
  }
  return true;
}
function acceptRoute(kind: EnrolmentKind, step: "start" | "verify"): string {
  return `${kind === "invite" ? "invites" : "enrolments"}/accept/${step}`;
}
const ERROR_CODE_RE = /^[a-z][a-z0-9_]{0,63}$/;

export type SessionEndReason = "signed-out" | "locked" | "expired" | "forgotten";

export interface PartnerApiConfig {
  /** The functions root, no trailing slash: `https://<host>/functions/v1`. Requests go to `<base>/<function>/<route>`. */
  readonly baseUrl: string;
  /** Injected for tests. The default is the global `fetch`, looked up at call time. */
  readonly fetch?: typeof fetch;
  readonly nowMs?: () => number;
  /** The partner functions `call()` may reach. Default: PARTNER_FUNCTIONS. Injected for tests only. */
  readonly functions?: readonly string[];
  /** Per-request timeout. Default: REQUEST_TIMEOUT_MS. Injected for tests only. */
  readonly timeoutMs?: number;
}

export interface EndOptions {
  /** `fetch(..., { keepalive: true })`: the request may outlive the page (a page that is going away). */
  readonly keepalive?: boolean;
}

export interface VerifyOptions {
  /**
   * The sign-in's cancel signal. It is NOT given to the request: a verify that is already on the wire may have created a session whose token only
   * the response carries, so cancelling it would orphan that session. Instead, if the signal is aborted by the time the response arrives, the new
   * token is revoked with a copy and never held, and verify rejects with kind "aborted".
   */
  readonly signal?: AbortSignal;
}

export interface RegisterFirstOptions {
  /** As for `VerifyOptions`: a cancel while the request is on the wire revokes the session it opened instead of holding it. */
  readonly signal?: AbortSignal;
}

export interface PartnerApi {
  hasSession(): boolean;
  /** `POST options`: a fresh sign-in challenge. */
  signInOptions(): Promise<ChallengeResponse>;
  /** `POST verify`: trades the assertion for a session. The token is kept inside the client and is NOT returned. */
  verify(input: { challengeToken: string; credential: AssertionJson }, opts?: VerifyOptions): Promise<SessionGrant>;
  /** `POST invites/accept/start` or `POST enrolments/accept/start` (no session): mails a one-time code to the address ON the invite. The server answers one constant body whatever the token is. */
  acceptStart(kind: EnrolmentKind, token: string): Promise<void>;
  /** `POST .../accept/verify` (no session): the emailed code, and the create ceremony's options if the token and the code were good. A refusal is one 403. */
  acceptVerify(kind: EnrolmentKind, input: { token: string; code: string }): Promise<EnrolmentChallenge>;
  /** `POST credentials` in enrolment mode (no session): the FIRST credential, which opens the person's first session. The token is kept inside the client and is NOT returned. */
  registerFirst(input: { challenge: EnrolmentChallenge; credential: RegistrationJson }, opts?: RegisterFirstOptions): Promise<FirstSessionGrant>;
  /** `GET session`: who am I (PEEK: does not extend the idle timer). */
  session(signal?: AbortSignal): Promise<WhoAmI>;
  /** `POST sign-out`: revokes the session on the server. The token is wiped (and the listeners told) BEFORE the request is sent, and the request uses a copy. */
  signOut(opts?: EndOptions): Promise<void>;
  /**
   * Lock: wipes the token and tells the listeners at once, then REVOKES the session with `POST sign-out` (design 20.4: lock must revoke, so a token copied
   * out of the page is dead immediately). The wording differs from sign-out (the reason is "locked"); the wire request is the same.
   */
  lock(opts?: EndOptions): Promise<void>;
  /** `POST reauth/options`. */
  reauthOptions(): Promise<ChallengeResponse>;
  /** `POST reauth`: a fresh passkey assertion by the session's own person. */
  reauth(input: { challengeToken: string; credential: AssertionJson }): Promise<ReauthResult>;
  /** An authenticated call to another partner function on the same API origin (later screens: attest, hand-over, stock). Same headers, same error mapping, same 401 handling. */
  call(method: "GET" | "POST" | "PATCH" | "DELETE", fn: string, route: string, body?: unknown): Promise<unknown>;
  /** Wipes the token without any request. */
  forgetSession(): void;
  /** Called after the token is wiped, with the reason. Returns an unsubscribe function. */
  onSessionEnded(listener: (reason: SessionEndReason) => void): () => void;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
const isString = (v: unknown): v is string => typeof v === "string";
const isStringOrNull = (v: unknown): v is string | null => v === null || typeof v === "string";
const isStringArray = (v: unknown): v is string[] => Array.isArray(v) && v.every(isString);

function malformed(status: number): PartnerApiError {
  return new PartnerApiError("malformed_response", { status });
}

function parseChallenge(data: unknown, status: number): ChallengeResponse {
  if (!isObject(data) || !isObject(data["options"]) || !isString(data["challengeToken"]) || !isString(data["expiresAt"])) throw malformed(status);
  return { options: data["options"], challengeToken: data["challengeToken"], expiresAt: data["expiresAt"] };
}

function parseWhoAmI(data: unknown, status: number): WhoAmI {
  if (!isObject(data)) throw malformed(status);
  const d = data;
  const stepUp = d["stepUp"];
  const memberships = d["memberships"];
  if (
    !isString(d["userId"]) || !isString(d["sessionId"]) ||
    typeof d["aal"] !== "number" || typeof d["requiredAal"] !== "number" ||
    !isString(d["createdAt"]) || !isString(d["lastSeenAt"]) || !isString(d["idleExpiresAt"]) || !isString(d["expiresAt"]) ||
    typeof d["isAdmin"] !== "boolean" || !isObject(stepUp) || !Array.isArray(memberships)
  ) throw malformed(status);
  if (typeof stepUp["pinGrantActive"] !== "boolean" || !isStringOrNull(stepUp["reauthUntil"] ?? null) || !isStringOrNull(stepUp["mfaUntil"] ?? null) || !isStringOrNull(stepUp["otpProofUntil"] ?? null) || !isStringOrNull(stepUp["enrolmentUntil"] ?? null)) throw malformed(status);
  const parsed = memberships.map((m: unknown) => {
    if (!isObject(m) || !isString(m["orgId"]) || !isString(m["role"]) || !isStringArray(m["facilityIds"]) || !isStringArray(m["trailIds"])) throw malformed(status);
    return { orgId: m["orgId"], role: m["role"], facilityIds: m["facilityIds"], trailIds: m["trailIds"] };
  });
  return {
    userId: d["userId"], sessionId: d["sessionId"], aal: d["aal"], requiredAal: d["requiredAal"],
    createdAt: d["createdAt"], lastSeenAt: d["lastSeenAt"], idleExpiresAt: d["idleExpiresAt"], expiresAt: d["expiresAt"],
    isAdmin: d["isAdmin"],
    stepUp: {
      pinGrantActive: stepUp["pinGrantActive"],
      reauthUntil: (stepUp["reauthUntil"] ?? null) as string | null,
      mfaUntil: (stepUp["mfaUntil"] ?? null) as string | null,
      otpProofUntil: (stepUp["otpProofUntil"] ?? null) as string | null,
      enrolmentUntil: (stepUp["enrolmentUntil"] ?? null) as string | null,
    },
    memberships: parsed,
  };
}

/** The signal of one request: the timeout, plus the caller's and the session's signals when there are any. Falls back where `AbortSignal.timeout` / `.any` are missing (older Safari). */
function requestSignal(timeoutMs: number, others: ReadonlyArray<AbortSignal | undefined>): AbortSignal {
  const signals: AbortSignal[] = [];
  if (typeof AbortSignal.timeout === "function") signals.push(AbortSignal.timeout(timeoutMs));
  else {
    const c = new AbortController();
    setTimeout(() => c.abort(new DOMException("request timed out", "TimeoutError")), timeoutMs);
    signals.push(c.signal);
  }
  for (const o of others) if (o !== undefined) signals.push(o);
  if (signals.length === 1) return signals[0] as AbortSignal;
  if (typeof AbortSignal.any === "function") return AbortSignal.any(signals);
  const merged = new AbortController();
  for (const sig of signals) {
    if (sig.aborted) {
      merged.abort(sig.reason);
      break;
    }
    sig.addEventListener("abort", () => merged.abort(sig.reason), { once: true });
  }
  return merged.signal;
}

export function createPartnerApi(config: PartnerApiConfig): PartnerApi {
  const base = config.baseUrl.replace(/\/+$/, "");
  const nowMs = config.nowMs ?? (() => Date.now());
  const timeoutMs = config.timeoutMs ?? REQUEST_TIMEOUT_MS;
  const allowedFunctions = config.functions ?? PARTNER_FUNCTIONS;
  // THE ONLY PLACE THE TOKEN IS HELD.
  let token: string | null = null;
  /** Changes whenever a token is stored or wiped, so a late answer can tell whether the session it was sent under is still the current one. */
  let epoch = 0;
  const listeners = new Set<(reason: SessionEndReason) => void>();
  /** Authenticated requests in flight under the CURRENT token: a wipe aborts them. */
  const inflight = new Set<AbortController>();

  function wipe(reason: SessionEndReason): void {
    const had = token !== null;
    token = null;
    if (!had) return;
    epoch += 1;
    for (const c of [...inflight]) c.abort();
    inflight.clear();
    for (const l of [...listeners]) {
      try {
        l(reason);
      } catch {
        // a listener's failure must not stop the others, nor the request that follows the wipe
      }
    }
  }

  /**
   * Starts one request and returns the pending response. NOT async on purpose: when it returns, nothing in this module's frames references the
   * bearer's header any more (the caller drops its own copy), so the page holds no copy of a token whose request is still hanging.
   */
  function dispatch(method: "GET" | "POST" | "PATCH" | "DELETE", fn: string, route: string, body: unknown, bearer: string | null, signal: AbortSignal, keepalive: boolean): Promise<Response> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (bearer !== null) headers["Authorization"] = `Bearer ${bearer}`;
    const init: RequestInit = {
      method,
      headers,
      credentials: "omit",
      mode: "cors",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal,
    };
    if (keepalive) init.keepalive = true;
    if (method !== "GET") init.body = JSON.stringify(body ?? {});
    return (config.fetch ?? fetch)(`${base}/${fn}/${route}`, init);
  }

  /** Reads the response of a dispatched request into `{ status, data }` or throws the typed error. `sessionEpoch`: the session a 401 may end (null: none). */
  async function finish(pending: Promise<Response>, sessionEpoch: number | null): Promise<{ status: number; data: unknown }> {
    let res: Response;
    try {
      res = await pending;
    } catch {
      throw new PartnerApiError("network");
    }
    if (res.ok) {
      let parsed: unknown;
      try {
        parsed = await res.json();
      } catch {
        throw malformed(res.status);
      }
      if (!isObject(parsed) || !("data" in parsed)) throw malformed(res.status);
      return { status: res.status, data: parsed["data"] };
    }
    let code: string | null = null;
    try {
      const parsed: unknown = await res.json();
      const c = isObject(parsed) && isObject(parsed["error"]) ? parsed["error"]["code"] : null;
      code = isString(c) && ERROR_CODE_RE.test(c) ? c : null;
    } catch {
      code = null;
    }
    const kind = kindForStatus(res.status, code);
    const err = new PartnerApiError(kind, {
      status: res.status,
      code,
      retryAfterSeconds: kind === "rate_limited" ? parseRetryAfter(res.headers.get("retry-after"), nowMs()) : null,
    });
    // a 401 on a request made under the CURRENT session means that session is dead: nothing is left to protect, so the token goes before anyone sees the error
    if (sessionEpoch !== null && sessionEpoch === epoch && kind === "unauthenticated") wipe("expired");
    throw err;
  }

  /** A request without a bearer (options, verify, the invite and enrolment routes). */
  function sendPublic(route: string, body: unknown, signal?: AbortSignal, fn: string = SESSION_FUNCTION): Promise<{ status: number; data: unknown }> {
    return finish(dispatch("POST", fn, route, body, null, requestSignal(timeoutMs, [signal]), false), null);
  }

  /**
   * The answer of a request that opens a session (`verify`, and `credentials` in enrolment mode): checks the token's shape, then either HOLDS it or, when the
   * caller cancelled while the request was on the wire (or another sign-in finished first), revokes it with a copy and never holds it. Returns the other fields.
   */
  async function adoptSession(r: { status: number; data: unknown }, signal: AbortSignal | undefined): Promise<Record<string, unknown>> {
    const d = r.data;
    if (!isObject(d) || !isString(d["token"]) || !isIssuedToken(d["token"]) || !isString(d["expiresAt"]) || typeof d["aal"] !== "number") throw malformed(r.status);
    if (signal?.aborted === true || token !== null) {
      const aborted = signal?.aborted === true;
      try {
        await revokeCopy(d["token"], false);
      } catch {
        // best effort: nothing holds this token, and the idle timer ends the session
      }
      throw aborted ? new PartnerApiError("aborted") : new PartnerApiError("bad_request", { code: "session_exists" });
    }
    token = d["token"];
    epoch += 1;
    return d;
  }

  /** A request under the live session token: aborted by a wipe, timed out, and a 401 ends the session. */
  async function sendAuthed(method: "GET" | "POST" | "PATCH" | "DELETE", fn: string, route: string, body: unknown, signal?: AbortSignal): Promise<{ status: number; data: unknown }> {
    if (token === null) throw new PartnerApiError("unauthenticated");
    const life = new AbortController();
    inflight.add(life);
    const sessionEpoch = epoch;
    try {
      return await finish(dispatch(method, fn, route, body, token, requestSignal(timeoutMs, [signal, life.signal]), false), sessionEpoch);
    } finally {
      inflight.delete(life);
    }
  }

  /** Revokes `bearer` (a copy that is no longer held by this client) with `POST sign-out`. NOT async: see `dispatch`. */
  function revokeCopy(bearer: string, keepalive: boolean): Promise<void> {
    return finish(dispatch("POST", SESSION_FUNCTION, "sign-out", {}, bearer, requestSignal(timeoutMs, []), keepalive), null).then(() => undefined);
  }

  /**
   * Ends the session NOW and revokes it on the server afterwards. Order is the point: the token is copied, wiped and the listeners are told (so the
   * screen is signed-out) before anything is sent; the request then uses the copy, and the copy is dropped as soon as `fetch` has been called.
   * NOT async, so no suspended frame keeps the copy. Rejects with the request's error (the wipe has happened either way).
   */
  function endSession(reason: SessionEndReason, keepalive: boolean): Promise<void> {
    let copy = token;
    if (copy === null) return Promise.reject(new PartnerApiError("unauthenticated"));
    wipe(reason);
    const pending = revokeCopy(copy, keepalive);
    copy = null;
    return pending;
  }

  const sessionCall = (route: string, signal?: AbortSignal) => sendAuthed("GET", SESSION_FUNCTION, route, undefined, signal);

  return {
    hasSession: () => token !== null,

    async signInOptions() {
      const r = await sendPublic("options", {});
      return parseChallenge(r.data, r.status);
    },

    async verify(input, opts = {}) {
      if (token !== null) throw new PartnerApiError("bad_request", { code: "session_exists" });
      // no caller signal on the request itself: see VerifyOptions
      const r = await sendPublic("verify", { challengeToken: input.challengeToken, credential: input.credential });
      const d = await adoptSession(r, opts.signal);
      return { expiresAt: d["expiresAt"] as string, aal: d["aal"] as number };
    },

    async acceptStart(kind, oneTimeToken) {
      const r = await sendPublic(acceptRoute(kind, "start"), { token: oneTimeToken }, undefined, INVITES_FUNCTION);
      if (!isObject(r.data) || r.data["requested"] !== true) throw malformed(r.status);
    },

    async acceptVerify(kind, input) {
      const r = await sendPublic(acceptRoute(kind, "verify"), { token: input.token, code: input.code }, undefined, INVITES_FUNCTION);
      const d = r.data;
      if (
        !isObject(d) || !isObject(d["options"]) || !isString(d["challengeToken"]) || !isString(d["expiresAt"]) || !isString(d["userId"]) || !isString(d["refId"]) ||
        d["refKind"] !== kind
      ) throw malformed(r.status);
      return { options: d["options"], challengeToken: d["challengeToken"], expiresAt: d["expiresAt"], userId: d["userId"], refKind: kind, refId: d["refId"] };
    },

    async registerFirst(input, opts = {}) {
      if (token !== null) throw new PartnerApiError("bad_request", { code: "session_exists" });
      const c = input.challenge;
      const r = await sendPublic("credentials", { userId: c.userId, refKind: c.refKind, refId: c.refId, challengeToken: c.challengeToken, credential: input.credential }, undefined, INVITES_FUNCTION);
      // a session without the enrolment window is not the documented answer: refused before the token is held
      if (!isObject(r.data) || !isString(r.data["enrolmentUntil"])) throw malformed(r.status);
      const d = await adoptSession(r, opts.signal);
      return { expiresAt: d["expiresAt"] as string, aal: d["aal"] as number, enrolmentUntil: r.data["enrolmentUntil"] };
    },

    async session(signal) {
      const r = await sessionCall("session", signal);
      return parseWhoAmI(r.data, r.status);
    },

    signOut: (opts = {}) => endSession("signed-out", opts.keepalive === true),

    lock: (opts = {}) => endSession("locked", opts.keepalive === true),

    async reauthOptions() {
      const r = await sendAuthed("POST", SESSION_FUNCTION, "reauth/options", {});
      return parseChallenge(r.data, r.status);
    },

    async reauth(input) {
      const r = await sendAuthed("POST", SESSION_FUNCTION, "reauth", { challengeToken: input.challengeToken, credential: input.credential });
      if (!isObject(r.data) || !isString(r.data["reauthUntil"])) throw malformed(r.status);
      return { reauthUntil: r.data["reauthUntil"] };
    },

    async call(method, fn, route, body) {
      // the bearer is attached here, so the target is a closed shape: a function on the explicit partner allow-list (never any other path on the API host, and the
      // same list the CSP's connect-src is built from), and a route of path-safe characters, no dot segments, no query, no fragment
      if (!allowedFunctions.includes(fn) || !/^[a-z][a-z0-9-]{0,63}$/.test(fn) || !/^[A-Za-z0-9_~/-]{0,200}$/.test(route) || route.includes("//")) throw new PartnerApiError("bad_request");
      return (await sendAuthed(method, fn, route, body)).data;
    },

    forgetSession: () => wipe("forgotten"),

    onSessionEnded(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
}
