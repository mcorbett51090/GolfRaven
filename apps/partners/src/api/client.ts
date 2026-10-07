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
 */

import { kindForStatus, parseRetryAfter, PartnerApiError } from "./errors";
import type { AssertionJson, ChallengeResponse, ReauthResult, SessionGrant, WhoAmI } from "./types";

export const SESSION_FUNCTION = "partner-session";
/** `gr_ps_` + 43 base64url characters: the shape the server issues (token.ts) and accepts. */
const TOKEN_RE = /^gr_ps_[A-Za-z0-9_-]{43}$/;
const ERROR_CODE_RE = /^[a-z][a-z0-9_]{0,63}$/;

export type SessionEndReason = "signed-out" | "locked" | "expired" | "forgotten";

export interface PartnerApiConfig {
  /** The functions root, no trailing slash: `https://<host>/functions/v1`. Requests go to `<base>/<function>/<route>`. */
  readonly baseUrl: string;
  /** Injected for tests. The default is the global `fetch`, looked up at call time. */
  readonly fetch?: typeof fetch;
  readonly nowMs?: () => number;
}

export interface PartnerApi {
  hasSession(): boolean;
  /** `POST options`: a fresh sign-in challenge. */
  signInOptions(): Promise<ChallengeResponse>;
  /** `POST verify`: trades the assertion for a session. The token is kept inside the client and is NOT returned. */
  verify(input: { challengeToken: string; credential: AssertionJson }): Promise<SessionGrant>;
  /** `GET session`: who am I (PEEK: does not extend the idle timer). */
  session(): Promise<WhoAmI>;
  /** `POST sign-out`: revokes the session on the server. The token is wiped whether or not the request succeeds. */
  signOut(): Promise<void>;
  /** `POST lock`: clears every step-up grant on the server, then wipes the token (a locked screen needs a fresh passkey tap). The token is wiped whether or not the request succeeds. */
  lock(): Promise<void>;
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

export function createPartnerApi(config: PartnerApiConfig): PartnerApi {
  const base = config.baseUrl.replace(/\/+$/, "");
  const nowMs = config.nowMs ?? (() => Date.now());
  // THE ONLY PLACE THE TOKEN IS HELD.
  let token: string | null = null;
  const listeners = new Set<(reason: SessionEndReason) => void>();

  function wipe(reason: SessionEndReason): void {
    const had = token !== null;
    token = null;
    if (had) for (const l of [...listeners]) l(reason);
  }

  async function send(method: "GET" | "POST" | "PATCH" | "DELETE", fn: string, route: string, body: unknown, authed: boolean): Promise<{ status: number; data: unknown }> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (authed) {
      if (token === null) throw new PartnerApiError("unauthenticated");
      headers["Authorization"] = `Bearer ${token}`;
    }
    const init: RequestInit = {
      method,
      headers,
      credentials: "omit",
      mode: "cors",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
    };
    if (method !== "GET") init.body = JSON.stringify(body ?? {});
    let res: Response;
    try {
      res = await (config.fetch ?? fetch)(`${base}/${fn}/${route}`, init);
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
    // a 401 on an authenticated call means the session is dead: nothing is left to protect, so the token goes before anyone sees the error
    if (authed && kind === "unauthenticated") wipe("expired");
    throw err;
  }

  const sessionCall = (method: "GET" | "POST", route: string) => send(method, SESSION_FUNCTION, route, undefined, true);

  return {
    hasSession: () => token !== null,

    async signInOptions() {
      const r = await send("POST", SESSION_FUNCTION, "options", {}, false);
      return parseChallenge(r.data, r.status);
    },

    async verify(input) {
      const r = await send("POST", SESSION_FUNCTION, "verify", { challengeToken: input.challengeToken, credential: input.credential }, false);
      const d = r.data;
      if (!isObject(d) || !isString(d["token"]) || !TOKEN_RE.test(d["token"]) || !isString(d["expiresAt"]) || typeof d["aal"] !== "number") throw malformed(r.status);
      token = d["token"];
      return { expiresAt: d["expiresAt"], aal: d["aal"] };
    },

    async session() {
      const r = await sessionCall("GET", "session");
      return parseWhoAmI(r.data, r.status);
    },

    async signOut() {
      try {
        await send("POST", SESSION_FUNCTION, "sign-out", {}, true);
      } finally {
        wipe("signed-out");
      }
    },

    async lock() {
      try {
        await send("POST", SESSION_FUNCTION, "lock", {}, true);
      } finally {
        wipe("locked");
      }
    },

    async reauthOptions() {
      const r = await send("POST", SESSION_FUNCTION, "reauth/options", {}, true);
      return parseChallenge(r.data, r.status);
    },

    async reauth(input) {
      const r = await send("POST", SESSION_FUNCTION, "reauth", { challengeToken: input.challengeToken, credential: input.credential }, true);
      if (!isObject(r.data) || !isString(r.data["reauthUntil"])) throw malformed(r.status);
      return { reauthUntil: r.data["reauthUntil"] };
    },

    async call(method, fn, route, body) {
      // the bearer is attached here, so the path is a closed shape: a function name and a route of path-safe characters, no dot segments, no query, no fragment
      if (!/^[a-z][a-z0-9-]{0,63}$/.test(fn) || !/^[A-Za-z0-9_~/-]{0,200}$/.test(route) || route.includes("//")) throw new PartnerApiError("bad_request");
      return (await send(method, fn, route, body, true)).data;
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
