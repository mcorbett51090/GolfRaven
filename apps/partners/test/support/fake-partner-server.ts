/**
 * A fake partner API for tests that runs the REAL `partner-session` handler (supabase/functions/_shared/partner/session-handler.ts) over in-memory
 * ports: so the SPA's requests are judged by the server's own Origin check, media-type rule, bearer-shape rule and strict body parser, not by a
 * second opinion written for this suite. Only the two ports are fake:
 *
 *   - `PartnerDb`: a stateful in-memory store (credentials, issued challenges and their one-time nonces, sessions, a rate-limit counter);
 *   - `AssertionVerifier`: a REAL ES256 verification (ECDSA over authenticatorData || sha256(clientDataJSON)) plus the checks the S0 wrapper makes
 *     (type, challenge, exact origin, rpIdHash, UP and UV flags, user handle, the counter).
 *
 * The sign-in `options` it returns have the shape `@simplewebauthn/server@14.0.3` `generateAuthenticationOptions` returns (read from the library
 * source in the Deno cache: `{ rpId, challenge, allowCredentials, timeout, userVerification, extensions }`).
 *
 * `handler` is a `(Request) => Promise<Response>`; `httpServer()` wraps it in a node:http server for the Playwright suite.
 */
import { createHash, randomBytes, verify } from "node:crypto";
import { createServer, type IncomingMessage, type Server } from "node:http";
import {
  type AssertionVerifier,
  type ChallengeIssue,
  type CredentialLookup,
  type MintInput,
  type MintResult,
  type PartnerDb,
  type PartnerMintTx,
  type PartnerSessionTx,
  PartnerSessionRefused,
  type ReauthCredential,
  type ReauthInput,
  type RpConfig,
  type VerifyAssertionRequest,
  type VerifyOutcome,
} from "../../../../supabase/functions/_shared/partner/ports.ts";
import { handlePartnerSessionRequest } from "../../../../supabase/functions/_shared/partner/session-handler.ts";
import { fromB64u, sha256Hex, toB64u } from "../../../../supabase/functions/_shared/partner/token.ts";
import { publicKeyFromSpki, type SoftCredential } from "./soft-authenticator";

export const USER_ID = "00000000-0000-4000-8000-0000000000a1";

export interface LoggedRequest {
  readonly method: string;
  readonly path: string;
  readonly contentType: string | null;
  readonly authorization: string | null;
  readonly cookie: string | null;
  readonly origin: string | null;
  readonly referer: string | null;
  readonly body: string;
}

export interface FakeServerOptions {
  /** The page's origin: what CORS allows and what a signed `clientDataJSON.origin` must equal. */
  readonly pageOrigin: string;
  readonly rpId: string;
  readonly credential: SoftCredential;
  readonly whoami?: Partial<{ aal: number; requiredAal: number; isAdmin: boolean; memberships: unknown[] }>;
}

export interface FakeServer {
  readonly handler: (req: Request) => Promise<Response>;
  readonly log: LoggedRequest[];
  /** every raw token the server issued (only for assertions that the client never leaks them) */
  readonly issuedTokens: string[];
  readonly state: {
    revokedSessions: Set<string>;
    lockCalls: number;
    signOutCalls: number;
    /** after this many reauth hits, answer 429 with Retry-After */
    reauthLimit: number;
    reauthHits: number;
    /** answer every `options` call with 503 */
    unavailable: boolean;
    reauthUntil: string | null;
    /** routes (the part after `/partner-session/`, e.g. "sign-out", "session") whose non-preflight requests are received, logged and then NEVER ANSWERED until reset() */
    hang: Set<string>;
    /** route -> ms: the handler runs (the server's state changes) and the RESPONSE is held back this long */
    delayAfter: Record<string, number>;
    /** when set, every `options` call is answered 429 with this Retry-After (seconds) */
    optionsRetryAfter: number | null;
  };
  /** the sha256 hex of every LIVE (not revoked) session token */
  sessions(): string[];
  /** kills a live session on the server (as an idle expiry would) without the client knowing */
  killAllSessions(): void;
  /** back to the state of a freshly created server: no sessions, no challenges, no log, counters and knobs at their defaults */
  reset(): void;
  httpServer(): Server;
}

const sha256 = (d: Uint8Array | string): Buffer => createHash("sha256").update(d).digest();

export function createFakePartnerServer(opts: FakeServerOptions): FakeServer {
  const rp: RpConfig = { rpId: opts.rpId, origin: opts.pageOrigin };
  const credId = toB64u(opts.credential.credentialId);
  const credentialRow = { id: "11111111-1111-4111-8111-111111111111", userId: USER_ID, alg: -7, publicKey: opts.credential.publicKeySpki, signCount: 0 };
  const challenges = new Map<string, { mac: string; exp: number; used: boolean; sessionHash: string | null }>();
  const sessions = new Map<string, { userId: string; createdAt: Date }>();
  const log: LoggedRequest[] = [];
  const issuedTokens: string[] = [];
  const state: FakeServer["state"] = { revokedSessions: new Set(), lockCalls: 0, signOutCalls: 0, reauthLimit: Number.POSITIVE_INFINITY, reauthHits: 0, unavailable: false, reauthUntil: null, hang: new Set(), delayAfter: {}, optionsRetryAfter: null };
  const held: Array<() => void> = [];
  let signCount = 0;

  const issue = (sessionHash: string | null): ChallengeIssue => {
    const nonce = randomBytes(32);
    const mac = randomBytes(32);
    const exp = Math.floor(Date.now() / 1000) + 120;
    challenges.set(toB64u(nonce), { mac: toB64u(mac), exp, used: false, sessionHash });
    return { nonce, exp, mac };
  };
  const consume = (nonce: Uint8Array, exp: number, mac: Uint8Array, sessionHash: string | null): boolean => {
    const c = challenges.get(toB64u(nonce));
    if (c === undefined || c.used || c.exp !== exp || c.mac !== toB64u(mac) || c.sessionHash !== sessionHash || c.exp * 1000 <= Date.now()) return false;
    c.used = true;
    return true;
  };

  const verifier: AssertionVerifier = {
    async options(_rp: RpConfig, challenge: Uint8Array) {
      return { rpId: _rp.rpId, challenge: toB64u(challenge), allowCredentials: [], timeout: 60000, userVerification: "required" };
    },
    async verify(input: VerifyAssertionRequest): Promise<VerifyOutcome> {
      const refuse: VerifyOutcome = { ok: false, counterOnly: false };
      const cd = fromB64u(input.response.response.clientDataJSON);
      const ad = fromB64u(input.response.response.authenticatorData);
      const sig = fromB64u(input.response.response.signature);
      if (cd === null || ad === null || sig === null || ad.length < 37) return refuse;
      let client: { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
      try {
        client = JSON.parse(new TextDecoder().decode(cd));
      } catch {
        return refuse;
      }
      if (client.type !== "webauthn.get" || client.challenge !== toB64u(input.expectedChallenge) || client.origin !== input.rp.origin || client.crossOrigin === true) return refuse;
      if (!Buffer.from(ad.subarray(0, 32)).equals(sha256(input.rp.rpId))) return refuse;
      const flags = ad[32] ?? 0;
      if ((flags & 0x01) === 0 || (flags & 0x04) === 0) return refuse; // user present and user verified
      const uh = input.response.response.userHandle;
      if (uh !== undefined) {
        const got = fromB64u(uh);
        if (got === null || !Buffer.from(got).equals(Buffer.from(input.expectedUserHandle))) return refuse;
      }
      const ok = verify("sha256", Buffer.concat([Buffer.from(ad), sha256(cd)]), { key: publicKeyFromSpki(input.credential.publicKey), dsaEncoding: "der" }, Buffer.from(sig));
      if (!ok) return refuse;
      const counter = Buffer.from(ad).readUInt32BE(33);
      if ((counter !== 0 || input.credential.signCount !== 0) && counter <= input.credential.signCount) return { ok: false, counterOnly: true };
      return { ok: true };
    },
  };

  const whoamiPayload = (sessionHash: string) => {
    const s = sessions.get(sessionHash)!;
    const now = Date.now();
    const iso = (ms: number) => new Date(ms).toISOString();
    return {
      userId: s.userId,
      sessionId: "22222222-2222-4222-8222-222222222222",
      aal: opts.whoami?.aal ?? 1,
      requiredAal: opts.whoami?.requiredAal ?? 1,
      createdAt: iso(s.createdAt.getTime()),
      lastSeenAt: iso(now),
      idleExpiresAt: iso(now + 30 * 60_000),
      expiresAt: iso(s.createdAt.getTime() + 8 * 3_600_000),
      isAdmin: opts.whoami?.isAdmin ?? false,
      stepUp: { pinGrantActive: false, reauthUntil: state.reauthUntil, mfaUntil: null, otpProofUntil: null, enrolmentUntil: null },
      memberships: opts.whoami?.memberships ?? [{ orgId: "33333333-3333-4333-8333-333333333333", role: "staff", facilityIds: ["44444444-4444-4444-8444-444444444444"], trailIds: [] }],
    };
  };

  const db: PartnerDb = {
    async withMint(op) {
      const tx: PartnerMintTx = {
        async rpConfig() {
          return rp;
        },
        async issueChallenge() {
          return issue(null);
        },
        async lookupCredential(id: Uint8Array): Promise<CredentialLookup> {
          return toB64u(id) === credId ? { status: "ok", credential: { ...credentialRow, signCount } } : { status: "unknown" };
        },
        async recordFailure() {
          return "counted";
        },
        async mint(input: MintInput): Promise<MintResult> {
          if (!consume(input.nonce, input.exp, input.mac, null)) return { status: "challenge_invalid", aal: null, expiresAt: null };
          signCount = Buffer.from(input.authenticatorData).readUInt32BE(33);
          sessions.set(input.tokenHash, { userId: USER_ID, createdAt: new Date() });
          return { status: "ok", aal: opts.whoami?.aal ?? 1, expiresAt: new Date(Date.now() + 8 * 3_600_000).toISOString() };
        },
      };
      return await op(tx);
    },
    async withSession(hash, op) {
      if (!sessions.has(hash) || state.revokedSessions.has(hash)) throw new PartnerSessionRefused();
      const tx: PartnerSessionTx = {
        async whoami() {
          return whoamiPayload(hash);
        },
        async signOut() {
          state.signOutCalls += 1;
          state.revokedSessions.add(hash);
        },
        async lock() {
          state.lockCalls += 1;
          state.reauthUntil = null;
        },
        async reauthOptions() {
          return { ...issue(hash), rp };
        },
        async reauthCredential(id: Uint8Array): Promise<ReauthCredential | null> {
          return toB64u(id) === credId ? { ...credentialRow, signCount, rp } : null;
        },
        // S1.3 step-up surface: fail closed. The S7a page never calls these (S7b builds the PIN screens and will implement the flows in this fake).
        async pinParams(): Promise<never> {
          throw new Error("fake partner server: the PIN flows are not implemented (S7b)");
        },
        async pinVerify(): Promise<never> {
          throw new Error("fake partner server: the PIN flows are not implemented (S7b)");
        },
        async pinSet(): Promise<never> {
          throw new Error("fake partner server: the PIN flows are not implemented (S7b)");
        },
        async pinChange(): Promise<never> {
          throw new Error("fake partner server: the PIN flows are not implemented (S7b)");
        },
        // S1.4 TOTP surface: fail closed. The S7 PIN/TOTP screens will implement these in this fake.
        async totpEnrol(): Promise<never> {
          throw new Error("fake partner server: the TOTP flows are not implemented (S7)");
        },
        async totpConfirm(): Promise<never> {
          throw new Error("fake partner server: the TOTP flows are not implemented (S7)");
        },
        async totpVerify(): Promise<never> {
          throw new Error("fake partner server: the TOTP flows are not implemented (S7)");
        },
        async totpReset(): Promise<never> {
          throw new Error("fake partner server: the TOTP flows are not implemented (S7)");
        },
        async otpTarget() {
          return null; // no mailbox: the email proof cannot start
        },
        async otpProof() {
          return { status: "refused" as const, otpProofUntil: null };
        },
        async reauth(input: ReauthInput) {
          if (!consume(input.nonce, input.exp, input.mac, hash)) return { status: "challenge_invalid", reauthUntil: null };
          signCount = Buffer.from(input.authenticatorData).readUInt32BE(33);
          state.reauthUntil = new Date(Date.now() + 5 * 60_000).toISOString();
          return { status: "ok", reauthUntil: state.reauthUntil };
        },
      };
      return await op(tx);
    },
    async hitRateLimit(hash) {
      if (!sessions.has(hash) || state.revokedSessions.has(hash)) throw new PartnerSessionRefused();
      state.reauthHits += 1;
      return state.reauthHits > state.reauthLimit ? { ok: false, retryAfterSeconds: 1800 } : { ok: true, retryAfterSeconds: 0 };
    },
    // S1.5 invite/member surface: fail closed. The S7 invite and member screens will implement these in this fake.
    withInviteMint() {
      return Promise.reject(new Error("fake partner server: invite mint is not implemented (S7)"));
    },
    withInvites() {
      return Promise.reject(new Error("fake partner server: invites are not implemented (S7)"));
    },
    withMembers() {
      return Promise.reject(new Error("fake partner server: members are not implemented (S7)"));
    },
    withAttest() {
      return Promise.reject(new Error("fake partner server: attest is not implemented (S7b)"));
    },
    withReview() {
      return Promise.reject(new Error("fake partner server: review is not implemented (S7d)"));
    },
    withStock() {
      return Promise.reject(new Error("fake partner server: stock is not implemented (S7c)"));
    },
    withEntitlements() {
      return Promise.reject(new Error("fake partner server: entitlements are not implemented (S7c)"));
    },
    withProgramme() {
      return Promise.reject(new Error("fake partner server: programme is not implemented (S7d)"));
    },
    withOffersAdmin() {
      return Promise.reject(new Error("fake partner server: offers-admin is not implemented (S7d)"));
    },
    withSponsorships() {
      return Promise.reject(new Error("fake partner server: sponsorships are not implemented (S7d)"));
    },
    async hitSystemRateLimit() {
      return { ok: true, retryAfterSeconds: 0 };
    },
  };

  const innerHandler = (req: Request) =>
    handlePartnerSessionRequest(req, {
      db,
      allowedOrigin: opts.pageOrigin,
      webauthn: verifier,
      // the email OTP of the step-up proof: nothing is sent and every code is refused (S7b)
      otp: {
        async send() {
          throw new Error("fake partner server: the email OTP is not implemented (S7b)");
        },
        async verify() {
          return { ok: false as const };
        },
      },
      nowMs: () => Date.now(),
      newSessionToken: async () => {
        const token = "gr_ps_" + toB64u(randomBytes(32));
        issuedTokens.push(token);
        return { token, hash: await sha256Hex(token) };
      },
    });

  const handler = async (req: Request): Promise<Response> => {
    const body = req.method === "GET" || req.method === "OPTIONS" ? "" : await req.clone().text();
    log.push({
      method: req.method,
      path: new URL(req.url).pathname,
      contentType: req.headers.get("content-type"),
      authorization: req.headers.get("authorization"),
      cookie: req.headers.get("cookie"),
      origin: req.headers.get("origin"),
      referer: req.headers.get("referer"),
      body,
    });
    const route = new URL(req.url).pathname.split("/partner-session/")[1] ?? "";
    if (req.method !== "OPTIONS" && state.hang.has(route)) {
      return await new Promise<Response>((resolve) => {
        held.push(() => resolve(new Response(null, { status: 503 })));
      });
    }
    if (state.optionsRetryAfter !== null && route === "options" && req.method === "POST") {
      return new Response(JSON.stringify({ error: { code: "rate_limited", message: "too many attempts" } }), {
        status: 429,
        headers: { "content-type": "application/json", "access-control-allow-origin": opts.pageOrigin, "access-control-expose-headers": "Retry-After", "retry-after": String(state.optionsRetryAfter), vary: "Origin" },
      });
    }
    if (state.unavailable && new URL(req.url).pathname.endsWith("/options") && req.method === "POST") {
      return new Response(JSON.stringify({ error: { code: "service_unavailable", message: "partner sign-in is not available" } }), { status: 503, headers: { "content-type": "application/json", "access-control-allow-origin": opts.pageOrigin, vary: "Origin" } });
    }
    const res = await innerHandler(req);
    const delay = req.method === "OPTIONS" ? undefined : state.delayAfter[route];
    if (delay !== undefined) await new Promise((r) => setTimeout(r, delay));
    return res;
  };

  return {
    handler,
    log,
    issuedTokens,
    state,
    sessions: () => [...sessions.keys()].filter((h) => !state.revokedSessions.has(h)),
    reset() {
      sessions.clear();
      challenges.clear();
      log.length = 0;
      issuedTokens.length = 0;
      signCount = 0;
      for (const release of held.splice(0)) release();
      Object.assign(state, { revokedSessions: new Set<string>(), lockCalls: 0, signOutCalls: 0, reauthLimit: Number.POSITIVE_INFINITY, reauthHits: 0, unavailable: false, reauthUntil: null, hang: new Set<string>(), delayAfter: {}, optionsRetryAfter: null });
    },
    killAllSessions: () => {
      for (const h of sessions.keys()) state.revokedSessions.add(h);
    },
    httpServer() {
      return createServer((nodeReq: IncomingMessage, nodeRes) => {
        const chunks: Buffer[] = [];
        nodeReq.on("data", (c: Buffer) => chunks.push(c));
        nodeReq.on("end", () => {
          void (async () => {
            const host = nodeReq.headers.host ?? "localhost";
            const method = nodeReq.method ?? "GET";
            const headers = new Headers();
            for (const [k, v] of Object.entries(nodeReq.headers)) if (v !== undefined) headers.set(k, Array.isArray(v) ? v.join(", ") : v);
            const hasBody = method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
            const init: RequestInit = { method, headers };
            if (hasBody) init.body = Buffer.concat(chunks);
            const res = await handler(new Request(`http://${host}${nodeReq.url ?? "/"}`, init));
            const out: Record<string, string> = {};
            res.headers.forEach((v, k) => {
              out[k] = v;
            });
            nodeRes.writeHead(res.status, out);
            nodeRes.end(Buffer.from(await res.arrayBuffer()));
          })();
        });
      });
    },
  };
}

/**
 * A `fetch` that behaves like a browser's CORS enforcement for a page at `pageOrigin`: it adds the `Origin` header, runs the preflight a JSON or
 * Authorization request needs, and (like a browser) turns a response without the right `Access-Control-Allow-Origin` into a network error. It is a
 * SIMPLIFIED model (the real thing is the Playwright suite), enough to prove the client's requests pass the real handler's Origin and preflight rules.
 */
export function browserLikeFetch(handler: (req: Request) => Promise<Response>, pageOrigin: string, apiBase: string): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    const headers = new Headers(init?.headers);
    const sendsAuth = headers.has("authorization");
    const preflightNeeded = !["GET", "HEAD", "POST"].includes(method) || sendsAuth || (headers.get("content-type") ?? "") !== "text/plain";
    if (new URL(url).origin !== new URL(apiBase).origin) throw new TypeError("blocked: not the API origin");
    if (preflightNeeded) {
      const pre = await handler(new Request(url, { method: "OPTIONS", headers: { origin: pageOrigin, "access-control-request-method": method, "access-control-request-headers": [...headers.keys()].sort().join(",") } }));
      const allowOrigin = pre.headers.get("access-control-allow-origin");
      const allowMethods = (pre.headers.get("access-control-allow-methods") ?? "").split(",").map((s) => s.trim());
      const allowHeaders = (pre.headers.get("access-control-allow-headers") ?? "").split(",").map((s) => s.trim().toLowerCase());
      if (pre.status !== 204 || allowOrigin !== pageOrigin || !allowMethods.includes(method) || ![...headers.keys()].every((k) => allowHeaders.includes(k.toLowerCase()))) throw new TypeError("CORS preflight failed");
    }
    headers.set("origin", pageOrigin);
    const reqInit: RequestInit = { method, headers };
    if (init?.body !== undefined && init.body !== null) reqInit.body = init.body;
    const res = await handler(new Request(url, reqInit));
    if (res.headers.get("access-control-allow-origin") !== pageOrigin) throw new TypeError("CORS: response not allowed for this origin");
    // like a browser, a cross-origin page sees only the CORS-safelisted response headers plus those named in Access-Control-Expose-Headers (the S1.2 server names none: Retry-After is hidden)
    const visible = new Set(["cache-control", "content-language", "content-length", "content-type", "expires", "last-modified", "pragma", ...(res.headers.get("access-control-expose-headers") ?? "").split(",").map((h) => h.trim().toLowerCase()).filter((h) => h !== "")]);
    const filtered = new Headers();
    res.headers.forEach((v, k) => {
      if (visible.has(k)) filtered.set(k, v);
    });
    return new Response(res.body, { status: res.status, headers: filtered });
  }) as typeof fetch;
}
