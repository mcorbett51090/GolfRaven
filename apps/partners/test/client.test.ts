import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPartnerApi, PARTNER_FUNCTIONS, REQUEST_TIMEOUT_MS, SESSION_FUNCTION, type PartnerApi, type PartnerApiConfig } from "../src/api/client";
import { isPartnerApiError, kindForStatus, parseRetryAfter, PartnerApiError } from "../src/api/errors";
import type { AssertionJson } from "../src/api/types";
import { installStorageSpies, type StorageSpies } from "./support/storage-spies";
import { jsonResponse, stubFetch, VALID_TOKEN, type Recorded } from "./support/stub-fetch";

const BASE = "https://api.example.test/functions/v1";
const CHALLENGE = "A".repeat(43) + ".1893456000." + "B".repeat(43);
const CRED: AssertionJson = { id: "Y3JlZA", rawId: "Y3JlZA", type: "public-key", response: { clientDataJSON: "e30", authenticatorData: "AAAA", signature: "c2ln" } };
const WHOAMI = {
  userId: "u",
  sessionId: "s",
  aal: 1,
  requiredAal: 1,
  createdAt: "2030-01-01T00:00:00Z",
  lastSeenAt: "2030-01-01T00:00:00Z",
  idleExpiresAt: "2030-01-01T00:30:00Z",
  expiresAt: "2030-01-01T08:00:00Z",
  isAdmin: false,
  stepUp: { pinGrantActive: false, reauthUntil: null, mfaUntil: null, otpProofUntil: null, enrolmentUntil: null },
  memberships: [{ orgId: "o", role: "staff", facilityIds: ["f"], trailIds: [] }],
};

/** the documented success body of each route */
function happy(call: Recorded): Response {
  const route = call.url.slice(`${BASE}/partner-session/`.length);
  switch (route) {
    case "options":
    case "reauth/options":
      return jsonResponse(200, { data: { options: { challenge: "x", userVerification: "required", allowCredentials: [] }, challengeToken: CHALLENGE, expiresAt: "2030-01-01T00:02:00Z" } });
    case "verify":
      return jsonResponse(201, { data: { token: VALID_TOKEN, expiresAt: "2030-01-01T08:00:00Z", aal: 1 } });
    case "session":
      return jsonResponse(200, { data: WHOAMI });
    case "sign-out":
      return jsonResponse(200, { data: { signedOut: true } });
    case "lock":
      return jsonResponse(200, { data: { locked: true } });
    case "reauth":
      return jsonResponse(200, { data: { reauthUntil: "2030-01-01T00:05:00Z" } });
    default:
      return jsonResponse(404, { error: { code: "not_found", message: "not found" } });
  }
}

/** Most tests exercise `call()` against a second, later partner function, so the default test client allows one; the allow-list tests use PARTNER_FUNCTIONS itself. */
const TEST_FUNCTIONS = [...PARTNER_FUNCTIONS, "later-fn"];

function make(responder: (c: Recorded) => Response | Promise<Response> = happy, over: Partial<PartnerApiConfig> = {}) {
  const s = stubFetch(responder);
  const api = createPartnerApi({ baseUrl: BASE, fetch: s.fetch, nowMs: () => Date.UTC(2030, 0, 1), functions: TEST_FUNCTIONS, ...over });
  return { api, calls: s.calls };
}

async function signedIn(responder?: (c: Recorded) => Response | Promise<Response>) {
  const m = make(responder);
  await m.api.verify({ challengeToken: CHALLENGE, credential: CRED });
  m.calls.length = 0;
  return m;
}

const kindOf = async (p: Promise<unknown>) => {
  try {
    await p;
    return "resolved";
  } catch (e) {
    return isPartnerApiError(e) ? e : "other";
  }
};

describe("requests: method, URL, body", () => {
  it("every route of the S1.2 contract is called with its method, path and body", async () => {
    const { api, calls } = make();
    await api.signInOptions();
    await api.verify({ challengeToken: CHALLENGE, credential: CRED });
    await api.session();
    await api.reauthOptions();
    await api.reauth({ challengeToken: CHALLENGE, credential: CRED });
    await api.lock(); // lock revokes: the wire request is `POST sign-out`
    const again = make();
    await again.api.verify({ challengeToken: CHALLENGE, credential: CRED });
    await again.api.signOut();

    const seen = [...calls, ...again.calls].map((c) => [c.init.method, c.url.slice(BASE.length), c.init.body === undefined ? undefined : JSON.parse(String(c.init.body))]);
    expect(seen).toEqual([
      ["POST", "/partner-session/options", {}],
      ["POST", "/partner-session/verify", { challengeToken: CHALLENGE, credential: CRED }],
      ["GET", "/partner-session/session", undefined],
      ["POST", "/partner-session/reauth/options", {}],
      ["POST", "/partner-session/reauth", { challengeToken: CHALLENGE, credential: CRED }],
      ["POST", "/partner-session/sign-out", {}],
      ["POST", "/partner-session/verify", { challengeToken: CHALLENGE, credential: CRED }],
      ["POST", "/partner-session/sign-out", {}],
    ]);
  });

  it("a trailing slash on the configured base does not double the slash", async () => {
    const s = stubFetch(happy);
    await createPartnerApi({ baseUrl: BASE + "/", fetch: s.fetch }).signInOptions();
    expect(s.calls[0]!.url).toBe(`${BASE}/partner-session/options`);
  });

  it("sends only the documented body fields (no pop_jkt, nothing extra)", async () => {
    const { api, calls } = make();
    await api.verify({ challengeToken: CHALLENGE, credential: CRED });
    expect(Object.keys(JSON.parse(String(calls[0]!.init.body))).sort()).toEqual(["challengeToken", "credential"]);
  });
});

describe("requests: headers and credentials mode", () => {
  async function everyCall() {
    const m = make();
    await m.api.signInOptions();
    await m.api.verify({ challengeToken: CHALLENGE, credential: CRED });
    await m.api.session();
    await m.api.reauthOptions();
    await m.api.reauth({ challengeToken: CHALLENGE, credential: CRED });
    await m.api.call("POST", "later-fn", "scan", { a: 1 }).catch(() => undefined);
    await m.api.lock();
    return m.calls;
  }

  it("EVERY request sends Content-Type exactly application/json, GET included, and nothing else but Authorization", async () => {
    const calls = await everyCall();
    expect(calls.length).toBeGreaterThanOrEqual(7);
    for (const c of calls) {
      expect(c.headers["content-type"], c.url).toBe("application/json");
      const names = c.headerKeys.map((k) => k.toLowerCase()).sort();
      expect(names, c.url).toEqual(c.headers["authorization"] === undefined ? ["content-type"] : ["authorization", "content-type"]);
      expect(c.headerKeys.filter((k) => k.toLowerCase() === "content-type"), "one Content-Type, one spelling").toEqual(["Content-Type"]);
    }
  });

  it("EVERY request omits credentials, refuses redirects, is uncacheable and sends no referrer (no cookie can ride along)", async () => {
    for (const c of await everyCall()) {
      expect(c.init.credentials, c.url).toBe("omit");
      expect(c.init.redirect, c.url).toBe("error");
      expect(c.init.cache, c.url).toBe("no-store");
      expect(c.init.referrerPolicy, c.url).toBe("no-referrer");
      expect(c.init.mode, c.url).toBe("cors");
    }
  });

  it("the Authorization header is Bearer <token> on session routes and ABSENT on options and verify", async () => {
    const calls = await everyCall();
    const byRoute = (r: string) => calls.find((c) => c.url.endsWith(`/partner-session/${r}`))!;
    expect(byRoute("options").headers["authorization"]).toBeUndefined();
    expect(byRoute("verify").headers["authorization"]).toBeUndefined();
    for (const r of ["session", "reauth/options", "reauth", "sign-out"]) expect(byRoute(r).headers["authorization"], r).toBe(`Bearer ${VALID_TOKEN}`);
  });

  it("a token that is HELD never leaks onto the pre-auth route: options carries no Authorization even in a signed-in client", async () => {
    const m = await signedIn();
    await m.api.signInOptions();
    expect(m.calls.map((c) => c.url.slice(BASE.length))).toEqual(["/partner-session/options"]);
    for (const c of m.calls) expect(c.headers["authorization"], c.url).toBeUndefined();
  });

  it("never sends the reserved X-GR-PoP header and never puts the token in a URL", async () => {
    for (const c of await everyCall()) {
      expect(c.headers["x-gr-pop"]).toBeUndefined();
      expect(c.url).not.toContain(VALID_TOKEN);
      expect(c.url).not.toContain("gr_ps_");
      expect(c.url).not.toContain("?");
    }
  });
});

describe("the token", () => {
  it("is never returned: verify resolves with expiry and aal only", async () => {
    const { api } = make();
    const grant = await api.verify({ challengeToken: CHALLENGE, credential: CRED });
    expect(grant).toEqual({ expiresAt: "2030-01-01T08:00:00Z", aal: 1 });
    expect(JSON.stringify(grant)).not.toContain("gr_ps_");
    expect(api.hasSession()).toBe(true);
  });

  it("is refused if it is not the issued shape, and then nothing is held", async () => {
    for (const token of ["gr_ps_short", "not-a-token", "GR_PS_" + "A".repeat(43), "gr_ps_" + "A".repeat(44), "gr_ps_" + "A".repeat(42) + "+", ""]) {
      const { api } = make(() => jsonResponse(201, { data: { token, expiresAt: "x", aal: 1 } }));
      const e = await kindOf(api.verify({ challengeToken: CHALLENGE, credential: CRED }));
      expect(e, token).toBeInstanceOf(PartnerApiError);
      expect((e as PartnerApiError).kind).toBe("malformed_response");
      expect(api.hasSession()).toBe(false);
    }
  });

  it("is not held after a failed verify (401), and a session call then makes no request", async () => {
    const m = make(() => jsonResponse(401, { error: { code: "unauthenticated", message: "authentication failed" } }));
    expect(((await kindOf(m.api.verify({ challengeToken: CHALLENGE, credential: CRED }))) as PartnerApiError).kind).toBe("unauthenticated");
    expect(m.api.hasSession()).toBe(false);
    m.calls.length = 0;
    expect(((await kindOf(m.api.session())) as PartnerApiError).kind).toBe("unauthenticated");
    expect(m.calls).toEqual([]);
  });

  it("sign-out wipes it, and the sign-out request itself carried it", async () => {
    const m = await signedIn();
    await m.api.signOut();
    expect(m.calls[0]!.headers["authorization"]).toBe(`Bearer ${VALID_TOKEN}`);
    expect(m.api.hasSession()).toBe(false);
    m.calls.length = 0;
    await kindOf(m.api.session());
    expect(m.calls).toEqual([]);
  });

  it("lock wipes it (a locked screen needs a fresh passkey tap), and REVOKES the session: the request is POST sign-out and it carried the token", async () => {
    const m = await signedIn();
    await m.api.lock();
    expect(m.calls).toHaveLength(1);
    expect(m.calls[0]!.url.endsWith("/partner-session/sign-out")).toBe(true);
    expect(m.calls[0]!.init.method).toBe("POST");
    expect(m.calls.some((c) => c.url.endsWith("/lock"))).toBe(false);
    expect(m.calls[0]!.headers["authorization"]).toBe(`Bearer ${VALID_TOKEN}`);
    expect(m.api.hasSession()).toBe(false);
  });

  it("sign-out and lock wipe it EVEN WHEN the request fails (network, 500)", async () => {
    for (const fail of [() => Promise.reject(new TypeError("offline")), () => jsonResponse(500, { error: { code: "internal_error", message: "x" } })]) {
      for (const op of ["signOut", "lock"] as const) {
        let phase = 0;
        const m = make((c) => (phase === 0 ? happy(c) : (fail() as Response)));
        await m.api.verify({ challengeToken: CHALLENGE, credential: CRED });
        phase = 1;
        const e = await kindOf(m.api[op]());
        expect(e).toBeInstanceOf(PartnerApiError);
        expect(m.api.hasSession(), `${op} after failure`).toBe(false);
      }
    }
  });

  it("a 401 on an authenticated call wipes it BEFORE the caller sees the error, and notifies listeners with 'expired'", async () => {
    let phase = 0;
    const m = make((c) => (phase === 0 ? happy(c) : jsonResponse(401, { error: { code: "unauthenticated", message: "authentication failed" } })));
    await m.api.verify({ challengeToken: CHALLENGE, credential: CRED });
    const reasons: string[] = [];
    m.api.onSessionEnded((r) => reasons.push(r));
    phase = 1;
    try {
      await m.api.session();
      expect.unreachable();
    } catch (e) {
      expect((e as PartnerApiError).kind).toBe("unauthenticated");
      expect(m.api.hasSession()).toBe(false);
    }
    expect(reasons).toEqual(["expired"]);
  });

  it("a 403 does NOT wipe it (the session is alive; authority was refused)", async () => {
    let phase = 0;
    const m = make((c) => (phase === 0 ? happy(c) : jsonResponse(403, { error: { code: "forbidden", message: "forbidden" } })));
    await m.api.verify({ challengeToken: CHALLENGE, credential: CRED });
    phase = 1;
    expect(((await kindOf(m.api.session())) as PartnerApiError).kind).toBe("forbidden");
    expect(m.api.hasSession()).toBe(true);
  });

  it("a reauth refusal (403 reauth_refused) does NOT wipe it", async () => {
    let phase = 0;
    const m = make((c) => (phase === 0 ? happy(c) : jsonResponse(403, { error: { code: "reauth_refused", message: "reauthentication failed" } })));
    await m.api.verify({ challengeToken: CHALLENGE, credential: CRED });
    phase = 1;
    const e = (await kindOf(m.api.reauth({ challengeToken: CHALLENGE, credential: CRED }))) as PartnerApiError;
    expect(e.kind).toBe("reauth_refused");
    expect(m.api.hasSession()).toBe(true);
  });

  it("forgetSession wipes without a request, notifies once, and is a no-op with no session", async () => {
    const m = await signedIn();
    const reasons: string[] = [];
    const off = m.api.onSessionEnded((r) => reasons.push(r));
    m.api.forgetSession();
    m.api.forgetSession();
    expect(reasons).toEqual(["forgotten"]);
    expect(m.calls).toEqual([]);
    expect(m.api.hasSession()).toBe(false);
    off();
  });

  it("two clients do not share a token", async () => {
    const a = await signedIn();
    const b = make();
    expect(a.api.hasSession()).toBe(true);
    expect(b.api.hasSession()).toBe(false);
  });
});

describe("error mapping", () => {
  const cases: Array<[number, string | null, string]> = [
    [401, "unauthenticated", "unauthenticated"],
    [403, "forbidden", "forbidden"],
    [403, "reauth_refused", "reauth_refused"],
    [403, null, "forbidden"],
    [415, "unsupported_media_type", "unsupported_media_type"],
    [429, "rate_limited", "rate_limited"],
    [400, "bad_request", "bad_request"],
    [413, "payload_too_large", "bad_request"],
    [404, "not_found", "not_found"],
    [405, "method_not_allowed", "not_found"],
    [503, "service_unavailable", "unavailable"],
    [500, "internal_error", "server"],
    [502, null, "server"],
  ];
  it.each(cases)("HTTP %i (%s) is kind %s", async (status, code, kind) => {
    const { api } = make(() => jsonResponse(status, code === null ? {} : { error: { code, message: "m" } }));
    const e = (await kindOf(api.signInOptions())) as PartnerApiError;
    expect(e).toBeInstanceOf(PartnerApiError);
    expect(e.kind).toBe(kind);
    expect(e.status).toBe(status);
    expect(e.code).toBe(code);
  });

  it("kindForStatus is the same table (and an unexpected 3xx or 2xx-as-error is malformed)", () => {
    for (const [status, code, kind] of cases) expect(kindForStatus(status, code)).toBe(kind);
    expect(kindForStatus(302, null)).toBe("malformed_response");
  });

  it("429 carries Retry-After in seconds when the browser could read it", async () => {
    const { api } = make(() => jsonResponse(429, { error: { code: "rate_limited", message: "m" } }, { "retry-after": "1800" }));
    const e = (await kindOf(api.signInOptions())) as PartnerApiError;
    expect(e.kind).toBe("rate_limited");
    expect(e.retryAfterSeconds).toBe(1800);
  });

  it("429 without a readable Retry-After has retryAfterSeconds null (cross-origin: the header is hidden unless exposed)", async () => {
    const { api } = make(() => jsonResponse(429, { error: { code: "rate_limited", message: "m" } }));
    expect(((await kindOf(api.signInOptions())) as PartnerApiError).retryAfterSeconds).toBeNull();
  });

  it("parseRetryAfter reads delta-seconds and HTTP dates, and nothing else", () => {
    const now = Date.UTC(2030, 0, 1, 0, 0, 0);
    expect(parseRetryAfter("120", now)).toBe(120);
    expect(parseRetryAfter(" 5 ", now)).toBe(5);
    expect(parseRetryAfter("Tue, 01 Jan 2030 00:01:30 GMT", now)).toBe(90);
    expect(parseRetryAfter("Mon, 31 Dec 2029 23:00:00 GMT", now)).toBe(0);
    expect(parseRetryAfter(null, now)).toBeNull();
    expect(parseRetryAfter("soon", now)).toBeNull();
    expect(parseRetryAfter("-5", now)).toBeNull();
    expect(parseRetryAfter("1.5", now)).toBeNull();
    expect(parseRetryAfter("9999999999", now)).toBeNull();
  });

  it("a thrown fetch (offline, CORS refusal) is kind network", async () => {
    const { api } = make(() => Promise.reject(new TypeError("Failed to fetch")) as unknown as Response);
    expect(((await kindOf(api.signInOptions())) as PartnerApiError).kind).toBe("network");
  });

  it("a 200 that is not JSON, not the envelope, or not the documented shape is malformed_response", async () => {
    for (const res of [new Response("<html>", { status: 200 }), jsonResponse(200, { nope: 1 }), jsonResponse(200, { data: { options: 1 } }), jsonResponse(200, { data: null })]) {
      const { api } = make(() => res.clone());
      expect(((await kindOf(api.signInOptions())) as PartnerApiError).kind, await res.clone().text()).toBe("malformed_response");
    }
  });

  it("an error body that is not JSON still maps by status; a hostile error code is dropped, never surfaced", async () => {
    const plain = make(() => new Response("upstream exploded", { status: 502 }));
    expect(((await kindOf(plain.api.signInOptions())) as PartnerApiError).kind).toBe("server");
    const hostile = make(() => jsonResponse(403, { error: { code: "<img src=x onerror=alert(1)>", message: "m" } }));
    const e = (await kindOf(hostile.api.signInOptions())) as PartnerApiError;
    expect(e.code).toBeNull();
    expect(e.kind).toBe("forbidden");
  });

  it("an error never carries the token, a header, the request body or the response body", async () => {
    const m = await signedIn((c) => (c.url.endsWith("/session") ? jsonResponse(500, { error: { code: "internal_error", message: "secret database text " + VALID_TOKEN } }) : happy(c)));
    const e = (await kindOf(m.api.session())) as PartnerApiError;
    const dump = JSON.stringify({ ...e, message: e.message, stack: e.stack });
    expect(dump).not.toContain("gr_ps_");
    expect(dump).not.toContain("secret database text");
    expect(dump).not.toContain("Bearer");
  });

  it("whoami: a malformed session body is malformed_response, not a half-built object", async () => {
    const broken = { ...WHOAMI, memberships: [{ orgId: "o", role: 3 }] };
    const { api } = await signedIn((c) => (c.url.endsWith("/session") ? jsonResponse(200, { data: broken }) : happy(c)));
    expect(((await kindOf(api.session())) as PartnerApiError).kind).toBe("malformed_response");
    const missing = await signedIn((c) => (c.url.endsWith("/session") ? jsonResponse(200, { data: { ...WHOAMI, stepUp: undefined } }) : happy(c)));
    expect(((await kindOf(missing.api.session())) as PartnerApiError).kind).toBe("malformed_response");
  });

  it("whoami: every documented field is required and typed (a missing or mistyped one is malformed_response)", async () => {
    const mutate: Array<[string, (w: Record<string, unknown>) => void]> = [
      ["userId", (w) => delete w["userId"]],
      ["sessionId", (w) => (w["sessionId"] = 5)],
      ["aal", (w) => (w["aal"] = "1")],
      ["requiredAal", (w) => delete w["requiredAal"]],
      ["createdAt", (w) => (w["createdAt"] = null)],
      ["lastSeenAt", (w) => delete w["lastSeenAt"]],
      ["idleExpiresAt", (w) => (w["idleExpiresAt"] = 1)],
      ["expiresAt", (w) => delete w["expiresAt"]],
      ["isAdmin", (w) => (w["isAdmin"] = "no")],
      ["isAdmin missing", (w) => delete w["isAdmin"]],
      ["stepUp", (w) => (w["stepUp"] = "x")],
      ["stepUp.pinGrantActive", (w) => (w["stepUp"] = { ...WHOAMI.stepUp, pinGrantActive: 1 })],
      ["stepUp.reauthUntil", (w) => (w["stepUp"] = { ...WHOAMI.stepUp, reauthUntil: 5 })],
      ["memberships", (w) => (w["memberships"] = {})],
      ["membership.facilityIds", (w) => (w["memberships"] = [{ orgId: "o", role: "staff", facilityIds: [1], trailIds: [] }])],
    ];
    for (const [name, change] of mutate) {
      const body = JSON.parse(JSON.stringify(WHOAMI)) as Record<string, unknown>;
      change(body);
      const { api } = await signedIn((c) => (c.url.endsWith("/session") ? jsonResponse(200, { data: body }) : happy(c)));
      expect(((await kindOf(api.session())) as PartnerApiError).kind, name).toBe("malformed_response");
    }
  });

  it("whoami parses the documented shape", async () => {
    const { api } = await signedIn();
    const w = await api.session();
    expect(w.aal).toBe(1);
    expect(w.memberships).toEqual([{ orgId: "o", role: "staff", facilityIds: ["f"], trailIds: [] }]);
    expect(w.stepUp.reauthUntil).toBeNull();
  });
});

describe("call(): authenticated requests to later partner functions", () => {
  it("attaches the same headers and credentials mode and applies the same 401 handling", async () => {
    let phase = 0;
    const m = make((c) => (phase === 0 ? happy(c) : c.url.endsWith("/later-fn/scan") ? jsonResponse(200, { data: { ok: true } }) : jsonResponse(401, { error: { code: "unauthenticated", message: "x" } })));
    await m.api.verify({ challengeToken: CHALLENGE, credential: CRED });
    phase = 1;
    m.calls.length = 0;
    expect(await m.api.call("POST", "later-fn", "scan", { a: 1 })).toEqual({ ok: true });
    expect(m.calls[0]!.url).toBe(`${BASE}/later-fn/scan`);
    expect(m.calls[0]!.headers["authorization"]).toBe(`Bearer ${VALID_TOKEN}`);
    expect(m.calls[0]!.headers["content-type"]).toBe("application/json");
    expect(m.calls[0]!.init.credentials).toBe("omit");
    await kindOf(m.api.call("GET", "later-fn", "other"));
    expect(m.api.hasSession()).toBe(false);
  });

  it("refuses a function name or route that could change the path", async () => {
    const m = await signedIn();
    for (const [fn, route] of [["..", "x"], ["a/b", "x"], ["later-fn", "../x"], ["later-fn", "x?y=1"], ["later-fn", "x#y"], ["later-fn", "//evil.test"], ["Partner", "x"], ["", "x"], ["later-fn", "a:b"]] as const) {
      expect(((await kindOf(m.api.call("GET", fn, route))) as PartnerApiError).kind, `${fn} ${route}`).toBe("bad_request");
    }
    expect(m.calls).toEqual([]);
    expect(m.api.hasSession()).toBe(true);
  });

  it("accepts a closed query object and refuses a bad key or value", async () => {
    const m = make((c) => (c.url.includes("/partner-attest/shift-log?") ? jsonResponse(200, { data: { entries: [] } }) : happy(c)));
    await m.api.verify({ challengeToken: CHALLENGE, credential: CRED });
    m.calls.length = 0;
    expect(await m.api.call("GET", "partner-attest", "shift-log", undefined, { facilityId: "fac_a" })).toEqual({ entries: [] });
    expect(m.calls[0]!.url).toBe(`${BASE}/partner-attest/shift-log?facilityId=fac_a`);
    expect(((await kindOf(m.api.call("GET", "partner-attest", "shift-log", undefined, { "bad key": "x" }))) as PartnerApiError).kind).toBe("bad_request");
    expect(((await kindOf(m.api.call("GET", "partner-attest", "shift-log", undefined, { facilityId: "a/b" }))) as PartnerApiError).kind).toBe("bad_request");
  });

  it("without a session it makes no request", async () => {
    const m = make();
    expect(((await kindOf(m.api.call("GET", "later-fn", "x"))) as PartnerApiError).kind).toBe("unauthenticated");
    expect(m.calls).toEqual([]);
  });
});

describe("call(): the bearer goes only to the partner-function allow-list (LOW-3)", () => {
  /** A client with the DEFAULT allow-list (the one the CSP is built from), unlike `make()`. */
  const strict = (responder: (c: Recorded) => Response | Promise<Response> = happy) => make(responder, { functions: PARTNER_FUNCTIONS });

  it("the default list is the partner functions of partner-functions.json, and includes the session function", () => {
    expect([...PARTNER_FUNCTIONS]).toContain(SESSION_FUNCTION);
  });

  it("a function that is not on the list gets NO request and NO bearer: another edge function, the data API's name, an auth path, a not-yet-built partner function", async () => {
    const m = strict();
    await m.api.verify({ challengeToken: CHALLENGE, credential: CRED });
    m.calls.length = 0;
    for (const fn of ["partner-offers-redeem", "other-fn", "rest", "auth", "me-export", "partner-session2", "partner"]) {
      expect(((await kindOf(m.api.call("POST", fn, "x", {}))) as PartnerApiError).kind, fn).toBe("bad_request");
    }
    expect(m.calls).toEqual([]);
    expect(m.api.hasSession()).toBe(true);
  });

  it("a function that IS on the list is called, with the bearer", async () => {
    const m = strict((c) => (c.url.endsWith("/partner-session/ping") ? jsonResponse(200, { data: { ok: 1 } }) : happy(c)));
    await m.api.verify({ challengeToken: CHALLENGE, credential: CRED });
    m.calls.length = 0;
    expect(await m.api.call("GET", "partner-session", "ping")).toEqual({ ok: 1 });
    expect(m.calls[0]!.headers["authorization"]).toBe(`Bearer ${VALID_TOKEN}`);
  });

  it("an explicit list in the config is the whole allow-list", async () => {
    const m = make(happy, { functions: ["only-this"] });
    await m.api.verify({ challengeToken: CHALLENGE, credential: CRED });
    m.calls.length = 0;
    expect(((await kindOf(m.api.call("GET", "partner-session", "session"))) as PartnerApiError).kind).toBe("bad_request");
    expect(m.calls).toEqual([]);
  });
});

/** A fetch that never answers: it settles only when the request's signal aborts (as a real fetch does). */
function hangingFetch(match: (url: string) => boolean, inner: (c: Recorded) => Response | Promise<Response> = happy) {
  const seen: Array<{ url: string; signal: AbortSignal | undefined; keepalive: boolean | undefined; authorization: string | null }> = [];
  const s = stubFetch((c) => inner(c));
  const f = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    seen.push({ url, signal: init?.signal ?? undefined, keepalive: init?.keepalive, authorization: new Headers(init?.headers).get("authorization") });
    if (!match(url)) return s.fetch(input, init);
    s.calls.push({ url, init: init ?? {}, headers: {}, headerKeys: [] });
    return await new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(init.signal!.reason ?? new DOMException("aborted", "AbortError")));
    });
  }) as typeof fetch;
  return { fetch: f, seen };
}

describe("timeouts (MEDIUM-2): every request is cut off", () => {
  it("the default is 15 seconds", () => {
    expect(REQUEST_TIMEOUT_MS).toBe(15_000);
  });

  it("EVERY request carries an abort signal (a timeout), the pre-auth ones and the authenticated ones", async () => {
    const seen: Array<AbortSignal | undefined> = [];
    const s = stubFetch(happy);
    const f = (async (i: RequestInfo | URL, init?: RequestInit) => {
      seen.push(init?.signal ?? undefined);
      return s.fetch(i, init);
    }) as typeof fetch;
    const api = createPartnerApi({ baseUrl: BASE, fetch: f });
    await api.signInOptions();
    await api.verify({ challengeToken: CHALLENGE, credential: CRED });
    await api.session();
    await api.reauthOptions();
    await api.reauth({ challengeToken: CHALLENGE, credential: CRED });
    await api.signOut();
    expect(seen).toHaveLength(6);
    for (const sig of seen) expect(sig, "a signal on every request").toBeInstanceOf(AbortSignal);
  });

  it("a request that never answers is aborted after the timeout and surfaces as a network error, for options, session and sign-out alike", async () => {
    for (const route of ["options", "session", "sign-out"]) {
      const h = hangingFetch((u) => u.endsWith(`/${route}`));
      const api = createPartnerApi({ baseUrl: BASE, fetch: h.fetch, timeoutMs: 40 });
      if (route !== "options") await api.verify({ challengeToken: CHALLENGE, credential: CRED });
      const started = Date.now();
      const e = await kindOf(route === "options" ? api.signInOptions() : route === "session" ? api.session() : api.signOut());
      expect((e as PartnerApiError).kind, route).toBe("network");
      expect(Date.now() - started, route).toBeGreaterThanOrEqual(30);
      expect(Date.now() - started, route).toBeLessThan(5000);
      const sig = h.seen.find((x) => x.url.endsWith(`/${route}`))!.signal!;
      expect(sig.aborted, route).toBe(true);
      expect((sig.reason as { name?: string }).name, route).toBe("TimeoutError");
    }
  });

  it("the caller's signal also aborts the request (session(signal))", async () => {
    const h = hangingFetch((u) => u.endsWith("/session"));
    const api = createPartnerApi({ baseUrl: BASE, fetch: h.fetch, timeoutMs: 60_000 });
    await api.verify({ challengeToken: CHALLENGE, credential: CRED });
    const ac = new AbortController();
    const p = kindOf(api.session(ac.signal));
    await new Promise((r) => setTimeout(r, 10));
    ac.abort();
    expect(((await p) as PartnerApiError).kind).toBe("network");
    expect(api.hasSession()).toBe(true); // a cancelled read is not a dead session
  });

  describe("fallbacks where AbortSignal.timeout / AbortSignal.any are missing (older Safari)", () => {
    const real = { timeout: AbortSignal.timeout, any: AbortSignal.any };
    const set = (k: "timeout" | "any", v: unknown) => Object.defineProperty(AbortSignal, k, { value: v, configurable: true, writable: true });
    afterEach(() => {
      set("timeout", real.timeout);
      set("any", real.any);
    });

    it("without AbortSignal.any: the timeout still fires, and so does the caller's signal", async () => {
      set("any", undefined);
      const h = hangingFetch((u) => u.endsWith("/session"));
      const api = createPartnerApi({ baseUrl: BASE, fetch: h.fetch, timeoutMs: 40 });
      await api.verify({ challengeToken: CHALLENGE, credential: CRED });
      expect(((await kindOf(api.session())) as PartnerApiError).kind).toBe("network");
      const ac = new AbortController();
      const long = createPartnerApi({ baseUrl: BASE, fetch: h.fetch, timeoutMs: 60_000 });
      await long.verify({ challengeToken: CHALLENGE, credential: CRED });
      const p = kindOf(long.session(ac.signal));
      await new Promise((r) => setTimeout(r, 10));
      ac.abort();
      expect(((await p) as PartnerApiError).kind).toBe("network");
    });

    it("without AbortSignal.timeout either: a timer-driven abort replaces it", async () => {
      set("any", undefined);
      set("timeout", undefined);
      const h = hangingFetch((u) => u.endsWith("/session"));
      const api = createPartnerApi({ baseUrl: BASE, fetch: h.fetch, timeoutMs: 40 });
      await api.verify({ challengeToken: CHALLENGE, credential: CRED });
      expect(((await kindOf(api.session())) as PartnerApiError).kind).toBe("network");
    });
  });
});

describe("ending a session is immediate (MEDIUM-2): wipe and notify BEFORE sending, send with a copy", () => {
  it.each(["signOut", "lock"] as const)("%s: by the time the request is on the wire the token is already gone and the listeners have already been told", async (op) => {
    const events: string[] = [];
    let api!: PartnerApi;
    const s = stubFetch((c) => {
      if (/\/sign-out$/.test(c.url)) events.push(`send(hasSession=${api.hasSession()})`);
      return happy(c);
    });
    api = createPartnerApi({ baseUrl: BASE, fetch: s.fetch });
    api.onSessionEnded((r) => events.push(`ended:${r}`));
    await api.verify({ challengeToken: CHALLENGE, credential: CRED });
    await api[op]();
    expect(events).toEqual([`ended:${op === "lock" ? "locked" : "signed-out"}`, "send(hasSession=false)"]);
    expect(s.calls.at(-1)!.headers["authorization"]).toBe(`Bearer ${VALID_TOKEN}`); // the request still carried the copy
  });

  it.each(["signOut", "lock"] as const)("%s: a request that never answers leaves the session already ended, then fails by timeout (and the wipe never waited for it)", async (op) => {
    const h = hangingFetch((u) => u.endsWith("/sign-out"));
    const api = createPartnerApi({ baseUrl: BASE, fetch: h.fetch, timeoutMs: 80 });
    const reasons: string[] = [];
    api.onSessionEnded((r) => reasons.push(r));
    await api.verify({ challengeToken: CHALLENGE, credential: CRED });
    const p = kindOf(api[op]());
    // synchronously after the call returns its promise: ended, token gone, the request is on the wire
    expect(api.hasSession()).toBe(false);
    expect(reasons).toEqual([op === "lock" ? "locked" : "signed-out"]);
    expect(h.seen.at(-1)!.authorization).toBe(`Bearer ${VALID_TOKEN}`);
    expect(((await p) as PartnerApiError).kind).toBe("network");
  });

  it("a listener that throws does not stop the request or the other listeners", async () => {
    const m = await signedIn();
    const reasons: string[] = [];
    m.api.onSessionEnded(() => {
      throw new Error("boom");
    });
    m.api.onSessionEnded((r) => reasons.push(r));
    await m.api.lock();
    expect(reasons).toEqual(["locked"]);
    expect(m.calls).toHaveLength(1);
  });

  it("sign-out and lock with no session reject 'unauthenticated' and send nothing", async () => {
    const m = make();
    for (const op of ["signOut", "lock"] as const) expect(((await kindOf(m.api[op]())) as PartnerApiError).kind).toBe("unauthenticated");
    expect(m.calls).toEqual([]);
  });

  it("a wipe aborts every authenticated request still in flight (a hung refresh does not outlive a lock)", async () => {
    const h = hangingFetch((u) => u.endsWith("/session"));
    const api = createPartnerApi({ baseUrl: BASE, fetch: h.fetch, timeoutMs: 60_000 });
    await api.verify({ challengeToken: CHALLENGE, credential: CRED });
    const read = kindOf(api.session());
    await new Promise((r) => setTimeout(r, 10));
    const sessionSignal = h.seen.find((x) => x.url.endsWith("/session"))!.signal!;
    expect(sessionSignal.aborted).toBe(false);
    await api.lock();
    expect(sessionSignal.aborted).toBe(true);
    expect(((await read) as PartnerApiError).kind).toBe("network");
  });

  it("the sign-out request of a lock is NOT aborted by the wipe that started it", async () => {
    const m = await signedIn();
    await m.api.lock();
    expect(m.calls).toHaveLength(1); // it went out and completed
  });

  it("a late 401 for an OLD session does not wipe the NEW one (the 401 belongs to the session the request was sent under)", async () => {
    let release!: (r: Response) => void;
    let hold = false;
    const s = stubFetch(happy);
    const f = (async (i: RequestInfo | URL, init?: RequestInit) => {
      if (hold && String(i).endsWith("/session")) return await new Promise<Response>((r) => (release = r));
      return s.fetch(i, init);
    }) as typeof fetch;
    const api = createPartnerApi({ baseUrl: BASE, fetch: f });
    await api.verify({ challengeToken: CHALLENGE, credential: CRED });
    hold = true;
    const old = kindOf(api.session());
    hold = false;
    api.forgetSession();
    await api.verify({ challengeToken: CHALLENGE, credential: CRED }); // a new session
    release(jsonResponse(401, { error: { code: "unauthenticated", message: "x" } }));
    expect(((await old) as PartnerApiError).kind).toBe("unauthenticated");
    expect(api.hasSession()).toBe(true);
  });

  it("keepalive is requested only when asked for (a page that is going away)", async () => {
    const h = hangingFetch(() => false);
    const api = createPartnerApi({ baseUrl: BASE, fetch: h.fetch });
    await api.verify({ challengeToken: CHALLENGE, credential: CRED });
    await api.signOut({ keepalive: true });
    await api.verify({ challengeToken: CHALLENGE, credential: CRED });
    await api.signOut();
    const outs = h.seen.filter((x) => x.url.endsWith("/sign-out"));
    expect(outs.map((x) => x.keepalive)).toEqual([true, undefined]);
    expect(h.seen.filter((x) => !x.url.endsWith("/sign-out")).every((x) => x.keepalive === undefined)).toBe(true);
  });
});

describe("verify() (NIT and LOW-4)", () => {
  it("refuses to overwrite a held token: it throws before sending anything, and the held token is untouched", async () => {
    const m = await signedIn();
    const e = (await kindOf(m.api.verify({ challengeToken: CHALLENGE, credential: CRED }))) as PartnerApiError;
    expect(e.kind).toBe("bad_request");
    expect(e.code).toBe("session_exists");
    expect(m.calls).toEqual([]);
    expect(m.api.hasSession()).toBe(true);
  });

  it("a second verify that finishes after another sign-in already stored a token revokes ITS OWN copy and leaves the stored token alone", async () => {
    let release!: (r: Response) => void;
    let first = true;
    const s = stubFetch((c) => (c.url.endsWith("/verify") ? jsonResponse(201, { data: { token: first ? "gr_ps_" + "B".repeat(43) : VALID_TOKEN, expiresAt: "x", aal: 1 } }) : happy(c)));
    const f = (async (i: RequestInfo | URL, init?: RequestInit) => {
      if (first && String(i).endsWith("/verify")) {
        first = false;
        return await new Promise<Response>((r) => (release = r));
      }
      return s.fetch(i, init);
    }) as typeof fetch;
    const api = createPartnerApi({ baseUrl: BASE, fetch: f });
    const slow = kindOf(api.verify({ challengeToken: CHALLENGE, credential: CRED }));
    await api.verify({ challengeToken: CHALLENGE, credential: CRED }); // the fast one stores VALID_TOKEN
    release(jsonResponse(201, { data: { token: "gr_ps_" + "B".repeat(43), expiresAt: "x", aal: 1 } }));
    expect(((await slow) as PartnerApiError).code).toBe("session_exists");
    expect(api.hasSession()).toBe(true);
    const revoked = s.calls.filter((c) => c.url.endsWith("/sign-out"));
    expect(revoked.map((c) => c.headers["authorization"])).toEqual(["Bearer gr_ps_" + "B".repeat(43)]);
  });

  it("a cancel that arrives while verify is on the wire does NOT abort the request; the session it opens is revoked with a copy and never held", async () => {
    let release!: (r: Response) => void;
    const s = stubFetch(happy);
    let verifySignal: AbortSignal | undefined;
    const f = (async (i: RequestInfo | URL, init?: RequestInit) => {
      if (String(i).endsWith("/verify")) {
        verifySignal = init?.signal ?? undefined;
        return await new Promise<Response>((r) => (release = r));
      }
      return s.fetch(i, init);
    }) as typeof fetch;
    const api = createPartnerApi({ baseUrl: BASE, fetch: f });
    const ac = new AbortController();
    const p = kindOf(api.verify({ challengeToken: CHALLENGE, credential: CRED }, { signal: ac.signal }));
    await new Promise((r) => setTimeout(r, 5));
    ac.abort();
    expect(verifySignal!.aborted, "the request itself is not cancelled").toBe(false);
    release(jsonResponse(201, { data: { token: VALID_TOKEN, expiresAt: "x", aal: 1 } }));
    expect(((await p) as PartnerApiError).kind).toBe("aborted");
    expect(api.hasSession()).toBe(false);
    expect(s.calls.map((c) => [c.init.method, c.url.slice(BASE.length), c.headers["authorization"]])).toEqual([["POST", "/partner-session/sign-out", `Bearer ${VALID_TOKEN}`]]);
  });

  it("a signal that is NOT aborted changes nothing", async () => {
    const m = make();
    await m.api.verify({ challengeToken: CHALLENGE, credential: CRED }, { signal: new AbortController().signal });
    expect(m.api.hasSession()).toBe(true);
  });
});

describe("storage: the token is never written anywhere", () => {
  let spies: StorageSpies;
  beforeEach(() => {
    spies = installStorageSpies();
  });
  afterEach(() => spies.restore());

  it("a full session (sign-in, session, reauth, call, lock, sign-in again, sign-out, a failing call) touches no storage API, no cookie and no console", async () => {
    const m = make();
    await m.api.signInOptions();
    await m.api.verify({ challengeToken: CHALLENGE, credential: CRED });
    await m.api.session();
    await m.api.reauthOptions();
    await m.api.reauth({ challengeToken: CHALLENGE, credential: CRED });
    await m.api.call("POST", "later-fn", "scan", {}).catch(() => undefined);
    await m.api.lock();
    await m.api.verify({ challengeToken: CHALLENGE, credential: CRED });
    await m.api.signOut();
    await m.api.session().catch(() => undefined);
    expect(spies.calls).toEqual([]);
  });

  it("the spies do work: touching a storage global is recorded (a control, so 'zero calls' means something)", () => {
    (globalThis as unknown as { localStorage: { setItem(k: string, v: string): void } }).localStorage.setItem("k", "v");
    void (globalThis as unknown as { document: { cookie: string } }).document.cookie;
    console.log("x");
    expect(spies.calls.length).toBe(4);
  });
});
