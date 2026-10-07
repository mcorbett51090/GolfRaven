import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createPartnerApi, type PartnerApi } from "../src/api/client";
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

function make(responder: (c: Recorded) => Response | Promise<Response> = happy) {
  const s = stubFetch(responder);
  const api = createPartnerApi({ baseUrl: BASE, fetch: s.fetch, nowMs: () => Date.UTC(2030, 0, 1) });
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
    await api.lock();
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
      ["POST", "/partner-session/lock", {}],
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
    await m.api.call("POST", "partner-attest", "scan", { a: 1 }).catch(() => undefined);
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
    for (const r of ["session", "reauth/options", "reauth", "lock"]) expect(byRoute(r).headers["authorization"], r).toBe(`Bearer ${VALID_TOKEN}`);
  });

  it("a token that is HELD never leaks onto the pre-auth routes: options and verify carry no Authorization even in a signed-in client", async () => {
    const m = await signedIn();
    await m.api.signInOptions();
    await m.api.verify({ challengeToken: CHALLENGE, credential: CRED });
    expect(m.calls.map((c) => c.url.slice(BASE.length))).toEqual(["/partner-session/options", "/partner-session/verify"]);
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

  it("lock wipes it (a locked screen needs a fresh passkey tap), and the lock request carried it", async () => {
    const m = await signedIn();
    await m.api.lock();
    expect(m.calls[0]!.url.endsWith("/partner-session/lock")).toBe(true);
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
    const m = make((c) => (phase === 0 ? happy(c) : c.url.endsWith("/partner-attest/scan") ? jsonResponse(200, { data: { ok: true } }) : jsonResponse(401, { error: { code: "unauthenticated", message: "x" } })));
    await m.api.verify({ challengeToken: CHALLENGE, credential: CRED });
    phase = 1;
    m.calls.length = 0;
    expect(await m.api.call("POST", "partner-attest", "scan", { a: 1 })).toEqual({ ok: true });
    expect(m.calls[0]!.url).toBe(`${BASE}/partner-attest/scan`);
    expect(m.calls[0]!.headers["authorization"]).toBe(`Bearer ${VALID_TOKEN}`);
    expect(m.calls[0]!.headers["content-type"]).toBe("application/json");
    expect(m.calls[0]!.init.credentials).toBe("omit");
    await kindOf(m.api.call("GET", "partner-attest", "other"));
    expect(m.api.hasSession()).toBe(false);
  });

  it("refuses a function name or route that could change the path", async () => {
    const m = await signedIn();
    for (const [fn, route] of [["..", "x"], ["a/b", "x"], ["partner-attest", "../x"], ["partner-attest", "x?y=1"], ["partner-attest", "x#y"], ["partner-attest", "//evil.test"], ["Partner", "x"], ["", "x"], ["partner-attest", "a:b"]] as const) {
      expect(((await kindOf(m.api.call("GET", fn, route))) as PartnerApiError).kind, `${fn} ${route}`).toBe("bad_request");
    }
    expect(m.calls).toEqual([]);
    expect(m.api.hasSession()).toBe(true);
  });

  it("without a session it makes no request", async () => {
    const m = make();
    expect(((await kindOf(m.api.call("GET", "partner-attest", "x"))) as PartnerApiError).kind).toBe("unauthenticated");
    expect(m.calls).toEqual([]);
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
    await m.api.call("POST", "partner-attest", "scan", {}).catch(() => undefined);
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
