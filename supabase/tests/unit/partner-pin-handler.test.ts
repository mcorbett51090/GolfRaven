// supabase/tests/unit/partner-pin-handler.test.ts
//
// The step-up PIN and email-proof routes of `partner-session` (docs/security/partner-auth-design.md 6.3, PA-18, PA-19, PA-21, slice S1.3), against the in-memory ports of partner-fakes.ts. What is decided HERE,
// by the pure handler: the strict body shapes (the request carries the BROWSER-DERIVED key, never the PIN), the status-to-response mapping, COMMIT ON EVERY STATUS (a refusal is a returned value, so the counter
// the database wrote commits with it), the rate-limit buckets, and the order of the email proof (no database transaction is ever open while GoTrue is called; the GoTrue session is closed AFTER the proof is
// recorded, on every path). What needs a real database is supabase/tests/integration/partner-pin.deno.test.ts and supabase/tests/matrix/28_partner_pin_step_up.sql.

import { describe, expect, it } from "vitest";
import { handlePartnerSessionRequest, OTP_SEND_BUCKET, OTP_SEND_PER_MEMBER_PER_HOUR, OTP_VERIFY_BUCKET, OTP_VERIFY_PER_MEMBER_PER_HOUR } from "../../functions/_shared/partner/session-handler.ts";
import { PartnerAuthorityRefused, PartnerConflict } from "../../functions/_shared/partner/ports.ts";
import { authed, bytes, makeFakes, ORIGIN, req, SESSION_TOKEN, sha256Hex, toB64u } from "./partner-fakes.ts";

const DERIVED = toB64u(bytes(32, 0x11));
const CURRENT = toB64u(bytes(32, 0x22));
const SALT = toB64u(bytes(16, 0x33));
const setBody = (over: Record<string, unknown> = {}) => ({ derived: DERIVED, salt: SALT, iterations: 600000, ...over });
const changeBody = (over: Record<string, unknown> = {}) => ({ currentDerived: CURRENT, ...setBody(), ...over });

const post = (path: string, body: unknown, f: ReturnType<typeof makeFakes>) => handlePartnerSessionRequest(req("POST", path, { headers: authed(), body }), f.deps);
const get = (path: string, f: ReturnType<typeof makeFakes>) => handlePartnerSessionRequest(req("GET", path, { headers: authed() }), f.deps);
const body = async (res: Response): Promise<{ data?: Record<string, unknown>; error?: { code: string; message: string } }> => JSON.parse(await res.text());

describe("routing and the bearer: the new routes are session routes", () => {
  const routes: Array<[string, string, unknown]> = [
    ["GET", "pin", undefined],
    ["POST", "step-up/pin", { derived: DERIVED }],
    ["POST", "pin/set", setBody()],
    ["POST", "pin/change", changeBody()],
    ["POST", "otp-proof/start", {}],
    ["POST", "otp-proof/verify", { code: "123456" }],
  ];
  it("each needs a gr_ps_ bearer: anything else is the ONE 401 with no port touched", async () => {
    const f = makeFakes();
    for (const [method, path, b] of routes) {
      for (const authorization of [undefined, "Bearer not-a-partner-token", `Bearer ${SESSION_TOKEN}x`, `Basic ${SESSION_TOKEN}`]) {
        const headers: Record<string, string> = { origin: ORIGIN };
        if (authorization !== undefined) headers.authorization = authorization;
        const res = await handlePartnerSessionRequest(req(method, path, { headers, body: b }), f.deps);
        expect(res.status, `${method} ${path} ${authorization}`).toBe(401);
      }
    }
    expect(f.calls).toEqual([]);
  });

  it("each has ONE method: the wrong one is 405 with Allow, before anything else is touched", async () => {
    const f = makeFakes();
    for (const [method, path, b] of routes) {
      const wrong = method === "GET" ? "POST" : "GET";
      const res = await handlePartnerSessionRequest(req(wrong, path, { headers: authed(), body: wrong === "POST" ? (b ?? {}) : undefined }), f.deps);
      expect(res.status, `${wrong} ${path}`).toBe(405);
      expect(res.headers.get("allow")).toBe(method);
    }
    expect(f.calls).toEqual([]);
  });

  it("a POST body must be exactly application/json (415 before the body is read)", async () => {
    const f = makeFakes();
    for (const [method, path] of routes.filter((r) => r[0] === "POST")) {
      const res = await handlePartnerSessionRequest(req(method, path, { headers: authed({ "content-type": "text/plain; x=application/json" }), raw: "{}" }), f.deps);
      expect(res.status, path).toBe(415);
    }
    expect(f.calls).toEqual([]);
  });
});

describe("GET pin: the PBKDF2 inputs the browser derives with", () => {
  it("a live PIN returns the salt (22 base64url characters), the iteration count and a running backoff; nothing is written", async () => {
    const f = makeFakes();
    const res = await get("pin", f);
    expect(res.status).toBe(200);
    const b = await body(res);
    expect(b.data).toEqual({ state: "ok", salt: toB64u(bytes(16, 8)), iterations: 600000, retryAfterSeconds: 0 });
    expect((b.data!.salt as string).length).toBe(22);
    expect(f.calls).toEqual(["db.withSession", "session.pinParams"]);
  });

  it("unset, must_change and locked carry NO salt and no iteration count (a locked PIN is refused while locked)", async () => {
    for (const state of ["unset", "must_change", "locked"] as const) {
      const f = makeFakes({ pinParams: { state } });
      const b = await body(await get("pin", f));
      expect(b.data, state).toEqual({ state });
    }
  });
});

describe("POST step-up/pin: the browser-derived key, never the PIN", () => {
  it("a correct key: 200 with the grant's expiry, the DERIVED BYTES (and nothing else) reach the port, and the response never echoes the key", async () => {
    const f = makeFakes();
    const res = await post("step-up/pin", { derived: DERIVED }, f);
    expect(res.status).toBe(200);
    expect(f.pinVerifyInputs).toHaveLength(1);
    expect(Array.from(f.pinVerifyInputs[0]!)).toEqual(Array.from(bytes(32, 0x11)));
    const text = await res.text();
    expect(JSON.parse(text)).toEqual({ data: { grantExpiresAt: "2030-01-01T12:01:00.000Z" } });
    expect(text).not.toContain(DERIVED);
    expect(f.calls).toEqual(["db.withSession", "session.pinVerify"]);
  });

  it("the body is STRICT: a PIN (4 digits), a key of the wrong length, padding, a wrong alphabet, an unknown key, a missing key and a non-object are all 400, and no port is touched", async () => {
    const f = makeFakes();
    const bad: unknown[] = [
      { derived: "1234" },
      { pin: "1234" },
      { derived: toB64u(bytes(31)) },
      { derived: toB64u(bytes(33)) },
      { derived: DERIVED + "=" },
      { derived: DERIVED.slice(0, 10) + "+" + DERIVED.slice(11) },
      { derived: DERIVED, extra: 1 },
      { derived: 12 },
      {},
      [],
      "x",
    ];
    for (const b of bad) expect((await post("step-up/pin", b, f)).status, JSON.stringify(b)).toBe(400);
    expect(f.calls).toEqual([]);
  });

  it("COMMIT ON EVERY STATUS: wrong, locked, backoff, unset and must_change are RETURNED, so the transaction commits (the failure counter commits with the refusal); each has its own answer", async () => {
    const cases: Array<[Parameters<typeof makeFakes>[0], number, string]> = [
      [{ pinVerify: { status: "wrong", retryAfterSeconds: 0, grantUntil: null } }, 403, "pin_wrong"],
      [{ pinVerify: { status: "wrong", retryAfterSeconds: 30, grantUntil: null } }, 403, "pin_wrong"],
      [{ pinVerify: { status: "locked", retryAfterSeconds: 0, grantUntil: null } }, 403, "pin_locked"],
      [{ pinVerify: { status: "retry_after", retryAfterSeconds: 17, grantUntil: null } }, 429, "pin_backoff"],
      [{ pinVerify: { status: "unset", retryAfterSeconds: 0, grantUntil: null } }, 409, "pin_not_set"],
      [{ pinVerify: { status: "must_change", retryAfterSeconds: 0, grantUntil: null } }, 409, "pin_must_change"],
    ];
    for (const [state, status, code] of cases) {
      const f = makeFakes(state);
      const res = await post("step-up/pin", { derived: DERIVED }, f);
      expect(res.status, code).toBe(status);
      expect((await body(res)).error?.code).toBe(code);
      expect(f.tx, code).toEqual([{ kind: "session", committed: true }]);
    }
    const f = makeFakes({ pinVerify: { status: "retry_after", retryAfterSeconds: 17, grantUntil: null } });
    expect((await post("step-up/pin", { derived: DERIVED }, f)).headers.get("retry-after")).toBe("17");
    const g = makeFakes({ pinVerify: { status: "retry_after", retryAfterSeconds: 0, grantUntil: null } });
    expect((await post("step-up/pin", { derived: DERIVED }, g)).headers.get("retry-after")).toBe("1");
  });

  it("a database fault is a constant 500 with no detail and ROLLS BACK; a dead session is the one 401; a definer refusal (no scope, below the required aal) is a 403", async () => {
    const f = makeFakes();
    f.deps.db.withSession = async () => {
      throw new Error("secret database text");
    };
    const res = await post("step-up/pin", { derived: DERIVED }, f);
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("secret database text");
    expect((await post("step-up/pin", { derived: DERIVED }, makeFakes({ bindRefused: true }))).status).toBe(401);
    const g = makeFakes();
    g.deps.db.withSession = async () => {
      throw new PartnerAuthorityRefused();
    };
    expect((await post("step-up/pin", { derived: DERIVED }, g)).status).toBe(403);
  });
});

describe("POST pin/set and pin/change", () => {
  it("set: the derived key, the salt and the iteration count reach the port as bytes and a number; the response is {set: true}", async () => {
    const f = makeFakes();
    const res = await post("pin/set", setBody(), f);
    expect(res.status).toBe(200);
    expect((await body(res)).data).toEqual({ set: true });
    const i = f.pinSetInputs[0]!;
    expect(Array.from(i.derived)).toEqual(Array.from(bytes(32, 0x11)));
    expect(Array.from(i.salt)).toEqual(Array.from(bytes(16, 0x33)));
    expect(i.iterations).toBe(600000);
    expect(f.calls).toEqual(["db.withSession", "session.pinSet"]);
  });

  it("change: also carries the CURRENT derived key; the response is {changed: true}", async () => {
    const f = makeFakes();
    const res = await post("pin/change", changeBody(), f);
    expect(res.status).toBe(200);
    expect((await body(res)).data).toEqual({ changed: true });
    const i = f.pinChangeInputs[0]!;
    expect(Array.from(i.current)).toEqual(Array.from(bytes(32, 0x22)));
    expect(Array.from(i.derived)).toEqual(Array.from(bytes(32, 0x11)));
  });

  it("the Edge validates LENGTH and ENCODING only: a PIN, a short key, a salt of 15 or 17 bytes, iterations outside 210000..1000000 (or not an integer), an unknown key and a missing one are 400, nothing is touched", async () => {
    const f = makeFakes();
    const badSet: unknown[] = [
      setBody({ derived: "1234" }),
      setBody({ derived: toB64u(bytes(31)) }),
      setBody({ salt: toB64u(bytes(15)) }),
      setBody({ salt: toB64u(bytes(17)) }),
      setBody({ salt: SALT + "=" }),
      setBody({ iterations: 209999 }),
      setBody({ iterations: 1000001 }),
      setBody({ iterations: 600000.5 }),
      setBody({ iterations: "600000" }),
      setBody({ pin: "7391" }),
      setBody({ currentDerived: CURRENT }),
      { derived: DERIVED, salt: SALT },
      { salt: SALT, iterations: 600000 },
    ];
    for (const b of badSet) expect((await post("pin/set", b, f)).status, JSON.stringify(b)).toBe(400);
    const badChange: unknown[] = [changeBody({ currentDerived: "1234" }), changeBody({ currentDerived: undefined }), changeBody({ currentDerived: toB64u(bytes(31)) }), changeBody({ iterations: 5 }), changeBody({ x: 1 }),
      // N5 (S1.3 gate): an extra `pin` key beside otherwise VALID derived keys (a client that also sends the PIN): the route's contract is "unknown keys are rejected", so it is a 400 before any work
      changeBody({ pin: "7391" })];
    for (const b of badChange) expect((await post("pin/change", b, f)).status, JSON.stringify(b)).toBe(400);
    expect(f.calls).toEqual([]);
    // the edges are accepted
    for (const iterations of [210000, 1000000]) expect((await post("pin/set", setBody({ iterations }), makeFakes())).status).toBe(200);
  });

  it("N5: an extra `pin` key on pin/change (and on pin/set, step-up/pin) is refused 400 even beside valid keys; the same body without it is 200", async () => {
    for (const [path, mk] of [["pin/change", changeBody], ["pin/set", setBody]] as const) {
      const f = makeFakes();
      const res = await post(path, mk({ pin: "7391" }), f);
      expect(res.status, path).toBe(400);
      expect(f.calls, path).toEqual([]);
      expect((await post(path, mk(), makeFakes())).status, path).toBe(200);
    }
    const f = makeFakes();
    expect((await post("step-up/pin", { derived: DERIVED, pin: "7391" }, f)).status).toBe(400);
    expect(f.calls).toEqual([]);
  });

  it("every status has its answer and the transaction COMMITS (a wrong current key of a change is counted by the database and the count commits)", async () => {
    const cases: Array<[string, number, string]> = [
      ["already_set", 409, "pin_already_set"],
      ["no_pin", 409, "pin_not_set"],
      ["unset", 409, "pin_not_set"],
      ["must_change", 409, "pin_must_change"],
      ["wrong", 403, "pin_wrong"],
      ["locked", 403, "pin_locked"],
      ["retry_after", 429, "pin_backoff"],
    ];
    for (const [status, http, code] of cases) {
      for (const path of ["pin/set", "pin/change"]) {
        const f = makeFakes({ pinWrite: { status: status as "ok", retryAfterSeconds: 9 } });
        const res = await post(path, path === "pin/set" ? setBody() : changeBody(), f);
        expect(res.status, `${path} ${status}`).toBe(http);
        expect((await body(res)).error?.code, `${path} ${status}`).toBe(code);
        expect(f.tx, `${path} ${status}`).toEqual([{ kind: "session", committed: true }]);
      }
    }
  });

  it("a definer refusal (no enrolment window or email proof, a passkey alone: 42501) is a 403 and a rollback; it is never a 401 (the session is fine)", async () => {
    for (const path of ["pin/set", "pin/change"]) {
      const f = makeFakes();
      f.deps.db.withSession = async () => {
        throw new PartnerAuthorityRefused();
      };
      const res = await post(path, path === "pin/set" ? setBody() : changeBody(), f);
      expect(res.status, path).toBe(403);
      expect((await body(res)).error?.code).toBe("forbidden");
    }
  });
});

describe("POST otp-proof/start: the code goes to the member's OWN address, from the database", () => {
  it("hit the 3-an-hour member bucket FIRST, read the address in one transaction, and send with NO transaction open; the response never carries the address", async () => {
    const f = makeFakes();
    const res = await post("otp-proof/start", {}, f);
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(JSON.parse(text)).toEqual({ data: { sent: true } });
    expect(text).not.toContain("staff@example.test");
    expect(f.calls).toEqual(["db.hitRateLimit", "db.withSession", "session.otpTarget", "otp.send"]);
    expect(f.rateLimitHits).toEqual([{ hash: await sha256Hex(SESSION_TOKEN), bucket: OTP_SEND_BUCKET, windowSeconds: 3600, max: OTP_SEND_PER_MEMBER_PER_HOUR }]);
    expect(OTP_SEND_PER_MEMBER_PER_HOUR).toBe(3);
    expect(f.otpSent).toEqual(["staff@example.test"]);
    expect(f.openTxAtOtpCall).toEqual([0]);
  });

  it("the body must be {}: a client-supplied address is a 400 (nobody can redirect the code), nothing is touched", async () => {
    const f = makeFakes();
    expect((await post("otp-proof/start", { email: "attacker@example.test" }, f)).status).toBe(400);
    expect(f.calls).toEqual([]);
  });

  it("over the bucket: 429 with Retry-After, and NOTHING else runs (no address read, no mail)", async () => {
    const f = makeFakes({ rateLimitOk: false });
    const res = await post("otp-proof/start", {}, f);
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("3600");
    expect(f.calls).toEqual(["db.hitRateLimit"]);
    expect(f.otpSent).toEqual([]);
  });

  it("an account with no address: 409, no mail; a mailer failure is a constant 500 with no detail", async () => {
    const f = makeFakes({ otpEmail: null });
    expect((await post("otp-proof/start", {}, f)).status).toBe(409);
    expect(f.otpSent).toEqual([]);
    const g = makeFakes({ otpSendThrows: true });
    const res = await post("otp-proof/start", {}, g);
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("secret provider text");
  });
});

describe("POST otp-proof/verify: the proof, bound to a fresh GoTrue session, which is closed AFTER it is recorded on every path", () => {
  const verify = (f: ReturnType<typeof makeFakes>, code = "123456") => post("otp-proof/verify", { code }, f);

  it("a correct code: limit, address, GoTrue with NO transaction open, then the proof in a second transaction, THEN the GoTrue session is closed", async () => {
    const f = makeFakes();
    const res = await verify(f);
    expect(res.status).toBe(200);
    expect((await body(res)).data).toEqual({ otpProofUntil: "2030-01-01T12:10:00.000Z" });
    expect(f.calls).toEqual(["db.hitRateLimit", "db.withSession", "session.otpTarget", "otp.verify", "db.withSession", "session.otpProof", "otp.closeSession"]);
    expect(f.otpVerified).toEqual([{ email: "staff@example.test", code: "123456" }]);
    expect(f.otpProofSessionIds).toEqual(["22222222-2222-2222-2222-222222222222"]);
    expect(f.otpClosed.count).toBe(1);
    expect(f.openTxAtOtpCall).toEqual([0, 0]);
    expect(f.rateLimitHits[0]).toMatchObject({ bucket: OTP_VERIFY_BUCKET, windowSeconds: 3600, max: OTP_VERIFY_PER_MEMBER_PER_HOUR });
    expect(OTP_VERIFY_PER_MEMBER_PER_HOUR).toBe(5);
  });

  it("the code is 6 to 10 digits and nothing else; unknown keys are refused: 400, nothing is touched", async () => {
    const f = makeFakes();
    for (const code of ["12345", "12345678901", "12345a", "", " 123456", "123 456"]) expect((await verify(f, code)).status, JSON.stringify(code)).toBe(400);
    expect((await post("otp-proof/verify", { code: "123456", email: "x@example.test" }, f)).status).toBe(400);
    expect((await post("otp-proof/verify", { code: 123456 }, f)).status).toBe(400);
    expect(f.calls).toEqual([]);
    for (const code of ["123456", "1234567890"]) expect((await verify(makeFakes(), code)).status, code).toBe(200);
  });

  it("a wrong or expired code is the ONE 403 `otp_refused`; no proof is recorded and there is no GoTrue session to close", async () => {
    const f = makeFakes({ otpVerifyOk: false });
    const res = await verify(f);
    expect(res.status).toBe(403);
    expect((await body(res)).error).toEqual({ code: "otp_refused", message: "that code was not accepted" });
    expect(f.calls).toEqual(["db.hitRateLimit", "db.withSession", "session.otpTarget", "otp.verify"]);
    expect(f.otpClosed.count).toBe(0);
  });

  it("every other refusal (no GoTrue session id, a stale or foreign GoTrue session, a GoTrue session already used for a proof) is the SAME 403 and the GoTrue session is STILL closed", async () => {
    const cases: Array<[string, Parameters<typeof makeFakes>[0]]> = [
      ["no session id", { otpSessionId: null }],
      ["refused by the database", { otpProofStatus: "refused" }],
      ["unique index", { otpProofThrows: new PartnerConflict() }],
    ];
    const seen = new Set<string>();
    for (const [name, state] of cases) {
      const f = makeFakes(state);
      const res = await verify(f);
      expect(res.status, name).toBe(403);
      seen.add(await res.text());
      expect(f.otpClosed.count, name).toBe(1);
    }
    expect(seen.size, "one uniform body").toBe(1);
  });

  it("a database fault while recording the proof still closes the GoTrue session, and the answer is a constant 500", async () => {
    const f = makeFakes({ otpProofThrows: new Error("secret database text") });
    const res = await verify(f);
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("secret database text");
    expect(f.otpClosed.count).toBe(1);
  });

  it("over the bucket: 429 and NOTHING else runs; an account with no address is refused as the same 403; a GoTrue transport failure is a constant 500 (not counted as a wrong code)", async () => {
    const f = makeFakes({ rateLimitOk: false });
    expect((await verify(f)).status).toBe(429);
    expect(f.calls).toEqual(["db.hitRateLimit"]);
    const g = makeFakes({ otpEmail: null });
    expect((await verify(g)).status).toBe(403);
    expect(g.otpVerified).toEqual([]);
    const h = makeFakes();
    h.deps.otp.verify = async () => {
      throw new Error("gotrue down: secret provider text");
    };
    const res = await verify(h);
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("secret provider text");
  });

  it("a conflict (23505) on any other route is a 409, and a dead session while proving is the one 401", async () => {
    const f = makeFakes();
    f.deps.db.withSession = async () => {
      throw new PartnerConflict();
    };
    expect((await post("pin/set", setBody(), f)).status).toBe(409);
    expect((await verify(makeFakes({ bindRefused: true }))).status).toBe(401);
  });
});
