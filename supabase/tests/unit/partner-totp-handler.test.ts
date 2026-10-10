// supabase/tests/unit/partner-totp-handler.test.ts
//
// The operator/admin TOTP routes of `partner-session` (docs/security/partner-auth-design.md 6.4, PA-20, PA-24, slice S1.4), against the in-memory ports of partner-fakes.ts. What is decided HERE, by
// the pure handler: the strict body shapes (`{ code }` of exactly 6 digits; enrol takes `{}`), the status-to-response mapping, COMMIT ON EVERY STATUS, the otpauth URI assembly from seed bytes, and the
// Origin refusal. What needs a real database is the pgTAP / Deno integration suite for migration 0053.

import { describe, expect, it } from "vitest";
import { handlePartnerSessionRequest } from "../../functions/_shared/partner/session-handler.ts";
import { PartnerAuthorityRefused, PartnerNotConfigured } from "../../functions/_shared/partner/ports.ts";
import { buildOtpauthUrl, encodeTotpSeed } from "../../functions/_shared/partner/totp-contract.ts";
import { authed, bytes, makeFakes, ORIGIN, req, SESSION_TOKEN } from "./partner-fakes.ts";

const CODE = "123456";
const post = (path: string, body: unknown, f: ReturnType<typeof makeFakes>) => handlePartnerSessionRequest(req("POST", path, { headers: authed(), body }), f.deps);
const body = async (res: Response): Promise<{ data?: Record<string, unknown>; error?: { code: string; message: string } }> => JSON.parse(await res.text());

describe("routing and the bearer: the TOTP routes are session routes", () => {
  const routes: Array<[string, unknown]> = [
    ["totp/enrol", {}],
    ["totp/confirm", { code: CODE }],
    ["step-up/totp", { code: CODE }],
  ];

  it("each needs a gr_ps_ bearer: anything else is the ONE 401 with no port touched", async () => {
    const f = makeFakes();
    for (const [path, b] of routes) {
      for (const authorization of [undefined, "Bearer not-a-partner-token", `Bearer ${SESSION_TOKEN}x`, `Basic ${SESSION_TOKEN}`]) {
        const headers: Record<string, string> = { origin: ORIGIN };
        if (authorization !== undefined) headers.authorization = authorization;
        const res = await handlePartnerSessionRequest(req("POST", path, { headers, body: b }), f.deps);
        expect(res.status, `${path} ${authorization}`).toBe(401);
      }
    }
    expect(f.calls).toEqual([]);
  });

  it("each is POST only: GET is 405 with Allow, before anything else is touched", async () => {
    const f = makeFakes();
    for (const [path] of routes) {
      const res = await handlePartnerSessionRequest(req("GET", path, { headers: authed() }), f.deps);
      expect(res.status, path).toBe(405);
      expect(res.headers.get("allow")).toBe("POST");
    }
    expect(f.calls).toEqual([]);
  });

  it("a POST body must be exactly application/json (415 before the body is read)", async () => {
    const f = makeFakes();
    for (const [path] of routes) {
      const res = await handlePartnerSessionRequest(req("POST", path, { headers: authed({ "content-type": "text/plain; x=application/json" }), raw: "{}" }), f.deps);
      expect(res.status, path).toBe(415);
    }
    expect(f.calls).toEqual([]);
  });

  it("a foreign Origin is 403 BEFORE routing, for every TOTP route, with no CORS header and no port touched", async () => {
    const f = makeFakes();
    for (const [path, b] of routes) {
      const res = await handlePartnerSessionRequest(req("POST", path, { headers: { origin: "https://evil.example.test", authorization: `Bearer ${SESSION_TOKEN}` }, body: b }), f.deps);
      expect(res.status, path).toBe(403);
      expect(res.headers.get("access-control-allow-origin")).toBeNull();
      expect((await body(res)).error).toEqual({ code: "forbidden", message: "origin not allowed" });
    }
    expect(f.calls).toEqual([]);
  });
});

describe("POST totp/enrol: the seed once, as base32 + otpauth", () => {
  it("ok: returns seed (base32), seedVersion, otpauthUrl, issuer, period, digits, algo; the raw seed bytes never leave as hex", async () => {
    const f = makeFakes();
    const seedBytes = bytes(32, 0xab);
    const res = await post("totp/enrol", {}, f);
    expect(res.status).toBe(200);
    const expectedSeed = encodeTotpSeed(seedBytes);
    const expectedUrl = buildOtpauthUrl({ seed: seedBytes, issuer: "GolfRaven", period: 30, digits: 6, algo: "SHA1" });
    expect((await body(res)).data).toEqual({
      seed: expectedSeed,
      seedVersion: 1,
      otpauthUrl: expectedUrl,
      issuer: "GolfRaven",
      period: 30,
      digits: 6,
      algo: "SHA1",
    });
    expect(expectedSeed).toMatch(/^[A-Z2-7]+$/);
    expect(expectedUrl.startsWith("otpauth://totp/")).toBe(true);
    expect(f.calls).toEqual(["db.withSession", "session.totpEnrol"]);
    expect(f.tx).toEqual([{ kind: "session", committed: true }]);
  });

  it("the body must be {}: unknown keys are 400, nothing is touched", async () => {
    const f = makeFakes();
    for (const b of [{ seed: "x" }, { code: CODE }, { extra: 1 }, [], "x"]) {
      expect((await post("totp/enrol", b, f)).status, JSON.stringify(b)).toBe(400);
    }
    expect(f.calls).toEqual([]);
  });

  it("already_confirmed is 409 and the transaction COMMITS; 42501 is 403; 55000 is 503", async () => {
    const f = makeFakes({ totpEnrol: { status: "already_confirmed", seed: null, seedVersion: null, issuer: null, period: null, digits: null, algo: null } });
    const res = await post("totp/enrol", {}, f);
    expect(res.status).toBe(409);
    expect((await body(res)).error?.code).toBe("totp_already_confirmed");
    expect(f.tx).toEqual([{ kind: "session", committed: true }]);

    const g = makeFakes();
    g.deps.db.withSession = async () => {
      throw new PartnerAuthorityRefused();
    };
    expect((await post("totp/enrol", {}, g)).status).toBe(403);

    const h = makeFakes();
    h.deps.db.withSession = async () => {
      throw new PartnerNotConfigured();
    };
    expect((await post("totp/enrol", {}, h)).status).toBe(503);
  });
});

describe("POST totp/confirm and POST step-up/totp: exactly `{ code }` of 6 digits", () => {
  for (const path of ["totp/confirm", "step-up/totp"] as const) {
    it(`${path}: the body is STRICT — wrong length, non-digits, unknown keys, missing code and a non-object are 400, no port is touched`, async () => {
      const f = makeFakes();
      const bad: unknown[] = [
        { code: "12345" },
        { code: "1234567" },
        { code: "12345a" },
        { code: " 123456" },
        { code: 123456 },
        { code: CODE, extra: 1 },
        { totp: CODE },
        {},
        [],
        "x",
      ];
      for (const b of bad) expect((await post(path, b, f)).status, JSON.stringify(b)).toBe(400);
      expect(f.calls).toEqual([]);
    });
  }

  it("confirm ok: 200 { confirmed: true }, the code reaches the port, the transaction commits", async () => {
    const f = makeFakes();
    const res = await post("totp/confirm", { code: CODE }, f);
    expect(res.status).toBe(200);
    expect((await body(res)).data).toEqual({ confirmed: true });
    expect(f.totpConfirmCodes).toEqual([CODE]);
    expect(f.calls).toEqual(["db.withSession", "session.totpConfirm"]);
    expect(f.tx).toEqual([{ kind: "session", committed: true }]);
  });

  it("step-up/totp ok: 200 { mfaUntil, aal: 2 }", async () => {
    const f = makeFakes();
    const res = await post("step-up/totp", { code: CODE }, f);
    expect(res.status).toBe(200);
    expect((await body(res)).data).toEqual({ mfaUntil: "2030-01-01T12:05:00.000Z", aal: 2 });
    expect(f.totpVerifyCodes).toEqual([CODE]);
    expect(f.calls).toEqual(["db.withSession", "session.totpVerify"]);
  });
});

describe("COMMIT ON EVERY STATUS: confirm and verify map statuses like PIN", () => {
  it("totp/confirm: every returned status has its HTTP answer and the transaction commits", async () => {
    const cases: Array<[Parameters<typeof makeFakes>[0], number, string]> = [
      [{ totpConfirm: { status: "wrong", retryAfterSeconds: 0 } }, 403, "totp_wrong"],
      [{ totpConfirm: { status: "locked", retryAfterSeconds: 900 } }, 403, "totp_locked"],
      [{ totpConfirm: { status: "unset", retryAfterSeconds: 0 } }, 409, "totp_not_set"],
      [{ totpConfirm: { status: "already_confirmed", retryAfterSeconds: 0 } }, 409, "totp_already_confirmed"],
      [{ totpConfirm: { status: "wrong_session", retryAfterSeconds: 0 } }, 409, "totp_wrong_session"],
    ];
    for (const [state, status, code] of cases) {
      const f = makeFakes(state);
      const res = await post("totp/confirm", { code: CODE }, f);
      expect(res.status, code).toBe(status);
      expect((await body(res)).error?.code).toBe(code);
      expect(f.tx, code).toEqual([{ kind: "session", committed: true }]);
    }
    const locked = makeFakes({ totpConfirm: { status: "locked", retryAfterSeconds: 900 } });
    expect((await post("totp/confirm", { code: CODE }, locked)).headers.get("retry-after")).toBe("900");
  });

  it("step-up/totp: wrong→403, locked→403 with Retry-After, retry_after→429, unset/unconfirmed→409", async () => {
    const cases: Array<[Parameters<typeof makeFakes>[0], number, string, string | null]> = [
      [{ totpVerify: { status: "wrong", retryAfterSeconds: 0, mfaUntil: null } }, 403, "totp_wrong", null],
      [{ totpVerify: { status: "locked", retryAfterSeconds: 900, mfaUntil: null } }, 403, "totp_locked", "900"],
      [{ totpVerify: { status: "retry_after", retryAfterSeconds: 17, mfaUntil: null } }, 429, "totp_backoff", "17"],
      [{ totpVerify: { status: "unset", retryAfterSeconds: 0, mfaUntil: null } }, 409, "totp_not_set", null],
      [{ totpVerify: { status: "unconfirmed", retryAfterSeconds: 0, mfaUntil: null } }, 409, "totp_unconfirmed", null],
    ];
    for (const [state, status, code, retry] of cases) {
      const f = makeFakes(state);
      const res = await post("step-up/totp", { code: CODE }, f);
      expect(res.status, code).toBe(status);
      expect((await body(res)).error?.code).toBe(code);
      expect(f.tx, code).toEqual([{ kind: "session", committed: true }]);
      if (retry !== null) expect(res.headers.get("retry-after"), code).toBe(retry);
    }
  });

  it("a dead session is the one 401; a definer refusal (42501) is 403; a database fault is a constant 500 with no detail", async () => {
    expect((await post("step-up/totp", { code: CODE }, makeFakes({ bindRefused: true }))).status).toBe(401);
    const g = makeFakes();
    g.deps.db.withSession = async () => {
      throw new PartnerAuthorityRefused();
    };
    expect((await post("step-up/totp", { code: CODE }, g)).status).toBe(403);
    const h = makeFakes();
    h.deps.db.withSession = async () => {
      throw new Error("secret database text");
    };
    const res = await post("totp/confirm", { code: CODE }, h);
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("secret database text");
  });
});
