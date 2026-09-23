import { afterEach, describe, expect, it, vi } from "vitest";
import { SIGNUP_EMAIL_DAILY_CAP } from "../src/config";
import { handleSignup } from "../src/index";
import { makeTestEnv } from "./env";
import { resendCalls, stubExternalFetch } from "./fetch-mock";

function jsonText(body: unknown): string {
  return JSON.stringify(body);
}

function signupRequest(body: unknown, ip = "203.0.113.10", extraHeaders: Record<string, string> = {}): Request {
  const text = jsonText(body);
  return new Request("https://golfraven.example/api/signup", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": String(new TextEncoder().encode(text).byteLength),
      "CF-Connecting-IP": ip,
      ...extraHeaders,
    },
    body: text,
  });
}

/**
 * A fake ExecutionContext: `waitUntil` records the promise instead of
 * blocking on it (like the real Workers runtime), and `flush` lets a test
 * explicitly wait for that backgrounded work when it wants to assert on
 * its result — mirroring how index.ts's handleSignup defers all
 * case-dependent work (gate finding F2).
 */
function makeWaitUntilCtx() {
  const waited: Promise<unknown>[] = [];
  return {
    ctx: { waitUntil: (p: Promise<unknown>) => { waited.push(p); } },
    flush: () => Promise.all(waited),
  };
}

const VALID_BODY = {
  email: "Player@Example.com",
  ageConfirmed: true,
  consentVersion: "2026-09-23",
  turnstileToken: "good-token",
  source: "reddit",
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("POST /api/signup — validation", () => {
  it("400s on malformed JSON", async () => {
    const env = makeTestEnv();
    const { ctx } = makeWaitUntilCtx();
    const badText = "{not json";
    const res = await handleSignup(
      new Request("https://golfraven.example/api/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": String(badText.length) },
        body: badText,
      }),
      env,
      ctx,
    );
    expect(res.status).toBe(400);
  });

  it("400s on an invalid payload without ever calling Turnstile/Resend", async () => {
    const fetchMock = stubExternalFetch({});
    const env = makeTestEnv();
    const { ctx } = makeWaitUntilCtx();
    const res = await handleSignup(signupRequest({ ...VALID_BODY, ageConfirmed: false }), env, ctx);
    expect(res.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("POST /api/signup — body limits (F10)", () => {
  it("415s when Content-Type is not application/json", async () => {
    const env = makeTestEnv();
    const fetchMock = stubExternalFetch({});
    const { ctx } = makeWaitUntilCtx();
    const res = await handleSignup(
      new Request("https://golfraven.example/api/signup", {
        method: "POST",
        headers: { "Content-Type": "text/plain", "Content-Length": "2" },
        body: "{}",
      }),
      env,
      ctx,
    );
    expect(res.status).toBe(415);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("411s when Content-Length is absent", async () => {
    const env = makeTestEnv();
    const { ctx } = makeWaitUntilCtx();
    const res = await handleSignup(
      new Request("https://golfraven.example/api/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: jsonText(VALID_BODY),
      }),
      env,
      ctx,
    );
    expect(res.status).toBe(411);
  });

  it("413s on an oversized body", async () => {
    const env = makeTestEnv();
    const { ctx } = makeWaitUntilCtx();
    const text = jsonText({ ...VALID_BODY, source: "x".repeat(9000) });
    const res = await handleSignup(
      new Request("https://golfraven.example/api/signup", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": String(new TextEncoder().encode(text).byteLength),
        },
        body: text,
      }),
      env,
      ctx,
    );
    expect(res.status).toBe(413);
  });
});

describe("POST /api/signup — Turnstile", () => {
  it("400s when Turnstile verification fails, and does not touch the DB or send an email", async () => {
    stubExternalFetch({ turnstileOk: false });
    const env = makeTestEnv();
    const { ctx, flush } = makeWaitUntilCtx();
    const res = await handleSignup(signupRequest(VALID_BODY), env, ctx);
    expect(res.status).toBe(400);
    await flush();
    expect(env.DB.rows).toHaveLength(0);
  });
});

describe("POST /api/signup — order of checks (F5)", () => {
  it("does not consume the per-email slot when Turnstile fails — the real signup owner isn't locked out by an attacker's junk token", async () => {
    const env = makeTestEnv();
    stubExternalFetch({ turnstileOk: false });
    for (let i = 0; i < SIGNUP_EMAIL_DAILY_CAP + 2; i += 1) {
      const { ctx } = makeWaitUntilCtx();
      // Different IPs so only the per-email cap is at stake, not the per-IP one.
      const res = await handleSignup(signupRequest(VALID_BODY, `198.51.100.${i}`), env, ctx);
      expect(res.status).toBe(400);
    }
    stubExternalFetch({ turnstileOk: true });
    const { ctx, flush } = makeWaitUntilCtx();
    const res = await handleSignup(signupRequest(VALID_BODY, "203.0.113.200"), env, ctx);
    // If the email slot had been spent by the attacker's failed-Turnstile
    // attempts above, this would 429 instead of 202.
    expect(res.status).toBe(202);
    await flush();
    expect(env.DB.rows).toHaveLength(1);
  });
});

describe("POST /api/signup — rate limiting", () => {
  it("429s once the per-IP-key daily cap is exceeded", async () => {
    stubExternalFetch({});
    const env = makeTestEnv();
    let lastStatus = 0;
    for (let i = 0; i < 21; i += 1) {
      const { ctx } = makeWaitUntilCtx();
      const res = await handleSignup(signupRequest({ ...VALID_BODY, email: `user${i}@example.com` }, "203.0.113.55"), env, ctx);
      lastStatus = res.status;
    }
    // SIGNUP_IP_DAILY_CAP is 20 — the 21st distinct-email request from the
    // same IP must be rejected.
    expect(lastStatus).toBe(429);
  });

  it("429s once the per-email-key daily cap is exceeded", async () => {
    stubExternalFetch({});
    const env = makeTestEnv();
    let lastStatus = 0;
    for (let i = 0; i < SIGNUP_EMAIL_DAILY_CAP + 1; i += 1) {
      const { ctx } = makeWaitUntilCtx();
      const res = await handleSignup(signupRequest(VALID_BODY, `203.0.113.${60 + i}`), env, ctx);
      lastStatus = res.status;
    }
    expect(lastStatus).toBe(429);
  });

  it("scopes an IPv6 per-IP cap to the /64, not the full address (F5/F6)", async () => {
    stubExternalFetch({});
    const env = makeTestEnv();
    let lastStatus = 0;
    for (let i = 0; i < 21; i += 1) {
      const { ctx } = makeWaitUntilCtx();
      // Same /64, low 64 bits rotate every request.
      const ip = `2001:db8:abcd:1234:${i.toString(16)}::1`;
      const res = await handleSignup(signupRequest({ ...VALID_BODY, email: `v6user${i}@example.com` }, ip), env, ctx);
      lastStatus = res.status;
    }
    expect(lastStatus).toBe(429);
  });
});

describe("POST /api/signup — timing oracle (F2)", () => {
  it("responds without waiting for the (fake) Resend send or D1 writes to resolve — new address", async () => {
    const env = makeTestEnv();
    let resolveResend!: (r: Response) => void;
    const resendGate = new Promise<Response>((resolve) => {
      resolveResend = resolve;
    });
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("challenges.cloudflare.com")) {
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }
      if (url.includes("api.resend.com")) return resendGate;
      throw new Error(`unexpected fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const { ctx, flush } = makeWaitUntilCtx();
    // If handleSignup internally awaited the Resend send, this next line
    // would hang forever (resendGate never resolves on its own) and the
    // test would time out — resolving proves it did not.
    const res = await handleSignup(signupRequest(VALID_BODY), env, ctx);
    expect(res.status).toBe(202);

    resolveResend(new Response(JSON.stringify({ id: "re_bg" }), { status: 200 }));
    await flush();
    expect(env.DB.rows).toHaveLength(1);
    expect(env.DB.rows[0]?.confirm_token_hash).not.toBeNull(); // not confirmed yet, still pending
  });

  it("responds without any background write/send for an already-confirmed address", async () => {
    const env = makeTestEnv();
    env.DB.rows.push({
      id: "row-2",
      email_lc: "confirmed@example.com",
      consent_version: "2026-09-23",
      age_confirmed: 1,
      source: null,
      created_at: new Date().toISOString(),
      confirmed_at: new Date().toISOString(),
      unsubscribed_at: null,
      confirm_token_hash: null,
      confirm_expires_at: null,
      unsubscribe_token_hash: "irrelevant-hash",
    });
    const fetchMock = stubExternalFetch({});
    const { ctx, flush } = makeWaitUntilCtx();
    const res = await handleSignup(signupRequest({ ...VALID_BODY, email: "confirmed@example.com" }), env, ctx);
    expect(res.status).toBe(202);
    await flush();
    expect(resendCalls(fetchMock)).toHaveLength(0);
  });
});

describe("POST /api/signup — enumeration safety + upsert cases", () => {
  it("case A (new address): creates a pending row, sends one confirmation email, and returns the generic 202", async () => {
    const fetchMock = stubExternalFetch({});
    const env = makeTestEnv();
    const { ctx, flush } = makeWaitUntilCtx();
    const res = await handleSignup(signupRequest(VALID_BODY), env, ctx);
    expect(res.status).toBe(202);
    const bodyA = await res.json();
    await flush();
    expect(env.DB.rows).toHaveLength(1);
    expect(env.DB.rows[0]?.email_lc).toBe("player@example.com");
    expect(env.DB.rows[0]?.confirmed_at).toBeNull();
    expect(resendCalls(fetchMock)).toHaveLength(1);

    // Case B (comparison): a DIFFERENT, already-confirmed address returns
    // the byte-identical response, proving the endpoint doesn't leak
    // which case applied.
    env.DB.rows.push({
      id: "row-2",
      email_lc: "confirmed@example.com",
      consent_version: "2026-09-23",
      age_confirmed: 1,
      source: null,
      created_at: new Date().toISOString(),
      confirmed_at: new Date().toISOString(),
      unsubscribed_at: null,
      confirm_token_hash: null,
      confirm_expires_at: null,
      unsubscribe_token_hash: "irrelevant-hash",
    });
    const { ctx: ctxB, flush: flushB } = makeWaitUntilCtx();
    const resB = await handleSignup(signupRequest({ ...VALID_BODY, email: "confirmed@example.com" }), env, ctxB);
    const bodyB = await resB.json();
    expect(resB.status).toBe(202);
    expect(bodyB).toEqual(bodyA);
    await flushB();
    // No new email sent for the already-confirmed, still-subscribed address.
    expect(resendCalls(fetchMock)).toHaveLength(1);
  });

  it("case C (pending, re-signup after the cooldown): rotates the confirm token and sends a new email, without creating a second row", async () => {
    const fetchMock = stubExternalFetch({});
    const env = makeTestEnv();
    const { ctx: ctx1, flush: flush1 } = makeWaitUntilCtx();
    await handleSignup(signupRequest(VALID_BODY), env, ctx1);
    await flush1();
    const firstHash = env.DB.rows[0]?.confirm_token_hash;
    // Clear the resend cooldown key so the second send in this test isn't
    // skipped by the new per-email cooldown (F6) — a separate concern from
    // token rotation, covered by its own test below.
    env.RATE_LIMIT_KV.store.clear();

    const { ctx: ctx2, flush: flush2 } = makeWaitUntilCtx();
    const res = await handleSignup(signupRequest(VALID_BODY), env, ctx2);
    expect(res.status).toBe(202);
    await flush2();
    expect(env.DB.rows).toHaveLength(1);
    expect(env.DB.rows[0]?.confirm_token_hash).not.toBe(firstHash);
    expect(resendCalls(fetchMock)).toHaveLength(2);
  });

  it("case D (previously unsubscribed): re-signup rotates the token and sends a new email, WITHOUT clearing unsubscribed_at until confirmed", async () => {
    const fetchMock = stubExternalFetch({});
    const env = makeTestEnv();
    const originalConfirmedAt = "2026-01-01T00:00:00.000Z";
    env.DB.rows.push({
      id: "row-unsub",
      email_lc: "player@example.com",
      consent_version: "2026-09-23",
      age_confirmed: 1,
      source: null,
      created_at: "2025-12-31T00:00:00.000Z",
      confirmed_at: originalConfirmedAt,
      unsubscribed_at: "2026-02-01T00:00:00.000Z",
      confirm_token_hash: null,
      confirm_expires_at: null,
      unsubscribe_token_hash: "old-hash",
    });

    const { ctx, flush } = makeWaitUntilCtx();
    const res = await handleSignup(signupRequest(VALID_BODY), env, ctx);
    expect(res.status).toBe(202);
    await flush();
    expect(env.DB.rows).toHaveLength(1);
    // A fresh confirm token was issued (re-signup sends a NEW email)...
    expect(env.DB.rows[0]?.confirm_token_hash).not.toBeNull();
    // ...but unsubscribed_at is untouched until the NEW link is actually
    // confirmed (task requirement: "may re-open only via a fresh confirmation").
    expect(env.DB.rows[0]?.unsubscribed_at).toBe("2026-02-01T00:00:00.000Z");
    // The historical confirmedAt (load-bearing for K2) is untouched.
    expect(env.DB.rows[0]?.confirmed_at).toBe(originalConfirmedAt);
    expect(resendCalls(fetchMock)).toHaveLength(1);
  });

});

// F3's "concurrent insert never 500s" guarantee (ON CONFLICT DO NOTHING +
// the re-read-and-rotate fallback) is unit-tested directly against
// createPendingSignup/db.ts in test/db.test.ts, where the race can be
// simulated deterministically; the router-level `return await` half of F3
// is covered in test/router.test.ts.

describe("POST /api/signup — resend send limits (F6)", () => {
  it("applies a per-email cooldown: a second signup shortly after the first sends no new email", async () => {
    const env = makeTestEnv();
    const fetchMock = stubExternalFetch({});
    const { ctx: ctx1, flush: flush1 } = makeWaitUntilCtx();
    await handleSignup(signupRequest(VALID_BODY), env, ctx1);
    await flush1();
    expect(resendCalls(fetchMock)).toHaveLength(1);

    const { ctx: ctx2, flush: flush2 } = makeWaitUntilCtx();
    await handleSignup(signupRequest(VALID_BODY), env, ctx2);
    await flush2();
    // Still just the one send — the cooldown blocked the second.
    expect(resendCalls(fetchMock)).toHaveLength(1);
  });

  it("stops sending once the global daily cap is reached, but still returns the generic 202 and logs an error", async () => {
    const env = makeTestEnv({ GLOBAL_DAILY_SEND_CAP: "1" });
    const fetchMock = stubExternalFetch({});
    const { ctx: ctx1, flush: flush1 } = makeWaitUntilCtx();
    const res1 = await handleSignup(signupRequest({ ...VALID_BODY, email: "first@example.com" }), env, ctx1);
    await flush1();
    expect(res1.status).toBe(202);
    expect(resendCalls(fetchMock)).toHaveLength(1);

    const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const { ctx: ctx2, flush: flush2 } = makeWaitUntilCtx();
    const res2 = await handleSignup(signupRequest({ ...VALID_BODY, email: "second@example.com" }), env, ctx2);
    await flush2();
    expect(res2.status).toBe(202);
    expect(resendCalls(fetchMock)).toHaveLength(1); // the second send was skipped
    expect(consoleErrorSpy).toHaveBeenCalledWith(
      "confirmation email skipped by send limit",
      expect.objectContaining({ reason: "global-send-daily-cap" }),
    );
    consoleErrorSpy.mockRestore();
  });
});

describe("POST /api/signup — Resend failure path", () => {
  it("still returns the generic 202 (no enumeration signal), but does not claim the email as sent, and logs only a fixed status (F14)", async () => {
    stubExternalFetch({ resendOk: false });
    const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const env = makeTestEnv();
    const { ctx, flush } = makeWaitUntilCtx();
    const res = await handleSignup(signupRequest(VALID_BODY), env, ctx);
    expect(res.status).toBe(202);
    await flush();
    // The row still exists (pending) so a retry can rotate-and-resend.
    expect(env.DB.rows).toHaveLength(1);
    expect(env.DB.rows[0]?.confirmed_at).toBeNull();
    expect(consoleErrorSpy).toHaveBeenCalledWith(
      "confirmation email send failed",
      expect.objectContaining({ status: expect.anything() }),
    );
    consoleErrorSpy.mockRestore();
  });
});
