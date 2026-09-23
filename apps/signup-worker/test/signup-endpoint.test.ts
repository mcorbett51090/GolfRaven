import { afterEach, describe, expect, it, vi } from "vitest";
import { handleSignup } from "../src/index";
import { makeTestEnv } from "./env";
import { resendCalls, stubExternalFetch } from "./fetch-mock";

function signupRequest(body: unknown, ip = "203.0.113.10"): Request {
  return new Request("https://golfraven.example/api/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip },
    body: JSON.stringify(body),
  });
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
    const res = await handleSignup(
      new Request("https://golfraven.example/api/signup", { method: "POST", body: "{not json" }),
      env,
    );
    expect(res.status).toBe(400);
  });

  it("400s on an invalid payload without ever calling Turnstile/Resend", async () => {
    const fetchMock = stubExternalFetch({});
    const env = makeTestEnv();
    const res = await handleSignup(signupRequest({ ...VALID_BODY, ageConfirmed: false }), env);
    expect(res.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("POST /api/signup — Turnstile", () => {
  it("400s when Turnstile verification fails, and does not touch the DB or send an email", async () => {
    stubExternalFetch({ turnstileOk: false });
    const env = makeTestEnv();
    const res = await handleSignup(signupRequest(VALID_BODY), env);
    expect(res.status).toBe(400);
    expect(env.DB.rows).toHaveLength(0);
  });
});

describe("POST /api/signup — rate limiting", () => {
  it("429s once the per-IP-key daily cap is exceeded", async () => {
    stubExternalFetch({});
    const env = makeTestEnv();
    let lastStatus = 0;
    for (let i = 0; i < 21; i += 1) {
      const res = await handleSignup(signupRequest({ ...VALID_BODY, email: `user${i}@example.com` }, "203.0.113.55"), env);
      lastStatus = res.status;
    }
    // SIGNUP_IP_DAILY_CAP is 20 — the 21st distinct-email request from the
    // same IP must be rejected.
    expect(lastStatus).toBe(429);
  });
});

describe("POST /api/signup — enumeration safety + upsert cases", () => {
  it("case A (new address): creates a pending row, sends one confirmation email, and returns the generic 202", async () => {
    const fetchMock = stubExternalFetch({});
    const env = makeTestEnv();
    const res = await handleSignup(signupRequest(VALID_BODY), env);
    expect(res.status).toBe(202);
    const bodyA = await res.json();
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
    const resB = await handleSignup(signupRequest({ ...VALID_BODY, email: "confirmed@example.com" }), env);
    const bodyB = await resB.json();
    expect(resB.status).toBe(202);
    expect(bodyB).toEqual(bodyA);
    // No new email sent for the already-confirmed, still-subscribed address.
    expect(resendCalls(fetchMock)).toHaveLength(1);
  });

  it("case C (pending, re-signup): rotates the confirm token and sends a new email, without creating a second row", async () => {
    const fetchMock = stubExternalFetch({});
    const env = makeTestEnv();
    await handleSignup(signupRequest(VALID_BODY), env);
    const firstHash = env.DB.rows[0]?.confirm_token_hash;

    const res = await handleSignup(signupRequest(VALID_BODY), env);
    expect(res.status).toBe(202);
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

    const res = await handleSignup(signupRequest(VALID_BODY), env);
    expect(res.status).toBe(202);
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

describe("POST /api/signup — Resend failure path", () => {
  it("still returns the generic 202 (no enumeration signal), but does not claim the email as sent", async () => {
    stubExternalFetch({ resendOk: false });
    const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const env = makeTestEnv();
    const res = await handleSignup(signupRequest(VALID_BODY), env);
    expect(res.status).toBe(202);
    // The row still exists (pending) so a retry can rotate-and-resend.
    expect(env.DB.rows).toHaveLength(1);
    expect(env.DB.rows[0]?.confirmed_at).toBeNull();
    expect(consoleErrorSpy).toHaveBeenCalledWith(
      "confirmation email send failed",
      expect.objectContaining({ reason: expect.any(String) }),
    );
    consoleErrorSpy.mockRestore();
  });
});
