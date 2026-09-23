import { describe, expect, it } from "vitest";
import {
  checkAndConsumeEmailRateLimit,
  checkAndConsumeIpRateLimit,
  checkAndConsumeResendSendLimits,
  rateLimitIpKeyMaterial,
} from "../src/ratelimit";
import { makeTestEnv } from "./env";

describe("checkAndConsumeIpRateLimit", () => {
  it("allows requests under the cap and consumes a slot", async () => {
    const env = makeTestEnv();
    const result = await checkAndConsumeIpRateLimit(env, "1.2.3.4", 5);
    expect(result.allowed).toBe(true);
  });

  it("blocks once the per-IP-key cap is reached", async () => {
    const env = makeTestEnv();
    for (let i = 0; i < 3; i += 1) {
      await checkAndConsumeIpRateLimit(env, "1.2.3.4", 3);
    }
    const result = await checkAndConsumeIpRateLimit(env, "1.2.3.4", 3);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("ip-daily-cap");
  });

  it("never stores the raw IP address as a KV key (only a hash)", async () => {
    const env = makeTestEnv();
    await checkAndConsumeIpRateLimit(env, "203.0.113.42", 5);
    for (const key of env.RATE_LIMIT_KV.store.keys()) {
      expect(key).not.toContain("203.0.113.42");
    }
  });
});

describe("checkAndConsumeEmailRateLimit", () => {
  it("allows requests under the cap and consumes a slot", async () => {
    const env = makeTestEnv();
    const result = await checkAndConsumeEmailRateLimit(env, "a@example.com", 5);
    expect(result.allowed).toBe(true);
  });

  it("blocks once the per-email cap is reached, independent of IP", async () => {
    const env = makeTestEnv();
    for (let i = 0; i < 3; i += 1) {
      await checkAndConsumeEmailRateLimit(env, "same@example.com", 3);
    }
    const result = await checkAndConsumeEmailRateLimit(env, "same@example.com", 3);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("email-daily-cap");
  });
});

describe("rateLimitIpKeyMaterial (F5/F6 — IPv6 /64 scoping)", () => {
  it("passes an IPv4 address through unchanged", () => {
    expect(rateLimitIpKeyMaterial("203.0.113.42")).toBe("203.0.113.42");
  });

  it("groups two IPv6 addresses in the same /64 to the same key", () => {
    const a = rateLimitIpKeyMaterial("2001:db8:abcd:1234:0000:0000:0000:0001");
    const b = rateLimitIpKeyMaterial("2001:db8:abcd:1234:ffff:ffff:ffff:ffff");
    expect(a).toBe(b);
  });

  it("gives a different key for a different /64", () => {
    const a = rateLimitIpKeyMaterial("2001:db8:abcd:1234::1");
    const b = rateLimitIpKeyMaterial("2001:db8:abcd:9999::1");
    expect(a).not.toBe(b);
  });

  it("handles the '::' shorthand form", () => {
    expect(rateLimitIpKeyMaterial("2001:db8:abcd:1234::1")).toBe(
      rateLimitIpKeyMaterial("2001:db8:abcd:1234:0:0:0:1"),
    );
  });
});

describe("checkAndConsumeResendSendLimits (F6)", () => {
  const opts = { cooldownSeconds: 600, emailDailyCap: 3, globalDailyCap: 500 };

  it("allows the first send for an address and starts the cooldown", async () => {
    const env = makeTestEnv();
    const result = await checkAndConsumeResendSendLimits(env, "a@example.com", opts);
    expect(result.allowed).toBe(true);
  });

  it("blocks a second send within the cooldown window", async () => {
    const env = makeTestEnv();
    await checkAndConsumeResendSendLimits(env, "a@example.com", opts);
    const second = await checkAndConsumeResendSendLimits(env, "a@example.com", opts);
    expect(second.allowed).toBe(false);
    expect(second.reason).toBe("resend-cooldown");
  });

  /** Clears any cooldown keys the fake KV set, simulating their TTL expiring (the fake has no real TTL). */
  function expireCooldowns(env: ReturnType<typeof makeTestEnv>): void {
    for (const key of [...env.RATE_LIMIT_KV.store.keys()]) {
      if (key.startsWith("rl:send-cooldown:")) env.RATE_LIMIT_KV.delete(key);
    }
  }

  it("blocks once the per-email daily send cap is reached, independent of the cooldown", async () => {
    const env = makeTestEnv();
    const dailyCapOpts = { ...opts, emailDailyCap: 2 };
    await checkAndConsumeResendSendLimits(env, "a@example.com", dailyCapOpts);
    expireCooldowns(env);
    await checkAndConsumeResendSendLimits(env, "a@example.com", dailyCapOpts);
    expireCooldowns(env);
    const third = await checkAndConsumeResendSendLimits(env, "a@example.com", dailyCapOpts);
    expect(third.allowed).toBe(false);
    expect(third.reason).toBe("email-send-daily-cap");
  });

  it("blocks once the global daily send cap is reached, across different addresses", async () => {
    const env = makeTestEnv();
    const tightGlobalOpts = { ...opts, globalDailyCap: 1 };
    await checkAndConsumeResendSendLimits(env, "a@example.com", tightGlobalOpts);
    const second = await checkAndConsumeResendSendLimits(env, "b@example.com", tightGlobalOpts);
    expect(second.allowed).toBe(false);
    expect(second.reason).toBe("global-send-daily-cap");
  });
});
