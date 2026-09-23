import { describe, expect, it } from "vitest";
import { checkAndConsumeRateLimit } from "../src/ratelimit";
import { makeTestEnv } from "./env";

describe("checkAndConsumeRateLimit", () => {
  it("allows requests under both caps and consumes a slot from each", async () => {
    const env = makeTestEnv();
    const result = await checkAndConsumeRateLimit(env, "1.2.3.4", "a@example.com", 5, 5);
    expect(result.allowed).toBe(true);
  });

  it("blocks once the per-IP-key cap is reached, before consuming another email slot", async () => {
    const env = makeTestEnv();
    for (let i = 0; i < 3; i += 1) {
      await checkAndConsumeRateLimit(env, "1.2.3.4", `user${i}@example.com`, 3, 100);
    }
    const result = await checkAndConsumeRateLimit(env, "1.2.3.4", "user4@example.com", 3, 100);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("ip-daily-cap");
  });

  it("blocks once the per-email cap is reached, independent of IP", async () => {
    const env = makeTestEnv();
    for (let i = 0; i < 3; i += 1) {
      await checkAndConsumeRateLimit(env, `10.0.0.${i}`, "same@example.com", 100, 3);
    }
    const result = await checkAndConsumeRateLimit(env, "10.0.0.99", "same@example.com", 100, 3);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("email-daily-cap");
  });

  it("never stores the raw IP address as a KV key (only a hash)", async () => {
    const env = makeTestEnv();
    await checkAndConsumeRateLimit(env, "203.0.113.42", "a@example.com", 5, 5);
    const kv = env.RATE_LIMIT_KV as unknown as { store: Map<string, string> };
    for (const key of kv.store.keys()) {
      expect(key).not.toContain("203.0.113.42");
    }
  });
});
