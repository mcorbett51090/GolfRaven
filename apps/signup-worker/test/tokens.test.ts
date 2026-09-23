import { describe, expect, it } from "vitest";
import { generateToken, hashWithPepper, isExpired, isoTimeFromNow } from "../src/tokens";

describe("tokens", () => {
  it("generates unique, URL-safe tokens with no padding", () => {
    const a = generateToken();
    const b = generateToken();
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(a.length).toBeGreaterThan(32);
  });

  it("hashes deterministically and includes the pepper", async () => {
    const h1 = await hashWithPepper("pepper-a", "token-1");
    const h2 = await hashWithPepper("pepper-a", "token-1");
    const h3 = await hashWithPepper("pepper-b", "token-1");
    expect(h1).toBe(h2);
    expect(h1).not.toBe(h3);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
  });

  it("isExpired is false for a future timestamp and true for a past one", () => {
    expect(isExpired(isoTimeFromNow(3600))).toBe(false);
    expect(isExpired(isoTimeFromNow(-1))).toBe(true);
  });

  it("isExpired treats a malformed timestamp as expired (fail closed)", () => {
    expect(isExpired("not-a-date")).toBe(true);
  });
});
