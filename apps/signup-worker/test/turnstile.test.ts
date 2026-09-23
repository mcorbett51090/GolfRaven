import { afterEach, describe, expect, it, vi } from "vitest";
import { verifyTurnstileToken } from "../src/turnstile";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("verifyTurnstileToken", () => {
  it("returns success on a valid siteverify response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ success: true }), { status: 200 })),
    );
    const result = await verifyTurnstileToken("good-token", "secret", "1.2.3.4");
    expect(result.success).toBe(true);
  });

  it("fails on a rejected siteverify response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ success: false, "error-codes": ["invalid-input-response"] }), { status: 200 })),
    );
    const result = await verifyTurnstileToken("bad-token", "secret", "1.2.3.4");
    expect(result.success).toBe(false);
    expect(result.errorCodes).toContain("invalid-input-response");
  });

  it("fails closed on a network error talking to Cloudflare", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      }),
    );
    const result = await verifyTurnstileToken("token", "secret", null);
    expect(result.success).toBe(false);
    expect(result.errorCodes).toEqual(["siteverify-network-error"]);
  });

  it("fails closed on a non-2xx siteverify response", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 503 })));
    const result = await verifyTurnstileToken("token", "secret", null);
    expect(result.success).toBe(false);
  });

  it("rejects an empty or oversized token before ever calling fetch", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    expect((await verifyTurnstileToken("", "secret", null)).success).toBe(false);
    expect((await verifyTurnstileToken("x".repeat(5000), "secret", null)).success).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  describe("hostname/action check (F12, defense in depth)", () => {
    it("succeeds when the response's hostname/action match what's expected", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => new Response(JSON.stringify({ success: true, hostname: "golfraven.example", action: "signup" }), { status: 200 })),
      );
      const result = await verifyTurnstileToken("tok", "secret", "1.2.3.4", { hostname: "golfraven.example", action: "signup" });
      expect(result.success).toBe(true);
    });

    it("fails when the response's hostname is present but does not match", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => new Response(JSON.stringify({ success: true, hostname: "evil.example" }), { status: 200 })),
      );
      const result = await verifyTurnstileToken("tok", "secret", "1.2.3.4", { hostname: "golfraven.example" });
      expect(result.success).toBe(false);
      expect(result.errorCodes).toContain("hostname-mismatch");
    });

    it("fails when the response's action is present but does not match", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => new Response(JSON.stringify({ success: true, action: "other" }), { status: 200 })),
      );
      const result = await verifyTurnstileToken("tok", "secret", "1.2.3.4", { action: "signup" });
      expect(result.success).toBe(false);
      expect(result.errorCodes).toContain("action-mismatch");
    });

    it("does not fail when hostname/action are expected but the response omits them", async () => {
      vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ success: true }), { status: 200 })));
      const result = await verifyTurnstileToken("tok", "secret", "1.2.3.4", { hostname: "golfraven.example", action: "signup" });
      expect(result.success).toBe(true);
    });
  });
});
