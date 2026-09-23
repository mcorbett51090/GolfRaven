import { afterEach, describe, expect, it, vi } from "vitest";
import { buildConfirmationEmail, sendConfirmationEmail, sendEmail } from "../src/email";
import { makeTestEnv } from "./env";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("buildConfirmationEmail", () => {
  it("carries List-Unsubscribe + List-Unsubscribe-Post (RFC 8058) and both links", () => {
    const msg = buildConfirmationEmail({
      fromEmail: "GolfRaven <hello@golfraven.example>",
      to: "player@example.com",
      confirmUrl: "https://golfraven.example/api/confirm?token=abc",
      unsubscribeUrl: "https://golfraven.example/api/unsubscribe?token=xyz",
    });
    expect(msg.headers?.["List-Unsubscribe"]).toBe("<https://golfraven.example/api/unsubscribe?token=xyz>");
    expect(msg.headers?.["List-Unsubscribe-Post"]).toBe("List-Unsubscribe=One-Click");
    expect(msg.html).toContain("https://golfraven.example/api/confirm?token=abc");
    expect(msg.html).toContain("https://golfraven.example/api/unsubscribe?token=xyz");
    expect(msg.to).toEqual(["player@example.com"]);
  });
});

describe("sendEmail / sendConfirmationEmail — Resend failure path", () => {
  it("returns ok:false (never a false success) when Resend rejects the request", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ message: "invalid from address" }), { status: 422 })),
    );
    const env = makeTestEnv();
    const result = await sendConfirmationEmail(env, {
      to: "player@example.com",
      confirmUrl: "https://golfraven.example/api/confirm?token=abc",
      unsubscribeUrl: "https://golfraven.example/api/unsubscribe?token=xyz",
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("invalid from address");
      expect(result.status).toBe(422);
    }
  });

  it("returns ok:false on a 2xx response missing a provider message id", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({}), { status: 200 })));
    const env = makeTestEnv();
    const result = await sendEmail(env, {
      from: "GolfRaven <hello@golfraven.example>",
      to: ["player@example.com"],
      subject: "hi",
      html: "<p>hi</p>",
    });
    expect(result.ok).toBe(false);
  });

  it("returns ok:false on a network error calling Resend", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      }),
    );
    const env = makeTestEnv();
    const result = await sendEmail(env, {
      from: "GolfRaven <hello@golfraven.example>",
      to: ["player@example.com"],
      subject: "hi",
      html: "<p>hi</p>",
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("network-error-calling-resend");
      expect(result.status).toBe("network-error");
    }
  });

  it("returns ok:true with the provider id only on a 2xx WITH an id", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ id: "re_123" }), { status: 200 })));
    const env = makeTestEnv();
    const result = await sendEmail(env, {
      from: "GolfRaven <hello@golfraven.example>",
      to: ["player@example.com"],
      subject: "hi",
      html: "<p>hi</p>",
    });
    expect(result).toEqual({ ok: true, providerId: "re_123" });
  });
});
