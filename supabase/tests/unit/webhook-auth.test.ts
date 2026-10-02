// supabase/tests/unit/webhook-auth.test.ts
import { describe, expect, it } from "vitest";
import { buildWebhookSignatureHeader, isAcceptableWebhookSecret, verifyWebhookSignature } from "../../functions/_shared/catalog/webhook-auth.js";

const SECRET = "test-shared-secret-do-not-use-in-real-life";
const NOW = new Date("2026-09-25T12:00:00.000Z");

describe("verifyWebhookSignature", () => {
  it("accepts a freshly built, matching signature", async () => {
    const body = new TextEncoder().encode('{"catalogVersion":"20260925-abc1234"}');
    const header = await buildWebhookSignatureHeader(SECRET, body, NOW);
    const r = await verifyWebhookSignature({ secret: SECRET, headerValue: header, rawBody: body, now: NOW });
    expect(r.ok).toBe(true);
  });

  it("rejects a missing header (anonymous/no credential — task: 401)", async () => {
    const r = await verifyWebhookSignature({ secret: SECRET, headerValue: null, rawBody: new Uint8Array(), now: NOW });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("missing_header");
  });

  it("rejects a malformed header", async () => {
    const r = await verifyWebhookSignature({ secret: SECRET, headerValue: "not-the-right-shape", rawBody: new Uint8Array(), now: NOW });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("malformed_header");
  });

  it("rejects a signature computed with the WRONG secret", async () => {
    const body = new TextEncoder().encode("{}");
    const header = await buildWebhookSignatureHeader("a-different-secret", body, NOW);
    const r = await verifyWebhookSignature({ secret: SECRET, headerValue: header, rawBody: body, now: NOW });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("signature_mismatch");
  });

  it("rejects a body that was tampered with after signing", async () => {
    const original = new TextEncoder().encode('{"catalogVersion":"20260925-abc1234"}');
    const header = await buildWebhookSignatureHeader(SECRET, original, NOW);
    const tampered = new TextEncoder().encode('{"catalogVersion":"20260925-fffffff"}');
    const r = await verifyWebhookSignature({ secret: SECRET, headerValue: header, rawBody: tampered, now: NOW });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("signature_mismatch");
  });

  it("rejects a stale timestamp outside the tolerance window (replay defense)", async () => {
    const body = new TextEncoder().encode("{}");
    const signedAt = new Date(NOW.getTime() - 10 * 60 * 1000); // 10 minutes before "now"
    const header = await buildWebhookSignatureHeader(SECRET, body, signedAt);
    const r = await verifyWebhookSignature({ secret: SECRET, headerValue: header, rawBody: body, now: NOW, toleranceSeconds: 300 });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("clock_skew");
  });

  it("accepts a timestamp just inside the tolerance window", async () => {
    const body = new TextEncoder().encode("{}");
    const signedAt = new Date(NOW.getTime() - 4 * 60 * 1000); // 4 minutes before "now", tolerance 5 min
    const header = await buildWebhookSignatureHeader(SECRET, body, signedAt);
    const r = await verifyWebhookSignature({ secret: SECRET, headerValue: header, rawBody: body, now: NOW, toleranceSeconds: 300 });
    expect(r.ok).toBe(true);
  });
});

// P3e round 2 gate, LOW: "reject an HMAC secret that is empty,
// whitespace-only or shorter than 32 bytes."
describe("weak webhook secrets are refused outright", () => {
  it.each([["empty", ""], ["whitespace-only", "                                      "], ["31 bytes", "x".repeat(31)]])("%s secret -> weak_secret even with an otherwise-correct signature", async (_label, weak) => {
    const body = new TextEncoder().encode("{}");
    const header = await buildWebhookSignatureHeader(weak || "placeholder", body, NOW);
    const r = await verifyWebhookSignature({ secret: weak, headerValue: header, rawBody: body, now: NOW });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("weak_secret");
  });

  it("a 32-byte secret is accepted", async () => {
    const secret = "x".repeat(32);
    const body = new TextEncoder().encode("{}");
    const header = await buildWebhookSignatureHeader(secret, body, NOW);
    expect((await verifyWebhookSignature({ secret, headerValue: header, rawBody: body, now: NOW })).ok).toBe(true);
    expect(isAcceptableWebhookSecret(secret)).toBe(true);
    expect(isAcceptableWebhookSecret("x".repeat(31))).toBe(false);
  });
});
