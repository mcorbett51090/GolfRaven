import { beforeEach, describe, expect, it } from "vitest";
import { handleConfirmPage, handleConfirmSubmit } from "../src/index";
import { hashWithPepper, isoTimeFromNow } from "../src/tokens";
import { makeTestEnv } from "./env";

const RAW_TOKEN = "test-confirm-token-value";

async function seedPendingRow(env: ReturnType<typeof makeTestEnv>, overrides: Partial<{ expiresInSeconds: number; alreadyConfirmed: string | null }> = {}) {
  const hash = await hashWithPepper(env.TOKEN_PEPPER, RAW_TOKEN);
  env.DB.rows.push({
    id: "row-1",
    email_lc: "player@example.com",
    consent_version: "2026-09-23",
    age_confirmed: 1,
    source: null,
    created_at: new Date().toISOString(),
    confirmed_at: overrides.alreadyConfirmed ?? null,
    unsubscribed_at: null,
    confirm_token_hash: hash,
    confirm_expires_at: isoTimeFromNow(overrides.expiresInSeconds ?? 3600),
    unsubscribe_token_hash: "unrelated-unsub-hash",
  });
}

function confirmGetRequest(token: string): Request {
  return new Request(`https://golfraven.example/api/confirm?token=${encodeURIComponent(token)}`, { method: "GET" });
}
function confirmPostRequest(token: string): Request {
  return new Request(`https://golfraven.example/api/confirm?token=${encodeURIComponent(token)}`, { method: "POST" });
}

describe("GET /api/confirm — never confirms", () => {
  let env: ReturnType<typeof makeTestEnv>;
  beforeEach(async () => {
    env = makeTestEnv();
    await seedPendingRow(env);
  });

  it("renders the confirm prompt page without touching confirmed_at", async () => {
    const res = await handleConfirmPage(confirmGetRequest(RAW_TOKEN), env);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("<form");
    expect(html.toLowerCase()).toContain("confirm");
    expect(env.DB.rows[0]?.confirmed_at).toBeNull();
  });

  it("400s with no token", async () => {
    const res = await handleConfirmPage(new Request("https://golfraven.example/api/confirm", { method: "GET" }), env);
    expect(res.status).toBe(400);
  });
});

describe("POST /api/confirm — confirms exactly once, then is idempotent", () => {
  it("sets confirmed_at on first confirm and shows the success page", async () => {
    const env = makeTestEnv();
    await seedPendingRow(env);
    const res = await handleConfirmSubmit(confirmPostRequest(RAW_TOKEN), env);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html.toLowerCase()).toContain("confirmed");
    expect(env.DB.rows[0]?.confirmed_at).not.toBeNull();
  });

  it("is single-use (F4): a second POST with the same token shows the generic invalid/already-used page and does not change confirmed_at", async () => {
    const env = makeTestEnv();
    await seedPendingRow(env);
    await handleConfirmSubmit(confirmPostRequest(RAW_TOKEN), env);
    const firstConfirmedAt = env.DB.rows[0]?.confirmed_at;
    expect(env.DB.rows[0]?.confirm_token_hash).toBeNull(); // cleared on success (F4)

    const res2 = await handleConfirmSubmit(confirmPostRequest(RAW_TOKEN), env);
    expect(res2.status).toBe(400);
    const html2 = await res2.text();
    expect(html2.toLowerCase()).toContain("already used");
    expect(env.DB.rows[0]?.confirmed_at).toBe(firstConfirmedAt);
  });

  it("a used link cannot be replayed to re-subscribe after an unsubscribe (F4 — closes the reuse hole)", async () => {
    const env = makeTestEnv();
    await seedPendingRow(env);
    await handleConfirmSubmit(confirmPostRequest(RAW_TOKEN), env);
    // Simulate the address unsubscribing afterward.
    env.DB.rows[0]!.unsubscribed_at = "2026-02-01T00:00:00.000Z";

    const replay = await handleConfirmSubmit(confirmPostRequest(RAW_TOKEN), env);
    expect(replay.status).toBe(400);
    // The old link must NOT have cleared unsubscribed_at.
    expect(env.DB.rows[0]?.unsubscribed_at).toBe("2026-02-01T00:00:00.000Z");
  });

  it("re-opens a previously-unsubscribed row without moving the original confirmed_at", async () => {
    const env = makeTestEnv();
    const originalConfirmedAt = "2026-01-01T00:00:00.000Z";
    await seedPendingRow(env, { alreadyConfirmed: originalConfirmedAt });
    env.DB.rows[0]!.unsubscribed_at = "2026-02-01T00:00:00.000Z";

    const res = await handleConfirmSubmit(confirmPostRequest(RAW_TOKEN), env);
    expect(res.status).toBe(200);
    expect(env.DB.rows[0]?.unsubscribed_at).toBeNull();
    expect(env.DB.rows[0]?.confirmed_at).toBe(originalConfirmedAt);
  });

  it("shows the generic invalid/expired page for an unknown token", async () => {
    const env = makeTestEnv();
    await seedPendingRow(env);
    const res = await handleConfirmSubmit(confirmPostRequest("wrong-token"), env);
    expect(res.status).toBe(400);
    expect(env.DB.rows[0]?.confirmed_at).toBeNull();
  });

  it("shows the generic invalid/expired page for an expired token, without confirming", async () => {
    const env = makeTestEnv();
    await seedPendingRow(env, { expiresInSeconds: -1 });
    const res = await handleConfirmSubmit(confirmPostRequest(RAW_TOKEN), env);
    expect(res.status).toBe(400);
    expect(env.DB.rows[0]?.confirmed_at).toBeNull();
  });

  it("400s with no token", async () => {
    const env = makeTestEnv();
    const res = await handleConfirmSubmit(new Request("https://golfraven.example/api/confirm", { method: "POST" }), env);
    expect(res.status).toBe(400);
  });
});
