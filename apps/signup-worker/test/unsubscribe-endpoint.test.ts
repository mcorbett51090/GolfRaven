import { describe, expect, it } from "vitest";
import { handleUnsubscribePage, handleUnsubscribeSubmit } from "../src/index";
import { hashWithPepper } from "../src/tokens";
import { makeTestEnv } from "./env";

const RAW_TOKEN = "test-unsubscribe-token-value";

async function seedConfirmedRow(env: ReturnType<typeof makeTestEnv>) {
  const hash = await hashWithPepper(env.TOKEN_PEPPER, RAW_TOKEN);
  env.DB.rows.push({
    id: "row-1",
    email_lc: "player@example.com",
    consent_version: "2026-09-23",
    age_confirmed: 1,
    source: null,
    created_at: new Date().toISOString(),
    confirmed_at: new Date().toISOString(),
    unsubscribed_at: null,
    confirm_token_hash: null,
    confirm_expires_at: null,
    unsubscribe_token_hash: hash,
    unsubscribe_token_hash_prev: null,
  });
}

function unsubGetRequest(token: string): Request {
  return new Request(
    `https://golfraven.example/api/unsubscribe?token=${encodeURIComponent(token)}`,
    {
      method: "GET",
    },
  );
}
function unsubPostRequest(token: string): Request {
  return new Request(
    `https://golfraven.example/api/unsubscribe?token=${encodeURIComponent(token)}`,
    {
      method: "POST",
    },
  );
}

describe("GET /api/unsubscribe", () => {
  it("renders a page with a button, and does not unsubscribe", async () => {
    const env = makeTestEnv();
    await seedConfirmedRow(env);
    const res = await handleUnsubscribePage(unsubGetRequest(RAW_TOKEN), env);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("<form");
    expect(env.DB.rows[0]?.unsubscribed_at).toBeNull();
  });
});

describe("POST /api/unsubscribe — one-click (RFC 8058)", () => {
  it("unsubscribes with a bare POST and no request body — the mail-client one-click shape", async () => {
    const env = makeTestEnv();
    await seedConfirmedRow(env);
    const res = await handleUnsubscribeSubmit(unsubPostRequest(RAW_TOKEN), env);
    expect(res.status).toBe(200);
    expect(env.DB.rows[0]?.unsubscribed_at).not.toBeNull();
  });

  it("is idempotent: a second POST does not error or change the timestamp", async () => {
    const env = makeTestEnv();
    await seedConfirmedRow(env);
    await handleUnsubscribeSubmit(unsubPostRequest(RAW_TOKEN), env);
    const firstUnsubscribedAt = env.DB.rows[0]?.unsubscribed_at;

    const res2 = await handleUnsubscribeSubmit(
      unsubPostRequest(RAW_TOKEN),
      env,
    );
    expect(res2.status).toBe(200);
    expect(env.DB.rows[0]?.unsubscribed_at).toBe(firstUnsubscribedAt);
  });

  it("shows a generic invalid message for an unknown token", async () => {
    const env = makeTestEnv();
    await seedConfirmedRow(env);
    const res = await handleUnsubscribeSubmit(
      unsubPostRequest("wrong-token"),
      env,
    );
    expect(res.status).toBe(400);
    expect(env.DB.rows[0]?.unsubscribed_at).toBeNull();
  });

  it("400s with no token", async () => {
    const env = makeTestEnv();
    const res = await handleUnsubscribeSubmit(
      new Request("https://golfraven.example/api/unsubscribe", {
        method: "POST",
      }),
      env,
    );
    expect(res.status).toBe(400);
  });
});
