import { describe, expect, it } from "vitest";
import type { D1Like, D1PreparedLike, Env } from "../src/config";
import worker from "../src/index";
import { FakeKV } from "./fakes";

/** A D1Like whose every method rejects — simulates "D1 down" (F3 probe). */
class ThrowingD1 implements D1Like {
  prepare(_sql: string): D1PreparedLike {
    const self: D1PreparedLike = {
      bind() {
        return self;
      },
      async run() {
        throw new Error("D1 down");
      },
      async first() {
        throw new Error("D1 down");
      },
      async all() {
        throw new Error("D1 down");
      },
    };
    return self;
  }
}

function makeCtx() {
  const waited: Promise<unknown>[] = [];
  return {
    ctx: {
      waitUntil: (p: Promise<unknown>) => {
        waited.push(p);
      },
    },
    flush: () => Promise.all(waited),
  };
}

function baseEnv(overrides: Partial<Env> = {}): Env {
  return {
    DB: new ThrowingD1(),
    RATE_LIMIT_KV: new FakeKV(),
    RESEND_API_KEY: "test-resend-key",
    TURNSTILE_SECRET: "test-turnstile-secret",
    TOKEN_PEPPER: "p".repeat(40), // >= the 32-char minimum (gate finding F-N6); runtime-built, see test/env.ts
    RESEND_FROM_EMAIL: "GolfRaven <hello@golfraven.example>",
    PUBLIC_BASE_URL: "https://golfraven.example",
    ALLOWED_DEV_ORIGINS: "",
    ...overrides,
  };
}

describe("default export fetch — router-level error handling (F3)", () => {
  it("a rejected handler promise is caught (return await) — a JSON 500, not an uncaught exception", async () => {
    const env = baseEnv();
    const { ctx } = makeCtx();
    const res = await worker.fetch(
      new Request("https://golfraven.example/api/confirm?token=abc", {
        method: "POST",
      }),
      env,
      ctx,
    );
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body).toEqual({ status: "error", error: "internal error" });
  });
});

describe("default export fetch — required secrets present (F13)", () => {
  it("500s when a required secret is empty, without reaching a handler at all", async () => {
    const env = baseEnv({ TOKEN_PEPPER: "" });
    const { ctx } = makeCtx();
    const res = await worker.fetch(
      new Request("https://golfraven.example/api/confirm?token=abc", {
        method: "GET",
      }),
      env,
      ctx,
    );
    expect(res.status).toBe(500);
  });

  it("500s when TOKEN_PEPPER is shorter than the minimum length", async () => {
    const env = baseEnv({ TOKEN_PEPPER: "short" });
    const { ctx } = makeCtx();
    const res = await worker.fetch(
      new Request("https://golfraven.example/api/confirm?token=abc", {
        method: "GET",
      }),
      env,
      ctx,
    );
    expect(res.status).toBe(500);
  });

  it("gate finding F-N6: 500s when TOKEN_PEPPER_PREVIOUS is set but shorter than the minimum length", async () => {
    const env = baseEnv({ TOKEN_PEPPER_PREVIOUS: "short" });
    const { ctx } = makeCtx();
    const res = await worker.fetch(
      new Request("https://golfraven.example/api/confirm?token=abc", {
        method: "GET",
      }),
      env,
      ctx,
    );
    expect(res.status).toBe(500);
  });
});

describe("default export fetch — unknown routes", () => {
  it("404s", async () => {
    const env = baseEnv();
    const { ctx } = makeCtx();
    const res = await worker.fetch(
      new Request("https://golfraven.example/nope", { method: "GET" }),
      env,
      ctx,
    );
    expect(res.status).toBe(404);
  });
});
