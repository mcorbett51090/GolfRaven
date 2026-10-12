// supabase/tests/unit/receipts-purge-handler.test.ts
//
// Pure core of `receipts-purge` (§42). Storage is a port; auth / rate-limit order mirrors exports-purge.

import { describe, expect, it } from "vitest";
import {
  RECEIPTS_PURGE_RATE_BUCKET,
  RECEIPTS_PURGE_RATE_MAX_PER_WINDOW,
  RECEIPTS_PURGE_RATE_WINDOW_SECONDS,
  RECEIPTS_RETENTION_MS,
  handleReceiptsPurgeRequest,
  type ReceiptsPurgeDeps,
} from "../../functions/_shared/receipts/purge-handler.ts";

const GOOD = { authorization: "Bearer scheduler-key" };
const post = (headers: Record<string, string> = {}) => new Request("https://x.test/receipts-purge", { method: "POST", headers });

function probe(over: Partial<ReceiptsPurgeDeps> & { purged?: number; throwPurge?: Error } = {}) {
  const calls: string[] = [];
  const rate: Array<[string, number, number]> = [];
  const logs: Array<Record<string, unknown>> = [];
  const clock = { now: 1_000_000_000_000 };
  const deps: ReceiptsPurgeDeps = {
    isAuthorized: (req) => req.headers.get("authorization") === GOOD.authorization,
    hitRateLimit: async (k, w, m) => {
      rate.push([k, w, m]);
      return { ok: true, count: 1 };
    },
    storage: {
      async purgeOlderThan(olderThanMs) {
        calls.push(`purge:${olderThanMs}`);
        if (over.throwPurge) throw over.throwPurge;
        return over.purged ?? 3;
      },
    },
    nowMs: () => clock.now,
    log: (e) => logs.push(e),
    ...over,
  };
  return { deps, calls, rate, logs, clock };
}

describe("receipts-purge handler", () => {
  it("only POST; unauthenticated is 401 before rate limit and storage", async () => {
    const p = probe();
    const get = await handleReceiptsPurgeRequest(new Request("https://x.test/receipts-purge", { method: "GET" }), p.deps);
    expect(get.status).toBe(405);
    expect(p.rate).toEqual([]);
    expect(p.calls).toEqual([]);

    const unauth = await handleReceiptsPurgeRequest(post(), p.deps);
    expect(unauth.status).toBe(401);
    expect(p.rate).toEqual([]);
    expect(p.calls).toEqual([]);
  });

  it("rate-limits then purges objects older than 90 days", async () => {
    const p = probe({ purged: 4 });
    const res = await handleReceiptsPurgeRequest(post(GOOD), p.deps);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ data: { purged: 4, complete: true } });
    expect(p.rate).toEqual([[RECEIPTS_PURGE_RATE_BUCKET, RECEIPTS_PURGE_RATE_WINDOW_SECONDS, RECEIPTS_PURGE_RATE_MAX_PER_WINDOW]]);
    expect(p.calls).toEqual([`purge:${p.clock.now - RECEIPTS_RETENTION_MS}`]);
    expect(p.logs[0]).toMatchObject({ event: "receipts_purge", purged: 4 });
  });

  it("429 when the system bucket is full; 500 on storage failure", async () => {
    const limited = probe({
      hitRateLimit: async () => ({ ok: false, count: 99, retryAfterSeconds: 99 }),
    });
    const r1 = await handleReceiptsPurgeRequest(post(GOOD), limited.deps);
    expect(r1.status).toBe(429);
    expect(limited.calls).toEqual([]);

    const failed = probe({ throwPurge: new Error("storage down") });
    const r2 = await handleReceiptsPurgeRequest(post(GOOD), failed.deps);
    expect(r2.status).toBe(500);
    expect((await r2.json()).error.code).toBe("receipts_purge_failed");
  });
});
