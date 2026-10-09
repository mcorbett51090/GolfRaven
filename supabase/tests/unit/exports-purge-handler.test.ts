// supabase/tests/unit/exports-purge-handler.test.ts
//
// Pure core of `exports-purge` (AT(17); P5.1b). Storage is a port; auth / rate-limit order mirrors retention-purge.

import { describe, expect, it } from "vitest";
import {
  EXPORTS_PURGE_RATE_BUCKET,
  EXPORTS_PURGE_RATE_MAX_PER_WINDOW,
  EXPORTS_PURGE_RATE_WINDOW_SECONDS,
  EXPORTS_RETENTION_MS,
  handleExportsPurgeRequest,
  type ExportsPurgeDeps,
} from "../../functions/_shared/exports/purge-handler.ts";
import type { ExportsStoragePort } from "../../functions/_shared/partner/ports.ts";

const GOOD = { authorization: "Bearer scheduler-key" };
const post = (headers: Record<string, string> = {}) => new Request("https://x.test/exports-purge", { method: "POST", headers });

function probe(over: Partial<ExportsPurgeDeps> & { purged?: number; throwPurge?: Error } = {}) {
  const calls: string[] = [];
  const rate: Array<[string, number, number]> = [];
  const logs: Array<Record<string, unknown>> = [];
  const clock = { now: 1_000_000_000_000 };
  const storage: ExportsStoragePort = {
    putSigned: async () => {
      throw new Error("not used");
    },
    async purgeOlderThan(olderThanMs) {
      calls.push(`purge:${olderThanMs}`);
      if (over.throwPurge) throw over.throwPurge;
      return over.purged ?? 3;
    },
  };
  const deps: ExportsPurgeDeps = {
    isAuthorized: (req) => req.headers.get("authorization") === GOOD.authorization,
    hitRateLimit: async (k, w, m) => {
      rate.push([k, w, m]);
      return { ok: true, count: 1 };
    },
    storage,
    nowMs: () => clock.now,
    log: (e) => logs.push(e),
    ...over,
  };
  return { deps, calls, rate, logs, clock };
}

describe("exports-purge handler", () => {
  it("only POST; unauthenticated is 401 before rate limit and storage", async () => {
    const p = probe();
    const get = await handleExportsPurgeRequest(new Request("https://x.test/exports-purge", { method: "GET" }), p.deps);
    expect(get.status).toBe(405);
    expect(p.rate).toEqual([]);
    expect(p.calls).toEqual([]);

    const unauth = await handleExportsPurgeRequest(post(), p.deps);
    expect(unauth.status).toBe(401);
    expect(p.rate).toEqual([]);
    expect(p.calls).toEqual([]);
  });

  it("rate-limits then purges objects older than 7 days (AT(17))", async () => {
    const p = probe({ purged: 4 });
    const res = await handleExportsPurgeRequest(post(GOOD), p.deps);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ purged: 4, complete: true });
    expect(p.rate).toEqual([[EXPORTS_PURGE_RATE_BUCKET, EXPORTS_PURGE_RATE_WINDOW_SECONDS, EXPORTS_PURGE_RATE_MAX_PER_WINDOW]]);
    expect(p.calls).toEqual([`purge:${p.clock.now - EXPORTS_RETENTION_MS}`]);
    expect(p.logs[0]).toMatchObject({ event: "exports_purge", purged: 4, complete: true });
  });

  it("429 when the system bucket is full; 500 on storage failure", async () => {
    const limited = probe({
      hitRateLimit: async () => ({ ok: false, count: 99, retryAfterSeconds: 99 }),
    });
    const r1 = await handleExportsPurgeRequest(post(GOOD), limited.deps);
    expect(r1.status).toBe(429);
    expect(limited.calls).toEqual([]);

    const failed = probe({ throwPurge: new Error("storage down") });
    const r2 = await handleExportsPurgeRequest(post(GOOD), failed.deps);
    expect(r2.status).toBe(500);
    expect((await r2.json()).error.code).toBe("exports_purge_failed");
  });
});
