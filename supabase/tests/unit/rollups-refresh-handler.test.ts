// supabase/tests/unit/rollups-refresh-handler.test.ts
//
// Pure core of `rollups-refresh` (§41). DB is a port; auth / rate-limit order mirrors exports-purge.

import { describe, expect, it } from "vitest";
import {
  handleRollupsRefreshRequest,
  ROLLUPS_REFRESH_RATE_BUCKET,
  ROLLUPS_REFRESH_RATE_MAX_PER_WINDOW,
  ROLLUPS_REFRESH_RATE_WINDOW_SECONDS,
  type RollupsRefreshDeps,
  type RollupsRefreshResult,
} from "../../functions/_shared/rollups/refresh-handler.ts";

const GOOD = { authorization: "Bearer scheduler-key" };
const post = (headers: Record<string, string> = {}, body?: string) =>
  new Request("https://x.test/rollups-refresh", { method: "POST", headers, body });

function probe(over: Partial<RollupsRefreshDeps> & { result?: RollupsRefreshResult; throwRefresh?: Error } = {}) {
  const calls: Array<string | null> = [];
  const rate: Array<[string, number, number]> = [];
  const logs: Array<Record<string, unknown>> = [];
  const deps: RollupsRefreshDeps = {
    isAuthorized: (req) => req.headers.get("authorization") === GOOD.authorization,
    hitRateLimit: async (k, w, m) => {
      rate.push([k, w, m]);
      return { ok: true, count: 1 };
    },
    refresh: async (month) => {
      calls.push(month);
      if (over.throwRefresh) throw over.throwRefresh;
      return (
        over.result ?? {
          operatorWritten: 2,
          operatorRemoved: 1,
          sponsorWritten: 1,
          sponsorRemoved: 0,
          month: month ?? "2026-10-01",
        }
      );
    },
    log: (e) => logs.push(e),
    ...over,
  };
  return { deps, calls, rate, logs };
}

describe("rollups-refresh handler", () => {
  it("only POST; unauthenticated is 401 before rate limit and refresh", async () => {
    const p = probe();
    const get = await handleRollupsRefreshRequest(new Request("https://x.test/rollups-refresh", { method: "GET" }), p.deps);
    expect(get.status).toBe(405);
    expect(p.rate).toEqual([]);
    expect(p.calls).toEqual([]);

    const unauth = await handleRollupsRefreshRequest(post(), p.deps);
    expect(unauth.status).toBe(401);
    expect(p.rate).toEqual([]);
    expect(p.calls).toEqual([]);
  });

  it("rate-limits then refreshes the current month when the body is empty", async () => {
    const p = probe();
    const res = await handleRollupsRefreshRequest(post(GOOD), p.deps);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      data: {
        month: "2026-10-01",
        operatorWritten: 2,
        operatorRemoved: 1,
        sponsorWritten: 1,
        sponsorRemoved: 0,
        complete: true,
      },
    });
    expect(p.rate).toEqual([[ROLLUPS_REFRESH_RATE_BUCKET, ROLLUPS_REFRESH_RATE_WINDOW_SECONDS, ROLLUPS_REFRESH_RATE_MAX_PER_WINDOW]]);
    expect(p.calls).toEqual([null]);
    expect(p.logs[0]).toMatchObject({ event: "rollups_refresh", operatorWritten: 2 });
  });

  it("accepts YYYY-MM-01 and refuses other bodies", async () => {
    const p = probe({
      result: {
        operatorWritten: 0,
        operatorRemoved: 0,
        sponsorWritten: 0,
        sponsorRemoved: 0,
        month: "2026-09-01",
      },
    });
    const ok = await handleRollupsRefreshRequest(post(GOOD, JSON.stringify({ month: "2026-09-01" })), p.deps);
    expect(ok.status).toBe(200);
    expect(p.calls).toEqual(["2026-09-01"]);

    const bad = await handleRollupsRefreshRequest(post(GOOD, JSON.stringify({ month: "2026-09-15" })), p.deps);
    expect(bad.status).toBe(400);
  });

  it("429 when the system bucket is full; 500 on refresh failure", async () => {
    const limited = probe({
      hitRateLimit: async () => ({ ok: false, count: 99, retryAfterSeconds: 99 }),
    });
    const r1 = await handleRollupsRefreshRequest(post(GOOD), limited.deps);
    expect(r1.status).toBe(429);
    expect(limited.calls).toEqual([]);

    const failed = probe({ throwRefresh: Object.assign(new Error("db"), { code: "57014" }) });
    const r2 = await handleRollupsRefreshRequest(post(GOOD), failed.deps);
    expect(r2.status).toBe(500);
    expect((await r2.json()).error.code).toBe("rollups_refresh_failed");
  });
});
