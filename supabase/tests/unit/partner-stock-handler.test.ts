// supabase/tests/unit/partner-stock-handler.test.ts
//
// The `stock-admin` handler and its strict shapes (docs/security/partner-auth-design.md 12, 28; slice S5, the Edge half of 0058), against an in-memory `PartnerDb`. What is decided HERE: the route table, the
// Origin / bearer / media-type / strict-body order, that every route is a session route, the status-to-HTTP map (a returned refusal is a status that COMMITS; a 42501 and a 22023 throw and ROLL BACK), and that
// the arguments reach the port exactly as validated. What is the DATABASE's (scope, class, row lock, never below zero, movement rows, availability): supabase/tests/matrix/36_partner_stock_handover.sql.

import { describe, expect, it } from "vitest";
import { handlePartnerStockRequest, STOCK_BUCKET, STOCK_PER_MEMBER_PER_HOUR, type PartnerStockDeps } from "../../functions/_shared/partner/stock-handler.ts";
import { parseStockMoveBody, parseStockQuery } from "../../functions/_shared/partner/stock-shape.ts";
import {
  type PartnerDb,
  type PartnerStockTx,
  PartnerAuthorityRefused,
  PartnerInvalidArgument,
  PartnerSessionRefused,
  type StockMoveResult,
  type StockRow,
} from "../../functions/_shared/partner/ports.ts";
import { fnReq, ORIGIN, SESSION_TOKEN, sha256Hex } from "./partner-fakes.ts";

const FN = "stock-admin";

interface World {
  calls: string[];
  committed: boolean[];
  rolledBack: boolean[];
  rate: Array<{ hash: string; bucket: string; windowSeconds: number; max: number }>;
  moves: Array<{ facilityId: string; trailId: string; kind: string; qty: number; note: string | null }>;
  reads: string[];
  result: StockMoveResult;
  rows: StockRow[];
  throwIn: "stockRead" | "stockMove" | null;
  throwWith: Error;
  rateOk: boolean;
  bindRefused: boolean;
}

const okMove: StockMoveResult = { status: "ok", onHand: 7, availability: "in_stock" };

function world(): { w: World; deps: PartnerStockDeps } {
  const w: World = {
    calls: [], committed: [], rolledBack: [], rate: [], moves: [], reads: [], result: okMove, throwIn: null, throwWith: new PartnerAuthorityRefused(), rateOk: true, bindRefused: false,
    rows: [{ trailId: "trl_t", onHand: 4, lowThreshold: 5, status: "low", lastCountedAt: "2030-01-01T12:00:00.000Z" }],
  };
  const tx: PartnerStockTx = {
    async stockRead(facilityId) {
      w.calls.push("tx.stockRead");
      w.reads.push(facilityId);
      if (w.throwIn === "stockRead") throw w.throwWith;
      return w.rows;
    },
    async stockMove(facilityId, trailId, kind, qty, note) {
      w.calls.push("tx.stockMove");
      w.moves.push({ facilityId, trailId, kind, qty, note });
      if (w.throwIn === "stockMove") throw w.throwWith;
      return w.result;
    },
  };
  const reject = () => Promise.reject(new Error("not used"));
  const db: PartnerDb = {
    withMint: reject,
    withInviteMint: reject,
    withSession: reject,
    withInvites: reject,
    withMembers: reject,
    withAttest: reject,
    withReview: reject,
    async withStock(_hash, op) {
      w.calls.push("db.withStock");
      if (w.bindRefused) throw new PartnerSessionRefused();
      try {
        const r = await op(tx);
        w.committed.push(true);
        return r;
      } catch (err) {
        w.rolledBack.push(true);
        throw err;
      }
    },
    withEntitlements: reject,
    async hitRateLimit(hash, bucket, windowSeconds, max) {
      w.calls.push("db.hitRateLimit");
      w.rate.push({ hash, bucket, windowSeconds, max });
      return w.rateOk ? { ok: true, retryAfterSeconds: 0 } : { ok: false, retryAfterSeconds: 3600 };
    },
    hitSystemRateLimit: reject,
  };
  return { w, deps: { db, allowedOrigin: ORIGIN } };
}

const auth = (extra: Record<string, string> = {}) => ({ origin: ORIGIN, authorization: `Bearer ${SESSION_TOKEN}`, ...extra });
const call = (deps: PartnerStockDeps, method: string, path: string, init: { headers?: Record<string, string>; body?: unknown; raw?: string } = {}) =>
  handlePartnerStockRequest(fnReq(FN, method, path, init), deps);

const MOVE = { facilityId: "fac_x", trailId: "trl_t", kind: "delivered", qty: 3 };
const ROUTES: Array<[string, string, unknown]> = [
  ["GET", "stock?facilityId=fac_x", undefined],
  ["POST", "stock/move", MOVE],
];

describe("routing, Origin, bearer and body order: every route is a session route", () => {
  it("OPTIONS from the allowed origin is 204 and touches NO port", async () => {
    const { w, deps } = world();
    for (const [, path] of ROUTES) {
      const res = await call(deps, "OPTIONS", path, { headers: { origin: ORIGIN, "access-control-request-method": "POST" } });
      expect(res.status, path).toBe(204);
    }
    expect(w.calls).toEqual([]);
  });

  it("a foreign Origin is 403 BEFORE routing, with no CORS header and no port touched", async () => {
    const { w, deps } = world();
    for (const [method, path, body] of ROUTES) {
      const res = await call(deps, method, path, { headers: { origin: "https://evil.example.test", authorization: `Bearer ${SESSION_TOKEN}` }, body });
      expect(res.status, `${method} ${path}`).toBe(403);
      expect(res.headers.get("access-control-allow-origin")).toBeNull();
    }
    expect(w.calls).toEqual([]);
  });

  it("no bearer, a Supabase-shaped JWT, another scheme and a malformed token are the ONE 401 on every route, with no port touched", async () => {
    const { w, deps } = world();
    const jwtShaped = ["aaa", "bbb", "ccc"].join(".");
    let first: string | null = null;
    for (const [method, path, body] of ROUTES) {
      for (const authorization of [undefined, `Bearer ${jwtShaped}`, `Basic ${SESSION_TOKEN}`, `Bearer ${SESSION_TOKEN}x`]) {
        const headers: Record<string, string> = { origin: ORIGIN };
        if (authorization !== undefined) headers.authorization = authorization;
        const res = await call(deps, method, path, { headers, body });
        expect(res.status, `${method} ${path} ${authorization}`).toBe(401);
        const t = await res.text();
        first ??= t;
        expect(t).toBe(first);
      }
    }
    expect(w.calls).toEqual([]);
  });

  it("an unknown route is 404 and a wrong method is 405 with Allow", async () => {
    const { deps } = world();
    expect((await call(deps, "POST", "nope", { headers: auth(), body: {} })).status).toBe(404);
    expect((await call(deps, "POST", "stock/delete", { headers: auth(), body: {} })).status).toBe(404);
    const post = await call(deps, "POST", "stock?facilityId=fac_x", { headers: auth(), body: {} });
    expect(post.status).toBe(405);
    expect(post.headers.get("allow")).toBe("GET");
    const get = await call(deps, "GET", "stock/move", { headers: auth() });
    expect(get.status).toBe(405);
    expect(get.headers.get("allow")).toBe("POST");
  });

  it("the exact JSON media type is required (415) before the body is read, and nothing reaches the database", async () => {
    const { w, deps } = world();
    const res = await call(deps, "POST", "stock/move", { headers: auth({ "content-type": "text/plain; x=application/json" }), raw: JSON.stringify(MOVE) });
    expect(res.status).toBe(415);
    expect(w.calls).toEqual([]);
  });
});

describe("strict bodies and queries: unknown keys and malformed values are 400, before any port", () => {
  const bad: Array<[string, unknown]> = [
    ["a stray key", { ...MOVE, entitlementId: "00000000-0000-0000-0000-00000000000b" }],
    ["a missing trail", { facilityId: "fac_x", kind: "delivered", qty: 3 }],
    ["redeemed (only the redeem path writes it)", { ...MOVE, kind: "redeemed" }],
    ["voucher_redeemed", { ...MOVE, kind: "voucher_redeemed" }],
    ["zero", { ...MOVE, qty: 0 }],
    ["a fraction", { ...MOVE, qty: 1.5 }],
    ["a string quantity", { ...MOVE, qty: "3" }],
    ["over the bound", { ...MOVE, qty: 100001 }],
    ["a negative delivery", { ...MOVE, qty: -3 }],
    ["a negative damaged", { ...MOVE, kind: "damaged", qty: -1 }],
    ["a bad facility", { ...MOVE, facilityId: "fac x" }],
    ["a bad trail", { ...MOVE, trailId: "trl/t" }],
    ["a note over 200", { ...MOVE, note: "x".repeat(201) }],
    ["a non-string note", { ...MOVE, note: 5 }],
  ];
  for (const [what, body] of bad) {
    it(`POST stock/move with ${what} is 400 and touches no port`, async () => {
      const { w, deps } = world();
      const res = await call(deps, "POST", "stock/move", { headers: auth(), body });
      expect(res.status).toBe(400);
      expect(w.calls).toEqual([]);
    });
  }
  it("a body that is not an object is 400", async () => {
    const { w, deps } = world();
    expect((await call(deps, "POST", "stock/move", { headers: auth(), body: [] })).status).toBe(400);
    expect(w.calls).toEqual([]);
  });
  for (const q of ["stock", "stock?facilityId=", "stock?facilityId=fac%20x", "stock?facilityId=fac_x&facilityId=fac_y", "stock?facilityId=fac_x&trail=trl_t"]) {
    it(`GET ${q} is 400 and touches no port`, async () => {
      const { w, deps } = world();
      const res = await call(deps, "GET", q, { headers: auth() });
      expect(res.status).toBe(400);
      expect(w.calls).toEqual([]);
    });
  }
  it("the shapes accept exactly what the database accepts: a signed count_adjustment, a null or absent note", () => {
    expect(parseStockMoveBody({ ...MOVE, kind: "count_adjustment", qty: -4 })).toEqual({ ok: true, value: { ...MOVE, kind: "count_adjustment", qty: -4, note: null } });
    expect(parseStockMoveBody({ ...MOVE, note: null })).toEqual({ ok: true, value: { ...MOVE, note: null } });
    expect(parseStockMoveBody({ ...MOVE, kind: "transfer_out", qty: 100000, note: "x".repeat(200) }).ok).toBe(true);
    expect(parseStockQuery("https://p.test/stock-admin/stock?facilityId=fac_x")).toEqual({ ok: true, value: { facilityId: "fac_x" } });
  });
});

describe("the bucket", () => {
  it("one per-member hit precedes the work, keyed on the token hash, in its own transaction before the request transaction opens", async () => {
    const { w, deps } = world();
    for (const [method, path, body] of ROUTES) {
      w.calls.length = 0;
      expect((await call(deps, method, path, { headers: auth(), body })).status).toBe(200);
      expect(w.calls[0], path).toBe("db.hitRateLimit");
      expect(w.calls[1], path).toBe("db.withStock");
    }
    expect(w.rate[0]).toEqual({ hash: await sha256Hex(SESSION_TOKEN), bucket: STOCK_BUCKET, windowSeconds: 3600, max: STOCK_PER_MEMBER_PER_HOUR });
  });

  it("an exhausted bucket is 429 with Retry-After and the work never opens", async () => {
    const { w, deps } = world();
    w.rateOk = false;
    for (const [method, path, body] of ROUTES) {
      const res = await call(deps, method, path, { headers: auth(), body });
      expect(res.status, path).toBe(429);
      expect(res.headers.get("retry-after")).toBe("3600");
    }
    expect(w.calls.filter((c) => c === "db.withStock")).toEqual([]);
  });
});

describe("GET stock", () => {
  it("returns the rows as the database gave them and passes the facility through", async () => {
    const { w, deps } = world();
    const res = await call(deps, "GET", "stock?facilityId=fac_x", { headers: auth() });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ data: { stock: [{ trailId: "trl_t", onHand: 4, lowThreshold: 5, status: "low", lastCountedAt: "2030-01-01T12:00:00.000Z" }] } });
    expect(w.reads).toEqual(["fac_x"]);
    expect(w.committed).toEqual([true]);
  });
});

describe("POST stock/move: the status map", () => {
  const cases: Array<[StockMoveResult, number, string | null]> = [
    [{ status: "ok", onHand: 7, availability: "in_stock" }, 200, null],
    [{ status: "no_stock_row", onHand: null, availability: null }, 422, "no_stock_row"],
    [{ status: "short", onHand: 2, availability: null }, 422, "short"],
    [{ status: "over_cap", onHand: 999999, availability: null }, 422, "over_cap"],
  ];
  for (const [result, http, code] of cases) {
    it(`${result.status} is ${http} and the transaction COMMITS`, async () => {
      const { w, deps } = world();
      w.result = result;
      const res = await call(deps, "POST", "stock/move", { headers: auth(), body: MOVE });
      expect(res.status).toBe(http);
      const body = (await res.json()) as { data?: unknown; error?: { code: string } };
      if (code === null) expect(body).toEqual({ data: { onHand: 7, availability: "in_stock" } });
      else expect(body.error?.code).toBe(code);
      expect(w.committed).toEqual([true]);
      expect(w.rolledBack).toEqual([]);
    });
  }

  it("the validated arguments reach the port as typed, a missing note as null", async () => {
    const { w, deps } = world();
    await call(deps, "POST", "stock/move", { headers: auth(), body: { ...MOVE, kind: "count_adjustment", qty: -2, note: "recount" } });
    await call(deps, "POST", "stock/move", { headers: auth(), body: MOVE });
    expect(w.moves).toEqual([
      { facilityId: "fac_x", trailId: "trl_t", kind: "count_adjustment", qty: -2, note: "recount" },
      { facilityId: "fac_x", trailId: "trl_t", kind: "delivered", qty: 3, note: null },
    ]);
  });
});

describe("thrown refusals roll back and map", () => {
  it("42501 (no scope, or no PIN grant) is 403, 22023 is 422, a refused bind is the ONE 401; each rolled back, none committed", async () => {
    for (const [throwWith, status] of [[new PartnerAuthorityRefused(), 403], [new PartnerInvalidArgument(), 422]] as const) {
      for (const [method, path, body, throwIn] of [["GET", "stock?facilityId=fac_x", undefined, "stockRead"], ["POST", "stock/move", MOVE, "stockMove"]] as const) {
        const { w, deps } = world();
        w.throwIn = throwIn;
        w.throwWith = throwWith;
        const res = await call(deps, method, path, { headers: auth(), body });
        expect(res.status, `${path} ${throwWith.name}`).toBe(status);
        expect(w.rolledBack).toEqual([true]);
        expect(w.committed).toEqual([]);
      }
    }
    const { w, deps } = world();
    w.bindRefused = true;
    expect((await call(deps, "POST", "stock/move", { headers: auth(), body: MOVE })).status).toBe(401);
    expect(w.committed).toEqual([]);
  });

  it("any other error is a constant 500 with no detail", async () => {
    const { w, deps } = world();
    w.throwIn = "stockMove";
    w.throwWith = new Error("secret database text");
    const res = await call(deps, "POST", "stock/move", { headers: auth(), body: MOVE });
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("secret");
  });
});
