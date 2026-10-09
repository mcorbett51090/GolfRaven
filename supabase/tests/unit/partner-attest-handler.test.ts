// supabase/tests/unit/partner-attest-handler.test.ts
//
// The `partner-attest` handler and its strict shapes (docs/security/partner-auth-design.md 26; AT(1), AT(2), AT(12), AT(13), AT(16); slice S3, the Edge half of 0056), against an in-memory `PartnerDb`. What is decided
// HERE: the route table, the Origin / bearer / media-type / strict-body order, that every route is a session route, the status-to-HTTP map (a returned refusal is a status that COMMITS; a 42501 and a 22023 throw and
// roll back), that no response names a seed, an expected code, a device or which check failed, that the six digits and the handle reach the database as typed and nothing else is computed here, and the reads' queries.
// What is the DATABASE's (scope, class, self-attest, replay, same-device, cold-start cap, the failure counters, the verification itself): supabase/tests/matrix/34_partner_attest_redeem.sql.

import { describe, expect, it } from "vitest";
import { ATTEST_BUCKET, ATTEST_PER_MEMBER_PER_HOUR, handlePartnerAttestRequest, type PartnerAttestDeps } from "../../functions/_shared/partner/attest-handler.ts";
import { parseOfflineAttestBody, parseOnlineAttestBody, parseShiftLogQuery, parseStaffActivityQuery } from "../../functions/_shared/partner/attest-shape.ts";
import {
  type AttestResult,
  type AttestStatus,
  type PartnerAttestTx,
  type PartnerDb,
  PartnerAuthorityRefused,
  PartnerInvalidArgument,
  PartnerSessionRefused,
  type ShiftLogRow,
  type StaffActivityRow,
} from "../../functions/_shared/partner/ports.ts";
import { fnReq, ORIGIN, SESSION_TOKEN, sha256Hex } from "./partner-fakes.ts";

const FN = "partner-attest";
const TOKEN = "34200000-0000-0000-0000-000000000001";

interface World {
  calls: string[];
  committed: boolean[];
  rate: Array<{ hash: string; bucket: string; windowSeconds: number; max: number }>;
  online: Array<{ facilityId: string; kind: string; token: string }>;
  offline: Array<{ facilityId: string; kind: string; handle: string; code: string }>;
  reads: Array<{ what: string; facilityId: string; days?: number }>;
  result: AttestResult;
  throwIn: "attest" | "offlineAttest" | "shiftLog" | "staffActivity" | null;
  throwWith: Error;
  rateOk: boolean;
  bindRefused: boolean;
  shiftLog: ShiftLogRow[];
  activity: StaffActivityRow[];
}

const okResult: AttestResult = { status: "ok", attestationId: "11111111-1111-1111-1111-111111111111", held: false };

function world(): { w: World; deps: PartnerAttestDeps } {
  const w: World = {
    calls: [], committed: [], rate: [], online: [], offline: [], reads: [], result: okResult, throwIn: null, throwWith: new PartnerAuthorityRefused(), rateOk: true, bindRefused: false,
    shiftLog: [{ id: "22222222-2222-2222-2222-222222222222", facilityId: "fac_x", createdAt: "2030-01-01T12:00:00.000Z", kind: "presence", playerHandle: "player_a", staffHandle: "staff_x" }],
    activity: [{ staffUserId: "33333333-3333-3333-3333-333333333333", facilityId: "fac_x", day: "2030-01-01", attests: 3, activations: 0, anomalies: [] }],
  };
  const tx: PartnerAttestTx = {
    async attest(facilityId, kind, token) {
      w.calls.push("tx.attest");
      w.online.push({ facilityId, kind, token });
      if (w.throwIn === "attest") throw w.throwWith;
      return w.result;
    },
    async offlineAttest(facilityId, kind, handle, code) {
      w.calls.push("tx.offlineAttest");
      w.offline.push({ facilityId, kind, handle, code });
      if (w.throwIn === "offlineAttest") throw w.throwWith;
      return w.result;
    },
    async shiftLog(facilityId) {
      w.calls.push("tx.shiftLog");
      w.reads.push({ what: "shiftLog", facilityId });
      if (w.throwIn === "shiftLog") throw w.throwWith;
      return w.shiftLog;
    },
    async staffActivity(facilityId, days) {
      w.calls.push("tx.staffActivity");
      w.reads.push({ what: "staffActivity", facilityId, days });
      if (w.throwIn === "staffActivity") throw w.throwWith;
      return w.activity;
    },
  };
  const reject = () => Promise.reject(new Error("not used"));
  const db: PartnerDb = {
    withMint: reject,
    withInviteMint: reject,
    withSession: reject,
    withInvites: reject,
    withMembers: reject,
    async withAttest(_hash, op) {
      w.calls.push("db.withAttest");
      if (w.bindRefused) throw new PartnerSessionRefused();
      const r = await op(tx);
      w.committed.push(true);
      return r;
    },
    withReview: reject,
    withStock: reject,
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
const call = (deps: PartnerAttestDeps, method: string, path: string, init: { headers?: Record<string, string>; body?: unknown; raw?: string } = {}) =>
  handlePartnerAttestRequest(fnReq(FN, method, path, init), deps);

const ROUTES: Array<[string, string, unknown]> = [
  ["POST", "attest", { facilityId: "fac_x", kind: "presence", token: TOKEN }],
  ["POST", "attest/offline", { facilityId: "fac_x", kind: "presence", handle: "player_a", code: "123456" }],
  ["GET", "shift-log?facilityId=fac_x", undefined],
  ["GET", "staff-activity?facilityId=fac_x&days=7", undefined],
];

describe("routing, Origin, bearer and body order: every route is a session route", () => {
  it("OPTIONS from the allowed origin is 204 and touches NO port (PA-10)", async () => {
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
    expect((await call(deps, "POST", "attest/online", { headers: auth(), body: {} })).status).toBe(404);
    const get = await call(deps, "GET", "attest", { headers: auth() });
    expect(get.status).toBe(405);
    expect(get.headers.get("allow")).toBe("POST");
    const post = await call(deps, "POST", "shift-log?facilityId=fac_x", { headers: auth(), body: {} });
    expect(post.status).toBe(405);
    expect(post.headers.get("allow")).toBe("GET");
  });

  it("the exact JSON media type is required (415) before the body is read, and nothing reaches the database", async () => {
    const { w, deps } = world();
    const res = await call(deps, "POST", "attest", { headers: auth({ "content-type": "text/plain; x=application/json" }), raw: JSON.stringify(ROUTES[0]![2]) });
    expect(res.status).toBe(415);
    expect(w.calls).toEqual([]);
  });
});

describe("strict bodies: unknown keys and malformed values are 400, before any port", () => {
  const bad: Array<[string, unknown]> = [
    ["attest", { facilityId: "fac_x", kind: "presence", token: TOKEN, playerId: "00000000-0000-0000-0000-00000000000b" }],
    ["attest", { facilityId: "fac_x", kind: "presence" }],
    ["attest", { facilityId: "fac_x", kind: "offer_redemption", token: TOKEN }],
    ["attest", { facilityId: "fac_x", kind: "presence", token: "not-a-uuid" }],
    ["attest", { facilityId: "fac x", kind: "presence", token: TOKEN }],
    ["attest", { facilityId: "fac_x", kind: "presence", token: TOKEN.toUpperCase().slice(0, 35) }],
    ["attest", []],
    ["attest/offline", { facilityId: "fac_x", kind: "presence", handle: "player_a", code: "12345" }],
    ["attest/offline", { facilityId: "fac_x", kind: "presence", handle: "player_a", code: "1234567" }],
    ["attest/offline", { facilityId: "fac_x", kind: "presence", handle: "player_a", code: "12345a" }],
    ["attest/offline", { facilityId: "fac_x", kind: "presence", handle: "player_a", code: 123456 }],
    ["attest/offline", { facilityId: "fac_x", kind: "presence", handle: "pl", code: "123456" }],
    ["attest/offline", { facilityId: "fac_x", kind: "presence", handle: "player a", code: "123456" }],
    ["attest/offline", { facilityId: "fac_x", kind: "presence", handle: "player_a", code: "123456", seed: "00" }],
    ["attest/offline", { facilityId: "fac_x", kind: "presence", handle: "player_a", code: "123456", expected: "123456" }],
    ["attest/offline", { facilityId: "fac_x", kind: "presence", code: "123456" }],
  ];
  for (const [path, body] of bad) {
    it(`POST ${path} ${JSON.stringify(body)} is 400 and touches no port`, async () => {
      const { w, deps } = world();
      const res = await call(deps, "POST", path, { headers: auth(), body });
      expect(res.status).toBe(400);
      expect(w.calls).toEqual([]);
    });
  }
  it("the offline body: a typed handle is trimmed and lower-cased; the code is passed as typed", async () => {
    const { w, deps } = world();
    const res = await call(deps, "POST", "attest/offline", { headers: auth(), body: { facilityId: "fac_x", kind: "marker_purchase", handle: "  Player_A ", code: "000123" } });
    expect(res.status).toBe(201);
    expect(w.offline).toEqual([{ facilityId: "fac_x", kind: "marker_purchase", handle: "player_a", code: "000123" }]);
  });
  it("the shapes in isolation", () => {
    expect(parseOnlineAttestBody({ facilityId: "fac_x", kind: "presence", token: TOKEN }).ok).toBe(true);
    expect(parseOnlineAttestBody(null).ok).toBe(false);
    expect(parseOfflineAttestBody({ facilityId: "fac_x", kind: "presence", handle: "abc", code: "000000" }).ok).toBe(true);
    expect(parseShiftLogQuery("https://x.test/f/shift-log?facilityId=fac_x").ok).toBe(true);
    expect(parseShiftLogQuery("https://x.test/f/shift-log").ok).toBe(false);
    expect(parseShiftLogQuery("https://x.test/f/shift-log?facilityId=fac_x&facilityId=fac_y").ok).toBe(false);
    expect(parseShiftLogQuery("https://x.test/f/shift-log?facilityId=fac_x&extra=1").ok).toBe(false);
    expect(parseStaffActivityQuery("https://x.test/f/staff-activity?facilityId=fac_x")).toEqual({ ok: true, value: { facilityId: "fac_x", days: 7 } });
    for (const days of ["0", "91", "abc", "-1", "1.5", "007x"]) expect(parseStaffActivityQuery(`https://x.test/f/staff-activity?facilityId=fac_x&days=${days}`).ok, days).toBe(false);
    expect(parseStaffActivityQuery("https://x.test/f/staff-activity?facilityId=fac_x&days=90")).toEqual({ ok: true, value: { facilityId: "fac_x", days: 90 } });
  });
});

describe("the status map: every returned status commits, every throw rolls back", () => {
  const MAP: Array<[AttestStatus, number, string | null]> = [
    ["ok", 201, null],
    ["replayed", 409, "replayed"],
    ["token_invalid", 422, "token_invalid"],
    ["verification_failed", 422, "verification_failed"],
    ["rate_limited", 429, "rate_limited"],
    ["cold_start_cap", 429, "rate_limited"],
    ["no_programme", 422, "no_programme"],
    ["no_facility", 404, "not_found"],
  ];
  for (const [status, http, code] of MAP) {
    for (const [path, body] of [[ROUTES[0]![1], ROUTES[0]![2]], [ROUTES[1]![1], ROUTES[1]![2]]] as Array<[string, unknown]>) {
      it(`${path}: ${status} is ${http}`, async () => {
        const { w, deps } = world();
        w.result = { status, attestationId: status === "ok" ? okResult.attestationId : null, held: false };
        const res = await call(deps, "POST", path, { headers: auth(), body });
        expect(res.status).toBe(http);
        const json = (await res.json()) as { data?: Record<string, unknown>; error?: { code: string } };
        if (code === null) expect(json.data).toEqual({ attestationId: okResult.attestationId, held: false });
        else expect(json.error?.code).toBe(code);
        if (http === 429) expect(res.headers.get("retry-after")).toBe("3600");
        expect(w.committed, "a returned status COMMITS (the failure counters survive)").toEqual([true]);
      });
    }
  }

  it("a held attest says so, and nothing else about why", async () => {
    const { w, deps } = world();
    w.result = { status: "ok", attestationId: okResult.attestationId, held: true };
    const res = await call(deps, "POST", "attest", { headers: auth(), body: ROUTES[0]![2] });
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ data: { attestationId: okResult.attestationId, held: true } });
  });

  it("a 42501 (no scope, no PIN grant, an operator) is 403 and rolls back; a 22023 (self-attest) is 422 and rolls back (AT(1), AT(16))", async () => {
    for (const [route, err, status] of [
      ["attest", new PartnerAuthorityRefused(), 403],
      ["attest/offline", new PartnerAuthorityRefused(), 403],
      ["attest", new PartnerInvalidArgument(), 422],
      ["attest/offline", new PartnerInvalidArgument(), 422],
    ] as const) {
      const { w, deps } = world();
      w.throwIn = route === "attest" ? "attest" : "offlineAttest";
      w.throwWith = err;
      const body = route === "attest" ? ROUTES[0]![2] : ROUTES[1]![2];
      const res = await call(deps, "POST", route, { headers: auth(), body });
      expect(res.status, `${route} ${err.name}`).toBe(status);
      expect(w.committed, "a throw never commits").toEqual([]);
    }
  });

  it("a dead session at the binder is the ONE 401", async () => {
    const { w, deps } = world();
    w.bindRefused = true;
    const res = await call(deps, "POST", "attest", { headers: auth(), body: ROUTES[0]![2] });
    expect(res.status).toBe(401);
  });

  it("no response names a seed, an expected code, a device, a step or which check failed", async () => {
    const { w, deps } = world();
    for (const status of ["verification_failed", "replayed", "token_invalid", "rate_limited"] as const) {
      w.result = { status, attestationId: null, held: false };
      const res = await call(deps, "POST", "attest/offline", { headers: auth(), body: ROUTES[1]![2] });
      const t = (await res.text()).toLowerCase();
      for (const word of ["seed", "expected", "device", "step", "mismatch", "handle", "no such"]) expect(t, `${status}: ${word}`).not.toContain(word);
    }
  });
});

describe("the per-member bucket and the work order", () => {
  it("the bucket is hit once per request, after the strict body and before the transaction, on every route", async () => {
    for (const [method, path, body] of ROUTES) {
      const { w, deps } = world();
      const res = await call(deps, method, path, { headers: auth(), body });
      expect(res.status, path).toBeLessThan(300);
      expect(w.calls[0], path).toBe("db.hitRateLimit");
      expect(w.calls[1], path).toBe("db.withAttest");
      expect(w.rate).toEqual([{ hash: await sha256Hex(SESSION_TOKEN), bucket: ATTEST_BUCKET, windowSeconds: 3600, max: ATTEST_PER_MEMBER_PER_HOUR }]);
    }
  });

  it("over the bucket is a 429 with Retry-After and the transaction never opens", async () => {
    for (const [method, path, body] of ROUTES) {
      const { w, deps } = world();
      w.rateOk = false;
      const res = await call(deps, method, path, { headers: auth(), body });
      expect(res.status, path).toBe(429);
      expect(res.headers.get("retry-after")).toBe("3600");
      expect(w.calls).toEqual(["db.hitRateLimit"]);
    }
  });

  it("the online attest passes the facility, the kind and the token and NOTHING about the player", async () => {
    const { w, deps } = world();
    await call(deps, "POST", "attest", { headers: auth(), body: ROUTES[0]![2] });
    expect(w.online).toEqual([{ facilityId: "fac_x", kind: "presence", token: TOKEN }]);
  });
});

describe("the reads", () => {
  it("shift-log returns the entries it was given, with the six columns and no pseudonym", async () => {
    const { w, deps } = world();
    const res = await call(deps, "GET", "shift-log?facilityId=fac_x", { headers: auth() });
    expect(res.status).toBe(200);
    const json = (await res.json()) as { data: { entries: Array<Record<string, unknown>> } };
    expect(Object.keys(json.data.entries[0]!).sort()).toEqual(["createdAt", "facilityId", "id", "kind", "playerHandle", "staffHandle"]);
    expect(w.reads).toEqual([{ what: "shiftLog", facilityId: "fac_x" }]);
  });

  it("staff-activity returns counts and anomaly markers with no player column, and passes the window", async () => {
    const { w, deps } = world();
    const res = await call(deps, "GET", "staff-activity?facilityId=fac_x&days=30", { headers: auth() });
    expect(res.status).toBe(200);
    const json = (await res.json()) as { data: { activity: Array<Record<string, unknown>> } };
    expect(Object.keys(json.data.activity[0]!).sort()).toEqual(["activations", "anomalies", "attests", "day", "facilityId", "staffUserId"]);
    expect(w.reads).toEqual([{ what: "staffActivity", facilityId: "fac_x", days: 30 }]);
  });

  it("a bad query is 400 and a refused read (42501) is 403", async () => {
    const { w, deps } = world();
    expect((await call(deps, "GET", "shift-log", { headers: auth() })).status).toBe(400);
    expect((await call(deps, "GET", "staff-activity?facilityId=fac_x&days=0", { headers: auth() })).status).toBe(400);
    expect(w.calls).toEqual([]);
    w.throwIn = "staffActivity";
    expect((await call(deps, "GET", "staff-activity?facilityId=fac_x", { headers: auth() })).status).toBe(403);
    w.throwIn = "shiftLog";
    expect((await call(deps, "GET", "shift-log?facilityId=fac_x", { headers: auth() })).status).toBe(403);
  });
});
