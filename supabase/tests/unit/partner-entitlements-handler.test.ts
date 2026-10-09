// supabase/tests/unit/partner-entitlements-handler.test.ts
//
// The `partner-entitlements` handler and its strict shapes (docs/security/partner-auth-design.md 12, 12.1, 28; AT(8), AT(21); slice S5, the Edge half of 0058), against an in-memory `PartnerDb`. What is decided
// HERE: the route table, the Origin / bearer / media-type / strict-body order, that every route is a session route, the status-to-HTTP map (a returned refusal is a status that COMMITS; a 42501 and a 22023
// throw and ROLL BACK), and the ONE thing this function owns about the hand-over token: it is generated here, returned to the caller ONCE, and the database (the port) only ever sees its SHA-256. What is
// the DATABASE's (scope, class, self-redeem, replay, the stock lock and the race for the last unit, the attestation, the cold-start cap): matrix 36 (supabase/tests/matrix/36_*).

import { describe, expect, it } from "vitest";
import {
  ENTITLEMENTS_BUCKET,
  ENTITLEMENTS_PER_MEMBER_PER_HOUR,
  handlePartnerEntitlementsRequest,
  type PartnerEntitlementsDeps,
} from "../../functions/_shared/partner/entitlements-handler.ts";
import { parseCollectQuery, parseEntitlementRefBody, parseRedeemBody } from "../../functions/_shared/partner/entitlements-shape.ts";
import {
  type EntitlementQueueRow,
  type HandoverMintResult,
  type PartnerDb,
  type PartnerEntitlementsTx,
  PartnerAuthorityRefused,
  PartnerInvalidArgument,
  PartnerSessionRefused,
  type RedeemResult,
  type RedeemStatus,
  type VoucherResult,
} from "../../functions/_shared/partner/ports.ts";
import { PARTNER_HANDOVER_TOKEN_RE } from "../../functions/_shared/partner/token.ts";
import { fnReq, ORIGIN, SESSION_TOKEN, sha256Hex } from "./partner-fakes.ts";

const FN = "partner-entitlements";
const ENT = "51000000-0000-0000-0000-000000003601";
const JTI = "34200000-0000-0000-0000-000000000001";
const HANDOVER = "gr_ho_" + "A".repeat(43);

type Op = "collectQueue" | "mintHandover" | "redeem" | "voucher";
interface World {
  calls: string[];
  committed: boolean[];
  rolledBack: boolean[];
  rate: Array<{ hash: string; bucket: string; windowSeconds: number; max: number }>;
  args: Array<{ op: Op; args: unknown[] }>;
  queue: EntitlementQueueRow[];
  mint: HandoverMintResult;
  redeem: RedeemResult;
  voucher: VoucherResult;
  throwIn: Op | null;
  throwWith: Error;
  rateOk: boolean;
  bindRefused: boolean;
}

const okMint: HandoverMintResult = { status: "ok", expiresAt: "2030-01-01T12:15:00.000Z" };
const okRedeem: RedeemResult = { status: "ok", attestationId: "11111111-1111-1111-1111-111111111111", movement: "redeemed", availability: "low" };
const okVoucher: VoucherResult = { status: "ok", voucherIssuedAt: "2030-01-01T12:00:00.000Z" };

function world(): { w: World; deps: PartnerEntitlementsDeps } {
  const w: World = {
    calls: [], committed: [], rolledBack: [], rate: [], args: [], mint: okMint, redeem: okRedeem, voucher: okVoucher, throwIn: null, throwWith: new PartnerAuthorityRefused(), rateOk: true, bindRefused: false,
    queue: [{ entitlementId: ENT, trailId: "trl_t", state: "redeemable", playerHandle: "player_a", activatedAt: "2030-01-01T10:00:00.000Z", voucherIssuedAt: null }],
  };
  const hit = (op: Op, args: unknown[]) => {
    w.calls.push(`tx.${op}`);
    w.args.push({ op, args });
    if (w.throwIn === op) throw w.throwWith;
  };
  const tx: PartnerEntitlementsTx = {
    async collectQueue(...a) {
      hit("collectQueue", a);
      return w.queue;
    },
    async mintHandover(...a) {
      hit("mintHandover", a);
      return w.mint;
    },
    async redeem(...a) {
      hit("redeem", a);
      return w.redeem;
    },
    async voucher(...a) {
      hit("voucher", a);
      return w.voucher;
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
    withStock: reject,
    withProgramme: reject,
    withOffersAdmin: reject,
    withSponsorships: reject,
    async withEntitlements(_hash, op) {
      w.calls.push("db.withEntitlements");
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
const call = (deps: PartnerEntitlementsDeps, method: string, path: string, init: { headers?: Record<string, string>; body?: unknown; raw?: string } = {}) =>
  handlePartnerEntitlementsRequest(fnReq(FN, method, path, init), deps);

const REF = { facilityId: "fac_x", entitlementId: ENT };
const SCAN = { ...REF, method: "staff_scan", credential: JTI };
const TOKEN_REDEEM = { ...REF, method: "hand_over_token", credential: HANDOVER };
const ROUTES: Array<[string, string, unknown]> = [
  ["GET", "collect?facilityId=fac_x", undefined],
  ["POST", "handover/mint", REF],
  ["POST", "redeem", SCAN],
  ["POST", "voucher", REF],
];
const portArgs = (w: World, op: Op) => w.args.filter((a) => a.op === op).map((a) => a.args);

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
      for (const authorization of [undefined, `Bearer ${jwtShaped}`, `Basic ${SESSION_TOKEN}`, `Bearer ${SESSION_TOKEN}x`, `Bearer ${HANDOVER}`]) {
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
    expect((await call(deps, "POST", "handover", { headers: auth(), body: REF })).status).toBe(404);
    expect((await call(deps, "POST", "redeem/offline", { headers: auth(), body: {} })).status).toBe(404);
    const get = await call(deps, "GET", "redeem", { headers: auth() });
    expect(get.status).toBe(405);
    expect(get.headers.get("allow")).toBe("POST");
    const post = await call(deps, "POST", "collect?facilityId=fac_x", { headers: auth(), body: {} });
    expect(post.status).toBe(405);
    expect(post.headers.get("allow")).toBe("GET");
  });

  it("the exact JSON media type is required (415) before the body is read, and nothing reaches the database", async () => {
    const { w, deps } = world();
    for (const [, path, body] of ROUTES.slice(1)) {
      const res = await call(deps, "POST", path, { headers: auth({ "content-type": "text/plain; x=application/json" }), raw: JSON.stringify(body) });
      expect(res.status, path).toBe(415);
    }
    expect(w.calls).toEqual([]);
  });
});

describe("strict bodies and queries: unknown keys and malformed values are 400, before any port", () => {
  const bad: Array<[string, string, unknown]> = [
    ["handover/mint", "a stray key", { ...REF, tokenHash: "0".repeat(64) }],
    ["handover/mint", "a client-supplied token", { ...REF, token: HANDOVER }],
    ["handover/mint", "a non-uuid entitlement", { ...REF, entitlementId: "nope" }],
    ["handover/mint", "no facility", { entitlementId: ENT }],
    ["voucher", "a stray key", { ...REF, userId: "00000000-0000-0000-0000-00000000000b" }],
    ["voucher", "a bad facility", { ...REF, facilityId: "fac x" }],
    ["redeem", "offline_code (not a method of this slice)", { ...REF, method: "offline_code", credential: "123456" }],
    ["redeem", "no method", { ...REF, credential: JTI }],
    ["redeem", "a stray key", { ...SCAN, playerId: "00000000-0000-0000-0000-00000000000b" }],
    ["redeem", "staff_scan with a non-uuid credential", { ...SCAN, credential: "not-a-uuid" }],
    ["redeem", "staff_scan with a hand-over token", { ...SCAN, credential: HANDOVER }],
    ["redeem", "hand_over_token with a uuid", { ...TOKEN_REDEEM, credential: JTI }],
    ["redeem", "hand_over_token with a short token", { ...TOKEN_REDEEM, credential: "gr_ho_abc" }],
    ["redeem", "hand_over_token with a SHA-256 (the hash is never the credential)", { ...TOKEN_REDEEM, credential: "a".repeat(64) }],
    ["redeem", "a session token as the credential", { ...TOKEN_REDEEM, credential: SESSION_TOKEN }],
    ["redeem", "a non-string credential", { ...SCAN, credential: 5 }],
    ["redeem", "an array", []],
  ];
  for (const [path, what, body] of bad) {
    it(`POST ${path} with ${what} is 400 and touches no port`, async () => {
      const { w, deps } = world();
      const res = await call(deps, "POST", path, { headers: auth(), body });
      expect(res.status).toBe(400);
      expect(w.calls).toEqual([]);
    });
  }
  for (const q of ["collect", "collect?facilityId=", "collect?facilityId=fac%20x", "collect?facilityId=fac_x&facilityId=fac_y", "collect?facilityId=fac_x&state=redeemable"]) {
    it(`GET ${q} is 400 and touches no port`, async () => {
      const { w, deps } = world();
      expect((await call(deps, "GET", q, { headers: auth() })).status).toBe(400);
      expect(w.calls).toEqual([]);
    });
  }
  it("the shapes: a uuid is lower-cased, a good token and a good query pass", () => {
    expect(parseEntitlementRefBody({ facilityId: "fac_x", entitlementId: ENT.toUpperCase() })).toEqual({ ok: true, value: REF });
    expect(parseRedeemBody({ ...SCAN, credential: JTI.toUpperCase() })).toEqual({ ok: true, value: { ...REF, method: "staff_scan", credential: JTI } });
    expect(parseRedeemBody(TOKEN_REDEEM)).toEqual({ ok: true, value: { ...REF, method: "hand_over_token", credential: HANDOVER } });
    expect(parseCollectQuery("https://p.test/partner-entitlements/collect?facilityId=fac_x")).toEqual({ ok: true, value: { facilityId: "fac_x" } });
  });
});

describe("the bucket", () => {
  it("one per-member hit precedes the work, keyed on the token hash, in its own transaction before the request transaction opens", async () => {
    const { w, deps } = world();
    for (const [method, path, body] of ROUTES) {
      w.calls.length = 0;
      const res = await call(deps, method, path, { headers: auth(), body });
      expect(res.status, path).toBeLessThan(300);
      expect(w.calls[0], path).toBe("db.hitRateLimit");
      expect(w.calls[1], path).toBe("db.withEntitlements");
    }
    expect(w.rate[0]).toEqual({ hash: await sha256Hex(SESSION_TOKEN), bucket: ENTITLEMENTS_BUCKET, windowSeconds: 3600, max: ENTITLEMENTS_PER_MEMBER_PER_HOUR });
  });

  it("an exhausted bucket is 429 with Retry-After and neither the work nor a token is produced", async () => {
    const { w, deps } = world();
    w.rateOk = false;
    for (const [method, path, body] of ROUTES) {
      const res = await call(deps, method, path, { headers: auth(), body });
      expect(res.status, path).toBe(429);
      expect(res.headers.get("retry-after")).toBe("3600");
      expect(await res.text()).not.toContain("gr_ho_");
    }
    expect(w.calls.filter((c) => c === "db.withEntitlements")).toEqual([]);
  });
});

describe("GET collect", () => {
  it("returns the queue by player handle and passes the facility through", async () => {
    const { w, deps } = world();
    const res = await call(deps, "GET", "collect?facilityId=fac_x", { headers: auth() });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      data: { entitlements: [{ entitlementId: ENT, trailId: "trl_t", state: "redeemable", playerHandle: "player_a", activatedAt: "2030-01-01T10:00:00.000Z", voucherIssuedAt: null }] },
    });
    expect(portArgs(w, "collectQueue")).toEqual([["fac_x"]]);
    expect(w.committed).toEqual([true]);
  });
});

describe("POST handover/mint: the plaintext token is the caller's alone; the database sees only its SHA-256", () => {
  it("201 with a gr_ho_ token of 32 random bytes and the expiry; the port got sha256(token), never the token", async () => {
    const { w, deps } = world();
    const res = await call(deps, "POST", "handover/mint", { headers: auth(), body: REF });
    expect(res.status).toBe(201);
    const { data } = (await res.json()) as { data: { token: string; expiresAt: string } };
    expect(data.token).toMatch(PARTNER_HANDOVER_TOKEN_RE);
    expect(data.expiresAt).toBe(okMint.expiresAt);
    const [facilityId, entitlementId, hash] = portArgs(w, "mintHandover")[0] as [string, string, string];
    expect([facilityId, entitlementId]).toEqual(["fac_x", ENT]);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hash).toBe(await sha256Hex(data.token));
    expect(JSON.stringify(w.args)).not.toContain(data.token);
    expect(w.committed).toEqual([true]);
  });

  it("two mints give two different tokens (the randomness is real)", async () => {
    const { deps } = world();
    const t = async () => ((await (await call(deps, "POST", "handover/mint", { headers: auth(), body: REF })).json()) as { data: { token: string } }).data.token;
    expect(await t()).not.toBe(await t());
  });

  const refusals: Array<[HandoverMintResult["status"], number]> = [
    ["not_found", 404],
    ["not_redeemable", 422],
    ["wrong_facility", 422],
    ["no_stock_row", 422],
    ["token_exists", 422],
  ];
  for (const [status, http] of refusals) {
    it(`${status} is ${http}, COMMITS, and the response carries no token`, async () => {
      const { w, deps } = world();
      w.mint = { status, expiresAt: null };
      const res = await call(deps, "POST", "handover/mint", { headers: auth(), body: REF });
      expect(res.status).toBe(http);
      expect(await res.text()).not.toContain("gr_ho_");
      expect(w.committed).toEqual([true]);
      expect(w.rolledBack).toEqual([]);
    });
  }
});

describe("POST redeem", () => {
  it("staff_scan: the check-in jti reaches the port as given; ok is 201 with the attestation, the movement and the availability", async () => {
    const { w, deps } = world();
    const res = await call(deps, "POST", "redeem", { headers: auth(), body: SCAN });
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ data: { attestationId: okRedeem.attestationId, movement: "redeemed", availability: "low" } });
    expect(portArgs(w, "redeem")).toEqual([["fac_x", ENT, "staff_scan", JTI]]);
    expect(w.committed).toEqual([true]);
  });

  it("hand_over_token: the PLAINTEXT is hashed here; the port gets the SHA-256 and the plaintext appears nowhere in what it received", async () => {
    const { w, deps } = world();
    const res = await call(deps, "POST", "redeem", { headers: auth(), body: TOKEN_REDEEM });
    expect(res.status).toBe(201);
    const [, , method, credential] = portArgs(w, "redeem")[0] as [string, string, string, string];
    expect(method).toBe("hand_over_token");
    expect(credential).toBe(await sha256Hex(HANDOVER));
    expect(credential).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(w.args)).not.toContain(HANDOVER);
  });

  it("a token minted by this function redeems by the hash the mint stored (the round trip the database relies on)", async () => {
    const { w, deps } = world();
    const minted = ((await (await call(deps, "POST", "handover/mint", { headers: auth(), body: REF })).json()) as { data: { token: string } }).data.token;
    await call(deps, "POST", "redeem", { headers: auth(), body: { ...REF, method: "hand_over_token", credential: minted } });
    const stored = (portArgs(w, "mintHandover")[0] as string[])[2];
    const presented = (portArgs(w, "redeem")[0] as string[])[3];
    expect(presented).toBe(stored);
  });

  const cases: Array<[RedeemStatus, number, string]> = [
    ["not_found", 404, "not_found"],
    ["no_facility", 404, "not_found"],
    ["not_redeemable", 422, "not_redeemable"],
    ["wrong_facility", 422, "wrong_facility"],
    ["token_invalid", 422, "token_invalid"],
    ["wrong_player", 422, "token_invalid"],
    ["no_stock_row", 422, "no_stock_row"],
    ["no_programme", 422, "no_programme"],
    ["replayed", 409, "replayed"],
    ["out_of_stock", 409, "out_of_stock"],
    ["cold_start_cap", 429, "rate_limited"],
  ];
  for (const [status, http, code] of cases) {
    it(`${status} is ${http} (code ${code}) and the transaction COMMITS`, async () => {
      const { w, deps } = world();
      w.redeem = { status, attestationId: null, movement: null, availability: status === "out_of_stock" ? "out" : null };
      const res = await call(deps, "POST", "redeem", { headers: auth(), body: SCAN });
      expect(res.status).toBe(http);
      expect(((await res.json()) as { error: { code: string } }).error.code).toBe(code);
      if (status === "cold_start_cap") expect(res.headers.get("retry-after")).toBe("3600");
      expect(w.committed).toEqual([true]);
      expect(w.rolledBack).toEqual([]);
    });
  }

  it("token_invalid and wrong_player are byte-identical on the wire: nothing says which check failed", async () => {
    const bodies: string[] = [];
    for (const status of ["token_invalid", "wrong_player"] as const) {
      const { w, deps } = world();
      w.redeem = { status, attestationId: null, movement: null, availability: null };
      bodies.push(await (await call(deps, "POST", "redeem", { headers: auth(), body: SCAN })).text());
    }
    expect(bodies[0]).toBe(bodies[1]);
  });
});

describe("POST voucher", () => {
  it("ok is 200 with the issue time and the arguments reach the port", async () => {
    const { w, deps } = world();
    const res = await call(deps, "POST", "voucher", { headers: auth(), body: REF });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ data: { voucherIssuedAt: okVoucher.voucherIssuedAt } });
    expect(portArgs(w, "voucher")).toEqual([["fac_x", ENT]]);
    expect(w.committed).toEqual([true]);
  });

  for (const [status, http] of [["not_found", 404], ["not_redeemable", 422], ["no_stock_row", 422]] as const) {
    it(`${status} is ${http} and COMMITS`, async () => {
      const { w, deps } = world();
      w.voucher = { status, voucherIssuedAt: null };
      expect((await call(deps, "POST", "voucher", { headers: auth(), body: REF })).status).toBe(http);
      expect(w.committed).toEqual([true]);
    });
  }
});

describe("thrown refusals roll back and map", () => {
  const ops: Array<[string, string, unknown, Op]> = [
    ["GET", "collect?facilityId=fac_x", undefined, "collectQueue"],
    ["POST", "handover/mint", REF, "mintHandover"],
    ["POST", "redeem", SCAN, "redeem"],
    ["POST", "voucher", REF, "voucher"],
  ];
  it("42501 (no scope, or no PIN grant) is 403 and 22023 (a self-redeem, a malformed argument) is 422; each rolled back, none committed, no token in the body", async () => {
    for (const [throwWith, status] of [[new PartnerAuthorityRefused(), 403], [new PartnerInvalidArgument(), 422]] as const) {
      for (const [method, path, body, throwIn] of ops) {
        const { w, deps } = world();
        w.throwIn = throwIn;
        w.throwWith = throwWith;
        const res = await call(deps, method, path, { headers: auth(), body });
        expect(res.status, `${path} ${throwWith.name}`).toBe(status);
        expect(await res.text()).not.toContain("gr_ho_");
        expect(w.rolledBack).toEqual([true]);
        expect(w.committed).toEqual([]);
      }
    }
  });

  it("a refused bind is the ONE 401; any other error is a constant 500 with no detail", async () => {
    const a = world();
    a.w.bindRefused = true;
    expect((await call(a.deps, "POST", "voucher", { headers: auth(), body: REF })).status).toBe(401);
    const b = world();
    b.w.throwIn = "redeem";
    b.w.throwWith = new Error("secret database text");
    const res = await call(b.deps, "POST", "redeem", { headers: auth(), body: SCAN });
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("secret");
  });
});
