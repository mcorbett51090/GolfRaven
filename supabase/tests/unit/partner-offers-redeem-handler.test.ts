// supabase/tests/unit/partner-offers-redeem-handler.test.ts
//
// The `partner-offers-redeem` handler and its strict shapes (docs/security/partner-auth-design.md 12, 32; P5.1b, the Edge half of 0060), against an in-memory `PartnerDb`.
// Database cells: matrix 38.

import { describe, expect, it } from "vitest";
import {
  handlePartnerOffersRedeemRequest,
  OFFERS_REDEEM_BUCKET,
  OFFERS_REDEEM_PER_MEMBER_PER_HOUR,
  type PartnerOffersRedeemDeps,
} from "../../functions/_shared/partner/offers-redeem-handler.ts";
import { parseOfferRedeemBody, parseOffersQueueQuery } from "../../functions/_shared/partner/offers-redeem-shape.ts";
import {
  type OfferQueueRow,
  type OfferRedeemResult,
  type PartnerDb,
  type PartnerOffersRedeemTx,
  PartnerAuthorityRefused,
  PartnerInvalidArgument,
  PartnerSessionRefused,
} from "../../functions/_shared/partner/ports.ts";
import { fnReq, ORIGIN, SESSION_TOKEN } from "./partner-fakes.ts";

const FN = "partner-offers-redeem";
const CODE = "78000000-0000-0000-0000-000000000001";
const JTI = "38200000-0000-0000-0000-000000000001";

type Op = "offersQueue" | "redeemOffer";
interface World {
  calls: string[];
  committed: boolean[];
  rolledBack: boolean[];
  rate: Array<{ hash: string; bucket: string; windowSeconds: number; max: number }>;
  args: Array<{ op: Op; args: unknown[] }>;
  queue: OfferQueueRow[];
  redeem: OfferRedeemResult;
  throwIn: Op | null;
  throwWith: Error;
  rateOk: boolean;
  bindRefused: boolean;
}

const okRedeem: OfferRedeemResult = { status: "ok", attestationId: "11111111-1111-1111-1111-111111111111" };

function world(): { w: World; deps: PartnerOffersRedeemDeps } {
  const w: World = {
    calls: [],
    committed: [],
    rolledBack: [],
    rate: [],
    args: [],
    redeem: okRedeem,
    throwIn: null,
    throwWith: new PartnerAuthorityRefused(),
    rateOk: true,
    bindRefused: false,
    queue: [{
      offerCodeId: CODE,
      offerId: "77000000-0000-0000-0000-000000000001",
      playerHandle: "player_b",
      expiresAt: "2030-01-01T12:00:00.000Z",
      faceValue: 5,
    }],
  };
  const hit = (op: Op, args: unknown[]) => {
    w.calls.push(`tx.${op}`);
    w.args.push({ op, args });
    if (w.throwIn === op) throw w.throwWith;
  };
  const tx: PartnerOffersRedeemTx = {
    async offersQueue(...a) {
      hit("offersQueue", a);
      return w.queue;
    },
    async redeemOffer(...a) {
      hit("redeemOffer", a);
      return w.redeem;
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
    withEntitlements: reject,
    withProgramme: reject,
    withOffersAdmin: reject,
    withSponsorships: reject,
    withSettlementExport: reject,
    async withOffersRedeem(_hash, op) {
      w.calls.push("db.withOffersRedeem");
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
const call = (deps: PartnerOffersRedeemDeps, method: string, path: string, init: { headers?: Record<string, string>; body?: unknown } = {}) =>
  handlePartnerOffersRedeemRequest(fnReq(FN, method, path, init), deps);

describe("offers-redeem-shape", () => {
  it("parseOffersQueueQuery / parseOfferRedeemBody: accept well-formed input; refuse unknown keys and offline_code", () => {
    expect(parseOffersQueueQuery(`https://p.test/${FN}/queue?facilityId=fac_x`)).toEqual({ ok: true, value: { facilityId: "fac_x" } });
    expect(parseOffersQueueQuery(`https://p.test/${FN}/queue?facilityId=fac_x&x=1`).ok).toBe(false);
    const ok = parseOfferRedeemBody({ facilityId: "fac_x", offerCodeId: CODE, method: "staff_scan", credential: JTI });
    expect(ok).toEqual({ ok: true, value: { facilityId: "fac_x", offerCodeId: CODE, method: "staff_scan", credential: JTI } });
    expect(parseOfferRedeemBody({ facilityId: "fac_x", offerCodeId: CODE, method: "offline_code", credential: "123456" }).ok).toBe(false);
    expect(parseOfferRedeemBody({ facilityId: "fac_x", offerCodeId: CODE, method: "staff_scan", credential: JTI, extra: 1 }).ok).toBe(false);
  });
});

describe("partner-offers-redeem handler", () => {
  it("GET queue: origin → bearer → bucket → port; returns offer codes", async () => {
    const { w, deps } = world();
    const res = await call(deps, "GET", "queue?facilityId=fac_x", { headers: auth() });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ offerCodes: [{ offerCodeId: CODE, playerHandle: "player_b", faceValue: 5 }] });
    expect(w.calls).toEqual(["db.hitRateLimit", "db.withOffersRedeem", "tx.offersQueue"]);
    expect(w.rate[0]).toEqual({ hash: expect.any(String), bucket: OFFERS_REDEEM_BUCKET, windowSeconds: 3600, max: OFFERS_REDEEM_PER_MEMBER_PER_HOUR });
    expect(w.committed).toEqual([true]);
  });

  it("POST redeem happy path is 201 with attestationId", async () => {
    const { w, deps } = world();
    const res = await call(deps, "POST", "redeem", {
      headers: auth(),
      body: { facilityId: "fac_x", offerCodeId: CODE, method: "staff_scan", credential: JTI },
    });
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ attestationId: okRedeem.attestationId });
    expect(w.args[0]).toEqual({ op: "redeemOffer", args: ["fac_x", CODE, "staff_scan", JTI] });
  });

  it("maps redeem statuses to HTTP", async () => {
    const cases: Array<[OfferRedeemResult["status"], number, string]> = [
      ["not_found", 404, "not_found"],
      ["no_facility", 404, "not_found"],
      ["not_issued", 422, "not_issued"],
      ["expired", 422, "expired"],
      ["wrong_facility", 422, "wrong_facility"],
      ["token_invalid", 422, "token_invalid"],
      ["wrong_player", 422, "token_invalid"],
      ["replayed", 409, "replayed"],
      ["budget_short", 422, "budget_short"],
      ["cold_start_cap", 429, "rate_limited"],
    ];
    for (const [status, http, code] of cases) {
      const { deps, w } = world();
      w.redeem = { status, attestationId: null };
      const res = await call(deps, "POST", "redeem", {
        headers: auth(),
        body: { facilityId: "fac_x", offerCodeId: CODE, method: "staff_scan", credential: JTI },
      });
      expect(res.status, status).toBe(http);
      expect((await res.json()).error.code, status).toBe(code);
    }
  });

  it("42501 → 403; 22023 → 422; bind refuse → 401; rate limit before port", async () => {
    const a = world();
    a.w.throwIn = "redeemOffer";
    a.w.throwWith = new PartnerAuthorityRefused();
    const r1 = await call(a.deps, "POST", "redeem", {
      headers: auth(),
      body: { facilityId: "fac_x", offerCodeId: CODE, method: "staff_scan", credential: JTI },
    });
    expect(r1.status).toBe(403);

    const b = world();
    b.w.throwIn = "redeemOffer";
    b.w.throwWith = new PartnerInvalidArgument();
    const r2 = await call(b.deps, "POST", "redeem", {
      headers: auth(),
      body: { facilityId: "fac_x", offerCodeId: CODE, method: "staff_scan", credential: JTI },
    });
    expect(r2.status).toBe(422);

    const c = world();
    c.w.bindRefused = true;
    const r3 = await call(c.deps, "GET", "queue?facilityId=fac_x", { headers: auth() });
    expect(r3.status).toBe(401);

    const d = world();
    d.w.rateOk = false;
    const r4 = await call(d.deps, "GET", "queue?facilityId=fac_x", { headers: auth() });
    expect(r4.status).toBe(429);
    expect(d.w.calls).toEqual(["db.hitRateLimit"]);
  });
});
